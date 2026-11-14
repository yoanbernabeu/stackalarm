// Package cli implements the stackalarm command line.
package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yoanbernabeu/stackalarm/internal/news"
	"github.com/yoanbernabeu/stackalarm/internal/source"
	"github.com/yoanbernabeu/stackalarm/internal/watch"
	"github.com/yoanbernabeu/stackalarm/sources"
)

// App holds the dependencies of every command, so tests can replace them.
type App struct {
	Out, Err  io.Writer
	Sources   []source.Source
	Fetcher   *news.Fetcher
	Now       func() time.Time
	Version   string
	Args      []string // nil means os.Args[1:]
	Getenv    func(string) string
	CacheRoot func() (string, error)
}

// Default returns the App used by the real binary.
func Default(version string) (*App, error) {
	srcs, err := source.LoadAll(sources.FS)
	if err != nil {
		return nil, fmt.Errorf("bundled sources are invalid: %w", err)
	}
	search, err := source.LoadSearch(sources.FS, srcs)
	if err != nil {
		return nil, fmt.Errorf("bundled search settings are invalid: %w", err)
	}
	return &App{
		Out: os.Stdout, Err: os.Stderr, Sources: srcs, Now: time.Now, Version: version,
		Getenv: os.Getenv, CacheRoot: os.UserCacheDir,
		Fetcher: &news.Fetcher{
			Client:     &http.Client{Timeout: 45 * time.Second}, // the NVD API is often slow
			UserAgent:  "stackalarm/" + version + " (+https://github.com/yoanbernabeu/stackalarm)",
			CacheTTL:   time.Hour,
			NVDDelay:   6 * time.Second, // 5 requests per 30 s without a key
			EUVDDelay:  time.Second,
			RetryDelay: 3 * time.Second,
			EPSSAPI:    "https://api.first.org/data/v1/epss",
			EOLAPI:     "https://endoflife.date/api/v1",
			OSVAPI:     "https://api.osv.dev/v1",
			CVEAPI:     "https://cveawg.mitre.org/api/cve",
			Search:     search,
		},
	}, nil
}

// Execute runs the command line and returns the exit code.
func (a *App) Execute(ctx context.Context) int {
	root := &cobra.Command{
		Use:           "stackalarm",
		Short:         "Security news for your stack, gathered for you and your AI agent",
		Long:          "stackalarm gathers security announcements, releases, advisories and CERT alerts\nfrom official sources, filtered by the technologies you name.",
		Version:       a.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(a.Out)
	root.SetErr(a.Err)
	root.AddCommand(a.newsCommand(), a.cveCommand(), a.sourcesCommand(), a.eolCommand())
	if a.Args != nil {
		root.SetArgs(a.Args)
	}
	if err := root.ExecuteContext(ctx); err != nil {
		if errors.Is(err, errFound) {
			return 2
		}
		fmt.Fprintln(a.Err, "Error:", err)
		return 1
	}
	return 0
}

// errFound makes the command exit with code 2: --fail-on found new items.
var errFound = errors.New("new items found")

type newsReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	Since       time.Time `json:"since"`
	Tags        []string  `json:"tags"`
	Keywords    []string  `json:"keywords"`
	Packages    []string  `json:"packages,omitempty"`
	// Components are the packages read from the SBOMs given, looked up on OSV.dev.
	Components []news.Component  `json:"components,omitempty"`
	Stack      []watch.Component `json:"stack,omitempty"` // from the profile
	Items      []news.Item       `json:"items"`
	Failures   []news.Failure    `json:"failures"`
	Truncated  []news.Truncation `json:"truncated"`
	Short      []news.Coverage   `json:"short"` // feeds that do not reach back to Since
	// Exploited tells, for each tag given with a version, what the KEV
	// catalog holds for it: a silence then reads as a check done.
	Exploited []news.ExploitedCheck `json:"exploited_checks,omitempty"`
	Warnings  []string              `json:"warnings"`
	// AlreadyReported counts the items left out because the state file says
	// an earlier run reported them.
	AlreadyReported int `json:"already_reported,omitempty"`
	// Ignored lists the items left out by a decision of the profile: never
	// silently, so a decision that aged badly can be seen.
	Ignored []ignoredItem `json:"ignored,omitempty"`
}

type ignoredItem struct {
	ID        string `json:"id"` // the id the profile names
	Title     string `json:"title"`
	Reason    string `json:"reason"`
	Until     string `json:"until,omitempty"`
	Exploited bool   `json:"exploited,omitempty"` // exploited in the wild, and kept ignored by even_if_exploited
}

func (a *App) newsCommand() *cobra.Command {
	var (
		tags, keywords []string
		order          []string // tags and keywords as given, for the limit of the CVE database searches
		packages       []string
		sboms          []string
		since, format  string
		noCache, noOSV bool
		profilePath    string
		statePath      string
		failOn         []string
	)
	cmd := &cobra.Command{
		Use:   "news",
		Short: "Gather the security news of the given technologies",
		Long: `Gather security announcements, releases, advisories and CERT alerts.

With --tag, only the sources of those technologies are read, plus the general
sources (CERTs, CVE databases, exploit feeds, security press) whose entries
mention one of the tags or --keyword values. The CVE databases (NVD, EUVD) are
searched for each tag and keyword, and only when there is one: without a key,
the NVD allows one request every 6 seconds (set NVD_API_KEY to go faster).
Run "stackalarm sources" to see the available tags.

With --package and versions (next@15.1.0), OSV.dev is asked which known
vulnerabilities hit those versions: they are listed whatever their date, since
a version locked today is still exposed to a flaw published last year. A tag
with its version (--tag php@8.3.20) is compared with the version ranges of the
CVE records. Both mark each range "affected" or "not-affected".

With --sbom, the packages of a CycloneDX or SPDX document (JSON, as syft,
trivy, docker sbom or cdxgen write it) are looked up on OSV.dev the same way,
system packages of a container image included: Debian, Ubuntu, Alpine, Rocky
Linux, AlmaLinux, Wolfi and Chainguard. Given alone, without a tag, a keyword
nor a profile, only those vulnerabilities are listed.

For a scheduled watch, --profile reads the tags, keywords and packages from a
file the agent wrote, --state shows only the items no earlier run reported, and
--fail-on exits with code 2 when a new item has one of the given stages.`,
		Example: "  stackalarm news --tag php --tag symfony --since 7d\n" +
			"  stackalarm news --tag node --tag npm --package express@4.21.2,dompurify@3.2.3 --format json\n" +
			"  stackalarm news --tag php --tag symfony --sbom image.cdx.json --format summary\n" +
			"  stackalarm news --profile .stackalarm.yaml --state .stackalarm-state --fail-on heads-up,alert,release --since 48h --format markdown",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			window, err := news.ParseSince(since)
			if err != nil {
				return fmt.Errorf("--since %q: %w", since, err)
			}
			if !slices.Contains([]string{"text", "summary", "json", "markdown", "sarif"}, format) {
				return fmt.Errorf("--format %q: use text, summary, json, markdown or sarif", format)
			}
			for _, st := range lower(failOn) {
				if !slices.Contains(source.Stages, source.Stage(st)) {
					return fmt.Errorf("--fail-on %q: use stages among %v", st, source.Stages)
				}
			}
			// A tag may carry the version in use (php@8.3.20): the ranges of the
			// CVE records are compared with it.
			// So may a keyword (libwebp@1.3.1, a library copied into the repository):
			// the flaws exploited in the wild that hit it are then looked for.
			versions := map[string]string{}
			for _, words := range [][]string{tags, keywords} {
				for i, t := range words {
					if name, version, ok := strings.Cut(strings.TrimSpace(t), "@"); ok && name != "" {
						words[i] = name
						if version != "" {
							versions[strings.ToLower(name)] = version
						}
					}
				}
			}
			var (
				stack   []watch.Component
				ignores []watch.Ignore
			)
			if profilePath != "" {
				p, err := watch.LoadProfile(profilePath)
				if err != nil {
					return fmt.Errorf("--profile: %w", err)
				}
				tags, keywords, packages = union(p.Tags, tags), union(p.Keywords, keywords), union(p.Packages, packages)
				stack, ignores = p.Stack, p.Ignore
				for _, c := range p.Stack { // a range would compare wrongly; a branch is compared as a branch
					if name := strings.ToLower(c.Name); (c.Precision == "exact" || c.Precision == "branch") && c.Version != "" && versions[name] == "" {
						versions[name] = c.Version
					}
				}
			}
			var (
				components []news.Component
				sbomNotes  []string
			)
			for _, path := range sboms {
				data, err := os.ReadFile(path)
				if err != nil {
					return fmt.Errorf("--sbom: %w", err)
				}
				sbom, err := news.ParseSBOM(data)
				if err != nil {
					return fmt.Errorf("--sbom %s: %w", path, err)
				}
				for _, c := range sbom.Components {
					if !slices.Contains(components, c) {
						components = append(components, c)
					}
				}
				if len(sbom.Components) == 0 {
					sbomNotes = append(sbomNotes, fmt.Sprintf("%s lists no package OSV.dev can look up", path))
				}
				if note := sbom.SkippedNote(); note != "" {
					sbomNotes = append(sbomNotes, fmt.Sprintf("%s: components not looked up: %s", path, note))
				}
			}
			if len(sboms) > 0 && (noOSV || a.Getenv("STACKALARM_NO_OSV") != "") {
				return errors.New("--sbom looks its packages up on OSV.dev: it cannot be used with --no-osv nor STACKALARM_NO_OSV")
			}
			// An SBOM alone asks one question: what hits these packages.
			sbomOnly := len(components) > 0 && len(tags)+len(keywords)+len(packages) == 0
			var state watch.State
			if statePath != "" {
				if state, err = watch.LoadState(statePath); err != nil {
					return fmt.Errorf("--state: %w", err)
				}
			}
			// An unknown tag is searched as a keyword in the general sources rather
			// than failing: agents guess tags, and a guess should still help.
			warnings := sbomNotes
			known := source.Tags(a.Sources)
			tags = slices.DeleteFunc(lower(tags), func(t string) bool {
				if slices.Contains(known, t) {
					return false
				}
				keywords = append(keywords, t)
				warnings = append(warnings, fmt.Sprintf("no source is tagged %q: searched as a keyword in the general sources instead (%s)", t, closeTags(t, known)))
				return true
			})
			f := *a.Fetcher
			f.Now = a.Now
			f.GitHubToken = cmp.Or(a.Getenv("GITHUB_TOKEN"), a.Getenv("GH_TOKEN"))
			if f.NVDAPIKey = a.Getenv("NVD_API_KEY"); f.NVDAPIKey != "" {
				f.NVDDelay = 700 * time.Millisecond // 50 requests per 30 s with a key
			}
			if !noCache {
				if dir, err := a.CacheRoot(); err == nil {
					f.CacheDir = filepath.Join(dir, "stackalarm")
				}
			}
			if noOSV || a.Getenv("STACKALARM_NO_OSV") != "" {
				f.OSVAPI = "" // the package versions then go to the GitHub API only
			}
			now := a.Now().UTC()
			// A profile tells the versions in use: a scheduled watch also learns
			// when their security fixes stop, which no advisory announces.
			var (
				eol     []news.Item
				eolErr  error
				eolDone = make(chan struct{})
			)
			go func() {
				defer close(eolDone)
				eol, eolErr = f.SupportItems(cmd.Context(), stack)
			}()
			for i, w := range order { // php@8.3.20 is searched as php
				if at := strings.Index(w, "@"); at > 0 {
					w = w[:at]
				}
				order[i] = strings.ToLower(strings.TrimSpace(w))
			}
			// A package may name its ecosystem (pip:redis@4.5.1): only that
			// ecosystem's sources read it, where a name exists in several.
			var plain []string
			scoped := map[string][]string{}
			for _, p := range packages {
				if eco, rest, ok := strings.Cut(p, ":"); ok && knownEcosystem(eco) {
					e := news.NormalEcosystem(eco)
					scoped[e] = append(scoped[e], rest)
					continue
				}
				plain = append(plain, p)
			}
			packages = plain
			res := f.Fetch(cmd.Context(), a.Sources, news.Query{Tags: tags, Keywords: keywords, Order: order, PackagesIn: scoped, Since: now.Add(-window), Packages: packages, Versions: versions, Components: components, ComponentsOnly: sbomOnly})
			<-eolDone
			if eolErr != nil {
				res.Failures = append(res.Failures, news.Failure{Source: news.SupportSource, Error: eolErr.Error()})
			}
			res.Items = append(slices.Clip(eol), res.Items...)
			if res.Items == nil {
				res.Items = []news.Item{}
			}
			if len(res.NotSearched) > 0 {
				warnings = append(warnings, fmt.Sprintf("the CVE databases are searched for %d words at most, in the order given: %s not searched (their tagged sources were still read); put the most important tags and keywords first, or run again for these",
					news.MaxTerms, strings.Join(res.NotSearched, ", ")))
			}
			report := newsReport{
				GeneratedAt: now, Since: now.Add(-window), Tags: nonNil(tags), Keywords: nonNil(keywords), Packages: packages, Components: components, Stack: stack,
				Items: res.Items, Failures: res.Failures, Truncated: res.Truncated, Short: res.Short, Warnings: nonNil(warnings), Exploited: res.Exploited,
			}
			for _, ig := range ignores {
				if ig.Expired(now) {
					warnings = append(warnings, fmt.Sprintf("the profile ignores %s until %s, which has passed: it is reported again; review the decision (%s)", ig.ID, ig.Until, ig.Reason))
					continue
				}
				match := ignoreMatcher(ig.ID)
				matches := func(it news.Item) bool { return it.ID == ig.ID || match.MatchString(it.Title+" "+it.URL) }
				// Exploitation in the wild ends the decision, unless it says otherwise:
				// every item of the vulnerability is then reported again.
				exploited := slices.ContainsFunc(report.Items, func(it news.Item) bool {
					return matches(it) && (len(it.ExploitedIn) > 0 || exploitedInTheWild.MatchString(it.Title))
				})
				if exploited && !ig.EvenIfExploited {
					warnings = append(warnings, fmt.Sprintf("the profile ignores %s (%s), but it is now reported exploited in the wild: it is reported again; review the decision, or set even_if_exploited on it if the reason still holds", ig.ID, ig.Reason))
					continue
				}
				report.Items = slices.DeleteFunc(report.Items, func(it news.Item) bool {
					if !matches(it) {
						return false
					}
					report.Ignored = append(report.Ignored, ignoredItem{ID: ig.ID, Title: it.Title, Reason: ig.Reason, Until: ig.Until, Exploited: exploited})
					return true
				})
			}
			report.Warnings = nonNil(warnings)
			if statePath != "" {
				report.Items = slices.DeleteFunc(report.Items, func(it news.Item) bool {
					if state.Seen(it.ID) {
						report.AlreadyReported++
						return true
					}
					return false
				})
			}
			found := slices.ContainsFunc(report.Items, func(it news.Item) bool { return slices.Contains(lower(failOn), string(it.Stage)) })
			switch format {
			case "json":
				enc := json.NewEncoder(a.Out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			case "summary":
				a.printSummary(report)
			case "markdown":
				a.printMarkdown(report)
			case "sarif":
				if err := a.printSARIF(report, cmp.Or(profilePath, ".stackalarm.yaml")); err != nil {
					return err
				}
			default:
				a.printNews(report)
			}
			// With --fail-on, items count as reported only when the run says so:
			// the quiet runs keep them for the next report.
			if statePath != "" && (len(failOn) == 0 || found) {
				for _, it := range report.Items {
					state.Add(it.ID, now)
				}
				if err := state.Save(statePath, now); err != nil {
					return fmt.Errorf("--state: %w", err)
				}
			}
			if found {
				fmt.Fprintf(a.Err, "stackalarm: new items at stage %s\n", strings.Join(lower(failOn), ", "))
				return errFound
			}
			return nil
		},
	}
	cmd.Flags().VarP(orderedList{&tags, &order}, "tag", "t", "technology to watch, repeatable (php, node, gitlab…); with its exact version (php@8.3.20), the version ranges of the CVE records are compared with it, and the flaws exploited in the wild that hit it are listed whatever their date")
	cmd.Flags().VarP(orderedList{&keywords, &order}, "keyword", "k", "extra word to look for in general sources, repeatable (roadrunner, htmx…); the CVE databases are searched for the first 8 tags and keywords, in the order given")
	cmd.Flags().StringSliceVarP(&packages, "package", "p", nil, "packages from the lockfile, repeatable, with their version or not (next@15.1.0, dompurify): the GitHub Advisory Database sources then return only their recent advisories, for that version, and OSV.dev every known vulnerability of that version")
	cmd.Flags().StringSliceVar(&sboms, "sbom", nil, "SBOM of the project or of its container image, repeatable (CycloneDX or SPDX, in JSON): OSV.dev is asked for every known vulnerability of its packages, system packages included")
	cmd.Flags().StringVar(&since, "since", "7d", "how far back to look: 24h, 7d, 2w…")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, summary (one line per item, for agents), json, markdown (an issue body) or sarif (the items a version in use proves, for a code scanning dashboard)")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "always fetch the sources (responses are otherwise reused for an hour)")
	cmd.Flags().StringVar(&profilePath, "profile", "", "project profile written by the agent (.stackalarm.yaml): tags, keywords and packages to watch, exact versions of the stack, vulnerabilities to ignore")
	cmd.Flags().BoolVar(&noOSV, "no-osv", false, "do not send the package versions to OSV.dev (or set STACKALARM_NO_OSV): only the recent advisories of the GitHub Advisory Database are then listed")
	cmd.Flags().StringVar(&statePath, "state", "", "file remembering the items already reported: only new ones are shown")
	cmd.Flags().StringSliceVar(&failOn, "fail-on", nil, "exit with code 2 when a new item has one of these stages (heads-up, alert, release…)")
	return cmd
}

func (a *App) printNews(r newsReport) {
	scope := "all sources"
	switch {
	case len(r.Tags) > 0:
		scope = strings.Join(r.Tags, ", ")
	case len(r.Components) > 0 && len(r.Keywords)+len(r.Packages) == 0:
		scope = fmt.Sprintf("the %d packages of the SBOM", len(r.Components))
	}
	for _, w := range r.Warnings {
		fmt.Fprintln(a.Err, "Warning:", w)
	}
	fmt.Fprintf(a.Out, "Security news since %s (%s)\n\n", r.Since.Format("2006-01-02 15:04 MST"), scope)
	if len(r.Items) == 0 {
		fmt.Fprintln(a.Out, "Nothing new.")
	}
	if r.AlreadyReported > 0 {
		fmt.Fprintf(a.Out, "(%d items already reported by an earlier run are left out)\n", r.AlreadyReported)
	}
	for _, ig := range r.Ignored {
		fmt.Fprintf(a.Out, "(ignored by the profile: %s, %s)\n", ig.ID, ignoredNote(ig))
	}
	for _, it := range r.Items {
		fmt.Fprintf(a.Out, "%s  %-9s %-24s %s\n", it.Published.Format("2006-01-02"), it.Stage, it.Source, it.Title)
		if aff := affected(it); aff != "" {
			fmt.Fprintf(a.Out, "%38saffects %s\n", "", aff)
		}
		if len(it.ExploitedIn) > 0 {
			fmt.Fprintf(a.Out, "%38sexploited in the wild (%s)\n", "", strings.Join(it.ExploitedIn, ", "))
		}
		if len(it.PublicExploitIn) > 0 {
			fmt.Fprintf(a.Out, "%38spublic exploit (%s)\n", "", strings.Join(it.PublicExploitIn, ", "))
		}
		if it.URL != "" {
			fmt.Fprintf(a.Out, "%38s%s\n", "", it.URL)
		}
	}
	if len(r.Exploited) > 0 {
		fmt.Fprintln(a.Out, "\nFlaws exploited in the wild (CISA KEV), for the versions given:")
		for _, c := range r.Exploited {
			fmt.Fprintf(a.Out, "  %s@%s: %s\n", c.Tag, c.Version, c.Note())
		}
	}
	if len(r.Truncated) > 0 {
		fmt.Fprintf(a.Out, "\nSources with more entries than shown (%d per source, %d for the OSV sources asked about packages):\n", news.MaxPerSource, news.MaxOSVPerSource)
		for _, t := range r.Truncated {
			fmt.Fprintf(a.Out, "  %s: %d more entries left out, the least severe or the oldest (narrow with --since, more precise keywords or fewer packages)\n", t.Source, t.Dropped)
		}
	}
	if len(r.Short) > 0 {
		fmt.Fprintln(a.Out, "\nFeeds that do not go back to the start of the period (older news may be missing):")
		for _, c := range r.Short {
			fmt.Fprintf(a.Out, "  %s: since %s\n", c.Source, c.Since.Format("2006-01-02 15:04"))
		}
	}
	if len(r.Failures) > 0 {
		fmt.Fprintln(a.Out, "\nSources that could not be read (their news may be missing):")
		for _, f := range r.Failures {
			fmt.Fprintf(a.Out, "  %s: %s\n", f.Source, f.Error)
		}
	}
}

// printSummary writes one line per item, fields separated by " | ", then the
// failures, truncations and warnings: compact for agents, easy to grep.
func (a *App) printSummary(r newsReport) {
	for _, it := range r.Items {
		score := "-"
		if it.Score > 0 {
			score = fmt.Sprintf("%.1f", it.Score)
		}
		line := strings.Join([]string{it.Published.Format("2006-01-02"), string(it.Stage), it.Source, score, it.Title, it.URL}, " | ")
		if len(it.AlsoIn) > 0 {
			line += " | also in " + strings.Join(it.AlsoIn, ",")
		}
		if len(it.ExploitedIn) > 0 {
			line += " | EXPLOITED in the wild (" + strings.Join(it.ExploitedIn, ",") + ")"
		}
		if len(it.PublicExploitIn) > 0 {
			line += " | PUBLIC EXPLOIT (" + strings.Join(it.PublicExploitIn, ",") + ")"
		}
		if aff := affected(it); aff != "" {
			line += " | affects " + aff
		}
		if it.EPSS > 0 {
			line += " | EPSS " + epss(it.EPSS)
		}
		fmt.Fprintln(a.Out, line)
	}
	for _, c := range r.Exploited {
		fmt.Fprintf(a.Out, "KEV | %s@%s | %s\n", c.Tag, c.Version, c.Note())
	}
	for _, f := range r.Failures {
		fmt.Fprintf(a.Out, "FAILED | %s | %s\n", f.Source, f.Error)
	}
	for _, t := range r.Truncated {
		fmt.Fprintf(a.Out, "TRUNCATED | %s | %d more entries left out, the least severe or the oldest\n", t.Source, t.Dropped)
	}
	for _, c := range r.Short {
		fmt.Fprintf(a.Out, "SHORT | %s | its feed only goes back to %s\n", c.Source, c.Since.Format("2006-01-02 15:04"))
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(a.Out, "WARNING | %s\n", w)
	}
	if r.AlreadyReported > 0 {
		fmt.Fprintf(a.Out, "ALREADY REPORTED | %d items left out\n", r.AlreadyReported)
	}
	for _, ig := range r.Ignored {
		fmt.Fprintf(a.Out, "IGNORED | %s | %s | %s\n", ig.ID, ig.Title, ignoredNote(ig))
	}
}

func (a *App) eolCommand() *cobra.Command {
	var format, profilePath string
	cmd := &cobra.Command{
		Use:   "eol [name@version...]",
		Short: "Tell whether the runtimes and frameworks in use still get security fixes",
		Long: `Look up the support status of each component on endoflife.date: the cycle
its version belongs to, when its security fixes stop, and whether a newer
release of the same cycle is out.

Statuses, from the most urgent: eol (no more security fixes), ending (they
stop within 180 days), behind (a newer patch release is out), supported, and
unknown (not on endoflife.date, or a version too vague to find its cycle).
With --profile, the components are read from the stack of the profile.`,
		Example: "  stackalarm eol php@8.3.35 node@22 gitlab@17.5\n" +
			"  stackalarm eol --profile .stackalarm.yaml --format json",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !slices.Contains([]string{"text", "json"}, format) {
				return fmt.Errorf("--format %q: use text or json", format)
			}
			if profilePath != "" {
				p, err := watch.LoadProfile(profilePath)
				if err != nil {
					return fmt.Errorf("--profile: %w", err)
				}
				for _, c := range p.Stack {
					if c.Version == "unknown" {
						c.Version = ""
					}
					args = append(args, strings.TrimSuffix(c.Name+"@"+c.Version, "@"))
				}
			}
			if len(args) == 0 {
				return errors.New("name the components (php@8.3.35 node@22) or give --profile")
			}
			f := *a.Fetcher
			f.Now = a.Now
			if dir, err := a.CacheRoot(); err == nil {
				f.CacheDir = filepath.Join(dir, "stackalarm")
			}
			support, err := f.Support(cmd.Context(), args)
			if err != nil {
				return err
			}
			if format == "json" {
				enc := json.NewEncoder(a.Out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"generated_at": a.Now().UTC(), "components": support})
			}
			w := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "COMPONENT\tCYCLE\tSTATUS\tNOTE")
			for _, s := range support {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", strings.TrimSuffix(s.Name+" "+s.Version, " "), cmp.Or(s.Cycle, "-"), s.Status, s.Note)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&profilePath, "profile", "", "project profile written by the agent (.stackalarm.yaml): its stack is looked up")
	return cmd
}

func (a *App) sourcesCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "sources",
		Short: "List the watched sources and their tags",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if format == "json" {
				enc := json.NewEncoder(a.Out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"tags": source.Tags(a.Sources), "sources": a.Sources})
			}
			if format != "text" {
				return fmt.Errorf("--format %q: use text or json", format)
			}
			w := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SOURCE\tTAGS\tSTAGE\tNAME")
			for _, s := range a.Sources {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.ID, strings.Join(s.Tags, ","), s.Stage, s.Name)
			}
			w.Flush()
			fmt.Fprintf(a.Out, "\nTags: %s\n", strings.Join(source.Tags(a.Sources), ", "))
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

// maxAffected keeps a line short: some advisories name dozens of packages.
const maxAffected = 3

// affected describes the packages of an advisory: "vite 6.4.4 (fixed in 6.4.5)".
func affected(it news.Item) string {
	var parts []string
	for i, af := range it.Affected {
		if i == maxAffected {
			parts = append(parts, fmt.Sprintf("and %d more", len(it.Affected)-maxAffected))
			break
		}
		part := af.Package + " " + cmp.Or(af.Versions, "all versions")
		switch {
		case af.Fixed != "" && af.Status == news.StatusAffected && otherBranch(af.InUse, af.Fixed):
			// node 20 against a fix in 22.23.4: no patch release of 20 will come
			part += " (fixed in " + af.Fixed + ", not on the " + branchOf(af.InUse) + " branch: upgrade the branch)"
		case af.Fixed != "":
			part += " (fixed in " + af.Fixed + ")"
		case af.FixUnknown:
			part += " (fixed version not given)" // "<= 1.25.2" names the last affected release, not the fix
		default:
			part += " (no fix yet)"
		}
		switch af.Status {
		case news.StatusAffected:
			part += " [" + af.InUse + " in use: AFFECTED]"
		case news.StatusPossiblyAffected:
			part += " [" + af.InUse + " in use: POSSIBLY AFFECTED, the patch level decides]"
		case news.StatusNotAffected:
			part += " [" + af.InUse + " in use: not affected]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

// branchOf gives the major version of a version in use: "20" for 20.20.2.
func branchOf(v string) string {
	major, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), ".")
	return major
}

// otherBranch tells whether the first fixed version is on a later major
// version than the one in use, with numbers on both sides.
func otherBranch(inUse, fixed string) bool {
	a, errA := strconv.Atoi(branchOf(inUse))
	b, errB := strconv.Atoi(branchOf(fixed))
	return errA == nil && errB == nil && b > a
}

// epss writes a probability as a percentage: "0.4%", "37%".
func epss(p float64) string {
	if p < 0.1 {
		return fmt.Sprintf("%.1f%%", p*100)
	}
	return fmt.Sprintf("%.0f%%", p*100)
}

// knownEcosystem tells whether a prefix names a package ecosystem.
func knownEcosystem(e string) bool {
	return slices.Contains([]string{"npm", "pip", "composer", "rubygems", "go", "rust", "maven", "nuget", "pub", "erlang", "swift", "actions"}, news.NormalEcosystem(e))
}

// closeTags suggests the known tags close to an unknown one, rather than
// listing the hundreds of them.
func closeTags(tag string, known []string) string {
	var close []string
	for _, k := range known {
		if len(close) < 5 && (strings.Contains(k, tag) || strings.Contains(tag, k) && len(k) > 2) {
			close = append(close, k)
		}
	}
	if len(close) == 0 {
		return "run stackalarm sources to see the tags"
	}
	return "close tags: " + strings.Join(close, ", ") + "; run stackalarm sources to see them all"
}

func lower(s []string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, strings.ToLower(strings.TrimSpace(v)))
	}
	return out
}

// union appends the values of b missing from a.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var exploitedInTheWild = regexp.MustCompile(`(?i)\bexploited in the wild\b`)

// ignoreMatcher finds a CVE or GHSA id as a whole word, whatever its case.
func ignoreMatcher(id string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(^|[^\w-])` + regexp.QuoteMeta(strings.TrimSpace(id)) + `($|[^\w-])`)
}

// ignoredNote tells why an item was left out, and when the decision ends.
func ignoredNote(ig ignoredItem) string {
	note := ig.Reason
	if ig.Until != "" {
		note += " (until " + ig.Until + ")"
	}
	if ig.Exploited {
		note += " — EXPLOITED in the wild, kept ignored by even_if_exploited"
	}
	return note
}
