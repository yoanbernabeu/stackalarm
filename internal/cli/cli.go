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
	"slices"
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
	return &App{
		Out: os.Stdout, Err: os.Stderr, Sources: srcs, Now: time.Now, Version: version,
		Getenv: os.Getenv, CacheRoot: os.UserCacheDir,
		Fetcher: &news.Fetcher{
			Client:    &http.Client{Timeout: 45 * time.Second}, // the NVD API is often slow
			UserAgent: "stackalarm/" + version + " (+https://github.com/yoanbernabeu/stackalarm)",
			CacheTTL:  time.Hour,
			NVDDelay:  6 * time.Second, // 5 requests per 30 s without a key
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
	root.AddCommand(a.newsCommand(), a.sourcesCommand())
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
	GeneratedAt time.Time         `json:"generated_at"`
	Since       time.Time         `json:"since"`
	Tags        []string          `json:"tags"`
	Keywords    []string          `json:"keywords"`
	Packages    []string          `json:"packages,omitempty"`
	Stack       []watch.Component `json:"stack,omitempty"` // from the profile
	Items       []news.Item       `json:"items"`
	Failures    []news.Failure    `json:"failures"`
	Truncated   []news.Truncation `json:"truncated"`
	Warnings    []string          `json:"warnings"`
	// AlreadyReported counts the items left out because the state file says
	// an earlier run reported them.
	AlreadyReported int `json:"already_reported,omitempty"`
}

func (a *App) newsCommand() *cobra.Command {
	var (
		tags, keywords []string
		packages       []string
		since, format  string
		noCache        bool
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

For a scheduled watch, --profile reads the tags, keywords and packages from a
file the agent wrote, --state shows only the items no earlier run reported, and
--fail-on exits with code 2 when a new item has one of the given stages.`,
		Example: "  stackalarm news --tag php --tag symfony --since 7d\n" +
			"  stackalarm news --tag node --tag npm --package express,dompurify --format json\n" +
			"  stackalarm news --profile .stackalarm.yaml --state .stackalarm-state --fail-on heads-up,alert,release --since 48h --format markdown",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			window, err := news.ParseSince(since)
			if err != nil {
				return fmt.Errorf("--since %q: %w", since, err)
			}
			if !slices.Contains([]string{"text", "summary", "json", "markdown"}, format) {
				return fmt.Errorf("--format %q: use text, summary, json or markdown", format)
			}
			for _, st := range lower(failOn) {
				if !slices.Contains(source.Stages, source.Stage(st)) {
					return fmt.Errorf("--fail-on %q: use stages among %v", st, source.Stages)
				}
			}
			var stack []watch.Component
			if profilePath != "" {
				p, err := watch.LoadProfile(profilePath)
				if err != nil {
					return fmt.Errorf("--profile: %w", err)
				}
				tags, keywords, packages = union(p.Tags, tags), union(p.Keywords, keywords), union(p.Packages, packages)
				stack = p.Stack
			}
			var state watch.State
			if statePath != "" {
				if state, err = watch.LoadState(statePath); err != nil {
					return fmt.Errorf("--state: %w", err)
				}
			}
			// An unknown tag is searched as a keyword in the general sources rather
			// than failing: agents guess tags, and a guess should still help.
			var warnings []string
			known := source.Tags(a.Sources)
			tags = slices.DeleteFunc(lower(tags), func(t string) bool {
				if slices.Contains(known, t) {
					return false
				}
				keywords = append(keywords, t)
				warnings = append(warnings, fmt.Sprintf("no source is tagged %q: searched as a keyword in the general sources instead (known tags: %s)", t, strings.Join(known, ", ")))
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
			now := a.Now().UTC()
			res := f.Fetch(cmd.Context(), a.Sources, news.Query{Tags: tags, Keywords: keywords, Since: now.Add(-window), Packages: packages})
			report := newsReport{
				GeneratedAt: now, Since: now.Add(-window), Tags: nonNil(tags), Keywords: nonNil(keywords), Packages: packages, Stack: stack,
				Items: res.Items, Failures: res.Failures, Truncated: res.Truncated, Warnings: nonNil(warnings),
			}
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
	cmd.Flags().StringSliceVarP(&tags, "tag", "t", nil, "technology to watch, repeatable (php, node, gitlab…)")
	cmd.Flags().StringSliceVarP(&keywords, "keyword", "k", nil, "extra word to look for in general sources, repeatable (frankenphp, express…)")
	cmd.Flags().StringSliceVarP(&packages, "package", "p", nil, "package names from the lockfile, repeatable: GitHub Advisory Database sources then return only their advisories")
	cmd.Flags().StringVar(&since, "since", "7d", "how far back to look: 24h, 7d, 2w…")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, summary (one line per item, for agents), json or markdown (an issue body)")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "always fetch the sources (responses are otherwise reused for an hour)")
	cmd.Flags().StringVar(&profilePath, "profile", "", "project profile written by the agent (.stackalarm.yaml): tags, keywords and packages to watch")
	cmd.Flags().StringVar(&statePath, "state", "", "file remembering the items already reported: only new ones are shown")
	cmd.Flags().StringSliceVar(&failOn, "fail-on", nil, "exit with code 2 when a new item has one of these stages (heads-up, alert, release…)")
	return cmd
}

func (a *App) printNews(r newsReport) {
	scope := "all sources"
	if len(r.Tags) > 0 {
		scope = strings.Join(r.Tags, ", ")
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
	for _, it := range r.Items {
		fmt.Fprintf(a.Out, "%s  %-9s %-24s %s\n", it.Published.Format("2006-01-02"), it.Stage, it.Source, it.Title)
		if it.URL != "" {
			fmt.Fprintf(a.Out, "%38s%s\n", "", it.URL)
		}
	}
	if len(r.Truncated) > 0 {
		fmt.Fprintf(a.Out, "\nOnly the %d most recent entries are shown for:\n", news.MaxPerSource)
		for _, t := range r.Truncated {
			fmt.Fprintf(a.Out, "  %s: %d older entries left out (narrow with --since or more precise keywords)\n", t.Source, t.Dropped)
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
		fmt.Fprintln(a.Out, line)
	}
	for _, f := range r.Failures {
		fmt.Fprintf(a.Out, "FAILED | %s | %s\n", f.Source, f.Error)
	}
	for _, t := range r.Truncated {
		fmt.Fprintf(a.Out, "TRUNCATED | %s | %d older entries left out\n", t.Source, t.Dropped)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(a.Out, "WARNING | %s\n", w)
	}
	if r.AlreadyReported > 0 {
		fmt.Fprintf(a.Out, "ALREADY REPORTED | %d items left out\n", r.AlreadyReported)
	}
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
