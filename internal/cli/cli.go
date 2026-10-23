// Package cli implements the stackalarm command line.
package cli

import (
	"cmp"
	"context"
	"encoding/json"
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
			Client:    &http.Client{Timeout: 20 * time.Second},
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
		fmt.Fprintln(a.Err, "Error:", err)
		return 1
	}
	return 0
}

type newsReport struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Since       time.Time         `json:"since"`
	Tags        []string          `json:"tags"`
	Keywords    []string          `json:"keywords"`
	Items       []news.Item       `json:"items"`
	Failures    []news.Failure    `json:"failures"`
	Truncated   []news.Truncation `json:"truncated"`
	Warnings    []string          `json:"warnings"`
}

func (a *App) newsCommand() *cobra.Command {
	var (
		tags, keywords []string
		since, format  string
		noCache        bool
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
Run "stackalarm sources" to see the available tags.`,
		Example: "  stackalarm news --tag php --tag symfony --since 7d\n  stackalarm news --tag node --keyword express --format json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			window, err := news.ParseSince(since)
			if err != nil {
				return fmt.Errorf("--since %q: %w", since, err)
			}
			if format != "text" && format != "json" {
				return fmt.Errorf("--format %q: use text or json", format)
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
			res := f.Fetch(cmd.Context(), a.Sources, news.Query{Tags: tags, Keywords: keywords, Since: now.Add(-window)})
			report := newsReport{
				GeneratedAt: now, Since: now.Add(-window), Tags: nonNil(tags), Keywords: nonNil(keywords),
				Items: res.Items, Failures: res.Failures, Truncated: res.Truncated, Warnings: nonNil(warnings),
			}
			if format == "json" {
				enc := json.NewEncoder(a.Out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			a.printNews(report)
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&tags, "tag", "t", nil, "technology to watch, repeatable (php, node, gitlab…)")
	cmd.Flags().StringSliceVarP(&keywords, "keyword", "k", nil, "extra word to look for in general sources, repeatable (frankenphp, express…)")
	cmd.Flags().StringVar(&since, "since", "7d", "how far back to look: 24h, 7d, 2w…")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "always fetch the sources (responses are otherwise reused for an hour)")
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

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
