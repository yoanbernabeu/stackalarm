package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yoanbernabeu/stackalarm/internal/news"
)

func (a *App) cveCommand() *cobra.Command {
	var (
		format  string
		noCache bool
	)
	cmd := &cobra.Command{
		Use:   "cve CVE-YYYY-NNNN [name@version...]",
		Short: "Gather what the databases say of one CVE",
		Long: `Look one CVE up in the CVE Program record (with the CISA Vulnrichment
decision points), the NVD, the GitHub Advisory Database, the lists of flaws
exploited in the wild (CISA KEV, EUVD), the catalogs of public exploits (Nuclei
templates, Metasploit modules) and EPSS, and print one record: what is
affected, what fixes it, and how likely it is to be exploited.

Give the versions in use after the id (next@15.1.0 php@8.3.20): each affected
range is then marked "affected" or "not-affected". A database that cannot be
read is reported, and the others still answer.`,
		Example: "  stackalarm cve CVE-2025-29927\n" +
			"  stackalarm cve CVE-2025-29927 next@15.1.0 --format json",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToUpper(strings.TrimSpace(args[0]))
			if !news.ValidCVE(id) {
				return fmt.Errorf("%q is not a CVE id (CVE-2025-29927)", args[0])
			}
			if !slices.Contains([]string{"text", "json"}, format) {
				return fmt.Errorf("--format %q: use text or json", format)
			}
			f := *a.Fetcher
			f.Now = a.Now
			f.GitHubToken = firstNonEmpty(a.Getenv("GITHUB_TOKEN"), a.Getenv("GH_TOKEN"))
			f.NVDAPIKey = a.Getenv("NVD_API_KEY")
			if !noCache {
				if dir, err := a.CacheRoot(); err == nil {
					f.CacheDir = filepath.Join(dir, "stackalarm")
				}
			}
			rec := f.CVE(cmd.Context(), id, a.Sources, args[1:])
			if format == "json" {
				enc := json.NewEncoder(a.Out)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					GeneratedAt time.Time `json:"generated_at"`
					news.CVERecord
				}{a.Now().UTC(), rec})
			}
			a.printCVE(rec)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "always fetch the databases (responses are otherwise reused for an hour)")
	return cmd
}

// maxCVEAffected keeps the record readable: the NVD can list dozens of
// products a flaw reaches through a bundled copy. The ranges of the versions
// given come first, so they are never the ones cut.
const maxCVEAffected = 12

func (a *App) printCVE(r news.CVERecord) {
	w := a.Out
	if len(r.FoundIn) == 0 {
		fmt.Fprintf(w, "%s: not found in any database (a reserved id is not published yet; check the number).\n", r.ID)
	} else {
		head := r.ID
		if r.Title != "" {
			head += ": " + r.Title
		}
		fmt.Fprintln(w, head)
		if r.State != "" && r.State != "PUBLISHED" {
			fmt.Fprintf(w, "State: %s\n", r.State)
		}
		var facts []string
		if r.Published != "" {
			facts = append(facts, "published "+r.Published)
		}
		if r.Score > 0 {
			facts = append(facts, fmt.Sprintf("CVSS %.1f", r.Score))
		}
		if r.EPSS > 0 {
			facts = append(facts, "EPSS "+epss(r.EPSS)+" (probability of exploitation within 30 days)")
		}
		if len(facts) > 0 {
			fmt.Fprintln(w, strings.Join(facts, ", "))
		}
		if r.Description != "" {
			fmt.Fprintf(w, "\n%s\n", r.Description)
		}
		fmt.Fprintln(w, "\nExploitation:")
		switch {
		case len(r.ExploitedIn) > 0:
			fmt.Fprintf(w, "  EXPLOITED in the wild (%s)\n", strings.Join(r.ExploitedIn, ", "))
			if r.Exploitation != "" {
				fmt.Fprintf(w, "  %s\n", r.Exploitation)
			}
		default:
			fmt.Fprintln(w, "  not in the lists of flaws exploited in the wild (CISA KEV, EUVD)")
		}
		if len(r.PublicExploitIn) > 0 {
			fmt.Fprintf(w, "  PUBLIC EXPLOIT available (%s)\n", strings.Join(r.PublicExploitIn, ", "))
		}
		if len(r.SSVC) > 0 {
			var parts []string
			for _, k := range []string{"exploitation", "automatable", "technical_impact"} {
				if v := r.SSVC[k]; v != "" {
					parts = append(parts, strings.ReplaceAll(k, "_", " ")+" "+v)
				}
			}
			fmt.Fprintf(w, "  CISA assessment (SSVC): %s\n", strings.Join(parts, ", "))
		}
		if len(r.Affected) > 0 {
			fmt.Fprintln(w, "\nAffected:")
			for i, af := range r.Affected {
				if i == maxCVEAffected {
					fmt.Fprintf(w, "  and %d more ranges, of other products or versions (--format json lists them all)\n", len(r.Affected)-maxCVEAffected)
					break
				}
				fmt.Fprintf(w, "  %s\n", affected(news.Item{Affected: []news.Affected{af}}))
			}
		}
		if len(r.Advisories) > 0 {
			fmt.Fprintln(w, "\nAdvisories:")
			for _, u := range r.Advisories {
				fmt.Fprintf(w, "  %s\n", u)
			}
		}
		if len(r.References) > 0 {
			fmt.Fprintln(w, "\nReferences:")
			for _, u := range r.References {
				fmt.Fprintf(w, "  %s\n", u)
			}
		}
		fmt.Fprintf(w, "\nFound in: %s\n%s\n", strings.Join(r.FoundIn, ", "), news.CVEURL(r.ID))
	}
	if len(r.Failures) > 0 {
		fmt.Fprintln(w, "\nDatabases that could not be read (their answer is missing):")
		for _, f := range r.Failures {
			fmt.Fprintf(w, "  %s: %s\n", f.Source, f.Error)
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
