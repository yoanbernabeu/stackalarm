package cli

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/yoanbernabeu/stackalarm/internal/news"
	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// markdownSections orders the stages by urgency, for a reader skimming an issue.
// The long tail (CVE records, press) is folded, so the signal stays on top.
var markdownSections = []struct {
	stage  source.Stage
	title  string
	noun   string
	folded bool
}{
	{source.StageHeadsUp, "Heads-up: security releases announced", "heads-up", false},
	{source.StageAlert, "Alerts: CERT alerts, public exploits, exploitation in the wild", "alert", false},
	{source.StageRelease, "Releases with security fixes", "release", false},
	{source.StageAdvisory, "Advisories", "advisory", true},
	{source.StageNews, "Press and research", "news item", true},
}

// printMarkdown writes the report as an issue body for a scheduled watch.
// Titles come from third parties: they are escaped so that they cannot
// mention people, embed images or break the layout.
func (a *App) printMarkdown(r newsReport) {
	w := a.Out
	byStage := map[source.Stage][]news.Item{}
	for _, it := range r.Items {
		byStage[it.Stage] = append(byStage[it.Stage], it)
	}
	headline := "nothing new"
	if len(r.Items) > 0 {
		var counts []string
		for _, sec := range markdownSections {
			if n := len(byStage[sec.stage]); n > 0 {
				counts = append(counts, fmt.Sprintf("%d %s", n, pluralize(sec.noun, n)))
			}
		}
		headline = strings.Join(counts, ", ")
	}
	fmt.Fprintf(w, "## stackalarm: %s\n\n", headline)
	watched := strings.Join(r.Tags, ", ")
	if len(r.Keywords) > 0 {
		watched += " (keywords: " + strings.Join(r.Keywords, ", ") + ")"
	}
	if len(r.Packages) > 0 {
		watched += fmt.Sprintf(", %d package%s", len(r.Packages), plural(len(r.Packages)))
	}
	fmt.Fprintf(w, "Watched: %s, since %s.\n", mdText(watched), r.Since.Format("2006-01-02 15:04 MST"))
	if len(r.Stack) > 0 {
		var parts []string
		for _, c := range r.Stack {
			part := c.Name + " " + cmp.Or(c.Version, "unknown version")
			if c.Precision != "" && c.Precision != "unknown" {
				part += " (" + c.Precision + ")"
			}
			if c.From != "" {
				part += " from " + c.From
			}
			parts = append(parts, part)
		}
		fmt.Fprintf(w, "Stack: %s.\n", mdText(strings.Join(parts, "; ")))
	}
	if r.AlreadyReported > 0 {
		fmt.Fprintf(w, "Left out, already reported by an earlier run: %d item%s.\n", r.AlreadyReported, plural(r.AlreadyReported))
	}
	for _, sec := range markdownSections {
		items := byStage[sec.stage]
		if len(items) == 0 {
			continue
		}
		if sec.folded {
			fmt.Fprintf(w, "\n<details><summary><b>%s</b> (%d)</summary>\n\n", sec.title, len(items))
		} else {
			fmt.Fprintf(w, "\n### %s\n\n", sec.title)
		}
		for _, it := range items {
			line := fmt.Sprintf("- %s · **%s** · %s", it.Published.Format("2006-01-02"), mdText(it.Title), it.Source)
			if it.Score > 0 {
				line += fmt.Sprintf(", CVSS %.1f", it.Score)
			}
			if len(it.AlsoIn) > 0 {
				line += ", also in " + strings.Join(it.AlsoIn, ", ")
			}
			if it.EPSS > 0 {
				line += ", EPSS " + epss(it.EPSS)
			}
			if aff := affected(it); aff != "" {
				line += "\n  Affects " + mdText(aff)
			}
			if link := mdLink(it.URL); link != "" {
				line += "\n  " + link
			}
			fmt.Fprintln(w, line)
		}
		if sec.folded {
			fmt.Fprintln(w, "\n</details>")
		}
	}
	if len(r.Failures) > 0 {
		fmt.Fprint(w, "\n### Sources that could not be read\n\nTheir news may be missing from this report.\n\n")
		for _, f := range r.Failures {
			fmt.Fprintf(w, "- %s: %s\n", f.Source, mdText(f.Error))
		}
	}
	if len(r.Truncated) > 0 {
		fmt.Fprintf(w, "\n### Sources with more entries than shown\n\nOnly the %d most relevant entries of each are listed.\n\n", news.MaxPerSource)
		for _, t := range r.Truncated {
			fmt.Fprintf(w, "- %s: %d left out\n", t.Source, t.Dropped)
		}
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "\n> Warning: %s\n", mdText(warn))
	}
	if len(r.Items) > 0 {
		fmt.Fprintln(w, "\n---\n\nThis list is raw news, not a verdict. To know whether the project is affected, open it in your AI agent and run `/stackalarm triage <link to this issue>`.")
	}
}

var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "#", `\#`, "|", `\|`, "!", `\!`, "~", `\~`,
	"<", "&lt;", ">", "&gt;", "&", "&amp;",
	"@", "@​", // no mention of a GitHub or GitLab user
	"\r", " ", "\n", " ",
)

// mdText escapes third-party text for one line of Markdown.
func mdText(s string) string { return mdEscaper.Replace(strings.TrimSpace(s)) }

// mdLink returns an autolink, or nothing for a link that is not plain http(s).
func mdLink(u string) string {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") || strings.ContainsAny(u, " \t\r\n<>") {
		return ""
	}
	return "<" + u + ">"
}

func pluralize(noun string, n int) string {
	switch {
	case n == 1:
		return noun
	case strings.HasSuffix(noun, "y"):
		return strings.TrimSuffix(noun, "y") + "ies"
	}
	return noun + "s"
}

func plural(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}
