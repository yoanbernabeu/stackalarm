package news

import (
	"bytes"
	"cmp"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// entry is what every parser returns, before the source fields are added.
type entry struct {
	Title     string
	URL       string
	Published time.Time
	Summary   string
	Score     float64 // CVSS base score, when the source gives one
	EPSS      float64
	Affected  []Affected
	Stage     source.Stage // when the entry says more than its source
}

type xmlLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
	Text string `xml:",chardata"`
}

type xmlItem struct { // RSS 2.0, RSS 1.0 (RDF) and Atom in one shape
	Title       string    `xml:"title"`
	Links       []xmlLink `xml:"link"`
	GUID        string    `xml:"guid"`
	ID          string    `xml:"id"` // Atom
	PubDate     string    `xml:"pubDate"`
	Date        string    `xml:"date"` // dc:date
	Published   string    `xml:"published"`
	Updated     string    `xml:"updated"`
	Description string    `xml:"description"`
	Summary     string    `xml:"summary"`
	Content     string    `xml:"content"`
}

type xmlFeed struct {
	Channel struct {
		Items []xmlItem `xml:"item"`
	} `xml:"channel"`
	Items   []xmlItem `xml:"item"`  // RSS 1.0 puts items at the root
	Entries []xmlItem `xml:"entry"` // Atom
}

// parseFeed reads RSS 2.0, RSS 1.0 (RDF) and Atom documents.
func parseFeed(data []byte) ([]entry, error) {
	var f xmlFeed
	dec := xml.NewDecoder(bytes.NewReader(stripControl(data)))
	dec.Strict = false
	dec.CharsetReader = charsetReader
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("not a valid RSS or Atom feed: %w", err)
	}
	var out []entry
	for _, it := range append(append(f.Channel.Items, f.Items...), f.Entries...) {
		e := entry{
			Title:   clean(it.Title),
			URL:     it.link(),
			Summary: clean(firstNonEmpty(it.Description, it.Summary, it.Content)),
		}
		e.Published, _ = parseDate(firstNonEmpty(it.PubDate, it.Date, it.Published, it.Updated))
		out = append(out, e)
	}
	return out, nil
}

// stripControl removes the control characters XML forbids, which some
// feeds let through and which would make the whole feed unreadable.
// It works on bytes, so it is safe for any charset: a multi-byte UTF-8
// sequence never contains a byte below 0x80.
func stripControl(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for _, b := range data {
		if b >= 0x20 || b == '\t' || b == '\n' || b == '\r' {
			out = append(out, b)
		}
	}
	return out
}

func (it xmlItem) link() string {
	for _, l := range it.Links {
		if l.Href != "" && (l.Rel == "" || l.Rel == "alternate") {
			return strings.TrimSpace(l.Href)
		}
		if t := strings.TrimSpace(l.Text); t != "" && l.Rel == "" { // RSS <link>url</link>
			return t
		}
	}
	for _, id := range []string{it.GUID, it.ID} { // permalinks, or Atom ids that are URLs
		if id = strings.TrimSpace(id); strings.HasPrefix(id, "http") {
			return id
		}
	}
	return ""
}

// charsetReader accepts the charsets met in the wild besides UTF-8.
func charsetReader(label string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return in, nil
	case "iso-8859-1", "latin1", "latin-1", "windows-1252":
		data, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}
		runes := make([]rune, len(data))
		for i, b := range data {
			runes[i] = rune(b)
		}
		return strings.NewReader(string(runes)), nil
	}
	return nil, fmt.Errorf("unsupported charset %q", label)
}

var dateLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339, time.RFC3339Nano,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST",
	"2 Jan 2006 15:04:05 -0700", "2006-01-02T15:04:05.000", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02",
	"Jan 2, 2006, 3:04:05 PM", // EUVD
}

func parseDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unknown date format %q", s)
}

// parseGitHubAdvisoryDatabase reads GET /advisories, keeping high and
// critical advisories: an ecosystem publishes dozens a week, and the agent
// finds the others with the ecosystem's own audit tool.
func parseGitHubAdvisoryDatabase(data []byte) ([]entry, error) {
	return parseGitHub(data, func(severity string) bool {
		return severity == "high" || severity == "critical" || severity == "" || severity == "unknown"
	})
}

// parseGitHubMalware reads GET /advisories?type=malware: a package version
// published with malicious code, an alert for a project that installs it.
func parseGitHubMalware(data []byte) ([]entry, error) {
	entries, err := parseGitHub(data, func(string) bool { return true })
	for i := range entries {
		entries[i].Title = "[malware] " + strings.TrimPrefix(strings.TrimPrefix(entries[i].Title, "[critical] "), "[unknown] ")
		entries[i].Stage = source.StageAlert
	}
	return entries, err
}

// parseGitHubAdvisories reads GET /repos/{owner}/{repo}/security-advisories.
func parseGitHubAdvisories(data []byte) ([]entry, error) {
	return parseGitHub(data, func(string) bool { return true })
}

func parseGitHub(data []byte, keepSeverity func(string) bool) ([]entry, error) {
	type score struct {
		Score float64 `json:"score"`
	}
	var advisories []struct {
		GHSA           string           `json:"ghsa_id"`
		CVE            string           `json:"cve_id"`
		URL            string           `json:"html_url"`
		Summary        string           `json:"summary"`
		Description    string           `json:"description"`
		Severity       string           `json:"severity"`
		PublishedAt    string           `json:"published_at"`
		CVSS           score            `json:"cvss"`
		CVSSSeverities map[string]score `json:"cvss_severities"`
		EPSS           struct {
			Percentage float64 `json:"percentage"`
		} `json:"epss"`
		Vulnerabilities []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Range        string `json:"vulnerable_version_range"`
			FirstPatched string `json:"first_patched_version"` // GitHub Advisory Database
			Patched      string `json:"patched_versions"`      // repository advisories
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &advisories); err != nil {
		return nil, fmt.Errorf("unexpected GitHub response: %w", err)
	}
	var out []entry
	for _, a := range advisories {
		if !keepSeverity(a.Severity) {
			continue
		}
		title := a.Summary
		if a.Severity != "" {
			title = "[" + a.Severity + "] " + title
		}
		if id := firstNonEmpty(a.CVE, a.GHSA); id != "" {
			title += " (" + id + ")"
		}
		e := entry{Title: clean(title), URL: a.URL, Summary: clean(a.Description), Score: a.CVSS.Score, EPSS: a.EPSS.Percentage}
		for _, s := range a.CVSSSeverities {
			e.Score = max(e.Score, s.Score)
		}
		for _, v := range a.Vulnerabilities {
			if v.Package.Name != "" {
				e.Affected = append(e.Affected, Affected{Package: v.Package.Name, Versions: v.Range, Fixed: cmp.Or(v.FirstPatched, v.Patched)})
			}
		}
		e.Published, _ = parseDate(a.PublishedAt)
		out = append(out, e)
	}
	return out, nil
}

// parseKEV reads the CISA Known Exploited Vulnerabilities catalog.
func parseKEV(data []byte) ([]entry, error) {
	var catalog struct {
		Vulnerabilities []struct {
			CVE         string `json:"cveID"`
			Vendor      string `json:"vendorProject"`
			Product     string `json:"product"`
			Name        string `json:"vulnerabilityName"`
			DateAdded   string `json:"dateAdded"`
			Description string `json:"shortDescription"`
			Action      string `json:"requiredAction"`
			Ransomware  string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("unexpected KEV catalog: %w", err)
	}
	var out []entry
	for _, v := range catalog.Vulnerabilities {
		e := entry{
			Title:   fmt.Sprintf("%s exploited in the wild: %s %s, %s", v.CVE, v.Vendor, v.Product, v.Name),
			URL:     "https://nvd.nist.gov/vuln/detail/" + v.CVE,
			Summary: clean(v.Description + " Required action: " + v.Action),
		}
		if v.Ransomware == "Known" {
			e.Summary += " Used in ransomware campaigns."
		}
		e.Published, _ = parseDate(v.DateAdded)
		out = append(out, e)
	}
	return out, nil
}

var (
	tags   = regexp.MustCompile(`(?s)<[^>]*>`)
	spaces = regexp.MustCompile(`\s+`)
)

const maxSummary = 600 // runes: enough for an LLM to judge, short enough to read many

// clean turns HTML into one line of plain text, cut to maxSummary runes.
func clean(s string) string {
	s = html.UnescapeString(tags.ReplaceAllString(html.UnescapeString(s), " "))
	s = strings.TrimSpace(spaces.ReplaceAllString(s, " "))
	if utf8.RuneCountInString(s) > maxSummary {
		s = string([]rune(s)[:maxSummary]) + "…"
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// minScore drops low-severity entries from the CVE databases, which publish
// hundreds of records a day. Unscored records are kept: new CVEs often wait
// days for a score, and those are the ones that matter most.
const minScore = 7.0

// parseNVD reads a response of the NVD CVE API 2.0.
func parseNVD(data []byte) ([]entry, error) {
	var r struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					Data struct {
						Score    float64 `json:"baseScore"`
						Severity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unexpected NVD response: %w", err)
	}
	var out []entry
	for _, v := range r.Vulnerabilities {
		var score float64
		for _, ms := range v.CVE.Metrics {
			for _, m := range ms {
				score = max(score, m.Data.Score)
			}
		}
		if score != 0 && score < minScore {
			continue
		}
		var desc string
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" || desc == "" {
				desc = d.Value
			}
		}
		e := entry{Title: cveTitle(v.CVE.ID, "", score, desc), URL: "https://nvd.nist.gov/vuln/detail/" + v.CVE.ID, Summary: clean(desc), Score: score}
		e.Published, _ = parseDate(v.CVE.Published)
		out = append(out, e)
	}
	if r.TotalResults > len(r.Vulnerabilities) { // one page holds 2,000 records
		return out, fmt.Errorf("partial: %d records, only %d read (use more precise keywords or a shorter --since)", r.TotalResults, len(r.Vulnerabilities))
	}
	return out, nil
}

// euvdTotal reads the number of records an EUVD search matched, over all pages.
func euvdTotal(data []byte) int {
	var r struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(data, &r) // a list endpoint has no total: one page
	return r.Total
}

// parseEUVD reads a list or a search result of the ENISA EUVD API.
func parseEUVD(data []byte) ([]entry, error) {
	type record struct {
		ID             string          `json:"id"`
		Description    string          `json:"description"`
		DatePublished  string          `json:"datePublished"`
		BaseScore      json.RawMessage `json:"baseScore"` // a number or a string, depending on the endpoint
		Aliases        string          `json:"aliases"`
		ExploitedSince string          `json:"exploitedSince"`
	}
	var list []record
	if err := json.Unmarshal(data, &list); err != nil {
		var search struct {
			Items []record `json:"items"`
		}
		if err := json.Unmarshal(data, &search); err != nil {
			return nil, fmt.Errorf("unexpected EUVD response: %w", err)
		}
		list = search.Items
	}
	var out []entry
	for _, r := range list {
		var score float64
		fmt.Sscan(strings.Trim(string(r.BaseScore), `"`), &score)
		if score != 0 && score < minScore && r.ExploitedSince == "" {
			continue
		}
		cve := ""
		for _, a := range strings.Fields(r.Aliases) {
			if strings.HasPrefix(a, "CVE-") {
				cve = a
				break
			}
		}
		title := cveTitle(cmp.Or(cve, r.ID), r.ID, score, r.Description)
		if r.ExploitedSince != "" {
			title = "Exploited in the wild: " + title
		}
		e := entry{Title: title, URL: "https://euvd.enisa.europa.eu/vulnerability/" + r.ID, Summary: clean(r.Description), Score: score}
		e.Published, _ = parseDate(cmp.Or(r.ExploitedSince, r.DatePublished))
		out = append(out, e)
	}
	return out, nil
}

// cveTitle builds "CVE-2026-1 (EUVD-2026-2) [9.8]: first words of the description".
func cveTitle(id, alias string, score float64, desc string) string {
	t := id
	if alias != "" && alias != id {
		t += " (" + alias + ")"
	}
	if score > 0 {
		t += fmt.Sprintf(" [%.1f]", score)
	}
	desc = clean(desc)
	if r := []rune(desc); len(r) > 140 {
		desc = string(r[:140]) + "…"
	}
	return t + ": " + desc
}
