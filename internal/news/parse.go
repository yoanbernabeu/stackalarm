package news

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// entry is what every parser returns, before the source fields are added.
type entry struct {
	Title     string
	URL       string
	Published time.Time
	Summary   string
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
	dec := xml.NewDecoder(bytes.NewReader(data))
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
	"2 Jan 2006 15:04:05 -0700", "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02",
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

// parseGitHubAdvisories reads GET /repos/{owner}/{repo}/security-advisories.
func parseGitHubAdvisories(data []byte) ([]entry, error) {
	var advisories []struct {
		GHSA        string `json:"ghsa_id"`
		CVE         string `json:"cve_id"`
		URL         string `json:"html_url"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		PublishedAt string `json:"published_at"`
	}
	if err := json.Unmarshal(data, &advisories); err != nil {
		return nil, fmt.Errorf("unexpected GitHub response: %w", err)
	}
	var out []entry
	for _, a := range advisories {
		title := a.Summary
		if a.Severity != "" {
			title = "[" + a.Severity + "] " + title
		}
		if id := firstNonEmpty(a.CVE, a.GHSA); id != "" {
			title += " (" + id + ")"
		}
		e := entry{Title: clean(title), URL: a.URL, Summary: clean(a.Description)}
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
