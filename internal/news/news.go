// Package news fetches the watched sources and turns their entries into one
// list of items, filtered by tag and date.
package news

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// Item is one entry of a source.
type Item struct {
	Source    string       `json:"source"`
	Tags      []string     `json:"tags"`
	Stage     source.Stage `json:"stage"`
	Title     string       `json:"title"`
	URL       string       `json:"url,omitempty"`
	Published time.Time    `json:"published"`
	Summary   string       `json:"summary,omitempty"`
	Score     float64      `json:"score,omitempty"` // CVSS base score, for CVE databases
	Language  string       `json:"language,omitempty"`
	AlsoIn    []string     `json:"also_in,omitempty"` // other databases listing the same CVE

	cve string // CVE id of a CVE database entry, used to merge duplicates
}

// Failure is a source that could not be read. It is always reported: a
// silent watch tool is worse than a noisy one.
type Failure struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

// Truncation tells that a source had more entries than shown.
type Truncation struct {
	Source  string `json:"source"`
	Dropped int    `json:"dropped"` // the oldest entries left out
}

// Result is the outcome of a fetch.
type Result struct {
	Items     []Item       `json:"items"`
	Failures  []Failure    `json:"failures"`
	Truncated []Truncation `json:"truncated"`
}

// MaxPerSource keeps the output readable for a person or an agent: a CVE
// database can return hundreds of records for a common word.
const MaxPerSource = 30

// Query selects what to fetch.
type Query struct {
	Tags     []string  // empty: every source
	Keywords []string  // extra words that select entries of general sources
	Since    time.Time // entries published before are dropped
	// Packages narrow the GitHub Advisory Database sources to these package
	// names (the agent reads them from the lockfile). Empty: the whole ecosystem.
	Packages []string
}

// Fetcher reads sources over HTTP, with a small on-disk cache.
type Fetcher struct {
	Client      *http.Client
	UserAgent   string
	GitHubToken string        // optional, raises the GitHub API rate limit
	GitHubAPI   string        // https://api.github.com unless a test changes it
	NVDAPIKey   string        // optional, raises the NVD API rate limit
	NVDDelay    time.Duration // pause between two NVD requests (the API allows 5 per 30 s without key)
	CacheDir    string        // empty disables the cache
	CacheTTL    time.Duration // how long a cached response is reused
	Now         func() time.Time
}

// Fetch reads the sources selected by q, in parallel.
func (f *Fetcher) Fetch(ctx context.Context, sources []source.Source, q Query) Result {
	selected := selectSources(sources, q.Tags)
	terms := searchTerms(q)
	words := matchers(terms)
	nvd := &gate{delay: f.NVDDelay}

	var (
		mu  sync.Mutex
		res = Result{Items: []Item{}, Failures: []Failure{}, Truncated: []Truncation{}}
		wg  sync.WaitGroup
	)
	for _, s := range selected {
		if s.Type.IsSearch() && len(terms) == 0 {
			continue // nothing to search for
		}
		wg.Go(func() {
			entries, err := f.read(ctx, s, terms, q, nvd)
			mu.Lock()
			defer mu.Unlock()
			if err != nil { // a search may fail for one word and succeed for others
				res.Failures = append(res.Failures, Failure{Source: s.ID, Error: err.Error()})
			}
			entries = slices.DeleteFunc(entries, func(e entry) bool {
				if e.Published.IsZero() || e.Published.Before(q.Since) {
					return true
				}
				if s.Type.IsSearch() { // the databases match loosely ("node.js" finds kernel "node"): check the whole term
					text := e.Title + " " + e.Summary
					return !slices.ContainsFunc(words, func(re *regexp.Regexp) bool { return re.MatchString(text) })
				}
				return !keep(s, e, words)
			})
			slices.SortStableFunc(entries, func(a, b entry) int {
				if s.Type.IsSearch() { // most severe first, so the cap drops the minor ones
					if c := cmp.Compare(priority(b.Score), priority(a.Score)); c != 0 {
						return c
					}
				}
				return b.Published.Compare(a.Published)
			})
			if len(entries) > MaxPerSource {
				res.Truncated = append(res.Truncated, Truncation{Source: s.ID, Dropped: len(entries) - MaxPerSource})
				entries = entries[:MaxPerSource]
			}
			for _, e := range entries {
				stage := s.Stage
				if stage == source.StageHeadsUp && releasedTitle.MatchString(e.Title) {
					stage = source.StageRelease // a heads-up feed also announces the release itself
				}
				item := Item{
					Source: s.ID, Tags: s.Tags, Stage: stage, Title: e.Title, URL: absolute(s.URL, e.URL),
					Published: e.Published, Summary: e.Summary, Score: e.Score, Language: s.Language,
				}
				if mergeable(s.Type) {
					item.cve = cveID.FindString(e.Title)
				}
				res.Items = append(res.Items, item)
			}
		})
	}
	wg.Wait()
	slices.SortFunc(res.Items, func(a, b Item) int {
		return cmp.Or(b.Published.Compare(a.Published), cmp.Compare(a.Source, b.Source), cmp.Compare(a.Title, b.Title))
	})
	res.Items = mergeDuplicateCVEs(res.Items)
	slices.SortFunc(res.Failures, func(a, b Failure) int { return cmp.Compare(a.Source, b.Source) })
	slices.SortFunc(res.Truncated, func(a, b Truncation) int { return cmp.Compare(a.Source, b.Source) })
	return res
}

var (
	releasedTitle = regexp.MustCompile(`(?i)\breleased\b`)
	cveID         = regexp.MustCompile(`CVE-\d{4}-\d+`)
)

// mergeable tells whether the entries of a source are vulnerability records
// that other databases may repeat. Alerts (KEV, exploited lists) and feeds are
// never merged: their own wording carries information.
func mergeable(t source.Type) bool {
	switch t {
	case source.TypeNVD, source.TypeEUVDSearch, source.TypeGitHubAdvisories, source.TypeGitHubAdvisoryDatabase:
		return true
	}
	return false
}

// mergeDuplicateCVEs keeps one entry per CVE across the vulnerability
// databases (GitHub advisories, NVD, EUVD), noting where else it appears.
func mergeDuplicateCVEs(items []Item) []Item {
	first := map[string]int{}
	out := items[:0]
	for _, it := range items {
		if it.cve != "" {
			if i, seen := first[it.cve]; seen {
				if out[i].Source != it.Source && !slices.Contains(out[i].AlsoIn, it.Source) {
					out[i].AlsoIn = append(out[i].AlsoIn, it.Source)
				}
				continue
			}
			first[it.cve] = len(out)
		}
		out = append(out, it)
	}
	return out
}

// absolute resolves a link found in a feed against the feed URL.
func absolute(base, link string) string {
	b, err := neturl.Parse(base)
	if err != nil || link == "" {
		return link
	}
	l, err := b.Parse(link)
	if err != nil {
		return link
	}
	return l.String()
}

// selectSources keeps the sources carrying one of the tags, plus the general
// ones. Without tags, every source is selected.
func selectSources(sources []source.Source, tags []string) []source.Source {
	if len(tags) == 0 {
		return sources
	}
	return slices.DeleteFunc(slices.Clone(sources), func(s source.Source) bool {
		return !s.IsGeneral() && !slices.ContainsFunc(s.Tags, func(t string) bool { return slices.Contains(tags, t) })
	})
}

// keep applies the source keywords, and for a general source, the requested
// tags and keywords.
func keep(s source.Source, e entry, words []*regexp.Regexp) bool {
	text := e.Title + " " + e.Summary
	if len(s.Keywords) > 0 && !slices.ContainsFunc(matchers(s.Keywords), func(re *regexp.Regexp) bool { return re.MatchString(text) }) {
		return false
	}
	if s.IsGeneral() && len(words) > 0 {
		return slices.ContainsFunc(words, func(re *regexp.Regexp) bool { return re.MatchString(text) })
	}
	return true
}

// matchers builds case-insensitive whole-word patterns ("node" matches
// "Node.js" but not "nodes").
func matchers(words []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, w := range words {
		if w = strings.TrimSpace(w); w != "" && w != source.General {
			out = append(out, regexp.MustCompile(`(?i)(^|[^\pL\pN])`+regexp.QuoteMeta(w)+`($|[^\pL\pN])`))
		}
	}
	return out
}

// priority ranks an unscored CVE as high: fresh CVEs wait days for a score.
func priority(score float64) float64 {
	if score == 0 {
		return 9
	}
	return score
}

// maxTerms bounds the requests made to search sources.
const maxTerms = 8

// searchAliases are the terms CVE databases are searched with for tags that
// are ambiguous words: "node" alone matches hundreds of Linux kernel CVEs
// (NUMA nodes, inodes), "go" matches almost anything.
var searchAliases = map[string]string{
	"node":   "node.js",
	"nextjs": "next.js",
	"go":     "golang",
	"dotnet": ".net",
}

// searchTerms returns the words search sources are queried with.
func searchTerms(q Query) []string {
	var out []string
	for _, w := range append(slices.Clone(q.Tags), q.Keywords...) {
		w = strings.ToLower(strings.TrimSpace(w))
		if alias, ok := searchAliases[w]; ok {
			w = alias
		}
		if w != "" && w != source.General && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out[:min(len(out), maxTerms)]
}

// gate spaces out requests to an API with a strict rate limit.
type gate struct {
	mu    sync.Mutex
	delay time.Duration
	last  time.Time
}

func (g *gate) wait(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if d := g.delay - time.Since(g.last); !g.last.IsZero() && d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	g.last = time.Now()
	return nil
}

func (f *Fetcher) read(ctx context.Context, s source.Source, terms []string, q Query, nvd *gate) ([]entry, error) {
	since := q.Since
	github := cmp.Or(f.GitHubAPI, "https://api.github.com")
	now := f.Now().UTC()
	switch s.Type {
	case source.TypeGitHubAdvisories:
		return f.readOne(ctx, github+"/repos/"+s.Repo+"/security-advisories?per_page=30&sort=published&direction=desc", "github", parseGitHubAdvisories)
	case source.TypeGitHubAdvisoryDatabase:
		u := github + "/advisories?type=reviewed&per_page=100&ecosystem=" + neturl.QueryEscape(s.Ecosystem) +
			"&published=" + neturl.QueryEscape(">="+since.UTC().Format(time.DateOnly))
		if len(q.Packages) > 0 {
			u += "&affects=" + neturl.QueryEscape(strings.Join(q.Packages, ","))
		}
		return f.readOne(ctx, u, "github", parseGitHubAdvisoryDatabase)
	case source.TypeKEV:
		return f.readOne(ctx, s.URL, "", parseKEV)
	case source.TypeEUVD:
		return f.readOne(ctx, s.URL, "", parseEUVD)
	case source.TypeNVD:
		// Whole hours keep the URL, hence the cache, stable within the hour.
		end := now.Truncate(time.Hour).Add(time.Hour)
		start := since.UTC().Truncate(24 * time.Hour)
		if oldest := end.Add(-120 * 24 * time.Hour); start.Before(oldest) {
			start = oldest // the API caps the range at 120 days
		}
		const layout = "2006-01-02T15:04:05.000Z"
		return f.search(ctx, terms, func(term string) string {
			return s.URL + "?keywordSearch=" + neturl.QueryEscape(term) + "&pubStartDate=" + start.Format(layout) + "&pubEndDate=" + end.Format(layout)
		}, "nvd", nvd, parseNVD)
	case source.TypeEUVDSearch:
		return f.search(ctx, terms, func(term string) string {
			return s.URL + "?size=100&text=" + neturl.QueryEscape(term) + "&fromDate=" + since.UTC().Format(time.DateOnly) + "&toDate=" + now.Format(time.DateOnly)
		}, "", nil, parseEUVD)
	default:
		return f.readOne(ctx, s.URL, "", parseFeed)
	}
}

func (f *Fetcher) readOne(ctx context.Context, url, api string, parse func([]byte) ([]entry, error)) ([]entry, error) {
	data, err := f.get(ctx, url, api)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

// search queries a search source once per term and merges the results.
func (f *Fetcher) search(ctx context.Context, terms []string, url func(string) string, api string, g *gate, parse func([]byte) ([]entry, error)) ([]entry, error) {
	var (
		out  []entry
		errs []error
		seen = map[string]bool{}
	)
	for _, term := range terms {
		u := url(term)
		if g != nil && !f.isCached(u) {
			if err := g.wait(ctx); err != nil {
				return out, err
			}
		}
		entries, err := f.readOne(ctx, u, api, parse)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", term, err))
			continue
		}
		for _, e := range entries {
			if !seen[e.URL] {
				seen[e.URL] = true
				out = append(out, e)
			}
		}
	}
	return out, errors.Join(errs...)
}

const maxBody = 32 << 20 // the KEV catalog is a few MB

func (f *Fetcher) isCached(url string) bool {
	_, ok := f.cached(f.cachePath(url))
	return ok
}

// get downloads url. api names the API it belongs to ("github", "nvd"), so
// the right headers and rate-limit hints are used.
func (f *Fetcher) get(ctx context.Context, url, api string) ([]byte, error) {
	github := api == "github"
	cache := f.cachePath(url)
	if data, ok := f.cached(cache); ok {
		return data, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	if github {
		req.Header.Set("Accept", "application/vnd.github+json")
		if f.GitHubToken != "" {
			req.Header.Set("Authorization", "Bearer "+f.GitHubToken)
		}
	}
	if api == "nvd" && f.NVDAPIKey != "" {
		req.Header.Set("apiKey", f.NVDAPIKey)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if github && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
			return nil, fmt.Errorf("GitHub API rate limit reached (HTTP %d): set GITHUB_TOKEN to raise it", resp.StatusCode)
		}
		if api == "nvd" && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
			return nil, fmt.Errorf("NVD API rate limit reached (HTTP %d): set NVD_API_KEY to raise it", resp.StatusCode)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if cache != "" {
		_ = os.MkdirAll(filepath.Dir(cache), 0o700)
		// A cache that cannot be written only costs a refetch.
		if os.WriteFile(cache, data, 0o600) == nil {
			_ = os.Chtimes(cache, f.Now(), f.Now()) // age is measured with the same clock
		}
	}
	return data, nil
}

func (f *Fetcher) cachePath(url string) string {
	if f.CacheDir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(f.CacheDir, hex.EncodeToString(sum[:16]))
}

func (f *Fetcher) cached(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	info, err := os.Stat(path)
	if err != nil || f.Now().Sub(info.ModTime()) > f.CacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(path)
	return data, err == nil
}

// ParseSince reads a duration such as 24h, 7d or 2w.
func ParseSince(s string) (time.Duration, error) {
	if n, unit, ok := cutUnit(s); ok {
		switch unit {
		case "d":
			return time.Duration(n) * 24 * time.Hour, nil
		case "w":
			return time.Duration(n) * 7 * 24 * time.Hour, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New("use a duration such as 24h, 7d or 2w")
	}
	return d, nil
}

func cutUnit(s string) (int, string, bool) {
	if len(s) < 2 {
		return 0, "", false
	}
	var n int
	if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err != nil || n <= 0 || fmt.Sprint(n) != s[:len(s)-1] {
		return 0, "", false
	}
	return n, s[len(s)-1:], true
}
