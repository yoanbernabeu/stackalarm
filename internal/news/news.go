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
	Language  string       `json:"language,omitempty"`
}

// Failure is a source that could not be read. It is always reported: a
// silent watch tool is worse than a noisy one.
type Failure struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

// Result is the outcome of a fetch.
type Result struct {
	Items    []Item    `json:"items"`
	Failures []Failure `json:"failures"`
}

// Query selects what to fetch.
type Query struct {
	Tags     []string  // empty: every source
	Keywords []string  // extra words that select entries of general sources
	Since    time.Time // entries published before are dropped
}

// Fetcher reads sources over HTTP, with a small on-disk cache.
type Fetcher struct {
	Client      *http.Client
	UserAgent   string
	GitHubToken string        // optional, raises the GitHub API rate limit
	GitHubAPI   string        // https://api.github.com unless a test changes it
	CacheDir    string        // empty disables the cache
	CacheTTL    time.Duration // how long a cached response is reused
	Now         func() time.Time
}

// Fetch reads the sources selected by q, in parallel.
func (f *Fetcher) Fetch(ctx context.Context, sources []source.Source, q Query) Result {
	selected := selectSources(sources, q.Tags)
	words := matchers(append(slices.Clone(q.Tags), q.Keywords...))

	var (
		mu  sync.Mutex
		res = Result{Items: []Item{}, Failures: []Failure{}}
		wg  sync.WaitGroup
	)
	for _, s := range selected {
		wg.Go(func() {
			entries, err := f.read(ctx, s)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Failures = append(res.Failures, Failure{Source: s.ID, Error: err.Error()})
				return
			}
			for _, e := range entries {
				if e.Published.IsZero() || e.Published.Before(q.Since) || !keep(s, e, words) {
					continue
				}
				res.Items = append(res.Items, Item{
					Source: s.ID, Tags: s.Tags, Stage: s.Stage, Title: e.Title, URL: absolute(s.URL, e.URL),
					Published: e.Published, Summary: e.Summary, Language: s.Language,
				})
			}
		})
	}
	wg.Wait()
	slices.SortFunc(res.Items, func(a, b Item) int {
		return cmp.Or(b.Published.Compare(a.Published), cmp.Compare(a.Source, b.Source), cmp.Compare(a.Title, b.Title))
	})
	slices.SortFunc(res.Failures, func(a, b Failure) int { return cmp.Compare(a.Source, b.Source) })
	return res
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

func (f *Fetcher) read(ctx context.Context, s source.Source) ([]entry, error) {
	url, accept := s.URL, ""
	if s.Type == source.TypeGitHubAdvisories {
		url = cmp.Or(f.GitHubAPI, "https://api.github.com") + "/repos/" + s.Repo + "/security-advisories?per_page=30&sort=published&direction=desc"
		accept = "application/vnd.github+json"
	}
	data, err := f.get(ctx, url, accept, s.Type == source.TypeGitHubAdvisories)
	if err != nil {
		return nil, err
	}
	switch s.Type {
	case source.TypeGitHubAdvisories:
		return parseGitHubAdvisories(data)
	case source.TypeKEV:
		return parseKEV(data)
	default:
		return parseFeed(data)
	}
}

const maxBody = 32 << 20 // the KEV catalog is a few MB

func (f *Fetcher) get(ctx context.Context, url, accept string, github bool) ([]byte, error) {
	cache := f.cachePath(url)
	if data, ok := f.cached(cache); ok {
		return data, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if github && f.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+f.GitHubToken)
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
