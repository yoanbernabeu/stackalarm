// Package news fetches the watched sources and turns their entries into one
// list of items, filtered by tag and date.
package news

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	ID        string       `json:"id"` // stable across runs, so a scheduled watch knows what it already reported
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
	// EPSS is the probability of exploitation in the next 30 days (0 to 1),
	// from FIRST, when known.
	EPSS float64 `json:"epss,omitempty"`
	// ExploitedIn names the sources reporting the CVE exploited in the wild
	// (CISA KEV, EUVD), at any date: an old flaw can be exploited today.
	ExploitedIn []string `json:"exploited_in,omitempty"`
	// PublicExploitIn names the catalogs of public exploits holding the CVE
	// (Nuclei templates, Metasploit modules): anyone can run them.
	PublicExploitIn []string   `json:"public_exploit_in,omitempty"`
	Affected        []Affected `json:"affected,omitempty"` // packages or products and their versions

	cve  string // CVE id of a CVE database entry, used to merge duplicates
	dup  string // GHSA id of an advisory without a CVE, used the same way
	rank int    // order within its source, for the cap
}

// Affected is a package an advisory names, with the vulnerable versions and
// the first fixed one.
type Affected struct {
	Package  string `json:"package"`
	Versions string `json:"versions"`
	Fixed    string `json:"fixed,omitempty"`
	// InUse is the version the query gave for the package, and Status whether
	// it is in the vulnerable range: StatusAffected or StatusNotAffected. Both
	// are empty when no version was given or the range could not be read.
	InUse  string `json:"in_use,omitempty"`
	Status string `json:"status,omitempty"`
}

// Statuses of a version in use against a vulnerable range.
const (
	StatusAffected    = "affected"
	StatusNotAffected = "not-affected"
)

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
	// NotSearched lists the words left out of the CVE database searches,
	// beyond MaxTerms: like a failure, a gap in the watch is always reported.
	NotSearched []string `json:"not_searched"`
	// Short lists the feeds whose oldest entry is newer than the start of the
	// period: they keep few entries, so older news may be missing.
	Short []Coverage `json:"short"`
}

// Coverage tells how far back a feed reaches.
type Coverage struct {
	Source string    `json:"source"`
	Since  time.Time `json:"since"` // its oldest entry
}

// MaxPerSource keeps the output readable for a person or an agent: a CVE
// database can return hundreds of records for a common word.
const MaxPerSource = 30

// Query selects what to fetch.
type Query struct {
	Tags     []string // empty: every source
	Keywords []string // extra words that select entries of general sources
	// Order lists the tags and keywords in the order they were given, mixed:
	// the CVE databases are searched for the first MaxTerms of them. Empty:
	// the tags, then the keywords.
	Order []string
	Since time.Time // entries published before are dropped
	// Packages narrow the GitHub Advisory Database sources to these package
	// names (the agent reads them from the lockfile). Empty: the whole ecosystem.
	Packages []string
	// Versions gives the version in use of a tag (php: 8.3.20). It never
	// filters: the ranges of the CVE records are compared with it.
	Versions map[string]string
	// Components are the packages of an SBOM: each names its ecosystem, and
	// the OSV sources of those ecosystems are read whatever the tags.
	Components []Component
	// ComponentsOnly reads nothing but the OSV sources of the components and
	// the lists that mark their CVEs exploited: a run on an SBOM alone.
	ComponentsOnly bool
}

// Fetcher reads sources over HTTP, with a small on-disk cache.
type Fetcher struct {
	Client      *http.Client
	UserAgent   string
	GitHubToken string        // optional, raises the GitHub API rate limit
	GitHubAPI   string        // https://api.github.com unless a test changes it
	NVDAPIKey   string        // optional, raises the NVD API rate limit
	EPSSAPI     string        // FIRST EPSS API, completing the scores of CVE records; empty skips it
	EOLAPI      string        // endoflife.date API, for the support status of components
	OSVAPI      string        // OSV.dev API, for the vulnerabilities of the package versions in use; empty skips it
	CVEAPI      string        // CVE Program API, for the record of one CVE
	NVDDelay    time.Duration // pause between two NVD requests (the API allows 5 per 30 s without key)
	EUVDDelay   time.Duration // pause between two EUVD search requests, which answer HTTP 429 to bursts
	RetryDelay  time.Duration // pause before trying an NVD request again, doubled the second time
	CacheDir    string        // empty disables the cache
	CacheTTL    time.Duration // how long a cached response is reused
	Search      source.Search // how tags become CVE database search terms
	Now         func() time.Time

	github chan struct{} // bounds the GitHub requests in flight
	// The pauses between two requests to the NVD and the EUVD, kept from one
	// Fetch to the next: a program that fetches tag after tag stays in the limits.
	nvdGate, euvdGate *gate
}

// GitHubConcurrency bounds the GitHub requests in flight: beyond, its
// secondary rate limit answers HTTP 403, even with a token.
const GitHubConcurrency = 16

// Fetch reads the sources selected by q, in parallel.
func (f *Fetcher) Fetch(ctx context.Context, sources []source.Source, q Query) Result {
	selected := selectSources(sources, q.Tags)
	if q.ComponentsOnly {
		selected = nil
	}
	for _, s := range sources {
		marks := s.Type == source.TypeKEV || s.Type == source.TypeEUVD && s.Stage == source.StageAlert || s.Type.IsExploitCatalog()
		inSBOM := s.Type == source.TypeOSV && slices.ContainsFunc(q.Components, func(c Component) bool { return inEcosystem(c.Ecosystem, s.Ecosystem) })
		if (inSBOM || marks && q.ComponentsOnly) && !slices.ContainsFunc(selected, func(o source.Source) bool { return o.ID == s.ID }) {
			selected = append(selected, s)
		}
	}
	f.github = make(chan struct{}, GitHubConcurrency)
	terms, left := searchTerms(q, f.Search)
	words := matchers(matchTerms(q, f.Search))
	if f.nvdGate == nil {
		f.nvdGate, f.euvdGate = &gate{delay: f.NVDDelay}, &gate{delay: f.EUVDDelay}
	}
	nvd, euvd := f.nvdGate, f.euvdGate
	exploited := map[string][]string{} // CVE: the sources reporting it exploited
	exploits := map[string][]string{}  // CVE: the catalogs holding a public exploit
	var (
		kevSource  source.Source
		kevCatalog []entry // the whole catalog, whatever the dates: searched for the versions in use
	)

	var (
		mu  sync.Mutex
		res = Result{Items: []Item{}, Failures: []Failure{}, Truncated: []Truncation{}, NotSearched: []string{}, Short: []Coverage{}}
		wg  sync.WaitGroup
	)
	if slices.ContainsFunc(selected, func(s source.Source) bool { return s.Type.IsSearch() }) {
		res.NotSearched = append(res.NotSearched, left...)
	}
	for _, s := range selected {
		if s.Type.IsSearch() && len(terms.words) == 0 && (s.Type != source.TypeNVD || len(terms.cpes) == 0) {
			continue // nothing to search for
		}
		wg.Go(func() {
			entries, err := f.read(ctx, s, terms, q, nvd, euvd)
			mu.Lock()
			defer mu.Unlock()
			if err != nil { // a search may fail for one word and succeed for others
				res.Failures = append(res.Failures, Failure{Source: s.ID, Error: err.Error()})
			}
			if oldest := oldestEntry(entries); s.Type == source.TypeFeed && err == nil && oldest.After(q.Since) {
				res.Short = append(res.Short, Coverage{Source: s.ID, Since: oldest})
			}
			if s.Type == source.TypeKEV {
				kevSource, kevCatalog = s, slices.Clone(entries)
			}
			for _, e := range entries { // the whole catalog, before the date and word filters
				if e.Exploit {
					if c := cveID.FindString(e.Title); c != "" && !slices.Contains(exploits[c], s.ID) {
						exploits[c] = append(exploits[c], s.ID)
					}
				}
				if exploitedTitle.MatchString(e.Title) {
					if c := cveID.FindString(e.Title); c != "" && !slices.Contains(exploited[c], s.ID) {
						exploited[c] = append(exploited[c], s.ID)
					}
				}
			}
			entries = slices.DeleteFunc(entries, func(e entry) bool {
				if q.ComponentsOnly && s.Type != source.TypeOSV {
					return true // read for its marks only
				}
				if e.Published.IsZero() || !e.Current && e.Published.Before(q.Since) {
					return true
				}
				if s.Type.IsSearch() { // the databases match loosely ("node.js" finds kernel "node"): check the whole term
					if e.Exact {
						return false // found by product, not by word
					}
					text := matchText(e)
					return !slices.ContainsFunc(words, func(re *regexp.Regexp) bool { return re.MatchString(text) })
				}
				return !keep(s, e, words)
			})
			for i := range entries {
				entries[i].Affected = annotate(entries[i].Affected, q)
			}
			slices.SortStableFunc(entries, func(a, b entry) int {
				// What a version in use proves, then the records of a watched
				// product, come before those that only mention a word.
				if c := cmp.Compare(relevance(a, q), relevance(b, q)); c != 0 {
					return c
				}
				if s.Type == source.TypeOSV { // what an update fixes today, before what has no fix yet
					if c := cmp.Compare(fixable(b), fixable(a)); c != 0 {
						return c
					}
				}
				if s.Type.IsSearch() || s.Type == source.TypeNVDProduct || s.Type == source.TypeGitHubAdvisoryDatabase || s.Type == source.TypeOSV { // most severe first, so the cap drops the minor ones
					if c := cmp.Compare(priority(b), priority(a)); c != 0 {
						return c
					}
				}
				return b.Published.Compare(a.Published)
			})
			if s.Type == source.TypeOSV {
				entries = inTurns(entries)
			}
			for rank, e := range entries {
				stage := cmp.Or(e.Stage, s.Stage)
				if stage == source.StageHeadsUp && releasedTitle.MatchString(e.Title) {
					stage = source.StageRelease // a heads-up feed also announces the release itself
				}
				item := Item{
					Source: s.ID, Tags: s.Tags, Stage: stage, Title: e.Title, URL: absolute(s.URL, e.URL),
					Published: e.Published, Summary: e.Summary, Score: e.Score, Language: s.Language, EPSS: e.EPSS, Affected: e.Affected,
				}
				if mergeable(s.Type) {
					item.cve = cveID.FindString(e.Title)
					item.dup = ghsaID.FindString(e.Title + " " + e.URL)
				}
				item.ID = itemID(item)
				item.rank = rank
				res.Items = append(res.Items, item)
			}
		})
	}
	wg.Wait()
	if !q.ComponentsOnly {
		res.Items = append(res.Items, f.kevInUse(ctx, kevSource, kevCatalog, q, sources, nvd, res.Items)...)
	}
	slices.SortFunc(res.Items, func(a, b Item) int {
		return cmp.Or(b.Published.Compare(a.Published), cmp.Compare(a.Source, b.Source), cmp.Compare(a.Title, b.Title))
	})
	for i, it := range res.Items {
		if sources := exploited[it.cve]; it.cve != "" && len(sources) > 0 {
			res.Items[i].ExploitedIn = slices.Sorted(slices.Values(sources))
			res.Items[i].rank -= 1 << 20 // kept first under the cap
		}
		if catalogs := exploits[it.cve]; it.cve != "" && len(catalogs) > 0 {
			res.Items[i].PublicExploitIn = slices.Sorted(slices.Values(catalogs))
			res.Items[i].rank -= 1 << 19 // then the ones anyone can exploit
		}
	}
	res.Items, res.Truncated = mergeAndCap(res.Items)
	if err := f.addEPSS(ctx, res.Items); err != nil {
		res.Failures = append(res.Failures, Failure{Source: "epss", Error: err.Error()})
	}
	slices.SortStableFunc(res.Items, func(a, b Item) int { return b.Published.Compare(a.Published) }) // a merged CVE carries the date of the entry kept
	if res.Items == nil {
		res.Items = []Item{}
	}
	slices.SortFunc(res.Failures, func(a, b Failure) int { return cmp.Compare(a.Source, b.Source) })
	if res.Truncated == nil {
		res.Truncated = []Truncation{}
	}
	slices.SortFunc(res.Truncated, func(a, b Truncation) int { return cmp.Compare(a.Source, b.Source) })
	slices.SortFunc(res.Short, func(a, b Coverage) int { return cmp.Compare(a.Source, b.Source) })
	return res
}

var (
	exploitedTitle = regexp.MustCompile(`(?i)\bexploited in the wild\b`)
	releasedTitle  = regexp.MustCompile(`(?i)\breleased\b`)
	cveID          = regexp.MustCompile(`CVE-\d{4}-\d+`)
	ghsaID         = regexp.MustCompile(`GHSA(-[23456789cfghjmpqrvwx]{4}){3}`)
)

// inTurns orders sorted OSV entries package by package, in turns: the most
// severe flaw of each package, then the second of each, and so on. The cap of
// a source then drops the minor flaws of the most exposed packages, never a
// whole package: a lockfile with one package holding forty advisories would
// otherwise hide every other package.
func inTurns(entries []entry) []entry {
	var (
		order []string
		lists = map[string][]entry{}
	)
	for _, e := range entries {
		key := ""
		for _, a := range e.Affected {
			if key == "" || a.Status == StatusAffected {
				key = a.Package
			}
			if a.Status == StatusAffected {
				break
			}
		}
		if _, seen := lists[key]; !seen {
			order = append(order, key)
		}
		lists[key] = append(lists[key], e)
	}
	out := make([]entry, 0, len(entries))
	for turn := 0; len(out) < len(entries); turn++ {
		for _, key := range order {
			if turn < len(lists[key]) {
				out = append(out, lists[key][turn])
			}
		}
	}
	return out
}

// mergeable tells whether the entries of a source are vulnerability records
// that other databases may repeat. Alerts (KEV, exploited lists) and feeds are
// never merged: their own wording carries information.
func mergeable(t source.Type) bool {
	switch t {
	case source.TypeNVD, source.TypeNVDProduct, source.TypeEUVDSearch, source.TypeGitHubAdvisories, source.TypeGitHubAdvisoryDatabase, source.TypeOSV:
		return true
	}
	return false
}

// oldestEntry returns the date of the oldest dated entry, or zero.
func oldestEntry(entries []entry) time.Time {
	var oldest time.Time
	for _, e := range entries {
		if !e.Published.IsZero() && (oldest.IsZero() || e.Published.Before(oldest)) {
			oldest = e.Published
		}
	}
	return oldest
}

// epssBatch is the number of CVEs the EPSS API answers in one request.
const epssBatch = 100

// addEPSS completes the CVE records lacking an EPSS, from the FIRST API.
func (f *Fetcher) addEPSS(ctx context.Context, items []Item) error {
	if f.EPSSAPI == "" {
		return nil
	}
	var cves []string
	for _, it := range items {
		if it.cve != "" && it.EPSS == 0 {
			cves = append(cves, it.cve)
		}
	}
	slices.Sort(cves) // a stable URL, for the cache
	cves = slices.Compact(cves)
	scores := map[string]float64{}
	for batch := range slices.Chunk(cves, epssBatch) {
		data, _, err := f.get(ctx, f.EPSSAPI+"?cve="+strings.Join(batch, ","), "")
		if err != nil {
			return err
		}
		var r struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("unexpected EPSS response: %w", err)
		}
		for _, d := range r.Data {
			var p float64
			fmt.Sscan(d.EPSS, &p)
			scores[d.CVE] = p
		}
	}
	for i := range items {
		if items[i].EPSS == 0 {
			items[i].EPSS = scores[items[i].cve]
		}
	}
	return nil
}

// fixable is 1 when a fixed version exists for a range the version in use is in.
func fixable(e entry) int {
	for _, a := range e.Affected {
		if a.Status == StatusAffected && a.Fixed != "" {
			return 1
		}
	}
	return 0
}

// statusOrder puts the ranges that hold a version in use first, and those
// that do not last.
func statusOrder(status string) int {
	switch status {
	case StatusAffected:
		return 0
	case StatusNotAffected:
		return 2
	}
	return 1
}

// relevance orders the entries of one source: 0 when a version in use is in
// a vulnerable range, 1 when the entry is the record of a watched product or
// package, 2 otherwise.
func relevance(e entry, q Query) int {
	r := 2
	if e.Exact {
		r = 1
	}
	for _, a := range e.Affected {
		switch {
		case a.Status == StatusAffected:
			return 0
		case slices.Contains(q.Tags, strings.ToLower(a.Package)), slices.ContainsFunc(q.Packages, func(p string) bool { return packageName(p) == a.Package }):
			r = 1
		}
	}
	return r
}

// annotate compares each range with the version in use, when the query gives
// one (a package with its version, or the version of a tag), then puts the
// ranges that matter first.
func annotate(affected []Affected, q Query) []Affected {
	for i, a := range affected {
		if a.Status != "" {
			continue // the source already told
		}
		version := q.Versions[strings.ToLower(a.Package)]
		for _, p := range q.Packages {
			if packageName(p) == a.Package {
				_, version, _ = strings.Cut(strings.TrimPrefix(p, a.Package), "@")
			}
		}
		if in, ok := inRange(version, a.Versions); ok {
			affected[i].InUse, affected[i].Status = version, StatusNotAffected
			if in {
				affected[i].Status = StatusAffected
			}
		}
	}
	watched := slices.Clone(q.Packages)
	for name, version := range q.Versions {
		watched = append(watched, name+"@"+version)
	}
	return watchedFirst(affected, watched)
}

// watchedFirst puts the packages the query names first, and among them the
// range that holds the version given, so a short display shows the one that
// matters: an advisory can name a dozen packages or ranges.
func watchedFirst(affected []Affected, packages []string) []Affected {
	order := func(a Affected) int {
		for _, p := range packages {
			if packageName(p) != a.Package && packageName(p) != strings.ToLower(a.Package) {
				continue
			}
			if a.Status == StatusAffected {
				return 0
			}
			_, version, _ := strings.Cut(strings.TrimPrefix(p, a.Package), "@") // empty without a version
			in, ok := inRange(version, a.Versions)
			switch {
			case in:
				return 0
			case !ok:
				return 1
			}
			return 2
		}
		return 3
	}
	slices.SortStableFunc(affected, func(a, b Affected) int { return cmp.Compare(order(a), order(b)) })
	return affected
}

// packageName drops the version of "name@1.2.3", keeping the scope of
// "@scope/name@1.2.3".
func packageName(p string) string {
	if i := strings.LastIndex(p, "@"); i > 0 {
		return p[:i]
	}
	return p
}

// mergeAndCap keeps one entry per CVE across the vulnerability databases
// (GitHub advisories, NVD, EUVD), noting where else it appears, and at most
// MaxPerSource entries per source, in the order of the source (the most
// severe first for CVE databases). A merged CVE takes one place, in the
// source that ranks it highest, or in another listing it when that source
// is full: a CVE is dropped only when no source has room for it.
func mergeAndCap(items []Item) ([]Item, []Truncation) {
	key := func(i int) string {
		if k := cmp.Or(items[i].cve, items[i].dup); k != "" {
			return k
		}
		return fmt.Sprint("#", i)
	}
	var (
		keys    []string             // in the order of items
		holders = map[string][]int{} // the items sharing a key, in the order of items
		owner   = map[string]int{}
		count   = map[string]int{} // keys owned, per source
	)
	for i := range items {
		k := key(i)
		if _, seen := holders[k]; !seen {
			keys = append(keys, k)
			owner[k] = i
		} else if items[i].rank < items[owner[k]].rank {
			owner[k] = i
		}
		holders[k] = append(holders[k], i)
	}
	for _, k := range keys {
		count[items[owner[k]].Source]++
	}
	// Move shared CVEs out of the full sources, the least ranked first.
	byRank := slices.Clone(keys)
	slices.SortStableFunc(byRank, func(a, b string) int { return cmp.Compare(items[owner[b]].rank, items[owner[a]].rank) })
	for _, k := range byRank {
		src := items[owner[k]].Source
		if count[src] <= MaxPerSource {
			continue
		}
		for _, h := range holders[k] {
			if other := items[h].Source; other != src && count[other] < MaxPerSource {
				owner[k] = h
				count[src]--
				count[other]++
				break
			}
		}
	}
	// Keep the best ranked keys of each source.
	owned := map[string][]string{}
	for _, k := range keys {
		owned[items[owner[k]].Source] = append(owned[items[owner[k]].Source], k)
	}
	var (
		dropped   = map[string]bool{}
		truncated []Truncation
	)
	for src, ks := range owned {
		if len(ks) <= MaxPerSource {
			continue
		}
		slices.SortStableFunc(ks, func(a, b string) int { return cmp.Compare(items[owner[a]].rank, items[owner[b]].rank) })
		for _, k := range ks[MaxPerSource:] {
			dropped[k] = true
		}
		truncated = append(truncated, Truncation{Source: src, Dropped: len(ks) - MaxPerSource})
	}
	var out []Item
	for _, k := range keys {
		if dropped[k] {
			continue
		}
		it := items[owner[k]]
		for _, h := range holders[k] {
			if s := items[h].Source; s != it.Source && !slices.Contains(it.AlsoIn, s) {
				it.AlsoIn = append(it.AlsoIn, s)
			}
			// Each database knows its own names and ranges (a package, a product):
			// the merged item keeps them all, what a version in use proves first.
			for _, af := range items[h].Affected {
				if h != owner[k] && !slices.Contains(it.Affected, af) {
					it.Affected = append(slices.Clip(it.Affected), af)
				}
			}
		}
		slices.SortStableFunc(it.Affected, func(a, b Affected) int {
			return cmp.Compare(statusOrder(a.Status), statusOrder(b.Status))
		})
		out = append(out, it)
	}
	return out, truncated
}

// itemID identifies an item by its CVE when databases may merge it (the one
// listing it first can change between runs), otherwise by its source and link.
func itemID(it Item) string {
	key := it.cve
	if key == "" {
		key = it.Source + "\n" + cmp.Or(it.URL, it.Title)
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
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
	text := matchText(e)
	if len(s.Keywords) > 0 && !slices.ContainsFunc(matchers(s.Keywords), func(re *regexp.Regexp) bool { return re.MatchString(text) }) {
		return false
	}
	if s.IsGeneral() && len(words) > 0 {
		return slices.ContainsFunc(words, func(re *regexp.Regexp) bool { return re.MatchString(text) })
	}
	return true
}

// links are left out of the text words are matched against: a mailing list
// post linking to github.com is not about GitHub.
var links = regexp.MustCompile(`(?i)\bhttps?://\S+|\b(?:[\w-]+\.)+(?:com|org|net|io|dev)/\S*`)

func matchText(e entry) string {
	return links.ReplaceAllString(e.Title+" "+e.Summary, " ")
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
func priority(e entry) float64 {
	return cmp.Or(e.Rank, e.Score, 9)
}

// MaxTerms bounds the requests made to search sources: without a key, the
// NVD allows one every 6 seconds.
const MaxTerms = 8

// matchTerms returns the words entries of general sources are matched
// against: every tag and keyword, with the aliases of sources/search.yaml.
func matchTerms(q Query, s source.Search) []string {
	var out []string
	words := append(slices.Clone(q.Tags), q.Keywords...)
	if len(q.Order) > 0 { // the order given on the command line, tags and keywords mixed
		at := func(w string) int {
			if i := slices.Index(q.Order, strings.ToLower(strings.TrimSpace(w))); i >= 0 {
				return i
			}
			return len(q.Order) // from a profile: after what was given
		}
		slices.SortStableFunc(words, func(a, b string) int { return cmp.Compare(at(a), at(b)) })
	}
	for _, w := range words {
		w = strings.ToLower(strings.TrimSpace(w))
		if alias, ok := s.Aliases[w]; ok {
			w = alias
		}
		if w != "" && w != source.General && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

// searchTerms returns the words search sources are queried with: the match
// terms, minus the tags sources/search.yaml skips (an explicit keyword is
// still searched), up to MaxTerms in the order given; left holds the rest.
//
// A skipped tag that has a product in the NVD dictionary (cpe in
// sources/search.yaml) is searched there by product instead: the word is
// ambiguous, the product is not. Those have their own limit of MaxTerms.
func searchTerms(q Query, s source.Search) (searched terms, left []string) {
	var cpes []string
	tags := slices.DeleteFunc(slices.Clone(q.Tags), func(t string) bool {
		t = strings.ToLower(strings.TrimSpace(t))
		if !slices.Contains(s.Skip, t) {
			return false
		}
		if cpe := s.CPE[t]; cpe != "" && !slices.Contains(cpes, cpe) {
			if len(cpes) < MaxTerms {
				cpes = append(cpes, cpe)
			} else {
				left = append(left, t)
			}
		}
		return true
	})
	out := matchTerms(Query{Tags: tags, Keywords: q.Keywords, Order: q.Order}, s)
	n := min(len(out), MaxTerms)
	return terms{words: out[:n], cpes: cpes}, append(out[n:], left...)
}

// terms is what the search sources are queried with.
type terms struct {
	words []string // every search source
	cpes  []string // vendor:product, for the NVD only
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

func (f *Fetcher) read(ctx context.Context, s source.Source, terms terms, q Query, nvd, euvd *gate) ([]entry, error) {
	since := q.Since
	github := cmp.Or(f.GitHubAPI, "https://api.github.com")
	now := f.Now().UTC()
	switch s.Type {
	case source.TypeGitHubAdvisories:
		return f.readGitHub(ctx, github+"/repos/"+s.Repo+"/security-advisories?per_page=100&sort=published&direction=desc", since, parseGitHubAdvisories)
	case source.TypeGitHubAdvisoryDatabase:
		u := github + "/advisories?per_page=100&ecosystem=" + neturl.QueryEscape(s.Ecosystem) +
			"&published=" + neturl.QueryEscape(">="+since.UTC().Format(time.DateOnly))
		if len(q.Packages) == 0 {
			return f.readGitHub(ctx, u+"&type=reviewed", since, parseGitHubAdvisoryDatabase)
		}
		u += "&affects=" + neturl.QueryEscape(strings.Join(q.Packages, ","))
		reviewed, err := f.readGitHub(ctx, u+"&type=reviewed", since, parseGitHubAdvisoryDatabase)
		// Malicious versions of the project's packages: a thousand a month in npm,
		// so they are only read for the packages given.
		malware, merr := f.readGitHub(ctx, u+"&type=malware", since, parseGitHubMalware)
		return append(reviewed, malware...), errors.Join(err, merr)
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
		period := "&pubStartDate=" + start.Format(layout) + "&pubEndDate=" + end.Format(layout)
		read := func(ctx context.Context, u, api string) ([]entry, error) {
			return f.readOne(ctx, u, api, func(data []byte) ([]entry, error) { return parseNVD(data, f.Search.CPE, minScore) })
		}
		// By product first: these records are kept whatever their wording.
		out, err := f.search(ctx, terms.cpes, func(cpe string) string {
			return s.URL + "?virtualMatchString=" + neturl.QueryEscape("cpe:2.3:a:"+cpe) + period
		}, "nvd", nvd, read)
		seen := map[string]bool{}
		for i := range out {
			out[i].Exact = true
			seen[out[i].URL] = true
		}
		byWord, werr := f.search(ctx, terms.words, func(term string) string {
			return s.URL + "?keywordSearch=" + neturl.QueryEscape(term) + period
		}, "nvd", nvd, read)
		for _, e := range byWord {
			if !seen[e.URL] {
				out = append(out, e)
			}
		}
		return out, errors.Join(err, werr)
	case source.TypeNVDProduct:
		// Every record of the product, whatever its score: it is the source of
		// the technology, and the cap keeps the most severe.
		end := now.Truncate(time.Hour).Add(time.Hour)
		start := since.UTC().Truncate(24 * time.Hour)
		if oldest := end.Add(-120 * 24 * time.Hour); start.Before(oldest) {
			start = oldest // the API caps the range at 120 days
		}
		const layout = "2006-01-02T15:04:05.000Z"
		u := s.URL + "?virtualMatchString=" + neturl.QueryEscape("cpe:2.3:a:"+s.Product) + "&pubStartDate=" + start.Format(layout) + "&pubEndDate=" + end.Format(layout)
		if nvd != nil && !f.isCached(u) {
			if err := nvd.wait(ctx); err != nil {
				return nil, err
			}
		}
		return f.readOne(ctx, u, "nvd", func(data []byte) ([]entry, error) {
			return parseNVD(data, map[string]string{s.Tags[0]: s.Product}, 0)
		})
	case source.TypeOSV:
		return f.readOSV(ctx, s.Ecosystem, q.Packages, q.Components)
	case source.TypeNuclei:
		return f.readOne(ctx, s.URL, "", parseNuclei)
	case source.TypeMetasploit:
		return f.readOne(ctx, s.URL, "", parseMetasploit)
	case source.TypeEUVDSearch:
		// The scores below 7 are dropped anyway: filtering them here saves pages.
		return f.search(ctx, terms.words, func(term string) string {
			return s.URL + "?size=" + fmt.Sprint(euvdPageSize) + "&fromScore=7&toScore=10&text=" + neturl.QueryEscape(term) +
				"&fromDate=" + since.UTC().Format(time.DateOnly) + "&toDate=" + now.Format(time.DateOnly)
		}, "", nil, func(ctx context.Context, u, _ string) ([]entry, error) { return f.readEUVDPages(ctx, u, euvd) })
	default:
		return f.readOne(ctx, s.URL, "", parseFeed)
	}
}

func (f *Fetcher) readOne(ctx context.Context, url, api string, parse func([]byte) ([]entry, error)) ([]entry, error) {
	data, _, err := f.get(ctx, url, api)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

// MaxPages bounds the pages read from a paginated API for one query: beyond,
// the query is too broad to be useful, and the gap is reported.
const MaxPages = 10

// readGitHub follows the pages of a GitHub list sorted newest first, until
// an entry is older than since. A list cut short is reported with what was read.
func (f *Fetcher) readGitHub(ctx context.Context, url string, since time.Time, parse func([]byte) ([]entry, error)) ([]entry, error) {
	var out []entry
	for page := 1; ; page++ {
		data, next, err := f.get(ctx, url, "github")
		if err != nil {
			return out, err
		}
		entries, err := parse(data)
		if err != nil {
			return out, err
		}
		out = append(out, entries...)
		if next == "" || len(entries) > 0 && entries[len(entries)-1].Published.Before(since) {
			return out, nil
		}
		if page == MaxPages {
			return out, fmt.Errorf("partial: more than %d pages of advisories, only the most recent were read (narrow with --package or --since)", MaxPages)
		}
		url = next
	}
}

const euvdPageSize = 100

// readEUVDPages reads every page of an EUVD search, which gives its total.
func (f *Fetcher) readEUVDPages(ctx context.Context, url string, g *gate) ([]entry, error) {
	var out []entry
	for page := 0; ; page++ {
		u := url + "&page=" + fmt.Sprint(page)
		if !f.isCached(u) {
			if err := g.wait(ctx); err != nil {
				return out, err
			}
		}
		data, _, err := f.get(ctx, u, "")
		if err != nil {
			return out, err
		}
		entries, err := parseEUVD(data)
		if err != nil {
			return out, err
		}
		out = append(out, entries...)
		total := euvdTotal(data)
		if (page+1)*euvdPageSize >= total {
			return out, nil
		}
		if page+1 == MaxPages {
			return out, fmt.Errorf("partial: %d records, only %d read (use more precise keywords or a shorter --since)", total, MaxPages*euvdPageSize)
		}
	}
}

// search queries a search source once per term and merges the results.
func (f *Fetcher) search(ctx context.Context, terms []string, url func(string) string, api string, g *gate, read func(ctx context.Context, url, api string) ([]entry, error)) ([]entry, error) {
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
		entries, err := read(ctx, u, api)
		if err != nil { // a partial read keeps what it got
			errs = append(errs, fmt.Errorf("%q: %w", term, err))
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

const maxBody = 32 << 20 // the KEV catalog is a few MB, the Metasploit one about 12

func (f *Fetcher) isCached(url string) bool {
	_, ok := f.cached(f.cachePath(url))
	return ok
}

// get downloads url, and returns the link to the next page a GitHub list
// gives. api names the API it belongs to ("github", "nvd"), so the right
// headers and rate-limit hints are used.
func (f *Fetcher) get(ctx context.Context, url, api string) (data []byte, next string, err error) {
	return f.do(ctx, url, "", api)
}

// post sends a JSON body. The answer is cached like a download: the APIs
// queried this way (OSV) only read.
func (f *Fetcher) post(ctx context.Context, url, body string) ([]byte, error) {
	data, _, err := f.do(ctx, url, body, "")
	return data, err
}

func (f *Fetcher) do(ctx context.Context, url, body, api string) (data []byte, next string, err error) {
	github := api == "github"
	cache := f.cachePath(url + body)
	if data, ok := f.cached(cache); ok {
		if link, ok := f.cached(cache + ".next"); ok {
			next = string(link)
		}
		return data, next, nil
	}
	method, payload := http.MethodGet, io.Reader(nil)
	if body != "" {
		method, payload = http.MethodPost, strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, payload)
	if err != nil {
		return nil, "", err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", f.UserAgent)
	if github && f.github != nil {
		select {
		case f.github <- struct{}{}:
			defer func() { <-f.github }()
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	if github {
		req.Header.Set("Accept", "application/vnd.github+json")
		if f.GitHubToken != "" {
			req.Header.Set("Authorization", "Bearer "+f.GitHubToken)
		}
	}
	if api == "nvd" && f.NVDAPIKey != "" {
		req.Header.Set("apiKey", f.NVDAPIKey)
	}
	var resp *http.Response
	for attempt := 1; ; attempt++ {
		resp, err = f.Client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("unreachable: %w", err)
		}
		// The NVD often answers 502 to 504 for a moment: a second try usually works.
		if api != "nvd" || attempt == nvdAttempts || resp.StatusCode < 502 || resp.StatusCode > 504 {
			break
		}
		resp.Body.Close()
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(time.Duration(attempt) * f.RetryDelay):
		}
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, "", fmt.Errorf("read failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if github && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
			if f.GitHubToken != "" {
				return nil, "", fmt.Errorf("GitHub API rate limit reached (HTTP %d) despite the token: run again in a few minutes", resp.StatusCode)
			}
			return nil, "", fmt.Errorf("GitHub API rate limit reached (HTTP %d): set GITHUB_TOKEN to raise it", resp.StatusCode)
		}
		if api == "nvd" && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
			return nil, "", fmt.Errorf("NVD API rate limit reached (HTTP %d): set NVD_API_KEY to raise it", resp.StatusCode)
		}
		return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if github {
		if m := nextLink.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			next = m[1]
		}
	}
	if cache != "" {
		_ = os.MkdirAll(filepath.Dir(cache), 0o700)
		// A cache that cannot be written only costs a refetch.
		f.writeCache(cache, data)
		if next != "" {
			f.writeCache(cache+".next", []byte(next))
		}
	}
	return data, next, nil
}

// nvdAttempts bounds the tries of one NVD request answering 502 to 504.
const nvdAttempts = 3

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func (f *Fetcher) writeCache(path string, data []byte) {
	if os.WriteFile(path, data, 0o600) == nil {
		_ = os.Chtimes(path, f.Now(), f.Now()) // age is measured with the same clock
	}
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
