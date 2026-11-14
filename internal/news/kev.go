package news

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	neturl "net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// maxKEVPerTag bounds the KEV entries checked for one tag with a version, the
// most recently added first: each one costs a lookup of its CVE record.
const maxKEVPerTag = 20

// kevConcurrency bounds the CVE records downloaded at once.
const kevConcurrency = 8

// exploitedInUse finds, in the whole KEV catalog, the flaws exploited in the
// wild that hit the version given with a tag (php@8.3.35), whatever the date
// they were added: a version deployed today is exposed to a flaw added last
// month, and it is the first thing to fix. An entry is kept only when the
// ranges of its CVE record (the CVE Program, or the NVD when the record has
// none for the product) hold the version: a name alone proves nothing.
func (f *Fetcher) exploitedInUse(ctx context.Context, catalog []entry, q Query, sources []source.Source, nvd *gate, nvdKEV map[string]map[string][]Affected) ([]entry, []ExploitedCheck) {
	if len(q.Versions) == 0 || len(catalog) == 0 {
		return nil, nil
	}
	checks := map[string]*ExploitedCheck{}
	var nvdURL string
	for _, s := range sources {
		if s.Type == source.TypeNVD {
			nvdURL = s.URL
		}
	}
	type candidate struct {
		e       entry
		tag     string
		version string
		names   []string   // the product names its ranges may carry
		ranges  []Affected // already known, from the NVD search of the product's KEV flaws
	}
	byCVE := map[string]entry{}
	for _, e := range catalog {
		byCVE[cveID.FindString(e.Title)] = e
	}
	var candidates []candidate
	for tag, version := range q.Versions {
		names := f.productNames(tag)
		var hits []entry
		for _, e := range catalog {
			if e.Product != "" && namesProduct(e.Product, names) {
				hits = append(hits, e)
			}
		}
		slices.SortStableFunc(hits, func(a, b entry) int { return b.Published.Compare(a.Published) })
		named := len(hits)
		hits = hits[:min(len(hits), maxKEVPerTag)]
		// The NVD knows the products a flaw reaches through a bundled library:
		// Node.js through Brotli, a KEV entry that never names Node.js.
		known := nvdKEV[tag]
		for id, ranges := range known {
			if e, ok := byCVE[id]; ok && !slices.ContainsFunc(hits, func(h entry) bool { return cveID.FindString(h.Title) == id }) {
				candidates = append(candidates, candidate{e: e, tag: tag, version: version, names: names, ranges: ranges})
			}
		}
		for _, e := range hits {
			// Only the ranges of the tag's own product count: the KEV entry may name
			// another one (React Native Community CLI, whose 19.x is not React's).
			candidates = append(candidates, candidate{e: e, tag: tag, version: version, names: names, ranges: known[cveID.FindString(e.Title)]})
		}
		extra := 0 // found by the NVD only
		for id := range known {
			if _, inKEV := byCVE[id]; inKEV && !slices.ContainsFunc(hits, func(h entry) bool { return cveID.FindString(h.Title) == id }) {
				extra++
			}
		}
		checks[tag] = &ExploitedCheck{Tag: tag, Version: version, Entries: named + extra, Checked: len(hits) + extra}
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, kevConcurrency)
		out []entry
	)
	for _, c := range candidates {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			id := cveID.FindString(c.e.Title)
			if id == "" {
				return
			}
			ranges := c.ranges
			if len(ranges) == 0 {
				ranges = f.programRanges(ctx, id, c.names)
			}
			if len(ranges) == 0 && nvdURL != "" {
				ranges = f.nvdRanges(ctx, nvdURL, id, c.names, nvd)
			}
			var hit []Affected
			for _, a := range ranges {
				if status, ok := versionStatus(c.version, a.Versions); ok && status != StatusNotAffected {
					a.Package, a.InUse, a.Status = c.tag, c.version, status
					if !slices.Contains(hit, a) {
						hit = append(hit, a)
					}
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(ranges) == 0 {
				checks[c.tag].Unproven++
			}
			if len(hit) == 0 {
				return // another branch, a version already fixed, or no range to prove it
			}
			slices.SortStableFunc(hit, func(a, b Affected) int { return cmp.Compare(statusOrder(a.Status), statusOrder(b.Status)) })
			e := c.e
			e.Affected, e.Current = hit, true
			out = append(out, e)
			checks[c.tag].Hits++
		})
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b entry) int { return b.Published.Compare(a.Published) })
	var list []ExploitedCheck
	for _, c := range checks {
		list = append(list, *c)
	}
	slices.SortFunc(list, func(a, b ExploitedCheck) int { return cmp.Compare(a.Tag, b.Tag) })
	return out, list
}

// ExploitedCheck tells what the KEV catalog holds for a tag given with its
// version: a silence must read as "checked, nothing hits it", never as a
// product the catalog does not know, nor as a check that was not done.
type ExploitedCheck struct {
	Tag     string `json:"tag"`
	Version string `json:"version"`
	Entries int    `json:"kev_entries"` // the KEV entries naming the product
	Checked int    `json:"checked"`     // the most recent ones, whose ranges were compared
	Hits    int    `json:"hits"`        // those that hit the version (or possibly, for a branch)
	// Unproven counts the entries whose CVE record gives no range for the
	// product: they could not be compared, and are not listed.
	Unproven int `json:"unproven,omitempty"`
}

// Note says the outcome in one line.
func (c ExploitedCheck) Note() string {
	switch {
	case c.Entries == 0:
		return "no KEV entry names this product: no flaw of it is known to be exploited"
	case c.Hits > 0:
		return fmt.Sprintf("%d of its %d KEV entries hit this version (listed as cisa-kev alerts)", c.Hits, c.Entries)
	}
	note := fmt.Sprintf("none of its %d KEV entries hits this version", c.Entries)
	if c.Checked < c.Entries {
		note = fmt.Sprintf("none of the %d most recent of its %d KEV entries hits this version", c.Checked, c.Entries)
	}
	if c.Unproven > 0 {
		note += fmt.Sprintf(" (%d without a range to compare: check them by hand with stackalarm cve)", c.Unproven)
	}
	return note
}

// kevInUse turns the KEV entries that hit a version in use into items. A CVE
// an item already proves for the same product (a database record whose range
// holds the version) is left to it: the KEV mark reaches it. The same CVE on
// another component (Brotli in an image, Node.js in the front end) is two
// findings, kept apart. A KEV alert the period listed alone gets the ranges
// that prove it, instead of a second item.
func (f *Fetcher) kevInUse(ctx context.Context, kev source.Source, catalog []entry, q Query, sources []source.Source, nvd *gate, nvdKEV map[string]map[string][]Affected, listed []Item) ([]Item, []ExploitedCheck) {
	var out []Item
	found, checks := f.exploitedInUse(ctx, catalog, q, sources, nvd, nvdKEV)
	for _, e := range found {
		id := cveID.FindString(e.Title)
		if slices.ContainsFunc(listed, func(it Item) bool { return it.cve == id && f.proves(it, e.Affected[0].Package) }) {
			continue
		}
		if i := slices.IndexFunc(listed, func(it Item) bool { return it.Source == kev.ID && cveID.FindString(it.Title) == id }); i >= 0 {
			listed[i].Affected = e.Affected
			continue
		}
		it := Item{
			Source: kev.ID, Tags: kev.Tags, Stage: kev.Stage, Title: e.Title, URL: e.URL, Published: e.Published,
			Summary: e.Summary, Language: kev.Language, Affected: e.Affected, cve: id, alone: true,
		}
		it.ID = itemID(it)
		out = append(out, it)
	}
	return out, checks
}

// proves tells whether an item marks the version in use of a product (a tag
// or keyword) affected, or possibly affected.
func (f *Fetcher) proves(it Item, word string) bool {
	names := f.productNames(word)
	return slices.ContainsFunc(it.Affected, func(a Affected) bool {
		return (a.Status == StatusAffected || a.Status == StatusPossiblyAffected) && (a.Package == word || slices.Contains(names, normalName(a.Package)))
	})
}

// productNames returns the names a tag's product goes by in the CVE records:
// the tag, its alias in sources/search.yaml, and its product in the NVD
// dictionary, written the way normalName writes them.
func (f *Fetcher) productNames(tag string) []string {
	names := []string{normalName(tag)}
	if alias := f.Search.Aliases[tag]; alias != "" {
		names = append(names, normalName(alias))
	}
	if cpe := f.Search.CPE[tag]; cpe != "" {
		_, product, _ := strings.Cut(cpe, ":")
		names = append(names, normalName(product))
	}
	return slices.Compact(names)
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// normalName lowercases a product name and drops what is not a letter or a
// digit: "Next.js", "nextjs" and "next-js" are one name.
func normalName(s string) string {
	return nonAlnum.ReplaceAllString(strings.ToLower(s), "")
}

// namesProduct tells whether a KEV vendor and product ("PHP Group PHP",
// "GitLab Community and Enterprise Editions") name one of the products: as a
// word of it, or as the whole of it.
func namesProduct(product string, names []string) bool {
	words := nonAlnum.Split(strings.ToLower(product), -1)
	for _, n := range names {
		if n != "" && (slices.Contains(words, n) || normalName(product) == n) {
			return true
		}
	}
	return false
}

// rangesOf keeps the ranges of the products named.
func rangesOf(affected []Affected, names []string) []Affected {
	var out []Affected
	for _, a := range affected {
		if a.Versions != "" && slices.Contains(names, normalName(a.Package)) {
			out = append(out, a)
		}
	}
	return out
}

// programRanges reads the ranges of the products named from the CVE Program
// record of a CVE.
func (f *Fetcher) programRanges(ctx context.Context, id string, names []string) []Affected {
	if f.CVEAPI == "" {
		return nil
	}
	data, _, err := f.get(ctx, f.CVEAPI+"/"+id, "")
	if err != nil {
		return nil
	}
	p, err := parseCVEProgram(data)
	if err != nil {
		return nil
	}
	return rangesOf(p.Affected, names)
}

// nvdKnown asks the NVD, for each tag or keyword given with a version, about
// the flaws of that version whatever their date, in one request each:
//   - a release of a product of its dictionary (cpe in sources/search.yaml):
//     every CVE whose ranges hold that release;
//   - a branch of such a product: the CVEs of the product in the KEV catalog;
//   - a word without a product (a bundled library such as libwebp): the CVEs
//     of the KEV catalog that mention it.
//
// It returns the ranges of the product in each CVE (word, then CVE), which
// the KEV search compares, and the records of each release, among which those
// with a public exploit are listed. A failed search is reported, and the KEV
// catalog is still searched by name.
func (f *Fetcher) nvdKnown(ctx context.Context, sources []source.Source, q Query, nvd *gate) (map[string]map[string][]Affected, map[string][]entry, error) {
	var nvdURL string
	for _, s := range sources {
		if s.Type == source.TypeNVD {
			nvdURL = s.URL
		}
	}
	ranges, records := map[string]map[string][]Affected{}, map[string][]entry{}
	if nvdURL == "" {
		return ranges, records, nil
	}
	words := slices.Sorted(maps.Keys(q.Versions)) // a stable order, for the cache and the errors
	var errs []error
	for _, word := range words {
		version, cpe := q.Versions[word], f.Search.CPE[word]
		var u string
		switch {
		case cpe != "" && !isBranch(version):
			u = nvdURL + "?virtualMatchString=" + neturl.QueryEscape("cpe:2.3:a:"+cpe+":"+version)
		case cpe != "":
			u = nvdURL + "?virtualMatchString=" + neturl.QueryEscape("cpe:2.3:a:"+cpe) + "&hasKev"
		default:
			u = nvdURL + "?keywordSearch=" + neturl.QueryEscape(word) + "&hasKev"
		}
		if nvd != nil && !f.isCached(u) {
			if err := nvd.wait(ctx); err != nil {
				return ranges, records, err
			}
		}
		data, _, err := f.get(ctx, u, "nvd")
		if err == nil {
			cpes := map[string]string{}
			if cpe != "" {
				cpes[word] = cpe
			}
			var entries []entry
			if entries, err = parseNVD(data, cpes, 0); err == nil {
				ranges[word] = map[string][]Affected{}
				for _, e := range entries {
					if id := cveID.FindString(e.Title); id != "" {
						ranges[word][id] = rangesOf(e.Affected, f.productNames(word))
					}
				}
				if cpe != "" && !isBranch(version) {
					records[word] = entries
				}
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", word, err))
		}
	}
	return ranges, records, errors.Join(errs...)
}

// exploitableInUse lists the NVD records of a release in use that have a
// public exploit (a Nuclei template, a Metasploit module), whatever their
// date: anyone can run the attack, even if CISA has not seen it exploited.
// The KEV ones are listed by the KEV search, and a CVE already listed is
// left to its item.
func exploitableInUse(records map[string][]entry, q Query, exploits, exploited map[string][]string, listed []Item, nvd source.Source) []Item {
	var out []Item
	for _, word := range slices.Sorted(maps.Keys(records)) {
		for _, e := range records[word] {
			id := cveID.FindString(e.Title)
			if id == "" || len(exploits[id]) == 0 || len(exploited[id]) > 0 ||
				slices.ContainsFunc(listed, func(it Item) bool { return it.cve == id && it.Source == nvd.ID }) ||
				slices.ContainsFunc(out, func(it Item) bool { return it.cve == id }) {
				continue
			}
			var hit []Affected
			for _, a := range e.Affected {
				if normalName(a.Package) != normalName(word) {
					continue
				}
				if status, ok := versionStatus(q.Versions[word], a.Versions); ok && status == StatusAffected {
					a.InUse, a.Status = q.Versions[word], status
					hit = append(hit, a)
				}
			}
			if len(hit) == 0 {
				continue
			}
			it := Item{
				Source: nvd.ID, Tags: nvd.Tags, Stage: nvd.Stage, Title: e.Title, URL: e.URL, Published: e.Published,
				Summary: e.Summary, Score: e.Score, Language: nvd.Language, Affected: hit, cve: id,
			}
			it.ID = itemID(it)
			out = append(out, it)
		}
	}
	return out
}

// nvdRanges reads the ranges of the products named from the NVD record of a
// CVE, within the pace the NVD allows.
func (f *Fetcher) nvdRanges(ctx context.Context, nvdURL, id string, names []string, nvd *gate) []Affected {
	u := nvdURL + "?cveId=" + id
	if nvd != nil && !f.isCached(u) {
		if err := nvd.wait(ctx); err != nil {
			return nil
		}
	}
	data, _, err := f.get(ctx, u, "nvd")
	if err != nil {
		return nil
	}
	entries, err := parseNVD(data, f.Search.CPE, 0)
	if err != nil {
		return nil
	}
	var out []Affected
	for _, e := range entries {
		out = append(out, rangesOf(e.Affected, names)...)
	}
	return out
}

// freshOfProducts checks the NVD records of the day, not yet tied to any
// product, that only the word of a tag with a version found: their CVE
// Program record names the product from the start, and the record is kept
// when it is the tag's ("react-server-dom-webpack" for react), dropped when
// it only shares the word ("The Streamit plugin for WordPress… PHP"). A
// record that cannot be read is kept: a doubt never hides a flaw.
func (f *Fetcher) freshOfProducts(ctx context.Context, entries []entry, precise map[string][]string, matched []string, words []*regexp.Regexp) []entry {
	if f.CVEAPI == "" {
		return entries
	}
	type check struct {
		i     int
		names []string
	}
	var checks []check
	for i, e := range entries {
		if len(e.Affected) > 0 || e.Exact {
			continue
		}
		text := matchText(e)
		var names []string
		loose := false
		for j, re := range words {
			if !re.MatchString(text) {
				continue
			}
			n, ok := precise[matched[j]]
			if !ok || n == nil {
				loose = true // an ordinary word matched it too: kept as before
				break
			}
			names = append(names, n...)
		}
		if !loose && len(names) > 0 {
			checks = append(checks, check{i, names})
		}
	}
	drop := make([]bool, len(entries))
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, kevConcurrency)
	)
	for _, c := range checks {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			id := cveID.FindString(entries[c.i].Title)
			data, _, err := f.get(ctx, f.CVEAPI+"/"+id, "")
			if err != nil {
				return
			}
			products, err := cnaProducts(data)
			if err != nil || len(products) == 0 {
				return
			}
			drop[c.i] = !slices.ContainsFunc(products, func(p string) bool { return ofProduct(p, c.names) })
		})
	}
	wg.Wait()
	out := entries[:0]
	for i, e := range entries {
		if !drop[i] {
			out = append(out, e)
		}
	}
	return out
}

// cnaProducts reads the products the publisher of a CVE record names.
func cnaProducts(data []byte) ([]string, error) {
	var r struct {
		Containers struct {
			CNA struct {
				Affected []struct {
					Product     string `json:"product"`
					PackageName string `json:"packageName"`
				} `json:"affected"`
			} `json:"cna"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	var out []string
	for _, a := range r.Containers.CNA.Affected {
		for _, p := range []string{a.Product, a.PackageName} {
			if p != "" && p != "n/a" {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// ofProduct tells whether a product a CVE record names is one of the names,
// or a package of it ("react-server-dom-webpack" of react), never a product
// that only starts with the name ("NginxPulse").
func ofProduct(product string, names []string) bool {
	lower := strings.ToLower(product) // a scope (@react-native/cli) is another product
	for _, n := range names {
		if n == "" {
			continue
		}
		if normalName(product) == n || strings.HasPrefix(lower, n+"-") || strings.HasPrefix(lower, n+"/") || strings.HasPrefix(lower, n+" ") {
			return true
		}
	}
	return false
}
