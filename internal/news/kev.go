package news

import (
	"context"
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
func (f *Fetcher) exploitedInUse(ctx context.Context, catalog []entry, q Query, sources []source.Source, nvd *gate) []entry {
	if len(q.Versions) == 0 || len(catalog) == 0 {
		return nil
	}
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
		names   []string // the product names its ranges may carry
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
		for _, e := range hits[:min(len(hits), maxKEVPerTag)] {
			candidates = append(candidates, candidate{e: e, tag: tag, version: version, names: append(slices.Clone(names), normalName(e.Product))})
		}
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
			ranges := f.programRanges(ctx, id, c.names)
			if len(ranges) == 0 && nvdURL != "" {
				ranges = f.nvdRanges(ctx, nvdURL, id, c.names, nvd)
			}
			var hit []Affected
			for _, a := range ranges {
				if in, ok := inRange(c.version, a.Versions); ok && in {
					a.Package, a.InUse, a.Status = c.tag, c.version, StatusAffected
					if !slices.Contains(hit, a) {
						hit = append(hit, a)
					}
				}
			}
			if len(hit) == 0 {
				return // another branch, a version already fixed, or no range to prove it
			}
			e := c.e
			e.Affected, e.Current = hit, true
			mu.Lock()
			out = append(out, e)
			mu.Unlock()
		})
	}
	wg.Wait()
	slices.SortFunc(out, func(a, b entry) int { return b.Published.Compare(a.Published) })
	return out
}

// kevInUse turns the KEV entries that hit a version in use into items. A CVE
// a vulnerability database already listed in the period is left to it: that
// record proves the version, and the KEV mark reaches it. A KEV alert the
// period listed alone gets the ranges that prove it, instead of a second item.
func (f *Fetcher) kevInUse(ctx context.Context, kev source.Source, catalog []entry, q Query, sources []source.Source, nvd *gate, listed []Item) []Item {
	var out []Item
	for _, e := range f.exploitedInUse(ctx, catalog, q, sources, nvd) {
		id := cveID.FindString(e.Title)
		if slices.ContainsFunc(listed, func(it Item) bool { return it.cve == id }) {
			continue
		}
		if i := slices.IndexFunc(listed, func(it Item) bool { return it.Source == kev.ID && cveID.FindString(it.Title) == id }); i >= 0 {
			listed[i].Affected = e.Affected
			continue
		}
		it := Item{
			Source: kev.ID, Tags: kev.Tags, Stage: kev.Stage, Title: e.Title, URL: e.URL, Published: e.Published,
			Summary: e.Summary, Language: kev.Language, Affected: e.Affected, cve: id,
		}
		it.ID = itemID(it)
		out = append(out, it)
	}
	return out
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
