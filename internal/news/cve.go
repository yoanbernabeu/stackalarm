package news

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// CVERecord gathers what the databases say of one CVE.
type CVERecord struct {
	ID          string  `json:"id"`
	State       string  `json:"state,omitempty"` // PUBLISHED or REJECTED, from the CVE Program
	Title       string  `json:"title,omitempty"`
	Description string  `json:"description,omitempty"`
	Published   string  `json:"published,omitempty"` // YYYY-MM-DD
	Score       float64 `json:"score,omitempty"`     // the highest CVSS base score given
	EPSS        float64 `json:"epss,omitempty"`
	// SSVC is the decision points of CISA (Vulnrichment): exploitation
	// (none, poc, active), automatable (yes, no), technical impact (partial, total).
	SSVC map[string]string `json:"ssvc,omitempty"`
	// ExploitedIn names the lists reporting the CVE exploited in the wild, and
	// Exploitation what they say of it.
	ExploitedIn     []string   `json:"exploited_in,omitempty"`
	Exploitation    string     `json:"exploitation,omitempty"`
	PublicExploitIn []string   `json:"public_exploit_in,omitempty"`
	Affected        []Affected `json:"affected,omitempty"`
	Advisories      []string   `json:"advisories,omitempty"` // GitHub advisories
	// NotNamed lists the packages given with a version that no range names: a
	// product bundling another's code (Next.js and React) may still be hit.
	NotNamed   []string  `json:"not_named,omitempty"`
	References []string  `json:"references,omitempty"`
	FoundIn    []string  `json:"found_in"` // the databases that know the CVE
	Failures   []Failure `json:"failures"`
}

// maxReferences keeps a record readable: some CVEs carry dozens of links.
const maxReferences = 12

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// ValidCVE tells whether id is written like a CVE id.
func ValidCVE(id string) bool { return cvePattern.MatchString(id) }

// CVE looks one CVE up in the CVE Program record (with the CISA enrichment),
// the NVD, the GitHub Advisory Database, the lists of exploited flaws, the
// catalogs of public exploits and EPSS. inUse gives versions in use
// (name@version), compared with the affected ranges. A database that fails
// is reported in Failures, and the others still answer.
func (f *Fetcher) CVE(ctx context.Context, id string, sources []source.Source, inUse []string) CVERecord {
	rec := CVERecord{ID: id, FoundIn: []string{}, Failures: []Failure{}}
	if f.nvdRejected == nil {
		f.nvdRejected = new(atomic.Bool)
	}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	run := func(name string, fn func() error) {
		wg.Go(func() {
			if err := fn(); err != nil {
				mu.Lock()
				rec.Failures = append(rec.Failures, Failure{Source: name, Error: err.Error()})
				mu.Unlock()
			}
		})
	}
	found := func(name string) {
		if !slices.Contains(rec.FoundIn, name) {
			rec.FoundIn = append(rec.FoundIn, name)
		}
	}
	var (
		program, nvd, github []Affected // merged once every database answered
		described            [3]string  // by the CVE Program, the NVD, GitHub: the first one is kept
	)

	if f.CVEAPI != "" {
		run("cve-program", func() error {
			data, _, err := f.get(ctx, f.CVEAPI+"/"+id, "")
			if err != nil {
				if strings.Contains(err.Error(), "HTTP 404") {
					return nil // unknown or only reserved: FoundIn tells
				}
				return err
			}
			p, err := parseCVEProgram(data)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			found("cve-program")
			rec.State, rec.Title, rec.Published, rec.SSVC = p.State, p.Title, p.Published, p.SSVC
			described[0] = p.Description
			rec.Score = max(rec.Score, p.Score)
			rec.References = p.References
			program = p.Affected
			return nil
		})
	}
	github_ := cmp.Or(f.GitHubAPI, "https://api.github.com")
	run("github-advisory-database", func() error {
		data, _, err := f.get(ctx, github_+"/advisories?cve_id="+id, "github")
		if err != nil {
			return err
		}
		entries, err := parseGitHubAdvisories(data)
		mu.Lock()
		defer mu.Unlock()
		for _, e := range entries {
			found("github-advisory-database")
			rec.Advisories = append(rec.Advisories, e.URL)
			rec.Score, rec.EPSS = max(rec.Score, e.Score), max(rec.EPSS, e.EPSS)
			described[2] = cmp.Or(described[2], e.Summary)
			github = append(github, e.Affected...)
		}
		return err
	})
	for _, s := range sources {
		switch {
		case s.Type == source.TypeNVD:
			run(s.ID, func() error {
				data, _, err := f.get(ctx, s.URL+"?cveId="+id, "nvd")
				if err != nil {
					return err
				}
				entries, err := parseNVD(data, f.Search.CPE, 0)
				mu.Lock()
				defer mu.Unlock()
				for _, e := range entries {
					found(s.ID)
					rec.Score = max(rec.Score, e.Score)
					described[1] = cmp.Or(described[1], e.Summary)
					nvd = append(nvd, e.Affected...)
				}
				return err
			})
		case s.Type == source.TypeKEV, s.Type == source.TypeEUVD && s.Stage == source.StageAlert, s.Type.IsExploitCatalog():
			run(s.ID, func() error {
				entries, err := f.read(ctx, s, terms{}, Query{}, nil, nil)
				mu.Lock()
				defer mu.Unlock()
				for _, e := range entries {
					if cveID.FindString(e.Title) != id {
						continue
					}
					switch {
					case e.Exploit:
						rec.PublicExploitIn = append(rec.PublicExploitIn, s.ID)
					case exploitedTitle.MatchString(e.Title):
						rec.ExploitedIn = append(rec.ExploitedIn, s.ID)
						if s.Type == source.TypeKEV {
							rec.Exploitation = "In CISA KEV since " + e.Published.Format("2006-01-02") + ". " + e.Summary
						}
					}
				}
				return err
			})
		}
	}
	wg.Wait()
	if f.nvdKeyRejected() {
		rec.Failures = append(rec.Failures, Failure{Source: "nvd-api-key", Error: NVDKeyRejected})
	}

	if rec.EPSS == 0 && f.EPSSAPI != "" {
		items := []Item{{cve: id}}
		if err := f.addEPSS(ctx, items); err != nil {
			rec.Failures = append(rec.Failures, Failure{Source: "epss", Error: err.Error()})
		}
		rec.EPSS = items[0].EPSS
	}
	rec.Description = cmp.Or(described[0], described[1], described[2])
	// Package ranges first (they name what a lockfile holds), then the vendor's
	// own, then the NVD products. The databases repeat each other under other
	// names (next, next.js): a range already listed is not listed again.
	for _, a := range slices.Concat(github, program, nvd) {
		if !slices.ContainsFunc(rec.Affected, func(b Affected) bool {
			return a == b || a.Versions != "" && a.Versions == b.Versions && sameProduct(a.Package, b.Package)
		}) {
			rec.Affected = append(rec.Affected, a)
		}
	}
	// The products the description names first: CVE-2023-4863 is a libwebp
	// flaw, and the NVD lists dozens of products that bundle it before it.
	text := normalName(rec.Title + " " + rec.Description)
	slices.SortStableFunc(rec.Affected, func(a, b Affected) int {
		named := func(x Affected) int {
			if n := normalName(x.Package); len(n) > 2 && strings.Contains(text, n) {
				return 0
			}
			return 1
		}
		return cmp.Compare(named(a), named(b))
	})
	q := Query{Packages: inUse, Versions: map[string]string{}}
	for _, p := range inUse {
		if name := packageName(p); name != p {
			q.Versions[strings.ToLower(name)] = strings.TrimPrefix(p, name+"@")
		}
	}
	rec.Affected = annotate(rec.Affected, q)
	for _, p := range inUse {
		name := packageName(p)
		if name != p && len(rec.Affected) > 0 && !slices.ContainsFunc(rec.Affected, func(a Affected) bool { return sameProduct(a.Package, name) }) {
			rec.NotNamed = append(rec.NotNamed, name)
		}
	}
	slices.Sort(rec.FoundIn)
	slices.Sort(rec.ExploitedIn)
	slices.Sort(rec.PublicExploitIn)
	slices.Sort(rec.Advisories)
	rec.Advisories = slices.Compact(rec.Advisories)
	slices.SortFunc(rec.Failures, func(a, b Failure) int { return cmp.Compare(a.Source, b.Source) })
	return rec
}

// sameProduct tells whether two databases name one product: "next" and
// "next.js", "PHP" and "php". react-server-dom-webpack and
// react-server-dom-parcel are two packages, even with the same ranges.
func sameProduct(a, b string) bool {
	x, y := normalName(a), normalName(b)
	return x == y || x+"js" == y || y+"js" == x
}

type cveProgram struct {
	State, Title, Description, Published string
	Score                                float64
	SSVC                                 map[string]string
	Affected                             []Affected
	References                           []string
}

// parseCVEProgram reads a CVE record (format 5), with the containers the
// authorized publishers add: CISA Vulnrichment gives SSVC and scores.
func parseCVEProgram(data []byte) (cveProgram, error) {
	type metrics []map[string]json.RawMessage
	type container struct {
		Title        string `json:"title"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics  metrics `json:"metrics"`
		Affected []struct {
			Vendor   string `json:"vendor"`
			Product  string `json:"product"`
			Versions []struct {
				Version         string `json:"version"`
				Status          string `json:"status"`
				LessThan        string `json:"lessThan"`
				LessThanOrEqual string `json:"lessThanOrEqual"`
			} `json:"versions"`
		} `json:"affected"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	}
	var r struct {
		Meta struct {
			State     string `json:"state"`
			Published string `json:"datePublished"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA container   `json:"cna"`
			ADP []container `json:"adp"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.Meta.State == "" {
		return cveProgram{}, fmt.Errorf("unexpected CVE record")
	}
	cna := r.Containers.CNA
	p := cveProgram{State: r.Meta.State, Title: clean(cna.Title)}
	if len(r.Meta.Published) >= 10 {
		p.Published = r.Meta.Published[:10]
	}
	for _, d := range cna.Descriptions {
		if strings.HasPrefix(d.Lang, "en") || p.Description == "" {
			p.Description = clean(d.Value)
		}
	}
	for _, c := range append([]container{cna}, r.Containers.ADP...) {
		for _, m := range c.Metrics {
			for kind, raw := range m {
				if strings.HasPrefix(kind, "cvss") {
					var s struct {
						Score float64 `json:"baseScore"`
					}
					_ = json.Unmarshal(raw, &s)
					p.Score = max(p.Score, s.Score)
				}
				if kind != "other" {
					continue
				}
				var o struct {
					Type    string `json:"type"`
					Content struct {
						Options []map[string]string `json:"options"`
					} `json:"content"`
				}
				if json.Unmarshal(raw, &o) != nil || o.Type != "ssvc" {
					continue
				}
				p.SSVC = map[string]string{}
				for _, opt := range o.Content.Options {
					for k, v := range opt {
						p.SSVC[strings.ReplaceAll(strings.ToLower(k), " ", "_")] = v
					}
				}
			}
		}
		for _, ref := range c.References {
			if len(p.References) < maxReferences && !slices.Contains(p.References, ref.URL) && strings.HasPrefix(ref.URL, "http") {
				p.References = append(p.References, ref.URL)
			}
		}
	}
	for _, a := range cna.Affected {
		for _, v := range a.Versions {
			if v.Status != "affected" || len(p.Affected) == maxNVDAffected {
				continue
			}
			af := Affected{Package: a.Product, Versions: v.Version}
			from := v.Version
			if from == "0" || from == "*" || from == "unspecified" {
				from = ""
			}
			switch {
			case v.LessThan != "" && v.LessThan != "*":
				af.Versions, af.Fixed = osvRange(from, "< "+v.LessThan), v.LessThan
			case v.LessThanOrEqual != "" && v.LessThanOrEqual != "*":
				af.Versions, af.FixUnknown = osvRange(from, "<= "+v.LessThanOrEqual), true
			case v.LessThan == "*" || v.LessThanOrEqual == "*":
				af.Versions = osvRange(from, "")
			case strings.ContainsAny(v.Version, "<>"): // the range written as text: ">= 15.0.0, < 15.2.3"
				af.Versions = tidyRange(v.Version)
				af.Fixed = fixedIn(af.Versions)
				af.FixUnknown = af.Fixed == ""
			default: // one release
				af.FixUnknown = true
			}
			if !slices.Contains(p.Affected, af) {
				p.Affected = append(p.Affected, af)
			}
		}
	}
	return p, nil
}

// CVEURL is the page of a CVE on cve.org.
func CVEURL(id string) string { return "https://www.cve.org/CVERecord?id=" + neturl.QueryEscape(id) }
