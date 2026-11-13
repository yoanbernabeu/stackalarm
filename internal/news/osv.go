package news

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	neturl "net/url"
	"slices"
	"strings"
	"sync"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// OSV limits: the queries of one batch request, the vulnerabilities whose
// record is downloaded for one ecosystem, and the downloads in flight.
const (
	osvBatch       = 500
	MaxOSVRecords  = 150
	osvConcurrency = 8
)

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// readOSV asks OSV.dev which known vulnerabilities hit the packages given
// with a version, in one ecosystem. Unlike the other sources it is not news:
// a flaw published last year still hits a version locked today, so its
// entries are kept whatever their date. Packages without a version are left
// to the GitHub Advisory Database sources, which read the recent advisories.
func (f *Fetcher) readOSV(ctx context.Context, ecosystem string, packages []string) ([]entry, error) {
	if f.OSVAPI == "" {
		return nil, nil
	}
	var queries []osvQuery
	for _, p := range packages {
		name := packageName(p)
		version := strings.TrimPrefix(strings.TrimPrefix(p, name), "@")
		if version == "" {
			continue
		}
		if ecosystem == "Go" {
			version = strings.TrimPrefix(version, "v") // go.mod writes v1.2.3, OSV 1.2.3
		}
		var q osvQuery
		q.Package.Name, q.Package.Ecosystem, q.Version = name, ecosystem, version
		queries = append(queries, q)
	}
	if len(queries) == 0 {
		return nil, nil
	}
	var (
		errs  []error
		hits  = map[string][]osvQuery{} // vulnerability id: the queries it answers
		order []string
	)
	for batch := range slices.Chunk(queries, osvBatch) {
		body, _ := json.Marshal(map[string]any{"queries": batch})
		data, err := f.post(ctx, f.OSVAPI+"/querybatch", string(body))
		if err != nil {
			return nil, err
		}
		var r struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
				Next string `json:"next_page_token"`
			} `json:"results"`
		}
		if err := json.Unmarshal(data, &r); err != nil || len(r.Results) != len(batch) {
			return nil, fmt.Errorf("unexpected OSV response: %d results for %d packages", len(r.Results), len(batch))
		}
		for i, res := range r.Results {
			if res.Next != "" {
				errs = append(errs, fmt.Errorf("partial: %s@%s has more vulnerabilities than one page holds", batch[i].Package.Name, batch[i].Version))
			}
			for _, v := range res.Vulns {
				if _, seen := hits[v.ID]; !seen {
					order = append(order, v.ID)
				}
				hits[v.ID] = append(hits[v.ID], batch[i])
			}
		}
	}
	if len(order) > MaxOSVRecords {
		errs = append(errs, fmt.Errorf("partial: %d vulnerabilities hit the packages given, only %d read (give fewer packages at a time)", len(order), MaxOSVRecords))
		order = order[:MaxOSVRecords]
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, osvConcurrency)
		out = make([]*entry, len(order))
	)
	for i, id := range order {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			data, _, err := f.get(ctx, f.OSVAPI+"/vulns/"+neturl.PathEscape(id), "")
			if err == nil {
				out[i], err = parseOSV(data, hits[id], order)
			}
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", id, err))
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	var entries []entry
	for _, e := range out {
		if e != nil {
			entries = append(entries, *e)
		}
	}
	return entries, errors.Join(errs...)
}

// parseOSV reads one OSV record. asked holds the packages and versions the
// record was returned for: their ranges are the ones shown, and returned the
// ids of every record of the answer. A withdrawn record gives no entry.
func parseOSV(data []byte, asked []osvQuery, returned []string) (*entry, error) {
	var v struct {
		ID        string   `json:"id"`
		Summary   string   `json:"summary"`
		Details   string   `json:"details"`
		Aliases   []string `json:"aliases"`
		Published string   `json:"published"`
		Withdrawn string   `json:"withdrawn"`
		Severity  []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Specific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced   string `json:"introduced"`
					Fixed        string `json:"fixed"`
					LastAffected string `json:"last_affected"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(data, &v); err != nil || v.ID == "" {
		return nil, fmt.Errorf("unexpected OSV record")
	}
	if v.Withdrawn != "" {
		return nil, nil
	}
	// The same flaw comes back once per database (GHSA, GO, PYSEC, RUSTSEC):
	// the record whose id sorts first is kept, GHSA ahead of the others.
	for _, alias := range v.Aliases {
		if alias < v.ID && slices.Contains(returned, alias) {
			return nil, nil
		}
	}
	e := entry{URL: "https://osv.dev/vulnerability/" + v.ID, Summary: clean(v.Details), Current: true}
	e.Published, _ = parseDate(v.Published)
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			e.Score = max(e.Score, cvss3(s.Score))
		}
	}
	id := v.ID
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			id = a
			break
		}
	}
	title := firstNonEmpty(v.Summary, v.Details)
	if r := []rune(clean(title)); len(r) > 140 {
		title = string(r[:140]) + "…"
	}
	severity := strings.ToLower(cmp.Or(v.Specific.Severity, severityOf(e.Score)))
	if strings.HasPrefix(v.ID, "MAL-") { // a version published with malicious code
		severity, e.Stage = "malware", source.StageAlert
	}
	if severity != "" {
		title = "[" + severity + "] " + title
	}
	e.Title = clean(title + " (" + id + ")")

	for _, q := range asked {
		var ranges []Affected
		for _, a := range v.Affected {
			if !strings.EqualFold(a.Package.Name, q.Package.Name) {
				continue
			}
			for _, r := range a.Ranges {
				if r.Type == "GIT" {
					continue // commits, not versions
				}
				from, open := "", false
				for _, ev := range r.Events {
					switch {
					case ev.Introduced != "":
						from, open = ev.Introduced, true
					case ev.Fixed != "":
						ranges = append(ranges, Affected{Package: q.Package.Name, Versions: osvRange(from, "< "+ev.Fixed), Fixed: ev.Fixed})
						open = false
					case ev.LastAffected != "":
						ranges = append(ranges, Affected{Package: q.Package.Name, Versions: osvRange(from, "<= "+ev.LastAffected)})
						open = false
					}
				}
				if open { // introduced, never fixed: every later version
					ranges = append(ranges, Affected{Package: q.Package.Name, Versions: osvRange(from, "")})
				}
			}
		}
		// OSV says the version is hit: tell which range holds it, when the
		// versions can be compared, and say it of the package otherwise.
		found := false
		for i := range ranges {
			if in, _ := inRange(q.Version, ranges[i].Versions); in || ranges[i].Versions == "" {
				ranges[i].InUse, ranges[i].Status, found = q.Version, StatusAffected, true
			}
		}
		if !found {
			ranges = []Affected{{Package: q.Package.Name, Versions: q.Version, InUse: q.Version, Status: StatusAffected, Fixed: lastFixed(ranges)}}
		} else {
			ranges = slices.DeleteFunc(ranges, func(a Affected) bool { return a.Status == "" }) // the other branches
		}
		e.Affected = append(e.Affected, ranges...)
	}
	return &e, nil
}

// osvRange writes ">= 13.0.0, < 13.5.9" from the events of an OSV range.
func osvRange(introduced, end string) string {
	if introduced == "" || introduced == "0" {
		return end
	}
	if end == "" {
		return ">= " + introduced
	}
	return ">= " + introduced + ", " + end
}

func lastFixed(ranges []Affected) string {
	for _, r := range slices.Backward(ranges) {
		if r.Fixed != "" {
			return r.Fixed
		}
	}
	return ""
}

// severityOf names a CVSS base score the way the advisory databases do.
func severityOf(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "moderate"
	case score > 0:
		return "low"
	}
	return ""
}

// cvss3 computes the base score of a CVSS 3.0 or 3.1 vector, 0 when it
// cannot be read. OSV gives the vector, never the score.
func cvss3(vector string) float64 {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, v, _ := strings.Cut(part, ":")
		m[k] = v
	}
	if !strings.HasPrefix(m["CVSS"], "3.") {
		return 0
	}
	changed := m["S"] == "C"
	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	pr, ok4 := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if changed && m["PR"] == "L" {
		pr = 0.68
	} else if changed && m["PR"] == "H" {
		pr = 0.5
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, ok5 := cia[m["C"]]
	i, ok6 := cia[m["I"]]
	a, ok7 := cia[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	base := impact + 8.22*av*ac*pr*ui
	if changed {
		base *= 1.08
	}
	return math.Ceil(min(base, 10)*10-1e-9) / 10 // rounded up to one decimal
}
