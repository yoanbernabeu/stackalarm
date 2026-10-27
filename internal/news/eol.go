package news

import (
	"context"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"slices"
	"strings"
	"time"
)

// Support statuses, from the most to the least urgent.
const (
	StatusEOL       = "eol"       // no more security fixes
	StatusEnding    = "ending"    // security fixes stop within EndingWithin
	StatusBehind    = "behind"    // a newer release of the same cycle is out
	StatusSupported = "supported" // nothing to do
	StatusUnknown   = "unknown"   // product or cycle not found, or version too vague
)

// EndingWithin is how early an end of support is reported: upgrading a
// runtime or a framework takes weeks to plan.
const EndingWithin = 180 * 24 * time.Hour

// Support is the support status of one component of a project, from
// endoflife.date.
type Support struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Product string `json:"product,omitempty"` // endoflife.date id
	Cycle   string `json:"cycle,omitempty"`
	Status  string `json:"status"`
	EOL     string `json:"eol,omitempty"`    // when security fixes stop, YYYY-MM-DD
	Latest  string `json:"latest,omitempty"` // the latest release of the cycle
	Note    string `json:"note"`
	URL     string `json:"url,omitempty"`
}

type eolRelease struct {
	Name     string `json:"name"`
	IsEOL    bool   `json:"isEol"`
	EOLFrom  string `json:"eolFrom"`
	IsMaint  bool   `json:"isMaintained"`
	IsEOAS   bool   `json:"isEoas"`
	EOASFrom string `json:"eoasFrom"`
	Latest   *struct {
		Name string `json:"name"`
		Date string `json:"date"`
	} `json:"latest"`
}

// Support looks up the support status of components given as name@version
// (php@8.3.35, node@22, gitlab). One failure fails the whole lookup: a
// partial answer would read as "the others are fine".
func (f *Fetcher) Support(ctx context.Context, components []string) ([]Support, error) {
	if f.EOLAPI == "" {
		return nil, fmt.Errorf("no endoflife.date API configured")
	}
	data, _, err := f.get(ctx, f.EOLAPI+"/products", "")
	if err != nil {
		return nil, fmt.Errorf("endoflife.date: %w", err)
	}
	var list struct {
		Result []struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("endoflife.date: unexpected product list: %w", err)
	}
	product := func(name string) string {
		for _, n := range []string{name, strings.NewReplacer(".", "", " ", "-").Replace(name)} {
			for _, p := range list.Result {
				if p.Name == n || slices.Contains(p.Aliases, n) {
					return p.Name
				}
			}
		}
		return ""
	}
	var out []Support
	for _, c := range components {
		name, version, _ := strings.Cut(strings.TrimSpace(c), "@")
		s := Support{Name: name, Version: version, Product: product(strings.ToLower(name)), Status: StatusUnknown}
		if s.Product == "" {
			s.Note = "not followed by endoflife.date: check its support policy by hand"
			out = append(out, s)
			continue
		}
		s.URL = "https://endoflife.date/" + s.Product
		data, _, err := f.get(ctx, f.EOLAPI+"/products/"+neturl.PathEscape(s.Product), "")
		if err != nil {
			return nil, fmt.Errorf("endoflife.date %s: %w", s.Product, err)
		}
		var p struct {
			Result struct {
				Releases []eolRelease `json:"releases"`
			} `json:"result"`
		}
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("endoflife.date %s: unexpected answer: %w", s.Product, err)
		}
		f.judge(&s, p.Result.Releases)
		out = append(out, s)
	}
	return out, nil
}

// judge sets the status of s from the releases of its product.
func (f *Fetcher) judge(s *Support, releases []eolRelease) {
	v := strings.TrimPrefix(s.Version, "v")
	var r *eolRelease
	for i, rel := range releases { // the longest cycle the version belongs to: 1.27 rather than 1
		if (v == rel.Name || strings.HasPrefix(v, rel.Name+".")) && (r == nil || len(rel.Name) > len(r.Name)) {
			r = &releases[i]
		}
	}
	if r == nil {
		var maintained []string
		for _, rel := range releases {
			if rel.IsMaint {
				maintained = append(maintained, rel.Name)
			}
		}
		s.Note = "version unknown or too vague to find its cycle; maintained cycles: " + strings.Join(maintained, ", ")
		return
	}
	s.Cycle, s.EOL = r.Name, r.EOLFrom
	if r.Latest != nil {
		s.Latest = r.Latest.Name
	}
	eol, _ := time.Parse(time.DateOnly, r.EOLFrom)
	now := f.Now()
	switch {
	case r.IsEOL:
		s.Status, s.Note = StatusEOL, "no security fixes since "+r.EOLFrom+": upgrade to a maintained cycle"
	case !eol.IsZero() && eol.Sub(now) < EndingWithin:
		s.Status, s.Note = StatusEnding, fmt.Sprintf("security fixes stop on %s, in %d days: plan the upgrade", r.EOLFrom, int(eol.Sub(now).Hours()/24)+1)
	case s.Latest != "" && v != r.Name && compareVersions(v, s.Latest) < 0:
		s.Status, s.Note = StatusBehind, "the latest "+r.Name+" release is "+s.Latest+" ("+r.Latest.Date+"): patch releases often carry security fixes"
	default:
		s.Status, s.Note = StatusSupported, "supported"
		if r.EOLFrom != "" {
			s.Note += " until " + r.EOLFrom
		}
	}
	if r.IsEOAS && !r.IsEOL {
		s.Note += " (active support has ended, only security fixes are published)"
	}
}
