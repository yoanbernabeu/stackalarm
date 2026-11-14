package news

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"slices"
	"strings"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
	"github.com/yoanbernabeu/stackalarm/internal/watch"
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
	if r == nil && v != "" { // docker-engine@24 names the 24.0 cycle
		for i, rel := range releases {
			if strings.HasPrefix(rel.Name, v+".") {
				r = &releases[i]
				break // the releases come newest first
			}
		}
	}
	if r == nil {
		var maintained []string
		for _, rel := range releases {
			if rel.IsMaint {
				maintained = append(maintained, rel.Name)
			}
		}
		// endoflife.date lists only the recent cycles of some products
		// (gitlab-runner): a release older than all of them is long unsupported.
		if len(releases) > 0 && v != "" && v[0] >= '0' && v[0] <= '9' {
			oldest := releases[0].Name
			for _, rel := range releases {
				if compareVersions(rel.Name, oldest) < 0 {
					oldest = rel.Name
				}
			}
			if compareVersions(v, oldest) < 0 {
				s.Status = StatusEOL
				s.Note = "older than every cycle endoflife.date lists (the oldest is " + oldest + "): no security fixes; upgrade to a maintained cycle: " + strings.Join(maintained, ", ")
				return
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
	// A branch (node@22, docker-engine@24) follows its latest release: only a
	// release can be behind.
	behind := s.Latest != "" && v != r.Name && !isBranch(v) && compareVersions(v, s.Latest) < 0
	// An old cycle still gets its last fixes: being behind on them is said
	// too, since the upgrade to the latest patch release is the quick step.
	behindNote := ""
	if behind {
		behindNote = "; also behind: the latest " + r.Name + " release is " + s.Latest + " (" + r.Latest.Date + "), update to it first"
	}
	switch {
	case r.IsEOL || !eol.IsZero() && !now.Before(eol): // the date passed before the data says so
		s.Status, s.Note = StatusEOL, "no security fixes since "+r.EOLFrom+": upgrade to a maintained cycle"+behindNote
	case !eol.IsZero() && eol.Sub(now) < EndingWithin:
		s.Status, s.Note = StatusEnding, fmt.Sprintf("security fixes stop on %s, in %d days: plan the upgrade%s", r.EOLFrom, int(eol.Sub(now).Hours()/24)+1, behindNote)
	case behind:
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

// SupportSource names the items SupportItems makes.
const SupportSource = "endoflife.date"

// SupportItems turns the components of a profile whose security fixes stop
// into items for a scheduled watch: ending as a heads-up, eol as an alert.
// Their id holds the status, so each change is reported once. behind is
// left out: the release sources already announce the new patch releases.
func (f *Fetcher) SupportItems(ctx context.Context, stack []watch.Component) ([]Item, error) {
	if f.EOLAPI == "" {
		return nil, nil
	}
	var (
		components []string
		from       []string
	)
	for _, c := range stack {
		if c.Version != "" && c.Version != "unknown" {
			components = append(components, c.Name+"@"+c.Version)
			from = append(from, c.From)
		}
	}
	if len(components) == 0 {
		return nil, nil
	}
	support, err := f.Support(ctx, components)
	if err != nil {
		return nil, err
	}
	var out []Item
	for i, s := range support {
		var stage source.Stage
		switch s.Status {
		case StatusEOL:
			stage = source.StageAlert
		case StatusEnding:
			stage = source.StageHeadsUp
		default:
			continue
		}
		where := ""
		if from[i] != "" {
			where = " (from " + from[i] + ")"
		}
		it := Item{
			Source: SupportSource, Tags: []string{strings.ToLower(s.Name)}, Stage: stage, URL: s.URL, Published: f.Now().UTC(),
			Title: "End of life: " + s.Name + " " + s.Version + where + ": " + s.Note,
			Summary: "The version comes from the project profile written by the stackalarm skill. If the project has moved on, " +
				"run /stackalarm to refresh .stackalarm.yaml.",
		}
		sum := sha256.Sum256([]byte(SupportSource + "\n" + s.Product + "\n" + s.Cycle + "\n" + s.Status))
		it.ID = hex.EncodeToString(sum[:6])
		out = append(out, it)
	}
	return out, nil
}
