package news

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// readRubySec reads the Ruby Advisory Database, the one bundle audit reads:
// many gem advisories (rodauth, phlex…) live there only, in neither OSV.dev
// nor the GitHub Advisory Database. It is read as one archive of a few
// hundred kilobytes, outside the rate limit of the GitHub API.
//
// Gems given with a version get every advisory hitting that version, whatever
// its date. Without versions, the advisories dated in the period are read,
// narrowed to the gems named when there are some. A version on the ruby or
// jruby tag gets the advisories of the interpreter itself.
func (f *Fetcher) readRubySec(ctx context.Context, url string, packages []string, versions map[string]string, since time.Time) ([]entry, error) {
	gems := map[string]string{} // name: version, "" when none
	for _, p := range packages {
		name := packageName(p)
		if strings.Contains(name, "/") || strings.HasPrefix(name, "@") {
			continue // a Composer, npm or Go package: not a gem
		}
		gems[name] = strings.TrimPrefix(strings.TrimPrefix(p, name), "@")
	}
	engines := map[string]string{}
	for _, e := range []string{"ruby", "jruby"} {
		if v := versions[e]; v != "" {
			engines[e] = v
		}
	}
	data, _, err := f.get(ctx, url, "")
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("unexpected Ruby Advisory Database archive: %w", err)
	}
	tr := tar.NewReader(zr)
	var (
		out  []entry
		errs []error
	)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("unexpected Ruby Advisory Database archive: %w", err)
		}
		// <root>/gems/<gem>/<id>.yml or <root>/rubies/<engine>/<id>.yml
		parts := strings.Split(h.Name, "/")
		if len(parts) != 4 || path.Ext(h.Name) != ".yml" {
			continue
		}
		kind, name := parts[1], parts[2]
		var version string
		switch kind {
		case "gems":
			v, ok := gems[name]
			if !ok && len(gems) > 0 {
				continue
			}
			version = v
		case "rubies":
			v, ok := engines[name]
			if !ok {
				continue
			}
			version = v
		default:
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return out, err
		}
		e, keep, err := rubyAdvisory(body, name, version, since)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h.Name, err))
			continue
		}
		if keep {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b entry) int { return b.Published.Compare(a.Published) })
	if len(errs) > 3 { // a few odd files are not worth a failure each
		errs = append(errs[:3], fmt.Errorf("and %d more files", len(errs)-3))
	}
	return out, errors.Join(errs...)
}

// rubyAdvisory reads one advisory and tells whether to keep it: with a
// version, when the version is neither patched nor unaffected; without, when
// it is dated in the period.
func rubyAdvisory(body []byte, name, version string, since time.Time) (entry, bool, error) {
	var a struct {
		Gem        string  `yaml:"gem"`
		Engine     string  `yaml:"engine"`
		CVE        string  `yaml:"cve"`
		GHSA       string  `yaml:"ghsa"`
		URL        string  `yaml:"url"`
		Title      string  `yaml:"title"`
		Date       string  `yaml:"date"`
		CVSS3      float64 `yaml:"cvss_v3"`
		CVSS4      float64 `yaml:"cvss_v4"`
		Patched    []any   `yaml:"patched_versions"`
		Unaffected []any   `yaml:"unaffected_versions"`
	}
	if err := yaml.Unmarshal(body, &a); err != nil {
		return entry{}, false, err
	}
	id := ""
	switch {
	case a.CVE != "":
		id = "CVE-" + strings.TrimPrefix(a.CVE, "CVE-")
	case a.GHSA != "":
		id = "GHSA-" + strings.TrimPrefix(a.GHSA, "GHSA-")
	}
	e := entry{URL: a.URL, Score: max(a.CVSS3, a.CVSS4), Current: version != ""}
	if d, err := time.Parse(time.DateOnly, a.Date); err == nil {
		e.Published = d
	}
	title := a.Title
	if s := severityOf(e.Score); s != "" {
		title = "[" + s + "] " + title
	}
	if id != "" && !strings.Contains(title, id) {
		title += " (" + id + ")"
	}
	e.Title = clean(title)
	patched, unaffected := constraints(a.Patched), constraints(a.Unaffected)
	if version == "" {
		if e.Published.Before(since) {
			return e, false, nil
		}
		e.Affected = []Affected{{Package: name, Versions: rubyRange(patched, unaffected), Fixed: lowestFix(patched, "")}}
		return e, true, nil
	}
	for _, c := range slices.Concat(patched, unaffected) {
		if ok, readable := gemSatisfies(version, c); readable && ok {
			return e, false, nil // patched, or never affected
		}
	}
	e.Affected = []Affected{{Package: name, Versions: rubyRange(patched, unaffected), Fixed: lowestFix(patched, version), InUse: version, Status: StatusAffected}}
	return e, true, nil
}

// constraints keeps the readable constraints of a list: some entries are notes.
func constraints(list []any) []string {
	var out []string
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if _, readable := gemSatisfies("0", s); readable {
			out = append(out, s)
		}
	}
	return out
}

// rubyRange describes the vulnerable versions: those that match none of the
// patched and unaffected constraints.
func rubyRange(patched, unaffected []string) string {
	all := slices.Concat(patched, unaffected)
	if len(all) == 0 {
		return ""
	}
	return "all but " + strings.Join(all, " or ")
}

// lowestFix gives the lowest patched release above the version in use (any,
// without one): the smallest update that fixes it.
func lowestFix(patched []string, version string) string {
	var best string
	for _, c := range patched {
		for _, part := range strings.Split(c, ",") {
			part = strings.TrimSpace(part)
			v, ok := strings.CutPrefix(part, ">=")
			if !ok {
				v, ok = strings.CutPrefix(part, "~>")
			}
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if version != "" && compareVersions(v, version) <= 0 {
				continue
			}
			if best == "" || compareVersions(v, best) < 0 {
				best = v
			}
		}
	}
	return best
}

// gemSatisfies tells whether a version matches a RubyGems constraint such as
// ">= 2.47.0", "~> 2.46.3" (>= 2.46.3, < 2.47) or "~> 5.2.4, >= 5.2.4.3";
// readable is false for a note that is no constraint.
func gemSatisfies(version, constraint string) (ok, readable bool) {
	ok = true
	for _, c := range strings.Split(constraint, ",") {
		c = strings.TrimSpace(c)
		op := c[:len(c)-len(strings.TrimLeft(c, "<>=!~"))]
		v := strings.TrimSpace(c[len(op):])
		if v == "" || !isVersionLike(v) {
			return false, false
		}
		d := compareVersions(version, v)
		switch op {
		case ">=":
			ok = ok && d >= 0
		case ">":
			ok = ok && d > 0
		case "<=":
			ok = ok && d <= 0
		case "<":
			ok = ok && d < 0
		case "=", "":
			ok = ok && d == 0
		case "!=":
			ok = ok && d != 0
		case "~>":
			// The last part may change, the one before may not: "~> 2.46.3" is
			// below 2.47, "~> 2.4" below 3, and "~> 5" below 6.
			parts := strings.Split(v, ".")
			if len(parts) > 1 {
				parts = parts[:len(parts)-1]
			}
			last, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				return false, false
			}
			parts[len(parts)-1] = strconv.Itoa(last + 1)
			ok = ok && d >= 0 && compareVersions(version, strings.Join(parts, ".")) < 0
		default:
			return false, false
		}
	}
	return ok, true
}

// isVersionLike tells whether a string reads as a version: digits and dots,
// with letters for pre-releases.
func isVersionLike(v string) bool {
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r == '.' || r >= 'a' && r <= 'z' || r == '-') {
			return false
		}
	}
	return true
}
