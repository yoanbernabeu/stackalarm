package news

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"slices"
	"strings"
	"time"
)

// packagistBatch bounds the packages of one request: they go in the URL.
const packagistBatch = 50

// readPackagist asks the Packagist API, the one composer audit reads, for the
// security advisories of Composer packages. It holds the FriendsOfPHP database
// besides the GitHub one, and FriendsOfPHP often lists a flaw days before
// OSV.dev does.
//
// Packages given with a version get every known advisory hitting that
// version, whatever its date, like OSV. Without versions, the advisories
// reported or updated in the period are read, narrowed to the packages named
// when there are some.
func (f *Fetcher) readPackagist(ctx context.Context, url string, packages []string, since time.Time) ([]entry, error) {
	versions := map[string]string{}
	var names []string
	for _, p := range packages {
		name := packageName(p)
		if strings.HasPrefix(name, "@") || strings.Count(name, "/") != 1 { // npm scopes, Go modules: not Composer
			continue
		}
		names = append(names, name)
		if v := strings.TrimPrefix(strings.TrimPrefix(p, name), "@"); v != "" {
			versions[name] = strings.TrimPrefix(v, "v")
		}
	}
	var (
		out  []entry
		errs []error
	)
	if len(versions) > 0 {
		asked := slices.Sorted(func(yield func(string) bool) {
			for n := range versions {
				if !yield(n) {
					return
				}
			}
		})
		for batch := range slices.Chunk(asked, packagistBatch) {
			q := neturl.Values{}
			for _, n := range batch {
				q.Add("packages[]", n)
			}
			entries, err := f.packagistAdvisories(ctx, url+"?"+q.Encode(), versions, nil)
			out = append(out, entries...)
			errs = append(errs, err)
		}
		return out, errors.Join(errs...)
	}
	u := url + "?updatedSince=" + fmt.Sprint(since.Unix())
	entries, err := f.packagistAdvisories(ctx, u, nil, names)
	return entries, err
}

// packagistAdvisories reads one answer of the API. With versions, only the
// advisories whose ranges hold the version are kept, marked affected; with
// names, only the advisories of those packages.
func (f *Fetcher) packagistAdvisories(ctx context.Context, url string, versions map[string]string, names []string) ([]entry, error) {
	data, _, err := f.get(ctx, url, "")
	if err != nil {
		return nil, err
	}
	var r struct {
		Advisories map[string][]struct {
			ID         string `json:"advisoryId"`
			Package    string `json:"packageName"`
			Title      string `json:"title"`
			Link       string `json:"link"`
			CVE        string `json:"cve"`
			Affected   string `json:"affectedVersions"`
			ReportedAt string `json:"reportedAt"`
			Severity   string `json:"severity"`
		} `json:"advisories"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("unexpected Packagist answer: %w", err)
	}
	var out []entry
	for pkg, list := range r.Advisories {
		if len(names) > 0 && !slices.Contains(names, pkg) {
			continue
		}
		for _, a := range list {
			version, given := versions[pkg]
			var ranges []Affected
			for _, alt := range strings.Split(a.Affected, "|") {
				rng, ok := composerRange(alt)
				if !ok {
					continue
				}
				af := Affected{Package: pkg, Versions: rng, Fixed: fixedIn(rng)}
				if given {
					status, ok := versionStatus(version, rng)
					if !ok || status != StatusAffected {
						continue
					}
					af.InUse, af.Status = version, status
				}
				ranges = append(ranges, af)
			}
			if given && len(ranges) == 0 {
				continue // another branch, or a version already fixed
			}
			id := firstNonEmpty(a.CVE, a.ID)
			title := a.Title
			if a.Severity != "" {
				title = "[" + strings.ToLower(a.Severity) + "] " + title
			}
			e := entry{Title: clean(title + " (" + id + ")"), URL: firstNonEmpty(a.Link, "https://packagist.org/security-advisories/"+a.ID), Affected: ranges, Current: true} // asked by version, or updated in the period: Packagist chose
			e.Published, _ = time.Parse(time.DateTime, a.ReportedAt)
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(a, b entry) int { return b.Published.Compare(a.Published) })
	return out, nil
}

// composerRange turns one alternative of a Composer constraint (">=6.3.0,<6.4.0")
// into a range ("">= 6.3.0, < 6.4.0"); ok is false for what the comparison
// does not read (^, ~, !=, wildcards).
func composerRange(alt string) (string, bool) {
	var parts []string
	for _, c := range strings.Split(strings.TrimSpace(alt), ",") {
		c = strings.TrimSpace(c)
		op := c[:len(c)-len(strings.TrimLeft(c, "<>=!~^"))]
		v := strings.TrimPrefix(strings.TrimSpace(c[len(op):]), "v")
		switch {
		case v == "" || strings.ContainsAny(v, "*x"):
			return "", false
		case op == "==":
			op = "="
		case !slices.Contains([]string{"<", "<=", ">", ">=", "=", ""}, op):
			return "", false
		}
		parts = append(parts, strings.TrimSpace(op+" "+v))
	}
	if len(parts) == 0 {
		return "", false
	}
	return tidyRange(strings.Join(parts, ", ")), true
}
