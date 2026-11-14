package news

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// The ranges maintainers write by hand in their repository advisories, met on
// Mastodon, Vaultwarden, Next.js and LibreChat.
func TestRepoStatus(t *testing.T) {
	for _, c := range []struct {
		version, rng, patched string
		status, fixed         string
		ok                    bool
	}{
		{"1.30.0", "≤ 1.36.0 ", "1.36.1", StatusAffected, "1.36.1", true},
		{"1.30.0", "1.35.3", "1.35.4", "", "", false},                          // the release it was found in proves its branch only
		{"1.35.1", "1.35.3", "1.35.4", StatusPossiblyAffected, "1.35.4", true}, // earlier than the release it was found in: may predate the code
		{"1.35.3", "1.35.3", "1.35.4", StatusAffected, "1.35.4", true},
		{"1.35.4", "1.35.3", "1.35.4", StatusNotAffected, "1.35.4", true},
		{"4.2.0", "v4.3.0-beta.1", "4.3.0-beta.2", "", "", false},
		{"4.2.0", "<= 4.2.8, <= 4.1.16", "4.2.9, 4.1.17", StatusAffected, "4.2.9", true}, // one bound per branch
		{"4.3.0", "<= 4.2.8, <= 4.1.16", "", StatusNotAffected, "", true},
		{"9.0.6", "<= 9.2.0-rc1, <= 9.1.2, <= 9.0.6, <= 8.1.4, <= 7.2.14", "9.0.7", StatusAffected, "9.0.7", true},
		{"9.0.7", "<= 9.2.0-rc1, <= 9.1.2, <= 9.0.6, <= 8.1.4, <= 7.2.14", "9.0.7", StatusNotAffected, "9.0.7", true},
		{"4.4.5", "< v4.5.3, < v4.4.10, < v4.3.17", "", StatusAffected, "4.4.10", true},
		{"4.2.0", "4.7.0-alpha.1; >=4.6.0-beta.1 <4.6.4", "4.6.4", StatusNotAffected, "4.6.4", true}, // alternatives
		{"4.6.1", "4.7.0-alpha.1; >=4.6.0-beta.1 <4.6.4", "4.6.4", StatusAffected, "4.6.4", true},
		{"9", ">= 7.2", "7.2.9, 8.0.3, 8.1.1", StatusNotAffected, "", true}, // a branch newer than every fix
		{"4.2.0", "all", "4.2.5, 4.1.13, 4.0.15", StatusAffected, "4.2.5", true},
		{"4.2.5", "all", "4.2.5, 4.1.13", StatusNotAffected, "4.2.5", true},
		{"4.0.2", "all", "4.2.5, 4.1.13", StatusAffected, "4.1.13", true}, // no fix on 4.0: the next branch
		{"4.2.0", "<= 4.2.x, all main", "", StatusAffected, "", true},
		{"4.3.0", "<= 4.2.x", "", StatusNotAffected, "", true},
		{"4.2.0", "3.1.5-4.4.2", "", StatusAffected, "", true},
		{"4.2.0", ">= 2.6.0", "4.2.5, 4.1.13", StatusAffected, "4.2.5", true},
		{"15.1.0", ">= 13.5.1", "13.5.7, 14.2.10", StatusNotAffected, "", true},
		{"14.0.0", ">= 13.5.1", "13.5.7, 14.2.10", StatusAffected, "14.2.10", true},
		{"0.8.1-rc1", "< v0.8.4-rc1", "v0.8.4-rc1", StatusAffected, "0.8.4-rc1", true},
		{"0.8.1-rc1", "v0.8.3", "0.8.4", StatusPossiblyAffected, "0.8.4", true}, // LibreChat: a feature 0.8.1 may lack
		{"8.38.0", "<= 8.39.0", "8.40.0", StatusAffected, "8.40.0", true},
		{"0.8.1-rc1", "v0.8.2-rc2, v0.8.2-rc3", "0.8.2", StatusNotAffected, "0.8.2", true}, // a list of the affected releases
		{"0.8.2-rc3", "v0.8.2-rc2, v0.8.2-rc3", "0.8.2", StatusAffected, "0.8.2", true},
		{"1.0", "the versions before the rewrite", "", "", "", false},
	} {
		status, fixed, ok := repoStatus(c.version, c.rng, c.patched)
		if status != c.status || fixed != c.fixed || ok != c.ok {
			t.Errorf("repoStatus(%q, %q, %q) = %q, %q, %v; want %q, %q, %v", c.version, c.rng, c.patched, status, fixed, ok, c.status, c.fixed, c.ok)
		}
	}
}

// A record that names the one release a reporter tested, and no fix, proves
// that release affected and says nothing of the others.
func TestASingleTestedReleaseGivesNoVerdictOnTheOthers(t *testing.T) {
	a := Affected{Package: "vaultwarden", Versions: "1.30.3", FixUnknown: true}
	if status, ok := statusOf("1.30.0", a); ok {
		t.Fatalf("1.30.0 against the tested 1.30.3: %q, want no verdict", status)
	}
	if status, ok := statusOf("1.30.3", a); !ok || status != StatusAffected {
		t.Fatalf("1.30.3 itself: %q, %v", status, ok)
	}
	if status, ok := statusOf("6.4.4", Affected{Versions: "6.4.4"}); !ok || status != StatusAffected {
		t.Fatalf("an exact release with a fix still compares: %q, %v", status, ok)
	}
}

// Mastodon's old advisories name no package, Vaultwarden's name its image,
// and both are older than the period: on the version in use, they are listed.
func TestRepositoryAdvisoriesHittingTheVersionAreListedWhateverTheirForm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
{"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2025-24364","html_url":"https://x/1","summary":"RCE in the admin panel","severity":"critical","state":"published","published_at":"2025-01-27T10:00:00Z","updated_at":"2025-01-27T10:00:00Z",
 "vulnerabilities":[{"package":{"ecosystem":"other","name":"vaultwarden/server"},"vulnerable_version_range":"< 1.33.0","patched_versions":"1.33.0"}]},
{"ghsa_id":"GHSA-dddd-eeee-ffff","cve_id":"CVE-2024-23832","html_url":"https://x/2","summary":"Remote user impersonation","severity":"critical","state":"published","published_at":"2024-02-01T10:00:00Z","updated_at":"2024-02-01T10:00:00Z",
 "vulnerabilities":[{"package":{"ecosystem":"","name":""},"vulnerable_version_range":"","patched_versions":"1.30.2"}]},
{"ghsa_id":"GHSA-gggg-hhhh-jjjj","cve_id":null,"html_url":"https://x/3","summary":"Old flaw, fixed long ago","severity":"high","state":"published","published_at":"2023-01-01T10:00:00Z","updated_at":"2023-01-01T10:00:00Z",
 "vulnerabilities":[{"package":{"ecosystem":"","name":""},"vulnerable_version_range":"≤ 1.25.0","patched_versions":"1.25.1"}]},
{"ghsa_id":"GHSA-kkkk-mmmm-pppp","cve_id":"CVE-2024-51999","html_url":"https://x/4","summary":"REJECTED (not a vulnerability): query parsing","severity":"low","state":"published","published_at":"2026-11-01T10:00:00Z","updated_at":"2026-11-01T10:00:00Z",
 "vulnerabilities":[{"package":{"ecosystem":"","name":""},"vulnerable_version_range":"< 2.0.0","patched_versions":"2.0.0"}]}]`))
	}))
	defer srv.Close()
	sources := []source.Source{{ID: "vaultwarden-advisories", Type: source.TypeGitHubAdvisories, Repo: "dani-garcia/vaultwarden", Tags: []string{"vaultwarden"}, Stage: source.StageAdvisory}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", GitHubAPI: srv.URL, Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), sources, Query{Tags: []string{"vaultwarden"}, Versions: map[string]string{"vaultwarden": "1.30.0"}, Since: now.Add(-7 * 24 * time.Hour)})
	var got []string
	for _, it := range res.Items {
		got = append(got, it.Title+" | "+affectedLine(it))
	}
	want := []string{
		"[critical] RCE in the admin panel (CVE-2025-24364) | vaultwarden/server < 1.33.0 fixed 1.33.0 [1.30.0 affected]",
		"[critical] Remote user impersonation (CVE-2024-23832) | vaultwarden  fixed 1.30.2 [1.30.0 affected]",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The NVD writes a pre-release in the update field of the CPE: Mastodon
// 4.2.0:rc1 is not the final 4.2.0.
func TestAPreReleaseCPEIsNotTheFinalRelease(t *testing.T) {
	data := `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2023-42451","published":"2023-09-19T15:15:00.000","descriptions":[{"lang":"en","value":"d"}],
"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:joinmastodon:mastodon:4.2.0:rc1:*:*:*:*:*:*"}]}]}]}},
{"cve":{"id":"CVE-2024-51999","vulnStatus":"Rejected","published":"2024-01-01T00:00:00.000","descriptions":[{"lang":"en","value":"** REJECT **"}]}}]}`
	entries, err := parseNVD([]byte(data), map[string]string{"mastodon": "joinmastodon:mastodon"}, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("a rejected record is dropped: %+v, %v", entries, err)
	}
	a := entries[0].Affected[0]
	if a.Versions != "4.2.0-rc1" {
		t.Fatalf("range %q", a.Versions)
	}
	if status, ok := statusOf("4.2.0", a); ok {
		t.Fatalf("4.2.0 against 4.2.0-rc1: %q", status)
	}
}

// The MongoDB server and its Node.js driver both go by "mongodb": a range of
// the server is never compared with the driver's version.
func TestAProductRangeIsNotComparedWithAPackageOfTheSameName(t *testing.T) {
	q := Query{Packages: []string{"mongodb@6.14.2"}, Versions: map[string]string{}}
	got := annotate([]Affected{{Package: "mongodb", Versions: ">= 6.0.0, < 6.0.30"}}, q, true)
	if got[0].Status != "" {
		t.Fatalf("server range against the driver: %+v", got[0])
	}
	got = annotate([]Affected{{Package: "mongodb", Versions: ">= 6.0.0, < 6.0.30"}}, q, false)
	if got[0].Status != StatusNotAffected {
		t.Fatalf("a package range compares with the package: %+v", got[0])
	}
}

func TestGoToolchain(t *testing.T) {
	if got := goToolchain([]string{"golang.org/x/net@v0.58.0"}, "1.25.5"); !slices.Equal(got, []string{"golang.org/x/net@v0.58.0", "stdlib@1.25.5", "toolchain@1.25.5"}) {
		t.Fatalf("from the tag: %v", got)
	}
	if got := goToolchain([]string{"stdlib@1.25.5"}, ""); !slices.Equal(got, []string{"stdlib@1.25.5", "toolchain@1.25.5"}) {
		t.Fatalf("from stdlib: %v", got)
	}
	if got := goToolchain(nil, "1.25"); len(got) != 0 {
		t.Fatalf("a branch names no release: %v", got)
	}
}

func TestURLBatches(t *testing.T) {
	got := urlBatches([]string{"aaaa", "bbbb", "cccc", "dd"}, 10)
	if len(got) != 2 || strings.Join(got[0], ",") != "aaaa,bbbb" || strings.Join(got[1], ",") != "cccc,dd" {
		t.Fatalf("%v", got)
	}
}

// One GHSA filed under two CVEs by two databases is one flaw; in an image, a
// Debian advisory and a Debian CVE record of the same CVE too.
func TestItemsSharingACVEOrAGHSAAreMerged(t *testing.T) {
	items := []Item{
		{Source: "ghsa-rubygems", Title: "a", cve: "CVE-2026-122006", dup: "GHSA-f3w6-w445-fwh9", rank: 0},
		{Source: "rails-advisories", Title: "b", cve: "CVE-2026-126082", dup: "GHSA-f3w6-w445-fwh9", rank: 1},
		{Source: "osv-debian", Title: "img, DSA", cve: "CVE-2023-44487", alone: true, scope: "img", rank: 2},
		{Source: "osv-debian", Title: "img, DEBIAN", cve: "CVE-2023-44487", alone: true, scope: "img", rank: 3},
		{Source: "osv-debian", Title: "other, DSA", cve: "CVE-2023-44487", alone: true, scope: "other", rank: 4},
		{Source: "cisa-kev", Title: "kev", cve: "CVE-2023-44487", alone: true, rank: 5},
	}
	out, _ := mergeAndCap(items, nil)
	var titles []string
	for _, it := range out {
		titles = append(titles, it.Title)
	}
	if strings.Join(titles, ",") != "a,img, DSA,other, DSA,kev" {
		t.Fatalf("got %v", titles)
	}
}

// Under the cap of an image, what Debian rates harmless comes after every real
// flaw, and what an update fixes before what no release fixes yet.
func TestTurnsPutHarmlessAndUnfixedLast(t *testing.T) {
	e := func(pkg string, fixed string, rank float64) entry {
		return entry{Title: pkg + fixed, Rank: rank, Affected: []Affected{{Package: pkg, Status: StatusAffected, Fixed: fixed}}}
	}
	got := inTurns([]entry{e("zlib", "", 0.1), e("zlib", "", 8), e("openssl", "3.0.1", 8), e("glibc", "", 9)}, true)
	var titles []string
	for _, x := range got {
		titles = append(titles, x.Title)
	}
	if strings.Join(titles, ",") != "openssl3.0.1,zlib,glibc,zlib" {
		t.Fatalf("got %v", titles)
	}
}

// PostgreSQL's CVEs of the day have no range at the NVD yet, but their CVE
// Program record has one: the version given is compared with it.
func TestFreshRecordsGetTheRangesOfTheirCVERecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cve/CVE-2026-116336":
			w.Write([]byte(cveRecord("PostgreSQL", `{"version":"16","lessThan":"16.16","status":"affected"},{"version":"17","lessThan":"17.8","status":"affected"}`)))
		case r.URL.Path == "/nvd" && r.URL.Query().Get("keywordSearch") == "postgresql":
			w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-116336","published":"2026-11-13T10:00:00.000","descriptions":[{"lang":"en","value":"A flaw in PostgreSQL before 16.16 lets an attacker run code."}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.8}}]}}}]}`))
		default:
			w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
		}
	}))
	defer srv.Close()
	sources := []source.Source{{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", CVEAPI: srv.URL + "/cve", Now: func() time.Time { return now },
		Search: source.Search{CPE: map[string]string{"postgresql": "postgresql:postgresql"}}}
	res := f.Fetch(context.Background(), sources, Query{Tags: []string{"postgresql"}, Versions: map[string]string{"postgresql": "16.15"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(res.Items) != 1 || affectedLine(res.Items[0]) != "postgresql >= 16, < 16.16 fixed 16.16 [16.15 affected]; postgresql >= 17, < 17.8 fixed 17.8 [16.15 not-affected]" {
		t.Fatalf("items: %+v", res.Items)
	}
}

// php alone does not list every advisory of Packagist: only the packages
// given, or the composer tag, read it.
func TestPackagistNeedsPackagesOrItsTag(t *testing.T) {
	var asked bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = true
		w.Write([]byte(`{"advisories":{}}`))
	}))
	defer srv.Close()
	sources := []source.Source{{ID: "packagist-advisories", Type: source.TypePackagist, URL: srv.URL + "/", Tags: []string{"php", "composer"}, Stage: source.StageAdvisory}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", Now: func() time.Time { return now }}
	if res := f.Fetch(context.Background(), sources, Query{Tags: []string{"php"}, Since: now.Add(-24 * time.Hour)}); asked || len(res.Failures) > 0 {
		t.Fatalf("php alone asked Packagist: %+v", res)
	}
	f.Fetch(context.Background(), sources, Query{Tags: []string{"composer"}, Since: now.Add(-24 * time.Hour)})
	if !asked {
		t.Fatal("the composer tag reads the advisories of the period")
	}
}

// A keyword alone searches the general sources, not every technology's.
func TestAKeywordAloneReadsTheGeneralSources(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Write([]byte(`<rss><channel></channel></rss>`))
	}))
	defer srv.Close()
	sources := []source.Source{
		{ID: "certfr", Type: source.TypeFeed, URL: srv.URL + "/cert", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "django-weblog", Type: source.TypeFeed, URL: srv.URL + "/django", Tags: []string{"django"}, Stage: source.StageRelease},
	}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", Now: func() time.Time { return now }}
	f.Fetch(context.Background(), sources, Query{Keywords: []string{"librechat"}, Since: now.Add(-24 * time.Hour)})
	if !slices.Equal(paths, []string{"/cert"}) {
		t.Fatalf("read %v", paths)
	}
}

// Django's security release of November 3 is "Deferred" at the NVD: no range,
// so its search by product misses it. The word finds it, the CVE Program
// record gives the range, and the release in use is listed as hit.
func TestDeferredRecordsOfAReleaseInUseAreListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cve/CVE-2026-108147":
			w.Write([]byte(cveRecord("Django", `{"version":"6.1","lessThan":"6.1.3","status":"affected"},{"version":"5.2.13","lessThan":"5.2.19","status":"affected"}`)))
		case r.URL.Path == "/cve/CVE-2026-1":
			w.Write([]byte(cveRecord("django-x", `{"version":"0","lessThan":"9","status":"affected"}`)))
		case r.URL.Path == "/nvd" && r.URL.Query().Get("keywordSearch") == "django" && r.URL.Query().Get("pubStartDate") < "2026-08":
			w.Write([]byte(`{"totalResults":3,"vulnerabilities":[
{"cve":{"id":"CVE-2026-108147","vulnStatus":"Deferred","published":"2026-11-03T10:00:00.000","descriptions":[{"lang":"en","value":"An issue was discovered in Django 5.2.13 before 5.2.19."}]}},
{"cve":{"id":"CVE-2026-1","published":"2026-11-02T10:00:00.000","descriptions":[{"lang":"en","value":"django-x, a Django app, before 9."}]}},
{"cve":{"id":"CVE-2026-2","published":"2026-11-01T10:00:00.000","descriptions":[{"lang":"en","value":"The Django Toolkit plugin for WordPress is vulnerable."}]}}]}`))
		default:
			w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
		}
	}))
	defer srv.Close()
	sources := []source.Source{
		{ID: "cisa-kev", Type: source.TypeKEV, URL: srv.URL + "/kev", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
	}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", CVEAPI: srv.URL + "/cve", Now: func() time.Time { return now },
		Search: source.Search{CPE: map[string]string{"django": "djangoproject:django"}, Skip: []string{"django"}}}
	res := f.Fetch(context.Background(), sources, Query{Tags: []string{"django"}, Versions: map[string]string{"django": "5.2.18"}, Since: now.Add(-7 * 24 * time.Hour)})
	var got []string
	for _, it := range res.Items {
		got = append(got, it.Source+" "+cveID.FindString(it.Title)+" "+affectedLine(it))
	}
	if strings.Join(got, "\n") != "nvd-versions CVE-2026-108147 django >= 5.2.13, < 5.2.19 fixed 5.2.19 [5.2.18 affected]" {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}
}

func TestNamesProduct(t *testing.T) {
	for entry, want := range map[string]bool{
		"PHP Group|PHP": true,
		"PHP|PHPMailer": false, // a library named after PHP is not PHP
		"GitLab|Community and Enterprise Editions": true,
		"Microsoft|Windows":                        false,
	} {
		if got := namesProduct(entry, []string{"php", "gitlab"}); got != want {
			t.Errorf("%s: %v", entry, got)
		}
	}
}

func TestTwoPartReleasesArePostgreSQLReleases(t *testing.T) {
	got := releasesOf(map[string]string{"postgresql": "16.11", "node": "20", "go": "1.25", "postgres": "9.6"})
	if got["postgresql"] != "16.11.0" || got["node"] != "20" || got["go"] != "1.25" || got["postgres"] != "9.6" {
		t.Fatalf("%v", got)
	}
}

func TestRubyOnRailsIsNotRuby(t *testing.T) {
	if namesProduct("Rails|Ruby on Rails", []string{"ruby"}) || !namesProduct("Ruby|Ruby", []string{"ruby"}) {
		t.Fatal("Ruby on Rails is not Ruby")
	}
}

// The MongoDB Node.js driver's advisories are read under the mongodb tag,
// which carries the server's version: the locked driver decides.
func TestARepositoryAdvisoryComparesTheLockedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2026-126837","html_url":"https://x/1","summary":"SRV redirect","severity":"critical","state":"published","published_at":"2025-01-27T10:00:00Z","updated_at":"2025-01-27T10:00:00Z",
 "vulnerabilities":[{"package":{"ecosystem":"npm","name":"mongodb"},"vulnerable_version_range":">= 3.3.3, < 7.8.0","patched_versions":"7.8.0"}]},
{"ghsa_id":"GHSA-dddd-eeee-ffff","cve_id":null,"html_url":"https://x/2","summary":"Pending","severity":"high","state":"published","published_at":"2025-01-27T10:00:00Z","updated_at":"2025-01-27T10:00:00Z",
 "vulnerabilities":[{"package":{"ecosystem":"","name":"redis-server"},"vulnerable_version_range":">= 2.8","patched_versions":"TBD"}]}]`))
	}))
	defer srv.Close()
	sources := []source.Source{{ID: "mongodb-node-driver-advisories", Type: source.TypeGitHubAdvisories, Repo: "mongodb/node-mongodb-native", Tags: []string{"mongodb"}, Stage: source.StageAdvisory}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", GitHubAPI: srv.URL, Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), sources, Query{Tags: []string{"mongodb"}, Versions: map[string]string{"mongodb": "8.0"}, Packages: []string{"mongodb@6.14.2"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(res.Items) != 1 || affectedLine(res.Items[0]) != "mongodb >= 3.3.3, < 7.8.0 fixed 7.8.0 [6.14.2 affected]" {
		t.Fatalf("items: %+v", res.Items)
	}
	entries, _ := parseGitHubAdvisories([]byte(`[{"ghsa_id":"GHSA-dddd-eeee-ffff","html_url":"https://x/2","summary":"Pending","severity":"high","published_at":"2025-01-27T10:00:00Z","vulnerabilities":[{"package":{"name":"redis-server"},"vulnerable_version_range":">= 2.8","patched_versions":"TBD"}]}]`))
	if a := entries[0].Affected[0]; a.Fixed != "" || !a.FixUnknown {
		t.Fatalf("TBD is no fixed version: %+v", a)
	}
}
