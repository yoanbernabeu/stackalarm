package news

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// A record of the product php:php, whose wording never says "twig" nor "php".
const nvdProduct = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-500","published":"2026-10-21T10:00:00.000",
"descriptions":[{"lang":"en","value":"Memory corruption in the engine."}],
"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]},
"configurations":[{"nodes":[{"cpeMatch":[
{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","versionStartIncluding":"8.2.0","versionEndExcluding":"8.2.34"},
{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","versionStartIncluding":"8.3.0","versionEndExcluding":"8.3.35"},
{"vulnerable":true,"criteria":"cpe:2.3:a:other:thing:1.2.3:*:*:*:*:*:*:*"},
{"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}]}]}}]}`

func TestNVDRangesAreComparedWithTheVersionInUse(t *testing.T) {
	entries, err := parseNVD([]byte(nvdProduct), map[string]string{"php": "php:php"}, minScore)
	if err != nil || len(entries) != 1 || len(entries[0].Affected) != 3 {
		t.Fatalf("got %+v, %v", entries, err)
	}
	got := annotate(entries[0].Affected, Query{Versions: map[string]string{"php": "8.3.20"}})
	if got[0] != (Affected{Package: "php", Versions: ">= 8.3.0, < 8.3.35", Fixed: "8.3.35", InUse: "8.3.20", Status: StatusAffected}) {
		t.Fatalf("the range holding the version in use comes first, named after the tag: %+v", got)
	}
	if got[1].Status != StatusNotAffected || got[2] != (Affected{Package: "thing", Versions: "1.2.3"}) {
		t.Fatalf("the other branch is not affected, an unwatched product has no status: %+v", got)
	}
}

func TestSkippedTagsAreSearchedByProduct(t *testing.T) {
	var (
		mu      sync.Mutex
		queries []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query().Get("virtualMatchString")+"|"+r.URL.Query().Get("keywordSearch"))
		mu.Unlock()
		w.Write([]byte(nvdProduct))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now },
		Search: source.Search{Skip: []string{"twig", "swift"}, CPE: map[string]string{"twig": "symfony:twig"}}}
	res := f.Fetch(context.Background(), []source.Source{
		{ID: "nvd", Type: source.TypeNVD, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageAdvisory},
	}, Query{Tags: []string{"twig", "swift"}, Since: now.Add(-7 * 24 * time.Hour)})
	if strings.Join(queries, ",") != "cpe:2.3:a:symfony:twig|" {
		t.Fatalf("twig is searched by product, swift not at all: %v", queries)
	}
	if len(res.Items) != 1 || len(res.Failures) != 0 {
		t.Fatalf("a record found by product is kept whatever its wording: %+v %+v", res.Items, res.Failures)
	}
}

func TestMergedCVEsKeepTheRangesOfEveryDatabase(t *testing.T) {
	advisory := `[{"ghsa_id":"GHSA-xxxx-xxxx-xxxx","cve_id":"CVE-2026-500","html_url":"https://github.com/php/php-src/security/advisories/GHSA-xxxx-xxxx-xxxx",
"summary":"Memory corruption in php","severity":"high","published_at":"2026-10-21T13:34:00Z"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			w.Write([]byte(advisory))
			return
		}
		w.Write([]byte(strings.Replace(nvdProduct, "in the engine", "in the PHP engine", 1)))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), GitHubAPI: srv.URL, Now: func() time.Time { return now }, Search: source.Search{CPE: map[string]string{"php": "php:php"}}}
	res := f.Fetch(context.Background(), []source.Source{
		{ID: "php-src-advisories", Type: source.TypeGitHubAdvisories, Repo: "php/php-src", Tags: []string{"php"}, Stage: source.StageAdvisory},
		{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
	}, Query{Tags: []string{"php"}, Versions: map[string]string{"php": "8.3.20"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(res.Items) != 1 || len(res.Items[0].AlsoIn) != 1 {
		t.Fatalf("one merged item: %+v", res.Items)
	}
	if aff := res.Items[0].Affected; len(aff) == 0 || aff[0].Status != StatusAffected || aff[0].InUse != "8.3.20" {
		t.Fatalf("whichever database is kept, the NVD range of the version in use is shown first: %+v", aff)
	}
}

const osvRecord = `{"id":"GHSA-f82v-jwr5-mffw","summary":"Authorization Bypass in Next.js Middleware","details":"Bypass.","aliases":["CVE-2025-29927"],
"published":"2025-03-21T15:20:12Z","database_specific":{"severity":"CRITICAL"},
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
"affected":[{"package":{"name":"next","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"13.0.0"},{"fixed":"13.5.9"}]}]},
{"package":{"name":"next","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"15.0.0"},{"fixed":"15.2.3"}]}]}]}`

func TestOSVListsTheFlawsOfTheVersionsInUseWhateverTheirDate(t *testing.T) {
	var batches []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/querybatch":
			body, _ := io.ReadAll(r.Body)
			batches = append(batches, string(body))
			w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-f82v-jwr5-mffw"},{"id":"GO-2025-1"},{"id":"GHSA-gone-gone-gone"}]},{}]}`))
		case "/vulns/GHSA-f82v-jwr5-mffw":
			w.Write([]byte(osvRecord))
		case "/vulns/GO-2025-1": // the same flaw, in another database
			w.Write([]byte(`{"id":"GO-2025-1","aliases":["GHSA-f82v-jwr5-mffw"],"published":"2025-03-22T00:00:00Z","summary":"dup"}`))
		case "/vulns/GHSA-gone-gone-gone":
			w.Write([]byte(`{"id":"GHSA-gone-gone-gone","withdrawn":"2025-04-01T00:00:00Z","published":"2025-03-22T00:00:00Z"}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), OSVAPI: srv.URL, Now: func() time.Time { return now }}
	sources := []source.Source{{ID: "osv-npm", Type: source.TypeOSV, Ecosystem: "npm", Tags: []string{"npm"}, Stage: source.StageAdvisory}}

	res := f.Fetch(context.Background(), sources, Query{Tags: []string{"npm"}, Packages: []string{"next", "@scope/pkg"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(batches) != 0 || len(res.Items) != 0 {
		t.Fatalf("without a version, OSV is not asked: %v %+v", batches, res.Items)
	}

	res = f.Fetch(context.Background(), sources, Query{Tags: []string{"npm"}, Packages: []string{"next@15.1.0", "dompurify", "@scope/pkg@1.0.0"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(batches) != 1 || !strings.Contains(batches[0], `"name":"next","ecosystem":"npm"},"version":"15.1.0"`) || strings.Contains(batches[0], "dompurify") ||
		!strings.Contains(batches[0], `"name":"@scope/pkg"`) {
		t.Fatalf("only the packages with a version are sent: %v", batches)
	}
	if len(res.Failures) != 0 || len(res.Items) != 1 {
		t.Fatalf("one item (duplicate and withdrawn records dropped): %+v %+v", res.Items, res.Failures)
	}
	it := res.Items[0]
	if it.Title != "[critical] Authorization Bypass in Next.js Middleware (CVE-2025-29927)" || it.Score != 9.1 || it.Published.Year() != 2025 {
		t.Fatalf("an old flaw of a version in use is kept, scored from its vector: %+v", it)
	}
	if len(it.Affected) != 1 || it.Affected[0] != (Affected{Package: "next", Versions: ">= 15.0.0, < 15.2.3", Fixed: "15.2.3", InUse: "15.1.0", Status: StatusAffected}) {
		t.Fatalf("only the range of the version in use: %+v", it.Affected)
	}
}

func TestOSVRangeWithoutFixAndGoVersions(t *testing.T) {
	e, err := parseOSV([]byte(`{"id":"GO-2026-1","summary":"SSRF","published":"2026-11-05T00:00:00Z",
"affected":[{"package":{"name":"example.com/mod"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`),
		[]osvQuery{{Package: struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}{"example.com/mod", "Go"}, Version: "1.3.0"}}, nil)
	if err != nil || len(e.Affected) != 1 || e.Affected[0].Status != StatusAffected || e.Affected[0].Fixed != "" || e.Affected[0].Versions != "" {
		t.Fatalf("every version, no fix: %+v %v", e, err)
	}
}

func TestCVSS3(t *testing.T) {
	for vector, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H":       0,
		"garbage":                                      0,
	} {
		if got := cvss3(vector); got != want {
			t.Errorf("%s: got %.1f, want %.1f", vector, got, want)
		}
	}
}

const (
	nucleiIndex = `{"ID":"CVE-2026-110264","Info":{"Name":"GitLab RCE"},"file_path":"http/cves/2026/CVE-2026-110264.yaml"}
{"ID":"CVE-2000-0114","Info":{"Name":"Old"}}
`
	metasploitMeta = `{"exploit_multi/http/gitlab_rce":{"name":"GitLab RCE","references":["CVE-2026-110264","URL-https://x"]},
"auxiliary_scanner/x":{"references":["OSVDB-1"]}}`
)

func TestPublicExploitsMarkTheCVEs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nuclei":
			w.Write([]byte(nucleiIndex))
		case "/msf":
			w.Write([]byte(metasploitMeta))
		default:
			w.Write([]byte(nvdBody))
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{
		{ID: "nuclei-templates", Type: source.TypeNuclei, URL: srv.URL + "/nuclei", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "metasploit-modules", Type: source.TypeMetasploit, URL: srv.URL + "/msf", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
	}, Query{Keywords: []string{"gitlab"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(res.Failures) != 0 {
		t.Fatalf("failures: %+v", res.Failures)
	}
	if slices.ContainsFunc(res.Items, func(it Item) bool { return it.Source != "nvd" }) {
		t.Fatalf("the catalogs give no item of their own: %+v", res.Items)
	}
	i := slices.IndexFunc(res.Items, func(it Item) bool { return strings.HasPrefix(it.Title, "CVE-2026-110264") })
	if i < 0 || strings.Join(res.Items[i].PublicExploitIn, ",") != "metasploit-modules,nuclei-templates" {
		t.Fatalf("the CVE with a public exploit is marked: %+v", res.Items)
	}
}

const cveProgramRecord = `{"cveMetadata":{"cveId":"CVE-2025-29927","state":"PUBLISHED","datePublished":"2025-03-21T14:34:49.570Z"},
"containers":{"cna":{"title":"Authorization Bypass in Next.js Middleware","descriptions":[{"lang":"en","value":"Middleware bypass."}],
"metrics":[{"cvssV3_1":{"baseScore":9.1}}],"references":[{"url":"https://example.org/advisory"}],
"affected":[{"vendor":"vercel","product":"next.js","versions":[{"version":">= 15.0.0, < 15.2.3","status":"affected"},{"version":"1.0","lessThan":"2.0","status":"affected"},{"version":"9","status":"unaffected"}]}]},
"adp":[{"title":"CISA ADP Vulnrichment","metrics":[{"other":{"type":"ssvc","content":{"options":[{"Exploitation":"poc"},{"Automatable":"yes"},{"Technical Impact":"total"}]}}}]}]}}`

func TestCVEGathersEveryDatabase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cve/CVE-2025-29927":
			w.Write([]byte(cveProgramRecord))
		case "/advisories":
			if r.URL.Query().Get("cve_id") != "CVE-2025-29927" {
				t.Errorf("query: %s", r.URL.RawQuery)
			}
			w.Write([]byte(`[{"ghsa_id":"GHSA-f82v-jwr5-mffw","cve_id":"CVE-2025-29927","html_url":"https://github.com/advisories/GHSA-f82v-jwr5-mffw","summary":"Bypass",
"severity":"critical","published_at":"2025-03-21T15:20:12Z","epss":{"percentage":0.93},
"vulnerabilities":[{"package":{"name":"next"},"vulnerable_version_range":">= 15.0.0, < 15.2.3","first_patched_version":"15.2.3"}]}]`))
		case "/kev":
			w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2025-29927","vendorProject":"Vercel","product":"Next.js","vulnerabilityName":"Bypass","dateAdded":"2025-04-01","shortDescription":"d","requiredAction":"Patch.","knownRansomwareCampaignUse":"Known"}]}`))
		case "/nuclei":
			w.Write([]byte(`{"ID":"CVE-2025-29927"}` + "\n"))
		case "/nvd":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), GitHubAPI: srv.URL, CVEAPI: srv.URL + "/cve", Now: func() time.Time { return now }}
	rec := f.CVE(context.Background(), "CVE-2025-29927", []source.Source{
		{ID: "cisa-kev", Type: source.TypeKEV, URL: srv.URL + "/kev", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "nuclei-templates", Type: source.TypeNuclei, URL: srv.URL + "/nuclei", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
		{ID: "a-feed", Type: source.TypeFeed, URL: srv.URL + "/feed", Tags: []string{"general"}, Stage: source.StageNews},
	}, []string{"next@15.1.0"})

	if rec.Title != "Authorization Bypass in Next.js Middleware" || rec.Description != "Middleware bypass." || rec.Published != "2025-03-21" || rec.Score != 9.1 || rec.EPSS != 0.93 {
		t.Fatalf("record: %+v", rec)
	}
	if strings.Join(rec.FoundIn, ",") != "cve-program,github-advisory-database" || len(rec.Failures) != 1 || rec.Failures[0].Source != "nvd" {
		t.Fatalf("a database that fails is reported, the others answer: %v %+v", rec.FoundIn, rec.Failures)
	}
	if rec.SSVC["exploitation"] != "poc" || rec.SSVC["technical_impact"] != "total" {
		t.Fatalf("ssvc: %v", rec.SSVC)
	}
	if strings.Join(rec.ExploitedIn, ",") != "cisa-kev" || !strings.Contains(rec.Exploitation, "since 2025-04-01") || !strings.Contains(rec.Exploitation, "ransomware") ||
		strings.Join(rec.PublicExploitIn, ",") != "nuclei-templates" {
		t.Fatalf("exploitation: %+v", rec)
	}
	if len(rec.Affected) != 2 || rec.Affected[0] != (Affected{Package: "next", Versions: ">= 15.0.0, < 15.2.3", Fixed: "15.2.3", InUse: "15.1.0", Status: StatusAffected}) ||
		rec.Affected[1] != (Affected{Package: "next.js", Versions: ">= 1.0, < 2.0", Fixed: "2.0"}) {
		t.Fatalf("the package range first, the same range under another name once: %+v", rec.Affected)
	}
	if !ValidCVE("CVE-2025-29927") || ValidCVE("cve-2025-1") || ValidCVE("GHSA-f82v-jwr5-mffw") {
		t.Fatal("ValidCVE")
	}
}

func TestNVDProductSourceReadsTheRecordsOfItsProduct(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("virtualMatchString")+"|"+r.URL.Query().Get("keywordSearch"))
		w.Write([]byte(strings.NewReplacer("php:php", "apache:tomcat", `"baseScore":7.5`, `"baseScore":4.3`).Replace(nvdProduct)))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	sources := []source.Source{
		{ID: "tomcat-nvd", Type: source.TypeNVDProduct, URL: srv.URL, Product: "apache:tomcat", Tags: []string{"tomcat"}, Stage: source.StageAdvisory},
	}
	q := Query{Tags: []string{"tomcat"}, Since: now.Add(-7 * 24 * time.Hour), Versions: map[string]string{"tomcat": "8.3.20"}}
	res := f.Fetch(context.Background(), sources, q)
	if strings.Join(queries, ",") != "cpe:2.3:a:apache:tomcat|" {
		t.Fatalf("the product is asked for, not a word: %v", queries)
	}
	if len(res.Items) != 1 || len(res.Failures) != 0 || res.Items[0].Score != 4.3 {
		t.Fatalf("a record of the product is kept whatever its wording and its score: %+v %+v", res.Items, res.Failures)
	}
	if a := res.Items[0].Affected[0]; a.Package != "tomcat" || a.Status != StatusAffected || a.InUse != "8.3.20" {
		t.Fatalf("its ranges are named after the tag and compared with the version in use: %+v", res.Items[0].Affected)
	}
	if res := f.Fetch(context.Background(), sources, Query{Tags: []string{"php"}, Since: q.Since}); len(res.Items) != 0 || len(queries) != 1 {
		t.Fatalf("another tag does not read it: %+v %v", res.Items, queries)
	}
}
