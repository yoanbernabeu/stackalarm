package news

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<item><title>[PHP-DEV] Upcoming Critical PHP Security Release</title>
<link>https://example.org/t/1</link>
<pubDate>Tue, 20 Oct 2026 09:12:00 +0000</pubDate>
<description>&lt;p&gt;Upcoming security release Wed, Oct 21st, &lt;b&gt;two critical&lt;/b&gt; vulnerabilities.&lt;/p&gt;</description></item>
<item><title>[PHP-DEV] RFC: pipe operator v3</title>
<link>https://example.org/t/2</link>
<pubDate>Mon, 19 Oct 2026 10:00:00 +0000</pubDate></item>
<item><title>Old news</title><link>https://example.org/t/0</link><pubDate>Mon, 01 Jan 2024 10:00:00 +0000</pubDate></item>
</channel></rss>`

const atom = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>PHP 8.3.36 Released!</title>
<link rel="alternate" href="https://www.php.net/releases/8_3_36.php"/>
<updated>2026-10-21T13:40:00+00:00</updated>
<content type="html">Security release fixing CVE-2026-109618.</content></entry>
</feed>`

const rdf = `<?xml version="1.0" encoding="ISO-8859-1"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<item><title>DSA-6001-1 php8.2 - security update</title><link>https://www.debian.org/security/2026/dsa-6001</link>
<dc:date>2026-10-22</dc:date><description>Caf` + "\xe9" + ` PHP</description></item>
</rdf:RDF>`

const cert = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
<item><title>2026-018: Critical Vulnerabilities in PHP</title><link>https://cert.example/18</link><pubDate>Tue, 20 Oct 2026 15:00:00 +0000</pubDate></item>
<item><title>2026-017: Critical Vulnerability in FortiOS</title><link>https://cert.example/17</link><pubDate>Mon, 19 Oct 2026 15:00:00 +0000</pubDate></item>
<item><title>2026-016: Node.js security releases</title><link>https://cert.example/16</link><pubDate>Mon, 19 Oct 2026 14:00:00 +0000</pubDate></item>
</channel></rss>`

const ghsa = `[{"ghsa_id":"GHSA-xxxx","cve_id":"CVE-2026-109618","html_url":"https://github.com/php/php-src/security/advisories/GHSA-xxxx",
"summary":"OOM bailout memory corruption","description":"Unauthenticated RCE.","severity":"critical","published_at":"2026-10-21T13:34:00Z"}]`

const kev = `{"vulnerabilities":[
{"cveID":"CVE-2026-109618","vendorProject":"PHP","product":"PHP","vulnerabilityName":"PHP Memory Corruption","dateAdded":"2026-10-23","shortDescription":"RCE.","requiredAction":"Apply updates.","knownRansomwareCampaignUse":"Unknown"},
{"cveID":"CVE-2026-1","vendorProject":"Fortinet","product":"FortiOS","vulnerabilityName":"x","dateAdded":"2026-10-23","shortDescription":"y","requiredAction":"z"}]}`

func TestParsers(t *testing.T) {
	entries, err := parseFeed([]byte(rss))
	if err != nil || len(entries) != 3 {
		t.Fatalf("rss: %v %v", entries, err)
	}
	if e := entries[0]; e.URL != "https://example.org/t/1" || e.Summary != "Upcoming security release Wed, Oct 21st, two critical vulnerabilities." ||
		!e.Published.Equal(time.Date(2026, 10, 20, 9, 12, 0, 0, time.UTC)) {
		t.Fatalf("rss entry: %+v", e)
	}

	entries, err = parseFeed([]byte(atom))
	if err != nil || len(entries) != 1 || entries[0].URL != "https://www.php.net/releases/8_3_36.php" || entries[0].Published.IsZero() {
		t.Fatalf("atom: %+v %v", entries, err)
	}

	entries, err = parseFeed([]byte(rdf))
	if err != nil || len(entries) != 1 || entries[0].Summary != "Café PHP" || entries[0].Published.IsZero() {
		t.Fatalf("rdf: %+v %v", entries, err)
	}

	entries, err = parseGitHubAdvisories([]byte(ghsa))
	if err != nil || entries[0].Title != "[critical] OOM bailout memory corruption (CVE-2026-109618)" {
		t.Fatalf("ghsa: %+v %v", entries, err)
	}

	entries, err = parseKEV([]byte(kev))
	if err != nil || len(entries) != 2 || !strings.HasPrefix(entries[0].Title, "CVE-2026-109618 exploited in the wild: PHP PHP") {
		t.Fatalf("kev: %+v %v", entries, err)
	}
}

func TestFetch(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/internals":
			w.Write([]byte(rss))
		case "/releases":
			w.Write([]byte(atom))
		case "/cert":
			w.Write([]byte(cert))
		case "/repos/php/php-src/security-advisories":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("missing GitHub token")
			}
			w.Write([]byte(ghsa))
		case "/node":
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()

	sources := []source.Source{
		{ID: "php-internals", Type: source.TypeFeed, URL: srv.URL + "/internals", Tags: []string{"php"}, Stage: source.StageHeadsUp, Keywords: []string{"security"}},
		{ID: "php-releases", Type: source.TypeFeed, URL: srv.URL + "/releases", Tags: []string{"php"}, Stage: source.StageRelease},
		{ID: "php-src", Type: source.TypeGitHubAdvisories, Repo: "php/php-src", Tags: []string{"php"}, Stage: source.StageAdvisory},
		{ID: "cert-eu", Type: source.TypeFeed, URL: srv.URL + "/cert", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "node-vulns", Type: source.TypeFeed, URL: srv.URL + "/node", Tags: []string{"node"}, Stage: source.StageRelease},
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", GitHubToken: "tok", GitHubAPI: srv.URL, CacheDir: t.TempDir(), CacheTTL: time.Hour, Now: func() time.Time { return now }}
	q := Query{Tags: []string{"php"}, Since: now.Add(-7 * 24 * time.Hour)}

	res := f.Fetch(context.Background(), sources, q)
	var titles []string
	for _, it := range res.Items {
		titles = append(titles, it.Source+": "+it.Title)
	}
	want := []string{
		"php-releases: PHP 8.3.36 Released!",
		"php-src: [critical] OOM bailout memory corruption (CVE-2026-109618)",
		"cert-eu: 2026-018: Critical Vulnerabilities in PHP",
		"php-internals: [PHP-DEV] Upcoming Critical PHP Security Release",
	}
	if strings.Join(titles, "\n") != strings.Join(want, "\n") {
		t.Fatalf("items:\n%s\nwant:\n%s", strings.Join(titles, "\n"), strings.Join(want, "\n"))
	}
	if len(res.Failures) != 0 {
		t.Fatalf("node is not selected by the php tag, got failures %v", res.Failures)
	}

	before := hits.Load()
	f.Fetch(context.Background(), sources, q)
	if hits.Load() != before {
		t.Fatal("second fetch should come from the cache")
	}

	res = f.Fetch(context.Background(), sources, Query{Tags: []string{"node"}, Since: q.Since})
	if len(res.Failures) != 1 || res.Failures[0].Source != "node-vulns" || res.Failures[0].Error != "HTTP 502" {
		t.Fatalf("failures: %+v", res.Failures)
	}
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Title, "Node.js") {
		t.Fatalf("general source filtered on node: %+v", res.Items)
	}
}

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := ParseSince(in); err != nil || got != want {
			t.Errorf("%s: got %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "d", "-1d", "1x", "7.5d"} {
		if _, err := ParseSince(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

const nvdBody = `{"vulnerabilities":[
{"cve":{"id":"CVE-2026-110264","published":"2026-10-21T18:00:00.000","descriptions":[{"lang":"en","value":"Integer overflow in GitLab regex compiler allows RCE."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":10.0,"baseSeverity":"CRITICAL"}}]}}},
{"cve":{"id":"CVE-2026-105711","published":"2026-10-22T01:16:57.340","descriptions":[{"lang":"en","value":"Low issue in GitLab."}],
 "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":3.5}}]}}},
{"cve":{"id":"CVE-2026-1","published":"2026-10-22T02:00:00.000","descriptions":[{"lang":"en","value":"Fresh GitLab CVE, not scored yet."}],"metrics":{}}}
]}`

const euvdSearch = `{"items":[
{"id":"EUVD-2026-1","description":"GitLab RCE","datePublished":"Oct 21, 2026, 6:00:19 PM","baseScore":"10.0","aliases":"CVE-2026-110264\nGHSA-x\n"},
{"id":"EUVD-2026-2","description":"minor","datePublished":"Oct 21, 2026, 6:00:19 PM","baseScore":"2.0","aliases":""}],"total":2}`

const euvdExploited = `[{"id":"EUVD-2026-85370","description":"Plex Media Server flaw","datePublished":"Sep 23, 2026, 4:07:10 PM",
"baseScore":5.5,"aliases":"CVE-2026-96656\n","exploitedSince":"Oct 20, 2026, 12:00:00 AM"}]`

func TestCVEDatabaseParsers(t *testing.T) {
	entries, err := parseNVD([]byte(nvdBody))
	if err != nil || len(entries) != 2 {
		t.Fatalf("nvd: low scores dropped, unscored kept: %+v %v", entries, err)
	}
	if !strings.HasPrefix(entries[0].Title, "CVE-2026-110264 [10.0]: Integer overflow") || entries[0].URL != "https://nvd.nist.gov/vuln/detail/CVE-2026-110264" {
		t.Fatalf("nvd entry: %+v", entries[0])
	}

	entries, err = parseEUVD([]byte(euvdSearch))
	if err != nil || len(entries) != 1 || entries[0].Title != "CVE-2026-110264 (EUVD-2026-1) [10.0]: GitLab RCE" || entries[0].Published.Hour() != 18 {
		t.Fatalf("euvd search: %+v %v", entries, err)
	}

	entries, err = parseEUVD([]byte(euvdExploited))
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Title, "Exploited in the wild: CVE-2026-96656") ||
		!entries[0].Published.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("euvd exploited (kept despite its score, dated by exploitation): %+v %v", entries, err)
	}
}

func TestSearchSources(t *testing.T) {
	var (
		mu      sync.Mutex
		queries []string
	)
	record := func(q string) { mu.Lock(); queries = append(queries, q); mu.Unlock() }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvd":
			record("nvd:" + r.URL.Query().Get("keywordSearch"))
			if r.Header.Get("apiKey") != "k" {
				t.Errorf("missing NVD key")
			}
			if r.URL.Query().Get("keywordSearch") == "broken" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write([]byte(nvdBody))
		case "/advisories":
			record("ghad:" + r.URL.Query().Get("ecosystem") + ":" + r.URL.Query().Get("published"))
			w.Write([]byte(ghsa))
		}
	}))
	defer srv.Close()
	sources := []source.Source{
		{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
		{ID: "ghsa-composer", Type: source.TypeGitHubAdvisoryDatabase, Ecosystem: "composer", Tags: []string{"php"}, Stage: source.StageAdvisory},
	}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), GitHubAPI: srv.URL, NVDAPIKey: "k", Now: func() time.Time { return now }}

	res := f.Fetch(context.Background(), sources, Query{Since: now.Add(-7 * 24 * time.Hour)})
	if len(queries) != 1 || queries[0] != "ghad:composer:>=2026-10-16" {
		t.Fatalf("without words, search sources are skipped: %v", queries)
	}

	queries = nil
	res = f.Fetch(context.Background(), sources, Query{Tags: []string{"php"}, Keywords: []string{"GitLab", "broken"}, Since: now.Add(-7 * 24 * time.Hour)})
	slices.Sort(queries)
	if strings.Join(queries, ",") != "ghad:composer:>=2026-10-16,nvd:broken,nvd:gitlab,nvd:php" {
		t.Fatalf("queries: %v", queries)
	}
	var nvdItems int
	for _, it := range res.Items {
		if it.Source == "nvd" {
			nvdItems++
		}
	}
	if nvdItems != 2 { // same records for php and gitlab: deduplicated
		t.Fatalf("nvd items: %d (%+v)", nvdItems, res.Items)
	}
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Error, `"broken"`) {
		t.Fatalf("a failing term is reported, the others kept: %+v", res.Failures)
	}
}

func TestFeedWithControlCharacters(t *testing.T) {
	entries, err := parseFeed([]byte("<rss><channel><item><title>Bad \x0b char</title><pubDate>Tue, 20 Oct 2026 09:12:00 +0000</pubDate></item></channel></rss>"))
	if err != nil || len(entries) != 1 || entries[0].Title != "Bad char" {
		t.Fatalf("%+v %v", entries, err)
	}
}

func TestMaxPerSource(t *testing.T) {
	var b strings.Builder
	b.WriteString("<rss><channel>")
	for i := range MaxPerSource + 5 {
		fmt.Fprintf(&b, "<item><title>n%d</title><pubDate>%s</pubDate></item>", i, time.Date(2026, 10, 1+i%20, 0, i, 0, 0, time.UTC).Format(time.RFC1123Z))
	}
	b.WriteString("</channel></rss>")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(b.String())) }))
	defer srv.Close()
	f := &Fetcher{Client: srv.Client(), Now: time.Now}
	res := f.Fetch(context.Background(), []source.Source{{ID: "big", Type: source.TypeFeed, URL: srv.URL, Tags: []string{"x"}, Stage: source.StageNews}}, Query{})
	if len(res.Items) != MaxPerSource || len(res.Truncated) != 1 || res.Truncated[0].Dropped != 5 {
		t.Fatalf("items %d, truncated %+v", len(res.Items), res.Truncated)
	}
	if res.Items[len(res.Items)-1].Published.Before(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)) { // days 1 and 2 are the oldest five
		t.Fatal("the oldest entries must be the ones dropped")
	}
}

func TestSearchCapKeepsTheMostSevere(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"vulnerabilities":[`)
	for i := range MaxPerSource + 10 {
		if i > 0 {
			b.WriteString(",")
		}
		score := 7.5
		if i == 0 {
			score = 10 // the oldest one is the critical one
		}
		fmt.Fprintf(&b, `{"cve":{"id":"CVE-2026-%d","published":"2026-10-%02dT10:00:00.000","descriptions":[{"lang":"en","value":"PHP issue"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":%.1f}}]}}}`, i, 10+i%12, score)
	}
	b.WriteString("]}")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(b.String())) }))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{{ID: "nvd", Type: source.TypeNVD, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageAdvisory}},
		Query{Keywords: []string{"php"}, Since: now.Add(-30 * 24 * time.Hour)})
	if len(res.Items) != MaxPerSource || !slices.ContainsFunc(res.Items, func(it Item) bool { return it.Score == 10 }) {
		t.Fatalf("the critical CVE must survive the cap: %d items", len(res.Items))
	}
}

func TestSearchTermsUseAliasesForAmbiguousTags(t *testing.T) {
	got := searchTerms(Query{Tags: []string{"node", "php", "general"}, Keywords: []string{"Node.js", "vite"}})
	if strings.Join(got, ",") != "node.js,php,vite" {
		t.Fatalf("got %v", got)
	}
}

func TestSearchResultsMustContainTheTerm(t *testing.T) {
	body := `{"items":[
{"id":"EUVD-1","description":"In the Linux kernel, a device tree node leaks.","datePublished":"Oct 21, 2026, 6:00:19 PM","baseScore":"0.0"},
{"id":"EUVD-2","description":"Node.js Brotli decoder out-of-bounds write.","datePublished":"Oct 21, 2026, 6:00:19 PM","baseScore":"8.8"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{{ID: "euvd", Type: source.TypeEUVDSearch, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageAdvisory}},
		Query{Tags: []string{"node"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Title, "Node.js") {
		t.Fatalf("only the Node.js entry must remain: %+v", res.Items)
	}
}

func TestPackagesNarrowTheAdvisoryDatabase(t *testing.T) {
	var affects string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		affects = r.URL.Query().Get("affects")
		w.Write([]byte(ghsa))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), GitHubAPI: srv.URL, Now: func() time.Time { return now }}
	f.Fetch(context.Background(), []source.Source{{ID: "ghsa-npm", Type: source.TypeGitHubAdvisoryDatabase, Ecosystem: "npm", Tags: []string{"npm"}, Stage: source.StageAdvisory}},
		Query{Tags: []string{"npm"}, Packages: []string{"dompurify", "picomatch"}, Since: now.Add(-7 * 24 * time.Hour)})
	if affects != "dompurify,picomatch" {
		t.Fatalf("affects = %q", affects)
	}
}

func TestDuplicateCVEsAreMerged(t *testing.T) {
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(nvdBody)) }))
	defer nvd.Close()
	euvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(euvdSearch)) }))
	defer euvd.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: http.DefaultClient, Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{
		{ID: "nvd", Type: source.TypeNVD, URL: nvd.URL, Tags: []string{"general"}, Stage: source.StageAdvisory},
		{ID: "euvd-search", Type: source.TypeEUVDSearch, URL: euvd.URL, Tags: []string{"general"}, Stage: source.StageAdvisory},
	}, Query{Keywords: []string{"gitlab"}, Since: now.Add(-7 * 24 * time.Hour)})
	var found int
	for _, it := range res.Items {
		if strings.HasPrefix(it.Title, "CVE-2026-110264") {
			found++
			if len(it.AlsoIn) != 1 {
				t.Errorf("also_in: %v", it.AlsoIn)
			}
		}
	}
	if found != 1 {
		t.Fatalf("CVE-2026-110264 appears %d times, want 1", found)
	}
}

func TestReleasedTitleInHeadsUpFeedIsARelease(t *testing.T) {
	feed := `<rss><channel>
<item><title>[PHP-DEV] Upcoming Critical PHP Security Release</title><pubDate>Tue, 20 Oct 2026 19:32:00 +0000</pubDate></item>
<item><title>[PHP-DEV] PHP 8.3.36 Released</title><pubDate>Wed, 21 Oct 2026 13:40:00 +0000</pubDate></item>
</channel></rss>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(feed)) }))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{{ID: "php-internals", Type: source.TypeFeed, URL: srv.URL, Tags: []string{"php"}, Stage: source.StageHeadsUp}}, Query{Since: now.Add(-7 * 24 * time.Hour)})
	stages := map[string]source.Stage{}
	for _, it := range res.Items {
		stages[it.Title] = it.Stage
	}
	if stages["[PHP-DEV] PHP 8.3.36 Released"] != source.StageRelease || stages["[PHP-DEV] Upcoming Critical PHP Security Release"] != source.StageHeadsUp {
		t.Fatalf("stages: %v", stages)
	}
}

func TestCVEsAreMergedAcrossGitHubAndCVEDatabases(t *testing.T) {
	gh := `[{"ghsa_id":"GHSA-x","cve_id":"CVE-2026-110264","html_url":"https://github.com/a","summary":"GitLab RCE","severity":"critical","published_at":"2026-10-21T19:00:00Z"}]`
	ghs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(gh)) }))
	defer ghs.Close()
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(nvdBody)) }))
	defer nvd.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: http.DefaultClient, GitHubAPI: ghs.URL, Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{
		{ID: "gitlab-advisories", Type: source.TypeGitHubAdvisories, Repo: "gitlab/x", Tags: []string{"gitlab"}, Stage: source.StageAdvisory},
		{ID: "nvd", Type: source.TypeNVD, URL: nvd.URL, Tags: []string{"general"}, Stage: source.StageAdvisory},
	}, Query{Tags: []string{"gitlab"}, Since: now.Add(-7 * 24 * time.Hour)})
	var n int
	for _, it := range res.Items {
		if strings.Contains(it.Title, "CVE-2026-110264") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("CVE-2026-110264 appears %d times: %+v", n, res.Items)
	}
}

func TestItemIDsAreStableAcrossDatabases(t *testing.T) {
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(nvdBody)) }))
	defer nvd.Close()
	euvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(euvdSearch)) }))
	defer euvd.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: http.DefaultClient, Now: func() time.Time { return now }}
	q := Query{Keywords: []string{"gitlab"}, Since: now.Add(-7 * 24 * time.Hour)}
	id := func(s source.Source) string { // the run where only one database answers must give the same id
		for _, it := range f.Fetch(context.Background(), []source.Source{s}, q).Items {
			if strings.HasPrefix(it.Title, "CVE-2026-110264") {
				return it.ID
			}
		}
		return ""
	}
	fromNVD := id(source.Source{ID: "nvd", Type: source.TypeNVD, URL: nvd.URL, Tags: []string{"general"}, Stage: source.StageAdvisory})
	fromEUVD := id(source.Source{ID: "euvd-search", Type: source.TypeEUVDSearch, URL: euvd.URL, Tags: []string{"general"}, Stage: source.StageAdvisory})
	if fromNVD == "" || fromNVD != fromEUVD {
		t.Fatalf("ids: nvd %q, euvd %q", fromNVD, fromEUVD)
	}
}

func TestLinksDoNotMatchTags(t *testing.T) {
	feed := `<rss><channel>
<item><title>Godot 4.x: heap out-of-bounds read</title><description>Fixed in https://github.com/godotengine/godot/pull/1 and github.com/godotengine/godot/pull/2</description><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item>
<item><title>GitHub Enterprise Server: critical flaw</title><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item>
<item><title>Node.js 22.23.4 security release</title><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(feed)) }))
	defer srv.Close()
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{{ID: "oss-security", Type: source.TypeFeed, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageHeadsUp}},
		Query{Tags: []string{"github", "node"}, Since: now.Add(-7 * 24 * time.Hour)})
	var titles []string
	for _, it := range res.Items {
		titles = append(titles, it.Title)
	}
	if strings.Join(titles, ",") != "GitHub Enterprise Server: critical flaw,Node.js 22.23.4 security release" {
		t.Fatalf("items: %v", titles)
	}
}
