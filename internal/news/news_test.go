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
	got, _ := searchTerms(Query{Tags: []string{"node", "php", "general"}, Keywords: []string{"Node.js", "vite"}}, testSearch)
	if strings.Join(got, ",") != "node.js,php,vite" {
		t.Fatalf("got %v", got)
	}
}

var testSearch = source.Search{Aliases: map[string]string{"node": "node.js"}, Skip: []string{"swift", "npm"}}

func TestSearchTermsSkipTags(t *testing.T) {
	if got, _ := searchTerms(Query{Tags: []string{"swift", "astro"}}, testSearch); strings.Join(got, ",") != "astro" {
		t.Fatalf("the swift tag must not be searched: %v", got)
	}
	if got, _ := searchTerms(Query{Tags: []string{"swift"}, Keywords: []string{"swift"}}, testSearch); strings.Join(got, ",") != "swift" {
		t.Fatalf("an explicit keyword must still be searched: %v", got)
	}
}

func TestSearchTermsBeyondTheLimitAreReported(t *testing.T) {
	tags := []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"}
	got, left := searchTerms(Query{Tags: tags}, testSearch)
	if len(got) != MaxTerms || strings.Join(left, ",") != "t9,t10" {
		t.Fatalf("searched %v, left %v", got, left)
	}

	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), nil, Query{Tags: tags, Since: now})
	if len(res.NotSearched) != 0 {
		t.Fatalf("without a search source, nothing is left out: %v", res.NotSearched)
	}
}

func TestFetchReportsTheWordsNotSearched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"vulnerabilities": []}`)) }))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{{ID: "nvd", Type: source.TypeNVD, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageAdvisory}},
		Query{Keywords: []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9"}, Since: now.Add(-24 * time.Hour)})
	if strings.Join(res.NotSearched, ",") != "k9" || len(res.Failures) != 0 {
		t.Fatalf("not searched %v, failures %v", res.NotSearched, res.Failures)
	}
}

func TestSkippedTagsStillMatchGeneralSources(t *testing.T) {
	feed := `<rss><channel>
<item><title>Self-replicating worm in npm packages</title><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item>
<item><title>Windows kernel flaw</title><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item>
</channel></rss>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(feed)) }))
	defer srv.Close()
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Search: testSearch, Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{{ID: "cert", Type: source.TypeFeed, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageAlert}},
		Query{Tags: []string{"npm"}, Since: now.Add(-7 * 24 * time.Hour)})
	if len(res.Items) != 1 || !strings.Contains(res.Items[0].Title, "npm") {
		t.Fatalf("only the npm alert must remain: %+v", res.Items)
	}
}

func TestSearchResultsMustContainTheTerm(t *testing.T) {
	body := `{"items":[
{"id":"EUVD-1","description":"In the Linux kernel, a device tree node leaks.","datePublished":"Oct 21, 2026, 6:00:19 PM","baseScore":"0.0"},
{"id":"EUVD-2","description":"Node.js Brotli decoder out-of-bounds write.","datePublished":"Oct 21, 2026, 6:00:19 PM","baseScore":"8.8"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Search: testSearch, Now: func() time.Time { return now }}
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

// advisoryPage is one page of GitHub advisories, all critical, dated day.
func advisoryPage(from, n, day int) string {
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"ghsa_id":"GHSA-%d","html_url":"https://github.com/advisories/GHSA-%d","summary":"flaw %d","severity":"critical","published_at":"2026-10-%02dT10:00:00Z"}`, from+i, from+i, from+i, day)
	}
	b.WriteString("]")
	return b.String()
}

func TestGitHubListsAreReadPageByPage(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		fmt.Sscan(r.URL.Query().Get("after"), &page)
		if page < MaxPages+5 {
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?after=%d>; rel="next"`, srv.URL, r.URL.Path, page+1))
		}
		day := 22
		if r.URL.Path == "/repos/o/r/security-advisories" {
			day = 23 - page // newest first: page 3 is older than the window
		}
		w.Write([]byte(advisoryPage(page*100, 2, day)))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), GitHubAPI: srv.URL, Now: func() time.Time { return now }}
	since := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

	res := f.Fetch(context.Background(), []source.Source{{ID: "ghsa-npm", Type: source.TypeGitHubAdvisoryDatabase, Ecosystem: "npm", Tags: []string{"npm"}, Stage: source.StageAdvisory}}, Query{Since: since})
	if len(res.Items) != 2*MaxPages {
		t.Fatalf("every page up to the limit must be read: %d items", len(res.Items))
	}
	if len(res.Failures) != 1 || !strings.Contains(res.Failures[0].Error, "partial") {
		t.Fatalf("a list cut short must be reported: %+v", res.Failures)
	}

	res = f.Fetch(context.Background(), []source.Source{{ID: "r", Type: source.TypeGitHubAdvisories, Repo: "o/r", Tags: []string{"r"}, Stage: source.StageAdvisory}}, Query{Since: since})
	if len(res.Items) != 4 || len(res.Failures) != 0 {
		t.Fatalf("a repository list stops at the first page older than the window: %d items, %+v", len(res.Items), res.Failures)
	}
}

func TestEUVDSearchIsReadPageByPage(t *testing.T) {
	var pages []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.Query().Get("page"))
		if r.URL.Query().Get("fromScore") != "7" {
			t.Errorf("low scores must be filtered by the API: %s", r.URL.RawQuery)
		}
		fmt.Fprintf(w, `{"total":%d,"items":[{"id":"EUVD-%s","description":"php flaw","datePublished":"Oct 21, 2026, 6:00:19 PM","baseScore":9.8}]}`, 2*euvdPageSize+1, r.URL.Query().Get("page"))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), []source.Source{{ID: "euvd", Type: source.TypeEUVDSearch, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageAdvisory}},
		Query{Keywords: []string{"php"}, Since: now.Add(-7 * 24 * time.Hour)})
	if strings.Join(pages, ",") != "0,1,2" || len(res.Items) != 3 || len(res.Failures) != 0 {
		t.Fatalf("pages %v, items %d, failures %+v", pages, len(res.Items), res.Failures)
	}
}

func TestNVDReportsRecordsBeyondOnePage(t *testing.T) {
	entries, err := parseNVD([]byte(`{"totalResults":2500,"vulnerabilities":[{"cve":{"id":"CVE-2026-1","published":"2026-10-21T10:00:00.000","descriptions":[{"lang":"en","value":"x"}]}}]}`))
	if len(entries) != 1 || err == nil || !strings.Contains(err.Error(), "2500 records") {
		t.Fatalf("%+v %v", entries, err)
	}
}

func TestMergedCVEsTakeOnePlaceInTheCap(t *testing.T) {
	var nvd, euvd strings.Builder
	nvd.WriteString(`{"vulnerabilities":[`)
	euvd.WriteString(`[`)
	for i := range MaxPerSource + 5 {
		if i > 0 {
			euvd.WriteString(",")
		}
		score := 9.8
		if i >= MaxPerSource {
			score = 7.5 // only in the EUVD, and less severe than the shared ones
		} else {
			if i > 0 {
				nvd.WriteString(",")
			}
			fmt.Fprintf(&nvd, `{"cve":{"id":"CVE-2026-%d","published":"2026-10-20T10:00:00.000","descriptions":[{"lang":"en","value":"php flaw"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]}}}`, i)
		}
		fmt.Fprintf(&euvd, `{"id":"EUVD-%d","description":"php flaw","datePublished":"Oct 20, 2026, 10:00:00 AM","baseScore":%.1f,"aliases":"CVE-2026-%d"}`, i, score, i)
	}
	nvd.WriteString("]}")
	euvd.WriteString("]")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nvd" {
			w.Write([]byte(nvd.String()))
		} else {
			w.Write([]byte(euvd.String()))
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), Now: func() time.Time { return now }}
	// Whichever database lists the shared CVEs first, the five others fit.
	for _, id := range []string{"euvd-search", "z-euvd"} {
		res := f.Fetch(context.Background(), []source.Source{
			{ID: id, Type: source.TypeEUVDSearch, URL: srv.URL + "/euvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
			{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
		}, Query{Keywords: []string{"php"}, Since: now.Add(-7 * 24 * time.Hour)})
		if len(res.Items) != MaxPerSource+5 || len(res.Truncated) != 0 {
			t.Fatalf("%s: every distinct CVE must be shown: %d items, truncated %+v", id, len(res.Items), res.Truncated)
		}
	}
}

func TestGitHubAdvisoriesCarryVersionsAndScores(t *testing.T) {
	db := `[{"ghsa_id":"GHSA-a","cve_id":"CVE-2026-2","html_url":"https://github.com/advisories/GHSA-a","summary":"Token leak","severity":"high","published_at":"2026-10-21T10:00:00Z",
"cvss":{"score":7.5},"cvss_severities":{"cvss_v3":{"score":7.5},"cvss_v4":{"score":8.7}},"epss":{"percentage":0.42,"percentile":0.97},
"vulnerabilities":[{"package":{"ecosystem":"npm","name":"@azure/msal-node"},"vulnerable_version_range":">= 5.0.0, < 7.1.0","first_patched_version":"7.1.0"}]}]`
	entries, err := parseGitHubAdvisoryDatabase([]byte(db))
	if err != nil || len(entries) != 1 {
		t.Fatalf("%+v %v", entries, err)
	}
	if e := entries[0]; e.Score != 8.7 || e.EPSS != 0.42 || len(e.Affected) != 1 ||
		e.Affected[0] != (Affected{Package: "@azure/msal-node", Versions: ">= 5.0.0, < 7.1.0", Fixed: "7.1.0"}) {
		t.Fatalf("entry: %+v", e)
	}

	repo := `[{"ghsa_id":"GHSA-b","html_url":"https://github.com/vitejs/vite/security/advisories/GHSA-b","summary":"fs.deny bypass","severity":"medium","published_at":"2026-10-21T10:00:00Z",
"cvss":{"score":null},"cvss_severities":{"cvss_v3":{"score":null},"cvss_v4":{"score":6.9}},"epss":null,
"vulnerabilities":[{"package":{"ecosystem":"npm","name":"vite"},"vulnerable_version_range":"6.4.4","patched_versions":"6.4.5"}]}]`
	entries, err = parseGitHubAdvisories([]byte(repo))
	if err != nil || entries[0].Score != 6.9 || entries[0].Affected[0].Fixed != "6.4.5" {
		t.Fatalf("repository advisory: %+v %v", entries, err)
	}
}

func TestWatchedPackagesComeFirst(t *testing.T) {
	got := watchedFirst([]Affected{{Package: "launch-editor"}, {Package: "@next/env"}, {Package: "next"}}, []string{"next@15.1.0", "@next/env@15.1.0"})
	if got[0].Package != "@next/env" || got[1].Package != "next" || got[2].Package != "launch-editor" {
		t.Fatalf("%+v", got)
	}
	if packageName("@scope/name") != "@scope/name" || packageName("name@1.0.0") != "name" {
		t.Fatal("packageName")
	}
}

func TestPackageVersionsAreSentToGitHub(t *testing.T) {
	var affects string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		affects = r.URL.Query().Get("affects")
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), GitHubAPI: srv.URL, Now: func() time.Time { return now }}
	f.Fetch(context.Background(), []source.Source{{ID: "ghsa-npm", Type: source.TypeGitHubAdvisoryDatabase, Ecosystem: "npm", Tags: []string{"npm"}, Stage: source.StageAdvisory}},
		Query{Tags: []string{"npm"}, Packages: []string{"next@15.1.0", "@azure/msal-node@7.0.0"}, Since: now.Add(-7 * 24 * time.Hour)})
	if affects != "next@15.1.0,@azure/msal-node@7.0.0" {
		t.Fatalf("affects = %q", affects)
	}
}

func TestInRange(t *testing.T) {
	for _, c := range []struct {
		version, rng string
		in, ok       bool
	}{
		{"6.0.7", ">= 8.3.0, <= 8.3.2", false, true},
		{"6.0.7", "< 6.4.5", true, true},
		{"6.4.4", "6.4.4", true, true},
		{"1.10.0", ">= 1.9.0, < 1.10.0", false, true},
		{"1.0.0-rc.1", "< 1.0.0", true, true},
		{"1.4.5-lts.1", "< 2.0.0", true, true},
		{"15.1.0", ">= 13.0.0, <= 15.5.27", true, true},
		{"", "< 1.0.0", false, false},
		{"1.0.0", "", false, false},
	} {
		if in, ok := inRange(c.version, c.rng); in != c.in || ok != c.ok {
			t.Errorf("inRange(%q, %q) = %v, %v", c.version, c.rng, in, ok)
		}
	}
}

func TestTheRangeOfTheVersionInUseComesFirst(t *testing.T) {
	got := watchedFirst([]Affected{{Package: "vite", Versions: ">= 8.3.0, <= 8.3.2"}, {Package: "vite-plus"}, {Package: "vite", Versions: ">= 6.0.0, < 6.4.5"}}, []string{"vite@6.0.7"})
	if got[0].Versions != ">= 6.0.0, < 6.4.5" || got[2].Package != "vite-plus" {
		t.Fatalf("%+v", got)
	}
	got = watchedFirst([]Affected{{Package: "other"}, {Package: "vite", Versions: "< 1.0.0"}}, []string{"vite"})
	if got[0].Package != "vite" {
		t.Fatalf("a package given without version still comes first: %+v", got)
	}
}

func TestMalwareIsAnAlertForTheGivenPackages(t *testing.T) {
	var types []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		types = append(types, r.URL.Query().Get("type"))
		mu.Unlock()
		if r.URL.Query().Get("type") == "malware" {
			w.Write([]byte(`[{"ghsa_id":"GHSA-m","html_url":"https://github.com/advisories/GHSA-m","summary":"Malware in left-pad","severity":"critical","published_at":"2026-10-22T10:00:00Z",
"vulnerabilities":[{"package":{"ecosystem":"npm","name":"left-pad"},"vulnerable_version_range":"= 1.3.1","first_patched_version":null}]}]`))
			return
		}
		w.Write([]byte(ghsa))
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), GitHubAPI: srv.URL, Now: func() time.Time { return now }}
	src := []source.Source{{ID: "ghsa-npm", Type: source.TypeGitHubAdvisoryDatabase, Ecosystem: "npm", Tags: []string{"npm"}, Stage: source.StageAdvisory}}

	f.Fetch(context.Background(), src, Query{Tags: []string{"npm"}, Since: now.Add(-7 * 24 * time.Hour)})
	if strings.Join(types, ",") != "reviewed" {
		t.Fatalf("without packages, malware is not read: %v", types)
	}

	types = nil
	res := f.Fetch(context.Background(), src, Query{Tags: []string{"npm"}, Packages: []string{"left-pad@1.3.1"}, Since: now.Add(-7 * 24 * time.Hour)})
	slices.Sort(types)
	if strings.Join(types, ",") != "malware,reviewed" {
		t.Fatalf("types: %v", types)
	}
	i := slices.IndexFunc(res.Items, func(it Item) bool { return strings.HasPrefix(it.Title, "[malware] Malware in left-pad") })
	if i < 0 || res.Items[i].Stage != source.StageAlert {
		t.Fatalf("malware must be an alert: %+v", res.Items)
	}
}
