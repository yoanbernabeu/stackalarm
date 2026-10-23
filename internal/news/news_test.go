package news

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
