package news

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

func TestGemSatisfies(t *testing.T) {
	for _, c := range []struct {
		version, constraint string
		ok, readable        bool
	}{
		{"2.47.0", ">= 2.47.0", true, true},
		{"2.30.0", ">= 2.47.0", false, true},
		{"2.46.5", "~> 2.46.3", true, true}, // >= 2.46.3, < 2.47
		{"2.47.0", "~> 2.46.3", false, true},
		{"3.9", "~> 2.4", false, true}, // < 3
		{"5.9.1", "~> 5", true, true},  // < 6
		{"5.2.4.3", "~> 5.2.4, >= 5.2.4.3", true, true},
		{"5.2.4.1", "~> 5.2.4, >= 5.2.4.3", false, true},
		{"1.0", "Ruby 3.4 series and earlier are not affected.", false, false},
	} {
		ok, readable := gemSatisfies(c.version, c.constraint)
		if ok != c.ok || readable != c.readable {
			t.Errorf("gemSatisfies(%q, %q) = %v, %v", c.version, c.constraint, ok, readable)
		}
	}
}

func rubyArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

// rodauth's advisories are in the Ruby Advisory Database only.
func TestRubySecGivesTheAdvisoriesOfTheGemsAndOfRuby(t *testing.T) {
	archive := rubyArchive(t, map[string]string{
		"ruby-advisory-db-master/gems/rodauth/CVE-2026-82466.yml": "gem: rodauth\ncve: 2026-82466\nurl: https://example.org/a\ntitle: Account takeover in webauthn_login feature\ndate: 2026-08-18\ncvss_v3: 9.4\npatched_versions:\n  - \">= 2.46.0\"\n",
		"ruby-advisory-db-master/gems/rodauth/GHSA-old.yml":       "gem: rodauth\nghsa: aaaa-bbbb-cccc\ntitle: Old one\ndate: 2015-01-01\npatched_versions:\n  - \">= 1.2.0\"\n",
		"ruby-advisory-db-master/gems/rails/CVE-2099-1.yml":       "gem: rails\ncve: 2099-1\ntitle: not asked\ndate: 2026-11-10\npatched_versions:\n  - \">= 9\"\n",
		"ruby-advisory-db-master/rubies/ruby/CVE-2025-61594.yml":  "engine: ruby\ncve: 2025-61594\ntitle: URI Credential Leakage Bypass\ndate: 2025-10-07\npatched_versions:\n  - \"~> 3.3.10\"\n  - \">= 3.4.7\"\nunaffected_versions:\n  - \"< 3.2\"\n",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(archive) }))
	defer srv.Close()
	sources := []source.Source{{ID: "rubysec-advisories", Type: source.TypeRubySec, URL: srv.URL, Tags: []string{"ruby"}, Stage: source.StageAdvisory}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), sources, Query{Tags: []string{"ruby"}, Versions: map[string]string{"ruby": "3.3.0"}, Packages: []string{"rodauth@2.30.0", "symfony/yaml@6.3.0"}, Since: now.Add(-7 * 24 * time.Hour)})
	var got []string
	for _, it := range res.Items {
		got = append(got, it.Title+" | "+affectedLine(it))
	}
	want := []string{
		"[critical] Account takeover in webauthn_login feature (CVE-2026-82466) | rodauth all but >= 2.46.0 fixed 2.46.0 [2.30.0 affected]",
		"URI Credential Leakage Bypass (CVE-2025-61594) | ruby all but ~> 3.3.10 or >= 3.4.7 or < 3.2 fixed 3.3.10 [3.3.0 affected]",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
