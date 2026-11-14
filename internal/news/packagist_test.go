package news

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

const packagistAnswer = `{"advisories":{"symfony/http-foundation":[
{"advisoryId":"PKSA-24ph-xkrh-y79j","packageName":"symfony/http-foundation","title":"HEAD Requests Bypass access_control","link":"https://symfony.com/cve-2026-118514","cve":"CVE-2026-118514","affectedVersions":">=6.3.0,<6.4.0|>=6.4.0,<6.4.50|>=7.0.0,<7.4.23","reportedAt":"2026-11-04 10:45:07","severity":null},
{"advisoryId":"PKSA-old","packageName":"symfony/http-foundation","title":"Fixed long ago","link":"","cve":"","affectedVersions":">=2.0.0,<2.8.52","reportedAt":"2019-01-01 10:00:00","severity":"high"}]}}`

func TestPackagistGivesTheAdvisoriesOfTheVersionsInUse(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RawQuery
		w.Write([]byte(packagistAnswer))
	}))
	defer srv.Close()
	sources := []source.Source{{ID: "packagist-advisories", Type: source.TypePackagist, URL: srv.URL + "/", Tags: []string{"composer"}, Stage: source.StageAdvisory}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", Now: func() time.Time { return now }}
	res := f.Fetch(context.Background(), sources, Query{Tags: []string{"composer"}, Packages: []string{"symfony/http-foundation@6.3.0", "next@15.1.0", "@scope/pkg@1.0.0"}, Since: now.Add(-7 * 24 * time.Hour)})
	if asked != "packages%5B%5D=symfony%2Fhttp-foundation" {
		t.Fatalf("only Composer packages are asked about: %q", asked)
	}
	if len(res.Items) != 1 || res.Items[0].Title != "HEAD Requests Bypass access_control (CVE-2026-118514)" ||
		affectedLine(res.Items[0]) != "symfony/http-foundation >= 6.3.0, < 6.4.0 fixed 6.4.0 [6.3.0 affected]" {
		t.Fatalf("the advisory hitting 6.3.0, whatever its date, and not the one of 2.x: %+v", res.Items)
	}

	res = f.Fetch(context.Background(), sources, Query{Tags: []string{"composer"}, Packages: []string{"symfony/http-foundation"}, Since: now.Add(-7 * 24 * time.Hour)})
	if !strings.HasPrefix(asked, "updatedSince=") || len(res.Items) != 2 {
		t.Fatalf("without a version, the advisories Packagist says were updated in the period: %q %+v", asked, res.Items)
	}
}

func TestComposerRange(t *testing.T) {
	for in, want := range map[string]string{
		">=6.3.0,<6.4.0": ">= 6.3.0, < 6.4.0",
		"<5.4.46":        "< 5.4.46",
		"==2.1.0":        "= 2.1.0",
		">=v1.0,<v1.2":   ">= 1.0, < 1.2",
	} {
		if got, ok := composerRange(in); !ok || got != want {
			t.Errorf("composerRange(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"^6.3", "~2.0", "!=1.0", "2.x-dev", ""} {
		if _, ok := composerRange(in); ok {
			t.Errorf("composerRange(%q) should not be read", in)
		}
	}
}
