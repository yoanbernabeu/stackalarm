package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/news"
	"github.com/yoanbernabeu/stackalarm/internal/source"
)

const testNVD = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-5000","published":"2026-10-21T10:00:00.000",
"descriptions":[{"lang":"en","value":"Memory corruption in the PHP engine."}],
"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]},
"configurations":[{"nodes":[{"cpeMatch":[
{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","versionStartIncluding":"8.3.0","versionEndExcluding":"8.3.35"}]}]}]}}]}`

// newRelevanceApp serves one NVD record of PHP, a KEV catalog that holds it,
// and the databases of the cve command.
func newRelevanceApp(t *testing.T, args ...string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvd":
			w.Write([]byte(testNVD))
		case "/kev":
			w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-5000","vendorProject":"PHP","product":"PHP","vulnerabilityName":"RCE","dateAdded":"2026-10-22","shortDescription":"d","requiredAction":"Patch."}]}`))
		case "/cve/CVE-2026-5000":
			w.Write([]byte(`{"cveMetadata":{"state":"PUBLISHED","datePublished":"2026-10-21T10:00:00Z"},"containers":{"cna":{"title":"PHP engine memory corruption","descriptions":[{"lang":"en","value":"Memory corruption."}]}}}`))
		case "/advisories":
			w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	var out, errOut bytes.Buffer
	app := &App{
		Out: &out, Err: &errOut, Version: "test", Args: args,
		Sources: []source.Source{
			{ID: "nvd", Name: "NVD", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
			{ID: "cisa-kev", Name: "KEV", Type: source.TypeKEV, URL: srv.URL + "/kev", Tags: []string{"general"}, Stage: source.StageAlert},
			{ID: "php-news", Name: "PHP", Type: source.TypeFeed, URL: srv.URL + "/none", Tags: []string{"php"}, Stage: source.StageRelease},
		},
		Fetcher: &news.Fetcher{Client: srv.Client(), UserAgent: "test", CacheTTL: time.Hour, GitHubAPI: srv.URL, CVEAPI: srv.URL + "/cve",
			Search: source.Search{CPE: map[string]string{"php": "php:php"}}},
		Now:       func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) },
		Getenv:    func(string) string { return "" },
		CacheRoot: func() (string, error) { return t.TempDir(), nil },
	}
	return app, &out, &errOut
}

func TestTagVersionIsComparedWithTheRanges(t *testing.T) {
	app, out, _ := newRelevanceApp(t, "news", "--tag", "php@8.3.20", "--format", "summary")
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "affects php >= 8.3.0, < 8.3.35 (fixed in 8.3.35) [8.3.20 in use: AFFECTED]") ||
		!strings.Contains(out.String(), "EXPLOITED in the wild (cisa-kev)") {
		t.Fatalf("got:\n%s", out)
	}

	app, out, _ = newRelevanceApp(t, "news", "--tag", "php@8.3.35", "--format", "summary")
	app.Execute(context.Background())
	if !strings.Contains(out.String(), "[8.3.35 in use: not affected]") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestProfileIgnoresAreLeftOutAndListed(t *testing.T) {
	profile := filepath.Join(t.TempDir(), ".stackalarm.yaml")
	write := func(until string) {
		os.WriteFile(profile, []byte("tags: [php]\nstack:\n  - {name: php, version: \"8.3.20\", precision: exact}\n"+
			"ignore:\n  - {id: cve-2026-5000, reason: \"the extension is not loaded\", until: \""+until+"\"}\n"), 0o600)
	}
	write("2027-01-31")
	app, out, _ := newRelevanceApp(t, "news", "--profile", profile, "--format", "summary")
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var ignored int
	for _, l := range lines {
		if strings.HasPrefix(l, "IGNORED | cve-2026-5000 | ") {
			ignored++
			if !strings.Contains(l, "the extension is not loaded (until 2027-01-31)") {
				t.Fatalf("the reason is shown: %s", l)
			}
		} else if strings.Contains(l, "CVE-2026-5000") {
			t.Fatalf("an ignored CVE must not be listed as news: %s", l)
		}
	}
	if ignored != 2 || !strings.Contains(out.String(), "now EXPLOITED in the wild: review the decision") {
		t.Fatalf("both items of the CVE are ignored, and its exploitation is told:\n%s", out)
	}

	write("2026-10-01") // the decision is past its review date
	app, out, _ = newRelevanceApp(t, "news", "--profile", profile, "--format", "summary")
	app.Execute(context.Background())
	if strings.Contains(out.String(), "IGNORED") || !strings.Contains(out.String(), "8.3.20 in use: AFFECTED") ||
		!strings.Contains(out.String(), "WARNING | the profile ignores cve-2026-5000 until 2026-10-01, which has passed") {
		t.Fatalf("an expired decision is reported again, with a warning (and the exact version of the stack is compared):\n%s", out)
	}
}

func TestSARIFHoldsOnlyWhatAVersionProves(t *testing.T) {
	app, out, _ := newRelevanceApp(t, "news", "--tag", "php@8.3.20", "--format", "sarif")
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("one result, the NVD record whose range holds 8.3.20 (the KEV alert proves nothing by itself):\n%s", out)
	}
	if r := doc.Runs[0].Results[0]; r.RuleID != "CVE-2026-5000" || r.Level != "error" || r.Locations[0].Physical.Artifact.URI != ".stackalarm.yaml" {
		t.Fatalf("result: %+v", r)
	}

	app, out, _ = newRelevanceApp(t, "news", "--tag", "php", "--format", "sarif")
	app.Execute(context.Background())
	if !strings.Contains(out.String(), `"results": []`) {
		t.Fatalf("without a version nothing is proven:\n%s", out)
	}
}

func TestCVECommand(t *testing.T) {
	app, out, _ := newRelevanceApp(t, "cve", "cve-2026-5000", "php@8.3.20")
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"CVE-2026-5000: PHP engine memory corruption", "published 2026-10-21, CVSS 9.8", "EXPLOITED in the wild (cisa-kev)",
		"php >= 8.3.0, < 8.3.35 (fixed in 8.3.35) [8.3.20 in use: AFFECTED]", "Found in: cve-program, nvd",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}

	app, out, _ = newRelevanceApp(t, "cve", "CVE-2026-999999", "--format", "json")
	app.Sources = app.Sources[1:2] // the KEV catalog only: nothing knows this id
	app.Execute(context.Background())
	if !strings.Contains(out.String(), `"found_in": []`) {
		t.Fatalf("an unknown CVE is found nowhere:\n%s", out)
	}

	app, _, errOut := newRelevanceApp(t, "cve", "GHSA-xxxx")
	if code := app.Execute(context.Background()); code != 1 || !strings.Contains(errOut.String(), "not a CVE id") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
