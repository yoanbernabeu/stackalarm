package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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
	write := func(rule string) {
		os.WriteFile(profile, []byte("tags: [php]\nstack:\n  - {name: php, version: \"8.3.20\", precision: exact}\n"+
			"ignore:\n  - {id: cve-2026-5000, reason: \"the extension is not loaded\""+rule+"}\n"), 0o600)
	}
	run := func(withKEV bool) string {
		app, out, _ := newRelevanceApp(t, "news", "--profile", profile, "--format", "summary")
		if !withKEV {
			app.Sources = slices.DeleteFunc(app.Sources, func(s source.Source) bool { return s.Type == source.TypeKEV })
		}
		if code := app.Execute(context.Background()); code != 0 {
			t.Fatalf("exit %d", code)
		}
		return out.String()
	}

	write(", until: \"2027-01-31\"")
	out := run(false)
	if strings.Count(out, "CVE-2026-5000") != 1 || !strings.Contains(out, "IGNORED | cve-2026-5000 | CVE-2026-5000") ||
		!strings.Contains(out, "the extension is not loaded (until 2027-01-31)") {
		t.Fatalf("an ignored CVE is left out of the news, and listed with its reason:\n%s", out)
	}

	out = run(true) // the CVE enters the KEV catalog
	if strings.Contains(out, "IGNORED") || !strings.Contains(out, "8.3.20 in use: AFFECTED") || !strings.Contains(out, "| alert | cisa-kev |") ||
		!strings.Contains(out, "WARNING | the profile ignores cve-2026-5000 (the extension is not loaded), but it is now reported exploited in the wild") {
		t.Fatalf("exploitation ends the decision: every item is reported again, with a warning:\n%s", out)
	}

	write(", even_if_exploited: true")
	out = run(true)
	if strings.Count(out, "IGNORED | cve-2026-5000 | ") != 2 || !strings.Contains(out, "EXPLOITED in the wild, kept ignored by even_if_exploited") ||
		strings.Contains(out, "WARNING") {
		t.Fatalf("even_if_exploited keeps both items ignored, and says so:\n%s", out)
	}

	write(", until: \"2026-10-01\"") // the decision is past its review date
	out = run(false)
	if strings.Contains(out, "IGNORED") || !strings.Contains(out, "8.3.20 in use: AFFECTED") ||
		!strings.Contains(out, "WARNING | the profile ignores cve-2026-5000 until 2026-10-01, which has passed") {
		t.Fatalf("an expired decision is reported again, with a warning:\n%s", out)
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

func TestNoOSVKeepsThePackageVersionsAway(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		env  string
		want int
	}{
		"by default":    {nil, "", 1},
		"with the flag": {[]string{"--no-osv"}, "", 0},
		"with the env":  {nil, "1", 0},
	} {
		var asked int
		osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			asked++
			w.Write([]byte(`{"results":[{}]}`))
		}))
		app, _, _ := newRelevanceApp(t, append([]string{"news", "--tag", "npm", "--package", "next@15.1.0"}, tc.args...)...)
		app.Sources = []source.Source{{ID: "osv-npm", Name: "OSV", Type: source.TypeOSV, Ecosystem: "npm", Tags: []string{"npm"}, Stage: source.StageAdvisory}}
		app.Fetcher.OSVAPI = osv.URL
		app.Getenv = func(k string) string {
			if k == "STACKALARM_NO_OSV" {
				return tc.env
			}
			return ""
		}
		if code := app.Execute(context.Background()); code != 0 || asked != tc.want {
			t.Errorf("%s: exit %d, OSV asked %d times, want %d", name, code, asked, tc.want)
		}
		osv.Close()
	}
}

func TestSBOMAloneListsOnlyItsVulnerabilities(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/querybatch":
			w.Write([]byte(`{"results":[{"vulns":[{"id":"ALPINE-CVE-2026-5000"}]}]}`))
		case "/vulns/ALPINE-CVE-2026-5000":
			w.Write([]byte(`{"id":"ALPINE-CVE-2026-5000","details":"Stack corruption in qsort.","upstream":["CVE-2026-5000"],"published":"2026-04-10T00:00:00Z",
"affected":[{"package":{"name":"musl","ecosystem":"Alpine:v3.19"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.4-r6"}]}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer osv.Close()
	sbom := filepath.Join(t.TempDir(), "image.cdx.json")
	os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[
{"type":"library","purl":"pkg:apk/alpine/musl-utils@1.2.4-r3?distro=3.19.9","properties":[{"name":"aquasecurity:trivy:SrcName","value":"musl"},{"name":"aquasecurity:trivy:SrcVersion","value":"1.2.4-r3"}]},
{"type":"library","purl":"pkg:generic/busybox@1.36"}]}`), 0o600)

	app, out, errOut := newRelevanceApp(t, "news", "--sbom", sbom, "--format", "summary")
	app.Sources = append(app.Sources, source.Source{ID: "osv-alpine", Name: "OSV Alpine", Type: source.TypeOSV, Ecosystem: "Alpine", Tags: []string{"alpine"}, Stage: source.StageAdvisory})
	app.Fetcher.OSVAPI = osv.URL
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "osv-alpine") || !strings.Contains(lines[0], "musl < 1.2.4-r6 (fixed in 1.2.4-r6) [1.2.4-r3 in use: AFFECTED]") ||
		!strings.Contains(lines[0], "EXPLOITED in the wild (cisa-kev)") {
		t.Fatalf("the source package is looked up, marked by the exploited list, and nothing else is listed:\n%s", out)
	}
	if !strings.Contains(lines[1], "WARNING") || !strings.Contains(lines[1], "1 of type generic, which OSV.dev does not cover") {
		t.Fatalf("a component that is not looked up is reported:\n%s", out)
	}

	app, _, errOut = newRelevanceApp(t, "news", "--sbom", sbom, "--no-osv")
	if code := app.Execute(context.Background()); code != 1 || !strings.Contains(errOut.String(), "--no-osv") {
		t.Fatalf("an SBOM cannot be looked up without OSV.dev: exit %d, %s", code, errOut)
	}
	app, _, errOut = newRelevanceApp(t, "news", "--sbom", filepath.Join(t.TempDir(), "package.json"))
	if code := app.Execute(context.Background()); code != 1 {
		t.Fatalf("a missing file is an error: exit %d, %s", code, errOut)
	}
}
