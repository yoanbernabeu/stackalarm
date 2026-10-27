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
	"github.com/yoanbernabeu/stackalarm/sources"
)

func TestBundledSourcesAreValid(t *testing.T) {
	srcs, err := source.LoadAll(sources.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(srcs) < 20 {
		t.Fatalf("only %d sources loaded", len(srcs))
	}
	if _, err := source.LoadSearch(sources.FS, srcs); err != nil {
		t.Fatal(err)
	}
}

func newTestApp(t *testing.T, args ...string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`<rss><channel>
<item><title>PHP 8.3.36 security release</title><link>https://x/1</link><pubDate>Wed, 21 Oct 2026 14:00:00 +0000</pubDate></item>
</channel></rss>`))
	}))
	t.Cleanup(srv.Close)
	var out, errOut bytes.Buffer
	app := &App{
		Out: &out, Err: &errOut, Version: "test", Args: args,
		Sources: []source.Source{
			{ID: "php-releases", Name: "PHP", Type: source.TypeFeed, URL: srv.URL, Tags: []string{"php"}, Stage: source.StageRelease},
			{ID: "cert", Name: "CERT", Type: source.TypeFeed, URL: srv.URL, Tags: []string{"general"}, Stage: source.StageAlert},
		},
		Fetcher:   &news.Fetcher{Client: srv.Client(), UserAgent: "test", CacheTTL: time.Hour},
		Now:       func() time.Time { return time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC) },
		Getenv:    func(string) string { return "" },
		CacheRoot: func() (string, error) { return t.TempDir(), nil },
	}
	return app, &out, &errOut
}

func TestNewsJSON(t *testing.T) {
	app, out, errOut := newTestApp(t, "news", "--tag", "PHP", "--format", "json")
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var r newsReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Items) != 2 || r.Items[0].Stage == "" || r.Tags[0] != "php" {
		t.Fatalf("report: %+v", r)
	}
}

func TestNewsText(t *testing.T) {
	app, out, _ := newTestApp(t, "news", "--tag", "php", "--since", "24h")
	app.Execute(context.Background())
	if !strings.Contains(out.String(), "Nothing new.") {
		t.Fatalf("an item older than 24h must not show:\n%s", out)
	}
}

func TestNewsSearchesUnknownTagAsKeyword(t *testing.T) {
	app, out, errOut := newTestApp(t, "news", "--tag", "php", "--tag", "COBOL", "--format", "json")
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var r newsReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Tags, ",") != "php" || strings.Join(r.Keywords, ",") != "cobol" || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], `"cobol"`) {
		t.Fatalf("report: %+v", r)
	}
}

func TestSources(t *testing.T) {
	app, out, _ := newTestApp(t, "sources")
	app.Execute(context.Background())
	if !strings.Contains(out.String(), "php-releases") || !strings.Contains(out.String(), "Tags: general, php") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestNewsSummary(t *testing.T) {
	app, out, errOut := newTestApp(t, "news", "--tag", "php", "--format", "summary")
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out.String(), "2026-10-21 | release | php-releases | - | PHP 8.3.36 security release | https://x/1") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestSummaryShowsAffectedVersionsAndEPSS(t *testing.T) {
	app, out, _ := newTestApp(t)
	app.printSummary(newsReport{Items: []news.Item{{
		Published: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC), Stage: source.StageAdvisory, Source: "ghsa-npm", Score: 8.7, EPSS: 0.004, Title: "Token leak",
		Affected: []news.Affected{{Package: "a", Versions: "< 7.1.0", Fixed: "7.1.0"}, {Package: "b", Versions: "<= 2.0.0"}, {Package: "c"}, {Package: "d"}},
	}}})
	want := " | affects a < 7.1.0 (fixed in 7.1.0); b <= 2.0.0 (no fix yet); c all versions (no fix yet); and 1 more | EPSS 0.4%"
	if !strings.HasSuffix(strings.TrimSpace(out.String()), want) {
		t.Fatalf("got:\n%s", out)
	}
}

func TestScheduledWatch(t *testing.T) {
	dir := t.TempDir()
	profile, state := filepath.Join(dir, ".stackalarm.yaml"), filepath.Join(dir, "state")
	os.WriteFile(profile, []byte("tags: [php]\nstack:\n  - {name: php, version: \"8.3\", precision: branch, from: Dockerfile}\n"), 0o600)
	run := func(failOn string) (int, *bytes.Buffer) {
		app, out, _ := newTestApp(t, "news", "--profile", profile, "--state", state, "--fail-on", failOn, "--format", "markdown")
		return app.Execute(context.Background()), out
	}

	if code, _ := run("heads-up"); code != 0 {
		t.Fatalf("no heads-up: exit %d, want 0", code)
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("a quiet run must not mark the items as reported")
	}
	code, out := run("release")
	if code != 2 {
		t.Fatalf("a new release: exit %d, want 2", code)
	}
	if !strings.Contains(out.String(), "## stackalarm: 1 alert, 1 release") || !strings.Contains(out.String(), "Stack: php 8.3 (branch) from Dockerfile.") ||
		!strings.Contains(out.String(), "### Releases with security fixes") {
		t.Fatalf("report:\n%s", out)
	}
	code, out = run("release")
	if code != 0 || !strings.Contains(out.String(), "nothing new") || !strings.Contains(out.String(), "already reported by an earlier run: 2 items") {
		t.Fatalf("second run: exit %d\n%s", code, out)
	}
}

func TestNewsRejectsUnknownFailOnStage(t *testing.T) {
	app, _, errOut := newTestApp(t, "news", "--tag", "php", "--fail-on", "urgent")
	if code := app.Execute(context.Background()); code != 1 || !strings.Contains(errOut.String(), "--fail-on") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestMarkdownEscapesThirdPartyText(t *testing.T) {
	var out bytes.Buffer
	app := &App{Out: &out}
	app.printMarkdown(newsReport{
		Tags: []string{"php"},
		Items: []news.Item{{
			ID: "x", Source: "cert", Stage: source.StageAlert, Title: "Ping @admin ![img](https://evil/x.png) <script>\n# title",
			URL: "javascript:alert(1)", Published: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		}},
	})
	got := out.String()
	for _, bad := range []string{"@admin", "![img]", "<script>", "javascript:", "\n# title"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q not escaped:\n%s", bad, got)
		}
	}
}

func TestEOLReadsTheStackOfTheProfile(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.URL.Path == "/products" {
			w.Write([]byte(`{"result":[{"name":"php","aliases":[]}]}`))
			return
		}
		w.Write([]byte(`{"result":{"releases":[{"name":"8.1","isEol":true,"eolFrom":"2025-12-31"}]}}`))
	}))
	defer srv.Close()
	profile := filepath.Join(t.TempDir(), ".stackalarm.yaml")
	os.WriteFile(profile, []byte("tags: [php]\nstack:\n  - {name: php, version: \"8.1\", precision: branch}\n  - {name: gitlab, version: unknown}\n"), 0o600)
	app, out, errOut := newTestApp(t, "eol", "--profile", profile)
	app.Fetcher = &news.Fetcher{Client: srv.Client(), EOLAPI: srv.URL}
	if code := app.Execute(context.Background()); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out.String(), "php 8.1    8.1    eol") || !strings.Contains(out.String(), "gitlab     -      unknown") {
		t.Fatalf("got:\n%s", out)
	}

	app, _, errOut = newTestApp(t, "eol")
	if code := app.Execute(context.Background()); code != 1 || !strings.Contains(errOut.String(), "name the components") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
