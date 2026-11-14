package news

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/source"
)

// A KEV catalog whose PHP flaws were all added before the period: one hits
// 8.3.35, one an older branch, one a PHP library that is not PHP itself.
const kevBeforeThePeriod = `{"vulnerabilities":[
{"cveID":"CVE-2026-109618","vendorProject":"PHP Group","product":"PHP","vulnerabilityName":"PHP Memory Corruption","dateAdded":"2026-10-26","shortDescription":"RCE.","requiredAction":"Patch."},
{"cveID":"CVE-2024-4577","vendorProject":"PHP Group","product":"PHP","vulnerabilityName":"PHP-CGI Argument Injection","dateAdded":"2024-06-12","shortDescription":"RCE.","requiredAction":"Patch."},
{"cveID":"CVE-2016-10033","vendorProject":"PHP","product":"PHPMailer","vulnerabilityName":"PHPMailer Command Injection","dateAdded":"2025-07-07","shortDescription":"RCE.","requiredAction":"Patch."},
{"cveID":"CVE-2026-97229","vendorProject":"GitLab","product":"Community Edition and Enterprise Edition","vulnerabilityName":"GitLab Integer Overflow","dateAdded":"2026-10-29","shortDescription":"RCE.","requiredAction":"Patch."}]}`

func cveRecord(product, ranges string) string {
	return `{"cveMetadata":{"state":"PUBLISHED","datePublished":"2026-10-21T10:00:00Z"},"containers":{"cna":{"title":"t","descriptions":[{"lang":"en","value":"d"}],
"affected":[{"vendor":"v","product":"` + product + `","versions":[` + ranges + `]}]}}}`
}

func TestExploitedFlawsHittingAVersionAreListedWhateverTheirDate(t *testing.T) {
	var nvdHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			w.Write([]byte(kevBeforeThePeriod))
		case "/cve/CVE-2026-109618": // the range written by the vendor, with a wildcard
			w.Write([]byte(cveRecord("PHP", `{"version":"8.3.*","lessThan":"8.3.36","status":"affected"}`)))
		case "/cve/CVE-2016-10033":
			w.Write([]byte(cveRecord("PHPMailer", `{"version":"0","lessThan":"5.2.18","status":"affected"}`)))
		case "/cve/CVE-2024-4577", "/cve/CVE-2026-97229": // no range in the record: the NVD has it
			w.Write([]byte(cveRecord("n/a", `{"version":"n/a","status":"affected"}`)))
		case "/nvd":
			nvdHits.Add(1)
			switch r.URL.Query().Get("cveId") {
			case "CVE-2024-4577":
				w.Write([]byte(nvdRecord("CVE-2024-4577", "php:php", "8.1.0", "8.1.29")))
			case "CVE-2026-97229":
				w.Write([]byte(nvdRecord("CVE-2026-97229", "gitlab:gitlab", "19.4.0", "19.4.6")))
			default:
				w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	sources := []source.Source{
		{ID: "cisa-kev", Type: source.TypeKEV, URL: srv.URL + "/kev", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "nvd", Type: source.TypeNVD, URL: srv.URL + "/nvd", Tags: []string{"general"}, Stage: source.StageAdvisory},
	}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", CVEAPI: srv.URL + "/cve", Now: func() time.Time { return now },
		Search: source.Search{CPE: map[string]string{"php": "php:php", "gitlab": "gitlab:gitlab"}, Skip: []string{"php", "gitlab"}}}
	q := Query{Tags: []string{"php", "gitlab"}, Versions: map[string]string{"php": "8.3.35", "gitlab": "19.4.0"}, Since: now.Add(-7 * 24 * time.Hour)}

	res := f.Fetch(context.Background(), sources, q)
	var got []string
	for _, it := range res.Items {
		got = append(got, it.Title[:strings.Index(it.Title, " ")]+" "+affectedLine(it))
	}
	want := []string{
		"CVE-2026-97229 gitlab >= 19.4.0, < 19.4.6 fixed 19.4.6 [19.4.0 affected]",
		"CVE-2026-109618 php >= 8.3, < 8.3.36 fixed 8.3.36 [8.3.35 affected]",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, it := range res.Items {
		if len(it.ExploitedIn) != 1 || it.Stage != source.StageAlert || it.Source != "cisa-kev" {
			t.Fatalf("an exploited flaw in use is an alert of the catalog: %+v", it)
		}
	}

	res = f.Fetch(context.Background(), sources, Query{Tags: []string{"php"}, Since: q.Since})
	if len(res.Items) != 0 {
		t.Fatalf("without a version, nothing proves the old entries: %+v", res.Items)
	}
}

func nvdRecord(id, cpe, from, fixed string) string {
	return fmt.Sprintf(`{"totalResults":1,"vulnerabilities":[{"cve":{"id":%q,"published":"2024-06-09T20:15:00.000","descriptions":[{"lang":"en","value":"d"}],
"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]},"configurations":[{"nodes":[{"cpeMatch":[
{"vulnerable":true,"criteria":"cpe:2.3:a:%s:*:*:*:*:*:*:*:*","versionStartIncluding":%q,"versionEndExcluding":%q}]}]}]}}]}`, id, cpe, from, fixed)
}

func affectedLine(it Item) string {
	var parts []string
	for _, a := range it.Affected {
		parts = append(parts, fmt.Sprintf("%s %s fixed %s [%s %s]", a.Package, a.Versions, a.Fixed, a.InUse, a.Status))
	}
	return strings.Join(parts, "; ")
}

func TestTidyRange(t *testing.T) {
	for in, want := range map[string]string{
		">= 1.3.2, < 1.3.2":                   "< 1.3.2", // the NVD slip that hid CVE-2023-4863 in libwebp 1.3.1
		">= 116.0.5845.187, < 116.0.5845.187": "< 116.0.5845.187",
		">= 8.3.*, < 8.3.36":                  ">= 8.3, < 8.3.36",
		">= 13.0.0, < 13.5.9":                 ">= 13.0.0, < 13.5.9",
		">= 2.0, <= 2.0":                      ">= 2.0, <= 2.0", // one version
		"< 5.4.46":                            "< 5.4.46",
		"6.4.4":                               "6.4.4",
		">= 1.0":                              ">= 1.0",
	} {
		if got := tidyRange(in); got != want {
			t.Errorf("tidyRange(%q) = %q, want %q", in, got, want)
		}
	}
	if in, ok := inRange("1.3.1", tidyRange(">= 1.3.2, < 1.3.2")); !ok || !in {
		t.Fatal("1.3.1 is in the repaired range")
	}
}

func TestRangeWrittenAsTextGivesItsFix(t *testing.T) {
	p, err := parseCVEProgram([]byte(cveRecord("next.js", `{"version":">= 15.0.0, < 15.2.3","status":"affected"},{"version":"< 5.4.46","status":"affected"},{"version":"<= 2.1","status":"affected"}`)))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, a := range p.Affected {
		got = append(got, a.Versions+" fixed "+a.Fixed)
	}
	if want := ">= 15.0.0, < 15.2.3 fixed 15.2.3|< 5.4.46 fixed 5.4.46|<= 2.1 fixed "; strings.Join(got, "|") != want {
		t.Fatalf("got %q, want %q", strings.Join(got, "|"), want)
	}
}

func TestSameProduct(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"next", "next.js", true},
		{"PHP", "php", true},
		{"react-server-dom-webpack", "react-server-dom-parcel", false},
		{"redis", "redis-py", false},
	} {
		if got := sameProduct(c.a, c.b); got != c.same {
			t.Errorf("sameProduct(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestBehindIsSaidOfAnEndingCycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/products":
			w.Write([]byte(eolProducts))
		case "/products/php":
			w.Write([]byte(eolPHP))
		}
	}))
	defer srv.Close()
	f := &Fetcher{Client: srv.Client(), EOLAPI: srv.URL, Now: func() time.Time { return time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC) }}
	got, err := f.Support(context.Background(), []string{"php@8.3.20", "php@8.1.31", "php@8.3.36"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != StatusEnding || !strings.Contains(got[0].Note, "also behind: the latest 8.3 release is 8.3.36") {
		t.Fatalf("ending and behind: %+v", got[0])
	}
	if got[1].Status != StatusEOL || !strings.Contains(got[1].Note, "also behind: the latest 8.1 release is 8.1.34") {
		t.Fatalf("eol and behind: %+v", got[1])
	}
	if strings.Contains(got[2].Note, "behind") {
		t.Fatalf("the latest release is not behind: %+v", got[2])
	}
}

func TestSearchTermsFollowTheOrderGiven(t *testing.T) {
	q := Query{
		Tags:     []string{"php", "nextjs", "gitlab", "symfony", "nginx", "node", "react", "twig"},
		Keywords: []string{"dompdf", "libwebp"},
		Order:    []string{"php", "dompdf", "nextjs", "libwebp", "gitlab", "symfony", "nginx", "node", "react", "twig"},
	}
	got, left := searchTerms(q, source.Search{})
	if strings.Join(got.words, ",") != "php,dompdf,nextjs,libwebp,gitlab,symfony,nginx,node" || strings.Join(left, ",") != "react,twig" {
		t.Fatalf("searched %v, left %v", got.words, left)
	}
	q.Order = nil
	if got, _ := searchTerms(q, source.Search{}); got.words[1] != "nextjs" {
		t.Fatalf("without an order, the tags come first: %v", got.words)
	}
}

func TestOSVEntriesTakeTurnsByPackage(t *testing.T) {
	e := func(pkg string, n int) entry {
		return entry{Title: fmt.Sprint(pkg, n), Affected: []Affected{{Package: pkg, Status: StatusAffected}}}
	}
	var titles []string
	for _, x := range inTurns([]entry{e("pillow", 1), e("pillow", 2), e("pillow", 3), e("jinja2", 1), e("urllib3", 1), e("jinja2", 2)}) {
		titles = append(titles, x.Title)
	}
	if strings.Join(titles, ",") != "pillow1,jinja21,urllib31,pillow2,jinja22,pillow3" {
		t.Fatalf("got %v", titles)
	}
}

func TestSBOMLeavesTheKernelOut(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","components":[
{"type":"library","purl":"pkg:deb/debian/linux-libc-dev@6.1.190-1?distro=debian-12","properties":[{"name":"aquasecurity:trivy:SrcName","value":"linux"},{"name":"aquasecurity:trivy:SrcVersion","value":"6.1.190"},{"name":"aquasecurity:trivy:SrcRelease","value":"1"}]},
{"type":"library","purl":"pkg:apk/alpine/linux-pam@1.6.1-r1?distro=3.21.0"},
{"type":"library","purl":"pkg:deb/debian/curl@7.88.1-10?distro=debian-12"}]}`
	sbom, err := ParseSBOM([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range sbom.Components {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "linux-pam,curl" || sbom.Skipped["kernel packages (a container runs the kernel of its host)"] != 1 {
		t.Fatalf("components %v, skipped %v", names, sbom.Skipped)
	}
}

func TestNVDIsTriedAgainOnAServerError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	f := &Fetcher{Client: srv.Client(), UserAgent: "test", Now: time.Now}
	if _, _, err := f.get(context.Background(), srv.URL, "nvd"); err != nil || calls.Load() != 2 {
		t.Fatalf("err %v after %d calls", err, calls.Load())
	}
	calls.Store(0)
	if _, _, err := f.get(context.Background(), srv.URL, ""); err == nil || calls.Load() != 1 {
		t.Fatalf("other APIs are not tried again: err %v after %d calls", err, calls.Load())
	}
}
