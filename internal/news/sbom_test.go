package news

import (
	"context"
	"encoding/json"
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

// What trivy writes for an image: the system and the image itself are not
// packages, and a distribution package names its source in properties.
const cycloneDX = `{"bomFormat":"CycloneDX","components":[
{"type":"operating-system","name":"debian","version":"12.15"},
{"type":"library","purl":"pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=arm64&distro=debian-12.15&epoch=1","properties":[
 {"name":"aquasecurity:trivy:SrcEpoch","value":"1"},{"name":"aquasecurity:trivy:SrcName","value":"zlib"},
 {"name":"aquasecurity:trivy:SrcRelease","value":"1"},{"name":"aquasecurity:trivy:SrcVersion","value":"1.2.13.dfsg"}]},
{"type":"library","purl":"pkg:npm/%40isaacs/cliui@8.0.2","components":[{"type":"library","purl":"pkg:golang/golang.org/x/net@v0.30.0"}]},
{"type":"library","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"},
{"type":"library","purl":"pkg:pypi/Flask_Login@0.6.3"},
{"type":"library","purl":"pkg:rpm/redhat/openssl@3.0.7-1.el9?distro=rhel-9"},
{"type":"library","purl":"pkg:deb/debian/tar@1.34"},
{"type":"library","name":"unnamed"}]}`

func TestSBOMCycloneDX(t *testing.T) {
	sbom, err := ParseSBOM([]byte(cycloneDX))
	if err != nil {
		t.Fatal(err)
	}
	want := []Component{
		{Ecosystem: "Debian:12", Name: "zlib", Version: "1:1.2.13.dfsg-1"}, // the source package, with its epoch
		{Ecosystem: "Go", Name: "golang.org/x/net", Version: "0.30.0"},     // nested, and without the v of go.mod
		{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
		{Ecosystem: "PyPI", Name: "flask-login", Version: "0.6.3"},
		{Ecosystem: "npm", Name: "@isaacs/cliui", Version: "8.0.2"},
	}
	if !slices.Equal(sbom.Components, want) {
		t.Fatalf("got %+v", sbom.Components)
	}
	note := sbom.SkippedNote()
	for _, reason := range []string{"1 of type rpm/redhat, which OSV.dev does not cover", "1 of type deb/debian, without the release", "1 without a package URL"} {
		if !strings.Contains(note, reason) {
			t.Fatalf("every component left out is counted, missing %q in %q", reason, note)
		}
	}
}

func TestSBOMSPDXAndSyftQualifiers(t *testing.T) {
	sbom, err := ParseSBOM([]byte(`{"spdxVersion":"SPDX-2.3","packages":[
{"name":"alpine:3.19","primaryPackagePurpose":"CONTAINER","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:oci/alpine@sha256%3Aabc"}]},
{"name":"ssl_client","sourceInfo":"built package from: busybox 1.36.1-r20","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/alpine/ssl_client@1.36.1-r20?arch=x86_64&distro=3.19.9"}]},
{"name":"libssl3","externalRefs":[{"referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:x:y"},{"referenceType":"purl","referenceLocator":"pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04&upstream=openssl"}]},
{"name":"libc6","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/libc6@2.36-9?distro=bookworm&upstream=glibc%402.36-9%2Bdeb12u1"}]},
{"name":"bash","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:rpm/rocky/bash@5.1.8-6.el9_1?arch=x86_64&distro=rocky-9.3&upstream=bash-5.1.8-6.el9_1.src.rpm"}]},
{"name":"glibc","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:apk/wolfi/glibc@2.44-r17?distro=20230201"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []Component{
		{Ecosystem: "Alpine:v3.19", Name: "busybox", Version: "1.36.1-r20"},
		{Ecosystem: "Debian:12", Name: "glibc", Version: "2.36-9+deb12u1"},
		{Ecosystem: "Rocky Linux:9", Name: "bash", Version: "5.1.8-6.el9_1"},
		{Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "3.0.2-0ubuntu1.18"},
		{Ecosystem: "Wolfi", Name: "glibc", Version: "2.44-r17"},
	}
	if !slices.Equal(sbom.Components, want) || len(sbom.Skipped) != 0 {
		t.Fatalf("got %+v, skipped %v", sbom.Components, sbom.Skipped)
	}
	for _, bad := range []string{`not json`, `{"name":"package.json"}`, `{"spdxVersion":"SPDX-3.0"}`} {
		if _, err := ParseSBOM([]byte(bad)); err == nil {
			t.Fatalf("%s is no SBOM this reads", bad)
		}
	}
}

const debianRecord = `{"id":"DEBIAN-CVE-2026-1000","details":"Heap overflow in inflate.","upstream":["CVE-2026-1000"],"published":"2025-01-02T00:00:00Z",
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[
{"package":{"name":"zlib","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.2.11-9"}]}]},
{"package":{"name":"zlib","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:1.2.13.dfsg-3"}]}]}]}`

func TestSBOMComponentsAreAskedInTheirOwnEcosystem(t *testing.T) {
	var (
		mu    sync.Mutex
		asked []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/osv/querybatch":
			body, _ := io.ReadAll(r.Body)
			var q struct{ Queries []osvQuery }
			json.Unmarshal(body, &q)
			out := `{"results":[`
			mu.Lock()
			for i, query := range q.Queries {
				asked = append(asked, query.Package.Ecosystem+"/"+query.Package.Name+"@"+query.Version)
				ids := map[string]string{"zlib": "DEBIAN-CVE-2026-1000", "dpkg": "DEBIAN-CVE-2026-1001", "tar": "DEBIAN-CVE-2026-1002"}
				out += strings.Repeat(",", min(i, 1)) + `{"vulns":[{"id":"` + ids[query.Package.Name] + `"}]}`
			}
			mu.Unlock()
			w.Write([]byte(out + `]}`))
		case r.URL.Path == "/osv/vulns/DEBIAN-CVE-2026-1000":
			w.Write([]byte(debianRecord))
		case r.URL.Path == "/osv/vulns/DEBIAN-CVE-2026-1001": // no fix, but Debian judges it harmless
			w.Write([]byte(`{"id":"DEBIAN-CVE-2026-1001","details":"Theoretical issue.","upstream":["CVE-2026-1001"],"published":"2026-10-20T00:00:00Z",
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[
{"package":{"name":"dpkg","ecosystem":"Debian:12"},"ecosystem_specific":{"urgency":"unimportant"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`))
		case r.URL.Path == "/osv/vulns/DEBIAN-CVE-2026-1002": // no fix yet
			w.Write([]byte(`{"id":"DEBIAN-CVE-2026-1002","details":"Path traversal.","upstream":["CVE-2026-1002"],"published":"2026-10-21T00:00:00Z",
"affected":[{"package":{"name":"tar","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`))
		case r.URL.Path == "/kev":
			w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-1000","vendorProject":"zlib","product":"zlib","vulnerabilityName":"overflow","dateAdded":"2026-10-22","shortDescription":"d","requiredAction":"Patch."},
{"cveID":"CVE-2026-7777","vendorProject":"Other","product":"Thing","vulnerabilityName":"RCE","dateAdded":"2026-10-22","shortDescription":"d","requiredAction":"Patch."}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), OSVAPI: srv.URL + "/osv", Now: func() time.Time { return now }}
	sources := []source.Source{
		{ID: "osv-debian", Type: source.TypeOSV, Ecosystem: "Debian", Tags: []string{"debian"}, Stage: source.StageAdvisory},
		{ID: "osv-npm", Type: source.TypeOSV, Ecosystem: "npm", Tags: []string{"npm"}, Stage: source.StageAdvisory},
		{ID: "cisa-kev", Type: source.TypeKEV, URL: srv.URL + "/kev", Tags: []string{"general"}, Stage: source.StageAlert},
		{ID: "php-news", Type: source.TypeFeed, URL: srv.URL + "/none", Tags: []string{"php"}, Stage: source.StageRelease},
	}
	res := f.Fetch(context.Background(), sources, Query{Since: now.Add(-7 * 24 * time.Hour), ComponentsOnly: true, Components: []Component{
		{Ecosystem: "Debian:12", Name: "zlib", Version: "1:1.2.13.dfsg-1"}, {Ecosystem: "Debian:12", Name: "dpkg", Version: "1.21.22"}, {Ecosystem: "Debian:12", Name: "tar", Version: "1.34"},
	}})
	slices.Sort(asked)
	if strings.Join(asked, " ") != "Debian:12/dpkg@1.21.22 Debian:12/tar@1.34 Debian:12/zlib@1:1.2.13.dfsg-1" {
		t.Fatalf("the release of the distribution is asked, and no other ecosystem: %v", asked)
	}
	if len(res.Failures) != 0 || len(res.Items) != 3 {
		t.Fatalf("an SBOM alone lists its vulnerabilities, not the feeds nor the exploited list itself: %+v %+v", res.Items, res.Failures)
	}
	byTitle := map[string]Item{}
	for _, it := range res.Items {
		byTitle[it.Title] = it
	}
	zlib, ok := byTitle["[critical] zlib: Heap overflow in inflate. (CVE-2026-1000)"]
	if !ok || !slices.Equal(zlib.ExploitedIn, []string{"cisa-kev"}) {
		t.Fatalf("named after the package and its CVE, and marked exploited: %+v", res.Items)
	}
	if len(zlib.Affected) != 1 || zlib.Affected[0] != (Affected{Package: "zlib", Versions: "< 1:1.2.13.dfsg-3", Fixed: "1:1.2.13.dfsg-3", InUse: "1:1.2.13.dfsg-1", Status: StatusAffected}) {
		t.Fatalf("only the range of the release in use, trusted as OSV.dev gave it: %+v", zlib.Affected)
	}
	if _, ok := byTitle["[unimportant] dpkg: Theoretical issue. (CVE-2026-1001)"]; !ok {
		t.Fatalf("what the distribution judges harmless is listed and says so: %+v", res.Items)
	}
}

func TestOSVOrderPutsWhatAnUpdateFixesFirst(t *testing.T) {
	fixed := entry{Score: 5, Affected: []Affected{{Status: StatusAffected, Fixed: "2"}}}
	if fixable(fixed) != 1 || fixable(entry{Score: 9.8, Affected: []Affected{{Status: StatusAffected}}}) != 0 {
		t.Fatal("a fixed version makes an entry fixable")
	}
	if priority(entry{Score: 9.8, Rank: 0.1}) != 0.1 || priority(entry{}) != 9 || priority(entry{Score: 4}) != 4 {
		t.Fatal("the rank a distribution gives comes before the score, and no score ranks high")
	}
}
