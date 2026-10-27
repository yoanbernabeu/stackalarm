package news

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const eolProducts = `{"result":[{"name":"nodejs","aliases":["node"]},{"name":"php","aliases":[]},{"name":"go","aliases":["golang"]}]}`

const eolPHP = `{"result":{"releases":[
{"name":"8.5","isEol":false,"eolFrom":"2029-12-31","isMaintained":true,"latest":{"name":"8.5.12","date":"2026-10-21"}},
{"name":"8.3","isEol":false,"eolFrom":"2027-03-31","isMaintained":true,"isEoas":true,"latest":{"name":"8.3.36","date":"2026-10-21"}},
{"name":"8.1","isEol":true,"eolFrom":"2025-12-31","isMaintained":false,"latest":{"name":"8.1.34","date":"2025-07-03"}}]}}`

const eolGo = `{"result":{"releases":[
{"name":"1.27","isEol":false,"eolFrom":null,"isMaintained":true,"latest":{"name":"1.27.3","date":"2026-10-01"}},
{"name":"1.2","isEol":true,"eolFrom":"2014-06-01","isMaintained":false,"latest":{"name":"1.2.2","date":"2014-05-05"}}]}}`

func TestSupport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/products":
			w.Write([]byte(eolProducts))
		case "/products/php":
			w.Write([]byte(eolPHP))
		case "/products/go":
			w.Write([]byte(eolGo))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	f := &Fetcher{Client: srv.Client(), EOLAPI: srv.URL, Now: func() time.Time { return now }}
	got, err := f.Support(context.Background(), []string{"php@8.1.31", "php@8.3.20", "php@8.5.12", "PHP@8.5", "golang@1.27.3", "frankenphp@1.4", "php@>=8.2"})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, s := range got {
		lines = append(lines, s.Name+"@"+s.Version+" "+s.Product+" "+s.Cycle+" "+s.Status)
	}
	want := []string{
		"php@8.1.31 php 8.1 eol",
		"php@8.3.20 php 8.3 ending", // March 2027 is within 180 days: more urgent than the missing patch
		"php@8.5.12 php 8.5 supported",
		"PHP@8.5 php 8.5 supported",       // a branch follows its latest release
		"golang@1.27.3 go 1.27 supported", // 1.27, not 1.2
		"frankenphp@1.4   unknown",
		"php@>=8.2 php  unknown",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(got[6].Note, "maintained cycles: 8.5, 8.3") {
		t.Fatalf("a vague version lists the maintained cycles: %q", got[6].Note)
	}

	f.Now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	got, _ = f.Support(context.Background(), []string{"php@8.3.20"})
	if got[0].Status != StatusBehind || !strings.Contains(got[0].Note, "8.3.36") {
		t.Fatalf("an older patch release is behind: %+v", got[0])
	}

	if _, err := f.Support(context.Background(), []string{"node@22"}); err == nil {
		t.Fatal("a product that cannot be read fails the lookup")
	}
}
