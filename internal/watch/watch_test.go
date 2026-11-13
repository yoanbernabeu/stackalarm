package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseProfile(t *testing.T) {
	p, err := ParseProfile([]byte(`
tags: [php, symfony]
keywords: [frankenphp]
packages: [twig/twig]
stack:
  - {name: php, version: "8.3", precision: branch, from: Dockerfile}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tags) != 2 || p.Keywords[0] != "frankenphp" || p.Packages[0] != "twig/twig" || p.Stack[0].From != "Dockerfile" {
		t.Fatalf("profile: %+v", p)
	}
}

func TestParseProfileRejects(t *testing.T) {
	for name, data := range map[string]string{
		"nothing to watch":  "packages: [twig/twig]\n",
		"unknown field":     "tags: [php]\nhost: gitlab.acme.internal\n",
		"bad precision":     "tags: [php]\nstack:\n  - {name: php, precision: about}\n",
		"no name":           "tags: [php]\nstack:\n  - {version: \"8.3\"}\n",
		"ignore, no reason": "tags: [php]\nignore:\n  - {id: CVE-2026-1}\n",
		"ignore, no id":     "tags: [php]\nignore:\n  - {reason: unused}\n",
		"ignore, bad date":  "tags: [php]\nignore:\n  - {id: CVE-2026-1, reason: unused, until: soon}\n",
	} {
		if _, err := ParseProfile([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIgnoreExpires(t *testing.T) {
	p, err := ParseProfile([]byte("tags: [php]\nignore:\n  - {id: CVE-2026-1, reason: unused, until: 2026-10-23}\n  - {id: CVE-2026-2, reason: unused}\n"))
	if err != nil || len(p.Ignore) != 2 {
		t.Fatalf("got %+v, %v", p, err)
	}
	day := func(d int) time.Time { return time.Date(2026, 10, d, 15, 0, 0, 0, time.UTC) }
	if p.Ignore[0].Expired(day(23)) || !p.Ignore[0].Expired(day(24)) || p.Ignore[1].Expired(day(24)) {
		t.Fatal("a decision holds until the end of its date, and for ever without one")
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache", "state")
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	s, err := LoadState(path)
	if err != nil || s.Seen("a") {
		t.Fatalf("a missing file must be an empty state: %v", err)
	}
	s.Add("a", now)
	s.Add("old", now.Add(-Retention-48*time.Hour))
	if err := s.Save(path, now); err != nil {
		t.Fatal(err)
	}
	s, err = LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Seen("a") || s.Seen("old") {
		t.Fatalf("state: %+v", s.seen)
	}
}

func TestLoadStateRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	os.WriteFile(path, []byte("a 2026-10-24\nnot a line\n"), 0o600)
	if _, err := LoadState(path); err == nil || !strings.Contains(err.Error(), ":2:") {
		t.Fatalf("err = %v", err)
	}
}
