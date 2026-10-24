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
		"nothing to watch": "packages: [twig/twig]\n",
		"unknown field":    "tags: [php]\nhost: gitlab.acme.internal\n",
		"bad precision":    "tags: [php]\nstack:\n  - {name: php, precision: about}\n",
		"no name":          "tags: [php]\nstack:\n  - {version: \"8.3\"}\n",
	} {
		if _, err := ParseProfile([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
