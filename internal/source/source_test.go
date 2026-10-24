package source

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseValid(t *testing.T) {
	for _, data := range []string{
		`{id: php-releases, name: PHP releases, type: feed, url: "https://www.php.net/releases/feed.php", tags: [php], stage: release}`,
		`{id: php-src, name: php-src advisories, type: github-advisories, repo: php/php-src, tags: [php], stage: advisory}`,
		`{id: kev, name: CISA KEV, type: kev, url: "https://example.org/kev.json", tags: [general], stage: alert}`,
	} {
		if _, err := Parse([]byte(data)); err != nil {
			t.Errorf("%s: %v", data, err)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]struct{ data, want string }{
		"unknown field":     {`{id: x, name: X, type: feed, url: "https://x", tags: [php], stage: release, typo: 1}`, "typo"},
		"bad id":            {`{id: X_Y, name: X, type: feed, url: "https://x", tags: [php], stage: release}`, "lowercase"},
		"bad type":          {`{id: x, name: X, type: html, url: "https://x", tags: [php], stage: release}`, "type"},
		"bad stage":         {`{id: x, name: X, type: feed, url: "https://x", tags: [php], stage: soon}`, "stage"},
		"no tags":           {`{id: x, name: X, type: feed, url: "https://x", stage: release}`, "tags are required"},
		"plain http":        {`{id: x, name: X, type: feed, url: "http://x", tags: [php], stage: release}`, "https"},
		"github needs repo": {`{id: x, name: X, type: github-advisories, tags: [php], stage: advisory}`, "owner/name"},
		"uppercase tag":     {`{id: x, name: X, type: feed, url: "https://x", tags: [PHP], stage: release}`, "lowercase"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.data))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestLoadAllRequiresMatchingFileName(t *testing.T) {
	_, err := LoadAll(fstest.MapFS{
		"other.yaml": {Data: []byte(`{id: x, name: X, type: feed, url: "https://x", tags: [php], stage: release}`)},
	})
	if err == nil || !strings.Contains(err.Error(), "must match the file name") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadSearch(t *testing.T) {
	sources := []Source{{ID: "x", Tags: []string{"node", "swift"}}, {ID: "y", Tags: []string{General}}}
	load := func(data string) (Search, error) {
		return LoadSearch(fstest.MapFS{SearchFile: {Data: []byte(data)}}, sources)
	}
	s, err := load("{aliases: {node: node.js}, skip: [swift]}")
	if err != nil || s.Aliases["node"] != "node.js" || len(s.Skip) != 1 {
		t.Fatalf("got %+v, %v", s, err)
	}
	for data, want := range map[string]string{
		"{aliases: {deno: deno.land}}":             `unknown tag "deno"`,
		"{aliases: {node: Node.js}}":               "lowercase",
		"{aliases: {node: node.js}, skip: [node]}": "both aliased and skipped",
		"{skip: [general]}":                        "not a technology tag",
		"{skip: [swift], typo: 1}":                 "typo",
	} {
		if _, err := load(data); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an error containing %q, got %v", data, want, err)
		}
	}
}

func TestLoadAllSkipsTheSearchFile(t *testing.T) {
	srcs, err := LoadAll(fstest.MapFS{
		SearchFile: {Data: []byte("{skip: [php]}")},
		"x.yaml":   {Data: []byte(`{id: x, name: X, type: feed, url: "https://x", tags: [php], stage: release}`)},
	})
	if err != nil || len(srcs) != 1 {
		t.Fatalf("got %d sources, %v", len(srcs), err)
	}
}
