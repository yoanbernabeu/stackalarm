// Command techdata gathers what the sources say of each tag over the last 30
// days, for the technology pages of the site (site/src/pages/tech): one JSON
// file per tag. It is run by the site workflow, and is not part of a release.
//
//	go run ./cmd/techdata -out site/.data/tech
//	go run ./cmd/techdata -out site/.data/tech -only php,node
//
// The CVE databases searched by word (NVD, EUVD) are left out: on a public
// page, "php" would list every plugin written in PHP, and the NVD allows one
// request every 6 seconds. Each other source is downloaded once, then reused
// from the cache for the next tags.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/yoanbernabeu/stackalarm/internal/cli"
	"github.com/yoanbernabeu/stackalarm/internal/news"
	"github.com/yoanbernabeu/stackalarm/internal/source"
)

const (
	days        = 30
	maxAffected = 3
	// maxFailures is how many times a source may fail before the next tags stop
	// waiting for it: one that hangs would otherwise be waited for once per tag.
	maxFailures = 2
)

type item struct {
	news.Item
	Affected     []news.Affected `json:"affected"`
	MoreAffected int             `json:"more_affected"`
}

type page struct {
	Tag         string         `json:"tag"`
	GeneratedAt time.Time      `json:"generated_at"`
	Since       time.Time      `json:"since"`
	Items       []item         `json:"items"`
	Failures    []news.Failure `json:"failures"`
}

func main() {
	out := flag.String("out", "site/.data/tech", "folder the JSON files are written to")
	only := flag.String("only", "", "comma-separated tags, instead of all of them")
	flag.Parse()
	if err := run(*out, *only); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(out, only string) error {
	app, err := cli.Default("site")
	if err != nil {
		return err
	}
	sources := slices.DeleteFunc(app.Sources, func(s source.Source) bool { return s.Type.IsSearch() })
	tags := slices.DeleteFunc(source.Tags(sources), func(t string) bool {
		return t == source.General || only != "" && !slices.Contains(strings.Split(only, ","), t)
	})
	f := *app.Fetcher
	f.Client = &http.Client{Timeout: 30 * time.Second}
	f.Now = time.Now
	f.GitHubToken = os.Getenv("GITHUB_TOKEN")
	if dir, err := os.UserCacheDir(); err == nil {
		f.CacheDir = filepath.Join(dir, "stackalarm")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	now := time.Now().UTC()
	since := now.Add(-days * 24 * time.Hour)
	failures := map[string]int{}     // source: how many tags it failed for
	lastError := map[string]string{} // source: what it last said
	failed := []string{}             // tags with a failed source of their own
	for i, tag := range tags {
		var gaveUp []news.Failure
		selected := slices.DeleteFunc(slices.Clone(sources), func(s source.Source) bool {
			if failures[s.ID] < maxFailures {
				return false
			}
			if s.IsGeneral() || slices.Contains(s.Tags, tag) {
				gaveUp = append(gaveUp, news.Failure{Source: s.ID, Error: lastError[s.ID]})
			}
			return true
		})
		res := f.Fetch(context.Background(), selected, news.Query{Tags: []string{tag}, Since: since})
		for _, fail := range res.Failures {
			failures[fail.Source]++
			lastError[fail.Source] = fail.Error
		}
		p := page{Tag: tag, GeneratedAt: now, Since: since, Items: []item{}, Failures: append(res.Failures, gaveUp...)}
		for _, it := range res.Items {
			more := max(0, len(it.Affected)-maxAffected)
			p.Items = append(p.Items, item{Item: it, Affected: append([]news.Affected{}, it.Affected[:len(it.Affected)-more]...), MoreAffected: more})
			p.Items[len(p.Items)-1].Summary = "" // the pages show titles and facts only
		}
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, tag+".json"), data, 0o644); err != nil {
			return err
		}
		own := slices.ContainsFunc(p.Failures, func(fail news.Failure) bool {
			return slices.ContainsFunc(sources, func(s source.Source) bool { return s.ID == fail.Source && slices.Contains(s.Tags, tag) })
		})
		if own {
			failed = append(failed, tag)
		}
		fmt.Printf("%d/%d %s: %d items, %d failed sources\n", i+1, len(tags), tag, len(p.Items), len(p.Failures))
	}
	meta, _ := json.Marshal(map[string]any{"generated_at": now, "days": days, "tags": len(tags), "failed": failed})
	if err := os.WriteFile(filepath.Join(out, "_meta.json"), meta, 0o644); err != nil {
		return err
	}
	// A run where the sources of many tags cannot be read (no network, the
	// GitHub API cap) must not replace the pages already published.
	if len(failed) > len(tags)/5 {
		return fmt.Errorf("the own sources of %d tags out of %d could not be read: not publishing this", len(failed), len(tags))
	}
	return nil
}
