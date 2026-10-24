# AGENTS.md

Guide for coding agents (and humans) changing stackalarm.

## What it is

A Go CLI that gathers security news (heads-ups, releases, advisories, CERT alerts, CISA KEV) from official sources, filtered by technology tags, plus an agent skill (`skills/stackalarm/SKILL.md`) that lets an AI agent read a project, pick the tags, run the CLI and judge what matters. The CLI does no stack detection on purpose: the agent does that.

## Layout

```
cmd/stackalarm/     entry point
internal/cli/       Cobra commands (news, sources); App holds every dependency
internal/news/      fetching, parsing (RSS, RDF, Atom, GitHub advisories, KEV), filtering, cache
internal/source/    the source format and its validation
internal/watch/     the project profile and the state of a scheduled watch
sources/            one YAML file per source, embedded in the binary
skills/stackalarm/  the agent skill (published on skills.sh)
evals/              test prompts and assertions for the skill (kept out of the skill folder)
action.yml          the GitHub Action of the scheduled watch
ci/                 ready-to-copy scheduled watch for GitHub and GitLab
site/               the presentation site (Astro), see site/DESIGN.md
```

## Adding a source (from a "New source" issue)

1. Check the URL answers and the entries carry dates.
2. Write `sources/<id>.yaml` (the id is the file name).
3. `go test ./...` validates every bundled source.
4. Run `go run ./cmd/stackalarm news --tag <tag> --since 30d --no-cache` and check the entries look right.
5. Commit with `Fixes #<issue>`.

## Rules

- Everything in English.
- Standard library first; no new dependency without a clear reason.
- A source that fails is always reported, never silently skipped.
- Tests never hit the network: use `httptest`.
- Checks before every commit: `gofmt -l .` (prints nothing), `go vet ./...`, `go test -race ./...`.
