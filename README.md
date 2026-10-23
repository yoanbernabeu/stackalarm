# stackalarm

**Security news for your stack, gathered for you and your AI agent.**

Open a project, ask your agent *"anything today?"*, and get a straight answer: what in this week's security news affects this repository, how urgent it is, and what to change.

Why: AI now turns a security patch into a working exploit in hours. In October 2026, the PHP team announced a critical release one day ahead ("PHP2Shell", CVE-2026-109618 and CVE-2026-109619); teams that caught the heads-up on Tuesday had a day to prepare, the others learned about it from their logs. stackalarm reads the places where those signals appear, so you do not have to.

## How it works

- **The CLI** gathers security news from official sources (project announcements, release feeds, GitHub security advisories, CERT-FR, CERT-EU, oss-security, CISA KEV), filtered by technology tags. It does no project analysis.
- **The agent skill** does the thinking: it reads your project, picks the tags and versions, runs the CLI, completes it with a web search (technologies without a source, affected versions, exploitation reports) and your ecosystem's dependency audits, decides what actually applies, explains it, and offers to fix what lives in the repository, one change at a time, after asking.

## Install

```sh
go install github.com/yoanbernabeu/stackalarm/cmd/stackalarm@latest
npx skills add yoanbernabeu/stackalarm      # the skill, for Claude Code, Codex, Cursor and others
```

## Use

With the skill, just ask your agent. On its own, the CLI works too:

```sh
stackalarm news --tag php --tag gitlab --since 7d
stackalarm news --tag node --keyword express --format json
stackalarm sources                          # the sources and their tags
```

```
Security news since 2026-10-16 09:19 UTC (php)

2026-10-21  release   php-releases             PHP 8.3.36 released!
2026-10-21  alert     cert-fr-alerts           [Màj] Multiples vulnérabilités dans PHP (21 octobre 2026)
2026-10-20  heads-up  php-internals            [PHP-DEV] Upcoming Critical PHP Security Release
…
```

Every item has a **stage**: `heads-up` (a security release is announced ahead), `release` (the fix is out), `advisory` (CVE details), `alert` (CERT alert or exploitation in the wild). Sources that cannot be read are always listed: a silent watch tool is worse than a noisy one.

| Option | Default | |
|---|---|---|
| `--tag`, `-t` | all sources | technology to watch, repeatable |
| `--keyword`, `-k` | | word searched in general sources (CERTs, oss-security, KEV), repeatable |
| `--since` | `7d` | `24h`, `7d`, `2w`… |
| `--format` | `text` | `text` or `json` |
| `--no-cache` | | responses are otherwise reused for an hour (in your user cache directory) |

Set `GITHUB_TOKEN` (or `GH_TOKEN`) to raise the GitHub API rate limit.

## Privacy

stackalarm only downloads public feeds. It sends nothing about your project anywhere, and has no telemetry. The skill runs your own audit tools locally.

## Contributing

Contributions go through **issues only**; pull requests are closed automatically. The most useful contribution is a new source: open a [New source](../../issues/new?template=new-source.yml) issue. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
