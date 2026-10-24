# stackalarm

**Type `/stackalarm` in your AI agent and get a straight answer about your project's security today.**

stackalarm is an agent skill and the CLI it relies on. Open a project in Claude Code, Codex, Cursor or another agent, run the skill, and the agent tells you what in this week's security news affects *this* repository, how urgent it is, and what to change.

An example, on a Symfony project with a self-hosted GitLab, in October 2026:

```
> /stackalarm

Verdict: yes, act today. Two critical PHP flaws (unauthenticated RCE, public exploit)
affect the 8.3 branch this project runs on, and the self-hosted GitLab needs a patch.

🔴 Act now
- PHP, CVE-2026-109618 / CVE-2026-109619 (CVSS 9.2): the Dockerfile uses php:8.3-fpm,
  a floating tag, so production is possibly affected depending on when the image was
  built. Rebuild with --pull, redeploy, check `php -v` shows 8.3.36.
  Until then: session.upload_progress.enabled=0.
- GitLab, CVE-2026-110264 (CVSS 10): the remote points to a self-hosted instance.
  Fixed in 19.5.1, 19.4.3, 19.3.6… Which version does gitlab.acme.internal run?

🟠 Prepare
- Symfony 7.3 no longer gets security fixes; CVE-2026-108082 is only fixed in 7.4.

Checked: php, symfony, composer, gitlab tags, CERTs, NVD, EUVD, KEV, web search, composer audit.
Not checked: the PHP version running in production, the full lockfile.

Shall I pin `FROM php:8.3.36-fpm` in the Dockerfile?
```

## Why

AI now turns a security patch into a working exploit in hours. In October 2026, the PHP team announced a critical release one day ahead ("PHP2Shell"); teams that caught the heads-up on Tuesday evening had a night to prepare, the others learned about it from their logs. Watching dozens of feeds by hand is not realistic. Reading them and matching them against a codebase is exactly what an agent is good at, provided it knows where to look.

## How it works

Neither half is useful alone.

- **The skill is the analyst.** It reads the project (manifests, lockfiles, Dockerfiles, CI, git remotes) to find the technologies and their versions, runs the CLI, and completes it with a web search and your ecosystem's dependency audits (`composer audit`, `npm audit`, `pip-audit`, `govulncheck`…). It decides what actually applies, says how sure it is (exact version, branch or range), asks the one question that would change the verdict, explains, and offers to fix what lives in the repository, one change at a time, after asking.
- **The CLI is its eyes.** It reads 92 sources first-hand, so the agent sees an announcement minutes after it is published, before search engines index it:
  - Projects and vendors: release feeds, security announcements and advisories (PHP, Node.js, Python, Ruby, Go, GitLab, Symfony, Laravel, Django, Rails, Astro, Vite, Next.js, Nuxt, SvelteKit, React, WordPress, Drupal, Netlify, GitHub, Microsoft, Cisco, Fortinet, Palo Alto…) and the GitHub Advisory Database per ecosystem.
  - CVE databases: NIST NVD (US) and ENISA EUVD (EU), searched for the project's technologies.
  - Governments and CERTs: CISA (KEV catalog and advisories), CERT/CC, CERT-FR, CERT-EU, NCSC UK, CERT-Bund, NCSC-NL, CERT Polska, Canadian Centre for Cyber Security, JPCERT/CC, JVN.
  - Exploits and research: Exploit-DB, Zero Day Initiative, Full Disclosure, oss-security, Project Zero, SANS ISC, watchTowr, and the security press.

The CLI does no project analysis, and the skill does not scrape feeds: each does what it is best at.

## Install

Both parts, in two commands.

**1. The CLI**

```sh
brew install yoanbernabeu/tap/stackalarm
```

or, on Linux and macOS:

```sh
curl -sSL https://raw.githubusercontent.com/yoanbernabeu/stackalarm/main/install.sh | sh
```

On Windows, download the zip from the [releases](https://github.com/yoanbernabeu/stackalarm/releases). With Go: `go install github.com/yoanbernabeu/stackalarm/cmd/stackalarm@latest`.

**2. The skill**, for Claude Code, Codex, Cursor and other agents:

```sh
npx skills add yoanbernabeu/stackalarm
```

Optional, for faster and fuller results: set `GITHUB_TOKEN` (or `GH_TOKEN`) to raise the GitHub API rate limit, and `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) to search the NVD faster (without a key, it allows one request every 6 seconds).

## Use

Open a project in your agent and **call the skill explicitly**:

```
/stackalarm
/stackalarm before the Friday deploy
/stackalarm are we affected by PHP2Shell?
```

In agents without slash commands, ask for it by name: *"use the stackalarm skill"*.

Why explicitly: agents tend to answer "any security flaws to fix?" on their own with `npm audit` or `composer audit`, which only see library advisories and know nothing of this week's runtime flaws or announced releases. And a vague question such as "anything today?" may wake up another skill (your calendar…). The skill description also lets the agent pick it on its own for security questions, but calling it is the reliable way.

The agent answers with a verdict, the findings grouped by urgency (act now, prepare, good to know), what it checked and what it could not. It never pushes, deploys or touches a server: what lives outside the repository is explained for you to do.

## The CLI on its own

The agent calls the CLI for you, but you can read the raw news too:

```sh
stackalarm news --tag php --tag gitlab --since 7d
stackalarm news --tag node --tag npm --package express,dompurify --format json
stackalarm sources                          # the sources and their tags
```

```
Security news since 2026-10-16 09:19 UTC (php)

2026-10-21  release   php-releases             PHP 8.3.36 released!
2026-10-21  alert     cert-fr-alerts           [Màj] Multiples vulnérabilités dans PHP (21 octobre 2026)
2026-10-21  alert     exploit-db               [remote] PHP2Shell (CVE-2026-109618) - PHP core versions after v5.4 - RCE
2026-10-20  heads-up  php-internals            [PHP-DEV] Upcoming Critical PHP Security Release
…
```

Every item has a **stage**: `heads-up` (a security release is announced ahead), `release` (the fix is out), `advisory` (CVE details), `alert` (CERT alert, public exploit or exploitation in the wild), `news` (security press and research). Sources that cannot be read are always listed: a silent watch tool is worse than a noisy one. Each source shows at most 30 entries (the most severe first for CVE databases), and the output says when some were left out.

| Option | Default | |
|---|---|---|
| `--tag`, `-t` | all sources | technology to watch, repeatable; an unknown tag is searched as a keyword |
| `--keyword`, `-k` | | word searched in general sources (CERTs, CVE databases, exploits, press), repeatable |
| `--package`, `-p` | | package names from the lockfile: the GitHub Advisory Database sources return only their advisories, repeatable |
| `--since` | `7d` | `24h`, `7d`, `2w`… |
| `--format` | `text` | `text`, `summary` (one line per item, compact for agents) or `json` |
| `--no-cache` | | responses are otherwise reused for an hour (in your user cache directory) |
| `--profile` | | read the tags, keywords and packages from a project profile (`.stackalarm.yaml`) |
| `--state` | | file remembering the items already reported: only new ones are shown |
| `--fail-on` | | exit with code `2` when a new item has one of these stages (`heads-up,alert,release`) |

`--format markdown` prints the report as an issue body. Exit codes: `0` nothing to report, `1` error, `2` new items matching `--fail-on`.

## Scheduled watch

A check only helps when someone runs it. The scheduled watch runs the CLI every few hours in your CI, and opens an issue when a heads-up, an alert or a security release concerns your stack. Quiet runs cost nothing and open nothing.

1. **The profile.** At the end of a `/stackalarm` run, the agent offers to write `.stackalarm.yaml`: the tags, keywords and packages to watch, and the stack they come from. It is refreshed on each run. It never holds host names or secrets.

   ```yaml
   tags: [php, symfony, composer, docker]
   keywords: [frankenphp]
   packages: [symfony/http-kernel, twig/twig]
   stack:
     - {name: php, version: "8.3", precision: branch, from: Dockerfile}
   ```

2. **The schedule.** Every run starts with the CLI alone, which reads the profile: quiet runs are free.
   - **GitHub**: copy [`ci/github/stackalarm.yml`](ci/github/stackalarm.yml) to `.github/workflows/`. It uses the `yoanbernabeu/stackalarm` action, which you can also call from your own workflows (inputs: `profile`, `since`, `fail-on`, `anthropic-api-key`, `issue`, `label`, `install`, `version`; outputs: `found`, `decision`, `report`, `issue-url`).
   - **GitLab**: include [`ci/gitlab/stackalarm.yml`](ci/gitlab/stackalarm.yml), add a `STACKALARM_GITLAB_TOKEN` variable and a pipeline schedule (instructions at the top of the file).

3. **The triage (optional, GitHub).** Raw news is not a verdict: a Go release the project already runs is news, not a reason to act. Set the secret `ANTHROPIC_API_KEY` and, when the CLI finds something new, Claude runs the skill on the project and an issue is opened only when it is concerned (`act` or `prepare`), with the verdict first and the raw news folded below. Otherwise, no issue: the verdict stays in the run summary. Two safety nets: a vulnerability exploited in the wild (CISA KEV, EUVD) that names a watched technology opens an issue whatever the verdict, and if the triage fails, the raw news is posted. The agent can only write its answer files: it cannot open issues nor change the repository. API usage happens only on the runs that find something.

   Without the key, every new heads-up, alert or security release opens an issue with the raw news; run `/stackalarm triage <issue link>` in your agent to judge it.

The CI cache keeps a small state file listing the items already reported, so each item is reported once. It is saved only after the issue is opened: if the cache is lost or the issue fails, an item may be reported twice, never missed.

## Privacy

The CLI downloads public feeds and queries public APIs. The only thing it sends is the tags and keywords it is given, as search terms to the CVE databases (NVD, EUVD): nothing about your project, and no telemetry. The skill runs your own audit tools locally, and its web searches go through your agent.

## Contributing

Contributions go through **issues only**; pull requests are closed automatically. The most useful contribution is a new source: open a [New source](../../issues/new?template=new-source.yml) issue. Ideas for the skill are welcome too. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
