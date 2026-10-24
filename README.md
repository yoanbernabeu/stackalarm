# stackalarm

**Type `/stackalarm` in your AI agent and get a straight answer about your project's security today.**

stackalarm is an agent skill and the CLI it relies on. Open a project in Claude Code, Codex, Cursor or another agent, run the skill, and the agent tells you what in this week's security news affects *this* repository, how urgent it is, and what to change.

**[stackalarm.dev](https://stackalarm.dev)**: what it does, an example answer, and the scheduled watch for your CI.

## How it works

- **The skill is the analyst.** It reads the project (manifests, lockfiles, Dockerfiles, CI, git remotes), runs the CLI, completes it with a web search and your ecosystem's audits (`composer audit`, `npm audit`, `pip-audit`, `govulncheck`…), judges what applies, and offers to fix what lives in the repository, one change at a time, after asking. It never pushes, deploys or touches a server.
- **The CLI is its eyes.** It reads 92 sources first-hand: project and vendor announcements, the GitHub Advisory Database, the NVD and EUVD CVE databases, CERTs, CISA KEV, exploit databases and the security press. It does no project analysis.

## Install

```sh
brew install yoanbernabeu/tap/stackalarm     # or: curl -sSL https://raw.githubusercontent.com/yoanbernabeu/stackalarm/main/install.sh | sh
npx skills add yoanbernabeu/stackalarm
```

On Windows, download the zip from the [releases](https://github.com/yoanbernabeu/stackalarm/releases). With Go: `go install github.com/yoanbernabeu/stackalarm/cmd/stackalarm@latest`.

Optional: `GITHUB_TOKEN` (or `GH_TOKEN`) raises the GitHub API rate limit, and `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) makes NVD searches faster.

## Use

Open a project in your agent and call the skill by name (agents otherwise tend to answer with `npm audit` alone, which knows nothing of this week's runtime flaws):

```
/stackalarm
/stackalarm before the Friday deploy
/stackalarm are we affected by PHP2Shell?
```

The CLI also works on its own:

```sh
stackalarm news --tag php --tag gitlab --since 7d
stackalarm sources                          # the sources and their tags
stackalarm news --help                      # every option
```

## Scheduled watch

Copy [`ci/github/stackalarm.yml`](ci/github/stackalarm.yml) to `.github/workflows/`, or include [`ci/gitlab/stackalarm.yml`](ci/gitlab/stackalarm.yml) in your GitLab CI. Every 4 hours, the CLI reads the `.stackalarm.yaml` profile the skill wrote and opens an issue when a heads-up, an alert or a security release is new. On GitHub, with an `ANTHROPIC_API_KEY` secret, Claude triages the news first and an issue is opened only when the project is concerned.

## Privacy

The CLI downloads public feeds and queries public APIs. It sends only what it is given: tags and keywords, as search terms to the CVE databases (NVD, EUVD), and package names, to the GitHub Advisory Database. Nothing else about your project, and no telemetry.

## Contributing

Contributions go through **issues only**; pull requests are closed automatically. The most useful one is a new source: open a [New source](../../issues/new?template=new-source.yml) issue. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
