# stackalarm

**Type `/stackalarm` in your AI agent and get a straight answer about your project's security today.**

stackalarm is an agent skill and the CLI it relies on. Open a project in Claude Code, Codex, Cursor or another agent, run the skill, and the agent tells you what in this week's security news affects *this* repository, how urgent it is, and what to change.

**[stackalarm.dev](https://stackalarm.dev)**: what it does and an example answer. **[Documentation](https://stackalarm.dev/docs/)**: the skill, every CLI option, the scheduled watch, the sources.

## How it works

- **The skill is the analyst.** It reads the project (manifests, lockfiles, Dockerfiles, CI, git remotes), runs the CLI, completes it with a web search and your ecosystem's audits (`composer audit`, `npm audit`, `pip-audit`, `govulncheck`…), judges what applies, and offers to fix what lives in the repository, one change at a time, after asking. It never pushes, deploys or touches a server.
- **The CLI is its eyes.** It reads more than 280 sources first-hand: project and vendor announcements, the GitHub Advisory Database, OSV.dev, the NVD and EUVD CVE databases, CERTs, CISA KEV, catalogs of public exploits and the security press. Given the versions in use, it tells which vulnerable ranges hold them. It does no project analysis.

## Install

```sh
npx skills add yoanbernabeu/stackalarm
```

The first time you run `/stackalarm`, the skill sees the CLI is missing and offers to install it; it runs nothing before you agree. To install the CLI yourself: `brew install yoanbernabeu/tap/stackalarm`, or `curl -sSL https://raw.githubusercontent.com/yoanbernabeu/stackalarm/main/install.sh | sh`. On Windows, download the zip from the [releases](https://github.com/yoanbernabeu/stackalarm/releases). With Go: `go install github.com/yoanbernabeu/stackalarm/cmd/stackalarm@latest`.

Optional: `GITHUB_TOKEN` (or `GH_TOKEN`) raises the GitHub API rate limit, and `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) makes NVD searches faster.

## Update

The skill and the CLI go together: a new CLI with an old skill still answers, but the agent does not know the newer commands. Update both.

```sh
npx skills add yoanbernabeu/stackalarm   # the skill: the install command again
brew upgrade stackalarm                  # the CLI (or run install.sh again)
```

## Use

Open a project in your agent and call the skill by name (agents otherwise tend to answer with `npm audit` alone, which knows nothing of this week's runtime flaws):

```
/stackalarm
/stackalarm before the Friday deploy
/stackalarm are we affected by PHP2Shell?
```

The CLI also works on its own:

```sh
stackalarm news --tag php@8.3.20 --tag gitlab --since 7d
stackalarm news --tag npm --package next@15.1.0  # every known flaw of that version
stackalarm news --sbom image.cdx.json           # every known flaw of an image's packages
stackalarm cve CVE-2025-29927 next@15.1.0       # one CVE: affected, fixed, exploited?
stackalarm eol php@8.3.20 node@20            # still getting security fixes?
stackalarm sources                          # the sources and their tags
stackalarm news --help                      # every option
```

No install needed to look around: [stackalarm.dev/tech](https://stackalarm.dev/tech/) shows the security news of each technology over the last 30 days, with a feed per technology.

## Scheduled watch

Copy [`ci/github/stackalarm.yml`](ci/github/stackalarm.yml) to `.github/workflows/`, or include [`ci/gitlab/stackalarm.yml`](ci/gitlab/stackalarm.yml) in your GitLab CI. Every 4 hours, the CLI reads the `.stackalarm.yaml` profile the skill wrote and opens an issue when a heads-up, an alert or a security release is new. On GitHub, with an `ANTHROPIC_API_KEY` secret, Claude triages the news first and an issue is opened only when the project is concerned. A Slack or Mattermost webhook can get a line for each issue, and the profile can record the vulnerabilities you already judged (`ignore`), with a reason and a review date.

## Privacy

The CLI downloads public feeds and queries public APIs. It sends only what it is given: tags and keywords, as search terms to the CVE databases (NVD, EUVD), package names (with their version when given), to the GitHub Advisory Database and, when a version is given, to OSV.dev (`--no-osv` or `STACKALARM_NO_OSV=1` turns that off), the package names and versions of an SBOM passed with `--sbom`, to OSV.dev, and the ids of the CVEs found, to the FIRST EPSS API (and to the CVE Program, the NVD and GitHub with `stackalarm cve`). Nothing else about your project, and no telemetry.

## Contributing

Contributions go through **issues only**; pull requests are closed automatically. The most useful one is a new source: open a [New source](../../issues/new?template=new-source.yml) issue. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
