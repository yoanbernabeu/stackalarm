// llms.txt (https://llmstxt.org): what stackalarm is, for language models, with links to the sources of truth.
import type { APIRoute } from "astro";
import { loadSources, stages } from "../lib/sources";

const repo = "https://github.com/yoanbernabeu/stackalarm";
const raw = "https://raw.githubusercontent.com/yoanbernabeu/stackalarm/main";

export const GET: APIRoute = () => {
  const sources = loadSources();
  const count = (s: string) => sources.filter((x) => x.stage === s).length;
  const body = `# stackalarm

> An agent skill and the Go CLI it relies on. Type /stackalarm in an AI coding agent (Claude Code, Codex, Cursor and others): the agent reads the project, gathers this week's security news from ${sources.length} sources with the CLI, and says what affects the repository, how urgent it is, and what to change. A scheduled watch runs the CLI in GitHub Actions or GitLab CI and opens an issue when new security news concerns the stack; on GitHub, with an Anthropic API key, Claude triages it first and an issue is opened only when the project is affected. Free and open source (MIT).

- The skill is the analyst: it reads manifests, lockfiles, Dockerfiles, CI files and git remotes, runs the CLI, completes it with a web search and the ecosystem's dependency audits (composer audit, npm audit, pip-audit, govulncheck), judges what applies, and offers fixes one at a time, after asking. It never pushes, deploys or touches a server.
- The CLI does no project analysis: it reads release feeds, vendor advisories, the GitHub Advisory Database, the NVD and EUVD CVE databases, CERTs (US, Europe, Canada, Japan), CISA KEV, exploit databases and the security press, filtered by technology tags.
- Every item has a stage: ${stages.map((s) => `${s} (${count(s)} sources)`).join(", ")}. A heads-up is a security release announced ahead, the most valuable signal.
- Sources that cannot be read are always reported. The CLI sends only what it is given: tags and keywords to the CVE databases (NVD, EUVD), package names to the GitHub Advisory Database; no telemetry.

Install: \`brew install yoanbernabeu/tap/stackalarm\` (or \`curl -sSL ${raw}/install.sh | sh\`), then \`npx skills add yoanbernabeu/stackalarm\`.

## Docs

- [README](${raw}/README.md): what it is, install, use, CLI options, scheduled watch, privacy
- [The skill](${raw}/skills/stackalarm/SKILL.md): the instructions the agent follows
- [GitHub Action](${raw}/action.yml): inputs and outputs of the scheduled watch
- [GitHub workflow to copy](${raw}/ci/github/stackalarm.yml)
- [GitLab CI job to include](${raw}/ci/gitlab/stackalarm.yml)

## Optional

- [Full text for language models](https://stackalarm.dev/llms-full.txt): the README and the skill in one file
- [Source code](${repo})
- [Releases](${repo}/releases)
- [Propose a new source](${repo}/issues/new?template=new-source.yml)
`;
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
};
