// The released version, as pinned in the GitHub workflow users copy (bumped at each release).
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export function latestTag(): string | undefined {
  const workflow = readFileSync(resolve(process.cwd(), "..", "ci/github/stackalarm.yml"), "utf8");
  return workflow.match(/yoanbernabeu\/stackalarm@v([\d.]+)/)?.[1];
}
