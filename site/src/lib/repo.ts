// Everything the docs state about the CLI, the action and the CI files is read
// from the repository at build time, so the docs cannot drift from the code.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";

export const repo = "https://github.com/yoanbernabeu/stackalarm";
export const raw = "https://raw.githubusercontent.com/yoanbernabeu/stackalarm/main";

const root = resolve(process.cwd(), "..");
export const readRepoFile = (path: string) => readFileSync(resolve(root, path), "utf8");

// The help of a CLI command, as the code prints it (needs Go at build time).
export function cliHelp(...args: string[]): string {
  return execFileSync("go", ["run", "./cmd/stackalarm", ...args, "--help"], { cwd: root, encoding: "utf8" }).trim();
}

type ActionField = { name: string; description: string; default?: string };

export function actionSpec(): { inputs: ActionField[]; outputs: ActionField[]; allowedTools: string[] } {
  const action = parse(readRepoFile("action.yml"));
  const fields = (o: Record<string, { description: string; default?: string }>) =>
    Object.entries(o).map(([name, f]) => ({ name, description: f.description, default: f.default }));
  const triage = action.runs.steps.find((s: { id?: string }) => s.id === "triage");
  const tools = String(triage.with.claude_args).match(/--allowedTools "([^"]+)"/)?.[1] ?? "";
  return { inputs: fields(action.inputs), outputs: fields(action.outputs), allowedTools: tools.split(",") };
}

// A CI file without its leading comment block.
export function ciFile(path: string): string {
  return readRepoFile(path)
    .split("\n")
    .filter((line) => !line.startsWith("#"))
    .join("\n")
    .trim();
}

export function gitlabVariables(): Record<string, string> {
  return parse(readRepoFile("ci/gitlab/stackalarm.yml")).stackalarm.variables;
}
