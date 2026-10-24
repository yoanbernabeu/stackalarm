// Reads the bundled sources at build time, so the site always matches sources/.
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parse } from "yaml";

export type Source = { id: string; name: string; stage: string; tags: string[] };

export const stages = ["heads-up", "release", "advisory", "alert", "news"] as const;

export function loadSources(): Source[] {
  const dir = resolve(process.cwd(), "..", "sources");
  return readdirSync(dir)
    .filter((f) => f.endsWith(".yaml") && f !== "search.yaml") // search.yaml tunes the CVE searches, it is not a source
    .map((f) => {
      const s = parse(readFileSync(join(dir, f), "utf8"));
      return { id: f.replace(/\.yaml$/, ""), name: s.name, stage: s.stage, tags: s.tags ?? [] };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}
