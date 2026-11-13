// The news gathered for each tag by scripts/gather-tech.mjs, read at build
// time. Without the data (a local build that did not run the script), the
// pages still list the sources of each tag and say the news is missing.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parse } from "yaml";
import { loadSources, type Source } from "./sources";

export type Affected = { package: string; versions: string; fixed?: string };
export type Item = {
  title: string;
  url?: string;
  published: string;
  stage: string;
  source: string;
  language?: string;
  score?: number;
  epss?: number;
  exploited_in?: string[];
  public_exploit_in?: string[];
  also_in?: string[];
  affected: Affected[];
  more_affected: number;
};
export type Tech = {
  tag: string;
  sources: Source[]; // its own sources, without the general ones
  gathered: boolean;
  generatedAt?: string;
  items: Item[]; // what its sources and the general ones say of it
  rest: Item[]; // the items that are not reported exploited
  mentions: Item[]; // CVE records that only match the word
  failures: { source: string; error: string }[];
  exploited: Item[];
};

const dir = resolve(process.cwd(), ".data/tech");
const search = parse(readFileSync(resolve(process.cwd(), "..", "sources/search.yaml"), "utf8"));
const databases = ["nvd", "euvd-search"];

export const days = 30;

// Links come from third-party feeds: only web links are rendered as links.
export const safeURL = (url?: string) => (url && /^https?:\/\//i.test(url) ? url : undefined);

export function meta(): { generated_at?: string; failed: string[] } {
  const file = resolve(dir, "_meta.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : { failed: [] };
}

let cache: Tech[] | undefined;

export function loadTech(): Tech[] {
  if (cache) return cache;
  const sources = loadSources();
  const tags = [...new Set(sources.flatMap((s) => s.tags))].filter((t) => t !== "general").sort();
  cache = tags.map((tag) => {
    const file = resolve(dir, `${tag}.json`);
    const data = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : undefined;
    const all: Item[] = data?.items ?? [];
    const own = new Set(sources.filter((s) => s.tags.includes(tag)).map((s) => s.id));
    // The CVE databases match on the word: "php" finds every plugin written in
    // PHP. A record is news of the technology when it names the product in its
    // ranges, was also published by one of its own sources, or, for a product
    // the NVD dictionary does not list here, starts with its name.
    const precise = (it: Item) =>
      !databases.includes(it.source) ||
      it.affected.some((a) => a.package.toLowerCase() === tag) ||
      (it.also_in ?? []).some((s) => own.has(s)) ||
      (!search.cpe?.[tag] && !search.skip?.includes(tag) && new RegExp(`^CVE-[\\d-]+( \\(EUVD-[\\d-]+\\))?( \\[[\\d.]+\\])?: ${escape(search.aliases?.[tag] ?? tag)}\\b`, "i").test(it.title));
    const items = all.filter(precise);
    const isExploited = (it: Item) => (it.exploited_in?.length ?? 0) > 0 || /exploited in the wild/i.test(it.title);
    return {
      tag,
      sources: sources.filter((s) => s.tags.includes(tag)),
      gathered: Boolean(data),
      generatedAt: data?.generated_at,
      items,
      mentions: all.filter((it) => !precise(it)),
      failures: data?.failures ?? [],
      exploited: items.filter(isExploited),
      rest: items.filter((it) => !isExploited(it)),
    };
  });
  return cache;
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const day = (iso: string) => iso.slice(0, 10);

export function epss(p: number): string {
  return p < 0.1 ? `${(p * 100).toFixed(1)}%` : `${Math.round(p * 100)}%`;
}

export function affectedText(a: Affected): string {
  return `${a.package} ${a.versions || "all versions"} ${a.fixed ? `(fixed in ${a.fixed})` : "(no fix yet)"}`;
}
