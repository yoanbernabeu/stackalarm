// The news gathered for each tag by cmd/sitenews (npm run news), read at build
// time. Without the data (a local build that did not run it), the
// pages still list the sources of each tag and say the news is missing.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
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
export type TagNews = {
  tag: string;
  sources: Source[]; // its own sources, without the general ones
  gathered: boolean;
  generatedAt?: string;
  items: Item[]; // what its sources and the general ones say of it
  rest: Item[]; // the items that are not reported exploited
  failures: { source: string; error: string }[];
  exploited: Item[];
};

const dir = resolve(process.cwd(), ".data/news");

// The general sources read for every page: all but the CVE databases searched
// by word, which cmd/sitenews leaves out.
export const generalSources = () => loadSources().filter((s) => s.tags.includes("general") && !["nvd", "euvd-search"].includes(s.type));

export const days = 30;

// Links come from third-party feeds: only web links are rendered as links.
export const safeURL = (url?: string) => (url && /^https?:\/\//i.test(url) ? url : undefined);

export function meta(): { generated_at?: string; failed: string[] } {
  const file = resolve(dir, "_meta.json");
  return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : { failed: [] };
}

let cache: TagNews[] | undefined;

export function loadNews(): TagNews[] {
  if (cache) return cache;
  const sources = loadSources();
  const tags = [...new Set(sources.flatMap((s) => s.tags))].filter((t) => t !== "general").sort();
  cache = tags.map((tag) => {
    const file = resolve(dir, `${tag}.json`);
    const data = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : undefined;
    const items: Item[] = (data?.items ?? []).map((it: Item) => ({ ...it, affected: it.affected ?? [] }));
    const isExploited = (it: Item) => (it.exploited_in?.length ?? 0) > 0 || /exploited in the wild/i.test(it.title);
    return {
      tag,
      sources: sources.filter((s) => s.tags.includes(tag)),
      gathered: Boolean(data),
      generatedAt: data?.generated_at,
      items,
      failures: data?.failures ?? [],
      exploited: items.filter(isExploited),
      rest: items.filter((it) => !isExploited(it)),
    };
  });
  return cache;
}

export const day = (iso: string) => iso.slice(0, 10);

export function epss(p: number): string {
  return p < 0.1 ? `${(p * 100).toFixed(1)}%` : `${Math.round(p * 100)}%`;
}

export function affectedText(a: Affected): string {
  return `${a.package} ${a.versions || "all versions"} ${a.fixed ? `(fixed in ${a.fixed})` : "(no fix yet)"}`;
}
