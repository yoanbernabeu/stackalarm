// Gathers the last 30 days of security news of every tag with the CLI of this
// repository, for the /tech/ pages: one JSON file per tag in .data/tech/.
//
//   node scripts/gather-tech.mjs            every tag
//   TECH_ONLY=php,node node scripts/gather-tech.mjs
//
// The NVD allows one request every 6 seconds without a key, and each tag
// costs one: the tags are read one after the other, paced accordingly. Set
// NVD_API_KEY to go about seven times faster, and GITHUB_TOKEN to lift the
// GitHub API cap.
import { execFile, execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const site = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(site, "..");
const out = resolve(site, ".data/tech");
const bin = resolve(site, ".data/bin/stackalarm");
export const days = 30;
const maxAffected = 3;

mkdirSync(out, { recursive: true });
mkdirSync(dirname(bin), { recursive: true });
execFileSync("go", ["build", "-o", bin, "./cmd/stackalarm"], { cwd: root, stdio: "inherit" });

const all = JSON.parse(execFileSync(bin, ["sources", "--format", "json"], { encoding: "utf8" })).tags.filter((t) => t !== "general");
const only = (process.env.TECH_ONLY ?? "").split(",").filter(Boolean);
const tags = only.length ? all.filter((t) => only.includes(t)) : all;
const pace = process.env.NVD_API_KEY ? 1000 : 6500;

const failed = [];
let last = 0;
for (const [i, tag] of tags.entries()) {
  const wait = last + pace - Date.now();
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  last = Date.now();
  try {
    const { stdout } = await run(bin, ["news", "--tag", tag, "--since", `${days}d`, "--format", "json"], {
      maxBuffer: 128 << 20,
      timeout: 10 * 60 * 1000,
    });
    const report = JSON.parse(stdout);
    const items = report.items.map((it) => ({
      title: it.title,
      url: it.url,
      published: it.published,
      stage: it.stage,
      source: it.source,
      language: it.language,
      score: it.score,
      epss: it.epss,
      exploited_in: it.exploited_in,
      public_exploit_in: it.public_exploit_in,
      also_in: it.also_in,
      affected: (it.affected ?? []).slice(0, maxAffected).map((a) => ({ package: a.package, versions: a.versions, fixed: a.fixed })),
      more_affected: Math.max(0, (it.affected ?? []).length - maxAffected),
    }));
    writeFileSync(
      resolve(out, `${tag}.json`),
      JSON.stringify({ tag, generated_at: report.generated_at, since: report.since, items, failures: report.failures, truncated: report.truncated }),
    );
    console.log(`${i + 1}/${tags.length} ${tag}: ${items.length} items, ${report.failures.length} failed sources`);
  } catch (err) {
    failed.push(tag);
    console.error(`${i + 1}/${tags.length} ${tag}: ${String(err.message ?? err).split("\n")[0]}`);
  }
}
writeFileSync(resolve(out, "_meta.json"), JSON.stringify({ generated_at: new Date().toISOString(), days, tags: tags.length, failed }));
if (failed.length > tags.length / 5) {
  console.error(`${failed.length} of ${tags.length} tags could not be gathered: not publishing this.`);
  process.exit(1);
}
