// The README and the skill in one plain-text file, read from the repository at build time.
import type { APIRoute } from "astro";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const read = (path: string) => readFileSync(resolve(process.cwd(), "..", path), "utf8").trim();

export const GET: APIRoute = () =>
  new Response(
    `${read("README.md")}

---

# The stackalarm skill (skills/stackalarm/SKILL.md)

${read("skills/stackalarm/SKILL.md")}
`,
    { headers: { "Content-Type": "text/plain; charset=utf-8" } },
  );
