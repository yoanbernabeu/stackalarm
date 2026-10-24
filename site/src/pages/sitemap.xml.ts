import type { APIRoute } from "astro";

const pages = [
  "/",
  "/docs/",
  "/docs/skill/",
  "/docs/cli/",
  "/docs/watch/",
  "/docs/sources/",
  "/docs/privacy/",
  "/llms.txt",
  "/llms-full.txt",
];

export const GET: APIRoute = ({ site }) =>
  new Response(
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${pages.map((p) => `  <url><loc>${new URL(p, site)}</loc></url>`).join("\n")}
</urlset>
`,
    { headers: { "Content-Type": "application/xml; charset=utf-8" } },
  );
