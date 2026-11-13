// The Atom feed of a technology page: the same items, for a feed reader.
import type { APIRoute } from "astro";
import { affectedText, days, loadTech, safeURL, type Tech } from "../../../lib/tech";

export function getStaticPaths() {
  return loadTech().map((tech) => ({ params: { tag: tech.tag }, props: { tech } }));
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export const GET: APIRoute = ({ props, site }) => {
  const { tag, items, generatedAt } = props.tech as Tech;
  const page = new URL(`/tech/${tag}/`, site).href;
  const updated = items[0]?.published ?? generatedAt ?? new Date(0).toISOString();
  const entries = items.map((it, i) => {
    const facts = [
      it.exploited_in?.length ? `Exploited in the wild (${it.exploited_in.join(", ")}).` : "",
      it.public_exploit_in?.length ? `Public exploit (${it.public_exploit_in.join(", ")}).` : "",
      it.affected.length ? `Affects ${it.affected.map(affectedText).join("; ")}.` : "",
      `Source: ${it.source}.`,
    ].filter(Boolean);
    const link = safeURL(it.url);
    return `  <entry>
    <id>${esc(link ?? `${page}#${i}-${it.published}`)}</id>
    <title>${esc(`[${it.stage}] ${it.title}`)}</title>
    <updated>${esc(it.published)}</updated>
    ${link ? `<link href="${esc(link)}" />` : ""}
    <category term="${esc(it.stage)}" />
    <summary>${esc(facts.join(" "))}</summary>
  </entry>`;
  });
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${page}</id>
  <title>${esc(tag)} security news, by stackalarm</title>
  <subtitle>Announced releases, fixes, advisories and alerts about ${esc(tag)} over the last ${days} days.</subtitle>
  <link href="${page}" />
  <link rel="self" href="${page}feed.xml" />
  <updated>${esc(updated)}</updated>
  <author><name>stackalarm</name></author>
${entries.join("\n")}
</feed>
`,
    { headers: { "Content-Type": "application/atom+xml; charset=utf-8" } },
  );
};
