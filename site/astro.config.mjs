import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://stackalarm.dev",
  // Compression drops the spaces between inline tags at line ends ("check<code>").
  compressHTML: false,
});
