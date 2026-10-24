# Site design

The direction of the stackalarm site, and the reason behind each choice.

**Direction:** a calm watch. A full-screen soft painting behind a large headline, then dark, quiet sections that show the product working: the answer, the CLI output, the CI files.

Dial: ENERGY 2 / RHYTHM 2 / MOTION 2

- **Theme.** Dark only (`#0B0E14`): a developer tool, and the hero's sea fades into it.
- **Palette.** Night (`#0B0E14`, `#121722`), bone text (`#ECEBE6`), one warm accent: beacon orange (`#FF8A4C`), the lighthouse lamp in the hero image. It marks the primary action and the `heads-up` stage. Red (`#FF6B5E`) is kept for urgency only: `alert`, "Act now".
- **Type.** Bricolage Grotesque for the text: a grotesque with character that holds at 6rem in the headline and stays readable at body size. IBM Plex Mono for commands and real CLI output; its zero and capital O differ, which matters in versions.
- **Motif.** The five stages as the CLI prints them (`heads-up`, `release`, `advisory`, `alert`, `news`), in mono, lowercase. They structure the "Why" timeline, the source list and the sample answer.
- **Glass.** Two elements only, both over the hero image: the Install pill in the nav and the install command.
- **Motion.** Two light movements, both once and both off under `prefers-reduced-motion`: the hero image settles in (the page arrives with the light already on), and the sections below rise in as they enter the screen (to pace the reading). Only `transform` and `opacity` move, and the headline never does, so Lighthouse's layout shift and largest paint are untouched.
- **Content.** Only what the code backs. The landing sells; the docs (`/docs/`) are the reference. Everything that can be is read from the repository at build time (`src/lib/repo.ts`, `src/lib/sources.ts`): the sources and tags, the CLI's own `--help` (so the build needs Go), the action's inputs, outputs and allowed tools, the CI files and GitLab variables. Prose claims are checked against the code before they ship.

## The hero image

`public/hero.webp`. Without it, the hero falls back to a plain night gradient.

Why this scene: the product keeps watch and warns before trouble reaches the project. A lighthouse at dawn says it calmly: the light is on, the sea is quiet. Its lamp is the orange accent of the whole page.

The sky is bright, so the headline and the lead are dark ink on a light wash, and the image is darkened only at the top (nav) and the bottom (where it meets the page). The note under the command has its own dark backing, since it lands on sky or sea depending on the width. Worst-pixel contrast measured under each line of text: headline 4.45:1 on desktop, 3.82:1 at 390px (large text, AA 3:1); lead 8.08:1 and 5.30:1. Measure again after changing the image or the scrim.

Prompt used for generation (16:9):

> Soft painterly illustration, 16:9. Blue hour just before dawn over a calm sea. A small white lighthouse on a low rocky point in the right third of the frame, its lamp glowing warm orange, a gentle beam sweeping across light mist. Far on the horizon, a thin line of distant clouds catches the first pale light. Muted palette of slate blue, dusty lavender and soft peach, the only saturated colour is the warm lamp. Smooth gradients, gentle brush texture, quiet and peaceful mood. The centre and upper half are open, softly graded sky with little detail, leaving room for a large headline; the bottom edge fades into deep navy. No text, no letters, no logos, no interface.

## Search and language models

- The page carries a canonical URL, Open Graph and Twitter cards, and a `SoftwareApplication` JSON-LD block (version read from `ci/github/stackalarm.yml`).
- `public/og.png` is rendered from `og/card.html` with headless Chrome: `npm run og`. Regenerate it when the headline or the hero image changes.
- `/llms.txt` follows llmstxt.org and links to the raw README, skill, action and CI files; `/llms-full.txt` holds the README and the skill in one file. Both are built from the repository, like the source count.
- `robots.txt` lets every crawler in, AI ones included, and points to `sitemap.xml`.
- Published by `.github/workflows/site.yml` to GitHub Pages, on the domain in `public/CNAME`.
- Icon: the `/` of `/stackalarm` in the lamp orange on night (`public/favicon.svg`), readable at 16px. `favicon.ico`, `apple-touch-icon.png` and the PWA icons are rendered from the same drawing; the Apple and PWA ones are full-bleed because those platforms round the corners themselves.
