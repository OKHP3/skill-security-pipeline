# Skillz Shield website

The standalone public explanation, evidence, and integration surface for
[Skillz Shield](https://github.com/OKHP3/skillz-shield). Vite builds this React,
TypeScript, and Tailwind CSS application as static files for GitHub Pages at
`https://okhp3.github.io/skillz-shield/`.

## Run locally

Use Node.js 24 (or another compatible version declared in `package.json`):

```text
cd site
npm ci
npm run dev
```

The development URL includes `/skillz-shield/`. Validate with:

```text
npm test
npm run build
```

The build includes TypeScript checking and writes `site/dist/`. `npm run preview`
serves that production output. The exact dependency graph lives in
`package-lock.json`.

## Evidence boundary

The page fetches `public/data/evidence.json` under Vite's configured base path.
The repository's publisher generates that file from verified full-scan reports;
do not hand-edit it to improve a displayed result. No scan runs in the browser.
There are no uploads, browser credentials, analytics, or application server.
Google Fonts supplies the shared OverKill Hill typefaces, with local fallbacks.

The frontend checks the evidence schema, source consistency, known engines,
immutable identities, inventory coverage, and finding totals before displaying
it. Missing or incompatible evidence remains unavailable. A failed refresh, a
different source revision, or an observed scan older than eight days is labeled
historical. This freshness cue does not replace the scan date or source SHA.

The published Shield release and the consumer's current pin are displayed
separately from the historical control pin and scanner versions used by the
recorded scan. Installation copies a complete read-only starter workflow pinned
to the published release. If the clipboard is unavailable, a selected text field
provides a manual copy path.

## Design provenance

The styling adapts the MIT-licensed `OKHP3/skillz` Forge design: Alfa Slab One
headlines, DM Sans body, JetBrains Mono labels, OverKill Hill palette, copper
rules, compact square corners, navigation, and footer patterns. The default
palette is inverted from the published light Forge: espresso backgrounds,
warm-paper text, teal structural panels, and amber actions. The inspection sheet
uses a restrained paper surface. The Shield illustration is local SVG.

Navigation uses native fragment links and landmarks. Menus expose expanded
state, Escape returns focus, the page includes a skip link and visible focus
styles, and reduced-motion preferences disable smooth scrolling. Expandable
engine pins use native details/summary controls. The page supports narrow screens
without hiding the evidence or replacing it with decorative status claims.
