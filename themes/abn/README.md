# okf-wiki theme: abn.is

An [okf-wiki](https://github.com/abn/okf-wiki) theme that skins the wiki
renderer in abn.is's own brand — violet + intersex-yellow, IBM Plex Sans body
text, IBM Plex Mono / JetBrains Mono display and code, light/dark via
`prefers-color-scheme` with a manual toggle. It's the theme directory used for
every personal, branded wiki instance for Arun's projects (okf-wiki calls this
a bundle's rendered docs site) — mounted or pointed at via `--theme` /
`OKF_WIKI_THEME`, never copied into those projects' own repos.

It lives here, in `abn.is`, rather than in the `okf-wiki` project itself,
because upstream's own [ADR on runtime themes](https://github.com/abn/okf-wiki/blob/main/docs/adr/0003-runtime-themes.md)
says so explicitly: *"The abn.is theme lives outside this repository. It is
brand-specific and is not published here."* okf-wiki resolves a theme from a
directory at render time (a `--theme DIR` flag, layered over the theme
compiled into the binary) rather than compiling brands in, so keeping this
theme in the `abn.is` repo — beside the design tokens it's built on — is the
natural home, not a workaround.

## What a theme is, briefly

okf-wiki's theme system (full contract:
[`docs/reference/themes.md`](https://github.com/abn/okf-wiki/blob/main/docs/reference/themes.md)
in that repo) resolves one directory over an embedded default:

- `theme.json` is the manifest — name, version, description, the `template`
  path, named `slots`, and an `assets` map keyed by output filename, each
  entry `inherit` (take the default's file — also the behaviour for any key
  the manifest omits), `replace` (use this theme's file), or `drop` (emit
  nothing for that key).
- Three sizes exist, cheapest first: **recolour** (just `tokens.css`),
  **reskin** (+ fonts, marks, and token overrides — keep the default's
  `template.html` and `wiki.css`), **relayout** (replace `template.html` too,
  which means taking on the DOM contract yourself — the ids `search.js` and
  the inline drawer/theme-toggle scripts require, and the classes the Go
  renderer and both client scripts write).

This theme is a **reskin**: it inherits `template.html`, `wiki.css`,
`search.js`, and `diagrams.js` from the upstream default theme, keeping full
compatibility with okf-wiki's 3-column layout, sticky table-of-contents
column, responsive drawer, breadcrumb dropdown, scroll-spy, and lightbox.
It replaces only the brand visual identity: design tokens, custom typography
(`fonts.css` and font assets), and the brand mark and favicon.

## Layout and provenance

| Path | Role | Where it comes from |
| :--- | :--- | :--- |
| `theme.json` | manifest | hand-written for this theme |
| `assets/tokens.css` | design tokens | vendored from this repo's `public/tokens.css` with trailing adapter mappings for okf-wiki default CSS hooks |
| `assets/fonts.css` | `@font-face` rules | copied verbatim from this repo's `public/fonts.css` |
| `assets/fonts/` | the woff2 files themselves | copied verbatim from this repo's `public/fonts/` (IBM Plex Mono, IBM Plex Sans, JetBrains Mono) |
| `assets/brand-mark.svg`, `assets/favicon.svg` | header mark, browser icon | the abn. mark — same SVG as this repo's `public/favicon.svg` |

The structural shell (`template.html`), layout stylesheet (`wiki.css`),
search modal (`search.js`), and diagram runtime (`diagrams.js`) are inherited
from the base okf-wiki binary.

## How it's used

Every mechanism okf-wiki offers for pointing at an external theme applies
here; this directory is just the argument.

**CLI**, rendering some other project's `docs/` bundle:

```bash
okf-wiki render --content ./docs --out ./public \
  --theme /path/to/abn.is/.contrib/themes/okf-wiki
```

**Container**, as a read-only bind mount plus `OKF_WIKI_THEME`:

```bash
podman run --rm -p 8080:8080 \
  -v "$(pwd)/docs:/content:ro,Z" \
  -v "/path/to/abn.is/.contrib/themes/okf-wiki:/theme:ro,Z" \
  -e OKF_WIKI_THEME=/theme \
  ghcr.io/abn/okf-wiki:latest
```

**GitHub Action**, with `theme-ref` pulling this theme straight from this
repository into someone else's workflow:

```yaml
- uses: abn/okf-wiki/action@v1
  with:
    content: docs
    theme-ref: abn/abn.is@main:.contrib/themes/okf-wiki
    deploy: true
```

Every render writes a resolved `theme.json` beside the output pages,
recording the theme's name/version/description and whether an override was
applied — the fastest way to confirm a given site actually picked this theme
up.

## Keeping it aligned with abn.is's tokens

The user brief for this theme is to track this repo's brand, not to freeze a
snapshot of it:

1. **`tokens.css` — sync after any token change that matters to a wiki page.**
   Run `make tokens` in this repo (regenerates `public/tokens.css` from
   `src/styles/tokens.css`), then copy the result over `assets/tokens.css`
   here, preserving the trailing okf-wiki adapter block.
2. **`fonts.css` / `fonts/` — sync only when the font stack itself changes**
   (a new weight, a family swap, a subset change).

## Verifying a change before it ships

Render the target `docs/` bundle through this theme:

- The output's own `theme.json` records this theme was picked up.
- Open the search modal and type — exercises the index fetch, base path, and
  result styling together.
- Click a diagram, open the lightbox, pan it.
- Check both light and dark grounds.
- Tab through the page — the focus ring should be visible everywhere.
