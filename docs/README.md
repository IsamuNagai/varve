# Varve site

Static site, no JavaScript, no external requests.

## Placeholder

Pages link to the repository using the literal text `https://github.com/IsamuNagai/varve`. Replace it everywhere with the repository base URL (no trailing slash).

## Serving

- GitHub Pages: Settings → Pages → Deploy from a branch → `main` / `/docs`.
- Any static host: serve the contents of this folder as-is.

## Pre-publish checklist

- [ ] Replace every `https://github.com/IsamuNagai/varve` placeholder.
- [ ] Confirm no external requests (browser network panel stays empty apart from this site).
- [ ] Keep the Content-Security-Policy meta tag on every page.
