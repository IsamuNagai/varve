# Contributing

## Ground rules

1. **Specification first.** Consensus behaviour is defined in `protocol/` and in
   accepted ADRs before any code implements it.
2. **One decision per ADR.** Use `adr/0000-template.md`. Decisions are never
   reversed silently: a new ADR supersedes the old one and explains the new evidence.
3. **Consensus changes are small and labelled.** Never mix consensus-affecting
   changes with unrelated edits.
4. **No invented cryptography.** Use only standardized primitives with exact
   parameter sets and audited implementations.
5. **Evidence over opinion.** Cite primary sources (standards, papers, original
   specifications) with access dates. Label claims FACT, DESIGN DECISION,
   ASSUMPTION, or OPEN QUESTION where it matters.
6. **No price talk.** Issues and discussions are for engineering.

## Never commit

- Private keys, seeds, mnemonics, wallet files, API tokens, `.env` files.
- Personal information about anyone, including yourself (emails in text, names,
  locations, screenshots containing account details).
- Binary blobs without a reproducible source.

- Images with metadata (author, software, location, timestamps). Only clean PNG
  or SVG files are accepted.

Run `sh tools/check-no-secrets.sh` and `python3 -I tools/check-image-metadata.py`
before every commit. CI runs both.

## Website

The site in `docs/` is static and served by GitHub Pages from `main` / `/docs`.
Its pages are generated: edit `site/pages/*.html` (page content),
`site/journal/*.md` (journal posts) or `whitepaper/varve-whitepaper.md`, then run
`python3 -I tools/build-site.py` and `python3 -I tools/status.py`. CI fails if
`docs/` is out of date. The site loads nothing from other sites and every page
keeps its Content-Security-Policy. When `style.css`, `site.js` or
`theme-init.js` change, bump `ASSET_VERSION` in `tools/build-site.py`.

## Licensing of contributions

By contributing you agree that your contributions are dual-licensed under MIT
and Apache-2.0, as described in the README.
