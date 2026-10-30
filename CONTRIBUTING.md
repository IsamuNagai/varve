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

Run `tools/check-no-secrets.sh` before every commit. CI will run it as well.

## Licensing of contributions

By contributing you agree that your contributions are dual-licensed under MIT
and Apache-2.0, as described in the README.
