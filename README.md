# Varve

Varve is a research-stage, open-source proof-of-work monetary protocol designed
for very long time horizons: post-quantum ownership from genesis, cryptographic
agility, native recovery primitives, predictable issuance, and verification that
ordinary people can run.

> **Status: specification phase.** No network exists. No coin exists.
> There will never be a presale, ICO, premine, founder allocation, or airdrop.
> Anyone selling "Varve" or "VARV" today is running a scam.

## What is here

| Path | Contents |
| --- | --- |
| `adr/` | Architecture Decision Records: one protocol decision per file |
| `registers/` | Decision register, research register, threat model, open questions |
| `protocol/` | Normative specification drafts (consensus rules only) |
| `whitepaper/` | Draft whitepaper |
| `simulations/` | Reproducible models (issuance, later difficulty and propagation) |
| `tools/` | Repository hygiene tools (secret scanning) |
| `docs/` | Project website (served by GitHub Pages) |

The specification, not any implementation, is the authority. Reference code
starts only after the specification is coherent enough to implement.

## Design direction (not final)

- UTXO ledger with typed outputs: `(output_version, scheme_id, commitment)`
- ML-DSA-65 (FIPS 204) for everyday authorization, behind a 32-byte hash commitment
- SLH-DSA-SHA2-128s (FIPS 205) as an independent recovery family
- A defined algorithm lifecycle, so signature schemes can be added or retired by soft fork
- Proof of work: RandomX v2 is the working candidate (see ADR-0003)
- Smooth issuance (8-year half-life) followed by a small permanent tail
- Block-height timelocks and timelocked recovery paths; no general smart-contract VM
- Fair launch: genesis is derived from a future Bitcoin block header, so no one
  can mine before anyone else

Website: https://isamunagai.github.io/varve/

Units: 1 varve = 100,000,000 laminae. Ticker: VARV.

## Contributing

Read `CONTRIBUTING.md`. Review of the ADRs and the specification is the most
valuable contribution right now. Security issues: see `SECURITY.md`.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.

---

The whitepaper is written under the pen name Isamu Nagai. It does not refer to
any real person; the protocol is meant to matter more than its author.
