# Independent review, 2026-10-31: resolution record

An independent reviewer, who asked to remain anonymous, reviewed commit
`f207836`. This file records each finding and what was done. The review is
informal: it does not replace the public, named security review that must
happen before any release candidate (roadmap phase 8).

Findings are paraphrased. Status: **Fixed**, **Partly fixed** (what remains is
stated), **Deferred** (deliberately out of v1, with reason), **Open**.

## Critical and high

| ID | Finding | Status | Resolution |
| --- | --- | --- | --- |
| C-01 | A work "gate" could override greatest-cumulative-work chain selection | Fixed | blocks.md §6: any header chain with more verified work than the active tip MUST be downloaded and validated; limits apply only to chains known to have less work. Prototype `sync_action` + tests |
| H-01 | RandomX cache rule was circular (caches gated on already-verified work) | Fixed | Caches are budgeted (slots, rate limits, queue), never gated on verified work; built after cheap header checks (blocks.md §6, p2p.md §9) |
| H-02 | Chainwork arithmetic width unspecified | Fixed | Chainwork is an unbounded integer; other counters have fixed widths and checked sums (blocks.md §5); vectors in `consensus.json` |
| H-03 | Real post-quantum signature tests skipped in CI | Fixed | `crypto` workflow builds pinned liboqs on x86_64 and ARM64 and fails if any signature test is skipped |
| H-04 | Proof of work not verified by CI | Fixed | `crypto` workflow builds pinned, patched RandomX and checks all 64 vectors (portable and JIT) on both architectures |
| H-05 | RandomX customization not reproducibly vendored | Fixed | Pinned commit, checksummed patch, build script (`tools/randomx/`) |
| H-06 | Genesis validation not implemented or tested | Fixed | Exact Bitcoin-compatible nBits decoding and six-header anchor check in the prototype; `genesis.json` with Bitcoin blocks 0–5 as a fixture, invalid linkage / nBits / PoW / compact / period / powLimit cases, all 480 single-byte mutations rejected (genesis.md v0.3) |
| H-07 | Consensus vector coverage too narrow | Fixed | `consensus.json` (parsing incl. malformed, txid, wtxid, weight, sighash, Merkle, headers, chainwork), `chain.json` (59 block-validity cases with real signatures), `signatures.json`, parser fuzzing in CI; an independent implementation written only from the spec (`verifier/`) agrees on every vector, and its mutation testing drove further vectors (`verifier/FINDINGS.md`) |
| H-08 | Emergency migration (commit–delay–reveal) is a sketch, yet presented as a lifecycle state | Deferred | Removed from v1: lifecycle is ACTIVE / NO_NEW_OUTPUTS / DISABLED (transactions.md §6). ADR-0009 marked DEFERRED with the full list of missing pieces; whitepaper, README and threat register no longer rely on it |

## Medium

| ID | Finding | Status | Resolution |
| --- | --- | --- | --- |
| M-01 | Soft-fork / lifecycle activation underspecified | Fixed (draft) | New `protocol/upgrades.md`: tightening vs loosening, height activation fixed in releases, lead times, reorg behaviour, upgrade documents and hashes. Also corrected an error found while writing it: adding a scheme or policy is a hard fork under v1 rules, not a soft fork |
| M-02 | Recovery path is an alternate owner, not revocation | Fixed (docs) | transactions.md §8.1 states the trust model; README, site and threat register updated; two-stage recovery recorded as open question Q-14 |
| M-03 | ~130-character Bech32m recovery addresses risk interoperability | Open | Recorded in addresses.md and as Q-13; must be tested before the address format is frozen |
| M-04 | Status drift between whitepaper, site and README | Fixed | `registers/status.json` generates both roadmaps (`tools/status.py`, checked in CI); whitepaper monetary section updated to the decided numbers |
| M-05 | Difficulty ADR quoted the effect for the wrong tau | Fixed | ADR-0005 now uses tau = 6 h and separates the one-time offset (≈1.94%) from the steady-state effect |
| M-06 | capacity.py used stale benchmark numbers | Fixed | capacity.py reads the committed benchmark file; results regenerated and checked in CI; ADR-0006 figures updated |
| M-07 | RandomX reference wording too loose | Fixed | pow.md pins one source commit; vectors on two architectures; RISC-V required before RC |
| M-08 | Main branch unprotected; commits unsigned | Partly fixed | `.github/CODEOWNERS` added. Branch protection (no force pushes or deletion, required checks) needs the repository owner to enable it in GitHub settings. Signed commits and signed release manifests are deferred to release engineering, where a key-custody plan for a pseudonymous maintainer will be defined |
| M-09 | No normative P2P specification | Fixed (draft) | `protocol/p2p.md` v0.2, consistent with blocks.md §5–6 |
| M-10 | Wallet key and backup format unresolved | Partly fixed | `protocol/wallet.md` v0.1 draft (seed words, separate recovery seed, SHAKE256 derivation, gap limit, watch-only). Needs wallet and hardware review and vectors |

## Low

| ID | Finding | Status | Resolution |
| --- | --- | --- | --- |
| L-01 | `assert` used for liboqs return codes | Fixed | Explicit `RuntimeError` |
| L-02 | liboqs handles not freed | Fixed | `close()` and context manager |
| L-03 | Secret scanner incomplete | Fixed | Scans exactly the files git would commit, including binary files, NUL-safe; `--history` scans all commits and commit identities (run in CI); regex patterns are self-checked so a broken pattern can no longer pass silently (a real bug of this kind was found and fixed). GitHub secret scanning should also be enabled by the owner |
| L-04 | Website status hand-maintained | Fixed | Generated from `registers/status.json` (see M-04) |
