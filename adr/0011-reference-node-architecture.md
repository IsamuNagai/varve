# ADR-0011: Reference node architecture

## Status
ACCEPTED for testnet (2026-10-31). Revisit before any release candidate.

## Context
The specification, prototype, and independent verifier exist. Mining needs a
real node: one that validates blocks, stores the chain, talks to peers, and
mines. ADR-0010 leans towards Rust.

## Decision
- **Language:** Rust (stable), with **no third-party Rust crates**. Everything
  above the C libraries uses the standard library only. This removes the
  largest supply-chain surface of a typical Rust node, at the cost of writing
  small pieces (JSON, HTTP for local RPC, big-integer arithmetic) ourselves.
- **Cryptography and proof of work via pinned C libraries, statically linked:**
  - liboqs at the commit already pinned for benchmarks and CI (ML-DSA-65,
    SLH-DSA-SHA2-128s, and its SHA3-256, SHAKE256 and SHA-256), so hashing,
    signatures and tests use one audited implementation;
  - RandomX at the commit pinned in pow.md, with the checked salt patch.
  `tools/build-deps.sh` fetches both at those exact commits, verifies them,
  and builds static libraries. The node binary is self-contained.
- **Layout:** `node/` is a Cargo workspace:
  - `varve-sys`: FFI bindings and safe wrappers;
  - `varve-consensus`: pure consensus rules, no I/O. It MUST pass every file in
    `test-vectors/`, which makes it the third implementation checked against
    the vectors (after the prototype and the spec-only verifier);
  - `varve` (binary): chain state and storage, P2P (protocol/p2p.md), mempool,
    miner, local JSON-RPC, wallet.
- **Arithmetic:** release builds keep integer overflow checks on; consensus
  code uses checked arithmetic explicitly regardless.
- **Storage:** append-only block files, a block index, and a UTXO set with
  per-block undo data for reorganizations. Simple and inspectable before fast.
- **Wallet:** minimal (addresses, balance, send), using the seeded derivation
  and encrypted file format of protocol/wallet.md (the same as the Strata
  wallet). The running node holds only public commitments; keys are decrypted
  only while a payment is signed. Strata (crates/strata) is the full wallet.

## Consequences
- Builds need git, CMake and a C/C++ compiler, and network access to GitHub
  for the two pinned sources (or a pre-built `VARVE_DEPS` directory).
- Linux and macOS first; Windows after the build is proven.
- A second, independent node implementation is still needed before mainnet
  (ADR-0010).
