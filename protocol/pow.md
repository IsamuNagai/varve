# Proof of work (normative, draft v0.3)

## 1. Algorithm

`POW(key, input)` is the **RandomX v2** algorithm as specified in
`doc/specs.md` of `tevador/RandomX` at commit
`ff6daa17fde3bb9032bbad15db16cad908deaee0` (algorithm version 2, selected with
`RANDOMX_FLAG_V2`). That document defines consensus, not any library version.
The configuration has exactly one change:

| Parameter | Monero default | Varve |
| --- | --- | --- |
| `RANDOMX_ARGON_SALT` | `"RandomX\x03"` | `"VarveRX\x01"` (8 bytes: `56 61 72 76 65 52 58 01`) |

Every other parameter keeps the RandomX v2 default, including
`RANDOMX_PROGRAM_SIZE = 384`. The RandomX documentation recommends a unique
salt per project, to prevent hashrate-rental attacks and pool redirection.

Implementations MUST produce bit-identical outputs in every mode: light,
fast, interpreter, JIT, software AES, and hardware AES.

**Reference build.** The reference build uses that exact commit plus
`tools/randomx/varve-salt.patch`, applied by `tools/randomx/build_and_check.sh`.
The script verifies the commit and the SHA-256 of the patched file before and
after patching, and the build fails on any difference. Moving to a different
upstream commit is a deliberate change: it needs a new review, regenerated
vectors, and green multi-architecture CI.

## 2. Input and comparison

- `input` = the 116-byte block header serialization (blocks.md §1).
- `pow_hash = POW(key(h), input)` is 32 bytes. It is read as a little-endian
  u256 and MUST be ≤ the header's `target`.

## 3. Key (seed) selection

RandomX uses a key to initialize its 256 MiB cache. The key changes
periodically, so precomputed datasets cannot be reused indefinitely.

    EPOCH = 2048 blocks (≈ 7.1 days)
    LAG   = 64 blocks   (≈ 5.3 hours)
    seed_height(h) = 0                                   if h ≤ EPOCH + LAG
                   = ((h − LAG − 1) / EPOCH) × EPOCH     otherwise   (integer division)
    key(h) = block_id(block at seed_height(h)) on the chain being validated   (32 bytes)

At height 0, the genesis block id is the key. The lag gives miners about 5
hours to build the new dataset before it is needed.

## 4. Cost (informative)

Verification in light mode needs the 256 MiB cache per key, plus a few
milliseconds per hash. Building a cache takes about one second, once per epoch.
Mining in fast mode uses about 2 GiB of dataset per key.

## 5. Test vectors

`test-vectors/pow.json` holds 64 vectors: 4 keys (including the empty key and a
long key) × 16 inputs of 116 bytes (all-zero, all-0xFF, a byte pattern, and 13
pseudo-random inputs). The CI workflow `crypto.yml` builds the pinned, patched
RandomX on **x86_64 and ARM64**. It checks every vector in portable mode
(interpreter, software AES) and in fast mode (JIT, hardware AES where
available). A mismatch blocks release. More architectures, notably RISC-V, are
needed before a release candidate.
