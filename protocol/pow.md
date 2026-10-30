# Proof of work (normative, draft v0.2)

## 1. Algorithm

`POW(key, input)` is **RandomX v2** as defined by the reference implementation
`tevador/RandomX` release v2.0.1 (or a later release producing identical
hashes) and its specification `doc/specs.md`, with exactly one configuration
change:

| Parameter | Monero default | Varve |
| --- | --- | --- |
| `RANDOMX_ARGON_SALT` | `"RandomX\x03"` | `"VarveRX\x01"` (8 bytes: `56 61 72 76 65 52 58 01`) |

Every other parameter keeps the RandomX v2 default, including
`RANDOMX_PROGRAM_SIZE = 384`. The RandomX documentation recommends a unique
salt per project, to prevent hashrate-rental attacks and pool redirection.

Implementations MUST produce bit-identical outputs in every mode: light,
fast, interpreter, JIT, software AES, and hardware AES.

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

`test-vectors/pow.json` lists hashes for fixed keys and inputs. They were
produced with `tools/pow_vectors.c` against `tevador/RandomX` commit
`ff6daa17fde3bb9032bbad15db16cad908deaee0`, using `RANDOMX_FLAG_V2` and the Varve
salt. The unmodified build at that commit passes the RandomX test suite. The portable interpreter and the JIT with hardware AES were cross-checked
and give identical results. The same program built with the default salt gives
different hashes, confirming the salt change takes effect.
