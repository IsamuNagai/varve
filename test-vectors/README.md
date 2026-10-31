# Test vectors

| File | Covers | Produced by | Checked in CI by |
| --- | --- | --- | --- |
| `params.json` | canonical constants, `params_hash` | `tools/params.py` | hygiene: regenerate + diff |
| `subsidy.json` | subsidy schedule | `simulations/subsidy.py` | hygiene: regenerate + diff; prototype tests |
| `difficulty.json` | ASERT targets | `tools/gen_vectors.py` | hygiene: regenerate + diff; prototype tests |
| `addresses.json` | commitments, Bech32m addresses | `tools/gen_vectors.py` | hygiene: regenerate + diff |
| `genesis.json` | Bitcoin compact nBits decoding; six-header anchor validation (valid: Bitcoin blocks 0–5 as a fixture; invalid: linkage, nBits, PoW, compact encoding, period boundary); example genesis | `tools/gen_genesis_vectors.py` | hygiene: regenerate + diff; prototype tests (plus all 480 single-byte mutations rejected) |
| `consensus.json` | transaction parsing (valid and malformed), txid, wtxid, weight, sighash, Merkle roots (1–17 leaves), header serialization and block id, chainwork | `tools/gen_consensus_vectors.py` | hygiene: regenerate + diff; prototype tests; parser fuzzing |
| `chain.json` | 42 block-validity cases on a 295-block regtest chain: header rules, coinbase rules, maturity and recovery-delay boundaries, signatures, value rules, locktime, double spends, same-block spends | `tools/gen_consensus_vectors.py --signed` (once) | crypto (x86_64 + ARM64): replay with real liboqs |
| `signatures.json` | ML-DSA-65 and SLH-DSA-SHA2-128s verification (valid, corrupted, wrong message) | `tools/gen_consensus_vectors.py --signed` (once) | crypto: verify with real liboqs |
| `pow.json` | RandomX v2 + Varve salt, 4 keys × 16 inputs | `tools/pow_vectors.c` | crypto: pinned, patched build on x86_64 + ARM64, portable and JIT modes |

Notes:

- Signatures are randomized, so `chain.json` and `signatures.json` are
  generated once and verified, not regenerated. Only public keys appear; no
  secret key was ever written to disk.
- Proof of work is not checked in `chain.json`; RandomX is covered by `pow.json`.
- The Bitcoin headers in `genesis.json` and the example genesis are fixtures.
  The real anchor will be six Bitcoin blocks mined after the launch announcement.
- Every vector file is also checked by the independent implementation in
  `../verifier/`, written from the specification without reading the prototype.
- Byte patterns used as keys in `consensus.json` and `addresses.json` are not keys.
