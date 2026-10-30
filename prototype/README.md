# Consensus prototype (disposable)

A slow, readable Python transcription of `protocol/*.md`, used to find
specification ambiguities and to cross-check the test vectors. It is **not**
production code, is not audited, and must never hold real value.

- `varve_proto.py`: encoding, transactions, signature messages, Merkle root,
  subsidy, difficulty, genesis, and block validation in the order of blocks.md §4.
- `test_proto.py`: vector checks plus an end-to-end chain with real ML-DSA-65
  and SLH-DSA-SHA2-128s signatures.

Proof of work is replaced by a test-only stub in the tests. RandomX is checked
separately through `test-vectors/pow.json`.

Run the tests (signature tests need a liboqs shared library):

    VARVE_LIBOQS=/path/to/liboqs.so python3 -I prototype/test_proto.py

Without `VARVE_LIBOQS`, the signature tests are skipped and the rest still run.
