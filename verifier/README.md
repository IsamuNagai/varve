# Varve independent verifier

A second implementation of the Varve consensus rules, written by a separate AI
agent from `protocol/*.md` and `test-vectors/*.json` only. Its purpose is to expose
ambiguities in the specification and disagreements between the specification
and the vectors. Python 3 standard library plus ctypes (liboqs) only.

**Isolation rule.** Nothing under `prototype/`, `tools/` or `simulations/` was
read, imported or searched, and no vector-generation code was consulted.
Where the spec was ambiguous the code implements the most natural reading and
the issue is tagged `SPEC-AMBIGUITY (A-nn)` in the code and listed in `FINDINGS.md`.

Files:

- `varve_verify.py` - the library (encoding, transactions, sighash, blocks,
  Merkle root, subsidy, ASERT, MTP, chainwork, genesis, params hash,
  addresses, full block validation with a UTXO set). Proof of work is not
  checked.
- `run_vectors.py` - checks the library against every vector file present.
- `selftest.py` - extra cases with real signatures for rules the vectors skip.
- `mutation_check.py` - breaks one rule at a time and reports which breaks
  the vectors fail to detect.

Run:

    VARVE_LIBOQS=/path/to/liboqs.so python3 -I verifier/run_vectors.py

Without `VARVE_LIBOQS`, signature-dependent checks are reported as skipped.
Exit status is 1 on any mismatch. Optional:

    VARVE_LIBOQS=... python3 -I verifier/selftest.py
    VARVE_LIBOQS=... python3 -I verifier/mutation_check.py
