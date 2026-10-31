# Varve independent verifier

A second implementation of the Varve consensus rules, written by a separate AI
agent from `protocol/*.md` and `test-vectors/*.json` only. Its purpose is to expose
ambiguities in the specification and disagreements between the specification
and the vectors. Python 3 standard library plus ctypes (liboqs) only.

**Isolation rule.** Nothing under `prototype/`, `tools/`, `simulations/` or
`node/` was read, imported or searched, and no vector-generation code was
consulted.
Where the spec was ambiguous the code implements the most natural reading and
the issue is tagged `SPEC-AMBIGUITY (A-nn)` in the code and listed in `FINDINGS.md`.

Files:

- `varve_verify.py` - the library (encoding, transactions, sighash, blocks,
  Merkle root, subsidy, anchored ASERT, MTP, chainwork, genesis, params hash,
  addresses, scheme lifecycle table, full block validation with a UTXO set,
  including shared authorization, path 2). Proof of work is not checked.
  `ChainState(..., lifecycle=...)` takes a lifecycle table; the default is the
  genesis table (both schemes ACTIVE).
- `run_vectors.py` - checks the library against every consensus vector file
  present. `pow.json` and `wallet.json` are reported as skipped (out of scope).
- `selftest.py` - extra cases for rules the vectors skip, including path 2
  and lifecycle transitions, with real signatures.
- `mutation_check.py` - breaks one rule at a time and reports which breaks
  the vectors fail to detect, then whether `selftest.py` detects them.

Run:

    VARVE_LIBOQS=/path/to/liboqs.so python3 -I verifier/run_vectors.py

Without `VARVE_LIBOQS`, signature-dependent checks are reported as skipped.
Exit status is 1 on any mismatch. Optional:

    VARVE_LIBOQS=... python3 -I verifier/selftest.py
    VARVE_LIBOQS=... python3 -I verifier/mutation_check.py    # a few minutes

Without `VARVE_LIBOQS`, `selftest.py` still runs, using random keys and
signatures of the correct lengths. Signature checks are skipped and the run
says so.

If liboqs was built only as a static archive (built with position-independent
code), a shared object can be linked from it:

    gcc -shared -o /tmp/liboqs.so -Wl,--whole-archive /path/to/liboqs.a -Wl,--no-whole-archive
