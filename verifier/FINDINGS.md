# Findings from the independent verifier (2026-10-31)

`verifier/` was written from `protocol/*.md` and `test-vectors/*.json` only,
without reading the prototype or the vector generators. Against every vector
file it reports **0 mismatches** (329 checks; only `pow.json` is out of
scope). Writing it surfaced the specification gaps below. Severity: H = two
readings could disagree on validity; M = encoding or tooling; L = wording.

## Specification ambiguities

| ID | Sev | Where | Finding | Resolution |
| --- | --- | --- | --- | --- |
| A-01 | M | params.md | Entry order defined by code (`tools/params.py`); combined rows | Order is now the table order; row expansion and 35-entry count stated |
| A-02 | M | subsidy.md | FRAC values normative only via a generated vector file | Defining inequality is now the normative text |
| A-03 | H | encoding.md, transactions.md §3, blocks.md §4 | Which rules are parse errors vs validity failures was unstated (genesis breaks output rules but must parse) | encoding.md §1.5 lists the parse rules exactly; prototype aligned (witness path now rejected at parse time) |
| A-04 | L | blocks.md | Header `version` is a validity rule, not a parse rule | Covered by encoding.md §1.5 |
| A-05 | M | blocks.md §4 step 9 | "Coinbase position and uniqueness" undefined | Step 9 now states the exact shape rules |
| A-06 | M | blocks.md §2, step 10 | Coinbase weighed by length only was stated in transactions.md §9 alone | Stated in blocks.md §2 and step 10 |
| A-07 | M | transactions.md §6 | Lifecycle "per height range" with no ranges; four states, one unreachable | v1 lifecycle reduced to three states; genesis table and changes defined in upgrades.md |
| A-08 | L | transactions.md §8 | Path-1 state rule below the table | Lifecycle table rewritten with the rule inline |
| A-09 | L | transactions.md §3 | Count × minimum-size check per list or cumulative | Per list, as a parse error (encoding.md §1.5) |
| A-10 | L | blocks.md step 2 | "Exactly 116 bytes" overlaps steps 1 and 7 | Open (wording) |
| A-11 | L | blocks.md step 13 | Same-block outputs and forward references not stated | Step 13 now states both |
| A-12 | M | transactions.md §1 vs addresses.md | "Template" meant 36/74 bytes in one, 35/73 in the other | addresses.md now says "payload = template without `output_version`" |
| A-13 | L | genesis.md §2 | Sign-bit test wording; check order implicit | No validity impact; open (wording) |
| A-14 | M | genesis.md §2 | Genesis `prev_txid` unstated; exemption from validity rules unstated | Both now explicit |
| A-15 | L | difficulty.md §2 | Early returns never change the result | Informative; kept as optimizations |
| A-16 | L | blocks.md | No explicit header target range | Follows from `target = next_target`; open (wording) |
| A-17 | L | params.md, transactions.md | Constants duplicated | Open; params.md is authoritative |
| A-18 | L | protocol/README.md | Stale versions and generator names | README rewritten |
| A-19 | L | blocks.md §4 | "Reject at first failing step" implied order is consensus | Reworded: validity is order-independent; order is a SHOULD |

## Coverage gaps (mutation testing)

`mutation_check.py` breaks one rule at a time and reruns the vectors.
Initially 31 of 53 mutations survived. After adding vectors (ASERT negative
fractions, rounding sweep and both final clamps; even-window MTP; the 720,000 /
720,001 weight boundary; transaction version and count rules; unknown parent;
recovery scheme and delay bounds; same-block coinbase spend; trailing bytes;
`tx_count` 0; an independent Bitcoin powLimit anchor case), **13 survive**.
None is an untested reachable rule:

- **Equivalent:** the two ASERT early returns (A-15).
- **Unreachable in chain vectors:** coinbase height ≥ 2^32 (prev_index mod
  2^32, locktime = height >> 32).
- **Redundant by construction**, i.e. always caught by another rule: amount,
  output-sum and input-sum caps (no input can exceed `MAX_MONEY`); zero-input
  transactions (every output is ≥ 1, so the fee would be negative); the raw
  size bound (weight ≥ bytes); coinbase input count, coinbase shape, zero
  `prev_txid` outside the coinbase, and duplicate txids (each masked by the
  coinbase height encoding or by double-spend rules). They stay as
  defence in depth.

## Not reproduced

The report noted `sighash.spent_outputs` as 10-byte placeholders. On
checking, they are full serialized outputs (44 and 82 bytes).
