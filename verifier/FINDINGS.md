# Findings from the independent verifier (2026-10-31)

`verifier/` was written from `protocol/*.md` and `test-vectors/*.json` only,
without reading the prototype or the vector generators. It now follows
consensus draft v0.5 (anchored ASERT, witness path 2 and when it is
mandatory, well-formed lifecycle lists). Against every vector file it reports
**0 mismatches** (348 checks with liboqs, including all 70 `chain.json`
cases; `pow.json` and `wallet.json` are out of scope). Writing it surfaced the
specification gaps below: 26 in all, of which 4 are open (all L wording).
Severity: H = two readings could disagree on validity; M = encoding or
tooling; L = wording.

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
| A-20 | H | transactions.md §6 (para. after the state table), upgrades.md §4 | "The state of the last transition for that scheme with `from_height ≤ h`": last in list order, or greatest `from_height`? These differ for a table not sorted by height. Also unstated: whether a table that goes backwards (e.g. DISABLED then NO_NEW_OUTPUTS), lists equal heights, or names an unknown scheme is malformed | Resolved in transactions.md §6 (v0.5): the state is that of the transition with the greatest `from_height ≤ h`, and a list is well formed only if, per scheme, the scheme is known, `from_height` strictly increases in list order and states strictly move forward (ACTIVE never listed); nodes must refuse a malformed list. Verifier follows this and selftest refuses 11 malformed lists. One leftover: upgrades.md §4 still gives a genesis table that the new rule calls malformed (A-26) |
| A-21 | L | transactions.md §6, para. after the scheme table | "At genesis both schemes are ACTIVE, and no other state is used" can be read as ruling out NO_NEW_OUTPUTS and DISABLED, which the later paragraph allows by transition. The genesis sentence is also repeated | Resolved: the sentence now refers to the state table and lifecycle list |
| A-22 | M | transactions.md §3 (txid bullet), §8.2 | Third-party witness malleability: a signed path-0 input whose output key is already authorized by an earlier input can be replaced by anyone with a 3-byte path-2 entry. The txid is unchanged; wtxid, size and weight change, and the result is still valid (selftest shows it). §3's "no third-party malleability" holds for txids only, and neither section says so. This matters for relay and compact blocks, which use wtxids | Resolved in transactions.md §8.2 (v0.5): path 2 is mandatory where it applies, so a path-0 or path-1 witness on an input whose primary key was selected by an earlier path-0/1 input is invalid, and stripping a signature no longer yields a second valid form. The vectors now reject 0-then-0 and 1-then-0; selftest also rejects 0-2-0, 0-then-1 and 1-then-1. Mandatory path 2 never blocks a spend that was otherwise valid: path 2 then always passes (same scheme and state as the authorizer; maturity applies to both). §3's new wording claims slightly more than the rule gives (A-25) |
| A-23 | L | transactions.md §8.2 steps 3-4 | Step 3 (state of `o_i.scheme_id`) can never fail on its own: the authorizer selected the same scheme at the same height and passed §8 step 4. Matching on the scheme in step 4 is also implied by the commitment, which hashes `u16(scheme)` | Informative; kept as written. Mutation testing finds both equivalent |
| A-24 | L | protocol/README.md; difficulty.md §2 heading | The README lists transactions.md as v0.3 (file says v0.4) and difficulty.md as v0.2 (file says v0.3). The §2 heading still says "anchored at genesis", but the anchor time is now `t0 + ASERT_ANCHOR_DELAY` (the anchor height is still 0) | Resolved: the README lists transactions.md v0.5 and difficulty.md v0.3, matching the files, and the §2 heading now says "anchored at genesis + ASERT_ANCHOR_DELAY" |
| A-25 | L | transactions.md §3 (txid bullet) | "Each valid transaction also has exactly one valid witness layout" is too strong. It holds against third parties only. Key holders can still choose: for inputs spending (primary K3, recovery K1, delay met) and then (primary K1), both (path 0 by K3, path 0 by K1) and (path 1 by K1, path 2) are valid with the same txid (selftest shows it). Signatures are also randomized, so the signers can always produce a new wtxid. The rest of the sentence ("nobody but the signers can change its wtxid") is correct | Resolved: §3 now limits the claim to third parties and notes signers may choose |
| A-26 | M | upgrades.md §4 vs transactions.md §6 | upgrades.md §4 still says the lifecycle table at genesis is `[(0x0001, ACTIVE, 0), (0x0002, ACTIVE, 0)]`. transactions.md §6 (v0.5) says the genesis list is empty, that ACTIVE is never listed, and that a node MUST refuse to run with such a list. A node built from upgrades.md would refuse to start under transactions.md. Both tables give the same states, so block validity is the same | Resolved: upgrades.md §4 now says the genesis list is empty |
## Coverage gaps (mutation testing)

`mutation_check.py` breaks one rule at a time and reruns the vectors. Each
mutation the vectors miss is then run against `selftest.py`. Of 95 mutations
(53 earlier, 26 for v0.4, 16 for v0.5), **35 survive the vectors**.

The 13 earlier survivors are unchanged. None is an untested reachable rule:

- **Equivalent:** the two ASERT early returns (A-15).
- **Unreachable in chain vectors:** coinbase height ≥ 2^32 (prev_index mod
  2^32, locktime = height >> 32). selftest catches both.
- **Redundant by construction**, i.e. always caught by another rule: amount,
  output-sum and input-sum caps (no input can exceed `MAX_MONEY`); zero-input
  transactions (every output is ≥ 1, so the fee would be negative); the raw
  size bound (weight ≥ bytes); coinbase input count, coinbase shape, zero
  `prev_txid` outside the coinbase, and duplicate txids (each masked by the
  coinbase height encoding or by double-spend rules). They stay as
  defence in depth.

Of the 26 v0.4 mutations, the vectors now catch 15. The new vector "path 2
spending an immature coinbase" closes the maturity gap reported earlier.
These 11 survive:

- **Equivalent (A-23):** path 2 matched on commitment only; path 2 without
  its own lifecycle check.
- **Vector gap (selftest catches it):** path 2 matched on **scheme only**.
  The vector "path 2 for an output under a different key" also uses a
  different scheme. It needs a same-scheme, different-key case.
- **Not expressible in the vectors (selftest catches all 8):** every lifecycle
  rule. The table is ignored (always ACTIVE); creation allowed while
  NO_NEW_OUTPUTS; spending allowed while DISABLED; spending refused while
  NO_NEW_OUTPUTS; the first matching transition used instead of the greatest
  `from_height`; `from_height` exclusive; path 1 checked against the primary
  scheme's state; creation checked at height 0. `chain.json` runs only under
  the genesis list (everything ACTIVE) and has no field for any other list.

Of the 16 v0.5 mutations, the vectors catch 5. Four are for mandatory path 2:
not enforced; enforced on path-1 witnesses only; triggered only by keys that
path-0 inputs select; compared with earlier outputs' primary keys instead of
their selected keys. The fifth uses the upgrades.md §4 genesis table, which
the verifier refuses at start-up (A-26). These 11 survive:

- **Equivalent:** mandatory path 2 matched on commitment only (the commitment
  hashes `u16(scheme)`); lifecycle lookup by last in list order instead of
  greatest `from_height` (the two agree on every well-formed list, which is
  now required).
- **Vector gaps (selftest catches them):**
  - mandatory path 2 enforced on **path-0 witnesses only**. No vector puts a
    path-1 witness on an input whose primary key is already authorized
    (selftest: 0 then 1, and 1 then 1).
  - mandatory path 2 matched on **scheme only**. No valid vector transaction
    signs two different keys of the same scheme.
  - mandatory path 2 also applied to a path-1 input's **recovery** key (too
    strict). No vector has a valid path-1 input whose recovery key an earlier
    input already selected (selftest: 0 then 1 under the same key).
- **Not expressible in the vectors (selftest catches all 6):** the
  well-formedness rules for lifecycle lists. Malformed list not refused;
  unknown scheme allowed; equal `from_height` allowed; height order not
  checked; a repeated state (or ACTIVE) allowed; states moving backwards.

## Not reproduced

The report noted `sighash.spent_outputs` as 10-byte placeholders. On
checking, they are full serialized outputs (44 and 82 bytes).
