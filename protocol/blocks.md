# Blocks, validation order, and chain selection (normative, draft v0.3)

## 1. Header (116 bytes)

| Field | Type | Rule |
| --- | --- | --- |
| `version` | u32 | MUST be `1` |
| `prev_block` | 32 bytes | block id of the parent |
| `tx_root` | 32 bytes | Merkle root over the block's wtxids (§3) |
| `timestamp` | u64 | seconds since 1970-01-01 UTC (difficulty.md §3) |
| `target` | 32 bytes | little-endian u256; MUST equal `next_target(parent)` (difficulty.md) |
| `nonce` | u64 | free |

- `block_id = H256("VARVE/block/v1", header)`.
- `pow_hash = POW(key(height), header)` as defined in pow.md (RandomX v2 with
  the Varve salt; the key rotates every 2,048 blocks). The header is valid only
  if `pow_hash`, read as a little-endian u256, is ≤ `target`.

## 2. Block

`block = header ‖ varint(tx_count) ‖ tx_0 (full serialization) ‖ … ‖ tx_{n−1}`

- `tx_count ≥ 1`; `tx_0` is the coinbase; no other transaction is a coinbase.
- `Σ weight(tx) ≤ MAX_BLOCK_WEIGHT = 720,000`, where the coinbase's weight is
  its serialized length only and every other transaction's weight is as in
  transactions.md §9.
- Weight is at least the serialized length, so a peer message larger than
  `116 + 5 + MAX_BLOCK_WEIGHT` bytes is rejected before parsing.

## 3. Transaction Merkle root

    leaf(x)   = H256("VARVE/merkle/leaf", wtxid(x))
    node(a,b) = H256("VARVE/merkle/node", a ‖ b)
    level_0   = [leaf(tx_0), …, leaf(tx_{n−1})]
    level_k+1 = pair adjacent nodes left to right; an unpaired last node is
                carried up unchanged (never duplicated)
    tree_root = the single node at the top level
    tx_root   = H256("VARVE/merkle/root", u32(n) ‖ tree_root)

Carrying instead of duplicating, plus committing to `n`, removes Bitcoin's
duplicate-transaction ambiguity (CVE-2012-2459). Separate leaf and node tags
prevent confusing a leaf with an inner node.

## 4. Acceptance and validation order

**Acceptance pre-check (not a validity rule).** A node defers, and does not
yet process, a block whose `timestamp > local_clock + MAX_FUTURE_DRIFT`
(600 s). A deferred block MUST NOT be marked invalid. The node MAY process it
later, once its clock has caught up.

**Validity.** A block is valid only if every step below passes; the result
does not depend on the order. Nodes SHOULD evaluate in this order, so cheap
checks come before expensive ones and peers are scored consistently.

1. **Size bound:** the raw message length is within the §2 bound.
2. **Header syntax:** exactly 116 bytes; `version = 1`.
3. **Parent:** the parent is known and is not invalid.
4. **Median time past:** `timestamp > MTP(parent)` (difficulty.md §3).
5. **Target:** `target = next_target(parent)`.
6. **Proof of work:** `pow_hash ≤ target`. This is the first expensive step.
7. **Block parse:** the canonical encoding parses exactly, with no trailing
   bytes, within the parse limits of transactions.md §3.
8. **Root:** `tx_root` matches.
9. **Structure:** `tx_0` has exactly one input, and its `prev_txid` is 32 zero
   bytes; no other transaction has any input with a zero `prev_txid`; no two
   transactions have the same txid.
10. **Weight:** `Σ weight ≤ MAX_BLOCK_WEIGHT`, with the coinbase weighed by its
    serialized length only (§2). This is computable from bytes alone
    (transactions.md §9).
11. **Each transaction, in order:**
    1. syntax, version, and counts;
    2. locktime (non-coinbase);
    3. every input refers to an unspent output in the UTXO set, or to an output
       of an earlier transaction in this block, and no output is spent twice
       within the block;
    4. output rules (transactions.md §1, §6);
    5. amount sums and fee;
    6. coinbase rules (transactions.md §4) for `tx_0`;
    7. every input's spend conditions (transactions.md §8).
12. **Coinbase value:** coinbase outputs ≤ `subsidy(height)` + total fees.
13. **Commit:** apply the UTXO changes atomically. An input may refer only to
    an output of an *earlier* transaction in the block, never to its own or a
    later one. Outputs created and spent within the same block never enter the
    UTXO set.

Signature verification (11.7) MAY run in parallel. The result MUST equal
sequential evaluation.

## 5. Chain selection

- `work(target) = floor(2^256 / (target + 1))`.
- `chainwork(B)` is the sum of `work(target)` over every block from genesis
  through B, genesis included. It is a **mathematical non-negative integer**:
  it never wraps and never saturates. A single block can contribute up to 2^255,
  so implementations MUST use arbitrary-precision integers, or a fixed width
  proven sufficient. For example, 320 bits suffices for 2^64 blocks.
- Nodes follow the valid chain with the greatest `chainwork`.
- On equal `chainwork`, a node keeps the chain it received first.
- There are no checkpoints and no consensus finality rules. A node follows any
  reorganization to a valid chain with greater `chainwork`.

**Other counters.** Heights are u64 (transactions.md §0). The block's total fees
are summed with checked u64 arithmetic. A sum above `MAX_MONEY` is invalid; this
cannot occur on a valid chain, because every input already exists. The RandomX
seed-height formula (pow.md §3) uses u64 and is only evaluated where it cannot
underflow.

## 6. Synchronization and denial-of-service protection (node policy)

Nothing in this section changes which chain is valid or best. It only decides
the order and rate at which a node spends resources. protocol/p2p.md gives the
full message-level rules.

**Overriding rule.** A node MUST download and fully validate any header chain
whose verified cumulative work exceeds the `chainwork` of its active tip.
Anti-DoS limits apply only to branches with **less** total work than the active
tip. No limit in this section may delay a better chain beyond normal bandwidth
and scheduling.

1. **Headers first.** Nodes download headers before blocks. Each header passes
   steps 2–6 of §4. A peer that sends a header failing step 2, 4, 5 or 6 is
   disconnected and banned.
2. **Inferior branches.** For a branch whose header chainwork is ≤ the active
   tip's, a node MAY postpone downloading block bodies until either:
   - its chainwork exceeds the active tip's; or
   - it is within `GATE_WORK` of the active tip's chainwork. `GATE_WORK` is the
     work of 6 blocks at the active tip's target. This lets near-tie forks be
     prepared early.

   The threshold is always measured against the active tip's total chainwork,
   never against the fork point. So a shorter-but-heavier fork is never blocked.
3. **Bounded cheap work.** `POW_LIMIT` is `INITIAL_TARGET × 256`
   (difficulty.md §1). Every block of every branch carries real work.
4. **RandomX caches are budgeted, never gated on verified work.**
   - A node MAY build the cache for a branch's key as soon as that branch's
     headers, up to the key's seed block, pass the cheap checks of §4 steps 2–5:
     syntax, linkage, median time past, and target.
   - Cache construction is limited by a budget: at most 3 resident caches
     (current key, next key, and one least-recently-used slot), plus a global and
     per-peer rate limit on builds.
   - A peer whose headers fail proof of work under a cache built for its branch
     is banned. That makes repeated forced builds costly to the sender.
   - Because a branch only needs one cache per 2,048 blocks, honest forks across
     a key rotation always fit within the budget.
5. **First sync.** A new node MAY use a release-supplied `MIN_CHAIN_WORK`, and
   ignore header chains with less total work until its active tip reaches it
   (p2p.md §5.3; no timeout, operator-overridable). This is a
   resource limit, not a checkpoint. Any chain above it is evaluated purely by
   consensus rules.

**Correction note.** Draft v0.2 measured `GATE_WORK` (144 blocks) from the fork
point. An independent audit (2026-10-31, C-01) showed that this could leave a
node on a lower-work chain. It also found that gating RandomX caches on
verified work was circular (H-01). Both rules are replaced above.
