# Blocks, validation order, and chain selection (normative, draft v0.2)

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
- `Σ weight(tx) ≤ MAX_BLOCK_WEIGHT = 720,000`.
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

**Validity.** Nodes MUST reject at the first failing step. The order is fixed,
so peers are scored consistently, and cheap checks come before expensive ones.

1. **Size bound:** the raw message length is within the §2 bound.
2. **Header syntax:** exactly 116 bytes; `version = 1`.
3. **Parent:** the parent is known and is not invalid.
4. **Median time past:** `timestamp > MTP(parent)` (difficulty.md §3).
5. **Target:** `target = next_target(parent)`.
6. **Proof of work:** `pow_hash ≤ target`. This is the first expensive step.
7. **Block parse:** the canonical encoding parses exactly, with no trailing
   bytes, within the parse limits of transactions.md §3.
8. **Root:** `tx_root` matches.
9. **Structure:** coinbase position and uniqueness; no duplicate txids.
10. **Weight:** `Σ weight ≤ MAX_BLOCK_WEIGHT`. This is computable from bytes
    alone (transactions.md §9).
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
13. **Commit:** apply the UTXO changes atomically.

Signature verification (11.7) MAY run in parallel. The result MUST equal
sequential evaluation.

## 5. Chain selection

- `work(target) = floor(2^256 / (target + 1))`.
- Nodes follow the valid chain with the greatest cumulative work.
- On equal work, a node keeps the chain it received first.
- There are no checkpoints and no consensus finality rules: a node follows any
  reorganization to a valid chain with more work.

## 6. Synchronization and denial-of-service protection (node policy)

None of the following changes which chain is valid or best. It only controls
what a node spends resources on.

1. **Headers first.** Nodes download and check headers (steps 2–6) before
   blocks. Peers that send a header failing step 2, 4, 5 or 6 are disconnected.
2. **Work gate.** A node stores and fully validates a competing branch only once
   its headers prove cumulative work ≥ the work of the node's active chain at
   the fork point + `GATE_WORK`. `GATE_WORK` is the work of 144 blocks at the
   active tip's current target. A node never downloads block bodies for a
   branch below this gate.
3. **Bounded cheap work.** `POW_LIMIT` is `INITIAL_TARGET × 256`
   (difficulty.md §1). Even an abandoned branch carries real work per block, so
   old-fork header floods cost the attacker real hashing.
4. **Cache budget.** A node keeps at most two RandomX caches (current and next
   key). Building a cache for a branch's key requires the branch to pass the
   work gate first.
5. **First sync.** A new node MAY use a release-supplied `MIN_CHAIN_WORK` value
   so that it ignores header chains with less total work. This value is a
   resource limit, not a checkpoint. Any chain with more work than it is still
   evaluated purely by consensus rules.
