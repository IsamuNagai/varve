# Blocks, validation order, and chain selection (normative, draft v0.1)

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
- `pow_hash = POW(header)` as defined by ADR-0003. Draft: RandomX v2 with the
  Varve parameter set; key-rotation rules to be specified with that ADR. The
  header is valid only if `pow_hash`, read as a little-endian u256, is ≤ `target`.

## 2. Block

`block = header ‖ varint(tx_count) ‖ tx_0 (full serialization) ‖ … ‖ tx_{n−1}`

- `tx_count ≥ 1`; `tx_0` is the coinbase; no other transaction is a coinbase.
- `Σ weight(tx) ≤ MAX_BLOCK_WEIGHT = 720,000`.
- `MAX_BLOCK_WEIGHT` bounds parsing: a peer message larger than
  `116 + 5 + MAX_BLOCK_WEIGHT` bytes is rejected before it is parsed.

## 3. Transaction Merkle root

    leaf(x)   = H256("VARVE/merkle/leaf", wtxid(x))
    node(a,b) = H256("VARVE/merkle/node", a ‖ b)
    level_0   = [leaf(tx_0), …, leaf(tx_{n−1})]
    level_k+1 = pair adjacent nodes left to right; an unpaired last node is
                carried up unchanged (never duplicated)
    tree_root = the single node at the top level
    tx_root   = H256("VARVE/merkle/root", u32(n) ‖ tree_root)

Carrying instead of duplicating, plus committing to `n`, removes the known
duplicate-transaction ambiguity of Bitcoin's Merkle construction (CVE-2012-2459).

## 4. Validation order

Nodes MUST reject at the first failing step. The order is fixed, so peers can
be scored consistently. Cheap checks run before expensive ones.

1. **Size bound:** the raw message length is within the §2 bound.
2. **Header syntax:** exactly 116 bytes; `version = 1`.
3. **Parent known:** the parent is known and not marked invalid.
4. **Timestamp:** rules in difficulty.md §3.
5. **Target:** `target = next_target(parent)`.
6. **Proof of work:** `pow_hash ≤ target`. This is the first expensive step.
7. **Block parse:** the canonical encoding parses exactly, with no trailing bytes.
8. **Root:** `tx_root` matches.
9. **Weight and structure:** the weight limit, the coinbase position and
   uniqueness, and no duplicate txids.
10. **Each transaction in order:**
    1. syntax and canonical encoding (transactions.md §1–3);
    2. locktime;
    3. every input refers to an unspent output in the UTXO set, or to an output
       of an earlier transaction in this block, and no output is spent twice
       within the block;
    4. output rules (amounts, versions, policies, creatable schemes);
    5. amount sums and fee;
    6. every signature (transactions.md §8).
11. **Coinbase value:** coinbase outputs ≤ `subsidy(height)` + total fees.
12. **Commit:** apply UTXO changes atomically.

Signature verification (10.6) MAY run in parallel. The result MUST equal
sequential evaluation.

## 5. Chain selection

- `work(target) = floor(2^256 / (target + 1))`.
- Nodes follow the valid chain with the greatest cumulative work.
- On equal work, a node keeps the chain it received first.
- There are no checkpoints and no finality rules: any reorganization to a
  valid chain with more work is followed.
