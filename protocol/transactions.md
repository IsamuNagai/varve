# Transactions and outputs (normative, draft v0.1)

Conventions (integer widths, little-endian, canonical `varint`, `bytes`, `H256`)
are defined in `encoding.md`. "Invalid" means the containing block is invalid.

## 1. Output

| Field | Type | Rule |
| --- | --- | --- |
| `amount` | u64 | 1 ≤ amount ≤ `MAX_MONEY` |
| `output_version` | u8 | MUST be `0x01` |
| `policy` | u8 | `0x00` single, or `0x01` primary-or-recovery; any other value is invalid |
| `scheme_id` | u16 | MUST be creatable at the block height (§6) |
| `commitment` | 32 bytes | `H256("VARVE/pk/v1", u16(scheme_id) ‖ public_key)` |
| `recovery_scheme_id` | u16 | present iff `policy = 0x01`; MUST be creatable |
| `recovery_commitment` | 32 bytes | present iff `policy = 0x01` |
| `recovery_delay` | u32 | present iff `policy = 0x01`; 1 ≤ value ≤ 2^31 − 1 blocks |

The serialization is the fields in table order. A single-policy output is 44
bytes; a recovery-policy output is 82 bytes. The output **template** is the
output without `amount`.

`MAX_MONEY` = 2^62 laminae. The sum of a transaction's outputs, and of its
spent inputs, is computed with checked u64 arithmetic. Overflow is invalid.

## 2. Input

| Field | Type | Rule |
| --- | --- | --- |
| `prev_txid` | 32 bytes | txid of the transaction that created the spent output |
| `prev_index` | u32 | index of that output |

The serialization is 36 bytes.

## 3. Transaction

Base serialization (hashed into `txid`):

| Field | Type | Rule |
| --- | --- | --- |
| `version` | u32 | MUST be `1` |
| `input_count` | varint | ≥ 1 |
| `inputs` | input × input_count | |
| `output_count` | varint | ≥ 1 |
| `outputs` | output × output_count | |
| `locktime` | u32 | 0, or a block height (§5) |

Witness serialization (one entry per input, in input order):

| Field | Type | Rule |
| --- | --- | --- |
| `path` | u8 | `0x00` primary, `0x01` recovery |
| `public_key` | bytes | exact length for the scheme (§6) |
| `signature` | bytes | exact length for the scheme (§6) |

Full serialization = base ‖ witness. There is no witness count field; the
witness has exactly `input_count` entries.

- `txid = H256("VARVE/txid/v1", base)`. Outpoints reference txids, so a change
  to witness data cannot change a txid (no third-party malleability).
- `wtxid = H256("VARVE/wtxid/v1", full)`.

## 4. Coinbase transaction

The first transaction of every block, and only that one, is the coinbase:

- exactly one input, with `prev_txid` = 32 zero bytes and `prev_index` = `0xFFFFFFFF`;
- `locktime` MUST equal the block height, which makes every coinbase txid unique;
- its single witness entry has `path = 0x00`, an empty `public_key`, and a
  `signature` field of 0–64 arbitrary bytes (extra nonce);
- the sum of its outputs MUST NOT exceed `subsidy(height)` plus the sum of the block's fees;
- its outputs MUST NOT be spent until 288 blocks later (coinbase maturity).

## 5. Locktime

If `locktime ≠ 0`, the transaction is valid only in a block whose height is at
least `locktime`. Locktime is height-only. Wall-clock time is never consulted.
The coinbase rule in §4 overrides this section.

## 6. Signature schemes

| scheme_id | Algorithm | public_key | signature | verify_units |
| --- | --- | --- | --- | --- |
| `0x0001` | ML-DSA-65 (FIPS 204, pure, empty context) | 1,952 B | 3,309 B | 100 |
| `0x0002` | SLH-DSA-SHA2-128s (FIPS 205, pure, empty context) | 32 B | 7,856 B | 1,700 |

All other ids are invalid to create or spend. Lifecycle states (ADR-0002) are
consensus constants per height range. At genesis both schemes are ACTIVE.

- **Creatable** = ACTIVE.
- **Spendable by the primary path** = ACTIVE or NO_NEW_OUTPUTS.
- SPEND_VIA_COMMITMENT and DISABLED are not used at genesis; their rules are
  specified when a soft fork introduces them (ADR-0009).

## 7. Signature message

For input `i` of transaction `tx`, spending output `o` via `path`:

    spent_hash = H256("VARVE/spent/v1", serialize(o_0) ‖ … ‖ serialize(o_{n−1}))   # all spent outputs, input order
    msg        = H256("VARVE/sighash/v1", network_id ‖ txid(tx) ‖ u32(i) ‖ spent_hash ‖ u8(path))

The signature is computed over the 32-byte `msg` with the scheme's pure-mode
sign function and an empty context string. Every signature commits to:

- all inputs and outputs (via txid);
- every spent amount and template, so a signer can always compute the fee;
- the network;
- the input index;
- the spending path.

There are no sighash flags.

## 8. Spending an output

An input spending output `o`, created at height `h_o`, in a block at height `h`, is valid iff:

1. `o` exists in the UTXO set (or an output of an earlier transaction in the same block; blocks.md §4, step 10.3) and is not otherwise spent.
2. **Path 0:**
   - `scheme = o.scheme_id`;
   - `H256("VARVE/pk/v1", u16(scheme) ‖ public_key) = o.commitment`;
   - the scheme is spendable;
   - lengths are exact;
   - `Verify(public_key, msg, signature)` returns true.
3. **Path 1:**
   - `o.policy = 0x01`;
   - `h ≥ h_o + o.recovery_delay`;
   - the same checks as path 0, using `recovery_scheme_id` and `recovery_commitment`;
   - the recovery path is spendable in every lifecycle state except an
     explicit future DISABLED state for its own scheme.
4. If `o` is a coinbase output, `h ≥ h_o + 288`.

## 9. Fees and weight

`fee = Σ spent amounts − Σ output amounts`. A negative fee is invalid.

    weight(tx) = len(full serialization)
               + Σ_inputs verify_units(scheme used)
               + 100 × max(0, output_count − input_count)

The coinbase's weight counts its serialized length only.
