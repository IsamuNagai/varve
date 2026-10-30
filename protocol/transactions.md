# Transactions and outputs (normative, draft v0.2)

Conventions (integer widths, little-endian, canonical `varint`, `bytes`, `H256`)
are defined in `encoding.md`. "Invalid" means the containing block is invalid.

## 0. Heights

- The genesis block has height 0. Every other block has height = parent height + 1.
- An output's **creation height** `h_o` is the height of the block containing
  the transaction that created it. This includes outputs created earlier in the
  same block.
- All height arithmetic, such as `h_o + recovery_delay` and `h_o + 288`, uses
  unsigned 64-bit checked arithmetic. It cannot overflow for heights below 2^63.

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

`MAX_MONEY` = 2^62 laminae. For every transaction:

- the sum of output amounts, computed with checked u64 arithmetic, MUST be ≤ `MAX_MONEY`;
- for non-coinbase transactions, the same applies to the sum of spent amounts.

Overflow is invalid. The coinbase has no spent inputs; its limit is §4.

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

| Field | Type | Parse-time rule |
| --- | --- | --- |
| `path` | u8 | `0x00` primary or `0x01` recovery |
| `public_key` | bytes | length ≤ 1,952 |
| `signature` | bytes | length ≤ 7,856 |

Full serialization = base ‖ witness. There is no witness count field; the
witness has exactly `input_count` entries.

- `txid = H256("VARVE/txid/v1", base)`. Outpoints reference txids, so a change
  to witness data cannot change a txid (no third-party malleability).
- `wtxid = H256("VARVE/wtxid/v1", full)`.

**Parsing limits.** Before allocating storage for `input_count` or
`output_count` items, a parser MUST check that the count times the item's
minimum size (36 bytes per input, 44 per output, 3 per witness entry) does not
exceed the remaining input. Every transaction lies inside a block bounded by
`MAX_BLOCK_WEIGHT` (blocks.md §2). Its weight MUST NOT exceed `MAX_BLOCK_WEIGHT`.

## 4. Coinbase transaction

The first transaction of every block, and only that one, is the coinbase:

- **Input:** exactly one, with `prev_txid` = 32 zero bytes and
  `prev_index` = the block height mod 2^32.
- **Locktime:** MUST equal `floor(height / 2^32)`. Together these encode the
  full 64-bit height, so every coinbase txid is unique.
- **Witness:** its single entry has `path = 0x00`, an empty `public_key`, and
  a `signature` field of 0–64 arbitrary bytes (extra nonce).
- **Value:** the sum of its outputs MUST NOT exceed `subsidy(height)` plus the
  sum of the block's fees.
- **Maturity:** its outputs MUST NOT be spent before height `h_o + 288`.

A non-coinbase transaction MUST NOT have an input whose `prev_txid` is 32
zero bytes. §5 does not apply to the coinbase.

## 5. Locktime

If `locktime ≠ 0`, a non-coinbase transaction is valid only in a block whose
height is at least `locktime`. Locktime is height-only; wall-clock time is
never consulted.

## 6. Signature schemes and lifecycle

| scheme_id | Algorithm | public_key | signature | verify_units |
| --- | --- | --- | --- | --- |
| `0x0001` | ML-DSA-65 (FIPS 204, pure, empty context) | 1,952 B | 3,309 B | 100 |
| `0x0002` | SLH-DSA-SHA2-128s (FIPS 205, pure, empty context) | 32 B | 7,856 B | 1,700 |

All other ids are invalid to create or spend. Each scheme has a lifecycle
state per height range, fixed by consensus. At genesis both schemes are
ACTIVE, and no other state is used.

| State | Create outputs | Spend via path 0 | Spend via path 1 (recovery) |
| --- | --- | --- | --- |
| ACTIVE | yes | yes | yes |
| NO_NEW_OUTPUTS | no | yes | yes |
| SPEND_VIA_COMMITMENT | no | only through commit–delay–reveal (ADR-0009) | only through commit–delay–reveal |
| DISABLED | no | no | no |

For path 1, the state that applies is the state of `recovery_scheme_id`.
Rules for SPEND_VIA_COMMITMENT and DISABLED take effect only when a soft fork
specifies them.

## 7. Signature message

For input `i` of transaction `tx`, spending output `o` via `path`, on the
chain whose genesis block id is `genesis_id`:

    spent_hash = H256("VARVE/spent/v1", serialize(o_0) ‖ … ‖ serialize(o_{n−1}))   # all spent outputs, input order
    msg        = H256("VARVE/sighash/v1",
                      network_id ‖ genesis_id ‖ txid(tx) ‖ u32(i) ‖ spent_hash ‖ u8(path))

The signature is computed over the 32-byte `msg` with the scheme's pure-mode
sign function and an empty context string. There are no sighash flags. Every
signature commits to:

- all inputs and outputs (via txid);
- every spent amount and template;
- the network and the specific chain, so signatures do not replay across
  testnet resets or forks with a different genesis;
- the input index;
- the spending path.

## 8. Spending an output

An input spending output `o`, created at height `h_o`, in a block at height `h`, is valid iff:

1. `o` exists in the UTXO set, or is an output of an earlier transaction in
   the same block (blocks.md §4, step 11.3). It must not otherwise be spent.
2. If `o` is a coinbase output, `h ≥ h_o + 288`.
3. Select the scheme and commitment by path:
   - **path 0:** `scheme_id`, `commitment`;
   - **path 1:** requires `o.policy = 0x01` and `h ≥ h_o + recovery_delay`;
     uses `recovery_scheme_id`, `recovery_commitment`.
4. The selected scheme permits this path in its state at height `h` (§6).
5. `public_key` and `signature` have exactly the lengths in §6 for the selected scheme.
6. `H256("VARVE/pk/v1", u16(scheme) ‖ public_key)` equals the selected commitment.
7. `Verify(public_key, msg, signature)` returns true.

## 9. Fees and weight

`fee = Σ spent amounts − Σ output amounts`. A negative fee is invalid.

    weight(tx) = len(full serialization)
               + Σ_witness entries verify_units(len(signature))
               + 100 × max(0, output_count − input_count)

where `verify_units(3,309) = 100`, `verify_units(7,856) = 1,700`, and
`verify_units` of any other length is 0. Weight therefore depends only on the
transaction bytes and can be computed before any input is looked up. Step 5 of
§8 then rejects any signature whose length does not match the selected scheme.
The coinbase's weight counts its serialized length only.
