# Consensus parameters (normative, draft v0.2)

Every consensus constant is listed once, in a fixed order, and committed into
genesis through `params_hash` (genesis.md). Changing any value changes genesis,
so parameters cannot be swapped after the launch datum is known.

## Serialization

For each entry, in the order of the Entries table below, top to bottom. A row
that lists several names (`SCHEME_0001_ALG / PK_LEN / …`) expands left to right
into separate entries named `SCHEME_0001_ALG`, `SCHEME_0001_PK_LEN`,
`SCHEME_0001_SIG_LEN`, `SCHEME_0001_VERIFY_UNITS` (likewise for 0002 and
`RANDOMX_KEY_EPOCH`, `RANDOMX_KEY_LAG`), 35 entries in all. Every `bytes` value,
fixed-length or not, carries its varint length:

    u8(len(name)) ‖ name (ASCII) ‖ value

| Type | Encoding |
| --- | --- |
| u8 / u16 / u32 / u64 | fixed-width little-endian |
| u256 | 32 bytes, little-endian |
| bytes | varint(length) ‖ bytes |

`params_hash = H256("VARVE/params/v1", serialization)`

## Entries

| Name | Type | Value |
| --- | --- | --- |
| NETWORK_ID | bytes | `VARV` |
| BLOCK_VERSION | u32 | 1 |
| TX_VERSION | u32 | 1 |
| OUTPUT_VERSION | u8 | 1 |
| MAX_MONEY | u64 | 2^62 |
| COINBASE_MATURITY | u32 | 288 |
| COINBASE_EXTRA_MAX | u32 | 64 |
| MAX_BLOCK_WEIGHT | u64 | 720,000 |
| UTXO_GROWTH_UNITS | u32 | 100 |
| RECOVERY_DELAY_MAX | u32 | 2^31 − 1 |
| SCHEME_0001_ALG / PK_LEN / SIG_LEN / VERIFY_UNITS | bytes / u32 / u32 / u32 | `ML-DSA-65` / 1,952 / 3,309 / 100 |
| SCHEME_0002_ALG / PK_LEN / SIG_LEN / VERIFY_UNITS | bytes / u32 / u32 / u32 | `SLH-DSA-SHA2-128s` / 32 / 7,856 / 1,700 |
| TARGET_SPACING | u32 | 300 |
| ASERT_TAU | u32 | 21,600 |
| MTP_WINDOW | u32 | 11 |
| MAX_FUTURE_DRIFT | u32 | 600 |
| INITIAL_SUBSIDY | u64 | 8,200,000,000 |
| TAIL_SUBSIDY | u64 | 600,000,000 |
| BLOCKS_PER_EPOCH | u32 | 13,149 |
| SUBSIDY_FRAC_Q63 | bytes | the 64 FRAC values, each u64 little-endian (512 bytes) |
| POW_ALGORITHM | bytes | `RandomX-v2` |
| RANDOMX_ARGON_SALT | bytes | `VarveRX\x01` |
| RANDOMX_KEY_EPOCH / RANDOMX_KEY_LAG | u32 / u32 | 2,048 / 64 |
| INITIAL_TARGET | u256 | set at freeze, < 2^244 (draft placeholder 2^240) |
| POW_LIMIT | u256 | INITIAL_TARGET × 256 (draft: 2^248) |
| BTC_ANCHOR_HEIGHT | u32 | set at freeze (draft placeholder 0) |
| BTC_ANCHOR_PREV_HASH | bytes | set at freeze (draft placeholder: 32 zero bytes) |
| BTC_ANCHOR_BITS | u32 | set at freeze: exact nBits of the Bitcoin period containing H … H+5 (draft placeholder 0) |

`MAX_FUTURE_DRIFT` is an acceptance rule, not a validity rule. It is committed
anyway, so every implementation uses the same value.

## Draft set

The draft set with its placeholders hashes to:

`params_hash = 9b2175c0878961feac922b2df436d77625a16d14cd030ef5f37c81568b974a7b`

The full entry list is in `test-vectors/params.json`. This set must never be
used for mainnet. Testnets derive their own sets with their own anchor fields.
