# Genesis (normative, draft v0.2)

Genesis is defined by construction, not validated by the ordinary block rules.
The goal: nobody, including the author, can compute genesis, and so mine on
it, before six consecutive Bitcoin blocks exist that were all produced after
the launch announcement.

## 1. Inputs fixed in the release candidate

| Name | Meaning |
| --- | --- |
| `BTC_ANCHOR_HEIGHT` (H) | Bitcoin height. Chosen so that H … H+5 all lie in one Bitcoin difficulty period (2,016 blocks) that has already begun at freeze time |
| `BTC_ANCHOR_PREV_HASH` | hash of Bitcoin block H−1 (known at freeze) |
| `BTC_ANCHOR_BITS` | the exact compact target (`nBits`) of that difficulty period (known at freeze) |
| `params_hash` | params.md |

## 2. Procedure

1. Obtain the 80-byte Bitcoin headers for heights H … H+5.
2. Check each header `X_k` (k = 0 … 5):
   - `X_k.prev` equals `BTC_ANCHOR_PREV_HASH` for k = 0, and `SHA256d(X_{k−1})` otherwise;
   - `X_k.nBits` equals `BTC_ANCHOR_BITS` exactly;
   - `SHA256d(X_k)`, read as a little-endian 256-bit integer, is ≤ the target
     decoded from `nBits`.
   - nBits is decoded as in Bitcoin Core: exponent = high byte; mantissa = low
     23 bits. A set sign bit (0x00800000), a zero mantissa, or a target ≥ 2^256
     makes the header invalid.
3. Compute the seed over all six headers:

        seed = H256("VARVE/genesis/v1", params_hash ‖ X_0 ‖ X_1 ‖ X_2 ‖ X_3 ‖ X_4 ‖ X_5)

4. `t0` = `sorted([X_0.time, …, X_5.time])[3]`, the upper median of the six
   Bitcoin header timestamps.
5. Genesis coinbase:
   - `version` 1;
   - one coinbase input (`prev_index` 0);
   - `locktime` 0;
   - one output with amount 0, `output_version` `0x00`, `policy` 0,
     `scheme_id` 0 and commitment = `seed`;
   - witness: path 0, empty public key, `signature` = `seed`.
6. Genesis header:
   - `version` 1, `prev_block` = 32 zero bytes;
   - `tx_root` over the coinbase;
   - `timestamp` = `t0`;
   - `target` = `INITIAL_TARGET`, `nonce` = 0.
7. The genesis outputs are **never** added to the UTXO set. Genesis proof of
   work is not checked.

## 3. Why this is fair, and what it does not prevent

- **No early computation.** The seed depends on all six headers. Nobody can
  compute it before Bitcoin block H+5 exists. The only possible head start goes
  to the miner of H+5, who would have to withhold a valid Bitcoin block (and
  risk losing its reward) to gain minutes.
- **No cheap forgery.** Each header must meet Bitcoin's real difficulty for
  that period, not a relaxed minimum. Faking six headers costs as much as
  mining six real Bitcoin blocks.
- **Timestamp grinding is bounded.** `t0` is a median, so no single Bitcoin
  miner controls it.
- **Residual risk: a Bitcoin reorganization of six or more blocks** across
  H … H+5 could produce two genesis candidates.
  - Nodes SHOULD wait until H+5 is buried under at least 6 more Bitcoin blocks,
    and compare headers from at least three independent sources before mining.
  - Once launched, client releases record the resulting genesis id, which
    anyone can recompute from public Bitcoin data.
- After genesis, Bitcoin data is never used again.
