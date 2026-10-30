# Genesis (normative, draft v0.1)

Genesis is defined by construction, not validated by the ordinary block rules.

## Inputs fixed in the release candidate

- `BTC_HEIGHT` H, and `BTC_PREV_HASH`: the hash of Bitcoin block H−1.
- `BTC_MIN_TARGET`: a conservative minimum Bitcoin target. Each supplied header's
  proof of work must meet it.
- `params_hash = H256("VARVE/params/v1", canonical serialization of every consensus constant)`.
  The constant list is defined in `params.md`, to be written at freeze.

## Procedure

1. Obtain the Bitcoin headers for heights H … H+5 (80 bytes each) from any source.
2. Verify that each header's `prev` field links to the previous one, starting
   at `BTC_PREV_HASH`. Verify that each header's SHA-256d hash meets its own
   encoded target and `BTC_MIN_TARGET`.
3. `seed = H256("VARVE/genesis/v1", params_hash ‖ header_H)`.
4. Genesis coinbase:
   - `version` 1;
   - one coinbase input;
   - `locktime` 0;
   - one output with amount 0, `output_version` `0x00`, `policy` 0,
     `scheme_id` 0 and commitment = `seed`;
   - witness: path 0, empty public key, `signature` = `seed`.
5. Genesis header:
   - `version` 1, `prev_block` = 32 zero bytes;
   - `tx_root` over the coinbase;
   - `timestamp` = the timestamp of `header_H`;
   - `target` = `INITIAL_TARGET`, `nonce` = 0.
6. The genesis outputs are **never** added to the UTXO set. Genesis proof of
   work is not checked.

Until Bitcoin block H+5 exists, nobody can compute `seed`, so nobody can build
on genesis. After genesis, Bitcoin data is never used again.
