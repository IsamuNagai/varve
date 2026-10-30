# Addresses (normative for wallets, draft v0.2)

Addresses are not consensus objects. Wallets MUST still implement this encoding
exactly, so they remain interoperable.

## Encoding

- Bech32m (BIP-350) checksum and character set. Wallets MUST display
  lowercase. Decoders MUST accept an all-lowercase or all-uppercase string
  (for example from an alphanumeric QR code), normalize it to lowercase, and
  reject mixed case.
- Human-readable part: `varve` (mainnet), `tvarve` (testnet), `rvarve` (regtest).
- Data: the first 5-bit symbol is `output_version` (`1`). It is followed by the
  output template bytes after `output_version`, converted from 8-bit to 5-bit
  groups with padding:

      policy (u8) ‖ scheme_id (u16 LE) ‖ commitment (32)
      [‖ recovery_scheme_id (u16 LE) ‖ recovery_commitment (32) ‖ recovery_delay (u32 LE)]

- The decoded template is exactly 35 bytes (single policy) or 73 bytes (recovery
  policy). Decoders MUST reject any other payload length. They MUST NOT apply
  BIP-350's 90-character limit, because recovery addresses exceed it.
- On mainnet, a single-policy address is 69 characters and a recovery-policy
  address is 130. Testnet adds one character.
- Bech32m guarantees detection of up to 4 errors only for strings up to 89
  characters. For recovery addresses, a random error goes undetected with
  probability about 2^−30. Wallets SHOULD show recovery addresses with the
  recovery delay spelled out, and ask the user to confirm it.

## Decoding

Decoders MUST reject:

- mixed case;
- an unknown human-readable part;
- a wrong checksum;
- `output_version ≠ 1`;
- an unknown policy;
- a payload length that does not match the policy;
- non-zero padding bits;
- any template that would make an invalid output under transactions.md §1 and
  §6. That includes a `scheme_id` or `recovery_scheme_id` that is not
  currently creatable, and a `recovery_delay` of 0 or ≥ 2^31.

Test vectors: `test-vectors/addresses.json`.
