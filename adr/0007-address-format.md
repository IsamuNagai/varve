# ADR-0007: Address format

## Status
PROPOSED (2026-10-30)

## Context
Addresses must be human-friendly, typo-resistant, QR-suitable, and versioned.
Full post-quantum public keys (about 2 KB) are unusable in addresses.

## Decision
**Bech32m (BIP-350)** encoding of the output template, excluding the amount:

- Human-readable part: `varve` (mainnet), `tvarve` (testnet), `rvarve` (regtest).
- Data payload: `output_version (u8) || policy (u8) || scheme_id (u16 LE) || commitment (32 bytes)`.
  When the policy includes recovery, the payload also carries
  `recovery_scheme_id || recovery_commitment || recovery_delay`.
- Single-path addresses are about 70 characters. Recovery-policy addresses
  exceed the 90-character limit of BIP-350 and use the same checksum with the
  length limit lifted, as specified in protocol/addresses.md.
- Lowercase only, so a QR code can use alphanumeric mode when uppercased.

## Rationale
Bech32m is mature, has strong error detection, and is widely implemented.
Hashing the public key into the commitment keeps addresses short and keys hidden until spend.

## Security implications
The checksum detects up to 4 character errors in short strings. Network
prefixes prevent sending mainnet coins to testnet addresses.

## Rejected alternatives
Base58Check (case-sensitive, weaker error detection); raw public keys (too large).

## Dependencies
ADR-0001, ADR-0002.

## Revisit trigger
A wallet usability study showing recovery-policy addresses are error-prone.
