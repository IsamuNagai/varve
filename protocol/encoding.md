# Encoding conventions (normative, draft v0.1)

## 1. General

1. All consensus integers are unsigned unless stated otherwise, and are
   encoded **little-endian** with fixed width: `u8`, `u16`, `u32`, `u64`.
2. Consensus code MUST NOT use floating point.
3. Arithmetic on amounts MUST be checked. Any overflow or underflow during
   validation makes the transaction or block invalid. It MUST NOT wrap or saturate.
4. A value MUST have exactly one valid encoding. Any other encoding of the same
   value is invalid. This includes non-minimal lengths, trailing bytes,
   unknown flags, and reserved values.

## 2. Compact size (`varint`)

Lengths and counts use a **canonical** unsigned LEB128 encoding, limited to
values below 2^32:

- Each byte carries 7 value bits (low bits first). The high bit set means another byte follows.
- At most 5 bytes.
- The encoding MUST be minimal: the final byte MUST NOT be `0x00`, unless the value is 0 and encoded as a single `0x00`.
- A value of 2^32 or above is invalid.

Decoders MUST check every length against the remaining input and the
applicable maximum **before allocating** memory.

## 3. Byte strings

`bytes` = `varint length || length bytes`. Each field type defines its own
maximum length, for example a public key of exactly 1,952 bytes for
scheme `0x0001`. A wrong length is invalid; no padding or truncation is allowed.

## 4. Hashes

| Name | Definition | Use |
| --- | --- | --- |
| `H256(tag, m)` | `SHA3-256(len(tag) as u8 \|\| tag \|\| m)` | Commitments, signature hashes, domain-separated hashing |
| `HB(m)` | `SHA-256(SHA-256(m))` | Block header hash, Merkle tree (ADR pending) |

Tags are ASCII strings beginning with `VARVE/`, for example `VARVE/pk/v1`.
Every use of a hash in consensus MUST have a unique tag.

## 5. Amounts

Amounts are `u64` laminae. A single output's amount MUST be at most
`MAX_MONEY` (to be set with ADR-0004 constants). The sum of outputs MUST be at
most the sum of inputs, using checked arithmetic.

## 6. Network identifier

`network_id` is 4 raw bytes, the ASCII strings `VARV` (mainnet), `TVAR`
(testnet), and `RVAR` (regtest), serialized in that byte order. It is included
in every signature hash to prevent cross-network replay.
