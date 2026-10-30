# ADR-0001: UTXO ledger with typed outputs

## Status
ACCEPTED (2026-10-30)

## Context
The ledger model determines how ownership, supply auditing, signature-scheme
migration, and spending conditions are expressed for the life of the chain.

## Requirements
- Supply is auditable by any node from the UTXO set alone.
- Every unit of value has explicit authorization semantics fixed when it is created.
- Signature schemes can be added and retired without touching existing outputs.
- Timelocks and recovery paths need no general-purpose scripting.
- Validation can be parallelised.

## Options
1. UTXO with a Bitcoin-style script language.
2. UTXO with fixed, typed outputs and a tiny, closed policy set.
3. Account model.

## Decision
**Option 2.** Each output carries:

| Field | Type | Meaning |
| --- | --- | --- |
| `amount` | u64 | Laminae (1 varve = 10^8 laminae) |
| `output_version` | u8 | Output format version; unknown versions are invalid to create |
| `policy` | u8 | `0x00` = single authorization; `0x01` = primary OR (recovery after relative delay); further values are reserved |
| `scheme_id` | u16 | Authorization scheme for the primary path (registry in ADR-0002) |
| `commitment` | 32 bytes | Hash commitment to the primary public key |
| `recovery_scheme_id` | u16 | Present only when `policy = 0x01` |
| `recovery_commitment` | 32 bytes | Present only when `policy = 0x01` |
| `recovery_delay` | u32 | The recovery path is valid in blocks at height ≥ creation height + recovery_delay; present only when `policy = 0x01` |

Exact serialization is defined in `protocol/transactions.md`.

## Rationale
UTXO gives explicit ownership, simple supply audit, and natural parallelism.
Fixed typing makes the authorization scheme of every output visible to
consensus, which is what an algorithm lifecycle (ADR-0002) needs. A closed
policy set captures timelocked recovery, the main custody need, without the
permanent attack surface of a script language.

## Security implications
- A small, closed set of output types is far easier to specify, test, and audit than a script VM.
- The commitment hides the public key until spend (see ADR-0002).
- New policies require a soft fork. This is intended.

## Tradeoffs
- No multisignature in v1. PQ threshold signatures are immature, and naive
  k-of-n multiplies signature bytes. Revisit with ADR-0010.
- No covenants or arbitrary contracts.
- Less expressive than Bitcoin Script.

## Rejected alternatives
- **Script language:** a large permanent attack surface, and hard to
  specify precisely enough for independent implementations.
- **Account model:** weaker supply audit, global nonce state, and
  migration semantics tied to accounts rather than individual coins.

## Dependencies
ADR-0002, ADR-0007, protocol/encoding.md, protocol/transactions.md.

## Revisit trigger
A custody requirement that cannot be met by the policy set and is justified
at Layer 1, or a mature PQ threshold-signature standard.
