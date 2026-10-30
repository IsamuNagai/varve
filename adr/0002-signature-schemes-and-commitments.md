# ADR-0002: Signature schemes, commitments, and algorithm lifecycle

## Status
PROPOSED (2026-10-30). Requires external cryptographic review before ACCEPTED.

## Context
Ownership must remain secure under currently understood classical and quantum
attack models for decades. No signature scheme can be assumed secure forever.

## Requirements
- Only standardized, unmodified algorithms with exact parameter sets.
- Two independent hardness families available from genesis.
- Public keys not exposed until spend.
- A deterministic, consensus-defined path to add, deprecate, and retire schemes.
- Spends cannot be downgraded to a weaker scheme than the output committed to.

## Options
| Scheme | Standard | Status (2026-10) | Public key / signature (bytes) |
| --- | --- | --- | --- |
| ML-DSA-44 | FIPS 204 | Final | 1,312 / 2,420 |
| ML-DSA-65 | FIPS 204 | Final | 1,952 / 3,309 |
| ML-DSA-87 | FIPS 204 | Final | 2,592 / 4,627 |
| SLH-DSA-SHA2-128s | FIPS 205 | Final | 32 / 7,856 |
| FN-DSA-512 | FIPS 206 | Draft | 897 / ~666 |
| XMSS / LMS | SP 800-208 | Final, stateful | small / ~2.5 KB |

## Decision
**Scheme registry at genesis:**

| scheme_id | Algorithm | Role | Initial state |
| --- | --- | --- | --- |
| `0x0000` | reserved, invalid | — | — |
| `0x0001` | ML-DSA-65 (FIPS 204, pure mode, empty context string) | Primary | ACTIVE |
| `0x0002` | SLH-DSA-SHA2-128s (FIPS 205, pure mode, empty context string) | Recovery or primary | ACTIVE |
| `0x0003`–`0xFFFF` | reserved for future soft forks | — | invalid to create or spend |

**Commitment:** `commitment = H256("VARVE/pk/v1", u16_le(scheme_id) || public_key)`, where `H256` is the length-prefixed, tagged SHA3-256 defined in protocol/encoding.md §4.
The domain tag and scheme id bind the commitment to the scheme, so a key cannot
be reinterpreted under another algorithm.

**Signed message:** a transaction signature hash defined in
`protocol/transactions.md` §7, with its own domain separation. Signatures use
**hedged (randomized) signing** where FIPS 204 permits it, to reduce
fault-attack exposure. Verification is deterministic either way.

**Lifecycle (consensus states per scheme_id):**

| State | New outputs | Spends |
| --- | --- | --- |
| ACTIVE | allowed | allowed |
| NO_NEW_OUTPUTS | rejected | allowed |
| SPEND_VIA_COMMITMENT | rejected | only through commit–delay–reveal (ADR-0009) |
| DISABLED | rejected | rejected, except via the output's recovery path |

State changes occur only by soft fork activated at a block height. Changes are
one-directional (no return to ACTIVE). There is no automatic or
oracle-triggered transition. "Discouraged" is wallet policy, not consensus.

## Rationale
- ML-DSA-65 adds lattice security margin over ML-DSA-44 for a multi-decade
  horizon, at about 1.4× the bytes. Verification is fast, so bytes dominate cost.
- SLH-DSA relies only on hash-function security, which is independent of
  lattice assumptions. It is ideal as a rarely used recovery path: large
  signatures and slow signing are acceptable there.
- FN-DSA is excluded until FIPS 206 is final and its floating-point determinism
  is settled across platforms.
- Stateful schemes (XMSS, LMS, SHRINCS) are excluded at genesis. State loss
  or reuse is catastrophic or degrading, and wallets must be misuse-resistant.
  Revisit as a future scheme_id.

## Security implications
- About 5.3 KB per ML-DSA-65 input; block weight must account for it (ADR-0006).
- SLH-DSA verification is hash-heavy and must carry verification-unit weight
  to prevent verification-DoS.
- Hash commitments protect unspent, never-revealed keys if ML-DSA is later broken.
- Key reuse exposes public keys. Wallets must never reuse commitments.
- Implementation risk: side channels, faults, and randomness in signing.
  Only audited implementations may be used (dependency review required).

## Tradeoffs
- Throughput is roughly 20–50× lower per byte than with Schnorr.
- No public (non-hardened) key derivation, so watch-only wallets need exported commitments.

## Rejected alternatives
ML-DSA-44 (thinner margin), ML-DSA-87 (cost without clear need), FN-DSA (draft),
stateful hash-based schemes (misuse risk), and any non-NIST or novel scheme.

## Dependencies
ADR-0001, ADR-0006 (weights), ADR-0007 (addresses), ADR-0009 (emergency migration).

## Revisit trigger
- Cryptanalysis reducing ML-DSA-65's estimated security below Category 3.
- FIPS 206 published final.
- A NIST additional-signature standard with materially smaller signatures.
- An audited compact stateful scheme with safe wallet state handling.
