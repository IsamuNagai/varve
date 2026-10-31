# ADR-0009: Emergency migration via commit–delay–reveal

## Status
DEFERRED (2026-10-31). Not part of v1. Research sketch only.

An independent review (finding H-08) noted that this sketch cannot be
implemented from the specification: it lacks a transaction representation for
the commitment (current outputs have no data field), a consensus commitment
index, exact validity rules, fee sponsorship, spam/state-growth bounds,
expiry, reorg handling and a definition of "earliest valid commitment" under
reorgs, reveal serialization, activation, interaction with recovery outputs,
and DoS limits. Until all of these are specified with vectors, Varve does not
claim this mechanism, and the v1 lifecycle (transactions.md §6) has no state
that depends on it.

## Context
If a signature scheme is broken in practice, spending an output reveals its
public key, and an attacker can then race the legitimate holder with a forged
spend. Agility does not help users who did not add a recovery path.

## Decision (sketch)
If a future upgrade added a SPEND_VIA_COMMITMENT lifecycle state:

1. **Commit.** The holder publishes a commitment transaction, paid from an
   output under a still-safe scheme, containing
   `C = H256("VARVE/migrate/v1", outpoint || public_key || destination_template || salt)` (encoding.md §4).
   This reveals nothing about the key.
2. **Delay.** C must be buried at least D blocks deep (proposed D = 288, about one day).
3. **Reveal.** The holder spends the output to `destination_template`. The
   spend reveals the public key, the signature, and the salt, and must match
   the earliest valid C for that outpoint.
4. Consensus accepts a spend of an affected output only if the matching
   commitment exists. Among competing commitments for the same outpoint, the
   earliest confirmed one wins.

## Open questions
- Fee payment for holders with no safe-scheme coins (sponsor transactions?).
- Commitment spam and state growth (bond or expiry).
- Interaction with reorgs deeper than D.

## Security implications
Prevents mempool racing for outputs whose keys were never revealed. It cannot
protect outputs whose public keys are already public (reused addresses).

## Dependencies
ADR-0002, ADR-0001.

## Revisit trigger
Full specification in Phase 2; review in Phase 3.
