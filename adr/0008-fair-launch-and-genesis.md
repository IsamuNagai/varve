# ADR-0008: Fair launch and genesis construction

## Status
PROPOSED (2026-10-30). Requires adversarial review in Phase 3.

## Context
The launch is part of the credibility model. Nobody, including the author,
may hold spendable coins at genesis or begin mining before others.

## Requirements
- No spendable output in genesis.
- Genesis cannot be computed before a public, unpredictable event.
- No ongoing dependence on any external system or oracle.
- Every frozen consensus parameter is bound to genesis.

## Decision
1. The release-candidate client hardcodes a Bitcoin target height **H**, the
   hash of Bitcoin block **H−1**, and the exact `nBits` of the Bitcoin
   difficulty period containing H … H+5. That period has already begun at
   freeze time, so its `nBits` is known.
2. The node takes the 80-byte Bitcoin headers for heights H to H+5, verifies
   their linkage from H−1, and verifies that each has exactly that `nBits`
   and valid proof of work.
3. `seed = H256("VARVE/genesis/v1", params_hash || header_H || … || header_{H+5})`.
   The seed covers **all six** headers, so it cannot be computed before
   Bitcoin block H+5 exists.
4. The genesis timestamp t0 is the upper median of the six Bitcoin header
   timestamps.
5. The genesis coinbase pays zero, to an unspendable output. Genesis contains
   no other transactions.
6. Block 1 needs `timestamp > t0`. Initial difficulty is a published constant;
   ASERT adapts from block 1.

protocol/genesis.md is authoritative.

After genesis, Bitcoin is never consulted again.

## Launch sequence
Spec v1.0 → source, wallet, and the exact reference miner published →
reproducible builds by at least 2 independent builders → release-candidate
testnet using the same genesis mechanism → parameter freeze and announcement
of H → Bitcoin block H+5 mined → anyone can derive genesis and start mining.

## Rationale
No party, including the author, learns genesis before Bitcoin block H+5 is
public. The only possible head start goes to the miner of H+5, who would have
to withhold a valid Bitcoin block. Requiring Bitcoin's real `nBits` makes
forged headers as expensive as real Bitcoin blocks. Using the median timestamp
means no single Bitcoin miner controls t0.

**Correction note:** the first draft hashed only `header_H`. That would have
let anyone with modified software compute genesis about 50 minutes early. An
independent review found the flaw, and it was fixed before any release.

## Security implications
- Prevents premine, hidden genesis balances, and pre-mined chains.
- Does not prevent day-one hashrate rental (ADR-0003, threat T-M1).
- Pre-release builds refuse mainnet parameters, to prevent accidental early mining.

## Tradeoffs
A one-time procedural dependency on Bitcoin's header chain at launch.

## Dependencies
ADR-0003, ADR-0005, protocol/genesis.md.

## Revisit trigger
Phase 3 finds a way to learn genesis early or to bias it.
