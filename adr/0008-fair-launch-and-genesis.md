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
1. The release-candidate client hardcodes a Bitcoin target height **H** (set
   about two weeks ahead at freeze time) and the hash of Bitcoin block **H−1**.
2. At startup, the node takes the 80-byte Bitcoin headers for heights H to H+5
   from any source. It verifies that they link back to H−1, and verifies each
   header's proof of work against a hardcoded minimum target.
3. `genesis_hash_input = SHA-256d("VARVE/genesis/v1" || params_hash || header_H)`,
   where `params_hash` commits to every consensus constant.
4. The genesis coinbase pays zero, to an unspendable output. Genesis contains
   no other transactions.
5. Block 1 must carry a timestamp of at least `header_H.time` (ADR-0005).
6. Initial difficulty is a published constant. ASERT adapts from block 1.

After genesis, Bitcoin is never consulted again.

## Launch sequence
Spec v1.0 → source, wallet, and the exact reference miner published →
reproducible builds by at least 2 independent builders → release-candidate
testnet using the same genesis mechanism → parameter freeze and announcement
of H → Bitcoin block H+5 mined → anyone can derive genesis and start mining.

## Rationale
Requiring six linked headers means a one-block Bitcoin reorg cannot produce
two genesis candidates. No party, including the author, learns genesis before
the public does.

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
