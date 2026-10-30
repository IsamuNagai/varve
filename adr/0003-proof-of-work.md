# ADR-0003: Proof-of-work algorithm

## Status
PROPOSED (2026-10-30). Working choice only; must be confirmed after the Phase 3
threat model.

## Context
New units enter circulation through open computational competition. No PoW
algorithm makes a small new chain secure against an attacker with access to
large external hashrate. The choice decides who can cheaply attack the chain
and who can participate in mining.

## Requirements
- Use an established, audited algorithm; do not invent one.
- Reduce the advantage of specialized hardware where practical, without
  claiming ASIC resistance.
- Verification must remain feasible on commodity hardware.
- Implementation must be identical for every participant, including the author.

## Options
| Option | Participation | Rental / redirect risk on a small chain | Verification cost | Maturity |
| --- | --- | --- | --- | --- |
| RandomX v2, distinct parameters | CPUs; commercial ASICs exist for v1 | Moderate–high | Heavy (256 MB light mode) | v1 audited 2019; v2 needs review |
| SHA-256d | ASIC only | Extreme (idle Bitcoin hardware) | Trivial | 17 years |
| Equi-X / HashX | CPUs | Moderate | Light | Not used for money |
| KawPow | GPUs | High | Moderate | Production |
| Novel algorithm | Unknown | Low at first | Unknown | None |

## Decision
**Working choice: RandomX v2**, with a Varve-specific parameter set that changes
only parameters classified as safe in the 2019 audits, so it is distinct from
Monero's. **SHA-256d is the documented fallback.** Merge-mining is excluded from v1.

## Rationale
RandomX best matches open participation. On SHA-256d, a negligible slice of
existing Bitcoin hashrate could overwhelm a new chain. A distinct parameter set
prevents trivial redirection of existing pool infrastructure, though not
determined rental.

## Security implications
- Botnet and malware incentive is real for CPU-friendly PoW.
- Specialized hardware for RandomX exists; its advantage may grow.
- Hashrate rental and selfish mining are serious risks in early years
  (Monero suffered 6- and 18-block reorgs in 2025).
- Early-life defence is operational: published confirmation guidance and reorg
  monitoring. No checkpoints, because they are an authority.

## Tradeoffs
Heavier header verification, which is unfriendly to light clients and phones.

## Rejected alternatives
A novel algorithm (unaudited, invites private optimization). KawPow (no
fairness gain). Merge-mining (couples security to another chain's miners).

## Dependencies
ADR-0005 (difficulty), ADR-0008 (fair launch), threat model T-M1 to T-M4.

## Revisit trigger
- The RandomX v2 security review finds an algorithmic shortcut.
- Phase 3 rental-attack analysis shows unacceptable risk compared with SHA-256d.
- Specialized hardware exceeds about 10× CPU efficiency per joule.
