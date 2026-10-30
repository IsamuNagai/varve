# ADR-0004: Monetary policy

## Status
ACCEPTED for specification v0.1 (2026-10-30). Exact constants are in protocol/subsidy.md.

## Context
Issuance must be deterministic, auditable, and encoded in consensus. It
determines how fairly early supply is distributed and whether miners are paid
when fee demand is low.

## Requirements
- Integer-only computation from block height; no floating point.
- No party can change issuance.
- Slower early distribution than Bitcoin-style halvings.
- A non-zero long-run security budget.

## Options
Normalized supply (100 = model A's cap):

| Model | Y1 | Y10 | Y20 | Y50 | Y100 | Inflation Y20 / Y50 / Y100 |
| --- | --- | --- | --- | --- | --- | --- |
| A. 4-year halvings, cap | 12.5 | 81.3 | 96.9 | 100.0 | 100.0 | 0.8% / 0% / 0% |
| B. Smooth, 4-year half-life, cap | 15.9 | 82.3 | 96.9 | 100.0 | 100.0 | 0.6% / 0% / 0% |
| C. B + fixed tail | 15.9 | 82.3 | 97.2 | 121.2 | 161.2 | 0.8% / 0.7% / 0.5% |
| E. 40-year half-life, cap | 1.7 | 15.9 | 29.3 | 58.0 | 82.3 | 4.4% / 1.3% / 0.4% |
| **F. Smooth, 8-year half-life + fixed tail** | **8.3** | **58.0** | **82.3** | **104.6** | **134.6** | **2.0% / 0.6% / 0.45%** |

Reproduce with `simulations/issuance.py`.

## Decision
**Model F.** The block subsidy decays smoothly with an 8-year half-life until it
reaches a fixed tail. From then on, the subsidy stays constant forever.

- Initial subsidy 82 varve per block; tail 6 varve per block, reached at
  block 3,182,059 (about year 30).
- Epoch = 13,149 blocks (1/64 of an 8-year half-life at 300 s).
  `subsidy = max(TAIL, (INITIAL × FRAC[e mod 64]) >> (63 + e div 64))`, using
  64 consensus constants proven exact (simulations/subsidy.py).
- Supply: 8.31 M (year 1), 58.0 M (10), 82.4 M (20), 105.3 M (50), 136.8 M (100).
  Inflation is 0.60% at year 50 and 0.46% at year 100.
- Amounts are u64 laminae. The total stays far below 2^63 for over 100,000 years.

## Rationale
- Halving first-year issuance relative to model A reduces the share captured
  while the network is small and least decentralized.
- A fixed absolute tail drives inflation toward zero while guaranteeing miner
  revenue and offsetting lost coins.

## Security implications
Under a hard cap, security in later decades depends entirely on fees. A tail
removes that dependence, but needs social acceptance of perpetual, decreasing
inflation.

## Tradeoffs
There is no "fixed supply" message. Supply is predictable, but not capped.

## Rejected alternatives
A (front-loaded, fee-only security), B (same), D (high fixed issuance),
E (too inflationary for decades), and percentage tails (perpetual inflation).

## Dependencies
protocol/subsidy.md, ADR-0005, Phase 4 simulation.

## Revisit trigger
Phase 4 fee and security modelling showing that the tail is too small to fund
security, or that early distribution is still too concentrated.
