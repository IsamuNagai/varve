# ADR-0006: Block interval, weight, and fees

## Status
PROPOSED (2026-10-30). Constants are set in Phase 4.

## Context
Post-quantum signatures are kilobytes large, and SLH-DSA verification costs
thousands of hash calls. Throughput must be capped by the cost of running a
full node, not by demand.

## Requirements
- A full node runs on a roughly 5-year-old laptop over residential bandwidth.
- Chain growth stays around 50–75 GB per year at sustained full blocks.
- Verification-cost denial of service is impossible within block limits.
- Fees only allocate block space and pay miners: no burns, taxes, or developer fees.

## Decision
- **Block interval:** 300 seconds (hypothesis; Phase 4 compares 120–600 s).
- **Weight:** each transaction has
  `weight = serialized_bytes + verify_units + utxo_growth_units`.
  - `verify_units`: a fixed cost per signature, set by benchmark. ML-DSA-65
    is low; SLH-DSA-SHA2-128s is high, roughly proportional to its hash calls.
  - `utxo_growth_units`: a charge per net new output, and a discount per net
    consumed output, bounded so weight never goes negative.
- **Maximum block weight:** sized so 52,560 blocks per year × maximum weight
  is about 60 GB per year of serialized data. That gives a starting point of
  about 1.1 M weight units, to be finalized.
- **Fees:** market-priced per weight unit and paid entirely to the miner. No
  minimum fee in consensus; relay policy sets minimums.

## Rationale
One-dimensional weight that includes verification and state cost keeps miner
incentives simple while pricing each real resource. A 5-minute interval keeps
the stale rate low with large post-quantum blocks while keeping confirmations usable.

## Security implications
Without verify_units, a block full of SLH-DSA spends could take many times
longer to verify than a block of ML-DSA spends.

## Tradeoffs
About 0.5–1 transactions per second at full blocks. Varve is a settlement
layer; higher volume belongs to layers above.

## Dependencies
ADR-0002, ADR-0005, Phase 4 propagation and benchmark work.

## Revisit trigger
Benchmarks or propagation simulation outside the requirements.
