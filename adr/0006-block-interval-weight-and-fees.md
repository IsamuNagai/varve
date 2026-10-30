# ADR-0006: Block interval, weight, and fees

## Status
ACCEPTED for specification v0.1 (2026-10-30), based on
`simulations/capacity.py` and measured signature benchmarks. Revisit with
testnet propagation data.

## Context
Post-quantum signatures are kilobytes large. Throughput must be capped by the
cost of running a full node, not by demand.

## Requirements
- A full node runs on a roughly 5-year-old laptop over residential bandwidth.
- Chain growth stays at or below about 75 GB per year at sustained full blocks (decision D-008).
- Worst-case block verification is negligible compared with the block interval.
- Fees only allocate block space and pay miners: no burns, taxes, or developer fees.

## Evidence
Measured verification times, single core, 2.1 GHz Xeon (liboqs; `simulations/benchmarks/pq-signatures.txt`):

| Scheme | Verify | Sign |
| --- | --- | --- |
| ML-DSA-65 | ~29–34 µs | ~0.1 ms |
| SLH-DSA-SHA2-128s | ~0.56–0.61 ms | ~0.55 s |

At a fixed growth budget, the block interval does not change throughput. It
trades confirmation latency against stale rate:

| Interval | Stale rate, compact relay | Stale rate, full relay (6 hops, 10 Mbit/s) |
| --- | --- | --- |
| 120 s | 1.9% | 4.5% |
| 300 s | 0.8% | 1.8% |
| 600 s | 0.4% | 0.9% |

## Decision
- **Block interval:** 300 seconds.
- **Maximum block weight:** 720,000. That is 75.7 GB per year at sustained
  full blocks, or about 129 typical transactions per block (0.43 tx/s).
- **Weight:** `serialized_bytes + Σ verify_units + 100 × max(0, outputs − inputs)`.
  - `verify_units` is 100 per ML-DSA-65 signature and 1,700 per SLH-DSA-SHA2-128s
    signature, proportional to measured verification time.
- **Fees:** market-priced per weight unit and paid entirely to the miner. No
  minimum fee in consensus; relay policy sets minimums.

Typical sizes:

| Transaction | Size | Weight |
| --- | --- | --- |
| 1-in/2-out ML-DSA-65 | 5,400 B | 5,600 |
| SLH-DSA recovery spend (1-in/1-out) | 7,982 B | 9,682 |

## Rationale
Bytes dominate cost. Worst-case verification of a full block is 4.5 ms with
ML-DSA spends and 42.5 ms with SLH-DSA spends, so CPU denial of service is not
a concern at this size. verify_units keep the ratio honest for future, costlier
schemes. A 300-second interval keeps stale rates around 1% even without compact
relay, while confirmations stay usable.

## Correction note
The first draft of this ADR computed the limit using 52,560 blocks per year,
which is the count for 10-minute blocks. That gave 1.1 M weight units. The
correct count at 300 seconds is 105,192 blocks per year, which gives 720,000
for the same growth budget.

## Security implications
SLH-DSA-heavy blocks cannot exceed the CPU budget of ML-DSA-heavy blocks by
more than about 10×, and both are far below one second.

## Tradeoffs
Throughput is about 0.4 transactions per second at full blocks. Varve is a
settlement layer; higher volume belongs to layers above it.

## Dependencies
ADR-0002, ADR-0005, protocol/transactions.md §9, protocol/blocks.md §2.

## Revisit trigger
Testnet propagation measurements, or verification benchmarks on low-end
hardware, outside the requirements.
