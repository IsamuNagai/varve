# ADR-0005: Difficulty adjustment and timestamp rules

## Status
PROPOSED (2026-10-30). Parameters to be confirmed by Phase 4 hash-shock simulation.

## Context
Early hashrate may swing by orders of magnitude, for example from 1 miner to
100, a sudden ×100 arrival, or a 90% departure. Bitcoin's 2016-block retarget
can stall for weeks after a large departure and has a known time-warp weakness.

## Requirements
- Per-block responsiveness without oscillation.
- No time-warp class attacks.
- Bounded influence of any single timestamp.
- Integer-only, deterministic computation.

## Options
Bitcoin's 2016-block retarget; LWMA (linearly weighted moving average);
ASERT (absolutely scheduled exponentially rising targets, deployed on Bitcoin
Cash since November 2020 as aserti3-2d).

## Decision
**ASERT**, anchored at the block after genesis:

    target(h+1) = target_anchor * 2^((t_h - t_anchor - T * (h - h_anchor)) / tau)

computed with the integer cubic approximation of 2^x used by aserti3-2d.

- T = block interval (target 300 s; set by ADR-0006 / Phase 4).
- tau = 1 day (proposed; Phase 4 compares 0.5–2 days).
- Target clamped to [1, pow_limit].

**Timestamp rules:**

1. A block's timestamp must be greater than the median of the previous 11.
2. It may be at most 10 minutes ahead of the node's network-adjusted clock.
   Nodes use local time only, never peer-reported time.
3. The block after genesis must have a timestamp greater than or equal to the
   Bitcoin header timestamp bound into genesis (ADR-0008).

## Rationale
ASERT depends only on the anchor and the latest block, so there is no window
boundary to exploit (no time warp). It recovers from large departures within
hours rather than weeks, and has five years of production use.

## Security implications
Timestamp manipulation shifts difficulty by about 2^(skew/tau). A 10-minute
skew with a 1-day tau changes difficulty by under 0.5%. The median-of-11 rule
bounds backdating.

## Tradeoffs
A shorter future-time limit makes nodes with badly set clocks reject valid
blocks. Node software must warn about clock drift.

## Rejected alternatives
2016-block retarget (stalls, time warp); LWMA (windowed and more complex,
with less production evidence at this scale).

## Dependencies
ADR-0003, ADR-0006, ADR-0008, simulations/difficulty (Phase 4).

## Revisit trigger
Phase 4 simulation showing oscillation or slow recovery under the specified shocks.
