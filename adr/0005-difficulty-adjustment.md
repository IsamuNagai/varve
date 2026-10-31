# ADR-0005: Difficulty adjustment and timestamp rules

## Status
ACCEPTED for specification v0.1 (2026-10-30), based on `simulations/difficulty.py` (20 runs per scenario).

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
**ASERT**, anchored at genesis (height 0, timestamp t0, target INITIAL_TARGET):

    next_target(parent h) = INITIAL_TARGET * 2^((t_h - t0 - T * h) / tau)

computed with the integer cubic approximation of 2^x used by aserti3-2d. A
parent at t0 + T*h is on schedule. protocol/difficulty.md is authoritative.

- T = block interval (target 300 s; set by ADR-0006 / Phase 4).
- tau = 21,600 s (6 hours = 72 blocks). Simulation compared 6 h, 12 h, 1 day and 2 days (table below).
- Target clamped to [1, POW_LIMIT], where POW_LIMIT = INITIAL_TARGET × 256. This bounds how cheap any block can be, which limits low-work fork floods (blocks.md §6).

**Timestamp rules:**

1. A block's timestamp must be greater than the median time past:
   `sorted(S)[len(S)/2]` over the parent and up to 10 ancestors, including
   genesis. For block 1 this means `timestamp > t0`.
2. Acceptance rule: a node defers, and never marks invalid, a block more than
   10 minutes ahead of its own clock. Nodes never use peer-reported time.

## Simulation results
Recovery is the number of hours until the median difficulty-implied interval is
within 10% of T. The hopper adds 100× hashrate for 3 days.

| tau | 10× growth | 90% departure | Hopper leaves | Steady jitter | Worst gap after 90% departure |
| --- | --- | --- | --- | --- | --- |
| **6 h** | **20 h** | **38 h** | **62 h** | **7.1%** | **3.6 h** (21 h after a 100× hopper leaves) |
| 12 h | 43 h | 78 h | 123 h | 4.9% | 5.9 h |
| 1 day | 77 h | 157 h | 239 h | 3.4% | 5.1 h |
| 2 days | 120 h | 312 h | 432 h | 2.3% | 5.2 h |

A 30% miner stamping every block at +600 s shifted the mean interval by
+0.06% or less for every tau. Hopping produced no net extra blocks, except
+97 at tau = 2 days.

## Rationale
ASERT depends only on the anchor and the latest block, so there is no window
boundary to exploit (no time warp). It recovers from large departures within
hours rather than weeks, and has five years of production use.

## Security implications
Timestamp manipulation shifts the target by about 2^(skew/tau). With the
chosen tau of 6 hours (21,600 s), two effects must be kept apart:

- **One-time offset.** A block stamped the full 600 s future limit ahead
  raises the next target by at most 2^(600/21600) ≈ 1.0194, about 1.94%. The
  offset is not cumulative: the next honest timestamp undoes it, because ASERT
  is anchored to genesis and depends only on the parent's timestamp.
- **Steady-state effect.** A miner with 30% of the hashrate who stamps every
  block +600 s moves the mean block interval from 300.0 s to about 300.2 s
  (+0.06%) in simulation (`simulations/difficulty-results.txt`, tau 0.25 day).

The median-of-11 rule bounds backdating.

*Corrected 2026-10-31 (independent review, finding M-05): this paragraph
previously quoted the effect for a 1-day tau, which was not the chosen value.*

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
