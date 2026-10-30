# Difficulty and timestamps (normative, draft v0.1)

## 1. Constants

| Name | Value | Note |
| --- | --- | --- |
| `TARGET_SPACING` (T) | 300 s | ADR-0006 |
| `TAU` | 21,600 s (6 hours, 72 blocks) | from `simulations/difficulty.py` |
| `POW_LIMIT` | 2^252 − 1 | easiest permitted target |
| `INITIAL_TARGET` | set at release-candidate freeze from testnet hashrate (placeholder 2^240) | ADR-0008 |
| `MAX_FUTURE_DRIFT` | 600 s | |

## 2. Next target (aserti3-2d)

The anchor is the genesis block: height 0, timestamp `t0`, target `INITIAL_TARGET`.
For a block at height `h + 1` whose parent has height `h` and timestamp `t_h`:

    exponent = ((t_h − t0) − T × (h + 1)) × 65536 / TAU      # signed, floor division
    shifts   = exponent >> 16                                 # arithmetic shift (floor)
    frac     = exponent & 0xFFFF
    factor   = 65536 + ((195766423245049 × frac
                         + 971821376 × frac^2
                         + 5127 × frac^3
                         + 2^47) >> 48)
    t        = INITIAL_TARGET × factor
    t        = (shifts ≥ 0) ? t << shifts : t >> (−shifts)
    t        = t >> 16
    next_target = clamp(t, 1, POW_LIMIT)

- All arithmetic uses integers of unbounded width. An implementation MAY use
  fixed width only if it is proven not to overflow for all inputs.
- `frac^3 < 2^48` and `INITIAL_TARGET × factor < 2^258` before shifting.
- "Floor division" rounds toward negative infinity.

## 3. Timestamp rules

1. `timestamp > median(timestamps of the up to 11 most recent ancestors)`.
   For block 1 this means `timestamp > t0`.
2. **Acceptance rule, not a validity rule:** a node does not accept a block
   with `timestamp > local_clock + MAX_FUTURE_DRIFT`. It MAY accept the same
   block later. Nodes use their own clock only, never peer-supplied time.
3. Timestamps are u64. No wraparound occurs before the year 292,277,026,596.

## 4. Simulation basis (informative)

From `simulations/difficulty-results.txt`, 20 runs per case:

| Case | Recovery to within 10% of T, tau = 6 h |
| --- | --- |
| 10× growth | 18–20 h |
| 90% departure | 38 h |
| 100× hashrate hopper, after departure | 60 h |

- Steady-state jitter is 7.1%.
- A 30% miner stamping +600 s changes the mean interval by +0.05%.
- Hopping gave no net extra blocks.
- **Residual risk:** after a large departure, block gaps of several hours occur
  (worst observed: 21 h after a 100× hopper leaves).
