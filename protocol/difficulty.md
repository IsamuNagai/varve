# Difficulty and timestamps (normative, draft v0.2)

## 1. Constants

| Name | Value | Note |
| --- | --- | --- |
| `TARGET_SPACING` (T) | 300 s | ADR-0006 |
| `TAU` | 21,600 s (6 hours, 72 blocks) | from `simulations/difficulty.py` |
| `INITIAL_TARGET` | set at release-candidate freeze from testnet hashrate; < 2^244 (draft placeholder 2^240) | ADR-0008 |
| `POW_LIMIT` | `INITIAL_TARGET × 256` | easiest permitted target |
| `MTP_WINDOW` | 11 | |
| `MAX_FUTURE_DRIFT` | 600 s | acceptance only (blocks.md §4) |

## 2. Next target (ASERT, aserti3-2d arithmetic, anchored at genesis)

Genesis has height 0, timestamp `t0` and target `INITIAL_TARGET`. For a block
whose parent has height `h` and timestamp `t_h`:

    exponent = floor(((t_h − t0) − T × h) × 65536 / TAU)     # signed; floor toward −∞
    if exponent ≥ 256 × 65536:   return POW_LIMIT
    if exponent ≤ −270 × 65536:  return 1
    shifts   = floor(exponent / 65536)                        # equivalently exponent >> 16, arithmetic
    frac     = exponent − shifts × 65536                      # 0 ≤ frac < 65536
    factor   = 65536 + ((195766423245049 × frac
                         + 971821376 × frac^2
                         + 5127 × frac^3
                         + 2^47) >> 48)
    t        = INITIAL_TARGET × factor
    t        = (shifts ≥ 0) ? t << shifts : t >> (−shifts)
    t        = t >> 16
    next_target = clamp(t, 1, POW_LIMIT)

A parent at `t0 + T × h` is exactly on schedule and yields `INITIAL_TARGET`.
Each `TAU` seconds behind schedule doubles the target (easier); each `TAU`
ahead halves it.

**Integer bounds.**

- `t_h − t0` is a signed difference of u64 values. The early returns bound
  `|exponent|` before any shift. Implementations MUST compute with at least
  128-bit signed intermediates, or with unbounded integers.
- After the early returns, `frac < 2^16`, `factor < 2^17`,
  `INITIAL_TARGET × factor < 2^261`, and `shifts < 256`. So `t` fits in 517
  bits before the final shift, and the clamp brings it back below 2^252.
- Implementations using fixed widths MUST use at least 520-bit unsigned
  arithmetic for `t`, or MUST clamp to `POW_LIMIT` as soon as the shifted
  value exceeds it.

## 3. Timestamp rules

1. **Median time past.** `MTP(parent)` = `sorted(S)[len(S) / 2]`, using integer
   division and zero-based indexing. S is the timestamps of the parent and its
   ancestors, at most `MTP_WINDOW` of them, nearest first, including genesis.
   For even `len(S)` this is the upper of the two middle values.
   A block is valid only if `timestamp > MTP(parent)`. For block 1, S = [t0],
   so the rule is `timestamp > t0`.
2. **Future drift** (acceptance rule, blocks.md §4): blocks more than
   `MAX_FUTURE_DRIFT` ahead of the node's own clock are deferred, never marked
   invalid. Nodes never use peer-supplied time.
3. Timestamps are u64. No wraparound occurs before the year 292,277,026,596.

## 4. Simulation basis (informative)

From `simulations/difficulty-results.txt`, 20 runs per case:

| Case | Recovery to within 10% of T, tau = 6 h |
| --- | --- |
| 10× growth | 19–20 h |
| 90% departure | 38 h |
| 100× hashrate hopper, after departure | 62 h |

- Steady-state jitter is 7.1%.
- A 30% miner stamping +600 s changes the mean interval by +0.06%.
- Hopping gave no net extra blocks.
- **Residual risk:** after a large departure, block gaps of several hours occur
  (worst observed: 21 h after a 100× hopper leaves).
