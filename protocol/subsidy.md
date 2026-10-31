# Block subsidy (normative, draft v0.2)

| Constant | Value |
| --- | --- |
| `INITIAL_SUBSIDY` | 8,200,000,000 laminae (82 varve) |
| `TAIL_SUBSIDY` | 600,000,000 laminae (6 varve) |
| `BLOCKS_PER_EPOCH` | 13,149 (64 epochs = 841,536 blocks ≈ 8 years at 300 s) |
| `FRAC[0..63]` | `FRAC[k] = floor(2^63 × 2^(−k/64))`: the unique integer `v` with `v^64 × 2^k ≤ 2^4032 < (v+1)^64 × 2^k`. This definition is normative; `test-vectors/subsidy.json` lists the values |

    subsidy(0) = 0                                   # genesis
    for height ≥ 1:
        epoch   = (height − 1) / BLOCKS_PER_EPOCH    # integer division
        shift   = 63 + epoch / 64
        decayed = (shift ≥ 128) ? 0 : (INITIAL_SUBSIDY × FRAC[epoch mod 64]) >> shift
        subsidy = max(decayed, TAIL_SUBSIDY)

`INITIAL_SUBSIDY × FRAC[k]` is below 2^97, so a u128 intermediate suffices.

The `FRAC` constants are part of consensus. Implementations MUST embed the 64
listed values, not compute them. `simulations/subsidy.py` proves each value exact
with integer arithmetic (`v^64 × 2^k ≤ 2^4032 < (v+1)^64 × 2^k`).

## Resulting supply (informative)

| Year | Supply (varve) | Annual inflation |
| --- | --- | --- |
| 1 | 8.31 M | — |
| 4 | 29.32 M | 28.0% |
| 10 | 58.01 M | 7.0% |
| 20 | 82.40 M | 2.0% |
| 50 | 105.28 M | 0.60% |
| 100 | 136.84 M | 0.46% |

The tail is reached at block 3,182,059 (about year 30.2). From then on,
issuance is 631,152 varve per year forever. Supply after 1,000 years is about
705 M varve, under 1% of 2^63 laminae.

Coinbase outputs MAY claim less than the full subsidy plus fees. Unclaimed
value is not created.
