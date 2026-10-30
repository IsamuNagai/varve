#!/usr/bin/env python3
"""Capacity, chain-growth, verification-load and stale-rate model for ADR-0006.

Deterministic arithmetic only. Transaction sizes follow protocol/transactions.md
(draft). Signature timings come from simulations/benchmarks/pq-signatures.txt.

Usage: python3 -I simulations/capacity.py
"""
import math

SECONDS_PER_YEAR = 365.25 * 86400

# --- serialized sizes (bytes), see protocol/transactions.md ------------------
TX_FIXED = 4 + 4            # version u32 + locktime u32
INPUT = 32 + 4              # prev txid + index u32
OUTPUT_SINGLE = 8 + 1 + 1 + 2 + 32          # amount, version, policy, scheme, commitment
OUTPUT_RECOVERY = OUTPUT_SINGLE + 2 + 32 + 4  # + recovery scheme, commitment, delay
WITNESS = {                 # per input: path byte + pubkey (len+bytes) + signature (len+bytes)
    "ML-DSA-65": 1 + (2 + 1952) + (2 + 3309),
    "SLH-DSA-SHA2-128s": 1 + (1 + 32) + (2 + 7856),
}
VERIFY_US = {"ML-DSA-65": 33.9, "SLH-DSA-SHA2-128s": 573.9}   # measured, 2.1 GHz Xeon core
VERIFY_UNITS = {"ML-DSA-65": 100, "SLH-DSA-SHA2-128s": 1700}  # proposed weight per signature
UTXO_UNITS_PER_NET_OUTPUT = 100


def varint_len(n):
    return 1 if n < 128 else 2


def tx_size(n_in, n_out, scheme="ML-DSA-65", recovery_outputs=0):
    base = TX_FIXED + varint_len(n_in) + varint_len(n_out) + n_in * INPUT
    base += (n_out - recovery_outputs) * OUTPUT_SINGLE + recovery_outputs * OUTPUT_RECOVERY
    return base + n_in * WITNESS[scheme]


def tx_weight(n_in, n_out, scheme="ML-DSA-65", recovery_outputs=0):
    w = tx_size(n_in, n_out, scheme, recovery_outputs) + n_in * VERIFY_UNITS[scheme]
    return w + UTXO_UNITS_PER_NET_OUTPUT * max(0, n_out - n_in)


def stale_rate(interval_s, delay_s):
    return 1 - math.exp(-delay_s / interval_s)


if __name__ == "__main__":
    print("Transaction sizes (bytes / weight)")
    for label, args in [("1-in 2-out ML-DSA-65", (1, 2)),
                        ("2-in 2-out ML-DSA-65", (2, 2)),
                        ("1-in 2-out, both outputs with recovery path", (1, 2, "ML-DSA-65", 2)),
                        ("1-in 1-out SLH-DSA recovery spend", (1, 1, "SLH-DSA-SHA2-128s"))]:
        print(f"  {label:45s} {tx_size(*args):6d} B   weight {tx_weight(*args):6d}")
    typical = tx_weight(1, 2)

    print("\nBlock weight limit vs. growth and throughput at sustained full blocks")
    for interval in (120, 300, 600):
        blocks = SECONDS_PER_YEAR / interval
        for gb_year in (50, 75, 100):
            w = gb_year * 1e9 / blocks
            tps = (w / typical) / interval
            print(f"  interval {interval:3d} s  target {gb_year:3d} GB/yr -> max weight {w / 1e3:6.0f} k, "
                  f"{w / typical:5.0f} typical tx/block, {tps:.2f} tx/s")

    W, interval = 720_000, 300
    print(f"\nChosen: max weight {W:,}, interval {interval} s")
    print(f"  chain growth at full blocks: {W * SECONDS_PER_YEAR / interval / 1e9:.1f} GB/yr")
    print(f"  throughput: {W / typical / interval:.2f} typical tx/s, {W / typical:.0f} tx/block")
    worst = {}
    for s in WITNESS:
        per_input_weight = INPUT + WITNESS[s] + VERIFY_UNITS[s]
        n = W // per_input_weight
        worst[s] = n * VERIFY_US[s] / 1000
        print(f"  worst-case verification, block of {s} spends: {n} signatures, {worst[s]:.1f} ms on one core")
    print("  (without verification units an SLH-only block would hold "
          f"{W // (INPUT + WITNESS['SLH-DSA-SHA2-128s'])} signatures)")

    print("\nStale-block rate estimate (exponential model, delay = latency + transfer + validation)")
    for interval in (120, 300, 600):
        for relay, transfer in (("compact relay", 0.3), ("full block, 6 hops at 10 Mbit/s", 6 * W * 8 / 10e6)):
            d = 2.0 + transfer + worst["ML-DSA-65"] / 1000
            print(f"  interval {interval:3d} s, {relay:32s} delay {d:5.1f} s -> stale {stale_rate(interval, d) * 100:.2f}%")
