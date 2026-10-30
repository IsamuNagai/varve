#!/usr/bin/env python3
"""Normalized issuance models for ADR-0004.

Exploratory only: uses floating point. The consensus subsidy will be an exact
integer table (see ADR-0004). Output is deterministic.

Usage: python3 simulations/issuance.py
"""
import math

YEARS = [1, 4, 10, 20, 50, 100]


def halvings(t, half=4.0):
    s, n = 0.0, int(t // half)
    for i in range(n):
        s += 50 / 2 ** i
    return s + (t - n * half) * (50 / half) / 2 ** n


def smooth(t, half):
    return 100 * (1 - math.exp(-math.log(2) / half * t))


def smooth_tail(t, half, tail):
    k = math.log(2) / half
    ts = math.log(100 * k / tail) / k  # year the decaying rate falls to the tail
    if t <= ts:
        return smooth(t, half)
    return smooth(ts, half) + tail * (t - ts)


MODELS = {
    "A halvings 4y, cap": halvings,
    "B smooth 4y, cap": lambda t: smooth(t, 4),
    "C smooth 4y + tail 0.8": lambda t: smooth_tail(t, 4, 0.8),
    "E smooth 40y, cap": lambda t: smooth(t, 40),
    "F smooth 8y + tail 0.6": lambda t: smooth_tail(t, 8, 0.6),
}

if __name__ == "__main__":
    for name, f in MODELS.items():
        print(name)
        for y in YEARS:
            s = f(y)
            issued = s - f(y - 1)
            infl = f"{issued / f(y - 1) * 100:6.2f}%" if y > 1 else "     -"
            print(f"  year {y:>3}: supply {s:7.2f}  issued {issued:6.3f}  inflation {infl}")
