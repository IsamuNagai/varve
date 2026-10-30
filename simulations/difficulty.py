#!/usr/bin/env python3
"""ASERT difficulty simulation for ADR-0005 (deterministic, integer target math).

The target computation is the integer aserti3-2d algorithm, the same arithmetic
a consensus implementation would use. Block discovery is simulated as a Poisson
process with a fixed random seed, so results are reproducible.

Scenarios (hashrate in multiples of the hashrate the initial target assumes):
  growth    1 -> 10 (day 2) -> 100 (day 7)
  hopper    1, then x100 arrival on day 3, departure on day 6
  exodus    1, then a 90% departure on day 3
  tswarp    steady 1; an attacker with 30% of hashrate stamps every block
            at the maximum allowed future time (+600 s)

Usage: python3 -I simulations/difficulty.py
"""
import bisect
import random

T = 300                      # target block interval, seconds
POW_LIMIT = (1 << 240) << 8  # INITIAL_TARGET x 256 (protocol/difficulty.md)
INIT_TARGET = 1 << 240       # initial target: 2^16 expected hashes per block
BASE_RATE = (1 << 16) / T    # hashes/s for "hashrate 1": one block per T at INIT_TARGET
FUTURE_LIMIT = 600           # max seconds ahead of the node clock (ADR-0005)
SEEDS = 20
DAYS = 24


def asert_target(anchor_target, time_delta, height_delta, tau):
    """ASERT (aserti3-2d arithmetic) anchored at genesis: next target after a parent block.

    time_delta   = parent timestamp - genesis timestamp
    height_delta = parent height (genesis = 0); a parent at t0 + T*h is on schedule
    """
    exponent = ((time_delta - T * height_delta) * 65536) // tau
    if exponent >= 256 << 16:
        return POW_LIMIT
    if exponent <= -(270 << 16):
        return 1
    shifts = exponent >> 16                 # arithmetic (floor) shift
    frac = exponent & 0xFFFF
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac * frac
                       + 5127 * frac * frac * frac + (1 << 47)) >> 48)
    target = anchor_target * factor
    target = target << shifts if shifts >= 0 else target >> -shifts
    target >>= 16
    return max(1, min(target, POW_LIMIT))


def median(xs):
    s = sorted(xs)
    return s[len(s) // 2]


def run(hashrate_at, tau, seed, attacker_share=0.0):
    rng = random.Random(seed)
    now = 0.0                          # true time
    stamps = [0]                       # block timestamps; genesis at 0
    true_times = [0.0]
    expected_log = [float(T)]
    anchor_parent_time, anchor_height = 0, 0
    target = INIT_TARGET
    while now < DAYS * 86400:
        rate = hashrate_at(now) * BASE_RATE                # hashes per second
        expected = ((1 << 256) / (target + 1)) / rate      # seconds per block
        now += rng.expovariate(1.0 / expected)
        mtp = median(stamps[-11:])
        if attacker_share and rng.random() < attacker_share:
            ts = int(now) + FUTURE_LIMIT                   # attacker: maximum future
        else:
            ts = int(now)
        ts = max(ts, mtp + 1)                              # median-of-11 rule
        stamps.append(ts)
        true_times.append(now)
        h = len(stamps) - 1
        target = asert_target(INIT_TARGET, stamps[h] - anchor_parent_time, h - anchor_height, tau)
        expected_log.append(((1 << 256) / (target + 1)) / (hashrate_at(now) * BASE_RATE))
    return true_times, stamps, expected_log


def window_mean_interval(true_times, start, end):
    n = bisect.bisect_left(true_times, end) - bisect.bisect_left(true_times, start)
    return (end - start) / max(1, n)


def settle_hours(true_times, expected_log, step_time, until, band=0.10):
    """Hours after step_time until the difficulty-implied interval stays within +/-10% of T."""
    i0 = bisect.bisect_left(true_times, step_time)
    i1 = bisect.bisect_left(true_times, until)
    last_bad = step_time
    for i in range(i0, i1):
        if abs(expected_log[i] - T) > band * T:
            last_bad = true_times[i]
    return (last_bad - step_time) / 3600


def extra_blocks(true_times, start, end):
    """Blocks found in [start, end) beyond the schedule's T-spacing."""
    n = bisect.bisect_left(true_times, end) - bisect.bisect_left(true_times, start)
    return n - (end - start) / T


def longest_gap_min(true_times, start, end):
    ts = true_times[bisect.bisect_left(true_times, start):bisect.bisect_left(true_times, end)]
    return max((b - a for a, b in zip(ts, ts[1:])), default=0) / 60


SCENARIOS = {
    "growth": (lambda t: 1 if t < 2 * 86400 else (10 if t < 7 * 86400 else 100), [2 * 86400, 7 * 86400]),
    "hopper": (lambda t: 100 if 3 * 86400 <= t < 6 * 86400 else 1, [3 * 86400, 6 * 86400]),
    "exodus": (lambda t: 1 if t < 3 * 86400 else 0.1, [3 * 86400]),
}

def hourly_ratio(true_times, expected_log):
    """Difficulty-implied interval / T, sampled at each hour (last block before the hour)."""
    out = []
    for hr in range(DAYS * 24):
        i = bisect.bisect_right(true_times, hr * 3600) - 1
        out.append(expected_log[max(i, 0)] / T)
    return out


def recovery_hours(median_series, step_time, until, band=0.10):
    h0, h1 = int(step_time // 3600), int(until // 3600)
    last_bad = h0
    for hr in range(h0, h1):
        if abs(median_series[hr] - 1) > band:
            last_bad = hr + 1
    return last_bad - h0


if __name__ == "__main__":
    print("Recovery = hours until the median (over %d runs) difficulty-implied block interval is" % SEEDS)
    print("within 10%% of %d s and stays there. Jitter = std. dev. of that ratio in steady state." % T)
    for tau_days in (0.25, 0.5, 1, 2):
        tau = int(tau_days * 86400)
        print(f"\ntau = {tau_days} day(s)")
        for name, (h, steps) in SCENARIOS.items():
            series, gaps, extra = [], [], []
            bounds = steps[1:] + [DAYS * 86400]
            for seed in range(SEEDS):
                tt, _, ex = run(h, tau, seed)
                series.append(hourly_ratio(tt, ex))
                gaps.append(max(longest_gap_min(tt, s0, s0 + 86400) for s0 in steps))
                if name == "hopper":
                    extra.append(extra_blocks(tt, steps[0], DAYS * 86400))
            med = [sorted(col)[SEEDS // 2] for col in zip(*series)]
            rec = [recovery_hours(med, s0, u) for s0, u in zip(steps, bounds)]
            line = (f"  {name:7s} recovery after each step (h): {rec}"
                    f" | longest gap in day after a step: median {sorted(gaps)[SEEDS // 2]:.0f} min, worst {max(gaps):.0f} min")
            if extra:
                line += f" | net extra blocks over the whole episode: {sum(extra) / SEEDS:+.0f}"
            print(line)
        steady = []
        for seed in range(SEEDS):
            tt, _, ex = run(lambda t: 1, tau, seed)
            steady += hourly_ratio(tt, ex)[48:]
        mu = sum(steady) / len(steady)
        sd = (sum((x - mu) ** 2 for x in steady) / len(steady)) ** 0.5
        base = [window_mean_interval(run(lambda t: 1, tau, s0)[0], 3 * 86400, DAYS * 86400) for s0 in range(SEEDS)]
        attk = [window_mean_interval(run(lambda t: 1, tau, s0, attacker_share=0.30)[0], 3 * 86400, DAYS * 86400) for s0 in range(SEEDS)]
        b, a = sum(base) / SEEDS, sum(attk) / SEEDS
        print(f"  steady  jitter {sd * 100:.1f}% | timestamp attack (30% hashrate, +600 s stamps): "
              f"mean interval {b:.1f} s -> {a:.1f} s ({(a - b) / b * 100:+.2f}%)")
