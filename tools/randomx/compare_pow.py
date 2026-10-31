#!/usr/bin/env python3
"""Compare pow_vectors output with test-vectors/pow.json. Exit 1 on any mismatch.

Usage: python3 -I compare_pow.py <pow.json> <output.txt> <mode-label>
"""
import json
import sys


def main(vec_path, out_path, label):
    with open(vec_path) as fh:
        expected = [(c["key_ascii"], c["input_hex"], c["pow_hash"]) for c in json.load(fh)["cases"]]
    with open(out_path) as fh:
        got = [tuple(line.split()) for line in fh if line.strip()]
    if got != expected:
        print(f"FAIL ({label}): RandomX output differs from pow.json")
        for e, g in zip(expected, got):
            if e != g:
                print(f"  expected {e}\n  got      {g}")
        if len(got) != len(expected):
            print(f"  expected {len(expected)} cases, got {len(got)}")
        return 1
    print(f"OK ({label}): {len(got)} vectors match")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
