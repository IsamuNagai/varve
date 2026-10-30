#!/usr/bin/env python3
"""Generate address, commitment, and difficulty test vectors.

The public keys used here are fixed byte patterns, NOT real keys. They exercise
hashing and encoding only. Standard library only; deterministic.

Usage: python3 -I tools/gen_vectors.py
"""
import hashlib
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "simulations"))
from difficulty import asert_target  # noqa: E402

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32m_encode(hrp, data):
    values = hrp_expand(hrp) + data
    pm = polymod(values + [0] * 6) ^ BECH32M_CONST
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def bech32m_verify(s):
    if s.lower() != s and s.upper() != s:
        return False
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return False
    hrp, data = s[:pos], [CHARSET.find(c) for c in s[pos + 1:]]
    return -1 not in data and polymod(hrp_expand(hrp) + data) == BECH32M_CONST


def convertbits(data, frombits, tobits):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def h256(tag, msg):
    t = tag.encode()
    return hashlib.sha3_256(bytes([len(t)]) + t + msg).digest()


def commitment(scheme_id, pk):
    return h256("VARVE/pk/v1", scheme_id.to_bytes(2, "little") + pk)


def address(hrp, template_after_version):
    return bech32m_encode(hrp, [1] + convertbits(template_after_version, 8, 5))


# Self-test against BIP-350 valid bech32m strings before generating anything.
for valid in ("A1LQFN3A", "a1lqfn3a",
              "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx"):
    assert bech32m_verify(valid), valid
assert not bech32m_verify("a1lqfn3b")

if __name__ == "__main__":
    pk_mldsa = bytes(i % 256 for i in range(1952))        # pattern, not a key
    pk_slh = bytes((255 - i) % 256 for i in range(32))    # pattern, not a key
    c1, c2 = commitment(1, pk_mldsa), commitment(2, pk_slh)
    single = bytes([0x00]) + (1).to_bytes(2, "little") + c1
    recov = bytes([0x01]) + (1).to_bytes(2, "little") + c1 + (2).to_bytes(2, "little") + c2 + (105192).to_bytes(4, "little")
    addr = {
        "description": "Address and commitment vectors. Public keys are byte patterns, not real keys.",
        "public_key_patterns": {"mldsa65": "bytes(i % 256 for i in range(1952))",
                                "slhdsa128s": "bytes((255 - i) % 256 for i in range(32))"},
        "commitments": {"mldsa65": c1.hex(), "slhdsa128s": c2.hex()},
        "addresses": [
            {"network": "mainnet", "policy": 0, "template_hex": "01" + single.hex(), "address": address("varve", single)},
            {"network": "testnet", "policy": 0, "template_hex": "01" + single.hex(), "address": address("tvarve", single)},
            {"network": "mainnet", "policy": 1, "recovery_delay": 105192, "template_hex": "01" + recov.hex(),
             "address": address("varve", recov)},
        ],
    }
    for a in addr["addresses"]:
        assert bech32m_verify(a["address"])
        a["length"] = len(a["address"])
    lengths = [a["length"] for a in addr["addresses"]]
    assert lengths == [69, 70, 130], lengths

    init, tau, T = 1 << 240, 21600, 300
    diff = {"description": "ASERT next-target vectors anchored at genesis (INITIAL_TARGET placeholder 2^240, "
                           "POW_LIMIT = INITIAL_TARGET x 256, TAU 21600, T 300). parent_time_minus_genesis is t_h - t0.",
            "cases": []}
    for label, dt, h in [("parent is genesis", 0, 0), ("on schedule, h=1000", 300 * 1000, 1000),
                         ("one tau ahead (fast)", 300 * 100 - 21600, 100), ("one tau behind (slow)", 300 * 100 + 21600, 100),
                         ("half tau behind", 300 * 100 + 10800, 100), ("1 second behind", 300 * 100 + 1, 100),
                         ("far behind (clamped to POW_LIMIT)", 10 ** 9, 10), ("far ahead (clamped to 1)", 0, 10 ** 7)]:
        t = asert_target(init, dt, h, tau)
        diff["cases"].append({"label": label, "parent_time_minus_genesis": dt, "parent_height": h, "next_target_hex": f"{t:064x}"})

    out = os.path.join(ROOT, "test-vectors")
    os.makedirs(out, exist_ok=True)
    for name, obj in (("addresses.json", addr), ("difficulty.json", diff)):
        with open(os.path.join(out, name), "w") as fh:
            json.dump(obj, fh, indent=1)
            fh.write("\n")
    print("address lengths", lengths)
    for a in addr["addresses"]:
        print(" ", a["address"][:40] + "…")
    for c in diff["cases"]:
        print(f"  {c['label']:40s} {c['next_target_hex'][:20]}…")
