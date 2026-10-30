#!/usr/bin/env python3
"""Canonical consensus-parameter list and params_hash (protocol/params.md).

Serialization, for each entry in the order below:
    u8(len(name)) || name (ASCII) || value
with value encoded by type: u8/u16/u32/u64 little-endian; u256 as 32 bytes
little-endian; bytes as varint(length) || bytes.

params_hash = H256("VARVE/params/v1", serialization)

The release candidate freezes the "mainnet" set. "draft" uses placeholders
(INITIAL_TARGET = 2^240, Bitcoin anchor fields zero) and is NOT a launch set.
Standard library only; deterministic.

Usage: python3 -I tools/params.py
"""
import hashlib
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "simulations"))
from subsidy import FRAC, INITIAL_SUBSIDY, TAIL_SUBSIDY, BLOCKS_PER_EPOCH  # noqa: E402


def h256(tag, msg):
    t = tag.encode()
    return hashlib.sha3_256(bytes([len(t)]) + t + msg).digest()


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


FRAC_BYTES = b"".join(x.to_bytes(8, "little") for x in FRAC)

PARAMS = [  # (name, type, value)
    ("NETWORK_ID", "bytes", b"VARV"),
    ("BLOCK_VERSION", "u32", 1),
    ("TX_VERSION", "u32", 1),
    ("OUTPUT_VERSION", "u8", 1),
    ("MAX_MONEY", "u64", 2 ** 62),
    ("COINBASE_MATURITY", "u32", 288),
    ("COINBASE_EXTRA_MAX", "u32", 64),
    ("MAX_BLOCK_WEIGHT", "u64", 720_000),
    ("UTXO_GROWTH_UNITS", "u32", 100),
    ("RECOVERY_DELAY_MAX", "u32", 2 ** 31 - 1),
    ("SCHEME_0001_ALG", "bytes", b"ML-DSA-65"),
    ("SCHEME_0001_PK_LEN", "u32", 1952),
    ("SCHEME_0001_SIG_LEN", "u32", 3309),
    ("SCHEME_0001_VERIFY_UNITS", "u32", 100),
    ("SCHEME_0002_ALG", "bytes", b"SLH-DSA-SHA2-128s"),
    ("SCHEME_0002_PK_LEN", "u32", 32),
    ("SCHEME_0002_SIG_LEN", "u32", 7856),
    ("SCHEME_0002_VERIFY_UNITS", "u32", 1700),
    ("TARGET_SPACING", "u32", 300),
    ("ASERT_TAU", "u32", 21_600),
    ("MTP_WINDOW", "u32", 11),
    ("MAX_FUTURE_DRIFT", "u32", 600),
    ("INITIAL_SUBSIDY", "u64", INITIAL_SUBSIDY),
    ("TAIL_SUBSIDY", "u64", TAIL_SUBSIDY),
    ("BLOCKS_PER_EPOCH", "u32", BLOCKS_PER_EPOCH),
    ("SUBSIDY_FRAC_Q63", "bytes", FRAC_BYTES),
    ("POW_ALGORITHM", "bytes", b"RandomX-v2"),
    ("RANDOMX_ARGON_SALT", "bytes", b"VarveRX\x01"),
    ("RANDOMX_KEY_EPOCH", "u32", 2048),
    ("RANDOMX_KEY_LAG", "u32", 64),
]

DRAFT_LAUNCH = [  # placeholders until release-candidate freeze
    ("INITIAL_TARGET", "u256", 2 ** 240),
    ("POW_LIMIT", "u256", 2 ** 240 * 256),          # always INITIAL_TARGET x 256
    ("BTC_ANCHOR_HEIGHT", "u32", 0),
    ("BTC_ANCHOR_PREV_HASH", "bytes", bytes(32)),
    ("BTC_ANCHOR_BITS", "u32", 0),
]

WIDTH = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "u256": 32}


def serialize(entries):
    out = bytearray()
    for name, typ, value in entries:
        n = name.encode("ascii")
        assert len(n) < 256
        out += bytes([len(n)]) + n
        if typ == "bytes":
            out += varint(len(value)) + value
        else:
            assert 0 <= value < 2 ** (8 * WIDTH[typ]), name
            out += value.to_bytes(WIDTH[typ], "little")
    return bytes(out)


if __name__ == "__main__":
    entries = PARAMS + DRAFT_LAUNCH
    vals = {n: val for n, _, val in entries}
    assert vals["POW_LIMIT"] == vals["INITIAL_TARGET"] * 256
    names = [e[0] for e in entries]
    assert len(names) == len(set(names))
    ser = serialize(entries)
    ph = h256("VARVE/params/v1", ser)
    doc = {
        "description": "Draft consensus parameter set. Placeholders for launch fields; NOT a mainnet set.",
        "set": "draft",
        "serialization_hex_sha256": hashlib.sha256(ser).hexdigest(),
        "serialization_length": len(ser),
        "params_hash": ph.hex(),
        "entries": [{"name": n, "type": t, "value": (v.hex() if isinstance(v, bytes) else str(v))} for n, t, v in entries],
    }
    with open(os.path.join(ROOT, "test-vectors", "params.json"), "w") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    print(f"{len(entries)} parameters, {len(ser)} bytes, draft params_hash {ph.hex()}")
