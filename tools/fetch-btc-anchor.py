#!/usr/bin/env python3
"""Fetch and verify six consecutive Bitcoin headers H..H+5 for a genesis anchor (genesis.md).

Each header is fetched from several independent public explorers. They must agree
byte for byte, link to each other, carry one nBits, and meet Bitcoin's proof of work.
H+5 must be buried under at least --min-depth further blocks.

  python3 -I tools/fetch-btc-anchor.py --height H
  python3 -I tools/fetch-btc-anchor.py --auto        # latest H with H mod 2016 <= 2010, buried >= min depth

Output: one JSON object (anchor height, prev hash, bits, six header hexes, t0).
Standard library only. Needs internet access (run it on any machine or in CI).
"""
import argparse
import hashlib
import json
import sys
import urllib.request

SOURCES = ["https://blockstream.info/api", "https://mempool.space/api"]
BTC_POW_LIMIT = 0xFFFF << 208


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "varve-anchor-tool"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode().strip()


def agree(path):
    vals = {get(s + path) for s in SOURCES}
    if len(vals) != 1:
        sys.exit(f"sources disagree on {path}: {vals}")
    return vals.pop()


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact(bits):
    size, word = bits >> 24, bits & 0x7FFFFF
    t = word >> (8 * (3 - size)) if size <= 3 else word << (8 * (size - 3))
    if (word and bits & 0x800000) or t >> 256 or t == 0 or t > BTC_POW_LIMIT:
        sys.exit(f"bad nBits {bits:#x}")
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--height", type=int)
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--min-depth", type=int, default=6)
    a = ap.parse_args()
    tip = int(agree("/blocks/tip/height"))
    if a.auto:
        h = tip - 5 - a.min_depth
        while h % 2016 > 2010:
            h -= 1
    else:
        h = a.height
    if h is None or h < 1 or h + 5 + a.min_depth > tip:
        sys.exit(f"height {h} not buried enough (tip {tip})")
    if h % 2016 > 2010:
        sys.exit("H..H+5 would cross a difficulty period")
    prev_hash_display = agree(f"/block-height/{h - 1}")
    headers = []
    for k in range(6):
        bh = agree(f"/block-height/{h + k}")
        hx = agree(f"/block/{bh}/header")
        raw = bytes.fromhex(hx)
        assert len(raw) == 80
        if sha256d(raw)[::-1].hex() != bh:
            sys.exit(f"header {h + k} does not hash to its block id")
        headers.append(raw)
    prev = bytes.fromhex(prev_hash_display)[::-1]
    bits = int.from_bytes(headers[0][72:76], "little")
    target = compact(bits)
    p = prev
    for x in headers:
        assert x[4:36] == p, "linkage"
        assert int.from_bytes(x[72:76], "little") == bits, "nBits differ"
        hsh = sha256d(x)
        assert int.from_bytes(hsh, "little") <= target, "proof of work"
        p = hsh
    times = sorted(int.from_bytes(x[68:72], "little") for x in headers)
    print(json.dumps({
        "btc_anchor_height": h,
        "btc_anchor_prev_hash_internal": prev.hex(),
        "btc_anchor_bits": f"0x{bits:08x}",
        "headers": [x.hex() for x in headers],
        "t0": times[3],
        "tip_at_fetch": tip,
        "sources": SOURCES,
    }, indent=1))


if __name__ == "__main__":
    main()
