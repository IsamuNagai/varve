#!/usr/bin/env python3
"""Generate test-vectors/genesis.json: Bitcoin-anchor validation cases (genesis.md §2).

The valid fixture is Bitcoin mainnet blocks 0-5. These are public, PoW-checked
headers; anyone can confirm the block hashes against any Bitcoin node. They are
a FIXTURE ONLY: the real launch anchor will be six blocks mined after the
launch announcement.

The illustrative genesis id uses the DRAFT params_hash and is NOT the Varve genesis.

Usage: python3 -I tools/gen_genesis_vectors.py
"""
import json
import os
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "prototype"))
import varve_proto as v  # noqa: E402

# Bitcoin mainnet heights 0..5: (merkle root, time, nonce), display (big-endian) hex.
BTC = [
    ("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", 1231006505, 2083236893),
    ("0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098", 1231469665, 2573394689),
    ("9b0fc92260312ce44e74ef369f5c66bbb85848f2eddd5a7a1cde251e54ccfdd5", 1231469744, 1639830024),
    ("999e1c837c76a1b7fbb7e57baf87b309960f5ffefbf2a9b95dd890602272f644", 1231470173, 1844305925),
    ("df2b060fa2e5e9c8ed5eaf6a45c13753ec8c63282b2688322eba40cd98ea067a", 1231470988, 2850094635),
    ("63522845d294ee9b0188ae5cac91bf389a0c3723f084ca1025e7d9cdfe481ce1", 1231471428, 2011431709),
]
BITS = 0x1D00FFFF
EXPECTED_HASHES = [
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
    "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
    "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
    "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",
    "000000009b7262315dbf071787ad3656097b892abffd1f95a1a022f896f533fc",
]


def build():
    hs, prev = [], bytes(32)
    for mr, t, n in BTC:
        x = struct.pack("<I", 1) + prev + bytes.fromhex(mr)[::-1] + struct.pack("<III", t, BITS, n)
        prev = v.sha256d(x)
        hs.append(x)
    got = [v.sha256d(x)[::-1].hex() for x in hs]
    assert got == EXPECTED_HASHES, "fixture does not reproduce known Bitcoin block hashes"
    return hs


def synthetic(bits):
    """Six linked headers mined (deterministically) at an easy target ABOVE Bitcoin's powLimit.
    TEST ONLY: they exist to show that the powLimit rule is enforced on its own."""
    target, prev, out = v.btc_compact_to_target(bits), bytes(32), []
    for k in range(6):
        for nonce in range(1 << 32):
            x = (struct.pack("<I", 1) + prev + v.h256("VARVE/test/btc-merkle", bytes([k]))
                 + struct.pack("<III", 1_900_000_000 + 600 * k, bits, nonce))
            if int.from_bytes(v.sha256d(x), "little") <= target:
                break
        out.append(x)
        prev = v.sha256d(x)
    return out


def case(name, headers, height=0, prev=bytes(32), bits=BITS):
    try:
        v.check_btc_anchor(headers, height, prev, bits)
        result = "valid"
    except v.Invalid as e:
        result = str(e)
    return {"name": name, "anchor_height": height, "anchor_prev_hash_internal": prev.hex(),
            "anchor_bits": f"0x{bits:08x}", "headers": [x.hex() for x in headers], "result": result}


def mutate(hs, k, off, val):
    out = list(hs)
    x = bytearray(out[k])
    x[off:off + len(val)] = val
    out[k] = bytes(x)
    return out


def main():
    hs = build()
    cases = [
        case("bitcoin mainnet 0-5", hs),
        case("wrong anchor prev hash", hs, prev=b"\x01" + bytes(31)),
        case("header 3 prev broken", mutate(hs, 3, 4, b"\x00")),
        case("header 2 nBits differs", mutate(hs, 2, 72, struct.pack("<I", 0x1D00FFFE))),
        case("anchor bits differ from headers", hs, bits=0x1C00FFFF),
        case("header 5 nonce changed (proof of work)", mutate(hs, 5, 76, struct.pack("<I", 0))),
        case("header 0 time changed (proof of work)", mutate(hs, 0, 68, struct.pack("<I", 1231006506))),
        case("negative compact", hs, bits=0x1D80FFFF),
        case("overflow compact", hs, bits=0x2200FFFF),
        case("zero compact", hs, bits=0x1D000000),
        case("compact shifts to zero", hs, bits=0x01003456),
        case("anchor nBits above Bitcoin powLimit", hs, bits=0x1D01FFFF),
        case("period boundary: H mod 2016 = 2011", hs, height=2011),
        case("period edge: H mod 2016 = 2010 (structurally allowed)", hs, height=2010),
        case("synthetic headers, nBits 0x2000ffff: linkage and PoW valid, only the powLimit rule rejects",
             synthetic(0x2000FFFF), bits=0x2000FFFF),
        case("only five headers", hs[:5]),
        case("headers out of order", [hs[1], hs[0]] + hs[2:]),
    ]
    compact = []
    for bits in (0x1D00FFFF, 0x1B0404CB, 0x170331DB, 0x03123456, 0x02123456, 0x01120000, 0x04923456,
                 0x04800000, 0x00000000, 0x21010000, 0x2100FFFF, 0x22000001, 0x20FFFFFF, 0xFF123456):
        try:
            t = v.btc_compact_to_target(bits)
            compact.append({"bits": f"0x{bits:08x}", "target": f"{t:064x}"})
        except v.Invalid as e:
            compact.append({"bits": f"0x{bits:08x}", "result": str(e)})
    params = json.load(open(os.path.join(ROOT, "test-vectors", "params.json")))
    g = v.genesis_block(bytes.fromhex(params["params_hash"]), hs, 2 ** 240)
    out = {
        "_comment": ("Genesis anchor validation (protocol/genesis.md §2). Valid fixture = Bitcoin mainnet "
                     "blocks 0-5, FIXTURE ONLY. Hashes inside headers are internal byte order. "
                     "'result' is 'valid' or the prototype's first rejection reason. "
                     "The example genesis uses the DRAFT params_hash and INITIAL_TARGET 2^240; it is NOT "
                     "the Varve genesis. Regenerate: python3 -I tools/gen_genesis_vectors.py"),
        "bitcoin_block_hashes": EXPECTED_HASHES,
        "anchor_cases": cases,
        "compact_cases": compact,
        "example_genesis": {
            "params_hash": params["params_hash"],
            "initial_target": f"{2**240:064x}",
            "t0": g.header.timestamp,
            "coinbase_txid": g.txs[0].txid().hex(),
            "tx_root": g.header.tx_root.hex(),
            "header": g.header.serialize().hex(),
            "block_id": g.header.block_id().hex(),
        },
    }
    with open(os.path.join(ROOT, "test-vectors", "genesis.json"), "w") as fh:
        json.dump(out, fh, indent=1)
        fh.write("\n")
    for c in cases:
        print(f"{c['result']:45s} {c['name']}")


if __name__ == "__main__":
    main()
