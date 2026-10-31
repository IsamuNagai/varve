"""Check varve_verify against every test-vector file that exists.

Usage: python3 -I verifier/run_vectors.py     (set VARVE_LIBOQS to check signatures)
Exit status 1 on any mismatch.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # -I removes the script directory from sys.path

import varve_verify as v  # noqa: E402

VECTORS = os.path.join(HERE, "..", "test-vectors")


class Report:
    def __init__(self):
        self.mismatches = 0
        self.checks = 0
        self.skipped = 0
        self.notes = []

    def check(self, label, ok, detail=""):
        self.checks += 1
        if not ok:
            self.mismatches += 1
            print("MISMATCH %s %s" % (label, detail))

    def skip(self, label, why):
        self.skipped += 1
        print("SKIPPED  %s (%s)" % (label, why))


R = Report()


def load(name):
    path = os.path.join(VECTORS, name)
    if not os.path.exists(path):
        R.skip(name, "file not present")
        return None
    with open(path) as f:
        return json.load(f)


def hx(s):
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------


def check_subsidy():
    data = load("subsidy.json")
    if not data:
        return
    c = data["constants"]
    R.check("subsidy/constants",
            (c["INITIAL_SUBSIDY"], c["TAIL_SUBSIDY"], c["BLOCKS_PER_EPOCH"])
            == (v.INITIAL_SUBSIDY, v.TAIL_SUBSIDY, v.BLOCKS_PER_EPOCH))
    R.check("subsidy/FRAC table matches embedded",
            [int(x, 16) for x in c["FRAC_Q63"]] == list(v.FRAC_Q63))
    # FRAC exactness: v^64 * 2^k <= 2^4032 < (v+1)^64 * 2^k
    for k, val in enumerate(v.FRAC_Q63):
        ok = val ** 64 * 2 ** k <= 2 ** 4032 < (val + 1) ** 64 * 2 ** k
        R.check("subsidy/FRAC[%d] exact" % k, ok)
    for e in data["subsidy"]:
        R.check("subsidy/height %d" % e["height"], v.subsidy(e["height"]) == e["subsidy"],
                "got %d want %d" % (v.subsidy(e["height"]), e["subsidy"]))
    for e in data["cumulative_supply"]:
        got = cumulative_supply(e["height"])
        R.check("supply/height %d" % e["height"], got == e["supply"],
                "got %d want %d" % (got, e["supply"]))


def cumulative_supply(height):
    total, h = 0, 1
    while h <= height:
        epoch_end = ((h - 1) // v.BLOCKS_PER_EPOCH + 1) * v.BLOCKS_PER_EPOCH
        last = min(height, epoch_end)
        total += v.subsidy(h) * (last - h + 1)
        h = last + 1
    return total


def check_difficulty():
    data = load("difficulty.json")
    if not data:
        return
    initial = 1 << 240
    # parent_time_minus_genesis is t_h - t0; next_target adds ASERT_ANCHOR_DELAY itself.
    for c in data["cases"]:
        got = v.next_target(c["parent_height"], c["parent_time_minus_genesis"], 0, initial)
        want = int(c["next_target_hex"], 16)
        R.check("difficulty/" + c["label"], got == want, "got %064x want %064x" % (got, want))


def check_addresses():
    data = load("addresses.json")
    if not data:
        return
    pk1 = bytes(i % 256 for i in range(1952))
    pk2 = bytes((255 - i) % 256 for i in range(32))
    R.check("addresses/commitment mldsa65",
            v.commitment_for(1, pk1).hex() == data["commitments"]["mldsa65"])
    R.check("addresses/commitment slhdsa128s",
            v.commitment_for(2, pk2).hex() == data["commitments"]["slhdsa128s"])
    for a in data["addresses"]:
        label = "addresses/%s policy %d" % (a["network"], a["policy"])
        template = hx(a["template_hex"])
        enc = v.encode_address(a["network"], template)
        R.check(label + " encode", enc == a["address"], "got %s" % enc)
        R.check(label + " length", len(a["address"]) == a["length"])
        try:
            net, tpl = v.decode_address(a["address"])
            R.check(label + " decode", (net, tpl) == (a["network"], template))
            R.check(label + " decode uppercase", v.decode_address(a["address"].upper())[1] == template)
        except ValueError as e:
            R.check(label + " decode", False, str(e))
    # negative decoding checks derived from addresses.md
    good = data["addresses"][0]["address"]
    bad = [good[:-1] + ("q" if good[-1] != "q" else "p"),   # checksum
           good[:10].upper() + good[10:],                    # mixed case
           "x" + good[1:]]                                   # hrp / checksum
    for s in bad:
        try:
            v.decode_address(s)
            R.check("addresses/negative " + s[:12], False, "accepted")
        except ValueError:
            R.check("addresses/negative", True)


def check_params():
    data = load("params.json")
    if not data:
        return
    mine = v.draft_params()
    theirs = data["entries"]
    R.check("params/entry count", len(mine) == len(theirs), "%d vs %d" % (len(mine), len(theirs)))
    for (name, typ, val), e in zip(mine, theirs):
        want = e["value"]
        got = val.hex() if typ == "bytes" else str(val)
        R.check("params/%s" % name, (name, typ, got) == (e["name"], e["type"], want),
                "got %s/%s/%s.. want %s/%s/%s.." % (name, typ, got[:20], e["name"], e["type"], want[:20]))
    ser = v.serialize_params(mine)
    R.check("params/serialization length", len(ser) == data["serialization_length"],
            "%d vs %d" % (len(ser), data["serialization_length"]))
    R.check("params/serialization sha256",
            hashlib.sha256(ser).hexdigest() == data["serialization_hex_sha256"])
    R.check("params/params_hash", v.params_hash(mine).hex() == data["params_hash"])


def check_genesis():
    data = load("genesis.json")
    if not data:
        return
    for c in data["compact_cases"]:
        bits = int(c["bits"], 16)
        label = "genesis/compact " + c["bits"]
        try:
            got = "%064x" % v.decode_compact(bits)
            R.check(label, "target" in c and got == c["target"], "got %s want %s" % (got, c))
        except v.AnchorError as e:
            R.check(label, c.get("result") == str(e), "got error %s want %s" % (e, c))
    for c in data["anchor_cases"]:
        label = "genesis/anchor " + c["name"]
        hdrs = [hx(h) for h in c["headers"]]
        try:
            v.check_anchor(c["anchor_height"], hx(c["anchor_prev_hash_internal"]),
                           int(c["anchor_bits"], 16), hdrs)
            got = "valid"
        except v.AnchorError as e:
            got = str(e)
        R.check(label, (got == "valid") == (c["result"] == "valid"), "got %r want %r" % (got, c["result"]))
        if got != c["result"] and (got == "valid") == (c["result"] == "valid"):
            R.notes.append("anchor reason differs: %s: mine %r vs %r" % (c["name"], got, c["result"]))
    ex = data["example_genesis"]
    fixture = [hx(h) for h in data["anchor_cases"][0]["headers"]]
    block, seed, t0 = v.build_genesis(hx(ex["params_hash"]), int(ex["initial_target"], 16), fixture)
    parsed = v.parse_block(block)
    R.check("genesis/t0", t0 == ex["t0"])
    R.check("genesis/coinbase txid", parsed.txs[0].txid().hex() == ex["coinbase_txid"])
    R.check("genesis/tx_root", parsed.header.tx_root.hex() == ex["tx_root"])
    R.check("genesis/header", parsed.raw_header.hex() == ex["header"])
    R.check("genesis/block_id", parsed.header.block_id().hex() == ex["block_id"])


def check_consensus():
    data = load("consensus.json")
    if not data:
        return
    for t in data["transactions"]:
        label = "tx/" + t["name"]
        raw = hx(t["hex"])
        try:
            tx = v.parse_tx(raw)
            parsed = "ok"
            err = ""
        except v.ParseError as e:
            parsed, err = "error", str(e)
        R.check(label + " parse", parsed == t["parse"], "got %s (%s) want %s (%s)" % (
            parsed, err, t["parse"], t.get("reason")))
        if parsed == "ok" and t["parse"] == "ok":
            R.check(label + " reserialize", tx.full_bytes() == raw)
            R.check(label + " txid", tx.txid().hex() == t["txid"])
            R.check(label + " wtxid", tx.wtxid().hex() == t["wtxid"])
            R.check(label + " weight", tx.weight() == t["weight"], "got %d want %d" % (tx.weight(), t["weight"]))
            R.check(label + " base_size", len(tx.base_bytes()) == t["base_size"])
    for m in data["merkle"]:
        got = v.merkle_root([hx(w) for w in m["wtxids"]]).hex()
        R.check("merkle/" + m["name"], got == m["root"])
    for h in data["headers"]:
        raw = hx(h["hex"])
        R.check("header/" + h["name"], v.block_id_of_header(raw).hex() == h["block_id"])
        parsed = v.Header.parse(raw)
        R.check("header/%s reserialize" % h["name"], parsed.serialize() == raw)
    for s in data["sighash"]:
        tx = v.parse_tx(hx(s["tx_hex"]))
        got = v.sighash(hx(s["network_id"]), hx(s["genesis_id"]), tx.txid(), s["index"],
                        [hx(o) for o in s["spent_outputs"]], s["path"])
        R.check("sighash/" + s["name"], got.hex() == s["sighash"])
    for c in data["chainwork"]:
        got = v.chainwork([int(t, 16) for t in c["targets"]])
        R.check("chainwork/" + c["name"], got == int(c["chainwork"], 16),
                "got %x want %s" % (got, c["chainwork"]))


def check_signatures(verifier):
    data = load("signatures.json")
    if not data:
        return
    if verifier is None:
        R.skip("signatures.json", "VARVE_LIBOQS unset")
        return
    for s in data["signatures"]:
        got = verifier.verify(s["scheme_id"], hx(s["public_key"]), hx(s["message"]), hx(s["signature"]))
        R.check("signature/" + s["name"], got == s["valid"], "got %s want %s" % (got, s["valid"]))


def check_chain(verifier):
    data = load("chain.json")
    if not data:
        return
    network_id = hx(data["network_id"])
    genesis_raw = hx(data["genesis"])
    R.check("chain/initial_target matches genesis header",
            v.parse_block(genesis_raw).header.target == int(data["initial_target"], 16))
    # Rebuild the genesis from the genesis.json fixture with the draft params_hash.
    gen = load("genesis.json")
    if gen:
        fixture = [hx(h) for h in gen["anchor_cases"][0]["headers"]]
        rebuilt, _seed, _t0 = v.build_genesis(hx(gen["example_genesis"]["params_hash"]),
                                               int(data["initial_target"], 16), fixture)
        R.check("chain/genesis rebuilt from fixture", rebuilt == genesis_raw)

    # Validate the base chain once, keeping each block's delta.
    state = v.ChainState(network_id, genesis_raw, verifier)
    deltas = []
    for n, raw in enumerate(data["base_chain"], 1):
        try:
            delta = state.validate(hx(raw))
        except v.Invalid as e:
            R.check("chain/base block %d" % n, False, "invalid: %s" % e)
            return
        state.apply(delta)
        deltas.append(delta)
    R.check("chain/base chain valid", True)

    for case in data["cases"]:
        s = v.ChainState(network_id, genesis_raw, verifier)
        for d in deltas[:case["parent_height"]]:
            s.apply(d)
        try:
            s.validate(hx(case["block"]))
            got, why = "valid", ""
        except v.Invalid as e:
            got, why = "invalid", str(e)
        except v.ParseError as e:
            got, why = "invalid", "parse: %s" % e
        label = "chain/" + case["name"]
        if got == "valid" and case["result"] == "invalid" and verifier is None and s.sig_checks_skipped:
            R.skip(label, "signature checks unavailable")
            continue
        R.check(label, got == case["result"],
                "mine=%s (%s) vector=%s (%s)" % (got, why, case["result"], case["reason"]))


def main():
    verifier = v.load_verifier()
    if verifier is None:
        print("note: VARVE_LIBOQS unset; signature-dependent checks are skipped")
    check_subsidy()
    check_difficulty()
    check_addresses()
    check_params()
    check_genesis()
    check_consensus()
    check_signatures(verifier)
    check_chain(verifier)
    load("pow.json") and R.skip("pow.json", "proof of work is out of scope for this verifier")
    load("wallet.json") and R.skip("wallet.json", "wallet derivation is not consensus; out of scope")
    for n in R.notes:
        print("note: " + n)
    print("checks=%d mismatches=%d skipped=%d" % (R.checks, R.mismatches, R.skipped))
    sys.exit(1 if R.mismatches else 0)


if __name__ == "__main__":
    main()
