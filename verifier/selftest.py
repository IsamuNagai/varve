"""Self-made consensus cases for rules the shipped vectors do not exercise.

These use real signatures (generated through liboqs) so they need VARVE_LIBOQS.
Usage: VARVE_LIBOQS=... python3 -I verifier/selftest.py
"""

import ctypes
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import varve_verify as v  # noqa: E402

NETWORK_ID = b"RVAR"
FAILURES = []


def expect(label, ok):
    print("%-5s %s" % ("ok" if ok else "FAIL", label))
    if not ok:
        FAILURES.append(label)


class Signer:
    """Key generation and signing through liboqs (test helper only)."""

    SK_LEN = {1: 4032, 2: 64}

    def __init__(self, verifier):
        self.lib = verifier.lib
        self.verifier = verifier
        self.lib.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.OQS_SIG_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
                                          ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]

    def keypair(self, scheme):
        pk = ctypes.create_string_buffer(v.SCHEMES[scheme][0])
        sk = ctypes.create_string_buffer(self.SK_LEN[scheme])
        assert self.lib.OQS_SIG_keypair(self.verifier._handle(scheme), pk, sk) == 0
        return pk.raw, sk.raw

    def sign(self, scheme, sk, msg):
        sig = ctypes.create_string_buffer(v.SCHEMES[scheme][1])
        n = ctypes.c_size_t(0)
        assert self.lib.OQS_SIG_sign(self.verifier._handle(scheme), sig, ctypes.byref(n), msg, len(msg), sk) == 0
        return sig.raw[:n.value]


def fixture_genesis():
    path = os.path.join(HERE, "..", "test-vectors", "genesis.json")
    with open(path) as f:
        data = json.load(f)
    headers = [bytes.fromhex(h) for h in data["anchor_cases"][0]["headers"]]
    raw, _seed, _t0 = v.build_genesis(bytes.fromhex(data["example_genesis"]["params_hash"]), 1 << 240, headers)
    return raw


def coinbase(height, outputs, extra=b""):
    return v.Tx(1, [(v.ZERO32, height % (1 << 32))], outputs, height >> 32, [v.Witness(0, b"", extra)])


def make_block(state, txs, timestamp=None, height_fix=None):
    height = state.height + 1
    if timestamp is None:
        timestamp = v.median_time_past([h[0] for h in reversed(state.headers[-v.MTP_WINDOW:])]) + 1
    target = v.next_target(state.height, state.headers[-1][0], state.t0, state.initial_target)
    root = v.merkle_root([t.wtxid() for t in txs])
    header = v.Header(1, state.headers[-1][2], root, timestamp, target, 0)
    return header.serialize() + v.varint_encode(len(txs)) + b"".join(t.full_bytes() for t in txs)


def accepts(state, raw):
    try:
        state.validate(raw)
        return True
    except (v.Invalid, v.ParseError):
        return False


def fresh(verifier):
    return v.ChainState(NETWORK_ID, fixture_genesis(), verifier)


def simple_output(amount, scheme, pk):
    return v.Output(amount, scheme, v.commitment_for(scheme, pk))


def test_weight_and_structure(verifier):
    state = fresh(verifier)
    pk = bytes(1952)
    unit = simple_output(1, 1, pk)

    def block_of_weight(n_outputs, extra_len):
        cb = coinbase(1, [unit] * n_outputs, bytes(extra_len))
        return make_block(state, [cb]), cb.weight(coinbase=True)

    # coinbase size = 51 + 44 * 16362 + extra (2-byte output_count varint) -> 720,000 at extra 22
    raw, w = block_of_weight(16362, 22)
    expect("block weight exactly 720,000 accepted (w=%d)" % w, w == 720_000 and accepts(state, raw))
    raw, w = block_of_weight(16362, 23)
    expect("block weight 720,001 rejected (w=%d)" % w, w == 720_001 and not accepts(state, raw))

    good = make_block(state, [coinbase(1, [unit])])
    expect("plain block accepted", accepts(state, good))
    expect("trailing byte rejected", not accepts(state, good + b"\x00"))
    expect("truncated rejected", not accepts(state, good[:-1]))
    expect("tx_count 0 rejected", not accepts(state, good[:116] + b"\x00"))
    bad_parent = bytearray(good)
    bad_parent[4] ^= 1
    expect("unknown parent rejected", not accepts(state, bytes(bad_parent)))
    cb_bad_version = coinbase(1, [unit])
    cb_bad_version.version = 2
    expect("tx version 2 rejected", not accepts(state, make_block(state, [cb_bad_version])))
    cb_two = coinbase(1, [unit])
    cb_two.inputs.append((bytes([1]) * 32, 0))
    cb_two.witnesses.append(v.Witness(0, b"", b""))
    expect("coinbase with two inputs rejected", not accepts(state, make_block(state, [cb_two])))
    expect("first tx not a coinbase rejected",
           not accepts(state, make_block(state, [v.Tx(1, [(bytes([1]) * 32, 0)], [unit], 0, [v.Witness(0, b"", b"")])])))
    expect("coinbase amount above MAX_MONEY rejected",
           not accepts(state, make_block(state, [coinbase(1, [simple_output(v.MAX_MONEY + 1, 1, pk)])])))
    # coinbase height encoding for heights >= 2^32 (check_coinbase is height-parametric)
    try:
        v.check_coinbase(coinbase((1 << 32) + 7, [unit]), (1 << 32) + 7)
        ok = True
    except v.Invalid:
        ok = False
    expect("coinbase encodes 64-bit height (prev_index 7, locktime 1)", ok)
    try:
        v.check_coinbase(coinbase(7, [unit]), (1 << 32) + 7)
        ok = False
    except v.Invalid:
        ok = True
    expect("coinbase at height 2^32+7 with plain height rejected", ok)


def test_mtp(verifier):
    state = fresh(verifier)
    t0 = state.t0
    pk = bytes(1952)
    unit = simple_output(1, 1, pk)
    state.connect(make_block(state, [coinbase(1, [unit])], timestamp=t0 + 100))
    # S = [t0+100, t0]; MTP is the upper middle value = t0+100
    low = make_block(state, [coinbase(2, [unit])], timestamp=t0 + 50)
    high = make_block(state, [coinbase(2, [unit])], timestamp=t0 + 101)
    expect("even window: upper median enforced (t0+50 rejected)", not accepts(state, low))
    expect("even window: t0+101 accepted", accepts(state, high))
    equal = make_block(state, [coinbase(2, [unit])], timestamp=t0 + 100)
    expect("even window: timestamp == MTP rejected", not accepts(state, equal))


def test_spends(verifier):
    signer = Signer(verifier)
    state = fresh(verifier)
    pk1, sk1 = signer.keypair(1)
    pk2, sk2 = signer.keypair(2)
    # recovery output: primary ML-DSA, recovery SLH-DSA after 3 blocks
    recov = v.Output(1_000_000, 1, v.commitment_for(1, pk1), 1, 1, 2, v.commitment_for(2, pk2), 3)
    first = [recov, simple_output(2_000_000, 1, pk1)]
    state.connect(make_block(state, [coinbase(1, first)]))
    for h in range(2, 290):
        state.connect(make_block(state, [coinbase(h, [simple_output(1, 1, pk1)])]))
    cb1 = state.utxo  # keyed by (txid, index); find outputs created at height 1
    outpoints = sorted(k for k, c in cb1.items() if c.height == 1)
    txid1 = outpoints[0][0]
    out_recov, out_plain = (txid1, 0), (txid1, 1)

    def spend(inputs, outputs, paths_keys):
        """paths_keys[i] = (scheme, pk, sk, path)"""
        tx = v.Tx(1, inputs, outputs, 0, [v.Witness(p, pk, b"") for _s, pk, _sk, p in paths_keys])
        spent = [state.utxo[i].output.serialize() for i in inputs]
        for i, (scheme, pk, sk, path) in enumerate(paths_keys):
            msg = v.sighash(NETWORK_ID, state.genesis_id, tx.txid(), i, spent, path)
            tx.witnesses[i].signature = signer.sign(scheme, sk, msg)
        return tx

    h = state.height + 1  # 290: coinbase of height 1 is mature (1 + 288 <= 290)
    cb = coinbase(h, [simple_output(1, 1, pk1)])
    fee = 7
    pay = spend([out_plain], [simple_output(2_000_000 - fee, 1, pk1)], [(1, pk1, sk1, 0)])
    cb_fee = coinbase(h, [simple_output(v.subsidy(h) + fee, 1, pk1)])
    expect("mature coinbase spend with fee accepted",
           accepts(state, make_block(state, [cb_fee, pay])))
    expect("coinbase claiming fee+1 rejected",
           not accepts(state, make_block(state, [coinbase(h, [simple_output(v.subsidy(h) + fee + 1, 1, pk1)]), pay])))
    # recovery path: output created at height 1, delay 3 -> spendable from height 4 (long satisfied)
    rec = spend([out_recov], [simple_output(999_000, 2, pk2)], [(2, pk2, sk2, 1)])
    expect("recovery path (SLH-DSA) after delay accepted", accepts(state, make_block(state, [cb, rec])))
    prim = spend([out_recov], [simple_output(999_000, 2, pk2)], [(1, pk1, sk1, 0)])
    expect("primary path on recovery-policy output accepted", accepts(state, make_block(state, [cb, prim])))
    wrong = spend([out_recov], [simple_output(999_000, 2, pk2)], [(1, pk1, sk1, 1)])
    expect("recovery path signed with primary key rejected", not accepts(state, make_block(state, [cb, wrong])))
    # two inputs, same outpoint twice
    dup = spend([out_plain, out_plain], [simple_output(1, 1, pk1)], [(1, pk1, sk1, 0)] * 2)
    expect("same outpoint twice in one tx rejected", not accepts(state, make_block(state, [cb, dup])))
    # same-block chain: parent then child spending parent's output
    child_in = (pay.txid(), 0)
    parent = spend([out_plain], [simple_output(1_999_000, 1, pk1)], [(1, pk1, sk1, 0)])
    child_tx = v.Tx(1, [(parent.txid(), 0)], [simple_output(1_998_000, 1, pk1)], 0, [v.Witness(0, pk1, b"")])
    spent = [parent.outputs[0].serialize()]
    msg = v.sighash(NETWORK_ID, state.genesis_id, child_tx.txid(), 0, spent, 0)
    child_tx.witnesses[0].signature = signer.sign(1, sk1, msg)
    expect("same-block parent-then-child accepted",
           accepts(state, make_block(state, [coinbase(h, [simple_output(v.subsidy(h) + 2000, 1, pk1)]), parent, child_tx])))
    del child_in
    # weight of a signed tx: size + 100 verify units per ML-DSA input
    expect("weight formula (1-in 1-out, ML-DSA)",
           pay.weight() == len(pay.full_bytes()) + 100)


def main():
    verifier = v.load_verifier()
    if verifier is None:
        sys.exit("selftest needs VARVE_LIBOQS")
    test_weight_and_structure(verifier)
    test_mtp(verifier)
    test_spends(verifier)
    print("%d failures" % len(FAILURES))
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
