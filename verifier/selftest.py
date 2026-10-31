"""Self-made consensus cases for rules the shipped vectors do not exercise.

Spend cases use real signatures generated through liboqs (VARVE_LIBOQS).
Without it, keys and signatures are random bytes of the right length and
signature verification is skipped, so only the non-signature rules are tested;
the run says so.  Usage: VARVE_LIBOQS=... python3 -I verifier/selftest.py
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


LAST = {"why": ""}


def expect(label, ok):
    why, LAST["why"] = LAST["why"], ""
    print("%-5s %s%s" % ("ok" if ok else "FAIL", label, "  [%s]" % why if why else ""))
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


class FakeSigner:
    """Without liboqs: random keys and signatures of the right lengths."""

    def keypair(self, scheme):
        return os.urandom(v.SCHEMES[scheme][0]), b""

    def sign(self, scheme, sk, msg):
        return os.urandom(v.SCHEMES[scheme][1])


def make_signer(verifier):
    return Signer(verifier) if verifier is not None else FakeSigner()


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
    except (v.Invalid, v.ParseError) as e:
        LAST["why"] = str(e)
        return False


def fresh(verifier, lifecycle=v.GENESIS_LIFECYCLE):
    return v.ChainState(NETWORK_ID, fixture_genesis(), verifier, lifecycle)


def make_spender(state, signer):
    def spend(inputs, outputs, paths_keys):
        """paths_keys[i] = (scheme, pk, sk, path); path 2 entries stay empty
        unless pk/sk are given as raw bytes to place in the witness."""
        tx = v.Tx(1, inputs, outputs, 0,
                  [v.Witness(p, pk if p != 2 else (pk or b""), b"") for _s, pk, _sk, p in paths_keys])
        spent = [state.utxo[i].output.serialize() for i in inputs]
        for i, (scheme, pk, sk, path) in enumerate(paths_keys):
            if path == 2:
                tx.witnesses[i].signature = sk or b""  # sk slot carries raw signature bytes for path 2
                continue
            msg = v.sighash(NETWORK_ID, state.genesis_id, tx.txid(), i, spent, path)
            tx.witnesses[i].signature = signer.sign(scheme, sk, msg)
        return tx
    return spend


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
    signer = make_signer(verifier)
    state = fresh(verifier)
    pk1, sk1 = signer.keypair(1)
    pk2, sk2 = signer.keypair(2)
    pk3, sk3 = signer.keypair(1)
    # recovery output: primary ML-DSA, recovery SLH-DSA after 3 blocks
    recov = v.Output(1_000_000, 1, v.commitment_for(1, pk1), 1, 1, 2, v.commitment_for(2, pk2), 3)
    first = [recov, simple_output(2_000_000, 1, pk1),
             simple_output(500_000, 1, pk1),      # 2: second output under pk1
             simple_output(400_000, 2, pk2),      # 3: SLH-DSA primary = recov's recovery key
             simple_output(300_000, 1, pk3),      # 4: a different key
             v.Output(200_000, 1, v.commitment_for(1, pk3), 1, 1, 1, v.commitment_for(1, pk1), 3),  # 5: recovery key = pk1
             simple_output(100_000, 1, pk1)]      # 6: third output under pk1
    state.connect(make_block(state, [coinbase(1, first)]))
    for h in range(2, 290):
        state.connect(make_block(state, [coinbase(h, [simple_output(1, 1, pk1)])]))
    cb1 = state.utxo  # keyed by (txid, index); find outputs created at height 1
    outpoints = sorted(k for k, c in cb1.items() if c.height == 1)
    txid1 = outpoints[0][0]
    out_recov, out_plain = (txid1, 0), (txid1, 1)
    spend = make_spender(state, signer)

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
    test_shared(state, spend, cb, txid1, pk1, sk1, pk2, sk2, pk3, sk3)


def test_shared(state, spend, cb, txid1, pk1, sk1, pk2, sk2, pk3, sk3):
    """transactions.md §8.2 (path 2) at height 290, genesis lifecycle."""
    recov, plain, plain2, slh, other, rec_pk1, plain3 = [(txid1, i) for i in range(7)]
    k1 = (1, pk1, sk1, 0)
    shared = (0, b"", b"", 2)
    out = [simple_output(1000, 1, pk1)]

    def ok(label, tx):
        expect(label, accepts(state, make_block(state, [cb, tx])))

    def bad(label, tx):
        expect(label, not accepts(state, make_block(state, [cb, tx])))

    good = spend([plain, plain2], out, [k1, shared])
    ok("path 2: second input reuses the first input's key (0 then 2)", good)
    bad("path 2: before any authorizing input (2 then 0)", spend([plain2, plain], out, [shared, k1]))
    bad("path 2: alone, no authorizing input", spend([plain2], out, [shared]))
    bad("path 2: non-empty public key", spend([plain, plain2], out, [k1, (0, pk1, b"", 2)]))
    bad("path 2: non-empty signature", spend([plain, plain2], out, [k1, (0, b"", b"\x00", 2)]))
    bad("path 2: one-byte public key", spend([plain, plain2], out, [k1, (0, b"\x01", b"", 2)]))
    bad("path 2: output under a different key", spend([plain, other], out, [k1, shared]))
    ok("path 2: authorized by a path-1 input whose recovery (scheme, commitment) equals its primary",
       spend([recov, slh], out, [(2, pk2, sk2, 1), shared]))
    bad("path 2: path-1 authorizer does not cover the output's own primary key (pk1)",
        spend([recov, plain2], out, [(2, pk2, sk2, 1), shared]))
    ok("path 2: authorized by path 0 of a recovery-policy output",
       spend([recov, plain2], out, [k1, shared]))
    bad("path 2: cannot stand in for a recovery spend (output's recovery key = authorizer)",
        spend([plain, rec_pk1], out, [k1, shared]))
    ok("path 2: chained 0, 2, 2", spend([plain, plain2, plain3], out, [k1, shared, shared]))
    # the coinbase of height 3 matures at 291; this block is at 290
    young = next(k for k, c in state.utxo.items() if c.height == 3)
    bad("path 2: immature coinbase output", spend([plain, young], out, [k1, shared]))
    expect("path 2: witness entry is 3 bytes and adds no verify units",
           good.weight() == len(good.full_bytes()) + 100
           and len(good.witnesses[1].serialize()) == 3)
    # transactions.md §8.2 (v0.5): path 2 is mandatory where it applies, so the
    # witness layout is unique (§3).  This resolves A-22.
    rec1 = (1, pk1, sk1, 1)  # path 1 selecting pk1 (output rec_pk1: primary pk3, recovery pk1)
    both = spend([plain, plain2], out, [k1, k1])
    bad("mandatory path 2: non-canonical second signature (0 then 0, same key)", both)
    stripped = v.Tx(both.version, both.inputs, both.outputs, both.locktime,
                    [both.witnesses[0], v.Witness(2, b"", b"")])
    expect("mandatory path 2: the canonical (0 then 2) layout keeps the txid",
           stripped.txid() == both.txid() and stripped.wtxid() != both.wtxid())
    ok("mandatory path 2: canonical layout (0 then 2) valid", stripped)
    bad("mandatory path 2: second same-key input signed again after a chain (0, 2, 0)",
        spend([plain, plain2, plain3], out, [k1, shared, k1]))
    bad("mandatory path 2: path 1 on an output whose primary key is already authorized (0 then 1)",
        spend([plain, recov], out, [k1, (2, pk2, sk2, 1)]))
    ok("mandatory path 2: same pair with path 2 (0 then 2) valid", spend([plain, recov], out, [k1, shared]))
    ok("mandatory path 2: path 1 then path 0 on the same primary key (path 1 selects the"
       " recovery key, so path 2 does not apply) valid",
       spend([recov, plain], out, [(2, pk2, sk2, 1), k1]))
    bad("mandatory path 2: path 1 then path 0 whose primary key equals the first input's"
        " recovery key", spend([rec_pk1, plain], out, [rec1, k1]))
    ok("mandatory path 2: same pair with path 2 (1 then 2) valid", spend([rec_pk1, plain], out, [rec1, shared]))
    bad("mandatory path 2: path 1 then path 1 whose primary key equals the first input's recovery key",
        spend([rec_pk1, recov], out, [rec1, (2, pk2, sk2, 1)]))
    ok("mandatory path 2: does not cover recovery keys (0 then 1 under the same key) valid",
       spend([plain, rec_pk1], out, [k1, rec1]))
    # A-25: the layout is unique against third parties, not against key holders.
    lay_a = spend([rec_pk1, plain], out, [(1, pk3, sk3, 0), k1])
    lay_b = spend([rec_pk1, plain], out, [rec1, shared])
    expect("A-25: two witness layouts (0,0) and (1,2) share one txid",
           lay_a.txid() == lay_b.txid() and lay_a.wtxid() != lay_b.wtxid())
    ok("A-25: layout (0 by pk3, 0 by pk1) valid", lay_a)
    ok("A-25: layout (1 by pk1, 2) valid", lay_b)


def test_lifecycle(verifier):
    """transactions.md §6: ML-DSA NO_NEW_OUTPUTS from 293, DISABLED from 295."""
    def refused(table):
        try:
            v.check_lifecycle(table)
        except ValueError:
            return True
        return False

    N, D = v.NO_NEW_OUTPUTS, v.DISABLED
    malformed = [
        ("unknown scheme", [(3, N, 10)]),
        ("ACTIVE listed", [(1, v.ACTIVE, 0)]),
        ("upgrades.md §4 genesis table (A-26)", [(1, v.ACTIVE, 0), (2, v.ACTIVE, 0)]),
        ("ACTIVE after NO_NEW_OUTPUTS", [(1, N, 10), (1, v.ACTIVE, 20)]),
        ("moving back from DISABLED", [(1, D, 10), (1, N, 20)]),
        ("state repeated", [(1, N, 10), (1, N, 20)]),
        ("out of height order", [(1, N, 20), (1, D, 10)]),
        ("equal from_height", [(1, N, 10), (1, D, 10)]),
        ("out of order across interleaved schemes", [(1, D, 20), (2, N, 5), (1, N, 10)]),
        ("unknown state", [(1, "RETIRED", 10)]),
        ("negative from_height", [(1, N, -1)]),
    ]
    for label, table in malformed:
        expect("lifecycle: malformed list refused (%s)" % label, refused(table))
    for label, table in malformed:
        try:
            fresh(verifier, table)
            ok = False
        except ValueError:
            ok = True
        expect("lifecycle: chain state refuses to start with a malformed list (%s)" % label, ok)
    well = [
        ("empty (genesis)", []),
        ("interleaved schemes", [(1, N, 10), (2, D, 5), (1, D, 20)]),
        ("skip straight to DISABLED", [(2, D, 0)]),
    ]
    for label, table in well:
        expect("lifecycle: well-formed list accepted (%s)" % label, not refused(table))
    expect("lifecycle: genesis list is empty", v.GENESIS_LIFECYCLE == ())
    inter = [(1, N, 10), (2, D, 5), (1, D, 20)]
    expect("lifecycle: greatest from_height <= h wins (interleaved list)",
           [v.scheme_state(inter, 1, h) for h in (9, 10, 19, 20)] == [v.ACTIVE, N, N, D]
           and [v.scheme_state(inter, 2, h) for h in (4, 5)] == [v.ACTIVE, D])
    table = [(1, N, 293), (1, D, 295)]
    expect("lifecycle: state lookup 292/293/294/295",
           [v.scheme_state(table, 1, h) for h in (292, 293, 294, 295)]
           == [v.ACTIVE, N, N, D]
           and v.scheme_state(table, 2, 10 ** 9) == v.ACTIVE and v.scheme_state(table, 3, 0) is None)
    signer = make_signer(verifier)
    state = fresh(verifier, table)
    pk1, sk1 = signer.keypair(1)
    pk2, sk2 = signer.keypair(2)
    rec = v.Output(1_000_000, 1, v.commitment_for(1, pk1), 1, 1, 2, v.commitment_for(2, pk2), 3)
    state.connect(make_block(state, [coinbase(1, [simple_output(2_000_000, 1, pk1),
                                                  simple_output(3_000_000, 1, pk1), rec])]))
    txid1 = next(k for k, c in state.utxo.items() if c.height == 1)[0]
    a, b, r = (txid1, 0), (txid1, 1), (txid1, 2)
    slh_out = simple_output(1, 2, pk2)
    while state.height < 291:
        state.connect(make_block(state, [coinbase(state.height + 1, [slh_out])]))
    spend = make_spender(state, signer)
    k1 = (1, pk1, sk1, 0)

    def block(txs, cb_out=None):
        h = state.height + 1
        return make_block(state, [coinbase(h, [cb_out or simple_output(1, 2, pk2)])] + txs)

    expect("lifecycle: ML-DSA output created at 292 (ACTIVE) accepted",
           accepts(state, block([], simple_output(1, 1, pk1))))
    state.connect(block([]))  # 292
    # candidate 293: NO_NEW_OUTPUTS
    expect("lifecycle: ML-DSA coinbase output while NO_NEW_OUTPUTS rejected",
           not accepts(state, block([], simple_output(1, 1, pk1))))
    expect("lifecycle: ML-DSA as recovery scheme while NO_NEW_OUTPUTS rejected",
           not accepts(state, block([], v.Output(1, 2, v.commitment_for(2, pk2), 1, 1, 1,
                                                  v.commitment_for(1, pk1), 5))))
    expect("lifecycle: spend creating an ML-DSA output while NO_NEW_OUTPUTS rejected",
           not accepts(state, block([spend([a], [simple_output(1_000, 1, pk1)], [k1])])))
    expect("lifecycle: ML-DSA spend (path 0) while NO_NEW_OUTPUTS accepted",
           accepts(state, block([spend([a], [simple_output(1_000, 2, pk2)], [k1])])))
    expect("lifecycle: path 0 then path 2 while NO_NEW_OUTPUTS accepted",
           accepts(state, block([spend([a, b], [simple_output(1_000, 2, pk2)], [k1, (0, b"", b"", 2)])])))
    state.connect(block([]))  # 293
    state.connect(block([]))  # 294
    # candidate 295: DISABLED
    expect("lifecycle: ML-DSA spend (path 0) while DISABLED rejected",
           not accepts(state, block([spend([a], [simple_output(1_000, 2, pk2)], [k1])])))
    expect("lifecycle: path 0 then path 2 while DISABLED rejected",
           not accepts(state, block([spend([a, b], [simple_output(1_000, 2, pk2)], [k1, (0, b"", b"", 2)])])))
    expect("lifecycle: path 0 of a recovery output under a disabled primary rejected",
           not accepts(state, block([spend([r], [simple_output(1_000, 2, pk2)], [k1])])))
    expect("lifecycle: path 1 (SLH-DSA) under a disabled primary accepted",
           accepts(state, block([spend([r], [simple_output(1_000, 2, pk2)], [(2, pk2, sk2, 1)])])))


def main():
    verifier = v.load_verifier()
    if verifier is None:
        print("note: VARVE_LIBOQS unset; random keys and signatures, signature checks SKIPPED")
    test_weight_and_structure(verifier)
    test_mtp(verifier)
    test_spends(verifier)
    test_lifecycle(verifier)
    print("%d failures%s" % (len(FAILURES), "" if verifier else " (signatures not verified)"))
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
