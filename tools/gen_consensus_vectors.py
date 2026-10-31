#!/usr/bin/env python3
"""Generate consensus test vectors.

  python3 -I tools/gen_consensus_vectors.py
      writes test-vectors/consensus.json (deterministic; CI regenerates and diffs it).

  VARVE_LIBOQS=/path/liboqs.so python3 -I tools/gen_consensus_vectors.py --signed
      also writes test-vectors/chain.json and test-vectors/signatures.json.
      These contain real ML-DSA-65 / SLH-DSA signatures, which are randomized, so
      they are generated once and checked (not regenerated) in CI. Only public keys
      and signatures are written; secret keys exist in memory only and are discarded.

Byte patterns used as keys in consensus.json are NOT real keys.
Every expected result below is asserted against the prototype while generating.
"""
import hashlib
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "prototype"))
import varve_proto as v  # noqa: E402

OUT = os.path.join(ROOT, "test-vectors")


def pat(tag, n):
    """Deterministic filler bytes (NOT keys or signatures)."""
    out, c = b"", 0
    while len(out) < n:
        out += hashlib.sha3_256(f"{tag}/{c}".encode()).digest()
        c += 1
    return out[:n]


def dump(name, obj):
    with open(os.path.join(OUT, name), "w") as fh:
        json.dump(obj, fh, indent=1)
        fh.write("\n")


# ------------------------------------------------------------------ consensus.json
def tx_case(name, raw, expect_ok):
    try:
        r = v.Reader(raw)
        tx = v.Tx.parse(r)
        r.done()
        res = {"name": name, "hex": raw.hex(), "parse": "ok", "txid": tx.txid().hex(), "wtxid": tx.wtxid().hex(),
               "weight": tx.weight(), "base_size": len(tx.base())}
        assert tx.full() == raw, name
    except v.Invalid as e:
        res = {"name": name, "hex": raw.hex(), "parse": "error", "reason": str(e)}
    assert (res["parse"] == "ok") == expect_ok, (name, res)
    return res


def sample_txs():
    o_single = v.Output(5_000_000_000, 0x0001, pat("com/a", 32))
    o_recov = v.Output(1_234_567, 0x0001, pat("com/b", 32), policy=1, recovery_scheme_id=0x0002,
                       recovery_commitment=pat("com/c", 32), recovery_delay=4320)
    w_ml = v.Witness(0, pat("pk/ml", 1952), pat("sig/ml", 3309))
    w_slh = v.Witness(1, pat("pk/slh", 32), pat("sig/slh", 7856))
    t1 = v.Tx([(pat("prev/1", 32), 0)], [o_single], [w_ml])
    t2 = v.Tx([(pat("prev/2", 32), 7), (pat("prev/3", 32), 0xFFFFFFFF)],
              [o_single, o_recov, v.Output(1, 0x0002, pat("com/d", 32))], [w_ml, w_slh], locktime=500_000)
    cb = v.Tx([(bytes(32), 12345)], [o_single], [v.Witness(0, b"", b"extra nonce")])
    return t1, t2, cb, o_single, o_recov


def consensus_vectors():
    t1, t2, cb, o_single, o_recov = sample_txs()
    raw1 = t1.full()
    txs = [
        tx_case("1-in 1-out, ML-DSA-65 sized witness", raw1, True),
        tx_case("2-in 3-out, policy-1 output, SLH-DSA sized recovery witness, locktime", t2.full(), True),
        tx_case("coinbase-shaped (weight given as if non-coinbase)", cb.full(), True),
        tx_case("truncated by one byte", raw1[:-1], False),
        tx_case("trailing byte", raw1 + b"\x00", False),
        tx_case("non-minimal varint input count", raw1[:4] + b"\x81\x00" + raw1[5:], False),
        tx_case("unknown policy 2", raw1[:4 + 1 + 36 + 1 + 8 + 1] + b"\x02" + raw1[4 + 1 + 36 + 1 + 8 + 2:], False),
        tx_case("input count exceeds remaining bytes", raw1[:4] + b"\xff\xff\x03" + raw1[5:], False),
        tx_case("varint longer than 5 bytes", raw1[:4] + b"\x81\x80\x80\x80\x80\x00" + raw1[5:], False),
        tx_case("varint value >= 2^32", raw1[:4] + b"\x80\x80\x80\x80\x10" + raw1[5:], False),
        tx_case("public key longer than 1952 bytes",
                v.Tx(t1.inputs, t1.outputs, [v.Witness(0, pat("pk", 1953), pat("sig", 3309))]).full(), False),
        tx_case("signature longer than 7856 bytes",
                v.Tx(t1.inputs, t1.outputs, [v.Witness(0, pat("pk", 32), pat("sig", 7857))]).full(), False),
        tx_case("missing witness", t1.base(), False),
        tx_case("shared witness (path 2, empty) on the second input",
                v.Tx(t2.inputs, t2.outputs, [t2.witnesses[0], v.Witness(2, b"", b"")], locktime=500_000).full(), True),
        tx_case("witness path 3", v.Tx(t1.inputs, t1.outputs, [v.Witness(3, b"", b"")]).full(), False),
    ]
    merkle = []
    for n in (1, 2, 3, 4, 5, 6, 7, 16, 17):
        ids = [v.h256("VARVE/test/leaf", n.to_bytes(4, "little") + i.to_bytes(4, "little")) for i in range(n)]
        merkle.append({"name": f"{n} leaves", "wtxids": [x.hex() for x in ids], "root": v.merkle_root(ids).hex()})
    headers = []
    for name, hd in [
        ("all zero except version 1", v.Header(bytes(32), bytes(32), 0, 0, 0, 1)),
        ("maximum field values", v.Header(b"\xff" * 32, b"\xff" * 32, 2 ** 64 - 1, 2 ** 256 - 1, 2 ** 64 - 1, 2 ** 32 - 1)),
        ("typical", v.Header(pat("prev", 32), pat("root", 32), 1_900_000_000, 2 ** 240, 0x0123456789ABCDEF, 1)),
    ]:
        raw = hd.serialize()
        assert len(raw) == 116
        headers.append({"name": name, "hex": raw.hex(), "block_id": hd.block_id().hex()})
    sigh = []
    spent = [o_single, o_recov]
    for net in ("mainnet", "testnet", "regtest"):
        for idx, path in ((0, 0), (1, 1)):
            sigh.append({"name": f"{net} input {idx} path {path}", "network_id": v.NETWORK_IDS[net].hex(),
                         "genesis_id": pat("genesis", 32).hex(), "tx_hex": t2.full().hex(), "index": idx,
                         "spent_outputs": [o.serialize().hex() for o in spent], "path": path,
                         "sighash": v.sighash(v.NETWORK_IDS[net], pat("genesis", 32), t2, idx, spent, path).hex()})
    cw = []
    for name, ts in [("one block at 2^240", [2 ** 240]), ("three blocks at 2^240", [2 ** 240] * 3),
                     ("target 1", [1]), ("target 2^256-1", [2 ** 256 - 1]),
                     ("mixed", [2 ** 240, 2 ** 239, 2 ** 241 + 12345, 7])]:
        cw.append({"name": name, "targets": [f"{t:064x}" for t in ts],
                   "chainwork": format(v.chainwork([v.Header(bytes(32), bytes(32), 0, t) for t in ts]), "x")})
    return {
        "_comment": ("Deterministic consensus vectors. Key/signature fields are byte patterns, not real keys. "
                     "'weight' treats every transaction as non-coinbase. Parse 'reason' is informative. "
                     "Regenerate: python3 -I tools/gen_consensus_vectors.py"),
        "transactions": txs, "merkle": merkle, "headers": headers, "sighash": sigh, "chainwork": cw,
    }


# ------------------------------------------------------------------ chain.json (signed)
class Builder:
    """Builds a regtest chain with the prototype. PoW is not checked (stub)."""

    def __init__(self, pq):
        self.pq = pq
        g = json.load(open(os.path.join(OUT, "genesis.json")))
        hs = [bytes.fromhex(x) for x in g["anchor_cases"][0]["headers"]]
        self.initial_target = 2 ** 240
        self.genesis = v.genesis_block(bytes.fromhex(g["example_genesis"]["params_hash"]), hs, self.initial_target)
        self.keys = {sid: pq.keypair(sid) for sid in (0x0001, 0x0002)}      # (pk, sk), memory only
        self.base = []

    def com(self, sid):
        return v.commitment(sid, self.keys[sid][0])

    def state(self, n):
        c = v.Chain("regtest", self.initial_target, lambda h, hd: True, self.pq)
        c.add_genesis(self.genesis)
        for b in self.base[:n]:
            c.connect(b)
        return c

    def coinbase(self, height, amount, extra=b"", outputs=None, prev_index=None, locktime=None, pk=b""):
        outs = outputs or [v.Output(amount, 0x0001, self.com(0x0001))]
        pi = height % 2 ** 32 if prev_index is None else prev_index
        lt = height >> 32 if locktime is None else locktime
        return v.Tx([(bytes(32), pi)], outs, [v.Witness(0, pk, extra)], locktime=lt)

    def sign(self, chain, tx, spent, paths, sids, mutate=None, network=None):
        net = v.NETWORK_IDS[network] if network else chain.network_id
        gid = chain.blocks[0].header.block_id()
        wits = []
        for i, (path, sid) in enumerate(zip(paths, sids)):
            if path == 2:  # shared authorization (transactions.md §8.2): empty witness
                wits.append(v.Witness(2, b"", b""))
                continue
            pk, sk = self.keys[sid]
            sig = self.pq.sign(sid, sk, v.sighash(net, gid, tx, i, spent, path))
            wits.append(v.Witness(path, pk, sig))
        tx.witnesses = wits
        if mutate:
            mutate(tx)
        return tx

    def block(self, chain, txs, ts=None, target=None, root=None, version=1):
        h = len(chain.blocks)
        parent = chain.blocks[-1].header
        t = chain.blocks[0].header.timestamp + v.T * h if ts is None else ts
        tg = v.next_target(self.initial_target, chain.blocks[0].header.timestamp, h - 1, parent.timestamp) \
            if target is None else target
        rt = v.merkle_root([x.wtxid() for x in txs]) if root is None else root
        return v.Block(v.Header(parent.block_id(), rt, t, tg, 0, version), txs)


def signed_vectors(pq):
    B = Builder(pq)
    ML, SLH = 0x0001, 0x0002
    # base chain ------------------------------------------------------------
    c = B.state(0)
    notes = {}
    for h in range(1, 296):
        txs = [B.coinbase(h, v.subsidy(h), extra=h.to_bytes(4, "little"))]
        if h == 290:
            cb1 = B.base[0].txs[0]                       # height-1 coinbase, mature at 289
            a = v.Output(v.subsidy(1) - 3_000_000, ML, B.com(ML))
            rec = v.Output(1_000_000, ML, B.com(ML), policy=1, recovery_scheme_id=SLH,
                           recovery_commitment=B.com(SLH), recovery_delay=5)
            t1 = B.sign(c, v.Tx([(cb1.txid(), 0)], [a, rec], []), [cb1.outputs[0]], [0], [ML])
            t2 = B.sign(c, v.Tx([(t1.txid(), 0)], [v.Output(a.amount - 1_000_000, SLH, B.com(SLH))], []),
                        [a], [0], [ML])                  # same-block spend of t1:0, fee 1,000,000
            txs = [B.coinbase(h, v.subsidy(h) + 2_000_000, extra=b"fees")] + [t1, t2]
            notes.update(t1=t1, t2=t2, rec=rec)
        blk = B.block(c, txs)
        c.connect(blk)
        B.base.append(blk)
    N = len(B.base)
    t1, t2, rec = notes["t1"], notes["t2"], notes["rec"]
    cases = []

    def case(name, parent, make, expect):
        chain = B.state(parent)
        blk = make(chain)
        raw = blk if isinstance(blk, bytes) else blk.serialize()
        try:
            B.state(parent).connect(v.Block.parse(raw))
            got, reason = "valid", ""
        except v.Invalid as e:
            got, reason = "invalid", str(e)
        assert got == expect, (name, got, reason)
        cases.append({"name": name, "parent_height": parent, "block": raw.hex(),
                      "result": got, "reason": reason})

    def cbonly(**kw):
        return lambda ch: B.block(ch, [B.coinbase(len(ch.blocks), v.subsidy(len(ch.blocks)), **kw)])

    def spend(prev_tx, idx, spent_out, path, sid, out_amount=None, fee=0, extra_cb=0, mutate=None, network=None,
              out=None, locktime=0, version=1, outs=None, **blk):
        def make(ch):
            h = len(ch.blocks)
            o = out or v.Output((out_amount if out_amount is not None else spent_out.amount - fee), ML, B.com(ML))
            tx = B.sign(ch, v.Tx([(prev_tx.txid(), idx)], [o] if outs is None else outs, [], locktime=locktime,
                                 version=version), [spent_out], [path], [sid],
                        mutate=mutate, network=network)
            return B.block(ch, [B.coinbase(h, v.subsidy(h) + fee + extra_cb)] + [tx], **blk)
        return make

    cb2 = B.base[1].txs[0]
    # header rules
    case("empty block, exact subsidy", N, cbonly(), "valid")
    case("coinbase claims subsidy + 1", N, lambda ch: B.block(ch, [B.coinbase(N + 1, v.subsidy(N + 1) + 1)]), "invalid")
    case("coinbase claims less than allowed", N, lambda ch: B.block(ch, [B.coinbase(N + 1, 1)]), "valid")
    case("header version 2", N, lambda ch: B.block(ch, [B.coinbase(N + 1, 1)], version=2), "invalid")
    case("wrong target", N, lambda ch: B.block(ch, [B.coinbase(N + 1, 1)], target=2 ** 240 - 1), "invalid")
    case("bad tx root", N, lambda ch: B.block(ch, [B.coinbase(N + 1, 1)], root=bytes(32)), "invalid")
    case("timestamp equal to median time past", N,
         lambda ch: B.block(ch, [B.coinbase(N + 1, 1)], ts=ch.mtp(),
                            target=v.next_target(2 ** 240, ch.blocks[0].header.timestamp, N, ch.blocks[-1].header.timestamp)),
         "invalid")
    case("timestamp median time past + 1", N,
         lambda ch: B.block(ch, [B.coinbase(N + 1, 1)], ts=ch.mtp() + 1), "valid")
    case("timestamp far behind schedule (target follows ASERT)", N,
         lambda ch: B.block(ch, [B.coinbase(N + 1, 1)], ts=ch.blocks[-1].header.timestamp + 20_000), "valid")
    # coinbase rules
    case("coinbase prev_index not height", N, cbonly(prev_index=N), "invalid")
    case("coinbase locktime not height>>32", N, cbonly(locktime=1), "invalid")
    case("coinbase extra 64 bytes", N, cbonly(extra=b"x" * 64), "valid")
    case("coinbase extra 65 bytes", N, cbonly(extra=b"x" * 65), "invalid")
    case("coinbase witness public key not empty", N, cbonly(pk=b"\x01"), "invalid")
    case("coinbase output amount 0", N, cbonly(outputs=[v.Output(0, ML, B.com(ML))]), "invalid")
    case("coinbase output unknown scheme", N, cbonly(outputs=[v.Output(1, 0x0003, B.com(ML))]), "invalid")
    case("coinbase output version 0", N, cbonly(outputs=[v.Output(1, ML, B.com(ML), output_version=0)]), "invalid")
    case("coinbase output recovery delay 0", N,
         cbonly(outputs=[v.Output(1, ML, B.com(ML), policy=1, recovery_scheme_id=SLH,
                                  recovery_commitment=B.com(SLH), recovery_delay=0)]), "invalid")
    case("two coinbases (null input outside position 0)", N,
         lambda ch: B.block(ch, [B.coinbase(N + 1, 1), B.coinbase(N + 1, 2, extra=b"2")]), "invalid")
    # maturity boundary: height-2 coinbase is spendable from height 290
    case("spend coinbase at height 289 (immature)", 288, spend(cb2, 0, cb2.outputs[0], 0, ML), "invalid")
    case("spend coinbase at height 290 (mature)", 289, spend(cb2, 0, cb2.outputs[0], 0, ML), "valid")
    # signatures
    case("SLH-DSA primary spend", N, spend(t2, 0, t2.outputs[0], 0, SLH), "valid")
    case("signature bit flipped", 289,
         spend(cb2, 0, cb2.outputs[0], 0, ML, mutate=lambda tx: setattr(tx.witnesses[0], "signature",
               bytes([tx.witnesses[0].signature[0] ^ 1]) + tx.witnesses[0].signature[1:])), "invalid")
    case("signature made for mainnet sighash", 289, spend(cb2, 0, cb2.outputs[0], 0, ML, network="mainnet"), "invalid")
    case("public key does not match commitment", 289,
         spend(cb2, 0, cb2.outputs[0], 0, ML, mutate=lambda tx: setattr(tx.witnesses[0], "public_key",
               bytes([tx.witnesses[0].public_key[0] ^ 1]) + tx.witnesses[0].public_key[1:])), "invalid")
    case("ML-DSA key and signature under SLH-DSA output", N, spend(t2, 0, t2.outputs[0], 0, ML), "invalid")
    # recovery boundary: output t1:1 created at 290 with delay 5 -> recovery from height 295
    case("primary path of recovery output at height 291", 290, spend(t1, 1, rec, 0, ML), "valid")
    case("recovery path at height 294 (too early)", 293, spend(t1, 1, rec, 1, SLH), "invalid")
    case("recovery path at height 295", 294, spend(t1, 1, rec, 1, SLH), "valid")
    case("recovery path on a single-policy output", N, spend(t2, 0, t2.outputs[0], 1, SLH), "invalid")
    case("path 2 without an earlier authorizing input", N, spend(t2, 0, t2.outputs[0], 2, SLH), "invalid")
    case("unknown path 3 (parse error)", N,
         spend(t2, 0, t2.outputs[0], 0, SLH, mutate=lambda tx: setattr(tx.witnesses[0], "path", 3)), "invalid")

    # --- shared authorization (transactions.md §8.2) ---
    cb3, cb4 = B.base[2].txs[0], B.base[3].txs[0]   # two mature coinbases paid to the same ML-DSA key

    def shared(paths, inputs=None, mutate=None, parent_h=None):
        def make(ch):
            h = len(ch.blocks)
            ins = inputs or [(cb3, 0), (cb4, 0)]
            spent = [t.outputs[i] for t, i in ins]
            total = sum(o.amount for o in spent)
            tx = v.Tx([(t.txid(), i) for t, i in ins], [v.Output(total - 10_000, SLH, B.com(SLH))], [])
            sids = [(o.recovery_scheme_id if p == 1 else o.scheme_id) for o, p in zip(spent, paths)]
            B.sign(ch, tx, spent, paths, sids, mutate=mutate)
            return B.block(ch, [B.coinbase(h, v.subsidy(h) + 10_000)] + [tx])
        return make
    case("shared: second input reuses the first input's key (path 0 then 2)", N, shared([0, 2]), "valid")
    case("shared: path 2 before the authorizing input", N, shared([2, 0]), "invalid")
    case("shared: path 2 with a public key", N,
         shared([0, 2], mutate=lambda tx: setattr(tx.witnesses[1], "public_key", tx.witnesses[0].public_key)), "invalid")
    case("shared: path 2 with a signature", N,
         shared([0, 2], mutate=lambda tx: setattr(tx.witnesses[1], "signature", tx.witnesses[0].signature)), "invalid")
    case("shared: path 2 for an output under a different key", N,
         shared([0, 2], inputs=[(cb3, 0), (t2, 0)]), "invalid")
    case("shared: both inputs signed (path 0 and 0)", N, shared([0, 0]), "valid")
    # recovery signature (SLH key) authorizes a later output whose primary key is that SLH key
    case("shared: recovery-path signature authorizes a later primary output of the same key", 294,
         shared([1, 2], inputs=[(t1, 1), (t2, 0)]), "valid")
    case("shared: recovery-path signature too early (delay not met)", 293,
         shared([1, 2], inputs=[(t1, 1), (t2, 0)]), "invalid")
    # value rules
    case("fee collected by coinbase", N, spend(t2, 0, t2.outputs[0], 0, SLH, fee=5000), "valid")
    case("coinbase claims fee + 1", N, spend(t2, 0, t2.outputs[0], 0, SLH, fee=5000, extra_cb=1), "invalid")
    case("outputs exceed inputs", N, spend(t2, 0, t2.outputs[0], 0, SLH, out_amount=t2.outputs[0].amount + 1), "invalid")
    case("locktime equal to height", N, spend(t2, 0, t2.outputs[0], 0, SLH, locktime=N + 1), "valid")
    case("locktime height + 1", N, spend(t2, 0, t2.outputs[0], 0, SLH, locktime=N + 2), "invalid")
    case("spend already-spent output", N, spend(t1, 0, t1.outputs[0], 0, ML), "invalid")
    case("spend nonexistent output", N, spend(t2, 5, t2.outputs[0], 0, SLH), "invalid")

    def double(ch):
        h = len(ch.blocks)
        o = t2.outputs[0]
        a = B.sign(ch, v.Tx([(t2.txid(), 0)], [v.Output(o.amount, ML, B.com(ML))], []), [o], [0], [SLH])
        b = B.sign(ch, v.Tx([(t2.txid(), 0)], [v.Output(o.amount - 1, ML, B.com(ML))], []), [o], [0], [SLH])
        return B.block(ch, [B.coinbase(h, v.subsidy(h))] + [a, b])
    case("double spend inside one block", N, double, "invalid")

    def dup(ch):
        h = len(ch.blocks)
        o = t2.outputs[0]
        a = B.sign(ch, v.Tx([(t2.txid(), 0)], [v.Output(o.amount, ML, B.com(ML))], []), [o], [0], [SLH])
        return B.block(ch, [B.coinbase(h, v.subsidy(h)), a, a])
    case("same transaction twice", N, dup, "invalid")

    def order(ch, reverse):
        h = len(ch.blocks)
        o = t2.outputs[0]
        a = B.sign(ch, v.Tx([(t2.txid(), 0)], [v.Output(o.amount, ML, B.com(ML))], []), [o], [0], [SLH])
        b = B.sign(ch, v.Tx([(a.txid(), 0)], [v.Output(o.amount, SLH, B.com(SLH))], []), [a.outputs[0]], [0], [ML])
        return B.block(ch, [B.coinbase(h, v.subsidy(h))] + ([b, a] if reverse else [a, b]))
    case("same-block spend, parent first", N, lambda ch: order(ch, False), "valid")
    case("same-block spend, child first", N, lambda ch: order(ch, True), "invalid")

    # --- added after the independent verifier's mutation testing (2026-10-31) ---
    t0 = B.genesis.header.timestamp
    case("even MTP window (4 blocks): timestamp = upper median, invalid", 3,
         lambda ch: B.block(ch, [B.coinbase(4, 1)], ts=t0 + 600), "invalid")
    case("even MTP window (4 blocks): upper median + 1, valid", 3,
         lambda ch: B.block(ch, [B.coinbase(4, 1)], ts=t0 + 601), "valid")

    def heavy(extra_len):
        # coinbase-only block; coinbase weight = its byte length (transactions.md §9)
        return lambda ch: B.block(ch, [B.coinbase(N + 1, 0, extra=b"w" * extra_len,
                                                  outputs=[v.Output(1, ML, B.com(ML))] * 16362)])
    for e, exp in ((22, "valid"), (23, "invalid")):
        blk = heavy(e)(B.state(N))
        assert blk.txs[0].weight(coinbase=True) == 719_978 + e
    case("block weight exactly 720,000", N, heavy(22), "valid")
    case("block weight 720,001", N, heavy(23), "invalid")
    case("transaction version 2", N, spend(t2, 0, t2.outputs[0], 0, SLH, version=2), "invalid")
    case("transaction with zero outputs", N, spend(t2, 0, t2.outputs[0], 0, SLH, outs=[]), "invalid")
    case("transaction with zero inputs", N,
         lambda ch: B.block(ch, [B.coinbase(N + 1, 1), v.Tx([], [v.Output(1, ML, B.com(ML))], [])]), "invalid")

    case("transaction with zero inputs and zero outputs", N,
         lambda ch: B.block(ch, [B.coinbase(N + 1, 1), v.Tx([], [], [])]), "invalid")

    def two_input_coinbase(ch):
        cbx = B.coinbase(N + 1, 1)
        cbx.inputs.append((t2.txid(), 0))
        cbx.witnesses.append(v.Witness(0, b"", b""))
        return B.block(ch, [cbx])
    case("coinbase with a second input", N, two_input_coinbase, "invalid")

    def no_coinbase(ch):
        o = t2.outputs[0]
        a = B.sign(ch, v.Tx([(t2.txid(), 0)], [v.Output(o.amount, ML, B.com(ML))], []), [o], [0], [SLH])
        return B.block(ch, [a])
    case("first transaction is not a coinbase", N, no_coinbase, "invalid")

    def orphan(ch):
        blk = B.block(ch, [B.coinbase(N + 1, 1)])
        blk.header.prev_block = bytes(31) + b"\x01"
        return blk
    case("unknown parent (prev_block mismatch)", N, orphan, "invalid")
    case("output with unknown recovery scheme", N,
         cbonly(outputs=[v.Output(1, ML, B.com(ML), policy=1, recovery_scheme_id=0x0003,
                                  recovery_commitment=B.com(SLH), recovery_delay=10)]), "invalid")
    case("recovery delay 2^31 - 1 (maximum)", N,
         cbonly(outputs=[v.Output(1, ML, B.com(ML), policy=1, recovery_scheme_id=SLH,
                                  recovery_commitment=B.com(SLH), recovery_delay=2 ** 31 - 1)]), "valid")
    case("recovery delay 2^31", N,
         cbonly(outputs=[v.Output(1, ML, B.com(ML), policy=1, recovery_scheme_id=SLH,
                                  recovery_commitment=B.com(SLH), recovery_delay=2 ** 31)]), "invalid")

    def spend_own_coinbase(ch):
        h = len(ch.blocks)
        cbx = B.coinbase(h, v.subsidy(h))
        tx = B.sign(ch, v.Tx([(cbx.txid(), 0)], [v.Output(cbx.outputs[0].amount, ML, B.com(ML))], []),
                    [cbx.outputs[0]], [0], [ML])
        return B.block(ch, [cbx, tx])
    case("coinbase output spent in the same block", N, spend_own_coinbase, "invalid")
    case("trailing byte after the last transaction", N,
         lambda ch: B.block(ch, [B.coinbase(N + 1, 1)]).serialize() + b"\x00", "invalid")
    case("tx_count 0", N, lambda ch: B.block(ch, [B.coinbase(N + 1, 1)]).header.serialize() + b"\x00", "invalid")

    sigs = []
    for sid, name in ((ML, "ML-DSA-65"), (SLH, "SLH-DSA-SHA2-128s")):
        pk, sk = B.keys[sid]
        msg = v.h256("VARVE/test/message", name.encode())
        sig = pq.sign(sid, sk, msg)
        assert pq.verify(sid, pk, msg, sig)
        bad = bytes([sig[-1] ^ 0x80])
        sigs += [
            {"name": f"{name} valid", "scheme_id": sid, "public_key": pk.hex(), "message": msg.hex(), "signature": sig.hex(), "valid": True},
            {"name": f"{name} last byte flipped", "scheme_id": sid, "public_key": pk.hex(), "message": msg.hex(),
             "signature": (sig[:-1] + bad).hex(), "valid": False},
            {"name": f"{name} other message", "scheme_id": sid, "public_key": pk.hex(), "message": bytes(32).hex(),
             "signature": sig.hex(), "valid": False},
        ]
        for s in sigs[-2:]:
            assert not pq.verify(sid, bytes.fromhex(s["public_key"]), bytes.fromhex(s["message"]), bytes.fromhex(s["signature"]))
    chain = {
        "_comment": ("Block-level validity cases on a regtest chain. Proof of work is NOT checked (any nonce). "
                     "Candidate height = parent_height + 1; state = genesis + base_chain[:parent_height]. "
                     "Genesis is built from the genesis.json fixture with the DRAFT params_hash. "
                     "Signatures are randomized, so this file is generated once and verified in CI, not regenerated. "
                     "Only public keys appear; no secret keys were stored. 'reason' is informative. "
                     "Not covered here: the 720,000 weight limit (see consensus.json weights)."),
        "network": "regtest", "network_id": v.NETWORK_IDS["regtest"].hex(),
        "initial_target": f"{B.initial_target:064x}",
        "genesis": B.genesis.serialize().hex(),
        "base_chain": [b.serialize().hex() for b in B.base],
        "cases": cases,
    }
    return chain, {"_comment": "Signature verification vectors. Public keys only; generated once.", "signatures": sigs}


def main():
    dump("consensus.json", consensus_vectors())
    if "--signed" in sys.argv:
        with v.PQ(os.environ.get("VARVE_LIBOQS")) as pq:
            chain, sigs = signed_vectors(pq)
        dump("chain.json", chain)
        dump("signatures.json", sigs)
        print(f"chain.json: {len(chain['base_chain'])} base blocks, {len(chain['cases'])} cases")


if __name__ == "__main__":
    main()
