"""Tests for the disposable consensus prototype.

Run:  VARVE_LIBOQS=/path/to/liboqs.so python3 -I -m unittest prototype/test_proto.py
Signature tests are skipped when VARVE_LIBOQS is not set.
Proof of work is a TEST-ONLY permissive stub; RandomX is covered by test-vectors/pow.json.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import varve_proto as v  # noqa: E402

ROOT = v.ROOT
INIT_TARGET = 2 ** 240
PARAMS_HASH = bytes.fromhex(json.load(open(os.path.join(ROOT, "test-vectors", "params.json")))["params_hash"])
def fake_btc_headers(times=(1_800_000_000, 1_800_000_600, 1_800_001_200, 1_800_001_800, 1_800_002_400, 1_800_003_000)):
    """Six 80-byte placeholders with only the timestamp field set. TEST ONLY: not real Bitcoin headers."""
    return [bytes([k]) * 68 + t.to_bytes(4, "little") + bytes(8) for k, t in enumerate(times)]


def load(name):
    with open(os.path.join(ROOT, "test-vectors", name)) as fh:
        return json.load(fh)


class Vectors(unittest.TestCase):
    def test_subsidy_vectors(self):
        for c in load("subsidy.json")["subsidy"]:
            self.assertEqual(v.subsidy(c["height"]), c["subsidy"], c)

    def test_difficulty_vectors(self):
        for c in load("difficulty.json")["cases"]:
            got = v.next_target(INIT_TARGET, 0, c["parent_height"], c["parent_time_minus_genesis"])
            self.assertEqual(f"{got:064x}", c["next_target_hex"], c["label"])

    def test_commitment_vectors(self):
        a = load("addresses.json")
        self.assertEqual(v.commitment(1, bytes(i % 256 for i in range(1952))).hex(), a["commitments"]["mldsa65"])
        self.assertEqual(v.commitment(2, bytes((255 - i) % 256 for i in range(32))).hex(), a["commitments"]["slhdsa128s"])


class ChainSelection(unittest.TestCase):
    def test_chainwork_never_wraps(self):
        # target = 1 gives work 2^255; two such blocks sum to 2^256, which does not fit in u256 (audit H-02)
        h = v.Header(bytes(32), bytes(32), 0, 1)
        self.assertEqual(v.work(1), 2 ** 255)
        self.assertEqual(v.chainwork([h, h]), 2 ** 256)

    def test_heavier_shorter_fork_is_always_validated(self):
        # audit C-01: active branch has 1 block after the fork, candidate has 2 at the same target
        t = 2 ** 240
        fork_work = 1000 * v.work(t)
        active = fork_work + 1 * v.work(t)
        candidate = fork_work + 2 * v.work(t)
        self.assertEqual(v.sync_action(candidate, active, t), "validate")

    def test_far_inferior_branch_may_be_postponed(self):
        t = 2 ** 240
        active = 1000 * v.work(t)
        self.assertEqual(v.sync_action(active - 100 * v.work(t), active, t), "may_postpone")
        self.assertEqual(v.sync_action(active - 3 * v.work(t), active, t), "validate")   # near-tie prepared early


class Genesis(unittest.TestCase):
    def test_seed_depends_on_every_header(self):
        base = v.genesis_block(PARAMS_HASH, fake_btc_headers(), INIT_TARGET).header.block_id()
        for k in range(6):
            hs = fake_btc_headers()
            hs[k] = bytes([0xEE]) + hs[k][1:]
            self.assertNotEqual(v.genesis_block(PARAMS_HASH, hs, INIT_TARGET).header.block_id(), base, k)

    def test_anchor_vectors(self):
        d = load("genesis.json")
        for c in d["anchor_cases"]:
            hs = [bytes.fromhex(x) for x in c["headers"]]
            try:
                v.check_btc_anchor(hs, c["anchor_height"], bytes.fromhex(c["anchor_prev_hash_internal"]),
                                   int(c["anchor_bits"], 16))
                got = "valid"
            except v.Invalid as e:
                got = str(e)
            self.assertEqual(got, c["result"], c["name"])
        for c in d["compact_cases"]:
            try:
                got = {"bits": c["bits"], "target": f"{v.btc_compact_to_target(int(c['bits'], 16)):064x}"}
            except v.Invalid as e:
                got = {"bits": c["bits"], "result": str(e)}
            self.assertEqual(got, c)

    def test_anchor_rejects_every_single_byte_mutation(self):
        hs = [bytes.fromhex(x) for x in load("genesis.json")["anchor_cases"][0]["headers"]]
        v.check_btc_anchor(hs, 0, bytes(32), 0x1D00FFFF)
        for k in range(6):
            for off in range(80):
                bad = list(hs)
                x = bytearray(bad[k])
                x[off] ^= 0x01
                bad[k] = bytes(x)
                with self.assertRaises(v.Invalid, msg=(k, off)):
                    v.check_btc_anchor(bad, 0, bytes(32), 0x1D00FFFF)

    def test_example_genesis_reproduces(self):
        d = load("genesis.json")
        hs = [bytes.fromhex(x) for x in d["anchor_cases"][0]["headers"]]
        g = v.genesis_block(bytes.fromhex(d["example_genesis"]["params_hash"]), hs, 2 ** 240)
        self.assertEqual(g.header.block_id().hex(), d["example_genesis"]["block_id"])

    def test_t0_is_upper_median(self):
        g = v.genesis_block(PARAMS_HASH, fake_btc_headers((5, 1, 9, 3, 7, 100)), INIT_TARGET)
        self.assertEqual(g.header.timestamp, 7)          # sorted [1,3,5,7,9,100][3]


class Encoding(unittest.TestCase):
    def test_varint_canonical(self):
        for n in (0, 1, 127, 128, 300, 2 ** 32 - 1):
            r = v.Reader(v.varint(n))
            self.assertEqual(r.varint(), n)
            r.done()
        for bad in (b"\x80\x00", b"\x81\x80\x00", b"\xff\xff\xff\xff\x10", b"\x80\x80\x80\x80\x80\x01", b"\x80"):
            with self.assertRaises(v.Invalid):
                v.Reader(bad).varint()

    def test_merkle_no_duplicate_ambiguity(self):
        a, b, c = (bytes([i]) * 32 for i in (1, 2, 3))
        self.assertNotEqual(v.merkle_root([a, b, c]), v.merkle_root([a, b, c, c]))
        self.assertNotEqual(v.merkle_root([a]), v.merkle_root([a, a]))

    def test_tx_roundtrip_and_txid_ignores_witness(self):
        o = v.Output(5, 1, b"\x11" * 32, policy=1, recovery_scheme_id=2, recovery_commitment=b"\x22" * 32, recovery_delay=9)
        tx = v.Tx([(b"\x33" * 32, 7)], [o], [v.Witness(0, b"k" * 1952, b"s" * 3309)])
        r = v.Reader(tx.full())
        back = v.Tx.parse(r)
        r.done()
        self.assertEqual(back.full(), tx.full())
        tx2 = v.Tx(tx.inputs, tx.outputs, [v.Witness(0, b"k" * 1952, b"t" * 3309)])
        self.assertEqual(tx.txid(), tx2.txid())
        self.assertNotEqual(tx.wtxid(), tx2.wtxid())
        self.assertEqual(len(o.serialize()), 82)

    def test_trailing_bytes_rejected(self):
        tx = v.Tx([(bytes(32), 0)], [v.Output(1, 1, bytes(32))], [v.Witness(0, b"", b"")])
        r = v.Reader(tx.full() + b"\x00")
        v.Tx.parse(r)
        with self.assertRaises(v.Invalid):
            r.done()


class ConsensusVectors(unittest.TestCase):
    def test_transactions(self):
        for c in load("consensus.json")["transactions"]:
            raw = bytes.fromhex(c["hex"])
            try:
                r = v.Reader(raw)
                tx = v.Tx.parse(r)
                r.done()
            except v.Invalid:
                self.assertEqual(c["parse"], "error", c["name"])
                continue
            self.assertEqual(c["parse"], "ok", c["name"])
            self.assertEqual((tx.txid().hex(), tx.wtxid().hex(), tx.weight(), len(tx.base())),
                             (c["txid"], c["wtxid"], c["weight"], c["base_size"]), c["name"])

    def test_merkle_headers_sighash_chainwork(self):
        d = load("consensus.json")
        for c in d["merkle"]:
            self.assertEqual(v.merkle_root([bytes.fromhex(x) for x in c["wtxids"]]).hex(), c["root"], c["name"])
        for c in d["headers"]:
            hd = v.Header.parse(v.Reader(bytes.fromhex(c["hex"])))
            self.assertEqual(hd.serialize().hex(), c["hex"])
            self.assertEqual(hd.block_id().hex(), c["block_id"], c["name"])
        for c in d["sighash"]:
            tx = v.Tx.parse(v.Reader(bytes.fromhex(c["tx_hex"])))
            spent = [v.Output.parse(v.Reader(bytes.fromhex(x))) for x in c["spent_outputs"]]
            got = v.sighash(bytes.fromhex(c["network_id"]), bytes.fromhex(c["genesis_id"]), tx, c["index"], spent, c["path"])
            self.assertEqual(got.hex(), c["sighash"], c["name"])
        for c in d["chainwork"]:
            hs = [v.Header(bytes(32), bytes(32), 0, int(t, 16)) for t in c["targets"]]
            self.assertEqual(v.chainwork(hs), int(c["chainwork"], 16), c["name"])

    def test_parser_fuzz(self):
        """Seeded mutation fuzzing: parsers either succeed or raise Invalid, never anything else."""
        import random
        rng = random.Random(0x5641525645)
        seeds = [bytes.fromhex(c["hex"]) for c in load("consensus.json")["transactions"]]
        for i in range(3000):
            data = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 8)):
                op = rng.randrange(4)
                pos = rng.randrange(len(data) + 1)
                if op == 0 and data:
                    data[pos % len(data)] = rng.randrange(256)
                elif op == 1:
                    data[pos:pos] = bytes([rng.randrange(256)] * rng.randint(1, 5))
                elif op == 2:
                    del data[pos:pos + rng.randint(1, 64)]
                else:
                    data = data[:pos]
            for parse in (lambda b: v.Tx.parse(v.Reader(b)), v.Block.parse):
                try:
                    parse(bytes(data))
                except v.Invalid:
                    pass


@unittest.skipUnless(os.environ.get("VARVE_LIBOQS"), "set VARVE_LIBOQS to run signature tests")
class SignedVectors(unittest.TestCase):
    def test_signatures(self):
        with v.PQ() as pq:
            for c in load("signatures.json")["signatures"]:
                ok = pq.verify(c["scheme_id"], bytes.fromhex(c["public_key"]), bytes.fromhex(c["message"]),
                               bytes.fromhex(c["signature"]))
                self.assertEqual(ok, c["valid"], c["name"])

    def test_chain_cases(self):
        d = load("chain.json")
        with v.PQ() as pq:
            def fresh(n):
                c = v.Chain(d["network"], int(d["initial_target"], 16), lambda h, hd: True, pq)
                c.add_genesis(v.Block.parse(bytes.fromhex(d["genesis"])))
                for b in base[:n]:
                    c.connect(b)
                return c
            base = [v.Block.parse(bytes.fromhex(x)) for x in d["base_chain"]]
            for b in base:
                self.assertEqual(b.serialize().hex(), d["base_chain"][base.index(b)])
            snapshots = {}
            for c in d["cases"]:
                p = c["parent_height"]
                if p not in snapshots:
                    snapshots[p] = fresh(p)
                chain = snapshots[p]
                state = (dict(chain.utxo), list(chain.blocks))
                try:
                    chain.connect(v.Block.parse(bytes.fromhex(c["block"])))
                    got = "valid"
                except v.Invalid:
                    got = "invalid"
                chain.utxo, chain.blocks = state
                self.assertEqual(got, c["result"], c["name"])


@unittest.skipUnless(os.environ.get("VARVE_LIBOQS"), "set VARVE_LIBOQS to run signature tests")
class ChainEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pq = v.PQ()
        cls.addClassCleanup(cls.pq.close)
        cls.pk_a, cls.sk_a = cls.pq.keypair(1)     # ML-DSA-65: everyday key
        cls.pk_r, cls.sk_r = cls.pq.keypair(2)     # SLH-DSA-128s: recovery key
        cls.pk_b, cls.sk_b = cls.pq.keypair(1)

    def new_chain(self, network="regtest"):
        c = v.Chain(network, INIT_TARGET, pow_ok=lambda h, hd: True, pq=self.pq)   # TEST-ONLY PoW stub
        c.add_genesis(v.genesis_block(PARAMS_HASH, fake_btc_headers(), INIT_TARGET))
        return c

    def mine(self, chain, txs=(), pay_to=None, claim_extra=0, coinbase=None, ts_offset=0):
        h = len(chain.blocks)
        g, p = chain.blocks[0].header, chain.blocks[-1].header
        pay_to = pay_to or v.Output(1, 1, bytes(32))
        pay_to.amount = v.subsidy(h) + claim_extra
        cb = coinbase or v.Tx([(bytes(32), h % 2 ** 32)], [pay_to], [v.Witness(0, b"", b"")], locktime=h >> 32)
        txs = [cb, *txs]
        ts = g.timestamp + v.T * h + ts_offset
        hd = v.Header(p.block_id(), v.merkle_root([t.wtxid() for t in txs]), ts,
                      v.next_target(INIT_TARGET, g.timestamp, h - 1, p.timestamp))
        return chain.connect(v.Block(hd, txs)), cb

    def sign_input(self, chain, tx, i, spent, path, sid, sk, pk):
        msg = v.sighash(chain.network_id, chain.blocks[0].header.block_id(), tx, i, spent, path)
        tx.witnesses[i] = v.Witness(path, pk, self.pq.sign(sid, sk, msg))

    def funded_chain(self, recovery_delay=10):
        c = self.new_chain()
        out = v.Output(0, 1, v.commitment(1, self.pk_a), policy=1, recovery_scheme_id=2,
                       recovery_commitment=v.commitment(2, self.pk_r), recovery_delay=recovery_delay)
        _, cb = self.mine(c, pay_to=out)
        while len(c.blocks) <= v.COINBASE_MATURITY + 1:
            self.mine(c)
        return c, (cb.txid(), 0), out

    def spend_tx(self, outpoint, coin_out, to_commitment, fee=1000):
        out = v.Output(coin_out.amount - fee, 1, to_commitment)
        return v.Tx([outpoint], [out], [v.Witness(0, b"", b"")])

    def test_spend_primary_and_reject_tampering(self):
        c, op, coin = self.funded_chain()
        tx = self.spend_tx(op, coin, v.commitment(1, self.pk_b))
        self.sign_input(c, tx, 0, [coin], 0, 1, self.sk_a, self.pk_a)
        bad = v.Tx(tx.inputs, tx.outputs, [v.Witness(0, tx.witnesses[0].public_key,
                                                      bytes([tx.witnesses[0].signature[0] ^ 1]) + tx.witnesses[0].signature[1:])])
        with self.assertRaises(v.Invalid):
            self.mine(c, [bad])
        weight, _ = self.mine(c, [tx])
        self.assertLessEqual(weight, v.MAX_BLOCK_WEIGHT)
        with self.assertRaises(v.Invalid):          # double spend in a later block
            self.mine(c, [tx])

    def test_cross_network_replay_rejected(self):
        c, op, coin = self.funded_chain()
        tx = self.spend_tx(op, coin, v.commitment(1, self.pk_b))
        msg = v.sighash(v.NETWORK_IDS["mainnet"], c.blocks[0].header.block_id(), tx, 0, [coin], 0)  # other network
        tx.witnesses[0] = v.Witness(0, self.pk_a, self.pq.sign(1, self.sk_a, msg))
        with self.assertRaises(v.Invalid):
            self.mine(c, [tx])

    def test_signature_bound_to_genesis(self):
        c, op, coin = self.funded_chain()
        tx = self.spend_tx(op, coin, v.commitment(1, self.pk_b))
        msg = v.sighash(c.network_id, bytes(32), tx, 0, [coin], 0)                # wrong genesis id
        tx.witnesses[0] = v.Witness(0, self.pk_a, self.pq.sign(1, self.sk_a, msg))
        with self.assertRaises(v.Invalid):
            self.mine(c, [tx])

    def test_coinbase_height_encoding_and_null_inputs(self):
        c = self.new_chain()
        bad_cb = v.Tx([(bytes(32), 999)], [v.Output(v.subsidy(1), 1, bytes(32))], [v.Witness(0, b"", b"")])
        with self.assertRaises(v.Invalid):
            self.mine(c, coinbase=bad_cb)                       # prev_index must equal height
        self.mine(c)
        fake = v.Tx([(bytes(32), 5)], [v.Output(1, 1, bytes(32))], [v.Witness(0, b"", b"")])
        with self.assertRaises(v.Invalid):
            self.mine(c, [fake])                                # null input outside the coinbase

    def test_median_time_past_even_count(self):
        c = self.new_chain()
        self.mine(c, ts_offset=200)                             # block 1 at t0+500
        t0 = c.blocks[0].header.timestamp
        # S = [t0, t0+500] -> upper median t0+500; block 2 at t0+400 must be rejected
        with self.assertRaises(v.Invalid):
            self.mine(c, ts_offset=400 - 2 * v.T)
        self.mine(c, ts_offset=501 - 2 * v.T)                   # t0+501 > MTP: accepted
        self.assertEqual(c.blocks[-1].header.timestamp, t0 + 501)

    def test_recovery_path_timing(self):
        c, op, coin = self.funded_chain(recovery_delay=v.COINBASE_MATURITY + 5)
        tx = self.spend_tx(op, coin, v.commitment(1, self.pk_b))
        self.sign_input(c, tx, 0, [coin], 1, 2, self.sk_r, self.pk_r)
        with self.assertRaises(v.Invalid):          # before created_height + delay
            self.mine(c, [tx])
        while len(c.blocks) < 1 + coin.recovery_delay:
            self.mine(c)
        self.mine(c, [tx])                          # exactly at created_height + delay

    def test_inflation_and_maturity_rejected(self):
        c, op, coin = self.funded_chain()
        with self.assertRaises(v.Invalid):
            self.mine(c, claim_extra=1)             # coinbase claims more than subsidy + fees
        young = self.new_chain()
        _, cb = self.mine(young, pay_to=v.Output(0, 1, v.commitment(1, self.pk_a)))
        out0 = cb.outputs[0]
        tx = self.spend_tx((cb.txid(), 0), out0, v.commitment(1, self.pk_b))
        self.sign_input(young, tx, 0, [out0], 0, 1, self.sk_a, self.pk_a)
        with self.assertRaises(v.Invalid):
            self.mine(young, [tx])                  # coinbase not yet mature


if __name__ == "__main__":
    # With VARVE_REQUIRE_LIBOQS=1 (CI crypto job), any skipped test is a failure (audit H-03).
    prog = unittest.main(exit=False)
    result = prog.result
    if os.environ.get("VARVE_REQUIRE_LIBOQS") and result.skipped:
        print(f"FAIL: {len(result.skipped)} test(s) skipped although real signatures are required")
        sys.exit(1)
    sys.exit(0 if result.wasSuccessful() else 1)
