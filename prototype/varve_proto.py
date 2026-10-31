"""Varve consensus prototype. DISPOSABLE: not production code, not audited.

A direct, readable transcription of protocol/*.md (draft v0.1), used to find
ambiguities and to cross-check the test vectors. It is deliberately simple and
slow. Proof of work is injected by the caller (the tests use a permissive
test-only stub), because RandomX is out of scope here. Signature verification
uses liboqs through ctypes when a shared library is available (VARVE_LIBOQS).

Never use this code to hold real value.
"""
import ctypes
import hashlib
import json
import os
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")

# ---------------------------------------------------------------- constants
NETWORK_IDS = {"mainnet": b"VARV", "testnet": b"TVAR", "regtest": b"RVAR"}
MAX_MONEY = 2 ** 62
COINBASE_MATURITY = 288
COINBASE_EXTRA_MAX = 64
MAX_BLOCK_WEIGHT = 720_000
UTXO_GROWTH_UNITS = 100
RECOVERY_DELAY_MAX = 2 ** 31 - 1
T, TAU, MTP_WINDOW = 300, 21_600, 11
ASERT_ANCHOR_DELAY = 7_200      # difficulty.md §2: schedule anchored at t0 + D
VERIFY_UNITS_BY_SIG_LEN = {3309: 100, 7856: 1700}
MIN_SIZE = {"input": 36, "output": 44, "witness": 3}
SCHEMES = {  # scheme_id: (liboqs name, pk_len, sk_len, sig_len, verify_units)
    0x0001: ("ML-DSA-65", 1952, 4032, 3309, 100),
    0x0002: ("SLH_DSA_PURE_SHA2_128S", 32, 64, 7856, 1700),
}
with open(os.path.join(ROOT, "test-vectors", "subsidy.json")) as _fh:
    _sv = json.load(_fh)["constants"]
INITIAL_SUBSIDY, TAIL_SUBSIDY = _sv["INITIAL_SUBSIDY"], _sv["TAIL_SUBSIDY"]
BLOCKS_PER_EPOCH = _sv["BLOCKS_PER_EPOCH"]
FRAC = [int(x, 16) for x in _sv["FRAC_Q63"]]


class Invalid(Exception):
    """Raised for any consensus-invalid encoding, transaction, or block."""


# ---------------------------------------------------------------- encoding.md
def u(n, width):
    if not 0 <= n < 1 << (8 * width):
        raise Invalid("integer out of range")
    return n.to_bytes(width, "little")


def varint(n):
    if not 0 <= n < 2 ** 32:
        raise Invalid("varint out of range")
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


class Reader:
    def __init__(self, data):
        self.d, self.i = data, 0

    def take(self, n):
        if n < 0 or self.i + n > len(self.d):
            raise Invalid("truncated")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def need(self, n):
        if self.i + n > len(self.d):
            raise Invalid("declared count exceeds remaining input")

    def uint(self, width):
        return int.from_bytes(self.take(width), "little")

    def varint(self):
        value = 0
        for k in range(5):
            b = self.take(1)[0]
            value |= (b & 0x7F) << (7 * k)
            if not b & 0x80:
                if k > 0 and b == 0:
                    raise Invalid("non-minimal varint")
                if value >= 2 ** 32:
                    raise Invalid("varint out of range")
                return value
        raise Invalid("varint too long")

    def bytes_(self, max_len):
        n = self.varint()
        if n > max_len:
            raise Invalid("byte string too long")
        return self.take(n)

    def done(self):
        if self.i != len(self.d):
            raise Invalid("trailing bytes")


def h256(tag, msg):
    t = tag.encode()
    return hashlib.sha3_256(bytes([len(t)]) + t + msg).digest()


# ---------------------------------------------------------------- transactions.md
@dataclass
class Output:
    amount: int
    scheme_id: int
    commitment: bytes
    policy: int = 0
    recovery_scheme_id: int = 0
    recovery_commitment: bytes = b""
    recovery_delay: int = 0
    output_version: int = 1

    def template(self):
        b = u(self.output_version, 1) + u(self.policy, 1) + u(self.scheme_id, 2) + self.commitment
        if self.policy == 1:
            b += u(self.recovery_scheme_id, 2) + self.recovery_commitment + u(self.recovery_delay, 4)
        return b

    def serialize(self):
        return u(self.amount, 8) + self.template()

    @staticmethod
    def parse(r):
        amount, version, policy = r.uint(8), r.uint(1), r.uint(1)
        scheme, commitment = r.uint(2), r.take(32)
        if policy not in (0, 1):
            raise Invalid("unknown policy")
        o = Output(amount, scheme, commitment, policy, output_version=version)
        if policy == 1:
            o.recovery_scheme_id, o.recovery_commitment, o.recovery_delay = r.uint(2), r.take(32), r.uint(4)
        return o


@dataclass
class Witness:
    path: int
    public_key: bytes
    signature: bytes

    def serialize(self):
        return u(self.path, 1) + varint(len(self.public_key)) + self.public_key + varint(len(self.signature)) + self.signature


@dataclass
class Tx:
    inputs: list            # list of (prev_txid: bytes, prev_index: int)
    outputs: list           # list of Output
    witnesses: list         # list of Witness
    locktime: int = 0
    version: int = 1

    def base(self):
        b = u(self.version, 4) + varint(len(self.inputs))
        for txid, idx in self.inputs:
            b += txid + u(idx, 4)
        b += varint(len(self.outputs)) + b"".join(o.serialize() for o in self.outputs)
        return b + u(self.locktime, 4)

    def full(self):
        return self.base() + b"".join(w.serialize() for w in self.witnesses)

    def txid(self):
        return h256("VARVE/txid/v1", self.base())

    def wtxid(self):
        return h256("VARVE/wtxid/v1", self.full())

    def has_null_input(self):
        return any(txid == bytes(32) for txid, _ in self.inputs)

    def weight(self, coinbase=False):
        """transactions.md §9: computable from bytes alone."""
        w = len(self.full())
        if coinbase:
            return w
        w += sum(VERIFY_UNITS_BY_SIG_LEN.get(len(x.signature), 0) for x in self.witnesses)
        return w + UTXO_GROWTH_UNITS * max(0, len(self.outputs) - len(self.inputs))

    @staticmethod
    def parse(r):
        version = r.uint(4)
        n_in = r.varint()
        r.need(n_in * (MIN_SIZE["input"] + MIN_SIZE["witness"]))
        inputs = [(r.take(32), r.uint(4)) for _ in range(n_in)]
        n_out = r.varint()
        r.need(n_out * MIN_SIZE["output"])
        outputs = [Output.parse(r) for _ in range(n_out)]
        locktime = r.uint(4)
        max_pk, max_sig = 1952, 7856
        witnesses = []
        for _ in range(n_in):
            path = r.uint(1)
            if path not in (0, 1, 2):
                raise Invalid("unknown witness path")          # parse-time rule (encoding.md §1.5)
            witnesses.append(Witness(path, r.bytes_(max_pk), r.bytes_(max_sig)))
        return Tx(inputs, outputs, witnesses, locktime, version)


def commitment(scheme_id, public_key):
    return h256("VARVE/pk/v1", u(scheme_id, 2) + public_key)


def sighash(network_id, genesis_id, tx, index, spent_outputs, path):
    spent_hash = h256("VARVE/spent/v1", b"".join(o.serialize() for o in spent_outputs))
    return h256("VARVE/sighash/v1", network_id + genesis_id + tx.txid() + u(index, 4) + spent_hash + u(path, 1))


# ---------------------------------------------------------------- liboqs (signatures)
class PQ:
    """Minimal ctypes wrapper. Pure-mode sign/verify with empty context."""

    def __init__(self, path=None):
        path = path or os.environ.get("VARVE_LIBOQS")
        if not path:
            raise RuntimeError("set VARVE_LIBOQS to a liboqs shared library")
        self.lib = ctypes.CDLL(path)
        self.lib.OQS_SIG_new.restype = ctypes.c_void_p
        self.lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]
        for f in ("OQS_SIG_keypair", "OQS_SIG_sign", "OQS_SIG_verify"):
            getattr(self.lib, f).restype = ctypes.c_int
        self.lib.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.OQS_SIG_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t),
                                          ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        self.lib.OQS_SIG_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        self.lib.OQS_SIG_free.restype = None
        self.lib.OQS_SIG_free.argtypes = [ctypes.c_void_p]
        self.handles = {sid: self.lib.OQS_SIG_new(v[0].encode()) for sid, v in SCHEMES.items()}
        if not all(self.handles.values()):
            self.close()
            raise RuntimeError("liboqs lacks a required scheme")

    def close(self):
        """Free liboqs handles (audit L-02)."""
        for sid, h in list(self.handles.items()):
            if h:
                self.lib.OQS_SIG_free(h)
            self.handles[sid] = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def keypair(self, sid):
        _, pk_len, sk_len, _, _ = SCHEMES[sid]
        pk, sk = ctypes.create_string_buffer(pk_len), ctypes.create_string_buffer(sk_len)
        if self.lib.OQS_SIG_keypair(self.handles[sid], pk, sk) != 0:      # explicit check (audit L-01)
            raise RuntimeError("liboqs keypair failed")
        return pk.raw, sk.raw

    def sign(self, sid, sk, msg):
        out, n = ctypes.create_string_buffer(SCHEMES[sid][3]), ctypes.c_size_t(0)
        if self.lib.OQS_SIG_sign(self.handles[sid], out, ctypes.byref(n), msg, len(msg), sk) != 0:
            raise RuntimeError("liboqs sign failed")
        if n.value != SCHEMES[sid][3]:
            raise RuntimeError("unexpected signature length")
        return out.raw[:n.value]

    def verify(self, sid, pk, msg, sig):
        return self.lib.OQS_SIG_verify(self.handles[sid], msg, len(msg), sig, len(sig), pk) == 0


# ---------------------------------------------------------------- subsidy.md / difficulty.md
def subsidy(height):
    if height == 0:
        return 0
    epoch = (height - 1) // BLOCKS_PER_EPOCH
    shift = 63 + epoch // 64
    decayed = 0 if shift >= 128 else (INITIAL_SUBSIDY * FRAC[epoch % 64]) >> shift
    return max(decayed, TAIL_SUBSIDY)


def next_target(initial_target, genesis_time, parent_height, parent_time):
    pow_limit = initial_target * 256
    exponent = ((parent_time - (genesis_time + ASERT_ANCHOR_DELAY)) - T * parent_height) * 65536 // TAU
    if exponent >= 256 << 16:
        return pow_limit
    if exponent <= -(270 << 16):
        return 1
    shifts, frac = exponent >> 16, exponent & 0xFFFF
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac ** 2 + 5127 * frac ** 3 + (1 << 47)) >> 48)
    t = initial_target * factor
    t = t << shifts if shifts >= 0 else t >> -shifts
    return max(1, min(t >> 16, pow_limit))


# ---------------------------------------------------------------- blocks.md
def merkle_root(wtxids):
    level = [h256("VARVE/merkle/leaf", w) for w in wtxids]
    if not level:
        raise Invalid("empty block")
    while len(level) > 1:
        nxt = [h256("VARVE/merkle/node", level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])            # carried up, never duplicated
        level = nxt
    return h256("VARVE/merkle/root", u(len(wtxids), 4) + level[0])


@dataclass
class Header:
    prev_block: bytes
    tx_root: bytes
    timestamp: int
    target: int
    nonce: int = 0
    version: int = 1

    def serialize(self):
        return (u(self.version, 4) + self.prev_block + self.tx_root + u(self.timestamp, 8)
                + u(self.target, 32) + u(self.nonce, 8))

    def block_id(self):
        return h256("VARVE/block/v1", self.serialize())

    @staticmethod
    def parse(r):
        version, prev, root = r.uint(4), r.take(32), r.take(32)
        ts, target, nonce = r.uint(8), r.uint(32), r.uint(8)
        return Header(prev, root, ts, target, nonce, version)


@dataclass
class Block:
    header: Header
    txs: list

    def serialize(self):
        return self.header.serialize() + varint(len(self.txs)) + b"".join(t.full() for t in self.txs)

    @staticmethod
    def parse(data):
        r = Reader(data)
        hd = Header.parse(r)
        n = r.varint()
        if n < 1:
            raise Invalid("empty block")
        r.need(n * (4 + 1 + MIN_SIZE["input"] + 1 + MIN_SIZE["output"] + 4 + MIN_SIZE["witness"]))
        txs = [Tx.parse(r) for _ in range(n)]
        r.done()
        return Block(hd, txs)


def work(target):
    """blocks.md §5: work of one block. Python ints are arbitrary precision (no wrap)."""
    return (1 << 256) // (target + 1)


def chainwork(headers):
    """Sum of work over the given headers (genesis included by the caller). Never wraps."""
    return sum(work(h.target) for h in headers)


def sync_action(candidate_chainwork, active_chainwork, active_tip_target, gate_blocks=6):
    """blocks.md §6 (node policy). Returns "validate" or "may_postpone".

    A branch with more total work than the active tip is ALWAYS validated (overriding rule).
    Only inferior branches may be postponed, and the threshold is measured against the
    active tip's total chainwork, never against the fork point.
    """
    if candidate_chainwork > active_chainwork:
        return "validate"
    if active_chainwork - candidate_chainwork <= gate_blocks * work(active_tip_target):
        return "validate"
    return "may_postpone"


# ---------------------------------------------------------------- chain state
@dataclass
class Coin:
    output: Output
    height: int
    coinbase: bool


@dataclass
class Chain:
    network: str
    initial_target: int
    pow_ok: object                       # callable(height, header) -> bool  (injected)
    pq: object = None                    # PQ instance, required to validate spends
    blocks: list = field(default_factory=list)
    utxo: dict = field(default_factory=dict)

    @property
    def network_id(self):
        return NETWORK_IDS[self.network]

    def add_genesis(self, block):
        if self.blocks:
            raise Invalid("genesis already set")
        self.blocks.append(block)         # genesis outputs are never added to the UTXO set

    def mtp(self):
        ts = sorted(b.header.timestamp for b in self.blocks[-MTP_WINDOW:])
        return ts[len(ts) // 2]

    def check_output(self, o):
        if o.output_version != 1 or o.policy not in (0, 1):
            raise Invalid("bad output version or policy")
        if not 1 <= o.amount <= MAX_MONEY:
            raise Invalid("amount out of range")
        if o.scheme_id not in SCHEMES:
            raise Invalid("scheme not creatable")
        if o.policy == 1:
            if o.recovery_scheme_id not in SCHEMES:
                raise Invalid("recovery scheme not creatable")
            if not 1 <= o.recovery_delay <= RECOVERY_DELAY_MAX:
                raise Invalid("recovery delay out of range")

    def check_spend(self, tx, i, coin, spent_outputs, height, authorized=()):
        """transactions.md §8. Returns the selected (scheme, commitment). `authorized` holds the
        selected pairs of earlier inputs with path 0/1 (for path 2, §8.2)."""
        w = tx.witnesses[i]
        o = coin.output
        if coin.coinbase and height < coin.height + COINBASE_MATURITY:
            raise Invalid("immature coinbase")
        if w.path == 2:
            if w.public_key or w.signature:
                raise Invalid("shared witness must be empty")
            if (o.scheme_id, o.commitment) not in authorized:
                raise Invalid("no earlier input authorizes this key")
            return None
        if w.path in (0, 1) and (o.scheme_id, o.commitment) in authorized:
            raise Invalid("path 2 required for an already authorized key")
        if w.path == 0:
            sid, com = o.scheme_id, o.commitment
        elif w.path == 1:
            if o.policy != 1:
                raise Invalid("no recovery path")
            if height < coin.height + o.recovery_delay:
                raise Invalid("recovery path not yet available")
            sid, com = o.recovery_scheme_id, o.recovery_commitment
        else:
            raise Invalid("unknown path")
        _, pk_len, _, sig_len, _ = SCHEMES[sid]
        if len(w.public_key) != pk_len or len(w.signature) != sig_len:
            raise Invalid("wrong key or signature length")
        if commitment(sid, w.public_key) != com:
            raise Invalid("commitment mismatch")
        msg = sighash(self.network_id, self.blocks[0].header.block_id(), tx, i, spent_outputs, w.path)
        if not self.pq.verify(sid, w.public_key, msg, w.signature):
            raise Invalid("bad signature")
        return (sid, com)

    def connect(self, block):
        """Validate and apply a block, following blocks.md §4. Raises Invalid; state unchanged on failure."""
        height = len(self.blocks)
        parent, genesis = self.blocks[-1].header, self.blocks[0].header
        hd = block.header
        # steps 2-6: header
        if hd.version != 1 or hd.prev_block != parent.block_id():
            raise Invalid("bad header link or version")
        if hd.timestamp <= self.mtp():
            raise Invalid("timestamp not above median time past")
        if hd.target != next_target(self.initial_target, genesis.timestamp, height - 1, parent.timestamp):
            raise Invalid("wrong target")
        if not self.pow_ok(height, hd):
            raise Invalid("insufficient proof of work")
        # steps 8-10: root, structure, weight
        if not block.txs or hd.tx_root != merkle_root([t.wtxid() for t in block.txs]):
            raise Invalid("bad transaction root")
        txids = [t.txid() for t in block.txs]
        if len(set(txids)) != len(txids):
            raise Invalid("duplicate txid")
        if any(t.has_null_input() for t in block.txs[1:]):
            raise Invalid("coinbase-style input outside position 0")
        weight = sum(t.weight(coinbase=(n == 0)) for n, t in enumerate(block.txs))
        if weight > MAX_BLOCK_WEIGHT:
            raise Invalid("block weight")
        # step 11: transactions in order
        view, spent, fees, coinbase_out = dict(self.utxo), set(), 0, 0
        for n, tx in enumerate(block.txs):
            if tx.version != 1 or not tx.inputs or not tx.outputs or len(tx.witnesses) != len(tx.inputs):
                raise Invalid("transaction structure")
            if n == 0:
                cw = tx.witnesses[0]
                ok = (len(tx.inputs) == 1 and tx.inputs[0] == (bytes(32), height % 2 ** 32)
                      and tx.locktime == height >> 32 and cw.path == 0 and not cw.public_key
                      and len(cw.signature) <= COINBASE_EXTRA_MAX)
                if not ok:
                    raise Invalid("coinbase rules")
            elif tx.locktime and height < tx.locktime:
                raise Invalid("locktime")
            coins = []
            if n > 0:
                for op in tx.inputs:
                    if op in spent or op not in view:
                        raise Invalid("missing or spent input")
                    spent.add(op)
                    coins.append(view[op])
            for o in tx.outputs:
                self.check_output(o)
            out_sum = sum(o.amount for o in tx.outputs)
            if out_sum > MAX_MONEY:
                raise Invalid("output sum overflow")
            if n == 0:
                coinbase_out = out_sum
            else:
                in_sum = sum(c.output.amount for c in coins)
                if in_sum > MAX_MONEY or in_sum < out_sum:
                    raise Invalid("input sum overflow or negative fee")
                spent_outputs = [c.output for c in coins]
                authorized = set()
                for i, c in enumerate(coins):
                    sel = self.check_spend(tx, i, c, spent_outputs, height, authorized)
                    if sel:
                        authorized.add(sel)
                fees += in_sum - out_sum
                for op in tx.inputs:
                    del view[op]
            for idx, o in enumerate(tx.outputs):
                view[(txids[n], idx)] = Coin(o, height, n == 0)
        # step 12: coinbase value
        if coinbase_out > subsidy(height) + fees:
            raise Invalid("coinbase claims too much")
        self.utxo = view
        self.blocks.append(block)
        return weight


# ---------------------------------------------------------------- genesis.md
BTC_PERIOD = 2016
BTC_POW_LIMIT = 0xFFFF << 208          # Bitcoin mainnet powLimit (nBits 0x1d00ffff)


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def btc_compact_to_target(bits):
    """Decode Bitcoin compact nBits exactly as Bitcoin Core's arith_uint256::SetCompact,
    rejecting what CheckProofOfWork rejects: negative, zero, or overflowing (>= 2^256) targets."""
    if not 0 <= bits < 1 << 32:
        raise Invalid("nBits out of range")
    size, word = bits >> 24, bits & 0x007FFFFF
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    if word and bits & 0x00800000:
        raise Invalid("nBits negative")
    if target >> 256:
        raise Invalid("nBits overflow")
    if target == 0:
        raise Invalid("nBits zero target")
    return target


def check_btc_anchor(headers, anchor_height, anchor_prev_hash, anchor_bits):
    """genesis.md §2 step 2. Hashes are in Bitcoin's internal (little-endian) byte order,
    i.e. the bytes as they appear inside a header. Raises Invalid with the first failure."""
    if len(headers) != 6 or any(len(x) != 80 for x in headers):
        raise Invalid("need six 80-byte Bitcoin headers")
    if anchor_height % BTC_PERIOD > BTC_PERIOD - 6:
        raise Invalid("anchor crosses a Bitcoin difficulty period")
    target = btc_compact_to_target(anchor_bits)
    if target > BTC_POW_LIMIT:
        raise Invalid("anchor nBits above Bitcoin powLimit")
    prev = anchor_prev_hash
    for k, x in enumerate(headers):
        if x[4:36] != prev:
            raise Invalid(f"header {k}: prev mismatch")
        if int.from_bytes(x[72:76], "little") != anchor_bits:
            raise Invalid(f"header {k}: nBits mismatch")
        hsh = sha256d(x)
        if int.from_bytes(hsh, "little") > target:
            raise Invalid(f"header {k}: proof of work")
        prev = hsh
    return True


def genesis_block(params_hash, btc_headers, initial_target):
    """genesis.md §2 steps 3-7, from params_hash and the six Bitcoin headers H..H+5.

    The caller must first run check_btc_anchor (step 2).
    """
    if len(btc_headers) != 6 or any(len(x) != 80 for x in btc_headers):
        raise Invalid("need six 80-byte Bitcoin headers")
    seed = h256("VARVE/genesis/v1", params_hash + b"".join(btc_headers))
    t0 = sorted(int.from_bytes(x[68:72], "little") for x in btc_headers)[3]
    out = Output(0, 0, seed, output_version=0)
    cb = Tx([(bytes(32), 0)], [out], [Witness(0, b"", seed)], locktime=0)
    hd = Header(bytes(32), merkle_root([cb.wtxid()]), t0, initial_target)
    return Block(hd, [cb])
