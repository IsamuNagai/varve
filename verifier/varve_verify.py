"""Independent implementation of the Varve consensus rules, from protocol/*.md only.

Standard library only; signatures go through liboqs via ctypes (VARVE_LIBOQS).
Proof of work is not checked.  Every place where the specification had to be
interpreted is marked with "SPEC-AMBIGUITY" and described in FINDINGS.md.
"""

import atexit
import ctypes
import hashlib
import os
import struct

# ---------------------------------------------------------------------------
# Constants (protocol/params.md, subsidy.md, difficulty.md)
# ---------------------------------------------------------------------------

MAX_MONEY = 1 << 62
COINBASE_MATURITY = 288
COINBASE_EXTRA_MAX = 64
MAX_BLOCK_WEIGHT = 720_000
UTXO_GROWTH_UNITS = 100
RECOVERY_DELAY_MAX = (1 << 31) - 1
HEADER_LEN = 116
TARGET_SPACING = 300
ASERT_TAU = 21_600
ASERT_ANCHOR_DELAY = 7_200  # difficulty.md §1, §2.1: t_a = t0 + D
MTP_WINDOW = 11
INITIAL_SUBSIDY = 8_200_000_000
TAIL_SUBSIDY = 600_000_000
BLOCKS_PER_EPOCH = 13_149
U32_LIMIT = 1 << 32

# scheme_id -> (public key length, signature length, verify units, liboqs name)
SCHEMES = {
    1: (1952, 3309, 100, "ML-DSA-65"),
    2: (32, 7856, 1700, "SLH_DSA_PURE_SHA2_128S"),
}
MAX_PK_LEN = 1952
MAX_SIG_LEN = 7856

# transactions.md §6 and upgrades.md §4: the lifecycle is a table of
# (scheme_id, state, from_height) transitions.  The state of a scheme at height
# h is that of the last transition for it with from_height <= h, else ACTIVE.
ACTIVE, NO_NEW_OUTPUTS, DISABLED = "ACTIVE", "NO_NEW_OUTPUTS", "DISABLED"
_STATE_RANK = {ACTIVE: 0, NO_NEW_OUTPUTS: 1, DISABLED: 2}
GENESIS_LIFECYCLE = ((1, ACTIVE, 0), (2, ACTIVE, 0))


def check_lifecycle(table):
    """Validate a lifecycle table and return it as a tuple; raise ValueError.

    SPEC-AMBIGUITY (A-20): "the last transition for that scheme" can mean last
    in list order or greatest from_height.  The two agree only if each scheme's
    entries are listed in height order, so such a table is required here, and
    states may only move forward (one-directional, upgrades.md §5).
    """
    last = {}
    for scheme_id, state, from_height in table:
        if scheme_id not in SCHEMES:
            raise ValueError("lifecycle entry for an unknown scheme")
        if state not in _STATE_RANK or from_height < 0:
            raise ValueError("bad lifecycle entry")
        prev = last.get(scheme_id)
        if prev is not None and (from_height < prev[1] or _STATE_RANK[state] < _STATE_RANK[prev[0]]):
            raise ValueError("lifecycle not in height order or not one-directional")
        last[scheme_id] = (state, from_height)
    return tuple(table)


def scheme_state(table, scheme_id, height):
    """State of scheme_id at height; None for an unknown id (never valid)."""
    if scheme_id not in SCHEMES:
        return None
    state = ACTIVE
    for entry_scheme, entry_state, from_height in table:
        if entry_scheme == scheme_id and from_height <= height:
            state = entry_state
    return state


def can_create(table, scheme_id, height):
    return scheme_state(table, scheme_id, height) == ACTIVE


def can_spend(table, scheme_id, height):
    return scheme_state(table, scheme_id, height) in (ACTIVE, NO_NEW_OUTPUTS)


# subsidy.md: FRAC[k] = floor(2^63 * 2^(-k/64)); embedded, not computed.
FRAC_Q63 = (
    0x8000000000000000, 0x7E9F06067A4360BA, 0x7D41D96DB915019D, 0x7BE86FB985689DDC,
    0x7A92BE8A92436616, 0x7940BB9E2CFFD89C, 0x77F25CCDEE6D7AE5, 0x76A7980F6CCA15C2,
    0x75606373EE921C97, 0x741CB5281E25EE34, 0x72DC8373BE41A454, 0x719FC4B95F452D28,
    0x70666F76154A7088, 0x6F307A412F074891, 0x6DFDDBCBED791BAA, 0x6CCE8AE13C57EBDA,
    0x6BA27E656B4EB57A, 0x6A79AD55E7F6FD0F, 0x69540EC8F895722D, 0x683199ED779592CA,
    0x6712460A8FC24071, 0x65F60A7F79393E2E, 0x64DCDEC3371793D1, 0x63C6BA6455DCD8AE,
    0x62B39508AA836D6E, 0x61A3666D124BB203, 0x6096266533384A2B, 0x5F8BCCDB3D398841,
    0x5E8451CFAC061B5F, 0x5D7FAD59099F22FD, 0x5C7DD7A3B17DCF74, 0x5B7EC8F19468BBC8,
    0x5A827999FCEF3242, 0x5988E20954889244, 0x5891FAC0E95612C7, 0x579DBC56B48521BA,
    0x56AC1F752150A563, 0x55BD1CDAD49F699B, 0x54D0AD5A753E077C, 0x53E6C9DA74B29AB4,
    0x52FF6B54D8A89C75, 0x521A8AD704F3404F, 0x513821818624B40C, 0x50582887DCB8A7E1,
    0x4F7A993048D088D6, 0x4E9F6CD3967FDBA8, 0x4DC69CDCEAA72A9C, 0x4CF022C9905BFD32,
    0x4C1BF828C6DC54B7, 0x4B4A169B900C2D00, 0x4A7A77D47F7B84B0, 0x49AD159789F37495,
    0x48E1E9B9D588E19B, 0x4818EE218A3358EE, 0x47521CC5A2E6A9E0, 0x468D6FADBF2DD4F2,
    0x45CAE0F1F545EB73, 0x450A6ABAA4B77ECD, 0x444C0740496D4293, 0x438FB0CB4F468808,
    0x42D561B3E6243D8A, 0x421D1461D66F2023, 0x4166C34C5615D0EB, 0x40B268F9DE0183B9,
)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """Non-canonical or truncated encoding."""


class Invalid(Exception):
    """A consensus rule failed; the message names the rule."""


# ---------------------------------------------------------------------------
# Hashing and varint (encoding.md)
# ---------------------------------------------------------------------------


def h256(tag, message):
    tag = tag.encode("ascii") if isinstance(tag, str) else tag
    return hashlib.sha3_256(bytes([len(tag)]) + tag + message).digest()


def varint_encode(value):
    if not 0 <= value < U32_LIMIT:
        raise ValueError("varint out of range")
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value:
            out.append(low | 0x80)
        else:
            out.append(low)
            return bytes(out)


def varint_decode(buf, pos):
    """Return (value, new_pos); raise ParseError on any non-canonical form."""
    value = 0
    for i in range(5):
        if pos >= len(buf):
            raise ParseError("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            if byte == 0 and i > 0:
                raise ParseError("non-minimal varint")
            if value >= U32_LIMIT:
                raise ParseError("varint >= 2^32")
            return value, pos
    raise ParseError("varint longer than 5 bytes")


class Reader:
    def __init__(self, data, pos=0):
        self.data, self.pos = data, pos

    def remaining(self):
        return len(self.data) - self.pos

    def take(self, n):
        if n < 0 or n > self.remaining():
            raise ParseError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint(self, size):
        return int.from_bytes(self.take(size), "little")

    def varint(self):
        value, self.pos = varint_decode(self.data, self.pos)
        return value

    def varbytes(self, max_len):
        n = self.varint()
        if n > max_len:
            raise ParseError("byte string longer than its maximum")
        return self.take(n)


def le(value, size):
    return value.to_bytes(size, "little")


# ---------------------------------------------------------------------------
# Transactions (transactions.md)
# ---------------------------------------------------------------------------


class Output:
    def __init__(self, amount, scheme_id, commitment, policy=0, output_version=1,
                 recovery_scheme_id=None, recovery_commitment=None, recovery_delay=None):
        self.amount = amount
        self.output_version = output_version
        self.policy = policy
        self.scheme_id = scheme_id
        self.commitment = commitment
        self.recovery_scheme_id = recovery_scheme_id
        self.recovery_commitment = recovery_commitment
        self.recovery_delay = recovery_delay

    def serialize(self):
        out = (le(self.amount, 8) + bytes([self.output_version, self.policy])
               + le(self.scheme_id, 2) + self.commitment)
        if self.policy == 1:
            out += (le(self.recovery_scheme_id, 2) + self.recovery_commitment
                    + le(self.recovery_delay, 4))
        return out

    @staticmethod
    def read(r):
        amount = r.uint(8)
        output_version = r.uint(1)
        policy = r.uint(1)
        if policy not in (0, 1):
            raise ParseError("unknown policy")
        scheme_id = r.uint(2)
        commitment = r.take(32)
        if policy == 0:
            return Output(amount, scheme_id, commitment, 0, output_version)
        rec_scheme = r.uint(2)
        rec_commitment = r.take(32)
        rec_delay = r.uint(4)
        return Output(amount, scheme_id, commitment, 1, output_version,
                      rec_scheme, rec_commitment, rec_delay)

    def check_creatable(self, lifecycle=GENESIS_LIFECYCLE, height=0):
        """transactions.md §1 and §6 output rules (rule 11.4) at a block height."""
        if not 1 <= self.amount <= MAX_MONEY:
            raise Invalid("output amount out of range")
        if self.output_version != 1:
            raise Invalid("output_version")
        if not can_create(lifecycle, self.scheme_id, height):
            raise Invalid("scheme not creatable")
        if self.policy == 1:
            if not can_create(lifecycle, self.recovery_scheme_id, height):
                raise Invalid("recovery scheme not creatable")
            if not 1 <= self.recovery_delay <= RECOVERY_DELAY_MAX:
                raise Invalid("recovery_delay out of range")


class Witness:
    def __init__(self, path, public_key, signature):
        self.path, self.public_key, self.signature = path, public_key, signature

    def serialize(self):
        return (bytes([self.path]) + varint_encode(len(self.public_key)) + self.public_key
                + varint_encode(len(self.signature)) + self.signature)


class Tx:
    def __init__(self, version, inputs, outputs, locktime, witnesses):
        self.version = version
        self.inputs = inputs  # list of (prev_txid, prev_index)
        self.outputs = outputs
        self.locktime = locktime
        self.witnesses = witnesses

    def base_bytes(self):
        out = le(self.version, 4) + varint_encode(len(self.inputs))
        for txid, index in self.inputs:
            out += txid + le(index, 4)
        out += varint_encode(len(self.outputs))
        for o in self.outputs:
            out += o.serialize()
        return out + le(self.locktime, 4)

    def full_bytes(self):
        return self.base_bytes() + b"".join(w.serialize() for w in self.witnesses)

    def txid(self):
        return h256("VARVE/txid/v1", self.base_bytes())

    def wtxid(self):
        return h256("VARVE/wtxid/v1", self.full_bytes())

    def is_coinbase_shaped(self):
        return len(self.inputs) == 1 and self.inputs[0][0] == ZERO32

    def weight(self, coinbase=False):
        """transactions.md §9; the coinbase counts its serialized length only."""
        size = len(self.full_bytes())
        if coinbase:
            return size
        units = sum(verify_units(len(w.signature)) for w in self.witnesses)
        return size + units + UTXO_GROWTH_UNITS * max(0, len(self.outputs) - len(self.inputs))


ZERO32 = bytes(32)
MIN_INPUT, MIN_OUTPUT, MIN_WITNESS = 36, 44, 3


def verify_units(sig_len):
    for _pk, slen, units, _name in SCHEMES.values():
        if slen == sig_len:
            return units
    return 0


def read_tx(r):
    """Parse one full-serialized transaction from a Reader.

    SPEC-AMBIGUITY (A-03): only structural rules are enforced here (canonical
    varints, truncation, unknown policy, witness path, witness length caps,
    count-vs-remaining).  Semantic rules (version, counts >= 1, output_version,
    amounts, scheme ids) are applied during block validation.
    """
    version = r.uint(4)
    n_in = r.varint()
    if n_in * MIN_INPUT > r.remaining():
        raise ParseError("input_count exceeds remaining input")
    inputs = [(r.take(32), r.uint(4)) for _ in range(n_in)]
    n_out = r.varint()
    if n_out * MIN_OUTPUT > r.remaining():
        raise ParseError("output_count exceeds remaining input")
    outputs = [Output.read(r) for _ in range(n_out)]
    locktime = r.uint(4)
    if n_in * MIN_WITNESS > r.remaining():
        raise ParseError("witness entries exceed remaining input")
    witnesses = []
    for _ in range(n_in):
        path = r.uint(1)
        if path not in (0, 1, 2):
            raise ParseError("unknown witness path")
        pk = r.varbytes(MAX_PK_LEN)
        sig = r.varbytes(MAX_SIG_LEN)
        witnesses.append(Witness(path, pk, sig))
    return Tx(version, inputs, outputs, locktime, witnesses)


def parse_tx(data):
    r = Reader(data)
    tx = read_tx(r)
    if r.remaining():
        raise ParseError("trailing bytes")
    return tx


# ---------------------------------------------------------------------------
# Signature message (transactions.md §7)
# ---------------------------------------------------------------------------


def sighash(network_id, genesis_id, txid, index, spent_outputs_serialized, path):
    spent_hash = h256("VARVE/spent/v1", b"".join(spent_outputs_serialized))
    return h256("VARVE/sighash/v1",
                network_id + genesis_id + txid + le(index, 4) + spent_hash + bytes([path]))


def commitment_for(scheme_id, public_key):
    return h256("VARVE/pk/v1", le(scheme_id, 2) + public_key)


# ---------------------------------------------------------------------------
# Signature verification through liboqs
# ---------------------------------------------------------------------------


class OqsVerifier:
    def __init__(self, path):
        lib = ctypes.CDLL(path)
        lib.OQS_SIG_new.restype = ctypes.c_void_p
        lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]
        lib.OQS_SIG_verify.restype = ctypes.c_int
        lib.OQS_SIG_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                       ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        lib.OQS_SIG_free.argtypes = [ctypes.c_void_p]
        self.lib = lib
        self.handles = {}
        self.memo = {}
        atexit.register(self.close)

    def _handle(self, scheme_id):
        if scheme_id not in self.handles:
            h = self.lib.OQS_SIG_new(SCHEMES[scheme_id][3].encode())
            if not h:
                raise RuntimeError("liboqs lacks " + SCHEMES[scheme_id][3])
            self.handles[scheme_id] = h
        return self.handles[scheme_id]

    def verify(self, scheme_id, public_key, message, signature):
        key = (scheme_id, public_key, message, signature)
        if key not in self.memo:
            self.memo[key] = self.lib.OQS_SIG_verify(
                self._handle(scheme_id), message, len(message),
                signature, len(signature), public_key) == 0
        return self.memo[key]

    def close(self):
        for h in self.handles.values():
            self.lib.OQS_SIG_free(h)
        self.handles = {}


def load_verifier():
    path = os.environ.get("VARVE_LIBOQS")
    return OqsVerifier(path) if path else None


# ---------------------------------------------------------------------------
# Headers, Merkle root, blocks (blocks.md §1-3)
# ---------------------------------------------------------------------------


class Header:
    def __init__(self, version, prev_block, tx_root, timestamp, target, nonce):
        self.version, self.prev_block, self.tx_root = version, prev_block, tx_root
        self.timestamp, self.target, self.nonce = timestamp, target, nonce  # target: int

    def serialize(self):
        return (le(self.version, 4) + self.prev_block + self.tx_root + le(self.timestamp, 8)
                + le(self.target, 32) + le(self.nonce, 8))

    def block_id(self):
        return h256("VARVE/block/v1", self.serialize())

    @staticmethod
    def parse(data):
        if len(data) != HEADER_LEN:
            raise ParseError("header must be exactly 116 bytes")
        r = Reader(data)
        return Header(r.uint(4), r.take(32), r.take(32), r.uint(8),
                      int.from_bytes(r.take(32), "little"), r.uint(8))


def block_id_of_header(header_bytes):
    return h256("VARVE/block/v1", header_bytes)


def merkle_root(wtxids):
    n = len(wtxids)
    if n == 0:
        raise ValueError("empty block")
    level = [h256("VARVE/merkle/leaf", w) for w in wtxids]
    while len(level) > 1:
        nxt = [h256("VARVE/merkle/node", level[i] + level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])  # carried unchanged, never duplicated
        level = nxt
    return h256("VARVE/merkle/root", le(n, 4) + level[0])


class Block:
    def __init__(self, header, txs, raw_header):
        self.header, self.txs, self.raw_header = header, txs, raw_header

    def serialize(self):
        return (self.raw_header + varint_encode(len(self.txs))
                + b"".join(t.full_bytes() for t in self.txs))


MIN_TX_LEN = 4 + 1 + MIN_INPUT + 1 + MIN_OUTPUT + 4 + MIN_WITNESS


def parse_block(data):
    """blocks.md §2 / §4 step 7: canonical parse with no trailing bytes."""
    if len(data) < HEADER_LEN:
        raise ParseError("short block")
    raw_header = data[:HEADER_LEN]
    header = Header.parse(raw_header)
    r = Reader(data, HEADER_LEN)
    count = r.varint()
    if count < 1:
        raise ParseError("tx_count must be >= 1")
    # SPEC-AMBIGUITY (A-09): no minimum transaction size is stated for blocks;
    # derived here from transactions.md §3 minima as an allocation guard only.
    if count * MIN_TX_LEN > r.remaining():
        raise ParseError("tx_count exceeds remaining input")
    txs = [read_tx(r) for _ in range(count)]
    if r.remaining():
        raise ParseError("trailing bytes")
    return Block(header, txs, raw_header)


# ---------------------------------------------------------------------------
# Subsidy (subsidy.md)
# ---------------------------------------------------------------------------


def subsidy(height):
    if height == 0:
        return 0
    epoch = (height - 1) // BLOCKS_PER_EPOCH
    shift = 63 + epoch // 64
    decayed = 0 if shift >= 128 else (INITIAL_SUBSIDY * FRAC_Q63[epoch % 64]) >> shift
    return max(decayed, TAIL_SUBSIDY)


# ---------------------------------------------------------------------------
# Difficulty (difficulty.md)
# ---------------------------------------------------------------------------


def pow_limit_for(initial_target):
    return initial_target * 256


def next_target(parent_height, parent_time, t0, initial_target):
    """difficulty.md §2; t0 is the genesis timestamp, the anchor is t0 + D."""
    pow_limit = pow_limit_for(initial_target)
    t_a = t0 + ASERT_ANCHOR_DELAY
    exponent = ((parent_time - t_a) - TARGET_SPACING * parent_height) * 65536 // ASERT_TAU
    if exponent >= 256 * 65536:
        return pow_limit
    if exponent <= -270 * 65536:
        return 1
    shifts = exponent >> 16
    frac = exponent - shifts * 65536
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac ** 2
                       + 5127 * frac ** 3 + (1 << 47)) >> 48)
    t = initial_target * factor
    t = t << shifts if shifts >= 0 else t >> -shifts
    t >>= 16
    return max(1, min(t, pow_limit))


def median_time_past(timestamps_nearest_first):
    window = timestamps_nearest_first[:MTP_WINDOW]
    return sorted(window)[len(window) // 2]


def work(target):
    return (1 << 256) // (target + 1)


def chainwork(targets):
    return sum(work(t) for t in targets)


# ---------------------------------------------------------------------------
# Genesis (genesis.md)
# ---------------------------------------------------------------------------

BITCOIN_POW_LIMIT = 0xFFFF << 208


class AnchorError(Exception):
    pass


def decode_compact(bits):
    """Bitcoin Core SetCompact; raises AnchorError for negative/zero/overflow."""
    size = bits >> 24
    word = bits & 0x007FFFFF
    if bits & 0x00800000 and word:
        raise AnchorError("nBits negative")
    target = word >> (8 * (3 - size)) if size <= 3 else word << (8 * (size - 3))
    if target == 0:
        raise AnchorError("nBits zero target")
    if target >= 1 << 256:
        raise AnchorError("nBits overflow")
    return target


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def check_anchor(height, prev_hash_internal, anchor_bits, headers):
    """genesis.md §2 step 2; raises AnchorError with the failing rule."""
    target = decode_compact(anchor_bits)
    if target > BITCOIN_POW_LIMIT:
        raise AnchorError("anchor nBits above Bitcoin powLimit")
    if height % 2016 > 2010:
        raise AnchorError("anchor crosses a Bitcoin difficulty period")
    if len(headers) != 6 or any(len(h) != 80 for h in headers):
        raise AnchorError("need six 80-byte Bitcoin headers")
    expected_prev = prev_hash_internal
    for k, h in enumerate(headers):
        if h[4:36] != expected_prev:
            raise AnchorError("header %d: prev mismatch" % k)
        if int.from_bytes(h[72:76], "little") != anchor_bits:
            raise AnchorError("header %d: nBits mismatch" % k)
        digest = sha256d(h)
        if int.from_bytes(digest, "little") > target:
            raise AnchorError("header %d: proof of work" % k)
        expected_prev = digest


def build_genesis(params_hash, initial_target, headers):
    """genesis.md §2 steps 3-6.  Returns (block bytes, seed, t0)."""
    seed = h256("VARVE/genesis/v1", params_hash + b"".join(headers))
    times = sorted(int.from_bytes(h[68:72], "little") for h in headers)
    t0 = times[3]
    out = Output(0, 0, seed, policy=0, output_version=0)
    coinbase = Tx(1, [(ZERO32, 0)], [out], 0, [Witness(0, b"", seed)])
    header = Header(1, ZERO32, merkle_root([coinbase.wtxid()]), t0, initial_target, 0)
    block = Block(header, [coinbase], header.serialize())
    return block.serialize(), seed, t0


# ---------------------------------------------------------------------------
# params_hash (params.md)
# ---------------------------------------------------------------------------


def serialize_params(entries):
    """entries: list of (name, type, value) with value already a Python int/bytes."""
    out = b""
    for name, typ, value in entries:
        nb = name.encode("ascii")
        out += bytes([len(nb)]) + nb
        if typ in ("u8", "u16", "u32", "u64"):
            out += le(value, {"u8": 1, "u16": 2, "u32": 4, "u64": 8}[typ])
        elif typ == "u256":
            out += le(value, 32)
        elif typ == "bytes":
            out += varint_encode(len(value)) + value
        else:
            raise ValueError(typ)
    return out


def params_hash(entries):
    return h256("VARVE/params/v1", serialize_params(entries))


def draft_params():
    """The draft parameter set as listed in params.md, in table order."""
    frac = b"".join(le(v, 8) for v in FRAC_Q63)
    initial = 1 << 240
    return [
        ("NETWORK_ID", "bytes", b"VARV"),
        ("BLOCK_VERSION", "u32", 1),
        ("TX_VERSION", "u32", 1),
        ("OUTPUT_VERSION", "u8", 1),
        ("MAX_MONEY", "u64", MAX_MONEY),
        ("COINBASE_MATURITY", "u32", COINBASE_MATURITY),
        ("COINBASE_EXTRA_MAX", "u32", COINBASE_EXTRA_MAX),
        ("MAX_BLOCK_WEIGHT", "u64", MAX_BLOCK_WEIGHT),
        ("UTXO_GROWTH_UNITS", "u32", UTXO_GROWTH_UNITS),
        ("RECOVERY_DELAY_MAX", "u32", RECOVERY_DELAY_MAX),
        ("SCHEME_0001_ALG", "bytes", b"ML-DSA-65"),
        ("SCHEME_0001_PK_LEN", "u32", 1952),
        ("SCHEME_0001_SIG_LEN", "u32", 3309),
        ("SCHEME_0001_VERIFY_UNITS", "u32", 100),
        ("SCHEME_0002_ALG", "bytes", b"SLH-DSA-SHA2-128s"),
        ("SCHEME_0002_PK_LEN", "u32", 32),
        ("SCHEME_0002_SIG_LEN", "u32", 7856),
        ("SCHEME_0002_VERIFY_UNITS", "u32", 1700),
        ("TARGET_SPACING", "u32", TARGET_SPACING),
        ("ASERT_TAU", "u32", ASERT_TAU),
        ("ASERT_ANCHOR_DELAY", "u32", ASERT_ANCHOR_DELAY),
        ("MTP_WINDOW", "u32", MTP_WINDOW),
        ("MAX_FUTURE_DRIFT", "u32", 600),
        ("INITIAL_SUBSIDY", "u64", INITIAL_SUBSIDY),
        ("TAIL_SUBSIDY", "u64", TAIL_SUBSIDY),
        ("BLOCKS_PER_EPOCH", "u32", BLOCKS_PER_EPOCH),
        ("SUBSIDY_FRAC_Q63", "bytes", frac),
        ("POW_ALGORITHM", "bytes", b"RandomX-v2"),
        ("RANDOMX_ARGON_SALT", "bytes", b"VarveRX\x01"),
        ("RANDOMX_KEY_EPOCH", "u32", 2048),
        ("RANDOMX_KEY_LAG", "u32", 64),
        ("INITIAL_TARGET", "u256", initial),
        ("POW_LIMIT", "u256", initial * 256),
        ("BTC_ANCHOR_HEIGHT", "u32", 0),
        ("BTC_ANCHOR_PREV_HASH", "bytes", bytes(32)),
        ("BTC_ANCHOR_BITS", "u32", 0),
    ]


# ---------------------------------------------------------------------------
# Chain state and full block validation (blocks.md §4)
# ---------------------------------------------------------------------------


class Coin:
    __slots__ = ("output", "height", "coinbase")

    def __init__(self, output, height, coinbase):
        self.output, self.height, self.coinbase = output, height, coinbase


class ChainState:
    """Active chain from genesis; UTXO set keyed by (txid, index)."""

    def __init__(self, network_id, genesis_bytes, verifier=None, lifecycle=GENESIS_LIFECYCLE):
        genesis = parse_block(genesis_bytes)
        self.network_id = network_id
        self.verifier = verifier
        self.lifecycle = check_lifecycle(lifecycle)
        self.genesis_id = genesis.header.block_id()
        self.t0 = genesis.header.timestamp
        self.initial_target = genesis.header.target
        # headers[h] = (timestamp, target, block_id)
        self.headers = [(self.t0, self.initial_target, self.genesis_id)]
        self.utxo = {}  # genesis outputs are never added (genesis.md §2.7)
        self.sig_checks_skipped = 0

    @property
    def height(self):
        return len(self.headers) - 1

    def apply(self, delta):
        spent, created, entry = delta
        for key in spent:
            del self.utxo[key]
        self.utxo.update(created)
        self.headers.append(entry)

    def validate(self, raw):
        """Validate a candidate on top of the tip.  Returns a delta; raises Invalid."""
        return validate_block(self, raw)

    def connect(self, raw):
        self.apply(self.validate(raw))


def validate_block(chain, raw):
    # 1. size bound
    if len(raw) > HEADER_LEN + 5 + MAX_BLOCK_WEIGHT:
        raise Invalid("1: size bound")
    # 2. header syntax
    if len(raw) < HEADER_LEN:
        raise Invalid("2: short header")
    header = Header.parse(raw[:HEADER_LEN])
    if header.version != 1:
        raise Invalid("2: header version")
    # 3. parent
    parent_height = chain.height
    if header.prev_block != chain.headers[-1][2]:
        raise Invalid("3: unknown parent")
    height = parent_height + 1
    # 4. median time past
    ancestors = [h[0] for h in reversed(chain.headers[-MTP_WINDOW:])]
    if header.timestamp <= median_time_past(ancestors):
        raise Invalid("4: timestamp <= MTP")
    # 5. target
    if header.target != next_target(parent_height, chain.headers[-1][0],
                                    chain.t0, chain.initial_target):
        raise Invalid("5: target")
    # 6. proof of work: not checked in these vectors.
    # 7. parse
    try:
        block = parse_block(raw)
    except ParseError as e:
        raise Invalid("7: parse: %s" % e)
    txs = block.txs
    # 8. root
    if merkle_root([t.wtxid() for t in txs]) != header.tx_root:
        raise Invalid("8: tx_root")
    # 9. structure
    if not txs[0].is_coinbase_shaped():
        raise Invalid("9: first transaction is not a coinbase")
    for t in txs[1:]:
        if any(prev == ZERO32 for prev, _ in t.inputs):
            raise Invalid("9: extra coinbase / zero prev_txid")
    txids = [t.txid() for t in txs]
    if len(set(txids)) != len(txids):
        raise Invalid("9: duplicate txid")
    # 10. weight
    total_weight = sum(t.weight(coinbase=(i == 0)) for i, t in enumerate(txs))
    if total_weight > MAX_BLOCK_WEIGHT:
        raise Invalid("10: block weight")
    # 11. each transaction
    created = {}  # outputs created by earlier txs of this block
    spent = set()
    total_fees = 0
    for i, tx in enumerate(txs):
        txid = txids[i]
        # 11.1 syntax, version, counts
        if tx.version != 1:
            raise Invalid("11.1: tx version")
        if not tx.inputs or not tx.outputs:
            raise Invalid("11.1: empty inputs or outputs")
        # 11.2 locktime (non-coinbase)
        if i > 0 and tx.locktime != 0 and height < tx.locktime:
            raise Invalid("11.2: locktime")
        # 11.3 inputs exist, unspent, no double spend
        coins = []
        if i > 0:
            for key in tx.inputs:
                if key in spent:
                    raise Invalid("11.3: output spent twice")
                coin = created.get(key) or chain.utxo.get(key)
                if coin is None:
                    raise Invalid("11.3: missing input")
                spent.add(key)
                coins.append(coin)
        # 11.4 output rules
        out_sum = 0
        for o in tx.outputs:
            o.check_creatable(chain.lifecycle, height)
            out_sum += o.amount
            if out_sum > MAX_MONEY:
                raise Invalid("11.4: output sum > MAX_MONEY")
        # 11.5 amounts and fee
        if i > 0:
            in_sum = sum(c.output.amount for c in coins)
            if in_sum > MAX_MONEY:
                raise Invalid("11.5: spent sum > MAX_MONEY")
            fee = in_sum - out_sum
            if fee < 0:
                raise Invalid("11.5: negative fee")
            total_fees += fee
            if total_fees > MAX_MONEY:
                raise Invalid("11.5: fee sum > MAX_MONEY")
        # 11.6 coinbase rules
        if i == 0:
            check_coinbase(tx, height)
        # 11.7 spend conditions
        if i > 0:
            check_spends(chain, tx, txid, coins, height)
        for idx, o in enumerate(tx.outputs):
            created[(txid, idx)] = Coin(o, height, i == 0)
    # 12. coinbase value
    if sum(o.amount for o in txs[0].outputs) > subsidy(height) + total_fees:
        raise Invalid("12: coinbase value")
    # 13. commit (returned as a delta so that callers decide)
    survivors = {k: v for k, v in created.items() if k not in spent}
    spent_utxo = [k for k in spent if k in chain.utxo]
    # SPEC-AMBIGUITY (A-11): an output created and spent inside the same block
    # never reaches the UTXO set; `spent_utxo` only lists pre-existing coins.
    entry = (header.timestamp, header.target, header.block_id())
    return spent_utxo, survivors, entry


def check_coinbase(tx, height):
    """transactions.md §4 (input, locktime, witness); value is rule 12."""
    prev_txid, prev_index = tx.inputs[0]
    if len(tx.inputs) != 1 or prev_txid != ZERO32:
        raise Invalid("11.6: coinbase input")
    if prev_index != height % U32_LIMIT:
        raise Invalid("11.6: coinbase prev_index")
    if tx.locktime != height >> 32:
        raise Invalid("11.6: coinbase locktime")
    w = tx.witnesses[0]
    if w.path != 0 or w.public_key != b"" or len(w.signature) > COINBASE_EXTRA_MAX:
        raise Invalid("11.6: coinbase witness")


def select_key(o, path, coin, height):
    """transactions.md §8 step 3 for path 0 or 1: (scheme, commitment)."""
    if path == 0:
        return o.scheme_id, o.commitment
    if o.policy != 1:
        raise Invalid("11.7: recovery path on single-policy output")
    if height < coin.height + o.recovery_delay:
        raise Invalid("11.7: recovery delay")
    return o.recovery_scheme_id, o.recovery_commitment


def check_spends(chain, tx, txid, coins, height):
    spent_serialized = [c.output.serialize() for c in coins]
    authorized = set()  # (scheme, commitment) selected by earlier path-0/1 inputs
    for idx, (coin, w) in enumerate(zip(coins, tx.witnesses)):
        o = coin.output
        if coin.coinbase and height < coin.height + COINBASE_MATURITY:
            raise Invalid("11.7: coinbase maturity")
        if w.path == 2:
            # transactions.md §8.2: replaces steps 3-7; no signature is verified.
            # SPEC-AMBIGUITY (A-22): the witness is not covered by any signature,
            # so a third party may swap a redundant signed entry for this one.
            # SPEC-AMBIGUITY (A-23): the state check below can never fail alone;
            # the authorizer selected the same scheme at the same height.
            if w.public_key or w.signature:
                raise Invalid("11.7: shared witness must be empty")
            if not can_spend(chain.lifecycle, o.scheme_id, height):
                raise Invalid("11.7: shared: scheme not spendable")
            if (o.scheme_id, o.commitment) not in authorized:
                raise Invalid("11.7: no earlier input authorizes this key")
            continue
        scheme, commitment = select_key(o, w.path, coin, height)
        if not can_spend(chain.lifecycle, scheme, height):
            raise Invalid("11.7: scheme not spendable")
        pk_len, sig_len, _u, _n = SCHEMES[scheme]
        if len(w.public_key) != pk_len or len(w.signature) != sig_len:
            raise Invalid("11.7: key or signature length")
        if commitment_for(scheme, w.public_key) != commitment:
            raise Invalid("11.7: commitment mismatch")
        msg = sighash(chain.network_id, chain.genesis_id, txid, idx, spent_serialized, w.path)
        if chain.verifier is None:
            chain.sig_checks_skipped += 1
        elif not chain.verifier.verify(scheme, w.public_key, msg, w.signature):
            raise Invalid("11.7: bad signature")
        authorized.add((scheme, commitment))


# ---------------------------------------------------------------------------
# Bech32m addresses (addresses.md)
# ---------------------------------------------------------------------------

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_HRP = {"mainnet": "varve", "testnet": "tvarve", "regtest": "rvarve"}


def _polymod(values):
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert(data, frm, to, pad):
    acc = bits = 0
    out = []
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if pad and bits:
        out.append((acc << (to - bits)) & ((1 << to) - 1))
    elif not pad and (bits >= frm or (acc << (to - bits)) & ((1 << to) - 1)):
        raise ValueError("non-zero padding")
    return out


def encode_address(network, template):
    """template = output_version byte followed by the output template bytes."""
    hrp = _HRP[network]
    data = [template[0]] + _convert(template[1:], 8, 5, True)
    chk = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 0x2BC830A3
    data += [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data)


def decode_address(address):
    """Returns (network, template bytes); raises ValueError."""
    if address.lower() != address and address.upper() != address:
        raise ValueError("mixed case")
    address = address.lower()
    pos = address.rfind("1")
    hrp, body = address[:pos], address[pos + 1:]
    network = {v: k for k, v in _HRP.items()}.get(hrp)
    if network is None:
        raise ValueError("unknown hrp")
    if len(body) < 7 or any(c not in _CHARSET for c in body):
        raise ValueError("bad characters")
    data = [_CHARSET.index(c) for c in body]
    if _polymod(_hrp_expand(hrp) + data) != 0x2BC830A3:
        raise ValueError("bad checksum")
    data = data[:-6]
    if data[0] != 1:
        raise ValueError("output_version")
    rest = bytes(_convert(data[1:], 5, 8, False))
    policy = rest[0] if rest else None
    if policy == 0 and len(rest) == 35:
        o = Output(1, int.from_bytes(rest[1:3], "little"), rest[3:35])
    elif policy == 1 and len(rest) == 73:
        o = Output(1, int.from_bytes(rest[1:3], "little"), rest[3:35], 1, 1,
                   int.from_bytes(rest[35:37], "little"), rest[37:69],
                   int.from_bytes(rest[69:73], "little"))
    else:
        raise ValueError("bad policy or length")
    o.check_creatable()
    return network, bytes([1]) + rest
