//! Consensus constants (params.md) and per-network parameters.

use crate::bignum::BigUint;
use crate::encoding::{h256, write_varint};

pub const BLOCK_VERSION: u32 = 1;
pub const TX_VERSION: u32 = 1;
pub const OUTPUT_VERSION: u8 = 1;
pub const MAX_MONEY: u64 = 1 << 62;
pub const COINBASE_MATURITY: u64 = 288;
pub const COINBASE_EXTRA_MAX: usize = 64;
pub const MAX_BLOCK_WEIGHT: u64 = 720_000;
pub const UTXO_GROWTH_UNITS: u64 = 100;
pub const RECOVERY_DELAY_MAX: u32 = (1 << 31) - 1;
pub const TARGET_SPACING: i128 = 300;
pub const ASERT_TAU: i128 = 21_600;
/// difficulty.md §2: the ASERT schedule is anchored at genesis time + this delay.
pub const ASERT_ANCHOR_DELAY: i128 = 7_200;
pub const MTP_WINDOW: usize = 11;
pub const MAX_FUTURE_DRIFT: u64 = 600;
pub const INITIAL_SUBSIDY: u64 = 8_200_000_000;
pub const TAIL_SUBSIDY: u64 = 600_000_000;
pub const BLOCKS_PER_EPOCH: u64 = 13_149;
pub const RANDOMX_KEY_EPOCH: u64 = 2048;
pub const RANDOMX_KEY_LAG: u64 = 64;
pub const HEADER_SIZE: usize = 116;

pub const MIN_INPUT_SIZE: usize = 36;
pub const MIN_OUTPUT_SIZE: usize = 44;
pub const MIN_WITNESS_SIZE: usize = 3;
/// version + varint + input + varint + output + locktime + witness
pub const MIN_TX_SIZE: usize = 4 + 1 + MIN_INPUT_SIZE + 1 + MIN_OUTPUT_SIZE + 4 + MIN_WITNESS_SIZE;
pub const MAX_PUBLIC_KEY_LEN: usize = 1952;
pub const MAX_SIGNATURE_LEN: usize = 7856;
/// blocks.md §2: a serialized block is at most 116 + 5 + MAX_BLOCK_WEIGHT bytes.
pub const MAX_BLOCK_BYTES: usize = HEADER_SIZE + 5 + MAX_BLOCK_WEIGHT as usize;

pub const SCHEME_ML_DSA_65: u16 = 0x0001;
pub const SCHEME_SLH_DSA_SHA2_128S: u16 = 0x0002;

pub struct SchemeInfo {
    pub id: u16,
    pub name: &'static str,
    pub sys: varve_sys::Scheme,
    pub pk_len: usize,
    pub sig_len: usize,
    pub verify_units: u64,
}

pub const SCHEMES: [SchemeInfo; 2] = [
    SchemeInfo { id: 1, name: "ML-DSA-65", sys: varve_sys::Scheme::MlDsa65, pk_len: 1952, sig_len: 3309, verify_units: 100 },
    SchemeInfo { id: 2, name: "SLH-DSA-SHA2-128s", sys: varve_sys::Scheme::SlhDsaSha2_128s, pk_len: 32, sig_len: 7856, verify_units: 1700 },
];

/// A known signature scheme (transactions.md §6), regardless of lifecycle state.
pub fn scheme(id: u16, _height: u64) -> Option<&'static SchemeInfo> {
    SCHEMES.iter().find(|s| s.id == id)
}

/// transactions.md §6 lifecycle states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemeState {
    Active,
    NoNewOutputs,
    Disabled,
}

/// One lifecycle transition (upgrades.md §4): from `from_height` on, `scheme_id` is in `state`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    pub scheme_id: u16,
    pub state: SchemeState,
    pub from_height: u64,
}

/// State of a known scheme at `height`: the last transition with from_height ≤ height, else ACTIVE.
/// None for unknown scheme ids (invalid to create or spend).
pub fn scheme_state(lifecycle: &[Transition], id: u16, height: u64) -> Option<SchemeState> {
    scheme(id, height)?;
    let mut st = SchemeState::Active;
    let mut best: Option<u64> = None;
    for t in lifecycle {
        if t.scheme_id == id && t.from_height <= height && best.map(|b| t.from_height >= b).unwrap_or(true) {
            st = t.state;
            best = Some(t.from_height);
        }
    }
    Some(st)
}

/// transactions.md §6: a lifecycle list is well formed iff, per scheme, it names a known
/// scheme, has strictly increasing heights, and only moves forward
/// (ACTIVE → NO_NEW_OUTPUTS → DISABLED, ACTIVE never listed).
pub fn lifecycle_well_formed(lifecycle: &[Transition]) -> Result<(), &'static str> {
    fn rank(s: SchemeState) -> u8 {
        match s {
            SchemeState::Active => 0,
            SchemeState::NoNewOutputs => 1,
            SchemeState::Disabled => 2,
        }
    }
    let mut last: Vec<(u16, u64, u8)> = Vec::new();
    for t in lifecycle {
        if scheme(t.scheme_id, 0).is_none() {
            return Err("lifecycle names an unknown scheme");
        }
        let r = rank(t.state);
        if r == 0 {
            return Err("lifecycle lists ACTIVE");
        }
        match last.iter_mut().find(|x| x.0 == t.scheme_id) {
            Some(x) => {
                if t.from_height <= x.1 || r <= x.2 {
                    return Err("lifecycle transitions out of order");
                }
                *x = (t.scheme_id, t.from_height, r);
            }
            None => last.push((t.scheme_id, t.from_height, r)),
        }
    }
    Ok(())
}

pub fn verify_units_for_sig_len(len: usize) -> u64 {
    match len {
        3309 => 100,
        7856 => 1700,
        _ => 0,
    }
}

pub const FRAC_Q63: [u64; 64] = [
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
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

/// Everything that differs between networks. The genesis block is derived from
/// these values and the six Bitcoin headers (genesis.md).
#[derive(Clone, Debug)]
pub struct ChainParams {
    pub network: Network,
    pub name: &'static str,
    pub network_id: [u8; 4],
    pub hrp: &'static str,
    pub default_port: u16,
    pub initial_target: BigUint,
    pub btc_anchor_height: u32,
    /// internal byte order
    pub btc_anchor_prev_hash: [u8; 32],
    pub btc_anchor_bits: u32,
    /// the six 80-byte Bitcoin headers H..H+5; empty if not yet fixed (mainnet draft)
    pub btc_headers: Vec<[u8; 80]>,
    /// false for the draft mainnet set: the node refuses to run it
    pub launchable: bool,
    /// signature-scheme lifecycle transitions (empty: every scheme ACTIVE)
    pub lifecycle: Vec<Transition>,
}

impl ChainParams {
    pub fn pow_limit(&self) -> BigUint {
        self.initial_target.mul_u64(256)
    }

    /// params.md serialization and params_hash.
    pub fn params_serialization(&self) -> Vec<u8> {
        let mut frac = Vec::with_capacity(512);
        for f in FRAC_Q63 {
            frac.extend_from_slice(&f.to_le_bytes());
        }
        enum V<'a> {
            B(&'a [u8]),
            U8(u8),
            U32(u32),
            U64(u64),
            U256(Vec<u8>),
        }
        let it = self.initial_target.to_le_bytes(32).expect("initial target < 2^256");
        let pl = self.pow_limit().to_le_bytes(32).expect("pow limit < 2^256");
        let entries: Vec<(&str, V)> = vec![
            ("NETWORK_ID", V::B(&self.network_id)),
            ("BLOCK_VERSION", V::U32(BLOCK_VERSION)),
            ("TX_VERSION", V::U32(TX_VERSION)),
            ("OUTPUT_VERSION", V::U8(OUTPUT_VERSION)),
            ("MAX_MONEY", V::U64(MAX_MONEY)),
            ("COINBASE_MATURITY", V::U32(COINBASE_MATURITY as u32)),
            ("COINBASE_EXTRA_MAX", V::U32(COINBASE_EXTRA_MAX as u32)),
            ("MAX_BLOCK_WEIGHT", V::U64(MAX_BLOCK_WEIGHT)),
            ("UTXO_GROWTH_UNITS", V::U32(UTXO_GROWTH_UNITS as u32)),
            ("RECOVERY_DELAY_MAX", V::U32(RECOVERY_DELAY_MAX)),
            ("SCHEME_0001_ALG", V::B(b"ML-DSA-65")),
            ("SCHEME_0001_PK_LEN", V::U32(1952)),
            ("SCHEME_0001_SIG_LEN", V::U32(3309)),
            ("SCHEME_0001_VERIFY_UNITS", V::U32(100)),
            ("SCHEME_0002_ALG", V::B(b"SLH-DSA-SHA2-128s")),
            ("SCHEME_0002_PK_LEN", V::U32(32)),
            ("SCHEME_0002_SIG_LEN", V::U32(7856)),
            ("SCHEME_0002_VERIFY_UNITS", V::U32(1700)),
            ("TARGET_SPACING", V::U32(TARGET_SPACING as u32)),
            ("ASERT_TAU", V::U32(ASERT_TAU as u32)),
            ("ASERT_ANCHOR_DELAY", V::U32(ASERT_ANCHOR_DELAY as u32)),
            ("MTP_WINDOW", V::U32(MTP_WINDOW as u32)),
            ("MAX_FUTURE_DRIFT", V::U32(MAX_FUTURE_DRIFT as u32)),
            ("INITIAL_SUBSIDY", V::U64(INITIAL_SUBSIDY)),
            ("TAIL_SUBSIDY", V::U64(TAIL_SUBSIDY)),
            ("BLOCKS_PER_EPOCH", V::U32(BLOCKS_PER_EPOCH as u32)),
            ("SUBSIDY_FRAC_Q63", V::B(&frac)),
            ("POW_ALGORITHM", V::B(b"RandomX-v2")),
            ("RANDOMX_ARGON_SALT", V::B(b"VarveRX\x01")),
            ("RANDOMX_KEY_EPOCH", V::U32(RANDOMX_KEY_EPOCH as u32)),
            ("RANDOMX_KEY_LAG", V::U32(RANDOMX_KEY_LAG as u32)),
            ("INITIAL_TARGET", V::U256(it)),
            ("POW_LIMIT", V::U256(pl)),
            ("BTC_ANCHOR_HEIGHT", V::U32(self.btc_anchor_height)),
            ("BTC_ANCHOR_PREV_HASH", V::B(&self.btc_anchor_prev_hash)),
            ("BTC_ANCHOR_BITS", V::U32(self.btc_anchor_bits)),
        ];
        let mut out = Vec::new();
        for (name, v) in entries {
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
            match v {
                V::B(b) => {
                    write_varint(&mut out, b.len() as u64);
                    out.extend_from_slice(b);
                }
                V::U8(x) => out.push(x),
                V::U32(x) => out.extend_from_slice(&x.to_le_bytes()),
                V::U64(x) => out.extend_from_slice(&x.to_le_bytes()),
                V::U256(b) => out.extend_from_slice(&b),
            }
        }
        out
    }

    pub fn params_hash(&self) -> [u8; 32] {
        h256("VARVE/params/v1", &self.params_serialization())
    }
}
