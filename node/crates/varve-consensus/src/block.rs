//! blocks.md §1–3, subsidy.md, difficulty.md, pow.md §3, chainwork (blocks.md §5).

use crate::bignum::BigUint;
use crate::encoding::{h256, write_varint, Reader};
use crate::params::*;
use crate::tx::Tx;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub prev_block: [u8; 32],
    pub tx_root: [u8; 32],
    pub timestamp: u64,
    /// u256, little-endian bytes as serialized
    pub target: [u8; 32],
    pub nonce: u64,
}

impl Header {
    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.prev_block);
        b[36..68].copy_from_slice(&self.tx_root);
        b[68..76].copy_from_slice(&self.timestamp.to_le_bytes());
        b[76..108].copy_from_slice(&self.target);
        b[108..116].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }
    pub fn parse(r: &mut Reader) -> Result<Header, Error> {
        Ok(Header {
            version: r.u32()?,
            prev_block: r.array()?,
            tx_root: r.array()?,
            timestamp: r.u64()?,
            target: r.array()?,
            nonce: r.u64()?,
        })
    }
    pub fn from_bytes(b: &[u8]) -> Result<Header, Error> {
        let mut r = Reader::new(b);
        let h = Header::parse(&mut r)?;
        r.finish()?;
        Ok(h)
    }
    pub fn block_id(&self) -> [u8; 32] {
        h256("VARVE/block/v1", &self.serialize())
    }
    pub fn target_int(&self) -> BigUint {
        BigUint::from_le_bytes(&self.target)
    }
}

pub fn target_bytes(t: &BigUint) -> [u8; 32] {
    let v = t.to_le_bytes(32).expect("target fits in 256 bits");
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = self.header.serialize().to_vec();
        write_varint(&mut b, self.txs.len() as u64);
        for t in &self.txs {
            b.extend_from_slice(&t.serialize());
        }
        b
    }
    /// blocks.md §2 / §4 step 7: canonical parse, no trailing bytes, size bound first.
    pub fn parse(data: &[u8]) -> Result<Block, Error> {
        if data.len() > MAX_BLOCK_BYTES {
            return Err(Error::Parse("block exceeds size bound"));
        }
        let mut r = Reader::new(data);
        let header = Header::parse(&mut r)?;
        let n = r.varint()?;
        if n == 0 {
            return Err(Error::Parse("empty block"));
        }
        r.need(n, MIN_TX_SIZE as u64)?;
        let mut txs = Vec::with_capacity(n as usize);
        for _ in 0..n {
            txs.push(Tx::parse(&mut r)?);
        }
        r.finish()?;
        Ok(Block { header, txs })
    }
}

/// blocks.md §3: tagged leaves and nodes, odd node carried up, root commits to n.
pub fn merkle_root(wtxids: &[[u8; 32]]) -> [u8; 32] {
    assert!(!wtxids.is_empty());
    let mut level: Vec<[u8; 32]> = wtxids.iter().map(|w| h256("VARVE/merkle/leaf", w)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2 + 1);
        let mut i = 0;
        while i + 1 < level.len() {
            let mut m = [0u8; 64];
            m[..32].copy_from_slice(&level[i]);
            m[32..].copy_from_slice(&level[i + 1]);
            next.push(h256("VARVE/merkle/node", &m));
            i += 2;
        }
        if level.len() % 2 == 1 {
            next.push(*level.last().unwrap());
        }
        level = next;
    }
    let mut m = (wtxids.len() as u32).to_le_bytes().to_vec();
    m.extend_from_slice(&level[0]);
    h256("VARVE/merkle/root", &m)
}

/// subsidy.md
pub fn subsidy(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let epoch = (height - 1) / BLOCKS_PER_EPOCH;
    let shift = 63 + epoch / 64;
    let decayed = if shift >= 128 {
        0u64
    } else {
        let p = INITIAL_SUBSIDY as u128 * FRAC_Q63[(epoch % 64) as usize] as u128;
        (p >> shift) as u64
    };
    decayed.max(TAIL_SUBSIDY)
}

/// difficulty.md §2: ASERT anchored at genesis.
/// `parent_height` = h, `parent_time` = t_h, `genesis_time` = t0.
pub fn next_target(initial_target: &BigUint, genesis_time: u64, parent_height: u64, parent_time: u64) -> BigUint {
    let pow_limit = initial_target.mul_u64(256);
    let anchor = genesis_time as i128 + ASERT_ANCHOR_DELAY;
    let num: i128 = ((parent_time as i128 - anchor) - TARGET_SPACING * parent_height as i128) * 65536;
    let exponent = num.div_euclid(ASERT_TAU); // floor toward −∞ (TAU > 0)
    if exponent >= 256 * 65536 {
        return pow_limit;
    }
    if exponent <= -270 * 65536 {
        return BigUint::from_u64(1);
    }
    let shifts = exponent >> 16; // arithmetic shift = floor division by 65536
    let frac = (exponent - shifts * 65536) as u128; // 0 ≤ frac < 65536
    let factor = 65536u128
        + ((195_766_423_245_049u128 * frac + 971_821_376u128 * frac * frac + 5127u128 * frac * frac * frac + (1u128 << 47)) >> 48);
    let mut t = initial_target.mul_u64(factor as u64);
    t = if shifts >= 0 { t.shl(shifts as u32) } else { t.shr((-shifts) as u32) };
    t = t.shr(16);
    let one = BigUint::from_u64(1);
    if t < one {
        one
    } else if t > pow_limit {
        pow_limit
    } else {
        t
    }
}

/// difficulty.md §3: upper median of the last ≤ 11 timestamps (including genesis).
pub fn median_time_past(timestamps: &[u64]) -> u64 {
    assert!(!timestamps.is_empty() && timestamps.len() <= MTP_WINDOW);
    let mut s = timestamps.to_vec();
    s.sort_unstable();
    s[s.len() / 2]
}

/// blocks.md §5: work = floor(2^256 / (target + 1)).
pub fn work(target: &BigUint) -> BigUint {
    BigUint::pow2(256).div(&target.add(&BigUint::from_u64(1))).unwrap()
}

/// pow.md §3
pub fn seed_height(h: u64) -> u64 {
    if h <= RANDOMX_KEY_EPOCH + RANDOMX_KEY_LAG {
        0
    } else {
        ((h - RANDOMX_KEY_LAG - 1) / RANDOMX_KEY_EPOCH) * RANDOMX_KEY_EPOCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seed_heights() {
        assert_eq!(seed_height(0), 0);
        assert_eq!(seed_height(2112), 0);
        assert_eq!(seed_height(2113), 2048);
        assert_eq!(seed_height(4160), 2048);
        assert_eq!(seed_height(4161), 4096);
    }
    #[test]
    fn mtp_upper_median() {
        assert_eq!(median_time_past(&[1, 2, 3, 4]), 3);
        assert_eq!(median_time_past(&[5]), 5);
        assert_eq!(median_time_past(&[9, 1, 5]), 5);
    }
}
