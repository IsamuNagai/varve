//! genesis.md: Bitcoin anchor validation and genesis construction.

use crate::bignum::BigUint;
use crate::block::{merkle_root, target_bytes, Block, Header};
use crate::params::ChainParams;
use crate::tx::{OutPoint, Output, Tx, Witness};
use crate::Error;

pub const BTC_PERIOD: u32 = 2016;

fn btc_pow_limit() -> BigUint {
    BigUint::from_u64(0xffff).shl(208)
}

/// Bitcoin Core SetCompact + the rejections of CheckProofOfWork.
pub fn btc_compact_to_target(bits: u32) -> Result<BigUint, Error> {
    let size = bits >> 24;
    let word = bits & 0x007f_ffff;
    let target = if size <= 3 {
        BigUint::from_u64((word >> (8 * (3 - size))) as u64)
    } else {
        BigUint::from_u64(word as u64).shl(8 * (size - 3))
    };
    if word != 0 && bits & 0x0080_0000 != 0 {
        return Err(Error::Invalid("nBits negative"));
    }
    if target.bits() > 256 {
        return Err(Error::Invalid("nBits overflow"));
    }
    if target.is_zero() {
        return Err(Error::Invalid("nBits zero target"));
    }
    Ok(target)
}

/// genesis.md §2 step 2. Hashes in Bitcoin's internal byte order.
pub fn check_btc_anchor(headers: &[[u8; 80]], anchor_height: u32, anchor_prev: &[u8; 32], anchor_bits: u32) -> Result<(), Error> {
    if headers.len() != 6 {
        return Err(Error::Invalid("need six 80-byte Bitcoin headers"));
    }
    if anchor_height % BTC_PERIOD > BTC_PERIOD - 6 {
        return Err(Error::Invalid("anchor crosses a Bitcoin difficulty period"));
    }
    let target = btc_compact_to_target(anchor_bits)?;
    if target > btc_pow_limit() {
        return Err(Error::Invalid("anchor nBits above Bitcoin powLimit"));
    }
    let mut prev = *anchor_prev;
    for x in headers {
        if x[4..36] != prev {
            return Err(Error::Invalid("Bitcoin header: prev mismatch"));
        }
        if u32::from_le_bytes(x[72..76].try_into().unwrap()) != anchor_bits {
            return Err(Error::Invalid("Bitcoin header: nBits mismatch"));
        }
        let h = varve_sys::sha256d(x);
        if BigUint::from_le_bytes(&h) > target {
            return Err(Error::Invalid("Bitcoin header: proof of work"));
        }
        prev = h;
    }
    Ok(())
}

/// genesis.md §2 steps 3–6 (no validation; call check_btc_anchor first).
pub fn genesis_block_from(params_hash: &[u8; 32], headers: &[[u8; 80]], initial_target: &BigUint) -> Block {
    assert_eq!(headers.len(), 6);
    let mut m = params_hash.to_vec();
    for x in headers {
        m.extend_from_slice(x);
    }
    let seed = crate::encoding::h256("VARVE/genesis/v1", &m);
    let mut times: Vec<u64> = headers.iter().map(|x| u32::from_le_bytes(x[68..72].try_into().unwrap()) as u64).collect();
    times.sort_unstable();
    let t0 = times[3];
    let out = Output { amount: 0, output_version: 0, scheme_id: 0, commitment: seed, recovery: None };
    let cb = Tx {
        version: 1,
        inputs: vec![OutPoint { txid: [0u8; 32], index: 0 }],
        outputs: vec![out],
        locktime: 0,
        witnesses: vec![Witness { path: 0, public_key: vec![], signature: seed.to_vec() }],
    };
    let header = Header {
        version: 1,
        prev_block: [0u8; 32],
        tx_root: merkle_root(&[cb.wtxid()]),
        timestamp: t0,
        target: target_bytes(initial_target),
        nonce: 0,
    };
    Block { header, txs: vec![cb] }
}

/// Validate the network's anchor and build its genesis block.
pub fn genesis_block(p: &ChainParams) -> Result<Block, Error> {
    check_btc_anchor(&p.btc_headers, p.btc_anchor_height, &p.btc_anchor_prev_hash, p.btc_anchor_bits)?;
    Ok(genesis_block_from(&p.params_hash(), &p.btc_headers, &p.initial_target))
}
