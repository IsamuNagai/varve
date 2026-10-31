//! Argon2id version 0x13 (RFC 9106), single-threaded, pure Rust.
//! Lanes are computed one after another; within a slice the lanes only read
//! blocks from finished slices or from themselves, so the result is identical
//! to a parallel implementation.

use crate::blake2b::Blake2b;
use crate::util::{wipe, wipe_u64};

const VERSION: u32 = 0x13;
const TYPE_ID: u32 = 2; // Argon2id
const SYNC_POINTS: u32 = 4;
const QWORDS: usize = 128; // 1024-byte block

type Block = [u64; QWORDS];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// memory size m in KiB
    pub m_kib: u32,
    /// passes t
    pub t: u32,
    /// lanes p
    pub p: u32,
}

/// H' (RFC 9106 §3.3): variable-length hash built from BLAKE2b.
fn h_prime(out: &mut [u8], parts: &[&[u8]]) {
    let t = out.len() as u32;
    if out.len() <= 64 {
        let mut h = Blake2b::new(out.len());
        h.update(&t.to_le_bytes());
        for p in parts {
            h.update(p);
        }
        out.copy_from_slice(&h.finalize());
        return;
    }
    let r = (out.len() + 31) / 32 - 2;
    let mut h = Blake2b::new(64);
    h.update(&t.to_le_bytes());
    for p in parts {
        h.update(p);
    }
    let mut v = h.finalize();
    out[..32].copy_from_slice(&v[..32]);
    for i in 1..r {
        let next = {
            let mut h = Blake2b::new(64);
            h.update(&v);
            h.finalize()
        };
        wipe(&mut v);
        v = next;
        out[32 * i..32 * i + 32].copy_from_slice(&v[..32]);
    }
    let last_len = out.len() - 32 * r;
    let mut h = Blake2b::new(last_len);
    h.update(&v);
    let last = h.finalize();
    out[32 * r..].copy_from_slice(&last);
    wipe(&mut v);
}

#[inline(always)]
fn fbla(a: u64, b: u64) -> u64 {
    let m = (a & 0xffff_ffff).wrapping_mul(b & 0xffff_ffff);
    a.wrapping_add(b).wrapping_add(m.wrapping_mul(2))
}

#[inline(always)]
fn gb(v: &mut Block, a: usize, b: usize, c: usize, d: usize) {
    v[a] = fbla(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = fbla(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = fbla(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = fbla(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The permutation P applied to the 16 words at the given indexes.
#[inline(always)]
fn p_round(v: &mut Block, i: &[usize; 16]) {
    gb(v, i[0], i[4], i[8], i[12]);
    gb(v, i[1], i[5], i[9], i[13]);
    gb(v, i[2], i[6], i[10], i[14]);
    gb(v, i[3], i[7], i[11], i[15]);
    gb(v, i[0], i[5], i[10], i[15]);
    gb(v, i[1], i[6], i[11], i[12]);
    gb(v, i[2], i[7], i[8], i[13]);
    gb(v, i[3], i[4], i[9], i[14]);
}

/// Compression G (RFC 9106 §3.5). Writes G(x, y) to `out`; if `with_xor` is set the
/// result is XORed into the old content of `out` (version 0x13 behaviour for passes > 0).
fn compress(x: &Block, y: &Block, out: &mut Block, with_xor: bool) {
    let mut r = [0u64; QWORDS];
    for i in 0..QWORDS {
        r[i] = x[i] ^ y[i];
    }
    let mut q = r;
    // rows: eight 128-byte rows of 16 consecutive words
    for row in 0..8 {
        let b = 16 * row;
        let idx: [usize; 16] = core::array::from_fn(|k| b + k);
        p_round(&mut q, &idx);
    }
    // columns: word pairs (2c, 2c+1) taken from each of the 8 rows
    for col in 0..8 {
        let b = 2 * col;
        let idx: [usize; 16] = core::array::from_fn(|k| b + (k / 2) * 16 + (k % 2));
        p_round(&mut q, &idx);
    }
    if with_xor {
        for i in 0..QWORDS {
            out[i] ^= q[i] ^ r[i];
        }
    } else {
        for i in 0..QWORDS {
            out[i] = q[i] ^ r[i];
        }
    }
    wipe_u64(&mut r);
    wipe_u64(&mut q);
}

fn block_from_bytes(b: &[u8]) -> Block {
    core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()))
}

/// Argon2id with optional secret `k` and associated data `x` (RFC 9106 §3.2).
pub fn argon2id(password: &[u8], salt: &[u8], secret: &[u8], ad: &[u8], params: Params, tag_len: usize) -> Result<Vec<u8>, &'static str> {
    let Params { m_kib, t, p } = params;
    if !(1..=0x00ff_ffff).contains(&p) {
        return Err("argon2: lanes out of range");
    }
    if t < 1 {
        return Err("argon2: passes must be at least 1");
    }
    if (m_kib as u64) < 8 * p as u64 {
        return Err("argon2: memory must be at least 8*p KiB");
    }
    if tag_len < 4 || tag_len > u32::MAX as usize {
        return Err("argon2: tag length out of range");
    }
    for len in [password.len(), salt.len(), secret.len(), ad.len()] {
        if len > u32::MAX as usize {
            return Err("argon2: input too long");
        }
    }
    if salt.len() < 8 {
        return Err("argon2: salt must be at least 8 bytes");
    }

    // H0
    let mut h = Blake2b::new(64);
    for v in [p, tag_len as u32, m_kib, t, VERSION, TYPE_ID] {
        h.update(&v.to_le_bytes());
    }
    for s in [password, salt, secret, ad] {
        h.update(&(s.len() as u32).to_le_bytes());
        h.update(s);
    }
    let mut h0 = h.finalize();

    let lanes = p as usize;
    let m_prime = 4 * p * (m_kib / (4 * p));
    let lane_len = (m_prime / p) as usize;
    let seg_len = lane_len / SYNC_POINTS as usize;
    let mut mem: Vec<Block> = Vec::new();
    if mem.try_reserve_exact(m_prime as usize).is_err() {
        wipe(&mut h0);
        return Err("argon2: cannot allocate memory");
    }
    mem.resize(m_prime as usize, [0u64; QWORDS]);

    let mut tmp = [0u8; 1024];
    for l in 0..lanes {
        for j in 0..2u32 {
            h_prime(&mut tmp, &[&h0, &j.to_le_bytes(), &(l as u32).to_le_bytes()]);
            mem[l * lane_len + j as usize] = block_from_bytes(&tmp);
        }
    }
    wipe(&mut tmp);
    wipe(&mut h0);

    let zero: Block = [0u64; QWORDS];
    let mut input: Block = [0u64; QWORDS];
    let mut addr: Block = [0u64; QWORDS];
    let mut tmp_blk: Block = [0u64; QWORDS];

    for pass in 0..t {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                let data_independent = pass == 0 && slice < 2;
                if data_independent {
                    input = [0u64; QWORDS];
                    input[0] = pass as u64;
                    input[1] = lane as u64;
                    input[2] = slice as u64;
                    input[3] = m_prime as u64;
                    input[4] = t as u64;
                    input[5] = TYPE_ID as u64;
                }
                let start = if pass == 0 && slice == 0 { 2 } else { 0 };
                if data_independent && start != 0 {
                    // first address block for this segment
                    input[6] += 1;
                    compress(&zero, &input, &mut tmp_blk, false);
                    compress(&zero, &tmp_blk, &mut addr, false);
                }
                for idx in start..seg_len {
                    let cur = lane * lane_len + slice as usize * seg_len + idx;
                    let prev = if cur % lane_len == 0 { cur + lane_len - 1 } else { cur - 1 };
                    let rand = if data_independent {
                        if idx % QWORDS == 0 {
                            input[6] += 1;
                            compress(&zero, &input, &mut tmp_blk, false);
                            compress(&zero, &tmp_blk, &mut addr, false);
                        }
                        addr[idx % QWORDS]
                    } else {
                        mem[prev][0]
                    };
                    let j1 = rand & 0xffff_ffff;
                    let j2 = rand >> 32;
                    let ref_lane = if pass == 0 && slice == 0 { lane } else { (j2 % p as u64) as usize };
                    let same_lane = ref_lane == lane;
                    // reference area size (RFC 9106 §3.4.2)
                    let area: u64 = if pass == 0 {
                        if slice == 0 {
                            idx as u64 - 1
                        } else if same_lane {
                            (slice as usize * seg_len + idx) as u64 - 1
                        } else {
                            (slice as usize * seg_len) as u64 - if idx == 0 { 1 } else { 0 }
                        }
                    } else if same_lane {
                        (lane_len - seg_len + idx) as u64 - 1
                    } else {
                        (lane_len - seg_len) as u64 - if idx == 0 { 1 } else { 0 }
                    };
                    let x = (j1 * j1) >> 32;
                    let y = (area * x) >> 32;
                    let rel = area - 1 - y;
                    let start_pos: u64 = if pass != 0 && slice != SYNC_POINTS - 1 {
                        ((slice + 1) as usize * seg_len) as u64
                    } else {
                        0
                    };
                    let ref_idx = ((start_pos + rel) % lane_len as u64) as usize;
                    let r = ref_lane * lane_len + ref_idx;
                    let (pb, rb) = (mem[prev], mem[r]);
                    compress(&pb, &rb, &mut mem[cur], pass > 0);
                }
            }
        }
    }

    let mut c: Block = mem[lane_len - 1];
    for l in 1..lanes {
        let last = &mem[l * lane_len + lane_len - 1];
        for i in 0..QWORDS {
            c[i] ^= last[i];
        }
    }
    let mut cb = [0u8; 1024];
    for i in 0..QWORDS {
        cb[8 * i..8 * i + 8].copy_from_slice(&c[i].to_le_bytes());
    }
    let mut tag = vec![0u8; tag_len];
    h_prime(&mut tag, &[&cb]);

    wipe(&mut cb);
    wipe_u64(&mut c);
    wipe_u64(&mut input);
    wipe_u64(&mut addr);
    wipe_u64(&mut tmp_blk);
    for b in mem.iter_mut() {
        wipe_u64(b);
    }
    Ok(tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    /// RFC 9106 §5.3 (Argon2id, version 0x13). Same tag as kats/argon2id of the
    /// reference implementation (github.com/P-H-C/phc-winner-argon2).
    #[test]
    fn rfc9106_argon2id() {
        let tag = argon2id(&[1u8; 32], &[2u8; 16], &[3u8; 8], &[4u8; 12], Params { m_kib: 32, t: 3, p: 4 }, 32).unwrap();
        assert_eq!(hex(&tag), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    /// Argon2id v1.3 hash tests from the reference implementation's src/test.c
    /// (github.com/P-H-C/phc-winner-argon2, commit f57e61e). Covers m = 64 MiB
    /// (the wallet default memory), p = 2 and non-power-of-two lane use.
    #[test]
    fn reference_impl_argon2id() {
        let cases: [(u32, u32, u32, &[u8], &[u8], &str); 7] = [
            (2, 16, 1, b"password", b"somesalt", "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"),
            (2, 8, 1, b"password", b"somesalt", "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"),
            (2, 8, 2, b"password", b"somesalt", "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037"),
            (1, 16, 1, b"password", b"somesalt", "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98"),
            (4, 16, 1, b"password", b"somesalt", "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c"),
            (2, 16, 1, b"differentpassword", b"somesalt", "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde"),
            (2, 16, 1, b"password", b"diffsalt", "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c"),
        ];
        for (t, log_m, p, pw, salt, want) in cases {
            let tag = argon2id(pw, salt, &[], &[], Params { m_kib: 1 << log_m, t, p }, 32).unwrap();
            assert_eq!(hex(&tag), want, "t={} m=2^{} p={}", t, log_m, p);
        }
    }

    #[test]
    fn h_prime_lengths() {
        // H' for T <= 64 is plain BLAKE2b over LE32(T) || input.
        let mut o = [0u8; 20];
        h_prime(&mut o, &[b"x"]);
        let mut h = Blake2b::new(20);
        h.update(&20u32.to_le_bytes());
        h.update(b"x");
        assert_eq!(o.to_vec(), h.finalize());
        // Lengths around the 64-byte boundary do not panic and differ.
        let mut a = [0u8; 65];
        let mut b = [0u8; 97];
        h_prime(&mut a, &[b"x"]);
        h_prime(&mut b, &[b"x"]);
        assert_ne!(a[..32], b[..32]); // T is hashed in, so prefixes differ
    }

    #[test]
    fn rejects_bad_params() {
        assert!(argon2id(b"p", b"saltsalt", &[], &[], Params { m_kib: 7, t: 1, p: 1 }, 32).is_err());
        assert!(argon2id(b"p", b"saltsalt", &[], &[], Params { m_kib: 64, t: 0, p: 1 }, 32).is_err());
        assert!(argon2id(b"p", b"saltsalt", &[], &[], Params { m_kib: 64, t: 1, p: 0 }, 32).is_err());
        assert!(argon2id(b"p", b"short", &[], &[], Params { m_kib: 64, t: 1, p: 1 }, 32).is_err());
    }
}
