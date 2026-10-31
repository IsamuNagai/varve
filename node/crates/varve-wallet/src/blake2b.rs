//! BLAKE2b (RFC 7693), sequential mode, optional key, 1..=64 byte output.

use crate::util::{wipe, wipe_u64};

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

pub struct Blake2b {
    h: [u64; 8],
    t: u128,
    buf: [u8; 128],
    buflen: usize,
    outlen: usize,
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

impl Blake2b {
    /// Unkeyed BLAKE2b with `outlen` (1..=64) bytes of output.
    pub fn new(outlen: usize) -> Self {
        Self::new_keyed(outlen, &[])
    }

    /// Keyed BLAKE2b; `key` at most 64 bytes.
    pub fn new_keyed(outlen: usize, key: &[u8]) -> Self {
        assert!((1..=64).contains(&outlen), "BLAKE2b output length must be 1..=64");
        assert!(key.len() <= 64, "BLAKE2b key must be at most 64 bytes");
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ outlen as u64;
        let mut s = Blake2b { h, t: 0, buf: [0; 128], buflen: 0, outlen };
        if !key.is_empty() {
            let mut block = [0u8; 128];
            block[..key.len()].copy_from_slice(key);
            s.update(&block);
            wipe(&mut block);
        }
        s
    }

    fn compress(&mut self, last: bool) {
        let mut m = [0u64; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u64::from_le_bytes(self.buf[8 * i..8 * i + 8].try_into().unwrap());
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u64;
        v[13] ^= (self.t >> 64) as u64;
        if last {
            v[14] = !v[14];
        }
        for s in SIGMA.iter() {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
        wipe_u64(&mut m);
        wipe_u64(&mut v);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // Only compress a full buffer once more input is known to follow,
            // because the final block must be compressed with the last flag.
            if self.buflen == 128 {
                self.t += 128;
                self.compress(false);
                self.buflen = 0;
            }
            let n = (128 - self.buflen).min(data.len());
            self.buf[self.buflen..self.buflen + n].copy_from_slice(&data[..n]);
            self.buflen += n;
            data = &data[n..];
        }
    }

    pub fn finalize(mut self) -> Vec<u8> {
        self.t += self.buflen as u128;
        for b in &mut self.buf[self.buflen..] {
            *b = 0;
        }
        self.compress(true);
        let mut out = Vec::with_capacity(64);
        for w in self.h.iter() {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(self.outlen);
        out
    }
}

impl Drop for Blake2b {
    fn drop(&mut self) {
        wipe_u64(&mut self.h);
        wipe(&mut self.buf);
    }
}

/// One-shot BLAKE2b.
pub fn blake2b(outlen: usize, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = Blake2b::new_keyed(outlen, key);
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex_strict};

    /// RFC 7693 Appendix A: BLAKE2b-512("abc").
    #[test]
    fn rfc7693_abc() {
        assert_eq!(
            hex(&blake2b(64, &[], b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    /// The 256 keyed BLAKE2b-512 KATs of the BLAKE2 reference repository
    /// (github.com/BLAKE2/BLAKE2 testvectors/blake2b-kat.txt), each hashed both in
    /// one call and fed byte by byte.
    #[test]
    fn reference_keyed_kats() {
        let txt = include_str!("../testdata/blake2b-kat.txt");
        let (mut input, mut key) = (None, None);
        let mut n = 0;
        for line in txt.lines() {
            if let Some(v) = line.strip_prefix("in:") {
                input = Some(unhex_strict(v.trim()).unwrap());
            } else if let Some(v) = line.strip_prefix("key:") {
                key = Some(unhex_strict(v.trim()).unwrap());
            } else if let Some(v) = line.strip_prefix("hash:") {
                let (i, k) = (input.take().unwrap(), key.take().unwrap());
                assert_eq!(hex(&blake2b(64, &k, &i)), v.trim());
                let mut h = Blake2b::new_keyed(64, &k);
                for b in &i {
                    h.update(std::slice::from_ref(b));
                }
                assert_eq!(hex(&h.finalize()), v.trim());
                n += 1;
            }
        }
        assert_eq!(n, 256);
    }
}
