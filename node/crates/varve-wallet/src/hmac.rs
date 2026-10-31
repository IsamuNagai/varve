//! HMAC-SHA256 (RFC 2104) over varve_sys::sha256, with constant-time verification.

use crate::util::{ct_eq, wipe};

const BLOCK: usize = 64;

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut kh = varve_sys::sha256(key);
        k0[..32].copy_from_slice(&kh);
        wipe(&mut kh);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend(k0.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let mut ih = varve_sys::sha256(&inner);
    wipe(&mut inner[..BLOCK]);
    let mut outer = [0u8; BLOCK + 32];
    for (o, k) in outer.iter_mut().zip(k0.iter()) {
        *o = k ^ 0x5c;
    }
    outer[BLOCK..].copy_from_slice(&ih);
    let tag = varve_sys::sha256(&outer);
    wipe(&mut k0);
    wipe(&mut outer);
    wipe(&mut ih);
    tag
}

/// Constant-time check of a full 32-byte tag.
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let t = hmac_sha256(key, msg);
    tag.len() == 32 && ct_eq(&t, tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex;

    /// RFC 4231 §4.2–4.8, HMAC-SHA-256 outputs (test case 5 is truncated to 128 bits).
    #[test]
    fn rfc4231() {
        let k4: Vec<u8> = (1..=25).collect();
        let cases: Vec<(Vec<u8>, Vec<u8>, &str)> = vec![
            (vec![0x0b; 20], b"Hi There".to_vec(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            (vec![0xaa; 20], vec![0xdd; 50], "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            (k4, vec![0xcd; 50], "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            (vec![0x0c; 20], b"Test With Truncation".to_vec(), "a3b6167473100ee06e0c796c2955552b"),
            (vec![0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (k, m, want) in cases {
            let t = hmac_sha256(&k, &m);
            assert_eq!(&hex(&t)[..want.len()], want);
            if want.len() == 64 {
                assert!(hmac_sha256_verify(&k, &m, &t));
                let mut bad = t;
                bad[31] ^= 1;
                assert!(!hmac_sha256_verify(&k, &m, &bad));
                assert!(!hmac_sha256_verify(&k, &m, &t[..16]));
            }
        }
    }
}
