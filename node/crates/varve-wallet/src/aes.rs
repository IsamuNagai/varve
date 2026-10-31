//! AES-256-CTR via liboqs (varve_sys::Aes256).
//!
//! The counter block is the 16-byte IV; its last 4 bytes are a big-endian
//! counter incremented per block. `ctr_xor` refuses inputs that would wrap that
//! 32-bit counter, so the result equals NIST SP 800-38A CTR with either a 32-bit
//! or a full 128-bit incrementing function.

pub const MAX_BLOCKS_FROM_IV_ZERO: u64 = 1 << 32;

/// Number of 16-byte blocks the keystream can still produce from `iv` without
/// the low 32-bit counter wrapping.
pub fn blocks_available(iv: &[u8; 16]) -> u64 {
    MAX_BLOCKS_FROM_IV_ZERO - u32::from_be_bytes(iv[12..16].try_into().unwrap()) as u64
}

pub fn fits(iv: &[u8; 16], len: usize) -> bool {
    (len as u64).div_ceil(16) <= blocks_available(iv)
}

/// Encrypt or decrypt `data` in place.
pub fn ctr_xor(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) -> Result<(), &'static str> {
    if !fits(iv, data.len()) {
        return Err("AES-CTR counter would wrap");
    }
    varve_sys::Aes256::new(key).ctr_xor(iv, data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex_strict};

    const KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const CTR: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                      30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    const CT: &str = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5\
                      2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";

    fn k() -> ([u8; 32], [u8; 16]) {
        (unhex_strict(KEY).unwrap().try_into().unwrap(), unhex_strict(CTR).unwrap().try_into().unwrap())
    }

    /// NIST SP 800-38A F.5.5 CTR-AES256.Encrypt and F.5.6 CTR-AES256.Decrypt.
    #[test]
    fn sp800_38a_f55_f56() {
        let (key, iv) = k();
        let mut d = unhex_strict(PT).unwrap();
        ctr_xor(&key, &iv, &mut d).unwrap();
        assert_eq!(hex(&d), CT);
        ctr_xor(&key, &iv, &mut d).unwrap();
        assert_eq!(hex(&d), PT);
    }

    /// Partial blocks give a prefix of the same keystream (all lengths 0..=64).
    #[test]
    fn partial_lengths() {
        let (key, iv) = k();
        let pt = unhex_strict(PT).unwrap();
        let ct = unhex_strict(CT).unwrap();
        for n in 0..=64 {
            let mut d = pt[..n].to_vec();
            ctr_xor(&key, &iv, &mut d).unwrap();
            assert_eq!(d, ct[..n]);
        }
    }

    #[test]
    fn refuses_counter_wrap() {
        let key = [7u8; 32];
        let mut iv = [0u8; 16];
        iv[12..].copy_from_slice(&0xffff_fffeu32.to_be_bytes());
        assert!(ctr_xor(&key, &iv, &mut [0u8; 32]).is_ok()); // 2 blocks: ...fe, ...ff
        assert!(ctr_xor(&key, &iv, &mut [0u8; 33]).is_err()); // a 3rd block would wrap
        assert_eq!(blocks_available(&[0u8; 16]), 1 << 32);
    }
}
