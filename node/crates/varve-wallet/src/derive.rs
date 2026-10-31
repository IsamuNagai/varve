//! protocol/wallet.md §2 and §4: master secret and per-key derivation, and
//! seeded key generation.

use crate::util::{wipe, SecretBytes};
use crate::WalletError;
use varve_consensus::params::{SCHEME_ML_DSA_65, SCHEME_SLH_DSA_SHA2_128S};
pub use varve_sys::Scheme;

pub const MASTER_TAG: &str = "VARVE/wallet/master/v1";
pub const KEY_TAG: &str = "VARVE/wallet/key/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Primary = 0,
    Recovery = 1,
}

pub fn scheme_id(s: Scheme) -> u16 {
    match s {
        Scheme::MlDsa65 => SCHEME_ML_DSA_65,
        Scheme::SlhDsaSha2_128s => SCHEME_SLH_DSA_SHA2_128S,
    }
}

pub fn scheme_from_id(id: u16) -> Option<Scheme> {
    match id {
        SCHEME_ML_DSA_65 => Some(Scheme::MlDsa65),
        SCHEME_SLH_DSA_SHA2_128S => Some(Scheme::SlhDsaSha2_128s),
        _ => None,
    }
}

/// `L` of wallet.md §4.
pub fn okm_len(s: Scheme) -> usize {
    match s {
        Scheme::MlDsa65 => 32,
        Scheme::SlhDsaSha2_128s => 48,
    }
}

/// The passphrase rule of wallet.md §2: UTF-8, NFKD-normalized. The standard
/// library has no Unicode normalization, so only ASCII (where NFKD is the
/// identity) is accepted; anything else is refused rather than silently
/// producing keys another wallet would not reproduce.
pub fn check_passphrase(pass: &str) -> Result<(), WalletError> {
    if !pass.is_ascii() {
        return Err(WalletError::Unsupported("non-ASCII passphrase (NFKD normalization not implemented)"));
    }
    if pass.len() > u16::MAX as usize {
        return Err(WalletError::Unsupported("passphrase longer than 65535 bytes"));
    }
    Ok(())
}

/// master = SHAKE256(u8(len(T)) ‖ T ‖ seed ‖ u16(len(pass)) ‖ pass, 64)
pub fn master(seed: &[u8; 32], pass: &str) -> Result<[u8; 64], WalletError> {
    check_passphrase(pass)?;
    let mut m = Vec::with_capacity(1 + MASTER_TAG.len() + 32 + 2 + pass.len());
    m.push(MASTER_TAG.len() as u8);
    m.extend_from_slice(MASTER_TAG.as_bytes());
    m.extend_from_slice(seed);
    m.extend_from_slice(&(pass.len() as u16).to_le_bytes());
    m.extend_from_slice(pass.as_bytes());
    let mut out = [0u8; 64];
    varve_sys::shake256(&m, &mut out);
    wipe(&mut m);
    Ok(out)
}

/// okm = SHAKE256(u8(len(T)) ‖ T ‖ master ‖ u8(role) ‖ u16(scheme_id) ‖ u32(account) ‖ u32(index), L)
pub fn okm(master: &[u8; 64], role: Role, scheme: Scheme, account: u32, index: u32) -> SecretBytes {
    let mut m = Vec::with_capacity(1 + KEY_TAG.len() + 64 + 11);
    m.push(KEY_TAG.len() as u8);
    m.extend_from_slice(KEY_TAG.as_bytes());
    m.extend_from_slice(master);
    m.push(role as u8);
    m.extend_from_slice(&scheme_id(scheme).to_le_bytes());
    m.extend_from_slice(&account.to_le_bytes());
    m.extend_from_slice(&index.to_le_bytes());
    let mut out = vec![0u8; okm_len(scheme)];
    varve_sys::shake256(&m, &mut out);
    wipe(&mut m);
    SecretBytes::new(out)
}

/// Deterministic key generation from okm: (public key, secret key).
pub fn keygen(scheme: Scheme, okm: &[u8]) -> Result<(Vec<u8>, SecretBytes), WalletError> {
    if okm.len() != okm_len(scheme) {
        return Err(WalletError::Crypto("wrong okm length"));
    }
    let r = match scheme {
        Scheme::MlDsa65 => varve_sys::mldsa65_keypair_from_seed(okm.try_into().unwrap()),
        Scheme::SlhDsaSha2_128s => varve_sys::slhdsa_sha2_128s_keypair_from_seed(
            okm[0..16].try_into().unwrap(),
            okm[16..32].try_into().unwrap(),
            okm[32..48].try_into().unwrap(),
        ),
    };
    let (pk, sk) = r.map_err(WalletError::Crypto)?;
    Ok((pk, SecretBytes::new(sk)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex, unhex_strict};
    use varve_consensus::json::Json;

    fn acvp() -> Json {
        Json::parse(include_str!("../testdata/acvp_keygen.json")).unwrap()
    }
    fn h(j: &Json, k: &str) -> Vec<u8> {
        unhex_strict(&j.at(k).as_str().unwrap().to_ascii_lowercase()).unwrap()
    }

    /// NIST ACVP ML-DSA-keyGen-FIPS204 (ACVP-Server v1.1.0.42), all 25 ML-DSA-65
    /// cases: seed ξ -> (pk, sk) must match byte for byte.
    #[test]
    fn acvp_mldsa65_keygen() {
        let j = acvp();
        let cases = j.at("ml_dsa_65").as_arr().unwrap();
        assert_eq!(cases.len(), 25);
        for c in cases {
            let (pk, sk) = keygen(Scheme::MlDsa65, &h(c, "seed")).unwrap();
            assert_eq!(pk, h(c, "pk"), "tcId {}", c.at("tcId").as_u64().unwrap());
            assert_eq!(sk.expose(), &h(c, "sk")[..], "tcId {}", c.at("tcId").as_u64().unwrap());
        }
    }

    /// NIST ACVP SLH-DSA-keyGen-FIPS205 (ACVP-Server v1.1.0.42), all 10
    /// SLH-DSA-SHA2-128s cases.
    #[test]
    fn acvp_slhdsa_sha2_128s_keygen() {
        let j = acvp();
        let cases = j.at("slh_dsa_sha2_128s").as_arr().unwrap();
        assert_eq!(cases.len(), 10);
        for c in cases {
            let mut okm = h(c, "skSeed");
            okm.extend(h(c, "skPrf"));
            okm.extend(h(c, "pkSeed"));
            let (pk, sk) = keygen(Scheme::SlhDsaSha2_128s, &okm).unwrap();
            assert_eq!(pk, h(c, "pk"), "tcId {}", c.at("tcId").as_u64().unwrap());
            assert_eq!(sk.expose(), &h(c, "sk")[..]);
        }
    }

    /// Seeded keys work with the normal liboqs sign/verify (which may dispatch to
    /// the AVX2 backend), and key generation is deterministic.
    #[test]
    fn seeded_keys_sign_verify_and_are_deterministic() {
        let m = master(&[0x42; 32], "").unwrap();
        for s in [Scheme::MlDsa65, Scheme::SlhDsaSha2_128s] {
            let o = okm(&m, Role::Primary, s, 0, 0);
            let (pk, sk) = keygen(s, o.expose()).unwrap();
            assert_eq!(pk.len(), s.public_key_len());
            assert_eq!(sk.len(), s.secret_key_len());
            let sig = varve_sys::sign(s, sk.expose(), b"varve wallet").unwrap();
            assert!(varve_sys::verify(s, &pk, b"varve wallet", &sig));
            assert!(!varve_sys::verify(s, &pk, b"varve wallet!", &sig));
            let (pk2, sk2) = keygen(s, okm(&m, Role::Primary, s, 0, 0).expose()).unwrap();
            assert_eq!(pk, pk2);
            assert_eq!(sk, sk2);
            let (pk3, _) = keygen(s, okm(&m, Role::Primary, s, 0, 1).expose()).unwrap();
            assert_ne!(pk, pk3);
        }
    }

    #[test]
    fn derivation_domain_separation() {
        let m = master(&[1; 32], "").unwrap();
        assert_ne!(m, master(&[1; 32], "x").unwrap());
        assert_ne!(m, master(&[2; 32], "").unwrap());
        let base = okm(&m, Role::Primary, Scheme::MlDsa65, 0, 0);
        for o in [
            okm(&m, Role::Recovery, Scheme::MlDsa65, 0, 0),
            okm(&m, Role::Primary, Scheme::MlDsa65, 1, 0),
            okm(&m, Role::Primary, Scheme::MlDsa65, 0, 1),
        ] {
            assert_ne!(base, o);
        }
        // ML-DSA okm is not a prefix of the SLH-DSA okm (different scheme_id input).
        let slh = okm(&m, Role::Primary, Scheme::SlhDsaSha2_128s, 0, 0);
        assert_ne!(base.expose(), &slh.expose()[..32]);
        assert!(master(&[1; 32], "caf\u{e9}").is_err());
    }

    /// Byte layout of the derivation inputs, recomputed by hand.
    #[test]
    fn derivation_layout() {
        let seed = [9u8; 32];
        let mut buf = vec![22u8];
        buf.extend_from_slice(b"VARVE/wallet/master/v1");
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&[2, 0]);
        buf.extend_from_slice(b"pw");
        let mut want = [0u8; 64];
        varve_sys::shake256(&buf, &mut want);
        let m = master(&seed, "pw").unwrap();
        assert_eq!(hex(&m), hex(&want));

        let mut buf = vec![19u8];
        buf.extend_from_slice(b"VARVE/wallet/key/v1");
        buf.extend_from_slice(&m);
        buf.extend_from_slice(&[1, 0x02, 0x00, 5, 0, 0, 0, 0x07, 0x01, 0, 0]);
        let mut want = [0u8; 48];
        varve_sys::shake256(&buf, &mut want);
        assert_eq!(okm(&m, Role::Recovery, Scheme::SlhDsaSha2_128s, 5, 0x107).expose(), &want[..]);
    }
}
