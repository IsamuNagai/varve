//! "strata-wallet-v1" encrypted container (protocol/wallet.md §8):
//! Argon2id -> (enc key, mac key); AES-256-CTR; HMAC-SHA256 encrypt-then-MAC
//! over a canonical binary encoding of every field; canonical JSON text.

use crate::argon2::{argon2id, Params};
use crate::hmac::{hmac_sha256, hmac_sha256_verify};
use crate::util::{hex, unhex_strict, wipe};
use crate::WalletError;
use std::collections::BTreeMap;
use varve_consensus::json::Json;

pub const FORMAT: &str = "strata-wallet-v1";
pub const KDF_NAME: &str = "argon2id";
pub const KDF_VERSION: u32 = 0x13;
pub const CIPHER_NAME: &str = "aes-256-ctr";
pub const SALT_LEN: usize = 16;
pub const IV_LEN: usize = 16;
pub const MAC_LEN: usize = 32;

/// Default KDF cost: m = 64 MiB, t = 3, p = 1.
pub const DEFAULT_PARAMS: Params = Params { m_kib: 65536, t: 3, p: 1 };
/// Accepted ranges. Files outside them are rejected before any KDF work, so a
/// malicious file can cost at most 1 GiB of memory and 10 passes.
pub const M_KIB_MIN: u32 = 8 * 1024;
pub const M_KIB_MAX: u32 = 1024 * 1024;
pub const T_MIN: u32 = 1;
pub const T_MAX: u32 = 10;
pub const P_MIN: u32 = 1;
pub const P_MAX: u32 = 4;
/// Largest accepted plaintext (and so ciphertext).
pub const MAX_PLAINTEXT: usize = 1 << 20;
/// Largest accepted container text, checked before parsing.
const MAX_TEXT: usize = 2 * MAX_PLAINTEXT + 1024;

pub fn check_params(p: Params) -> Result<(), WalletError> {
    if !(M_KIB_MIN..=M_KIB_MAX).contains(&p.m_kib) || !(T_MIN..=T_MAX).contains(&p.t) || !(P_MIN..=P_MAX).contains(&p.p) {
        return Err(WalletError::KdfParams);
    }
    Ok(())
}

/// The byte string the MAC covers.
fn mac_input(p: Params, salt: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(100 + ct.len());
    for s in [FORMAT, KDF_NAME] {
        m.push(s.len() as u8);
        m.extend_from_slice(s.as_bytes());
    }
    for v in [KDF_VERSION, p.m_kib, p.t, p.p] {
        m.extend_from_slice(&v.to_le_bytes());
    }
    m.extend_from_slice(salt);
    m.push(CIPHER_NAME.len() as u8);
    m.extend_from_slice(CIPHER_NAME.as_bytes());
    m.extend_from_slice(iv);
    m.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    m.extend_from_slice(ct);
    m
}

/// Argon2id(passphrase, salt) -> 64 bytes; returns (enc key, mac key).
fn keys(pass: &str, salt: &[u8], p: Params) -> Result<([u8; 32], [u8; 32]), WalletError> {
    crate::derive::check_passphrase(pass)?;
    let mut k = argon2id(pass.as_bytes(), salt, &[], &[], p, 64).map_err(WalletError::Crypto)?;
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&k[..32]);
    mac.copy_from_slice(&k[32..]);
    wipe(&mut k);
    Ok((enc, mac))
}

fn to_json(p: Params, salt: &[u8], iv: &[u8], ct: &[u8], tag: &[u8]) -> String {
    Json::obj(vec![
        ("format", Json::str(FORMAT)),
        (
            "kdf",
            Json::obj(vec![
                ("name", Json::str(KDF_NAME)),
                ("version", Json::num(KDF_VERSION)),
                ("m_kib", Json::num(p.m_kib)),
                ("t", Json::num(p.t)),
                ("p", Json::num(p.p)),
                ("salt", Json::str(hex(salt))),
            ]),
        ),
        ("cipher", Json::obj(vec![("name", Json::str(CIPHER_NAME)), ("iv", Json::str(hex(iv)))])),
        ("ciphertext", Json::str(hex(ct))),
        ("mac", Json::str(hex(tag))),
    ])
    .to_string()
}

pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<String, WalletError> {
    encrypt_with_params(plaintext, passphrase, DEFAULT_PARAMS)
}

pub fn encrypt_with_params(plaintext: &[u8], passphrase: &str, p: Params) -> Result<String, WalletError> {
    check_params(p)?;
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(WalletError::Format("plaintext too large"));
    }
    let mut salt = [0u8; SALT_LEN];
    varve_sys::random_bytes(&mut salt);
    // Draw IVs until the 32-bit block counter cannot wrap (fails with
    // probability < 2^-12 per draw for the largest allowed plaintext).
    let mut iv = [0u8; IV_LEN];
    loop {
        varve_sys::random_bytes(&mut iv);
        if crate::aes::fits(&iv, plaintext.len()) {
            break;
        }
    }
    encrypt_inner(plaintext, passphrase, p, &salt, &iv)
}

fn encrypt_inner(plaintext: &[u8], passphrase: &str, p: Params, salt: &[u8; SALT_LEN], iv: &[u8; IV_LEN]) -> Result<String, WalletError> {
    check_params(p)?;
    let (mut ek, mut mk) = keys(passphrase, salt, p)?;
    let mut ct = plaintext.to_vec();
    let r = crate::aes::ctr_xor(&ek, iv, &mut ct);
    let tag = hmac_sha256(&mk, &mac_input(p, salt, iv, &ct));
    wipe(&mut ek);
    wipe(&mut mk);
    r.map_err(WalletError::Crypto)?;
    Ok(to_json(p, salt, iv, &ct, &tag))
}

fn obj<'a>(j: &'a Json, keys: &[&str]) -> Result<&'a BTreeMap<String, Json>, WalletError> {
    let m = j.as_obj().ok_or(WalletError::Format("expected an object"))?;
    if m.len() != keys.len() || !keys.iter().all(|k| m.contains_key(*k)) {
        return Err(WalletError::Format("unexpected or missing fields"));
    }
    Ok(m)
}

fn s<'a>(m: &'a BTreeMap<String, Json>, k: &str) -> Result<&'a str, WalletError> {
    m[k].as_str().ok_or(WalletError::Format("expected a string"))
}

fn u32f(m: &BTreeMap<String, Json>, k: &str) -> Result<u32, WalletError> {
    m[k].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or(WalletError::Format("expected a 32-bit integer"))
}

fn hexf(m: &BTreeMap<String, Json>, k: &str, len: Option<usize>) -> Result<Vec<u8>, WalletError> {
    let v = unhex_strict(s(m, k)?).ok_or(WalletError::Format("bad hex"))?;
    if len.is_some_and(|l| l != v.len()) {
        return Err(WalletError::Format("wrong field length"));
    }
    Ok(v)
}

/// Decrypt a container. Errors: `UnknownFormat`, `KdfParams`, `Format` (anything
/// structurally wrong or non-canonical), `Auth` (wrong passphrase or modified).
pub fn decrypt(text: &str, passphrase: &str) -> Result<Vec<u8>, WalletError> {
    if text.len() > MAX_TEXT {
        return Err(WalletError::Format("file too large"));
    }
    let trimmed = text.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    let j = Json::parse(trimmed).map_err(|_| WalletError::Format("not JSON"))?;
    let top = j.as_obj().ok_or(WalletError::Format("expected an object"))?;
    if top.get("format").and_then(|f| f.as_str()) != Some(FORMAT) {
        return Err(WalletError::UnknownFormat);
    }
    let top = obj(&j, &["format", "kdf", "cipher", "ciphertext", "mac"])?;
    let kdf = obj(&top["kdf"], &["name", "version", "m_kib", "t", "p", "salt"])?;
    let cipher = obj(&top["cipher"], &["name", "iv"])?;
    if s(kdf, "name")? != KDF_NAME || u32f(kdf, "version")? != KDF_VERSION || s(cipher, "name")? != CIPHER_NAME {
        return Err(WalletError::UnknownFormat);
    }
    let p = Params { m_kib: u32f(kdf, "m_kib")?, t: u32f(kdf, "t")?, p: u32f(kdf, "p")? };
    check_params(p)?;
    let salt = hexf(kdf, "salt", Some(SALT_LEN))?;
    let iv: [u8; IV_LEN] = hexf(cipher, "iv", Some(IV_LEN))?.try_into().unwrap();
    let tag = hexf(top, "mac", Some(MAC_LEN))?;
    if s(top, "ciphertext")?.len() > 2 * MAX_PLAINTEXT {
        return Err(WalletError::Format("ciphertext too large"));
    }
    let mut ct = hexf(top, "ciphertext", None)?;
    if !crate::aes::fits(&iv, ct.len()) {
        return Err(WalletError::Format("iv and length would wrap the counter"));
    }
    // Exactly one text per file: anything a canonical writer would not produce
    // (whitespace, field order, number spelling, escapes) is rejected here,
    // before the expensive KDF.
    if to_json(p, &salt, &iv, &ct, &tag) != trimmed {
        return Err(WalletError::Format("non-canonical encoding"));
    }
    let (mut ek, mut mk) = keys(passphrase, &salt, p)?;
    let ok = hmac_sha256_verify(&mk, &mac_input(p, &salt, &iv, &ct), &tag);
    wipe(&mut mk);
    if !ok {
        wipe(&mut ek);
        return Err(WalletError::Auth);
    }
    let r = crate::aes::ctr_xor(&ek, &iv, &mut ct);
    wipe(&mut ek);
    r.map_err(WalletError::Crypto)?;
    Ok(ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-input known answer, pinning the exact format. The AES-CTR, MAC input
    /// layout and JSON were checked independently (Python hashlib/hmac + OpenSSL
    /// CLI) from KAT_K and the text of protocol/wallet.md §8.
    const KAT_K: &str = "e827745305024800d743de66b614c5b1f86142e16f604d0bbe15b9442a15c6cb80d0d88bbd4eb3fe0ba74cbae388a0e25c0af55c40bc85b5931ca52caf225a76";
    const KAT_FILE: &str = "{\"cipher\":{\"iv\":\"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\",\"name\":\"aes-256-ctr\"},\"ciphertext\":\"7f970ae3e36a930fa981f289e1523d59a58aea0a342ea5d2e20dae52\",\"format\":\"strata-wallet-v1\",\"kdf\":{\"m_kib\":8192,\"name\":\"argon2id\",\"p\":1,\"salt\":\"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\",\"t\":1,\"version\":19},\"mac\":\"53c5fea6e15e9cf057610e06acdf16e58a65fab41b59b7daec6ae10bffa0b3a6\"}";
    #[test]
    fn known_answer() {
        let salt: [u8; 16] = core::array::from_fn(|i| 0xa0 + i as u8);
        let iv: [u8; 16] = core::array::from_fn(|i| 0xb0 + i as u8);
        let k = argon2id(b"varve test", &salt, &[], &[], FAST, 64).unwrap();
        assert_eq!(hex(&k), KAT_K);
        let f = encrypt_inner(b"strata wallet test plaintext", "varve test", FAST, &salt, &iv).unwrap();
        assert_eq!(f, KAT_FILE);
        assert_eq!(decrypt(KAT_FILE, "varve test").unwrap(), b"strata wallet test plaintext");
    }

    /// Cheapest allowed cost, so the per-byte tamper test stays fast.
    const FAST: Params = Params { m_kib: M_KIB_MIN, t: 1, p: 1 };

    #[test]
    fn roundtrip_default_params() {
        let pt = b"seed material \x00\x01\x02 with binary";
        let f = encrypt(pt, "correct horse battery staple").unwrap();
        assert!(f.starts_with("{\"cipher\":{\"iv\":\""));
        assert!(f.contains("\"m_kib\":65536") && f.contains("\"t\":3") && f.contains("\"p\":1"));
        assert_eq!(decrypt(&f, "correct horse battery staple").unwrap(), pt);
        assert_eq!(decrypt(&format!("{}\n", f), "correct horse battery staple").unwrap(), pt);
        assert_eq!(decrypt(&f, "correct horse battery stapl"), Err(WalletError::Auth));
    }

    #[test]
    fn roundtrip_sizes_and_fresh_randomness() {
        for n in [0usize, 1, 15, 16, 17, 1000] {
            let pt: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let a = encrypt_with_params(&pt, "pw", FAST).unwrap();
            let b = encrypt_with_params(&pt, "pw", FAST).unwrap();
            assert_ne!(a, b, "salt and iv must be fresh");
            assert_eq!(decrypt(&a, "pw").unwrap(), pt);
            assert_eq!(decrypt(&b, "pw").unwrap(), pt);
        }
    }

    #[test]
    fn wrong_passphrase() {
        let f = encrypt_with_params(b"secret", "pw", FAST).unwrap();
        for wrong in ["", "pW", "pw ", "pw\0"] {
            assert_eq!(decrypt(&f, wrong), Err(WalletError::Auth));
        }
    }

    /// Changing any single byte of the file to any of several other values is
    /// rejected (whitespace changes at the very ends are allowed by design and
    /// cannot occur here because the file has none).
    #[test]
    fn every_byte_tamper() {
        let f = encrypt_with_params(b"sixteen byte msg", "pw", FAST).unwrap();
        let bytes = f.as_bytes();
        let mut kdf_runs = 0;
        for i in 0..bytes.len() {
            for alt in [bytes[i] ^ 0x01, if bytes[i] == b'0' { b'f' } else { b'0' }, b' '] {
                if alt == bytes[i] {
                    continue;
                }
                let mut t = bytes.to_vec();
                t[i] = alt;
                let Ok(ts) = String::from_utf8(t) else { continue };
                let r = decrypt(&ts, "pw");
                assert!(r.is_err(), "tamper at byte {} ({:?} -> {:?}) accepted", i, bytes[i] as char, alt as char);
                if r == Err(WalletError::Auth) {
                    kdf_runs += 1;
                }
            }
        }
        assert!(kdf_runs > 100, "hex-field tampering must reach the MAC check");
    }

    #[test]
    fn truncation_and_extension() {
        let f = encrypt_with_params(b"0123456789abcdef0123", "pw", FAST).unwrap();
        for n in 0..f.len() {
            assert!(decrypt(&f[..n], "pw").is_err(), "truncated to {}", n);
        }
        // ciphertext shortened by one byte (two hex digits): valid JSON, MAC fails
        let ct_start = f.find("\"ciphertext\":\"").unwrap() + 14;
        let short = format!("{}{}", &f[..ct_start], &f[ct_start + 2..]);
        assert_eq!(decrypt(&short, "pw"), Err(WalletError::Auth));
        let long = format!("{}00{}", &f[..ct_start], &f[ct_start..]);
        assert_eq!(decrypt(&long, "pw"), Err(WalletError::Auth));
        assert!(decrypt(&format!("{}x", f), "pw").is_err());
    }

    fn with_kdf(f: &str, field: &str, value: &str) -> String {
        let j = Json::parse(f).unwrap();
        let mut top = j.as_obj().unwrap().clone();
        let mut kdf = top["kdf"].as_obj().unwrap().clone();
        kdf.insert(field.into(), Json::Num(value.into()));
        top.insert("kdf".into(), Json::Obj(kdf));
        Json::Obj(top).to_string()
    }

    #[test]
    fn rejects_out_of_range_kdf_params_before_kdf() {
        let f = encrypt_with_params(b"x", "pw", FAST).unwrap();
        for (k, v) in [
            ("m_kib", "8191"),
            ("m_kib", "1048577"),
            ("m_kib", "4294967295"),
            ("t", "0"),
            ("t", "11"),
            ("t", "4000000000"),
            ("p", "0"),
            ("p", "5"),
        ] {
            assert_eq!(decrypt(&with_kdf(&f, k, v), "pw"), Err(WalletError::KdfParams), "{}={}", k, v);
        }
        assert!(matches!(decrypt(&with_kdf(&f, "m_kib", "99999999999"), "pw"), Err(WalletError::Format(_))));
        assert!(matches!(decrypt(&with_kdf(&f, "t", "-1"), "pw"), Err(WalletError::Format(_))));
        // in range but different from what was used: MAC fails
        assert_eq!(decrypt(&with_kdf(&f, "t", "2"), "pw"), Err(WalletError::Auth));
        assert!(encrypt_with_params(b"x", "pw", Params { m_kib: 1024, t: 1, p: 1 }).is_err());
    }

    #[test]
    fn rejects_unknown_format_and_structure() {
        let f = encrypt_with_params(b"x", "pw", FAST).unwrap();
        assert_eq!(decrypt(&f.replace(FORMAT, "strata-wallet-v2"), "pw"), Err(WalletError::UnknownFormat));
        assert_eq!(decrypt(&f.replace("argon2id", "argon2i"), "pw"), Err(WalletError::UnknownFormat));
        assert_eq!(decrypt(&f.replace("aes-256-ctr", "aes-128-ctr"), "pw"), Err(WalletError::UnknownFormat));
        assert_eq!(decrypt(&f.replace("\"version\":19", "\"version\":16"), "pw"), Err(WalletError::UnknownFormat));
        assert_eq!(decrypt("{}", "pw"), Err(WalletError::UnknownFormat));
        assert!(decrypt("[]", "pw").is_err());
        assert!(decrypt("", "pw").is_err());
        // extra field
        let extra = f.replacen('{', "{\"comment\":\"hi\",", 1);
        assert!(matches!(decrypt(&extra, "pw"), Err(WalletError::Format(_))));
        // non-canonical spacing / uppercase hex
        assert!(matches!(decrypt(&f.replacen(":", ": ", 1), "pw"), Err(WalletError::Format(_))));
        let mac_at = f.find("\"mac\":\"").unwrap() + 7;
        let mut up = f.clone().into_bytes();
        for b in &mut up[mac_at..mac_at + 64] {
            b.make_ascii_uppercase();
        }
        let up = String::from_utf8(up).unwrap();
        if up != f {
            assert!(matches!(decrypt(&up, "pw"), Err(WalletError::Format(_))));
        }
        assert!(matches!(decrypt(&" ".repeat(MAX_TEXT + 1), "pw"), Err(WalletError::Format(_))));
    }

    #[test]
    fn counter_wrap_iv_rejected() {
        let f = encrypt_with_params(&[0u8; 40], "pw", FAST).unwrap();
        let iv_at = f.find("\"iv\":\"").unwrap() + 6;
        let bad = format!("{}{}{}", &f[..iv_at + 24], "ffffffff", &f[iv_at + 32..]);
        assert!(matches!(decrypt(&bad, "pw"), Err(WalletError::Format(_))));
    }
}
