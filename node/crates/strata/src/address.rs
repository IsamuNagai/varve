//! Bech32m address decoding (protocol/addresses.md). Encoding comes from
//! varve-wallet; decoding is adapted from node/crates/varve/src/address.rs because
//! Strata cannot depend on the node binary crate.

use varve_consensus::params::{scheme, RECOVERY_DELAY_MAX};
use varve_consensus::tx::{Output, Recovery};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
/// Longest address we accept (a policy-1 address is ~130 characters).
const MAX_ADDRESS_LEN: usize = 200;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

fn convert_bits_5_to_8(data: &[u8]) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for &d in data {
        if d >> 5 != 0 {
            return None;
        }
        acc = (acc << 5) | d as u32;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
        return None; // too much or non-zero padding
    }
    Some(out)
}

/// Encode a policy-0 or policy-1 output template.
pub fn encode(hrp: &str, o: &Output) -> String {
    varve_wallet::address::encode(hrp, o)
}

/// Decode an address for the expected network. Returns the output template with
/// amount 0. Errors are fixed strings and never echo the input.
pub fn decode(expected_hrp: &str, addr: &str) -> Result<Output, &'static str> {
    if addr.is_empty() {
        return Err("enter an address");
    }
    if addr.len() > MAX_ADDRESS_LEN || !addr.is_ascii() {
        return Err("not a Varve address");
    }
    let lower = addr.to_ascii_lowercase();
    if addr != lower && addr != addr.to_ascii_uppercase() {
        return Err("address mixes upper and lower case");
    }
    let pos = lower.rfind('1').ok_or("not a Varve address")?;
    let (hrp, rest) = (&lower[..pos], &lower[pos + 1..]);
    if hrp != expected_hrp {
        return Err("address is for a different network");
    }
    if rest.len() < 7 {
        return Err("address is too short");
    }
    let mut data = Vec::with_capacity(rest.len());
    for c in rest.bytes() {
        data.push(CHARSET.iter().position(|&x| x == c).ok_or("address contains an invalid character")? as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend(&data);
    if polymod(&values) != BECH32M_CONST {
        return Err("address checksum is wrong (check for a typo)");
    }
    let data = &data[..data.len() - 6];
    if data[0] != 1 {
        return Err("unknown address version");
    }
    let payload = convert_bits_5_to_8(&data[1..]).ok_or("malformed address")?;
    let policy = *payload.first().ok_or("malformed address")?;
    let want_len = match policy {
        0 => 35,
        1 => 73,
        _ => return Err("unknown address type"),
    };
    if payload.len() != want_len {
        return Err("malformed address");
    }
    let scheme_id = u16::from_le_bytes([payload[1], payload[2]]);
    if scheme(scheme_id, 0).is_none() {
        return Err("address uses an unknown signature scheme");
    }
    let commitment: [u8; 32] = payload[3..35].try_into().unwrap();
    let recovery = if policy == 1 {
        let rs = u16::from_le_bytes([payload[35], payload[36]]);
        if scheme(rs, 0).is_none() {
            return Err("address uses an unknown recovery scheme");
        }
        let delay = u32::from_le_bytes(payload[69..73].try_into().unwrap());
        if delay == 0 || delay > RECOVERY_DELAY_MAX {
            return Err("address has an invalid recovery delay");
        }
        Some(Recovery { scheme_id: rs, commitment: payload[37..69].try_into().unwrap(), delay })
    } else {
        None
    };
    Ok(Output { amount: 0, output_version: 1, scheme_id, commitment, recovery })
}

#[cfg(test)]
mod tests {
    use super::*;
    use varve_consensus::encoding::unhex;
    use varve_consensus::json::Json;

    #[test]
    fn vectors_roundtrip_and_reject() {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../test-vectors/addresses.json");
        let j = Json::parse(&std::fs::read_to_string(p).unwrap()).unwrap();
        for a in j.at("addresses").as_arr().unwrap() {
            let hrp = if a.at("network").as_str() == Some("mainnet") { "varve" } else { "tvarve" };
            let addr = a.at("address").as_str().unwrap();
            let o = decode(hrp, addr).unwrap();
            assert_eq!(o.template(), unhex(a.at("template_hex").as_str().unwrap()).unwrap());
            assert_eq!(encode(hrp, &o), addr);
            assert_eq!(decode(hrp, &addr.to_ascii_uppercase()).unwrap(), o);
            // wrong network
            assert_eq!(decode("rvarve", addr), Err("address is for a different network"));
            // one changed character breaks the checksum
            let mut bad = addr.as_bytes().to_vec();
            let i = bad.len() - 10;
            bad[i] = if bad[i] == b'q' { b'p' } else { b'q' };
            assert!(decode(hrp, std::str::from_utf8(&bad).unwrap()).is_err());
        }
    }

    #[test]
    fn rejects_garbage() {
        let o = Output::single(0, 1, [9; 32]);
        let good = encode("tvarve", &o);
        assert!(decode("tvarve", &good).is_ok());
        // mixed case
        let mut mixed = good.clone();
        mixed.replace_range(0..1, "T");
        assert!(decode("tvarve", &mixed).is_err());
        assert!(decode("tvarve", "").is_err());
        assert!(decode("tvarve", "tvarve1").is_err());
        assert!(decode("tvarve", &"x".repeat(500)).is_err());
        assert!(decode("tvarve", "tvarve1qqqqqqqqb").is_err()); // 'b' not in charset
        // unknown scheme id
        let unk = encode("tvarve", &Output::single(0, 7, [9; 32]));
        assert_eq!(decode("tvarve", &unk), Err("address uses an unknown signature scheme"));
        // error messages never echo the input
        let e = decode("tvarve", "tvarve1secretstuffzz").unwrap_err();
        assert!(!e.contains("secret"));
    }
}
