//! addresses.md: Bech32m addresses carrying an output template.

use varve_consensus::params::{scheme, RECOVERY_DELAY_MAX};
use varve_consensus::tx::{Output, Recovery};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

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

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &d in data {
        if (d as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | d as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None; // non-zero padding or too much padding
    }
    Some(out)
}

/// Encode an output's template as an address.
pub fn encode(hrp: &str, o: &Output) -> String {
    let template = o.template();
    let mut data = vec![template[0]]; // output_version as the first 5-bit symbol
    data.extend(convert_bits(&template[1..], 8, 5, true).unwrap());
    let mut values = hrp_expand(hrp);
    values.extend(&data);
    values.extend([0u8; 6]);
    let pm = polymod(&values) ^ BECH32M_CONST;
    let mut s = String::from(hrp);
    s.push('1');
    for d in data {
        s.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// Decode an address for the expected network (hrp). Returns an Output template with amount 0.
pub fn decode(expected_hrp: &str, addr: &str) -> Result<Output, &'static str> {
    let lower = addr.to_ascii_lowercase();
    if addr != lower && addr != addr.to_ascii_uppercase() {
        return Err("mixed case");
    }
    let pos = lower.rfind('1').ok_or("no separator")?;
    let (hrp, rest) = (&lower[..pos], &lower[pos + 1..]);
    if hrp != expected_hrp {
        return Err("address is for a different network");
    }
    if rest.len() < 7 {
        return Err("too short");
    }
    let mut data = Vec::with_capacity(rest.len());
    for c in rest.bytes() {
        data.push(CHARSET.iter().position(|&x| x == c).ok_or("invalid character")? as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend(&data);
    if polymod(&values) != BECH32M_CONST {
        return Err("bad checksum");
    }
    let data = &data[..data.len() - 6];
    if data[0] != 1 {
        return Err("unknown output version");
    }
    let payload = convert_bits(&data[1..], 5, 8, false).ok_or("bad padding")?;
    let policy = *payload.first().ok_or("empty payload")?;
    let want_len = match policy {
        0 => 35,
        1 => 73,
        _ => return Err("unknown policy"),
    };
    if payload.len() != want_len {
        return Err("payload length does not match policy");
    }
    let scheme_id = u16::from_le_bytes([payload[1], payload[2]]);
    if scheme(scheme_id, 0).is_none() {
        return Err("scheme not creatable");
    }
    let commitment: [u8; 32] = payload[3..35].try_into().unwrap();
    let recovery = if policy == 1 {
        let rs = u16::from_le_bytes([payload[35], payload[36]]);
        if scheme(rs, 0).is_none() {
            return Err("recovery scheme not creatable");
        }
        let delay = u32::from_le_bytes(payload[69..73].try_into().unwrap());
        if delay == 0 || delay > RECOVERY_DELAY_MAX {
            return Err("recovery delay out of range");
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
    fn address_vectors() {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../test-vectors/addresses.json");
        let j = Json::parse(&std::fs::read_to_string(p).unwrap()).unwrap();
        for a in j.at("addresses").as_arr().unwrap() {
            let hrp = if a.at("network").as_str() == Some("mainnet") { "varve" } else { "tvarve" };
            let addr = a.at("address").as_str().unwrap();
            let o = decode(hrp, addr).unwrap();
            assert_eq!(o.template(), unhex(a.at("template_hex").as_str().unwrap()).unwrap());
            assert_eq!(encode(hrp, &o), addr);
            assert_eq!(decode(hrp, &addr.to_ascii_uppercase()).unwrap(), o);
            assert!(decode("rvarve", addr).is_err());
            let mut bad = addr.as_bytes().to_vec();
            let i = bad.len() - 10;
            bad[i] = if bad[i] == b'q' { b'p' } else { b'q' };
            assert!(decode(hrp, std::str::from_utf8(&bad).unwrap()).is_err());
        }
    }
}
