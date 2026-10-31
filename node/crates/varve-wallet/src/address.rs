//! Bech32m address encoding (protocol/addresses.md). Copied from
//! node/crates/varve/src/address.rs (encode only) so the wallet library does not
//! depend on the node binary crate; checked against test-vectors/addresses.json.

use varve_consensus::tx::Output;

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

fn to_5bit(data: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for &d in data {
        acc = (acc << 8) | d as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// Encode an output's template as an address. `hrp` must be lowercase ASCII.
pub fn encode(hrp: &str, o: &Output) -> String {
    let template = o.template();
    let mut data = vec![template[0]]; // output_version as the first 5-bit symbol
    data.extend(to_5bit(&template[1..]));
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

pub fn valid_hrp(hrp: &str) -> bool {
    !hrp.is_empty() && hrp.len() <= 83 && hrp.bytes().all(|c| (33..=126).contains(&c) && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use varve_consensus::json::Json;
    use varve_consensus::tx::Recovery;

    /// Re-encode every address of test-vectors/addresses.json from its template.
    #[test]
    fn address_vectors() {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../test-vectors/addresses.json");
        let j = Json::parse(&std::fs::read_to_string(p).unwrap()).unwrap();
        for a in j.at("addresses").as_arr().unwrap() {
            let hrp = if a.at("network").as_str() == Some("mainnet") { "varve" } else { "tvarve" };
            let t = crate::util::unhex_strict(a.at("template_hex").as_str().unwrap()).unwrap();
            let commitment: [u8; 32] = t[4..36].try_into().unwrap();
            let mut o = Output::single(0, u16::from_le_bytes([t[2], t[3]]), commitment);
            if t[1] == 1 {
                o.recovery = Some(Recovery {
                    scheme_id: u16::from_le_bytes([t[36], t[37]]),
                    commitment: t[38..70].try_into().unwrap(),
                    delay: u32::from_le_bytes(t[70..74].try_into().unwrap()),
                });
            }
            assert_eq!(o.template(), t);
            assert_eq!(encode(hrp, &o), a.at("address").as_str().unwrap());
        }
    }
}
