//! BIP-39 English mnemonics for 256-bit entropy (24 words). Only the
//! entropy <-> words encoding is used; the BIP-39 PBKDF2 seed step is not
//! (protocol/wallet.md §2).

use crate::util::wipe;
use crate::WalletError;
use std::sync::OnceLock;

/// bitcoin/bips bip-0039/english.txt, verified against this SHA-256 when fetched
/// and again on first use.
const ENGLISH_TXT: &str = include_str!("bip39_english.txt");
pub const ENGLISH_SHA256: &str = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

pub const WORDS: usize = 24;

pub fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        assert_eq!(crate::util::hex(&varve_sys::sha256(ENGLISH_TXT.as_bytes())), ENGLISH_SHA256, "embedded BIP-39 word list corrupted");
        let v: Vec<&str> = ENGLISH_TXT.lines().collect();
        assert_eq!(v.len(), 2048);
        assert!(v.windows(2).all(|w| w[0] < w[1]), "word list must be sorted");
        v
    })
}

/// 32 bytes of entropy -> 24 words separated by single spaces.
pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> String {
    let list = wordlist();
    let mut bits = [0u8; 33];
    bits[..32].copy_from_slice(entropy);
    bits[32] = varve_sys::sha256(entropy)[0]; // 256/32 = 8 checksum bits
    let mut words = Vec::with_capacity(WORDS);
    for i in 0..WORDS {
        let mut idx = 0usize;
        for b in 0..11 {
            let pos = i * 11 + b;
            let bit = (bits[pos / 8] >> (7 - pos % 8)) & 1;
            idx = (idx << 1) | bit as usize;
        }
        words.push(list[idx]);
    }
    wipe(&mut bits);
    words.join(" ")
}

/// Normalize (ASCII case, any whitespace) and decode 24 words to 32 bytes of
/// entropy, checking the checksum.
pub fn mnemonic_to_entropy(phrase: &str) -> Result<[u8; 32], WalletError> {
    let list = wordlist();
    let lower = phrase.to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    if words.len() != WORDS {
        return Err(WalletError::Mnemonic("mnemonic must have exactly 24 words"));
    }
    let mut bits = [0u8; 33];
    for (i, w) in words.iter().enumerate() {
        let idx = list.binary_search(w).map_err(|_| WalletError::Mnemonic("unknown word"))?;
        for b in 0..11 {
            if (idx >> (10 - b)) & 1 == 1 {
                let pos = i * 11 + b;
                bits[pos / 8] |= 1 << (7 - pos % 8);
            }
        }
    }
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&bits[..32]);
    let ok = varve_sys::sha256(&entropy)[0] == bits[32];
    wipe(&mut bits);
    if !ok {
        wipe(&mut entropy);
        return Err(WalletError::Mnemonic("bad checksum"));
    }
    Ok(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::unhex_strict;

    /// The 256-bit English entropy -> mnemonic vectors of trezor/python-mnemonic
    /// vectors.json (commit b57a5ad); the PBKDF2 seed column is not used by Varve.
    const VECTORS: [(&str, &str); 8] = [
        ("0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
        ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
        ("8080808080808080808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
        ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"),
        ("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"),
        ("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"),
        ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"),
    ];

    #[test]
    fn wordlist_hash() {
        assert_eq!(crate::util::hex(&varve_sys::sha256(ENGLISH_TXT.as_bytes())), ENGLISH_SHA256);
        assert_eq!(wordlist().len(), 2048);
        assert_eq!(wordlist()[0], "abandon");
        assert_eq!(wordlist()[2047], "zoo");
    }

    #[test]
    fn official_vectors() {
        for (e, m) in VECTORS {
            let ent: [u8; 32] = unhex_strict(e).unwrap().try_into().unwrap();
            assert_eq!(entropy_to_mnemonic(&ent), m);
            assert_eq!(mnemonic_to_entropy(m).unwrap(), ent);
        }
    }

    #[test]
    fn normalizes_case_and_whitespace() {
        let (e, m) = VECTORS[4];
        let messy = format!("  {}\n", m.to_uppercase().replace(' ', " \t "));
        assert_eq!(crate::util::hex(&mnemonic_to_entropy(&messy).unwrap()), e);
    }

    #[test]
    fn rejects_bad_input() {
        let m = VECTORS[5].1;
        let words: Vec<&str> = m.split(' ').collect();
        // wrong count
        assert!(mnemonic_to_entropy(&words[..23].join(" ")).is_err());
        assert!(mnemonic_to_entropy(&format!("{} abandon", m)).is_err());
        assert!(mnemonic_to_entropy("").is_err());
        // 12-word BIP-39 phrases are not Varve seeds
        assert!(mnemonic_to_entropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_err());
        // unknown word
        let mut w = words.clone();
        w[3] = "gorillaz";
        assert_eq!(mnemonic_to_entropy(&w.join(" ")), Err(WalletError::Mnemonic("unknown word")));
        // bad checksum: change the last word to every other word; only 1/256 of
        // last words... rather, exactly the 8 with the right checksum bits pass.
        let mut passing = 0;
        for cand in wordlist() {
            let mut w = words.clone();
            w[23] = cand;
            if mnemonic_to_entropy(&w.join(" ")).is_ok() {
                passing += 1;
            }
        }
        assert_eq!(passing, 8); // 3 free entropy bits in the last word
        // swapping two different words breaks the checksum here
        let mut w = words.clone();
        w.swap(0, 1);
        assert_eq!(mnemonic_to_entropy(&w.join(" ")), Err(WalletError::Mnemonic("bad checksum")));
    }
}
