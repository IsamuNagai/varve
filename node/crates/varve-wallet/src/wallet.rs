//! The public wallet API.

use crate::argon2::Params;
use crate::derive::{self, Role, Scheme};
use crate::util::{wipe, SecretBytes};
use crate::{bip39, file, WalletError};
use varve_consensus::tx::{commitment, Output};

/// Plaintext of a wallet file: u8(1) ‖ seed[32] ‖ u16(len(pass)) ‖ pass.
const PAYLOAD_VERSION: u8 = 1;

/// A string holding secret text (a mnemonic). Wiped on drop, never printed.
pub struct SecretString(String);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8, so the String stays valid.
        wipe(unsafe { self.0.as_bytes_mut() });
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// A deterministic wallet: one 32-byte seed plus an optional passphrase.
pub struct Wallet {
    seed: [u8; 32],
    passphrase: SecretBytes,
    master: [u8; 64],
}

impl Drop for Wallet {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.master);
    }
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Wallet").field("seed", &"<redacted>").field("has_passphrase", &!self.passphrase.is_empty()).finish()
    }
}

/// One derived key.
pub struct KeyPair {
    pub role: Role,
    pub scheme: Scheme,
    pub account: u32,
    pub index: u32,
    pub pk: Vec<u8>,
    sk: SecretBytes,
    /// H256("VARVE/pk/v1", u16(scheme_id) ‖ pk)
    pub commitment: [u8; 32],
}

impl KeyPair {
    pub fn scheme_id(&self) -> u16 {
        derive::scheme_id(self.scheme)
    }
    /// The secret key in liboqs format. Handle with care.
    pub fn sk(&self) -> &[u8] {
        self.sk.expose()
    }
    /// Hedged pure-mode signature with an empty context (transactions.md §6).
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, WalletError> {
        varve_sys::sign(self.scheme, self.sk.expose(), msg).map_err(WalletError::Crypto)
    }
    /// A policy-0 output template paying this key.
    pub fn output(&self, amount: u64) -> Output {
        Output::single(amount, self.scheme_id(), self.commitment)
    }
    /// Bech32m address of the policy-0 output for this key.
    pub fn address(&self, hrp: &str) -> Result<String, WalletError> {
        if !crate::address::valid_hrp(hrp) {
            return Err(WalletError::Unsupported("invalid address prefix"));
        }
        Ok(crate::address::encode(hrp, &self.output(0)))
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("role", &self.role)
            .field("scheme", &self.scheme)
            .field("account", &self.account)
            .field("index", &self.index)
            .field("commitment", &crate::util::hex(&self.commitment))
            .field("sk", &"<redacted>")
            .finish()
    }
}

impl Wallet {
    /// New wallet from fresh OS randomness, no passphrase.
    pub fn generate() -> Wallet {
        Self::generate_with_passphrase("").expect("empty passphrase is always valid")
    }

    pub fn generate_with_passphrase(passphrase: &str) -> Result<Wallet, WalletError> {
        let mut seed = [0u8; 32];
        varve_sys::random_bytes(&mut seed);
        let w = Self::from_seed(&seed, Some(passphrase));
        wipe(&mut seed);
        w
    }

    pub fn from_seed(seed: &[u8; 32], passphrase: Option<&str>) -> Result<Wallet, WalletError> {
        let pass = passphrase.unwrap_or("");
        let master = derive::master(seed, pass)?;
        Ok(Wallet { seed: *seed, passphrase: SecretBytes::new(pass.as_bytes().to_vec()), master })
    }

    /// Restore from 24 words (case and whitespace are normalized) and the
    /// optional seed passphrase.
    pub fn from_mnemonic(words: &str, passphrase: Option<&str>) -> Result<Wallet, WalletError> {
        let mut seed = bip39::mnemonic_to_entropy(words)?;
        let w = Self::from_seed(&seed, passphrase);
        wipe(&mut seed);
        w
    }

    /// The 24-word backup of the seed (the passphrase is not part of it).
    pub fn mnemonic(&self) -> SecretString {
        SecretString(bip39::entropy_to_mnemonic(&self.seed))
    }

    pub fn has_passphrase(&self) -> bool {
        !self.passphrase.is_empty()
    }

    /// Derive the key for (role, scheme, account, index) (wallet.md §4).
    pub fn derive(&self, role: Role, scheme: Scheme, account: u32, index: u32) -> Result<KeyPair, WalletError> {
        let okm = derive::okm(&self.master, role, scheme, account, index);
        let (pk, sk) = derive::keygen(scheme, okm.expose())?;
        let commitment = commitment(derive::scheme_id(scheme), &pk);
        Ok(KeyPair { role, scheme, account, index, pk, sk, commitment })
    }

    /// Receive address `index`: primary role, ML-DSA-65, account 0, policy 0.
    pub fn address(&self, hrp: &str, index: u32) -> Result<String, WalletError> {
        self.derive(Role::Primary, Scheme::MlDsa65, 0, index)?.address(hrp)
    }

    fn payload(&self) -> SecretBytes {
        let p = self.passphrase.expose();
        let mut v = Vec::with_capacity(35 + p.len());
        v.push(PAYLOAD_VERSION);
        v.extend_from_slice(&self.seed);
        v.extend_from_slice(&(p.len() as u16).to_le_bytes());
        v.extend_from_slice(p);
        SecretBytes::new(v)
    }

    fn from_payload(b: &[u8]) -> Result<Wallet, WalletError> {
        if b.len() < 35 || b[0] != PAYLOAD_VERSION {
            return Err(WalletError::Format("unknown wallet payload"));
        }
        let n = u16::from_le_bytes([b[33], b[34]]) as usize;
        if b.len() != 35 + n {
            return Err(WalletError::Format("wallet payload length"));
        }
        let pass = std::str::from_utf8(&b[35..]).map_err(|_| WalletError::Format("passphrase is not UTF-8"))?;
        Self::from_seed(b[1..33].try_into().unwrap(), Some(pass))
    }

    /// Encrypt the wallet (seed and seed passphrase) under `file_passphrase`
    /// with the default KDF cost.
    pub fn save(&self, file_passphrase: &str) -> Result<String, WalletError> {
        file::encrypt(self.payload().expose(), file_passphrase)
    }

    pub fn save_with_params(&self, file_passphrase: &str, params: Params) -> Result<String, WalletError> {
        file::encrypt_with_params(self.payload().expose(), file_passphrase, params)
    }

    pub fn load(contents: &str, file_passphrase: &str) -> Result<Wallet, WalletError> {
        let pt = SecretBytes::new(file::decrypt(contents, file_passphrase)?);
        Self::from_payload(pt.expose())
    }

    /// Write the encrypted wallet to `path` (owner-only permissions on Unix;
    /// written to a temporary file in the same directory, then renamed).
    pub fn save_to_path(&self, path: &std::path::Path, file_passphrase: &str) -> Result<(), WalletError> {
        let text = self.save(file_passphrase)?;
        let io = |e: std::io::Error| WalletError::Io(e.kind().to_string());
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        {
            use std::io::Write;
            let mut f = opts.open(&tmp).map_err(io)?;
            let r = f.write_all(text.as_bytes()).and_then(|_| f.sync_all());
            if let Err(e) = r {
                let _ = std::fs::remove_file(&tmp);
                return Err(io(e));
            }
        }
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io(e)
        })
    }

    pub fn load_from_path(path: &std::path::Path, file_passphrase: &str) -> Result<Wallet, WalletError> {
        let meta = std::fs::metadata(path).map_err(|e| WalletError::Io(e.kind().to_string()))?;
        if meta.len() > 4 << 20 {
            return Err(WalletError::Format("file too large"));
        }
        let text = std::fs::read_to_string(path).map_err(|e| WalletError::Io(e.kind().to_string()))?;
        Self::load(&text, file_passphrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Params = Params { m_kib: file::M_KIB_MIN, t: 1, p: 1 };

    #[test]
    fn generate_mnemonic_restore() {
        let w = Wallet::generate();
        let m = w.mnemonic();
        assert_eq!(m.expose().split(' ').count(), 24);
        let r = Wallet::from_mnemonic(m.expose(), None).unwrap();
        assert_eq!(w.address("varve", 0).unwrap(), r.address("varve", 0).unwrap());
        // a passphrase gives an unrelated wallet
        let p = Wallet::from_mnemonic(m.expose(), Some("extra")).unwrap();
        assert_ne!(w.address("varve", 0).unwrap(), p.address("varve", 0).unwrap());
        assert!(p.has_passphrase() && !w.has_passphrase());
        assert_ne!(Wallet::generate().mnemonic().expose(), m.expose());
    }

    #[test]
    fn derive_sign_verify_both_schemes_and_roles() {
        let w = Wallet::from_seed(&[7; 32], None).unwrap();
        for role in [Role::Primary, Role::Recovery] {
            for s in [Scheme::MlDsa65, Scheme::SlhDsaSha2_128s] {
                let k = w.derive(role, s, 0, 3).unwrap();
                let sig = k.sign(b"msg").unwrap();
                assert!(varve_sys::verify(s, &k.pk, b"msg", &sig));
                assert_eq!(k.commitment, commitment(k.scheme_id(), &k.pk));
                let a = k.address("tvarve").unwrap();
                assert!(a.starts_with("tvarve1"));
            }
        }
        assert!(w.derive(Role::Primary, Scheme::MlDsa65, 0, 0).unwrap().address("Varve").is_err());
    }

    #[test]
    fn debug_never_shows_secrets() {
        let seed = [0xab; 32];
        let w = Wallet::from_seed(&seed, Some("hunter2")).unwrap();
        let k = w.derive(Role::Primary, Scheme::SlhDsaSha2_128s, 0, 0).unwrap();
        let m = w.mnemonic();
        let sk_hex = crate::util::hex(k.sk());
        for d in [format!("{:?}", w), format!("{:#?}", k), format!("{:?}", m), format!("{:?}", SecretBytes::new(k.sk().to_vec()))] {
            assert!(!d.contains(&crate::util::hex(&seed)));
            assert!(!d.contains("ab, ab") && !d.contains("171, 171"));
            assert!(!d.contains("hunter2"));
            assert!(!d.contains(&sk_hex[..16]));
            assert!(!d.contains(m.expose()));
            assert!(d.contains("redacted"));
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let w = Wallet::from_seed(&[3; 32], Some("seed pass")).unwrap();
        let f = w.save_with_params("file pass", FAST).unwrap();
        let r = Wallet::load(&f, "file pass").unwrap();
        assert_eq!(r.mnemonic().expose(), w.mnemonic().expose());
        assert!(r.has_passphrase());
        assert_eq!(r.address("varve", 5).unwrap(), w.address("varve", 5).unwrap());
        assert_eq!(Wallet::load(&f, "seed pass").unwrap_err(), WalletError::Auth);
    }

    #[test]
    fn save_load_path() {
        let dir = std::env::temp_dir().join(format!("varve-wallet-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");
        let _ = std::fs::remove_file(&path);
        let w = Wallet::generate();
        w.save_to_path(&path, "pw").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let r = Wallet::load_from_path(&path, "pw").unwrap();
        assert_eq!(r.mnemonic().expose(), w.mnemonic().expose());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn payload_rejects_garbage() {
        assert!(Wallet::from_payload(&[]).is_err());
        assert!(Wallet::from_payload(&[2; 35]).is_err());
        let mut p = vec![1u8];
        p.extend([0u8; 32]);
        p.extend([1, 0]);
        assert!(Wallet::from_payload(&p).is_err()); // declared 1 byte, none present
        p.push(b'x');
        assert!(Wallet::from_payload(&p).is_ok());
    }
}
