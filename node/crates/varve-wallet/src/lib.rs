//! Varve wallet cryptography (protocol/wallet.md v0.2).
//!
//! - [`Wallet`]: 32-byte seed shown as 24 BIP-39 words, optional seed
//!   passphrase, deterministic ML-DSA-65 / SLH-DSA-SHA2-128s keys, addresses,
//!   and save/load through the encrypted "strata-wallet-v1" file format.
//! - Primitives: BLAKE2b, Argon2id, HMAC-SHA256 (pure Rust), AES-256-CTR and
//!   seeded key generation (liboqs via varve-sys).
//!
//! Secret material is wiped on drop where practical and is never printed by
//! `Debug`. Copies made by the allocator (reallocation) or the OS (swap) are
//! out of reach of this library.

pub mod address;
pub mod aes;
pub mod argon2;
pub mod bip39;
pub mod blake2b;
pub mod derive;
pub mod file;
pub mod hmac;
pub mod util;
mod wallet;

#[cfg(test)]
mod vectors;

pub use derive::{Role, Scheme};
pub use util::SecretBytes;
pub use wallet::{KeyPair, SecretString, Wallet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletError {
    /// mnemonic parse failure
    Mnemonic(&'static str),
    /// malformed or non-canonical wallet file
    Format(&'static str),
    /// wallet file names a format, KDF or cipher this library does not implement
    UnknownFormat,
    /// wallet file KDF parameters outside the accepted ranges
    KdfParams,
    /// wrong passphrase, or the file was modified
    Auth,
    /// input this implementation refuses (see message)
    Unsupported(&'static str),
    /// failure inside a primitive
    Crypto(&'static str),
    /// file system error (message only; no paths or contents)
    Io(String),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WalletError::Mnemonic(s) => write!(f, "invalid mnemonic: {}", s),
            WalletError::Format(s) => write!(f, "invalid wallet file: {}", s),
            WalletError::UnknownFormat => write!(f, "unknown wallet file format"),
            WalletError::KdfParams => write!(f, "wallet file KDF parameters out of range"),
            WalletError::Auth => write!(f, "wrong passphrase or corrupted wallet file"),
            WalletError::Unsupported(s) => write!(f, "unsupported: {}", s),
            WalletError::Crypto(s) => write!(f, "crypto error: {}", s),
            WalletError::Io(s) => write!(f, "i/o error: {}", s),
        }
    }
}

impl std::error::Error for WalletError {}
