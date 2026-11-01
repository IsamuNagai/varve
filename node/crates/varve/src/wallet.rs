//! The node's built-in wallet, used mainly for mining (ADR-0011).
//!
//! Keys are derived from a 24-word recovery phrase (protocol/wallet.md) and stored
//! only in the encrypted "strata-wallet-v1" file (`wallet.strata.json`), the same
//! format and derivation as the Strata wallet, so the same words open both.
//! The running node never needs a private key to mine or to show balances: it works
//! from `wallet-public.json`, a list of the wallet's public key commitments. Private
//! keys exist in memory only while the wallet is unlocked for a payment
//! (`walletpassphrase`, at most one hour), and are wiped when it locks.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use varve_consensus::encoding::{hex, unhex};
use varve_consensus::json::Json;
use varve_consensus::params::{scheme, COINBASE_MATURITY, SCHEME_ML_DSA_65};
use varve_consensus::tx::{sighash, OutPoint, Output, Tx, Witness};
use varve_consensus::validate::{ChainIds, Coin};
use varve_wallet::{Role, Scheme};

use crate::address;

pub const ENCRYPTED_FILE: &str = "wallet.strata.json";
pub const PUBLIC_FILE: &str = "wallet-public.json";
const LEGACY_FILE: &str = "wallet.json";
const PUBLIC_FORMAT: &str = "varve-node-wallet-public-v1";
/// Public commitments kept ready per account (receive = account 0, change = account 1).
const LOOKAHEAD: u32 = 500;
pub const MAX_UNLOCK_SECS: u64 = 3600;
const RECEIVE: u32 = 0;
const CHANGE: u32 = 1;

#[derive(Debug, Default)]
pub struct Balance {
    pub spendable: u64,
    pub immature: u64,
    pub utxos: usize,
}

pub struct Wallet {
    dir: PathBuf,
    /// commitments by account (0 receive, 1 change) and index; empty if no wallet
    lists: [Vec<[u8; 32]>; 2],
    by_commitment: HashMap<[u8; 32], (u32, u32)>,
    next: [u32; 2],
    unlocked: Option<(varve_wallet::Wallet, Instant)>,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Wallet").field("addresses", &self.lists[0].len()).field("unlocked", &self.unlocked.is_some()).finish()
    }
}

/// Passphrase rule for the encrypted file (same spirit as Strata's): at least 10
/// printable ASCII characters (protocol/wallet.md: non-ASCII needs normalization).
pub fn check_passphrase(p: &str) -> Result<(), String> {
    if p.len() < 10 {
        return Err("the passphrase must be at least 10 characters".into());
    }
    if p.len() > 1024 || !p.bytes().all(|c| (0x20..0x7f).contains(&c)) {
        return Err("the passphrase must be printable ASCII, at most 1024 characters".into());
    }
    if p.bytes().all(|c| c == p.as_bytes()[0]) {
        return Err("the passphrase is too weak".into());
    }
    Ok(())
}

fn derive_commitment(w: &varve_wallet::Wallet, account: u32, index: u32) -> Result<[u8; 32], String> {
    Ok(w.derive(Role::Primary, Scheme::MlDsa65, account, index).map_err(|e| e.to_string())?.commitment)
}

impl Wallet {
    /// Open the wallet in `dir` (public part only). A missing wallet is not an error:
    /// the node runs without one, and wallet commands explain how to create it.
    pub fn open(dir: &Path) -> Result<Wallet, String> {
        if dir.join(LEGACY_FILE).exists() {
            return Err(format!(
                "{} is an unencrypted wallet from an older development build. Varve now only uses encrypted wallets: move that file out of the data directory (its coins are test coins), then create a new wallet with `varve wallet create`",
                dir.join(LEGACY_FILE).display()
            ));
        }
        let mut w = Wallet { dir: dir.to_path_buf(), lists: [Vec::new(), Vec::new()], by_commitment: HashMap::new(), next: [0, 0], unlocked: None };
        let pubp = dir.join(PUBLIC_FILE);
        if !pubp.exists() {
            if dir.join(ENCRYPTED_FILE).exists() {
                return Err(format!("{} is missing; restore it by unlocking: `varve wallet repair`", PUBLIC_FILE));
            }
            return Ok(w);
        }
        let text = std::fs::read_to_string(&pubp).map_err(|e| format!("{}: {}", PUBLIC_FILE, e))?;
        let j = Json::parse(&text).map_err(|e| format!("{}: {}", PUBLIC_FILE, e))?;
        if j.get("format").and_then(|f| f.as_str()) != Some(PUBLIC_FORMAT) {
            return Err(format!("{}: unknown format", PUBLIC_FILE));
        }
        for (acct, key) in [(RECEIVE, "receive"), (CHANGE, "change")] {
            let arr = j.get(key).and_then(|a| a.as_arr()).ok_or(format!("{}: missing {}", PUBLIC_FILE, key))?;
            for (i, c) in arr.iter().enumerate() {
                let b: [u8; 32] = c.as_str().and_then(unhex).and_then(|v| v.try_into().ok()).ok_or(format!("{}: bad entry", PUBLIC_FILE))?;
                w.lists[acct as usize].push(b);
                w.by_commitment.insert(b, (acct, i as u32));
            }
            let n = j.get(&format!("next_{}", key)).and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            w.next[acct as usize] = n.min(w.lists[acct as usize].len() as u32);
        }
        Ok(w)
    }

    pub fn exists(&self) -> bool {
        !self.lists[0].is_empty()
    }

    fn require(&self) -> Result<(), String> {
        if self.exists() {
            Ok(())
        } else {
            Err("this node has no wallet: create one with `varve wallet create` (then restart the node), or mine to an address with --mine-to".into())
        }
    }

    /// Create a new wallet (fresh 24 words, or `words` to restore). Writes the encrypted
    /// file and the public file. Returns the recovery phrase to show once.
    pub fn create(dir: &Path, file_pass: &str, words: Option<&str>) -> Result<String, String> {
        check_passphrase(file_pass)?;
        if dir.join(ENCRYPTED_FILE).exists() || dir.join(PUBLIC_FILE).exists() {
            return Err(format!("a wallet already exists in {}", dir.display()));
        }
        if dir.join(LEGACY_FILE).exists() {
            return Err(format!("move the old unencrypted {} out of {} first", LEGACY_FILE, dir.display()));
        }
        let w = match words {
            Some(m) => varve_wallet::Wallet::from_mnemonic(m, None).map_err(|e| e.to_string())?,
            None => varve_wallet::Wallet::generate(),
        };
        let phrase = w.mnemonic().expose().to_string();
        w.save_to_path(&dir.join(ENCRYPTED_FILE), file_pass).map_err(|e| e.to_string())?;
        let mut pubw = Wallet { dir: dir.to_path_buf(), lists: [Vec::new(), Vec::new()], by_commitment: HashMap::new(), next: [0, 0], unlocked: None };
        pubw.extend_from(&w, LOOKAHEAD)?;
        pubw.save_public()?;
        Ok(phrase)
    }

    /// Rebuild the public file from the encrypted one (if it was lost or damaged).
    pub fn repair(dir: &Path, file_pass: &str) -> Result<(), String> {
        let w = varve_wallet::Wallet::load_from_path(&dir.join(ENCRYPTED_FILE), file_pass).map_err(|e| e.to_string())?;
        let mut pubw = Wallet { dir: dir.to_path_buf(), lists: [Vec::new(), Vec::new()], by_commitment: HashMap::new(), next: [0, 0], unlocked: None };
        pubw.extend_from(&w, LOOKAHEAD)?;
        pubw.save_public()
    }

    /// The recovery phrase, after checking the passphrase.
    pub fn phrase(dir: &Path, file_pass: &str) -> Result<String, String> {
        let w = varve_wallet::Wallet::load_from_path(&dir.join(ENCRYPTED_FILE), file_pass).map_err(|e| e.to_string())?;
        Ok(w.mnemonic().expose().to_string())
    }

    fn extend_from(&mut self, w: &varve_wallet::Wallet, to: u32) -> Result<(), String> {
        for acct in [RECEIVE, CHANGE] {
            while (self.lists[acct as usize].len() as u32) < to {
                let i = self.lists[acct as usize].len() as u32;
                let c = derive_commitment(w, acct, i)?;
                self.lists[acct as usize].push(c);
                self.by_commitment.insert(c, (acct, i));
            }
        }
        Ok(())
    }

    fn save_public(&self) -> Result<(), String> {
        let list = |a: usize| Json::Arr(self.lists[a].iter().map(|c| Json::str(hex(c))).collect());
        let doc = Json::obj(vec![
            ("format", Json::str(PUBLIC_FORMAT)),
            ("note", Json::str("Public key commitments of this node's wallet. No secrets. The keys are in wallet.strata.json, encrypted.")),
            ("receive", list(0)),
            ("change", list(1)),
            ("next_receive", Json::num(self.next[0])),
            ("next_change", Json::num(self.next[1])),
        ]);
        let path = self.dir.join(PUBLIC_FILE);
        let tmp = path.with_extension("json.tmp");
        write_private(&tmp, doc.to_string().as_bytes())?;
        varve_wallet::util::rename_with_retry(&tmp, &path).map_err(|e| e.to_string())
    }

    // ---------------------------------------------------------------- lock / unlock

    /// Decrypt the keys for `secs` seconds (1..=3600). Also checks that the public file
    /// really belongs to these keys, so a tampered public file cannot redirect coins.
    pub fn unlock(&mut self, file_pass: &str, secs: u64) -> Result<(), String> {
        self.require()?;
        let w = varve_wallet::Wallet::load_from_path(&self.dir.join(ENCRYPTED_FILE), file_pass).map_err(|e| match e {
            varve_wallet::WalletError::Auth => "wrong passphrase".to_string(),
            e => e.to_string(),
        })?;
        for acct in [RECEIVE, CHANGE] {
            let n = self.lists[acct as usize].len() as u32;
            let check: Vec<u32> = (0..n.min(8)).chain([n.saturating_sub(1), self.next[acct as usize].min(n.saturating_sub(1))]).collect();
            for i in check {
                if derive_commitment(&w, acct, i)? != self.lists[acct as usize][i as usize] {
                    return Err(format!("{} does not match the encrypted wallet (was it modified?); run `varve wallet repair`", PUBLIC_FILE));
                }
            }
        }
        self.unlocked = Some((w, Instant::now() + Duration::from_secs(secs.clamp(1, MAX_UNLOCK_SECS))));
        Ok(())
    }

    /// Drop the decrypted keys (the library wipes them).
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    /// Lock if the unlock period has ended. Called regularly by the node.
    pub fn expire(&mut self) {
        if matches!(&self.unlocked, Some((_, until)) if Instant::now() >= *until) {
            self.unlocked = None;
        }
    }

    pub fn unlocked_secs(&self) -> u64 {
        self.unlocked.as_ref().map(|(_, until)| until.saturating_duration_since(Instant::now()).as_secs()).unwrap_or(0)
    }

    // ---------------------------------------------------------------- addresses

    pub fn output_for(&self, account: u32, index: u32) -> Output {
        Output::single(0, SCHEME_ML_DSA_65, self.lists[account as usize][index as usize])
    }

    /// The address miners pay to by default: receive address 0.
    pub fn mining_output(&self) -> Result<Output, String> {
        self.require()?;
        Ok(self.output_for(RECEIVE, 0))
    }

    pub fn address(&self, hrp: &str, account: u32, index: u32) -> String {
        address::encode(hrp, &self.output_for(account, index))
    }

    /// Next unused address of an account. Uses the public list; when it runs out, the
    /// wallet must be unlocked to derive more.
    fn next_of(&mut self, acct: u32) -> Result<u32, String> {
        self.require()?;
        let a = acct as usize;
        if self.next[a] as usize >= self.lists[a].len() {
            let more = self.lists[a].len() as u32 + LOOKAHEAD;
            match self.unlocked.take() {
                Some((w, until)) => {
                    let r = self.extend_from(&w, more);
                    self.unlocked = Some((w, until));
                    r?;
                }
                None => return Err("all prepared addresses are used: unlock the wallet once (walletpassphrase) to prepare more".into()),
            }
        }
        let i = self.next[a];
        self.next[a] += 1;
        self.save_public()?;
        Ok(i)
    }

    pub fn new_receive(&mut self) -> Result<u32, String> {
        self.next_of(RECEIVE)
    }

    pub fn addresses_used(&self, hrp: &str) -> Vec<String> {
        (0..self.next[0].max(1).min(self.lists[0].len() as u32)).map(|i| self.address(hrp, RECEIVE, i)).collect()
    }

    pub fn is_mine(&self, o: &Output) -> bool {
        o.recovery.is_none() && o.scheme_id == SCHEME_ML_DSA_65 && self.by_commitment.contains_key(&o.commitment)
    }

    /// Our coins in a UTXO set, skipping outpoints in `exclude` (spent by the mempool).
    pub fn coins(&self, utxo: &HashMap<OutPoint, Coin>, exclude: &dyn Fn(&OutPoint) -> bool) -> Vec<(OutPoint, Coin)> {
        let mut v: Vec<(OutPoint, Coin)> = utxo.iter().filter(|(op, c)| self.is_mine(&c.output) && !exclude(op)).map(|(o, c)| (o.clone(), c.clone())).collect();
        v.sort_by(|a, b| a.1.height.cmp(&b.1.height).then(a.0.cmp(&b.0)));
        v
    }

    pub fn balance(&self, utxo: &HashMap<OutPoint, Coin>, tip_height: u64, exclude: &dyn Fn(&OutPoint) -> bool) -> Balance {
        let mut b = Balance::default();
        for (_, c) in self.coins(utxo, exclude) {
            b.utxos += 1;
            if c.coinbase && tip_height + 1 < c.height + COINBASE_MATURITY {
                b.immature += c.output.amount;
            } else {
                b.spendable += c.output.amount;
            }
        }
        b
    }

    // ---------------------------------------------------------------- payments

    /// Build and sign a payment (the wallet must be unlocked). `feerate` in laminae per
    /// weight unit.
    pub fn create_payment(&mut self, coins: Vec<(OutPoint, Coin)>, to: Output, amount: u64, feerate: u64, next_height: u64, ids: &ChainIds) -> Result<Tx, String> {
        self.require()?;
        self.expire();
        if self.unlocked.is_none() {
            return Err("the wallet is locked: unlock it first (`varve wallet send` asks for the passphrase)".into());
        }
        if amount == 0 || amount > varve_consensus::params::MAX_MONEY {
            return Err("amount out of range".into());
        }
        if feerate > 1_000_000 {
            return Err("feerate too high (max 1,000,000 laminae per weight unit)".into());
        }
        let spendable: Vec<(OutPoint, Coin)> = coins.into_iter().filter(|(_, c)| !(c.coinbase && next_height < c.height + COINBASE_MATURITY)).collect();
        let change_i = self.next_of(CHANGE)?;
        let change_out = self.output_for(CHANGE, change_i);
        let mut chosen: Vec<(OutPoint, Coin)> = Vec::new();
        let mut total = 0u64;
        for c in spendable {
            if chosen.len() >= 200 {
                break;
            }
            total = total.saturating_add(c.1.output.amount);
            chosen.push(c);
            let fee = estimate_fee(&chosen, &to, amount, &change_out, feerate);
            if total >= amount.saturating_add(fee) {
                let change = total - amount - fee;
                let mut dest = to.clone();
                dest.amount = amount;
                let mut outputs = vec![dest];
                // drop dust change (it would cost more than it is worth); it becomes fee
                if change > 2_000u64.saturating_mul(feerate.max(1)) {
                    let mut ch = change_out.clone();
                    ch.amount = change;
                    outputs.push(ch);
                }
                return self.sign(chosen, outputs, ids);
            }
        }
        Err(format!("insufficient spendable funds: have {} laminae", total))
    }

    fn sign(&self, chosen: Vec<(OutPoint, Coin)>, outputs: Vec<Output>, ids: &ChainIds) -> Result<Tx, String> {
        let (w, _) = self.unlocked.as_ref().ok_or("the wallet is locked")?;
        let mut tx = Tx { version: 1, inputs: chosen.iter().map(|c| c.0.clone()).collect(), outputs, locktime: 0, witnesses: Vec::new() };
        let spent: Vec<Output> = chosen.iter().map(|c| c.1.output.clone()).collect();
        let plan = shared_plan(&chosen);
        for (i, (_, c)) in chosen.iter().enumerate() {
            if plan[i] {
                // transactions.md §8.2: an earlier input already signed for this key
                tx.witnesses.push(Witness { path: 2, public_key: vec![], signature: vec![] });
                continue;
            }
            let &(acct, idx) = self.by_commitment.get(&c.output.commitment).ok_or("not our coin")?;
            let kp = w.derive(Role::Primary, Scheme::MlDsa65, acct, idx).map_err(|e| e.to_string())?;
            if kp.commitment != c.output.commitment {
                return Err("wallet key does not match the coin".into());
            }
            let msg = sighash(&ids.network_id, &ids.genesis_id, &tx, i as u32, &spent, 0);
            let sig = kp.sign(&msg).map_err(|e| e.to_string())?;
            tx.witnesses.push(Witness { path: 0, public_key: kp.pk.clone(), signature: sig });
        }
        Ok(tx)
    }
}

fn estimate_fee(chosen: &[(OutPoint, Coin)], to: &Output, amount: u64, change: &Output, feerate: u64) -> u64 {
    // signatures have fixed length, so a dummy of the right size gives the exact weight
    let mut dest = to.clone();
    dest.amount = amount.max(1);
    let mut ch = change.clone();
    ch.amount = 1;
    let tx = Tx {
        version: 1,
        inputs: chosen.iter().map(|c| c.0.clone()).collect(),
        outputs: vec![dest, ch],
        locktime: 0,
        witnesses: chosen
            .iter()
            .zip(shared_plan(chosen))
            .map(|(c, shared)| {
                if shared {
                    return Witness { path: 2, public_key: vec![], signature: vec![] };
                }
                let s = scheme(c.1.output.scheme_id, 0).unwrap();
                Witness { path: 0, public_key: vec![0u8; s.pk_len], signature: vec![0u8; s.sig_len] }
            })
            .collect(),
    };
    tx.weight(false).saturating_mul(feerate.max(1))
}

/// For each chosen coin: true if an earlier coin has the same (scheme, commitment), so
/// this input can use the shared witness (path 2) instead of a second signature.
fn shared_plan(chosen: &[(OutPoint, Coin)]) -> Vec<bool> {
    let mut seen: Vec<(u16, [u8; 32])> = Vec::new();
    chosen
        .iter()
        .map(|(_, c)| {
            let k = (c.output.scheme_id, c.output.commitment);
            if seen.contains(&k) {
                true
            } else {
                seen.push(k);
                false
            }
        })
        .collect()
}

/// Write a file readable only by its owner (on Unix).
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    f.write_all(data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("varve-wallet-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn encrypted_wallet_lifecycle() {
        let d = tmp("life");
        assert!(!Wallet::open(&d).unwrap().exists());
        assert!(Wallet::create(&d, "short", None).is_err(), "weak passphrase refused");
        let words = Wallet::create(&d, "correct horse battery", None).unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        // nothing secret in clear on disk: the public file is hex commitments only, and the
        // encrypted file is the strata-wallet-v1 container (hex ciphertext, no words)
        let pubtext = std::fs::read_to_string(d.join(PUBLIC_FILE)).unwrap();
        let enc = std::fs::read_to_string(d.join(ENCRYPTED_FILE)).unwrap();
        assert!(enc.contains("\"strata-wallet-v1\""));
        let is_hex = |w: &str| w.bytes().all(|c| c.is_ascii_hexdigit());
        for word in words.split_whitespace().filter(|w| w.len() >= 5 && !is_hex(w)) {
            assert!(!enc.contains(word), "recovery word in the encrypted file");
        }
        let pj = Json::parse(&pubtext).unwrap();
        for k in ["receive", "change"] {
            assert!(pj.at(k).as_arr().unwrap().iter().all(|c| c.as_str().map(|x| x.len() == 64 && is_hex(x)).unwrap_or(false)));
        }
        let mut w = Wallet::open(&d).unwrap();
        assert!(w.exists());
        assert!(w.unlock("wrong passphrase!", 10).is_err());
        w.unlock("correct horse battery", 10).unwrap();
        assert!(w.unlocked_secs() > 0);
        w.lock();
        assert_eq!(w.unlocked_secs(), 0);
        // same words, same addresses (and the same as Strata's derivation)
        let d2 = tmp("restore");
        Wallet::create(&d2, "another passphrase", Some(&words)).unwrap();
        let w2 = Wallet::open(&d2).unwrap();
        assert_eq!(w.address("tvarve", 0, 0), w2.address("tvarve", 0, 0));
        let ref_w = varve_wallet::Wallet::from_mnemonic(&words, None).unwrap();
        assert_eq!(w.address("tvarve", 0, 3), ref_w.derive(Role::Primary, Scheme::MlDsa65, 0, 3).unwrap().address("tvarve").unwrap());
        assert!(Wallet::create(&d, "correct horse battery", None).is_err(), "never overwrites");
    }

    #[test]
    fn tampered_public_file_is_detected() {
        let d = tmp("tamper");
        Wallet::create(&d, "correct horse battery", None).unwrap();
        let p = d.join(PUBLIC_FILE);
        let text = std::fs::read_to_string(&p).unwrap();
        let j = Json::parse(&text).unwrap();
        let first = j.at("receive").idx(0).unwrap().as_str().unwrap().to_string();
        std::fs::write(&p, text.replacen(&first, &"ab".repeat(32), 1)).unwrap();
        let mut w = Wallet::open(&d).unwrap();
        assert!(w.unlock("correct horse battery", 10).unwrap_err().contains("does not match"));
        Wallet::repair(&d, "correct horse battery").unwrap();
        let mut w = Wallet::open(&d).unwrap();
        w.unlock("correct horse battery", 10).unwrap();
    }

    #[test]
    fn legacy_plaintext_wallet_is_refused() {
        let d = tmp("legacy");
        std::fs::write(d.join(LEGACY_FILE), "{}").unwrap();
        assert!(Wallet::open(&d).unwrap_err().contains("unencrypted"));
    }
}
