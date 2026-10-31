//! Minimal wallet (ADR-0011): random ML-DSA-65 keys, single-policy addresses, balance,
//! and payments. TESTNET ONLY: keys are stored unencrypted in `wallet.json` (mode 0600).
//! Seeded derivation (protocol/wallet.md) is future work.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use varve_consensus::encoding::{hex, unhex};
use varve_consensus::json::Json;
use varve_consensus::params::{scheme, COINBASE_MATURITY, SCHEME_ML_DSA_65};
use varve_consensus::tx::{commitment, sighash, OutPoint, Output, Tx, Witness};
use varve_consensus::validate::{ChainIds, Coin};

use crate::address;

pub struct Key {
    pub scheme_id: u16,
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
    pub commitment: [u8; 32],
}

pub struct Wallet {
    path: PathBuf,
    pub keys: Vec<Key>,
    by_commitment: HashMap<[u8; 32], usize>,
}

#[derive(Debug, Default)]
pub struct Balance {
    pub spendable: u64,
    pub immature: u64,
    pub utxos: usize,
}

impl Wallet {
    pub fn open_or_create(dir: &Path) -> Result<Wallet, String> {
        let path = dir.join("wallet.json");
        let mut w = Wallet { path: path.clone(), keys: Vec::new(), by_commitment: HashMap::new() };
        if path.exists() {
            let j = Json::parse(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)?;
            for k in j.get("keys").and_then(|k| k.as_arr()).ok_or("wallet.json: no keys")? {
                let sid = k.get("scheme_id").and_then(|x| x.as_u64()).ok_or("scheme_id")? as u16;
                let pk = unhex(k.get("public_key").and_then(|x| x.as_str()).ok_or("public_key")?).ok_or("hex")?;
                let sk = unhex(k.get("secret_key").and_then(|x| x.as_str()).ok_or("secret_key")?).ok_or("hex")?;
                w.push(Key { scheme_id: sid, commitment: commitment(sid, &pk), public_key: pk, secret_key: sk });
            }
        } else {
            w.new_key()?;
        }
        Ok(w)
    }

    fn push(&mut self, k: Key) {
        self.by_commitment.insert(k.commitment, self.keys.len());
        self.keys.push(k);
    }

    fn save(&self) -> Result<(), String> {
        let keys: Vec<Json> = self
            .keys
            .iter()
            .map(|k| {
                Json::obj(vec![
                    ("scheme_id", Json::num(k.scheme_id)),
                    ("public_key", Json::str(hex(&k.public_key))),
                    ("secret_key", Json::str(hex(&k.secret_key))),
                ])
            })
            .collect();
        let doc = Json::obj(vec![
            ("warning", Json::str("TESTNET WALLET. Secret keys are NOT encrypted. Never share this file.")),
            ("keys", Json::Arr(keys)),
        ]);
        let tmp = self.path.with_extension("json.tmp");
        write_private(&tmp, doc.to_string().as_bytes())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    /// New ML-DSA-65 key; returns its index.
    pub fn new_key(&mut self) -> Result<usize, String> {
        let (pk, sk) = varve_sys::keypair(varve_sys::Scheme::MlDsa65).map_err(|e| e.to_string())?;
        self.push(Key { scheme_id: SCHEME_ML_DSA_65, commitment: commitment(SCHEME_ML_DSA_65, &pk), public_key: pk, secret_key: sk });
        self.save()?;
        Ok(self.keys.len() - 1)
    }

    pub fn output_for(&self, i: usize) -> Output {
        Output::single(0, self.keys[i].scheme_id, self.keys[i].commitment)
    }

    pub fn address(&self, hrp: &str, i: usize) -> String {
        address::encode(hrp, &self.output_for(i))
    }

    pub fn is_mine(&self, o: &Output) -> bool {
        o.recovery.is_none() && self.by_commitment.get(&o.commitment).map(|&i| self.keys[i].scheme_id == o.scheme_id).unwrap_or(false)
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

    /// Build and sign a payment. `feerate` in laminae per weight unit.
    pub fn create_payment(
        &mut self,
        coins: Vec<(OutPoint, Coin)>,
        to: Output,
        amount: u64,
        feerate: u64,
        next_height: u64,
        ids: &ChainIds,
    ) -> Result<Tx, String> {
        if amount == 0 || amount > varve_consensus::params::MAX_MONEY {
            return Err("amount out of range".into());
        }
        if feerate > 1_000_000 {
            return Err("feerate too high (max 1,000,000 laminae per weight unit)".into());
        }
        let spendable: Vec<(OutPoint, Coin)> =
            coins.into_iter().filter(|(_, c)| !(c.coinbase && next_height < c.height + COINBASE_MATURITY)).collect();
        let change_idx = self.new_key()?;
        let mut chosen: Vec<(OutPoint, Coin)> = Vec::new();
        let mut total = 0u64;
        for c in spendable {
            if chosen.len() >= 200 {
                break;
            }
            total = total.saturating_add(c.1.output.amount);
            chosen.push(c);
            let fee = self.estimate_fee(&chosen, &to, amount, change_idx, feerate);
            if total >= amount.saturating_add(fee) {
                let change = total - amount - fee;
                let mut dest = to.clone();
                dest.amount = amount;
                let mut outputs = vec![dest];
                // drop dust change (it would cost more than it is worth); it becomes fee
                if change > 2_000u64.saturating_mul(feerate.max(1)) {
                    let mut ch = self.output_for(change_idx);
                    ch.amount = change;
                    outputs.push(ch);
                }
                return self.sign(chosen, outputs, ids);
            }
        }
        Err(format!("insufficient spendable funds: have {} laminae", total))
    }

    fn estimate_fee(&self, chosen: &[(OutPoint, Coin)], to: &Output, amount: u64, change_idx: usize, feerate: u64) -> u64 {
        // signatures have fixed length, so a dummy of the right size gives the exact weight
        let mut dest = to.clone();
        dest.amount = amount.max(1);
        let mut ch = self.output_for(change_idx);
        ch.amount = 1;
        let tx = Tx {
            version: 1,
            inputs: chosen.iter().map(|c| c.0.clone()).collect(),
            outputs: vec![dest, ch],
            locktime: 0,
            witnesses: chosen
                .iter()
                .map(|c| {
                    let s = scheme(c.1.output.scheme_id, 0).unwrap();
                    Witness { path: 0, public_key: vec![0u8; s.pk_len], signature: vec![0u8; s.sig_len] }
                })
                .collect(),
        };
        tx.weight(false).saturating_mul(feerate.max(1))
    }

    fn sign(&self, chosen: Vec<(OutPoint, Coin)>, outputs: Vec<Output>, ids: &ChainIds) -> Result<Tx, String> {
        let mut tx = Tx { version: 1, inputs: chosen.iter().map(|c| c.0.clone()).collect(), outputs, locktime: 0, witnesses: Vec::new() };
        let spent: Vec<Output> = chosen.iter().map(|c| c.1.output.clone()).collect();
        for (i, (_, c)) in chosen.iter().enumerate() {
            let k = &self.keys[*self.by_commitment.get(&c.output.commitment).ok_or("not our coin")?];
            let s = scheme(k.scheme_id, 0).ok_or("unknown scheme")?;
            let msg = sighash(&ids.network_id, &ids.genesis_id, &tx, i as u32, &spent, 0);
            let sig = varve_sys::sign(s.sys, &k.secret_key, &msg).map_err(|e| e.to_string())?;
            tx.witnesses.push(Witness { path: 0, public_key: k.public_key.clone(), signature: sig });
        }
        Ok(tx)
    }
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
