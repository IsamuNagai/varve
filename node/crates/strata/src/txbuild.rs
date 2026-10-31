//! Payment construction: parse the node API's coins, prove each one belongs to this
//! wallet, select coins, compute the exact weight and fee, sign (path 0 for the first
//! input of each key, path 2 for the rest, transactions.md §8.2), and check the result
//! with the consensus rules before anything leaves the process.

use std::collections::{BTreeMap, HashMap};

use varve_consensus::encoding::{hex, unhex, Reader};
use varve_consensus::json::Json;
use varve_consensus::params::{scheme, COINBASE_MATURITY, MAX_MONEY};
use varve_consensus::tx::{sighash, OutPoint, Output, Tx, Witness};
use varve_consensus::validate::{check_transaction, ChainIds, Coin};
use varve_wallet::{KeyPair, Role, Scheme, Wallet};

/// Node relay policy limit (node/crates/varve/src/mempool.rs MAX_STANDARD_TX_WEIGHT).
pub const MAX_STANDARD_TX_WEIGHT: u64 = 100_000;
pub const MAX_FEERATE: u64 = 1_000_000;
/// Change below DUST_WEIGHT × feerate is not worth an output; it goes to the fee.
pub const DUST_WEIGHT: u64 = 2_000;
/// Sanity cap: refuse fees above 5% of the amount AND above 0.5 VARV unless allowed.
pub const HIGH_FEE_ABS: u64 = 50_000_000;
pub const MAX_UTXOS: usize = 5_000;

/// Receive keys use account 0 and change keys account 1 (role primary, ML-DSA-65).
pub const RECEIVE_ACCOUNT: u32 = 0;
pub const CHANGE_ACCOUNT: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyPath {
    pub account: u32,
    pub index: u32,
}

impl KeyPath {
    pub fn receive(index: u32) -> KeyPath {
        KeyPath { account: RECEIVE_ACCOUNT, index }
    }
    pub fn change(index: u32) -> KeyPath {
        KeyPath { account: CHANGE_ACCOUNT, index }
    }
    pub fn derive(&self, w: &Wallet) -> Result<KeyPair, String> {
        w.derive(Role::Primary, Scheme::MlDsa65, self.account, self.index).map_err(|_| "key derivation failed".to_string())
    }
}

/// A coin as reported by `GET /api/v1/address/<a>/utxos`.
#[derive(Clone, Debug)]
pub struct ApiUtxo {
    pub outpoint: OutPoint,
    pub amount: u64,
    /// None for a coin created by a mempool transaction
    pub height: Option<u64>,
    pub coinbase: bool,
    pub mature: bool,
    pub spent_in_mempool: bool,
    pub output_bytes: Vec<u8>,
    pub output: Output,
}

pub fn parse_amount(s: &str) -> Result<u64, String> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return Err("amount must be a whole number of laminae".into());
    }
    let v: u64 = s.parse().map_err(|_| "amount out of range".to_string())?;
    if v > MAX_MONEY {
        return Err("amount out of range".into());
    }
    Ok(v)
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    unhex(s)?.try_into().ok()
}

/// Strictly parse one API coin object. Messages never contain the input.
pub fn parse_utxo(j: &Json) -> Result<ApiUtxo, String> {
    let bad = |f: &str| format!("coin data from the node is invalid ({})", f);
    let txid = j.get("txid").and_then(|v| v.as_str()).and_then(hex32).ok_or_else(|| bad("txid"))?;
    let index = j.get("index").and_then(|v| v.as_u64()).filter(|v| *v <= u32::MAX as u64).ok_or_else(|| bad("index"))? as u32;
    let amount = j.get("amount").and_then(|v| v.as_str()).ok_or_else(|| bad("amount")).and_then(|s| parse_amount(s).map_err(|_| bad("amount")))?;
    if amount == 0 {
        return Err(bad("amount"));
    }
    let height = match j.get("height") {
        None | Some(Json::Null) => None,
        Some(v) => Some(v.as_u64().ok_or_else(|| bad("height"))?),
    };
    let flag = |k: &str| j.get(k).and_then(|v| v.as_bool()).ok_or_else(|| bad(k));
    let coinbase = flag("coinbase")?;
    let mature = flag("mature")?;
    let spent_in_mempool = flag("spent_in_mempool")?;
    let oh = j.get("output").and_then(|v| v.as_str()).ok_or_else(|| bad("output"))?;
    if oh.len() > 200 || !oh.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(bad("output"));
    }
    let output_bytes = unhex(oh).ok_or_else(|| bad("output"))?;
    let mut r = Reader::new(&output_bytes);
    let output = Output::parse(&mut r).map_err(|_| bad("output"))?;
    r.finish().map_err(|_| bad("output"))?;
    Ok(ApiUtxo { outpoint: OutPoint { txid, index }, amount, height, coinbase, mature, spent_in_mempool, output_bytes, output })
}

/// Check that a coin pays one of this wallet's keys: find the key by commitment in the
/// address window, re-derive it, and compare the full serialized output (amount and
/// template) byte for byte against what the API sent.
pub fn check_owned(u: &ApiUtxo, w: &Wallet, window: &HashMap<[u8; 32], KeyPath>) -> Result<(KeyPath, KeyPair), String> {
    if u.output.amount != u.amount {
        return Err("a coin's amount does not match its output data; refusing to sign".into());
    }
    let path = *window.get(&u.output.commitment).ok_or("a coin does not belong to this wallet; refusing to sign")?;
    let key = path.derive(w)?;
    let expected = key.output(u.amount).serialize();
    if expected != u.output_bytes {
        return Err("a coin does not belong to this wallet; refusing to sign".into());
    }
    Ok((path, key))
}

/// Is the coin spendable in a block at `next_height`?
pub fn spendable(u: &ApiUtxo, next_height: u64) -> bool {
    if u.spent_in_mempool || !u.mature {
        return false;
    }
    if u.coinbase {
        match u.height {
            Some(h) => next_height >= h.saturating_add(COINBASE_MATURITY),
            None => false,
        }
    } else {
        true
    }
}

/// One spendable coin for selection: its position in the caller's list and its key.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub pos: usize,
    pub outpoint: OutPoint,
    pub key: KeyPath,
    pub scheme_id: u16,
    pub commitment: [u8; 32],
    pub amount: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Selection {
    /// candidate positions in input order (same-key coins adjacent)
    pub inputs: Vec<usize>,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub total_in: u64,
    pub weight: u64,
}

/// Dummy witnesses of the exact lengths give the exact weight (signature lengths are fixed).
pub fn weight_of(inputs: &[&Candidate], outputs: &[Output]) -> u64 {
    let mut seen: Vec<(u16, [u8; 32])> = Vec::new();
    let witnesses = inputs
        .iter()
        .map(|c| {
            let k = (c.scheme_id, c.commitment);
            if seen.contains(&k) {
                Witness { path: 2, public_key: vec![], signature: vec![] }
            } else {
                seen.push(k);
                let s = scheme(c.scheme_id, 0).expect("known scheme");
                Witness { path: 0, public_key: vec![0u8; s.pk_len], signature: vec![0u8; s.sig_len] }
            }
        })
        .collect();
    let tx = Tx { version: 1, inputs: inputs.iter().map(|c| c.outpoint.clone()).collect(), outputs: outputs.to_vec(), locktime: 0, witnesses };
    tx.weight(false)
}

/// Amount: Some(n) pays exactly n; None sends everything (no change).
pub fn select(cands: &[Candidate], dest: &Output, change_out: &Output, amount: Option<u64>, feerate: u64) -> Result<Selection, String> {
    if !(1..=MAX_FEERATE).contains(&feerate) {
        return Err("fee rate out of range".into());
    }
    // group by key; each group is spent completely (one signature covers every coin of
    // the key via path 2, and a key whose public key is revealed should not keep coins)
    let mut groups: BTreeMap<KeyPath, Vec<&Candidate>> = BTreeMap::new();
    for c in cands {
        groups.entry(c.key).or_default().push(c);
    }
    let mut groups: Vec<(u64, Vec<&Candidate>)> = groups
        .into_values()
        .map(|mut g| {
            g.sort_by(|a, b| a.outpoint.cmp(&b.outpoint));
            (g.iter().fold(0u64, |s, c| s.saturating_add(c.amount)), g)
        })
        .collect();
    let have = groups.iter().fold(0u64, |s, g| s.saturating_add(g.0));
    let fee_for = |w: u64| w.checked_mul(feerate).ok_or_else(|| "fee overflow".to_string());
    let mut dest = dest.clone();
    let mut change_out = change_out.clone();

    let finish = |chosen: &[&Candidate], dest: &mut Output, change_out: &mut Output| -> Result<Option<Selection>, String> {
        let total: u64 = chosen.iter().try_fold(0u64, |s, c| s.checked_add(c.amount)).filter(|s| *s <= MAX_MONEY).ok_or("input sum overflow")?;
        let inputs: Vec<usize> = chosen.iter().map(|c| c.pos).collect();
        match amount {
            None => {
                dest.amount = 1;
                let w = weight_of(chosen, std::slice::from_ref(dest));
                let fee = fee_for(w)?;
                if total <= fee {
                    return Ok(None);
                }
                Ok(Some(Selection { inputs, amount: total - fee, fee, change: 0, total_in: total, weight: w }))
            }
            Some(a) => {
                dest.amount = a;
                change_out.amount = 1;
                let w2 = weight_of(chosen, &[dest.clone(), change_out.clone()]);
                let fee2 = fee_for(w2)?;
                if let Some(change) = total.checked_sub(a).and_then(|r| r.checked_sub(fee2)) {
                    if change > DUST_WEIGHT.saturating_mul(feerate) {
                        return Ok(Some(Selection { inputs, amount: a, fee: fee2, change, total_in: total, weight: w2 }));
                    }
                }
                let w1 = weight_of(chosen, std::slice::from_ref(dest));
                let fee1 = fee_for(w1)?;
                if total >= a.saturating_add(fee1) {
                    // the leftover is dust: it becomes part of the fee
                    return Ok(Some(Selection { inputs, amount: a, fee: total - a, change: 0, total_in: total, weight: w1 }));
                }
                Ok(None)
            }
        }
    };
    let too_big = |s: &Selection| s.weight > MAX_STANDARD_TX_WEIGHT;

    if groups.is_empty() {
        return Err("no spendable coins".into());
    }
    if amount.is_none() {
        groups.sort_by(|a, b| b.0.cmp(&a.0));
        let all: Vec<&Candidate> = groups.iter().flat_map(|g| g.1.iter().copied()).collect();
        return match finish(&all, &mut dest, &mut change_out)? {
            Some(s) if too_big(&s) => Err("too many coins to send in one transaction; send a smaller amount first".into()),
            Some(s) => Ok(s),
            None => Err("the balance does not cover the fee".into()),
        };
    }
    // 1. the smallest single key that covers the payment
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    for g in &groups {
        if let Some(s) = finish(&g.1, &mut dest, &mut change_out)? {
            if !too_big(&s) {
                return Ok(s);
            }
        }
    }
    // 2. otherwise the largest keys first, until the payment is covered
    groups.sort_by(|a, b| b.0.cmp(&a.0));
    let mut chosen: Vec<&Candidate> = Vec::new();
    for g in &groups {
        chosen.extend(g.1.iter().copied());
        if let Some(s) = finish(&chosen, &mut dest, &mut change_out)? {
            if too_big(&s) {
                return Err("this payment needs too many coins for one transaction; send a smaller amount".into());
            }
            return Ok(s);
        }
    }
    Err(format!("insufficient funds: spendable {} laminae", have))
}

pub struct BuildRequest<'a> {
    pub to: &'a Output,
    /// None = send the whole spendable balance
    pub amount: Option<u64>,
    pub feerate: u64,
    pub utxos: &'a [ApiUtxo],
    pub api_height: u64,
    pub allow_high_fee: bool,
    pub change_key: &'a KeyPair,
}

#[derive(Debug)]
pub struct Built {
    pub tx: Tx,
    pub fee: u64,
    pub total_in: u64,
    pub change: u64,
    pub weight: u64,
    pub amount: u64,
}

pub fn high_fee(fee: u64, amount: u64) -> bool {
    (fee as u128) * 100 > (amount as u128) * 5 && fee > HIGH_FEE_ABS
}

/// Build, sign and check a payment.
pub fn build(w: &Wallet, window: &HashMap<[u8; 32], KeyPath>, ids: &ChainIds, req: &BuildRequest) -> Result<Built, String> {
    if req.utxos.len() > MAX_UTXOS {
        return Err("too many coins in the request".into());
    }
    if let Some(a) = req.amount {
        if a == 0 || a > MAX_MONEY {
            return Err("amount out of range".into());
        }
    }
    let next_height = req.api_height.checked_add(1).ok_or("height out of range")?;
    // ownership of EVERY supplied coin is checked, spendable or not
    let mut keys: HashMap<KeyPath, KeyPair> = HashMap::new();
    let mut cands = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (pos, u) in req.utxos.iter().enumerate() {
        if !seen.insert(u.outpoint.clone()) {
            return Err("duplicate coin in the request".into());
        }
        let (path, key) = check_owned(u, w, window)?;
        if !spendable(u, next_height) {
            continue;
        }
        cands.push(Candidate { pos, outpoint: u.outpoint.clone(), key: path, scheme_id: key.scheme_id(), commitment: key.commitment, amount: u.amount });
        keys.entry(path).or_insert(key);
    }
    let change_out = req.change_key.output(0);
    let sel = select(&cands, req.to, &change_out, req.amount, req.feerate)?;
    if high_fee(sel.fee, sel.amount) && !req.allow_high_fee {
        return Err(format!("the fee ({} laminae) is unusually high for this amount; confirm to send anyway", sel.fee));
    }
    let mut dest = req.to.clone();
    dest.amount = sel.amount;
    let mut outputs = vec![dest];
    if sel.change > 0 {
        outputs.push(req.change_key.output(sel.change));
    }
    let chosen: Vec<&Candidate> = sel.inputs.iter().map(|p| cands.iter().find(|c| c.pos == *p).unwrap()).collect();
    let spent: Vec<Output> = chosen.iter().map(|c| req.utxos[c.pos].output.clone()).collect();
    let mut tx = Tx { version: 1, inputs: chosen.iter().map(|c| c.outpoint.clone()).collect(), outputs, locktime: 0, witnesses: Vec::new() };
    let mut signed: Vec<KeyPath> = Vec::new();
    for (i, c) in chosen.iter().enumerate() {
        if signed.contains(&c.key) {
            // §8.2: an earlier input already signed for this key; path 2 is mandatory
            tx.witnesses.push(Witness { path: 2, public_key: vec![], signature: vec![] });
            continue;
        }
        let key = &keys[&c.key];
        let msg = sighash(&ids.network_id, &ids.genesis_id, &tx, i as u32, &spent, 0);
        let sig = key.sign(&msg).map_err(|_| "signing failed".to_string())?;
        tx.witnesses.push(Witness { path: 0, public_key: key.pk.clone(), signature: sig });
        signed.push(c.key);
    }
    let weight = tx.weight(false);
    if weight != sel.weight {
        return Err("internal error: weight estimate mismatch".into());
    }
    // consensus check against the supplied coins, as if mined in the next block
    let view: HashMap<OutPoint, Coin> = chosen
        .iter()
        .map(|c| {
            let u = &req.utxos[c.pos];
            (u.outpoint.clone(), Coin { output: u.output.clone(), height: u.height.unwrap_or(next_height), coinbase: u.coinbase })
        })
        .collect();
    let (fee, _) = check_transaction(&tx, next_height, ids, &view, true).map_err(|e| format!("built transaction failed validation: {}", e))?;
    if fee != sel.fee {
        return Err("internal error: fee mismatch".into());
    }
    Ok(Built { tx, fee, total_in: sel.total_in, change: sel.change, weight, amount: sel.amount })
}

pub fn txid_hex(tx: &Tx) -> String {
    hex(&tx.txid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use varve_consensus::params::Network;

    fn ids() -> ChainIds {
        ChainIds { network_id: *b"RVAR", genesis_id: [5; 32], lifecycle: vec![] }
    }

    fn window(w: &Wallet, n: u32) -> HashMap<[u8; 32], KeyPath> {
        let mut m = HashMap::new();
        for i in 0..n {
            for p in [KeyPath::receive(i), KeyPath::change(i)] {
                m.insert(p.derive(w).unwrap().commitment, p);
            }
        }
        m
    }

    fn utxo(w: &Wallet, p: KeyPath, amount: u64, tag: u8, height: u64, coinbase: bool) -> ApiUtxo {
        let o = p.derive(w).unwrap().output(amount);
        let mut txid = [tag; 32];
        txid[0] = 0xaa;
        ApiUtxo { outpoint: OutPoint { txid, index: tag as u32 }, amount, height: Some(height), coinbase, mature: true, spent_in_mempool: false, output_bytes: o.serialize(), output: o }
    }

    fn utxo_json(u: &ApiUtxo) -> Json {
        Json::obj(vec![
            ("txid", Json::str(hex(&u.outpoint.txid))),
            ("index", Json::num(u.outpoint.index)),
            ("amount", Json::str(u.amount.to_string())),
            ("height", Json::num(u.height.unwrap())),
            ("coinbase", Json::Bool(u.coinbase)),
            ("mature", Json::Bool(u.mature)),
            ("spent_in_mempool", Json::Bool(u.spent_in_mempool)),
            ("output", Json::str(hex(&u.output_bytes))),
        ])
    }

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("1"), Ok(1));
        assert_eq!(parse_amount(&MAX_MONEY.to_string()), Ok(MAX_MONEY));
        for bad in ["", "01", "-1", "+1", "1.5", "1e3", " 1", "4611686018427387905", "99999999999999999999999"] {
            assert!(parse_amount(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn utxo_parsing_is_strict() {
        let w = Wallet::from_seed(&[1; 32], None).unwrap();
        let u = utxo(&w, KeyPath::receive(0), 1000, 1, 10, false);
        let j = utxo_json(&u);
        let p = parse_utxo(&j).unwrap();
        assert_eq!(p.output, u.output);
        let mut s = j.to_string();
        s = s.replace(&hex(&u.outpoint.txid), &hex(&u.outpoint.txid).to_uppercase());
        assert!(parse_utxo(&Json::parse(&s).unwrap()).is_err());
        let s = j.to_string().replace("\"1000\"", "1000");
        assert!(parse_utxo(&Json::parse(&s).unwrap()).is_err());
        let s = j.to_string().replace(&hex(&u.output_bytes), &(hex(&u.output_bytes) + "00"));
        assert!(parse_utxo(&Json::parse(&s).unwrap()).is_err());
    }

    #[test]
    fn ownership() {
        let w = Wallet::from_seed(&[1; 32], None).unwrap();
        let other = Wallet::from_seed(&[2; 32], None).unwrap();
        let win = window(&w, 5);
        let mine = utxo(&w, KeyPath::receive(3), 5000, 1, 10, false);
        assert_eq!(check_owned(&mine, &w, &win).unwrap().0, KeyPath::receive(3));
        // foreign coin
        let foreign = utxo(&other, KeyPath::receive(3), 5000, 2, 10, false);
        assert!(check_owned(&foreign, &w, &win).is_err());
        // tampered amount: the API claims more than the output says
        let mut t = mine.clone();
        t.amount = 6000;
        assert!(check_owned(&t, &w, &win).is_err());
        // tampered output bytes (amount field) no longer match the re-derived output
        let mut t2 = mine.clone();
        t2.output_bytes[0] ^= 1;
        assert!(check_owned(&t2, &w, &win).is_err());
        // our commitment wrapped in a recovery policy is not ours
        let mut rec = mine.clone();
        rec.output.recovery = Some(varve_consensus::tx::Recovery { scheme_id: 1, commitment: [0; 32], delay: 10 });
        rec.output_bytes = rec.output.serialize();
        assert!(check_owned(&rec, &w, &win).is_err());
        // outside the address window
        let far = utxo(&w, KeyPath::receive(50), 5000, 3, 10, false);
        assert!(check_owned(&far, &w, &win).is_err());
    }

    fn cand(pos: usize, key: u32, amount: u64) -> Candidate {
        Candidate { pos, outpoint: OutPoint { txid: [pos as u8 + 1; 32], index: 0 }, key: KeyPath::receive(key), scheme_id: 1, commitment: [key as u8; 32], amount }
    }

    #[test]
    fn selection() {
        let dest = Output::single(0, 1, [0xdd; 32]);
        let chg = Output::single(0, 1, [0xcc; 32]);
        let fr = 1;
        // key 0: 3 coins of 10k each (30k), key 1: one coin of 100k, key 2: 20k
        let c = vec![cand(0, 0, 10_000_000), cand(1, 1, 100_000_000), cand(2, 0, 10_000_000), cand(3, 2, 20_000_000), cand(4, 0, 10_000_000)];
        // a 25M payment: the smallest single key covering it is key 0 (30M), all 3 coins
        let s = select(&c, &dest, &chg, Some(25_000_000), fr).unwrap();
        let mut ins = s.inputs.clone();
        ins.sort();
        assert_eq!(ins, vec![0, 2, 4]);
        assert_eq!(s.total_in, 30_000_000);
        assert_eq!(s.total_in, s.amount + s.fee + s.change);
        // weight: one full witness and two 3-byte shared entries; with 3 inputs and 2
        // outputs there is no UTXO growth charge (1 input / 2 outputs pays 100)
        let one = weight_of(&[&c[0]], &[dest.clone(), chg.clone()]);
        assert_eq!(s.weight, one + 2 * (36 + 3) - 100);
        assert_eq!(s.fee, s.weight * fr);
        // 115M needs two keys: largest first (key 1 = 100M, then key 0 = 30M)
        let s = select(&c, &dest, &chg, Some(115_000_000), fr).unwrap();
        assert_eq!(s.inputs[0], 1);
        assert_eq!(s.inputs.len(), 4);
        // insufficient
        assert!(select(&c, &dest, &chg, Some(150_000_000), fr).unwrap_err().contains("insufficient"));
        // max: everything, no change
        let s = select(&c, &dest, &chg, None, fr).unwrap();
        assert_eq!(s.inputs.len(), 5);
        assert_eq!(s.change, 0);
        assert_eq!(s.amount + s.fee, 150_000_000);
        // dust change is dropped into the fee
        let w1 = weight_of(&[&c[1]], &[dest.clone()]);
        let s = select(&c[1..2], &dest, &chg, Some(100_000_000 - w1 - 10), fr).unwrap();
        assert_eq!(s.change, 0);
        assert_eq!(s.fee, w1 + 10);
        // fee rate bounds
        assert!(select(&c, &dest, &chg, Some(1), 0).is_err());
        assert!(select(&c, &dest, &chg, Some(1), MAX_FEERATE + 1).is_err());
    }

    #[test]
    fn high_fee_rule() {
        assert!(!high_fee(HIGH_FEE_ABS, 1)); // not above 0.5 VARV
        assert!(high_fee(HIGH_FEE_ABS + 1, 1_000_000_000)); // > 5% and > 0.5 VARV
        assert!(!high_fee(HIGH_FEE_ABS + 1, 100_000_000_000)); // < 5%
    }

    #[test]
    fn build_signs_canonically_and_validates() {
        let _ = Network::Regtest;
        let w = Wallet::from_seed(&[1; 32], None).unwrap();
        let win = window(&w, 3);
        let height = 1000;
        let utxos = vec![
            utxo(&w, KeyPath::receive(0), 30_000_000, 1, 100, true),
            utxo(&w, KeyPath::receive(0), 30_000_000, 2, 101, true),
            utxo(&w, KeyPath::receive(1), 50_000_000, 3, 102, false),
            utxo(&w, KeyPath::receive(0), 30_000_000, 4, 103, true),
            utxo(&w, KeyPath::receive(2), 9_000_000, 5, 990, true), // immature coinbase: skipped
        ];
        let to = Output::single(0, 1, [0xdd; 32]);
        let change_key = KeyPath::change(0).derive(&w).unwrap();
        let req = BuildRequest { to: &to, amount: Some(100_000_000), feerate: 2, utxos: &utxos, api_height: height, allow_high_fee: false, change_key: &change_key };
        let b = build(&w, &win, &ids(), &req).unwrap();
        // key 1 (50M) and key 0 (3 × 30M) are both needed
        assert_eq!(b.tx.inputs.len(), 4);
        let paths: Vec<u8> = b.tx.witnesses.iter().map(|x| x.path).collect();
        assert_eq!(paths.iter().filter(|p| **p == 0).count(), 2);
        assert_eq!(paths.iter().filter(|p| **p == 2).count(), 2);
        assert!(b.tx.inputs.iter().all(|i| i.txid[1] != 5));
        assert_eq!(b.fee, b.weight * 2);
        assert_eq!(b.total_in, 140_000_000);
        assert_eq!(b.change, b.total_in - b.amount - b.fee);
        assert_eq!(b.tx.outputs[1], change_key.output(b.change));
        // check_transaction already ran inside build; run it again here, and show that
        // signing a later same-key input again (path 0) is rejected
        let view: HashMap<OutPoint, Coin> = utxos.iter().map(|u| (u.outpoint.clone(), Coin { output: u.output.clone(), height: u.height.unwrap(), coinbase: u.coinbase })).collect();
        check_transaction(&b.tx, height + 1, &ids(), &view, true).unwrap();
        let mut bad = b.tx.clone();
        let i2 = paths.iter().position(|p| *p == 2).unwrap();
        bad.witnesses[i2] = b.tx.witnesses[i2 - 1].clone();
        assert!(check_transaction(&bad, height + 1, &ids(), &view, false).is_err());
        // a round trip through bytes gives the same transaction
        assert_eq!(Tx::from_bytes(&b.tx.serialize()).unwrap(), b.tx);
        // a foreign coin anywhere in the request is refused, even if not needed
        let other = Wallet::from_seed(&[2; 32], None).unwrap();
        let mut with_foreign = utxos.clone();
        with_foreign.push(utxo(&other, KeyPath::receive(0), 1, 9, 100, false));
        let req2 = BuildRequest { utxos: &with_foreign, ..req };
        assert!(build(&w, &win, &ids(), &req2).unwrap_err().contains("does not belong"));
        // high fee cap
        let small = BuildRequest { amount: Some(1_000_000), feerate: 10_000, utxos: &utxos, ..req };
        assert!(build(&w, &win, &ids(), &small).unwrap_err().contains("unusually high"));
        let small_ok = BuildRequest { allow_high_fee: true, ..small };
        assert!(build(&w, &win, &ids(), &small_ok).is_ok());
        // send max
        let max = BuildRequest { amount: None, ..req };
        let b = build(&w, &win, &ids(), &max).unwrap();
        assert_eq!(b.change, 0);
        assert_eq!(b.amount + b.fee, 140_000_000);
        assert_eq!(b.tx.outputs.len(), 1);
    }
}
