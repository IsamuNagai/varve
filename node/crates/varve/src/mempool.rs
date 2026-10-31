//! Transaction pool (p2p.md §8 policy subset).

use std::collections::{HashMap, HashSet};

use varve_consensus::params::{MAX_BLOCK_WEIGHT, MAX_MONEY};
use varve_consensus::tx::{OutPoint, Tx};
use varve_consensus::validate::{check_transaction, Coin, UtxoView};

use crate::chain::{now, Chain, Id};

pub const MAX_STANDARD_TX_WEIGHT: u64 = 100_000;
/// laminae per weight unit (placeholder, p2p.md §8)
pub const MIN_RELAY_FEERATE: u64 = 1;
pub const MAX_MEMPOOL_TXS: usize = 20_000;
/// p2p.md §8: about 100 MB; weight ≥ bytes, so a weight cap bounds memory.
pub const MAX_MEMPOOL_WEIGHT: u64 = 100_000_000;
/// unconfirmed ancestors allowed per transaction (keeps template selection cheap)
pub const MAX_ANCESTORS: usize = 25;
pub const EXPIRY_SECS: u64 = 14 * 24 * 3600;

#[derive(Clone)]
pub struct Entry {
    pub tx: Tx,
    pub txid: Id,
    pub wtxid: Id,
    pub fee: u64,
    pub weight: u64,
    pub time: u64,
    pub seq: u64,
}

#[derive(Default)]
pub struct Mempool {
    pub txs: HashMap<Id, Entry>,
    by_wtxid: HashMap<Id, Id>,
    spends: HashMap<OutPoint, Id>,
    seq: u64,
}

/// UTXO view = chain UTXO set plus unspent mempool outputs, minus mempool spends.
struct View<'a> {
    chain: &'a HashMap<OutPoint, Coin>,
    pool: &'a Mempool,
    height: u64,
}

impl UtxoView for View<'_> {
    fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
        if self.pool.spends.contains_key(op) {
            return None;
        }
        if let Some(c) = self.chain.get(op) {
            return Some(c.clone());
        }
        let e = self.pool.txs.get(&op.txid)?;
        let o = e.tx.outputs.get(op.index as usize)?;
        Some(Coin { output: o.clone(), height: self.height, coinbase: false })
    }
}

impl Mempool {
    pub fn contains_wtxid(&self, w: &Id) -> bool {
        self.by_wtxid.contains_key(w)
    }
    pub fn get_by_wtxid(&self, w: &Id) -> Option<&Entry> {
        self.by_wtxid.get(w).and_then(|t| self.txs.get(t))
    }

    /// p2p.md §8 order: parse (done), weight, policy, inputs, fee, commitments, signatures.
    pub fn accept(&mut self, tx: Tx, chain: &Chain) -> Result<Id, String> {
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        if self.txs.contains_key(&txid) {
            return Err("already in mempool".into());
        }
        let weight = tx.weight(false);
        if weight > MAX_STANDARD_TX_WEIGHT {
            return Err("transaction too heavy (policy)".into());
        }
        if self.txs.len() >= MAX_MEMPOOL_TXS || self.total_weight().saturating_add(weight) > MAX_MEMPOOL_WEIGHT {
            return Err("mempool full".into());
        }
        if self.ancestors(&tx) > MAX_ANCESTORS {
            return Err("too many unconfirmed ancestors (policy)".into());
        }
        for op in &tx.inputs {
            if self.spends.contains_key(op) {
                return Err("conflicts with a mempool transaction (no replacement)".into());
            }
        }
        let height = chain.height() + 1;
        let view = View { chain: &chain.utxo, pool: self, height };
        let (fee, _) = check_transaction(&tx, height, &chain.ids(), &view, true).map_err(|e| e.to_string())?;
        if fee < weight.saturating_mul(MIN_RELAY_FEERATE) {
            return Err(format!("fee {} below minimum relay fee {}", fee, weight * MIN_RELAY_FEERATE));
        }
        self.insert(tx, txid, wtxid, fee, weight);
        Ok(txid)
    }

    fn total_weight(&self) -> u64 {
        self.txs.values().map(|e| e.weight).sum()
    }

    /// Number of distinct unconfirmed ancestors, counting up to MAX_ANCESTORS + 1.
    fn ancestors(&self, tx: &Tx) -> usize {
        let mut seen: HashSet<Id> = HashSet::new();
        let mut stack: Vec<Id> = tx.inputs.iter().map(|i| i.txid).collect();
        while let Some(t) = stack.pop() {
            if seen.len() > MAX_ANCESTORS {
                break;
            }
            if let Some(e) = self.txs.get(&t) {
                if seen.insert(t) {
                    stack.extend(e.tx.inputs.iter().map(|i| i.txid));
                }
            }
        }
        seen.len()
    }

    fn insert(&mut self, tx: Tx, txid: Id, wtxid: Id, fee: u64, weight: u64) {
        for op in &tx.inputs {
            self.spends.insert(op.clone(), txid);
        }
        self.seq += 1;
        self.by_wtxid.insert(wtxid, txid);
        self.txs.insert(txid, Entry { tx, txid, wtxid, fee, weight, time: now(), seq: self.seq });
    }


    /// After the active chain changed: drop confirmed, conflicting, expired or no longer
    /// valid transactions; try to re-add transactions from disconnected blocks.
    pub fn update(&mut self, chain: &Chain, returned: Vec<Tx>) {
        let mut entries: Vec<Entry> = self.txs.drain().map(|(_, e)| e).collect();
        self.by_wtxid.clear();
        self.spends.clear();
        entries.sort_by_key(|e| e.seq);
        let height = chain.height() + 1;
        let t = now();
        for tx in returned {
            let _ = self.accept(tx, chain);
        }
        for e in entries {
            if t.saturating_sub(e.time) > EXPIRY_SECS || e.tx.inputs.iter().any(|op| self.spends.contains_key(op)) {
                continue;
            }
            let view = View { chain: &chain.utxo, pool: self, height };
            // signatures were verified on entry and do not depend on height
            if check_transaction(&e.tx, height, &chain.ids(), &view, false).is_ok() {
                self.insert(e.tx, e.txid, e.wtxid, e.fee, e.weight);
            }
        }
    }

    /// Highest-feerate set that fits, parents before children.
    pub fn select(&self, max_weight: u64) -> (Vec<Tx>, u64) {
        let mut order: Vec<&Entry> = self.txs.values().collect();
        order.sort_by(|a, b| (b.fee as u128 * a.weight as u128).cmp(&(a.fee as u128 * b.weight as u128)).then(a.seq.cmp(&b.seq)));
        let mut chosen: Vec<Tx> = Vec::new();
        let mut in_block: HashSet<Id> = HashSet::new();
        let mut weight = 0u64;
        let mut fees = 0u64;
        let mut progress = true;
        while progress {
            progress = false;
            for e in &order {
                if in_block.contains(&e.txid) || weight + e.weight > max_weight {
                    continue;
                }
                let parents_ok = e.tx.inputs.iter().all(|op| !self.txs.contains_key(&op.txid) || in_block.contains(&op.txid));
                if !parents_ok {
                    continue;
                }
                in_block.insert(e.txid);
                weight += e.weight;
                fees = (fees + e.fee).min(MAX_MONEY);
                chosen.push(e.tx.clone());
                progress = true;
            }
        }
        (chosen, fees)
    }
}

pub const COINBASE_WEIGHT_RESERVE: u64 = 1_000;
pub const TEMPLATE_MAX_WEIGHT: u64 = MAX_BLOCK_WEIGHT - COINBASE_WEIGHT_RESERVE;
