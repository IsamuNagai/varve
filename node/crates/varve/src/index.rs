//! In-memory indexes for the public API (API.md): transactions, spends and per-address
//! history, totals and unspent coins. Rebuilt on startup as blocks are connected from
//! disk, and kept exact across reorganizations (connect/disconnect are inverses).

use std::collections::{HashMap, HashSet};

use varve_consensus::block::{subsidy, Block};
use varve_consensus::tx::OutPoint;
use varve_consensus::validate::{BlockUndo, Coin};

use crate::chain::Id;

/// One transaction touching an address: height, txid, amount received, amount sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrEntry {
    pub height: u64,
    pub txid: Id,
    pub received: u64,
    pub sent: u64,
}

#[derive(Default, Debug)]
pub struct AddrInfo {
    /// in chain order (oldest first)
    pub entries: Vec<AddrEntry>,
    pub received: u128,
    pub sent: u128,
    pub utxos: HashSet<OutPoint>,
}

#[derive(Default)]
pub struct Index {
    /// txid → (block id, position in block)
    pub tx: HashMap<Id, (Id, u32)>,
    /// spent outpoint → (spending txid, input index)
    pub spent: HashMap<OutPoint, (Id, u32)>,
    /// output template → address info
    pub addr: HashMap<Vec<u8>, AddrInfo>,
    /// total block subsidy issued on the active chain
    pub issued: u128,
}

impl Index {
    /// Per-template (received, sent) for each transaction of a block, with the coins it
    /// spends resolved from the undo data or from earlier transactions in the same block.
    fn effects(b: &Block, undo: &BlockUndo) -> Vec<(Id, Vec<(Vec<u8>, u64, u64)>, Vec<(OutPoint, Vec<u8>)>, Vec<(OutPoint, Vec<u8>)>)> {
        let before: HashMap<&OutPoint, &Coin> = undo.spent.iter().map(|(o, c)| (o, c)).collect();
        let mut local: HashMap<OutPoint, (Vec<u8>, u64)> = HashMap::new();
        let mut out = Vec::with_capacity(b.txs.len());
        for (n, tx) in b.txs.iter().enumerate() {
            let txid = tx.txid();
            let mut per: Vec<(Vec<u8>, u64, u64)> = Vec::new();
            let mut add = |t: Vec<u8>, r: u64, s: u64| match per.iter_mut().find(|x| x.0 == t) {
                Some(x) => {
                    x.1 += r;
                    x.2 += s;
                }
                None => per.push((t, r, s)),
            };
            let mut spends = Vec::new();
            if n > 0 {
                for op in &tx.inputs {
                    let (t, amt) = match local.remove(op) {
                        Some(v) => v,
                        None => match before.get(op) {
                            Some(c) => (c.output.template(), c.output.amount),
                            None => continue, // cannot happen for a connected block
                        },
                    };
                    add(t.clone(), 0, amt);
                    spends.push((op.clone(), t));
                }
            }
            let mut creates = Vec::new();
            for (i, o) in tx.outputs.iter().enumerate() {
                let op = OutPoint { txid, index: i as u32 };
                let t = o.template();
                add(t.clone(), o.amount, 0);
                local.insert(op.clone(), (t.clone(), o.amount));
                creates.push((op, t));
            }
            out.push((txid, per, spends, creates));
        }
        out
    }

    pub fn connect(&mut self, id: &Id, height: u64, b: &Block, undo: &BlockUndo) {
        for (pos, (txid, per, spends, creates)) in Self::effects(b, undo).into_iter().enumerate() {
            self.tx.insert(txid, (*id, pos as u32));
            let tx = &b.txs[pos];
            if pos > 0 {
                for (i, op) in tx.inputs.iter().enumerate() {
                    self.spent.insert(op.clone(), (txid, i as u32));
                }
            }
            for (op, t) in spends {
                if let Some(a) = self.addr.get_mut(&t) {
                    a.utxos.remove(&op);
                }
            }
            for (op, t) in creates {
                self.addr.entry(t).or_default().utxos.insert(op);
            }
            for (t, r, s) in per {
                let a = self.addr.entry(t).or_default();
                a.received += r as u128;
                a.sent += s as u128;
                a.entries.push(AddrEntry { height, txid, received: r, sent: s });
            }
        }
        self.issued += subsidy(height) as u128;
    }

    pub fn disconnect(&mut self, height: u64, b: &Block, undo: &BlockUndo) {
        for (pos, (txid, per, spends, creates)) in Self::effects(b, undo).into_iter().enumerate().rev() {
            self.tx.remove(&txid);
            let tx = &b.txs[pos];
            if pos > 0 {
                for op in &tx.inputs {
                    self.spent.remove(op);
                }
            }
            for (op, t) in creates {
                if let Some(a) = self.addr.get_mut(&t) {
                    a.utxos.remove(&op);
                }
            }
            for (op, t) in spends {
                self.addr.entry(t).or_default().utxos.insert(op);
            }
            for (t, r, s) in per {
                if let Some(a) = self.addr.get_mut(&t) {
                    a.received -= r as u128;
                    a.sent -= s as u128;
                    if let Some(i) = a.entries.iter().rposition(|e| e.txid == txid && e.height == height) {
                        a.entries.remove(i);
                    }
                    if a.entries.is_empty() && a.utxos.is_empty() {
                        self.addr.remove(&t);
                    }
                }
            }
        }
        // outputs spent inside the block were removed from and re-added to utxos above;
        // coins created inside and spent inside cancel out
        self.issued -= subsidy(height) as u128;
    }
}
