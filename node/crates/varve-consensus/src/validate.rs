//! blocks.md §4: header and block validity, given the chain context and a UTXO view.
//! Proof of work (step 6) is checked by the caller with RandomX (pow.rs).

use std::collections::{HashMap, HashSet};

use crate::bignum::BigUint;
use crate::block::{merkle_root, next_target, subsidy, Block, Header};
use crate::params::*;
use crate::tx::{commitment, sighash, OutPoint, Output, Tx};
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub output: Output,
    pub height: u64,
    pub coinbase: bool,
}

pub trait UtxoView {
    fn get_coin(&self, op: &OutPoint) -> Option<Coin>;
}

impl UtxoView for HashMap<OutPoint, Coin> {
    fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
        self.get(op).cloned()
    }
}

/// What the chain knows about the parent when a new block arrives.
pub struct HeaderContext<'a> {
    /// height of the NEW block
    pub height: u64,
    pub parent_id: [u8; 32],
    pub parent_timestamp: u64,
    /// timestamps of the last ≤ 11 blocks ending with the parent (genesis included when in range)
    pub recent_timestamps: &'a [u64],
    pub genesis_timestamp: u64,
    pub initial_target: &'a BigUint,
}

/// Steps 2–5 (cheap header checks). Step 3's "parent is known and not invalid" is the
/// caller's lookup; here we check linkage to the given parent.
pub fn check_header(h: &Header, ctx: &HeaderContext) -> Result<(), Error> {
    if h.version != BLOCK_VERSION {
        return Err(Error::Invalid("header version"));
    }
    if h.prev_block != ctx.parent_id {
        return Err(Error::Invalid("prev_block does not match parent"));
    }
    if ctx.height == 0 {
        return Err(Error::Invalid("height 0 is genesis"));
    }
    if h.timestamp <= crate::block::median_time_past(ctx.recent_timestamps) {
        return Err(Error::Invalid("timestamp not above median time past"));
    }
    let expected = next_target(ctx.initial_target, ctx.genesis_timestamp, ctx.height - 1, ctx.parent_timestamp);
    if h.target_int() != expected {
        return Err(Error::Invalid("wrong target"));
    }
    Ok(())
}

/// Proof-of-work comparison (pow.md §2): pow_hash read as little-endian u256 ≤ target.
pub fn pow_hash_meets_target(pow_hash: &[u8; 32], h: &Header) -> bool {
    BigUint::from_le_bytes(pow_hash) <= h.target_int()
}

pub struct ChainIds {
    pub network_id: [u8; 4],
    pub genesis_id: [u8; 32],
    /// scheme lifecycle transitions of this network (transactions.md §6)
    pub lifecycle: Vec<Transition>,
}

/// The UTXO changes a valid block makes, in a form that can be undone.
#[derive(Clone, Debug, Default)]
pub struct BlockUndo {
    /// coins that existed before the block and were spent by it, in spend order
    pub spent: Vec<(OutPoint, Coin)>,
    /// coins created by the block that remain unspent after it
    pub created: Vec<(OutPoint, Coin)>,
    pub fees: u64,
    pub weight: u64,
}

struct SigJob {
    scheme: varve_sys::Scheme,
    public_key: Vec<u8>,
    msg: [u8; 32],
    signature: Vec<u8>,
}

fn creatable(ids: &ChainIds, id: u16, height: u64) -> bool {
    scheme_state(&ids.lifecycle, id, height) == Some(SchemeState::Active)
}

fn spendable(ids: &ChainIds, id: u16, height: u64) -> bool {
    matches!(scheme_state(&ids.lifecycle, id, height), Some(SchemeState::Active) | Some(SchemeState::NoNewOutputs))
}

fn check_output(o: &Output, height: u64, ids: &ChainIds) -> Result<(), Error> {
    if o.output_version != OUTPUT_VERSION {
        return Err(Error::Invalid("output version"));
    }
    if o.amount == 0 || o.amount > MAX_MONEY {
        return Err(Error::Invalid("amount out of range"));
    }
    if !creatable(ids, o.scheme_id, height) {
        return Err(Error::Invalid("scheme not creatable"));
    }
    if let Some(r) = &o.recovery {
        if !creatable(ids, r.scheme_id, height) {
            return Err(Error::Invalid("recovery scheme not creatable"));
        }
        if r.delay == 0 || r.delay > RECOVERY_DELAY_MAX {
            return Err(Error::Invalid("recovery delay out of range"));
        }
    }
    Ok(())
}

fn check_coinbase_shape(cb: &Tx, height: u64) -> Result<(), Error> {
    let w = &cb.witnesses[0];
    if cb.inputs.len() != 1
        || cb.inputs[0].txid != [0u8; 32]
        || cb.inputs[0].index as u64 != height % (1u64 << 32)
        || cb.locktime as u64 != height >> 32
        || w.path != 0
        || !w.public_key.is_empty()
        || w.signature.len() > COINBASE_EXTRA_MAX
    {
        return Err(Error::Invalid("coinbase rules"));
    }
    Ok(())
}

/// Steps 8–12 for a block whose header already passed steps 2–6.
/// `verify_signatures = false` is only for tests and benchmarking.
pub fn check_block(block: &Block, height: u64, ids: &ChainIds, utxo: &dyn UtxoView, verify_signatures: bool) -> Result<BlockUndo, Error> {
    let txs = &block.txs;
    // step 8: root
    if txs.is_empty() {
        return Err(Error::Invalid("no transactions"));
    }
    let wtxids: Vec<[u8; 32]> = txs.iter().map(|t| t.wtxid()).collect();
    if merkle_root(&wtxids) != block.header.tx_root {
        return Err(Error::Invalid("bad transaction root"));
    }
    // step 9: structure
    if !txs[0].is_coinbase_shaped() {
        return Err(Error::Invalid("first transaction is not a coinbase"));
    }
    for t in &txs[1..] {
        if t.inputs.iter().any(|i| i.txid == [0u8; 32]) {
            return Err(Error::Invalid("coinbase-style input outside position 0"));
        }
    }
    let txids: Vec<[u8; 32]> = txs.iter().map(|t| t.txid()).collect();
    {
        let mut seen = HashSet::with_capacity(txids.len());
        if !txids.iter().all(|t| seen.insert(*t)) {
            return Err(Error::Invalid("duplicate txid"));
        }
    }
    // step 10: weight
    let mut weight = 0u64;
    for (n, t) in txs.iter().enumerate() {
        weight = weight.checked_add(t.weight(n == 0)).ok_or(Error::Invalid("weight overflow"))?;
    }
    if weight > MAX_BLOCK_WEIGHT {
        return Err(Error::Invalid("block weight"));
    }
    // step 11: transactions in order
    let mut created: HashMap<OutPoint, Coin> = HashMap::new();
    let mut spent_here: HashSet<OutPoint> = HashSet::new();
    let mut undo = BlockUndo::default();
    let mut fees = 0u64;
    let mut coinbase_out = 0u64;
    let mut jobs: Vec<SigJob> = Vec::new();
    for (n, tx) in txs.iter().enumerate() {
        // 11.1 syntax, version and counts
        if tx.version != TX_VERSION || tx.inputs.is_empty() || tx.outputs.is_empty() || tx.witnesses.len() != tx.inputs.len() {
            return Err(Error::Invalid("transaction structure"));
        }
        if n == 0 {
            check_coinbase_shape(tx, height)?; // 11.6
        } else if tx.locktime != 0 && height < tx.locktime as u64 {
            return Err(Error::Invalid("locktime")); // 11.2
        }
        // 11.3 inputs
        let mut coins: Vec<Coin> = Vec::new();
        if n > 0 {
            for op in &tx.inputs {
                if !spent_here.insert(op.clone()) {
                    return Err(Error::Invalid("output spent twice in block"));
                }
                let coin = if let Some(c) = created.remove(op) {
                    c
                } else if let Some(c) = utxo.get_coin(op) {
                    undo.spent.push((op.clone(), c.clone()));
                    c
                } else {
                    return Err(Error::Invalid("missing or spent input"));
                };
                coins.push(coin);
            }
        }
        // 11.4 outputs
        let mut out_sum = 0u64;
        for o in &tx.outputs {
            check_output(o, height, ids)?;
            out_sum = out_sum.checked_add(o.amount).filter(|s| *s <= MAX_MONEY).ok_or(Error::Invalid("output sum overflow"))?;
        }
        // 11.5 sums and fee
        if n == 0 {
            coinbase_out = out_sum;
        } else {
            let mut in_sum = 0u64;
            for c in &coins {
                in_sum = in_sum.checked_add(c.output.amount).filter(|s| *s <= MAX_MONEY).ok_or(Error::Invalid("input sum overflow"))?;
            }
            if in_sum < out_sum {
                return Err(Error::Invalid("negative fee"));
            }
            fees = fees.checked_add(in_sum - out_sum).filter(|s| *s <= MAX_MONEY).ok_or(Error::Invalid("fee sum overflow"))?;
            // 11.7 spend conditions
            let spent_outputs: Vec<Output> = coins.iter().map(|c| c.output.clone()).collect();
            jobs.extend(spend_jobs(tx, &coins, &spent_outputs, height, ids)?);
        }
        for (idx, o) in tx.outputs.iter().enumerate() {
            created.insert(OutPoint { txid: txids[n], index: idx as u32 }, Coin { output: o.clone(), height, coinbase: n == 0 });
        }
    }
    // 11.7 signatures (order-independent; may run in parallel)
    if verify_signatures && !verify_all(&jobs) {
        return Err(Error::Invalid("bad signature"));
    }
    // step 12: coinbase value
    let allowed = subsidy(height).checked_add(fees).ok_or(Error::Invalid("subsidy overflow"))?;
    if coinbase_out > allowed {
        return Err(Error::Invalid("coinbase claims too much"));
    }
    let mut created: Vec<(OutPoint, Coin)> = created.into_iter().collect();
    created.sort_by(|a, b| a.0.cmp(&b.0));
    undo.created = created;
    undo.fees = fees;
    undo.weight = weight;
    Ok(undo)
}

/// transactions.md §8 for every input of a transaction. Returns the signature checks
/// (step 7) as jobs; path-2 inputs (§8.2) need none.
fn spend_jobs(tx: &Tx, coins: &[Coin], spent: &[Output], height: u64, ids: &ChainIds) -> Result<Vec<SigJob>, Error> {
    let mut jobs = Vec::with_capacity(coins.len());
    // (scheme, commitment) selected by earlier inputs with path 0 or 1
    let mut authorized: Vec<(u16, [u8; 32])> = Vec::new();
    for (i, coin) in coins.iter().enumerate() {
        let w = &tx.witnesses[i];
        let o = &coin.output;
        if coin.coinbase && height < coin.height.checked_add(COINBASE_MATURITY).ok_or(Error::Invalid("height overflow"))? {
            return Err(Error::Invalid("immature coinbase"));
        }
        if w.path == 2 {
            if !w.public_key.is_empty() || !w.signature.is_empty() {
                return Err(Error::Invalid("shared witness must be empty"));
            }
            if !spendable(ids, o.scheme_id, height) {
                return Err(Error::Invalid("scheme not spendable"));
            }
            if !authorized.contains(&(o.scheme_id, o.commitment)) {
                return Err(Error::Invalid("no earlier input authorizes this key"));
            }
            continue;
        }
        // §8.2: path 2 is mandatory for an already authorized key (unique witness layout)
        if (w.path == 0 || w.path == 1) && authorized.contains(&(o.scheme_id, o.commitment)) {
            return Err(Error::Invalid("path 2 required for an already authorized key"));
        }
        let (sid, com) = match w.path {
            0 => (o.scheme_id, o.commitment),
            1 => {
                let r = o.recovery.as_ref().ok_or(Error::Invalid("no recovery path"))?;
                if height < coin.height.checked_add(r.delay as u64).ok_or(Error::Invalid("height overflow"))? {
                    return Err(Error::Invalid("recovery path not yet available"));
                }
                (r.scheme_id, r.commitment)
            }
            _ => return Err(Error::Invalid("unknown path")),
        };
        if !spendable(ids, sid, height) {
            return Err(Error::Invalid("scheme not spendable"));
        }
        let s = scheme(sid, height).ok_or(Error::Invalid("unknown scheme"))?;
        if w.public_key.len() != s.pk_len || w.signature.len() != s.sig_len {
            return Err(Error::Invalid("wrong key or signature length"));
        }
        if commitment(sid, &w.public_key) != com {
            return Err(Error::Invalid("commitment mismatch"));
        }
        let msg = sighash(&ids.network_id, &ids.genesis_id, tx, i as u32, spent, w.path);
        jobs.push(SigJob { scheme: s.sys, public_key: w.public_key.clone(), msg, signature: w.signature.clone() });
        authorized.push((sid, com));
    }
    Ok(jobs)
}

fn verify_all(jobs: &[SigJob]) -> bool {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(16);
    if jobs.len() < 4 || threads == 1 {
        return jobs.iter().all(|j| varve_sys::verify(j.scheme, &j.public_key, &j.msg, &j.signature));
    }
    let chunk = jobs.len().div_ceil(threads);
    let check = |c: &[SigJob]| c.iter().all(|j| varve_sys::verify(j.scheme, &j.public_key, &j.msg, &j.signature));
    std::thread::scope(|s| {
        let mut ok = true;
        let mut handles = Vec::new();
        for c in jobs.chunks(chunk) {
            // if a thread cannot be started, verify that chunk here instead of panicking
            match std::thread::Builder::new().spawn_scoped(s, move || check(c)) {
                Ok(h) => handles.push(h),
                Err(_) => ok &= check(c),
            }
        }
        for h in handles {
            ok &= h.join().unwrap_or(false);
        }
        ok
    })
}

/// A loose transaction checked as if included in a block at `height` (used by the
/// mempool; policy on top). Same rules as blocks.md §4 step 11 for a non-coinbase
/// transaction. Returns (fee, spent coins). Block validation remains authoritative.
pub fn check_transaction(tx: &Tx, height: u64, ids: &ChainIds, utxo: &dyn UtxoView, verify_signatures: bool) -> Result<(u64, Vec<Coin>), Error> {
    if tx.version != TX_VERSION || tx.inputs.is_empty() || tx.outputs.is_empty() || tx.witnesses.len() != tx.inputs.len() {
        return Err(Error::Invalid("transaction structure"));
    }
    if tx.inputs.iter().any(|i| i.txid == [0u8; 32]) {
        return Err(Error::Invalid("coinbase-style input"));
    }
    if tx.locktime != 0 && height < tx.locktime as u64 {
        return Err(Error::Invalid("locktime"));
    }
    let mut seen = HashSet::new();
    let mut coins = Vec::with_capacity(tx.inputs.len());
    for op in &tx.inputs {
        if !seen.insert(op.clone()) {
            return Err(Error::Invalid("output spent twice"));
        }
        coins.push(utxo.get_coin(op).ok_or(Error::Invalid("missing or spent input"))?);
    }
    let mut out_sum = 0u64;
    for o in &tx.outputs {
        check_output(o, height, ids)?;
        out_sum = out_sum.checked_add(o.amount).filter(|s| *s <= MAX_MONEY).ok_or(Error::Invalid("output sum overflow"))?;
    }
    let mut in_sum = 0u64;
    for c in &coins {
        in_sum = in_sum.checked_add(c.output.amount).filter(|s| *s <= MAX_MONEY).ok_or(Error::Invalid("input sum overflow"))?;
    }
    if in_sum < out_sum {
        return Err(Error::Invalid("negative fee"));
    }
    let spent: Vec<Output> = coins.iter().map(|c| c.output.clone()).collect();
    let jobs = spend_jobs(tx, &coins, &spent, height, ids)?;
    if verify_signatures && !verify_all(&jobs) {
        return Err(Error::Invalid("bad signature"));
    }
    Ok((in_sum - out_sum, coins))
}
