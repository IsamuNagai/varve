//! Shared node state. Lock order is always: chain, then mempool, then wallet, then peers.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use varve_consensus::block::{merkle_root, subsidy, target_bytes, Block, Header};
use varve_consensus::encoding::hex;
use varve_consensus::tx::{OutPoint, Output, Tx, Witness};

use crate::chain::{now, Chain, Id, Reject};
use crate::mempool::{Mempool, TEMPLATE_MAX_WEIGHT};
use crate::wallet::Wallet;
use crate::wire::{Msg, INV_TX};

pub struct Config {
    pub datadir: PathBuf,
    pub listen: Option<SocketAddr>,
    pub connect: Vec<String>,
    pub seeds: Vec<String>,
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub rpc_port: u16,
    pub user_agent: String,
}

pub struct Node {
    pub cfg: Config,
    pub chain: Mutex<Chain>,
    pub mempool: Mutex<Mempool>,
    pub wallet: Mutex<Wallet>,
    pub peers: Mutex<crate::p2p::Peers>,
    pub shutdown: AtomicBool,
    /// increments whenever the active tip or mempool changes (miners rebuild templates)
    pub tip_version: AtomicU64,
    pub started: u64,
}

pub enum Submit {
    Accepted { new_tip: bool },
    Rejected(String),
}

impl Node {
    pub fn new(cfg: Config, chain: Chain, wallet: Wallet) -> Arc<Node> {
        Arc::new(Node {
            cfg,
            chain: Mutex::new(chain),
            mempool: Mutex::new(Mempool::default()),
            wallet: Mutex::new(wallet),
            peers: Mutex::new(crate::p2p::Peers::default()),
            shutdown: AtomicBool::new(false),
            tip_version: AtomicU64::new(0),
            started: now(),
        })
    }

    pub fn running(&self) -> bool {
        !self.shutdown.load(Ordering::SeqCst)
    }

    /// Accept a block from a peer, the miner or RPC. Whenever the active tip moves (even if
    /// the offered block itself proved invalid), the mempool is updated, miners are
    /// notified and the new tip is announced. Senders of invalid blocks are banned.
    pub fn submit_block(&self, b: Block, from_peer: Option<u64>) -> Submit {
        let id = b.header.block_id();
        let mut chain = self.chain.lock().unwrap();
        let old_active: Vec<Id> = chain.active.clone();
        let outcome = match chain.accept_block(b, from_peer) {
            Ok(o) => o,
            Err(Reject::Duplicate) => return Submit::Rejected("duplicate".into()),
            Err(Reject::Orphan) => return Submit::Rejected("orphan: parent unknown".into()),
            Err(Reject::Deferred) => return Submit::Rejected("timestamp too far in the future (deferred)".into()),
            Err(Reject::Invalid(e)) => {
                eprintln!("[node] rejected block {}: {}", hex(&id), e);
                return Submit::Rejected(format!("invalid: {}", e));
            }
            Err(Reject::Local(s)) => {
                eprintln!("[node] set aside block {}: {}", hex(&id), s);
                return Submit::Rejected(s);
            }
        };
        if outcome.tip_changed {
            let mut returned = Vec::new();
            for oid in old_active.iter().skip(1) {
                if !chain.is_active(oid) {
                    if let Some(ob) = chain.get_block(oid) {
                        returned.extend(ob.txs.into_iter().skip(1));
                    }
                }
            }
            let tip = chain.tip().header.clone();
            let height = chain.height();
            self.mempool.lock().unwrap().update(&chain, returned);
            drop(chain);
            self.tip_version.fetch_add(1, Ordering::SeqCst);
            eprintln!("[node] new tip {} height {}", hex(&tip.block_id()), height);
            self.peers.lock().unwrap().broadcast(&Msg::Headers(vec![tip]), from_peer);
        } else {
            drop(chain);
        }
        if !outcome.bad_sources.is_empty() {
            let mut p = self.peers.lock().unwrap();
            for src in &outcome.bad_sources {
                if Some(*src) != from_peer {
                    p.ban_peer(*src, "sent a block that failed validation");
                }
            }
        }
        if outcome.self_invalid {
            return Submit::Rejected("invalid: block failed validation".into());
        }
        Submit::Accepted { new_tip: outcome.tip_changed }
    }

    /// Accept a transaction into the mempool and announce it.
    pub fn submit_tx(&self, tx: Tx, from_peer: Option<u64>) -> Result<Id, String> {
        let wtxid = tx.wtxid();
        let chain = self.chain.lock().unwrap();
        let mut mp = self.mempool.lock().unwrap();
        let txid = mp.accept(tx, &chain)?;
        drop(mp);
        drop(chain);
        self.tip_version.fetch_add(1, Ordering::SeqCst);
        self.peers.lock().unwrap().broadcast_tx_inv(&Msg::Inv(vec![(INV_TX, wtxid)]), from_peer);
        Ok(txid)
    }

    /// A block template paying `pay_to`. The header's nonce is left at 0.
    pub fn block_template(&self, pay_to: &Output, extra: &[u8]) -> (Block, Id, u64) {
        let chain = self.chain.lock().unwrap();
        let mp = self.mempool.lock().unwrap();
        let parent = chain.tip_id();
        let height = chain.height() + 1;
        let (txs, fees) = mp.select(TEMPLATE_MAX_WEIGHT);
        drop(mp);
        let mut out = pay_to.clone();
        out.amount = subsidy(height) + fees;
        let mut extra = extra.to_vec();
        extra.truncate(64);
        let cb = Tx {
            version: 1,
            inputs: vec![OutPoint { txid: [0u8; 32], index: (height % (1u64 << 32)) as u32 }],
            outputs: vec![out],
            locktime: (height >> 32) as u32,
            witnesses: vec![Witness { path: 0, public_key: vec![], signature: extra }],
        };
        let mut all = vec![cb];
        all.extend(txs);
        let root = merkle_root(&all.iter().map(|t| t.wtxid()).collect::<Vec<_>>());
        let ts = now().max(chain.mtp(&parent) + 1);
        let target = chain.next_target_after(&parent);
        let header = Header { version: 1, prev_block: parent, tx_root: root, timestamp: ts, target: target_bytes(&target), nonce: 0 };
        let key = chain.pow_key(&parent, height).expect("seed block on active chain");
        (Block { header, txs: all }, key, height)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().count()
    }

    pub fn mempool_info(&self) -> (usize, u64) {
        let mp = self.mempool.lock().unwrap();
        (mp.txs.len(), mp.txs.values().map(|e| e.weight).sum())
    }

}
