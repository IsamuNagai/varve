//! Block index, active chain, UTXO set, reorganizations, and block storage.
//!
//! Storage model (testnet): only blocks that passed full validation are written to
//! `blocks.dat` (length-prefixed records). On start the file is replayed (structure
//! re-checked, signatures and PoW already verified when first accepted). Side-branch
//! block data waits in memory until it is connected.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use varve_consensus::bignum::BigUint;
use varve_consensus::block::{next_target, seed_height, work, Block, Header};
use varve_consensus::genesis::genesis_block;
use varve_consensus::params::*;
use varve_consensus::pow::PowVerifier;
use varve_consensus::tx::OutPoint;
use varve_consensus::validate::*;
use varve_consensus::Error;

pub type Id = [u8; 32];

/// Blocks held in memory before connection (each ≤ ~720 KB): bounded at ~180 MB.
const MAX_PENDING_BLOCKS: usize = 256;
/// Download window; must stay below MAX_PENDING_BLOCKS (audit finding 1).
pub const BLOCK_DOWNLOAD_WINDOW: usize = 128;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// header passed blocks.md §4 steps 2–6
    HeaderValid,
    /// fully validated and connected at least once (data on disk)
    Valid,
    Invalid,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub header: Header,
    pub height: u64,
    pub chainwork: BigUint,
    pub status: Status,
    /// arrival order, for first-seen tie breaking
    pub seq: u64,
    /// offset in blocks.dat if stored
    pub file_pos: Option<u64>,
}

#[derive(Debug)]
pub enum Reject {
    /// consensus-invalid: ban-worthy for the sender
    Invalid(Error),
    /// parent unknown (orphan) — ask for headers
    Orphan,
    /// timestamp beyond local clock + MAX_FUTURE_DRIFT: retry later, no penalty
    Deferred,
    /// already known
    Duplicate,
    /// local failure (I/O, memory)
    Local(String),
}

pub struct Chain {
    pub params: ChainParams,
    pub genesis_id: Id,
    pub index: HashMap<Id, Entry>,
    /// active chain: height → id
    pub active: Vec<Id>,
    pub utxo: HashMap<OutPoint, Coin>,
    /// public API indexes (index.rs)
    pub idx: crate::index::Index,
    undo: HashMap<Id, BlockUndo>,
    /// header-valid blocks received but not yet connected (never on disk), with their sender
    pending: HashMap<Id, (Block, Option<u64>)>,
    /// index entries without children
    leaves: HashSet<Id>,
    pow: PowVerifier,
    store: Store,
    seq: u64,
    /// set while replaying our own disk (PoW and signatures were verified when first accepted)
    loading: bool,
}

/// Result of offering a block.
#[derive(Debug, Default)]
pub struct BlockOutcome {
    pub tip_changed: bool,
    /// the offered block itself turned out invalid
    pub self_invalid: bool,
    /// peers that sent blocks found invalid during this activation (p2p.md §10.4)
    pub bad_sources: Vec<u64>,
    /// stored for later connection (not yet on the active chain)
    pub held: bool,
}

struct Store {
    path: PathBuf,
    file: File,
}

impl Store {
    fn open(dir: &Path) -> std::io::Result<Store> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("blocks.dat");
        let file = OpenOptions::new().read(true).append(true).create(true).open(&path)?;
        Ok(Store { path, file })
    }
    fn append(&mut self, raw: &[u8]) -> std::io::Result<u64> {
        let pos = self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&(raw.len() as u32).to_le_bytes())?;
        self.file.write_all(raw)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(pos)
    }
    fn read_at(&self, pos: u64) -> std::io::Result<Vec<u8>> {
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(pos))?;
        let mut len = [0u8; 4];
        f.read_exact(&mut len)?;
        let n = u32::from_le_bytes(len) as usize;
        if n > MAX_BLOCK_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "record too large"));
        }
        let mut b = vec![0u8; n];
        f.read_exact(&mut b)?;
        Ok(b)
    }
    /// All complete records; truncates a partial record left by a crash.
    fn scan(&mut self) -> std::io::Result<Vec<(u64, Vec<u8>)>> {
        let mut data = Vec::new();
        File::open(&self.path)?.read_to_end(&mut data)?;
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 4 <= data.len() {
            let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            if n > MAX_BLOCK_BYTES || i + 4 + n > data.len() {
                break;
            }
            out.push((i as u64, data[i + 4..i + 4 + n].to_vec()));
            i += 4 + n;
        }
        if i != data.len() {
            self.file.set_len(i as u64)?;
        }
        Ok(out)
    }
}

impl Chain {
    pub fn open(params: ChainParams, datadir: &Path) -> Result<Chain, String> {
        if !params.launchable {
            return Err(format!("network {} is not launchable (draft parameters)", params.name));
        }
        varve_consensus::params::lifecycle_well_formed(&params.lifecycle).map_err(|e| format!("network {}: {}", params.name, e))?;
        let genesis = genesis_block(&params).map_err(|e| format!("genesis: {}", e))?;
        let gid = genesis.header.block_id();
        let mut store = Store::open(datadir).map_err(|e| e.to_string())?;
        let records = store.scan().map_err(|e| e.to_string())?;
        let mut c = Chain {
            genesis_id: gid,
            index: HashMap::new(),
            active: vec![gid],
            utxo: HashMap::new(),
            idx: Default::default(),
            undo: HashMap::new(),
            pending: HashMap::new(),
            leaves: HashSet::new(),
            pow: PowVerifier::new(3),
            store,
            seq: 0,
            loading: true,
            params,
        };
        c.index.insert(
            gid,
            Entry { header: genesis.header.clone(), height: 0, chainwork: work(&genesis.header.target_int()), status: Status::Valid, seq: 0, file_pos: None },
        );
        c.leaves.insert(gid);
        // Index our own validated blocks by file position (bodies stay on disk), then connect.
        let mut loaded = 0usize;
        for (pos, raw) in records {
            if raw.len() < HEADER_SIZE {
                continue;
            }
            let Ok(h) = Header::from_bytes(&raw[..HEADER_SIZE]) else { continue };
            let id = h.block_id();
            if c.index.contains_key(&id) {
                continue;
            }
            if c.accept_header(&h).is_ok() {
                c.index.get_mut(&id).unwrap().file_pos = Some(pos);
                loaded += 1;
            }
        }
        c.activate_best_chain();
        c.loading = false;
        eprintln!("[chain] {}: indexed {} blocks from disk, tip height {}", c.params.name, loaded, c.height());
        Ok(c)
    }

    pub fn ids(&self) -> ChainIds {
        ChainIds { network_id: self.params.network_id, genesis_id: self.genesis_id, lifecycle: self.params.lifecycle.clone() }
    }
    pub fn height(&self) -> u64 {
        (self.active.len() - 1) as u64
    }
    pub fn tip(&self) -> &Entry {
        &self.index[self.active.last().unwrap()]
    }
    pub fn tip_id(&self) -> Id {
        *self.active.last().unwrap()
    }
    pub fn is_active(&self, id: &Id) -> bool {
        self.index.get(id).map(|e| (e.height as usize) < self.active.len() && self.active[e.height as usize] == *id).unwrap_or(false)
    }

    /// Ancestor of `id` at `height` (walks the active chain when possible).
    pub fn ancestor(&self, id: &Id, height: u64) -> Option<Id> {
        let mut cur = *id;
        loop {
            let e = self.index.get(&cur)?;
            if e.height == height {
                return Some(cur);
            }
            if e.height < height {
                return None;
            }
            if self.is_active(&cur) {
                return self.active.get(height as usize).copied();
            }
            cur = e.header.prev_block;
        }
    }

    /// Timestamps of up to 11 blocks ending at `id`.
    fn recent_timestamps(&self, id: &Id) -> Vec<u64> {
        let mut out = Vec::with_capacity(MTP_WINDOW);
        let mut cur = Some(*id);
        while let Some(c) = cur {
            if out.len() == MTP_WINDOW {
                break;
            }
            let e = &self.index[&c];
            out.push(e.header.timestamp);
            cur = if e.height == 0 { None } else { Some(e.header.prev_block) };
        }
        out
    }

    pub fn mtp(&self, id: &Id) -> u64 {
        varve_consensus::block::median_time_past(&self.recent_timestamps(id))
    }

    /// Target required for a child of `parent`.
    pub fn next_target_after(&self, parent: &Id) -> BigUint {
        let p = &self.index[parent];
        let g = &self.index[&self.genesis_id];
        next_target(&self.params.initial_target, g.header.timestamp, p.height, p.header.timestamp)
    }

    /// RandomX key for a block at `height` whose parent is `parent` (pow.md §3).
    pub fn pow_key(&self, parent: &Id, height: u64) -> Option<Id> {
        self.ancestor(parent, seed_height(height))
    }

    pub fn pow_hash(&self, key: &Id, h: &Header) -> Result<[u8; 32], String> {
        self.pow.pow_hash(key, h).map_err(|e| e.to_string())
    }

    /// blocks.md §4 steps 2–6 for a header. Inserts it into the index.
    pub fn accept_header(&mut self, h: &Header) -> Result<Id, Reject> {
        let id = h.block_id();
        if let Some(e) = self.index.get(&id) {
            return if e.status == Status::Invalid { Err(Reject::Invalid(Error::Invalid("known invalid"))) } else { Err(Reject::Duplicate) };
        }
        let parent = match self.index.get(&h.prev_block) {
            None => return Err(Reject::Orphan),
            Some(p) if p.status == Status::Invalid => return Err(Reject::Invalid(Error::Invalid("parent is invalid"))),
            Some(p) => p.clone(),
        };
        if !self.loading && h.timestamp > now() + MAX_FUTURE_DRIFT {
            return Err(Reject::Deferred);
        }
        let ts = self.recent_timestamps(&h.prev_block);
        let g = &self.index[&self.genesis_id];
        let ctx = HeaderContext {
            height: parent.height + 1,
            parent_id: h.prev_block,
            parent_timestamp: parent.header.timestamp,
            recent_timestamps: &ts,
            genesis_timestamp: g.header.timestamp,
            initial_target: &self.params.initial_target,
        };
        check_header(h, &ctx).map_err(Reject::Invalid)?;
        if !self.loading {
            let key = self.pow_key(&h.prev_block, parent.height + 1).ok_or_else(|| Reject::Local("no seed block".into()))?;
            let ph = self.pow_hash(&key, h).map_err(Reject::Local)?;
            if !pow_hash_meets_target(&ph, h) {
                return Err(Reject::Invalid(Error::Invalid("insufficient proof of work")));
            }
        }
        self.seq += 1;
        let cw = parent.chainwork.add(&work(&h.target_int()));
        self.leaves.remove(&h.prev_block);
        self.leaves.insert(id);
        self.index.insert(id, Entry { header: h.clone(), height: parent.height + 1, chainwork: cw, status: Status::HeaderValid, seq: self.seq, file_pos: None });
        Ok(id)
    }

    /// Header with the most chainwork (first seen on ties) that is not invalid.
    pub fn best_header(&self) -> (Id, u64) {
        let mut best = self.tip_id();
        for l in &self.leaves {
            let (e, b) = (&self.index[l], &self.index[&best]);
            if e.status != Status::Invalid && (e.chainwork > b.chainwork || (e.chainwork == b.chainwork && e.seq < b.seq)) {
                best = *l;
            }
        }
        (best, self.index[&best].height)
    }

    /// Is `id` on the branch leading to a header chain with more work than the tip?
    fn on_heavier_branch(&self, id: &Id) -> bool {
        let h = self.index[id].height;
        let tip_work = &self.tip().chainwork;
        self.leaves.iter().any(|l| {
            let e = &self.index[l];
            e.status != Status::Invalid && e.chainwork > *tip_work && self.ancestor(l, h) == Some(*id)
        })
    }

    /// Accept a full block from `source` (None = local). Header checks first; the body is
    /// held only if it can matter, then the best chain is activated.
    pub fn accept_block(&mut self, b: Block, source: Option<u64>) -> Result<BlockOutcome, Reject> {
        let id = b.header.block_id();
        match self.accept_header(&b.header) {
            Ok(_) | Err(Reject::Duplicate) => {}
            Err(e) => return Err(e),
        }
        let e = &self.index[&id];
        if e.status == Status::Invalid {
            return Err(Reject::Invalid(Error::Invalid("known invalid")));
        }
        if self.has_data(&id) {
            return Err(Reject::Duplicate);
        }
        // context-free body check before holding anything
        if b.txs.is_empty() || varve_consensus::block::merkle_root(&b.txs.iter().map(|t| t.wtxid()).collect::<Vec<_>>()) != b.header.tx_root {
            return Err(Reject::Invalid(Error::Invalid("bad transaction root")));
        }
        // Keep the body only if it can become part of the active chain: it extends a branch
        // with more work than the tip, or it is within NEAR_TIP of the tip's work.
        let near = self.tip().chainwork.checked_sub(&near_tip_allowance(&self.tip().header.target_int())).unwrap_or_default();
        if e.chainwork < near && !self.on_heavier_branch(&id) {
            return Err(Reject::Local("block on a low-work branch; not kept".into()));
        }
        if self.pending.len() >= MAX_PENDING_BLOCKS && !self.make_room(&id) {
            return Err(Reject::Local("pending block buffer full".into()));
        }
        self.pending.insert(id, (b, source));
        let before = self.tip_id();
        let invalid = self.activate_best_chain();
        let mut out = BlockOutcome { tip_changed: self.tip_id() != before, ..Default::default() };
        out.self_invalid = invalid.contains_key(&id);
        out.bad_sources = invalid.values().filter_map(|s| *s).collect();
        out.held = self.pending.contains_key(&id);
        self.prune_pending();
        Ok(out)
    }

    /// Evict the pending block furthest ahead to make room for `incoming`, if `incoming`
    /// is lower (more urgently needed). Never refuses a block the active tip can connect.
    fn make_room(&mut self, incoming: &Id) -> bool {
        let inc_h = self.index[incoming].height;
        let h = |k: &Id| self.index.get(k).map(|e| e.height).unwrap_or(u64::MAX);
        let worst = self.pending.keys().max_by_key(|k| h(k)).copied();
        match worst {
            Some(w) if h(&w) > inc_h || self.index[incoming].header.prev_block == self.tip_id() => {
                self.pending.remove(&w);
                true
            }
            _ => false,
        }
    }

    /// Drop held bodies that can no longer matter.
    fn prune_pending(&mut self) {
        let near = self.tip().chainwork.checked_sub(&near_tip_allowance(&self.tip().header.target_int())).unwrap_or_default();
        let stale: Vec<Id> = self
            .pending
            .keys()
            .filter(|k| match self.index.get(*k) {
                None => true,
                Some(e) => e.chainwork < near && !self.on_heavier_branch(k),
            })
            .copied()
            .collect();
        for k in stale {
            self.pending.remove(&k);
        }
    }

    /// Body available: on disk (validated earlier) or held in memory.
    fn has_data(&self, id: &Id) -> bool {
        *id == self.genesis_id || self.pending.contains_key(id) || self.index.get(id).map(|e| e.file_pos.is_some()).unwrap_or(false)
    }

    fn load_block(&self, id: &Id) -> Option<Block> {
        if let Some((b, _)) = self.pending.get(id) {
            return Some(b.clone());
        }
        let pos = self.index.get(id)?.file_pos?;
        let b = Block::parse(&self.store.read_at(pos).ok()?).ok()?;
        // A stored body that no longer matches its header means local corruption (disk
        // error, partial overwrite), never an invalid block: report it as unreadable.
        if b.header.block_id() != *id || b.txs.is_empty() || varve_consensus::block::merkle_root(&b.txs.iter().map(|t| t.wtxid()).collect::<Vec<_>>()) != b.header.tx_root {
            return None;
        }
        Some(b)
    }

    /// Blocks served to peers: only validated ones (active or stored on disk), never held,
    /// unvalidated bodies (an honest peer would ban us for relaying an invalid block).
    pub fn get_block(&self, id: &Id) -> Option<Block> {
        if *id == self.genesis_id {
            return genesis_block(&self.params).ok();
        }
        let e = self.index.get(id)?;
        if e.status != Status::Valid || e.file_pos.is_none() {
            return None;
        }
        self.load_block(id)
    }

    /// blocks.md §5: the valid entry with the most chainwork, first seen on ties, whose whole
    /// branch back to the active chain has data. The current tip competes too, so an
    /// equal-work branch never replaces the first-seen chain, and a failed reorganization
    /// returns to it.
    fn best_candidate(&self, unusable: &HashSet<Id>) -> Id {
        let mut best = self.tip_id();
        for (id, e) in &self.index {
            if e.status == Status::Invalid || unusable.contains(id) || !self.has_data(id) {
                continue;
            }
            let b = &self.index[&best];
            if !(e.chainwork > b.chainwork || (e.chainwork == b.chainwork && e.seq < b.seq)) {
                continue;
            }
            if self.branch_connectable(id, unusable) {
                best = *id;
            }
        }
        best
    }

    fn branch_connectable(&self, id: &Id, unusable: &HashSet<Id>) -> bool {
        let mut cur = *id;
        while !self.is_active(&cur) {
            let Some(e) = self.index.get(&cur) else { return false };
            if e.status == Status::Invalid || unusable.contains(&cur) || !self.has_data(&cur) {
                return false;
            }
            cur = e.header.prev_block;
        }
        true
    }

    /// Reorganize to the best valid chain. Returns blocks found invalid, with their senders.
    pub fn activate_best_chain(&mut self) -> HashMap<Id, Option<u64>> {
        let mut invalid: HashMap<Id, Option<u64>> = HashMap::new();
        let mut unusable: HashSet<Id> = HashSet::new();
        for _round in 0..10_000 {
            let target = self.best_candidate(&unusable);
            if target == self.tip_id() {
                break;
            }
            let mut path = Vec::new();
            let mut cur = target;
            while !self.is_active(&cur) {
                path.push(cur);
                cur = self.index[&cur].header.prev_block;
            }
            path.reverse();
            let fork_h = self.index[&cur].height;
            while self.height() > fork_h {
                if !self.disconnect_tip() {
                    let t = self.tip_id();
                    eprintln!("[chain] cannot disconnect {} (no undo data)", varve_consensus::encoding::hex(&t));
                    return invalid;
                }
            }
            for id in path {
                let Some(b) = self.load_block(&id) else {
                    // Forget the damaged local copy so the block is fetched again from peers
                    // (missing_blocks); the block itself is not invalid.
                    eprintln!("[chain] stored copy of block {} is unreadable or corrupt; will fetch it again", varve_consensus::encoding::hex(&id));
                    if !self.pending.contains_key(&id) {
                        if let Some(e) = self.index.get_mut(&id) {
                            e.file_pos = None;
                        }
                    }
                    unusable.insert(id);
                    break;
                };
                match self.connect(&id, &b) {
                    Ok(()) => {}
                    Err(ConnectError::Invalid(e)) => {
                        eprintln!("[chain] block {} invalid: {}", varve_consensus::encoding::hex(&id), e);
                        for (bad, src) in self.mark_invalid(&id) {
                            invalid.insert(bad, src);
                        }
                        break;
                    }
                    Err(ConnectError::Local(e)) => {
                        eprintln!("[chain] cannot store block {}: {}", varve_consensus::encoding::hex(&id), e);
                        unusable.insert(id);
                        break;
                    }
                }
            }
        }
        invalid
    }

    /// Mark a block and all its descendants invalid. Returns them with their senders.
    fn mark_invalid(&mut self, id: &Id) -> Vec<(Id, Option<u64>)> {
        let mut children: HashMap<Id, Vec<Id>> = HashMap::new();
        for (k, e) in &self.index {
            children.entry(e.header.prev_block).or_default().push(*k);
        }
        let mut out = Vec::new();
        let mut stack = vec![*id];
        while let Some(k) = stack.pop() {
            if let Some(e) = self.index.get_mut(&k) {
                e.status = Status::Invalid;
            }
            let src = self.pending.remove(&k).and_then(|(_, s)| s);
            out.push((k, src));
            if let Some(cs) = children.get(&k) {
                stack.extend(cs.iter().copied());
            }
        }
        out
    }

    /// Validate and apply one block on top of the tip. The block is written to disk
    /// before the UTXO set changes, so a write failure leaves the state untouched.
    fn connect(&mut self, id: &Id, b: &Block) -> Result<(), ConnectError> {
        let height = self.index[id].height;
        let verify = !self.loading;
        let undo = check_block(b, height, &self.ids(), &self.utxo, verify).map_err(ConnectError::Invalid)?;
        if self.index[id].file_pos.is_none() {
            let pos = self.store.append(&b.serialize()).map_err(|e| ConnectError::Local(e.to_string()))?;
            self.index.get_mut(id).unwrap().file_pos = Some(pos);
        }
        for (op, _) in &undo.spent {
            self.utxo.remove(op);
        }
        for (op, coin) in &undo.created {
            self.utxo.insert(op.clone(), coin.clone());
        }
        self.idx.connect(id, height, b, &undo);
        self.undo.insert(*id, undo);
        self.active.push(*id);
        self.index.get_mut(id).unwrap().status = Status::Valid;
        self.pending.remove(id);
        Ok(())
    }

    /// Undo the tip block using its undo data (no disk read needed).
    fn disconnect_tip(&mut self) -> bool {
        let id = self.tip_id();
        if id == self.genesis_id {
            return false;
        }
        let Some(b) = self.load_block(&id) else { return false };
        let Some(undo) = self.undo.remove(&id) else { return false };
        let height = self.index[&id].height;
        self.idx.disconnect(height, &b, &undo);
        for (op, _) in &undo.created {
            self.utxo.remove(op);
        }
        for (op, coin) in undo.spent {
            self.utxo.insert(op, coin);
        }
        self.active.pop();
        true
    }

    /// Block locator: dense near the tip, then exponentially spaced, ending at genesis.
    pub fn locator(&self) -> Vec<Id> {
        let mut out = Vec::new();
        let mut h = self.height() as i64;
        let mut step = 1i64;
        while h > 0 && out.len() < 63 {
            out.push(self.active[h as usize]);
            if out.len() >= 10 {
                step *= 2;
            }
            h -= step;
        }
        out.push(self.genesis_id);
        out
    }

    /// Headers following the first locator entry found on the active chain.
    pub fn headers_after(&self, locator: &[Id], stop: &Id, max: usize) -> Vec<Header> {
        let start = locator.iter().find(|id| self.is_active(id)).map(|id| self.index[id].height).unwrap_or(0);
        let mut out = Vec::new();
        for h in (start + 1)..=self.height() {
            let id = self.active[h as usize];
            out.push(self.index[&id].header.clone());
            if out.len() >= max || id == *stop {
                break;
            }
        }
        out
    }

    /// Blocks to download (p2p.md §6): for every header chain with more work than the tip,
    /// best first, the missing bodies just above its fork point, within `window` heights.
    pub fn missing_blocks(&self, window: usize) -> Vec<Id> {
        let tip_work = self.tip().chainwork.clone();
        let mut leaves: Vec<&Id> = self.leaves.iter().filter(|l| {
            let e = &self.index[*l];
            e.status != Status::Invalid && e.chainwork > tip_work
        }).collect();
        leaves.sort_by(|a, b| self.index[*b].chainwork.cmp(&self.index[*a].chainwork).then(self.index[*a].seq.cmp(&self.index[*b].seq)));
        let mut out: Vec<Id> = Vec::new();
        let mut seen: HashSet<Id> = HashSet::new();
        for l in leaves.into_iter().take(8) {
            // fork point with the active chain
            let mut cur = *l;
            while !self.is_active(&cur) {
                cur = self.index[&cur].header.prev_block;
            }
            let fork_h = self.index[&cur].height;
            let lh = self.index[l].height;
            // walk down from the leaf to the top of the window, then collect the window
            let top = lh.min(fork_h + window as u64);
            let Some(mut c) = self.ancestor(l, top) else { continue };
            let mut branch = Vec::new();
            while self.index[&c].height > fork_h {
                branch.push(c);
                c = self.index[&c].header.prev_block;
            }
            for id in branch.into_iter().rev() {
                if !self.has_data(&id) && self.index[&id].status != Status::Invalid && seen.insert(id) {
                    out.push(id);
                }
            }
            if out.len() >= window {
                break;
            }
        }
        out.truncate(window);
        out
    }
}

enum ConnectError {
    Invalid(Error),
    Local(String),
}

/// Work of 6 blocks at `target` (p2p.md §5.3 NEAR_TIP_ALLOWANCE): near-tie forks are kept.
fn near_tip_allowance(target: &BigUint) -> BigUint {
    work(target).mul_u64(6)
}

#[cfg(test)]
mod tests {
    //! Regressions for the 2026-10-31 node review (findings 1 and 3), on regtest.
    use super::*;
    use std::sync::Arc;
    use varve_consensus::block::{merkle_root, subsidy, target_bytes};
    use varve_consensus::tx::{Output, Tx, Witness};
    use varve_sys::{RxCache, RxVm};

    fn mine(c: &Chain, vm: &mut RxVm, parent: Id, ts: u64, tag: u8, amount: u64) -> Block {
        let height = c.index[&parent].height + 1;
        let cb = Tx {
            version: 1,
            inputs: vec![OutPoint { txid: [0; 32], index: height as u32 }],
            outputs: vec![Output::single(amount, 1, [tag; 32])],
            locktime: 0,
            witnesses: vec![Witness { path: 0, public_key: vec![], signature: vec![tag] }],
        };
        let target = c.next_target_after(&parent);
        let mut h = Header { version: 1, prev_block: parent, tx_root: merkle_root(&[cb.wtxid()]), timestamp: ts, target: target_bytes(&target), nonce: 0 };
        while BigUint::from_le_bytes(&vm.hash(&h.serialize())) > target {
            h.nonce += 1;
        }
        Block { header: h, txs: vec![cb] }
    }

    fn setup(name: &str) -> (Chain, RxVm, u64) {
        let dir = std::env::temp_dir().join(format!("varve-chain-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // test-only: an easier initial target so the first block needs ~512 hashes, not ~8,000
        let mut p = varve_consensus::networks::regtest();
        p.initial_target = BigUint::pow2(247); // POW_LIMIT = 2^255 still fits in 256 bits
        let c = Chain::open(p, &dir).unwrap();
        let vm = RxVm::light(Arc::new(RxCache::new(&c.genesis_id).unwrap())).unwrap();
        (c, vm, now() - 100_000)
    }

    #[test]
    fn failed_reorg_returns_to_first_seen_chain() {
        let (mut c, mut vm, t) = setup("tie");
        let s = subsidy(1);
        let a1 = mine(&c, &mut vm, c.genesis_id, t + 1, 1, s);
        let a1id = a1.header.block_id();
        c.accept_block(a1, None).unwrap();
        let a2 = mine(&c, &mut vm, a1id, t + 2, 2, s);
        let a2id = a2.header.block_id();
        c.accept_block(a2, None).unwrap();
        let b2 = mine(&c, &mut vm, a1id, t + 3, 3, s);
        let b2id = b2.header.block_id();
        assert!(!c.accept_block(b2, None).unwrap().tip_changed, "equal work must not replace the first-seen tip");
        let b3 = mine(&c, &mut vm, b2id, t + 4, 4, s * 10); // valid PoW, invalid body
        let out = c.accept_block(b3, Some(7)).unwrap();
        assert!(out.self_invalid);
        assert_eq!(c.tip_id(), a2id, "after the failed reorg the first-seen chain must be active");
    }

    #[test]
    fn full_pending_buffer_never_blocks_the_next_block() {
        let (mut c, mut vm, t) = setup("pending");
        let s = subsidy(1);
        let a1 = mine(&c, &mut vm, c.genesis_id, t + 1, 1, s);
        let a1id = a1.header.block_id();
        c.accept_block(a1, None).unwrap();
        let a2 = mine(&c, &mut vm, a1id, t + 2, 2, s);
        let a2id = a2.header.block_id();
        c.accept_block(a2, None).unwrap();
        // fill the buffer directly with equal-work siblings (mining 256 here would be slow)
        let sibling = mine(&c, &mut vm, a1id, t + 10, 9, s);
        for i in 0..MAX_PENDING_BLOCKS {
            let mut b = sibling.clone();
            b.header.nonce = b.header.nonce.wrapping_add(1_000_000 + i as u64); // distinct ids; PoW not rechecked here
            let id = b.header.block_id();
            let mut e = c.index[&a2id].clone(); // same height and work as a sibling of A2
            e.header = b.header.clone();
            e.status = Status::HeaderValid;
            e.file_pos = None;
            c.index.insert(id, e);
            c.pending.insert(id, (b, None));
        }
        assert_eq!(c.pending.len(), MAX_PENDING_BLOCKS);
        let a3 = mine(&c, &mut vm, a2id, t + 20, 3, s);
        let out = c.accept_block(a3, None).unwrap();
        assert!(out.tip_changed && c.height() == 3, "honest block extending the tip must be accepted");
    }

    #[test]
    fn corrupt_stored_block_is_refetched_not_marked_invalid() {
        // battle test run 1: a damaged block file made the node mark an honest block
        // invalid forever and ban every peer that offered it
        let (mut c, mut vm, t) = setup("corrupt");
        let s = subsidy(1);
        let a1 = mine(&c, &mut vm, c.genesis_id, t + 1, 1, s);
        let a1id = a1.header.block_id();
        c.accept_block(a1, None).unwrap();
        let a2 = mine(&c, &mut vm, a1id, t + 2, 2, s);
        let a2id = a2.header.block_id();
        c.accept_block(a2.clone(), None).unwrap();
        let a3 = mine(&c, &mut vm, a2id, t + 3, 3, s);
        c.accept_block(a3, None).unwrap();
        assert_eq!(c.height(), 3);
        let path = c.store.path.clone();
        let params = c.params.clone();
        drop(c);
        // flip the last byte of A2's record (its coinbase extra): still parses, root mismatch
        let mut data = std::fs::read(&path).unwrap();
        let raw = a2.serialize();
        let at = data.windows(raw.len()).position(|w| w == &raw[..]).unwrap();
        data[at + raw.len() - 1] ^= 0xff;
        std::fs::write(&path, &data).unwrap();
        let mut c = Chain::open(params, path.parent().unwrap()).unwrap();
        assert_eq!(c.height(), 1, "chain stops before the damaged block");
        assert_ne!(c.index[&a2id].status, Status::Invalid, "damaged local copy must not make the block invalid");
        assert!(!c.has_data(&a2id), "the damaged copy is forgotten so it can be fetched again");
        assert!(c.missing_blocks(16).contains(&a2id), "and the node asks peers for it");
        c.accept_block(a2, Some(1)).unwrap();
        assert_eq!(c.height(), 3, "the clean copy from a peer restores the chain (A3 still on disk)");
    }
}
