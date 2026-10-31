//! Peers, connection management, sync and relay (p2p.md subset; see node/README.md).

use std::collections::{HashMap, HashSet};
use std::io::BufReader;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;


use crate::chain::{now, Id, Reject, BLOCK_DOWNLOAD_WINDOW};
use crate::node::{Node, Submit};
use crate::wire::*;

const BAN_SECS: u64 = 24 * 3600;
const BLOCKS_IN_FLIGHT_PER_PEER: usize = 16;
const BLOCK_TIMEOUT_SECS: u64 = 600;
const HANDSHAKE_SECS: u64 = 60;
const PING_SECS: u64 = 120;
const PING_TIMEOUT_SECS: u64 = 20 * 60;
const MAX_ADDRS: usize = 10_000;
const SEND_QUEUE: usize = 4096;
/// p2p.md §11: per-peer send buffer; reading from the peer pauses while it is exceeded.
const SEND_BUFFER_BYTES: usize = 5_000_000;

pub struct PeerHandle {
    pub addr: SocketAddr,
    pub outbound: bool,
    tx: SyncSender<(Msg, usize)>,
    stream: TcpStream,
    pub version: Option<Version>,
    pub handshake_done: bool,
    pub relay_tx: bool,
    pub connected_at: u64,
    pub last_recv: u64,
    /// outstanding ping: (nonce, sent at)
    pub ping_out: Option<(u64, u64)>,
    pub last_rtt: Option<u64>,
    /// bytes queued for this peer's writer
    queued: Arc<AtomicUsize>,
    pub inflight: HashSet<Id>,
    pub sent_getaddr_reply: bool,
    pub orphan_headers: u32,
}

#[derive(Default)]
pub struct Peers {
    pub map: HashMap<u64, PeerHandle>,
    next_id: u64,
    pub addrs: HashMap<SocketAddr, u64>,
    pub banned: HashMap<IpAddr, u64>,
    failed: HashMap<SocketAddr, u64>,
    pub inflight: HashMap<Id, (u64, u64)>,
    local_nonces: HashSet<u64>,
}

impl Peers {
    pub fn count(&self) -> usize {
        self.map.len()
    }
    fn send(&self, id: u64, m: Msg) {
        if let Some(p) = self.map.get(&id) {
            let n = m.payload_len_hint();
            p.queued.fetch_add(n, Ordering::SeqCst);
            if let Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) = p.tx.try_send((m, n)) {
                p.queued.fetch_sub(n, Ordering::SeqCst);
                let _ = p.stream.shutdown(Shutdown::Both);
            }
        }
    }
    /// Bytes queued for a peer (None if gone).
    fn queued(&self, id: u64) -> Option<usize> {
        self.map.get(&id).map(|p| p.queued.load(Ordering::SeqCst))
    }
    pub fn broadcast(&self, m: &Msg, except: Option<u64>) {
        for (id, p) in &self.map {
            if Some(*id) != except && p.handshake_done {
                self.send(*id, m.clone());
            }
        }
    }
    pub fn broadcast_tx_inv(&self, m: &Msg, except: Option<u64>) {
        for (id, p) in &self.map {
            if Some(*id) != except && p.handshake_done && p.relay_tx {
                self.send(*id, m.clone());
            }
        }
    }
    fn is_banned(&mut self, ip: &IpAddr) -> bool {
        match self.banned.get(ip) {
            Some(&until) if until > now() => true,
            Some(_) => {
                self.banned.remove(ip);
                false
            }
            None => false,
        }
    }
    fn disconnect(&mut self, id: u64, ban: Option<&str>) {
        if let Some(p) = self.map.get(&id) {
            if let Some(why) = ban {
                // never ban loopback (local tools and tests)
                if !p.addr.ip().is_loopback() {
                    self.banned.insert(p.addr.ip(), now() + BAN_SECS);
                }
                eprintln!("[p2p] banning {}: {}", p.addr, why);
            }
            let _ = p.stream.shutdown(Shutdown::Both);
        }
    }
    pub fn ban_peer(&mut self, id: u64, why: &str) {
        self.disconnect(id, Some(why));
    }
    fn remove(&mut self, id: u64) {
        if let Some(p) = self.map.remove(&id) {
            for b in p.inflight {
                self.inflight.remove(&b);
            }
        }
    }
    pub fn info(&self) -> Vec<(u64, SocketAddr, bool, Option<Version>, u64, Option<u64>)> {
        self.map.iter().map(|(id, p)| (*id, p.addr, p.outbound, p.version.clone(), p.connected_at, p.last_rtt)).collect()
    }
}

/// Start the listener, connection manager and housekeeping threads.
pub fn start(node: Arc<Node>) {
    if let Some(addr) = node.cfg.listen {
        match TcpListener::bind(addr) {
            Ok(l) => {
                eprintln!("[p2p] listening on {}", addr);
                let n = node.clone();
                std::thread::spawn(move || listen_loop(n, l));
            }
            Err(e) => eprintln!("[p2p] cannot listen on {}: {}", addr, e),
        }
    }
    {
        let mut peers = node.peers.lock().unwrap();
        let path = node.cfg.datadir.join("peers.txt");
        if let Ok(s) = std::fs::read_to_string(path) {
            for l in s.lines() {
                if let Ok(a) = l.trim().parse::<SocketAddr>() {
                    peers.addrs.insert(a, 0);
                }
            }
        }
    }
    let n = node.clone();
    std::thread::spawn(move || connman_loop(n));
    let n = node.clone();
    std::thread::spawn(move || housekeeping_loop(n));
}

fn listen_loop(node: Arc<Node>, l: TcpListener) {
    for s in l.incoming() {
        if !node.running() {
            return;
        }
        let Ok(s) = s else { continue };
        let Ok(addr) = s.peer_addr() else { continue };
        {
            let mut peers = node.peers.lock().unwrap();
            let inbound = peers.map.values().filter(|p| !p.outbound).count();
            if peers.is_banned(&addr.ip()) || inbound >= node.cfg.max_inbound {
                let _ = s.shutdown(Shutdown::Both);
                continue;
            }
        }
        let n = node.clone();
        std::thread::spawn(move || run_peer(n, s, addr, false));
    }
}

fn resolve(s: &str, default_port: u16) -> Vec<SocketAddr> {
    let with_port = if s.parse::<SocketAddr>().is_ok() || s.rsplit_once(':').map(|(_, p)| p.parse::<u16>().is_ok()).unwrap_or(false) {
        s.to_string()
    } else {
        format!("{}:{}", s, default_port)
    };
    with_port.to_socket_addrs().map(|i| i.collect()).unwrap_or_default()
}

fn connman_loop(node: Arc<Node>) {
    let port = node.chain.lock().unwrap().params.default_port;
    while node.running() {
        let (outbound, connected): (usize, HashSet<SocketAddr>) = {
            let p = node.peers.lock().unwrap();
            (p.map.values().filter(|x| x.outbound).count(), p.map.values().map(|x| x.addr).collect())
        };
        if outbound < node.cfg.max_outbound {
            let mut candidates: Vec<SocketAddr> = Vec::new();
            let fixed: Vec<String> = if node.cfg.connect.is_empty() { node.cfg.seeds.clone() } else { node.cfg.connect.clone() };
            for s in &fixed {
                candidates.extend(resolve(s, port));
            }
            if node.cfg.connect.is_empty() {
                let p = node.peers.lock().unwrap();
                let mut learned: Vec<SocketAddr> = p.addrs.keys().copied().collect();
                learned.sort_by_key(|a| std::cmp::Reverse(p.addrs[a]));
                candidates.extend(learned.into_iter().take(64));
            }
            let mut p = node.peers.lock().unwrap();
            let t = now();
            let pick = candidates.into_iter().find(|a| {
                !connected.contains(a) && !p.is_banned(&a.ip()) && p.failed.get(a).map(|&f| t > f + 60).unwrap_or(true)
            });
            if let Some(a) = pick {
                p.failed.insert(a, t); // cleared on success
                drop(p);
                let n = node.clone();
                std::thread::spawn(move || match TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
                    Ok(s) => run_peer(n, s, a, true),
                    Err(_) => {}
                });
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn housekeeping_loop(node: Arc<Node>) {
    let mut last_save = now();
    while node.running() {
        std::thread::sleep(Duration::from_secs(2));
        let t = now();
        let ids: Vec<u64> = {
            let mut p = node.peers.lock().unwrap();
            // block request timeouts: disconnect without ban, re-request elsewhere
            let expired: Vec<(Id, u64)> = p.inflight.iter().filter(|(_, (_, at))| t > at + BLOCK_TIMEOUT_SECS).map(|(b, (pid, _))| (*b, *pid)).collect();
            for (b, pid) in expired {
                p.inflight.remove(&b);
                p.disconnect(pid, None);
            }
            let mut pings = Vec::new();
            for (id, peer) in p.map.iter_mut() {
                if !peer.handshake_done && t > peer.connected_at + HANDSHAKE_SECS {
                    let _ = peer.stream.shutdown(Shutdown::Both);
                } else if peer.handshake_done {
                    match peer.ping_out {
                        Some((_, sent)) if t > sent + PING_TIMEOUT_SECS => {
                            let _ = peer.stream.shutdown(Shutdown::Both); // unanswered ping
                        }
                        None if t > peer.last_recv + PING_SECS => {
                            let nonce = rand_u64();
                            peer.ping_out = Some((nonce, t));
                            pings.push((*id, nonce));
                        }
                        _ => {}
                    }
                }
            }
            for (id, n) in pings {
                p.send(id, Msg::Ping(n));
            }
            p.map.iter().filter(|(_, x)| x.handshake_done).map(|(id, _)| *id).collect()
        };
        for id in ids {
            request_blocks(&node, id);
        }
        if t > last_save + 300 {
            last_save = t;
            let p = node.peers.lock().unwrap();
            let s: String = p.addrs.keys().take(1000).map(|a| format!("{}\n", a)).collect();
            let _ = std::fs::write(node.cfg.datadir.join("peers.txt"), s);
        }
    }
}

pub fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    varve_sys::random_bytes(&mut b);
    u64::from_le_bytes(b)
}

fn run_peer(node: Arc<Node>, stream: TcpStream, addr: SocketAddr, outbound: bool) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(PING_TIMEOUT_SECS + 60)));
    let (magic, genesis_id, height) = {
        let c = node.chain.lock().unwrap();
        (c.params.network_id, c.genesis_id, c.height())
    };
    let (tx, rx) = sync_channel::<(Msg, usize)>(SEND_QUEUE);
    let queued = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicBool::new(false));
    let nonce = rand_u64();
    let id = {
        let mut p = node.peers.lock().unwrap();
        p.next_id += 1;
        let id = p.next_id;
        p.local_nonces.insert(nonce);
        let Ok(s2) = stream.try_clone() else { return };
        p.map.insert(
            id,
            PeerHandle {
                addr,
                outbound,
                tx: tx.clone(),
                stream: s2,
                version: None,
                handshake_done: false,
                relay_tx: false,
                connected_at: now(),
                last_recv: now(),
                ping_out: None,
                last_rtt: None,
                queued: queued.clone(),
                inflight: HashSet::new(),
                sent_getaddr_reply: false,
                orphan_headers: 0,
            },
        );
        id
    };
    // writer thread
    let Ok(mut ws) = stream.try_clone() else { return };
    let wq = queued.clone();
    let wc = closed.clone();
    let writer = std::thread::spawn(move || {
        while let Ok((m, n)) = rx.recv() {
            let r = write_msg(&mut ws, &magic, &m);
            let _ = wq.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |q| Some(q.saturating_sub(n)));
            if r.is_err() {
                let _ = ws.shutdown(Shutdown::Both);
                break;
            }
        }
        wc.store(true, Ordering::SeqCst);
    });
    let ver = Version {
        version: PROTOCOL_VERSION,
        services: NODE_NETWORK,
        timestamp: now(),
        nonce,
        user_agent: node.cfg.user_agent.clone(),
        best_height: height,
        genesis_id,
        ruleset_hash: ruleset_hash(),
        relay: true,
    };
    queued.fetch_add(400, Ordering::SeqCst); // accounted like every other send
    let _ = tx.try_send((Msg::Version(ver), 400));
    let mut reader = BufReader::with_capacity(64 * 1024, stream);
    let mut got_version = false;
    let mut got_verack = false;
    loop {
        if !node.running() || closed.load(Ordering::SeqCst) {
            break;
        }
        // p2p.md §11: stop reading while this peer's send buffer is over its limit
        while queued.load(Ordering::SeqCst) > SEND_BUFFER_BYTES && !closed.load(Ordering::SeqCst) && node.running() {
            std::thread::sleep(Duration::from_millis(50));
        }
        let m = match read_msg(&mut reader, &magic) {
            Ok(m) => m,
            Err(FrameError::Io(_)) => break,
            Err(FrameError::Disconnect(why)) => {
                eprintln!("[p2p] {} disconnect: {}", addr, why);
                break;
            }
            Err(FrameError::Violation(why)) => {
                node.peers.lock().unwrap().disconnect(id, Some(&why));
                break;
            }
        };
        node.peers.lock().unwrap().map.get_mut(&id).map(|p| p.last_recv = now());
        // handshake (p2p.md §3)
        match (&m, got_version, got_verack) {
            (Msg::Version(v), false, _) => {
                if v.genesis_id != genesis_id {
                    eprintln!("[p2p] {} is on a different chain", addr);
                    break;
                }
                if node.peers.lock().unwrap().local_nonces.contains(&v.nonce) {
                    break; // connected to ourselves
                }
                if v.ruleset_hash != ruleset_hash() {
                    eprintln!("[p2p] {} runs a different rule set (upgrades.md §4); staying connected", addr);
                }
                got_version = true;
                {
                    let mut p = node.peers.lock().unwrap();
                    if let Some(ph) = p.map.get_mut(&id) {
                        ph.version = Some(v.clone());
                        ph.relay_tx = v.relay;
                    }
                }
                queued.fetch_add(24, Ordering::SeqCst);
                let _ = tx.try_send((Msg::Verack, 24));
                continue;
            }
            (Msg::Version(_), true, _) => {
                node.peers.lock().unwrap().disconnect(id, Some("second version"));
                break;
            }
            (Msg::Verack, true, false) => {
                got_verack = true;
                let mut p = node.peers.lock().unwrap();
                if let Some(ph) = p.map.get_mut(&id) {
                    ph.handshake_done = true;
                }
                if outbound {
                    p.failed.remove(&addr);
                    p.addrs.insert(addr, now());
                    p.send(id, Msg::GetAddr);
                }
                drop(p);
                let loc = node.chain.lock().unwrap().locator();
                node.peers.lock().unwrap().send(id, Msg::GetHeaders { locator: loc, stop: [0u8; 32] });
                eprintln!("[p2p] connected {} {} ({})", if outbound { "to" } else { "from" }, addr, node.peer_count());
                continue;
            }
            (_, true, true) => {}
            _ => {
                node.peers.lock().unwrap().disconnect(id, Some("message before handshake"));
                break;
            }
        }
        if let Err(why) = handle(&node, id, outbound, m) {
            node.peers.lock().unwrap().disconnect(id, Some(&why));
            break;
        }
    }
    {
        let mut p = node.peers.lock().unwrap();
        p.local_nonces.remove(&nonce);
        p.remove(id);
    }
    drop(tx);
    let _ = writer.join();
}

/// Hash of the upgrade documents this node implements (upgrades.md §4). v1: none.
pub fn ruleset_hash() -> [u8; 32] {
    varve_consensus::encoding::h256("VARVE/ruleset/v1", b"")
}

/// Handle one post-handshake message. Err = ban-worthy violation.
fn handle(node: &Arc<Node>, id: u64, outbound: bool, m: Msg) -> Result<(), String> {
    match m {
        Msg::Ping(n) => node.peers.lock().unwrap().send(id, Msg::Pong(n)),
        Msg::Pong(n) => {
            let mut p = node.peers.lock().unwrap();
            if let Some(ph) = p.map.get_mut(&id) {
                if let Some((want, sent)) = ph.ping_out {
                    if want == n {
                        ph.ping_out = None;
                        ph.last_rtt = Some(now().saturating_sub(sent));
                    }
                }
            }
        }
        Msg::GetAddr => {
            let mut p = node.peers.lock().unwrap();
            let allowed = p.map.get(&id).map(|x| !x.outbound && !x.sent_getaddr_reply).unwrap_or(false);
            if allowed {
                p.map.get_mut(&id).unwrap().sent_getaddr_reply = true;
                let list: Vec<AddrEntry> = p.addrs.iter().take(MAX_ADDR).map(|(a, t)| AddrEntry { time: *t, services: NODE_NETWORK, addr: *a }).collect();
                p.send(id, Msg::Addr(list));
            }
        }
        Msg::Addr(list) => {
            let mut p = node.peers.lock().unwrap();
            for a in list.into_iter().take(MAX_ADDR) {
                if p.addrs.len() < MAX_ADDRS && a.addr.port() != 0 && !a.addr.ip().is_unspecified() {
                    p.addrs.entry(a.addr).or_insert(a.time.min(now()));
                }
            }
        }
        Msg::GetHeaders { locator, stop } => {
            let hs = node.chain.lock().unwrap().headers_after(&locator, &stop, MAX_HEADERS);
            node.peers.lock().unwrap().send(id, Msg::Headers(hs));
        }
        Msg::Headers(hs) => {
            for w in hs.windows(2) {
                if w[1].prev_block != w[0].block_id() {
                    return Err("non-linking headers".into());
                }
            }
            let full = hs.len() == MAX_HEADERS;
            let last = hs.last().map(|h| h.block_id());
            let mut ask_more = full;
            let mut chain = node.chain.lock().unwrap();
            for (i, h) in hs.iter().enumerate() {
                match chain.accept_header(h) {
                    Ok(_) | Err(Reject::Duplicate) => {}
                    Err(Reject::Orphan) if i == 0 => {
                        let loc = chain.locator();
                        drop(chain);
                        let mut p = node.peers.lock().unwrap();
                        let n = p.map.get_mut(&id).map(|x| {
                            x.orphan_headers += 1;
                            x.orphan_headers
                        });
                        if n.unwrap_or(0) > 10 {
                            p.disconnect(id, None);
                        } else {
                            p.send(id, Msg::GetHeaders { locator: loc, stop: [0u8; 32] });
                        }
                        return Ok(());
                    }
                    Err(Reject::Orphan) => return Err("headers do not connect".into()),
                    Err(Reject::Deferred) => {
                        ask_more = false;
                        break;
                    }
                    Err(Reject::Invalid(e)) => return Err(format!("invalid header: {}", e)),
                    Err(Reject::Local(e)) => {
                        eprintln!("[p2p] local error on header: {}", e);
                        ask_more = false;
                        break;
                    }
                }
            }
            drop(chain);
            if let Some(ph) = node.peers.lock().unwrap().map.get_mut(&id) {
                ph.orphan_headers = 0;
            }
            if ask_more {
                if let Some(l) = last {
                    let mut loc = vec![l];
                    loc.extend(node.chain.lock().unwrap().locator().into_iter().take(MAX_LOCATOR - 1));
                    node.peers.lock().unwrap().send(id, Msg::GetHeaders { locator: loc, stop: [0u8; 32] });
                }
            }
            request_blocks(node, id);
        }
        Msg::Inv(items) => {
            let mut want = Vec::new();
            let mut ask_headers = false;
            {
                let mp = node.mempool.lock().unwrap();
                for (t, h) in items {
                    if t == INV_TX && !mp.contains_wtxid(&h) && want.len() < 100 {
                        want.push((t, h));
                    } else if t == INV_BLOCK {
                        ask_headers = true;
                    }
                }
            }
            if ask_headers {
                let loc = node.chain.lock().unwrap().locator();
                node.peers.lock().unwrap().send(id, Msg::GetHeaders { locator: loc, stop: [0u8; 32] });
            }
            if !want.is_empty() {
                node.peers.lock().unwrap().send(id, Msg::GetData(want));
            }
        }
        Msg::GetData(items) => {
            let mut notfound = Vec::new();
            for (t, h) in items {
                // pause while the send buffer is full; stop if the peer is gone
                loop {
                    match node.peers.lock().unwrap().queued(id) {
                        None => return Ok(()),
                        Some(q) if q > SEND_BUFFER_BYTES => {}
                        Some(_) => break,
                    }
                    if !node.running() {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let found = match t {
                    INV_BLOCK => node.chain.lock().unwrap().get_block(&h).map(Msg::Block),
                    INV_TX => node.mempool.lock().unwrap().get_by_wtxid(&h).map(|e| Msg::Tx(e.tx.clone())),
                    _ => None,
                };
                match found {
                    Some(m) => node.peers.lock().unwrap().send(id, m),
                    None => notfound.push((t, h)),
                }
            }
            if !notfound.is_empty() {
                node.peers.lock().unwrap().send(id, Msg::NotFound(notfound));
            }
        }
        Msg::NotFound(items) => {
            let mut p = node.peers.lock().unwrap();
            for (_, h) in items {
                if p.inflight.get(&h).map(|x| x.0) == Some(id) {
                    p.inflight.remove(&h);
                    if let Some(ph) = p.map.get_mut(&id) {
                        ph.inflight.remove(&h);
                    }
                }
            }
        }
        Msg::Block(b) => {
            let bid = b.header.block_id();
            {
                let mut p = node.peers.lock().unwrap();
                p.inflight.remove(&bid);
                if let Some(ph) = p.map.get_mut(&id) {
                    ph.inflight.remove(&bid);
                }
            }
            match node.submit_block(b, Some(id)) {
                Submit::Accepted { .. } => {}
                Submit::Rejected(why) if why.starts_with("invalid") => return Err(why),
                Submit::Rejected(why) if why.starts_with("orphan") => {
                    let loc = node.chain.lock().unwrap().locator();
                    node.peers.lock().unwrap().send(id, Msg::GetHeaders { locator: loc, stop: [0u8; 32] });
                }
                Submit::Rejected(_) => {}
            }
            request_blocks(node, id);
        }
        Msg::Tx(t) => {
            if let Err(e) = node.submit_tx(t, Some(id)) {
                // policy rejections are never penalized (p2p.md §10.4); bad signatures could be,
                // but this node only drops them for now
                if e.contains("bad signature") {
                    eprintln!("[p2p] peer {} relayed a transaction with a bad signature", id);
                }
            }
        }
        Msg::FeeFilter(_) | Msg::Unknown(_) => {}
        Msg::Version(_) | Msg::Verack => return Err("unexpected handshake message".into()),
    }
    let _ = outbound;
    Ok(())
}

/// Ask a peer for missing blocks on the best header chain (p2p.md §6).
fn request_blocks(node: &Arc<Node>, id: u64) {
    let missing = node.chain.lock().unwrap().missing_blocks(BLOCK_DOWNLOAD_WINDOW);
    if missing.is_empty() {
        return;
    }
    let mut p = node.peers.lock().unwrap();
    let have = p.map.get(&id).map(|x| x.inflight.len()).unwrap_or(BLOCKS_IN_FLIGHT_PER_PEER);
    let mut req = Vec::new();
    for b in missing {
        if have + req.len() >= BLOCKS_IN_FLIGHT_PER_PEER {
            break;
        }
        if !p.inflight.contains_key(&b) {
            req.push(b);
        }
    }
    if req.is_empty() {
        return;
    }
    let t = now();
    for b in &req {
        p.inflight.insert(*b, (id, t));
        if let Some(ph) = p.map.get_mut(&id) {
            ph.inflight.insert(*b);
        }
    }
    p.send(id, Msg::GetData(req.into_iter().map(|b| (INV_BLOCK, b)).collect()));
}

