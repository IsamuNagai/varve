//! Public read-only HTTP API (node/API.md) for explorers and light wallets.
//! Binds to 127.0.0.1 unless told otherwise. No wallet, mining or admin functions.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use varve_consensus::block::subsidy;
use varve_consensus::encoding::{hex, unhex};
use varve_consensus::json::Json;
use varve_consensus::params::{scheme, COINBASE_MATURITY, MAX_BLOCK_WEIGHT};
use varve_consensus::tx::{OutPoint, Output, Tx};

use crate::address;
use crate::chain::{Chain, Id};
use crate::mempool::{Mempool, MIN_RELAY_FEERATE};
use crate::node::Node;

const MAX_CONNECTIONS: usize = 64;
const MAX_LINE: u64 = 8 * 1024;
const MAX_HEADERS: usize = 48;
const MAX_TX_HEX: usize = 400_000;
const RATE: f64 = 20.0;
const BURST: f64 = 60.0;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

pub struct ApiConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub trust_proxy: bool,
}

struct Limiter {
    buckets: HashMap<IpAddr, (f64, Instant)>,
    last_sweep: Instant,
}

impl Limiter {
    fn allow(&mut self, ip: IpAddr, cost: f64) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) > Duration::from_secs(60) {
            self.buckets.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(120));
            self.last_sweep = now;
        }
        if self.buckets.len() > 100_000 && !self.buckets.contains_key(&ip) {
            return false; // pathological number of clients; refuse newcomers
        }
        let b = self.buckets.entry(ip).or_insert((BURST, now));
        b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * RATE).min(BURST);
        b.1 = now;
        if b.0 >= cost {
            b.0 -= cost;
            true
        } else {
            false
        }
    }
}

pub fn start(node: Arc<Node>, cfg: ApiConfig) -> Result<(), String> {
    let l = TcpListener::bind(SocketAddr::new(cfg.bind, cfg.port)).map_err(|e| format!("api bind {}:{}: {}", cfg.bind, cfg.port, e))?;
    eprintln!("[api] listening on {}:{}", cfg.bind, cfg.port);
    let limiter = Arc::new(Mutex::new(Limiter { buckets: HashMap::new(), last_sweep: Instant::now() }));
    let trust = cfg.trust_proxy;
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let (n, lim) = (node.clone(), limiter.clone());
            let ok = std::thread::Builder::new().spawn(move || {
                let _ = serve(&n, s, &lim, trust);
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
            });
            if ok.is_err() {
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
            }
        }
    });
    Ok(())
}

struct Resp {
    code: u16,
    body: String,
    cache: &'static str,
}

fn ok(j: Json, cache: &'static str) -> Resp {
    Resp { code: 200, body: j.to_string(), cache }
}
fn err(code: u16, msg: &str) -> Resp {
    Resp { code, body: Json::obj(vec![("error", Json::str(msg))]).to_string(), cache: "no-store" }
}

fn serve(node: &Arc<Node>, mut s: TcpStream, lim: &Mutex<Limiter>, trust_proxy: bool) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    let peer = s.peer_addr()?.ip();
    let mut r = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    (&mut r).take(MAX_LINE).read_line(&mut line)?;
    let mut len: Option<usize> = None;
    let mut fwd: Option<String> = None;
    let mut n = 0;
    loop {
        let mut h = String::new();
        if (&mut r).take(MAX_LINE).read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        n += 1;
        if n > MAX_HEADERS || !h.ends_with('\n') {
            return send(&mut s, err(400, "bad request"));
        }
        let (k, v) = h.split_once(':').unwrap_or(("", ""));
        let k = k.trim().to_ascii_lowercase();
        if k == "content-length" {
            len = Some(v.trim().parse().unwrap_or(usize::MAX));
        } else if k == "x-forwarded-for" {
            fwd = Some(v.trim().to_string());
        }
    }
    let ip = if trust_proxy {
        fwd.as_deref().and_then(|f| f.rsplit(',').next()).and_then(|x| x.trim().parse().ok()).unwrap_or(peer)
    } else {
        peer
    };
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method == "OPTIONS" {
        let msg = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 600\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        return s.write_all(msg.as_bytes());
    }
    let cost = if method == "POST" { 10.0 } else { 1.0 };
    if !lim.lock().unwrap().allow(ip, cost) {
        return send(&mut s, err(429, "rate limited"));
    }
    let resp = match method {
        "GET" | "HEAD" => get(node, target),
        "POST" if path_of(target) == "/api/v1/tx" => match len {
            None => err(411, "length required"),
            Some(l) if l > MAX_TX_HEX + 64 => err(413, "body too large"),
            Some(l) => {
                let mut body = vec![0u8; l];
                r.read_exact(&mut body)?;
                post_tx(node, &body)
            }
        },
        "POST" => err(404, "not found"),
        _ => err(405, "method not allowed"),
    };
    send(&mut s, resp)
}

fn send(s: &mut TcpStream, r: Resp) -> std::io::Result<()> {
    let reason = match r.code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let cache = match r.cache {
        "immutable" => "public, max-age=31536000, immutable",
        "short" => "public, max-age=5",
        _ => "no-store",
    };
    write!(
        s,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nCache-Control: {}\r\nConnection: close\r\n\r\n{}",
        r.code,
        reason,
        r.body.len(),
        cache,
        r.body
    )
}

fn path_of(target: &str) -> &str {
    target.split('?').next().unwrap_or("")
}

fn query(target: &str, key: &str) -> Option<String> {
    let q = target.split_once('?')?.1;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == key).then(|| v.to_string())
    })
}

fn id32(s: &str) -> Option<Id> {
    if s.len() != 64 {
        return None;
    }
    unhex(s)?.try_into().ok()
}

fn amt(v: u64) -> Json {
    Json::str(v.to_string())
}
fn amt128(v: u128) -> Json {
    Json::str(v.to_string())
}

// ------------------------------------------------------------------ GET routes

fn get(node: &Arc<Node>, target: &str) -> Resp {
    let path = path_of(target);
    let rest = match path.strip_prefix("/api/v1/") {
        Some(r) => r,
        None => return err(404, "not found"),
    };
    let segs: Vec<&str> = rest.split('/').collect();
    let chain = node.chain.lock().unwrap();
    match segs.as_slice() {
        ["info"] => {
            let mp = node.mempool.lock().unwrap();
            ok(info(&chain, &mp), "short")
        }
        ["blocks"] => blocks(&chain, target),
        ["block", id] => block(&chain, id),
        ["tx", id] => {
            let mp = node.mempool.lock().unwrap();
            tx(&chain, &mp, id)
        }
        ["address", a] => {
            let mp = node.mempool.lock().unwrap();
            address_info(&chain, &mp, a)
        }
        ["address", a, "txs"] => {
            let mp = node.mempool.lock().unwrap();
            address_txs(&chain, &mp, a, target)
        }
        ["address", a, "utxos"] => {
            let mp = node.mempool.lock().unwrap();
            address_utxos(&chain, &mp, a)
        }
        ["mempool"] => {
            let mp = node.mempool.lock().unwrap();
            mempool(&mp)
        }
        ["fees"] => {
            let mp = node.mempool.lock().unwrap();
            ok(fees(&mp), "short")
        }
        ["search"] => search(&chain, &node.mempool.lock().unwrap(), &query(target, "q").unwrap_or_default()),
        _ => err(404, "not found"),
    }
}

fn difficulty(chain: &Chain) -> String {
    // genesis target / tip target, with 8 decimals
    let g = chain.index[&chain.genesis_id].header.target_int();
    let t = chain.tip().header.target_int();
    let scaled = g.mul_u64(100_000_000).div(&t).and_then(|q| q.to_u64());
    match scaled {
        Some(v) => {
            let s = format!("{}.{:08}", v / 100_000_000, v % 100_000_000);
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        }
        None => "0".into(),
    }
}

fn info(chain: &Chain, mp: &Mempool) -> Json {
    let tip = chain.tip();
    let w: u64 = mp.txs.values().map(|e| e.weight).sum();
    let (_, best_h) = chain.best_header();
    Json::obj(vec![
        ("network", Json::str(chain.params.name)),
        ("height", Json::num(chain.height())),
        ("best", Json::str(hex(&chain.tip_id()))),
        ("time", Json::num(tip.header.timestamp)),
        ("mtp", Json::num(chain.mtp(&chain.tip_id()))),
        ("target", Json::str(tip.header.target_int().to_hex_padded(32))),
        ("difficulty", Json::str(difficulty(chain))),
        ("mempool", Json::obj(vec![("count", Json::num(mp.txs.len())), ("weight", Json::num(w))])),
        ("supply", amt128(chain.idx.issued)),
        ("genesis", Json::str(hex(&chain.genesis_id))),
        ("hrp", Json::str(chain.params.hrp)),
        ("syncing", Json::Bool(best_h > chain.height() + 2)),
        ("version", Json::str(env!("CARGO_PKG_VERSION"))),
    ])
}

fn miner_of(chain: &Chain, b: &varve_consensus::block::Block) -> Json {
    b.txs.first().and_then(|t| t.outputs.first()).map(|o| Json::str(address::encode(chain.params.hrp, o))).unwrap_or(Json::Null)
}

fn blocks(chain: &Chain, target: &str) -> Resp {
    let tip = chain.height();
    let before = query(target, "before").and_then(|v| v.parse::<u64>().ok()).unwrap_or(tip + 1).min(tip + 1);
    let limit = query(target, "limit").and_then(|v| v.parse::<u64>().ok()).unwrap_or(20).clamp(1, 50);
    let mut out = Vec::new();
    let mut h = before;
    while h > 0 && (out.len() as u64) < limit {
        h -= 1;
        let id = chain.active[h as usize];
        let Some(b) = chain.get_block(&id) else { continue };
        let reward: u64 = b.txs[0].outputs.iter().map(|o| o.amount).sum();
        let weight: u64 = b.txs.iter().enumerate().map(|(i, t)| t.weight(i == 0)).sum();
        out.push(Json::obj(vec![
            ("height", Json::num(h)),
            ("hash", Json::str(hex(&id))),
            ("time", Json::num(b.header.timestamp)),
            ("txs", Json::num(b.txs.len())),
            ("size", Json::num(b.serialize().len())),
            ("weight", Json::num(weight)),
            ("reward", amt(reward)),
            ("miner", if h == 0 { Json::Null } else { miner_of(chain, &b) }),
        ]));
    }
    ok(Json::obj(vec![("blocks", Json::Arr(out))]), "short")
}

fn resolve_block(chain: &Chain, s: &str) -> Option<Id> {
    if let Some(id) = id32(s) {
        return chain.is_active(&id).then_some(id);
    }
    if s.len() <= 12 && !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) {
        let h: usize = s.parse().ok()?;
        return chain.active.get(h).copied();
    }
    None
}

fn block(chain: &Chain, s: &str) -> Resp {
    let Some(id) = resolve_block(chain, s) else { return err(404, "block not found in the active chain") };
    let Some(b) = chain.get_block(&id) else { return err(404, "block data not available") };
    let e = &chain.index[&id];
    let h = e.height;
    let reward: u64 = b.txs[0].outputs.iter().map(|o| o.amount).sum();
    let sub = if h == 0 { 0 } else { subsidy(h) };
    let weight: u64 = b.txs.iter().enumerate().map(|(i, t)| t.weight(i == 0)).sum();
    let deep = chain.height() - h >= 100;
    ok(
        Json::obj(vec![
            ("height", Json::num(h)),
            ("hash", Json::str(hex(&id))),
            ("prev", if h == 0 { Json::Null } else { Json::str(hex(&b.header.prev_block)) }),
            ("next", chain.active.get(h as usize + 1).map(|n| Json::str(hex(n))).unwrap_or(Json::Null)),
            ("time", Json::num(b.header.timestamp)),
            ("mtp", Json::num(chain.mtp(&id))),
            ("target", Json::str(b.header.target_int().to_hex_padded(32))),
            ("nonce", Json::str(b.header.nonce.to_string())),
            ("size", Json::num(b.serialize().len())),
            ("weight", Json::num(weight)),
            ("confirmations", Json::num(chain.height() - h + 1)),
            ("reward", amt(reward)),
            ("subsidy", amt(sub)),
            ("fees", amt(reward.saturating_sub(sub))),
            ("miner", if h == 0 { Json::Null } else { miner_of(chain, &b) }),
            ("txids", Json::Arr(b.txs.iter().map(|t| Json::str(hex(&t.txid()))).collect())),
        ]),
        if deep { "immutable" } else { "short" },
    )
}

/// A transaction from the chain (with its block id and position) or the mempool.
fn find_tx(chain: &Chain, mp: &Mempool, txid: &Id) -> Option<(Tx, Option<(Id, u32)>)> {
    if let Some((bid, pos)) = chain.idx.tx.get(txid) {
        let b = chain.get_block(bid)?;
        return Some((b.txs.get(*pos as usize)?.clone(), Some((*bid, *pos))));
    }
    mp.txs.get(txid).map(|e| (e.tx.clone(), None))
}

/// The output an input spends (from the chain or the mempool).
fn prev_output(chain: &Chain, mp: &Mempool, op: &OutPoint) -> Option<Output> {
    if let Some(c) = chain.utxo.get(op) {
        return Some(c.output.clone());
    }
    let (t, _) = find_tx(chain, mp, &op.txid)?;
    t.outputs.get(op.index as usize).cloned()
}

fn scheme_name(id: u16) -> Json {
    scheme(id, 0).map(|s| Json::str(s.name)).unwrap_or(Json::str("unknown"))
}

fn tx(chain: &Chain, mp: &Mempool, s: &str) -> Resp {
    let Some(txid) = id32(s) else { return err(400, "expected a 64-character transaction id") };
    let Some((t, place)) = find_tx(chain, mp, &txid) else { return err(404, "transaction not found") };
    let coinbase = matches!(place, Some((_, 0)));
    let mut inputs = Vec::new();
    let mut in_sum: u64 = 0;
    let mut all_known = true;
    if !coinbase {
        for (i, op) in t.inputs.iter().enumerate() {
            let prev = prev_output(chain, mp, op);
            if prev.is_none() {
                all_known = false;
            }
            in_sum = in_sum.saturating_add(prev.as_ref().map(|o| o.amount).unwrap_or(0));
            inputs.push(Json::obj(vec![
                ("txid", Json::str(hex(&op.txid))),
                ("index", Json::num(op.index)),
                ("amount", prev.as_ref().map(|o| amt(o.amount)).unwrap_or(Json::Null)),
                ("address", prev.as_ref().map(|o| Json::str(address::encode(chain.params.hrp, o))).unwrap_or(Json::Null)),
                ("path", Json::num(t.witnesses[i].path)),
            ]));
        }
    }
    let out_sum: u64 = t.outputs.iter().map(|o| o.amount).sum();
    let weight = t.weight(coinbase);
    let fee = (!coinbase && all_known).then(|| in_sum.saturating_sub(out_sum));
    let outputs: Vec<Json> = t
        .outputs
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let op = OutPoint { txid, index: i as u32 };
            let spent = chain.idx.spent.get(&op).copied().or_else(|| mp.spender(&op).map(|s| {
                let inp = mp.txs.get(&s).and_then(|e| e.tx.inputs.iter().position(|x| *x == op)).unwrap_or(0) as u32;
                (s, inp)
            }));
            Json::obj(vec![
                ("index", Json::num(i)),
                ("amount", amt(o.amount)),
                ("address", Json::str(address::encode(chain.params.hrp, o))),
                ("scheme", scheme_name(o.scheme_id)),
                (
                    "recovery",
                    o.recovery.as_ref().map(|r| Json::obj(vec![("scheme", scheme_name(r.scheme_id)), ("delay", Json::num(r.delay))])).unwrap_or(Json::Null),
                ),
                (
                    "spent_by",
                    spent.map(|(s, inp)| Json::obj(vec![("txid", Json::str(hex(&s))), ("input", Json::num(inp))])).unwrap_or(Json::Null),
                ),
            ])
        })
        .collect();
    let (status, height, block, time, conf) = match place {
        Some((bid, _)) => {
            let e = &chain.index[&bid];
            ("confirmed", Json::num(e.height), Json::str(hex(&bid)), Json::num(e.header.timestamp), chain.height() - e.height + 1)
        }
        None => ("mempool", Json::Null, Json::Null, Json::Null, 0),
    };
    ok(
        Json::obj(vec![
            ("txid", Json::str(hex(&txid))),
            ("wtxid", Json::str(hex(&t.wtxid()))),
            ("status", Json::str(status)),
            ("height", height),
            ("block", block),
            ("time", time),
            ("confirmations", Json::num(conf)),
            ("coinbase", Json::Bool(coinbase)),
            ("size", Json::num(t.serialize().len())),
            ("weight", Json::num(weight)),
            ("fee", fee.map(amt).unwrap_or(Json::Null)),
            ("feerate", fee.map(|f| Json::num(format!("{:.3}", f as f64 / weight.max(1) as f64))).unwrap_or(Json::Null)),
            ("locktime", Json::num(t.locktime)),
            ("inputs", Json::Arr(inputs)),
            ("outputs", Json::Arr(outputs)),
        ]),
        if conf >= 100 { "immutable" } else { "short" },
    )
}

fn decode_addr(chain: &Chain, a: &str) -> Result<Vec<u8>, Resp> {
    if a.len() > 200 {
        return Err(err(400, "address too long"));
    }
    address::decode(chain.params.hrp, a).map(|o| o.template()).map_err(|e| err(400, &format!("invalid address: {}", e)))
}

/// Net effect of mempool transactions on a template, and the txids involved.
fn mempool_effect(chain: &Chain, mp: &Mempool, t: &[u8]) -> (i128, Vec<(Id, i128, u64, u64)>) {
    let mut total: i128 = 0;
    let mut list = Vec::new();
    for e in mp.txs.values() {
        let mut d: i128 = 0;
        let mut touched = false;
        for o in &e.tx.outputs {
            if o.template() == t {
                d += o.amount as i128;
                touched = true;
            }
        }
        for op in &e.tx.inputs {
            if let Some(p) = prev_output(chain, mp, op) {
                if p.template() == t {
                    d -= p.amount as i128;
                    touched = true;
                }
            }
        }
        if touched {
            total += d;
            list.push((e.txid, d, e.fee, e.time));
        }
    }
    list.sort_by(|a, b| b.3.cmp(&a.3));
    (total, list)
}

fn address_info(chain: &Chain, mp: &Mempool, a: &str) -> Resp {
    let t = match decode_addr(chain, a) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let canon = a.to_ascii_lowercase();
    let (unconf, _) = mempool_effect(chain, mp, &t);
    let info = chain.idx.addr.get(&t);
    let (received, sent, n, utxos) = info.map(|i| (i.received, i.sent, i.entries.len(), i.utxos.len())).unwrap_or((0, 0, 0, 0));
    let first_seen = info.and_then(|i| i.entries.first()).map(|e| {
        let time = chain.active.get(e.height as usize).map(|id| chain.index[id].header.timestamp).unwrap_or(0);
        Json::obj(vec![("height", Json::num(e.height)), ("txid", Json::str(hex(&e.txid))), ("time", Json::num(time))])
    });
    let mut funded = Vec::new();
    if let Some(i) = info {
        for e in i.entries.iter().filter(|e| e.received > e.sent).take(10) {
            let from = match find_tx(chain, mp, &e.txid) {
                Some((tx, Some((_, 0)))) => {
                    let _ = tx;
                    Json::str("coinbase")
                }
                Some((tx, _)) => tx
                    .inputs
                    .first()
                    .and_then(|op| prev_output(chain, mp, op))
                    .map(|o| Json::str(address::encode(chain.params.hrp, &o)))
                    .unwrap_or(Json::Null),
                None => Json::Null,
            };
            funded.push(Json::obj(vec![
                ("txid", Json::str(hex(&e.txid))),
                ("height", Json::num(e.height)),
                ("amount", amt(e.received - e.sent)),
                ("from", from),
            ]));
        }
    }
    ok(
        Json::obj(vec![
            ("address", Json::str(canon)),
            ("balance", amt128(received - sent)),
            ("received", amt128(received)),
            ("sent", amt128(sent)),
            ("tx_count", Json::num(n)),
            ("utxo_count", Json::num(utxos)),
            ("unconfirmed", Json::str(unconf.to_string())),
            ("first_seen", first_seen.unwrap_or(Json::Null)),
            ("funded_by", Json::Arr(funded)),
        ]),
        "no-store",
    )
}

fn address_txs(chain: &Chain, mp: &Mempool, a: &str, target: &str) -> Resp {
    let t = match decode_addr(chain, a) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let limit = query(target, "limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(25).clamp(1, 50);
    let before = query(target, "before").and_then(|v| v.parse::<u64>().ok());
    let mut out = Vec::new();
    if before.is_none() {
        let (_, list) = mempool_effect(chain, mp, &t);
        for (txid, d, fee, _) in list.into_iter().take(limit) {
            out.push(Json::obj(vec![
                ("txid", Json::str(hex(&txid))),
                ("height", Json::Null),
                ("time", Json::Null),
                ("delta", Json::str(d.to_string())),
                ("fee", amt(fee)),
            ]));
        }
    }
    let mut next = Json::Null;
    if let Some(info) = chain.idx.addr.get(&t) {
        let cut = before.unwrap_or(u64::MAX);
        let mut iter = info.entries.iter().rev().filter(|e| e.height < cut).peekable();
        let mut last_h = None;
        while out.len() < limit {
            let Some(e) = iter.next() else { break };
            // keep whole heights on one page so `before` paging never skips entries
            last_h = Some(e.height);
            let time = chain.active.get(e.height as usize).map(|id| chain.index[id].header.timestamp).unwrap_or(0);
            out.push(Json::obj(vec![
                ("txid", Json::str(hex(&e.txid))),
                ("height", Json::num(e.height)),
                ("time", Json::num(time)),
                ("delta", Json::str((e.received as i128 - e.sent as i128).to_string())),
                ("fee", Json::Null),
            ]));
        }
        while let (Some(h), Some(e)) = (last_h, iter.peek()) {
            if e.height != h {
                break;
            }
            let e = iter.next().unwrap();
            let time = chain.active.get(e.height as usize).map(|id| chain.index[id].header.timestamp).unwrap_or(0);
            out.push(Json::obj(vec![
                ("txid", Json::str(hex(&e.txid))),
                ("height", Json::num(e.height)),
                ("time", Json::num(time)),
                ("delta", Json::str((e.received as i128 - e.sent as i128).to_string())),
                ("fee", Json::Null),
            ]));
        }
        if iter.peek().is_some() {
            if let Some(h) = last_h {
                next = Json::num(h);
            }
        }
    }
    ok(Json::obj(vec![("txs", Json::Arr(out)), ("next", next)]), "no-store")
}

fn address_utxos(chain: &Chain, mp: &Mempool, a: &str) -> Resp {
    let t = match decode_addr(chain, a) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let tip = chain.height();
    let mut coins: Vec<(OutPoint, varve_consensus::validate::Coin)> = chain
        .idx
        .addr
        .get(&t)
        .map(|i| i.utxos.iter().filter_map(|op| chain.utxo.get(op).map(|c| (op.clone(), c.clone()))).collect())
        .unwrap_or_default();
    coins.sort_by(|a, b| b.1.output.amount.cmp(&a.1.output.amount).then(a.0.cmp(&b.0)));
    coins.truncate(1000);
    let list: Vec<Json> = coins
        .into_iter()
        .map(|(op, c)| {
            Json::obj(vec![
                ("txid", Json::str(hex(&op.txid))),
                ("index", Json::num(op.index)),
                ("amount", amt(c.output.amount)),
                ("height", Json::num(c.height)),
                ("coinbase", Json::Bool(c.coinbase)),
                ("mature", Json::Bool(!c.coinbase || tip + 1 >= c.height + COINBASE_MATURITY)),
                ("spent_in_mempool", Json::Bool(mp.spender(&op).is_some())),
                ("output", Json::str(hex(&c.output.serialize()))),
            ])
        })
        .collect();
    ok(Json::obj(vec![("height", Json::num(tip)), ("utxos", Json::Arr(list))]), "no-store")
}

fn mempool(mp: &Mempool) -> Resp {
    let mut v: Vec<_> = mp.txs.values().collect();
    v.sort_by(|a, b| (b.fee as u128 * a.weight as u128).cmp(&(a.fee as u128 * b.weight as u128)));
    let w: u64 = mp.txs.values().map(|e| e.weight).sum();
    let list: Vec<Json> = v
        .into_iter()
        .take(100)
        .map(|e| {
            Json::obj(vec![
                ("txid", Json::str(hex(&e.txid))),
                ("fee", amt(e.fee)),
                ("weight", Json::num(e.weight)),
                ("feerate", Json::num(format!("{:.3}", e.fee as f64 / e.weight.max(1) as f64))),
                ("time", Json::num(e.time)),
            ])
        })
        .collect();
    ok(Json::obj(vec![("count", Json::num(mp.txs.len())), ("weight", Json::num(w)), ("txs", Json::Arr(list))]), "short")
}

fn fees(mp: &Mempool) -> Json {
    // fee rate needed to be within the next block / next three blocks of waiting transactions
    let mut v: Vec<(f64, u64)> = mp.txs.values().map(|e| (e.fee as f64 / e.weight.max(1) as f64, e.weight)).collect();
    v.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let rate_at = |depth: u64| -> u64 {
        let mut w = 0u64;
        for (r, wt) in &v {
            w += wt;
            if w >= depth {
                return (r.ceil() as u64 + 1).max(MIN_RELAY_FEERATE);
            }
        }
        MIN_RELAY_FEERATE
    };
    let fast = rate_at(MAX_BLOCK_WEIGHT / 2).max(MIN_RELAY_FEERATE * 2);
    let normal = rate_at(MAX_BLOCK_WEIGHT).max(MIN_RELAY_FEERATE);
    let slow = rate_at(MAX_BLOCK_WEIGHT * 3).max(MIN_RELAY_FEERATE);
    Json::obj(vec![
        ("min", Json::num(MIN_RELAY_FEERATE)),
        ("slow", Json::num(slow)),
        ("normal", Json::num(normal.max(slow))),
        ("fast", Json::num(fast.max(normal))),
    ])
}

fn search(chain: &Chain, mp: &Mempool, q: &str) -> Resp {
    let q = q.trim();
    if q.is_empty() || q.len() > 200 {
        return err(400, "empty or too long query");
    }
    if q.bytes().all(|c| c.is_ascii_digit()) && q.len() <= 12 {
        if let Some(id) = resolve_block(chain, q) {
            return ok(Json::obj(vec![("type", Json::str("block")), ("id", Json::str(hex(&id)))]), "no-store");
        }
        return err(404, "no block at that height");
    }
    if let Some(id) = id32(&q.to_ascii_lowercase()) {
        if chain.is_active(&id) {
            return ok(Json::obj(vec![("type", Json::str("block")), ("id", Json::str(hex(&id)))]), "no-store");
        }
        if find_tx(chain, mp, &id).is_some() {
            return ok(Json::obj(vec![("type", Json::str("tx")), ("id", Json::str(hex(&id)))]), "no-store");
        }
        return err(404, "no block or transaction with that id");
    }
    if address::decode(chain.params.hrp, q).is_ok() {
        return ok(Json::obj(vec![("type", Json::str("address")), ("id", Json::str(q.to_ascii_lowercase()))]), "no-store");
    }
    err(404, "nothing found")
}

fn post_tx(node: &Arc<Node>, body: &[u8]) -> Resp {
    let Ok(text) = std::str::from_utf8(body) else { return err(400, "body must be hex text") };
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_TX_HEX {
        return err(400, "body must be hex text of at most 400,000 characters");
    }
    let Some(raw) = unhex(text) else { return err(400, "body must be hex text") };
    let t = match Tx::from_bytes(&raw) {
        Ok(t) => t,
        Err(e) => return err(400, &e.to_string()),
    };
    match node.submit_tx(t, None) {
        Ok(txid) => ok(Json::obj(vec![("txid", Json::str(hex(&txid)))]), "no-store"),
        Err(e) => err(400, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing() {
        assert_eq!(query("/x?before=5&limit=3", "limit").as_deref(), Some("3"));
        assert_eq!(query("/x?before=5", "limit"), None);
        assert_eq!(path_of("/api/v1/blocks?before=1"), "/api/v1/blocks");
        assert!(id32("zz").is_none());
        assert!(id32(&"a".repeat(64)).is_some());
        assert!(id32(&"g".repeat(64)).is_none());
    }

    #[test]
    fn limiter_bounds_bursts() {
        let mut l = Limiter { buckets: HashMap::new(), last_sweep: Instant::now() };
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut allowed = 0;
        for _ in 0..200 {
            if l.allow(ip, 1.0) {
                allowed += 1;
            }
        }
        assert!(allowed >= 60 && allowed < 70, "burst {}", allowed);
        assert!(l.allow("10.0.0.2".parse().unwrap(), 10.0));
    }
}
