//! Local JSON-RPC over HTTP. Binds to 127.0.0.1 only and requires the cookie in
//! `<datadir>/.cookie` (HTTP Basic auth, user "__cookie__"). Never expose this port.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use varve_consensus::block::Block;
use varve_consensus::encoding::{hex, unhex};
use varve_consensus::json::Json;
use varve_consensus::tx::Tx;

use crate::address;
use crate::chain::{now, Id};
use crate::miner::MinerStats;
use crate::node::{Node, Submit};

pub const COOKIE_USER: &str = "__cookie__";
const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_LINE: u64 = 8 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_CONNECTIONS: usize = 16;
static ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn start(node: Arc<Node>, miner: Option<Arc<MinerStats>>) -> Result<(), String> {
    let mut secret = [0u8; 32];
    varve_sys::random_bytes(&mut secret);
    let cookie = format!("{}:{}", COOKIE_USER, hex(&secret));
    crate::wallet::write_private(&node.cfg.datadir.join(".cookie"), cookie.as_bytes())?;
    let l = TcpListener::bind(("127.0.0.1", node.cfg.rpc_port)).map_err(|e| format!("rpc bind 127.0.0.1:{}: {}", node.cfg.rpc_port, e))?;
    eprintln!("[rpc] listening on 127.0.0.1:{}", node.cfg.rpc_port);
    let expected = format!("Basic {}", base64(cookie.as_bytes()));
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
                continue; // drops the connection
            }
            let (n, e, m) = (node.clone(), expected.clone(), miner.clone());
            let spawned = std::thread::Builder::new().spawn(move || {
                let _ = serve(n, s, &e, m);
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
            });
            if spawned.is_err() {
                ACTIVE.fetch_sub(1, Ordering::SeqCst);
            }
        }
    });
    Ok(())
}

fn serve(node: Arc<Node>, mut s: TcpStream, expected_auth: &str, miner: Option<Arc<MinerStats>>) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    (&mut r).take(MAX_LINE).read_line(&mut line)?;
    let mut len = 0usize;
    let mut auth_ok = false;
    let mut n_headers = 0;
    loop {
        let mut h = String::new();
        if (&mut r).take(MAX_LINE).read_line(&mut h)? == 0 || h == "\r\n" || h == "\n" {
            break;
        }
        n_headers += 1;
        if n_headers > MAX_HEADERS || !h.ends_with('\n') {
            return respond(&mut s, 400, "{\"error\":\"bad request\"}");
        }
        let (k, v) = h.split_once(':').unwrap_or(("", ""));
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            len = v.parse().unwrap_or(usize::MAX);
        } else if k == "authorization" {
            auth_ok = constant_time_eq(v.as_bytes(), expected_auth.as_bytes());
        }
    }
    if !line.starts_with("POST ") {
        return respond(&mut s, 405, "{\"error\":\"POST only\"}");
    }
    if !auth_ok {
        std::thread::sleep(Duration::from_millis(250));
        return respond(&mut s, 401, "{\"error\":\"unauthorized\"}");
    }
    if len > MAX_BODY {
        return respond(&mut s, 413, "{\"error\":\"too large\"}");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let req = match Json::parse(&String::from_utf8_lossy(&body)) {
        Ok(j) => j,
        Err(e) => return respond(&mut s, 400, &Json::obj(vec![("error", Json::str(e))]).to_string()),
    };
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let params = req.get("params").cloned().unwrap_or(Json::Arr(vec![]));
    let id = req.get("id").cloned().unwrap_or(Json::Null);
    let out = match call(&node, &method, &params, &miner) {
        Ok(v) => Json::obj(vec![("result", v), ("error", Json::Null), ("id", id)]),
        Err(e) => Json::obj(vec![("result", Json::Null), ("error", Json::obj(vec![("message", Json::str(e))])), ("id", id)]),
    };
    respond(&mut s, 200, &out.to_string())
}

fn respond(s: &mut TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    write!(s, "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", code, reason, body.len(), body)?;
    s.flush()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// "1.5" → 150,000,000 laminae (at most 8 decimals).
pub fn parse_amount(s: &str) -> Result<u64, String> {
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if f.len() > 8 || w.is_empty() && f.is_empty() || !w.chars().chain(f.chars()).all(|c| c.is_ascii_digit()) {
        return Err(format!("bad amount {}", s));
    }
    let whole: u64 = if w.is_empty() { 0 } else { w.parse().map_err(|_| "amount too large")? };
    let frac: u64 = format!("{:0<8}", f).parse().unwrap();
    whole.checked_mul(100_000_000).and_then(|x| x.checked_add(frac)).ok_or_else(|| "amount too large".into())
}

pub fn fmt_amount(l: u64) -> String {
    format!("{}.{:08}", l / 100_000_000, l % 100_000_000)
}

fn p_str(p: &Json, i: usize) -> Result<String, String> {
    match p.idx(i) {
        Some(Json::Str(s)) => Ok(s.clone()),
        Some(Json::Num(n)) => Ok(n.clone()),
        _ => Err(format!("missing parameter {}", i)),
    }
}

fn id32(s: &str) -> Result<Id, String> {
    unhex(s).and_then(|v| v.try_into().ok()).ok_or_else(|| "expected 64 hex characters".into())
}

pub fn call(node: &Arc<Node>, method: &str, p: &Json, miner: &Option<Arc<MinerStats>>) -> Result<Json, String> {
    match method {
        "getblockchaininfo" => {
            let c = node.chain.lock().unwrap();
            let (best_h, best_hh) = c.best_header();
            let _ = best_h;
            let tip = c.tip();
            Ok(Json::obj(vec![
                ("chain", Json::str(c.params.name)),
                ("blocks", Json::num(c.height())),
                ("headers", Json::num(best_hh)),
                ("bestblockhash", Json::str(hex(&c.tip_id()))),
                ("genesis", Json::str(hex(&c.genesis_id))),
                ("time", Json::num(tip.header.timestamp)),
                ("mediantime", Json::num(c.mtp(&c.tip_id()))),
                ("target", Json::str(tip.header.target_int().to_hex_padded(32))),
                ("chainwork", Json::str(tip.chainwork.to_hex())),
                ("params_hash", Json::str(hex(&c.params.params_hash()))),
            ]))
        }
        "getblockcount" => Ok(Json::num(node.chain.lock().unwrap().height())),
        "getbestblockhash" => Ok(Json::str(hex(&node.chain.lock().unwrap().tip_id()))),
        "getblockhash" => {
            let h: u64 = p_str(p, 0)?.parse().map_err(|_| "height")?;
            let c = node.chain.lock().unwrap();
            c.active.get(h as usize).map(|id| Json::str(hex(id))).ok_or_else(|| "height out of range".into())
        }
        "getblock" => {
            let id = id32(&p_str(p, 0)?)?;
            let c = node.chain.lock().unwrap();
            let e = c.index.get(&id).ok_or("unknown block")?.clone();
            let b = c.get_block(&id).ok_or("block data not available")?;
            let verbose = p_str(p, 1).map(|v| v != "0" && v != "false").unwrap_or(true);
            if !verbose {
                return Ok(Json::str(hex(&b.serialize())));
            }
            Ok(Json::obj(vec![
                ("hash", Json::str(hex(&id))),
                ("height", Json::num(e.height)),
                ("in_active_chain", Json::Bool(c.is_active(&id))),
                ("previousblockhash", Json::str(hex(&b.header.prev_block))),
                ("time", Json::num(b.header.timestamp)),
                ("nonce", Json::num(b.header.nonce)),
                ("target", Json::str(b.header.target_int().to_hex_padded(32))),
                ("size", Json::num(b.serialize().len())),
                ("tx", Json::Arr(b.txs.iter().map(|t| Json::str(hex(&t.txid()))).collect())),
            ]))
        }
        "submitblock" => {
            let raw = unhex(&p_str(p, 0)?).ok_or("hex")?;
            let b = Block::parse(&raw).map_err(|e| e.to_string())?;
            match node.submit_block(b, None) {
                Submit::Accepted { .. } => Ok(Json::Null),
                Submit::Rejected(why) => Err(why),
            }
        }
        "sendrawtransaction" => {
            let raw = unhex(&p_str(p, 0)?).ok_or("hex")?;
            let t = Tx::from_bytes(&raw).map_err(|e| e.to_string())?;
            Ok(Json::str(hex(&node.submit_tx(t, None)?)))
        }
        "getrawmempool" => {
            let mp = node.mempool.lock().unwrap();
            Ok(Json::Arr(mp.txs.keys().map(|k| Json::str(hex(k))).collect()))
        }
        "getmempoolinfo" => {
            let (n, w) = node.mempool_info();
            Ok(Json::obj(vec![("size", Json::num(n)), ("weight", Json::num(w))]))
        }
        "getpeerinfo" => {
            let peers = node.peers.lock().unwrap().info();
            Ok(Json::Arr(
                peers
                    .into_iter()
                    .map(|(id, a, out, v, since, ping)| {
                        Json::obj(vec![
                            ("id", Json::num(id)),
                            ("addr", Json::str(a.to_string())),
                            ("inbound", Json::Bool(!out)),
                            ("subver", Json::str(v.as_ref().map(|v| v.user_agent.clone()).unwrap_or_default())),
                            ("startingheight", Json::num(v.map(|v| v.best_height).unwrap_or(0))),
                            ("conntime", Json::num(since)),
                            ("pingtime", ping.map(Json::num).unwrap_or(Json::Null)),
                        ])
                    })
                    .collect(),
            ))
        }
        "getconnectioncount" => Ok(Json::num(node.peer_count())),
        "getmininginfo" => {
            let c = node.chain.lock().unwrap();
            let target = c.next_target_after(&c.tip_id());
            let (rate, found, mode, threads) = match miner {
                Some(m) => {
                    let secs = m.started.elapsed().as_secs_f64().max(1.0);
                    (m.hashes.load(Ordering::Relaxed) as f64 / secs, m.blocks_found.load(Ordering::Relaxed), m.mode.lock().unwrap().clone(), m.threads)
                }
                None => (0.0, 0, "off".to_string(), 0),
            };
            // expected hashes per block = 2^256 / (target + 1)
            let w = varve_consensus::block::work(&target);
            Ok(Json::obj(vec![
                ("blocks", Json::num(c.height())),
                ("next_target", Json::str(target.to_hex_padded(32))),
                ("expected_hashes_per_block", Json::str(w.to_hex())),
                ("mining", Json::Bool(miner.is_some())),
                ("mode", Json::str(mode)),
                ("threads", Json::num(threads)),
                ("hashrate_avg", Json::num(format!("{:.1}", rate))),
                ("blocks_found", Json::num(found)),
            ]))
        }
        "getnewaddress" => {
            let hrp = node.chain.lock().unwrap().params.hrp;
            let mut w = node.wallet.lock().unwrap();
            let i = w.new_key()?;
            Ok(Json::str(w.address(hrp, i)))
        }
        "getbalance" | "getwalletinfo" => {
            let c = node.chain.lock().unwrap();
            let mp = node.mempool.lock().unwrap();
            let w = node.wallet.lock().unwrap();
            let spent: std::collections::HashSet<_> = mp.txs.values().flat_map(|e| e.tx.inputs.clone()).collect();
            let b = w.balance(&c.utxo, c.height(), &|op| spent.contains(op));
            Ok(Json::obj(vec![
                ("spendable", Json::str(fmt_amount(b.spendable))),
                ("immature", Json::str(fmt_amount(b.immature))),
                ("utxos", Json::num(b.utxos)),
                ("keys", Json::num(w.keys.len())),
                ("addresses", Json::Arr((0..w.keys.len()).map(|i| Json::str(w.address(c.params.hrp, i))).collect())),
            ]))
        }
        "sendtoaddress" => {
            let to = p_str(p, 0)?;
            let amount = parse_amount(&p_str(p, 1)?)?;
            let feerate: u64 = p_str(p, 2).ok().and_then(|f| f.parse().ok()).unwrap_or(crate::mempool::MIN_RELAY_FEERATE);
            let tx = {
                let c = node.chain.lock().unwrap();
                let mp = node.mempool.lock().unwrap();
                let mut w = node.wallet.lock().unwrap();
                let dest = address::decode(c.params.hrp, &to)?;
                let spent: std::collections::HashSet<_> = mp.txs.values().flat_map(|e| e.tx.inputs.clone()).collect();
                let coins = w.coins(&c.utxo, &|op| spent.contains(op));
                w.create_payment(coins, dest, amount, feerate, c.height() + 1, &c.ids())?
            };
            Ok(Json::str(hex(&node.submit_tx(tx, None)?)))
        }
        "uptime" => Ok(Json::num(now().saturating_sub(node.started))),
        "stop" => {
            node.shutdown.store(true, Ordering::SeqCst);
            Ok(Json::str("stopping"))
        }
        _ => Err(format!("unknown method {}", method)),
    }
}

/// Client side: call a running node.
pub fn client_call(datadir: &std::path::Path, port: u16, method: &str, params: Vec<String>) -> Result<String, String> {
    let cookie = std::fs::read_to_string(datadir.join(".cookie")).map_err(|e| format!("cannot read cookie (is the node running?): {}", e))?;
    let body = Json::obj(vec![
        ("method", Json::str(method)),
        ("params", Json::Arr(params.into_iter().map(Json::Str).collect())),
        ("id", Json::num(1)),
    ])
    .to_string();
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("cannot connect to node RPC on port {}: {}", port, e))?;
    write!(s, "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", base64(cookie.trim().as_bytes()), body.len(), body).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    let body = resp.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
    let j = Json::parse(body)?;
    match j.get("error") {
        Some(Json::Null) | None => Ok(match j.get("result") {
            Some(Json::Str(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => String::new(),
        }),
        Some(e) => Err(e.get("message").and_then(|m| m.as_str()).unwrap_or("error").to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn amounts_and_base64() {
        assert_eq!(parse_amount("1.5").unwrap(), 150_000_000);
        assert_eq!(parse_amount("0.00000001").unwrap(), 1);
        assert_eq!(parse_amount("82").unwrap(), 8_200_000_000);
        assert!(parse_amount("1.000000001").is_err());
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount(".").is_err());
        assert_eq!(fmt_amount(150_000_001), "1.50000001");
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
    }
}
