//! Battle-test toolkit for Varve regtest nodes. Development only: it is not part of
//! any release. It mirrors a running regtest node's chain over RPC, builds blocks and
//! transactions (valid ones and deliberately broken ones, with real RandomX proof of
//! work and real signatures), submits them over RPC and P2P, and prints one JSON
//! result per line on stdout. battle/run.py drives it.
//!
//! Usage:
//!   varve-testkit address
//!   varve-testkit run --datadir D --rpcport R --p2pport P --group G [--quick]

#[path = "../../varve/src/wire.rs"]
#[allow(dead_code)]
mod wire;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use varve_consensus::bignum::BigUint;
use varve_consensus::block::{merkle_root, median_time_past, next_target, seed_height, subsidy, target_bytes, Block, Header};
use varve_consensus::json::Json;
use varve_consensus::params::*;
use varve_consensus::tx::{commitment, sighash, OutPoint, Output, Recovery, Tx, Witness};
use varve_consensus::validate::{check_block, ChainIds, Coin};
use varve_sys::{RxCache, RxDataset, RxVm};

type Id = [u8; 32];

// ---------------------------------------------------------------- small helpers

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}
fn jstr(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

/// Deterministic xorshift for reproducible fuzzing.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

// ---------------------------------------------------------------- RPC

struct Rpc {
    port: u16,
    auth: String,
}

impl Rpc {
    fn new(datadir: &str, port: u16) -> Rpc {
        let cookie = std::fs::read_to_string(format!("{}/.cookie", datadir)).expect("cookie");
        Rpc { port, auth: base64(cookie.trim().as_bytes()) }
    }
    /// Ok(result) or Err(error message)
    fn call(&self, method: &str, params: &[&str]) -> Result<Json, String> {
        let ps: Vec<String> = params.iter().map(|p| jstr(p)).collect();
        let body = format!("{{\"method\":{},\"params\":[{}],\"id\":1}}", jstr(method), ps.join(","));
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).map_err(|e| format!("rpc connect: {}", e))?;
        s.set_read_timeout(Some(Duration::from_secs(300))).ok();
        write!(s, "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", self.auth, body.len(), body)
            .map_err(|e| e.to_string())?;
        let mut resp = String::new();
        s.read_to_string(&mut resp).map_err(|e| format!("rpc read: {}", e))?;
        let b = resp.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("");
        let j = Json::parse(b).map_err(|e| format!("rpc json: {} in {:?}", e, &b[..b.len().min(200)]))?;
        match j.get("error") {
            Some(Json::Null) | None => Ok(j.get("result").cloned().unwrap_or(Json::Null)),
            Some(e) => Err(e.get("message").and_then(|m| m.as_str()).unwrap_or("error").to_string()),
        }
    }
    fn s(&self, method: &str, params: &[&str]) -> Result<String, String> {
        self.call(method, params).map(|j| match j {
            Json::Str(s) => s,
            Json::Num(n) => n,
            other => other.to_string(),
        })
    }
    fn height(&self) -> u64 {
        self.s("getblockcount", &[]).unwrap().parse().unwrap()
    }
    fn best(&self) -> String {
        self.s("getbestblockhash", &[]).unwrap()
    }
    fn alive(&self) -> bool {
        self.s("getblockcount", &[]).is_ok()
    }
}

// ---------------------------------------------------------------- keys

struct Key {
    scheme: u16,
    pk: Vec<u8>,
    sk: Vec<u8>,
}
impl Key {
    fn ml(seed: u8) -> Key {
        let (pk, sk) = varve_sys::mldsa65_keypair_from_seed(&[seed; 32]).unwrap();
        Key { scheme: SCHEME_ML_DSA_65, pk, sk }
    }
    fn slh(seed: u8) -> Key {
        let (pk, sk) = varve_sys::slhdsa_sha2_128s_keypair_from_seed(&[seed; 16], &[seed ^ 0x55; 16], &[seed ^ 0xaa; 16]).unwrap();
        Key { scheme: SCHEME_SLH_DSA_SHA2_128S, pk, sk }
    }
    fn com(&self) -> Id {
        commitment(self.scheme, &self.pk)
    }
    fn out(&self, amount: u64) -> Output {
        Output::single(amount, self.scheme, self.com())
    }
    fn sys(&self) -> varve_sys::Scheme {
        if self.scheme == SCHEME_ML_DSA_65 {
            varve_sys::Scheme::MlDsa65
        } else {
            varve_sys::Scheme::SlhDsaSha2_128s
        }
    }
}

// ---------------------------------------------------------------- chain mirror

#[derive(Clone)]
struct Mirror {
    ids: Vec<Id>,
    headers: Vec<Header>,
    utxo: HashMap<OutPoint, Coin>,
}

struct Kit {
    rpc: Rpc,
    p2pport: u16,
    params: varve_consensus::params::ChainParams,
    cids: ChainIds,
    m: Mirror,
    vm: RxVm,
    key: Key,
    out: Vec<String>,
    quick: bool,
}

fn utxo_apply(utxo: &mut HashMap<OutPoint, Coin>, b: &Block, height: u64, ids: &ChainIds) -> Result<(), String> {
    let undo = check_block(b, height, ids, utxo, false).map_err(|e| e.to_string())?;
    for (op, _) in &undo.spent {
        utxo.remove(op);
    }
    for (op, c) in undo.created {
        utxo.insert(op, c);
    }
    Ok(())
}

/// Apply a block's spends and outputs without validating it.
fn raw_apply(utxo: &mut HashMap<OutPoint, Coin>, b: &Block, height: u64) {
    for (n, t) in b.txs.iter().enumerate() {
        if n > 0 {
            for i in &t.inputs {
                utxo.remove(i);
            }
        }
        let txid = t.txid();
        for (j, o) in t.outputs.iter().enumerate() {
            utxo.insert(OutPoint { txid, index: j as u32 }, Coin { output: o.clone(), height, coinbase: n == 0 });
        }
    }
}

impl Kit {
    fn sync(&mut self) {
        let h = self.rpc.height();
        // find the fork point with the node's active chain
        let mut keep = self.m.ids.len().min(h as usize + 1);
        while keep > 1 {
            let id = self.rpc.s("getblockhash", &[&(keep - 1).to_string()]).unwrap();
            if hex(&self.m.ids[keep - 1]) == id {
                break;
            }
            keep -= 1;
        }
        if keep < self.m.ids.len() {
            // rebuild the UTXO set from genesis (simple and safe for a few thousand blocks)
            self.m.ids.truncate(keep);
            self.m.headers.truncate(keep);
            self.m.utxo.clear();
            for height in 1..keep as u64 {
                let b = self.fetch(height);
                if utxo_apply(&mut self.m.utxo, &b, height, &self.cids).is_err() {
                    raw_apply(&mut self.m.utxo, &b, height);
                }
            }
        }
        for height in self.m.ids.len() as u64..=h {
            let b = self.fetch(height);
            if utxo_apply(&mut self.m.utxo, &b, height, &self.cids).is_err() {
                // the node runs older rules than this library: mirror the block anyway
                raw_apply(&mut self.m.utxo, &b, height);
            }
            self.m.ids.push(b.header.block_id());
            self.m.headers.push(b.header.clone());
        }
    }
    fn fetch(&self, height: u64) -> Block {
        let id = self.rpc.s("getblockhash", &[&height.to_string()]).unwrap();
        let raw = self.rpc.s("getblock", &[&id, "0"]).unwrap();
        Block::parse(&unhex(&raw).unwrap()).unwrap()
    }
    fn tip_height(&self) -> u64 {
        (self.m.ids.len() - 1) as u64
    }

    /// Mature coins of `key` in a UTXO set, oldest first.
    fn coins_of(&self, utxo: &HashMap<OutPoint, Coin>, key: &Key, at_height: u64) -> Vec<(OutPoint, Coin)> {
        let mut v: Vec<_> = utxo
            .iter()
            .filter(|(_, c)| c.output.commitment == key.com() && c.output.recovery.is_none() && (!c.coinbase || at_height >= c.height + COINBASE_MATURITY))
            .map(|(o, c)| (o.clone(), c.clone()))
            .collect();
        v.sort_by(|a, b| a.1.height.cmp(&b.1.height).then(a.0.cmp(&b.0)));
        v
    }

    /// Sign `tx` in place: first input of each key path 0, later ones path 2.
    fn sign(&self, tx: &mut Tx, spent: &[Output], keys: &[&Key]) {
        tx.witnesses = vec![Witness { path: 0, public_key: vec![], signature: vec![] }; tx.inputs.len()];
        let mut seen: HashSet<Id> = HashSet::new();
        for (i, o) in spent.iter().enumerate() {
            let k = keys.iter().find(|k| k.com() == o.commitment).expect("key for input");
            if !seen.insert(o.commitment) {
                tx.witnesses[i].path = 2;
                continue;
            }
            let msg = sighash(&self.cids.network_id, &self.cids.genesis_id, tx, i as u32, spent, 0);
            let sig = varve_sys::sign(k.sys(), &k.sk, &msg).unwrap();
            tx.witnesses[i] = Witness { path: 0, public_key: k.pk.clone(), signature: sig };
        }
    }

    fn pay(&self, inputs: &[(OutPoint, Coin)], outputs: Vec<Output>, keys: &[&Key]) -> Tx {
        let mut tx = Tx { version: TX_VERSION, inputs: inputs.iter().map(|c| c.0.clone()).collect(), outputs, locktime: 0, witnesses: vec![] };
        let spent: Vec<Output> = inputs.iter().map(|c| c.1.output.clone()).collect();
        self.sign(&mut tx, &spent, keys);
        tx
    }

    fn coinbase(&self, height: u64, amount: u64, extra: Vec<u8>) -> Tx {
        Tx {
            version: TX_VERSION,
            inputs: vec![OutPoint { txid: [0; 32], index: height as u32 }],
            outputs: vec![self.key.out(amount)],
            locktime: 0,
            witnesses: vec![Witness { path: 0, public_key: vec![], signature: extra }],
        }
    }

    /// Target for a child of `parent` (index into `branch`, a list of headers from genesis).
    fn target_after(&self, branch: &[Header]) -> BigUint {
        let p = branch.last().unwrap();
        next_target(&self.params.initial_target, branch[0].timestamp, (branch.len() - 1) as u64, p.timestamp)
    }
    fn mtp_of(branch: &[Header]) -> u64 {
        let ts: Vec<u64> = branch.iter().rev().take(MTP_WINDOW).map(|h| h.timestamp).collect();
        median_time_past(&ts)
    }

    /// Grind the nonce until the header meets `target` (and the block's own target field).
    fn grind(&mut self, h: &mut Header, target: &BigUint) {
        loop {
            let hv = BigUint::from_le_bytes(&self.vm.hash(&h.serialize()));
            if &hv <= target {
                return;
            }
            h.nonce = h.nonce.wrapping_add(1);
        }
    }

    /// Build a block on top of `branch` with `txs` after a coinbase paying subsidy+fees+delta.
    fn build_on(&mut self, branch: &[Header], utxo: &HashMap<OutPoint, Coin>, txs: Vec<Tx>, delta: i64, ts: Option<u64>) -> Block {
        let height = branch.len() as u64;
        assert!(height < RANDOMX_KEY_EPOCH + RANDOMX_KEY_LAG, "testkit uses the genesis RandomX key only");
        let mut fees = 0u64;
        let mut view = utxo.clone();
        for t in &txs {
            let ins: u64 = t.inputs.iter().map(|i| view.get(i).map(|c| c.output.amount).unwrap_or(0)).sum();
            let outs: u64 = t.outputs.iter().map(|o| o.amount).sum();
            fees = fees.saturating_add(ins.saturating_sub(outs));
            let txid = t.txid();
            for (n, o) in t.outputs.iter().enumerate() {
                view.insert(OutPoint { txid, index: n as u32 }, Coin { output: o.clone(), height, coinbase: false });
            }
        }
        let amount = (subsidy(height) + fees) as i64 + delta;
        let mut all = vec![self.coinbase(height, amount.max(0) as u64, vec![(now() & 0xff) as u8, (height & 0xff) as u8, 0x74, 0x6b])];
        all.extend(txs);
        let target = self.target_after(branch);
        let ts = ts.unwrap_or_else(|| now().max(Self::mtp_of(branch) + 1));
        let wt: Vec<Id> = all.iter().map(|t| t.wtxid()).collect();
        let mut h = Header { version: BLOCK_VERSION, prev_block: branch.last().unwrap().block_id(), tx_root: merkle_root(&wt), timestamp: ts, target: target_bytes(&target), nonce: 0 };
        self.grind(&mut h, &target);
        Block { header: h, txs: all }
    }

    /// Recompute the merkle root and re-grind after mutating a block's transactions.
    fn reseal(&mut self, b: &mut Block) {
        let wt: Vec<Id> = b.txs.iter().map(|t| t.wtxid()).collect();
        b.header.tx_root = merkle_root(&wt);
        let t = b.header.target_int();
        b.header.nonce = 0;
        self.grind(&mut b.header, &t);
    }

    fn submit(&self, b: &Block) -> Result<(), String> {
        self.rpc.call("submitblock", &[&hex(&b.serialize())]).map(|_| ())
    }

    fn emit(&mut self, id: &str, cat: &str, name: &str, attack: &str, expected: &str, outcome: &str, detail: &str, t0: Instant) {
        let line = format!(
            "{{\"id\":{},\"category\":{},\"name\":{},\"attack\":{},\"expected\":{},\"outcome\":{},\"detail\":{},\"duration_s\":{:.2}}}",
            jstr(id), jstr(cat), jstr(name), jstr(attack), jstr(expected), jstr(outcome), jstr(detail), t0.elapsed().as_secs_f64()
        );
        println!("{}", line);
        std::io::stdout().flush().ok();
        self.out.push(line);
    }
    fn metric(&mut self, id: &str, name: &str, value: f64, unit: &str, detail: &str) {
        println!(
            "{{\"metric\":true,\"id\":{},\"name\":{},\"value\":{:.3},\"unit\":{},\"detail\":{}}}",
            jstr(id),
            jstr(name),
            value,
            jstr(unit),
            jstr(detail)
        );
        std::io::stdout().flush().ok();
    }

    /// Submit an invalid block over RPC and P2P; the node must reject it and keep its tip.
    fn expect_reject(&mut self, id: &str, name: &str, attack: &str, b: Block) {
        let t0 = Instant::now();
        let before = self.rpc.best();
        let r = self.submit(&b);
        // also over P2P from a fresh peer
        let p2p = p2p_send(self.p2pport, &self.params, self.cids.genesis_id, &[wire::Msg::Block(b.clone())]);
        std::thread::sleep(Duration::from_millis(300));
        let alive = self.rpc.alive();
        let after = if alive { self.rpc.best() } else { String::new() };
        let accepted_id = hex(&b.header.block_id());
        let (outcome, detail) = if !alive {
            ("crash", "node stopped answering RPC after the block".to_string())
        } else if after == accepted_id || r.is_ok() {
            ("vulnerable", format!("node ACCEPTED the invalid block (rpc: {:?}, tip now {})", r, &after[..16]))
        } else if after != before {
            ("vulnerable", "tip moved".to_string())
        } else {
            ("defended", format!("rejected: {}; p2p: {}", r.err().unwrap_or_default(), p2p))
        };
        self.emit(id, "Consensus", name, attack, "reject the block and keep the current tip", outcome, &detail, t0);
    }

    fn tip_branch(&self) -> Vec<Header> {
        self.m.headers.clone()
    }
}

// ---------------------------------------------------------------- P2P client

struct Peer {
    s: TcpStream,
    magic: [u8; 4],
}

fn p2p_connect(port: u16, params: &varve_consensus::params::ChainParams, genesis: Id) -> Result<Peer, String> {
    let s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut p = Peer { s, magic: params.network_id };
    let v = wire::Version {
        version: wire::PROTOCOL_VERSION,
        services: 0,
        timestamp: now(),
        nonce: Rng(now() ^ 0x9e37).next(),
        user_agent: "/varve-testkit/".into(),
        best_height: 0,
        genesis_id: genesis,
        ruleset_hash: varve_consensus::encoding::h256("VARVE/ruleset/v1", b""),
        relay: true,
    };
    p.send(&wire::Msg::Version(v))?;
    let mut got_v = false;
    let mut got_ack = false;
    let t0 = Instant::now();
    while !(got_v && got_ack) {
        if t0.elapsed() > Duration::from_secs(10) {
            return Err("handshake timeout".into());
        }
        match wire::read_msg(&mut p.s, &p.magic) {
            Ok(wire::Msg::Version(_)) => {
                got_v = true;
                p.send(&wire::Msg::Verack)?;
            }
            Ok(wire::Msg::Verack) => got_ack = true,
            Ok(_) => {}
            Err(_) => return Err("handshake failed".into()),
        }
    }
    Ok(p)
}

impl Peer {
    fn send(&mut self, m: &wire::Msg) -> Result<(), String> {
        wire::write_msg(&mut self.s, &self.magic, m).map_err(|e| e.to_string())
    }
}

/// Connect, send messages, linger briefly. Returns a short description.
fn p2p_send(port: u16, params: &varve_consensus::params::ChainParams, genesis: Id, msgs: &[wire::Msg]) -> String {
    match p2p_connect(port, params, genesis) {
        Err(e) => format!("connect failed: {}", e),
        Ok(mut p) => {
            for m in msgs {
                if let Err(e) = p.send(m) {
                    return format!("send failed: {}", e);
                }
            }
            // stay connected like a real peer until the node has gone quiet (2 s without
            // traffic, at most 60 s), so it can process everything we sent
            p.s.set_read_timeout(Some(Duration::from_millis(2000))).ok();
            let mut buf = [0u8; 65536];
            let mut disconnected = false;
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(60) {
                match p.s.read(&mut buf) {
                    Ok(0) => {
                        disconnected = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            if disconnected { "peer disconnected us".into() } else { "still connected".into() }
        }
    }
}

// ---------------------------------------------------------------- scenarios

fn group_setup(k: &mut Kit) {
    // Fan out one mature coinbase into many small coins for later scenarios.
    let t0 = Instant::now();
    let h = k.tip_height();
    let coins = k.coins_of(&k.m.utxo, &k.key, h + 1);
    if coins.is_empty() {
        k.emit("setup", "Setup", "funding", "-", "-", "error", "no mature coins for the test key", t0);
        return;
    }
    let mut chosen = vec![];
    let mut total = 0;
    for c in coins.iter().take(4) {
        total += c.1.output.amount;
        chosen.push(c.clone());
    }
    let n = 400u64;
    let wallet_amt = 100_00000000u64;
    let each = (total - wallet_amt - 10_000_000) / n;
    let mut outs: Vec<Output> = (0..n).map(|_| k.key.out(each)).collect();
    // fund the node's own wallet for the wallet abuse tests
    if let Ok(a) = k.rpc.s("getnewaddress", &[]) {
        if let Some(o) = decode_addr(&a) {
            for _ in 0..20 {
                outs.push(Output { amount: wallet_amt / 20, ..o.clone() });
            }
        }
    }
    let key = Key::ml(1);
    let tx = k.pay(&chosen, outs, &[&key]);
    let br = k.tip_branch();
    let utxo = k.m.utxo.clone();
    let b = k.build_on(&br, &utxo, vec![tx], 0, None);
    let r = k.submit(&b);
    k.sync();
    k.emit(
        "setup-fanout",
        "Setup",
        "Valid control block with a 4-input, 400-output transaction",
        "control case (not an attack): a valid block with one signature covering four same-key inputs",
        "accept",
        if r.is_ok() { "defended" } else { "error" },
        &format!("{:?}", r),
        t0,
    );
}

fn small_coins(k: &Kit, n: usize) -> Vec<(OutPoint, Coin)> {
    k.coins_of(&k.m.utxo, &k.key, k.tip_height() + 1).into_iter().filter(|c| !c.1.coinbase).take(n).collect()
}

fn group_consensus(k: &mut Kit) {
    let key = Key::ml(1);
    let other = Key::ml(2);
    let br = k.tip_branch();
    let utxo = k.m.utxo.clone();
    let coins = small_coins(k, 20);
    if coins.len() < 12 {
        let t0 = Instant::now();
        k.emit("consensus", "Consensus", "consensus group", "-", "-", "error", "not enough small coins (run setup first)", t0);
        return;
    }
    let h = k.tip_height() + 1;

    let b = k.build_on(&br, &utxo, vec![], 1, None);
    k.expect_reject("c-inflation", "Coinbase pays 1 lamina too much (inflation)", "miner creates money: coinbase = subsidy + fees + 1", b);

    let b = k.build_on(&br, &utxo, vec![], 100_000_000_000, None);
    k.expect_reject("c-inflation-large", "Coinbase pays 1,000 VARV extra", "miner creates 1,000 VARV out of thin air", b);

    let mut b = k.build_on(&br, &utxo, vec![], 0, None);
    b.header.tx_root[0] ^= 1;
    let t = b.header.target_int();
    k.grind(&mut b.header, &t);
    k.expect_reject("c-bad-merkle", "Header commits to the wrong transaction root", "valid PoW, but the merkle root does not match the transactions", b);

    let t1 = k.pay(&coins[0..1], vec![key.out(coins[0].1.output.amount - 100_000)], &[&key]);
    let t2 = k.pay(&coins[0..1], vec![other.out(coins[0].1.output.amount - 200_000)], &[&key]);
    let b = k.build_on(&br, &utxo, vec![t1, t2], 0, None);
    k.expect_reject("c-double-spend-in-block", "Same coin spent twice in one block", "two transactions in one block spend the same coin", b);

    let dup = vec![coins[1].clone(), coins[1].clone()];
    let t = k.pay(&dup, vec![key.out(coins[1].1.output.amount * 2 - 100_000)], &[&key]);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-duplicate-input", "Transaction lists the same input twice", "one transaction spends one coin twice to double its value", b);

    let ghost = (OutPoint { txid: [0x42; 32], index: 7 }, Coin { output: key.out(5_000_000_000), height: 1, coinbase: false });
    let t = k.pay(&[ghost], vec![key.out(4_000_000_000)], &[&key]);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-nonexistent-coin", "Spend of a coin that never existed", "transaction spends an outpoint that is not in the UTXO set", b);

    let immature: Vec<_> = utxo.iter().filter(|(_, c)| c.coinbase && h < c.height + COINBASE_MATURITY && c.output.commitment == key.com()).map(|(o, c)| (o.clone(), c.clone())).take(1).collect();
    if let Some(c) = immature.first() {
        let t = k.pay(&[c.clone()], vec![key.out(c.1.output.amount - 100_000)], &[&key]);
        let b = k.build_on(&br, &utxo, vec![t], 0, None);
        k.expect_reject("c-immature-coinbase", "Spend of an immature coinbase", "spends a block reward before the 288-block maturity", b);
    }

    let mut t = k.pay(&coins[2..3], vec![key.out(coins[2].1.output.amount - 100_000)], &[&key]);
    t.witnesses[0].signature[100] ^= 0x01;
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-bad-signature", "Transaction with a corrupted signature", "one bit of the ML-DSA signature flipped", b);

    // someone else's key signs: valid signature, wrong commitment
    let mut t = Tx { version: TX_VERSION, inputs: vec![coins[3].0.clone()], outputs: vec![other.out(coins[3].1.output.amount - 100_000)], locktime: 0, witnesses: vec![] };
    let spent = vec![coins[3].1.output.clone()];
    let msg = sighash(&k.cids.network_id, &k.cids.genesis_id, &t, 0, &spent, 0);
    let sig = varve_sys::sign(other.sys(), &other.sk, &msg).unwrap();
    t.witnesses = vec![Witness { path: 0, public_key: other.pk.clone(), signature: sig }];
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-theft-wrong-key", "Thief signs someone else's coin with their own key", "valid signature by the attacker's key on a coin locked to the victim's key", b);

    // path 2 on the first input (no earlier authorization)
    let mut t = k.pay(&coins[4..6], vec![key.out(coins[4].1.output.amount * 2 - 100_000)], &[&key]);
    t.witnesses.swap(0, 1);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-shared-unauthorized", "Shared witness with no earlier signature", "uses the one-signature-for-many-coins witness without any signature before it", b);

    // shared witness for a coin of a different key
    let other_coin = (coins[6].0.clone(), Coin { output: other.out(coins[6].1.output.amount), ..coins[6].1.clone() });
    let _ = other_coin; // the real coin belongs to `key`; emulate theft: our signed input + victim's coin via path 2
    let victim: Vec<_> = utxo.iter().filter(|(_, c)| c.output.commitment != key.com() && !c.coinbase).map(|(o, c)| (o.clone(), c.clone())).take(1).collect();
    if let Some(v) = victim.first() {
        let mut t = Tx { version: TX_VERSION, inputs: vec![coins[7].0.clone(), v.0.clone()], outputs: vec![key.out(coins[7].1.output.amount)], locktime: 0, witnesses: vec![] };
        let spent = vec![coins[7].1.output.clone(), v.1.output.clone()];
        let msg = sighash(&k.cids.network_id, &k.cids.genesis_id, &t, 0, &spent, 0);
        let sig = varve_sys::sign(key.sys(), &key.sk, &msg).unwrap();
        t.witnesses = vec![Witness { path: 0, public_key: key.pk.clone(), signature: sig }, Witness { path: 2, public_key: vec![], signature: vec![] }];
        let b = k.build_on(&br, &utxo, vec![t], 0, None);
        k.expect_reject("c-shared-theft", "Shared witness used to steal another key's coin", "attacker signs their own coin and attaches a victim's coin with an empty shared witness", b);
    }

    let mut t = k.pay(&coins[8..9], vec![key.out(coins[8].1.output.amount - 100_000)], &[&key]);
    t.witnesses[0].path = 3;
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-unknown-path", "Unknown witness path", "witness path 3, which no rule defines", b);

    // over max weight: one tx with ~5,100 outputs
    let n = 5_100u64;
    let each = (coins[9].1.output.amount - 50_000_000) / n;
    let t = k.pay(&coins[9..10], (0..n).map(|_| key.out(each.max(1))).collect(), &[&key]);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-overweight", "Block over the 720,000 weight limit", "a block stuffed past the weight limit with a 5,100-output transaction", b);

    let b = k.build_on(&br, &utxo, vec![], 0, Some(now() + 3_600));
    k.expect_reject("c-future-time", "Timestamp one hour in the future", "header timestamp 3,600 s ahead (limit: 600 s)", b);

    let mtp = Kit::mtp_of(&br);
    let b = k.build_on(&br, &utxo, vec![], 0, Some(mtp));
    k.expect_reject("c-time-at-mtp", "Timestamp not above median time past", "timestamp equal to the median of the last 11 blocks (time-warp building block)", b);

    // easier target than required
    let mut b = k.build_on(&br, &utxo, vec![], 0, None);
    // 64x easier, kept inside 256 bits (regtest already runs close to its limit)
    let mut easy = k.target_after(&br).mul_u64(64);
    if easy > BigUint::pow2(255) {
        easy = BigUint::pow2(255);
    }
    b.header.target = target_bytes(&easy);
    b.header.nonce = 0;
    k.grind(&mut b.header, &easy);
    k.expect_reject("c-easy-target", "Block claims an easier difficulty", "header target 64x easier than the schedule allows", b);

    // no PoW at all
    let mut b = k.build_on(&br, &utxo, vec![], 0, None);
    let target = b.header.target_int();
    loop {
        b.header.nonce = b.header.nonce.wrapping_add(1);
        if BigUint::from_le_bytes(&k.vm.hash(&b.header.serialize())) > target {
            break;
        }
    }
    k.expect_reject("c-bad-pow", "Block without valid proof of work", "nonce that does not meet the target", b);

    let mut b = k.build_on(&br, &utxo, vec![], 0, None);
    let cb2 = k.coinbase(h, 1, vec![9]);
    b.txs.push(cb2);
    k.reseal(&mut b);
    k.expect_reject("c-second-coinbase", "Second coinbase transaction", "a block with two reward transactions", b);

    // a header followed by a transaction count of zero, sent as raw bytes
    {
        let t0 = Instant::now();
        let mut b = k.build_on(&br, &utxo, vec![], 0, None);
        b.header.tx_root = [0x11; 32];
        let t = b.header.target_int();
        k.grind(&mut b.header, &t);
        let mut raw = b.header.serialize().to_vec();
        raw.push(0);
        let before = k.rpc.best();
        let r = k.rpc.call("submitblock", &[&hex(&raw)]);
        let alive = k.rpc.alive();
        let ok = r.is_err() && alive && k.rpc.best() == before;
        k.emit("c-no-coinbase", "Consensus", "Block with no transactions at all", "a valid-PoW header followed by an empty transaction list", "reject the block and keep the current tip", if !alive { "crash" } else if ok { "defended" } else { "vulnerable" }, &format!("{:?}", r.err()), t0);
    }

    let tx_ok = k.pay(&coins[10..11], vec![key.out(coins[10].1.output.amount - 100_000)], &[&key]);
    let mut b = k.build_on(&br, &utxo, vec![tx_ok], 0, None);
    b.txs.swap(0, 1);
    k.reseal(&mut b);
    k.expect_reject("c-coinbase-not-first", "Coinbase not in first position", "a normal transaction placed before the coinbase", b);

    let mut b = k.build_on(&br, &utxo, vec![], 0, None);
    b.txs[0].inputs[0].index = (h + 5) as u32;
    k.reseal(&mut b);
    k.expect_reject("c-coinbase-height", "Coinbase commits to the wrong height", "coinbase input index differs from the block height (duplicate-txid risk)", b);

    let mut b = k.build_on(&br, &utxo, vec![], 0, None);
    b.txs[0].witnesses[0].signature = vec![7u8; 65];
    k.reseal(&mut b);
    k.expect_reject("c-coinbase-extra", "Coinbase extra data over 64 bytes", "65 bytes of coinbase extra data", b);

    let t = k.pay(&coins[11..12], vec![key.out(coins[11].1.output.amount + 1)], &[&key]);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-negative-fee", "Transaction spends more than its inputs", "outputs exceed inputs by 1 lamina", b);

    let t = k.pay(&coins[12..13], vec![key.out(MAX_MONEY), key.out(MAX_MONEY)], &[&key]);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-overflow", "Output sum overflow", "two outputs of MAX_MONEY each", b);

    let mut o = key.out(coins[13].1.output.amount - 100_000);
    o.scheme_id = 3;
    let t = k.pay(&coins[13..14], vec![o], &[&key]);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-unknown-scheme", "Output locked to an unknown signature scheme", "creates an output with scheme id 3", b);

    let mut t = k.pay(&coins[14..15], vec![key.out(coins[14].1.output.amount - 100_000)], &[&key]);
    t.locktime = (h + 100) as u32;
    let spent = vec![coins[14].1.output.clone()];
    k.sign(&mut t, &spent, &[&key]);
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-locktime", "Transaction locked until a future height", "locktime 100 blocks ahead", b);

    // recovery path before its delay
    let rec_out = Output { amount: coins[15].1.output.amount - 100_000, output_version: 1, scheme_id: key.scheme, commitment: key.com(), recovery: Some(Recovery { scheme_id: other.scheme, commitment: other.com(), delay: 1000 }) };
    let t_create = k.pay(&coins[15..16], vec![rec_out.clone()], &[&key]);
    let rc = (OutPoint { txid: t_create.txid(), index: 0 }, Coin { output: rec_out.clone(), height: h, coinbase: false });
    let mut t_spend = Tx { version: TX_VERSION, inputs: vec![rc.0.clone()], outputs: vec![other.out(rec_out.amount - 100_000)], locktime: 0, witnesses: vec![] };
    let msg = sighash(&k.cids.network_id, &k.cids.genesis_id, &t_spend, 0, &[rec_out.clone()], 1);
    t_spend.witnesses = vec![Witness { path: 1, public_key: other.pk.clone(), signature: varve_sys::sign(other.sys(), &other.sk, &msg).unwrap() }];
    let b = k.build_on(&br, &utxo, vec![t_create, t_spend], 0, None);
    k.expect_reject("c-recovery-early", "Recovery key used before its delay", "recovery-path spend 999 blocks too early", b);

    // invalid parent: child of a rejected block
    let t0 = Instant::now();
    let bad = k.build_on(&br, &utxo, vec![], 1, None);
    let mut br2 = br.clone();
    br2.push(bad.header.clone());
    let child = k.build_on(&br2, &utxo, vec![], 0, None);
    let before = k.rpc.best();
    let r1 = k.submit(&bad);
    let r2 = k.submit(&child);
    let after = k.rpc.best();
    let ok = r1.is_err() && r2.is_err() && before == after;
    k.emit(
        "c-invalid-parent",
        "Consensus",
        "Valid-looking block built on an invalid parent",
        "submits an inflating block, then a well-formed child on top of it",
        "reject both; never build on the invalid branch",
        if ok { "defended" } else { "vulnerable" },
        &format!("parent: {:?}; child: {:?}", r1, r2),
        t0,
    );

    // known header, malleated body first, then the real body
    let t0 = Instant::now();
    let good = k.build_on(&br, &utxo, vec![], 0, None);
    let mut bad = good.clone();
    bad.txs[0].witnesses[0].signature.push(1); // body no longer matches the header's merkle root
    let mut p = p2p_connect(k.p2pport, &k.params, k.cids.genesis_id);
    let detail;
    if let Ok(pp) = p.as_mut() {
        let _ = pp.send(&wire::Msg::Headers(vec![good.header.clone()]));
        std::thread::sleep(Duration::from_millis(300));
        let _ = pp.send(&wire::Msg::Block(bad));
        std::thread::sleep(Duration::from_millis(500));
        let r = k.submit(&good);
        std::thread::sleep(Duration::from_millis(300));
        let tip = k.rpc.best();
        let accepted = tip == hex(&good.header.block_id());
        detail = format!("real block after mutated copy: {:?}; tip is the real block: {}", r, accepted);
        k.emit(
            "c-malleated-body",
            "Consensus",
            "Mutated copy of a real block sent first",
            "announces a real header, sends a body that does not match it, then the real block arrives",
            "reject the mutated body without marking the real block invalid; accept the real block",
            if accepted { "defended" } else { "vulnerable" },
            &detail,
            t0,
        );
        k.sync();
    } else {
        k.emit("c-malleated-body", "Consensus", "Mutated copy of a real block sent first", "-", "-", "error", "p2p connect failed", t0);
    }

    // (last: an older node accepts this block, which would move the tip)
    // two inputs of the same key, both fully signed (the second should use the shared form)
    let mut t = Tx { version: TX_VERSION, inputs: vec![coins[16].0.clone(), coins[17].0.clone()], outputs: vec![key.out(coins[16].1.output.amount + coins[17].1.output.amount - 200_000)], locktime: 0, witnesses: vec![] };
    let spent = vec![coins[16].1.output.clone(), coins[17].1.output.clone()];
    let mut ws = vec![];
    for i in 0..2 {
        let msg = sighash(&k.cids.network_id, &k.cids.genesis_id, &t, i as u32, &spent, 0);
        ws.push(Witness { path: 0, public_key: key.pk.clone(), signature: varve_sys::sign(key.sys(), &key.sk, &msg).unwrap() });
    }
    t.witnesses = ws;
    k.sync();
    let br = k.tip_branch();
    let utxo = k.m.utxo.clone();
    let b = k.build_on(&br, &utxo, vec![t], 0, None);
    k.expect_reject("c-noncanonical-witness", "Same key signed twice instead of the shared form", "a relayer re-encodes a transaction's witnesses so its witness id and size change (witness malleability)", b);

}

fn group_reorg(k: &mut Kit) {
    let key = Key::ml(1);
    let attacker = Key::ml(3);
    // 1. double spend through a longer private chain
    let t0 = Instant::now();
    let victim_addr = k.rpc.s("getnewaddress", &[]).unwrap();
    let bal0 = k.rpc.call("getbalance", &[]).unwrap();
    let spend0 = bal0.get("spendable").and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| Some(v.to_string()))).unwrap_or_default();
    let victim_out = decode_addr(&victim_addr).expect("victim address");
    let coins = small_coins(k, 2);
    let c = coins[0].clone();
    let half = c.1.output.amount / 2;
    let pay_victim = k.pay(&[c.clone()], vec![Output { amount: half, ..victim_out }, key.out(c.1.output.amount - half - 1_000_000)], &[&key]);
    let fork = k.tip_branch();
    let utxo_fork = k.m.utxo.clone();
    let pub_b = k.build_on(&fork, &utxo_fork, vec![pay_victim.clone()], 0, None);
    let r = k.submit(&pub_b);
    std::thread::sleep(Duration::from_millis(300));
    let bal1 = k.rpc.call("getbalance", &[]).unwrap().to_string();
    // private chain: same coin to the attacker, 2 blocks
    let steal = k.pay(&[c.clone()], vec![attacker.out(c.1.output.amount - 1_000_000)], &[&key]);
    let q1 = k.build_on(&fork, &utxo_fork, vec![steal], 0, Some(pub_b.header.timestamp));
    let mut f2 = fork.clone();
    f2.push(q1.header.clone());
    let mut u2 = utxo_fork.clone();
    utxo_apply(&mut u2, &q1, f2.len() as u64 - 1, &k.cids).unwrap();
    let q2 = k.build_on(&f2, &u2, vec![], 0, None);
    let p = p2p_send(k.p2pport, &k.params, k.cids.genesis_id, &[wire::Msg::Block(q1.clone()), wire::Msg::Block(q2.clone())]);
    std::thread::sleep(Duration::from_millis(1500));
    let tip = k.rpc.best();
    let bal2 = k.rpc.call("getbalance", &[]).unwrap().to_string();
    let mempool = k.rpc.call("getrawmempool", &[]).unwrap().to_string();
    let switched = tip == hex(&q2.header.block_id());
    let t1_in_pool = mempool.contains(&hex(&pay_victim.txid()));
    let ok = r.is_ok() && switched && !t1_in_pool && bal2 != bal1;
    k.emit(
        "r-double-spend",
        "Reorg",
        "Double spend by a longer private chain",
        "pays the node's wallet in a public block, then publishes a longer private chain that sends the same coin back to the attacker",
        "follow the most-work chain, drop the conflicting payment, and reflect the reversal in the wallet balance",
        if ok { "defended" } else { "vulnerable" },
        &format!("public block: {:?}; switched to private chain: {}; reversed payment left in mempool: {}; balance before {} / after payment {} / after reorg {}; p2p: {}", r, switched, t1_in_pool, spend0, bal1, bal2, p),
        t0,
    );
    k.sync();

    // 2. equal-work tie: first seen wins
    let t0 = Instant::now();
    let br = k.tip_branch();
    let u = k.m.utxo.clone();
    let a = k.build_on(&br, &u, vec![], 0, None);
    let b = k.build_on(&br, &u, vec![], -1, None);
    let ra = k.submit(&a);
    let rb = k.submit(&b);
    let tip = k.rpc.best();
    let ok = ra.is_ok() && tip == hex(&a.header.block_id());
    k.emit(
        "r-tie",
        "Reorg",
        "Competing block with equal work",
        "a second block at the same height arrives after the first",
        "keep the first-seen block (no flip-flopping on ties)",
        if ok { "defended" } else { "vulnerable" },
        &format!("first: {:?}; second: {:?}", ra, rb),
        t0,
    );
    k.sync();

    // 3. deep reorg (and 4. longer chain with an invalid block inside)
    let depth = if k.quick { 6 } else { 20 };
    let fork = k.tip_branch();
    let ufork = k.m.utxo.clone();
    for _ in 0..depth {
        let br = k.tip_branch();
        let u = k.m.utxo.clone();
        let b = k.build_on(&br, &u, vec![], 0, None);
        let _ = k.submit(&b);
        k.sync();
    }
    // invalid-in-the-middle chain of depth+2 first
    let t0 = Instant::now();
    let mut br = fork.clone();
    let mut u = ufork.clone();
    let mut blocks = vec![];
    for i in 0..depth + 2 {
        let delta = if i == 3 { 1 } else { 0 };
        let b = k.build_on(&br, &u, vec![], delta, None);
        if delta == 0 {
            let _ = utxo_apply(&mut u, &b, br.len() as u64, &k.cids);
        }
        br.push(b.header.clone());
        blocks.push(b);
    }
    let before = k.rpc.best();
    // like a real peer: announce the headers first, then deliver the blocks
    let mut msgs: Vec<wire::Msg> = vec![wire::Msg::Headers(blocks.iter().map(|b| b.header.clone()).collect())];
    msgs.extend(blocks.iter().map(|b| wire::Msg::Block(b.clone())));
    let _ = p2p_send(k.p2pport, &k.params, k.cids.genesis_id, &msgs);
    for b in &blocks {
        let _ = k.submit(b);
    }
    std::thread::sleep(Duration::from_millis(1000));
    let after = k.rpc.best();
    let alive = k.rpc.alive();
    k.emit(
        "r-invalid-in-longer-chain",
        "Reorg",
        &format!("Longer chain ({} blocks) with an invalid block inside", depth + 2),
        "publishes a chain with more work than the node's, whose 4th block inflates the supply",
        "stay on the valid chain",
        if !alive { "crash" } else if before == after { "defended" } else { "vulnerable" },
        &format!("tip unchanged: {}", before == after),
        t0,
    );
    let t0 = Instant::now();
    let mut br = fork.clone();
    let mut u = ufork.clone();
    let mut blocks = vec![];
    for _ in 0..depth + 1 {
        let b = k.build_on(&br, &u, vec![], -2, None);
        utxo_apply(&mut u, &b, br.len() as u64, &k.cids).unwrap();
        br.push(b.header.clone());
        blocks.push(b);
    }
    // like a real peer: announce the headers first, then deliver the blocks
    let mut msgs: Vec<wire::Msg> = vec![wire::Msg::Headers(blocks.iter().map(|b| b.header.clone()).collect())];
    msgs.extend(blocks.iter().map(|b| wire::Msg::Block(b.clone())));
    let t_send = Instant::now();
    let _ = p2p_send(k.p2pport, &k.params, k.cids.genesis_id, &msgs);
    let want = hex(&blocks.last().unwrap().header.block_id());
    let mut switched = false;
    for _ in 0..60 {
        if k.rpc.best() == want {
            switched = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let secs = t_send.elapsed().as_secs_f64();
    k.emit(
        "r-deep",
        "Reorg",
        &format!("Deep reorganization ({} blocks replaced)", depth),
        &format!("publishes a valid chain one block longer than the node's last {} blocks", depth),
        "switch to the most-work chain cleanly and quickly",
        if switched { "defended" } else { "vulnerable" },
        &format!("switched: {} in {:.1} s", switched, secs),
        t0,
    );
    if switched {
        k.metric("cap-reorg", &format!("{}-block reorganization time", depth), secs, "s", "from first block sent to new tip, over P2P");
    }
    k.sync();
}

/// Minimal Bech32m address decode (template only) for the victim address.
fn decode_addr(a: &str) -> Option<Output> {
    const CS: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let (_, data) = a.rsplit_once('1')?;
    let vals: Vec<u8> = data.bytes().map(|c| CS.iter().position(|&x| x == c).map(|p| p as u8)).collect::<Option<_>>()?;
    let vals = &vals[..vals.len() - 6];
    let version = vals[0];
    let mut acc = 0u32;
    let mut bits = 0;
    let mut out = vec![version];
    for &v in &vals[1..] {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    let mut r = varve_consensus::encoding::Reader::new(&out);
    let mut full = 0u64.to_le_bytes().to_vec();
    full.extend_from_slice(&out);
    let _ = &mut r;
    let mut r = varve_consensus::encoding::Reader::new(&full);
    Output::parse(&mut r).ok()
}

fn group_mempool(k: &mut Kit) {
    let key = Key::ml(1);
    let coins = small_coins(k, 400);
    if coins.len() < 300 {
        let t0 = Instant::now();
        k.emit("mempool", "Mempool", "mempool group", "-", "-", "error", &format!("only {} coins", coins.len()), t0);
        return;
    }
    // double spend
    let t0 = Instant::now();
    let a = k.pay(&coins[0..1], vec![key.out(coins[0].1.output.amount - 200_000)], &[&key]);
    let b = k.pay(&coins[0..1], vec![key.out(coins[0].1.output.amount - 900_000)], &[&key]);
    let ra = k.rpc.s("sendrawtransaction", &[&hex(&a.serialize())]);
    let rb = k.rpc.s("sendrawtransaction", &[&hex(&b.serialize())]);
    k.emit("m-double-spend", "Mempool", "Conflicting transaction after the first", "two transactions spending the same coin, the second paying a higher fee", "accept the first, refuse the conflict", if ra.is_ok() && rb.is_err() { "defended" } else { "vulnerable" }, &format!("first {:?}, second {:?}", ra.is_ok(), rb), t0);

    // zero fee
    let t0 = Instant::now();
    let z = k.pay(&coins[1..2], vec![key.out(coins[1].1.output.amount)], &[&key]);
    let rz = k.rpc.s("sendrawtransaction", &[&hex(&z.serialize())]);
    k.emit("m-zero-fee", "Mempool", "Zero-fee transaction", "a valid transaction that pays no fee", "refuse to relay (minimum relay fee)", if rz.is_err() { "defended" } else { "degraded" }, &format!("{:?}", rz), t0);

    // unconfirmed chain length
    let t0 = Instant::now();
    let mut prev = coins[2].clone();
    let mut accepted = 0;
    let mut first_err = String::new();
    for i in 0..40 {
        let amt = prev.1.output.amount - 300_000;
        let t = k.pay(&[prev.clone()], vec![key.out(amt)], &[&key]);
        match k.rpc.s("sendrawtransaction", &[&hex(&t.serialize())]) {
            Ok(_) => accepted += 1,
            Err(e) => {
                first_err = format!("stopped at {}: {}", i, e);
                break;
            }
        }
        prev = (OutPoint { txid: t.txid(), index: 0 }, Coin { output: key.out(amt), height: 0, coinbase: false });
    }
    k.emit("m-long-chain", "Mempool", "Long chain of unconfirmed transactions", "40 transactions each spending the previous one before any confirms", "cap the chain (ancestor limit) instead of growing without bound", if accepted <= 26 { "defended" } else { "degraded" }, &format!("accepted {}; {}", accepted, first_err), t0);

    // one transaction with a corrupted signature, relayed by a peer
    let t0 = Instant::now();
    let mut bad = k.pay(&coins[3..4], vec![key.out(coins[3].1.output.amount - 300_000)], &[&key]);
    bad.witnesses[0].signature[9] ^= 1;
    let r = p2p_send(k.p2pport, &k.params, k.cids.genesis_id, &[wire::Msg::Tx(bad)]);
    let cut = r.contains("disconnected");
    k.emit("m-invalid-sig-relay", "Mempool", "Peer relays a transaction with an invalid signature", "a peer sends one transaction whose signature fails verification", "drop it and disconnect the peer (honest nodes verify before relaying)", if cut { "defended" } else { "degraded" }, &r, t0);

    // throughput: sign + submit N independent txs
    let n = if k.quick { 60 } else { 200 };
    let mut txs = vec![];
    let t_sign = Instant::now();
    for c in coins[10..10 + n].iter() {
        txs.push(k.pay(&[c.clone()], vec![key.out(c.1.output.amount - 400_000)], &[&key]));
    }
    let sign_s = t_sign.elapsed().as_secs_f64();
    let t_sub = Instant::now();
    let mut ok = 0;
    for t in &txs {
        if k.rpc.s("sendrawtransaction", &[&hex(&t.serialize())]).is_ok() {
            ok += 1;
        }
    }
    let sub_s = t_sub.elapsed().as_secs_f64();
    k.metric("cap-tx-accept", "Transactions accepted into the mempool per second (RPC, fully verified)", ok as f64 / sub_s, "tx/s", &format!("{} of {} accepted in {:.2} s", ok, n, sub_s));
    k.metric("cap-sign", "ML-DSA-65 signatures created per second (test machine)", n as f64 / sign_s, "sig/s", "");

}

fn group_capacity(k: &mut Kit) {
    // full block validation time: a block near max weight with many signed ML-DSA inputs
    let key = Key::ml(1);
    let coins = small_coins(k, 400);
    let br = k.tip_branch();
    let u = k.m.utxo.clone();
    let mut txs = vec![];
    let mut w = 0u64;
    let mut nsig = 0;
    for c in coins.iter() {
        let t = k.pay(&[c.clone()], vec![key.out(c.1.output.amount - 1_000_000)], &[&key]);
        let tw = t.weight(false);
        if w + tw > MAX_BLOCK_WEIGHT - 2_000 {
            break;
        }
        w += tw;
        nsig += 1;
        txs.push(t);
    }
    let b = k.build_on(&br, &u, txs, 0, None);
    let t = Instant::now();
    let r = k.submit(&b);
    let secs = t.elapsed().as_secs_f64();
    k.metric("cap-full-block", "Full block validation time (ML-DSA signatures)", secs, "s", &format!("{} signatures, weight {}, accepted: {:?}", nsig, w, r.is_ok()));
    k.metric("cap-sigs-per-block", "Signature-checked transactions in one full block", nsig as f64, "tx", "single-input ML-DSA transactions");
    k.sync();

    // same-key consolidation: how many inputs fit with the shared witness
    let coins = small_coins(k, 400);
    let mut n = 0;
    let mut w = 0;
    for i in 1..coins.len() {
        let t = k.pay(&coins[..i], vec![key.out(1)], &[&key]);
        if t.weight(false) > MAX_BLOCK_WEIGHT - 2_000 {
            break;
        }
        n = i;
        w = t.weight(false);
    }
    k.metric("cap-shared-inputs", "Same-key inputs that fit in one block with one signature", n as f64, "inputs", &format!("weight {}", w));
}

fn group_fuzz(k: &mut Kit) {
    let key = Key::ml(1);
    let coins = small_coins(k, 4);
    let t0 = Instant::now();
    let br = k.tip_branch();
    let u = k.m.utxo.clone();
    let tx = k.pay(&coins[0..2], vec![key.out(1_000_000), key.out(coins[0].1.output.amount)], &[&key]);
    let b = k.build_on(&br, &u, vec![tx.clone()], 0, None);
    let raw_b = b.serialize();
    let raw_t = tx.serialize();
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let n = if k.quick { 300 } else { 2_000 };
    let mut accepted_bad = 0;
    let mut crashes = 0;
    for i in 0..n {
        let src = if i % 2 == 0 { &raw_b } else { &raw_t };
        let mut m = src.clone();
        let flips = 1 + rng.below(8);
        for _ in 0..flips {
            match rng.below(4) {
                0 => {
                    let p = rng.below(m.len());
                    m[p] ^= 1 << rng.below(8);
                }
                1 => {
                    let p = rng.below(m.len());
                    m[p] = rng.next() as u8;
                }
                2 => {
                    let p = rng.below(m.len());
                    m.truncate(p.max(1));
                }
                _ => {
                    let p = rng.below(m.len());
                    let v: Vec<u8> = (0..rng.below(64)).map(|_| rng.next() as u8).collect();
                    m.splice(p..p, v);
                }
            }
        }
        if m == *src {
            continue;
        }
        let r = if i % 2 == 0 { k.rpc.call("submitblock", &[&hex(&m)]) } else { k.rpc.call("sendrawtransaction", &[&hex(&m)]) };
        if let Err(e) = &r {
            if e.starts_with("rpc connect") || e.starts_with("rpc read") {
                crashes += 1;
                break;
            }
        } else if i % 2 == 0 {
            // an accepted mutated block must still be a valid block (e.g. only the nonce changed
            // and still meets the target is astronomically unlikely); count it for review
            accepted_bad += 1;
        }
    }
    let outcome = if crashes > 0 { "crash" } else if accepted_bad > 0 { "vulnerable" } else { "defended" };
    k.emit("f-mutate-rpc", "Fuzzing", &format!("{} randomly mutated blocks and transactions (RPC)", n), "bit flips, random bytes, truncation and insertion applied to a valid block and transaction", "reject every malformed input without crashing", outcome, &format!("crashes {}, mutated blocks accepted {}", crashes, accepted_bad), t0);
    k.sync();

    // message decoder fuzzing, in process (no network): random payloads for every message type
    let t0 = Instant::now();
    let cmds = ["version", "verack", "ping", "pong", "getaddr", "addr", "getheaders", "headers", "inv", "getdata", "notfound", "block", "tx", "feefilter"];
    let iters = if k.quick { 20_000 } else { 200_000 };
    let mut decoded = 0u64;
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for i in 0..iters {
            let c = cmds[i % cmds.len()];
            let len = rng.below(if i % 5 == 0 { 4000 } else { 120 });
            let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            if wire::Msg::decode(c, &payload).is_ok() {
                decoded += 1;
            }
        }
    }));
    k.emit("f-decoder", "Fuzzing", &format!("{} random messages through the message decoder", iters), "random bytes decoded as every one of the 14 message types, in process", "return an error for malformed input, never panic", if res.is_ok() { "defended" } else { "crash" }, &format!("panics: {}; random inputs that happened to decode: {}", res.is_err() as u8, decoded), t0);
}

/// Mutated transactions with the node's parse verdict, for comparison against the
/// Python reference implementation (battle/run.py does the comparison).
fn group_diff(k: &mut Kit, out_path: &str) {
    let key = Key::ml(1);
    let coins = small_coins(k, 3);
    let tx = k.pay(&coins[0..3], vec![key.out(1_000_000), key.out(2_000_000)], &[&key]);
    let raw = tx.serialize();
    let mut rng = Rng(0xd1ff_0000_5eed_0002);
    let n = if k.quick { 500 } else { 3_000 };
    let mut lines = Vec::with_capacity(n);
    for _ in 0..n {
        let mut m = raw.clone();
        for _ in 0..1 + rng.below(4) {
            let p = rng.below(m.len());
            match rng.below(4) {
                0 => m[p] ^= 1 << rng.below(8),
                1 => m[p] = rng.next() as u8,
                2 => m.truncate(p.max(1)),
                _ => {
                    let v: Vec<u8> = (0..1 + rng.below(8)).map(|_| rng.next() as u8).collect();
                    m.splice(p..p, v);
                }
            }
        }
        let verdict = match Tx::from_bytes(&m) {
            Ok(_) => "parsed",
            Err(_) => "parse_error",
        };
        // the running node must agree with the library it is built from
        let node = match k.rpc.call("sendrawtransaction", &[&hex(&m)]) {
            Err(e) if e.starts_with("parse error") => "parse_error",
            Err(e) if e.starts_with("rpc") => "rpc_failure",
            _ => "parsed",
        };
        lines.push(format!("{{\"hex\":\"{}\",\"lib\":\"{}\",\"node\":\"{}\"}}", hex(&m), verdict, node));
    }
    std::fs::write(out_path, lines.join("\n")).unwrap();
    eprintln!("[testkit] wrote {} differential cases", n);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key = Key::ml(1);
    if args.get(1).map(|s| s.as_str()) == Some("address") {
        println!("{}", varve_wallet::address::encode("rvarve", &key.out(0)));
        return;
    }
    let get = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let datadir = get("--datadir").expect("--datadir");
    let rpcport: u16 = get("--rpcport").expect("--rpcport").parse().unwrap();
    let p2pport: u16 = get("--p2pport").expect("--p2pport").parse().unwrap();
    let group = get("--group").unwrap_or_else(|| "all".into());
    let quick = args.iter().any(|a| a == "--quick");
    let params = varve_consensus::networks::regtest();
    let genesis = varve_consensus::genesis::genesis_block(&params).unwrap();
    let cids = ChainIds { network_id: params.network_id, genesis_id: genesis.header.block_id(), lifecycle: params.lifecycle.clone() };
    eprintln!("[testkit] building RandomX dataset (fast mode)...");
    let cache = Arc::new(RxCache::new(&cids.genesis_id).unwrap());
    let ds = Arc::new(RxDataset::new(&cache, 2).unwrap());
    let vm = RxVm::fast(cache, ds).unwrap();
    let mut k = Kit {
        rpc: Rpc::new(&datadir, rpcport),
        p2pport,
        params,
        cids,
        m: Mirror { ids: vec![genesis.header.block_id()], headers: vec![genesis.header.clone()], utxo: HashMap::new() },
        vm,
        key,
        out: vec![],
        quick,
    };
    k.sync();
    eprintln!("[testkit] mirrored {} blocks", k.tip_height());
    let _ = seed_height;
    for g in group.split(',') {
        match g {
            "setup" => group_setup(&mut k),
            "consensus" => group_consensus(&mut k),
            "reorg" => group_reorg(&mut k),
            "mempool" => group_mempool(&mut k),
            "capacity" => group_capacity(&mut k),
            "fuzz" => group_fuzz(&mut k),
            "diff" => group_diff(&mut k, &get("--diff-out").expect("--diff-out")),
            _ => eprintln!("unknown group {}", g),
        }
        k.sync();
    }
    let _ = Key::slh;
}
