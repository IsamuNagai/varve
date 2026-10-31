//! Randomized mutation fuzzer for every Varve parser. Development only.
//!
//!   varve-fuzz [--seconds N] [--seed S] [--out DIR]
//!
//! Starts from real inputs (test vectors) and applies random mutations. For each
//! target it checks that nothing panics and, where the format is canonical, that
//! parsing and re-encoding gives back exactly the input (a broken round trip would
//! mean two encodings for one object: malleability). A failing input is written to
//! DIR as hex and the process exits with status 1. Not coverage-guided: it runs
//! continuously in CI (every change, plus a long nightly run) to find what vectors miss.

#[path = "../../varve/src/wire.rs"]
#[allow(dead_code)]
mod wire;
#[path = "../../varve/src/address.rs"]
#[allow(dead_code)]
mod address;
#[path = "../../strata/src/http.rs"]
#[allow(dead_code)]
mod http;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use varve_consensus::block::{Block, Header};
use varve_consensus::encoding::{hex, unhex};
use varve_consensus::json::Json;
use varve_consensus::tx::Tx;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// One random mutation step.
fn mutate(r: &mut Rng, input: &[u8], seeds: &[Vec<u8>]) -> Vec<u8> {
    let mut m = input.to_vec();
    for _ in 0..1 + r.below(6) {
        let len = m.len();
        match r.below(9) {
            0 if len > 0 => {
                let p = r.below(len);
                m[p] ^= 1 << r.below(8);
            }
            1 if len > 0 => {
                let p = r.below(len);
                m[p] = r.next() as u8;
            }
            2 if len > 1 => {
                let p = r.below(len);
                let n = 1 + r.below((len - p).min(64));
                m.drain(p..p + n);
            }
            3 => {
                let p = r.below(len + 1);
                let v: Vec<u8> = (0..1 + r.below(32)).map(|_| r.next() as u8).collect();
                m.splice(p..p, v);
            }
            4 if len > 0 => {
                // interesting values: varint prefixes, extremes
                let p = r.below(len);
                m[p] = [0x00, 0x01, 0x7f, 0x80, 0xfc, 0xfd, 0xfe, 0xff][r.below(8)];
            }
            5 if len > 4 => {
                // overwrite a 4-byte little-endian length or count
                let p = r.below(len - 4);
                let v: u32 = [0, 1, 2, 0xff, 0x100, 0xffff, 0x10000, 0x7fff_ffff, 0xffff_ffff][r.below(9)];
                m[p..p + 4].copy_from_slice(&v.to_le_bytes());
            }
            6 if !seeds.is_empty() => {
                // splice in a slice of another seed
                let o = &seeds[r.below(seeds.len())];
                if !o.is_empty() {
                    let a = r.below(o.len());
                    let b = a + r.below(o.len() - a + 1).min(256);
                    let p = r.below(len + 1);
                    m.splice(p..p, o[a..b].iter().copied());
                }
            }
            7 if len > 2 => {
                let p = r.below(len);
                m.truncate(p.max(1));
            }
            _ if len > 1 => {
                // duplicate a chunk
                let a = r.below(len);
                let b = (a + 1 + r.below(64)).min(len);
                let chunk = m[a..b].to_vec();
                let p = r.below(len + 1);
                m.splice(p..p, chunk);
            }
            _ => m.push(r.next() as u8),
        }
    }
    m
}

struct Failure {
    target: &'static str,
    input: Vec<u8>,
    why: String,
}

type Check = fn(&[u8]) -> Result<(), String>;

fn check_tx(b: &[u8]) -> Result<(), String> {
    if let Ok(t) = Tx::from_bytes(b) {
        if t.serialize() != b {
            return Err("transaction re-encodes differently (non-canonical parse)".into());
        }
        let _ = (t.txid(), t.wtxid(), t.weight(false));
    }
    Ok(())
}

fn check_block(b: &[u8]) -> Result<(), String> {
    if let Ok(blk) = Block::parse(b) {
        if blk.serialize() != b {
            return Err("block re-encodes differently (non-canonical parse)".into());
        }
        let _ = blk.header.block_id();
    }
    Ok(())
}

fn check_header(b: &[u8]) -> Result<(), String> {
    if let Ok(h) = Header::from_bytes(b) {
        if h.serialize()[..] != *b {
            return Err("header re-encodes differently".into());
        }
        let _ = h.target_int();
    }
    Ok(())
}

const CMDS: [&str; 14] = ["version", "verack", "ping", "pong", "getaddr", "addr", "getheaders", "headers", "inv", "getdata", "notfound", "block", "tx", "feefilter"];
const ROUND_TRIP: [&str; 10] = ["ping", "pong", "getheaders", "headers", "inv", "getdata", "notfound", "block", "tx", "feefilter"];

/// First byte selects the command; the rest is the payload.
fn check_msg(b: &[u8]) -> Result<(), String> {
    let Some((&c, payload)) = b.split_first() else { return Ok(()) };
    let cmd = CMDS[c as usize % CMDS.len()];
    if let Ok(m) = wire::Msg::decode(cmd, payload) {
        if ROUND_TRIP.contains(&cmd) && m.payload() != payload {
            return Err(format!("{} message re-encodes differently", cmd));
        }
        let mut frame = Vec::new();
        let _ = wire::write_msg(&mut frame, b"RVAR", &m);
        // and the framed form must read back
        if wire::read_msg(&mut &frame[..], b"RVAR").is_err() {
            return Err(format!("{} message does not survive framing", cmd));
        }
    }
    let _ = wire::read_msg(&mut &b[..], b"RVAR"); // raw bytes as a frame
    Ok(())
}

fn check_address(b: &[u8]) -> Result<(), String> {
    let Ok(s) = std::str::from_utf8(b) else { return Ok(()) };
    for hrp in ["varve", "tvarve", "rvarve"] {
        if let Ok(o) = address::decode(hrp, s) {
            if address::encode(hrp, &o) != s.to_ascii_lowercase() {
                return Err("address re-encodes differently".into());
            }
        }
    }
    Ok(())
}

fn check_json(b: &[u8]) -> Result<(), String> {
    let Ok(s) = std::str::from_utf8(b) else { return Ok(()) };
    if let Ok(j) = Json::parse(s) {
        let again = Json::parse(&j.to_string()).map_err(|e| format!("re-serialized JSON does not parse: {}", e))?;
        if again.to_string() != j.to_string() {
            return Err("JSON does not round-trip".into());
        }
    }
    Ok(())
}

fn check_mnemonic(b: &[u8]) -> Result<(), String> {
    let Ok(s) = std::str::from_utf8(b) else { return Ok(()) };
    if let Ok(e) = varve_wallet::bip39::mnemonic_to_entropy(s) {
        let words = varve_wallet::bip39::entropy_to_mnemonic(&e);
        if varve_wallet::bip39::mnemonic_to_entropy(&words).ok() != Some(e) {
            return Err("mnemonic does not round-trip".into());
        }
    }
    Ok(())
}

fn check_http(b: &[u8]) -> Result<(), String> {
    let _ = http::parse_head(b);
    let _ = http::read_request(&mut &b[..], Instant::now() + Duration::from_secs(1));
    Ok(())
}

/// A wallet file encrypted with the cheapest allowed parameters (created once). Any
/// change to it must be rejected by authentication: a successful decrypt of different
/// text is a failure. Surrounding whitespace is ignored by design (files may end in a
/// newline), so it is not counted as a change.
fn wallet_file_seed() -> &'static str {
    static ORIG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ORIG.get_or_init(|| {
        varve_wallet::file::encrypt_with_params(b"fuzz plaintext", "fuzz passphrase", varve_wallet::argon2::Params { m_kib: 8192, t: 1, p: 1 }).unwrap()
    })
}

fn check_wallet_file(b: &[u8]) -> Result<(), String> {
    let Ok(s) = std::str::from_utf8(b) else { return Ok(()) };
    let orig = wallet_file_seed();
    let same = s.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n')) == orig;
    if !same && varve_wallet::file::decrypt(s, "fuzz passphrase").is_ok() {
        return Err("a modified wallet file decrypted successfully".into());
    }
    if same && varve_wallet::file::decrypt(s, "fuzz passphrase").ok().as_deref() != Some(&b"fuzz plaintext"[..]) {
        return Err("the original wallet file no longer decrypts".into());
    }
    Ok(())
}

fn seeds() -> Vec<(&'static str, Check, Vec<Vec<u8>>, usize)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../test-vectors/");
    let load = |f: &str| Json::parse(&std::fs::read_to_string(format!("{}{}", dir, f)).expect("test vectors")).expect("json");
    let cons = load("consensus.json");
    let chain = load("chain.json");
    let txs: Vec<Vec<u8>> = cons.at("transactions").as_arr().unwrap().iter().filter_map(|t| t.get("hex").and_then(|h| h.as_str()).and_then(unhex)).collect();
    let headers: Vec<Vec<u8>> = cons.at("headers").as_arr().unwrap().iter().filter_map(|t| t.get("hex").and_then(|h| h.as_str()).and_then(unhex)).collect();
    let mut blocks: Vec<Vec<u8>> = chain.at("base_chain").as_arr().unwrap().iter().filter_map(|b| b.as_str().and_then(unhex)).take(40).collect();
    blocks.extend(chain.at("cases").as_arr().unwrap().iter().filter_map(|c| c.get("block").and_then(|b| b.as_str()).and_then(unhex)).take(40));
    let mut block_txs = Vec::new();
    for b in blocks.iter().take(40) {
        if let Ok(blk) = Block::parse(b) {
            block_txs.extend(blk.txs.iter().map(|t| t.serialize()));
        }
    }
    let mut all_txs = txs.clone();
    all_txs.extend(block_txs);
    let msgs: Vec<Vec<u8>> = all_txs
        .iter()
        .take(20)
        .map(|t| {
            let mut v = vec![12u8]; // "tx"
            v.extend(t);
            v
        })
        .chain(blocks.iter().take(5).map(|b| {
            let mut v = vec![11u8]; // "block"
            v.extend(b);
            v
        }))
        .chain([vec![8u8, 1, 1, 0, 0, 0].into_iter().chain([7u8; 32]).collect(), vec![2u8, 1, 2, 3, 4, 5, 6, 7, 8]])
        .collect();
    let addrs: Vec<Vec<u8>> = load("addresses.json").at("addresses").as_arr().map(|a| a.iter().filter_map(|c| c.get("address").and_then(|x| x.as_str()).map(|s| s.as_bytes().to_vec())).collect()).unwrap_or_default();
    let json_seeds: Vec<Vec<u8>> = vec![
        br#"{"method":"getblockcount","params":["1",2,true,null,[],{}],"id":1}"#.to_vec(),
        br#"[1.5e10,-0,"\u00e9\n",{"a":{"b":[[[]]]}}]"#.to_vec(),
    ];
    let mn = varve_wallet::bip39::entropy_to_mnemonic(&[0x5a; 32]);
    let http_seeds = vec![
        b"POST /local/build HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        b"GET /app.js HTTP/1.1\r\nHost: localhost:1234\r\n\r\n".to_vec(),
    ];
    vec![
        ("transaction", check_tx as Check, all_txs, 200),
        ("block", check_block, blocks, 50),
        ("header", check_header, headers, 200),
        ("p2p-message", check_msg, msgs, 200),
        ("address", check_address, addrs, 200),
        ("json", check_json, json_seeds, 200),
        ("mnemonic", check_mnemonic, vec![mn.into_bytes()], 200),
        ("strata-http", check_http, http_seeds, 200),
        ("wallet-file", check_wallet_file, vec![wallet_file_seed().as_bytes().to_vec()], 2),
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let seconds: u64 = get("--seconds").and_then(|v| v.parse().ok()).unwrap_or(60);
    let seed: u64 = get("--seed").and_then(|v| v.parse().ok()).unwrap_or_else(|| {
        let mut b = [0u8; 8];
        varve_sys::random_bytes(&mut b);
        u64::from_le_bytes(b) | 1
    });
    let out = get("--out").unwrap_or_else(|| "fuzz-crashes".into());
    println!("varve-fuzz: seed {} for {} s", seed, seconds);
    let targets = seeds();
    std::panic::set_hook(Box::new(|_| {})); // panics in targets are caught and reported below
    let mut rng = Rng(seed);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut counts = vec![0u64; targets.len()];
    let mut failure: Option<Failure> = None;
    'outer: while Instant::now() < deadline {
        for (i, (name, check, pool, per_round)) in targets.iter().enumerate() {
            // per_round: inputs per round; the wallet-file target is slow (a mutated file
            // that stays well-formed runs the key-derivation function)
            for _ in 0..*per_round {
                let base: Vec<u8> = if pool.is_empty() || rng.below(10) == 0 {
                    (0..rng.below(300)).map(|_| rng.next() as u8).collect()
                } else {
                    pool[rng.below(pool.len())].clone()
                };
                let input = mutate(&mut rng, &base, pool);
                counts[i] += 1;
                match catch_unwind(AssertUnwindSafe(|| check(&input))) {
                    Ok(Ok(())) => {}
                    Ok(Err(why)) => {
                        failure = Some(Failure { target: name, input, why });
                        break 'outer;
                    }
                    Err(p) => {
                        let why = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_else(|| "panic".into());
                        failure = Some(Failure { target: name, input, why: format!("panic: {}", why) });
                        break 'outer;
                    }
                }
            }
        }
    }
    for ((name, ..), n) in targets.iter().zip(&counts) {
        println!("  {:<12} {:>10} inputs", name, n);
    }
    if let Some(f) = failure {
        let _ = std::fs::create_dir_all(&out);
        let path = format!("{}/{}-{}.hex", out, f.target, seed);
        let _ = std::fs::write(&path, hex(&f.input));
        println!("FAIL [{}] {} (input saved to {}; reproduce with --seed {})", f.target, f.why, path, seed);
        std::process::exit(1);
    }
    println!("OK: no panics or round-trip failures");
}
