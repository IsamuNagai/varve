//! `varve` — reference node, miner and wallet (testnet software; see node/README.md).

mod address;
mod api;
mod chain;
mod index;
mod mempool;
mod miner;
mod node;
mod p2p;
mod rpc;
mod wallet;
mod wire;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use varve_consensus::networks;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Public testnet seed nodes (host or host:port). Filled in when the first public node exists.
const TESTNET_SEEDS: &[&str] = &[];

const USAGE: &str = "\
varve — Varve reference node, miner and wallet (TESTNET SOFTWARE)

USAGE:
  varve node   [options]               run a node (add --mine to mine)
  varve rpc    [options] METHOD [ARGS] call a running node
  varve wallet [options] balance | address | newaddress | send ADDRESS AMOUNT [FEERATE]
  varve version

OPTIONS:
  --network NAME     testnet (default) or regtest. Mainnet does not exist yet.
  --datadir DIR      data directory (default: ~/.varve/<network>)
  --port N           P2P port to listen on (default: 39900 testnet, 49900 regtest)
  --nolisten         do not accept incoming connections
  --connect HOST     connect only to this peer (repeatable)
  --seed HOST        extra peer to connect to (repeatable)
  --rpcport N        local RPC port (default: P2P port + 1); bound to 127.0.0.1 only
  --mine             mine new blocks (pays to your wallet's first address)
  --mine-to ADDRESS  pay mined coins to this address instead
  --threads N        mining threads (default: all CPU cores)
  --light            mine in light mode (256 MiB instead of ~2.1 GiB, slower)
  --api-port N       serve the public read-only API (node/API.md) on port N
  --api-bind ADDR    address for the API (default 127.0.0.1; use a TLS proxy to publish)
  --api-trust-proxy  rate-limit by the last X-Forwarded-For address (behind a proxy only)

RPC METHODS:
  getblockchaininfo getblockcount getbestblockhash getblockhash getblock
  getmininginfo getpeerinfo getconnectioncount getmempoolinfo getrawmempool
  getbalance getnewaddress sendtoaddress sendrawtransaction submitblock uptime stop
";

struct Args {
    cmd: String,
    network: String,
    datadir: Option<PathBuf>,
    port: Option<u16>,
    listen: bool,
    connect: Vec<String>,
    seeds: Vec<String>,
    rpcport: Option<u16>,
    mine: bool,
    mine_to: Option<String>,
    threads: Option<usize>,
    light: bool,
    api_port: Option<u16>,
    api_bind: Option<String>,
    api_trust_proxy: bool,
    rest: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut a = Args {
        cmd,
        network: "testnet".into(),
        datadir: None,
        port: None,
        listen: true,
        connect: vec![],
        seeds: vec![],
        rpcport: None,
        mine: false,
        mine_to: None,
        threads: None,
        light: false,
        api_port: None,
        api_bind: None,
        api_trust_proxy: false,
        rest: vec![],
    };
    while let Some(x) = it.next() {
        let mut val = |name: &str| it.next().ok_or(format!("{} needs a value", name));
        match x.as_str() {
            "--network" => a.network = val("--network")?,
            "--datadir" => a.datadir = Some(PathBuf::from(val("--datadir")?)),
            "--port" => a.port = Some(val("--port")?.parse().map_err(|_| "bad --port")?),
            "--nolisten" => a.listen = false,
            "--connect" => a.connect.push(val("--connect")?),
            "--seed" | "--addnode" => a.seeds.push(val("--seed")?),
            "--rpcport" => a.rpcport = Some(val("--rpcport")?.parse().map_err(|_| "bad --rpcport")?),
            "--mine" => a.mine = true,
            "--mine-to" => a.mine_to = Some(val("--mine-to")?),
            "--threads" => a.threads = Some(val("--threads")?.parse().map_err(|_| "bad --threads")?),
            "--light" => a.light = true,
            "--api-port" => a.api_port = Some(val("--api-port")?.parse().map_err(|_| "bad --api-port")?),
            "--api-bind" => a.api_bind = Some(val("--api-bind")?),
            "--api-trust-proxy" => a.api_trust_proxy = true,
            "-h" | "--help" => a.cmd = "help".into(),
            s if s.starts_with("--") => return Err(format!("unknown option {}", s)),
            _ => a.rest.push(x),
        }
    }
    Ok(a)
}

fn main() {
    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}\n\n{}", e, USAGE);
            std::process::exit(2);
        }
    };
    let code = match a.cmd.as_str() {
        "node" => run_node(a),
        "rpc" => run_rpc(&a, a.rest.first().cloned().unwrap_or_default(), a.rest.iter().skip(1).cloned().collect()),
        "wallet" => run_wallet(&a),
        "version" | "--version" => {
            println!("varve {} (testnet software)", VERSION);
            0
        }
        _ => {
            print!("{}", USAGE);
            if a.cmd.is_empty() || a.cmd == "help" { 0 } else { 2 }
        }
    };
    std::process::exit(code);
}

fn params_for(a: &Args) -> Result<varve_consensus::params::ChainParams, String> {
    let p = networks::by_name(&a.network).ok_or_else(|| format!("unknown network {}", a.network))?;
    if !p.launchable {
        return Err(format!("network '{}' does not exist yet: its launch parameters are not final", a.network));
    }
    Ok(p)
}

fn datadir(a: &Args) -> PathBuf {
    a.datadir.clone().unwrap_or_else(|| {
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".varve").join(&a.network)
    })
}

fn rpc_port(a: &Args, p2p: u16) -> u16 {
    a.rpcport.unwrap_or(p2p + 1)
}

fn run_node(a: Args) -> i32 {
    let params = match params_for(&a) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    let dir = datadir(&a);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("error: cannot create {}: {}", dir.display(), e);
        return 1;
    }
    let port = a.port.unwrap_or(params.default_port);
    let hrp = params.hrp;
    let mut seeds = a.seeds.clone();
    if params.name == "testnet" {
        seeds.extend(TESTNET_SEEDS.iter().map(|s| s.to_string()));
    }
    eprintln!("varve {} — {} — data in {}", VERSION, params.name, dir.display());
    let chain = match chain::Chain::open(params, &dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    eprintln!("[chain] genesis {}", varve_consensus::encoding::hex(&chain.genesis_id));
    let wallet = match wallet::Wallet::open_or_create(&dir) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: wallet: {}", e);
            return 1;
        }
    };
    let pay_to = if a.mine {
        match &a.mine_to {
            Some(addr) => match address::decode(hrp, addr) {
                Ok(o) => Some(o),
                Err(e) => {
                    eprintln!("error: --mine-to: {}", e);
                    return 1;
                }
            },
            None => Some(wallet.output_for(0)),
        }
    } else {
        None
    };
    if let Some(o) = &pay_to {
        eprintln!("[miner] paying to {}", address::encode(hrp, o));
    }
    let cfg = node::Config {
        datadir: dir.clone(),
        listen: if a.listen { Some(SocketAddr::from(([0, 0, 0, 0], port))) } else { None },
        connect: a.connect.clone(),
        seeds,
        max_outbound: 8,
        max_inbound: 117,
        rpc_port: rpc_port(&a, port),
        user_agent: format!("/varve:{}/", VERSION),
    };
    let node = node::Node::new(cfg, chain, wallet);
    p2p::start(node.clone());
    let stats = pay_to.map(|o| {
        let threads = a.threads.unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
        eprintln!("[miner] {} threads, {} mode", threads, if a.light { "light" } else { "fast" });
        miner::start(node.clone(), o, threads, !a.light)
    });
    if let Err(e) = rpc::start(node.clone(), stats) {
        eprintln!("error: {}", e);
        return 1;
    }
    if let Some(port) = a.api_port {
        let bind = match a.api_bind.as_deref().unwrap_or("127.0.0.1").parse() {
            Ok(b) => b,
            Err(_) => {
                eprintln!("error: bad --api-bind");
                return 1;
            }
        };
        if let Err(e) = api::start(node.clone(), api::ApiConfig { bind, port, trust_proxy: a.api_trust_proxy }) {
            eprintln!("error: {}", e);
            return 1;
        }
    }
    while node.running() {
        std::thread::sleep(Duration::from_millis(500));
    }
    node.shutdown.store(true, Ordering::SeqCst);
    eprintln!("[node] stopped");
    0
}

fn run_rpc(a: &Args, method: String, params: Vec<String>) -> i32 {
    if method.is_empty() {
        eprintln!("usage: varve rpc METHOD [ARGS]");
        return 2;
    }
    let p = match networks::by_name(&a.network) {
        Some(p) => p,
        None => {
            eprintln!("unknown network");
            return 2;
        }
    };
    let port = rpc_port(a, a.port.unwrap_or(p.default_port));
    match rpc::client_call(&datadir(a), port, &method, params) {
        Ok(s) => {
            println!("{}", s);
            0
        }
        Err(e) => {
            eprintln!("error: {}", e);
            1
        }
    }
}

fn run_wallet(a: &Args) -> i32 {
    let sub = a.rest.first().map(|s| s.as_str()).unwrap_or("");
    let (m, params): (&str, Vec<String>) = match sub {
        "balance" => ("getbalance", vec![]),
        "newaddress" => ("getnewaddress", vec![]),
        "address" => {
            // first address, without contacting the node
            let p = match params_for(a) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return 1;
                }
            };
            let dir = datadir(a);
            let _ = std::fs::create_dir_all(&dir);
            return match wallet::Wallet::open_or_create(&dir) {
                Ok(w) => {
                    println!("{}", w.address(p.hrp, 0));
                    0
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    1
                }
            };
        }
        "send" => ("sendtoaddress", a.rest.iter().skip(1).cloned().collect()),
        _ => {
            eprintln!("usage: varve wallet balance | address | newaddress | send ADDRESS AMOUNT [FEERATE]");
            return 2;
        }
    };
    run_rpc(a, m.to_string(), params)
}
