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
  varve wallet [options] create | import | address | balance | newaddress
                         | send ADDRESS AMOUNT [FEERATE] | phrase | repair
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
  --mine-to ADDRESS  pay mined coins to this address instead (no keys needed on
                     this machine; for example an address from Strata)
  --threads N        mining threads (default: all CPU cores)
  --light            mine in light mode (256 MiB instead of ~2.1 GiB, slower)
  --api-port N       serve the public read-only API (node/API.md) on port N
  --api-bind ADDR    address for the API (default 127.0.0.1; use a TLS proxy to publish)
  --api-trust-proxy  rate-limit by the last X-Forwarded-For address (behind a proxy only)
  --passphrase-file F  read the wallet passphrase from a file (automation and tests)

WALLET:
  The wallet is encrypted with your passphrase and restorable from 24 words (the same
  format as the Strata wallet). The node only needs public addresses to mine and to show
  balances; private keys are decrypted only for a payment and wiped right after.

RPC METHODS:
  getblockchaininfo getblockcount getbestblockhash getblockhash getblock
  getmininginfo getpeerinfo getconnectioncount getmempoolinfo getrawmempool
  getbalance getnewaddress sendtoaddress walletpassphrase walletlock
  sendrawtransaction submitblock uptime stop
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
    passphrase_file: Option<PathBuf>,
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
        passphrase_file: None,
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
            "--passphrase-file" => a.passphrase_file = Some(PathBuf::from(val("--passphrase-file")?)),
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

/// Create the data directory and make it owner-only (0700) on Unix, so files added
/// later never depend on their own permissions to stay private.
fn make_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
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
    if let Err(e) = make_private_dir(&dir) {
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
    let wallet = match wallet::Wallet::open(&dir) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: wallet: {}", e);
            return 1;
        }
    };
    if wallet.exists() {
        eprintln!("[wallet] encrypted wallet loaded (public addresses only; keys stay encrypted until a payment)");
    }
    let pay_to = if a.mine {
        match &a.mine_to {
            Some(addr) => match address::decode(hrp, addr) {
                Ok(o) => Some(o),
                Err(e) => {
                    eprintln!("error: --mine-to: {}", e);
                    return 1;
                }
            },
            None => match wallet.mining_output() {
                Ok(o) => Some(o),
                Err(e) => {
                    eprintln!("error: --mine: {}", e);
                    return 1;
                }
            },
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
    {
        // lock the wallet again when its unlock period ends
        let n = node.clone();
        std::thread::spawn(move || {
            while n.running() {
                std::thread::sleep(Duration::from_secs(2));
                n.wallet.lock().unwrap().expire();
            }
        });
    }
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
        let bind: std::net::IpAddr = match a.api_bind.as_deref().unwrap_or("127.0.0.1").parse() {
            Ok(b) => b,
            Err(_) => {
                eprintln!("error: bad --api-bind");
                return 1;
            }
        };
        if a.api_trust_proxy && !bind.is_loopback() {
            // forwarded addresses can only be trusted when the only client is a local proxy
            eprintln!("error: --api-trust-proxy needs the API on a loopback address (put the TLS proxy in front of 127.0.0.1)");
            return 1;
        }
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

/// Read a secret from the terminal without echo (Unix), or from --passphrase-file.
fn read_secret(a: &Args, prompt: &str) -> Result<String, String> {
    if let Some(f) = &a.passphrase_file {
        let t = std::fs::read_to_string(f).map_err(|e| format!("--passphrase-file: {}", e))?;
        return Ok(t.lines().next().unwrap_or("").to_string());
    }
    read_hidden(prompt)
}

fn read_hidden(prompt: &str) -> Result<String, String> {
    use std::io::Write;
    eprint!("{}", prompt);
    let _ = std::io::stderr().flush();
    #[cfg(unix)]
    let echo_off = std::process::Command::new("stty").arg("-echo").stdin(std::process::Stdio::inherit()).status().map(|s| s.success()).unwrap_or(false);
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    #[cfg(unix)]
    if echo_off {
        let _ = std::process::Command::new("stty").arg("echo").stdin(std::process::Stdio::inherit()).status();
        eprintln!();
    }
    r.map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn new_passphrase(a: &Args) -> Result<String, String> {
    let p = read_secret(a, "Choose a wallet passphrase (at least 10 characters): ")?;
    wallet::check_passphrase(&p)?;
    if a.passphrase_file.is_none() && read_hidden("Repeat the passphrase: ")? != p {
        return Err("the passphrases do not match".into());
    }
    Ok(p)
}

fn run_wallet(a: &Args) -> i32 {
    let sub = a.rest.first().map(|s| s.as_str()).unwrap_or("");
    let p = match params_for(a) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    let dir = datadir(a);
    let fail = |e: String| {
        eprintln!("error: {}", e);
        1
    };
    match sub {
        "create" | "import" => {
            if let Err(e) = make_private_dir(&dir) {
                return fail(e.to_string());
            }
            let words = if sub == "import" {
                match read_hidden("Enter your 24-word recovery phrase: ") {
                    Ok(w) => Some(w),
                    Err(e) => return fail(e),
                }
            } else {
                None
            };
            let pass = match new_passphrase(a) {
                Ok(p) => p,
                Err(e) => return fail(e),
            };
            match wallet::Wallet::create(&dir, &pass, words.as_deref()) {
                Ok(phrase) => {
                    if sub == "create" {
                        println!("Your recovery phrase (write it down on paper, keep it secret; it is shown only now):\n");
                        for (i, w) in phrase.split_whitespace().enumerate() {
                            print!("{:>2}. {:<10}{}", i + 1, w, if i % 4 == 3 { "\n" } else { " " });
                        }
                        println!("\nAnyone with these words can take the coins. The same words open this wallet in Strata.");
                    }
                    match wallet::Wallet::open(&dir) {
                        Ok(w) => println!("First address: {}", w.address(p.hrp, 0, 0)),
                        Err(e) => return fail(e),
                    }
                    println!("Wallet saved, encrypted, in {}. Restart the node if it is running.", dir.display());
                    0
                }
                Err(e) => fail(e),
            }
        }
        "address" => match wallet::Wallet::open(&dir).and_then(|w| w.mining_output().map(|o| address::encode(p.hrp, &o))) {
            Ok(addr) => {
                println!("{}", addr);
                0
            }
            Err(e) => fail(e),
        },
        "phrase" => match read_secret(a, "Wallet passphrase: ").and_then(|pass| wallet::Wallet::phrase(&dir, &pass)) {
            Ok(w) => {
                println!("{}", w);
                0
            }
            Err(e) => fail(e),
        },
        "repair" => match read_secret(a, "Wallet passphrase: ").and_then(|pass| wallet::Wallet::repair(&dir, &pass)) {
            Ok(()) => {
                println!("Public address list rebuilt. Restart the node if it is running.");
                0
            }
            Err(e) => fail(e),
        },
        "balance" => run_rpc(a, "getbalance".into(), vec![]),
        "newaddress" => run_rpc(a, "getnewaddress".into(), vec![]),
        "send" => {
            let args: Vec<String> = a.rest.iter().skip(1).cloned().collect();
            if args.len() < 2 {
                return fail("usage: varve wallet send ADDRESS AMOUNT [FEERATE]".into());
            }
            let pass = match read_secret(a, "Wallet passphrase: ") {
                Ok(p) => p,
                Err(e) => return fail(e),
            };
            let port = rpc_port(a, a.port.unwrap_or(p.default_port));
            // unlock for one minute, pay, lock again right away
            if let Err(e) = rpc::client_call(&dir, port, "walletpassphrase", vec![pass, "60".into()]) {
                return fail(e);
            }
            let r = rpc::client_call(&dir, port, "sendtoaddress", args);
            let _ = rpc::client_call(&dir, port, "walletlock", vec![]);
            match r {
                Ok(txid) => {
                    println!("{}", txid);
                    0
                }
                Err(e) => fail(e),
            }
        }
        _ => {
            eprintln!("usage: varve wallet create | import | address | balance | newaddress | send ADDRESS AMOUNT [FEERATE] | phrase | repair");
            2
        }
    }
}
