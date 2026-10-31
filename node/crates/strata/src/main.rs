//! Strata: the Varve desktop wallet. A small local server on 127.0.0.1 holds the
//! keys and signs; the UI runs in the user's browser and reads public chain data
//! from a Varve node API (node/API.md).

mod address;
mod app;
mod config;
mod http;
mod txbuild;

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use varve_consensus::encoding::hex;
use varve_consensus::validate::ChainIds;

use crate::app::App;
use crate::http::{Access, Response};

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");
const MARK_PNG: &[u8] = include_bytes!("../ui/varve-mark-light.png");

const USAGE: &str = "Strata, the Varve desktop wallet

Usage: strata [--network testnet|regtest] [--port N] [--no-browser] [--datadir DIR]

  --network   testnet (default) or regtest. Mainnet has not launched.
  --port      local port for the wallet UI (default: a random free port)
  --no-browser  print the address instead of opening a browser
  --datadir   base data directory (default: the OS application data directory);
              each network uses its own subfolder
";

struct Args {
    network: String,
    port: u16,
    browser: bool,
    datadir: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args { network: "testnet".into(), port: 0, browser: true, datadir: None };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |name: &str| it.next().ok_or(format!("{} needs a value", name));
        match arg.as_str() {
            "--network" => a.network = val("--network")?,
            "--port" => a.port = val("--port")?.parse().map_err(|_| "bad --port")?,
            "--no-browser" => a.browser = false,
            "--datadir" => a.datadir = Some(PathBuf::from(val("--datadir")?)),
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "--version" => {
                println!("strata {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            s => return Err(format!("unknown option {}", s)),
        }
    }
    Ok(a)
}

/// Open the URL in the default browser. The URL is passed as a single argument,
/// never through a shell string.
fn open_browser(url: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    #[cfg(target_os = "macos")]
    let mut c = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(windows)]
    let mut c = {
        // `start` is a cmd built-in; the empty string is the window title. The URL only
        // contains [0-9a-z:/.#=], so cmd has nothing to interpret in it.
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]).arg(url);
        c
    };
    #[cfg(not(any(target_os = "macos", windows)))]
    let mut c = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(|_| ())
}

fn serve_static(path: &str) -> Response {
    match path {
        "/" | "/index.html" => Response { status: 200, content_type: "text/html; charset=utf-8", body: INDEX_HTML.as_bytes().to_vec() },
        "/app.js" => Response { status: 200, content_type: "text/javascript; charset=utf-8", body: APP_JS.as_bytes().to_vec() },
        "/app.css" => Response { status: 200, content_type: "text/css; charset=utf-8", body: APP_CSS.as_bytes().to_vec() },
        "/varve-mark.png" | "/favicon.ico" => Response { status: 200, content_type: "image/png", body: MARK_PNG.to_vec() },
        _ => Response::error(404, "not found"),
    }
}

fn handle_conn(mut s: TcpStream, app: &App, port: u16, token: &str) {
    let _ = s.set_read_timeout(Some(http::READ_TIMEOUT));
    let _ = s.set_write_timeout(Some(http::READ_TIMEOUT));
    let deadline = Instant::now() + http::READ_TIMEOUT;
    let (resp, head) = match http::read_request(&mut s, deadline) {
        Err(e) => (Response::error(e.0, e.1), false),
        Ok(req) => {
            let head = req.method == "HEAD";
            let resp = match http::guard(&req, port, token) {
                Err(e) => Response::error(e.0, e.1),
                Ok(Access::Static) => serve_static(&req.path),
                Ok(Access::Local) => app.handle(&req),
            };
            (resp, head)
        }
    };
    // the CSP reflects the endpoint configured at the time of the response
    let origin = app.api_origin();
    http::write_response(&mut s, &http::render(&resp, &origin, head));
    let _ = s.shutdown(std::net::Shutdown::Both);
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}\n\n{}", e, USAGE);
            std::process::exit(2);
        }
    };
    if args.network == "mainnet" {
        eprintln!("error: Varve mainnet has not launched. Strata runs on testnet (default) or regtest.");
        std::process::exit(2);
    }
    let params = match args.network.as_str() {
        "testnet" => varve_consensus::networks::testnet(),
        "regtest" => varve_consensus::networks::regtest(),
        _ => {
            eprintln!("error: unknown network {:?}; use testnet or regtest", args.network);
            std::process::exit(2);
        }
    };
    let genesis = match varve_consensus::genesis::genesis_block(&params) {
        Ok(b) => b.header.block_id(),
        Err(e) => {
            eprintln!("error: cannot build the {} genesis block: {}", params.name, e);
            std::process::exit(1);
        }
    };
    let ids = ChainIds { network_id: params.network_id, genesis_id: genesis, lifecycle: params.lifecycle.clone() };
    let base = match args.datadir.clone().map(Ok).unwrap_or_else(config::default_base_dir) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    };
    let dir = base.join(params.name);
    if let Err(e) = config::create_private_dir(&dir) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
    let listener = match TcpListener::bind(("127.0.0.1", args.port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: cannot listen on 127.0.0.1:{}: {}", args.port, e);
            std::process::exit(1);
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(args.port);
    let mut t = [0u8; 32];
    varve_sys::random_bytes(&mut t);
    let token = Arc::new(hex(&t));
    let app = Arc::new(App::new(params, ids, dir.clone()));
    let url = format!("http://127.0.0.1:{}/#token={}", port, token);

    eprintln!("[strata] {} wallet, data in {}", app.params.name, dir.display());
    eprintln!("[strata] chain data from {}", app.api_endpoint());
    println!("Strata is running. Open this address in your browser (keep it private):");
    println!("{}", url);
    if args.browser {
        if let Err(e) = open_browser(&url) {
            eprintln!("[strata] could not open a browser ({}); open the address above yourself", e.kind());
        }
    }
    {
        let app = app.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            app.autolock_check();
        });
    }
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(mut s) = conn else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= http::MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
            http::write_response(&mut s, &http::render(&Response::error(503, "too many connections"), &app.api_origin(), false));
            continue;
        }
        let (app2, token2, active2) = (app.clone(), token.clone(), active.clone());
        let spawned = std::thread::Builder::new().spawn(move || {
            handle_conn(s, &app2, port, &token2);
            active2.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}
