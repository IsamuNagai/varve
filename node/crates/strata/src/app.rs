//! Wallet session state and the /local/* endpoints.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use varve_consensus::encoding::hex;
use varve_consensus::json::Json;
use varve_consensus::params::ChainParams;
use varve_consensus::validate::ChainIds;
use varve_wallet::{Wallet, WalletError};

use crate::address;
use crate::config::{self, AddrState, Config, GAP, WALLET_FILE};
use crate::http::{Request, Response};
use crate::txbuild::{self, KeyPath};

pub const MIN_FILE_PASS: usize = 10;
pub const MAX_PASS: usize = 1024;
const MAX_UNLOCK_DELAY_SECS: u64 = 300;
/// Hard bound on address indexes the UI can make us derive.
const MAX_INDEX: u32 = 100_000;

pub struct Session {
    wallet: Wallet,
    /// non-secret: commitment and address per derived key
    keys: HashMap<KeyPath, ([u8; 32], String)>,
    by_commitment: HashMap<[u8; 32], KeyPath>,
}

impl Session {
    fn new(wallet: Wallet) -> Session {
        Session { wallet, keys: HashMap::new(), by_commitment: HashMap::new() }
    }
    fn key(&mut self, p: KeyPath, hrp: &str) -> Result<([u8; 32], String), String> {
        if let Some(k) = self.keys.get(&p) {
            return Ok(k.clone());
        }
        let kp = p.derive(&self.wallet)?;
        let addr = kp.address(hrp).map_err(|_| "address encoding failed".to_string())?;
        self.keys.insert(p, (kp.commitment, addr.clone()));
        self.by_commitment.insert(kp.commitment, p);
        Ok((kp.commitment, addr))
    }
    fn wallet_id(&mut self, hrp: &str) -> Result<String, String> {
        Ok(hex(&self.key(KeyPath::receive(0), hrp)?.0[..8]))
    }
}

pub struct State {
    pub config: Config,
    pub addrs: AddrState,
    pub session: Option<Session>,
    pub last_activity: Instant,
    pub failures: u32,
    pub next_attempt: Option<Instant>,
}

pub struct App {
    pub params: ChainParams,
    pub ids: ChainIds,
    pub dir: PathBuf,
    pub st: Mutex<State>,
    /// test hook: KDF parameters for new wallet files (None = library default)
    pub kdf: Option<varve_wallet::argon2::Params>,
}

type R = Result<Json, (u16, String)>;

fn err<T>(status: u16, msg: impl Into<String>) -> Result<T, (u16, String)> {
    Err((status, msg.into()))
}

/// File passphrase policy: at least 10 characters, ASCII (the wallet file format's
/// normalization rule), and not trivially weak.
pub fn check_file_pass(p: &str) -> Result<(), &'static str> {
    if p.len() > MAX_PASS {
        return Err("the passphrase is too long");
    }
    if !p.is_ascii() || p.bytes().any(|c| c < b' ' || c == 0x7f) {
        return Err("use printable ASCII characters only (letters, digits, punctuation, spaces)");
    }
    if p.chars().count() < MIN_FILE_PASS {
        return Err("use at least 10 characters");
    }
    let lower = p.to_ascii_lowercase();
    let mut distinct: Vec<u8> = lower.bytes().collect();
    distinct.sort();
    distinct.dedup();
    if distinct.len() < 4 {
        return Err("this passphrase is too easy to guess; use more different characters");
    }
    let b = lower.as_bytes();
    let step_run = b.windows(2).all(|w| w[1] as i16 - w[0] as i16 == b[1] as i16 - b[0] as i16) && (b[1] as i16 - b[0] as i16).abs() <= 1;
    if step_run {
        return Err("this passphrase is too easy to guess");
    }
    const WEAK: [&str; 16] = [
        "password", "passw0rd", "qwerty", "azerty", "123456", "letmein", "iloveyou", "welcome", "admin", "abc123", "monkey", "dragon",
        "varve", "strata", "wallet", "bitcoin",
    ];
    let stripped: String = lower.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let digits_only = lower.bytes().all(|c| c.is_ascii_digit());
    if digits_only && p.len() < 16 {
        return Err("a passphrase of only digits must have at least 16 digits");
    }
    for w in WEAK {
        // a common word plus a few characters of padding
        if lower.contains(w) && lower.len() < w.len() + 6 {
            return Err("this passphrase is too easy to guess");
        }
        if stripped == w {
            return Err("this passphrase is too easy to guess");
        }
    }
    Ok(())
}

fn unlock_delay(failures: u32) -> Duration {
    Duration::from_secs((1u64 << failures.saturating_sub(1).min(16)).min(MAX_UNLOCK_DELAY_SECS))
}

fn body_json(req: &Request) -> Result<Json, (u16, String)> {
    let s = std::str::from_utf8(&req.body).map_err(|_| (400, "request body is not UTF-8".to_string()))?;
    let j = Json::parse(s).map_err(|_| (400, "request body is not valid JSON".to_string()))?;
    if j.as_obj().is_none() {
        return err(400, "request body must be a JSON object");
    }
    Ok(j)
}

fn get_str<'a>(j: &'a Json, k: &str) -> Result<Option<&'a str>, (u16, String)> {
    match j.get(k) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Str(s)) => Ok(Some(s)),
        _ => err(400, format!("{} must be a string", k)),
    }
}

fn get_bool(j: &Json, k: &str) -> Result<bool, (u16, String)> {
    match j.get(k) {
        None | Some(Json::Null) => Ok(false),
        Some(Json::Bool(b)) => Ok(*b),
        _ => err(400, format!("{} must be true or false", k)),
    }
}

/// Map wallet library errors to messages that never contain secret input.
fn wallet_err(e: &WalletError) -> String {
    match e {
        WalletError::Mnemonic(m) => format!("the recovery phrase is not valid: {}", m),
        WalletError::Auth => "wrong passphrase".into(),
        WalletError::Unsupported(_) => "use printable ASCII characters only in passphrases".into(),
        WalletError::Io(k) => format!("file error: {}", k),
        WalletError::Format(_) | WalletError::UnknownFormat | WalletError::KdfParams => "the wallet file is damaged or in an unknown format".into(),
        WalletError::Crypto(_) => "a cryptographic operation failed".into(),
    }
}

impl App {
    pub fn new(params: ChainParams, ids: ChainIds, dir: PathBuf) -> App {
        let config = Config::load(&dir, params.name);
        let addrs = AddrState::load(&dir);
        App {
            params,
            ids,
            dir,
            st: Mutex::new(State { config, addrs, session: None, last_activity: Instant::now(), failures: 0, next_attempt: None }),
            kdf: None,
        }
    }

    pub fn wallet_path(&self) -> PathBuf {
        self.dir.join(WALLET_FILE)
    }

    pub fn api_origin(&self) -> String {
        self.lock_state().config.api_origin.clone()
    }

    pub fn api_endpoint(&self) -> String {
        self.lock_state().config.api_endpoint.clone()
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        // a panic while holding the lock must not brick the wallet: recover the guard
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop the wallet (the library wipes the seed on drop) if idle too long.
    pub fn autolock_check(&self) {
        let mut st = self.lock_state();
        let idle = Duration::from_secs(st.config.autolock_minutes as u64 * 60);
        if st.session.is_some() && st.last_activity.elapsed() >= idle {
            st.session = None;
            eprintln!("[strata] wallet locked after {} idle minutes", st.config.autolock_minutes);
        }
    }

    pub fn handle(&self, req: &Request) -> Response {
        self.autolock_check();
        let background = req.header_once("x-strata-background").ok().flatten() == Some("1");
        if req.path != "/local/status" && !background {
            self.lock_state().last_activity = Instant::now();
        }
        let r = match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/local/status") => Ok(self.status(&self.lock_state())),
            ("POST", "/local/ping") => Ok(self.status(&self.lock_state())),
            ("POST", "/local/create") => body_json(req).and_then(|j| self.create(&j, None)),
            ("POST", "/local/import") => body_json(req).and_then(|j| {
                let m = get_str(&j, "mnemonic")?.ok_or((400, "enter your recovery phrase".to_string()))?.to_string();
                self.create(&j, Some(m))
            }),
            ("POST", "/local/unlock") => body_json(req).and_then(|j| self.unlock(&j)),
            ("POST", "/local/lock") => {
                let mut st = self.lock_state();
                st.session = None;
                Ok(self.status(&st))
            }
            ("POST", "/local/reveal") => body_json(req).and_then(|j| self.reveal(&j)),
            ("GET", "/local/addresses") => self.addresses(),
            ("POST", "/local/mark_used") => body_json(req).and_then(|j| self.mark_used(&j)),
            ("POST", "/local/new_address") => self.new_address(),
            ("POST", "/local/build") => body_json(req).and_then(|j| self.build(&j)),
            ("POST", "/local/settings") => body_json(req).and_then(|j| self.settings(&j)),
            (_, p) if p.starts_with("/local/") => err(404, "unknown endpoint"),
            _ => err(404, "not found"),
        };
        match r {
            Ok(j) => Response::json(200, j.to_string()),
            Err((s, m)) => Response::error(s, &m),
        }
    }

    fn status(&self, st: &State) -> Json {
        let retry = st.next_attempt.map(|t| t.saturating_duration_since(Instant::now()).as_secs()).unwrap_or(0);
        Json::obj(vec![
            ("network", Json::str(self.params.name)),
            ("hrp", Json::str(self.params.hrp)),
            ("genesis", Json::str(hex(&self.ids.genesis_id))),
            ("api_endpoint", Json::str(&st.config.api_endpoint)),
            ("has_wallet", Json::Bool(self.wallet_path().exists())),
            ("unlocked", Json::Bool(st.session.is_some())),
            ("autolock_minutes", Json::num(st.config.autolock_minutes)),
            ("retry_after", Json::num(retry)),
            ("version", Json::str(env!("CARGO_PKG_VERSION"))),
        ])
    }

    /// Rate limit for passphrase checks: increasing delay after each failure.
    fn check_rate(&self, st: &State) -> Result<(), (u16, String)> {
        if let Some(t) = st.next_attempt {
            let now = Instant::now();
            if now < t {
                let secs = (t - now).as_secs() + 1;
                return err(429, format!("too many wrong passphrases; try again in {} s", secs));
            }
        }
        Ok(())
    }

    fn record_failure(&self, st: &mut State) {
        st.failures = st.failures.saturating_add(1);
        st.next_attempt = Some(Instant::now() + unlock_delay(st.failures));
    }

    /// The wallet just loaded or created: reset the address state if it belongs to another wallet.
    fn adopt(&self, st: &mut State, mut s: Session, fresh: bool) -> Result<(), (u16, String)> {
        let id = s.wallet_id(self.params.hrp).map_err(|e| (500, e))?;
        if fresh || st.addrs.wallet_id != id {
            st.addrs = AddrState { wallet_id: id, ..AddrState::default() };
            st.addrs.save(&self.dir).map_err(|e| (500, e))?;
        }
        st.session = Some(s);
        st.last_activity = Instant::now();
        Ok(())
    }

    /// POST /local/create and /local/import.
    fn create(&self, j: &Json, mnemonic: Option<String>) -> R {
        let file_pass = get_str(j, "file_pass")?.unwrap_or("");
        check_file_pass(file_pass).map_err(|e| (400, e.to_string()))?;
        let seed_pass = get_str(j, "seed_pass")?.unwrap_or("");
        if seed_pass.len() > MAX_PASS {
            return err(400, "the seed passphrase is too long");
        }
        if !seed_pass.is_ascii() {
            return err(400, "the seed passphrase must use ASCII characters only");
        }
        let replace = get_bool(j, "replace")?;
        let confirm = get_str(j, "confirm")?.unwrap_or("");
        let mut st = self.lock_state();
        let path = self.wallet_path();
        if path.exists() && !(replace && confirm == "REPLACE") {
            return err(409, "a wallet already exists; to replace it, confirm by typing REPLACE");
        }
        let w = match &mnemonic {
            None => Wallet::generate_with_passphrase(seed_pass),
            Some(m) => {
                if m.len() > 1000 {
                    return err(400, "the recovery phrase is too long");
                }
                Wallet::from_mnemonic(m, Some(seed_pass))
            }
        }
        .map_err(|e| (400, wallet_err(&e)))?;
        config::create_private_dir(&self.dir).map_err(|e| (500, e))?;
        if path.exists() {
            // keep the replaced file next to the new one rather than destroying it
            let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let bak = self.dir.join(format!("wallet-replaced-{}.json", secs));
            std::fs::rename(&path, &bak).map_err(|e| (500, format!("cannot move the old wallet file aside: {}", e.kind())))?;
        }
        let saved = match self.kdf {
            Some(p) => w.save_with_params(file_pass, p).map_err(|e| wallet_err(&e)).and_then(|t| config::write_atomic(&path, t.as_bytes())),
            None => {
                let mut tmp = path.as_os_str().to_owned();
                tmp.push(".tmp");
                let _ = std::fs::remove_file(PathBuf::from(tmp));
                w.save_to_path(&path, file_pass).map_err(|e| wallet_err(&e))
            }
        };
        saved.map_err(|e| (500, e))?;
        let words = if mnemonic.is_none() { Some(w.mnemonic()) } else { None };
        self.adopt(&mut st, Session::new(w), true)?;
        st.failures = 0;
        st.next_attempt = None;
        let mut out = vec![("ok", Json::Bool(true))];
        if let Some(m) = &words {
            out.push(("mnemonic", Json::Arr(m.expose().split(' ').map(Json::str).collect())));
        }
        out.push(("status", self.status(&st)));
        Ok(Json::obj(out))
    }

    /// Check a passphrase against the wallet file (rate-limited). Returns the loaded wallet.
    fn load_checked(&self, st: &mut State, j: &Json) -> Result<Wallet, (u16, String)> {
        let pass = get_str(j, "file_pass")?.unwrap_or("");
        if !self.wallet_path().exists() {
            return err(404, "there is no wallet on this computer for this network");
        }
        self.check_rate(st)?;
        if pass.is_empty() || pass.len() > MAX_PASS {
            self.record_failure(st);
            return err(400, "wrong passphrase");
        }
        match Wallet::load_from_path(&self.wallet_path(), pass) {
            Ok(w) => {
                st.failures = 0;
                st.next_attempt = None;
                Ok(w)
            }
            Err(WalletError::Auth) | Err(WalletError::Unsupported(_)) => {
                self.record_failure(st);
                err(400, "wrong passphrase")
            }
            Err(e) => err(500, wallet_err(&e)),
        }
    }

    fn unlock(&self, j: &Json) -> R {
        // the KDF runs while holding the state lock, so attempts are serialized
        let mut st = self.lock_state();
        let w = self.load_checked(&mut st, j)?;
        self.adopt(&mut st, Session::new(w), false)?;
        Ok(self.status(&st))
    }

    /// POST /local/reveal: show the recovery phrase again; requires the file passphrase.
    fn reveal(&self, j: &Json) -> R {
        let mut st = self.lock_state();
        if st.session.is_none() {
            return err(423, "the wallet is locked");
        }
        let w = self.load_checked(&mut st, j)?;
        let m = w.mnemonic();
        Ok(Json::obj(vec![
            ("mnemonic", Json::Arr(m.expose().split(' ').map(Json::str).collect())),
            ("has_seed_passphrase", Json::Bool(w.has_passphrase())),
        ]))
    }

    fn with_session<T>(&self, f: impl FnOnce(&mut State) -> Result<T, (u16, String)>) -> Result<T, (u16, String)> {
        let mut st = self.lock_state();
        if st.session.is_none() {
            return err(423, "the wallet is locked");
        }
        f(&mut st)
    }

    fn addr_list(&self, st: &mut State) -> R {
        let hrp = self.params.hrp;
        let (rw, cw) = (st.addrs.receive_window().min(MAX_INDEX), st.addrs.change_window().min(MAX_INDEX));
        let cur = st.addrs.receive_current();
        let s = st.session.as_mut().unwrap();
        let mut list = |n: u32, f: fn(u32) -> KeyPath| -> Result<Vec<Json>, (u16, String)> {
            (0..n).map(|i| Ok(Json::obj(vec![("index", Json::num(i)), ("address", Json::str(s.key(f(i), hrp).map_err(|e| (500, e))?.1))]))).collect()
        };
        let receive = list(rw, KeyPath::receive)?;
        let change = list(cw, KeyPath::change)?;
        let current = s.key(KeyPath::receive(cur), hrp).map_err(|e| (500, e))?.1;
        let o = |v: Option<u32>| v.map(Json::num).unwrap_or(Json::Null);
        Ok(Json::obj(vec![
            ("receive", Json::Arr(receive)),
            ("change", Json::Arr(change)),
            ("current", Json::obj(vec![("index", Json::num(cur)), ("address", Json::str(current))])),
            ("receive_used", o(st.addrs.receive_used)),
            ("change_used", o(st.addrs.change_used)),
            ("gap", Json::num(GAP)),
        ]))
    }

    fn addresses(&self) -> R {
        self.with_session(|st| self.addr_list(st))
    }

    fn mark_used(&self, j: &Json) -> R {
        self.with_session(|st| {
            let parse = |k: &str, window: u32| -> Result<Option<u32>, (u16, String)> {
                let mut best = None;
                if let Some(v) = j.get(k) {
                    let arr = v.as_arr().ok_or((400, format!("{} must be a list of indexes", k)))?;
                    if arr.len() > 10_000 {
                        return err(400, "too many indexes");
                    }
                    for x in arr {
                        let i = x.as_u64().ok_or((400, format!("{} must be a list of indexes", k)))?;
                        if i >= window as u64 {
                            return err(400, "index outside the address window");
                        }
                        best = best.max(Some(i as u32));
                    }
                }
                Ok(best)
            };
            let r = parse("receive", st.addrs.receive_window())?;
            let c = parse("change", st.addrs.change_window())?;
            let before = st.addrs.clone();
            st.addrs.receive_used = st.addrs.receive_used.max(r);
            st.addrs.change_used = st.addrs.change_used.max(c);
            if st.addrs != before {
                st.addrs.save(&self.dir).map_err(|e| (500, e))?;
            }
            self.addr_list(st)
        })
    }

    fn new_address(&self) -> R {
        self.with_session(|st| {
            let i = st.addrs.issue_receive();
            st.addrs.save(&self.dir).map_err(|e| (500, e))?;
            let a = st.session.as_mut().unwrap().key(KeyPath::receive(i), self.params.hrp).map_err(|e| (500, e))?.1;
            Ok(Json::obj(vec![("index", Json::num(i)), ("address", Json::str(a))]))
        })
    }

    fn build(&self, j: &Json) -> R {
        let to_s = get_str(j, "to")?.unwrap_or("").trim().to_string();
        let to = address::decode(self.params.hrp, &to_s).map_err(|e| (400, e.to_string()))?;
        let send_max = get_bool(j, "send_max")?;
        let amount = if send_max {
            None
        } else {
            let a = txbuild::parse_amount(get_str(j, "amount_laminae")?.unwrap_or("")).map_err(|e| (400, e))?;
            if a == 0 {
                return err(400, "the amount must be more than zero");
            }
            Some(a)
        };
        let feerate = j.get("feerate").and_then(|v| v.as_u64()).filter(|f| (1..=txbuild::MAX_FEERATE).contains(f)).ok_or((400, "invalid fee rate".to_string()))?;
        let api_height = j.get("height").and_then(|v| v.as_u64()).filter(|h| *h < 1 << 40).ok_or((400, "missing or invalid chain height".to_string()))?;
        let allow_high_fee = get_bool(j, "allow_high_fee")?;
        let arr = j.get("utxos").and_then(|v| v.as_arr()).ok_or((400, "utxos must be a list".to_string()))?;
        if arr.len() > txbuild::MAX_UTXOS {
            return err(400, "too many coins in the request");
        }
        let utxos: Vec<txbuild::ApiUtxo> = arr.iter().map(txbuild::parse_utxo).collect::<Result<_, _>>().map_err(|e| (400, e))?;
        self.with_session(|st| {
            let hrp = self.params.hrp;
            let (rw, cw) = (st.addrs.receive_window().min(MAX_INDEX), st.addrs.change_window().min(MAX_INDEX));
            let change_index = st.addrs.change_next();
            let s = st.session.as_mut().unwrap();
            for i in 0..rw {
                s.key(KeyPath::receive(i), hrp).map_err(|e| (500, e))?;
            }
            for i in 0..cw {
                s.key(KeyPath::change(i), hrp).map_err(|e| (500, e))?;
            }
            let window: HashMap<[u8; 32], KeyPath> =
                s.by_commitment.iter().filter(|(_, p)| (p.account == txbuild::RECEIVE_ACCOUNT && p.index < rw) || (p.account == txbuild::CHANGE_ACCOUNT && p.index < cw)).map(|(c, p)| (*c, *p)).collect();
            let change_path = KeyPath::change(change_index);
            let change_key = change_path.derive(&s.wallet).map_err(|e| (500, e))?;
            let change_address = s.key(change_path, hrp).map_err(|e| (500, e))?.1;
            let req = txbuild::BuildRequest { to: &to, amount, feerate, utxos: &utxos, api_height, allow_high_fee, change_key: &change_key };
            let b = txbuild::build(&s.wallet, &window, &self.ids, &req).map_err(|e| (400, e))?;
            let high = txbuild::high_fee(b.fee, b.amount);
            Ok(Json::obj(vec![
                ("hex", Json::str(hex(&b.tx.serialize()))),
                ("txid", Json::str(txbuild::txid_hex(&b.tx))),
                ("fee", Json::str(b.fee.to_string())),
                ("total_in", Json::str(b.total_in.to_string())),
                ("change", Json::str(b.change.to_string())),
                ("change_index", if b.change > 0 { Json::num(change_index) } else { Json::Null }),
                ("change_address", if b.change > 0 { Json::str(change_address) } else { Json::Null }),
                ("weight", Json::num(b.weight)),
                ("to", Json::str(address::encode(hrp, &to))),
                ("amount", Json::str(b.amount.to_string())),
                ("inputs", Json::num(b.tx.inputs.len())),
                ("feerate", Json::num(feerate)),
                ("high_fee", Json::Bool(high)),
            ]))
        })
    }

    fn settings(&self, j: &Json) -> R {
        let ep = get_str(j, "api_endpoint")?.map(config::validate_endpoint).transpose().map_err(|e| (400, e.to_string()))?;
        let mins = match j.get("autolock_minutes") {
            None | Some(Json::Null) => None,
            Some(v) => Some(v.as_u64().filter(|m| (1..=60).contains(m)).ok_or((400, "auto-lock must be between 1 and 60 minutes".to_string()))? as u32),
        };
        let mut st = self.lock_state();
        let mut c = st.config.clone();
        if let Some((e, o)) = ep {
            c.api_endpoint = e;
            c.api_origin = o;
        }
        if let Some(m) = mins {
            c.autolock_minutes = m;
        }
        config::create_private_dir(&self.dir).map_err(|e| (500, e))?;
        c.save(&self.dir).map_err(|e| (500, e))?;
        st.config = c;
        Ok(self.status(&st))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_policy() {
        for bad in ["short", "aaaaaaaaaaaa", "abababababab", "1234567890", "abcdefghijk", "password123", "Password!!", "qwerty1234", "0123456789012", "varvevarve", "pässwordlong1", "tab\there12345"] {
            assert!(check_file_pass(bad).is_err(), "{}", bad);
        }
        for good in ["correct horse battery", "Tr0ub4dor&3x", "my password is long enough", "8371-2290-5512-0098", "river.copper.7.lantern"] {
            assert!(check_file_pass(good).is_ok(), "{}", good);
        }
        assert!(check_file_pass(&"ab1!".repeat(300)).is_err());
    }

    #[test]
    fn unlock_delays_increase() {
        assert_eq!(unlock_delay(1), Duration::from_secs(1));
        assert_eq!(unlock_delay(2), Duration::from_secs(2));
        assert_eq!(unlock_delay(5), Duration::from_secs(16));
        assert_eq!(unlock_delay(40), Duration::from_secs(MAX_UNLOCK_DELAY_SECS));
    }

    fn test_app(name: &str) -> App {
        let d = std::env::temp_dir().join(format!("strata-app-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let params = varve_consensus::networks::regtest();
        let ids = ChainIds { network_id: params.network_id, genesis_id: [3; 32], lifecycle: vec![] };
        let mut a = App::new(params, ids, d);
        a.kdf = Some(varve_wallet::argon2::Params { m_kib: varve_wallet::file::M_KIB_MIN, t: 1, p: 1 });
        a
    }

    fn post(path: &str, body: &str) -> Request {
        Request { method: "POST".into(), path: path.into(), query: String::new(), headers: vec![], body: body.as_bytes().to_vec() }
    }
    fn get(path: &str) -> Request {
        Request { method: "GET".into(), path: path.into(), query: String::new(), headers: vec![], body: vec![] }
    }
    fn call(a: &App, r: Request) -> (u16, Json) {
        let resp = a.handle(&r);
        (resp.status, Json::parse(std::str::from_utf8(&resp.body).unwrap()).unwrap())
    }

    #[test]
    fn wallet_lifecycle() {
        let a = test_app("life");
        let (s, j) = call(&a, get("/local/status"));
        assert_eq!(s, 200);
        assert_eq!(j.at("has_wallet").as_bool(), Some(false));
        assert_eq!(call(&a, get("/local/addresses")).0, 423);
        // weak passphrase refused, and the error does not echo it
        let (s, j) = call(&a, post("/local/create", r#"{"file_pass":"password12"}"#));
        assert_eq!(s, 400);
        assert!(!j.to_string().contains("password12"));
        let (s, j) = call(&a, post("/local/create", r#"{"file_pass":"correct horse battery"}"#));
        assert_eq!(s, 200, "{}", j.to_string());
        let words: Vec<String> = j.at("mnemonic").as_arr().unwrap().iter().map(|w| w.as_str().unwrap().to_string()).collect();
        assert_eq!(words.len(), 24);
        assert_eq!(j.at("status.unlocked").as_bool(), Some(true));
        // a second create without REPLACE is refused
        assert_eq!(call(&a, post("/local/create", r#"{"file_pass":"correct horse battery"}"#)).0, 409);
        assert_eq!(call(&a, post("/local/create", r#"{"file_pass":"correct horse battery","replace":true,"confirm":"replace"}"#)).0, 409);
        // addresses: GAP receive and GAP change
        let (s, j) = call(&a, get("/local/addresses"));
        assert_eq!(s, 200);
        assert_eq!(j.at("receive").as_arr().unwrap().len(), GAP as usize);
        assert_eq!(j.at("change").as_arr().unwrap().len(), GAP as usize);
        let addr0 = j.at("receive.0.address").as_str().unwrap().to_string();
        assert!(addr0.starts_with("rvarve1"));
        // marking index 5 used extends the window
        let (_, j) = call(&a, post("/local/mark_used", r#"{"receive":[5],"change":[0]}"#));
        assert_eq!(j.at("receive").as_arr().unwrap().len(), 6 + GAP as usize);
        assert_eq!(j.at("change").as_arr().unwrap().len(), 1 + GAP as usize);
        assert_eq!(j.at("current.index").as_u64(), Some(6));
        assert_eq!(call(&a, post("/local/mark_used", r#"{"receive":[500]}"#)).0, 400);
        let (_, j) = call(&a, post("/local/new_address", "{}"));
        assert_eq!(j.at("index").as_u64(), Some(7));
        // lock, then a wrong passphrase is rate-limited
        call(&a, post("/local/lock", "{}"));
        assert_eq!(call(&a, get("/local/addresses")).0, 423);
        let (s, j) = call(&a, post("/local/unlock", r#"{"file_pass":"bad guess 12345"}"#));
        assert_eq!((s, j.at("error").as_str()), (400, Some("wrong passphrase")));
        assert!(!j.to_string().contains("bad guess"));
        assert_eq!(call(&a, post("/local/unlock", r#"{"file_pass":"correct horse battery"}"#)).0, 429);
        a.lock_state().next_attempt = None;
        let (s, j) = call(&a, post("/local/unlock", r#"{"file_pass":"correct horse battery"}"#));
        assert_eq!(s, 200, "{}", j.to_string());
        // the address state survived (same wallet)
        let (_, j) = call(&a, get("/local/addresses"));
        assert_eq!(j.at("receive.0.address").as_str(), Some(addr0.as_str()));
        assert_eq!(j.at("current.index").as_u64(), Some(7));
        // reveal needs the passphrase
        assert_eq!(call(&a, post("/local/reveal", r#"{"file_pass":"nope nope nope"}"#)).0, 400);
        a.lock_state().next_attempt = None;
        let (s, j) = call(&a, post("/local/reveal", r#"{"file_pass":"correct horse battery"}"#));
        assert_eq!(s, 200);
        let again: Vec<String> = j.at("mnemonic").as_arr().unwrap().iter().map(|w| w.as_str().unwrap().to_string()).collect();
        assert_eq!(again, words);
        // import with REPLACE restores the same addresses and keeps the old file aside
        let body = format!(r#"{{"mnemonic":"{}","file_pass":"another good one","replace":true,"confirm":"REPLACE"}}"#, words.join(" "));
        let (s, j) = call(&a, post("/local/import", &body));
        assert_eq!(s, 200, "{}", j.to_string());
        assert!(j.get("mnemonic").is_none());
        let (_, j) = call(&a, get("/local/addresses"));
        assert_eq!(j.at("receive.0.address").as_str(), Some(addr0.as_str()));
        let baks = std::fs::read_dir(&a.dir).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("wallet-replaced-")).count();
        assert_eq!(baks, 1);
        // a bad phrase is refused without echoing it
        let (s, j) = call(&a, post("/local/import", r#"{"mnemonic":"zebra secretword","file_pass":"another good one","replace":true,"confirm":"REPLACE"}"#));
        assert_eq!(s, 400);
        assert!(!j.to_string().contains("secretword"));
        // settings
        assert_eq!(call(&a, post("/local/settings", r#"{"api_endpoint":"http://evil.example"}"#)).0, 400);
        assert_eq!(call(&a, post("/local/settings", r#"{"autolock_minutes":0}"#)).0, 400);
        let (s, j) = call(&a, post("/local/settings", r#"{"api_endpoint":"https://api.example.org/","autolock_minutes":3}"#));
        assert_eq!(s, 200);
        assert_eq!(j.at("api_endpoint").as_str(), Some("https://api.example.org"));
        assert_eq!(a.api_origin(), "https://api.example.org");
        // auto-lock
        a.lock_state().last_activity = Instant::now() - Duration::from_secs(181);
        let (_, j) = call(&a, get("/local/status"));
        assert_eq!(j.at("unlocked").as_bool(), Some(false));
        std::fs::remove_dir_all(&a.dir).unwrap();
    }

    #[test]
    fn build_endpoint_validates_inputs() {
        let a = test_app("build");
        call(&a, post("/local/create", r#"{"file_pass":"correct horse battery"}"#));
        let (_, j) = call(&a, get("/local/addresses"));
        let me = j.at("receive.0.address").as_str().unwrap().to_string();
        let b = |body: String| call(&a, post("/local/build", &body));
        // wrong network address
        let tv = address::encode("tvarve", &varve_consensus::tx::Output::single(0, 1, [1; 32]));
        let (s, j) = b(format!(r#"{{"to":"{}","amount_laminae":"1000","feerate":1,"height":10,"utxos":[]}}"#, tv));
        assert_eq!((s, j.at("error").as_str()), (400, Some("address is for a different network")));
        // amount must be a string of laminae
        let (s, _) = b(format!(r#"{{"to":"{}","amount_laminae":1000,"feerate":1,"height":10,"utxos":[]}}"#, me));
        assert_eq!(s, 400);
        let (s, _) = b(format!(r#"{{"to":"{}","amount_laminae":"0","feerate":1,"height":10,"utxos":[]}}"#, me));
        assert_eq!(s, 400);
        let (s, _) = b(format!(r#"{{"to":"{}","amount_laminae":"1000","feerate":0,"height":10,"utxos":[]}}"#, me));
        assert_eq!(s, 400);
        let (s, j) = b(format!(r#"{{"to":"{}","amount_laminae":"1000","feerate":1,"height":10,"utxos":[]}}"#, me));
        assert_eq!((s, j.at("error").as_str()), (400, Some("no spendable coins")));
        std::fs::remove_dir_all(&a.dir).unwrap();
    }
}
