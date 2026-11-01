//! Data directory, settings and the non-secret address state.

use std::path::{Path, PathBuf};

use varve_consensus::json::Json;

pub const GAP: u32 = 20;
pub const AUTOLOCK_DEFAULT: u32 = 10;
pub const WALLET_FILE: &str = "wallet.json";
pub const CONFIG_FILE: &str = "config.json";
pub const STATE_FILE: &str = "addresses.json";

/// The OS data directory for Strata (without the network subfolder).
pub fn default_base_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let appdata = std::env::var_os("APPDATA").ok_or("APPDATA is not set; use --datadir")?;
        Ok(PathBuf::from(appdata).join("Strata"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or("HOME is not set; use --datadir")?;
        Ok(PathBuf::from(home).join("Library").join("Application Support").join("Strata"))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
            let p = PathBuf::from(x);
            if p.is_absolute() {
                return Ok(p.join("strata"));
            }
        }
        let home = std::env::var_os("HOME").ok_or("HOME is not set; use --datadir")?;
        Ok(PathBuf::from(home).join(".local").join("share").join("strata"))
    }
}

/// Create a directory (and parents) readable only by the owner on Unix.
pub fn create_private_dir(p: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p).map_err(|e| format!("cannot create data directory: {}", e.kind()))
}

/// Write a small file atomically: temp file in the same directory, then rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let r = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        varve_wallet::util::rename_with_retry(&tmp, path)
    })();
    if let Err(e) = r {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write file: {}", e.kind()));
    }
    Ok(())
}

fn read_json(path: &Path) -> Option<Json> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > 64 * 1024 {
        return None;
    }
    Json::parse(&std::fs::read_to_string(path).ok()?).ok()
}

/// Validate an API endpoint. Only `https://host[:port][/path]`, or plain http to the
/// loopback names with an explicit port. Returns (normalized endpoint, origin).
/// The origin goes into the CSP header, so the accepted characters are very strict.
pub fn validate_endpoint(s: &str) -> Result<(String, String), &'static str> {
    const ERR: &str = "use an https:// URL, or http://127.0.0.1:PORT / http://localhost:PORT";
    let s = s.trim();
    if s.is_empty() || s.len() > 200 || !s.is_ascii() {
        return Err(ERR);
    }
    let s = s.trim_end_matches('/');
    let (scheme, rest) = if let Some(r) = s.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = s.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err(ERR);
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if !path.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._~/".contains(&c)) || path.contains("//") {
        return Err("the URL path contains characters that are not allowed");
    }
    let (host, port) = match hostport.rfind(':') {
        Some(i) => (&hostport[..i], Some(&hostport[i + 1..])),
        None => (hostport, None),
    };
    let host = host.to_ascii_lowercase();
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit()) || p.starts_with('0') {
            return Err("invalid port");
        }
        let n: u32 = p.parse().map_err(|_| "invalid port")?;
        if n == 0 || n > 65535 {
            return Err("invalid port");
        }
    }
    let label_ok = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    if host.len() > 253 || !host.split('.').all(label_ok) {
        return Err("invalid host name");
    }
    if scheme == "http" {
        if host != "127.0.0.1" && host != "localhost" {
            return Err("plain http is only allowed to 127.0.0.1 or localhost; use https");
        }
        if port.is_none() {
            return Err("give the port, for example http://127.0.0.1:39911");
        }
    }
    let origin = match port {
        Some(p) => format!("{}://{}:{}", scheme, host, p),
        None => format!("{}://{}", scheme, host),
    };
    Ok((format!("{}{}", origin, path), origin))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub api_endpoint: String,
    pub api_origin: String,
    pub autolock_minutes: u32,
}

pub fn default_endpoint(network: &str) -> &'static str {
    match network {
        "regtest" => "http://127.0.0.1:49921",
        _ => "http://127.0.0.1:39911",
    }
}

impl Config {
    pub fn load(dir: &Path, network: &str) -> Config {
        let (ep, origin) = validate_endpoint(default_endpoint(network)).unwrap();
        let mut c = Config { api_endpoint: ep, api_origin: origin, autolock_minutes: AUTOLOCK_DEFAULT };
        if let Some(j) = read_json(&dir.join(CONFIG_FILE)) {
            if let Some(Ok((e, o))) = j.get("api_endpoint").and_then(|v| v.as_str()).map(validate_endpoint) {
                c.api_endpoint = e;
                c.api_origin = o;
            }
            if let Some(m) = j.get("autolock_minutes").and_then(|v| v.as_u64()).filter(|m| (1..=60).contains(m)) {
                c.autolock_minutes = m as u32;
            }
        }
        c
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let j = Json::obj(vec![("api_endpoint", Json::str(&self.api_endpoint)), ("autolock_minutes", Json::num(self.autolock_minutes))]);
        write_atomic(&dir.join(CONFIG_FILE), j.to_string().as_bytes())
    }
}

/// Which receive and change indexes have been used or handed out. Not secret.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AddrState {
    /// identifies the wallet this state belongs to (hex of receive address 0's commitment prefix)
    pub wallet_id: String,
    pub receive_used: Option<u32>,
    pub change_used: Option<u32>,
    pub receive_issued: Option<u32>,
}

impl AddrState {
    pub fn load(dir: &Path) -> AddrState {
        let mut s = AddrState::default();
        if let Some(j) = read_json(&dir.join(STATE_FILE)) {
            let idx = |k: &str| j.get(k).and_then(|v| v.as_u64()).filter(|v| *v < 1_000_000).map(|v| v as u32);
            s.wallet_id = j.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            s.receive_used = idx("receive_used");
            s.change_used = idx("change_used");
            s.receive_issued = idx("receive_issued");
        }
        s
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let o = |v: Option<u32>| v.map(Json::num).unwrap_or(Json::Null);
        let j = Json::obj(vec![
            ("wallet_id", Json::str(&self.wallet_id)),
            ("receive_used", o(self.receive_used)),
            ("change_used", o(self.change_used)),
            ("receive_issued", o(self.receive_issued)),
        ]);
        write_atomic(&dir.join(STATE_FILE), j.to_string().as_bytes())
    }
    /// Number of receive addresses to watch: highest used (or handed out) + 1 + GAP.
    pub fn receive_window(&self) -> u32 {
        let base = self.receive_used.map(|u| u + 1).unwrap_or(0).max(self.receive_issued.map(|u| u + 1).unwrap_or(0));
        base + GAP
    }
    pub fn change_window(&self) -> u32 {
        self.change_used.map(|u| u + 1).unwrap_or(0) + GAP
    }
    /// The receive address the UI shows: the first unused one, or the last handed out.
    pub fn receive_current(&self) -> u32 {
        self.receive_used.map(|u| u + 1).unwrap_or(0).max(self.receive_issued.unwrap_or(0))
    }
    /// The change index for the next payment.
    pub fn change_next(&self) -> u32 {
        self.change_used.map(|u| u + 1).unwrap_or(0)
    }
    /// Hand out a new receive address, staying inside the gap after the last used one.
    pub fn issue_receive(&mut self) -> u32 {
        let first_unused = self.receive_used.map(|u| u + 1).unwrap_or(0);
        let next = (self.receive_current() + 1).min(first_unused + GAP - 1);
        self.receive_issued = Some(next);
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let ok = |s: &str, e: &str, o: &str| assert_eq!(validate_endpoint(s), Ok((e.to_string(), o.to_string())), "{}", s);
        ok("https://api.varve.example", "https://api.varve.example", "https://api.varve.example");
        ok("https://API.Varve.example:8443/", "https://api.varve.example:8443", "https://api.varve.example:8443");
        ok("https://x.example/varve/api/", "https://x.example/varve/api", "https://x.example");
        ok("http://127.0.0.1:39911", "http://127.0.0.1:39911", "http://127.0.0.1:39911");
        ok("http://localhost:8080", "http://localhost:8080", "http://localhost:8080");
        for bad in [
            "",
            "ftp://x.example",
            "http://example.com",
            "http://127.0.0.1",
            "http://127.0.0.2:80",
            "http://localhost.evil.example:80",
            concat!("https://user", "@", "host.example"),
            "https://host.example:0",
            "https://host.example:65536",
            "https://host.example:08",
            "https://host .example",
            "https://host.example/a b",
            "https://host.example/?q=1",
            "https://host.example/#x",
            "https://host.example; script-src *",
            "https://host.example'",
            "https://-bad.example",
            "https://a..b",
            "https://[::1]:80",
            "https://héllo.example",
            "javascript:alert(1)",
        ] {
            assert!(validate_endpoint(bad).is_err(), "{}", bad);
        }
    }

    #[test]
    fn addr_state_windows() {
        let mut s = AddrState::default();
        assert_eq!(s.receive_window(), GAP);
        assert_eq!(s.receive_current(), 0);
        assert_eq!(s.change_next(), 0);
        assert_eq!(s.issue_receive(), 1);
        assert_eq!(s.receive_current(), 1);
        assert_eq!(s.receive_window(), 2 + GAP);
        s.receive_used = Some(4);
        assert_eq!(s.receive_current(), 5);
        assert_eq!(s.receive_window(), 5 + GAP);
        for _ in 0..100 {
            s.issue_receive();
        }
        // never beyond the gap after the last used address
        assert_eq!(s.receive_current(), 5 + GAP - 1);
        assert_eq!(s.receive_window(), 5 + GAP - 1 + 1 + GAP);
        s.change_used = Some(2);
        assert_eq!(s.change_next(), 3);
        assert_eq!(s.change_window(), 3 + GAP);
    }

    #[test]
    fn files_roundtrip() {
        let d = std::env::temp_dir().join(format!("strata-cfg-{}", std::process::id()));
        create_private_dir(&d).unwrap();
        let mut c = Config::load(&d, "testnet");
        assert_eq!(c.api_endpoint, "http://127.0.0.1:39911");
        c.autolock_minutes = 5;
        c.save(&d).unwrap();
        assert_eq!(Config::load(&d, "testnet"), c);
        let s = AddrState { wallet_id: "ab".into(), receive_used: Some(3), change_used: None, receive_issued: Some(7) };
        s.save(&d).unwrap();
        assert_eq!(AddrState::load(&d), s);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
