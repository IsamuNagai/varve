//! p2p.md §2–8 message encoding. Framing checks happen before any payload allocation.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use varve_consensus::block::{Block, Header};
use varve_consensus::encoding::{h256, write_bytes, write_varint, Reader};
use varve_consensus::params::{HEADER_SIZE, MAX_BLOCK_BYTES};
use varve_consensus::tx::Tx;
use varve_consensus::Error;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_PAYLOAD_UNKNOWN: u32 = 800_000;
pub const MAX_HEADERS: usize = 2000;
pub const MAX_INV: usize = 5000;
pub const MAX_ADDR: usize = 1000;
pub const MAX_LOCATOR: usize = 64;
pub const NODE_NETWORK: u64 = 1;
pub const INV_TX: u32 = 1;
pub const INV_BLOCK: u32 = 2;

pub fn max_payload(cmd: &str) -> u32 {
    match cmd {
        "version" => 359,
        "verack" | "getaddr" => 0,
        "ping" | "pong" | "feefilter" => 8,
        "addr" => 65_536,
        "getheaders" => 2_081,
        "headers" => 232_002,
        "inv" | "getdata" | "notfound" => 180_002,
        "block" => MAX_BLOCK_BYTES as u32,
        "tx" => 100_000,
        _ => MAX_PAYLOAD_UNKNOWN,
    }
}

#[derive(Clone, Debug)]
pub struct Version {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub nonce: u64,
    pub user_agent: String,
    pub best_height: u64,
    pub genesis_id: [u8; 32],
    pub ruleset_hash: [u8; 32],
    pub relay: bool,
}

#[derive(Clone, Debug)]
pub struct AddrEntry {
    pub time: u64,
    pub services: u64,
    pub addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub enum Msg {
    Version(Version),
    Verack,
    Ping(u64),
    Pong(u64),
    GetAddr,
    Addr(Vec<AddrEntry>),
    GetHeaders { locator: Vec<[u8; 32]>, stop: [u8; 32] },
    Headers(Vec<Header>),
    Inv(Vec<(u32, [u8; 32])>),
    GetData(Vec<(u32, [u8; 32])>),
    NotFound(Vec<(u32, [u8; 32])>),
    Block(Block),
    Tx(Tx),
    FeeFilter(u64),
    Unknown(String),
}

impl Msg {
    pub fn command(&self) -> &str {
        match self {
            Msg::Version(_) => "version",
            Msg::Verack => "verack",
            Msg::Ping(_) => "ping",
            Msg::Pong(_) => "pong",
            Msg::GetAddr => "getaddr",
            Msg::Addr(_) => "addr",
            Msg::GetHeaders { .. } => "getheaders",
            Msg::Headers(_) => "headers",
            Msg::Inv(_) => "inv",
            Msg::GetData(_) => "getdata",
            Msg::NotFound(_) => "notfound",
            Msg::Block(_) => "block",
            Msg::Tx(_) => "tx",
            Msg::FeeFilter(_) => "feefilter",
            Msg::Unknown(c) => c,
        }
    }

    /// Approximate encoded size, for send-buffer accounting.
    pub fn payload_len_hint(&self) -> usize {
        24 + match self {
            Msg::Block(b) => b.txs.iter().map(|t| t.serialize().len()).sum::<usize>() + 121,
            Msg::Tx(t) => t.serialize().len(),
            Msg::Headers(h) => 3 + h.len() * 116,
            Msg::Inv(v) | Msg::GetData(v) | Msg::NotFound(v) => 3 + v.len() * 36,
            Msg::Addr(v) => 3 + v.len() * 40,
            _ => 400,
        }
    }

    pub fn payload(&self) -> Vec<u8> {
        let mut p = Vec::new();
        match self {
            Msg::Version(v) => {
                p.extend_from_slice(&v.version.to_le_bytes());
                p.extend_from_slice(&v.services.to_le_bytes());
                p.extend_from_slice(&v.timestamp.to_le_bytes());
                p.extend_from_slice(&v.nonce.to_le_bytes());
                let ua: Vec<u8> = v.user_agent.bytes().filter(|c| c.is_ascii() && !c.is_ascii_control()).take(256).collect();
                write_bytes(&mut p, &ua);
                p.extend_from_slice(&v.best_height.to_le_bytes());
                p.extend_from_slice(&v.genesis_id);
                p.extend_from_slice(&v.ruleset_hash);
                p.push(v.relay as u8);
            }
            Msg::Verack | Msg::GetAddr | Msg::Unknown(_) => {}
            Msg::Ping(n) | Msg::Pong(n) | Msg::FeeFilter(n) => p.extend_from_slice(&n.to_le_bytes()),
            Msg::Addr(list) => {
                write_varint(&mut p, list.len() as u64);
                for a in list {
                    p.extend_from_slice(&a.time.to_le_bytes());
                    p.extend_from_slice(&a.services.to_le_bytes());
                    match a.addr.ip() {
                        IpAddr::V4(ip) => {
                            p.push(1);
                            write_bytes(&mut p, &ip.octets());
                        }
                        IpAddr::V6(ip) => {
                            p.push(2);
                            write_bytes(&mut p, &ip.octets());
                        }
                    }
                    p.extend_from_slice(&a.addr.port().to_le_bytes());
                }
            }
            Msg::GetHeaders { locator, stop } => {
                write_varint(&mut p, locator.len() as u64);
                for l in locator {
                    p.extend_from_slice(l);
                }
                p.extend_from_slice(stop);
            }
            Msg::Headers(hs) => {
                write_varint(&mut p, hs.len() as u64);
                for h in hs {
                    p.extend_from_slice(&h.serialize());
                }
            }
            Msg::Inv(v) | Msg::GetData(v) | Msg::NotFound(v) => {
                write_varint(&mut p, v.len() as u64);
                for (t, h) in v {
                    p.extend_from_slice(&t.to_le_bytes());
                    p.extend_from_slice(h);
                }
            }
            Msg::Block(b) => p = b.serialize(),
            Msg::Tx(t) => p = t.serialize(),
        }
        p
    }

    pub fn decode(cmd: &str, payload: &[u8]) -> Result<Msg, Error> {
        let mut r = Reader::new(payload);
        let m = match cmd {
            "version" => {
                let version = r.u32()?;
                let services = r.u64()?;
                let timestamp = r.u64()?;
                let nonce = r.u64()?;
                let ua = r.bytes(256)?;
                if !ua.iter().all(|c| c.is_ascii() && !c.is_ascii_control()) {
                    return Err(Error::Parse("user agent not printable ASCII"));
                }
                let best_height = r.u64()?;
                let genesis_id = r.array()?;
                let ruleset_hash = r.array()?;
                let relay = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Parse("relay flag")),
                };
                Msg::Version(Version {
                    version,
                    services,
                    timestamp,
                    nonce,
                    user_agent: String::from_utf8_lossy(ua).into_owned(),
                    best_height,
                    genesis_id,
                    ruleset_hash,
                    relay,
                })
            }
            "verack" => Msg::Verack,
            "getaddr" => Msg::GetAddr,
            "ping" => Msg::Ping(r.u64()?),
            "pong" => Msg::Pong(r.u64()?),
            "feefilter" => Msg::FeeFilter(r.u64()?),
            "addr" => {
                let n = r.varint()? as usize;
                if n > MAX_ADDR {
                    return Err(Error::Parse("too many addresses"));
                }
                let mut v = Vec::new();
                for _ in 0..n {
                    let time = r.u64()?;
                    let services = r.u64()?;
                    let net = r.u8()?;
                    let a = r.bytes(512)?;
                    let port = r.u16()?;
                    let ip = match (net, a.len()) {
                        (1, 4) => IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])),
                        (2, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(a).unwrap())),
                        (3, 32) | (4, 32) => continue, // Tor/I2P: not supported by this node yet; skipped
                        (1..=4, _) => return Err(Error::Parse("address length does not match network")),
                        _ => continue, // unknown network: skipped
                    };
                    v.push(AddrEntry { time, services, addr: SocketAddr::new(ip, port) });
                }
                Msg::Addr(v)
            }
            "getheaders" => {
                let n = r.varint()? as usize;
                if n == 0 || n > MAX_LOCATOR {
                    return Err(Error::Parse("locator size"));
                }
                let mut locator = Vec::with_capacity(n);
                for _ in 0..n {
                    locator.push(r.array()?);
                }
                Msg::GetHeaders { locator, stop: r.array()? }
            }
            "headers" => {
                let n = r.varint()? as usize;
                if n > MAX_HEADERS {
                    return Err(Error::Parse("too many headers"));
                }
                r.need(n as u64, HEADER_SIZE as u64)?;
                let mut hs = Vec::with_capacity(n);
                for _ in 0..n {
                    hs.push(Header::parse(&mut r)?);
                }
                Msg::Headers(hs)
            }
            "inv" | "getdata" | "notfound" => {
                let n = r.varint()? as usize;
                if n > MAX_INV {
                    return Err(Error::Parse("too many inventory items"));
                }
                r.need(n as u64, 36)?;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push((r.u32()?, r.array()?));
                }
                match cmd {
                    "inv" => Msg::Inv(v),
                    "getdata" => Msg::GetData(v),
                    _ => Msg::NotFound(v),
                }
            }
            "block" => return Ok(Msg::Block(Block::parse(payload)?)),
            "tx" => return Ok(Msg::Tx(Tx::from_bytes(payload)?)),
            other => return Ok(Msg::Unknown(other.to_string())),
        };
        r.finish()?;
        Ok(m)
    }
}

#[derive(Debug)]
pub enum FrameError {
    Io(#[allow(dead_code)] std::io::Error),
    /// disconnect without ban (p2p.md §10.4)
    Disconnect(&'static str),
    /// protocol violation: ban
    Violation(String),
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let h = h256("VARVE/p2p/v1", payload);
    [h[0], h[1], h[2], h[3]]
}

pub fn write_msg(w: &mut impl Write, magic: &[u8; 4], m: &Msg) -> std::io::Result<()> {
    let payload = m.payload();
    let mut cmd = [0u8; 12];
    cmd[..m.command().len()].copy_from_slice(m.command().as_bytes());
    let mut frame = Vec::with_capacity(24 + payload.len());
    frame.extend_from_slice(magic);
    frame.extend_from_slice(&cmd);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&checksum(&payload));
    frame.extend_from_slice(&payload);
    w.write_all(&frame)?;
    w.flush()
}

pub fn read_msg(r: &mut impl Read, magic: &[u8; 4]) -> Result<Msg, FrameError> {
    let mut hdr = [0u8; 24];
    r.read_exact(&mut hdr).map_err(FrameError::Io)?;
    if &hdr[0..4] != magic {
        return Err(FrameError::Disconnect("wrong network magic"));
    }
    let cmd_bytes = &hdr[4..16];
    let end = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    if end == 0 || !cmd_bytes[..end].iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) || cmd_bytes[end..].iter().any(|&b| b != 0) {
        return Err(FrameError::Disconnect("malformed command"));
    }
    let cmd = std::str::from_utf8(&cmd_bytes[..end]).unwrap().to_string();
    let len = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
    if len > max_payload(&cmd) {
        return Err(FrameError::Disconnect("payload too large"));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).map_err(FrameError::Io)?;
    if checksum(&payload) != hdr[20..24] {
        return Err(FrameError::Disconnect("bad checksum"));
    }
    Msg::decode(&cmd, &payload).map_err(|e| FrameError::Violation(format!("{}: {}", cmd, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_limits() {
        let magic = *b"RVAR";
        let msgs = vec![
            Msg::Ping(7),
            Msg::GetHeaders { locator: vec![[1u8; 32]], stop: [0u8; 32] },
            Msg::Inv(vec![(INV_TX, [9u8; 32])]),
            Msg::Addr(vec![AddrEntry { time: 1, services: 1, addr: "1.2.3.4:39900".parse().unwrap() }]),
            Msg::Version(Version { version: 1, services: 1, timestamp: 5, nonce: 6, user_agent: "/varve:0.1.0/".into(), best_height: 3, genesis_id: [2u8; 32], ruleset_hash: [3u8; 32], relay: true }),
        ];
        for m in msgs {
            let mut buf = Vec::new();
            write_msg(&mut buf, &magic, &m).unwrap();
            let back = read_msg(&mut &buf[..], &magic).unwrap();
            assert_eq!(back.payload(), m.payload());
            assert!(matches!(read_msg(&mut &buf[..], b"TVAR"), Err(FrameError::Disconnect(_))));
        }
        // a full-size version message fits its maximum
        let v = Msg::Version(Version { version: 1, services: 1, timestamp: 5, nonce: 6, user_agent: "x".repeat(256), best_height: 3, genesis_id: [2u8; 32], ruleset_hash: [3u8; 32], relay: true });
        assert_eq!(v.payload().len() as u32, max_payload("version"));
        // oversized length is rejected before allocation
        let mut bad = Vec::new();
        bad.extend_from_slice(&magic);
        bad.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
        bad.extend_from_slice(&9u32.to_le_bytes());
        bad.extend_from_slice(&[0u8; 4]);
        assert!(matches!(read_msg(&mut &bad[..], &magic), Err(FrameError::Disconnect(_))));
    }
}
