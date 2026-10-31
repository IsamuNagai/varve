//! A deliberately small HTTP/1.1 server for the local UI: one request per
//! connection, strict limits, and the request guard (Host, Origin, token).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub const MAX_HEAD: usize = 8 * 1024;
pub const MAX_BODY: usize = 1024 * 1024;
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_CONNECTIONS: usize = 8;
pub const TOKEN_HEADER: &str = "x-strata-token";

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    #[allow(dead_code)] // parsed for completeness; no endpoint takes a query
    pub query: String,
    /// names lowercased
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(n, _)| n == name).map(|(_, v)| v.as_str()).collect()
    }
    /// The value of a header that must appear at most once; Err if repeated.
    pub fn header_once(&self, name: &str) -> Result<Option<&str>, ()> {
        let v = self.header_all(name);
        match v.len() {
            0 => Ok(None),
            1 => Ok(Some(v[0])),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HttpError(pub u16, pub &'static str);

fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// Parse the request line and headers (everything before the blank line).
pub fn parse_head(head: &[u8]) -> Result<Request, HttpError> {
    let text = std::str::from_utf8(head).map_err(|_| HttpError(400, "bad request"))?;
    let mut lines = text.split("\r\n");
    let rl = lines.next().ok_or(HttpError(400, "bad request"))?;
    let parts: Vec<&str> = rl.split(' ').collect();
    if parts.len() != 3 || !parts[0].bytes().all(|c| c.is_ascii_uppercase()) || parts[0].is_empty() {
        return Err(HttpError(400, "bad request line"));
    }
    if parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0" {
        return Err(HttpError(505, "HTTP version not supported"));
    }
    let target = parts[1];
    if !target.starts_with('/') || target.bytes().any(|c| c <= b' ' || c >= 0x7f) {
        return Err(HttpError(400, "bad request target"));
    }
    let (path, query) = match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    };
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HttpError(400, "folded headers are not supported"));
        }
        let i = line.find(':').ok_or(HttpError(400, "bad header"))?;
        let name = &line[..i];
        if name.is_empty() || !name.bytes().all(is_token_char) {
            return Err(HttpError(400, "bad header name"));
        }
        let value = line[i + 1..].trim_matches(|c| c == ' ' || c == '\t');
        if value.bytes().any(|c| c < b' ' && c != b'\t' || c == 0x7f) {
            return Err(HttpError(400, "bad header value"));
        }
        headers.push((name.to_ascii_lowercase(), value.to_string()));
        if headers.len() > 100 {
            return Err(HttpError(431, "too many headers"));
        }
    }
    Ok(Request { method: parts[0].to_string(), path: path.to_string(), query: query.to_string(), headers, body: Vec::new() })
}

/// Content length of the body; rejects chunked or ambiguous framing.
pub fn body_length(req: &Request) -> Result<usize, HttpError> {
    if !req.header_all("transfer-encoding").is_empty() {
        return Err(HttpError(501, "transfer-encoding is not supported"));
    }
    match req.header_once("content-length").map_err(|_| HttpError(400, "repeated content-length"))? {
        None => Ok(0),
        Some(v) => {
            if v.is_empty() || v.len() > 10 || !v.bytes().all(|c| c.is_ascii_digit()) {
                return Err(HttpError(400, "bad content-length"));
            }
            let n: usize = v.parse().map_err(|_| HttpError(400, "bad content-length"))?;
            if n > MAX_BODY {
                return Err(HttpError(413, "request body too large"));
            }
            Ok(n)
        }
    }
}

/// Read one request from any reader. `deadline` bounds the total time (slow clients).
pub fn read_request<R: Read>(r: &mut R, deadline: Instant) -> Result<Request, HttpError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() >= MAX_HEAD {
            return Err(HttpError(431, "request header too large"));
        }
        if Instant::now() >= deadline {
            return Err(HttpError(408, "request timeout"));
        }
        let want = (MAX_HEAD + 4 - buf.len()).min(chunk.len());
        let n = r.read(&mut chunk[..want]).map_err(|_| HttpError(408, "request timeout"))?;
        if n == 0 {
            return Err(HttpError(400, "connection closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if head_end > MAX_HEAD {
        return Err(HttpError(431, "request header too large"));
    }
    let mut req = parse_head(&buf[..head_end])?;
    let len = body_length(&req)?;
    let mut body = buf[head_end + 4..].to_vec();
    if body.len() > len {
        return Err(HttpError(400, "unexpected data after the body"));
    }
    while body.len() < len {
        if Instant::now() >= deadline {
            return Err(HttpError(408, "request timeout"));
        }
        let want = (len - body.len()).min(chunk.len());
        let n = r.read(&mut chunk[..want]).map_err(|_| HttpError(408, "request timeout"))?;
        if n == 0 {
            return Err(HttpError(400, "connection closed"));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    req.body = body;
    Ok(req)
}

/// What a request may access after the guard.
#[derive(Debug, PartialEq, Eq)]
pub enum Access {
    /// a static asset (no token needed)
    Static,
    /// an authenticated /local/* call
    Local,
}

/// Constant-time comparison for equal-length strings (the token length is public).
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    varve_wallet::util::ct_eq(a.as_bytes(), b.as_bytes())
}

/// Host (DNS rebinding), Origin (cross-site requests), token and content-type checks.
pub fn guard(req: &Request, port: u16, token: &str) -> Result<Access, HttpError> {
    // DNS rebinding: the Host header must name the loopback address and our port exactly
    let host = req.header_once("host").map_err(|_| HttpError(400, "repeated host header"))?.ok_or(HttpError(400, "missing host header"))?;
    if host != format!("127.0.0.1:{}", port) && host != format!("localhost:{}", port) {
        return Err(HttpError(421, "wrong host"));
    }
    // cross-origin requests are refused outright
    if let Some(origin) = req.header_once("origin").map_err(|_| HttpError(400, "repeated origin header"))? {
        if origin != format!("http://127.0.0.1:{}", port) && origin != format!("http://localhost:{}", port) {
            return Err(HttpError(403, "cross-origin request refused"));
        }
    }
    if !req.path.starts_with("/local/") {
        if req.method != "GET" && req.method != "HEAD" {
            return Err(HttpError(405, "method not allowed"));
        }
        return Ok(Access::Static);
    }
    if let Ok(Some(site)) = req.header_once("sec-fetch-site") {
        if site != "same-origin" && site != "none" {
            return Err(HttpError(403, "cross-site request refused"));
        }
    }
    let t = req.header_once(TOKEN_HEADER).map_err(|_| HttpError(401, "invalid session token"))?;
    match t {
        Some(t) if t.len() == token.len() && ct_eq_str(t, token) => {}
        _ => return Err(HttpError(401, "invalid session token")),
    }
    match req.method.as_str() {
        "GET" => {}
        "POST" => {
            // a cross-origin HTML form cannot send this content type (CSRF defence)
            let ct = req.header_once("content-type").map_err(|_| HttpError(415, "content-type must be application/json"))?.unwrap_or("");
            let media = ct.split(';').next().unwrap_or("").trim();
            if !media.eq_ignore_ascii_case("application/json") {
                return Err(HttpError(415, "content-type must be application/json"));
            }
        }
        _ => return Err(HttpError(405, "method not allowed")),
    }
    Ok(Access::Local)
}

pub fn csp(api_origin: &str) -> String {
    format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' {}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        api_origin
    )
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(status: u16, body: String) -> Response {
        Response { status, content_type: "application/json; charset=utf-8", body: body.into_bytes() }
    }
    pub fn error(status: u16, msg: &str) -> Response {
        let j = varve_consensus::json::Json::obj(vec![("error", varve_consensus::json::Json::str(msg))]);
        Response::json(status, j.to_string())
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        423 => "Locked",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// Serialize a response with the security headers that go on every response.
pub fn render(resp: &Response, api_origin: &str, head_only: bool) -> Vec<u8> {
    let mut h = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
    let headers = [
        ("Content-Type", resp.content_type.to_string()),
        ("Content-Length", resp.body.len().to_string()),
        ("Connection", "close".to_string()),
        ("Content-Security-Policy", csp(api_origin)),
        ("X-Frame-Options", "DENY".to_string()),
        ("Referrer-Policy", "no-referrer".to_string()),
        ("X-Content-Type-Options", "nosniff".to_string()),
        ("Cache-Control", "no-store".to_string()),
        ("Cross-Origin-Opener-Policy", "same-origin".to_string()),
        ("Cross-Origin-Resource-Policy", "same-origin".to_string()),
    ];
    for (k, v) in headers {
        h.push_str(k);
        h.push_str(": ");
        h.push_str(&v);
        h.push_str("\r\n");
    }
    h.push_str("\r\n");
    let mut out = h.into_bytes();
    if !head_only {
        out.extend_from_slice(&resp.body);
    }
    out
}

pub fn write_response(s: &mut TcpStream, bytes: &[u8]) {
    let _ = s.write_all(bytes);
    let _ = s.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 41234;
    const TOKEN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn req(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers: headers.iter().map(|(a, b)| (a.to_ascii_lowercase(), b.to_string())).collect(),
            body: vec![],
        }
    }

    fn local(method: &str, extra: &[(&str, &str)]) -> Request {
        let mut h = vec![("Host", "127.0.0.1:41234"), ("X-Strata-Token", TOKEN)];
        h.extend_from_slice(extra);
        req(method, "/local/status", &h)
    }

    #[test]
    fn host_check() {
        let g = |h: &str| guard(&req("GET", "/", &[("Host", h)]), PORT, TOKEN);
        assert_eq!(g("127.0.0.1:41234"), Ok(Access::Static));
        assert_eq!(g("localhost:41234"), Ok(Access::Static));
        for bad in ["127.0.0.1", "localhost", "127.0.0.1:41235", "evil.example:41234", "evil.example", "LOCALHOST:41234", "127.0.0.1:41234.evil", "[::1]:41234", ""] {
            assert_eq!(g(bad).unwrap_err().0, 421, "{}", bad);
        }
        assert_eq!(guard(&req("GET", "/", &[]), PORT, TOKEN).unwrap_err().0, 400);
        let two = req("GET", "/", &[("Host", "127.0.0.1:41234"), ("Host", "evil.example")]);
        assert_eq!(guard(&two, PORT, TOKEN).unwrap_err().0, 400);
    }

    #[test]
    fn origin_check() {
        assert_eq!(guard(&local("GET", &[("Origin", "http://127.0.0.1:41234")]), PORT, TOKEN), Ok(Access::Local));
        assert_eq!(guard(&local("GET", &[("Origin", "http://localhost:41234")]), PORT, TOKEN), Ok(Access::Local));
        for bad in ["null", "http://evil.example", "http://127.0.0.1:1", "https://127.0.0.1:41234", "http://127.0.0.1:41234/", ""] {
            assert_eq!(guard(&local("GET", &[("Origin", bad)]), PORT, TOKEN).unwrap_err().0, 403, "{}", bad);
        }
        // the Origin check applies to static assets too
        let s = req("GET", "/app.js", &[("Host", "127.0.0.1:41234"), ("Origin", "http://evil.example")]);
        assert_eq!(guard(&s, PORT, TOKEN).unwrap_err().0, 403);
        assert_eq!(guard(&local("GET", &[("Sec-Fetch-Site", "cross-site")]), PORT, TOKEN).unwrap_err().0, 403);
        assert_eq!(guard(&local("GET", &[("Sec-Fetch-Site", "same-origin")]), PORT, TOKEN), Ok(Access::Local));
    }

    #[test]
    fn token_check() {
        assert_eq!(guard(&local("GET", &[]), PORT, TOKEN), Ok(Access::Local));
        let no = req("GET", "/local/status", &[("Host", "127.0.0.1:41234")]);
        assert_eq!(guard(&no, PORT, TOKEN).unwrap_err().0, 401);
        let mut wrong = TOKEN.to_string();
        wrong.replace_range(63..64, "0");
        for t in [wrong.as_str(), "", &TOKEN[..63], &format!("{}0", TOKEN), &TOKEN.to_uppercase()] {
            let r = req("GET", "/local/status", &[("Host", "127.0.0.1:41234"), ("X-Strata-Token", t)]);
            assert_eq!(guard(&r, PORT, TOKEN).unwrap_err().0, 401, "{}", t);
        }
        let twice = req("GET", "/local/status", &[("Host", "127.0.0.1:41234"), ("X-Strata-Token", TOKEN), ("X-Strata-Token", TOKEN)]);
        assert_eq!(guard(&twice, PORT, TOKEN).unwrap_err().0, 401);
        // static assets need no token
        assert_eq!(guard(&req("GET", "/app.js", &[("Host", "localhost:41234")]), PORT, TOKEN), Ok(Access::Static));
        assert!(ct_eq_str(TOKEN, TOKEN) && !ct_eq_str(TOKEN, &wrong));
    }

    #[test]
    fn methods_and_content_type() {
        assert_eq!(guard(&local("POST", &[]), PORT, TOKEN).unwrap_err().0, 415);
        assert_eq!(guard(&local("POST", &[("Content-Type", "text/plain")]), PORT, TOKEN).unwrap_err().0, 415);
        assert_eq!(guard(&local("POST", &[("Content-Type", "application/x-www-form-urlencoded")]), PORT, TOKEN).unwrap_err().0, 415);
        assert_eq!(guard(&local("POST", &[("Content-Type", "multipart/form-data")]), PORT, TOKEN).unwrap_err().0, 415);
        assert_eq!(guard(&local("POST", &[("Content-Type", "application/json")]), PORT, TOKEN), Ok(Access::Local));
        assert_eq!(guard(&local("POST", &[("Content-Type", "application/json; charset=utf-8")]), PORT, TOKEN), Ok(Access::Local));
        assert_eq!(guard(&local("PUT", &[("Content-Type", "application/json")]), PORT, TOKEN).unwrap_err().0, 405);
        assert_eq!(guard(&req("POST", "/", &[("Host", "127.0.0.1:41234")]), PORT, TOKEN).unwrap_err().0, 405);
    }

    fn read(bytes: &[u8]) -> Result<Request, HttpError> {
        read_request(&mut &bytes[..], Instant::now() + Duration::from_secs(5))
    }

    #[test]
    fn request_limits() {
        let r = read(b"POST /local/x?a=1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.query.as_str(), r.body.as_slice()), ("POST", "/local/x", "a=1", &b"{}"[..]));
        // header block over 8 KB
        let mut big = b"GET / HTTP/1.1\r\nX-A: ".to_vec();
        big.extend(vec![b'a'; MAX_HEAD]);
        big.extend(b"\r\n\r\n");
        assert_eq!(read(&big).unwrap_err().0, 431);
        // body over 1 MB
        let r = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(read(r.as_bytes()).unwrap_err().0, 413);
        // exactly 1 MB is fine
        let mut ok = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY).into_bytes();
        ok.extend(vec![b'x'; MAX_BODY]);
        assert_eq!(read(&ok).unwrap().body.len(), MAX_BODY);
        // framing ambiguities
        assert_eq!(read(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err().0, 501);
        assert_eq!(read(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx").unwrap_err().0, 400);
        assert_eq!(read(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n").unwrap_err().0, 400);
        assert_eq!(read(b"POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nxy").unwrap_err().0, 400);
        assert_eq!(read(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nxy").unwrap_err().0, 400); // closed early
        assert_eq!(read(b"GET http://evil/ HTTP/1.1\r\n\r\n").unwrap_err().0, 400);
        assert_eq!(read(b"GET / HTTP/2\r\n\r\n").unwrap_err().0, 505);
        assert_eq!(read(b"GET / HTTP/1.1\r\nX: a\r\n folded\r\n\r\n").unwrap_err().0, 400);
        assert_eq!(read(b"get / HTTP/1.1\r\n\r\n").unwrap_err().0, 400);
        // a deadline in the past times out a slow client
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(read_request(&mut &b"GET / HTTP/1.1\r\n"[..], past).unwrap_err().0, 408);
    }

    #[test]
    fn security_headers() {
        let out = String::from_utf8(render(&Response::error(404, "x"), "http://127.0.0.1:39911", false)).unwrap();
        for h in [
            "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:39911; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n",
            "X-Frame-Options: DENY\r\n",
            "Referrer-Policy: no-referrer\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "Cache-Control: no-store\r\n",
            "Cross-Origin-Opener-Policy: same-origin\r\n",
            "Cross-Origin-Resource-Policy: same-origin\r\n",
        ] {
            assert!(out.contains(h), "{}", h);
        }
    }
}
