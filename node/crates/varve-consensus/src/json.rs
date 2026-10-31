//! Minimal JSON (RFC 8259) value, parser and writer. Used for test vectors and the
//! local RPC interface. Numbers keep their source text so large integers are exact.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// the literal number text
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }
    pub fn idx(&self, i: usize) -> Option<&Json> {
        match self {
            Json::Arr(a) => a.get(i),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Num(n) => n.parse().ok(),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Obj(m) => Some(m),
            _ => None,
        }
    }
    /// Convenience: `j["a"]["b"]` style lookups that panic with a clear message (tests).
    pub fn at(&self, path: &str) -> &Json {
        let mut cur = self;
        for k in path.split('.') {
            cur = match k.parse::<usize>() {
                Ok(i) => cur.idx(i),
                Err(_) => cur.get(k),
            }
            .unwrap_or_else(|| panic!("json path {} missing at {}", path, k));
        }
        cur
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    pub fn num(n: impl std::fmt::Display) -> Json {
        Json::Num(n.to_string())
    }
    pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn parse(s: &str) -> Result<Json, String> {
        let mut p = Parser { b: s.as_bytes(), i: 0, depth: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing characters at {}", p.i));
        }
        Ok(v)
    }

    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(n),
            Json::Str(s) => write_str(s, out),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 64;

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn expect(&mut self, lit: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("expected {} at {}", lit, self.i))
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'n') => self.expect("null").map(|_| Json::Null),
            Some(b't') => self.expect("true").map(|_| Json::Bool(true)),
            Some(b'f') => self.expect("false").map(|_| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::Str),
            Some(b'[') => {
                self.enter()?;
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Json::Arr(a));
                }
                loop {
                    self.ws();
                    a.push(self.value()?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(format!("expected , or ] at {}", self.i)),
                    }
                }
                self.depth -= 1;
                Ok(Json::Arr(a))
            }
            Some(b'{') => {
                self.enter()?;
                self.i += 1;
                let mut m = BTreeMap::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Json::Obj(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    self.expect(":")?;
                    self.ws();
                    let v = self.value()?;
                    m.insert(k, v);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(format!("expected , or }} at {}", self.i)),
                    }
                }
                self.depth -= 1;
                Ok(Json::Obj(m))
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let st = self.i;
                self.i += 1;
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                        self.i += 1;
                    } else {
                        break;
                    }
                }
                Ok(Json::Num(String::from_utf8_lossy(&self.b[st..self.i]).into_owned()))
            }
            _ => Err(format!("unexpected input at {}", self.i)),
        }
    }
    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("nesting too deep".into());
        }
        Ok(())
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect("\"")?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&cp) {
                                self.expect("\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("bad surrogate".into());
                                }
                                char::from_u32(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00))
                            } else {
                                char::from_u32(cp)
                            };
                            out.push(ch.ok_or("bad code point")?);
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                c if c < 0x20 => return Err("control character in string".into()),
                _ => {
                    // copy the full UTF-8 sequence
                    let st = self.i - 1;
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let end = (st + len).min(self.b.len());
                    out.push_str(std::str::from_utf8(&self.b[st..end]).map_err(|_| "invalid utf-8")?);
                    self.i = end;
                }
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err("short \\u escape".into());
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4]).map_err(|_| "bad hex")?;
        self.i += 4;
        u32::from_str_radix(s, 16).map_err(|_| "bad hex".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let j = Json::parse(r#"{"a":[1,2,{"b":"x\"yé"}],"c":true,"d":null,"e":-12345678901234567890}"#).unwrap();
        assert_eq!(j.at("a.2.b").as_str(), Some("x\"yé"));
        assert_eq!(Json::parse(&j.to_string()).unwrap(), j);
        assert!(Json::parse("[1,]").is_err());
        assert!(Json::parse(&"[".repeat(100)).is_err());
    }
}
