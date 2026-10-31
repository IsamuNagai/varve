//! encoding.md: little-endian integers, canonical varint, tagged hashing.

use crate::Error;

/// H256(tag, m) = SHA3-256(u8(len(tag)) ‖ tag ‖ m)   (encoding.md §4)
pub fn h256(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = tag.as_bytes();
    assert!(t.len() < 256);
    let mut buf = Vec::with_capacity(1 + t.len() + msg.len());
    buf.push(t.len() as u8);
    buf.extend_from_slice(t);
    buf.extend_from_slice(msg);
    varve_sys::sha3_256(&buf)
}

/// Canonical unsigned LEB128, values < 2^32, at most 5 bytes.
pub fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    assert!(n < (1u64 << 32), "varint out of range");
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

pub fn varint_len(n: u64) -> usize {
    let mut v = Vec::new();
    write_varint(&mut v, n);
    v.len()
}

pub fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

/// Bounds-checked reader. Every error is a parse error (encoding.md §1.5).
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining() {
            return Err(Error::Parse("truncated"));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn varint(&mut self) -> Result<u64, Error> {
        let mut value = 0u64;
        for k in 0..5 {
            let b = self.u8()?;
            value |= ((b & 0x7f) as u64) << (7 * k);
            if b & 0x80 == 0 {
                if k > 0 && b == 0 {
                    return Err(Error::Parse("non-minimal varint"));
                }
                if value >= 1 << 32 {
                    return Err(Error::Parse("varint out of range"));
                }
                return Ok(value);
            }
        }
        Err(Error::Parse("varint too long"))
    }
    /// Length-prefixed bytes with a maximum length, checked before reading.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = self.varint()? as usize;
        if n > max {
            return Err(Error::Parse("byte string too long"));
        }
        self.take(n)
    }
    /// Fails unless `count * min_size` fits in the remaining input (before allocating).
    pub fn need(&self, count: u64, min_size: u64) -> Result<(), Error> {
        match count.checked_mul(min_size) {
            Some(n) if n <= self.remaining() as u64 => Ok(()),
            _ => Err(Error::Parse("declared count exceeds remaining input")),
        }
    }
    pub fn finish(&self) -> Result<(), Error> {
        if self.remaining() != 0 {
            return Err(Error::Parse("trailing bytes"));
        }
        Ok(())
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn varint_roundtrip_and_rejects() {
        for n in [0u64, 1, 127, 128, 255, 16383, 16384, (1 << 32) - 1] {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            let mut r = Reader::new(&v);
            assert_eq!(r.varint().unwrap(), n);
            r.finish().unwrap();
        }
        assert!(Reader::new(&[0x80, 0x00]).varint().is_err());
        assert!(Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x10]).varint().is_err());
        assert!(Reader::new(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]).varint().is_err());
        assert!(Reader::new(&[0x80]).varint().is_err());
    }
}
