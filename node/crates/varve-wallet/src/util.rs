//! Small helpers: zeroization, constant-time comparison, strict hex.

use std::sync::atomic::{compiler_fence, Ordering};

/// Overwrite a buffer with zeros in a way the optimizer will not elide.
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: x is a valid, aligned &mut u8.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn wipe_u64(b: &mut [u64]) {
    for x in b.iter_mut() {
        // SAFETY: x is a valid, aligned &mut u64.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Constant-time equality for equal-length inputs (length itself is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // Keep the optimizer from short-circuiting on d.
    unsafe { std::ptr::read_volatile(&d) == 0 }
}

/// A heap byte buffer that is wiped on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        SecretBytes(v)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Strict lowercase hex: rejects uppercase, signs, whitespace and odd length,
/// so every accepted string has exactly one byte encoding.
pub fn unhex_strict(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    b.chunks(2).map(|p| Some(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_strict() {
        assert_eq!(unhex_strict("00ff10").unwrap(), vec![0, 255, 16]);
        assert!(unhex_strict("0F").is_none());
        assert!(unhex_strict("+f").is_none());
        assert!(unhex_strict("abc").is_none());
        assert_eq!(hex(&[0xde, 0xad]), "dead");
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}

/// Atomically replace `to` with `from`. On Windows a file that was just written can be
/// held open for a moment by other software (antivirus, indexing), which makes the
/// rename fail with "access denied"; retry briefly there instead of failing.
pub fn rename_with_retry(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    let mut attempt = 0u64;
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if cfg!(windows) && attempt < 20 && (e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(32)) => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(25 * attempt));
            }
            Err(e) => return Err(e),
        }
    }
}
