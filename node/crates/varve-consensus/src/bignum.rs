//! Minimal arbitrary-precision unsigned integers, used for targets, ASERT
//! intermediates (up to ~520 bits, difficulty.md §2) and chainwork (unbounded,
//! blocks.md §5). Little-endian u64 limbs, always normalized (no high zero limbs).

use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    pub fn zero() -> Self {
        BigUint { limbs: Vec::new() }
    }
    pub fn from_u64(v: u64) -> Self {
        let mut b = BigUint { limbs: vec![v] };
        b.normalize();
        b
    }
    pub fn from_u128(v: u128) -> Self {
        let mut b = BigUint { limbs: vec![v as u64, (v >> 64) as u64] };
        b.normalize();
        b
    }
    /// 2^bits
    pub fn pow2(bits: u32) -> Self {
        let mut limbs = vec![0u64; (bits / 64) as usize + 1];
        limbs[(bits / 64) as usize] = 1u64 << (bits % 64);
        BigUint { limbs }
    }
    /// Little-endian bytes of any length.
    pub fn from_le_bytes(b: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(b.len() / 8 + 1);
        for chunk in b.chunks(8) {
            let mut w = [0u8; 8];
            w[..chunk.len()].copy_from_slice(chunk);
            limbs.push(u64::from_le_bytes(w));
        }
        let mut r = BigUint { limbs };
        r.normalize();
        r
    }
    /// Exactly `n` little-endian bytes; None if the value does not fit.
    pub fn to_le_bytes(&self, n: usize) -> Option<Vec<u8>> {
        if self.bits() > (n as u64) * 8 {
            return None;
        }
        let mut out = vec![0u8; n];
        for (i, l) in self.limbs.iter().enumerate() {
            for j in 0..8 {
                let idx = i * 8 + j;
                if idx < n {
                    out[idx] = (l >> (8 * j)) as u8;
                }
            }
        }
        Some(out)
    }
    /// Parse big-endian hex (as used in test vectors).
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.trim_start_matches("0x");
        if s.is_empty() {
            return Some(Self::zero());
        }
        let mut r = Self::zero();
        for c in s.chars() {
            let d = c.to_digit(16)? as u64;
            r = r.shl(4).add(&Self::from_u64(d));
        }
        Some(r)
    }
    pub fn to_hex(&self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        let mut s = String::new();
        for (i, l) in self.limbs.iter().rev().enumerate() {
            if i == 0 {
                s += &format!("{:x}", l);
            } else {
                s += &format!("{:016x}", l);
            }
        }
        s
    }
    /// Zero-padded big-endian hex of `n` bytes.
    pub fn to_hex_padded(&self, n: usize) -> String {
        let h = self.to_hex();
        format!("{:0>width$}", h, width = n * 2)
    }
    fn normalize(&mut self) {
        while let Some(&0) = self.limbs.last() {
            self.limbs.pop();
        }
    }
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }
    pub fn bits(&self) -> u64 {
        match self.limbs.last() {
            None => 0,
            Some(&top) => (self.limbs.len() as u64 - 1) * 64 + (64 - top.leading_zeros() as u64),
        }
    }
    pub fn to_u64(&self) -> Option<u64> {
        match self.limbs.len() {
            0 => Some(0),
            1 => Some(self.limbs[0]),
            _ => None,
        }
    }
    pub fn add(&self, o: &BigUint) -> BigUint {
        let n = self.limbs.len().max(o.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u128;
        for i in 0..n {
            let s = *self.limbs.get(i).unwrap_or(&0) as u128 + *o.limbs.get(i).unwrap_or(&0) as u128 + carry;
            out.push(s as u64);
            carry = s >> 64;
        }
        if carry > 0 {
            out.push(carry as u64);
        }
        let mut r = BigUint { limbs: out };
        r.normalize();
        r
    }
    /// self − o; None if o > self.
    pub fn checked_sub(&self, o: &BigUint) -> Option<BigUint> {
        if self < o {
            return None;
        }
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i128;
        for i in 0..self.limbs.len() {
            let mut d = self.limbs[i] as i128 - *o.limbs.get(i).unwrap_or(&0) as i128 - borrow;
            if d < 0 {
                d += 1i128 << 64;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(d as u64);
        }
        let mut r = BigUint { limbs: out };
        r.normalize();
        Some(r)
    }
    pub fn mul_u64(&self, m: u64) -> BigUint {
        let mut out = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u128;
        for &l in &self.limbs {
            let p = l as u128 * m as u128 + carry;
            out.push(p as u64);
            carry = p >> 64;
        }
        if carry > 0 {
            out.push(carry as u64);
        }
        let mut r = BigUint { limbs: out };
        r.normalize();
        r
    }
    pub fn shl(&self, bits: u32) -> BigUint {
        if self.is_zero() {
            return BigUint::zero();
        }
        let (w, b) = ((bits / 64) as usize, bits % 64);
        let mut out = vec![0u64; w];
        let mut carry = 0u64;
        for &l in &self.limbs {
            if b == 0 {
                out.push(l);
            } else {
                out.push((l << b) | carry);
                carry = l >> (64 - b);
            }
        }
        if carry > 0 {
            out.push(carry);
        }
        let mut r = BigUint { limbs: out };
        r.normalize();
        r
    }
    pub fn shr(&self, bits: u32) -> BigUint {
        let (w, b) = ((bits / 64) as usize, bits % 64);
        if w >= self.limbs.len() {
            return BigUint::zero();
        }
        let src = &self.limbs[w..];
        let mut out = Vec::with_capacity(src.len());
        for i in 0..src.len() {
            let lo = src[i] >> b;
            let hi = if b > 0 && i + 1 < src.len() { src[i + 1] << (64 - b) } else { 0 };
            out.push(lo | hi);
        }
        let mut r = BigUint { limbs: out };
        r.normalize();
        r
    }
    fn bit(&self, i: u64) -> bool {
        let w = (i / 64) as usize;
        w < self.limbs.len() && (self.limbs[w] >> (i % 64)) & 1 == 1
    }
    /// Floor division; None on division by zero. Simple shift-subtract (inputs here are ≤ ~520 bits).
    pub fn div(&self, d: &BigUint) -> Option<BigUint> {
        if d.is_zero() {
            return None;
        }
        if self < d {
            return Some(BigUint::zero());
        }
        let mut q = BigUint::zero();
        let mut r = BigUint::zero();
        for i in (0..self.bits()).rev() {
            r = r.shl(1);
            if self.bit(i) {
                r = r.add(&BigUint::from_u64(1));
            }
            if r >= *d {
                r = r.checked_sub(d).unwrap();
                q = q.add(&BigUint::pow2(i as u32));
            }
        }
        Some(q)
    }
}

impl Ord for BigUint {
    fn cmp(&self, o: &Self) -> Ordering {
        if self.limbs.len() != o.limbs.len() {
            return self.limbs.len().cmp(&o.limbs.len());
        }
        for i in (0..self.limbs.len()).rev() {
            match self.limbs[i].cmp(&o.limbs[i]) {
                Ordering::Equal => continue,
                x => return x,
            }
        }
        Ordering::Equal
    }
}
impl PartialOrd for BigUint {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arithmetic() {
        let a = BigUint::pow2(256);
        let one = BigUint::from_u64(1);
        assert_eq!(a.checked_sub(&one).unwrap().bits(), 256);
        assert_eq!(a.div(&BigUint::pow2(240).add(&one)).unwrap().to_u64(), Some(65535));
        assert_eq!(BigUint::from_hex("ffff").unwrap().shl(208).to_hex_padded(32),
                   "00000000ffff0000000000000000000000000000000000000000000000000000");
        let x = BigUint::from_hex("123456789abcdef0123456789abcdef0fedcba").unwrap();
        assert_eq!(x.shl(77).shr(77), x);
        assert_eq!(BigUint::from_le_bytes(&x.to_le_bytes(40).unwrap()), x);
        assert_eq!(x.mul_u64(1 << 20), x.shl(20));
        assert!(BigUint::from_u64(1).checked_sub(&BigUint::from_u64(2)).is_none());
        assert_eq!(BigUint::from_u128(u128::MAX).add(&one), BigUint::pow2(128));
    }
}
