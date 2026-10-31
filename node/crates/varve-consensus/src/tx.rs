//! transactions.md: outputs, inputs, witnesses, transactions, txid/wtxid, weight.

use crate::encoding::{h256, write_bytes, write_varint, Reader};
use crate::params::*;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub scheme_id: u16,
    pub commitment: [u8; 32],
    pub delay: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub amount: u64,
    pub output_version: u8,
    pub scheme_id: u16,
    pub commitment: [u8; 32],
    /// policy 1 iff Some
    pub recovery: Option<Recovery>,
}

impl Output {
    pub fn single(amount: u64, scheme_id: u16, commitment: [u8; 32]) -> Self {
        Output { amount, output_version: 1, scheme_id, commitment, recovery: None }
    }
    pub fn policy(&self) -> u8 {
        if self.recovery.is_some() { 1 } else { 0 }
    }
    /// The output without `amount` (transactions.md §1).
    pub fn template(&self) -> Vec<u8> {
        let mut b = vec![self.output_version, self.policy()];
        b.extend_from_slice(&self.scheme_id.to_le_bytes());
        b.extend_from_slice(&self.commitment);
        if let Some(r) = &self.recovery {
            b.extend_from_slice(&r.scheme_id.to_le_bytes());
            b.extend_from_slice(&r.commitment);
            b.extend_from_slice(&r.delay.to_le_bytes());
        }
        b
    }
    pub fn serialize_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.template());
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(82);
        self.serialize_into(&mut v);
        v
    }
    pub fn parse(r: &mut Reader) -> Result<Output, Error> {
        let amount = r.u64()?;
        let output_version = r.u8()?;
        let policy = r.u8()?;
        let scheme_id = r.u16()?;
        let commitment = r.array::<32>()?;
        let recovery = match policy {
            0 => None,
            1 => Some(Recovery { scheme_id: r.u16()?, commitment: r.array::<32>()?, delay: r.u32()? }),
            _ => return Err(Error::Parse("unknown policy")),
        };
        Ok(Output { amount, output_version, scheme_id, commitment, recovery })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub path: u8,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<OutPoint>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
    /// exactly one per input
    pub witnesses: Vec<Witness>,
}

impl Tx {
    pub fn base(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(16 + 36 * self.inputs.len() + 82 * self.outputs.len());
        b.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut b, self.inputs.len() as u64);
        for i in &self.inputs {
            b.extend_from_slice(&i.txid);
            b.extend_from_slice(&i.index.to_le_bytes());
        }
        write_varint(&mut b, self.outputs.len() as u64);
        for o in &self.outputs {
            o.serialize_into(&mut b);
        }
        b.extend_from_slice(&self.locktime.to_le_bytes());
        b
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut b = self.base();
        for w in &self.witnesses {
            b.push(w.path);
            write_bytes(&mut b, &w.public_key);
            write_bytes(&mut b, &w.signature);
        }
        b
    }
    pub fn txid(&self) -> [u8; 32] {
        h256("VARVE/txid/v1", &self.base())
    }
    pub fn wtxid(&self) -> [u8; 32] {
        h256("VARVE/wtxid/v1", &self.serialize())
    }
    pub fn is_coinbase_shaped(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].txid == [0u8; 32]
    }
    /// transactions.md §9. `coinbase` = weigh by serialized length only.
    pub fn weight(&self, coinbase: bool) -> u64 {
        let mut w = self.serialize().len() as u64;
        if coinbase {
            return w;
        }
        for x in &self.witnesses {
            w += verify_units_for_sig_len(x.signature.len());
        }
        let growth = (self.outputs.len() as u64).saturating_sub(self.inputs.len() as u64);
        w + UTXO_GROWTH_UNITS * growth
    }
    pub fn parse(r: &mut Reader) -> Result<Tx, Error> {
        let version = r.u32()?;
        let n_in = r.varint()?;
        r.need(n_in, (MIN_INPUT_SIZE + MIN_WITNESS_SIZE) as u64)?;
        let mut inputs = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            inputs.push(OutPoint { txid: r.array::<32>()?, index: r.u32()? });
        }
        let n_out = r.varint()?;
        r.need(n_out, MIN_OUTPUT_SIZE as u64)?;
        let mut outputs = Vec::with_capacity(n_out as usize);
        for _ in 0..n_out {
            outputs.push(Output::parse(r)?);
        }
        let locktime = r.u32()?;
        let mut witnesses = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            let path = r.u8()?;
            if path > 2 {
                return Err(Error::Parse("unknown witness path"));
            }
            let public_key = r.bytes(MAX_PUBLIC_KEY_LEN)?.to_vec();
            let signature = r.bytes(MAX_SIGNATURE_LEN)?.to_vec();
            witnesses.push(Witness { path, public_key, signature });
        }
        Ok(Tx { version, inputs, outputs, locktime, witnesses })
    }
    /// Parse exactly one transaction with no trailing bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Tx, Error> {
        let mut r = Reader::new(b);
        let t = Tx::parse(&mut r)?;
        r.finish()?;
        Ok(t)
    }
}

/// H256("VARVE/pk/v1", u16(scheme_id) ‖ public_key)
pub fn commitment(scheme_id: u16, public_key: &[u8]) -> [u8; 32] {
    let mut m = scheme_id.to_le_bytes().to_vec();
    m.extend_from_slice(public_key);
    h256("VARVE/pk/v1", &m)
}

/// transactions.md §7
pub fn sighash(network_id: &[u8; 4], genesis_id: &[u8; 32], tx: &Tx, index: u32, spent: &[Output], path: u8) -> [u8; 32] {
    let mut s = Vec::with_capacity(82 * spent.len());
    for o in spent {
        o.serialize_into(&mut s);
    }
    let spent_hash = h256("VARVE/spent/v1", &s);
    let mut m = Vec::with_capacity(4 + 32 + 32 + 4 + 32 + 1);
    m.extend_from_slice(network_id);
    m.extend_from_slice(genesis_id);
    m.extend_from_slice(&tx.txid());
    m.extend_from_slice(&index.to_le_bytes());
    m.extend_from_slice(&spent_hash);
    m.push(path);
    h256("VARVE/sighash/v1", &m)
}
