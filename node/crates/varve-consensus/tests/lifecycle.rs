//! Scheme lifecycle (transactions.md §6) and shared authorization (§8.2), exercised
//! end to end through check_transaction with real signatures.

use std::collections::HashMap;

use varve_consensus::params::*;
use varve_consensus::tx::{commitment, sighash, OutPoint, Output, Recovery, Tx, Witness};
use varve_consensus::validate::{check_transaction, ChainIds, Coin};

struct Key {
    scheme: u16,
    pk: Vec<u8>,
    sk: Vec<u8>,
}

impl Key {
    fn new(scheme: u16) -> Key {
        let sys = scheme_sys(scheme);
        let (pk, sk) = varve_sys::keypair(sys).unwrap();
        Key { scheme, pk, sk }
    }
    fn com(&self) -> [u8; 32] {
        commitment(self.scheme, &self.pk)
    }
}

fn scheme_sys(id: u16) -> varve_sys::Scheme {
    scheme(id, 0).unwrap().sys
}

const ML: u16 = SCHEME_ML_DSA_65;
const SLH: u16 = SCHEME_SLH_DSA_SHA2_128S;

/// ML-DSA: NO_NEW_OUTPUTS from 100, DISABLED from 200 (listed out of order on purpose).
fn ids() -> ChainIds {
    ChainIds {
        network_id: *b"VRVt",
        genesis_id: [7u8; 32],
        lifecycle: vec![
            Transition { scheme_id: ML, state: SchemeState::Disabled, from_height: 200 },
            Transition { scheme_id: ML, state: SchemeState::NoNewOutputs, from_height: 100 },
        ],
    }
}

fn op(n: u8) -> OutPoint {
    OutPoint { txid: [n; 32], index: 0 }
}

/// Builds a tx spending `inputs` (coin, signing key or None for path 2, path) to `outs`,
/// signs it, and runs check_transaction at `height`.
fn run(inputs: &[(Coin, Option<&Key>, u8)], outs: Vec<Output>, height: u64) -> Result<(u64, Vec<Coin>), varve_consensus::Error> {
    let ids = ids();
    let mut utxo = HashMap::new();
    let mut tx = Tx { version: TX_VERSION, inputs: vec![], outputs: outs, locktime: 0, witnesses: vec![] };
    for (n, (c, _, path)) in inputs.iter().enumerate() {
        utxo.insert(op(n as u8 + 1), c.clone());
        tx.inputs.push(op(n as u8 + 1));
        tx.witnesses.push(Witness { path: *path, public_key: vec![], signature: vec![] });
    }
    let spent: Vec<Output> = inputs.iter().map(|(c, _, _)| c.output.clone()).collect();
    for (n, (_, key, path)) in inputs.iter().enumerate() {
        if let Some(k) = key {
            let msg = sighash(&ids.network_id, &ids.genesis_id, &tx, n as u32, &spent, *path);
            let sig = varve_sys::sign(scheme_sys(k.scheme), &k.sk, &msg).unwrap();
            tx.witnesses[n] = Witness { path: *path, public_key: k.pk.clone(), signature: sig };
        }
    }
    check_transaction(&tx, height, &ids, &utxo, true)
}

fn coin(o: Output) -> Coin {
    Coin { output: o, height: 1, coinbase: false }
}

fn err(r: Result<(u64, Vec<Coin>), varve_consensus::Error>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => format!("{e:?}"),
    }
}

#[test]
fn scheme_state_resolution() {
    let l = ids().lifecycle;
    assert_eq!(scheme_state(&l, ML, 0), Some(SchemeState::Active));
    assert_eq!(scheme_state(&l, ML, 99), Some(SchemeState::Active));
    assert_eq!(scheme_state(&l, ML, 100), Some(SchemeState::NoNewOutputs));
    assert_eq!(scheme_state(&l, ML, 199), Some(SchemeState::NoNewOutputs));
    assert_eq!(scheme_state(&l, ML, 200), Some(SchemeState::Disabled));
    assert_eq!(scheme_state(&l, ML, u64::MAX), Some(SchemeState::Disabled));
    assert_eq!(scheme_state(&l, SLH, u64::MAX), Some(SchemeState::Active));
    assert_eq!(scheme_state(&l, 3, 0), None);
    assert_eq!(scheme_state(&l, 0, 0), None);
    assert_eq!(scheme_state(&[], ML, 5), Some(SchemeState::Active));
}

#[test]
fn creation_follows_lifecycle() {
    let a = Key::new(ML);
    let b = Key::new(SLH);
    let c = coin(Output::single(1000, ML, a.com()));
    // ML-DSA outputs creatable while ACTIVE only
    assert_eq!(err(run(&[(c.clone(), Some(&a), 0)], vec![Output::single(900, ML, a.com())], 99)), "ok");
    assert!(err(run(&[(c.clone(), Some(&a), 0)], vec![Output::single(900, ML, a.com())], 100)).contains("not creatable"));
    // recovery scheme must be creatable too
    let rec = Output { amount: 900, output_version: 1, scheme_id: SLH, commitment: b.com(), recovery: Some(Recovery { scheme_id: ML, commitment: a.com(), delay: 10 }) };
    assert!(err(run(&[(c.clone(), Some(&a), 0)], vec![rec], 150)).contains("not creatable"));
    // migrating away while NO_NEW_OUTPUTS works
    assert_eq!(err(run(&[(c, Some(&a), 0)], vec![Output::single(900, SLH, b.com())], 150)), "ok");
}

#[test]
fn spending_follows_lifecycle() {
    let a = Key::new(ML);
    let b = Key::new(SLH);
    let c = coin(Output::single(1000, ML, a.com()));
    let to_b = || vec![Output::single(900, SLH, b.com())];
    assert_eq!(err(run(&[(c.clone(), Some(&a), 0)], to_b(), 199)), "ok");
    assert!(err(run(&[(c.clone(), Some(&a), 0)], to_b(), 200)).contains("not spendable"));
    // a disabled primary scheme can still be left through an ACTIVE recovery scheme
    let r = coin(Output { amount: 1000, output_version: 1, scheme_id: ML, commitment: a.com(), recovery: Some(Recovery { scheme_id: SLH, commitment: b.com(), delay: 10 }) });
    assert!(err(run(&[(r.clone(), Some(&a), 0)], to_b(), 250)).contains("not spendable"));
    assert_eq!(err(run(&[(r, Some(&b), 1)], to_b(), 250)), "ok");
}

#[test]
fn shared_authorization() {
    let a = Key::new(ML);
    let other = Key::new(ML);
    let b = Key::new(SLH);
    let ca = || coin(Output::single(1000, ML, a.com()));
    let out = || vec![Output::single(2500, SLH, b.com())];
    // one signature covers three coins of the same key
    let r = run(&[(ca(), Some(&a), 0), (ca(), None, 2), (ca(), None, 2)], out(), 10).unwrap();
    assert_eq!(r.0, 500);
    // path 2 needs an EARLIER authorizing input
    assert!(err(run(&[(ca(), None, 2), (ca(), Some(&a), 0)], vec![Output::single(1500, SLH, b.com())], 10)).contains("authorizes"));
    // a different key does not authorize
    let co = coin(Output::single(1000, ML, other.com()));
    assert!(err(run(&[(ca(), Some(&a), 0), (co, None, 2)], vec![Output::single(1500, SLH, b.com())], 10)).contains("authorizes"));
    // path 2 is still subject to the lifecycle
    assert_eq!(err(run(&[(ca(), Some(&a), 0), (ca(), None, 2)], vec![Output::single(1500, SLH, b.com())], 150)), "ok");
    assert!(err(run(&[(ca(), Some(&a), 0), (ca(), None, 2)], vec![Output::single(1500, SLH, b.com())], 200)).contains("not spendable"));
}

#[test]
fn shared_witness_must_be_empty() {
    let a = Key::new(ML);
    let b = Key::new(SLH);
    let ca = coin(Output::single(1000, ML, a.com()));
    let ids = ids();
    let mut utxo = HashMap::new();
    utxo.insert(op(1), ca.clone());
    utxo.insert(op(2), ca.clone());
    let mut tx = Tx {
        version: TX_VERSION,
        inputs: vec![op(1), op(2)],
        outputs: vec![Output::single(1500, SLH, b.com())],
        locktime: 0,
        witnesses: vec![Witness { path: 0, public_key: vec![], signature: vec![] }, Witness { path: 2, public_key: vec![], signature: vec![] }],
    };
    let spent = vec![ca.output.clone(), ca.output.clone()];
    let msg = sighash(&ids.network_id, &ids.genesis_id, &tx, 0, &spent, 0);
    let sig = varve_sys::sign(scheme_sys(ML), &a.sk, &msg).unwrap();
    tx.witnesses[0] = Witness { path: 0, public_key: a.pk.clone(), signature: sig.clone() };
    assert!(check_transaction(&tx, 10, &ids, &utxo, true).is_ok());
    tx.witnesses[1].public_key = a.pk.clone();
    assert!(check_transaction(&tx, 10, &ids, &utxo, true).is_err());
    tx.witnesses[1].public_key.clear();
    tx.witnesses[1].signature = sig;
    assert!(check_transaction(&tx, 10, &ids, &utxo, true).is_err());
}
