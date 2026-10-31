//! Runs every file in test-vectors/ against this implementation.

use std::collections::HashMap;
use std::path::PathBuf;

use varve_consensus::bignum::BigUint;
use varve_consensus::block::*;
use varve_consensus::encoding::{hex, unhex, Reader};
use varve_consensus::genesis::*;
use varve_consensus::json::Json;
use varve_consensus::params::*;
use varve_consensus::tx::*;
use varve_consensus::validate::*;

fn load(name: &str) -> Json {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../test-vectors").join(name);
    Json::parse(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e))).unwrap()
}
fn ub(s: &str) -> Vec<u8> {
    unhex(s).unwrap()
}
fn a32(s: &str) -> [u8; 32] {
    ub(s).try_into().unwrap()
}

#[test]
fn params_hash_matches_draft_set() {
    let j = load("params.json");
    let p = varve_consensus::networks::mainnet_draft();
    assert_eq!(hex(&p.params_hash()), j.at("params_hash").as_str().unwrap());
    assert_eq!(p.params_serialization().len() as u64, j.at("serialization_length").as_u64().unwrap());
}

#[test]
fn subsidy_vectors_and_frac_exactness() {
    let j = load("subsidy.json");
    for c in j.at("subsidy").as_arr().unwrap() {
        assert_eq!(subsidy(c.at("height").as_u64().unwrap()), c.at("subsidy").as_u64().unwrap());
    }
    let fr = j.at("constants.FRAC_Q63").as_arr().unwrap();
    for (k, f) in fr.iter().enumerate() {
        assert_eq!(u64::from_str_radix(&f.as_str().unwrap()[2..], 16).unwrap(), FRAC_Q63[k]);
    }
    // supply checkpoints
    let mut supply = 0u128;
    let mut h = 0u64;
    for c in j.at("cumulative_supply").as_arr().unwrap() {
        let target = c.at("height").as_u64().unwrap();
        while h < target {
            h += 1;
            supply += subsidy(h) as u128;
        }
        assert_eq!(supply, c.at("supply").as_u64().unwrap() as u128, "supply at {}", target);
    }
}

/// subsidy.md: FRAC[k] is the unique v with v^64·2^k ≤ 2^4032 < (v+1)^64·2^k.
#[test]
fn frac_definition_holds() {
    fn pow64(v: u64) -> BigUint {
        // square six times: v^64
        let mut x = BigUint::from_u64(v);
        for _ in 0..6 {
            x = mul(&x, &x);
        }
        x
    }
    fn mul(a: &BigUint, b: &BigUint) -> BigUint {
        // schoolbook via 64-bit chunks of b
        let bb = b.to_le_bytes(((b.bits() + 7) / 8) as usize).unwrap();
        let mut acc = BigUint::zero();
        for (i, chunk) in bb.chunks(8).enumerate() {
            let mut w = [0u8; 8];
            w[..chunk.len()].copy_from_slice(chunk);
            acc = acc.add(&a.mul_u64(u64::from_le_bytes(w)).shl(64 * i as u32));
        }
        acc
    }
    let bound = BigUint::pow2(4032);
    for (k, &v) in FRAC_Q63.iter().enumerate() {
        assert!(pow64(v).shl(k as u32) <= bound, "lower k={}", k);
        assert!(pow64(v + 1).shl(k as u32) > bound, "upper k={}", k);
    }
}

#[test]
fn difficulty_vectors() {
    let j = load("difficulty.json");
    let init = BigUint::pow2(240);
    for c in j.at("cases").as_arr().unwrap() {
        let dt = c.at("parent_time_minus_genesis").as_i64().unwrap();
        let h = c.at("parent_height").as_u64().unwrap();
        // genesis time chosen so the parent time is non-negative
        let t0: u64 = 1 << 40;
        let got = next_target(&init, t0, h, (t0 as i64 + dt) as u64);
        assert_eq!(got.to_hex_padded(32), c.at("next_target_hex").as_str().unwrap(), "{:?}", c.get("label"));
    }
}

#[test]
fn genesis_vectors() {
    let j = load("genesis.json");
    for c in j.at("anchor_cases").as_arr().unwrap() {
        let hs: Vec<[u8; 80]> = c.at("headers").as_arr().unwrap().iter().map(|h| ub(h.as_str().unwrap()).try_into().unwrap()).collect();
        let bits = u32::from_str_radix(&c.at("anchor_bits").as_str().unwrap()[2..], 16).unwrap();
        let r = check_btc_anchor(&hs, c.at("anchor_height").as_u64().unwrap() as u32, &a32(c.at("anchor_prev_hash_internal").as_str().unwrap()), bits);
        let want_valid = c.at("result").as_str().unwrap() == "valid";
        assert_eq!(r.is_ok(), want_valid, "{} -> {:?}", c.at("name").as_str().unwrap(), r);
    }
    for c in j.at("compact_cases").as_arr().unwrap() {
        let bits = u32::from_str_radix(&c.at("bits").as_str().unwrap()[2..], 16).unwrap();
        match (btc_compact_to_target(bits), c.get("target")) {
            (Ok(t), Some(want)) => assert_eq!(t.to_hex_padded(32), want.as_str().unwrap()),
            (Err(_), None) => {}
            (r, w) => panic!("compact {:x}: {:?} vs {:?}", bits, r, w),
        }
    }
    let e = j.at("example_genesis");
    let hs: Vec<[u8; 80]> = j.at("anchor_cases.0.headers").as_arr().unwrap().iter().map(|h| ub(h.as_str().unwrap()).try_into().unwrap()).collect();
    let g = genesis_block_from(&a32(e.at("params_hash").as_str().unwrap()), &hs, &BigUint::from_hex(e.at("initial_target").as_str().unwrap()).unwrap());
    assert_eq!(hex(&g.header.serialize()), e.at("header").as_str().unwrap());
    assert_eq!(hex(&g.header.block_id()), e.at("block_id").as_str().unwrap());
    assert_eq!(hex(&g.txs[0].txid()), e.at("coinbase_txid").as_str().unwrap());
}

#[test]
fn consensus_vectors() {
    let j = load("consensus.json");
    for c in j.at("transactions").as_arr().unwrap() {
        let name = c.at("name").as_str().unwrap();
        let r = Tx::from_bytes(&ub(c.at("hex").as_str().unwrap()));
        match c.at("parse").as_str().unwrap() {
            "ok" => {
                let t = r.unwrap_or_else(|e| panic!("{}: {:?}", name, e));
                assert_eq!(hex(&t.txid()), c.at("txid").as_str().unwrap(), "{}", name);
                assert_eq!(hex(&t.wtxid()), c.at("wtxid").as_str().unwrap(), "{}", name);
                assert_eq!(t.weight(false), c.at("weight").as_u64().unwrap(), "{}", name);
                assert_eq!(t.base().len() as u64, c.at("base_size").as_u64().unwrap(), "{}", name);
                assert_eq!(hex(&t.serialize()), c.at("hex").as_str().unwrap(), "{}", name);
            }
            _ => assert!(r.is_err(), "{} should not parse", name),
        }
    }
    for c in j.at("merkle").as_arr().unwrap() {
        let ids: Vec<[u8; 32]> = c.at("wtxids").as_arr().unwrap().iter().map(|x| a32(x.as_str().unwrap())).collect();
        assert_eq!(hex(&merkle_root(&ids)), c.at("root").as_str().unwrap());
    }
    for c in j.at("headers").as_arr().unwrap() {
        let h = Header::from_bytes(&ub(c.at("hex").as_str().unwrap())).unwrap();
        assert_eq!(hex(&h.serialize()), c.at("hex").as_str().unwrap());
        assert_eq!(hex(&h.block_id()), c.at("block_id").as_str().unwrap());
    }
    for c in j.at("sighash").as_arr().unwrap() {
        let t = Tx::from_bytes(&ub(c.at("tx_hex").as_str().unwrap())).unwrap();
        let spent: Vec<Output> = c.at("spent_outputs").as_arr().unwrap().iter().map(|o| {
            let b = ub(o.as_str().unwrap());
            let mut r = Reader::new(&b);
            let out = Output::parse(&mut r).unwrap();
            r.finish().unwrap();
            out
        }).collect();
        let nid: [u8; 4] = ub(c.at("network_id").as_str().unwrap()).try_into().unwrap();
        let got = sighash(&nid, &a32(c.at("genesis_id").as_str().unwrap()), &t, c.at("index").as_u64().unwrap() as u32, &spent, c.at("path").as_u64().unwrap() as u8);
        assert_eq!(hex(&got), c.at("sighash").as_str().unwrap());
    }
    for c in j.at("chainwork").as_arr().unwrap() {
        let mut total = BigUint::zero();
        for t in c.at("targets").as_arr().unwrap() {
            total = total.add(&work(&BigUint::from_hex(t.as_str().unwrap()).unwrap()));
        }
        assert_eq!(total.to_hex(), c.at("chainwork").as_str().unwrap().trim_start_matches('0'), "{:?}", c.get("name"));
    }
}

#[test]
fn signature_vectors() {
    let j = load("signatures.json");
    for c in j.at("signatures").as_arr().unwrap() {
        let sid = c.at("scheme_id").as_u64().unwrap() as u16;
        let s = scheme(sid, 0).unwrap();
        let ok = varve_sys::verify(s.sys, &ub(c.at("public_key").as_str().unwrap()), &ub(c.at("message").as_str().unwrap()), &ub(c.at("signature").as_str().unwrap()));
        assert_eq!(ok, c.at("valid").as_bool().unwrap(), "{}", c.at("name").as_str().unwrap());
    }
}

/// Minimal in-memory chain to replay chain.json (PoW not checked there).
struct MemChain {
    blocks: Vec<Block>,
    utxo: HashMap<OutPoint, Coin>,
    ids: ChainIds,
    init: BigUint,
}

impl MemChain {
    fn connect(&mut self, b: &Block) -> Result<(), varve_consensus::Error> {
        let height = self.blocks.len() as u64;
        let parent = &self.blocks.last().unwrap().header;
        let start = self.blocks.len().saturating_sub(MTP_WINDOW);
        let ts: Vec<u64> = self.blocks[start..].iter().map(|b| b.header.timestamp).collect();
        let ctx = HeaderContext {
            height,
            parent_id: parent.block_id(),
            parent_timestamp: parent.timestamp,
            recent_timestamps: &ts,
            genesis_timestamp: self.blocks[0].header.timestamp,
            initial_target: &self.init,
        };
        check_header(&b.header, &ctx)?;
        let undo = check_block(b, height, &self.ids, &self.utxo, true)?;
        for (op, _) in &undo.spent {
            self.utxo.remove(op);
        }
        for (op, c) in undo.created {
            self.utxo.insert(op, c);
        }
        self.blocks.push(b.clone());
        Ok(())
    }
}

#[test]
fn chain_vectors() {
    let j = load("chain.json");
    let genesis = Block::parse(&ub(j.at("genesis").as_str().unwrap())).unwrap();
    let base: Vec<Block> = j.at("base_chain").as_arr().unwrap().iter().map(|b| {
        let raw = ub(b.as_str().unwrap());
        let blk = Block::parse(&raw).unwrap();
        assert_eq!(blk.serialize(), raw, "re-serialization");
        blk
    }).collect();
    let fresh = || MemChain {
        blocks: vec![genesis.clone()],
        utxo: HashMap::new(),
        ids: ChainIds { network_id: ub(j.at("network_id").as_str().unwrap()).try_into().unwrap(), genesis_id: genesis.header.block_id(), lifecycle: Vec::new() },
        init: BigUint::from_hex(j.at("initial_target").as_str().unwrap()).unwrap(),
    };
    // one pass over the base chain, snapshotting the states the cases need
    let mut wanted: Vec<u64> = j.at("cases").as_arr().unwrap().iter().map(|c| c.at("parent_height").as_u64().unwrap()).collect();
    wanted.sort();
    wanted.dedup();
    let mut snaps: HashMap<u64, (Vec<Block>, HashMap<OutPoint, Coin>)> = HashMap::new();
    let mut ch = fresh();
    for (i, b) in base.iter().enumerate() {
        if wanted.contains(&(i as u64)) {
            snaps.insert(i as u64, (ch.blocks.clone(), ch.utxo.clone()));
        }
        ch.connect(b).unwrap_or_else(|e| panic!("base block {} invalid: {}", i + 1, e));
    }
    if wanted.contains(&(base.len() as u64)) {
        snaps.insert(base.len() as u64, (ch.blocks.clone(), ch.utxo.clone()));
    }
    let mut n = 0;
    for c in j.at("cases").as_arr().unwrap() {
        let name = c.at("name").as_str().unwrap();
        let (blocks, utxo) = snaps[&c.at("parent_height").as_u64().unwrap()].clone();
        let mut m = fresh();
        m.blocks = blocks;
        m.utxo = utxo;
        let r = Block::parse(&ub(c.at("block").as_str().unwrap())).and_then(|b| m.connect(&b));
        let want = c.at("result").as_str().unwrap() == "valid";
        assert_eq!(r.is_ok(), want, "{}: got {:?}, vector reason {:?}", name, r, c.get("reason"));
        n += 1;
    }
    assert!(n >= 59);
}

#[test]
fn pow_vectors() {
    let j = load("pow.json");
    let mut caches: HashMap<String, std::sync::Arc<varve_sys::RxCache>> = HashMap::new();
    for c in j.at("cases").as_arr().unwrap() {
        let k = c.at("key_ascii").as_str().unwrap();
        let key = if k == "(empty)" { vec![] } else { k.as_bytes().to_vec() };
        let cache = caches.entry(k.to_string()).or_insert_with(|| std::sync::Arc::new(varve_sys::RxCache::new(&key).unwrap())).clone();
        let mut vm = varve_sys::RxVm::light(cache).unwrap();
        assert_eq!(hex(&vm.hash(&ub(c.at("input_hex").as_str().unwrap()))), c.at("pow_hash").as_str().unwrap(), "key {}", k);
    }
}

#[test]
fn regtest_genesis_builds() {
    let p = varve_consensus::networks::regtest();
    let g = genesis_block(&p).unwrap();
    assert_eq!(g.header.timestamp, 1231470173);
    assert!(genesis_block(&varve_consensus::networks::mainnet_draft()).is_err());
}

#[test]
fn testnet_genesis_builds() {
    let p = varve_consensus::networks::testnet();
    let g = genesis_block(&p).expect("testnet anchor verifies");
    assert_eq!(g.header.timestamp, 1793448402);
    println!("testnet genesis {}", hex(&g.header.block_id()));
}
