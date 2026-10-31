//! test-vectors/wallet.json: fixed seeds -> master -> keys -> commitments ->
//! addresses. Only public data and the (public, test-only) seeds and masters
//! are written; never okm or secret keys.
//!
//! Regenerate with
//!   VARVE_WRITE_WALLET_VECTORS=1 cargo test --release -p varve-wallet vectors
//! (the file is then checked by the same test on every run).

use crate::derive::{scheme_id, scheme_from_id, Role, Scheme};
use crate::util::{hex, unhex_strict};
use crate::Wallet;
use varve_consensus::json::Json;

fn path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../test-vectors/wallet.json")
}

/// (role, scheme, account, index) per case.
fn key_list(extended: bool) -> Vec<(Role, Scheme, u32, u32)> {
    let mut v: Vec<_> = (0..3).map(|i| (Role::Primary, Scheme::MlDsa65, 0, i)).collect();
    if extended {
        v.push((Role::Recovery, Scheme::MlDsa65, 0, 0));
        v.push((Role::Primary, Scheme::MlDsa65, 1, 0));
        v.push((Role::Primary, Scheme::SlhDsaSha2_128s, 0, 0));
    }
    v
}

fn generate() -> Json {
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let mut cases = Vec::new();
    for (pass, extended) in [("", true), ("varve test passphrase", false)] {
        let w = Wallet::from_seed(&seed, Some(pass)).unwrap();
        let master = crate::derive::master(&seed, pass).unwrap();
        let mut keys = Vec::new();
        for (role, scheme, account, index) in key_list(extended) {
            let k = w.derive(role, scheme, account, index).unwrap();
            let mut fields = vec![
                ("role", Json::num(role as u8)),
                ("scheme_id", Json::num(scheme_id(scheme))),
                ("account", Json::num(account)),
                ("index", Json::num(index)),
                ("public_key_len", Json::num(k.pk.len())),
                ("public_key_sha3_256", Json::str(hex(&varve_sys::sha3_256(&k.pk)))),
                ("commitment", Json::str(hex(&k.commitment))),
                ("template_hex", Json::str(hex(&k.output(0).template()))),
                ("address_mainnet", Json::str(k.address("varve").unwrap())),
                ("address_testnet", Json::str(k.address("tvarve").unwrap())),
            ];
            if scheme == Scheme::SlhDsaSha2_128s {
                fields.push(("public_key_hex", Json::str(hex(&k.pk))));
            }
            keys.push(Json::obj(fields));
        }
        cases.push(Json::obj(vec![
            ("seed_hex", Json::str(hex(&seed))),
            ("mnemonic", Json::str(w.mnemonic().expose())),
            ("passphrase", Json::str(pass)),
            ("master_hex", Json::str(hex(&master))),
            ("keys", Json::Arr(keys)),
        ]));
    }
    Json::obj(vec![
        (
            "description",
            Json::str(
                "protocol/wallet.md v0.2 derivation vectors. TEST SEEDS ONLY: the seeds are public and must never hold funds. \
                 Keys: role 0 primary / 1 recovery; scheme_id 1 ML-DSA-65, 2 SLH-DSA-SHA2-128s. public_key_sha3_256 = SHA3-256(public key). \
                 commitment = H256(\"VARVE/pk/v1\", u16(scheme_id) || public key). Addresses are policy-0 outputs; mainnet hrp varve, testnet hrp tvarve. \
                 No okm or secret keys are included.",
            ),
        ),
        ("cases", Json::Arr(cases)),
    ])
}

/// Pretty-print with one key per line so diffs stay readable.
fn pretty(j: &Json, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent + 1);
    match j {
        Json::Obj(m) => {
            out.push_str("{\n");
            for (i, (k, v)) in m.iter().enumerate() {
                out.push_str(&pad);
                out.push_str(&Json::str(k.clone()).to_string());
                out.push_str(": ");
                pretty(v, indent + 1, out);
                out.push_str(if i + 1 < m.len() { ",\n" } else { "\n" });
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
        Json::Arr(a) => {
            out.push_str("[\n");
            for (i, v) in a.iter().enumerate() {
                out.push_str(&pad);
                pretty(v, indent + 1, out);
                out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[test]
fn wallet_vectors() {
    let generated = generate();
    if std::env::var("VARVE_WRITE_WALLET_VECTORS").as_deref() == Ok("1") {
        let mut s = String::new();
        pretty(&generated, 0, &mut s);
        s.push('\n');
        std::fs::write(path(), s).unwrap();
    }
    let text = std::fs::read_to_string(path()).expect("test-vectors/wallet.json missing");
    let file = Json::parse(&text).unwrap();
    assert_eq!(file, generated, "test-vectors/wallet.json does not match the implementation");

    // Independent re-derivation of every field from the file's own inputs,
    // through the lower-level functions rather than Wallet.
    let cases = file.at("cases").as_arr().unwrap();
    assert_eq!(cases.len(), 2);
    for c in cases {
        let seed: [u8; 32] = unhex_strict(c.at("seed_hex").as_str().unwrap()).unwrap().try_into().unwrap();
        let pass = c.at("passphrase").as_str().unwrap();
        assert_eq!(crate::bip39::mnemonic_to_entropy(c.at("mnemonic").as_str().unwrap()).unwrap(), seed);
        let master = crate::derive::master(&seed, pass).unwrap();
        assert_eq!(hex(&master), c.at("master_hex").as_str().unwrap());
        let keys = c.at("keys").as_arr().unwrap();
        assert!(keys.len() >= 3);
        for k in keys {
            let role = match k.at("role").as_u64().unwrap() {
                0 => Role::Primary,
                1 => Role::Recovery,
                _ => panic!("role"),
            };
            let sid = k.at("scheme_id").as_u64().unwrap() as u16;
            let scheme = scheme_from_id(sid).unwrap();
            let okm = crate::derive::okm(&master, role, scheme, k.at("account").as_u64().unwrap() as u32, k.at("index").as_u64().unwrap() as u32);
            let (pk, _sk) = crate::derive::keygen(scheme, okm.expose()).unwrap();
            assert_eq!(hex(&varve_sys::sha3_256(&pk)), k.at("public_key_sha3_256").as_str().unwrap());
            let cm = varve_consensus::tx::commitment(sid, &pk);
            assert_eq!(hex(&cm), k.at("commitment").as_str().unwrap());
            let o = varve_consensus::tx::Output::single(0, sid, cm);
            assert_eq!(hex(&o.template()), k.at("template_hex").as_str().unwrap());
            assert_eq!(crate::address::encode("varve", &o), k.at("address_mainnet").as_str().unwrap());
            assert_eq!(crate::address::encode("tvarve", &o), k.at("address_testnet").as_str().unwrap());
        }
    }
    // The first three keys of the first case are ML-DSA-65 primary, indexes 0..2.
    let k0 = cases[0].at("keys").as_arr().unwrap();
    for (i, k) in k0.iter().take(3).enumerate() {
        assert_eq!(k.at("scheme_id").as_u64(), Some(1));
        assert_eq!(k.at("index").as_u64(), Some(i as u64));
    }
}
