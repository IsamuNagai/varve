//! Testnet parameters. Anchor: Bitcoin blocks 973970..973975, fetched from two
//! independent explorers by tools/fetch-btc-anchor.py (CI workflow "anchor") and re-verified
//! (linkage, nBits, proof of work) by check_btc_anchor at every node start.
use crate::bignum::BigUint;
use crate::networks::{headers, prev_hash};
use crate::params::{ChainParams, Network};

pub fn testnet() -> ChainParams {
    ChainParams {
        network: Network::Testnet,
        name: "testnet",
        network_id: *b"TVAR",
        hrp: "tvarve",
        default_port: 39900,
        initial_target: BigUint::pow2(240),
        btc_anchor_height: 973970,
        btc_anchor_prev_hash: prev_hash("eb91cd1769c1b30a5f0f8e39b3188b7d25764b2c649d01000000000000000000"),
        btc_anchor_bits: 0x1701e5ac,
        btc_headers: headers(&[
        "0080442deb91cd1769c1b30a5f0f8e39b3188b7d25764b2c649d01000000000000000000ea27f92a8040220a755fd7cffd46cf3bc49f0949c5af654868181b1775faf1a6a3d4e56aace5011716112ccd",
        "00a0542effc777bf3460c9a7bf206f887285af856e921854261d00000000000000000000ef70842efe7c8d7d1e9b776143e0a5c89c54d675b289223021c30af73fe996fbf0d4e56aace501171435ea37",
        "00000120fa7ef8e2e146821d9ae0cd257e9d104320d5d4bb7dbf000000000000000000000306720b1a8d83d0ecf78761cbe98ad2d7e27cfde9aa8740076a60eb747cd4f120d6e56aace50117ca338849",
        "00c00c3e9ebe362daff241bfbb750e83d61d1fba30ba6ac70cc801000000000000000000028a147d812ceddd02a609d4d3c4f03ddd29d28a59c35551507332d7807b57d9d2d9e56aace5011738850e03",
        "00e000205f98634509fa173f0d8f6fc83a9872db235b1dee83c1010000000000000000001002691c264843509bffc88eec57d1d2c34b2436ad78ade3dceb35066f3219bfbbdae56aace5011710fb1412",
        "00803626e3331903759ad8ed33b97b3e69e8ea204eabeed7a89701000000000000000000b0b3403c3909455a227c99d5111b09abbf2300121ce8fb76539759cdbdac3931ffdae56aace501178e7e8975",
        ]),
        launchable: true,
    }
}
