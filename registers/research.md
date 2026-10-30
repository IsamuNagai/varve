# Research register

Sources accessed 2026-10-30 unless noted. Secondary reports must be replaced
with primary sources before an ADR moves to ACCEPTED.

| Topic | Source | Conclusion | Confidence | Likely to change | Used by |
| --- | --- | --- | --- | --- | --- |
| ML-DSA / SLH-DSA | NIST FIPS 204, FIPS 205 (Aug 2024) | Final; parameter sizes as in ADR-0002 | High | No | ADR-0002 |
| FN-DSA | NIST pqc-forum; industry summaries | FIPS 206 still draft as of Aug 2026 | High | Yes | ADR-0002 |
| Additional signatures | NIST IR 8610 and NIST news (May 2026, updated Jul 2026) | 9 candidates in round 3; HAWK withdrawn Jul 2026 | High | Yes | ADR-0002 |
| Bitcoin PQ proposals | BIP-360 (P2MR), BIP-361 (draft), SHRINCS draft BIP (Aug 2026) | All draft; no activation scheduled | High | Yes | Existence test |
| Quantus | News coverage; tokenomics summaries | PoW + ML-DSA mainnet Sep 2026; 27% genesis allocation | Medium | Yes | Competitor analysis |
| QRL | theqrl.org roadmap | XMSS + RandomX legacy chain; moving to PoS with ML-DSA-87 | Medium | Yes | Competitor analysis |
| Abelian | CoinDesk asset page | GPU PoW, lattice privacy, 9.14% premine | Medium | Low | Competitor analysis |
| RandomX audits | OSTIF report (2019) | 4 audits; safe-parameter guidance from Trail of Bits | High | No | ADR-0003 |
| RandomX hardware | Pool documentation; news (2026) | Commercial RandomX ASIC shipping; RandomX v2 released Mar 2026 | Medium | Yes | ADR-0003 |
| Hashrate attacks | Decrypt, The Block (2025) | Qubic-linked 6- and 18-block Monero reorgs | High | No | ADR-0003, T-C1 |
| ASERT | Bitcoin Cash aserti3-2d (Nov 2020) | In production since 2020 | High | No | ADR-0005 |
| Bech32m | BIP-350 | Mature checksum; 90-character limit | High | No | ADR-0007 |
| PQ signature speed | liboqs speed_sig, own run (simulations/benchmarks) | ML-DSA-65 verify ~30 µs; SLH-DSA-128s verify ~0.6 ms, sign ~0.55 s | High (one machine) | Low | ADR-0006 |
| RandomX v2 | tevador/RandomX releases and doc/configuration.md; benchmark gist | v2.0 released 25 Mar 2026, v2.0.1 fixes rare ARM/RISC-V invalid hashes; salt change recommended per project | High | Yes | ADR-0003 |
| RandomX hardware market | OneMiners report (Oct 2026); pool documentation | X5 ~6.4 J/kH; X9 (~2.5 J/kH) withdrawn; RandomX v2 not on Monero mainnet | Medium (secondary) | Yes | ADR-0003 |
| Spec v0.1 review | Independent adversarial review agent (2026-10-30) | 1 critical, 3 high, 13 medium/low findings; all addressed in spec v0.2 | High | No | All protocol/*.md |
