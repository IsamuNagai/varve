# Decision register

Never reverse a decision silently. Supersede it with a new ADR and update this table.

| ID | Topic | Status | Decision | Dependencies | Revisit trigger |
| --- | --- | --- | --- | --- | --- |
| D-001 | Name | ACCEPTED | Varve (protocol, network, currency) | — | Blocking trademark or domain conflict |
| D-002 | Ticker | ACCEPTED | VARV | D-001 | Exchange symbol conflict |
| D-003 | Smallest unit | ACCEPTED | lamina; 1 varve = 10^8 laminae | ADR-0004 | — |
| D-004 | Author pen name | ACCEPTED | Isamu Nagai | — | Notable collision |
| ADR-0001 | Ledger | ACCEPTED | UTXO with typed outputs, closed policy set | — | Unmet custody need |
| ADR-0002 | Signatures | PROPOSED | ML-DSA-65 primary, SLH-DSA-SHA2-128s recovery, SHA3-256 commitments, 4-state lifecycle | ADR-0001 | Cryptanalysis; FIPS 206 final |
| ADR-0003 | PoW | PROPOSED | RandomX v2 with distinct safe parameters; SHA-256d fallback | ADR-0005 | v2 review; Phase 3 |
| ADR-0004 | Issuance | ACCEPTED (shape) | 8-year half-life smooth decay + fixed tail | ADR-0005 | Phase 4 |
| ADR-0005 | Difficulty | PROPOSED | ASERT, tau ≈ 1 day; median-11; +10 min future limit | ADR-0003 | Phase 4 |
| ADR-0006 | Interval / weight / fees | PROPOSED | 300 s; bytes + verify + UTXO weight; ~60 GB/yr cap; market fees | ADR-0002 | Phase 4 |
| ADR-0007 | Addresses | PROPOSED | Bech32m, prefixes `varve` / `tvarve` / `rvarve` | ADR-0001/2 | Usability study |
| ADR-0008 | Genesis | PROPOSED | Derived from Bitcoin headers H..H+5; unspendable coinbase | ADR-0005 | Phase 3 |
| ADR-0009 | Emergency migration | PROPOSED (sketch) | Commit–delay–reveal | ADR-0002 | Phase 2/3 |
| ADR-0010 | License / language | ACCEPTED / PROPOSED | MIT OR Apache-2.0; Rust leaning | — | Dependency review |
