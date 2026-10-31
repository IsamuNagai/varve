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
| ADR-0003 | PoW | ACCEPTED (spec v0.1, low–medium confidence) | RandomX v2, salt "VarveRX\x01", key every 2,048 blocks (lag 64); SHA-256d fallback | ADR-0005 | v2 review; hardware > 5× CPU efficiency; Phase 3 |
| ADR-0004 | Issuance | ACCEPTED (spec v0.1) | 82 varve initial, 8-year half-life in 64 exact epochs/half-life, 6 varve tail from ~year 30 | ADR-0006 | Fee/security model |
| ADR-0005 | Difficulty | ACCEPTED (spec v0.1) | aserti3-2d, tau 6 h; median-11; +10 min acceptance limit | ADR-0003 | Testnet hashrate data |
| ADR-0006 | Interval / weight / fees | ACCEPTED (spec v0.1) | 300 s; max weight 720,000 (75.7 GB/yr, ~0.43 tx/s); verify units 100 / 1,700 | ADR-0002 | Testnet propagation |
| ADR-0007 | Addresses | PROPOSED | Bech32m, prefixes `varve` / `tvarve` / `rvarve` | ADR-0001/2 | Usability study |
| ADR-0008 | Genesis | PROPOSED (revised after review) | Seed over all six Bitcoin headers H..H+5 with exact nBits; t0 = median; unspendable coinbase | ADR-0005 | Phase 3 |
| ADR-0009 | Emergency migration | DEFERRED (not in v1) | Commit–delay–reveal, research only | ADR-0002 | post-v1 |
| ADR-0010 | License / language | ACCEPTED / PROPOSED | MIT OR Apache-2.0; Rust leaning | — | Dependency review |
