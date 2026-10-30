# Open questions

| ID | Question | Blocks | Resolve in |
| --- | --- | --- | --- |
| Q-01 | Is RandomX v2 reviewed, and which parameters are safe to change? | ADR-0003 | Phase 1–3 |
| Q-02 | Is rental-attack exposure acceptable compared with SHA-256d? | ADR-0003 | Phase 3 |
| Q-03 | ~~Block interval, maximum weight, verify_units~~ RESOLVED: 300 s, 720,000, 100 / 1,700 | ADR-0006 | Done |
| Q-04 | ~~ASERT tau~~ RESOLVED: 6 h | ADR-0005 | Done |
| Q-05 | ~~Denomination, initial subsidy, tail~~ RESOLVED: 82 / 6 varve | ADR-0004 | Done |
| Q-06 | Commit–delay–reveal fee sponsorship and spam bounds | ADR-0009 | Phase 2 |
| Q-07 | Multisignature: wait for PQ threshold standards, or allow naive k-of-n? | ADR-0001 | Phase 1 |
| Q-08 | Audited Rust ML-DSA / SLH-DSA implementation suitable for consensus? | ADR-0010 | Phase 1 |
| Q-09 | Mnemonic and backup format for ML-DSA seeds (BIP-39-like or new) | Wallet spec | Phase 2 |
| Q-10 | Should consensus reject outputs to already-revealed commitments? (State cost vs. reuse protection) | ADR-0002 | Phase 2 |
| Q-11 | INITIAL_TARGET value and RandomX v2 key-rotation rules | genesis.md, pow.md | Release candidate |
| Q-12 | Fee/security-budget model under low-price scenarios | ADR-0004 | Phase 4b |
