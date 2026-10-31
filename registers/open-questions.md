# Open questions

| ID | Question | Blocks | Resolve in |
| --- | --- | --- | --- |
| Q-01 | Independent security review of RandomX v2 (program size 384, CFROUND change). Parameter choice RESOLVED: salt only | ADR-0003 | Before release candidate |
| Q-02 | Is rental-attack exposure acceptable compared with SHA-256d? | ADR-0003 | Phase 3 |
| Q-03 | ~~Block interval, maximum weight, verify_units~~ RESOLVED: 300 s, 720,000, 100 / 1,700 | ADR-0006 | Done |
| Q-04 | ~~ASERT tau~~ RESOLVED: 6 h | ADR-0005 | Done |
| Q-05 | ~~Denomination, initial subsidy, tail~~ RESOLVED: 82 / 6 varve | ADR-0004 | Done |
| Q-06 | Commit–delay–reveal: full design (state, formats, reorgs, sponsorship, spam). DEFERRED, not in v1 | ADR-0009 | post-v1 |
| Q-07 | Multisignature: wait for PQ threshold standards, or allow naive k-of-n? | ADR-0001 | Phase 1 |
| Q-08 | Audited Rust ML-DSA / SLH-DSA implementation suitable for consensus? | ADR-0010 | Phase 1 |
| Q-09 | Mnemonic and backup format: draft in protocol/wallet.md (24 BIP-39 words encode the seed; SHAKE256 derivation; separate recovery seed). Needs wallet/hardware review and vectors | wallet.md | Phase 2 |
| Q-10 | Should consensus reject outputs to already-revealed commitments? (State cost vs. reuse protection) | ADR-0002 | Phase 2 |
| Q-11 | INITIAL_TARGET value and RandomX v2 key-rotation rules | genesis.md, pow.md | Release candidate |
| Q-12 | Fee/security-budget model under low-price scenarios | ADR-0004 | Phase 4b |
| Q-13 | Recovery addresses are ~130 characters, beyond BIP-350's 90 limit: run an interoperability/usability test (libraries, QR, copy errors) before freezing; consider a distinct encoding or compact recovery descriptor (audit M-03) | addresses.md, ADR-0007 | Before address freeze |
| Q-14 | Two-stage recovery (initiate, owner can cancel) instead of direct delayed spend? Stronger, but adds consensus state (audit M-02) | transactions.md §8.1 | Phase 2 |
| Q-15 | Minimum lead time for an emergency tightening (scheme break) | upgrades.md §6 | Before release candidate |
| Q-16 | Should a future extension point allow soft-fork additions (anyone-can-spend style)? Current answer: no (upgrades.md §1) | upgrades.md | Revisit post-v1 |
