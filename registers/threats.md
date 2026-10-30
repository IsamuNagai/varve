# Threat model (living document, v0.1)

Likelihood and impact: L = low, M = medium, H = high. Tests refer to future test suites.

| ID | Threat | Attacker | Prerequisites | Likelihood | Impact | Mitigation | Residual | Test |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-C1 | 51% / deep reorg double-spend | Hashrate renter, large pool | Hashrate above honest total | H (years 1–3) | H | Confirmation guidance, reorg monitoring, honest messaging | H early | Reorg simulation |
| T-C2 | Selfish mining | Pool with ≥25–33% | Good connectivity | M | M | Fast block relay; monitoring | M | Network simulation |
| T-C3 | Timestamp / difficulty manipulation | Miner | Mining share | M | L | ASERT, median-11, +10 min limit | L | Difficulty vectors |
| T-N1 | Eclipse attack | Network adversary | Many IPs | M | H | Outbound diversity, anchor connections, address bucketing | M | P2P test |
| T-N2 | DoS via malformed or oversized messages | Anyone | None | H | M | Bounded parsing, size limits before allocation, ban scores | L | Fuzzing |
| T-T1 | Verification-cost DoS (SLH-DSA-heavy blocks) | Miner or spammer | Fees | M | M | verify_units in weight (ADR-0006) | L | Benchmark vectors |
| T-T2 | Transaction malleability | Relay node | None | L | M | Txid excludes witness; canonical encodings only | L | Encoding vectors |
| T-T3 | Cross-network replay | Anyone | Testnet/mainnet keys | L | M | Network id in signature hash | L | Signature-hash vectors |
| T-K1 | ML-DSA cryptanalytic weakening | Researchers, states | Breakthrough | L–M | H | Lifecycle, commitments, recovery path, ADR-0009 | L–M | — |
| T-K2 | Implementation flaw (side channel, fault, bad RNG) | Local attacker, malware | Device access | M | H | Audited libraries, hedged signing, constant-time review | M | KAT and fault tests |
| T-K3 | Public key exposure via address reuse | Future quantum attacker | Reuse | M | M | Wallets never reuse addresses; documentation | M | Wallet tests |
| T-W1 | Seed theft or clipboard replacement | Malware | Infected device | H | H | Address verification UX, offline signing | M | — |
| T-W2 | Recovery-path misuse (early recovery claim) | Heir or thief holding the recovery key | Recovery key | M | H | Relative delay; wallet alerts on recovery-path activity | M | Policy tests |
| T-M1 | Day-one hashrate rental | Well-funded party | Market liquidity | H | H | None technical; launch messaging | H | — |
| T-M2 | Private miner optimization by the author | Author | Secrecy | L | H | Publish exact miner; delay launch if an optimization is found | L | Public benchmarks |
| T-M3 | Botnet mining | Criminals | CPU-friendly PoW | H | M | None technical | M | — |
| T-M4 | Specialized RandomX hardware | Manufacturers | Profit | H | M | Honest claims; review triggers in ADR-0003 | M | — |
| T-S1 | Malicious dependency | Supply-chain attacker | Upstream compromise | M | H | Pinned lockfiles, minimal dependencies, review, SBOM | M | CI audit |
| T-S2 | Fake releases or fake official sites | Scammers | None | H | M | Reproducible builds, multiple signers, scam warnings | M | — |
| T-G1 | Founder cult or repository capture | Social | Popularity | M | H | Multiple maintainers, authoritative spec, founder minimization | M | — |
| T-G2 | Contested emergency fork | Community split | Crypto break | L | H | Lifecycle rules published before any crisis | M | — |
| T-G3 | Author deanonymization leading to coercion | Investigators, criminals | Metadata leaks | M | H | No personal data in repo; metadata hygiene; author irrelevance by design | M | `tools/check-no-secrets.sh` |
