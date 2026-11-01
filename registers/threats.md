# Threat model (living document, v0.2)

Likelihood and impact: L = low, M = medium, H = high. The Test column names the suite that exercises each mitigation today, or what is still missing. Battle tests: `battle/`; fuzzing: `node/crates/varve-fuzz`.

| ID | Threat | Attacker | Prerequisites | Likelihood | Impact | Mitigation | Residual | Test |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-C1 | 51% / deep reorg double-spend | Hashrate renter, large pool | Hashrate above honest total | H (years 1–3) | H | Confirmation guidance, reorg monitoring, honest messaging | H early | Battle tests (private-chain double spend, 20-block reorg); reorg monitoring still to build |
| T-C2 | Selfish mining | Pool with ≥25–33% | Good connectivity | M | M | Fast block relay; monitoring | M | Network simulation |
| T-C3 | Timestamp / difficulty manipulation | Miner | Mining share | M | L | ASERT (tau 6 h), median-11, +10 min acceptance limit; simulated effect +0.05% | L | test-vectors/difficulty.json |
| T-N1 | Eclipse attack | Network adversary | Many IPs | M | H | Done: at most one outbound peer per network group, chosen at random; at most 8 inbound per group. Pending: address manager buckets, anchor connections | M | Network-group unit tests; flood and eclipse testing still to do |
| T-N2 | DoS via malformed or oversized messages | Anyone | None | H | M | Bounded parsing, size limits before allocation, bans for invalid data | L | Continuous fuzzing of every parser (every change + nightly); battle tests |
| T-T1 | Verification-cost DoS (SLH-DSA-heavy blocks) | Miner or spammer | Fees | M | M | verify_units in weight (ADR-0006); per-peer verification-cost token buckets; disconnect peers relaying invalid signatures (p2p.md §8) | L | Benchmark vectors; battle test (invalid-signature relay) |
| T-T2 | Transaction malleability | Relay node | None | L | M | Txid excludes witness; canonical encodings only; shared witness mandatory where it applies, so each transaction has one witness layout (transactions.md §8.2) | L | Encoding and chain vectors; fuzzing checks every parse re-encodes byte for byte |
| T-T3 | Cross-network replay | Anyone | Testnet/mainnet keys | L | M | Network id in signature hash | L | Signature-hash vectors |
| T-K1 | ML-DSA cryptanalytic weakening | Researchers, states | Breakthrough | L–M | H | Lifecycle, commitments, recovery path (ADR-0009 deferred, not relied on) | L–M | — |
| T-K2 | Implementation flaw (side channel, fault, bad RNG) | Local attacker, malware | Device access | M | H | Pinned liboqs, hedged signing, constant-time review | M | NIST ACVP and RFC vectors on every platform in CI (they caught an MSVC miscompilation of SLH-DSA; Windows now builds liboqs with clang-cl) |
| T-K3 | Public key exposure via address reuse | Future quantum attacker | Reuse | M | M | Wallets never reuse addresses; documentation | M | Wallet tests |
| T-W1 | Seed theft or clipboard replacement | Malware | Infected device | H | H | Strata shows a full review (recipient, amount, fee, change) before signing; keys never reach the browser page; offline signing pending | M | Strata unit, end-to-end and browser tests |
| T-W2 | Recovery-path misuse (early recovery claim) | Heir or thief holding the recovery key | Recovery key | M | H | Relative delay; wallet refresh + alerts; documented as delayed alternate authorization, not revocation (transactions.md §8.1) | M | chain.json recovery-boundary cases |
| T-M1 | Day-one hashrate rental | Well-funded party | Market liquidity | H | H | None technical; launch messaging | H | — |
| T-M2 | Private miner optimization by the author | Author | Secrecy | L | H | Publish exact miner; delay launch if an optimization is found | L | Public benchmarks |
| T-M3 | Botnet mining | Criminals | CPU-friendly PoW | H | M | None technical | M | — |
| T-M4 | Specialized RandomX hardware | Manufacturers | Profit | H | M | Honest claims; review triggers in ADR-0003 | M | — |
| T-S1 | Malicious dependency | Supply-chain attacker | Upstream compromise | M | H | Pinned lockfiles and C library commits, pinned CI actions, no crates.io dependencies; SBOM pending | M | CI checks pins; secret and history scan |
| T-S2 | Fake releases or fake official sites | Scammers | None | H | M | Reproducible builds, multiple signers, scam warnings | M | — |
| T-G1 | Founder cult or repository capture | Social | Popularity | M | H | Multiple maintainers, authoritative spec, founder minimization | M | — |
| T-G2 | Contested emergency fork | Community split | Crypto break | L | H | Lifecycle rules published before any crisis | M | — |
| T-G3 | Author deanonymization leading to coercion | Investigators, criminals | Metadata leaks | M | H | No personal data in repo; metadata hygiene; author irrelevance by design | M | `tools/check-no-secrets.sh` |
| T-L1 | Early genesis computation (head start) | Anyone with modified software | First draft hashed only Bitcoin header H | — | H | FIXED: seed covers H..H+5; only the miner of H+5 could gain minutes, by withholding a Bitcoin block | L | prototype Genesis tests |
| T-L2 | Competing genesis via forged or reorganized Bitcoin headers | Large Bitcoin miner, eclipse attacker | Relaxed difficulty floor, or 6+ block Bitcoin reorg | L | H | Exact nBits required; compare sources; wait 6 extra confirmations; release records genesis id | L | Genesis vectors (at freeze) |
| T-N3 | Low-work fork flood (resource exhaustion) | Anyone | ASERT eases far-behind forks | M | M | POW_LIMIT = INITIAL_TARGET × 256; headers-first work gate; cache budget; ban invalid PoW | L | Chain unit tests; battle tests (invalid block deep in a longer chain) |
| T-C4 | Network split via ambiguous median timestamp | Miner | Even-count median undefined | — | H | FIXED: upper median defined normatively | L | prototype MTP test |
| T-W3 | Theft of a wallet file or a server | Malware, intruder | File or machine access | M | H | Wallet files (node and Strata) encrypted: Argon2id, AES-256-CTR, HMAC-SHA256; node keys decrypted only while signing; servers mine to an address with no keys on the machine | M (offline passphrase guessing) | Wallet unit tests; wallet-file fuzzing (modified files never decrypt) |
| T-W4 | A web page attacks the local Strata wallet (DNS rebinding, cross-site requests) | Malicious website | User runs Strata | M | H | Loopback only; exact Host and Origin checks; per-session token; JSON-only requests; strict CSP | L | Strata unit and end-to-end tests |
| T-S3 | Platform-specific miscompilation of cryptography | Compiler bug | Release built on that platform | L | H | Same official test vectors on every platform before any release | L | CI on Windows, macOS, Linux x86-64 and ARM64 |
| T-L3 | Easy-block burst when a network starts long after its genesis anchor | First miners | Late start | — | L (testnet) | ASERT starts 2 h after genesis (difficulty.md §2.1); mainnet procedure starts mining inside that window. The testnet starts days after its anchor, so its first blocks are easy until the chain catches up (no value at stake) | L | Difficulty vectors |
