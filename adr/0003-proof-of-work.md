# ADR-0003: Proof-of-work algorithm

## Status
ACCEPTED for specification v0.1 (2026-10-30). Confidence: LOW–MEDIUM. To be
re-examined in the Phase 3 threat model and before the release candidate.

## Context
New units enter circulation through open computational competition. No PoW
algorithm makes a small new chain secure against an attacker with access to
large external hashrate. The choice decides who can cheaply attack the chain
and who can take part in mining.

## Requirements
- An established, audited algorithm; nothing invented.
- A reduced advantage for specialized hardware, without claiming ASIC resistance.
- Verification feasible on commodity hardware.
- An identical implementation for every participant, including the author.

## Evidence (accessed 2026-10-30)
- RandomX was audited four times in 2019 (Trail of Bits, Kudelski, X41,
  Quarkslab). No algorithmic shortcut was found.
- RandomX v2:
  - 384-instruction programs instead of 256;
  - rarer CFROUND rounding changes;
  - about 53% more work per hash.
  - The reference implementation added it in release v2.0 (25 March 2026).
  - v2.0.1 (10 May 2026) fixed rare invalid hashes on ARM and RISC-V.
  - Monero has scheduled it on testnet; it has no mainnet date.
- Community benchmarks of RandomX v2 show CPUs doing about 14–57% more work
  per joule than with v1.
- Specialized hardware:
  - Bitmain Antminer X5: about 6.4 J/kH (RandomX v1).
  - The announced X9 (about 2.5 J/kH) was withdrawn before shipping.
  - Efficient CPUs on v1 reach about 3.6 J/kH (Zen 5 laptop) to about 10 J/kH
    (Zen 2 desktop).
  - So the specialized-hardware advantage is roughly 1–4×, compared with
    roughly 10^6× for SHA-256d.
- RandomX's configuration guide recommends a unique configuration per
  project, to prevent hashpower-rental attacks. It also says every
  implementation should choose a unique salt.

## Options
| Option | Participation | Rental / redirect risk on a small chain | Verification cost | Maturity |
| --- | --- | --- | --- | --- |
| **RandomX v2, Varve salt** | CPUs; specialized hardware ~1–4× | Moderate: rental needs a custom configuration | 256 MiB light mode, ms per hash | Audited core; v2 is new |
| SHA-256d | ASIC only | Extreme: idle Bitcoin hardware | Trivial | 17 years |
| Equi-X / HashX | CPUs | Moderate | Light | Not used for money |
| KawPow | GPUs | High | Moderate | Production |
| Novel algorithm | Unknown | Low at first | Unknown | None |

## Decision
**RandomX v2 with `RANDOMX_ARGON_SALT = "VarveRX\x01"` and every other
parameter at its v2 default** (protocol/pow.md). The key rotates every 2,048
blocks with a 64-block lag. SHA-256d stays the documented fallback. Merge-mining
is excluded.

Changing only the salt is the most conservative way to become distinct:

- The audited program generator and VM are untouched.
- Existing optimized open-source miners need only a configuration change.
- Monero pools and rental capacity cannot be pointed at Varve without
  deliberate reconfiguration.

Test vectors were generated and cross-checked between the interpreter and the
JIT (test-vectors/pow.json).

## Security implications
- The botnet and malware incentive is real for CPU-friendly PoW (threat T-M3).
- Specialized hardware exists. Its advantage is modest today and may grow (T-M4).
- Day-one hashrate rental and selfish mining remain the dominant early risk
  (T-C1, T-M1). Monero suffered 6- and 18-block reorganizations in 2025.
- Implementation risk: RandomX v2 is newer than v1. The ARM/RISC-V bug fixed
  in v2.0.1 shows that cross-platform consistency must be tested. Nodes must
  run the pow.json vectors on every platform they support.
- C++ dependency: the reference node must isolate it behind a narrow, fuzzed
  boundary (ADR-0010).

## Tradeoffs
Header verification is heavier than with SHA-256d: about 256 MiB of memory and
milliseconds per header. Light clients and phones pay the most.

## Rejected alternatives
- **SHA-256d:** a negligible slice of Bitcoin hashrate could overwhelm a new chain.
- **Novel algorithm:** unaudited, and it invites private optimization.
- **KawPow:** no fairness gain.
- **Merge-mining:** it couples security to another chain's miners.
- **Further RandomX parameter changes:** they leave the audited configuration
  for little extra benefit.

## Dependencies
protocol/pow.md, protocol/blocks.md, ADR-0005, ADR-0008, threat model T-C1,
T-M1–T-M4.

## Revisit trigger
- An independent review of RandomX v2 finds an algorithmic shortcut.
- Specialized hardware exceeds about 5× the per-joule efficiency of
  contemporary CPUs on RandomX v2.
- Monero changes RandomX again for security reasons.
- The Phase 3 rental-attack analysis favours another option.
