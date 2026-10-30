# Varve: Long-Horizon Proof-of-Work Money with Post-Quantum Ownership

**Isamu Nagai**

*Draft 0.1 (specification phase). Not a final design. Every parameter may change before mainnet.*

---

## Abstract

Varve is a proposal for peer-to-peer electronic money designed to remain
verifiable and spendable over decades of cryptographic change. New units enter
circulation only through proof of work. Ownership is authorized by standardized
post-quantum signatures from the first block. Every output records which
signature scheme protects it, so schemes can be added, deprecated, and retired
by deliberate consensus upgrades without restarting the chain. Outputs may
carry a timelocked recovery path under an independent hash-based scheme.
Issuance follows a fixed, smooth schedule ending in a small permanent tail.
There is no premine, no allocation, and no privileged party. Genesis is derived
from a future Bitcoin block header, so no one can begin mining early.

Labels used in this paper: **[FACT]** externally verifiable statement;
**[DESIGN]** a decision of this protocol; **[ASSUMPTION]** something the design
relies on but cannot prove; **[OPEN]** unresolved.

## 1. Problem

[FACT] Bitcoin showed that a scarce digital asset can be issued and transferred
without a trusted party. Its signatures (ECDSA and Schnorr over secp256k1) are
believed secure against classical computers, but would be broken by a
sufficiently large quantum computer running Shor's algorithm.

[FACT] In 2024, NIST published final standards for post-quantum signatures:
ML-DSA (FIPS 204, lattice-based) and SLH-DSA (FIPS 205, hash-based).

[FACT] Bitcoin developers have proposed post-quantum output types and migration
plans (BIP-360, BIP-361, and hash-based signature drafts). As of late 2026,
none has an activation schedule.

[ASSUMPTION] Migrating an existing monetary network away from a broken
signature scheme is a social problem as much as a technical one. Coins whose
owners never migrate force a choice between freezing them and letting them be stolen.

This paper does **not** claim that quantum computers will break existing
networks soon. Timelines are uncertain. The question is narrower: *if neutral
digital money were designed today for a 50 to 100 year horizon, how should it
handle the certainty that cryptographic assumptions change?*

## 2. Design principles

In priority order: correctness, security, simplicity, cryptographic
adaptability, independent verification, decentralization, predictable monetary
rules, permissionless participation, long-term maintainability, and performance.

Consequences:

- [DESIGN] No general smart-contract virtual machine, token platform, or
  on-chain governance. Every consensus feature is permanent attack surface.
- [DESIGN] Throughput is limited by what an ordinary computer can verify, not by demand.
- [DESIGN] No component may require the author's continued participation.

## 3. Transaction model

[DESIGN] Varve uses unspent transaction outputs (UTXOs). Each output is typed:

    amount (u64 laminae) | output_version (u8) | policy (u8) |
    scheme_id (u16) | commitment (32 bytes) | [recovery fields]

The **commitment** is a domain-separated SHA3-256 hash of the scheme id and the
public key. Public keys appear on chain only when an output is spent.

Two policies exist at launch:

1. **Single authorization:** a valid signature under `scheme_id` for the committed key.
2. **Primary or recovery:** either the primary signature, or, after a relative
   delay of `recovery_delay` blocks since the output confirmed, a signature
   under the independent recovery scheme and key.

[DESIGN] There is no script language. New policies require a soft fork. The
policy set covers the main long-term custody needs, such as inheritance,
disaster recovery, and dormant cold storage. Consensus knows nothing about
heirs or deaths; it evaluates only signatures, paths, and block heights.

[DESIGN] Amounts are 64-bit unsigned integers in laminae; 1 varve = 10^8 laminae.
All consensus arithmetic is checked integer arithmetic. Any overflow invalidates.

## 4. Proof of work

[DESIGN] Blocks are produced by proof of work, so new units are distributed to
whoever contributes computation, not to existing holders.

[FACT] No proof-of-work algorithm prevents specialized hardware. RandomX was
designed for general-purpose CPUs and was audited four times in 2019, but a
commercial RandomX ASIC now exists. RandomX v2 was released in 2026 in response.

[DESIGN, provisional] The working choice is RandomX v2 with a Varve-specific
parameter set restricted to parameters classified as safe by its audits. The
fallback is SHA-256d. This choice is reviewed after the threat-model phase.

[FACT] A small proof-of-work chain is vulnerable to anyone who can rent or
redirect hashrate exceeding its honest total. Monero, a far larger network,
experienced 6- and 18-block reorganizations in 2025 driven by a single mining
operation. Varve will be weakest when it is youngest. Recipients of large
payments should wait for many confirmations in the early years.

Difficulty adjusts every block using ASERT (absolutely scheduled exponentially
rising targets) with a six-hour half-life. Because ASERT is anchored to a fixed reference block, it has
no adjustment window to exploit. It recovers from sudden hashrate departures in
hours rather than weeks.

## 5. Post-quantum authorization

[DESIGN, proposed] Two schemes are active at genesis:

| scheme_id | Scheme | Public key | Signature | Assumption | Role |
| --- | --- | --- | --- | --- | --- |
| 0x0001 | ML-DSA-65 (FIPS 204) | 1,952 B | 3,309 B | Module lattices (MLWE/MSIS) | Everyday spending |
| 0x0002 | SLH-DSA-SHA2-128s (FIPS 205) | 32 B | 7,856 B | Hash functions only | Recovery, long-term storage |

[ASSUMPTION] The two families fail independently: a break of lattice problems
does not imply a break of SHA-2, and vice versa.

The cost is size. A typical one-input, two-output ML-DSA-65 transaction is
about 5.4 KB, against roughly 0.2 KB for a Bitcoin Taproot transaction.
[DESIGN] Varve accepts lower throughput rather than weaker assumptions or
unstandardized cryptography.

[DESIGN] Transaction weight counts serialized bytes, a verification cost per
signature, and net growth of the UTXO set. A block of expensive-to-verify
signatures therefore cannot exceed the time budget of a block of cheap ones.

[DESIGN] Blocks target 300 seconds. The maximum block weight is 720,000, which
is about 76 GB of chain growth per year at sustained full blocks. Measured
verification times set the weights: about 30 µs per ML-DSA-65 signature and
about 0.6 ms per SLH-DSA-SHA2-128s signature on one 2.1 GHz core. A full block
verifies in under 50 ms in the worst case.

## 6. Cryptographic agility

Each scheme id has a consensus state:

| State | New outputs | Spending |
| --- | --- | --- |
| ACTIVE | allowed | allowed |
| NO_NEW_OUTPUTS | rejected | allowed |
| SPEND_VIA_COMMITMENT | rejected | only through commit–delay–reveal |
| DISABLED | rejected | only through an output's recovery path |

[DESIGN] Transitions happen only by soft fork at a fixed height, are
one-directional, and are never triggered automatically by an oracle. An output
can only be spent under the scheme it committed to, so downgrade is impossible
by construction. Future standardized schemes enter as new scheme ids, without
new currency, without restarting the chain, and without touching existing outputs.

**What agility can and cannot do.**

- *Gradual weakening:* stop new outputs under the weakened scheme and let users
  move funds at leisure. No losses.
- *Practical break:* unspent outputs whose public keys were never revealed
  remain protected by their hash commitments, but spending reveals the key and
  invites a race. [DESIGN, sketch] **Commit–delay–reveal** addresses this.
  1. The owner first publishes a hash binding the outpoint, the key, and the
     destination, paid from a safe output.
  2. After a delay, the owner reveals and spends.
  3. Consensus accepts only spends that match the earliest buried commitment.
- *Outputs with a recovery path* can be moved under the independent hash-based
  scheme without any race.
- *Cannot be solved:* outputs whose keys are already public through address
  reuse, owners who neither migrate nor added a recovery path, and simultaneous
  breaks of both families. Agility reduces these risks; it does not remove them.

## 7. Monetary issuance

[DESIGN] The block subsidy decays smoothly with an eight-year half-life until it
reaches a fixed tail. From then on it is constant forever. It is computed from
block height using an integer lookup table fixed in consensus.

Normalized supply (100 = what an equivalent hard-capped, four-year-halving
schedule would ever issue):

| Year | 1 | 4 | 10 | 20 | 50 | 100 |
| --- | --- | --- | --- | --- | --- | --- |
| Supply | 8.3 | 29.3 | 58.0 | 82.3 | 104.6 | 134.6 |
| Annual inflation | — | 28.0% | 7.0% | 2.0% | 0.58% | 0.45% |

Reasons:

1. **Fairer early distribution.** A four-year-halving schedule issues 12.5% of
   its total in the first year, when the network is smallest and least
   decentralized. This schedule issues 8.3%.
2. **A permanent security budget.** Under a hard cap, miner revenue eventually
   depends entirely on fees. A fixed absolute tail keeps mining funded while
   inflation tends toward zero, and it offsets coins lost over time.

[OPEN] The absolute numbers (denomination, initial subsidy, tail size) are
set after fee and security modelling. Denomination is cosmetic; the shape of
distribution is not.

Fees are paid to miners in full. There are no burns, developer fees, or taxes.

## 8. Network

[DESIGN] Nodes discover peers through hard-coded fallback addresses, DNS seeds
run by independent operators, and peer exchange. None of these is consensus
infrastructure. Nodes keep diverse outbound connections to resist eclipse
attacks, and check every message's size before allocating memory for it. Tor
and IPv6 are supported. Software never updates itself automatically.

## 9. Fair launch

[DESIGN, proposed] Nobody, including the author, receives coins except by
mining under the same rules as everyone else.

1. The specification, source code, wallet, and **the exact mining software the
   author will use** are published weeks in advance. Builds are reproducible,
   and at least two independent builders must match.
2. A public release-candidate testnet rehearses the launch procedure.
3. Consensus parameters are frozen, and a future Bitcoin block height H is announced.
4. Genesis is defined as a hash over a domain tag, a commitment to all
   consensus parameters, and Bitcoin block header H. Nodes accept headers H
   through H+5 from any source and verify their proof of work and linkage.
   Until that block exists, nobody can know the genesis hash or mine block 1.
5. The genesis coinbase is unspendable, and genesis contains nothing else.

After genesis, Varve never consults Bitcoin again.

## 10. Security considerations

The main risks, in rough order of likelihood:

1. **Low hashrate.** Deep reorganizations and double spends by rented or
   redirected hashrate, especially in the first years.
2. **No adoption.** Without users, the chain cannot fund its own security.
3. **Consensus bugs.** Mitigated by specification-first development, test
   vectors, fuzzing, and independent review.
4. **Signature implementation flaws.** Side channels, faults, and weak
   randomness. Mitigated by using only audited implementations and hedged signing.
5. **Specialized hardware and botnets.** Both can concentrate mining.
6. **Chain growth.** It must not price out independent verification.
7. **Social capture.** A founder cult, a dominant implementation, or a
   contested emergency fork after a cryptographic break.

AI-assisted analysis contributed to this draft. It is not a security audit.
Mainnet requires independent human review.

## 11. Limitations

- Throughput is low by design, about 0.4 transactions per second at full
  blocks. Varve is a settlement layer.
- Transactions are large compared with elliptic-curve systems.
- There is no multisignature at launch; post-quantum threshold signatures are immature.
- No public key derivation, so watch-only wallets need exported commitments.
- The proof-of-work choice is provisional and every option has serious drawbacks.
- If Bitcoin completes a post-quantum migration, Varve's remaining distinction
  is narrower: no legacy elliptic-curve outputs, built-in agility and recovery,
  and a launch with no allocation.

## 12. Launch criteria

Mainnet launches only if all of the following hold:

- The specification lets two independent teams build compatible nodes without
  asking what a rule means.
- Public adversarial testnets have run without unresolved critical findings.
- Independent reviews of cryptography, consensus, networking, and wallet code
  are complete, with all critical and high findings resolved.
- Reproducible builds match across independent builders.

If these cannot be met, Varve does not launch. Time already invested is not a
reason to launch.

---

*Varve is open source under MIT or Apache-2.0. Isamu Nagai is a pen name and
does not refer to any real person.*

## References

1. S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008.
2. NIST, FIPS 204: Module-Lattice-Based Digital Signature Standard, 2024.
3. NIST, FIPS 205: Stateless Hash-Based Digital Signature Standard, 2024.
4. NIST, IR 8610: Status Report on the Second Round of the Additional Digital Signature Schemes, 2026.
5. BIP-350: Bech32m format for v1+ witness addresses.
6. BIP-360 (Pay to Merkle Root) and BIP-361 (Post Quantum Migration and Legacy Signature Sunset), drafts.
7. tevador et al., RandomX specification; OSTIF, "Four audits of RandomX," 2019.
8. Bitcoin Cash, aserti3-2d difficulty adjustment specification, 2020.
