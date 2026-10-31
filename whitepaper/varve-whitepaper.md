# Varve: Long-Horizon Proof-of-Work Money with Post-Quantum Ownership

**Isamu Nagai**

*Draft 0.3 (specification and testnet phase). Parameters may still change before mainnet.*

---

## Abstract

Varve is peer-to-peer electronic money built to stay secure, verifiable and
spendable for a century, through whatever cryptographic change that century
brings. New units enter circulation only through proof of work. Ownership is
protected by standardized post-quantum signatures from the very first block,
so there are no legacy elliptic-curve coins to migrate, ever. Every output
records which signature scheme protects it, so schemes can be added, retired
or replaced by deliberate upgrades without restarting the chain or touching
existing coins. Outputs can carry a timelocked recovery path under an
independent, hash-based scheme. Issuance follows a fixed, smooth schedule
ending in a small permanent tail that funds security forever. There is no
premine, no allocation and no privileged party: genesis is derived from six
future Bitcoin blocks, so nobody, not even the author, can start mining early.

Labels used in this paper: **[FACT]** externally verifiable statement;
**[DESIGN]** a decision of this protocol; **[ASSUMPTION]** something the design
relies on but cannot prove; **[OPEN]** unresolved.

## 1. Why Varve

[FACT] Bitcoin proved that scarce digital money can exist without a trusted
party. Its signatures (ECDSA and Schnorr over secp256k1) are secure against
today's computers, but a sufficiently large quantum computer running Shor's
algorithm would break them, and with them the ownership of every coin whose
public key is visible.

[FACT] In 2024 NIST finalized the first post-quantum signature standards:
ML-DSA (FIPS 204, lattice-based) and SLH-DSA (FIPS 205, hash-based).

[FACT] Bitcoin developers have drafted post-quantum output types and migration
plans (BIP-360, BIP-361, hash-based signature proposals). As of late 2026 none
has an activation schedule.

[ASSUMPTION] Moving an existing monetary network off a broken signature scheme
is as much a social problem as a technical one. Coins whose owners never move
force a choice between freezing them and letting them be stolen.

Nobody knows when, or whether, a cryptographically relevant quantum computer
will arrive, and this paper does not pretend to. Varve starts from a simpler
observation: money meant to be held for decades should not depend on any single
cryptographic assumption lasting forever. *If neutral digital money were
designed today for a 50 to 100 year horizon, what would it look like?* Varve is
one serious answer: quantum-resistant from genesis, able to change its
cryptography without a restart, and launched so fairly that no one starts ahead.

## 2. Design principles

In priority order: correctness, security, simplicity, cryptographic
adaptability, independent verification, decentralization, predictable monetary
rules, permissionless participation, long-term maintainability, and performance.

Consequences:

- [DESIGN] No general smart-contract virtual machine, token platform, or
  on-chain governance. Every consensus feature is permanent attack surface,
  and money that must last a century should have very little of it.
- [DESIGN] Throughput is limited by what an ordinary computer can verify, not by
  demand, so anyone can check the whole chain themselves.
- [DESIGN] No component may require the author's continued participation.

## 3. Transaction model

[DESIGN] Varve uses unspent transaction outputs (UTXOs). Each output is typed:

    amount (u64 laminae) | output_version (u8) | policy (u8) |
    scheme_id (u16) | commitment (32 bytes) | [recovery fields]

The **commitment** is a domain-separated SHA3-256 hash of the scheme id and the
public key. Public keys appear on chain only when an output is spent, so an
unspent coin is protected by a hash even if its signature scheme weakens.

Two policies exist at launch:

1. **Single authorization:** a valid signature under `scheme_id` for the committed key.
2. **Primary or recovery:** either the primary signature, or, after a relative
   delay of `recovery_delay` blocks since the output confirmed, a signature
   under the independent recovery scheme and key.

[DESIGN] There is no script language. New policies require a coordinated
upgrade of all nodes (a hard fork), because unknown policies are invalid rather
than anyone-can-spend. The two policies cover the main long-term custody needs:
inheritance, disaster recovery and dormant cold storage. Consensus knows nothing
about heirs or deaths; it evaluates only signatures, paths and block heights.
After its delay, a recovery key is a second owner, not a revocation switch: it
must be trusted like the primary key.

[DESIGN] Amounts are 64-bit unsigned integers in laminae; 1 varve = 10^8 laminae.
All consensus arithmetic is checked integer arithmetic. Any overflow invalidates.

## 4. Proof of work

[DESIGN] Blocks are produced by proof of work, so new units go to whoever
contributes computation, not to existing holders or insiders.

[FACT] No proof-of-work algorithm prevents specialized hardware forever. RandomX
was designed for general-purpose CPUs and was audited four times in 2019; a
commercial RandomX ASIC now exists, and RandomX v2 was released in 2026 in
response.

[DESIGN] Varve uses RandomX v2 with every audited default unchanged except its
salt, set to a Varve-specific value, exactly as the RandomX authors recommend
for new chains, so existing rented hashrate and pools cannot simply be pointed
at Varve. Specialized RandomX hardware has so far been roughly 1–4× as
efficient as good CPUs, against roughly a million-fold for SHA-256 ASICs, so an
ordinary computer can still mine meaningfully. SHA-256d remains the documented
fallback.

[FACT] A small proof-of-work chain is vulnerable to anyone who can rent or
redirect more hashrate than its honest total. Monero, a far larger network,
saw 6- and 18-block reorganizations in 2025 driven by a single mining
operation. Varve will be weakest when it is youngest; recipients of large
payments should wait for many confirmations in the early years.

Difficulty adjusts every block using ASERT (absolutely scheduled exponentially
rising targets) with a six-hour half-life. Anchored to genesis, it has no
adjustment window to exploit and recovers from sudden hashrate departures in
hours rather than weeks.

## 5. Post-quantum authorization

[DESIGN] Two schemes are active at genesis:

| scheme_id | Scheme | Public key | Signature | Assumption | Role |
| --- | --- | --- | --- | --- | --- |
| 0x0001 | ML-DSA-65 (FIPS 204) | 1,952 B | 3,309 B | Module lattices (MLWE/MSIS) | Everyday spending |
| 0x0002 | SLH-DSA-SHA2-128s (FIPS 205) | 32 B | 7,856 B | Hash functions only | Recovery, long-term storage |

[ASSUMPTION] The two families fail independently: a break of lattice problems
does not imply a break of SHA-2, and vice versa. SLH-DSA in particular relies
only on the security of hash functions, the most conservative assumption in
modern cryptography.

The price is size. A typical one-input, two-output ML-DSA-65 transaction is
about 5.4 KB, against roughly 0.2 KB for a Bitcoin Taproot transaction.
[DESIGN] Varve deliberately accepts lower throughput rather than weaker
assumptions or unstandardized cryptography.

[DESIGN] Transaction weight counts serialized bytes, a verification cost per
signature, and net growth of the UTXO set, so a block of expensive-to-verify
signatures cannot exceed the time budget of a block of cheap ones.

[DESIGN] Blocks target 300 seconds. The maximum block weight is 720,000, about
76 GB of chain growth per year at sustained full blocks. Measured verification
times set the weights: about 29 µs per ML-DSA-65 signature and about 0.6 ms per
SLH-DSA-SHA2-128s signature on one 2.1 GHz core, so the signatures of a
worst-case full block verify in under 50 ms on a single ordinary core. In the
first battle test (31 October 2026), a full block of 131 signed transactions was
accepted end to end, including parsing, all checks and storage, in under 0.1 s
on a two-core machine.

## 6. Cryptographic agility

Each scheme id has a consensus state:

| State | New outputs | Spending |
| --- | --- | --- |
| ACTIVE | allowed | allowed |
| NO_NEW_OUTPUTS | rejected | allowed |
| DISABLED | rejected | only through an output's recovery path |

[DESIGN] Transitions happen only by a consensus upgrade at a fixed height, are
one-directional, and are never triggered automatically by an oracle. An output
can only be spent under the scheme it committed to, so downgrade attacks are
impossible by construction. Future standardized schemes enter as new scheme ids
through a scheduled, height-activated upgrade (protocol/upgrades.md): no new
currency, no restart, and no change to existing outputs.

**What agility can and cannot do.**

- *Gradual weakening:* stop new outputs under the weakened scheme and let users
  move funds at leisure. No losses.
- *Practical break:* unspent outputs whose public keys were never revealed
  remain protected by their hash commitments, but spending reveals the key and
  invites a race. [RESEARCH, not in v1] A commit–delay–reveal spend path could
  address this; it needs new consensus state and many unresolved rules
  (ADR-0009), so v1 does not include or rely on it.
- *Outputs with a recovery path* can be moved under the independent hash-based
  scheme without any race.
- *Cannot be solved:* outputs whose keys are already public through address
  reuse, owners who neither migrate nor added a recovery path, and simultaneous
  breaks of both families. Agility greatly reduces these risks; it does not
  remove them.

## 7. Monetary issuance

[DESIGN] The block subsidy decays smoothly with an eight-year half-life until it
reaches a fixed tail, then stays constant forever. It is computed from block
height using an integer lookup table fixed in consensus.

Normalized supply (100 = what an equivalent hard-capped, four-year-halving
schedule would ever issue):

| Year | 1 | 4 | 10 | 20 | 50 | 100 |
| --- | --- | --- | --- | --- | --- | --- |
| Supply | 8.3 | 29.3 | 58.0 | 82.3 | 104.6 | 134.6 |
| Annual inflation | — | 28.0% | 7.0% | 2.0% | 0.58% | 0.45% |

Why this shape:

1. **Fairer early distribution.** A four-year-halving schedule issues 12.5% of
   its total in the first year, when the network is smallest and least
   decentralized. This schedule issues 8.3%, leaving more for those who join later.
2. **A permanent security budget.** Under a hard cap, miner revenue eventually
   depends entirely on fees. A fixed absolute tail keeps mining funded forever
   while inflation trends toward zero, and it offsets coins lost over time.

[DESIGN] The numbers (ADR-0004, protocol/subsidy.md): the subsidy starts at
**82 varve** per block and falls by a factor 2^(−1/64) every 13,149 blocks (an
eight-year half-life at 300-second blocks), computed exactly from a 64-entry
integer table. It reaches the **6 varve** tail at block 3,182,059, about 30
years after launch, and stays there.

Fees go to miners in full. There are no burns, developer fees or taxes.

## 8. Network

[DESIGN] Nodes discover peers through fallback seed addresses and peer exchange,
none of which is consensus infrastructure. Nodes keep diverse outbound
connections to resist eclipse attacks and check every message's size before
allocating memory for it. The reference node supports IPv4 and IPv6; Tor and
I2P support are specified and planned. Software never updates itself.

## 9. Fair launch

[DESIGN] Nobody, including the author, receives coins except by mining under
the same rules as everyone else.

1. The specification, source code, wallet, and **the exact mining software the
   author will use** are published weeks in advance. Builds are reproducible,
   and at least two independent builders must match.
2. A public release-candidate testnet rehearses the launch procedure.
3. Consensus parameters are frozen, and a future Bitcoin block height H is announced.
4. Genesis is a hash over a domain tag, a commitment to all consensus
   parameters, and **all six** Bitcoin block headers H through H+5. Each header
   must link to the previous one and meet Bitcoin's real difficulty for that
   period, fixed in advance. Until Bitcoin block H+5 exists, nobody can know the
   genesis hash or mine block 1. The genesis timestamp is the median of the six
   Bitcoin timestamps, so no single Bitcoin miner controls it.
5. The genesis coinbase is unspendable, and genesis contains nothing else.

After genesis, Varve never consults Bitcoin again. [OPEN] Mainnet must also
bound the easy-block burst that would follow a launch long after genesis time
(open question Q-17).

## 10. Status

As of October 2026:

- **Specification.** Normative documents cover encoding, transactions, blocks,
  difficulty, subsidy, proof of work, genesis, upgrades, P2P and wallets.
- **Three agreeing implementations of the rules.** A disposable prototype, an
  independent verifier written only from the specification, and the reference
  node all pass the same consensus test vectors, including real ML-DSA and
  SLH-DSA signatures and RandomX hashes on x86_64 and ARM64.
- **Reference node.** A Rust node, miner and wallet with no third-party Rust
  dependencies, tested across separate nodes: mining, sync, signed payments,
  chain reorganizations and restarts.
- **Testnet.** Genesis is anchored to Bitcoin blocks 973,970–973,975, verified by
  every node at start-up. A public testnet opens once its first seed node is
  online.
- **Reviews.** An independent human review of the protocol found one critical
  and several high-severity design issues, all fixed in the current
  specification. An AI-assisted review of the node code found no divergence
  from the specification. Every finding is resolved or tracked in public audit
  records. A public, named security audit is still ahead.

## 11. Security considerations

The main risks, in rough order of likelihood:

1. **Low hashrate.** Deep reorganizations and double spends by rented or
   redirected hashrate, especially in the first years.
2. **No adoption.** Without users, the chain cannot fund its own security.
3. **Consensus bugs.** Mitigated by specification-first development, test
   vectors checked by independent implementations, fuzzing, and review.
4. **Signature implementation flaws.** Side channels, faults and weak
   randomness. Mitigated by audited implementations and hedged signing.
5. **Specialized hardware and botnets.** Both can concentrate mining.
6. **Chain growth.** It must never price out independent verification.
7. **Social capture.** A founder cult, a dominant implementation, or a
   contested emergency fork after a cryptographic break.

AI-assisted analysis contributed to this work. It is not a security audit:
mainnet requires independent, named human review.

## 12. Limitations

- Throughput is low by design, about 0.4 transactions per second at full
  blocks. Varve is a base settlement layer, built for value that must last.
- Transactions are large compared with elliptic-curve systems.
- There is no multisignature at launch; post-quantum threshold signatures are
  still maturing.
- There is no public key derivation, so watch-only wallets need exported commitments.
- The proof-of-work choice has serious tradeoffs, as every option does.
- If Bitcoin completes a post-quantum migration, Varve's distinction narrows to
  what it was designed around from the start: no legacy elliptic-curve outputs,
  built-in agility and recovery, and a launch with no allocation.

## 13. Launch criteria

Mainnet launches only if all of the following hold:

- The specification lets two independent teams build compatible nodes without
  asking what a rule means.
- Public adversarial testnets have run without unresolved critical findings.
- Independent reviews of cryptography, consensus, networking and wallet code are
  complete, with all critical and high findings resolved.
- Reproducible builds match across independent builders.

These criteria are the promise: Varve launches when it is ready, and not before.

---

*Varve is open source under MIT or Apache-2.0. Source: github.com/IsamuNagai/varve ·
Updates: x.com/isanagai*

## References

1. S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008.
2. NIST, FIPS 204: Module-Lattice-Based Digital Signature Standard, 2024.
3. NIST, FIPS 205: Stateless Hash-Based Digital Signature Standard, 2024.
4. NIST, IR 8610: Status Report on the Second Round of the Additional Digital Signature Schemes, 2026.
5. BIP-350: Bech32m format for v1+ witness addresses.
6. BIP-360 (Pay to Merkle Root) and BIP-361 (Post Quantum Migration and Legacy Signature Sunset), drafts.
7. tevador et al., RandomX specification; OSTIF, "Four audits of RandomX," 2019.
8. Bitcoin Cash, aserti3-2d difficulty adjustment specification, 2020.
