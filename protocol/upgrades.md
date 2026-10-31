# Consensus upgrades and activation (normative, draft v0.1)

This document answers audit finding M-01: how a consensus rule change, such as
a signature-scheme lifecycle change, is defined, activated and identified.

## 1. Two kinds of change

| Kind | Effect on old nodes | Examples in Varve |
| --- | --- | --- |
| **Tightening** (soft fork) | Old nodes still accept every block new nodes accept | ACTIVE → NO_NEW_OUTPUTS; NO_NEW_OUTPUTS → DISABLED; a lower weight limit |
| **Loosening** (hard fork) | Old nodes reject some blocks new nodes accept, so every node must upgrade | adding a scheme id; adding an output policy; adding an output version; any new spend path |

v1 makes unknown scheme ids, policies and output versions **invalid**, not
"anyone can spend". Therefore adding any of them is a hard fork. This is a
deliberate choice: an anyone-can-spend extension point (Bitcoin's approach for
new witness versions) would allow soft-fork additions, but it creates outputs
that are unprotected on any node that has not upgraded, which is a poor fit for
a currency whose purpose is long-horizon custody. (Earlier drafts said new
schemes and policies would arrive by soft fork. That was wrong under the v1
rules and is corrected here; see §7.)

## 2. Activation is by height, fixed in the release

- Every change has an **activation height** `A` written into the release that
  implements it. Rules are a pure function of block height: a block at height
  `h ≥ A` is validated under the new rules, a block at `h < A` under the old.
- There is **no miner signaling** in v1. The header `version` MUST be 1
  (blocks.md §4), so it carries no signal bits. Miner signaling would let a
  hashrate majority veto or delay changes; with height activation, the
  decision is made by the users and node operators who choose which software
  to run.
- **Lead time.** The release that fixes `A` SHOULD be published at least
  105,192 blocks (about one year) before `A` for a hard fork, and at least
  26,298 blocks (about three months) for a tightening. A scheme break may
  justify a shorter lead time for a tightening, never for a hard fork.
- **Reorgs.** Because rules depend only on height, a reorganization across
  `A` needs no special handling: each block of the new branch is validated
  under the rules for its own height. There is no activation state to roll back.

## 3. Upgrade documents

Each change is a numbered document `protocol/upgrades/NNNN-name.md` containing:

1. The exact rule change, written as a diff against the affected sections.
2. Kind (tightening or loosening) with the reasoning.
3. Activation height per network (mainnet, testnet, regtest).
4. For a new scheme id: the exact algorithm, parameter set, encoding,
   `verify_units`, a pinned reference implementation, and verification vectors
   (valid and invalid) on every supported architecture.
5. Consensus vectors that straddle `A` (blocks at `A − 1` and `A`).
6. `upgrade_hash = H256("VARVE/upgrade/v1", canonical bytes of the document)`.

## 4. Identifying the active rule set

- Each node release lists the upgrade documents it implements and their
  `upgrade_hash` values. The P2P `version` message SHOULD carry the hash of
  that list so peers can detect incompatible rule sets early (p2p.md).
- The scheme lifecycle table is a list of `(scheme_id, state, from_height)`
  entries, compiled into the node from the upgrade documents. At genesis it is
  empty, which means every scheme is ACTIVE (transactions.md §6). Entries only
  ever record a move to NO_NEW_OUTPUTS or DISABLED.

## 5. Lifecycle transitions

- One-directional: ACTIVE → NO_NEW_OUTPUTS → DISABLED. A state may be skipped
  (ACTIVE → DISABLED) only for a practical break.
- No automatic, oracle- or price-triggered transitions.
- DISABLED makes outputs under that scheme unspendable through that path. An
  output with a recovery path under a different, non-disabled scheme remains
  spendable through it. Users are warned about this in wallet software and
  release notes long before `A`.

## 6. What is not specified yet

- Format of the rule-set hash in the `version` message (p2p.md Q-list).
- Whether a tightening under emergency may use a shorter minimum lead time,
  and how short.
- Spending via commitment for broken schemes (ADR-0009, deferred).

## 7. Corrections made with this document

- ADR-0001, ADR-0002 and the whitepaper said new policies and scheme ids would
  arrive "by soft fork". Under v1 rules they are hard forks. Text corrected.
