# Protocol specification (draft v0.3)

The consensus documents are **normative**: they define consensus. A rule that
two reasonable implementations could read differently is a specification bug.

Keywords MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

## Consensus

| File | Status |
| --- | --- |
| `encoding.md` | Draft v0.2: integers, varint, hashing, network id |
| `transactions.md` | Draft v0.5: outputs, inputs, txid/wtxid, coinbase, locktime, schemes and v1 lifecycle, signature message, spending rules, recovery trust model, weight |
| `blocks.md` | Draft v0.3: header, Merkle root, validation order, arbitrary-precision chainwork, chain selection, sync policy |
| `difficulty.md` | Draft v0.3: aserti3-2d anchored two hours after genesis, timestamp rules |
| `subsidy.md` | Draft v0.2: exact integer schedule |
| `genesis.md` | Draft v0.3: construction from six Bitcoin headers, exact anchor validation |
| `pow.md` | Draft v0.3: RandomX v2 at a pinned commit with the Varve salt, key rotation, vectors |
| `upgrades.md` | Draft v0.1: soft vs hard forks, height activation, upgrade documents |
| `params.md` | Draft v0.2: canonical constant list and `params_hash` |

## Node behaviour and wallets (normative for interoperability, not consensus)

| File | Status |
| --- | --- |
| `p2p.md` | Draft v0.2: transport, framing, handshake, headers-first sync, compact blocks, relay, RandomX cache policy, anti-eclipse |
| `addresses.md` | Draft v0.2: Bech32m wallet encoding (recovery-address format under review, audit M-03) |
| `wallet.md` | Draft v0.1: seeds, separate primary/recovery seeds, key derivation, scanning, watch-only |

## Test vectors

`../test-vectors/` holds the vectors; `../test-vectors/README.md` lists each
file, how it is produced, and which CI job checks it. An independent
implementation written only from these documents lives in `../verifier/`, and the
reference node in `../node/` also passes every vector file.
