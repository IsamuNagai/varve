# Varve reference node (testnet software)

`varve` is a full node, CPU miner and minimal wallet in one program. It
implements the consensus rules in [`protocol/`](../protocol/) and passes every
file in [`test-vectors/`](../test-vectors/), so it agrees with the disposable
prototype and the independent spec-only verifier.

> **Testnet only.** Testnet coins have no value and the testnet may be reset.
> Mainnet does not exist: the node refuses to run it until its launch
> parameters are final, after independent review (see the roadmap).

## Build

Needs Rust (stable), CMake, a C/C++ compiler, git, and network access to
GitHub for the two pinned C libraries (liboqs and RandomX, fetched and
verified by [`tools/build-deps.sh`](../tools/build-deps.sh)). No Rust crates are
downloaded: the node uses the standard library only.

    cd node
    cargo build --release
    ./target/release/varve version

## Mine on the testnet

The simplest and safest way is to mine straight to an address from the
[Strata](crates/strata/) wallet. The node then holds no keys at all:

    ./target/release/varve node --mine --mine-to <your tvarve1... address>

Or give the node its own wallet first. It is encrypted with your passphrase
and can be restored from 24 words, which also open it in Strata:

    ./target/release/varve wallet create      # shows the 24 words once: write them down
    ./target/release/varve node --mine

The node only needs public addresses to mine and to show balances. The private
keys stay encrypted on disk and are decrypted only while a payment is signed.
Check progress from another terminal:

    ./target/release/varve rpc getmininginfo
    ./target/release/varve wallet balance

Mined coins can be spent after 288 blocks (about a day). `wallet send` asks
for your passphrase, unlocks the wallet for at most a minute, pays and locks
it again:

    ./target/release/varve wallet send <address> <amount>

Other wallet commands: `wallet import` (restore from 24 words), `wallet phrase`
(show the words again, after your passphrase), `wallet address`,
`wallet newaddress`, and `wallet repair` (rebuild the public address list).

Mining uses all cores in RandomX fast mode, which needs about 2.1 GiB of free
memory. Use `--threads N` to limit cores and `--light` on small machines.

## Run a public node (server)

See [`deploy/`](deploy/): one command installs the node as a system service
that restarts automatically. Open TCP port 39900. Never expose the RPC port
(it listens on 127.0.0.1 only and needs the cookie file in the data directory).

## Public API (for the explorer and wallets)

`--api-port 39911` serves the read-only API in [`API.md`](API.md) on
127.0.0.1. It exposes only public chain data and is rate-limited per client.
To publish it, keep it on 127.0.0.1 and put a TLS reverse proxy in front of it.
With [Caddy](https://caddyserver.com) and a domain pointing at the server,
`/etc/caddy/Caddyfile` is just:

```
api.example.org {
    reverse_proxy 127.0.0.1:39911
}
```

Then start the node with `--api-port 39911 --api-trust-proxy`, so that rate
limits apply per visitor instead of to the proxy. The node refuses
`--api-trust-proxy` unless the API listens on a loopback address, because
forwarded addresses can only be trusted when the proxy is the only client.

## What is implemented

- Consensus: everything in `protocol/` (transactions, blocks, ASERT, subsidy,
  RandomX v2 with the Varve salt, genesis from six Bitcoin headers, chain
  selection by greatest chainwork, reorganizations).
- P2P (subset of `protocol/p2p.md`): framing with all size checks before
  allocation, handshake with genesis check, ping, headers-first sync, parallel
  block download with timeouts, block and transaction relay, address
  exchange, bans for invalid data.
- Mempool with the p2p.md policy subset (weight limit, minimum feerate,
  no replacement), block templates by feerate.
- Miner: RandomX fast or light mode, multi-threaded.
- Wallet: ML-DSA-65 keys, addresses, balance, payments.
- Local JSON-RPC (`varve rpc <method>`), cookie-authenticated, loopback only.
- Public read-only API with transaction, spend and address indexes that stay
  exact across reorganizations ([`API.md`](API.md)).
- [Strata](crates/strata/), the desktop wallet: encrypted wallet file,
  24-word recovery phrase, local web interface.

## Known limitations (to fix before any mainnet candidate)

- Implemented from p2p.md §8 and §10: per-peer verification-cost token
  buckets, disconnection of peers that relay invalid signatures, at most 8
  inbound connections per network group (IPv4 /16, IPv6 /32), and at most one
  outbound connection per group among learned addresses, chosen at random.
- Not yet implemented: presync (§5.3), compact blocks (§7), the full address
  manager with buckets and anti-eclipse rules (§4, §10), orphan transactions,
  Tor/I2P. The node is therefore weaker against denial-of-service and eclipse
  attacks than the specification requires.
- Storage keeps the UTXO set in memory and replays `blocks.dat` on start.
  Simple and inspectable; slower to start as the chain grows.
- Chain selection scans the block index for each new block; fine for testnet,
  to be replaced by a candidate set before mainnet.
- On Windows, liboqs is compiled with clang-cl: built with MSVC's own
  compiler, its SLH-DSA code fails the NIST ACVP key-generation vectors. The
  test suite checks this on every change on every platform.
- The node's built-in wallet uses the same encrypted file format and seeded
  derivation as Strata (`protocol/wallet.md`). It is simple on purpose (one
  account, ML-DSA keys only); Strata is the full wallet.
- API indexes live in memory and are rebuilt at start-up.
- One implementation is not enough for mainnet (ADR-0010): an independent
  second node implementation is required.

An independent review of this code and how each finding was resolved:
[`audits/2026-10-31-node-review.md`](../audits/2026-10-31-node-review.md).
Battle-test results: [`battle/`](../battle/).

## Tests

    cargo test --release                       # unit tests + every test-vector file
    python3 -I tests/e2e_regtest.py target/release/varve   # multi-node network test
    python3 -I tests/strata_e2e.py target/release/strata target/release/varve   # wallet payments
    target/release/varve-fuzz --seconds 300    # randomized fuzzing of every parser

Battle tests (attacks on a private local network) are in [`../battle/`](../battle/).
