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

    ./target/release/varve node --mine --seed <seed-node-address>

On first start the node creates a wallet in `~/.varve/testnet/wallet.json` and
mines to its first address. Check progress from another terminal:

    ./target/release/varve rpc getmininginfo
    ./target/release/varve wallet balance

Mined coins can be spent after 288 blocks (about a day). Send them with:

    ./target/release/varve wallet send <address> <amount>

Mining uses all cores in RandomX fast mode, which needs about 2.1 GiB of free
memory. Use `--threads N` to limit cores and `--light` on small machines.

## Run a public node (server)

See [`deploy/`](deploy/): one command installs the node as a system service
that restarts automatically. Open TCP port 39900. Never expose the RPC port
(it listens on 127.0.0.1 only and needs the cookie file in the data directory).

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

## Known limitations (to fix before any mainnet candidate)

- Not yet implemented from p2p.md: presync (§5.3), compact blocks (§7),
  the full address manager with network-group buckets and anti-eclipse
  rules (§4, §10), verification-cost token buckets (§8), orphan transactions,
  Tor/I2P. The node is therefore weaker against denial-of-service and eclipse
  attacks than the specification requires.
- Storage keeps the UTXO set in memory and replays `blocks.dat` on start.
  Simple and inspectable; slower to start as the chain grows.
- Chain selection scans the block index for each new block; fine for testnet,
  to be replaced by a candidate set before mainnet.
- Windows builds are not produced yet (use WSL, or Linux/macOS).

An independent review of this code and how each finding was resolved:
[`audits/2026-10-31-node-review.md`](../audits/2026-10-31-node-review.md).
- The wallet stores keys **unencrypted** and does not yet use the seeded
  derivation of `protocol/wallet.md`. Back up `wallet.json`; never share it.
- One implementation is not enough for mainnet (ADR-0010): an independent
  second node implementation is required.

## Tests

    cargo test --release                       # unit tests + every test-vector file
    python3 -I tests/e2e_regtest.py target/release/varve   # multi-node network test
