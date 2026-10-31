# Battle tests

We attack the Varve node on a private regtest network and publish the results, failures
included. Everything runs on one machine against nodes bound to 127.0.0.1, and nothing
is sent anywhere else.

| Run | Date (UTC) | Version | Result |
| --- | --- | --- | --- |
| [Run 1](results/run-1.json), before fixes | 2026-10-31 19:10 | `121906a` | 53 of 55 handled correctly, 2 problems found |
| [Run 2](results/run-final.json), after fixes | 2026-10-31 19:27 | `812a3f2` | 55 of 55 handled correctly |

The charts are in [`docs/assets/`](../docs/assets/) and on the website's security page.

## What is tested

- **Consensus (30 tests):** blocks with real RandomX proof of work but invalid content:
  - inflation, double spends, duplicate or nonexistent inputs
  - immature coinbase spends, bad signatures, signatures by the wrong key
  - misuse of the shared witness, unknown witness paths, oversized blocks
  - future and time-warp timestamps, an easier target than allowed, missing proof of work
  - coinbase shape rules, negative fees, value overflow, unknown schemes
  - locktime, early recovery-path spends
  - children of invalid blocks, mutated copies of real blocks, non-canonical witnesses

  Each is sent by RPC and over P2P. The node must reject it and keep its tip.
- **Chain reorganizations (4):** a double spend through a longer private chain; ties between equal-work blocks (the first seen must win); a 20-block reorg; a longer chain with an invalid block hidden inside.
- **Mempool policy (3):** conflicting spends, zero-fee transactions, long chains of unconfirmed transactions.
- **Wallet input (9):** malformed or wrong-network addresses, impossible amounts, insufficient funds, twelve concurrent payments.
- **Fuzzing and cross-checks (3):**
  - 2,000 mutated blocks and transactions sent by RPC
  - 200,000 random messages through the message decoder
  - 3,000 mutated transactions judged by both the Rust node and the separate Python reference implementation, which must agree on every one
- **Crash and data recovery (6):** a truncated, appended-to, corrupted or deleted block file; a SIGKILL during initial sync; a SIGKILL while mining.

Capacity figures (block verification time, transactions per second, sync speed, reorg time, peak memory) are recorded in the same files.

**Not covered:** network-flood and connection-exhaustion testing, and an independent human code audit. Passing these tests shows the node enforces its rules under these attacks. It does not prove the absence of bugs.

## Problems found and fixed

1. **A corrupted local block made a good block "invalid" forever.** After a block file was damaged, the node treated its broken copy as proof that the block itself was invalid. It then rejected the clean copy and banned the peers that offered it. Fix: a stored copy that no longer matches its header is discarded and fetched again (`node/crates/varve/src/chain.rs`). Regression test: `corrupt_stored_block_is_refetched_not_marked_invalid`.
2. **Witness malleability via the shared witness.** A relayer could replace a full signature with the 3-byte shared form when an earlier input already signed for the same key. The txid stayed the same, but the wtxid, size and weight changed. Fix: the shared form is now mandatory where it applies (transactions.md §8.2), so each transaction has exactly one valid witness layout. Covered by test vectors and the battle test.

## Reproduce

```
cd node && VARVE_DEPS=/path/to/deps cargo build --release && cd ..
python3 -I battle/run.py --bin node/target/release/varve \
    --testkit node/target/release/varve-testkit --run-id my-run --label "My run"
python3 -I battle/render.py battle/results/my-run.json my-run.png
```

A full run takes about 15 minutes on two cores and needs about 4 GB of RAM: the test kit
builds blocks using RandomX's fast mode. `varve-testkit` is a development tool and is not
part of any release.
