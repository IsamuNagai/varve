# Reference node review, 2026-10-31: resolution record

An independent reviewer that had not written the code audited the first version
of the Rust node (`node/`) against the specification, before any public release.
**No consensus divergence was found**: parsing, validity and arithmetic rules
match the spec, and the node passes every test-vector file. The findings concern
chain-state management, peer-to-peer resource limits, and the install script.
Two were reproduced with a program built against the real chain code; both
reproductions are now permanent regression tests in `node/crates/varve/src/chain.rs`.

| # | Severity | Finding | Status | Resolution |
| --- | --- | --- | --- | --- |
| 1 | High | A full buffer of unconnected blocks made the node refuse every block, including the next one it needed (attack or slow peer); restart could fill it with stale blocks | Fixed | Bodies are held only if they extend a heavier branch or are near the tip; the download window (128) is below the buffer (256); the block furthest ahead is evicted for a more urgent one, and a block extending the tip is never refused; restart indexes on-disk blocks by file position instead of loading them into memory. Regression test |
| 2 | High | Block download stalled once headers were more than 100,000 blocks ahead | Fixed | Missing blocks are collected upward from the fork point |
| 3 | Medium | A reorganization that failed part-way left an equal-work branch active (violating first-seen) and skipped mempool/miner updates | Fixed | The current tip competes in chain selection, so a failed reorganization returns to the first-seen chain; tip changes are reported separately from invalidity and always update the mempool, miner and peers. Regression test |
| 4 | Medium | Only one header chain was downloaded, so a withheld block on the heaviest headers could stall a lighter but better-than-tip chain | Fixed | Bodies are requested for every header chain heavier than the tip (best first, up to 8 branches) |
| 5 | Medium | One peer could queue hundreds of MB of outgoing blocks | Fixed | Byte-accounted 5 MB send buffer per peer (p2p.md §11); reading from a peer pauses while it is full; `getdata` serving pauses and stops if the peer is gone |
| 6 | Medium | Peers were dropped right after a successful ping (RTT read as a send time) | Fixed | Outstanding ping and last RTT kept in separate fields |
| 7 | Medium | `install.sh` upgrades could rebuild a stale commit, and the service account could tamper with the next build that root installs | Fixed | Separate `varve-build` account the service cannot write to; checkout of `origin/REF` or an exact commit; the built binary is never executed as root; service restarted on upgrade; inputs validated |
| 8 | Low–medium | Disk failures could hang the node (infinite loop) or lose undo data | Fixed | Blocks are written before the UTXO set changes; disconnecting uses undo data only; an unreadable or unwritable block is skipped for that activation instead of looping |
| 9 | Low | Unvalidated held blocks were served to peers | Fixed | Only validated blocks are served |
| 10 | Low | Senders of invalid blocks delivered out of order were not banned | Fixed | The sender of each held block is recorded and banned if it proves invalid |
| 11 | Low | CPU cost under the chain lock | Partly fixed | Invalid-marking uses a child map (one pass). Chain selection still scans the block index per block: acceptable for testnet, to be replaced by a candidate set before mainnet |
| 12 | Low | Mempool selection could be quadratic; pool up to ~2 GB | Fixed | 100 MB weight cap; at most 25 unconfirmed ancestors per transaction |
| 13 | Low | Absurd RPC amounts could overflow and poison all locks; a failed thread spawn could panic | Fixed | Checked/saturating arithmetic and range checks in the wallet; signature verification falls back to the current thread |
| 14 | Low | Unauthenticated local clients could exhaust RPC memory | Fixed | 8 KB line limit, 64 headers, 16 concurrent connections |
| 15 | Low | `uptime` RPC could panic if the clock moved backwards | Fixed | Saturating subtraction |
