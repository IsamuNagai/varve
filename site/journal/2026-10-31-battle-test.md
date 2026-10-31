title: The first battle test: two real bugs found, both fixed
date: 2026-10-31

Today we turned on Varve. Not in public yet, but on a private test network where the only job was to break it.

We built a battle-test harness that starts real nodes and attacks them. It sends blocks that create coins out of thin air, spend the same coin twice, or steal coins with someone else's signature. It sends blocks with impossible timestamps or fake difficulty, and longer secret chains that try to undo a payment that already confirmed. It sends thousands of randomly corrupted blocks, transactions and network messages. Every attack block carries real RandomX proof of work and every signature is a real post-quantum signature, so the node can't reject anything for a cheap reason. A separate implementation of the rules checks the same inputs, and the two must agree on every single one. Then we pulled the plug on running nodes and damaged their data files.

The first run passed 53 of 55 tests. The two failures were real:

- **A damaged spot in a node's own block file made it distrust a good block forever.** The node treated its broken local copy as proof the block was invalid. It then refused the clean copy from other nodes and cut those nodes off. On a live network, one bad disk sector could have isolated a node. Now the node recognises a damaged local copy, throws it away and fetches the block again.
- **A transaction's witness data could be re-encoded by anyone relaying it.** Since this week, Varve can cover several coins from the same key with a single signature. A relayer could swap a full signature for that short shared form. That changed the transaction's size and witness ID, though never what it pays or to whom. The rule is now strict: where the shared form applies, it is the only valid form, so every transaction has exactly one valid encoding.

The second run passed all 55. The two charts, with the date and version tested, are on the [security page](security.html#battle-tests). The harness and raw results are in the repository, so anyone can rerun them.

The same work brought two improvements of its own. The difficulty schedule now starts two hours after genesis, which removes a burst of too-easy blocks right at launch. Spending many coins from one address now needs only one signature: in the battle test, one transaction spent 398 coins and weighed about 21 KB, where separate signatures would have taken over 2 MB. A full block of 131 separately signed transactions verifies in under 0.1 seconds on a modest two-core machine.

What this does not prove: no test suite proves there are no bugs. Network-flood testing and an independent human code audit are still ahead, and both must happen before mainnet. The public testnet is where everyone else gets to try.
