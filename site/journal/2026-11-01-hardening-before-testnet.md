title: Final hardening before the testnet
date: 2026-11-01

The last work before the testnet goes live was about making the whole structure tighter without slowing anything down.

**The node's wallet is now encrypted.** It uses the same format as Strata: a 24-word recovery phrase, Argon2id to protect your passphrase, and AES-256 with an authentication code for the file. The node mines and shows balances from public addresses only. Private keys are decrypted just long enough to sign a payment and wiped right after. On a server you can go further and mine straight to a Strata address, with no keys on the machine at all. The installer now works that way.

**The network layer got stricter.** Each peer has a budget for how much signature verification it can make a node do, and anything beyond it is dropped unverified. A peer that relays a transaction with an invalid signature is disconnected, because honest nodes check before they relay. A node accepts only a few inbound connections from the same network range, and spreads its own outbound connections across different ranges, chosen at random. That makes it harder for one party to surround a node.

**Every parser is now fuzzed continuously.** Transactions, blocks, network messages, addresses, recovery phrases, wallet files and the wallet's local web server each get a stream of randomly corrupted input. Anything that parses must re-encode to exactly the same bytes, so no object can have two encodings. It runs on every change and for 45 minutes every night. The first runs, hundreds of millions of inputs, found nothing.

Mining speed is unchanged: none of this touches the miner. The battle tests pass with all of it in place, now 57 out of 57. What is still ahead before mainnet is on the [readiness page](mainnet.html). Next: the testnet.
