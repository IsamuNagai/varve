title: A working node, and a testnet born from today's Bitcoin blocks
date: 2026-10-31

Varve now runs. The reference node, miner and wallet are written in Rust, with no third-party Rust packages at all. The only external code is the two pinned cryptographic libraries the protocol depends on: liboqs for the post-quantum signatures, and RandomX for mining. It passes every consensus test vector, which makes it the third implementation that agrees on the rules.

What it can already do, tested with separate nodes talking over the network on every change:

- mine blocks with RandomX on an ordinary CPU;
- sync from other nodes, header-first;
- send a payment signed with ML-DSA that relays, confirms and shows up in the other wallet;
- recover from a chain split by switching to the chain with more work, without losing payments;
- restart from disk exactly where it left off.

An AI-assisted review of the node code found no deviation from the specification and fifteen robustness issues, including two ways a node could get stuck. All are fixed or documented, with regression tests.

The testnet now has a genesis block too. It is anchored to Bitcoin blocks 973,970 to 973,975, mined earlier today, and every node verifies those six headers against Bitcoin's real proof of work each time it starts. It is a rehearsal of exactly how mainnet will launch.

The whitepaper is updated to draft 0.3. Next step: bring the first public seed node online, so anyone can download the node and start mining testnet coins. Testnet coins have no value. Their job is to let as many people as possible try to break Varve before mainnet.
