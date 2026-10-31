# Peer-to-peer protocol and synchronization (draft v0.2)

This document defines how a Varve node talks to peers and how it finds,
downloads and relays headers, blocks and transactions. It does not define
validity. Consensus validity is defined only in `encoding.md`,
`transactions.md`, `blocks.md`, `difficulty.md`, `pow.md` and `genesis.md`. Everything here
is node behaviour and local policy. Two nodes with different p2p settings MUST
still agree on which chain is valid and best. Keywords are as in RFC 2119.
Every constant marked "initial value" is a starting point, to be tuned on testnet.

## 0. Chain-selection invariant (overrides every other rule here)

1. The chain-selection rule in blocks.md §5 (greatest cumulative work,
   arbitrary precision) is authoritative.
2. A node MUST download and fully validate any header chain whose cumulative
   work exceeds the cumulative work of its active tip. No rule in this
   document may cause a node to refuse such a chain, defer it indefinitely,
   or fail to download or validate it. Rate limits MAY slow such a chain
   down, but MUST still guarantee progress (§5.4, §9).
3. Anti-DoS gating applies only to branches that are *known* to have less
   total work than the active tip.
4. The node MUST NOT make PoW-verification resources (RandomX caches)
   conditional on work that has already been verified, because that is
   circular. Cache construction is instead budgeted (§9). It is allowed once
   the branch passes cheap syntactic and linkage checks.
5. There are no checkpoints and no reorganization depth limit.

6. **Initial sync floor.** The single exception to item 2 is `MIN_CHAIN_WORK`
   (blocks.md §6 item 5): until a node's active tip reaches it, header chains
   below it are not downloaded (§5.3 item 4). It is derived from the real chain
   before each release, so the honest chain always meets it.

blocks.md v0.3 §6 matches this section (the earlier `GATE_WORK` conflict is resolved).

## 1. Transport

- **Transport.** TCP. A node MAY also connect over Tor (onion services v3, via
  SOCKS5) and I2P (SAM). Each network is reachable or unreachable by local
  configuration.
- **Default ports.** These are placeholders, to be assigned before testnet:

  | Network | network_id | Port |
  | --- | --- | --- |
  | mainnet | `VARV` | 29900 |
  | testnet | `TVAR` | 39900 |
  | regtest | `RVAR` | 49900 |

- **Encryption.** v0.1 has no encryption or authentication requirement. A
  later version SHOULD add an opportunistically encrypted transport in the
  style of BIP-324, including pseudorandom-looking bytes on the wire and
  rekeying (open question Q4: post-quantum key exchange).

## 2. Message framing

Each message is a 24-byte frame header followed by the payload.

| Field | Type | Rule |
| --- | --- | --- |
| `magic` | 4 bytes | `network_id` (encoding.md §6): `VARV`, `TVAR` or `RVAR` |
| `command` | 12 bytes | ASCII `[a-z0-9]`, zero-padded on the right; bytes after the first `0x00` MUST be `0x00` |
| `length` | u32 | payload length in bytes |
| `checksum` | 4 bytes | first 4 bytes of `H256("VARVE/p2p/v1", payload)` |
| `payload` | `length` bytes | command-specific |

Receivers MUST check the following, in this order:

1. If `magic` does not match the local network, disconnect.
2. If `command` is malformed, disconnect.
3. If `length` exceeds the command's maximum (table below) or, for an unknown
   command, `MAX_PAYLOAD = 800,000`, disconnect. This check MUST happen
   **before** any buffer for the payload is allocated.
4. If the checksum does not match, disconnect.
5. Parse the payload with the canonical-encoding rules of encoding.md. If any
   field is non-canonical or any trailing byte remains, count a protocol
   violation (§10.4).

| Command | Max payload (bytes) | Section |
| --- | --- | --- |
| `version` | 359 | §3 |
| `verack`, `getaddr` | 0 | §3, §4 |
| `ping`, `pong`, `feefilter` | 8 | §3, §8 |
| `addr` | 65,536 | §4 |
| `getheaders` | 2,081 | §5 |
| `headers` | 232,002 | §5 |
| `inv`, `getdata`, `notfound` | 180,002 | §6 |
| `block` | 720,121 (blocks.md §2) | §6 |
| `tx` | 100,000 (= `MAX_STANDARD_TX_WEIGHT`, because weight ≥ size) | §8 |
| `sendcmpct` | 9 | §7 |
| `cmpctblock`, `blocktxn` | 800,000 | §7 |
| `getblocktxn` | 15,518 | §7 |

A message with an unknown command MUST be read and discarded, and otherwise
ignored. It MUST NOT be penalized (§12).

## 3. Handshake

`version` payload:

| Field | Type | Rule |
| --- | --- | --- |
| `protocol_version` | u32 | sender's highest supported version; v0.1 = `1` |
| `services` | u64 | service bits (§12) |
| `timestamp` | u64 | sender's clock, Unix seconds. Informative only (§13) |
| `nonce` | u64 | random per connection; used to detect self-connections |
| `user_agent` | bytes | length ≤ 256; ASCII; informative only |
| `best_height` | u64 | informative only; MUST NOT influence chain selection |
| `genesis_id` | 32 bytes | genesis block id; MUST equal the local one, otherwise disconnect |
| `ruleset_hash` | 32 bytes | hash of the upgrade list this node implements (upgrades.md §4). Informative: a mismatch is logged and shown to the operator, not a reason to disconnect, since nodes on either side of an upcoming activation must keep talking |
| `relay` | u8 | `1` = send transaction inventory, `0` = do not; any other value is a protocol violation |

1. The initiator sends `version` first. The responder replies with `version`,
   and each side then sends `verack` (empty) after accepting the peer's
   `version`.
2. Before both `verack`s are exchanged, any other message is a protocol
   violation. A second `version` is also a protocol violation.
3. If `nonce` equals a nonce this node sent on a pending outbound connection,
   disconnect (self-connection).
4. The negotiated version is `min(local, remote)`. If it is below
   `MIN_PEER_PROTOCOL_VERSION` (= 1), disconnect without penalty.
5. The handshake MUST complete within 60 s (initial value), otherwise disconnect.
6. `ping` and `pong` each carry `nonce` u64. A node SHOULD ping every 120 s.
   It MUST answer `ping` with `pong` echoing the nonce. If a ping goes
   unanswered for 20 min (initial value), disconnect.

## 4. Address relay

`addr` payload: `varint count` (≤ 1,000), followed by `count` entries:

| Field | Type | Rule |
| --- | --- | --- |
| `time` | u64 | last-seen time claimed by the sender; used only for address-manager freshness |
| `services` | u64 | service bits |
| `net` | u8 | `1` IPv4 (4 B), `2` IPv6 (16 B), `3` Tor v3 (32 B), `4` I2P (32 B) |
| `addr` | bytes | length MUST match `net`; unknown `net`: length ≤ 512, entry skipped |
| `port` | u16 | little-endian |

- **Rate limit.** Each peer has a token bucket of 0.1 addresses/s with a burst
  of 1,000 (initial values). Addresses that exceed it are dropped without
  penalty. Addresses for unreachable networks are stored but not relayed to
  peers that cannot use them.
- **`getaddr`.** A node answers at most once per connection, only on inbound
  connections. It answers from a response cache refreshed about every 24 h,
  with ≤ 1,000 entries and ≤ 23% of known addresses.
- **Self-advertisement.** A node SHOULD advertise its reachable address to
  each peer at random intervals, averaging 24 h.
- **Address manager** (in the style of Bitcoin's addrman):
  - A **new** table (1,024 buckets × 64) holds unverified addresses. A
    **tried** table (256 buckets × 64) holds addresses this node has
    connected to successfully.
  - Bucket placement uses `H256("VARVE/p2p/addrman/v1", secret ‖ …)`, keyed by
    a random 32-byte local secret. The new-table input is the address group
    plus the source group. The tried-table input is the address plus its
    group. This limits how many buckets one source or one group can fill.
  - **Network groups:**
    - IPv4 /16;
    - IPv6 /32;
    - Tor and I2P each form a separate class, grouped by the first 4 bits of
      the address.
  - Implementations SHOULD support an optional AS-based map later.
  - Collisions in the tried table are resolved by test-connecting to the old
    entry, and evicting it only if that connection fails.
- **Bootstrap.** DNS seeds and hard-coded fallback seeds are used only when
  the address manager is empty or unusable. They are never trusted for
  anything else, and they play no role in consensus.

## 5. Headers-first synchronization

### 5.1 Messages

`getheaders`:

| Field | Type | Rule |
| --- | --- | --- |
| `locator_count` | varint | 1 … 64 |
| `locator` | 32 bytes × count | block ids, newest first; dense near the tip, then exponentially spaced, ending at genesis |
| `stop_hash` | 32 bytes | all zero = as many as allowed |

`headers`: `varint count` (0 … `MAX_HEADERS` = 2,000), followed by `count` ×
116-byte headers (blocks.md §1). There is no per-header transaction count.

- The responder finds the first locator entry on its **active** chain. It
  returns the following headers in order, up to 2,000 or up to and including
  `stop_hash`.
- A `headers` message whose headers do not each link to the previous one is a
  protocol violation.
- Fewer than 2,000 headers means the peer has nothing more.
- New blocks are announced by sending their header(s) in `headers`, or by
  `cmpctblock` (§7).
- If the first header's parent is unknown, the receiver replies with
  `getheaders`. Disconnect after 10 consecutive non-connecting messages
  (initial value).

### 5.2 Header checks (before storing)

For each header, in order (blocks.md §4 steps 2–6):

1. syntax: 116 bytes, `version = 1`;
2. linkage: the parent is known (stored or earlier in the same session) and
   is not invalid;
3. `timestamp > MTP(parent)`;
4. `target = next_target(parent)`;
5. `pow_hash ≤ target`, using the key from pow.md §3 on this branch (§9).

A header failing any step leads to disconnect and ban (§10.4). A header with
`timestamp > local_clock + MAX_FUTURE_DRIFT` is **deferred**, not failed. The
session pauses at that header and resumes once the local clock has caught up,
with no penalty (blocks.md §4).

### 5.3 Presync (low-memory work tracking)

A header chain is committed to the block index only once its work is proven.
Until then the node tracks it per peer in O(1) memory, plus a small amount of
state per epoch.

1. **Direct path.** A header that connects to a stored header MAY be stored
   immediately if either:
   - the resulting chain's cumulative work is > the active tip's work; or
   - it is within `NEAR_TIP_ALLOWANCE` (the work of 6 blocks at the tip's
     target; initial value) below it.

   Fork headers near the tip are kept, so competing tips are visible
   (§14, T-C2).
2. **Presync state.** Any other connecting chain starts a presync session
   with the sending peer. The session holds:
   - the fork point;
   - the last header;
   - its height;
   - the cumulative work (arbitrary precision);
   - the last ≤ 11 timestamps (for MTP);
   - the block id at each seed height crossed (32 B per 2,048 headers), so
     `key(h)` can be found;
   - one commitment bit every `COMMIT_PERIOD` headers.

   Because `next_target` depends only on the parent's height and timestamp
   and on genesis (difficulty.md §2), this state is enough to apply every
   check in §5.2.
3. **Commitments.** The commitment bit is the low bit of
   `H256("VARVE/p2p/presync/v1", local_salt ‖ block_id)`. It is stored for
   heights at a random per-session offset modulo `COMMIT_PERIOD` (initial
   value 600).
4. **Threshold.** The session moves to redownload when its cumulative work is
   > max(active tip's work, `MIN_CHAIN_WORK`). There is no timeout on the
   `MIN_CHAIN_WORK` floor: a fresh node fed only low-work chains by an eclipse
   attacker keeps waiting and tells the operator so. The operator MAY lower the
   floor by explicit configuration. `MIN_CHAIN_WORK` changes priority only,
   never validity. (Resolves former Q2: a time cap would hand an eclipse
   attacker exactly the outcome the floor exists to prevent, while the floor
   cannot stall an honest node because it is taken from the real chain's past
   work. It is 0 in the first release.)
5. **Redownload.** The node requests the chain again from the fork point. It
   re-applies checks 1–4 and checks every commitment bit. It buffers up to
   `REDOWNLOAD_BUFFER` = 14,000 headers (initial value), and commits headers
   (with full §5.2 checks) only once they are that far behind the newest
   matching header, or once the peer's chain ends.
   - If a commitment bit does not match, the peer is disconnected and banned.
6. **Interruption.** If a session that has reached the threshold is
   interrupted, the node MUST restart it with the same peer or with any other
   peer that announces that chain.
7. **Proven lower work.** A session whose peer has sent its final headers
   with total work ≤ the active tip is discarded without penalty. A valid
   low-work chain is not misbehaviour.

### 5.4 Obligation to validate

Any header chain with more total work than the active tip MUST be downloaded
(§6) and fully validated (blocks.md §4). If a block on it is invalid, that
block and its descendants are marked invalid. The node then continues with
the most-work chain that is not marked invalid. Limits on presync
concurrency or verification budget (§11) MAY queue such a chain behind
others, but every queued session MUST get a slot within bounded time.

## 6. Block download

Inventory entry (used by `inv`, `getdata` and `notfound`): `varint count`
(≤ `MAX_INV` = 5,000, initial value), followed by entries:

| Field | Type | Values |
| --- | --- | --- |
| `type` | u32 | `1` TX (hash = wtxid), `2` BLOCK (block id), `3` CMPCT_BLOCK (block id; `getdata` only) |
| `hash` | 32 bytes | |

Unknown `type` values are ignored. `block` carries one full block
(blocks.md §2). `notfound` lists requested items the peer does not have.

1. **What to fetch.** Blocks are requested only for header chains in the
   block index whose work is > the active tip. Blocks are requested in height
   order, within a window of `BLOCK_DOWNLOAD_WINDOW` = 1,024 blocks
   (initial value) beyond the last fully validated block.
2. **Parallel.** Requests are spread over all peers that have the chain (by
   `headers` received from them). A pruned peer is asked only for blocks
   within 288 of its tip.
3. **In flight.** At most `MAX_BLOCKS_IN_FLIGHT_PER_PEER` = 16 (initial value).
   A block is in flight from one peer at a time, except as in item 5.
4. **Timeout.** A request expires after 600 s plus 300 s for each other peer
   that is downloading from this node (initial values). The peer is then
   disconnected without a ban, and the block is requested elsewhere.
5. **Stalling.** If the window cannot advance only because one peer holds the
   earliest missing block, the node:
   - disconnects that peer after `STALL_TIMEOUT` = 10 s (initial value,
     doubling after each stall disconnect, up to 64 s); or
   - MAY request the same block from a second peer.
6. **Deferred blocks.** A block deferred by the future-drift rule is held or
   re-requested later. It MUST NOT be marked invalid, and its sender MUST NOT
   be penalized.

## 7. Compact block relay

Transactions are large (about 5.4 KB for a typical ML-DSA-65 spend,
ADR-0006), so a full block can approach 720 KB. Peers already hold most of a
new block's transactions in their mempools. Compact relay sends the header
plus 6-byte short ids, so propagation is limited mainly by missing
transactions rather than block size. ADR-0006 estimates the stale rate at
300 s as 0.8% with compact relay versus 1.8% with full relay (6 hops,
10 Mbit/s). Those figures are model estimates, to be confirmed on testnet.

| Message | Layout |
| --- | --- |
| `sendcmpct` | `high_bandwidth` u8 (0/1) ‖ `cmpct_version` u64 (= 1) |
| `cmpctblock` | `header` (116 B) ‖ `nonce` u64 ‖ `varint n_short` ‖ `short_id` (6 B) × n_short ‖ `varint n_pre` ‖ (`varint index_delta` ‖ `tx`) × n_pre |
| `getblocktxn` | `block_id` (32 B) ‖ `varint n` ‖ `varint index_delta` × n |
| `blocktxn` | `block_id` (32 B) ‖ `varint n` ‖ `tx` × n |

- **Short ids:**

      k        = H256("VARVE/p2p/cmpct/v1", header ‖ u64(nonce))
      short_id = first 6 bytes of H256("VARVE/p2p/shortid/v1", k ‖ wtxid)

  - The sender picks a fresh random `nonce` for each connection and each
    block, so a short-id collision cannot be targeted at the whole network.
  - Indexes are encoded differentially, as in BIP-152: each delta is the gap
    from the previous index minus one.
  - `n_short + n_pre` MUST be ≤ ⌊720,000 / 93⌋ = 7,742, where 93 bytes is the
    smallest parseable transaction (transactions.md §3).
  - The coinbase MUST be prefilled.
- **Modes.**
  - A node SHOULD select up to 3 peers (initial value) as high-bandwidth.
    They send `cmpctblock` unsolicited, after header checks §5.2 pass and
    before full validation.
  - Other peers announce by `headers`, and the receiver requests
    `getdata CMPCT_BLOCK`.
- **Fallback.**
  1. Missing transactions are fetched with `getblocktxn` / `blocktxn`.
  2. If reconstruction fails (missing transactions, ambiguous short id, or
     `tx_root` mismatch), the receiver requests the full block with
     `getdata BLOCK`.
  3. During initial sync and for deep reorganizations, nodes use full
     `block` messages.
- **Penalties.** A `tx_root` mismatch after reconstruction is not
  misbehaviour, because short ids can collide. A high-bandwidth peer that
  relays a block whose header is valid but whose body is invalid is not
  banned, because it relayed before validation. It is banned only if it sends
  an invalid header (§10.4).

## 8. Transaction relay

- **Announcement.** Transactions are announced by `inv` type 1 (wtxid) and
  fetched by `getdata`.
  - Announcements are batched and sent at Poisson-distributed intervals:
    mean 5 s to inbound peers and 2 s to outbound peers (initial values).
    Inbound peers share one timer, which limits timing analysis.
  - A node's own transactions are relayed exactly like others.
  - Peers with `relay = 0` receive no transaction inventory.
- **`feefilter`** carries `min_feerate` u64, in laminae per 1,000 weight units.
  The receiver SHOULD NOT announce transactions below it.
- **Mempool policy.** These limits are policy, not consensus. A block
  containing transactions that break them is still valid.

  | Policy | Initial value |
  | --- | --- |
  | `MAX_MEMPOOL_BYTES` | 100 MB; lowest feerate evicted first, which raises the effective minimum |
  | `MIN_RELAY_FEERATE` | 1 lamina per weight unit (placeholder) |
  | `MAX_STANDARD_TX_WEIGHT` | 100,000 |
  | Scheme ids | relay only transactions whose every output scheme id and every spending scheme is ACTIVE and known to this node's policy; never relay transactions with unknown scheme ids |
  | Mempool expiry | 14 days |

- **Order of checks.** A node verifies a transaction in this order, so
  signature work comes last and is paid for by fees:
  1. parse;
  2. weight;
  3. policy limits;
  4. inputs exist;
  5. fee and feerate;
  6. commitment hashes;
  7. signatures (transactions.md §8).
- **Verification-cost accounting.** Each peer has a token bucket in
  verify_units (transactions.md §9): refill 2,000 units/s, burst 100,000
  (initial values). Each signature checked for a peer's transaction is
  charged its verify_units: 100 for ML-DSA-65, 1,700 for SLH-DSA.
  - When the bucket is empty, that peer's transactions are queued or dropped
    without penalty.
  - A peer whose transactions fail signature verification is charged ten
    times the cost and MAY be disconnected.
  - This limits SLH-DSA-heavy spam to a fixed CPU share per peer.
- **Orphans.** A transaction with unknown inputs goes to the orphan pool:
  - at most 100 transactions and 2 MB in total;
  - at most 10 per peer;
  - each expires after 20 min;
  - when full, a random entry is evicted (initial values).

## 9. RandomX cache policy

Verifying `pow_hash` needs the 256 MiB cache for `key(h)` (pow.md §3–4).

1. **Slots.** A node keeps at most `MAX_RX_CACHES` caches. The default is 3
   (initial value):
   - the active tip's current key;
   - the next key, known 64 blocks before it is needed;
   - one LRU slot for a competing branch or a historical epoch during sync.

   Low-memory nodes MAY use 2, at the cost of rebuilding caches more often.
   (Former Q3: 768 MiB fits the ADR-0006 reference machine alongside the UTXO
   set, so 3 stays the default.)
2. **Preconditions.** Building a cache for key `K` = block id of seed header
   `S` on a branch requires only that every header from the fork point up to
   and including `S`, and the header that needs `K`, pass §5.2 checks 1–4
   (syntax, linkage, MTP, target).
   - It MUST NOT require any amount of already-verified work.
   - Nodes SHOULD verify PoW in height order, so that headers up to `S` have
     already been verified under earlier keys. A forced build then costs the
     attacker real hashing on the branch.
3. **Budgets** (initial values):
   - globally, at most 1 build per 10 s, with a burst of 3;
   - per peer, at most 1 build of a key not already cached per 120 s.

   A request over budget is queued, not refused. The queue is served first
   for outbound peers, and then in order of arrival, so a branch with more
   work than the tip still makes progress (§0).
4. **Eviction.** When a slot is needed, the cache used least recently is
   evicted, except the active tip's current key.
5. **Abuse.** A peer whose header fails PoW under a cache built for it is
   disconnected and banned (§10.4). A peer that triggers builds for branches
   repeatedly proven to have less work than the tip MAY be deprioritized in
   the build queue.

## 10. Peer management and anti-eclipse

1. **Outbound.**
   - At least 8 full-relay outbound connections, each in a distinct network
     group (§4);
   - plus 2 block-relay-only outbound connections, which send `relay = 0`
     and do not exchange `addr`;
   - plus a short-lived feeler connection about every 2 min, to test
     new-table addresses and move them to tried.

   If no new block has arrived for 30 min (initial value), the node SHOULD
   open one extra outbound connection to look for headers. It SHOULD also
   periodically rotate an extra block-relay-only peer.
2. **Anchors.** On shutdown, the current block-relay-only peers are written to
   an anchors file. On startup, the node reconnects to them first.
3. **Inbound eviction.** Total connections are at most 125 (initial value).
   When inbound slots are full, the node protects the following inbound peers
   and evicts from the remainder the peer in the most-populated network
   group:
   - 4 chosen for distinct network groups, by keyed hash;
   - 8 with the lowest ping;
   - 4 that most recently delivered novel transactions;
   - 4 that most recently delivered novel blocks;
   - half of the remainder by longest uptime, with a share reserved for
     Tor/I2P.
4. **Misbehaviour** (explicit, no fractional scores). Disconnect and ban for
   24 h (initial value) for:
   - a header failing §5.2 checks 1–5, including invalid PoW;
   - a presync commitment mismatch;
   - a block failing blocks.md §4 steps 7–12, except the high-bandwidth
     compact relay case in §7;
   - protocol violations: malformed known messages, non-linking `headers`,
     messages sent before the handshake completes, more items than a message
     allows.

   Disconnect without a ban for:
   - bad magic or checksum;
   - oversized length;
   - timeouts;
   - stalling.

   Never penalize:
   - blocks or headers deferred by the future-drift rule;
   - valid low-work chains;
   - unknown commands, inventory types or service bits;
   - `notfound`;
   - policy-rejected transactions.

   For inbound Tor/I2P peers, "ban" means disconnect and deprioritize, since
   their address cannot be banned meaningfully.

## 11. Resource ceilings (per peer unless stated; initial values)

| Resource | Limit |
| --- | --- |
| Receive buffer | one frame header plus one payload ≤ its maximum (§2) |
| Send buffer | 5 MB; stop reading from the peer while it is exceeded |
| Bandwidth | optional upload cap per day; blocks for the active chain's last 288 blocks are always served |
| Headers per message | 2,000 |
| Inventory items per message | 5,000 |
| Addresses per message | 1,000; rate limit as in §4 |
| Blocks in flight | 16 |
| Presync sessions | 1 per peer; global cap 8, queued per §5.4 |
| Signature verification | token bucket, §8 |
| RandomX cache builds | §9 (per peer and global) |
| Orphan transactions | 10 per peer; 100 / 2 MB global |
| Unanswered `getdata` for transactions | 100 in flight |

## 12. Versioning and service bits

| Bit | Name | Meaning |
| --- | --- | --- |
| 0 | `NODE_NETWORK` | serves the full block chain |
| 1 | `NODE_PRUNED` | serves at least the last 288 blocks of its active chain, and all headers |

- Unknown service bits are ignored.
- The protocol version is negotiated as described in §3. A new message MUST
  be gated on the negotiated version, or on a feature message such as
  `sendcmpct`.
- Unknown messages are ignored, not banned. This is how new features roll
  out without breaking older peers.

## 13. Privacy

- By default, nodes MUST NOT write peer IP addresses or onion/I2P addresses
  to logs. Logs use local peer ids. Address logging is an explicit opt-in
  debug option.
- Tor and I2P are supported for both outbound and inbound connections. A
  node MAY be restricted to only those networks. A Tor-only node MUST NOT
  leak clearnet addresses in `version` or `addr`.
- Peer-supplied time (`version.timestamp`, `addr.time`) MUST NOT be used for
  any validation, acceptance or difficulty decision. Nodes use only their own
  clock (difficulty.md §3). A node MAY show a warning when many peers'
  clocks differ from its own.
- `user_agent` SHOULD be generic, and SHOULD NOT reveal platform details.
- Transaction trickling (§8) treats a node's own transactions exactly like
  relayed ones.

## 14. Threat mapping

| Threat (registers/threats.md) | Mitigations in this document |
| --- | --- |
| T-N1 eclipse | §4 keyed bucketing by network group, new/tried tables, seeds bootstrap only; §10.1 eight diverse outbound plus 2 block-relay-only plus feelers and stale-tip extra peer; §10.2 anchors; §10.3 eviction protection; §0 any more-work chain is always fetched, so one honest peer suffices |
| T-N2 DoS | §2 length checked before allocation, per-command maxima, checksum; §8 verification budgets and check order; §9 cache budgets; §10.4 bans; §11 ceilings |
| T-N3 low-work fork flood | §5.3 presync with O(1) state and commitment bits; gating only for chains proven below the tip; §9 queued, rate-limited cache builds; bans for invalid PoW; `POW_LIMIT` (blocks.md §6.3) makes each fork header cost real work |
| T-C2 selfish mining | §7 high-bandwidth compact relay to cut propagation delay; §5.3 near-tip fork headers kept so competing tips are visible for monitoring; §10.1 block-relay-only links. Residual risk: the first-seen tie rule (blocks.md §5) favours well-connected attackers (Q5) |

## 15. Open questions

- **Q1 (resolved in v0.2).** blocks.md v0.3 §6 now matches §0; p2p.md is
  listed in protocol/README.md as normative for node behaviour, not consensus.
- **Q2 (resolved in v0.2).** No timeout on `MIN_CHAIN_WORK` (§5.3 item 4).
- **Q3 (resolved in v0.2).** Default 3 caches, 2 allowed (§9).
- **Q4.** Encrypted transport: BIP-324 uses ECDH, which is not post-quantum.
  Should v2 transport use ML-KEM or a hybrid?
- **Q5.** First-seen tie-breaking and selfish mining: should equal-work ties
  be resolved differently? Any change would be a blocks.md matter, not p2p.
- **Q6.** Are 6-byte short ids sufficient, given the per-block, per-connection
  salt and a mempool of up to about 18,000 typical transactions?
- **Q7.** Port numbers, DNS seed operators and the `MIN_RELAY_FEERATE` unit
  are placeholders.
