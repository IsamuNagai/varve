# Varve node public API (read-only, v1)

A node started with `--api-port <port>` serves this HTTP API. It is used by the
Varvescan explorer and the Strata wallet. It exposes only public chain data. There
are no wallet, mining or administration functions; those stay on the cookie-protected
JSON-RPC port.

- It binds to `127.0.0.1` by default. To publish it, put it behind a TLS reverse proxy
  (for example Caddy) and pass `--api-bind 0.0.0.0` only if you understand the exposure.
  `--api-trust-proxy` makes the rate limiter use the last address in `X-Forwarded-For`.
- Responses are `application/json; charset=utf-8` and carry
  `Access-Control-Allow-Origin: *` (public data), `X-Content-Type-Options: nosniff`
  and `Cache-Control: no-store`, `max-age=5` or `max-age=31536000, immutable` as appropriate.
- Errors are `{"error": "<message>"}` with status 400 (bad request), 404 (not found),
  405, 413 (body too large), 429 (rate limited) or 503 (still syncing).
- Every amount is a **decimal string of laminae** (1 VARV = 100,000,000 laminae),
  because amounts can exceed 2^53. Heights, sizes, weights, fee rates and times are
  JSON numbers. Hashes are lowercase hex in display order, the same bytes the node
  prints. Addresses are Bech32m: `varve1…` on mainnet, `tvarve1…` on testnet,
  `rvarve1…` on regtest.
- Rate limit: a token bucket per client IP, 20 requests/second with a burst of 60.
  `POST /api/v1/tx` costs 10 tokens.

## Endpoints

### `GET /api/v1/info`
```json
{"network":"testnet","height":1234,"best":"<hash>","time":1793000000,
 "mtp":1792999000,"target":"<hex u256>","difficulty":"<decimal>",
 "mempool":{"count":3,"weight":15000},"supply":"<laminae>",
 "genesis":"<hash>","hrp":"tvarve","syncing":false,"version":"0.1.0"}
```
`target` is always 64 hex characters (zero-padded). `difficulty` is the genesis target divided by the current target, as a decimal string with up to 8 decimals.

### `GET /api/v1/blocks?before=<height>&limit=<n>`
The newest blocks with height `< before` (default: tip + 1). `limit` ≤ 50, default 20.
```json
{"blocks":[{"height":1234,"hash":"…","time":1793000000,"txs":2,"size":5400,
            "weight":5600,"reward":"8200005000","miner":"tvarve1…"}]}
```
`miner` is the address of the coinbase's first output. `txs` counts the coinbase.

### `GET /api/v1/block/<hash or height>`
```json
{"height":1234,"hash":"…","prev":"…","next":"…"|null,"time":…,"mtp":…,
 "target":"…","nonce":"…","size":…,"weight":…,"confirmations":1,
 "reward":"…","subsidy":"…","fees":"…","miner":"tvarve1…",
 "txids":["…", …]}
```
`nonce` is a decimal string.

### `GET /api/v1/tx/<txid>`
```json
{"txid":"…","wtxid":"…","status":"confirmed"|"mempool",
 "height":1234|null,"block":"…"|null,"time":…|null,"confirmations":0,
 "coinbase":false,"size":…,"weight":…,"fee":"…"|null,"feerate":2.5|null,"locktime":0,
 "inputs":[{"txid":"…","index":0,"amount":"…","address":"tvarve1…","path":0}],
 "outputs":[{"index":0,"amount":"…","address":"tvarve1…","scheme":"ML-DSA-65",
             "recovery":{"scheme":"SLH-DSA-SHA2-128s","delay":52560}|null,
             "spent_by":{"txid":"…","input":0}|null}]}
```
For `path` 2 the authorizing signature is the earliest input of the same transaction whose spent output has the same address key. The coinbase has `inputs: []`, `fee: null` and `feerate: null`. `path` is 0 (primary key), 1 (recovery key) or 2 (shared with an earlier input). `time` is the block time.

### `GET /api/v1/address/<address>`
```json
{"address":"tvarve1…","balance":"…","received":"…","sent":"…",
 "tx_count":12,"utxo_count":3,"unconfirmed":"<signed laminae>",
 "first_seen":{"height":100,"txid":"…","time":…}|null,
 "funded_by":[{"txid":"…","height":100,"amount":"…","from":"tvarve1…"|"coinbase"}]}
```
A valid address with no history returns zeros (not 404); an address for another network or with a bad checksum returns 400. `balance`, `received` and `sent` count confirmed transactions only. `unconfirmed` is the net effect of mempool transactions. `funded_by` lists the first (up to 10) confirmed transactions that paid this address, each with the address of that transaction's first input, or `"coinbase"`.

### `GET /api/v1/address/<address>/txs?before=<height>&limit=<n>`
Newest first. Mempool transactions come first on the first page (no `before`) and count toward `limit`. `limit` ≤ 50, default 25. A page never ends partway through a block height: it may run past `limit` to finish the height, so `before=<next>` never skips entries.
```json
{"txs":[{"txid":"…","height":1234|null,"time":…|null,"delta":"-150000","fee":"…"|null}],
 "next":1200|null}
```
`delta` is the signed net change to this address in laminae. Pass `next` as `before` to get the next page.

### `GET /api/v1/address/<address>/utxos`
```json
{"height":1234,"utxos":[{"txid":"…","index":0,"amount":"…","height":1200,"coinbase":false,
            "mature":true,"spent_in_mempool":false,"output":"<hex>"}]}
```
`output` is the serialized output (transactions.md §2): amount, version, template. Wallets use it to compute the signature message. Because the message commits to every spent output, a server that lies here can only make the transaction invalid; it cannot redirect funds. At most 1,000 coins are returned (largest first).

### `GET /api/v1/mempool`
```json
{"count":3,"weight":15000,"txs":[{"txid":"…","fee":"…","weight":…,"feerate":2.5,"time":…}]}
```
At most 100 transactions, highest fee rate first. `time` is when this node first accepted the transaction.

### `GET /api/v1/fees`
```json
{"min":1,"slow":1,"normal":2,"fast":5}
```
Fee rates in laminae per weight unit.

### `POST /api/v1/tx`
The body is the transaction as hex text, at most 400,000 characters. On success: `200 {"txid":"…"}`. On rejection: `400 {"error":"…"}`.

### `GET /api/v1/search?q=<text>`
`{"type":"block"|"tx"|"address","id":"…"}` or 404. Any valid address for this network returns `type: "address"`, even if it has no history. A number is a height, 64 hex characters a block or a transaction, `…varve1…` an address.

### `OPTIONS` (any path)
CORS preflight: `204` with `Access-Control-Allow-Methods: GET, POST, OPTIONS` and `Access-Control-Allow-Headers: Content-Type`.
