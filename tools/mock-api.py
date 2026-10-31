#!/usr/bin/env python3
"""Mock of the Varve node public API (node/API.md) for testing Varvescan locally.

  python3 -I tools/mock-api.py [--port 8765]

Then serve the site and open the explorer against the mock:

  python3 -m http.server --bind 127.0.0.1 --directory docs 8000
  http://127.0.0.1:8000/scan/?api=http://127.0.0.1:8765

The data is fake but follows the API shapes: a deterministic chain of 150 blocks
with real Bech32m testnet addresses, a mempool, an address index and fee rates.
Some fields deliberately carry hostile strings (HTML and script in error messages,
in one mempool transaction's output and in one block's txid list) so the
explorer's escaping and validation can be checked. Special requests:

  /api/v1/block/777777   429 rate limited
  /api/v1/block/888888   503 still syncing
  /api/v1/block/999999   answers after 20 s (client timeout)

Standard library only. Binds to 127.0.0.1.
"""
import hashlib
import json
import random
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LAMINAE = 100_000_000
SUBSIDY = 82 * LAMINAE
SPACING = 300
BLOCKS = 150
HRP = "tvarve"
HOSTILE = '<img src=x onerror=alert(1)>'

# ------------------------------------------------------------------ Bech32m
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def convertbits(data, frombits, tobits):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32m(hrp, data):
    pm = polymod(hrp_expand(hrp) + data + [0] * 6) ^ BECH32M_CONST
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + chk)


def make_address(seed, recovery):
    h = hashlib.sha256(seed.encode()).digest()
    payload = bytes([1 if recovery else 0, 1, 0]) + h
    if recovery:
        payload += bytes([2, 0]) + bytes([0x50, 0xCD, 0, 0]) + hashlib.sha256(h).digest()[:32]
    return bech32m(HRP, [1] + convertbits(payload, 8, 5))


def sha(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


# ------------------------------------------------------------------ chain
class Chain:
    def __init__(self):
        rnd = random.Random(7)
        self.rnd = rnd
        self.wallets = [make_address(f"wallet-{i}", recovery=(i % 3 == 0)) for i in range(14)]
        self.recovery = {a: (i % 3 == 0) for i, a in enumerate(self.wallets)}
        self.miners = self.wallets[:4]
        self.blocks, self.by_hash, self.txs = [], {}, {}
        self.utxos = {}  # (txid, index) -> output info
        self.addr_txs = {}  # address -> list of (txid)
        now = int(time.time())
        gaps = [max(20, int(rnd.expovariate(1 / SPACING))) for _ in range(BLOCKS - 1)]
        t = now - 75 - sum(gaps)
        for h in range(BLOCKS):
            if h:
                t += gaps[h - 1]
            self.add_block(h, t)
        self.mempool = []
        for i in range(6):
            tx = self.make_tx(None, now - rnd.randint(5, 900))
            if tx:
                self.mempool.append(tx["txid"])
        self.add_hostile_mempool_tx(now - 30)

    def out(self, address, amount):
        return {"amount": amount, "address": address, "scheme": "ML-DSA-65",
                "recovery": {"scheme": "SLH-DSA-SHA2-128s", "delay": 52560} if self.recovery.get(address) else None}

    def index_tx(self, tx):
        for io in tx["inputs"] + tx["outputs"]:
            a = io["address"]
            if re.fullmatch(r"[a-z0-9]+", a):
                lst = self.addr_txs.setdefault(a, [])
                if tx["txid"] not in lst:
                    lst.append(tx["txid"])

    def make_tx(self, height, t):
        rnd = self.rnd
        owners = {}
        for k, o in self.utxos.items():
            if not o.get("pending"):
                owners.setdefault(o["address"], []).append(k)
        owners = {a: ks for a, ks in owners.items() if ks}
        if not owners:
            return None
        frm = rnd.choice(sorted(owners))
        keys = sorted(owners[frm])
        rnd.shuffle(keys)
        spend = keys[:rnd.randint(1, min(3, len(keys)))]
        total = sum(self.utxos[k]["amount"] for k in spend)
        n_in, n_out = len(spend), 2
        size = 12 + n_in * 5306 + n_out * 48
        weight = size + n_out * 52 + 40
        feerate = rnd.choice([1, 1, 2, 2, 2.5, 3, 5, 8])
        fee = int(weight * feerate)
        if total <= fee + 1000:
            return None
        to = rnd.choice([w for w in self.wallets if w != frm])
        pay = rnd.randint(1, total - fee - 1)
        pay = max(1, pay - pay % 1000) if rnd.random() < 0.6 else pay
        change = total - fee - pay
        txid = sha("tx", height, t, spend)
        inputs = []
        for i, k in enumerate(spend):
            o = self.utxos[k]
            path = 0 if i == 0 else 2
            if i == 0 and o["recovery"] and rnd.random() < 0.25:
                path = 1
            inputs.append({"txid": k[0], "index": k[1], "amount": str(o["amount"]), "address": o["address"], "path": path})
            if height is None:
                o["pending"] = True
            self.txs[k[0]]["outputs"][k[1]]["spent_by"] = {"txid": txid, "input": i}
        outs = [self.out(to, pay), self.out(frm, change)]
        tx = {"txid": txid, "wtxid": sha("w", txid), "status": "confirmed" if height is not None else "mempool",
              "height": height, "block": None, "time": t if height is not None else None, "confirmations": 0,
              "coinbase": False, "size": size, "weight": weight, "fee": str(fee),
              "feerate": round(fee / weight, 3), "locktime": 0, "inputs": inputs,
              "outputs": [dict(o, index=i, amount=str(o["amount"]), spent_by=None) for i, o in enumerate(outs)],
              "_seen": t}
        self.txs[txid] = tx
        if height is not None:
            for k in spend:
                del self.utxos[k]
            for i, o in enumerate(outs):
                self.utxos[(txid, i)] = dict(o, height=height, coinbase=False)
        self.index_tx(tx)
        return tx

    def add_block(self, h, t):
        rnd = self.rnd
        txs = []
        if h >= 3:
            for _ in range(rnd.choice([0, 1, 1, 2, 3, 4, 6])):
                tx = self.make_tx(h, t)
                if tx:
                    txs.append(tx)
        fees = sum(int(x["fee"]) for x in txs)
        miner = self.miners[h % len(self.miners)] if h % 7 else self.wallets[4 + h % 10]
        reward = SUBSIDY + fees
        cb_id = sha("cb", h)
        cb = {"txid": cb_id, "wtxid": sha("w", cb_id), "status": "confirmed", "height": h, "block": None, "time": t,
              "confirmations": 0, "coinbase": True, "size": 160, "weight": 520, "fee": None, "feerate": None,
              "locktime": 0, "inputs": [],
              "outputs": [dict(self.out(miner, reward), index=0, amount=str(reward), spent_by=None)]}
        self.txs[cb_id] = cb
        self.utxos[(cb_id, 0)] = dict(self.out(miner, reward), height=h, coinbase=True)
        self.index_tx(cb)
        all_txs = [cb] + txs
        prev = self.blocks[-1]["hash"] if self.blocks else "0" * 64
        bhash = "0000" + sha("block", h, prev)[4:]
        size = 80 + sum(x["size"] for x in all_txs)
        b = {"height": h, "hash": bhash, "prev": prev, "next": None, "time": t,
             "mtp": t - 5 * SPACING if h > 10 else t, "target": "0000" + "f" * 4 + sha("target", h // 50)[8:],
             "nonce": str(int(sha("nonce", h)[:15], 16)), "size": size, "weight": size + 40 * len(all_txs),
             "reward": str(reward), "subsidy": str(SUBSIDY), "fees": str(fees), "miner": miner,
             "txids": [x["txid"] for x in all_txs]}
        if self.blocks:
            self.blocks[-1]["next"] = bhash
        for x in all_txs:
            x["block"] = bhash
        if h == 5:
            b["miner"] = '"><img src=x onerror=alert(1)>'
        if h == 7:
            b["txids"] = b["txids"] + ['<b onclick="alert(1)">bad</b>']
        self.blocks.append(b)
        self.by_hash[bhash] = b

    def add_hostile_mempool_tx(self, t):
        txid = sha("hostile")
        src = next(k for k, o in sorted(self.utxos.items()) if not o.get("pending"))
        o = self.utxos[src]
        o["pending"] = True
        self.txs[src[0]]["outputs"][src[1]]["spent_by"] = {"txid": txid, "input": 0}
        tx = {"txid": txid, "wtxid": sha("w", txid), "status": "mempool", "height": None, "block": None, "time": None,
              "confirmations": 0, "coinbase": False, "size": 5400, "weight": 5600, "fee": "5600", "feerate": 1,
              "locktime": 0,
              "inputs": [{"txid": src[0], "index": src[1], "amount": str(o["amount"]), "address": o["address"], "path": 0}],
              "outputs": [
                  {"index": 0, "amount": "1000", "address": '"><img src=x onerror=alert(1)>',
                   "scheme": "<script>alert(1)</script>", "recovery": {"scheme": "javascript:alert(1)", "delay": "52560"},
                   "spent_by": {"txid": "javascript:alert(1)", "input": 0}},
                  {"index": 1, "amount": str(o["amount"] - 6600), "address": o["address"], "scheme": "ML-DSA-65",
                   "recovery": None, "spent_by": None}],
              "_seen": t}
        self.txs[txid] = tx
        self.mempool.append(txid)
        self.index_tx(tx)

    # -------------------------------------------------------------- views
    @property
    def tip(self):
        return self.blocks[-1]

    def tx_view(self, txid):
        tx = dict(self.txs[txid])
        tx.pop("_seen", None)
        if tx["status"] == "confirmed":
            tx["confirmations"] = self.tip["height"] - tx["height"] + 1
        return tx

    def block_view(self, b):
        return dict(b, confirmations=self.tip["height"] - b["height"] + 1)

    def supply(self):
        return str(SUBSIDY * len(self.blocks))

    def address_view(self, a):
        bal = rec = sent = 0
        unconf = 0
        funded = []
        first = None
        count = 0
        for txid in self.addr_txs.get(a, []):
            tx = self.txs[txid]
            d = sum(int(o["amount"]) for o in tx["outputs"] if o["address"] == a) - \
                sum(int(i["amount"]) for i in tx["inputs"] if i["address"] == a)
            gain = sum(int(o["amount"]) for o in tx["outputs"] if o["address"] == a)
            loss = sum(int(i["amount"]) for i in tx["inputs"] if i["address"] == a)
            if tx["status"] == "mempool":
                unconf += d
                continue
            count += 1
            rec += gain
            sent += loss
            if first is None:
                first = {"height": tx["height"], "txid": txid, "time": tx["time"]}
            if gain and len(funded) < 10:
                funded.append({"txid": txid, "height": tx["height"], "amount": str(gain),
                               "from": "coinbase" if tx["coinbase"] else tx["inputs"][0]["address"]})
        bal = rec - sent
        utxo_count = sum(1 for o in self.utxos.values() if o["address"] == a)
        return {"address": a, "balance": str(bal), "received": str(rec), "sent": str(sent), "tx_count": count,
                "utxo_count": utxo_count, "unconfirmed": str(unconf), "first_seen": first, "funded_by": funded}

    def address_txs(self, a, before, limit):
        rows = []
        for txid in self.addr_txs.get(a, []):
            tx = self.txs[txid]
            d = sum(int(o["amount"]) for o in tx["outputs"] if o["address"] == a) - \
                sum(int(i["amount"]) for i in tx["inputs"] if i["address"] == a)
            rows.append({"txid": txid, "height": tx["height"], "time": tx["time"], "delta": str(d), "fee": tx["fee"]})
        mem = [r for r in rows if r["height"] is None]
        conf = sorted((r for r in rows if r["height"] is not None), key=lambda r: -r["height"])
        page = mem if before is None else []
        conf = [r for r in conf if before is None or r["height"] < before]
        # take whole heights so that "before=next" never skips a transaction
        nxt = None
        for i, r in enumerate(conf):
            if len(page) >= limit and r["height"] != page[-1]["height"]:
                nxt = page[-1]["height"]
                break
            page.append(r)
        return {"txs": page, "next": nxt}


CHAIN = None


class Handler(BaseHTTPRequestHandler):
    server_version = "varve-mock"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("mock-api: " + (fmt % args) + "\n")

    def send(self, status, obj, cache="no-store"):
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def err(self, status, msg):
        self.send(status, {"error": msg})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        self.err(400, "the mock does not accept transactions")

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        p = u.path
        c = CHAIN

        def limit(default=20):
            n = int(q.get("limit", default))
            if not 1 <= n <= 50:
                raise ValueError("limit must be 1..50")
            return n

        try:
            if p == "/api/v1/info":
                mp_w = sum(c.txs[t]["weight"] for t in c.mempool)
                return self.send(200, {"network": "testnet", "height": c.tip["height"], "best": c.tip["hash"],
                                       "time": c.tip["time"], "mtp": c.tip["mtp"], "target": c.tip["target"],
                                       "difficulty": "1.84213377", "mempool": {"count": len(c.mempool), "weight": mp_w},
                                       "supply": c.supply(), "genesis": c.blocks[0]["hash"], "hrp": HRP,
                                       "syncing": False, "version": "0.1.0"}, "max-age=5")
            if p == "/api/v1/fees":
                return self.send(200, {"min": 1, "slow": 1, "normal": 2, "fast": 5}, "max-age=5")
            if p == "/api/v1/blocks":
                before = int(q.get("before", c.tip["height"] + 1))
                n = limit()
                bs = [b for b in reversed(c.blocks) if b["height"] < before][:n]
                return self.send(200, {"blocks": [{k: b[k] for k in ("height", "hash", "time", "size", "weight", "reward", "miner")}
                                                  | {"txs": len(b["txids"])} for b in bs]})
            m = re.fullmatch(r"/api/v1/block/([^/]+)", p)
            if m:
                ident = m.group(1)
                if ident == "777777":
                    return self.err(429, "rate limited " + HOSTILE)
                if ident == "888888":
                    return self.err(503, "still syncing")
                if ident == "999999":
                    time.sleep(20)
                    return self.err(404, "block not found")
                b = None
                if re.fullmatch(r"[0-9]{1,10}", ident) and int(ident) < len(c.blocks):
                    b = c.blocks[int(ident)]
                elif ident in c.by_hash:
                    b = c.by_hash[ident]
                if not b:
                    return self.err(404, HOSTILE + " block not found")
                return self.send(200, c.block_view(b))
            m = re.fullmatch(r"/api/v1/tx/([^/]+)", p)
            if m:
                if m.group(1) not in c.txs:
                    return self.err(404, HOSTILE + " transaction not found")
                return self.send(200, c.tx_view(m.group(1)))
            m = re.fullmatch(r"/api/v1/address/([^/]+)(/txs|/utxos)?", p)
            if m:
                a = m.group(1)
                if not re.fullmatch(r"[a-z]+1[a-z0-9]{6,200}", a):
                    return self.err(400, HOSTILE + " invalid address")
                if not a.startswith(HRP + "1"):
                    return self.err(400, "address is for another network")
                if m.group(2) == "/txs":
                    before = int(q["before"]) if "before" in q else None
                    return self.send(200, c.address_txs(a, before, limit()))
                if m.group(2) == "/utxos":
                    return self.send(200, {"height": c.tip["height"], "utxos": []})
                return self.send(200, c.address_view(a))
            if p == "/api/v1/mempool":
                txs = sorted((c.txs[t] for t in c.mempool), key=lambda t: -t["feerate"])
                return self.send(200, {"count": len(c.mempool), "weight": sum(t["weight"] for t in txs),
                                       "txs": [{"txid": t["txid"], "fee": t["fee"], "weight": t["weight"],
                                                "feerate": t["feerate"], "time": t["_seen"]} for t in txs]})
            if p == "/api/v1/search":
                s = q.get("q", "").strip().lower()
                if re.fullmatch(r"[0-9]{1,10}", s) and int(s) < len(c.blocks):
                    return self.send(200, {"type": "block", "id": c.blocks[int(s)]["hash"]})
                if s in c.by_hash:
                    return self.send(200, {"type": "block", "id": s})
                if s in c.txs:
                    return self.send(200, {"type": "tx", "id": s})
                if "varve1" in s and re.fullmatch(r"[a-z0-9]+", s):
                    return self.send(200, {"type": "address", "id": s})
                return self.err(404, HOSTILE + " no match")
            return self.err(404, "unknown endpoint")
        except (ValueError, KeyError) as e:
            return self.err(400, "bad request: " + str(e))


def main():
    global CHAIN
    port = 8765
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    CHAIN = Chain()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock-api: {len(CHAIN.blocks)} blocks, {len(CHAIN.txs)} transactions, "
          f"{len(CHAIN.mempool)} in mempool on http://127.0.0.1:{port}", flush=True)
    print(f"mock-api: example address {CHAIN.wallets[1]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
