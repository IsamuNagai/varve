#!/usr/bin/env python3
"""End-to-end test of Strata against a real regtest node (Python stdlib only).

1. Start Strata (regtest, no browser) and create a wallet through /local/*.
2. Start a regtest node that mines to Strata's first receive address and serves the
   public API (--api-port, node/API.md).
3. Acting as the browser UI: read coins from the API, ask Strata to build a payment
   to the node's wallet, broadcast it through the API, and wait for it to confirm.
   The payment spends many coinbase outputs of one key: one signature plus shared
   (path 2) witnesses.
4. Spend everything that is left (send max), including the change output of step 3.
5. Lock: building now fails; the request guard refuses a wrong Host and a missing token.

Usage: python3 -I node/tests/strata_e2e.py path/to/strata path/to/varve
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

STRATA = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "node/target/release/strata")
VARVE = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "node/target/release/varve")
TMP = os.environ.get("STRATA_E2E_DIR") or tempfile.mkdtemp(prefix="strata-e2e-")
SLOW = float(os.environ.get("VARVE_E2E_SLOW", "1"))
NODE_PORT, API_PORT = 51300, 51311
COIN = 100_000_000
PROCS = []


def ok(msg):
    print(f"ok   {msg}", flush=True)


def wait(cond, what, timeout=300):
    timeout *= SLOW
    t = time.time()
    last = None
    while time.time() - t < timeout:
        try:
            if cond():
                return
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(1)
    log = os.path.join(TMP, "node", "log.txt")
    if os.path.exists(log):
        print(open(log).read()[-3000:])
    raise SystemExit(f"timeout waiting for: {what} (last error: {last})")


def http(method, url, body=None, headers=None):
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:  # noqa: BLE001
            return e.code, None


def api(path, body=None):
    for attempt in range(10):
        s, j = http("POST" if body is not None else "GET", f"http://127.0.0.1:{API_PORT}{path}", body, {"Content-Type": "text/plain"} if body else None)
        if s != 429:
            break
        time.sleep(1 + attempt)  # the node's rate limiter: back off and retry
    if s != 200:
        raise RuntimeError(f"API {path}: {s} {j}")
    return j


class Strata:
    def __init__(self):
        d = os.path.join(TMP, "strata")
        self.p = subprocess.Popen([STRATA, "--network", "regtest", "--no-browser", "--datadir", d], stdout=subprocess.PIPE, stderr=open(os.path.join(TMP, "strata.log"), "w"), text=True)
        PROCS.append(self.p)
        for _ in range(50):
            m = re.search(r"http://127\.0\.0\.1:(\d+)/#token=([0-9a-f]{64})", self.p.stdout.readline())
            if m:
                self.port, self.token = int(m.group(1)), m.group(2)
                return
        raise SystemExit("strata did not start")

    def call(self, method, path, body=None, headers=None):
        h = {"X-Strata-Token": self.token, "Content-Type": "application/json"}
        h.update(headers or {})
        return http(method, f"http://127.0.0.1:{self.port}{path}", json.dumps(body) if body is not None else None, h)

    def ok(self, method, path, body=None):
        s, j = self.call(method, path, body)
        if s != 200:
            raise SystemExit(f"strata {path}: {s} {j}")
        return j


def rpc(method, *params):
    d = os.path.join(TMP, "node")
    out = subprocess.run([VARVE, "rpc", "--network", "regtest", "--datadir", d, "--port", str(NODE_PORT), method, *map(str, params)], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"{method}: {out.stderr.strip()}")
    return out.stdout.strip()


def coins(addresses):
    utxos, height = [], None
    for a in addresses:
        j = api(f"/api/v1/address/{a}/utxos")
        height = j["height"] if height is None else min(height, j["height"])
        utxos += j["utxos"]
    return utxos, height


def build_and_send(st, to, amount=None, send_max=False):
    addrs = st.ok("GET", "/local/addresses")
    all_addrs = [a["address"] for a in addrs["receive"] + addrs["change"]]
    with_funds = [a for a in all_addrs if api(f"/api/v1/address/{a}")["utxo_count"] > 0]
    utxos, height = coins(with_funds)
    fees = api("/api/v1/fees")
    body = {"to": to, "feerate": fees["normal"], "height": height, "utxos": utxos, "send_max": send_max}
    if amount is not None:
        body["amount_laminae"] = str(amount)
    b = st.ok("POST", "/local/build", body)
    r = api("/api/v1/tx", b["hex"])
    assert r["txid"] == b["txid"], (r, b["txid"])
    if b["change_index"] is not None:
        st.ok("POST", "/local/mark_used", {"change": [b["change_index"]]})
    return b, utxos, height


def main():
    for p in (STRATA, VARVE):
        if not os.path.exists(p):
            raise SystemExit(f"missing binary {p}")
    h = subprocess.run([VARVE, "help"], capture_output=True, text=True)
    if "--api-port" not in h.stdout + h.stderr:
        raise SystemExit("FAIL: this varve binary has no --api-port (node/API.md)")

    st = Strata()
    status = st.ok("GET", "/local/status")
    assert status["network"] == "regtest" and status["hrp"] == "rvarve" and not status["has_wallet"]
    created = st.ok("POST", "/local/create", {"file_pass": "e2e river copper lantern"})
    assert len(created["mnemonic"]) == 24
    addrs = st.ok("GET", "/local/addresses")
    mine_to = addrs["receive"][0]["address"]
    ok(f"strata wallet created; mining to {mine_to[:20]}...")

    nd = os.path.join(TMP, "node")
    os.makedirs(nd, exist_ok=True)
    log = open(os.path.join(nd, "log.txt"), "a")
    node = subprocess.Popen([VARVE, "node", "--network", "regtest", "--datadir", nd, "--port", str(NODE_PORT), "--nolisten",
                             "--mine", "--threads", "1", "--mine-to", mine_to, "--api-port", str(API_PORT)], stdout=log, stderr=subprocess.STDOUT)
    PROCS.append(node)
    wait(lambda: api("/api/v1/info")["height"] >= 300, "node mines 300 blocks")
    info = api("/api/v1/info")
    assert info["genesis"] == status["genesis"], "strata and the node disagree on the regtest genesis"
    assert info["hrp"] == "rvarve"
    ok(f"node at height {info['height']}, genesis matches strata")

    st.ok("POST", "/local/settings", {"api_endpoint": f"http://127.0.0.1:{API_PORT}"})
    dest = rpc("getnewaddress")
    b, utxos, height = build_and_send(st, dest, amount=100 * COIN)
    mature = [u for u in utxos if u["mature"] and not u["spent_in_mempool"]]
    tx = api(f"/api/v1/tx/{b['txid']}")
    paths = [i["path"] for i in tx["inputs"]]
    assert paths[0] == 0 and paths.count(0) == 1 and all(p == 2 for p in paths[1:]), paths
    assert len(paths) == len(mature), (len(paths), len(mature))
    assert int(b["amount"]) == 100 * COIN and int(b["change"]) > 0
    assert int(b["fee"]) == b["weight"] * b["feerate"]
    ok(f"built and broadcast {b['txid'][:16]}...: {len(paths)} coinbase inputs, 1 signature + {len(paths) - 1} shared witnesses, fee {b['fee']} laminae")

    wait(lambda: api(f"/api/v1/tx/{b['txid']}")["status"] == "confirmed", "payment confirms", 180)
    assert api(f"/api/v1/address/{dest}")["balance"] == str(100 * COIN)
    ok(f"payment confirmed at height {api('/api/v1/tx/' + b['txid'])['height']}; recipient balance 100 VARV")

    # change is on change address 0 now; spend everything that is spendable
    wait(lambda: api(f"/api/v1/address/{b['change_address']}")["balance"] == b["change"], "change visible", 60)
    dest2 = rpc("getnewaddress")
    b2, utxos2, _ = build_and_send(st, dest2, send_max=True)
    assert b2["change_index"] is None and int(b2["change"]) == 0
    tx2 = api(f"/api/v1/tx/{b2['txid']}")
    assert len(tx2["outputs"]) == 1
    keys = {u["output"][18:] for u in utxos2 if u["mature"] and not u["spent_in_mempool"]}
    assert [i["path"] for i in tx2["inputs"]].count(0) == len(keys), "one signature per key"
    wait(lambda: api(f"/api/v1/tx/{b2['txid']}")["status"] == "confirmed", "send-max confirms", 180)
    ok(f"send max confirmed: {len(tx2['inputs'])} inputs from {len(keys)} keys (coinbase + change), amount {int(b2['amount']) / COIN} VARV")

    # foreign coin: the node's coin offered as ours is refused
    foreign, h = coins([dest])
    s, j = st.call("POST", "/local/build", {"to": dest, "amount_laminae": "1000", "feerate": 1, "height": h, "utxos": foreign})
    assert s == 400 and "does not belong" in j["error"], (s, j)
    ok("a coin of another wallet is refused")

    # guard checks on the live server
    s, _ = http("GET", f"http://127.0.0.1:{st.port}/local/status", headers={"Host": f"evil.example:{st.port}", "X-Strata-Token": st.token})
    assert s == 421, s
    s, _ = http("GET", f"http://127.0.0.1:{st.port}/local/status")
    assert s == 401, s
    s, _ = st.call("POST", "/local/lock", {}, headers={"Origin": "http://evil.example"})
    assert s == 403, s
    ok("wrong Host, missing token and foreign Origin are refused")

    st.ok("POST", "/local/lock", {})
    s, _ = st.call("GET", "/local/addresses")
    assert s == 423, s
    st.ok("POST", "/local/unlock", {"file_pass": "e2e river copper lantern"})
    ok("lock and unlock work")
    print("ALL STRATA E2E CHECKS PASSED")


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in PROCS:
            p.terminate()
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()
        if os.environ.get("KEEP") != "1":
            shutil.rmtree(TMP, ignore_errors=True)
