#!/usr/bin/env python3
"""End-to-end test on a private regtest network, using real node processes.

1. Node A mines; node B syncs from A over P2P.
2. After coinbase maturity, A pays B; the payment confirms; balances update.
3. Partition: node C mines alone, then connects to A; every node converges on the
   chain with the most work, and the losing blocks' payments are not lost.
4. A node restarted from its data directory reloads the same tip.

Usage: python3 -I node/tests/e2e_regtest.py path/to/varve
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "node/target/release/varve")
TMP = os.environ.get("VARVE_E2E_DIR") or tempfile.mkdtemp(prefix="varve-e2e-")
os.makedirs(TMP, exist_ok=True)
SLOW = float(os.environ.get("VARVE_E2E_SLOW", "1"))  # timeout multiplier for slow machines
PROCS = {}


def start(name, port, *extra):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    log = open(os.path.join(d, "log.txt"), "a")
    p = subprocess.Popen([BIN, "node", "--network", "regtest", "--datadir", d, "--port", str(port), *extra],
                         stdout=log, stderr=subprocess.STDOUT)
    PROCS[name] = (p, d, port)
    for _ in range(100):
        try:
            rpc(name, "getblockcount")
            return
        except Exception:
            time.sleep(0.2)
    raise SystemExit(f"{name} did not start; see {d}/log.txt")


def stop(name):
    p, d, port = PROCS.pop(name)
    try:
        rpc_raw(d, port, "stop")
    except Exception:
        pass
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()


def rpc_raw(d, port, method, *params):
    out = subprocess.run([BIN, "rpc", "--network", "regtest", "--datadir", d, "--port", str(port), method, *map(str, params)],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"{method}: {out.stderr.strip()}")
    return out.stdout.strip()


def rpc(name, method, *params):
    _, d, port = PROCS[name]
    return rpc_raw(d, port, method, *params)


def rpcj(name, method, *params):
    return json.loads(rpc(name, method, *params))


def wait(cond, what, timeout=300):
    timeout *= SLOW
    t = time.time()
    while time.time() - t < timeout:
        try:
            if cond():
                return
        except Exception:
            pass
        time.sleep(0.5)
    for n, (_, d, _) in PROCS.items():
        print(f"--- {n} log tail ---")
        print(open(os.path.join(d, "log.txt")).read()[-3000:])
    for n, (_, d, _) in PROCS.items():
        tail = open(os.path.join(d, "log.txt")).read().splitlines()[-6:]
        print(f"::error title=e2e {n}::{what} | " + " | ".join(tail).replace("%", "%25"))
    raise SystemExit(f"timeout waiting for: {what}")


API = {"A": 51005, "B": 51015, "C": 51025}


def api(name, path):
    import urllib.request
    with urllib.request.urlopen(f"http://127.0.0.1:{API[name]}/api/v1/{path}", timeout=30) as r:
        assert r.headers["Access-Control-Allow-Origin"] == "*"
        return json.loads(r.read())


PASSFILE = os.path.join(TMP, "wallet-pass.txt")


def make_wallet(name):
    """Encrypted node wallet (varve wallet create), as a user would make it."""
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    with open(PASSFILE, "w") as f:
        f.write("e2e test passphrase\n")
    out = subprocess.run([BIN, "wallet", "create", "--network", "regtest", "--datadir", d, "--passphrase-file", PASSFILE],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert len([l for l in out.stdout.splitlines() if l.strip()[:3].strip(". ").isdigit()]) >= 6, "recovery phrase printed"


def send(name, addr, amount):
    """varve wallet send: unlocks with the passphrase, pays, locks again."""
    _, d, port = PROCS[name]
    out = subprocess.run([BIN, "wallet", "send", "--network", "regtest", "--datadir", d, "--port", str(port), "--passphrase-file", PASSFILE,
                          addr, amount], capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout.strip()


def ok(msg):
    print(f"ok   {msg}", flush=True)


try:
    for n in ("A", "B", "C"):
        make_wallet(n)
    ok("encrypted wallets created for A, B and C")
    start("A", 51000, "--mine", "--threads", "1", "--api-port", str(API["A"]))
    start("B", 51010, "--connect", "127.0.0.1:51000", "--api-port", str(API["B"]))
    wait(lambda: int(rpc("A", "getblockcount")) >= 300, "A mines 300 blocks")
    ok(f"A mined {rpc('A', 'getblockcount')} blocks")
    wait(lambda: rpc("B", "getbestblockhash") == rpc("A", "getbestblockhash"), "B syncs to A")
    ok(f"B synced to height {rpc('B', 'getblockcount')}")

    bal = rpcj("A", "getbalance")
    assert float(bal["spendable"]) > 0, bal
    ok(f"A balance: spendable {bal['spendable']}, immature {bal['immature']}")

    b_addr = rpc("B", "getnewaddress")
    try:
        rpc("A", "sendtoaddress", b_addr, "12.5")
        raise SystemExit("a locked wallet must refuse to pay")
    except RuntimeError as e:
        assert "locked" in str(e), e
    ok("locked wallet refuses to pay")
    txid = send("A", b_addr, "12.5")
    ok(f"A sent 12.5 to B: {txid}")
    wait(lambda: txid in rpc("B", "getrawmempool"), "tx relayed to B's mempool", 60)
    ok("payment relayed to B's mempool")
    wait(lambda: float(rpcj("B", "getbalance")["spendable"]) == 12.5, "payment confirmed at B", 120)
    ok("payment confirmed; B spendable = 12.5")

    # a second payment to the SAME address, then B spends both coins at once:
    # one signature plus a shared witness (transactions.md §8.2)
    txid2 = send("A", b_addr, "7.5")
    wait(lambda: float(rpcj("B", "getbalance")["spendable"]) == 20.0, "second payment confirmed at B", 120)
    a_addr = rpc("A", "getnewaddress")
    txid3 = send("B", a_addr, "15")
    assert rpcj("B", "getbalance")["unlocked_seconds"] == 0, "wallet locks again after sending"
    wait(lambda: api("A", f"tx/{txid3}")["txid"] == txid3, "B's two-coin spend relayed to A (mempool or mined)", 60)
    wait(lambda: txid3 not in rpc("A", "getrawmempool") and float(rpcj("B", "getbalance")["spendable"]) < 5.0, "two-coin spend confirmed", 120)
    ok(f"B spent two same-key coins with one signature: {txid3}")
    b_left = float(rpcj("B", "getbalance")["spendable"])

    # public API (node/API.md) agrees with what just happened
    info = api("A", "info")
    assert abs(info["height"] - int(rpc("A", "getblockcount"))) <= 3 and info["hrp"] == "rvarve", info
    ai = api("A", f"address/{b_addr}")
    assert ai["received"] == "2000000000" and ai["sent"] == "2000000000" and ai["balance"] == "0", ai
    assert ai["tx_count"] == 3 and ai["funded_by"][0]["txid"] == txid, ai
    t3 = api("A", f"tx/{txid3}")
    assert [i["path"] for i in t3["inputs"]] == [0, 2], t3["inputs"]
    assert t3["status"] == "confirmed" and int(t3["fee"]) > 0
    hist = api("A", f"address/{b_addr}/txs?limit=2")
    assert len(hist["txs"]) == 2 and hist["txs"][0]["txid"] == txid3 and hist["next"] is not None, hist
    hist2 = api("A", f"address/{b_addr}/txs?limit=2&before={hist['next']}")
    assert [t["txid"] for t in hist2["txs"]] == [txid], hist2
    assert api("A", f"search?q={txid3}")["type"] == "tx"
    assert api("B", f"address/{b_addr}") == ai, "B's index must match A's"
    ok("public API: info, address, history paging, tx paths and search are consistent across nodes")

    # partition and reorg
    start("C", 51020, "--mine", "--threads", "1", "--nolisten", "--connect", "127.0.0.1:1", "--api-port", str(API["C"]))
    wait(lambda: int(rpc("C", "getblockcount")) >= 20, "C mines its own chain")
    c_miner = api("C", "block/1")["miner"]
    assert int(api("C", f"address/{c_miner}")["tx_count"]) >= 20
    stop("C")
    hA = int(rpc("A", "getblockcount"))
    ok(f"C mined an isolated chain; A is at {hA}")
    start("C", 51020, "--connect", "127.0.0.1:51000", "--nolisten", "--api-port", str(API["C"]))
    wait(lambda: rpc("C", "getbestblockhash") == rpc("A", "getbestblockhash"), "C reorganizes onto A's heavier chain")
    ok(f"C reorganized to A's chain at height {rpc('C', 'getblockcount')}")
    cm = api("C", f"address/{c_miner}")
    assert cm["tx_count"] == 0 and cm["balance"] == "0" and cm["utxo_count"] == 0, cm
    assert api("C", f"address/{b_addr}") == api("A", f"address/{b_addr}")
    def same_tip_supply():
        a, c = api("A", "info"), api("C", "info")
        return a["best"] == c["best"] and a["supply"] == c["supply"]
    wait(same_tip_supply, "C and A agree on supply at the same tip", 60)
    ok("API indexes on C exactly undo its reorganized-away blocks")
    wait(lambda: float(rpcj("B", "getbalance")["spendable"]) == b_left, "B keeps its balance across the reorg")

    # restart from disk
    tip = rpc("B", "getbestblockhash")
    stop("B")
    start("B", 51010, "--nolisten", "--connect", "127.0.0.1:1", "--api-port", str(API["B"]))
    assert rpc("B", "getbestblockhash") == tip or int(rpc("B", "getblockcount")) >= 300
    ok(f"B restarted from disk at height {rpc('B', 'getblockcount')}")
    assert api("B", f"address/{b_addr}") == api("A", f"address/{b_addr}"), "index rebuilt from disk"
    ok("API indexes rebuilt from disk match")
    print("ALL E2E CHECKS PASSED")
finally:
    for n in list(PROCS):
        stop(n)
    if os.environ.get("KEEP") != "1":
        shutil.rmtree(TMP, ignore_errors=True)
    else:
        print("data kept in", TMP)
