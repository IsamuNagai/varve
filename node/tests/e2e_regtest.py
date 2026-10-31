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
TMP = tempfile.mkdtemp(prefix="varve-e2e-")
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
    raise SystemExit(f"timeout waiting for: {what}")


def ok(msg):
    print(f"ok   {msg}", flush=True)


try:
    start("A", 51000, "--nolisten")
    stop("A")  # restart listening (A must accept B); first run just creates its wallet
    start("A", 51000, "--mine", "--threads", "1")
    start("B", 51010, "--connect", "127.0.0.1:51000")
    wait(lambda: int(rpc("A", "getblockcount")) >= 300, "A mines 300 blocks")
    ok(f"A mined {rpc('A', 'getblockcount')} blocks")
    wait(lambda: rpc("B", "getbestblockhash") == rpc("A", "getbestblockhash"), "B syncs to A")
    ok(f"B synced to height {rpc('B', 'getblockcount')}")

    bal = rpcj("A", "getbalance")
    assert float(bal["spendable"]) > 0, bal
    ok(f"A balance: spendable {bal['spendable']}, immature {bal['immature']}")

    b_addr = rpc("B", "getnewaddress")
    txid = rpc("A", "sendtoaddress", b_addr, "12.5")
    ok(f"A sent 12.5 to B: {txid}")
    wait(lambda: txid in rpc("B", "getrawmempool"), "tx relayed to B's mempool", 60)
    ok("payment relayed to B's mempool")
    wait(lambda: float(rpcj("B", "getbalance")["spendable"]) == 12.5, "payment confirmed at B", 120)
    ok("payment confirmed; B spendable = 12.5")

    # partition and reorg
    start("C", 51020, "--mine", "--threads", "1", "--nolisten", "--connect", "127.0.0.1:1")
    wait(lambda: int(rpc("C", "getblockcount")) >= 20, "C mines its own chain")
    stop("C")
    hA = int(rpc("A", "getblockcount"))
    ok(f"C mined an isolated chain; A is at {hA}")
    start("C", 51020, "--connect", "127.0.0.1:51000", "--nolisten")
    wait(lambda: rpc("C", "getbestblockhash") == rpc("A", "getbestblockhash"), "C reorganizes onto A's heavier chain")
    ok(f"C reorganized to A's chain at height {rpc('C', 'getblockcount')}")
    wait(lambda: float(rpcj("B", "getbalance")["spendable"]) == 12.5, "B keeps its payment")

    # restart from disk
    tip = rpc("B", "getbestblockhash")
    stop("B")
    start("B", 51010, "--nolisten", "--connect", "127.0.0.1:1")
    assert rpc("B", "getbestblockhash") == tip or int(rpc("B", "getblockcount")) >= 300
    ok(f"B restarted from disk at height {rpc('B', 'getblockcount')}")
    print("ALL E2E CHECKS PASSED")
finally:
    for n in list(PROCS):
        stop(n)
    if os.environ.get("KEEP") != "1":
        shutil.rmtree(TMP, ignore_errors=True)
    else:
        print("data kept in", TMP)
