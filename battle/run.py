#!/usr/bin/env python3
"""Varve battle test. Runs entirely on this machine against private regtest nodes
bound to 127.0.0.1. Nothing is sent anywhere else.

    python3 -I battle/run.py --bin node/target/release/varve \
        --testkit node/target/release/varve-testkit --run-id run-1 --label "..."

Groups: consensus, reorg, mempool, capacity and fuzzing (through varve-testkit),
plus storage recovery, wallet input checks and sync speed (here).
Writes battle/results/<run-id>.json. Python 3 standard library only.
"""
import argparse, base64, hashlib, http.client, json, os, platform, shutil, signal, subprocess, tempfile, threading, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ap = argparse.ArgumentParser()
ap.add_argument("--bin", default=os.path.join(ROOT, "node/target/release/varve"))
ap.add_argument("--testkit", default=os.path.join(ROOT, "node/target/release/varve-testkit"))
ap.add_argument("--run-id", default="run-local")
ap.add_argument("--label", default="Local battle test")
ap.add_argument("--commit", default="")
ap.add_argument("--quick", action="store_true")
ap.add_argument("--keep", action="store_true")
ap.add_argument("--groups", default="setup,consensus,reorg,mempool,capacity,fuzz", help="test kit groups")
ap.add_argument("--only-testkit", action="store_true", help="skip wallet, storage and sync groups (debugging)")
A = ap.parse_args()
BIN, KIT = os.path.abspath(A.bin), os.path.abspath(A.testkit)
TMP = tempfile.mkdtemp(prefix="varve-battle-")
PROCS, TESTS, CAPACITY = {}, [], []
T_START = datetime.now(timezone.utc)
BASE = 52000 + (os.getpid() % 50) * 20


def log(m):
    print(f"[battle {time.strftime('%H:%M:%S')}] {m}", flush=True)


def record(tid, cat, name, attack, expected, outcome, detail, t0):
    TESTS.append(dict(id=tid, category=cat, name=name, attack=attack, expected=expected, outcome=outcome,
                      detail=detail, duration_s=round(time.time() - t0, 2)))
    log(f"{outcome:10s} {tid}: {detail[:160]}")


def metric(mid, name, value, unit, detail=""):
    CAPACITY.append(dict(id=mid, name=name, value=round(value, 3), unit=unit, detail=detail))
    log(f"metric     {mid}: {value:.3f} {unit} {detail}")


def start(name, port, *extra, datadir=None):
    d = datadir or os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    logf = open(os.path.join(d, "log.txt"), "a")
    p = subprocess.Popen([BIN, "node", "--network", "regtest", "--datadir", d, "--port", str(port),
                          "--rpcport", str(port + 1), *extra], stdout=logf, stderr=subprocess.STDOUT)
    PROCS[name] = dict(p=p, d=d, port=port, rpc=port + 1)
    for _ in range(600):
        if p.poll() is not None:
            PROCS.pop(name)
            raise RuntimeError(f"{name} exited at start (code {p.returncode})")
        try:
            rpc(name, "getblockcount")
            return PROCS[name]
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"{name} did not start")


def stop(name, kill=False):
    n = PROCS.pop(name, None)
    if not n:
        return
    if kill:
        n["p"].send_signal(signal.SIGKILL)
        n["p"].wait()
        return
    try:
        rpc_node(n, "stop")
    except Exception:
        pass
    try:
        n["p"].wait(timeout=60)
    except subprocess.TimeoutExpired:
        n["p"].kill()
        n["p"].wait()


def rpc_node(n, method, *params, timeout=120):
    with open(os.path.join(n["d"], ".cookie")) as f:
        auth = base64.b64encode(f.read().strip().encode()).decode()
    c = http.client.HTTPConnection("127.0.0.1", n["rpc"], timeout=timeout)
    c.request("POST", "/", json.dumps({"method": method, "params": [str(p) for p in params], "id": 1}),
              {"Authorization": "Basic " + auth})
    r = json.loads(c.getresponse().read())
    c.close()
    if r.get("error"):
        raise RuntimeError(r["error"].get("message"))
    return r["result"]


def rpc(name, method, *params, timeout=120):
    return rpc_node(PROCS[name], method, *params, timeout=timeout)


def alive(name):
    try:
        rpc(name, "getblockcount", timeout=20)
        return True
    except Exception:
        return False


def wait_for(cond, timeout):
    t = time.time()
    while time.time() - t < timeout:
        try:
            if cond():
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def hwm_mb(name):
    try:
        with open(f"/proc/{PROCS[name]['p'].pid}/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        return -1


def run_testkit(groups):
    n = PROCS["A"]
    cmd = [KIT, "run", "--datadir", n["d"], "--rpcport", str(n["rpc"]), "--p2pport", str(n["port"]), "--group", groups]
    if A.quick:
        cmd.append("--quick")
    log(f"testkit: {groups}")
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in p.stdout:
        try:
            j = json.loads(line)
        except Exception:
            continue
        if j.get("metric"):
            metric(j["id"], j["name"], j["value"], j["unit"], j.get("detail", ""))
        else:
            TESTS.append(j)
            log(f"{j['outcome']:10s} {j['id']}: {j['detail'][:160]}")
    p.wait()
    if p.returncode != 0:
        lines = p.stderr.read().strip().splitlines()
        err = [l for l in lines if "panicked" in l or l.startswith(("Error", "error"))][:1] + [l for l in lines if "panicked" not in l][-1:]
        with open(os.path.join(HERE, "results", f"{A.run_id}-testkit-stderr.txt"), "w") as f:
            f.write("\n".join(lines[-60:]))
        crashed = not alive("A")
        record("testkit-" + groups.replace(",", "-"), "Harness", "test kit run", "-", "-",
               "crash" if crashed else "error", ("node stopped answering; " if crashed else "") + " | ".join(err), t0)


def group_wallet():
    cases = [
        ("w-bad-address", "Malformed address", ["notanaddress", "1"]),
        ("w-wrong-network", "Address from another network", ["varve1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsl5pdc", "1"]),
        ("w-zero", "Zero amount", [None, "0"]),
        ("w-negative", "Negative amount", [None, "-5"]),
        ("w-decimals", "Nine decimal places", [None, "1.000000001"]),
        ("w-too-large", "Amount above total supply", [None, "99999999999"]),
        ("w-insufficient", "More than the wallet holds", [None, "100000"]),
        ("w-garbage-amount", "Non-numeric amount", [None, "1e3"]),
    ]
    good = rpc("A", "getnewaddress")
    for tid, name, (addr, amt) in cases:
        t0 = time.time()
        try:
            r = rpc("A", "sendtoaddress", addr or good, amt)
            outcome, detail = "vulnerable", f"accepted: {r}"
        except Exception as e:
            outcome, detail = ("defended", f"refused: {e}") if alive("A") else ("crash", str(e))
        record(tid, "Wallet", name, f"sendtoaddress with {name.lower()}", "refuse with a clear error", outcome, detail, t0)

    # concurrent sends must never double-spend the wallet's own coins
    t0 = time.time()
    results = []

    def send():
        try:
            results.append(("ok", rpc("A", "sendtoaddress", good, "1")))
        except Exception as e:
            results.append(("err", str(e)))
    th = [threading.Thread(target=send) for _ in range(12)]
    [t.start() for t in th]
    [t.join() for t in th]
    ok = [r[1] for r in results if r[0] == "ok"]
    pool = rpc("A", "getrawmempool")
    missing = [t for t in ok if t not in pool]
    outcome = "defended" if ok and not missing else ("vulnerable" if missing else "degraded")
    record("w-concurrent", "Wallet", "Twelve payments sent at the same moment",
           "12 simultaneous sendtoaddress calls from one wallet",
           "every accepted payment is valid (no coin spent twice)", outcome,
           f"{len(ok)} accepted, {len(missing)} accepted-but-invalid; errors: {sorted(set(r[1][:60] for r in results if r[0] == 'err'))}", t0)


def group_diff():
    import sys
    sys.path.insert(0, os.path.join(ROOT, "prototype"))
    import varve_proto as v
    t0 = time.time()
    n = PROCS["A"]
    out = os.path.join(TMP, "diff.jsonl")
    cmd = [KIT, "run", "--datadir", n["d"], "--rpcport", str(n["rpc"]), "--p2pport", str(n["port"]), "--group", "diff", "--diff-out", out]
    if A.quick:
        cmd.append("--quick")
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        record("d-parse", "Fuzzing", "Differential parsing", "-", "-", "error", p.stderr.strip()[-200:], t0)
        return
    cases = [json.loads(l) for l in open(out) if l.strip()]
    disagree, node_lib, parsed = [], 0, 0
    for c in cases:
        data = bytes.fromhex(c["hex"])
        try:
            r = v.Reader(data)
            v.Tx.parse(r)
            r.done()
            ref = "parsed"
        except Exception:
            ref = "parse_error"
        parsed += ref == "parsed"
        if c["lib"] != c["node"]:
            node_lib += 1
        if ref != c["lib"]:
            disagree.append(c["hex"][:40])
    outcome = "defended" if not disagree and not node_lib else "vulnerable"
    record("d-parse", "Fuzzing", f"Two independent implementations agree on {len(cases):,} mutated transactions",
           "randomly mutated transactions checked by the Rust node and by the separate Python reference implementation",
           "both implementations reach the same verdict on every input (a disagreement could split the chain)", outcome,
           f"disagreements: {len(disagree)}; node vs its own library: {node_lib}; inputs that still parsed: {parsed}", t0)


def group_kill_mining():
    t0 = time.time()
    port = BASE + 14
    d = os.path.join(TMP, "m-kill")
    start("M", port, "--mine", "--threads", "1", "--nolisten", datadir=d)
    wait_for(lambda: int(rpc("M", "getblockcount")) >= 15, 900)
    h_before = int(rpc("M", "getblockcount"))
    stop("M", kill=True)
    try:
        start("M", port, "--mine", "--threads", "1", "--nolisten", datadir=d)
        h_restart = int(rpc("M", "getblockcount"))
        grew = wait_for(lambda: int(rpc("M", "getblockcount")) > h_restart + 2, 600)
        ok = h_restart >= h_before - 1 and grew
        detail = f"killed at height {h_before}; restarted at {h_restart}; kept mining: {grew}"
    except Exception as e:
        ok, detail = False, f"restart failed: {e}"
    stop("M")
    record("s-kill-mining", "Storage/Recovery", "Power cut while mining", "mining node killed with SIGKILL mid-work, then restarted",
           "restart with its chain intact and keep mining", "defended" if ok else "vulnerable", detail, t0)


def group_storage(src_dir, tip_hash, tip_h):
    port = BASE + 10

    def fresh(name):
        d = os.path.join(TMP, name)
        shutil.copytree(src_dir, d, ignore=shutil.ignore_patterns(".cookie", "log.txt", ".lock"))
        return d

    def check(tid, name, attack, d, expect_full=True, then_sync=True):
        t0 = time.time()
        try:
            start("S", port, "--connect", f"127.0.0.1:{PROCS['A']['port']}", "--nolisten", datadir=d)
        except Exception as e:
            record(tid, "Storage/Recovery", name, attack, "recover, or refuse to start with a clear error",
                   "defended" if "corrupt" in str(e).lower() else "degraded", f"node refused to start: {e}", t0)
            return
        h0 = int(rpc("S", "getblockcount"))
        synced = wait_for(lambda: rpc("S", "getbestblockhash") == rpc("A", "getbestblockhash"), 240) if then_sync else True
        outcome = "defended" if synced else "vulnerable"
        record(tid, "Storage/Recovery", name, attack, "come back up and re-sync to the honest chain", outcome,
               f"restarted at height {h0} (source tip {tip_h}); back in sync with the network: {synced}", t0)
        stop("S")

    d = fresh("s-truncate")
    p = os.path.join(d, "blocks.dat")
    sz = os.path.getsize(p)
    with open(p, "r+b") as f:
        f.truncate(sz - 777)
    check("s-truncated", "Block file cut off mid-record", "the last 777 bytes of the block file are removed (power loss)", d)

    d = fresh("s-garbage")
    with open(os.path.join(d, "blocks.dat"), "ab") as f:
        f.write(os.urandom(5000))
    check("s-garbage", "Random bytes appended to the block file", "5,000 random bytes appended", d)

    d = fresh("s-corrupt")
    p = os.path.join(d, "blocks.dat")
    sz = os.path.getsize(p)
    with open(p, "r+b") as f:
        f.seek(sz // 2)
        f.write(os.urandom(64))
    check("s-corrupt-middle", "Block file corrupted in the middle", "64 random bytes written over the middle of the block file", d)

    d = fresh("s-deleted")
    os.remove(os.path.join(d, "blocks.dat"))
    check("s-deleted", "Block file deleted", "the whole block file is removed", d)

    # kill -9 during initial sync
    t0 = time.time()
    d = os.path.join(TMP, "s-killsync")
    start("S", port, "--connect", f"127.0.0.1:{PROCS['A']['port']}", "--nolisten", datadir=d)
    wait_for(lambda: int(rpc("S", "getblockcount")) > tip_h // 3, 240)
    mid = int(rpc("S", "getblockcount"))
    stop("S", kill=True)
    check("s-kill-sync", "Power cut during initial sync", f"process killed with SIGKILL at height {mid} while syncing", d)

    # sync speed from scratch
    t0 = time.time()
    d = os.path.join(TMP, "s-syncspeed")
    start("S", port, "--connect", f"127.0.0.1:{PROCS['A']['port']}", "--nolisten", datadir=d)
    ok = wait_for(lambda: rpc("S", "getbestblockhash") == rpc("A", "getbestblockhash"), 600)
    secs = time.time() - t0
    if ok:
        metric("cap-sync", f"Full sync of {tip_h} blocks from one peer", secs, "s", f"{tip_h / secs:.1f} blocks/s, every signature verified")
    stop("S")


def main():
    log(f"temp dir {TMP}")
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    addr = subprocess.run([KIT, "address"], capture_output=True, text=True, check=True).stdout.strip()
    port = BASE
    # 1. a funded chain: node A mines 320 blocks to the test kit's key
    start("A", port, "--mine", "--threads", "1", "--mine-to", addr, "--nolisten")
    target = 320
    if not wait_for(lambda: int(rpc("A", "getblockcount")) >= target, 3600):
        raise SystemExit("mining too slow")
    stop("A")
    start("A", port)  # listening, not mining
    log(f"chain at height {rpc('A', 'getblockcount')}")

    run_testkit(A.groups)
    if A.only_testkit:
        return
    if alive("A"):
        group_diff()
    if alive("A"):
        group_wallet()
    metric("cap-rss", "Peak memory of the node during the whole run", hwm_mb("A"), "MB", "VmHWM")
    tip_h, tip_hash = int(rpc("A", "getblockcount")), rpc("A", "getbestblockhash")
    # storage tests run on copies of A's data directory
    src = os.path.join(TMP, "A-copy")
    stop("A")
    shutil.copytree(PROCS.get("A", {}).get("d", os.path.join(TMP, "A")), src, ignore=shutil.ignore_patterns(".cookie", "log.txt", ".lock"))
    start("A", port)
    group_storage(src, tip_hash, tip_h)
    stop("A")
    group_kill_mining()


try:
    main()
finally:
    for n in list(PROCS):
        stop(n, kill=True)
    commit = A.commit or subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    with open(BIN, "rb") as f:
        bsha = hashlib.sha256(f.read()).hexdigest()
    out = dict(run_id=A.run_id, label=A.label, date_utc=T_START.strftime("%Y-%m-%dT%H:%M:%SZ"), commit=commit,
               binary_sha256=bsha, machine=dict(cpus=os.cpu_count(), mem_gb=round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30),
                                                os=platform.system()),
               scope="Local only: private regtest nodes on 127.0.0.1. Network-flood tests are out of scope.",
               tests=TESTS, capacity=CAPACITY)
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    path = os.path.join(HERE, "results", f"{A.run_id}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    counts = {}
    for t in TESTS:
        counts[t["outcome"]] = counts.get(t["outcome"], 0) + 1
    log(f"wrote {path}: {counts}")
    if not A.keep:
        shutil.rmtree(TMP, ignore_errors=True)
