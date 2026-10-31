#!/usr/bin/env python3
"""Visual check of the Strata UI against a mock node API (Python stdlib + Playwright).

Runs the create -> confirm -> home -> receive -> send -> review -> sent flow in a
desktop and a mobile viewport, decodes the receive QR code (if OpenCV is installed),
fails on any browser console error (for example a CSP violation), and writes
screenshots OUTSIDE the repository (default /tmp/strata-shots).

Usage: python3 -I node/tests/strata_ui.py [path/to/strata]
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "node/target/release/strata")
SHOTS = os.environ.get("STRATA_SHOTS", "/tmp/strata-shots")
HRP = "rvarve"
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
COIN = 100_000_000
FRAG = "#token="


# ---------------------------------------------------------------- bech32m and tx helpers
def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def hrp_expand(h):
    return [ord(c) >> 5 for c in h] + [0] + [ord(c) & 31 for c in h]


def convert(data, frm, to, pad):
    acc = bits = 0
    out = []
    for d in data:
        acc = (acc << frm) | d
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & ((1 << to) - 1))
    if pad and bits:
        out.append((acc << (to - bits)) & ((1 << to) - 1))
    return out


def encode_addr(template, hrp=HRP):
    data = [template[0]] + convert(template[1:], 8, 5, True)
    pm = polymod(hrp_expand(hrp) + data + [0] * 6) ^ 0x2BC830A3
    return hrp + "1" + "".join(CHARSET[d] for d in data + [(pm >> (5 * (5 - i))) & 31 for i in range(6)])


def decode_addr(addr):
    pos = addr.rfind("1")
    data = [CHARSET.index(c) for c in addr[pos + 1:]][:-6]
    return bytes([data[0]] + convert(data[1:], 5, 8, False))


def h256(tag, msg):
    t = tag.encode()
    return hashlib.sha3_256(bytes([len(t)]) + t + msg).digest()


def read_varint(b, i):
    n = shift = 0
    while True:
        c = b[i]
        i += 1
        n |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return n, i


def parse_tx(raw):
    i = 4
    n_in, i = read_varint(raw, i)
    ins = []
    for _ in range(n_in):
        ins.append((raw[i:i + 32].hex(), int.from_bytes(raw[i + 32:i + 36], "little")))
        i += 36
    n_out, i = read_varint(raw, i)
    outs = []
    for _ in range(n_out):
        amount = int.from_bytes(raw[i:i + 8], "little")
        ln = 44 if raw[i + 9] == 0 else 82
        outs.append((amount, raw[i + 8:i + ln]))
        i += ln
    i += 4
    return h256("VARVE/txid/v1", raw[:i]).hex(), ins, outs


# ---------------------------------------------------------------- mock node API
class Mock:
    def __init__(self, genesis):
        self.genesis = genesis
        self.height = 5000
        self.utxos = {}  # addr -> list of utxo dicts
        self.txs = {}  # addr -> list of tx dicts
        self.broadcast = []
        self.lock = threading.Lock()

    def fund(self, addr, amount, coinbase=False, height=None, n=1):
        tpl = decode_addr(addr)
        for _ in range(n):
            txid = secrets.token_hex(32)
            h = height or self.height - 300
            self.utxos.setdefault(addr, []).append({
                "txid": txid, "index": 0, "amount": str(amount), "height": h, "coinbase": coinbase,
                "mature": (not coinbase) or self.height + 1 >= h + 288, "spent_in_mempool": False,
                "output": (amount.to_bytes(8, "little") + tpl).hex()})
            self.txs.setdefault(addr, []).append({"txid": txid, "height": h, "time": 1793000000 + h * 300, "delta": str(amount), "fee": None if coinbase else "6000"})

    def summary(self, addr):
        u = self.utxos.get(addr, [])
        t = self.txs.get(addr, [])
        bal = sum(int(x["amount"]) for x in u if x["height"] is not None)
        unc = sum(int(x["delta"]) for x in t if x["height"] is None)
        return {"address": addr, "balance": str(bal), "received": str(bal), "sent": "0", "tx_count": len(t),
                "utxo_count": len(u), "unconfirmed": str(unc), "first_seen": None, "funded_by": []}

    def accept(self, hexstr):
        raw = bytes.fromhex(hexstr)
        txid, ins, outs = parse_tx(raw)
        with self.lock:
            deltas = {}
            for addr, lst in self.utxos.items():
                for u in lst:
                    if (u["txid"], u["index"]) in ins:
                        if u["spent_in_mempool"]:
                            raise ValueError("double spend")
                        u["spent_in_mempool"] = True
                        deltas[addr] = deltas.get(addr, 0) - int(u["amount"])
            if len(deltas) == 0:
                raise ValueError("missing inputs")
            for idx, (amount, tpl) in enumerate(outs):
                a = encode_addr(tpl)
                deltas[a] = deltas.get(a, 0) + amount
                self.utxos.setdefault(a, []).append({"txid": txid, "index": idx, "amount": str(amount), "height": None, "coinbase": False,
                                                     "mature": True, "spent_in_mempool": False, "output": (amount.to_bytes(8, "little") + tpl).hex()})
            for a, d in deltas.items():
                self.txs.setdefault(a, []).insert(0, {"txid": txid, "height": None, "time": None, "delta": str(d), "fee": None})
            self.broadcast.append(txid)
        return txid


def make_handler(mock):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self):
            p = self.path.split("?")[0]
            if p == "/api/v1/info":
                return self.send(200, {"network": "regtest", "height": mock.height, "best": "00" * 32, "time": 1793000000, "genesis": mock.genesis, "hrp": HRP, "syncing": False, "version": "0.1.0"})
            if p == "/api/v1/fees":
                return self.send(200, {"min": 1, "slow": 1, "normal": 2, "fast": 5})
            m = re.fullmatch(r"/api/v1/address/([a-z0-9]+)(/txs|/utxos)?", p)
            if m:
                a, sub = m.group(1), m.group(2)
                with mock.lock:
                    if sub == "/txs":
                        return self.send(200, {"txs": mock.txs.get(a, []), "next": None})
                    if sub == "/utxos":
                        return self.send(200, {"height": mock.height, "utxos": mock.utxos.get(a, [])})
                    return self.send(200, mock.summary(a))
            self.send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/api/v1/tx":
                return self.send(404, {"error": "not found"})
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
            try:
                self.send(200, {"txid": mock.accept(body.strip())})
            except Exception as e:  # noqa: BLE001
                self.send(400, {"error": str(e)})

    return H


# ---------------------------------------------------------------- strata process
class Strata:
    def __init__(self, tag):
        self.dir = tempfile.mkdtemp(prefix=f"strata-ui-{tag}-")
        self.p = subprocess.Popen([BIN, "--network", "regtest", "--no-browser", "--datadir", self.dir], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for _ in range(100):
            line = self.p.stdout.readline()
            m = re.search(r"(http://127\.0\.0\.1:(\d+))/#token=([0-9a-f]{64})", line)
            if m:
                self.base, self.port, self.token = m.group(1), int(m.group(2)), m.group(3)
                self.url = m.group(0)
                return
        raise SystemExit("strata did not start")

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={"X-Strata-Token": self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def until(fn, what, timeout=30):
    """Poll from Python (the page CSP forbids Playwright's string evaluation)."""
    t = time.time()
    while time.time() - t < timeout:
        try:
            if fn():
                return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.2)
    raise AssertionError(f"timeout waiting for {what}")


def ok(msg):
    print(f"ok   {msg}", flush=True)


def qr_decode(path):
    try:
        import cv2  # noqa: PLC0415
    except ImportError:
        return None
    img = cv2.imread(path)
    val, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    return val


def run_flow(pw, name, viewport, mobile):
    st = Strata(name)
    status = st.call("GET", "/local/status")
    mock = Mock(status["genesis"])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(mock))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    st.call("POST", "/local/settings", {"api_endpoint": f"http://127.0.0.1:{srv.server_port}"})
    browser = pw.chromium.launch()
    ctx = browser.new_context(viewport=viewport, is_mobile=mobile, has_touch=mobile, device_scale_factor=2 if mobile else 1, permissions=["clipboard-read", "clipboard-write"])
    page = ctx.new_page()
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    def shot(n):
        page.wait_for_timeout(450)  # let the fade-in animation finish
        page.screenshot(path=os.path.join(SHOTS, f"{name}-{n}.png"), full_page=False)
    try:
        page.goto(st.url)
        page.wait_for_selector("text=Create a new wallet")
        assert "#token" not in page.url, "token must be removed from the address bar"
        assert page.locator("#banner").inner_text().lower().startswith("regtest: coins have no value")
        shot("01-welcome")
        page.click("text=Create a new wallet")
        page.fill("#" + page.locator("input[type=password]").nth(0).get_attribute("id"), "river copper lantern 7")
        page.locator("input[type=password]").nth(1).fill("river copper lantern 7")
        shot("02-create")
        page.click("button:has-text('Create wallet')")
        page.wait_for_selector(".word")
        words = [w.inner_text() for w in page.locator(".word span").all()]
        assert len(words) == 24, words
        shot("03-words")
        page.check("input[type=checkbox]")
        page.click("button:has-text('Continue')")
        page.wait_for_selector("text=Confirm your phrase")
        # fund the wallet in the mock before the home screen loads
        addrs = st.call("GET", "/local/addresses")
        r0, r2 = addrs["receive"][0]["address"], addrs["receive"][2]["address"]
        mock.fund(r0, 82 * COIN, coinbase=True, n=3)
        mock.fund(r2, 25 * COIN)
        mock.fund(r2, 5 * COIN, coinbase=True, height=mock.height - 10)  # immature
        labels = page.locator("label:has-text('Word #')").all()
        for i, lab in enumerate(labels):
            n = int(lab.inner_text().split("#")[1])
            page.locator("#" + lab.get_attribute("for")).fill(words[n - 1])
        shot("04-confirm")
        page.click("button:has-text('Confirm')")
        page.wait_for_selector(".balance .amt")
        until(lambda: page.locator(".balance .amt").inner_text() != "\u2014", "balance")
        bal = page.locator(".balance .amt").inner_text()
        assert bal == "276.00", bal  # 3 x 82 + 25 + 5
        page.wait_for_selector(".row")
        shot("05-home")
        ok(f"{name}: created wallet, balance {bal} VARV, activity shown")

        page.click("button:has-text('Receive')")
        page.wait_for_selector(".qr-card svg")
        addr_text = page.locator(".addr-box").inner_text().replace("\n", "")
        cur = st.call("GET", "/local/addresses")["current"]
        assert cur["index"] == 3, cur  # 0 and 2 have history, so the first unused is 3
        assert addr_text == cur["address"], (addr_text, cur)
        r0 = cur["address"]
        qr_path = os.path.join(SHOTS, f"{name}-qr.png")
        page.locator(".qr-card").screenshot(path=qr_path)
        dec = qr_decode(qr_path)
        if dec is None:
            ok(f"{name}: receive screen (OpenCV not installed; QR not decoded)")
        else:
            assert dec == r0, f"QR decodes to {dec!r}, expected {r0}"
            ok(f"{name}: receive QR decodes to the address")
        shot("06-receive")
        page.click("button:has-text('New address')")
        until(lambda: r0[-6:] not in page.locator(".addr-box").inner_text(), "new address")
        ok(f"{name}: new address issued")

        page.click("nav >> text=Home")
        page.click("button.action:has-text('Send')")
        page.wait_for_selector("text=Spendable:")
        until(lambda: "Spendable: 271.00" in page.locator("body").inner_text(), "spendable balance")
        dest = encode_addr(bytes([1, 0, 1, 0]) + secrets.token_bytes(32))
        page.locator("input.mono").first.fill(dest)
        page.locator("input[inputmode=decimal]").fill("100.5")
        page.click(".seg button:has-text('Fast')")
        shot("07-send")
        page.click("button:has-text('Review')")
        page.wait_for_selector("text=Review payment", timeout=60000)
        assert dest in page.locator(".summary").inner_text()
        shot("08-review")
        page.click("button:has-text('Send now')")
        page.wait_for_selector("text=Payment sent", timeout=30000)
        assert len(mock.broadcast) == 1
        assert mock.broadcast[0] in page.locator(".summary").inner_text()
        shot("09-sent")
        ok(f"{name}: payment built, reviewed and broadcast ({mock.broadcast[0][:16]}...)")

        page.click("button:has-text('Done')")
        page.click("nav >> text=Activity")
        page.wait_for_selector("text=Pending", timeout=30000)
        shot("10-activity")
        page.click("nav >> text=Settings")
        page.wait_for_selector("text=Show recovery phrase")
        shot("11-settings")
        # node unreachable message
        st.call("POST", "/local/settings", {"api_endpoint": "http://127.0.0.1:59998"})
        page.goto(st.base + "/?reload=1" + FRAG + st.token)  # a new document, not a hash change
        page.wait_for_selector("text=Can't reach the Varve node at http://127.0.0.1:59998", timeout=30000)
        shot("12-unreachable")
        ok(f"{name}: unreachable node message shown")
        page.click("button[aria-label='Lock now']")
        page.wait_for_selector("text=Welcome back")
        shot("13-unlock")
        bad = [e for e in errors if "127.0.0.1:59998" not in e and "ERR_CONNECTION_REFUSED" not in e]
        assert not bad, f"console errors: {bad}"
        ok(f"{name}: no console errors (CSP clean)")
    except Exception:
        shot("FAIL")
        print("page text at failure:", page.locator("body").inner_text()[:1500])
        print("console errors:", errors)
        raise
    finally:
        browser.close()
        srv.shutdown()
        st.stop()


def main():
    os.makedirs(SHOTS, exist_ok=True)
    from playwright.sync_api import sync_playwright  # noqa: PLC0415
    with sync_playwright() as pw:
        run_flow(pw, "desktop", {"width": 1280, "height": 860}, False)
        run_flow(pw, "mobile", {"width": 390, "height": 844}, True)
    print(f"ALL UI CHECKS PASSED (screenshots in {SHOTS})")


if __name__ == "__main__":
    main()
