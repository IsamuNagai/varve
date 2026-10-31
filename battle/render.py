#!/usr/bin/env python3
"""Render a battle-test results file as a dated PNG card with the Varve logo.

    python3 -I battle/render.py battle/results/run-1.json docs/assets/battle-run-1.png
    python3 -I battle/render.py battle/results/run-final.json docs/assets/battle-run-final.png \
        --compare battle/results/run-1.json

Everything on the card comes from the results file. Needs Python Playwright with Chromium.
"""
import argparse, base64, html, json, os, tempfile
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ap = argparse.ArgumentParser()
ap.add_argument("results")
ap.add_argument("out")
ap.add_argument("--compare", help="earlier results file: list what changed since then")
A = ap.parse_args()
R = json.load(open(A.results))
C = json.load(open(A.compare)) if A.compare else None

E = html.escape
OK = {"defended"}
COLORS = {"defended": "#6cc08f", "vulnerable": "#e5675e", "crash": "#e5675e", "degraded": "#e0a948", "error": "#8b93a1", "skipped": "#8b93a1"}
CATS = ["Consensus", "Reorg", "Mempool", "Wallet", "Fuzzing", "Storage/Recovery", "Resource exhaustion"]
CAT_LABEL = {"Storage/Recovery": "Crash & data recovery", "Fuzzing": "Fuzzing & cross-checks", "Reorg": "Chain reorganizations",
             "Consensus": "Consensus rules", "Mempool": "Mempool policy", "Wallet": "Wallet input", "Resource exhaustion": "Resource limits"}

tests = [t for t in R["tests"] if t["category"] not in ("Setup", "Harness")]
date = datetime.strptime(R["date_utc"], "%Y-%m-%dT%H:%M:%SZ")
date_s = date.strftime("%-d %B %Y, %H:%M UTC")
n = len(tests)
n_ok = sum(t["outcome"] in OK for t in tests)
bad = [t for t in tests if t["outcome"] not in OK]
logo = base64.b64encode(open(os.path.join(ROOT, "docs/assets/varve-mark-light.png"), "rb").read()).decode()

rows = []
for c in CATS:
    ts = [t for t in tests if t["category"] == c]
    if not ts:
        continue
    k = sum(t["outcome"] in OK for t in ts)
    segs = "".join(f'<span style="flex:1;background:{COLORS.get(t["outcome"], "#888")}" title="{E(t["name"])}"></span>' for t in sorted(ts, key=lambda t: t["outcome"] not in OK))
    rows.append(f'<div class="row"><div class="cat">{E(CAT_LABEL.get(c, c))}</div><div class="bar">{segs}</div><div class="cnt">{k}/{len(ts)}</div></div>')

def finding(t):
    col = COLORS.get(t["outcome"], "#888")
    return f'<li><span class="tag" style="background:{col}">{E(t["outcome"].upper())}</span><b>{E(t["name"])}</b><div class="d">{E(t["attack"])}</div></li>'

if C:
    before = {t["id"]: t for t in C["tests"]}
    fixed = [t for t in tests if t["outcome"] in OK and t["id"] in before and before[t["id"]]["outcome"] not in OK]
    new = [t for t in tests if t["id"] not in before]
    side_title = "Fixed since run 1"
    side = "".join(f'<li><span class="tag" style="background:{COLORS["defended"]}">FIXED</span><b>{E(t["name"])}</b><div class="d">{E(t["attack"])}</div></li>' for t in fixed)
    if bad:
        side += "".join(finding(t) for t in bad)
    if not side:
        side = "<li>No changes.</li>"
    extra = f'<p class="note">{len(new)} new test{"s" if len(new) != 1 else ""} added since run 1. {"Every test passed." if not bad else ""}</p>'
else:
    side_title = "What the battle test found"
    side = "".join(finding(t) for t in bad) or "<li>Nothing: every test passed.</li>"
    extra = ""

CAP = [("cap-full-block", "Full block verified in", lambda v: f"{v * 1000:.0f} ms"),
       ("cap-sigs-per-block", "Signed transactions per full block", lambda v: f"{v:.0f}"),
       ("cap-shared-inputs", "Same-key coins in one block, one signature", lambda v: f"{v:.0f}"),
       ("cap-tx-accept", "Transactions verified per second", lambda v: f"{v:,.0f}"),
       ("cap-sync", "Full re-sync of the test chain", lambda v: f"{v:.1f} s"),
       ("cap-reorg", "Deep reorganization handled in", lambda v: f"{v:.1f} s"),
       ("cap-rss", "Peak node memory", lambda v: f"{v:.0f} MB")]
capd = {c["id"]: c for c in R.get("capacity", [])}
caps = "".join(f'<div class="cap"><div class="v">{f(capd[i]["value"])}</div><div class="l">{E(l)}</div></div>' for i, l, f in CAP if i in capd)

page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{width:1200px;background:#0d1117;color:#faf0e2;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}}
.card{{padding:56px 64px 44px;background:radial-gradient(1200px 500px at 85% -10%,rgba(207,174,120,.16),transparent 60%),#0d1117}}
header{{display:flex;align-items:center;gap:22px;margin-bottom:34px}}
header img{{width:74px;height:74px}}
.brand{{font-family:ui-serif,Georgia,serif;font-size:40px;letter-spacing:.5px}}
.brand small{{display:block;font-family:system-ui,sans-serif;font-size:15px;letter-spacing:3px;color:#cfae78;text-transform:uppercase;margin-top:4px}}
.date{{margin-left:auto;text-align:right;color:#b8b0a2;font-size:16px;line-height:1.5}}
.date b{{color:#faf0e2;font-size:20px;display:block}}
h1{{font-family:ui-serif,Georgia,serif;font-weight:500;font-size:44px;line-height:1.1;margin-bottom:8px}}
.sub{{color:#b8b0a2;font-size:18px;margin-bottom:30px}}
.stats{{display:flex;gap:18px;margin-bottom:34px}}
.stat{{flex:1;background:#131a24;border:1px solid #263040;border-radius:14px;padding:20px 24px}}
.stat .v{{font-size:52px;font-weight:700;line-height:1}}
.stat .l{{color:#b8b0a2;font-size:16px;margin-top:8px}}
.grid{{display:grid;grid-template-columns:1.05fr 1fr;gap:26px}}
.panel{{background:#131a24;border:1px solid #263040;border-radius:14px;padding:24px 26px}}
.panel h2{{font-size:15px;letter-spacing:2.5px;text-transform:uppercase;color:#cfae78;font-weight:600;margin-bottom:18px}}
.row{{display:flex;align-items:center;gap:14px;margin:11px 0}}
.cat{{width:200px;font-size:17px}}
.bar{{flex:1;height:20px;display:flex;gap:3px;border-radius:5px;overflow:hidden}}
.cnt{{width:56px;text-align:right;font-variant-numeric:tabular-nums;color:#b8b0a2;font-size:16px}}
ul{{list-style:none}}
li{{margin:0 0 16px;font-size:17px;line-height:1.35}}
li .d{{color:#b8b0a2;font-size:15px;margin-top:3px}}
.tag{{display:inline-block;font-size:12px;font-weight:700;letter-spacing:1px;color:#0d1117;border-radius:4px;padding:2px 7px;margin-right:9px;vertical-align:2px}}
.caps{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:26px}}
.cap{{background:#131a24;border:1px solid #263040;border-radius:12px;padding:16px 18px}}
.cap .v{{font-size:28px;font-weight:700;color:#cfae78}}
.cap .l{{color:#b8b0a2;font-size:14px;margin-top:6px;line-height:1.3}}
.legend{{display:flex;gap:18px;color:#b8b0a2;font-size:14px;margin-top:16px}}
.legend i{{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}}
.note{{color:#b8b0a2;font-size:15px;margin-top:6px}}
footer{{margin-top:28px;color:#8b93a1;font-size:14px;line-height:1.6;border-top:1px solid #263040;padding-top:18px}}
footer code{{color:#b8b0a2}}
</style></head><body><div class="card">
<header><img src="data:image/png;base64,{logo}" alt=""><div class="brand">Varve<small>Battle test</small></div>
<div class="date"><b>{E(date.strftime("%-d %B %Y"))}</b>Test run {E(date_s)}</div></header>
<h1>{E(R["label"])}</h1>
<div class="sub">Our own test of the Varve node, run on a private local test network.</div>
<div class="stats">
<div class="stat"><div class="v">{n}</div><div class="l">attacks and fault tests run</div></div>
<div class="stat"><div class="v" style="color:#6cc08f">{n_ok}</div><div class="l">handled correctly</div></div>
<div class="stat"><div class="v" style="color:{'#e5675e' if bad else '#6cc08f'}">{len(bad)}</div><div class="l">{'problems found' if bad else 'problems remaining'}</div></div>
</div>
<div class="grid">
<div class="panel"><h2>Results by area</h2>{''.join(rows)}
<div class="legend"><span><i style="background:#6cc08f"></i>handled correctly</span><span><i style="background:#e5675e"></i>problem found</span></div></div>
<div class="panel"><h2>{E(side_title)}</h2><ul>{side}</ul>{extra}</div>
</div>
<div class="caps">{caps}</div>
<footer>Scope: Varve node commit <code>{E(R["commit"][:10])}</code>, binary SHA-256 <code>{E(R["binary_sha256"][:16])}…</code>, on a {R["machine"]["cpus"]}-core test machine. Every block in these tests carries real RandomX proof of work, and every signature is a real post-quantum signature.
Not covered: network-flood tests and an independent human code audit. Reproduce with <code>battle/run.py</code> and <code>battle/render.py</code>.</footer>
</div></body></html>"""

from playwright.sync_api import sync_playwright
with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
    f.write(page)
    path = f.name
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1200, "height": 800}, device_scale_factor=2)
    pg.goto("file://" + path)
    pg.locator(".card").screenshot(path=A.out)
    b.close()
os.unlink(path)
print(f"wrote {A.out}")
