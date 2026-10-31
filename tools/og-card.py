#!/usr/bin/env python3
"""Render docs/assets/og-card.png, the 1200x630 share card for links to the site.

    python3 -I tools/og-card.py

Brand colours and fonts match the website. Needs Python Playwright with Chromium.
"""
import base64, os, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
logo = base64.b64encode(open(os.path.join(ROOT, "docs/assets/varve-mark-light.png"), "rb").read()).decode()
lines = "".join(
    f'<path d="M0 {80 + i * 46} C 300 {60 + i * 46 + (i % 3) * 14}, 700 {110 + i * 46 - (i % 4) * 10}, 1200 {75 + i * 46}" />'
    for i in range(13))
page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{width:1200px;height:630px;overflow:hidden;background:#0d1117;color:#faf0e2;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}}
.c{{position:relative;width:1200px;height:630px;padding:72px 84px;background:radial-gradient(900px 480px at 88% 0%,rgba(207,174,120,.20),transparent 62%),#0d1117}}
svg.s{{position:absolute;inset:0;opacity:.22}}
svg.s path{{fill:none;stroke:#cfae78;stroke-width:1.2}}
.top{{position:relative;display:flex;align-items:center;gap:20px}}
.top img{{width:72px;height:72px}}
.top span{{font-family:ui-serif,Georgia,serif;font-size:44px}}
h1{{position:relative;font-family:ui-serif,Georgia,serif;font-weight:500;font-size:70px;line-height:1.06;margin-top:58px;max-width:960px}}
p{{position:relative;color:#b8b0a2;font-size:27px;margin-top:26px;max-width:940px;line-height:1.4}}
.tags{{position:absolute;left:84px;bottom:64px;display:flex;gap:12px}}
.tags b{{font-weight:600;font-size:19px;color:#cfae78;border:1px solid rgba(207,174,120,.45);border-radius:999px;padding:8px 16px}}
</style></head><body><div class="c"><svg class="s" viewBox="0 0 1200 630">{lines}</svg>
<div class="top"><img src="data:image/png;base64,{logo}" alt=""><span>Varve</span></div>
<h1>Proof-of-work money built to outlast its cryptography</h1>
<p>Post-quantum signatures from the first block. Upgradable cryptography. A fair launch with no premine.</p>
<div class="tags"><b>Open source</b><b>CPU mining</b><b>Testnet phase</b></div>
</div></body></html>"""

from playwright.sync_api import sync_playwright
with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
    f.write(page)
    path = f.name
out = os.path.join(ROOT, "docs/assets/og-card.png")
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1200, "height": 630})
    pg.goto("file://" + path)
    pg.screenshot(path=out)
    b.close()
os.unlink(path)
print("wrote", out)
