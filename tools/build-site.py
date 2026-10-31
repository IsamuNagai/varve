#!/usr/bin/env python3
"""Build the website (docs/) from site/ sources.

  python3 -I tools/build-site.py          write docs/*.html
  python3 -I tools/build-site.py --check  exit 1 if docs/ is out of date (CI)

Sources:
  site/pages/<name>.html   main content of each page (inner HTML of <main>)
  site/journal/*.md        journal posts: first lines "title: ...", "date: YYYY-MM-DD", blank line, Markdown
  whitepaper/varve-whitepaper.md   rendered into docs/whitepaper.html
The roadmap block in index.html is filled by tools/status.py afterwards (markers kept).
Standard library only; output is deterministic.
"""
import html
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SITE = os.path.join(ROOT, "site")
OUT = os.path.join(ROOT, "docs")
ASSET_VERSION = "9"  # bump when style.css, site.js or theme-init.js change
REPO = "https://github.com/IsamuNagai/varve"
X_URL = "https://x.com/isanagai"
SITE_URL = "https://isamunagai.github.io/varve/"

NAV = [("index.html", "Home"), ("about.html", "About"), ("whitepaper.html", "Whitepaper"),
       ("journal.html", "Journal"), ("download.html", "Download"), ("scan/", "Explorer"), ("forum.html", "Forum"), ("security.html", "Security"), ("faq.html", "FAQ")]

PAGES = {  # file: (title, description)
    "index.html": ("Varve: proof-of-work money built to outlast its cryptography",
                   "Varve is open-source proof-of-work money with post-quantum signatures from the first block, "
                   "cryptography that can be upgraded without a restart, and a fair launch with no premine."),
    "about.html": ("About Varve", "What Varve is, the principles behind it, and what it deliberately does not build."),
    "whitepaper.html": ("Varve whitepaper", "Varve: Long-Horizon Proof-of-Work Money with Post-Quantum Ownership, by Isamu Nagai."),
    "journal.html": ("Varve journal", "Development notes and progress updates from Isamu Nagai."),
    "forum.html": ("Varve forum", "Where Varve discussion takes place, and the community guidelines."),
    "security.html": ("Varve security", "How to report a vulnerability, how releases are verified, and a note on seed phrases."),
    "download.html": ("Download Varve: Strata wallet, Varvescan explorer and the Varve node",
                      "Download the Strata wallet for Windows, macOS and Linux, open the Varvescan block explorer, or set up the Varve node and miner."),
    "mainnet.html": ("Varve mainnet readiness", "What has to be true before Varve's mainnet launches: what is proven, what is designed, and what is still missing."),
    "faq.html": ("Varve FAQ", "Frequently asked questions about Varve: status, post-quantum design, fair launch, testnet and how to help."),
    "404.html": ("Page not found · Varve", "The page you requested does not exist on the Varve site."),
}

X_ICON = ('<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M17.8 3h3.1l-6.8 7.8L22 21h-6.2l-4.9-6.4L5.3 21H2.2'
          'l7.3-8.3L1.9 3h6.4l4.4 5.8L17.8 3zm-1.1 16.2h1.7L7.3 4.7H5.5l11.2 14.5z"/></svg>')
SUN_MOON = ('<svg class="only-dark" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="4"/>'
            '<path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'
            '<svg class="only-light" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>')


def social(name, title, desc):
    """Canonical URL and share-card tags (Open Graph and X)."""
    if name == "404.html":
        return '<meta name="robots" content="noindex">'
    url = SITE_URL + ("" if name == "index.html" else name)
    img = SITE_URL + "assets/og-card.png"
    t, d = html.escape(title), html.escape(desc)
    return "\n".join([
        f'<link rel="canonical" href="{url}">',
        '<meta property="og:type" content="website">',
        '<meta property="og:site_name" content="Varve">',
        f'<meta property="og:title" content="{t}">',
        f'<meta property="og:description" content="{d}">',
        f'<meta property="og:url" content="{url}">',
        f'<meta property="og:image" content="{img}">',
        '<meta property="og:image:width" content="1200">',
        '<meta property="og:image:height" content="630">',
        '<meta property="og:image:alt" content="Varve: proof-of-work money built to outlast its cryptography">',
        '<meta name="twitter:card" content="summary_large_image">',
        '<meta name="twitter:site" content="@isanagai">',
        f'<meta name="twitter:title" content="{t}">',
        f'<meta name="twitter:description" content="{d}">',
        f'<meta name="twitter:image" content="{img}">',
    ])


def sitemap():
    urls = [SITE_URL] + [SITE_URL + n for n in PAGES if n not in ("index.html", "404.html")] + [SITE_URL + "scan/"]
    body = "".join(f"<url><loc>{u}</loc></url>\n" for u in urls)
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + body + "</urlset>\n"


def page(name, main):
    title, desc = PAGES[name]
    v = ASSET_VERSION
    nav = "\n".join(f'<a href="{f}"' + (' aria-current="page"' if f == name else "") + f">{label}</a>" for f, label in NAV)
    foot = "\n".join(f'<a href="{f}">{label}</a>' for f, label in NAV[1:])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'">
<meta name="referrer" content="no-referrer">
<meta name="description" content="{html.escape(desc)}">
<title>{html.escape(title)}</title>
{social(name, title, desc)}
<script src="theme-init.js?v={v}"></script>
<link rel="stylesheet" href="style.css?v={v}">
<script src="site.js?v={v}" defer></script>
<link rel="icon" type="image/png" href="favicon.png">
</head>
<body>
<div class="bg" aria-hidden="true"><div class="bg-glow"></div><div class="bg-layer bg-layer-1"></div><div class="bg-layer bg-layer-2"></div></div>
<a class="skip" href="#main">Skip to content</a>
<header class="site-header">
<div class="bar">
<a class="brand" href="index.html"><img class="only-light" src="assets/varve-mark-dark.png" alt="" width="28" height="28"><img class="only-dark" src="assets/varve-mark-light.png" alt="" width="28" height="28" aria-hidden="true"><span>Varve</span></a>
<nav class="nav" aria-label="Main">
{nav}
<a class="nav-ext" href="{REPO}">GitHub</a>
<a class="nav-ext nav-icon" href="{X_URL}" aria-label="Isamu Nagai on X">{X_ICON}</a>
</nav>
<button class="theme-toggle" type="button" aria-pressed="false" aria-label="Switch to dark mode">{SUN_MOON}</button>
</div>
</header>
<main id="main">
{main.strip()}
</main>
<footer class="site-footer">
<div class="wrap">
<div class="foot-top">
<a class="brand" href="index.html"><img class="only-light" src="assets/varve-mark-dark.png" alt="" width="24" height="24"><img class="only-dark" src="assets/varve-mark-light.png" alt="" width="24" height="24" aria-hidden="true"><span>Varve</span></a>
<nav class="foot-nav" aria-label="Footer">
{foot}
<a href="mainnet.html">Mainnet readiness</a>
<a href="{REPO}">Source code</a>
<a href="{X_URL}">X</a>
</nav>
</div>
<p>Mainnet has not launched and no coin can be bought. There will never be a presale, ICO, premine or airdrop: anyone selling "Varve" or "VARV" is running a scam.</p>
<p>Open source under MIT or Apache-2.0.</p>
</div>
</footer>
</body>
</html>
"""


# ------------------------------------------------------------------ Markdown (subset)
def inline(t):
    t = html.escape(t, quote=False)
    t = re.sub(r"`([^`]+)`", lambda m: "<code>" + m.group(1) + "</code>", t)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+|[\w./#-]+)\)", lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', t)
    return t


def slug(t):
    return re.sub(r"[^a-z0-9]+", "-", t.lower()).strip("-")


def markdown(md, heading_offset=0):
    lines = md.split("\n")
    out, i = [], 0
    para = []

    def flush():
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para.clear()

    while i < len(lines):
        ln = lines[i]
        if not ln.strip():
            flush()
            i += 1
            continue
        m = re.match(r"^(#{1,4}) (.*)$", ln)
        if m:
            flush()
            lvl = min(6, len(m.group(1)) + heading_offset)
            txt = m.group(2).strip()
            out.append(f'<h{lvl} id="{slug(txt)}">{inline(txt)}</h{lvl}>')
            i += 1
            continue
        if ln.strip() == "---":
            flush()
            out.append("<hr>")
            i += 1
            continue
        if ln.startswith("    ") and not para:
            code = []
            while i < len(lines) and (lines[i].startswith("    ") or not lines[i].strip()):
                code.append(lines[i][4:])
                i += 1
            while code and not code[-1].strip():
                code.pop()
            out.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
            continue
        if ln.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            head, body = rows[0], [r for r in rows[1:] if not all(re.fullmatch(r":?-+:?", c) for c in r)]
            t = ['<div class="table-wrap"><table><thead><tr>' + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead><tbody>"]
            for r in body:
                t.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            out.append("".join(t))
            continue
        m = re.match(r"^(\s*)([-*]|\d+\.) (.*)$", ln)
        if m:
            flush()
            ordered = m.group(2)[0].isdigit()
            tag = "ol" if ordered else "ul"
            items = []
            while i < len(lines):
                mm = re.match(r"^(\s*)([-*]|\d+\.) (.*)$", lines[i])
                if mm and len(mm.group(1)) == 0:
                    items.append([mm.group(3)])
                elif mm or (lines[i].startswith("  ") and items):
                    items[-1].append(lines[i].strip())
                else:
                    break
                i += 1
            out.append(f"<{tag}>" + "".join("<li>" + inline(" ".join(it)) + "</li>" for it in items) + f"</{tag}>")
            continue
        para.append(ln.strip())
        i += 1
    flush()
    return "\n".join(out)


# ------------------------------------------------------------------ journal
def journal_posts():
    posts = []
    d = os.path.join(SITE, "journal")
    for f in sorted(os.listdir(d)):
        if not f.endswith(".md"):
            continue
        text = open(os.path.join(d, f), encoding="utf-8").read()
        head, _, body = text.partition("\n\n")
        meta = dict(l.split(": ", 1) for l in head.splitlines())
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["date"]), f
        posts.append({"file": f, "id": f[:-3], "title": meta["title"], "date": meta["date"], "body": body.strip()})
    posts.sort(key=lambda p: (p["date"], p["file"]), reverse=True)
    return posts


def human_date(d):
    y, m, dd = d.split("-")
    months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
    return f"{int(dd)} {months[int(m) - 1]} {y}"


def journal_main(posts):
    parts = ["""<section class="page-head">
<div class="wrap narrow">
<p class="eyebrow">Journal</p>
<h1>Development journal</h1>
<p class="lead">Notes from Isamu Nagai on what is being built, what changed, and what comes next. For every detail, the <a href="https://github.com/IsamuNagai/varve/commits/main">commit history</a> is the full record.</p>
</div>
</section>
<div class="wrap narrow prose">"""]
    for p in posts:
        parts.append(f'<article class="entry block reveal" id="{p["id"]}">\n<p class="entry-meta"><time datetime="{p["date"]}">{human_date(p["date"])}</time> · Isamu Nagai</p>\n'
                     f'<h2><a href="#{p["id"]}">{inline(p["title"])}</a></h2>\n{markdown(p["body"], heading_offset=2)}\n</article>')
    parts.append("</div>")
    return "\n".join(parts)


def latest_teaser(posts):
    p = posts[0]
    first = p["body"].split("\n\n")[0].replace("\n", " ")
    return (f'<p class="entry-meta"><time datetime="{p["date"]}">{human_date(p["date"])}</time> · Isamu Nagai</p>\n'
            f'<h3><a href="journal.html#{p["id"]}">{inline(p["title"])}</a></h3>\n<p>{inline(first)}</p>')


def whitepaper_main():
    md = open(os.path.join(ROOT, "whitepaper", "varve-whitepaper.md"), encoding="utf-8").read()
    # title and author line become the page head
    lines = md.split("\n")
    title = lines[0].lstrip("# ").strip()
    body = "\n".join(lines[1:])
    body = re.sub(r"^\*\*Isamu Nagai\*\*\s*$", "", body, count=1, flags=re.M)
    status = re.search(r"^\*(Draft [^*]+)\*\s*$", body, flags=re.M)
    body = body.replace(status.group(0), "", 1) if status else body
    body = re.sub(r"\A\s*---\s*\n", "", body)  # the separator under the title is redundant on the page
    return f"""<section class="page-head">
<div class="wrap narrow">
<p class="eyebrow">Whitepaper</p>
<h1>{inline(title)}</h1>
<p class="lead">Isamu Nagai · {inline(status.group(1) if status else "")}</p>
<p class="actions"><a class="btn" href="{REPO}/blob/main/whitepaper/varve-whitepaper.md">Source in the repository</a><a class="btn" href="{REPO}/commits/main/whitepaper/varve-whitepaper.md">Revision history</a></p>
</div>
</section>
<div class="wrap narrow prose whitepaper">
{markdown(body, heading_offset=0)}
</div>"""


def build():
    out = {}
    posts = journal_posts()
    for name in PAGES:
        if name == "whitepaper.html":
            main = whitepaper_main()
        elif name == "journal.html":
            main = journal_main(posts)
        else:
            main = open(os.path.join(SITE, "pages", name), encoding="utf-8").read()
            main = main.replace("{{LATEST_JOURNAL}}", latest_teaser(posts))
        out[name] = page(name, main)
    out["sitemap.xml"] = sitemap()
    return out


def sync_scan(text):
    """Keep the hand-written explorer page's header, footer and asset version in step."""
    def rel(f):
        return "./" if f == "scan/" else "../" + f
    nav = "\n".join(f'<a href="{rel(f)}"' + (' aria-current="page"' if f == "scan/" else "") + f">{label}</a>" for f, label in NAV)
    foot = "\n".join(f'<a href="{rel(f)}">{label}</a>' for f, label in NAV[1:])
    text = re.sub(r'(<nav class="nav" aria-label="Main">\n).*?(\n<a class="nav-ext" href=)', lambda m: m.group(1) + nav + m.group(2), text, flags=re.S)
    text = re.sub(r'(<nav class="foot-nav" aria-label="Footer">\n).*?(\n<a href="\.\./mainnet\.html">)', lambda m: m.group(1) + foot + m.group(2), text, flags=re.S)
    return re.sub(r'\?v=\d+"', f'?v={ASSET_VERSION}"', text)


def main():
    check = "--check" in sys.argv
    stale = []
    scan = os.path.join(OUT, "scan", "index.html")
    if os.path.exists(scan):
        old = open(scan, encoding="utf-8").read()
        new = sync_scan(old)
        if new != old:
            stale.append("scan/index.html")
            if not check:
                with open(scan, "w", encoding="utf-8") as fh:
                    fh.write(new)
    for name, text in build().items():
        path = os.path.join(OUT, name)
        old = open(path, encoding="utf-8").read() if os.path.exists(path) else None
        # the roadmap block is owned by tools/status.py: compare with it normalized
        norm = lambda s: re.sub(r"<!-- status:begin -->.*?<!-- status:end -->", "<!-- status -->", s or "", flags=re.S)
        if norm(old) != norm(text):
            stale.append(name)
            if not check:
                if old and "<!-- status:begin -->" in old:
                    block = re.search(r"<!-- status:begin -->.*?<!-- status:end -->", old, flags=re.S).group(0)
                    text = re.sub(r"<!-- status:begin -->.*?<!-- status:end -->", lambda _: block, text, flags=re.S)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
    if check and stale:
        sys.exit("site out of date (run python3 -I tools/build-site.py): " + ", ".join(stale))
    print("site: " + ("updated " + ", ".join(stale) if stale else "up to date"))


if __name__ == "__main__":
    main()
