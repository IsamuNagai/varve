#!/usr/bin/env python3
"""Generate the README and website roadmaps from registers/status.json.

  python3 -I tools/status.py          rewrite the generated blocks
  python3 -I tools/status.py --check  exit 1 if any generated block is out of date (CI)

Generated blocks sit between 'status:begin' and 'status:end' marker comments.
"""
import html
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
STATE_LABEL = {"done": "Done", "active": "In progress", "upcoming": "Upcoming"}
STATE_CLASS = {"done": "done", "active": "current", "upcoming": "next"}
SOFT = {"implementation": "imple&shy;mentation"}


def phases():
    with open(os.path.join(ROOT, "registers", "status.json")) as fh:
        ps = json.load(fh)["phases"]
    assert [p["n"] for p in ps] == list(range(len(ps))), "phases must be numbered 0..n-1"
    assert all(p["state"] in STATE_LABEL for p in ps)
    return ps


def readme_block(ps):
    mark = {"done": " ✓", "active": " ◐", "upcoming": ""}
    lines = ["```mermaid", "flowchart LR"]
    for p in ps:
        node = f'    P{p["n"]}["{p["n"]} · {p["name"]}{mark[p["state"]]}"]'
        lines.append(node if p["n"] == 0 else f'    P{p["n"] - 1} --> {node.strip()}')
    lines += ['    P3 -. "critical flaw" .-> P1', "```", "",
              "✓ done · ◐ in progress. Generated from `registers/status.json`."]
    return "\n".join(lines)


def site_block(ps):
    first_active = next((p["n"] for p in ps if p["state"] == "active"), None)
    out = ['<ol class="timeline reveal">']
    for p in ps:
        name = html.escape(p["name"])
        for k, val in SOFT.items():
            name = name.replace(k, val)
        cur = ' aria-current="step"' if p["n"] == first_active else ""
        title = f' title="{html.escape(p["note"])}"' if p.get("note") else ""
        out.append(f'<li class="step {STATE_CLASS[p["state"]]}"{cur}{title}><span class="step-n">{p["n"]:02d}</span>'
                   f'<span class="step-name">{name}</span><span class="step-state">{STATE_LABEL[p["state"]]}</span></li>')
    out.append("</ol>")
    return "\n".join(out)


TARGETS = [
    ("README.md", "<!-- status:begin -->", "<!-- status:end -->", readme_block),
    ("docs/index.html", "<!-- status:begin -->", "<!-- status:end -->", site_block),
]


def main():
    check = "--check" in sys.argv
    ps, stale = phases(), []
    for rel, begin, end, gen in TARGETS:
        path = os.path.join(ROOT, rel)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        pat = re.compile(re.escape(begin) + r"\n.*?\n" + re.escape(end), re.S)
        if not pat.search(text):
            sys.exit(f"{rel}: status markers missing")
        new = pat.sub(lambda _: f"{begin}\n{gen(ps)}\n{end}", text)
        if new != text:
            stale.append(rel)
            if not check:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(new)
    if check and stale:
        sys.exit("status out of date (run python3 -I tools/status.py): " + ", ".join(stale))
    print("status: " + ("updated " + ", ".join(stale) if stale else "up to date"))


if __name__ == "__main__":
    main()
