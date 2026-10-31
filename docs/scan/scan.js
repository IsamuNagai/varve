/* Varvescan: block explorer for Varve.
 *
 * Static, no dependencies. Reads the node's public read-only API (node/API.md).
 * Every value from the API is treated as untrusted: it is validated before it is
 * used in a URL or route, and rendered with textContent / createElement only.
 */
(function () {
  "use strict";

  /* Public testnet API base, e.g. "https://testnet.example.org" (no trailing slash).
   * Empty until the first public node is online. */
  var TESTNET_API = "";

  var NET_KEY = "varvescan-network";
  var LAMINAE_PER_VARV = 100000000n;
  var BLOCK_PAGE = 20;
  var HISTORY_PAGE = 25;
  var TX_BATCH = 25;
  var TIMEOUT_MS = 15000;

  var RE_HEX64 = /^[0-9a-f]{64}$/;
  var RE_HEX = /^[0-9a-f]{1,128}$/;
  var RE_ADDR = /^[a-z0-9]{8,200}$/;
  var RE_ADDR_LIKE = /^[tr]?varve1[a-z0-9]{6,200}$/;
  var RE_HEIGHT = /^[0-9]{1,10}$/;
  var RE_AMOUNT = /^-?[0-9]{1,40}$/;
  var RE_DECIMAL = /^[0-9]{1,80}(\.[0-9]{1,18})?$/;
  var RE_WORD = /^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,40}$/;
  var MAX_HEIGHT = 4294967295;

  var view = document.getElementById("scan-view");
  var searchForm = document.getElementById("scan-search");
  var searchInput = document.getElementById("scan-q");
  var netButtons = document.querySelectorAll("[data-net]");
  var apiNote = document.getElementById("scan-api-note");
  if (!view) { return; }

  /* ------------------------------------------------------------ API base */

  function readOverride() {
    var raw = null;
    try { raw = new URLSearchParams(window.location.search).get("api"); } catch (e) { raw = null; }
    if (raw === null) { return { base: null, rejected: false }; }
    var m = /^http:\/\/(127\.0\.0\.1|localhost):([0-9]{1,5})\/?$/.exec(raw);
    if (m) {
      var port = Number(m[2]);
      if (port >= 1 && port <= 65535) { return { base: "http://" + m[1] + ":" + port, rejected: false }; }
    }
    return { base: null, rejected: true };
  }

  var override = readOverride();

  function validConstBase(b) {
    return typeof b === "string" && /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?(\/[A-Za-z0-9._~-]+)*$/.test(b);
  }

  function getNet() {
    try {
      var v = window.localStorage.getItem(NET_KEY);
      if (v === "mainnet" || v === "testnet") { return v; }
    } catch (e) { /* storage unavailable */ }
    return "testnet";
  }

  function setNet(v) {
    try { window.localStorage.setItem(NET_KEY, v); } catch (e) { /* storage unavailable */ }
  }

  function apiBase() {
    if (getNet() !== "testnet") { return null; }
    if (override.base) { return override.base; }
    return validConstBase(TESTNET_API) ? TESTNET_API : null;
  }

  /* ------------------------------------------------------------ fetch */

  function ApiError(kind, status, message) {
    this.kind = kind;       // "http" | "network" | "timeout" | "format"
    this.status = status;   // HTTP status or 0
    this.message = message; // text from the node (untrusted), may be ""
  }

  function api(path) {
    var base = apiBase();
    if (!base) { return Promise.reject(new ApiError("network", 0, "")); }
    var ctrl = new AbortController();
    var timer = window.setTimeout(function () { ctrl.abort(); }, TIMEOUT_MS);
    return fetch(base + path, {
      method: "GET",
      credentials: "omit",
      mode: "cors",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { "Accept": "application/json" },
      signal: ctrl.signal
    }).then(function (res) {
      var ct = (res.headers.get("content-type") || "").toLowerCase();
      var isJson = /^application\/json(\s*;|$)/.test(ct);
      if (!res.ok) {
        if (!isJson) { throw new ApiError("http", res.status, ""); }
        return res.json().then(function (body) {
          var msg = body && typeof body.error === "string" ? body.error.slice(0, 200) : "";
          throw new ApiError("http", res.status, msg);
        }, function () { throw new ApiError("http", res.status, ""); });
      }
      if (!isJson) { throw new ApiError("format", res.status, ""); }
      return res.json().then(function (body) {
        if (body === null || typeof body !== "object") { throw new ApiError("format", res.status, ""); }
        return body;
      }, function () { throw new ApiError("format", res.status, ""); });
    }, function (err) {
      if (err && err.name === "AbortError") { throw new ApiError("timeout", 0, ""); }
      throw new ApiError("network", 0, "");
    }).finally(function () { window.clearTimeout(timer); });
  }

  /* ------------------------------------------------------------ validation */

  function isStr(v) { return typeof v === "string"; }
  function isHash(v) { return isStr(v) && RE_HEX64.test(v); }
  function isAddr(v) { return isStr(v) && RE_ADDR.test(v); }
  function isUint(v) { return typeof v === "number" && Number.isSafeInteger(v) && v >= 0; }
  function isHeight(v) { return isUint(v) && v <= MAX_HEIGHT; }
  function isNum(v) { return typeof v === "number" && Number.isFinite(v) && v >= 0; }
  function isAmount(v) { return isStr(v) && RE_AMOUNT.test(v); }
  function isTime(v) { return isUint(v) && v < 1e11; }
  function arr(v) { return Array.isArray(v) ? v : []; }

  function routeBlock(id) {
    if (isHeight(id)) { return "#/block/" + id; }
    if (isHash(id)) { return "#/block/" + encodeURIComponent(id); }
    return null;
  }
  function routeTx(id) { return isHash(id) ? "#/tx/" + encodeURIComponent(id) : null; }
  function routeAddr(a) { return isAddr(a) ? "#/address/" + encodeURIComponent(a) : null; }

  /* ------------------------------------------------------------ DOM helpers */

  function el(tag, attrs) {
    var n = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) { return; }
        if (k === "class") { n.className = v; }
        else if (k === "text") { n.textContent = String(v); }
        else if (k === "onclick") { n.addEventListener("click", v); }
        else { n.setAttribute(k, v === true ? "" : String(v)); }
      });
    }
    for (var i = 2; i < arguments.length; i++) { add(n, arguments[i]); }
    return n;
  }

  function add(parent, c) {
    if (c === null || c === undefined || c === false) { return; }
    if (Array.isArray(c)) { c.forEach(function (x) { add(parent, x); }); return; }
    if (typeof c === "string" || typeof c === "number") { parent.appendChild(document.createTextNode(String(c))); return; }
    parent.appendChild(c);
  }

  var SVG_NS = "http://www.w3.org/2000/svg";
  var ICONS = {
    copy: ["M9 9h10v10H9z", "M5 15V5h10"],
    check: ["M5 12.5l4.5 4.5L19 7.5"],
    left: ["M15 5l-7 7 7 7"],
    right: ["M9 5l7 7-7 7"],
    arrow: ["M4 12h15", "M13 6l6 6-6 6"],
    search: ["M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13z", "M15.5 15.5L20 20"]
  };
  function icon(name) {
    var s = document.createElementNS(SVG_NS, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("aria-hidden", "true");
    s.setAttribute("focusable", "false");
    s.setAttribute("class", "icon");
    ICONS[name].forEach(function (d) {
      var p = document.createElementNS(SVG_NS, "path");
      p.setAttribute("d", d);
      s.appendChild(p);
    });
    return s;
  }

  function link(href, content, cls) {
    if (!href) { return el("span", { class: (cls || "") + " invalid", title: "Invalid value from the node" }, content); }
    return el("a", { href: href, class: cls || null }, content);
  }

  /* A hash shown in full on wide screens and shortened on narrow ones. */
  function hashText(h) {
    if (!isStr(h)) { return el("span", { class: "muted" }, "unknown"); }
    var full = h.slice(0, 128);
    var short = full.length > 20 ? full.slice(0, 10) + "…" + full.slice(-8) : full;
    return el("span", { class: "hash", title: full },
      el("span", { class: "h-full" }, full), el("span", { class: "h-short" }, short));
  }

  function shortText(h, head, tail) {
    if (!isStr(h)) { return "unknown"; }
    var s = h.slice(0, 200);
    return s.length > head + tail + 1 ? s.slice(0, head) + "…" + s.slice(-tail) : s;
  }

  function txLink(id) { return link(routeTx(id), hashText(id), "mono"); }
  function addrLink(a, full) {
    var txt = full ? el("span", { class: "addr" }, isStr(a) ? a.slice(0, 200) : "unknown")
      : el("span", { class: "addr", title: isStr(a) ? a.slice(0, 200) : null }, shortText(a, 14, 8));
    return link(routeAddr(a), txt, "mono");
  }
  function heightLink(h) { return isHeight(h) ? link(routeBlock(h), fmtInt(h)) : el("span", { class: "muted" }, "unknown"); }

  function copyButton(value, label) {
    var b = el("button", { type: "button", class: "copy", "aria-label": label || "Copy" }, icon("copy"), el("span", { text: "Copy" }));
    b.addEventListener("click", function () {
      var done = function () {
        b.classList.add("is-done");
        b.replaceChildren(icon("check"), el("span", { text: "Copied" }));
        window.setTimeout(function () {
          b.classList.remove("is-done");
          b.replaceChildren(icon("copy"), el("span", { text: "Copy" }));
        }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(done, function () { fallbackCopy(value) && done(); });
      } else if (fallbackCopy(value)) { done(); }
    });
    return b;
  }

  function fallbackCopy(value) {
    var t = el("textarea", { class: "copy-buffer", readonly: true, "aria-hidden": "true" });
    t.value = value;
    document.body.appendChild(t);
    t.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    t.remove();
    return ok;
  }

  /* ------------------------------------------------------------ formatting */

  var intFmt = new Intl.NumberFormat("en-US");
  function fmtInt(n) { return isNum(n) ? intFmt.format(n) : "unknown"; }
  function group(digits) { return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ","); }

  /* laminae decimal string -> VARV string, up to 8 decimals, trailing zeros trimmed */
  function fmtVarv(s, signed) {
    if (!isAmount(s)) { return null; }
    var n = BigInt(s);
    var neg = n < 0n;
    if (neg) { n = -n; }
    var whole = n / LAMINAE_PER_VARV;
    var frac = (n % LAMINAE_PER_VARV).toString().padStart(8, "0").replace(/0+$/, "");
    var sign = neg ? "−" : (signed && n > 0n ? "+" : "");
    return sign + group(whole.toString()) + (frac ? "." + frac : "");
  }

  function varv(s, opts) {
    opts = opts || {};
    var txt = fmtVarv(s, opts.signed);
    if (txt === null) { return el("span", { class: "muted", title: "Invalid amount from the node" }, "unknown"); }
    var cls = "amt";
    if (opts.signed) {
      var n = BigInt(s);
      cls += n > 0n ? " pos" : (n < 0n ? " neg" : "");
    }
    return el("span", { class: cls }, el("span", { class: "amt-n", text: txt }), el("span", { class: "unit" }, " VARV"));
  }

  function sumAmounts(list) {
    var t = 0n;
    for (var i = 0; i < list.length; i++) {
      if (!list[i] || !isAmount(list[i].amount)) { return null; }
      t += BigInt(list[i].amount);
    }
    return t.toString();
  }

  function fmtDecimal(s) {
    if (!isStr(s) || !RE_DECIMAL.test(s)) { return "unknown"; }
    var p = s.split(".");
    var frac = p[1] ? p[1].slice(0, 8).replace(/0+$/, "") : "";
    return group(p[0].replace(/^0+(?=\d)/, "")) + (frac ? "." + frac : "");
  }

  function fmtRate(v) {
    if (!isNum(v)) { return "unknown"; }
    return (Math.round(v * 1000) / 1000).toLocaleString("en-US", { maximumFractionDigits: 3 });
  }

  function pad(n) { return n < 10 ? "0" + n : String(n); }
  function utc(ts) {
    var d = new Date(ts * 1000);
    return d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()) + " " +
      pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds()) + " UTC";
  }

  function rel(ts) {
    var diff = Math.round(Date.now() / 1000 - ts);
    if (diff < -120) { return "in the future"; }
    if (diff < 45) { return "just now"; }
    var m = Math.max(1, Math.floor(diff / 60));
    if (m < 60) { return m + " min ago"; }
    var h = Math.floor(diff / 3600);
    if (h < 48) { return h + (h === 1 ? " hour ago" : " hours ago"); }
    var d = Math.floor(diff / 86400);
    if (d < 60) { return d + " days ago"; }
    return utc(ts).slice(0, 10);
  }

  function timeNode(ts) {
    if (!isTime(ts)) { return el("span", { class: "muted" }, "unknown"); }
    var iso = new Date(ts * 1000).toISOString();
    return el("time", { datetime: iso, title: utc(ts), "data-ts": ts }, rel(ts));
  }

  window.setInterval(function () {
    var ts = view.querySelectorAll("time[data-ts]");
    for (var i = 0; i < ts.length; i++) {
      var v = Number(ts[i].getAttribute("data-ts"));
      if (isTime(v)) { ts[i].textContent = rel(v); }
    }
  }, 30000);

  var PATHS = ["primary key", "recovery key", "shared signature"];
  var PATH_HINTS = [
    "Signed with the output's primary key",
    "Signed with the output's recovery key, after its delay",
    "Covered by the signature of an earlier input in this transaction"
  ];

  function word(v) { return isStr(v) && RE_WORD.test(v) ? v : null; }

  /* ------------------------------------------------------------ building blocks */

  function sectionHead(title, extra) {
    return el("div", { class: "sec-head" }, el("h2", { text: title }), extra || null);
  }

  function kv(rows) {
    var dl = el("dl", { class: "kv" });
    rows.forEach(function (r) {
      if (!r) { return; }
      dl.appendChild(el("div", { class: "kv-row" }, el("dt", { text: r[0] }), el("dd", null, r[1])));
    });
    return dl;
  }

  function chip(text, cls, title) { return el("span", { class: "chip" + (cls ? " " + cls : ""), title: title || null }, text); }

  function stat(label, value, sub) {
    return el("div", { class: "stat" },
      el("p", { class: "stat-label", text: label }),
      el("p", { class: "stat-value" }, value),
      sub ? el("p", { class: "stat-sub" }, sub) : null);
  }

  function loadingBox(text) {
    return el("div", { class: "scan-loading", role: "status" },
      el("span", { class: "loader", "aria-hidden": "true" }, el("i"), el("i"), el("i")),
      el("span", { text: text || "Loading…" }));
  }

  function panel(opts) {
    var box = el("section", { class: "scan-panel" + (opts.cls ? " " + opts.cls : "") });
    if (opts.mark) {
      box.appendChild(el("div", { class: "panel-mark", "aria-hidden": "true" },
        el("img", { class: "only-light", src: "../assets/varve-mark-dark.png", alt: "", width: 44, height: 44 }),
        el("img", { class: "only-dark", src: "../assets/varve-mark-light.png", alt: "", width: 44, height: 44 })));
    }
    if (opts.eyebrow) { box.appendChild(el("p", { class: "eyebrow", text: opts.eyebrow })); }
    box.appendChild(el("h2", { text: opts.title, tabindex: "-1" }));
    (opts.body || []).forEach(function (p) { box.appendChild(typeof p === "string" ? el("p", { text: p }) : p); });
    if (opts.actions && opts.actions.length) { box.appendChild(el("p", { class: "panel-actions" }, opts.actions)); }
    return box;
  }

  function errorBox(err, retry, compact) {
    var e = err instanceof ApiError ? err : new ApiError("format", 0, "");
    var title, text, code;
    if (e.kind === "timeout") {
      code = "Timeout"; title = "The node took too long";
      text = "No answer within 15 seconds. The node may be busy; try again in a moment.";
    } else if (e.kind === "network") {
      code = "Network"; title = "Cannot reach the node";
      text = "The request failed before the node answered. Check your connection, or the node may be offline.";
    } else if (e.kind === "format") {
      code = "Response"; title = "Unexpected response";
      text = "The node answered with something that is not valid explorer data.";
    } else if (e.status === 404) {
      code = "404"; title = "Not found";
      text = "The node does not know this block, transaction or address.";
    } else if (e.status === 429) {
      code = "429"; title = "Slow down";
      text = "Too many requests in a short time. Wait a few seconds, then try again.";
    } else if (e.status === 503) {
      code = "503"; title = "The node is still syncing";
      text = "It is catching up with the network. Try again shortly.";
    } else if (e.status === 400) {
      code = "400"; title = "Bad request";
      text = "The node could not understand this request.";
    } else {
      code = String(e.status || "Error"); title = "Something went wrong";
      text = "The node returned an error.";
    }
    var body = [text];
    if (e.message) {
      body.push(el("p", { class: "node-msg" }, el("span", { class: "muted", text: "Message from the node: " }), el("span", { text: e.message })));
    }
    var actions = [];
    if (retry) { actions.push(el("button", { type: "button", class: "btn", onclick: retry }, "Try again")); }
    if (e.status === 404) { actions.push(el("a", { class: "btn", href: "#/" }, "Explorer home")); }
    return panel({ cls: "is-error" + (compact ? " is-compact" : ""), eyebrow: code, title: title, body: body, actions: actions });
  }

  /* ------------------------------------------------------------ routing */

  var token = 0;

  function parseRoute() {
    var h = window.location.hash || "";
    if (h === "" || h === "#" || h === "#/") { return { name: "home" }; }
    if (h.slice(0, 2) !== "#/") { return null; }
    var parts = h.slice(2).split("/");
    var name = parts[0];
    var arg = parts.slice(1).join("/");
    try { arg = decodeURIComponent(arg); } catch (e) { arg = ""; }
    arg = arg.trim();
    if (arg.length > 200) { arg = ""; }
    return { name: name, arg: arg };
  }

  function setTitle(t) { document.title = t ? t + " · Varvescan" : "Varvescan · Varve block explorer"; }

  function show(nodes, focus) {
    view.replaceChildren();
    add(view, nodes);
    view.removeAttribute("aria-busy");
    if (focus) {
      var h = view.querySelector("h2");
      if (h) {
        if (!h.hasAttribute("tabindex")) { h.setAttribute("tabindex", "-1"); }
        h.focus({ preventScroll: true });
      }
    }
  }

  function syncNetButtons() {
    var net = getNet();
    for (var i = 0; i < netButtons.length; i++) {
      netButtons[i].setAttribute("aria-pressed", netButtons[i].getAttribute("data-net") === net ? "true" : "false");
    }
    if (apiNote) {
      apiNote.replaceChildren();
      if (override.base && net === "testnet") {
        apiNote.appendChild(el("span", { class: "chip local" }, "Local API: " + override.base));
      }
      apiNote.hidden = !apiNote.firstChild;
    }
  }

  function render(fromNav) {
    var route = parseRoute();
    if (route === null) { return; } // an in-page anchor such as #main
    var tk = ++token;
    var live = function () { return tk === token; };
    syncNetButtons();
    view.setAttribute("aria-busy", "true");
    if (fromNav) { window.scrollTo(0, 0); }

    if (getNet() === "mainnet") { setTitle("Mainnet"); show(mainnetPanel(), fromNav); return; }
    if (!apiBase()) { setTitle(null); show(pendingPanel(), fromNav); return; }

    var a = route.arg;
    switch (route.name) {
      case "home": return renderHome(live, fromNav);
      case "block":
        if (RE_HEIGHT.test(a) && Number(a) <= MAX_HEIGHT) { return renderBlock(String(Number(a)), live, fromNav); }
        if (RE_HEX64.test(a.toLowerCase())) { return renderBlock(a.toLowerCase(), live, fromNav); }
        return show(badInput("block", "That is not a block height or a 64-character block hash."), fromNav);
      case "tx":
        if (RE_HEX64.test(a.toLowerCase())) { return renderTx(a.toLowerCase(), live, fromNav); }
        return show(badInput("transaction", "A transaction id is 64 hexadecimal characters."), fromNav);
      case "address":
        if (RE_ADDR.test(a.toLowerCase())) { return renderAddress(a.toLowerCase(), live, fromNav); }
        return show(badInput("address", "Addresses contain only lowercase letters and digits."), fromNav);
      case "search": return renderSearch(a, live, fromNav);
      default:
        setTitle("Not found");
        return show(panel({ cls: "is-error", eyebrow: "404", title: "Not found", body: ["This explorer page does not exist."],
          actions: [el("a", { class: "btn", href: "#/" }, "Explorer home")] }), fromNav);
    }
  }

  function badInput(kind, text) {
    setTitle("Not found");
    return panel({ cls: "is-error", eyebrow: "Not found", title: "Not a valid " + kind, body: [text],
      actions: [el("a", { class: "btn", href: "#/" }, "Explorer home")] });
  }

  function mainnetPanel() {
    return panel({
      mark: true, cls: "is-feature", eyebrow: "Mainnet",
      title: "Mainnet has not launched",
      body: [
        "There is no mainnet chain yet, so there is nothing to explore here.",
        "No coin can be bought. There will never be a presale, ICO, premine or airdrop: anyone selling “Varve” or “VARV” is running a scam."
      ],
      actions: [
        el("button", { type: "button", class: "btn primary", onclick: function () { switchNet("testnet"); } }, "Switch to testnet"),
        el("a", { class: "btn", href: "../faq.html" }, "Read the FAQ")
      ]
    });
  }

  function pendingPanel() {
    var body = ["The testnet explorer goes live when the first public node is online.",
      "Progress is posted in the journal. Meanwhile you can run your own node on a private network and follow along."];
    if (override.rejected) {
      body.push(el("p", { class: "node-msg" },
        "The ?api= value in this link was ignored. For local development only http://127.0.0.1:<port> or http://localhost:<port> is accepted."));
    }
    return panel({
      mark: true, cls: "is-feature", eyebrow: "Testnet",
      title: "Not live yet",
      body: body,
      actions: [el("a", { class: "btn primary", href: "../journal.html" }, "Read the journal"),
        el("a", { class: "btn", href: "https://github.com/IsamuNagai/varve" }, "Source code")]
    });
  }

  function switchNet(net) {
    if (net !== "testnet" && net !== "mainnet") { return; }
    setNet(net);
    render(true);
  }

  /* ------------------------------------------------------------ home */

  function renderHome(live, fromNav) {
    setTitle(null);
    show(loadingBox("Loading the latest blocks…"));
    Promise.allSettled([api("/api/v1/info"), api("/api/v1/fees"),
      api("/api/v1/blocks?limit=" + BLOCK_PAGE), api("/api/v1/mempool")]).then(function (r) {
      if (!live()) { return; }
      if (r[0].status === "rejected") { show(errorBox(r[0].reason, function () { render(false); }), fromNav); return; }
      var info = r[0].value;
      var out = [statsSection(info, r[1].status === "fulfilled" ? r[1].value : null)];
      var cols = el("div", { class: "home-cols" });
      cols.appendChild(blocksSection(r[2], live));
      cols.appendChild(mempoolSection(r[3]));
      out.push(cols);
      show(out, fromNav);
    });
  }

  function statsSection(info, fees) {
    var meta = el("div", { class: "net-meta" });
    var net = word(info.network);
    if (net) { meta.appendChild(chip(net, "net")); }
    if (word(info.version)) { meta.appendChild(chip("Node " + info.version)); }
    if (info.syncing === true) { meta.appendChild(chip("Syncing", "warn", "This node is still catching up; recent data may be missing")); }

    var feeVal = el("span", { class: "fees" });
    if (fees && typeof fees === "object") {
      [["slow", "Slow"], ["normal", "Normal"], ["fast", "Fast"]].forEach(function (f) {
        feeVal.appendChild(el("span", { class: "fee" }, el("b", { text: fmtRate(fees[f[0]]) }), el("small", { text: f[1] })));
      });
    } else {
      feeVal.appendChild(el("span", { class: "muted", text: "unavailable" }));
    }
    var mp = info.mempool && typeof info.mempool === "object" ? info.mempool : {};

    var grid = el("div", { class: "stats" },
      stat("Height", isHeight(info.height) ? link(routeBlock(info.height), fmtInt(info.height)) : "unknown",
        isHash(info.best) ? link(routeBlock(info.best), shortText(info.best, 10, 6), "mono") : null),
      stat("Last block", timeNode(info.time), isTime(info.time) ? utc(info.time) : null),
      stat("Difficulty", fmtDecimal(info.difficulty), "relative to genesis"),
      stat("Supply", varv(info.supply), "mined so far"),
      stat("Mempool", isUint(mp.count) ? fmtInt(mp.count) + (mp.count === 1 ? " tx" : " txs") : "unknown",
        isUint(mp.weight) ? fmtInt(mp.weight) + " WU" : null),
      stat("Fee rates", feeVal, fees && isNum(fees.min) ? "lam/WU · min " + fmtRate(fees.min) : "laminae per WU")
    );
    return el("section", { class: "home-stats", "aria-label": "Network status" }, el("h2", { class: "visually-hidden", text: "Network status" }), meta, grid);
  }

  function blockRow(b) {
    if (!b || typeof b !== "object") { return null; }
    return el("li", { class: "row brow" },
      el("div", { class: "brow-h" },
        heightLink(b.height),
        timeNode(b.time)),
      el("div", { class: "brow-id" },
        link(routeBlock(b.hash), hashText(b.hash), "mono"),
        el("span", { class: "muted small" }, "Miner ", addrLink(b.miner))),
      el("div", { class: "brow-n" },
        el("span", { text: isUint(b.txs) ? fmtInt(b.txs) + (b.txs === 1 ? " tx" : " txs") : "" }),
        el("span", { class: "muted small", text: isUint(b.size) ? fmtInt(b.size) + " B" : "" })),
      el("div", { class: "brow-r" }, varv(b.reward), el("span", { class: "muted small", text: "reward" })));
  }

  function blocksSection(result, live) {
    var sec = el("section", { class: "card-sec blocks-sec", "aria-labelledby": "latest-blocks" });
    sec.appendChild(sectionHead("Latest blocks"));
    sec.querySelector("h2").id = "latest-blocks";
    if (result.status === "rejected") { sec.appendChild(errorBox(result.reason, function () { render(false); }, true)); return sec; }
    var blocks = arr(result.value.blocks);
    if (!blocks.length) { sec.appendChild(emptyBox("No blocks yet.")); return sec; }
    var list = el("ol", { class: "rows" });
    var lowest = Infinity;
    var addBlocks = function (bs) {
      bs.forEach(function (b) {
        if (b && isHeight(b.height) && b.height < lowest) { lowest = b.height; list.appendChild(blockRow(b)); }
      });
    };
    addBlocks(blocks);
    sec.appendChild(list);
    var more = el("div", { class: "more" });
    var btn = el("button", { type: "button", class: "btn" }, "Load more blocks");
    var update = function (n) { if (lowest === 0 || lowest === Infinity || n < BLOCK_PAGE) { more.remove(); } };
    btn.addEventListener("click", function () {
      btn.disabled = true;
      btn.textContent = "Loading…";
      api("/api/v1/blocks?before=" + lowest + "&limit=" + BLOCK_PAGE).then(function (r) {
        if (!live()) { return; }
        var bs = arr(r.blocks);
        addBlocks(bs);
        btn.disabled = false;
        btn.textContent = "Load more blocks";
        update(bs.length);
      }, function (err) {
        if (!live()) { return; }
        btn.disabled = false;
        btn.textContent = "Load more blocks";
        more.replaceChildren(errorBox(err, null, true), btn);
      });
    });
    more.appendChild(btn);
    sec.appendChild(more);
    update(blocks.length);
    return sec;
  }

  function emptyBox(text) { return el("p", { class: "empty", text: text }); }

  function mempoolSection(result) {
    var sec = el("section", { class: "card-sec mempool-sec", "aria-labelledby": "mempool-h" });
    var head = sectionHead("Mempool");
    head.querySelector("h2").id = "mempool-h";
    sec.appendChild(head);
    if (result.status === "rejected") { sec.appendChild(errorBox(result.reason, function () { render(false); }, true)); return sec; }
    var m = result.value;
    if (isUint(m.count)) {
      head.appendChild(el("span", { class: "muted small", text: fmtInt(m.count) + " waiting" + (isUint(m.weight) ? " · " + fmtInt(m.weight) + " WU" : "") }));
    }
    var txs = arr(m.txs);
    if (!txs.length) { sec.appendChild(emptyBox("The mempool is empty. Every known transaction is in a block.")); return sec; }
    var list = el("ol", { class: "rows" });
    txs.slice(0, 100).forEach(function (t) {
      if (!t || typeof t !== "object") { return; }
      list.appendChild(el("li", { class: "row mrow" },
        el("div", { class: "mrow-id" }, txLink(t.txid), timeNode(t.time)),
        el("div", { class: "mrow-r" },
          varv(t.fee),
          el("span", { class: "muted small", text: fmtRate(t.feerate) + " lam/WU · " + (isUint(t.weight) ? fmtInt(t.weight) + " WU" : "") }))));
    });
    sec.appendChild(list);
    if (isUint(m.count) && m.count > txs.length) {
      sec.appendChild(el("p", { class: "muted small foot-note", text: "Showing the " + txs.length + " highest fee rates of " + fmtInt(m.count) + "." }));
    }
    return sec;
  }

  /* ------------------------------------------------------------ block */

  function pageHead(eyebrow, title, idValue, extra) {
    var h = el("div", { class: "page-title" },
      el("p", { class: "eyebrow", text: eyebrow }),
      el("h2", { text: title }));
    if (idValue) {
      h.appendChild(el("div", { class: "id-line" }, el("code", { class: "id-text", text: idValue }), copyButton(idValue, "Copy " + eyebrow.toLowerCase())));
    }
    if (extra) { h.appendChild(extra); }
    return h;
  }

  function renderBlock(id, live, fromNav) {
    setTitle("Block " + (RE_HEIGHT.test(id) ? id : shortText(id, 8, 6)));
    show(loadingBox("Loading block…"));
    api("/api/v1/block/" + encodeURIComponent(id)).then(function (b) {
      if (!live()) { return; }
      if (isHeight(b.height)) { setTitle("Block " + fmtInt(b.height)); }
      var txids = arr(b.txids).slice(0, 100000);
      var nav = el("div", { class: "pager" },
        isHash(b.prev) && b.height !== 0
          ? el("a", { class: "btn small", href: routeBlock(isHeight(b.height) && b.height > 0 ? b.height - 1 : b.prev) }, icon("left"), "Previous")
          : el("span", { class: "btn small is-disabled", "aria-disabled": "true" }, icon("left"), "Genesis"),
        isHash(b.next)
          ? el("a", { class: "btn small", href: routeBlock(b.next) }, "Next", icon("right"))
          : el("span", { class: "btn small is-disabled", "aria-disabled": "true" }, "Tip", icon("right")));

      var head = pageHead("Block", isHeight(b.height) ? "Block " + fmtInt(b.height) : "Block", isHash(b.hash) ? b.hash : null, nav);

      var details = el("section", { class: "card-sec" }, sectionHead("Details"), kv([
        ["Height", isHeight(b.height) ? fmtInt(b.height) : "unknown"],
        ["Confirmations", isUint(b.confirmations) ? fmtInt(b.confirmations) : "unknown"],
        ["Time", [timeNode(b.time), isTime(b.time) ? el("span", { class: "muted small", text: " · " + utc(b.time) }) : null]],
        ["Median time past", isTime(b.mtp) ? utc(b.mtp) : "unknown"],
        ["Transactions", fmtInt(txids.length)],
        ["Size", isUint(b.size) ? fmtInt(b.size) + " bytes" : "unknown"],
        ["Weight", isUint(b.weight) ? fmtInt(b.weight) + " WU" : "unknown"],
        ["Reward", varv(b.reward)],
        ["Subsidy", varv(b.subsidy)],
        ["Fees", varv(b.fees)],
        ["Miner", addrLink(b.miner, true)],
        ["Previous block", isHash(b.prev) ? link(routeBlock(b.prev), b.prev, "mono break") : el("span", { class: "muted", text: "none (genesis)" })],
        ["Next block", isHash(b.next) ? link(routeBlock(b.next), b.next, "mono break") : el("span", { class: "muted", text: "none yet (this is the tip)" })],
        ["Target", isStr(b.target) && RE_HEX.test(b.target) ? el("span", { class: "mono break", text: b.target }) : "unknown"],
        ["Nonce", isStr(b.nonce) && /^[0-9]{1,40}$/.test(b.nonce) ? el("span", { class: "mono", text: group(b.nonce) }) : "unknown"]
      ]));

      var txSec = el("section", { class: "card-sec" }, sectionHead("Transactions", el("span", { class: "muted small", text: fmtInt(txids.length) })));
      if (!txids.length) {
        txSec.appendChild(emptyBox("This block has no transactions."));
      } else {
        var list = el("ol", { class: "rows txrows" });
        txSec.appendChild(list);
        var more = el("div", { class: "more" });
        var btn = el("button", { type: "button", class: "btn" });
        var shown = 0;
        var next = function () {
          var batch = txids.slice(shown, shown + TX_BATCH);
          var start = shown;
          shown += batch.length;
          var cells = batch.map(function (id, i) {
            var meta = el("div", { class: "txrow-meta" }, el("span", { class: "muted small", text: "…" }));
            list.appendChild(el("li", { class: "row txrow" },
              el("span", { class: "txrow-n muted", text: "#" + (start + i) }),
              el("div", { class: "txrow-id" }, txLink(id)),
              meta));
            return { id: id, meta: meta };
          });
          var rest = txids.length - shown;
          if (rest > 0) { btn.textContent = "Show " + Math.min(TX_BATCH, rest) + " more of " + fmtInt(rest); }
          else { more.remove(); }
          return runPool(cells, 4, function (c) {
            if (!isHash(c.id)) { c.meta.replaceChildren(el("span", { class: "muted small", text: "invalid id" })); return Promise.resolve(); }
            return api("/api/v1/tx/" + encodeURIComponent(c.id)).then(function (tx) {
              if (live()) { c.meta.replaceChildren(); add(c.meta, txSummary(tx)); }
            }, function (err) {
              if (live()) { c.meta.replaceChildren(el("span", { class: "muted small", text: err && err.status === 429 ? "slow down" : "details unavailable" })); }
            });
          }, live);
        };
        btn.addEventListener("click", function () { next(); });
        more.appendChild(btn);
        txSec.appendChild(more);
        next();
      }
      show([head, details, txSec], fromNav);
    }, function (err) {
      if (!live()) { return; }
      setTitle(err.status === 404 ? "Not found" : "Error");
      show(errorBox(err, function () { render(false); }), fromNav);
    });
  }

  function runPool(items, n, fn, live) {
    var i = 0;
    var worker = function () {
      if (i >= items.length || !live()) { return Promise.resolve(); }
      var item = items[i++];
      return fn(item).then(worker, worker);
    };
    var ws = [];
    for (var k = 0; k < Math.min(n, items.length); k++) { ws.push(worker()); }
    return Promise.all(ws);
  }

  function txSummary(tx) {
    var outs = arr(tx.outputs);
    var total = sumAmounts(outs);
    var parts = [];
    if (tx.coinbase === true) { parts.push(chip("Block reward", "gold")); }
    else { parts.push(el("span", { class: "muted small", text: arr(tx.inputs).length + " in · " + outs.length + " out" })); }
    parts.push(total === null ? el("span", { class: "muted", text: "unknown" }) : varv(total));
    if (tx.coinbase !== true && isAmount(tx.fee)) {
      parts.push(el("span", { class: "muted small" }, "fee ", el("span", { text: fmtVarv(tx.fee) })));
    }
    return parts;
  }

  /* ------------------------------------------------------------ transaction */

  function renderTx(id, live, fromNav) {
    setTitle("Transaction " + shortText(id, 8, 6));
    show(loadingBox("Loading transaction…"));
    api("/api/v1/tx/" + encodeURIComponent(id)).then(function (tx) {
      if (!live()) { return; }
      var confirmed = tx.status === "confirmed";
      var badges = el("div", { class: "badges" },
        confirmed ? chip("Confirmed", "ok") : (tx.status === "mempool" ? chip("In mempool", "warn") : chip("Unknown status")),
        isUint(tx.confirmations) && confirmed ? chip(fmtInt(tx.confirmations) + (tx.confirmations === 1 ? " confirmation" : " confirmations")) : null,
        tx.coinbase === true ? chip("Block reward", "gold") : null);
      var head = pageHead("Transaction", tx.coinbase === true ? "Block reward" : "Transaction", isHash(tx.txid) ? tx.txid : id, badges);

      var inputs = arr(tx.inputs);
      var outputs = arr(tx.outputs);
      var inTotal = sumAmounts(inputs);
      var outTotal = sumAmounts(outputs);

      var details = el("section", { class: "card-sec" }, sectionHead("Details"), kv([
        ["Status", confirmed ? "Confirmed" : (tx.status === "mempool" ? "Waiting in the mempool" : "unknown")],
        ["Confirmations", isUint(tx.confirmations) ? fmtInt(tx.confirmations) : "unknown"],
        ["Block", confirmed && isHeight(tx.height)
          ? [heightLink(tx.height), isHash(tx.block) ? el("span", { class: "muted small" }, " · ", link(routeBlock(tx.block), shortText(tx.block, 10, 8), "mono")) : null]
          : el("span", { class: "muted", text: "not yet in a block" })],
        ["Time", isTime(tx.time) ? [timeNode(tx.time), el("span", { class: "muted small", text: " · " + utc(tx.time) })] : el("span", { class: "muted", text: "not yet in a block" })],
        tx.coinbase === true ? ["Fee", el("span", { class: "muted", text: "none (block reward)" })] : ["Fee", varv(tx.fee)],
        tx.coinbase === true ? null : ["Fee rate", isNum(tx.feerate) ? fmtRate(tx.feerate) + (Number(tx.feerate) === 1 ? " lamina" : " laminae") + " per weight unit" : "unknown"],
        ["Total output", outTotal === null ? "unknown" : varv(outTotal)],
        ["Size", isUint(tx.size) ? fmtInt(tx.size) + " bytes" : "unknown"],
        ["Weight", isUint(tx.weight) ? fmtInt(tx.weight) + " WU" : "unknown"],
        ["Locktime", isUint(tx.locktime) ? fmtInt(tx.locktime) : "unknown"],
        ["Witness id", isHash(tx.wtxid) ? el("span", { class: "mono break", text: tx.wtxid }) : "unknown"]
      ]));

      var inCol = el("section", { class: "io-col", "aria-labelledby": "inputs-h" },
        el("div", { class: "io-head" }, el("h3", { id: "inputs-h", text: tx.coinbase === true ? "Input" : "Inputs (" + inputs.length + ")" }),
          inTotal !== null && inputs.length ? varv(inTotal) : null));
      var inList = el("ol", { class: "io-list" });
      if (tx.coinbase === true) {
        inList.appendChild(el("li", { class: "io-item coinbase" },
          el("p", { class: "io-title" }, chip("Block reward", "gold")),
          el("p", { class: "muted small", text: "Newly created coins plus the fees of the block's other transactions. A block reward has no inputs." })));
      } else if (!inputs.length) {
        inList.appendChild(el("li", { class: "io-item" }, emptyBox("No inputs.")));
      }
      inputs.forEach(function (inp, i) {
        if (!inp || typeof inp !== "object") { return; }
        var p = isUint(inp.path) && inp.path < 3 ? inp.path : null;
        inList.appendChild(el("li", { class: "io-item" },
          el("div", { class: "io-top" }, el("span", { class: "io-n muted", text: "#" + i }), addrLink(inp.address, true), varv(inp.amount)),
          el("div", { class: "io-meta" },
            p === null ? chip("unknown spend path") : chip("Signed: " + PATHS[p], p === 1 ? "warn" : (p === 2 ? "" : "ok"), PATH_HINTS[p]),
            el("span", { class: "muted small" }, "Spends ",
              link(routeTx(inp.txid), shortText(inp.txid, 8, 6), "mono"),
              isUint(inp.index) ? ":" + inp.index : ""))));
      });
      inCol.appendChild(inList);

      var outCol = el("section", { class: "io-col", "aria-labelledby": "outputs-h" },
        el("div", { class: "io-head" }, el("h3", { id: "outputs-h", text: "Outputs (" + outputs.length + ")" }), outTotal !== null ? varv(outTotal) : null));
      var outList = el("ol", { class: "io-list" });
      outputs.forEach(function (o, i) {
        if (!o || typeof o !== "object") { return; }
        var rec = o.recovery && typeof o.recovery === "object" ? o.recovery : null;
        var spent = o.spent_by && typeof o.spent_by === "object" ? o.spent_by : null;
        outList.appendChild(el("li", { class: "io-item" },
          el("div", { class: "io-top" }, el("span", { class: "io-n muted", text: "#" + (isUint(o.index) ? o.index : i) }), addrLink(o.address, true), varv(o.amount)),
          el("div", { class: "io-meta" },
            chip(word(o.scheme) || "unknown scheme", "scheme", "Signature scheme of the primary key"),
            rec
              ? chip("Recovery: " + (word(rec.scheme) || "unknown") + (isUint(rec.delay) ? " after " + fmtInt(rec.delay) + " blocks" : ""), "", "A recovery key can spend this output after the delay")
              : chip("No recovery key", "dim"),
            spent
              ? el("span", { class: "muted small" }, "Spent by ", link(routeTx(spent.txid), shortText(spent.txid, 8, 6), "mono"),
                isUint(spent.input) ? " (input " + spent.input + ")" : "")
              : el("span", { class: "muted small", text: "Unspent" }))));
      });
      if (!outputs.length) { outList.appendChild(el("li", { class: "io-item" }, emptyBox("No outputs."))); }
      outCol.appendChild(outList);

      var io = el("section", { class: "card-sec io-sec" }, sectionHead("Inputs and outputs"),
        el("div", { class: "io" }, inCol, el("div", { class: "io-arrow", "aria-hidden": "true" }, icon("arrow")), outCol));

      show([head, details, io], fromNav);
    }, function (err) {
      if (!live()) { return; }
      setTitle(err.status === 404 ? "Not found" : "Error");
      show(errorBox(err, function () { render(false); }), fromNav);
    });
  }

  /* ------------------------------------------------------------ address */

  function renderAddress(addr, live, fromNav) {
    setTitle("Address " + shortText(addr, 12, 6));
    show(loadingBox("Loading address…"));
    var enc = encodeURIComponent(addr);
    Promise.allSettled([api("/api/v1/address/" + enc), api("/api/v1/address/" + enc + "/txs?limit=" + HISTORY_PAGE)]).then(function (r) {
      if (!live()) { return; }
      if (r[0].status === "rejected") {
        setTitle(r[0].reason && r[0].reason.status === 404 ? "Not found" : "Error");
        show(errorBox(r[0].reason, function () { render(false); }), fromNav);
        return;
      }
      var a = r[0].value;
      var head = pageHead("Address", "Address", addr, null);

      var fs = a.first_seen && typeof a.first_seen === "object" ? a.first_seen : null;
      var unconf = isAmount(a.unconfirmed) ? a.unconfirmed : null;
      var stats = el("section", { class: "stats addr-stats", "aria-label": "Address summary" },
        stat("Balance", varv(a.balance), "confirmed"),
        stat("Received", varv(a.received), "confirmed"),
        stat("Sent", varv(a.sent), "confirmed"),
        stat("Unconfirmed", unconf === null ? "unknown" : varv(unconf, { signed: true }), "net, in the mempool"),
        stat("Transactions", isUint(a.tx_count) ? fmtInt(a.tx_count) : "unknown", isUint(a.utxo_count) ? fmtInt(a.utxo_count) + " unspent outputs" : null),
        stat("First seen", fs && isHeight(fs.height) ? ["Block ", heightLink(fs.height)] : el("span", { class: "muted", text: "never" }),
          fs ? [timeNode(fs.time), isHash(fs.txid) ? [" · ", link(routeTx(fs.txid), "transaction")] : null] : null));

      var funded = el("section", { class: "card-sec" }, sectionHead("Funded by"));
      var fb = arr(a.funded_by).slice(0, 10);
      if (!fb.length) {
        funded.appendChild(emptyBox("No confirmed payment to this address yet."));
      } else {
        funded.appendChild(el("p", { class: "muted small sec-note", text: "The first confirmed transactions that paid this address, with the address of each one's first input." }));
        var fl = el("ol", { class: "rows" });
        fb.forEach(function (f) {
          if (!f || typeof f !== "object") { return; }
          fl.appendChild(el("li", { class: "row frow" },
            el("div", { class: "frow-from" },
              f.from === "coinbase" ? chip("Block reward", "gold") : el("span", { class: "from-line" }, el("span", { class: "muted small", text: "From " }), addrLink(f.from)),
              el("span", { class: "muted small" }, "Block ", heightLink(f.height), " · ", link(routeTx(f.txid), shortText(f.txid, 8, 6), "mono"))),
            el("div", { class: "frow-r" }, varv(f.amount))));
        });
        funded.appendChild(fl);
      }

      var hist = el("section", { class: "card-sec" }, sectionHead("History", isUint(a.tx_count) ? el("span", { class: "muted small", text: fmtInt(a.tx_count) + " confirmed" }) : null));
      if (r[1].status === "rejected") {
        hist.appendChild(errorBox(r[1].reason, function () { render(false); }, true));
      } else {
        historyList(hist, addr, r[1].value, live);
      }
      show([head, stats, el("div", { class: "detail-cols addr-cols" }, hist, funded)], fromNav);
    });
  }

  function historyList(sec, addr, first, live) {
    var seen = Object.create(null);
    var list = el("ol", { class: "rows" });
    var count = 0;
    var addRows = function (txs) {
      arr(txs).forEach(function (t) {
        if (!t || typeof t !== "object" || !isHash(t.txid) || seen[t.txid]) { return; }
        seen[t.txid] = true;
        count++;
        list.appendChild(el("li", { class: "row hrow" },
          el("div", { class: "hrow-id" },
            txLink(t.txid),
            el("span", { class: "muted small" },
              isHeight(t.height) ? ["Block ", heightLink(t.height), " · ", timeNode(t.time)] : chip("Unconfirmed", "warn"))),
          el("div", { class: "hrow-r" },
            varv(t.delta, { signed: true }),
            isAmount(t.fee) && isAmount(t.delta) && BigInt(t.delta) < 0n ? el("span", { class: "muted small", text: "fee " + fmtVarv(t.fee) }) : null)));
      });
    };
    addRows(first.txs);
    if (!count) { sec.appendChild(emptyBox("No transactions for this address.")); return; }
    sec.appendChild(list);
    var more = el("div", { class: "more" });
    var btn = el("button", { type: "button", class: "btn" }, "Older transactions");
    var cursor = isHeight(first.next) ? first.next : null;
    btn.addEventListener("click", function () {
      if (cursor === null) { return; }
      btn.disabled = true;
      btn.textContent = "Loading…";
      api("/api/v1/address/" + encodeURIComponent(addr) + "/txs?before=" + cursor + "&limit=" + HISTORY_PAGE).then(function (r) {
        if (!live()) { return; }
        addRows(r.txs);
        var nx = isHeight(r.next) && r.next < cursor ? r.next : null;
        cursor = nx;
        btn.disabled = false;
        btn.textContent = "Older transactions";
        if (cursor === null) { more.remove(); }
      }, function (err) {
        if (!live()) { return; }
        btn.disabled = false;
        btn.textContent = "Older transactions";
        more.replaceChildren(errorBox(err, null, true), btn);
      });
    });
    more.appendChild(btn);
    if (cursor !== null) { sec.appendChild(more); }
  }

  /* ------------------------------------------------------------ search */

  function renderSearch(raw, live, fromNav) {
    var q = raw.replace(/\s+/g, "").toLowerCase();
    setTitle("Search");
    if (!q) { window.location.replace("#/"); return; }
    if (RE_HEIGHT.test(q) && Number(q) <= MAX_HEIGHT) { window.location.replace("#/block/" + Number(q)); return; }
    if (RE_ADDR_LIKE.test(q)) { window.location.replace("#/address/" + encodeURIComponent(q)); return; }
    if (!/^[a-z0-9]{1,200}$/.test(q)) {
      show(noMatch(raw), fromNav);
      return;
    }
    show(loadingBox("Searching…"));
    api("/api/v1/search?q=" + encodeURIComponent(q)).then(function (r) {
      if (!live()) { return; }
      var dest = null;
      if (r.type === "block") { dest = routeBlock(r.id); }
      else if (r.type === "tx") { dest = routeTx(r.id); }
      else if (r.type === "address") { dest = routeAddr(r.id); }
      if (dest) { window.location.replace(dest); }
      else { show(noMatch(raw), fromNav); }
    }, function (err) {
      if (!live()) { return; }
      if (err.status === 404) { show(noMatch(raw), fromNav); }
      else { show(errorBox(err, function () { render(false); }), fromNav); }
    });
  }

  function noMatch(q) {
    setTitle("No match");
    return panel({ cls: "is-error", eyebrow: "Search", title: "No match",
      body: [el("p", null, "Nothing was found for ", el("code", { class: "break", text: q.slice(0, 120) }), "."),
        "Search accepts a block height, a 64-character block hash or transaction id, or an address."],
      actions: [el("a", { class: "btn", href: "#/" }, "Explorer home")] });
  }

  /* ------------------------------------------------------------ wiring */

  if (searchForm && searchInput) {
    searchForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var q = searchInput.value.replace(/\s+/g, "").slice(0, 200);
      if (!q) { searchInput.focus(); return; }
      var target = "#/search/" + encodeURIComponent(q);
      if (window.location.hash === target) { render(true); } else { window.location.hash = target; }
      searchInput.blur();
    });
  }

  for (var i = 0; i < netButtons.length; i++) {
    netButtons[i].addEventListener("click", function (ev) {
      var net = ev.currentTarget.getAttribute("data-net");
      if (net !== getNet()) { switchNet(net); }
    });
  }

  window.addEventListener("hashchange", function () { render(true); });
  document.documentElement.classList.add("scan-ready");
  render(false);
})();
