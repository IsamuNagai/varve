// Strata UI. Plain DOM: every value is inserted with textContent or createElement,
// never innerHTML. Amounts are BigInt laminae; JSON carries them as strings.
'use strict';
(function () {
  const SVGNS = 'http://www.w3.org/2000/svg';
  const COIN = 100000000n;
  const MAX_MONEY = 1n << 62n;
  const MATURITY = 288;
  const RE_HEX64 = /^[0-9a-f]{64}$/;
  const RE_TOKEN = /^[0-9a-f]{64}$/;
  const FRAG = '#token=';

  // ------------------------------------------------------------------ state
  const S = {
    token: null,
    status: null,
    screen: 'loading',
    replaceMode: false,
    addrs: null,
    summaries: new Map(),
    info: null,
    fees: null,
    balance: null,
    unconfirmed: 0n,
    activity: null,
    netErr: null,
    refreshing: false,
    lastPing: 0,
    words: null, // shown once after create; dropped after the confirmation step
    lockNote: null,
    send: { to: '', amount: '', max: false, speed: 'normal', allowHigh: false, utxos: null, height: null, spendable: null, err: null, highFeeAsk: false },
    built: null,
    sent: null,
    openTx: null,
  };

  // ------------------------------------------------------------------ DOM helpers
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const k of Object.keys(props)) {
        const v = props[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'value') el.value = v;
        else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const kid of kids.flat(4)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  const ICONS = {
    lock: ['M6 11h12v10H6z', 'M8.5 11V7.5a3.5 3.5 0 0 1 7 0V11'],
    receive: ['M12 4v13', 'M6 11l6 6 6-6', 'M5 20h14'],
    send: ['M12 20V7', 'M6 13l6-6 6 6', 'M5 4h14'],
    home: ['M3.5 11 12 4l8.5 7', 'M6 9.5V20h12V9.5'],
    activity: ['M4 6h16', 'M4 12h16', 'M4 18h10'],
    settings: ['M12 15.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4z', 'M19.4 13.5a7.6 7.6 0 0 0 0-3l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2.6-1.5L14 2.5h-4l-.4 2.5A7.6 7.6 0 0 0 7 6.5l-2.4-1-2 3.4 2 1.6a7.6 7.6 0 0 0 0 3l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 0 0 2.6 1.5l.4 2.5h4l.4-2.5a7.6 7.6 0 0 0 2.6-1.5l2.4 1 2-3.4z'],
    back: ['M15 18l-6-6 6-6'],
    copy: ['M9 9h11v11H9z', 'M5 15H4V4h11v1'],
    check: ['M5 12.5l4.5 4.5L19 7.5'],
    refresh: ['M20 11a8 8 0 1 0-2.3 5.7', 'M20 4v7h-7'],
    arrowIn: ['M17 7 7 17', 'M15 17H7V9'],
    arrowOut: ['M7 17 17 7', 'M9 7h8v8'],
    plus: ['M12 5v14', 'M5 12h14'],
  };
  function icon(name) {
    const svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    for (const d of ICONS[name]) {
      const p = document.createElementNS(SVGNS, 'path');
      p.setAttribute('d', d);
      svg.append(p);
    }
    return svg;
  }

  const root = document.getElementById('app');
  function mount(...nodes) {
    root.replaceChildren(...nodes);
  }

  let toastTimer = null;
  function toast(msg) {
    document.querySelectorAll('.toast').forEach((t) => t.remove());
    const t = h('div', { class: 'toast', role: 'status', text: msg });
    document.body.append(t);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.remove(), 1800);
  }

  async function copy(text, what) {
    try {
      await navigator.clipboard.writeText(text);
      toast((what || 'Text') + ' copied');
    } catch (_) {
      toast('Copy failed; select the text and copy it manually');
    }
  }

  function spinner() {
    return h('span', { class: 'spinner', 'aria-label': 'Loading' });
  }

  // run an async action from a button, showing a spinner and disabling it meanwhile
  async function busy(btn, fn) {
    if (btn.disabled) return;
    const kids = Array.from(btn.childNodes);
    btn.disabled = true;
    btn.replaceChildren(spinner());
    try {
      await fn();
    } finally {
      if (btn.isConnected) {
        btn.disabled = false;
        btn.replaceChildren(...kids);
      }
    }
  }

  // ------------------------------------------------------------------ amounts
  function fmt(b, opts) {
    opts = opts || {};
    const neg = b < 0n;
    const a = neg ? -b : b;
    const whole = (a / COIN).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    let frac = (a % COIN).toString().padStart(8, '0').replace(/0+$/, '');
    const minDec = opts.minDec === undefined ? 2 : opts.minDec;
    while (frac.length < minDec) frac += '0';
    const sign = neg ? '−' : opts.sign && a > 0n ? '+' : '';
    return sign + whole + (frac ? '.' + frac : '');
  }
  function fmtPlain(b) {
    // for input fields: no grouping, no forced decimals
    return fmt(b, { minDec: 0 }).replace(/,/g, '');
  }
  function parseVarv(s) {
    s = String(s).trim().replace(/[,\s]/g, '');
    const m = /^(\d{1,11})(?:\.(\d{1,8}))?$/.exec(s);
    if (!m) return null;
    const v = BigInt(m[1]) * COIN + BigInt(((m[2] || '') + '00000000').slice(0, 8));
    if (v <= 0n || v > MAX_MONEY) return null;
    return v;
  }

  // ------------------------------------------------------------------ validation of API data
  class ApiError extends Error {
    constructor(msg, unreachable) {
      super(msg);
      this.unreachable = !!unreachable;
    }
  }
  class LocalError extends Error {
    constructor(status, msg) {
      super(msg);
      this.status = status;
    }
  }
  function bad() {
    return new ApiError('The node sent data Strata does not understand.');
  }
  function vAmt(v) {
    if (typeof v !== 'string' || !/^(0|[1-9]\d{0,18})$/.test(v)) throw bad();
    const b = BigInt(v);
    if (b > MAX_MONEY) throw bad();
    return b;
  }
  function vSigned(v) {
    if (typeof v !== 'string' || !/^-?(0|[1-9]\d{0,18})$/.test(v)) throw bad();
    const b = BigInt(v);
    if (b > MAX_MONEY || b < -MAX_MONEY) throw bad();
    return b;
  }
  function vUint(v) {
    if (!Number.isSafeInteger(v) || v < 0) throw bad();
    return v;
  }
  function vOptUint(v) {
    return v === null || v === undefined ? null : vUint(v);
  }
  function vHex64(v) {
    if (typeof v !== 'string' || !RE_HEX64.test(v)) throw bad();
    return v;
  }
  function vBool(v) {
    if (typeof v !== 'boolean') throw bad();
    return v;
  }
  function vNum(v, max) {
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > max) throw bad();
    return v;
  }

  // ------------------------------------------------------------------ bech32m (instant feedback; the backend re-checks)
  const B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
    }
    return chk;
  }
  function addressProblem(addr, hrp) {
    if (!addr) return null;
    if (addr.length > 200) return 'This is not a Varve address.';
    const s = addr.toLowerCase();
    if (addr !== s && addr !== addr.toUpperCase()) return 'The address mixes upper and lower case.';
    const pos = s.lastIndexOf('1');
    if (pos < 1) return 'This is not a Varve address.';
    const pre = s.slice(0, pos);
    if (pre !== hrp) {
      if (/^[a-z]*varve$/.test(pre)) return 'This address is for a different Varve network (' + pre + '). This wallet uses ' + hrp + '.';
      return 'This is not a Varve address.';
    }
    const data = [];
    for (const c of s.slice(pos + 1)) {
      const i = B32.indexOf(c);
      if (i < 0) return 'The address contains a character that cannot appear in addresses.';
      data.push(i);
    }
    if (data.length < 8) return 'The address is too short.';
    const exp = [];
    for (const c of hrp) exp.push(c.charCodeAt(0) >> 5);
    exp.push(0);
    for (const c of hrp) exp.push(c.charCodeAt(0) & 31);
    if (polymod(exp.concat(data)) !== 0x2bc830a3) return 'The address checksum is wrong. Check for a typo.';
    return null;
  }

  // ------------------------------------------------------------------ QR code (byte mode, error correction M, versions 1-9)
  const QR = (function () {
    const ECC = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22];
    const BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5];
    function rawModules(v) {
      let r = (16 * v + 128) * v + 64;
      if (v >= 2) {
        const n = Math.floor(v / 7) + 2;
        r -= (25 * n - 10) * n - 55;
        if (v >= 7) r -= 36;
      }
      return r;
    }
    const dataCw = (v) => Math.floor(rawModules(v) / 8) - ECC[v] * BLOCKS[v];
    function mul(x, y) {
      let z = 0;
      for (let i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >>> 7) * 0x11d);
        z ^= ((y >>> i) & 1) * x;
      }
      return z;
    }
    function divisor(deg) {
      const r = new Array(deg).fill(0);
      r[deg - 1] = 1;
      let root = 1;
      for (let i = 0; i < deg; i++) {
        for (let j = 0; j < deg; j++) {
          r[j] = mul(r[j], root);
          if (j + 1 < deg) r[j] ^= r[j + 1];
        }
        root = mul(root, 2);
      }
      return r;
    }
    function remainder(data, div) {
      const r = div.map(() => 0);
      for (const b of data) {
        const f = b ^ r.shift();
        r.push(0);
        div.forEach((c, i) => (r[i] ^= mul(c, f)));
      }
      return r;
    }
    function alignPositions(v) {
      if (v === 1) return [];
      const n = Math.floor(v / 7) + 2;
      const size = v * 4 + 17;
      const step = Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2;
      const res = [6];
      for (let pos = size - 7; res.length < n; pos -= step) res.splice(1, 0, pos);
      return res;
    }
    const bit = (x, i) => ((x >>> i) & 1) !== 0;

    function encode(text) {
      const bytes = new TextEncoder().encode(text);
      let v = 1;
      while (v <= 9 && 12 + bytes.length * 8 > dataCw(v) * 8) v++;
      if (v > 9) return null;
      const bits = [];
      const put = (val, len) => {
        for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
      };
      put(4, 4);
      put(bytes.length, 8);
      for (const b of bytes) put(b, 8);
      const cap = dataCw(v) * 8;
      put(0, Math.min(4, cap - bits.length));
      put(0, (8 - (bits.length % 8)) % 8);
      for (let p = 0xec; bits.length < cap; p ^= 0xec ^ 0x11) put(p, 8);
      const data = [];
      for (let i = 0; i < bits.length; i += 8) {
        let b = 0;
        for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
        data.push(b);
      }
      // split into blocks, add Reed-Solomon codewords, interleave
      const nb = BLOCKS[v];
      const ecl = ECC[v];
      const raw = Math.floor(rawModules(v) / 8);
      const nShort = nb - (raw % nb);
      const shortLen = Math.floor(raw / nb);
      const div = divisor(ecl);
      const blocks = [];
      for (let i = 0, k = 0; i < nb; i++) {
        const dat = data.slice(k, k + shortLen - ecl + (i < nShort ? 0 : 1));
        k += dat.length;
        const ecc = remainder(dat, div);
        if (i < nShort) dat.push(0);
        blocks.push(dat.concat(ecc));
      }
      const all = [];
      for (let i = 0; i < blocks[0].length; i++) {
        blocks.forEach((b, j) => {
          if (i !== shortLen - ecl || j >= nShort) all.push(b[i]);
        });
      }
      // modules
      const size = v * 4 + 17;
      const mod = [];
      const fn = [];
      for (let y = 0; y < size; y++) {
        mod.push(new Array(size).fill(false));
        fn.push(new Array(size).fill(false));
      }
      const setF = (x, y, d) => {
        mod[y][x] = d;
        fn[y][x] = true;
      };
      for (let i = 0; i < size; i++) {
        setF(6, i, i % 2 === 0);
        setF(i, 6, i % 2 === 0);
      }
      const finder = (cx, cy) => {
        for (let dy = -4; dy <= 4; dy++) {
          for (let dx = -4; dx <= 4; dx++) {
            const d = Math.max(Math.abs(dx), Math.abs(dy));
            const x = cx + dx;
            const y = cy + dy;
            if (x >= 0 && x < size && y >= 0 && y < size) setF(x, y, d !== 2 && d !== 4);
          }
        }
      };
      finder(3, 3);
      finder(size - 4, 3);
      finder(3, size - 4);
      const ap = alignPositions(v);
      for (let i = 0; i < ap.length; i++) {
        for (let j = 0; j < ap.length; j++) {
          if ((i === 0 && j === 0) || (i === 0 && j === ap.length - 1) || (i === ap.length - 1 && j === 0)) continue;
          for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) setF(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
      const drawFormat = (mask) => {
        const d = (0 << 3) | mask; // level M = 0b00
        let rem = d;
        for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
        const b = ((d << 10) | rem) ^ 0x5412;
        for (let i = 0; i <= 5; i++) setF(8, i, bit(b, i));
        setF(8, 7, bit(b, 6));
        setF(8, 8, bit(b, 7));
        setF(7, 8, bit(b, 8));
        for (let i = 9; i < 15; i++) setF(14 - i, 8, bit(b, i));
        for (let i = 0; i < 8; i++) setF(size - 1 - i, 8, bit(b, i));
        for (let i = 8; i < 15; i++) setF(8, size - 15 + i, bit(b, i));
        setF(8, size - 8, true);
      };
      drawFormat(0);
      if (v >= 7) {
        let rem = v;
        for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
        const b = (v << 12) | rem;
        for (let i = 0; i < 18; i++) {
          const a = size - 11 + (i % 3);
          const c = Math.floor(i / 3);
          setF(a, c, bit(b, i));
          setF(c, a, bit(b, i));
        }
      }
      let k = 0;
      for (let right = size - 1; right >= 1; right -= 2) {
        if (right === 6) right = 5;
        for (let vert = 0; vert < size; vert++) {
          for (let j = 0; j < 2; j++) {
            const x = right - j;
            const up = ((right + 1) & 2) === 0;
            const y = up ? size - 1 - vert : vert;
            if (!fn[y][x] && k < all.length * 8) {
              mod[y][x] = bit(all[k >>> 3], 7 - (k & 7));
              k++;
            }
          }
        }
      }
      const maskFn = [
        (x, y) => (x + y) % 2 === 0,
        (x, y) => y % 2 === 0,
        (x) => x % 3 === 0,
        (x, y) => (x + y) % 3 === 0,
        (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
        (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
        (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
        (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
      ];
      const applyMask = (m) => {
        for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && maskFn[m](x, y)) mod[y][x] = !mod[y][x];
      };
      const penalty = () => {
        let p = 0;
        const line = (get) => {
          let s = '';
          for (let i = 0; i < size; i++) s += get(i) ? '1' : '0';
          return s;
        };
        for (let i = 0; i < size; i++) {
          for (const s of [line((x) => mod[i][x]), line((y) => mod[y][i])]) {
            for (const run of s.match(/0{5,}|1{5,}/g) || []) p += run.length - 2;
            let at = -1;
            while ((at = s.indexOf('1011101', at + 1)) >= 0) {
              const before = s.slice(Math.max(0, at - 4), at);
              const after = s.slice(at + 7, at + 11);
              if ((at < 4 ? true : before === '0000') || (at + 11 > size ? true : after === '0000')) p += 40;
            }
          }
        }
        let dark = 0;
        for (let y = 0; y < size; y++) {
          for (let x = 0; x < size; x++) {
            if (mod[y][x]) dark++;
            if (x < size - 1 && y < size - 1 && mod[y][x] === mod[y][x + 1] && mod[y][x] === mod[y + 1][x] && mod[y][x] === mod[y + 1][x + 1]) p += 3;
          }
        }
        const total = size * size;
        p += Math.max(0, Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
        return p;
      };
      let best = 0;
      let bestP = Infinity;
      for (let m = 0; m < 8; m++) {
        applyMask(m);
        drawFormat(m);
        const p = penalty();
        if (p < bestP) {
          bestP = p;
          best = m;
        }
        applyMask(m);
      }
      applyMask(best);
      drawFormat(best);
      return mod;
    }

    function svg(text) {
      const m = encode(text);
      if (!m) return null;
      const n = m.length;
      const q = 4;
      const s = document.createElementNS(SVGNS, 'svg');
      s.setAttribute('viewBox', '0 0 ' + (n + 2 * q) + ' ' + (n + 2 * q));
      s.setAttribute('shape-rendering', 'crispEdges');
      s.setAttribute('role', 'img');
      s.setAttribute('aria-label', 'QR code of the address');
      const bg = document.createElementNS(SVGNS, 'rect');
      bg.setAttribute('width', String(n + 2 * q));
      bg.setAttribute('height', String(n + 2 * q));
      bg.setAttribute('fill', '#faf0e2');
      s.append(bg);
      let d = '';
      for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (m[y][x]) d += 'M' + (x + q) + ' ' + (y + q) + 'h1v1h-1z';
      const p = document.createElementNS(SVGNS, 'path');
      p.setAttribute('d', d);
      p.setAttribute('fill', '#0d1117');
      s.append(p);
      return s;
    }
    return { svg: svg, encode: encode };
  })();

  // ------------------------------------------------------------------ backend and node API
  async function local(method, path, body, opts) {
    opts = opts || {};
    const headers = { 'X-Strata-Token': S.token };
    if (opts.background) headers['X-Strata-Background'] = '1';
    const init = { method: method, headers: headers, cache: 'no-store', credentials: 'same-origin', redirect: 'error' };
    if (method === 'POST') {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body || {});
    }
    let r;
    try {
      r = await fetch(path, init);
    } catch (_) {
      throw new LocalError(0, 'Strata is not responding. If you closed it, start it again and open the new address it prints.');
    }
    let j = null;
    try {
      j = await r.json();
    } catch (_) {
      /* not JSON */
    }
    const msg = j && typeof j.error === 'string' ? j.error : 'Request failed (' + r.status + ')';
    if (r.status === 401) {
      S.token = null;
      showNoToken();
      throw new LocalError(401, msg);
    }
    if (r.status === 423 && path !== '/local/reveal') {
      onLocked(null);
      throw new LocalError(423, msg);
    }
    if (!r.ok) throw new LocalError(r.status, msg);
    return j;
  }

  // GET requests are retried with a growing delay when the node rate-limits (429)
  async function api(path, opts) {
    opts = opts || {};
    for (let attempt = 0; ; attempt++) {
      try {
        return await apiOnce(path, opts);
      } catch (e) {
        if (e.status !== 429 || opts.method === 'POST' || attempt >= 4) throw e;
        await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
      }
    }
  }

  async function apiOnce(path, opts) {
    const base = S.status.api_endpoint;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), opts.timeout || 15000);
    let r;
    try {
      const init = { method: opts.method || 'GET', signal: ctl.signal, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', mode: 'cors' };
      if (opts.body !== undefined) {
        init.body = opts.body;
        init.headers = { 'Content-Type': 'text/plain' };
      }
      r = await fetch(base + path, init);
    } catch (_) {
      throw new ApiError("Can't reach the Varve node at " + base + '. Check that the node is running with its API enabled, or change the node in Settings.', true);
    } finally {
      clearTimeout(timer);
    }
    let j = null;
    try {
      j = await r.json();
    } catch (_) {
      /* not JSON */
    }
    if (!r.ok) {
      let m = j && typeof j.error === 'string' ? j.error.slice(0, 300) : 'HTTP ' + r.status;
      if (r.status === 429) m = 'The node is limiting requests. Wait a moment and try again.';
      if (r.status === 503) m = 'The node is still syncing. Try again when it has caught up.';
      const e = new ApiError(m);
      e.status = r.status;
      throw e;
    }
    if (j === null || typeof j !== 'object' || Array.isArray(j)) throw bad();
    return j;
  }

  async function pool(items, n, fn) {
    let i = 0;
    const workers = [];
    for (let w = 0; w < Math.min(n, items.length); w++) {
      workers.push(
        (async () => {
          while (i < items.length) {
            const it = items[i++];
            await fn(it);
          }
        })()
      );
    }
    await Promise.all(workers);
  }

  function vAddrList(a) {
    if (!a || !Array.isArray(a.receive) || !Array.isArray(a.change) || !a.current) throw new Error('bad address list');
    const one = (x) => {
      if (!x || !Number.isSafeInteger(x.index) || typeof x.address !== 'string' || !x.address.startsWith(S.status.hrp + '1')) throw new Error('bad address list');
      return { index: x.index, address: x.address };
    };
    return {
      receive: a.receive.map(one),
      change: a.change.map(one),
      current: one(a.current),
      receive_used: a.receive_used === null ? null : a.receive_used,
      change_used: a.change_used === null ? null : a.change_used,
    };
  }

  function allAddresses() {
    if (!S.addrs) return [];
    return S.addrs.receive.map((a) => ({ chain: 'receive', index: a.index, address: a.address })).concat(S.addrs.change.map((a) => ({ chain: 'change', index: a.index, address: a.address })));
  }

  async function loadInfo() {
    const j = await api('/api/v1/info');
    const info = { network: String(j.network || ''), height: vUint(j.height), genesis: vHex64(j.genesis), hrp: typeof j.hrp === 'string' ? j.hrp : '', syncing: j.syncing === true };
    if (info.genesis !== S.status.genesis || info.hrp !== S.status.hrp) {
      throw new ApiError('The node at ' + S.status.api_endpoint + ' is on a different network (' + (info.network.slice(0, 20) || 'unknown') + '). This wallet uses ' + S.status.network + '.');
    }
    S.info = info;
    return info;
  }

  // full refresh: address window (with gap scanning), balances, activity
  function refresh(background) {
    if (S.refreshPromise) return S.refreshPromise;
    if (!S.status || !S.status.unlocked) return Promise.resolve();
    S.refreshPromise = doRefresh(background).finally(() => {
      S.refreshPromise = null;
    });
    return S.refreshPromise;
  }

  async function doRefresh(background) {
    S.refreshing = true;
    if (!background) rerender();
    try {
      S.addrs = vAddrList(await local('GET', '/local/addresses', null, { background: background }));
      await loadInfo();
      const summaries = new Map();
      for (let round = 0; round < 100; round++) {
        const todo = allAddresses().filter((a) => !summaries.has(a.address));
        await pool(todo, 4, async (a) => {
          const j = await api('/api/v1/address/' + encodeURIComponent(a.address));
          summaries.set(a.address, {
            balance: vAmt(j.balance),
            unconfirmed: vSigned(j.unconfirmed),
            txCount: vUint(j.tx_count),
            utxoCount: vUint(j.utxo_count),
          });
        });
        let maxR = -1;
        let maxC = -1;
        for (const a of allAddresses()) {
          const s = summaries.get(a.address);
          if (s && (s.txCount > 0 || s.unconfirmed !== 0n)) {
            if (a.chain === 'receive') maxR = Math.max(maxR, a.index);
            else maxC = Math.max(maxC, a.index);
          }
        }
        const needR = maxR >= 0 && (S.addrs.receive_used === null || maxR > S.addrs.receive_used);
        const needC = maxC >= 0 && (S.addrs.change_used === null || maxC > S.addrs.change_used);
        if (!needR && !needC) break;
        S.addrs = vAddrList(await local('POST', '/local/mark_used', { receive: needR ? [maxR] : [], change: needC ? [maxC] : [] }, { background: background }));
      }
      S.summaries = summaries;
      let bal = 0n;
      let unc = 0n;
      for (const s of summaries.values()) {
        bal += s.balance;
        unc += s.unconfirmed;
      }
      // activity: merge every address's history by txid
      const merged = new Map();
      const withHistory = allAddresses().filter((a) => {
        const s = summaries.get(a.address);
        return s && (s.txCount > 0 || s.unconfirmed !== 0n);
      });
      await pool(withHistory, 4, async (a) => {
        const j = await api('/api/v1/address/' + encodeURIComponent(a.address) + '/txs?limit=50');
        if (!Array.isArray(j.txs)) throw bad();
        for (const t of j.txs) {
          const txid = vHex64(t.txid);
          const e = merged.get(txid) || { txid: txid, height: null, time: null, delta: 0n, fee: null };
          e.delta += vSigned(t.delta);
          const hgt = vOptUint(t.height);
          if (hgt !== null) e.height = hgt;
          const tm = vOptUint(t.time);
          if (tm !== null) e.time = tm;
          if (t.fee !== null && t.fee !== undefined) e.fee = vAmt(t.fee);
          merged.set(txid, e);
        }
      });
      S.activity = Array.from(merged.values()).sort((a, b) => {
        if (a.height === null && b.height !== null) return -1;
        if (b.height === null && a.height !== null) return 1;
        return (b.height || 0) - (a.height || 0) || (b.time || 0) - (a.time || 0) || (a.txid < b.txid ? -1 : 1);
      });
      S.balance = bal;
      S.unconfirmed = unc;
      S.netErr = null;
    } catch (e) {
      if (!(e instanceof LocalError && (e.status === 401 || e.status === 423))) S.netErr = e.message || String(e);
    } finally {
      S.refreshing = false;
      if (['home', 'activity'].includes(S.screen)) rerender();
    }
  }

  // ------------------------------------------------------------------ layout
  function topbar() {
    const net = S.status ? S.status.network : '';
    const kids = [
      h('div', { class: 'brand' }, h('img', { src: '/varve-mark.png', alt: '', width: 26, height: 26 }), h('span', { class: 'brand-name', text: 'Strata' })),
      net ? h('span', { class: 'pill', title: 'Network' }, h('span', { class: 'dot' }), net) : null,
    ];
    if (S.status && S.status.unlocked) {
      kids.push(h('button', { class: 'icon-btn', title: 'Lock now', 'aria-label': 'Lock now', onclick: lockNow }, icon('lock')));
    }
    return h('header', { class: 'topbar' }, kids);
  }

  function nav(active) {
    const item = (id, label, ic) => h('button', { 'aria-current': active === id ? 'page' : null, onclick: () => go(id) }, icon(ic), label);
    return h('nav', { class: 'nav', 'aria-label': 'Main' }, item('home', 'Home', 'home'), item('activity', 'Activity', 'activity'), item('settings', 'Settings', 'settings'));
  }

  function frame(screen, opts) {
    opts = opts || {};
    const parts = [topbar(), h('div', { class: 'content' }, screen)];
    if (opts.nav) parts.push(nav(opts.nav));
    mount(...parts);
  }

  function headRow(title, backTo) {
    return h('div', { class: 'head-row' }, backTo ? h('button', { class: 'icon-btn', 'aria-label': 'Back', title: 'Back', onclick: () => go(backTo) }, icon('back')) : null, h('h2', { text: title }));
  }

  function alertBox(msg, kind) {
    return msg ? h('div', { class: 'alert' + (kind ? ' ' + kind : ''), role: 'alert', text: msg }) : null;
  }

  function errorSlot() {
    const el = h('div', { class: 'hidden', role: 'alert' });
    el.set = (msg) => {
      el.className = msg ? 'alert' : 'hidden';
      el.textContent = msg || '';
    };
    return el;
  }

  function field(label, input, hint) {
    const id = 'f' + Math.random().toString(36).slice(2, 9);
    input.id = id;
    return h('div', { class: 'field' }, h('label', { for: id, text: label }), input, hint || null);
  }

  function passInput(placeholder, autocomplete) {
    return h('input', { class: 'input', type: 'password', placeholder: placeholder, autocomplete: autocomplete, spellcheck: 'false', autocapitalize: 'off', maxlength: 1024 });
  }

  function strength(p) {
    let s = 0;
    if (p.length >= 10) s++;
    if (p.length >= 14) s++;
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
    if (classes >= 3 || p.includes(' ')) s++;
    if (p.length >= 20) s++;
    return p.length === 0 ? 0 : Math.max(1, s);
  }

  // ------------------------------------------------------------------ navigation
  function go(screen) {
    S.screen = screen;
    if (screen !== 'settings') S.revealed = null;
    rerender();
    const c = root.querySelector('.content');
    if (c) c.scrollTop = 0;
    if ((screen === 'home' || screen === 'activity') && !S.refreshing && S.balance === null) refresh(false);
  }

  function rerender() {
    const f = SCREENS[S.screen] || SCREENS.loading;
    // keep focus and typed values: only re-render screens that hold no user input
    f();
  }

  function onLocked(note) {
    const wasUnlocked = S.status && S.status.unlocked;
    if (S.status) S.status.unlocked = false;
    S.addrs = null;
    S.summaries = new Map();
    S.balance = null;
    S.activity = null;
    S.built = null;
    S.words = null;
    S.revealed = null;
    S.send = Object.assign(S.send, { utxos: null, spendable: null, err: null });
    if (note !== null) S.lockNote = note;
    else if (wasUnlocked && S.lockNote === null) S.lockNote = 'Strata locked the wallet after ' + (S.status ? S.status.autolock_minutes : 10) + ' minutes without activity.';
    S.screen = 'unlock';
    rerender();
  }

  async function lockNow() {
    try {
      await local('POST', '/local/lock', {});
    } catch (_) {
      /* the server locks on its own timer as well */
    }
    onLocked('The wallet is locked.');
  }

  function showNoToken() {
    S.screen = 'noToken';
    rerender();
  }

  // ------------------------------------------------------------------ screens
  const SCREENS = {};

  SCREENS.loading = () => mount(h('div', { class: 'content' }, h('div', { class: 'screen center' }, h('img', { class: 'mark-xl', src: '/varve-mark.png', alt: '' }), spinner())));

  SCREENS.noToken = () =>
    mount(
      h(
        'div',
        { class: 'content' },
        h(
          'div',
          { class: 'screen center' },
          h('img', { class: 'mark-xl', src: '/varve-mark.png', alt: '' }),
          h('h2', { text: 'Open Strata from its start address' }),
          h('p', { class: 'lead', text: 'For your safety this page only works when opened from the address Strata prints when it starts (it contains a one-time session key). Close this tab and open that address again, or restart Strata.' })
        )
      )
    );

  SCREENS.welcome = () => {
    const replacing = S.status.has_wallet;
    frame(
      h(
        'div',
        { class: 'screen fill' },
        h('div', { class: 'hero' }, h('img', { class: 'mark-xl', src: '/varve-mark.png', alt: '' }), h('div', { class: 'eyebrow', text: 'Varve wallet' }), h('h1', { text: 'Strata' }), h('p', { class: 'lead', text: 'Your keys are created and kept on this computer. Strata signs payments here and reads public chain data from a Varve node.' })),
        h('div', { class: 'strata-lines' }),
        replacing ? h('div', { class: 'notice danger' }, h('div', { class: 'grow' }, h('strong', { text: 'A wallet already exists on this computer.' }), h('span', { text: 'Creating or importing a wallet replaces it. Make sure you have its recovery phrase first. The old file is kept as a backup copy in the data folder.' }))) : null,
        h('div', { class: 'stack' }, h('button', { class: 'btn primary block', onclick: () => go('create') }, icon('plus'), 'Create a new wallet'), h('button', { class: 'btn block', onclick: () => go('import') }, 'Import a recovery phrase')),
        replacing ? h('button', { class: 'btn ghost block', onclick: () => { S.replaceMode = false; go('unlock'); } }, 'Back to unlock') : null
      )
    );
  };

  function replaceBox() {
    if (!S.status.has_wallet) return { el: null, values: () => ({}) };
    const chk = h('input', { type: 'checkbox' });
    const word = h('input', { class: 'input mono', placeholder: 'Type REPLACE', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'characters' });
    const el = h(
      'div',
      { class: 'notice danger' },
      h('div', { class: 'grow' }, h('strong', { text: 'Replace the existing wallet' }), h('label', { class: 'check' }, chk, h('span', { text: 'I have the recovery phrase of the current wallet, or it holds no coins. Replace it.' })), word)
    );
    return { el: el, values: () => ({ replace: chk.checked, confirm: word.value.trim() }) };
  }

  function advancedSeedPass(intro) {
    const sp = passInput('Leave empty unless you need one', 'off');
    const el = h(
      'details',
      { class: 'advanced' },
      h('summary', { text: 'Advanced: seed passphrase' }),
      h('p', { class: 'hint', text: intro }),
      field('Seed passphrase (optional)', sp)
    );
    return { el: el, input: sp };
  }

  SCREENS.create = () => {
    const p1 = passInput('At least 10 characters', 'new-password');
    const p2 = passInput('Type it again', 'new-password');
    const meter = h('i');
    const mlabel = h('span', { class: 'hint', text: ' ' });
    p1.addEventListener('input', () => {
      const s = strength(p1.value);
      meter.className = s ? 'w' + s : '';
      mlabel.textContent = ['', 'Weak', 'Fair', 'Good', 'Strong'][s] || ' ';
    });
    const adv = advancedSeedPass('A seed passphrase is mixed into your keys and is not part of the recovery phrase. Without it, the 24 words restore a different, empty wallet. Only use it if you know you need it, and write it down separately.');
    const rep = replaceBox();
    const err = errorSlot();
    const btn = h('button', { class: 'btn primary block', type: 'submit' }, 'Create wallet');
    const form = h(
      'form',
      { class: 'screen', novalidate: true },
      headRow('Create a passphrase', 'welcome'),
      h('p', { class: 'lead', text: 'The passphrase encrypts the wallet file on this computer and unlocks Strata. It cannot restore your coins on another device; the recovery phrase does that.' }),
      field('Passphrase', p1, h('div', { class: 'stack' }, h('div', { class: 'meter' }, meter), mlabel)),
      field('Confirm passphrase', p2),
      adv.el,
      rep.el,
      err,
      btn
    );
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      err.set('');
      if (p1.value !== p2.value) return err.set('The two passphrases do not match.');
      if (p1.value.length < 10) return err.set('Use at least 10 characters.');
      busy(btn, async () => {
        try {
          const body = Object.assign({ file_pass: p1.value, seed_pass: adv.input.value || null }, rep.values());
          const r = await local('POST', '/local/create', body);
          if (!Array.isArray(r.mnemonic) || r.mnemonic.length !== 24 || !r.mnemonic.every((w) => typeof w === 'string' && /^[a-z]{3,8}$/.test(w))) throw new Error('Unexpected response from Strata.');
          p1.value = p2.value = adv.input.value = '';
          S.status = r.status;
          S.replaceMode = false;
          S.words = r.mnemonic;
          go('words');
        } catch (e) {
          err.set(e.message);
        }
      });
    });
    frame(form);
    p1.focus();
  };

  function wordGrid(words) {
    return h(
      'ol',
      { class: 'words', 'aria-label': 'Recovery phrase' },
      words.map((w, i) => h('li', { class: 'word' }, h('i', { text: String(i + 1) }), h('span', { text: w })))
    );
  }

  SCREENS.words = () => {
    if (!S.words) return go('home');
    const chk = h('input', { type: 'checkbox' });
    const btn = h('button', { class: 'btn primary block', disabled: true, onclick: () => go('confirm') }, 'Continue');
    chk.addEventListener('change', () => (btn.disabled = !chk.checked));
    frame(
      h(
        'div',
        { class: 'screen' },
        headRow('Your recovery phrase'),
        h(
          'div',
          { class: 'notice danger' },
          h(
            'div',
            { class: 'grow' },
            h('strong', { text: 'Write these 24 words on paper, in order.' }),
            h('span', { text: 'They are the only way to restore this wallet if this computer is lost. Anyone who sees them can take your coins. Do not keep them in a screenshot, email, chat or cloud note.' })
          )
        ),
        wordGrid(S.words),
        h('label', { class: 'check' }, chk, h('span', { text: 'I have written down all 24 words in the right order.' })),
        btn
      )
    );
  };

  function randomPositions(n, k) {
    const out = new Set();
    const buf = new Uint32Array(1);
    while (out.size < k) {
      crypto.getRandomValues(buf);
      const lim = Math.floor(0x100000000 / n) * n;
      if (buf[0] < lim) out.add(buf[0] % n);
    }
    return Array.from(out).sort((a, b) => a - b);
  }

  SCREENS.confirm = () => {
    if (!S.words) return go('home');
    if (!S.confirmPos) S.confirmPos = randomPositions(24, 3);
    const inputs = S.confirmPos.map(() => h('input', { class: 'input mono', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', maxlength: 12 }));
    const err = errorSlot();
    const form = h(
      'form',
      { class: 'screen', novalidate: true },
      headRow('Confirm your phrase', 'words'),
      h('p', { class: 'lead', text: 'Enter the requested words from your written copy to check it is complete.' }),
      h('div', { class: 'confirm-grid' }, S.confirmPos.map((p, i) => field('Word #' + (p + 1), inputs[i]))),
      err,
      h('button', { class: 'btn primary block', type: 'submit' }, 'Confirm'),
      h('button', { class: 'btn ghost block', type: 'button', onclick: () => go('words') }, 'Show the words again')
    );
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const ok = S.confirmPos.every((p, i) => inputs[i].value.trim().toLowerCase() === S.words[p]);
      inputs.forEach((inp, i) => inp.classList.toggle('invalid', inp.value.trim().toLowerCase() !== S.words[S.confirmPos[i]]));
      if (!ok) return err.set('That does not match. Check your written copy; the words must be in order.');
      S.words = null;
      S.confirmPos = null;
      toast('Recovery phrase confirmed');
      S.balance = null;
      go('home');
    });
    frame(form);
    inputs[0].focus();
  };

  SCREENS.import = () => {
    const ta = h('textarea', { class: 'textarea', rows: 4, placeholder: 'word1 word2 word3 …', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', maxlength: 1000 });
    const count = h('span', { class: 'hint', text: '0 of 24 words' });
    ta.addEventListener('input', () => {
      const n = ta.value.trim() ? ta.value.trim().split(/\s+/).length : 0;
      count.textContent = n + ' of 24 words';
    });
    const p1 = passInput('At least 10 characters', 'new-password');
    const p2 = passInput('Type it again', 'new-password');
    const adv = advancedSeedPass('If the wallet was created with a seed passphrase, enter it here. A wrong or missing seed passphrase restores a different, empty wallet.');
    const rep = replaceBox();
    const err = errorSlot();
    const btn = h('button', { class: 'btn primary block', type: 'submit' }, 'Import wallet');
    const form = h(
      'form',
      { class: 'screen', novalidate: true },
      headRow('Import a recovery phrase', 'welcome'),
      h('p', { class: 'lead', text: 'Enter the 24 words of a Varve wallet, separated by spaces.' }),
      field('Recovery phrase', ta, count),
      field('New passphrase for this computer', p1),
      field('Confirm passphrase', p2),
      adv.el,
      rep.el,
      err,
      btn
    );
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      err.set('');
      const words = ta.value.trim().toLowerCase().split(/\s+/);
      if (words.length !== 24) return err.set('A Varve recovery phrase has exactly 24 words.');
      if (p1.value !== p2.value) return err.set('The two passphrases do not match.');
      busy(btn, async () => {
        try {
          const body = Object.assign({ mnemonic: words.join(' '), file_pass: p1.value, seed_pass: adv.input.value || null }, rep.values());
          const r = await local('POST', '/local/import', body);
          ta.value = p1.value = p2.value = adv.input.value = '';
          S.status = r.status;
          S.replaceMode = false;
          S.balance = null;
          toast('Wallet imported');
          go('home');
        } catch (e) {
          err.set(e.message);
        }
      });
    });
    frame(form);
    ta.focus();
  };

  SCREENS.unlock = () => {
    const p = passInput('Passphrase', 'current-password');
    const err = errorSlot();
    const btn = h('button', { class: 'btn primary block', type: 'submit' }, 'Unlock');
    const note = S.lockNote;
    S.lockNote = null;
    const form = h(
      'form',
      { class: 'screen', novalidate: true },
      h('div', { class: 'hero' }, h('img', { class: 'mark-xl', src: '/varve-mark.png', alt: '' }), h('h1', { text: 'Welcome back' }), h('p', { class: 'lead', text: 'Enter your passphrase to unlock this wallet.' })),
      note ? alertBox(note, 'info') : null,
      field('Passphrase', p),
      err,
      btn,
      h('button', { class: 'btn ghost block', type: 'button', onclick: () => { S.replaceMode = true; go('welcome'); } }, 'Use a different wallet')
    );
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      err.set('');
      if (!p.value) return err.set('Enter your passphrase.');
      busy(btn, async () => {
        try {
          S.status = await local('POST', '/local/unlock', { file_pass: p.value });
          p.value = '';
          S.balance = null;
          go('home');
        } catch (e) {
          err.set(e.message === 'wrong passphrase' ? 'Wrong passphrase.' : e.message);
          p.select();
        }
      });
    });
    frame(form);
    p.focus();
  };

  function activityRow(t, expandable) {
    const incoming = t.delta > 0n;
    const title = t.delta === 0n ? 'Moved within wallet' : incoming ? 'Received' : 'Sent';
    const when = t.height === null ? 'Pending' : (t.time ? new Date(t.time * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Block ' + t.height);
    const row = h(
      'button',
      { class: 'row', 'aria-expanded': expandable ? String(S.openTx === t.txid) : null, onclick: () => { if (expandable) { S.openTx = S.openTx === t.txid ? null : t.txid; rerender(); } else go('activity'); } },
      h('span', { class: 'act-icon' + (incoming ? ' in' : '') }, icon(incoming ? 'arrowIn' : 'arrowOut')),
      h('span', { class: 'mid' }, h('span', { class: 'title' }, title, t.height === null ? ' ' : null, t.height === null ? h('span', { class: 'badge', text: 'Pending' }) : null), h('span', { class: 'sub', text: t.height === null ? t.txid.slice(0, 16) + '…' : when })),
      h('span', { class: 'amt' + (incoming ? ' in' : ''), text: fmt(t.delta, { sign: true, minDec: 2 }) })
    );
    if (!expandable || S.openTx !== t.txid) return row;
    const conf = t.height !== null && S.info ? S.info.height - t.height + 1 : 0;
    return [
      row,
      h(
        'div',
        { class: 'row-detail' },
        h('div', null, 'Transaction ID'),
        h('div', { class: 'mono', text: t.txid }),
        h('div', { text: t.height === null ? 'Waiting in the mempool for a block.' : 'Block ' + t.height + ' · ' + conf + ' confirmation' + (conf === 1 ? '' : 's') + (t.time ? ' · ' + when : '') }),
        t.fee !== null && t.delta < 0n ? h('div', { text: 'Network fee: ' + fmt(t.fee, { minDec: 0 }) + ' VARV' }) : null,
        h('div', null, h('button', { class: 'btn small', onclick: () => copy(t.txid, 'Transaction ID') }, icon('copy'), 'Copy ID'))
      ),
    ];
  }

  function netError() {
    if (!S.netErr) return null;
    return h(
      'div',
      { class: 'alert', role: 'alert' },
      h('div', { text: S.netErr }),
      h('div', { class: 'btn-row' }, h('button', { class: 'btn small', onclick: () => refresh(false) }, 'Try again'), h('button', { class: 'btn small', onclick: () => go('settings') }, 'Change node'))
    );
  }

  function nodeLine() {
    const ok = !S.netErr && S.info;
    return h(
      'div',
      { class: 'node-line' },
      h('span', { class: 'dot' + (ok ? '' : ' off') }),
      ok ? 'Node at block ' + S.info.height.toLocaleString() : S.refreshing ? 'Connecting to node…' : 'Node unavailable',
      h('button', { class: 'icon-btn', title: 'Refresh', 'aria-label': 'Refresh', onclick: () => refresh(false) }, icon('refresh'))
    );
  }

  SCREENS.home = () => {
    const loading = S.balance === null;
    let sub;
    if (loading) sub = S.refreshing ? 'Loading balance…' : '';
    else if (S.unconfirmed !== 0n) sub = fmt(S.unconfirmed, { sign: true }) + ' VARV pending confirmation';
    else sub = 'All transactions confirmed';
    const recent = S.activity ? S.activity.slice(0, 5) : null;
    frame(
      h(
        'div',
        { class: 'screen' },
        h(
          'section',
          { class: 'balance-card', 'aria-label': 'Balance' },
          h('div', { class: 'balance-label', text: 'Total balance' }),
          h('div', { class: 'balance' }, h('span', { class: 'amt', text: loading ? '—' : fmt(S.balance) }), h('span', { class: 'cur', text: 'VARV' })),
          h('div', { class: 'balance-sub', text: sub })
        ),
        h(
          'div',
          { class: 'actions' },
          h('button', { class: 'btn action', onclick: () => go('receive') }, h('span', { class: 'big-icon' }, icon('receive')), 'Receive'),
          h('button', { class: 'btn action primary', onclick: () => go('send') }, h('span', { class: 'big-icon' }, icon('send')), 'Send')
        ),
        netError(),
        h('div', { class: 'section-head' }, h('h3', { text: 'Recent activity' }), recent && recent.length ? h('button', { class: 'link', onclick: () => go('activity') }, 'See all') : null),
        recent === null
          ? h('div', { class: 'list' }, h('div', { class: 'empty' }, S.refreshing ? spinner() : 'Activity appears here once the node is reachable.'))
          : recent.length
            ? h('div', { class: 'list' }, recent.map((t) => activityRow(t, false)))
            : h('div', { class: 'list' }, h('div', { class: 'empty', text: 'No transactions yet. Use Receive to get an address.' })),
        nodeLine()
      ),
      { nav: 'home' }
    );
  };

  SCREENS.activity = () => {
    const list = S.activity;
    frame(
      h(
        'div',
        { class: 'screen' },
        h('div', { class: 'head-row' }, h('h2', { text: 'Activity' }), h('button', { class: 'icon-btn', title: 'Refresh', 'aria-label': 'Refresh', onclick: () => refresh(false) }, S.refreshing ? spinner() : icon('refresh'))),
        netError(),
        list === null
          ? h('div', { class: 'list' }, h('div', { class: 'empty' }, S.refreshing ? spinner() : 'Activity appears here once the node is reachable.'))
          : list.length
            ? h('div', { class: 'list' }, list.map((t) => activityRow(t, true)))
            : h('div', { class: 'list' }, h('div', { class: 'empty', text: 'No transactions yet.' })),
        list && list.length >= 50 ? h('p', { class: 'hint', text: 'Showing the most recent transactions of each address.' }) : null
      ),
      { nav: 'activity' }
    );
  };

  SCREENS.receive = () => {
    const holder = h('div', { class: 'stack' }, h('div', { class: 'screen center' }, spinner()));
    const screen = h(
      'div',
      { class: 'screen' },
      headRow('Receive VARV', 'home'),
      holder
    );
    frame(screen, { nav: 'home' });
    const show = (addr) => {
      const q = QR.svg(addr);
      const box = h('div', { class: 'addr-box', 'aria-label': 'Receive address' }, h('span', { class: 'hl', text: addr.slice(0, 8) }), addr.slice(8, -6), h('span', { class: 'hl', text: addr.slice(-6) }));
      holder.replaceChildren(
        q ? h('div', { class: 'qr-card' }, q) : null,
        box,
        h('div', { class: 'btn-row' }, h('button', { class: 'btn primary', onclick: () => copy(addr, 'Address') }, icon('copy'), 'Copy address'), h('button', { class: 'btn', onclick: (ev) => busy(ev.currentTarget, newAddress) }, icon('plus'), 'New address')),
        h('div', { class: 'notice' }, h('div', { class: 'grow' }, h('strong', { text: 'Use a fresh address for each payment.' }), h('span', { text: 'Varve addresses are meant to be used once: spending from an address reveals its public key. Only send ' + S.status.network + ' VARV to this address.' })))
      );
    };
    const newAddress = async () => {
      try {
        const r = await local('POST', '/local/new_address', {});
        if (typeof r.address !== 'string' || !r.address.startsWith(S.status.hrp + '1')) throw new Error('Unexpected response from Strata.');
        if (S.addrs) S.addrs.current = { index: r.index, address: r.address };
        show(r.address);
        toast('New address ready');
      } catch (e) {
        holder.prepend(alertBox(e.message));
      }
    };
    (async () => {
      try {
        if (!S.addrs) S.addrs = vAddrList(await local('GET', '/local/addresses'));
        if (S.screen === 'receive') show(S.addrs.current.address);
      } catch (e) {
        holder.replaceChildren(alertBox(e.message));
      }
    })();
  };

  async function loadUtxos() {
    if (!S.info) await loadInfo();
    const addrs = allAddresses().filter((a) => {
      const s = S.summaries.get(a.address);
      return s && (s.utxoCount > 0 || s.unconfirmed !== 0n || s.balance > 0n);
    });
    const utxos = [];
    let height = null;
    await pool(addrs, 4, async (a) => {
      const j = await api('/api/v1/address/' + encodeURIComponent(a.address) + '/utxos');
      const hgt = vUint(j.height);
      height = height === null ? hgt : Math.min(height, hgt);
      if (!Array.isArray(j.utxos)) throw bad();
      for (const u of j.utxos) {
        if (typeof u.output !== 'string' || !/^[0-9a-f]{88,164}$/.test(u.output)) throw bad();
        utxos.push({
          txid: vHex64(u.txid),
          index: vUint(u.index),
          amount: vAmt(u.amount).toString(),
          height: vOptUint(u.height),
          coinbase: vBool(u.coinbase),
          mature: vBool(u.mature),
          spent_in_mempool: vBool(u.spent_in_mempool),
          output: u.output,
        });
      }
    });
    if (height === null) height = S.info.height;
    let spendable = 0n;
    for (const u of utxos) {
      const matureNow = !u.coinbase || (u.height !== null && height + 1 >= u.height + MATURITY);
      if (u.mature && !u.spent_in_mempool && matureNow) spendable += BigInt(u.amount);
    }
    S.send.utxos = utxos.slice(0, 3000);
    S.send.height = height;
    S.send.spendable = spendable;
  }

  async function loadFees() {
    const j = await api('/api/v1/fees');
    const f = (v) => Math.max(1, Math.ceil(vNum(v, 1000000)));
    S.fees = { slow: f(j.slow), normal: f(j.normal), fast: f(j.fast) };
  }

  SCREENS.send = () => {
    const d = S.send;
    const to = h('input', { class: 'input mono', placeholder: S.status.hrp + '1…', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', value: d.to, maxlength: 200 });
    const toHint = h('span', { class: 'hint err' });
    const amount = h('input', { class: 'input', inputmode: 'decimal', placeholder: '0.00', autocomplete: 'off', value: d.max ? 'Max' : d.amount, readonly: d.max ? true : null });
    const maxBtn = h('button', { class: 'btn small', type: 'button', 'aria-pressed': String(d.max) }, d.max ? 'Clear' : 'Max');
    const avail = h('span', { class: 'hint' }, d.spendable === null ? 'Checking spendable balance…' : 'Spendable: ' + fmt(d.spendable) + ' VARV' + (d.max ? ' (the fee is taken from this amount)' : ''));
    const err = errorSlot();
    const highWrap = h('label', { class: 'check' + (d.highFeeAsk ? '' : ' hidden') }, h('input', { type: 'checkbox', onchange: (ev) => (d.allowHigh = ev.target.checked), checked: d.allowHigh ? true : null }), h('span', { text: 'I understand the fee is high for this amount. Build it anyway.' }));
    const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Fee' });
    const drawSeg = () => {
      seg.replaceChildren(
        ...['slow', 'normal', 'fast'].map((k) =>
          h(
            'button',
            { type: 'button', 'aria-pressed': String(d.speed === k), onclick: () => { d.speed = k; drawSeg(); } },
            h('span', { class: 't', text: k[0].toUpperCase() + k.slice(1) }),
            h('span', { class: 's', text: S.fees ? S.fees[k] + ' lam/wu' : '…' })
          )
        )
      );
    };
    drawSeg();
    const checkTo = () => {
      const p = addressProblem(to.value.trim(), S.status.hrp);
      toHint.textContent = p || '';
      to.classList.toggle('invalid', !!p);
      return !p;
    };
    to.addEventListener('input', () => {
      d.to = to.value;
      if (toHint.textContent) checkTo();
    });
    to.addEventListener('blur', checkTo);
    amount.addEventListener('input', () => (d.amount = amount.value));
    maxBtn.addEventListener('click', () => {
      d.max = !d.max;
      if (!d.max) d.amount = '';
      rerender();
    });
    const btn = h('button', { class: 'btn primary block', type: 'submit' }, 'Review');
    const form = h(
      'form',
      { class: 'screen', novalidate: true },
      headRow('Send VARV', 'home'),
      field('Recipient address', to, toHint),
      field('Amount', h('div', { class: 'input-wrap' }, amount, h('span', { class: 'suffix' }, h('span', { class: 'unit', text: 'VARV' }), maxBtn)), avail),
      h('div', { class: 'field' }, h('span', { class: 'label', text: 'Network fee' }), seg, h('span', { class: 'hint', text: 'A higher fee rate confirms sooner when blocks are full. The exact fee is shown before you send.' })),
      err,
      highWrap,
      btn
    );
    if (d.err) err.set(d.err);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      d.err = null;
      err.set('');
      if (!to.value.trim()) return err.set('Enter the recipient address.');
      if (!checkTo()) return;
      let lam = null;
      if (!d.max) {
        lam = parseVarv(amount.value);
        if (lam === null) return err.set('Enter an amount in VARV, with at most 8 decimals.');
        if (d.spendable !== null && lam > d.spendable) return err.set('The amount is more than your spendable balance.');
      }
      busy(btn, async () => {
        try {
          if (!S.fees) await loadFees();
          if (!d.utxos) await loadUtxos();
          const body = {
            to: to.value.trim(),
            amount_laminae: d.max ? null : lam.toString(),
            send_max: d.max,
            feerate: S.fees[d.speed],
            height: d.height,
            utxos: d.utxos,
            allow_high_fee: d.allowHigh,
          };
          const b = await local('POST', '/local/build', body);
          const built = {
            hex: String(b.hex),
            txid: vHex64(b.txid),
            fee: vAmt(b.fee),
            total_in: vAmt(b.total_in),
            change: vAmt(b.change),
            change_index: b.change_index === null ? null : vUint(b.change_index),
            weight: vUint(b.weight),
            to: String(b.to),
            amount: vAmt(b.amount),
            inputs: vUint(b.inputs),
            feerate: vUint(b.feerate),
            high_fee: b.high_fee === true,
          };
          if (!/^[0-9a-f]+$/.test(built.hex) || built.to !== to.value.trim().toLowerCase() || (!d.max && built.amount !== lam)) throw new Error('Strata returned a transaction that does not match the request. Nothing was sent.');
          S.built = built;
          d.highFeeAsk = false;
          go('review');
        } catch (e) {
          if (/unusually high/.test(e.message)) d.highFeeAsk = true;
          d.err = e.message;
          if (S.screen === 'send') rerender();
        }
      });
    });
    frame(form, { nav: 'home' });
    // load fees and coins in the background so the spendable amount shows up
    if (!S.fees || d.spendable === null) {
      (async () => {
        try {
          if (S.balance === null) await refresh(true);
          if (!S.fees) await loadFees();
          if (d.spendable === null) await loadUtxos();
          if (S.screen === 'send') rerender();
        } catch (e) {
          d.err = e.message;
          if (S.screen === 'send') rerender();
        }
      })();
    }
  };

  SCREENS.review = () => {
    const b = S.built;
    if (!b) return go('send');
    const err = errorSlot();
    const btn = h('button', { class: 'btn primary block' }, icon('send'), 'Send now');
    btn.addEventListener('click', () =>
      busy(btn, async () => {
        err.set('');
        try {
          const r = await api('/api/v1/tx', { method: 'POST', body: b.hex, timeout: 30000 });
          if (r.txid !== b.txid) throw new Error('The node answered with a different transaction ID. Check Activity before trying again.');
          if (b.change_index !== null) {
            try {
              await local('POST', '/local/mark_used', { change: [b.change_index] });
            } catch (_) {
              /* the next refresh marks it from the node's data */
            }
          }
          S.sent = { txid: b.txid, amount: b.amount, to: b.to, fee: b.fee };
          S.built = null;
          S.send = { to: '', amount: '', max: false, speed: S.send.speed, allowHigh: false, utxos: null, height: null, spendable: null, err: null, highFeeAsk: false };
          go('sent');
          setTimeout(() => refresh(true), 1500);
        } catch (e) {
          err.set(e.message);
        }
      })
    );
    frame(
      h(
        'div',
        { class: 'screen' },
        headRow('Review payment', 'send'),
        h('div', { class: 'review-amount' }, h('span', { class: 'amt', text: fmt(b.amount, { minDec: 2 }) }), h('span', { class: 'cur', text: 'VARV' })),
        h(
          'div',
          { class: 'summary' },
          h('div', { class: 'line' }, h('span', { class: 'k', text: 'To' }), h('span', { class: 'v', text: b.to })),
          h('div', { class: 'line' }, h('span', { class: 'k', text: 'Amount' }), h('span', { class: 'v', text: fmt(b.amount, { minDec: 0 }) + ' VARV' })),
          h('div', { class: 'line' }, h('span', { class: 'k', text: 'Network fee' }), h('span', { class: 'v', text: fmt(b.fee, { minDec: 0 }) + ' VARV' })),
          h('div', { class: 'line total' }, h('span', { class: 'k', text: 'Total' }), h('span', { class: 'v', text: fmt(b.amount + b.fee, { minDec: 0 }) + ' VARV' }))
        ),
        b.high_fee ? h('div', { class: 'notice danger' }, h('div', { class: 'grow' }, h('strong', { text: 'High fee' }), h('span', { text: 'The fee is more than 5% of the amount. Check it before sending.' }))) : null,
        h(
          'p',
          { class: 'hint' },
          b.inputs + ' coin' + (b.inputs === 1 ? '' : 's') + ' spent · weight ' + b.weight.toLocaleString() + ' · ' + b.feerate + ' laminae per weight unit' + (b.change > 0n ? ' · ' + fmt(b.change, { minDec: 0 }) + ' VARV returns to your wallet as change' : '')
        ),
        err,
        btn,
        h('button', { class: 'btn ghost block', onclick: () => go('send') }, 'Edit')
      ),
      { nav: 'home' }
    );
  };

  SCREENS.sent = () => {
    const s = S.sent;
    if (!s) return go('home');
    frame(
      h(
        'div',
        { class: 'screen' },
        h('div', { class: 'big-check' }, icon('check')),
        h('h2', { text: 'Payment sent', class: 'center-text' }),
        h('p', { class: 'lead center-text', text: 'The node accepted the transaction. It will confirm when it is included in a block.' }),
        h(
          'div',
          { class: 'summary' },
          h('div', { class: 'line' }, h('span', { class: 'k', text: 'Amount' }), h('span', { class: 'v', text: fmt(s.amount, { minDec: 0 }) + ' VARV' })),
          h('div', { class: 'line' }, h('span', { class: 'k', text: 'To' }), h('span', { class: 'v', text: s.to })),
          h('div', { class: 'line' }, h('span', { class: 'k', text: 'Transaction ID' }), h('span', { class: 'v', text: s.txid }))
        ),
        h('div', { class: 'btn-row' }, h('button', { class: 'btn', onclick: () => copy(s.txid, 'Transaction ID') }, icon('copy'), 'Copy ID'), h('button', { class: 'btn primary', onclick: () => go('home') }, 'Done'))
      ),
      { nav: 'home' }
    );
  };

  SCREENS.settings = () => {
    const st = S.status;
    const ep = h('input', { class: 'input mono', value: st.api_endpoint, autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', maxlength: 200 });
    const epErr = errorSlot();
    const epBtn = h('button', { class: 'btn small', type: 'submit' }, 'Save and reload');
    const epForm = h('form', { class: 'stack', novalidate: true }, field('Node API address', ep, h('span', { class: 'hint', text: 'Strata reads balances and history from this Varve node API. Use an https:// address, or http://127.0.0.1:PORT for a node on this computer. A node you do not run yourself could hide coins or show a wrong history, but it can never move your coins: every payment is checked and signed here. Your own node is the most trustworthy choice.' })), epErr, h('div', null, epBtn));
    epForm.addEventListener('submit', (ev) => {
      ev.preventDefault();
      epErr.set('');
      busy(epBtn, async () => {
        try {
          S.status = await local('POST', '/local/settings', { api_endpoint: ep.value.trim() });
          // the page's connect-src policy is fixed at load: reload to apply the new node
          history.replaceState(null, '', '/' + FRAG + S.token);
          location.reload();
        } catch (e) {
          epErr.set(e.message);
        }
      });
    });
    const lockSel = h('select', { class: 'select' }, [1, 2, 5, 10, 15, 30, 60].map((m) => h('option', { value: String(m), selected: m === st.autolock_minutes ? true : null, text: m + (m === 1 ? ' minute' : ' minutes') })));
    lockSel.addEventListener('change', async () => {
      try {
        S.status = await local('POST', '/local/settings', { autolock_minutes: Number(lockSel.value) });
        toast('Auto-lock updated');
      } catch (e) {
        toast(e.message);
      }
    });

    const reveal = h('div', { class: 'stack' });
    const drawReveal = () => {
      if (S.revealed) {
        reveal.replaceChildren(
          h('div', { class: 'notice danger' }, h('div', { class: 'grow' }, h('strong', { text: 'Keep these words private.' }), h('span', { text: 'Anyone who sees them can take your coins.' + (S.revealed.seedPass ? ' This wallet also uses a seed passphrase, which is not shown here.' : '') }))),
          wordGrid(S.revealed.words),
          h('button', { class: 'btn block', onclick: () => { S.revealed = null; drawReveal(); } }, 'Hide recovery phrase')
        );
        return;
      }
      const p = passInput('Wallet passphrase', 'current-password');
      const e = errorSlot();
      const b = h('button', { class: 'btn small', type: 'submit' }, 'Show recovery phrase');
      const f = h('form', { class: 'stack', novalidate: true }, h('p', { class: 'hint', text: 'Enter your passphrase to see the 24 words again. Make sure nobody can see your screen.' }), p, e, h('div', null, b));
      f.addEventListener('submit', (ev) => {
        ev.preventDefault();
        busy(b, async () => {
          try {
            const r = await local('POST', '/local/reveal', { file_pass: p.value });
            p.value = '';
            if (!Array.isArray(r.mnemonic) || r.mnemonic.length !== 24) throw new Error('Unexpected response from Strata.');
            S.revealed = { words: r.mnemonic.map(String), seedPass: r.has_seed_passphrase === true };
            drawReveal();
          } catch (err) {
            e.set(err.message === 'wrong passphrase' ? 'Wrong passphrase.' : err.message);
          }
        });
      });
      reveal.replaceChildren(f);
    };
    drawReveal();

    frame(
      h(
        'div',
        { class: 'screen' },
        h('h2', { text: 'Settings' }),
        h('section', { class: 'card' }, h('h3', { text: 'Network' }), h('div', { class: 'kv' }, h('span', { class: 'k', text: 'Network' }), h('span', { text: st.network })), h('div', { class: 'kv' }, h('span', { class: 'k', text: 'Address prefix' }), h('span', { class: 'mono', text: st.hrp + '1' })), h('div', { class: 'kv' }, h('span', { class: 'k', text: 'Strata version' }), h('span', { text: st.version }))),
        h('section', { class: 'card' }, h('h3', { text: 'Node' }), epForm),
        h('section', { class: 'card' }, h('h3', { text: 'Security' }), field('Lock automatically after', lockSel), h('button', { class: 'btn block', onclick: lockNow }, icon('lock'), 'Lock now')),
        h('section', { class: 'card' }, h('h3', { text: 'Recovery phrase' }), reveal)
      ),
      { nav: 'settings' }
    );
  };

  // ------------------------------------------------------------------ timers and boot
  async function pollStatus() {
    if (!S.token || !S.status) return;
    try {
      const st = await local('GET', '/local/status', null, { background: true });
      const was = S.status.unlocked;
      S.status = st;
      if (was && !st.unlocked) onLocked(null);
    } catch (_) {
      /* shown on the next action */
    }
  }

  function userActivity() {
    if (!S.status || !S.status.unlocked) return;
    const now = Date.now();
    if (now - S.lastPing < 60000) return;
    S.lastPing = now;
    local('POST', '/local/ping', {}).catch(() => {});
  }

  async function boot() {
    const m = /^#token=([0-9a-f]{64})$/.exec(location.hash);
    if (m && RE_TOKEN.test(m[1])) S.token = m[1];
    // remove the token from the address bar and history; it stays in memory only
    if (location.hash) history.replaceState(null, '', location.pathname);
    if (!S.token) return showNoToken();
    try {
      S.status = await local('GET', '/local/status');
    } catch (e) {
      if (S.screen !== 'noToken') mount(h('div', { class: 'content' }, h('div', { class: 'screen center' }, alertBox(e.message))));
      return;
    }
    const net = S.status.network;
    document.getElementById('banner').textContent = net.charAt(0).toUpperCase() + net.slice(1) + ': coins have no value';
    document.addEventListener('pointerdown', userActivity, { passive: true });
    document.addEventListener('keydown', userActivity, { passive: true });
    setInterval(pollStatus, 15000);
    setInterval(() => {
      if (document.visibilityState === 'visible' && S.status && S.status.unlocked && ['home', 'activity'].includes(S.screen)) refresh(true);
    }, 30000);
    if (!S.status.has_wallet) go('welcome');
    else if (!S.status.unlocked) go('unlock');
    else go('home');
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
