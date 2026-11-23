// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The text of a PDF, page by page and line by line, with each word's position - Node stdlib only (zlib), nothing executed.
 *   pdfText(buf, { maxPages }) -> { pages: [{ n, lines: [{ y, text, cells: [{ x, text }] }] }], warnings: [] }
 * What it reads: the objects (also inside compressed object streams), Flate-compressed content streams, the page tree in order
 * (inherited resources), fonts with ToUnicode maps (1- and 2-byte codes), simple-font widths and CID widths (W / DW) so a run's
 * end is known, form XObjects (Do) with their matrix, and the text operators (Tf Tm Td TD T* TL Tc Tw Tz Ts Tj TJ ' ").
 * A line is the words at one height; a cell is a run of words separated from the next by a clear gap - how a table's columns
 * come out of a report. What it does not read: scanned pages (images - no text to read, said in warnings), encrypted PDFs
 * (refused), Type3 glyph shapes. It never runs JavaScript, actions or embedded files: only text-drawing operators are interpreted.
 */
const zlib = require('node:zlib');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const MAX_STREAM = 64 * 1024 * 1024, MAX_TOTAL = 256 * 1024 * 1024;   // a decompression bomb stops here
let inflated = 0;

// ---------------------------------------------------------------- objects
const WS = new Set([0, 9, 10, 12, 13, 32]), DELIM = new Set('()<>[]{}/%'.split('').map((c) => c.charCodeAt(0)));
function parseAt(s, i) {   // s: latin1 string; returns [value, nextIndex]
  const skip = () => { for (;;) { while (i < s.length && WS.has(s.charCodeAt(i))) i++; if (s[i] === '%') { while (i < s.length && s[i] !== '\n' && s[i] !== '\r') i++; continue; } break; } };
  skip(); const c = s[i];
  if (c === '<' && s[i + 1] === '<') { i += 2; const d = {}; for (;;) { skip(); if (s[i] === '>' && s[i + 1] === '>') { i += 2; return [d, i]; } if (i >= s.length) return [d, i]; const [k, j] = parseAt(s, i); i = j; const [v, j2] = parseAt(s, i); i = j2; if (k && k.name) d[k.name] = v; } }
  if (c === '[') { i++; const a = []; for (;;) { skip(); if (s[i] === ']') return [a, i + 1]; if (i >= s.length) return [a, i]; const [v, j] = parseAt(s, i); i = j; a.push(v); } }
  if (c === '(') { let depth = 1, out = ''; i++; while (i < s.length && depth) { const ch = s[i];
      if (ch === '\\') { const n = s[i + 1]; const map = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', '(': '(', ')': ')', '\\': '\\' };
        if (map[n] !== undefined) { out += map[n]; i += 2; } else if (/[0-7]/.test(n)) { let o = ''; i++; while (o.length < 3 && /[0-7]/.test(s[i])) o += s[i++]; out += String.fromCharCode(parseInt(o, 8) & 255); } else if (n === '\r' || n === '\n') { i += 2; if (n === '\r' && s[i] === '\n') i++; } else { out += n || ''; i += 2; } continue; }
      if (ch === '(') depth++; else if (ch === ')') { depth--; if (!depth) { i++; break; } } out += ch; i++; }
    return [{ str: out }, i]; }
  if (c === '<') { const e = s.indexOf('>', i); let h = s.slice(i + 1, e < 0 ? s.length : e).replace(/[^0-9A-Fa-f]/g, ''); if (h.length % 2) h += '0'; let out = ''; for (let k = 0; k < h.length; k += 2) out += String.fromCharCode(parseInt(h.substr(k, 2), 16)); return [{ str: out, hex: true }, e < 0 ? s.length : e + 1]; }
  if (c === '/') { let j = i + 1; while (j < s.length && !WS.has(s.charCodeAt(j)) && !DELIM.has(s.charCodeAt(j))) j++; return [{ name: s.slice(i + 1, j).replace(/#([0-9A-Fa-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))) }, j]; }
  let j = i; while (j < s.length && !WS.has(s.charCodeAt(j)) && !DELIM.has(s.charCodeAt(j))) j++; const tok = s.slice(i, j);
  if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(tok)) {   // a reference "n g R"?
    const m = /^\s+(\d+)\s+R(?![A-Za-z])/.exec(s.slice(j, j + 24)); if (m && /^\d+$/.test(tok)) return [{ ref: +tok }, j + m[0].length];
    return [Number(tok), j]; }
  if (tok === 'true') return [true, j]; if (tok === 'false') return [false, j]; if (tok === 'null') return [null, j];
  return [{ op: tok }, j === i ? i + 1 : j];
}
function loadObjects(buf) {
  const S = buf.toString('latin1'), objs = new Map(), re = /(\d+)\s+(\d+)\s+obj\b/g; let m;
  while ((m = re.exec(S))) {
    const num = +m[1], start = m.index + m[0].length;
    let [val, j] = parseAt(S, start), stream = null;
    const k = S.slice(j, j + 20).search(/\bstream(\r\n|\n|\r)/);
    if (k >= 0 && val && typeof val === 'object' && !Array.isArray(val) && /^\s*$/.test(S.slice(j, j + k))) {
      const ds = j + k + 6 + (S.slice(j + k + 6, j + k + 8) === '\r\n' ? 2 : 1);
      let end = typeof val.Length === 'number' && S.slice(ds + val.Length, ds + val.Length + 30).includes('endstream') ? ds + val.Length : S.indexOf('endstream', ds);
      if (end < 0) end = S.length; stream = buf.slice(ds, end); re.lastIndex = end;
    }
    objs.set(num, { dict: val, raw: stream });
  }
  return { objs, S };
}
function decodeStream(o, R) {
  if (!o || !o.raw) return Buffer.alloc(0); if (o.dec) return o.dec;
  let f = R(o.dict.Filter); f = Array.isArray(f) ? f.map((x) => R(x)) : f ? [f] : []; let b = o.raw;
  for (const x of f) { const n = x && x.name;
    if (n === 'FlateDecode' || n === 'Fl') { const zo = { finishFlush: zlib.constants.Z_SYNC_FLUSH, maxOutputLength: MAX_STREAM };
      try { b = zlib.inflateSync(b, zo); } catch (e) { if (e.code === 'ERR_BUFFER_TOO_LARGE') throw httpErr(400, 'the PDF holds a stream that expands beyond 64 MB - refused'); try { b = zlib.inflateRawSync(b, zo); } catch (e2) { if (e2.code === 'ERR_BUFFER_TOO_LARGE') throw httpErr(400, 'the PDF holds a stream that expands beyond 64 MB - refused'); b = Buffer.alloc(0); /* unreadable stream: read as empty; a text-less result is reported in warnings */ } }
      inflated += b.length; if (inflated > MAX_TOTAL) throw httpErr(400, 'the PDF expands beyond 256 MB of content - refused');
      const dp = R(o.dict.DecodeParms); if (dp && R(dp.Predictor) >= 10) b = unpredict(b, R(dp.Columns) || 1); }
    else if (n === 'ASCIIHexDecode' || n === 'AHx') { const h = b.toString('latin1').replace(/[^0-9A-Fa-f]/g, ''); b = Buffer.from(h.length % 2 ? h + '0' : h, 'hex'); }
    else { b = Buffer.alloc(0); break; }   // images (DCT, JPX, CCITT) and others: not text
  }
  o.dec = b; return b;
}
function unpredict(b, cols) { const out = [], row = cols + 1; let prev = Buffer.alloc(cols);
  for (let i = 0; i + row <= b.length; i += row) { const t = b[i], cur = Buffer.from(b.slice(i + 1, i + row));
    for (let k = 0; k < cols; k++) { const a = k ? cur[k - 1] : 0, up = prev[k], c = k ? prev[k - 1] : 0; if (t === 1) cur[k] = (cur[k] + a) & 255; else if (t === 2) cur[k] = (cur[k] + up) & 255; else if (t === 3) cur[k] = (cur[k] + ((a + up) >> 1)) & 255; else if (t === 4) { const p = a + up - c, pa = Math.abs(p - a), pb = Math.abs(p - up), pc = Math.abs(p - c); cur[k] = (cur[k] + (pa <= pb && pa <= pc ? a : pb <= pc ? up : c)) & 255; } }
    out.push(cur); prev = cur; }
  return Buffer.concat(out); }

// ---------------------------------------------------------------- fonts
function cmapOf(text) {
  const map = new Map(); let bytes = 1;
  const cs = /begincodespacerange([\s\S]*?)endcodespacerange/g; let m; while ((m = cs.exec(text))) { const h = /<([0-9A-Fa-f]+)>/.exec(m[1]); if (h) bytes = Math.max(1, Math.ceil(h[1].length / 2)); }
  const uni = (h) => { let s = ''; for (let i = 0; i + 4 <= h.length; i += 4) s += String.fromCharCode(parseInt(h.substr(i, 4), 16)); if (h.length === 2) s = String.fromCharCode(parseInt(h, 16)); return s; };
  const bc = /beginbfchar([\s\S]*?)endbfchar/g; while ((m = bc.exec(text))) { const re = /<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>/g; let x; while ((x = re.exec(m[1]))) map.set(parseInt(x[1], 16), uni(x[2])); }
  const br = /beginbfrange([\s\S]*?)endbfrange/g; while ((m = br.exec(text))) { const re = /<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<([0-9A-Fa-f]*)>|\[([^\]]*)\])/g; let x;
    while ((x = re.exec(m[1]))) { const lo = parseInt(x[1], 16), hi = parseInt(x[2], 16); if (hi - lo > 65535) continue;
      if (x[4] !== undefined) { const base = x[4]; const head = base.slice(0, -4), last = parseInt(base.slice(-4) || '0', 16); for (let c = lo; c <= hi; c++) map.set(c, uni(head) + String.fromCharCode(last + c - lo)); }
      else { const list = (x[5].match(/<([0-9A-Fa-f]*)>/g) || []).map((h) => uni(h.slice(1, -1))); for (let c = lo; c <= hi && c - lo < list.length; c++) map.set(c, list[c - lo]); } } }
  return { map, bytes };
}
const WIN = { 0x80: '€', 0x82: '‚', 0x84: '„', 0x85: '…', 0x91: '‘', 0x92: '’', 0x93: '“', 0x94: '”', 0x95: '•', 0x96: '–', 0x97: '—', 0x99: '™', 0xa0: ' ' };
function fontOf(ref, R, cache) {
  const key = ref && ref.ref != null ? ref.ref : null; if (key != null && cache.has(key)) return cache.get(key);
  const d = R(ref) || {}, F = { bytes: 1, map: null, widths: null, first: 0, dw: 500, cid: false, diff: null };
  const tu = d.ToUnicode && R.obj(d.ToUnicode); if (tu) { const c = cmapOf(decodeStream(tu, R).toString('latin1')); F.map = c.map; F.bytes = c.bytes; }
  if (R(d.Subtype) && R(d.Subtype).name === 'Type0') { F.cid = true; F.bytes = F.map ? F.bytes : 2; const df = R((R(d.DescendantFonts) || [])[0]) || {};
    F.dw = typeof R(df.DW) === 'number' ? R(df.DW) : 1000; const W = R(df.W); if (Array.isArray(W)) { F.cw = new Map(); for (let i = 0; i < W.length;) { const a = R(W[i]), b = R(W[i + 1]);
        if (Array.isArray(b)) { b.forEach((w, k) => F.cw.set(a + k, R(w))); i += 2; } else { const w = R(W[i + 2]); for (let c = a; c <= b && c - a < 65536; c++) F.cw.set(c, w); i += 3; } } } }
  else { const w = R(d.Widths); if (Array.isArray(w)) { F.widths = w.map((x) => R(x)); F.first = R(d.FirstChar) || 0; }
    const fd = R(d.FontDescriptor); if (fd && typeof R(fd.MissingWidth) === 'number') F.dw = R(fd.MissingWidth);
    const enc = R(d.Encoding); if (enc && Array.isArray(R(enc.Differences))) { F.diff = new Map(); let code = 0; for (const x of R(enc.Differences)) { const v = R(x); if (typeof v === 'number') code = v; else if (v && v.name) F.diff.set(code++, v.name); } } }
  if (key != null) cache.set(key, F); return F;
}
const GLYPH = { space: ' ', percent: '%', period: '.', comma: ',', hyphen: '-', minus: '-', parenleft: '(', parenright: ')', slash: '/', colon: ':', zero: '0', one: '1', two: '2', three: '3', four: '4', five: '5', six: '6', seven: '7', eight: '8', nine: '9' };
function decodeText(F, s) {
  const out = []; const n = F.bytes;
  for (let i = 0; i + n <= s.length; i += n) { let code = 0; for (let k = 0; k < n; k++) code = code * 256 + s.charCodeAt(i + k);
    let ch = F.map && F.map.has(code) ? F.map.get(code) : null;
    if (ch == null && F.diff && F.diff.has(code)) { const g = F.diff.get(code); ch = GLYPH[g] || (/^[A-Za-z]$/.test(g) ? g : /^uni([0-9A-F]{4})$/.test(g) ? String.fromCharCode(parseInt(g.slice(3), 16)) : ''); }
    if (ch == null) ch = F.cid ? '' : (WIN[code] || String.fromCharCode(code));
    let w; if (F.cid) w = F.cw && F.cw.has(code) ? F.cw.get(code) : F.dw; else w = F.widths && code >= F.first && code - F.first < F.widths.length ? F.widths[code - F.first] : F.dw;
    out.push({ ch, w: typeof w === 'number' ? w : 500, space: n === 1 && code === 32 }); }
  return out;
}

// ---------------------------------------------------------------- content streams
const mul = (a, b) => [a[0] * b[0] + a[1] * b[2], a[0] * b[1] + a[1] * b[3], a[2] * b[0] + a[3] * b[2], a[2] * b[1] + a[3] * b[3], a[4] * b[0] + a[5] * b[2] + b[4], a[4] * b[1] + a[5] * b[3] + b[5]];
function runContent(src, res, R, ctm0, items, fontCache, depth, budget) {
  const s = src.toString('latin1'); let i = 0, ops = [], ctm = ctm0.slice(), stack = [];
  let tm = [1, 0, 0, 1, 0, 0], tlm = tm, font = null, fs = 10, tc = 0, tw = 0, tz = 1, tl = 0, rise = 0;
  const fonts = R(res && res.Font) || {}, xo = R(res && res.XObject) || {};
  const show = (str) => {
    if (!font) font = { bytes: 1, map: null, widths: null, first: 0, dw: 500 };
    const g = decodeText(font, str); let text = '', adv = 0;
    for (const x of g) { text += x.ch; adv += (x.w / 1000 * fs + tc + (x.space ? tw : 0)) * tz; }
    const m = mul([fs * tz, 0, 0, fs, 0, rise], mul(tm, ctm)), e = mul([1, 0, 0, 1, adv, 0], mul(tm, ctm));
    if (text.trim()) items.push({ x: m[4], y: m[5], x2: e[4], size: Math.abs(m[3]) || Math.abs(fs), text });
    tm = mul([1, 0, 0, 1, adv, 0], tm);
  };
  while (i < s.length) {
    if (--budget.n < 0) throw httpErr(400, 'the PDF is too complex to read (too many drawing operations)');
    const [v, j] = parseAt(s, i); if (j <= i) { i++; continue; } i = j;
    if (!(v && v.op !== undefined)) { ops.push(v); continue; }
    const op = v.op, a = ops; ops = [];
    switch (op) {
      case 'BI': { const e = s.indexOf('EI', s.indexOf('ID', i)); i = e < 0 ? s.length : e + 2; break; }   // inline image: skipped
      case 'q': stack.push(ctm.slice()); break; case 'Q': ctm = stack.pop() || ctm0.slice(); break;
      case 'cm': if (a.length >= 6) ctm = mul(a.slice(-6).map(Number), ctm); break;
      case 'BT': tm = [1, 0, 0, 1, 0, 0]; tlm = tm; break;
      case 'Tf': { const nm = a[0] && a[0].name; fs = Number(a[1]) || fs; font = nm && fonts[nm] ? fontOf(fonts[nm], R, fontCache) : null; break; }
      case 'Tc': tc = Number(a[0]) || 0; break; case 'Tw': tw = Number(a[0]) || 0; break; case 'Tz': tz = (Number(a[0]) || 100) / 100; break;
      case 'TL': tl = Number(a[0]) || 0; break; case 'Ts': rise = Number(a[0]) || 0; break;
      case 'Td': tlm = mul([1, 0, 0, 1, Number(a[0]) || 0, Number(a[1]) || 0], tlm); tm = tlm; break;
      case 'TD': tl = -(Number(a[1]) || 0); tlm = mul([1, 0, 0, 1, Number(a[0]) || 0, Number(a[1]) || 0], tlm); tm = tlm; break;
      case 'Tm': if (a.length >= 6) { tlm = a.slice(-6).map(Number); tm = tlm; } break;
      case 'T*': tlm = mul([1, 0, 0, 1, 0, -tl], tlm); tm = tlm; break;
      case 'Tj': if (a[0] && a[0].str != null) show(a[0].str); break;
      case "'": tlm = mul([1, 0, 0, 1, 0, -tl], tlm); tm = tlm; if (a[0] && a[0].str != null) show(a[0].str); break;
      case '"': tw = Number(a[0]) || 0; tc = Number(a[1]) || 0; tlm = mul([1, 0, 0, 1, 0, -tl], tlm); tm = tlm; if (a[2] && a[2].str != null) show(a[2].str); break;
      case 'TJ': for (const x of (Array.isArray(a[0]) ? a[0] : [])) { if (x && x.str != null) show(x.str); else if (typeof x === 'number') { const dx = -x / 1000 * fs * tz;
          if (x < -180 && items.length) { const last = items[items.length - 1]; if (last) last.gapAfter = true; } tm = mul([1, 0, 0, 1, dx, 0], tm); } } break;
      case 'Do': { const nm = a[0] && a[0].name, o = nm && xo[nm] && R.obj(xo[nm]);
        if (o && depth < 6 && R(o.dict.Subtype) && R(o.dict.Subtype).name === 'Form') { const mx = Array.isArray(R(o.dict.Matrix)) ? R(o.dict.Matrix).map((x) => Number(R(x))) : [1, 0, 0, 1, 0, 0];
          runContent(decodeStream(o, R), R(o.dict.Resources) || res, R, mul(mx, ctm), items, fontCache, depth + 1, budget); } break; }
      default: break;
    }
  }
}

// ---------------------------------------------------------------- lines and cells
function layout(items) {
  if (!items.length) return [];
  const its = items.filter((t) => isFinite(t.x) && isFinite(t.y)).sort((a, b) => b.y - a.y || a.x - b.x), lines = [];
  for (const t of its) { const L = lines[lines.length - 1]; if (L && Math.abs(L.y - t.y) <= Math.max(1.5, 0.35 * Math.min(L.size, t.size))) L.items.push(t); else lines.push({ y: t.y, size: t.size, items: [t] }); }
  return lines.map((L) => { L.items.sort((a, b) => a.x - b.x); const cells = []; let cur = null, prev = null;
    for (const t of L.items) { const gap = prev ? t.x - prev.x2 : 0, sz = Math.max(4, Math.min(prev ? prev.size : t.size, t.size));
      if (!cur || gap > 1.1 * sz) { cur = { x: Math.round(t.x * 10) / 10, x2: t.x2, text: t.text.replace(/^\s+/, '') }; cells.push(cur); }
      else { cur.text += (gap > 0.18 * sz || (prev && prev.gapAfter)) && !/\s$/.test(cur.text) && !/^\s/.test(t.text) ? ' ' + t.text : t.text; cur.x2 = t.x2; }
      prev = t; }
    for (const c of cells) { c.text = c.text.replace(/\s+/g, ' ').trim(); c.x2 = Math.round(c.x2 * 10) / 10; }
    const cs = cells.filter((c) => c.text);
    return { y: Math.round(L.y * 10) / 10, text: cs.map((c) => c.text).join('   '), cells: cs }; }).filter((l) => l.cells.length);
}

function pdfText(buf, o = {}) {
  if (!Buffer.isBuffer(buf) || buf.slice(0, 5).toString('latin1') !== '%PDF-') throw httpErr(400, 'not a PDF file');
  const maxPages = o.maxPages || 400, warnings = []; inflated = 0;
  const { objs, S } = loadObjects(buf);
  // compressed object streams
  for (const [, ob] of [...objs]) { const d = ob.dict; if (!d || !d.Type || d.Type.name !== 'ObjStm' || !ob.raw) continue;
    const R0 = (v) => (v && v.ref != null ? (objs.get(v.ref) || {}).dict : v);
    let txt; try { txt = decodeStream(ob, Object.assign(R0, { obj: (v) => objs.get(v.ref) })).toString('latin1'); } catch (e) { warnings.push('an object stream could not be read'); continue; }
    const first = R0(d.First), n = R0(d.N), head = txt.slice(0, first).trim().split(/\s+/).map(Number);
    for (let k = 0; k < n && 2 * k + 1 < head.length; k++) { const num = head[2 * k], off = head[2 * k + 1]; if (!objs.has(num)) { try { objs.set(num, { dict: parseAt(txt, first + off)[0], raw: null }); } catch (e) { warnings.push('object ' + num + ' could not be read'); } } } }
  const R = (v, seen = 0) => { while (v && v.ref != null && seen++ < 20) { const x = objs.get(v.ref); v = x ? x.dict : null; } return v; };
  R.obj = (v) => (v && v.ref != null ? objs.get(v.ref) : null);
  if (/\/Encrypt\s/.test(S.slice(Math.max(0, S.length - 4096))) || [...objs.values()].some((x) => x.dict && x.dict.Type && x.dict.Type.name === 'XRef' && x.dict.Encrypt)) throw httpErr(400, 'the PDF is encrypted or password-protected - save an unprotected copy (or export it again) and upload that');
  // the page tree, in order
  const cat = [...objs.values()].find((x) => x.dict && x.dict.Type && x.dict.Type.name === 'Catalog');
  const pages = [];
  const walk = (node, inh, depth) => { const d = R(node); if (!d || depth > 40 || pages.length >= maxPages) return;
    const res = d.Resources ? R(d.Resources) : inh;
    if (d.Type && d.Type.name === 'Pages' || Array.isArray(R(d.Kids))) { for (const k of R(d.Kids) || []) walk(k, res, depth + 1); return; }
    pages.push({ d, res }); };
  if (cat && cat.dict.Pages) walk(cat.dict.Pages, null, 0);
  if (!pages.length) for (const x of objs.values()) if (x.dict && x.dict.Type && x.dict.Type.name === 'Page') pages.push({ d: x.dict, res: R(x.dict.Resources) });
  const fontCache = new Map(), budget = { n: 4e6 }, out = [];
  pages.slice(0, maxPages).forEach((p, idx) => {
    let c = R(p.d.Contents); const refs = Array.isArray(p.d.Contents) ? p.d.Contents : Array.isArray(c) ? c : [p.d.Contents];
    const src = Buffer.concat(refs.map((r) => { const o2 = R.obj(r); return o2 ? Buffer.concat([decodeStream(o2, R), Buffer.from('\n')]) : Buffer.alloc(0); }));
    const items = []; runContent(src, p.res, R, [1, 0, 0, 1, 0, 0], items, fontCache, 0, budget);
    out.push({ n: idx + 1, lines: layout(items) });
  });
  const empty = out.filter((p) => !p.lines.length).length;
  if (out.length && empty === out.length) warnings.push('no text in the PDF - it looks scanned (pictures of pages); export the report from Word / Excel as PDF, or upload the Excel model instead');
  else if (empty) warnings.push(empty + ' page(s) have no text (scanned or pictures only)');
  if (pages.length > maxPages) warnings.push('only the first ' + maxPages + ' pages were read');
  return { pages: out, warnings };
}
module.exports = { pdfText, _t: { parseAt, cmapOf, layout } };
