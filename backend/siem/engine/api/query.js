// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Query language → AST → (a) parameterised ClickHouse SQL, (b) in-memory JS predicate (live tail, rule tests).
//
//   field:value            exact match (user/domain/category/action/… compared lower-case; http_method upper-case)
//   field:"exact phrase"   quoted value (exact for keyword fields, substring for text fields raw/message/cmdline/url/user_agent)
//   field:val*  field:*x?y wildcards (* any, ? one char); trailing-* only → startsWith; field:* → field is present
//   field:>=3 field:<10    comparisons on numbers (severity, ports, http_status), time (ts, rts) and fields.<key> (numeric)
//   field:[a TO b] {a TO b} ranges (inclusive / exclusive, * = open) on numbers and time
//   ip:10.0.0.0/8          CIDR (or exact / prefix) on src_ip OR dst_ip;  src_ip:/dst_ip:/host_ip: accept CIDR too
//   field:(a OR b c)       grouped values for one field
//   word  "a phrase"       full text over raw + message (hasTokenCaseInsensitive for single tokens, else positionCaseInsensitiveUTF8)
//   AND OR NOT ( ) -term   boolean logic; adjacent terms are AND-ed. Precedence NOT > AND > OR.
//   fields.<key>:value     vendor fields map (fields['key'])
// Time values: ISO-8601, YYYY-MM-DD, epoch s/ms, now, now-15m (s m h d w).
// All values are passed as ClickHouse query parameters ({q1:String} …) — never concatenated into SQL.
const net = require('node:net');
const { FIELDS } = require('../schema');

class QueryError extends Error {
  constructor(message, pos) { super(pos === undefined ? message : `${message} (at position ${pos})`); this.name = 'QueryError'; this.status = 400; this.pos = pos; }
}

const MAX_LEN = 4096;
const MAX_TERMS = 128;
const MAX_DEPTH = 24;
const MAX_WILD = 16; // wildcards (* and ?) per term
const MAP_KEY_RE = /^[A-Za-z0-9_.:@$-]{1,128}$/;
const TOKEN_RE = /^[A-Za-z0-9\u0080-￿]+$/; // hasToken needles: no ASCII separators
const KEYWORDS = new Set(['AND', 'OR', 'NOT']);
const SPECIAL = new Set([' ', '\t', '\n', '\r', '(', ')', '"']);

// ---------------------------------------------------------------- parser
function parse(q) {
  if (q === undefined || q === null) q = '';
  if (typeof q !== 'string') throw new QueryError('query must be a string');
  if (q.length > MAX_LEN) throw new QueryError(`query too long (max ${MAX_LEN} characters)`);
  let i = 0;
  let terms = 0;
  let depth = 0;

  const ws = () => { while (i < q.length && /\s/.test(q[i])) i++; };
  const end = () => i >= q.length;
  const peekKeyword = (kw) => {
    if (q.startsWith(kw, i)) { const n = q[i + kw.length]; return n === undefined || /[\s()]/.test(n); }
    return false;
  };

  function readQuoted() {
    const start = i;
    i++; // opening quote
    let s = '';
    while (i < q.length && q[i] !== '"') {
      if (q[i] === '\\' && i + 1 < q.length) { s += q[i + 1]; i += 2; continue; }
      s += q[i++];
    }
    if (q[i] !== '"') throw new QueryError('unterminated quote', start);
    i++;
    return s;
  }

  // bare word: returns {text, wild:boolean, pattern:[{lit}|{any}|{one}]}
  function readWord(stopAtColon) {
    const start = i;
    let text = '';
    const pattern = [];
    let wild = false;
    let wilds = 0;
    let lit = '';
    while (i < q.length && !SPECIAL.has(q[i]) && !(stopAtColon && q[i] === ':')) {
      const c = q[i];
      if (c === '\\' && i + 1 < q.length) { lit += q[i + 1]; text += q[i + 1]; i += 2; continue; }
      if (c === '*' || c === '?') {
        if (++wilds > MAX_WILD) throw new QueryError(`too many wildcards in one term (max ${MAX_WILD})`, i);
        wild = true; if (lit) pattern.push({ lit }); lit = ''; pattern.push(c === '*' ? { any: 1 } : { one: 1 }); text += c; i++; continue;
      }
      lit += c; text += c; i++;
    }
    if (lit) pattern.push({ lit });
    if (i === start) throw new QueryError('expected a term', start);
    return { text, wild, pattern };
  }

  function countTerm() { if (++terms > MAX_TERMS) throw new QueryError(`too many terms (max ${MAX_TERMS})`); }

  function parseOr(field) {
    const items = [parseAnd(field)];
    for (;;) {
      ws();
      if (peekKeyword('OR')) { i += 2; ws(); if (end() || q[i] === ')') throw new QueryError('OR needs a right-hand term', i); items.push(parseAnd(field)); } else break;
    }
    return items.length === 1 ? items[0] : { type: 'or', items };
  }

  function parseAnd(field) {
    const items = [parseUnary(field)];
    for (;;) {
      ws();
      if (end() || q[i] === ')' || peekKeyword('OR')) break;
      if (peekKeyword('AND')) { i += 3; ws(); if (end() || q[i] === ')') throw new QueryError('AND needs a right-hand term', i); }
      items.push(parseUnary(field));
    }
    return items.length === 1 ? items[0] : { type: 'and', items };
  }

  function parseUnary(field) {
    ws();
    if (peekKeyword('NOT')) { i += 3; ws(); if (end()) throw new QueryError('NOT needs a term', i); return { type: 'not', item: parseUnary(field) }; }
    if (q[i] === '-' && i + 1 < q.length && /[A-Za-z_("]/.test(q[i + 1])) { i++; return { type: 'not', item: parseUnary(field) }; }
    return parsePrimary(field);
  }

  function parsePrimary(field) {
    ws();
    if (end()) throw new QueryError('unexpected end of query', i);
    const c = q[i];
    if (c === ')') throw new QueryError('unexpected ")"', i);
    if (c === '(') {
      const start = i;
      if (++depth > MAX_DEPTH) throw new QueryError('query nested too deeply');
      i++;
      ws();
      if (q[i] === ')') throw new QueryError('empty parentheses', start);
      const e = parseOr(field);
      ws();
      if (q[i] !== ')') throw new QueryError('missing ")"', start);
      i++;
      depth--;
      return e;
    }
    if (c === '"') {
      countTerm();
      const v = readQuoted();
      return field ? makeTerm(field, { phrase: v }, i) : { type: 'text', value: v, phrase: true };
    }
    // field:value ?
    if (!field) {
      const m = /^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_.@$-]+)?):/.exec(q.slice(i, i + 200));
      if (m) {
        const fname = m[1];
        const at = i;
        i += m[0].length;
        return parseFieldValue(fname, at);
      }
    }
    countTerm();
    const w = readWord(false);
    if (KEYWORDS.has(w.text)) throw new QueryError(`unexpected keyword ${w.text}`, i - w.text.length);
    if (field) return makeTerm(field, w.wild ? { wild: w } : { value: w.text }, i);
    return { type: 'text', value: w.text, wild: w.wild ? w.pattern : null };
  }

  function parseFieldValue(fname, at) {
    if (end() || /\s/.test(q[i])) throw new QueryError(`missing value for field "${fname}"`, at);
    const spec = fieldSpec(fname, at);
    const c = q[i];
    if (c === '(') {
      if (++depth > MAX_DEPTH) throw new QueryError('query nested too deeply');
      const start = i;
      i++;
      ws();
      if (q[i] === ')') throw new QueryError('empty value group', start);
      const e = parseOr(spec);
      ws();
      if (q[i] !== ')') throw new QueryError('missing ")"', start);
      i++;
      depth--;
      return e;
    }
    countTerm();
    if (c === '"') return makeTerm(spec, { phrase: readQuoted() }, at);
    if (c === '[' || c === '{') return makeTerm(spec, readRange(), at);
    const cm = /^(>=|<=|>|<)/.exec(q.slice(i, i + 2));
    if (cm) {
      i += cm[1].length;
      if (end() || /\s/.test(q[i])) throw new QueryError(`missing value after ${cm[1]}`, i);
      const v = q[i] === '"' ? readQuoted() : readWord(false).text;
      return makeTerm(spec, { cmp: cm[1], value: v }, at);
    }
    const w = readWord(false);
    if (w.text === '*') return makeTerm(spec, { exists: true }, at);
    return makeTerm(spec, w.wild ? { wild: w } : { value: w.text }, at);
  }

  function readRange() {
    const start = i;
    const open = q[i++];
    const close = open === '[' ? ']' : '}';
    const endIdx = q.indexOf(open === '[' ? ']' : '}', i);
    const endAlt = q.indexOf(open === '[' ? '}' : ']', i); // mixed brackets [a TO b}
    let e = endIdx;
    if (e < 0 || (endAlt >= 0 && endAlt < e)) e = endAlt;
    if (e < 0) throw new QueryError('unterminated range', start);
    const body = q.slice(i, e).trim();
    const incHi = q[e] === ']';
    i = e + 1;
    const m = /^("(?:[^"\\]|\\.)*"|\S+)\s+TO\s+("(?:[^"\\]|\\.)*"|\S+)$/.exec(body);
    if (!m) throw new QueryError('range must be [a TO b]', start);
    const un = (s) => (s[0] === '"' ? s.slice(1, -1).replace(/\\(.)/g, '$1') : s);
    void close;
    return { range: { lo: m[1] === '*' ? null : un(m[1]), hi: m[2] === '*' ? null : un(m[2]), incLo: open === '[', incHi } };
  }

  ws();
  if (end()) return { type: 'all' };
  const ast = parseOr(null);
  ws();
  if (!end()) throw new QueryError(q[i] === ')' ? 'unbalanced ")"' : 'unexpected input', i);
  return ast;
}

// ---------------------------------------------------------------- field semantics
function fieldSpec(name, at) {
  if (name === 'ip') return { name: 'ip', kind: 'ipany' };
  if (name.startsWith('fields.')) {
    const key = name.slice(7);
    if (!MAP_KEY_RE.test(key)) throw new QueryError(`invalid fields key "${key}"`, at);
    return { name, kind: 'mapkey', key };
  }
  const d = FIELDS[name];
  if (!d) throw new QueryError(`unknown field "${name}" (use fields.<key> for vendor fields, or quote the text to search it)`, at);
  if (d.kind === 'map') throw new QueryError('use fields.<key>:value to search vendor fields', at);
  return { name, kind: d.kind, max: d.max, lower: !!d.lower, upper: !!d.upper };
}

const NOW_RE = /^now(?:([+-])(\d+)([smhdw]))?$/;
const UNIT_MS = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 };

function parseTimeValue(v, now = Date.now()) {
  if (typeof v === 'number') return v > 1e11 ? Math.trunc(v) : Math.trunc(v * 1000);
  const s = String(v).trim();
  let m;
  if ((m = NOW_RE.exec(s))) return m[1] ? now + (m[1] === '-' ? -1 : 1) * Number(m[2]) * UNIT_MS[m[3]] : now;
  if (/^\d{9,13}$/.test(s)) { const n = Number(s); return n > 1e11 ? n : n * 1000; }
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) { const t = Date.parse(s + 'T00:00:00Z'); if (Number.isFinite(t)) return t; }
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:?\d{2})?$/.test(s)) {
    let x = s.replace(' ', 'T');
    if (!/(Z|[+-]\d{2}:?\d{2})$/.test(x)) x += 'Z';
    const t = Date.parse(x);
    if (Number.isFinite(t)) return t;
  }
  if (/^\d{4}-\d{2}-\d{2}T/.test(s)) { const t = Date.parse(s); if (Number.isFinite(t)) return t; }
  throw new QueryError(`invalid time "${s}" (use ISO-8601, YYYY-MM-DD, epoch or now-15m)`);
}

function parseNum(spec, v) {
  if (!/^-?\d+(\.\d+)?$/.test(String(v))) throw new QueryError(`${spec.name} needs a number, got "${v}"`);
  const n = Number(v);
  if (spec.kind === 'num' && (!Number.isInteger(n) || n < 0 || n > 65535)) throw new QueryError(`${spec.name} value out of range: ${v}`);
  return n;
}

function parseCidr(v) {
  const [a, b, extra] = String(v).split('/');
  const fam = net.isIP(a);
  const bits = Number(b);
  if (extra !== undefined || !fam || !/^\d{1,3}$/.test(b || '') || bits > (fam === 4 ? 32 : 128)) throw new QueryError(`invalid CIDR "${v}"`);
  return { addr: a, bits, fam };
}

function normValue(spec, v) {
  const s = String(v);
  if (spec.lower) return s.toLowerCase();
  if (spec.upper) return s.toUpperCase();
  return s;
}

// Build a validated term node (all value checks happen here so SQL and JS compilers get clean input).
function makeTerm(spec, v, at) {
  const t = { type: 'term', field: spec.name, kind: spec.kind, key: spec.key };
  const k = spec.kind;
  if (v.exists) {
    if (k === 'num' || k === 'time' || k === 'uuid') throw new QueryError(`${spec.name}:* is not supported (field always has a value)`, at);
    t.op = 'exists';
    return t;
  }
  if (v.range) {
    if (k !== 'num' && k !== 'time' && k !== 'mapkey') throw new QueryError(`ranges are only supported on numeric/time fields, not ${spec.name}`, at);
    const conv = (x) => (x === null ? null : k === 'time' ? parseTimeValue(x) : parseNum(spec, x));
    t.op = 'range';
    t.lo = conv(v.range.lo);
    t.hi = conv(v.range.hi);
    t.incLo = v.range.incLo;
    t.incHi = v.range.incHi;
    if (t.lo === null && t.hi === null) { t.op = k === 'mapkey' ? 'exists' : 'all'; }
    return t;
  }
  if (v.cmp) {
    if (k !== 'num' && k !== 'time' && k !== 'mapkey') throw new QueryError(`comparison is only supported on numeric/time fields, not ${spec.name}`, at);
    t.op = 'cmp';
    t.cmp = v.cmp;
    t.value = k === 'time' ? parseTimeValue(v.value) : parseNum(spec, v.value);
    return t;
  }
  if (v.wild) {
    if (k === 'num' || k === 'time' || k === 'uuid') throw new QueryError(`wildcards are not supported on ${spec.name}`, at);
    const pat = v.wild.pattern.map((p) => (p.lit !== undefined ? { lit: normValue(spec, p.lit) } : p));
    const onlyTrailing = pat.length === 2 && pat[0].lit !== undefined && pat[1].any;
    if (onlyTrailing && k !== 'text') { t.op = 'prefix'; t.value = pat[0].lit; } else { t.op = 'like'; t.pattern = pat; }
    return t;
  }
  const raw = v.phrase !== undefined ? v.phrase : v.value;
  if (raw === '') throw new QueryError(`empty value for ${spec.name}`, at);
  switch (k) {
    case 'num': t.op = 'eq'; t.value = parseNum(spec, raw); return t;
    case 'time': throw new QueryError(`use ${spec.name}:>=… or ${spec.name}:[a TO b] for time`, at);
    case 'uuid':
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw)) throw new QueryError(`invalid id "${raw}"`, at);
      t.op = 'eq'; t.value = raw.toLowerCase(); return t;
    case 'ip': case 'ipany':
      if (raw.includes('/')) { t.op = 'cidr'; t.cidr = parseCidr(raw); t.value = raw; return t; }
      t.op = 'eq'; t.value = raw.toLowerCase(); return t;
    case 'text': t.op = 'contains'; t.value = raw; return t;
    case 'mapkey':
      if (v.phrase === undefined && raw.includes('/') && net.isIP(raw.split('/')[0])) { t.op = 'cidr'; t.cidr = parseCidr(raw); t.value = raw; return t; }
      t.op = 'eq'; t.value = raw; return t;
    default: t.op = 'eq'; t.value = normValue(spec, raw); return t;
  }
}

// ---------------------------------------------------------------- SQL compiler
function likeEscape(s) { return s.replace(/[\\%_]/g, (c) => '\\' + c); }
function trimAny(pat) {
  let a = 0; let b = pat.length;
  while (a < b && pat[a].any) a++;
  while (b > a && pat[b - 1].any) b--;
  return pat.slice(a, b);
}
function patternToLike(pat, anchored) {
  if (!anchored) pat = trimAny(pat);
  let s = pat.map((p) => (p.lit !== undefined ? likeEscape(p.lit) : p.any ? '%' : '_')).join('');
  if (!anchored) s = '%' + s + '%';
  return s;
}

function compile(q, { prefix = 'q' } = {}) {
  const ast = typeof q === 'object' && q && q.type ? q : parse(q);
  const params = {};
  let n = 0;
  const P = (type, value) => { const name = prefix + (++n); params[name] = { type, value }; return `{${name}:${type}}`; };
  const col = (f) => '`' + f + '`';

  function strExpr(t) { return t.kind === 'mapkey' ? `fields[${P('String', t.key)}]` : col(t.field); }

  function ipTerm(colName, t) {
    const c = col(colName);
    if (t.op === 'eq') return `${c} = ${P('String', t.value)}`;
    if (t.op === 'prefix') return `startsWith(${c}, ${P('String', t.value)})`;
    if (t.op === 'like') return `${c} LIKE ${P('String', patternToLike(t.pattern, true))}`;
    if (t.op === 'cidr') return `(${c} != '' AND isIPAddressInRange(${c}, ${P('String', t.value)}))`;
    if (t.op === 'exists') return `${c} != ''`;
    throw new QueryError('unsupported ip operation');
  }

  function cmpSql(expr, t, type, conv) {
    const ops = { '>': '>', '>=': '>=', '<': '<', '<=': '<=' };
    if (t.op === 'eq') return `${expr} = ${conv(P(type, t.value))}`;
    if (t.op === 'cmp') return `${expr} ${ops[t.cmp]} ${conv(P(type, t.value))}`;
    const parts = [];
    if (t.lo !== null) parts.push(`${expr} ${t.incLo ? '>=' : '>'} ${conv(P(type, t.lo))}`);
    if (t.hi !== null) parts.push(`${expr} ${t.incHi ? '<=' : '<'} ${conv(P(type, t.hi))}`);
    return parts.length ? '(' + parts.join(' AND ') + ')' : '1';
  }

  function term(t) {
    if (t.op === 'all') return '1';
    switch (t.kind) {
      case 'ipany':
        if (t.op === 'exists') return `(src_ip != '' OR dst_ip != '')`;
        return `(${ipTerm('src_ip', t)} OR ${ipTerm('dst_ip', t)})`;
      case 'ip': return ipTerm(t.field, t);
      case 'num': return cmpSql(col(t.field), t, 'UInt16', (x) => x);
      case 'time': return cmpSql(col(t.field), t, 'Int64', (x) => `fromUnixTimestamp64Milli(${x})`);
      case 'uuid': return `${col(t.field)} = toUUIDOrZero(${P('String', t.value)})`;
      case 'tags':
        if (t.op === 'exists') return 'notEmpty(tags)';
        if (t.op === 'eq') return `has(tags, ${P('String', t.value)})`;
        if (t.op === 'prefix') return `arrayExists(x -> startsWith(x, ${P('String', t.value)}), tags)`;
        return `arrayExists(x -> x ILIKE ${P('String', patternToLike(t.pattern, true))}, tags)`;
      case 'mapkey': {
        if (t.op === 'exists') return `mapContains(fields, ${P('String', t.key)})`;
        if (t.op === 'cidr') { const k = P('String', t.key); return `((isIPv4String(fields[${k}]) OR isIPv6String(fields[${k}])) AND isIPAddressInRange(fields[${k}], ${P('String', t.value)}))`; }
        const e = strExpr(t);
        if (t.op === 'eq') return `${e} = ${P('String', t.value)}`;
        if (t.op === 'prefix') return `startsWith(${e}, ${P('String', t.value)})`;
        if (t.op === 'like') return `${e} ILIKE ${P('String', patternToLike(t.pattern, true))}`;
        return cmpSql(`toFloat64OrNull(${e})`, t, 'Float64', (x) => x);
      }
      case 'text': {
        const c = col(t.field);
        if (t.op === 'exists') return `${c} != ''`;
        if (t.op === 'contains') return `positionCaseInsensitiveUTF8(${c}, ${P('String', t.value)}) > 0`;
        if (t.op === 'prefix') return `startsWith(${c}, ${P('String', t.value)})`;
        return `${c} ILIKE ${P('String', patternToLike(t.pattern, true))}`;
      }
      default: { // str
        const c = col(t.field);
        if (t.op === 'exists') return `${c} != ''`;
        if (t.op === 'eq') return `${c} = ${P('String', t.value)}`;
        if (t.op === 'prefix') return `startsWith(${c}, ${P('String', t.value)})`;
        return `${c} ILIKE ${P('String', patternToLike(t.pattern, true))}`;
      }
    }
  }

  function text(t) {
    if (t.wild) { const p = P('String', patternToLike(t.wild, false)); return `(raw ILIKE ${p} OR message ILIKE ${p})`; }
    const p = P('String', t.value);
    if (!t.phrase && TOKEN_RE.test(t.value)) return `(hasTokenCaseInsensitive(raw, ${p}) OR hasTokenCaseInsensitive(message, ${p}))`;
    return `(positionCaseInsensitiveUTF8(raw, ${p}) > 0 OR positionCaseInsensitiveUTF8(message, ${p}) > 0)`;
  }

  function node(a) {
    switch (a.type) {
      case 'all': return '1';
      case 'and': return '(' + a.items.map(node).join(' AND ') + ')';
      case 'or': return '(' + a.items.map(node).join(' OR ') + ')';
      case 'not': return `NOT (${node(a.item)})`;
      case 'term': return term(a);
      case 'text': return text(a);
      default: throw new QueryError('bad AST node');
    }
  }
  return { where: node(ast), params, ast };
}

// ---------------------------------------------------------------- JS predicate compiler
function reEscape(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
// Wildcards are matched with a linear glob matcher, never a backtracking RegExp: `a*a*a*b` against a long log line
// made `[\s\S]*` chains run for minutes on the single engine thread (live tail evaluates every incoming event).
// Segments between `*` are found left to right (greedy-leftmost is exact for globs); a literal segment uses indexOf.
const ONE = 0; // a `?` position inside a segment
function patternToRe(pat, anchored) {
  if (!anchored) pat = trimAny(pat);
  const segs = [[]];
  for (const p of pat) {
    if (p.lit !== undefined) segs[segs.length - 1].push(...p.lit.toLowerCase().split(''));
    else if (p.any) segs.push([]);
    else segs[segs.length - 1].push(ONE);
  }
  const parts = segs.map((toks) => ({ toks, lit: toks.includes(ONE) ? null : toks.join('') }));
  function at(s, seg, pos) {
    if (pos < 0 || pos + seg.toks.length > s.length) return false;
    for (let k = 0; k < seg.toks.length; k++) if (seg.toks[k] !== ONE && seg.toks[k] !== s[pos + k]) return false;
    return true;
  }
  function find(s, seg, from) {
    if (seg.lit !== null) return s.indexOf(seg.lit, from);
    for (let p = from; p + seg.toks.length <= s.length; p++) if (at(s, seg, p)) return p;
    return -1;
  }
  function test(input) {
    const s = String(input).toLowerCase();
    let pos = 0;
    let first = 0;
    let last = parts.length;
    if (anchored) {
      if (parts.length === 1) return s.length === parts[0].toks.length && at(s, parts[0], 0);
      if (!at(s, parts[0], 0)) return false;
      pos = parts[0].toks.length;
      first = 1;
      last = parts.length - 1;
    }
    for (let i = first; i < last; i++) {
      const p = find(s, parts[i], pos);
      if (p < 0) return false;
      pos = p + parts[i].toks.length;
    }
    if (!anchored) return true;
    const tail = parts[parts.length - 1];
    const start = s.length - tail.toks.length;
    return start >= pos && at(s, tail, start);
  }
  return { test };
}
const SEP = '[\\x00-\\x2F\\x3A-\\x40\\x5B-\\x60\\x7B-\\x7F]';

function ipInCidr(ip, c) {
  if (!ip) return false;
  const fam = net.isIP(ip);
  if (!fam || fam !== c.fam) return false;
  if (!c.list) { c.list = new net.BlockList(); c.list.addSubnet(c.addr, c.bits, fam === 4 ? 'ipv4' : 'ipv6'); }
  return c.list.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}

function compileJS(q) {
  const ast = typeof q === 'object' && q && q.type ? q : parse(q);
  function get(ev, t) { return t.kind === 'mapkey' ? (ev.fields ? ev.fields[t.key] : undefined) : ev[t.field]; }
  function cmp(x, t) {
    if (x === undefined || x === null || x === '' || !Number.isFinite(Number(x))) return false;
    const n = Number(x);
    if (t.op === 'eq') return n === t.value;
    if (t.op === 'cmp') return t.cmp === '>' ? n > t.value : t.cmp === '>=' ? n >= t.value : t.cmp === '<' ? n < t.value : n <= t.value;
    if (t.lo !== null && !(t.incLo ? n >= t.lo : n > t.lo)) return false;
    if (t.hi !== null && !(t.incHi ? n <= t.hi : n < t.hi)) return false;
    return true;
  }
  function strOp(v, t) {
    const s = v === undefined || v === null ? '' : String(v);
    switch (t.op) {
      case 'exists': return s !== '';
      case 'eq': return s === t.value;
      case 'prefix': return s.startsWith(t.value);
      case 'like': return (t.re || (t.re = patternToRe(t.pattern, true))).test(s);
      case 'contains': return s.toLowerCase().includes(t.lower || (t.lower = t.value.toLowerCase()));
      case 'cidr': return ipInCidr(s, t.cidr);
      default: return false;
    }
  }
  function term(ev, t) {
    if (t.op === 'all') return true;
    switch (t.kind) {
      case 'ipany': return strOp(ev.src_ip, t) || strOp(ev.dst_ip, t);
      case 'num': case 'time': return cmp(ev[t.field], t);
      case 'tags': {
        const tags = Array.isArray(ev.tags) ? ev.tags : [];
        if (t.op === 'exists') return tags.length > 0;
        return tags.some((x) => strOp(x, t));
      }
      case 'mapkey':
        if (t.op === 'exists') return !!ev.fields && Object.prototype.hasOwnProperty.call(ev.fields, t.key);
        if (t.op === 'cmp' || t.op === 'range') return cmp(get(ev, t), t);
        return strOp(get(ev, t), t);
      default: return strOp(get(ev, t), t);
    }
  }
  function text(ev, t) {
    const hay = [ev.raw || '', ev.message || ''];
    if (t.wild) { const re = t.re || (t.re = patternToRe(t.wild, false)); return hay.some((h) => re.test(h)); }
    if (!t.phrase && TOKEN_RE.test(t.value)) {
      const re = t.re || (t.re = new RegExp(`(?:^|${SEP})${reEscape(t.value)}(?:$|${SEP})`, 'i'));
      return hay.some((h) => re.test(h));
    }
    const lv = t.lower || (t.lower = t.value.toLowerCase());
    return hay.some((h) => h.toLowerCase().includes(lv));
  }
  function node(ev, a) {
    switch (a.type) {
      case 'all': return true;
      case 'and': for (const x of a.items) if (!node(ev, x)) return false; return true;
      case 'or': for (const x of a.items) if (node(ev, x)) return true; return false;
      case 'not': return !node(ev, a.item);
      case 'term': return term(ev, a);
      case 'text': return text(ev, a);
      default: return false;
    }
  }
  return (ev) => { try { return node(ev, ast); } catch { return false; } };
}

module.exports = { parse, compile, compileJS, parseTimeValue, QueryError, fieldSpec };
