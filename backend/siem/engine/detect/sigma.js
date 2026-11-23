// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Sigma → native rule converter.
 *
 *   convertSigma(yamlTextOrObject, { id?, enabled?, suppress_s? })
 *     → { ok: true, rule, warnings[] }  |  { ok: false, errors[] (unsupported constructs, clearly named), warnings[] }
 *   convertSigmaAll(yamlText, opts) → [result per YAML document]
 *
 * Never guesses: anything it cannot translate faithfully is reported in `errors` and no rule is produced.
 * Lossy-but-safe situations (e.g. a logsource we cannot map, the `cased` modifier on a case-insensitive engine)
 * produce `warnings` and a rule.
 *
 * Supported
 *   logsource  product/category/service → src_type/category/action/event_code filters (LOGSOURCE_MAP below)
 *   detection  selections as maps (AND) or lists of maps (OR); lists of values (OR, or AND with |all);
 *              keyword lists (plain strings) → full-text contains on raw; null value → field absent;
 *              wildcards * and ? in values (→ contains/startswith/endswith, or an anchored regex);
 *              modifiers contains, startswith, endswith, all, re (incl. re|i|m|s flags), cidr, gt, gte, lt, lte,
 *              exists, windash, cased (warning — engine is case-insensitive).
 *   condition  and / or / not, parentheses, `1 of sel*`, `any of sel*`, `all of sel*`, `1 of them`, `all of them`,
 *              list of conditions (OR); aggregation `<cond> | count() [by f] > N` → threshold,
 *              `<cond> | count(field) [by f] > N` → distinct (operators > and >=; timeframe → window_s).
 * Unsupported (reported): base64 / base64offset / utf16* / wide / expand / fieldref modifiers, `near`,
 *   aggregations other than count, `<`/`<=`/`=` aggregation operators, `N of` with N > 1, correlation rules,
 *   Sigma collections with `action: global`.
 */
const yaml = require('./yaml');
const { checkRegex } = require('./saferegex');

const FIELD_MAP = {
  image: 'process', newprocessname: 'process', processname: 'process',
  parentimage: 'parent_process', parentprocessname: 'parent_process',
  commandline: 'cmdline', processcommandline: 'cmdline',
  targetusername: 'target_user',
  subjectusername: 'user', user: 'user', username: 'user', accountname: 'user',
  ipaddress: 'src_ip', sourceip: 'src_ip', src_ip: 'src_ip', clientip: 'src_ip', 'c-ip': 'src_ip', sourceaddress: 'src_ip',
  destinationip: 'dst_ip', dst_ip: 'dst_ip', destinationaddress: 'dst_ip',
  sourceport: 'src_port', destinationport: 'dst_port', dst_port: 'dst_port',
  eventid: 'event_code', event_id: 'event_code',
  queryname: 'dns_query', query: 'dns_query',
  hashes: 'hash', hash: 'hash', md5: 'hash', sha1: 'hash', sha256: 'hash',
  computer: 'host', computername: 'host', hostname: 'host', workstationname: 'fields.WorkstationName',
  'cs-method': 'http_method', method: 'http_method', 'sc-status': 'http_status', status_code: 'http_status',
  'c-uri': 'url', 'cs-uri': 'url', 'cs-uri-query': 'url', 'cs-uri-stem': 'url', url: 'url', uri: 'url',
  'c-useragent': 'user_agent', 'cs-user-agent': 'user_agent', useragent: 'user_agent', user_agent: 'user_agent',
  protocol: 'proto', message: 'message', keywords: 'raw',
};

function mapField(name) {
  const k = String(name).toLowerCase();
  if (Object.prototype.hasOwnProperty.call(FIELD_MAP, k)) return FIELD_MAP[k];
  return `fields.${name}`;
}

// logsource → native conditions. Each entry: list of leaf conditions (ANDed).
const LOGSOURCE_MAP = {
  product: {
    windows: [{ field: 'src_type', op: 'eq', value: 'windows' }],
    linux: [{ field: 'src_type', op: 'eq', value: 'linux' }],
    fortigate: [{ field: 'src_type', op: 'eq', value: 'fortigate' }],
    fortios: [{ field: 'src_type', op: 'eq', value: 'fortigate' }],
    cisco: [{ field: 'src_type', op: 'eq', value: 'cisco' }],
    m365: [{ field: 'src_type', op: 'eq', value: 'm365' }],
    azure: [{ field: 'src_type', op: 'eq', value: 'm365' }],
    microsoft365: [{ field: 'src_type', op: 'eq', value: 'm365' }],
    nginx: [{ field: 'src_type', op: 'eq', value: 'nginx' }],
    apache: [{ field: 'category', op: 'eq', value: 'web' }],
  },
  category: {
    process_creation: [{ field: 'action', op: 'eq', value: 'process-start' }],
    network_connection: [{ field: 'category', op: 'eq', value: 'network' }],
    firewall: [{ field: 'category', op: 'eq', value: 'network' }],
    dns: [{ field: 'category', op: 'eq', value: 'dns' }],
    dns_query: [{ field: 'category', op: 'eq', value: 'dns' }],
    webserver: [{ field: 'category', op: 'eq', value: 'web' }],
    proxy: [{ field: 'category', op: 'eq', value: 'web' }],
    file_event: [{ field: 'category', op: 'eq', value: 'file' }],
    file_access: [{ field: 'category', op: 'eq', value: 'file' }],
    file_delete: [{ field: 'category', op: 'eq', value: 'file' }],
    registry_event: [{ field: 'category', op: 'eq', value: 'registry' }],
    registry_set: [{ field: 'category', op: 'eq', value: 'registry' }],
    registry_add: [{ field: 'category', op: 'eq', value: 'registry' }],
    registry_delete: [{ field: 'category', op: 'eq', value: 'registry' }],
    process_access: [{ field: 'event_code', op: 'eq', value: '10' }],
    image_load: [{ field: 'event_code', op: 'eq', value: '7' }],
    driver_load: [{ field: 'event_code', op: 'eq', value: '6' }],
    create_remote_thread: [{ field: 'event_code', op: 'eq', value: '8' }],
    ps_script: [{ field: 'event_code', op: 'eq', value: '4104' }],
    ps_module: [{ field: 'event_code', op: 'eq', value: '4103' }],
    authentication: [{ field: 'category', op: 'eq', value: 'authentication' }],
    antivirus: [{ field: 'action', op: 'eq', value: 'av-detection' }],
  },
  service: {
    security: [], system: [], sysmon: [], powershell: [], 'powershell-classic': [], application: [],
    'taskscheduler': [], 'windefend': [],
    sshd: [{ field: 'src_type', op: 'eq', value: 'linux' }],
    auth: [{ field: 'src_type', op: 'eq', value: 'linux' }],
    sudo: [{ field: 'src_type', op: 'eq', value: 'linux' }],
    syslog: [], auditd: [{ field: 'src_type', op: 'eq', value: 'linux' }],
    signinlogs: [{ field: 'src_type', op: 'eq', value: 'm365' }],
    auditlogs: [{ field: 'src_type', op: 'eq', value: 'm365' }],
    audit: [{ field: 'src_type', op: 'eq', value: 'm365' }],
    exchange: [{ field: 'src_type', op: 'eq', value: 'm365' }],
  },
};

const LEVELS = { informational: 0, info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const UNSUPPORTED_MODS = new Set(['base64', 'base64offset', 'utf16le', 'utf16be', 'utf16', 'wide', 'expand', 'fieldref']);

class Unsupported extends Error {}

// ---------- wildcard handling (Sigma: * any, ? one char, \ escapes * ? \)
function parseWildcards(s) {
  // → tokens: {lit: string} | {star} | {q}
  const toks = []; let lit = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\' && (s[i + 1] === '*' || s[i + 1] === '?' || s[i + 1] === '\\')) { lit += s[i + 1]; i++; continue; }
    if (c === '*' || c === '?') { if (lit) toks.push({ lit }); lit = ''; toks.push(c === '*' ? { star: true } : { q: true }); continue; }
    lit += c;
  }
  if (lit) toks.push({ lit });
  return toks;
}
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** plain Sigma value (no string modifier) → leaf condition */
function valueLeaf(field, v) {
  if (v === null) return { field, op: 'exists', value: false };
  if (typeof v !== 'string') return { field, op: 'eq', value: String(v) };
  const t = parseWildcards(v);
  const hasWild = t.some((x) => x.star || x.q);
  if (!hasWild) return { field, op: 'eq', value: t.length ? t[0].lit : '' };
  if (t.every((x) => x.star)) return { field, op: 'exists', value: true };
  const qs = t.some((x) => x.q);
  const lits = t.filter((x) => x.lit);
  if (!qs && lits.length === 1) {
    const s0 = t[0].star, sN = t[t.length - 1].star;
    const core = lits[0].lit;
    if (t.length === 3 && s0 && sN) return { field, op: 'contains', value: core };
    if (t.length === 2 && s0) return { field, op: 'endswith', value: core };
    if (t.length === 2 && sN) return { field, op: 'startswith', value: core };
  }
  const re = '^' + t.map((x) => (x.star ? '.*' : x.q ? '.' : reEsc(x.lit))).join('') + '$';
  return { field, op: 're', value: re };
}

/** value under contains/startswith/endswith: inner wildcards → regex */
function modLeaf(field, op, v) {
  if (v === null) throw new Unsupported(`null value with |${op} on ${field}`);
  const s = String(v);
  const t = parseWildcards(s);
  if (!t.some((x) => x.star || x.q)) return { field, op, value: t.length ? t[0].lit : '' };
  const body = t.map((x) => (x.star ? '.*' : x.q ? '.' : reEsc(x.lit))).join('');
  const re = op === 'contains' ? body : op === 'startswith' ? '^' + body : body + '$';
  return { field, op: 're', value: re };
}

function windash(v) {
  const s = String(v);
  const out = new Set([s]);
  // swap a leading dash of any option token with '/', en-dash, em-dash, horizontal bar
  for (const alt of ['/', '–', '—', '―']) out.add(s.replace(/(^|\s)-/g, `$1${alt}`));
  return [...out];
}

/** one `Field|mods: values` entry → native condition */
function fieldCondition(rawKey, value, warnings) {
  const parts = String(rawKey).split('|');
  const fname = parts[0];
  const mods = parts.slice(1).map((m) => m.toLowerCase());
  for (const m of mods) if (UNSUPPORTED_MODS.has(m)) throw new Unsupported(`modifier |${m} (field ${fname})`);
  const known = new Set(['contains', 'startswith', 'endswith', 'all', 're', 'cidr', 'gt', 'gte', 'lt', 'lte', 'exists', 'windash', 'cased', 'i', 'm', 's']);
  for (const m of mods) if (!known.has(m)) throw new Unsupported(`unknown modifier |${m} (field ${fname})`);
  if (!fname) throw new Unsupported('keyword search with modifiers (|…) without a field name');
  const field = mapField(fname);
  if (mods.includes('cased')) warnings.push(`|cased on ${fname}: the engine compares case-insensitively`);
  let vals = Array.isArray(value) ? value : [value];
  if (!vals.length) throw new Unsupported(`empty value list for ${fname}`);
  if (vals.some((v) => v !== null && typeof v === 'object')) throw new Unsupported(`nested map/list value for ${fname}`);
  if (mods.includes('windash')) vals = vals.flatMap(windash);
  const all = mods.includes('all');

  let leaves;
  const strOp = ['contains', 'startswith', 'endswith'].find((m) => mods.includes(m));
  if (mods.includes('re')) {
    if (mods.includes('m') || mods.includes('s')) throw new Unsupported(`regex flags |m/|s on ${fname}`);
    leaves = vals.map((v) => {
      // the engine is case-insensitive already: a leading (?i) is dropped; other inline flags are not supported by JS
      let p = String(v).replace(/^\(\?i\)/, '');
      if (/^\(\?[a-z]+\)/.test(p)) throw new Unsupported(`inline regex flags ${p.match(/^\(\?[a-z]+\)/)[0]} on ${fname}`);
      p = p.replace(/\(\?P</g, '(?<'); // Python-style named groups → JavaScript
      try { new RegExp(p, 'i'); } catch (e) { throw new Unsupported(`regex on ${fname} is not valid in JavaScript: ${e.message}`); }
      try { checkRegex(p); } catch (e) { throw new Unsupported(`regex on ${fname} refused: ${e.message}`); }
      return { field, op: 're', value: p };
    });
  } else if (mods.includes('cidr')) {
    leaves = [{ field, op: 'cidr', value: vals.map(String) }];
    if (all) throw new Unsupported(`|cidr|all on ${fname}`);
  } else if (['gt', 'gte', 'lt', 'lte'].some((m) => mods.includes(m))) {
    const op = ['gt', 'gte', 'lt', 'lte'].find((m) => mods.includes(m));
    leaves = vals.map((v) => {
      if (!Number.isFinite(Number(v))) throw new Unsupported(`non-numeric |${op} value on ${fname}`);
      return { field, op, value: Number(v) };
    });
  } else if (mods.includes('exists')) {
    if (vals.length !== 1 || typeof vals[0] !== 'boolean') throw new Unsupported(`|exists needs true/false on ${fname}`);
    leaves = [{ field, op: 'exists', value: vals[0] }];
  } else if (strOp) {
    leaves = vals.map((v) => modLeaf(field, strOp, v));
  } else {
    leaves = vals.map((v) => valueLeaf(field, v));
  }
  if (leaves.length === 1) return leaves[0];
  if (all) return { all: leaves };
  // merge same-op literal leaves into one any-of leaf for speed
  const simple = leaves.every((l) => l.field === field && l.op === leaves[0].op && ['eq', 'contains', 'startswith', 'endswith', 're'].includes(l.op) && !Array.isArray(l.value));
  if (simple) return { field, op: leaves[0].op === 'eq' ? 'in' : leaves[0].op, value: leaves.map((l) => l.value) };
  return { any: leaves };
}

function selectionToMatch(name, sel, warnings) {
  if (Array.isArray(sel)) {
    if (!sel.length) throw new Unsupported(`empty selection ${name}`);
    if (sel.every((x) => typeof x === 'string' || typeof x === 'number')) {
      // keyword list → full-text on raw (OR)
      const leaves = sel.map((k) => modLeaf('raw', 'contains', String(k).replace(/^\*|\*$/g, '')));
      warnings.push(`selection ${name}: keywords are matched as substrings of the raw event`);
      return leaves.length === 1 ? leaves[0] : { any: leaves };
    }
    if (sel.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
      const alts = sel.map((m, k) => selectionToMatch(`${name}[${k}]`, m, warnings));
      return alts.length === 1 ? alts[0] : { any: alts };
    }
    throw new Unsupported(`selection ${name} mixes keywords and maps`);
  }
  if (sel && typeof sel === 'object') {
    const keys = Object.keys(sel);
    if (!keys.length) throw new Unsupported(`empty selection ${name}`);
    const conds = keys.map((k) => fieldCondition(k, sel[k], warnings));
    return conds.length === 1 ? conds[0] : { all: conds };
  }
  if (typeof sel === 'string' || typeof sel === 'number') {
    warnings.push(`selection ${name}: keyword matched as substring of the raw event`);
    return modLeaf('raw', 'contains', String(sel));
  }
  throw new Unsupported(`selection ${name} has an unsupported shape`);
}

// ---------- condition parser
function tokenize(s) {
  const toks = [];
  const re = /\s*(\(|\)|\||[A-Za-z0-9_*.\-]+|>=|<=|>|<|=|\S)/y;
  let m;
  while (re.lastIndex < s.length && (m = re.exec(s))) toks.push(m[1]);
  return toks.filter((t) => t !== '');
}

function parseCondition(expr, selNames) {
  const toks = tokenize(expr);
  let p = 0;
  const peek = () => toks[p];
  const next = () => toks[p++];
  const lower = (t) => (t || '').toLowerCase();

  function pattern(pat) {
    if (lower(pat) === 'them') return selNames.filter((n) => !n.startsWith('_'));
    if (pat.indexOf('*') >= 0) {
      const re = new RegExp('^' + pat.split('*').map(reEsc).join('.*') + '$');
      return selNames.filter((n) => re.test(n));
    }
    if (!selNames.includes(pat)) throw new Unsupported(`condition references unknown selection "${pat}"`);
    return [pat];
  }

  function primary() {
    const t = next();
    if (t === undefined) throw new Unsupported('condition ends unexpectedly');
    if (t === '(') {
      const e = orExpr();
      if (next() !== ')') throw new Unsupported('unbalanced parentheses in condition');
      return e;
    }
    if (lower(t) === 'not') return { not: primary() };
    if (/^\d+$/.test(t) || lower(t) === 'all' || lower(t) === 'any') {
      if (lower(peek()) !== 'of') {
        if (lower(t) === 'all' || lower(t) === 'any') throw new Unsupported(`"${t}" without "of"`);
        return { sel: t };
      }
      next();
      const pat = next();
      if (!pat) throw new Unsupported(`"${t} of" without a target`);
      const names = pattern(pat);
      if (!names.length) throw new Unsupported(`"${t} of ${pat}" matches no selection`);
      if (lower(t) === 'all') return { and: names.map((n) => ({ sel: n })) };
      if (t === '1' || lower(t) === 'any') return { or: names.map((n) => ({ sel: n })) };
      throw new Unsupported(`"${t} of ${pat}" (only 1/any/all of … are supported)`);
    }
    if (lower(t) === 'near') throw new Unsupported('"near" correlation');
    if (/^[A-Za-z0-9_.\-*]+$/.test(t) && !['and', 'or', ')'].includes(lower(t))) {
      if (!selNames.includes(t)) throw new Unsupported(`condition references unknown selection "${t}"`);
      return { sel: t };
    }
    throw new Unsupported(`unexpected token "${t}" in condition`);
  }
  function andExpr() {
    const items = [primary()];
    while (lower(peek()) === 'and') { next(); items.push(primary()); }
    return items.length === 1 ? items[0] : { and: items };
  }
  function orExpr() {
    const items = [andExpr()];
    while (lower(peek()) === 'or') { next(); items.push(andExpr()); }
    return items.length === 1 ? items[0] : { or: items };
  }
  const ast = orExpr();
  if (p < toks.length) throw new Unsupported(`unexpected "${toks.slice(p).join(' ')}" in condition`);
  return ast;
}

function astToMatch(ast, sels) {
  if (ast.sel) return sels[ast.sel];
  if (ast.not) return { none: [astToMatch(ast.not, sels)] };
  if (ast.and) return { all: ast.and.map((a) => astToMatch(a, sels)) };
  if (ast.or) return { any: ast.or.map((a) => astToMatch(a, sels)) };
  throw new Unsupported('bad condition');
}

function parseAggregation(agg) {
  // count() by f1, f2 > 10   |   count(Field) by f > 5
  const m = agg.trim().match(/^(\w+)\s*\(\s*([^)]*)\s*\)\s*(?:by\s+([\w.,\s-]+?))?\s*(>=|<=|>|<|==|=)\s*(\d+)\s*$/i);
  if (!m) throw new Unsupported(`aggregation "${agg.trim()}"`);
  const [, fn, arg, by, op, n] = m;
  if (fn.toLowerCase() !== 'count') throw new Unsupported(`aggregation function ${fn}() (only count() is supported)`);
  if (op !== '>' && op !== '>=') throw new Unsupported(`aggregation operator "${op}" (only > and >= are supported)`);
  const N = Number(n) + (op === '>' ? 1 : 0);
  return { field: arg.trim() || null, by: by ? by.split(',').map((s) => s.trim()).filter(Boolean) : [], count: N };
}

function parseTimeframe(tf) {
  const m = String(tf).trim().match(/^(\d+)\s*([smhdM])$/);
  if (!m) throw new Unsupported(`timeframe "${tf}"`);
  const mult = { s: 1, m: 60, h: 3600, d: 86400, M: 30 * 86400 }[m[2]];
  return Number(m[1]) * mult;
}

function shortId(s) { return String(s || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 8).toUpperCase(); }

function convertDoc(doc, opts = {}) {
  const warnings = [];
  const errors = [];
  try {
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Unsupported('document is not a YAML map');
    if (doc.action) throw new Unsupported(`Sigma collection action "${doc.action}"`);
    if (doc.correlation) throw new Unsupported('Sigma correlation rules');
    if (!doc.title) throw new Unsupported('missing title');
    const det = doc.detection;
    if (!det || typeof det !== 'object') throw new Unsupported('missing detection');
    if (det.condition === undefined) throw new Unsupported('missing detection.condition');

    // logsource
    const pre = [];
    const ls = doc.logsource || {};
    for (const key of ['product', 'category', 'service']) {
      const v = ls[key];
      if (v === undefined || v === null) continue;
      const mapped = LOGSOURCE_MAP[key][String(v).toLowerCase()];
      if (mapped === undefined) warnings.push(`logsource ${key}: ${v} is not mapped — the rule is not restricted by it`);
      else pre.push(...mapped.map((c) => Object.assign({}, c)));
    }
    // drop duplicate src_type constraints
    const seen = new Set();
    const filters = pre.filter((c) => { const k = `${c.field}=${c.value}`; if (seen.has(k)) return false; seen.add(k); return true; });

    // selections
    const sels = {};
    const names = Object.keys(det).filter((k) => k !== 'condition' && k !== 'timeframe');
    for (const n of names) {
      try { sels[n] = selectionToMatch(n, det[n], warnings); } catch (e) { if (e instanceof Unsupported) errors.push(e.message); else throw e; }
    }
    if (errors.length) return { ok: false, errors, warnings };

    // condition(s)
    const conds = Array.isArray(det.condition) ? det.condition : [det.condition];
    let agg = null;
    const matches = conds.map((c) => {
      const s = String(c);
      const bar = s.indexOf('|');
      if (bar >= 0) {
        if (conds.length > 1) throw new Unsupported('aggregation inside a list of conditions');
        agg = parseAggregation(s.slice(bar + 1));
        return astToMatch(parseCondition(s.slice(0, bar), names), sels);
      }
      return astToMatch(parseCondition(s, names), sels);
    });
    let match = matches.length === 1 ? matches[0] : { any: matches };
    // flatten into {all: [...filters, match]}
    const all = filters.slice();
    if (match.field !== undefined) all.push(match);
    else if (match.all && !match.any && !match.none) all.push(...match.all);
    else all.push(match);
    match = { all };

    const tags = Array.isArray(doc.tags) ? doc.tags.map(String) : [];
    const mitre = tags.filter((t) => /^attack\.t\d{4}/i.test(t)).map((t) => t.slice(7).toUpperCase());
    const tactics = tags.filter((t) => /^attack\.[a-z_-]+$/i.test(t) && !/^attack\.(g|s)\d{4}$/i.test(t)).map((t) => t.slice(7).replace(/_/g, '-'));
    const level = String(doc.level || 'medium').toLowerCase();
    if (!(level in LEVELS)) warnings.push(`unknown level "${doc.level}" → medium`);

    const rule = {
      id: opts.id || `SIGMA-${shortId(doc.id) || shortId(doc.title)}`,
      name: String(doc.title),
      enabled: opts.enabled !== undefined ? !!opts.enabled : true,
      severity: LEVELS[level] !== undefined ? LEVELS[level] : 2,
      mitre, tactic: tactics[0] || '',
      description: doc.description ? String(doc.description).trim().split('\n')[0] : '',
      author: doc.author ? String(doc.author) : '',
      version: 1,
      source: 'sigma', sigma_id: doc.id ? String(doc.id) : '', sigma_status: doc.status ? String(doc.status) : '',
      falsepositives: Array.isArray(doc.falsepositives) ? doc.falsepositives.map(String) : [],
      references: Array.isArray(doc.references) ? doc.references.map(String) : [],
      type: 'single',
      match,
      suppress_s: opts.suppress_s !== undefined ? opts.suppress_s : 3600,
      group_by: ['host'],
      fields_in_alert: [],
    };
    if (Array.isArray(doc.fields)) rule.fields_in_alert = doc.fields.map(mapField);
    if (!rule.fields_in_alert.length) {
      const used = new Set();
      (function walk(m) { if (!m) return; if (m.field) { if (m.field !== 'src_type' && m.field !== 'raw') used.add(m.field); return; } for (const k of ['all', 'any', 'none']) (m[k] || []).forEach(walk); })(match);
      rule.fields_in_alert = ['host', 'user', ...[...used].filter((f) => f !== 'host' && f !== 'user')].slice(0, 8);
    }
    if (agg) {
      const tf = det.timeframe || doc.timeframe;
      if (!tf) throw new Unsupported('aggregation without timeframe');
      rule.window_s = parseTimeframe(tf);
      rule.group_by = agg.by.map(mapField);
      if (agg.field) {
        if (agg.count < 2) throw new Unsupported('count(field) threshold below 2');
        rule.type = 'distinct';
        rule.distinct_field = mapField(agg.field);
        rule.distinct_count = agg.count;
      } else {
        rule.type = 'threshold';
        rule.count = Math.max(1, agg.count);
      }
      rule.suppress_s = opts.suppress_s !== undefined ? opts.suppress_s : rule.window_s;
    } else if (det.timeframe) warnings.push('timeframe ignored (no aggregation in condition)');
    return { ok: true, rule, warnings };
  } catch (e) {
    if (e instanceof Unsupported) return { ok: false, errors: [...errors, `unsupported: ${e.message}`], warnings };
    if (e instanceof yaml.YamlError) return { ok: false, errors: [e.message], warnings };
    throw e;
  }
}

function convertSigmaAll(input, opts = {}) {
  let docs;
  try { docs = typeof input === 'string' ? yaml.parseAll(input) : [input]; } catch (e) {
    if (e instanceof yaml.YamlError) return [{ ok: false, errors: [e.message], warnings: [] }];
    throw e;
  }
  return docs.map((d, k) => convertDoc(d, Object.assign({}, opts, docs.length > 1 && opts.id ? { id: `${opts.id}-${k + 1}` } : {})));
}

function convertSigma(input, opts = {}) {
  const all = convertSigmaAll(input, opts);
  if (all.length !== 1) return { ok: false, errors: [`expected one Sigma document, got ${all.length}`], warnings: [] };
  return all[0];
}

module.exports = { convertSigma, convertSigmaAll, mapField, FIELD_MAP, LOGSOURCE_MAP };
