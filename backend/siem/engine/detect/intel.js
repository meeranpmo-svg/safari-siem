// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * IOC (threat-intel) lists for the `intel` rule op.
 *
 *   createIntel({ dir, log, pollMs = 15000, watch = true }) → { match(list, value), lookup(value), reload(), add(list, values),
 *                                                            lists(), stats(), close() }
 *
 * Files: <data>/intel/*.txt and *.csv (one indicator per line; `#` comments and blank lines ignored).
 *   .txt  → indicator per line (anything after the first whitespace is kept as the description)
 *   .csv  → indicator,type?,description?  (header row allowed: a first line whose first cell is not an indicator is skipped)
 * The indicator type is auto-detected (or taken from the csv `type` column: ip|cidr|domain|hash|url):
 *   IPv4/IPv6 → ip, a.b.c.d/nn or v6/nn → cidr, 32/40/64 hex → hash (md5/sha1/sha256), URL → its host (domain/ip), else domain.
 * List names usable in rules ({"op":"intel","value":"<name>"}):
 *   "ip"      every ip + cidr indicator of every file          "domain"  every domain (a listed domain also matches its subdomains)
 *   "hash"    every hash                                          "any"     all of the above
 *   "<file>"  one file only (basename without extension, e.g. "bad-domains")
 *   allow-* / internal-* files (e.g. internal-mail-domains.txt) are reference lists: addressable by name only, never
 *   merged into the ip/domain/hash/any IOC aggregates.
 * Event values are normalised before lookup: URLs are reduced to their host, hosts lose a trailing dot and port,
 * Sysmon-style "SHA256=…,MD5=…" hash strings are split into their hex parts.
 * Hot reload: the directory is polled every pollMs (mtime/size of every file) and fs.watch is used when available.
 */
const fs = require('fs');
const path = require('path');
const { parseIP, createCidrSet } = require('./ip');

const HASH_RE = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
// Files named allow-*.txt|csv or internal-*.txt|csv are reference lists (e.g. internal-mail-domains.txt used by
// SENTRA-EXO-002 to recognise internal forwarding targets): usable by name in rules, but NOT part of ip/domain/hash/any.
const REFERENCE_LIST = /^(allow|internal)[-_]/i;
const HEX_TOKEN = /[0-9a-f]{32,64}/gi;

function hostOf(v) {
  let s = String(v).trim().toLowerCase();
  if (!s) return '';
  const scheme = s.indexOf('://');
  if (scheme >= 0) s = s.slice(scheme + 3);
  const cut = s.search(/[/?#]/);
  if (cut >= 0) s = s.slice(0, cut);
  const at = s.lastIndexOf('@');
  if (at >= 0) s = s.slice(at + 1);
  if (s.startsWith('[')) { const e = s.indexOf(']'); return e > 0 ? s.slice(1, e) : s; }
  const colon = s.indexOf(':');
  if (colon >= 0 && s.indexOf(':', colon + 1) < 0) s = s.slice(0, colon); // host:port (not IPv6)
  if (s.endsWith('.')) s = s.slice(0, -1);
  return s;
}

function classify(ind, typeHint) {
  let s = String(ind || '').trim();
  if (!s) return null;
  const t = String(typeHint || '').trim().toLowerCase();
  if (t === 'url' || /^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    s = hostOf(s);
    if (!s) return null;
    return parseIP(s) ? { type: 'ip', value: s } : { type: 'domain', value: s };
  }
  if (t === 'hash' || t === 'md5' || t === 'sha1' || t === 'sha256' || (!t && HASH_RE.test(s))) {
    return HASH_RE.test(s) ? { type: 'hash', value: s.toLowerCase() } : null;
  }
  if (s.indexOf('/') > 0) {
    try { createCidrSet([s]); return { type: 'cidr', value: s }; } catch { return null; }
  }
  if (parseIP(s)) return { type: 'ip', value: s };
  s = s.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (/^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/.test(s) && s.indexOf('.') > 0) return { type: 'domain', value: s };
  return null;
}

function splitCsv(line) {
  const out = []; let cur = ''; let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { out.push(cur); cur = ''; } else cur += c;
  }
  out.push(cur);
  return out.map((x) => x.trim());
}

/** Parse one file's text → [{type, value, desc}] */
function parseIntelText(text, isCsv) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  let first = true;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (isCsv) {
      const cells = splitCsv(line);
      const ind = classify(cells[0], cells[1] && /^(ip|cidr|domain|hash|url|md5|sha1|sha256)$/i.test(cells[1]) ? cells[1] : '');
      if (!ind) { if (!first) out.push({ invalid: cells[0] }); first = false; continue; }
      ind.desc = cells.length > 2 ? cells.slice(2).join(', ') : (cells[1] && !/^(ip|cidr|domain|hash|url|md5|sha1|sha256)$/i.test(cells[1]) ? cells[1] : '');
      out.push(ind);
    } else {
      const m = line.match(/^(\S+)\s*(.*)$/);
      const ind = classify(m[1]);
      if (!ind) { out.push({ invalid: m[1] }); continue; }
      ind.desc = m[2] || '';
      out.push(ind);
    }
    first = false;
  }
  return out;
}

function buildList(name, entries) {
  const ips = []; const domains = new Map(); const hashes = new Map();
  for (const e of entries) {
    if (e.type === 'ip' || e.type === 'cidr') ips.push(e.value);
    else if (e.type === 'domain') domains.set(e.value, e.desc || '');
    else if (e.type === 'hash') hashes.set(e.value, e.desc || '');
  }
  return { name, ipSet: createCidrSet(ips), ipCount: ips.length, domains, hashes };
}

function matchDomain(domains, host) {
  if (!host || !domains.size) return false;
  if (domains.has(host)) return true;
  let i = host.indexOf('.');
  while (i >= 0) {
    const parent = host.slice(i + 1);
    if (parent.indexOf('.') < 0 && !domains.has(parent)) return false; // do not walk to a bare TLD unless listed
    if (domains.has(parent)) return true;
    i = host.indexOf('.', i + 1);
  }
  return false;
}

function matchList(L, value) {
  if (value === undefined || value === null) return false;
  const s = typeof value === 'string' ? value : String(value);
  if (!s) return false;
  if (L.ipCount && L.ipSet.has(s)) return true;
  if (L.hashes.size) {
    if (L.hashes.has(s.toLowerCase())) return true;
    if (s.length > 64 || s.indexOf('=') >= 0) {
      const toks = s.match(HEX_TOKEN);
      if (toks) for (const t of toks) if (L.hashes.has(t.toLowerCase())) return true;
    }
  }
  if (L.domains.size || L.ipCount) {
    const h = hostOf(s);
    if (h !== s && L.ipCount && L.ipSet.has(h)) return true;
    if (L.domains.size && matchDomain(L.domains, h)) return true;
  }
  return false;
}

function createIntel(opts = {}) {
  const dir = opts.dir;
  const log = opts.log || { info() {}, warn() {}, error() {} };
  const pollMs = opts.pollMs || 15000;
  let lists = new Map();            // name → built list
  let agg = { ip: null, domain: null, hash: null, any: null };
  let sig = '';
  let loadedAt = 0; let invalid = 0;
  const extra = new Map();          // lists added at runtime via add()
  const hits = new Map();
  let timer = null; let watcher = null;

  function rebuild(fileEntries) {
    const next = new Map();
    const all = [];
    const add = (name, entries) => {
      next.set(name, buildList(name, entries));
      if (!REFERENCE_LIST.test(name)) all.push(...entries); // allow-/internal- lists are reference data, not IOCs
    };
    for (const [name, entries] of fileEntries) add(name, entries);
    for (const [name, entries] of extra) add(name, entries);
    lists = next;
    agg = {
      ip: buildList('ip', all.filter((e) => e.type === 'ip' || e.type === 'cidr')),
      domain: buildList('domain', all.filter((e) => e.type === 'domain')),
      hash: buildList('hash', all.filter((e) => e.type === 'hash')),
    };
    agg.any = buildList('any', all);
  }

  let lastFiles = [];
  function scan() {
    if (!dir) return [];
    let names = [];
    try { names = fs.readdirSync(dir).filter((n) => /\.(txt|csv)$/i.test(n)).sort(); } catch { return []; }
    return names.map((n) => {
      const p = path.join(dir, n);
      try { const st = fs.statSync(p); return { n, p, sig: `${n}:${st.size}:${st.mtimeMs}` }; } catch { return null; }
    }).filter(Boolean);
  }

  function reload(force) {
    const files = scan();
    const s = files.map((f) => f.sig).join('|');
    if (!force && s === sig && loadedAt) return false;
    const fileEntries = [];
    invalid = 0;
    for (const f of files) {
      try {
        const entries = parseIntelText(fs.readFileSync(f.p, 'utf8'), /\.csv$/i.test(f.n));
        const good = entries.filter((e) => !e.invalid);
        invalid += entries.length - good.length;
        fileEntries.push([f.n.replace(/\.(txt|csv)$/i, ''), good]);
      } catch (e) { log.warn('intel file unreadable', { file: f.n, err: e.message }); }
    }
    rebuild(fileEntries);
    lastFiles = fileEntries;
    sig = s; loadedAt = Date.now();
    log.info('intel loaded', { files: files.length, ip: agg.ip.ipCount, domain: agg.domain.domains.size, hash: agg.hash.hashes.size, invalid });
    return true;
  }

  function resolve(name) {
    const n = String(name || 'any').toLowerCase();
    if (n === 'ip' || n === 'cidr') return agg.ip;
    if (n === 'domain' || n === 'domains') return agg.domain;
    if (n === 'hash' || n === 'hashes') return agg.hash;
    if (n === 'any' || n === 'all' || n === 'ioc') return agg.any;
    return lists.get(name) || lists.get(n) || null;
  }

  function match(name, value) {
    const L = resolve(name);
    if (!L) return false;
    const ok = matchList(L, value);
    if (ok) hits.set(L.name, (hits.get(L.name) || 0) + 1);
    return ok;
  }

  /** Which lists contain this value (for enrichment / the UI). */
  function lookup(value) {
    const out = [];
    for (const [name, L] of lists) if (matchList(L, value)) out.push(name);
    return out;
  }

  function add(name, values) {
    const entries = [];
    for (const v of values || []) { const c = classify(v); if (c) entries.push(c); }
    extra.set(name, entries);
    rebuild(lastFiles);
    return entries.length;
  }

  reload(true);
  if (dir && opts.watch !== false) {
    timer = setInterval(() => { try { reload(false); } catch (e) { log.warn('intel reload failed', { err: e.message }); } }, pollMs);
    if (timer.unref) timer.unref();
    try {
      let pending = null;
      watcher = fs.watch(dir, () => {
        if (pending) return;
        pending = setTimeout(() => { pending = null; try { reload(false); } catch { /* next poll retries */ } }, 250);
        if (pending.unref) pending.unref();
      });
      watcher.on('error', () => { try { watcher.close(); } catch { /* ignore */ } watcher = null; });
    } catch { watcher = null; }
  }

  return {
    match, lookup, reload: () => reload(true), add,
    lists: () => [...lists.values()].map((L) => ({ name: L.name, ip: L.ipCount, domain: L.domains.size, hash: L.hashes.size })),
    stats: () => ({
      loaded_at: loadedAt, invalid_lines: invalid,
      ip: agg.ip.ipCount, domain: agg.domain.domains.size, hash: agg.hash.hashes.size,
      lists: lists.size, hits: Object.fromEntries(hits),
    }),
    close() { if (timer) clearInterval(timer); if (watcher) try { watcher.close(); } catch { /* ignore */ } },
  };
}

module.exports = { createIntel, parseIntelText, classify, hostOf, matchDomain };
