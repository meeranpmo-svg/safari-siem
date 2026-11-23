// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Threat-intel feeds: download indicator feeds on a schedule and keep them as files in the intel folder, where
 * detect/intel.js picks them up within 15 s (same lists, same rule op "intel"). Before this the lists only changed when
 * someone copied files onto the server by hand.
 *   Built-in feeds (all OFF until an administrator switches them on - nothing is downloaded implicitly):
 *     abuse.ch Feodo Tracker (botnet C2 IPs) · abuse.ch URLhaus (malware URLs, recent) · abuse.ch ThreatFox (IOC host
 *     file) · abuse.ch MalwareBazaar (malware SHA-256, recent) · Spamhaus DROP (hijacked netblocks)
 *   Own feeds: any https URL (a MISP / OpenCTI export, the firewall vendor's list, a CERT-SA / NCA list published on an
 *   internal web server), optional header for an API key (write-only: kept in secrets.json, never returned or logged).
 *   Upload: a list received by e-mail is pasted / uploaded from the page (offline servers).
 * Formats read: one indicator per line (# and ; comments), "0.0.0.0 domain" host files, CSV (first column, or a named
 * column), NDJSON / JSON lines ({"ip"|"cidr"|"domain"|"url"|"sha256_hash"|"ioc_value":…}). Every value goes through
 * intel.js classify(); private, loopback and link-local addresses are dropped (a feed must never make an internal
 * address "malicious"). At most 500 000 indicators / 30 MB per feed. A failed download keeps the last good file.
 * Outbound: https only, 60 s timeout, no redirect to http; uses HTTPS_PROXY when the engine runs with
 * NODE_USE_ENV_PROXY=1 (install/netops-setup.sh --proxy). Every change and run is audited (intel.feed.*).
 *   createIntelFeeds({ dir, state, config, log, fetch?, now?, audit?, secretsPath? })
 *     .list() .put(feed, by) .remove(id, by) .setEnabled(id, on, by) .run(id?, by) .upload(name, text, by) .start() .stop()
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { classify } = require('./intel');

const PRESETS = [
  { id: 'abusech-feodo', name: 'abuse.ch Feodo Tracker - botnet C2 IPs', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', interval_h: 6 },
  { id: 'abusech-urlhaus', name: 'abuse.ch URLhaus - malware URLs (recent)', url: 'https://urlhaus.abuse.ch/downloads/text_recent/', interval_h: 6 },
  { id: 'abusech-threatfox', name: 'abuse.ch ThreatFox - IOC host file', url: 'https://threatfox.abuse.ch/downloads/hostfile/', interval_h: 12 },
  { id: 'abusech-bazaar', name: 'abuse.ch MalwareBazaar - malware SHA-256 (recent)', url: 'https://bazaar.abuse.ch/export/txt/sha256/recent/', interval_h: 12 },
  { id: 'spamhaus-drop', name: 'Spamhaus DROP - hijacked netblocks', url: 'https://www.spamhaus.org/drop/drop_v4.json', interval_h: 24 },
];
const MAX_BYTES = 30 * 1024 * 1024, MAX_IND = 500000;
const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const PRIVATE = /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|fc|fd)/i;
class FeedError extends Error { constructor(code, msg) { super(msg); this.code = code; this.errors = [msg]; } }
const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);

/* text of a feed → indicators (strings classify() accepts), dropping comments and internal addresses */
function parseFeed(text, { column } = {}) {
  const out = new Set();
  let header = null;
  for (const raw of String(text).split(/\r?\n/)) {
    if (out.size >= MAX_IND) break;
    const line = raw.trim();
    if (!line || line[0] === '#' || line[0] === ';' || line.startsWith('//')) continue;
    let vals = [];
    if (line[0] === '{') {   // JSON lines (Spamhaus DROP v4, ThreatFox / MISP exports)
      try { const o = JSON.parse(line); for (const k of ['ioc_value', 'ioc', 'cidr', 'ip', 'domain', 'url', 'sha256_hash', 'sha256', 'md5_hash', 'value']) if (o[k]) { vals.push(String(o[k])); break; } } catch (e) { continue; }
    } else if (/^(0\.0\.0\.0|127\.0\.0\.1)\s+\S/.test(line)) {   // host file
      vals.push(line.split(/\s+/)[1]);
    } else if (line.includes(',') || line.includes(';')) {   // CSV
      const cells = line.split(/[,;]/).map((c) => c.trim().replace(/^"|"$/g, ''));
      if (!header && column) { const i = cells.findIndex((c) => c.toLowerCase() === String(column).toLowerCase()); if (i >= 0) { header = i; continue; } }
      vals.push(cells[header != null ? header : 0]);
    } else vals.push(line.split(/\s+/)[0]);
    for (const v of vals) {
      if (!v) continue;
      const c = classify(v);
      if (!c) continue;
      if ((c.type === 'ip' || c.type === 'cidr') && PRIVATE.test(c.value)) continue;
      if (c.type === 'domain' && /(^|\.)(localhost|local|lan|internal|arpa)$/.test(c.value)) continue;
      out.add(c.value);
    }
  }
  return [...out];
}

function createIntelFeeds({ dir, state, config, log, fetch: fetchImpl, now, audit, secretsPath } = {}) {
  if (!dir) throw new Error('intel feeds need the intel folder');
  const L = log || { info() {}, warn() {}, error() {} }, NOW = now || Date.now;
  const col = state ? state.collection('intel_feeds') : null, mem = new Map();
  const doFetch = fetchImpl || ((u, o) => fetch(u, o));
  const AUD = (action, target, detail) => { try { if (audit) audit({ by: detail.by || 'intel-feeds', role: 'system', ip: '', action, target, detail }); } catch (e) { /* best effort */ } };
  let timer = null, running = null;

  const get = (id) => (col ? col.get(id) : mem.get(id)) || null;
  const save = (f) => (col ? col.put(f) : mem.set(f.id, f));
  const all = () => (col ? col.all() : [...mem.values()]);
  function secrets() { if (!secretsPath) return {}; try { return ((SF.read(secretsPath) || {}).intel_feeds) || {}; } catch (e) { return {}; } }
  function setSecret(id, header) {
    if (!secretsPath) throw new FeedError(500, 'secrets path unknown');
    let sec = {}; try { sec = SF.read(secretsPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    sec.intel_feeds = sec.intel_feeds || {};
    if (header) sec.intel_feeds[id] = header; else delete sec.intel_feeds[id];
    const t = secretsPath + '.tmp-' + crypto.randomBytes(4).toString('hex');
    SF.write(secretsPath, sec); void t;
  }
  function file(id) { return path.join(dir, 'feed-' + id + '.txt'); }
  function view(f) {
    const p = PRESETS.find((x) => x.id === f.id);
    return { id: f.id, name: f.name, url: f.url, preset: !!p, enabled: !!f.enabled, interval_h: f.interval_h, column: f.column || '', header_set: !!secrets()[f.id],
      last_run: f.last_run || null, last_ok: f.last_ok || null, last_error: f.last_error || '', count: f.count || 0, bytes: f.bytes || 0, file: path.basename(file(f.id)) };
  }
  function list() {
    for (const p of PRESETS) if (!get(p.id)) save(Object.assign({ enabled: false }, p));
    return all().sort((a, b) => (!!PRESETS.find((x) => x.id === b.id)) - (!!PRESETS.find((x) => x.id === a.id)) || a.name.localeCompare(b.name)).map(view);
  }
  function httpsUrl(v) {
    let u; try { u = new URL(String(v)); } catch (e) { throw new FeedError(400, 'feed URL is not valid'); }
    const loop = /^(127\.0\.0\.1|localhost|\[::1\])$/.test(u.hostname);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loop)) throw new FeedError(400, 'feed URL must be https://');
    if (u.username || u.password) throw new FeedError(400, 'no login inside the URL - use the header field (kept write-only)');
    return u.href;
  }
  function put(b, by) {
    const id = clean(b.id, 40).toLowerCase() || ('feed-' + crypto.randomBytes(3).toString('hex'));
    if (!ID_RE.test(id)) throw new FeedError(400, 'feed id: 2-40 lowercase letters, digits and dashes');
    const cur = get(id), preset = PRESETS.find((x) => x.id === id);
    const f = Object.assign({}, cur || preset || {}, { id });
    if (!preset) { f.name = clean(b.name || f.name, 120); if (!f.name) throw new FeedError(400, 'name required'); f.url = httpsUrl(b.url || f.url); }
    if (b.interval_h !== undefined) { const v = Number(b.interval_h); if (!Number.isInteger(v) || v < 1 || v > 168) throw new FeedError(400, 'interval: 1-168 hours'); f.interval_h = v; }
    if (!f.interval_h) f.interval_h = 12;
    if (b.column !== undefined) f.column = clean(b.column, 60);
    if (b.enabled !== undefined) f.enabled = b.enabled === true;
    // a feed's header (its API key) belongs to the URL it was entered for: a new URL without a new header drops it
    if (cur && !preset && cur.url && f.url !== cur.url && b.header === undefined) setSecret(id, '');
    if (b.header !== undefined && !preset) { const h = clean(b.header, 600); if (h && !/^[A-Za-z0-9-]{1,60}:\s*\S/.test(h)) throw new FeedError(400, 'header must look like "Authorization: <key>"'); setSecret(id, h); }
    save(f); AUD(cur ? 'intel.feed.update' : 'intel.feed.add', id, { by, url: f.url, was: cur ? cur.url || null : null, enabled: !!f.enabled, header_changed: b.header !== undefined });
    return view(f);
  }
  function remove(id, by) {
    if (PRESETS.find((x) => x.id === id)) throw new FeedError(400, 'a built-in feed is switched off, not removed');
    if (!get(id)) throw new FeedError(404, 'feed not found');
    if (col) col.remove(id); else mem.delete(id);
    try { fs.unlinkSync(file(id)); } catch (e) { /* none */ }
    try { setSecret(id, ''); } catch (e) { /* none */ }
    AUD('intel.feed.remove', id, { by }); return { removed: id };
  }
  async function fetchOne(f) {
    const h = { 'User-Agent': 'sentra-siem-intel/1', Accept: 'text/plain, text/csv, application/json, */*' }, sec = secrets()[f.id];
    if (sec) { const i = sec.indexOf(':'); h[sec.slice(0, i).trim()] = sec.slice(i + 1).trim(); }
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 60000);
    let res;
    try { res = await doFetch(f.url, { headers: h, redirect: sec ? 'error' : 'follow', signal: ctl.signal }); }   // a key is never sent on to another address
    catch (e) { clearTimeout(t); throw new FeedError(502, (e.name === 'AbortError' ? 'timed out after 60 s' : 'not reachable (' + (e.cause && e.cause.code || e.message) + ')') + ' - if the server has no direct internet, set the proxy: install/netops-setup.sh --proxy http://proxy:8080'); }
    clearTimeout(t);
    if (res.url && !/^https:/.test(res.url) && !/^http:\/\/(127\.0\.0\.1|localhost)/.test(res.url)) throw new FeedError(502, 'redirected to a non-https address - refused');
    if (!res.ok) throw new FeedError(502, 'HTTP ' + res.status + (res.status === 401 || res.status === 403 ? ' (the feed needs a key - set the header)' : ''));
    const len = Number(res.headers.get('content-length') || 0); if (len > MAX_BYTES) throw new FeedError(502, 'feed larger than 30 MB');
    const buf = Buffer.from(await res.arrayBuffer()); if (buf.length > MAX_BYTES) throw new FeedError(502, 'feed larger than 30 MB');
    return buf.toString('utf8');
  }
  function writeList(id, name, values, by) {
    fs.mkdirSync(dir, { recursive: true });
    const head = `# ${name}\n# written by the SIEM (${by}) at ${new Date(NOW()).toISOString()} - ${values.length} indicators - do not edit: the next download replaces it\n`;
    const t = path.join(dir, '.feed-' + id + '.' + crypto.randomBytes(4).toString('hex') + '.tmp');
    fs.writeFileSync(t, head + values.join('\n') + '\n', { mode: 0o640 }); fs.renameSync(t, file(id));
  }
  async function runOne(f, by) {
    const at = NOW();
    try {
      const text = await fetchOne(f), vals = parseFeed(text, { column: f.column });
      if (!vals.length) throw new FeedError(502, 'the download contained no indicators (wrong URL or format?)');
      writeList(f.id, f.name, vals, by);
      save(Object.assign(get(f.id) || f, { last_run: at, last_ok: at, last_error: '', count: vals.length, bytes: text.length }));
      AUD('intel.feed.run', f.id, { by, ok: true, count: vals.length });
      return { id: f.id, ok: true, count: vals.length };
    } catch (e) {
      save(Object.assign(get(f.id) || f, { last_run: at, last_error: clean(e.message, 300) }));
      AUD('intel.feed.run', f.id, { by, ok: false, error: clean(e.message, 200) });
      L.warn('intel feed failed', { id: f.id, err: e.message });
      return { id: f.id, ok: false, error: clean(e.message, 300) };
    }
  }
  async function run(id, by = 'schedule') {
    if (id) { const f = get(id) || (list(), get(id)); if (!f) throw new FeedError(404, 'feed not found'); return [await runOne(f, by)]; }
    if (running) return running;
    running = (async () => { const out = []; const t = NOW();
      for (const f of (list(), all())) if (f.enabled && (!f.last_run || t - f.last_run >= f.interval_h * 3600000 || (f.last_error && t - f.last_run >= 3600000))) out.push(await runOne(f, by));
      return out; })();
    try { return await running; } finally { running = null; }
  }
  function upload(name, text, by) {
    const id = 'upload-' + (clean(name, 40).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'list');
    if (!ID_RE.test(id.slice(0, 40))) throw new FeedError(400, 'name: letters and digits');
    if (String(text || '').length > MAX_BYTES) throw new FeedError(400, 'list larger than 30 MB');
    const vals = parseFeed(text); if (!vals.length) throw new FeedError(400, 'no indicators found in the text');
    writeList(id.slice(0, 40), 'uploaded: ' + clean(name, 80), vals, by);
    AUD('intel.upload', id, { by, count: vals.length });
    return { list: 'feed-' + id.slice(0, 40), count: vals.length };
  }
  function start() { stop(); const tick = () => run(null, 'schedule').catch((e) => L.warn('intel feeds run failed', { err: e.message })); const a = setTimeout(tick, 90000); timer = setInterval(tick, 15 * 60000); for (const x of [a, timer]) if (x.unref) x.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { list, put, remove, setEnabled: (id, on, by) => put({ id, enabled: !!on }, by), run, upload, start, stop, PRESETS };
}

module.exports = { createIntelFeeds, parseFeed, PRESETS };
