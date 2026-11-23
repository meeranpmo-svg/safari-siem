// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * YSoft SAFEQ 6 (on-premises): a web link to its console, and scheduled READ-ONLY pulls from it.
 *   createSafeq({state, config, printers, writeJson, getRaw, log, now})
 *     .settings()            {console_url, usage_url, devices_url, auth, header_name, username, interval_min, tls, secret_set,
 *                             last_usage, last_devices}   (never the password / token)
 *     .setSettings(b, by)    admin; the secret goes to secrets.json printers.safeq (write-only, like the SNMP secret)
 *     .test(which)           fetch usage_url or devices_url once: format, columns found, row count, the first rows
 *     .pullUsage(by)         usage_url → this month's usage (the same column recognition as the CSV import; a pull
 *                            replaces that month), and last month too during the first 5 days of a month
 *     .pullDevices(by)       devices_url → printers matched by IP: name / model / serial / location / SAFEQ name filled,
 *                            new ones added (source "safeq"); none are removed
 *     .tick()                every interval_min (default 60)
 * The URLs are whatever the customer's SAFEQ answers: a SAFEQ 6 REST API endpoint, or the address of a scheduled report
 * export. CSV and JSON are both read (JSON: the first array of records found, nested keys flattened). {from} {to}
 * {period} in a URL become this month's dates (YYYY-MM-DD, YYYY-MM). Authentication: none, Basic, Bearer token or a
 * named header (API key). GET only, https only, no redirects followed; TLS by system CAs, a CA file or a pinned
 * certificate (SHA-256). A URL with a user name or password in it is refused - credentials go in the secret field.
 */
const fs = require('node:fs');

const AUTH = ['none', 'basic', 'bearer', 'header'];
const clean = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
const bad = (m, status = 400) => Object.assign(new Error(m), { status });
const pad = (n) => String(n).padStart(2, '0');

function checkUrl(v, label, allowHttp) {
  const t = clean(v, 1000);
  if (!t) return '';
  let u; try { u = new URL(t.replace(/\{(from|to|period)\}/g, 'x')); } catch (e) { throw bad(`${label}: not a web address`); }
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:')) throw bad(`${label}: must start with https://`);
  if (u.username || u.password) throw bad(`${label}: remove the user name / password from the address - put the credential in the secret field`);
  return t;
}
// JSON → [head, rows]: the first array of objects (top level, or under data / items / content / results / …), keys flattened
function recordsOf(j) {
  let arr = Array.isArray(j) ? j : null;
  if (!arr && j && typeof j === 'object') {
    const seen = [j];
    while (seen.length && !arr) {
      const o = seen.shift();
      for (const k of Object.keys(o)) { const v = o[k]; if (Array.isArray(v) && v.length && typeof v[0] === 'object') { arr = v; break; } if (v && typeof v === 'object' && !Array.isArray(v) && seen.length < 50) seen.push(v); }
    }
  }
  if (!arr) return null;
  const flat = (o, p, out) => { for (const [k, v] of Object.entries(o || {})) { const key = p ? p + ' ' + k : k; if (v && typeof v === 'object' && !Array.isArray(v)) flat(v, key, out); else out[key] = Array.isArray(v) ? v.join(', ') : v; } return out; };
  const rows = arr.slice(0, 200000).map((x) => flat(x, '', {}));
  const head = []; for (const r of rows.slice(0, 500)) for (const k of Object.keys(r)) if (!head.includes(k)) head.push(k);
  return [head, rows.map((r) => head.map((h) => (r[h] == null ? '' : String(r[h]))))];
}
// "deviceName" / "device_name" / "Device name" all become "device name", so the CSV column rules recognise them
const human = (h) => String(h).replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_.]+/g, ' ').replace(/\s+/g, ' ').trim();

function createSafeq({ state, config, printers, writeJson = null, getRaw = null, log = null, now = Date.now } = {}) {
  const L = log || { info() {}, warn() {} };
  const cfgCol = state.collection('printer_settings');
  const fetchRaw = getRaw || require('../netops/http').getRaw;
  const allowHttp = () => !!(config.printers && config.printers.safeq_allow_http);   // lab / tests only
  let busy = false, lastTick = 0;

  function raw() { return Object.assign({ auth: 'none', interval_min: 60 }, ((cfgCol.get('safeq') || {}).value) || {}); }
  function secret() { const s = config.secrets && config.secrets.printers && config.secrets.printers.safeq; return s && s.value ? String(s.value) : ''; }
  function settings() {
    const c = raw();
    return { console_url: c.console_url || '', usage_url: c.usage_url || '', devices_url: c.devices_url || '', auth: c.auth, header_name: c.header_name || '', username: c.username || '', interval_min: c.interval_min,
      tls: { fingerprint256: c.fingerprint256 || '', ca_file: c.ca_file || '' }, secret_set: !!secret(), last_usage: c.last_usage || null, last_devices: c.last_devices || null };
  }
  function setSettings(b, by) {
    const c = raw();
    if ('console_url' in b) c.console_url = checkUrl(b.console_url, 'SAFEQ console address', allowHttp());
    if ('usage_url' in b) c.usage_url = checkUrl(b.usage_url, 'Usage address', allowHttp());
    if ('devices_url' in b) c.devices_url = checkUrl(b.devices_url, 'Printer list address', allowHttp());
    if ('auth' in b) { if (!AUTH.includes(b.auth)) throw bad('authentication must be ' + AUTH.join(' / ')); c.auth = b.auth; }
    if ('header_name' in b) { const h = clean(b.header_name, 60); if (h && !/^[A-Za-z0-9-]{1,60}$/.test(h)) throw bad('header name: letters, digits and - only'); c.header_name = h; }
    if ('username' in b) c.username = clean(b.username, 120);
    if ('interval_min' in b) { const n = Number(b.interval_min); if (!(n >= 15 && n <= 1440)) throw bad('pull every 15 to 1440 minutes'); c.interval_min = Math.round(n); }
    if ('fingerprint256' in b) { const fp = clean(b.fingerprint256, 120).replace(/[^0-9a-f]/gi, '').toUpperCase(); if (fp && fp.length !== 64) throw bad('certificate fingerprint: 64 hex characters (SHA-256)'); c.fingerprint256 = fp; }
    if ('ca_file' in b) { const f = clean(b.ca_file, 250); if (f && !/^\/[A-Za-z0-9._/-]+$/.test(f)) throw bad('CA file: an absolute path on the SIEM server'); c.ca_file = f; }
    if (c.auth === 'header' && !c.header_name) throw bad('give the header name for the API key (e.g. X-Api-Key)');
    if (c.auth === 'basic' && !c.username) throw bad('give the user name for Basic authentication');
    if (b.secret != null && String(b.secret) !== '') {
      const v = String(b.secret); if (v.length > 4096) throw bad('secret too long');
      const p = config._paths && config._paths.secrets; if (!p || !writeJson) throw bad('secrets file not available', 409);
      let sec = {}; try { sec = require('../secretfile').read(p) || {}; } catch (e) { throw bad('secrets file cannot be read: ' + e.message, 500); }
      sec.printers = Object.assign({}, sec.printers || {}, { safeq: { value: v, set_by: by || '', set_at: new Date(now()).toISOString() } }); writeJson(p, sec);
      config.secrets = config.secrets || {}; config.secrets.printers = Object.assign(config.secrets.printers || {}, { safeq: { value: v } });
    }
    if (c.auth !== 'none' && !secret()) throw bad(c.auth === 'basic' ? 'enter the password' : 'enter the token / API key');
    c.updated = now(); c.updated_by = by || '';
    cfgCol.put({ id: 'safeq', value: c });
    return settings();
  }

  function month(offset) { const d = new Date(now()); const m = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + offset, 1)); const last = offset === 0 ? d : new Date(Date.UTC(m.getUTCFullYear(), m.getUTCMonth() + 1, 0));
    return { period: `${m.getUTCFullYear()}-${pad(m.getUTCMonth() + 1)}`, from: `${m.getUTCFullYear()}-${pad(m.getUTCMonth() + 1)}-01`, to: `${last.getUTCFullYear()}-${pad(last.getUTCMonth() + 1)}-${pad(last.getUTCDate())}` }; }
  const fill = (url, m) => url.replace(/\{from\}/g, m.from).replace(/\{to\}/g, m.to).replace(/\{period\}/g, m.period);
  async function fetchTable(url) {
    const c = raw(), s = secret(), headers = { Accept: 'application/json, text/csv;q=0.9, */*;q=0.5' };
    if (c.auth === 'basic') headers.Authorization = 'Basic ' + Buffer.from(`${c.username}:${s}`).toString('base64');
    if (c.auth === 'bearer') headers.Authorization = 'Bearer ' + s;
    if (c.auth === 'header') headers[c.header_name] = s;
    let ca; if (c.ca_file) { try { ca = fs.readFileSync(c.ca_file); } catch (e) { throw bad(`CA file not readable (${e.code})`, 409); } }
    let r;
    try { r = await fetchRaw(url, { headers, timeoutMs: 60000, maxBytes: 64 * 1048576, allow_http: allowHttp(), tls: { ca, fingerprint256: c.fingerprint256 || undefined } }); }
    catch (e) { throw bad(/certificate|self.signed|unable to verify|CERT/i.test(e.message) ? 'SAFEQ certificate not trusted - enter its SHA-256 fingerprint or a CA file' : `SAFEQ could not be reached (${e.code || e.message})`, 502); }
    if (r.status === 401 || r.status === 403) throw bad(`SAFEQ refused the credential (HTTP ${r.status})`, 502);
    if (r.status >= 300 && r.status < 400) throw bad(`SAFEQ answered with a redirect (HTTP ${r.status}) - usually the login page: check the address and the authentication`, 502);
    if (r.status < 200 || r.status >= 300) throw bad(`SAFEQ answered HTTP ${r.status}`, 502);
    const text = String(r.text || '');
    if (/^\s*</.test(text)) throw bad('SAFEQ answered with a web page, not data - usually the login page: check the address and the authentication', 502);
    if (r.json != null) { const t = recordsOf(r.json); if (!t) throw bad('the JSON answer has no list of records', 502); return { format: 'json', head: t[0].map(human), rows: t[1] }; }
    const rows = printers.parseCsvText(text);
    if (rows.length < 1) throw bad('the answer is empty', 502);
    return { format: 'csv', head: rows[0].map(human), rows: rows.slice(1) };
  }
  async function test(which) {
    const c = raw(), url = which === 'devices' ? c.devices_url : c.usage_url;
    if (!url) throw bad('enter the address first', 409);
    const t = await fetchTable(fill(url, month(0)));
    return { ok: true, format: t.format, columns: t.head, rows: t.rows.length, sample: t.rows.slice(0, 3).map((r) => Object.fromEntries(t.head.map((h, i) => [h, String(r[i] == null ? '' : r[i]).slice(0, 80)]))) };
  }
  function note(key, v) { const c = raw(); c[key] = v; cfgCol.put({ id: 'safeq', value: c }); }
  async function pullUsage(by) {
    const c = raw(); if (!c.usage_url) throw bad('no usage address set', 409);
    const months = [month(0)]; if (new Date(now()).getUTCDate() <= 5) months.push(month(-1));
    const out = { at: now(), ok: true, periods: [] };
    try {
      for (const m of months) { const t = await fetchTable(fill(c.usage_url, m)); const r = printers.importRows(t.head, t.rows, { period: m.period }, by || 'safeq', 'safeq'); out.periods.push({ period: m.period, rows: r.rows, pages: r.pages, format: t.format }); }
    } catch (e) { out.ok = false; out.error = e.message; }
    note('last_usage', out);
    if (!out.ok) L.warn('SAFEQ usage pull failed', { err: out.error });
    return out;
  }
  const DEV = { name: /^(name|device ?name|printer|printer ?name|terminal ?name|title)$/i, ip: /^(ip|ip ?address|address|network ?address|host|hostname|device ?ip|terminal ?ip)$/i,
    model: /^(model|device ?model|printer ?model|type|product)$/i, serial: /^(serial|serial ?number|sn)$/i, location: /^(location|place|room|building|floor)$/i, id: /^(id|device ?id|terminal ?id|uuid)$/i };
  async function pullDevices(by) {
    const c = raw(); if (!c.devices_url) throw bad('no printer list address set', 409);
    const out = { at: now(), ok: true, rows: 0, added: 0, updated: 0, skipped: 0 };
    try {
      const t = await fetchTable(fill(c.devices_url, month(0))), map = {};
      for (const [k, re] of Object.entries(DEV)) { const i = t.head.findIndex((h) => re.test(h)); if (i >= 0) map[k] = i; }
      if (map.ip === undefined) throw bad('no IP address column found - columns: ' + t.head.slice(0, 30).join(', '), 502);
      const byIp = new Map(printers.list().map((p) => [p.ip, p]));
      for (const r of t.rows) {
        out.rows++;
        const g = (k) => (map[k] === undefined ? '' : String(r[map[k]] || '').trim());
        const ip = (g('ip').match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/) || [])[0];
        if (!ip) { out.skipped++; continue; }
        const ex = byIp.get(ip), f = { safeq_name: g('name'), safeq_id: g('id') };
        if (g('model')) f.model = g('model'); if (g('serial')) f.serial = g('serial'); if (g('location')) f.location = g('location');
        try {
          if (ex) { const ch = Object.keys(f).filter((k) => f[k] && f[k] !== ex[k]); if (ch.length) { printers.put(Object.assign({ id: ex.id }, f), by || 'safeq'); out.updated++; } }
          else { const p = printers.put(Object.assign({ ip, name: g('name') || ip, source: 'safeq' }, f), by || 'safeq'); byIp.set(ip, p); out.added++; }
        } catch (e) { out.skipped++; }
      }
    } catch (e) { out.ok = false; out.error = e.message; }
    note('last_devices', out);
    if (!out.ok) L.warn('SAFEQ printer list pull failed', { err: out.error });
    return out;
  }
  async function tick() {
    const c = raw();
    if (busy || (!c.usage_url && !c.devices_url) || now() - lastTick < (c.interval_min || 60) * 60000) return null;
    busy = true; lastTick = now();
    try { const r = {}; if (c.devices_url) r.devices = await pullDevices('safeq'); if (c.usage_url) r.usage = await pullUsage('safeq'); return r; } finally { busy = false; }
  }
  return { settings, setSettings, test, pullUsage, pullDevices, tick, recordsOf };
}

module.exports = { createSafeq, recordsOf, checkUrl };
