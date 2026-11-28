// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Printer management (Xerox fleet behind YSoft SAFEQ 6). Read-only.
 *   createPrinters({state, config, log, ch, discovery, snmp, writeJson, now})
 *     .start() .stop() .list() .get(id) .put(input, by) .remove(id) .pollNow(id)
 *     .syncFromInventory(who)   printers (type "printer" with a management IP) from IT Asset Management, every 30 min
 *     .settings() .setSettings(s, by)      SNMP credentials for the fleet (write-only, secrets.json printers.snmp)
 *     .importUsage(csv, opts, by) .usage({days})   SAFEQ 6 usage reports (CSV export) → pages / colour / cost per
 *                                                   user, department, printer
 * Polling every 5 min over SNMP, standard Printer-MIB (RFC 3805) + Host Resources MIB (RFC 2790), which Xerox
 * implements: device / printer status, detected errors (paper, toner, door, jam, offline, service), supplies (toner,
 * drum, waste) with % left, input trays, active alerts, total impressions (page counter), serial and model.
 * ClickHouse net_metrics (TTL 400 d): printer_up, pages_total, toner_min_pct per printer.
 */
const crypto = require('node:crypto');
const net = require('node:net');

const O = {
  sysDescr: '1.3.6.1.2.1.1.1.0', sysName: '1.3.6.1.2.1.1.5.0', sysLocation: '1.3.6.1.2.1.1.6.0', sysUpTime: '1.3.6.1.2.1.1.3.0',
  hrDeviceDescr: '1.3.6.1.2.1.25.3.2.1.3', hrDeviceStatus: '1.3.6.1.2.1.25.3.2.1.5',
  hrPrinterStatus: '1.3.6.1.2.1.25.3.5.1.1', hrPrinterErr: '1.3.6.1.2.1.25.3.5.1.2',
  prtSerial: '1.3.6.1.2.1.43.5.1.1.17', prtLife: '1.3.6.1.2.1.43.10.2.1.4',
  supType: '1.3.6.1.2.1.43.11.1.1.5', supDescr: '1.3.6.1.2.1.43.11.1.1.6', supMax: '1.3.6.1.2.1.43.11.1.1.8', supLevel: '1.3.6.1.2.1.43.11.1.1.9',
  inDescr: '1.3.6.1.2.1.43.8.2.1.18', inMax: '1.3.6.1.2.1.43.8.2.1.9', inLevel: '1.3.6.1.2.1.43.8.2.1.10', inName: '1.3.6.1.2.1.43.8.2.1.13',
  alSev: '1.3.6.1.2.1.43.18.1.1.2', alDescr: '1.3.6.1.2.1.43.18.1.1.8',
};
const DEV_ST = { 1: 'unknown', 2: 'running', 3: 'warning', 4: 'testing', 5: 'down' };
const PRN_ST = { 1: 'other', 2: 'unknown', 3: 'idle', 4: 'printing', 5: 'warming up' };
// hrPrinterDetectedErrorState: bit 0 = most significant bit of the first octet (RFC 2790)
const ERR_BITS = ['low paper', 'no paper', 'low toner', 'no toner', 'door open', 'paper jam', 'offline', 'service requested',
  'input tray missing', 'output tray missing', 'supply missing', 'output nearly full', 'output full', 'input tray empty', 'maintenance overdue'];
const BAD_ERR = new Set(['no paper', 'no toner', 'door open', 'paper jam', 'offline', 'service requested', 'output full', 'supply missing']);
const SUP_TYPE = { 3: 'toner', 4: 'waste toner', 5: 'ink', 9: 'drum', 15: 'fuser', 6: 'ink cartridge', 21: 'transfer unit' };
const DEFAULTS = { poll_s: 300, sync_inventory: true, toner_warn_pct: 15, toner_crit_pct: 5 };

const str = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : v == null ? '' : String(v)).replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
const clean = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
const tail = (oid, base) => oid.slice(base.length + 1);
function errBits(v) {
  const b = Buffer.isBuffer(v) ? v : Buffer.alloc(0), out = [];
  for (let i = 0; i < ERR_BITS.length; i++) { const byte = b[i >> 3]; if (byte !== undefined && (byte & (0x80 >> (i & 7)))) out.push(ERR_BITS[i]); }
  return out;
}
function pct(level, max) { // Printer-MIB: -2 unknown, -3 "some remaining", max -1/-2 unknown
  const l = Number(level), m = Number(max);
  if (!(l >= 0)) return { pct: null, state: l === -3 ? 'ok' : 'unknown' };
  if (!(m > 0)) return { pct: null, state: 'unknown' };
  return { pct: Math.max(0, Math.min(100, Math.round(l / m * 100))), state: 'measured' };
}

async function pollSnmp(p, cred, createSnmp) {
  const s = createSnmp(Object.assign({ host: p.ip, port: 161, timeoutMs: 2500, retries: 1 }, cred));
  try {
    const g = await s.get([O.sysDescr, O.sysName, O.sysLocation, O.sysUpTime]);
    const W = async (o, max) => { try { return await s.walk(o, { maxRows: max || 200 }); } catch { return []; } };
    const [ds, pst, perr, ser, life, sT, sD, sM, sL, iD, iM, iL, iN, aS, aD, hd] = await Promise.all([W(O.hrDeviceStatus), W(O.hrPrinterStatus), W(O.hrPrinterErr), W(O.prtSerial), W(O.prtLife),
      W(O.supType), W(O.supDescr), W(O.supMax), W(O.supLevel), W(O.inDescr), W(O.inMax), W(O.inLevel), W(O.inName), W(O.alSev, 100), W(O.alDescr, 100), W(O.hrDeviceDescr)]);
    const byIdx = (rows, base) => new Map(rows.map(([o, v]) => [tail(o, base), v]));
    const supD = byIdx(sD, O.supDescr), supM = byIdx(sM, O.supMax), supL = byIdx(sL, O.supLevel), supT = byIdx(sT, O.supType);
    const supplies = [...supD.keys()].map((k) => Object.assign({ name: str(supD.get(k)).slice(0, 80), type: SUP_TYPE[Number(supT.get(k))] || 'other' }, pct(supL.get(k), supM.get(k)))).slice(0, 24);
    const inD = byIdx(iD, O.inDescr), inN = byIdx(iN, O.inName), inM = byIdx(iM, O.inMax), inL = byIdx(iL, O.inLevel);
    const trays = [...new Set([...inD.keys(), ...inN.keys()])].map((k) => Object.assign({ name: (str(inN.get(k)) || str(inD.get(k)) || 'tray ' + k).slice(0, 60) }, pct(inL.get(k), inM.get(k)))).slice(0, 12);
    const alD = byIdx(aD, O.alDescr), alS = byIdx(aS, O.alSev);
    const alerts = [...alD.keys()].map((k) => ({ text: str(alD.get(k)).slice(0, 160), severity: { 3: 'critical', 4: 'warning', 5: 'warning' }[Number(alS.get(k))] || 'info' })).filter((a) => a.text).slice(0, 20);
    const errors = perr.length ? errBits(perr[0][1]) : [];
    const pages = life.length ? Number(life[0][1]) : null;
    const descr = str(g[O.sysDescr]);
    return {
      ok: true, name: str(g[O.sysName]).slice(0, 120), location: str(g[O.sysLocation]).slice(0, 120), uptime_s: g[O.sysUpTime] != null ? Math.round(Number(g[O.sysUpTime]) / 100) : null,
      model: (hd.length ? str(hd[0][1]) : descr.split(/[;\r\n]/)[0]).slice(0, 120), descr: descr.slice(0, 200), serial: ser.length ? str(ser[0][1]).slice(0, 60) : '',
      device_status: ds.length ? DEV_ST[Number(ds[0][1])] || 'unknown' : 'unknown', printer_status: pst.length ? PRN_ST[Number(pst[0][1])] || 'unknown' : 'unknown',
      errors, supplies, trays, alerts, pages_total: Number.isFinite(pages) ? pages : null,
    };
  } finally { try { s.close(); } catch { /* */ } }
}

function createPrinters({ state, config, log, ch = null, discovery = null, snmp = null, writeJson = null, now = Date.now } = {}) {
  const L = log || { info() {}, warn() {}, error() {} };
  const col = state.collection('printers'), snaps = state.collection('printer_snapshots'), usageCol = state.collection('printer_usage'), cfgCol = state.collection('printer_settings');
  const createSnmp = snmp || require('../netops/snmp').createSnmp;
  const db = (config.clickhouse && config.clickhouse.database) || 'siem';
  let timer = null, syncTimer = null, running = false;
  const stats = { polls: 0, last_poll_at: 0, last_sync_at: 0, last_sync: null, last_sync_error: '' };

  function settings() { return Object.assign({}, DEFAULTS, (config.printers || {}), (cfgCol.get('settings') || {}).value || {}); }
  function cred() { const s = (config.secrets && config.secrets.printers && config.secrets.printers.snmp) || null; return s && (s.community || s.user) ? s : null; }
  function setSettings(s, by) {
    const v = Object.assign({}, (cfgCol.get('settings') || {}).value || {});
    for (const k of ['toner_warn_pct', 'toner_crit_pct']) if (s[k] !== undefined) { const n = Number(s[k]); if (!(n >= 0 && n <= 100)) throw Object.assign(new Error(k + ' must be 0-100'), { status: 400 }); v[k] = Math.round(n); }
    if (s.sync_inventory !== undefined) v.sync_inventory = s.sync_inventory === true || s.sync_inventory === 'true';
    cfgCol.put({ id: 'settings', value: v, updated: now(), updated_by: by || '' });
    if (s.snmp) {
      const x = s.snmp, c = { version: x.version === '3' ? '3' : '2c' };
      if (c.version === '2c') { if (typeof x.community !== 'string' || !x.community || x.community.length > 64) throw Object.assign(new Error('SNMP community required (max 64)'), { status: 400 }); c.community = x.community; }
      else { c.user = clean(x.user, 64); if (!c.user) throw Object.assign(new Error('SNMPv3 user required'), { status: 400 }); c.authProto = x.authProto === 'sha256' ? 'sha256' : 'sha'; c.authKey = String(x.authKey || ''); if (c.authKey.length < 8) throw Object.assign(new Error('SNMPv3 auth password: at least 8 characters'), { status: 400 }); if (x.privKey) { c.privProto = 'aes'; c.privKey = String(x.privKey); } }
      const p = config._paths && config._paths.secrets; if (!p || !writeJson) throw Object.assign(new Error('secrets file not available'), { status: 409 });
      let sec = {}; try { sec = require('../secretfile').read(p) || {}; } catch (e) { if (log && log.error) log.error('printers: secrets file cannot be read', { err: e.message }); throw Object.assign(new Error('the secrets file cannot be read - the detail is in the SIEM log'), { status: 500 }); }
      sec.printers = Object.assign({}, sec.printers || {}, { snmp: c }); writeJson(p, sec);
      if (config.secrets) config.secrets.printers = Object.assign(config.secrets.printers || {}, { snmp: c });
    }
    return Object.assign({}, settings(), { snmp: cred() ? { version: cred().version || '2c', set: true } : { set: false } });
  }

  function validate(input, ex) {
    const p = Object.assign({}, ex || {});
    if (!ex) p.id = 'p-' + crypto.createHash('sha1').update(String(input.ip) + now()).digest('hex').slice(0, 10);
    if (input.ip !== undefined || !ex) { p.ip = clean(input.ip, 45); if (!net.isIP(p.ip)) throw Object.assign(new Error('valid IP address required'), { status: 400 }); }
    for (const k of ['name', 'site', 'location', 'department', 'model', 'safeq_name']) if (input[k] !== undefined) p[k] = clean(input[k], 120);
    if (input.source !== undefined) p.source = input.source === 'inventory' ? 'inventory' : input.source === 'safeq' ? 'safeq' : 'manual';
    for (const k of ['serial', 'safeq_id']) if (input[k] !== undefined) p[k] = clean(input[k], 120);
    if (input.asset_id !== undefined) p.asset_id = clean(input.asset_id, 64);
    if (!p.name) p.name = p.ip;
    return p;
  }
  const put = (input, by) => { const ex = input.id ? col.get(String(input.id)) : null; if (input.id && !ex) throw Object.assign(new Error('printer not found'), { status: 404 }); const p = validate(input, ex); p.updated = now(); p.updated_by = by || ''; col.put(p); return p; };
  function remove(id) { if (!col.get(id)) throw Object.assign(new Error('printer not found'), { status: 404 }); col.remove(id); snaps.remove(id); return { removed: id }; }

  async function pollOne(p) {
    const c = cred(), t = now();
    let r;
    if (!c) r = { ok: false, error: 'no SNMP credentials set (Printers → Settings)' };
    else { try { r = await pollSnmp(p, c, createSnmp); } catch (e) { r = { ok: false, error: /timeout/i.test(e.message) ? 'no SNMP answer (printer off, wrong community, or UDP 161 blocked)' : e.message }; } }
    const prev = snaps.get(p.id) || {};
    const snap = Object.assign({ id: p.id, at: t }, r.ok ? r : { ok: false, error: r.error, last_ok: prev.ok ? prev.at : prev.last_ok || null, pages_total: prev.pages_total, supplies: prev.supplies, model: prev.model, serial: prev.serial });
    snaps.put(snap);
    if (r.ok && ((!p.model && r.model) || (!p.serial && r.serial))) col.patch(p.id, (x) => { if (!x.model) x.model = r.model; if (!x.serial) x.serial = r.serial; });
    if (ch) {
      const ts = Math.floor(t / 1000), toner = (r.supplies || []).filter((s) => /toner|ink/.test(s.type) && s.pct != null).map((s) => s.pct);
      const rows = [{ ts, device: p.id, site: p.site || '', key: '', metric: 'printer_up', value: r.ok ? 1 : 0 }];
      if (r.ok && r.pages_total != null) rows.push({ ts, device: p.id, site: p.site || '', key: '', metric: 'pages_total', value: r.pages_total });
      if (toner.length) rows.push({ ts, device: p.id, site: p.site || '', key: '', metric: 'toner_min_pct', value: Math.min(...toner) });
      ch.insertRows(db + '.net_metrics', rows).catch((e) => L.warn('printer metrics insert failed', { err: e.message }));
    }
    return snap;
  }
  async function pollAll() {
    if (running) return; running = true;
    try { const list = col.all(); let i = 0; const worker = async () => { while (i < list.length) await pollOne(list[i++]); }; await Promise.all(Array.from({ length: Math.min(8, list.length || 1) }, worker)); }
    finally { running = false; stats.polls++; stats.last_poll_at = now(); }
  }

  function issues(p, s, st) {
    const out = [];
    if (!s) return [{ level: 'info', text: 'not polled yet' }];
    if (!s.ok) out.push({ level: 'bad', text: 'not answering: ' + (s.error || 'no reply') });
    for (const e of (s.ok ? s.errors : []) || []) out.push({ level: BAD_ERR.has(e) ? 'bad' : 'warn', text: e });
    for (const x of (s.ok ? s.supplies : []) || []) if (x.pct != null && /toner|ink/.test(x.type)) { if (x.pct <= st.toner_crit_pct) out.push({ level: 'bad', text: `${x.name}: ${x.pct}% left` }); else if (x.pct <= st.toner_warn_pct) out.push({ level: 'warn', text: `${x.name}: ${x.pct}% left` }); }
    for (const x of (s.ok ? s.supplies : []) || []) if (x.pct != null && /drum|fuser|transfer/.test(x.type) && x.pct <= 10) out.push({ level: 'warn', text: `${x.name}: ${x.pct}% life left` });
    for (const x of (s.ok ? s.supplies : []) || []) if (x.type === 'waste toner' && x.pct != null && x.pct >= 90) out.push({ level: 'warn', text: `${x.name}: ${x.pct}% full` });
    if (s.ok && s.device_status === 'down') out.push({ level: 'bad', text: 'printer reports itself down' });
    return out;
  }
  async function pagesByDay(days) {
    if (!ch) return {};
    try {
      const rows = await ch.query(`SELECT device, toDate(ts) AS d, max(value) - min(value) AS n FROM ${db}.net_metrics WHERE metric = 'pages_total' AND ts >= now() - INTERVAL {days:UInt32} DAY GROUP BY device, d ORDER BY d`, { days: { type: 'UInt32', value: days } }, { readonly: true, timeout_ms: 15000 });
      const m = {}; for (const r of rows) (m[r.device] = m[r.device] || []).push({ day: String(r.d), pages: Math.max(0, Number(r.n) || 0) });
      return m;
    } catch (e) { L.warn('printer pages query failed', { err: e.message }); return {}; }
  }
  async function view() {
    const st = settings(), list = col.all(), pd = await pagesByDay(30);
    const items = list.map((p) => {
      const s = snaps.get(p.id) || null, iss = issues(p, s, st), days = pd[p.id] || [], today = new Date(now()).toISOString().slice(0, 10);
      return Object.assign({}, p, { snapshot: s, status: !s ? 'unknown' : !s.ok ? 'offline' : iss.some((x) => x.level === 'bad') ? 'error' : iss.some((x) => x.level === 'warn') ? 'warning' : 'ok',
        issues: iss, pages_today: (days.find((d) => d.day === today) || {}).pages || 0, pages_30d: days.reduce((a, d) => a + d.pages, 0), pages_by_day: days });
    }).sort((a, b) => ({ offline: 0, error: 1, warning: 2, unknown: 3, ok: 4 }[a.status] - { offline: 0, error: 1, warning: 2, unknown: 3, ok: 4 }[b.status]) || String(a.name).localeCompare(String(b.name)));
    const c = (k) => items.filter((i) => i.status === k).length;
    return { items, summary: { total: items.length, ok: c('ok'), warning: c('warning'), error: c('error'), offline: c('offline'), unknown: c('unknown'),
      toner_low: items.filter((i) => i.issues.some((x) => /% left$/.test(x.text))).length, pages_today: items.reduce((a, i) => a + i.pages_today, 0), pages_30d: items.reduce((a, i) => a + i.pages_30d, 0) },
      settings: Object.assign({}, st, { snmp: cred() ? { version: cred().version || '2c', set: true } : { set: false } }), stats };
  }

  async function syncFromInventory(who) {
    if (!discovery || typeof discovery.assets !== 'function') throw Object.assign(new Error('IT Asset Management is not linked to the SIEM (install/link-itam.sh)'), { status: 503 });
    const r = await discovery.assets({ type: 'printer', limit: 5000 }, who || { user: 'system:printers', role: 'viewer' });
    const out = { fetched: r.assets.length, added: 0, updated: 0, removed: 0, skipped_no_ip: [] }, keep = new Set();
    for (const a of r.assets) {
      if (a.type !== 'printer' || ['retired', 'disposed', 'lost'].includes(a.status)) continue;
      const ip = clean(a.mgmt_ip, 45); if (!net.isIP(ip)) { if (out.skipped_no_ip.length < 50) out.skipped_no_ip.push(a.name || a.asset_tag || a.id); continue; }
      keep.add(a.id);
      const ex = col.all((p) => p.ip === ip)[0];
      if (ex) { if (!ex.asset_id) col.patch(ex.id, (x) => { x.asset_id = a.id; }); out.updated++; }
      else { put({ ip, name: a.name || ip, site: a.site || '', department: a.department || '', model: [a.vendor, a.model].filter(Boolean).join(' '), source: 'inventory', asset_id: a.id }, 'system:printers'); out.added++; }
    }
    for (const p of col.all((x) => x.source === 'inventory' && x.asset_id && !keep.has(x.asset_id))) { remove(p.id); out.removed++; }
    stats.last_sync_at = now(); stats.last_sync = out; stats.last_sync_error = '';
    return out;
  }

  /* ---- SAFEQ 6 usage reports (CSV export of a SAFEQ report) ---- */
  const HEAD = { user: /^(user|user ?name|login|account|owner)$/i, department: /^(department|dept|cost ?cent(er|re)|group)$/i, printer: /^(printer|device|device ?name|terminal|mfd|print ?queue|queue)$/i,
    pages: /^(pages|total ?pages|total|sheets|impressions|page ?count|printed ?pages)$/i, color: /^(colou?r|colou?r ?pages|colou?r ?impressions|pages ?colou?r)$/i, mono: /^(b ?& ?w|b ?\/ ?w|bw|mono|black( ?(and|&) ?white)?)( ?pages| ?impressions)?$|^pages ?(mono|bw|b ?& ?w)$/i,
    cost: /^(cost|price|amount|total ?cost)$/i, date: /^(date|day|period|month|time)$/i, jobs: /^(jobs|job ?count|documents)$/i };
  function parseCsv(text) {
    const rows = [], s = String(text || '').replace(/^﻿/, ''), sep = (s.split('\n')[0].match(/;/g) || []).length > (s.split('\n')[0].match(/,/g) || []).length ? ';' : ',';
    let row = [], cell = '', q = false;
    for (let i = 0; i < s.length; i++) {
      const ch2 = s[i];
      if (q) { if (ch2 === '"') { if (s[i + 1] === '"') { cell += '"'; i++; } else q = false; } else cell += ch2; continue; }
      if (ch2 === '"') q = true; else if (ch2 === sep) { row.push(cell); cell = ''; } else if (ch2 === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; } else if (ch2 !== '\r') cell += ch2;
      if (rows.length > 200000) break;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    return rows.filter((r) => r.some((c) => c.trim()));
  }
  function importUsage(csv, opts, by) {
    if (typeof csv !== 'string' || !csv.trim()) throw Object.assign(new Error('paste or upload the CSV exported from a SAFEQ report'), { status: 400 });
    if (csv.length > 20 * 1024 * 1024) throw Object.assign(new Error('CSV larger than 20 MB'), { status: 413 });
    const rows = parseCsv(csv); if (rows.length < 2) throw Object.assign(new Error('the CSV has no data rows'), { status: 400 });
    return importRows(rows[0], rows.slice(1), opts, by, 'csv');
  }
  // rows already split into cells (a CSV file, or records pulled from SAFEQ by engine/printers/safeq.js)
  function importRows(headIn, dataRows, opts, by, source) {
    const head = headIn.map((h) => String(h == null ? '' : h).trim()), map = {};
    for (const [k, re] of Object.entries(HEAD)) { const i = head.findIndex((h) => re.test(h)); if (i >= 0) map[k] = i; }
    if (map.pages === undefined && map.color === undefined && map.mono === undefined) throw Object.assign(new Error('no page column found (expected e.g. "Pages", "Total pages", "Colour", "B&W") — columns: ' + head.join(', ')), { status: 400 });
    const period = clean(opts && opts.period, 40) || new Date(now()).toISOString().slice(0, 7);
    const num = (v) => { const n = Number(String(v == null ? '' : v).replace(/[^\d.,-]/g, '').replace(',', '.')); return Number.isFinite(n) ? n : 0; };
    const items = [];
    for (const r of dataRows) {
      const g = (k) => (map[k] === undefined ? '' : String(r[map[k]] || '').trim());
      const color = num(g('color')), mono = num(g('mono')), pages = map.pages !== undefined ? num(g('pages')) : color + mono;
      if (!pages && !color && !mono) continue;
      items.push({ user: g('user').slice(0, 120), department: g('department').slice(0, 120), printer: g('printer').slice(0, 120), date: g('date').slice(0, 40), pages, color, mono, cost: num(g('cost')), jobs: num(g('jobs')) });
    }
    const rec = { id: 'u-' + crypto.createHash('sha1').update(period + dataRows.length + now() + Math.random()).digest('hex').slice(0, 10), period, imported_at: now(), by: by || '', source: source || 'csv', columns: Object.keys(map), rows: items.length, items: items.slice(0, 100000) };
    for (const old of usageCol.all((x) => x.period === period)) usageCol.remove(old.id);   // one import per period (re-import replaces)
    usageCol.put(rec);
    return { id: rec.id, period, rows: items.length, columns: rec.columns, pages: items.reduce((a, x) => a + x.pages, 0) };
  }
  // per-user printing is personal data (PDPL): only operators / admins get by_user; everyone sees departments and printers
  function usage(opts) {
    const users = !opts || opts.users !== false;
    const imports = usageCol.all().sort((a, b) => String(b.period).localeCompare(String(a.period)));
    const agg = (rec, key) => { const m = new Map(); for (const x of rec.items) { const k = x[key] || '(unknown)'; const o = m.get(k) || { name: k, pages: 0, color: 0, mono: 0, cost: 0, jobs: 0 }; o.pages += x.pages; o.color += x.color; o.mono += x.mono; o.cost += x.cost; o.jobs += x.jobs; m.set(k, o); } return [...m.values()].sort((a, b) => b.pages - a.pages); };
    return { users_shown: users, periods: imports.map((r) => ({ id: r.id, period: r.period, rows: r.rows, imported_at: r.imported_at, by: r.by, source: r.source || 'csv', columns: r.columns,
      totals: r.items.reduce((a, x) => ({ pages: a.pages + x.pages, color: a.color + x.color, mono: a.mono + x.mono, cost: Math.round((a.cost + x.cost) * 100) / 100 }), { pages: 0, color: 0, mono: 0, cost: 0 }),
      by_user: users ? agg(r, 'user').slice(0, 100) : [], by_department: agg(r, 'department').slice(0, 100), by_printer: agg(r, 'printer').slice(0, 200) })) };
  }

  const api = {
    start() {
      if (timer) return;
      setTimeout(guardJob('printers.printers.pollAll', () => pollAll()), 15000).unref(); timer = setInterval(guardJob('printers.printers.pollAll', () => pollAll()), Math.max(60, settings().poll_s) * 1000); timer.unref();
      const sync = () => { if (!settings().sync_inventory || !discovery || typeof discovery.assets !== 'function') return; api.syncFromInventory().catch((e) => { stats.last_sync_error = e.message; L.warn('printer inventory sync failed', { err: e.message }); }); };
      setTimeout(sync, 25000).unref(); syncTimer = setInterval(guardJob('printers.printers.sync', sync), 30 * 60000); syncTimer.unref();
    },
    stop() { if (timer) clearInterval(timer); if (syncTimer) clearInterval(syncTimer); timer = syncTimer = null; },
    list: () => col.all(), get: (id) => col.get(id) || null, put, remove, view, settings, setSettings, syncFromInventory, importUsage, importRows, usage, pollAll, parseCsvText: parseCsv,
    async pollNow(id) { const p = col.get(id); if (!p) throw Object.assign(new Error('printer not found'), { status: 404 }); return pollOne(p); },
    detail: async (id) => { const v = await view(); return v.items.find((x) => x.id === id) || null; },
  };
  return api;
}

module.exports = { createPrinters, pollSnmp, errBits, pct, ERR_BITS };
