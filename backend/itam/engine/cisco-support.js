// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Cisco support coverage (Smart Net Total Care / Smart Net) for the Cisco switches, routers, firewalls and UCS servers in
// IT Asset Management: which contract covers each device, and is that true.
//
//   Assigned   a contract is assigned to a device by its SERIAL NUMBER (exact, case-insensitive) — from the contract
//              export of Cisco Commerce Workspace / Smart Net Total Care (CSV import), or entered by hand on one asset.
//   Validated  Cisco itself is asked, by serial, whether the device is covered and until when (Cisco Support API
//              "Serial Number to Information", coverage summary). Only serial numbers are sent to Cisco.
//   Status     covered · expiring (within expiring_days) · expired · not-covered (Cisco says no) · not-assigned (no
//              contract known) · no-serial (the asset has no serial: read it from the device first). A contract that
//              the import shows but Cisco does not confirm is flagged "mismatch"; import-only rows read "not validated".
//
//   GET  /cisco-support/status                  settings (no secret), counts, last check            any role
//   GET  /cisco-support/report                  per device + contracts that match no asset          any role
//   GET  /cisco-support/coverage?serial|ip|name one device, with a ready-to-open TAC case summary   any role (SIEM ticket desk)
//   POST /cisco-support/import  {text, filename} contract export (CSV)                              operator
//   POST /cisco-support/assign  {asset_id, contract, service_level?, start?, end}                   operator
//   POST /cisco-support/unassign {serial}                                                            operator
//   POST /cisco-support/check                   ask Cisco now (API configured)                      operator
//   POST /cisco-support/config  {api:{enabled, client_id, client_secret, token_url?, base_url?, interval_h?},
//                                expiring_days?, include_phones?}                                    admin
// The API client secret is sealed (AES-256-GCM, discovery vault key), never returned, logged or audited; changing the
// client id or an address needs the secret again. https only, TLS always verified (httpc). Only the token call and the
// coverage-summary GET (CISCO_CALLS) can be made. Every change is audited (cisco.*). Field names of the Cisco API and of
// the CCW / SNTC exports differ between versions: both are read defensively, and the import reports which columns it used.
// Added to an existing install with one registration line (install/add-cisco-support.sh).
const httpc = require('./discovery/httpc');
const { createSealer } = require('./discovery/vault');
const { parseCsv } = require('./import');

const SYS = { user: 'system:cisco-support', role: 'admin', ip: '' };
const DAY = 86400000;
const CLOSED = { retired: 1, disposed: 1 };
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const iso = (t) => new Date(t == null ? Date.now() : t).toISOString();
const normSerial = (v) => String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 40);
function dateOf(v) {
  const t = String(v || '').trim(); if (!t) return null;
  let m = /^(\d{4})-(\d{2})-(\d{2})/.exec(t); if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  m = /^(\d{1,2})[-/ ]([A-Za-z]{3})[A-Za-z]*[-/ ](\d{2,4})$/.exec(t);          // 15-Mar-2027 (CCW)
  if (m) { const mon = 'jan feb mar apr may jun jul aug sep oct nov dec'.split(' ').indexOf(m[2].toLowerCase()); if (mon >= 0) { const y = m[3].length === 2 ? '20' + m[3] : m[3]; return `${y}-${String(mon + 1).padStart(2, '0')}-${m[1].padStart(2, '0')}`; } }
  m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(t);                               // dd/mm/yyyy (Saudi exports) — mm/dd when the first part > 12 is impossible
  if (m) { const a = +m[1], b = +m[2]; const [d, mo] = a > 12 ? [a, b] : b > 12 ? [b, a] : [a, b]; return `${m[3]}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`; }
  const p = Date.parse(t); return Number.isFinite(p) ? iso(p).slice(0, 10) : null;
}

// what the Cisco Support API may be asked (verify the token URL for the customer's Cisco API client: id.cisco.com is the
// current identity service; older clients use cloudsso.cisco.com/as/token.oauth2)
const DEFAULT_TOKEN_URL = 'https://id.cisco.com/oauth2/default/v1/token';
const DEFAULT_BASE_URL = 'https://apix.cisco.com';
const CISCO_CALLS = [['POST', /^\/oauth2\/default\/v1\/token$|^\/as\/token\.oauth2$/], ['GET', /^\/sn2info\/v2\/coverage\/summary\/serial_numbers\/[A-Z0-9,]{1,4000}$/],
  ['GET', /^\/security\/advisories\/v2\/OSType\/(ios|iosxe|nxos|asa)$/]];   // PSIRT openVuln: advisories for one software version
const PER_CALL = 50;

// which assets are Cisco hardware with a support contract (phones are usually covered per cluster, not per unit)
const CISCO_MODEL = /^(WS-C|C9\d{3}|C8\d{3}|C1\d{3}|C\d{4}[A-Z]|ISR|ASR|N\dK|N\d{2}K|UCS|ASA|FPR|AIR-|C9800|CBS\d|SG\d{3}|IE-\d|CISCO\d)/i;
// the vendor, model and operating system as an asset or a discovery sighting records them: "Cisco Systems, Inc.",
// "CiscoSystems", "cisco-ios" (AI Network Engineer), "Cisco IOS Software", "Catalyst 9300", "NX-OS" - not only "Cisco"
const CISCO_TEXT = /cisco|catalyst|nexus|\bios[- ]?xe\b|\bnx-?os\b|\bios[- ]?xr\b/i;
const CISCO_TYPES = ['network', 'server', 'storage', 'other', 'phone'];
const looksCisco = (a) => CISCO_TEXT.test([a.vendor, a.os, a.model, a.discovery && a.discovery.vendor, a.discovery && a.discovery.os].filter(Boolean).join(' ')) || CISCO_MODEL.test(a.model || '');
function isCisco(a, includePhones) {
  if (!a || CLOSED[a.status]) return false;
  if (a.type === 'phone' && !includePhones) return false;
  if (a.type && !CISCO_TYPES.includes(a.type)) return false;
  return looksCisco(a);
}
// why a Cisco-looking asset is not on the coverage list (so a missing switch is explained, never silently absent)
function whyNot(a, includePhones) {
  if (CLOSED[a.status]) return `${a.status} - closed assets are not tracked`;
  if (a.type === 'phone' && !includePhones) return 'IP phone - phones are covered per cluster (turn on "include phones" to list them)';
  if (a.type && !CISCO_TYPES.includes(a.type)) return `type is "${a.type}" - set the type to Network (switch / router / firewall / AP) or Server (UCS)`;
  return '';
}

// export column names (CCW, SNTC, CCW-R and hand-made sheets) → our fields
const COLS = {
  serial: ['serial number', 'serial number/pak', 'serial', 'serial no', 'serial #', 'sn', 'instance serial number'],
  contract: ['contract number', 'contract #', 'contract', 'service contract number', 'contract id'],
  service_level: ['service level', 'service level description', 'service program', 'service description', 'service sku', 'service line description'],
  start: ['coverage start date', 'start date', 'service start date', 'contract start date'],
  end: ['coverage end date', 'end date', 'service end date', 'contract end date', 'coverage end'],
  pid: ['product id', 'product number', 'pid', 'item', 'product', 'covered product'],
  site_name: ['install site name', 'installed at site', 'install site', 'site name', 'installed at'],
};
const nh = (h) => String(h || '').trim().toLowerCase().replace(/[\s_]+/g, ' ');
function pickColumns(headers) {
  const out = {}, H = headers.map(nh);
  for (const [k, names] of Object.entries(COLS)) { const i = H.findIndex((h) => names.includes(h)); if (i >= 0) out[k] = headers[i]; }
  return out;
}
/* CCW / SNTC exports often start with title lines: find the header row (the first one that names a serial column) */
function parseExport(text) {
  const lines = String(text || '').replace(/^﻿/, '').split(/\r?\n/);
  for (let i = 0; i < Math.min(lines.length, 30); i++) {
    if (!lines[i].trim()) continue;
    const p = parseCsv(lines.slice(i).join('\n'));
    const cols = pickColumns(p.headers);
    if (cols.serial) return { columns: cols, rows: p.rows, header_line: i + 1 };
  }
  return { columns: {}, rows: [], header_line: 0 };
}

// ---- the Cisco Support API exchange, nothing stored: serials in → one entry per serial out, in the order Cisco answered.
// The Python module pyengine/cisco_api.py does exactly the same (docs/PYTHON-MIGRATION.md step 3).
//   entry: [serial, data, kind]  kind = covered | not_covered | unknown
//   → {entries, error?, error_class?}  (entries of the batches read before an error are kept)
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost']);
function ciscoAllowed(method, url) { let u; try { u = new URL(url); } catch { return false; } return (u.protocol === 'https:' || (u.protocol === 'http:' && LOOPBACK_HOSTS.has(u.hostname))) && CISCO_CALLS.some(([m, re]) => m === method && re.test(u.pathname)); }
function apiRow(x) {
  const yes = /^(yes|true|y)$/i.test(String(x.is_covered == null ? '' : x.is_covered));
  const pid = (Array.isArray(x.orderable_pid_list) && x.orderable_pid_list[0] && (x.orderable_pid_list[0].orderable_pid || x.orderable_pid_list[0].pid)) || x.base_pid_list || '';
  return { covered: yes, end: dateOf(x.coverage_end_date || x.covered_product_line_end_date), contract: s(x.service_contract_number, 60), service_level: s(x.service_line_descr, 120),
    warranty_end: dateOf(x.warranty_end_date), warranty_type: s(x.warranty_type, 60), pid: s(typeof pid === 'string' ? pid : '', 60), customer: s(x.contract_site_customer_name, 120) };
}
async function coverageFetch(o) {
  const req = o.request || httpc.request, entries = [];
  try {
    if (!ciscoAllowed('POST', o.token_url)) throw bad('token URL is not a Cisco OAuth token endpoint');
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: o.client_id, client_secret: o.client_secret }).toString();
    const t = await req(o.token_url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body, timeoutMs: 20000 });
    if (t.status === 401 || t.status === 400) throw Object.assign(new Error('Cisco refused the API client (check the client id / secret)'), { error_class: 'auth' });
    if (t.status !== 200 || !t.json || !t.json.access_token) throw Object.assign(new Error('token request failed (HTTP ' + t.status + ')'), { error_class: 'api' });
    const tok = t.json.access_token, serials = o.serials || [], per = o.per_call || PER_CALL;
    for (let i = 0; i < serials.length; i += per) {
      const part = serials.slice(i, i + per), url = o.base_url + '/sn2info/v2/coverage/summary/serial_numbers/' + part.join(',');
      if (!ciscoAllowed('GET', url)) throw bad('refused: not a coverage-summary call');
      const r = await req(url, { method: 'GET', headers: { Authorization: 'Bearer ' + tok, Accept: 'application/json' }, timeoutMs: 30000 });
      if (r.status === 401 || r.status === 403) throw Object.assign(new Error('Cisco refused the coverage call (HTTP ' + r.status + '): the API client needs the Serial Number to Information API'), { error_class: 'auth' });
      if (r.status !== 200 || !r.json) throw Object.assign(new Error('coverage call failed (HTTP ' + r.status + ')'), { error_class: 'api' });
      const seen = new Set();
      for (const x of Array.isArray(r.json.serial_numbers) ? r.json.serial_numbers : []) {
        if (!x || typeof x !== 'object') continue;   // one empty row must not lose the whole batch
        const sn = normSerial(x.sr_no); if (!sn || !part.includes(sn)) continue; seen.add(sn);
        if (x.ErrorResponse || x.error) { entries.push([sn, { covered: null, error: s((x.ErrorResponse && JSON.stringify(x.ErrorResponse)) || x.error, 200) }, 'unknown']); continue; }
        const v = apiRow(x); entries.push([sn, v, v.covered ? 'covered' : 'not_covered']);
      }
      for (const sn of part) if (!seen.has(sn)) entries.push([sn, { covered: null, error: 'Cisco returned nothing for this serial' }, 'unknown']);
    }
    return { entries };
  } catch (e) { return { entries, error: s(e.message, 300), error_class: e.error_class || 'network' }; }
}

// ---- Cisco PSIRT openVuln: which published security advisories affect a software version (IOS, IOS-XE, NX-OS, ASA).
// The same Cisco API client as the coverage check (its secret sealed here); the client must have the "Cisco PSIRT
// openVuln API" ticked in the Cisco API Console. Only version strings are sent to Cisco - no serial, name or address.
const VERSION_RE = /^[0-9][0-9A-Za-z.()_-]{0,39}$/;
// the OS type and the version as openVuln wants them: IOS-XE 16.x / 17.x without leading zeros ("17.09.04a" -> "17.9.4a")
function psirtKey(vendor, version, descr) {
  let v = String(version || '').trim(); if (!v || !VERSION_RE.test(v)) return null;
  const d = String(descr || '');
  let os = vendor === 'cisco-asa' || /Adaptive Security Appliance/i.test(d) ? 'asa' : /NX-OS/i.test(d) ? 'nxos' : (/IOS[\s-]?XE/i.test(d) || /^(16|17|3)\.\d/.test(v)) && !/\(/.test(v) ? 'iosxe' : 'ios';
  if (os === 'iosxe') v = v.split('.').map((x) => x.replace(/^0+(?=\d)/, '')).join('.');
  return { ostype: os, version: v, key: os + ':' + v };
}
function advRow(a) {
  const ff = Array.isArray(a.firstFixed) ? a.firstFixed : a.firstFixed ? [a.firstFixed] : [];
  const url = /^https:\/\/(sec\.cloudapps|tools|www)\.cisco\.com\//.test(String(a.publicationUrl || '')) ? s(a.publicationUrl, 300) : '';
  return { id: s(a.advisoryId, 80), title: s(a.advisoryTitle, 200), sir: s(a.sir, 20), cvss: a.cvssBaseScore != null && Number.isFinite(Number(a.cvssBaseScore)) ? Number(a.cvssBaseScore) : null,
    cves: (Array.isArray(a.cves) ? a.cves : []).map((c) => s(c, 30)).filter((c) => /^CVE-\d{4}-\d{3,}$/.test(c)).slice(0, 30), first_fixed: ff.map((x) => s(x, 40)).filter(Boolean).slice(0, 20),
    published: dateOf(a.firstPublished), updated: dateOf(a.lastUpdated), url };
}
async function psirtFetch(o) {
  const req = o.request || httpc.request, out = [];
  try {
    if (!ciscoAllowed('POST', o.token_url)) throw bad('token URL is not a Cisco OAuth token endpoint');
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: o.client_id, client_secret: o.client_secret }).toString();
    const t = await req(o.token_url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body, timeoutMs: 20000 });
    if (t.status === 401 || t.status === 400) throw Object.assign(new Error('Cisco refused the API client (check the client id / secret)'), { error_class: 'auth' });
    if (t.status !== 200 || !t.json || !t.json.access_token) throw Object.assign(new Error('token request failed (HTTP ' + t.status + ')'), { error_class: 'api' });
    for (const k of o.versions || []) {
      const url = o.base_url + '/security/advisories/v2/OSType/' + k.ostype + '?version=' + encodeURIComponent(k.version);
      if (!ciscoAllowed('GET', url) || !VERSION_RE.test(k.version)) { out.push({ key: k.key, error: 'refused: not a PSIRT version query' }); continue; }
      const r = await req(url, { method: 'GET', headers: { Authorization: 'Bearer ' + t.json.access_token, Accept: 'application/json' }, timeoutMs: 30000 });
      if (r.status === 401 || r.status === 403) throw Object.assign(new Error('Cisco refused the advisory call (HTTP ' + r.status + '): tick "Cisco PSIRT openVuln API" for this client in the Cisco API Console'), { error_class: 'auth' });
      if (r.status === 404 || (r.json && /NO_DATA_FOUND/i.test(JSON.stringify(r.json).slice(0, 300)))) { out.push({ key: k.key, advisories: [] }); continue; }   // openVuln answers 404 for "no advisory"
      if (r.status !== 200 || !r.json) { out.push({ key: k.key, error: 'advisory call failed (HTTP ' + r.status + ')' }); continue; }
      out.push({ key: k.key, advisories: (Array.isArray(r.json.advisories) ? r.json.advisories : []).filter((a) => a && typeof a === 'object').slice(0, 300).map(advRow) });
    }
    return { results: out };
  } catch (e) { return { results: out, error: s(e.message, 300), error_class: e.error_class || 'network' }; }
}

function createCiscoSupport(app, opts = {}) {
  const { store } = app, dc = app.config.discovery || {};
  const now = opts.now || Date.now, req = opts.request || httpc.request;
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-cisco-support' });
  const assets = store.collection('assets'), discDevices = store.collection('disc_devices'), cov = store.collection('cisco_coverage'), cfgCol = store.collection('cisco_support');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const st = { last_check: null, last_error: '', checked: 0 };
  let timer = null, running = null;

  function config() {
    const c = cfgCol.get('config') || { id: 'config' };
    c.api = Object.assign({ enabled: false, client_id: '', token_url: DEFAULT_TOKEN_URL, base_url: DEFAULT_BASE_URL, interval_h: 24 }, c.api || {});
    if (c.expiring_days == null) c.expiring_days = 90;
    if (c.include_phones == null) c.include_phones = false;
    return c;
  }
  function pubConfig() { const c = config(); return { api: { enabled: !!c.api.enabled, client_id: c.api.client_id, secret_set: !!c.api.enc, secret_at: c.api.secret_at || null, secret_by: c.api.secret_by || '', token_url: c.api.token_url, base_url: c.api.base_url, interval_h: c.api.interval_h, last_check: c.api.last_check || null, last_error: c.api.last_error || '' }, expiring_days: c.expiring_days, include_phones: c.include_phones, updated_by: c.updated_by || '', updated_at: c.updated_at || null }; }
  function httpsUrl(v, label) { let u; try { u = new URL(String(v)); } catch { throw bad(label + ' is not a valid URL'); } if (u.protocol !== 'https:' || u.username || u.password) throw bad(label + ' must be an https:// address without a login'); return u.origin + u.pathname.replace(/\/+$/, ''); }
  function saveConfig(b, who) {
    const c = config(), a = Object.assign({}, c.api), nb = b.api || {};
    let target = false;
    if (nb.client_id !== undefined) { const v = s(nb.client_id, 200); if (v !== a.client_id) target = true; a.client_id = v; }
    if (nb.token_url !== undefined) { const v = nb.token_url ? httpsUrl(nb.token_url, 'token URL') : DEFAULT_TOKEN_URL; if (v !== a.token_url) target = true; a.token_url = v; }
    if (nb.base_url !== undefined) { const v = nb.base_url ? httpsUrl(nb.base_url, 'API address') : DEFAULT_BASE_URL; if (v !== a.base_url) target = true; a.base_url = v; }
    if (nb.interval_h !== undefined) { const v = Number(nb.interval_h); if (!Number.isInteger(v) || v < 6 || v > 168) throw bad('check interval must be 6-168 hours'); a.interval_h = v; }
    if (nb.client_secret) { a.enc = sealer.seal('cisco-api', s(nb.client_secret, 500)); a.secret_at = iso(now()); a.secret_by = who.user; }
    else if (target && a.enc) { throw bad('the client id or an address changed: enter the client secret again'); }   // a saved secret never goes to a new place
    if (nb.enabled !== undefined) a.enabled = nb.enabled === true;
    if (a.enabled && (!a.client_id || !a.enc)) throw bad('the Cisco API needs a client id and a client secret');
    if (b.expiring_days !== undefined) { const v = Number(b.expiring_days); if (!Number.isInteger(v) || v < 7 || v > 365) throw bad('expiring window must be 7-365 days'); c.expiring_days = v; }
    if (b.include_phones !== undefined) c.include_phones = b.include_phones === true;
    c.api = a; c.updated_by = who.user; c.updated_at = iso(now()); cfgCol.put(c);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'cisco.config', target: 'cisco-support', detail: { api_enabled: a.enabled, client_id: a.client_id, secret_changed: !!nb.client_secret, expiring_days: c.expiring_days } });
    start();
    return pubConfig();
  }

  /* ---- contracts by serial */
  function put(serial, src, data, who) {
    const id = normSerial(serial); if (!id) return null;
    const cur = cov.get(id) || { id, serial: id, sources: {}, created_at: iso(now()) };
    cur.sources = Object.assign({}, cur.sources, { [src]: Object.assign({ at: iso(now()), by: who.user }, data) });
    cur.updated_at = iso(now()); cov.put(cur); return cur;
  }
  function importText(b, who) {
    const text = String(b.text || ''); if (!text.trim()) throw bad('no file content');
    if (text.length > 7 * 1024 * 1024) throw bad('file too large (max 7 MB) - split it');
    const p = parseExport(text);
    if (!p.columns.serial) throw bad('no serial-number column found (expected a header such as "Serial Number"); save the export as CSV');
    if (!p.columns.end && !p.columns.contract) throw bad('no contract number or coverage end date column found');
    let imported = 0, updated = 0; const skipped = [], file = s(b.filename, 120);
    p.rows.forEach((r, i) => {
      const line = p.header_line + i + 1, sn = normSerial(r[p.columns.serial]);
      if (!sn) { if (Object.values(r).some((v) => String(v).trim())) skipped.push({ line, reason: 'no serial number' }); return; }
      const end = p.columns.end ? dateOf(r[p.columns.end]) : null;
      if (p.columns.end && r[p.columns.end] && !end) { skipped.push({ line, serial: sn, reason: 'coverage end date not understood: ' + s(r[p.columns.end], 40) }); return; }
      const had = !!(cov.get(sn) && cov.get(sn).sources.import);
      put(sn, 'import', { contract: s(r[p.columns.contract], 60), service_level: s(r[p.columns.service_level], 120), start: p.columns.start ? dateOf(r[p.columns.start]) : null, end, pid: s(r[p.columns.pid], 60), site_name: s(r[p.columns.site_name], 120), file }, who);
      if (had) updated++; else imported++;
    });
    const known = new Set(assets.all().map((a) => normSerial(a.serial)).filter(Boolean));
    const unmatched = cov.all((c) => c.sources.import && !known.has(c.id)).length;
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'cisco.import', target: file || 'contract export', detail: { rows: p.rows.length, imported, updated, skipped: skipped.length } });
    return { rows: p.rows.length, imported, updated, skipped: skipped.slice(0, 200), skipped_total: skipped.length, columns: p.columns, header_line: p.header_line, unmatched_serials: unmatched };
  }
  function assign(b, who) {
    const a = assets.get(s(b.asset_id, 60)); if (!a) throw bad('asset not found', 404);
    const sn = normSerial(a.serial); if (!sn) throw bad('this asset has no serial number: record it first (contracts are matched by serial)');
    const end = dateOf(b.end); if (!end) throw bad('coverage end date required (YYYY-MM-DD)');
    const contract = s(b.contract, 60); if (!contract) throw bad('contract number required');
    put(sn, 'manual', { contract, service_level: s(b.service_level, 120), start: dateOf(b.start), end, asset_id: a.id }, who);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'cisco.assign', target: a.id, detail: { serial: sn, contract, end } });
    return row(a, config());
  }
  function unassign(b, who) {
    const sn = normSerial(b.serial), c = cov.get(sn); if (!c) throw bad('no contract recorded for that serial', 404);
    const src = b.source === 'import' ? 'import' : 'manual'; if (!c.sources[src]) throw bad('no ' + src + ' contract for that serial', 404);
    delete c.sources[src]; c.updated_at = iso(now());
    if (!Object.keys(c.sources).length) cov.remove(sn); else cov.put(c);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'cisco.unassign', target: sn, detail: { source: src } });
    return { ok: true };
  }

  /* ---- Cisco Support API (serial numbers only): the exchange runs in Python (pyengine/cisco_api.py); config
     cisco_support.engine = "node", an injected request (tests) or no Python → coverageFetch() above */
  const py = opts.request || ((app.config && app.config.cisco_support) || {}).engine === 'node' ? null : (() => { try { return require('./pyengine').createPyEngine({ python: dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3' }); } catch (e) { return null; } })();
  async function fetchCoverage(q) {
    if (py) { const r = await py.call('cisco.coverage', q); if (!(r && r.error_class === 'missing_python')) return Object.assign(r || { entries: [] }, { engine: 'python' }); }
    return Object.assign(await coverageFetch(Object.assign({ request: req }, q)), { engine: 'node' });
  }
  async function check(who = SYS) {
    if (running) return running;
    running = (async () => {
      const c = config();
      if (!c.api.enabled || !c.api.enc) return { ok: false, error: 'the Cisco API is not configured', error_class: 'config' };
      const serials = [...new Set(assets.all((a) => isCisco(a, c.include_phones)).map((a) => normSerial(a.serial)).filter(Boolean))];
      const out = { ok: true, serials: serials.length, checked: 0, covered: 0, not_covered: 0, unknown: 0 };
      const q = { token_url: c.api.token_url, base_url: c.api.base_url, client_id: c.api.client_id, client_secret: sealer.unseal('cisco-api', c.api.enc), serials, per_call: PER_CALL };
      const r = await fetchCoverage(q); q.client_secret = null;
      for (const [sn, v, kind] of r.entries || []) {
        put(sn, 'api', v, who);
        if (kind === 'unknown') out.unknown++; else { out.checked++; if (kind === 'covered') out.covered++; else out.not_covered++; }
      }
      if (r.error) { out.ok = false; out.error = r.error; out.error_class = r.error_class || 'network'; c.api.last_error = out.error; } else c.api.last_error = '';
      out.engine = r.engine;
      c.api.last_check = iso(now()); cfgCol.put(c); st.last_check = c.api.last_check;
      if (who !== SYS || !out.ok) audit({ by: who.user, role: who.role, ip: who.ip, action: 'cisco.check', target: 'cisco-api', detail: out });
      return out;
    })();
    try { return await running; } finally { running = null; }
  }

  /* ---- assessment */
  function effective(c) {
    if (!c) return null;
    const S = c.sources, api = S.api && S.api.covered != null ? S.api : null, rec = S.manual || S.import || null;
    return { api, rec, any: api || rec };
  }
  function row(a, cf) {
    const sn = normSerial(a.serial), c = sn ? cov.get(sn) : null, e = effective(c), today = new Date(now()).toISOString().slice(0, 10);
    const r = { asset_id: a.id, name: a.name || a.asset_tag || a.id, type: a.type, vendor: a.vendor || '', model: a.model || '', site: a.site || a.location || '', mgmt_ip: a.mgmt_ip || '', serial: sn,
      status: 'not-assigned', contract: '', service_level: '', end: null, days_left: null, source: '', validated_at: null, validated: false, notes: [] };
    if (!sn) { r.status = 'no-serial'; r.notes.push('No serial number on the asset: read it from the device (AI Network Engineer → device → read model / serial, SNMP discovery, or UCS / vCenter) or type it in.'); return r; }
    if (!e || !e.any) { r.notes.push('No contract known for this serial: import the Smart Net export or assign the contract.'); return r; }
    const rec = e.rec, api = e.api;
    r.contract = (api && api.contract) || (rec && rec.contract) || ''; r.service_level = (api && api.service_level) || (rec && rec.service_level) || '';
    r.end = (api && api.end) || (rec && rec.end) || null; r.source = c.sources.manual ? 'manual' : c.sources.import ? 'import' : 'api';
    if (api) { r.validated_at = api.at; r.validated = (now() - Date.parse(api.at)) < 8 * DAY; }
    if (api && api.covered === false) {
      r.status = 'not-covered'; r.notes.push('Cisco reports this serial is not covered' + (rec && rec.contract ? ` - the ${r.source} record says contract ${rec.contract}: mismatch, check with the Cisco partner` : '') + '.');
      if (api.warranty_end && api.warranty_end >= today) r.notes.push(`Hardware warranty (${api.warranty_type || 'warranty'}) until ${api.warranty_end}.`);
      return r;
    }
    if (rec && api && rec.contract && api.contract && rec.contract !== api.contract) r.notes.push(`Cisco reports contract ${api.contract}; the ${r.source} record says ${rec.contract}.`);
    if (c.sources.api && c.sources.api.covered == null && c.sources.api.error) r.notes.push('Cisco check: ' + c.sources.api.error);
    if (!api) r.notes.push('Not validated with Cisco yet' + (config().api.enabled ? ' (next check: run "Check with Cisco")' : ' (Cisco API not configured)') + '.');
    if (!r.end) { r.status = 'covered'; r.notes.push('No end date known.'); return r; }
    r.days_left = Math.round((Date.parse(r.end + 'T00:00:00Z') - Date.parse(today + 'T00:00:00Z')) / DAY);
    r.status = r.days_left < 0 ? 'expired' : r.days_left <= cf.expiring_days ? 'expiring' : 'covered';
    return r;
  }
  function report() {
    const cf = config(), list = assets.all((a) => isCisco(a, cf.include_phones)), rows = list.map((a) => row(a, cf));
    const order = { expired: 0, 'not-covered': 1, expiring: 2, 'not-assigned': 3, 'no-serial': 4, covered: 5 };
    rows.sort((x, y) => order[x.status] - order[y.status] || (x.days_left ?? 1e9) - (y.days_left ?? 1e9) || x.name.localeCompare(y.name));
    const counts = {}; for (const r of rows) counts[r.status] = (counts[r.status] || 0) + 1;
    const known = new Set(assets.all().map((a) => normSerial(a.serial)).filter(Boolean));
    const unmatched = cov.all((c) => !known.has(c.id)).map((c) => { const e = effective(c), x = (e && e.any) || {}; return { serial: c.id, contract: x.contract || '', end: x.end || null, pid: x.pid || '', site_name: x.site_name || '' }; }).slice(0, 500);
    // Cisco devices the platform knows that are NOT in the list: assets excluded (with the reason) and devices waiting in
    // Asset Discovery (e.g. switches the network team added in the AI Network Engineer come back here for approval)
    const excluded = assets.all((a) => looksCisco(a) && !isCisco(a, cf.include_phones) && !CLOSED[a.status] && !(a.type === 'phone' && !cf.include_phones))
      .map((a) => ({ asset_id: a.id, name: a.name || a.asset_tag || a.id, type: a.type, model: a.model || '', serial: normSerial(a.serial), why: whyNot(a, cf.include_phones) })).slice(0, 500);
    const NET_CLASS = ['switch', 'router', 'firewall', 'ap', 'unknown', 'server', 'storage', ''];
    const waiting = discDevices.all((d) => d.status === 'new' && !d.asset_id && NET_CLASS.includes(d.type || '') && looksCisco(d))
      .map((d) => ({ device_id: d.id, name: d.hostname || d.fqdn || d.ip || d.id, ip: d.ip || '', model: d.model || '', serial: normSerial(d.serial), class: d.type || '', seen_by: Object.keys(d.methods || {}), last_seen: d.last_seen || null }))
      .sort((x, y) => x.name.localeCompare(y.name)).slice(0, 500);
    return { at: iso(now()), expiring_days: cf.expiring_days, counts, total: rows.length, validated: rows.filter((r) => r.validated).length, rows, unmatched_contracts: unmatched, excluded, waiting, api: pubConfig().api };
  }
  function coverage(q = {}) {
    const cf = config(), sn = normSerial(q.serial), ip = s(q.ip, 45), name = s(q.name, 120).toLowerCase();
    const a = assets.all((x) => !CLOSED[x.status] && ((sn && normSerial(x.serial) === sn) || (ip && x.mgmt_ip === ip) || (name && String(x.name || '').toLowerCase() === name)))[0];
    if (!a) return { found: false };
    const r = row(a, cf);
    const tac = r.status === 'covered' || r.status === 'expiring'
      ? { open_at: 'https://mycase.cloudapps.cisco.com/case', serial: r.serial, contract: r.contract, service_level: r.service_level, pid: a.model || '', note: 'Open the case in Support Case Manager with this serial and contract; attach "show tech-support" (switch / router) or the UCS tech-support bundle.' }
      : null;
    return { found: true, cisco: isCisco(a, true), device: r, tac };
  }
  /* ---- PSIRT: the Cisco devices of the AI Network Engineer (SIEM) → their software versions → advisories per version */
  const psCol = store.collection('cisco_psirt'), SEVN = { Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 };
  async function netDevices() {
    if (opts.siemDevices) return opts.siemDevices();
    const siem = app.discovery && app.discovery.siem;
    if (!siem || typeof siem.call !== 'function') throw bad('the SIEM link is not configured (the Cisco devices live in the AI Network Engineer)', 409);
    let r; try { r = await siem.call('GET', '/netops/devices', SYS); } catch (e) { throw bad('the AI Network Engineer (SIEM) is not reachable: ' + s(e.message, 160), 409); }
    if (!r || r.status !== 200 || !r.json) throw bad('the AI Network Engineer did not answer (HTTP ' + (r && r.status) + ') - check the SIEM link and that the SIEM is updated', 409);
    return (r.json.items || []);
  }
  function deviceKeys(items) {
    return items.filter((d) => d.vendor === 'cisco-ios' || d.vendor === 'cisco-asa').map((d) => {
      const f = d.cli_facts || {}, sys = (d.last && d.last.system) || {}, sv = (/Version\s+([0-9][^\s,]*)/i.exec(String(sys.version || '')) || [])[1];
      const k = psirtKey(d.vendor, f.version || sv, sys.version);
      return { id: s(d.id, 80), name: s(d.name || d.id, 120), vendor: d.vendor, ostype: k ? k.ostype : null, version: k ? k.version : null, key: k ? k.key : null };
    });
  }
  function psirtView() {
    const rows = psCol.all(), meta = (cfgCol.get('psirt_meta') || {});
    const versions = rows.filter((r) => r.id !== 'psirt_meta').map((r) => { const A = r.advisories || [], sev = {}; for (const a of A) sev[a.sir] = (sev[a.sir] || 0) + 1;
      return { key: r.id, ostype: r.ostype, version: r.version, at: r.at, error: r.error || null, count: A.length, by_sir: sev, worst: A.reduce((w, a) => (SEVN[a.sir] > (SEVN[w] == null ? -1 : SEVN[w]) ? a.sir : w), null),
        advisories: A.slice().sort((a, b) => (SEVN[b.sir] || 0) - (SEVN[a.sir] || 0) || (b.cvss || 0) - (a.cvss || 0)) }; });
    return { api: { enabled: !!config().api.enabled, secret_set: !!config().api.enc }, last_check: meta.at || null, last_error: meta.error || null, devices: meta.devices || [], versions,
      note: 'Advisories that Cisco PSIRT lists for each software version. A device is exposed only if the affected feature is in use: read each advisory before planning the upgrade.' };
  }
  let psRunning = null;
  async function psirtCheck(who = SYS) {
    if (psRunning) return psRunning;
    psRunning = (async () => {
      const c = config();
      if (!c.api.enabled || !c.api.enc) throw bad('the Cisco API is not configured: Support Contracts → Cisco API (client ID and secret, with "Cisco PSIRT openVuln API" ticked in the Cisco API Console)', 409);
      const devs = deviceKeys(await netDevices()), uniq = {};
      for (const d of devs) if (d.key) uniq[d.key] = { key: d.key, ostype: d.ostype, version: d.version };
      const versions = Object.values(uniq).slice(0, 200);
      const q = { token_url: c.api.token_url, base_url: c.api.base_url, client_id: c.api.client_id, client_secret: sealer.unseal('cisco-api', c.api.enc), versions, request: req };
      const r = await psirtFetch(q); q.client_secret = null;
      const at = iso(now());
      for (const x of r.results) { const v = uniq[x.key]; if (!v) continue; psCol.put({ id: x.key, ostype: v.ostype, version: v.version, at, advisories: x.advisories || (psCol.get(x.key) || {}).advisories || [], error: x.error || null }); }
      const out = { ok: !r.error, devices: devs.length, versions: versions.length, without_version: devs.filter((d) => !d.key).length, checked: r.results.filter((x) => !x.error).length,
        advisories: r.results.reduce((n, x) => n + ((x.advisories || []).length), 0), error: r.error || null, error_class: r.error_class || null };
      cfgCol.put({ id: 'psirt_meta', at, error: r.error || null, devices: devs });
      audit({ by: who.user, role: who.role, ip: who.ip, action: 'cisco.psirt.check', target: 'cisco-psirt', detail: { devices: out.devices, versions: out.versions, advisories: out.advisories, error: out.error } });
      return out;
    })();
    try { return await psRunning; } finally { psRunning = null; }
  }
  function status() { const r = report(); return { config: pubConfig(), counts: r.counts, total: r.total, validated: r.validated, unmatched_contracts: r.unmatched_contracts.length }; }
  function start() { if (timer) clearInterval(timer); timer = null; const c = config(); if (!c.api.enabled || opts.noTimer) return; timer = setInterval(guardOf(app, 'cisco-support.check', () => check()), c.api.interval_h * 3600000); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { config: pubConfig, saveConfig, importText, assign, unassign, check, report, coverage, status, start, stop, isCisco, parseExport, dateOf, psirtView, psirtCheck };
}

function registerCiscoSupport(srv, app) {
  const C = createCiscoSupport(app);
  (app.addons = app.addons || {}).ciscoSupport = C;
  srv.route('GET', '/cisco-support/status', (ctx) => void ctx.need('viewer') || C.status());
  srv.route('GET', '/cisco-support/report', (ctx) => void ctx.need('viewer') || C.report());
  srv.route('GET', '/cisco-support/coverage', (ctx) => void ctx.need('viewer') || C.coverage(ctx.query || {}));
  srv.route('POST', '/cisco-support/import', (ctx) => { ctx.need('operator'); return C.importText(ctx.body || {}, ctx.who); }, { maxBody: 8 * 1024 * 1024 });
  srv.route('POST', '/cisco-support/assign', (ctx) => { ctx.need('operator'); return C.assign(ctx.body || {}, ctx.who); });
  srv.route('POST', '/cisco-support/unassign', (ctx) => { ctx.need('operator'); return C.unassign(ctx.body || {}, ctx.who); });
  srv.route('POST', '/cisco-support/check', async (ctx) => { ctx.need('operator'); const r = await C.check(ctx.who); return { check: r, report: C.report() }; });
  srv.route('POST', '/cisco-support/config', (ctx) => { ctx.need('admin'); return C.saveConfig(ctx.body || {}, ctx.who); });
  // PSIRT advisories for the Cisco switches / routers / ASAs of the AI Network Engineer (only version strings go to Cisco)
  srv.route('GET', '/cisco-support/psirt', (ctx) => { ctx.need('viewer'); return C.psirtView(); });
  srv.route('POST', '/cisco-support/psirt/check', async (ctx) => { ctx.need('operator'); const r = await C.psirtCheck(ctx.who); return { check: r, psirt: C.psirtView() }; });
  C.start();
  return C;
}

module.exports = { createCiscoSupport, registerCiscoSupport, normSerial, dateOf, parseExport, isCisco, CISCO_CALLS, coverageFetch, apiRow, ciscoAllowed, psirtKey, psirtFetch, advRow };
