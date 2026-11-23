// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
/*
 * Baseline Hardening (Security -> Baseline Hardening, {P} = /api/itam): every IT asset in the register scanned against its
 * CIS benchmark, mapped to SAMA CSF 3.3.8 / NCA ECC 2-3 and the domain clause of each setting. Judged in Python
 * (pyengine/hardening_rules.py); this module only gathers the facts, all from READ-ONLY sources:
 *   Windows Server / Windows 11   the SIEM Windows agent's daily snapshot (agent 1.2+): SIEM GET /api/soc/hardening/snapshots;
 *   IIS / Hyper-V                 agent 1.3 adds their settings to the same snapshot where the role is installed
 *   Active Directory / Exchange   agent 1.4 adds the domain's settings on a domain controller, the organisation's on Exchange
 *   Oracle / SQL Server / PostgreSQL  fixed read-only SELECTs through the login Asset Discovery proved (inv-helper db_harden)
 *   Oracle Linux / Linux / Solaris the platform's SSH read (Servers / Database Servers, inv-helper.py ssh_health h_* commands)
 *   Cisco switches / routers       the running-config the SIEM captures (secrets removed): /audit/evidence/network/config/:id
 *   FortiGate / Palo Alto / ASA    the SIEM network poller's security findings: /audit/evidence/network
 *   ESXi / Nutanix / Proxmox       the virtualization connections, read-only (virt-capacity.js hardeningRead: vSphere
 *                                  RetrievePropertiesEx on HostSystem; Prism GET cluster / authconfig / remote_syslog_servers;
 *                                  Proxmox VE API token GET firewall / users / tfa / apt / certificates)
 * An asset with no source is NOT SCANNED and says what to connect - it is never counted as compliant. A failed check gives a
 * fix and a rollback for a person to run in a change window; nothing here changes a device.
 *
 * Routes: GET  /hardening                     viewer    summary + one row per asset (scores and counts, no settings)
 *         GET  /hardening/assets/:id          operator  the asset's checks with evidence (how a machine is defended)
 *         POST /hardening/scan                operator  read every source again now (audited)
 *         POST /hardening/script {asset_id, checks[]}  operator  fix + rollback script for the chosen failed checks (audited)
 * A daily job keeps the summary in hardening_history (trend and audit evidence: score, coverage, failures per day).
 */
const DAY = 86400000;
const CLOSED = { disposed: 1, retired: 1, lost: 1, stolen: 1, archived: 1 };
const CHECK_ID = /^[A-Z0-9-]{3,40}$/;
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const lc = (v) => String(v == null ? '' : v).trim().toLowerCase();
const ts = (v) => { const t = typeof v === 'number' ? v : Date.parse(v || ''); return Number.isFinite(t) ? t : 0; };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const SIEM_AS = { user: 'system:itam-hardening', role: 'analyst' };

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

// what kind of scan an asset gets, from the register (type, OS, vendor) and what Asset Discovery saw
function classify(a, devOs) {
  const os = lc(a.os) + ' ' + lc(devOs), vendor = lc(a.vendor) + ' ' + lc(a.model), type = lc(a.type);
  if (/fortigate|fortinet|fortios/.test(vendor + os)) return { kind: 'firewall', platform: 'fortigate' };
  if (/palo ?alto|pan-os/.test(vendor + os)) return { kind: 'firewall', platform: 'paloalto' };
  if (/\basa\b|adaptive security/.test(vendor + os)) return { kind: 'firewall', platform: 'cisco-asa' };
  if (/esxi|vmware esx\b/.test(os)) return { kind: 'esxi', platform: 'esxi' };
  if (/nutanix|\bahv\b/.test(os) || (/nutanix/.test(vendor) && type === 'server')) return { kind: 'nutanix', platform: 'nutanix' };
  if (/proxmox/.test(os + vendor)) return { kind: 'proxmox', platform: 'proxmox' };
  if (/hyper-v/.test(os)) return { kind: 'windows', platform: 'hyperv' };
  if (/xenserver|xcp-ng/.test(os)) return { kind: 'unsupported', platform: 'hypervisor' };
  if (/windows/.test(os)) {
    const client = /windows (10|11)\b/.test(os) || ['workstation', 'laptop', 'desktop'].includes(type);
    return { kind: 'windows', platform: client ? 'windows_client' : 'windows_server' };
  }
  if (/solaris|sunos/.test(os)) return { kind: 'unix', platform: 'solaris' };
  if (/oracle linux|\bol ?\d|oel/.test(os)) return { kind: 'unix', platform: 'oracle_linux' };
  if (/linux|red ?hat|rhel|centos|rocky|alma|ubuntu|debian|suse/.test(os)) return { kind: 'unix', platform: 'linux' };
  if (/cisco|ios/.test(vendor + os) && (type === 'network' || /ios/.test(os))) return { kind: 'ios', platform: 'cisco' };
  if (type === 'network') return { kind: 'ios', platform: 'network' };
  if (['server', 'vm', 'workstation', 'laptop', 'desktop'].includes(type)) return { kind: 'unknown', platform: 'unknown' };
  return null;
}

const WHY = {
  windows: 'no hardening snapshot from the SIEM Windows agent - install or update the agent (1.2 or later) on this machine; it sends one a day',
  unix: 'no SSH read of this server - give it a read-only SSH login and trust its host key (Servers & Virtualization -> Solaris / Oracle Linux)',
  ios: 'the running-config is not captured - add an SSH login and trust the host key in Network Engineer -> Devices',
  firewall: 'not in the SIEM network inventory - add the firewall with a read-only API key in Network Engineer -> Devices',
  esxi: 'no hardening read of this ESXi host yet - it is read through its vCenter or standalone-host connection (Virtualization, or a vCenter scope in Asset Discovery) with a read-only role; press Scan now',
  proxmox: 'no hardening read of this Proxmox node yet - add the Proxmox VE connection on Virtualization (API token with the PVEAuditor role) and press Scan now',
  nutanix: 'no hardening read of this Nutanix host yet - it is read through its Prism connection (Virtualization, or a Nutanix scope in Asset Discovery); press Scan now',
  unsupported: 'this hypervisor\'s baseline is not part of this scan yet - listed so the gap is visible',
  unknown: 'the operating system is not known - set it on the asset (or let Asset Discovery read it) so the right benchmark applies',
};

function createHardening(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const assets = store.collection('assets'), devs = store.collection('disc_devices'), hist = store.collection('hardening_history');
  const osSnaps = store.collection('server_os_health'), dbSnaps = store.collection('db_server_health');
  const lg = app.log || { info() {}, warn() {} };
  const every = (key, msg, extra) => { try { if (lg.every) lg.every('hardening:' + key, 600000, 'warn', msg, extra); else lg.warn(msg, extra); } catch (e) { /* logging never stops the answer */ } };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || 'system:itam-hardening', role: (who && who.role) || 'system', ip: (who && who.ip) || '', action, target, detail }); };
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  let cache = null, running = null;

  async function siem(path) {
    if (opts.siem) return opts.siem(path);
    const L = app.discovery && app.discovery.siem; if (!L || typeof L.call !== 'function') return { _down: 'the SIEM link is not configured' };
    const r = await L.call('GET', path, SIEM_AS);
    if (!r) return { _down: 'the SIEM did not answer' };
    if (r.status === 404) return { _down: 'the SIEM has no ' + path.split('?')[0] + ' route yet - update the SIEM' };
    if (r.status !== 200) return { _down: 'SIEM ' + path.split('?')[0] + ': HTTP ' + r.status };
    return r.json || {};
  }

  async function gather() {
    const src = { windows: null, network: null };
    const win = await siem('/hardening/snapshots');
    if (win._down) src.windows = win._down; else if (win.available === false) src.windows = win.reason || 'not running on the SIEM';
    const winBy = new Map();
    for (const h of (win && win.hosts) || []) { const n = lc(h.host); winBy.set(n, h); winBy.set(n.split('.')[0], h); if (h.ip) winBy.set(h.ip, h); }
    const net = await siem('/audit/evidence/network');
    if (net._down) src.network = net._down; else if (net.available === false) src.network = net.reason || 'network inventory not available';
    const netBy = new Map();
    for (const d of (net && net.devices) || []) { if (d.ip) netBy.set(d.ip, d); if (d.name) netBy.set(lc(d.name), d); }

    const devBy = new Map();
    for (const d of devs.all((x) => x.asset_id)) { const o = devBy.get(d.asset_id); if (!o || ts(d.last_seen) > ts(o.last_seen)) devBy.set(d.asset_id, d); }
    // ESXi / Nutanix: the facts the read-only virtualization read keeps per platform (virt-capacity.js hardeningRead), matched
    // to the asset by the platform's own id first (Asset Discovery uid), then the host name, then the address
    const CAP = app.addons && app.addons.virtCapacity, vfacts = opts.virtFacts ? opts.virtFacts() : (CAP && typeof CAP.hardeningFacts === 'function' ? CAP.hardeningFacts() : []);
    src.virtualization = CAP || opts.virtFacts ? null : 'the virtualization capacity add-on is not installed';
    const hvBy = new Map(), hvErr = [];
    for (const p of vfacts) {
      if (p.error) hvErr.push(p.label + ': ' + p.error);
      for (const h of p.hosts || []) {
        const f = { kind: p.kind, platform_label: p.label, platform_error: p.error || null, at: p.error_at && !(p.hosts || []).length ? null : p.at, host: h, cluster: p.cluster || null, auth: p.auth || null, syslog: p.syslog || null };
        const n = lc(h.name), keys = p.kind === 'proxmox' ? ['pve-node:' + p.id + ':' + h.id, n, n.split('.')[0], h.ip] : p.kind === 'esxi' ? ['vc-host:' + p.id.replace(/^dv_/, '') + ':' + h.id, 'vc-host:' + p.id + ':' + h.id, n, n.split('.')[0], 'vc-host:' + h.id] : ['ntnx-host:' + h.id, n, n.split('.')[0], h.ip, h.cvm_ip];
        for (const k of keys) if (k && !hvBy.has(k)) hvBy.set(k, f);
      }
    }
    if (hvErr.length) src.virtualization = hvErr.slice(0, 4).join('; ');
    const dbBy = new Map(), dbIp = new Map();
    for (const d of dbCol.all(() => true)) { if (d.asset_id) (dbBy.get(d.asset_id) || dbBy.set(d.asset_id, []).get(d.asset_id)).push(d); else (dbIp.get(d.ip) || dbIp.set(d.ip, []).get(d.ip)).push(d); }
    const uidsOf = (id) => [].concat(...devs.all((d) => d.asset_id === id).map((d) => d.uids || (d.uid ? [d.uid] : [])));
    const out = [];
    for (const a of assets.all((x) => !CLOSED[x.status]).slice(0, 20000)) {
      const dev = devBy.get(a.id) || null, c = classify(a, dev && (dev.os || dev.os_version));
      if (!c) continue;
      const ip = a.mgmt_ip || (dev && dev.ip) || '', names = [lc(a.hostname), lc(a.name), lc(dev && dev.hostname)].filter(Boolean);
      const row = { id: a.id, name: s(a.name || a.hostname || a.id, 120), ip: s(ip, 64), platform: c.platform, kind: c.kind, site: s(a.site || a.location, 80), criticality: s(a.criticality, 20) };
      if (c.kind === 'windows') {
        const h = (ip && winBy.get(ip)) || names.map((n) => winBy.get(n) || winBy.get(n.split('.')[0])).find(Boolean);
        if (h) Object.assign(row, { data: h.settings, at: h.at }); else row.why = src.windows ? 'SIEM: ' + src.windows : WHY.windows;
      } else if (c.kind === 'unix') {
        const mine = osSnaps.get(a.id), theirs = ip ? dbSnaps.get(ip) : null;
        const r = [mine, theirs].filter((x) => x && x.server && x.server.harden).sort((x, y) => ts(y.at) - ts(x.at))[0];
        if (r) Object.assign(row, { data: r.server.harden, at: r.at });
        else row.why = (mine && mine.error) ? 'SSH read failed: ' + s(mine.error, 200) : (mine && mine.server) ? 'the last SSH read predates the hardening checks - it is refreshed on the next server read (Scan now on the Servers page)' : WHY.unix;
      } else if (c.kind === 'ios' || c.kind === 'firewall') {
        const d = (ip && netBy.get(ip)) || names.map((n) => netBy.get(n)).find(Boolean);
        if (!d) row.why = src.network ? 'SIEM: ' + src.network : WHY[c.kind];
        else if (c.kind === 'firewall' || ['fortigate', 'paloalto', 'cisco-asa'].includes(d.vendor)) {
          Object.assign(row, { kind: 'firewall', platform: d.vendor || c.platform, data: d, at: d.security_at || null });
        } else if (d.config && d.config.sha256) {
          const cf = await siem('/audit/evidence/network/config/' + encodeURIComponent(d.id));
          if (cf && cf.text) Object.assign(row, { platform: 'cisco', data: cf.text, at: cf.at }); else row.why = 'running-config not readable: ' + s(cf && cf._down, 160);
        } else row.why = (d.config && d.config.error) ? 'running-config not captured: ' + s(d.config.error, 160) : WHY.ios;
      } else if (c.kind === 'esxi' || c.kind === 'nutanix' || c.kind === 'proxmox') {
        const f = uidsOf(a.id).map((u) => hvBy.get(u)).find(Boolean) || names.map((n) => hvBy.get(n) || hvBy.get(n.split('.')[0])).find(Boolean) || (ip && hvBy.get(ip));
        if (f && f.at) Object.assign(row, { data: f, at: f.at });
        else row.why = f && f.platform_error ? 'read through ' + f.platform_label + ' failed: ' + s(f.platform_error, 200) : WHY[c.kind];
      } else row.why = WHY[c.kind] || WHY.unknown;
      const dbs = [...new Set((dbBy.get(a.id) || []).concat(ip ? dbIp.get(ip) || [] : []))];
      if (dbs.length) row.dbs = dbs.map((d) => ({ engine: d.engine, instance: d.instance || d.host || d.ip, port: d.port, login: d.login || null, at: d.at || null, error: d.error || null, results: d.results || null, errors: d.errors || {} }));
      // the role decides the card: a domain controller / Exchange server is scored with its AD / Exchange checks too (agent 1.4)
      const has = (k) => c.kind === 'windows' && row.data && row.data[k] && !row.data[k].error;
      if (has('ad')) row.platform = 'domain_controller'; else if (has('exchange')) row.platform = 'exchange'; else if (has('hyperv')) row.platform = 'hyperv';
      out.push(row);
    }
    return { assets: out, src };
  }

  async function assess(force) {
    if (!force && cache && now() - cache.at < 5 * 60000) return cache.v;
    if (running) return running;
    running = (async () => {
      const g = await gather();
      const r = await py().call('hardening.assess', { assets: g.assets, now: now(), max_age_days: Number((app.config && app.config.hardening && app.config.hardening.max_age_days) || 7) });
      if (!r || r.ok === false || !Array.isArray(r.assets)) {
        every('py', 'hardening: the rules (Python) did not answer', { cls: r && r.error_class, err: s(r && r.error, 200) });
        throw httpErr(409, 'The hardening rules run in Python and Python did not answer (' + ((r && r.error_class) || 'error') + ') - run the update so pyengine is installed');
      }
      const v = Object.assign(r, { generated_at: new Date(now()).toISOString(), sources: g.src });
      cache = { at: now(), v };
      return v;
    })().finally(() => { running = null; });
    return running;
  }

  async function view() {
    const v = await assess(false);
    const rows = v.assets.map((x) => ({ id: x.id, name: x.name, ip: x.ip, platform: x.platform, kind: x.kind, site: x.site, criticality: x.criticality, state: x.state, why: x.why || null, at: x.at, score: x.score, counts: x.counts }));
    const trend = hist.all(() => true).sort((a, b) => (a.id < b.id ? -1 : 1)).slice(-90).map((h) => ({ day: h.id, score: h.score, coverage_pct: h.coverage_pct, fail: h.fail }));
    return { generated_at: v.generated_at, summary: v.summary, sources: v.sources, assets: rows, trend };
  }
  async function one(id) {
    const v = await assess(false);
    const x = v.assets.find((a) => a.id === id); if (!x) throw httpErr(404, 'asset not in the hardening scope (not in the register, or not a server / workstation / network device)');
    return x;
  }
  // databases (Oracle, SQL Server, PostgreSQL): the read-only login Asset Discovery proved on each host (disc_devices
  // extra.db_login.<engine>) and the Oracle databases registered on the Databases page run the fixed SELECTs of
  // inv-helper.py op db_harden; kept per database in db_hardening (asset, instance, results, the queries the login may not run)
  const dbCol = store.collection('db_hardening'), DB_ENGINES = ['oracle', 'mssql', 'postgres'];
  let runHelper = null;
  const helper = () => opts.invRun || runHelper || (runHelper = require('./discovery/methods/login').realRunner(((app.config && app.config.discovery) || {}).python_bin || '/opt/sentra-siem/pyenv/bin/python3'));
  const dbTargets = () => require('./db-targets').dbTargets(app, { engines: DB_ENGINES });
  async function readDbs(who) {
    const V = app.discovery && app.discovery.vault, res = { at: new Date(now()).toISOString(), read: 0, failed: 0, targets: 0 };
    if (!V) return Object.assign(res, { note: 'Asset Discovery credential vault not available' });
    for (const t of dbTargets()) {
      res.targets++;
      let c = null, r = null;
      try {
        c = V.open(t.cred_id);
        const tg = c.target || {};
        r = await helper()({ op: 'db_harden', engine: t.engine, host: t.ip, port: t.port, username: c.secret.username, password: c.secret.password, service: t.service || tg.service, database: tg.database, tls: tg.tls || 'off', ca_file: tg.ca_file });
        t.user = String(c.secret.username || '').slice(0, 64);
      } catch (e) { r = { ok: false, error: e.message, error_class: 'error' }; }
      finally { if (c) try { c.release(); } catch (e) { /* the vault entry is released on its own at the end of the read */ } }
      const rec = { id: t.key, engine: t.engine, ip: t.ip, port: t.port, asset_id: t.asset_id, host: t.host, instance: t.instance, login: t.user || null };
      if (r && r.ok) { dbCol.put(Object.assign(rec, { at: res.at, error: null, results: r.results, errors: r.errors || {} })); res.read++; }
      else {
        res.failed++;
        const prev = dbCol.get(t.key) || {};
        dbCol.put(Object.assign({}, prev, rec, { error: s((r && r.error) || 'no answer', 200), error_class: (r && r.error_class) || 'error', error_at: res.at }));
        every('db:' + t.key, 'hardening: database read failed', { engine: t.engine, ip: t.ip, cls: r && r.error_class });
      }
    }
    if (who) audit(who, 'hardening.db.read', 'databases', res);
    return res;
  }
  async function readVirt(who) {
    const CAP = app.addons && app.addons.virtCapacity;
    if (opts.virtRead) return opts.virtRead(who);
    if (CAP && typeof CAP.hardeningRead === 'function') { try { return await CAP.hardeningRead(who); } catch (e) { every('virt', 'hardening: the ESXi / Nutanix read failed', { err: s(e.message, 200) }); } }
    return null;
  }
  async function scan(who) {
    const vr = await readVirt(who), dbr = await readDbs(who).catch((e) => ({ error: s(e.message, 200) }));
    const v = await assess(true);
    const virt = Array.isArray(vr) ? vr.map((r) => ({ label: r.label, ok: r.ok, hosts: r.hosts == null ? null : r.hosts, error: r.error || null })) : null;
    audit(who, 'hardening.scan', 'all', { assets: v.summary.assets, scanned: v.summary.scanned, score: v.summary.score, fail: v.summary.fail, virtualization: virt });
    record(v);
    return { generated_at: v.generated_at, summary: v.summary, virtualization: virt, databases: dbr };
  }
  async function script(input, who) {
    const b = body(input || {}).str('asset_id', { required: true, max: 80, id: true }).list('checks', { required: true, max: 60, item: 'str' }).done();
    const bad = b.checks.find((c) => !CHECK_ID.test(String(c)));
    if (bad !== undefined) throw httpErr(400, 'checks: "' + s(bad, 40) + '" is not a check id');
    const x = await one(b.asset_id);
    const chosen = x.checks.filter((c) => b.checks.includes(c.id) && c.state === 'fail');
    if (!chosen.length) throw httpErr(400, 'checks: none of the chosen checks failed on this asset - nothing to fix');
    const r = await py().call('hardening.script', { kind: x.kind, platform: x.platform, name: x.name, checks: chosen });
    if (!r || r.ok === false) throw httpErr(400, s(r && r.error, 200) || 'script not generated');
    audit(who, 'hardening.script', x.id, { name: x.name, checks: chosen.map((c) => c.id) });
    return { asset_id: x.id, name: x.name, kind: x.kind, checks: chosen.map((c) => c.id), script: r.script, sql: !!r.sql, os: r.os !== false };
  }
  function record(v) {
    const day = new Date(now() + 3 * 3600000).toISOString().slice(0, 10);   // Riyadh day
    const S = v.summary;
    hist.put({ id: day, at: new Date(now()).toISOString(), score: S.score, coverage_pct: S.coverage_pct, assets: S.assets, scanned: S.scanned, fail: S.fail, critical_fail: S.critical_fail });
  }
  let timer = null;
  const daily = guardOf(app, 'hardening.daily', async () => { await readVirt(null); await readDbs(null); const v = await assess(true); record(v); });
  function start() { if (!timer) { timer = setInterval(daily, 6 * 3600000); if (timer.unref) timer.unref(); setTimeout(daily, 120000).unref(); } }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  // an asset added / changed (asset-propagate.js): the next view re-reads the register instead of the 5-minute cache
  function refresh() { cache = null; return { ok: true }; }
  return { view, one, scan, script, assess, refresh, start, stop, classify };
}

function registerHardeningRoutes(srv, app, H) {
  srv.route('GET', '/hardening', (ctx) => { ctx.need('viewer'); return H.view(); });
  srv.route('GET', '/hardening/assets/:id', (ctx) => { ctx.need('operator'); return H.one(param(ctx.params.id, 'id')); });
  srv.route('POST', '/hardening/scan', (ctx) => { ctx.need('operator'); return H.scan(ctx.who); });
  srv.route('POST', '/hardening/script', (ctx) => { ctx.need('operator'); return H.script(ctx.body, ctx.who); });
}

module.exports = { createHardening, registerHardeningRoutes, classify };
