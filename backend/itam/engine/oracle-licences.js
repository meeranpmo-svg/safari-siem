// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const SR = require('./saferegex');
const { guardOf } = require('./errors');
/*
 * Databases -> Oracle Licence Inventory ({P} = /api/itam). Every Oracle Database deployment the platform knows, the physical
 * servers each one has to be licensed on, and the processor licences that needs - with the core factor matched from the
 * Oracle Processor Core Factor Table against each server's CPU model.
 *
 * Deployments: software inventory (core-licensing oracleOf), a person's entry, and every database the platform MONITORS
 *   (db-health): its edition is read from the database itself (V$VERSION banner: Enterprise / Standard Edition 2 / …) and
 *   written to the server's facts as oracle_detected, so Licence audit -> Core-based licences counts it too.
 * Core factor: CORE_FACTOR_TABLE (built in, as published by Oracle; an administrator can add rows for chips it does not list and
 *   override a built-in row - Oracle revises the table, the page links the current one). The row matched to the server's CPU
 *   text is written to its facts (core_factor, core_factor_src 'table', core_factor_row); a factor a PERSON enters for one server
 *   (with a reason) wins and is never replaced by a match. A CPU nothing matches keeps the default factor and is shown as
 *   ASSUMED - never as matched. Single-core chips are 1.0 (Oracle's rule for every single-core chip).
 * The licence arithmetic itself stays in core-licensing.js (and its Python twin): processor licences = physical cores x core
 *   factor rounded up per server, VMware = every host of the cluster / vCenter (soft partitioning), NUP minimum 25 per
 *   processor, SE2 = occupied sockets on servers of at most 2 sockets. This page shows it per database.
 * Compliance (below inventory()): the licence compliance matrix per product, over-utilisation / at-risk / expiry alerts, and a
 *   one-page report for the Infrastructure Manager and the DBA team, e-mailed on a new alert and once a month.
 * Routes: GET /oracle-licences (operator) · POST /oracle-licences/factor {asset_id, factor|null, reason} (operator, a person)
 *         GET /oracle-licences/compliance · GET /oracle-licences/report (operator) · POST /oracle-licences/report/send (operator)
 *         GET /oracle-licences/table (operator) · POST /oracle-licences/table {rows:[{id?, label, pattern, factor}]} (admin, a person)
 */
const SC = require('./approve-scopes');

const SOURCE_URL = 'https://www.oracle.com/assets/processor-core-factor-table-070634.pdf';
// Oracle Processor Core Factor Table - most specific first; the first row whose pattern matches the CPU text wins.
const CORE_FACTOR_TABLE = [
  { id: 'sparc-t1-low', label: 'Sun UltraSPARC T1 (1.0 / 1.2 GHz)', pattern: 'ultra\\s*sparc\\s*t1\\b.*\\b1\\.[02]\\s*ghz', factor: 0.25 },
  { id: 'sparc-t1', label: 'Sun UltraSPARC T1 (1.4 GHz)', pattern: 'ultra\\s*sparc\\s*t1\\b', factor: 0.5 },
  { id: 'ampere', label: 'Ampere Altra / Altra Max / AmpereOne (ARM)', pattern: '\\bampere\\s*(altra|one)\\b', factor: 0.25 },
  { id: 'sparc-t2', label: 'Sun UltraSPARC T2 / T2+', pattern: 'ultra\\s*sparc\\s*t2', factor: 0.5 },
  { id: 'sparc-modern', label: 'SPARC T3 / T4 / T5 / T7 / T8, M5 / M6 / M7 / M8, S7', pattern: '\\bsparc\\s*(t[345789]|m[5-8]|s7)\\b', factor: 0.5 },
  { id: 'sparc64-new', label: 'Fujitsu SPARC64 VII+ / X / X+ / XII', pattern: '\\bsparc\\s*64\\s*(vii\\+|x\\+?|xii)\\b|\\bsparc64\\s*(vii\\+|x\\+?|xii)\\b', factor: 0.5 },
  { id: 'sparc-old', label: 'Sun UltraSPARC III / IV / IV+, Fujitsu SPARC64 VI / VII', pattern: 'ultra\\s*sparc\\s*(iii|iv)|\\bsparc\\s*64\\s*vii?\\b|\\bsparc64\\s*vii?\\b', factor: 0.75 },
  { id: 'itanium-9300', label: 'Intel Itanium 9300 series or later', pattern: '\\bitanium\\b.*\\b9[3-9]\\d\\d\\b', factor: 0.5 },
  { id: 'itanium-old', label: 'Intel Itanium (before the 9300 series)', pattern: '\\bitanium\\b', factor: 1 },
  { id: 'ibm-power', label: 'IBM POWER (POWER5 and later)', pattern: '\\bpower\\s*(pc\\s*)?([5-9]|1[01])\\b|\\bibm\\b.*\\bpower\\b|\\bpower\\s*systems?\\b', factor: 1 },
  { id: 'ibm-z', label: 'IBM System z / LinuxONE', pattern: '\\b(system\\s*z|zseries|z\\d{2}|linuxone)\\b', factor: 1 },
  { id: 'pa-risc', label: 'HP PA-RISC', pattern: '\\bpa[\\s-]?risc\\b', factor: 0.75 },
  { id: 'intel-xeon', label: 'Intel Xeon (multicore) and other Intel x86-64', pattern: '\\bxeon\\b|\\bintel\\b', factor: 0.5 },
  { id: 'amd', label: 'AMD EPYC / Opteron (multicore x86-64)', pattern: '\\bepyc\\b|\\bopteron\\b|\\bamd\\b', factor: 0.5 },
];
const FACTORS = [0.25, 0.5, 0.75, 1];
const ORA_SW = /oracle.*database|oracle\s*db|oracle\s*\d+[cgi]\b/i;   // the same test as core-licensing.js oracleOf

function createOracleLicences(app, opts = {}) {
  const store = app.store, facts = store.collection('core_lic_facts'), assets = store.collection('assets'), tcol = store.collection('oracle_cf_table');
  const C = () => opts.coreLicensing || (app.addons && app.addons.coreLicensing) || null;
  const H = () => opts.dbHealth || (app.addons && app.addons.dbHealth) || null;
  const SV = () => opts.dbServers || (app.addons && app.addons.dbServers) || null;
  const now = opts.now || Date.now;
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || 'system:oracle-licences', role: (who && who.role) || 'system', ip: (who && who.ip) || '', action, target, detail }); };

  // the table in force: the administrator's rows first (custom chips, overrides of a built-in id), then the built-in rows
  function table() {
    const mine = ((tcol.get('rows') || {}).rows || []);
    const ids = new Set(mine.map((r) => r.id));
    return mine.map((r) => Object.assign({}, r, { custom: true })).concat(CORE_FACTOR_TABLE.filter((r) => !ids.has(r.id)).map((r) => Object.assign({}, r, { custom: false })));
  }
  const rx = new Map();
  function re(r) { const k = r.id + '|' + r.pattern; if (!rx.has(k)) { try { rx.set(k, new RegExp(SR.checkRegex(r.pattern), 'i')); } catch (e) { rx.set(k, null); } } return rx.get(k); }
  function match(cpu, coresPerSocket) {
    if (coresPerSocket === 1) return { factor: 1, row: 'single-core chip (every single-core chip is 1.0)', id: 'single-core' };
    const c = String(cpu || ''); if (!c.trim()) return null;
    for (const r of table()) { const x = re(r); if (x && x.test(c)) return { factor: r.factor, row: r.label, id: r.id }; }
    return null;
  }
  function setTable(b, who) {
    if (!SC.isHuman(who && who.user)) throw bad('only a person changes the core factor table', 403);
    const rows = Array.isArray(b && b.rows) ? b.rows : null; if (!rows || rows.length > 60) throw bad('rows: a list of up to 60 rows');
    const out = rows.map((r, i) => {
      const id = clip(r.id, 40) || 'custom-' + (i + 1), label = clip(r.label, 120), pattern = String(r.pattern || '').slice(0, 300), f = Number(r.factor);
      if (!label) throw bad(`row ${i + 1}: a label is required (the chip family as Oracle names it)`);
      if (!pattern) throw bad(`row ${i + 1}: a pattern is required`);
      try { new RegExp(pattern, 'i'); } catch (e) { throw bad(`row ${i + 1}: the pattern is not a valid regular expression`); }
      try { SR.checkRegex(pattern); } catch (e) { throw bad(`row ${i + 1}: ${e.message}`); }
      if (!FACTORS.includes(f)) throw bad(`row ${i + 1}: factor must be one of ${FACTORS.join(', ')}`);
      return { id, label, pattern, factor: f };
    });
    tcol.put({ id: 'rows', rows: out, by: who.user, at: new Date(now()).toISOString() });
    audit(who, 'oracle.core_factor.table', 'table', { rows: out.length, ids: out.map((r) => r.id) });
    sync();
    return { table: table(), source: SOURCE_URL };
  }

  // the monitored databases (db-health), each with the asset of the server it runs on and its edition read from the database
  function monitored() {
    const h = H(); if (!h) return [];
    const last = ((h.status && h.status().last) || {}).results || [];
    const out = [];
    for (const t of h.targets().list) {
      const r = last.find((x) => x.ip === t.ip && (x.credential === t.cred_label || !x.credential)) || last.find((x) => x.ip === t.ip) || {};
      let asset = null;
      try { const sv = SV(); if (sv && sv.resolveAsset) asset = (sv.resolveAsset({ ip: t.ip, host: t.host }) || {}).asset || null; } catch (e) { asset = null; }
      if (!asset && t.asset_id) asset = assets.get(t.asset_id) || null;
      if (!asset) asset = assets.all((a) => a.mgmt_ip === t.ip && !/retired|disposed/.test(a.status || ''))[0] || null;
      out.push({ key: t.key, label: t.host || t.ip, ip: t.ip, service: t.service || '', instance: r.instance || t.instance || '', version: r.version || '', edition: r.edition || '', banner: r.banner || '', role: r.role || '',
        read_ok: r.ok === true, read_at: ((h.status().last) || {}).at || null, asset_id: asset ? asset.id : null, asset_name: asset ? (asset.name || asset.id) : null });
    }
    return out;
  }
  // write what the platform learnt into the core-licensing facts: the matched core factor (never over a person's) and the
  // edition a monitored database reported (never over a person's oracle: ee / se2 / none)
  function sync() {
    let changed = 0; const t = new Date(now()).toISOString();
    for (const a of assets.all((x) => !/retired|disposed/.test(x.status || '') && x.type !== 'vm' && !(Array.isArray(x.tags) && x.tags.includes('vm')))) {
      const f = facts.get(a.id) || null; if (f && f.core_factor_src === 'entered') continue;
      const m = match(a.cpu, f && Number(f.cores_per_socket) ? Number(f.cores_per_socket) : null);
      const cur = f ? [f.core_factor, f.core_factor_row] : [undefined, undefined];
      if (m && (cur[0] !== m.factor || cur[1] !== m.row)) { facts.put(Object.assign({ id: a.id }, f || {}, { core_factor: m.factor, core_factor_src: 'table', core_factor_row: m.row, core_factor_at: t })); changed++; }
      else if (!m && f && f.core_factor_src === 'table') { const n = Object.assign({}, f); delete n.core_factor; delete n.core_factor_src; delete n.core_factor_row; delete n.core_factor_at; facts.put(n); changed++; }
    }
    for (const d of monitored()) {
      if (!d.asset_id || !d.edition) continue;
      const ed = d.edition === 'EE' ? 'ee' : d.edition === 'SE2' ? 'se2' : null; if (!ed) continue;
      const f = facts.get(d.asset_id) || { id: d.asset_id };
      if (f.oracle_detected !== ed) { facts.put(Object.assign({}, f, { oracle_detected: ed, oracle_detected_from: d.instance || d.label, oracle_detected_at: t })); changed++; }
    }
    return changed;
  }

  function setFactor(b, who) {
    if (!SC.isHuman(who && who.user)) throw bad('a person enters a core factor', 403);
    const a = assets.get(String((b && b.asset_id) || '')); if (!a) throw bad('server not found', 404);
    const reason = clip(b && b.reason, 300), f = facts.get(a.id) || { id: a.id }, n = Object.assign({}, f);
    if (b.factor === null || b.factor === '' || b.factor === undefined) { delete n.core_factor; delete n.core_factor_src; delete n.core_factor_row; delete n.core_factor_note; facts.put(n); sync(); audit(who, 'oracle.core_factor.clear', a.id, { server: a.name }); return inventory(); }
    const x = Number(b.factor); if (!FACTORS.includes(x)) throw bad('factor must be one of ' + FACTORS.join(', '));
    if (!reason) throw bad('say why (e.g. the chip and the Oracle table row, or the contract clause) - it is the audit evidence');
    facts.put(Object.assign(n, { core_factor: x, core_factor_src: 'entered', core_factor_row: 'entered by ' + who.user + ': ' + reason, core_factor_note: reason, updated_by: who.user, updated_at: new Date(now()).toISOString() }));
    audit(who, 'oracle.core_factor.set', a.id, { server: a.name, factor: x, reason, matched: (match(a.cpu) || {}).factor || null });
    return inventory();
  }

  function inventory() {
    sync();
    const c = C(); if (!c) throw bad('core licensing is not installed', 503);
    const v = c.view(), st = v.settings, hostsById = new Map(v.hosts.map((h) => [h.id, h]));
    const mon = monitored(), monBy = new Map(); for (const m of mon) if (m.asset_id) { const L = monBy.get(m.asset_id) || []; L.push(m); monBy.set(m.asset_id, L); }
    const ora = v.deployments.filter((d) => d.edition === 'ee' || d.edition === 'se2');
    const rows = ora.map((d) => {
      const scope = (d.scope || []).map((n) => v.hosts.find((h) => h.name === n)).filter(Boolean);
      const lic = scope.map((h) => d.edition === 'ee' ? { host: h.name, host_id: h.id, cpu: h.cpu, sockets: h.sockets, cores: h.cores, factor: h.factor, factor_source: h.factor_source, factor_row: h.factor_row, factor_assumed: h.factor_assumed, licences: h.cores ? Math.ceil(h.cores * h.factor) : null }
        : { host: h.name, host_id: h.id, cpu: h.cpu, sockets: h.sockets, cores: h.cores, licences: h.sockets || null, problem: h.sockets > 2 ? 'SE2 is allowed only on servers with at most 2 sockets' : null });
      const dbs = monBy.get(d.id) || (d.vm ? [] : monBy.get(d.host_id) || []);
      const f = facts.get(d.id) || {};
      return { id: d.id, name: d.name, edition: d.edition, vm: d.vm, physical_host: d.host_id && hostsById.get(d.host_id) ? hostsById.get(d.host_id).name : null,
        how: f.oracle === 'ee' || f.oracle === 'se2' ? 'entered by ' + (f.updated_by || 'a person') : ((assets.get(d.id) || {}).software || []).some((x) => ORA_SW.test(`${(x && x.publisher) || ''} ${(x && x.name) || x || ''}`)) ? 'software inventory' : f.oracle_detected === d.edition ? 'read from the database (' + (f.oracle_detected_from || '') + ')' : 'software inventory',
        databases: dbs.map((m) => ({ instance: m.instance, service: m.service, version: m.version, edition: m.edition, banner: m.banner, role: m.role })),
        scope: lic, problem: d.problem || null, licences: lic.every((x) => x.licences != null) ? lic.reduce((a, x) => a + x.licences, 0) : null };
    });
    // monitored databases that are NOT licensed anywhere yet: no asset, or an edition the page cannot place
    const unplaced = mon.filter((m) => !m.asset_id || !rows.some((r) => r.id === m.asset_id)).map((m) => ({ label: m.label, ip: m.ip, instance: m.instance, edition: m.edition || 'not read', asset: m.asset_name,
      why: !m.read_ok ? 'not read yet (Databases → test it)' : !m.asset_id ? 'its server is not in the asset register - link it (Databases → Database Servers)' : !m.edition ? 'the database did not say its edition (the banner names none; 11g Standard Edition does not) - set it on the server (oracle: ee / se2)' : m.edition === 'XE' || m.edition === 'FREE' || m.edition === 'PE' ? m.edition + ' needs no processor licence' : 'edition ' + m.edition + ' is not counted by processor here' }));
    const hostRows = [];
    const seen = new Set();
    for (const r of rows) for (const x of r.scope) { if (seen.has(r.edition + x.host_id)) continue; seen.add(r.edition + x.host_id); const h = hostsById.get(x.host_id) || {};
      hostRows.push(Object.assign({ edition: r.edition, esxi: !!h.esxi, cluster: h.cluster || '', cores_from: h.cores_from || null, cores_hint: h.cores_hint || null, matched: (match(h.cpu, h.cores_per_socket) || null) }, x)); }
    const sum = v.summary.filter((s) => s.product === 'oracle_ee' || s.product === 'oracle_se2');
    return { at: new Date(now()).toISOString(), settings: { oracle_scope: st.oracle_scope, core_factor: st.core_factor }, summary: sum, deployments: rows, hosts: hostRows, unplaced, monitored: mon,
      table: table(), table_source: SOURCE_URL, factors: FACTORS, entitlements: v.entitlements.filter((e) => e.product === 'oracle_ee' || e.product === 'oracle_se2'),
      totals: { deployments: rows.length, ee: rows.filter((r) => r.edition === 'ee').length, se2: rows.filter((r) => r.edition === 'se2').length, hosts: hostRows.length,
        factor_assumed: hostRows.filter((h) => h.factor_assumed).length, cores_unknown: hostRows.filter((h) => h.cores == null).length, unplaced: unplaced.length } };
  }
  /* ---- compliance matrix, over-utilisation alerts, the one-page report (Infrastructure manager + DBA) --------------------
   * Matrix: per product the metric, licences owned (valid entitlements), licences the deployments need, the difference and
   * utilisation (needed / owned). Levels: over (needed > owned), near (>= NEAR_PCT of owned), incomplete (cores unknown or
   * core factor assumed - the count may be UNDER-stated, so it is never called compliant), compliant, not used.
   * Alerts are kept with first / last seen; a new over-use (or SE2 on a server of more than 2 sockets, or an entitlement
   * ending within 90 days) is e-mailed once with the one-page report to the DBA recipients and the infrastructure managers
   * set on the Database Dashboard (through the SIEM's mail relay, as service identity system:itam-oracle-licences), and
   * reminded every 7 days while it stays open. The report is also sent on the configured day each month.
   */
  const NEAR_PCT = 90, REMIND_MS = 7 * 86400000;
  const alertCol = store.collection('ora_lic_alerts'), repCol = store.collection('ora_lic_reports');
  const LSYS = { user: 'system:itam-oracle-licences', role: 'admin', ip: '' };
  const D = () => opts.discovery || app.discovery || null;
  const rcfg = () => Object.assign({ report_day: 1, report_at: '08:00', mail: true }, (app.config && app.config.oracle_licences) || {});
  const ESC = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const METRIC = { ee: 'Processor: physical cores × core factor, per server', se2: 'Processor: occupied sockets (servers of at most 2 sockets)' };
  const LEVEL = { over: 'OVER-UTILISED', near: 'AT RISK', incomplete: 'INCOMPLETE', compliant: 'COMPLIANT', not_used: 'NOT USED' };

  function compliance(inv) {
    inv = inv || inventory();
    const matrix = inv.summary.map((s) => {
      const ed = s.product === 'oracle_ee' ? 'ee' : 'se2';
      const deps = inv.deployments.filter((d) => d.edition === ed), hs = inv.hosts.filter((h) => h.edition === ed);
      const assumed = ed === 'ee' ? hs.filter((h) => h.factor_assumed).length : 0, unknown = hs.filter((h) => ed === 'ee' ? h.cores == null : h.sockets == null).length;
      const util = s.owned ? Math.round(s.required / s.owned * 100) : null;
      const level = s.required > s.owned ? 'over' : s.owned && util >= NEAR_PCT ? 'near' : (unknown || assumed) && s.required ? 'incomplete' : !s.required && !s.owned ? 'not_used' : unknown || assumed ? 'incomplete' : 'compliant';
      return { product: s.product, name: s.name, edition: ed, metric: METRIC[ed], owned: s.owned, required: s.required, delta: s.owned - s.required, utilisation_pct: util, level, level_label: LEVEL[level],
        nup_minimum: ed === 'ee' ? s.required * 25 : hs.length * 10, deployments: deps.length, servers: hs.length, databases: deps.reduce((n, d) => n + d.databases.length, 0),
        factor_assumed: assumed, cores_unknown: unknown, expiring: s.expiring || [],
        entitlements: (inv.entitlements || []).filter((e) => e.product === s.product).map((e) => ({ id: e.id, quantity: e.quantity, contract: e.contract || '', expiry: e.expiry || null, days_left: e.days_left })) };
    });
    const alerts = [], add = (key, severity, title, action, owner) => alerts.push({ key, severity, title, action, owner });
    for (const m of matrix) {
      const top = inv.hosts.filter((h) => h.edition === m.edition && h.licences).sort((a, b) => b.licences - a.licences).slice(0, 3).map((h) => `${h.host} (${h.licences})`).join(', ');
      if (m.level === 'over') add('over:' + m.product, 'critical', `${m.name}: ${m.required} licences needed, ${m.owned} owned - over-utilised by ${m.required - m.owned}`, `Buy ${m.required - m.owned} more ${m.edition === 'ee' ? 'processor' : 'SE2 processor'} licences, or remove / consolidate Oracle from servers${top ? ' - largest: ' + top : ''}.`, 'Infrastructure manager');
      else if (m.level === 'near') add('near:' + m.product, 'warning', `${m.name}: ${m.utilisation_pct}% of owned licences in use (${m.required} of ${m.owned})`, 'Plan before adding Oracle to another server or adding cores - any new deployment will exceed what is owned.', 'Infrastructure manager');
      if (m.cores_unknown || m.factor_assumed) add('inc:' + m.product, 'info', `${m.name}: ${m.cores_unknown} server(s) with unknown ${m.edition === 'ee' ? 'cores' : 'sockets'}, ${m.factor_assumed} with an assumed core factor - the count may be under-stated`, 'Confirm the CPU model and cores of these servers (Oracle Licence Inventory → servers), so the number is evidence.', 'DBA');
      for (const e of m.expiring) add('exp:' + e.id, e.days_left <= 30 ? 'critical' : 'warning', `${m.name}: entitlement ${e.contract || e.id} ends ${e.expiry} (${e.days_left} days)`, 'Renew the support contract or plan the exit - an expired entitlement is not counted as owned.', 'Infrastructure manager');
    }
    for (const d of inv.deployments) for (const x of d.scope || []) if (x.problem) add('se2:' + x.host_id, 'critical', `${x.host}: ${x.problem}`, 'Move the database to a server of at most 2 sockets or license Enterprise Edition there.', 'DBA');
    for (const u of inv.unplaced || []) if (!/needs no processor licence/.test(u.why)) add('unp:' + u.ip + ':' + u.instance, 'info', `${u.label} ${u.instance || ''}: monitored but not counted - ${u.why}`, 'Place it so it is licensed (link the server / set its edition).', 'DBA');
    const SEVR = { critical: 3, warning: 2, info: 1 };
    alerts.sort((a, b) => SEVR[b.severity] - SEVR[a.severity]);
    const worst = matrix.some((m) => m.level === 'over') || alerts.some((a) => a.key.startsWith('se2:')) ? 'over' : matrix.some((m) => m.level === 'near') ? 'near' : matrix.some((m) => m.level === 'incomplete') ? 'incomplete' : matrix.every((m) => m.level === 'not_used') ? 'not_used' : 'compliant';
    return { at: inv.at, verdict: worst, verdict_label: LEVEL[worst], matrix, alerts, settings: inv.settings };
  }

  // the one A4 page: verdict, the matrix, what to do (with owner), the servers that drive the count, entitlements
  function reportOf(inv) {
    inv = inv || inventory();
    const c = compliance(inv), day = new Date(now() + 3 * 3600000).toISOString().slice(0, 10);
    const CLR = { over: '#c62828', near: '#b26a00', incomplete: '#555', compliant: '#2e7d32', not_used: '#777', critical: '#c62828', warning: '#b26a00', info: '#555' };
    const hosts = inv.hosts.filter((h) => h.licences).sort((a, b) => b.licences - a.licences).slice(0, 8);
    const td = 'style="padding:4px 6px;border-bottom:1px solid #ddd"', th = 'style="padding:4px 6px;border-bottom:2px solid #333;text-align:left"';
    const num = (v) => (v == null ? '—' : String(v));
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#111;max-width:780px">`
      + `<div style="display:flex;justify-content:space-between;align-items:baseline;border-bottom:3px solid #111;padding-bottom:6px"><div><div style="font-size:18px;font-weight:700">Oracle Licence Compliance</div><div style="color:#555">For the Infrastructure Manager and the DBA team · ${ESC(day)}</div></div>`
      + `<div style="font-size:16px;font-weight:700;color:${CLR[c.verdict]}">${ESC(c.verdict_label)}</div></div>`
      + `<h3 style="font-size:13px;margin:12px 0 4px">Compliance matrix</h3><table style="border-collapse:collapse;width:100%"><thead><tr><th ${th}>Product</th><th ${th}>Metric</th><th ${th}>Owned</th><th ${th}>Needed</th><th ${th}>Difference</th><th ${th}>Use</th><th ${th}>Status</th></tr></thead><tbody>`
      + c.matrix.map((m) => `<tr><td ${td}><b>${ESC(m.name)}</b><div style="color:#666">${m.deployments} deployment(s) · ${m.servers} server(s) · ${m.databases} database(s)</div></td><td ${td}>${ESC(m.metric)}</td><td ${td}>${num(m.owned)}</td><td ${td}>${num(m.required)}</td><td style="padding:4px 6px;border-bottom:1px solid #ddd;color:${m.delta < 0 ? '#c62828' : '#111'};font-weight:${m.delta < 0 ? 700 : 400}">${m.delta >= 0 ? '+' : ''}${m.delta}</td><td ${td}>${m.utilisation_pct == null ? (m.required ? 'none owned' : '—') : m.utilisation_pct + '%'}</td><td style="padding:4px 6px;border-bottom:1px solid #ddd;color:${CLR[m.level]};font-weight:700">${ESC(m.level_label)}</td></tr>`).join('')
      + `</tbody></table><div style="color:#666;margin-top:3px">Named User Plus minimum if licensed per user: ${c.matrix.map((m) => `${m.edition.toUpperCase()} ${m.nup_minimum}`).join(' · ')}. VMware scope: ${ESC(c.settings.oracle_scope)} (soft partitioning: every host the VM can run on).</div>`
      + `<h3 style="font-size:13px;margin:12px 0 4px">Alerts and actions</h3>` + (c.alerts.length ? `<table style="border-collapse:collapse;width:100%"><tbody>` + c.alerts.slice(0, 7).map((a) => `<tr><td style="padding:4px 6px;border-bottom:1px solid #ddd;color:${CLR[a.severity]};font-weight:700;white-space:nowrap">${ESC(a.severity.toUpperCase())}</td><td ${td}>${ESC(a.title)}<div style="color:#444">${ESC(a.action)}</div></td><td style="padding:4px 6px;border-bottom:1px solid #ddd;white-space:nowrap">${ESC(a.owner)}</td></tr>`).join('') + `</tbody></table>${c.alerts.length > 7 ? `<div style="color:#666">+ ${c.alerts.length - 7} more on the Oracle Licence Inventory page.</div>` : ''}` : `<p style="color:#2e7d32;margin:0">No alert.</p>`)
      + `<h3 style="font-size:13px;margin:12px 0 4px">Servers that drive the count</h3>` + (hosts.length ? `<table style="border-collapse:collapse;width:100%"><thead><tr><th ${th}>Server</th><th ${th}>Edition</th><th ${th}>CPU</th><th ${th}>Cores / sockets</th><th ${th}>Factor</th><th ${th}>Licences</th></tr></thead><tbody>` + hosts.map((h) => `<tr><td ${td}>${ESC(h.host)}${h.esxi ? ' (ESXi' + (h.cluster ? ' · ' + ESC(h.cluster) : '') + ')' : ''}</td><td ${td}>${h.edition === 'ee' ? 'EE' : 'SE2'}</td><td ${td}>${ESC(String(h.cpu || '—').slice(0, 48))}</td><td ${td}>${h.edition === 'ee' ? num(h.cores) + ' cores' : num(h.sockets) + ' socket(s)'}</td><td ${td}>${h.edition === 'ee' ? ESC(h.factor) + (h.factor_assumed ? ' (assumed)' : '') : '—'}</td><td ${td}><b>${num(h.licences)}</b></td></tr>`).join('') + `</tbody></table>` : `<p style="color:#666;margin:0">No server to license.</p>`)
      + `<h3 style="font-size:13px;margin:12px 0 4px">Entitlements</h3>` + (c.matrix.some((m) => m.entitlements.length) ? c.matrix.filter((m) => m.entitlements.length).map((m) => `<div><b>${ESC(m.name)}:</b> ${m.entitlements.map((e) => `${ESC(e.quantity)} × ${ESC(e.contract || e.id)}${e.expiry ? ' until ' + ESC(e.expiry) + (e.days_left != null && e.days_left < 0 ? ' (EXPIRED - not counted)' : '') : ''}`).join('; ')}</div>`).join('') : `<p style="color:#c62828;margin:0">No entitlement recorded - every deployment counts as unlicensed. Enter what is owned in Licence audit → Core-based licences.</p>`)
      + `<p style="color:#666;font-size:10.5px;margin-top:10px;border-top:1px solid #ccc;padding-top:4px">Method: Oracle Processor Core Factor Table matched to each server's CPU (a factor entered by a person wins); editions read from the databases themselves where they are monitored; VMware licensed per the scope above. A count marked incomplete may be under-stated. This is an internal compliance position for planning, not a statement from Oracle. Generated by ${ZYB_ORG.short} IT Asset Management at ${ESC(new Date(now()).toISOString().slice(0, 16).replace('T', ' '))} UTC.</p></div>`;
    const text = [`Oracle Licence Compliance ${day}: ${c.verdict_label}`, ''].concat(c.matrix.map((m) => `${m.name}: owned ${m.owned}, needed ${m.required}, difference ${m.delta >= 0 ? '+' : ''}${m.delta}, ${m.level_label}`), [''], c.alerts.slice(0, 10).map((a) => `${a.severity.toUpperCase()} ${a.title} -> ${a.action} (${a.owner})`)).join('\n');
    return { day, verdict: c.verdict, verdict_label: c.verdict_label, subject: `Oracle licence compliance ${day}: ${c.verdict_label}${c.alerts.filter((a) => a.severity === 'critical').length ? ' - ' + c.alerts.filter((a) => a.severity === 'critical').length + ' critical alert(s)' : ''}`, html, text, compliance: c };
  }

  async function sendReport(why, who) {
    const r = reportOf(), rec = { id: 'OLR-' + new Date(now()).toISOString().replace(/[-:T]/g, '').slice(0, 12), at: new Date(now()).toISOString(), day: r.day, why, by: (who && who.user) || 'system', verdict: r.verdict, mail: null };
    const d = D();
    if (!d || !d.siem || typeof d.siem.call !== 'function') rec.mail = { ok: false, error: 'no link to the SIEM (mail relay)' };
    else {
      try { const x = await d.siem.call('POST', '/db/dba/morning-report', LSYS, { id: rec.id, day: r.day, subject: r.subject, text: r.text, html: r.html, audience: 'dba+managers' });
        rec.mail = x && x.status >= 200 && x.status < 300 ? { ok: true, recipients: (x.json && x.json.recipients) || null, managers: (x.json && x.json.managers) || 0 } : { ok: false, error: (x && x.json && x.json.error) || ('SIEM HTTP ' + (x && x.status)) };
      } catch (e) { rec.mail = { ok: false, error: String(e.message || e).slice(0, 200) }; }
    }
    repCol.put(rec);
    for (const old of repCol.all().sort((a, b) => (a.at < b.at ? 1 : -1)).slice(60)) repCol.remove(old.id);
    audit(who || LSYS, 'oracle.licence.report.send', rec.id, { why, verdict: r.verdict, mail: rec.mail });
    return rec;
  }

  // hourly: refresh the alert list; a new critical / warning alert (or one open 7 days since the last mail) sends the report
  let checking = null;
  async function check() {
    if (checking) return checking;
    checking = (async () => {
      let inv; try { inv = inventory(); } catch (e) { return { skipped: e.message }; }
      const c = compliance(inv), t = now(), at = new Date(t).toISOString(), open = new Set(c.alerts.map((a) => a.key));
      let notify = false;
      for (const a of c.alerts) {
        const cur = alertCol.get(a.key);
        if (!cur || cur.cleared_at) { alertCol.put({ id: a.key, severity: a.severity, title: a.title, first_seen: at, last_seen: at, cleared_at: null, mailed_at: null }); if (a.severity !== 'info') notify = true; }
        else { alertCol.put(Object.assign(cur, { severity: a.severity, title: a.title, last_seen: at })); if (a.severity !== 'info' && (!cur.mailed_at || t - Date.parse(cur.mailed_at) >= REMIND_MS)) notify = true; }
      }
      for (const x of alertCol.all((y) => !y.cleared_at && !open.has(y.id))) alertCol.put(Object.assign(x, { cleared_at: at }));
      const R = rcfg(), riy = new Date(t + 3 * 3600000), hm = riy.toISOString().slice(11, 16), dayKey = riy.toISOString().slice(0, 7);
      const monthly = Number(riy.getUTCDate()) === Number(R.report_day) && hm >= String(R.report_at) && !repCol.all((r) => r.why === 'monthly' && String(r.day).slice(0, 7) === dayKey).length;
      let sent = null;
      if (R.mail !== false && (notify || monthly)) {
        sent = await sendReport(monthly && !notify ? 'monthly' : 'alert', LSYS);
        if (sent.mail && sent.mail.ok) for (const a of c.alerts) if (a.severity !== 'info') { const cur = alertCol.get(a.key); if (cur) alertCol.put(Object.assign(cur, { mailed_at: at })); }
      }
      return { at, alerts: c.alerts.length, verdict: c.verdict, sent: sent ? { id: sent.id, ok: !!(sent.mail && sent.mail.ok) } : null };
    })().finally(() => { checking = null; });
    return checking;
  }
  function complianceView() {
    const inv = inventory(), c = compliance(inv);
    const hist = new Map(alertCol.all().map((a) => [a.id, a]));
    c.alerts = c.alerts.map((a) => Object.assign({}, a, { first_seen: (hist.get(a.key) || {}).first_seen || null, mailed_at: (hist.get(a.key) || {}).mailed_at || null }));
    c.reports = repCol.all().sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 12).map((r) => ({ id: r.id, at: r.at, why: r.why, by: r.by, verdict: r.verdict, mail: r.mail }));
    c.report_settings = rcfg();
    return c;
  }

  return { table, match, setTable, sync, setFactor, inventory, monitored, compliance, complianceView, reportOf, sendReport, check, CORE_FACTOR_TABLE };
}

function registerOracleLicences(srv, app, opts = {}) {
  const O = createOracleLicences(app, opts);
  (app.addons = app.addons || {}).oracleLicences = O;
  srv.route('GET', '/oracle-licences', (ctx) => { ctx.need('operator'); return O.inventory(); });
  srv.route('POST', '/oracle-licences/factor', (ctx) => { ctx.need('operator'); return O.setFactor(ctx.body || {}, ctx.who); });
  srv.route('GET', '/oracle-licences/table', (ctx) => { ctx.need('operator'); return { table: O.table(), source: 'https://www.oracle.com/assets/processor-core-factor-table-070634.pdf' }; });
  srv.route('POST', '/oracle-licences/table', (ctx) => { ctx.need('admin'); return O.setTable(ctx.body || {}, ctx.who); });
  srv.route('GET', '/oracle-licences/compliance', (ctx) => { ctx.need('operator'); return O.complianceView(); });
  srv.route('GET', '/oracle-licences/report', (ctx) => { ctx.need('operator'); const r = O.reportOf(); return { day: r.day, verdict: r.verdict, verdict_label: r.verdict_label, subject: r.subject, html: r.html }; });
  srv.route('POST', '/oracle-licences/report/send', async (ctx) => { ctx.need('operator'); return O.sendReport('manual', ctx.who); });
  if (!opts.noTimer) { const sync = guardOf(app, 'oracle-licences.sync', () => O.sync()), check = guardOf(app, 'oracle-licences.check', () => O.check()); const t = setInterval(guardOf(app, 'oracle-licences.hourly', () => { sync(); check(); }), 3600000); if (t.unref) t.unref(); const t0 = setTimeout(check, 300000); if (t0.unref) t0.unref(); }
  return O;
}

module.exports = { createOracleLicences, registerOracleLicences, CORE_FACTOR_TABLE, FACTORS };
