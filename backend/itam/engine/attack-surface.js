// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('crypto');
const { param } = require('./check');
const { guardOf } = require('./errors');
/*
 * Continuous Attack Surface ({P} = /api/itam; Pentest & Vulnerability Management -> Attack Surface). The external attack surface the
 * platform can SEE, kept current and diffed on every run - what an attacker reaches first. READ-ONLY and PASSIVE: it correlates what
 * the platform already holds (the asset register, Asset Discovery open ports, the scanners' findings through the VAPT Center). It
 * sends no packet, runs no scan and exploits nothing; a scan is still requested on Vulnerability Scans and a test on the VAPT
 * Workflow, each with four-eyes approval. "Validated" means an authorised test a person recorded - never something fired here.
 *   surface     one row per internet-facing asset, with the exposed SERVICES (Asset Discovery open ports -> a service name) and the
 *               APIs among them (a web/API port with web software, an application asset, or an asset tagged api) - each service
 *               carries its evidence (the port and the source that reported it). Shadow = reachable but in no asset record.
 *   exposure    0-100 per asset, itemised: worst open finding (severity / CVSS, +exploit named), count of exposed services,
 *               a risky service (RDP / SMB / database / admin open to the internet), business-critical / sensitive-data target.
 *   changes     every run is diffed against the last snapshot: a new internet-facing asset, a newly exposed service / API, a new
 *               external finding, a service that closed, an asset no longer exposed - each is something to VERIFY, never a result.
 *   chain       an internet-facing asset with an exposed service is an ENTRY point; the link to the AI-Driven Attack Chain
 *               (engine/ai-pentest.js) that chains it to a crown jewel. A proposal to test one is filed there (four eyes).
 *   continuous  a snapshot every 6 h ('attacksurface.snapshot') and whenever onChange() is called by an ingest path; the change
 *               feed and the trend come from those snapshots. Nothing in a snapshot changes a device.
 *   GET  /attack-surface                       operator  KPIs, surface, APIs, changes since the last snapshot, trend, coverage
 *   GET  /attack-surface/:id                   operator  one asset: its services, APIs, findings, exposure breakdown, chain entry
 *   POST /attack-surface/snapshot              admin     record the surface now (also diffs)                           audited
 * Host names, addresses and services are internal: operators and administrators.
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (v) => String(v == null ? '' : v).toLowerCase();
const s = (v, n) => String(v == null ? '' : v).slice(0, n || 200);
// a port -> a service name and whether it is an API surface (a, web) or a risky management service (risk)
const SVC = {
  21: ['FTP', { risk: true }], 22: ['SSH', { risk: true }], 23: ['Telnet', { risk: true }], 25: ['SMTP', {}], 53: ['DNS', {}],
  80: ['HTTP', { web: true }], 110: ['POP3', {}], 143: ['IMAP', {}], 389: ['LDAP', { risk: true }], 443: ['HTTPS', { web: true }],
  445: ['SMB', { risk: true }], 1433: ['MS SQL', { risk: true, db: true }], 1521: ['Oracle DB', { risk: true, db: true }], 2049: ['NFS', { risk: true }],
  3306: ['MySQL', { risk: true, db: true }], 3389: ['RDP', { risk: true }], 5432: ['PostgreSQL', { risk: true, db: true }], 5900: ['VNC', { risk: true }],
  5985: ['WinRM', { risk: true }], 5986: ['WinRM/HTTPS', { risk: true }], 6379: ['Redis', { risk: true, db: true }], 8080: ['HTTP alt', { web: true }],
  8443: ['HTTPS alt', { web: true }], 8000: ['HTTP alt', { web: true }], 9200: ['Elasticsearch', { risk: true, db: true, web: true }], 27017: ['MongoDB', { risk: true, db: true }],
};
const svcOf = (p) => SVC[p] || [p <= 1024 ? 'port ' + p : 'service ' + p, {}];
const WEBSW = /\b(iis|apache|nginx|tomcat|node|express|kong|apigee|gateway|swagger|graphql|rest|api)\b/;
const SEVR = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const EXPL = /remote code|rce|exploit|known.exploited|kev|unauth/i;

function createAttackSurface(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const A = () => app.addons || {};
  const col = (n) => { try { return store.collection(n); } catch (e) { return null; } };
  const all = (n, f) => { const c = col(n); return c ? c.all(f || (() => true)) : []; };
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'attacksurface.' + action, target, detail }); };
  const hist = () => col('attack_surface_hist');

  // every address the platform saw a device at, with its open ports and when it last answered
  function observed() {
    const M = new Map();
    for (const d of all('disc_devices', (x) => x.status !== 'ignored')) for (const ip of d.ips || []) {
      const r = M.get(ip) || { ip, ports: new Set(), host: d.hostname || null, last: null, in_register: false };
      for (const p of d.open_ports || []) r.ports.add(p); const t = Date.parse(d.last_seen); if (isFinite(t) && (!r.last || t > r.last)) r.last = t; M.set(ip, r);
    }
    return M;
  }

  async function build() {
    const obs = observed();
    let findings = [], fstatus = { vapt_center: { ok: false, error: 'VAPT Center is not installed' } };
    const VC = A().vaptCenter;
    if (VC && VC.gather) { try { const g = await VC.gather(); findings = g.findings || []; fstatus = g.status || {}; } catch (e) { fstatus = { vapt_center: { ok: false, error: s(e.message, 200) } }; } }
    const findByHost = new Map();
    for (const f of findings) if (f.status === 'open') { for (const k of [low(f.host), low(f.asset)]) if (k) { (findByHost.get(k) || findByHost.set(k, []).get(k)).push(f); } }
    const pol = (col('pentest_settings') && col('pentest_settings').get('cadence') || {}).values || {};
    const ctags = (pol.critical_tags || ['business-critical', 'critical', 'crown-jewel']).map(low);
    const rows = [], apis = [];
    const seenIp = new Set();
    for (const a of all('assets', (x) => !['disposed', 'retired', 'lost', 'stolen'].includes(x.status))) {
      const ips = [...new Set([a.mgmt_ip].concat(a.ips || []).map((x) => String(x || '').trim()).filter(Boolean))];
      const exposed = a.internet_facing === true || a.exposure === 'external' || (a.tags || []).some((t) => /internet|dmz|public|external/i.test(t));
      const fnd = ips.map(low).concat([low(a.name), low(a.hostname), low(a.fqdn)]).filter(Boolean).flatMap((k) => findByHost.get(k) || []);
      const extFnd = fnd.filter((f) => f.exposure === 'external');
      if (!exposed && !extFnd.length) continue;
      for (const ip of ips) seenIp.add(ip);
      const ports = new Set(); let last = null; for (const ip of ips) { const o = obs.get(ip); if (o) { for (const p of o.ports) ports.add(p); if (o.last && (!last || o.last > last)) last = o.last; } }
      const sw = (a.software || []).map((x) => low(x && (x.name || x))).join(' ') + ' ' + low(a.os) + ' ' + (a.tags || []).join(' ').toLowerCase();
      const services = [...ports].sort((x, y) => x - y).map((p) => { const [name, meta] = svcOf(p); return { port: p, name, risk: !!meta.risk, db: !!meta.db, api: !!(meta.web), evidence: 'Asset Discovery saw port ' + p + ' open' }; });
      // APIs: a web/API service with web software, or an application asset, or a tagged api
      const isApp = ['webapp', 'application', 'api'].includes(low(a.type)) || (a.tags || []).some((t) => /\bapi\b/i.test(t));
      const apiSvcs = services.filter((x) => x.api && (WEBSW.test(sw) || isApp || true)).map((x) => Object.assign({}, x, { why: WEBSW.test(sw) ? 'web / API software on the host' : isApp ? 'application asset' : 'web port open' }));
      const critical = ctags.some((t) => (a.tags || []).map(low).includes(t)) || low(a.criticality) === 'critical' || low(a.cia && a.cia.a) === 'high';
      const sensitive = ['secret', 'top_secret', 'restricted'].includes(low(a.classification)) || low(a.cia && a.cia.c) === 'high';
      const worst = extFnd.concat(fnd).sort((x, y) => (SEVR[low(y.severity)] || 0) - (SEVR[low(x.severity)] || 0) || (y.cvss || 0) - (x.cvss || 0))[0] || null;
      // exposure 0-100, itemised
      const why = []; let sc = 0;
      if (worst) { const w = SEVR[low(worst.severity)] || 0, base = Math.max(w * 10, worst.cvss ? Math.round(worst.cvss * 4) : 0); sc += base; why.push({ points: base, text: 'worst open finding: ' + s(worst.title, 80) + ' (' + worst.severity + ')' });
        if (EXPL.test(s(worst.title, 200) + ' ' + s(worst.description, 200))) { sc += 10; why.push({ points: 10, text: 'an exploit / RCE is named' }); } }
      const risky = services.filter((x) => x.risk); if (risky.length) { const k = Math.min(20, risky.length * 7); sc += k; why.push({ points: k, text: risky.length + ' risky service(s) exposed: ' + risky.map((x) => x.name).join(', ') }); }
      if (services.length > risky.length) { const k = Math.min(10, (services.length - risky.length) * 2); sc += k; why.push({ points: k, text: (services.length - risky.length) + ' other exposed service(s)' }); }
      if (critical) { sc += 25; why.push({ points: 25, text: 'business-critical asset' }); }
      if (sensitive) { sc += 15; why.push({ points: 15, text: 'holds sensitive data' }); }
      const exposure = Math.min(100, sc);
      const row = { id: a.id, name: s(a.name || a.asset_tag || a.id, 120), type: a.type || '', site: a.site || '', owner: a.owner || '', ips, host: a.hostname || a.fqdn || null,
        services, apis: apiSvcs, open_findings: fnd.length, external_findings: extFnd.length, worst: worst ? { title: s(worst.title, 120), severity: worst.severity, cvss: worst.cvss == null ? null : worst.cvss, cves: (worst.cves || []).slice(0, 5) } : null,
        critical, sensitive, exposure, band: exposure >= 75 ? 'critical' : exposure >= 50 ? 'high' : exposure >= 25 ? 'medium' : 'low', why, last_seen: last ? iso(last) : null, shadow: false };
      // the asset's open findings, kept off the list (not enumerable) and read by one() for the required actions
      const seenF = new Set(); Object.defineProperty(row, '_f', { enumerable: false, value: fnd.filter((f) => { const k = f.src + ':' + f.id; if (seenF.has(k)) return false; seenF.add(k); return true; }) });
      rows.push(row);
      for (const x of apiSvcs) apis.push({ asset_id: a.id, asset: row.name, ip: ips[0] || '', port: x.port, name: x.name, why: x.why, exposure });
    }
    // shadow surface: an address answering a web/remote port, in no asset record and seen within 30 days
    for (const o of obs.values()) { if (seenIp.has(o.ip)) continue; if (o.in_register) continue;
      const known = all('assets', (a) => [a.mgmt_ip].concat(a.ips || []).map(String).includes(o.ip)).length; if (known) continue;
      const ports = [...o.ports]; const web = ports.filter((p) => (svcOf(p)[1].web)); if (!web.length && !ports.some((p) => (svcOf(p)[1].risk))) continue;
      if (o.last && now() - o.last > 30 * DAY) continue;
      const services = ports.sort((x, y) => x - y).map((p) => { const [name, meta] = svcOf(p); return { port: p, name, risk: !!meta.risk, api: !!meta.web, evidence: 'Asset Discovery saw port ' + p + ' open' }; });
      rows.push({ id: 'shadow:' + o.ip, name: o.host || o.ip, type: 'unknown', site: '', owner: null, ips: [o.ip], host: o.host, services, apis: services.filter((x) => x.api), open_findings: 0, external_findings: 0, worst: null, critical: false, sensitive: false,
        exposure: Math.min(60, 20 + services.filter((x) => x.risk).length * 8), band: 'medium', why: [{ points: 20, text: 'reachable but in no asset record (shadow)' }], last_seen: o.last ? iso(o.last) : null, shadow: true });
    }
    rows.sort((a, b) => b.exposure - a.exposure || b.open_findings - a.open_findings);
    return { rows, apis, fstatus, connected: !!(VC && VC.gather) };
  }

  function fingerprint(rows) { const m = {}; for (const r of rows) m[r.id] = { exposure: r.exposure, services: r.services.map((x) => x.port).sort((a, b) => a - b), findings: r.open_findings, shadow: r.shadow }; return m; }
  function diff(rows) {
    const H = (hist() && hist().all().sort((a, b) => String(b.id).localeCompare(String(a.id)))) || [];
    const prev = H[0] && H[0].fp; if (!prev) return { since: null, items: [], first: true };
    const byId = new Map(rows.map((r) => [r.id, r])), items = [];
    for (const r of rows) { const p = prev[r.id];
      if (!p) { items.push({ kind: r.shadow ? 'new_shadow' : 'new_asset', id: r.id, name: r.name, text: (r.shadow ? 'New shadow surface ' : 'Newly internet-facing: ') + r.name + (r.services.length ? ' - ' + r.services.map((x) => x.name).join(', ') : ''), exposure: r.exposure, severity: r.band }); continue; }
      const now0 = r.services.map((x) => x.port), added = now0.filter((x) => !p.services.includes(x)), gone = p.services.filter((x) => !now0.includes(x));
      for (const pt of added) { const [name, meta] = svcOf(pt); items.push({ kind: meta.web ? 'new_api' : 'new_service', id: r.id, name: r.name, text: 'New ' + (meta.web ? 'API / web' : meta.risk ? 'risky' : '') + ' service on ' + r.name + ': ' + name + ' (port ' + pt + ')', severity: meta.risk || meta.web ? 'high' : 'medium' }); }
      for (const pt of gone) items.push({ kind: 'service_closed', id: r.id, name: r.name, text: svcOf(pt)[0] + ' (port ' + pt + ') closed on ' + r.name, severity: 'info' });
      if (r.open_findings > p.findings) items.push({ kind: 'new_finding', id: r.id, name: r.name, text: (r.open_findings - p.findings) + ' new open finding(s) on ' + r.name, severity: r.band });
    }
    for (const id of Object.keys(prev)) if (!byId.has(id)) items.push({ kind: 'gone', id, name: prev[id].name || id, text: (prev[id].shadow ? 'Shadow surface ' : '') + id + ' no longer exposed - confirm it was decommissioned or firewalled', severity: 'info' });
    const rank = { new_api: 0, new_service: 1, new_shadow: 1, new_finding: 2, new_asset: 2, gone: 3, service_closed: 4 };
    items.sort((a, b) => (rank[a.kind] || 9) - (rank[b.kind] || 9));
    return { since: H[0].id, items: items.slice(0, 200), first: false };
  }

  async function view() {
    const B = await build(), ch = diff(B.rows), rows = B.rows;
    const risky = rows.filter((r) => r.services.some((x) => x.risk));
    const kpis = { exposed: rows.length, shadow: rows.filter((r) => r.shadow).length, apis: B.apis.length, risky_services: rows.reduce((a, r) => a + r.services.filter((x) => x.risk).length, 0),
      critical: rows.filter((r) => r.band === 'critical').length, with_findings: rows.filter((r) => r.open_findings > 0).length, changes: ch.items.length };
    const H = (hist() && hist().all().sort((a, b) => String(a.id).localeCompare(String(b.id)))) || [];
    const chain = A().aiPentest ? '/ai-pentest' : null;
    return { generated_at: iso(), connected: B.connected, source_status: B.fstatus, kpis, surface: rows.slice(0, 2000), apis: B.apis.slice(0, 1000), changes: ch,
      trend: H.slice(-60).map((h) => ({ day: h.id, exposed: h.exposed, apis: h.apis, critical: h.critical })), chain_link: chain,
      note: 'Passive and read-only: the surface is built from the asset register, Asset Discovery open ports and the scanners\' findings. Nothing here sends a packet, scans or exploits - a scan is requested on Vulnerability Scans, a test on the VAPT Workflow, each with four-eyes approval. An entry point is a lead to the AI-Driven Attack Chain, not proof a path is open.' };
  }
  // what to do about one asset, worst first: each open finding's own fix (with why and how to verify), then risky exposed services not
  // already covered by a finding, then API services. Built only from what the scanners and the platform's checks said - a finding a
  // scanner reported with no fix says so instead of inventing one.
  function actionsFor(r) {
    const out = [], seen = new Set(), add = (a) => { const k = String(a.action).toLowerCase(); if (seen.has(k)) return; seen.add(k); out.push(a); };
    const fs = (r._f || []).slice().sort((x, y) => (SEVR[low(y.severity)] || 0) - (SEVR[low(x.severity)] || 0) || (y.cvss || 0) - (x.cvss || 0));
    for (const f of fs) add({ severity: low(f.severity) || 'info', action: f.fix ? s(f.fix, 400) : 'Remediate "' + s(f.title, 120) + '" as the scanner describes it' + ((f.cves || []).length ? ' (' + f.cves.slice(0, 3).join(', ') + ')' : '') + ' - the scanner gave no fix text: see the finding in the VAPT Center.',
      why: s(f.why || f.description || '', 300) || null, verify: s(f.verify || '', 300) || 'Confirm the fix with a rescan of this host (Scan Coverage Assurance or the VAPT Center).', finding: s(f.title, 160), source: f.src || 'scanner', cves: (f.cves || []).slice(0, 5) });
    const covered = new Set(fs.map((f) => { const m = /port\s*(\d+)/i.exec(f.title || ''); return m ? +m[1] : null; }).filter(Boolean));
    for (const x of r.services.filter((y) => y.risk && !covered.has(y.port))) add({ severity: 'high', action: 'Close port ' + x.port + ' (' + x.name + ') or restrict it to the hosts that need it; if it must stay, require strong authentication.', why: x.name + ' is a commonly attacked service and Asset Discovery saw it open.', verify: 'Re-run Asset Discovery and confirm port ' + x.port + ' is closed or filtered.', finding: null, source: 'exposed service', cves: [] });
    for (const x of r.apis) add({ severity: 'medium', action: 'Confirm the API on port ' + x.port + ' (' + x.name + ') needs to be reachable; put it behind authentication (an API gateway or reverse proxy) and log its use.', why: 'An exposed API is a direct way into the application\'s data.', verify: 'Test it on the AI-Driven Attack Chain or file a VAPT Workflow engagement (four-eyes).', finding: null, source: 'API service', cves: [] });
    return out.slice(0, 40);
  }
  async function one(id0) {
    const id = param(id0, 'id'); const B = await build(); const r = B.rows.find((x) => x.id === id); if (!r) throw httpErr(404, 'asset ' + id + ' not in the attack surface');
    let chain = null; try { const AP = A().aiPentest; if (AP && AP.view) { const v = await AP.view({ role: 'operator' }); chain = (v.paths || []).filter((p) => p.entry_id === id).slice(0, 10); } } catch (e) { chain = null; /* the chain is optional */ }
    const actions = actionsFor(r);
    return Object.assign({}, r, { chain_entry: chain, actions, actions_note: actions.length ? null : 'No action required: no open finding and no risky or API service on this asset.', note: 'To test an exposed service: open the AI-Driven Attack Chain for the path, or file an engagement on the VAPT Workflow (four-eyes). Nothing is tested from here.' });
  }
  async function snapshot(who) {
    const B = await build(), ch = diff(B.rows), h = hist(); if (!h) return null;
    const rec = { id: iso().slice(0, 10) + 'T' + iso().slice(11, 16), at: iso(), exposed: B.rows.length, apis: B.apis.length, critical: B.rows.filter((r) => r.band === 'critical').length, shadow: B.rows.filter((r) => r.shadow).length, fp: fingerprint(B.rows) };
    h.put(rec); for (const x of h.all((y) => Date.parse(y.at) < now() - 120 * DAY)) if (h.remove) h.remove(x.id);
    if (who) audit(who, 'snapshot', rec.id, { exposed: rec.exposed, apis: rec.apis, changes: ch.items.length });
    return { snapshot: rec.id, changes: ch.items.length, exposed: rec.exposed };
  }
  let timer = null;
  const runSnap = guardOf(app, 'attacksurface.snapshot', async () => { await snapshot(null); });
  function start() { if (opts.noTimer || timer) return; const loop = () => { Promise.resolve(runSnap()).finally(() => { timer = setTimeout(loop, 6 * 3600000); if (timer.unref) timer.unref(); }); }; timer = setTimeout(loop, 90000); if (timer.unref) timer.unref(); }
  // an ingest path can call this when the surface may have changed (new discovery, new finding): it records a snapshot so the
  // change feed fires on the change rather than only on the 6-hour timer. Guarded and throttled so a burst does not thrash.
  let lastChange = 0;
  async function onChange() { if (now() - lastChange < 60000) return; lastChange = now(); try { await snapshot(null); } catch (e) { if (app.log && app.log.every) app.log.every('attacksurface.onchange', 600000, 'warn', 'attack surface: snapshot on change failed', { err: s(e.message, 200) }); } }
  return { view, one, snapshot, build, onChange, start, SVC };
}

function registerAttackSurface(srv, app, X0) {
  const X = X0 && X0.view ? X0 : createAttackSurface(app, X0 || {});
  app.addons = app.addons || {}; app.addons.attackSurface = X; X.start();
  srv.route('GET', '/attack-surface', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('GET', '/attack-surface/:id', (ctx) => { ctx.need('operator'); return X.one(ctx.params.id); });
  srv.route('POST', '/attack-surface/snapshot', (ctx) => { ctx.need('admin'); return X.snapshot(Object.assign({ ip: ctx.ip }, ctx.who)); }, { maxBody: 512 });
  return X;
}
module.exports = { createAttackSurface, registerAttackSurface };
