// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const fs = require('node:fs');
const { body } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * VAPT Center ({P} = /api/itam, Pentest & Vulnerability Management -> VAPT Center): one place over every finding the platform holds
 * and one place to start a scan.
 *   sources    Greenbone internal scans (engine/vulnscan.js), FireCompass + Tenable (engine/vapt-studio.js), the penetration
 *              testing engineer (engine/pentest.js). Each stays where it is (its own owners, triage, four-eyes risk acceptance);
 *              this module only reads them. The asset register adds criticality (tier / critical tag), owner and department.
 *   analysis   pyengine/vapt_center_rules.py: the same vulnerability from several sources merged into one row, a priority with
 *              its reasons (severity / CVSS, known-exploited, internet exposure, business-critical, past SLA, confirmed twice),
 *              SLA per severity with the breaches forecast for 14 days, likely lateral-movement paths (internet-facing vulnerable
 *              host next to a business-critical asset), what is new / fixed / REOPENED since the last daily snapshot, time to fix
 *              per severity and owner, and roll-ups per asset, owner, department and source.
 *   scanning   the scan wizard proposes targets - assets whose test is never done / overdue / due soon under the testing cadence,
 *              and hosts with high or critical findings not rescanned for 30 days (a retest) - and files ONE Greenbone scan request
 *              for the chosen ones. The request goes through Vulnerability Scans unchanged: inside the admin's scope only, and a
 *              different named person approves before anything is sent into the network.
 *   reports    executive, technical, per asset, per owner, per department, compliance (SAMA CSF / NCA ECC / ISO 27001
 *              mapping), SLA, delta, retest list - HTML (print / PDF) or CSV, audited. The Reporting Center schedules them.
 *   GET  /vapt-center                     operator  the analysis + scan suggestions + scope
 *   GET  /vapt-center/reports/:kind       operator  ?format=html|csv   {filename, html|csv}                       audited
 *   POST /vapt-center/scan                operator  {targets[], profile?, hours?, reason?}  a person; files a scan request   audited
 *   POST /vapt-center/sla                 admin     {critical, high, medium, low} days                            audited
 *   POST /vapt-center/snapshot            admin     record today's open findings now                            audited
 */
const DAY = 86400000, RIYADH = 3 * 3600000;
const KINDS = ['executive', 'technical', 'asset', 'owner', 'department', 'compliance', 'sla', 'delta', 'retest'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const escH = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
// what each control family asks of vulnerability management - the compliance report maps findings to them
const COMPLIANCE = [
  { fw: 'SAMA CSF', ref: '3.3.7 Patch management / 3.3.8 Vulnerability management', need: 'vulnerabilities identified, prioritised and remediated within defined timelines', test: (a) => ({ ok: a.sla.breached === 0, evidence: a.sla.breached + ' finding(s) past their SLA; ' + a.open + ' open' }) },
  { fw: 'SAMA CSF', ref: '3.3.8 Penetration testing', need: 'periodic penetration testing of critical systems', test: (a, x) => ({ ok: x.overdue === 0, evidence: x.overdue + ' asset(s) never tested or overdue under the testing cadence' }) },
  { fw: 'NCA ECC', ref: '2-10 Vulnerabilities Management', need: 'periodic scanning, classification by risk and remediation of technical vulnerabilities', test: (a) => ({ ok: a.counts.critical === 0 && a.sla.breached === 0, evidence: a.counts.critical + ' critical open, ' + a.sla.breached + ' past SLA' }) },
  { fw: 'NCA ECC', ref: '2-11 Penetration Testing', need: 'penetration tests on internet-facing services and critical systems', test: (a, x) => ({ ok: x.overdue === 0, evidence: x.overdue + ' asset(s) overdue for testing' }) },
  { fw: 'ISO 27001:2022', ref: 'A.8.8 Management of technical vulnerabilities', need: 'information about vulnerabilities obtained, exposure evaluated, measures taken', test: (a) => ({ ok: a.sla.breached === 0 && !a.paths.length, evidence: a.sla.breached + ' past SLA, ' + a.paths.length + ' likely lateral-movement path(s)' }) },
];

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createVaptCenter(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const A = () => app.addons || {};
  const snapC = () => store.collection('vc_snapshots'), cfgC = () => store.collection('vc_cfg');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'vapt.center.' + action, target, detail }); };
  const iso = () => new Date(now()).toISOString();
  const day = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const sla = () => Object.assign({ critical: 15, high: 30, medium: 90, low: 180 }, (cfgC().get('sla') || {}).days || {});

  /* ---- read every source; the register adds criticality, owner, department */
  function registerIndex() {
    const pol = (store.collection('pentest_settings').get('cadence') || {}).values || {}, ctags = (pol.critical_tags || ['business-critical', 'critical', 'crown-jewel']).map((x) => String(x).toLowerCase());
    const tiers = store.collection('test_tier'), idx = new Map(), crit = [];
    for (const a of store.collection('assets').all((x) => x.status !== 'disposed')) {
      const o = tiers.get(a.id), tags = (a.tags || []).map((x) => String(x).toLowerCase());
      const c = o ? (o.tier === 'critical' ? 'critical' : null) : tags.some((t) => ctags.includes(t)) ? 'critical' : null;
      const rec = { criticality: c, owner: a.owner || null, department: a.department || null, name: a.name };
      for (const k of [a.mgmt_ip, a.hostname, a.name, a.fqdn]) if (k) idx.set(String(k).toLowerCase(), rec);
      if (c && a.mgmt_ip) crit.push({ name: a.name, ip: a.mgmt_ip });
    }
    return { idx, crit };
  }
  async function gather() {
    const out = [], status = {};
    const V = A().vulnscan;
    if (V) { try { for (const f of V.findings({ status: 'all' }).items || []) out.push({ src: 'greenbone', id: f.id, host: f.host, asset: f.hostname || f.host, title: f.name, severity: f.severity, cvss: typeof f.score === 'number' ? f.score : null, cves: f.cves || [], status: f.status === 'risk_accepted' || f.status === 'accepted' ? 'accepted' : f.status === 'fixed' ? 'fixed' : 'open', first_seen: f.first_seen, last_seen: f.last_seen, fixed_at: f.fixed_at, owner: f.owner, fix: f.solution || f.fix || null, verify: null, why: f.summary || f.insight || null }); status.greenbone = { ok: true }; } catch (e) { status.greenbone = { ok: false, error: s(e.message, 200) }; } }
    else status.greenbone = { ok: false, error: 'Vulnerability Scans (Greenbone) is not installed' };
    const S = A().vaptStudio;
    if (S) { try { const v = await S.view(); for (const f of v.findings || []) out.push({ src: f.vendor || 'firecompass', id: f.id, host: f.host, asset: f.asset || f.host, title: f.title, severity: f.severity, cvss: f.cvss == null ? null : Number(f.cvss), cves: f.cves || [], status: f.status === 'open' ? 'open' : /accept/.test(f.status || '') ? 'accepted' : 'fixed', first_seen: f.first_seen, last_seen: f.last_seen || null, owner: f.owner, exposure: f.exposure, description: f.description, fix: f.remediation || f.recommendation || f.fix || null, verify: null, why: null }); status.vapt = { ok: true }; } catch (e) { status.vapt = { ok: false, error: s(e.message, 200) }; } }
    else status.vapt = { ok: false, error: 'VAPT Studio is not installed' };
    const P = A().pentest;
    if (P) { try { const v = P.view(); for (const f of v.findings || []) out.push({ src: 'pentest', id: f.id, host: f.ip || f.asset, asset: f.asset, asset_id: f.asset_id || null, title: f.title, severity: f.severity, cvss: f.cvss ? Number(f.cvss) || null : null, cves: f.cves || [], status: f.status === 'closed' || f.status === 'fixed' ? 'fixed' : 'open', first_seen: f.at || null, exposure: f.internet ? 'external' : undefined, fix: f.fix || null, verify: f.verify || null, why: f.why || null }); status.pentest = { ok: true }; } catch (e) { status.pentest = { ok: false, error: s(e.message, 200) }; } }
    else status.pentest = { ok: false, error: 'the penetration testing engineer is not installed' };
    const R = registerIndex();
    for (const f of out) { const a = R.idx.get(String(f.host || '').toLowerCase()) || R.idx.get(String(f.asset || '').toLowerCase()); if (a) { f.criticality = a.criticality; f.owner = f.owner || a.owner; f.department = a.department; } }
    return { findings: out, status, critical_assets: R.crit };
  }
  let CACHE = null;
  async function analysis(force) {
    if (!force && CACHE && now() - CACHE.at < 60000) return CACHE.r;
    const g = await gather();
    let r;
    try { r = await py().call('vapt.center', { findings: g.findings, snapshots: snapC().all(() => true).sort((a, b) => a.day.localeCompare(b.day)).filter((x) => x.day < day(now())).slice(-90), sla: sla(), critical_assets: g.critical_assets, now: now() }); }
    catch (e) { r = { ok: false, error: 'the VAPT analysis could not run: ' + s(e.message, 200) }; }
    r.sources = g.status;
    CACHE = { at: now(), r }; return r;
  }
  async function snapshot(who) {
    const a = await analysis(true); if (!a.ok) throw httpErr(424, a.error);
    const d = day(now()); snapC().put({ id: d, day: d, at: now(), open: a.findings.filter((f) => f.status === 'open').map((f) => f.key), counts: a.counts });
    for (const old of snapC().all((x) => x.day < day(now() - 400 * DAY))) snapC().remove(old.id);
    if (who) audit(who, 'snapshot', d, { open: a.open });
    return { day: d, open: a.open };
  }
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'vapt.center.snapshot', async () => { if (!snapC().get(day(now())) && new Date(now() + RIYADH).getUTCHours() >= 6) await snapshot(null); }), 30 * 60000); if (tm.unref) tm.unref(); }

  /* ---- scan wizard */
  function cadence() { try { return A().pentest && A().pentest.cadence ? A().pentest.cadence.schedule() : null; } catch (e) { return null; /* the cadence is optional: no suggestions from it */ } }
  async function suggestions(a) {
    const out = [], sc = cadence(), seen = new Set();
    let scope = null; try { const v = A().vulnscan && A().vulnscan.view(); scope = v ? v.scope : null; } catch (e) { scope = null; /* not installed: the wizard says so */ }
    const rows = sc ? (Array.isArray(sc) ? sc : sc.rows || sc.items || []) : [];
    for (const r of rows) { if (!r.ip || !IPV4.test(r.ip) || !['never', 'overdue', 'due_soon'].includes(r.worst) || seen.has(r.ip)) continue; seen.add(r.ip); out.push({ target: r.ip, asset: r.asset, why: r.worst === 'never' ? 'never tested' : r.worst === 'overdue' ? 'test overdue' : 'test due soon', tier: r.tier, kind: 'cadence' }); }
    if (a && a.ok) for (const f of a.findings) { if (f.status !== 'open' || !['high', 'critical'].includes(f.severity) || !IPV4.test(String(f.host)) || seen.has(f.host)) continue; const last = Date.parse(f.last_seen || '') || f.first_seen_ms; if (last && now() - last < 30 * DAY) continue; seen.add(f.host); out.push({ target: f.host, asset: f.asset || f.host, why: 'retest: ' + f.severity + ' finding not rescanned for 30 days', kind: 'retest' }); }
    return { items: out.slice(0, 200), scope, installed: !!A().vulnscan };
  }
  async function scan(input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person requests a scan, not a service or AI identity');
    const b = body(input).list('targets', { required: true, max: 64, item: 'str', itemMax: 40, unique: true }).oneOf('profile', ['full', 'discovery'], { def: 'full' }).int('hours', { min: 1, max: 12, def: 4 }).str('reason', { max: 500 }).done();
    const bad = b.targets.find((t) => !IPV4.test(t)); if (bad) throw httpErr(400, 'targets: "' + s(bad, 40) + '" is not an IPv4 address');
    const V = A().vulnscan; if (!V) throw httpErr(424, 'Vulnerability Scans (Greenbone) is not installed on this server - run the update');
    const start = now() + 10 * 60000, end = start + b.hours * 3600000;
    const req = await V.request({ name: 'VAPT Center scan ' + day(now()) + ' (' + b.targets.length + ' host' + (b.targets.length > 1 ? 's' : '') + ')', targets: b.targets, exclude: [], profile: b.profile,
      window_start: new Date(start).toISOString(), window_end: new Date(end).toISOString(), reason: b.reason || 'Requested from the VAPT Center scan wizard' }, who);
    audit(who, 'scan', req && req.id || 'scan', { targets: b.targets.length, hours: b.hours });
    return { request: req, note: 'Filed in Vulnerability Scans: a different named person approves it before anything is sent; it runs only inside the scan scope.' };
  }
  function saveSla(input, who) {
    const b = body(input).int('critical', { min: 1, max: 365 }).int('high', { min: 1, max: 365 }).int('medium', { min: 1, max: 730 }).int('low', { min: 1, max: 730 }).done();
    const d = Object.assign(sla(), b); if (!(d.critical <= d.high && d.high <= d.medium && d.medium <= d.low)) throw httpErr(400, 'SLA days must not shorten as severity drops (critical <= high <= medium <= low)');
    cfgC().put({ id: 'sla', days: d, by: who.user, at: iso() }); CACHE = null; audit(who, 'sla', 'sla', d); return { days: d };
  }

  async function view() {
    const a = await analysis();
    const sg = await suggestions(a), sc = cadence();
    const rows = sc ? (Array.isArray(sc) ? sc : sc.rows || sc.items || []) : [];
    return Object.assign({}, a, { suggestions: sg, cadence: { overdue: rows.filter((r) => ['never', 'overdue'].includes(r.worst)).length, due_soon: rows.filter((r) => r.worst === 'due_soon').length, assets: rows.length }, kinds: KINDS, sla_days: sla(), generated_at: iso() });
  }

  /* ---- reports */
  async function report(kind, format, who) {
    if (!KINDS.includes(kind)) throw httpErr(404, 'no report "' + s(kind, 30) + '" - one of ' + KINDS.join(', '));
    if (!['html', 'csv'].includes(format)) throw httpErr(400, 'format must be html or csv');
    const v = await view(); if (!v.ok) throw httpErr(424, v.error);
    const open = v.findings.filter((f) => f.status === 'open'), keyset = (L2) => new Set(L2);
    const fcols = ['Priority', 'Severity', 'Host', 'Asset', 'Finding', 'CVEs', 'Sources', 'Exposure', 'Criticality', 'Owner', 'Department', 'Age (days)', 'SLA', 'Status'];
    const frow = (f) => [f.priority, f.severity, f.host, f.asset, f.title, (f.cves || []).join(' '), f.sources.join(' + '), f.exposure, f.criticality || '', f.owner || '', f.department || '', f.age_days == null ? '' : f.age_days, f.sla_state || '', f.status];
    const T = { title: '', intro: '', kpis: [], tables: [] };
    const kp = [['Open findings', v.open], ['Critical', v.counts.critical], ['High', v.counts.high], ['Past SLA', v.sla.breached], ['Due in 14 days', v.sla.due_14d], ['Lateral paths', v.paths.length], ['Merged duplicates', v.duplicates_merged]];
    if (kind === 'executive') { T.title = 'VAPT executive summary'; T.intro = v.sla.text + '. Sources: ' + Object.entries(v.sources).map(([k, x]) => k + (x.ok ? '' : ' (not read: ' + x.error + ')')).join(', ') + '.'; T.kpis = kp;
      T.tables.push({ title: 'Top 10 to fix first', cols: ['Priority', 'Severity', 'Host', 'Finding', 'Why'], rows: open.slice(0, 10).map((f) => [f.priority, f.severity, f.host, f.title, f.why.map((w) => w.text).join('; ')]) });
      T.tables.push({ title: 'Likely lateral-movement paths', cols: ['From (internet-facing)', 'Finding', 'To (business-critical)', 'Network'], rows: v.paths.map((p) => [p.from, p.finding, p.to, p.via]) });
      T.tables.push({ title: 'By department', cols: ['Department', 'Open', 'Critical', 'High', 'Past SLA'], rows: v.rollups.department.map((x) => [x.department, x.open, x.critical, x.high, x.breached]) }); }
    else if (kind === 'technical') { T.title = 'VAPT technical findings'; T.kpis = kp; T.tables.push({ title: 'Open findings by priority', cols: fcols, rows: open.map(frow) }); }
    else if (kind === 'asset' || kind === 'owner' || kind === 'department') { const key = kind === 'asset' ? 'host' : kind; T.title = 'VAPT findings per ' + kind; T.kpis = kp;
      T.tables.push({ title: 'Summary per ' + kind, cols: [kind[0].toUpperCase() + kind.slice(1), 'Open', 'Critical', 'High', 'Past SLA', 'Highest priority'], rows: v.rollups[kind].map((x) => [x[key], x.open, x.critical, x.high, x.breached, x.max_priority]) });
      for (const x of v.rollups[kind].slice(0, 40)) T.tables.push({ title: x[key], cols: ['Priority', 'Severity', 'Host', 'Finding', 'SLA'], rows: open.filter((f) => (f[key] || '(not set)') === x[key]).map((f) => [f.priority, f.severity, f.host, f.title, f.sla_state || '']) }); }
    else if (kind === 'compliance') { T.title = 'VAPT compliance mapping'; T.kpis = kp; T.intro = 'Each control is read against the platform\'s own findings and testing cadence - evidence, not a certification.';
      T.tables.push({ title: 'Controls', cols: ['Framework', 'Control', 'Requirement', 'Status', 'Evidence'], rows: COMPLIANCE.map((c) => { const r = c.test(v, v.cadence); return [c.fw, c.ref, c.need, r.ok ? 'met' : 'gap', r.evidence]; }) }); }
    else if (kind === 'sla') { T.title = 'VAPT remediation SLA'; T.kpis = kp; T.intro = v.sla.text + '. SLA days: ' + Object.entries(v.sla_days).map(([k, d]) => k + ' ' + d).join(', ') + '.';
      T.tables.push({ title: 'Past SLA', cols: fcols, rows: open.filter((f) => f.sla_state === 'breached').map(frow) }); T.tables.push({ title: 'Due within 14 days', cols: fcols, rows: open.filter((f) => f.sla_state === 'due').map(frow) });
      T.tables.push({ title: 'Time to fix (median days)', cols: ['Severity', 'Fixed', 'Median days'], rows: Object.entries(v.mttr.severity).map(([k, x]) => [k, x.fixed, x.median_days == null ? 'needs 3' : x.median_days]) }); }
    else if (kind === 'delta') { const d = v.delta, byKey = new Map(v.findings.map((f) => [f.key, f])); T.title = 'VAPT changes' + (d.since ? ' since ' + d.since : ''); T.kpis = [['New', d.new.length], ['Fixed', d.fixed.length], ['Reopened', d.reopened.length]];
      T.intro = d.since ? '' : 'No earlier snapshot yet - the first is recorded today; changes appear from tomorrow.';
      const ro = keyset(d.reopened); for (const [t, L2] of [['New since ' + (d.since || '-'), d.new.filter((k) => !ro.has(k))], ['Reopened (regressions)', d.reopened], ['Fixed', d.fixed]]) T.tables.push({ title: t, cols: ['Host', 'Finding', 'Severity'], rows: L2.map((k) => { const f = byKey.get(k); return f ? [f.host, f.title, f.severity] : [k.split('|')[0], k.split('|')[1], '']; }) }); }
    else { T.title = 'VAPT retest list'; T.intro = 'Hosts to rescan: high / critical findings not seen by a scan for 30 days, and assets whose testing is never done or overdue. File them as one scan from the VAPT Center.';
      T.tables.push({ title: 'Retest', cols: ['Target', 'Asset', 'Why'], rows: v.suggestions.items.map((x) => [x.target, x.asset, x.why]) }); }
    const stamp = iso().slice(0, 10);
    audit(who, 'report', kind, { format });
    if (format === 'csv') {
      const cell = (x) => { let t = s(x, 2000); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return '"' + t.replace(/"/g, '""') + '"'; };
      const L2 = [[T.title], ['Generated', iso()]].map((r) => r.map(cell).join(','));
      for (const [k, x] of T.kpis) L2.push([k, x].map(cell).join(','));
      for (const t of T.tables) { L2.push(''); L2.push(cell(t.title)); L2.push(t.cols.map(cell).join(',')); for (const r of t.rows) L2.push(r.map(cell).join(',')); }
      return { filename: 'vapt-' + kind + '-' + stamp + '.csv', csv: L2.join('\r\n') };
    }
    let h = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>' + escH(T.title) + '</title><style>body{font:14px/1.45 Segoe UI,Arial,sans-serif;color:#1b1f27;max-width:1100px;margin:24px auto;padding:0 16px}h1{font-size:22px;margin:0}h2{font-size:15px;margin:20px 0 6px;border-bottom:2px solid #e3e6ec;padding-bottom:4px}.m{color:#5c6577;font-size:12px}.k{display:inline-block;border:1px solid #e3e6ec;border-radius:10px;padding:8px 12px;margin:8px 8px 0 0;min-width:120px}.k b{display:block;font-size:20px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;padding:4px 6px;border-bottom:1px solid #eceef2;vertical-align:top}th{color:#5c6577}@media print{body{margin:0}}</style></head><body>';
    h += '<h1>' + escH(T.title) + ('</h1><div class="m">' + ZYB_ORG.short + ' · generated ') + escH(iso().replace('T', ' ').slice(0, 16)) + ' UTC · from the platform\'s own findings (Greenbone, FireCompass, Tenable, penetration testing)</div>';
    if (T.intro) h += '<p>' + escH(T.intro) + '</p>';
    h += T.kpis.map(([k, x]) => '<div class="k"><b>' + escH(x) + '</b><span class="m">' + escH(k) + '</span></div>').join('');
    for (const t of T.tables) h += '<h2>' + escH(t.title) + '</h2>' + (t.rows.length ? '<table><tr>' + t.cols.map((c) => '<th>' + escH(c) + '</th>').join('') + '</tr>' + t.rows.map((r) => '<tr>' + r.map((c) => '<td>' + escH(c) + '</td>').join('') + '</tr>').join('') + '</table>' : '<div class="m">None.</div>');
    return { filename: 'vapt-' + kind + '-' + stamp + '.html', html: h + '</body></html>' };
  }
  return { view, analysis, gather, snapshot, suggestions, scan, saveSla, report, KINDS, slaDays: sla };
}

function registerVaptCenter(srv, app, V0) {
  const V = V0 && V0.view ? V0 : createVaptCenter(app, V0 || {});
  app.addons = app.addons || {}; app.addons.vaptCenter = V;
  srv.route('GET', '/vapt-center', (ctx) => { ctx.need('operator'); return V.view(); });
  srv.route('GET', '/vapt-center/reports/:kind', (ctx) => { ctx.need('operator'); return V.report(String(ctx.params.kind || ''), (ctx.query && ctx.query.format) || 'html', ctx.who); });
  srv.route('POST', '/vapt-center/scan', (ctx) => { ctx.need('operator'); return V.scan(ctx.body, ctx.who); });
  srv.route('POST', '/vapt-center/sla', (ctx) => { ctx.need('admin'); return V.saveSla(ctx.body, ctx.who); });
  srv.route('POST', '/vapt-center/snapshot', (ctx) => { ctx.need('admin'); return V.snapshot(ctx.who); });
  return V;
}

module.exports = { createVaptCenter, registerVaptCenter, KINDS };
