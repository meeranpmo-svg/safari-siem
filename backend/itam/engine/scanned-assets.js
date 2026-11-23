// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const IP = require('./discovery/ipv4');
/*
 * Scanned Assets ({P} = /api/itam, Pentest & Vulnerability Management -> Scanned Assets; replaces the old portal's "Scanned Assets"
 * view, which read /api/vuln - a service with no platform dashboard). Nothing is collected or entered here: it reads what the
 * platform already holds.
 *   findings   VAPT Center gather() (engine/vapt-center.js): Greenbone internal scans, Tenable and FireCompass (VAPT Studio) and
 *              the penetration-testing engineer - open, risk-accepted and fixed, with first / last seen.
 *   scans      the hosts each scanner examined, also the clean ones: Greenbone (vulnscan_results), Tenable / Nessus (vapt_scanned),
 *              FireCompass (fc_findings: an import lists only what it found) - the same index Coverage & Query reads.
 *   scope      the approved internal scan scope of Vulnerability Scans (vulnscan: scope, set by an administrator).
 *   SLA        the remediation SLA of the VAPT Center (days per severity, VAPT Center -> SLA). VAPT Center absent = not judged.
 *   register   the asset register (assets), criticality from the testing tier / critical tags (as VAPT Center) else the record.
 *
 * One SCANNED ASSET per register record a scanner reported, or per host the register does not know. Matching, first hit wins:
 *   1. asset id  - the finding carries the register id (the penetration-testing engineer)
 *   2. IP        - the scanned address is the asset's management IP / IP / one of its IPs
 *   3. name      - the scanned name is the asset's name / host name / FQDN, or their short name when only one asset has it
 * The same vulnerability on one asset from several scanners is ONE finding (identity: the first CVE, else the normalised title -
 * the key of the Vulnerabilities page, so each finding links to it).
 * RISK = sum over the open findings of  max(severity weight, CVSS band weight)  x 1.5 when known-exploited / RCE is named in the
 *   finding  x 1.25 when a scanner reported it internet-facing; then x the asset's criticality (critical 2, high 1.5, medium /
 *   unrated 1, low 0.75). Weights: critical 10, high 5, medium 2, low 0.5 (CVSS band: >= 9 critical, >= 7 high, >= 4 medium).
 *   EPSS is not in any source the platform reads, so it is not used - and the rule says so.
 * OVERDUE = an open finding older (since first seen) than the SLA days of its severity; one without a first-seen date is not judged.
 * COVERAGE  register assets with an address inside the approved scan scope that no scanner has examined (never) or not for
 *   stale_days (admin setting, default 30); scanned hosts not in the register (unknown assets).
 * Host names and owners are internal: operators and administrators.
 *   GET  /scanned-assets                 operator  ?sev=&scanner=&site=&criticality=&owner=&q=   assets, KPIs, chart, coverage
 *   GET  /scanned-assets/export          operator  the same filters - rows for the Excel file                       audited
 *   GET  /scanned-assets/:id             operator  one asset with its findings
 *   POST /scanned-assets/settings        admin     {stale_days}                                                     audited
 */
const DAY = 86400000, RIYADH = 3 * 3600000;
const SEVS = ['critical', 'high', 'medium', 'low'];
const SEVR = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const W = { critical: 10, high: 5, medium: 2, low: 0.5, info: 0 };
const CRIT_M = { critical: 2, high: 1.5, medium: 1, unrated: 1, low: 0.75 };
const CRITS = ['critical', 'high', 'medium', 'low', 'unrated'];
const SCANNERS = { greenbone: 'Greenbone', tenable: 'Tenable', firecompass: 'FireCompass', pentest: 'Pentest engineer' };
const EXPL = /\b(exploit(ed|able)?|kev|known exploited|ransomware|rce|remote code execution|actively exploited|wormable)\b/i;
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const RISK_RULE = 'risk = sum over open findings of max(severity weight, CVSS band weight) x 1.5 when known-exploited / remote code execution is named x 1.25 when internet-facing; then x asset criticality (critical 2, high 1.5, medium / unrated 1, low 0.75). Weights: critical 10, high 5, medium 2, low 0.5. EPSS is not in the scanner data and is not used.';
const MATCH_RULE = 'matched to the register by the asset id the finding carries, else by IP address, else by name (name, host name, FQDN or a unique short name)';
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);
const low = (v) => String(v == null ? '' : v).toLowerCase().trim();
const short = (v) => low(v).split('.')[0];
const sevOf = (v) => (SEVR[low(v)] != null ? low(v) : 'info');
const band = (c) => (c == null ? 'info' : c >= 9 ? 'critical' : c >= 7 ? 'high' : c >= 4 ? 'medium' : c > 0 ? 'low' : 'info');
const ms = (v) => { if (v == null || v === '') return null; const t = typeof v === 'number' ? v : Date.parse(String(v).length === 10 ? v + 'T00:00:00Z' : v); return Number.isFinite(t) ? t : null; };
const isoOf = (t) => (t == null ? null : new Date(t).toISOString());
const ipsOf = (a) => [...new Set([a.mgmt_ip, a.ip].concat(a.ips || []).filter((x) => IP_RE.test(String(x || ''))))];
const hid = (h) => 'h.' + crypto.createHash('sha256').update(low(h)).digest('hex').slice(0, 16);
// the identity of a vulnerability - the same key as the Vulnerabilities page (engine/vuln-intel.js), so a finding links to it
function vulnKey(f) {
  const cves = [...new Set((f.cves || []).map((c) => String(c).toUpperCase()).filter((c) => /^CVE-\d{4}-\d{3,}$/.test(c)))].sort();
  return { key: cves[0] || 't:' + low(f.title).replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 80), cves };
}

function createScannedAssets(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {}, every() {} };
  const A = () => app.addons || {};
  const cfgC = () => store.collection('sa_cfg');
  const iso = () => new Date(now()).toISOString(), day = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'scanned.assets.' + action, target, detail }); };
  const settings = () => { const x = cfgC().get('settings') || {}; return { stale_days: Number.isInteger(x.stale_days) ? x.stale_days : 30, by: x.by || null, at: x.at || null }; };

  /* ---- the asset register, indexed by id, address and name */
  function register() {
    const pol = (store.collection('pentest_settings').get('cadence') || {}).values || {}, ctags = (pol.critical_tags || ['business-critical', 'critical', 'crown-jewel']).map(low);
    const tiers = store.collection('test_tier'), byId = new Map(), byIp = new Map(), byName = new Map(), shortN = new Map();
    for (const a of store.collection('assets').all((x) => x.status !== 'disposed' && x.status !== 'retired')) {
      const t = tiers.get(a.id), c0 = low(a.criticality || (a.cia && a.cia.a));
      const crit = t && t.tier === 'critical' ? 'critical' : (a.tags || []).map(low).some((x) => ctags.includes(x)) ? 'critical' : CRIT_M[c0] && c0 !== 'unrated' ? c0 : 'unrated';
      const rec = { id: a.id, name: s(a.name, 120), owner: s(a.owner, 120) || null, department: s(a.department, 120) || null, criticality: crit, type: a.type || null, site: s(a.site, 80) || null, ips: ipsOf(a), names: [a.name, a.hostname, a.fqdn].filter(Boolean).map((x) => s(x, 200)) };
      byId.set(a.id, rec);
      for (const ip of rec.ips) if (!byIp.has(ip)) byIp.set(ip, rec);
      for (const n of rec.names) { if (!byName.has(low(n))) byName.set(low(n), rec); const sh = short(n); if (sh && !IP_RE.test(low(n))) { const e = shortN.get(sh); shortN.set(sh, e && e !== rec ? 'ambiguous' : rec); } }
    }
    for (const [k, v] of shortN) if (v !== 'ambiguous' && !byName.has(k)) byName.set(k, v);
    return { byId, byIp, byName };
  }
  function match(R, { asset_id, ips = [], names = [] }) {
    if (asset_id && R.byId.has(asset_id)) return { a: R.byId.get(asset_id), by: 'asset id', on: asset_id };
    for (const ip of ips) if (R.byIp.has(ip)) return { a: R.byIp.get(ip), by: 'IP', on: ip };
    for (const n of names) { const k = low(n); if (R.byName.has(k)) return { a: R.byName.get(k), by: 'name', on: n }; if (!IP_RE.test(k) && k.indexOf('.') > 0 && R.byName.has(short(k))) return { a: R.byName.get(short(k)), by: 'name', on: n }; }
    return null;
  }
  const split = (list) => { const ips = [], names = []; for (const x of list) { const v = s(x, 200); if (!v) continue; (IP_RE.test(v) ? ips : names).push(v); } return { ips: [...new Set(ips)], names: [...new Set(names)] }; };

  /* ---- every host a scanner examined (also the clean ones), with when and by which tool */
  function scanRecords() {
    const out = [], tools = new Set();
    for (const r of store.collection('vulnscan_results').all()) { tools.add('Greenbone'); for (const h of r.hosts || []) out.push({ list: [h], at: ms(r.at), tool: 'Greenbone' }); }
    for (const r of store.collection('vapt_scanned').all()) { tools.add('Tenable'); out.push({ list: (r.ips || []).concat(r.names || []), at: ms(r.at), tool: 'Tenable' }); }
    for (const f of store.collection('fc_findings').all()) {
      const tool = (f.vendor || 'firecompass') === 'tenable' ? 'Tenable' : 'FireCompass'; tools.add(tool);
      out.push({ list: [f.host, f.asset].filter(Boolean), at: ms(f.last_seen && /^\d{4}-\d{2}-\d{2}/.test(f.last_seen) ? f.last_seen : f.last_imported), tool });
    }
    return { records: out, tools: [...tools].sort() };
  }
  async function findings() {
    const VC = A().vaptCenter;
    if (!VC || !VC.gather) return { findings: [], status: { vapt_center: { ok: false, error: 'VAPT Center is not installed - run the update' } }, sla: null };
    let g;
    try { g = await VC.gather(); } catch (e) { L.every('sa:gather', 3600000, 'warn', 'Scanned Assets: the scanners could not be read', { err: s(e.message, 200) }); return { findings: [], status: { vapt_center: { ok: false, error: s(e.message, 200) } }, sla: null }; }
    let sla = null; try { sla = VC.slaDays ? VC.slaDays() : null; } catch (e) { L.every('sa:sla', 3600000, 'warn', 'Scanned Assets: the VAPT Center SLA could not be read', { err: s(e.message, 200) }); sla = null; }
    return { findings: g.findings || [], status: g.status || {}, sla };
  }

  /* ---- one record per scanned asset */
  async function build() {
    const t = now(), R = register(), F = await findings(), S = scanRecords(), ents = new Map();
    const ent = (m, primary) => {
      const id = m ? 'a.' + m.a.id : hid(primary);
      let e = ents.get(id);
      if (!e) ents.set(id, e = { id, asset: m ? m.a : null, match: m ? { by: m.by, on: m.on } : null, ips: new Set(m ? m.a.ips : []), names: new Set(m ? m.a.names : []), tools: new Set(), last_scan: null, last_tool: null, rows: new Map() });
      return e;
    };
    for (const r of S.records) {
      const p = split(r.list); if (!p.ips.length && !p.names.length) continue;
      const e = ent(match(R, p), p.ips[0] || p.names[0]);
      p.ips.forEach((x) => e.ips.add(x)); p.names.forEach((x) => e.names.add(x)); e.tools.add(r.tool);
      if (r.at && (!e.last_scan || r.at > e.last_scan)) { e.last_scan = r.at; e.last_tool = r.tool; }
    }
    for (const f of F.findings) {
      const p = split([f.host, f.asset]); if (!p.ips.length && !p.names.length) continue;
      const e = ent(match(R, { asset_id: f.asset_id, ips: p.ips, names: p.names }), p.ips[0] || p.names[0]);
      p.ips.forEach((x) => e.ips.add(x)); p.names.forEach((x) => e.names.add(x));
      const src = SCANNERS[f.src] ? f.src : 'firecompass'; e.tools.add(SCANNERS[src]);
      const k = vulnKey(f); if (k.key === 't:') continue;
      let r = e.rows.get(k.key);
      if (!r) e.rows.set(k.key, r = { key: k.key, title: s(f.title, 240), cves: new Set(), severity: 'info', cvss: null, sources: new Set(), st: new Set(), first: null, last: null, fixed_at: null, external: false, exploited: false });
      k.cves.forEach((c) => r.cves.add(c)); r.sources.add(src); r.st.add(f.status);
      if (SEVR[sevOf(f.severity)] > SEVR[r.severity]) r.severity = sevOf(f.severity);
      if (typeof f.cvss === 'number' && isFinite(f.cvss) && (r.cvss == null || f.cvss > r.cvss)) r.cvss = f.cvss;
      const fs0 = ms(f.first_seen), ls = ms(f.last_seen), fx = ms(f.fixed_at);
      if (fs0 && (!r.first || fs0 < r.first)) r.first = fs0;
      if (ls && (!r.last || ls > r.last)) r.last = ls;
      if (fx && (!r.fixed_at || fx > r.fixed_at)) r.fixed_at = fx;
      if (f.exposure === 'external') r.external = true;
      if (EXPL.test(String(f.title || '') + ' ' + String(f.description || ''))) r.exploited = true;
    }
    const sla = F.sla, out = [];
    for (const e of ents.values()) {
      const crit = e.asset ? e.asset.criticality : 'unrated', mult = CRIT_M[crit];
      const open = { critical: 0, high: 0, medium: 0, low: 0 }, list = [];
      let base = 0, oldest = null, overdue = sla ? 0 : null, notJudged = 0, fixed30 = 0;
      for (const r of e.rows.values()) {
        const status = r.st.has('open') ? 'open' : r.st.has('accepted') ? 'accepted' : 'fixed';
        const age = r.first ? Math.floor((t - r.first) / DAY) : null;
        let pts = 0, sla_state = null;
        if (status === 'open') {
          if (open[r.severity] != null) open[r.severity]++;
          pts = Math.max(W[r.severity], W[band(r.cvss)]) * (r.exploited ? 1.5 : 1) * (r.external ? 1.25 : 1); base += pts;
          if (age != null && (oldest == null || age > oldest)) oldest = age;
          if (sla && sla[r.severity]) { if (age == null) { sla_state = 'not judged'; notJudged++; } else if (age > sla[r.severity]) { sla_state = 'overdue'; overdue++; } else sla_state = 'within'; }
        } else if (status === 'fixed' && r.fixed_at && t - r.fixed_at <= 30 * DAY) fixed30++;
        list.push({ key: r.key, title: r.title, cves: [...r.cves], severity: r.severity, cvss: r.cvss, scanners: [...r.sources].map((x) => SCANNERS[x]), status, first_seen: isoOf(r.first), last_seen: isoOf(r.last), fixed_at: isoOf(r.fixed_at),
          age_days: age, internet_facing: r.external, known_exploited: r.exploited, points: Math.round(pts * 100) / 100, sla_days: sla && sla[r.severity] ? sla[r.severity] : null, sla_state });
      }
      list.sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1) || SEVR[b.severity] - SEVR[a.severity] || b.points - a.points);
      const ips = [...e.ips], names = [...e.names];
      out.push({ id: e.id, ip: ips[0] || null, ips, host: (e.asset && e.asset.name) || names[0] || ips[0], names, registered: !!e.asset,
        asset: e.asset ? { id: e.asset.id, name: e.asset.name, owner: e.asset.owner, department: e.asset.department, criticality: e.asset.criticality, type: e.asset.type, site: e.asset.site } : null,
        match: e.match, criticality: crit, open, open_total: SEVS.reduce((x, k) => x + open[k], 0), risk: Math.round(base * mult * 10) / 10, risk_base: Math.round(base * 10) / 10, risk_multiplier: mult,
        oldest_open_days: oldest, last_scan: isoOf(e.last_scan), last_scan_tool: e.last_tool, scanners: [...e.tools].sort(), fixed_30d: fixed30, overdue, not_judged: notJudged, _findings: list });
    }
    out.sort((a, b) => b.risk - a.risk || b.open_total - a.open_total || String(a.host).localeCompare(String(b.host)));
    return { rows: out, status: F.status, sla, tools: S.tools, R, t };
  }

  /* ---- coverage: in the approved scope and never / not recently scanned; scanned and not in the register */
  function coverage(B) {
    const st = settings(), sc = store.collection('vulnscan').get('scope') || { allowed: [], exclude: [] };
    const res = { stale_days: st.stale_days, scope: { allowed: sc.allowed || [], exclude: sc.exclude || [] }, never: [], stale: [], unknown: [], note: null };
    let allowed = [], exclude = [];
    try { allowed = (sc.allowed || []).map((x) => IP.parseTarget(x)); exclude = (sc.exclude || []).map((x) => IP.parseTarget(x)); } catch (e) { res.note = 'the scan scope could not be read: ' + s(e.message, 160); L.every('sa:scope', 3600000, 'warn', 'Scanned Assets: the scan scope could not be read', { err: s(e.message, 160) }); allowed = []; }
    if (!allowed.length) res.note = res.note || 'no approved scan scope yet - an administrator sets the internal ranges in Vulnerability Scans; never / stale scanned is not judged until then';
    else {
      const byAsset = new Map(B.rows.filter((r) => r.registered).map((r) => [r.asset.id, r]));
      for (const a of B.R.byId.values()) {
        const inScope = a.ips.filter((ip) => IP.contains(allowed, ip) && !IP.contains(exclude, ip)); if (!inScope.length) continue;
        const r = byAsset.get(a.id), last = r && r.last_scan ? Date.parse(r.last_scan) : null;
        const item = { asset_id: a.id, name: a.name, ip: inScope[0], owner: a.owner, department: a.department, site: a.site, criticality: a.criticality, type: a.type, last_scan: r ? r.last_scan : null, last_scan_tool: r ? r.last_scan_tool : null, days: last ? Math.floor((B.t - last) / DAY) : null };
        if (!last) res.never.push(item); else if (item.days > st.stale_days) res.stale.push(item);
      }
      const rank = (c) => SEVR[c === 'unrated' ? 'medium' : c] || 0;
      res.never.sort((x, y) => rank(y.criticality) - rank(x.criticality) || String(x.name).localeCompare(String(y.name))); res.stale.sort((x, y) => y.days - x.days);
    }
    res.unknown = B.rows.filter((r) => !r.registered).map((r) => ({ id: r.id, host: r.host, ip: r.ip, names: r.names, scanners: r.scanners, last_scan: r.last_scan, open: r.open, open_total: r.open_total }))
      .sort((x, y) => y.open_total - x.open_total || String(x.host).localeCompare(String(y.host)));
    return res;
  }

  function filterRows(rows, q) {
    const term = low(q.q), owner = low(q.owner), site = low(q.site);
    return rows.filter((r) => (!q.sev || r.open[q.sev] > 0) && (!q.scanner || r.scanners.includes(SCANNERS[q.scanner])) && (!site || low(r.asset && r.asset.site) === site)
      && (!q.criticality || r.criticality === q.criticality) && (!owner || low(r.asset && r.asset.owner).includes(owner))
      && (!term || low([r.host, r.ips.join(' '), r.names.join(' '), r.asset && r.asset.name, r.asset && r.asset.owner, r.asset && r.asset.department, r._findings.map((f) => f.cves.join(' ')).join(' ')].join(' ')).includes(term)));
  }
  const slim = (r) => { const o = Object.assign({}, r); delete o._findings; return o; };

  async function view(who, q = {}) {
    const B = await build(), rows = filterRows(B.rows, q), all = B.rows, st = settings();
    const sum = (L2, k) => L2.reduce((x, r) => x + (r[k] || 0), 0), open = {}; for (const k of SEVS) open[k] = rows.reduce((x, r) => x + r.open[k], 0);
    const cov = coverage(B), anyData = all.length > 0;
    return { generated_at: iso(), sources: B.status, scanners_read: B.tools, can_edit: who.role === 'admin', settings: st,
      sla: B.sla ? { days: B.sla, from: 'VAPT Center remediation SLA (days per severity, set in VAPT Center)' } : { days: null, from: null, note: 'overdue is not judged: the VAPT Center, which holds the remediation SLA, is not installed' },
      risk_rule: RISK_RULE, match_rule: MATCH_RULE,
      empty: anyData ? null : 'No scan results yet - connect Greenbone in Vulnerability Scans, or Tenable / FireCompass in VAPT Studio. Nothing is shown until a scanner has reported.',
      totals: { scanned: rows.length, registered: rows.filter((r) => r.registered).length, unknown: rows.filter((r) => !r.registered).length, with_open: rows.filter((r) => r.open_total).length, open,
        overdue: B.sla ? sum(rows, 'overdue') : null, fixed_30d: sum(rows, 'fixed_30d'), never_scanned: cov.never.length, stale: cov.stale.length },
      facets: { sites: [...new Set(all.map((r) => r.asset && r.asset.site).filter(Boolean))].sort(), owners: [...new Set(all.map((r) => r.asset && r.asset.owner).filter(Boolean))].sort(), scanners: Object.entries(SCANNERS).map(([key, label]) => ({ key, label })) },
      riskiest: rows.filter((r) => r.open_total).slice(0, 10).map((r) => ({ id: r.id, host: r.host, risk: r.risk, open: r.open })),
      assets: rows.slice(0, 2000).map(slim), truncated: rows.length > 2000, coverage: cov };
  }
  async function one(id) {
    const r = (await build()).rows.find((x) => x.id === id); if (!r) throw httpErr(404, 'no scanned asset ' + id + ' - it may have been rescanned or matched to the register since the page loaded');
    return Object.assign(slim(r), { findings: r._findings.slice(0, 1000), risk_rule: RISK_RULE });
  }
  async function exportRows(who, q = {}) {
    const B = await build(), rows = filterRows(B.rows, q);
    const findings = []; for (const r of rows) for (const f of r._findings) if (f.status === 'open') findings.push([r.host, r.ip, f.title, f.cves.join(' '), f.severity, f.cvss, f.scanners.join(', '), f.first_seen ? f.first_seen.slice(0, 10) : '', f.age_days, f.sla_state || '']);
    const filter = Object.entries(q).filter(([, v]) => v).map(([k, v]) => k + '=' + v).join(' ') || 'all scanned assets';
    audit(who, 'export', 'scanned-assets', { assets: rows.length, findings: findings.length, filter });
    return { filename: 'scanned-assets-' + day(now()) + '.xlsx', filter, generated_at: iso(), risk_rule: RISK_RULE,
      assets: rows.map((r) => [r.host, r.ips.join(' '), r.registered ? 'yes' : 'no', r.match ? r.match.by : '', r.asset ? r.asset.owner : '', r.asset ? r.asset.department : '', r.criticality, r.asset ? r.asset.type : '', r.asset ? r.asset.site : '',
        r.open.critical, r.open.high, r.open.medium, r.open.low, r.risk, r.oldest_open_days, r.last_scan ? r.last_scan.slice(0, 10) : '', r.scanners.join(', '), r.fixed_30d, r.overdue]),
      findings };
  }
  function saveSettings(input, who) {
    const b = body(input).int('stale_days', { required: true, min: 1, max: 365 }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot change the scan freshness setting: a person does');
    const prev = settings().stale_days;
    cfgC().put({ id: 'settings', stale_days: b.stale_days, by: who.user, at: iso() });
    audit(who, 'settings', 'stale_days', { from: prev, to: b.stale_days });
    return settings();
  }
  return { view, one, exportRows, saveSettings, build, coverage };
}

function registerScannedAssets(srv, app, X) {
  const S = X && X.view ? X : createScannedAssets(app, X || {});
  app.addons = app.addons || {}; app.addons.scannedAssets = S;
  const Q = (ctx) => body(ctx.query || {}).oneOf('sev', SEVS).oneOf('scanner', Object.keys(SCANNERS)).str('site', { max: 80 }).oneOf('criticality', CRITS).str('owner', { max: 120 }).str('q', { max: 120 }).done();
  srv.route('GET', '/scanned-assets', (ctx) => { ctx.need('operator'); return S.view(ctx.who, Q(ctx)); });
  srv.route('GET', '/scanned-assets/export', (ctx) => { ctx.need('operator'); return S.exportRows(ctx.who, Q(ctx)); });
  srv.route('POST', '/scanned-assets/settings', (ctx) => { ctx.need('admin'); return S.saveSettings(ctx.body, ctx.who); });
  srv.route('GET', '/scanned-assets/:id', (ctx) => { ctx.need('operator'); const id = param(ctx.params.id, 'id'); if (!/^(a\.[A-Za-z0-9_.:-]{1,78}|h\.[0-9a-f]{16})$/.test(id)) throw httpErr(400, 'id is not a scanned asset id'); return S.one(id); });
  return S;
}

module.exports = { createScannedAssets, registerScannedAssets, RISK_RULE };
