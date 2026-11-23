// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * Vulnerabilities + Risk Prioritization ({P} = /api/itam). Nothing is entered here: both read what the platform already holds.
 *
 * VULNERABILITIES - one consistent inventory over every scanner ("adapter"). The raw findings come from VAPT Center's gather()
 *   (Greenbone, Tenable, FireCompass, the penetration-testing engineer). The same vulnerability reported by several adapters, or on
 *   several devices, is ONE row: its identity is the CVE (else the normalised title). Per row: the adapters that reported it, the
 *   devices it is on, the PRIMARY score (the score of the first adapter in the primary order that reported it - the order is a
 *   setting, shown on the page) and the MAX score across adapters, and the worst severity. Charts: by severity (unique
 *   vulnerabilities), by software (the installed product on the device whose name appears in the finding, else the product named at
 *   the start of the finding title - each row says which), by OS (affected devices, from the asset register; a host not in the
 *   register is counted as such, never guessed).
 *
 * RISK PRIORITIZATION - every device in the asset register gets an explained 0-100 risk score (higher = riskier):
 *   worst open vulnerability (critical 40 / high 28 / medium 15 / low 5, or CVSS x 4 when higher), +2 per further high/critical
 *   (max +10), internet-facing +15, OS / platform past end of support +15, sensitive data (classification secret / top secret /
 *   restricted, or confidentiality high) +10, business-critical +10, no endpoint protection +10. Capped at 100. An input the
 *   platform does not hold adds 0 and is listed as not measured - a flat score means missing context, never "safe".
 *   Bands: critical >= 60, medium 30-59, low < 30. Devices are grouped into PROFILES (device classes matched on type and OS family,
 *   first match wins, the last one catches the rest); an inactive profile's devices are not scored into the overall picture and
 *   are listed as such. A profile's severity is the business weight used to order the fix-first list (critical 1.0, high 0.85,
 *   medium 0.7, low 0.5). Risk factors: the share of scored devices carrying each factor.
 *   Learning: one snapshot a day of the bands; per band the least-squares slope per week over the last 30 snapshots (3+ needed),
 *   otherwise withheld.
 *
 * Host names and device lists are internal: a viewer sees charts, counts and profiles; operators see rows and devices.
 *   GET  /vuln-inventory                    viewer    sources, by severity / software / OS, totals (+ inventory rows: operator)
 *   GET  /vuln-inventory/item?key=          operator  one vulnerability: devices, adapters, scores
 *   GET  /vuln-inventory/export             operator  CSV                                                       audited
 *   PUT  /vuln-inventory/settings           admin     {primary_order: [adapter...]}                             audited
 *   GET  /risk-prioritization               viewer    overall, bands, trend, factors, profiles (+ fix-first devices: operator)
 *   POST /risk-prioritization/profiles      admin     {name, description?, types?, os?, severity, active?}      audited
 *   PUT  /risk-prioritization/profiles/:id  admin     any of the above                                          audited
 *   POST /risk-prioritization/profiles/:id/delete   admin  (the catch-all profile cannot be deleted)          audited
 */
const DAY = 86400000, RIYADH = 3 * 3600000;
const ADAPTERS = ['tenable', 'greenbone', 'pentest', 'firecompass'];
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEVR = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const TYPES = ['server', 'workstation', 'laptop', 'network', 'storage', 'printer', 'phone', 'mobile', 'appliance', 'virtual', 'other'];
const OSF = ['windows', 'linux', 'macos', 'unix', 'network', 'other'];
const WEIGHT = { critical: 1, high: 0.85, medium: 0.7, low: 0.5 };
const DEFAULT_PROFILES = [
  { id: 'p-winsrv', name: 'Windows Server profile', description: 'Windows Server devices.', types: ['server', 'virtual'], os: ['windows'], severity: 'critical' },
  { id: 'p-linsrv', name: 'Linux Server profile', description: 'Linux and Unix server devices.', types: ['server', 'virtual'], os: ['linux', 'unix'], severity: 'critical' },
  { id: 'p-winws', name: 'Windows Workstation profile', description: 'Windows desktops and laptops.', types: ['workstation', 'laptop'], os: ['windows'], severity: 'medium' },
  { id: 'p-macws', name: 'macOS Workstation profile', description: 'macOS desktops and laptops.', types: ['workstation', 'laptop'], os: ['macos'], severity: 'medium' },
  { id: 'p-net', name: 'Network Devices profile', description: 'Switches, routers, firewalls and other network devices.', types: ['network', 'appliance'], os: [], severity: 'high' },
  { id: 'p-other', name: 'Other Devices profile', description: 'Every device no other profile matches.', types: [], os: [], severity: 'low', catchall: true }
];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const low = (v) => String(v == null ? '' : v).toLowerCase();
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
const sevOf = (v) => (SEVR[low(v)] != null ? low(v) : 'info');

function osFamily(os, type) {
  const o = low(os);
  if (/windows/.test(o)) return 'windows';
  if (/linux|red ?hat|rhel|ubuntu|centos|oracle linux|suse|debian|rocky|alma/.test(o)) return 'linux';
  if (/mac ?os|os ?x|darwin/.test(o)) return 'macos';
  if (/solaris|aix|hp-ux|freebsd/.test(o)) return 'unix';
  if (/ios|nx-os|junos|pan-os|fortios|routeros|arubaos|comware/.test(o) || ['network', 'appliance'].includes(low(type))) return 'network';
  return o ? 'other' : 'unknown';
}
const OS_LABEL = { windows: 'Windows', linux: 'Linux', macos: 'macOS', unix: 'Unix', network: 'Network OS', other: 'Other', unknown: 'OS not recorded', unregistered: 'Not in the asset register' };
// the product a finding title names: the text before a version comparison or the word "vulnerability" ("OpenSSH < 9.6" -> OpenSSH)
function titleProduct(t) {
  const parts = String(t || '').split(/\s(?:<|<=|>|before|prior to|vulnerabilit|multiple|remote|denial|security update|end of life|unsupported|version|\d)/i); if (parts.length < 2) return null; // no version / vulnerability wording: the title does not name a product
  const m = parts[0].replace(/[(:,;].*$/, '').trim();
  return m && m.length >= 3 && m.length <= 60 && !/^(no|missing|weak|unsupported|outdated|the|a|an)\b/i.test(m) ? m : null;
}
const swKey = (n) => low(n).replace(/\(.*?\)/g, ' ').replace(/\b(v?\d[\w.]*|x64|x86|64-bit|32-bit|edition|for windows)\b/g, ' ').replace(/\s+/g, ' ').trim();

function lsq(pts) { const n = pts.length; if (n < 3) return null; const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n, sxx = pts.reduce((a, p) => a + (p[0] - mx) ** 2, 0); return sxx ? pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0) / sxx : 0; }

function createVulnIntel(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const cfgC = () => store.collection('vi_cfg'), profC = () => store.collection('rp_profiles'), histC = () => store.collection('rp_hist');
  const iso = () => new Date(now()).toISOString(), day = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const primaryOrder = () => { const o = (cfgC().get('settings') || {}).primary_order; return Array.isArray(o) && o.length ? o : ADAPTERS.slice(); };

  /* ---- the asset register, indexed by every name a scanner may report */
  function register() {
    const idx = new Map(), list = [];
    for (const a of store.collection('assets').all((x) => x.status !== 'disposed' && x.status !== 'retired')) {
      list.push(a);
      for (const k of [a.mgmt_ip, a.hostname, a.name, a.fqdn].concat(a.ips || [])) if (k) idx.set(low(k), a);
    }
    return { idx, list };
  }
  async function raw() {
    const VC = (app.addons || {}).vaptCenter;
    if (!VC || !VC.gather) return { findings: [], status: { vapt_center: { ok: false, error: 'VAPT Center is not installed - run the update' } } };
    try { return await VC.gather(); } catch (e) { L.every('vi:gather', 3600000, 'warn', 'Vulnerabilities: the scanners could not be read', { err: s(e.message, 200) }); return { findings: [], status: { vapt_center: { ok: false, error: s(e.message, 200) } } }; }
  }

  /* ---- Vulnerabilities */
  async function inventory() {
    const g = await raw(), R = register(), order = primaryOrder(), rows = new Map();
    for (const f of g.findings) {
      if (f.status !== 'open') continue;
      const cves = [...new Set((f.cves || []).map((c) => String(c).toUpperCase()).filter((c) => /^CVE-\d{4}-\d{3,}$/.test(c)))].sort();
      const key = cves[0] || 't:' + low(f.title).replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 80);
      if (key === 't:') continue;
      let r = rows.get(key);
      if (!r) rows.set(key, r = { key, cve: cves[0] || null, cves: new Set(), title: s(f.title, 200), severity: 'info', scores: {}, adapters: new Set(), devices: new Map(), first_seen: null });
      cves.forEach((c) => r.cves.add(c));
      const src = ADAPTERS.includes(f.src) ? f.src : 'other';
      r.adapters.add(src);
      if (SEVR[sevOf(f.severity)] > SEVR[r.severity]) r.severity = sevOf(f.severity);
      if (typeof f.cvss === 'number' && isFinite(f.cvss)) r.scores[src] = Math.max(r.scores[src] == null ? -1 : r.scores[src], f.cvss);
      const host = s(f.host || f.asset, 120), a = R.idx.get(low(f.host)) || R.idx.get(low(f.asset)) || null;
      const dk = a ? 'a:' + a.id : 'h:' + low(host);
      if (!r.devices.has(dk)) r.devices.set(dk, { host, asset: a ? a.name : null, asset_id: a ? a.id : null, os: a ? osFamily(a.os, a.type) : 'unregistered', software: a ? a.software || [] : [], adapters: new Set() });
      r.devices.get(dk).adapters.add(src);
      if (f.first_seen && (!r.first_seen || String(f.first_seen) < r.first_seen)) r.first_seen = String(f.first_seen);
    }
    const out = [];
    for (const r of rows.values()) {
      const sc = Object.entries(r.scores), primAd = order.find((x) => r.scores[x] != null) || (sc[0] && sc[0][0]) || null;
      // software: the installed product named in the finding (on any affected device), else the title's own product
      let product = null, product_from = null;
      const tl = low(r.title);
      for (const d of r.devices.values()) { for (const sw of d.software) { const k = swKey(sw && (sw.name || sw)); if (k.length >= 4 && (tl.includes(k) || (k.split(' ').length > 1 && tl.includes(k.split(' ').slice(1).join(' ')) && k.split(' ').slice(1).join(' ').length >= 5))) { product = s(sw.name || sw, 80).replace(/\s+v?\d[\w.]*$/, ''); product_from = 'installed software'; break; } } if (product) break; }
      if (!product) { const p = titleProduct(r.title); if (p) { product = p; product_from = 'finding title'; } }
      out.push({ key: r.key, cve: r.cve, cves: [...r.cves], title: r.title, severity: r.severity, adapters: [...r.adapters].sort((a, b) => order.indexOf(a) - order.indexOf(b)),
        primary_adapter: primAd, primary_score: primAd ? r.scores[primAd] : null, max_score: sc.length ? Math.max(...sc.map((x) => x[1])) : null,
        devices: r.devices.size, os: [...new Set([...r.devices.values()].map((d) => d.os))], product, product_from, first_seen: r.first_seen, _dev: r.devices });
    }
    out.sort((a, b) => SEVR[b.severity] - SEVR[a.severity] || (b.max_score || 0) - (a.max_score || 0) || b.devices - a.devices);
    return { rows: out, status: g.status, register: R };
  }
  function pct(n, d) { return d ? Math.round(1000 * n / d) / 10 : 0; }
  async function vulnView(who, q = {}) {
    const I = await inventory(), rows = I.rows;
    const total = rows.length, instances = rows.reduce((a, r) => a + r.devices, 0);
    const bySev = SEV.filter((x) => x !== 'info').map((k) => { const n = rows.filter((r) => r.severity === k).length; return { key: k, count: n, pct: pct(n, total) }; });
    const info = rows.filter((r) => r.severity === 'info').length; if (info) bySev.push({ key: 'info', count: info, pct: pct(info, total) });
    const sw = new Map(); for (const r of rows) if (r.product) { const k = r.product; const e = sw.get(k) || { key: k, vulnerabilities: 0, devices: new Set(), from: r.product_from }; e.vulnerabilities++; for (const d of r._dev.keys()) e.devices.add(d); if (r.product_from === 'installed software') e.from = 'installed software'; sw.set(k, e); }
    const bySw = [...sw.values()].map((e) => ({ key: e.key, vulnerabilities: e.vulnerabilities, devices: e.devices.size, from: e.from })).sort((a, b) => b.vulnerabilities - a.vulnerabilities || b.devices - a.devices).slice(0, 10);
    const devOs = new Map(); for (const r of rows) for (const [k, d] of r._dev) devOs.set(k, d.os);
    const osCount = {}; for (const o of devOs.values()) osCount[o] = (osCount[o] || 0) + 1;
    const byOs = Object.entries(osCount).map(([k, n]) => ({ key: k, label: OS_LABEL[k] || k, devices: n, pct: pct(n, devOs.size) })).sort((a, b) => b.devices - a.devices);
    const res = { generated_at: iso(), sources: I.status, primary_order: primaryOrder(), totals: { vulnerabilities: total, instances, devices: devOs.size, critical: bySev[0].count, high: bySev[1].count, multi_adapter: rows.filter((r) => r.adapters.length > 1).length },
      by_severity: bySev, by_software: bySw, by_os: byOs, can_see_rows: ['operator', 'admin'].includes(who.role) };
    if (res.can_see_rows) {
      const term = low(q.q), sev = low(q.sev), ad = low(q.adapter);
      res.inventory = rows.filter((r) => (!sev || r.severity === sev) && (!ad || r.adapters.includes(ad)) && (!term || low(r.cve + ' ' + r.title + ' ' + r.product + ' ' + r.cves.join(' ')).includes(term)))
        .slice(0, 500).map((r) => { const o = Object.assign({}, r); delete o._dev; return o; });
    }
    return res;
  }
  async function item(key) {
    const k = s(key, 120); if (!k) throw httpErr(400, 'key is required');
    const r = (await inventory()).rows.find((x) => x.key === k); if (!r) throw httpErr(404, 'no open vulnerability ' + k);
    const o = Object.assign({}, r, { devices_list: [...r._dev.values()].map((d) => ({ host: d.host, asset: d.asset, asset_id: d.asset_id, os: OS_LABEL[d.os] || d.os, adapters: [...d.adapters] })) }); delete o._dev; return o;
  }
  async function exportCsv(who) {
    const rows = (await inventory()).rows;
    const head = ['cve', 'other_cves', 'title', 'severity', 'primary_adapter', 'primary_score', 'max_score', 'adapters', 'devices', 'software', 'software_from', 'first_seen'];
    const csv = [head.join(',')].concat(rows.map((r) => [r.cve, r.cves.slice(1).join(' '), r.title, r.severity, r.primary_adapter, r.primary_score, r.max_score, r.adapters.join(' '), r.devices, r.product, r.product_from, r.first_seen].map(csvCell).join(','))).join('\n');
    audit(who, 'vuln.inventory.export', 'vulnerabilities', { rows: rows.length });
    return { filename: 'vulnerabilities-' + day(now()) + '.csv', csv };
  }
  function saveSettings(input, who) {
    const b = body(input).list('primary_order', { required: true, max: ADAPTERS.length, item: ADAPTERS }).done();
    if (new Set(b.primary_order).size !== b.primary_order.length) throw httpErr(400, 'primary_order: an adapter is listed twice');
    person(who, 'change the primary adapter order');
    const order = b.primary_order.concat(ADAPTERS.filter((x) => !b.primary_order.includes(x)));
    const prev = primaryOrder();
    cfgC().put({ id: 'settings', primary_order: order, by: who.user, at: iso() });
    audit(who, 'vuln.inventory.settings', 'primary_order', { from: prev, to: order });
    return { primary_order: order };
  }

  /* ---- Risk prioritization */
  function profiles() {
    if (!profC().get('p-other')) for (const p of DEFAULT_PROFILES) if (!profC().get(p.id)) profC().put(Object.assign({ active: true, builtin: true, order: DEFAULT_PROFILES.indexOf(p), by: 'built-in', at: null }, p));
    return profC().all().sort((a, b) => (a.catchall ? 1 : 0) - (b.catchall ? 1 : 0) || (a.order || 0) - (b.order || 0) || String(a.name).localeCompare(String(b.name)));
  }
  const matches = (p, a) => p.catchall || ((!p.types || !p.types.length || p.types.includes(low(a.type))) && (!p.os || !p.os.length || p.os.includes(osFamily(a.os, a.type))));
  async function coverageIndex() {
    const AC = (app.addons || {}).assetCoverage; if (!AC || !AC._build) return null;
    try { const m = new Map(); for (const r of (await AC._build()).rows || []) m.set(r.id || r.name, r); return m; } catch (e) { L.every('vi:cov', 3600000, 'warn', 'Risk prioritization: coverage could not be read', { err: s(e.message, 200) }); return null; }
  }
  async function score() {
    const I = await inventory(), cov = await coverageIndex(), P = profiles(), t = now();
    const perAsset = new Map();
    for (const r of I.rows) for (const d of r._dev.values()) if (d.asset_id) { const e = perAsset.get(d.asset_id) || []; e.push(r); perAsset.set(d.asset_id, e); }
    const external = new Set(); for (const f of (await raw()).findings) if (f.status === 'open' && f.exposure === 'external') { const a = I.register.idx.get(low(f.host)) || I.register.idx.get(low(f.asset)); if (a) external.add(a.id); }
    const pol = (store.collection('pentest_settings').get('cadence') || {}).values || {}, ctags = (pol.critical_tags || ['business-critical', 'critical', 'crown-jewel']).map(low), tiers = store.collection('test_tier');
    const anyEol = I.register.list.some((a) => a.eol), anyCls = I.register.list.some((a) => a.classification || a.cia);
    const devices = [];
    for (const a of I.register.list) {
      const prof = P.find((p) => matches(p, a)) || P[P.length - 1];
      const vs = perAsset.get(a.id) || [], why = [];
      let pts = 0;
      if (vs.length) {
        const w = vs.slice().sort((x, y) => SEVR[y.severity] - SEVR[x.severity] || (y.max_score || 0) - (x.max_score || 0))[0];
        const base = Math.max({ critical: 40, high: 28, medium: 15, low: 5, info: 0 }[w.severity], w.max_score != null ? Math.round(w.max_score * 4) : 0);
        pts += base; why.push({ points: base, text: 'worst open vulnerability: ' + (w.cve || w.title) + ' (' + w.severity + (w.max_score != null ? ', score ' + w.max_score : '') + ')' });
        const more = Math.min(10, 2 * Math.max(0, vs.filter((x) => SEVR[x.severity] >= 3).length - 1));
        if (more) { pts += more; why.push({ points: more, text: 'further high / critical vulnerabilities' }); }
      }
      const factors = {};
      factors.internet = external.has(a.id) || a.internet_facing === true || a.exposure === 'external';
      if (factors.internet) { pts += 15; why.push({ points: 15, text: 'internet-facing' }); }
      factors.eol = !!(a.eol && Date.parse(a.eol) && Date.parse(a.eol) < t);
      if (factors.eol) { pts += 15; why.push({ points: 15, text: 'past end of support (' + String(a.eol).slice(0, 10) + ')' }); }
      factors.sensitive = ['secret', 'top_secret', 'restricted'].includes(low(a.classification)) || low(a.cia && a.cia.c) === 'high';
      if (factors.sensitive) { pts += 10; why.push({ points: 10, text: 'holds sensitive data (' + (a.classification || 'confidentiality high') + ')' }); }
      const o = tiers.get(a.id); factors.critical = o ? o.tier === 'critical' : (a.tags || []).map(low).some((x) => ctags.includes(x)) || low(a.criticality) === 'critical';
      if (factors.critical) { pts += 10; why.push({ points: 10, text: 'business-critical' }); }
      const cr = cov && (cov.get(a.id) || cov.get(a.name)), edr = cr && cr.controls && cr.controls.edr ? cr.controls.edr.state : null;
      factors.no_edr = edr === 'missing';
      if (factors.no_edr) { pts += 10; why.push({ points: 10, text: 'no endpoint protection' }); }
      factors.vuln_critical = vs.some((x) => x.severity === 'critical');
      const sc = Math.min(100, pts), band = sc >= 60 ? 'critical' : sc >= 30 ? 'medium' : 'low';
      const not = []; if (!cov) not.push('endpoint protection (Coverage & Query not available)'); if (!anyEol) not.push('end of support (no end-of-support dates in the register)'); if (!anyCls) not.push('data sensitivity (no classification in the register)');
      devices.push({ id: a.id, name: a.name, type: a.type || null, os: OS_LABEL[osFamily(a.os, a.type)], profile: prof.id, active: prof.active !== false, score: sc, band, why, factors, not_measured: not, vulnerabilities: vs.length, priority: Math.round(sc * (WEIGHT[prof.severity] || 0.5)) });
    }
    return { devices, profiles: P, measured: { eol: anyEol, classification: anyCls, coverage: !!cov }, status: I.status };
  }
  function snapshotToday(S) {
    const d = day(now()), act = S.devices.filter((x) => x.active), c = { critical: 0, medium: 0, low: 0 };
    for (const x of act) c[x.band]++;
    histC().put({ id: d, day: d, at: now(), total: act.length, critical: c.critical, medium: c.medium, low: c.low });
    for (const old of histC().all((x) => x.day < day(now() - 400 * DAY))) histC().remove(old.id);
  }
  async function riskView(who) {
    const S = await score(); snapshotToday(S);
    const act = S.devices.filter((x) => x.active), n = act.length, c = { critical: 0, medium: 0, low: 0 };
    for (const x of act) c[x.band]++;
    const hist = histC().all().sort((a, b) => a.day.localeCompare(b.day)).slice(-30);
    const learn = {}; for (const k of ['critical', 'medium', 'low']) { const sl = lsq(hist.map((h, i) => [i, h[k]])); learn[k] = sl == null ? null : Math.round(sl * 7 * 10) / 10; }
    const F = [['internet', 'Internet-facing', true], ['eol', 'OS / platform past end of support', S.measured.eol], ['sensitive', 'Sensitive data access', S.measured.classification], ['vuln_critical', 'Critical vulnerability open', true], ['no_edr', 'No endpoint protection', S.measured.coverage], ['critical', 'Business-critical', true]];
    const factors = F.map(([k, label, m]) => { const hit = act.filter((x) => x.factors[k]).length; return { key: k, label, measured: !!m, devices: m ? hit : null, pct: m ? pct(hit, n) : null, level: !m ? null : pct(hit, n) >= 30 ? 'critical' : pct(hit, n) >= 10 ? 'medium' : 'low' }; });
    const profs = S.profiles.map((p) => { const ds = S.devices.filter((x) => x.profile === p.id); return { id: p.id, name: p.name, description: p.description || '', types: p.types || [], os: p.os || [], severity: p.severity, active: p.active !== false, catchall: !!p.catchall, builtin: !!p.builtin, devices: ds.length, average_score: ds.length ? Math.round(ds.reduce((a, x) => a + x.score, 0) / ds.length) : null }; });
    const res = { generated_at: iso(), sources: S.status, scored: n, inactive: S.devices.length - n, overall: n ? Math.round(act.reduce((a, x) => a + x.score, 0) / n) : null,
      bands: ['critical', 'medium', 'low'].map((k) => ({ key: k, devices: c[k], pct: pct(c[k], n) })),
      by_profile: profs.filter((p) => p.active && p.devices).map((p) => ({ key: p.name, devices: p.devices })), trend: hist.map((h) => ({ day: h.day, critical: h.critical, medium: h.medium, low: h.low })),
      learning: { days: hist.length, per_week: learn, note: hist.length < 3 ? 'trend withheld - ' + hist.length + ' day(s) recorded, 3 needed' : null },
      factors, profiles: profs, measured: S.measured, can_see_devices: ['operator', 'admin'].includes(who.role), can_edit: who.role === 'admin', weights: WEIGHT, types: TYPES, os_families: OSF };
    if (res.can_see_devices) res.fix_first = act.filter((x) => x.score > 0).sort((a, b) => b.priority - a.priority || b.score - a.score).slice(0, 50);
    return res;
  }
  function profileBody(input, partial) {
    const b = body(input).str('name', { required: !partial, max: 80 }).str('description', { max: 300 })
      .list('types', { max: TYPES.length, item: TYPES, unique: true })
      .list('os', { max: OSF.length, item: OSF, unique: true })
      .oneOf('severity', ['critical', 'high', 'medium', 'low'], { required: !partial }).bool('active').done();
    if (b.name != null && !b.name.trim()) throw httpErr(400, 'name is required');
    return b;
  }
  function createProfile(input, who) {
    const b = profileBody(input, false); person(who, 'change risk profiles');
    if (!(b.types || []).length && !(b.os || []).length) throw httpErr(400, 'types or os: a profile needs at least one type or OS family');
    if (profiles().length >= 40) throw httpErr(409, 'at most 40 profiles');
    const id = 'p-' + require('node:crypto').randomBytes(4).toString('hex');
    const p = { id, name: b.name.trim(), description: b.description || '', types: b.types || [], os: b.os || [], severity: b.severity, active: b.active !== false, order: 50, by: who.user, at: iso() };
    profC().put(p); audit(who, 'risk.profile.create', id, { name: p.name, types: p.types, os: p.os, severity: p.severity, active: p.active });
    return { profile: p };
  }
  function updateProfile(id, input, who) {
    const p = profiles().find((x) => x.id === id); if (!p) throw httpErr(404, 'no risk profile ' + id);
    const b = profileBody(input, true); person(who, 'change risk profiles');
    if (p.catchall && (b.types || b.os)) throw httpErr(400, 'types / os: the catch-all profile matches every remaining device');
    const next = Object.assign({}, p), changed = {};
    for (const k of ['name', 'description', 'types', 'os', 'severity', 'active']) if (b[k] !== undefined && JSON.stringify(b[k]) !== JSON.stringify(p[k])) { changed[k] = { from: p[k], to: b[k] }; next[k] = k === 'name' ? b[k].trim() : b[k]; }
    if (!next.catchall && !(next.types || []).length && !(next.os || []).length) throw httpErr(400, 'types or os: a profile needs at least one type or OS family');
    next.by = who.user; next.at = iso(); profC().put(next);
    audit(who, 'risk.profile.update', id, { name: next.name, changed });
    return { profile: next };
  }
  function deleteProfile(id, who) {
    const p = profiles().find((x) => x.id === id); if (!p) throw httpErr(404, 'no risk profile ' + id);
    if (p.catchall) throw httpErr(409, 'the catch-all profile cannot be deleted - it holds every device no other profile matches');
    person(who, 'change risk profiles');
    profC().remove(id); audit(who, 'risk.profile.delete', id, { name: p.name });
    return { ok: true };
  }
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'risk.snapshot', async () => { if (!histC().get(day(now()))) snapshotToday(await score()); }), 6 * 3600000); if (tm.unref) tm.unref(); }
  return { vulnView, item, exportCsv, saveSettings, riskView, createProfile, updateProfile, deleteProfile, score, inventory };
}

function registerVulnIntel(srv, app, V0) {
  const V = V0 && V0.vulnView ? V0 : createVulnIntel(app, V0 || {});
  app.addons = app.addons || {}; app.addons.vulnIntel = V;
  const PID = (ctx) => { const v = param(ctx.params.id, 'id'); if (!/^p-[a-z0-9]{2,20}$/.test(v)) throw httpErr(400, 'id is not a risk profile id'); return v; };
  const Q = (ctx, k, n, re) => { const v = ctx.query && ctx.query[k] != null ? String(ctx.query[k]).slice(0, n) : ''; if (v && re && !re.test(v)) throw httpErr(400, k + ' is not valid'); return v; };
  srv.route('GET', '/vuln-inventory', (ctx) => { ctx.need('viewer'); return V.vulnView(ctx.who, { q: Q(ctx, 'q', 120), sev: Q(ctx, 'sev', 10, /^(critical|high|medium|low|info)$/), adapter: Q(ctx, 'adapter', 20, /^(tenable|greenbone|pentest|firecompass)$/) }); });
  srv.route('GET', '/vuln-inventory/item', (ctx) => { ctx.need('operator'); return V.item(Q(ctx, 'key', 120)); });
  srv.route('GET', '/vuln-inventory/export', (ctx) => { ctx.need('operator'); return V.exportCsv(ctx.who); });
  srv.route('PUT', '/vuln-inventory/settings', (ctx) => { ctx.need('admin'); return V.saveSettings(ctx.body, ctx.who); });
  srv.route('GET', '/risk-prioritization', (ctx) => { ctx.need('viewer'); return V.riskView(ctx.who); });
  srv.route('POST', '/risk-prioritization/profiles', (ctx) => { ctx.need('admin'); return V.createProfile(ctx.body, ctx.who); });
  srv.route('PUT', '/risk-prioritization/profiles/:id', (ctx) => { ctx.need('admin'); return V.updateProfile(PID(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/risk-prioritization/profiles/:id/delete', (ctx) => { ctx.need('admin'); return V.deleteProfile(PID(ctx), ctx.who); });
  return V;
}

module.exports = { createVulnIntel, registerVulnIntel, osFamily, titleProduct };
