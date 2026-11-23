// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Platform Map ({P} = /api/itam, Home -> Platform Map): how the platform works for the organisation, drawn from what it actually
 * holds - the sources feeding it (each with its real state), the stages inside (collect, correlate, machine learning, AI
 * engineers, a person approves) and the outcomes it produces (each with a live figure where one is cheap to read).
 * A source is:
 *   connected       it delivered data (a sync that worked, records read)
 *   error           it is configured but its last read failed - the reason is shown
 *   not_connected   nothing is configured or nothing has arrived; the page says where to connect it
 * Read-only, from this engine's own store: no call to any external system, so the page is fast and never stalls on a source.
 * Machine learning on top (explained, no AI model):
 *   readiness      0-100: each source carries a weight (how much of the platform's output depends on it); connected counts in full,
 *                  needs-attention half, not connected zero - every point itemised
 *   outcomes       each outcome names the sources it depends on; its confidence is the weighted share of those that deliver, and
 *                  the missing ones are listed - an outcome built on missing sources says so instead of looking complete
 *   next actions   which source to connect or fix first: the readiness it adds plus the outcomes it unlocks, ranked
 *   history        one snapshot a day (platform_map_hist, 90 days, taken by the 'platformMap.snapshot' job): per-source 30-day
 *                  strip and days delivering, sources that regressed in 7 days, flapping (3+ changes in 14 days), readiness trend
 *                  (least-squares slope over 14 days) and, when it improves, the projected day it reaches 80 - withheld below 5 days
 *   GET /platform-map    viewer
 */
const { guardOf } = require('./errors');
const ALIVE_DAYS = 7, DAY = 86400000;
// how much of the platform's output each source carries (sums to 100)
const WEIGHT = { vuln: 14, siem: 14, edr: 12, network: 9, identity: 9, discovery: 8, endpoint: 8, backup: 7, virt: 5, storage: 3, db: 3, certs: 3, itsm: 3, email: 2 };
// which sources each outcome is built from
const DEPS = { assets: ['discovery', 'virt', 'identity', 'endpoint', 'network', 'storage'], coverage: ['edr', 'endpoint', 'backup', 'vuln', 'siem', 'discovery'],
  vulns: ['vuln'], risk: ['vuln', 'discovery', 'edr', 'backup'], compliance: ['vuln', 'siem', 'edr', 'identity', 'backup', 'endpoint', 'certs', 'itsm'],
  soc: ['siem', 'edr', 'identity', 'email', 'network'], verify: ['vuln', 'endpoint', 'edr'] };
const STATE_PTS = { connected: 1, error: 0.5, not_connected: 0 };
const dayOf = (t) => new Date(t).toISOString().slice(0, 10);

function createPlatformMap(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const col = (n) => { try { return store.collection(n); } catch (e) { return null; /* a module that is not installed has no collection */ } };
  const all = (n) => { const c = col(n); return c ? c.all() : []; };
  const get = (n, id) => { const c = col(n); return c ? c.get(id) : null; };
  const iso = (t) => (t == null ? null : new Date(typeof t === 'number' ? t : Date.parse(t)).toISOString());
  const newest = (list) => list.filter(Boolean).map((x) => (typeof x === 'number' ? x : Date.parse(x))).filter(Number.isFinite).sort((a, b) => b - a)[0] || null;
  const fresh = (t) => t != null && now() - t <= ALIVE_DAYS * DAY;

  // platforms that keep last_sync {at, ok, error} on each record (virtualization, storage, backup)
  function platforms(name, what) {
    const rows = all(name); if (!rows.length) return { state: 'not_connected', detail: 'no ' + what + ' connected' };
    const bad = rows.filter((p) => p.last_sync && p.last_sync.ok === false), ok = rows.filter((p) => p.last_sync && p.last_sync.ok !== false), last = newest(ok.map((p) => p.last_sync.at));
    if (!ok.length && bad.length) return { state: 'error', detail: bad.length + ' of ' + rows.length + ' cannot be read: ' + String(bad[0].last_sync.error || 'error').slice(0, 160), count: rows.length };
    if (!ok.length) return { state: 'not_connected', detail: rows.length + ' configured, not read yet', count: rows.length };
    return { state: bad.length ? 'error' : 'connected', detail: ok.length + ' of ' + rows.length + ' read' + (bad.length ? ', ' + bad.length + ' failing' : ''), count: rows.length, last: iso(last) };
  }
  const counted = (n, what, at) => { const rows = all(n); const last = at ? newest(rows.map(at)) : null;
    return rows.length ? { state: last == null || fresh(last) ? 'connected' : 'error', detail: rows.length + ' ' + what + (last != null && !fresh(last) ? ' - nothing new for more than ' + ALIVE_DAYS + ' days' : ''), count: rows.length, last: iso(last) } : { state: 'not_connected', detail: 'no ' + what + ' yet' }; };

  const SOURCES = [
    { id: 'vuln', label: 'Vulnerability scanners', vendors: 'Greenbone · Tenable / Nessus · FireCompass', icon: 'bug', page: 'vapt-studio.html', read: () => {
      const gb = all('vulnscan_results'), tn = get('fc_config', 'tenable'), fc = all('fc_imports');
      const tools = [gb.length ? 'Greenbone' : null, tn && tn.last_pull ? 'Tenable' : null, fc.some((x) => (x.vendor || 'firecompass') === 'firecompass') ? 'FireCompass' : null].filter(Boolean);
      const last = newest(gb.map((r) => r.at).concat([tn && tn.last_pull], fc.map((x) => x.at)));
      if (tn && tn.last_error && !tools.length) return { state: 'error', detail: 'Tenable: ' + String(tn.last_error).slice(0, 160) };
      return tools.length ? { state: 'connected', detail: tools.join(', ') + ' read', last: iso(last) } : { state: 'not_connected', detail: 'no scan read yet' }; } },
    { id: 'network', label: 'Firewalls & network', vendors: 'Palo Alto · FortiGate · Cisco · Silver Peak · Genian NAC', icon: 'network', page: 'network-dashboard.html', read: () => {
      const n = all('disc_devices').filter((d) => d.type === 'network' || d.type === 'firewall'); const last = newest(n.map((d) => d.last_seen));
      return n.length ? { state: fresh(last) ? 'connected' : 'error', detail: n.length + ' network devices seen' + (fresh(last) ? '' : ' - none recently'), count: n.length, last: iso(last) } : { state: 'not_connected', detail: 'no network device discovered yet' }; } },
    { id: 'edr', label: 'Endpoint protection', vendors: 'Kaspersky · Defender · CrowdStrike · others', icon: 'shield-check', page: 'asset-coverage.html', read: () => {
      let EDR = []; try { EDR = require('./asset-coverage').EDR; } catch (e) { EDR = []; /* Coverage & Query not installed */ }
      const withSw = all('assets').filter((a) => (a.software || []).length), hit = withSw.filter((a) => (a.software || []).some((s) => EDR.some((p) => p[1].test(String((s && (s.name || s)) || '')))));
      return withSw.length ? { state: 'connected', detail: hit.length + ' of ' + withSw.length + ' inventoried assets show endpoint protection', count: hit.length } : { state: 'not_connected', detail: 'no installed-software inventory yet (agent or import)' }; } },
    { id: 'siem', label: 'SIEM & log sources', vendors: 'syslog · Windows / Linux agents · Exchange · M365', icon: 'radar-2', page: 'soc-overview.html', read: () => {
      const siem = app.discovery && app.discovery.siem, cfg = !!(siem && (typeof siem.configured !== 'function' || siem.configured()));
      const n = all('assets').filter((a) => a.siem && a.siem.source_id).length;
      return !cfg ? { state: 'not_connected', detail: 'SIEM link not configured' } : { state: 'connected', detail: n + ' assets enrolled as SIEM log sources', count: n }; } },
    { id: 'itsm', label: 'Service desk (ITSM)', vendors: 'ManageEngine ServiceDesk Plus', icon: 'ticket', page: 'tickets.html', read: () => counted('me_tickets', 'tickets read', (t) => t.updated_at || t.created_at) },
    { id: 'endpoint', label: 'Endpoint & patch', vendors: 'Endpoint Central · Intune', icon: 'device-desktop', page: 'desktops.html', read: () => counted('me_ec_computers', 'computers with an agent', (c) => c.seen_at) },
    { id: 'identity', label: 'Identity', vendors: 'Active Directory · Entra ID', icon: 'users', page: 'identity-signin.html', read: () => {
      const l = get('ad_directory', 'last'); return l ? { state: 'connected', detail: (l.users || []).length + ' directory users read', count: (l.users || []).length, last: iso(l.at) } : { state: 'not_connected', detail: 'directory not read yet' }; } },
    { id: 'email', label: 'Email security', vendors: 'Libraesva ESG · Exchange', icon: 'mail', page: 'libraesva.html', read: () => {
      const st = get('esg', 'state'), cfg = all('esg').find((x) => x.id !== 'state'); if (!cfg && !st) return { state: 'not_connected', detail: 'email gateway not connected' };
      const d = st && st.last_diagnose; return d ? { state: d.ok ? 'connected' : 'error', detail: d.ok ? 'gateway answers' : 'last check failed', last: iso(d.at) } : { state: 'connected', detail: 'gateway configured' }; } },
    { id: 'backup', label: 'Backup', vendors: 'NetBackup · Veeam · Cohesity', icon: 'database-export', page: 'backup.html', read: () => platforms('backup_platforms', 'backup platform') },
    { id: 'virt', label: 'Virtualization', vendors: 'VMware vCenter · Nutanix · Hyper-V', icon: 'server-2', page: 'virtualization.html', read: () => platforms('virt_platforms', 'virtualization platform') },
    { id: 'storage', label: 'Storage', vendors: 'NetApp · HPE MSA · Synology', icon: 'database', page: 'storage.html', read: () => platforms('storage_platforms', 'storage array') },
    { id: 'db', label: 'Databases', vendors: 'Oracle · SQL Server · PostgreSQL · MySQL', icon: 'table', page: 'databases.html', read: () => counted('db_health_targets', 'databases monitored', null) },
    { id: 'certs', label: 'Certificates', vendors: 'TLS endpoints · internal CA · ACME', icon: 'certificate', page: 'certificates.html', read: () => counted('cert_endpoints', 'certificate endpoints', (c) => c.last_scan || c.updated_at) },
    { id: 'discovery', label: 'Network discovery', vendors: 'scans · ARP · LLDP / CDP · agents', icon: 'radar', page: 'discovery-studio.html', read: () => counted('disc_devices', 'devices discovered', (d) => d.last_seen) },
  ];

  const hist = () => col('platform_map_hist');
  function readSources() {
    return SOURCES.map((s) => { let r; try { r = s.read(); } catch (e) { r = { state: 'error', detail: 'could not be read here (' + String(e.message).slice(0, 120) + ')' }; }
      return Object.assign({ id: s.id, label: s.label, vendors: s.vendors, icon: s.icon, page: s.page }, r); });
  }
  const readinessOf = (states) => Math.round(Object.keys(WEIGHT).reduce((a, k) => a + WEIGHT[k] * (STATE_PTS[states[k]] || 0), 0));
  // one snapshot a day (the latest reading of the day wins); 90 days kept
  function snapshot() {
    const h = hist(); if (!h) return null;
    const src = readSources(), states = {}; src.forEach((x) => { states[x.id] = x.state; });
    const day = dayOf(now()), rec = { id: day, day, at: new Date(now()).toISOString(), states, readiness: readinessOf(states) };
    h.put(rec);
    const cut = dayOf(now() - 90 * DAY); for (const r of h.all()) if (r.day < cut) h.remove(r.id);
    return rec;
  }
  function slope(pts) {   // least squares over [x, y]
    const n = pts.length; if (n < 2) return 0; const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n;
    const den = pts.reduce((a, p) => a + (p[0] - mx) * (p[0] - mx), 0); return den ? pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0) / den : 0;
  }
  function view() {
    const sources = readSources();
    const assets = all('assets').filter((a) => !['retired', 'disposed'].includes(a.status));
    const rels = all('relationships').filter((r) => r.status !== 'rejected').length;
    const openV = all('vulnscan_findings').filter((f) => f.status !== 'fixed').length + all('fc_findings').filter((f) => f.seen_in_latest !== false && (!f.decision || f.decision.state !== 'approved')).length;
    let ai = { mode: 'anthropic' }; try { ai = require('./ai-backend').status(); } catch (e) { ai = { mode: 'unknown' }; /* AI Engine not installed */ }
    const outcomes = [
      { id: 'assets', label: 'Asset intelligence', page: 'cmdb-studio.html', icon: 'topology-star-3', value: assets.length, unit: 'assets', how: 'one record per asset, merged from every source; relationships and what fails with what', ml: 'PageRank importance, duplicates, learned relationships' },
      { id: 'coverage', label: 'Security coverage gaps', page: 'asset-coverage.html', icon: 'shield-check', value: null, how: 'EDR, patch, backup, scan, logs and monitoring per asset, with the source that said so', ml: 'gaps ranked by business criticality' },
      { id: 'vulns', label: 'Unified vulnerabilities', page: 'vapt-studio.html', icon: 'bug', value: openV, unit: 'open findings', how: 'Greenbone, Tenable and FireCompass in one list; the same weakness from two tools merged', ml: 'explained 0-100 risk, weakness families' },
      { id: 'risk', label: 'Risk prioritization', page: 'risk-studio.html', icon: 'chart-dots-3', value: null, how: 'risks rated on likelihood and impact from live findings', ml: 'trend, forecast and what moved the score' },
      { id: 'compliance', label: 'Compliance automation', page: 'compliance-overview.html', icon: 'certificate', value: null, how: 'NCA ECC, SAMA CSF, PDPL, NDMO, ISO 27001 verified from platform evidence', ml: 'gaps to remediation actions, forecast to target' },
      { id: 'soc', label: 'Detection & response', page: 'soc-overview.html', icon: 'radar-2', value: null, how: 'detections, alerts, cases, UEBA and XDR correlation in the SIEM', ml: 'alert scoring, behaviour baselines, rare / first-seen' },
      { id: 'verify', label: 'Remediation verification', page: 'ai-team.html', icon: 'circle-check', value: null, how: 'AI engineers re-check every fix; a problem that returns is reopened', ml: 'proposals approved by a named person' },
    ];
    // ---- ML: readiness, dependencies, history, next actions, findings
    const states = {}; sources.forEach((x) => { states[x.id] = x.state; });
    const byId = {}; sources.forEach((x) => { byId[x.id] = x; });
    const H = (hist() ? hist().all() : []).sort((a, b) => a.day.localeCompare(b.day));
    const today = dayOf(now()), past = H.filter((r) => r.day < today), days30 = []; for (let i = 29; i >= 0; i--) days30.push(dayOf(now() - i * DAY));
    const hmap = {}; H.forEach((r) => { hmap[r.day] = r; }); hmap[today] = { day: today, states, readiness: readinessOf(states) };
    sources.forEach((x) => {
      x.weight = WEIGHT[x.id] || 0; x.feeds = Object.keys(DEPS).filter((o) => DEPS[o].includes(x.id));
      x.history = days30.map((d) => ({ day: d, state: hmap[d] ? hmap[d].states[x.id] || null : null }));
      const seen = x.history.filter((h) => h.state); x.days_recorded = seen.length; x.days_delivering = seen.filter((h) => h.state === 'connected').length;
      x.age_h = x.last ? Math.round((now() - Date.parse(x.last)) / 360000) / 10 : null;
    });
    const items = sources.map((x) => ({ id: x.id, label: x.label, weight: x.weight, state: x.state, points: Math.round(x.weight * STATE_PTS[x.state] * 10) / 10,
      why: x.state === 'connected' ? 'delivering (+' + x.weight + ')' : x.state === 'error' ? 'configured but failing (+' + (x.weight / 2) + ' of ' + x.weight + ')' : 'not connected (0 of ' + x.weight + ')' }));
    const score = readinessOf(states);
    outcomes.forEach((o) => { const d = DEPS[o.id] || [], w = d.reduce((a, k) => a + (WEIGHT[k] || 0), 0);
      o.depends = d; o.confidence = w ? Math.round(100 * d.reduce((a, k) => a + (WEIGHT[k] || 0) * (STATE_PTS[states[k]] || 0), 0) / w) : null;
      o.missing = d.filter((k) => states[k] !== 'connected').map((k) => ({ id: k, label: byId[k] ? byId[k].label : k, state: states[k] })); });
    const next = sources.filter((x) => x.state !== 'connected').map((x) => { const gain = x.weight * (1 - STATE_PTS[x.state]);
      const lift = outcomes.filter((o) => o.depends.includes(x.id)).map((o) => o.label);
      return { id: x.id, label: x.label, page: x.page, state: x.state, action: x.state === 'error' ? 'fix' : 'connect', gain: Math.round(gain * 10) / 10, outcomes: lift, rank: gain + lift.length * 1.5, why: x.detail };
    }).sort((a, b) => b.rank - a.rank);
    const trendPts = days30.filter((d) => hmap[d]).map((d) => ({ day: d, readiness: hmap[d].readiness }));
    const insights = [];
    const recent = trendPts.slice(-14), sl = recent.length >= 5 ? slope(recent.map((p, i) => [i, p.readiness])) : null;
    if (sl != null && Math.abs(sl) >= 0.3) insights.push({ kind: sl > 0 ? 'good' : 'bad', text: 'Readiness is ' + (sl > 0 ? 'improving' : 'declining') + ' by about ' + Math.abs(Math.round(sl * 10) / 10) + ' points a day over the last ' + recent.length + ' days' + (sl > 0 && score < 80 ? ' - at this pace it reaches 80 around ' + dayOf(now() + Math.ceil((80 - score) / sl) * DAY) : '') });
    else if (sl == null) insights.push({ kind: 'info', text: 'Trend withheld: ' + trendPts.length + ' day(s) recorded, 5 needed' });
    const wk = hmap[dayOf(now() - 7 * DAY)] || past.filter((r) => r.day >= dayOf(now() - 7 * DAY))[0];
    if (wk) sources.forEach((x) => { const was = wk.states[x.id]; if (was && STATE_PTS[was] > STATE_PTS[x.state]) insights.push({ kind: 'bad', source: x.id, text: x.label + ' regressed since ' + wk.day + ': ' + was.replace('_', ' ') + ' → ' + x.state.replace('_', ' ') + ' (' + x.detail + ')' });
      else if (was && STATE_PTS[was] < STATE_PTS[x.state]) insights.push({ kind: 'good', source: x.id, text: x.label + ' now ' + x.state.replace('_', ' ') + ' (was ' + was.replace('_', ' ') + ' on ' + wk.day + ')' }); });
    sources.forEach((x) => { const h = x.history.slice(-14).map((v) => v.state).filter(Boolean); let ch = 0; for (let i = 1; i < h.length; i++) if (h[i] !== h[i - 1]) ch++;
      if (ch >= 3) insights.push({ kind: 'bad', source: x.id, text: x.label + ' is unstable: its state changed ' + ch + ' times in 14 days - check the account, network path or schedule' });
      if (x.state === 'connected' && x.age_h != null && x.age_h > 72) insights.push({ kind: 'warn', source: x.id, text: x.label + ': newest data is ' + Math.round(x.age_h / 24) + ' days old - it is connected but may have stopped sending' }); });
    outcomes.filter((o) => o.confidence != null && o.confidence < 50).forEach((o) => insights.push({ kind: 'warn', outcome: o.id, text: o.label + ' runs on ' + o.confidence + '% of its sources - missing: ' + o.missing.map((m) => m.label).join(', ') }));
    return { generated_at: new Date(now()).toISOString(), relationships: rels, sources, outcomes,
      readiness: { score, items, next, trend: trendPts, insights, method: 'each source weighted by how much output depends on it; connected = full weight, needs attention = half, not connected = 0' }, ai: { mode: ai.mode, data_leaves_network: !!ai.data_leaves_network, model: ai.local ? ai.local.model : '' },
      summary: { sources: sources.length, connected: sources.filter((s) => s.state === 'connected').length, error: sources.filter((s) => s.state === 'error').length, not_connected: sources.filter((s) => s.state === 'not_connected').length },
      stages: [
        { id: 'collect', label: 'Collect', text: 'read-only accounts; credentials sealed; nothing changed on a source' },
        { id: 'correlate', label: 'Correlate', text: 'one record per asset (CMDB), each fact with the source that said it' },
        { id: 'ml', label: 'Machine learning', text: 'scores, anomalies, trends and forecasts on this server - explained, no AI model' },
        { id: 'ai', label: 'AI engineers', text: 'investigate and propose; tools filtered by role; input treated as untrusted' },
        { id: 'approve', label: 'A person approves', text: 'every change is four-eyes by a named person; every step audited' },
      ] };
  }
  const runSnap = guardOf(app, 'platformMap.snapshot', () => snapshot());
  if (!(app.noTimers || opts.noTimer)) {
    let timer = null; const loop = async () => { try { await runSnap(); } finally { timer = setTimeout(loop, 3600000); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, 30000); if (timer.unref) timer.unref();
  }
  return { view, snapshot };
}

function registerPlatformMap(srv, app, M0) {
  const M = M0 && M0.view ? M0 : createPlatformMap(app, M0 && !M0.view ? M0 : {});
  app.addons = app.addons || {}; app.addons.platformMap = M;
  srv.route('GET', '/platform-map', (ctx) => { ctx.need('viewer'); return M.view(); });
  return M;
}
module.exports = { createPlatformMap, registerPlatformMap };
