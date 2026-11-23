// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { classify } = require('./hardening');
const LC = require('./lifecycle');
/*
 * Unified Patch Management ({P} = /api/itam; IT Operations -> Patch Management). One answer to "is every IT asset patched?" -
 * servers, desktops and laptops, switches and routers, firewalls and databases - joined from what the platform already reads.
 * Nothing is installed, scheduled or changed from here: each class links to the page where its patching is done under its own
 * approval (Update Studio, Desktop Patch Management, Cisco Update Manager, Databases).
 *   sources    Update Studio (servers: Endpoint Central, the agent, the hypervisor reads, the UPD-01..07 rules), Endpoint Central
 *              (desktops: missing / critical-missing patches, last contact), Cisco Update Manager (IOS / IOS-XE / NX-OS / ASA:
 *              target release, PSIRT advisories and their deadlines), the database inventory (engine + version read with a
 *              read-only login), the vulnerability scanner (open findings whose fix is a vendor patch, aged against the SLA),
 *              end of life (lifecycle.js rules on OS / firmware text), and the administrator's baseline release per platform
 *              (FortiGate, Palo Alto, Aruba, Oracle, SQL Server ...) for what has no vendor feed here.
 *   status     per asset the WORST of what its sources say: end of life > overdue (a deadline passed) > behind > current.
 *              An asset no source measures is "not measured" with what to connect - never current. An approved exception
 *              (reason, compensating control, end date <= 180 days, a different named person approves) shows the asset as
 *              excepted until the date; it then counts again - nothing renews silently.
 *   priority   every point named: criticality, production, each source's finding.
 *   GET  /patching                               viewer    summary, classes, assets, policy, exceptions
 *   POST /patching/policy                        admin     {sla{critical, high, medium, low}, fresh_days, baselines[{class, platform, target, minimum?, note?}]}
 *   POST /patching/exceptions                    operator  {key, reason, compensating, until}
 *   POST /patching/exceptions/:id/decide         admin     {decision: approved|rejected, comment} - never the requester
 *   POST /patching/exceptions/:id/revoke         admin     {reason}
 * Every state change is audited (patching.*) with who, role, IP and what changed.
 */
const DAY = 86400000;
const CLASSES = ['server', 'desktop', 'network', 'firewall', 'database'];
const CLABEL = { server: 'Servers', desktop: 'Desktops & laptops', network: 'Switches & routers', firewall: 'Firewalls', database: 'Databases' };
const PAGE = { server: 'update-studio.html', desktop: 'desktop-patches.html', network: 'cisco-update.html', firewall: 'lifecycle.html', database: 'databases.html' };
const CONNECT = {
  server: 'connect Endpoint Central or install the IT Asset Management agent, or connect its hypervisor (Update Studio)',
  desktop: 'connect ManageEngine Endpoint Central (IT Operations -> ManageEngine) so its patch state is read',
  network: 'Cisco: give the AI Network Engineer an SSH login and set a target release (Cisco Update Manager); other vendors: record the firmware on the asset and set a baseline release below',
  firewall: 'record the firmware on the asset (or let discovery read it) and set a baseline release for its platform below',
  database: 'add a read-only database login in Asset Discovery -> Credentials so the version is read (Databases), and set a baseline release for its engine below',
};
const SEV = ['critical', 'high', 'medium', 'low'];
const DEF_SLA = { critical: 15, high: 30, medium: 90, low: 180 };
const RANKS = { eol: 4, overdue: 3, behind: 2, current: 1 };
const VER_RE = /^[0-9][0-9A-Za-z.()_-]{0,39}$/, PLAT_RE = /^[a-z0-9][a-z0-9 ._-]{0,39}$/;
const CLOSED = { disposed: 1, retired: 1, lost: 1, stolen: 1, archived: 1 };
const SERVICE = /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i;
const lc = (s) => String(s == null ? '' : s).toLowerCase().trim();
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const critW = (c) => ({ critical: 30, high: 20, medium: 10, low: 5 }[lc(c)] || 0);
const isProd = (a) => { const e = lc(a.environment || a.env || a.tier); if (e) return /prod|live/.test(e) && !/non.?prod|pre.?prod/.test(e); return !/(^|[-_.])(dev|test|tst|uat|qa|stg|stage|dr|lab|sandbox)([-_.\d]|$)/.test(lc(a.name || a.hostname)); };
// numeric release compare (9.4.2 < 9.10.1; 15.0.4385.2 > 15.0.4375); non-numeric parts compared as text
function cmpVer(a, b) {
  const pa = String(a).split(/[^0-9A-Za-z]+/).filter(Boolean), pb = String(b).split(/[^0-9A-Za-z]+/).filter(Boolean);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || '0', y = pb[i] || '0', nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    const c = nx && ny ? Number(x) - Number(y) : x.localeCompare(y, undefined, { numeric: true });
    if (c) return c < 0 ? -1 : 1;
  }
  return 0;
}
const verOf = (t) => (/\bv?(\d+\.\d+(?:\.\d+){0,3})/i.exec(String(t || '')) || [])[1] || '';

function classOf(a) {
  const t = lc(a.type);
  if (['firewall', 'utm'].includes(t)) return 'firewall';
  if (['switch', 'router', 'network', 'wireless_controller', 'core switch'].includes(t)) return 'network';
  if (['desktop', 'laptop', 'workstation', 'pc', 'thin_client'].includes(t)) return 'desktop';
  const c = classify(a); if (!c) return null;
  if (c.kind === 'firewall') return 'firewall';
  if (c.kind === 'ios') return 'network';
  if (c.platform === 'windows_client') return 'desktop';
  return 'server';
}
function platformOf(a, cls) {
  const c = classify(a);
  if (cls === 'firewall') return c && c.platform && c.platform !== 'network' ? c.platform : (lc(a.vendor).split(/\s+/)[0] || 'unknown');
  if (cls === 'network') return /cisco/.test(lc(a.vendor) + ' ' + lc(a.os)) ? 'cisco' : (lc(a.vendor).split(/\s+/)[0] || 'unknown');
  return (c && c.platform) || 'unknown';
}

function createPatchHub(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, iso = () => new Date(now()).toISOString();
  const L = app.log || { info() {}, warn() {} };
  const C = { cfg: () => store.collection('patch_cfg'), exc: () => store.collection('patch_exceptions') };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const A = () => app.addons || {};
  function policy() { const v = ((C.cfg().get('policy') || {}).value) || {}; return { sla: Object.assign({}, DEF_SLA, v.sla || {}), fresh_days: v.fresh_days || 7, baselines: v.baselines || [] }; }

  // ---------- each source, read once per view; a missing or failing one is named, never filled in
  function sources() {
    const out = { notes: {}, us: new Map(), ec: [], cisco: new Map(), db: [], vuln: new Map() };
    const read = (k, fn) => { try { fn(); } catch (e) { out.notes[k] = 'read failed: ' + String(e.message).slice(0, 160); L.warn('patching: ' + k + ' read failed', { err: e.message }); } };
    read('update_studio', () => { const U = A().updateStudio; if (!U) { out.notes.update_studio = 'Update Studio is not installed'; return; } for (const s of U.model().servers || []) out.us.set(s.id, s); });
    read('endpoint_central', () => { const m = A().manageengine; if (!m) { out.notes.endpoint_central = 'the Endpoint Central integration is not installed'; return; } out.ec = m.computers().computers || []; });
    read('cisco', () => { const cu = A().ciscoUpdate; if (!cu) { out.notes.cisco = 'Cisco Update Manager is not installed'; return; } for (const d of cu.view().devices || []) out.cisco.set(lc(d.name), d); });
    read('databases', () => { out.db = store.collection('db_inventory').all((r) => !r.error || (r.server && r.server.version)); });
    read('scanner', () => {
      const t = now(), P = policy();
      for (const f of store.collection('vulnscan_findings').all((x) => x.status === 'open' && SEV.includes(x.severity))) {
        if (f.risk && f.risk.state === 'approved' && Date.parse(f.risk.until) > t) continue;   // risk accepted on the scanner page
        if (f.solution_type && !/vendorfix/i.test(f.solution_type)) continue;                   // only what a vendor patch fixes
        const age = f.first_seen ? Math.floor((t - Date.parse(f.first_seen)) / DAY) : null, sla = P.sla[f.severity];
        const h = out.vuln.get(f.host) || out.vuln.set(f.host, { critical: 0, high: 0, medium: 0, low: 0, overdue: 0, oldest: 0, worst_overdue: null }).get(f.host);
        h[f.severity]++; if (age != null && age > sla) { h.overdue++; if (!h.worst_overdue || SEV.indexOf(f.severity) < SEV.indexOf(h.worst_overdue)) h.worst_overdue = f.severity; } if (age != null) h.oldest = Math.max(h.oldest, age);
      }
    });
    return out;
  }
  function findEc(list, a) {
    const names = [lc(a.hostname), lc(a.name)].filter(Boolean), short = names.map((n) => n.split('.')[0]), ip = a.mgmt_ip || a.ip;
    return list.find((c) => c.asset_id === a.id) || list.find((c) => names.includes(lc(c.name)) || short.includes(lc(c.name).split('.')[0])) || (ip ? list.find((c) => c.ip === ip) : null) || null;
  }

  // ---------- the model
  function model() {
    const S = sources(), P = policy(), t = now(), rules = LC.compile(((app.config && app.config.discovery) || {}).lifecycle && app.config.discovery.lifecycle.rules);
    const exc = C.exc().all(), excBy = new Map();
    for (const x of exc) if (x.state === 'approved' && Date.parse(x.until) > t) excBy.set(x.key, x);
    const base = (cls, plat) => P.baselines.find((b) => b.class === cls && b.platform === lc(plat)) || null;
    const items = [];
    function evaluate(it, a, text) {
      const sig = [], add = (state, source, txt, points) => sig.push({ state, source, text: txt, points: points || 0 });
      // end of life
      const e = LC.evaluate(text, rules, t);
      if (e.status === 'eol') add('eol', 'end of life', (e.product || 'this release') + ' is past vendor end of support' + (e.eol ? ' (' + e.eol + ')' : '') + ' - no more security patches', 30);
      else if (e.status === 'soon') add('current', 'end of life', (e.product || 'this release') + ' reaches end of support on ' + e.eol + ' (' + e.days + ' days) - plan the upgrade', 5);
      // baseline release (platforms without a vendor feed here, or Cisco with no target set on the Cisco page)
      const b = base(it.class, it.platform);
      if (b && !it.cisco_measured) {
        if (!it.version) add(null, 'baseline', 'baseline ' + b.target + ' is set for ' + it.platform + ' but the running version is not recorded', 0);
        else if (b.minimum && cmpVer(it.version, b.minimum) < 0) add('behind', 'baseline', it.version + ' is below the minimum ' + b.minimum + ' for ' + it.platform + ' - must be upgraded', 20);
        else if (cmpVer(it.version, b.target) < 0) add('behind', 'baseline', it.version + ' is behind the baseline ' + b.target + ' for ' + it.platform, 8);
        else add('current', 'baseline', it.version + ' meets the baseline ' + b.target, 0);
      }
      // scanner: open findings whose fix is a vendor patch
      const v = it.ip ? S.vuln.get(it.ip) : null;
      if (v) {
        const n = v.critical + v.high + v.medium + v.low;
        if (v.overdue) add('overdue', 'vulnerability scanner', v.overdue + ' finding(s) past the ' + v.worst_overdue + ' SLA (' + P.sla[v.worst_overdue] + ' days) - ' + n + ' open with a vendor fix, oldest ' + v.oldest + ' days', Math.min(40, 20 + 5 * v.overdue) + (v.worst_overdue === 'critical' ? 10 : 0));
        else add('behind', 'vulnerability scanner', n + ' open finding(s) with a vendor fix (' + SEV.filter((s) => v[s]).map((s) => v[s] + ' ' + s).join(', ') + '), within SLA', Math.min(20, 8 * v.critical + 4 * v.high + v.medium));
      }
      it.signals = sig.concat(it.signals || []);
      const all = it.signals.filter((x) => x.state);
      it.status = all.length ? all.reduce((w, x) => (RANKS[x.state] > RANKS[w] ? x.state : w), 'current') : 'not_measured';
      if (!all.length) it.reason = CONNECT[it.class];
      const pts = [];
      if (critW(it.criticality)) pts.push({ points: critW(it.criticality), text: 'criticality ' + it.criticality });
      if (it.prod) pts.push({ points: 10, text: 'production' });
      for (const x of it.signals) if (x.points && x.state && x.state !== 'current') pts.push({ points: x.points, text: x.source + ': ' + x.text });
      if (it.status === 'not_measured') pts.push({ points: 10, text: 'patch state unknown' });
      const ex = excBy.get(it.key);
      it.exception = ex ? { id: ex.id, until: ex.until, reason: ex.reason, compensating: ex.compensating, approved_by: ex.decided_by } : null;
      it.priority = ex ? 0 : Math.min(100, pts.reduce((n, p) => n + p.points, 0));
      it.points = pts; it.page = PAGE[it.class];
      items.push(it);
    }
    // assets in the register
    for (const a of store.collection('assets').all((x) => !CLOSED[lc(x.status)]).slice(0, 20000)) {
      const cls = classOf(a); if (!cls) continue;
      const it = { key: 'asset:' + a.id, asset_id: a.id, name: a.name || a.hostname || a.asset_tag || a.id, class: cls, platform: platformOf(a, cls), ip: a.mgmt_ip || a.ip || '', site: a.site || a.location || '',
        criticality: a.criticality || '', prod: isProd(a), version: a.firmware || a.os_version || verOf(a.os) || '', signals: [] };
      const add = (state, source, txt, points) => it.signals.push({ state, source, text: txt, points: points || 0 });
      if (cls === 'server' && S.us.has(a.id)) {
        const s = S.us.get(a.id); if (s.version) it.version = s.version;
        const crit = s.checks.find((c) => c.rule === 'UPD-01' && c.state === 'fail');
        if (crit) add('behind', 'Update Studio', crit.detail, Math.min(40, 10 * ((s.ec && s.ec.critical) || 1)));
        for (const c of s.checks.filter((x) => x.state === 'fail' && x.rule !== 'UPD-01' && x.rule !== 'UPD-02')) add('behind', 'Update Studio', c.rule + ': ' + c.detail, c.rule === 'UPD-04' ? 10 : 5);
        const fresh = s.checks.find((c) => c.rule === 'UPD-02');
        if (s.compliant === true) add('current', 'Update Studio', 'every measured update rule passes', 0);
        else if (fresh && fresh.state === 'fail') add(null, 'Update Studio', fresh.detail, 10);
      } else if (cls === 'desktop' || (cls === 'server' && !A().updateStudio)) {
        const c = findEc(S.ec, a);
        if (c) {
          const stale = !c.last_contact || t - c.last_contact > P.fresh_days * DAY;
          if (stale) add(null, 'Endpoint Central', c.last_contact ? 'last agent contact ' + Math.floor((t - c.last_contact) / DAY) + ' days ago - patch state is stale' : 'the agent has not reported', 0);
          else if (c.critical > 0) add('behind', 'Endpoint Central', c.critical + ' critical patch(es) missing' + (c.missing > c.critical ? ', ' + c.missing + ' in all' : ''), Math.min(40, 10 * c.critical));
          else if (c.missing > 0) add('behind', 'Endpoint Central', c.missing + ' patch(es) missing, none critical', Math.min(10, c.missing));
          else if (c.missing === 0) add('current', 'Endpoint Central', 'no missing patch', 0);
        }
      }
      if (cls === 'network' || cls === 'firewall') {
        const d = S.cisco.get(lc(a.name)) || S.cisco.get(lc(a.hostname));
        if (d) {
          it.platform = 'cisco ' + d.ostype; if (d.version) it.version = d.version;
          if (d.status === 'on-target' || d.status === 'behind' || d.status === 'below-minimum') it.cisco_measured = true;
          if (d.overdue) add('overdue', 'Cisco Update Manager', d.overdue + ' PSIRT advisory deadline(s) passed on ' + d.version + (d.target ? ' - target ' + d.target : ''), 20 + ({ Critical: 20, High: 10 }[d.worst] || 0));
          else if (d.status === 'below-minimum' || d.status === 'behind') add('behind', 'Cisco Update Manager', d.why + (d.advisories.length ? ' · ' + d.advisories.length + ' advisory(ies), worst ' + d.worst : ''), d.status === 'below-minimum' ? 20 : 8 + ({ Critical: 20, High: 10, Medium: 4 }[d.worst] || 0));
          else if (d.status === 'on-target') add(d.advisories.length ? 'behind' : 'current', 'Cisco Update Manager', d.advisories.length ? 'on target but ' + d.advisories.length + ' advisory(ies) on ' + d.version + ' - check the target fixes them' : d.why, d.advisories.length ? 5 : 0);
          else add(null, 'Cisco Update Manager', d.why, 0);
          if (d.plan) it.plan = { id: d.plan.id, status: d.plan.status, name: d.plan.name };
        }
      }
      evaluate(it, a, [a.os, a.os_version, a.firmware, a.sys_descr, a.vendor, a.model].filter(Boolean).join(' '));
    }
    // databases (not assets of their own: the instance on a server)
    for (const r of S.db) {
      const sv = r.server || {}, label = { oracle: 'Oracle', mssql: 'SQL Server', postgres: 'PostgreSQL', mysql: 'MySQL' }[r.engine] || r.engine;
      const it = { key: 'db:' + r.id, db_id: r.id, name: (r.host || r.ip) + ' · ' + label + (sv.instance ? ' ' + sv.instance : ''), class: 'database', platform: r.engine, ip: r.ip || '', site: '', criticality: '', prod: isProd({ name: r.host || '' }),
        version: sv.version || '', signals: [] };
      const a = r.asset_id ? store.collection('assets').get(r.asset_id) : null; if (a) { it.criticality = a.criticality || ''; it.prod = isProd(a); it.asset_id = a.id; }
      if (r.at && t - Date.parse(r.at) > P.fresh_days * DAY) it.signals.push({ state: null, source: 'database inventory', text: 'version last read ' + Math.floor((t - Date.parse(r.at)) / DAY) + ' days ago', points: 0 });
      it.ip = '';   // the server's own findings are counted on the server, not again on its database
      evaluate(it, null, label + ' ' + (sv.version || '') + ' ' + (sv.edition || '') + ' ' + (sv.banner || ''));
    }
    items.sort((x, y) => y.priority - x.priority || (RANKS[y.status] || 0) - (RANKS[x.status] || 0) || String(x.name).localeCompare(String(y.name)));
    const cnt = (L0, f) => L0.filter(f).length;
    const classes = CLASSES.map((k) => { const L0 = items.filter((i) => i.class === k), m = L0.filter((i) => i.status !== 'not_measured');
      return { class: k, label: CLABEL[k], page: PAGE[k], connect: CONNECT[k], total: L0.length, measured: m.length, coverage: L0.length ? Math.round(m.length / L0.length * 100) : null,
        current: cnt(L0, (i) => i.status === 'current'), behind: cnt(L0, (i) => i.status === 'behind'), overdue: cnt(L0, (i) => i.status === 'overdue'), eol: cnt(L0, (i) => i.status === 'eol'),
        not_measured: L0.length - m.length, excepted: cnt(L0, (i) => i.exception), pct: m.length ? Math.round(cnt(m, (i) => i.status === 'current') / m.length * 100) : null }; });
    const m = items.filter((i) => i.status !== 'not_measured');
    const platforms = {}; for (const i of items) { const k = i.class + '|' + i.platform; const p = platforms[k] = platforms[k] || { class: i.class, platform: i.platform, assets: 0, versions: {}, baseline: base(i.class, i.platform) }; p.assets++; if (i.version) p.versions[i.version] = (p.versions[i.version] || 0) + 1; }
    return { at: iso(), policy: P, classes, items: items.slice(0, 5000), notes: S.notes, platforms: Object.values(platforms).sort((a, b) => b.assets - a.assets),
      exceptions: exc.sort((a, b) => String(b.requested_at).localeCompare(String(a.requested_at))).slice(0, 300).map((x) => Object.assign({}, x, { active: x.state === 'approved' && Date.parse(x.until) > t, expired: x.state === 'approved' && Date.parse(x.until) <= t })),
      summary: { assets: items.length, measured: m.length, current: cnt(m, (i) => i.status === 'current'), behind: cnt(m, (i) => i.status === 'behind'), overdue: cnt(m, (i) => i.status === 'overdue'), eol: cnt(m, (i) => i.status === 'eol'),
        not_measured: items.length - m.length, excepted: cnt(items, (i) => i.exception), pending_exceptions: cnt(exc, (x) => x.state === 'pending'),
        pct: m.length ? Math.round(cnt(m, (i) => i.status === 'current') / m.length * 100) : null, coverage: items.length ? Math.round(m.length / items.length * 100) : null },
      note: 'Measured from what the platform already reads; an asset no source reports on is not measured, never patched. Patching itself is done on each class\'s own page, under its own change and approval.' };
  }
  function view(who) { const v = model(); v.can_act = ['operator', 'admin'].includes(who.role); v.can_admin = who.role === 'admin'; return v; }

  // ---------- policy (administrator)
  function savePolicy(input, who) {
    if (SERVICE.test(String(who.user || ''))) throw bad('a person sets the patch policy', 403);
    const b = body(input || {}).int('fresh_days', { min: 1, max: 60 }).done();
    const cur = ((C.cfg().get('policy') || {}).value) || {};
    if (input && input.sla !== undefined) {
      if (!input.sla || typeof input.sla !== 'object' || Array.isArray(input.sla)) throw bad('sla must be {critical, high, medium, low} in days');
      const sla = {}; for (const [k, v] of Object.entries(input.sla)) { if (!SEV.includes(k)) throw bad('sla.' + String(k).slice(0, 20) + ' is not a severity (critical, high, medium, low)'); if (!Number.isInteger(v) || v < 1 || v > 365) throw bad('sla.' + k + ' must be a whole number of days 1-365'); sla[k] = v; }
      const mm = Object.assign({}, DEF_SLA, sla); if (!(mm.critical <= mm.high && mm.high <= mm.medium && mm.medium <= mm.low)) throw bad('sla: critical <= high <= medium <= low');
      cur.sla = sla;
    }
    if (input && input.baselines !== undefined) {
      if (!Array.isArray(input.baselines) || input.baselines.length > 100) throw bad('baselines must be a list of at most 100');
      const seen = new Set();
      cur.baselines = input.baselines.map((x, i) => {
        const r = body(x).oneOf('class', CLASSES, { required: true }).str('platform', { required: true, max: 40 }).str('target', { required: true, max: 40 }).str('minimum', { max: 40 }).str('note', { max: 300 }).done();
        r.platform = lc(r.platform);
        if (!PLAT_RE.test(r.platform)) throw bad('baselines[' + i + '].platform: letters, digits, space . _ - only (e.g. fortigate, aruba, oracle, mssql)');
        if (!VER_RE.test(r.target)) throw bad('baselines[' + i + '].target is not a release (e.g. 7.4.5)');
        if (r.minimum && !VER_RE.test(r.minimum)) throw bad('baselines[' + i + '].minimum is not a release');
        if (r.minimum && cmpVer(r.minimum, r.target) > 0) throw bad('baselines[' + i + '].minimum must not be newer than the target');
        const k = r.class + '|' + r.platform; if (seen.has(k)) throw bad('baselines[' + i + ']: ' + r.class + ' / ' + r.platform + ' is listed twice'); seen.add(k);
        return r;
      });
    }
    if (b.fresh_days !== undefined) cur.fresh_days = b.fresh_days;
    C.cfg().put({ id: 'policy', value: cur, by: who.user, at: iso() });
    audit(who, 'patching.policy', 'policy', { sla: cur.sla, fresh_days: cur.fresh_days, baselines: (cur.baselines || []).map((x) => x.class + '/' + x.platform + ' ' + x.target) });
    return policy();
  }

  // ---------- exceptions: a patch that cannot be installed yet, with a compensating control, approved by another person
  const nextId = () => 'PX-' + String(C.exc().all().reduce((mx, x) => Math.max(mx, Number(String(x.id).split('-')[1]) || 0), 0) + 1).padStart(5, '0');
  function requestException(input, who) {
    if (SERVICE.test(String(who.user || ''))) throw bad('a person requests a patch exception', 403);
    const b = body(input || {}).str('key', { required: true, max: 120 }).str('reason', { required: true, max: 1000 }).str('compensating', { required: true, max: 1000 }).date('until', { required: true }).done();
    if (!/^(asset|db):[A-Za-z0-9_.:-]{1,100}$/.test(b.key)) throw bad('key must be asset:<id> or db:<id>');
    if (b.reason.length < 10) throw bad('reason: say why the patch cannot be installed yet (at least 10 characters)');
    if (b.compensating.length < 10) throw bad('compensating: say what reduces the risk meanwhile (at least 10 characters)');
    const until = Date.parse(b.until + 'T23:59:59Z'), t = now();
    if (!(until > t)) throw bad('until must be in the future');
    if (until - t > 180 * DAY) throw bad('until: an exception lasts at most 180 days - request a new one when it ends');
    const it = model().items.find((i) => i.key === b.key); if (!it) throw bad('there is no asset or database "' + b.key.slice(0, 80) + '" on the patch list', 404);
    if (C.exc().all((x) => x.key === b.key && (x.state === 'pending' || (x.state === 'approved' && Date.parse(x.until) > t))).length) throw bad(it.name + ' already has a pending or active exception', 409);
    const x = { id: nextId(), key: b.key, name: it.name, class: it.class, status_at_request: it.status, reason: b.reason, compensating: b.compensating, until: new Date(until).toISOString(), state: 'pending', requested_by: who.user, requested_at: iso(), history: [{ at: iso(), by: who.user, action: 'requested' }] };
    C.exc().put(x);
    audit(who, 'patching.exception.request', x.id, { key: x.key, until: x.until, status: it.status });
    return x;
  }
  function needX(id) { const x = C.exc().get(param(String(id || ''))); if (!x) throw bad('there is no exception ' + String(id).slice(0, 40), 404); return x; }
  function decide(id, input, who) {
    const x = needX(id), b = body(input || {}).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 1000 }).done();
    if (SERVICE.test(String(who.user || ''))) throw bad('a person decides a patch exception - never a service or AI identity', 403);
    if (lc(who.user) === lc(x.requested_by)) throw bad('the person who requested the exception cannot decide it', 403);
    if (x.state !== 'pending') throw bad('exception is ' + x.state, 409);
    if (b.decision === 'rejected' && !(b.comment && b.comment.length >= 5)) throw bad('comment is required when rejecting (why)');
    x.state = b.decision; x.decided_by = who.user; x.decided_at = iso(); x.history.push({ at: iso(), by: who.user, action: b.decision, note: b.comment || '' });
    C.exc().put(x);
    audit(who, 'patching.exception.' + b.decision, x.id, { key: x.key, comment: b.comment || undefined });
    return x;
  }
  function revoke(id, input, who) {
    const x = needX(id), b = body(input || {}).str('reason', { required: true, max: 1000 }).done();
    if (!['pending', 'approved'].includes(x.state)) throw bad('exception is ' + x.state, 409);
    x.state = 'revoked'; x.history.push({ at: iso(), by: who.user, action: 'revoked', note: b.reason }); C.exc().put(x);
    audit(who, 'patching.exception.revoke', x.id, { key: x.key, reason: b.reason });
    return x;
  }
  return { view, model, policy, savePolicy, requestException, decide, revoke };
}

function registerPatchHub(srv, app, S0) {
  const S = S0 || createPatchHub(app);
  app.addons = app.addons || {}; app.addons.patchHub = S;
  srv.route('GET', '/patching', (ctx) => { ctx.need('viewer'); return S.view(ctx.who); });
  srv.route('POST', '/patching/policy', (ctx) => { ctx.need('admin'); return S.savePolicy(ctx.body, ctx.who); });
  srv.route('POST', '/patching/exceptions', (ctx) => { ctx.need('operator'); return S.requestException(ctx.body, ctx.who); });
  srv.route('POST', '/patching/exceptions/:id/decide', (ctx) => { ctx.need('admin'); return S.decide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/patching/exceptions/:id/revoke', (ctx) => { ctx.need('admin'); return S.revoke(ctx.params.id, ctx.body, ctx.who); });
  return S;
}

module.exports = { createPatchHub, registerPatchHub, cmpVer, classOf, CLASSES };
