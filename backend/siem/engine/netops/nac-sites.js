// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * NAC BY SITE - head office, branches and project sites - over the endpoint view of netops/fmg-nac.js (FortiGate device detection +
 * the H3C / Cisco switch port map; read-only, nothing is pushed to a device).
 *   profile     every site the FortiGates report is a head office, branch, project site, office or data centre (guessed from its name,
 *               set by an administrator); each kind has a VLAN template - VLAN id -> role (corporate, voice, printers, cctv, iot, guest,
 *               contractor, management, servers, quarantine) - and a site can override a VLAN. Saved by an administrator, audited.
 *   class       each endpoint's device class from what was seen: PC, mobile, phone, printer, camera / NVR, network device, server, IoT
 *   policy      which classes a role admits; a known class on a VLAN that does not admit it is a finding (a camera on the corporate
 *               VLAN; an unknown device on management); an unauthorised device on corporate / management / servers after the 7-day
 *               learning; a contractor authorisation past its end date and the device still seen; a VLAN the profile does not describe
 *   coverage    the share of a site's endpoints also seen on a switch port (no switch read = no port, no quarantine step)
 *   ML          each site's endpoint count per day against its OWN days before (robust z, 7+ days): a project site that suddenly has
 *               twice its devices, a branch that went quiet - said with the numbers
 *   fix         for a VLAN finding: the port, the target VLAN of the right role at that site, and the H3C / Cisco lines a person runs
 *               (shown, never pushed); authorise (with an end date for contractors) and quarantine stay the NAC four-eyes decisions
 *   GET {P}/nac/sites            analyst (names devices)
 *   PUT {P}/nac/sites/profile    admin   {sites: {name: kind}, templates: {kind: {vlan: role}}, overrides: {site: {vlan: role}}}
 */
const { body } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

const DAY = 86400000;
const KINDS = ['head_office', 'branch', 'project_site', 'office', 'data_centre'];
const ROLES = ['corporate', 'voice', 'printers', 'cctv', 'iot', 'guest', 'contractor', 'management', 'servers', 'quarantine'];
const CLASSES = ['pc', 'mobile', 'phone', 'printer', 'camera', 'network', 'server', 'iot', 'unknown'];
// which device classes a VLAN role admits ('*' = any)
const ADMITS = { corporate: ['pc', 'printer', 'mobile'], voice: ['phone'], printers: ['printer'], cctv: ['camera'], iot: ['iot', 'camera', 'printer'], guest: ['*'], contractor: ['pc', 'mobile'],
  management: ['network', 'server', 'pc'], servers: ['server'], quarantine: ['*'] };
const RESTRICTED = { corporate: 'medium', management: 'high', servers: 'high' };   // unauthorised devices are a finding here
// a starting template per kind - VLAN numbers differ per organisation: shown as a template to confirm, never as fact
const TEMPLATES = {
  head_office: { 10: 'corporate', 20: 'voice', 30: 'printers', 40: 'cctv', 50: 'guest', 99: 'management', 100: 'servers', 999: 'quarantine' },
  branch: { 10: 'corporate', 20: 'voice', 30: 'printers', 40: 'cctv', 50: 'guest', 99: 'management', 999: 'quarantine' },
  project_site: { 10: 'corporate', 40: 'cctv', 45: 'iot', 50: 'guest', 60: 'contractor', 99: 'management', 999: 'quarantine' },
  office: { 10: 'corporate', 30: 'printers', 50: 'guest', 99: 'management', 999: 'quarantine' },
  data_centre: { 99: 'management', 100: 'servers', 999: 'quarantine' },
};
const lc = (x) => String(x == null ? '' : x).toLowerCase();
const kindOf = (name) => { const n = lc(name); return /head ?office|\bho\b|hq|headquarter/.test(n) ? 'head_office' : /project|site|camp|plant|yard/.test(n) ? 'project_site' : /data ?cent|\bdc\b|dr site/.test(n) ? 'data_centre' : /branch/.test(n) ? 'branch' : n ? 'office' : 'office'; };
function classOf(e) {
  const t = lc([e.os, e.host, e.vendor, e.sw && e.sw.desc].filter(Boolean).join(' '));
  if (/hikvision|dahua|axis|hanwha|uniview|camera|\bcam\b|\bipc\b|nvr|dvr|milestone/.test(t)) return 'camera';
  if (/printer|laserjet|officejet|ricoh|canon|kyocera|konica|xerox|brother|epson|lexmark|\bmfp\b/.test(t)) return 'printer';
  if (/ip ?phone|cisco ?cp-|yealink|polycom|avaya|grandstream|fanvil|\bsip\b/.test(t)) return 'phone';
  if (/fortigate|fortiap|fortiswitch|h3c|comware|cisco ios|aruba|switch|access point|\bap\b|router/.test(t)) return 'network';
  if (/windows server|server 20\d\d|esx|hyper-v|red ?hat|rhel|centos|ubuntu server|oracle linux|srv|-db|sql/.test(t)) return 'server';
  if (/android|ios|ipados|iphone|ipad|mobile/.test(t)) return 'mobile';
  if (/windows|mac ?os|macbook|chrome ?os|laptop|desktop|\bpc\b|ubuntu|linux/.test(t)) return 'pc';
  if (/sensor|plc|scada|hvac|bms|badge|access control|ups|iot|esp|tuya|smart/.test(t)) return 'iot';
  return 'unknown';
}
const med = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

function profileOf(saved, siteNames) {
  const p = saved || {}, sites = {}, src = {};
  for (const n of siteNames) { const k = p.sites && KINDS.includes(p.sites[n]) ? p.sites[n] : kindOf(n); sites[n] = k; src[n] = p.sites && p.sites[n] ? 'set' : 'guessed from the name'; }
  const templates = {}; for (const k of KINDS) templates[k] = Object.assign({}, TEMPLATES[k], (p.templates || {})[k] || {});
  return { sites, kind_source: src, templates, overrides: p.overrides || {}, saved: !!saved, saved_by: p.saved_by || null, saved_at: p.saved_at || null };
}
const roleAt = (prof, site, vlan) => { const v = String(vlan || ''); if (!v) return null; const o = (prof.overrides[site] || {})[v]; if (o) return o; const t = prof.templates[prof.sites[site] || 'office'] || {}; return t[v] || null; };
const vlanFor = (prof, site, role) => { const k = prof.sites[site] || 'office', o = prof.overrides[site] || {}; for (const [v, r] of Object.entries(o)) if (r === role) return v; for (const [v, r] of Object.entries(prof.templates[k] || {})) if (r === role) return v; return null; };
const fixLines = (sw, vlan) => (sw.vendor === 'h3c-comware' ? ['system-view', 'interface ' + sw.port, 'port access vlan ' + vlan, 'quit', 'save'] : ['configure terminal', 'interface ' + sw.port, 'switchport access vlan ' + vlan, 'end', 'write memory']);
const ROLE_FOR = { camera: 'cctv', printer: 'printers', phone: 'voice', server: 'servers', network: 'management', iot: 'iot', pc: 'corporate', mobile: 'guest', unknown: 'guest' };

function analyse(view, prof, history, now) {
  const eps = (view && view.endpoints) || [], F = [], today = new Date(now + 3 * 3600000).toISOString().slice(0, 10);
  const add = (severity, code, site, e, title, why, fix) => F.push({ severity, code, site: site || '(no site)', mac: e ? e.mac : null, host: e ? e.host || e.ip || e.mac : null, title, why, fix: fix || null });
  const S = new Map(), siteOf = (e) => e.site || (e.sw ? 'switch ' + e.sw.switch : '(no site)');
  for (const e of eps) {
    const site = siteOf(e), cls = classOf(e), vlan = e.sw ? String(e.sw.vlan || '') : '', role = roleAt(prof, site, vlan);
    const x = S.get(site) || S.set(site, { site, kind: prof.sites[site] || kindOf(site), endpoints: 0, on_switch: 0, risky: 0, authorised: 0, bad: 0, classes: {}, roles: {}, unknown_vlans: new Set() }).get(site);
    x.endpoints++; if (e.sw) x.on_switch++; if (e.risk >= 30) x.risky++; if (e.authorised) x.authorised++; x.classes[cls] = (x.classes[cls] || 0) + 1; if (role) x.roles[role] = (x.roles[role] || 0) + 1;
    let bad = false; const mark = () => { if (!bad) { bad = true; x.bad++; } };
    if (vlan && !role) x.unknown_vlans.add(vlan);
    if (role && cls !== 'unknown' && ADMITS[role] && ADMITS[role][0] !== '*' && !ADMITS[role].includes(cls)) {
      const want = ROLE_FOR[cls], tv = vlanFor(prof, site, want), sev = (cls === 'camera' || cls === 'iot') && (role === 'corporate' || role === 'management' || role === 'servers') ? 'high' : 'medium';
      add(sev, 'wrong-vlan', site, e, 'A ' + cls + ' on the ' + role + ' VLAN ' + vlan, (e.host || e.mac) + ' is a ' + cls + ' (from ' + ([e.os, e.host].filter(Boolean).join(' / ') || 'what was seen') + ') on ' + e.sw.switch + ' ' + e.sw.port, tv ? { vlan: tv, role: want, switch: e.sw.switch, port: e.sw.port, lines: fixLines(e.sw, tv), note: 'move the port to the ' + want + ' VLAN ' + tv + ' (a person runs it in a change window)' } : { note: 'no ' + want + ' VLAN is set for this site - add it to the profile' });
      mark();
    }
    if (role && RESTRICTED[role] && !e.authorised && !view.learning && !e.quarantine && now - (Date.parse(e.first_seen) || now) > 7 * DAY) {
      add(cls === 'unknown' && role !== 'corporate' ? 'high' : RESTRICTED[role], 'unauthorised', site, e, 'Unauthorised ' + (cls === 'unknown' ? 'device' : cls) + ' on the ' + role + ' VLAN ' + vlan, 'seen since ' + String(e.first_seen).slice(0, 10) + ', never authorised', { note: 'authorise it (owner) or quarantine it - four-eyes on the NAC page' }); mark();
    }
    if (e.auth_expired && now - (Date.parse(e.last_seen) || 0) < DAY) { add(prof.sites[site] === 'project_site' ? 'high' : 'medium', 'expired', site, e, 'Access ended on ' + e.auth_expires + ' but the device is still connected', (e.host || e.mac) + ' was authorised until ' + e.auth_expires, { note: 'extend it (a new authorisation with a new end date) or quarantine it' }); mark(); }
    if (role === 'quarantine' && now - (Date.parse(e.last_seen) || 0) < DAY) add('low', 'in-quarantine', site, e, 'In the quarantine VLAN', (e.host || e.mac) + ' on ' + e.sw.switch + ' ' + e.sw.port, null);
  }
  // per site: coverage, undescribed VLANs, the day's endpoint count against the site's own history (robust z)
  const sites = [...S.values()].map((x) => {
    const hist = (history[x.site] || []).filter((h) => h.day < today).slice(-30).map((h) => h.n), m = med(hist), mad = hist.length ? med(hist.map((v) => Math.abs(v - m))) || Math.max(1, m * 0.05) : null;
    const z = hist.length >= 7 ? Math.round(10 * (x.endpoints - m) / (1.4826 * mad)) / 10 : null;
    if (z != null && Math.abs(z) >= 3.5 && Math.abs(x.endpoints - m) >= 5) add(z > 0 ? 'medium' : 'low', 'count', x.site, null, (z > 0 ? 'Unusually many devices at ' : 'Unusually few devices at ') + x.site + ': ' + x.endpoints + ' against usually ' + m, 'robust z ' + z + ' over its last ' + hist.length + ' days' + (z > 0 && x.kind === 'project_site' ? ' - new contractors or equipment? authorise them with an end date' : z < 0 ? ' - a link or a FortiGate not reporting?' : ''), null);
    const cov = x.endpoints ? Math.round(100 * x.on_switch / x.endpoints) : null;
    if (x.endpoints >= 10 && cov != null && cov < 50) add('low', 'coverage', x.site, null, x.site + ': only ' + cov + ' % of endpoints seen on a switch port', 'without the switch read there is no port to move or quarantine', { note: 'add the site\'s H3C / Cisco access switches to the port map (read-only SSH)' });
    if (x.unknown_vlans.size) add('low', 'vlan-undescribed', x.site, null, x.site + ': VLAN ' + [...x.unknown_vlans].slice(0, 6).join(', ') + ' not in the profile', 'their devices cannot be checked against a role', { note: 'give each VLAN its role (NAC by Site - profile)' });
    return { site: x.site, kind: x.kind, kind_source: prof.kind_source[x.site] || 'guessed from the name', endpoints: x.endpoints, authorised: x.authorised, risky: x.risky, violations: x.bad, coverage_pct: cov,
      compliance_pct: x.endpoints ? Math.round(100 * (x.endpoints - x.bad) / x.endpoints) : null, classes: x.classes, roles: x.roles, usual: m, z, unknown_vlans: [...x.unknown_vlans] };
  }).sort((a, b) => (a.compliance_pct == null ? 101 : a.compliance_pct) - (b.compliance_pct == null ? 101 : b.compliance_pct));
  const SEV = { high: 3, medium: 2, low: 1 }; F.sort((a, b) => SEV[b.severity] - SEV[a.severity] || a.site.localeCompare(b.site));
  const byKind = {}; for (const k of KINDS) { const L = sites.filter((s) => s.kind === k); if (!L.length) continue; const n = L.reduce((t, s) => t + s.endpoints, 0), b = L.reduce((t, s) => t + s.violations, 0); byKind[k] = { sites: L.length, endpoints: n, violations: b, compliance_pct: n ? Math.round(100 * (n - b) / n) : null }; }
  const expiring = eps.filter((e) => e.auth_expires && !e.auth_expired && Date.parse(e.auth_expires + 'T23:59:59Z') - now < 7 * DAY).map((e) => ({ mac: e.mac, host: e.host || e.ip || '', site: siteOf(e), expires: e.auth_expires }));
  const ins = [];
  const worst = sites.find((s) => s.compliance_pct != null && s.compliance_pct < 90); if (worst) ins.push(worst.site + ' (' + worst.kind.replace('_', ' ') + ') is the least compliant site: ' + worst.compliance_pct + ' % of its ' + worst.endpoints + ' endpoints follow its VLAN policy.');
  const wv = F.filter((f) => f.code === 'wrong-vlan' && f.severity === 'high').length; if (wv) ins.push(wv + ' camera / IoT device(s) sit on a corporate, management or server VLAN - the most direct way in for an attacker; move them to the CCTV / IoT VLAN.');
  const ex = F.filter((f) => f.code === 'expired').length; if (ex) ins.push(ex + ' device(s) are still connected after their time-limited access ended - mostly contractors at project sites.');
  if (expiring.length) ins.push(expiring.length + ' contractor / visitor authorisation(s) end within 7 days.');
  const un = F.filter((f) => f.code === 'unauthorised').length; if (un) ins.push(un + ' unauthorised device(s) on restricted VLANs after the learning week.');
  if (view.learning) ins.push('NAC is still learning until ' + view.learning_until + ' - unauthorised devices are not judged before then.');
  if (!eps.length) ins.push('No endpoint is seen yet: connect FortiManager (or the FortiGates) and add the access switches to the port map.');
  return { at: new Date(now).toISOString(), today, learning: !!view.learning, learning_until: view.learning_until || null, connected: !!view.connected,
    kpis: { sites: sites.length, endpoints: eps.length, violations: F.filter((f) => ['wrong-vlan', 'unauthorised', 'expired'].includes(f.code)).length, high: F.filter((f) => f.severity === 'high').length,
      compliance_pct: eps.length ? Math.round(100 * (eps.length - sites.reduce((t, s) => t + s.violations, 0)) / eps.length) : null, coverage_pct: eps.length ? Math.round(100 * eps.filter((e) => e.sw).length / eps.length) : null, expiring: expiring.length },
    by_kind: byKind, sites, findings: F.slice(0, 1000), expiring, insights: ins,
    profile: { sites: prof.sites, kind_source: prof.kind_source, templates: prof.templates, overrides: prof.overrides, saved: prof.saved, saved_by: prof.saved_by, saved_at: prof.saved_at, kinds: KINDS, roles: ROLES, admits: ADMITS },
    note: 'From the FortiGates\' device detection and the switch port map (read-only). VLAN roles come from the profile - the starting templates are a suggestion to confirm. Moves and quarantines are carried out by a person; authorise and quarantine are four-eyes on the NAC page.' };
}

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps), store = deps.state.collection('nac_sites'), daily = deps.state.collection('nac_site_daily'), NOW = deps.now || Date.now;
  const view = () => {
    if (!deps.nacApi) throw new HttpError(503, 'the NAC module is not running');
    const v = deps.nacApi.view(), now = NOW(), today = new Date(now + 3 * 3600000).toISOString().slice(0, 10);
    const names = [...new Set((v.endpoints || []).map((e) => e.site || (e.sw ? 'switch ' + e.sw.switch : '(no site)')))];
    const prof = profileOf(store.get('profile'), names);
    // the day's count per site, for each site's own history (kept 120 days)
    const cnt = {}; for (const e of v.endpoints || []) { const s = e.site || (e.sw ? 'switch ' + e.sw.switch : '(no site)'); cnt[s] = (cnt[s] || 0) + 1; }
    for (const [s, k] of Object.entries(cnt)) daily.put({ id: s + '|' + today, site: s, day: today, n: k });
    const hist = {}; for (const d of daily.all()) { if (now - Date.parse(d.day + 'T00:00:00Z') > 120 * DAY) { daily.remove(d.id); continue; } (hist[d.site] = hist[d.site] || []).push(d); }
    for (const k of Object.keys(hist)) hist[k].sort((a, b) => a.day.localeCompare(b.day));
    return analyse(v, prof, hist, now);
  };
  api.route('GET', `${P}/nac/sites`, wrap(deps, 'analyst', async (ctx) => { const r = view(); audit(ctx, 'nac.sites.read', 'all', { sites: r.kpis.sites, violations: r.kpis.violations }); return ctx.ok(r); }));
  api.route('PUT', `${P}/nac/sites/profile`, wrap(deps, 'admin', async (ctx) => {
    body(ctx.body || {});   // a JSON object; its three maps are checked field by field below (unknown fields refused)
    const src = ctx.body && typeof ctx.body === 'object' && !Array.isArray(ctx.body) ? ctx.body : {};
    for (const k of Object.keys(src)) if (!['sites', 'templates', 'overrides'].includes(k)) throw new HttpError(400, k + ': not a profile field (sites, templates, overrides)');
    const obj = (x, name) => { if (x === undefined) return {}; if (!x || typeof x !== 'object' || Array.isArray(x)) throw new HttpError(400, name + ' must be an object'); return x; };
    const sites = {}, templates = {}, overrides = {}, vlanOk = (v) => /^\d{1,4}$/.test(String(v)) && +v >= 1 && +v <= 4094, name = (n) => typeof n === 'string' && n.length <= 120 && !/[\u0000-\u001f]/.test(n);
    const S0 = obj(src.sites, 'sites'); if (Object.keys(S0).length > 500) throw new HttpError(400, 'sites: at most 500');
    for (const [n, k] of Object.entries(S0)) { if (!name(n)) throw new HttpError(400, 'sites: "' + String(n).slice(0, 40) + '" is not a site name'); if (!KINDS.includes(k)) throw new HttpError(400, 'sites.' + n + ': one of ' + KINDS.join(', ')); sites[n] = k; }
    const vmap = (m, where) => { const out = {}; obj(m, where); if (Object.keys(m).length > 200) throw new HttpError(400, where + ': at most 200 VLANs'); for (const [v, r] of Object.entries(m)) { if (!vlanOk(v)) throw new HttpError(400, where + ': VLAN "' + String(v).slice(0, 8) + '" must be 1-4094'); if (!ROLES.includes(r)) throw new HttpError(400, where + '.' + v + ': one of ' + ROLES.join(', ')); out[String(+v)] = r; } return out; };
    for (const [k, m] of Object.entries(obj(src.templates, 'templates'))) { if (!KINDS.includes(k)) throw new HttpError(400, 'templates: "' + String(k).slice(0, 30) + '" is not a site kind'); templates[k] = vmap(m, 'templates.' + k); }
    const O0 = obj(src.overrides, 'overrides'); if (Object.keys(O0).length > 500) throw new HttpError(400, 'overrides: at most 500 sites');
    for (const [n, m] of Object.entries(O0)) { if (!name(n)) throw new HttpError(400, 'overrides: "' + String(n).slice(0, 40) + '" is not a site name'); overrides[n] = vmap(m, 'overrides.' + n); }
    const p = { id: 'profile', sites, templates, overrides, saved_by: ctx.user, saved_at: new Date(NOW()).toISOString() };
    store.put(p);
    audit(ctx, 'nac.sites.profile', 'profile', { sites: Object.keys(sites).length, templates: Object.keys(templates), overrides: Object.keys(overrides).length });
    return ctx.ok({ saved: true, saved_at: p.saved_at });
  }));
}

module.exports = { register, analyse, profileOf, classOf, kindOf, TEMPLATES, ADMITS, KINDS, ROLES };
