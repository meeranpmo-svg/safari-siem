// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Microsoft 365 Security - analysis over what the Graph collector (collect/m365-graph.js) already holds: Secure Score, MFA
 * registration, Entra ID risky users and risk detections, Conditional Access policies, Defender alerts and sign-ins. Nothing new is
 * read from Microsoft and nothing is changed there; every "fix" is a link to the Microsoft admin page that does it.
 *   score        Secure Score now, the weakest controls (where the points are), the trend from the daily history (slope per week, a
 *                change unusual against the last 30 days by robust z on median / MAD, 7+ samples)
 *   mfa          coverage, administrators without MFA first (the highest-impact gap), everyone not registered
 *   identity     risky users by level and risk detections by type and country; a person at risk who also has no MFA, an open
 *                Defender alert or several detections is ranked first - one score per person, every point named
 *   chains       a risk detection and a Defender alert on the same account within 24 hours: one incident to look at, not two
 *   access       Conditional Access: enabled / report-only / off; no enforced policy; report-only for 30+ days (decide); changed in
 *                the last 7 days (change review); the usual baseline policies looked for BY NAME and said to be by name only
 *   alerts       Defender alerts by severity, status, category and product; open high-severity alerts and how long they have waited
 *   coverage     which dataset Graph did not give and the exact permission to grant - a missing block reads "not read", never 0
 * People are counted, not named, for viewers (PDPL); a named read is audited. Indicators for an analyst to confirm, not proof.
 *   GET {P}/m365/security     any signed-in user (names to analyst and above)
 */
const { wrap, audit, prefixOf } = require('../soc/routeutil');
const DAY = 86400000, RIYADH = 3 * 3600000, RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const SEC = ['secureScore', 'mfa', 'riskyUsers', 'riskDetections', 'conditionalAccess', 'defenderAlerts'];
const PERM = { secureScore: 'SecurityEvents.Read.All', mfa: 'UserAuthenticationMethod.Read.All + AuditLog.Read.All', riskyUsers: 'IdentityRiskyUser.Read.All', riskDetections: 'IdentityRiskEvent.Read.All', conditionalAccess: 'Policy.Read.All', defenderAlerts: 'SecurityAlert.Read.All', signins: 'AuditLog.Read.All' };
const LABEL = { secureScore: 'Secure Score', mfa: 'MFA registration', riskyUsers: 'Risky users', riskDetections: 'Risk detections', conditionalAccess: 'Conditional Access', defenderAlerts: 'Defender alerts', signins: 'Sign-ins' };
// fixed Microsoft admin pages - the only links this page offers (never built from tenant data)
const LINK = { score: 'https://security.microsoft.com/securescore', mfa: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails',
  risky: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/RiskyUsers', detections: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/RiskDetections',
  ca: 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies', alerts: 'https://security.microsoft.com/alerts' };
const RISK_TYPE = { unfamiliarFeatures: 'Unfamiliar sign-in properties', impossibleTravel: 'Impossible travel', anonymizedIPAddress: 'Anonymous IP address', maliciousIPAddress: 'Malicious IP address',
  leakedCredentials: 'Leaked credentials', passwordSpray: 'Password spray', suspiciousIPAddress: 'Suspicious IP address', unlikelyTravel: 'Atypical travel', mcasImpossibleTravel: 'Impossible travel (Defender for Cloud Apps)',
  suspiciousInboxForwarding: 'Suspicious inbox forwarding', mcasSuspiciousInboxManipulationRules: 'Suspicious inbox rules', investigationsThreatIntelligence: 'Microsoft threat intelligence', adminConfirmedUserCompromised: 'Admin confirmed compromised',
  anomalousToken: 'Anomalous token', tokenIssuerAnomaly: 'Token issuer anomaly', newCountry: 'New country', riskyIPAddress: 'Activity from a risky IP', generic: 'Other' };
// the baseline every tenant is expected to enforce - looked for by policy NAME only (Graph gives the name and state here, not the conditions)
const BASELINE = [['admins-mfa', 'MFA for administrators', /admin|privileg/i, /mfa|multi.?factor|2fa|authentication strength/i], ['all-mfa', 'MFA for all users', /all users|everyone|all-users|\ball\b/i, /mfa|multi.?factor|2fa/i],
  ['legacy', 'Block legacy authentication', /legacy|basic auth|imap|pop|smtp auth/i, null], ['risk', 'Sign-in / user risk policy', /risk/i, null], ['location', 'Block or limit by location', /location|country|geo|trusted/i, null]];
const median = (a) => { const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length ? (b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2) : null; };
const pct = (a, b) => (b ? Math.round(a / b * 1000) / 10 : null);
const dayOf = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
const low = (s) => String(s || '').toLowerCase();
function robustZ(series, x) { if (series.length < 7 || x == null) return null; const m = median(series), mad = median(series.map((v) => Math.abs(v - m))); return Math.round(((x - m) / (1.4826 * (mad || 0.5))) * 10) / 10; }
function slope(pts) { if (pts.length < 3) return null; const n = pts.length, mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n; let nu = 0, de = 0; for (const [x, y] of pts) { nu += (x - mx) * (y - my); de += (x - mx) ** 2; } return de ? nu / de : 0; }
const isOpen = (s) => !/resolved|dismissed|remediated|closed/i.test(String(s || ''));

function analyse(d, hist, now) {
  const t = now || Date.now(), out = { configured: !!(d && d.configured), updated: (d && d.updated) || null, reason: (d && d.reason) || null, coverage: [], kpis: {}, actions: [], links: LINK };
  if (!out.configured) { out.note = 'Microsoft 365 is not connected to the SIEM - connect it in Connections & Setup (the same Entra ID app as the Exchange Online audit pull).'; return out; }
  const sec = d.security || {}, B = d.blocks || {}, ok = (k) => !!(sec[k] && sec[k].ok), data = (k) => (ok(k) ? sec[k].data : null);
  for (const k of SEC.concat(['signins'])) { const b = B[k] || {}; out.coverage.push({ key: k, label: LABEL[k], ok: !!b.ok, perm: b.ok ? null : (b.perm || PERM[k]), error: b.ok ? null : (b.error || 'not read'), stale_since: b.stale_since || null }); }
  const missing = out.coverage.filter((c) => !c.ok);
  // ---- Secure Score
  const ss = data('secureScore'), H = (hist || []).slice().sort((a, b) => String(a.day).localeCompare(String(b.day)));
  if (ss) {
    const p = pct(ss.current, ss.max), series = H.filter((h) => h.day !== dayOf(t) && h.score_pct != null).slice(-30).map((h) => h.score_pct);
    const pts = H.filter((h) => h.score_pct != null).slice(-60).map((h) => [Date.parse(h.day) / DAY, h.score_pct]), sl = slope(pts);
    out.score = { current: Math.round(ss.current * 10) / 10, max: Math.round(ss.max * 10) / 10, pct: p, weakest: (ss.lowest || []).map((c) => ({ control: c.name, category: c.cat || '', score: c.score == null ? null : Math.round(c.score * 10) / 10 })),
      trend: { samples: pts.length, per_week: sl == null ? null : Math.round(sl * 7 * 10) / 10, z: robustZ(series, p), why: pts.length < 3 ? 'needs 3 daily samples (' + pts.length + ' so far)' : null } };
  }
  // ---- MFA
  const mfa = data('mfa');
  if (mfa) out.mfa = { users: mfa.users, registered: mfa.registered, pct: pct(mfa.registered, mfa.users), not_registered: (mfa.notRegistered || []).length, admins: (mfa.notRegistered || []).filter((u) => u.admin).map((u) => ({ name: u.name, upn: u.upn })), list: (mfa.notRegistered || []).map((u) => ({ name: u.name, upn: u.upn, admin: !!u.admin })) };
  const noMfa = new Map(((mfa && mfa.notRegistered) || []).map((u) => [low(u.upn), u]));
  // ---- risky users and detections
  const risky = data('riskyUsers') || [], det = data('riskDetections') || [], alerts = data('defenderAlerts') || [];
  const detOpen = det.filter((x) => isOpen(x.state)), byType = {}, byCountry = {};
  for (const x of det) { const k = RISK_TYPE[x.type] || x.type || 'Other'; byType[k] = (byType[k] || 0) + 1; if (x.country) byCountry[x.country] = (byCountry[x.country] || 0) + 1; }
  if (ok('riskyUsers')) out.risky = { total: risky.length, high: risky.filter((r) => r.level === 'high').length, medium: risky.filter((r) => r.level === 'medium').length, low: risky.filter((r) => r.level === 'low').length };
  if (ok('riskDetections')) out.detections = { total: det.length, open: detOpen.length, by_type: Object.entries(byType).map(([type, n]) => ({ type, n })).sort((a, b) => b.n - a.n), by_country: Object.entries(byCountry).map(([country, n]) => ({ country, n })).sort((a, b) => b.n - a.n),
    recent: det.slice().sort((a, b) => String(b.when).localeCompare(String(a.when))).slice(0, 50).map((x) => ({ when: x.when, upn: x.upn, type: RISK_TYPE[x.type] || x.type, level: x.level, state: x.state, ip: x.ip, where: [x.city, x.country].filter(Boolean).join(', ') })) };
  // ---- Defender alerts
  if (ok('defenderAlerts')) {
    const open = alerts.filter((a) => isOpen(a.status)), sev = (s) => alerts.filter((a) => low(a.severity) === s).length, cat = {}, prod = {};
    for (const a of alerts) { cat[a.category || 'other'] = (cat[a.category || 'other'] || 0) + 1; prod[a.product || 'other'] = (prod[a.product || 'other'] || 0) + 1; }
    const age = (a) => Math.max(0, Math.round((t - Date.parse(a.created)) / DAY * 10) / 10);
    out.alerts = { total: alerts.length, open: open.length, open_high: open.filter((a) => low(a.severity) === 'high').length, by_severity: { high: sev('high'), medium: sev('medium'), low: sev('low'), informational: sev('informational') },
      by_category: Object.entries(cat).map(([category, n]) => ({ category, n })).sort((a, b) => b.n - a.n), by_product: Object.entries(prod).map(([product, n]) => ({ product, n })).sort((a, b) => b.n - a.n),
      oldest_open_days: open.length ? Math.max(...open.map(age)) : null,
      list: alerts.slice().sort((a, b) => ({ high: 0, medium: 1, low: 2 }[low(a.severity)] ?? 3) - ({ high: 0, medium: 1, low: 2 }[low(b.severity)] ?? 3) || String(b.created).localeCompare(String(a.created))).map((a) => ({ created: a.created, title: a.title, category: a.category, severity: low(a.severity), status: a.status, open: isOpen(a.status), product: a.product, user: a.user, age_days: age(a) })) };
  }
  // ---- Conditional Access
  const ca = data('conditionalAccess');
  if (ca) {
    const on = ca.filter((p) => p.state === 'enabled'), ro = ca.filter((p) => p.state === 'enabledForReportingButNotEnforced'), off = ca.filter((p) => p.state === 'disabled');
    const base = BASELINE.map(([id, label, a, b]) => { const hit = on.find((p) => a.test(p.name) && (!b || b.test(p.name))) || null, ro1 = !hit && ro.find((p) => a.test(p.name) && (!b || b.test(p.name))); return { id, label, found: hit ? hit.name : null, report_only: ro1 ? ro1.name : null }; });
    out.access = { total: ca.length, enabled: on.length, report_only: ro.length, disabled: off.length, baseline: base,
      stale_report_only: ro.filter((p) => p.modified && t - Date.parse(p.modified) > 30 * DAY).map((p) => ({ name: p.name, since: p.modified, days: Math.round((t - Date.parse(p.modified)) / DAY) })),
      recent_changes: ca.filter((p) => p.modified && t - Date.parse(p.modified) <= 7 * DAY).map((p) => ({ name: p.name, state: p.state, modified: p.modified })),
      policies: ca.map((p) => ({ name: p.name, state: p.state, modified: p.modified })), note: 'Graph gives each policy\'s name and state here; the baseline is matched by name only - open the policy to confirm what it enforces.' };
  }
  // ---- one explainable score per person: Entra risk + no MFA + Defender alerts + detections + failed sign-ins
  const signins = d.signinsOk ? (d.signins || []) : [], P = new Map(), add = (upn, name, pts, why, kind) => { if (!upn) return; const k = low(upn); const p = P.get(k) || { upn, name: name || '', score: 0, why: [], kinds: new Set() }; if (!p.name && name) p.name = name; p.score += pts; p.why.push({ points: pts, text: why }); p.kinds.add(kind); P.set(k, p); };
  for (const r of risky) add(r.upn, r.name, r.level === 'high' ? 40 : r.level === 'medium' ? 25 : 10, 'Entra ID user risk ' + r.level, 'risk');
  for (const [k, u] of noMfa) if (P.has(k) || u.admin) add(u.upn, u.name, u.admin ? 30 : 15, u.admin ? 'administrator without MFA' : 'no MFA registered', 'mfa');
  const alertBy = {}; for (const a of alerts) if (a.user && isOpen(a.status)) (alertBy[low(a.user)] = alertBy[low(a.user)] || []).push(a);
  for (const [k, L] of Object.entries(alertBy)) { const hi = L.filter((a) => low(a.severity) === 'high').length; add(L[0].user, '', Math.min(40, hi * 25 + (L.length - hi) * 10), L.length + ' open Defender alert(s)' + (hi ? ', ' + hi + ' high' : ''), 'alert'); }
  const detBy = {}; for (const x of detOpen) if (x.upn) (detBy[low(x.upn)] = detBy[low(x.upn)] || []).push(x);
  for (const L of Object.values(detBy)) add(L[0].upn, '', Math.min(20, L.length * 5), L.length + ' open risk detection(s): ' + [...new Set(L.map((x) => RISK_TYPE[x.type] || x.type))].slice(0, 3).join(', '), 'detection');
  const failBy = {}; for (const s of signins) if (s.status === 'Failed' && s.upn) failBy[low(s.upn)] = (failBy[low(s.upn)] || 0) + 1;
  for (const [k, n] of Object.entries(failBy)) if (n >= 5 && P.has(k)) add(P.get(k).upn, '', 10, n + ' failed sign-ins in the collected window', 'signin');
  for (const p of P.values()) if (p.kinds.size >= 3) { p.score += 10; p.why.push({ points: 10, text: 'signals from ' + p.kinds.size + ' different sources agree' }); }
  out.people = [...P.values()].map((p) => ({ upn: p.upn, name: p.name, score: Math.min(100, p.score), level: p.score >= 60 ? 'high' : p.score >= 30 ? 'medium' : 'low', why: p.why, sources: [...p.kinds] })).sort((a, b) => b.score - a.score).slice(0, 200);
  // ---- chains: a detection and an alert on the same account within 24 hours
  out.chains = [];
  for (const x of det) { if (!x.upn) continue; const w = Date.parse(x.when); for (const a of alertBy[low(x.upn)] || []) { const g = Math.abs(Date.parse(a.created) - w); if (g <= DAY) out.chains.push({ upn: x.upn, detection: RISK_TYPE[x.type] || x.type, detected: x.when, alert: a.title, severity: low(a.severity), alerted: a.created, hours_apart: Math.round(g / 3600000 * 10) / 10 }); } }
  out.chains.sort((a, b) => a.hours_apart - b.hours_apart); out.chains = out.chains.slice(0, 50);
  // ---- KPIs and trend of the headline numbers
  out.kpis = { score_pct: out.score ? out.score.pct : null, mfa_pct: out.mfa ? out.mfa.pct : null, admins_no_mfa: out.mfa ? out.mfa.admins.length : null, risky_high: out.risky ? out.risky.high : null, risky_total: out.risky ? out.risky.total : null,
    detections_open: out.detections ? out.detections.open : null, alerts_open: out.alerts ? out.alerts.open : null, alerts_open_high: out.alerts ? out.alerts.open_high : null, ca_enabled: out.access ? out.access.enabled : null, chains: out.chains.length, people_high: out.people.filter((p) => p.level === 'high').length, not_read: missing.length };
  out.unusual = [];
  const last30 = H.filter((h) => h.day !== dayOf(t)).slice(-30);
  for (const [k, label, bad] of [['score_pct', 'Secure Score %', -1], ['mfa_pct', 'MFA coverage %', -1], ['risky_high', 'users at high risk', 1], ['alerts_open_high', 'open high-severity alerts', 1], ['detections_open', 'open risk detections', 1]]) {
    const z = robustZ(last30.map((h) => h[k]).filter((v) => v != null), out.kpis[k]);
    if (z != null && Math.abs(z) >= 3 && Math.sign(z) === bad) out.unusual.push({ metric: label, now: out.kpis[k], usual: median(last30.map((h) => h[k]).filter((v) => v != null)), z });
  }
  out.history = H.slice(-90).map((h) => ({ day: h.day, score_pct: h.score_pct, mfa_pct: h.mfa_pct, risky_high: h.risky_high, alerts_open_high: h.alerts_open_high }));
  // ---- what to do first
  const A = (p, title, detail, n, link, filter) => { if (n) out.actions.push({ priority: p, title, detail, count: n, link: LINK[link] || null, filter: filter || null }); };
  const hiP = out.people.filter((p) => p.level === 'high');
  A(100, (out.mfa ? out.mfa.admins.length : 0) + ' administrator account(s) without MFA', 'The highest-impact gap in the tenant: register MFA (or a phishing-resistant method) and enforce it with Conditional Access for every admin role.', out.mfa && out.mfa.admins.length, 'mfa', 'admins');
  A(95, out.chains.length + ' account(s) with a risk detection and a Defender alert within 24 hours', 'Treat each as one incident: confirm with the user, revoke sessions and reset the password if it was not them.', out.chains.length, 'alerts', 'chains');
  A(90, (out.risky ? out.risky.high : 0) + ' user(s) at high Entra ID risk', 'Confirm compromised or dismiss in Identity Protection; a confirmed account needs a password reset and session revoke.', out.risky && out.risky.high, 'risky', 'risky');
  A(85, (out.alerts ? out.alerts.open_high : 0) + ' open high-severity Defender alert(s)' + (out.alerts && out.alerts.oldest_open_days != null ? ' (oldest ' + out.alerts.oldest_open_days + ' days)' : ''), 'Assign and triage in the Defender portal; an alert left open is a detection nobody acted on.', out.alerts && out.alerts.open_high, 'alerts', 'alerts');
  A(80, out.access && !out.access.enabled ? 'No Conditional Access policy is enforced' : '', 'Every sign-in is decided by password alone. Enforce at least MFA for admins and block legacy authentication.', out.access && !out.access.enabled ? 1 : 0, 'ca', 'access');
  A(70, (out.access ? out.access.baseline.filter((b) => !b.found).length : 0) + ' baseline Conditional Access protection(s) not found by name', 'Check whether a policy covers each (the match is by name only); add the missing ones in report-only first, then enforce.', out.access && out.access.baseline.filter((b) => !b.found).length, 'ca', 'access');
  A(60, (out.access ? out.access.stale_report_only.length : 0) + ' Conditional Access policy(ies) in report-only for 30+ days', 'Report-only protects nothing: read its sign-in impact, then enforce or remove it.', out.access && out.access.stale_report_only.length, 'ca', 'access');
  A(55, hiP.length + ' person(s) where several signals agree', 'Look at these first: the score adds Entra ID risk, missing MFA, open alerts, detections and failed sign-ins.', hiP.length, null, 'people');
  A(50, (out.access ? out.access.recent_changes.length : 0) + ' Conditional Access policy(ies) changed in the last 7 days', 'Confirm each change was approved - a weakened policy is a common persistence step.', out.access && out.access.recent_changes.length, 'ca', 'access');
  A(45, (out.mfa ? out.mfa.not_registered : 0) + ' user(s) without MFA', 'Register them, or require registration through Conditional Access.', out.mfa && out.mfa.not_registered, 'mfa', 'mfa');
  A(40, out.score && out.score.weakest.length ? 'Secure Score ' + out.score.pct + '% - ' + out.score.weakest.length + ' weakest controls listed' : '', 'The weakest controls are where the points are; each opens in the Secure Score page.', out.score && out.score.pct != null && out.score.pct < 70 ? 1 : 0, 'score', 'score');
  for (const u of out.unusual) A(65, u.metric + ' moved to ' + u.now + ' (usual about ' + u.usual + ')', 'Far from the last 30 days (robust z ' + u.z + '). Find what changed.', 1, null, 'trend');
  A(30, missing.length + ' security dataset(s) not read from Microsoft Graph', 'Grant: ' + missing.map((c) => c.perm).filter(Boolean).join(' · ') + ' - then admin consent. Until then those parts read "not read", not zero.', missing.length, null, 'coverage');
  out.actions.sort((a, b) => b.priority - a.priority);
  out.note = 'Indicators for an analyst to confirm, not proof. Nothing here changes Microsoft 365 - each action opens the Microsoft page that does it. People are counted, not named, for viewers.';
  return out;
}
function sample(a, t) { const k = a.kpis; return { id: dayOf(t), day: dayOf(t), at: t, score_pct: k.score_pct, mfa_pct: k.mfa_pct, risky_high: k.risky_high, alerts_open_high: k.alerts_open_high, detections_open: k.detections_open }; }

function createM365Security({ graph, state, now } = {}) {
  const NOW = now || Date.now, col = state ? state.collection('m365_security_hist') : null;
  function compute() {
    const d = graph ? graph.data() : null, t = NOW(), a = analyse(d, col ? col.all() : [], t);
    if (col && a.configured && d.updated) { const s = sample(a, t), cur = col.get(s.id); if (!cur || cur.at < t - 3600000) { col.put(s); const all = col.all().sort((p, q) => p.day.localeCompare(q.day)); for (const x of all.slice(0, Math.max(0, all.length - 400))) col.remove(x.id); } }
    return a;
  }
  function view(role) {
    const a = compute(), named = (RANK[role] || 0) >= RANK.analyst;
    if (!named && a.configured) {   // PDPL: people are counted, not named
      a.people = { hidden: true, count: a.people.length, high: a.people.filter((p) => p.level === 'high').length };
      a.chains = { hidden: true, count: a.chains.length };
      if (a.mfa) { a.mfa.admins = { hidden: true, count: a.mfa.admins.length }; a.mfa.list = { hidden: true, count: a.mfa.not_registered }; }
      if (a.detections) a.detections.recent = { hidden: true, count: a.detections.recent.length };
      if (a.alerts) a.alerts.list = a.alerts.list.map((x) => Object.assign({}, x, { user: x.user ? '(hidden)' : '' }));
    }
    a.named = named;
    return a;
  }
  return { view, compute };
}

function register(api, deps) {
  const P = prefixOf(deps); if (!deps.m365Graph) return;
  const S = createM365Security({ graph: deps.m365Graph, state: deps.state });
  api.route('GET', `${P}/m365/security`, wrap(deps, null, (ctx) => {
    const v = S.view(String(ctx.role || '').toLowerCase());
    if (v.named && v.configured) audit(ctx, 'm365.security.read', 'microsoft-365', { people: v.people.length, chains: v.chains.length });
    return v;
  }));
}

module.exports = { register, analyse, createM365Security, RISK_TYPE, LINK };
