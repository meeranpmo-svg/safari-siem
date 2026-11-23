// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft 365 Security (engine/collect/m365-security.js) over a SYNTHETIC Graph snapshot: Secure Score with its weakest controls and
// trend; MFA with administrators first; risky users, detections by type and country; one score per person with every point named
// (risk + no MFA + open alert + detections + failed sign-ins agree); a detection and an alert within 24 h are one chain; Conditional
// Access with no enforced policy, report-only for 30+ days, changed this week and the baseline found by name only; open
// high-severity alerts and their age; a missing permission reads "not read" with the permission named, never 0; an unusual drop
// against the history; actions ranked; viewers get counts only and an analyst's read is audited; not connected says what to do.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const S = require('../engine/collect/m365-security');

const T = Date.parse('2026-11-04T08:00:00Z'), D = 86400000, iso = (ms) => new Date(T - ms).toISOString();
const ok = (data) => ({ ok: true, data });
function snap(over) {
  const blocks = { secureScore: { ok: true }, mfa: { ok: true }, riskyUsers: { ok: true }, riskDetections: { ok: true }, conditionalAccess: { ok: true }, defenderAlerts: { ok: true }, signins: { ok: true } };
  const d = { configured: true, updated: iso(0), blocks, signinsOk: true,
    signins: Array.from({ length: 6 }, (_, i) => ({ time: iso(i * 3600000), upn: 'omar.syn@as.test', status: 'Failed' })).concat([{ time: iso(0), upn: 'sara.syn@as.test', status: 'Success' }]),
    security: {
      secureScore: ok({ current: 41.5, max: 100, lowest: [{ name: 'MFARegistrationV2', cat: 'Identity', score: 0 }, { name: 'BlockLegacyAuthentication', cat: 'Identity', score: 0 }] }),
      mfa: ok({ users: 50, registered: 45, notRegistered: [{ name: 'Admin Syn', upn: 'admin.syn@as.test', admin: true }, { name: 'Omar Syn', upn: 'omar.syn@as.test', admin: false }, { name: 'X1', upn: 'x1.syn@as.test' }, { name: 'X2', upn: 'x2.syn@as.test' }, { name: 'X3', upn: 'x3.syn@as.test' }] }),
      riskyUsers: ok([{ name: 'Omar Syn', upn: 'omar.syn@as.test', level: 'high', state: 'atRisk' }, { name: 'Sara Syn', upn: 'sara.syn@as.test', level: 'low', state: 'atRisk' }]),
      riskDetections: ok([{ when: iso(5 * 3600000), upn: 'omar.syn@as.test', type: 'impossibleTravel', level: 'high', state: 'atRisk', ip: '198.51.100.7', city: 'Lagos', country: 'NG' },
        { when: iso(2 * D), upn: 'omar.syn@as.test', type: 'anonymizedIPAddress', level: 'medium', state: 'atRisk', country: 'NL' }, { when: iso(9 * D), upn: 'sara.syn@as.test', type: 'unfamiliarFeatures', level: 'low', state: 'dismissed', country: 'SA' }]),
      conditionalAccess: ok([{ name: 'Require MFA for administrators', state: 'enabledForReportingButNotEnforced', modified: iso(60 * D) }, { name: 'Block legacy authentication', state: 'disabled', modified: iso(2 * D) }]),
      defenderAlerts: ok([{ created: iso(2 * 3600000), title: 'Suspicious inbox forwarding <img src=x>', category: 'Exfiltration', severity: 'high', status: 'new', product: 'microsoftDefenderForOffice365', user: 'omar.syn@as.test' },
        { created: iso(10 * D), title: 'Malware detected', category: 'Malware', severity: 'high', status: 'inProgress', product: 'microsoftDefenderForEndpoint', user: '' }, { created: iso(20 * D), title: 'Old', category: 'Other', severity: 'low', status: 'resolved', product: 'x', user: 'sara.syn@as.test' }]),
    } };
  return Object.assign(d, over || {});
}

test('score, MFA, identity, chains, access, alerts, actions', () => {
  const a = S.analyse(snap(), [], T);
  assert.equal(a.score.pct, 41.5); assert.equal(a.score.weakest[0].control, 'MFARegistrationV2'); assert.match(a.score.trend.why, /needs 3 daily samples/);
  assert.equal(a.mfa.pct, 90); assert.deepEqual(a.mfa.admins.map((x) => x.upn), ['admin.syn@as.test']);
  assert.equal(a.risky.high, 1); assert.equal(a.detections.open, 2); assert.ok(a.detections.by_type.some((x) => x.type === 'Impossible travel'), 'detection types are named, not Graph codes'); assert.equal(a.detections.by_country[0].country, 'NG');
  const top = a.people[0]; assert.equal(top.upn, 'omar.syn@as.test'); assert.equal(top.level, 'high'); assert.equal(top.score, Math.min(100, top.why.reduce((s, w) => s + w.points, 0)));
  for (const re of [/Entra ID user risk high/, /no MFA registered/, /open Defender alert/, /open risk detection/, /6 failed sign-ins/, /sources agree/]) assert.ok(top.why.some((w) => re.test(w.text)), re.source);
  assert.ok(a.people.some((p) => p.upn === 'admin.syn@as.test' && /administrator without MFA/.test(p.why[0].text)), 'an admin without MFA is ranked even without other signals');
  assert.equal(a.chains.length, 1); assert.equal(a.chains[0].upn, 'omar.syn@as.test'); assert.equal(a.chains[0].hours_apart, 3);
  assert.equal(a.access.enabled, 0); assert.equal(a.access.stale_report_only[0].days, 60); assert.equal(a.access.recent_changes[0].name, 'Block legacy authentication');
  assert.equal(a.access.baseline.find((b) => b.id === 'admins-mfa').report_only, 'Require MFA for administrators'); assert.equal(a.access.baseline.find((b) => b.id === 'admins-mfa').found, null);
  assert.match(a.access.note, /by name only/);
  assert.equal(a.alerts.open, 2); assert.equal(a.alerts.open_high, 2); assert.equal(a.alerts.oldest_open_days, 10); assert.equal(a.alerts.list[0].severity, 'high');
  assert.match(a.actions[0].title, /administrator account\(s\) without MFA/); assert.ok(a.actions[0].link.startsWith('https://entra.microsoft.com/'));
  for (const re of [/risk detection and a Defender alert within 24 hours/, /high Entra ID risk/, /open high-severity Defender alert\(s\) \(oldest 10 days\)/, /No Conditional Access policy is enforced/, /report-only for 30\+ days/, /changed in the last 7 days/]) assert.ok(a.actions.some((x) => re.test(x.title)), re.source);
  assert.ok(a.actions.every((x) => x.link === null || /^https:\/\/(entra|security)\.microsoft\.com\//.test(x.link)), 'links are the fixed Microsoft pages only');
});

test('a missing permission reads "not read" with the permission named; not connected says what to do', () => {
  const d = snap(); d.blocks.defenderAlerts = { ok: false, perm: 'SecurityAlert.Read.All', error: 'permission not granted' }; d.security.defenderAlerts = { ok: false, perm: 'SecurityAlert.Read.All' };
  const a = S.analyse(d, [], T);
  assert.equal(a.alerts, undefined); assert.equal(a.kpis.alerts_open, null, 'not read, never 0'); assert.equal(a.chains.length, 0);
  const c = a.coverage.find((x) => x.key === 'defenderAlerts'); assert.equal(c.ok, false); assert.equal(c.perm, 'SecurityAlert.Read.All');
  assert.ok(a.actions.some((x) => /security dataset\(s\) not read/.test(x.title) && /SecurityAlert\.Read\.All/.test(x.detail)));
  const n = S.analyse({ configured: false }, [], T); assert.match(n.note, /not connected/);
});

test('trend: an unusual drop in Secure Score against the history', () => {
  const hist = Array.from({ length: 20 }, (_, i) => ({ day: new Date(T - (20 - i) * D + 3 * 3600000).toISOString().slice(0, 10), score_pct: 62 + (i % 2), mfa_pct: 90, risky_high: 0, alerts_open_high: 0, detections_open: 1 }));
  const a = S.analyse(snap(), hist, T);
  assert.ok(a.unusual.some((u) => u.metric === 'Secure Score %' && u.now === 41.5), JSON.stringify(a.unusual)); assert.ok(a.score.trend.per_week != null);
  assert.ok(a.actions.some((x) => /Secure Score % moved to 41\.5/.test(x.title)));
});

test('route: viewers counted, analysts named and audited, one sample a day', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-m365s-')) });
  const R = {}, audits = [], d = snap();
  S.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config: {}, log: { info() {}, warn() {}, error() {} }, m365Graph: { data: () => d } });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (role) => { const out = {}; const ctx = { role, user: 'nora.syn', body: {}, params: {}, query: {}, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, x) => audits.push({ a, t, x }), fail(c, m) { out.status = c; out.error = m; }, ok: (x) => x };
    const rv = await R['GET /api/soc/m365/security'](ctx); return out.status ? out : rv; };
  const v = await call('viewer');
  assert.equal(v.named, false); assert.equal(v.people.hidden, true); assert.ok(v.people.count >= 2); assert.equal(v.mfa.admins.count, 1); assert.equal(v.chains.count, 1);
  assert.ok(!JSON.stringify(v).includes('omar.syn'), 'no name for a viewer'); assert.equal(v.kpis.admins_no_mfa, 1);
  assert.equal(audits.length, 0);
  const a = await call('analyst'); assert.equal(a.people[0].upn, 'omar.syn@as.test'); assert.ok(audits.some((x) => x.a === 'm365.security.read'));
  assert.equal(state.collection('m365_security_hist').all().length, 1); await call('analyst'); assert.equal(state.collection('m365_security_hist').all().length, 1);
});
