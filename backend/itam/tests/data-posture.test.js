// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Data Security Posture (engine/data-posture.js) through the real routes on SYNTHETIC SIEM answers (tests/data-posture-fixtures.js:
// SharePoint / OneDrive / file shares, Azure stores, Shadow AI, Microsoft 365 security and directory) and local PDPL registers,
// database scans and an access review: every risk's count and measures, the score arithmetic (per item, capped per risk, why[]
// with its source), trend against the previous snapshot, the SIEM credentials summary winning over the capped file list,
// not_measured never counted as safe (provisional "based on N of M"), the 404 "SIEM not updated" cloud source, the empty state,
// roles (viewer counts only - no names; operator items; refused drill-down), validation naming the field, the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const DP = require('../engine/data-posture');
const F = require('./data-posture-fixtures');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
const T0 = Date.parse('2026-11-08T08:00:00Z');

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  if (o.pdpl !== false) e.app.addons.pdpl = require('../engine/pdpl').createPdpl(e.app, { now: () => T0 });
  if (o.local !== false) F.seedLocal(e.app, T0);
  const siem = o.siem === null ? undefined : (o.siem || F.fakeSiem(T0, o.fake || {}));
  const X = DP.registerDataPosture(e.app.srv, e.app, DP.createDataPosture(e.app, { now: () => T0, siem, noTimer: true }));
  const call = (m, p, who) => e.req(m, p, who);
  const audits = (a) => e.app.store.auditTail(300).filter((x) => x.action === a);
  return { e, X, siem, call, audits };
}
const risk = (v, k) => v.risks.find((r) => r.key === k);
const measure = (r, m) => (r.breakdown.find((b) => b.measure === m) || { count: 0 }).count;

test('data posture: every risk from the real sources, the score arithmetic, why[] with sources, trend', async (t) => {
  const s = await setup(t);
  s.e.app.store.collection('data_posture_hist').put({ id: '2026-11-07', at: '2026-11-07T08:00:00.000Z', score: 5, measured: 12, counts: { exposed: 1, privacy: 3 } });
  const r = await s.call('GET', '/data-posture', OP); assert.equal(r.status, 200, r.text);
  const v = r.json;
  // shadow data: HRDB-SYN (only an ARCHIVED activity names it), HR-Site-SYN, the file share, three Azure stores; CLAIMS-DB-SYN health not declared
  const sh = risk(v, 'shadow');
  assert.equal(measure(sh, 'undeclared_store'), 6); assert.equal(measure(sh, 'undeclared_category'), 1);
  assert.ok(sh.items.some((i) => i.store === 'HRDB-SYN') && sh.items.some((i) => i.store === 'HR-Site-SYN') && !sh.items.some((i) => /OneDrive/.test(i.store)), 'OneDrive is personal storage: not shadow data');
  assert.deepEqual(sh.items.find((i) => i.measure === 'undeclared_category').classes, ['health']);
  assert.equal(sh.deduction, 2); assert.equal(sh.capped, true, '6 x 0.5 + 0.1 = 3.1, capped at 2');
  // exposed: one anonymous link, one external share, one public Azure store; the unknown-public store is said, not safe
  const ex = risk(v, 'exposed');
  assert.deepEqual([measure(ex, 'anonymous'), measure(ex, 'external'), measure(ex, 'public_store')], [1, 1, 1]); assert.equal(ex.deduction, 1.5);
  assert.match(ex.note, /could not be read - unknown, not safe/);
  assert.equal(ex.items.find((i) => i.name === 'payroll-syn.xlsx').exposure, 95, 'the SIEM insights\' exposure score of the file');
  assert.ok(ex.items.some((i) => i.name === F.HOSTILE), 'a hostile file name is kept as data');
  assert.deepEqual(ex.trend, { previous: 1, delta: 2, previous_at: '2026-11-07T08:00:00.000Z' });
  // credentials: keys-syn shared organisation-wide, the OneDrive API key unshared, the password in the public store
  const cr = risk(v, 'credentials');
  assert.deepEqual([measure(cr, 'shared'), measure(cr, 'unshared')], [2, 1]); assert.equal(cr.deduction, 1.25); assert.equal(cr.shared, 2);
  assert.deepEqual(cr.by_kind.map((k) => k.kind).sort(), ['api_key', 'password', 'private_key', 'secret_file']);
  // localisation: westeurope store with personal data; a transfer with no basis, one without a signed TIA (the signed one is fine)
  const lo = risk(v, 'localisation');
  assert.deepEqual([measure(lo, 'outside_store'), measure(lo, 'no_basis'), measure(lo, 'no_tia')], [1, 1, 1]); assert.equal(lo.deduction, 1.5); assert.equal(lo.capped, false);
  // excessive: dormant Domain Admin undecided, 2 undecided in the overdue campaign, a removal not done, an admin without MFA, a stale guest
  const xs = risk(v, 'excessive');
  assert.deepEqual(['priv_dormant', 'undecided', 'removal_open', 'admin_no_mfa', 'stale_guest'].map((m) => measure(xs, m)), [1, 2, 1, 1, 1]);
  assert.equal(xs.deduction, 0.46); assert.equal(xs.campaign.overdue, true); assert.deepEqual(xs.guests, { total: 2, judged: 2 });
  assert.ok(xs.items.some((i) => i.name === 'admin.syn@example.invalid') && xs.items.some((i) => i.name === 'old.admin.syn'));
  // misplaced: passport in OneDrive, a file unchanged 1200 days, health shared organisation-wide, salaries readable by everyone
  const mp = risk(v, 'misplaced');
  assert.deepEqual(['onedrive_strong', 'old', 'general_sensitive'].map((m) => measure(mp, m)), [1, 1, 2]); assert.equal(mp.deduction, 0.27);
  // privacy: ChatGPT received personal data it is not allowed (Copilot is allowed personal: not counted); an open breach; a DLP alert
  const pv = risk(v, 'privacy');
  assert.deepEqual(['ai_leak', 'breach_open', 'breach_subjects', 'dlp_alert'].map((m) => measure(pv, m)), [1, 1, 0, 1]); assert.equal(pv.deduction, 1.5);
  assert.equal(pv.items.find((i) => i.measure === 'ai_leak').store, 'ChatGPT');
  assert.equal(pv.trend.delta, 0);
  // the score: 10 - (2 + 1.5 + 1.25 + 1.5 + 0.46 + 0.27 + 1.5) = 1.52 -> 1.5, Poor, 12 of 12 sources
  assert.equal(v.score.deducted, 8.48); assert.equal(v.score.value, 1.5); assert.equal(v.score.label, 'Poor');
  assert.deepEqual(v.score.based_on, { measured: 12, of: 12, text: 'based on 12 of 12 sources' }); assert.equal(v.score.provisional, false);
  assert.equal(Math.round(-v.score.why.filter((w) => w.source !== 'cap').reduce((a, w) => a + w.points, 0) * 100) / 100, 9.58, 'why[] adds up to the raw deductions');
  assert.ok(v.score.why.every((w) => w.source && w.text), 'every deduction says its source');
  assert.ok(v.score.why.some((w) => w.risk === 'shadow' && w.source === 'cap' && /capped at 2/.test(w.text)));
  assert.equal(v.score.trend.previous, 5); assert.deepEqual(v.not_measured, []);
  // stores, scan status, classes
  const ty = Object.fromEntries(v.stores.types.map((x) => [x.type, x]));
  assert.equal(ty.sharepoint.count, 1); assert.equal(ty.onedrive.count, 1); assert.equal(ty.fileshare.count, 1); assert.equal(ty['cloud:azure'].count, 3); assert.equal(ty['cloud:azure'].label, 'Azure storage accounts');
  assert.equal(ty['db:oracle'].count, 1); assert.equal(ty['db:mssql'].count, 1); assert.equal(v.stores.file_servers, 1);
  assert.match(v.stores.teams_note, /Teams files are counted in their SharePoint site/);
  assert.equal(v.stores.types[0].type, 'sharepoint', 'Microsoft 365 first');
  const ss = Object.fromEntries(v.scan_status.map((x) => [x.source, x]));
  assert.equal(ss.m365_files.state, 'scanned'); assert.equal(ss['cloud:azure'].state, 'scanned'); assert.equal(ss['cloud:aws'].state, 'not_connected'); assert.equal(ss.databases.state, 'scanned');
  assert.ok(ss.m365_files.items.length === 2, 'operators see which sites were read');
  assert.ok(v.classes[0].weight >= v.classes[v.classes.length - 1].weight, 'ordered by sensitivity');
  assert.equal(v.classes.find((c) => c.kind === 'national_id').count, 1 + 2 + 1, 'files + objects + columns');
  // the snapshot for today is kept for tomorrow's trend
  assert.equal(s.e.app.store.collection('data_posture_hist').get('2026-11-08').counts.exposed, 3);
  // the SIEM was read as the person, with the analyst role
  assert.ok(s.siem.calls.every((c) => c.who.user === OP.user && c.who.role === 'analyst'));
});

test('data posture: the SIEM credentials summary wins over the capped file list', async (t) => {
  const s = await setup(t, { fake: { credSummary: { files: 7, by_kind: { password: 5, api_key: 2 }, shared: 3 } } });
  const cr = risk((await s.call('GET', '/data-posture', OP)).json, 'credentials');
  assert.deepEqual([measure(cr, 'shared'), measure(cr, 'unshared')], [3 + 1, 4], 'summary 3 shared / 4 not, + the password in the public store');
  assert.equal(cr.deduction, 1.5, '4 x 0.5 + 4 x 0.25 = 3, capped at 1.5');
  assert.equal(cr.by_kind.find((k) => k.kind === 'password').count, 6); assert.deepEqual(cr.siem_summary, { files: 7, by_kind: { password: 5, api_key: 2 }, shared: 3 });
});

test('data posture: a source that is not connected is not measured - never safe; the SIEM not updated is said', async (t) => {
  // only the Shadow AI register and signals answer: privacy is measured from them, everything else is not measured
  const s = await setup(t, { pdpl: false, local: false, fake: { only: ['/shadow-ai/register', '/shadow-ai/signals?hours=720'] } });
  const v = (await s.call('GET', '/data-posture', OP)).json;
  assert.equal(v.score.based_on.measured, 1); assert.equal(v.score.based_on.of, 12); assert.equal(v.score.provisional, true);
  assert.equal(v.score.deducted, 0.25); assert.equal(v.score.value, 9.8, '10 - the one AI leak (0.25), shown to one decimal: the unmeasured risks deduct nothing');
  for (const k of ['shadow', 'exposed', 'credentials', 'localisation', 'excessive', 'misplaced']) { const r = risk(v, k); assert.equal(r.measured, false, k); assert.equal(r.count, null, k + ' has no count, not 0'); assert.equal(r.deduction, 0); assert.ok(r.missing.length && r.missing.every((m) => m.connect), k + ' says what to connect'); }
  assert.equal(risk(v, 'privacy').measured, true);
  const cl = v.not_measured.find((x) => x.key === 'cloud'); assert.match(cl.reason, /SIEM is not updated yet.*cloud-data\/stores.*404/);
  assert.equal(v.not_measured.length, 11);
  assert.ok(v.not_measured.find((x) => x.key === 'ropa').connect.includes('PDPL'));
  // nothing at all: no score, the empty state says what to connect
  const s2 = await setup(t, { pdpl: false, local: false, siem: null });
  const v2 = (await s2.call('GET', '/data-posture', VIEW)).json;
  assert.equal(v2.score.value, null); assert.equal(v2.score.label, 'Not measured'); assert.match(v2.empty, /Nothing is connected yet/);
  assert.match(v2.not_measured.find((x) => x.key === 'm365_files').reason, /no link to the SIEM/);
  assert.ok(v2.risks.every((r) => r.count === null));
  // a SIEM that fails: stated, logged once with context
  const s3 = await setup(t, { pdpl: false, local: false, fake: { fail: true } });
  const v3 = (await s3.call('GET', '/data-posture', OP)).json;
  assert.match(v3.not_measured.find((x) => x.key === 'm365_security').reason, /not reachable: synthetic SIEM outage/);
  assert.ok(s3.e.logs.some((l) => /SIEM is not reachable/.test(l[1]) && l[2].path));
});

test('data posture: roles, validation and audit', async (t) => {
  const s = await setup(t);
  // viewer: counts only - no file, site, bucket, server or person name anywhere in the answer
  const vr = await s.call('GET', '/data-posture', VIEW); assert.equal(vr.status, 200, vr.text);
  assert.equal(vr.json.named, false); assert.ok(vr.json.risks.every((r) => !r.items), 'no items for viewers');
  for (const n of ['payroll-syn', 'HR-Site-SYN', 'alia.syn', 'admin.syn', 'FS-SYN-01', 'claimsdocssyn', 'HRDB-SYN', 'old.admin.syn', 'guest1-syn', 'BR-SYN-1', 'Reinsurer SYN']) assert.ok(!vr.text.includes(n), 'viewer answer has no ' + n);
  assert.ok(vr.json.scan_status.every((x) => !x.items));
  assert.equal(s.audits('data.posture.read').length, 0, 'a counts-only read is not a named read');
  // operator: names, audited
  const o = await s.call('GET', '/data-posture?evil=1', OP); assert.equal(o.status, 200, 'undeclared query fields are dropped');
  const a = s.audits('data.posture.read').pop(); assert.equal(a.by, 'nora.syn'); assert.equal(a.role, 'operator'); assert.ok(a.detail.items > 0);
  // drill-down: operator / admin only; the key and limit are validated
  assert.equal((await s.call('GET', '/data-posture/risks/exposed', VIEW)).status, 403, 'a viewer is refused the names');
  let r = await s.call('GET', '/data-posture/risks/exposed', ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.total, 3); assert.equal(r.json.items.length, 3);
  const d = s.audits('data.posture.risk.read').pop(); assert.equal(d.by, 'syed'); assert.equal(d.role, 'admin'); assert.equal(d.target, 'exposed'); assert.equal(d.detail.items, 3);
  r = await s.call('GET', '/data-posture/risks/exposed?limit=1', OP); assert.equal(r.json.items.length, 1); assert.equal(r.json.truncated, true);
  r = await s.call('GET', '/data-posture/risks/everything', OP); assert.equal(r.status, 400); assert.match(r.text, /key must be one of: shadow, exposed/);
  r = await s.call('GET', '/data-posture/risks/bad%20key', OP); assert.equal(r.status, 400); assert.match(r.text, /key is not a valid id/);
  r = await s.call('GET', '/data-posture/risks/exposed?limit=0', OP); assert.equal(r.status, 400); assert.match(r.text, /limit must be at least 1/);
  r = await s.call('GET', '/data-posture/risks/exposed?limit=many', OP); assert.equal(r.status, 400); assert.match(r.text, /limit must be a whole number/);
  r = await s.call('GET', '/data-posture/risks/exposed?limit=900', OP); assert.equal(r.status, 400); assert.match(r.text, /limit must be at most 500/);
});

test('data posture: registered by the duty desk, with nothing connected it still answers', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true, now: () => T0, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => ({ ok: true, assets: [] }), acovAvail: async () => ({ ok: true, hosts: {} }) });
  assert.ok(e.app.addons.dataPosture && e.app.addons.aiLineage, 'both modules registered');
  const r = await e.req('GET', '/data-posture', { user: 'vera.syn', role: 'viewer' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.score.based_on.of, 12); assert.ok(r.json.not_measured.some((x) => x.key === 'cloud'));
  assert.ok(!r.json.not_measured.some((x) => ['ropa', 'transfers', 'breaches'].includes(x.key)), 'the PDPL registers are installed by the duty desk');
});
