// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SharePoint & OneDrive insights (engine/collect/m365-files-insights.js) over a SYNTHETIC discovery result: exposure scored with every
// point named (category x sharing; sharing not read = unknown, not safe), sources ranked, files unchanged for 3 years, folders,
// actions ranked, the trend across runs with an unusual jump, coverage gaps said; viewers get counts only, an analyst's read is
// audited; no personal-data value is ever present.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const FI = require('../engine/collect/m365-files-insights');
const { CATEGORY } = require('../engine/pii/classify');

const T = Date.parse('2026-11-04T08:00:00Z'), D = 86400000, iso = (ms) => new Date(T - ms).toISOString();
const hit = (name, kinds, shared, ageDays, nameKinds) => ({ id: name, drive: 'd', name, path: '/HR/Payroll', size: 1000, modified: iso(ageDays * D), kinds, name_kinds: nameKinds || [], by: Object.keys(kinds).length ? 'content' : 'name', shared });
const SNAP = { at: '2026-11-04T07:00:00Z', sources: [
  { key: 'sp:hr', kind: 'sharepoint', label: 'HR (synthetic)', url: 'https://as.sharepoint.test/sites/hr', files_seen: 400, files_read: 300, files_skipped: 2, files_unreadable: 1, truncated: false, errors: [],
    hits: [hit('medical-claims.xlsx', { national_id: 12, mobile: 9 }, 'anonymous', 10, ['health']), hit('salaries-2022.csv', { iban: 40 }, 'organization', 4 * 365), hit('cv-list.docx', {}, null, 20, ['cv'])] },
  { key: 'od:u1', kind: 'onedrive', label: 'OneDrive: nora.syn@as.test', url: '', files_seen: 50, files_read: 40, truncated: true, errors: ['Files.Read.All not granted'],
    hits: [hit('passport-scan.pdf', {}, 'external', 30, ['passport'])] },
  { key: 'sp:it', kind: 'sharepoint', label: 'IT (synthetic)', files_seen: 100, files_read: 90, errors: [], hits: [] }] };

test('exposure itemised, sources ranked, retention, folders, actions', () => {
  const a = FI.analyse(SNAP, [], T, CATEGORY);
  const top = a.files[0];
  assert.equal(top.name, 'medical-claims.xlsx'); assert.equal(top.score, top.why.reduce((s, w) => s + w.points, 0));
  assert.ok(top.why.some((w) => /anyone with the link/.test(w.text)) && top.why.some((w) => /3 kinds/.test(w.text)) && top.why.some((w) => /health/.test(w.text)));
  assert.ok(a.files.find((f) => f.name === 'cv-list.docx').why.some((w) => /sharing not read - treated as unknown, not safe/.test(w.text)));
  assert.equal(a.sources[0].key, 'sp:hr', 'the site holding the most exposure first'); assert.equal(a.sources[0].exposed, 1);
  assert.ok(a.sources.find((s) => s.key === 'od:u1').coverage.truncated);
  assert.deepEqual([a.kpis.sensitive, a.kpis.anonymous, a.kpis.external, a.kpis.organization, a.kpis.unknown_sharing, a.kpis.old], [4, 1, 1, 1, 1, 1]);
  assert.equal(a.folders[0].folder, 'HR (synthetic) › /HR/Payroll'); assert.equal(a.folders[0].files, 3);
  assert.match(a.actions[0].title, /anonymous link/); assert.ok(a.actions.some((x) => /health or identity data shared outside/.test(x.title)) && a.actions.some((x) => /unchanged for 3 years/.test(x.title)) && a.actions.some((x) => /not fully read/.test(x.title)));
  assert.ok(!JSON.stringify(a).match(/\b1\d{9}\b/), 'no personal-data value anywhere');
});

test('credentials in files: scored as credentials, a shared credential listed near the top, counts only', () => {
  const s = JSON.parse(JSON.stringify(SNAP));
  s.sources[2].hits.push(hit('deploy.env', { api_key: 1, password: 2 }, 'anonymous', 5, ['secret_file']), hit('id_rsa', {}, 'none', 50, ['secret_file']));
  const a = FI.analyse(s, [], T, CATEGORY), f = a.files.find((x) => x.name === 'deploy.env');
  assert.deepEqual(f.categories, ['credentials']);
  assert.ok(f.why.some((w) => w.text === 'holds credentials (api_key, password, secret_file)' && w.points === 25), JSON.stringify(f.why));
  assert.ok(f.why.some((w) => w.text === '3 kinds of credentials in one file'));
  assert.ok(f.why.some((w) => /anyone with the link/.test(w.text)));
  assert.equal(f.score, 25 + 10 + 40 + 5);
  assert.deepEqual([a.kpis.credentials, a.kpis.credentials_shared], [2, 1]);
  const i = a.actions.findIndex((x) => /shared file\(s\) holding credentials/.test(x.title));
  assert.ok(i >= 0 && i <= 1, 'near the top: ' + JSON.stringify(a.actions.map((x) => x.title)));
  assert.equal(a.actions[i].title, '1 shared file(s) holding credentials (api_key, password, secret_file)'); assert.match(a.actions[i].detail, /^Treat each as leaked: rotate the key \/ password first, then remove it from the file/);
  assert.ok(a.actions.some((x) => /1 other file\(s\) holding credentials/.test(x.title)), 'the unshared one too');
  // mixed: personal data and a credential in one file reads naturally
  const m = FI.scoreFile({ kinds: { national_id: 3, api_key: 1 }, name_kinds: [], shared: 'none', by: 'content' }, CATEGORY);
  assert.ok(m.why.some((w) => w.text === 'holds identity data and credentials (national_id, api_key)'), JSON.stringify(m.why));
  assert.ok(m.why.some((w) => w.text === '2 kinds of personal data and credentials in one file'));
  // no credential: actions and text unchanged
  const plain = FI.analyse(SNAP, [], T, CATEGORY);
  assert.ok(!plain.actions.some((x) => /credentials/.test(x.title))); assert.equal(plain.kpis.credentials, 0);
});

test('trend: an unusual jump in exposed files against previous runs', () => {
  const hist = ['2026-10-01', '2026-10-08', '2026-10-15', '2026-10-22', '2026-10-29'].map((d) => ({ at: d + 'T07:00:00Z', exposed: 0, sensitive: 3 }));
  const s = JSON.parse(JSON.stringify(SNAP)); for (let i = 0; i < 6; i++) s.sources[0].hits.push(hit('leak-' + i + '.csv', { national_id: 5 }, 'anonymous', 1));
  const a = FI.analyse(s, hist, T, CATEGORY);
  assert.ok(a.trend.unusual && a.trend.unusual.exposed === 8, JSON.stringify(a.trend)); assert.ok(a.actions.some((x) => /Exposed files moved from about 0 to 8/.test(x.title)));
  assert.equal(FI.analyse(SNAP, hist.slice(0, 2), T, CATEGORY).trend.unusual, null, 'fewer than 4 previous runs: no verdict');
});

test('route: viewers counted, analysts named and audited, a sample per run kept', async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-fi-')) });
  const R = {}, audits = [];
  FI.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config: {}, log: { info() {}, warn() {}, error() {} }, m365Files: { data: () => SNAP } });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (role) => { const out = {}; const ctx = { role, user: 'nora.syn', body: {}, params: {}, query: {}, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d }), fail(c, m) { out.status = c; out.error = m; }, ok: (x) => x };
    const rv = await R['GET /api/soc/m365/files/insights'](ctx); return out.status ? out : { status: 200, body: rv }; };
  const v = (await call('viewer')).body;
  assert.ok(v.limited); assert.equal(v.files.length, 0); assert.equal(v.sources[0].label, undefined); assert.equal(v.kpis.anonymous, 1);
  assert.equal(audits.length, 0, 'a viewer read of counts is not a named read');
  const a = (await call('analyst')).body; assert.equal(a.files[0].name, 'medical-claims.xlsx'); assert.ok(audits.some((x) => x.a === 'm365.files.insights.read'));
  assert.equal(state.collection('m365_files_hist').all().length, 1, 'one sample per discovery run');
  // a credential in a shared file: viewers see the counts and the action, never the file name
  const C2 = JSON.parse(JSON.stringify(SNAP)); C2.at = '2026-11-04T07:30:00Z'; C2.sources[2].hits.push(hit('deploy.env', { api_key: 1 }, 'anonymous', 5, ['secret_file']));
  const R2 = {};
  FI.register({ route: (m, p, h) => { R2[m + ' ' + p] = h; } }, { config: {}, m365Files: { data: () => C2 } });
  const vctx = { role: 'viewer', user: 'v.syn', query: {}, need: () => true, audit: (x, t, d) => audits.push({ a: x, t, d }), fail() {} };
  const vv = await R2['GET /api/soc/m365/files/insights'](vctx);
  assert.equal(vv.kpis.credentials_shared, 1); assert.ok(vv.actions.some((x) => /holding credentials/.test(x.title))); assert.ok(!JSON.stringify(vv).includes('deploy.env'), 'no file name to a viewer');
  const actx = Object.assign({}, vctx, { role: 'analyst', user: 'nora.syn' });
  assert.ok((await R2['GET /api/soc/m365/files/insights'](actx)).files.some((f) => f.name === 'deploy.env'), 'analysts see where it lies'); await call('analyst'); assert.equal(state.collection('m365_files_hist').all().length, 1);
});
