// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SharePoint & OneDrive activity (engine/collect/m365-files-activity.js, GET {P}/m365/files/activity) over unified audit events:
// sharing scopes (anonymous, external guest / outside domain, organisation, internal), anonymous links used, a mass download against
// the user's own 14 days (and a heavy but usual downloader not flagged), after-hours activity as a change in the user's own share,
// the analyst role (viewer refused), validation naming the field, the audit record, the query the route asks for (real parser).
// SYNTHETIC events only.
const test = require('node:test');
const assert = require('node:assert/strict');
const A = require('../engine/collect/m365-files-activity');
const { parse } = require('../engine/api/query');
const { fakeApi } = require('./soc-fakes');

const H = 3600e3, DAY = 24 * H, NOW = Date.parse('2026-11-18T09:00:00Z');   // Wednesday 12:00 Riyadh
const e = (o) => Object.assign({ src_type: 'm365', host: 'sharepoint', user: 'syn.lina@corp.example', event_code: 'FileAccessed', ts: NOW - H, fields: { SourceFileName: 'report.xlsx', SiteUrl: 'https://tenant.example/sites/finance-syn' } }, o);

function world() {
  const ev = [];
  // the tenant: two internal users act
  ev.push(e({ user: 'syn.omar@corp.example' }));
  // sharing
  ev.push(e({ event_code: 'AnonymousLinkCreated', fields: { SourceFileName: 'payroll-syn.xlsx', SiteUrl: 'https://tenant.example/sites/hr-syn' } }));
  ev.push(e({ event_code: 'SharingInvitationCreated', fields: { SourceFileName: 'claims-syn.docx', TargetUserOrGroupName: 'partner@outside.example', TargetUserOrGroupType: 'Member' } }));
  ev.push(e({ event_code: 'SharingSet', fields: { SourceFileName: 'plan-syn.docx', TargetUserOrGroupName: 'guest_x#ext#@tenant.example', TargetUserOrGroupType: 'Guest' } }));
  ev.push(e({ event_code: 'CompanyLinkCreated', fields: { SourceFileName: 'memo-syn.docx' } }));
  ev.push(e({ event_code: 'SharingSet', fields: { SourceFileName: 'team-syn.docx', TargetUserOrGroupName: 'syn.omar@corp.example', TargetUserOrGroupType: 'Member' } }));
  for (let i = 0; i < 3; i++) ev.push(e({ event_code: 'AnonymousLinkUsed', user: 'anonymous', fields: { SourceFileName: 'payroll-syn.xlsx' } }));
  // mass download: syn.lina downloads 80 files in one hour, never more than 3 an hour before
  for (let d = 9; d <= 20; d++) for (let i = 0; i < 3; i++) ev.push(e({ event_code: 'FileDownloaded', ts: NOW - d * DAY + i * 60000 }));
  for (let i = 0; i < 80; i++) ev.push(e({ event_code: 'FileDownloaded', ts: NOW - 2 * H + i * 30000, fields: { SourceFileName: 'f' + i + '.pdf', SiteUrl: 'https://tenant.example/sites/hr-syn' } }));
  // a backup account that always downloads 100 an hour: not flagged
  for (let d = 8; d <= 20; d++) for (let i = 0; i < 100; i++) ev.push(e({ user: 'syn.backup@corp.example', event_code: 'FileSyncDownloadedFull', ts: NOW - d * DAY - i * 10000 }));
  for (let i = 0; i < 100; i++) ev.push(e({ user: 'syn.backup@corp.example', event_code: 'FileSyncDownloadedFull', ts: NOW - 3 * H - i * 10000 }));
  // after hours: syn.omar worked days only, now 25 actions at 23:00 Riyadh
  for (let d = 9; d <= 20; d++) { const wd = new Date(NOW - d * DAY + 3 * H).getUTCDay(); if (wd === 5 || wd === 6) continue; for (let i = 0; i < 5; i++) ev.push(e({ user: 'syn.omar@corp.example', ts: NOW - d * DAY + i * 60000 })); }   // working days only
  for (let i = 0; i < 25; i++) ev.push(e({ user: 'syn.omar@corp.example', ts: Date.parse('2026-11-17T20:00:00Z') + i * 60000 }));
  return ev;
}

test('activity: sharing scopes, anonymous use, mass download against the user\'s own history, after-hours change', () => {
  const r = A.analyse(world(), NOW, { days: 7 });
  const S = Object.fromEntries(r.sharing.map((x) => [x.file, x.scope]));
  assert.equal(S['payroll-syn.xlsx'], 'anonymous'); assert.equal(S['claims-syn.docx'], 'external', 'an address outside the tenant domains');
  assert.equal(S['plan-syn.docx'], 'external', 'a guest'); assert.equal(S['memo-syn.docx'], 'organisation'); assert.equal(S['team-syn.docx'], 'internal');
  assert.deepEqual(r.internal_domains, ['corp.example']);
  assert.equal(r.kpis.external, 3); assert.equal(r.anonymous_used[0].file, 'payroll-syn.xlsx'); assert.equal(r.kpis.anonymous_used, 3);
  assert.deepEqual(r.downloads.map((x) => x.user), ['syn.lina@corp.example']); assert.equal(r.downloads[0].files, 80); assert.equal(r.downloads[0].usual_max, 3);
  assert.match(r.downloads[0].why, /80 downloads in one hour against at most 3/);
  assert.deepEqual(r.after_hours.map((x) => x.user), ['syn.omar@corp.example']); assert.equal(r.after_hours[0].usual_pct, 0);
  assert.ok(r.series.length === 7 && r.series.reduce((a, s) => a + s.downloads, 0) >= 180);
});

test('route: analyst, days validated, audited, the query parses', async () => {
  const asked = []; const search = { fetchEvents: async (o) => { parse(o.q); asked.push(o); return world(); } };
  const api = fakeApi({ realRanks: true }); A.register(api, { search, config: {}, log: { warn() {}, error() {} }, now: () => NOW });
  let r = await api.call('GET', '/api/soc/m365/files/activity', { role: 'viewer' }); assert.equal(r.status, 403);
  r = await api.call('GET', '/api/soc/m365/files/activity?days=90', { role: 'analyst' }); assert.equal(r.status, 400); assert.match(r.body.error, /days must be/);
  r = await api.call('GET', '/api/soc/m365/files/activity?days=7', { role: 'analyst', user: 'syn.dpo' }); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.kpis.mass_downloads, 1); assert.equal(asked[0].from, NOW - 21 * DAY);
  assert.ok(api.audits.some((a) => a.action === 'm365.files.activity.read' && a.user === 'syn.dpo'));
});
