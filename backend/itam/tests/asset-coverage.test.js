// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Coverage & Query (engine/asset-coverage.js) through the real routes on SYNTHETIC assets: each control's state from its source
// (EDR from installed software incl. an out-of-date version, Endpoint Central, backup, Greenbone, SIEM log coverage), NOT CHECKED
// when a source is not connected, priority by criticality, the query language (and its 400s), exemptions (admin, reason, end date),
// saved queries + schedule + on-change delivery through the relay, and the four-eyes Action Center (requester never approves, an AI
// identity never approves, viewer refused, audited, per-asset results).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { parseQuery, vcmp } = require('../engine/asset-coverage');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:asset-analyst', role: 'admin' };
const T0 = Date.parse('2026-11-05T08:00:00Z'), DAY = 86400000;

async function setup(t, o = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let now = T0; const mail = [];
  const logCov = o.noSiem ? async () => ({ ok: false, error: 'SIEM not reachable (synthetic)' }) : async () => ({ ok: true, assets: [] });
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => now, python: process.env.PYTHON || 'python3', acovLogCoverage: async () => { const r = await logCov(); if (r.ok) r.assets = (e._siem || []); return r; },
    acovAvail: async () => (o.noSiem ? { ok: false, error: 'SIEM not reachable (synthetic)' } : { ok: true, hosts: e._avail || {} }),
    acovSiem: async (m, p, b, user) => { mail.push(Object.assign({}, b, { _path: p, _user: user })); return { ok: true }; } });
  const col = e.app.store.collection('assets');
  const mk = (x) => { const extra = { criticality: x.criticality, software: x.software, sources: x.sources }; delete x.criticality; delete x.software; delete x.sources;
    const id = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id;
    const cur = col.get(id); col.put(Object.assign({}, cur, Object.fromEntries(Object.entries(extra).filter(([, v]) => v !== undefined)))); return id; };
  const fresh = [{ source: 'agent', last_seen: new Date(T0 - DAY).toISOString() }];
  const id = {
    db: mk({ name: 'DB-SYN-1', mgmt_ip: '10.70.1.10', criticality: 'critical', software: [{ name: 'Kaspersky Endpoint Security for Windows', version: '12.1' }], sources: fresh }),
    app: mk({ name: 'APP-SYN-1', mgmt_ip: '10.70.1.11', criticality: 'high', software: [{ name: 'Kaspersky Endpoint Security for Windows', version: '12.6' }], sources: fresh }),
    web: mk({ name: 'WEB-SYN-1', mgmt_ip: '10.70.1.12', criticality: 'low', software: [{ name: 'Notepad++', version: '8' }], sources: fresh }),
    bare: mk({ name: 'NEW-SYN-1', mgmt_ip: '10.70.1.13' }),
    sw: mk({ name: 'SW-SYN-1', type: 'network', mgmt_ip: '10.70.1.1' }),
  };
  e._avail = { '10.70.1.10': { s: 'online', since: T0 - 30 * DAY }, '10.70.1.11': { s: 'offline', since: T0 - 3600000 } };
  e._siem = [{ asset_id: id.db, status: 'covered', last_seen: new Date(T0).toISOString() }, { asset_id: id.app, status: 'silent' }, { asset_id: id.sw, status: 'absent' }];
  e.app.store.collection('me_ec_computers').put({ id: 'ec1', name: 'DB-SYN-1', asset_id: id.db, last_contact: T0 - DAY, critical: 0, missing: 2, agent_version: '11.3' });
  e.app.store.collection('me_ec_computers').put({ id: 'ec2', name: 'APP-SYN-1', last_contact: T0 - 20 * DAY, critical: 0 });
  e.app.store.collection('vulnscan_results').put({ id: 's1', hosts: ['10.70.1.10'], at: new Date(T0 - 10 * DAY).toISOString() });
  e.app.store.collection('vulnscan_results').put({ id: 's2', hosts: ['10.70.1.11', '10.70.1.1'], at: new Date(T0 - 200 * DAY).toISOString() });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, id, call, mail, setNow: (x) => { now = x; } };
}

test('query language: parsing and its errors', () => {
  assert.equal(parseQuery('type:server,vm edr:missing gaps>0 -site:DR os~2012 SRV-1').length, 6);
  assert.throws(() => parseQuery('colour:red'), /unknown field "colour"/);
  assert.throws(() => parseQuery('edr:maybe'), /edr takes present/);
  assert.throws(() => parseQuery('site>3'), /not a number field/);
  assert.throws(() => parseQuery('x'.repeat(501)), /longer than 500/);
  assert.throws(() => parseQuery(Array.from({ length: 21 }, (_, i) => 'w' + i).join(' ')), /more than 20 terms/);
  assert.equal(vcmp('12.10', '12.9'), 1); assert.equal(vcmp('12.1', '12.6'), -1);
});

test('coverage per control from its source, not-checked when unconnected, priority by criticality', async (t) => {
  const { call, id } = await setup(t);
  const r = await call('GET', '/asset-coverage', undefined, VIEW); assert.equal(r.status, 200, r.text); const v = r.json;
  const A = (x) => v.assets.find((a) => a.id === x);
  assert.equal(A(id.db).controls.edr.state, 'weak', 'Kaspersky 12.1 is older than the 12.6 on another server'); assert.match(A(id.db).controls.edr.why, /older than 12\.6/);
  assert.equal(A(id.app).controls.edr.state, 'present'); assert.equal(A(id.web).controls.edr.state, 'missing');
  assert.equal(A(id.bare).controls.edr.state, 'not_checked', 'no software inventory: not checked, never missing');
  assert.equal(A(id.sw).controls.edr.state, 'na', 'EDR does not apply to a switch');
  assert.equal(A(id.db).controls.patch.state, 'present'); assert.equal(A(id.app).controls.patch.state, 'weak', 'matched by name, last contact 20 days ago'); assert.equal(A(id.web).controls.patch.state, 'missing');
  assert.equal(A(id.db).controls.backup.state, 'not_checked'); assert.match(A(id.db).controls.backup.why, /no backup platform/);
  assert.equal(A(id.db).controls.vuln_scan.state, 'present'); assert.equal(A(id.app).controls.vuln_scan.state, 'weak'); assert.equal(A(id.web).controls.vuln_scan.state, 'missing');
  assert.equal(A(id.db).controls.siem_logs.state, 'present'); assert.equal(A(id.app).controls.siem_logs.state, 'weak'); assert.equal(A(id.sw).controls.siem_logs.state, 'missing');
  assert.equal(A(id.db).priority, 4 * (0 * 2 + 1), 'critical: one weak control (monitored and online)'); assert.equal(A(id.bare).criticality, 'unrated');
  assert.equal(v.summary.per_control.edr.missing, 1); assert.equal(v.summary.per_control.backup.coverage_pct, null, 'not measured, never 0%');
  assert.ok(v.assets.findIndex((a) => a.id === id.app) < v.assets.findIndex((a) => a.id === id.web), 'high with 2 weak + 1 missing ranks above low');
  const one = await call('GET', '/asset-coverage/asset/' + id.db, undefined, VIEW); assert.equal(one.status, 200); assert.equal(one.json.asset.name, 'DB-SYN-1');
  assert.equal((await call('GET', '/asset-coverage/asset/bad%24id', undefined, VIEW)).status, 400);
});

test('vulnerability scan coverage across Greenbone, Tenable (clean hosts too) and FireCompass, the tool named', async (t) => {
  const { call, id, e } = await setup(t);
  e.app.store.collection('vapt_scanned').put({ id: 'tenable|1', vendor: 'tenable', tool: 'Nessus', ips: ['10.70.1.12'], names: ['web-syn-1.syn.local'], at: new Date(T0 - 3 * DAY).toISOString() });
  e.app.store.collection('vapt_scanned').put({ id: 'tenable|2', vendor: 'tenable', tool: 'Nessus', ips: ['10.70.1.10'], names: [], at: new Date(T0 - DAY).toISOString() });
  e.app.store.collection('fc_findings').put({ id: 'fc1', vendor: 'firecompass', host: 'new-syn-1', asset: 'new-syn-1.syn.example', title: 'TLS 1.0 enabled', last_imported: new Date(T0 - 2 * DAY).toISOString() });
  const v = (await call('GET', '/asset-coverage', undefined, VIEW)).json, A = (x) => v.assets.find((a) => a.id === x).controls.vuln_scan;
  assert.equal(A(id.web).state, 'present', 'Tenable scanned it and found nothing: covered'); assert.match(A(id.web).why, /by Nessus/);
  assert.match(A(id.db).why, /by Nessus/, 'the newest scan wins: Nessus yesterday over Greenbone 10 days ago');
  assert.equal(A(id.bare).state, 'present', 'a FireCompass finding matched by host name'); assert.match(A(id.bare).why, /FireCompass/);
  assert.equal(A(id.app).state, 'weak', 'still only the 200-day-old Greenbone scan'); assert.match(A(id.app).why, /Greenbone/);
  assert.match(v.controls.vuln_scan.source, /Tenable/);
  const q = (await call('GET', '/asset-coverage/query?q=' + encodeURIComponent('vuln_scan:present'), undefined, VIEW)).json; assert.ok(q.rows.some((r) => r.id === id.web));
});

test('vulnerability scan: no scanner read at all = not checked', async (t) => {
  const { call, id, e } = await setup(t);
  for (const r of e.app.store.collection('vulnscan_results').all()) e.app.store.collection('vulnscan_results').remove(r.id);
  const a = (await call('GET', '/asset-coverage', undefined, VIEW)).json.assets.find((x) => x.id === id.db).controls.vuln_scan;
  assert.equal(a.state, 'not_checked'); assert.match(a.why, /Greenbone, Tenable or FireCompass/);
});

test('availability monitoring from Server Availability: online / offline / not monitored / no IP / SIEM down', async (t) => {
  const { call, id, e } = await setup(t);
  const nip = e.app.assets.create({ name: 'NOIP-SYN-1', type: 'server', status: 'in_use', site: 'HQ' }, ADM).asset.id;
  const v = (await call('GET', '/asset-coverage', undefined, VIEW)).json, A = (x) => v.assets.find((a) => a.id === x).controls.monitoring;
  assert.equal(A(id.db).state, 'present'); assert.match(A(id.db).why, /online since/);
  assert.equal(A(id.app).state, 'weak'); assert.match(A(id.app).why, /not answering since/);
  assert.equal(A(id.web).state, 'missing'); assert.match(A(id.web).why, /not monitored by Server Availability \(10\.70\.1\.12\)/);
  assert.equal(A(nip).state, 'missing'); assert.match(A(nip).why, /no IP address/);
  assert.equal(A(id.sw).state, 'missing', 'network devices are monitored too');
  assert.equal(v.summary.per_control.monitoring.present, 1);
  const q = (await call('GET', '/asset-coverage/query?q=' + encodeURIComponent('type:server monitoring:missing'), undefined, VIEW)).json; assert.ok(q.rows.some((r) => r.id === id.web) && !q.rows.some((r) => r.id === id.db));
});

test('SIEM unreachable = not checked, said with the reason', async (t) => {
  const { call, id } = await setup(t, { noSiem: true });
  const v = (await call('GET', '/asset-coverage', undefined, VIEW)).json;
  const a = v.assets.find((x) => x.id === id.sw); assert.equal(a.controls.siem_logs.state, 'not_checked'); assert.match(a.controls.siem_logs.why, /synthetic/);
  assert.equal(v.sources.siem_logs.ok, false); assert.equal(a.controls.monitoring.state, 'not_checked'); assert.equal(v.sources.monitoring.ok, false);
});

test('query route: results, 400 naming the field, limit checked', async (t) => {
  const { call, id } = await setup(t);
  let r = await call('GET', '/asset-coverage/query?q=' + encodeURIComponent('type:server edr:gap'), undefined, VIEW); assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.rows.map((x) => x.id).sort(), [id.db, id.web].sort());
  r = await call('GET', '/asset-coverage/query?q=' + encodeURIComponent('criticality:critical,high siem_logs:present'), undefined, VIEW); assert.deepEqual(r.json.rows.map((x) => x.id), [id.db]);
  r = await call('GET', '/asset-coverage/query?q=' + encodeURIComponent('name:*-syn-1 -type:network gaps>=2'), undefined, VIEW); assert.ok(r.json.rows.every((x) => x.type !== 'network' && x.gaps >= 2));
  r = await call('GET', '/asset-coverage/query?q=' + encodeURIComponent('10.70.1.13'), undefined, VIEW); assert.deepEqual(r.json.rows.map((x) => x.id), [id.bare], 'a bare word matches an address');
  r = await call('GET', '/asset-coverage/query?q=colour:red', undefined, VIEW); assert.equal(r.status, 400); assert.match(r.text, /colour/);
  r = await call('GET', '/asset-coverage/query?q=type:server&limit=0', undefined, VIEW); assert.equal(r.status, 400); assert.match(r.text, /limit/);
  assert.equal((await call('GET', '/asset-coverage/fields', undefined, VIEW)).status, 200);
});

test('exemptions: admin only, reason and end date required, audited, take the control out of the gaps', async (t) => {
  const { call, id, e } = await setup(t);
  const b = { asset_id: id.web, control: 'edr', reason: 'appliance image, vendor forbids agents', until: '2027-03-01' };
  assert.equal((await call('POST', '/asset-coverage/exempt', b, OP)).status, 403);
  let r = await call('POST', '/asset-coverage/exempt', Object.assign({}, b, { reason: '' }), ADM); assert.equal(r.status, 400); assert.match(r.text, /reason/);
  r = await call('POST', '/asset-coverage/exempt', Object.assign({}, b, { until: '2029-01-01' }), ADM); assert.equal(r.status, 400); assert.match(r.text, /within a year/);
  r = await call('POST', '/asset-coverage/exempt', Object.assign({}, b, { control: 'antivirus' }), ADM); assert.equal(r.status, 400); assert.match(r.text, /control/);
  r = await call('POST', '/asset-coverage/exempt', b, ADM); assert.equal(r.status, 200, r.text);
  const v = (await call('GET', '/asset-coverage', undefined, VIEW)).json; assert.equal(v.assets.find((x) => x.id === id.web).controls.edr.state, 'exempt');
  assert.ok(e.app.store.auditTail(50).some((x) => x.action === 'asset.coverage.exempt' && x.by === 'syed' && x.detail.until === '2027-03-01'));
});

test('saved queries + schedule: operator saves, admin schedules, on-change delivery, recipients hidden from viewers', async (t) => {
  const { call, mail, setNow, e, id } = await setup(t);
  assert.equal((await call('POST', '/asset-coverage/queries', { name: 'Servers without EDR', q: 'type:server edr:missing' }, VIEW)).status, 403);
  let r = await call('POST', '/asset-coverage/queries', { name: 'Bad', q: 'colour:red' }, OP); assert.equal(r.status, 400); assert.match(r.text, /colour/);
  r = await call('POST', '/asset-coverage/queries', { name: 'Servers without EDR', q: 'type:server edr:missing', team: 'Desktop & Endpoint' }, OP); assert.equal(r.status, 200, r.text); const qid = r.json.query.id;
  assert.equal((await call('POST', '/asset-coverage/queries/' + qid + '/schedule', { enabled: true, recipients: ['team@example.test'] }, OP)).status, 403, 'scheduling e-mail is admin');
  r = await call('POST', '/asset-coverage/queries/' + qid + '/schedule', { enabled: true, recipients: ['not-an-address'] }, ADM); assert.equal(r.status, 400); assert.match(r.text, /recipients/);
  r = await call('POST', '/asset-coverage/queries/' + qid + '/schedule', { enabled: true, period: 'daily', at: '07:30', recipients: ['team@example.test'], mode: 'on_change' }, ADM); assert.equal(r.status, 200, r.text);
  const vq = (await call('GET', '/asset-coverage/queries', undefined, VIEW)).json.queries.find((x) => x.id === qid); assert.equal(vq.schedule.recipients, undefined); assert.equal(vq.schedule.recipient_count, 1);
  const C = e.app.addons.assetCoverage;
  setNow(T0 + DAY); await C.tick(); assert.equal(mail.length, 1, 'first run sends');
  // the SIEM relay only accepts system:itam-report-center / system:itam-notify - any other caller is refused with 403
  assert.equal(mail[0]._path, '/reports/deliver'); assert.equal(mail[0]._user, 'system:itam-notify', 'sent as a caller the SIEM relay accepts'); assert.match(mail[0].subject, /1 asset/); assert.match(mail[0].attachments[0].content, /WEB-SYN-1/);
  setNow(T0 + 2 * DAY); await C.tick(); assert.equal(mail.length, 1, 'nothing changed: not sent again');
  e.app.store.collection('assets').put(Object.assign({}, e.app.store.collection('assets').get(id.app), { software: [{ name: 'Notepad++' }] }));
  setNow(T0 + 3 * DAY); await C.tick(); assert.equal(mail.length, 2, 'an asset entered the result: sent'); assert.match(mail[1].text, /New since the last run: 1 - APP-SYN-1/);
  assert.ok((await call('GET', '/asset-coverage/queries', undefined, ADM)).json.runs.some((x) => x.status === 'unchanged'));
  assert.equal((await call('POST', '/asset-coverage/queries/' + qid + '/delete', undefined, OP2)).status, 403, 'another operator cannot delete it');
  assert.equal((await call('POST', '/asset-coverage/queries/' + qid + '/delete', undefined, OP)).status, 200);
});

test('Action Center: four-eyes, AI refused, viewer refused, validated, per-asset results, audited', async (t) => {
  const { call, id, e } = await setup(t);
  const b = { kind: 'set_owner', q: 'type:server edr:missing', owner: 'Synthetic Infra Team', reason: 'owner missing on servers without EDR' };
  assert.equal((await call('POST', '/asset-coverage/actions', b, VIEW)).status, 403);
  let r = await call('POST', '/asset-coverage/actions', Object.assign({}, b, { owner: undefined }), OP); assert.equal(r.status, 400); assert.match(r.text, /owner or department/);
  r = await call('POST', '/asset-coverage/actions', Object.assign({}, b, { kind: 'reboot' }), OP); assert.equal(r.status, 400); assert.match(r.text, /kind/);
  r = await call('POST', '/asset-coverage/actions', Object.assign({}, b, { reason: 'short' }), OP); assert.equal(r.status, 400); assert.match(r.text, /reason/);
  r = await call('POST', '/asset-coverage/actions', b, OP); assert.equal(r.status, 200, r.text); const aid = r.json.action.id; assert.deepEqual(r.json.action.asset_ids, [id.web]);
  assert.equal((await call('POST', '/asset-coverage/actions/' + aid + '/approve', undefined, OP)).status, 403, 'the requester never approves');
  assert.equal((await call('POST', '/asset-coverage/actions/' + aid + '/approve', undefined, BOT)).status, 403, 'an AI identity never approves');
  assert.equal((await call('POST', '/asset-coverage/actions/' + aid + '/approve', undefined, VIEW)).status, 403);
  r = await call('POST', '/asset-coverage/actions/' + aid + '/approve', undefined, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.action.status, 'done'); assert.equal(e.app.store.collection('assets').get(id.web).owner, 'Synthetic Infra Team');
  assert.equal((await call('POST', '/asset-coverage/actions/' + aid + '/approve', undefined, ADM)).status, 409, 'decided once');
  const a = e.app.store.auditTail(80);
  assert.ok(a.some((x) => x.action === 'asset.coverage.action.request' && x.by === 'nora.syn'));
  assert.ok(a.some((x) => x.action === 'asset.coverage.action.approve' && x.by === 'syed' && x.detail.requested_by === 'nora.syn' && x.detail.ok === 1));
  // reject needs a reason; cancel by the requester
  r = await call('POST', '/asset-coverage/actions', { kind: 'add_tag', asset_ids: [id.db, id.app], tag: 'pci-scope', reason: 'tag the payment servers for review' }, OP); const a2 = r.json.action.id;
  assert.equal((await call('POST', '/asset-coverage/actions/' + a2 + '/reject', {}, ADM)).status, 400);
  assert.equal((await call('POST', '/asset-coverage/actions/' + a2 + '/reject', { reason: 'not in scope yet' }, ADM)).json.action.status, 'rejected');
  r = await call('POST', '/asset-coverage/actions', { kind: 'add_tag', asset_ids: [id.db], tag: 'pci-scope', reason: 'tag the payment server for review' }, OP); const a3 = r.json.action.id;
  assert.equal((await call('POST', '/asset-coverage/actions/' + a3 + '/cancel', undefined, OP2)).status, 403);
  assert.equal((await call('POST', '/asset-coverage/actions/' + a3 + '/cancel', undefined, OP)).json.action.status, 'cancelled');
  r = await call('POST', '/asset-coverage/actions', { kind: 'add_tag', asset_ids: ['nope-1'], tag: 'x', reason: 'tag something that is not there' }, OP); assert.equal(r.status, 400); assert.match(r.text, /asset_ids/);
});
