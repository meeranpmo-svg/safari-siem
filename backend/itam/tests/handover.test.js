// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Staff handover (engine/handover.js): the scan of what a leaver owns, successors who accept in person, the access
// checklist closed by someone else, notes that refuse secrets, sign-off by the named manager only when everything is
// closed, owner fields moved at sign-off (audited; a record changed since is left alone), roles (viewers refused - PDPL),
// validation (fields named, undeclared fields dropped) and the audit trail. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerHandover } = require('../engine/handover');

const ADM = { user: 'syed', role: 'admin', ip: '' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const S = e.app.store, A = e.app.assets;
  const a1 = A.create({ name: 'LAP-SYN-01', type: 'laptop', status: 'in_use', owner: 'khalid.syn', custodian: 'khalid.syn' }, ADM).asset.id;
  const a2 = A.create({ name: 'FW-SYN-01', type: 'firewall', status: 'in_use', owner: 'Khalid.Syn ' }, ADM).asset.id;
  const a3 = A.create({ name: 'OLD-SYN-01', type: 'server', status: 'in_use', owner: 'khalid.syn' }, ADM).asset.id;
  S.collection('assets').patch(a3, (x) => { x.status = 'disposed'; return x; });
  S.collection('ownership_services').put({ id: 'svc_claims', business_service: 'Claims portal', it_owner: 'khalid.syn', business_owner: 'huda.syn' });
  S.collection('grc_risks').put({ id: 'RSK-0001', status: 'open', description: 'Firewall end of support', owner: 'khalid.syn' });
  S.collection('grc_risks').put({ id: 'RSK-0002', status: 'closed', description: 'old', owner: 'khalid.syn' });
  S.collection('grc_actions').put({ id: 'ACT-0001', status: 'open', description: 'Replace FW-SYN-01', owner: 'khalid.syn', due: '2026-12-31' });
  S.collection('grc_actions').put({ id: 'ACT-0002', status: 'done', description: 'done one', owner: 'khalid.syn' });
  S.collection('support_contracts').put({ id: 'sc_1', vendor: 'Fortinet', contract_no: 'FC-SYN-1', owner: 'khalid.syn', end: '2027-03-01' });
  S.collection('dom_domains').put({ id: 'dom_1', name: 'syn-example.test', owner: 'khalid.syn', expires: '2027-01-10' });
  S.collection('job_roles').put({ id: 'netadmin', name: 'Network Admin', approves: ['eng:net'] });
  S.collection('role_assignments').put({ id: 'ra_k', user: 'khalid.syn', role_id: 'netadmin' });
  S.collection('virt_power').put({ id: 'VPW-0009', state: 'approved', requested_by: 'khalid.syn', title: 'Restart: esx-syn-01' });
  S.collection('disc_credentials').put({ id: 'cr_1', kind: 'ssh', label: 'core switches (read-only)', created_by: 'khalid.syn' });
  const H = registerHandover(e.app.srv, e.app, {});
  return { e, S, H, a1, a2 };
}
const op = (user, role = 'operator') => ({ user, role });
const post = (e, who, p, b) => e.req('POST', '/handover' + p, Object.assign({ body: b || {} }, who));
const audits = (e, re) => e.app.store.auditTail(300, (x) => re.test(x.action || '')).reverse();
const NEW = { leaver: 'khalid.syn', leaver_name: 'Khalid (synthetic)', team: 'Cyber Security', last_day: '2026-11-30', manager: 'sara.syn', reason: 'resignation' };

test('roles and validation: viewers refused (personal data), fields named, undeclared fields dropped', async (t) => {
  const { e } = await setup(t);
  assert.equal((await e.req('GET', '/handover', { role: 'viewer' })).status, 403);
  assert.equal((await post(e, { role: 'viewer' }, '', NEW)).status, 403);
  assert.match((await post(e, op('sara.syn'), '', Object.assign({}, NEW, { leaver: '' }))).json.error, /leaver is required/);
  assert.match((await post(e, op('sara.syn'), '', Object.assign({}, NEW, { team: 'Sales' }))).json.error, /team must be one of/);
  assert.match((await post(e, op('sara.syn'), '', Object.assign({}, NEW, { last_day: '30/11/2026' }))).json.error, /last_day must be a date/);
  assert.match((await post(e, op('sara.syn'), '', Object.assign({}, NEW, { manager: 'khalid.syn' }))).json.error, /cannot be the person leaving/);
  assert.match((await post(e, op('sara.syn'), '', Object.assign({}, NEW, { manager: 'duty:virt' }))).json.error, /user name|named people/);
  assert.match((await post(e, op('sara.syn'), '', Object.assign({}, NEW, { leaver: 'khalid<script>' }))).json.error, /leaver must be a user name/);
  const r = await post(e, op('sara.syn'), '', Object.assign({}, NEW, { state: 'signed-off', signoff: { by: 'x' }, items: [] }));
  assert.equal(r.status, 200); assert.equal(r.json.state, 'open'); assert.equal(r.json.signoff, undefined);
  assert.equal((await post(e, op('ali.syn'), '', NEW)).status, 409, 'one open handover per leaver');
  assert.equal((await e.req('GET', '/handover/people', op('ali.syn'))).json.people.includes('khalid.syn'), true);
});

test('scan: everything named after the leaver (open items only), case- and space-insensitive', async (t) => {
  const { e } = await setup(t);
  const h = (await post(e, op('sara.syn'), '', NEW)).json;
  const by = (src) => h.items.filter((i) => i.source === src);
  assert.equal(by('Asset').length, 3, 'laptop owner + custodian, firewall owner ("Khalid.Syn ") - not the disposed server');
  assert.deepEqual([by('Business service').length, by('Risk').length, by('GRC action').length, by('Support contract').length, by('Domain').length], [1, 1, 1, 1, 1], 'closed risk / done action left out');
  assert.equal(by('Job role')[0].kind, 'follow-up'); assert.match(by('Job role')[0].detail, /approves: eng:net/);
  assert.equal(by('Power plan')[0].kind, 'follow-up'); assert.equal(by('Saved credential').length, 1);
  assert.ok(h.access.find((a) => a.id === 'pam').how.includes('1 credential(s)'), 'credentials the leaver saved are named in the PAM step');
  assert.equal(h.access.length, 10); assert.ok(h.access.every((a) => a.state === 'open'));
  assert.equal(h.progress.done, 0); assert.ok(h.blockers.length === 3);
});

test('successors accept in person; leaver / manager / admin assign; declines need a reason', async (t) => {
  const { e } = await setup(t);
  const h = (await post(e, op('sara.syn'), '', NEW)).json, id = h.id, k = (src) => h.items.find((i) => i.source === src).key;
  assert.equal((await post(e, op('ali.syn'), `/${id}/assign`, { all: true, successor: 'omar.syn' })).status, 403, 'a bystander cannot assign');
  assert.match((await post(e, op('sara.syn'), `/${id}/assign`, { all: true, successor: 'khalid.syn' })).json.error, /cannot take over their own/);
  assert.match((await post(e, op('sara.syn'), `/${id}/assign`, { keys: ['assets:nope:owner'], successor: 'omar.syn' })).json.error, /not in this handover/);
  assert.equal((await post(e, op('khalid.syn'), `/${id}/assign`, { all: true, successor: 'omar.syn' })).status, 200, 'the leaver proposes successors');
  assert.equal((await post(e, op('sara.syn'), `/${id}/assign`, { keys: [k('Domain')], successor: 'ali.syn' })).json.items.find((i) => i.source === 'Domain').successor, 'ali.syn');
  const enc = (key) => encodeURIComponent(key);
  assert.equal((await post(e, op('sara.syn'), `/${id}/items/${enc(k('Risk'))}/accept`)).status, 403, 'only the named successor accepts');
  assert.equal((await post(e, op('omar.syn'), `/${id}/items/${enc(k('Risk'))}/decline`, {})).status, 400, 'a decline needs a reason');
  const d = await post(e, op('omar.syn'), `/${id}/items/${enc(k('Risk'))}/decline`, { reason: 'not my area - GRC team' });
  assert.equal(d.json.items.find((i) => i.source === 'Risk').state, 'declined');
  await post(e, op('sara.syn'), `/${id}/assign`, { keys: [k('Risk')], successor: 'ali.syn' });
  assert.equal((await post(e, op('ali.syn'), `/${id}/items/${enc(k('Risk'))}/accept`, { note: 'taking it' })).json.items.find((i) => i.source === 'Risk').state, 'accepted');
  assert.equal((await post(e, op('ali.syn'), `/${id}/items/${enc(k('Risk'))}/accept`)).status, 409, 'accepted once');
  assert.equal((await post(e, op('khalid.syn'), `/${id}/items/${enc(k('Saved credential'))}/na`, { reason: 'retired login' })).status, 403, 'the leaver cannot close own items');
  assert.equal((await post(e, op('sara.syn'), `/${id}/items/${enc(k('Saved credential'))}/na`, { reason: 'credential rotated and re-saved by the team' })).json.items.find((i) => i.source === 'Saved credential').state, 'na');
  assert.equal((await post(e, op('sara.syn'), `/${id}/items/bad%20key/accept`)).status, 400);
  // a re-scan keeps the decisions
  const again = (await post(e, op('sara.syn'), `/${id}/scan`)).json;
  assert.equal(again.items.find((i) => i.source === 'Risk').state, 'accepted'); assert.equal(again.items.length, h.items.length);
});

test('access checklist by someone else, evidence required; notes refuse secrets, keep locations', async (t) => {
  const { e } = await setup(t);
  const id = (await post(e, op('sara.syn'), '', NEW)).json.id;
  assert.equal((await post(e, op('khalid.syn'), `/${id}/access/ad`, { state: 'done', evidence: 'done myself' })).status, 403, 'the leaver cannot confirm own access removal');
  assert.match((await post(e, op('ali.syn'), `/${id}/access/ad`, { state: 'done' })).json.error, /evidence/);
  assert.match((await post(e, op('ali.syn'), `/${id}/access/ad`, { state: 'removed', evidence: 'x' })).json.error, /state must be one of/);
  assert.equal((await post(e, op('ali.syn'), `/${id}/access/ad`, { state: 'done', evidence: 'SR-SYN-445 disabled 30 Nov' })).json.access.find((a) => a.id === 'ad').by, 'ali.syn');
  assert.equal((await post(e, op('ali.syn'), `/${id}/access/zzz`, { state: 'done', evidence: 'x' })).status, 404);
  const put = (who, b) => e.req('PUT', `/handover/${id}/notes`, Object.assign({ body: b }, who));
  assert.equal((await put(op('ali.syn'), { systems: 'x' })).status, 403, 'a bystander cannot write the notes');
  for (const bad of ['FortiGate admin password=Winter2026!', 'root password is P@ssw0rd123', 'PSK for the Riyadh tunnel: Rt7!xyz99', 'github token ghp_abcdefghijklmnopqrstuvwxyz0123456789'])
    assert.match((await put(op('khalid.syn'), { secrets_location: bad })).json.error, /secrets_location: this looks like it contains a password/, bad);
  const ok = await put(op('khalid.syn'), { systems: 'FortiGate HA pair, Wazuh, SIEM rules', secrets_location: 'admin password is kept in CyberArk safe NET-FW; SNMP in the platform vault', vendors: 'Fortinet TAC 800-SYN', bogus: 'dropped' });
  assert.equal(ok.status, 200); assert.equal(ok.json.notes.bogus, undefined); assert.match(ok.json.notes.secrets_location, /CyberArk/);
  const n = audits(e, /^handover\.notes$/)[0]; assert.deepEqual(n.detail.fields.sort(), ['secrets_location', 'systems', 'vendors']); assert.ok(!JSON.stringify(n).includes('CyberArk'), 'note text stays out of the audit line');
});

test('sign-off: manager only, only when complete; owner fields move (audited); a record changed since is left alone', async (t) => {
  const { e, S, a1, a2 } = await setup(t);
  const h = (await post(e, op('sara.syn'), '', NEW)).json, id = h.id;
  const so = (who, b) => post(e, who, `/${id}/signoff`, b);
  assert.equal((await so(op('khalid.syn'))).status, 403, 'not the leaver');
  assert.equal((await so(op('ali.syn'))).status, 403, 'not a bystander operator');
  assert.equal((await so(op('duty:virt', 'admin'))).status, 403, 'never a service identity');
  const early = await so(op('sara.syn'));
  assert.equal(early.status, 409); assert.match(early.json.error, /item\(s\) not accepted.*access not closed.*notes are empty/);
  // complete it
  await post(e, op('sara.syn'), `/${id}/assign`, { all: true, successor: 'omar.syn' });
  for (const i of (await e.req('GET', '/handover/' + id, op('sara.syn'))).json.items) await post(e, op('omar.syn'), `/${id}/items/${encodeURIComponent(i.key)}/accept`);
  for (const a of h.access) await post(e, op('ali.syn'), `/${id}/access/${a.id}`, { state: a.id === 'physical' ? 'na' : 'done', evidence: a.id === 'physical' ? 'remote worker, no badge' : 'SR-SYN-' + a.id });
  await e.req('PUT', `/handover/${id}/notes`, { user: 'khalid.syn', role: 'operator', body: { systems: 'FortiGate HA pair, Wazuh' } });
  S.collection('grc_risks').patch('RSK-0001', (x) => { x.owner = 'nora.syn'; return x; });   // changed hands meanwhile
  const done = await so(op('sara.syn'), { comment: 'handover complete' });
  assert.equal(done.status, 200, JSON.stringify(done.json)); assert.equal(done.json.state, 'signed-off'); assert.equal(done.json.signoff.by, 'sara.syn');
  assert.equal(S.collection('assets').get(a1).owner, 'omar.syn'); assert.equal(S.collection('assets').get(a1).custodian, 'omar.syn'); assert.equal(S.collection('assets').get(a2).owner, 'omar.syn');
  assert.equal(S.collection('ownership_services').get('svc_claims').it_owner, 'omar.syn'); assert.equal(S.collection('ownership_services').get('svc_claims').business_owner, 'huda.syn');
  assert.equal(S.collection('grc_actions').get('ACT-0001').owner, 'omar.syn'); assert.equal(S.collection('support_contracts').get('sc_1').owner, 'omar.syn'); assert.equal(S.collection('dom_domains').get('dom_1').owner, 'omar.syn');
  assert.equal(S.collection('grc_risks').get('RSK-0001').owner, 'nora.syn', 'not overwritten'); assert.equal(done.json.items.find((i) => i.source === 'Risk').applied, 'changed since - not moved');
  assert.equal(S.collection('role_assignments').get('ra_k').user, 'khalid.syn', 'a job role is never changed here (admin, Roles & Functions)');
  assert.equal(S.collection('virt_power').get('VPW-0009').requested_by, 'khalid.syn', 'who asked for a plan is history, never rewritten');
  assert.ok(audits(e, /^asset\.assign$/).length >= 2, 'assets moved through the asset register (history + audit)');
  const re = audits(e, /^handover\.reassign$/).map((x) => [x.target, x.detail.field, x.detail.from, x.detail.to]);
  assert.deepEqual(re.map((x) => x[0]).sort(), ['ACT-0001', 'dom_1', 'sc_1', 'svc_claims']); assert.ok(re.every((x) => x[3] === 'omar.syn'));
  assert.deepEqual(audits(e, /^handover\.signoff$/).map((x) => [x.by, x.detail.reassigned, x.detail.skipped]), [['sara.syn', 7, 1]]);
  assert.equal((await post(e, op('sara.syn'), `/${id}/scan`)).status, 409, 'closed after sign-off');
  assert.equal((await post(e, op('ali.syn'), `/${id}/cancel`, { reason: 'mistake made' })).status, 409);
});

test('cancel: manager, creator or admin, with a reason', async (t) => {
  const { e } = await setup(t);
  const id = (await post(e, op('ali.syn'), '', NEW)).json.id;
  assert.equal((await post(e, op('omar.syn'), `/${id}/cancel`, { reason: 'not leaving after all' })).status, 403);
  assert.equal((await post(e, op('ali.syn'), `/${id}/cancel`, {})).status, 400);
  assert.equal((await post(e, op('ali.syn'), `/${id}/cancel`, { reason: 'not leaving after all' })).json.state, 'cancelled');
  assert.deepEqual(audits(e, /^handover\./).map((x) => x.action), ['handover.create', 'handover.cancel']);
});
