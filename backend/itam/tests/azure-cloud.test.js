// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Azure Cloud Servers (engine/azure-cloud.js) against a fake Azure (sign-in, Resource Graph, Resource Manager), SYNTHETIC tenant:
// settings (admin, vault credentials only, a separate action credential), refresh reads every section and tolerates one failing,
// the analysis (exposure, backup, patches, Defender, stopped-but-billed, orphan disks / IPs, Advisor savings, risk and reasons),
// viewers see no tags, adding servers to the asset register, four-eyes actions (operator proposes, a different administrator
// approves, never an AI identity, sent with the action credential, refused cases), validation errors, audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

const ADM = { user: 'admin.syn', role: 'admin' }, ADM2 = { user: 'admin2.syn', role: 'admin' }, OP = { user: 'op.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:engineer', role: 'admin' };
const { fakeAzure, SUB, TEN, APP, APP2, VM } = require('./azure-fake');

async function setup(t, o) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = [];
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true, azureRequest: fakeAzure(calls, o) });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const mk = (label, client, secret) => e.app.discovery.createCredential({ kind: 'azure', label, target: { tenant_id: TEN, client_id: client, subscriptions: [SUB] }, secret: { client_secret: secret } }, ADM);
  const read = mk('Azure reader (synthetic)', APP, 'Synthetic-Read-1'), act = mk('Azure VM operator (synthetic)', APP2, 'Synthetic-Act-1');
  const id = (x) => (x.credential ? x.credential.id : x.id);
  return { e, call, calls, readId: id(read), actId: id(act) };
}

test('azure cloud: settings, refresh, analysis, viewer view, register', async (t) => {
  const { e, call, calls, readId, actId } = await setup(t);
  let v = (await call('GET', '/azure-cloud', undefined, VIEW)).json; assert.equal(v.configured, false); assert.deepEqual(v.vms, []); assert.deepEqual(v.credentials, [], 'a viewer sees no credentials');
  assert.equal((await call('POST', '/azure-cloud/refresh', {}, OP)).status, 409, 'not configured yet');
  assert.equal((await call('PUT', '/azure-cloud/settings', { credential_id: readId }, OP)).status, 403, 'an operator does not set the connection');
  assert.equal((await call('PUT', '/azure-cloud/settings', { credential_id: readId }, BOT)).status, 403, 'never an AI identity');
  let r = await call('PUT', '/azure-cloud/settings', { credential_id: 'nope' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^credential_id/);
  r = await call('PUT', '/azure-cloud/settings', { credential_id: readId, action_credential_id: readId }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /separate credential/);
  r = await call('PUT', '/azure-cloud/settings', { credential_id: 'cr_000000000000' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /not an Azure credential/);
  r = await call('PUT', '/azure-cloud/settings', { credential_id: readId, refresh_hours: 99 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /refresh_hours/);
  r = await call('PUT', '/azure-cloud/settings', { credential_id: readId, refresh_hours: 4, extra: 'dropped' }, ADM); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.credentials.length, 2); assert.ok(!JSON.stringify(r.json).includes('Synthetic-Read'), 'the secret never leaves the vault');
  assert.equal((await call('POST', '/azure-cloud/refresh', {}, VIEW)).status, 403);
  r = await call('POST', '/azure-cloud/refresh', {}, OP); assert.equal(r.status, 200, r.text);
  assert.ok(calls.some((c) => /oauth2/.test(c.url) && /Synthetic-Read-1/.test(c.body)) && !calls.some((c) => /Synthetic-Act/.test(c.body || '')), 'refresh signs in with the read credential only');
  v = r.json; assert.equal(v.totals.vms, 3);
  const W = v.vms.find((x) => x.name === 'web-syn'), A = v.vms.find((x) => x.name === 'app-syn'), D = v.vms.find((x) => x.name === 'db-syn');
  assert.equal(v.vms[0].name, 'web-syn', 'the riskiest first');
  assert.deepEqual(W.public_ips, ['203.0.113.10']); assert.equal(W.open_ports[0].label, 'RDP'); assert.ok(W.reasons.some((x) => /RDP open to the internet/.test(x)), W.reasons.join('|'));
  assert.ok(W.reasons.some((x) => /3 critical patch/.test(x)) && W.reasons.some((x) => /not protected by Azure Backup/.test(x)) && W.defender.high === 1);
  assert.ok(A.reasons.some((x) => /stopped but not deallocated/.test(x)) && A.reasons.some((x) => /no owner tag/.test(x)));
  assert.ok(D.backup && D.backup.age_days === 0 && D.hybrid_benefit && D.advisor[0].target_sku === 'Standard_E4s_v5');
  assert.equal(v.totals.exposed, 1); assert.equal(v.totals.no_backup, 2); assert.equal(v.totals.stopped_billed, 1); assert.equal(v.totals.orphan_disks, 1); assert.equal(v.totals.orphan_disk_gb, 512); assert.equal(v.totals.orphan_ips, 1);
  assert.equal(v.totals.advisor_savings, 413); assert.equal(v.totals.secure_score, 70); assert.equal(v.totals.not_in_register, 3);
  assert.ok(v.insights.some((i) => i.level === 'crit' && /management port/.test(i.title) && i.servers.includes('web-syn')));
  assert.ok(v.insights.some((i) => /stopped but still billed/.test(i.title)) && v.insights.some((i) => /Hybrid Benefit/.test(i.title) && i.servers.includes('web-syn')));
  assert.equal(W.tags.owner, 'a.syn');
  const vv = (await call('GET', '/azure-cloud', undefined, VIEW)).json; assert.deepEqual(vv.vms.find((x) => x.name === 'web-syn').tags, {}, 'a viewer sees no tags'); assert.equal(vv.settings.credential_id, undefined);
  // register
  r = await call('POST', '/azure-cloud/register', { ids: [W.id, D.id, VM('ghost')] }, OP); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.created.length, 2); assert.equal(r.json.missing.length, 1);
  const as = e.app.store.collection('assets').all().find((x) => x.name === 'web-syn'); assert.equal(as.site, 'Azure uaenorth'); assert.equal(as.mgmt_ip, '10.50.0.4'); assert.equal(as.type, 'server'); assert.ok(as.tags.includes('azure'));
  assert.equal(e.app.store.collection('assets').all().find((x) => x.name === 'db-syn').status, 'in_stock', 'a deallocated server');
  r = await call('POST', '/azure-cloud/register', { ids: [W.id] }, OP); assert.equal(r.json.created.length, 0); assert.equal(r.json.skipped[0].why, 'already in the register');
  assert.equal((await call('POST', '/azure-cloud/register', { ids: [] }, OP)).status, 400); assert.equal((await call('POST', '/azure-cloud/register', { ids: [W.id] }, VIEW)).status, 403);
  assert.equal((await call('GET', '/azure-cloud', undefined, OP)).json.totals.not_in_register, 1);
  const au = e.app.store.auditTail(100).map((x) => x.action); assert.ok(au.includes('azure.settings') && au.includes('azure.refresh') && au.includes('azure.register'), au.join(','));
  const st = e.app.store.auditTail(100).find((x) => x.action === 'azure.settings'); assert.equal(st.by, 'admin.syn'); assert.equal(st.role, 'admin');
  void actId;
});

test('azure cloud: one section refused (Defender) still shows the rest', async (t) => {
  const { call, readId } = await setup(t, { noDefender: true });
  await call('PUT', '/azure-cloud/settings', { credential_id: readId }, ADM);
  const v = (await call('POST', '/azure-cloud/refresh', {}, OP)).json;
  assert.equal(v.sections.score.ok, false); assert.equal(v.sections.score.error, 'authz'); assert.equal(v.totals.vms, 3); assert.equal(v.totals.secure_score, null);
});

test('azure cloud: four-eyes actions - propose, refuse the proposer and AI, approve sends with the action credential', async (t) => {
  const { e, call, calls, readId, actId } = await setup(t);
  await call('PUT', '/azure-cloud/settings', { credential_id: readId }, ADM); await call('POST', '/azure-cloud/refresh', {}, OP);
  const id = VM('app-syn');
  assert.equal((await call('POST', '/azure-cloud/actions', { vm_id: id, action: 'deallocate', reason: 'stopped and billed (synthetic)' }, VIEW)).status, 403);
  assert.equal((await call('POST', '/azure-cloud/actions', { vm_id: id, action: 'deallocate', reason: 'stopped and billed (synthetic)' }, { user: 'ai:engineer', role: 'operator' })).status, 403, 'an AI never proposes');
  let r = await call('POST', '/azure-cloud/actions', { vm_id: id, action: 'delete', reason: 'nope nope' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /^action/);
  r = await call('POST', '/azure-cloud/actions', { vm_id: id, action: 'deallocate' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  r = await call('POST', '/azure-cloud/actions', { vm_id: '/subscriptions/x/../../etc', action: 'start', reason: 'path trick (synthetic)' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /vm_id/);
  r = await call('POST', '/azure-cloud/actions', { vm_id: VM('ghost'), action: 'start', reason: 'not read (synthetic)' }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/azure-cloud/actions', { vm_id: id, action: 'deallocate', reason: 'stopped and billed (synthetic)' }, OP); assert.equal(r.status, 200, r.text); const ch = r.json;
  assert.equal(ch.state, 'pending'); assert.equal((await call('POST', '/azure-cloud/actions', { vm_id: id, action: 'start', reason: 'second one (synthetic)' }, OP)).status, 409, 'one change per server at a time');
  assert.equal((await call('POST', '/azure-cloud/actions/' + ch.id + '/decide', { decision: 'approve' }, OP)).status, 403, 'an operator does not approve');
  assert.equal((await call('POST', '/azure-cloud/actions/' + ch.id + '/decide', { decision: 'approve' }, BOT)).status, 403, 'never an AI identity');
  assert.equal((await call('POST', '/azure-cloud/actions/' + ch.id + '/decide', { decision: 'maybe' }, ADM)).status, 400);
  r = await call('POST', '/azure-cloud/actions/' + ch.id + '/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 409, 'no action credential yet'); assert.match(r.json.error, /action credential/);
  await call('PUT', '/azure-cloud/settings', { credential_id: readId, action_credential_id: actId }, ADM);
  // the proposer can never approve their own change
  const mine = (await call('POST', '/azure-cloud/actions', { vm_id: VM('web-syn'), action: 'restart', reason: 'patching (synthetic)' }, ADM)).json;
  r = await call('POST', '/azure-cloud/actions/' + mine.id + '/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  r = await call('POST', '/azure-cloud/actions/' + mine.id + '/decide', { decision: 'reject', note: 'not now' }, ADM2); assert.equal(r.json.state, 'rejected');
  calls.length = 0;
  r = await call('POST', '/azure-cloud/actions/' + ch.id + '/decide', { decision: 'approve', note: 'ok' }, ADM2); assert.equal(r.status, 200, r.text); assert.equal(r.json.state, 'sent'); assert.equal(r.json.decided_by, 'admin2.syn');
  assert.ok(calls.some((c) => /oauth2/.test(c.url) && /Synthetic-Act-1/.test(c.body)) && !calls.some((c) => /Synthetic-Read/.test(c.body || '')), 'the action credential, not the read one');
  assert.ok(calls.some((c) => c.method === 'POST' && c.url.endsWith(id + '/deallocate?api-version=2024-07-01') && c.auth === 'Bearer bearer-4444'));
  assert.equal((await call('POST', '/azure-cloud/actions/' + ch.id + '/decide', { decision: 'approve' }, ADM2)).status, 409, 'decided once');
  const au = e.app.store.auditTail(200).filter((x) => /^azure\.action\./.test(x.action)).map((x) => x.action);
  assert.ok(['azure.action.propose', 'azure.action.approve', 'azure.action.sent', 'azure.action.reject'].every((a) => au.includes(a)), au.join(','));
  assert.ok(!JSON.stringify(e.app.store.auditTail(200)).includes('Synthetic-Act'), 'no secret in the audit');
  const v = (await call('GET', '/azure-cloud', undefined, VIEW)).json; assert.equal(v.actions.length, 2); assert.equal(v.actions[0].reason, undefined, 'a viewer sees no reasons');
});

test('azure cloud: a refused action is recorded as failed with a reason the person can act on', async (t) => {
  const { call, readId, actId } = await setup(t, { actStatus: 403 });
  await call('PUT', '/azure-cloud/settings', { credential_id: readId, action_credential_id: actId }, ADM); await call('POST', '/azure-cloud/refresh', {}, OP);
  const ch = (await call('POST', '/azure-cloud/actions', { vm_id: VM('db-syn'), action: 'start', reason: 'month end (synthetic)' }, OP)).json;
  const r = await call('POST', '/azure-cloud/actions/' + ch.id + '/decide', { decision: 'approve' }, ADM); assert.equal(r.json.state, 'failed'); assert.match(r.json.error, /Virtual Machine Contributor/);
});
