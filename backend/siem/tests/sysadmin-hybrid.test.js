// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Exchange hybrid migration workspace (engine/sysadmin/hybrid.js): readiness from the read-only checks (unknown until read,
// never "ready" by default), versions, certificate, EWS / MRS Proxy, routing domain, remote domain, connector, HCW, manual
// steps, waves (validation, roles, flow, failure needs a reason), the Exchange Online commands, privacy for viewers.
// All names are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const routes = require('../engine/sysadmin/routes');
const { readiness, versionVerdict } = require('../engine/sysadmin/hybrid');

const DATA = {
  ex_servers: [{ name: 'EXCH01', version: 'Version 15.2 (Build 1544.4)' }, { name: 'EXCH02', version: 'Version 15.1 (Build 2375.7)' }],
  ex_certificates: [{ thumbprint: 'AA', subject: 'CN=mail.corp-synth.sa', services: 'IMAP, POP, IIS, SMTP', days_left: 200, self_signed: false, names: ['mail.corp-synth.sa', 'autodiscover.corp-synth.sa'] }, { thumbprint: 'BB', subject: 'CN=EXCH01', services: 'SMTP', days_left: 900, self_signed: true }],
  ex_hybrid_ews: [{ server: 'EXCH01', external_url: 'https://mail.corp-synth.sa/EWS/Exchange.asmx', mrs_proxy: true }, { server: 'EXCH02', external_url: '', mrs_proxy: false }],
  ex_hybrid_domains: { accepted: [{ name: 'corp-synth.sa', type: 'Authoritative', default: true }, { name: 'corpsynth.mail.onmicrosoft.com', type: 'Authoritative' }], remote: [{ name: 'Hybrid Domain - corpsynth.mail.onmicrosoft.com', domain: 'corpsynth.mail.onmicrosoft.com', target_delivery: true }],
    send_connectors: [{ name: 'Outbound to Office 365 - 1a2b', enabled: true, spaces: ['smtp:corpsynth.mail.onmicrosoft.com;1'], smart_hosts: ['corpsynth-sa.mail.protection.outlook.com'], tls_domain: 'mail.protection.outlook.com', cloud: true }] },
  ex_hybrid: { hybrid: true, domains: ['corp-synth.sa'], features: ['FreeBusy', 'MoveMailbox', 'Mailtips'], servers: ['EXCH01'], org_relationships: [{ name: 'O365 to On-premises', enabled: true, free_busy: true }], intra_org_connectors: [], auth_servers: [{ name: 'EvoSts - 1a2b', enabled: true, type: 'AzureAD' }] },
  ex_mailbox_counts: { on_premises: 420, by_type: [{ type: 'UserMailbox', count: 400 }, { type: 'SharedMailbox', count: 20 }], by_database: [{ database: 'DB01', count: 300 }, { database: 'DB02', count: 120 }], with_archive: 15, in_cloud: 35, in_cloud_by_type: [{ type: 'RemoteUserMailbox', count: 35 }] },
};
const fakeExec = () => async (req) => req.op === 'version' ? { ok: true } : req.op === 'run' ? { ok: true, data: DATA[req.check] !== undefined ? DATA[req.check] : [], errors: [] } : { ok: false, kind: 'input', error: 'x' };

async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-hyb-')), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = {}; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets }, enumerable: false });
  const S = routes.createSysadmin({ state, config, log: { info() {}, warn() {}, error() {} }, sysadminExec: fakeExec() });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, sysadmin: S });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  async function call(m, p, { role = 'viewer', user = 'u1', body, params = {}, query = {} } = {}) {
    const out = {}; const ctx = { role, user, body, params, query, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push([a, t, d]), ok(b) { out.status = 200; out.body = b; }, fail(c, msg) { out.status = c; out.error = msg; } };
    const rv = await R[m + ' /api/soc/sysadmin' + p](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } return out;
  }
  return { call, audits };
}

test('versions: 2013 out of support, 2016 before CU23 and 2019 before CU14 need an update', () => {
  assert.equal(versionVerdict('Version 15.0 (Build 1497.2)')[0], 'bad');
  assert.equal(versionVerdict('Version 15.1 (Build 2375.7)')[0], 'warn');
  assert.equal(versionVerdict('Version 15.1 (Build 2507.6)')[0], 'ok');
  assert.equal(versionVerdict('Version 15.2 (Build 1258.12)')[0], 'warn');
  assert.equal(versionVerdict('Version 15.2 (Build 2562.17)')[1], 'Exchange Server SE');
  assert.equal(versionVerdict('')[0], 'unknown');
});

test('readiness: nothing read = incomplete, never ready', () => {
  const r = readiness({}, { tenant: '' });
  assert.equal(r.verdict, 'incomplete'); assert.ok(r.items.every((i) => i.status === 'unknown'));
  assert.ok(r.items.every((i) => /not read yet/.test(i.detail)));
  const e = readiness({ ex_hybrid: { at: 1, error: 'access denied' } }, {});
  assert.match(e.items.find((i) => i.id === 'hcw').detail, /could not be read: access denied/);
});

test('workspace: readiness from the servers, manual steps, waves, commands, roles', async () => {
  const { call, audits } = await setup();
  await call('POST', '/targets', { role: 'admin', body: { id: 'exch01', name: 'EXCH01', ip: '10.0.1.20', roles: ['exchange'] } });
  await call('PUT', '/profiles/:id', { role: 'admin', params: { id: 'exchange' }, body: { username: 'CORP\\svc-exro', password: 'Pw-123456' } });
  assert.equal((await call('POST', '/hybrid/refresh', { role: 'analyst' })).status, 403);
  let v = (await call('POST', '/hybrid/refresh', { role: 'operator' })).body;
  const it = (id) => v.readiness.items.find((x) => x.id === id);
  assert.equal(it('versions').status, 'warn'); assert.match(it('versions').detail, /EXCH02: Exchange 2016 before CU23/);
  assert.equal(it('certificate').status, 'ok'); assert.match(it('certificate').detail, /mail\.corp-synth\.sa/);
  assert.equal(it('ews').status, 'warn'); assert.match(it('ews').detail, /EXCH02: no external URL, MRS Proxy off/);
  assert.equal(it('routing').status, 'ok'); assert.equal(it('remote').status, 'ok'); assert.equal(it('connector').status, 'ok');
  assert.equal(it('hcw').status, 'ok'); assert.equal(it('freebusy').status, 'ok'); assert.equal(it('oauth').status, 'ok');
  assert.equal(v.readiness.verdict, 'ready_with_warnings');
  assert.equal(v.inventory.on_premises, 420); assert.equal(v.inventory.in_cloud, 35);
  assert.equal(v.manual.length, 7); assert.ok(v.manual.every((m) => m.done === false));
  // tenant setting narrows the routing-domain check to this tenant
  assert.equal((await call('PUT', '/hybrid/settings', { role: 'operator', body: { tenant: 'x' } })).status, 403);
  assert.equal((await call('PUT', '/hybrid/settings', { role: 'admin', body: { tenant: 'bad name!' } })).status, 400);
  await call('PUT', '/hybrid/settings', { role: 'admin', body: { tenant: 'other-tenant.onmicrosoft.com', notify: 'it-ops@corp-synth.sa' } });
  v = (await call('GET', '/hybrid')).body;
  assert.equal(v.settings.tenant, 'other-tenant'); assert.equal(v.readiness.items.find((x) => x.id === 'routing').status, 'bad', 'another tenant\'s routing domain does not count');
  await call('PUT', '/hybrid/settings', { role: 'admin', body: { tenant: 'corpsynth' } });
  // manual step
  const m = await call('POST', '/hybrid/manual/:id', { role: 'operator', params: { id: 'entra' }, body: { done: true, note: 'Entra Connect v2, hybrid write-back on' } });
  assert.equal(m.body.manual.find((x) => x.id === 'entra').done, true); assert.equal(m.body.manual.find((x) => x.id === 'entra').by, 'u1');
  assert.equal((await call('POST', '/hybrid/manual/:id', { role: 'operator', params: { id: 'nope' }, body: {} })).status, 404);
  // waves
  assert.equal((await call('POST', '/hybrid/waves', { role: 'operator', body: { name: 'Pilot', mailboxes: 'not-an-address' } })).status, 400);
  assert.equal((await call('POST', '/hybrid/waves', { role: 'analyst', body: { name: 'Pilot', mailboxes: 'a@corp-synth.sa' } })).status, 403);
  const w = (await call('POST', '/hybrid/waves', { role: 'operator', body: { name: 'Wave 1 - IT pilot', planned: '2026-11-05', mailboxes: "a.one@corp-synth.sa, b.two@corp-synth.sa\no'neil@corp-synth.sa a.one@corp-synth.sa" } })).body;
  assert.equal(w.mailboxes.length, 3, 'duplicates removed'); assert.equal(w.status, 'planned');
  assert.equal((await call('POST', '/hybrid/waves', { role: 'operator', body: { name: 'wave 1 - it pilot', mailboxes: 'c@corp-synth.sa' } })).status, 400, 'names are unique');
  const cmd = (await call('GET', '/hybrid/waves/:id/commands', { role: 'operator', params: { id: w.id } })).body;
  assert.match(cmd.csv, /^EmailAddress\r\na\.one@corp-synth\.sa/);
  assert.match(cmd.powershell, /New-MigrationBatch -Name 'Wave 1 - IT pilot' -SourceEndpoint 'Hybrid Migration Endpoint - EWS \(Default Web Site\)' -TargetDeliveryDomain 'corpsynth\.mail\.onmicrosoft\.com'/);
  assert.match(cmd.powershell, /-NotificationEmails 'it-ops@corp-synth\.sa'/); assert.match(cmd.powershell, /Complete-MigrationBatch -Identity 'Wave 1 - IT pilot'/);
  assert.equal((await call('GET', '/hybrid/waves/:id/commands', { role: 'viewer', params: { id: w.id } })).status, 403);
  assert.equal((await call('POST', '/hybrid/waves/:id/status', { role: 'operator', params: { id: w.id }, body: { status: 'failed' } })).status, 400, 'failure needs a reason');
  await call('POST', '/hybrid/waves/:id/status', { role: 'operator', params: { id: w.id }, body: { status: 'syncing' } });
  const done = (await call('POST', '/hybrid/waves/:id/status', { role: 'operator', params: { id: w.id }, body: { status: 'completed', note: 'all 3 completed' } })).body;
  assert.equal(done.status, 'completed'); assert.equal(done.history.length, 3);
  // a viewer sees counts, not the people
  const vv = (await call('GET', '/hybrid', { role: 'viewer' })).body;
  assert.equal(vv.waves[0].count, 3); assert.equal(vv.waves[0].mailboxes, undefined); assert.equal(vv.waves_summary.completed_mailboxes, 3);
  assert.ok((await call('GET', '/hybrid', { role: 'operator' })).body.waves[0].mailboxes.includes("o'neil@corp-synth.sa"));
  assert.ok(audits.some(([a]) => a === 'sysadmin.hybrid.wave') && audits.some(([a]) => a === 'sysadmin.hybrid.commands') && audits.some(([a]) => a === 'sysadmin.hybrid.step'));
});
