// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Active Directory on Connections: the domain controllers the SIEM Windows agent reports from (engine/ad-directory.js
// domainControllers, over SYNTHETIC SIEM hardening snapshots) - a primary and a backup DC are listed with their domain, a member
// server is not, no account name leaves; a SIEM that does not answer is said, not an error; GET /ad-directory carries them
// (operator), a viewer is refused.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createAdDirectory } = require('../engine/ad-directory');

const AD = { domain: 'corp.syn.test', domain_mode: 'Windows2016Domain', groups: { domain_admins: { count: 2, names: ['adm.a.syn', 'adm.b.syn'] } } };
const SNAP = { status: 200, json: { available: true, hosts: [
  { host: 'dc-syn-02', ip: '10.9.1.12', at: '2026-11-27T06:00:00Z', agent_version: '1.4.0', settings: { os: { domain_role: 4 }, ad: AD } },
  { host: 'dc-syn-01', ip: '10.9.1.10', at: '2026-11-27T06:00:00Z', agent_version: '1.4.0', settings: { os: { domain_role: 5 }, ad: AD } },
  { host: 'app-syn-01', ip: '10.9.2.20', at: '2026-11-27T06:00:00Z', agent_version: '1.4.0', settings: { os: { domain_role: 3 } } }] } };

test('domain controllers from the agent snapshots: DCs only, no account names, a silent SIEM is said', async () => {
  const calls = [];
  const X = createAdDirectory({ store: { collection: () => ({ get: () => null }) }, discovery: { siem: { call: async (m, p, who) => { calls.push([m, p, who.user]); return SNAP; } } } }, { noTimer: true, ad: null });
  const r = await X.domainControllers();
  assert.deepEqual(r.dcs.map((d) => [d.host, d.role, d.domain]), [['dc-syn-01', 'primary', 'corp.syn.test'], ['dc-syn-02', 'domain controller', 'corp.syn.test']]);
  assert.ok(!JSON.stringify(r).includes('adm.a.syn'), 'no account name leaves');
  assert.deepEqual(calls[0], ['GET', '/hardening/snapshots', 'system:itam-ad-directory']);
  const down = createAdDirectory({ store: { collection: () => ({ get: () => null }) }, discovery: { siem: { call: async () => null } } }, { noTimer: true });
  const d = await down.domainControllers(); assert.deepEqual(d.dcs, []); assert.match(d.why, /did not answer/);
  const none = createAdDirectory({ store: { collection: () => ({ get: () => null }) } }, { noTimer: true });
  assert.match((await none.domainControllers()).why, /not configured/);
});

test('route: GET /ad-directory carries the domain controllers for an operator; a viewer is refused', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.discovery = Object.assign(e.app.discovery || {}, { siem: Object.assign((e.app.discovery && e.app.discovery.siem) || {}, { call: async () => SNAP }) });
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const r = await e.req('GET', '/ad-directory', { user: 'nora.syn', role: 'operator' });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.domain_controllers.length, 2); assert.equal(r.json.connection.ok, false, 'the LDAP read is still not set');
  assert.equal((await e.req('GET', '/ad-directory', { user: 'vera.syn', role: 'viewer' })).status, 403);
});
