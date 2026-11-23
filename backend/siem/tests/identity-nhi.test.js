// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Non-Human Identities on the SIEM: the AD sync reads service principal names, descriptions and managed service accounts
// (gMSA / sMSA; a failed MSA search keeps the rest of the sync), identity.nhi() lists only non-human accounts with the reason,
// Microsoft Graph reads app registrations with the END DATES of their secrets / certificates (no value, no hint), and
// GET /identity/nhi: analyst reads it, viewer refused, a source not connected says why. Fake LDAP / Graph, SYNTHETIC directory.
const test = require('node:test');
const assert = require('node:assert/strict');
const real = require('../engine/ad/ldap-client');
const { createAdSync } = require('../engine/ad/sync');
const { createIdentity } = require('../engine/ad/identity');
const { createGraph } = require('../engine/collect/m365-graph');
const routes = require('../engine/ad/routes');

const NOW = Date.parse('2026-10-28T08:00:00Z');
const ft = (ms) => String(BigInt(ms) * 10000n + 116444736000000000n);   // epoch ms -> AD FILETIME
const ent = (dn, attrs) => ({ dn, raw: {}, attrs: Object.fromEntries(Object.entries(attrs).map(([k, v]) => [k.toLowerCase(), [].concat(v)])) });
const DA = 'CN=Domain Admins,CN=Users,DC=corp,DC=syn';
function fakeLdap(msaFails) {
  const conn = {
    server: { url: 'ldaps://dc1.corp.syn' }, bind: async () => {}, rootDSE: async () => ent('', { configurationNamingContext: 'CN=Configuration,DC=corp,DC=syn' }),
    search: async (base, o) => {
      const f = o.filter || '';
      if (/ManagedServiceAccount/.test(f)) {
        if (msaFails) throw new Error('0x32 insufficient access');
        return { entries: [
          ent('CN=gmsa-sql,CN=Managed Service Accounts,DC=corp,DC=syn', { sAMAccountName: 'gmsa-sql$', objectClass: ['top', 'msDS-GroupManagedServiceAccount'], servicePrincipalName: 'MSSQLSvc/sql01.corp.syn:1433', memberOf: DA,
            userAccountControl: '4096', 'msDS-ManagedPasswordInterval': '30', pwdLastSet: ft(NOW - 10 * 86400000), lastLogonTimestamp: ft(NOW - 86400000), whenCreated: '20250101000000.0Z' }),
          ent('CN=msa-old,CN=Managed Service Accounts,DC=corp,DC=syn', { sAMAccountName: 'msa-old$', objectClass: ['msDS-ManagedServiceAccount'], userAccountControl: '4096', lastLogonTimestamp: ft(NOW - 200 * 86400000) })], pages: 1 };
      }
      if (/objectClass=group/.test(f) && !/IN_CHAIN|1\.2\.840/.test(f)) return { entries: [ent(DA, { sAMAccountName: 'Domain Admins' })], pages: 1 };
      if (/1\.2\.840\.113556\.1\.4\.1941/.test(f)) return { entries: [ent('CN=svc-backup,OU=Service,DC=corp,DC=syn', { sAMAccountName: 'svc-backup' })], pages: 1 };
      if (/objectCategory=person/.test(f)) return { entries: [
        ent('CN=svc-backup,OU=Service,DC=corp,DC=syn', { sAMAccountName: 'svc-backup', userAccountControl: String(512 | 0x10000), description: 'Veeam backup service', memberOf: DA,
          pwdLastSet: ft(NOW - 900 * 86400000), lastLogonTimestamp: ft(NOW - 86400000) }),
        ent('CN=app-crm,OU=Service,DC=corp,DC=syn', { sAMAccountName: 'app-crm', userAccountControl: String(512 | 0x400000), servicePrincipalName: ['HTTP/crm.corp.syn', 'HTTP/crm'], pwdLastSet: ft(NOW - 400 * 86400000) }),
        ent('CN=Nora Syn,OU=Staff,DC=corp,DC=syn', { sAMAccountName: 'nora.syn', displayName: 'Nora Syn', mail: 'nora@corp.syn', userAccountControl: '512', pwdLastSet: ft(NOW - 30 * 86400000) })], pages: 1 };
      return { entries: [], pages: 1 };
    } };
  return { createClient: () => ({ run: (fn) => fn(conn) }), ad: real.ad, escapeFilter: real.escapeFilter, OID: real.OID };
}
const CONF = { ad: { enabled: true, servers: ['ldaps://dc1.corp.syn'], caFile: '/x.pem', baseDN: 'DC=corp,DC=syn', bindDN: 'CN=svc-siem,DC=corp,DC=syn' }, secrets: { ad: { bind_password: 'synthetic' } } };

test('AD sync + identity.nhi: service users (pattern / SPN) and managed service accounts, never a person', async () => {
  const id = createIdentity({ now: () => NOW, servicePatterns: ['svc-*'] });
  const r = await createAdSync({ config: CONF, identity: id, ldap: fakeLdap(false), now: () => NOW }).syncNow('test');
  assert.equal(r.ok, true, r.error);
  const n = id.nhi(NOW), by = Object.fromEntries(n.accounts.map((a) => [a.name, a]));
  assert.deepEqual(Object.keys(by).sort(), ['app-crm', 'gmsa-sql$', 'msa-old$', 'svc-backup'], 'the person is not listed');
  assert.equal(n.managed_read, true);
  assert.deepEqual(by['svc-backup'].why, ['name pattern']); assert.equal(by['svc-backup'].privileged, true); assert.equal(by['svc-backup'].pwd_never_expires, true);
  assert.ok(by['svc-backup'].pwd_age_days >= 899); assert.equal(by['svc-backup'].description, 'Veeam backup service');
  assert.deepEqual(by['app-crm'].why, ['service principal name']); assert.equal(by['app-crm'].no_preauth, true); assert.equal(by['app-crm'].spn.length, 2);
  assert.equal(by['gmsa-sql$'].kind, 'gmsa'); assert.equal(by['gmsa-sql$'].managed, true); assert.equal(by['gmsa-sql$'].privileged, true, 'direct member of Domain Admins');
  assert.equal(by['gmsa-sql$'].pwd_interval_days, 30);
  assert.equal(by['msa-old$'].kind, 'smsa'); assert.equal(by['msa-old$'].dormant, true);
});

test('AD sync: a refused managed-account search keeps the sync and says it was not read', async () => {
  const id = createIdentity({ now: () => NOW, servicePatterns: ['svc-*'] });
  const r = await createAdSync({ config: CONF, identity: id, ldap: fakeLdap(true), now: () => NOW }).syncNow('test');
  assert.equal(r.ok, true, r.error);
  const n = id.nhi(NOW);
  assert.equal(n.managed_read, false); assert.equal(n.accounts.length, 2);
});

test('Graph: app registrations with credential end dates only', async () => {
  const TEN = '11111111-2222-3333-4444-555555555555', CID = '66666666-7777-8888-9999-000000000000';
  const c = { m365: {} }; Object.defineProperty(c, 'secrets', { value: { m365: { tenant: TEN, client_id: CID, client_secret: 'synthetic-secret' } } });
  const R = (status, j) => ({ status, ok: status < 300, json: async () => j });
  const fetchImpl = async (url) => {
    if (url.includes('/oauth2/v2.0/token')) return R(200, { access_token: 'tok', expires_in: 3600 });
    if (url.includes('/applications')) return R(200, { value: [{ id: 'o1', appId: 'a1', displayName: 'CRM connector (synthetic)', createdDateTime: '2024-01-01T00:00:00Z',
      passwordCredentials: [{ displayName: 'prod', startDateTime: '2024-01-01T00:00:00Z', endDateTime: '2026-11-05T00:00:00Z', hint: 'Ab1', secretText: null }],
      keyCredentials: [{ displayName: 'cert', type: 'AsymmetricX509Cert', endDateTime: '2027-01-01T00:00:00Z' }],
      requiredResourceAccess: [{ resourceAppId: '00000003-0000-0000-c000-000000000000', resourceAccess: [{ id: 'x', type: 'Role' }, { id: 'y', type: 'Role' }, { id: 'z', type: 'Scope' }] }],
      owners: [{ userPrincipalName: 'omar@corp.syn' }] }] });
    return R(403, { error: { code: 'Forbidden', message: 'no' } });
  };
  const g = createGraph({ config: c, fetchImpl, now: () => NOW });
  await g.syncNow();
  const d = g.data();
  assert.equal(d.blocks.apps.ok, true);
  const a = d.apps[0];
  assert.deepEqual(a.owners, ['omar@corp.syn']); assert.equal(a.app_permissions, 2); assert.equal(a.delegated_permissions, 1);
  assert.deepEqual(a.secrets, [{ name: 'prod', start: '2024-01-01T00:00:00Z', end: '2026-11-05T00:00:00Z' }]);
  assert.ok(!JSON.stringify(d.apps).includes('Ab1'), 'the secret hint is not kept');
});

test('route /identity/nhi: analyst reads non-human identities, viewer refused, unconnected sources say why', async () => {
  const id = createIdentity({ now: () => NOW, servicePatterns: ['svc-*'] });
  const R = {}; const reg = (deps) => routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, Object.assign({ identity: id, config: {}, log: { info() {}, warn() {}, error() {} } }, deps));
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (role) => { const o = {}; const ctx = { role, user: 'u', query: {}, params: {}, need(r) { if (RANK[role] < RANK[r]) { o.s = 403; return false; } return true; }, audit() {}, ok(x) { o.s = 200; o.b = x; return x; }, fail(c2, m) { o.s = c2; o.e = m; } }; await R['GET /api/soc/identity/nhi'](ctx); return o; };
  reg({});
  assert.equal((await call('viewer')).s, 403);
  let o = await call('analyst'); assert.equal(o.s, 200);
  assert.equal(o.b.ad.available, false); assert.match(o.b.ad.reason, /no Active Directory sync/);
  assert.equal(o.b.entra.available, false); assert.match(o.b.entra.reason, /not configured/);
  id.replace({ synced: NOW, users: [{ sam: 'svc-x', uac: 512, member_of: [], priv_groups: [] }, { sam: 'nora.syn', uac: 512, mail: 'n@x', member_of: [], priv_groups: [] }], groups: [] });
  reg({ m365Graph: { data: () => ({ configured: true, updated: 'u', blocks: { apps: { ok: false, perm: 'Application.Read.All', error: 'permission not granted' } } }) } });
  o = await call('analyst');
  assert.deepEqual(o.b.ad.accounts.map((a) => a.name), ['svc-x']);
  assert.match(o.b.entra.reason, /grant Application\.Read\.All/);
});
