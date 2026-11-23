// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD sync reads the Exchange organisation's server objects (msExchExchangeServer in the configuration partition): name,
// FQDN from networkAddress, version, roles decoded from msExchCurrentServerRoles; a forest without Exchange gives null (not
// "no servers"). GET /identity/exchange-servers: analyst reads it, viewer refused. Fake LDAP, SYNTHETIC directory.
const test = require('node:test');
const assert = require('node:assert/strict');
const real = require('../engine/ad/ldap-client');
const { createAdSync } = require('../engine/ad/sync');
const routes = require('../engine/ad/routes');

const CFG = 'CN=Configuration,DC=corp,DC=syn';
const ent = (dn, attrs) => ({ dn, attrs: Object.fromEntries(Object.entries(attrs).map(([k, v]) => [k.toLowerCase(), [].concat(v)])) });
function fakeLdap(withExchange) {
  const searches = [];
  const conn = {
    server: { url: 'ldaps://dc1.corp.syn' },
    bind: async () => {}, rootDSE: async () => ent('', { configurationNamingContext: CFG }),
    search: async (base, o) => {
      searches.push([base, o.filter]);
      if (/^CN=Microsoft Exchange,CN=Services,/.test(base)) {
        if (!withExchange) throw new Error('0x20 no such object');
        return { entries: [ent('CN=EXCH01,CN=Servers,...', { cn: 'EXCH01', networkAddress: ['ncacn_vns_spp:EXCH01', 'ncacn_ip_tcp:EXCH01.corp.syn'], serialNumber: 'Version 15.2 (Build 1544.4)', msExchCurrentServerRoles: '54' }),
          ent('CN=EDGE01,CN=Servers,...', { cn: 'EDGE01', networkAddress: 'ncacn_ip_tcp:edge01.dmz.syn', serialNumber: 'Version 15.2 (Build 1544.4)', msExchCurrentServerRoles: '64' })], pages: 1 };
      }
      return { entries: [], pages: 1 };
    } };
  return { searches, ldap: { createClient: () => ({ run: (fn) => fn(conn) }), ad: real.ad, escapeFilter: real.escapeFilter, OID: real.OID } };
}
function identityStub() { let snap = { users: [] }; return { replace: (s) => { snap = s; }, snapshot: () => snap }; }
const CONF = { ad: { enabled: true, servers: ['ldaps://dc1.corp.syn'], caFile: '/x.pem', baseDN: 'DC=corp,DC=syn', bindDN: 'CN=svc-siem,DC=corp,DC=syn' }, secrets: { ad: { bind_password: 'synthetic' } } };

test('AD sync: Exchange servers from the configuration partition, roles decoded; no organisation = null', async () => {
  const f = fakeLdap(true), id = identityStub();
  const r = await createAdSync({ config: CONF, identity: id, ldap: f.ldap }).syncNow('test');
  assert.equal(r.ok, true, r.error);
  assert.deepEqual(id.snapshot().exchange_servers, [
    { name: 'EXCH01', fqdn: 'exch01.corp.syn', version: 'Version 15.2 (Build 1544.4)', roles: ['mailbox', 'client access', 'unified messaging', 'hub transport'] },
    { name: 'EDGE01', fqdn: 'edge01.dmz.syn', version: 'Version 15.2 (Build 1544.4)', roles: ['edge transport'] }]);
  assert.ok(f.searches.some(([b, flt]) => b === 'CN=Microsoft Exchange,CN=Services,' + CFG && flt === '(objectClass=msExchExchangeServer)'));
  const g = fakeLdap(false), id2 = identityStub();
  assert.equal((await createAdSync({ config: CONF, identity: id2, ldap: g.ldap }).syncNow('test')).ok, true, 'no Exchange organisation does not fail the sync');
  assert.equal(id2.snapshot().exchange_servers, null);
});

test('route: analyst reads the Exchange servers AD lists, viewer refused', async () => {
  const id = identityStub(); id.replace({ users: [], synced: 1, exchange_servers: [{ name: 'EXCH01', fqdn: 'exch01.corp.syn', version: 'x', roles: ['mailbox'] }] });
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { identity: id, config: {}, log: { info() {}, error() {} } });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const call = async (role) => { const o = {}; const ctx = { role, user: 'u', query: {}, params: {}, need(r) { if (RANK[role] < RANK[r]) { o.s = 403; return false; } return true; }, audit() {}, ok(x) { o.s = 200; o.b = x; return x; }, fail(c, m) { o.s = c; o.e = m; } }; await R['GET /api/soc/identity/exchange-servers'](ctx); return o; };
  assert.equal((await call('viewer')).s, 403);
  const a = await call('analyst'); assert.equal(a.s, 200); assert.equal(a.b.available, true); assert.equal(a.b.items[0].fqdn, 'exch01.corp.syn');
});
