// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Active Directory computer objects over LDAPS (or LDAP + StartTLS — never cleartext), via ../ldap-client.js.
// Read-only: one simple bind with the discovery service account, then a paged subtree search. Nothing is written.
//   collect(cred, {ca, caFile, timeoutMs, maxEntries}) → {ok, computers[{dn, name, fqdn, os, os_version, last_logon, ou,
//                                                          enabled, is_dc}]} | {ok:false, error_class}
//   test(cred, opts) → {ok, latency_ms} | {ok:false, error_class}
//   mapEntry(entry) → computer (pure)
// Example: ldaps://dc01.example.com:636 (dial its IP), CA /etc/ssl/corp-hq/corp-ca.pem.
const L = require('../ldap-client');
const diag = require('../diag');

const ATTRS = ['cn', 'name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp', 'userAccountControl', 'distinguishedName', 'primaryGroupID'];
const DEFAULT_CA = '/etc/ssl/corp-hq/corp-ca.pem';

function ouOf(dn) {
  const parts = String(dn || '').split(/,(?=(?:OU|CN|DC)=)/i);
  const ous = parts.filter((p) => /^OU=/i.test(p)).map((p) => p.slice(3));
  return ous.length ? ous.join(' / ') : (parts.some((p) => /^CN=Computers$/i.test(p)) ? 'Computers' : null);
}

function mapEntry(e) {
  const g = (n) => L.ad.first(e, n);
  const uac = Number(g('userAccountControl')) || 0;
  const ms = L.ad.fileTimeToMs(g('lastLogonTimestamp'));
  const dn = e.dn || g('distinguishedName');
  const ou = ouOf(dn);
  return {
    dn, name: g('cn') || g('name') || L.ad.firstRdnValue(dn), fqdn: (g('dNSHostName') || '').toLowerCase() || null,
    os: g('operatingSystem') || null, os_version: g('operatingSystemVersion') || null,
    last_logon: ms ? new Date(ms).toISOString() : null, ou, enabled: !(uac & L.ad.UAC.ACCOUNTDISABLE),
    // primaryGroupID 516 = Domain Controllers (521 = read-only DCs); the OU name is the fallback hint
    is_dc: g('primaryGroupID') === '516' || g('primaryGroupID') === '521' || /domain controllers/i.test(ou || ''),
  };
}

// LDAP outcome → diagnostic code + stage. Distinguishes invalidCredentials (49) from insufficientAccessRights (50)
// so a missing read privilege no longer looks like a wrong password, and an untrusted TLS chain never reads as auth.
function classifyLdap(e) {
  const c = e && e.code;
  if (c === 49 || c === 'EMPTY_PASSWORD' || c === 'EMPTY_DN' || c === 48) return { code: 'auth', stage: 'auth', tlsTrusted: true };
  if (c === 50) return { code: 'authz', stage: 'authz', tlsTrusted: true };
  if (c === 'CA_FILE') return { code: 'config', stage: 'config' };
  if (e && /certificate|TLS|self.signed|altname/i.test(String(e.message || ''))) return { code: 'tls', stage: 'tls' };
  if (c === 'TIMEOUT') return { code: 'timeout', stage: 'connect' };
  if (e && e.transport) return { code: 'unreachable', stage: 'connect' };
  if (e instanceof L.LdapError && /invalid LDAP server URL|invalid ip/.test(e.message)) return { code: 'config', stage: 'config' };
  return { code: 'protocol', stage: 'read', tlsTrusted: true };
}
function errorClass(e) { return classifyLdap(e).code; }

function client(cred, o) {
  const t = cred.target || {};
  const servers = (t.servers || []).map((url, i) => (t.ip && i === 0 ? { url, ip: t.ip } : url));
  return L.createClient({ servers, ca: o.ca, caFile: o.ca ? undefined : (t.ca_file || o.caFile || DEFAULT_CA), timeoutMs: o.timeoutMs || 15000 });
}

async function collect(cred, o = {}) {
  const t0 = Date.now();
  try {
    const c = client(cred, o);
    const r = await c.run(async (conn) => {
      await conn.bind(cred.secret.bind_dn, cred.secret.password);
      return conn.search(cred.target.base_dn, { scope: 'sub', filter: '(objectClass=computer)', attributes: ATTRS, pageSize: 500, maxEntries: o.maxEntries || 50000 });
    });
    return { ok: true, computers: r.entries.map(mapEntry), latency_ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: errorClass(e), latency_ms: Date.now() - t0 }; }
}

async function test(cred, o = {}) {
  const t0 = Date.now();
  try {
    const c = client(cred, o);
    await c.run(async (conn) => {
      await conn.bind(cred.secret.bind_dn, cred.secret.password);
      return conn.search(cred.target.base_dn, { scope: 'base', filter: '(objectClass=*)', attributes: ['distinguishedName'], maxEntries: 1 });
    });
    return diag.result('ldap', { latency_ms: Date.now() - t0 });
  } catch (e) {
    const k = classifyLdap(e);
    return diag.fromError('ldap', Object.assign(new Error(e && e.message), k), { latency_ms: Date.now() - t0 });
  }
}

module.exports = { collect, test, mapEntry, ouOf, errorClass, DEFAULT_CA, ATTRS };
