// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD & Exchange settings from the portal: validation, files written (atomic), applied live, secrets write-only, test steps.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAdSettings } = require('../engine/ad/settings');
const { writeJsonAtomic } = require('../engine/onboard/store');

function setup(extra) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adset-'));
  const cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ syslog: { udp: { port: 5514 } }, ad: { enabled: false, sync_minutes: 60 } }));
  fs.writeFileSync(secFile, JSON.stringify({ proxy_secret: 'x'.repeat(32) }));
  const config = { ad: { enabled: false, sync_minutes: 60, servers: [] }, m365: { enabled: false } };
  Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } });
  Object.defineProperty(config, 'secrets', { value: { proxy_secret: 'x'.repeat(32), ad: { bind_password: '' }, m365: {} }, writable: true });
  const calls = { reconf: 0, m365: 0 };
  const adSync = { status: () => ({ enabled: config.ad.enabled }), reconfigure: () => { calls.reconf++; } };
  const S = createAdSettings(Object.assign({ config, adSync, writeJson: writeJsonAtomic, reloadM365: async () => { calls.m365++; } }, extra || {}));
  return { S, config, cfgFile, secFile, calls, dir };
}

test('AD settings: validate, write both files, apply live, never return secrets', async () => {
  const { S, config, cfgFile, secFile, calls } = setup();
  await assert.rejects(S.save({ ad: { enabled: true, servers: ('ldap://dc-hqa.' + 'corp-hq.com' + ':389') } }, 'adm'), /fill in/);
  await assert.rejects(S.save({ ad: { servers: 'http://192.168.12.51:389' } }, 'adm'), /invalid LDAP server URL/);
  await assert.rejects(S.save({ ad: { caFile: 'relative/path.pem' } }, 'adm'), /absolute path/);
  const r = await S.save({ ad: { enabled: true, servers: [{ url: ('ldap://dc-hqa.' + 'corp-hq.com' + ':389'), ip: '192.168.12.52' }], caFile: '/etc/sentra-itam/ad-ca-bundle.pem', baseDN: 'DC=corp-hq,DC=com', bindDN: 'CN=svc-zyberon,OU=Service Accounts,DC=corp-hq,DC=com', bind_password: 'Secr3t-Bind!', sync_minutes: 30 } }, 'adm');
  assert.deepEqual(r.saved, ['ad', 'ad.bind_password']); assert.equal(r.ad_applied, true); assert.equal(calls.reconf, 1);
  const f = JSON.parse(fs.readFileSync(cfgFile, 'utf8')); assert.equal(f.ad.enabled, true); assert.equal(f.ad.sync_minutes, 30); assert.equal(f.syslog.udp.port, 5514, 'other settings kept');
  assert.equal(JSON.parse(fs.readFileSync(secFile, 'utf8')).ad.bind_password, 'Secr3t-Bind!'); assert.equal(config.secrets.ad.bind_password, 'Secr3t-Bind!');
  assert.ok(!fs.readFileSync(cfgFile, 'utf8').includes('Secr3t'), 'password only in secrets.json');
  const v = S.view(); assert.equal(v.ad.password_set, true); assert.ok(!JSON.stringify(v).includes('Secr3t'));
  assert.equal(v.ad.servers[0].ip, '192.168.12.52');
  // empty password field = keep the stored one
  await S.save({ ad: { sync_minutes: 45, bind_password: '' } }, 'adm'); assert.equal(config.secrets.ad.bind_password, 'Secr3t-Bind!');
});

test('Exchange Online settings: GUIDs, write-only secret, collector reloaded', async () => {
  const { S, secFile, calls } = setup();
  await assert.rejects(S.save({ m365: { enabled: true, tenant: '00000000-1111-2222-3333-444444444444' } }, 'adm'), /fill in tenant/);
  await assert.rejects(S.save({ m365: { tenant: 'not a guid' } }, 'adm'), /tenant/);
  const r = await S.save({ m365: { enabled: true, tenant: '00000000-1111-2222-3333-444444444444', client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', client_secret: 'cs~very.secret' } }, 'adm');
  assert.equal(r.m365_applied, true); assert.equal(calls.m365, 1); assert.equal(r.m365.secret_set, true); assert.ok(!JSON.stringify(r).includes('very.secret'));
  assert.equal(JSON.parse(fs.readFileSync(secFile, 'utf8')).m365.client_secret, 'cs~very.secret');
});

test('connection test: CA file, TLS per DC (name hint), bind refused / ok', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adca-')), ca = path.join(dir, 'ca.pem'); fs.writeFileSync(ca, '-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n');
  let bindOk = false;
  const ldap = Object.assign({}, require('../engine/ad/ldap-client'), {
    createClient: ({ servers }) => ({
      connect: async () => { if (/192\.168/.test(JSON.stringify(servers)) && !/dc-hqa/.test(JSON.stringify(servers))) throw new Error('Hostname/IP does not match certificate\'s altnames'); return { sock: { getPeerCertificate: () => ({ valid_to: 'Sep 24 05:48:21 2027 GMT' }) }, close() {} }; },
      run: async (fn) => fn({ bind: async () => { if (!bindOk) throw new Error('bind failed: invalidCredentials (49)'); }, search: async (b, o) => ({ entries: o.scope === 'base' ? [{}] : [{}, {}, {}], pages: 1 }) }),
    }),
  });
  const { S } = setup({ ldap });
  const base = { servers: ['ldap://192.168.12.52:389', { url: ('ldap://dc-hqa.' + 'corp-hq.com' + ':389'), ip: '192.168.12.52' }], caFile: ca, baseDN: 'DC=corp-hq,DC=com', bindDN: ('svc@' + 'corp-hq.com'), bind_password: 'pw' };
  let r = await S.test({ ad: base });
  assert.equal(r.ok, false); assert.match(r.steps[1].text, /use the DC name from its certificate/); assert.equal(r.steps[2].ok, true); assert.match(r.steps.at(-1).text, /wrong bind account or password/);
  bindOk = true; r = await S.test({ ad: Object.assign({}, base, { servers: [base.servers[1]] }) });
  assert.equal(r.ok, true, JSON.stringify(r.steps)); assert.match(r.steps.at(-1).text, /3 user accounts readable/);
  r = await S.test({ ad: Object.assign({}, base, { caFile: '/nonexistent/ca.pem' }) }); assert.match(r.steps[0].text, /ad-tls-check/);
});
