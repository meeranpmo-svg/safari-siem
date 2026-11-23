// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco PSIRT openVuln for the switches / routers / ASAs of the AI Network Engineer (engine/cisco-support.js): versions
// from the CLI facts or the SNMP description, IOS-XE written as openVuln wants it, one query per distinct version, only
// version strings sent to Cisco (no serial, name or address), "no advisory" (404) is an empty list not an error, a client
// without the openVuln API is told what to tick, the token / advisory calls are the only ones allowed, the secret is not
// in the result or the audit record; routes: viewer reads, operator checks (audited), viewer refused, not configured = 409.
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createCiscoSupport, registerCiscoSupport, psirtKey, ciscoAllowed } = require('../engine/cisco-support');

const ADM = { user: 'syed', role: 'admin', ip: '' }, OP = { user: 'eng1', role: 'operator', ip: '' };
const DEVS = [
  { id: 'sw1', name: 'core-syn', vendor: 'cisco-ios', ip: '10.0.0.1', cli_facts: { version: '17.09.04a', serials: ['FDO1'] } },
  { id: 'sw2', name: 'acc-syn-1', vendor: 'cisco-ios', ip: '10.0.0.2', last: { system: { version: 'Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)' } } },
  { id: 'sw3', name: 'acc-syn-2', vendor: 'cisco-ios', ip: '10.0.0.3', last: { system: { version: 'Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)' } } },
  { id: 'fw1', name: 'asa-syn', vendor: 'cisco-asa', ip: '10.0.0.9', cli_facts: { version: '9.16(4)' } },
  { id: 'sw4', name: 'never-read', vendor: 'cisco-ios', ip: '10.0.0.4' },
  { id: 'pa1', name: 'pa-syn', vendor: 'paloalto', ip: '10.0.0.5', cli_facts: { version: '10.2.4' } }];

test('version keys: IOS, IOS-XE without leading zeros, ASA, NX-OS; nothing invented', () => {
  assert.deepEqual(psirtKey('cisco-ios', '17.09.04a', ''), { ostype: 'iosxe', version: '17.9.4a', key: 'iosxe:17.9.4a' });
  assert.equal(psirtKey('cisco-ios', '15.2(7)E3', 'Cisco IOS Software').key, 'ios:15.2(7)E3');
  assert.equal(psirtKey('cisco-asa', '9.16(4)', '').key, 'asa:9.16(4)');
  assert.equal(psirtKey('cisco-ios', '9.3(10)', 'Cisco NX-OS(tm) n9000').ostype, 'nxos');
  assert.equal(psirtKey('cisco-ios', '', ''), null); assert.equal(psirtKey('cisco-ios', '15.2; rm -rf', ''), null, 'a version that is not a version is not sent');
  assert.ok(ciscoAllowed('GET', 'https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=17.9.4a'));
  assert.ok(!ciscoAllowed('GET', 'https://apix.cisco.com/security/advisories/v2/all'), 'only the per-version query');
});

test('PSIRT check: one query per distinct version, only versions sent, 404 = no advisory, results per device; roles, audit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = [];
  const request = async (url, o) => {
    calls.push({ url, body: o.body || '' });
    if (url.endsWith('/oauth2/default/v1/token')) return { status: 200, json: { access_token: 'tok' } };
    if (/OSType\/iosxe\?version=17\.9\.4a$/.test(url)) return { status: 200, json: { advisories: [{ advisoryId: 'cisco-sa-syn-webui', advisoryTitle: 'IOS XE Web UI Privilege Escalation (SYN)', sir: 'Critical', cvssBaseScore: '10.0', cves: ['CVE-2023-20198', 'bad'], firstFixed: ['17.9.4a'], firstPublished: '2023-10-16T15:00:00', publicationUrl: 'https://sec.cloudapps.cisco.com/security/center/content/x' }, { advisoryId: 'cisco-sa-syn-low', advisoryTitle: 'Low one', sir: 'Medium', cvssBaseScore: '5.3', publicationUrl: 'javascript:alert(1)' }] } };
    if (/OSType\/ios\?/.test(url)) return { status: 404, json: { errorCode: 'NO_DATA_FOUND' } };
    if (/OSType\/asa\?/.test(url)) return { status: 200, json: { advisories: [{ advisoryId: 'cisco-sa-asa-syn', advisoryTitle: 'ASA VPN DoS (SYN)', sir: 'High', cvssBaseScore: 8.6 }] } };
    return { status: 500, json: null };
  };
  const C = createCiscoSupport(e.app, { request, noTimer: true, siemDevices: async () => DEVS, now: () => Date.parse('2026-10-24T08:00:00Z') });
  await assert.rejects(C.psirtCheck(OP), (x) => x.status === 409 && /Cisco API is not configured/.test(x.message));
  C.saveConfig({ api: { enabled: true, client_id: 'cid', client_secret: 'secret-SYN-1' } }, ADM);
  const r = await C.psirtCheck(OP);
  assert.equal(r.ok, true); assert.equal(r.devices, 5, 'Cisco devices only'); assert.equal(r.versions, 3, 'two switches on 15.2(7)E3: one query'); assert.equal(r.without_version, 1); assert.equal(r.advisories, 3);
  const q = calls.filter((c) => /advisories/.test(c.url));
  assert.equal(q.length, 3);
  assert.ok(q.every((c) => !/FDO1|10\.0\.0|core-syn|acc-syn/.test(c.url)), 'only version strings go to Cisco');
  const v = C.psirtView();
  const xe = v.versions.find((x) => x.key === 'iosxe:17.9.4a');
  assert.equal(xe.worst, 'Critical'); assert.equal(xe.advisories[0].id, 'cisco-sa-syn-webui'); assert.deepEqual(xe.advisories[0].cves, ['CVE-2023-20198']); assert.equal(xe.advisories[0].cvss, 10);
  assert.equal(xe.advisories[1].url, '', 'a link that is not a Cisco https page is dropped');
  assert.equal(v.versions.find((x) => x.key === 'ios:15.2(7)E3').count, 0, '404 NO_DATA_FOUND = no advisory, not an error');
  assert.equal(v.devices.find((d) => d.id === 'sw2').key, 'ios:15.2(7)E3'); assert.equal(v.devices.find((d) => d.id === 'sw4').key, null);
  const a = e.app.store.auditTail(10).find((x) => x.action === 'cisco.psirt.check');
  assert.ok(a && a.by === 'eng1' && a.detail.advisories === 3 && !JSON.stringify(a).includes('secret-SYN-1'));
  assert.ok(!JSON.stringify(v).includes('secret-SYN-1') && !JSON.stringify(r).includes('secret-SYN-1'));
});

test('PSIRT: a client without the openVuln API is told what to tick; routes and roles', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const request = async (url) => (url.endsWith('/token') ? { status: 200, json: { access_token: 'tok' } } : { status: 403, json: {} });
  const C = createCiscoSupport(e.app, { request, noTimer: true, siemDevices: async () => DEVS });
  C.saveConfig({ api: { enabled: true, client_id: 'cid', client_secret: 'secret-SYN-2' } }, ADM);
  const r = await C.psirtCheck(OP);
  assert.equal(r.ok, false); assert.match(r.error, /Cisco PSIRT openVuln API/); assert.equal(r.error_class, 'auth');
  // routes (the registered module, SIEM link absent in the test app → the check says so)
  registerCiscoSupport(e.app.srv, e.app);
  assert.equal((await e.req('POST', '/cisco-support/psirt/check', { role: 'viewer', body: {} })).status, 403);
  const v = await e.req('GET', '/cisco-support/psirt', { role: 'viewer' });
  assert.equal(v.status, 200); assert.ok(Array.isArray(v.json.versions));
  const c = await e.req('POST', '/cisco-support/psirt/check', { role: 'operator', body: {} });
  assert.equal(c.status, 409, 'not configured / no SIEM link: a clear 4xx/5xx, not a crash: ' + c.status);
  assert.ok(c.json && /SIEM|AI Network Engineer|not configured/.test(c.json.error), 'the reason, not "internal error": ' + (c.json && c.json.error));
});
