// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Automatic certificate discovery from Asset Discovery (engine/cert-autodiscover.js): the open TLS ports discovery recorded
// on each device are read (TLS handshake, stubbed here) and what presents a certificate is added to the inventory as source
// "discovery" with the device's FQDN as SNI and the asset's owner / criticality, then scanned; a port without TLS is not
// probed again for 7 days; already-registered endpoints are skipped; ignored devices and non-TLS ports are not probed;
// "propose" mode adds nothing; the timer respects the interval; settings admin-only and validated; audited. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const NOW = Date.parse('2026-10-28T08:00:00Z');
const CERT = (cn) => ({ ok: true, subject: cn, issuer: 'Corp Issuing CA', names: [cn], name_ok: true, trusted: true, self_signed: false, not_after: NOW + 40 * 86400000, not_after_iso: '2026-12-07', key_type: 'rsa', key_bits: 2048, serial: 'AB' + cn.length, fingerprint256: 'FP:' + cn });
const TLS = { '10.0.0.10:443': CERT('portal.corp.syn'), '10.0.0.10:8443': CERT('admin.corp.syn'), '10.0.0.11:636': CERT('dc01.corp.syn'), '10.0.0.12:444': CERT('mail.corp.syn') };

async function setup(t) {
  const clock = { t: NOW }, probes = [];
  const read = async (h, p, sni) => { probes.push(h + ':' + p + (sni ? '#' + sni : '')); return TLS[h + ':' + p] || { ok: false, error: 'ECONNRESET' }; };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', readCert: read });
  const S = e.app.store;
  S.collection('assets').put({ id: 'ast_web', name: 'WEB01', type: 'server', status: 'in_use', owner: 'web-team@corp.syn', criticality: 'critical', lifecycle: [] });
  const D = S.collection('disc_devices');
  D.put({ id: 'dd_1', status: 'approved', asset_id: 'ast_web', ip: '10.0.0.10', ips: ['10.0.0.10'], hostname: 'web01', fqdn: 'portal.corp.syn', open_ports: [22, 80, 443, 3389, 8443] });
  D.put({ id: 'dd_2', status: 'new', ip: '10.0.0.11', ips: ['10.0.0.11'], hostname: 'dc01', fqdn: '', open_ports: [53, 389, 636] });
  D.put({ id: 'dd_3', status: 'new', ip: '10.0.0.12', ips: ['10.0.0.12'], hostname: 'mail', open_ports: [25, 444, 993] });
  D.put({ id: 'dd_4', status: 'ignored', ip: '10.0.0.13', ips: ['10.0.0.13'], hostname: 'printer', open_ports: [443] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, S, clock, probes, post: (p, b, who) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who) };
}
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('open TLS ports from discovery become inventory endpoints with SNI, owner and criticality, scanned at once', async (t) => {
  const { e, S, probes, post, get } = await setup(t);
  await post('/certs/endpoints', { host: '10.0.0.12', port: 444 }, OP);   // already registered by hand
  let v = (await get('/certs/autodiscovery')).json;
  assert.equal(v.coverage.devices_with_tls_ports, 3, 'the ignored device is left out'); assert.equal(v.coverage.open_tls_ports, 5); assert.equal(v.coverage.registered, 1);
  const r = await post('/certs/autodiscovery/run', {}, OP); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.added, 3); assert.equal(r.json.not_tls, 1, '993 answered without a certificate');
  assert.ok(!probes.some((p) => /:(22|80|3389|25|53|389)\b/.test(p)), 'only TLS ports are probed: ' + probes.join(','));
  assert.ok(probes.includes('10.0.0.10:443#portal.corp.syn'), 'the device FQDN is the SNI');
  assert.ok(!probes.some((p) => p.startsWith('10.0.0.13')) && !probes.some((p) => p.startsWith('10.0.0.12:444')), 'ignored device and registered endpoint not probed');
  const eps = S.collection('cert_endpoints').all((x) => x.source === 'discovery');
  const web = eps.find((x) => x.port === 443);
  assert.equal(web.sni, 'portal.corp.syn'); assert.equal(web.owner, 'web-team@corp.syn'); assert.equal(web.critical, true); assert.equal(web.asset_id, 'ast_web'); assert.equal(web.created_by, 'system:pki-discovery');
  assert.ok(S.collection('cert_scans').get(web.id).scan.ok, 'scanned at once');
  const inv = (await get('/certs', VIEW)).json; assert.ok(JSON.stringify(inv).includes('admin.corp.syn'), 'in the certificate inventory');
  // second run: nothing new, the non-TLS port is not probed again
  probes.length = 0;
  const r2 = await post('/certs/autodiscovery/run', {}, OP); assert.equal(r2.json.added, 0); assert.equal(r2.json.skipped_recent_not_tls, 1); assert.equal(probes.length, 0);
  v = (await get('/certs/autodiscovery')).json; assert.equal(v.coverage.registered, 4); assert.equal(v.coverage.from_discovery, 3);
  assert.equal(auditOf(e, 'certs.autodiscovery.run').length, 2); assert.ok(auditOf(e, 'certs.endpoint.add').some((a) => a.by === 'system:pki-discovery'));
});

test('propose mode adds nothing; settings admin only and validated; the timer respects the interval; unapproved devices can be left out', async (t) => {
  const { e, S, clock, post, get } = await setup(t);
  assert.equal((await get('/certs/autodiscovery', VIEW)).status, 403);
  assert.equal((await post('/certs/autodiscovery', { enabled: true }, OP)).status, 403, 'admin only');
  let r = await post('/certs/autodiscovery', { ports: [0] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^ports/);
  r = await post('/certs/autodiscovery', { mode: 'magic' }, ADM); assert.match(r.json.error, /^mode/);
  r = await post('/certs/autodiscovery', { enabled: true, mode: 'propose', every_hours: 6 }, ADM); assert.equal(r.status, 200);
  const x = await e.app.addons.certs.autodiscover.tick(); assert.equal(x.proposals.length, 4); assert.equal(S.collection('cert_endpoints').all().length, 0, 'propose adds nothing');
  assert.equal(await e.app.addons.certs.autodiscover.tick(), null, 'not again before the interval');
  clock.t += 7 * 3600000;
  await post('/certs/autodiscovery', { mode: 'add', include_unapproved: false }, ADM);
  const y = await e.app.addons.certs.autodiscover.tick(); assert.equal(y.added, 2, 'only the approved device (443 + 8443)');
  assert.ok(auditOf(e, 'certs.autodiscovery.settings').length === 2);
});

test('a slow probe answers "running" instead of holding the request past the gateway (HTTP 504), then the result is kept', async (t) => {
  const prev = process.env.SENTRA_CERT_WAIT_MS; process.env.SENTRA_CERT_WAIT_MS = '150'; t.after(() => { if (prev === undefined) delete process.env.SENTRA_CERT_WAIT_MS; else process.env.SENTRA_CERT_WAIT_MS = prev; });
  const slow = async (h, p) => { await new Promise((r) => setTimeout(r, 400)); return TLS[h + ':' + p] || { ok: false, error: 'ECONNRESET' }; };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3', readCert: slow });
  e.app.store.collection('assets').put({ id: 'ast_a', name: 'WEB01', type: 'server', status: 'in_use', mgmt_ip: '10.0.0.10', lifecycle: [] });
  e.app.store.collection('disc_devices').put({ id: 'dd_1', status: 'new', ip: '10.0.0.11', ips: ['10.0.0.11'], hostname: 'dc01', open_ports: [636] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  // manual probe of the register
  let r = await call('POST', '/certs/discover', {}, OP); assert.equal(r.status, 200); assert.equal(r.json.status, 'running', 'answered before the probe finished'); assert.ok(r.json.total >= 4);
  r = await call('POST', '/certs/discover', {}, OP); assert.equal(r.json.status, 'running', 'a second click joins the probe already running');
  await new Promise((ok) => setTimeout(ok, 700));
  r = await call('GET', '/certs/discover', undefined, OP); assert.equal(r.json.status, 'done'); assert.deepEqual(r.json.found.map((x) => x.subject).sort(), ['admin.corp.syn', 'portal.corp.syn']);
  assert.equal((await call('GET', '/certs/discover', undefined, VIEW)).status, 403);
  // automatic run from Asset Discovery
  r = await call('POST', '/certs/autodiscovery/run', {}, OP); assert.equal(r.json.status, 'running');
  assert.ok((await call('GET', '/certs/autodiscovery', undefined, OP)).json.running, 'progress shown');
  await new Promise((ok) => setTimeout(ok, 700));
  r = await call('GET', '/certs/autodiscovery', undefined, OP); assert.equal(r.json.running, null); assert.equal(r.json.last_run.added, 1);
});
