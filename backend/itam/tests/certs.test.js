// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Certificate lifecycle (engine/certs.js; the rules in Python - pyengine/cert_rules.py, run for real here) and the AI PKI
// Engineer: the reader reads a real TLS endpoint (subject, issuer, names, key, chain, expiry; nothing sent to the service);
// lifecycle states valid / renew-due (issuer lead time) / expiring / expired; weak key, name mismatch, untrusted public
// chain and self-signed-on-critical are findings; a renewal moves open → requested → issued → installed and is VERIFIED only
// by a scan that sees the new certificate; roles (viewer reads, operator acts, admin policy), validation names the field,
// every write audited; discovery proposes assets' TLS endpoints; the duty desk raises the findings. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const tls = require('node:tls');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { readCert } = require('../engine/certs');
const { makeCA, makeServerCert } = require('./helpers/x509');

const PY = process.env.PYTHON || 'python3';
const DAY = 86400000;
let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
// the stub reader: what each synthetic endpoint presents now
const PRESENT = {};
const cert = (o) => Object.assign({ ok: true, subject: 'portal.synthetic.test', issuer: 'Synthetic Issuing CA', names: ['portal.synthetic.test'], name_ok: true, trusted: true, self_signed: false,
  not_after: clock + 200 * DAY, key_type: 'rsa', key_bits: 2048, serial: 'AA01', fingerprint256: 'FP:01', chain: ['Synthetic Issuing CA'] }, o);
const stubRead = async (host, port) => { const p = PRESENT[host + ':' + port]; if (!p) return { ok: false, error: 'ECONNREFUSED' }; const c = Object.assign({}, p); c.not_after_iso = new Date(c.not_after).toISOString().slice(0, 10); return c; };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, readCert: stubRead });
  return { e, D };
}
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
const epOf = (v, id) => v.endpoints.find((x) => x.id === id);

test('the reader reads a real TLS endpoint: names, key, chain, expiry, trust', async (t) => {
  const ca = makeCA('Synthetic Root'), sc = makeServerCert(ca, { cn: 'localhost', dns: ['localhost'], ip: ['127.0.0.1'], days: 20 });
  const srv = tls.createServer({ key: sc.key, cert: sc.cert }, (s) => s.end());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); t.after(() => srv.close());
  const r = await readCert('localhost', srv.address().port, '', 4000);
  assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(r.subject, 'localhost'); assert.ok(r.names.includes('localhost')); assert.equal(r.name_ok, true);
  assert.equal(r.key_type, 'rsa'); assert.equal(r.key_bits, 2048); assert.equal(r.trusted, false, 'a private CA is not publicly trusted'); assert.equal(r.self_signed, false);
  assert.ok(Math.abs(r.not_after - (Date.now() + 20 * DAY)) < 2 * DAY); assert.match(r.fingerprint256, /^[0-9A-F:]+$/);
  const no = await readCert('127.0.0.1', 1, '', 2000); assert.equal(no.ok, false);
});

test('lifecycle states, findings, roles, validation and audit', async (t) => {
  const { e, D } = await setup(t);
  PRESENT['a.synthetic.test:443'] = cert({ not_after: clock + 200 * DAY });                                     // valid
  PRESENT['b.synthetic.test:443'] = cert({ not_after: clock + 40 * DAY, issuer: "R3 · Let's Encrypt", fingerprint256: 'FP:B1' }); // acme: inside 30? no - 40 days: valid
  PRESENT['c.synthetic.test:443'] = cert({ not_after: clock + 50 * DAY, fingerprint256: 'FP:C1' });              // adcs (private, untrusted guessed): lead 45 → valid; manual (trusted) lead 60 → renew-due
  PRESENT['d.synthetic.test:8443'] = cert({ not_after: clock + 10 * DAY, key_bits: 1024, name_ok: false, names: ['other.synthetic.test'] });
  PRESENT['e.synthetic.test:443'] = cert({ not_after: clock - 3 * DAY });
  PRESENT['f.synthetic.test:443'] = cert({ self_signed: true, trusted: false, issuer: 'f.synthetic.test' });
  // validation and roles
  let r = await post(e, '/certs/endpoints', { host: 'a.synthetic.test' }); assert.equal(r.status, 400); assert.match(r.json.error, /port/);
  r = await post(e, '/certs/endpoints', { host: 'bad host!', port: 443 }); assert.equal(r.status, 400); assert.match(r.json.error, /host/);
  r = await post(e, '/certs/endpoints', { host: 'a.synthetic.test', port: 99999 }); assert.equal(r.status, 400); assert.match(r.json.error, /port/);
  r = await post(e, '/certs/endpoints', { host: 'a.synthetic.test', port: 443, issuer_kind: 'magic' }); assert.equal(r.status, 400); assert.match(r.json.error, /issuer_kind/);
  assert.equal((await post(e, '/certs/endpoints', { host: 'a.synthetic.test', port: 443 }, { user: 'v', role: 'viewer' })).status, 403);
  const ids = {};
  for (const [h, p, extra] of [['a.synthetic.test', 443, {}], ['b.synthetic.test', 443, {}], ['c.synthetic.test', 443, { issuer_kind: 'manual' }], ['d.synthetic.test', 8443, { deploy_target: 'iis' }], ['e.synthetic.test', 443, {}], ['f.synthetic.test', 443, { critical: true }], ['gone.synthetic.test', 443, {}]]) {
    r = await post(e, '/certs/endpoints', Object.assign({ host: h, port: p, injected: 'x' }, extra)); assert.equal(r.status, 200, JSON.stringify(r.json)); ids[h] = r.json.id; assert.equal(r.json.injected, undefined);
  }
  assert.equal((await post(e, '/certs/endpoints', { host: 'A.synthetic.test', port: 443 })).status, 409, 'duplicate host:port refused');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'certs.endpoint.add' && x.by === 'nora.syn'));
  let v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  assert.equal(v.engine, 'python'); assert.equal(epOf(v, ids['a.synthetic.test']).state, 'not-scanned');
  assert.equal((await post(e, '/certs/scan', {}, { user: 'v', role: 'viewer' })).status, 403);
  const s = await post(e, '/certs/scan', {}); assert.equal(s.status, 200); assert.equal(s.json.scanned, 7); assert.equal(s.json.failed, 1);
  assert.ok(e.app.store.auditTail(5).some((x) => x.action === 'certs.scan' && x.detail.read === 6));
  v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  assert.equal(epOf(v, ids['a.synthetic.test']).state, 'valid');
  assert.equal(epOf(v, ids['b.synthetic.test']).issuer_kind, 'acme', 'guessed from the issuer'); assert.equal(epOf(v, ids['b.synthetic.test']).state, 'valid');
  assert.equal(epOf(v, ids['c.synthetic.test']).state, 'renew-due', 'manual order: 60-day lead time');
  assert.equal(epOf(v, ids['d.synthetic.test']).state, 'expiring');
  assert.equal(epOf(v, ids['e.synthetic.test']).state, 'expired');
  assert.equal(epOf(v, ids['f.synthetic.test']).issuer_kind, 'self');
  assert.equal(epOf(v, ids['gone.synthetic.test']).state, 'unreachable');
  const keys = v.findings.map((f) => f.key).join(' ');
  for (const k of [ids['e.synthetic.test'] + ':expired', ids['d.synthetic.test'] + ':expiring', ids['d.synthetic.test'] + ':weak-key', ids['d.synthetic.test'] + ':name-mismatch', ids['c.synthetic.test'] + ':renew-due', ids['f.synthetic.test'] + ':self-signed', ids['gone.synthetic.test'] + ':unreachable'])
    assert.ok(keys.includes(k), k + ' in ' + keys);
  assert.equal(v.findings[0].severity, 'critical'); assert.equal(v.counts.expired, 1);
  assert.match(v.automation.issuance, /ACME, AD CS/); assert.match(v.automation.installation, /Palo Alto and FortiGate/);
  // the duty desk raises them for the AI PKI Engineer
  await D.patrol('pki');
  const items = D.list({ engineer: 'pki', status: 'open', limit: 100 }).items;
  assert.ok(items.some((x) => /EXPIRED/.test(x.title)) && items.length >= 7, items.length + ' work items');
  // policy: admin only, bounded
  assert.equal((await post(e, '/certs/policy', { lead_days: { manual: 30 } })).status, 403);
  assert.match((await post(e, '/certs/policy', { lead_days: { manual: 3 } }, ADM)).json.error, /lead_days\.manual/);
  assert.match((await post(e, '/certs/policy', { lead_days: { magic: 30 } }, ADM)).json.error, /issuer kind/);
  assert.equal((await post(e, '/certs/policy', { lead_days: { manual: 30 } }, ADM)).status, 200);
  v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  assert.equal(epOf(v, ids['c.synthetic.test']).state, 'valid', 'shorter lead time: no longer due');
  // retire needs a reason
  assert.match((await post(e, '/certs/endpoints/' + ids['gone.synthetic.test'] + '/retire', {})).json.error, /reason/);
  assert.equal((await post(e, '/certs/endpoints/' + ids['gone.synthetic.test'] + '/retire', { reason: 'decommissioned (synthetic)' })).status, 200);
  assert.ok(!(await e.req('GET', '/certs', { role: 'viewer' })).json.endpoints.some((x) => x.id === ids['gone.synthetic.test']));
});

test('a renewal is verified only by a scan that sees the new certificate', async (t) => {
  const { e } = await setup(t);
  PRESENT['r.synthetic.test:443'] = cert({ not_after: clock + 10 * DAY, fingerprint256: 'FP:OLD', serial: 'OLD1' });
  const ep = (await post(e, '/certs/endpoints', { host: 'r.synthetic.test', port: 443, deploy_target: 'linux-nginx' })).json;
  assert.equal((await post(e, '/certs/renewals', { endpoint_id: ep.id })).status, 409, 'scan first');
  await post(e, '/certs/scan', { id: ep.id });
  const rn = (await post(e, '/certs/renewals', { endpoint_id: ep.id, ticket: 'CHG-SYN-1' })).json;
  assert.equal(rn.status, 'open'); assert.equal(rn.old_fingerprint, 'FP:OLD');
  assert.equal((await post(e, '/certs/renewals', { endpoint_id: ep.id })).status, 409, 'one open renewal per endpoint');
  assert.match((await post(e, '/certs/renewals/' + rn.id, { status: 'verified' })).json.error, /status/, 'verified cannot be set by hand');
  assert.equal((await post(e, '/certs/renewals/' + rn.id, { status: 'installed' })).status, 409, 'no skipping steps');
  for (const st of ['requested', 'issued', 'installed']) assert.equal((await post(e, '/certs/renewals/' + rn.id, { status: st, note: st + ' (synthetic)' })).status, 200);
  // "installed" but the server still presents the old certificate: not verified
  await post(e, '/certs/scan', { id: ep.id });
  let v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  assert.equal(v.renewals.find((x) => x.id === rn.id).status, 'installed');
  assert.ok(v.findings.some((f) => f.key === ep.id + ':expiring'), 'still expiring');
  // the new certificate is live: the next scan verifies the renewal and the finding goes
  PRESENT['r.synthetic.test:443'] = cert({ not_after: clock + 90 * DAY, fingerprint256: 'FP:NEW', serial: 'NEW1' });
  await post(e, '/certs/scan', { id: ep.id });
  v = (await e.req('GET', '/certs', { role: 'viewer' })).json;
  const done = v.renewals.find((x) => x.id === rn.id);
  assert.equal(done.status, 'verified'); assert.equal(done.new_fingerprint, 'FP:NEW'); assert.match(done.history.at(-1).note, /NEW1/);
  assert.equal(epOf(v, ep.id).state, 'valid'); assert.ok(!v.findings.some((f) => f.key.startsWith(ep.id + ':')));
  const au = e.app.store.auditTail(30).map((x) => x.action);
  for (const a of ['certs.renewal.open', 'certs.renewal.requested', 'certs.renewal.issued', 'certs.renewal.installed', 'certs.renewal.verified']) assert.ok(au.includes(a), a);
  // cancel needs a note
  PRESENT['s.synthetic.test:443'] = cert({ fingerprint256: 'FP:S' });
  const ep2 = (await post(e, '/certs/endpoints', { host: 's.synthetic.test', port: 443 })).json; await post(e, '/certs/scan', { id: ep2.id });
  const rn2 = (await post(e, '/certs/renewals', { endpoint_id: ep2.id })).json;
  assert.match((await post(e, '/certs/renewals/' + rn2.id, { status: 'cancelled' })).json.error, /note/);
  assert.equal((await post(e, '/certs/renewals/' + rn2.id, { status: 'cancelled', note: 'not needed (synthetic)' })).status, 200);
});

test('discovery probes the register\'s networked assets and proposes what answers', async (t) => {
  const { e } = await setup(t);
  e.app.assets.create({ name: 'SRV-SYN-WEB', type: 'server', status: 'in_use', mgmt_ip: '10.99.0.5' }, ADM);
  e.app.assets.create({ name: 'SRV-SYN-DB', type: 'server', status: 'in_use', mgmt_ip: '10.99.0.6' }, ADM);
  PRESENT['10.99.0.5:443'] = cert({ subject: 'web.synthetic.test' }); PRESENT['10.99.0.6:636'] = cert({ subject: 'dc.synthetic.test' });
  assert.equal((await post(e, '/certs/discover', {}, { user: 'v', role: 'viewer' })).status, 403);
  const d = await post(e, '/certs/discover', {});
  assert.equal(d.status, 200); assert.equal(d.json.probed, 8);
  assert.deepEqual(d.json.found.map((x) => x.host + ':' + x.port).sort(), ['10.99.0.5:443', '10.99.0.6:636']);
  assert.equal(d.json.found[0].label.startsWith('SRV-SYN'), true);
  assert.equal((await e.req('GET', '/certs', { role: 'viewer' })).json.endpoints.length, 0, 'proposals only: nothing added');
  assert.ok(e.app.store.auditTail(5).some((x) => x.action === 'certs.discover' && x.detail.found === 2));
});
