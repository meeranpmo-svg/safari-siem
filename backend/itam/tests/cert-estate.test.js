// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Certificate lifecycle across the estate (engine/cert-estate.js, pyengine/cert_estate.py): one row per certificate seen on
// the network, in Windows machine stores and in an AD CS CA's issued list (matched on the serial number), risks (expired and
// presented, expiring, weak key, SHA-1, self-signed, expired left in a store, issued but installed nowhere), the expiry
// timeline, alerts sent once per (certificate, threshold) through the platform relay to the list and the owner, the
// compliance report and its CSV (audited), roles and validation, a SIEM that does not answer named. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
const DAY = 86400000, NOW = Date.parse('2026-10-28T08:00:00Z');
const iso = (d) => new Date(NOW + d * DAY).toISOString();
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const PRESENT = {
  'portal.corp.syn:443': { ok: true, subject: 'portal.corp.syn', issuer: 'Corp Issuing CA', names: ['portal.corp.syn'], name_ok: true, trusted: true, self_signed: false, not_after: NOW + 10 * DAY, key_type: 'rsa', key_bits: 2048, serial: '0A1B', fingerprint256: 'FP:1' },
  'old.corp.syn:443': { ok: true, subject: 'old.corp.syn', issuer: 'old.corp.syn', names: ['old.corp.syn'], name_ok: true, trusted: false, self_signed: true, not_after: NOW - 3 * DAY, key_type: 'rsa', key_bits: 1024, serial: '0C0D', fingerprint256: 'FP:2' },
};
const stubRead = async (h, p) => { const c = PRESENT[h + ':' + p]; return c ? Object.assign({}, c, { not_after_iso: new Date(c.not_after).toISOString().slice(0, 10) }) : { ok: false, error: 'ECONNREFUSED' }; };
let SIEM;
const siemOk = () => ({ available: true, hosts: [
  { host: 'web01.corp.syn', at: iso(0), settings: { certs: [
    { store: 'My', subject: 'portal.corp.syn', issuer: 'Corp Issuing CA', serial: '00000A1B', thumbprint: 'T1', not_before: iso(-355), not_after: iso(10), has_key: true, key_alg: 'RSA', key_bits: 2048, sig_alg: 'sha256RSA', self_signed: false, sans: ['portal.corp.syn'], eku: ['Server Authentication'] },
    { store: 'My', subject: 'legacy.corp.syn', issuer: 'Corp Issuing CA', serial: '0E0F', thumbprint: 'T2', not_before: iso(-800), not_after: iso(-40), has_key: true, key_alg: 'RSA', key_bits: 2048, sig_alg: 'sha1RSA', self_signed: false, sans: [], eku: [] }] } },
  { host: 'ca01.corp.syn', at: iso(0), settings: { certs: [], ca_issued: [
    { request_id: '17', cn: 'portal.corp.syn', not_after: iso(10), template: 'WebServer', serial: '0a1b' },
    { request_id: '18', cn: 'spare.corp.syn', not_after: iso(20), template: 'WebServer', serial: '1111' }] } },
  { host: 'old-srv.corp.syn', at: iso(0), settings: { os: {} } }] });

async function setup(t) {
  SIEM = siemOk;
  const mails = [];
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: PY, readCert: stubRead, certSiem: async () => SIEM(), privacyOffice: { send: async (s, m) => { mails.push(m); return { accepted: m.to }; } } });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who = OP) => call('POST', p, b, who), get = (p, who = OP) => call('GET', p, undefined, who);
  await post('/certs/endpoints', { host: 'portal.corp.syn', port: 443, owner: 'pki@corp.syn', critical: true, issuer_kind: 'adcs' });
  await post('/certs/endpoints', { host: 'old.corp.syn', port: 443 });
  await post('/certs/scan', {});
  return { e, mails, post, get };
}
const row = (v, subj) => v.items.find((x) => x.subject === subj);
const keys = (x) => x.risks.map((r) => r.key);

test('one row per certificate across network, keystores and the CA, with risks', async (t) => {
  const { get } = await setup(t);
  const r = await get('/certs/estate', VIEW); assert.equal(r.status, 200, r.raw);
  const v = r.json;
  const p = row(v, 'portal.corp.syn');
  assert.deepEqual(p.sources, ['ca', 'keystore', 'network'], 'the same serial seen in three places is one row');
  assert.equal(p.places.length, 3); assert.ok(keys(p).includes('expiring')); assert.equal(p.owner, 'pki@corp.syn');
  const o = row(v, 'old.corp.syn');
  assert.ok(['expired', 'weak_key', 'self_signed'].every((k) => keys(o).includes(k)), keys(o).join()); assert.equal(o.risk, 'high');
  const l = row(v, 'legacy.corp.syn'); assert.ok(keys(l).includes('expired_installed') && keys(l).includes('sha1'));
  assert.ok(keys(row(v, 'spare.corp.syn')).includes('expiring_unplaced'), 'issued by the CA but installed nowhere the platform reads');
  assert.equal(v.timeline.find((b) => b.bucket === '8-30').count, 1); assert.equal(v.timeline.find((b) => b.bucket === 'expired').count, 2);
  assert.ok(v.sources.every((s) => s.connected));
});

test('a SIEM that does not answer: keystores and CA named, network still shown', async (t) => {
  const { get } = await setup(t);
  SIEM = () => ({ _down: 'the SIEM did not answer' });
  const v = (await get('/certs/estate', VIEW)).json;
  const ks = v.sources.find((s) => s.id === 'keystore'); assert.equal(ks.connected, false); assert.match(ks.reason, /did not answer/);
  assert.deepEqual(row(v, 'portal.corp.syn').sources, ['network']);
});

// bug fix ("internal error" across the four pillars): the SIEM link throws when the SIEM is unreachable (503), and that used
// to fail the whole estate. Now the keystores and the CA are named as not reachable and the network certificates still show.
test('a SIEM link that throws: the estate still answers, keystores named, network shown', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: PY, readCert: stubRead });
  e.app.discovery = Object.assign(e.app.discovery || {}, { siem: { call: async () => { throw Object.assign(new Error('SIEM link: HTTP 503'), { status: 503 }); } } });
  await e.req('POST', '/certs/endpoints', Object.assign({ body: { host: 'portal.corp.syn', port: 443 } }, OP));
  await e.req('POST', '/certs/scan', Object.assign({ body: {} }, OP));
  const r = await e.req('GET', '/certs/estate', VIEW);
  assert.equal(r.status, 200, r.text);
  const ks = r.json.sources.find((s) => s.id === 'keystore'); assert.equal(ks.connected, false); assert.match(ks.reason, /SIEM did not answer.*503/);
  assert.deepEqual(row(r.json, 'portal.corp.syn').sources, ['network']);
});

test('alerts: settings validated, admin only; sent once per threshold to the list and the owner; audited', async (t) => {
  const { e, mails, post, get } = await setup(t);
  assert.equal((await post('/certs/alerts', { enabled: true, recipients: ['pki-team@corp.syn'] }, OP)).status, 403, 'admin only');
  assert.equal((await get('/certs/alerts', VIEW)).status, 403);
  let r = await post('/certs/alerts', { enabled: true, recipients: ['not-an-address'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^recipients/);
  r = await post('/certs/alerts', { enabled: true, thresholds: [400] }, ADM); assert.match(r.json.error, /^thresholds/);
  r = await post('/certs/alerts', { enabled: true, recipients: ['pki-team@corp.syn'], thresholds: [30, 7], notify_owners: true }, ADM); assert.equal(r.status, 200, r.raw);
  r = await post('/certs/alerts/run', {}, ADM); assert.equal(r.json.sent, 0); assert.match(JSON.stringify(r.json), /e-mail is off/, 'e-mail off in the relay: nothing is recorded as sent');
  await post('/pdpl/office/notify', { email_enabled: true, smtp: { host: 'smtp.corp.syn', port: 25, from: 'grc@corp.syn' } }, ADM);
  r = await post('/certs/alerts/run', {}, ADM); assert.equal(r.status, 200, r.raw);
  assert.ok(r.json.sent >= 3, 'expiring + expired installed certificates: ' + JSON.stringify(r.json));
  const portal = mails.find((m) => /portal\.corp\.syn/.test(m.subject));
  assert.ok(portal && portal.to.includes('pki-team@corp.syn') && portal.to.includes('pki@corp.syn'), 'list + owner');
  assert.match(portal.subject, /^\[critical\]/); assert.ok(!mails.some((m) => /spare\.corp\.syn/.test(m.subject)), 'a certificate installed nowhere is not an outage alert');
  const n = mails.length;
  r = await post('/certs/alerts/run', {}, ADM); assert.equal(r.json.sent, 0); assert.equal(mails.length, n, 'sent once per threshold');
  assert.ok(e.app.store.auditTail(200).some((a) => a.action === 'certs.alerts.sent') && e.app.store.auditTail(200).some((a) => a.action === 'certs.alerts.settings'));
  const v = (await get('/certs/alerts', OP)).json; assert.equal(v.due.length, 0); assert.ok(v.sent.length >= 3);
});

test('compliance report and export', async (t) => {
  const { e, get } = await setup(t);
  const r = (await get('/certs/report', VIEW)).json.report;
  assert.equal(r.by_source.keystore, 2); assert.equal(r.by_source.ca, 2); assert.equal(r.endpoints_with_owner_pct, 50);
  assert.ok(r.controls.find((c) => /strong keys/.test(c.what)).ok === false && r.controls.find((c) => /expired certificate/.test(c.what)).ok === false);
  assert.ok(r.within_policy_pct < 100);
  assert.equal((await get('/certs/report/export', VIEW)).status, 403);
  const x = await get('/certs/report/export', OP); assert.equal(x.status, 200); assert.match(x.json.csv, /"portal\.corp\.syn"/); assert.match(x.json.filename, /^certificate-inventory-/);
  assert.ok(e.app.store.auditTail(200).some((a) => a.action === 'certs.report.export'));
});
