// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Regression tests for the pre-go-live security review (Oct 2026), IT Asset Management side. Each fails on the code before
// its fix: service identities passing as people in four-eyes · privileged AD groups offered to joiners when their name has
// no "admin" · enrolment tokens stored in clear and revoked by any prefix · the database credential test ignoring the
// credential's TLS setting · secrets reaching the journal through log calls · the full AI prompt kept in the audit trail.
// (The pin-before-send, link-check SSRF and help-desk regex fixes have their tests in cert-install, asset-links and
// desksupport.) SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');

const ADM = { user: 'syed', role: 'admin' };

test('four-eyes: service and command-line identities never count as a person (same rule as the SIEM)', () => {
  const { isHuman } = require('../engine/approve-scopes');
  for (const u of ['system', 'duty', 'sentra-siem-ad@srv01', 'sentra-itam-sync', 'svc-backup', 'ai:itam']) assert.equal(isHuman(u), false, u);
  for (const u of ['nora.syn', 'aisha.syn', 'systemadmin.syn', 'sara']) assert.equal(isHuman(u), true, u);
  const a = fs.readFileSync(path.join(__dirname, '../engine/approve-scopes.js'), 'utf8').match(/const MACHINE = .*$/m)[0];
  let b = null; try { b = fs.readFileSync(path.join(process.env.SENTRA_SIEM_DIR || path.join(__dirname, '../../siem'), 'engine/approvers/scopes.js'), 'utf8').match(/const MACHINE = .*$/m); } catch (e) { b = null; /* the SIEM repository is not checked out next to this one: compared when it is */ }
  if (b) assert.equal(a, b[0], 'the two engines decide "a person" the same way');
});

test('onboarding never grants a privileged group, whatever its name', () => {
  const { PRIVILEGED } = require('../engine/onboarding-ad');
  for (const g of ['Domain Admins', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'Group Policy Creator Owners', 'Organization Management', 'Exchange Trusted Subsystem', 'DnsAdmins', 'Cert Publishers', 'Remote Management Users']) assert.ok(PRIVILEGED.test(g), g);
  for (const g of ['Finance Users', 'Claims Team', 'Operations Team', 'VPN Users']) assert.ok(!PRIVILEGED.test(g), g);
});

test('enrolment tokens: stored as a hash, never in clear; revoke needs the listed 8-character prefix', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const r = await e.req('POST', '/settings/agent-tokens', Object.assign({ body: { note: 'synthetic' } }, ADM));
  assert.equal(r.status, 200, r.raw); const token = r.json.token;
  const recs = e.app.store.collection('enrol_tokens').all();
  assert.ok(recs.length === 1 && recs[0].id !== token && !JSON.stringify(recs).includes(token), 'the token is not in the state');
  const dir = e.app.store.dir; e.app.store.snapshot && e.app.store.snapshot();
  for (const f of fs.readdirSync(dir).filter((x) => /enrol_tokens/.test(x))) assert.ok(!fs.readFileSync(path.join(dir, f), 'utf8').includes(token), f + ' holds no token');
  assert.equal((await e.req('POST', '/settings/agent-tokens/' + token.slice(0, 1) + '/revoke', Object.assign({ body: {} }, ADM))).status, 400, 'a 1-character prefix is refused');
  assert.equal((await e.req('POST', '/settings/agent-tokens/' + token.slice(0, 8) + '/revoke', Object.assign({ body: {} }, ADM))).status, 200);
  assert.equal(e.app.store.collection('enrol_tokens').all()[0].revoked, true);
});

test('the database credential test uses the credential\'s own TLS setting', () => {
  const src = fs.readFileSync(path.join(__dirname, '../engine/discovery/index.js'), 'utf8');
  const call = src.slice(src.indexOf("if (meta.kind === 'db_login') {"), src.indexOf("if (meta.kind === 'db_login') {") + 600);
  assert.match(call, /tls: c\.target\.tls \|\| 'off', ca_file: c\.target\.ca_file/);
});

test('log lines never carry a password, token or connection string', () => {
  const { createLogger } = require('../engine/log'); const out = [];
  const L = createLogger({ stream: { write: (l) => out.push(l) } });
  L.error('db failed: jdbc://dba:SynthPass1@db01/x', { err: new Error('login failed password=Synth2026!'), hdr: 'Authorization: Bearer abcdef0123456789xyz' });
  const line = out.join('');
  for (const s of ['SynthPass1', 'Synth2026!', 'abcdef0123456789xyz']) assert.ok(!line.includes(s), s);
  JSON.parse(out[0]);
});

test('the audit record of an AI call keeps hashes, never the prompt text', () => {
  const src = fs.readFileSync(path.join(__dirname, '../engine/ai/jobs.js'), 'utf8');
  const a = src.slice(src.indexOf("action: 'ai.call'"), src.indexOf("action: 'ai.call'") + 600);
  assert.ok(!/prompt: pair \? pair\.prompt/.test(a) && !/system: pair \? pair\.system/.test(a)); assert.match(a, /prompt_sha256/);
});
