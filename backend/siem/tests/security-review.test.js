// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Regression tests for the pre-go-live security review (Oct 2026). Each test fails on the code before its fix:
//   hardening / PII snapshots accepted from any sender · a data pipeline's detection override taken from an operator's body,
//   and an operator's edit leaving a live pipeline enforcing · a log destination / intel feed keeping its write-only secret
//   when pointed elsewhere · prototype pollution through log-supplied names in the Database Audit report · service
//   identities passing as people in four-eyes · a Copilot proposal decided by someone else · TLS syslog requiring client
//   certificates with no CA (= every public CA) · viewers reading the archive / triage / beacons. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'secrev-'));
const quiet = { info() {}, warn() {}, error() {}, debug() {}, every() {}, child() { return quiet; } };

test('hardening and personal-data snapshots are taken only from an agent over HTTPS ingest', () => {
  const { createHardeningStore } = require('../engine/hardening/store');
  const st = createHardeningStore({});
  const forged = (extra) => Object.assign({ action: 'agent-hardening', host: 'dc-hqa.corp.syn', ts: Date.now(), fields: { settings: '{"compliant":true}', agent_version: '9' } }, extra);
  st.stage(forged({ collector: 'syslog-udp', src_type: 'windows' }));
  st.stage(forged({ collector: 'http', src_type: 'json' }));
  st.stage(forged({}));
  assert.equal(st.get('dc-hqa.corp.syn'), null, 'a syslog line or another source saying action=agent-hardening is refused');
  assert.equal(st.stats().rejected, 3);
  st.stage(forged({ collector: 'agent', src_type: 'windows' }));
  assert.equal(st.get('dc-hqa.corp.syn').settings.compliant, true, 'the agent itself is accepted');
});

test('data pipelines: the detection override is an administrator\'s; an operator\'s edit takes a live pipeline out of service', () => {
  const { createState } = require('../engine/soc/state');
  const { createDataOpt } = require('../engine/dataopt');
  const dir = tmp(), d = createDataOpt({ state: createState({ dir, log: quiet }), dir, log: quiet, config: {} });
  const rule = (extra) => Object.assign({ id: 'r1', action: 'drop', reason: 'noise (synthetic)', match: { field: 'src_type', op: 'eq', value: 'fortigate' } }, extra);
  d.createPipeline({ id: 'p1', name: 'p1', rules: [rule({ override: { who: 'admin1', why: 'forged at create' } })] }, 'op1');
  assert.equal(d.getPipeline('p1').rules[0].override, undefined, 'an override in the create body is dropped');
  d.enable('p1', { user: 'adm' });
  assert.equal(d.getPipeline('p1').enabled, true);
  const u = d.updatePipeline('p1', { rules: [rule({ override: { who: 'admin1', why: 'forged' } })] }, 'op1', 'operator');
  assert.equal(u.enabled, false, 'an operator\'s edit of a live pipeline disables it until an administrator re-enables it');
  assert.equal(d.getPipeline('p1').rules[0].override, undefined, 'an override in the edit body is dropped');
  d.enable('p1', { user: 'adm' });
  assert.equal(d.updatePipeline('p1', { rules: [rule({})] }, 'adm', 'admin').enabled, true, 'an administrator\'s edit keeps it running');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a log destination\'s secret is dropped when it is pointed at another endpoint', () => {
  const { createDestinations } = require('../engine/dataopt/destinations');
  const dir = tmp(), D = createDestinations({ dir, log: quiet });
  D.create({ id: 'siem2', kind: 'http', url: 'https://collector.corp.syn/in', credentials: { token: 'SYNTH-TOKEN' } }, 'adm');
  assert.equal(D.get('siem2').credentials.set, true);
  D.update('siem2', { name: 'renamed' }, 'adm');
  assert.equal(D.get('siem2').credentials.set, true, 'a change that keeps the endpoint keeps the secret');
  D.update('siem2', { url: 'https://attacker.example/collect' }, 'adm');
  assert.notEqual(D.get('siem2').credentials.set, true, 'a new endpoint without new credentials has no secret');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an intel feed\'s header is dropped when its URL changes', () => {
  const { createIntelFeeds } = require('../engine/detect/intel-feeds');
  const dir = tmp(), secrets = path.join(dir, 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  const audits = [], F = createIntelFeeds({ dir, secretsPath: secrets, audit: (e) => audits.push(e) });
  F.put({ id: 'feed-syn', name: 'Synthetic', url: 'https://feeds.corp.syn/list', header: 'X-API-Key: SYNTH' }, 'adm');
  assert.equal(F.list().find((f) => f.id === 'feed-syn').header_set, true);
  F.put({ id: 'feed-syn', name: 'Synthetic', url: 'https://attacker.example/list' }, 'adm');
  assert.equal(F.list().find((f) => f.id === 'feed-syn').header_set, false);
  const a = audits.filter((x) => /intel\.feed/.test(x.action)).pop(); assert.equal(a.detail.was, 'https://feeds.corp.syn/list', 'the old URL is in the audit record');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Database Audit report: a user named __proto__ stays a user and pollutes nothing', () => {
  const { summarize } = require('../engine/db-audit/audit-report');
  const ev = (user, action) => ({ ts: Date.UTC(2026, 9, 20, 9), action, outcome: 'failure', user, fields: { instance: 'ESS', userhost: 'h', program: 'p', reason: 'r' }, tags: ['db-audit'] });
  const rows = [ev('__proto__', 'logon-failed'), ev('constructor', 'logon-failed'), ev('app_syn', 'logon-failed')];
  const r = summarize(rows, { posture: [], monitored: ['ESS'], now: Date.UTC(2026, 9, 23, 12), hours: 168 });
  assert.equal(({}).events, undefined, 'Object.prototype was not written'); assert.equal(({}).failed, undefined);
  assert.ok(r.summary, 'the report still builds');
});

test('four-eyes: service and command-line identities never count as a person', () => {
  const { isHuman } = require('../engine/approvers/scopes');
  for (const u of ['system', 'duty', 'ai', 'sentra-siem-ad@srv01', 'sentra-siem-validate', 'sentra-itam-sync', 'svc-backup', 'ai:soc', 'zyb-update', 'zyb-readiness']) assert.equal(isHuman(u), false, u);
  for (const u of ['nora.syn', 'aisha.syn', 'systemadmin.syn', 'botan.syn', 'sara']) assert.equal(isHuman(u), true, u);
});

test('a Copilot proposal is decided by the analyst who asked (or an administrator)', async () => {
  const { createState } = require('../engine/soc/state');
  const { createCopilot } = require('../engine/soc/copilot');
  const dir = tmp(), state = createState({ dir, log: quiet });
  const { createAlerts } = require('../engine/soc/alerts'), { createCases } = require('../engine/soc/cases');
  const alerts = createAlerts({ state, log: quiet }), C = createCopilot({ state, alerts, cases: createCases({ state, alerts, log: quiet }), log: quiet, config: {}, noTimers: true });
  // the decide path is reached through a stored proposal
  state.collection('soc_copilot_proposals').put({ id: 'CP-1', kind: 'save_hunt', input: { name: 'x', q: 'user:x', reason: 'r' }, status: 'pending', requested_by: 'omar.syn', conversation: 'c1', at: Date.now(), needs_role: 'analyst' });
  assert.throws(() => C.decide('CP-1', { decision: 'reject' }, { user: 'nora.syn', role: 'operator' }), /omar\.syn's conversation/);
  const r = C.decide('CP-1', { decision: 'reject', note: 'cleared' }, { user: 'syed', role: 'admin' }); assert.equal(r.status || (r.proposal && r.proposal.status), 'rejected', 'an administrator may clear it');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('TLS syslog: client certificates without our own CA are refused (no public CA can get in)', async () => {
  const src = fs.readFileSync(path.join(__dirname, '../engine/collect/syslog.js'), 'utf8');
  assert.match(src, /request_cert && !sc\.tls\.ca\) throw/);
});

test('viewers do not read the raw archive, AI triage or beacon analysis', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  assert.match(read('engine/dataopt/api.js'), /archive\/search`, wrap\(deps, 'analyst'[\s\S]{0,700}\{ auditRead: true \}/);
  assert.match(read('engine/soc/analyst-routes.js'), /soc\/triage\/:id`, wrap\(deps, 'analyst'/);
  assert.match(read('engine/xdr/routes.js'), /xdr\/beacons`, wrap\(deps, 'analyst'/);
});

test('log lines never carry a password, token or connection string', () => {
  const { createLogger } = require('../engine/log'); const out = [];
  const L = createLogger({ stream: { write: (l) => out.push(l) } });
  L.error('ch failed: password=Synth2026!', { err: new Error('token=abcdef0123456789abcd'), hdr: 'Authorization: Bearer abcdef0123456789xyz' });
  for (const s of ['Synth2026!', 'abcdef0123456789abcd', 'abcdef0123456789xyz']) assert.ok(!out.join('').includes(s), s);
  JSON.parse(out[0]);
});

test('AES-GCM decryption requires the full 16-byte tag', () => {
  for (const f of ['engine/secretfile.js', 'engine/dataopt/destinations.js', 'engine/soc/credposture.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    for (const m of src.match(/createDecipheriv\('aes-256-gcm'[^;]*/g) || []) assert.match(m, /authTagLength: 16/, f);
  }
});

test('dataopt master key: an existing key is re-read, never overwritten; a group/world readable key is refused; new folder is 0700', { skip: process.platform === 'win32' }, () => {
  const { loadMasterKey } = require('../engine/dataopt/destinations');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-mk-')), dir = path.join(root, 'keys'), file = path.join(dir, 'master.key');
  const k1 = loadMasterKey(file);
  assert.equal(k1.length, 32); assert.equal((fs.statSync(dir).mode & 0o777).toString(8), '700'); assert.equal((fs.statSync(file).mode & 0o777).toString(8), '600');
  const before = fs.readFileSync(file, 'utf8');
  assert.deepEqual(loadMasterKey(file), k1, 'the same key is read again'); assert.equal(fs.readFileSync(file, 'utf8'), before, 'file untouched');
  // the race: the file appears after the first read failed (EEXIST) - the existing key is used, not replaced
  const raceFile = path.join(root, 'race.key'), real = fs.readFileSync, other = 'ab'.repeat(32); let n = 0;
  fs.readFileSync = function (f, ...a) {
    if (f === raceFile && n++ === 0) { fs.writeFileSync(raceFile, other + '\n', { mode: 0o600 }); const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; }
    return real.call(this, f, ...a);
  };
  try { assert.equal(loadMasterKey(raceFile).toString('hex'), other, 'the key another process wrote wins'); } finally { fs.readFileSync = real; }
  assert.equal(real.call(fs, raceFile, 'utf8').trim(), other);
  fs.chmodSync(file, 0o644);
  assert.throws(() => loadMasterKey(file), /readable by group or other/);
  fs.chmodSync(file, 0o640); assert.throws(() => loadMasterKey(file), /readable by group or other/);
});
