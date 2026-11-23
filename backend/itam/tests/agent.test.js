// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { startApp, tmpDir } = require('./helpers');
const agentCli = require('../agent/agent');
const collector = require('../agent/collect');
const { createAgentState } = require('../agent/config');

const admin = { user: 'adm', role: 'admin' };
async function enrolAgent(h) {
  const tok = (await h.req('POST', '/settings/agent-tokens', { body: { note: 't' }, ...admin })).json.token;
  const enr = (await h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'PC1', platform: 'windows' } })).json;
  return { tok, enr };
}

test('enrol: valid token → agent id + key; token is single-use', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const { tok, enr } = await enrolAgent(h);
  assert.ok(enr.agent_id && enr.agent_key);
  const again = await h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok, hostname: 'PC1' } });
  assert.equal(again.status, 401); assert.equal(again.json.code, 'enrol_used');
});

test('enrol: expired token rejected', async (t) => {
  const h = await startApp({ noAi: true, config: { agent: { enrol_token_ttl_hours: -1 } } });
  t.after(() => h.close());
  const tok = (await h.req('POST', '/settings/agent-tokens', { body: {}, ...admin })).json.token;
  const r = await h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: tok } });
  assert.equal(r.status, 401); assert.equal(r.json.code, 'enrol_expired');
});

test('enrol: bogus token rejected', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const r = await h.req('POST', '/agent/enrol', { user: '', role: '', body: { token: 'not-a-real-token' } });
  assert.equal(r.status, 401); assert.equal(r.json.code, 'enrol_bad_token');
});

test('report: accepted once; replay (same seq/nonce) and stale ts rejected', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const { enr } = await enrolAgent(h);
  const bearer = enr.agent_key;
  const ok = await h.req('POST', '/agent/report', { user: '', role: '', bearer, body: { seq: 1, ts: new Date().toISOString(), nonce: 'n1', host: { hostname: 'PC1', serial: 'S1' }, software: [] } });
  assert.equal(ok.status, 200);
  const replay = await h.req('POST', '/agent/report', { user: '', role: '', bearer, body: { seq: 1, ts: new Date().toISOString(), nonce: 'n2', host: {} } });
  assert.equal(replay.status, 409); assert.equal(replay.json.code, 'report_replay');
  const stale = await h.req('POST', '/agent/report', { user: '', role: '', bearer, body: { seq: 2, ts: new Date(Date.now() - 3600_000).toISOString(), nonce: 'n3', host: {} } });
  assert.equal(stale.status, 409); assert.equal(stale.json.code, 'report_stale');
});

test('heartbeat + report require a valid key; revoked agent is refused', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const { enr } = await enrolAgent(h);
  assert.equal((await h.req('POST', '/agent/heartbeat', { user: '', role: '', bearer: 'wrong-key' })).status, 401);
  assert.equal((await h.req('POST', '/agent/heartbeat', { user: '', role: '', bearer: enr.agent_key })).status, 200);
  await h.req('POST', `/agents/${enr.agent_id}/revoke`, { ...admin });
  assert.equal((await h.req('POST', '/agent/heartbeat', { user: '', role: '', bearer: enr.agent_key })).status, 401);
});

test('agent CLI store-and-forward: spools on network failure, flushes on recovery (monotonic seq)', async (t) => {
  const origCollect = collector.collect;
  collector.collect = async () => ({ host: { hostname: 'PC1', serial: 'S1', platform: 'windows', macs: [] }, software: [] });
  t.after(() => { collector.collect = origCollect; });
  const state = createAgentState({ dir: tmpDir() }); state.load();
  state.set({ server: 'http://127.0.0.1:1/agent', agent_id: 'agt_x', agent_key: 'k' });
  const sent = [];
  let online = false;
  const post = async (url, body) => { if (!online) return { ok: false, error: 'ECONNREFUSED' }; sent.push(body); return { ok: true, status: 200, json: { ok: true } }; };
  let r = await agentCli.reportOnce(state, post);
  assert.equal(r.ok, false); assert.equal(state.get().spool.length, 1, 'report spooled while offline');
  online = true;
  r = await agentCli.reportOnce(state, post);
  assert.equal(r.ok, true);
  assert.equal(state.get().spool.length, 0, 'spool flushed');
  assert.equal(sent.length, 2, 'spooled + fresh report both sent');
  assert.ok(sent[0].seq < sent[1].seq, 'seq monotonic across spool + new');
});

test('agent key is persisted with 0600 and parseArgs works', () => {
  const state = createAgentState({ dir: tmpDir() });
  state.set({ agent_key: 'secret' });
  if (process.platform !== 'win32') { const mode = fs.statSync(state.file).mode & 0o777; assert.equal(mode, 0o600); }
  const a = agentCli.parseArgs(['enrol', '--server', 'https://x/agent', '--token', 'T']);
  assert.deepEqual([a._[0], a.server, a.token], ['enrol', 'https://x/agent', 'T']);
});

// ---- ZS-26: agent transport + token handling ---------------------------------------------------------------------------
test('ZS-26 agent refuses non-HTTPS servers (http only for loopback) for enrol and every POST', async () => {
  assert.equal(agentCli.serverUrlError('https://portal.example/agent'), null);
  assert.equal(agentCli.serverUrlError('http://127.0.0.1:9/agent'), null);
  assert.equal(agentCli.serverUrlError('http://localhost:9/agent'), null);
  assert.match(agentCli.serverUrlError('http://portal.example/agent'), /must be https/);
  assert.match(agentCli.serverUrlError('ftp://portal.example/agent'), /must be https/);
  const state = createAgentState({ dir: tmpDir() }); state.load();
  let called = 0;
  await assert.rejects(agentCli.enrol({ server: 'http://portal.example/agent', token: 'T', state }, async () => { called++; return { ok: true, json: { agent_key: 'k', agent_id: 'a' } }; }), /must be https/);
  assert.equal(called, 0, 'token never sent over http');
  const r = await agentCli.post('http://portal.example/agent/report', { x: 1 }, { Authorization: 'Bearer k' });
  assert.equal(r.ok, false); assert.match(r.error, /must be https/);
});

test('ZS-26 agent enrol reads the token from --token-file / stdin (installers never put it on argv)', async () => {
  const { Readable } = require('node:stream');
  const path = require('node:path');
  const dir = tmpDir(); const f = path.join(dir, 'tok'); fs.writeFileSync(f, 'FILE-TOKEN-123\n', { mode: 0o600 });
  assert.equal(await agentCli.resolveToken(agentCli.parseArgs(['enrol', '--token-file', f])), 'FILE-TOKEN-123');
  assert.equal(await agentCli.resolveToken(agentCli.parseArgs(['enrol', '--token-stdin']), { stdin: Readable.from([Buffer.from('STDIN-TOKEN-9\n')]) }), 'STDIN-TOKEN-9');
  const sh = fs.readFileSync(path.join(__dirname, '..', 'agent', 'install', 'install.sh'), 'utf8');
  const ps = fs.readFileSync(path.join(__dirname, '..', 'agent', 'install', 'install.ps1'), 'utf8');
  for (const [name, src] of [['install.sh', sh], ['install.ps1', ps]]) {
    const enrolLine = src.split('\n').find((l) => /agent\.js.*enrol/.test(l) && !l.trim().startsWith('#'));
    assert.ok(enrolLine && /--token-stdin/.test(enrolLine), `${name} passes the token on stdin`);
    assert.ok(!/--token\s+["$]/.test(enrolLine), `${name} does not pass the token on the command line`);
  }
});
