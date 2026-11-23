// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, SECRET } = require('./helpers');

test('proxy secret + identity enforced; health needs secret but no identity', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  assert.equal((await h.req('GET', '/health', { secret: null })).status, 401);
  assert.equal((await h.req('GET', '/health')).status, 200);
  assert.equal((await h.req('GET', '/summary', { user: '', role: '' })).status, 401);
  assert.equal((await h.req('GET', '/summary', { role: 'bogus' })).status, 401);
});

test('roles: viewer read-only; operator edits; admin-only settings/audit', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  // viewer cannot create
  assert.equal((await h.req('POST', '/assets', { body: { name: 'x', type: 'other', serial: 'S' }, role: 'viewer' })).status, 403);
  // operator can
  const id = (await h.req('POST', '/assets', { body: { name: 'x', type: 'other', serial: 'S' } })).json.asset.id;
  assert.ok(id);
  // viewer can read
  assert.equal((await h.req('GET', `/assets/${id}`, { role: 'viewer' })).status, 200);
  // operator cannot change settings or read audit (admin only)
  assert.equal((await h.req('POST', '/settings', { body: { auto_adopt: true } })).status, 403);
  assert.equal((await h.req('GET', '/audit')).status, 403);
  assert.equal((await h.req('GET', '/audit', { user: 'adm', role: 'admin' })).status, 200);
  // operator cannot open a stocktake (admin)
  assert.equal((await h.req('POST', '/stocktake', { body: {} })).status, 403);
});

test('everyone (viewer) can look up an asset by tag — self-service', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  await h.req('POST', '/assets', { body: { name: 'Shared Printer', type: 'printer', asset_tag: 'PRN-7', owner: 'Ops' } });
  const r = await h.req('GET', '/lookup?tag=PRN-7', { role: 'viewer' });
  assert.equal(r.status, 200); assert.equal(r.json.found, 1);
  assert.equal(r.json.assets[0].owner, 'Ops');
});

test('connector credentials are write-only: set succeeds, never returned', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const admin = { user: 'adm', role: 'admin' };
  const set = await h.req('POST', '/settings/credential', { body: { name: 'vcenter_pass', value: 'super-secret-pw' }, ...admin });
  assert.equal(set.status, 200);
  assert.equal(set.json.credentials.vcenter_pass.configured, true);
  // the value is never present in any read
  const s = (await h.req('GET', '/settings', { ...admin })).json;
  assert.equal(s.credentials.vcenter_pass.configured, true);
  assert.ok(!JSON.stringify(s).includes('super-secret-pw'));
  const status = (await h.req('GET', '/status', { role: 'viewer' })).json;
  assert.ok(!JSON.stringify(status).includes('super-secret-pw'));
  // audit never records the value
  const audit = (await h.req('GET', '/audit', { ...admin })).json;
  assert.ok(!JSON.stringify(audit).includes('super-secret-pw'));
});

test('ZS-25 connector credentials are sealed at rest (AES-256-GCM vault key) and legacy plaintext is migrated on load', async (t) => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { tmpDir } = require('./helpers');
  const admin = { user: 'adm', role: 'admin' };
  const dir = tmpDir();
  const stateDir = path.join(dir, 'state');
  const onDisk = () => fs.readdirSync(stateDir).filter((f) => f.startsWith('credentials')).map((f) => fs.readFileSync(path.join(stateDir, f), 'utf8')).join('\n');
  let h = await startApp({ noAi: true, dir });
  for (const [name, value] of [['vcenter_pass', 'sealed-vc-pass-AS25'], ['netops_token', 'sealed-netops-tok-AS25'], ['private_token', 'sealed-private-tok-AS25']]) {
    assert.equal((await h.req('POST', '/settings/credential', { body: { name, value }, ...admin })).status, 200);
  }
  assert.ok(!/sealed-(vc-pass|netops-tok|private-tok)-AS25/.test(onDisk()), 'no plaintext in credentials journal/snapshot');
  assert.match(onDisk(), /aes-256-gcm/);
  assert.equal(h.app.settings.getCredential('vcenter_pass'), 'sealed-vc-pass-AS25', 'engine can still read it');
  // simulate a legacy plaintext record written by the old code, then restart → migrated + journal compacted
  h.app.store.collection('credentials').put({ id: 'netops_token', set_at: new Date().toISOString(), by: 'old', len: 10, value: 'legacy-plain-AS25' });
  await h.close();
  assert.match(onDisk(), /legacy-plain-AS25/);
  h = await startApp({ noAi: true, dir });
  t.after(() => h.close());
  assert.equal(h.app.settings.getCredential('netops_token'), 'legacy-plain-AS25');
  assert.ok(!onDisk().includes('legacy-plain-AS25'), 'plaintext gone from disk after migration');
});

test('agent tokens: issued once (admin), token value not re-listed in plaintext', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const admin = { user: 'adm', role: 'admin' };
  assert.equal((await h.req('POST', '/settings/agent-tokens', { body: {} })).status, 403); // operator denied
  const issued = (await h.req('POST', '/settings/agent-tokens', { body: { note: 'HQ laptops' }, ...admin })).json;
  assert.ok(issued.token && issued.install_hint.includes('itam-agent enrol'));
  const list = (await h.req('GET', '/settings/agent-tokens', { ...admin })).json.tokens;
  assert.ok(list[0].token_prefix && !list.some((t2) => t2.token === issued.token), 'full token not relisted');
});

test('ZS-07 CSRF: non-JSON Content-Type → 415, Sec-Fetch-Site cross-site/same-site → 403; agent requests still pass', async (t) => {
  const http = require('node:http');
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const admin = { user: 'adm', role: 'admin' };
  const rawReq = (method, p, body, headers) => new Promise((resolve, reject) => {
    const data = body == null ? null : Buffer.from(body);
    const r = http.request({ host: '127.0.0.1', port: h.port, method, path: p, headers: Object.assign({ 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': 'adm', 'X-Auth-Role': 'admin' }, data ? { 'Content-Length': data.length } : {}, headers) }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
  // text/plain "simple request" carrying JSON (classic CSRF) and an empty form POST are refused
  assert.equal(await rawReq('POST', '/api/itam/assets', JSON.stringify({ name: 'csrf' }), { 'Content-Type': 'text/plain' }), 415);
  assert.equal(await rawReq('POST', '/api/itam/assets', 'name=csrf', { 'Content-Type': 'application/x-www-form-urlencoded' }), 415);
  assert.equal(await rawReq('POST', '/api/itam/settings/agent-tokens', '', { 'Content-Type': 'application/x-www-form-urlencoded' }), 415);
  assert.equal(await rawReq('POST', '/api/itam/assets', JSON.stringify({ name: 'csrf' }), {}), 415, 'body without a Content-Type');
  // cross-site / same-site browser requests refused even with JSON
  for (const site of ['cross-site', 'same-site']) {
    const r = await h.req('POST', '/assets', { body: { name: 'csrf' }, headers: { 'Sec-Fetch-Site': site } });
    assert.equal(r.status, 403, site);
  }
  assert.equal((await h.req('GET', '/assets', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await h.req('GET', '/assets', { role: 'viewer' })).json.total, 0, 'nothing was created');
  // same-origin JSON (the portal UI) and application/json; charset=utf-8 still work
  assert.equal((await h.req('POST', '/assets', { body: { name: 'ok1' }, headers: { 'Sec-Fetch-Site': 'same-origin' } })).status, 200);
  assert.equal(await rawReq('POST', '/api/itam/assets', JSON.stringify({ name: 'ok2' }), { 'Content-Type': 'application/json; charset=utf-8' }), 200);
  // the real agent client (agent/agent.js post) enrols + reports through the gateway
  const agentCli = require('../agent/agent');
  const tok = (await h.req('POST', '/settings/agent-tokens', { body: {}, ...admin })).json.token;
  const post = (url, body, headers) => agentCli.post(url, body, Object.assign({ 'X-Sentra-Proxy-Secret': SECRET }, headers));
  const enr = await post(`http://127.0.0.1:${h.port}/agent/enrol`, { token: tok, hostname: 'PC-AS07', platform: 'linux' });
  assert.equal(enr.status, 200);
  const rep = await post(`http://127.0.0.1:${h.port}/agent/report`, { seq: 1, ts: new Date().toISOString(), nonce: 'x', host: { hostname: 'PC-AS07', serial: 'AS07SN' }, software: [] }, { Authorization: `Bearer ${enr.json.agent_key}` });
  assert.equal(rep.status, 200);
});
