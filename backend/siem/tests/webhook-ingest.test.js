// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Generic inbound webhook receiver (engine/collect/webhook-ingest.js) through the REAL API server (engine/api/server.js) with
// SYNTHETIC payloads: per-webhook token (shown once, stored only as SHA-256 in secrets.json SEALED at rest), HMAC signature,
// mapping to events (dot paths, events_path, static fields, no payload unless asked, prototype keys dropped), payload cap and
// rate limit checked from the headers before the body, failed-attempt limit, /ingest/<src_id> unaffected; configuration routes:
// administrator only (viewer / operator refused), validation errors naming the field, audit records without any secret,
// rotate invalidates the old value, delete removes the secrets.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-wh-')), key = path.join(dir, 'secrets.key');
fs.writeFileSync(key, crypto.randomBytes(32).toString('hex'), { mode: 0o440 });
process.env.SENTRA_SIEM_SECRETS_KEY = key;
const SF = require('../engine/secretfile'); SF._reset();
const { createApi } = require('../engine/api/server');
const { createState } = require('../engine/soc/state');
const WH = require('../engine/collect/webhook-ingest');

const SECRET = 'P'.repeat(32);
function req(port, method, p, { body, headers } = {}) {
  return new Promise((ok, no) => {
    const data = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: Object.assign({ 'Content-Type': 'application/json' }, data ? { 'Content-Length': data.length } : {}, headers || {}) }, (res) => {
      let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(b); } catch (e) { j = null; } ok({ status: res.statusCode, json: j }); });
    });
    r.on('error', no); if (data) r.write(data); r.end();
  });
}
const admin = { 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': 'syn.admin', 'X-Auth-Role': 'admin' };
const as = (role) => ({ 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': 'syn.' + role, 'X-Auth-Role': role });

test('mapping: validated in full; items mapped to event fields; payload only when asked; prototype keys never followed', () => {
  assert.throws(() => WH.normMapping({ fields: { password: 'a' } }), /mapping\.fields\.password is not an event field/);
  assert.throws(() => WH.normMapping({ fields: { host: 'a..b' } }), /dot path/); assert.throws(() => WH.normMapping({ events_path: '__proto__.x' }), /events_path/);
  assert.throws(() => WH.normMapping({ script: 'x' }), /mapping\.script is not a mapping field/);
  const m = WH.normMapping({ fields: { message: 'alert.title', severity: 'alert.level', host: 'target.hosts.0', src_ip: 'net.src' }, static: { category: 'alert' } });
  const o = WH.mapItem({ alert: { title: 'SYN disk full', level: 'high' }, target: { hosts: ['syn-app-01'] }, net: { src: '198.51.100.4' }, secret_field: 'x' }, m, 'syn');
  assert.deepEqual(o, { message: 'SYN disk full', severity: 'high', host: 'syn-app-01', src_ip: '198.51.100.4', category: 'alert', webhook: 'syn' }, 'nothing but the mapped fields');
  assert.equal(WH.mapItem({ a: 1 }, WH.normMapping({ keep_payload: true }), 'syn').data.a, 1);
  assert.throws(() => WH.normMapping({ fields: { host: 'constructor.name' } }), /dot path/); assert.equal(WH.mapItem({ constructor: { name: 'x' } }, { fields: { host: 'constructor.name' }, static: {} }, 'syn').host, undefined, 'even a stored mapping never follows it');
  const raw = Buffer.from('{"a":1}'), sig = 'sha256=' + crypto.createHmac('sha256', 'k').update(raw).digest('hex');
  assert.equal(WH.hmacOk(raw, 'k', sig, 'sha256='), true); assert.equal(WH.hmacOk(raw, 'k', sig.slice(0, -1) + '0', 'sha256='), false); assert.equal(WH.hmacOk(raw, 'other', sig, 'sha256='), false);
});

test('end to end: token, HMAC, mapping, caps, rate limit, sealed secrets, admin-only audited configuration', async () => {
  const sec = path.join(dir, 'secrets.json'); SF.write(sec, { proxy_secret: SECRET, ingest_tokens: { syslog1: 'tok-src-1' } });
  const config = { api_prefix: '/api/soc' }; Object.defineProperty(config, 'secrets', { value: SF.read(sec), enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets: sec }, enumerable: false });
  const state = await createState({ dir: path.join(dir, 'state') });
  const emitted = [], audits = [], warns = [];
  const parser = { parse: (line, meta) => ({ line, meta, obj: meta.obj }) }, pipeline = { emit: (e) => emitted.push(e) };
  const log = { info() {}, warn() {}, error: (m, f) => warns.push('ERR ' + m + ' ' + (f && f.err && f.err.stack || '')), every: (k, ms, lvl, msg, f) => warns.push(msg + ' ' + JSON.stringify(f)) };
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: SECRET, log });
  api.route('POST', '/ingest/:src_id', () => ({ ok: 'src' }));   // the existing per-source route: untouched
  WH.register(api, { state, config, log, parser, pipeline });
  const { port } = await api.start();
  try {
    const B = '/api/soc/collect/webhooks';
    for (const role of ['viewer', 'operator']) {
      assert.equal((await req(port, 'GET', B, { headers: as(role) })).status, 403, role + ' cannot read webhook settings');
      assert.equal((await req(port, 'POST', B, { headers: as(role), body: { name: 'syn-alerts' } })).status, 403, role + ' cannot create one');
    }
    let r = await req(port, 'POST', B, { headers: admin, body: { name: 'Bad Name' } }); assert.equal(r.status, 400); assert.match(r.json.error, /^name: 2-40 lowercase/);
    r = await req(port, 'POST', B, { headers: admin, body: { name: 'syn-alerts', rate_per_min: 0 } }); assert.match(r.json.error, /rate_per_min must be at least 1/);
    r = await req(port, 'POST', B, { headers: admin, body: { name: 'syn-alerts', mapping: { fields: { evil: 'x' } } } }); assert.equal(r.status, 400); assert.match(r.json.error, /mapping\.fields\.evil/);
    r = await req(port, 'POST', B, { headers: admin, body: { name: 'syn-alerts', label: 'SYNTHETIC alerting tool', hmac_enabled: true, rate_per_min: 5, max_kb: 2, created_by: 'mallory',
      mapping: { events_path: 'alerts', fields: { message: 'title', severity: 'level', host: 'host' }, static: { category: 'alert' } } } });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    const token = r.json.token, hsec = r.json.hmac_secret;
    assert.ok(token.length >= 30 && hsec.length >= 30); assert.equal(r.json.webhook.created_by, 'syn.admin'); assert.equal(r.json.webhook.path, '/ingest/webhook/syn-alerts');
    const disk = fs.readFileSync(sec, 'utf8'); assert.ok(SF.isSealed(JSON.parse(disk)), 'secrets.json sealed'); assert.ok(!disk.includes(token) && !disk.includes(hsec), 'no secret in clear on disk');
    const stored = SF.read(sec).webhooks['syn-alerts']; assert.match(stored.token, /^sha256:[0-9a-f]{64}$/, 'the token only as its digest'); assert.equal(stored.hmac_secret, hsec);
    assert.equal(SF.read(sec).ingest_tokens.syslog1, 'tok-src-1', 'other secrets kept');
    const created = audits.find((a) => a.action === 'collect.webhook.create'); assert.equal(created.by, 'syn.admin'); assert.equal(created.role, 'admin'); assert.equal(created.target, 'syn-alerts');
    assert.ok(!JSON.stringify(audits).includes(token) && !JSON.stringify(audits).includes(hsec), 'no secret in the audit trail');
    r = await req(port, 'GET', B, { headers: admin }); assert.equal(r.json.items[0].token_set, true); assert.ok(!JSON.stringify(r.json).includes(token) && !JSON.stringify(r.json).includes(hsec) && !/sha256:/.test(JSON.stringify(r.json)), 'never returned again');

    const W = '/ingest/webhook/syn-alerts';
    const payload = { alerts: [{ title: 'SYN CPU high', level: 'high', host: 'syn-app-01', __proto__x: 1 }, { title: 'SYN disk', level: 'low', host: 'syn-app-02' }, 'not an object'] };
    const raw = Buffer.from(JSON.stringify(payload)), sig = 'sha256=' + crypto.createHmac('sha256', hsec).update(raw).digest('hex');
    assert.equal((await req(port, 'POST', W, { body: raw })).status, 401, 'no token');
    assert.equal((await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': 'wrong' } })).status, 401);
    assert.equal((await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': token } })).status, 401, 'signature missing');
    assert.equal((await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': token, 'X-Hub-Signature-256': sig.slice(0, -1) + (sig.endsWith('0') ? '1' : '0') } })).status, 401, 'signature wrong');
    r = await req(port, 'POST', W, { body: raw, headers: { Authorization: 'Bearer ' + token, 'X-Hub-Signature-256': sig } });
    assert.equal(r.status, 200, JSON.stringify(r.json)); assert.deepEqual([r.json.accepted, r.json.rejected], [2, 1]); assert.match(r.json.errors[0], /item 2: expected an object/);
    assert.deepEqual(emitted[0].obj, { message: 'SYN CPU high', severity: 'high', host: 'syn-app-01', category: 'alert', webhook: 'syn-alerts' });
    assert.equal(emitted[0].meta.collector, 'webhook'); assert.equal(emitted[0].meta.src_id, 'webhook:syn-alerts'); assert.equal(emitted[0].meta.src_type, 'json');
    assert.equal((await req(port, 'POST', W, { body: Buffer.alloc(3000, 32), headers: { 'X-Sentra-Token': token } })).status, 413, 'over max_kb, refused before the body');
    assert.equal((await req(port, 'POST', W, { body: '{"alerts":[]}', headers: { 'X-Sentra-Token': token, 'X-Hub-Signature-256': 'sha256=' + crypto.createHmac('sha256', hsec).update('{"alerts":[]}').digest('hex') } })).status, 200, 'empty list fine');
    r = await req(port, 'POST', W, { body: '{"x":1}', headers: { 'X-Sentra-Token': token, 'X-Hub-Signature-256': 'sha256=' + crypto.createHmac('sha256', hsec).update('{"x":1}').digest('hex') } });
    assert.equal(r.status, 400); assert.match(r.json.error, /events_path "alerts" not found/);
    r = await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': token, 'X-Hub-Signature-256': sig } }); assert.equal(r.status, 429, 'rate limit (5 per minute: every authenticated request counts)'); assert.match(r.json.error, /5 per minute/);
    assert.equal((await req(port, 'POST', '/ingest/webhook/nope', { body: raw, headers: { 'X-Sentra-Token': token } })).status, 404);
    assert.equal((await req(port, 'POST', '/ingest/syslog1', { body: '{}' })).json.ok, 'src', '/ingest/<src_id> still reaches its own route');
    assert.ok(warns.length && warns.every((w) => !w.includes(token) && !w.includes(hsec)), 'rejections logged, without the token');

    r = await req(port, 'PUT', B + '/syn-alerts', { headers: admin, body: { rate_per_min: 600, hmac_enabled: false } }); assert.equal(r.status, 200);
    assert.deepEqual(audits.find((a) => a.action === 'collect.webhook.update').detail.changed.sort(), ['hmac_enabled', 'rate_per_min']);
    assert.equal((await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': token } })).status, 200, 'signature no longer required');
    assert.equal((await req(port, 'POST', B + '/syn-alerts/rotate', { headers: admin, body: { what: 'all' } })).status, 400);
    assert.equal((await req(port, 'POST', B + '/syn-alerts/rotate', { headers: as('operator'), body: { what: 'token' } })).status, 403);
    r = await req(port, 'POST', B + '/syn-alerts/rotate', { headers: admin, body: { what: 'token' } }); const t2 = r.json.token;
    assert.equal((await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': token } })).status, 401, 'the old token no longer works');
    assert.equal((await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': t2 } })).status, 200);
    assert.deepEqual(audits.find((a) => a.action === 'collect.webhook.rotate').detail, { what: 'token' });

    // a wrong token, over and over: the failed-attempt limit answers 429
    let last = 0; for (let i = 0; i < 32; i++) last = (await req(port, 'POST', W, { body: '{}', headers: { 'X-Sentra-Token': 'guess-' + i } })).status;
    assert.equal(last, 429);

    assert.equal((await req(port, 'DELETE', B + '/syn-alerts', { headers: as('operator') })).status, 403);
    r = await req(port, 'DELETE', B + '/syn-alerts', { headers: admin }); assert.equal(r.status, 200);
    assert.equal(SF.read(sec).webhooks['syn-alerts'], undefined, 'secrets removed'); assert.ok(audits.some((a) => a.action === 'collect.webhook.delete' && a.by === 'syn.admin'));
    assert.equal((await req(port, 'POST', W, { body: raw, headers: { 'X-Sentra-Token': t2 } })).status, 404);
  } finally { await api.stop(); }
});
