// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Mimecast: parser (email schema), API 2.0 collector (token, batch pages, pre-signed gzip / JSON-lines files, cursor, rate
// limit, refused credentials, the secret never logged and never sent to the download host), settings routes (roles, the
// refused case, validation, write-only secrets, audit). Tenants, addresses and secrets are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const P = require('../engine/parse');
const MC = require('../engine/collect/mimecast');

const BASE = 'https://api.services.mimecast.com', NOW = Date.parse('2026-11-25T10:00:00Z');
const res = (status, j, extra) => Object.assign({ status, ok: status >= 200 && status < 300, json: async () => j, headers: { get: () => null } }, extra || {});
const fileRes = (buf) => ({ status: 200, ok: true, headers: { get: () => String(buf.length) }, arrayBuffer: async () => buf });

test('parser: Mimecast records land on the email schema; unknown keys are kept as an email event', () => {
  const av = P.parse('', { src_type: 'mimecast', obj: { _mc: 'av', timestamp: NOW, senderEnvelope: 'Bad@Evil.example', recipients: ['a@corp.example', 'b@corp.example'], subject: 'Invoice', action: 'Hold', virusFound: 'Synthetic.Test', senderIp: '203.0.113.5', fileName: 'inv.exe' } });
  assert.deepEqual([av.src_type, av.category, av.action, av.outcome, av.src_ip, av.fields.email_verdict, av.fields.email_from, av.fields.email_to], ['mimecast', 'email', 'quarantined', 'failure', '203.0.113.5', 'malware', 'bad@evil.example', 'a@corp.example, b@corp.example']);
  assert.match(av.fields.email_subject, /^sha256:/, 'the subject is hashed (PDPL), not stored in clear');
  assert.ok(av.severity >= 2 && av.tags.includes('mimecast') && av.tags.includes('malware'));
  assert.equal(av.ts, NOW);
  const imp = P.parse('', { src_type: 'mimecast', obj: { _mc: 'impersonation protect', datetime: '2026-11-25T09:00:00Z', sender: 'ceo@lookalike.example', recipient: 'cfo@corp.example', action: 'Block' } });
  assert.deepEqual([imp.action, imp.fields.email_verdict], ['blocked', 'phishing']); assert.ok(imp.tags.includes('T1566'));
  const rec = P.parse('', { src_type: 'mimecast', obj: { _mc: 'receipt', timestamp: '1795601100', senderEnvelope: 'x@partner.example', recipients: 'a@corp.example' } });
  assert.deepEqual([rec.category, rec.action, rec.outcome], ['email', 'delivered', 'success']);
  const odd = P.parse('', { src_type: 'mimecast', obj: { _mc: 'journal', somethingNew: 1 } });
  assert.deepEqual([odd.src_type, odd.category], ['mimecast', 'email']);
  assert.equal(P.parse('{"x":1}', {}).src_type === 'mimecast', false, 'a JSON line without the marker is not taken for Mimecast');
});

test('file decoding: gzip, JSON lines with a bad line, a JSON array, and {data:[...]}', () => {
  const lines = '{"a":1}\nnot json\n{"a":2}\n';
  assert.deepEqual(MC.decodeFile(zlib.gzipSync(Buffer.from(lines))), { items: [{ a: 1 }, { a: 2 }], bad: 1 });
  assert.deepEqual(MC.decodeFile(Buffer.from('[{"a":1},{"a":2}]')).items.length, 2);
  assert.deepEqual(MC.decodeFile(Buffer.from('{"data":[{"a":3}]}')).items, [{ a: 3 }]);
  assert.deepEqual(MC.linksOf({ value: [{ url: 'https://dl.example/1' }, { other: 'https://dl.example/2' }, 'https://dl.example/3', { x: 1 }] }), ['https://dl.example/1', 'https://dl.example/2', 'https://dl.example/3']);
  assert.equal(MC.baseOk(BASE), true); assert.equal(MC.baseOk('https://api.services.mimecast.com.evil.example'), false); assert.equal(MC.baseOk('http://api.services.mimecast.com'), false);
});

test('collector: token, pages until caught up, files downloaded without the token, cursor, rate limit, refused secret', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mc-')), events = [], calls = [];
  let tokens = 0;
  const fetchImpl = async (url, o = {}) => {
    calls.push([url, (o.headers || {}).Authorization || '', o.method || 'GET', String(o.body || '')]);
    if (url === BASE + '/oauth/token') { tokens++; return res(200, { access_token: 'tok-' + tokens, expires_in: 1800, token_type: 'Bearer' }); }
    if (url.startsWith(BASE + '/siem/v1/batch/events/cg?')) {
      const q = new URL(url).searchParams;
      if (q.get('type') === 'spam') return res(400, { fail: [{ message: 'unknown type' }] });
      if (!q.get('nextPage')) return res(200, { value: [{ url: 'https://dl.example/f1' }], '@nextPage': 'p2', isCaughtUp: false });
      if (q.get('nextPage') === 'p2') return res(200, { value: [{ url: 'https://dl.example/f2' }], '@nextPage': 'p3', isCaughtUp: true });
      return res(200, { value: [], '@nextPage': 'p3', isCaughtUp: true });
    }
    if (url === 'https://dl.example/f1') return fileRes(zlib.gzipSync(Buffer.from('{"senderEnvelope":"a@x.example","action":"Accept"}\n{"senderEnvelope":"b@x.example","action":"Reject"}\n')));
    if (url === 'https://dl.example/f2') return fileRes(Buffer.from('[{"senderEnvelope":"c@x.example","action":"Accept"}]'));
    return res(404, {});
  };
  const config = { mimecast: { enabled: true, types: ['receipt', 'spam'], poll_min: 15 } }; Object.defineProperty(config, 'secrets', { value: { mimecast: { client_id: 'cid-syn', client_secret: 'mc-secret-syn' } } });
  const logs = []; const log = { info: (m, f) => logs.push([m, f]), warn: (m, f) => logs.push([m, f]), error: (m, f) => logs.push([m, f]) };
  const c = MC.start({ config, parser: P, pipeline: { emit: (e) => events.push(e) }, log, stateDir: dir, fetchImpl, autoStart: false, now: () => NOW });
  await c.pollNow();
  const st = c.stats();
  assert.equal(st.records, 3); assert.equal(st.files, 2); assert.equal(st.caught_up.receipt, true);
  assert.match(st.last_error, /spam: Mimecast API HTTP 400: unknown type/, 'a refused log type is reported, the others still run');
  assert.ok(events.every((e) => e.src_type === 'mimecast' && e.category === 'email'));
  const tokenCall = calls.find((x) => x[0] === BASE + '/oauth/token');
  assert.equal(tokenCall[2], 'POST'); assert.match(tokenCall[3], /grant_type=client_credentials/); assert.match(tokenCall[3], /client_id=cid-syn/);
  assert.ok(calls.filter((x) => x[0].startsWith(BASE + '/siem')).every((x) => x[1] === 'Bearer tok-1'), 'API calls carry the token');
  assert.ok(calls.filter((x) => x[0].startsWith('https://dl.example')).every((x) => x[1] === ''), 'the download host never sees the token');
  assert.ok(calls.find((x) => /dateRangeStartsAt=2026-11-24/.test(x[0])), 'first run looks back one day');
  assert.ok(!JSON.stringify(logs).includes('mc-secret-syn') && !JSON.stringify(st).includes('mc-secret-syn'), 'the secret is never logged or shown');
  const cur = JSON.parse(fs.readFileSync(path.join(dir, 'mimecast-cursor.json'), 'utf8')); assert.equal(cur.receipt.next, 'p3');
  // next poll continues from the cursor: no date range, no file repeated
  calls.length = 0; await c.pollNow();
  assert.ok(calls.some((x) => /type=receipt/.test(x[0]) && /nextPage=p3/.test(x[0]) && !/dateRangeStartsAt/.test(x[0]))); assert.equal(c.stats().records, 3);
  // rate limit: stops this poll, says so, backs off
  const c429 = MC.start({ config, parser: P, pipeline: { emit() {} }, log, stateDir: '', autoStart: false, now: () => NOW, fetchImpl: async (u) => (u.endsWith('/oauth/token') ? res(200, { access_token: 't', expires_in: 1800 }) : res(429, {})) });
  await c429.pollNow(); assert.match(c429.stats().last_error, /rate limit/);
  // refused credentials: a clear message, no retry storm
  const cBad = MC.start({ config, parser: P, pipeline: { emit() {} }, log, stateDir: '', autoStart: false, now: () => NOW, fetchImpl: async () => res(401, { error: 'invalid_client' }) });
  await cBad.pollNow(); assert.match(cBad.stats().last_error, /refused the client ID \/ secret/);
  const t = await cBad.testConnection(); assert.equal(t.ok, false); assert.match(t.steps[0].text, /refused/);
  // misconfigured: not started, says why; a non-Mimecast address is refused before any secret is sent
  assert.match(MC.start({ config: { mimecast: { enabled: true } }, parser: P, pipeline: {} }).stats().error, /client ID and secret are not set/);
  const evil = { mimecast: { enabled: true, base_url: 'https://collector.evil.example' } }; Object.defineProperty(evil, 'secrets', { value: { mimecast: { client_id: 'a', client_secret: 'b' } } });
  assert.match(MC.start({ config: evil, parser: P, pipeline: {} }).stats().error, /https address on mimecast\.com/);
});

test('settings routes: roles and the refused case, validation, write-only secrets, files written, collector reloaded, audit', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcr-')), cfgFile = path.join(dir, 'config.json'), secFile = path.join(dir, 'secrets.json');
  fs.writeFileSync(cfgFile, '{"api":{"port":9120}}'); fs.writeFileSync(secFile, '{}');
  const config = {}; Object.defineProperty(config, '_paths', { value: { config: cfgFile, secrets: secFile } }); Object.defineProperty(config, 'secrets', { value: {}, writable: true });
  let reloads = 0, polls = 0;
  const mimecastFetch = async (u) => (u.endsWith('/oauth/token') ? res(200, { access_token: 't', expires_in: 1800 }) : res(200, { value: [], '@nextPage': 'x', isCaughtUp: true }));
  const R = {}; require('../engine/collect/mimecast-routes').register({ route: (m, p, h) => { R[m + ' ' + p] = h; } },
    { config, log: { error() {}, info() {}, warn() {} }, mimecastFetch, reloadMimecast: async () => { reloads++; }, mimecastStats: () => ({ polls, records: 0, last_error: '' }), mimecastPoll: async () => { polls++; } });
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 }, audits = [];
  const call = async (m, p, b, role = 'admin') => {
    const o = {}; const ctx = { role, user: role + '.syn', body: b, params: {}, audit: (a, t, d) => audits.push({ a, t, d, by: role + '.syn' }), ok(x) { o.s = 200; o.b = x; }, fail(c, msg) { o.s = c; o.e = msg; },
      need(r) { if ((RANK[role] || 0) >= (RANK[r] || 0)) return true; this.fail(403, 'forbidden'); return false; } };
    const rv = await R[m + ' /api/soc' + p](ctx); if (o.s === undefined) { o.s = 200; o.b = rv; } return o;
  };
  // roles: settings are admin-only; poll now is operator
  for (const role of ['viewer', 'operator']) { assert.equal((await call('GET', '/cloud/mimecast', undefined, role)).s, 403, role); assert.equal((await call('PUT', '/cloud/mimecast', { enabled: false }, role)).s, 403, role); assert.equal((await call('POST', '/cloud/mimecast/test', {}, role)).s, 403, role); }
  assert.equal((await call('POST', '/cloud/mimecast/sync', {}, 'viewer')).s, 403);
  // validation, each naming the field
  let r = await call('PUT', '/cloud/mimecast', { enabled: true }); assert.equal(r.s, 400); assert.match(r.e, /client ID and client secret/);
  r = await call('PUT', '/cloud/mimecast', { base_url: 'https://collector.evil.example' }); assert.equal(r.s, 400); assert.match(r.e, /base_url/);
  r = await call('PUT', '/cloud/mimecast', { types: ['receipt', 'DROP TABLE;'] }); assert.equal(r.s, 400); assert.match(r.e, /types/);
  r = await call('PUT', '/cloud/mimecast', { poll_min: 5 }); assert.equal(r.s, 400); assert.match(r.e, /poll_min/);
  r = await call('PUT', '/cloud/mimecast', { client_secret: 'has space' }); assert.equal(r.s, 400); assert.match(r.e, /client_secret/);
  r = await call('PUT', '/cloud/mimecast', { enabled: true, client_id: 'cid-syn', client_secret: 'mc-secret-syn', types: ['receipt', 'URL Protect'], extra: 'dropped' });
  assert.equal(r.s, 200, r.e); assert.equal(r.b.client_secret_set, true); assert.equal(r.b.applied, true); assert.equal(reloads, 1); assert.deepEqual(r.b.types, ['receipt', 'url protect']);
  assert.ok(!JSON.stringify(r.b).includes('mc-secret-syn') && !JSON.stringify(r.b).includes('cid-syn'), 'secrets are write-only');
  assert.equal(JSON.parse(fs.readFileSync(secFile, 'utf8')).mimecast.client_secret, 'mc-secret-syn'); assert.ok(!fs.readFileSync(cfgFile, 'utf8').includes('mc-secret-syn')); assert.ok(!('extra' in JSON.parse(fs.readFileSync(cfgFile, 'utf8')).mimecast), 'undeclared fields are dropped');
  const a = audits.find((x) => x.a === 'cloud.mimecast.config'); assert.ok(a && a.by === 'admin.syn' && a.d.client_secret_changed === true && !JSON.stringify(a).includes('mc-secret-syn'), 'audited with who, without the secret');
  // test + poll now
  const t = await call('POST', '/cloud/mimecast/test', {}); assert.equal(t.s, 200); assert.equal(t.b.ok, true, JSON.stringify(t.b)); assert.ok(audits.some((x) => x.a === 'cloud.mimecast.test'));
  config.mimecast.enabled = true;
  const s = await call('POST', '/cloud/mimecast/sync', {}, 'operator'); assert.equal(s.s, 200); assert.equal(polls, 1); assert.ok(audits.some((x) => x.a === 'cloud.mimecast.sync' && x.by === 'operator.syn'));
  assert.equal((await call('POST', '/cloud/mimecast/sync', { anything: 1 }, 'operator')).s, 200, 'undeclared fields are ignored, not used');
});
