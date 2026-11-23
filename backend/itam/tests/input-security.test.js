// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hostile input at the API boundary: malformed / oversized / mistyped bodies, prototype keys, mass assignment, duplicate
// records, concurrent and repeated submissions, stale edits, malicious uploads, formula injection in exports, and data a
// caller may not read. Every value here is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { startApp, SECRET } = require('./helpers');
const { fileCheck } = require('../engine/check');

function raw(port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = Buffer.isBuffer(body) ? body : Buffer.from(body || '');
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: Object.assign({ 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': 'op.one', 'X-Auth-Role': 'operator', 'Content-Type': 'application/json', 'Content-Length': data.length }, headers) }, (res) => {
      const c = []; res.on('data', (x) => c.push(x)); res.on('end', () => { const t = Buffer.concat(c).toString(); let j = null; try { j = JSON.parse(t); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json: j }); });
    });
    r.on('error', reject); r.end(data);
  });
}
const PDF = Buffer.concat([Buffer.from('%PDF-1.7\n'), Buffer.alloc(200, 0x20)]);
const b64 = (b) => Buffer.from(b).toString('base64');

test('malformed, oversized and mistyped bodies are refused before any logic runs', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const port = e.app.srv.address().port, P = '/api/itam/assets';
  assert.equal((await raw(port, 'POST', P, '{"name": "x",')).status, 400, 'broken JSON');
  assert.equal((await raw(port, 'POST', P, '[1,2,3]')).status, 400, 'an array instead of an object');
  assert.equal((await raw(port, 'POST', P, '"text"')).status, 400, 'a bare string');
  assert.equal((await raw(port, 'POST', P, 'name=x', { 'Content-Type': 'application/x-www-form-urlencoded' })).status, 415, 'a form post (CSRF shape)');
  assert.equal((await raw(port, 'POST', P, '{"name":"' + 'A'.repeat(1100000) + '"}')).status, 413, 'over the 1 MB default');
  const pr = await raw(port, 'POST', P, '{"name":"x","type":"server","__proto__":{"admin":true}}');
  assert.equal(pr.status, 400); assert.match(pr.json.error, /__proto__/);
  assert.equal(({}).admin, undefined, 'Object.prototype untouched');
  assert.equal((await raw(port, 'POST', P, '{"name":"x","constructor":{"prototype":{"x":1}}}')).status, 400);
  assert.equal((await raw(port, 'GET', '/api/itam/assets?limit=99999999')).status, 200, 'an absurd limit is clamped, not obeyed');
  assert.ok((await raw(port, 'GET', '/api/itam/assets?limit=99999999')).json.assets.length <= 5000);
});

test('mass assignment: fields a caller may not set are dropped', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const r = await e.req('POST', '/assets', { body: { name: 'MASS-1', type: 'server', id: 'as_evil', created_at: '1999-01-01', source: 'vcenter', locked: { name: false }, history: [{ x: 1 }], role: 'admin' } });
  assert.equal(r.status, 200);
  const a = e.app.store.collection('assets').get(r.json.asset.id);
  assert.notEqual(a.id, 'as_evil'); assert.notEqual(a.created_at, '1999-01-01'); assert.equal(a.source, 'manual'); assert.equal(a.role, undefined);
});

test('duplicate records: one asset per asset tag and per real serial', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const a = await e.req('POST', '/assets', { body: { name: 'DUP-1', type: 'server', asset_tag: 'AT-100', serial: 'SN-REAL-1' } });
  assert.equal(a.status, 200);
  const t2 = await e.req('POST', '/assets', { body: { name: 'DUP-2', type: 'server', asset_tag: ' at-100 ' } });
  assert.equal(t2.status, 409); assert.equal(t2.json.code, 'duplicate_asset_tag'); assert.match(t2.json.error, /DUP-1/);
  const s2 = await e.req('POST', '/assets', { body: { name: 'DUP-3', type: 'server', serial: 'sn-real-1' } });
  assert.equal(s2.status, 409); assert.equal(s2.json.code, 'duplicate_serial');
  for (const junk of ['To be filled by O.E.M.', '0', 'N/A']) assert.equal((await e.req('POST', '/assets', { body: { name: 'J-' + junk, type: 'server', serial: junk } })).status, 200, 'placeholder serial "' + junk + '" is not a duplicate');
  assert.equal((await e.req('POST', `/assets/${a.json.asset.id}`, { body: { asset_tag: 'AT-100', serial: 'SN-REAL-1', notes: 'own values again' } })).status, 200, 'an asset keeps its own tag');
});

test('concurrent duplicate submissions run once; Idempotency-Key replays; stale edits are refused', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  // a double click on a slow action: the second identical request waits for the first and gets its answer
  let runs = 0;
  e.app.srv.route('POST', '/test/slow-create', async (ctx) => { ctx.need('operator'); const n = ++runs; await new Promise((r) => setTimeout(r, 150)); return { id: 'run-' + n, name: ctx.body.name }; });
  const body = { name: 'DOUBLE-CLICK' };
  const [x, y] = await Promise.all([e.req('POST', '/test/slow-create', { body }), e.req('POST', '/test/slow-create', { body })]);
  assert.equal(x.status, 200); assert.equal(y.status, 200);
  assert.equal(runs, 1, 'the action ran once'); assert.equal(x.json.id, y.json.id, 'both callers get the same answer');
  const [o1, o2] = await Promise.all([e.req('POST', '/test/slow-create', { body, user: 'ali' }), e.req('POST', '/test/slow-create', { body, user: 'sara' })]);
  assert.notEqual(o1.json.id, o2.json.id, 'two different people are never merged');
  await e.req('POST', '/test/slow-create', { body });
  assert.equal(runs, 4, 'a repeat after the first finished is a new request (business rules decide)');
  const k = { 'Idempotency-Key': 'form-7f3a9c21' };
  const i1 = await e.req('POST', '/assets', { body: { name: 'RETRY-1', type: 'server' }, headers: k });
  const i2 = await e.req('POST', '/assets', { body: { name: 'RETRY-1', type: 'server' }, headers: k });
  assert.equal(i1.json.asset.id, i2.json.asset.id); assert.equal(i2.headers['idempotent-replay'], 'true');
  assert.equal((await e.req('POST', '/assets', { body: { name: 'X', type: 'server' }, headers: { 'Idempotency-Key': 'bad key!' } })).status, 400);
  const id = i1.json.asset.id, at = e.app.store.collection('assets').get(id).updated_at;
  assert.equal((await e.req('POST', `/assets/${id}`, { body: { notes: 'first editor', if_updated_at: at } })).status, 200);
  const st = await e.req('POST', `/assets/${id}`, { body: { notes: 'second editor, loaded earlier', if_updated_at: at } });
  assert.equal(st.status, 409); assert.equal(st.json.code, 'stale_edit');
});

test('uploads: type allow-list, real content, clean names', async (t) => {
  assert.throws(() => fileCheck('report.html', Buffer.from('<html><script>alert(1)</script>')), /not accepted/);
  assert.throws(() => fileCheck('logo.svg', Buffer.from('<svg onload=alert(1)>')), /not accepted/);
  assert.throws(() => fileCheck('invoice.pdf', Buffer.from('MZ\x90\x00 this is a program')), /not a real \.pdf/);
  assert.throws(() => fileCheck('sheet.xlsx', Buffer.from('PK\x03\x04 but no content types')), /not a real \.xlsx/);
  assert.throws(() => fileCheck('list.csv', Buffer.from('a,b\n<script>fetch("//x")</script>')), /script content/);
  assert.throws(() => fileCheck('data.csv', Buffer.from([0x61, 0x00, 0x62])), /not a real \.csv/);
  assert.throws(() => fileCheck('noext', PDF), /not accepted/);
  assert.equal(fileCheck('..\\..\\etc/../evidence:"Q3".pdf', PDF).name, 'evidence"Q3".pdf'.replace(/"/g, ''), 'path and reserved characters removed');
  assert.equal(fileCheck('.hidden.pdf', PDF).name, 'hidden.pdf');
  assert.throws(() => fileCheck('big.pdf', Buffer.concat([PDF, Buffer.alloc(9 * 1024 * 1024)]), { max: 8 * 1024 * 1024 }), /larger than 8 MB/);

  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const up = (filename, content) => e.req('POST', '/grc/evidence', { body: { framework: 'SAMA CSF', control: '3.3.5', title: 'Synthetic evidence', filename, content_b64: b64(content) } });
  assert.equal((await up('x.html', '<script>alert(1)</script>')).status, 400, 'GRC evidence: HTML refused');
  assert.equal((await up('virus.pdf', 'MZ\x90\x00')).status, 400, 'GRC evidence: a renamed program refused');
  const ok = await up('../../policy.pdf', PDF);
  assert.equal(ok.status, 200, 'a real PDF is accepted: ' + JSON.stringify(ok.json));
  const f = e.app.store.collection('grc_files').all()[0];
  assert.equal(f.filename, 'policy.pdf'); assert.equal(f.mime, 'application/pdf');
  // unauthorized data access
  assert.equal((await e.req('GET', '/grc/files/' + f.id, { role: 'viewer' })).status, 403, 'a viewer cannot download evidence');
  assert.equal((await e.req('GET', '/grc/files/' + f.id, { role: 'operator' })).status, 200);
});

test('unauthorized access and malicious payloads', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const port = e.app.srv.address().port;
  assert.equal((await e.req('POST', '/assets', { role: 'viewer', body: { name: 'V', type: 'server' } })).status, 403, 'viewer cannot write');
  assert.equal((await e.req('GET', '/assets', { user: '', role: '' })).status, 401, 'no identity');
  assert.equal((await e.req('GET', '/assets', { secret: 'wrong-secret-0123456789' })).status, 401, 'not through the proxy');
  assert.equal((await e.req('GET', '/assets', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403, 'cross-site browser request');
  assert.equal((await e.req('GET', '/assets', { role: 'superuser' })).status, 401, 'an unknown role is no role');
  assert.equal((await raw(port, 'GET', '/api/itam/assets/..%2f..%2fetc%2fpasswd')).status, 404, 'a traversal id finds nothing');
  // stored as data, returned as JSON (never as HTML) - the pages escape on output
  const x = await e.req('POST', '/assets', { body: { name: '<img src=x onerror=alert(1)>', type: 'server' } });
  assert.equal(x.status, 200);
  const g = await e.req('GET', `/assets/${x.json.asset.id}`);
  assert.match(g.headers['content-type'], /^application\/json/); assert.equal(g.headers['x-content-type-options'], 'nosniff');
  // formula injection in an export
  const { createCadence } = require('../engine/pentest');
  e.app.assets.create({ name: '=HYPERLINK("http://x","click")', type: 'server', status: 'in_use' }, { user: 'syed', role: 'admin' });
  assert.match(createCadence(e.app).csv(), /"'=HYPERLINK/, 'a cell that starts with = is neutralised');
});

/* review regressions (2026-10-22): each failed before its fix */
test('review: uniqueness and stale edits hold under concurrency with the Python writer on (production default)', async (t) => {
  const e = await startApp({ noAi: true, config: { discovery: { python_bin: 'python3' } } }); t.after(() => e.close());
  const [a, b] = await Promise.all([e.req('POST', '/assets', { body: { name: 'RACE-A', type: 'server', asset_tag: 'AT-RACE' } }), e.req('POST', '/assets', { body: { name: 'RACE-B', type: 'server', asset_tag: 'AT-RACE' } })]);
  assert.deepEqual([a.status, b.status].sort(), [200, 409]);
  assert.equal(e.app.store.collection('assets').all((x) => x.asset_tag === 'AT-RACE').length, 1, 'one asset per tag');
  const id = (a.status === 200 ? a : b).json.asset.id, at = e.app.store.collection('assets').get(id).updated_at;
  const [x, y] = await Promise.all([e.req('POST', `/assets/${id}`, { user: 'alice', body: { notes: 'from alice', if_updated_at: at } }), e.req('POST', `/assets/${id}`, { user: 'bob', body: { notes: 'from bob', if_updated_at: at } })]);
  assert.deepEqual([x.status, y.status].sort(), [200, 409], 'one of two editors who loaded the same version is told it changed');
});

test('review: duplicate guard keeps query strings apart; an Idempotency-Key cannot be reused for another body', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const ran = [];
  e.app.srv.route('POST', '/test/run', async (ctx) => { ctx.need('operator'); ran.push(ctx.query.source); await new Promise((r) => setTimeout(r, 100)); return { ran: ctx.query.source }; });
  const [n, v] = await Promise.all([e.req('POST', '/test/run?source=netops', { body: {} }), e.req('POST', '/test/run?source=vcenter', { body: {} })]);
  assert.deepEqual([n.json.ran, v.json.ran], ['netops', 'vcenter']); assert.equal(ran.length, 2);
  const k = { 'Idempotency-Key': 'form-reuse-0001' };
  assert.equal((await e.req('POST', '/test/run?source=a', { body: { x: 1 }, headers: k })).status, 200);
  const reuse = await e.req('POST', '/test/run?source=a', { body: { x: 2 }, headers: k });
  assert.equal(reuse.status, 422, 'same key, different body: refused, not a silent replay of the old answer');
});

test('review: evidence text files as Windows saves them are accepted; disguised binaries and namespaced script are not', () => {
  assert.equal(fileCheck('export.csv', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('name,value\r\nsrv,1\r\n', 'utf16le')])).ext, 'csv', 'UTF-16 LE with BOM (Excel Unicode Text)');
  assert.equal(fileCheck('notes.txt', Buffer.from('caf\xe9 r\xe9sum\xe9', 'latin1')).ext, 'txt', 'Windows-1252');
  assert.throws(() => fileCheck('bin.csv', Buffer.from([0x4d, 0x5a, 0x00, 0x01])), /not a real \.csv/);
  assert.throws(() => fileCheck('x.xml', Buffer.from('<h:script>alert(1)</h:script>')), /script content/);
  assert.throws(() => fileCheck('u.csv', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('<script>x</script>', 'utf16le')])), /script content/);
});
