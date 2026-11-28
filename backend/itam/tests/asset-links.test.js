// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Web addresses of an asset: validation (http/https, no logins in the URL), replace-list semantics, roles, audit, and
// the reachability check against a real local web server.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { startApp } = require('./helpers');
const { registerAssetLinks, normUrl } = require('../engine/asset-links');

const ADM = { user: 'syed', role: 'admin' };

test('normUrl: http(s) only, host required, no credentials, scheme added when missing', () => {
  assert.equal(normUrl(('https://sol01.' + 'corp-hq.com' + ':8443/em')), ('https://sol01.' + 'corp-hq.com' + ':8443/em'));
  assert.equal(normUrl(('ilom-sol01.' + 'corp-hq.com')), ('https://ilom-sol01.' + 'corp-hq.com' + '/'));
  assert.throws(() => normUrl('ftp://x.local/a'), /only http/);
  assert.throws(() => normUrl('https://admin:Secret1@ilom.local/'), /user name \/ password/);
  assert.throws(() => normUrl(''), /required/);
  assert.equal(normUrl('https://app.local/x#frag'), 'https://app.local/x');
});

test('asset links: saved per asset, replaced as a list, roles enforced, audited; check reports status and errors', async (t) => {
  const site = http.createServer((req, res) => {
    if (req.url === '/ok') { res.writeHead(200); return res.end('hello'); }
    if (req.url === '/login') { res.writeHead(401); return res.end(); }
    if (req.url === '/moved') { res.writeHead(302, { Location: '/ok' }); return res.end(); }
    res.writeHead(500); res.end();
  });
  await new Promise((r) => site.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${site.address().port}`;
  const e = await startApp({ noAi: true });
  t.after(async () => { site.close(); await e.close(); });
  registerAssetLinks(e.app.srv, e.app, { blocked: () => false });   // the test site runs on 127.0.0.1, which production refuses
  const id = e.app.assets.create({ name: 'SOL01', type: 'server', status: 'in_use', mgmt_ip: '192.168.9.30' }, ADM).asset.id;
  const op = e.as('ali', 'operator'), viewer = e.as('v', 'viewer');

  assert.equal((await viewer('POST', `/asset-links/${id}`, { body: { links: [{ url: base + '/ok' }] } })).status, 403, 'viewer cannot change');
  let r = await op('POST', `/asset-links/${id}`, { body: { links: [
    { label: 'ERP', url: base + '/ok', kind: 'app' }, { label: 'ILOM', url: base + '/login', kind: 'mgmt' },
    { label: 'old', url: base + '/moved' }, { url: base + '/ok' }, { label: 'dead', url: 'http://127.0.0.1:1/' } ] } });
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json.links.map((l) => [l.label, l.kind]), [['ERP', 'app'], ['ILOM', 'mgmt'], ['old', 'other'], ['dead', 'other']], 'duplicate dropped, unknown kind = other');
  assert.equal((await op('POST', `/asset-links/${id}`, { body: { links: [{ url: 'https://u:p@x.local' }] } })).status, 400);
  assert.equal((await op('POST', '/asset-links/as_nope', { body: { links: [] } })).status, 404);
  assert.equal((await op('POST', `/asset-links/${id}`, { body: { links: Array.from({ length: 21 }, (_, i) => ({ url: `https://h${i}.local` })) } })).status, 400);
  // everyone can read
  r = await viewer('GET', `/asset-links/${id}`);
  assert.equal(r.status, 200); assert.equal(r.json.links.length, 4);
  // check
  r = await op('POST', `/asset-links/${id}/check`);
  const c = r.json.checked;
  assert.deepEqual([c[base + '/ok'].status, c[base + '/ok'].ok], [200, true]);
  assert.deepEqual([c[base + '/login'].status, c[base + '/login'].ok], [401, true], 'a login page answering 401 is reachable');
  assert.equal(c[base + '/moved'].redirect, '/ok');
  assert.deepEqual([c['http://127.0.0.1:1/'].ok, c['http://127.0.0.1:1/'].error], [false, 'connection refused']);
  // replacing keeps ids and check results of addresses that stay, drops removed ones
  const ilomId = r.json.links.find((l) => l.label === 'ILOM').id;
  r = await op('POST', `/asset-links/${id}`, { body: { links: [{ label: 'ILOM (renamed)', url: base + '/login', kind: 'mgmt' }] } });
  assert.equal(r.json.links[0].id, ilomId); assert.ok(r.json.checked[base + '/login']); assert.equal(Object.keys(r.json.checked).length, 1);
  // export + audit
  assert.equal((await viewer('GET', '/asset-links')).status, 403);
  assert.deepEqual(Object.keys((await op('GET', '/asset-links')).json.assets), [id]);
  const aud = e.app.store.auditTail(50, (x) => /^asset\.links/.test(x.action || ''));
  assert.ok(aud.some((x) => x.action === 'asset.links' && x.detail.removed.length === 3));
  assert.ok(aud.some((x) => x.action === 'asset.links.check'));
});

// security review: the link check never reaches this server, link-local or cloud metadata (by IP literal or by a name)
test('link check refuses loopback, link-local and metadata addresses', async () => {
  const L = require('../engine/asset-links');
  for (const ip of ['127.0.0.1', '127.8.8.8', '::1', '169.254.169.254', '0.0.0.0', 'fe80::1', '::ffff:127.0.0.1']) assert.equal(L.blockedAddr(ip), true, ip);
  for (const ip of ['10.1.2.3', '192.168.1.10', '172.16.0.5', '8.8.8.8']) assert.equal(L.blockedAddr(ip), false, ip + ' (internal consoles are what asset links are for)');
  // end to end with the production guard: a link to this server is refused, nothing is fetched
  const http = require('node:http'); let hits = 0;
  const site = http.createServer((req, res) => { hits++; res.end('x'); }); await new Promise((r) => site.listen(0, '127.0.0.1', r));
  const e = await startApp({ noAi: true });
  try {
    L.registerAssetLinks(e.app.srv, e.app);
    const id = e.app.assets.create({ name: 'SSRF01', type: 'server', status: 'in_use', mgmt_ip: '192.168.9.31' }, ADM).asset.id, op = e.as('ali', 'operator');
    await op('POST', `/asset-links/${id}`, { body: { links: [{ url: 'http://127.0.0.1:' + site.address().port + '/', kind: 'app' }, { url: 'http://localhost:' + site.address().port + '/', kind: 'app' }] } });
    const r = await op('POST', `/asset-links/${id}/check`, { body: {} });
    assert.equal(r.status, 200, r.raw); assert.equal(hits, 0, 'the server never fetched itself');
    for (const v of Object.values(r.json.checked)) assert.match(v.error, /refused/);
  } finally { site.close(); await e.close(); }
});

test('SSRF: an IPv4-mapped IPv6 address cannot reach this server or cloud metadata (dotted, hex as the URL parser writes it, written out)', () => {
  const { blockedAddr } = require('../engine/asset-links');
  const host = (u) => new URL(u).hostname.replace(/^\[|\]$/g, '');
  for (const u of ['http://[::ffff:127.0.0.1]:8123/', 'http://[::ffff:7f00:1]/', 'http://[::ffff:169.254.169.254]/latest/meta-data/', 'http://[::ffff:a9fe:a9fe]/', 'http://[0:0:0:0:0:ffff:7f00:0001]/'])
    assert.equal(blockedAddr(host(u)), true, u + ' -> ' + host(u));
  for (const ok of ['10.0.1.49', '::ffff:a00:131', '2001:db8::1']) assert.equal(blockedAddr(ok), false, ok + ' is an ordinary address');
});
