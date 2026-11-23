// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Threat-intel feeds: formats (lines, host file, CSV column, JSON lines), internal addresses dropped, file written into
// the intel folder and picked up by intel.js, schedule / failures keep the last good file, header kept write-only,
// https-only URLs, upload, presets off by default.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createIntelFeeds, parseFeed } = require('../engine/detect/intel-feeds');
const { createIntel } = require('../engine/detect/intel');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-feeds-'));

test('feed formats are read; private, loopback and local names are dropped', () => {
  assert.deepEqual(parseFeed('# Feodo\n203.0.113.5\n10.1.1.1\n198.51.100.7 # c2\n127.0.0.1\n'), ['203.0.113.5', '198.51.100.7']);
  assert.deepEqual(parseFeed('0.0.0.0 bad.example\n127.0.0.1 evil.test\n0.0.0.0 printer.local\n'), ['bad.example', 'evil.test']);
  assert.deepEqual(parseFeed('{"cidr":"192.0.2.0/24","sblid":"SBL1"}\n{"cidr":"172.16.0.0/12"}\n'), ['192.0.2.0/24']);
  assert.deepEqual(parseFeed('first_seen,ioc,threat\n2026-10-01,https://mal.example/x.exe,payload\n', { column: 'ioc' }), ['mal.example']);
  assert.deepEqual(parseFeed('44d88612fea8a8f36de82e1278abb02f\n'), ['44d88612fea8a8f36de82e1278abb02f']);
});

test('download → file in the intel folder → intel.js matches it; failures keep the last good list; header write-only', async (t) => {
  const dir = tmp(), secrets = path.join(tmp(), 'secrets.json'); fs.writeFileSync(secrets, '{}', { mode: 0o600 });
  let body = '203.0.113.5\n198.51.100.0/24\n', status = 200, seenKey = null;
  const srv = http.createServer((req, res) => { seenKey = req.headers['x-api-key'] || null; res.statusCode = status; res.end(body); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); t.after(() => srv.close());
  const url = `http://127.0.0.1:${srv.address().port}/list.txt`, audits = [];
  const F = createIntelFeeds({ dir, secretsPath: secrets, audit: (e) => audits.push(e.action) });
  const presets = F.list(); assert.ok(presets.length >= 5 && presets.every((p) => p.enabled === false), 'built-in feeds are off until switched on');
  assert.throws(() => F.put({ id: 'x1', name: 'x', url: 'http://feeds.example/list' }, 'admin'), /https/);
  assert.throws(() => F.put({ id: 'x1', name: 'x', url: 'https://u:p@feeds.example/list' }, 'admin'), /no login/);
  const v = F.put({ id: 'cert-sa', name: 'CERT-SA IOCs', url, enabled: true, interval_h: 6, header: 'X-API-Key: k-123' }, 'admin');
  assert.equal(v.header_set, true); assert.ok(!JSON.stringify(F.list()).includes('k-123'), 'the key is never returned');
  assert.equal(JSON.parse(fs.readFileSync(secrets, 'utf8')).intel_feeds['cert-sa'], 'X-API-Key: k-123');
  const r = await F.run('cert-sa', 'admin');
  assert.deepEqual(r, [{ id: 'cert-sa', ok: true, count: 2 }]); assert.equal(seenKey, 'k-123');
  const intel = await createIntel({ dir, watch: false }); t.after(() => intel.close());
  assert.deepEqual(intel.lookup('198.51.100.9'), ['feed-cert-sa', 'ip', 'any'].filter((n) => intel.lookup('198.51.100.9').includes(n)));
  assert.ok(intel.lookup('198.51.100.9').includes('feed-cert-sa'));
  // the feed breaks: the last good file stays, the error is shown
  status = 500; const r2 = await F.run('cert-sa', 'admin'); assert.equal(r2[0].ok, false); assert.match(r2[0].error, /HTTP 500/);
  assert.match(fs.readFileSync(path.join(dir, 'feed-cert-sa.txt'), 'utf8'), /203\.0\.113\.5/);
  assert.match(F.list().find((x) => x.id === 'cert-sa').last_error, /HTTP 500/);
  status = 200; body = '# nothing\n';
  assert.match((await F.run('cert-sa', 'admin'))[0].error, /no indicators/);
  // upload (offline servers)
  const u = F.upload('NCA advisory 2026-41', 'evil.example\nhttps://bad.example/a\n10.0.0.1\n', 'admin');
  assert.equal(u.count, 2); assert.ok(fs.existsSync(path.join(dir, 'feed-upload-nca-advisory-2026-41.txt')));
  assert.throws(() => F.remove('abusech-feodo', 'admin'), /switched off, not removed/);
  F.remove('cert-sa', 'admin'); assert.ok(!fs.existsSync(path.join(dir, 'feed-cert-sa.txt'))); assert.equal(JSON.parse(fs.readFileSync(secrets, 'utf8')).intel_feeds['cert-sa'], undefined);
  for (const a of ['intel.feed.add', 'intel.feed.run', 'intel.upload', 'intel.feed.remove']) assert.ok(audits.includes(a), a);
});
