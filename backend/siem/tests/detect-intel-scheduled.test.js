// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { createIntel, parseIntelText, hostOf } = require('../engine/detect/intel');
const { createScheduled } = require('../engine/detect/scheduled');
const { createDetector } = require('../engine/detect/engine');
const { tmpDir, fakeSearch } = require('./soc-fakes');

const SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

test('intel: txt + csv parsing, auto type detection, invalid lines counted', () => {
  const e = parseIntelText('# comment\n198.51.100.7 c2 server\n203.0.113.0/24\nEvil.Example.\n*.wild.example\nhttp://phish.example/login\n' + SHA + '\nnot a valid indicator!\n', false);
  assert.deepEqual(e.filter((x) => !x.invalid).map((x) => x.type), ['ip', 'cidr', 'domain', 'domain', 'domain', 'hash']);
  assert.equal(e.find((x) => x.type === 'ip').desc, 'c2 server');
  assert.equal(e.filter((x) => x.invalid).length, 1);
  const c = parseIntelText('indicator,type,description\n2001:db8::/32,cidr,test net\n"bad.example",domain,"quoted, with comma"\n44d88612fea8a8f36de82e1278abb02f,md5,\n', true);
  assert.deepEqual(c.map((x) => x.type), ['cidr', 'domain', 'hash']);
  assert.equal(c[1].desc, 'quoted, with comma');
  assert.equal(hostOf('HTTPS://User@Sub.Example.COM:8443/path?q=1'), 'sub.example.com');
  assert.equal(hostOf('[2001:db8::1]:443'), '2001:db8::1');
});

test('intel: lists from <dir>, aggregate names, subdomains, cidr, sysmon hash strings, lookup, hot reload', async () => {
  const dir = tmpDir('sentra-intel-');
  fs.writeFileSync(path.join(dir, 'c2-ips.txt'), '198.51.100.7\n203.0.113.0/24\n2001:db8:bad::/48\n');
  fs.writeFileSync(path.join(dir, 'bad-domains.csv'), 'indicator,type,description\nevil.example,domain,c2\n');
  fs.writeFileSync(path.join(dir, 'hashes.txt'), SHA + '\n');
  fs.writeFileSync(path.join(dir, 'ignored.json'), '{}');
  const intel = createIntel({ dir, pollMs: 50 });
  try {
    assert.ok(intel.match('ip', '198.51.100.7'));
    assert.ok(intel.match('ip', '203.0.113.99'));
    assert.ok(intel.match('ip', '2001:db8:bad::1'));
    assert.ok(!intel.match('ip', '8.8.8.8'));
    assert.ok(intel.match('c2-ips', '203.0.113.1'), 'per-file list name');
    assert.ok(!intel.match('bad-domains', '203.0.113.1'));
    assert.ok(intel.match('domain', 'evil.example'));
    assert.ok(intel.match('domain', 'a.b.EVIL.example.'), 'subdomain + case + trailing dot');
    assert.ok(!intel.match('domain', 'notevil.example'));
    assert.ok(!intel.match('domain', 'example'));
    assert.ok(intel.match('domain', 'https://x.evil.example/path'), 'URL reduced to host');
    assert.ok(intel.match('hash', `SHA1=AAAA,MD5=BBBB,SHA256=${SHA.toUpperCase()}`), 'Sysmon Hashes string');
    assert.ok(intel.match('any', 'evil.example') && intel.match('any', '198.51.100.7'));
    assert.ok(!intel.match('no-such-list', '198.51.100.7'));
    assert.deepEqual(intel.lookup('198.51.100.7'), ['c2-ips']);
    const st = intel.stats();
    assert.equal(st.lists, 3);
    assert.equal(st.domain, 1);
    assert.ok(st.hits.ip >= 1);
    // hot reload: new file + changed file are picked up by the poller
    fs.writeFileSync(path.join(dir, 'new.txt'), 'fresh-bad.example\n');
    fs.writeFileSync(path.join(dir, 'c2-ips.txt'), '192.0.2.10\n');
    let ok = false;
    for (let i = 0; i < 60 && !ok; i++) { await new Promise((r) => setTimeout(r, 50)); ok = intel.match('domain', 'fresh-bad.example') && intel.match('ip', '192.0.2.10') && !intel.match('ip', '198.51.100.7'); }
    assert.ok(ok, 'hot reload');
    // runtime lists + detector integration
    intel.add('manual', ['6.6.6.6']);
    const out = [];
    const d = createDetector({ rules: [{ id: 'I-1', name: 'ioc', suppress_s: 0, match: { any: [{ field: 'dst_ip', op: 'intel', value: 'ip' }, { field: 'dns_query', op: 'intel', value: 'domain' }] } }], intel, onAlert: (a) => out.push(a) });
    d.onEvent({ id: '1', ts: 1, dst_ip: '6.6.6.6' });
    d.onEvent({ id: '2', ts: 2, dns_query: 'www.fresh-bad.example' });
    d.onEvent({ id: '3', ts: 3, dst_ip: '1.1.1.1', dns_query: 'example.org' });
    assert.equal(out.length, 2);
  } finally { intel.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('scheduled: count condition, per-group condition, absence rule, suppression, errors', async () => {
  const T = Date.UTC(2026, 8, 29, 10, 0, 0);
  const events = [];
  for (let i = 0; i < 30; i++) events.push({ id: `f${i}`, ts: T - 60000 - i * 1000, action: 'logon-failed', src_ip: i < 25 ? '203.0.113.5' : '10.0.0.1' });
  const search = fakeSearch(events, { filter: (q, e) => q.includes('logon-failed') ? e.action === 'logon-failed' : q.includes('fortigate') ? e.src_type === 'fortigate' : true });
  const alerts = [];
  let now = T;
  const sch = createScheduled({
    rules: [
      { id: 'S-1', name: 'Spike', type: 'scheduled', query: 'action:logon-failed', every_min: 15, lookback_min: 60, condition: { op: 'gte', value: 20 }, severity: 2, mitre: ['T1110'] },
      { id: 'S-2', name: 'Per source', type: 'scheduled', query: 'action:logon-failed', every_min: 5, group_by: ['src_ip'], threshold: 20 },
      { id: 'S-3', name: 'Silent', type: 'scheduled', query: 'src_type:fortigate', every_min: 10, lookback_min: 30, condition: { op: 'lt', value: 1 } },
      { id: 'S-4', name: 'Disabled', type: 'scheduled', enabled: false, query: 'x' },
      { id: 'D-1', name: 'realtime rule ignored', match: { all: [{ field: 'a', op: 'eq', value: 1 }] } },
    ],
    search, onAlert: (a) => alerts.push(a), now: () => now,
  });
  assert.equal(sch.stats().length, 3);
  assert.equal(await sch.runDue(T), 3);
  const byRule = (id) => alerts.filter((a) => a.rule_id === id);
  assert.equal(byRule('S-1').length, 1);
  assert.equal(byRule('S-1')[0].count, 30);
  assert.equal(byRule('S-1')[0].source, 'scheduled');
  assert.equal(byRule('S-1')[0].ts_last - byRule('S-1')[0].ts_first, 60 * 60000);
  assert.match(byRule('S-1')[0].summary, /30 gte 20 in last 60m/);
  assert.equal(byRule('S-2').length, 1);
  assert.deepEqual(byRule('S-2')[0].group, { src_ip: '203.0.113.5' });
  assert.equal(byRule('S-2')[0].sample_event_ids.length, 20);
  assert.equal(byRule('S-3').length, 1, 'absence rule fires on zero results');
  // not due yet → no runs; later → runs again but suppressed
  assert.equal(await sch.runDue(T + 60000), 0);
  now = T + 16 * 60000;
  assert.equal(await sch.runDue(T + 16 * 60000), 3);
  assert.equal(byRule('S-1').length, 1, 'suppressed within suppress_s');
  assert.ok(sch.stats().find((s) => s.id === 'S-1').suppressed >= 1);
  // search failure is recorded, not thrown
  const bad = createScheduled({ rules: [{ id: 'S-5', name: 'x', type: 'scheduled', query: 'q' }], search: async () => { throw new Error('CH down'); } });
  const r = await bad.runRule('S-5', T);
  assert.equal(r.error, 'CH down');
  assert.equal(bad.stats()[0].errors, 1);
  // validation
  const v = createScheduled({ rules: [{ id: 'S-6', name: 'x', type: 'scheduled', query: '' }, { id: 'S-7', name: 'y', type: 'scheduled', query: 'q', group_by: ['user'], condition: { op: 'lt', value: 1 } }] });
  assert.deepEqual(v.load([{ id: 'S-6', name: 'x', type: 'scheduled', query: '' }]).errors.map((e) => e.id), ['S-6']);
  assert.match(v.load([{ id: 'S-7', name: 'y', type: 'scheduled', query: 'q', group_by: ['user'], condition: { op: 'lt', value: 1 } }]).errors[0].error, /absence/);
});

test('scheduled: pages through array-only search results when no total_estimate', async () => {
  const T = Date.UTC(2026, 8, 29, 10, 0, 0);
  const events = Array.from({ length: 2500 }, (_, i) => ({ id: `x${i}`, ts: T - 1000 - i, user: `u${i % 3}` }));
  const search = fakeSearch(events, { arrayOnly: true });
  const alerts = [];
  const sch = createScheduled({ rules: [{ id: 'S-8', name: 'big', type: 'scheduled', query: '*', every_min: 5, condition: { op: 'gt', value: 2000 } }], search, onAlert: (a) => alerts.push(a) });
  await sch.runRule('S-8', T);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].count, 2500);
  assert.equal(search.calls.length, 3);
});

test('intel: allow-*/internal-* files are reference lists, not IOCs', () => {
  const dir = tmpDir('sentra-intel-ref-');
  fs.writeFileSync(path.join(dir, 'internal-mail-domains.txt'), 'corp-internal.example\n');
  fs.writeFileSync(path.join(dir, 'allow-scanners.txt'), '10.0.0.99\n');
  fs.writeFileSync(path.join(dir, 'c2.txt'), 'evil.example\n');
  const intel = createIntel({ dir, watch: false });
  try {
    assert.ok(intel.match('internal-mail-domains', 'smtp:cfo@mail.corp-internal.example'), 'addressable by name; address → domain');
    assert.ok(!intel.match('domain', 'corp-internal.example'), 'not in the IOC domain aggregate');
    assert.ok(!intel.match('any', '10.0.0.99'));
    assert.ok(intel.match('allow-scanners', '10.0.0.99'));
    assert.ok(intel.match('domain', 'x.evil.example'));
  } finally { intel.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
