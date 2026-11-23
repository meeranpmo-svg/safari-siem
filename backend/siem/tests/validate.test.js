// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// sentra-siem-validate (engine/validate): the synthetic attack scenarios fire every rule they target through the real
// parser + detector, every built-in rule is covered (or explicitly skipped), the events are labelled, and the live /
// check commands talk to the engine API correctly (fake API that runs the real parser + detector behind /ingest).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { buildScenarios } = require('../engine/validate/scenarios');
const cli = require('../engine/validate/cli');
const { loadBuiltinRules } = require('../engine/detect/ruleset');
const { createParser } = require('../engine/parse');
const { createDetector } = require('../engine/detect/engine');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-validate-'));
const silent = { print: () => {}, printErr: () => {} };

test('every enabled built-in rule has a scenario or a stated reason to skip', () => {
  const set = buildScenarios({ tag: 'cov' });
  // rules still without fixtures (tests/fixtures-pending.json) have no validation scenario either
  const covered = new Set([...set.scenarios.flatMap((s) => s.rules), ...set.skipped.map((s) => s.rule), ...require('./fixtures-pending.json').rules]);
  const missing = loadBuiltinRules().filter((r) => r.enabled !== false && !covered.has(r.id)).map((r) => r.id);
  assert.deepEqual(missing, [], `rules without a validation scenario: ${missing.join(', ')}`);
  const ids = new Set(loadBuiltinRules().map((r) => r.id));
  for (const s of set.scenarios) for (const r of s.rules) assert.ok(ids.has(r), `${s.id} targets unknown rule ${r}`);
});

test('scenario events are labelled synthetic data', () => {
  const set = buildScenarios({ tag: 'lbl42' });
  assert.equal(set.tag, 'lbl42');
  const ok = /^(10\.25[01]\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1$|0\.0\.0\.0$)/;
  for (const sc of set.scenarios) {
    assert.ok(sc.items.length > 0, sc.id);
    for (const it of sc.items) {
      assert.ok(it.line.includes('ashval') || it.line.includes('lbl42') || /eicar|validation|evil\.example/i.test(it.line) || sc.id.startsWith('web-cmd'), `${sc.id}: unlabelled line ${it.line.slice(0, 120)}`);
      for (const ip of it.line.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []) assert.ok(ok.test(ip), `${sc.id}: ${ip} outside the documentation/test ranges`);
    }
  }
  assert.notEqual(buildScenarios().tag, buildScenarios().tag, 'each run gets its own tag');
});

test('offline: every scenario fires the rules it targets', async () => {
  const out = tmp();
  const code = await cli.main(['offline', '--out', out, '--tag', 'off1'], silent);
  const rep = JSON.parse(fs.readFileSync(path.join(out, fs.readdirSync(out).find((f) => f.endsWith('.json'))), 'utf8'));
  const failed = rep.rows.filter((r) => r.result === 'FAIL').map((r) => r.rule);
  assert.deepEqual(failed, []);
  assert.equal(code, 0);
  assert.ok(rep.summary.pass >= 60, `only ${rep.summary.pass} rules passed`);
  assert.ok(rep.rows.some((r) => r.rule === 'SENTRA-SCH-001' && r.result === 'SKIPPED'));
  const html = fs.readFileSync(path.join(out, fs.readdirSync(out).find((f) => f.endsWith('.html'))), 'utf8');
  assert.match(html, /detection validation/);
  assert.match(html, /100%/);
});

test('report notes explain baseline and organisation-wide misses; html escapes', () => {
  const set = { tag: 't', skipped: [] };
  const scenarios = [{ id: 's1', platform: 'Exchange', title: 'x', rules: ['R1'], learning: true }, { id: 's2', platform: 'Windows', title: '<b>y</b>', rules: ['R2', 'R3'] }];
  const rules = [{ id: 'R1', name: 'one', enabled: true, org_wide: false }, { id: 'R2', name: 'two', enabled: true, org_wide: true, suppress_s: 3600 }, { id: 'R3', name: 'three', enabled: false }];
  const res = cli.buildResult({ o: { source: 'sentra-validate' }, mode: 'live', set, scenarios, rules, alerts: [], sentAt: { s1: 1, s2: 2 } });
  const by = Object.fromEntries(res.rows.map((r) => [r.rule, r]));
  assert.match(by.R1.note, /learning period/);
  assert.match(by.R2.note, /organisation-wide.*60 min/);
  assert.equal(by.R3.result, 'DISABLED');
  assert.ok(!cli.html(res).includes('<b>y</b>'));
});

test('options are validated', () => {
  assert.throws(() => cli.parseArgs(['live', '--only', 'mainframe']), /unknown platform/);
  assert.throws(() => cli.parseArgs(['live', '--source', '../x']), /invalid --source/);
  assert.throws(() => cli.parseArgs(['live', '--wait', '0']), /--wait/);
  assert.equal(cli.parseArgs(['live', '--only', 'Linux,web']).only.join(), 'linux,web');
});

// ---- fake engine API: real parser + detector behind /ingest, alert list / bulk close like soc/routes.js
function fakeEngine({ secret, token }) {
  const parser = createParser({});
  const alerts = [];
  const seen = { ingest: 0, bulk: [], identities: new Set() };
  const det = createDetector({ rules: loadBuiltinRules(), onAlert: (a) => { if (!a.update) alerts.push(Object.assign({ id: `ALR-${alerts.length + 1}`, status: 'new', created: Date.now() }, a)); } });
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
      const url = new URL(req.url, 'http://x');
      if (url.pathname.startsWith('/ingest/')) {
        if (req.headers['x-sentra-token'] !== token) return send(401, { error: 'invalid or missing X-Sentra-Token' });
        const lines = body.split('\n').filter(Boolean);
        for (const line of lines) { const ev = parser.parse(line, { collector: 'http', src_id: url.pathname.slice(8), src_type: 'syslog', peer_ip: '127.0.0.1', rts: Date.now() }); ev.id = `e${++seen.ingest}`; det.onEvent(ev); }
        return send(200, { ok: true, accepted: lines.length, rejected: 0, errors: [] });
      }
      if (req.headers['x-sentra-proxy-secret'] !== secret) return send(401, { error: 'proxy secret' });
      seen.identities.add(`${req.headers['x-auth-user']}/${req.headers['x-auth-role']}`);
      if (url.pathname === '/api/soc/health') return send(200, { ok: true });
      if (url.pathname === '/api/soc/rules') return send(200, { items: loadBuiltinRules() });
      if (url.pathname === '/api/soc/alerts' && req.method === 'GET') return send(200, { total: alerts.length, items: alerts.slice().reverse() });
      if (url.pathname === '/api/soc/alerts/bulk') {
        const b = JSON.parse(body); seen.bulk.push(b);
        for (const a of alerts) if (b.ids.includes(a.id)) a.status = 'closed-benign';
        return send(200, { ok: b.ids.length, failed: 0 });
      }
      return send(404, { error: 'not found' });
    });
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, port: srv.address().port, alerts, seen })));
}

function etcFor(port, dataDir, secret, token) {
  const etc = tmp();
  fs.writeFileSync(path.join(etc, 'config.json'), JSON.stringify({ data_dir: dataDir, api: { host: '127.0.0.1', port }, sources: [{ id: 'sentra-validate', type: 'syslog' }] }));
  fs.writeFileSync(path.join(etc, 'secrets.json'), JSON.stringify({ proxy_secret: secret, ingest_tokens: { 'sentra-validate': token } }));
  return etc;
}

test('live: sends the scenarios, collects the alerts, closes them, removes the test IOC list', async () => {
  const secret = 'p'.repeat(32); const token = 't'.repeat(64);
  const eng = await fakeEngine({ secret, token });
  const data = tmp(); fs.mkdirSync(path.join(data, 'intel'));
  const etc = etcFor(eng.port, data, secret, token);
  const out = tmp();
  process.env.SENTRA_VALIDATE_INTEL_WAIT_MS = '0';
  try {
    const code = await cli.main(['live', '--etc', etc, '--out', out, '--wait', '20', '--only', 'linux,web,intel', '--tag', 'live1'], silent);
    const rep = JSON.parse(fs.readFileSync(path.join(out, fs.readdirSync(out).find((f) => f.endsWith('.json'))), 'utf8'));
    // the fake engine has no intel lists loaded, so intel rules are expected to be missed; everything else passes
    const failed = rep.rows.filter((r) => r.result === 'FAIL').map((r) => r.rule);
    assert.deepEqual(failed.filter((r) => !r.startsWith('SENTRA-INTEL')), []);
    assert.equal(code, failed.length ? 1 : 0);
    assert.ok(rep.rows.find((r) => r.rule === 'SENTRA-LNX-001').alert_id.startsWith('ALR-'));
    assert.equal(eng.seen.bulk.length, 1);
    assert.equal(eng.seen.bulk[0].action, 'close');
    assert.equal(eng.seen.bulk[0].reason, 'benign');
    assert.match(eng.seen.bulk[0].note, /live1/);
    assert.ok(eng.alerts.every((a) => a.status === 'closed-benign'));
    assert.deepEqual([...eng.seen.identities], ['sentra-siem-validate/operator']);
    assert.deepEqual(fs.readdirSync(path.join(data, 'intel')), [], 'test IOC list removed after the run');
  } finally { delete process.env.SENTRA_VALIDATE_INTEL_WAIT_MS; eng.srv.close(); }
});

test('live: a missing token or unreachable engine is a clear error (exit 2)', async () => {
  const etc = etcFor(1, tmp(), 'p'.repeat(32), 't'.repeat(64));
  const errs = [];
  const io = { print: () => {}, printErr: (s) => errs.push(String(s)) };
  try {
    assert.equal(await cli.main(['live', '--etc', etc, '--source', 'other-src'], io), 2);
    assert.match(errs.join(''), /sentra-siem-validate setup/);
    assert.equal(await cli.main(['live', '--etc', etc, '--only', 'web'], io), 2);
    assert.match(errs.join(''), /cannot reach the engine API/);
  } finally { /* nothing to restore */ }
});

test('check: alerts for one host since a time, expected rules PASS/FAIL', async () => {
  const secret = 'p'.repeat(32); const token = 't'.repeat(64);
  const eng = await fakeEngine({ secret, token });
  const etc = etcFor(eng.port, tmp(), secret, token);
  try {
    const since = new Date(Date.now() - 1000).toISOString();
    eng.alerts.push({ id: 'ALR-1', rule_id: 'SENTRA-IAM-001', rule_name: 'x', severity: 4, host: 'pc01.corp.local', created: Date.now(), status: 'new' });
    eng.alerts.push({ id: 'ALR-2', rule_id: 'SENTRA-SYS-004', rule_name: 'y', severity: 2, host: 'pc02', created: Date.now(), status: 'new' });
    eng.alerts.push({ id: 'ALR-3', rule_id: 'SENTRA-SYS-002', rule_name: 'z', severity: 2, host: 'pc01', created: Date.now() - 3600000, status: 'new' });
    assert.equal(await cli.main(['check', '--etc', etc, '--host', 'PC01', '--since', since, '--expect', 'SENTRA-IAM-001'], silent), 0);
    assert.equal(await cli.main(['check', '--etc', etc, '--host', 'pc01', '--since', since, '--expect', 'SENTRA-IAM-001,SENTRA-SYS-004'], silent), 1);
    assert.equal(await cli.main(['check', '--etc', etc, '--host', 'pc01'], silent), 2, '--since is required');
    assert.deepEqual([...eng.seen.identities], ['sentra-siem-validate/viewer']);
  } finally { eng.srv.close(); }
});
