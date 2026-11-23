// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// VAPT Studio (engine/vapt-studio.js, pyengine/firecompass_rules.py) - FireCompass and Tenable merged with Greenbone - through the real routes on SYNTHETIC findings (FireCompass's
// API, Greenbone and the vault stubbed): the field mapper on a CSV and a JSON export, a preview stores nothing, the import stores
// and audits with the mapping, rows without an asset are dropped and counted, re-import updates and a full import marks what is
// gone; the merge with Greenbone (same CVE / likely / never by title alone), exposure, the explained risk; the API connection
// (https + public host only, key sealed and never returned or logged, the key again on a new address), test / pull (GET only,
// nothing stored without a confirmed mapping, a refused key named); four-eyes false positive / accepted risk; roles and the export.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:fc', role: 'admin' };
const NOW = Date.parse('2026-10-31T09:00:00Z');
const CSV = 'Finding ID,Affected Asset,Risk Title,Severity,CVSS Score,CVE IDs,Status,Discovered On,Recommendation\r\n'
  + 'FC-1,https://portal.syn-example.sa/login,Apache HTTP Server path traversal (remote code execution),Critical,9.8,CVE-2021-41773,Open,2026-06-01,Upgrade Apache to a supported release\r\n'
  + 'FC-2,10.20.0.5,OpenSSH user enumeration,Medium,5.3,CVE-2018-15473,Open,2026-10-20,Upgrade OpenSSH\r\n'
  + 'FC-3,10.20.0.6,"TLS 1.0 enabled on listener, weak ciphers",Medium,5.0,,Open,2026-10-25,Disable TLS 1.0\r\n'
  + 'FC-4,,No asset row,High,7.5,,Open,2026-10-25,x\r\n'
  + 'FC-5,mail.syn-example.sa,TLS 1.0 enabled,Low,3.1,,Open,2026-10-25,Disable TLS 1.0\r\n';

function fakeSealer() { return { seal: (id, p) => ({ alg: 'test', ct: Buffer.from(String(p)).toString('base64') }), unseal: (id, e) => Buffer.from(e.ct, 'base64').toString() }; }

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = [];
  let answer = { status: 200, json: { data: [{ uid: 'A1', target: { host: '203.0.113.10' }, name: 'Exposed admin panel', risk_level: 'High', found: '2026-10-01' }, { uid: 'A2', target: { host: '203.0.113.11' }, name: 'Expired certificate', risk_level: 'Low', found: '2026-10-02' }] } };
  const request = async (url, o) => { calls.push({ url, o }); return answer; };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3', fcRequest: request, fcSealer: fakeSealer() });
  e.app.addons.vulnscan = { findings: () => ({ items: [{ id: 'gb1', host: '10.20.0.5', hostname: 'ssh01', name: 'OpenSSH user enumeration vulnerability', severity: 'medium', score: 5.3, cves: ['CVE-2018-15473'] }, { id: 'gb2', host: '10.20.0.6', hostname: '', name: 'TLS 1.0 enabled weak ciphers listener', severity: 'medium', score: 4.3, cves: [] }, { id: 'gb3', host: '10.20.0.9', name: 'Other thing', severity: 'low', score: 2, cves: [] }] }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call, calls, setAnswer: (a) => { answer = a; } };
}
const auditOf = (e, a) => e.app.store.auditTail(300).filter((x) => x.action === a);

test('import: mapping proposed, preview stores nothing, import stores with the mapping, merge with Greenbone and explained risk', async (t) => {
  const { e, call } = await setup(t);
  e.app.assets.create({ name: 'SSH01', mgmt_ip: '10.20.0.5', type: 'server', status: 'in_use', tags: ['business-critical'] }, ADM);
  let r = await call('POST', '/vapt-studio/firecompass/import/preview', { filename: 'fc.csv', content: CSV }, OP); assert.equal(r.status, 200, r.raw);
  const pv = r.json;
  assert.equal(pv.mapping.asset, 'Affected Asset'); assert.equal(pv.mapping.title, 'Risk Title'); assert.equal(pv.mapping.cvss, 'CVSS Score'); assert.equal(pv.mapping.cve, 'CVE IDs');
  assert.equal(pv.rows, 5); assert.equal(pv.sample[0].severity, 'critical'); assert.deepEqual(pv.sample[0].cves, ['CVE-2021-41773']);
  assert.equal((await call('GET', '/vapt-studio', undefined, OP)).json.findings.length, 0, 'a preview stores nothing');
  r = await call('POST', '/vapt-studio/firecompass/import', { filename: 'fc.csv', content: CSV, mapping: { asset: 'Affected Asset' } }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /title is required/);
  r = await call('POST', '/vapt-studio/firecompass/import', { filename: 'fc.csv', content: CSV, mapping: Object.assign({}, pv.mapping, { title: 'Nope' }) }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /not in the file/);
  r = await call('POST', '/vapt-studio/firecompass/import', { filename: 'fc.csv', content: CSV, mapping: pv.mapping }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/vapt-studio/firecompass/import', { filename: 'fc.csv', content: CSV, mapping: pv.mapping }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/vapt-studio/firecompass/import', { filename: 'fc.csv', content: CSV, mapping: pv.mapping }, OP); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.import.added, 4); assert.equal(r.json.import.dropped.no_asset, 1);
  const au = auditOf(e, 'vapt.firecompass.import')[0]; assert.equal(au.by, 'nora.syn'); assert.equal(au.detail.added, 4); assert.equal(au.detail.mapping.asset, 'Affected Asset');
  const v = (await call('GET', '/vapt-studio', undefined, OP)).json;
  assert.equal(v.findings.length, 4); assert.equal(v.connection.mapping_confirmed, true);
  const f1 = v.findings.find((x) => x.source_id === 'FC-1');
  assert.equal(f1.exposure, 'external'); assert.ok(f1.why_risk.some((w) => /internet/.test(w.text)) && f1.why_risk.some((w) => /remote code execution/.test(w.text)) && f1.why_risk.some((w) => /open for \d+ days/.test(w.text)));
  assert.equal(f1.risk, Math.min(100, f1.why_risk.reduce((a, w) => a + w.points, 0)));
  const f2 = v.findings.find((x) => x.source_id === 'FC-2'); assert.equal(f2.exposure, 'internal'); assert.equal(f2.overlap, 'same'); assert.equal(f2.overlap_with.id, 'gb1');
  assert.ok(f2.why_risk.some((w) => /business-critical in IT Asset Management/.test(w.text)) && f2.why_risk.some((w) => /Greenbone/.test(w.text)));
  assert.equal(v.findings.find((x) => x.source_id === 'FC-3').overlap, 'likely', 'same host and most title words');
  assert.equal(v.findings.find((x) => x.source_id === 'FC-5').overlap, null, 'same title on another host is not the same finding');
  assert.equal(v.overlap.both, 2); assert.equal(v.overlap.gb_only, 1);
  assert.ok(v.families.some((x) => /tls/.test(x.family)), 'TLS 1.0 family: ' + JSON.stringify(v.families));
  // re-import: updates; a full import marks the missing
  r = await call('POST', '/vapt-studio/firecompass/import', { filename: 'fc.csv', content: CSV.split('\r\n').slice(0, 3).join('\r\n'), mapping: pv.mapping, full: true }, OP);
  assert.equal(r.json.import.updated, 2); assert.equal(r.json.import.missing, 2);
  // JSON export with nested fields
  r = await call('POST', '/vapt-studio/firecompass/import/preview', { filename: 'fc.json', content: JSON.stringify({ results: [{ id: 'J1', asset: { name: 'vpn.syn-example.sa' }, title: 'VPN portal exposed', severity: 'High' }] }) }, OP);
  assert.equal(r.status, 200); assert.equal(r.json.mapping.asset, 'asset.name');
  r = await call('POST', '/vapt-studio/firecompass/import/preview', { filename: 'x.json', content: '{"a":1}' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /no list of findings/);
  r = await call('POST', '/vapt-studio/firecompass/import/preview', { filename: 'x.json', content: '{bad' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /not valid JSON/);
  // export
  r = await call('GET', '/vapt-studio/export', undefined, OP); assert.equal(r.status, 200); assert.match(r.json.csv, /Apache HTTP Server/); assert.equal(auditOf(e, 'vapt.export').length, 1);
  r = await call('GET', '/vapt-studio', undefined, VIEW); assert.equal(r.status, 403, 'asset names are internal: operators only');
});

test('API connection: https + public host, key sealed and never shown or logged, test / pull GET only, nothing stored without a mapping', async (t) => {
  const { e, call, calls, setAnswer } = await setup(t);
  let r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://api.firecompass.syn', path: '/v1/findings', api_key: 'fc-SECRET-key-123' }, OP); assert.equal(r.status, 403, 'admin only');
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'http://api.firecompass.syn', path: '/v1/findings', api_key: 'k' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /https/);
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://10.0.0.5', path: '/v1/findings', api_key: 'k' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /public/);
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://localhost', path: '/v1/findings', api_key: 'k' }, ADM); assert.equal(r.status, 400);
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://api.firecompass.syn', path: 'v1', api_key: 'k' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /path/);
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://api.firecompass.syn', path: '/v1/findings' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /api_key is required/);
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://api.firecompass.syn', path: '/v1/findings', api_key: 'fc-SECRET-key-123' }, BOT); assert.equal(r.status, 403);
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://api.firecompass.syn', path: '/v1/findings', api_key: 'fc-SECRET-key-123', interval_h: 12 }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.key_set, true); assert.ok(!JSON.stringify(r.json).includes('SECRET'));
  r = await call('PUT', '/vapt-studio/firecompass/config', { base_url: 'https://other.firecompass.syn', path: '/v1/findings' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /again when the address changes/);
  r = await call('POST', '/vapt-studio/firecompass/pull', undefined, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /no confirmed field mapping/);
  assert.equal(calls.length, 0, 'nothing fetched before a mapping is confirmed');
  r = await call('POST', '/vapt-studio/firecompass/test', undefined, ADM); assert.equal(r.status, 200); assert.equal(r.json.ok, true); assert.equal(r.json.rows, 2);
  assert.equal(r.json.proposed.asset, 'target.host'); assert.equal(r.json.proposed.severity, 'risk_level');
  assert.equal(calls[0].url, 'https://api.firecompass.syn/v1/findings'); assert.equal(calls[0].o.method, 'GET'); assert.equal(calls[0].o.headers.Authorization, 'Bearer fc-SECRET-key-123');
  // confirm the mapping through an import of the same shape, then pull
  const json = JSON.stringify({ data: [{ uid: 'A1', target: { host: '203.0.113.10' }, name: 'Exposed admin panel', risk_level: 'High', found: '2026-10-01' }, { uid: 'A2', target: { host: '203.0.113.11' }, name: 'Expired certificate', risk_level: 'Low', found: '2026-10-02' }] });
  const pv = (await call('POST', '/vapt-studio/firecompass/import/preview', { filename: 'api.json', content: json }, OP)).json;
  r = await call('POST', '/vapt-studio/firecompass/import', { filename: 'api.json', content: json, mapping: pv.mapping }, OP); assert.equal(r.status, 200);
  r = await call('POST', '/vapt-studio/firecompass/pull', undefined, OP); assert.equal(r.status, 403);
  r = await call('POST', '/vapt-studio/firecompass/pull', undefined, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.import.updated, 2);
  const v = (await call('GET', '/vapt-studio', undefined, OP)).json; assert.equal(v.connection.verified, true); assert.ok(v.connection.last_pull);
  assert.ok(v.findings.every((f) => f.exposure === 'external'));
  setAnswer({ status: 401, json: {} });
  r = await call('POST', '/vapt-studio/firecompass/pull', undefined, ADM); assert.equal(r.status, 424); assert.match(r.json.error, /refused the key/);
  assert.match((await call('GET', '/vapt-studio', undefined, OP)).json.connection.last_error, /refused the key/);
  assert.ok(!JSON.stringify(e.app.store.auditTail(300)).includes('SECRET'), 'the key is never in the audit');
  assert.equal(auditOf(e, 'vapt.firecompass.config')[0].detail.key_changed, true);
  r = await call('DELETE', '/vapt-studio/firecompass/config', undefined, ADM); assert.equal(r.status, 200);
  assert.equal((await call('GET', '/vapt-studio', undefined, OP)).json.connection.configured, false);
});

test('four-eyes false positive / accepted risk, owner, validation', async (t) => {
  const { e, call } = await setup(t);
  const pv = (await call('POST', '/vapt-studio/firecompass/import/preview', { filename: 'fc.csv', content: CSV }, OP)).json;
  await call('POST', '/vapt-studio/firecompass/import', { filename: 'fc.csv', content: CSV, mapping: pv.mapping }, OP);
  const id = (await call('GET', '/vapt-studio', undefined, OP)).json.findings.find((x) => x.source_id === 'FC-5').id;
  let r = await call('POST', '/vapt-studio/findings/bad-id/owner', { owner: 'x' }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/vapt-studio/findings/' + id + '/owner', { owner: 'Infra team (synthetic)' }, OP); assert.equal(r.status, 200); assert.equal(r.json.owner, 'Infra team (synthetic)');
  r = await call('POST', '/vapt-studio/findings/' + id + '/triage', { want: 'accepted', reason: 'legacy mail relay, retired in Q1 (synthetic)' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /until is required/);
  r = await call('POST', '/vapt-studio/findings/' + id + '/triage', { want: 'false_positive', reason: 'short' }, OP); assert.equal(r.status, 400);
  r = await call('POST', '/vapt-studio/findings/' + id + '/triage', { want: 'false_positive', reason: 'the listener only offers TLS 1.2 - verified with a manual handshake (synthetic)' }, OP); assert.equal(r.status, 200); assert.equal(r.json.decision.state, 'pending');
  r = await call('POST', '/vapt-studio/findings/' + id + '/triage', { want: 'false_positive', reason: 'again and again and again' }, OP2); assert.equal(r.status, 409);
  r = await call('POST', '/vapt-studio/findings/' + id + '/decision', { decision: 'approve' }, Object.assign({}, OP, { role: 'admin' })); assert.equal(r.status, 403, 'the requester cannot decide');
  r = await call('POST', '/vapt-studio/findings/' + id + '/decision', { decision: 'approve' }, BOT); assert.equal(r.status, 403, 'an AI identity cannot decide');
  r = await call('POST', '/vapt-studio/findings/' + id + '/decision', { decision: 'maybe' }, ADM); assert.equal(r.status, 400);
  r = await call('POST', '/vapt-studio/findings/' + id + '/decision', { decision: 'approve', note: 'checked (synthetic)' }, ADM); assert.equal(r.status, 200); assert.equal(r.json.status, 'false_positive');
  assert.equal(auditOf(e, 'vapt.decision')[0].detail.requested_by, 'nora.syn');
  assert.equal(auditOf(e, 'vapt.triage').length, 1); assert.equal(auditOf(e, 'vapt.owner').length, 1);
  const v = (await call('GET', '/vapt-studio', undefined, OP)).json; assert.equal(v.summary.open, 3, 'a decided false positive is no longer open');
  r = await call('POST', '/vapt-studio/ai/ask', { question: 'what first?' }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/vapt-studio/ai/ask', { question: 'what first?' }, OP); assert.equal(r.status, 503);
});

test('Tenable cloud: keys sealed, X-ApiKeys GET only, findings per asset merged with Greenbone, refused keys named', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const calls = []; let refuse = false;
  const request = async (url, o) => {
    calls.push({ url, o });
    if (refuse) return { status: 401, json: {} };
    if (/\/workbenches\/assets\?/.test(url)) return { status: 200, json: { assets: [{ id: '1b2c3d4e-0000-4000-8000-000000000001', ipv4: ['10.20.0.5'], fqdn: ['ssh01.syn.local'] }, { id: 'bad id with spaces' }, { id: '1b2c3d4e-0000-4000-8000-000000000002', ipv4: ['203.0.113.20'], hostname: ['web-syn'] }] } };
    if (/assets\/1b2c3d4e-0000-4000-8000-000000000001\/vulnerabilities/.test(url)) return { status: 200, json: { vulnerabilities: [{ plugin_id: 90317, plugin_name: 'OpenSSH user enumeration', severity: 2, cvss3_base_score: 5.3, plugin_family: 'Misc.' }, { plugin_id: 19506, plugin_name: 'Nessus Scan Information', severity: 0 }] } };
    if (/assets\/1b2c3d4e-0000-4000-8000-000000000002\/vulnerabilities/.test(url)) return { status: 200, json: { vulnerabilities: [{ plugin_id: 142960, plugin_name: 'Apache 2.4.x < 2.4.51 Path Traversal (remote code execution)', severity: 4, cvss3_base_score: 9.8 }] } };
    return { status: 404, json: {} };
  };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3', fcRequest: request, fcSealer: fakeSealer() });
  e.app.addons.vulnscan = { findings: () => ({ items: [{ id: 'gb1', host: '10.20.0.5', name: 'OpenSSH user enumeration vulnerability', severity: 'medium', score: 5.3, cves: [] }] }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  let r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'cloud', access_key: 'AKSYNTHETIC0001', secret_key: 'SKSYNTHETIC0001' }, OP); assert.equal(r.status, 403);
  r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'cloud', access_key: 'AKSYNTHETIC0001' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /together/);
  r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'cloud', access_key: 'bad key!', secret_key: 'SKSYNTHETIC0001' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /access_key/);
  r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'cloud', base_url: 'https://192.168.1.5', access_key: 'AKSYNTHETIC0001', secret_key: 'SKSYNTHETIC0001' }, ADM); assert.equal(r.status, 400, 'the cloud is a public host');
  r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'cloud', access_key: 'AKSYNTHETIC0001', secret_key: 'SKSYNTHETIC0001', interval_h: 24 }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.base_url, 'https://cloud.tenable.com'); assert.equal(r.json.keys_set, true); assert.ok(!JSON.stringify(r.json).includes('SKSYNTHETIC'));
  r = await call('POST', '/vapt-studio/tenable/test', undefined, ADM); assert.equal(r.json.ok, true); assert.equal(r.json.count, 3);
  r = await call('POST', '/vapt-studio/tenable/pull', undefined, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.import.added, 2, 'informational (severity 0) plugins are left out; a malformed asset id is skipped');
  assert.ok(calls.every((c) => c.o.method === 'GET' && c.o.headers['X-ApiKeys'] === 'accessKey=AKSYNTHETIC0001;secretKey=SKSYNTHETIC0001'));
  assert.ok(!calls.some((c) => /bad id/.test(c.url)), 'an asset id outside the expected shape is never put in a URL');
  const scanned = e.app.store.collection('vapt_scanned').all();
  assert.equal(scanned.length, 2, 'every examined host is recorded for Coverage & Query (the malformed one is not)');
  assert.ok(scanned.some((x) => x.ips.includes('10.20.0.5') && x.names.includes('ssh01.syn.local') && x.tool === 'Tenable Vulnerability Management'));
  const v = (await call('GET', '/vapt-studio', undefined, OP)).json;
  assert.equal(v.summary.by_vendor.tenable, 2); assert.equal(v.tenable.verified, true); assert.equal(v.tenable.assets, 3);
  const web = v.findings.find((f) => /Apache/.test(f.title)); assert.equal(web.vendor, 'tenable'); assert.equal(web.severity, 'critical'); assert.equal(web.exposure, 'external'); assert.match(web.id, /^tn:/);
  assert.equal(v.findings.find((f) => /OpenSSH/.test(f.title)).overlap, 'likely', 'merged with the Greenbone finding on the same host');
  r = await call('GET', '/vapt-studio/findings/' + web.id, undefined, OP); assert.equal(r.status, 200);
  refuse = true;
  r = await call('POST', '/vapt-studio/tenable/pull', undefined, ADM); assert.equal(r.status, 424); assert.match(r.json.error, /refused the keys/);
  assert.ok(!JSON.stringify(e.app.store.auditTail(300)).includes('SKSYNTHETIC'), 'keys never in the audit');
  assert.equal(e.app.store.auditTail(300).filter((x) => x.action === 'vapt.tenable.config')[0].detail.keys_changed, true);
  assert.equal(e.app.store.auditTail(300).filter((x) => x.action === 'vapt.tenable.pull').length, 2);
});

test('Tenable Nessus scanner: certificate Trust & pin, latest completed scan, nothing pulled before the pin', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const FP = 'ab'.repeat(32); let pinned = null;
  const request = async (url, o) => {
    if (!o.pin) throw Object.assign(new Error('TLS certificate not trusted'), { code: 'tls', presented: { fingerprint256: FP.match(/../g).join(':').toUpperCase() } });
    pinned = o.pin;
    if (/\/scans$/.test(url)) return { status: 200, json: { scans: [{ id: 5, name: 'Old (synthetic)', status: 'completed', last_modification_date: 100 }, { id: 7, name: 'Weekly (synthetic)', status: 'completed', last_modification_date: 200 }, { id: 9, name: 'Running', status: 'running', last_modification_date: 300 }] } };
    if (/\/scans\/7$/.test(url)) return { status: 200, json: { hosts: [{ host_id: 2, hostname: '10.20.0.9' }] } };
    if (/\/scans\/7\/hosts\/2$/.test(url)) return { status: 200, json: { info: { 'host-ip': '10.20.0.9', 'host-fqdn': 'db09.syn.local' }, vulnerabilities: [{ plugin_id: 51192, plugin_name: 'SSL Certificate Cannot Be Trusted', severity: 2 }] } };
    return { status: 404, json: {} };
  };
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3', fcRequest: request, fcSealer: fakeSealer() });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  let r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'nessus', access_key: 'AKSYNTHETIC0001', secret_key: 'SKSYNTHETIC0001' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /base_url is required/);
  r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'nessus', base_url: 'https://127.0.0.1:8834', access_key: 'AKSYNTHETIC0001', secret_key: 'SKSYNTHETIC0001' }, ADM); assert.equal(r.status, 400);
  r = await call('PUT', '/vapt-studio/tenable/config', { kind: 'nessus', base_url: 'https://10.20.0.50:8834', access_key: 'AKSYNTHETIC0001', secret_key: 'SKSYNTHETIC0001' }, ADM); assert.equal(r.status, 200, 'a scanner in the LAN is allowed');
  r = await call('POST', '/vapt-studio/tenable/pull', undefined, ADM); assert.equal(r.status, 409); assert.match(r.json.error, /Trust & pin/);
  r = await call('POST', '/vapt-studio/tenable/test', undefined, ADM); assert.equal(r.json.ok, false); assert.equal(r.json.seen_fingerprint, FP); assert.match(r.json.error, /not trusted/);
  r = await call('POST', '/vapt-studio/tenable/pin', { fingerprint: 'cd'.repeat(32) }, ADM); assert.equal(r.status, 409, 'only the certificate the test saw');
  r = await call('POST', '/vapt-studio/tenable/pin', { fingerprint: FP }, OP); assert.equal(r.status, 403);
  r = await call('POST', '/vapt-studio/tenable/pin', { fingerprint: FP }, ADM); assert.equal(r.status, 200); assert.equal(r.json.pinned, true);
  r = await call('POST', '/vapt-studio/tenable/pull', undefined, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.import.added, 1); assert.equal(pinned, FP);
  const v = (await call('GET', '/vapt-studio', undefined, OP)).json;
  const f = v.findings.find((x) => x.vendor === 'tenable'); assert.equal(f.asset, 'db09.syn.local'); assert.equal(f.host, '10.20.0.9'); assert.equal(f.exposure, 'internal');
  assert.equal(e.app.store.auditTail(100).filter((x) => x.action === 'vapt.tenable.pin').length, 1);
  r = await call('DELETE', '/vapt-studio/tenable/config', undefined, ADM); assert.equal(r.status, 200);
  assert.equal((await call('GET', '/vapt-studio', undefined, OP)).json.tenable.configured, false);
});
