// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Shadow AI DLP (engine/soc/shadow-ai.js, engine/soc/shadow-ai-routes.js) through the REAL API server with SYNTHETIC data and a
// ClickHouse stub answering by query tag: AI apps found by host / App-ID; not connected says what to send; viewers get counts,
// operators names (PDPL) and every view is audited; uploads above the threshold and policy gaps; the register changes only by
// request + four-eyes approval by a different PERSON (requester, operator and service identity refused); validation errors
// name the field; block list export; DLP signals to AI apps; SOC cases (manual, deduplicated, automatic); settings admin-only;
// the extension ingest: token (shown once, SHA-256 at rest), policy, metadata-only events (unknown field dropped, unknown kind
// refused), failed-attempt limit. The browser extension's classifier and app list are kept identical to the engine's.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-sai-')), keyf = path.join(dir, 'secrets.key');
fs.writeFileSync(keyf, crypto.randomBytes(32).toString('hex'), { mode: 0o440 });
process.env.SENTRA_SIEM_SECRETS_KEY = keyf;
const SF = require('../engine/secretfile'); SF._reset();
const { createApi } = require('../engine/api/server');
const { createState } = require('../engine/soc/state');
const S = require('../engine/soc/shadow-ai');
const R = require('../engine/soc/shadow-ai-routes');
const PII = require('../engine/pii/classify');
const EXT = path.join(__dirname, '..', 'agents', 'browser-ai-dlp');
const X = require(path.join(EXT, 'classify.js'));

const SECRET = 'Q'.repeat(32), NOW = Date.UTC(2026, 10, 14, 9, 0);
function req(port, method, p, { body, headers } = {}) {
  return new Promise((ok, no) => {
    const data = body === undefined ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: Object.assign({ 'Content-Type': 'application/json' }, data ? { 'Content-Length': data.length } : {}, headers || {}) }, (res) => {
      let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => { let j = null; try { j = JSON.parse(b); } catch (e) { j = null; /* a text download */ } ok({ status: res.statusCode, json: j, text: b, headers: res.headers }); });
    });
    r.on('error', no); if (data) r.write(data); r.end();
  });
}
const as = (role, user) => ({ 'X-Sentra-Proxy-Secret': SECRET, 'X-Auth-User': user || 'syn.' + role, 'X-Auth-Role': role });
const MB = 1024 * 1024;
const A = {
  sa_any: [{ c: 'web', n: 90000 }, { c: 'network', n: 40000 }],
  sa_src: [{ s: 'fortigate', c: 'web', n: 5000, last: '2026-11-14 08:59:00' }],
  sa_hosts: [
    { host: 'chatgpt.com', app: '', n: 4000, blk: 0, u: 60, out: 80 * MB, first: '2026-11-08 07:00:00', last: '2026-11-14 08:58:00' },
    { host: 'files.oaiusercontent.com', app: '', n: 300, blk: 0, u: 12, out: 40 * MB, first: '2026-11-09 07:00:00', last: '2026-11-14 08:00:00' },
    { host: 'chat.deepseek.com', app: '', n: 120, blk: 20, u: 4, out: 2 * MB, first: '2026-11-12 10:00:00', last: '2026-11-14 07:00:00' },
    { host: '', app: 'Claude.AI', n: 500, blk: 0, u: 9, out: 0, first: '2026-11-07 10:00:00', last: '2026-11-14 06:00:00' },
    { host: 'news.example.com', app: '', n: 9, blk: 0, u: 1, out: 0, first: '2026-11-10 10:00:00', last: '2026-11-10 11:00:00' },
  ],
  sa_days: [{ d: '2026-11-13', host: 'chatgpt.com', app: '', n: 600 }, { d: '2026-11-14', host: 'chatgpt.com', app: '', n: 700 }, { d: '2026-11-14', host: 'chat.deepseek.com', app: '', n: 50 }],
  sa_users: [
    { who: 'nora.syn', host: 'chatgpt.com', app: '', n: 300, blk: 0, out: 45 * MB, last: '2026-11-14 08:58:00' },
    { who: 'nora.syn', host: 'files.oaiusercontent.com', app: '', n: 20, blk: 0, out: 30 * MB, last: '2026-11-14 08:00:00' },
    { who: 'omar.syn', host: 'chat.deepseek.com', app: '', n: 60, blk: 10, out: 2 * MB, last: '2026-11-14 07:00:00' },
    { who: 'lina.syn', host: '', app: 'claude.ai', n: 100, blk: 0, out: 0, last: '2026-11-14 06:00:00' },
  ],
  sa_first: [{ host: 'chat.deepseek.com', app: '', first: '2026-11-12 10:00:00' }],
  sa_dlp: [
    { ts: '2026-11-14 08:30:00', id: 'INC-SYN-1', who: 'nora.syn', host: 'syn-pc-01', ai: '', dest: 'chatgpt.com', urlhost: '', chan: 'web', act: 'permitted', cls: 'National ID, IBAN', pol: 'PII to web', m: 14, prod: 'Somansa Privacy-i', vendor: 'somansa', zdlp: '' },
    { ts: '2026-11-14 08:10:00', id: 'aidlp-1', who: 'omar.syn', host: '', ai: 'deepseek', dest: 'chat.deepseek.com', urlhost: '', chan: 'ai-paste', act: 'blocked', cls: 'credentials', pol: '', m: 1, prod: 'Zyberon AI DLP (browser)', vendor: 'zyberon', zdlp: '' },
  ],
  sa_ext: [{ v: '1.0.0', u: 40, d: 42, last: '2026-11-14 08:59:00' }],
  sa_ext_act: [{ a: 'blocked', n: 3 }, { a: 'sent_after_warning', n: 2 }],
};

async function boot(answers) {
  const sec = path.join(dir, 'secrets-' + crypto.randomBytes(3).toString('hex') + '.json'); SF.write(sec, { proxy_secret: SECRET });
  const config = { api_prefix: '/api/soc' }; Object.defineProperty(config, 'secrets', { value: SF.read(sec), enumerable: false, writable: true }); Object.defineProperty(config, '_paths', { value: { secrets: sec }, enumerable: false });
  const state = await createState({ dir: fs.mkdtempSync(path.join(dir, 'st-')) });
  const calls = [], audits = [], emitted = [], made = [], warns = [];
  const ch = { query: async (sql, p) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, p }); return (answers[tag] || []).map((r) => Object.assign({}, r)); } };
  const cases = { create: (input, by) => { const c = { id: 'CASE-SYN-' + (made.length + 1), status: 'open', input, by }; made.push(c); return c; }, get: (id) => made.find((c) => c.id === id) };
  const log = { info() {}, warn() {}, error: (m, f) => warns.push(m + ' ' + JSON.stringify(f || {})), every: (k, ms, lvl, msg, f) => warns.push(msg + ' ' + JSON.stringify(f || {})) };
  const api = createApi({ port: 0, audit: (e) => audits.push(e), proxySecret: SECRET, log });
  const X2 = R.register(api, { state, config, log, ch, cases, now: () => NOW, noTimers: true, emitEvent: (ev) => emitted.push(ev) });
  const { port } = await api.start();
  return { port, api, calls, audits, emitted, made, warns, sec, X: X2 };
}

test('catalog: hosts and App-IDs map to AI apps; the regex parameters cover every domain', () => {
  const cat = S.CATALOG;
  assert.equal(S.appForHost('chatgpt.com', cat).id, 'chatgpt'); assert.equal(S.appForHost('files.oaiusercontent.com', cat).id, 'chatgpt');
  assert.equal(S.appForHost('api.openai.com', cat).id, 'openai-api', 'the longest domain wins'); assert.equal(S.appForHost('https://claude.ai:443/new', cat).id, 'claude');
  assert.equal(S.appForHost('notchatgpt.com', cat), null, 'a look-alike is not the app'); assert.equal(S.appForHost('news.example.com', cat), null);
  assert.equal(S.appForName('Claude.AI', cat).id, 'claude'); assert.equal(S.appForName('GitHub-Copilot', cat).id, 'github-copilot'); assert.equal(S.appForName('Microsoft-Copilot', cat).id, 'copilot');
  assert.equal(S.appForName('Salesforce', cat), null);
  const rx = new RegExp(S.hostRegex(cat)); assert.ok(rx.test('chat.deepseek.com') && rx.test('claude.ai') && !rx.test('claude.ai.evil.example'));
});

test('browser extension: classifier rules and app list identical to the engine; prompts classified locally; decisions', () => {
  for (const r of PII.RULES) { const e = X.RULES.find((x) => x.kind === r.kind); assert.ok(e, r.kind + ' in the extension'); assert.equal(e.re.source, r.re.source, r.kind + ' pattern'); assert.equal(e.re.flags, r.re.flags, r.kind + ' flags'); }
  assert.deepEqual(X.KIND_CLASS, S.KIND_CLASS, 'kinds and their classes');
  assert.deepEqual(X.APPS.map((a) => [a[0], a[2]]), S.CATALOG.map((a) => [a.id, a.domains]), 'the same AI apps and domains');
  const man = JSON.parse(fs.readFileSync(path.join(EXT, 'manifest.json'), 'utf8')), m = man.content_scripts[0].matches;
  for (const a of S.CATALOG) for (const d of a.domains) assert.ok(m.includes('https://' + d + '/*') && m.includes('https://*.' + d + '/*'), d + ' covered by the content script');
  assert.equal(man.manifest_version, 3); assert.equal(man.storage.managed_schema, 'managed_schema.json');
  // synthetic prompt text
  const f = X.classify('Customer list SYN: 1012345678, 1098765432 and IBAN SA03 8000 0000 6080 1016 7519. key AKIAABCDEFGHIJKLMNOP. Project Falcon SYN', ['falcon syn']);
  assert.deepEqual(f.kinds, { national_id: 2, iban: 1, api_key: 1, keyword: 1 }); assert.deepEqual(f.classes.sort(), ['confidential', 'credentials', 'financial', 'personal']);
  assert.deepEqual(X.classify('card 4111 1111 1111 1111').kinds, { card: 1 }); assert.deepEqual(X.classify('number 4111 1111 1111 1112').kinds, {}, 'a number failing Luhn is no card');
  assert.deepEqual(X.classify('مستند سري للعرض').kinds, { label: 1 }); assert.deepEqual(X.classify('write me a poem about the sea').kinds, {});
  assert.equal(X.describe({ national_id: 2, api_key: 1 }), '2 national ID numbers, 1 API keys');
  const ok = { id: 'copilot', status: 'sanctioned', allowed_classes: ['personal'] }, tol = { id: 'chatgpt', status: 'tolerated', allowed_classes: [] };
  assert.equal(X.decide(ok, X.classify('ids 1012345678'), 'block').action, 'allow', 'a sanctioned app receives its allowed classes');
  assert.equal(X.decide(ok, f, 'warn').action, 'warn'); assert.equal(X.decide(tol, f, 'block').action, 'block');
  assert.equal(X.decide({ status: 'blocked' }, X.classify(''), 'warn').page, true); assert.equal(X.decide(null, f, 'block').action, 'allow', 'not an AI page: nothing to decide');
  assert.equal(X.appFor('www.chatgpt.com').id, 'chatgpt'); assert.equal(X.appFor('chatgpt.com.evil.example'), null);
});

test('discovery: not connected says what to send; viewers counts, operators names; uploads, unsanctioned, new apps; audited', async () => {
  let b = await boot({});
  try {
    const r = await req(b.port, 'GET', '/api/soc/shadow-ai/discovery', { headers: as('viewer') });
    assert.equal(r.status, 200); assert.equal(r.json.configured, false); assert.match(r.json.note, /web-filter/);
    assert.ok(!b.calls.some((c) => c.tag === 'sa_hosts'), 'no further query without logs');
  } finally { await b.api.stop(); }
  b = await boot(A);
  try {
    let r = await req(b.port, 'GET', '/api/soc/shadow-ai/discovery?hours=168', { headers: as('viewer') }), v = r.json;
    assert.equal(v.configured, true); assert.deepEqual(v.apps.map((a) => a.id), ['chatgpt', 'claude', 'deepseek'], 'by people, the unrelated site left out');
    const gpt = v.apps[0]; assert.equal(gpt.requests, 4300); assert.equal(gpt.mb_sent, 120); assert.equal(gpt.status, 'unreviewed'); assert.equal(gpt.unsanctioned, true);
    assert.equal(v.apps.find((a) => a.id === 'claude').requests, 500, 'found by App-ID with no host'); assert.equal(v.apps.find((a) => a.id === 'deepseek').new_in_window, true);
    assert.equal(v.totals.users, 3); assert.equal(v.totals.unsanctioned_users, 3); assert.equal(v.trend.length, 2); assert.equal(v.trend[1].apps.chatgpt, 700);
    assert.equal(v.named, false); assert.equal(v.people.hidden, true); assert.equal(v.uploads.length, 1); assert.equal(v.uploads[0].who, null, 'viewer: no names');
    assert.match(v.note, /indicators, not proof/i);
    const hq = b.calls.find((c) => c.tag === 'sa_hosts'); assert.ok(!/chatgpt|deepseek/.test(hq.sql), 'domains are parameters, not SQL text'); assert.match(hq.p.hrx.value, /chatgpt\\\.com/);
    r = await req(b.port, 'GET', '/api/soc/shadow-ai/discovery', { headers: as('operator') }); v = r.json;
    assert.equal(v.named, true); assert.equal(v.people[0].who, 'nora.syn'); assert.equal(v.uploads[0].who, 'nora.syn'); assert.match(v.uploads[0].why, /75 MB sent to ChatGPT \(unreviewed\)/);
    r = await req(b.port, 'GET', '/api/soc/shadow-ai/discovery?hours=5', { headers: as('viewer') }); assert.equal(r.status, 400); assert.match(r.json.error, /hours must be one of/);
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.discovery.view' && a.detail.named === false) && b.audits.some((a) => a.action === 'shadow_ai.discovery.view' && a.by === 'syn.operator' && a.detail.named === true));
  } finally { await b.api.stop(); }
});

test('register: request by an operator, four-eyes approval by a different person; refusals and validation; block list; policy gap', async () => {
  const b = await boot(A);
  try {
    const P = '/api/soc/shadow-ai/requests';
    for (const role of ['viewer', 'analyst']) assert.equal((await req(b.port, 'POST', P, { headers: as(role), body: { app: 'deepseek', status: 'blocked', reason: 'not approved' } })).status, 403, role + ' cannot request');
    let r = await req(b.port, 'POST', P, { headers: as('operator'), body: { app: 'deepseek', status: 'blocked' } }); assert.equal(r.status, 400); assert.match(r.json.error, /reason is required/);
    r = await req(b.port, 'POST', P, { headers: as('operator'), body: { app: 'deepseek', status: 'unreviewed', reason: 'reset it' } }); assert.match(r.json.error, /unreviewed cannot be requested/);
    r = await req(b.port, 'POST', P, { headers: as('operator'), body: { app: 'deepseek', status: 'maybe', reason: 'xxxxx' } }); assert.match(r.json.error, /status must be one of/);
    r = await req(b.port, 'POST', P, { headers: as('operator'), body: { app: 'deepseek', status: 'blocked', allowed_classes: ['personal'], reason: 'data leaves the Kingdom' } }); assert.match(r.json.error, /allowed_classes must be empty for a blocked app/);
    r = await req(b.port, 'POST', P, { headers: as('operator'), body: { app: 'custom:syn-notes', status: 'tolerated', name: 'SYN Notes AI', domains: ['bad domain'], reason: 'pilot' } }); assert.match(r.json.error, /domains must be host names/);
    r = await req(b.port, 'POST', P, { headers: as('operator'), body: { app: 'chatgpt', status: 'tolerated', domains: ['x.example.com'], reason: 'pilot' } }); assert.match(r.json.error, /only for a custom app/);
    r = await req(b.port, 'POST', P, { headers: as('operator', 'sami.syn'), body: { app: 'deepseek', status: 'blocked', owner: 'CISO SYN', reason: 'data leaves the Kingdom', approved_by: 'mallory' } });
    assert.equal(r.status, 200, JSON.stringify(r.json)); const id = r.json.id; assert.equal(r.json.status, 'pending'); assert.equal(r.json.approved_by, undefined, 'an undeclared field is dropped');
    r = await req(b.port, 'POST', P, { headers: as('operator'), body: { app: 'deepseek', status: 'tolerated', reason: 'second request' } }); assert.equal(r.status, 409);
    const D = P + '/' + id + '/decide';
    assert.equal((await req(b.port, 'POST', D, { headers: as('operator', 'oper.syn'), body: { decision: 'approve' } })).status, 403, 'an operator who is not an approver');
    assert.equal((await req(b.port, 'POST', D, { headers: as('admin', 'system:automation'), body: { decision: 'approve' } })).status, 403, 'a service identity never approves');
    r = await req(b.port, 'POST', D, { headers: as('admin', 'syn.admin'), body: { decision: 'maybe' } }); assert.equal(r.status, 400); assert.match(r.json.error, /decision must be one of/);
    assert.equal((await req(b.port, 'GET', '/api/soc/shadow-ai/register', { headers: as('viewer') })).json.items.find((a) => a.id === 'deepseek').status, 'unreviewed', 'nothing changes before approval');
    // the requester, even as an administrator, never approves
    const own = await req(b.port, 'POST', P, { headers: as('admin', 'ali.syn'), body: { app: 'claude', status: 'sanctioned', allowed_classes: ['personal'], reason: 'enterprise plan, data in region' } });
    r = await req(b.port, 'POST', P + '/' + own.json.id + '/decide', { headers: as('admin', 'ali.syn'), body: { decision: 'approve' } }); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
    r = await req(b.port, 'POST', D, { headers: as('admin', 'ali.syn'), body: { decision: 'approve', comment: 'agreed' } }); assert.equal(r.status, 200); assert.equal(r.json.status, 'approved');
    assert.equal((await req(b.port, 'POST', D, { headers: as('admin', 'ali.syn'), body: { decision: 'reject' } })).status, 409, 'decided once');
    const reg = (await req(b.port, 'GET', '/api/soc/shadow-ai/register', { headers: as('viewer') })).json.items.find((a) => a.id === 'deepseek');
    assert.equal(reg.status, 'blocked'); assert.equal(reg.owner, 'CISO SYN'); assert.equal(reg.approved_by, 'ali.syn');
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.request' && a.by === 'sami.syn' && a.detail.change.status === 'blocked'));
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.request.approve' && a.by === 'ali.syn' && a.detail.requested_by === 'sami.syn'));
    // block list: operator, audited, text for the firewall
    assert.equal((await req(b.port, 'GET', '/api/soc/shadow-ai/blocklist', { headers: as('viewer') })).status, 403);
    r = await req(b.port, 'GET', '/api/soc/shadow-ai/blocklist?format=txt', { headers: as('operator') });
    assert.equal(r.status, 200); assert.match(r.headers['content-disposition'], /blocked-ai-apps\.txt/); assert.deepEqual(r.text.split('\n').filter((l) => l && !l.startsWith('#')), ['deepseek.com']);
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.blocklist.export' && a.detail.domains === 1));
    // blocked in the register, still allowed by the firewall: a gap
    const v = (await req(b.port, 'GET', '/api/soc/shadow-ai/discovery', { headers: as('viewer') })).json;
    assert.equal(v.apps.find((a) => a.id === 'deepseek').gap, true); assert.equal(v.totals.gaps, 1);
    // a custom app joins the catalog once approved
    r = await req(b.port, 'POST', P, { headers: as('operator', 'sami.syn'), body: { app: 'custom:syn-notes', status: 'tolerated', name: 'SYN Notes AI', category: 'writing', domains: ['Notes.Syn-AI.example'], reason: 'pilot in finance' } });
    await req(b.port, 'POST', P + '/' + r.json.id + '/decide', { headers: as('admin', 'ali.syn'), body: { decision: 'approve' } });
    assert.ok(b.X.catalog().some((a) => a.id === 'custom:syn-notes' && a.domains[0] === 'notes.syn-ai.example'));
  } finally { await b.api.stop(); }
});

test('signals: DLP incidents to AI apps with their data classes; names for operators; cases manual, deduplicated and automatic', async () => {
  const b = await boot(A);
  try {
    let v = (await req(b.port, 'GET', '/api/soc/shadow-ai/signals', { headers: as('viewer') })).json;
    assert.equal(v.totals.incidents, 2); assert.equal(v.totals.left, 1); assert.equal(v.totals.sensitive_left, 1); assert.equal(v.by_source.extension, 1);
    const i0 = v.incidents[0]; assert.equal(i0.app, 'chatgpt'); assert.deepEqual(i0.classes, ['personal', 'financial']); assert.equal(i0.left, true); assert.equal(i0.who, null);
    v = (await req(b.port, 'GET', '/api/soc/shadow-ai/signals', { headers: as('operator') })).json; assert.equal(v.incidents[0].who, 'nora.syn'); assert.equal(v.incidents[1].source, 'extension');
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.signals.view'));
    const C = '/api/soc/shadow-ai/cases';
    assert.equal((await req(b.port, 'POST', C, { headers: as('analyst'), body: { kind: 'upload', app: 'chatgpt' } })).status, 403);
    let r = await req(b.port, 'POST', C, { headers: as('operator'), body: { kind: 'leak', app: 'chatgpt' } }); assert.equal(r.status, 400); assert.match(r.json.error, /kind must be one of/);
    r = await req(b.port, 'POST', C, { headers: as('operator'), body: { kind: 'upload', app: 'no-such-app' } }); assert.equal(r.status, 400); assert.match(r.json.error, /app must be an app from the catalog/);
    r = await req(b.port, 'POST', C, { headers: as('operator'), body: { kind: 'upload', app: 'chatgpt', who: 'nora.syn', detail: '75 MB in 7 days' } });
    assert.equal(r.status, 200); assert.equal(r.json.existed, false); const c = b.made[0];
    assert.match(c.input.title, /Shadow AI: ChatGPT - large upload/); assert.match(c.input.description, /Indicators, not proof/); assert.equal(c.by, 'syn.operator');
    r = await req(b.port, 'POST', C, { headers: as('operator'), body: { kind: 'upload', app: 'chatgpt', who: 'nora.syn' } }); assert.equal(r.json.existed, true); assert.equal(b.made.length, 1, 'one case per kind / app / person / day');
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.case' && a.target === 'CASE-SYN-1'));
    const auto = await b.X.autoCases(); assert.equal(auto.opened, 1, 'data the DLP product let go to an AI app with a sensitive class');
    assert.equal(b.made[1].by, 'system:shadow-ai'); assert.match(b.made[1].input.title, /sensitive data sent to an AI app \(nora\.syn\)/);
    assert.equal((await b.X.autoCases()).opened, 0, 'not twice');
  } finally { await b.api.stop(); }
});

test('settings: read by analysts, changed by administrators only, validated, audited', async () => {
  const b = await boot(A);
  try {
    const P = '/api/soc/shadow-ai/settings';
    assert.equal((await req(b.port, 'GET', P, { headers: as('viewer') })).status, 403);
    assert.equal((await req(b.port, 'GET', P, { headers: as('analyst') })).json.extension.mode, 'warn');
    assert.equal((await req(b.port, 'POST', P, { headers: as('operator'), body: { mode: 'block' } })).status, 403);
    let r = await req(b.port, 'POST', P, { headers: as('admin'), body: { upload_mb: 0 } }); assert.equal(r.status, 400); assert.match(r.json.error, /upload_mb must be at least 1/);
    r = await req(b.port, 'POST', P, { headers: as('admin'), body: { keywords: ['ok word', 'x'] } }); assert.match(r.json.error, /at least 3 characters/);
    r = await req(b.port, 'POST', P, { headers: as('admin'), body: { mode: 'block', upload_mb: 25, keywords: ['Project Falcon SYN'], auto_gaps: false } });
    assert.equal(r.status, 200); assert.deepEqual(r.json.changed.sort(), ['auto_cases.gaps', 'extension.keywords', 'extension.mode', 'upload_mb']);
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.settings' && a.detail.keywords === 1 && !JSON.stringify(a.detail).includes('Falcon')), 'the keywords themselves are not in the audit');
  } finally { await b.api.stop(); }
});

test('extension ingest: token shown once and sealed, policy, metadata-only events, refusals, failed-attempt limit', async () => {
  const b = await boot(A);
  try {
    assert.equal((await req(b.port, 'POST', '/api/soc/shadow-ai/extension/token', { headers: as('operator') })).status, 403, 'credentials are admin-only');
    assert.equal((await req(b.port, 'GET', '/ingest/ai-dlp/policy')).status, 401, 'no token yet: refused');
    const t = await req(b.port, 'POST', '/api/soc/shadow-ai/extension/token', { headers: as('admin') }); assert.equal(t.status, 200); const token = t.json.token;
    const disk = SF.read(b.sec); assert.match(disk.shadow_ai.ext_token, /^sha256:[0-9a-f]{64}$/); assert.ok(!fs.readFileSync(b.sec, 'utf8').includes(token), 'only the SHA-256 is stored (sealed)');
    assert.ok(b.audits.some((a) => a.action === 'shadow_ai.extension.token') && !JSON.stringify(b.audits).includes(token), 'audited, without the token');
    const H = { 'X-Sentra-Token': token };
    const pol = await req(b.port, 'GET', '/ingest/ai-dlp/policy', { headers: H }); assert.equal(pol.status, 200);
    assert.ok(pol.json.apps.some((a) => a.id === 'chatgpt' && a.status === 'unreviewed')); assert.equal(pol.json.mode, 'warn'); assert.match(pol.json.version, /^[0-9a-f]{16}$/);
    const E = '/ingest/ai-dlp/events';
    let r = await req(b.port, 'POST', E, { headers: H, body: { events: [
      { ts: NOW - 1000, app: 'chatgpt', host: 'chatgpt.com', action: 'sent_after_warning', channel: 'paste', kinds: { national_id: 3 }, classes: ['personal'], user: 'nora.syn@example.com', ext_version: '1.0.0', prompt: 'SECRET TEXT SYN' },
      { action: 'heartbeat', ext_version: '1.0.0', user: 'nora.syn@example.com' },
    ] } });
    assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.accepted, 2); assert.equal(r.json.heartbeats, 1);
    const ev = b.emitted[0];
    assert.equal(ev.action, 'dlp-incident'); assert.equal(ev.fields.ai_app, 'chatgpt'); assert.equal(ev.fields.dlp_action, 'permitted'); assert.equal(ev.fields.dlp_vendor, 'zyberon');
    assert.match(ev.fields.dlp_classification, /national id/); assert.equal(ev.fields.dlp_match_count, '3'); assert.equal(ev.user, 'nora.syn@example.com');
    assert.ok(!JSON.stringify(b.emitted).includes('SECRET TEXT SYN'), 'a text field sent by a client is dropped, never stored');
    assert.equal(b.emitted[1].action, 'ai-dlp-heartbeat');
    r = await req(b.port, 'POST', E, { headers: H, body: { events: [{ action: 'blocked', host: 'chatgpt.com', kinds: { prompt_text: 1 } }] } }); assert.equal(r.status, 400); assert.match(r.json.error, /events\[0\]\.kinds\.prompt_text is not a known kind/);
    r = await req(b.port, 'POST', E, { headers: H, body: { events: [{ action: 'blocked' }] } }); assert.match(r.json.error, /events\[0\]\.host is required/);
    r = await req(b.port, 'POST', E, { headers: H, body: { events: [{ action: 'exfiltrate', host: 'chatgpt.com' }] } }); assert.match(r.json.error, /events\[0\]\.action must be one of/);
    r = await req(b.port, 'POST', E, { headers: H, body: { events: [{ action: 'blocked', host: 'chatgpt.com', user: '<script>' }] } }); assert.match(r.json.error, /user must be an account name/);
    r = await req(b.port, 'POST', E, { headers: H, body: { events: new Array(201).fill({ action: 'heartbeat' }) } }); assert.equal(r.status, 413);
    const st = (await req(b.port, 'GET', '/api/soc/shadow-ai/extension', { headers: as('operator') })).json; assert.equal(st.token_set, true); assert.equal(st.users_24h, 40); assert.equal(st.actions_7d.blocked, 3);
    assert.equal((await req(b.port, 'GET', '/api/soc/shadow-ai/extension', { headers: as('analyst') })).status, 403);
    let last = 0; for (let i = 0; i < 32; i++) last = (await req(b.port, 'GET', '/ingest/ai-dlp/policy', { headers: { 'X-Sentra-Token': 'wrong-' + i } })).status;
    assert.equal(last, 429, 'guessing the token is limited'); assert.ok(b.warns.some((w) => /rejected token/.test(w) && !w.includes('wrong-')), 'logged without the token');
  } finally { await b.api.stop(); }
});
