// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Dark Web Watch (engine/soc/darkweb.js): Have I Been Pwned domain search (+ the breach catalogue and stealer logs, a refused key
// and an unverified domain named), provider imports in JSON and CSV - only the company's domains kept, PASSWORDS NEVER STORED
// (dropped and counted), the same finding merged, not duplicated; the directory match (privileged, disabled, password changed
// since the leak) and an itemised risk; one alert for a serious new exposure; the lifecycle (one step at a time, reset VERIFIED
// from the directory or ATTESTED with a note, a note to close); the HIBP key write-only in the sealed secrets file; roles (viewer
// counts only, analyst names, operator actions, admin settings), validation errors naming the field, and the audit records.
// SYNTHETIC accounts and breaches only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { createState } = require('../engine/soc/state');
const { createAlerts } = require('../engine/soc/alerts');
const DW = require('../engine/soc/darkweb');
const { fakeApi, tmpDir, quietLog } = require('./soc-fakes');

const DAY = 86400000, T = Date.parse('2026-11-15T08:00:00Z');
const KEY = 'abcdef0123456789abcdef0123456789';
function world(o = {}) {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), alerts = createAlerts({ state, log: quietLog }), calls = [];
  const users = { 'omar.syn': { sam: 'omar.syn', privileged: true, disabled: false, pwd_last_set: T - 650 * DAY, last_logon: T - DAY },
    'sara.syn': { sam: 'sara.syn', privileged: false, disabled: false, pwd_last_set: T - 5 * DAY, last_logon: T - DAY },
    'old.syn': { sam: 'old.syn', privileged: false, disabled: true, pwd_last_set: T - 900 * DAY } };
  const identity = { lookup: (n) => users[String(n).toLowerCase().split('@')[0]] || null };
  const R = (status, j) => ({ status, ok: status < 300, json: async () => j });
  const fetchImpl = async (url, opt) => {
    calls.push({ url, key: opt.headers['hibp-api-key'] || null });
    if (url.endsWith('/breaches')) return R(200, [{ Name: 'SynCorp', Title: 'SynCorp (synthetic)', BreachDate: '2025-06-01', AddedDate: '2025-07-01T00:00:00Z', DataClasses: ['Email addresses', 'Passwords'] }, { Name: 'OldForum', Title: 'Old forum (synthetic)', BreachDate: '2019-01-01', DataClasses: ['Email addresses'] }]);
    if (opt.headers['hibp-api-key'] !== KEY) return R(401, {});
    if (url.includes('/breacheddomain/zs-syn.test')) return R(200, { 'omar.syn': ['SynCorp'], 'sara.syn': ['SynCorp', 'OldForum'], 'old.syn': ['OldForum'] });
    if (url.includes('/breacheddomain/')) return R(403, {});
    if (url.includes('/stealerlogsbyemaildomain/zs-syn.test')) return o.stealer ? R(200, { 'omar.syn': ['portal.example'] }) : R(403, {});
    return R(404, {});
  };
  const secrets = path.join(dir, 'secrets.json');
  const deps = { state, alerts, identity, config: { _paths: { secrets } }, log: quietLog, now: () => T, fetch: fetchImpl, noTimers: true };
  const api = fakeApi({ realRanks: true }); DW.register(api, deps);
  return { api, alerts, calls, secrets, call: (m, p, x) => api.call(m, '/api/soc' + p, x), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('settings: admin only, validated, the HIBP key write-only in the sealed secrets file, audited without the key', async () => {
  const w = world(); try {
    assert.equal((await w.call('POST', '/soc/darkweb/settings', { role: 'operator', body: { domains: ['zs-syn.test'] } })).status, 403);
    let r = await w.call('POST', '/soc/darkweb/settings', { role: 'admin', body: { domains: ['not a domain'] } }); assert.equal(r.status, 400); assert.match(r.body.error, /domains\[0\] is not a domain/);
    r = await w.call('POST', '/soc/darkweb/settings', { role: 'admin', body: { hibp_key: 'short' } }); assert.equal(r.status, 400); assert.match(r.body.error, /hibp_key/);
    r = await w.call('POST', '/soc/darkweb/settings', { role: 'admin', body: { poll_h: 1 } }); assert.equal(r.status, 400); assert.match(r.body.error, /poll_h/);
    r = await w.call('POST', '/soc/darkweb/settings', { role: 'admin', user: 'syed', body: { domains: ['ZS-SYN.test', 'zs-syn.test'], hibp_key: KEY, poll_h: 24 } });
    assert.equal(r.status, 200); assert.deepEqual(r.body.domains, ['zs-syn.test']); assert.equal(r.body.key_set, true); assert.ok(!JSON.stringify(r.body).includes(KEY), 'the key is never returned');
    assert.equal(require('../engine/secretfile').read(w.secrets).darkweb.hibp_key, KEY, 'kept in the secrets file (sealed when a sealing key exists)');
    const v = (await w.call('GET', '/soc/darkweb', { role: 'viewer' })).body; assert.equal(v.settings.key_set, true); assert.ok(!JSON.stringify(v).includes(KEY));
    const a = w.api.audits.find((x) => x.action === 'soc.darkweb.settings'); assert.ok(a && a.user === 'syed' && !JSON.stringify(a).includes(KEY), 'audited without the key');
  } finally { w.cleanup(); }
});

test('HIBP sync: exposures matched to the directory, itemised risk, one alert for a serious one, errors named, merged on re-sync', async () => {
  const w = world({ stealer: true }); try {
    let r = await w.call('POST', '/soc/darkweb/sync', { role: 'operator', body: {} }); assert.equal(r.status, 409); assert.match(r.body.error, /no Have I Been Pwned API key/);
    await w.call('POST', '/soc/darkweb/settings', { role: 'admin', body: { domains: ['zs-syn.test', 'other-syn.test'], hibp_key: KEY } });
    assert.equal((await w.call('POST', '/soc/darkweb/sync', { role: 'analyst', body: {} })).status, 403);
    r = await w.call('POST', '/soc/darkweb/sync', { role: 'operator', user: 'nora.syn', body: {} }); assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.created, 5); assert.equal(r.body.stealer, 'read'); assert.ok(r.body.errors.some((e) => /other-syn\.test: the domain is not verified/.test(e)));
    assert.ok(w.calls.filter((c) => c.url.endsWith('/breaches')).every((c) => c.key === null), 'the public catalogue is read without the key');
    const L = (await w.call('GET', '/soc/darkweb/exposures', { role: 'analyst', user: 'ana.syn' })).body.items;
    const omar = L.find((x) => x.account === 'omar.syn@zs-syn.test' && x.kind === 'breach'), st = L.find((x) => x.kind === 'stealer');
    assert.equal(L[0].id, st.id, 'the stealer log on a privileged account ranks first');
    assert.equal(omar.directory.privileged, true); assert.equal(omar.directory.changed_since_leak, false);
    for (const re of [/data breach/, /included a password/, /privileged account/, /not changed since the leak/]) assert.ok(omar.risk_why.some((p) => re.test(p.why)), String(re));
    assert.equal(omar.risk, Math.max(0, Math.min(100, omar.risk_why.reduce((s, p) => s + p.points, 0))), 'every point itemised');
    const sara = L.find((x) => x.account === 'sara.syn@zs-syn.test' && /SynCorp/.test(x.source)); assert.equal(sara.directory.changed_since_leak, true, 'her password changed after the leak');
    const old = L.find((x) => x.account === 'old.syn@zs-syn.test'); assert.ok(old.risk_why.some((p) => /disabled/.test(p.why) && p.points < 0)); assert.equal(old.level, 'low');
    const al = w.alerts.all((a) => a.rule_id === 'dw-exposure'); assert.ok(al.length >= 1 && al.some((a) => a.severity === 4), 'a serious new exposure raises an alert');
    assert.ok(!al.some((a) => /old\.syn/.test(a.summary)), 'a low-risk exposure does not');
    r = await w.call('POST', '/soc/darkweb/sync', { role: 'operator', body: {} }); assert.equal(r.body.created, 0, 'a re-sync merges, it does not duplicate');
    assert.ok(w.api.audits.some((a) => a.action === 'soc.darkweb.read' && a.user === 'ana.syn') && w.api.audits.some((a) => a.action === 'soc.darkweb.sync' && a.user === 'nora.syn'));
    // viewer: counts, no names
    const v = (await w.call('GET', '/soc/darkweb', { role: 'viewer' })).body; assert.equal(v.summary.open, 5); assert.ok(!JSON.stringify(v).includes('omar.syn'));
    assert.equal((await w.call('GET', '/soc/darkweb/exposures', { role: 'viewer' })).status, 403, 'names are personal data');
    // a refused key is named
    await w.call('POST', '/soc/darkweb/settings', { role: 'admin', body: { hibp_key: 'ffffffffffffffffffffffffffffffff' } });
    r = await w.call('POST', '/soc/darkweb/sync', { role: 'operator', body: {} }); assert.ok(r.body.errors.some((e) => /the API key was refused/.test(e)));
  } finally { w.cleanup(); }
});

test('provider import: own domains only, passwords dropped and never stored, CSV and JSON, validated', async () => {
  const w = world(); try {
    let r = await w.call('POST', '/soc/darkweb/import', { role: 'operator', body: { provider: 'SynIntel', format: 'json', content: '[]' } }); assert.equal(r.status, 409, 'domains first');
    await w.call('POST', '/soc/darkweb/settings', { role: 'admin', body: { domains: ['zs-syn.test'] } });
    const json = JSON.stringify([{ email: 'Sara.Syn@zs-syn.test', source: 'Infostealer market (synthetic)', type: 'infostealer', password: 'Hunter2-synthetic', cookie: 'sess=abc', date: '2026-11-01' },
      { email: 'someone@gmail.example', source: 'x', password: 'p' }, { email: 'not-an-email' }, { email: 'omar.syn@zs-syn.test', source: 'Forum post (synthetic)', kind: 'mention' }]);
    r = await w.call('POST', '/soc/darkweb/import', { role: 'operator', user: 'nora.syn', body: { provider: 'SynIntel', format: 'json', content: json, extra: 1 } });
    assert.equal(r.status, 200); assert.deepEqual([r.body.kept, r.body.created, r.body.other_domain, r.body.invalid, r.body.passwords_dropped], [2, 2, 1, 1, 3]);
    const store = fs.readdirSync(w.secrets.replace(/secrets\.json$/, '')).map((f) => { try { return fs.statSync(path.join(path.dirname(w.secrets), f)).isFile() ? fs.readFileSync(path.join(path.dirname(w.secrets), f), 'utf8') : ''; } catch (e) { return ''; } }).join('\n');
    assert.ok(!/Hunter2-synthetic|sess=abc/.test(store) && !/Hunter2-synthetic/.test(JSON.stringify((await w.call('GET', '/soc/darkweb/exposures', { role: 'analyst' })).body)), 'the password and cookie are never stored');
    const L = (await w.call('GET', '/soc/darkweb/exposures', { role: 'analyst' })).body.items;
    const s = L.find((x) => x.account === 'sara.syn@zs-syn.test'); assert.equal(s.kind, 'stealer'); assert.equal(s.includes_password, true); assert.equal(s.provider, 'import:SynIntel');
    assert.equal(L.find((x) => x.account === 'omar.syn@zs-syn.test').kind, 'mention');
    const csv = 'email,source,type,password\n"sara.syn@zs-syn.test","Infostealer market (synthetic)",infostealer,xyz\nnew.syn@zs-syn.test,"Paste, site (synthetic)",paste,\n';
    r = await w.call('POST', '/soc/darkweb/import', { role: 'operator', body: { provider: 'SynIntel', format: 'csv', content: csv } });
    assert.deepEqual([r.body.kept, r.body.created, r.body.passwords_dropped], [2, 1, 1], 'the same finding merges; quoted commas parse');
    const n = (await w.call('GET', '/soc/darkweb/exposures', { role: 'analyst' })).body.items.find((x) => x.account === 'new.syn@zs-syn.test'); assert.equal(n.source, 'Paste, site (synthetic)'); assert.equal(n.directory.matched, false);
    r = await w.call('POST', '/soc/darkweb/import', { role: 'operator', body: { provider: 'SynIntel', format: 'json', content: '{bad' } }); assert.equal(r.status, 400); assert.match(r.body.error, /not valid JSON/);
    r = await w.call('POST', '/soc/darkweb/import', { role: 'operator', body: { provider: 'SynIntel', format: 'xml', content: 'x' } }); assert.equal(r.status, 400); assert.match(r.body.error, /format must be one of/);
    assert.equal((await w.call('POST', '/soc/darkweb/import', { role: 'analyst', body: { provider: 'x', format: 'json', content: '[]' } })).status, 403);
    assert.ok(w.api.audits.some((a) => a.action === 'soc.darkweb.import' && a.detail.passwords_dropped === 3));
    assert.deepEqual(DW.csvRows('a,b\n"x,1","y""z"\n'), [{ a: 'x,1', b: 'y"z' }]);
  } finally { w.cleanup(); }
});

test('lifecycle: one step at a time, reset verified from the directory or attested with a note, a note to close', async () => {
  const w = world(); try {
    await w.call('POST', '/soc/darkweb/settings', { role: 'admin', body: { domains: ['zs-syn.test'], hibp_key: KEY } });
    await w.call('POST', '/soc/darkweb/sync', { role: 'operator', body: {} });
    const L = (await w.call('GET', '/soc/darkweb/exposures', { role: 'analyst' })).body.items;
    const omar = L.find((x) => x.account.startsWith('omar.syn')), sara = L.find((x) => x.account.startsWith('sara.syn') && /SynCorp/.test(x.source));
    let r = await w.call('POST', '/soc/darkweb/exposures/' + omar.id, { role: 'operator', body: { status: 'closed', note: 'done done' } }); assert.equal(r.status, 409); assert.match(r.body.error, /next step/);
    r = await w.call('POST', '/soc/darkweb/exposures/' + omar.id, { role: 'operator', body: { status: 'reset' } }); assert.equal(r.status, 400); assert.match(r.body.error, /no password change since this exposure was found/);
    r = await w.call('POST', '/soc/darkweb/exposures/' + omar.id, { role: 'operator', user: 'nora.syn', body: { status: 'reset', note: 'reset by the service desk, ticket SYN-12' } }); assert.equal(r.status, 200); assert.equal(r.body.reset_evidence, 'attested');
    assert.equal((await w.call('POST', '/soc/darkweb/exposures/' + omar.id, { role: 'operator', body: { status: 'closed' } })).status, 400, 'a note to close');
    assert.equal((await w.call('POST', '/soc/darkweb/exposures/' + omar.id, { role: 'operator', body: { status: 'closed', note: 'user confirmed' } })).body.status, 'closed');
    // sara's password changed 5 days ago, but the exposure was first seen now - not verified either
    r = await w.call('POST', '/soc/darkweb/exposures/' + sara.id, { role: 'operator', body: { status: 'reset' } }); assert.equal(r.status, 400);
    assert.equal((await w.call('POST', '/soc/darkweb/exposures/' + omar.id, { role: 'analyst', body: { status: 'notified' } })).status, 403);
    assert.equal((await w.call('POST', '/soc/darkweb/exposures/DW-99999', { role: 'operator', body: { status: 'notified' } })).status, 404);
    assert.equal((await w.call('POST', '/soc/darkweb/exposures/' + sara.id, { role: 'operator', body: { status: 'gone' } })).status, 400);
    assert.ok(w.api.audits.some((a) => a.action === 'soc.darkweb.status' && a.detail.evidence === 'attested' && a.user === 'nora.syn'));
  } finally { w.cleanup(); }
});

test('charts: counts only - by month, kind, status, risk band, data exposed, remediation, reset time, an unusual month', () => {
  const state = createState({ dir: tmpDir() }), DAY = 864e5, T = Date.parse('2026-11-20T09:00:00Z'); let t = T - 300 * DAY;
  const users = { 'syn.lina': { sam: 'syn.lina', pwd_last_set: T - 400 * DAY }, 'syn.omar': { sam: 'syn.omar', pwd_last_set: T - 1 * DAY } };
  const D = DW.createDarkweb({ state, identity: { lookup: (n) => users[String(n).toLowerCase().split('@')[0]] || null }, config: {}, log: quietLog, now: () => t, noTimers: true });
  D.setSettings({ domains: ['corp.example'] }, 'syn.admin');
  // one or two a month for most of a year, then a burst in the last month
  for (let m = 10; m >= 1; m--) { t = T - m * 30 * DAY; D.importFindings({ provider: 'SynIntel', format: 'json', content: JSON.stringify([{ account: 'u' + m + '@corp.example', source: 'SynBreach ' + m, kind: 'breach', breach_date: '2024-0' + (1 + (m % 9)) + '-01', data_classes: ['Email addresses', 'Passwords'], password: 'x' }]) }, 'syn.ops'); }
  t = T - 2 * DAY;
  D.importFindings({ provider: 'SynIntel', format: 'json', content: JSON.stringify(Array.from({ length: 9 }, (_, i) => ({ account: (i ? 'v' + i : 'syn.lina') + '@corp.example', source: 'SynStealer', kind: 'stealer', data_classes: ['Cookies'], password: 'x' })).concat([{ account: 'syn.omar@corp.example', source: 'SynBreach', kind: 'breach', breach_date: '2025-06-01', password: 'x' }])) }, 'syn.ops');
  t = T;
  const c = D.view(false).charts;
  assert.equal(c.months.length, 12); assert.equal(c.months[11].new, 10); assert.equal(c.months[11].stealer, 9);
  assert.equal(c.by_kind.stealer, 9); assert.equal(c.by_status.new, 20); assert.equal(c.risk_bands.reduce((a, b) => a + b.exposures, 0), 20);
  assert.ok(c.data_classes.some((x) => x.class === 'Cookies' && x.exposures === 9));
  assert.equal(c.remediation.changed_since_leak, 1, 'syn.omar changed the password after the leak'); assert.equal(c.remediation.not_changed, 1, 'syn.lina did not');
  assert.ok(c.unusual && c.unusual.exposures === 10 && /new exposures this month/.test(c.unusual.why), JSON.stringify(c.unusual));
  assert.ok(!JSON.stringify(c).includes('corp.example'), 'no account in the chart data');
  assert.deepEqual(c.funnel.map((f) => f.status), ['new', 'notified', 'reset', 'closed']);
});
