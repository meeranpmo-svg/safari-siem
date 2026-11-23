// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Exchange Reports (engine/soc/exchange-reports.js) over the AI Exchange Server Administrator's read-only checks (the real
// sysadmin runner with a fake WinRM helper): the daily inventory (paged per database), size growth from the daily
// history, near quota / inactive / hidden / forwarding outside / features, permissions by mailbox and by holder, lists
// with nested expansion (bounded, cycles stopped) and external members, public folders, mobile devices (stale,
// unapproved models), Exchange Online from Graph usage reports, OWA / ActiveSync from IIS logs; a part that fails keeps
// its last good copy with the error; no server = not connected; roles (names for administrators only), validation (400
// naming the field), audit records, no password in a log line, the daily job. All names and data are SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const sysadmin = require('../engine/sysadmin/routes');
const XR = require('../engine/soc/exchange-reports');

const D = 'corp-synth.sa', MB = 1048576, GB = 1024 * MB, DAY = 86400000;
const NOW0 = Date.UTC(2026, 9, 14, 6, 0);           // 09:00 Riyadh, 30 days before NOW
const NOW = Date.UTC(2026, 10, 13, 6, 0);
const PW = 'Synthetic-Pw-9';

// the organisation the fake helper answers for (scale = growth between the two collections)
function org(scale, t) {
  const iso = (daysAgo) => new Date(t - daysAgo * DAY).toISOString();
  const m = (local, db, sizeMb, o = {}) => Object.assign({ address: `${local}@${D}`, name: local.replace('.', ' ') + ' (synthetic)', type: 'UserMailbox', database: db, size_bytes: Math.round(sizeMb * MB), items: 1000, last_logon: iso(1), prohibit_send_bytes: 10 * GB, warning_bytes: 9 * GB, quota_from_database: true, archive: 'None', hidden: false, litigation_hold: false, forwarding_smtp: '', forwarding_recipient: null, deliver_and_forward: false, created: iso(900) }, o);
  const db1 = [];
  for (let i = 0; i < 520; i++) db1.push(m('user' + String(i).padStart(4, '0'), 'DB01', 100));
  db1.push(m('alice.syn', 'DB01', 8000 * scale), m('bob.syn', 'DB01', 500, { last_logon: iso(200), hidden: true }), m('carol.syn', 'DB01', 700, { forwarding_smtp: 'smtp:carol.private@mail-synth.example', deliver_and_forward: true }),
    m('dave.syn', 'DB01', 300, { forwarding_recipient: `SMTP:dave.two@${D}` }), m('shared.finance', 'DB01', 2000, { type: 'SharedMailbox', last_logon: null, archive: 'Active', litigation_hold: true }));
  const db2 = [m('ceo.syn', 'DB02', 30000 * scale, { prohibit_send_bytes: null, warning_bytes: null, quota_from_database: false }), m('pa.syn', 'DB02', 900)];
  return {
    ex_inv_databases: [{ name: 'DB01', server: 'EXSYN01', mounted: true, size_bytes: 400 * GB, whitespace_bytes: 20 * GB, prohibit_send_bytes: 10 * GB, warning_bytes: 9 * GB }, { name: 'DB02', server: 'EXSYN02', mounted: true, size_bytes: 60 * GB, whitespace_bytes: 2 * GB, prohibit_send_bytes: null, warning_bytes: null }],
    mailboxes: { DB01: db1, DB02: db2 },
    cas: db1.concat(db2).map((x) => ({ address: x.address, owa: true, eas: true, pop: x.address.startsWith('alice'), imap: x.address.startsWith('bob'), mapi: true, ews: null, eas_policy: 'Default' })),
    perms: { DB01: [{ mailbox: `shared.finance@${D}`, name: 'Finance shared', type: 'SharedMailbox', full_access: ['CORP\\alice.syn', 'CORP\\bob.syn'], send_as: ['CORP\\alice.syn'], send_on_behalf: [] }], DB02: [{ mailbox: `ceo.syn@${D}`, name: 'ceo syn', type: 'UserMailbox', full_access: ['CORP\\pa.syn'], send_as: [], send_on_behalf: [`pa.syn@${D}`] }] },
    groups: [
      { address: `all-staff@${D}`, name: 'All staff', type: 'MailUniversalDistributionGroup', hidden: false, accepts_external: true, managed_by: ['corp-synth.sa/Users/IT Admin Synthetic'], members: [{ address: `alice.syn@${D}`, name: 'alice', type: 'UserMailbox' }, { address: `finance-team@${D}`, name: 'Finance team', type: 'MailUniversalDistributionGroup' }, { address: `auditor@${D}`, name: 'External auditor', type: 'MailContact', external: 'SMTP:partner@audit-synth.example' }, { address: `moved.syn@${D}`, name: 'Moved to EXO', type: 'RemoteUserMailbox', external: 'SMTP:moved.syn@corpsynth.mail.onmicrosoft.com' }] },
      { address: `finance-team@${D}`, name: 'Finance team', type: 'MailUniversalSecurityGroup', hidden: true, accepts_external: false, managed_by: [], members: [{ address: `bob.syn@${D}`, name: 'bob', type: 'UserMailbox' }, { address: `all-staff@${D}`, name: 'All staff', type: 'MailUniversalDistributionGroup' }] },
      { address: `empty-list@${D}`, name: 'Empty list', type: 'MailUniversalDistributionGroup', hidden: false, accepts_external: false, managed_by: [], members: [] },
    ],
    dynamic: [{ address: `dyn-everyone@${D}`, name: 'Everyone (dynamic)', hidden: false, accepts_external: false }],
    folders: { present: true, total: 1, items: [{ path: '\\Finance\\Invoices', mail_enabled: true, content_mailbox: 'PFMBX1', items: 120, size: '1.5 MB (1,572,864 bytes)', last_modified: iso(3) }] },
    mobile: [{ owner: 'corp-synth.sa/Users/alice syn', device_id: 'ABCDEF0123', model: 'iPhone15C2', type: 'iPhone', os: 'iOS 17.4', client: 'EAS', access: 'Allowed', access_reason: 'Global', policy: 'Default', policy_status: 'AppliedInFull', first_sync: iso(300), last_sync: iso(2) },
      { owner: 'corp-synth.sa/Users/bob syn', device_id: 'ZZ99', model: 'SM-X900', type: 'Android', os: 'Android 13', client: 'EAS', access: 'Quarantined', access_reason: 'DeviceRule', policy: 'Default', policy_status: 'NotApplied', first_sync: iso(400), last_sync: iso(60) }],
  };
}
const page = (list, p) => ({ total: list.length, items: list.slice(p.skip || 0, (p.skip || 0) + (p.take || 500)) });
function fakeExec(state) {
  const calls = [];
  const exec = async (req) => {
    if (req.op === 'version') return { ok: true, pypsrp: 'synthetic' };
    if (req.op !== 'run') return { ok: false, kind: 'input', error: 'x' };
    calls.push({ check: req.check, params: req.params, password_sent: req.password === PW });
    if (state.fail && state.fail[req.check]) return state.fail[req.check];
    const O = org(state.scale, state.now()), p = req.params || {};
    const data = { ex_inv_databases: O.ex_inv_databases, ex_inv_mailboxes: page(O.mailboxes[p.database] || [], p), ex_inv_cas: page(O.cas, p), ex_inv_permissions: page(O.perms[p.database] || [], p),
      ex_inv_groups: Object.assign(page(O.groups, p), { dynamic: p.skip ? [] : O.dynamic }), ex_inv_public_folders: O.folders, ex_inv_mobile: page(O.mobile, p) }[req.check];
    return data === undefined ? { ok: false, kind: 'input', error: 'unknown check' } : { ok: true, data, errors: [] };
  };
  exec.calls = calls; return exec;
}
const CSV_USAGE = '﻿Report Refresh Date,User Principal Name,Display Name,Is Deleted,Deleted Date,Created Date,Last Activity Date,Item Count,Storage Used (Byte),Issue Warning Quota (Byte),Prohibit Send Quota (Byte),Prohibit Send/Receive Quota (Byte),Deleted Item Count,Deleted Item Size (Byte),Deleted Item Quota (Byte),Has Archive,Recipient Type,Report Period\r\n'
  + `2026-11-12,eva.syn@${D},"Eva, Synthetic",False,,2025-01-01,2026-11-11,5000,${48 * GB},${45 * GB},${49 * GB},${50 * GB},0,0,0,True,User,30\r\n`
  + `2026-11-12,old.syn@${D},Old Synthetic,False,,2024-01-01,2026-08-01,10,${1 * GB},${45 * GB},${49 * GB},${50 * GB},0,0,0,False,User,30\r\n`
  + `2026-11-12,gone.syn@${D},Gone,True,2026-10-01,2024-01-01,,0,0,0,0,0,0,0,0,False,User,30\r\n`;
const CSV_ACT = 'Report Refresh Date,User Principal Name,Display Name,Is Deleted,Deleted Date,Last Activity Date,Send Count,Receive Count,Read Count,Meeting Created Count,Meeting Interacted Count,Assigned Products,Report Period\n'
  + `2026-11-12,eva.syn@${D},Eva,False,,2026-11-11,120,900,800,3,4,OFFICE 365 E3,30\n`;

async function setup({ server = true, graph, ch } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-exrep-'));
  const state = await createState({ dir: path.join(dir, 'state') });
  const config = {}; Object.defineProperty(config, 'secrets', { value: server ? { sysadmin: { profiles: { exchange: { username: 'CORP\\svc-synth-ro', password: PW, auth: 'negotiate' } } } } : {}, enumerable: false, writable: true });
  const st = { scale: 1, fail: null, t: NOW0, now: () => st.t };
  const logs = [], log = { info: (...a) => logs.push(a), warn: (...a) => logs.push(a), error: (...a) => logs.push(a), every: (...a) => logs.push(a) };
  const exec = fakeExec(st);
  const S = sysadmin.createSysadmin({ state, config, log, sysadminExec: exec });
  if (server) S.targets.put({ id: 'exsyn01', name: 'EXSYN01', ip: '10.0.1.20', roles: ['exchange'] }, 'test');
  const R = {}, audits = [];
  const deps = { state, config, log, ch: ch || null, m365Graph: graph, sysadminInstance: S, now: () => st.t };
  const X = XR.createExchangeReports({ state, sysadmin: S, graph, ch: ch || null, config, log, now: () => st.t });
  XR.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, Object.assign({ exchangeReports: X }, deps));
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  async function call(m, p, { role = 'viewer', user = role + '.syn', body, query = {} } = {}) {
    const out = {};
    const ctx = { role, user, body, query, params: {}, path: p, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; out.error = 'requires ' + r; return false; } return true; },
      audit: (a, t, d) => audits.push({ a, t, d, by: user, role }), ok(b) { out.status = 200; out.body = b; return out; }, fail(c, msg) { out.status = c; out.error = msg; return out; } };
    const h = R[m + ' /api/soc' + p]; assert.ok(h, 'route ' + m + ' ' + p);
    const rv = await h(ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; }
    return out;
  }
  return { X, S, st, exec, call, audits, logs, state };
}

test('pure: mailbox normalisation, nested lists bounded with cycles stopped, holders, devices, Graph CSV', () => {
  const m = XR.normMailbox({ address: 'Alice@Corp-Synth.SA', size_bytes: 9 * GB, prohibit_send_bytes: 10 * GB, forwarding_smtp: 'smtp:X@Mail-Synth.example', archive: 'Active' });
  assert.equal(m.address, 'alice@corp-synth.sa'); assert.equal(m.used_pct, 90); assert.equal(m.forwarding, 'x@mail-synth.example'); assert.equal(m.archive, true);
  assert.equal(XR.normMailbox({ address: 'not-an-address' }), null, 'a row without an address is dropped');
  assert.equal(XR.normMailbox({ address: 'a@b.sa', items: null }).items, null, 'unknown item count stays unknown, never 0');
  // a chain of 8 nested lists: expansion stops at depth 5 and says so; a cycle is followed once
  const chain = Array.from({ length: 8 }, (_, i) => ({ address: `g${i}@${D}`, name: 'G' + i, type: 'MailUniversalDistributionGroup', members: [{ address: `p${i}@${D}`, name: 'P' + i, type: 'UserMailbox' }].concat(i < 7 ? [{ address: `g${i + 1}@${D}`, name: 'G' + (i + 1), type: 'MailUniversalDistributionGroup' }] : [{ address: `g0@${D}`, name: 'G0', type: 'MailUniversalDistributionGroup' }]) }));
  const E = XR.expandGroups(chain, new Set([D]));
  assert.equal(E[0].truncated, true); assert.equal(E[0].members, 6, 'people in G0..G5');
  assert.equal(E[7].members, 6); assert.ok(E[7].truncated);
  const O = org(1, NOW), G = XR.expandGroups(O.groups.map(XR.normGroup), new Set([D]));
  const all = G.find((g) => g.address === `all-staff@${D}`);
  assert.equal(all.members, 4, 'alice, bob (through Finance team), the contact, the moved mailbox - All staff inside Finance team is not counted twice');
  assert.deepEqual(all.external.map((x) => x.address), ['partner@audit-synth.example'], 'the contact is external; a mailbox moved to Exchange Online is not');
  assert.equal(all.people.find((p) => p.name === 'bob').via, 'Finance team');
  const H = XR.holdersOf(Object.values(O.perms).flat().map(XR.normPerm));
  assert.equal(H[0].holder, 'CORP\\alice.syn'); assert.equal(H[0].full_access, 1); assert.equal(H[0].send_as, 1); assert.equal(H[0].mailboxes, 1);
  const st = { stale_device_days: 30, approved_models: [] };
  const dv = XR.normDevice(O.mobile[1]);
  assert.equal(dv.owner, 'bob syn', 'the canonical name is cut to the display name');
  assert.deepEqual(XR.deviceFlags(dv, st, NOW), { stale: true, unapproved: null, blocked: true }, 'no approved list = not judged, never "all unapproved"');
  assert.equal(XR.deviceFlags(dv, Object.assign({}, st, { approved_models: ['iphone'] }), NOW).unapproved, true);
  const on = XR.onlineFrom(CSV_USAGE, CSV_ACT);
  assert.equal(on.items.length, 2, 'deleted mailboxes left out'); assert.equal(on.items[0].name, 'Eva, Synthetic', 'quoted comma');
  assert.equal(on.items[0].used_pct, 98); assert.equal(on.items[0].sent, 120); assert.equal(on.items[1].sent, null, 'no activity row: unknown, not 0'); assert.equal(on.concealed, false);
  const hidden = XR.onlineFrom(CSV_USAGE.replace(/eva\.syn@corp-synth\.sa/g, 'a'.repeat(32)).replace(/old\.syn@corp-synth\.sa/g, 'b'.repeat(32)), '');
  assert.equal(hidden.concealed, true, 'Microsoft 365 concealed names are recognised');
});

test('no Exchange server with a login: not connected, Collect now refused, nothing invented', async () => {
  const { call } = await setup({ server: false });
  const s = (await call('GET', '/exchange/reports/summary')).body;
  assert.equal(s.status.connected, false); assert.match(s.status.reason, /AI Exchange Server Administrator/);
  assert.equal(s.mailboxes, null); assert.equal(s.permissions, null); assert.equal(s.groups, null); assert.equal(s.mobile, null);
  const c = await call('POST', '/exchange/reports/collect', { role: 'operator', body: {} });
  assert.equal(c.status, 409); assert.match(c.error, /no Exchange server with a login/);
  const on = (await call('GET', '/exchange/reports/online')).body;
  assert.equal(on.state, 'not_connected'); assert.match(on.note, /not loaded|not connected/);
});

test('inventory: paged per database, daily history, growth, every mailbox report; parts keep their last good copy', async () => {
  const graph = { status: () => ({ ready: true, missing: [] }), graphContent: async (u) => Buffer.from(/getMailboxUsageDetail/.test(u) ? CSV_USAGE : CSV_ACT) };
  const { X, st, exec, call, audits, logs } = await setup({ graph });
  let r = await X.collect('operator.syn');
  assert.ok(r.results.every((x) => x.ok), JSON.stringify(r.results));
  const mb = exec.calls.filter((c) => c.check === 'ex_inv_mailboxes');
  assert.deepEqual(mb.map((c) => [c.params.database, c.params.skip]), [['DB01', 0], ['DB01', 500], ['DB02', 0]], '525 mailboxes in DB01 = two pages of 500');
  assert.ok(exec.calls.every((c) => c.password_sent), 'the login goes to the helper on stdin');
  assert.ok(exec.calls.every((c) => /^ex_inv_/.test(c.check)), 'only the allow-listed inventory checks run');
  // 30 days later: alice and the CEO grew by 10 %
  st.t = NOW; st.scale = 1.1; r = await X.collect('system:exchange-reports');
  const sum = (await call('GET', '/exchange/reports/summary')).body;
  assert.equal(sum.mailboxes.total, 527); assert.equal(sum.mailboxes.by_type.SharedMailbox, 1);
  assert.equal(sum.mailboxes.near_quota, 0, 'alice: 8800 MB of 10 GB = 85.9 % - below the 90 % default; the CEO has no quota');
  assert.equal(sum.mailboxes.inactive, 1, 'bob (200 days); the shared mailbox is not a person'); assert.equal(sum.mailboxes.hidden, 1);
  assert.equal(sum.mailboxes.forwarding, 2); assert.equal(sum.mailboxes.forwarding_outside, 1, 'carol forwards outside; dave forwards inside');
  assert.equal(sum.mailboxes.features.pop, 1); assert.equal(sum.mailboxes.features.imap, 1); assert.equal(sum.mailboxes.unlimited, 1);
  assert.equal(sum.mailboxes.growth_30d.days, 30); assert.equal(sum.mailboxes.growth_30d.gb, Math.round((800 + 3000) / 102.4) / 10);
  assert.equal(sum.trend.length, 2); assert.equal(sum.db_trend.DB02.length, 2); assert.deepEqual(sum.domains, [D]); assert.equal(sum.domains_derived, true);
  assert.equal(sum.permissions.full_access, 3); assert.equal(sum.permissions.send_as, 1); assert.equal(sum.permissions.send_on_behalf, 1); assert.equal(sum.permissions.mailboxes_with_delegates, 2);
  assert.equal(sum.groups.total, 3); assert.equal(sum.groups.empty, 1); assert.equal(sum.groups.with_external, 2, 'Finance team reaches the contact through All staff'); assert.equal(sum.groups.dynamic, 1); assert.equal(sum.groups.nested, 2);
  assert.equal(sum.public_folders.present, true); assert.equal(sum.public_folders.size_gb, 0);
  assert.equal(sum.mobile.devices, 2); assert.equal(sum.mobile.stale, 1); assert.equal(sum.mobile.quarantined, 1); assert.equal(sum.mobile.unapproved, null);
  assert.equal(sum.online.mailboxes, 2); assert.equal(sum.online.near_quota, 1); assert.equal(sum.online.inactive_30d, 1);
  const flat = JSON.stringify(sum);
  for (const who of ['alice.syn', 'bob.syn', 'CORP\\\\', 'partner@audit', 'Finance team', 'eva.syn']) assert.ok(!flat.includes(who), 'the summary names nobody: ' + who);
  // administrator reports
  const A = (p, query) => call('GET', p, { role: 'admin', query });
  const big = (await A('/exchange/reports/mailboxes', { view: 'largest', limit: '3' })).body;
  assert.deepEqual(big.items.map((x) => x.address), [`ceo.syn@${D}`, `alice.syn@${D}`, `shared.finance@${D}`]); assert.equal(big.total, 527);
  const grow = (await A('/exchange/reports/mailboxes', { view: 'growing', days: '30' })).body;
  assert.equal(grow.items[0].address, `ceo.syn@${D}`); assert.equal(grow.items[0].growth_mb, 3000); assert.equal(grow.growth.since, '2026-10-14');
  assert.deepEqual((await A('/exchange/reports/mailboxes', { view: 'inactive' })).body.items.map((x) => x.address), [`bob.syn@${D}`]);
  assert.deepEqual((await A('/exchange/reports/mailboxes', { view: 'hidden' })).body.items.map((x) => x.address), [`bob.syn@${D}`]);
  const fw = (await A('/exchange/reports/mailboxes', { view: 'forwarding' })).body.items;
  assert.deepEqual(fw.map((x) => [x.address, x.forwarding_outside]), [[`carol.syn@${D}`, true], [`dave.syn@${D}`, false]]);
  assert.deepEqual((await A('/exchange/reports/mailboxes', { view: 'features', feature: 'pop' })).body.items.map((x) => x.address), [`alice.syn@${D}`]);
  assert.deepEqual((await A('/exchange/reports/mailboxes', { view: 'all', database: 'DB02' })).body.items.map((x) => x.address), [`ceo.syn@${D}`, `pa.syn@${D}`]);
  // near quota follows the threshold the administrator sets
  assert.equal((await call('PUT', '/exchange/reports/settings', { role: 'admin', body: { near_quota_pct: 85, approved_models: ['iPhone'] } })).status, 200);
  assert.deepEqual((await A('/exchange/reports/mailboxes', { view: 'quota' })).body.items.map((x) => x.address), [`alice.syn@${D}`]);
  const dev = (await A('/exchange/reports/devices', { view: 'unapproved' })).body; assert.deepEqual(dev.items.map((d) => d.model), ['SM-X900']);
  assert.deepEqual((await A('/exchange/reports/devices', { view: 'stale' })).body.items.map((d) => d.owner), ['bob syn']);
  const pm = (await A('/exchange/reports/permissions', { view: 'mailbox' })).body; assert.equal(pm.items[0].mailbox, `shared.finance@${D}`);
  const ho = (await A('/exchange/reports/permissions', { view: 'holders', right: 'send_on_behalf' })).body; assert.deepEqual(ho.items.map((h) => h.holder), [`pa.syn@${D}`]);
  assert.deepEqual((await A('/exchange/reports/groups', { view: 'external' })).body.items.map((g) => g.address), [`all-staff@${D}`, `finance-team@${D}`]);
  assert.deepEqual((await A('/exchange/reports/groups', { view: 'empty' })).body.items.map((g) => g.address), [`empty-list@${D}`]);
  assert.deepEqual((await A('/exchange/reports/groups', { view: 'dynamic' })).body.items.map((g) => g.address), [`dyn-everyone@${D}`]);
  assert.equal((await A('/exchange/reports/public-folders', {})).body.items[0].path, '\\Finance\\Invoices');
  const onl = (await A('/exchange/reports/online', { view: 'inactive' })).body; assert.deepEqual(onl.items.map((x) => x.upn), [`old.syn@${D}`]);
  assert.ok(audits.filter((x) => x.a === 'exchange.reports.view').length >= 10, 'every named view is audited');
  assert.ok(audits.every((x) => !JSON.stringify(x.d).includes('alice')), 'the audit says what was viewed, not the names');
  // a part fails: its last good copy stays, marked with the error; the others are read
  st.fail = { ex_inv_groups: { ok: false, kind: 'error', error: 'Get-DistributionGroup: synthetic failure' } };
  await X.collect('system:exchange-reports');
  const stt = (await call('GET', '/exchange/reports/status')).body;
  assert.equal(stt.parts.groups.ok, false); assert.match(stt.parts.groups.error, /synthetic failure/); assert.equal(stt.parts.groups.count, 3, 'last good copy kept');
  assert.equal(stt.parts.mailboxes.ok, true);
  // a login failure stops the Exchange parts (they would fail the same way) and says why
  st.fail = { ex_inv_databases: { ok: false, kind: 'auth', error: 'login refused: wrong user name / password' } };
  r = await X.collect('system:exchange-reports');
  assert.ok(r.results.filter((x) => x.part !== 'online').every((x) => !x.ok)); assert.ok(r.results.find((x) => x.part === 'permissions').error.startsWith('not read: login refused'));
  assert.ok(exec.calls.filter((c) => c.check === 'ex_inv_databases').length >= 1);
  assert.ok(!JSON.stringify(logs).includes(PW), 'the password never reaches a log line');
});

test('roles, validation and audit on every route', async () => {
  const { X, call, audits } = await setup();
  await X.collect('operator.syn');
  for (const p of ['/exchange/reports/mailboxes', '/exchange/reports/permissions', '/exchange/reports/groups', '/exchange/reports/public-folders', '/exchange/reports/devices', '/exchange/reports/digest']) {
    assert.equal((await call('GET', p, { role: 'viewer' })).status, 403, 'viewer: ' + p);
    assert.equal((await call('GET', p, { role: 'operator' })).status, 403, 'operator: ' + p + ' names people - administrators only');
    assert.equal((await call('GET', p, { role: 'admin' })).status, 200, 'admin: ' + p);
  }
  let r = await call('GET', '/exchange/reports/mailboxes', { role: 'admin', query: { view: 'everything' } }); assert.equal(r.status, 400); assert.match(r.error, /^view must be one of/);
  r = await call('GET', '/exchange/reports/mailboxes', { role: 'admin', query: { limit: '0' } }); assert.equal(r.status, 400); assert.match(r.error, /^limit must be at least 1/);
  r = await call('GET', '/exchange/reports/mailboxes', { role: 'admin', query: { database: "DB01'; Remove-Item" } }); assert.equal(r.status, 400); assert.match(r.error, /^database/);
  r = await call('GET', '/exchange/reports/permissions', { role: 'admin', query: { right: 'owner' } }); assert.equal(r.status, 400); assert.match(r.error, /^right/);
  r = await call('GET', '/exchange/reports/clients', { query: { range: '365' } }); assert.equal(r.status, 400); assert.match(r.error, /^range/);
  // settings: administrators only, every field checked, audited
  assert.equal((await call('PUT', '/exchange/reports/settings', { role: 'operator', body: { inactive_days: 60 } })).status, 403);
  r = await call('PUT', '/exchange/reports/settings', { role: 'admin', body: { internal_domains: ['not a domain'] } }); assert.equal(r.status, 400); assert.match(r.error, /^internal_domains/);
  r = await call('PUT', '/exchange/reports/settings', { role: 'admin', body: { inactive_days: 3 } }); assert.equal(r.status, 400); assert.match(r.error, /^inactive_days must be at least 7/);
  r = await call('PUT', '/exchange/reports/settings', { role: 'admin', body: { evil: 1 } }); assert.equal(r.status, 400, 'an undeclared field is dropped, and nothing is left to change');
  r = await call('PUT', '/exchange/reports/settings', { role: 'admin', body: { inactive_days: 60, internal_domains: ['Corp-Synth.SA.', 'sub.corp-synth.sa'], evil: 1 } });
  assert.equal(r.status, 200); assert.deepEqual(r.body.settings.internal_domains, [D, 'sub.corp-synth.sa']); assert.equal(r.body.settings.evil, undefined);
  assert.deepEqual(audits.find((x) => x.a === 'exchange.reports.settings').d, { changed: ['inactive_days', 'internal_domains'] });
  assert.equal(audits.find((x) => x.a === 'exchange.reports.settings').by, 'admin.syn');
  // collect: operators and administrators; parts validated; audited
  assert.equal((await call('POST', '/exchange/reports/collect', { role: 'viewer', body: {} })).status, 403);
  r = await call('POST', '/exchange/reports/collect', { role: 'operator', body: { parts: ['mailboxes', 'shell'] } }); assert.equal(r.status, 400); assert.match(r.error, /^parts\[1\] must be one of/);
  r = await call('POST', '/exchange/reports/collect', { role: 'operator', body: { parts: ['mobile'] } }); assert.equal(r.status, 200); assert.equal(r.body.started, true);
  await X.idle();
  assert.deepEqual(audits.find((x) => x.a === 'exchange.reports.collect'), { a: 'exchange.reports.collect', t: 'inventory', d: { parts: ['mobile'] }, by: 'operator.syn', role: 'operator' });
  // viewers get counts; the status and summary answer every signed-in role
  assert.equal((await call('GET', '/exchange/reports/status', { role: 'viewer' })).status, 200);
  assert.equal((await call('GET', '/exchange/reports/summary', { role: 'viewer' })).status, 200);
});

test('Exchange Online: permission missing says which; OWA / ActiveSync from IIS: names for administrators only', async () => {
  const denied = { status: () => ({ ready: true, missing: [] }), graphContent: async () => { throw Object.assign(new Error('HTTP 403'), { status: 403 }); } };
  const calls = [];
  const A = { cl_tot: [{ owa: 900, eas: 4000, owa_users: 40, signins: 55, eas_users: 30, devices: 33, failed: 12, failed_users: 3, failed_ips: 2 }], cl_series: [{ k: 0, ou: 10, ed: 20, fl: 2 }],
    cl_vdir: [{ v: 'OWA', fl: 5, err: 0, n: 900 }, { v: 'ActiveSync', fl: 7, err: 1, n: 4000 }], cl_users: [{ u: 'alice.syn', d: 'corp', signins: 3, owa: 50, syncs: 200, failed: 0, devices: 1, ips: 2, last: '2026-11-13 08:00:00' }],
    cl_failed: [{ u: 'bob.syn', ip: '203.0.113.9', v: 'ActiveSync', n: 7, last: '2026-11-13 07:00:00' }], cl_devices: [{ id: 'ABCDEF0123', type: 'iPhone', u: 'alice.syn', ua: 'Apple-iPhone15C2/2104', n: 300, err: 0, last: '2026-11-13 08:00:00' }] };
  const ch = { query: async (sql, p) => { const tag = /^\/\*q:([a-z_]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, p }); return (A[tag] || []).map((x) => Object.assign({}, x)); } };
  const { X, call } = await setup({ graph: denied, ch });
  const r = await X.collect('operator.syn', ['online']);
  assert.equal(r.results[0].ok, false); assert.match(r.results[0].error, /Reports\.Read\.All/);
  const on = (await call('GET', '/exchange/reports/online', { role: 'admin' })).body; assert.equal(on.state, 'not_connected'); assert.match(on.note, /Reports\.Read\.All/);
  const v = (await call('GET', '/exchange/reports/clients', { role: 'viewer', query: { range: '7' } })).body;
  assert.equal(v.configured, true); assert.equal(v.totals.failed, 12); assert.equal(v.named, false); assert.equal(v.users, null); assert.equal(v.devices_seen, null); assert.match(v.note, /administrators only/);
  assert.ok(!calls.some((c) => /cl_users|cl_failed|cl_devices/.test(c.tag)), 'a viewer\'s request never reads names from the store');
  const a = (await call('GET', '/exchange/reports/clients', { role: 'admin', query: { range: '7' } })).body;
  assert.equal(a.users[0].user, 'alice.syn'); assert.equal(a.failed[0].ip, '203.0.113.9'); assert.equal(a.devices_seen[0].device_id, 'ABCDEF0123'); assert.equal(a.series.length, 7);
  const tot = calls.find((c) => c.tag === 'cl_tot'); assert.match(tot.sql, /exchange-microsoft-server-activesync/); assert.match(tot.sql, /http_status = 401 AND user != ''/);
  assert.equal(typeof tot.p.t_from.value, 'number', 'the window is a parameter');
  A.cl_tot = [{ owa: 0, eas: 0 }];
  const none = (await call('GET', '/exchange/reports/clients', { role: 'admin' })).body; assert.equal(none.configured, false); assert.equal(none.totals, null); assert.match(none.note, /forward the IIS logs/);
});

test('digest for the Reporting Center and the daily job (once a day, after the hour, guarded)', async () => {
  const ch = { query: async () => [] };
  const { X, st, exec, call, audits } = await setup({ ch });
  st.t = Date.UTC(2026, 10, 12, 22, 30);   // 01:30 Riyadh on 13 November
  await X.collect('system:exchange-reports');
  const d = await call('GET', '/exchange/reports/digest', { role: 'admin' });
  assert.equal(d.status, 200); assert.equal(d.body.summary.mailboxes.total, 527);
  assert.equal(d.body.largest[0].address, `ceo.syn@${D}`); assert.equal(d.body.holders[0].holder, 'CORP\\alice.syn');
  assert.deepEqual(d.body.external_groups.map((g) => g.external), [1, 1]); assert.equal(d.body.empty_groups[0].address, `empty-list@${D}`);
  assert.equal(d.body.traffic.exchange, false, 'no message tracking: said, not zero-filled');
  assert.ok(audits.some((x) => x.a === 'exchange.reports.view' && x.t === 'reporting-center'));
  const n0 = exec.calls.length;
  // the daily tick: not before the hour, once after it, not again the same day
  st.t = Date.UTC(2026, 10, 13, 22, 0);   // 01:00 Riyadh next day
  await X.tick(); assert.equal(exec.calls.length, n0, 'before 02:00 Riyadh nothing runs');
  st.t = Date.UTC(2026, 10, 13, 23, 30);  // 02:30 Riyadh
  await X.tick(); assert.ok(exec.calls.length > n0, 'after 02:00 the inventory is read');
  const n1 = exec.calls.length; await X.tick(); assert.equal(exec.calls.length, n1, 'once a day');
  assert.equal((await call('GET', '/exchange/reports/status')).body.last_day, '2026-11-14');
});
