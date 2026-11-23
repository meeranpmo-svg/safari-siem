// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Exchange Reports (exchange-reports.html) against the REAL SIEM modules (sentra-siem engine/soc/exchange-reports.js and
// engine/soc/mailstats.js) over the real AI Exchange Administrator runner with a FAKE WinRM helper, a stubbed ClickHouse and a
// fake Microsoft Graph - all data SYNTHETIC. An administrator: every tab (Mailboxes with the growth trend and the reports,
// Permissions by mailbox and by person, Distribution lists with external members, Traffic with top senders, OWA & ActiveSync
// with stale devices, Exchange Online), filters reach the SIEM as parameters, Collect now, settings, Excel; a hostile mailbox
// name stays text. A viewer: counts only, no name anywhere (PDPL). No Exchange server with a login: the page says what to add.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node exchange-reports.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const XR = require(path.join(SIEM, 'engine/soc/exchange-reports'));
const MS = require(path.join(SIEM, 'engine/soc/mailstats'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const sysadmin = require(path.join(SIEM, 'engine/sysadmin/routes'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const D = 'corp-synth.sa', MB = 1048576, GB = 1024 * MB, DAY = 86400000;
let clock = Date.now() - 30 * DAY, scale = 1;

function org() {
  const iso = (d) => new Date(clock - d * DAY).toISOString();
  const m = (local, db, sizeMb, o = {}) => Object.assign({ address: `${local}@${D}`, name: local + ' (synthetic)', type: 'UserMailbox', database: db, size_bytes: Math.round(sizeMb * MB), items: 900, last_logon: iso(1), prohibit_send_bytes: 10 * GB, warning_bytes: 9 * GB, archive: 'None', hidden: false, litigation_hold: false, forwarding_smtp: '', deliver_and_forward: false }, o);
  const mbx = { DB01: [m('alice.syn', 'DB01', 9300 * scale, { name: 'Alice ' + XSS }), m('bob.syn', 'DB01', 400, { last_logon: iso(200), hidden: true }), m('carol.syn', 'DB01', 700, { forwarding_smtp: 'smtp:carol.home@mail-synth.example' }), m('shared.finance', 'DB01', 2000, { type: 'SharedMailbox', last_logon: null })],
    DB02: [m('ceo.syn', 'DB02', 30000 * scale, { prohibit_send_bytes: null }), m('pa.syn', 'DB02', 800)] };
  const all = mbx.DB01.concat(mbx.DB02);
  return {
    ex_inv_databases: [{ name: 'DB01', server: 'EXSYN01', mounted: true, size_bytes: 300 * GB, whitespace_bytes: 12 * GB, prohibit_send_bytes: 10 * GB, warning_bytes: 9 * GB }, { name: 'DB02', server: 'EXSYN02', mounted: true, size_bytes: 80 * GB, whitespace_bytes: 3 * GB }],
    mbx, cas: all.map((x) => ({ address: x.address, owa: true, eas: true, pop: x.address.startsWith('bob'), imap: false, mapi: true })),
    perms: { DB01: [{ mailbox: `shared.finance@${D}`, name: 'Finance shared', type: 'SharedMailbox', full_access: ['CORP\\alice.syn', 'CORP\\bob.syn'], send_as: ['CORP\\alice.syn'], send_on_behalf: [] }], DB02: [{ mailbox: `ceo.syn@${D}`, name: 'CEO synthetic', type: 'UserMailbox', full_access: ['CORP\\pa.syn'], send_as: [], send_on_behalf: [`pa.syn@${D}`] }] },
    groups: [{ address: `all-staff@${D}`, name: 'All staff', type: 'MailUniversalDistributionGroup', accepts_external: true, members: [{ address: `alice.syn@${D}`, name: 'alice', type: 'UserMailbox' }, { address: `auditor@${D}`, name: 'External auditor', type: 'MailContact', external: 'SMTP:partner@audit-synth.example' }] },
      { address: `empty-list@${D}`, name: 'Empty list', type: 'MailUniversalDistributionGroup', members: [] }],
    mobile: [{ owner: 'corp-synth.sa/Users/alice syn', device_id: 'ABC123', model: 'iPhone15C2', type: 'iPhone', os: 'iOS 17.4', access: 'Allowed', policy: 'Default', last_sync: iso(1) }, { owner: 'corp-synth.sa/Users/bob syn', device_id: 'ZZ99', model: 'SM-X900', type: 'Android', os: 'Android 13', access: 'Quarantined', policy: 'Default', last_sync: iso(70) }],
  };
}
const page = (list, p) => ({ total: list.length, items: list.slice(p.skip || 0, (p.skip || 0) + (p.take || 500)) });
const exec = async (req) => {
  if (req.op === 'version') return { ok: true };
  const O = org(), p = req.params || {};
  const data = { ex_inv_databases: O.ex_inv_databases, ex_inv_mailboxes: page(O.mbx[p.database] || [], p), ex_inv_cas: page(O.cas, p), ex_inv_permissions: page(O.perms[p.database] || [], p),
    ex_inv_groups: Object.assign(page(O.groups, p), { dynamic: [] }), ex_inv_public_folders: { present: false, total: 0, items: [] }, ex_inv_mobile: page(O.mobile, p) }[req.check];
  return data === undefined ? { ok: false, kind: 'input', error: 'unknown check' } : { ok: true, data, errors: [] };
};
const CSV_U = `Report Refresh Date,User Principal Name,Display Name,Is Deleted,Last Activity Date,Item Count,Storage Used (Byte),Prohibit Send Quota (Byte),Has Archive,Recipient Type\n2026-11-12,eva.syn@${D},Eva Synthetic,False,2026-11-11,5000,${40 * GB},${49 * GB},True,User\n2026-11-12,old.syn@${D},Old Synthetic,False,2026-07-01,10,${GB},${49 * GB},False,User\n`;
const CSV_A = `Report Refresh Date,User Principal Name,Send Count,Receive Count,Read Count\n2026-11-12,eva.syn@${D},120,900,800\n`;
const graph = { status: () => ({ ready: true, missing: [] }), graphContent: async (u) => Buffer.from(/MailboxUsage/.test(u) ? CSV_U : CSV_A) };
const A = {
  tr_ex: [{ n: 500 }], tr_status: [{ a: 'receive', n: 3000 }, { a: 'deliver', n: 2600 }, { a: 'send', n: 500 }, { a: 'fail', n: 40 }, { a: 'defer', n: 12 }],
  tr_reasons: [{ reason: '550 5.1.1 RESOLVER.ADR.RecipNotFound; not found <address>', a: 'fail', n: 25 }], tr_series: [{ k: 0, rcv: 400, dlv: 380, snd: 70, fl: 5 }, { k: 6, rcv: 450, dlv: 420, snd: 80, fl: 9 }],
  tr_hours: [{ h: 9, n: 800 }], tr_dow: [{ d: 7, n: 900 }], tr_sizes: [{ k: 0, n: 1000, bytes: 5 * MB }, { k: 3, n: 100, bytes: 300 * MB }], tr_split: [{ r: 1200, i: 1400, s: 450 }], tr_domain: [{ rf: 30, st: 44, fl: 2 }],
  tr_senders: [{ a: `alice.syn@${D}`, n: 120, bytes: 50 * MB }], tr_rcpts: [{ a: 'partner@audit-synth.example', n: 40 }],
  cl_tot: [{ owa: 900, eas: 4000, owa_users: 40, signins: 55, eas_users: 30, devices: 33, failed: 12, failed_users: 3, failed_ips: 2 }], cl_series: [{ k: 0, ou: 10, ed: 20, fl: 2 }], cl_vdir: [{ v: 'OWA', fl: 5, err: 0, n: 900 }],
  cl_users: [{ u: 'alice.syn', d: 'CORP', signins: 3, owa: 50, syncs: 200, failed: 0, devices: 1, ips: 2, last: '2026-11-13 08:00:00' }], cl_failed: [{ u: 'bob.syn', ip: '203.0.113.9', v: 'ActiveSync', n: 7, last: '2026-11-13 07:00:00' }], cl_devices: [],
};
const CALLS = [];
const ch = { query: async (sql, p) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; CALLS.push({ tag, p }); return (A[tag] || []).map((r) => Object.assign({}, r)); } };
const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
let ROLE = 'admin';

async function engine(withServer) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-exrep-ui-'));
  const state = await createState({ dir });
  const config = {}; Object.defineProperty(config, 'secrets', { value: withServer ? { sysadmin: { profiles: { exchange: { username: 'CORP\\svc-synth-ro', password: 'synthetic', auth: 'negotiate' } } } } : {}, enumerable: false, writable: true });
  const log = { info() {}, warn() {}, error() {}, every() {} };
  const S = sysadmin.createSysadmin({ state, config, log, sysadminExec: exec });
  if (withServer) S.targets.put({ id: 'exsyn01', name: 'EXSYN01', ip: '10.0.1.20', roles: ['exchange'] }, 'test');
  const X = XR.createExchangeReports({ state, sysadmin: S, graph, ch, config, log, now: () => clock });
  const routes = {}, audits = [], api = { route: (m, p, fn) => { routes[m + ' ' + p] = fn; } };
  const deps = { state, config, log, ch, now: () => clock, exchangeReports: X, sysadminInstance: S };
  XR.register(api, deps); MS.register(api, deps);
  return { X, routes, audits };
}

(async () => {
  let E = await engine(true);
  await E.X.collect('test');                       // 30 days ago
  clock = Date.now(); scale = 1.1; await E.X.collect('test');   // today: alice and the CEO grew 10 %
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: ROLE + '.syn', role: ROLE });
    const key = req.method + ' ' + u;
    if (E.routes[key]) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { let out = null;
      const ctx = { query: Object.fromEntries(url.searchParams), body: b ? JSON.parse(b) : {}, role: ROLE, user: ROLE + '.syn', path: u, ok: (x) => { out = [200, x]; return out; }, fail: (s, m) => { out = [s, { error: m }]; return out; },
        need: (r) => { if ((RANK[ROLE] || 0) < RANK[r]) { out = [403, { error: 'requires role ' + r }]; return false; } return true; }, audit: (a, t, d) => E.audits.push({ a, t, d, by: ROLE }) };
      const rv = await E.routes[key](ctx); if (!out) out = [200, rv]; json(out[0], out[1]); }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/exchange-reports.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg, ms) => p.waitForFunction(fn, arg, { timeout: ms || 15000 }).then(() => true, () => false);
  const txt = (p, s) => p.textContent(s);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(url);
    ok(await wait(p, () => /Mailboxes\s*6/.test(document.getElementById('mb-k').textContent)), 'mailbox tiles load');
    const k = await txt(p, '#mb-k');
    ok(/Near quota\s*1/.test(k) && /Inactive\s*1/.test(k) && /Forwarding outside\s*1/.test(k) && /POP \/ IMAP on\s*1/.test(k) && /Hidden\s*1/.test(k), 'tiles: near quota, inactive, forwarding outside, POP / IMAP, hidden');
    ok(/Growth/.test(k) && /since \d{4}-\d{2}-\d{2}/.test(k), 'growth since the first inventory');
    ok((await p.$$('#mb-trend .vb i')).length === 2, 'trend chart: one bar per daily inventory');
    ok(/DB02/.test(await txt(p, '#mb-db')) && /file 300 GB/.test(await txt(p, '#mb-db')), 'by database with the file size');
    ok(await wait(p, () => /ceo\.syn@corp-synth\.sa/.test(document.getElementById('mb-t').textContent)), 'largest mailboxes');
    ok((await p.$eval('#mb-t tbody tr', (r) => r.textContent)).includes('ceo.syn'), 'the CEO mailbox is the largest');
    ok(!(await p.evaluate(() => window.__xss)) && /<img src=x/.test(await txt(p, '#mb-t')), 'a hostile mailbox name stays text');
    ok(/Mailboxes:\s*\S/.test(await txt(p, '#parts')) && /from EXSYN01/.test(await txt(p, '#up')), 'what was read, when and from which server');
    await p.click('[data-mv="growing"]');
    ok(await wait(p, () => /\+2\.9 GB \(10 %\)/.test(document.getElementById('mb-t').textContent)), 'fastest growing: +3000 MB (10 %)');
    await p.click('[data-mv="inactive"]');
    ok(await wait(p, () => { const t = document.getElementById('mb-t').textContent; return /bob\.syn/.test(t) && !/shared\.finance/.test(t); }), 'inactive: the person, not the shared mailbox');
    await p.click('[data-mv="forwarding"]'); ok(await wait(p, () => /forwards to carol\.home@mail-synth\.example/.test(document.getElementById('mb-t').textContent)), 'forwarding outside');
    await p.click('[data-mv="features"]'); ok(await wait(p, () => /bob\.syn/.test(document.getElementById('mb-t').textContent) && !/alice/.test(document.getElementById('mb-t').textContent)), 'POP / IMAP on');
    await p.click('[data-mv="all"]'); await p.fill('#mb-q', 'pa.syn');
    ok(await wait(p, () => document.querySelectorAll('#mb-t tbody tr').length === 1), 'search filters');
    ok(E.audits.some((x) => x.a === 'exchange.reports.view' && x.d.view === 'mailboxes.all'), 'the named view is audited');
    const [dl1] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^exchange-mailboxes-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl1.suggestedFilename()), 'Excel export of the mailboxes');
    // Permissions
    await p.click('[data-tab="pm"]');
    ok(await wait(p, () => /shared\.finance@corp-synth\.sa/.test(document.getElementById('pm-t').textContent)), 'permissions by mailbox');
    ok(/Full Access\s*3/.test(await txt(p, '#pm-k')) && /Send As\s*1/.test(await txt(p, '#pm-k')), 'permission tiles');
    await p.click('[data-pv="holders"]'); ok(await wait(p, () => /CORP\\alice\.syn/.test(document.getElementById('pm-t').textContent)), 'non-owner access by person');
    await p.selectOption('#pm-right', 'send_on_behalf'); ok(await wait(p, () => /pa\.syn@corp-synth\.sa/.test(document.getElementById('pm-t').textContent) && !/alice/.test(document.getElementById('pm-t').textContent)), 'right filter');
    // Distribution lists
    await p.click('[data-tab="dl"]'); ok(await wait(p, () => /All staff/.test(document.getElementById('dl-t').textContent)), 'lists');
    await p.click('[data-lv="external"]'); ok(await wait(p, () => /External auditor/.test(document.getElementById('dl-t').textContent) && !/Empty list/.test(document.getElementById('dl-t').textContent)), 'lists with external members');
    await p.click('[data-lv="empty"]'); ok(await wait(p, () => /Empty list/.test(document.getElementById('dl-t').textContent)), 'empty lists');
    // Traffic
    await p.click('[data-tab="tr"]'); ok(await wait(p, () => /Failed\s*40/.test(document.getElementById('tr-k').textContent)), 'traffic tiles');
    ok(/Internal\s*1,400/.test(await txt(p, '#tr-k')), 'internal split with our domains (prefilled from the mailboxes)');
    ok(/5\.1\.1/.test(await txt(p, '#tr-why')) && /alice\.syn@corp-synth\.sa/.test(await txt(p, '#tr-snd')), 'reasons and top senders');
    await p.fill('#tr-pd', 'audit-synth.example'); await p.click('#tr-go');
    ok(await wait(p, () => /audit-synth\.example\s*30 \/ 44/.test(document.getElementById('tr-k').textContent)), 'traffic with one domain');
    ok(CALLS.some((c) => c.tag === 'tr_domain' && c.p.pd.value === 'audit-synth.example'), 'the domain reaches the SIEM as a parameter');
    // OWA & ActiveSync
    await p.click('[data-tab="cl"]'); ok(await wait(p, () => /Failed logons\s*12/.test(document.getElementById('cl-k').textContent)), 'OWA / ActiveSync tiles');
    ok(await wait(p, () => /203\.0\.113\.9/.test(document.getElementById('cl-fail').textContent)), 'failed logons per account and address');
    await p.click('[data-dv="stale"]'); ok(await wait(p, () => /bob syn/.test(document.getElementById('dv-t').textContent) && !/alice syn/.test(document.getElementById('dv-t').textContent)), 'stale devices');
    // Online
    await p.click('[data-tab="on"]'); ok(await wait(p, () => /Mailboxes\s*2/.test(document.getElementById('on-k').textContent)), 'Exchange Online tiles');
    await p.click('[data-ov="inactive"]'); ok(await wait(p, () => /old\.syn/.test(document.getElementById('on-t').textContent) && !/eva\.syn/.test(document.getElementById('on-t').textContent)), 'Exchange Online inactive');
    // settings + Collect now
    await p.click('#set summary'); await p.fill('#setf [name=approved_models]', 'iPhone'); await p.click('#setf button[type=submit]');
    ok(await wait(p, () => /Settings saved/.test(document.body.textContent)), 'settings saved');
    ok(E.audits.some((x) => x.a === 'exchange.reports.settings' && x.d.changed.includes('approved_models')), 'settings audited');
    await p.click('[data-tab="cl"]'); await p.click('[data-dv="unapproved"]');
    ok(await wait(p, () => /SM-X900/.test(document.getElementById('dv-t').textContent)), 'unapproved models after the approved list is set');
    await p.click('#collect'); ok(await wait(p, () => /Reading the Exchange organisation/.test(document.body.textContent)), 'Collect now');
    ok(E.audits.some((x) => x.a === 'exchange.reports.collect'), 'Collect now audited');
    await E.X.idle();
    // viewer: counts only, nobody named
    ROLE = 'viewer'; const q = await ctx.newPage(); q.on('pageerror', (e) => errs.push(e.message)); await q.goto(url);
    ok(await wait(q, () => /Mailboxes\s*6/.test(document.getElementById('mb-k').textContent)), 'viewer: counts');
    ok(/administrators only/.test(await q.textContent('#mb-t')) && await q.isHidden('#collect') && await q.isHidden('#set'), 'viewer: no mailbox list, no Collect now, no settings');
    for (const t of ['pm', 'dl', 'tr', 'cl', 'on']) { await q.click(`[data-tab="${t}"]`); await q.waitForTimeout(400); }
    const body = await q.textContent('main');
    ok(!/alice|bob\.syn|CORP\\|carol|audit-synth|eva\.syn/.test(body), 'viewer: no name anywhere (PDPL)');
    // not connected
    ROLE = 'admin'; E = await engine(false); const r = await ctx.newPage(); r.on('pageerror', (e) => errs.push(e.message)); await r.goto(url);
    ok(await wait(r, () => /No Exchange server with a login/.test(document.getElementById('nc').textContent)), 'not connected says what to add');
    ok(/not read yet|Not connected/.test(await r.textContent('#mb-k')) && await r.isHidden('#collect'), 'nothing invented, no Collect now');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
