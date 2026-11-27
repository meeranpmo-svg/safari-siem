// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PAM Center (engine/pam-center.js), SYNTHETIC directory accounts and passwords: privileged accounts with their risk and every point
// named (standing privilege, dormant, never used, shared name, everyday account with admin rights); the safe: an administrator adds
// an entry (sealed, the value never stored in clear, never in the view or the audit), an operator requests a checkout, the requester
// cannot approve, an AI never approves, another administrator approves; only the requester reveals, inside the window, at most 3
// times; check-in marks the entry for rotation; the owner records a new password (the same one refused); maturity and insights;
// roles and validation; audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path');
const { startApp } = require('./helpers');

const ADM = { user: 'admin.syn', role: 'admin' }, ADM2 = { user: 'admin2.syn', role: 'admin' }, OP = { user: 'net.syn', role: 'operator' }, OWN = { user: 'owner.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:engineer', role: 'admin' };
const SECRET = 'Synthetic-BreakGlass-9!x', SECRET2 = 'Synthetic-Rotated-7#q';
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true, copilotAiOff: true });
  const day = (n) => new Date(Date.now() - n * 864e5).toISOString();
  e.app.store.collection('ad_directory').put({ id: 'last', at: day(0), by: 'admin.syn', users: [
    { sam: 'administrator', display_name: 'Built-in', enabled: true, last_logon: day(2), admin_count: 1 },
    { sam: 'a.harbi', display_name: 'Ali (synthetic)', enabled: true, last_logon: day(1), admin_count: 1 },
    { sam: 's.qahtani-adm', display_name: 'Sara admin (synthetic)', enabled: true, last_logon: day(200), admin_count: 1 },
    { sam: 'old.contractor-adm', display_name: 'Old (synthetic)', enabled: true, last_logon: null, admin_count: 1 },
    { sam: 'm.shehri', display_name: 'Not privileged (synthetic)', enabled: true, last_logon: day(1), admin_count: 0 }] });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}

test('PAM Center: privileged accounts and risk, the safe with four-eyes checkout, reveal, check-in, rotation, maturity, roles, audit', async (t) => {
  const { e, call } = await setup(t);
  assert.equal((await call('GET', '/pam-center', undefined, VIEW)).status, 403, 'it names privileged accounts');
  let v = (await call('GET', '/pam-center', undefined, OP)).json;
  const id = (n) => v.identities.find((x) => x.name === n);
  assert.equal(v.kpis.privileged, 4, 'admin_count accounts only'); assert.ok(!id('m.shehri'));
  assert.ok(id('administrator').reasons.some((r) => /shared or built-in/.test(r.why)) && id('administrator').reasons.some((r) => /standing/.test(r.why)));
  assert.ok(id('a.harbi').reasons.some((r) => /everyday account/.test(r.why)), 'a person\'s everyday account with admin rights');
  assert.ok(!id('s.qahtani-adm').reasons.some((r) => /everyday/.test(r.why)) && id('s.qahtani-adm').reasons.some((r) => /not signed in for 200 days/.test(r.why)));
  assert.ok(id('old.contractor-adm').reasons.some((r) => /never signed in/.test(r.why)));
  assert.ok(v.insights.some((i) => /hold admin rights all the time/.test(i.title)) && v.insights.some((i) => /dormant or never used/.test(i.title)));
  assert.ok(v.maturity !== null && v.parts.find((p) => p.name === 'Standing privilege').score === 0);
  // the safe
  const E = { system: 'Riyadh DC (synthetic)', account: 'BG-DomainAdmin', kind: 'break-glass', owner: 'owner.syn', rotate_days: 90, max_hours: 4, secret: SECRET };
  assert.equal((await call('POST', '/pam-center/safe', E, OP)).status, 403); assert.equal((await call('POST', '/pam-center/safe', E, BOT)).status, 403, 'never an AI');
  let r = await call('POST', '/pam-center/safe', Object.assign({}, E, { kind: 'castle' }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /kind/);
  r = await call('POST', '/pam-center/safe', Object.assign({}, E, { secret: 'short' }), ADM); assert.equal(r.status, 400); assert.match(r.json.error, /secret/);
  r = await call('POST', '/pam-center/safe', E, ADM); assert.equal(r.status, 200, r.text); const PS = r.json.id;
  assert.equal((await call('POST', '/pam-center/safe', E, ADM)).status, 409, 'once per system / account');
  const raw = JSON.stringify(e.app.store.collection('pamc_safe').all()); assert.ok(!raw.includes(SECRET), 'sealed at rest');
  v = (await call('GET', '/pam-center', undefined, ADM)).json; assert.ok(!JSON.stringify(v).includes(SECRET), 'never in the view'); assert.equal(v.safe[0].sealed, true);
  // checkout: request, four-eyes, reveal by the requester only
  r = await call('POST', '/pam-center/checkouts', { entry: PS, hours: 8, reason: 'patch the domain controllers (synthetic)' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /at most 4/);
  r = await call('POST', '/pam-center/checkouts', { entry: PS, hours: 2, reason: 'short' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason/);
  r = await call('POST', '/pam-center/checkouts', { entry: PS, hours: 2, reason: 'patch the domain controllers (synthetic)', ticket: 'CHG-1001' }, OP); assert.equal(r.status, 200, r.text); const PC = r.json.id;
  assert.equal((await call('POST', '/pam-center/checkouts', { entry: PS, hours: 2, reason: 'patch the domain controllers again (synthetic)' }, OP)).status, 409, 'one open request per person and account');
  assert.equal((await call('POST', '/pam-center/checkouts/' + PC + '/reveal', {}, OP)).status, 409, 'not before approval');
  assert.equal((await call('POST', '/pam-center/checkouts/' + PC + '/decide', { decision: 'approve' }, OP)).status, 403, 'an operator does not approve');
  r = await call('POST', '/pam-center/checkouts/' + PC + '/decide', { decision: 'approve' }, { user: 'net.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await call('POST', '/pam-center/checkouts/' + PC + '/decide', { decision: 'approve' }, BOT)).status, 403);
  assert.equal((await call('POST', '/pam-center/checkouts/' + PC + '/decide', { decision: 'reject' }, ADM2)).status, 400, 'a rejection says why');
  r = await call('POST', '/pam-center/checkouts/' + PC + '/decide', { decision: 'approve' }, ADM2); assert.equal(r.status, 200, r.text); assert.equal(r.json.state, 'approved');
  assert.equal((await call('POST', '/pam-center/checkouts/' + PC + '/reveal', {}, ADM2)).status, 403, 'not even the approver reveals');
  r = await call('POST', '/pam-center/checkouts/' + PC + '/reveal', {}, OP); assert.equal(r.status, 200, r.text); assert.equal(r.json.secret, SECRET);
  await call('POST', '/pam-center/checkouts/' + PC + '/reveal', {}, OP); await call('POST', '/pam-center/checkouts/' + PC + '/reveal', {}, OP);
  assert.equal((await call('POST', '/pam-center/checkouts/' + PC + '/reveal', {}, OP)).status, 429, 'at most 3 reveals');
  assert.equal((await call('POST', '/pam-center/safe/' + PS + '/rotate', { secret: SECRET2 }, OWN)).status, 409, 'not while checked out');
  r = await call('POST', '/pam-center/checkouts/' + PC + '/checkin', { note: 'done (synthetic)' }, OP); assert.equal(r.status, 200, r.text);
  v = (await call('GET', '/pam-center', undefined, ADM)).json; assert.equal(v.safe[0].overdue, true, 'used: marked for rotation'); assert.ok(v.insights.some((i) => /due for rotation/.test(i.title)));
  // rotation by the owner
  assert.equal((await call('POST', '/pam-center/safe/' + PS + '/rotate', { secret: SECRET2 }, OP)).status, 403, 'not the owner');
  r = await call('POST', '/pam-center/safe/' + PS + '/rotate', { secret: SECRET }, OWN); assert.equal(r.status, 400); assert.match(r.json.error, /same password/);
  r = await call('POST', '/pam-center/safe/' + PS + '/rotate', { secret: SECRET2 }, OWN); assert.equal(r.status, 200, r.text);
  v = (await call('GET', '/pam-center', undefined, ADM)).json; assert.equal(v.safe[0].overdue, false);
  // audit: every step, never a value
  const au = e.app.store.auditTail(200).filter((x) => /^pamc\./.test(x.action)), acts = au.map((x) => x.action);
  for (const a of ['pamc.safe.add', 'pamc.checkout.request', 'pamc.checkout.approve', 'pamc.checkout.reveal', 'pamc.checkout.checkin', 'pamc.safe.rotate']) assert.ok(acts.includes(a), a);
  assert.ok(!JSON.stringify(au).includes(SECRET) && !JSON.stringify(au).includes(SECRET2), 'no password in the audit');
  // nothing in clear in the data directory
  const dir = e.dir || (e.app.config && e.app.config.data_dir);
  if (dir && fs.existsSync(dir)) { const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((x) => x.isDirectory() ? walk(path.join(d, x.name)) : [path.join(d, x.name)]);
    for (const f of walk(dir)) { const s = fs.readFileSync(f, 'latin1'); assert.ok(!s.includes(SECRET2) && !s.includes(SECRET), 'clear text found in ' + f); } }
});

test('PAM Center ML: a week of checkouts far above the entry\'s own usual weeks is flagged; with no history it is learning', async (t) => {
  const { e, call } = await setup(t);
  const id = (await call('POST', '/pam-center/safe', { system: 'FW-SYN', account: 'admin', kind: 'network-admin', owner: 'owner.syn', secret: 'Synthetic-Fw-Admin-1!' }, ADM)).json.id;
  let v = (await call('GET', '/pam-center', undefined, ADM)).json; assert.equal(v.safe[0].learning, true, 'no history: learning, never normal');
  const C = e.app.store.collection('pamc_checkouts'); let n = 1; const at = (d) => new Date(Date.now() - d * 864e5).toISOString();
  for (let w = 11; w >= 1; w--) C.put({ id: 'PC-' + String(n++).padStart(4, '0'), entry: id, requester: 'net.syn', hours: 1, reason: 'weekly check (synthetic)', state: 'approved', at: at(w * 7 + 1), until: at(w * 7), checked_in_at: at(w * 7) });
  for (let i = 0; i < 6; i++) C.put({ id: 'PC-' + String(n++).padStart(4, '0'), entry: id, requester: 'net.syn', hours: 1, reason: 'many this week (synthetic)', state: 'approved', at: at(0.5 + i * 0.5), until: at(0.4 + i * 0.5), checked_in_at: at(0.4 + i * 0.5) });
  v = (await call('GET', '/pam-center', undefined, ADM)).json; const s = v.safe[0];
  assert.equal(s.learning, false); assert.ok(s.reasons.some((r) => /far above its usual 1 a week/.test(r.why)), JSON.stringify(s.reasons)); assert.ok(v.insights.some((i) => /Unusual use of FW-SYN/.test(i.title)));
});
