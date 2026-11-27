// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Microsoft 365 Licences & Security (engine/m365-licence-intel.js) over a SYNTHETIC tenant (the HR Onboarding connection faked):
// read-only refresh by a person (operator), refused for a viewer and an AI identity; licences with bought / assigned / free /
// expiring seats; waste: disabled, inactive, never used, overlap (a subset licence), right-size (desktop Office unused); the money
// from the prices entered; the forecast and an unusual jump from the daily history; the security the licences buy (Entra ID P1 ...)
// with the people without P1; a viewer sees figures and no names; settings admin-only, validated (400 naming the field), audited;
// not connected: says what to set; the background tick skips without a connection.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createM365LicenceIntel, registerM365LicenceIntel } = require('../engine/m365-licence-intel');

const ADM = { user: 'admin.syn', role: 'admin' }, OP = { user: 'op.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:engineer', role: 'operator' };
const P = (id, name) => ({ id, name });
const E3 = { sku_id: 'sku-e3', part: 'SPE_E3', enabled: 10, consumed: 8, free: 2, warning: 2, suspended: 0, plans: [P('p-ex', 'EXCHANGE_S_ENTERPRISE'), P('p-off', 'OFFICESUBSCRIPTION'), P('p-aad', 'AAD_PREMIUM'), P('p-int', 'INTUNE_A')] };
const EXO = { sku_id: 'sku-exo', part: 'EXCHANGEENTERPRISE', enabled: 5, consumed: 3, free: 2, warning: 0, suspended: 0, plans: [P('p-ex', 'EXCHANGE_S_ENTERPRISE')] };
const MDO = { sku_id: 'sku-mdo', part: 'ATP_ENTERPRISE', enabled: 3, consumed: 2, free: 1, plans: [P('p-atp', 'ATP_ENTERPRISE')] };
const FREEBI = { sku_id: 'sku-bi', part: 'POWER_BI_STANDARD', enabled: 1000000, consumed: 4, free: 999996, plans: [P('p-bi', 'BI_AZURE_P0')] };
const L = (...ids) => ids.map((skuId) => ({ skuId, disabledPlans: [] }));
const day = (d) => new Date(Date.now() - d * 86400000).toISOString().slice(0, 10);
const USERS = [
  { userPrincipalName: 'a.syn@corp.test', displayName: 'A Syn', accountEnabled: true, assignedLicenses: L('sku-e3', 'sku-mdo') },
  { userPrincipalName: 'b.syn@corp.test', displayName: 'B Syn', accountEnabled: false, assignedLicenses: L('sku-e3') },
  { userPrincipalName: 'c.syn@corp.test', displayName: 'C Syn', accountEnabled: true, assignedLicenses: L('sku-e3') },
  { userPrincipalName: 'd.syn@corp.test', displayName: 'D Syn', accountEnabled: true, assignedLicenses: L('sku-e3', 'sku-exo') },
  { userPrincipalName: 'e.syn@corp.test', displayName: 'E Syn', accountEnabled: true, assignedLicenses: L('sku-e3') },
  { userPrincipalName: 'f.syn@corp.test', displayName: 'F Syn', accountEnabled: true, assignedLicenses: L('sku-exo', 'sku-bi') },
  { userPrincipalName: 'g.syn@corp.test', displayName: 'Nobody Licensed', accountEnabled: true, assignedLicenses: [] }];
const ACT = [{ userPrincipalName: 'a.syn@corp.test', exchangeLastActivityDate: day(1) }, { userPrincipalName: 'c.syn@corp.test', exchangeLastActivityDate: day(200) },
  { userPrincipalName: 'd.syn@corp.test', teamsLastActivityDate: day(2) }, { userPrincipalName: 'e.syn@corp.test' }, { userPrincipalName: 'f.syn@corp.test', exchangeLastActivityDate: day(3) }];
const APPS = [{ userPrincipalName: 'a.syn@corp.test', details: [{ windows: true, web: true }] }, { userPrincipalName: 'd.syn@corp.test', details: [{ windows: false, mac: false, web: true, mobile: true }] }];
function fakeSource(state) { return () => ({ connected: () => state.connected, userApps: async () => { state.reads++; return { skus: [E3, EXO, MDO, FREEBI], users: USERS, act: ACT, apps: APPS, errors: [] }; } }); }

async function setup(t, connected = true) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const state = { connected, reads: 0 }, X = createM365LicenceIntel(e.app, { source: fakeSource(state) });
  registerM365LicenceIntel(e.app.srv, e.app, X, { noTimer: true });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, X, state, call };
}

test('M365 licences: not connected says what to set; the tick skips; refresh is refused with the reason', async (t) => {
  const { call, X, state } = await setup(t, false);
  const v = (await call('GET', '/m365-licences', undefined, VIEW)).json;
  assert.equal(v.connected, false); assert.match(v.note, /HR Onboarding -> Microsoft 365/); assert.match(v.note, /Reports\.Read\.All/);
  await X.tick(); assert.equal(state.reads, 0, 'no read without a connection');
  const r = await call('POST', '/m365-licences/refresh', {}, OP); assert.equal(r.status, 409); assert.match(r.json.error, /not connected/);
});

test('M365 licences: refresh roles, licences, waste with reasons, money, security coverage, viewer without names, audit', async (t) => {
  const { e, call, state } = await setup(t);
  assert.equal((await call('POST', '/m365-licences/refresh', {}, VIEW)).status, 403, 'viewer refused');
  assert.equal((await call('POST', '/m365-licences/refresh', {}, BOT)).status, 403, 'an AI identity does not refresh');
  const r = await call('POST', '/m365-licences/refresh', {}, OP); assert.equal(r.status, 200, r.text); assert.equal(state.reads, 1);
  const v = r.json;
  const e3 = v.licences.find((l) => l.part === 'SPE_E3');
  assert.equal(e3.name, 'Microsoft 365 E3'); assert.equal(e3.bought, 10); assert.equal(e3.assigned, 8); assert.equal(e3.free, 2); assert.equal(e3.expiring, 2); assert.equal(e3.util, 80);
  assert.equal(v.totals.bought, 18, 'free subscriptions are not counted'); assert.equal(v.totals.assigned, 13);
  const why = (upn, part) => (v.waste.items.find((w) => w.upn === upn && w.part === part) || {}).reason;
  assert.equal(why('b.syn@corp.test', 'SPE_E3'), 'disabled');
  assert.equal(why('c.syn@corp.test', 'SPE_E3'), 'inactive');
  assert.equal(why('e.syn@corp.test', 'SPE_E3'), 'never-used');
  assert.equal(why('d.syn@corp.test', 'EXCHANGEENTERPRISE'), 'overlap', 'Exchange Plan 2 is inside E3');
  assert.equal(why('d.syn@corp.test', 'SPE_E3'), 'right-size', 'desktop Office unused');
  assert.equal(why('a.syn@corp.test', 'SPE_E3'), undefined, 'an active desktop user is fine');
  assert.ok(!v.waste.items.some((w) => w.part === 'POWER_BI_STANDARD'), 'a free licence is never waste');
  assert.equal(v.waste.monthly, null, 'no prices: counts only');
  // security coverage among enabled people with a paid licence (a, c, d, e, f)
  const sec = (k) => v.security.find((x) => x.key === k);
  assert.equal(v.people, 5); assert.equal(sec('p1').covered, 4); assert.equal(sec('p1').pct, 80); assert.equal(sec('mdo1').covered, 1);
  assert.equal(sec('p2').licensed_in_tenant, false);
  assert.deepEqual(v.no_p1.map((x) => x.upn), ['f.syn@corp.test']);
  const N = v.noticed.map((x) => x.text).join(' | ');
  assert.match(N, /1 paid licences sit on disabled accounts/); assert.match(N, /1 licensed people have no Entra ID P1/); assert.match(N, /2 seats are in the expiry warning/);
  // a viewer: figures, no names
  const vv = (await call('GET', '/m365-licences', undefined, VIEW)).json;
  assert.equal(vv.waste.items.length, 0); assert.equal(vv.no_p1.length, 0); assert.equal(vv.waste.by_reason.disabled, 1); assert.ok(!JSON.stringify(vv).includes('corp.test'), 'no user principal name for a viewer');
  const au = e.app.store.auditTail(50).filter((x) => x.action === 'm365lic.refresh');
  assert.equal(au.length, 1); assert.equal(au[0].by, 'op.syn'); assert.ok(!JSON.stringify(au).includes('corp.test'), 'no names in the audit');
});

test('M365 licences: settings admin-only and validated; prices turn waste into money; audited', async (t) => {
  const { e, call } = await setup(t);
  await call('POST', '/m365-licences/refresh', {}, OP);
  assert.equal((await call('PUT', '/m365-licences/settings', { inactive_days: 60 }, OP)).status, 403);
  let r = await call('PUT', '/m365-licences/settings', { inactive_days: 5 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /inactive_days/);
  r = await call('PUT', '/m365-licences/settings', { currency: 'riyal' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /currency/);
  r = await call('PUT', '/m365-licences/settings', { prices: { SPE_E3: -1 } }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /prices\.SPE_E3/);
  r = await call('PUT', '/m365-licences/settings', { prices: { 'bad key!': 3 } }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^prices\./);
  r = await call('PUT', '/m365-licences/settings', { inactive_days: 60, currency: 'SAR', prices: { SPE_E3: 135, EXCHANGEENTERPRISE: 30 }, extra: 'dropped' }, ADM);
  assert.equal(r.status, 200, r.text); assert.equal(r.json.settings.inactive_days, 60); assert.equal(r.json.settings.extra, undefined);
  // 4 E3 flagged (disabled, inactive, never used, right-size) x 135 + 1 Exchange overlap x 30
  assert.equal(r.json.waste.monthly, 570); assert.match(r.json.noticed.map((x) => x.text).join(' '), /about 570 SAR a month \(6,840 a year\)/);
  const au = e.app.store.auditTail(50).filter((x) => x.action === 'm365lic.settings');
  assert.equal(au.length, 1); assert.equal(au[0].by, 'admin.syn'); assert.equal(au[0].detail.prices, 2);
  assert.equal((await call('GET', '/m365-licences', undefined, OP)).json.settings.prices, undefined, 'prices are shown to administrators');
});

test('M365 licences: ML - forecast to full and an unusual jump from the daily history', async (t) => {
  const { e, call } = await setup(t);
  const D = e.app.store.collection('m365lic_daily');
  // E3 assignments growing 0.1 a day over 20 days up to 7 yesterday, flat Exchange at 1 then a jump to 3 today
  for (let i = 20; i >= 1; i--) D.put({ id: day(i), skus: { SPE_E3: { enabled: 10, consumed: 7 - i * 0.05 }, EXCHANGEENTERPRISE: { enabled: 5, consumed: 1 }, ATP_ENTERPRISE: { enabled: 3, consumed: 2 } } });
  const v = (await call('POST', '/m365-licences/refresh', {}, OP)).json;
  const e3 = v.licences.find((l) => l.part === 'SPE_E3');
  assert.ok(e3.days_to_full > 0 && e3.days_to_full < 400, 'forecast days: ' + e3.days_to_full);
  const exo = v.licences.find((l) => l.part === 'EXCHANGEENTERPRISE');
  assert.equal(exo.jump, null, 'a jump of 2 seats is too small to flag');
  const mdo = v.licences.find((l) => l.part === 'ATP_ENTERPRISE'); assert.equal(mdo.days_to_full, null, 'flat: no forecast');
  for (let i = 30; i >= 1; i--) D.put({ id: day(i), skus: { SPE_E3: { enabled: 100, consumed: 20 + (i % 2) } } });
  const big = createM365LicenceIntel(e.app, { source: () => ({ connected: () => true, userApps: async () => ({ skus: [Object.assign({}, E3, { enabled: 100, consumed: 60 })], users: [], act: [], apps: [], errors: [] }) }) });
  await big.refresh(OP); const j = big.view('operator').licences[0].jump;
  assert.ok(j && j.to === 60 && j.z >= 3, 'an unusual jump is flagged: ' + JSON.stringify(j));
});
