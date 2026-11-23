// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Renewal Autopilot (engine/renewals.js) through the real routes over a SYNTHETIC register and a fake RDAP service: the registry is
// read (GET, https, from the IANA bootstrap; a ccTLD without RDAP said, a 404 said); a later registry expiry corrects the register;
// a domain inside the lead time opens a task by itself; request -> approve (an admin, not the requester) -> renewed (new expiry,
// evidence) -> verified BY THE REGISTRY when RDAP shows the new date; hosting verified by a second admin with evidence; hijack signs
// (lock removed, registrar changed, expiry earlier); risk with every point named; lead time learned from completed renewals;
// 12-month cost forecast; viewers see no costs or people; validation names the field; AI identity refused; signals for
// Notification & Escalation; every step audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createRenewals, registerRenewals, parseRdap } = require('../engine/renewals');

const DAY = 86400000;
let NOW = Date.parse('2026-11-04T08:00:00Z');
const ADM = { user: 'syed.syn', role: 'admin' }, ADM2 = { user: 'fatima.syn', role: 'admin' }, OP = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:renewals', role: 'admin' };
const rdapDoc = (name, expires, o = {}) => ({ objectClassName: 'domain', ldhName: name, status: o.status || ['client transfer prohibited', 'active'],
  events: [{ eventAction: 'registration', eventDate: '2015-03-01T00:00:00Z' }, { eventAction: 'expiration', eventDate: expires + 'T00:00:00Z' }, { eventAction: 'last changed', eventDate: '2026-01-01T00:00:00Z' }],
  entities: [{ roles: ['registrar'], handle: '9999', vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', o.registrar || 'Synthetic Registrar LLC']]] }], nameservers: [{ ldhName: 'NS1.SYN-DNS.TEST' }] });

async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const REG = { 'corp2-syn.com': rdapDoc('corp2-syn.com', '2026-11-20'), 'brand-syn.net': rdapDoc('brand-syn.net', '2027-09-01') }, calls = [];
  const fetch = async (url) => { calls.push(url); assert.match(url, /^https:\/\//, 'https only');
    if (url === 'https://data.iana.org/rdap/dns.json') return { status: 200, json: { services: [[['com', 'net'], ['https://rdap.syn.test/']], [['org'], ['http://insecure.test/']]] } };
    const m = /^https:\/\/rdap\.syn\.test\/domain\/(.+)$/.exec(url); if (!m) return { status: 500, json: null };
    const d = REG[decodeURIComponent(m[1])]; return d ? { status: 200, json: d } : { status: 404, json: { errorCode: 404 } }; };
  const X = createRenewals(e.app, { fetch, now: () => NOW, noTimer: true }); e.app.addons.renewals = X; registerRenewals(e.app.srv, e.app, X);
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who = OP) => call('POST', p, b, who), get = (p, who = OP) => call('GET', p, undefined, who);
  for (const d of [{ name: 'corp2-syn.com', registrar: '', expires: '2026-11-20', auto_renew: false, cost: 60, owner: 'it.syn' }, { name: 'brand-syn.net', registrar: 'Synthetic Registrar LLC', expires: '2027-06-01', auto_renew: true, cost: 45 }, { name: 'example-syn.sa', expires: '2027-02-01', cost: 100 }, { name: 'gone-syn.com', expires: '2027-03-01' }])
    assert.equal((await post('/domains', d, ADM)).status, 200);
  return { e, X, REG, calls, post, get, audit: (a) => e.app.store.auditTail(500).filter((x) => x.action === 'renewals.' + a) };
}

test('parseRdap: expiry, registrar, lock, nameservers', () => {
  const p = parseRdap(rdapDoc('x.com', '2027-01-02', { status: ['active'] }));
  assert.deepEqual([p.expires, p.registered, p.registrar, p.locked, p.ns[0]], ['2027-01-02', '2015-03-01', 'Synthetic Registrar LLC', false, 'ns1.syn-dns.test']);
  assert.equal(parseRdap(rdapDoc('x.com', '2027-01-02')).locked, true);
});

test('registry read, register corrected, task opened, four-eyes, verified by the registry', async (t) => {
  const s = await setup(t);
  assert.equal((await s.post('/renewals/rdap', {}, VIEW)).status, 403, 'viewer cannot read the registry');
  let r = await s.post('/renewals/rdap', {}); assert.equal(r.status, 200, r.text); assert.equal(r.json.read, 4); assert.equal(r.json.ok, 2);
  assert.ok(r.json.failed.some((f) => f.domain === 'example-syn.sa' && /publishes no RDAP/.test(f.error)), '.sa has no RDAP - said');
  assert.ok(r.json.failed.some((f) => f.domain === 'gone-syn.com' && /no record of gone-syn\.com/.test(f.error)), 'a 404 said');
  assert.ok(s.calls.every((u) => u.startsWith('https://')), 'only https GETs');
  let v = (await s.get('/renewals')).json;
  const br = v.items.find((x) => x.name === 'brand-syn.net'); assert.equal(br.expires, '2027-09-01', 'a later registry expiry corrected the register (renewed at the registrar)');
  assert.ok(s.audit('expiry.sync').some((a) => a.detail.domain === 'brand-syn.net' && a.detail.to === '2027-09-01'));
  const ar = v.items.find((x) => x.name === 'corp2-syn.com'); assert.equal(ar.days_left, 15); assert.equal(ar.registry.registrar, 'Synthetic Registrar LLC'); assert.equal(ar.registry.locked, true);
  assert.ok(ar.task && ar.task.state === 'open', 'a task opened by itself inside the lead time');
  assert.equal(ar.score, ar.why.reduce((a, w) => a + w.points, 0)); assert.ok(ar.why.some((w) => /expires in 15 days/.test(w.text)) && ar.why.some((w) => /auto-renew is off/.test(w.text)));
  assert.equal(v.lead.used, 60); assert.match(v.lead.basis, /needs 3 completed renewals/);
  const id = ar.task.id;
  // the people steps
  assert.match((await s.post('/renewals/tasks/' + id + '/advance', { to: 'approved', note: 'skip ahead' }, ADM)).text, /can go to requested or cancelled/);
  assert.equal((await s.post('/renewals/tasks/' + id + '/advance', { to: 'requested', note: 'renew for 2 years' }, BOT)).status, 403, 'an AI identity never moves a task');
  assert.match((await s.post('/renewals/tasks/' + id + '/advance', { to: 'requested' }, ADM)).text, /note is required/);
  assert.equal((await s.post('/renewals/tasks/' + id + '/advance', { to: 'requested', note: 'renew for 2 years (synthetic)' }, ADM)).status, 200);
  assert.equal((await s.post('/renewals/tasks/' + id + '/advance', { to: 'approved', note: 'looks fine' }, OP)).status, 403, 'approval needs an administrator');
  assert.match((await s.post('/renewals/tasks/' + id + '/advance', { to: 'approved', note: 'looks fine' }, ADM)).text, /four eyes/);
  assert.equal((await s.post('/renewals/tasks/' + id + '/advance', { to: 'approved', note: 'budget ok (synthetic)' }, ADM2)).status, 200);
  assert.match((await s.post('/renewals/tasks/' + id + '/advance', { to: 'renewed', note: 'done', evidence: 'INV-1' })).text, /new_expiry: the expiry date/);
  assert.match((await s.post('/renewals/tasks/' + id + '/advance', { to: 'renewed', note: 'done', new_expiry: '2026-11-01', evidence: 'INV-1' })).text, /not after the current expiry/);
  assert.match((await s.post('/renewals/tasks/' + id + '/advance', { to: 'renewed', note: 'done', new_expiry: '2028-11-20' })).text, /evidence: the order/);
  assert.equal((await s.post('/renewals/tasks/' + id + '/advance', { to: 'renewed', note: 'paid at the registrar (synthetic)', new_expiry: '2028-11-20', cost: 75, evidence: 'ORDER-SYN-1' })).status, 200);
  assert.match((await s.post('/renewals/tasks/' + id + '/advance', { to: 'verified', note: 'looks fine', evidence: 'portal' }, ADM2)).text, /verified by the registry \(RDAP\) automatically/, 'a domain is not verified by hand while the registry is readable');
  v = (await s.get('/renewals')).json; assert.ok(v.actions.some((a) => a.filter === 'unverified'), 'renewed but not yet confirmed by the registry');
  // the registry moves: verified by RDAP
  s.REG['corp2-syn.com'] = rdapDoc('corp2-syn.com', '2028-11-20');
  await s.post('/renewals/rdap', { domain: 'corp2-syn.com' });
  v = (await s.get('/renewals')).json; const done = v.tasks.find((x) => x.id === id);
  assert.equal(done.state, 'verified'); assert.equal(done.verified_by, 'registry (RDAP)'); assert.equal(v.items.find((x) => x.name === 'corp2-syn.com').expires, '2028-11-20');
  for (const a of ['task.open', 'task.requested', 'task.approved', 'task.renewed', 'task.verified', 'rdap.read']) assert.ok(s.audit(a).length, a + ' audited');
});

test('hijack signs, hosting verified by a second admin, risk, forecast, viewers, signals, learned lead time', async (t) => {
  const s = await setup(t);
  await s.post('/renewals/rdap', {});
  // the lock goes and the registrar changes on brand-syn.net
  s.REG['brand-syn.net'] = rdapDoc('brand-syn.net', '2027-09-01', { status: ['active'], registrar: 'Other Registrar Inc' });
  await s.post('/renewals/rdap', { domain: 'brand-syn.net' });
  let v = (await s.get('/renewals')).json;
  const br = v.items.find((x) => x.name === 'brand-syn.net');
  assert.ok(br.registry.changes.some((c) => /transfer lock was removed/.test(c.text)) && br.registry.changes.some((c) => /registrar changed from Synthetic Registrar LLC to Other Registrar Inc/.test(c.text)));
  assert.equal(v.actions[0].filter, 'hijack'); assert.ok(br.why.some((w) => /no transfer lock/.test(w.text)));
  const sig = s.X.signals(); assert.ok(sig.some((x) => x.fp === 'renewal:hijack:' + br.id && x.severity === 4));
  // hosting subscription
  assert.match((await s.post('/renewals/hosting', { provider: 'Synthetic Cloud', service: 'Web hosting' }, ADM)).text, /renews is required/);
  assert.equal((await s.post('/renewals/hosting', { provider: 'Synthetic Cloud', service: 'Web hosting', renews: '2026-12-01', owner: 'web.syn' }, OP)).status, 403);
  assert.match((await s.post('/renewals/hosting', { provider: 'Synthetic Cloud', service: 'Web hosting', renews: '2026-12-01', owner: 'web.syn', hosts: ['host_nope'] }, ADM)).text, /not a hostname in the register/);
  let r = await s.post('/renewals/hosting', { provider: 'Synthetic Cloud', service: 'Web hosting', plan: 'Business', renews: '2026-12-01', term_months: 12, cost: 1200, owner: 'web.syn' }, ADM); assert.equal(r.status, 200, r.text);
  v = (await s.get('/renewals')).json; const hs = v.items.find((x) => x.kind === 'hosting'); assert.ok(hs.task, 'hosting inside the lead time opens a task');
  const hid = hs.task.id;
  await s.post('/renewals/tasks/' + hid + '/advance', { to: 'requested', note: 'renew (synthetic)' }, OP);
  await s.post('/renewals/tasks/' + hid + '/advance', { to: 'approved', note: 'ok (synthetic)' }, ADM);
  await s.post('/renewals/tasks/' + hid + '/advance', { to: 'renewed', note: 'paid (synthetic)', new_expiry: '2027-12-01', cost: 1500, evidence: 'INV-SYN-9' }, ADM);
  assert.match((await s.post('/renewals/tasks/' + hid + '/advance', { to: 'verified', note: 'checked', evidence: 'portal' }, ADM)).text, /four eyes: the renewal is verified by someone other/);
  assert.match((await s.post('/renewals/tasks/' + hid + '/advance', { to: 'verified', note: 'checked' }, ADM2)).text, /evidence: what you checked/);
  assert.equal((await s.post('/renewals/tasks/' + hid + '/advance', { to: 'verified', note: 'checked in the provider portal (synthetic)', evidence: 'portal shows 2027-12-01' }, ADM2)).status, 200);
  v = (await s.get('/renewals')).json; assert.equal(v.items.find((x) => x.kind === 'hosting').expires, '2027-12-01', 'the register carries the new date');
  // forecast and viewer
  assert.equal(v.forecast.length, 12); assert.ok(v.forecast.some((m) => m.items > 0));
  const vv = (await s.get('/renewals', VIEW)).json; assert.equal(vv.named, false); assert.ok(vv.items.every((x) => x.cost === undefined && x.owner === undefined)); assert.ok(vv.forecast.every((m) => m.cost === undefined));
  assert.ok(!JSON.stringify(vv.tasks).includes('omar.syn') && !JSON.stringify(vv.tasks).includes('INV-SYN-9'), 'no people or evidence for a viewer');
  // settings: admin, a person, versioned
  assert.equal((await s.post('/renewals/settings', { lead_days: 90, version: 0 }, OP)).status, 403);
  assert.match((await s.post('/renewals/settings', { lead_days: 5, version: 0 }, ADM)).text, /lead_days/);
  assert.equal((await s.post('/renewals/settings', { lead_days: 90, version: 0 }, ADM)).status, 200);
  assert.equal((await s.post('/renewals/settings', { lead_days: 80, version: 0 }, ADM)).status, 409, 'a stale version is refused');
  // learned lead time: three completed renewals that took 40 days each
  const T = s.e.app.store.collection('ren_tasks');
  for (let i = 0; i < 3; i++) T.put({ id: 'RN-L' + i, item: 'domain:x' + i, kind: 'domain', name: 'x' + i, due: '2026-01-01', state: 'verified', opened_at: '2025-10-01T00:00:00Z', renewed_at: '2025-11-10T00:00:00Z', verified_at: '2025-11-12T00:00:00Z', history: [{ at: '2025-11-12T00:00:00Z', by: 'x', what: 'v' }] });
  v = (await s.get('/renewals')).json; assert.equal(v.lead.learned, 54); assert.equal(v.lead.used, 90, 'the larger of configured and learned');
});
