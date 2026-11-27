// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IP Address Management by site (engine/ipam-sites.js) over the subnet register (engine/ipam.js), SYNTHETIC sites and addresses:
// a head office registered with its block (overlap and outside-the-range refused), a new project site proposed by an operator with
// the next free block and the template laid out (gateway first, DHCP the second half), approved only by another administrator (never
// the proposer, never an AI) which creates the subnets; per-site utilisation and conflicts; insights (project site ending, site
// names in use but not registered, subnets outside the block); a template changed by an administrator (must fit); closing a site
// retires its subnets and keeps the block out of reuse; CSV plan; roles; validation; audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

const ADM = { user: 'admin.syn', role: 'admin' }, ADM2 = { user: 'admin2.syn', role: 'admin' }, OP = { user: 'net.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:network', role: 'admin' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true, copilotAiOff: true });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}
const day = (n) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);

test('sites: register, propose a project site, four-eyes approval creates the subnets, utilisation, insights, close, CSV, roles, audit', async (t) => {
  const { e, call } = await setup(t);
  let v = (await call('GET', '/ipam/sites', undefined, VIEW)).json; assert.equal(v.kpis.sites, 0); assert.equal(v.supernet, '10.0.0.0/8'); assert.ok(v.templates.project_site.length >= 5);
  // head office with its block; an existing subnet and assets at an unregistered site
  let r = await call('PUT', '/ipam/sites/riyadh-ho', { name: 'Riyadh Head Office', kind: 'head_office', city: 'Riyadh', block: '10.10.0.0/16' }, OP); assert.equal(r.status, 403, 'an operator does not edit the register');
  r = await call('PUT', '/ipam/sites/riyadh-ho', { name: 'Riyadh Head Office', kind: 'head_office', city: 'Riyadh', block: '10.10.0.0/16' }, BOT); assert.equal(r.status, 403, 'never an AI');
  r = await call('PUT', '/ipam/sites/riyadh-ho', { name: 'Riyadh Head Office', kind: 'head_office', city: 'Riyadh', block: '192.168.0.0/16' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /inside the organisation range/);
  r = await call('PUT', '/ipam/sites/riyadh-ho', { name: 'Riyadh Head Office', kind: 'castle', block: '10.10.0.0/16' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /kind/);
  r = await call('PUT', '/ipam/sites/riyadh-ho', { name: 'Riyadh Head Office', kind: 'head_office', city: 'Riyadh', block: '10.10.0.0/16' }, ADM); assert.equal(r.status, 200, r.text);
  assert.equal((await call('PUT', '/ipam/sites/riyadh-dup', { name: 'Riyadh 2', kind: 'office', city: 'Riyadh', block: '10.10.16.0/20' }, ADM)).status, 409, 'blocks never overlap');
  assert.equal((await call('POST', '/ipam/subnets', { cidr: '10.10.4.0/24', name: 'HQ users', site: 'Riyadh Head Office', vlan: 10, gateway: '10.10.4.1', dhcp_start: '10.10.4.100', dhcp_end: '10.10.4.250' }, OP)).status, 200);
  assert.equal((await call('POST', '/ipam/subnets', { cidr: '10.20.1.0/24', name: 'Jeddah users', site: 'Jeddah Branch' }, OP)).status, 200);
  for (let i = 0; i < 6; i++) e.app.assets.create({ name: 'PC-SYN-' + i, type: 'workstation', status: 'in_use', site: 'Riyadh Head Office', mgmt_ip: '10.10.4.' + (20 + i) }, ADM);
  e.app.assets.create({ name: 'PC-SYN-X', type: 'workstation', status: 'in_use', site: 'Riyadh Head Office', mgmt_ip: '10.10.4.20' }, ADM);   // a second asset on one address
  // propose a project site: the next free /20 that overlaps nothing, the template laid out
  r = await call('POST', '/ipam/sites/propose', { name: 'Jubail Project Site', kind: 'project_site', city: 'Jubail', contact: 'site.syn', ends: day(20) }, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/ipam/sites/propose', { name: 'Jubail Project Site', kind: 'project_site' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /city/);
  r = await call('POST', '/ipam/sites/propose', { name: 'Jubail Project Site', kind: 'project_site', city: 'Jubail', contact: 'site.syn', ends: day(20), extra: 1 }, OP); assert.equal(r.status, 200, r.text);
  const P = r.json; assert.equal(P.state, 'pending'); assert.match(P.block, /\/20$/); assert.notEqual(P.block, '10.10.0.0/20'); assert.ok(!P.block.startsWith('10.10.'), 'not inside the head office block: ' + P.block);
  const users = P.subnets.find((x) => x.name === 'Site users'); assert.match(users.cidr, /\/24$/); assert.ok(users.gateway.endsWith('.1') && users.dhcp_start.endsWith('.128') && users.dhcp_end.endsWith('.254'), JSON.stringify(users));
  assert.equal(P.subnets.find((x) => x.name === 'CCTV / NVR').dhcp_start, '', 'no DHCP for cameras');
  assert.equal((await call('POST', '/ipam/sites/propose', { name: 'jubail project site', kind: 'project_site', city: 'Jubail' }, OP)).status, 409, 'one proposal per site');
  const P2 = (await call('POST', '/ipam/sites/propose', { name: 'Yanbu Project Site', kind: 'project_site', city: 'Yanbu' }, OP)).json; assert.notEqual(P2.block, P.block, 'a pending block is not handed out twice');
  // four-eyes
  assert.equal((await call('POST', '/ipam/site-proposals/' + P.id + '/decide', { decision: 'approve' }, OP)).status, 403, 'an operator does not approve');
  r = await call('POST', '/ipam/site-proposals/' + P.id + '/decide', { decision: 'approve' }, { user: 'net.syn', role: 'admin' }); assert.equal(r.status, 403); assert.match(r.json.error, /four-eyes/);
  assert.equal((await call('POST', '/ipam/site-proposals/' + P.id + '/decide', { decision: 'approve' }, BOT)).status, 403);
  r = await call('POST', '/ipam/site-proposals/' + P.id + '/decide', { decision: 'approve', note: 'ok' }, ADM2); assert.equal(r.status, 200, r.text); assert.equal(r.json.state, 'applied'); assert.equal(r.json.subnets_changed, P.subnets.length);
  assert.equal((await call('POST', '/ipam/site-proposals/' + P.id + '/decide', { decision: 'approve' }, ADM2)).status, 409, 'decided once');
  r = await call('POST', '/ipam/site-proposals/' + P2.id + '/decide', { decision: 'reject', note: 'later' }, ADM2); assert.equal(r.json.state, 'rejected');
  // the view per site
  v = (await call('GET', '/ipam/sites', undefined, OP)).json;
  const HQ = v.sites.find((s) => s.id === 'riyadh-ho'), JB = v.sites.find((s) => s.name === 'Jubail Project Site');
  assert.equal(HQ.subnets, 1); assert.equal(HQ.used, 7, '6 addresses + the gateway'); assert.equal(HQ.pct, 3); assert.equal(JB.subnets, P.subnets.length); assert.equal(JB.status, 'active'); assert.equal(JB.approved_by, 'admin2.syn');
  assert.equal(v.kpis.sites, 2); assert.equal(v.kpis.project_sites, 1); assert.ok(v.missing.some((m) => m.name === 'Jeddah Branch'), 'a site in use but not registered');
  assert.ok(v.insights.some((i) => /end within 30 days/.test(i.title)) && v.insights.some((i) => /not in the site register/.test(i.title)), JSON.stringify(v.insights.map((i) => i.title)));
  // template: an administrator changes it, it must fit the block size
  r = await call('PUT', '/ipam/templates/project_site', { rows: [{ name: 'Users', vlan: 10, prefix: 20 }, { name: 'More', vlan: 11, prefix: 20 }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /do not fit/);
  r = await call('PUT', '/ipam/templates/project_site', { rows: [{ name: 'Users', vlan: 10, prefix: 23, dhcp: true }, { name: 'Users 2', vlan: 10, prefix: 24 }] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /each VLAN once/);
  r = await call('PUT', '/ipam/templates/project_site', { rows: [{ name: 'Users', vlan: 10, prefix: 23, dhcp: true }, { name: 'Cameras', vlan: 60, prefix: 25 }] }, OP); assert.equal(r.status, 403);
  r = await call('PUT', '/ipam/templates/project_site', { rows: [{ name: 'Users', vlan: 10, prefix: 23, dhcp: true }, { name: 'Cameras', vlan: 60, prefix: 25 }] }, ADM); assert.equal(r.status, 200); assert.equal(r.json.templates.project_site.length, 2);
  // CSV
  r = await call('GET', '/ipam/sites/' + JB.id + '/plan', undefined, OP); assert.match(r.json.csv, /^"site","kind","block"/); assert.match(r.json.csv, /Site users/);
  // close the site: retired subnets, block held back
  r = await call('POST', '/ipam/sites/' + JB.id + '/close', { reason: 'x' }, OP); assert.equal(r.status, 400);
  const C = (await call('POST', '/ipam/sites/' + JB.id + '/close', { reason: 'project handed over (synthetic)' }, OP)).json; assert.equal(C.kind, 'close');
  r = await call('POST', '/ipam/site-proposals/' + C.id + '/decide', { decision: 'approve' }, ADM); assert.equal(r.status, 200, r.text); assert.equal(r.json.subnets_changed, P.subnets.length);
  v = (await call('GET', '/ipam/sites', undefined, OP)).json; assert.equal(v.sites.find((s) => s.id === JB.id).status, 'closed'); assert.equal(v.kpis.sites, 1);
  const P3 = (await call('POST', '/ipam/sites/propose', { name: 'Tabuk Project Site', kind: 'project_site', city: 'Tabuk' }, OP)).json; assert.notEqual(P3.block, P.block, 'the closed block is not reused for 90 days');
  const au = e.app.store.auditTail(100).map((x) => x.action); for (const a of ['ipam.site.register', 'ipam.site.propose', 'ipam.site.open', 'ipam.site.reject', 'ipam.site.template', 'ipam.site.propose_close', 'ipam.site.close']) assert.ok(au.includes(a), a);
});
