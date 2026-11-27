// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Asset Onboarding (engine/asset-onboard.js) with SYNTHETIC assets: the helper reads a CSV with a header, a header-less list of
// names / IPs / MACs and FQDNs; the type from the naming convention or the OS, the site from a column, a branch name inside the
// host name, or learned from the /24, each with its reason; an asset already in the register is matched (serial, MAC, name, IP);
// add creates only new rows, skips duplicates and invalid rows with the field named, is audited, and is refused to a viewer and an
// AI identity; branch accuracy: completeness, sources, stale, duplicates, site conflicts, no site; a viewer sees no names.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { readText } = require('../engine/asset-onboard');

const ADM = { user: 'admin.syn', role: 'admin' }, OP = { user: 'op.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' }, BOT = { user: 'ai:engineer', role: 'operator' };
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true });
  const A = (o) => e.app.assets.create(Object.assign({ status: 'in_use' }, o), ADM).asset;
  A({ name: 'JED-PC-SYN01', type: 'workstation', site: 'Jeddah', mgmt_ip: '10.20.1.11', serial: 'SERJ1', owner: 'a.syn', os: 'Windows 11' });
  A({ name: 'JED-PC-SYN02', type: 'workstation', site: 'Jeddah', mgmt_ip: '10.20.1.12', serial: 'SERJ2', os: 'Windows 11' });
  A({ name: 'JED-PC-SYN03', type: 'workstation', site: 'Jeddah', mgmt_ip: '10.20.1.13', serial: 'SERJ3' });
  A({ name: 'RUH-FS-SYN01', type: 'server', site: 'Riyadh', mgmt_ip: '10.20.1.14', serial: 'SERR1' });   // in Jeddah's /24: a site conflict
  A({ name: 'RUH-PC-SYN09', type: 'workstation', site: 'Riyadh', mgmt_ip: '10.10.1.9', serial: 'SERJ3B', mac: '00:11:22:33:44:55' });
  A({ name: 'NOSITE-SYN', type: 'workstation', mgmt_ip: '10.30.1.5', mac: '00:11:22:33:44:55' });   // same MAC as above: a duplicate
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, call };
}

test('reader: header CSV, header-less lists, FQDNs', () => {
  let r = readText('Computer Name,IP Address,Serial Number,Branch\nJED-SRV-SYN05,10.20.1.50,ABC123XYZ,Jeddah\n"DC-SYN01, main",10.0.0.10,,Riyadh');
  assert.equal(r.header, true); assert.equal(r.rows.length, 2); assert.equal(r.rows[0].name, 'JED-SRV-SYN05'); assert.equal(r.rows[0].ip, '10.20.1.50'); assert.equal(r.rows[0].site, 'Jeddah'); assert.equal(r.rows[1].name, 'DC-SYN01, main');
  r = readText('HQ-PC-SYN44 10.10.1.44 aa-bb-cc-dd-ee-ff\nfs01.corp.example\n# a comment\n10.20.1.99');
  assert.equal(r.header, false); assert.equal(r.rows[0].name, 'HQ-PC-SYN44'); assert.equal(r.rows[0].ip, '10.10.1.44'); assert.equal(r.rows[0].mac, 'aa-bb-cc-dd-ee-ff');
  assert.equal(r.rows[1].name, 'fs01'); assert.equal(r.rows[2].ip, '10.20.1.99'); assert.equal(r.rows.length, 3);
});

test('parse: types, sites with reasons, matches; add: new only, duplicates and bad rows skipped, roles, audit', async (t) => {
  const { e, call } = await setup(t);
  const text = 'name,ip,mac,serial,os\nJED-DC-SYN01,10.20.1.60,,,Windows Server 2022\nJEDDAH-LT-SYN07,,,,\nSW-SYN-CORE,10.20.1.2,,,\nJED-PC-SYN02,,,,\nX-SYN,10.99.0.1,,SERR1,\nPRN-SYN-3F,10.40.0.7,,,\nbad name!,1.2.3,,,';
  assert.equal((await call('POST', '/asset-onboard/parse', { text }, VIEW)).status, 403, 'viewer refused');
  assert.equal((await call('POST', '/asset-onboard/parse', { text }, BOT)).status, 403, 'an AI identity does not add assets');
  assert.equal((await call('POST', '/asset-onboard/parse', { text: '' }, OP)).status, 400);
  const r = await call('POST', '/asset-onboard/parse', { text, extra: 'dropped' }, OP); assert.equal(r.status, 200, r.text);
  const R = Object.fromEntries(r.json.rows.map((x) => [x.name || x.ip, x]));
  assert.equal(R['JED-DC-SYN01'].type, 'server'); assert.ok(R['JED-DC-SYN01'].tags.includes('domain-controller')); assert.equal(R['JED-DC-SYN01'].site, 'Jeddah');
  assert.ok(R['JED-DC-SYN01'].why.some((w) => /learned: 3 of 4 assets in 10\.20\.1\.0\/24 are at Jeddah/.test(w)), R['JED-DC-SYN01'].why.join(' | '));
  assert.equal(R['JEDDAH-LT-SYN07'].type, 'laptop'); assert.equal(R['JEDDAH-LT-SYN07'].site, 'Jeddah'); assert.ok(R['JEDDAH-LT-SYN07'].why.some((w) => /"Jeddah" is in the name/.test(w)));
  assert.equal(R['SW-SYN-CORE'].type, 'network'); assert.ok(R['SW-SYN-CORE'].tags.includes('switch'));
  assert.equal(R['JED-PC-SYN02'].action, 'skip'); assert.equal(R['JED-PC-SYN02'].match.by, 'name');
  assert.equal(R['X-SYN'].match.by, 'serial'); assert.equal(R['PRN-SYN-3F'].type, 'printer'); assert.ok(R['PRN-SYN-3F'].issues.some((i) => /no site/.test(i)));
  const badRow = r.json.rows.find((x) => /bad name/.test(x.name)); assert.equal(badRow.action, 'fix'); assert.ok(badRow.issues.some((i) => /not an IPv4/.test(i)));
  assert.equal(r.json.summary.read, 7); assert.equal(r.json.summary.already, 2);
  // add what a person keeps
  const keep = r.json.rows.filter((x) => x.action === 'create').map((x) => ({ name: x.name, ip: x.ip, os: x.os, site: x.site || 'Dammam', type: x.type, tags: x.tags }));
  assert.equal((await call('POST', '/asset-onboard/commit', { rows: keep }, VIEW)).status, 403);
  assert.equal((await call('POST', '/asset-onboard/commit', { rows: [] }, OP)).status, 400);
  const c = await call('POST', '/asset-onboard/commit', { rows: keep.concat([{ name: 'JED-PC-SYN01' }, { name: 'ok-syn', ip: '999.1.1.1' }, { name: 'T-SYN', type: 'spaceship' }]) }, OP);
  assert.equal(c.status, 200, c.text); assert.equal(c.json.created.length, keep.length);
  assert.ok(c.json.skipped.some((x) => /already in the register as JED-PC-SYN01/.test(x.reason)) && c.json.skipped.some((x) => /\.ip: not an IPv4/.test(x.reason)) && c.json.skipped.some((x) => /rows\[\d+\]: type must be one of/.test(x.reason)));
  const DC = e.app.store.collection('assets').all().find((a) => a.name === 'JED-DC-SYN01'); assert.ok(DC && DC.site === 'Jeddah' && DC.tags.includes('onboarding-helper') && DC.tags.includes('domain-controller'));
  const au = e.app.store.auditTail(50).filter((x) => x.action === 'asset_onboard.commit'); assert.equal(au.length, 1); assert.equal(au[0].by, 'op.syn'); assert.equal(au[0].detail.created, keep.length);
});

test('accuracy per branch: completeness, duplicates, site conflicts, no site; a viewer sees no names', async (t) => {
  const { call } = await setup(t);
  const v = (await call('GET', '/asset-onboard/overview', undefined, OP)).json;
  const J = v.branches.find((b) => b.site === 'Jeddah'), Rb = v.branches.find((b) => b.site === 'Riyadh'), N = v.branches.find((b) => b.site === '(no site)');
  assert.equal(J.assets, 3); assert.equal(J.pct.serial, 100); assert.equal(J.pct.owner, 33); assert.equal(J.pct.os, 67);
  assert.equal(Rb.conflict, 1, 'RUH-FS-SYN01 sits in a Jeddah /24'); assert.ok(Rb.issues.some((x) => x.name === 'RUH-FS-SYN01' && x.issues.some((i) => /mostly Jeddah/.test(i))));
  assert.equal(v.totals.duplicates, 2, 'the same MAC on two records'); assert.equal(v.totals.no_site, 1); assert.equal(N.score, 0);
  assert.ok(typeof v.totals.score === 'number'); assert.equal(v.names, true);
  const vv = (await call('GET', '/asset-onboard/overview', undefined, VIEW)).json; assert.equal(vv.names, false); assert.ok(!JSON.stringify(vv.branches).includes('RUH-FS-SYN01'), 'no names for a viewer');
});
