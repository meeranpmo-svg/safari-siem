// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const imp = require('../engine/import');
const { startApp } = require('./helpers');

const ME_CSV = [
  'Asset Name,Asset Tag,Product Type,Manufacturer,Serial Number,IP Address,Operating System,Department,Warranty Expiry,Weird Column',
  'FIN-PC-01,SAF-1001,Workstation,Dell,DL-SN-1,10.2.0.11,Windows 11,Finance,2027-03-01,ignore-me',
  'HR-PC-02,SAF-1002,Laptop,Lenovo,LN-SN-2,10.2.0.12,Windows 10,HR,2026-11-15,ignore-me',
].join('\n');

test('CSV parser handles quoted fields with commas', () => {
  const { headers, rows } = imp.parseCsv('a,b\n"x,y",z\n');
  assert.deepEqual(headers, ['a', 'b']);
  assert.equal(rows[0].a, 'x,y'); assert.equal(rows[0].b, 'z');
});

test('ManageEngine AssetExplorer mapping + unmapped-column report', () => {
  const r = imp.mapRow({ 'Asset Name': 'X', 'Serial Number': 'S1', 'Warranty Expiry': '2027-01-01', 'Weird Column': 'zzz' }, imp.MANAGEENGINE);
  assert.equal(r.fields.name, 'X'); assert.equal(r.fields.serial, 'S1');
  assert.equal(r.fields.warranty.end, '2027-01-01');
  assert.deepEqual(r.unmapped, ['Weird Column']);
});

test('import is idempotent: re-running the same CSV updates, never duplicates', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const run1 = (await h.req('POST', '/import/run', { body: { format: 'csv', mapping: 'manageengine', text: ME_CSV } })).json;
  assert.equal(run1.created, 2); assert.equal(run1.updated, 0);
  assert.ok(run1.unmapped_columns.includes('Weird Column'));
  const run2 = (await h.req('POST', '/import/run', { body: { format: 'csv', mapping: 'manageengine', text: ME_CSV } })).json;
  assert.equal(run2.created, 0); assert.equal(run2.updated, 2, 'second run merges, no new records');
  const assets = (await h.req('GET', '/assets', { role: 'viewer' })).json;
  assert.equal(assets.total, 2, 'exactly two assets after two imports');
});

// the Inventory page's own export (Export CSV) imports back: its '# ...' note line is not the header, Tag / Type / Warranty end /
// Support end / Classification map, the spreadsheet guard quote before = + - @ is taken off, computed columns are reported unmapped;
// a viewer is refused and the run is in the audit trail
test('an Inventory export imports back (round trip), operators only, audited', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const EXP = ['# ITAM inventory export 2026-11-21T08:00:00.000Z - 2 of 2 assets (filters applied)',
    '"Quality","Name","Tag","Type","Status","Serial","Warranty end","Support end","Classification","IP","Seen","Issues"',
    '"80","PC-SYN-1","T-SYN-1","laptop","in_use","SN-SYN-1","2027-01-01","2028-01-01","restricted","10.0.0.5","3","stale"',
    '"70","\'-SYN-2","T-SYN-2","printer","in_stock","SN-SYN-2","","","","","",""'].join('\r\n');
  const p = imp.parseCsv(EXP); assert.equal(p.headers[1], 'Name', 'the note line is not the header'); assert.equal(p.rows.length, 2);
  assert.equal((await h.req('POST', '/import/run', { body: { format: 'csv', mapping: 'inventory', text: EXP }, role: 'viewer' })).status, 403);
  const r = (await h.req('POST', '/import/run', { body: { format: 'csv', mapping: 'inventory', text: EXP } })).json;
  assert.equal(r.created, 2); assert.deepEqual(r.errors, []);
  assert.deepEqual(r.unmapped_columns.sort(), ['Issues', 'Quality', 'Seen']);
  const all = (await h.req('GET', '/assets', { role: 'viewer' })).json.assets;
  const a = all.find((x) => x.serial === 'SN-SYN-1'), b = all.find((x) => x.serial === 'SN-SYN-2');
  assert.equal(a.asset_tag, 'T-SYN-1'); assert.equal(a.type, 'laptop'); assert.match(a.warranty.end, /^2027-01-01/); assert.match(a.support.end, /^2028-01-01/);
  assert.equal(a.mgmt_ip, '10.0.0.5'); assert.equal(a.classification, "restricted");
  assert.equal(b.name, '-SYN-2', 'the guard quote is taken off');
  const again = (await h.req('POST', '/import/run', { body: { format: 'csv', mapping: 'inventory', text: EXP } })).json;
  assert.equal(again.created, 0); assert.equal(again.updated, 2, 'importing the same export twice never duplicates');
  assert.ok(h.app.store.auditTail(50).some((x) => x.action === 'import.run'), 'audited');
});

// an export carries each asset's Platform ID: re-importing it updates that exact asset - even one with no serial, tag or MAC (a
// name alone is too weak to merge, so it used to come back as a duplicate) and one whose serial another record shares (ambiguous)
test('Platform ID: an exported asset is updated in place, never duplicated; an unknown id falls back to matching', async (t) => {
  const h = await startApp({ noAi: true });
  t.after(() => h.close());
  const A = h.app.store.collection('assets');
  A.put({ id: 'as_syn_nameonly', name: 'SRV-NAMEONLY-SYN', type: 'server', status: 'in_use', updated_at: '2026-11-01T00:00:00Z' });
  A.put({ id: 'as_syn_a', name: 'WS-A-SYN', type: 'workstation', status: 'in_use', serial: 'SER-SHARED', updated_at: '2026-11-01T00:00:00Z' });
  A.put({ id: 'as_syn_b', name: 'WS-B-SYN', type: 'workstation', status: 'in_use', serial: 'SER-SHARED', updated_at: '2026-11-01T00:00:00Z' });
  const before = A.all().length;
  const EXP = ['# ITAM inventory export (synthetic)', '"Platform ID","Name","Serial","Site"',
    '"as_syn_nameonly","SRV-NAMEONLY-SYN","","Jeddah"', '"as_syn_b","WS-B-SYN","SER-SHARED","Dammam"', '"as_unknown_syn","WS-NEW-SYN","SER-NEW-SYN","Riyadh"'].join('\r\n');
  const dry = (await h.req('POST', '/import/run', { body: { format: 'csv', mapping: 'inventory', text: EXP, dry_run: true } })).json;
  assert.equal(dry.matched_by_id, 2); assert.equal(dry.unknown_ids, 1); assert.equal(A.all().length, before, 'a dry run writes nothing');
  const r = (await h.req('POST', '/import/run', { body: { format: 'csv', mapping: 'inventory', text: EXP } })).json;
  assert.equal(r.updated, 2); assert.equal(r.created, 1, 'only the row with an unknown id and a new serial is new'); assert.equal(r.matched_by_id, 2);
  assert.equal(A.all().length, before + 1);
  assert.equal(A.get('as_syn_nameonly').site, 'Jeddah', 'name-only asset updated in place');
  assert.equal(A.get('as_syn_b').site, 'Dammam', 'the exact record, not the other with the same serial'); assert.notEqual(A.get('as_syn_a').site, 'Dammam');
});
