// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Database Audit collection (engine/db-health.js readAudit + inv-helper op oracle_audit): first pass reads the last 24 h,
// the cursor moves to the newest row, a row on the cursor's own timestamp is never sent twice, rows go to the SIEM as
// kind unified_audit on the database's instance key, and a database without AUDIT_VIEWER names "audit_trail" as missing.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createDbHealth, SRC_ID } = require('../engine/db-health');
const { createSealer } = require('../engine/discovery/vault');

test('audit trail: 24 h backfill, cursor, no duplicates, missing grant named', async (tt) => {
  const e = await startApp({ noAi: true }); tt.after(() => e.close());
  const creds = [{ id: 'cr1', kind: 'db_login', label: 'oracle-ESS', target: { engine: 'oracle', port: 1521, service: 'ESS' }, _s: { username: 'zyb_monitor', password: 'Synthetic-1' } }];
  const vault = { available: () => true, list: () => creds, get: (id) => creds.find((c) => c.id === id), open: (id) => { const c = creds.find((x) => x.id === id); return { target: c.target, secret: Object.assign({}, c._s), release() {} }; } };
  e.app.store.collection('db_health_targets').put({ id: 'odb_1', label: 'Eskauat', host: '192.168.9.30', port: 1521, service: 'ESS', cred_id: 'cr1', cred_label: 'oracle-ESS' });
  const sent = [], audits = []; let t = Date.UTC(2026, 9, 20, 10, 0), grant = true;
  const row = (ts, sid, act) => ({ kind: 'unified_audit', EVENT_TIMESTAMP_UTC: ts + 'Z', DBUSERNAME: 'APP', ACTION_NAME: act || 'LOGON', RETURN_CODE: '1017', SESSIONID: String(sid), ENTRY_ID: '1', STATEMENT_ID: '1' });
  let batch = [row('2026-10-20T09:00:00.000000', 1), row('2026-10-20T09:30:00.000000', 2), row('2026-10-20T09:30:00.000000', 3)];
  const helper = async (r) => {
    if (r.op === 'oracle_audit') { audits.push(r.since); return grant ? { ok: true, rows: batch.filter((x) => x.EVENT_TIMESTAMP_UTC.replace('Z', '') >= (r.since.includes('.') ? r.since : r.since + '.000000')) } : { ok: false, error_class: 'denied' }; }
    return { ok: true, records: [{ kind: 'instance', instance: 'ESS', host: 'eskauat', db_name: 'ESS', role: 'PRIMARY' }], errors: [] };
  };
  const H = createDbHealth(e.app, { discovery: { vault, siem: { call: async () => ({ status: 200, json: { source: { id: SRC_ID }, token: 't1' } }) } },
    sealer: createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-db-health' }),
    invRun: helper, request: async (url, o) => { sent.push(...o.body.trim().split('\n').map((l) => JSON.parse(l))); return { status: 200 }; }, now: () => t });
  await H.pass();
  assert.equal(audits[0], '2026-10-19T10:00:00', 'first pass: the last 24 h');
  let a = sent.filter((x) => x.kind === 'unified_audit');
  assert.equal(a.length, 3); assert.ok(a.every((x) => x.instance === 'ESS' && x.host === 'eskauat'));
  // next pass: the cursor is the newest row; the two rows on that timestamp are not sent again, a new one is
  batch.push(row('2026-10-20T09:45:00.000000', 4)); sent.length = 0; t += 240000;
  await H.pass();
  assert.equal(audits[1], '2026-10-20T09:30:00.000000');
  a = sent.filter((x) => x.kind === 'unified_audit');
  assert.deepEqual(a.map((x) => x.SESSIONID), ['4'], 'only the new row');
  // no AUDIT_VIEWER: health still read, the audit reading is named missing
  grant = false; t += 240000; const p = await H.pass();
  assert.equal(p.read, 1); assert.ok(p.results[0].missing.includes('audit_trail'));
});
