// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SAMA evidence ClickHouse probes (engine/compliance/evidence-ch.js). Bug fixed: the SIEM's ClickHouse user is granted SELECT on siem.*
// only, so "oldest data" from system.parts failed with Code 497 ACCESS_DENIED and marked the whole evidence store unreadable - every
// check read "evidence unavailable" and no daily snapshot was taken. Now a refusal falls back to min(ts) of the tables themselves.
const test = require('node:test');
const assert = require('node:assert/strict');
const { probeClickHouse, oldestData } = require('../engine/compliance/evidence-ch');

const T0 = Date.parse('2026-01-05T00:00:00Z');
const DENY = 'ClickHouse: Code: 497. DB::Exception: sentra_siem: Not enough privileges. To execute this query, it\'s necessary to have the grant SELECT ON system.parts. (ACCESS_DENIED)';
function fakeCh({ parts = 'deny', archive = true, tableErr = null } = {}) {
  const seen = [];
  return { seen, query: async (sql) => {
    seen.push(sql.replace(/\s+/g, ' ').trim());
    if (/FROM system\.parts/.test(sql)) { if (parts === 'deny') throw new Error(DENY); if (parts === 'fail') throw new Error('Code: 159. Timeout exceeded'); return [{ table: 'events', oldest: T0 / 1000 }]; }
    if (/FROM system\.tables/.test(sql)) return [{ name: 'events', engine_full: 'MergeTree TTL toDateTime(ts) + toIntervalDay(365)' }];
    if (/min\(ts\)\) AS oldest FROM siem\.events_archive/.test(sql)) { if (!archive) throw new Error('Code: 60. DB::Exception: Table siem.events_archive does not exist. (UNKNOWN_TABLE)'); return [{ oldest: (T0 - 86400000 * 400) / 1000 }]; }
    if (/min\(ts\)\) AS oldest FROM siem\.events/.test(sql)) { if (tableErr) throw new Error(tableErr); return [{ oldest: T0 / 1000 }]; }
    return [];
  } };
}

test('system.parts refused (Code 497): the probe still succeeds, oldest read from the tables, never from system.parts again', async () => {
  const ch = fakeCh();
  const r = await probeClickHouse(ch, { database: 'siem' });
  assert.equal(r.ok, true, r.error); assert.equal(r.error, null);
  assert.equal(r.oldest.events, T0); assert.equal(r.oldest.events_archive, T0 - 86400000 * 400);
  assert.ok(ch.seen.some((q) => /min\(ts\)\) AS oldest FROM siem\.events$/.test(q)));
});

test('granted system.parts is used as before; a missing archive table is null, not an error', async () => {
  let r = await probeClickHouse(fakeCh({ parts: 'ok' }), { database: 'siem' }); assert.equal(r.ok, true); assert.equal(r.oldest.events, T0);
  r = await probeClickHouse(fakeCh({ archive: false }), { database: 'siem' }); assert.equal(r.ok, true, r.error); assert.equal(r.oldest.events_archive, null);
});

test('a real failure still says so, and only that probe fails', async () => {
  let r = await probeClickHouse(fakeCh({ parts: 'fail' }), { database: 'siem' });
  assert.equal(r.ok, false); assert.match(r.error, /oldest: Code: 159/); assert.equal(r.oldest, null); assert.ok(Array.isArray(r.hosts), 'the other probes are unaffected'); assert.equal(r.partial, true);
  r = await probeClickHouse(fakeCh({ tableErr: 'Code: 241. Memory limit exceeded' }), { database: 'siem' });
  assert.equal(r.ok, false); assert.match(r.error, /oldest \(events\): Code: 241/);
  const errs = []; assert.equal(await oldestData(fakeCh(), 'siem; DROP', {}, errs), null); assert.match(errs[0], /invalid database name/);
});
