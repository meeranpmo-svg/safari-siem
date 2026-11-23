// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ClickHouse probes for the SAMA evidence collector. Every query is read-only (readonly=2), bounded (LIMIT, time
// window, timeout) and independent: one failing probe never hides the others. Result: { ok, error?, hosts[], defender[],
// ttl:{events, events_archive}, oldest:{events, events_archive} } with null where a probe failed.
//   hosts     one row per (src_type, src_id, host) that sent events within the active window, with the number of KDC
//             (Kerberos) events — a host producing 4768/4769/4771 is a domain controller
//   defender  hosts with Microsoft Defender channel events in the window
//   ttl       retention in days parsed from the live table TTL (system.tables.engine_full)
//   oldest    oldest data still present (system.parts min_time, else min(ts) when system.parts is not granted), epoch ms
const DB_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

function ttlDays(engineFull) {
  // engine_full shows the normalised form `TTL toDateTime(ts) + toIntervalDay(365)`; the schema file uses INTERVAL 365 DAY
  const m = /TTL[\s\S]*?(?:INTERVAL\s+(\d+)\s+DAY|toIntervalDay\((\d+)\))/i.exec(String(engineFull || ''));
  return m ? Number(m[1] || m[2]) : null;
}

const toMs = (v) => {
  if (v === null || v === undefined || v === '') return 0;
  if (typeof v === 'number') return v < 1e11 ? v * 1000 : v;
  const s = String(v);
  if (/^\d+(\.\d+)?$/.test(s)) { const n = Number(s); return n < 1e11 ? n * 1000 : n; }
  const t = Date.parse(s.replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? '' : 'Z'));
  return Number.isFinite(t) ? t : 0;
};

const DENIED = /ACCESS_DENIED|Not enough privileges|Code: 497\b/i;
// oldest data still present per table. system.parts answers from metadata, but the SIEM's own ClickHouse user is granted SELECT on
// siem.* only (install/ch-install.sh - least privilege), so on a refusal min(ts) is read from each table itself: both tables are
// partitioned by ts, so ClickHouse answers it from the partition min/max index without scanning the events. A missing archive
// table is simply null. Only when the table read also fails is it an error (and then only this probe fails, not the others).
async function oldestData(ch, database, opts, errors) {
  const out = { events: null, events_archive: null };
  if (!DB_RE.test(String(database))) { errors.push('oldest: invalid database name'); return null; }
  try {
    const o = await ch.query(`SELECT table, toUnixTimestamp(min(min_time)) AS oldest FROM system.parts
       WHERE database = {db:String} AND table IN ('events', 'events_archive') AND active GROUP BY table`, { db: { type: 'String', value: database } }, opts);
    for (const r of o || []) out[r.table] = toMs(r.oldest) || null;
    return out;
  } catch (e) {
    if (!DENIED.test(String(e && e.message))) { errors.push('oldest: ' + e.message); return null; }
  }
  for (const table of ['events', 'events_archive']) {
    try { const r = await ch.query(`SELECT toUnixTimestamp(min(ts)) AS oldest FROM ${database}.${table}`, {}, opts); out[table] = toMs(r && r[0] && r[0].oldest) || null; }
    catch (e) { if (table === 'events' || !/UNKNOWN_TABLE|Code: 60\b|does not exist/i.test(String(e && e.message))) { errors.push('oldest (' + table + '): ' + e.message); return null; } }
  }
  return out;
}

async function probeClickHouse(ch, { database = 'siem', windowH = 24, kdcCodes = ['4768', '4769', '4771'], channelContains = 'defender', timeoutMs = 10000 } = {}) {
  const out = { ok: false, error: null, hosts: null, defender: null, ttl: null, oldest: null };
  if (!ch || typeof ch.query !== 'function') { out.error = 'ClickHouse client not available'; return out; }
  if (!DB_RE.test(database)) { out.error = 'invalid database name'; return out; }
  const opts = { readonly: true, timeout_ms: timeoutMs };
  const h = { type: 'UInt32', value: Math.max(1, Math.min(24 * 400, Math.round(windowH))) };
  const errors = [];
  const run = async (name, sql, params) => {
    try { return await ch.query(sql, params, opts); } catch (e) { errors.push(`${name}: ${e.message}`); return null; }
  };

  const hosts = await run('hosts',
    `SELECT src_type, src_id, host, count() AS events, toUnixTimestamp64Milli(max(ts)) AS last_ms,
            countIf(has({kdc:Array(String)}, event_code)) AS kdc
     FROM ${database}.events WHERE ts >= now64(3) - toIntervalHour({h:UInt32})
     GROUP BY src_type, src_id, host ORDER BY events DESC LIMIT 5000`,
    { h, kdc: { type: 'Array(String)', value: kdcCodes.map(String) } });
  if (hosts) out.hosts = hosts.map((r) => ({ src_type: String(r.src_type || ''), src_id: String(r.src_id || ''), host: String(r.host || ''), events: Number(r.events) || 0, last_ms: toMs(r.last_ms), kdc: Number(r.kdc) || 0 }));

  if (channelContains) {
    const d = await run('defender',
      `SELECT host, count() AS events FROM ${database}.events
       WHERE ts >= now64(3) - toIntervalHour({h:UInt32}) AND src_type = 'windows'
         AND positionCaseInsensitive(fields['channel'], {chan:String}) > 0
       GROUP BY host ORDER BY events DESC LIMIT 2000`,
      { h, chan: { type: 'String', value: String(channelContains) } });
    if (d) out.defender = d.map((r) => ({ host: String(r.host || ''), events: Number(r.events) || 0 }));
  }

  const t = await run('ttl', `SELECT name, engine_full FROM system.tables WHERE database = {db:String} AND name IN ('events', 'events_archive')`,
    { db: { type: 'String', value: database } });
  if (t) { out.ttl = { events: null, events_archive: null }; for (const r of t) out.ttl[r.name] = ttlDays(r.engine_full); }

  out.oldest = await oldestData(ch, database, opts, errors);

  out.ok = errors.length === 0;
  out.error = errors.length ? errors.join('; ').slice(0, 1000) : null;
  out.partial = errors.length > 0 && errors.length < 4;
  return out;
}

module.exports = { probeClickHouse, oldestData, ttlDays, toMs };
