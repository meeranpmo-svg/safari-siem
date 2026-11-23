// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Host name → last IP address (and MAC) seen in the logs, for IT Asset Management discovery: user PCs and laptops are
 * found in Active Directory without an address when DNS has no (or a stale) record, and are usually outside the scanned
 * ranges, so the SIEM's own view of them is the most reliable source:
 *   kerberos   domain-controller events 4768/4769/4770/4776/4624 for the computer account (NAME$) - every domain PC
 *              authenticates several times a day, from its current address
 *   logon      event 4624 WorkstationName + IpAddress
 *   firewall   FortiGate device identification (srcname = host name, srcmac = MAC)
 * MAC addresses come from the FortiGate logs for the address found (srcmac) - present when device detection is on.
 *   POST {P}/hostmap {names: ["pc-0123", …] (max 5000), days?: 1-30 (default 14)} → {hosts: {name: {ip, mac, seen, via}}}
 *   GET  {P}/reporting-hosts ?hours=168 (1-720) → {hosts:[{host, ip, src_id, last_seen, events}], hours}
 *        every machine that itself SENT logs in the window (the event's host / host_ip), newest activity per host -
 *        what IT Asset Management shows per asset as connected / silent / not connected, also for servers that share one
 *        agent or syslog source. Cached 60 s.
 * Read-only; any signed-in caller (ITAM calls it server side with the proxy secret).
 */
const { HttpError, wrap, prefixOf } = require('./routeutil');

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const BAD_IP = new Set(['', '-', '127.0.0.1', '::1', '0.0.0.0']);
const cleanIp = (v) => { const s = String(v || '').trim().replace(/^::ffff:/i, ''); return BAD_IP.has(s) ? '' : s; };
const macFmt = (v) => { const h = String(v || '').toLowerCase().replace(/[^0-9a-f]/g, ''); return h.length === 12 && h !== '000000000000' && h !== 'ffffffffffff' ? h.match(/.{2}/g).join(':') : ''; };

async function lookup(ch, db, names, days) {
  const T = `${db}.events`, d = Math.max(1, Math.min(30, Number(days) || 14));
  // s.ip / s.ts: the outer names are aggregates, and a bare ip in WHERE would mean argMax(...) (ILLEGAL_AGGREGATION)
  const sql = `SELECT s.name AS name, argMax(s.ip, s.ts) AS ip, max(s.ts) AS seen, argMax(s.via, s.ts) AS via FROM (
      SELECT lower(replaceRegexpOne(user, '\\\\$$', '')) AS name, src_ip AS ip, ts, 'kerberos' AS via FROM ${T}
        WHERE ts >= now() - INTERVAL ${d} DAY AND src_type = 'windows' AND endsWith(user, '$') AND src_ip != '' AND event_code IN ('4768','4769','4770','4776','4624')
      UNION ALL
      SELECT lower(fields['workstation']) AS name, src_ip AS ip, ts, 'logon' AS via FROM ${T}
        WHERE ts >= now() - INTERVAL ${d} DAY AND src_type = 'windows' AND event_code = '4624' AND fields['workstation'] != '' AND src_ip != ''
      UNION ALL
      SELECT lower(fields['srcname']) AS name, src_ip AS ip, ts, 'firewall' AS via FROM ${T}
        WHERE ts >= now() - INTERVAL ${Math.min(d, 7)} DAY AND src_type = 'fortigate' AND fields['srcname'] != '' AND src_ip != ''
    ) AS s WHERE s.name IN {names:Array(String)} AND s.ip NOT IN ('127.0.0.1','::1','-','::ffff:127.0.0.1') GROUP BY s.name`;
  const rows = await ch.query(sql, { names }, { readonly: true, timeout_ms: 60000, settings: { max_execution_time: 60 } });
  const hosts = {};
  for (const r of rows || []) { const ip = cleanIp(r.ip); if (ip) hosts[r.name] = { ip, mac: '', seen: r.seen, via: r.via }; }
  const ips = [...new Set(Object.values(hosts).map((h) => h.ip))];
  if (ips.length) {
    const macs = await ch.query(`SELECT src_ip AS ip, argMax(fields['srcmac'], ts) AS mac FROM ${T}
        WHERE ts >= now() - INTERVAL 3 DAY AND src_type = 'fortigate' AND fields['srcmac'] != '' AND src_ip IN {ips:Array(String)} GROUP BY src_ip`,
      { ips: ips.concat(ips.map((x) => '::ffff:' + x)) }, { readonly: true, timeout_ms: 60000, settings: { max_execution_time: 60 } }).catch(() => []);
    const byIp = new Map((macs || []).map((m) => [cleanIp(m.ip), macFmt(m.mac)]));
    for (const h of Object.values(hosts)) h.mac = byIp.get(h.ip) || '';
  }
  return hosts;
}

async function reportingHosts(ch, db, hours) {
  const h = Math.max(1, Math.min(720, Math.trunc(Number(hours) || 168)));
  const rows = await ch.query(`SELECT lower(host) AS host, argMax(host_ip, ts) AS ip, argMax(src_id, ts) AS src_id, max(ts) AS last_seen, count() AS events
    FROM ${db}.events AS e WHERE e.ts >= now() - toIntervalHour({h:UInt32}) AND e.host != '' AND e.host != '-' GROUP BY host ORDER BY events DESC LIMIT 50000`,
  { h: { type: 'UInt32', value: h } }, { readonly: true, timeout_ms: 60000, settings: { max_execution_time: 60 } });
  return { hours: h, hosts: rows.map((r) => ({ host: r.host, ip: cleanIp(r.ip), src_id: r.src_id, last_seen: r.last_seen, events: Number(r.events) || 0 })) };
}

function register(api, deps) {
  const P = prefixOf(deps), ch = deps.ch, db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  api.route('POST', `${P}/hostmap`, wrap(deps, null, async (ctx) => {
    const b = ctx.body || {};
    if (!Array.isArray(b.names)) throw new HttpError(400, 'names[] required');
    const names = [...new Set(b.names.map((n) => String(n || '').trim().toLowerCase().split('.')[0]).filter((n) => NAME_RE.test(n)))].slice(0, 5000);
    if (!names.length) return ctx.ok({ hosts: {} });
    if (!ch || typeof ch.query !== 'function') throw new HttpError(503, 'log store not available');
    return ctx.ok({ hosts: await lookup(ch, db, names, b.days) });
  }), { anyRole: 'a lookup of host names in the logs (POST only for the size of the list)' });
  let rcache = null;
  api.route('GET', `${P}/reporting-hosts`, wrap(deps, null, async (ctx) => {
    if (!ch || typeof ch.query !== 'function') throw new HttpError(503, 'log store not available');
    const hours = (ctx.query || {}).hours;
    if (rcache && rcache.hours === String(hours || '') && Date.now() - rcache.at < 60000) return ctx.ok(rcache.v);
    const v = await reportingHosts(ch, db, hours);
    rcache = { at: Date.now(), hours: String(hours || ''), v };
    return ctx.ok(v);
  }));
}

module.exports = { register, lookup, reportingHosts, cleanIp, macFmt };
