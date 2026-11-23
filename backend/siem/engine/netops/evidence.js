// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Evidence from the logs the SIEM already holds (ClickHouse <db>.events / net_metrics). Read-only, parameterised SQL,
 * readonly=2, short timeouts, bounded results. Every function returns plain rows the AI and the UI can show as evidence.
 *   createEvidence({ ch, config })
 *     .deviceEvents({ip, host, minutes, limit, kind})  kind: 'all' | 'link' (interface/tunnel/routing up-down) | 'config'
 *     .configChanges({ip?, hours})                    who changed what on network devices (FortiGate/PAN/Cisco/EdgeConnect)
 *     .blocked({src?, dst?, port?, minutes})          denied/blocked connections grouped by src → dst:port
 *     .topTalkers({minutes, ip?, by:'pair'|'src'|'app'})  firewall traffic logs: bytes and sessions
 *     .nacLookup({ip?, mac?, hours})                   Genian NAC / 802.1X events for an endpoint
 *     .metricHistory({device, metric, key?, hours})   from net_metrics (bucketed)
 *     .peakUtilByDay({days})                           per interface daily peak utilisation (capacity forecasting)
 *     .sessions({src?, dst?, ports[], minutes})        how FortiGate / Palo Alto sessions to those ports ENDED: per firewall and
 *                                                      end reason (FortiGate action close/timeout/server-rst/client-rst/deny,
 *                                                      PAN-OS session_end_reason), one-way sessions (no reply), durations
 *     .sessionApps({src?, dst?, ports[], minutes})     PAN-OS application / rule / action for the same flows (App-ID, denies)
 *     .voiceFlows({a, b, minutes})                    UDP voice between two endpoints (IP or subnet) in BOTH directions, plus the
 *                                                      SIP / SCCP signalling of side a: per firewall, direction, kind (rtp/sip/sccp),
 *                                                      action, NAT, sessions with no reply (one-way)
 */
const net = require('node:net');
const CIDR = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12]\d|3[0-2])$/;

const LINK_RE = '(?i)(LINK-3-UPDOWN|LINEPROTO-5-UPDOWN|link (status|monitor|down|up)|interface [^ ]+ (is )?(down|up)|tunnel[^.]{0,60}(down|up)|ipsec[^.]{0,60}(down|up|negotiat)|phase ?[12][^.]{0,40}(fail|down)|BGP-5-ADJCHANGE|bgp[^.]{0,60}(down|established|neighbor)|OSPF-5-ADJCHG|ospf[^.]{0,60}(down|full)|HA[^.]{0,40}(failover|state|sync))';
const CFG_RE = '(?i)(SYS-5-CONFIG_I|configured from|PARSER-5-CFGLOG|config(uration)? (change|commit)|commit (succeeded|job)|logid="?010004454[67]|attribute configured|object (added|deleted|edited)|cfg[-_ ]?change)';
const DENY = ['deny', 'denied', 'block', 'blocked', 'drop', 'dropped', 'reject', 'reset-both', 'reset-client', 'reset-server', 'server-rst', 'client-rst', 'timeout-deny'];

// The output renames ts (as text) and message (cut to 300): the filters and the order use e.ts / e.message, the stored
// columns. A bare name means the alias (ClickHouse 24.3+ analyzer) - a text ts against a date is refused (NO_COMMON_TYPE).
function createEvidence({ ch, config } = {}) {
  const db = /^[A-Za-z0-9_]+$/.test((config && config.clickhouse && config.clickhouse.database) || '') ? config.clickhouse.database : 'siem';
  const opts = { readonly: true, timeout_ms: 15000, settings: { max_execution_time: 12, max_result_rows: 2000, result_overflow_mode: 'break' } };
  const lim = (v, d, max) => Math.max(1, Math.min(max, Math.round(Number(v) || d)));
  const ip = (v) => (v && net.isIP(String(v)) ? String(v) : '');
  async function q(sql, params) { if (!ch) throw new Error('log database not available'); return ch.query(sql, params, opts); }
  const S = (v) => ({ type: 'String', value: String(v) });
  // the flow filter shared by sessions() / sessionApps(): users as an IP or CIDR, the server as an IP, 1-10 ports
  function flowWhere({ src, dst, ports }) {
    const sql = [], params = {};
    const ps = (Array.isArray(ports) ? ports : []).map(Number).filter((p) => Number.isInteger(p) && p > 0 && p < 65536).slice(0, 10);
    if (!ps.length) throw new Error('at least one port required');
    sql.push('AND dst_port IN {ports:Array(UInt16)}'); params.ports = { type: 'Array(UInt16)', value: ps };
    const d = ip(dst); if (d) { sql.push('AND dst_ip = {dst:String}'); params.dst = S(d); }
    const sv = String(src || '').trim();
    if (sv && net.isIP(sv)) { sql.push('AND src_ip = {src:String}'); params.src = S(sv); }
    else if (sv && CIDR.test(sv)) { sql.push('AND isIPAddressInRange(src_ip, {src:String})'); params.src = S(sv); }
    return { sql: sql.join(' '), params };
  }

  return {
    async deviceEvents({ ip: dip, host, minutes = 60, limit = 50, kind = 'all' } = {}) {
      const a = ip(dip); if (!a && !host) throw new Error('device IP or host name required');
      const re = kind === 'link' ? ` AND match(e.message, {re:String})` : kind === 'config' ? ` AND (category IN ('config','configuration','change') OR match(e.message, {re:String}))` : '';
      return q(`SELECT toString(e.ts) AS ts, src_type, host, host_ip, category, action, outcome, severity, event_code, user, substring(e.message, 1, 300) AS message
        FROM ${db}.events AS e WHERE e.ts >= now() - toIntervalMinute({m:UInt32}) AND (host_ip = {ip:String} OR (host != '' AND host = {host:String}))${re}
        ORDER BY e.ts DESC LIMIT {n:UInt32}`, { m: { type: 'UInt32', value: lim(minutes, 60, 10080) }, ip: S(a), host: S(host || '\u0000'), n: { type: 'UInt32', value: lim(limit, 50, 200) }, re: S(kind === 'link' ? LINK_RE : CFG_RE) });
    },
    async configChanges({ ip: dip, hours = 24, limit = 50 } = {}) {
      const a = ip(dip);
      return q(`SELECT toString(e.ts) AS ts, toUnixTimestamp64Milli(toDateTime64(e.ts, 3)) AS at, src_type, host, host_ip, user, substring(e.message, 1, 300) AS message
        FROM ${db}.events AS e WHERE e.ts >= now() - toIntervalHour({h:UInt32}) AND src_type IN ('fortigate','paloalto','cisco','ciscoasa','silverpeak','f5','netscaler')
          AND (category IN ('config','configuration','change') OR match(e.message, {re:String}))${a ? ' AND host_ip = {ip:String}' : ''}
        ORDER BY e.ts DESC LIMIT {n:UInt32}`, { h: { type: 'UInt32', value: lim(hours, 24, 720) }, re: S(CFG_RE), ip: S(a), n: { type: 'UInt32', value: lim(limit, 50, 1000) } });
    },
    async blocked({ src, dst, port, minutes = 60, limit = 20 } = {}) {
      const s = ip(src), d = ip(dst), p = Number(port) || 0;
      return q(`SELECT src_ip, dst_ip, dst_port, proto, any(host) AS firewall, count() AS hits, toString(max(ts)) AS last_seen, any(substring(message,1,200)) AS sample
        FROM ${db}.events WHERE ts >= now() - toIntervalMinute({m:UInt32}) AND lower(action) IN {deny:Array(String)}
          ${s ? 'AND src_ip = {s:String}' : ''} ${d ? 'AND dst_ip = {d:String}' : ''} ${p ? 'AND dst_port = {p:UInt16}' : ''}
        GROUP BY src_ip, dst_ip, dst_port, proto ORDER BY hits DESC LIMIT {n:UInt32}`,
      { m: { type: 'UInt32', value: lim(minutes, 60, 10080) }, deny: { type: 'Array(String)', value: DENY }, s: S(s), d: S(d), p: { type: 'UInt16', value: p }, n: { type: 'UInt32', value: lim(limit, 20, 100) } });
    },
    async topTalkers({ minutes = 60, ip: who, by = 'pair', limit = 15 } = {}) {
      const a = ip(who);
      const bytes = `toUInt64OrZero(fields['sentbyte']) + toUInt64OrZero(fields['rcvdbyte']) + toUInt64OrZero(fields['bytes'])`;
      const key = by === 'src' ? 'src_ip' : by === 'app' ? `if(fields['app'] != '', fields['app'], if(fields['service'] != '', fields['service'], toString(dst_port)))` : `concat(src_ip, ' → ', dst_ip, ':', toString(dst_port))`;
      return q(`SELECT ${key} AS key, sum(${bytes}) AS bytes, count() AS sessions, uniqExact(src_ip) AS sources
        FROM ${db}.events WHERE ts >= now() - toIntervalMinute({m:UInt32}) AND src_type IN ('fortigate','paloalto','ciscoasa','silverpeak') AND category = 'network'
          ${a ? 'AND (src_ip = {a:String} OR dst_ip = {a:String})' : ''}
        GROUP BY key ORDER BY bytes DESC, sessions DESC LIMIT {n:UInt32}`, { m: { type: 'UInt32', value: lim(minutes, 60, 1440) }, a: S(a), n: { type: 'UInt32', value: lim(limit, 15, 50) } });
    },
    async nacLookup({ ip: who, mac, hours = 24, limit = 30 } = {}) {
      const a = ip(who), m = String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
      if (!a && m.length !== 12) throw new Error('endpoint IP or MAC address required');
      const macFmt = m.length === 12 ? m.match(/../g).join(':') : '';
      return q(`SELECT toString(e.ts) AS ts, src_type, host, src_ip, dst_ip, user, action, outcome, substring(e.message, 1, 300) AS message
        FROM ${db}.events AS e WHERE e.ts >= now() - toIntervalHour({h:UInt32})
          AND (src_type ILIKE '%genian%' OR src_type ILIKE '%nac%' OR category = 'authentication' OR match(e.message, '(?i)(dot1x|802\\.1x|mab|radius|quarantin)'))
          AND (${a ? 'src_ip = {a:String} OR dst_ip = {a:String} OR position(e.message, {a:String}) > 0' : '0'} ${macFmt ? 'OR positionCaseInsensitive(e.message, {mac:String}) > 0 OR positionCaseInsensitive(e.message, {mac2:String}) > 0' : ''})
        ORDER BY e.ts DESC LIMIT {n:UInt32}`, { h: { type: 'UInt32', value: lim(hours, 24, 720) }, a: S(a), mac: S(macFmt), mac2: S(macFmt.replace(/:/g, '-')), n: { type: 'UInt32', value: lim(limit, 30, 100) } });
    },
    async metricHistory({ device, metric, key = '', hours = 24 } = {}) {
      if (!/^[a-z0-9-]{2,40}$/.test(String(device || '')) || !/^[a-z_]{2,30}$/.test(String(metric || ''))) throw new Error('device and metric required');
      const h = lim(hours, 24, 24 * 90), bucket = h <= 24 ? 300 : h <= 168 ? 3600 : 21600;
      return q(`SELECT toString(toStartOfInterval(ts, toIntervalSecond({b:UInt32}))) AS t, round(avg(value), 2) AS avg, round(max(value), 2) AS max
        FROM ${db}.net_metrics WHERE device = {dev:String} AND metric = {met:String} ${key ? 'AND key = {k:String}' : ''} AND ts >= now() - toIntervalHour({h:UInt32})
        GROUP BY t ORDER BY t`, { b: { type: 'UInt32', value: bucket }, dev: S(device), met: S(metric), k: S(key), h: { type: 'UInt32', value: h } });
    },
    async sessions({ src, dst, ports, minutes = 120 } = {}) {
      const w = flowWhere({ src, dst, ports });
      const reason = `lower(if(src_type = 'fortigate', fields['action'], fields['session_end_reason']))`;
      const dur = `toFloat64OrZero(if(src_type = 'fortigate', fields['duration'], fields['elapsed']))`;
      const oneway = `if(src_type = 'fortigate', toUInt64OrZero(fields['sentbyte']) > 0 AND toUInt64OrZero(fields['rcvdbyte']) = 0, toUInt64OrZero(fields['pkts_sent']) > 0 AND toUInt64OrZero(fields['pkts_received']) = 0)`;
      return q(`SELECT src_type AS vendor, any(host) AS firewall, host_ip AS firewall_ip, ${reason} AS reason, dst_port AS port, count() AS sessions, countIf(${oneway}) AS oneway,
          round(quantile(0.5)(${dur})) AS p50_s, round(quantile(0.9)(${dur})) AS p90_s, max(${dur}) AS max_s, uniqExact(src_ip) AS clients, uniqExact(dst_ip) AS servers,
          any(concat(src_ip, ' → ', dst_ip, ':', toString(dst_port))) AS sample, toString(max(ts)) AS last_seen
        FROM ${db}.events WHERE ts >= now() - toIntervalMinute({m:UInt32}) AND src_type IN ('fortigate','paloalto') AND category = 'network' ${w.sql}
        GROUP BY vendor, firewall_ip, reason, port ORDER BY sessions DESC LIMIT 200`, Object.assign({ m: { type: 'UInt32', value: lim(minutes, 120, 10080) } }, w.params));
    },
    async sessionApps({ src, dst, ports, minutes = 120 } = {}) {
      const w = flowWhere({ src, dst, ports });
      return q(`SELECT any(host) AS firewall, host_ip AS firewall_ip, fields['app'] AS app, fields['rule'] AS rule, lower(action) AS action, lower(fields['session_end_reason']) AS reason, count() AS sessions,
          any(concat(src_ip, ' → ', dst_ip, ':', toString(dst_port))) AS sample
        FROM ${db}.events WHERE ts >= now() - toIntervalMinute({m:UInt32}) AND src_type = 'paloalto' AND category = 'network' ${w.sql}
        GROUP BY firewall_ip, app, rule, action, reason ORDER BY sessions DESC LIMIT 100`, Object.assign({ m: { type: 'UInt32', value: lim(minutes, 120, 10080) } }, w.params));
    },
    async voiceFlows({ a, b, minutes = 120 } = {}) {
      const side = (v, k, params) => { const x = String(v || '').trim(); if (net.isIP(x)) { params[k] = S(x); return `{col} = {${k}:String}`; } if (CIDR.test(x)) { params[k] = S(x); return `isIPAddressInRange({col}, {${k}:String})`; } throw new Error(k + ' must be an IP address or subnet'); };
      const params = { m: { type: 'UInt32', value: lim(minutes, 120, 10080) } };
      const A = side(a, 'a', params), B = side(b, 'b', params), at = (c, x) => x.replace(/\{col\}/g, c);
      const rtp = `(lower(proto) IN ('udp','17') AND dst_port BETWEEN 1024 AND 65535 AND dst_port NOT IN (5060, 5061, 2000))`;
      const kind = `multiIf(dst_port IN (5060, 5061), 'sip', dst_port = 2000, 'sccp', ${rtp}, 'rtp', 'other')`;
      const dir = `multiIf(${at('src_ip', A)} AND ${at('dst_ip', B)}, 'a_to_b', ${at('src_ip', B)} AND ${at('dst_ip', A)}, 'b_to_a', ${at('src_ip', A)}, 'a_signalling', 'other')`;
      const oneway = `if(src_type = 'fortigate', toUInt64OrZero(fields['sentbyte']) > 0 AND toUInt64OrZero(fields['rcvdbyte']) = 0, toUInt64OrZero(fields['pkts_sent']) > 0 AND toUInt64OrZero(fields['pkts_received']) = 0)`;
      const nat = `if(src_type = 'fortigate', fields['transip'], fields['natsrc'])`;
      return q(`SELECT src_type AS vendor, any(host) AS firewall, host_ip AS firewall_ip, ${dir} AS direction, ${kind} AS kind, lower(action) AS action, count() AS sessions, countIf(${oneway}) AS oneway,
          uniqExact(dst_ip) AS peers, any(dst_ip) AS peer, any(${nat}) AS nat_ip, any(concat(src_ip, ':', toString(src_port), ' → ', dst_ip, ':', toString(dst_port))) AS sample, toString(max(ts)) AS last_seen
        FROM ${db}.events WHERE ts >= now() - toIntervalMinute({m:UInt32}) AND src_type IN ('fortigate','paloalto','silverpeak') AND category = 'network'
          AND ((${at('src_ip', A)} AND ${at('dst_ip', B)}) OR (${at('src_ip', B)} AND ${at('dst_ip', A)}) OR (${at('src_ip', A)} AND dst_port IN (5060, 5061, 2000)))
        GROUP BY vendor, firewall_ip, direction, kind, action ORDER BY sessions DESC LIMIT 200`, params);
    },
    async peakUtilByDay({ days = 30 } = {}) {
      return q(`SELECT device, key, toString(toDate(ts)) AS day, max(value) AS peak FROM ${db}.net_metrics
        WHERE metric = 'util_pct' AND ts >= now() - toIntervalDay({d:UInt32}) GROUP BY device, key, day ORDER BY device, key, day`, { d: { type: 'UInt32', value: lim(days, 30, 180) } });
    },
  };
}

module.exports = { createEvidence, LINK_RE, CFG_RE, DENY };
