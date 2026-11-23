// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA ClickHouse analytics — SQL builders. The heavy aggregation (per-entity-per-day numeric features + distinct
 * value sets) runs in ClickHouse; the small robust-stats / scoring layer runs in Node (engine/ueba/baseline.js,
 * risk.js). Geo/subnet derivation stays in Node (engine/ueba/geo.js) from the raw IP arrays this returns.
 *
 *   entityTypeExpr(settings)                     → SQL expression classifying lower(user) → 'ai_agent'|'service_account'|'user'
 *   dailyNumericSQL({ database, settings })      → per (entity_id, day) numeric features        (params: from, to)
 *   knownValuesSQL({ database, settings })       → per entity_id distinct value arrays + hour histogram (params: from, to)
 *   recentEventsSQL({ database })                → raw events for the detector window            (params: from, to, limit, offset)
 *
 * All time params are DateTime64(3,'UTC'); callers pass ISO 'YYYY-MM-DD HH:MM:SS.mmm'. Standard library only.
 */
const { PRIV_ACTIONS, BYTE_FIELDS, SCOPE_FIELDS } = require('./baseline');

function qlist(arr) { return '(' + (arr.length ? arr.map((s) => `'${String(s).replace(/'/g, "\\'")}'`).join(',') : "''") + ')'; }
function db(database) { return database || 'siem'; }

function entityTypeExpr(settings = {}) {
  const sa = settings.service_accounts || {};
  const agents = (settings.ai_agents && settings.ai_agents.identities) || [];
  const agentUsers = [];
  for (const a of agents) for (const u of (a.match && a.match.user) || []) agentUsers.push(String(u).toLowerCase());
  const svcNames = (sa.names || []).map((s) => String(s).toLowerCase());
  const patterns = (sa.patterns || []).map((p) => String(p));
  const svcRegex = patterns.length ? patterns.join('|') : '';
  const svcTerm = [];
  if (svcRegex) svcTerm.push(`match(lower(user), '${svcRegex.replace(/'/g, "\\'")}')`);
  if (svcNames.length) svcTerm.push(`lower(user) IN ${qlist(svcNames)}`);
  const svcCond = svcTerm.length ? svcTerm.join(' OR ') : '0';
  return `multiIf(lower(user) IN ${qlist(agentUsers)}, 'ai_agent', (${svcCond}), 'service_account', 'user')`;
}

// bytes sum expression over the known byte-carrying fields in the Map(String,String) `fields`
function bytesExpr() {
  return BYTE_FIELDS.map((k) => `toUInt64OrZero(fields['${k}'])`).join(' + ');
}
function privExpr() {
  return `(action IN ${qlist([...PRIV_ACTIONS])} OR has(tags, 'admin'))`;
}
function localHourExpr(settings) {
  const off = Number((settings && settings.timezone_offset_min) || 180);
  return `toHour(toDateTime(ts) + toIntervalMinute(${off}))`;
}
function dayExpr(settings) {
  const off = Number((settings && settings.timezone_offset_min) || 180);
  return `toInt64(intDiv(toUnixTimestamp64Milli(ts) + ${off * 60000}, 86400000))`;
}

// actor rows (grouped by classified user) UNION host rows (grouped by host)
function dailyNumericSQL({ database, settings } = {}) {
  const D = db(database);
  const type = entityTypeExpr(settings);
  const day = dayExpr(settings);
  const common = `
    count() AS events,
    countIf(category = 'authentication' AND (outcome = 'failure' OR action = 'logon-failed')) AS auth_fail,
    countIf(category = 'authentication' AND outcome = 'success') AS auth_success,
    sum(${bytesExpr()}) AS egress_bytes,
    countIf(${privExpr()}) AS privileged,
    toUnixTimestamp64Milli(min(ts)) AS first_ts,
    toUnixTimestamp64Milli(max(ts)) AS last_ts`;
  const actor = `
    SELECT concat(${type}, ':', lower(user)) AS entity_id, ${type} AS entity_type, lower(user) AS entity_name, ${day} AS day,
           ${common}, uniqExact(host) AS distinct_hosts
    FROM ${D}.events
    WHERE ts >= {from:DateTime64(3,'UTC')} AND ts < {to:DateTime64(3,'UTC')} AND user != '' AND action != 'agent-heartbeat'
    GROUP BY entity_id, entity_type, entity_name, day`;
  const host = `
    SELECT concat('host:', lower(host)) AS entity_id, 'host' AS entity_type, lower(host) AS entity_name, ${day} AS day,
           ${common}, uniqExact(dst_ip) AS distinct_hosts
    FROM ${D}.events
    WHERE ts >= {from:DateTime64(3,'UTC')} AND ts < {to:DateTime64(3,'UTC')} AND host != '' AND action != 'agent-heartbeat'
    GROUP BY entity_id, entity_type, entity_name, day`;
  return `${actor}\nUNION ALL${host}\nORDER BY entity_id, day`;
}

function hourHistExpr(settings) {
  const h = localHourExpr(settings);
  const parts = [];
  for (let i = 0; i < 24; i++) parts.push(`countIf(${h} = ${i})`);
  return `[${parts.join(', ')}]`;
}
function scopeArrayExpr() {
  // arrayFilter nonempty over the scope-ish fields joined per row, then groupUniqArrayArray
  const terms = SCOPE_FIELDS.map((k) => `if(fields['${k}'] != '', concat('${k}=', lower(fields['${k}'])), '')`);
  return `groupUniqArrayArray(arrayFilter(x -> x != '', [${terms.join(', ')}]))`;
}

function knownValuesSQL({ database, settings } = {}) {
  const D = db(database);
  const type = entityTypeExpr(settings);
  const hist = hourHistExpr(settings);
  const svc = `if(dst_port != 0, concat(if(proto != '', proto, 'tcp'), '/', toString(dst_port)), '')`;
  const common = `
    ${hist} AS hour_hist,
    arrayFilter(x -> x != '', groupUniqArray(upper(fields['country']))) AS countries,
    arrayFilter(x -> x != '', groupUniqArray(src_ip)) AS ips,
    arrayFilter(x -> x != '', groupUniqArray(${svc})) AS services,
    arrayFilter(x -> x != '', groupUniqArray(lower(process))) AS processes,
    arrayFilter(x -> x != '', groupUniqArray(lower(coalesce(fields['logon_type_name'], fields['logon_type'], '')))) AS logon_types,
    ${scopeArrayExpr()} AS api_scopes,
    arrayFilter(x -> x != '', groupUniqArray(action)) AS action_types`;
  const actor = `
    SELECT concat(${type}, ':', lower(user)) AS entity_id, ${type} AS entity_type, lower(user) AS entity_name,
           ${common},
           arrayFilter(x -> x != '', groupUniqArray(lower(host))) AS hosts,
           arrayFilter(x -> x != '', groupUniqArray(lower(coalesce(nullif(target_user,''), dst_ip, '')))) AS targets
    FROM ${D}.events
    WHERE ts >= {from:DateTime64(3,'UTC')} AND ts < {to:DateTime64(3,'UTC')} AND user != '' AND action != 'agent-heartbeat'
    GROUP BY entity_id, entity_type, entity_name`;
  const host = `
    SELECT concat('host:', lower(host)) AS entity_id, 'host' AS entity_type, lower(host) AS entity_name,
           ${common},
           arrayFilter(x -> x != '', groupUniqArray(dst_ip)) AS hosts,
           arrayFilter(x -> x != '', groupUniqArray(lower(coalesce(nullif(target_user,''), dst_ip, '')))) AS targets
    FROM ${D}.events
    WHERE ts >= {from:DateTime64(3,'UTC')} AND ts < {to:DateTime64(3,'UTC')} AND host != '' AND action != 'agent-heartbeat'
    GROUP BY entity_id, entity_type, entity_name`;
  return `${actor}\nUNION ALL${host}`;
}

// e.ts in the filter, not ts: the output ts is milliseconds, and a bare name means the alias (no rows were ever matched)
function recentEventsSQL({ database } = {}) {
  const D = db(database);
  return `
    SELECT toUnixTimestamp64Milli(e.ts) AS ts, toString(e.id) AS id, src_type, collector, host, host_ip, category, action,
           outcome, severity, user, target_user, domain, src_ip, dst_ip, dst_port, proto, process, tags, fields
    FROM ${D}.events AS e
    WHERE e.ts >= {from:DateTime64(3,'UTC')} AND e.ts < {to:DateTime64(3,'UTC')} AND action != 'agent-heartbeat'
    ORDER BY e.ts
    LIMIT {limit:UInt32} OFFSET {offset:UInt32}`;
}

module.exports = { entityTypeExpr, dailyNumericSQL, knownValuesSQL, recentEventsSQL, bytesExpr, privExpr };
