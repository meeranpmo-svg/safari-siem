// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cloudflare records pulled by collect/cloudflare.js (objects tagged with _cf):
//   _cf = 'audit'     account audit log (API v4 /accounts/:id/audit_logs): who changed what (DNS, WAF, SSL, members, API tokens)
//   _cf = 'security'  security / firewall events (GraphQL firewallEventsAdaptive): WAF, rate limiting, bot, IP rules -
//                     the request that was blocked / challenged / logged, client IP, country, host, path, rule
// Both are also accepted as JSON lines (Logpush-style) when the _cf marker is present.
const { parseTime, ipOrEmpty, safeJson, clean } = require('./util');

const SEC_SEV = { block: 2, challenge: 1, jschallenge: 1, managed_challenge: 1, challenge_failed: 2, jschallenge_failed: 2, managed_challenge_failed: 2, drop: 2, log: 0, allow: 0, skip: 0, bypass: 0 };
const AUDIT_SENSITIVE = /token|member|role|ssl|certificate|firewall|waf|ruleset|access|zone_delete|dns|page_rule|account_settings|logpush|api_key|two_factor|2fa/i;

function audit(o) {
  const act = o.action || {}, actor = o.actor || {}, res = o.resource || {};
  const type = clean(act.type || '').toLowerCase(), ok = act.result !== false;
  const sensitive = AUDIT_SENSITIVE.test(`${type} ${res.type || ''}`);
  return {
    src_type: 'cloudflare', ts: parseTime(o.when), category: /login/.test(type) ? 'authentication' : 'cloud', action: type || 'change', outcome: ok ? 'success' : 'failure',
    user: clean(actor.email || actor.id || '').toLowerCase(), src_ip: ipOrEmpty(actor.ip), host: 'cloudflare', severity: !ok && /login/.test(type) ? 1 : sensitive ? 1 : 0,
    tags: ['cloudflare', 'cloudflare-audit'].concat(sensitive ? ['config-change'] : []),
    message: `Cloudflare: ${actor.email || actor.type || 'someone'} ${type || 'changed'} ${res.type || ''} ${(o.metadata && (o.metadata.zone_name || o.metadata.name)) || res.id || ''}${ok ? '' : ' (failed)'}`.replace(/\s+/g, ' ').trim().slice(0, 300),
    fields: { cf_type: 'audit', audit_id: clean(o.id), actor_type: clean(actor.type), resource_type: clean(res.type), resource_id: clean(res.id), zone: clean(o.metadata && o.metadata.zone_name), interface: clean(o.interface),
      new_value: o.newValue == null ? undefined : String(typeof o.newValue === 'object' ? JSON.stringify(o.newValue) : o.newValue).slice(0, 500),
      old_value: o.oldValue == null ? undefined : String(typeof o.oldValue === 'object' ? JSON.stringify(o.oldValue) : o.oldValue).slice(0, 500) },
  };
}

function security(o) {
  const action = clean(o.action || '').toLowerCase(), host = clean(o.clientRequestHTTPHost || o.host || '').toLowerCase(), pathq = clean(o.clientRequestPath || '') + (o.clientRequestQuery ? clean(o.clientRequestQuery) : '');
  const blocked = /block|drop|failed/.test(action);
  return {
    src_type: 'cloudflare', ts: parseTime(o.datetime), category: 'web', action: action || 'event', outcome: blocked ? 'failure' : /challenge/.test(action) ? 'unknown' : 'success',   // the request was denied / challenged / let through
    src_ip: ipOrEmpty(o.clientIP), url: host ? `https://${host}${pathq}`.slice(0, 2000) : pathq.slice(0, 2000), http_method: clean(o.clientRequestHTTPMethodName || '').toUpperCase(),
    user_agent: clean(o.userAgent || '').slice(0, 500), host: host || 'cloudflare', severity: SEC_SEV[action] !== undefined ? SEC_SEV[action] : 1,
    tags: ['cloudflare', 'cloudflare-security'].concat(blocked ? ['blocked'] : []),
    message: `Cloudflare ${clean(o.source || 'security')} ${action || 'event'}: ${o.clientIP || '?'}${o.clientCountryName ? ' (' + o.clientCountryName + ')' : ''} → ${host}${clean(o.clientRequestPath || '')}`.slice(0, 300),
    fields: { cf_type: 'security', source: clean(o.source), rule_id: clean(o.ruleId), ray: clean(o.rayName), country: clean(o.clientCountryName), asn: o.clientAsn == null ? undefined : String(o.clientAsn),
      asn_name: clean(o.clientASNDescription), zone: clean(o._zone), edge_status: o.edgeResponseStatus == null ? undefined : String(o.edgeResponseStatus), description: clean(o.description || '').slice(0, 200) },
  };
}

function parse(line, meta = {}) {
  const o = meta.obj || safeJson(line);
  if (!o || Array.isArray(o)) return null;
  if (o._cf === 'audit' || (o._cf === undefined && o.when !== undefined && o.action && o.actor && o.resource)) return audit(o);
  if (o._cf === 'security' || (o._cf === undefined && o.rayName !== undefined && o.datetime !== undefined && o.clientIP !== undefined)) return security(o);
  return null;
}

module.exports = {
  name: 'cloudflare',
  sniff(line, meta = {}) { const o = meta.obj || safeJson(line); return !!o && (o._cf === 'audit' || o._cf === 'security' || (o.rayName !== undefined && o.datetime !== undefined && o.clientIP !== undefined)); },
  parse,
};
