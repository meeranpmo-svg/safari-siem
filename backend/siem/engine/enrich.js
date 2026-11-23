// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Core enrichment stage (runs first in the pipeline). Cheap, in-memory only — no external lookups:
//   * tag "internet" when src_ip or dst_ip is a public address,
//   * asset lookups from config.enrich.assets [{ip, host?, tags?[]}] (fills host for events that lack one, adds tags),
//   * tag "admin" for users listed in config.enrich.admin_users.
//   * AD identity (optional `identity` = engine/ad/identity.js, filled by the AD sync): when ev.user / ev.target_user is a
//     directory account → fields user_dept, user_title, user_privileged, user_disabled, user_dormant, user_service_account,
//     user_last_logon (target_* for target_user, matched by fields.member_sid first) + tags ad-privileged (+ "admin", so
//     UEBA's admin sensitivity weights privileged users), ad-disabled, ad-dormant, service-account. Group-membership events
//     get fields.group_privileged. Flags are "1"/"0" strings (the events `fields` map is String→String).
const net = require('node:net');

const PRIVATE = new net.BlockList();
for (const [a, b] of [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['127.0.0.0', 8], ['169.254.0.0', 16], ['100.64.0.0', 10], ['0.0.0.0', 8], ['224.0.0.0', 3]]) PRIVATE.addSubnet(a, b, 'ipv4');
for (const [a, b] of [['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['::', 128]]) PRIVATE.addSubnet(a, b, 'ipv6');

function isPublic(ip) {
  if (!ip) return false;
  const fam = net.isIP(ip);
  if (!fam) return false;
  return !PRIVATE.check(ip, fam === 4 ? 'ipv4' : 'ipv6');
}

const GROUP_ACTIONS = new Set(['group-member-added', 'group-member-removed']);
function addTag(ev, t) { if (!ev.tags.includes(t)) ev.tags.push(t); }

function identityFields(ev, identity, rec, prefix) {
  const f = identity.flags(rec);
  const x = ev.fields;
  if (rec.dept) x[prefix + 'dept'] = rec.dept;
  if (rec.title) x[prefix + 'title'] = rec.title;
  x[prefix + 'privileged'] = f.privileged ? '1' : '0';
  x[prefix + 'disabled'] = f.disabled ? '1' : '0';
  x[prefix + 'dormant'] = f.dormant ? '1' : '0';
  if (rec.last_logon) x[prefix + 'last_logon'] = new Date(rec.last_logon).toISOString();
  if (f.privileged) { addTag(ev, 'ad-privileged'); addTag(ev, 'admin'); }
  if (f.disabled) addTag(ev, 'ad-disabled');
  if (f.dormant) addTag(ev, 'ad-dormant');
}

function enrichIdentity(ev, identity) {
  if (!ev.fields || typeof ev.fields !== 'object') ev.fields = {};
  if (ev.user) {
    const u = identity.lookup(ev.user, ev.domain);
    if (u) identityFields(ev, identity, u, 'user_');
    if (identity.isServiceName(ev.user)) { ev.fields.user_service_account = '1'; addTag(ev, 'service-account'); }   // pattern match, AD or not
  }
  if (ev.target_user || ev.fields.member_sid) {
    const t = identity.lookupSid(ev.fields.member_sid) || (ev.target_user && ev.target_user !== ev.user ? identity.lookup(ev.target_user, '') : null);
    if (t) identityFields(ev, identity, t, 'target_');
  }
  if (GROUP_ACTIONS.has(ev.action) && (ev.fields.group || ev.fields.TargetSid)) {
    ev.fields.group_privileged = identity.isPrivilegedGroup(ev.fields.group, ev.fields.TargetSid || ev.fields.group_sid) ? '1' : '0';
  }
}

function createEnricher({ config = {}, identity = null } = {}) {
  const en = config.enrich || {};
  const assets = new Map();
  for (const a of en.assets || []) if (a && a.ip) assets.set(String(a.ip).toLowerCase(), { host: a.host || '', tags: Array.isArray(a.tags) ? a.tags.map(String) : [] });
  const admins = new Set((en.admin_users || []).map((u) => String(u).toLowerCase()));
  const pubCache = new Map();

  function pub(ip) {
    if (!ip) return false;
    let v = pubCache.get(ip);
    if (v === undefined) { v = isPublic(ip); if (pubCache.size > 100000) pubCache.clear(); pubCache.set(ip, v); }
    return v;
  }

  return function enrich(ev) {
    if (!Array.isArray(ev.tags)) ev.tags = [];
    if ((pub(ev.src_ip) || pub(ev.dst_ip)) && !ev.tags.includes('internet')) ev.tags.push('internet');
    if (assets.size) {
      const a = assets.get(ev.host_ip);
      if (a) { if (!ev.host && a.host) ev.host = a.host; for (const t of a.tags) if (!ev.tags.includes(t)) ev.tags.push(t); }
    }
    if (admins.size && (admins.has(ev.user) || admins.has(ev.target_user)) && !ev.tags.includes('admin')) ev.tags.push('admin');
    if (identity && (ev.user || ev.target_user) && ev.action !== 'agent-heartbeat') enrichIdentity(ev, identity);
  };
}

module.exports = { createEnricher, isPublic };
