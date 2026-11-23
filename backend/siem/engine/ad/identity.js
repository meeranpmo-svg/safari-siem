// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AD identity store — the latest directory snapshot held in memory for enrichment (per event, Map lookups only) and the
 * identity API. Filled by engine/ad/sync.js; persisted to <state_dir>/ad-identity.json (mode 600) so enrichment works
 * right after a restart, before the first sync of the new process.
 *
 *   createIdentity({ file, dormantDays = 90, servicePatterns = ['svc-*'], netbios = [], privilegedNames = [], now })
 *     → { load(), replace(snapshot), lookup(name, domain?), lookupSid(sid), isPrivilegedGroup(name, sid), isServiceName(name),
 *         flags(rec), size(), meta(), summary(), list(q), snapshot() }
 *
 * snapshot = { synced, server, baseDN, dnsDomain, netbios[], users: [rec], groups: [{dn, sam, sid, privileged, members:[{sam, dn, nested}]}] }
 * rec      = { sam, upn, name, mail, dept, title, manager, dn, cn, sid, uac, disabled, admin_count, privileged, priv_groups[],
 *              member_of[], last_logon, pwd_last_set, created, expires }   (times: epoch ms, 0 = never / unknown)
 * Audit flags from userAccountControl (uac): pwd_never_expires 0x10000, pwd_not_required 0x20, no_preauth 0x400000 (AS-REP
 * roastable), delegation 0x80000 (trusted for unconstrained delegation); counted for enabled accounts only.
 * "dormant" and "service account" are derived at lookup time (dormant_days / patterns can change without a re-sync).
 */
const fs = require('fs');

const DAY = 86400000;
// well-known privileged groups: builtin RIDs (S-1-5-32-x) and domain RIDs (S-1-5-21-…-x)
const BUILTIN_PRIV_RIDS = new Set(['544', '548', '549', '551']);            // Administrators, Account/Server/Backup Operators
const DOMAIN_PRIV_RIDS = new Set(['512', '518', '519', '520']);             // Domain/Schema/Enterprise Admins, GP Creator Owners
const DEFAULT_PRIVILEGED = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators',
  'Backup Operators', 'Server Operators', 'Group Policy Creator Owners'];

function globRe(patterns) {
  const parts = [].concat(patterns || []).map(String).filter(Boolean)
    .map((p) => p.toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.'));
  return parts.length ? new RegExp('^(?:' + parts.join('|') + ')$') : null;
}

function createIdentity({ file = '', dormantDays = 90, servicePatterns = ['svc-*', 'svc_*'], netbios = [], privilegedNames = [], now = Date.now } = {}) {
  let snap = { synced: 0, users: [], groups: [] };
  let byKey = new Map();          // sam / upn / dn / sid → rec   (lower-case)
  let byCn = new Map();           // cn → rec (only when the cn is unique)
  let domains = new Set();
  let privGroups = new Set();     // lower-case sam / cn of privileged groups
  const svcRe = globRe(servicePatterns);
  const dormantMs = Math.max(1, Number(dormantDays) || 90) * DAY;
  const extraPriv = [].concat(privilegedNames || []).map(String);

  function index() {
    byKey = new Map(); byCn = new Map();
    const cnSeen = new Map();
    for (const r of snap.users) {
      for (const k of [r.sam, r.upn, r.dn, r.sid]) if (k) byKey.set(String(k).toLowerCase(), r);
      if (r.cn) { const c = r.cn.toLowerCase(); cnSeen.set(c, (cnSeen.get(c) || 0) + 1); byCn.set(c, r); }
    }
    for (const [c, n] of cnSeen) if (n > 1) byCn.delete(c);
    domains = new Set([].concat(netbios, snap.netbios || [], snap.dnsDomain ? [snap.dnsDomain, snap.dnsDomain.split('.')[0]] : []).filter(Boolean).map((d) => String(d).toLowerCase()));
    privGroups = new Set(DEFAULT_PRIVILEGED.concat(extraPriv.filter((x) => x.indexOf('=') < 0)).map((x) => x.toLowerCase()));
    for (const g of snap.groups || []) if (g.privileged) { if (g.sam) privGroups.add(g.sam.toLowerCase()); if (g.dn) privGroups.add(g.dn.toLowerCase()); }
  }
  index();

  function load() {
    if (!file) return false;
    try { const s = JSON.parse(fs.readFileSync(file, 'utf8')); if (s && Array.isArray(s.users)) { snap = s; index(); return true; } } catch { /* first run / unreadable */ }
    return false;
  }
  function replace(s) {
    snap = s; index();
    if (file) { const tmp = file + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(s), { mode: 0o600 }); fs.renameSync(tmp, file); }
  }

  // "CORP-HQ\alice" | "alice@the organisation" | "alice" (+ the event's domain field) → rec | null
  function lookup(name, domain) {
    let n = String(name || '').trim().toLowerCase();
    if (!n || !snap.users.length) return null;
    let d = String(domain || '').trim().toLowerCase();
    const bs = n.indexOf('\\');
    if (bs >= 0) { d = n.slice(0, bs); n = n.slice(bs + 1); }
    if (d && domains.size && !domains.has(d)) return null;             // a local / foreign account with the same name
    const hit = byKey.get(n);
    if (hit) return hit;
    const at = n.lastIndexOf('@');
    if (at > 0 && domains.has(n.slice(at + 1))) return byKey.get(n.slice(0, at)) || null;
    return byCn.get(n) || null;
  }
  function lookupSid(sid) { return sid ? byKey.get(String(sid).toLowerCase()) || null : null; }
  function isPrivilegedGroup(name, sid) {
    const s = String(sid || '').toUpperCase();
    let m = /^S-1-5-32-(\d+)$/.exec(s);
    if (m && BUILTIN_PRIV_RIDS.has(m[1])) return true;
    m = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/.exec(s);
    if (m && DOMAIN_PRIV_RIDS.has(m[1])) return true;
    const n = String(name || '').trim().toLowerCase();
    return !!n && privGroups.has(n.indexOf('\\') >= 0 ? n.slice(n.indexOf('\\') + 1) : n);
  }
  function isServiceName(name) {
    if (!svcRe) return false;
    let n = String(name || '').trim().toLowerCase();
    if (n.indexOf('\\') >= 0) n = n.slice(n.indexOf('\\') + 1);
    if (n.indexOf('@') > 0) n = n.slice(0, n.indexOf('@'));
    return svcRe.test(n);
  }
  function flags(r, t = now()) {
    const ref = r.last_logon || r.created || 0;
    return {
      disabled: !!r.disabled,
      privileged: !!r.privileged,
      dormant: !r.disabled && ref > 0 && t - ref > dormantMs,
      service_account: isServiceName(r.sam),
      expired: !!(r.expires && r.expires <= t),
    };
  }
  function view(r, t) {
    const f = flags(r, t), uac = Number(r.uac) || 0;
    return { sam: r.sam, upn: r.upn, name: r.name, mail: r.mail, department: r.dept, title: r.title, manager: r.manager, dn: r.dn,
      privileged: f.privileged, privileged_groups: r.priv_groups || [], disabled: f.disabled, dormant: f.dormant, expired: f.expired,
      service_account: f.service_account, admin_count: r.admin_count || 0, admin_orphan: !!(r.admin_count && !f.privileged),
      pwd_never_expires: !!(uac & 0x10000), pwd_not_required: !!(uac & 0x20), no_preauth: !!(uac & 0x400000), delegation: !!(uac & 0x80000),
      pwd_age_days: r.pwd_last_set ? Math.floor((t - r.pwd_last_set) / DAY) : null, never_logon: !r.last_logon,
      last_logon: r.last_logon ? new Date(r.last_logon).toISOString() : null, pwd_last_set: r.pwd_last_set ? new Date(r.pwd_last_set).toISOString() : null,
      created: r.created ? new Date(r.created).toISOString() : null, expires: r.expires ? new Date(r.expires).toISOString() : null };
  }
  const truthy = (v) => v === true || v === '1' || v === 'true' || v === 1;
  function list(q = {}) {
    const t = now();
    let rows = snap.users.map((r) => view(r, t));
    if (q.privileged !== undefined && q.privileged !== '') rows = rows.filter((r) => r.privileged === truthy(q.privileged));
    if (q.disabled !== undefined && q.disabled !== '') rows = rows.filter((r) => r.disabled === truthy(q.disabled));
    if (q.dormant !== undefined && q.dormant !== '') rows = rows.filter((r) => r.dormant === truthy(q.dormant));
    if (q.service !== undefined && q.service !== '') rows = rows.filter((r) => r.service_account === truthy(q.service));
    // audit flags (enabled accounts only, except admin_orphan / expired): ?flag=pwd_never_expires|pwd_not_required|no_preauth|delegation|old_pwd|never_logon|admin_orphan|expired
    if (q.flag) {
      const old = Math.max(1, parseInt(q.pwd_days, 10) || 365), fl = String(q.flag);
      const test = { old_pwd: (r) => !r.disabled && r.pwd_age_days !== null && r.pwd_age_days > old, admin_orphan: (r) => r.admin_orphan, expired: (r) => r.expired }[fl] || ((r) => !r.disabled && !!r[fl]);
      rows = rows.filter(test);
    }
    if (q.department) { const d = String(q.department).toLowerCase(); rows = rows.filter((r) => String(r.department || '').toLowerCase() === d); }
    if (q.q) { const s = String(q.q).toLowerCase(); rows = rows.filter((r) => [r.sam, r.upn, r.name, r.mail, r.title, r.department].some((x) => String(x || '').toLowerCase().includes(s))); }
    rows.sort((a, b) => (a.sam < b.sam ? -1 : a.sam > b.sam ? 1 : 0));
    const limit = Math.min(1000, Math.max(1, parseInt(q.limit, 10) || 100));
    const offset = Math.max(0, parseInt(q.offset, 10) || 0);
    return { total: rows.length, synced: snap.synced ? new Date(snap.synced).toISOString() : null, items: rows.slice(offset, offset + limit) };
  }
  function summary() {
    const t = now();
    const c = { users: 0, enabled: 0, disabled: 0, privileged: 0, privileged_enabled: 0, dormant: 0, dormant_privileged: 0, service_accounts: 0, expired: 0, admin_count_orphans: 0,
      pwd_never_expires: 0, pwd_not_required: 0, no_preauth: 0, delegation: 0, old_pwd: 0, never_logon: 0, privileged_pwd_never_expires: 0 };
    const depts = new Map();
    for (const r of snap.users) {
      const f = flags(r, t);
      c.users++; if (f.disabled) c.disabled++; else c.enabled++;
      if (f.privileged) { c.privileged++; if (!f.disabled) c.privileged_enabled++; }
      if (f.dormant) { c.dormant++; if (f.privileged) c.dormant_privileged++; }
      if (f.service_account) c.service_accounts++;
      if (f.expired) c.expired++;
      if (r.admin_count && !f.privileged) c.admin_count_orphans++;      // adminCount=1 but no longer in a protected group (AdminSDHolder leftovers)
      const uac = Number(r.uac) || 0;
      if (!f.disabled) {
        if (uac & 0x10000) c.pwd_never_expires++;
        if (uac & 0x20) c.pwd_not_required++;
        if (uac & 0x400000) c.no_preauth++;
        if (uac & 0x80000) c.delegation++;
        if (r.pwd_last_set && t - r.pwd_last_set > 365 * DAY) c.old_pwd++;
        if (!r.last_logon) c.never_logon++;
        if ((uac & 0x10000) && f.privileged) c.privileged_pwd_never_expires++;
      }
      if (r.dept) depts.set(r.dept, (depts.get(r.dept) || 0) + 1);
    }
    return {
      synced: snap.synced ? new Date(snap.synced).toISOString() : null, server: snap.server || '', base_dn: snap.baseDN || '', domain: snap.dnsDomain || '',
      netbios: snap.netbios || [], dormant_days: dormantMs / DAY, counts: c,
      privileged_groups: (snap.groups || []).filter((g) => g.privileged).map((g) => ({ name: g.sam, dn: g.dn, members: (g.members || []).length, nested_members: (g.members || []).filter((m) => m.nested).length })),
      departments: [...depts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([name, users]) => ({ name, users })),
    };
  }
  // Non-Human Identities in the directory: managed service accounts (gMSA / sMSA), user accounts with a service principal name
  // (they run a service and are Kerberoastable) and accounts matching the service-name patterns. People are never listed here:
  // an account is included only for one of those three reasons, and the reason is given.
  function nhi(t = now()) {
    const out = [];
    for (const r of snap.users) {
      const why = [];
      if (isServiceName(r.sam)) why.push('name pattern');
      if (r.spn && r.spn.length) why.push('service principal name');
      if (!why.length) continue;
      const v = view(r, t);
      out.push({ source: 'ad', kind: 'service_user', id: 'ad:' + r.sam, name: r.sam, upn: r.upn || '', why, description: r.desc || '', spn: r.spn || [],
        privileged: v.privileged, privileged_groups: v.privileged_groups, disabled: v.disabled, dormant: v.dormant, pwd_never_expires: v.pwd_never_expires,
        pwd_not_required: v.pwd_not_required, no_preauth: v.no_preauth, delegation: v.delegation, pwd_age_days: v.pwd_age_days, never_logon: v.never_logon,
        last_logon: v.last_logon, pwd_last_set: v.pwd_last_set, created: v.created, managed: false });
    }
    for (const m of snap.managed || []) {
      const ref = m.last_logon || m.created || 0;
      out.push({ source: 'ad', kind: m.kind, id: 'ad:' + m.sam, name: m.sam, upn: '', why: [m.kind === 'gmsa' ? 'group managed service account' : 'managed service account'], description: m.desc || '',
        spn: m.spn || [], privileged: !!m.privileged, privileged_groups: m.priv_groups || [], disabled: !!m.disabled, dormant: !m.disabled && ref > 0 && t - ref > dormantMs,
        pwd_never_expires: false, pwd_not_required: false, no_preauth: false, delegation: !!((Number(m.uac) || 0) & 0x80000),
        pwd_age_days: m.pwd_last_set ? Math.floor((t - m.pwd_last_set) / DAY) : null, never_logon: !m.last_logon, last_logon: m.last_logon ? new Date(m.last_logon).toISOString() : null,
        pwd_last_set: m.pwd_last_set ? new Date(m.pwd_last_set).toISOString() : null, created: m.created ? new Date(m.created).toISOString() : null, managed: true, pwd_interval_days: m.pwd_interval_days || null, host: m.host || '' });
    }
    return { synced: snap.synced ? new Date(snap.synced).toISOString() : null, managed_read: Array.isArray(snap.managed), service_patterns: [].concat(servicePatterns || []), accounts: out.sort((a, b) => (a.name < b.name ? -1 : 1)) };
  }
  return {
    load, replace, lookup, lookupSid, isPrivilegedGroup, isServiceName, flags, list, summary, nhi,
    size: () => snap.users.length, snapshot: () => snap,
    meta: () => ({ synced: snap.synced || 0, users: snap.users.length, groups: (snap.groups || []).length, server: snap.server || '' }),
  };
}

module.exports = { createIdentity, DEFAULT_PRIVILEGED, globRe };
