// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * AD identity sync — periodic, READ-ONLY pull of users and privileged groups from on-prem Active Directory over LDAPS.
 *
 *   createAdSync({ config, identity, ch?, pipeline?, log?, now?, ldap? }) → { syncNow(reason), start(), stop(), status(), problems(), reconfigure() }
 *
 * Every config.ad.sync_minutes (default 60): service bind (secrets.json ad.bind_password) → NetBIOS name from the
 * partitions container → privileged groups (built-in admin groups + ad.privileged_groups, by name or DN) → all users
 * (paged, 1000 per page) → for each privileged group the users in it through any nesting (LDAP_MATCHING_RULE_IN_CHAIN)
 * plus users whose primaryGroupID is the group's RID → snapshot.
 * The snapshot replaces the in-memory identity store (engine/ad/identity.js → enrichment + API), is mirrored to ClickHouse
 * (siem.identity_users / identity_groups / identity_sync; ReplacingMergeTree, query with FINAL) and diffed against the
 * previous one: a member of a privileged group that was not there at the previous sync becomes an event
 * (src_type "ad", event_code AD-SYNC-PRIV-NEW → rule SENTRA-AD-004); a removed one AD-SYNC-PRIV-REMOVED (informational).
 * Nothing is ever written to AD. The bind password is never logged.
 */
const fs = require('fs');
const path = require('path');
const ldapDefault = require('./ldap-client');
const { finalise } = require('../schema');
const { DEFAULT_PRIVILEGED } = require('./identity');

const USER_ATTRS = ['sAMAccountName', 'userPrincipalName', 'displayName', 'mail', 'department', 'title', 'manager', 'memberOf',
  'userAccountControl', 'adminCount', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'accountExpires', 'objectSid', 'primaryGroupID',
  'servicePrincipalName', 'description'];
// managed service accounts (gMSA / sMSA): not "person" objects, so the user search misses them - read for Non-Human Identities
const MSA_ATTRS = ['sAMAccountName', 'servicePrincipalName', 'memberOf', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'description',
  'objectSid', 'objectClass', 'msDS-ManagedPasswordInterval', 'dNSHostName'];
const POLICY_ATTRS = ['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge', 'pwdProperties', 'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow', 'msDS-Behavior-Version'];
// AD stores ages as negative 100-ns intervals ("-9223372036854775808" / 0 = never): → days / minutes, null = never
function policyOf(get) {
  const int = (n) => { const v = get(n); if (v === undefined || v === null || v === '') return null; const x = Number(v); return Number.isFinite(x) ? x : null; };
  const span = (n, unit) => { const v = get(n); if (v === undefined || v === null || v === '') return null; let b; try { b = BigInt(v); } catch (e) { return null; /* not a number: treated as not readable */ }
    if (b === 0n || b <= -9223372036854775000n) return 0; return Math.round(Number(-b) / 1e7 / unit); };
  const props = int('pwdProperties');
  return { min_length: int('minPwdLength'), history: int('pwdHistoryLength'), max_age_days: span('maxPwdAge', 86400), min_age_days: span('minPwdAge', 86400),
    complexity: props === null ? null : !!(props & 1), reversible: props === null ? null : !!(props & 16), lockout_threshold: int('lockoutThreshold'),
    lockout_minutes: span('lockoutDuration', 60), lockout_window_minutes: span('lockOutObservationWindow', 60), functional_level: int('msDS-Behavior-Version') };
}
const EX_ROLES = { 2: 'mailbox', 4: 'client access', 16: 'unified messaging', 32: 'hub transport', 64: 'edge transport' };
const chTime = (ms) => new Date(ms > 0 ? ms : 0).toISOString().replace('T', ' ').replace('Z', '');

function buildRows(snap, prev, syncedMs) {
  const synced = chTime(syncedMs);
  const users = snap.users.map((r) => ({
    sam: r.sam, upn: r.upn || '', display_name: r.name || '', mail: r.mail || '', department: r.dept || '', title: r.title || '',
    manager: r.manager || '', dn: r.dn, sid: r.sid || '', member_of: r.member_of || [], uac: r.uac || 0, disabled: r.disabled ? 1 : 0,
    admin_count: r.admin_count ? 1 : 0, privileged: r.privileged ? 1 : 0, privileged_groups: r.priv_groups || [],
    last_logon: chTime(r.last_logon), pwd_last_set: chTime(r.pwd_last_set), created: chTime(r.created), expires: chTime(r.expires),
    deleted: 0, synced,
  }));
  const now = new Set(snap.users.map((r) => r.sam));
  for (const r of (prev && prev.users) || []) if (!now.has(r.sam)) users.push({ sam: r.sam, upn: r.upn || '', display_name: r.name || '', dn: r.dn, deleted: 1, synced });
  const groups = [];
  for (const g of snap.groups) for (const m of g.members) groups.push({ group_dn: g.dn, group_sam: g.sam, group_sid: g.sid || '', member_sam: m.sam, member_dn: m.dn, nested: m.nested ? 1 : 0, privileged: g.privileged ? 1 : 0, removed: 0, synced });
  for (const g of (prev && prev.groups) || []) {
    const cur = snap.groups.find((x) => x.dn.toLowerCase() === g.dn.toLowerCase());
    const have = new Set(cur ? cur.members.map((m) => m.sam) : []);
    for (const m of g.members) if (!have.has(m.sam)) groups.push({ group_dn: g.dn, group_sam: g.sam, group_sid: g.sid || '', member_sam: m.sam, member_dn: m.dn, nested: m.nested ? 1 : 0, privileged: g.privileged ? 1 : 0, removed: 1, synced });
  }
  return { users, groups };
}

/* membership changes of privileged groups between two snapshots (only for groups present in both) */
function diffPrivileged(prev, snap) {
  const out = [];
  if (!prev || !prev.synced) return out;
  for (const g of snap.groups) {
    if (!g.privileged) continue;
    const old = (prev.groups || []).find((x) => x.privileged && x.dn.toLowerCase() === g.dn.toLowerCase());
    if (!old) continue;
    const before = new Set(old.members.map((m) => m.sam)), after = new Set(g.members.map((m) => m.sam));
    for (const m of g.members) if (!before.has(m.sam)) out.push({ kind: 'added', group: g, member: m });
    for (const m of old.members) if (!after.has(m.sam)) out.push({ kind: 'removed', group: g, member: m });
  }
  return out;
}

function createAdSync({ config, identity, ch = null, pipeline = null, log = null, now = Date.now, ldap = ldapDefault } = {}) {
  const ad = Object.assign({}, (config && config.ad) || {});
  const secrets = (config && config.secrets) || {};
  const stateDir = (config && config.state_dir) || '';
  const statusFile = stateDir ? path.join(stateDir, 'ad-sync-status.json') : '';
  const L = log || { info() {}, warn() {}, error() {}, debug() {} };
  let timer = null, first = null, running = null, nextAt = 0;
  let last = null;
  try { if (statusFile) last = JSON.parse(fs.readFileSync(statusFile, 'utf8')); } catch { /* none yet */ }

  function password() { return (secrets.ad && secrets.ad.bind_password) || ''; }
  function problems() {
    const p = [];
    if (!ad.enabled) p.push('ad.enabled is false');
    if (!Array.isArray(ad.servers) || !ad.servers.length) p.push('ad.servers is empty');
    if (!ad.caFile) p.push('ad.caFile is not set');
    if (!ad.baseDN) p.push('ad.baseDN is not set');
    if (!ad.bindDN) p.push('ad.bindDN is not set');
    if (!password()) p.push('secrets.json ad.bind_password is not set (sudo sentra-siem-ad set-password)');
    return p;
  }
  function client() {
    return ldap.createClient({ servers: ad.servers, caFile: ad.caFile, timeoutMs: ad.timeout_ms || 15000,
      log: (lvl, msg, meta) => { const f = L[lvl] || L.info; f.call(L, msg, meta); } });
  }

  // The Exchange organisation's own list of its servers: every Exchange server is an msExchExchangeServer object under
  // CN=Microsoft Exchange,CN=Services in the configuration partition (readable by Domain Users) with its FQDN, version and
  // roles. null = no Exchange organisation in this forest (or not readable); [] = an organisation with no server objects.
  async function exchangeServers(conn, cfgNc, A) {
    try {
      const r = await conn.search('CN=Microsoft Exchange,CN=Services,' + cfgNc, { scope: 'sub', filter: '(objectClass=msExchExchangeServer)', attributes: ['cn', 'networkAddress', 'serialNumber', 'msExchCurrentServerRoles'], pageSize: 500, maxEntries: 500 });
      return r.entries.map((e) => {
        const na = A.all(e, 'networkAddress').map(String), fq = (na.find((x) => /^ncacn_ip_tcp:/i.test(x)) || '').slice(13).toLowerCase();
        const bits = parseInt(A.first(e, 'msExchCurrentServerRoles'), 10) || 0, roles = Object.entries(EX_ROLES).filter(([b]) => bits & Number(b)).map(([, n]) => n);
        return { name: String(A.first(e, 'cn') || '').slice(0, 64), fqdn: fq.slice(0, 255), version: String(A.first(e, 'serialNumber') || '').slice(0, 60), roles };
      }).filter((x) => x.name);
    } catch (e) { if (e.transport) throw e; L.debug('ad sync: no Exchange organisation readable', { err: e.message }); return null; }
  }

  async function pull(conn) {
    const A = ldap.ad, esc = ldap.escapeFilter, base = ad.baseDN, page = ad.page_size || 1000;
    await conn.bind(ad.bindDN, password());
    // NetBIOS / DNS name of the domain (best effort — needs read access to the configuration partition, which Domain Users have)
    let netbios = [], exchange = null, dnsDomain = base.split(',').filter((p) => /^dc=/i.test(p.trim())).map((p) => p.trim().slice(3)).join('.').toLowerCase();
    try {
      const root = await conn.rootDSE(['configurationNamingContext', 'dnsHostName']);
      const cfgNc = root && A.first(root, 'configurationNamingContext');
      if (cfgNc) {
        const r = await conn.search('CN=Partitions,' + cfgNc, { scope: 'one', filter: `(&(objectClass=crossRef)(nCName=${esc(base)}))`, attributes: ['nETBIOSName', 'dnsRoot'] });
        if (r.entries[0]) { netbios = A.all(r.entries[0], 'nETBIOSName'); dnsDomain = (A.first(r.entries[0], 'dnsRoot') || dnsDomain).toLowerCase(); }
        exchange = await exchangeServers(conn, cfgNc, A);
      }
    } catch (e) { if (e.transport) throw e; L.debug('ad sync: NetBIOS name not readable', { err: e.message }); }
    // the domain's default password and lockout policy (attributes of the domain head, readable by Domain Users) - for the
    // AI auditors (CIS / SAMA 3.3.5 / NCA 2-2); fine-grained password policies are not read. Best effort.
    let policy = null;
    try {
      const r = await conn.search(base, { scope: 'base', filter: '(objectClass=domain)', attributes: POLICY_ATTRS });
      if (r.entries[0]) policy = policyOf((n) => A.first(r.entries[0], n));
    } catch (e) { if (e.transport) throw e; L.debug('ad sync: domain password policy not readable', { err: e.message }); }
    // privileged groups
    const wanted = DEFAULT_PRIVILEGED.concat([].concat(ad.privileged_groups || []).map(String));
    const names = wanted.filter((x) => x.indexOf('=') < 0), dns = wanted.filter((x) => x.indexOf('=') >= 0);
    const gattrs = ['sAMAccountName', 'cn', 'objectSid', 'distinguishedName'];
    const found = new Map();
    const gr = await conn.search(base, { scope: 'sub', filter: `(&(objectClass=group)(|${names.map((n) => `(sAMAccountName=${esc(n)})`).join('')}))`, attributes: gattrs, pageSize: page });
    for (const e of gr.entries) found.set(e.dn.toLowerCase(), e);
    for (const dn of dns) {
      try { const r = await conn.search(dn, { scope: 'base', filter: '(objectClass=group)', attributes: gattrs }); if (r.entries[0]) found.set(r.entries[0].dn.toLowerCase(), r.entries[0]); else L.warn('ad sync: privileged group is not a group', { dn }); }
      catch (e) { if (e.transport) throw e; L.warn('ad sync: privileged group not found', { dn, err: e.message }); }
    }
    // users
    const uf = `(&(objectCategory=person)(objectClass=user)${ad.user_filter ? (ad.user_filter.trim().startsWith('(') ? ad.user_filter.trim() : '(' + ad.user_filter.trim() + ')') : ''})`;
    const ur = await conn.search(base, { scope: 'sub', filter: uf, attributes: USER_ATTRS, pageSize: page, maxEntries: 1000000 });
    const users = [], bySam = new Map(), byDn = new Map();
    for (const e of ur.entries) {
      const sam = A.first(e, 'sAMAccountName').toLowerCase();
      if (!sam) continue;
      const uac = parseInt(A.first(e, 'userAccountControl'), 10) || 0;
      const sidRaw = e.raw.objectsid && e.raw.objectsid[0];
      const r = { sam, upn: A.first(e, 'userPrincipalName').toLowerCase(), name: A.first(e, 'displayName'), mail: A.first(e, 'mail'),
        dept: A.first(e, 'department'), title: A.first(e, 'title'), manager: A.first(e, 'manager'), dn: e.dn, cn: A.firstRdnValue(e.dn),
        sid: sidRaw && sidRaw.length >= 8 ? A.sidToString(sidRaw) : '', uac, disabled: !!(uac & A.UAC.ACCOUNTDISABLE),
        admin_count: parseInt(A.first(e, 'adminCount'), 10) || 0, member_of: A.all(e, 'memberOf'),
        primary_group: parseInt(A.first(e, 'primaryGroupID'), 10) || 0,
        last_logon: A.fileTimeToMs(A.first(e, 'lastLogonTimestamp')), pwd_last_set: A.fileTimeToMs(A.first(e, 'pwdLastSet')),
        created: A.generalizedTimeToMs(A.first(e, 'whenCreated')), expires: A.fileTimeToMs(A.first(e, 'accountExpires')),
        priv_groups: [], privileged: false };
      // service principal names make an account Kerberoastable; the description often says what the account runs (kept short)
      const spn = A.all(e, 'servicePrincipalName'); if (spn.length) r.spn = spn.slice(0, 20).map((x) => String(x).slice(0, 200));
      const desc = A.first(e, 'description'); if (desc) r.desc = String(desc).slice(0, 200);
      users.push(r); bySam.set(sam, r); byDn.set(e.dn.toLowerCase(), r);
    }
    // nested membership of each privileged group
    const groups = [];
    for (const e of found.values()) {
      const gsam = A.first(e, 'sAMAccountName') || A.first(e, 'cn') || A.firstRdnValue(e.dn);
      const sidRaw = e.raw.objectsid && e.raw.objectsid[0];
      const gsid = sidRaw && sidRaw.length >= 8 ? A.sidToString(sidRaw) : '';
      const rid = gsid ? Number(gsid.split('-').pop()) : 0;
      const mr = await conn.search(base, { scope: 'sub', filter: `(&(objectCategory=person)(objectClass=user)(memberOf:${ldap.OID.IN_CHAIN}:=${esc(e.dn)}))`, attributes: ['sAMAccountName'], pageSize: page, maxEntries: 1000000 });
      const members = new Map();
      for (const m of mr.entries) {
        const u = byDn.get(m.dn.toLowerCase()) || bySam.get(A.first(m, 'sAMAccountName').toLowerCase());
        if (!u) continue;                                          // outside the user filter
        members.set(u.sam, { sam: u.sam, dn: u.dn, nested: !u.member_of.some((d) => d.toLowerCase() === e.dn.toLowerCase()) });
      }
      if (rid && /^S-1-5-21-/.test(gsid)) for (const u of users) if (u.primary_group === rid && !members.has(u.sam)) members.set(u.sam, { sam: u.sam, dn: u.dn, nested: false, primary: true });
      const list = [...members.values()].sort((a, b) => (a.sam < b.sam ? -1 : 1));
      for (const m of list) { const u = bySam.get(m.sam); u.privileged = true; if (u.priv_groups.indexOf(gsam) < 0) u.priv_groups.push(gsam); }
      groups.push({ dn: e.dn, sam: gsam, sid: gsid, privileged: true, members: list });
    }
    for (const u of users) delete u.primary_group;
    // managed service accounts: privileged when a direct member of a privileged group (nested membership is read for people only)
    let managed = null;
    try {
      const mr = await conn.search(base, { scope: 'sub', filter: '(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))', attributes: MSA_ATTRS, pageSize: page, maxEntries: 100000 });
      const privDn = new Map(groups.map((g) => [g.dn.toLowerCase(), g.sam]));
      managed = mr.entries.map((e) => {
        const uac = parseInt(A.first(e, 'userAccountControl'), 10) || 0, sidRaw = e.raw.objectsid && e.raw.objectsid[0];
        const cls = A.all(e, 'objectClass').map((c) => String(c).toLowerCase()), mo = A.all(e, 'memberOf');
        const pg = mo.map((d) => privDn.get(String(d).toLowerCase())).filter(Boolean);
        return { sam: A.first(e, 'sAMAccountName').toLowerCase(), kind: cls.includes('msds-groupmanagedserviceaccount') ? 'gmsa' : 'smsa', dn: e.dn,
          sid: sidRaw && sidRaw.length >= 8 ? A.sidToString(sidRaw) : '', uac, disabled: !!(uac & A.UAC.ACCOUNTDISABLE), member_of: mo, priv_groups: pg, privileged: pg.length > 0,
          spn: A.all(e, 'servicePrincipalName').slice(0, 20).map((x) => String(x).slice(0, 200)), desc: String(A.first(e, 'description') || '').slice(0, 200),
          pwd_interval_days: parseInt(A.first(e, 'msDS-ManagedPasswordInterval'), 10) || null, host: A.first(e, 'dNSHostName') || '',
          last_logon: A.fileTimeToMs(A.first(e, 'lastLogonTimestamp')), pwd_last_set: A.fileTimeToMs(A.first(e, 'pwdLastSet')), created: A.generalizedTimeToMs(A.first(e, 'whenCreated')) };
      }).filter((m) => m.sam);
    } catch (e) { L.warn('ad sync: managed service accounts not read (the rest of the sync is kept)', { err: e.message }); managed = null; }
    return { users, groups, netbios, dnsDomain, policy, exchange, managed, pages: ur.pages };
  }

  function emit(changes, prev, syncedMs) {
    if (!pipeline || !changes.length) return 0;
    const nb = (identity.snapshot().netbios || [])[0] || '';
    for (const c of changes) {
      const added = c.kind === 'added';
      const ev = {
        ts: syncedMs, rts: syncedMs, src_type: 'ad', src_id: 'ad-sync', collector: 'ad-sync', host: identity.snapshot().server || '',
        category: 'iam', action: added ? 'group-member-added' : 'group-member-removed', outcome: 'success', severity: added ? 3 : 1,
        target_user: c.member.sam, domain: nb, event_code: added ? 'AD-SYNC-PRIV-NEW' : 'AD-SYNC-PRIV-REMOVED',
        message: `${c.member.sam} ${added ? 'is a new member of' : 'is no longer a member of'} privileged AD group ${c.group.sam}${c.member.nested ? ' (through a nested group)' : ''} — seen by the AD identity sync`,
        tags: ['ad-sync', 'admin', 'T1098'],
        fields: { group: c.group.sam, group_dn: c.group.dn, member_dn: c.member.dn, nested: c.member.nested ? '1' : '0', previous_sync: new Date(prev.synced).toISOString(), group_privileged: '1' },
      };
      pipeline.emit(finalise(ev, { rts: syncedMs }));
    }
    return changes.filter((c) => c.kind === 'added').length;
  }

  async function mirror(snap, prev, syncedMs, extra) {
    if (!ch || typeof ch.insertRows !== 'function') return null;
    try {
      const rows = buildRows(snap, prev, syncedMs);
      for (let i = 0; i < rows.users.length; i += 5000) await ch.insertRows('identity_users', rows.users.slice(i, i + 5000));
      for (let i = 0; i < rows.groups.length; i += 5000) await ch.insertRows('identity_groups', rows.groups.slice(i, i + 5000));
      await ch.insertRows('identity_sync', [Object.assign({ ts: chTime(syncedMs) }, extra)]);
      return null;
    } catch (e) { L.warn('ad sync: ClickHouse mirror failed (identity kept in memory and on disk)', { err: e.message }); return e.message; }
  }

  function record(s) {
    last = s;
    if (statusFile) { try { fs.writeFileSync(statusFile + '.tmp', JSON.stringify(s), { mode: 0o600 }); fs.renameSync(statusFile + '.tmp', statusFile); } catch { /* state dir not writable */ } }
  }

  async function run(reason) {
    const t0 = now();
    const p = problems();
    if (p.length) { const s = { at: new Date(t0).toISOString(), ok: false, reason, error: 'not configured: ' + p.join('; ') }; record(s); return s; }
    try {
      let server = '';
      const data = await client().run(async (conn) => { server = conn.server.url; return pull(conn); });
      const prev = identity.snapshot();
      const snap = { synced: t0, server, baseDN: ad.baseDN, dnsDomain: data.dnsDomain, netbios: data.netbios.length ? data.netbios : [].concat(ad.netbios || []), users: data.users, groups: data.groups, managed: data.managed, policy: data.policy || null, exchange_servers: data.exchange };
      const changes = diffPrivileged(prev, snap);
      identity.replace(snap);
      const newPriv = emit(changes, prev, t0);
      const counts = { users: snap.users.length, groups: snap.groups.length, privileged: snap.users.filter((u) => u.privileged).length, disabled: snap.users.filter((u) => u.disabled).length, pages: data.pages };
      const chErr = await mirror(snap, prev, t0, { ok: 1, server, users: counts.users, groups: counts.groups, privileged: counts.privileged, new_privileged: newPriv, duration_ms: now() - t0, error: '' });
      const s = Object.assign({ at: new Date(t0).toISOString(), ok: true, reason, server, duration_ms: now() - t0, new_privileged: newPriv, removed_privileged: changes.length - newPriv, clickhouse_error: chErr || undefined }, counts);
      L.info('ad sync done', s);
      record(s);
      return s;
    } catch (e) {
      const s = { at: new Date(t0).toISOString(), ok: false, reason, duration_ms: now() - t0, error: String(e.message || e).slice(0, 500) };
      L.error('ad sync failed', s);
      if (ch && typeof ch.insertRows === 'function') { try { await ch.insertRows('identity_sync', [{ ts: chTime(t0), ok: 0, server: '', users: 0, groups: 0, privileged: 0, new_privileged: 0, duration_ms: s.duration_ms, error: s.error }]); } catch { /* ignore */ } }
      record(s);
      return s;
    }
  }
  function syncNow(reason = 'manual') {
    if (!running) running = run(reason).finally(() => { running = null; });
    return running;
  }
  function start() {
    if (!ad.enabled) { L.info('ad sync disabled (config ad.enabled=false)'); return false; }
    const p = problems();
    if (p.length) L.warn('ad sync enabled but not fully configured — it will report errors until fixed', { problems: p });
    const every = Math.max(5, Number(ad.sync_minutes) || 60) * 60000;
    first = setTimeout(guardJob('ad.sync', () => syncNow('startup')), 10000);
    timer = setInterval(guardJob('ad.sync', () => { nextAt = now() + every; return syncNow('schedule'); }), every);   // a failed sync is logged and counted (util/errors.js), the next one runs on time
    nextAt = now() + 10000;
    if (first.unref) first.unref();
    if (timer.unref) timer.unref();
    return true;
  }
  function stop() { if (first) clearTimeout(first); if (timer) clearInterval(timer); first = timer = null; return running || Promise.resolve(); }
  function status() {
    return { enabled: !!ad.enabled, problems: problems(), running: !!running, sync_minutes: Number(ad.sync_minutes) || 60, next_at: nextAt ? new Date(nextAt).toISOString() : null, last, identity: identity.meta() };
  }
  /* settings changed from the portal (engine/ad/settings.js): pick up config.ad and restart the schedule */
  function reconfigure() {
    stop();
    for (const k of Object.keys(ad)) delete ad[k];
    Object.assign(ad, (config && config.ad) || {});
    nextAt = 0;
    return start();
  }
  return { syncNow, start, stop, status, problems, reconfigure };
}

module.exports = { policyOf, createAdSync, buildRows, diffPrivileged, USER_ATTRS };
