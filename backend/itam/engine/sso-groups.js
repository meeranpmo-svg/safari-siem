// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
/*
 * SSO access from Active Directory ({P} = /api/itam; Platform Administration -> SSO Access from AD, page sso-access.html).
 *
 * Single sign-on is OpenID Connect with Microsoft Entra ID: a person's platform role comes from the "groups" claim through the
 * role mapping in Identity & Sign-in. This module turns AD groups into that mapping, with four-eyes and without ever creating
 * an account, touching MFA or writing to AD:
 *   read      the AD groups under the base DN (READ ONLY, the directory connection HR onboarding holds) and, for one group, its
 *             members including nested groups - the way Entra ID counts them
 *   propose   an administrator maps groups to platform roles (viewer / operator / admin); the server works out who would get which
 *             role (highest wins), and flags admins in large groups, privileged AD accounts, members with no UPN (they cannot sign
 *             in through Entra ID), distribution groups (Entra does not send them) - broad groups (Domain Users, Everyone,
 *             Authenticated Users, Domain Computers, Users, Guests ...) are REFUSED for any role
 *   approve   a DIFFERENT administrator, a person (never a service / AI identity), approves or rejects with a reason
 *   applied   the approved mapping is saved into Identity & Sign-in by that administrator from the page (the same admin API the
 *             Identity & Sign-in Save button uses, keeping MFA and every other setting); the page reads the configuration back
 *             and records it here - the record is refused unless the role map holds exactly the approved groups and roles
 * The claim value is what Entra ID sends for a synced group, set in the app registration's token configuration: sAMAccountName,
 * NetBIOS\sAMAccountName, DNS\sAMAccountName or the on-premises SID (settings.claim). Member names are personal data (PDPL):
 * operators and administrators only; reading members is audited.
 *   GET  /sso-groups                       operator   settings, groups last read, the open proposal, history, what is applied
 *   POST /sso-groups/refresh               operator   read the AD groups now {q?} (a person)                               audited
 *   GET  /sso-groups/members?group=        operator   one group's members, nested included                               audited
 *   POST /sso-groups/settings              admin      {claim: sam|netbios|dns|sid, netbios?}                              audited
 *   POST /sso-groups/propose               admin      {mappings: [{group, role}], note?}                                  audited
 *   POST /sso-groups/:id/approve           admin      a different person than the proposer                                audited
 *   POST /sso-groups/:id/reject            admin      {reason}                                                            audited
 *   POST /sso-groups/:id/applied           admin      {role_map, role_claim, verified}  not the proposer; must match       audited
 *   POST /sso-groups/sync                  admin      re-read the members of the applied job-role groups now              audited
 * Job roles (Roles & Functions, e.g. Penetration Testing Engineer): a mapping may also carry a job role; its platform role
 * must be the job role's base level. Once the proposal is applied, everyone in that group (nested included) gets the job role
 * as an assignment marked source 'sso-group' under both their sAMAccountName and UPN (whichever the sign-in uses) - so the
 * same menu and the same server-side limits apply as for a local account. A job role set by hand in Roles & Functions always
 * wins. AD stays the source: membership is re-read every hour (and on Sync now), joiners get it, leavers lose it, audited.
 * A person who would get two different job roles is refused at proposal; a person whose highest platform role is not the
 * job role's base (e.g. admin through another group) is listed and gets no job role (an administrator is never limited).
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const RANK = { viewer: 1, operator: 2, admin: 3 };
const CLAIMS = ['sam', 'netbios', 'dns', 'sid'];
// groups that mean "everybody" - giving them a role would open the platform to the whole company (or to machines)
const BROAD_SID = [/^S-1-1-0$/, /^S-1-5-11$/, /^S-1-5-7$/, /^S-1-5-32-54[56]$/, /^S-1-5-21-[\d-]+-51[3-6]$/];
const BROAD_NAME = /^(domain users|domain computers|domain guests|domain controllers|everyone|authenticated users|users|guests|anonymous logon)$/i;
const MAX_MAPPINGS = 50, BIG_ADMIN_GROUP = 25;

function createSsoGroups(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, iso = () => new Date(now()).toISOString();
  const C = () => store.collection('sso_groups');
  const AD = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const person = (who, what) => { if (!who || !who.user || isService(who.user)) throw httpErr(403, what + ' is done by a person, not a service or AI identity'); };
  const settings = () => Object.assign({ claim: 'sam', netbios: '' }, (C().get('settings') || {}).v || {});
  function connection() {
    const a = AD(); if (!a) return { ok: false, why: 'HR onboarding (which holds the directory connection) is not installed - run the update' };
    const c = a.cfg(); if (!(c.bind_enc && (c.servers || []).length && c.base_dn)) return { ok: false, why: 'the directory connection is not set - an administrator sets it in HR Onboarding -> Directory settings (servers, base DN, bind account)' };
    return { ok: true, servers: c.servers, base_dn: c.base_dn };
  }
  const dnsOf = (baseDn) => String(baseDn || '').split(',').map((p) => /^\s*dc=(.+)$/i.exec(p)).filter(Boolean).map((m) => m[1].trim()).join('.');
  function claimValue(g, s, baseDn) {
    if (s.claim === 'sid') return g.sid || '';
    if (s.claim === 'netbios') return s.netbios ? s.netbios.toUpperCase() + '\\' + g.sam : '';
    if (s.claim === 'dns') { const d = dnsOf(baseDn); return d ? d + '\\' + g.sam : ''; }
    return g.sam || '';
  }
  const broad = (g) => BROAD_SID.some((re) => re.test(g.sid || '')) || BROAD_NAME.test(g.sam || '') || BROAD_NAME.test(g.name || '');
  const groupsRead = () => C().get('groups') || null;
  const proposals = () => C().all ? C().all().filter((x) => /^SSO-/.test(x.id)).sort((a, b) => String(b.at).localeCompare(String(a.at))) : [];
  const applied = () => proposals().find((p) => p.status === 'applied') || null;
  const R = () => app.roles || null;
  const roleById = (id) => { const r = R(); if (!r) return null; return (r.list().roles || []).find((x) => x.id === id) || null; };
  const handAssigned = (p) => { const r = R(); if (!r) return false; const A = r.list().assignments || []; return A.some((a) => !a.source && [p.sam, p.upn].filter(Boolean).some((u) => u.toLowerCase() === String(a.user).toLowerCase())); };
  // the job roles of the applied mapping, re-read from AD: everyone in a job-role group (nested), enabled, whose highest role is
  // the job role's base; one assignment under the sAMAccountName and one under the UPN
  async function sync(who, reason) {
    const r = R(), a = applied();
    if (!r || typeof r.syncDerived !== 'function') return { synced: false, reason: 'Roles & Functions is not installed' };
    const cn = connection(); if (!cn.ok) return { synced: false, reason: cn.why };
    const jm = a ? a.mappings.filter((m) => m.job_role) : [];
    const best = new Map(), jobs = new Map();
    for (const m of (a ? a.mappings : [])) {
      const M = await readMembers({ dn: m.dn, sam: m.group });
      for (const u of M) { if (!u.enabled) continue; const kk = u.sam.toLowerCase(), cur = best.get(kk); if (!cur || RANK[m.role] > RANK[cur.role]) best.set(kk, { role: m.role, u });
        if (m.job_role) jobs.set(kk, { m, u }); }
    }
    const want = [];
    for (const [kk, j] of jobs) { const jr = roleById(j.m.job_role), b = best.get(kk); if (!jr || !b || b.role !== jr.base) continue;
      for (const name of [j.u.sam, j.u.upn].filter(Boolean)) want.push({ user: name, role_id: jr.id, via: j.m.group, proposal: a.id }); }
    const res = r.syncDerived(want, who);
    C().put({ id: 'sync', at: iso(), by: who.user, reason, groups: jm.length, people: jobs.size, added: res.added.length, removed: res.removed.length, changed: res.changed.length });
    if (res.added.length || res.removed.length || res.changed.length || reason !== 'timer') audit(who, 'sso_groups.sync', a ? a.id : '-', { reason, added: res.added.slice(0, 50), removed: res.removed.slice(0, 50), changed: res.changed.slice(0, 50) });
    return Object.assign({ synced: true }, res);
  }

  function view() {
    const cn = connection(), g = groupsRead(), P = proposals();
    return { connection: cn.ok ? { ok: true, servers: cn.servers, base_dn: cn.base_dn, dns_domain: dnsOf(cn.base_dn) } : cn, settings: settings(),
      groups: g ? { at: g.at, by: g.by, q: g.q, truncated: g.truncated, items: g.items.map((x) => Object.assign({}, x, { broad: broad(x), claim: claimValue(x, settings(), cn.base_dn) })) } : null,
      open: P.find((p) => p.status === 'proposed' || p.status === 'approved') || null, applied: applied(), history: P.slice(0, 20).map((p) => ({ id: p.id, status: p.status, by: p.by, at: p.at, approver: p.approver || null, reason: p.reason || '', mappings: p.mappings.length, people: p.preview ? p.preview.people.length : 0 })),
      roles: Object.keys(RANK), claims: CLAIMS, last_sync: C().get('sync') || null,
      job_roles: R() ? (R().list().roles || []).map((x) => ({ id: x.id, name: x.name, base: x.base })) : [],
      derived: R() ? (R().list().assignments || []).filter((x) => x.source === 'sso-group') : [],
      note: 'Being in an AD group gives access only after the mapping is approved by a second administrator and saved into Identity & Sign-in. No account is created and nothing is written to Active Directory; MFA stays as Identity & Sign-in sets it.' };
  }
  async function refresh(who, b0) {
    person(who, 'Reading the directory');
    const b = body(b0 || {}).str('q', { max: 64, re: /^[A-Za-z0-9 ._$-]*$/, msg: 'q must be part of a group name (letters, digits, space . _ $ -)' }).done();
    const cn = connection(); if (!cn.ok) throw httpErr(409, cn.why);
    let r;
    try { r = await AD().writer().directoryGroups({ q: b.q || undefined, max: 2000 }); }
    catch (e) {
      if (e.status) throw e;
      if (app.log && app.log.every) app.log.every('sso-groups:read', 600000, 'warn', 'AD groups could not be read', { err: String(e.message).slice(0, 200) });
      throw httpErr(424, 'the directory could not be read: ' + String(e.message).slice(0, 200));
    }
    const items = r.groups.filter((g) => g.sam).sort((x, y) => String(x.sam).localeCompare(String(y.sam)));
    C().put({ id: 'groups', at: iso(), by: who.user, q: b.q || '', truncated: !!r.truncated, items });
    audit(who, 'sso_groups.refresh', b.q || 'all', { groups: items.length, truncated: !!r.truncated });
    return view();
  }
  async function readMembers(group) {
    let m;
    try { m = await AD().writer().groupMembers(group.dn, { nested: true }); }
    catch (e) { if (e.status) throw e; throw httpErr(424, 'the members of ' + group.sam + ' could not be read: ' + String(e.message).slice(0, 200)); }
    if (!m) throw httpErr(404, 'group ' + group.sam + ' is no longer in the directory - read the groups again');
    return m.members;
  }
  function findGroup(name) {
    const g = groupsRead(); if (!g) throw httpErr(409, 'read the AD groups first');
    const k = String(name || '').toLowerCase(), x = g.items.find((i) => i.sam.toLowerCase() === k || String(i.dn).toLowerCase() === k);
    if (!x) throw httpErr(404, 'group ' + name + ' is not in the groups last read - read the groups again');
    return x;
  }
  async function members(who, q) {
    person(who, 'Reading group members');
    const p = body(q || {}).str('group', { required: true, max: 400, msg: 'group must be a group name or DN from the list' }).done();
    const cn = connection(); if (!cn.ok) throw httpErr(409, cn.why);
    const g = findGroup(p.group), M = await readMembers(g);
    audit(who, 'sso_groups.members', g.sam, { members: M.length });
    return { group: g.sam, dn: g.dn, members: M.map((u) => ({ sam: u.sam, upn: u.upn || '', display_name: u.display_name, enabled: u.enabled, admin_count: u.admin_count, last_logon: u.last_logon })) };
  }
  function saveSettings(who, b0) {
    person(who, 'Changing the SSO claim setting');
    const b = body(b0 || {}).oneOf('claim', CLAIMS, { required: true }).str('netbios', { max: 15, re: /^[A-Za-z0-9-]*$/, msg: 'netbios must be the NetBIOS domain name (letters, digits, -), up to 15 characters' }).done();
    if (b.claim === 'netbios' && !b.netbios) throw httpErr(400, 'netbios: the NetBIOS domain name is needed for NetBIOS\\sAMAccountName');
    C().put({ id: 'settings', v: { claim: b.claim, netbios: b.netbios || '' }, by: who.user, at: iso() });
    audit(who, 'sso_groups.settings', 'settings', { claim: b.claim, netbios: b.netbios || '' });
    return view();
  }
  async function syncNow(who) { person(who, 'Syncing job roles'); return sync(who, 'manual'); }
  async function propose(who, b0) {
    person(who, 'Proposing SSO access');
    const b = body(b0 || {}).list('mappings', { required: true, max: MAX_MAPPINGS }).str('note', { max: 500 }).done();
    if (!b.mappings.length) throw httpErr(400, 'mappings: choose at least one group and its role');
    const cn = connection(); if (!cn.ok) throw httpErr(409, cn.why);
    const s = settings(), seen = new Set(), maps = [];
    for (const [i, m0] of b.mappings.entries()) {
      const m = body(m0 || {}).str('group', { required: true, max: 400, msg: 'mappings[' + i + '].group must be a group name' }).oneOf('role', Object.keys(RANK), { required: true })
        .str('job_role', { max: 60, re: /^[A-Za-z0-9._-]*$/, msg: 'mappings[' + i + '].job_role must be a job role id' }).done();
      let jr = null;
      if (m.job_role) {
        jr = roleById(m.job_role); if (!jr) throw httpErr(400, 'mappings[' + i + '].job_role: ' + m.job_role + ' is not a job role in Roles & Functions');
        if (jr.base !== m.role) throw httpErr(400, 'mappings[' + i + '].role: the job role ' + jr.name + ' has the base level ' + jr.base + ' - the group role must be ' + jr.base);
      }
      const g = findGroup(m.group);
      if (broad(g)) throw httpErr(400, 'mappings[' + i + ']: ' + g.sam + ' means everyone (or every computer) in the domain - it cannot be given a role; use a group made for the platform');
      if (seen.has(g.dn.toLowerCase())) throw httpErr(400, 'mappings[' + i + ']: ' + g.sam + ' is listed twice');
      seen.add(g.dn.toLowerCase());
      const key = claimValue(g, s, cn.base_dn);
      if (!key) throw httpErr(400, 'mappings[' + i + ']: ' + g.sam + ' has no ' + (s.claim === 'sid' ? 'SID' : 'claim value') + ' for the claim setting ' + s.claim);
      maps.push(Object.assign({ group: g.sam, dn: g.dn, sid: g.sid, security: g.security, key, role: m.role }, jr ? { job_role: jr.id, job_role_name: jr.name } : {}));
    }
    // who would get which role: members through nested groups, the highest role wins (as the sign-in service applies it)
    const people = new Map(), warnings = [];
    for (const m of maps) {
      const M = await readMembers({ dn: m.dn, sam: m.group }); m.members = M.length;
      if (!m.security) warnings.push({ group: m.group, kind: 'distribution', text: m.group + ' is a distribution group - Entra ID sends security groups only, so nobody would get access through it' });
      if (m.role === 'admin' && M.length > BIG_ADMIN_GROUP) warnings.push({ group: m.group, kind: 'big-admin', text: M.length + ' people would be administrators through ' + m.group + ' - an admin group should be small' });
      for (const u of M) {
        const k = u.sam.toLowerCase(), p = people.get(k) || { sam: u.sam, upn: u.upn || '', display_name: u.display_name, enabled: u.enabled, admin_count: u.admin_count, role: null, via: [] };
        p.via.push(m.group + ' → ' + m.role + (m.job_role ? ' (' + m.job_role_name + ')' : '')); if (!p.role || RANK[m.role] > RANK[p.role]) p.role = m.role;
        if (m.job_role) (p.jobs = p.jobs || {})[m.job_role] = m.group;
        people.set(k, p);
      }
    }
    // job roles: two different ones for one person cannot be decided - refused; one that does not fit the highest role is dropped
    const clash = [...people.values()].filter((p) => p.jobs && Object.keys(p.jobs).length > 1);
    if (clash.length) throw httpErr(400, 'mappings: ' + clash.length + ' person(s) would get two different job roles - ' + clash.slice(0, 8).map((p) => p.sam + ' (' + Object.values(p.jobs).join(', ') + ')').join('; ') + ' - a person may be in one job-role group only');
    for (const p of people.values()) {
      if (!p.jobs) continue; const jid = Object.keys(p.jobs)[0], jr = roleById(jid);
      if (jr && jr.base === p.role) { p.job_role = jid; p.job_role_name = jr.name; p.job_via = p.jobs[jid]; } else p.job_dropped = jr ? jr.name : jid;
      delete p.jobs;
    }
    const dropped = [...people.values()].filter((p) => p.job_dropped && p.enabled);
    if (dropped.length) warnings.push({ kind: 'job-role-dropped', text: dropped.length + ' person(s) get a higher role through another group, so their job role does not apply: ' + dropped.slice(0, 6).map((p) => p.sam).join(', ') });
    const hand = [...people.values()].filter((p) => p.job_role && handAssigned(p));
    if (hand.length) warnings.push({ kind: 'job-role-hand', text: hand.length + ' person(s) already have a job role set by hand in Roles & Functions - that one is kept: ' + hand.slice(0, 6).map((p) => p.sam).join(', ') });
    const P = [...people.values()].sort((x, y) => RANK[y.role] - RANK[x.role] || String(x.display_name || x.sam).localeCompare(String(y.display_name || y.sam)));
    const noUpn = P.filter((p) => !p.upn && p.enabled).length, priv = P.filter((p) => p.admin_count && p.enabled).length;
    if (noUpn) warnings.push({ kind: 'no-upn', text: noUpn + ' enabled member(s) have no UPN - they cannot sign in through Entra ID' });
    if (priv) warnings.push({ kind: 'privileged', text: priv + ' member(s) are privileged AD accounts (adminCount) - a separate everyday account is safer for the platform' });
    const counts = { admin: 0, operator: 0, viewer: 0, disabled: 0, job_roles: 0 }; for (const p of P) { if (!p.enabled) counts.disabled++; else { counts[p.role]++; if (p.job_role) counts.job_roles++; } }
    // one open proposal at a time: a new one supersedes the previous open one
    for (const o of proposals().filter((x) => x.status === 'proposed' || x.status === 'approved')) C().put(Object.assign({}, o, { status: 'superseded', superseded_at: iso() }));
    const id = 'SSO-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2, 6).toUpperCase();
    const doc = { id, status: 'proposed', by: who.user, at: iso(), note: b.note || '', claim: s.claim, mappings: maps, preview: { counts, people: P, warnings } };
    C().put(doc);
    audit(who, 'sso_groups.propose', id, { mappings: maps.map((m) => m.group + '=' + m.role), people: P.length, admins: counts.admin, warnings: warnings.length });
    return doc;
  }
  function get(id) { const p = C().get(id); if (!p || !/^SSO-/.test(p.id)) throw httpErr(404, 'proposal ' + id + ' not found'); return p; }
  function approve(who, id) {
    person(who, 'Approving SSO access');
    const p = get(id); if (p.status !== 'proposed') throw httpErr(409, 'proposal ' + id + ' is ' + p.status + ', not waiting for approval');
    if (p.by === who.user) throw httpErr(403, 'four-eyes: the person who proposed the access cannot approve it - another administrator does');
    const d = Object.assign({}, p, { status: 'approved', approver: who.user, approved_at: iso() }); C().put(d);
    audit(who, 'sso_groups.approve', id, { proposer: p.by, mappings: p.mappings.map((m) => m.group + '=' + m.role) });
    return d;
  }
  function reject(who, id, b0) {
    person(who, 'Rejecting SSO access');
    const b = body(b0 || {}).str('reason', { required: true, max: 500, msg: 'reason: say why it is rejected' }).done();
    const p = get(id); if (p.status !== 'proposed' && p.status !== 'approved') throw httpErr(409, 'proposal ' + id + ' is ' + p.status);
    const d = Object.assign({}, p, { status: 'rejected', reason: b.reason, rejected_by: who.user, rejected_at: iso() }); C().put(d);
    audit(who, 'sso_groups.reject', id, { proposer: p.by, reason: b.reason });
    return d;
  }
  async function markApplied(who, id, b0) {
    person(who, 'Applying SSO access');
    const b = body(b0 || {}).oneOf('role_claim', ['groups', 'roles'], { required: true }).bool('verified', { def: false }).done();
    const rm = b0 && b0.role_map;
    if (!rm || typeof rm !== 'object' || Array.isArray(rm)) throw httpErr(400, 'role_map must be the saved role mapping (an object)');
    const ks = Object.keys(rm); if (ks.length > 500) throw httpErr(400, 'role_map has more than 500 entries');
    for (const k of ks) if (k.length > 400 || /[\u0000-\u001f]/.test(k) || !RANK[rm[k]]) throw httpErr(400, 'role_map: ' + k.slice(0, 60) + ' must map to viewer, operator or admin');
    b.role_map = rm;
    const p = get(id); if (p.status !== 'approved') throw httpErr(409, 'proposal ' + id + ' is ' + p.status + ' - only an approved proposal is applied');
    if (p.by === who.user) throw httpErr(403, 'four-eyes: the proposer does not apply their own proposal - the approver (or another administrator) does');
    if (b.role_claim !== 'groups') throw httpErr(400, 'role_claim: group mapping needs the role claim set to groups');
    const bad = p.mappings.filter((m) => b.role_map[m.key] !== m.role);
    if (bad.length) throw httpErr(400, 'role_map does not hold the approved mapping: ' + bad.map((m) => m.group + ' (' + m.key + ') must be ' + m.role).join('; ').slice(0, 400));
    const prev = applied();
    if (prev) C().put(Object.assign({}, prev, { status: 'superseded', superseded_at: iso() }));
    const d = Object.assign({}, p, { status: 'applied', applied_by: who.user, applied_at: iso(), verified: !!b.verified, keys: p.mappings.map((m) => m.key) }); C().put(d);
    audit(who, 'sso_groups.applied', id, { mappings: p.mappings.map((m) => m.group + '=' + m.role + (m.job_role ? '/' + m.job_role : '')), verified: !!b.verified, replaced: prev ? prev.id : null });
    let js = null;
    try { js = await sync(who, 'applied'); } catch (e) { js = { synced: false, reason: String(e.message).slice(0, 200) }; if (app.log && app.log.warn) app.log.warn('sso-groups: job-role sync after apply failed', { err: js.reason }); }
    return Object.assign({}, d, { job_role_sync: js });
  }
  return { view, refresh, members, saveSettings, propose, approve, reject, markApplied, syncNow, sync, connection, _claimValue: claimValue, _broad: broad };
}

function registerSsoGroups(srv, app, X, opts = {}) {
  // AD membership is the source of the job roles: re-read every hour (joiners get the role, leavers lose it)
  if (!opts.noTimer) { const { guardOf } = require('./errors'); const SYS = { user: 'system:sso-groups', role: 'admin', ip: '' };
    let t = null; const tick = guardOf(app, 'sso-groups.sync', async () => { try { if (X.connection().ok) await X.sync(SYS, 'timer'); } finally { t = setTimeout(tick, 3600000); if (t.unref) t.unref(); } });
    t = setTimeout(tick, 120000); if (t.unref) t.unref(); }
  const who = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || ctx.ip || '' });
  const pid = (ctx) => { const p = body(ctx.params || {}).str('id', { required: true, max: 40, re: /^SSO-[A-Z0-9-]{4,36}$/, msg: 'id must be a proposal id (SSO-…)' }).done(); return p.id; };
  srv.route('GET', '/sso-groups', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('POST', '/sso-groups/refresh', (ctx) => { ctx.need('operator'); return X.refresh(who(ctx), ctx.body); }, { maxBody: 1024 });
  srv.route('GET', '/sso-groups/members', (ctx) => { ctx.need('operator'); return X.members(who(ctx), ctx.query); });
  srv.route('POST', '/sso-groups/settings', (ctx) => { ctx.need('admin'); return X.saveSettings(who(ctx), ctx.body); }, { maxBody: 1024 });
  srv.route('POST', '/sso-groups/propose', (ctx) => { ctx.need('admin'); return X.propose(who(ctx), ctx.body); }, { maxBody: 32 * 1024 });
  srv.route('POST', '/sso-groups/:id/approve', (ctx) => { ctx.need('admin'); return X.approve(who(ctx), pid(ctx)); }, { maxBody: 1024 });
  srv.route('POST', '/sso-groups/:id/reject', (ctx) => { ctx.need('admin'); return X.reject(who(ctx), pid(ctx), ctx.body); }, { maxBody: 2048 });
  srv.route('POST', '/sso-groups/sync', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return X.syncNow(who(ctx)); }, { maxBody: 1024 });
  srv.route('POST', '/sso-groups/:id/applied', (ctx) => { ctx.need('admin'); return X.markApplied(who(ctx), pid(ctx), ctx.body); }, { maxBody: 64 * 1024 });
}
module.exports = { createSsoGroups, registerSsoGroups };
