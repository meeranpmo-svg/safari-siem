// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
const { createSealer } = require('./discovery/vault');
const { tempPassword } = require('./ad-writer');
const { PRIVILEGED } = require('./onboarding-ad');
/*
 * Active Directory management ({P} = /api/itam; Platform Administration -> AD Management): create, disable, enable, reset the
 * password, unlock, move, change groups and details, and delete user accounts in the organisation's own AD - through the directory
 * connection HR onboarding holds (engine/onboarding-ad.js: LDAPS / StartTLS, the bind password sealed in the vault).
 *
 * FOUR EYES. Every change is a REQUEST with a reason; a DIFFERENT named administrator approves it, and only then is it written
 * to AD, read back and verified. Service and AI identities never request or approve. The one exception is an EMERGENCY DISABLE
 * (a compromised or departing account): it runs at once and a second administrator reviews it afterwards.
 * PROTECTED - never changed from here: privileged accounts (adminCount = 1, or a member of a privileged group: Domain / Enterprise
 * / Schema Admins, operators, Exchange management ...), the directory's own bind account, the never-disable list (HR onboarding)
 * and this page's protected list, and the requester's own account. A privileged group is never added.
 * DELETE is permanent (the SID is gone). It is offered only when switched on in the settings, only for an account that is
 * DISABLED and has not changed in AD for DELETE_DAYS (30) days (whenChanged - any later change restarts the clock), and the
 * conditions are checked again at approval, just before the delete.
 * PASSWORDS (create, reset) are random 16-character temporary passwords with "change at first sign-in"; sealed in the vault for
 * a ONE-TIME reveal by the requester (who hands it to the person), destroyed after the reveal or after 72 hours; never logged,
 * audited, e-mailed or shown twice.
 * UNLOCK clears a lockout (lockoutTime = 0) and nothing else - the password is not touched. Requested only for an account the
 * directory shows locked out, with when it was locked and, when the SIEM holds the 4740 events, the computer the bad passwords
 * came from (a phone or a mapped drive with an old password locks the account again - the requester should fix that first).
 * Four eyes like every other change (no emergency path: unlocking does not contain a threat); read back to verify.
 * End users never unlock or reset their own accounts here (no self-service, by decision).
 * Pending requests expire after 7 days. Names and groups of employees are personal data (PDPL): operators read, admins change.
 *
 *   GET  /ad-manage                          operator  connection, settings, requests (never a password)
 *   GET  /ad-manage/user/:sam                operator  one account: groups, enabled, protected (why), can it be deleted (why)  audited
 *   POST /ad-manage/settings                 admin     {enabled, delete_enabled, create_ou, protected[]}                       audited
 *   POST /ad-manage/requests                 admin     {action, sam, reason, ...}   action: create | disable | enable |
 *                                                      reset_password | unlock | move | add_group | remove_group | update |
 *                                                      delete                                                                audited
 *   POST /ad-manage/requests/:id/approve     admin     a different person; written to AD, read back                         audited
 *   POST /ad-manage/requests/:id/reject      admin     {reason}                                                              audited
 *   POST /ad-manage/requests/:id/cancel      admin     the requester                                                         audited
 *   POST /ad-manage/requests/:id/review      admin     {note} - the second look at an emergency disable (not the requester) audited
 *   POST /ad-manage/requests/:id/reveal      admin     the requester, once: the temporary password                          audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const SAM = /^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/;                       // sAMAccountName: at most 20 characters
const OU_DN = /^OU=[^,=\u0000-\u001f]{1,64}(,(OU|DC)=[^,=\u0000-\u001f]{1,64})+$/i;
const GROUP = /^[A-Za-z0-9 ._&()-]{1,128}$|^CN=[^\u0000-\u001f]{1,396}$/i;
const NAME = /^[^\u0000-\u001f<>"\\;=,+#*]{1,64}$/;
const ACTIONS = ['create', 'disable', 'enable', 'reset_password', 'unlock', 'move', 'add_group', 'remove_group', 'update', 'delete'];
const LOCKOUT_DAYS = 7;   // how far back the SIEM is asked for the lockout source
const DELETE_DAYS = 30, REVEAL_HOURS = 72, PENDING_DAYS = 7, DAY = 86400000;
const UPDATABLE = ['department', 'title', 'company', 'physicalDeliveryOfficeName', 'telephoneNumber', 'displayName'];

function createAdManage(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, iso = () => new Date(now()).toISOString();
  const C = () => store.collection('ad_manage'), R = () => store.collection('ad_manage_requests'), S = () => store.collection('ad_manage_secrets');
  const OB = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const PRIV = () => opts.privileged || PRIVILEGED;   // every built-in group that grants control of servers, the domain or Exchange
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-ad-manage' });
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('ad-manage:' + key, 600000, 'warn', msg, detail); };
  const SYSTEM = { user: 'system:ad-manage', role: 'system', ip: '' };
  const low = (s) => String(s || '').trim().toLowerCase();
  const settings = () => Object.assign({ enabled: false, delete_enabled: false, create_ou: '', protected: [] }, (C().get('settings') || {}).v || {});

  function connection() {
    const a = OB(); if (!a) return { ok: false, why: 'HR onboarding (which holds the directory connection) is not installed - run the update' };
    const c = a.cfg(); if (!(c.bind_enc && (c.servers || []).length && c.base_dn)) return { ok: false, why: 'the directory connection is not set - an administrator sets it in HR Onboarding -> Directory settings (servers, base DN, bind account)' };
    return { ok: true, servers: c.servers, base_dn: c.base_dn, bind_dn: c.bind_dn, upn_suffix: c.upn_suffix || '', ou: c.ou || '', never_disable: c.never_disable || [] };
  }
  function ready() {
    const cn = connection(); if (!cn.ok) throw httpErr(409, cn.why);
    if (!settings().enabled) throw httpErr(409, 'AD management is switched off - an administrator switches it on in AD Management -> Settings');
    return cn;
  }
  const W = () => OB().writer();
  async function ad(what, fn) {
    try { return await fn(W()); } catch (e) {
      if (e.status) throw e;
      warn(what, 'AD management: ' + what + ' failed', { err: String(e.message).slice(0, 200) });
      throw httpErr(424, 'the directory refused or could not be reached (' + what + '): ' + String(e.message).slice(0, 200));
    }
  }
  const inBase = (dn, cn) => low(dn).endsWith(',' + low(cn.base_dn)) || low(dn) === low(cn.base_dn);
  const cnOf = (dn) => { const m = /^CN=((?:[^,\\]|\\.)+)/i.exec(String(dn || '')); return m ? m[1].replace(/\\(.)/g, '$1') : String(dn || ''); };

  // why this account may not be changed from here ('' = it may)
  function protectedWhy(u, cn, who) {
    const s = settings(), sam = low(u.sam);
    if (u.admin_count) return 'a privileged account (adminCount = 1) - change it in Active Directory Users and Computers';
    const pg = (u.member_of || []).map(cnOf).find((g) => PRIV().test(g));
    if (pg) return 'a member of the privileged group ' + pg + ' - change it in Active Directory Users and Computers';
    if (cn.bind_dn && low(u.dn) === low(cn.bind_dn)) return 'the account the platform uses to reach the directory';
    if (cn.never_disable.map(low).includes(sam) || (s.protected || []).map(low).includes(sam)) return 'on the protected list (break-glass or service account)';
    if (who && sam === low(String(who.user).replace(/@.*$/, ''))) return 'your own account - another administrator requests changes to it';
    if (!inBase(u.dn, cn)) return 'outside the directory base the platform manages';
    return '';
  }
  function deleteWhy(u) {
    if (!settings().delete_enabled) return 'deleting is switched off in the settings';
    if (u.enabled) return 'the account is enabled - disable it first; it can be deleted ' + DELETE_DAYS + ' days after that';
    const wc = u.when_changed ? Date.parse(u.when_changed) : NaN;
    if (!Number.isFinite(wc)) return 'the directory did not say when the account last changed, so ' + DELETE_DAYS + ' days disabled cannot be shown';
    const days = Math.floor((now() - wc) / DAY);
    if (days < DELETE_DAYS) return 'disabled and unchanged for ' + days + ' day(s) - deleting is possible after ' + DELETE_DAYS + ' (from ' + new Date(wc + DELETE_DAYS * DAY).toISOString().slice(0, 10) + ')';
    return '';
  }
  async function account(sam, cn) {
    const u = await ad('read', (w) => w.findUser(sam));
    if (!u) throw httpErr(404, 'no account ' + sam + ' in the directory');
    return u;
  }
  // where the lockouts came from: the SIEM's 4740 events (caller computer) through the platform's one SIEM link, read as the
  // analyst role (named accounts). Never required - a SIEM that is not linked or not answering says so and the unlock goes on.
  const SIEM_WHO = { user: 'system:itam-ad-manage', role: 'analyst' };
  async function lockoutSource(sam) {
    const q = { q: 'action:account-locked AND target_user:"' + low(sam) + '"', from: 'now-' + LOCKOUT_DAYS + 'd', to: 'now', field: 'fields.caller_computer', limit: 5 };
    try {
      let r;
      if (opts.siem) r = await opts.siem('POST', '/top', q);
      else { const L = app.discovery && app.discovery.siem; if (!L || typeof L.call !== 'function' || (L.configured && !L.configured())) return { available: false, reason: 'the SIEM is not linked to IT Asset Management' }; r = await L.call('POST', '/top', SIEM_WHO, q); }
      if (!r || r.status === 404) return { available: false, reason: 'this SIEM version does not answer lockout questions - update the SIEM' };
      if (r.status !== 200 || !r.json || !Array.isArray(r.json.values)) return { available: false, reason: 'the SIEM answered HTTP ' + (r && r.status) };
      const values = r.json.values.filter((v) => v && v.v).slice(0, 5).map((v) => ({ computer: String(v.v).slice(0, 128), lockouts: Number(v.n) || 0 }));
      return { available: true, days: LOCKOUT_DAYS, sources: values, note: values.length ? '' : 'no lockout event (4740) for this account in the SIEM in the last ' + LOCKOUT_DAYS + ' days - are the domain controllers\' Security logs collected?' };
    } catch (e) {
      warn('siem', 'AD management: lockout source not read from the SIEM', { err: String(e.message).slice(0, 160) });
      return { available: false, reason: 'the SIEM could not be read (' + String(e.message).slice(0, 120) + ')' };
    }
  }
  const pub = (u, cn, who) => {
    const p = protectedWhy(u, cn, who), d = p || deleteWhy(u);
    return { sam: u.sam, upn: u.upn, display_name: u.display_name, mail: u.mail || '', department: u.department, title: u.title, enabled: u.enabled, dn: u.dn,
      groups: (u.member_of || []).map(cnOf).sort(), last_logon: u.last_logon, when_changed: u.when_changed || null, privileged: !!u.admin_count,
      protected: !!p, protected_why: p, can_delete: !d, delete_why: d, lockout_time: u.lockout_time || null, locked: !!u.lockout_time };
  };

  function view(who) {
    const cn = connection(), s = settings();
    const reqs = R().all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 300).map((r) => Object.assign({}, r, { secret: undefined,
      password_ready: !!(S().get(r.id) && r.by === who.user), password_waiting: !!S().get(r.id) }));
    return { connection: cn.ok ? { ok: true, servers: cn.servers, base_dn: cn.base_dn, upn_suffix: cn.upn_suffix, default_ou: s.create_ou || cn.ou } : cn, settings: s,
      delete_days: DELETE_DAYS, requests: reqs, pending: reqs.filter((r) => r.status === 'pending').length, reviews: reqs.filter((r) => r.review === 'pending').length,
      note: 'Every change is approved by a second administrator before it reaches Active Directory. Privileged and protected accounts are changed in Active Directory itself.' };
  }
  async function lookup(sam0, who) {
    if (!SAM.test(String(sam0 || ''))) throw httpErr(400, 'sam must be an AD user name (sAMAccountName, at most 20 characters)');
    const cn = connection(); if (!cn.ok) throw httpErr(409, cn.why);
    const u = await account(sam0, cn), out = pub(u, cn, who);
    if (u.lockout_time) {   // lockoutTime stays set after the lockout duration ran out: the computed flag says whether it still holds
      const x = await ad('read', (w) => w.read(u.dn));
      out.locked = !!(x && x.locked);
      if (out.locked) out.lockout_source = await lockoutSource(u.sam);
    }
    audit(who, 'ad_manage.lookup', u.sam, {});
    return out;
  }
  function saveSettings(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person changes the AD management settings, not a service or AI identity');
    const b = body(b0 || {}).bool('enabled', { def: false }).bool('delete_enabled', { def: false })
      .str('create_ou', { max: 400, re: /^$|^OU=/i, msg: 'create_ou must be an OU distinguished name (OU=...,DC=...) or empty for the HR onboarding OU' })
      .list('protected', { item: 'str', itemMax: 20, max: 500, unique: true, def: [] }).done();
    if (b.create_ou && !OU_DN.test(b.create_ou)) throw httpErr(400, 'create_ou must be an OU distinguished name (OU=...,DC=...)');
    for (const p of b.protected) if (!SAM.test(p)) throw httpErr(400, 'protected: ' + p + ' is not an AD user name');
    const cn = connection(); if (b.create_ou && cn.ok && !inBase(b.create_ou, cn)) throw httpErr(400, 'create_ou must be inside ' + cn.base_dn);
    const before = settings();
    C().put({ id: 'settings', v: b, by: who.user, at: iso() });
    audit(who, 'ad_manage.settings', 'settings', { enabled: b.enabled, delete_enabled: b.delete_enabled, create_ou: b.create_ou || '', protected: b.protected.length,
      changed: Object.keys(b).filter((k) => JSON.stringify(b[k]) !== JSON.stringify(before[k])) });
    return view(who);
  }

  // ---- requests
  async function request(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person requests a directory change, not a service or AI identity');
    const cn = ready();
    const a = (b0 && b0.action) || '';
    const v = body(b0 || {}).oneOf('action', ACTIONS, { required: true })
      .str('sam', { required: true, re: SAM, msg: 'sam must be an AD user name (letters, digits, . _ -; at most 20 characters)' })
      .str('reason', { required: true, min: 5, max: 500 }).bool('emergency', { def: false });
    if (a === 'create') v.str('given_name', { required: true, re: NAME, msg: 'given_name has characters AD does not accept' }).str('surname', { required: true, re: NAME, msg: 'surname has characters AD does not accept' })
      .str('display_name', { re: NAME, msg: 'display_name has characters AD does not accept' }).str('upn', { max: 120, email: true }).str('ou', { max: 400 })
      .str('department', { max: 64 }).str('title', { max: 64 }).list('groups', { item: 'str', itemMax: 400, max: 20, unique: true, def: [] }).bool('enable', { def: true });
    if (a === 'move') v.str('ou', { required: true, max: 400 });
    if (a === 'add_group' || a === 'remove_group') v.str('group', { required: true, max: 400, re: GROUP, msg: 'group must be a group name or its DN (CN=...)' });
    if (a === 'update') v.str('department', { max: 64 }).str('title', { max: 64 }).str('company', { max: 64 }).str('physicalDeliveryOfficeName', { max: 128 })
      .str('telephoneNumber', { max: 32, re: /^[0-9 +()-]*$/, msg: 'telephoneNumber: digits, spaces and + ( ) - only' }).str('displayName', { max: 64, re: NAME, msg: 'displayName has characters AD does not accept' });
    const b = v.rule((o) => (o.emergency && o.action !== 'disable' ? 'emergency is only for disabling an account' : '')).done();
    const r = { id: 'adr_' + crypto.randomBytes(8).toString('hex'), action: b.action, sam: b.sam, reason: b.reason, by: who.user, by_role: who.role || '', at: iso(), status: 'pending', history: [] };

    if (b.action === 'create') {
      const ou = b.ou || settings().create_ou || cn.ou;
      if (!OU_DN.test(ou) || !inBase(ou, cn)) throw httpErr(400, 'ou must be an OU inside ' + cn.base_dn);
      const upn = b.upn || (cn.upn_suffix ? b.sam + '@' + cn.upn_suffix : '');
      if (!upn) throw httpErr(400, 'upn is required (no UPN suffix is set in HR Onboarding -> Directory settings)');
      for (const g of b.groups) { if (!GROUP.test(g)) throw httpErr(400, 'groups: ' + g + ' is not a group name or DN'); if (PRIV().test(cnOf(g))) throw httpErr(403, 'groups: ' + cnOf(g) + ' is a privileged group - add it in Active Directory Users and Computers'); }
      const dup = await ad('check', (w) => w.exists({ sam: b.sam, upn }));
      if (dup) throw httpErr(409, 'an account ' + b.sam + ' / ' + upn + ' already exists in the directory');
      for (const g of b.groups) if (!(await ad('group', (w) => w.findGroup(g)))) throw httpErr(400, 'groups: ' + g + ' was not found in the directory');
      r.create = { given_name: b.given_name, surname: b.surname, display_name: b.display_name || (b.given_name + ' ' + b.surname), upn, ou, department: b.department || '', title: b.title || '', groups: b.groups, enable: b.enable };
      r.summary = 'create ' + b.sam + ' (' + r.create.display_name + ') in ' + ou + (b.groups.length ? ', groups ' + b.groups.map(cnOf).join(', ') : '') + (b.enable ? ', enabled' : ', disabled');
    } else {
      const u = await account(b.sam, cn), p = protectedWhy(u, cn, who);
      if (p) throw httpErr(403, b.sam + ' is ' + p);
      r.target = { dn: u.dn, display_name: u.display_name, enabled: u.enabled };
      if (b.action === 'disable' && !u.enabled) throw httpErr(409, b.sam + ' is already disabled');
      if (b.action === 'enable' && u.enabled) throw httpErr(409, b.sam + ' is already enabled');
      if (b.action === 'delete') { const d = deleteWhy(u); if (d) throw httpErr(409, b.sam + ' cannot be deleted: ' + d); }
      if (b.action === 'unlock') {
        const x = await ad('read', (w) => w.read(u.dn));
        if (!x || !x.locked) throw httpErr(409, b.sam + ' is not locked out' + (u.lockout_time ? ' (the lockout of ' + u.lockout_time.slice(0, 16).replace('T', ' ') + ' UTC has already run out)' : ''));
        const src = await lockoutSource(u.sam);
        r.lockout = { lockout_time: x.lockout_time || u.lockout_time || null, sources: src.available ? src.sources : [], source_note: src.available ? (src.note || '') : src.reason };
      }
      if (b.action === 'move') {
        if (!OU_DN.test(b.ou) || !inBase(b.ou, cn)) throw httpErr(400, 'ou must be an OU inside ' + cn.base_dn);
        r.ou = b.ou;
      }
      if (b.action === 'add_group' || b.action === 'remove_group') {
        if (b.action === 'add_group' && PRIV().test(cnOf(b.group))) throw httpErr(403, cnOf(b.group) + ' is a privileged group - change its members in Active Directory Users and Computers');
        const g = await ad('group', (w) => w.findGroup(b.group)); if (!g) throw httpErr(400, 'group ' + b.group + ' was not found in the directory');
        const isMember = (u.member_of || []).map(low).includes(low(g));
        if (b.action === 'add_group' && isMember) throw httpErr(409, b.sam + ' is already a member of ' + cnOf(g));
        if (b.action === 'remove_group' && !isMember) throw httpErr(409, b.sam + ' is not a member of ' + cnOf(g));
        r.group = g;
      }
      if (b.action === 'update') {
        const ch = {}; for (const k of UPDATABLE) if (b0[k] !== undefined && b[k] !== undefined) ch[k] = b[k]; else if (b0[k] === '') ch[k] = '';
        if (!Object.keys(ch).length) throw httpErr(400, 'nothing to change - give at least one of ' + UPDATABLE.join(', '));
        r.changes = ch;
      }
      r.summary = { disable: 'disable', enable: 'enable', reset_password: 'reset the password of', unlock: 'unlock', move: 'move', add_group: 'add', remove_group: 'remove', update: 'change the details of', delete: 'DELETE' }[b.action] + ' ' + b.sam
        + (b.action === 'unlock' ? (r.lockout.lockout_time ? ' (locked out ' + r.lockout.lockout_time.slice(0, 16).replace('T', ' ') + ' UTC' + (r.lockout.sources.length ? ', from ' + r.lockout.sources.map((x) => x.computer).join(', ') : '') + ')' : '') : '')
        + (b.action === 'move' ? ' to ' + r.ou : b.action === 'add_group' ? ' to ' + cnOf(r.group) : b.action === 'remove_group' ? ' from ' + cnOf(r.group) : b.action === 'update' ? ': ' + Object.keys(r.changes).join(', ') : '');
    }
    r.history.push({ at: r.at, by: who.user, what: 'requested', note: b.reason });
    if (b.emergency) {
      r.emergency = true; R().put(r);
      audit(who, 'ad_manage.emergency_disable', b.sam, { id: r.id, reason: b.reason });
      return execute(r, who, true);
    }
    R().put(r);
    audit(who, 'ad_manage.request', b.sam, { id: r.id, action: r.action, summary: r.summary, reason: b.reason });
    return R().get(r.id);
  }
  const get = (id) => { const r = R().get(id); if (!r) throw httpErr(404, 'no such request'); return r; };
  const pendingOnly = (r) => { if (r.status !== 'pending') throw httpErr(409, 'the request is ' + r.status + ', not pending'); if (Date.parse(r.at) + PENDING_DAYS * DAY <= now()) { expireOne(r); throw httpErr(410, 'the request expired unapproved after ' + PENDING_DAYS + ' days - request it again'); } };

  async function approve(id, b0, who) {
    body(b0 || {}).str('note', { max: 500 }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a person approves a directory change, not a service or AI identity');
    const r = get(id); pendingOnly(r);
    if (low(r.by) === low(who.user)) throw httpErr(403, 'four eyes: a different administrator approves - you requested this');
    ready();
    return execute(r, who, false);
  }
  // write to AD, read back, verify; the conditions are checked again here (the directory may have changed since the request)
  async function execute(r0, who, emergency) {
    const cn = connection(), r = R().get(r0.id);
    let result = '', pw = null;
    try {
      if (r.action === 'create') {
        const c = r.create; pw = tempPassword();
        const made = await ad('create', (w) => w.createUser(c.ou, { sAMAccountName: r.sam, userPrincipalName: c.upn, displayName: c.display_name, givenName: c.given_name, sn: c.surname, department: c.department, title: c.title }, pw, 'Created through Zyberon AD request ' + r.id));
        for (const g of c.groups) { const gd = await ad('group', (w) => w.findGroup(g)); if (!gd) throw httpErr(424, 'group ' + g + ' is no longer in the directory - the account was created without it'); await ad('group', (w) => w.addToGroup(gd, made.dn)); }
        if (c.enable) await ad('enable', (w) => w.setEnabled(made.dn, true));
        const back = await ad('read back', (w) => w.read(made.dn));
        if (!back || !back.must_change || back.enabled !== !!c.enable) throw httpErr(424, 'the account was written but the read-back does not match (enabled / change at first sign-in) - check it in Active Directory');
        r.created_dn = made.dn; result = 'created ' + made.dn + (c.enable ? ', enabled' : ', disabled') + ', password must be changed at first sign-in';
      } else {
        const u = await account(r.sam, cn), p = protectedWhy(u, cn, null);
        if (p) throw httpErr(403, r.sam + ' is now ' + p + ' - not changed');
        if (low(u.dn) !== low(r.target.dn)) throw httpErr(409, r.sam + ' moved or was renamed since the request (' + u.dn + ') - request it again');
        if (r.action === 'disable') { await ad('disable', (w) => w.setEnabled(u.dn, false)); const x = await ad('read back', (w) => w.read(u.dn)); if (!x || x.enabled) throw httpErr(424, 'the directory still shows ' + r.sam + ' enabled'); result = 'disabled'; }
        if (r.action === 'enable') { await ad('enable', (w) => w.setEnabled(u.dn, true)); const x = await ad('read back', (w) => w.read(u.dn)); if (!x || !x.enabled) throw httpErr(424, 'the directory still shows ' + r.sam + ' disabled'); result = 'enabled'; }
        if (r.action === 'reset_password') { pw = tempPassword(); await ad('password', (w) => w.resetPassword(u.dn, pw)); const x = await ad('read back', (w) => w.read(u.dn)); if (!x || !x.must_change) throw httpErr(424, 'the password was set but "change at first sign-in" is not shown'); result = 'temporary password set, change at first sign-in'; }
        if (r.action === 'unlock') {
          const x0 = await ad('read', (w) => w.read(u.dn));
          if (x0 && !x0.locked) result = 'already unlocked (the lockout ran out or was cleared in AD) - nothing written';
          else { await ad('unlock', (w) => w.unlock(u.dn)); const x = await ad('read back', (w) => w.read(u.dn)); if (!x || x.locked) throw httpErr(424, 'the directory still shows ' + r.sam + ' locked out'); result = 'unlocked (the password was not changed)'; }
        }
        if (r.action === 'move') { const nd = await ad('move', (w) => w.move(u.dn, r.ou)); r.new_dn = nd; result = 'moved to ' + r.ou; }
        if (r.action === 'add_group') { await ad('group', (w) => w.addToGroup(r.group, u.dn)); const x = await ad('read back', (w) => w.read(u.dn)); if (!x || !x.member_of.map(low).includes(low(r.group))) throw httpErr(424, 'the directory does not show the new membership'); result = 'added to ' + cnOf(r.group); }
        if (r.action === 'remove_group') { await ad('group', (w) => w.removeFromGroup(r.group, u.dn)); const x = await ad('read back', (w) => w.read(u.dn)); if (!x || x.member_of.map(low).includes(low(r.group))) throw httpErr(424, 'the directory still shows the membership'); result = 'removed from ' + cnOf(r.group); }
        if (r.action === 'update') { await ad('details', (w) => w.setAttrs(u.dn, r.changes)); result = 'changed ' + Object.keys(r.changes).join(', '); }
        if (r.action === 'delete') {
          const d = deleteWhy(u); if (d) throw httpErr(409, r.sam + ' cannot be deleted now: ' + d);
          await ad('delete', (w) => w.deleteUser(u.dn));
          if (await ad('read back', (w) => w.findUser(r.sam))) throw httpErr(424, 'the directory still has ' + r.sam);
          result = 'deleted';
        }
      }
    } catch (e) {
      Object.assign(r, { status: 'failed', decided_by: who.user, decided_at: iso(), error: String(e.message).slice(0, 300) });
      if (emergency) r.review = 'pending';
      r.history.push({ at: iso(), by: who.user, what: 'failed', note: r.error }); R().put(r);
      audit(who, 'ad_manage.failed', r.sam, { id: r.id, action: r.action, error: r.error });
      throw e.status ? e : httpErr(424, r.error);
    }
    if (pw) {
      if (!sealer.available()) { warn('vault', 'AD management: the vault is unavailable, the temporary password cannot be kept', { id: r.id }); r.password_note = 'the vault was unavailable: request a password reset to issue a new one'; }
      else S().put({ id: r.id, enc: sealer.seal('temp:' + r.id, pw), at: iso(), expires_at: new Date(now() + REVEAL_HOURS * 3600000).toISOString() });
      pw = null;
    }
    Object.assign(r, { status: 'done', decided_by: who.user, decided_at: iso(), result });
    if (emergency) r.review = 'pending';
    r.history.push({ at: iso(), by: who.user, what: emergency ? 'emergency disable (review pending)' : 'approved and written', note: result }); R().put(r);
    audit(who, emergency ? 'ad_manage.emergency_done' : 'ad_manage.approve', r.sam, { id: r.id, action: r.action, requested_by: r.by, result });
    return R().get(r.id);
  }
  function reject(id, b0, who) {
    const b = body(b0 || {}).str('reason', { required: true, min: 3, max: 500 }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a person rejects a directory change, not a service or AI identity');
    const r = get(id); pendingOnly(r);
    Object.assign(r, { status: 'rejected', decided_by: who.user, decided_at: iso(), note: b.reason }); r.history.push({ at: iso(), by: who.user, what: 'rejected', note: b.reason }); R().put(r);
    audit(who, 'ad_manage.reject', r.sam, { id: r.id, action: r.action, requested_by: r.by, reason: b.reason });
    return r;
  }
  function cancel(id, b0, who) {
    body(b0 || {}).done();
    const r = get(id); pendingOnly(r);
    if (low(r.by) !== low(who.user)) throw httpErr(403, 'only the requester cancels a request - reject it instead');
    Object.assign(r, { status: 'cancelled', decided_by: who.user, decided_at: iso() }); r.history.push({ at: iso(), by: who.user, what: 'cancelled' }); R().put(r);
    audit(who, 'ad_manage.cancel', r.sam, { id: r.id, action: r.action });
    return r;
  }
  function review(id, b0, who) {
    const b = body(b0 || {}).str('note', { required: true, min: 3, max: 500 }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a person reviews an emergency disable, not a service or AI identity');
    const r = get(id); if (r.review !== 'pending') throw httpErr(409, 'this request has no review waiting');
    if (low(r.by) === low(who.user)) throw httpErr(403, 'four eyes: a different administrator reviews your emergency disable');
    Object.assign(r, { review: 'done', reviewed_by: who.user, reviewed_at: iso(), review_note: b.note }); r.history.push({ at: iso(), by: who.user, what: 'emergency disable reviewed', note: b.note }); R().put(r);
    audit(who, 'ad_manage.review', r.sam, { id: r.id, requested_by: r.by, note: b.note });
    return r;
  }
  function reveal(id, b0, who) {
    body(b0 || {}).done();
    const r = get(id);
    if (low(r.by) !== low(who.user)) throw httpErr(403, 'only the requester sees the temporary password, once');
    const s = S().get(r.id); if (!s) throw httpErr(410, 'the temporary password was already shown or has expired - request a password reset');
    if (Date.parse(s.expires_at) <= now()) { S().remove(r.id); throw httpErr(410, 'the temporary password expired unrevealed (' + REVEAL_HOURS + ' h) and was destroyed - request a password reset'); }
    let pw; try { pw = sealer.unseal('temp:' + r.id, s.enc); } catch (e) { throw httpErr(503, 'the temporary password cannot be opened from the vault - request a password reset'); }
    S().remove(r.id);
    r.history.push({ at: iso(), by: who.user, what: 'temporary password shown (once)' }); R().put(r);
    audit(who, 'ad_manage.password_shown', r.sam, { id: r.id });
    return { sam: r.sam, password: pw, note: 'Shown once. The person must change it at first sign-in.' };
  }
  function expireOne(r) {
    Object.assign(r, { status: 'expired', decided_at: iso() }); r.history.push({ at: iso(), by: SYSTEM.user, what: 'expired unapproved' }); R().put(r);
    audit(SYSTEM, 'ad_manage.expired', r.sam, { id: r.id, action: r.action, requested_by: r.by });
  }
  function tick() {
    let n = 0;
    for (const r of R().all((x) => x.status === 'pending' && Date.parse(x.at) + PENDING_DAYS * DAY <= now())) { expireOne(r); n++; }
    for (const s of S().all((x) => Date.parse(x.expires_at) <= now())) { S().remove(s.id); audit(SYSTEM, 'ad_manage.password_destroyed', s.id, { unrevealed_hours: REVEAL_HOURS }); n++; }
    return n;
  }
  if (!(app.noTimers || opts.noTimer)) { const t = setInterval(guardOf(app, 'ad_manage.expire', tick), 3600000); if (t.unref) t.unref(); }

  return { view, lookup, saveSettings, request, approve, reject, cancel, review, reveal, tick, connection, DELETE_DAYS };
}

function registerAdManage(srv, app, X) {
  srv.route('GET', '/ad-manage', (ctx) => { ctx.need('operator'); return X.view(ctx.who); });
  srv.route('GET', '/ad-manage/user/:sam', (ctx) => { ctx.need('operator'); return X.lookup(ctx.params.sam, ctx.who); });
  srv.route('POST', '/ad-manage/settings', (ctx) => { ctx.need('admin'); return X.saveSettings(ctx.body, ctx.who); }, { maxBody: 16384 });
  srv.route('POST', '/ad-manage/requests', (ctx) => { ctx.need('admin'); return X.request(ctx.body, ctx.who); }, { maxBody: 16384 });
  for (const [verb, fn] of [['approve', 'approve'], ['reject', 'reject'], ['cancel', 'cancel'], ['review', 'review'], ['reveal', 'reveal']]) {
    srv.route('POST', '/ad-manage/requests/:id/' + verb, (ctx) => { ctx.need('admin'); if (!/^adr_[0-9a-f]{16}$/.test(String(ctx.params.id))) throw Object.assign(new Error('id is not a valid request id'), { status: 400 }); return X[fn](ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  }
}
module.exports = { createAdManage, registerAdManage, DELETE_DAYS };
