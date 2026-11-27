// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * PAM Center ({P} = /api/itam; Identity -> PAM Center) - the organisation's privileged access in one place, and the safe for the
 * accounts that cannot be personal (break-glass domain admin, local administrator, firewall / switch admin, root, ERP super user).
 *   inventory   every privileged identity the platform can see: directory accounts protected by AdminSDHolder (admin_count, i.e.
 *               members of the built-in admin groups) from the directory read (engine/ad-directory.js); the just-in-time requests
 *               and active grants (engine/pam.js); privileged non-human identities (engine/nhi.js); the safe's shared accounts.
 *   risk        per identity 0-100, every point named: standing privilege (held all the time instead of just in time), dormant but
 *               enabled, never signed in, a shared / built-in name, a person's everyday account holding admin rights (no separate
 *               admin account); per safe entry: rotation overdue, checked out and not returned, used out of hours.
 *   ML          checkouts per week of each safe entry judged against that entry's own history (robust z on median / MAD, 4+ weeks):
 *               a week far above usual is flagged; until there is history the entry is "learning", never "normal".
 *   maturity    a PAM maturity index 0-100 from what is measured (standing privilege share, separate admin accounts, dormant
 *               privileged accounts, shared accounts in the safe, rotation on time, checkouts returned) - parts not measured say so.
 *   safe        an administrator adds an entry (system, account, kind, owner, rotation days, most hours per checkout) with its secret,
 *               sealed AES-256-GCM with the platform key. To USE it, an operator requests a checkout (reason, ticket, hours); a
 *               DIFFERENT person - an administrator, never the requester, never an AI or service identity - approves; within the
 *               window only the requester can reveal the secret, at most 3 times, each reveal audited (never the value); check-in
 *               ends it and marks the entry for rotation (one use, then a new password). The owner records the rotation with the new
 *               secret. The platform never logs, audits or returns a secret except to the approved requester inside the window, and
 *               never changes a password on a system itself - the owner rotates it there.
 *   ask         the read-only AI advisor (intel kit: budget, redactSecrets, untrusted(), UNTRUSTED_RULE, tools re-checked) - it never
 *               sees a secret: its tool returns the view, which holds none.
 *   GET  /pam-center                       operator  the picture (it names privileged accounts)
 *   POST /pam-center/safe                  admin     add an entry with its secret
 *   PUT  /pam-center/safe/:id              admin     edit an entry (not its secret)
 *   POST /pam-center/safe/:id/rotate       operator  the owner or an administrator records the new secret
 *   POST /pam-center/checkouts             operator  request a checkout
 *   POST /pam-center/checkouts/:id/decide  admin     approve / reject - another person
 *   POST /pam-center/checkouts/:id/reveal  operator  the approved requester, inside the window
 *   POST /pam-center/checkouts/:id/checkin operator  the requester or an administrator
 *   POST /pam-center/ask                   operator  the advisor
 */
const crypto = require('crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const { createSealer } = require('./discovery/vault');
const { createIntelKit, robustZ } = require('./intel-kit');
const ZYB_ORG = require('./brand');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const DAY = 864e5, H = 36e5, KINDS = { 'break-glass': 'Break-glass domain admin', 'local-admin': 'Local administrator', 'network-admin': 'Network device admin', root: 'Unix / Linux root', 'db-admin': 'Database admin', 'app-admin': 'Application super user', 'cloud-admin': 'Cloud admin', service: 'Service account' };
const SHARED_NAME = /^(admin|administrator|root|sa|sysadm|backup|svc[_-]|service|it[_-]?admin|support|helpdesk|test)/i;
const ADMIN_SUFFIX = /([._-](adm|admin|a|da|t0|t1)$)|^(adm|admin)[._-]/i;
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const riyadhHour = (ms) => (new Date(ms).getUTCHours() + 3) % 24, riyadhDay = (ms) => new Date(ms + 3 * H).getUTCDay();
const outOfHours = (ms) => { const h = riyadhHour(ms), d = riyadhDay(ms); return d === 5 || d === 6 || h < 7 || h >= 18; };

function createPamCenter(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString();
  const SAFE = () => app.store.collection('pamc_safe'), CO = () => app.store.collection('pamc_checkouts');
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-pam-center' });
  const A = () => app.addons || {};
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'pamc.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who.user)) throw bad('a person ' + what + '; an AI or service identity never does', 403); };
  const same = (a, b) => low(a) === low(b);
  const nid = (col, pre) => { let n = col().all().length + 1, id; do { id = pre + String(n++).padStart(4, '0'); } while (col().get(id)); return id; };

  // ---------- inventory and risk ----------
  async function sources() {
    const out = { directory: null, jit: null, nhi: null, notes: [] };
    try { const D = A().adDirectory; if (D) { const v = D.view(); out.directory = { connected: !!(v.connection && v.connection.ok), read_at: v.last ? v.last.at : null, users: v.users || [] }; if (!out.directory.connected) out.notes.push('Directory not connected: HR Onboarding -> Directory, then Directory Users -> read.'); } else out.notes.push('Directory users module not installed.'); }
    catch (e) { out.notes.push('directory: ' + String(e.message).slice(0, 120)); }
    try { const P = A().pam; if (P) out.jit = P.list({ user: 'system:pam-center', role: 'admin' }); } catch (e) { out.notes.push('just-in-time requests: ' + String(e.message).slice(0, 120)); }
    try { const N = A().nhi; if (N && typeof N.view === 'function') { const v = await N.view(); out.nhi = (v.items || []).filter((x) => x.privileged); } } catch (e) { out.notes.push('non-human identities: ' + String(e.message).slice(0, 120)); }
    return out;
  }
  function identities(S) {
    const t = now(), jitActive = new Set(((S.jit && S.jit.active) || []).map((r) => low(r.requester))), L = [];
    for (const u of ((S.directory && S.directory.users) || []).filter((x) => x.admin_count)) {
      const reasons = [], add = (p, w) => reasons.push({ points: p, why: w }), ll = u.last_logon ? Date.parse(u.last_logon) : null, idle = ll ? Math.floor((t - ll) / DAY) : null;
      if (!jitActive.has(low(u.sam))) add(30, 'standing privilege - held all the time, not just in time');
      if (u.enabled && idle !== null && idle > 90) add(20, 'enabled but not signed in for ' + idle + ' days');
      if (u.enabled && ll === null) add(15, 'enabled and never signed in');
      if (SHARED_NAME.test(u.sam)) add(15, 'a shared or built-in name - nobody can be held accountable for its use');
      else if (!ADMIN_SUFFIX.test(u.sam)) add(15, 'looks like a person\'s everyday account holding admin rights - use a separate admin account');
      if (!u.enabled) reasons.length = 0;
      L.push({ id: 'ad:' + u.sam, source: 'directory', name: u.sam, display: u.display_name || '', kind: SHARED_NAME.test(u.sam) ? 'shared' : 'person', enabled: !!u.enabled, last_logon: u.last_logon || null, idle_days: idle,
        risk: Math.min(100, reasons.reduce((n, r) => n + r.points, 0)), reasons });
    }
    for (const n of S.nhi || []) {
      const reasons = []; if (n.secret_age_days != null && n.secret_age_days > 365) reasons.push({ points: 25, why: 'secret ' + n.secret_age_days + ' days old' }); if (!n.owner) reasons.push({ points: 20, why: 'no owner' });
      L.push({ id: 'nhi:' + n.id, source: 'non-human identities', name: n.name, display: n.kind_name || '', kind: 'service', enabled: true, last_logon: n.last_used || null, idle_days: null, risk: Math.min(100, reasons.reduce((a, r) => a + r.points, 0)), reasons });
    }
    return L.sort((a, b) => b.risk - a.risk);
  }
  function safeRows() {
    const t = now(), C = CO().all();
    return SAFE().all((e) => !e.retired).map((e) => {
      const mine = C.filter((c) => c.entry === e.id), last = e.last_rotated ? Date.parse(e.last_rotated) : Date.parse(e.created_at);
      const due = last + e.rotate_days * DAY, overdue = e.rotation_due || t > due, open = mine.filter((c) => c.state === 'approved' && Date.parse(c.until) < t && !c.checked_in_at);
      // ML: checkouts per week against the entry's own weeks (robust z), judged from 4 weeks of history
      const weeks = []; for (let w = 11; w >= 0; w--) { const a = t - (w + 1) * 7 * DAY, b = t - w * 7 * DAY; weeks.push(mine.filter((c) => { const x = Date.parse(c.at); return x >= a && x < b; }).length); }
      const zr = weeks.slice(0, -1).filter((x, i, arr) => arr.slice(0, i + 1).some((y) => y > 0)).length >= 4 ? robustZ(weeks.slice(0, -1), weeks[weeks.length - 1]) : null, z = zr ? zr.z : null;
      const reasons = []; if (overdue) reasons.push({ points: e.rotation_due ? 25 : 30, why: e.rotation_due ? 'used and not rotated since' : 'rotation overdue (every ' + e.rotate_days + ' days)' });
      if (open.length) reasons.push({ points: 30, why: open.length + ' checkout(s) ended without check-in' });
      const ooh = mine.filter((c) => c.revealed_at && outOfHours(Date.parse(c.revealed_at)) && t - Date.parse(c.revealed_at) < 30 * DAY).length; if (ooh) reasons.push({ points: 10, why: ooh + ' use(s) out of working hours in 30 days' });
      if (z !== null && z >= 4 && weeks[weeks.length - 1] > zr.usual) reasons.push({ points: 20, why: weeks[weeks.length - 1] + ' checkouts this week - far above its usual ' + zr.usual + ' a week' + (isFinite(z) ? ' (z ' + z + ')' : ' (it never varied before)') });
      return { id: e.id, system: e.system, account: e.account, kind: e.kind, kind_label: KINDS[e.kind], owner: e.owner, rotate_days: e.rotate_days, max_hours: e.max_hours, last_rotated: e.last_rotated || null, rotation_due_at: new Date(due).toISOString().slice(0, 10),
        overdue: !!overdue, checkouts_30d: mine.filter((c) => t - Date.parse(c.at) < 30 * DAY).length, weekly: weeks, learning: z === null, risk: Math.min(100, reasons.reduce((n, r) => n + r.points, 0)), reasons, sealed: !!e.enc };
    });
  }
  function checkoutRows(who) {
    const t = now(), adm = who.role === 'admin';
    return CO().all().sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 200).map((c) => {
      let st = c.state; if (st === 'approved' && c.checked_in_at) st = 'checked-in'; else if (st === 'approved' && Date.parse(c.until) < t) st = 'expired';
      const e = SAFE().get(c.entry) || {};
      return { id: c.id, entry: c.entry, system: e.system, account: e.account, requester: c.requester, reason: adm || same(c.requester, who.user) ? c.reason : undefined, ticket: c.ticket, hours: c.hours, state: st, at: c.at,
        decided_by: c.decided_by || null, from: c.from || null, until: c.until || null, reveals: c.reveals || 0, checked_in_at: c.checked_in_at || null, mine: same(c.requester, who.user) };
    });
  }
  async function view(who) {
    const S = await sources(), I = identities(S), SF = safeRows(), CK = checkoutRows(who), t = now();
    const priv = I.filter((x) => x.source === 'directory' && x.enabled), standing = priv.filter((x) => x.reasons.some((r) => /standing/.test(r.why))), sep = priv.filter((x) => x.kind === 'person' && !x.reasons.some((r) => /everyday/.test(r.why)));
    const dormant = priv.filter((x) => x.idle_days !== null && x.idle_days > 90 || x.last_logon === null), sharedDir = priv.filter((x) => x.kind === 'shared');
    const ret = CO().all().filter((c) => c.state === 'approved' && Date.parse(c.until) < t), returned = ret.filter((c) => c.checked_in_at);
    const parts = [
      ['Standing privilege', priv.length ? Math.round(100 * (1 - standing.length / priv.length)) : null, priv.length ? standing.length + ' of ' + priv.length + ' privileged accounts hold it all the time' : 'directory not read'],
      ['Separate admin accounts', priv.filter((x) => x.kind === 'person').length ? Math.round(100 * sep.length / priv.filter((x) => x.kind === 'person').length) : null, 'people use a separate account for admin work'],
      ['No dormant admins', priv.length ? Math.round(100 * (1 - dormant.length / priv.length)) : null, dormant.length + ' dormant or never used'],
      ['Shared accounts in the safe', sharedDir.length || SF.length ? Math.round(100 * SF.filter((e) => e.kind === 'break-glass' || e.kind === 'local-admin').length / Math.max(1, sharedDir.length + SF.filter((e) => e.kind === 'break-glass' || e.kind === 'local-admin').length) * 1) : null, SF.length + ' entry(ies) vaulted, ' + sharedDir.length + ' shared directory account(s) outside'],
      ['Rotation on time', SF.length ? Math.round(100 * SF.filter((e) => !e.overdue).length / SF.length) : null, SF.filter((e) => e.overdue).length + ' overdue'],
      ['Checkouts returned', ret.length ? Math.round(100 * returned.length / ret.length) : null, ret.length - returned.length + ' not checked in'],
    ].map(([name, score, why]) => ({ name, score, why }));
    const m = parts.filter((p) => p.score !== null), maturity = m.length >= 3 ? Math.round(m.reduce((n, p) => n + p.score, 0) / m.length) : null;
    const kpis = { privileged: priv.length, standing: standing.length, jit_active: ((S.jit && S.jit.active) || []).length, jit_pending: ((S.jit && S.jit.counts) || {}).pending || 0, safe: SF.length, overdue: SF.filter((e) => e.overdue).length,
      checkouts_open: CK.filter((c) => c.state === 'approved').length, waiting: CK.filter((c) => c.state === 'pending').length, service: I.filter((x) => x.kind === 'service').length, high_risk: I.filter((x) => x.risk >= 50).length + SF.filter((e) => e.risk >= 50).length };
    return { generated_at: iso(), maturity, parts, kpis, identities: I.slice(0, 500), safe: SF, checkouts: CK, kinds: KINDS, vault: { available: sealer.available(), reason: sealer.unavailableReason() },
      jit: S.jit ? { groups: (S.jit.groups || []).map((g) => ({ name: g.name, max_hours: g.max_hours })), active: S.jit.active || [], counts: S.jit.counts || {} } : null, directory: S.directory ? { connected: S.directory.connected, read_at: S.directory.read_at } : null,
      insights: insights(I, SF, CK, standing, dormant, sharedDir), notes: S.notes, can_manage: who.role === 'admin' };
  }
  function insights(I, SF, CK, standing, dormant, sharedDir) {
    const out = [], p = (lvl, t, d) => out.push({ level: lvl, title: t, detail: d });
    if (standing.length) p('crit', standing.length + ' account(s) hold admin rights all the time', 'Standing privilege is what an attacker steals first. Remove them from the admin groups and let them request the group just in time (Privileged Access): ' + standing.slice(0, 5).map((x) => x.name).join(', ') + '.');
    if (dormant.length) p('warn', dormant.length + ' privileged account(s) dormant or never used', 'Disable them through the access review: ' + dormant.slice(0, 5).map((x) => x.name).join(', ') + '.');
    if (sharedDir.length) p('warn', sharedDir.length + ' shared admin account(s) used directly in the directory', 'Put them in the safe so every use has a named requester and an approver: ' + sharedDir.slice(0, 4).map((x) => x.name).join(', ') + '.');
    const od = SF.filter((e) => e.overdue); if (od.length) p('crit', od.length + ' safe password(s) due for rotation', od.slice(0, 5).map((e) => e.system + ' / ' + e.account).join(', ') + '. The owner changes it on the system and records it here.');
    const nr = CK.filter((c) => c.state === 'expired'); if (nr.length) p('warn', nr.length + ' checkout(s) ended without check-in', 'Ask the requesters to check in; the password is then marked for rotation.');
    const ml = SF.filter((e) => e.reasons.some((r) => /far above its usual/.test(r.why))); if (ml.length) p('crit', 'Unusual use of ' + ml.map((e) => e.system + ' / ' + e.account).join(', '), 'Checkouts this week are far above the entry\'s own usual weeks - confirm the work behind them.');
    const ooh = SF.filter((e) => e.reasons.some((r) => /out of working hours/.test(r.why))); if (ooh.length) p('info', 'Privileged use out of working hours on ' + ooh.length + ' safe entry(ies)', 'Expected for incidents; otherwise ask why.');
    return out;
  }

  // ---------- the safe ----------
  function addEntry(b0, who) {
    person(who, 'adds a safe entry'); if (!sealer.available()) throw bad('the safe is not available: ' + sealer.unavailableReason(), 503);
    const b = body(b0 || {}).str('system', { required: true, min: 2, max: 120 }).str('account', { required: true, min: 1, max: 120 }).oneOf('kind', Object.keys(KINDS), { required: true }).str('owner', { required: true, max: 64, re: /^[A-Za-z0-9._@-]+$/, msg: 'owner: a platform user name' })
      .int('rotate_days', { min: 7, max: 365, def: 90 }).int('max_hours', { min: 1, max: 24, def: 4 }).str('secret', { required: true, min: 8, max: 512 }).str('note', { max: 300 }).done();
    if (SAFE().all((e) => !e.retired && same(e.system, b.system) && same(e.account, b.account)).length) throw bad('this system / account is already in the safe', 409);
    const id = nid(SAFE, 'PS-'), secret = b.secret; delete b.secret;
    SAFE().put(Object.assign({ id, enc: sealer.seal(id, secret), fingerprint: crypto.createHash('sha256').update(id + '|' + secret).digest('hex').slice(0, 12), created_by: who.user, created_at: iso(), last_rotated: iso() }, b));
    audit(who, 'safe.add', id, { system: b.system, account: b.account, kind: b.kind, owner: b.owner });
    return { id };
  }
  function editEntry(id0, b0, who) {
    person(who, 'edits a safe entry'); const e = SAFE().get(param(id0, 'id')); if (!e || e.retired) throw bad('entry not found', 404);
    const b = body(b0 || {}).str('owner', { max: 64, re: /^[A-Za-z0-9._@-]*$/, msg: 'owner: a platform user name' }).int('rotate_days', { min: 7, max: 365 }).int('max_hours', { min: 1, max: 24 }).str('note', { max: 300 }).bool('retired', {}).done();
    SAFE().patch(e.id, (o) => Object.assign(o, b, { updated_by: who.user, updated_at: iso() })); audit(who, b.retired ? 'safe.retire' : 'safe.edit', e.id, b); return { id: e.id };
  }
  function rotate(id0, b0, who) {
    person(who, 'records a rotation'); const e = SAFE().get(param(id0, 'id')); if (!e || e.retired) throw bad('entry not found', 404);
    if (!(same(e.owner, who.user) || who.role === 'admin')) throw bad('the owner (' + e.owner + ') or an administrator records the rotation', 403);
    const b = body(b0 || {}).str('secret', { required: true, min: 8, max: 512 }).str('note', { max: 300 }).done();
    const fp = crypto.createHash('sha256').update(e.id + '|' + b.secret).digest('hex').slice(0, 12); if (fp === e.fingerprint) throw bad('secret: the same password - change it on the system first');
    if (CO().all((c) => c.entry === e.id && c.state === 'approved' && !c.checked_in_at && Date.parse(c.until) > now()).length) throw bad('a checkout is in progress - check it in first', 409);
    SAFE().patch(e.id, (o) => Object.assign(o, { enc: sealer.seal(e.id, b.secret), fingerprint: fp, last_rotated: iso(), rotated_by: who.user, rotation_due: false }));
    audit(who, 'safe.rotate', e.id, { system: e.system, account: e.account, note: b.note || null }); return { id: e.id, last_rotated: iso() };
  }
  function request(b0, who) {
    person(who, 'requests a privileged password');
    const b = body(b0 || {}).str('entry', { required: true, max: 12, re: /^PS-\d{4,}$/, msg: 'entry: a safe entry id' }).int('hours', { required: true, min: 1, max: 24 }).str('reason', { required: true, min: 10, max: 400 }).str('ticket', { max: 40 }).done();
    const e = SAFE().get(b.entry); if (!e || e.retired) throw bad('entry not found', 404);
    if (b.hours > e.max_hours) throw bad('hours: at most ' + e.max_hours + ' for ' + e.system + ' / ' + e.account);
    if (CO().all((c) => c.entry === e.id && same(c.requester, who.user) && (c.state === 'pending' || (c.state === 'approved' && !c.checked_in_at && Date.parse(c.until) > now()))).length) throw bad('you already have a request open for this account', 409);
    const rec = { id: nid(CO, 'PC-'), entry: e.id, requester: who.user, hours: b.hours, reason: b.reason, ticket: b.ticket || '', state: 'pending', at: iso() };
    CO().put(rec); audit(who, 'checkout.request', rec.id, { entry: e.id, system: e.system, account: e.account, hours: b.hours, ticket: b.ticket || null });
    return rec;
  }
  function decide(id0, b0, who) {
    person(who, 'approves a privileged password');
    const c = CO().get(param(id0, 'id')); if (!c) throw bad('request not found', 404); if (c.state !== 'pending') throw bad('request is ' + c.state, 409);
    if (same(c.requester, who.user)) throw bad('four-eyes: ' + who.user + ' requested this - another person approves', 403);
    const b = body(b0 || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 }).done();
    if (b.decision === 'reject' && !b.note) throw bad('note: say why it is rejected');
    const t = now(); CO().patch(c.id, (o) => Object.assign(o, b.decision === 'approve' ? { state: 'approved', from: new Date(t).toISOString(), until: new Date(t + c.hours * H).toISOString() } : { state: 'rejected' }, { decided_by: who.user, decided_at: iso(), note: b.note || '' }));
    audit(who, 'checkout.' + (b.decision === 'approve' ? 'approve' : 'reject'), c.id, { entry: c.entry, requester: c.requester, hours: c.hours });
    return CO().get(c.id);
  }
  function reveal(id0, who) {
    person(who, 'reveals a privileged password');
    const c = CO().get(param(id0, 'id')); if (!c) throw bad('request not found', 404);
    if (!same(c.requester, who.user)) throw bad('only the approved requester reveals the password', 403);
    if (c.state !== 'approved' || c.checked_in_at) throw bad('the request is not approved or already checked in', 409);
    if (Date.parse(c.until) < now()) throw bad('the checkout window has ended', 409);
    if ((c.reveals || 0) >= 3) throw bad('revealed 3 times already - check in and request again', 429);
    const e = SAFE().get(c.entry); if (!e || e.retired) throw bad('entry not found', 404);
    const secret = sealer.unseal(e.id, e.enc);
    CO().patch(c.id, (o) => Object.assign(o, { reveals: (o.reveals || 0) + 1, revealed_at: iso() }));
    audit(who, 'checkout.reveal', c.id, { entry: e.id, system: e.system, account: e.account, reveal: (c.reveals || 0) + 1, out_of_hours: outOfHours(now()) });
    return { system: e.system, account: e.account, secret, until: c.until, note: 'Shown once - do not copy it anywhere. Check in when done; the owner then rotates it.' };
  }
  function checkin(id0, b0, who) {
    person(who, 'checks in a privileged password');
    const c = CO().get(param(id0, 'id')); if (!c) throw bad('request not found', 404);
    if (!(same(c.requester, who.user) || who.role === 'admin')) throw bad('the requester or an administrator checks in', 403);
    if (c.state !== 'approved' || c.checked_in_at) throw bad('nothing to check in', 409);
    const b = body(b0 || {}).str('note', { max: 300 }).done();
    CO().patch(c.id, (o) => Object.assign(o, { checked_in_at: iso(), checked_in_by: who.user, note_in: b.note || '' }));
    if (c.reveals) SAFE().patch(c.entry, (o) => Object.assign(o, { rotation_due: true }));   // used: one use, then a new password
    audit(who, 'checkout.checkin', c.id, { entry: c.entry, revealed: c.reveals || 0 });
    return CO().get(c.id);
  }

  const K = createIntelKit(app, { key: 'pam-center', feature: 'itam.pam-center', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: true,
    system: 'You are the privileged access advisor for the IT security team of ' + (ZYB_ORG.name || 'the organisation') + '. You read the privileged accounts with their risk and reasons, the safe entries (never a password - you are never given one), the checkouts and the PAM maturity, and say what to fix first and why. You cannot change anything; a person approves every checkout and rotation.',
    tools: [{ name: 'pam_overview', description: 'PAM maturity, KPIs, privileged accounts with risk and reasons, safe entries (no secrets), checkouts, insights.', run: async () => { const v = await view({ user: 'system:pam-advisor', role: 'operator' }); return { maturity: v.maturity, parts: v.parts, kpis: v.kpis, identities: v.identities.slice(0, 60), safe: v.safe, checkouts: v.checkouts.slice(0, 60), insights: v.insights }; } }] });
  return { view, addEntry, editEntry, rotate, request, decide, reveal, checkin, ask: K.ask, KINDS };
}

function registerPamCenter(srv, app, X) {
  const id = (ctx) => String((ctx.params && ctx.params.id) || '');
  srv.route('GET', '/pam-center', (ctx) => { ctx.need('operator'); return X.view(ctx.who); });
  srv.route('POST', '/pam-center/safe', (ctx) => { ctx.need('admin'); return X.addEntry(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('PUT', '/pam-center/safe/:id', (ctx) => { ctx.need('admin'); return X.editEntry(id(ctx), ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/pam-center/safe/:id/rotate', (ctx) => { ctx.need('operator'); return X.rotate(id(ctx), ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/pam-center/checkouts', (ctx) => { ctx.need('operator'); return X.request(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/pam-center/checkouts/:id/decide', (ctx) => { ctx.need('admin'); return X.decide(id(ctx), ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/pam-center/checkouts/:id/reveal', (ctx) => { ctx.need('operator'); body(ctx.body || {}).done(); return X.reveal(id(ctx), ctx.who); }, { maxBody: 256 });
  srv.route('POST', '/pam-center/checkouts/:id/checkin', (ctx) => { ctx.need('operator'); return X.checkin(id(ctx), ctx.body, ctx.who); }, { maxBody: 1024 });
  srv.route('POST', '/pam-center/ask', (ctx) => { ctx.need('operator'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
  (app.addons = app.addons || {}).pamCenter = X;
  return X;
}

module.exports = { createPamCenter, registerPamCenter, KINDS };
