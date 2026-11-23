// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { guardOf } = require('./errors');
/*
 * HR onboarding ({P} = /api/itam, User Desktops -> HR Onboarding): a new joiner from HR's request to a working laptop and
 * account, every step by a named person and the two decisions by a second one.
 *   1. request     HR (operator) records the joiner: name, employee number, job, department, branch, start date, manager,
 *                  laptop profile and what they need (mailbox, VPN, Microsoft 365)
 *   2. approve     the named manager (or an administrator) approves - never the person who requested it
 *   3. laptop      the desktop administrator picks an in-stock laptop / desktop from the asset register; it is reserved for
 *                  the joiner (custodian + department on the asset, audited) and released again if the request is cancelled
 *   4. account     the desktop administrator proposes the account: user name (checked unique among joiners), groups (never a
 *                  privileged group - that is a separate privileged-access request), licences, mailbox, VPN
 *   5. approve     an administrator who did not propose it approves the account (four eyes)
 *   6. created     AUTOMATIC when an administrator configured Active Directory (engine/onboarding-ad.js): right after the
 *                  four-eyes approval the platform creates the user in the joiners' OU, DISABLED, with a random temporary
 *                  password and change-at-first-sign-in, adds only the approved groups that are on the allowed list, and
 *                  reads it back. If that is not configured or it fails, the person who created it by hand records it with
 *                  the directory reference (anything typed that looks like a password is refused)
 *   7. credentials automatic accounts: the named manager reveals the temporary password ONCE (sealed in the vault until then,
 *                  destroyed after the reveal or after 72 h; never logged, audited, e-mailed or shown again) and hands it
 *                  over; a lost one is re-issued only when an administrator other than the requester approves.
 *                  Manual accounts: how it reached the joiner (in person / through the manager / sealed envelope), with
 *                  change-at-first-sign-in and MFA enrolment confirmed
 *   8. handover    the laptop is handed to the joiner: the asset becomes in use with the joiner as custodian, and an automatic
 *                  account is enabled. Cancelling after the account was created disables it (never deletes it)
 *   9. licensed    when Microsoft 365 licensing is configured (engine/m365-licensing.js): the approved licences (or the default
 *                  ones for a joiner who needs Microsoft 365) are assigned in Entra ID once the account has synced there, seats
 *                  checked first and read back after; or recorded by hand
 * The request is complete when 2, 3, 6, 7 and 8 are done; a joiner starting within 3 days with steps open is "at risk".
 * Names and employee numbers are personal data (PDPL): operators and administrators only; viewers are refused.
 *   GET  /onboarding                          operator  list + counts
 *   GET  /onboarding/laptops                  operator  in-stock laptops / desktops not reserved for another joiner
 *   GET  /onboarding/:id                      operator
 *   GET  /onboarding/:id/username             operator  a suggested user name (first.last, unique)
 *   POST /onboarding                          operator  {name, employee_id, job_title, department, branch?, start_date, manager,
 *                                                        laptop_profile, mailbox?, vpn?, m365?, note?}
 *   POST /onboarding/:id/approve              operator  {decision: approve|reject, note?}  the named manager or an admin, not the requester
 *   POST /onboarding/:id/laptop               operator  {asset_id}
 *   POST /onboarding/:id/account              operator  {username, groups[], licences[], mailbox?, vpn?}
 *   POST /onboarding/:id/account/decide       admin     {decision: approve|reject, note?}  not the proposer
 *   POST /onboarding/:id/account/created      operator  {username, directory_ref, note?}
 *   POST /onboarding/:id/credentials          operator  {method, must_change: true, mfa: enrolled|at_first_sign_in, note?}
 *   POST /onboarding/:id/handover             operator  {acknowledged: true, evidence?, note?}
 *   POST /onboarding/:id/cancel               operator  {reason}  the requester, the manager or an admin
 *   POST /onboarding/:id/account/provision    admin     retry the automatic creation after a failure
 *   POST /onboarding/:id/credentials/reveal   operator  the named manager only, once -> {password}            audited (no value)
 *   POST /onboarding/:id/credentials/reissue  operator  {reason}  the manager or an admin asks for a new temporary password
 *   POST /onboarding/:id/credentials/reissue/decide  admin  {decision: approve|reject, note?}  not the requester
 *   POST /onboarding/:id/licences/retry       admin     try the licence assignment now
 *   POST /onboarding/:id/licences/manual      operator  {reference}   assigned by hand (licensing off or failing)
 *   (directory settings: GET/POST /onboarding/ad, POST /onboarding/ad/test - engine/onboarding-ad.js;
 *    licensing settings: GET/POST /onboarding/m365, POST /onboarding/m365/test - engine/m365-licensing.js)
 */
const DAY = 86400000;
const PROFILES = ['standard', 'power', 'executive'];
const DELIVERY = ['in_person', 'via_manager', 'sealed_envelope'];
const MFA = ['enrolled', 'at_first_sign_in'];
const DESK = ['laptop', 'desktop', 'workstation', 'pc'];
const USER = { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'manager must be a platform user name (letters, digits, . _ - @ \\)' };
const UNAME = /^[a-z][a-z0-9._-]{1,19}$/;
// privileged groups a new joiner never gets through onboarding (a separate, approved privileged-access request)
const PRIVILEGED = /^(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|print operators|dnsadmins|group policy creator owners|key admins|enterprise key admins|cert publishers|organization management|exchange (organization|recipient) admin\w*|global administrators?|.*\b(admins?|administrators?)\b.*)$/i;
// a value next to a secret word, or a long mixed string, is refused: the platform never holds a password
const SECRETISH = /\b(pass(word|wd|phrase|code)?|pwd|temp(orary)?\s*pass\w*|secret|pin)\b\s*(is|was|=|:|-)?\s*\S{4,}/i;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));

function createOnboarding(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const col = () => store.collection('onboarding');
  const iso = () => new Date(now()).toISOString();
  const today = () => iso().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const person = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const noSecret = (o, fields) => { for (const f of fields) if (o[f] && SECRETISH.test(o[f])) throw httpErr(400, f + ' looks like it contains a password - the platform never holds one; say how it was delivered, not what it is'); };
  const get = (id) => { const k = param(id); if (!/^ONB-\d{3,6}$/.test(k)) throw httpErr(400, 'id must be an onboarding request (ONB-nnn)'); const r = col().get(k); if (!r) throw httpErr(404, 'no onboarding request ' + k); return r; };
  const open = (r) => !['completed', 'cancelled'].includes(r.status);
  const hist = (r, who, step, detail) => { r.history = (r.history || []).concat([{ at: iso(), by: who.user, role: who.role, step, detail: detail || null }]).slice(-200); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('onboarding:' + key, 3600000, 'warn', msg, detail); };
  const AD = require('./onboarding-ad').createOnboardingAd(app, { now, privileged: PRIVILEGED, writer: opts.adWriter, sealer: opts.adSealer });
  const SYSTEM = { user: 'system:onboarding-ad', role: 'system', ip: '' };
  const LIC = require('./m365-licensing').createM365Licensing(app, { now, request: opts.graphRequest, loginBase: opts.graphLogin, graphBase: opts.graphBase, sealer: opts.licSealer });
  const LSYS = { user: 'system:m365-licensing', role: 'system', ip: '' };
  const LDONE = ['assigned', 'not_needed', 'assigned_manually'];
  const auto = (r) => !!(r.account && r.account.provisioned);

  function steps(r) {
    const a = r.account || {};
    return [
      { key: 'approve', name: 'Manager approval', done: !!(r.approval && r.approval.decision === 'approve'), by: r.approval && r.approval.by },
      { key: 'laptop', name: 'Laptop reserved', done: !!r.laptop, by: r.laptop && r.laptop.by },
      { key: 'account', name: 'Account proposed', done: !!a.proposed_by, by: a.proposed_by },
      { key: 'account_approve', name: 'Account approved (four eyes)', done: !!a.approved_by, by: a.approved_by },
      { key: 'created', name: 'Account created in the directory', done: !!a.created_by, by: a.created_by },
      { key: 'credentials', name: 'Credentials delivered', done: !!r.credentials, by: r.credentials && r.credentials.by },
      { key: 'handover', name: 'Laptop handed over', done: !!r.handover, by: r.handover && r.handover.by },
    ].concat(r.licensing ? [{ key: 'licensed', name: 'Microsoft 365 licence assigned', done: LDONE.includes(r.licensing.status), by: r.licensing.by || (r.licensing.status === 'assigned' ? LSYS.user : null) }] : []);
  }
  function view(r) {
    const st = steps(r), left = st.filter((s) => !s.done);
    const days = Math.floor((Date.parse(r.start_date + 'T00:00:00Z') - Date.parse(today() + 'T00:00:00Z')) / DAY);
    return Object.assign({}, r, { steps: st, next: open(r) && left.length ? left[0].key : null, days_to_start: days,
      at_risk: open(r) && left.length > 0 && days <= 3, password_waiting: auto(r) ? AD.secretState(r.id) : null });
  }
  function maybeComplete(r, who) {
    if (r.status === 'cancelled') return;
    if (steps(r).every((s) => s.done)) { r.status = 'completed'; r.completed_at = iso(); hist(r, who, 'completed'); audit(who, 'onboarding.complete', r.id, { username: r.account.username, asset: r.laptop.asset_id }); }
    else if (r.approval && r.approval.decision === 'approve') r.status = 'in_progress';
  }
  const reserved = () => { const s = new Set(); for (const r of col().all((x) => open(x) && x.laptop)) s.add(r.laptop.asset_id); return s; };
  const assetsAll = () => (app.assets && typeof app.assets.all === 'function' ? app.assets.all() : store.collection('assets').all());

  function list() {
    const items = col().all(() => true).map(view).sort((a, b) => (a.status === b.status ? String(a.start_date).localeCompare(String(b.start_date)) : open(a) ? -1 : 1));
    const o = items.filter(open);
    return { items, counts: { open: o.length, waiting_manager: o.filter((x) => x.next === 'approve').length, waiting_laptop: o.filter((x) => x.next === 'laptop').length,
      waiting_account_approval: o.filter((x) => x.next === 'account_approve').length, at_risk: o.filter((x) => x.at_risk).length, completed: items.filter((x) => x.status === 'completed').length },
    profiles: PROFILES, delivery: DELIVERY, mfa: MFA, directory: { automatic: AD.enabled() },
    licensing: { automatic: LIC.enabled(), catalogue: LIC.view().catalogue.map((x) => x.name), default_licences: LIC.view().default_licences } };
  }
  function laptops() {
    const r = reserved();
    return { items: assetsAll().filter((a) => a.status === 'in_stock' && DESK.includes(String(a.type || '').toLowerCase()) && !r.has(a.id))
      .map((a) => ({ id: a.id, asset_tag: a.asset_tag || null, name: a.name || null, type: a.type, vendor: a.vendor || null, model: a.model || null, serial: a.serial || null, site: a.site || null })),
    note: 'In-stock laptops and desktops from the asset register that are not reserved for another joiner. Add or restock one in Assets if the list is empty.' };
  }

  function create(input, who) {
    person(who, 'raise an onboarding request');
    const b = body(input || {}).str('name', { required: true, max: 120, min: 3 }).str('employee_id', { required: true, max: 20, re: /^[A-Za-z0-9-]{1,20}$/, msg: 'employee_id must be the HR employee number (letters, digits, -)' })
      .str('job_title', { required: true, max: 120 }).str('department', { required: true, max: 120 }).str('branch', { max: 120 }).date('start_date', { required: true })
      .str('manager', Object.assign({ required: true }, USER)).oneOf('laptop_profile', PROFILES, { required: true }).bool('mailbox', { def: true }).bool('vpn', { def: false }).bool('m365', { def: true }).str('note', { max: 1000 })
      .rule((o) => (o.start_date < today() ? 'start_date cannot be in the past' : null)).done();
    if (!/[A-Za-z]/.test(b.name)) throw httpErr(400, 'name must be written in English letters as it will appear in the directory (Arabic name can go in the note)');
    noSecret(b, ['note']);
    if (col().all((r) => open(r) && same(r.employee_id, b.employee_id)).length) throw httpErr(409, 'an open onboarding request already exists for employee ' + b.employee_id);
    const n = col().all(() => true).length + 1, id = 'ONB-' + String(n).padStart(3, '0');
    const r = Object.assign({ id }, b, { status: 'requested', requested_by: who.user, requested_at: iso(), history: [] });
    hist(r, who, 'requested');
    col().put(r);
    audit(who, 'onboarding.request', id, { department: b.department, start_date: b.start_date, manager: b.manager, profile: b.laptop_profile });
    return view(r);
  }

  function approve(id, input, who) {
    const r = get(id); person(who, 'approve an onboarding request');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    if (r.status !== 'requested') throw httpErr(409, r.id + ' is ' + r.status + ' - only a new request is approved');
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' requested ' + r.id + ' and cannot also approve it');
    if (!(same(r.manager, who.user) || who.role === 'admin')) throw httpErr(403, 'approving needs the named manager (' + r.manager + ') or an administrator');
    r.approval = { decision: b.decision, by: who.user, at: iso(), note: b.note || '' };
    r.status = b.decision === 'approve' ? 'in_progress' : 'cancelled';
    if (b.decision === 'reject') r.cancel = { by: who.user, at: iso(), reason: 'rejected: ' + b.note };
    hist(r, who, 'approve', { decision: b.decision }); col().put(r);
    audit(who, 'onboarding.approve', r.id, { decision: b.decision, requested_by: r.requested_by });
    return view(r);
  }

  const active = (r, what) => { if (r.status !== 'in_progress') throw httpErr(409, r.id + ' is ' + r.status + ' - ' + what + ' needs an approved, open request'); };

  function laptop(id, input, who) {
    const r = get(id); person(who, 'reserve a laptop'); active(r, 'reserving a laptop');
    const b = body(input || {}).str('asset_id', { required: true, max: 80, re: /^[A-Za-z0-9_.:-]{1,80}$/, msg: 'asset_id must be an asset register id' }).done();
    if (r.handover) throw httpErr(409, 'the laptop was already handed over - change it in Assets');
    const a = assetsAll().find((x) => x.id === b.asset_id);
    if (!a) throw httpErr(404, 'no asset ' + b.asset_id);
    if (!DESK.includes(String(a.type || '').toLowerCase())) throw httpErr(400, 'asset_id: ' + b.asset_id + ' is a ' + a.type + ', not a laptop or desktop');
    if (a.status !== 'in_stock') throw httpErr(409, b.asset_id + ' is ' + a.status + ' - only an in-stock laptop can be reserved');
    if (reserved().has(a.id) && !(r.laptop && r.laptop.asset_id === a.id)) throw httpErr(409, b.asset_id + ' is reserved for another joiner');
    if (r.laptop && r.laptop.asset_id !== a.id) release(r, who);
    if (app.assets && typeof app.assets.assign === 'function') app.assets.assign(a.id, { custodian: r.name + ' (joiner ' + r.id + ')', department: r.department }, who);
    r.laptop = { asset_id: a.id, asset_tag: a.asset_tag || null, serial: a.serial || null, model: [a.vendor, a.model].filter(Boolean).join(' ') || null, by: who.user, at: iso() };
    hist(r, who, 'laptop', { asset: a.id }); col().put(r);
    audit(who, 'onboarding.laptop', r.id, { asset: a.id, serial: a.serial || null });
    return view(r);
  }
  function release(r, who) {
    if (!r.laptop || r.handover) return;
    try { if (app.assets && typeof app.assets.assign === 'function') app.assets.assign(r.laptop.asset_id, { custodian: '', department: '' }, who); }
    catch (e) { if (app.log && app.log.every) app.log.every('onboarding:release', 3600000, 'warn', 'onboarding: the reserved laptop could not be released', { id: r.id, err: String(e.message).slice(0, 160) }); }
    audit(who, 'onboarding.laptop.release', r.id, { asset: r.laptop.asset_id });
  }

  function suggest(id) {
    const r = get(id);
    const parts = String(r.name).normalize('NFKD').replace(/[^\x20-\x7e]/g, '').toLowerCase().replace(/[^a-z ]/g, ' ').trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return { username: null, note: 'the name has no English letters - type the user name' };
    const taken = new Set(col().all((x) => x.id !== r.id && x.status !== 'cancelled' && x.account && x.account.username).map((x) => x.account.username));
    const base = (parts.length > 1 ? parts[0] + '.' + parts[parts.length - 1] : parts[0]).slice(0, 18);
    let u = base, i = 2; while (taken.has(u) && i < 100) u = base.slice(0, 17) + (i++);
    return { username: u, note: 'first.last from the name, unique among the joiners on this platform. Check it is free in Active Directory before creating it.' };
  }

  function account(id, input, who) {
    const r = get(id); person(who, 'propose an account'); active(r, 'proposing the account');
    const b = body(input || {}).str('username', { required: true, max: 20, re: UNAME, msg: 'username must be 2-20 lower-case letters, digits, . _ - and start with a letter' })
      .list('groups', { max: 30, item: 'str', itemMax: 120, unique: true, def: [] }).list('licences', { max: 10, item: 'str', itemMax: 80, unique: true, def: [] })
      .bool('mailbox', { def: r.mailbox !== false }).bool('vpn', { def: !!r.vpn }).done();
    const priv = b.groups.filter((g) => PRIVILEGED.test(g));
    if (priv.length) throw httpErr(400, 'groups: ' + priv.join(', ') + ' is privileged - a new joiner never gets it through onboarding; raise a privileged-access request');
    if (LIC.enabled()) { const off = LIC.validNames(b.licences); if (off.length) throw httpErr(400, 'licences: ' + off.join(', ') + ' is not in the Microsoft 365 licence catalogue (' + LIC.view().catalogue.map((x) => x.name).join(', ') + ')'); }
    if (r.account && r.account.created_by) throw httpErr(409, 'the account was already created - change it in the directory');
    if (col().all((x) => x.id !== r.id && x.status !== 'cancelled' && x.account && x.account.username === b.username).length) throw httpErr(409, 'username ' + b.username + ' is already proposed for another joiner');
    r.account = Object.assign({}, b, { upn: null, proposed_by: who.user, proposed_at: iso(), approved_by: null, approved_at: null });
    hist(r, who, 'account', { username: b.username, groups: b.groups.length }); col().put(r);
    audit(who, 'onboarding.account.propose', r.id, { username: b.username, groups: b.groups, licences: b.licences, mailbox: b.mailbox, vpn: b.vpn });
    return view(r);
  }

  async function accountDecide(id, input, who) {
    const r = get(id); person(who, 'approve an account'); active(r, 'approving the account');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say what to change' : null)).done();
    const a = r.account; if (!a || !a.proposed_by) throw httpErr(409, 'no account proposed yet for ' + r.id);
    if (a.approved_by) throw httpErr(409, 'the account was already approved by ' + a.approved_by);
    if (same(a.proposed_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' proposed the account and cannot also approve it');
    if (b.decision === 'reject') { r.account = null; hist(r, who, 'account_reject', { note: b.note }); audit(who, 'onboarding.account.reject', r.id, { proposed_by: a.proposed_by, note: b.note }); }
    else { a.approved_by = who.user; a.approved_at = iso(); hist(r, who, 'account_approve'); audit(who, 'onboarding.account.approve', r.id, { username: a.username, proposed_by: a.proposed_by }); }
    col().put(r);
    if (b.decision === 'approve' && AD.enabled()) { const v = await provisionNow(r, who); const r2 = get(r.id); if (r2.licensing && r2.licensing.status === 'waiting') { await licenseNow(r2); return view(get(r.id)); } return v; }
    return view(r);
  }

  // ---- Microsoft 365 licences: queued when the account exists, assigned by licenseNow / the 10-minute job
  function startLicensing(r) {
    if (r.licensing || !LIC.enabled() || !LIC.wanted(r).length) return;
    r.licensing = { status: 'waiting', since: iso(), attempts: 0, licences: LIC.wanted(r).map((x) => x.name) };
  }
  async function licenseNow(r) {
    const before = r.licensing && r.licensing.status;
    r.licensing = await LIC.attempt(r, AD.cfg().upn_suffix);
    if (r.licensing.status !== before || r.licensing.status === 'assigned') {
      hist(r, LSYS, 'licensing_' + r.licensing.status, { licences: r.licensing.licences, error: r.licensing.error || null });
      audit(LSYS, 'onboarding.licences.' + r.licensing.status, r.id, { upn: r.licensing.upn || null, licences: r.licensing.licences || [], usage_location_set: r.licensing.usage_location_set || null, error: r.licensing.error || null });
    }
    if (r.licensing.status === 'assigned') maybeComplete(r, LSYS);
    col().put(r);
    return r;
  }
  async function licensingTick() {
    if (!LIC.enabled()) return 0;
    let n = 0;
    for (const r of col().all((x) => x.status === 'in_progress' && x.licensing && ['waiting', 'retrying', 'blocked'].includes(x.licensing.status))) { await licenseNow(r); n++; }
    return n;
  }
  async function licencesRetry(id, who) {
    const r = get(id); person(who, 'assign licences'); active(r, 'assigning licences');
    if (!r.licensing) throw httpErr(409, 'no Microsoft 365 licence is due for ' + r.id);
    if (LDONE.includes(r.licensing.status)) throw httpErr(409, 'the licences are already ' + r.licensing.status.replace('_', ' '));
    if (!LIC.enabled()) throw httpErr(409, 'automatic licensing is off - assign them in the Microsoft 365 admin center and record it');
    audit(who, 'onboarding.licences.retry', r.id, {});
    await licenseNow(r);
    return view(get(r.id));
  }
  function licencesManual(id, input, who) {
    const r = get(id); person(who, 'record licences'); active(r, 'recording licences');
    const b = body(input || {}).str('reference', { required: true, min: 3, max: 200 }).done();
    noSecret(b, ['reference']);
    if (!r.account || !r.account.created_by) throw httpErr(409, 'the account must exist before licences are assigned');
    if (r.licensing && LDONE.includes(r.licensing.status)) throw httpErr(409, 'the licences are already ' + r.licensing.status.replace('_', ' '));
    r.licensing = Object.assign({}, r.licensing || {}, { status: 'assigned_manually', by: who.user, at: iso(), reference: b.reference, error: null });
    hist(r, who, 'licensing_manual', { reference: b.reference }); maybeComplete(r, who); col().put(r);
    audit(who, 'onboarding.licences.manual', r.id, { reference: b.reference });
    return view(r);
  }

  // the automatic creation, under the platform's own name; the approval that allowed it is the administrator's above
  async function provisionNow(r, who) {
    const a = r.account;
    try {
      const p = await AD.provision(r);
      Object.assign(a, { created_by: SYSTEM.user, created_at: iso(), directory_ref: p.dn, upn: p.upn, provisioned: p, provision_error: null });
      hist(r, SYSTEM, 'created', { dn: p.dn, groups_added: p.groups_added.length, groups_refused: p.groups_refused.length, verified: p.verified });
      audit(SYSTEM, 'onboarding.account.provisioned', r.id, { username: a.username, dn: p.dn, groups_added: p.groups_added, groups_refused: p.groups_refused, verified: p.verified, approved_by: a.approved_by, triggered_by: who.user });
      startLicensing(r);
      maybeComplete(r, who);
    } catch (e) {
      a.provision_error = { at: iso(), error: String(e.message).slice(0, 300) };
      hist(r, SYSTEM, 'create_failed', { error: a.provision_error.error });
      audit(SYSTEM, 'onboarding.account.provision_failed', r.id, { username: a.username, error: a.provision_error.error, triggered_by: who.user });
      warn('provision', 'onboarding: automatic account creation failed', { id: r.id, err: a.provision_error.error });
    }
    col().put(r);
    return view(r);
  }
  async function provision(id, who) {
    const r = get(id); person(who, 'create the account'); active(r, 'creating the account');
    const a = r.account; if (!a || !a.approved_by) throw httpErr(409, 'the account must be approved (four eyes) before it is created');
    if (a.created_by) throw httpErr(409, 'the account was already created (' + a.created_by + ')');
    if (!AD.enabled()) throw httpErr(409, 'automatic creation is not configured - an administrator sets it in Directory settings, or create it by hand and record it');
    return provisionNow(r, who);
  }

  function created(id, input, who) {
    const r = get(id); person(who, 'record the account'); active(r, 'recording the account');
    const b = body(input || {}).str('username', { required: true, max: 20, re: UNAME, msg: 'username must be the account name as created' })
      .str('directory_ref', { required: true, max: 200, min: 3 }).str('note', { max: 1000 }).done();
    noSecret(b, ['directory_ref', 'note']);
    const a = r.account; if (!a || !a.approved_by) throw httpErr(409, 'the account must be approved before it is created');
    if (a.created_by) throw httpErr(409, 'already recorded by ' + a.created_by);
    if (b.username !== a.username) throw httpErr(400, 'username: ' + b.username + ' is not the approved name ' + a.username + ' - propose the new name again if it had to change');
    Object.assign(a, { created_by: who.user, created_at: iso(), directory_ref: b.directory_ref, created_note: b.note || '' });
    startLicensing(r);
    hist(r, who, 'created', { directory_ref: b.directory_ref }); maybeComplete(r, who); col().put(r);
    audit(who, 'onboarding.account.created', r.id, { username: a.username, directory_ref: b.directory_ref });
    return view(r);
  }

  function credentials(id, input, who) {
    const r = get(id); person(who, 'record the credential delivery'); active(r, 'recording the credentials');
    const b = body(input || {}).oneOf('method', DELIVERY, { required: true }).bool('must_change', { required: true }).oneOf('mfa', MFA, { required: true }).str('note', { max: 500 })
      .rule((o) => (o.must_change !== true ? 'must_change must be true: the joiner changes the temporary password at first sign-in' : null)).done();
    noSecret(b, ['note']);
    if (!r.account || !r.account.created_by) throw httpErr(409, 'the account must be created before its credentials are delivered');
    if (auto(r)) throw httpErr(409, 'the platform created this account: the temporary password waits for the manager (' + r.manager + ') to reveal it once');
    if (r.credentials) throw httpErr(409, 'already recorded by ' + r.credentials.by);
    r.credentials = { method: b.method, must_change: true, mfa: b.mfa, note: b.note || '', by: who.user, at: iso() };
    hist(r, who, 'credentials', { method: b.method, mfa: b.mfa }); maybeComplete(r, who); col().put(r);
    audit(who, 'onboarding.credentials', r.id, { method: b.method, mfa: b.mfa });
    return view(r);
  }

  async function handover(id, input, who) {
    const r = get(id); person(who, 'hand over the laptop'); active(r, 'the handover');
    const b = body(input || {}).bool('acknowledged', { required: true }).str('evidence', { max: 200 }).str('note', { max: 500 })
      .rule((o) => (o.acknowledged !== true ? 'acknowledged must be true: the joiner signed for the laptop' : null)).done();
    if (!r.laptop) throw httpErr(409, 'reserve a laptop first');
    if (!r.account || !r.account.created_by) throw httpErr(409, 'create the account first - the laptop is handed over with a working sign-in');
    if (r.handover) throw httpErr(409, 'already handed over by ' + r.handover.by);
    if (auto(r) && !r.account.enabled_at) {
      try { await AD.setEnabled(r, true); } catch (e) { warn('enable', 'onboarding: the account could not be enabled', { id: r.id, err: String(e.message).slice(0, 160) }); throw httpErr(409, 'the directory refused to enable ' + r.account.username + ': ' + String(e.message).slice(0, 160)); }
      r.account.enabled_at = iso(); col().put(r);
      audit(SYSTEM, 'onboarding.account.enabled', r.id, { username: r.account.username, dn: r.account.directory_ref, handed_over_by: who.user });
    }
    if (app.assets) {
      try {
        if (typeof app.assets.assign === 'function') app.assets.assign(r.laptop.asset_id, { custodian: r.account.username, department: r.department }, who);
        if (typeof app.assets.transition === 'function') app.assets.transition(r.laptop.asset_id, 'activate', who, 'handed to new joiner ' + r.account.username + ' (' + r.id + ')');
      } catch (e) { throw httpErr(409, 'the asset register refused the handover: ' + String(e.message).slice(0, 160)); }
    }
    r.handover = { by: who.user, at: iso(), evidence: b.evidence || '', note: b.note || '' };
    hist(r, who, 'handover', { asset: r.laptop.asset_id }); maybeComplete(r, who); col().put(r);
    audit(who, 'onboarding.handover', r.id, { asset: r.laptop.asset_id, custodian: r.account.username });
    return view(r);
  }

  async function cancel(id, input, who) {
    const r = get(id); person(who, 'cancel an onboarding request');
    const b = body(input || {}).str('reason', { required: true, max: 500, min: 5 }).done();
    if (!open(r)) throw httpErr(409, r.id + ' is already ' + r.status);
    if (!(same(r.requested_by, who.user) || same(r.manager, who.user) || who.role === 'admin')) throw httpErr(403, 'cancelling needs the requester, the manager or an administrator');
    release(r, who);
    let warning = r.account && r.account.created_by ? 'the account ' + r.account.username + ' was already created - disable it in the directory' : null;
    if (auto(r)) {
      AD.drop(r.id);
      try { await AD.setEnabled(r, false); r.account.disabled_at = iso(); warning = null; audit(SYSTEM, 'onboarding.account.disabled', r.id, { username: r.account.username, dn: r.account.directory_ref, cancelled_by: who.user }); }
      catch (e) { warn('disable', 'onboarding: the cancelled account could not be disabled', { id: r.id, err: String(e.message).slice(0, 160) }); warning = 'the directory refused to disable ' + r.account.username + ' (' + String(e.message).slice(0, 120) + ') - disable it in Active Directory'; }
    }
    r.status = 'cancelled'; r.cancel = { by: who.user, at: iso(), reason: b.reason };
    hist(r, who, 'cancel', { reason: b.reason }); col().put(r);
    audit(who, 'onboarding.cancel', r.id, { reason: b.reason, account_created: !!(r.account && r.account.created_by), account_disabled: !!(r.account && r.account.disabled_at) });
    return Object.assign(view(r), warning ? { warning } : {});
  }

  // the named manager sees the temporary password once; the value is never written to the audit, the history or a log
  function reveal(id, who) {
    const r = get(id); person(who, 'see a temporary password'); active(r, 'revealing the password');
    if (!auto(r)) throw httpErr(409, 'this account was not created by the platform - there is no password here');
    if (!same(r.manager, who.user)) { audit(who, 'onboarding.credentials.reveal_refused', r.id, { manager: r.manager }); throw httpErr(403, 'only the named manager (' + r.manager + ') can see the temporary password'); }
    const pw = AD.reveal(r);
    const n = ((r.credentials && r.credentials.reveals) || 0) + 1;
    r.credentials = { method: 'manager_reveal', must_change: true, mfa: 'at_first_sign_in', note: '', by: who.user, at: iso(), reveals: n };
    hist(r, who, 'credentials', { method: 'manager_reveal', reveal: n }); maybeComplete(r, who); col().put(r);
    audit(who, 'onboarding.credentials.revealed', r.id, { username: r.account.username, reveal: n });
    return { password: pw, username: r.account.username, upn: r.account.upn, must_change: true, shown: 'once', note: 'Give it to ' + r.name + ' in person. It is not stored any more: it cannot be shown again. The joiner must change it at first sign-in and enrol MFA.' };
  }
  function reissueRequest(id, input, who) {
    const r = get(id); person(who, 'ask for a new temporary password'); active(r, 'a re-issue');
    const b = body(input || {}).str('reason', { required: true, max: 500, min: 5 }).done();
    noSecret(b, ['reason']);
    if (!auto(r)) throw httpErr(409, 'this account was not created by the platform - reset it in Active Directory');
    if (!(same(r.manager, who.user) || who.role === 'admin')) throw httpErr(403, 'a re-issue is asked by the named manager or an administrator');
    if (r.reissue && r.reissue.status === 'pending') throw httpErr(409, 'a re-issue is already waiting for approval');
    r.reissue = { status: 'pending', requested_by: who.user, at: iso(), reason: b.reason };
    hist(r, who, 'reissue_request', { reason: b.reason }); col().put(r);
    audit(who, 'onboarding.credentials.reissue_request', r.id, { reason: b.reason });
    return view(r);
  }
  async function reissueDecide(id, input, who) {
    const r = get(id); person(who, 'approve a new temporary password'); active(r, 'a re-issue');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const q = r.reissue; if (!q || q.status !== 'pending') throw httpErr(409, 'no re-issue is waiting for ' + r.id);
    if (same(q.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for the re-issue and cannot also approve it');
    if (b.decision === 'approve') {
      try { await AD.reissue(r); } catch (e) { warn('reissue', 'onboarding: the password re-issue failed', { id: r.id, err: String(e.message).slice(0, 160) }); throw httpErr(409, 'the directory refused the new password: ' + String(e.message).slice(0, 160)); }
    }
    Object.assign(q, { status: b.decision === 'approve' ? 'done' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'reissue_' + b.decision); col().put(r);
    audit(who, 'onboarding.credentials.reissue_' + b.decision, r.id, { requested_by: q.requested_by, username: r.account.username });
    return view(r);
  }
  function start() {
    if (app.noTimers || opts.noTimer) return;
    const t = setInterval(guardOf(app, 'onboarding.secrets', () => { const n = AD.purge(); if (n) audit(SYSTEM, 'onboarding.credentials.expired', 'secrets', { destroyed: n }); }), 3600000);
    const t2 = setInterval(guardOf(app, 'onboarding.licensing', licensingTick), 10 * 60000);
    if (t.unref) { t.unref(); t2.unref(); }
  }
  start();

  return { list, laptops, one: (id) => view(get(id)), create, approve, laptop, suggest, account, accountDecide, created, credentials, handover, cancel,
    provision, reveal, reissueRequest, reissueDecide, licencesRetry, licencesManual, licensingTick, ad: AD, lic: LIC, PRIVILEGED };
}

function registerOnboarding(srv, app, O) {
  require('./onboarding-ad').registerOnboardingAdRoutes(srv, app, O.ad);   // first: /onboarding/ad is not an :id
  require('./m365-licensing').registerM365LicensingRoutes(srv, app, O.lic);
  srv.route('GET', '/onboarding', (ctx) => { ctx.need('operator'); return O.list(); });
  srv.route('GET', '/onboarding/laptops', (ctx) => { ctx.need('operator'); return O.laptops(); });
  srv.route('GET', '/onboarding/:id', (ctx) => { ctx.need('operator'); return O.one(ctx.params.id); });
  srv.route('GET', '/onboarding/:id/username', (ctx) => { ctx.need('operator'); return O.suggest(ctx.params.id); });
  srv.route('POST', '/onboarding', (ctx) => { ctx.need('operator'); return O.create(ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/approve', (ctx) => { ctx.need('operator'); return O.approve(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/laptop', (ctx) => { ctx.need('operator'); return O.laptop(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/account', (ctx) => { ctx.need('operator'); return O.account(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/account/decide', (ctx) => { ctx.need('admin'); return O.accountDecide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/account/created', (ctx) => { ctx.need('operator'); return O.created(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/credentials', (ctx) => { ctx.need('operator'); return O.credentials(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/handover', (ctx) => { ctx.need('operator'); return O.handover(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/cancel', (ctx) => { ctx.need('operator'); return O.cancel(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/licences/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.licencesRetry(ctx.params.id, ctx.who); });
  srv.route('POST', '/onboarding/:id/licences/manual', (ctx) => { ctx.need('operator'); return O.licencesManual(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/account/provision', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return O.provision(ctx.params.id, ctx.who); });
  srv.route('POST', '/onboarding/:id/credentials/reveal', (ctx) => { ctx.need('operator'); body(ctx.body).done(); return O.reveal(ctx.params.id, ctx.who); });
  srv.route('POST', '/onboarding/:id/credentials/reissue', (ctx) => { ctx.need('operator'); return O.reissueRequest(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/:id/credentials/reissue/decide', (ctx) => { ctx.need('admin'); return O.reissueDecide(ctx.params.id, ctx.body, ctx.who); });
}

module.exports = { createOnboarding, registerOnboarding, PROFILES, DELIVERY, PRIVILEGED };
