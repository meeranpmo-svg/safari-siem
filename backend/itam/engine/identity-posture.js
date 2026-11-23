// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Password & MFA Posture ({P} = /api/itam; Identity & Sign-in -> Password & MFA Posture, page identity-posture.html).
 * REPORT ONLY: it reads what the platform already holds and changes nothing anywhere. By decision there is no end-user
 * self-service password reset, no logon-screen agent and no endpoint MFA; the one change path for an account is AD Management
 * (engine/ad-manage.js: a request a different named administrator approves - unlock, reset, disable).
 *
 * Sources - nothing is collected twice, every read goes through the platform's ONE SIEM link (app.discovery.siem.call) as the
 * analyst role (named accounts: viewers may not read them), the way the AI auditors read it:
 *   ad         GET  /audit/evidence/ad       the SIEM's AD sync: the Default Domain Policy (minPwdLength, pwdHistoryLength, maxPwdAge,
 *                                            minPwdAge, pwdProperties, lockoutThreshold, lockoutDuration, lockOutObservationWindow)
 *                                            and every account's audit flags (password never expires / not required, pwdLastSet)
 *   m365       GET  /audit/evidence/m365     the SIEM's Microsoft Graph sync (the same data as Microsoft 365 Security): MFA
 *                                            registration (registered yes / no, administrators flagged) and Conditional Access
 *                                            policies (name and state)
 *   lockouts   POST /histogram, POST /top    the SIEM's 4740 events (action account-locked): per day, top accounts, top caller computers
 *   fgpp       the directory connection HR onboarding holds (engine/ad-writer.js passwordSettings, read only): fine-grained
 *              password policies - the SIEM does not read them, and AD lets only accounts granted Read on the Password Settings
 *              Container see them, so "none seen" is said to prove nothing
 * A source that is not there says what to connect - never a zero, never a sample.
 *
 * BASELINE: the platform's identity requirements (NCA ECC 2-2-3, SAMA CSF 3.3.5, CIS Windows Server benchmark 1.1 / 1.2 -
 * the same criteria as the AI auditors' CY-18). An administrator may adjust it within fixed bounds, with a reason; audited with
 * what changed. Some rules are not adjustable: reversible encryption off, an account lockout on, MFA for every administrator.
 *
 *   GET  /identity-posture             operator  the report (names people - PDPL: operators and above; the read is audited)
 *   POST /identity-posture/baseline    admin     {reason, values: {...}} or {reason, reset: true}                         audited
 * Never a password, hash or secret: none of the sources has one.
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000, LOCK_DAYS = 30, CACHE_MS = 60000, LIST_MAX = 300;
const SIEM_WHO = { user: 'system:itam-identity-posture', role: 'analyst' };
const REF = { ecc: 'NCA ECC 2-2-3', sama: 'SAMA CSF 3.3.5', cisPwd: 'CIS Windows Server benchmark 1.1 (password policy)', cisLock: 'CIS Windows Server benchmark 1.2 (account lockout)', iso: 'ISO 27001 A.5.17' };
const REFS_ID = [REF.ecc, REF.sama];
// adjustable values: [default, min, max, label]
const KNOBS = {
  min_length: [14, 8, 64, 'Minimum password length (characters)'],
  history: [24, 5, 24, 'Passwords remembered (history)'],
  max_age_days: [365, 30, 999, 'Maximum password age (days; never-expiring is a finding)'],
  min_age_days: [1, 1, 30, 'Minimum password age (days)'],
  lockout_threshold: [5, 3, 10, 'Lock out after at most this many bad passwords'],
  lockout_minutes: [15, 15, 1440, 'Lockout lasts at least (minutes)'],
  old_password_days: [365, 90, 1095, 'An enabled account\'s password is "old" after (days)'],
  mfa_users_pct: [100, 80, 100, 'MFA registration target for all users (%)'],
};
const FIXED = ['Password complexity on', 'Reversible encryption off', 'Account lockout on (a threshold of 0 never locks)', 'MFA registered for every administrator', 'A Conditional Access policy enforcing MFA'];
const LINK = { ad: 'ad-audit.html', m365: 'm365-security.html', manage: 'ad-manage.html', idp: 'identity-signin.html', adset: 'ad-exchange.html' };
const MFA_NAME = /mfa|multi.?factor|2fa|authentication strength/i, ADMIN_NAME = /admin|privileg/i;
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n || 200);

function createIdentityPosture(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, iso = () => new Date(now()).toISOString();
  const C = () => store.collection('identity_posture');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('identity-posture:' + key, 600000, 'warn', msg, detail); };
  let cache = null;

  // ---- baseline
  const defaults = () => Object.fromEntries(Object.entries(KNOBS).map(([k, v]) => [k, v[0]]));
  function baseline() {
    const rec = C().get('baseline') || null;
    return { values: Object.assign(defaults(), (rec && rec.v) || {}), defaults: defaults(), changed_by: rec ? rec.by : null, changed_at: rec ? rec.at : null, reason: rec ? rec.reason : null,
      knobs: Object.entries(KNOBS).map(([k, v]) => ({ key: k, label: v[3], def: v[0], min: v[1], max: v[2] })), fixed: FIXED, refs: [REF.ecc, REF.sama, REF.cisPwd, REF.cisLock, REF.iso] };
  }
  function saveBaseline(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person changes the identity baseline, not a service or AI identity');
    const b = body(b0 || {}).str('reason', { required: true, min: 5, max: 500 }).bool('reset', { def: false }).done();
    const raw = (b0 && b0.values) || {};
    if (typeof raw !== 'object' || Array.isArray(raw)) throw httpErr(400, 'values must be an object');
    let v = body(raw);
    for (const [k, d] of Object.entries(KNOBS)) v = v.int(k, { min: d[1], max: d[2] });
    const vals = v.done();
    if (!b.reset && !Object.keys(vals).length) throw httpErr(400, 'values: nothing to change - give at least one of ' + Object.keys(KNOBS).join(', '));
    const before = baseline().values, after = b.reset ? defaults() : Object.assign({}, before, vals);
    const changed = Object.keys(KNOBS).filter((k) => after[k] !== before[k]).map((k) => ({ key: k, from: before[k], to: after[k], weaker: weaker(k, before[k], after[k]) }));
    C().put({ id: 'baseline', v: after, by: who.user, at: iso(), reason: b.reason });
    cache = null;
    audit(who, 'identity_posture.baseline', 'baseline', { reason: b.reason, reset: b.reset, changed });
    return baseline();
  }
  // is the new value less strict than the old one? (shown in the audit record and on the page)
  function weaker(k, from, to) { return ['max_age_days', 'lockout_threshold', 'old_password_days'].includes(k) ? to > from : to < from; }

  // ---- sources
  function link() { const L = app.discovery && app.discovery.siem; return L && typeof L.call === 'function' && (!L.configured || L.configured()) ? L : null; }
  async function siem(method, path, payload) {
    if (opts.siem) return opts.siem(method, path, payload);
    const L = link(); if (!L) throw Object.assign(new Error('the SIEM is not linked to IT Asset Management (discovery.siem in the ITAM configuration)'), { notConnected: true });
    const r = await L.call(method, path, SIEM_WHO, payload);
    if (!r || r.status === 404) throw Object.assign(new Error('this SIEM version does not have ' + path + ' - update the SIEM'), { notConnected: true });
    if (r.status !== 200 || !r.json) throw new Error('the SIEM answered HTTP ' + (r && r.status) + ' for ' + path + (r && r.json && r.json.error ? ': ' + s(r.json.error, 120) : ''));
    return r.json;
  }
  async function source(name, fn) {
    try { return Object.assign({ state: 'live' }, await fn()); }
    catch (e) {
      if (!e.notConnected) warn(name, 'identity posture: the ' + name + ' source could not be read', { err: s(e.message, 200) });
      return { state: e.notConnected ? 'not_connected' : 'error', reason: s(e.message, 240) };
    }
  }
  const adSrc = () => source('ad', async () => {
    const d = await siem('GET', '/audit/evidence/ad');
    if (!d.available) throw Object.assign(new Error(s(d.reason, 200) || 'the SIEM has no AD sync'), { notConnected: true });
    return { data: d };
  });
  const m365Src = () => source('m365', async () => {
    const d = await siem('GET', '/audit/evidence/m365');
    if (!d.available) throw Object.assign(new Error(s(d.reason, 200) || 'Microsoft 365 is not configured on the SIEM'), { notConnected: true });
    return { data: d };
  });
  const lockSrc = () => source('lockouts', async () => {
    const q = 'action:account-locked', from = 'now-' + LOCK_DAYS + 'd';
    const [h, top, comp] = await Promise.all([siem('POST', '/histogram', { q, from, to: 'now', buckets: LOCK_DAYS }), siem('POST', '/top', { q, from, to: 'now', field: 'target_user', limit: 15 }),
      siem('POST', '/top', { q, from, to: 'now', field: 'fields.caller_computer', limit: 10 })]);
    return { data: { buckets: (h.buckets || []).map((b) => ({ t: new Date(Number(b.t)).toISOString().slice(0, 10), n: Number(b.n) || 0 })), top: (top.values || []).filter((x) => x && x.v).map((x) => ({ sam: s(x.v, 128), n: Number(x.n) || 0 })),
      computers: (comp.values || []).filter((x) => x && x.v).map((x) => ({ computer: s(x.v, 128), n: Number(x.n) || 0 })) } };
  });
  const fgppSrc = () => source('fgpp', async () => {
    if (opts.fgpp) return { data: await opts.fgpp() };
    const a = app.addons && app.addons.onboarding && app.addons.onboarding.ad;
    const c = a && typeof a.cfg === 'function' ? a.cfg() : null;
    if (!c || !(c.bind_enc && (c.servers || []).length && c.base_dn)) throw Object.assign(new Error('the directory connection is not set (HR Onboarding -> Directory settings)'), { notConnected: true });
    try { return { data: await a.writer().passwordSettings() }; }
    catch (e) { throw new Error('the directory could not be read: ' + s(e.message, 160)); }
  });

  // ---- scoring
  function policyChecks(p, B, scope) {
    const c = [], add = (id, label, value, expected, ok, refs, why) => c.push({ id: scope + ':' + id, label, value, expected, ok, refs, why: ok ? '' : why });
    const known = (v) => v !== null && v !== undefined;
    add('min_length', 'Minimum password length', p.min_length, '≥ ' + B.min_length, known(p.min_length) && p.min_length >= B.min_length, [REF.cisPwd, ...REFS_ID], 'short passwords are guessed and sprayed');
    add('history', 'Password history', p.history, '≥ ' + B.history, known(p.history) && p.history >= B.history, [REF.cisPwd, ...REFS_ID], 'people cycle back to an old password');
    add('max_age', 'Maximum password age (days)', p.max_age_days === 0 ? 'never' : p.max_age_days, '1 - ' + B.max_age_days, known(p.max_age_days) && p.max_age_days > 0 && p.max_age_days <= B.max_age_days, [REF.cisPwd, ...REFS_ID], 'a leaked password stays valid');
    add('min_age', 'Minimum password age (days)', p.min_age_days, '≥ ' + B.min_age_days, known(p.min_age_days) && p.min_age_days >= B.min_age_days, [REF.cisPwd], 'history can be bypassed by changing the password repeatedly');
    add('complexity', 'Complexity', p.complexity === null || p.complexity === undefined ? null : p.complexity ? 'on' : 'off', 'on', p.complexity === true, [REF.cisPwd, ...REFS_ID], 'simple passwords are accepted');
    add('reversible', 'Reversible encryption', p.reversible === null || p.reversible === undefined ? null : p.reversible ? 'on' : 'off', 'off', p.reversible === false, [REF.cisPwd, REF.iso], 'passwords are stored in a recoverable form');
    add('lockout_threshold', 'Lockout threshold (bad passwords)', p.lockout_threshold === 0 ? '0 (never locks)' : p.lockout_threshold, '1 - ' + B.lockout_threshold, known(p.lockout_threshold) && p.lockout_threshold > 0 && p.lockout_threshold <= B.lockout_threshold, [REF.cisLock, ...REFS_ID], 'unlimited password guessing');
    add('lockout_minutes', 'Lockout duration (minutes)', p.lockout_minutes === 0 ? '0 (until unlocked)' : p.lockout_minutes, '≥ ' + B.lockout_minutes + ' or until unlocked', !p.lockout_threshold ? false : known(p.lockout_minutes) && (p.lockout_minutes === 0 || p.lockout_minutes >= B.lockout_minutes), [REF.cisLock], 'a locked account frees itself too soon to slow an attack');
    return c;
  }
  const pctOf = (c) => (c.length ? Math.round(c.filter((x) => x.ok).length / c.length * 100) : null);

  async function build() {
    const B = baseline().values, t = now();
    const [ad, m365, lock, fgpp] = await Promise.all([adSrc(), m365Src(), lockSrc(), fgppSrc()]);
    const out = { generated_at: new Date(t).toISOString(), baseline: baseline(), sources: {}, remediation: [], note: 'Report only - nothing is changed from this page. Accounts are changed in AD Management, where a second administrator approves every change.' };
    const srcOut = (x, live) => (x.state === 'live' ? Object.assign({ state: 'live' }, live || {}) : { state: x.state, reason: x.reason });
    const R = [], rec = (score, severity, title, detail, count, refs, page) => { if (count) R.push({ score, severity, title, detail, count, refs, page }); };

    // domain password policy + accounts (SIEM AD sync)
    if (ad.state === 'live') {
      const d = ad.data, p = d.policy;
      out.sources.ad = srcOut(ad, { synced: d.synced || null, domain: s(d.domain, 120) });
      if (p) {
        const checks = policyChecks(p, B, 'domain');
        out.policy = { available: true, values: p, checks, score: pctOf(checks) };
        for (const c of checks.filter((x) => !x.ok && !(x.id === 'domain:lockout_minutes' && p.lockout_threshold === 0))) rec({ reversible: 95, lockout_threshold: 80, min_length: 70, complexity: 70, max_age: 45, lockout_minutes: 35, history: 30, min_age: 20 }[c.id.split(':')[1]] || 30,
          ['reversible', 'lockout_threshold'].includes(c.id.split(':')[1]) ? 'high' : 'medium', 'Domain password policy: ' + c.label.toLowerCase() + ' is ' + (c.value === null || c.value === undefined ? 'not readable' : c.value) + ' (baseline ' + c.expected + ')',
          'Change it in the Default Domain Policy (Group Policy Management -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies): ' + c.why + '.', 1, c.refs, LINK.ad);
      } else out.policy = { available: false, reason: 'the SIEM AD sync did not read the domain password policy (the domain head attributes) - update the SIEM, or check the sync account can read the domain object' };
      const users = (d.users || []).filter((u) => !u.disabled);
      const pick = (f) => users.filter(f).map((u) => ({ sam: s(u.sam, 64), name: s(u.name, 120), privileged: !!u.privileged, service: !!u.service_account, pwd_last_set: u.pwd_last_set || null,
        pwd_age_days: u.pwd_last_set ? Math.floor((t - Date.parse(u.pwd_last_set)) / DAY) : null })).sort((a, b) => (b.privileged - a.privileged) || String(a.sam).localeCompare(String(b.sam)));
      const never = pick((u) => u.pwd_never_expires), notReq = pick((u) => u.pwd_not_required), old = pick((u) => u.pwd_last_set && t - Date.parse(u.pwd_last_set) > B.old_password_days * DAY && !u.pwd_never_expires)
        .sort((a, b) => (b.privileged - a.privileged) || (b.pwd_age_days - a.pwd_age_days));
      const cut = (a) => ({ count: a.length, items: a.slice(0, LIST_MAX), truncated: a.length > LIST_MAX });
      out.accounts = { enabled: users.length, never_expires: cut(never), not_required: cut(notReq), old: cut(old), old_days: B.old_password_days,
        note: 'Enabled accounts only. Service accounts are marked: a never-expiring password is expected on some of them, but each should be a managed service account (gMSA) or listed in Non-Human Identities.' };
      const priv = (a) => a.filter((u) => u.privileged);
      rec(90, 'high', 'Enabled account(s) that may have no password (PASSWD_NOTREQD)', 'Clear "password not required" (userAccountControl 0x20) and set a password; AD lets such an account have an empty one.', notReq.length, [REF.ecc, REF.sama, REF.iso], LINK.ad);
      rec(75, 'high', 'Privileged account(s) whose password never expires', 'An administrator\'s password must expire or be vaulted and rotated (privileged access management).', priv(never).length, [REF.ecc, REF.sama], LINK.ad);
      rec(55, 'medium', 'Privileged account(s) with a password older than ' + B.old_password_days + ' days', 'Rotate them first - an old administrator password is the most valuable credential to steal.', priv(old).length, [REF.ecc, REF.sama], LINK.ad);
      rec(50, 'medium', 'People\'s account(s) whose password never expires', 'Remove "password never expires" from accounts that belong to a person; move service accounts to gMSA.', never.filter((u) => !u.privileged && !u.service).length, [REF.cisPwd, REF.ecc, REF.sama], LINK.ad);
      rec(40, 'low', 'Account(s) with a password older than ' + B.old_password_days + ' days', 'These passwords predate the expiry the baseline expects - often accounts excluded from expiry by a fine-grained policy or unused.', old.filter((u) => !u.privileged).length, [REF.cisPwd, REF.sama], LINK.ad);
    } else { out.sources.ad = srcOut(ad); out.policy = { available: false, reason: ad.reason + ' - connect Active Directory to the SIEM (Identity & Sign-in -> AD & Exchange settings)' }; out.accounts = { available: false, reason: ad.reason }; }

    // fine-grained password policies (directory connection)
    if (fgpp.state === 'live') {
      const f = fgpp.data || {};
      out.sources.fgpp = srcOut(fgpp, { readable: !!f.readable });
      const items = (f.items || []).map((p) => { const checks = policyChecks(p, B, 'pso:' + s(p.name, 64)); return Object.assign({}, p, { name: s(p.name, 120), checks, score: pctOf(checks) }); })
        .sort((a, b) => (a.precedence == null) - (b.precedence == null) || a.precedence - b.precedence);
      out.fine_grained = { available: !!f.readable, items, reason: f.readable ? '' : 'the Password Settings Container could not be read (' + s(f.error, 120) + ')',
        note: items.length ? 'A fine-grained policy replaces the domain policy for the users and groups it applies to (the lowest precedence wins).'
          : 'No fine-grained password policy is visible to the directory bind account. AD shows them only to accounts granted Read on CN=Password Settings Container,CN=System - none seen does not prove none exist.' };
      for (const p of items) for (const c of p.checks.filter((x) => !x.ok && ['reversible', 'lockout_threshold', 'min_length', 'complexity', 'max_age'].includes(x.id.split(':').pop())))
        rec(65, c.id.endsWith('reversible') ? 'high' : 'medium', 'Fine-grained policy ' + p.name + ': ' + c.label.toLowerCase() + ' is ' + (c.value === null || c.value === undefined ? 'not set' : c.value) + ' (baseline ' + c.expected + ')',
          'It applies to ' + (p.applies_to || 0) + ' user(s) / group(s) and overrides the domain policy for them - ' + c.why + '. Change it in Active Directory Administrative Center -> System -> Password Settings Container.', 1, c.refs, LINK.ad);
    } else { out.sources.fgpp = srcOut(fgpp); out.fine_grained = { available: false, items: [], reason: fgpp.reason }; }

    // MFA (SIEM Graph sync - the same data Microsoft 365 Security shows)
    if (m365.state === 'live') {
      const d = m365.data, mfa = d.mfa, ca = d.conditional_access, blocks = d.blocks || {};
      const perm = (k, p) => (blocks[k] && blocks[k].ok === false ? 'not read: grant ' + (blocks[k].perm || p) + ' to the SIEM app registration' + (blocks[k].error ? ' (' + s(blocks[k].error, 100) + ')' : '') : 'not read yet (next Graph sync on the SIEM)');
      out.sources.m365 = srcOut(m365, { updated: d.updated || null });
      if (mfa) {
        const not = (mfa.notRegistered || []).map((u) => ({ name: s(u.name, 120), upn: s(u.upn, 200), admin: !!u.admin }));
        const pct = mfa.users ? Math.round(mfa.registered / mfa.users * 1000) / 10 : null, admins = not.filter((u) => u.admin);
        out.mfa = { available: true, users: mfa.users, registered: mfa.registered, pct, target_pct: B.mfa_users_pct, admins_without: admins, not_registered: { count: not.length, items: not.slice(0, LIST_MAX), truncated: not.length > LIST_MAX },
          methods: { available: false, reason: 'the SIEM\'s Graph sync keeps whether each person has registered MFA, not which methods - see Entra admin center -> Authentication methods -> User registration details' } };
        rec(100, 'critical', 'Administrator(s) without MFA registered', 'Register MFA (preferably a phishing-resistant method) for every admin role and enforce it with Conditional Access.', admins.length, [REF.ecc, REF.sama], LINK.m365);
        if (pct !== null && pct < B.mfa_users_pct) rec(60, 'medium', 'MFA registration ' + pct + '% (target ' + B.mfa_users_pct + '%)', 'Require registration through Conditional Access (registration campaign) for the people not registered.', not.filter((u) => !u.admin).length, [REF.ecc, REF.sama], LINK.m365);
      } else out.mfa = { available: false, reason: perm('mfa', 'UserAuthenticationMethod.Read.All + AuditLog.Read.All') };
      if (Array.isArray(ca)) {
        const on = ca.filter((p) => p.state === 'enabled'), ro = ca.filter((p) => p.state === 'enabledForReportingButNotEnforced');
        const mfaOn = on.filter((p) => MFA_NAME.test(p.name)), mfaRo = ro.filter((p) => MFA_NAME.test(p.name));
        out.conditional_access = { available: true, total: ca.length, enabled: on.length, report_only: ro.length, mfa_enforced: mfaOn.map((p) => s(p.name, 160)), mfa_report_only: mfaRo.map((p) => s(p.name, 160)),
          admins_mfa: mfaOn.some((p) => ADMIN_NAME.test(p.name)), policies: ca.map((p) => ({ name: s(p.name, 160), state: s(p.state, 60), modified: p.modified || null })),
          note: 'Graph gives each policy\'s name and state here; "requires MFA" is matched by name only - open the policy in Entra to confirm what it enforces.' };
        rec(85, 'high', 'No enabled Conditional Access policy enforcing MFA (by name)', mfaRo.length ? 'Policies in report-only mode: ' + mfaRo.map((p) => s(p.name, 80)).join(', ') + ' - switch one on.' : 'Create one that requires MFA for all users, and one for admin roles.', mfaOn.length ? 0 : 1, [REF.ecc, REF.sama], LINK.m365);
        if (mfaOn.length) rec(45, 'medium', 'No enabled Conditional Access policy for administrators that requires MFA (by name)', 'Add a policy requiring MFA (or phishing-resistant authentication strength) for every directory admin role.', out.conditional_access.admins_mfa ? 0 : 1, [REF.ecc, REF.sama], LINK.m365);
      } else out.conditional_access = { available: false, reason: perm('conditionalAccess', 'Policy.Read.All') };
    } else {
      out.sources.m365 = srcOut(m365);
      const why = m365.reason + ' - connect Microsoft 365 to the SIEM (Identity & Microsoft 365 -> Microsoft 365 settings)';
      out.mfa = { available: false, reason: why }; out.conditional_access = { available: false, reason: why };
    }

    // lockouts (SIEM 4740)
    if (lock.state === 'live') {
      const L = lock.data, total = L.buckets.reduce((a, b) => a + b.n, 0);
      out.sources.lockouts = srcOut(lock);
      out.lockouts = { available: true, days: LOCK_DAYS, total, per_day: L.buckets, top_accounts: L.top, top_computers: L.computers,
        note: total ? 'From the domain controllers\' event 4740. An account locked again and again usually has an old password saved on a phone, a mapped drive or a service - or is being guessed.'
          : 'No lockout event (4740) in the SIEM in the last ' + LOCK_DAYS + ' days. If accounts do lock out, the domain controllers\' Security logs are not reaching the SIEM.' };
      const hot = L.top.filter((x) => x.n >= 10);
      rec(35, 'low', 'Account(s) locked out 10 or more times in ' + LOCK_DAYS + ' days', 'Find the device with the old password (the caller computer in AD Management) before unlocking again: ' + hot.slice(0, 5).map((x) => x.sam + ' (' + x.n + ')').join(', ') + '.', hot.length, [REF.cisLock, REF.sama], LINK.manage);
    } else { out.sources.lockouts = srcOut(lock); out.lockouts = { available: false, reason: lock.reason + ' - lockouts come from the domain controllers\' Security logs (event 4740) collected by the SIEM' }; }

    R.sort((a, b) => b.score - a.score || b.count - a.count);
    out.remediation = R.map((x, i) => Object.assign({ rank: i + 1 }, x));
    const scores = [out.policy && out.policy.score, out.mfa && out.mfa.available && out.mfa.pct !== null ? Math.min(100, Math.round(out.mfa.pct / Math.max(1, B.mfa_users_pct) * 100)) : null].filter((x) => typeof x === 'number');
    out.summary = { policy_score: out.policy ? out.policy.score ?? null : null, mfa_pct: out.mfa && out.mfa.available ? out.mfa.pct : null, admins_without_mfa: out.mfa && out.mfa.available ? out.mfa.admins_without.length : null,
      never_expires: out.accounts && out.accounts.never_expires ? out.accounts.never_expires.count : null, not_required: out.accounts && out.accounts.not_required ? out.accounts.not_required.count : null,
      lockouts: out.lockouts && out.lockouts.available ? out.lockouts.total : null, actions: out.remediation.length, overall: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null };
    return out;
  }

  async function report(q0, who) {
    const q = body(q0 || {}).oneOf('refresh', ['0', '1'], { def: '0' }).done();
    if (!cache || q.refresh === '1' || now() - cache.at > CACHE_MS) cache = { at: now(), v: await build() };
    const v = cache.v;
    audit(who, 'identity_posture.read', 'report', { refresh: q.refresh === '1', admins_without_mfa: v.summary.admins_without_mfa, actions: v.summary.actions });
    return Object.assign({}, v, { baseline: baseline() });
  }
  return { report, saveBaseline, baseline, build, KNOBS };
}

function registerIdentityPosture(srv, app, X) {
  srv.route('GET', '/identity-posture', (ctx) => { ctx.need('operator'); return X.report(ctx.query, ctx.who); });
  srv.route('POST', '/identity-posture/baseline', (ctx) => { ctx.need('admin'); return X.saveBaseline(ctx.body, ctx.who); }, { maxBody: 4096 });
}
module.exports = { createIdentityPosture, registerIdentityPosture, KNOBS };
