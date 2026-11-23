// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { guardOf } = require('./errors');
/*
 * Directory users ({P} = /api/itam; Platform Administration -> User Management -> Directory users): the people in Active
 * Directory, READ ONLY, through the same directory connection HR onboarding uses (engine/onboarding-ad.js settings, the bind
 * password sealed in the vault; LDAPS / StartTLS with the certificate checked). Nothing here writes to AD and nothing here
 * creates a platform account: an administrator creates the account in Identity & Sign-in -> Users, where 2FA enrolment applies.
 *   read     person accounts under the base DN, or only the members of one group (an administrator's setting, e.g.
 *            SENTRA-Platform-Users) - name, user name, UPN, mail, department, title, enabled, last sign-in, privileged (adminCount)
 *   kept     the last read is kept (who read it, when, how many); the page compares it with the platform accounts
 * Names, departments and sign-in times of employees are personal data (PDPL): operators and administrators only.
 *   GET  /ad-directory                operator   settings, the last read and its users
 *   POST /ad-directory/refresh        operator   read the directory now (a person)                                 audited
 *   POST /ad-directory/settings       admin      {group: '' | sAMAccountName | DN, auto_hours: 0 | 6 | 12 | 24}         audited
 * auto_hours re-reads the directory on its own (as system:ad-directory, audited like a person's read); 0 = only when a person presses Read.
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));

function createAdDirectory(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, iso = () => new Date(now()).toISOString();
  const C = () => store.collection('ad_directory');
  const AD = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const settings = () => Object.assign({ group: '', auto_hours: 0 }, (C().get('settings') || {}).v || {});
  function connection() {
    const a = AD(); if (!a) return { ok: false, why: 'HR onboarding (which holds the directory connection) is not installed - run the update' };
    const c = a.cfg(); if (!(c.bind_enc && (c.servers || []).length && c.base_dn)) return { ok: false, why: 'the directory connection is not set - an administrator sets it in HR Onboarding -> Directory settings (servers, base DN, bind account)' };
    return { ok: true, servers: c.servers, base_dn: c.base_dn };
  }
  function view() {
    const cn = connection(), last = C().get('last') || null;
    return { connection: cn.ok ? { ok: true, servers: cn.servers, base_dn: cn.base_dn } : cn, settings: settings(), last: last ? { at: last.at, by: last.by, count: last.users.length, truncated: last.truncated, group: last.group } : null,
      users: last ? last.users : [], note: 'Read only. A platform account is created by an administrator in Identity & Sign-in -> Users (two-factor enrolment applies); being in the directory does not give access.' };
  }
  const SYSTEM = { user: 'system:ad-directory', role: 'system', ip: '' };
  async function refresh(who, scheduled) {
    if (!scheduled && isService(who.user)) throw httpErr(403, 'a person reads the directory, not a service or AI identity');
    const cn = connection(); if (!cn.ok) throw httpErr(409, cn.why);
    const s = settings(); let r;
    try { r = await AD().writer().directoryUsers({ group: s.group || undefined }); }
    catch (e) {
      if (e.status) throw e;
      if (app.log && app.log.every) app.log.every('ad-directory:read', 600000, 'warn', 'directory users could not be read', { err: String(e.message).slice(0, 200) });
      throw httpErr(424, 'the directory could not be read: ' + String(e.message).slice(0, 200));
    }
    const users = r.users.filter((u) => u.sam).sort((a, b) => String(a.display_name || a.sam).localeCompare(String(b.display_name || b.sam)));
    C().put({ id: 'last', at: iso(), by: who.user, group: s.group || '', truncated: !!r.truncated, users });
    audit(who, scheduled ? 'ad_directory.auto_refresh' : 'ad_directory.refresh', s.group || 'all', { users: users.length, enabled: users.filter((u) => u.enabled).length, truncated: !!r.truncated });
    return view();
  }
  function saveSettings(b0, who) {
    const b = body(b0 || {}).str('group', { max: 400, re: /^$|^[A-Za-z0-9 ._$-]{1,256}$|^CN=[^\u0000-\u001f]{1,396}$/i, msg: 'group must be a group name (sAMAccountName) or its DN (CN=...), or empty for everyone' })
      .oneOf('auto_hours', [0, 6, 12, 24]).done();
    const v = { group: b.group || '', auto_hours: b.auto_hours !== undefined ? b.auto_hours : settings().auto_hours };
    C().put({ id: 'settings', v, by: who.user, at: iso() });
    audit(who, 'ad_directory.settings', 'settings', v);
    return view();
  }
  // the automatic re-read: due when auto_hours is set and the last read is older than that; a failure is logged (once an hour) and
  // retried on the next tick, never retried in a tight loop
  async function tick() {
    const s = settings(); if (!s.auto_hours || !connection().ok) return false;
    const last = C().get('last'); if (last && Date.parse(last.at) + s.auto_hours * 3600000 > now()) return false;
    try { await refresh(SYSTEM, true); return true; } catch (e) { if (app.log && app.log.every) app.log.every('ad-directory:auto', 3600000, 'warn', 'the automatic directory read failed', { err: String(e.message).slice(0, 200) }); return false; }
  }
  if (!(app.noTimers || opts.noTimer)) { const t = setInterval(guardOf(app, 'ad_directory.auto', tick), 10 * 60000); if (t.unref) t.unref(); }
  return { view, refresh, saveSettings, connection, tick };
}
function registerAdDirectory(srv, app, X) {
  srv.route('GET', '/ad-directory', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('POST', '/ad-directory/refresh', (ctx) => { ctx.need('operator'); body(ctx.body).done(); return X.refresh(ctx.who); });
  srv.route('POST', '/ad-directory/settings', (ctx) => { ctx.need('admin'); return X.saveSettings(ctx.body, ctx.who); }, { maxBody: 2048 });
}
module.exports = { createAdDirectory, registerAdDirectory };
