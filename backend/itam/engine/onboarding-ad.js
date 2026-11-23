// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, isIp } = require('./check');
const { createSealer } = require('./discovery/vault');
const { createAdWriter, tempPassword } = require('./ad-writer');
/*
 * HR onboarding - automatic Active Directory account creation (engine/onboarding.js calls this; engine/ad-writer.js writes).
 * Off until an administrator configures it. Then, and only after the account was APPROVED by an administrator who did not
 * propose it (four eyes, in onboarding.js):
 *   create     the user in the configured OU, DISABLED, with a random 16-character temporary password and "change at first
 *              sign-in"; added only to the approved groups that are also on the administrator's allowed list (never a
 *              privileged group); read back and verified (exists, disabled, must change, group memberships)
 *   password   sealed in the vault for a ONE-TIME reveal by the named line manager (a person, not the requester's desk, not
 *              a service), who hands it to the joiner; purged after the reveal or after 72 hours. Nobody else sees it; it is
 *              never logged, audited, e-mailed or shown twice. A lost password is re-issued only through a request that a
 *              different administrator approves
 *   enable     when the joiner signs for the laptop (the handover step)
 *   disable    when the request is cancelled after the account was created (never deleted)
 * Mailbox and licences are not created here: Exchange / Microsoft 365 provisioning stays with their administrators.
 *
 *   GET  /onboarding/ad                       operator  settings (never the bind password)
 *   POST /onboarding/ad                       admin     {enabled, servers[], ca_file | ca_pem, bind_dn, bind_password?, base_dn, ou,
 *                                                        upn_suffix, allowed_groups[], leavers_enabled, leavers_ou?,
 *                                                        disable_hour, scramble_password, never_disable[], movers_enabled} audited
 * The same connection serves leavers (engine/offboarding.js): leavers_enabled switches automatic disabling on; the bind
 * account then also needs "write userAccountControl / description / reset password" on the staff OUs (and "move" into
 * leavers_ou if one is set). never_disable lists accounts the platform must never disable or change (break-glass, service).
 * movers_enabled switches automatic group changes for movers on (engine/movers.js): the bind account then needs "write
 * members" on the groups movers may join or leave, and "write department / title" on the staff OUs.
 *   POST /onboarding/ad/test                  admin     bind and check the OU (read-only)                             audited
 */
const DN = /^(?:(?:CN|OU|DC)=[^,=]{1,128},)*(?:CN|OU|DC)=[^,=]{1,128}$/i;
const SUFFIX = /^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/;
const URL_RE = /^ldaps?:\/\/[A-Za-z0-9.-]{1,253}(:\d{1,5})?\/?$/i;
const GROUP = /^[A-Za-z0-9 ._&()-]{1,128}$/;
const REVEAL_HOURS = 72;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (s) => String(s || '').trim().toLowerCase();

// every built-in / well-known group that grants control of servers, the domain or Exchange - not only names with "admin"
// in them: Account / Backup / Server / Print Operators, Group Policy Creator Owners, DnsAdmins, Cert Publishers, Exchange
// Organization Management / Trusted Subsystem / Windows Permissions, Hyper-V, remote management, tier 0
const PRIVILEGED = /admin|\boperators?\b|group policy creator|organization management|exchange (trusted subsystem|windows permissions|servers)|cert publishers|\bkey admins\b|hyper-v|remote management users|enterprise read-only|replicator|protected users|krbtgt|\b(tier ?0|t0)\b/i;

function createOnboardingAd(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-onboarding-ad' });
  const cfgC = () => store.collection('onboarding_ad'), secC = () => store.collection('onboarding_secrets');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('onboarding-ad:' + key, 3600000, 'warn', msg, detail); };
  const cfg = () => cfgC().get('cfg') || { id: 'cfg', enabled: false, servers: [], allowed_groups: [] };
  const privileged = opts.privileged || PRIVILEGED;

  function view() {
    const c = cfg();
    return { enabled: !!c.enabled, servers: c.servers || [], server_ips: c.server_ips || {}, ca_file: c.ca_file || '', ca: caInfo(c), bind_dn: c.bind_dn || '', bind_password_set: !!c.bind_enc, base_dn: c.base_dn || '', ou: c.ou || '',
      upn_suffix: c.upn_suffix || '', allowed_groups: c.allowed_groups || [], leavers_enabled: !!c.leavers_enabled, leavers_ou: c.leavers_ou || '',
      disable_hour: c.disable_hour === undefined ? 18 : c.disable_hour, scramble_password: c.scramble_password !== false, never_disable: c.never_disable || [], movers_enabled: !!c.movers_enabled, updated_by: c.updated_by || null, updated_at: c.updated_at || null, last_test: c.last_test || null,
      vault: sealer.available() ? 'available' : 'unavailable: ' + sealer.unavailableReason(), reveal_hours: REVEAL_HOURS };
  }
  // the AD CS root certificate: a file on the server (ca_file) or the PEM held in these settings (ca_pem, set by Connect Active
  // Directory after the administrator compared its fingerprint) - a public certificate, not a secret
  function caInfo(c) {
    if (c.ca_pem) { try { const x = new (require('node:crypto').X509Certificate)(c.ca_pem); return { source: 'settings', subject: x.subject.replace(/\n/g, ', '), fingerprint256: x.fingerprint256, valid_to: new Date(x.validTo).toISOString() }; } catch (e) { return { source: 'settings', error: 'not a readable certificate' }; } }
    return c.ca_file ? { source: 'file', path: c.ca_file } : null;
  }
  const hasCa = (c) => !!(c.ca_file || c.ca_pem);
  const enabled = () => { const c = cfg(); return !!(c.enabled && c.bind_enc && c.ou && (c.servers || []).length); };
  const moversEnabled = () => { const c = cfg(); return !!(c.movers_enabled && c.bind_enc && c.base_dn && (c.servers || []).length); };
  const leaversEnabled = () => { const c = cfg(); return !!(c.leavers_enabled && c.bind_enc && c.base_dn && (c.servers || []).length); };

  function configure(input, who) {
    const b = body(input || {}).bool('enabled').list('servers', { max: 4, item: 'str', itemMax: 270, unique: true }).str('ca_file', { max: 300, re: /^\/[^\0]{1,299}$/, msg: 'ca_file must be the absolute path of the AD CS root certificate (PEM) on the server' })
      .str('ca_pem', { max: 20000, re: /^(-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+$/, msg: 'ca_pem must be the PEM (Base-64) root CA certificate: -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----' })
      .str('bind_dn', { max: 400, re: DN, msg: 'bind_dn must be a distinguished name (CN=svc-onboarding,OU=Service,DC=corp,DC=local)' }).str('bind_password', { max: 256 })
      .str('base_dn', { max: 300, re: DN, msg: 'base_dn must be the domain DN (DC=corp,DC=local)' }).str('ou', { max: 400, re: DN, msg: 'ou must be the DN of the OU new accounts go into' })
      .str('upn_suffix', { max: 253, re: SUFFIX, msg: 'upn_suffix must be a domain name (corp.com)' }).list('allowed_groups', { max: 100, item: 'str', itemMax: 128, unique: true })
      .bool('leavers_enabled').str('leavers_ou', { max: 400, re: DN, msg: 'leavers_ou must be the DN of the OU disabled accounts move to (or empty)' }).num('disable_hour', { min: 0, max: 23 })
      .bool('scramble_password').bool('movers_enabled').list('never_disable', { max: 200, item: 'str', itemMax: 64, unique: true }).done();
    if (b.disable_hour !== undefined && !Number.isInteger(b.disable_hour)) throw httpErr(400, 'disable_hour must be a whole hour, 0-23 (Riyadh time)');
    if (b.never_disable && b.never_disable.some((x) => !/^[A-Za-z0-9._$-]{1,64}$/.test(x))) throw httpErr(400, 'never_disable: each must be an account name (sAMAccountName)');
    // server_ips {dc name: ip}: dial the IP, verify the certificate under the name (a DC the platform's DNS cannot resolve)
    if (input && input.server_ips !== undefined) {
      const m = input.server_ips; if (!m || typeof m !== 'object' || Array.isArray(m) || Object.keys(m).length > 4) throw httpErr(400, 'server_ips must be {domain controller name: IP address}, at most 4');
      for (const [k, v] of Object.entries(m)) if (!/^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/.test(k) || !isIp(String(v))) throw httpErr(400, 'server_ips: ' + k.slice(0, 60) + ' must be a domain controller name with an IP address');
      b.server_ips = Object.fromEntries(Object.entries(m).map(([k, v]) => [k.toLowerCase(), String(v)]));
    }
    if (b.servers && b.servers.some((s) => !URL_RE.test(s))) throw httpErr(400, 'servers: each must be ldaps://dc.domain:636 (or ldap://dc.domain:389, upgraded with StartTLS)');
    if (b.allowed_groups) {
      const bad = b.allowed_groups.filter((g) => !GROUP.test(g)); if (bad.length) throw httpErr(400, 'allowed_groups: ' + bad[0] + ' is not a group name');
      const priv = b.allowed_groups.filter((g) => privileged.test(g)); if (priv.length) throw httpErr(400, 'allowed_groups: ' + priv.join(', ') + ' is privileged - onboarding never grants it');
    }
    if (b.ca_pem) { try { const x = new (require('node:crypto').X509Certificate)(b.ca_pem); if (!x.ca) throw httpErr(400, 'ca_pem is not a CA certificate - give the root CA that issued the domain controller certificate'); } catch (e) { if (e.status) throw e; throw httpErr(400, 'ca_pem is not a readable certificate'); } }
    const c = Object.assign({}, cfg());
    for (const k of ['enabled', 'servers', 'server_ips', 'ca_file', 'ca_pem', 'bind_dn', 'base_dn', 'ou', 'upn_suffix', 'allowed_groups', 'leavers_enabled', 'leavers_ou', 'disable_hour', 'scramble_password', 'never_disable', 'movers_enabled']) if (b[k] !== undefined) c[k] = b[k];
    if (c.ou && c.base_dn && !low(c.ou).endsWith(low(c.base_dn))) throw httpErr(400, 'ou must be inside base_dn');
    if (c.leavers_ou && c.base_dn && !low(c.leavers_ou).endsWith(low(c.base_dn))) throw httpErr(400, 'leavers_ou must be inside base_dn');
    if (b.bind_password) { if (!sealer.available()) throw httpErr(503, 'credential vault unavailable: ' + sealer.unavailableReason()); c.bind_enc = sealer.seal('bind', b.bind_password); c.bind_at = iso(); }
    if (c.enabled && !(c.servers && c.servers.length && hasCa(c) && c.bind_dn && c.bind_enc && c.base_dn && c.ou && c.upn_suffix)) throw httpErr(400, 'enabled needs servers, the CA certificate, bind_dn, bind_password, base_dn, ou and upn_suffix first');
    if (c.movers_enabled && !(c.servers && c.servers.length && hasCa(c) && c.bind_dn && c.bind_enc && c.base_dn)) throw httpErr(400, 'movers_enabled needs servers, the CA certificate, bind_dn, bind_password and base_dn first');
    if (c.leavers_enabled && !(c.servers && c.servers.length && hasCa(c) && c.bind_dn && c.bind_enc && c.base_dn)) throw httpErr(400, 'leavers_enabled needs servers, the CA certificate, bind_dn, bind_password and base_dn first');
    c.updated_by = who.user; c.updated_at = iso();
    cfgC().put(c);
    audit(who, 'onboarding.ad.settings', 'ad', { ca: b.ca_pem ? 'certificate ' + (caInfo(c) || {}).fingerprint256 : b.ca_file ? 'file' : 'unchanged', enabled: !!c.enabled, servers: (c.servers || []).length, ou: c.ou || null, allowed_groups: (c.allowed_groups || []).length, bind_password: b.bind_password ? 'changed' : 'unchanged',
      leavers_enabled: !!c.leavers_enabled, movers_enabled: !!c.movers_enabled, leavers_ou: c.leavers_ou || null, disable_hour: c.disable_hour, never_disable: (c.never_disable || []).length });
    return view();
  }

  function writer() {
    const c = cfg();
    if (opts.writer) return opts.writer(c);
    let password; try { password = sealer.unseal('bind', c.bind_enc); } catch (e) { throw httpErr(503, 'the bind password cannot be opened from the vault - save it again'); }
    return createAdWriter({ servers: (c.servers || []).map((u) => { const h = String(u).replace(/^ldaps?:\/\/|:\d+\/?$/gi, '').toLowerCase(), ip = (c.server_ips || {})[h]; return ip ? { url: u, ip } : u; }), ca: c.ca_pem || undefined, caFile: c.ca_pem ? undefined : c.ca_file, bindDN: c.bind_dn, password, baseDN: c.base_dn, log: (level, msg, meta) => warn('ldap', 'AD writer: ' + msg, meta) });
  }
  async function test(who) {
    const c = cfg(); let r;
    try { r = await writer().test(c.ou); r = { ok: true, server: r.server, ou_found: r.ou }; }
    catch (e) { r = { ok: false, error: String(e.message).slice(0, 200) }; }
    cfgC().put(Object.assign({}, cfg(), { last_test: Object.assign({ at: iso(), by: who.user }, r) }));
    audit(who, 'onboarding.ad.test', 'ad', r);
    return r;
  }

  // ---- called by onboarding.js once the account is approved (four eyes already enforced there)
  async function provision(r) {
    const c = cfg(), a = r.account, W = writer();
    const upn = a.username + '@' + c.upn_suffix;
    const taken = await W.exists({ sam: a.username, upn });
    const marker = ('Created by ' + ZYB_ORG.short + ' onboarding ') + r.id;
    if (taken) {
      const cur = await W.read(taken);
      if (!cur || cur.description !== marker) throw httpErr(409, 'the user name ' + a.username + ' or ' + upn + ' already exists in the directory - propose another name');
    }
    const parts = String(r.name).trim().split(/\s+/);
    const pw = tempPassword();
    const made = await W.createUser(c.ou, { sAMAccountName: a.username, userPrincipalName: upn, displayName: r.name, givenName: parts[0], sn: parts.slice(1).join(' ') || parts[0],
      department: r.department, title: r.job_title, employeeID: r.employee_id, physicalDeliveryOfficeName: r.branch || undefined }, pw, marker);
    const allowed = new Set((c.allowed_groups || []).map(low));
    const added = [], refused = [];
    for (const g of a.groups || []) {
      if (!allowed.has(low(g)) || privileged.test(g)) { refused.push(g + ' (not on the allowed list)'); continue; }
      const gdn = await W.findGroup(g);
      if (!gdn) { refused.push(g + ' (not found in the directory)'); continue; }
      try { await W.addToGroup(gdn, made.dn); added.push(g); } catch (e) { refused.push(g + ' (' + String(e.message).slice(0, 80) + ')'); }
    }
    const v = await W.read(made.dn);
    const verified = !!(v && !v.enabled && v.must_change && v.sam.toLowerCase() === a.username);
    if (!sealer.available()) throw httpErr(503, 'credential vault unavailable: the temporary password cannot be kept for the manager');
    secC().put({ id: r.id, enc: sealer.seal('temp:' + r.id, pw), at: iso(), expires_at: new Date(now() + REVEAL_HOURS * 3600000).toISOString() });
    return { dn: made.dn, upn, existed: made.existed, groups_added: added, groups_refused: refused, verified, member_of: v ? v.member_of.length : 0, at: iso() };
  }
  function secretState(id) { const s = secC().get(id); return s ? { waiting: Date.parse(s.expires_at) > now(), expires_at: s.expires_at } : null; }
  function reveal(r) {
    const s = secC().get(r.id);
    if (!s) throw httpErr(410, 'no temporary password is waiting - it was already shown, or it expired; request a re-issue');
    secC().remove(r.id);
    if (Date.parse(s.expires_at) <= now()) throw httpErr(410, 'the temporary password expired unrevealed (' + REVEAL_HOURS + ' h) and was destroyed - request a re-issue');
    let pw; try { pw = sealer.unseal('temp:' + r.id, s.enc); } catch (e) { throw httpErr(503, 'the temporary password cannot be opened from the vault - request a re-issue'); }
    return pw;
  }
  async function reissue(r) {
    const pw = tempPassword();
    await writer().resetPassword(r.account.provisioned.dn, pw);
    secC().put({ id: r.id, enc: sealer.seal('temp:' + r.id, pw), at: iso(), expires_at: new Date(now() + REVEAL_HOURS * 3600000).toISOString() });
    return true;
  }
  const setEnabled = (r, on) => writer().setEnabled(r.account.provisioned.dn, on);
  function purge() { let n = 0; for (const s of secC().all((x) => Date.parse(x.expires_at) <= now())) { secC().remove(s.id); n++; } return n; }
  const drop = (id) => secC().remove(id);
  return { view, configure, test, enabled, leaversEnabled, moversEnabled, writer, cfg, provision, reveal, reissue, setEnabled, purge, drop, secretState };
}

function registerOnboardingAdRoutes(srv, app, X) {
  const human = (ctx, what) => { if (/^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(ctx.who.user || ''))) throw httpErr(403, 'a service or AI identity cannot ' + what); };
  srv.route('GET', '/onboarding/ad', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('POST', '/onboarding/ad', (ctx) => { ctx.need('admin'); human(ctx, 'change the directory settings'); return X.configure(ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/ad/test', (ctx) => { ctx.need('admin'); human(ctx, 'test the directory connection'); body(ctx.body).done(); return X.test(ctx.who); });
}

module.exports = { PRIVILEGED, createOnboardingAd, registerOnboardingAdRoutes, REVEAL_HOURS };
