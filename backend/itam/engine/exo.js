// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { body } = require('./check');
const { createSealer } = require('./discovery/vault');
/*
 * Exchange Online for the platform (used by HR Offboarding to remove a leaver's mailbox forwarding and convert the mailbox to a
 * shared mailbox). Microsoft Graph cannot change a mailbox type or another user's inbox rules - only Exchange Online PowerShell
 * can - so this runs engine/exo/exo-run.ps1 under PowerShell 7 with the ExchangeOnlineManagement module, app-only sign-in with
 * a certificate. A FIXED list of operations, each validated
 * here and again in the script; the certificate password is sealed in the vault and handed to the script on stdin only.
 *   GET  /offboarding/exo          operator  settings (never the password)
 *   POST /offboarding/exo          admin     {enabled, organization, app_id, cert_path, cert_password?, pwsh?, autoreply_template?,
 *                                            spo_admin_url?, onedrive_days?}  audited
 * SharePoint Online (the leaver's OneDrive given to the manager) runs engine/exo/spo-run.ps1 with PnP.PowerShell and the SAME
 * app and certificate; it is on when spo_admin_url (https://<tenant>-admin.sharepoint.com) is set.
 *   POST /offboarding/exo/test     admin     sign in and read the organisation name (read-only)                             audited
 */
const OPS = ['test', 'get-mailbox', 'convert-shared', 'add-fullaccess', 'set-autoreply', 'get-forwarding', 'clear-forwarding', 'disable-inbox-rule'];
const SPO_OPS = ['spo-test', 'get-onedrive', 'add-site-admin', 'remove-site-admin'];
const ONEDRIVE = /^https:\/\/[a-z0-9-]{1,63}-my\.sharepoint\.com\/personal\/[A-Za-z0-9_]{1,200}\/?$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ORG = /^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/;
const ADDR = /^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function createExo(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-exo' });
  const cfgC = () => store.collection('exo_cfg');
  const cfg = () => Object.assign({ enabled: false, pwsh: 'pwsh', autoreply_template: ('{name} no longer works at ' + ZYB_ORG.short + '. For anything you need, please contact {delegate}.') }, cfgC().get('cfg') || {});
  const enabled = () => { const c = cfg(); return !!(c.enabled && c.organization && c.app_id && c.cert_path && c.pass_enc); };
  const spoEnabled = () => enabled() && !!cfg().spo_admin_url;
  const onedriveDays = () => { const v = cfg().onedrive_days; return Number.isInteger(v) ? v : 60; };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };

  function view() {
    const c = cfg();
    return { enabled: !!c.enabled, ready: enabled(), organization: c.organization || '', app_id: c.app_id || '', cert_path: c.cert_path || '', cert_password_set: !!c.pass_enc, pwsh: c.pwsh, spo_admin_url: c.spo_admin_url || '', onedrive_days: onedriveDays(), sharepoint_ready: spoEnabled(),
      autoreply_template: c.autoreply_template, last_test: c.last_test || null, updated_by: c.updated_by || null, updated_at: c.updated_at || null,
      vault: sealer.available() ? 'available' : 'unavailable: ' + sealer.unavailableReason(),
      requirements: 'PowerShell 7 (pwsh) and the ExchangeOnlineManagement module (3.x) on the platform server; an app registration with Exchange.ManageAsApp and an Exchange role allowing Get-EXOMailbox, Set-Mailbox, Add-MailboxPermission, Set-MailboxAutoReplyConfiguration, Get-InboxRule, Disable-InboxRule and Get-AcceptedDomain; its certificate as a .pfx on the server. OneDrive for leavers: the PnP.PowerShell module (2.x, PowerShell 7.4) and the SharePoint application permission Sites.FullControl.All on the same app' };
  }
  function configure(input, who) {
    if (/^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(who.user || ''))) throw httpErr(403, 'a service or AI identity cannot change these settings');
    const b = body(input || {}).bool('enabled').str('organization', { max: 253, re: ORG, msg: 'organization must be the tenant domain (contoso.onmicrosoft.com)' })
      .str('app_id', { max: 36, re: GUID, msg: 'app_id must be the application (client) id - a GUID' }).str('cert_path', { max: 300, re: /^\/[^\0]{1,298}\.pfx$/i, msg: 'cert_path must be the absolute path of the app certificate (.pfx) on the server' })
      .str('cert_password', { max: 200 }).str('pwsh', { max: 200, re: /^(pwsh|\/[A-Za-z0-9._\/-]{1,199})$/, msg: 'pwsh must be "pwsh" or the absolute path of PowerShell 7' })
      .str('autoreply_template', { max: 1000, min: 10 })
      .str('spo_admin_url', { max: 120, re: /^$|^https:\/\/[a-z0-9-]{1,63}-admin\.sharepoint\.com\/?$/, msg: 'spo_admin_url must be https://<tenant>-admin.sharepoint.com (empty switches OneDrive off)' })
      .num('onedrive_days', { min: 7, max: 365 }).done();
    if (b.onedrive_days !== undefined && !Number.isInteger(b.onedrive_days)) throw httpErr(400, 'onedrive_days must be a whole number of days');
    const c = Object.assign({}, cfg());
    for (const k of ['enabled', 'organization', 'app_id', 'cert_path', 'pwsh', 'autoreply_template', 'spo_admin_url', 'onedrive_days']) if (b[k] !== undefined) c[k] = b[k];
    if (c.spo_admin_url) c.spo_admin_url = c.spo_admin_url.replace(/\/$/, '');
    if (b.cert_password) { if (!sealer.available()) throw httpErr(503, 'credential vault unavailable: ' + sealer.unavailableReason()); c.pass_enc = sealer.seal('pfx', b.cert_password); c.pass_at = iso(); }
    if (c.enabled && !(c.organization && c.app_id && c.cert_path && c.pass_enc)) throw httpErr(400, 'enabled needs organization, app_id, cert_path and cert_password first');
    Object.assign(c, { id: 'cfg', updated_by: who.user, updated_at: iso() });
    cfgC().put(c);
    audit(who, 'offboarding.exo.settings', 'exo', { enabled: !!c.enabled, organization: c.organization || null, app_id: c.app_id || null, cert_path: c.cert_path || null, cert_password: b.cert_password ? 'changed' : 'unchanged', spo_admin_url: c.spo_admin_url || null, onedrive_days: c.onedrive_days || null });
    return view();
  }

  // one operation: validated, then the script with everything on stdin; resolves {ok, data|error}
  function run(op, params) {
    const spo = SPO_OPS.includes(op);
    if (!OPS.includes(op) && !spo) return Promise.resolve({ ok: false, error: 'operation not allowed' });
    const p = params || {};
    if (spo && !cfg().spo_admin_url) return Promise.resolve({ ok: false, error: 'SharePoint is not set up - add the SharePoint admin address in Exchange Online settings' });
    if ((op === 'add-site-admin' || op === 'remove-site-admin') && (!ONEDRIVE.test(String(p.site || '')) || !ADDR.test(String(p.user || '')))) return Promise.resolve({ ok: false, error: 'site must be a OneDrive address and user a user address' });
    if (!spo && op !== 'test' && !ADDR.test(String(p.identity || ''))) return Promise.resolve({ ok: false, error: 'identity must be a mailbox address' });
    if (op === 'get-onedrive' && !ADDR.test(String(p.identity || ''))) return Promise.resolve({ ok: false, error: 'identity must be a user address' });
    if (op === 'add-fullaccess' && !ADDR.test(String(p.user || ''))) return Promise.resolve({ ok: false, error: 'user must be a mailbox address' });
    if (op === 'disable-inbox-rule' && !/^\d{1,20}$/.test(String(p.rule || ''))) return Promise.resolve({ ok: false, error: 'rule must be the inbox rule id (digits)' });
    if (opts.run) return Promise.resolve(opts.run(op, p));
    const c = cfg();
    let pass; try { pass = sealer.unseal('pfx', c.pass_enc); } catch (e) { return Promise.resolve({ ok: false, error: 'the certificate password cannot be opened from the vault - save it again' }); }
    return new Promise((resolve) => {
      let out = '', err = '', done = false;
      const fin = (v) => { if (!done) { done = true; resolve(v); } };
      let child;
      try { child = spawn(c.pwsh, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', path.join(__dirname, 'exo', spo ? 'spo-run.ps1' : 'exo-run.ps1')], { stdio: ['pipe', 'pipe', 'pipe'] }); }
      catch (e) { return fin({ ok: false, error: 'PowerShell 7 could not be started (' + c.pwsh + '): ' + e.code }); }
      const t = setTimeout(() => { child.kill('SIGKILL'); fin({ ok: false, error: 'Exchange Online did not answer within 3 minutes' }); }, opts.timeoutMs || 180000);
      child.on('error', (e) => { clearTimeout(t); fin({ ok: false, error: e.code === 'ENOENT' ? 'PowerShell 7 (pwsh) is not installed on the platform server' : 'PowerShell could not be started: ' + e.code }); });
      child.stdout.on('data', (d) => { out += d; if (out.length > 65536) child.kill('SIGKILL'); });
      child.stderr.on('data', (d) => { err += d; if (err.length > 8192) err = err.slice(-8192); });
      child.on('close', () => {
        clearTimeout(t);
        const line = out.trim().split(/\r?\n/).filter(Boolean).pop() || '';
        try { const j = JSON.parse(line); fin(j && typeof j === 'object' ? j : { ok: false, error: 'unexpected output' }); }
        catch (e) { fin({ ok: false, error: 'the Exchange Online runner gave no result' + (err ? ': ' + err.replace(/\s+/g, ' ').slice(0, 200) : '') }); }
      });
      child.stdin.end(JSON.stringify(Object.assign({ org: c.organization, app_id: c.app_id, cert_path: c.cert_path, cert_password: pass, op, params: p }, spo ? { admin_url: c.spo_admin_url } : {})));
      pass = null;
    });
  }
  async function test(who) {
    const r = await run('test', {});
    const rec = r.ok ? { ok: true, organization: r.data && r.data.organization } : { ok: false, error: String(r.error || '').slice(0, 240) };
    if (cfg().spo_admin_url) { const s = await run('spo-test', {}); rec.sharepoint = s.ok ? { ok: true } : { ok: false, error: String(s.error || '').slice(0, 240) }; }
    cfgC().put(Object.assign({}, cfg(), { id: 'cfg', last_test: Object.assign({ at: iso(), by: who.user }, rec) }));
    audit(who, 'offboarding.exo.test', 'exo', rec);
    return rec;
  }
  return { view, configure, enabled, spoEnabled, onedriveDays, run, test, template: () => cfg().autoreply_template };
}

function registerExoRoutes(srv, app, X) {
  srv.route('GET', '/offboarding/exo', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('POST', '/offboarding/exo', (ctx) => { ctx.need('admin'); return X.configure(ctx.body, ctx.who); });
  srv.route('POST', '/offboarding/exo/test', (ctx) => { ctx.need('admin'); body(ctx.body).done(); if (/^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(ctx.who.user || ''))) throw httpErr(403, 'a person does this'); return X.test(ctx.who); });
}

module.exports = { createExo, registerExoRoutes, OPS, SPO_OPS, ONEDRIVE };
