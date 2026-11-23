// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { createSealer } = require('./discovery/vault');
const httpc = require('./discovery/httpc');
/*
 * HR onboarding - automatic Microsoft 365 / Entra ID licence assignment for joiners (engine/onboarding.js calls this).
 * The licences are part of the account proposal that an administrator who did not propose it approved (four eyes); this
 * module only carries out that approval, through Microsoft Graph with an app registration (client credentials):
 *   1. catalogue    an administrator names the licences joiners may get (e.g. "Microsoft 365 E3" -> its SKU id, optionally
 *                   service plans switched off) and the default licences for a joiner who needs Microsoft 365. "Test" reads the
 *                   tenant's subscriptions (GET /subscribedSkus) so the SKU ids, seats bought and seats free are shown
 *   2. wait         once the account exists in Active Directory, the joiner's Entra ID user is looked up by UPN every 10 min
 *                   (Entra Connect syncs it, normally within 30 min); after 48 h without it the request says so
 *   3. assign       usage location set when it is missing (licences cannot be assigned without it), free seats checked for
 *                   every licence - nothing is assigned when one has none ("blocked", with the licence named) - then
 *                   POST /users/{id}/assignLicense and the user read back to confirm every licence is on it
 * Nothing else is changed for joiners: no licence is removed, no other user is touched. The client secret is sealed in the vault.
 * Leavers (engine/offboarding.js): readUser / removeLicences take back a disabled leaver's licences, after the hold period
 * (reclaim_hold_days, default 30) and an administrator's approval - only the licences that approval named, read back after.
 * Leavers' groups and teams (teams_enabled): ownedGroups / addOwner / removeOwner hand a disabled leaver's Microsoft 365 groups and
 * Teams to the manager after the disable approval named it (engine/offboarding.js) - Group.ReadWrite.All and Directory.Read.All.
 * Leavers' meetings (calendar_enabled): organizedMeetings / recreateMeeting / retireMeeting move the meetings a disabled leaver
 * organises to the manager (Exchange cannot change an organiser: the meeting is created again from the manager's calendar and
 * the leaver's one is ended) - Calendars.ReadWrite.
 * Leavers under legal hold (legal_enabled): Microsoft Purview eDiscovery through Graph (/security/cases/ediscoveryCases) - case,
 * custodian with the mailbox (Teams chats included) and OneDrive, hold, search, estimate, export IN Purview. The content never
 * leaves Microsoft 365; the platform keeps ids, counts and sizes - eDiscovery.ReadWrite.All.
 * Leavers' devices (devices_enabled): userDevices / deviceGet / deviceAction list a leaver's Intune devices and send the wipe
 * (company device) or retire (any device) a person approved - DeviceManagementManagedDevices.Read.All and
 * DeviceManagementManagedDevices.PrivilegedOperations.All.
 * Leavers' business applications (apps_enabled): servicePrincipal / appAssignments / removeAppAssignment / revokeSessions remove
 * a disabled leaver's Entra ID enterprise-application assignments and end their sign-in sessions - AppRoleAssignment.ReadWrite.All,
 * Application.Read.All and User.RevokeSessions.All.
 * Graph application permissions: LicenseAssignment.ReadWrite.All, Organization.Read.All, User.Read.All (and
 * User.ReadWrite.All only when the platform is to set the usage location).
 *   GET  /onboarding/m365            operator  settings (never the secret), catalogue, last subscriptions read
 *   POST /onboarding/m365            admin     {enabled, tenant_id, client_id, client_secret?, usage_location, set_usage_location,
 *                                               catalogue: [{name, sku_id, disabled_plans?[]}], default_licences[]}   audited
 *   POST /onboarding/m365/test       admin     token + subscriptions (read-only)                                     audited
 */
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NAME = /^[A-Za-z0-9 ._()+&-]{2,60}$/;
const SYNC_WAIT_MS = 48 * 3600000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (s) => String(s || '').trim().toLowerCase();

function createM365Licensing(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-m365-licensing' });
  const cfgC = () => store.collection('onboarding_m365');
  const loginBase = (opts.loginBase || 'https://login.microsoftonline.com').replace(/\/+$/, '');
  const graphBase = (opts.graphBase || 'https://graph.microsoft.com/v1.0').replace(/\/+$/, '');
  const request = opts.request || httpc.request;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('m365-lic:' + key, 3600000, 'warn', msg, detail); };
  const cfg = () => Object.assign({ enabled: false, usage_location: 'SA', set_usage_location: true, catalogue: [], default_licences: [], reclaim_enabled: false, reclaim_hold_days: 30 }, cfgC().get('cfg') || {});
  const enabled = () => { const c = cfg(); return !!(c.enabled && c.tenant_id && c.client_id && c.secret_enc && c.catalogue.length); };
  const reclaimEnabled = () => { const c = cfg(); return !!(c.reclaim_enabled && c.tenant_id && c.client_id && c.secret_enc); };
  const appsEnabled = () => { const c = cfg(); return !!(c.apps_enabled && c.tenant_id && c.client_id && c.secret_enc); };
  const devicesEnabled = () => { const c = cfg(); return !!(c.devices_enabled && c.tenant_id && c.client_id && c.secret_enc); };
  const legalEnabled = () => { const c = cfg(); return !!(c.legal_enabled && c.tenant_id && c.client_id && c.secret_enc); };
  const calendarEnabled = () => { const c = cfg(); return !!(c.calendar_enabled && c.tenant_id && c.client_id && c.secret_enc); };
  const calendarDays = () => (Number.isInteger(cfg().calendar_days) ? cfg().calendar_days : 180);
  const teamsEnabled = () => { const c = cfg(); return !!(c.teams_enabled && c.tenant_id && c.client_id && c.secret_enc); };

  function view() {
    const c = cfg();
    return { enabled: !!c.enabled, ready: enabled(), tenant_id: c.tenant_id || '', client_id: c.client_id || '', client_secret_set: !!c.secret_enc, usage_location: c.usage_location, set_usage_location: c.set_usage_location,
      catalogue: c.catalogue, default_licences: c.default_licences, reclaim_enabled: !!c.reclaim_enabled, reclaim_ready: reclaimEnabled(), reclaim_hold_days: c.reclaim_hold_days, teams_enabled: !!c.teams_enabled, teams_ready: teamsEnabled(), calendar_enabled: !!c.calendar_enabled, calendar_ready: calendarEnabled(), calendar_days: calendarDays(), legal_enabled: !!c.legal_enabled, legal_ready: legalEnabled(), devices_enabled: !!c.devices_enabled, devices_ready: devicesEnabled(), apps_enabled: !!c.apps_enabled, apps_ready: appsEnabled(), skus: c.skus || null, last_test: c.last_test || null, updated_by: c.updated_by || null, updated_at: c.updated_at || null,
      vault: sealer.available() ? 'available' : 'unavailable: ' + sealer.unavailableReason(),
      permissions: 'Graph application permissions: LicenseAssignment.ReadWrite.All, Organization.Read.All, User.Read.All (+ User.ReadWrite.All to set the usage location; + Group.ReadWrite.All and Directory.Read.All for leavers\' groups and Teams; + Calendars.ReadWrite for leavers\' meetings; + eDiscovery.ReadWrite.All for leavers under legal hold; + DeviceManagementManagedDevices.Read.All and .PrivilegedOperations.All for leavers\' devices; + AppRoleAssignment.ReadWrite.All, Application.Read.All and User.RevokeSessions.All for leavers\' applications)' };
  }

  function configure(input, who) {
    if (/^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(who.user || ''))) throw httpErr(403, 'a service or AI identity cannot change these settings');
    const b = body(input || {}).bool('enabled').str('tenant_id', { max: 36, re: GUID, msg: 'tenant_id must be the directory (tenant) id - a GUID from Entra ID -> Overview' })
      .str('client_id', { max: 36, re: GUID, msg: 'client_id must be the application (client) id of the app registration - a GUID' }).str('client_secret', { max: 200 })
      .str('usage_location', { max: 2, re: /^[A-Z]{2}$/, msg: 'usage_location must be a two-letter country code (SA)' }).bool('set_usage_location')
      .list('catalogue', { max: 50 }).list('default_licences', { max: 10, item: 'str', itemMax: 60, unique: true })
      .bool('reclaim_enabled').num('reclaim_hold_days', { min: 0, max: 90 }).bool('teams_enabled').bool('calendar_enabled').num('calendar_days', { min: 30, max: 730 }).bool('legal_enabled').bool('devices_enabled').bool('apps_enabled').done();
    if (b.calendar_days !== undefined && !Number.isInteger(b.calendar_days)) throw httpErr(400, 'calendar_days must be a whole number of days (30-730)');
    if (b.reclaim_hold_days !== undefined && !Number.isInteger(b.reclaim_hold_days)) throw httpErr(400, 'reclaim_hold_days must be a whole number of days (0-90)');
    const c = Object.assign({}, cfg());
    if (b.catalogue) {
      const seen = new Set();
      c.catalogue = b.catalogue.map((x, i) => {
        if (!x || typeof x !== 'object' || Array.isArray(x)) throw httpErr(400, 'catalogue[' + i + '] must be {name, sku_id, disabled_plans?}');
        const e = body(x).str('name', { required: true, max: 60, re: NAME, msg: 'catalogue[' + i + '].name must be a short licence name (Microsoft 365 E3)' })
          .str('sku_id', { required: true, max: 36, re: GUID, msg: 'catalogue[' + i + '].sku_id must be the licence SKU id (a GUID - use Test to list them)' })
          .list('disabled_plans', { max: 40, item: 'str', itemMax: 36, unique: true, def: [] }).done();
        if (e.disabled_plans.some((p) => !GUID.test(p))) throw httpErr(400, 'catalogue[' + i + '].disabled_plans: each must be a service plan id (a GUID)');
        if (seen.has(low(e.name))) throw httpErr(400, 'catalogue: ' + e.name + ' is listed twice'); seen.add(low(e.name));
        return e;
      });
    }
    if (b.default_licences !== undefined) c.default_licences = b.default_licences;
    for (const k of ['enabled', 'tenant_id', 'client_id', 'usage_location', 'set_usage_location', 'reclaim_enabled', 'reclaim_hold_days', 'teams_enabled', 'calendar_enabled', 'calendar_days', 'legal_enabled', 'devices_enabled', 'apps_enabled']) if (b[k] !== undefined) c[k] = b[k];
    const unknown = (c.default_licences || []).filter((n) => !c.catalogue.some((x) => low(x.name) === low(n)));
    if (unknown.length) throw httpErr(400, 'default_licences: ' + unknown.join(', ') + ' is not in the catalogue');
    if (b.client_secret) { if (!sealer.available()) throw httpErr(503, 'credential vault unavailable: ' + sealer.unavailableReason()); c.secret_enc = sealer.seal('graph', b.client_secret); c.secret_at = iso(); }
    if (c.enabled && !(c.tenant_id && c.client_id && c.secret_enc && c.catalogue.length)) throw httpErr(400, 'enabled needs tenant_id, client_id, client_secret and at least one licence in the catalogue');
    if (c.reclaim_enabled && !(c.tenant_id && c.client_id && c.secret_enc)) throw httpErr(400, 'reclaim_enabled needs tenant_id, client_id and client_secret');
    if (c.teams_enabled && !(c.tenant_id && c.client_id && c.secret_enc)) throw httpErr(400, 'teams_enabled needs tenant_id, client_id and client_secret');
    if (c.apps_enabled && !(c.tenant_id && c.client_id && c.secret_enc)) throw httpErr(400, 'apps_enabled needs tenant_id, client_id and client_secret');
    if (c.devices_enabled && !(c.tenant_id && c.client_id && c.secret_enc)) throw httpErr(400, 'devices_enabled needs tenant_id, client_id and client_secret');
    if (c.legal_enabled && !(c.tenant_id && c.client_id && c.secret_enc)) throw httpErr(400, 'legal_enabled needs tenant_id, client_id and client_secret');
    if (c.calendar_enabled && !(c.tenant_id && c.client_id && c.secret_enc)) throw httpErr(400, 'calendar_enabled needs tenant_id, client_id and client_secret');
    Object.assign(c, { id: 'cfg', updated_by: who.user, updated_at: iso() });
    cfgC().put(c);
    audit(who, 'onboarding.m365.settings', 'm365', { enabled: !!c.enabled, tenant_id: c.tenant_id || null, client_id: c.client_id || null, catalogue: c.catalogue.map((x) => x.name), default_licences: c.default_licences, reclaim_enabled: !!c.reclaim_enabled, reclaim_hold_days: c.reclaim_hold_days, teams_enabled: !!c.teams_enabled, calendar_enabled: !!c.calendar_enabled, calendar_days: c.calendar_days || null, legal_enabled: !!c.legal_enabled, devices_enabled: !!c.devices_enabled, apps_enabled: !!c.apps_enabled, client_secret: b.client_secret ? 'changed' : 'unchanged' });
    return view();
  }

  // ---- Microsoft Graph (client credentials); every error carries the HTTP status and Graph's own message, never the secret
  async function token() {
    const c = cfg();
    let secret; try { secret = sealer.unseal('graph', c.secret_enc); } catch (e) { throw httpErr(503, 'the client secret cannot be opened from the vault - save it again'); }
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: c.client_id, client_secret: secret, scope: 'https://graph.microsoft.com/.default' }).toString();
    const r = await request(loginBase + '/' + encodeURIComponent(c.tenant_id) + '/oauth2/v2.0/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form, timeoutMs: 30000 });
    if (r.status >= 300 || !r.json || !r.json.access_token) throw new Error('Entra ID refused the app credentials (HTTP ' + r.status + (r.json && r.json.error ? ': ' + r.json.error : '') + ')');
    return r.json.access_token;
  }
  async function graph(bearer, method, path, payload, extra) {
    const r = await request(graphBase + path, { method, headers: Object.assign({ Authorization: 'Bearer ' + bearer, Accept: 'application/json' }, payload ? { 'Content-Type': 'application/json' } : {}, extra || {}), body: payload ? JSON.stringify(payload) : undefined, timeoutMs: 30000 });
    if (r.status === 404) return null;
    if (r.status >= 300) { const m = r.json && r.json.error ? (r.json.error.code + ': ' + String(r.json.error.message || '').slice(0, 160)) : 'HTTP ' + r.status; throw Object.assign(new Error('Graph ' + method + ' ' + path.split('?')[0] + ' - ' + m), { http: r.status }); }
    return r.json || {};
  }
  // ---- read-only: Microsoft 365 licences and app usage per user (User Inventory, engine/people-inventory.js) ----------------
  // GET only: /subscribedSkus, /users (User.Read.All), and the usage reports (Reports.Read.All) - the beta report endpoints are
  // the ones that answer in JSON. Paging follows @odata.nextLink only while it stays on Graph.
  const connected = () => { const c = cfg(); return !!(c.tenant_id && c.client_id && c.secret_enc); };
  const betaBase = (opts.graphBetaBase || graphBase.replace(/\/v1\.0$/, '/beta')).replace(/\/+$/, '');
  async function getAll(bearer, base, path, maxPages) {
    const out = []; let url = base + path, n = 0;
    while (url && n++ < (maxPages || 50)) {
      const r = await request(url, { method: 'GET', headers: { Authorization: 'Bearer ' + bearer, Accept: 'application/json' }, timeoutMs: 60000 });
      if (r.status >= 300) { const m = r.json && r.json.error ? (r.json.error.code + ': ' + String(r.json.error.message || '').slice(0, 160)) : 'HTTP ' + r.status; throw Object.assign(new Error('Graph GET ' + path.split('?')[0] + ' - ' + m), { http: r.status }); }
      const j = r.json || {}; out.push(...(j.value || []));
      const nx = j['@odata.nextLink']; url = nx && (nx.startsWith(graphBase) || nx.startsWith(betaBase)) ? nx : null;
    }
    return out;
  }
  async function userApps() {
    if (!connected()) throw httpErr(409, 'Microsoft 365 is not connected - an administrator sets the tenant, app and secret in HR Onboarding -> Microsoft 365');
    const t = await token(), errors = [];
    const perm = (e, what, p) => (e.http === 403 || /Authorization|Forbidden|Access/i.test(e.message) ? what + ': the app registration needs the ' + p + ' application permission (admin consent)' : what + ': ' + String(e.message).slice(0, 200));
    let skus = [], users = [], apps = null, act = null;
    try { skus = skuRows(await graph(t, 'GET', '/subscribedSkus')); } catch (e) { errors.push(perm(e, 'licences', 'Organization.Read.All')); }
    try { users = await getAll(t, graphBase, '/users?$select=id,userPrincipalName,mail,displayName,accountEnabled,assignedLicenses&$top=999', 50); } catch (e) { errors.push(perm(e, 'users', 'User.Read.All')); }
    try { apps = await getAll(t, betaBase, "/reports/getM365AppUserDetail(period='D30')?$format=application/json", 50); } catch (e) { errors.push(perm(e, 'app usage', 'Reports.Read.All')); }
    try { act = await getAll(t, betaBase, "/reports/getOffice365ActiveUserDetail(period='D30')?$format=application/json", 50); } catch (e) { errors.push(perm(e, 'service usage', 'Reports.Read.All')); }
    return { skus, users, apps, act, errors };
  }
  const skuRows = (j) => (j.value || []).map((s) => ({ sku_id: s.skuId, part: s.skuPartNumber, enabled: (s.prepaidUnits || {}).enabled || 0, consumed: s.consumedUnits || 0, free: ((s.prepaidUnits || {}).enabled || 0) - (s.consumedUnits || 0),
    plans: (s.servicePlans || []).map((p) => ({ id: p.servicePlanId, name: p.servicePlanName })).slice(0, 80) }));

  async function test(who) {
    let r;
    try { const t = await token(); const skus = skuRows(await graph(t, 'GET', '/subscribedSkus')); r = { ok: true, skus: skus.length }; cfgC().put(Object.assign({}, cfg(), { skus: { at: iso(), list: skus } })); }
    catch (e) { r = { ok: false, error: String(e.message).slice(0, 240) }; }
    cfgC().put(Object.assign({}, cfg(), { last_test: Object.assign({ at: iso(), by: who.user }, r) }));
    audit(who, 'onboarding.m365.test', 'm365', r);
    return Object.assign(r, { list: r.ok ? cfg().skus.list : [] });
  }

  // the licences an onboarding request gets: its approved names, else the defaults when it asked for Microsoft 365
  function wanted(r) {
    const c = cfg(), names = (r.account && r.account.licences && r.account.licences.length) ? r.account.licences : (r.m365 ? c.default_licences : []);
    return names.map((n) => c.catalogue.find((x) => low(x.name) === low(n))).filter(Boolean);
  }
  const validNames = (names) => { const c = cfg(); return (names || []).filter((n) => !c.catalogue.some((x) => low(x.name) === low(n))); };

  // one attempt for one request; returns the licensing record to store on it
  async function attempt(r, upnSuffix) {
    const L = Object.assign({ status: 'waiting', attempts: 0, since: iso() }, r.licensing || {});
    L.attempts++; L.last_try = iso();
    const lic = wanted(r);
    if (!lic.length) return Object.assign(L, { status: 'not_needed', note: 'no Microsoft 365 licence was asked for' });
    const upn = (r.account && r.account.upn) || (upnSuffix ? r.account.username + '@' + upnSuffix : null);
    if (!upn) return Object.assign(L, { status: 'failed', error: 'the sign-in name (UPN) is not known - set the UPN suffix in Directory settings' });
    L.upn = upn; L.licences = lic.map((x) => x.name);
    try {
      const t = await token();
      const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id,userPrincipalName,usageLocation,accountEnabled,assignedLicenses');
      if (!u) {
        if (now() - Date.parse(L.since) > SYNC_WAIT_MS) return Object.assign(L, { status: 'failed', error: upn + ' has not appeared in Entra ID after 48 hours - check Entra Connect sync (the OU must be in its scope)' });
        return Object.assign(L, { status: 'waiting', note: 'waiting for Entra Connect to sync ' + upn + ' to Entra ID (normally within 30 minutes)' });
      }
      L.entra_id = u.id;
      const have = new Set((u.assignedLicenses || []).map((x) => low(x.skuId)));
      const todo = lic.filter((x) => !have.has(low(x.sku_id)));
      if (!todo.length) return Object.assign(L, { status: 'assigned', at: iso(), verified: true, note: 'already licensed', error: null });
      const c = cfg();
      if (!u.usageLocation) {
        if (!c.set_usage_location) return Object.assign(L, { status: 'blocked', error: 'the user has no usage location in Entra ID and the platform is not allowed to set it - set it, or allow it in the licensing settings' });
        await graph(t, 'PATCH', '/users/' + encodeURIComponent(u.id), { usageLocation: c.usage_location });
        L.usage_location_set = c.usage_location;
      }
      const skus = skuRows(await graph(t, 'GET', '/subscribedSkus'));
      const short = todo.filter((x) => { const s = skus.find((y) => low(y.sku_id) === low(x.sku_id)); return !s || s.free < 1; });
      if (short.length) { warn('seats', 'licensing: no free seats', { licences: short.map((x) => x.name) }); return Object.assign(L, { status: 'blocked', error: 'no free seat of ' + short.map((x) => x.name).join(', ') + ' - buy more or free one, then it is retried' }); }
      await graph(t, 'POST', '/users/' + encodeURIComponent(u.id) + '/assignLicense', { addLicenses: todo.map((x) => ({ skuId: x.sku_id, disabledPlans: x.disabled_plans || [] })), removeLicenses: [] });
      const back = await graph(t, 'GET', '/users/' + encodeURIComponent(u.id) + '?$select=id,assignedLicenses');
      const now2 = new Set(((back && back.assignedLicenses) || []).map((x) => low(x.skuId)));
      const missing = lic.filter((x) => !now2.has(low(x.sku_id)));
      if (missing.length) return Object.assign(L, { status: 'failed', error: 'read back: ' + missing.map((x) => x.name).join(', ') + ' not on the user' });
      return Object.assign(L, { status: 'assigned', at: iso(), verified: true, assigned: todo.map((x) => x.name), error: null, note: null });
    } catch (e) {
      warn('assign', 'licensing: attempt failed', { err: String(e.message).slice(0, 200) });
      return Object.assign(L, { status: e.http === 403 ? 'failed' : 'retrying', error: String(e.message).slice(0, 240) + (e.http === 403 ? ' - the app registration lacks a Graph permission (see the settings)' : '') });
    }
  }
  // ---- leavers: what licences the user holds (named from the catalogue, else the SKU part number), and taking some back
  async function readUser(upn) {
    const t = await token();
    const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id,userPrincipalName,accountEnabled,assignedLicenses');
    if (!u) return { found: false };
    const skus = skuRows(await graph(t, 'GET', '/subscribedSkus')), cat = cfg().catalogue;
    const name = (id) => { const c = cat.find((x) => low(x.sku_id) === low(id)); if (c) return c.name; const s = skus.find((x) => low(x.sku_id) === low(id)); return s ? s.part : id; };
    return { found: true, entra_id: u.id, account_enabled: u.accountEnabled, licences: (u.assignedLicenses || []).map((l) => ({ sku_id: l.skuId, name: name(l.skuId) })) };
  }
  async function removeLicences(entraId, skuIds) {
    const t = await token();
    await graph(t, 'POST', '/users/' + encodeURIComponent(entraId) + '/assignLicense', { addLicenses: [], removeLicenses: skuIds });
    const back = await graph(t, 'GET', '/users/' + encodeURIComponent(entraId) + '?$select=id,assignedLicenses');
    const still = ((back && back.assignedLicenses) || []).map((x) => low(x.skuId)).filter((x) => skuIds.map(low).includes(x));
    if (still.length) throw new Error('read back: ' + still.length + ' licence(s) still on the user');
    return true;
  }
  // ---- leavers' Microsoft 365 groups and Teams: what the user owns, who else owns each, and changing an owner (read back)
  const GID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  async function pages(t, path, max, extra) {
    let out = [], p = path, n = 0;
    while (p && n++ < max) {
      const j = await graph(t, 'GET', p, null, extra); if (!j) break;
      out = out.concat(j.value || []);
      const next = j['@odata.nextLink']; p = next && next.indexOf(graphBase) === 0 ? next.slice(graphBase.length) : null;   // only Graph's own next page
    }
    return out;
  }
  async function userRef(upn) {
    const t = await token();
    const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id,userPrincipalName,accountEnabled');
    return u ? { id: u.id, upn: low(u.userPrincipalName), enabled: u.accountEnabled !== false } : null;
  }
  async function owners(t, gid) {
    return (await pages(t, '/groups/' + gid + '/owners?$select=id,userPrincipalName,accountEnabled&$top=100', 3)).map((o) => ({ id: o.id, upn: low(o.userPrincipalName), enabled: o.accountEnabled !== false }));
  }
  async function ownedGroups(upn) {
    const t = await token();
    const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id');
    if (!u) return { found: false };
    const gs = (await pages(t, '/users/' + u.id + '/ownedObjects/microsoft.graph.group?$select=id,displayName,groupTypes,resourceProvisioningOptions,mail&$top=100', 5)).filter((g) => GID.test(String(g.id))).slice(0, 200);
    const out = [];
    for (const g of gs) {
      const os = await owners(t, g.id);
      out.push({ id: g.id, name: String(g.displayName || '').slice(0, 120), team: (g.resourceProvisioningOptions || []).includes('Team'), unified: (g.groupTypes || []).includes('Unified'), mail: g.mail || null,
        owners: os.map((o) => o.upn).slice(0, 20), other_active_owners: os.filter((o) => o.id !== u.id && o.enabled).length });
    }
    return { found: true, user_id: u.id, groups: out };
  }
  const already = (e) => e.http === 400 && /already exist/i.test(e.message);
  // a team owner must also be a member, so a team gets the member first; "already exists" is not an error
  async function addOwner(gid, uid, team) {
    if (!GID.test(gid) || !GID.test(uid)) throw new Error('group and user must be ids');
    const t = await token(), ref = { '@odata.id': graphBase + '/directoryObjects/' + uid };
    if (team) { try { await graph(t, 'POST', '/groups/' + gid + '/members/$ref', ref); } catch (e) { if (!already(e)) throw e; } }
    try { await graph(t, 'POST', '/groups/' + gid + '/owners/$ref', ref); } catch (e) { if (!already(e)) throw e; }
    if (!(await owners(t, gid)).some((o) => o.id === uid)) throw new Error('read back: not an owner yet');
    return true;
  }
  async function removeOwner(gid, uid) {
    if (!GID.test(gid) || !GID.test(uid)) throw new Error('group and user must be ids');
    const t = await token();
    const os = await owners(t, gid);
    if (!os.some((o) => o.id !== uid && o.enabled)) throw new Error('refused: it would leave the group without an active owner');
    await graph(t, 'DELETE', '/groups/' + gid + '/owners/' + uid + '/$ref');
    if ((await owners(t, gid)).some((o) => o.id === uid)) throw new Error('read back: still an owner');
    return true;
  }
  // ---- leavers' meetings: Exchange cannot change an organiser, so a meeting is created again from the new owner's calendar
  // (same subject, agenda, attendees, place, repeat pattern from the next occurrence, a new Teams link when it was online) and
  // the leaver's one is ended: a series stops yesterday (past occurrences stay in everyone's calendar), a single one is cancelled
  const EVSEL = 'id,subject,type,isOrganizer,isCancelled,start,end,recurrence,attendees,isOnlineMeeting,onlineMeetingProvider,location,sensitivity,originalStartTimeZone,organizer';
  const tzH = (tz) => ({ Prefer: 'outlook.timezone="' + String(tz || 'UTC').replace(/[^A-Za-z0-9 _/+().-]/g, '') + '"' });
  const asUtc = (dt) => Date.parse(String(dt || '').replace(/(\.\d{3})\d*$/, '$1') + (/[zZ]|[+-]\d\d:\d\d$/.test(String(dt)) ? '' : 'Z'));
  async function orgDomains(t) { const o = await graph(t, 'GET', '/organization?$select=verifiedDomains'); return (((o && o.value && o.value[0]) || {}).verifiedDomains || []).map((d) => low(d.name)); }
  async function seriesInstances(t, upn, ev, from, to) {
    const tz = ev.originalStartTimeZone || 'UTC';
    const list = await pages(t, '/users/' + encodeURIComponent(upn) + '/events/' + encodeURIComponent(ev.id) + '/instances?startDateTime=' + encodeURIComponent(from) + '&endDateTime=' + encodeURIComponent(to) + '&$select=id,start,end,isCancelled&$top=200', 5);
    return { tz, list: list.filter((i) => !i.isCancelled) };
  }
  async function organizedMeetings(upn, days) {
    const t = await token();
    const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id');
    if (!u) return { found: false };
    const from = new Date(now()).toISOString(), to = new Date(now() + (days || calendarDays()) * 86400000).toISOString();
    const dom = await orgDomains(t);
    const evs = (await pages(t, '/users/' + encodeURIComponent(upn) + '/events?$select=' + EVSEL + '&$top=100', 20)).filter((e) => e.isOrganizer && !e.isCancelled && (e.attendees || []).length);
    const out = [];
    for (const e of evs.slice(0, 1000)) {
      const att = (e.attendees || []).map((a) => low(a.emailAddress && a.emailAddress.address)).filter(Boolean);
      const base = { id: e.id, subject: String(e.subject || '(no subject)').slice(0, 160), recurring: e.type === 'seriesMaster', attendees: att.length, external: dom.length ? att.filter((a) => !dom.some((d) => a.endsWith('@' + d) || a.endsWith('.' + d))).length : null,
        online: !!e.isOnlineMeeting, private: e.sensitivity === 'private' || e.sensitivity === 'confidential' };
      if (e.type === 'seriesMaster') {
        const s = await seriesInstances(t, upn, e, from, to);
        if (!s.list.length) continue;
        out.push(Object.assign(base, { next_start: s.list[0].start.dateTime, next_tz: s.list[0].start.timeZone || 'UTC', remaining: s.list.length, pattern: (e.recurrence && e.recurrence.pattern && e.recurrence.pattern.type) || null }));
      } else if (e.type === 'singleInstance') {
        const st = asUtc(e.start && e.start.dateTime), en = asUtc(e.end && e.end.dateTime);
        if (!(en >= now() && st <= Date.parse(to))) continue;
        out.push(Object.assign(base, { next_start: e.start.dateTime, next_tz: e.start.timeZone || 'UTC', remaining: 1 }));
      }
    }
    out.sort((a, b) => String(a.next_start).localeCompare(String(b.next_start)));
    return { found: true, user_id: u.id, meetings: out.slice(0, 300), window_days: days || calendarDays(), domains_known: !!dom.length };
  }
  // the new meeting: read the original again (its agenda is not stored on the platform), then create it as the new owner;
  // transactionId makes a retry return the meeting already created instead of sending a second invitation
  async function recreateMeeting(fromUpn, eventId, owner, opts2) {
    const t = await token();
    const e = await graph(t, 'GET', '/users/' + encodeURIComponent(fromUpn) + '/events/' + encodeURIComponent(eventId) + '?$select=' + EVSEL + ',body,allowNewTimeProposals', null, tzH('UTC'));
    if (!e) throw new Error('the meeting is no longer in the leaver\'s calendar');
    const skip = [low(fromUpn), low(owner)];
    const attendees = (e.attendees || []).filter((a) => a.emailAddress && a.emailAddress.address && !skip.includes(low(a.emailAddress.address))).map((a) => ({ emailAddress: { address: a.emailAddress.address, name: a.emailAddress.name || undefined }, type: a.type || 'required' }));
    const ev = { subject: e.subject || '(no subject)', body: { contentType: 'HTML', content: opts2.note + ((e.body && e.body.content) || '') }, attendees, location: e.location && e.location.displayName ? { displayName: e.location.displayName } : undefined,
      isOnlineMeeting: !!e.isOnlineMeeting, onlineMeetingProvider: e.isOnlineMeeting ? (e.onlineMeetingProvider || 'teamsForBusiness') : undefined, allowNewTimeProposals: e.allowNewTimeProposals !== false, sensitivity: e.sensitivity || 'normal', transactionId: opts2.transactionId };
    if (e.type === 'seriesMaster') {
      const native = await graph(t, 'GET', '/users/' + encodeURIComponent(fromUpn) + '/events/' + encodeURIComponent(eventId) + '?$select=id,originalStartTimeZone,recurrence,start,end');
      const tz = native.originalStartTimeZone || (native.start && native.start.timeZone) || 'UTC';
      const from = new Date(now()).toISOString(), to = new Date(now() + 730 * 86400000).toISOString();
      const inst = (await pages(t, '/users/' + encodeURIComponent(fromUpn) + '/events/' + encodeURIComponent(eventId) + '/instances?startDateTime=' + encodeURIComponent(from) + '&endDateTime=' + encodeURIComponent(to) + '&$select=id,start,end,isCancelled&$top=200', 10, tzH(tz))).filter((i) => !i.isCancelled);
      if (!inst.length) throw new Error('the series has no occurrence left');
      const first = inst[0], r0 = native.recurrence.range || {};
      ev.start = { dateTime: first.start.dateTime, timeZone: tz }; ev.end = { dateTime: first.end.dateTime, timeZone: tz };
      ev.recurrence = { pattern: native.recurrence.pattern, range: Object.assign({ type: r0.type === 'numbered' ? 'numbered' : r0.type === 'endDate' ? 'endDate' : 'noEnd', startDate: String(first.start.dateTime).slice(0, 10), recurrenceTimeZone: r0.recurrenceTimeZone || tz },
        r0.type === 'endDate' ? { endDate: r0.endDate } : r0.type === 'numbered' ? { numberOfOccurrences: inst.length } : {}) };
    } else { ev.start = { dateTime: e.start.dateTime, timeZone: 'UTC' }; ev.end = { dateTime: e.end.dateTime, timeZone: 'UTC' }; }
    const made = await graph(t, 'POST', '/users/' + encodeURIComponent(owner) + '/events', ev);
    if (!made || !made.id) throw new Error('the new meeting was not created');
    const back = await graph(t, 'GET', '/users/' + encodeURIComponent(owner) + '/events/' + encodeURIComponent(made.id) + '?$select=id,subject,isOrganizer');
    if (!back) throw new Error('read back: the new meeting is not in ' + owner + "'s calendar");
    return { id: made.id, recurring: e.type === 'seriesMaster', online: !!made.isOnlineMeeting };
  }
  // end the leaver's meeting: a series with past occurrences stops yesterday (the past stays), anything else is cancelled
  async function retireMeeting(upn, eventId, comment) {
    const t = await token(), path = '/users/' + encodeURIComponent(upn) + '/events/' + encodeURIComponent(eventId);
    const e = await graph(t, 'GET', path + '?$select=id,type,isCancelled,recurrence,start,originalStartTimeZone');
    if (!e || e.isCancelled) return { done: 'already gone' };
    const today = new Date(now()).toISOString().slice(0, 10), yesterday = new Date(now() - 86400000).toISOString().slice(0, 10);
    const r0 = (e.recurrence && e.recurrence.range) || {};
    if (e.type === 'seriesMaster' && r0.startDate && r0.startDate < today) {
      await graph(t, 'PATCH', path, { recurrence: { pattern: e.recurrence.pattern, range: { type: 'endDate', startDate: r0.startDate, endDate: yesterday, recurrenceTimeZone: r0.recurrenceTimeZone || e.originalStartTimeZone || 'UTC' } } });
      const b = await graph(t, 'GET', path + '?$select=id,recurrence');
      if (!b || !b.recurrence || b.recurrence.range.endDate !== yesterday) throw new Error('read back: the series still runs past ' + yesterday);
      return { done: 'series ended ' + yesterday };
    }
    await graph(t, 'POST', path + '/cancel', { comment: String(comment || '').slice(0, 1000) });
    const b = await graph(t, 'GET', path + '?$select=id,isCancelled');
    if (b && !b.isCancelled) throw new Error('read back: the meeting is not cancelled');
    return { done: 'cancelled' };
  }
  // ---- legal hold: Microsoft Purview eDiscovery (the content stays in Microsoft 365; only ids, counts and sizes come back)
  const CASES = '/security/cases/ediscoveryCases';
  const cid = (x) => encodeURIComponent(String(x || ''));
  async function ediscovery(op, a) {
    const t = await token();
    switch (op) {
      case 'case-get': { const c = await graph(t, 'GET', CASES + '/' + cid(a.caseId) + '?$select=id,displayName,status'); return c ? { id: c.id, name: c.displayName, status: c.status } : null; }
      case 'case-create': { const c = await graph(t, 'POST', CASES, { displayName: a.name, description: a.description, externalId: a.externalId || undefined }); if (!c || !c.id) throw new Error('the eDiscovery case was not created'); return { id: c.id, name: c.displayName }; }
      case 'custodian': {   // the existing custodian is reused (a person is one custodian per case)
        const list = await graph(t, 'GET', CASES + '/' + cid(a.caseId) + '/custodians?$select=id,email,status,holdStatus');
        const have = ((list && list.value) || []).find((x) => low(x.email) === low(a.upn));
        if (have) return { id: have.id, existing: true };
        const c = await graph(t, 'POST', CASES + '/' + cid(a.caseId) + '/custodians', { email: a.upn });
        if (!c || !c.id) throw new Error('the custodian was not added'); return { id: c.id };
      }
      case 'user-source': {
        const base = CASES + '/' + cid(a.caseId) + '/custodians/' + cid(a.custodianId) + '/userSources';
        const list = await graph(t, 'GET', base + '?$select=id,email,includedSources');
        const have = ((list && list.value) || []).find((x) => low(x.email) === low(a.upn));
        if (have) return { id: have.id, existing: true, included: have.includedSources };
        const u = await graph(t, 'POST', base, { email: a.upn, includedSources: 'mailbox,site' });
        if (!u || !u.id) throw new Error('the mailbox and OneDrive were not added to the custodian'); return { id: u.id, included: u.includedSources };
      }
      case 'apply-hold': await graph(t, 'POST', CASES + '/' + cid(a.caseId) + '/custodians/' + cid(a.custodianId) + '/applyHold', {}); return true;
      case 'remove-hold': await graph(t, 'POST', CASES + '/' + cid(a.caseId) + '/custodians/' + cid(a.custodianId) + '/removeHold', {}); return true;
      case 'hold-status': { const c = await graph(t, 'GET', CASES + '/' + cid(a.caseId) + '/custodians/' + cid(a.custodianId) + '?$select=id,holdStatus'); return c ? String(c.holdStatus || '') : null; }
      case 'search-create': {
        const sr = await graph(t, 'POST', CASES + '/' + cid(a.caseId) + '/searches', { displayName: a.name, description: a.description, contentQuery: a.query || '' });
        if (!sr || !sr.id) throw new Error('the search was not created');
        await graph(t, 'POST', CASES + '/' + cid(a.caseId) + '/searches/' + cid(sr.id) + '/custodianSources/$ref', { '@odata.id': graphBase + CASES + '/' + a.caseId + '/custodians/' + a.custodianId + '/userSources/' + a.sourceId });
        return { id: sr.id };
      }
      case 'estimate': await graph(t, 'POST', CASES + '/' + cid(a.caseId) + '/searches/' + cid(a.searchId) + '/estimateStatistics', {}); return true;
      case 'estimate-result': {
        const o = await graph(t, 'GET', CASES + '/' + cid(a.caseId) + '/searches/' + cid(a.searchId) + '/lastEstimateStatisticsOperation');
        if (!o) return null;
        return { status: o.status, items: o.indexedItemCount || 0, bytes: o.indexedItemsSize || 0, unindexed: o.unindexedItemCount || 0, unindexed_bytes: o.unindexedItemsSize || 0, mailboxes: o.mailboxCount || 0, sites: o.siteCount || 0 };
      }
      case 'export': await graph(t, 'POST', CASES + '/' + cid(a.caseId) + '/searches/' + cid(a.searchId) + '/exportResult', { displayName: a.name, description: a.description, exportCriteria: 'searchHits,partiallyIndexed', exportFormat: 'pst', exportLocation: 'responsiveLocations', additionalOptions: 'none' }); return true;
      case 'export-status': {   // the newest export operation of the case started after `since`; file names and sizes only - never the download links
        const ops = await graph(t, 'GET', CASES + '/' + cid(a.caseId) + '/operations');
        const o = ((ops && ops.value) || []).filter((x) => /export/i.test(String(x.action || '')) && Date.parse(x.createdDateTime || 0) >= Date.parse(a.since) - 60000).sort((x, y) => String(y.createdDateTime).localeCompare(String(x.createdDateTime)))[0];
        if (!o) return null;
        return { id: o.id, status: o.status, progress: o.percentProgress || 0, files: (o.exportFileMetadata || []).map((f) => ({ name: String(f.fileName || '').slice(0, 200), size: f.size || 0 })).slice(0, 50) };
      }
    }
    throw new Error('unknown eDiscovery operation');
  }
  // ---- leavers' Intune devices: list, read back, and the two actions a person may approve (wipe = factory reset, retire =
  // remove company data only); nothing else is sent
  const DEVSEL = 'id,deviceName,operatingSystem,osVersion,serialNumber,managedDeviceOwnerType,userPrincipalName,lastSyncDateTime,complianceState,model,manufacturer,managementState';
  const devRow = (d) => ({ id: d.id, name: String(d.deviceName || '').slice(0, 120), os: String(d.operatingSystem || '').slice(0, 40), os_version: String(d.osVersion || '').slice(0, 40), serial: String(d.serialNumber || '').slice(0, 80),
    owner_type: String(d.managedDeviceOwnerType || 'unknown').toLowerCase(), upn: low(d.userPrincipalName), last_sync: d.lastSyncDateTime || null, compliance: d.complianceState || null,
    model: [d.manufacturer, d.model].filter(Boolean).join(' ').slice(0, 120), state: d.managementState || null });
  async function userDevices(upn) {
    const t = await token();
    const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id');
    if (!u) return { found: false };
    return { found: true, devices: (await pages(t, '/users/' + u.id + '/managedDevices?$select=' + DEVSEL + '&$top=100', 5)).map(devRow).slice(0, 100) };
  }
  async function deviceGet(id) {
    if (!GID.test(String(id))) throw new Error('device id must be an Intune device id');
    const t = await token();
    const d = await graph(t, 'GET', '/deviceManagement/managedDevices/' + id + '?$select=' + DEVSEL + ',deviceActionResults');
    if (!d) return null;
    return Object.assign(devRow(d), { actions: (d.deviceActionResults || []).map((a) => ({ name: String(a.actionName || '').toLowerCase(), state: String(a.actionState || '').toLowerCase(), started: a.startDateTime || null, updated: a.lastUpdatedDateTime || null })) });
  }
  async function deviceAction(id, action) {
    if (!GID.test(String(id))) throw new Error('device id must be an Intune device id');
    if (!['wipe', 'retire'].includes(action)) throw new Error('only wipe or retire');
    const t = await token();
    await graph(t, 'POST', '/deviceManagement/managedDevices/' + id + '/' + action, action === 'wipe' ? { keepEnrollmentData: false, keepUserData: false } : undefined);
    return true;
  }
  // ---- leavers' Entra ID enterprise applications: the user's own (direct) assignments to one application, removed and read back
  async function servicePrincipal(spId) {
    if (!GID.test(String(spId))) throw new Error('the application must be its service principal (object) id');
    const t = await token();
    const sp = await graph(t, 'GET', '/servicePrincipals/' + spId + '?$select=id,displayName,appId');
    return sp ? { id: sp.id, name: String(sp.displayName || '').slice(0, 120), app_id: sp.appId } : null;
  }
  async function appAssignments(upn, spId) {
    const t = await token();
    const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id');
    if (!u) return { found: false };
    const all = await pages(t, '/users/' + u.id + '/appRoleAssignments?$top=100', 10);
    return { found: true, user_id: u.id, assignments: all.filter((a) => String(a.resourceId) === String(spId)).map((a) => ({ id: a.id, role_id: a.appRoleId, resource: a.resourceDisplayName || null })) };
  }
  async function removeAppAssignment(userId, assignmentId) {
    if (!GID.test(String(userId))) throw new Error('user id must be an Entra ID object id');
    if (!/^[A-Za-z0-9_-]{8,80}$/.test(String(assignmentId))) throw new Error('assignment id is not valid');
    const t = await token();
    await graph(t, 'DELETE', '/users/' + userId + '/appRoleAssignments/' + encodeURIComponent(assignmentId));
    const left = (await pages(t, '/users/' + userId + '/appRoleAssignments?$top=100', 10)).filter((a) => a.id === assignmentId);
    if (left.length) throw new Error('read back: the assignment is still there');
    return true;
  }
  async function revokeSessions(upn) {
    const t = await token();
    const u = await graph(t, 'GET', '/users/' + encodeURIComponent(upn) + '?$select=id');
    if (!u) return false;
    await graph(t, 'POST', '/users/' + u.id + '/revokeSignInSessions', {});
    return true;
  }
  return { view, configure, test, connected, userApps, enabled, reclaimEnabled, teamsEnabled, legalEnabled, ediscovery, devicesEnabled, appsEnabled, servicePrincipal, appAssignments, removeAppAssignment, revokeSessions, userDevices, deviceGet, deviceAction, calendarEnabled, calendarDays, organizedMeetings, recreateMeeting, retireMeeting, userRef, ownedGroups, addOwner, removeOwner, holdDays: () => cfg().reclaim_hold_days, attempt, wanted, validNames, readUser, removeLicences };
}

function registerM365LicensingRoutes(srv, app, X) {
  const human = (ctx) => { if (/^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(ctx.who.user || ''))) throw httpErr(403, 'a person does this'); };
  srv.route('GET', '/onboarding/m365', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('POST', '/onboarding/m365', (ctx) => { ctx.need('admin'); return X.configure(ctx.body, ctx.who); });
  srv.route('POST', '/onboarding/m365/test', (ctx) => { ctx.need('admin'); human(ctx); body(ctx.body).done(); return X.test(ctx.who); });
}

module.exports = { createM365Licensing, registerM365LicensingRoutes };
