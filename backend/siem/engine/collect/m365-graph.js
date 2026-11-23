// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
// Microsoft 365 inventory + posture from Microsoft Graph (v1.0) for the portal's Microsoft 365, Users, Intune and
// M365 Security pages. Same Entra ID app registration as the Exchange Online audit pull (secrets.m365: tenant,
// client_id, client_secret or certificate) - token scope https://graph.microsoft.com/.default, client credentials.
// Each block is fetched independently, so a permission that has not been granted only blanks that block:
//   licenses          GET /subscribedSkus (+ /directory/subscriptions for renewal dates)  LicenseManagement.Read.All or Organization.Read.All
//   users             GET /users                                                          User.Read.All
//   signins           GET /auditLogs/signIns                                              AuditLog.Read.All (+ Entra ID P1)
//   intune            GET /deviceManagement/managedDevices                                DeviceManagementManagedDevices.Read.All
//   serviceHealth     GET /admin/serviceAnnouncement/healthOverviews + /issues            ServiceHealth.Read.All
//   security.secureScore        /security/secureScores                                    SecurityEvents.Read.All
//   security.mfa                /reports/authenticationMethods/userRegistrationDetails    UserAuthenticationMethod.Read.All + AuditLog.Read.All
//   security.riskyUsers         /identityProtection/riskyUsers                            IdentityRiskyUser.Read.All
//   security.riskDetections     /identityProtection/riskDetections                        IdentityRiskEvent.Read.All
//   security.conditionalAccess  /identity/conditionalAccess/policies                      Policy.Read.All
//   security.defenderAlerts     /security/alerts_v2                                       SecurityAlert.Read.All
//   apps              GET /applications (+ owners): app registrations and the END DATES of their secrets / certificates - Graph
//                     never returns a secret value, and only the dates, names and permission counts are kept   Application.Read.All
// The result has the shape the portal's pullM365() reads from /api/m365 (configured, updated, licenses[], users.list[],
// signins[], signinsOk, intune[], intuneOk, serviceHealth, security). Kept in memory and in <state_dir>/m365-graph.json.
// config.json "m365": { "graph": true, "graph_poll_s": 900 }   (graph defaults to on once the credentials are saved)
const fs = require('node:fs');
const path = require('node:path');
const { makeAssertion } = require('./m365');

const GRAPH = 'https://graph.microsoft.com/v1.0';
const PERMS = {
  licenses: 'LicenseManagement.Read.All', users: 'User.Read.All', signins: 'AuditLog.Read.All', intune: 'DeviceManagementManagedDevices.Read.All',
  serviceHealth: 'ServiceHealth.Read.All', secureScore: 'SecurityEvents.Read.All', mfa: 'UserAuthenticationMethod.Read.All + AuditLog.Read.All',
  riskyUsers: 'IdentityRiskyUser.Read.All', riskDetections: 'IdentityRiskEvent.Read.All', conditionalAccess: 'Policy.Read.All', defenderAlerts: 'SecurityAlert.Read.All',
  apps: 'Application.Read.All',
};
const ADMIN_ROLES = /admin/i;

function credsOf(config) {
  const mc = Object.assign({}, require('../config').DEFAULTS.m365 || {}, config.m365 || {});
  const sec = (config.secrets && config.secrets.m365) || {};
  const tenant = String(sec.tenant || mc.tenant || ''), clientId = String(sec.client_id || mc.client_id || '');
  let certPem = sec.cert_pem || '', keyPem = sec.key_pem || '';
  try { if (!certPem && sec.cert_file) certPem = fs.readFileSync(sec.cert_file, 'utf8'); if (!keyPem && sec.key_file) keyPem = fs.readFileSync(sec.key_file, 'utf8'); } catch { certPem = keyPem = ''; }
  const errs = [];
  if (!/^[0-9a-f-]{36}$/i.test(tenant) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(tenant)) errs.push('tenant ID missing');
  if (!/^[0-9a-f-]{36}$/i.test(clientId)) errs.push('application (client) ID missing');
  if (!(certPem && keyPem) && !sec.client_secret) errs.push('client secret missing');
  return { mc, tenant, clientId, secret: sec.client_secret || '', certPem, keyPem, passphrase: sec.key_passphrase, authority: String(mc.authority || 'https://login.microsoftonline.com').replace(/\/+$/, ''), errs };
}

function createGraph({ config = {}, log, stateDir, fetchImpl, now = Date.now } = {}) {
  const lg = log || { info() {}, warn() {}, error() {} };
  const doFetch = fetchImpl || ((...a) => fetch(...a));
  const file = stateDir ? path.join(stateDir, 'm365-graph.json') : '';
  let snap = null; try { if (file) snap = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { snap = null; }
  const st = { polls: 0, last_poll_at: null, last_error: '', running: false };
  let timer = null, stopped = false, running = null, token = null, tokenExp = 0, tokenKey = '';

  async function getToken(c) {
    const key = c.tenant + '|' + c.clientId + '|' + (c.secret ? c.secret.length : 'cert');
    if (token && key === tokenKey && now() < tokenExp - 300000) return token;
    const url = `${c.authority}/${c.tenant}/oauth2/v2.0/token`, form = new URLSearchParams({ grant_type: 'client_credentials', client_id: c.clientId, scope: 'https://graph.microsoft.com/.default' });
    if (c.certPem && c.keyPem) { form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'); form.set('client_assertion', makeAssertion({ tenant: c.tenant, clientId: c.clientId, certPem: c.certPem, keyPem: c.keyPem, passphrase: c.passphrase, authority: c.authority, nowMs: now() })); }
    else form.set('client_secret', c.secret);
    const res = await doFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString(), signal: AbortSignal.timeout(30000) });
    let j = {}; try { j = await res.json(); } catch { j = {}; }
    if (!res.ok || !j.access_token) throw new Error(`sign-in to Microsoft failed: HTTP ${res.status} ${j.error || ''} ${String(j.error_description || '').split('\n')[0].slice(0, 200)}`.trim());
    token = j.access_token; tokenKey = key; tokenExp = now() + (Number(j.expires_in) || 3599) * 1000;
    // the application permissions Microsoft actually granted are the token's own "roles" claim - read for the auto-configuration
    // page (m365-autoconfig.js); only the permission names are kept, the token is never stored or logged
    try { const pl = JSON.parse(Buffer.from(String(token).split('.')[1] || '', 'base64url').toString('utf8')); st.granted = { roles: Array.isArray(pl.roles) ? pl.roles.map(String).slice(0, 200).sort() : [], at: now() }; }
    catch (e) { st.granted = { roles: null, at: now(), note: 'the token could not be read for its permissions' }; /* opaque token: fall back to what each dataset answered */ }
    return token;
  }
  async function get(c, u, pages = 1) {
    let url = u.startsWith('http') ? u : GRAPH + u, out = [];
    for (let p = 0; p < pages && url; p++) {
      const res = await doFetch(url, { headers: { Authorization: `Bearer ${await getToken(c)}`, Accept: 'application/json', ConsistencyLevel: 'eventual' }, signal: AbortSignal.timeout(60000) });
      let j = {}; try { j = await res.json(); } catch { j = {}; }
      if (res.status === 401) token = null;   // revoked / expired before its time: sign in again next time
      if (!res.ok) {
        // Graph answers {error:{code,message}}; the token endpoint (and some proxies) answer {error:'string', error_description}
        const msg = typeof j.error === 'string' ? (j.error + ': ' + String(j.error_description || '').split('\n')[0].slice(0, 200))
          : (j.error && ((j.error.code || 'error') + ': ' + String(j.error.message || '').slice(0, 200)));
        const e = new Error(msg ? `HTTP ${res.status} ${msg}` : `HTTP ${res.status}`); e.status = res.status; throw e;
      }
      if (!Array.isArray(j.value)) return j;
      out = out.concat(j.value); url = j['@odata.nextLink'] || '';
      if (!url.startsWith(GRAPH)) url = '';   // never follow a link off Graph with the token
    }
    return out;
  }
  const block = async (perm, fn) => { try { return { ok: true, data: await fn() }; } catch (e) { return { ok: false, perm, error: e.status === 403 ? 'permission not granted' : e.message }; } };

  async function syncNow() {
    if (running) return running;
    running = (async () => {
      const c = credsOf(config);
      st.polls++; st.last_poll_at = new Date(now()).toISOString(); st.running = true;
      try {
        if (c.errs.length) throw new Error(c.errs.join('; '));
        await getToken(c);
        const day = 86400000, t = now();
        const APPSEL = '/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess&$top=999';
        const [lic, subs, usr, sig, intu, hov, iss, ss, mfa, ru, rd, ca, da, apps] = await Promise.all([
          block(PERMS.licenses, () => get(c, '/subscribedSkus')),
          block(PERMS.licenses, () => get(c, '/directory/subscriptions')),
          // signInActivity (last sign-in, for the licence audit) needs AuditLog.Read.All + Entra ID P1; without it ask again without it
          block(PERMS.users, () => get(c, '/users?$select=displayName,userPrincipalName,department,accountEnabled,assignedLicenses,signInActivity,userType,createdDateTime&$top=999', 20)
            .catch(() => get(c, '/users?$select=displayName,userPrincipalName,department,accountEnabled,assignedLicenses,userType,createdDateTime&$top=999', 20))),
          block(PERMS.signins, () => get(c, '/auditLogs/signIns?$top=200')),
          block(PERMS.intune, () => get(c, '/deviceManagement/managedDevices?$select=deviceName,userDisplayName,userPrincipalName,operatingSystem,osVersion,serialNumber,complianceState,lastSyncDateTime&$top=999', 10)),
          block(PERMS.serviceHealth, () => get(c, '/admin/serviceAnnouncement/healthOverviews')),
          block(PERMS.serviceHealth, () => get(c, '/admin/serviceAnnouncement/issues?$top=50&$orderby=startDateTime desc')),
          block(PERMS.secureScore, () => get(c, '/security/secureScores?$top=1')),
          block(PERMS.mfa, () => get(c, '/reports/authenticationMethods/userRegistrationDetails?$top=999', 20)),
          block(PERMS.riskyUsers, () => get(c, "/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'&$top=200")),
          block(PERMS.riskDetections, () => get(c, '/identityProtection/riskDetections?$top=50&$orderby=detectedDateTime desc')),
          block(PERMS.conditionalAccess, () => get(c, '/identity/conditionalAccess/policies')),
          block(PERMS.defenderAlerts, () => get(c, '/security/alerts_v2?$top=50&$orderby=createdDateTime desc')),
          block(PERMS.apps, () => get(c, APPSEL + '&$expand=owners($select=userPrincipalName)', 5).catch(() => get(c, APPSEL, 5))),
        ]);
        const renew = {};
        if (subs.ok) for (const s of subs.data) { if (s.skuPartNumber && s.nextLifecycleDateTime) { const d = s.nextLifecycleDateTime; if (!renew[s.skuPartNumber] || d < renew[s.skuPartNumber]) renew[s.skuPartNumber] = d; } }
        const out = { configured: true, source: 'siem-graph', updated: new Date(t).toISOString(), blocks: {} };
        const mark = (k, b) => { out.blocks[k] = b.ok ? { ok: true } : { ok: false, perm: b.perm, error: b.error }; };
        mark('licenses', lic); mark('users', usr); mark('signins', sig); mark('intune', intu); mark('serviceHealth', hov);
        mark('apps', apps);
        if (apps.ok) out.apps = apps.data.map((a) => {
          const perms = [].concat(a.requiredResourceAccess || []).reduce((o, r) => { for (const x of r.resourceAccess || []) o[x.type === 'Role' ? 'application' : 'delegated']++; return o; }, { application: 0, delegated: 0 });
          return { id: a.id, app_id: a.appId, name: a.displayName || '', created: a.createdDateTime || null, audience: a.signInAudience || '',
            owners: Array.isArray(a.owners) ? a.owners.map((o) => o.userPrincipalName).filter(Boolean) : null,
            secrets: [].concat(a.passwordCredentials || []).map((k) => ({ name: k.displayName || '', start: k.startDateTime || null, end: k.endDateTime || null })),
            certs: [].concat(a.keyCredentials || []).map((k) => ({ name: k.displayName || '', type: k.type || '', start: k.startDateTime || null, end: k.endDateTime || null })),
            app_permissions: perms.application, delegated_permissions: perms.delegated };
        });
        if (lic.ok) out.licenses = lic.data.filter((l) => l.capabilityStatus !== 'Deleted').map((l) => { const total = (l.prepaidUnits && l.prepaidUnits.enabled) || 0, r = renew[l.skuPartNumber]; return { sku: l.skuPartNumber, total, consumed: l.consumedUnits || 0, free: total >= 10000, renews: r ? r.slice(0, 10) : undefined, days: r ? Math.round((Date.parse(r) - t) / day) : undefined }; });
        const skuName = {}; if (lic.ok) for (const l of lic.data) if (l.skuId) skuName[l.skuId] = l.skuPartNumber;
        if (usr.ok) out.users = { total: usr.data.length, list: usr.data.map((u) => { const si = u.signInActivity || null; const last = si ? [si.lastSignInDateTime, si.lastNonInteractiveSignInDateTime].filter(Boolean).sort().pop() || null : undefined; return { name: u.displayName || '', upn: u.userPrincipalName || '', dept: u.department || '', lic: (u.assignedLicenses || []).length, skus: (u.assignedLicenses || []).map((a) => skuName[a.skuId] || a.skuId), enabled: u.accountEnabled !== false, guest: u.userType === 'Guest', created: u.createdDateTime || null, last }; }) };
        out.signinsOk = sig.ok; out.signins = sig.ok ? sig.data.map((x) => ({ time: x.createdDateTime, user: x.userDisplayName || '', upn: x.userPrincipalName || '', app: x.appDisplayName || '', ip: x.ipAddress || '', status: x.status && x.status.errorCode ? 'Failed' : 'Success', reason: (x.status && x.status.failureReason) || '', location: [x.location && x.location.city, x.location && x.location.countryOrRegion].filter(Boolean).join(', ') })) : [];
        out.intuneOk = intu.ok; out.intune = intu.ok ? intu.data.map((d) => ({ name: d.deviceName || '', user: d.userDisplayName || d.userPrincipalName || '', upn: d.userPrincipalName || '', os: [d.operatingSystem, d.osVersion].filter(Boolean).join(' '), serial: d.serialNumber || '', compliance: d.complianceState || '', lastSync: d.lastSyncDateTime || null, reasons: [] })) : [];
        out.serviceHealth = hov.ok ? { ok: true, updated: out.updated, services: hov.data.map((h) => ({ service: h.service, status: h.status })), issues: iss.ok ? iss.data.map((i) => ({ service: i.service, classification: i.classification, title: i.title || '', start: i.startDateTime, isResolved: !!i.isResolved })) : [] } : { ok: false, perm: PERMS.serviceHealth, error: hov.error };
        const sec = out.security = { updated: out.updated };
        sec.secureScore = ss.ok ? (ss.data[0] ? { ok: true, data: { current: ss.data[0].currentScore, max: ss.data[0].maxScore, lowest: (ss.data[0].controlScores || []).slice().sort((a, b) => (a.score || 0) - (b.score || 0)).slice(0, 10).map((x) => ({ name: x.controlName, cat: x.controlCategory, score: x.score })) } } : { ok: false, perm: PERMS.secureScore, error: 'no secure score yet' }) : ss;
        if (mfa.ok) { const people = mfa.data.filter((u) => u.userType !== 'guest'), not = people.filter((u) => !u.isMfaRegistered); sec.mfa = { ok: true, data: { users: people.length, registered: people.length - not.length, notRegistered: not.slice(0, 500).map((u) => ({ name: u.userDisplayName || '', upn: u.userPrincipalName || '', admin: !!u.isAdmin || ADMIN_ROLES.test(String(u.userRoles || '')) })) } }; } else sec.mfa = mfa;
        sec.riskyUsers = ru.ok ? { ok: true, data: ru.data.map((u) => ({ name: u.userDisplayName || '', upn: u.userPrincipalName || '', level: u.riskLevel, state: u.riskState, updated: u.riskLastUpdatedDateTime })) } : ru;
        sec.riskDetections = rd.ok ? { ok: true, data: rd.data.map((d) => ({ when: d.detectedDateTime, upn: d.userPrincipalName || '', type: d.riskEventType || '', level: d.riskLevel, state: d.riskState, ip: d.ipAddress || '', city: d.location && d.location.city, country: d.location && d.location.countryOrRegion })) } : rd;
        sec.conditionalAccess = ca.ok ? { ok: true, data: ca.data.map((p) => ({ name: p.displayName || '', state: p.state, modified: p.modifiedDateTime || p.createdDateTime })) } : ca;
        sec.defenderAlerts = da.ok ? { ok: true, data: da.data.map((a) => ({ created: a.createdDateTime, title: a.title || '', category: a.category || '', severity: a.severity, status: a.status, product: a.serviceSource || a.detectionSource || '', user: ((a.evidence || []).find((e) => e.userAccount) || { userAccount: {} }).userAccount.userPrincipalName || '' })) } : da;
        ['secureScore', 'mfa', 'riskyUsers', 'riskDetections', 'conditionalAccess', 'defenderAlerts'].forEach((k) => { const b = sec[k]; out.blocks[k] = b.ok ? { ok: true } : { ok: false, perm: b.perm || PERMS[k], error: b.error }; });
        // nothing answered (token refused by Graph, outage, network): a failed sync, not an empty tenant - keep the last good copy
        const okBlocks = Object.values(out.blocks).filter((b) => b.ok).length;
        if (!okBlocks) throw new Error('Microsoft Graph answered no request: ' + (Object.values(out.blocks).map((b) => b.error).find(Boolean) || 'unknown error'));
        // a part that failed for another reason than a missing permission keeps its last good data, marked with its age
        if (snap) {
          const carry = { licenses: ['licenses'], users: ['users'], signins: ['signins', 'signinsOk'], intune: ['intune', 'intuneOk'], serviceHealth: ['serviceHealth'], apps: ['apps'] };
          for (const [k, fields] of Object.entries(carry)) {
            const b = out.blocks[k];
            if (b && !b.ok && b.error !== 'permission not granted' && snap.blocks && snap.blocks[k] && (snap.blocks[k].ok || snap.blocks[k].stale_since)) {
              for (const f of fields) if (snap[f] !== undefined) out[f] = snap[f];
              out.blocks[k] = Object.assign({}, b, { ok: true, stale_since: snap.blocks[k].stale_since || snap.updated, last_error: b.error });
            }
          }
          for (const k of ['secureScore', 'mfa', 'riskyUsers', 'riskDetections', 'conditionalAccess', 'defenderAlerts']) {
            const b = out.blocks[k], prev = snap.security && snap.security[k];
            if (b && !b.ok && b.error !== 'permission not granted' && prev && prev.ok) { out.security[k] = prev; out.blocks[k] = Object.assign({}, b, { ok: true, stale_since: (snap.blocks[k] && snap.blocks[k].stale_since) || snap.updated, last_error: b.error }); }
          }
        }
        snap = out; st.last_error = '';
        if (file) { try { fs.writeFileSync(file + '.tmp', JSON.stringify(out), { mode: 0o600 }); fs.renameSync(file + '.tmp', file); } catch (e) { lg.warn('m365 graph: snapshot not saved', { err: e.message }); } }
      } catch (e) { st.last_error = e.message; lg.warn('m365 graph: sync failed', { err: e.message }); }
      finally { st.running = false; running = null; }
      return snap;
    })();
    return running;
  }
  function enabled() { const c = credsOf(config); return c.mc.graph !== false && !c.errs.length; }
  function schedule() {
    if (stopped) return;
    let ms = 900000;   // an unreadable setting keeps the default interval: the schedule itself must never fail
    try { ms = Math.max(300, Number(credsOf(config).mc.graph_poll_s) || 900) * 1000; } catch (e) { lg.warn('m365 graph: poll interval not readable - using 15 minutes', { err: e.message }); }
    timer = setTimeout(async () => { try { await guardJob('collect.m365-graph.sync', async () => { if (enabled()) { await syncNow(); if (st.last_error) throw new Error(st.last_error); } })(); } finally { schedule(); } }, ms); if (timer.unref) timer.unref();
  }
  return {
    start() { const t0 = setTimeout(async () => { try { await guardJob('collect.m365-graph.sync', async () => { if (enabled()) { await syncNow(); if (st.last_error) throw new Error(st.last_error); } })(); } finally { schedule(); } }, 15000); if (t0.unref) t0.unref(); return this; },
    stop() { stopped = true; if (timer) clearTimeout(timer); },
    syncNow, enabled,
    // what the portal reads: nothing secret, no tokens
    // + the sync state, so the page can say when the figures are old or the last sync failed (it keeps the last good copy)
    data() {
      const pollS = Math.max(300, Number(credsOf(config).mc.graph_poll_s) || 900), age = snap && snap.updated ? Date.now() - Date.parse(snap.updated) : null;
      const sync = { last_error: st.last_error || '', last_poll_at: st.last_poll_at, running: st.running, interval_s: pollS, age_s: age == null ? null : Math.round(age / 1000), stale: age != null && age > pollS * 3000, enabled: enabled() };
      return snap ? Object.assign({}, snap, { sync }) : { configured: false, reason: credsOf(config).errs.join('; ') || (st.last_error ? 'first sync failed: ' + st.last_error : 'first sync pending'), sync };
    },
    // read-only Graph access for other collectors with the same app registration (collect/m365-files.js): JSON GETs and file
    // content (the download redirect goes to a pre-signed SharePoint URL; the bearer token is not sent off Graph)
    graphGet: (u, pages) => { const c = credsOf(config); if (c.errs.length) return Promise.reject(new Error(c.errs.join('; '))); return get(c, u, pages); },
    async graphContent(u, maxBytes) {
      const c = credsOf(config); if (c.errs.length) throw new Error(c.errs.join('; '));
      if (!u.startsWith('/')) throw new Error('only Graph paths');
      const res = await doFetch(GRAPH + u, { headers: { Authorization: `Bearer ${await getToken(c)}` }, redirect: 'manual', signal: AbortSignal.timeout(60000) });
      let r = res;
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) r = await doFetch(res.headers.get('location'), { signal: AbortSignal.timeout(60000) });
      if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      const len = Number(r.headers.get('content-length') || 0); if (len > maxBytes) { const e = new Error('too large'); e.status = 413; throw e; }
      const b = Buffer.from(await r.arrayBuffer()); if (b.length > maxBytes) { const e = new Error('too large'); e.status = 413; throw e; }
      return b;
    },
    status() { const c = credsOf(config); return Object.assign({ enabled: c.mc.graph !== false, ready: !c.errs.length, missing: c.errs, updated: snap ? snap.updated : null, blocks: snap ? snap.blocks : {} }, st); },
    PERMS,
  };
}

module.exports = { createGraph, PERMS, credsOf };
