// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AD & Exchange settings from the portal (admin): the AD identity sync connection (config.ad + secrets.ad.bind_password)
 * and the Microsoft 365 / Exchange Online pull (config.m365.enabled + secrets.m365 {tenant, client_id, client_secret}).
 *
 *   createAdSettings({config, adSync, ldap, writeJson, reloadM365, log})
 *     .view()            current settings; secrets only as "set" / "not set"
 *     .save(body, by)    validates, writes config.json / secrets.json (atomic, backup), applies without a restart
 *     .test(body)        CA file → TLS to each DC (certificate + name checked) → service bind → base DN → users visible
 * Passwords and client secrets are write-only: never returned, never logged.
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('fs');
const crypto = require('crypto');

const AD_KEYS = ['enabled', 'servers', 'caFile', 'baseDN', 'bindDN', 'privileged_groups', 'sync_minutes', 'dormant_days'];
const PATH_RE = /^\/[A-Za-z0-9._\/-]{1,300}$/;
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);

function createAdSettings({ config, adSync = null, ldap = require('./ldap-client'), writeJson, reloadM365 = null, log = null, now = Date.now } = {}) {
  const L = log || { info() {}, warn() {}, error() {} };
  const paths = config._paths || {};
  const secrets = () => { if (!config.secrets) Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true }); return config.secrets; };

  function view() {
    const a = config.ad || {}, m = config.m365 || {}, sm = secrets().m365 || {};
    return {
      ad: Object.assign(Object.fromEntries(AD_KEYS.map((k) => [k, a[k] === undefined ? null : a[k]])), { password_set: !!(secrets().ad && secrets().ad.bind_password) }),
      ad_status: adSync ? adSync.status() : null,
      m365: { enabled: !!m.enabled, graph: m.graph !== false, tenant: sm.tenant || '', client_id: sm.client_id || '', secret_set: !!sm.client_secret, certificate: !!sm.cert_file },
      writable: !!paths.config,
    };
  }

  function normAd(input, cur) {
    const o = Object.assign({}, cur);
    if ('enabled' in input) o.enabled = input.enabled === true || input.enabled === 'true';
    if ('servers' in input) {
      const list = (Array.isArray(input.servers) ? input.servers : String(input.servers || '').split(/[\n,]+/)).map((s) => (typeof s === 'object' && s ? { url: str(s.url, 300), ip: str(s.ip, 45) } : str(s, 300))).filter((s) => (typeof s === 'object' ? s.url : s));
      if (list.length > 6) throw bad('at most 6 domain controllers');
      o.servers = list.map((s) => { const x = typeof s === 'object' ? (s.ip ? s : s.url) : s; try { ldap.parseServer(x); } catch (e) { throw bad(e.message); } return x; });
    }
    if ('caFile' in input) { const p = str(input.caFile, 300); if (p && !PATH_RE.test(p)) throw bad('CA file must be an absolute path on the SIEM server'); o.caFile = p; }
    for (const k of ['baseDN', 'bindDN']) if (k in input) { const v = str(input[k], 400); if (v && !/^[A-Za-z]+=/.test(v) && !(k === 'bindDN' && /^[^@\s]+@[^@\s]+$/.test(v))) throw bad(`${k} must look like CN=…,DC=… ${k === 'bindDN' ? 'or user@domain' : ''}`); o[k] = v; }
    if ('privileged_groups' in input) { const g = (Array.isArray(input.privileged_groups) ? input.privileged_groups : String(input.privileged_groups || '').split(/\n+/)).map((x) => str(x, 400)).filter(Boolean); if (g.length > 50) throw bad('at most 50 extra privileged groups'); o.privileged_groups = g; }
    if ('sync_minutes' in input) { const n = Number(input.sync_minutes); if (!(n >= 5 && n <= 1440)) throw bad('sync every 5-1440 minutes'); o.sync_minutes = Math.round(n); }
    if ('dormant_days' in input) { const n = Number(input.dormant_days); if (!(n >= 7 && n <= 3650)) throw bad('dormant after 7-3650 days'); o.dormant_days = Math.round(n); }
    return o;
  }

  function readFile(p) { try { if (SF.isSecretsPath(p)) return SF.read(p) || {}; return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw Object.assign(new Error(`cannot read ${p}: ${e.message}`), { status: 500 }); } }

  async function save(body, by) {
    body = body || {};
    if (!paths.config || !paths.secrets) throw Object.assign(new Error('the SIEM was started without config / secrets files - settings cannot be saved here'), { status: 409 });
    const out = { saved: [] };
    const file = readFile(paths.config), sec = readFile(paths.secrets);
    let adChanged = false, m365Changed = false, secChanged = false;
    if (body.ad) {
      const ad = normAd(body.ad, Object.assign({}, config.ad || {}));
      if (ad.enabled && (!ad.servers || !ad.servers.length || !ad.baseDN || !ad.bindDN)) throw bad('to enable the sync, fill in the domain controllers, base DN and bind account');
      file.ad = Object.assign({}, file.ad || {}, Object.fromEntries(AD_KEYS.filter((k) => ad[k] !== undefined).map((k) => [k, ad[k]])));
      config.ad = Object.assign(config.ad || {}, file.ad); adChanged = true; out.saved.push('ad');
    }
    if (body.ad && typeof body.ad.bind_password === 'string' && body.ad.bind_password !== '') {
      const pw = body.ad.bind_password; if (pw.length > 256 || /[\u0000\r\n]/.test(pw)) throw bad('invalid password');
      sec.ad = Object.assign({}, sec.ad || {}, { bind_password: pw }); secrets().ad = Object.assign(secrets().ad || {}, { bind_password: pw }); secChanged = true; out.saved.push('ad.bind_password');
    }
    if (body.m365) {
      const m = body.m365, sm = Object.assign({}, sec.m365 || {});
      if ('tenant' in m) { const v = str(m.tenant, 64); if (v && !GUID_RE.test(v) && !/^[a-z0-9-]+\.onmicrosoft\.com$/i.test(v)) throw bad('tenant: the directory (tenant) ID GUID or name.onmicrosoft.com'); sm.tenant = v; }
      if ('client_id' in m) { const v = str(m.client_id, 64); if (v && !GUID_RE.test(v)) throw bad('client_id: the application (client) ID GUID'); sm.client_id = v; }
      if (typeof m.client_secret === 'string' && m.client_secret !== '') { if (m.client_secret.length > 512 || /[\u0000\r\n]/.test(m.client_secret)) throw bad('invalid client secret'); sm.client_secret = m.client_secret; out.saved.push('m365.client_secret'); }
      const en = 'enabled' in m ? (m.enabled === true || m.enabled === 'true') : !!(config.m365 && config.m365.enabled);
      if (en && (!sm.tenant || !sm.client_id || !(sm.client_secret || sm.cert_file))) throw bad('to enable Exchange Online, fill in tenant, client ID and client secret');
      sec.m365 = sm; secrets().m365 = Object.assign(secrets().m365 || {}, sm); secChanged = true;
      file.m365 = Object.assign({}, file.m365 || {}, { enabled: en });
      if ('graph' in m) file.m365.graph = !(m.graph === false || m.graph === 'false');   // Microsoft Graph inventory for the portal (collect/m365-graph.js)
      if (sm.tenant && GUID_RE.test(sm.tenant) && !file.m365.publisher_id) file.m365.publisher_id = sm.tenant;
      config.m365 = Object.assign(config.m365 || {}, file.m365); m365Changed = true; out.saved.push('m365');
    }
    if (adChanged || m365Changed) writeJson(paths.config, file);
    if (secChanged) writeJson(paths.secrets, sec);
    if (adChanged && adSync && typeof adSync.reconfigure === 'function') { adSync.reconfigure(); out.ad_applied = true; }
    if (m365Changed && typeof reloadM365 === 'function') { try { await reloadM365(); out.m365_applied = true; } catch (e) { out.m365_applied = false; out.m365_error = e.message; } }
    L.info('ad/exchange settings saved', { by, saved: out.saved });
    return Object.assign(out, view());
  }

  async function test(body) {
    const ad = normAd((body && body.ad) || {}, Object.assign({}, config.ad || {}));
    const pw = (body && body.ad && typeof body.ad.bind_password === 'string' && body.ad.bind_password) || (secrets().ad && secrets().ad.bind_password) || '';
    const steps = [], step = (ok, text) => { steps.push({ ok, text }); return ok; };
    try { const pem = fs.readFileSync(ad.caFile || '/nonexistent', 'utf8'); step(/BEGIN CERTIFICATE/.test(pem), /BEGIN CERTIFICATE/.test(pem) ? `CA file ${ad.caFile}` : `CA file ${ad.caFile} holds no PEM certificate`); } catch (e) { step(false, `CA file ${ad.caFile || '(not set)'}: ${e.code || e.message} — run install/ad-tls-check.sh on the SIEM server to create it`); }
    if (!(ad.servers || []).length) { step(false, 'no domain controller entered'); return { ok: false, steps }; }
    let usable = null;
    for (const raw of ad.servers) {
      const s = ldap.parseServer(raw);
      try { const conn = await ldap.createClient({ servers: [raw], caFile: ad.caFile, timeoutMs: 10000 }).connect(); const c = conn.sock.getPeerCertificate(); conn.close(); step(true, `${s.url}${s.ip ? ' (via ' + s.ip + ')' : ''}: encrypted, certificate trusted for ${s.servername}, expires ${c.valid_to}`); if (!usable) usable = raw; }
      catch (e) { step(false, `${s.url}${s.ip ? ' (via ' + s.ip + ')' : ''}: ${e.message}${/altname|Hostname\/IP/i.test(e.message) ? ' — use the DC name from its certificate and put the IP in "via"' : ''}`); }
    }
    if (!usable) return { ok: false, steps };
    if (!ad.bindDN || !pw) { step(false, 'bind account or password not set'); return { ok: false, steps }; }
    try {
      await ldap.createClient({ servers: [usable], caFile: ad.caFile, timeoutMs: 15000 }).run(async (conn) => {
        await conn.bind(ad.bindDN, pw); step(true, `signed in as ${ad.bindDN}`);
        if (!ad.baseDN) { step(false, 'base DN not set'); return; }
        await conn.search(ad.baseDN, { scope: 'base', attributes: ['distinguishedName'] }); step(true, `base DN ${ad.baseDN} found`);
        const u = await conn.search(ad.baseDN, { filter: '(&(objectCategory=person)(objectClass=user))', attributes: ['1.1'], pageSize: 1000, maxEntries: 200000 });
        step(u.entries.length > 0, `${u.entries.length} user accounts readable`);
      });
    } catch (e) { step(false, /49|invalid credentials/i.test(e.message) ? 'sign-in refused: wrong bind account or password (LDAP 49)' : /32|no such object/i.test(e.message) ? `base DN not found (${e.message})` : e.message); }
    return { ok: steps.every((x) => x.ok), steps, tested_at: new Date(now()).toISOString(), id: crypto.randomBytes(4).toString('hex') };
  }

  return { view, save, test };
}

module.exports = { createAdSettings, AD_KEYS };
