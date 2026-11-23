// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * Cloud log source settings from the portal (admin; the API token is write-only):
 *   GET  {P}/cloud/cloudflare          settings (token as set / not set) + collector status            admin
 *   PUT  {P}/cloud/cloudflare          {enabled, account_id, zones[], api_token?, poll_s}               admin
 *   POST {P}/cloud/cloudflare/test     verify the token (GET /user/tokens/verify) and list the zones it can read
 *   POST {P}/cloud/cloudflare/diagnose step by step: settings, token type, egress, token, zones, security events per zone,
 *                                      audit log, collector status - each step with the fix (read-only GET / GraphQL query)  admin
 * Zones may be entered as domain names (example.com): they are resolved to zone IDs with the token when saved.
 * config.json "cloudflare" + secrets.json "cloudflare.api_token"; applied at once (collector restarted in-process).
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const ID_RE = /^[0-9a-f]{32}$/i;
const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const API = 'https://api.cloudflare.com/client/v4';

function register(api, deps) {
  const P = prefixOf(deps), cfg = deps.config, writeJson = require('../onboard/store').writeJsonAtomic;
  const doFetch = deps.cloudFetch || ((u, o) => fetch(u, o));
  const tok = () => String((cfg.secrets && cfg.secrets.cloudflare && cfg.secrets.cloudflare.api_token) || '');
  const view = () => { const c = cfg.cloudflare || {}; return { enabled: !!c.enabled, account_id: c.account_id || '', zones: c.zones || [], poll_s: c.poll_s || 300, token_set: !!tok(), status: deps.cloudflareStats ? deps.cloudflareStats() : null }; };
  const read = (p) => { try { if (SF.isSecretsPath(p)) return SF.read(p) || {}; return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw new HttpError(500, `cannot read ${p}`); } };

  api.route('GET', `${P}/cloud/cloudflare`, wrap(deps, 'admin', () => view()));
  api.route('PUT', `${P}/cloud/cloudflare`, wrap(deps, 'admin', async (ctx) => {
    const b = ctx.body || {}, paths = cfg._paths || {};
    if (!paths.config || !paths.secrets) throw new HttpError(409, 'config / secrets files not available');
    const c = Object.assign({}, cfg.cloudflare || {});
    if ('account_id' in b) { const v = String(b.account_id || '').trim(); if (v && !ID_RE.test(v)) throw new HttpError(400, 'account ID: the 32-character ID from the Cloudflare dashboard (right side of the account overview)'); c.account_id = v; }
    const newTok0 = typeof b.api_token === 'string' && b.api_token.trim() ? b.api_token.trim() : '';
    if ('zones' in b) {
      const z = (Array.isArray(b.zones) ? b.zones : String(b.zones || '').split(/[\s,]+/)).map((x) => String(x).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')).filter(Boolean);
      if (z.length > 50) throw new HttpError(400, 'at most 50 zones');
      const bad = z.filter((x) => !ID_RE.test(x) && !DOMAIN_RE.test(x)); if (bad.length) throw new HttpError(400, 'zones: a domain name (example.com) or a 32-character zone ID: ' + bad.slice(0, 3).join(', '));
      // a domain name is looked up with the token (the zone list it can read) - engineers know the domain, not the ID
      const names = z.filter((x) => !ID_RE.test(x)), t = newTok0 || tok();
      if (names.length && !t) throw new HttpError(400, 'zones: enter the API token first, so domain names can be looked up to zone IDs');
      const ids = [];
      for (const x of z) {
        if (ID_RE.test(x)) { ids.push(x); continue; }
        let r; try { r = await doFetch(`${API}/zones?name=${encodeURIComponent(x)}`, { headers: { Authorization: `Bearer ${t}`, Accept: 'application/json' }, signal: AbortSignal.timeout(15000) }); }
        catch (e) { throw new HttpError(400, `zones: ${x} could not be looked up - api.cloudflare.com not reachable from the SIEM server (${e.message}); enter the zone ID instead`); }
        let j = null; try { j = await r.json(); } catch { j = null; }
        const hit = j && Array.isArray(j.result) ? j.result.find((q) => String(q.name).toLowerCase() === x) : null;
        if (!hit) throw new HttpError(400, `zones: ${x} is not a zone this token can read - check the spelling, or give the token Zone → Analytics: Read on it`);
        ids.push(hit.id);
      }
      c.zones = [...new Set(ids)];
    }
    if ('poll_s' in b) { const n = Number(b.poll_s); if (!(n >= 60 && n <= 3600)) throw new HttpError(400, 'poll every 60-3600 s'); c.poll_s = Math.round(n); }
    if ('enabled' in b) c.enabled = b.enabled === true || b.enabled === 'true';
    const newTok = typeof b.api_token === 'string' && b.api_token.trim() ? b.api_token.trim() : '';
    if (newTok && (newTok.length > 200 || /\s/.test(newTok))) throw new HttpError(400, 'invalid API token');
    if (c.enabled && !(newTok || tok())) throw new HttpError(400, 'enter the API token to enable the Cloudflare collector');
    if (c.enabled && !c.account_id && !(c.zones || []).length) throw new HttpError(400, 'enter the account ID and/or zone IDs');
    const file = read(paths.config); file.cloudflare = Object.assign({}, file.cloudflare || {}, c); writeJson(paths.config, file); cfg.cloudflare = Object.assign(cfg.cloudflare || {}, c);
    if (newTok) { const sec = read(paths.secrets); sec.cloudflare = Object.assign({}, sec.cloudflare || {}, { api_token: newTok }); writeJson(paths.secrets, sec); if (cfg.secrets) cfg.secrets.cloudflare = Object.assign(cfg.secrets.cloudflare || {}, { api_token: newTok }); }
    let applied = false; if (deps.reloadCloudflare) { await deps.reloadCloudflare(); applied = true; }
    audit(ctx, 'cloud.cloudflare.config', '', { enabled: c.enabled, zones: (c.zones || []).length, token_changed: !!newTok });
    return Object.assign(view(), { applied });
  }));
  api.route('POST', `${P}/cloud/cloudflare/test`, wrap(deps, 'admin', async (ctx) => {
    const b = ctx.body || {}, t = (typeof b.api_token === 'string' && b.api_token.trim()) || tok();
    if (!t) throw new HttpError(400, 'no API token entered or stored');
    const steps = [], H = { Authorization: `Bearer ${t}`, Accept: 'application/json' };
    const get = async (u) => { const r = await doFetch(u, { headers: H, signal: AbortSignal.timeout(15000) }); let j = null; try { j = await r.json(); } catch { j = null; } return { status: r.status, j }; };
    try {
      const v = await get('https://api.cloudflare.com/client/v4/user/tokens/verify');
      const ok = v.status === 200 && v.j && v.j.result && v.j.result.status === 'active';
      steps.push({ ok, text: ok ? 'API token is valid and active' : `token not accepted (HTTP ${v.status}${v.j && v.j.errors && v.j.errors[0] ? ': ' + v.j.errors[0].message : ''})` });
      if (ok) {
        const z = await get('https://api.cloudflare.com/client/v4/zones?per_page=50');
        const list = (z.j && z.j.result) || [];
        steps.push({ ok: list.length > 0, text: list.length ? `${list.length} zone(s) readable: ` + list.slice(0, 10).map((x) => `${x.name} (${x.id})`).join(', ') : 'no zones readable with this token (add Zone → Analytics: Read)' });
        const acct = (typeof b.account_id === 'string' && b.account_id.trim()) || (cfg.cloudflare && cfg.cloudflare.account_id);
        if (acct) { const a = await get(`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(acct)}/audit_logs?per_page=1`); steps.push({ ok: a.status === 200, text: a.status === 200 ? 'account audit log readable' : `audit log not readable (HTTP ${a.status}) - add Account → Account Settings: Read` }); }
        return { ok: steps.every((s) => s.ok), steps, zones: list.map((x) => ({ id: x.id, name: x.name })) };
      }
    } catch (e) { steps.push({ ok: false, text: `cannot reach api.cloudflare.com: ${e.message} (outbound HTTPS from the SIEM server needed)` }); }
    return { ok: false, steps };
  }));

  // the integration doctor: every step in order, each with what was seen and the exact fix. Read-only: GET calls and one
  // GraphQL query (a read) per zone, nothing else; the token is never returned or logged.
  api.route('POST', `${P}/cloud/cloudflare/diagnose`, wrap(deps, 'admin', async (ctx) => {
    const c = cfg.cloudflare || {}, t = tok(), steps = [], add = (step, status, detail, fix) => steps.push({ step, status, detail: String(detail || '').slice(0, 400), fix: fix || '' });
    const done = () => { const ok = steps.every((x) => x.status !== 'fail'); audit(ctx, 'cloud.cloudflare.diagnose', '', { ok, failed: (steps.find((x) => x.status === 'fail') || {}).step || null }); return { ok, steps, at: new Date().toISOString() }; };
    // 1. settings
    if (!t) { add('Settings', 'fail', 'no API token stored', 'Cloudflare dashboard → My Profile → API Tokens → Create Token → Custom: Zone → Analytics: Read (+ Account → Account Settings: Read for the audit log), then paste it here and save.'); return done(); }
    if (!c.account_id && !(c.zones || []).length) { add('Settings', 'fail', 'no account ID and no zone', ('Enter your domain names (e.g. ' + ZYB_ORG.domain + ') in Zones - they are looked up to zone IDs - and/or the account ID.')); return done(); }
    add('Settings', c.enabled ? 'ok' : 'warn', (c.enabled ? 'enabled' : 'saved but NOT enabled') + ', ' + (c.zones || []).length + ' zone(s)' + (c.account_id ? ', account set' : ', no account (no audit log)'), c.enabled ? '' : 'Tick "Enabled" and save, or the collector will not pull anything.');
    // 2. the kind of key: a Global API Key (37 hex characters) is not an API token and is refused as a Bearer token
    if (/^[0-9a-f]{37}$/i.test(t)) { add('Token type', 'fail', 'this looks like the Global API Key, not an API Token', 'Do not use the Global API Key. Create an API Token (My Profile → API Tokens → Create Token) with read-only permissions and paste that instead.'); return done(); }
    add('Token type', 'ok', 'an API Token (Bearer)', '');
    const H = { Authorization: `Bearer ${t}`, Accept: 'application/json' };
    const get = async (u) => { const r = await doFetch(u, { headers: H, signal: AbortSignal.timeout(15000) }); let j = null; try { j = await r.json(); } catch { j = null; } return { status: r.status, j }; };
    const err0 = (x) => (x && x.j && x.j.errors && x.j.errors[0] ? x.j.errors[0].code + ': ' + x.j.errors[0].message : 'HTTP ' + (x && x.status));
    // 3. egress + 4. token
    let v;
    try { v = await get(`${API}/user/tokens/verify`); }
    catch (e) {
      const dns = /ENOTFOUND|EAI_AGAIN/.test(String(e.cause && e.cause.code || e.message));
      add('Outbound HTTPS to api.cloudflare.com', 'fail', (dns ? 'the SIEM server cannot resolve api.cloudflare.com' : 'no connection to api.cloudflare.com:443') + ' (' + String((e.cause && e.cause.code) || e.message).slice(0, 80) + ')',
        dns ? 'Give the SIEM server a DNS resolver that resolves internet names.' : 'Allow outbound HTTPS from the SIEM server to api.cloudflare.com:443 on the firewall. If the network only allows the internet through a proxy, open a direct rule for api.cloudflare.com - the collector does not use a proxy.');
      return done();
    }
    add('Outbound HTTPS to api.cloudflare.com', 'ok', 'reachable', '');
    const st = v.j && v.j.result && v.j.result.status;
    if (v.status !== 200 || st !== 'active') {
      const m = err0(v);
      add('API token', 'fail', 'token not accepted: ' + (st || m), /expired|not_before|disabled/i.test(String(st) + m) ? 'The token is expired or disabled: roll or recreate it in My Profile → API Tokens.'
        : /9109|ip/i.test(m) ? 'The token has a client-IP restriction: add the SIEM server\'s public IP to the token\'s IP filtering, or remove the restriction.' : 'Copy the token again (it is shown once when created) and save it here; the Global API Key or an API Key will not work.');
      return done();
    }
    add('API token', 'ok', 'valid and active', '');
    // 5. zones
    const z = await get(`${API}/zones?per_page=50`), list = (z.j && z.j.result) || [], readable = new Map(list.map((x) => [x.id, x.name]));
    const want = c.zones || [], missing = want.filter((id) => !readable.has(id));
    if (!list.length) add('Zones', 'fail', 'the token can read no zone', 'Edit the token: Permissions → Zone → Analytics: Read; Zone Resources → Include → All zones (or the zones you want).');
    else if (missing.length) add('Zones', 'fail', missing.length + ' configured zone(s) not readable with this token: ' + missing.join(', '), 'Add these zones to the token\'s Zone Resources, or remove them from Zones. Readable: ' + list.slice(0, 8).map((x) => x.name).join(', '));
    else add('Zones', want.length ? 'ok' : 'warn', want.length ? want.map((id) => readable.get(id)).join(', ') : 'no zone selected - readable: ' + list.slice(0, 8).map((x) => x.name).join(', '), want.length ? '' : 'Enter the domains to collect security events from in Zones.');
    // 6. security events per zone: one GraphQL read of the last hour
    for (const id of want.filter((x) => readable.has(x)).slice(0, 10)) {
      const since = new Date(Date.now() - 3600000).toISOString();
      let r; try {
        const res = await doFetch(`${API}/graphql`, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, H), signal: AbortSignal.timeout(20000),
          body: JSON.stringify({ query: 'query($z:String!,$s:Time!){viewer{zones(filter:{zoneTag:$z}){firewallEventsAdaptive(filter:{datetime_geq:$s},limit:1){datetime}}}}', variables: { z: id, s: since } }) });
        r = await res.json();
      } catch (e) { add('Security events: ' + readable.get(id), 'fail', 'GraphQL not reachable (' + e.message + ')', 'Allow outbound HTTPS to api.cloudflare.com:443.'); continue; }
      const ge = r && r.errors && r.errors[0] ? String(r.errors[0].message || '') : '';
      if (ge) add('Security events: ' + readable.get(id), 'fail', ge, /not authorized|access|permission/i.test(ge) ? 'Give the token Zone → Analytics: Read on this zone.' : /plan|not available|limit/i.test(ge) ? 'This zone\'s Cloudflare plan does not offer security-event analytics through the API; the account audit log still works.' : 'Read the Cloudflare message above.');
      else { const n = (((((r.data || {}).viewer || {}).zones || [])[0] || {}).firewallEventsAdaptive || []).length; add('Security events: ' + readable.get(id), 'ok', n ? 'readable (events in the last hour)' : 'readable (no event in the last hour)', ''); }
    }
    // 7. account audit log
    if (c.account_id) {
      const a = await get(`${API}/accounts/${encodeURIComponent(c.account_id)}/audit_logs?per_page=1`);
      if (a.status === 200) add('Account audit log', 'ok', 'readable', '');
      else add('Account audit log', 'fail', 'not readable: ' + err0(a), a.status === 403 ? 'Give the token Account → Account Settings: Read on this account.' : 'Check the account ID (Cloudflare dashboard → account home → right column "Account ID").');
    }
    // 8. the collector itself
    const s = deps.cloudflareStats ? deps.cloudflareStats() : null;
    if (!s || !s.enabled) add('Collector', 'warn', 'not running', 'Tick Enabled and save; the collector starts at once.');
    else if (s.error || s.last_error) add('Collector', 'fail', 'last error: ' + (s.error || s.last_error), 'Fix the step above that fails; the collector retries on its own.');
    else add('Collector', s.polls ? 'ok' : 'warn', s.polls ? s.polls + ' poll(s), ' + (s.records || 0) + ' record(s) collected, last ' + (s.last_poll_at || '-') : 'started, no poll yet', s.polls ? '' : 'Wait one poll interval, then run this again.');
    return done();
  }));
}

module.exports = { register };
