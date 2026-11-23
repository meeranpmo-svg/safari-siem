// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * The platform licence ({P} = /api/itam; Platform Admin -> Modules & Solutions). A licence is issued by Citynet: a JSON document
 *   { licence_id, customer, edition, modules: [module ids] | null, limits: { users, ips, servers, network_devices, databases,
 *     log_sources }, issued, expires } + signature (Ed25519 over the canonical JSON of everything else)
 * signed with Citynet's private key, which never leaves Citynet (tools/licence/licence-tool.js signs offline). The server holds only
 * the public key (config licence.public_key_file, default /etc/sentra-itam/licence-pub.pem), so a customer cannot raise a limit.
 * A limit of null or "unlimited" = no limit.
 *   no licence installed   -> UNLIMITED, every module (the agreement with the organisation: no licence is installed there)
 *   valid                  -> the licence's modules and limits; usage measured from the platform's own records
 *   expired / over a limit -> said on the page and in the status; nothing is locked or switched off (a monitoring platform that
 *                              stops monitoring when a count is exceeded is a security risk); Citynet renews or extends the licence
 *   invalid signature      -> refused when installed; an installed file that no longer verifies is reported, never trusted
 * Usage: users = people (not service or AI identities) who used the platform in the last 90 days of the audit trail plus everyone
 * with an assigned job role; ips = distinct management IPs of active assets; servers / network devices / databases = active assets
 * by type; log sources are counted by the SIEM and read here only when the SIEM link reports them (else "not measured").
 *   GET  /licence            viewer   licence, limits, usage, warnings (no names)
 *   POST /licence            admin    {licence} install a licence issued by Citynet - verified before it is kept   audited
 */
/* Enforcement (Nov 2026), on top of the above - active only when the issuer's public key is BUILT INTO the code (licence-pubkey.js):
 *   - a key file on the server is then ignored (nobody on the server can install their own key and sign their own licence)
 *   - a licence may list `servers`: fingerprints of the servers it is for (`licence-tool.js fingerprint`, or GET /licence on the
 *     server); a licence for other servers does not count here
 *   - no licence, a licence that does not verify, has expired or is for another server: administrators are warned for a grace
 *     period (licence.grace_days, default 90, at most 90) from the first time it was seen; after that people are refused by
 *     every API of this engine (403 'licence') except the licence routes - sign-in, service / AI identities between the
 *     engines, the agent gateway, log ingestion and detection keep running, so a lapse never blinds the SOC
 *   - limits stay warnings only; a clock moved back more than two days is itself a problem
 *   - the signed licence is sent to the SIEM, which verifies it with the same built-in key and enforces it the same way
 */
const BUILTIN_KEY = (() => { try { return require('./licence-pubkey').PUBLIC_KEY || ''; } catch (e) { return ''; /* no key file in this build: not enforced */ } })();
const GRACE_DAYS = 90, MAX_GRACE = 90;   // a 90-day trial / grace period (was 14, at most 30)
const isServiceId = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
function readMachineId() {
  for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) { try { const v = fs.readFileSync(f, 'utf8').trim(); if (v) return v; } catch (e) { /* not on this system: try the next file */ } }
  return '';
}
// a short, stable fingerprint of this server: host name + machine id (SHA-256, first 16 hex, grouped)
function fingerprintOf(hostname, machineId) {
  return crypto.createHash('sha256').update(String(hostname || '').toLowerCase() + '|' + String(machineId || '')).digest('hex').slice(0, 16).toUpperCase().replace(/(.{4})(?=.)/g, '$1-');
}
const LIMITS = ['users', 'ips', 'servers', 'network_devices', 'databases', 'log_sources'];
const LABEL = { users: 'Named users', ips: 'Monitored IP addresses', servers: 'Servers', network_devices: 'Network devices', databases: 'Databases', log_sources: 'SIEM log sources' };
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
// canonical JSON: keys sorted at every level, so the signer and the server hash the same bytes
const canon = (o) => JSON.stringify((function sort(v) { if (Array.isArray(v)) return v.map(sort); if (v && typeof v === 'object') return Object.keys(v).sort().reduce((r, k) => { r[k] = sort(v[k]); return r; }, {}); return v; })(o));
function payloadOf(lic) { const o = Object.assign({}, lic); delete o.signature; return canon(o); }
function verify(lic, pubPem) {
  if (!pubPem) return { ok: false, why: 'no licence verification key is installed on this server (licence.public_key_file)' };
  if (!lic || typeof lic.signature !== 'string') return { ok: false, why: 'the licence carries no signature' };
  try { return crypto.verify(null, Buffer.from(payloadOf(lic)), crypto.createPublicKey(pubPem), Buffer.from(lic.signature, 'base64')) ? { ok: true } : { ok: false, why: 'the signature does not match - the licence was not issued by Citynet or was changed' }; }
  catch (e) { return { ok: false, why: 'the signature could not be checked: ' + String(e.message).slice(0, 120) }; }
}
const unlimited = (v) => v === null || v === undefined || v === 'unlimited';

function createLicence(app, opts = {}) {
  const now = opts.now || Date.now, cfg = (app.config && app.config.licence) || {};
  const FILE = opts.file || cfg.file || '/etc/sentra-itam/licence.json', KEYF = opts.publicKeyFile || cfg.public_key_file || '/etc/sentra-itam/licence-pub.pem';
  // not enforced only for tests: opts.enforce === false, or the test helper's app flag (tests/helpers.js startApp) unless a test
  // asks for enforcement - neither can be set from config, the environment or a request
  const builtin = (opts.enforce === false || (opts.enforce === undefined && app.__testNoLicence === true)) ? '' : opts.publicKey !== undefined && opts.enforce ? opts.publicKey : BUILTIN_KEY;
  const enforced = !!builtin;
  const FP = fingerprintOf(opts.hostname !== undefined ? opts.hostname : require('node:os').hostname(), opts.machineId !== undefined ? opts.machineId : readMachineId());
  const readKey = () => { if (enforced) return builtin; if (opts.publicKey) return opts.publicKey; try { return fs.readFileSync(KEYF, 'utf8'); } catch (e) { return null; /* no key installed: no licence can verify */ } };
  const readLic = () => { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { if (e.code !== 'ENOENT' && app.log && app.log.every) app.log.every('licence:read', 3600000, 'warn', 'licence file unreadable', { err: String(e.message).slice(0, 120) }); return null; } };
  function usage() {
    const st = app.store, out = {};
    const assets = st.collection('assets').all((a) => !['retired', 'disposed'].includes(a.status));
    const t = (re) => assets.filter((a) => re.test(String(a.type || ''))).length;
    out.ips = new Set(assets.map((a) => a.mgmt_ip || a.ip).filter(Boolean)).size;
    out.servers = t(/server|^vm$|virtual|host|hypervisor/i);
    out.network_devices = t(/switch|router|firewall|wireless|access.?point|^ap$|network|load.?balancer|wan/i);
    out.databases = t(/database|^db$/i);
    const since = now() - 90 * DAY, people = new Set();
    for (const r of (typeof st.auditTail === 'function' ? st.auditTail(5000) : [])) if (r.by && isHuman(r.by) && Date.parse(r.at) >= since) people.add(String(r.by).toLowerCase());
    for (const a of st.collection('role_assignments').all(() => true)) if (a.user && isHuman(a.user)) people.add(String(a.user).toLowerCase());
    out.users = people.size;
    out.log_sources = opts.logSources ? opts.logSources() : null;
    return out;
  }
  // enforcement: is this server licensed now? {ok, reason}; the first time a problem is seen and the latest time ever seen are kept
  const ST = () => app.store.collection('licence_state');
  function enforcement(lic) {
    if (!enforced) return null;
    const t = now(); let reason = '';
    if (!lic) reason = 'no licence is installed';
    else { const v = verify(lic, builtin);
      if (!v.ok) reason = v.why;
      else if (Array.isArray(lic.servers) && lic.servers.length && !lic.servers.map((x) => String(x).toUpperCase()).includes(FP)) reason = 'the licence is for other servers (this server is ' + FP + ')';
      else if (lic.expires && Date.parse(lic.expires) < t) reason = 'the licence expired on ' + String(lic.expires).slice(0, 10);
      else if (lic.issued && Date.parse(lic.issued) > t + DAY) reason = 'the licence is not valid yet (issued ' + String(lic.issued).slice(0, 10) + ')'; }
    const st = (ST().get('state') || {}).v || {};
    if (st.max_seen && t < st.max_seen - 2 * DAY) reason = reason || 'the server clock moved back - check the time (NTP)';
    const next = Object.assign({}, st, { max_seen: Math.max(st.max_seen || 0, t) });
    if (!reason) { delete next.first_problem; if (st.first_problem || !st.max_seen || t - st.max_seen > 3600000) ST().put({ id: 'state', v: next }); return { enforced: true, ok: true, gate: 'ok', fingerprint: FP }; }
    if (!next.first_problem) { next.first_problem = t; if (app.audit) app.audit({ by: 'system:licence', role: 'admin', ip: '', action: 'licence.problem', target: FP, detail: { reason } }); }
    if (next.first_problem !== st.first_problem || !st.max_seen || t - st.max_seen > 3600000) ST().put({ id: 'state', v: next });
    const grace = Math.min(MAX_GRACE, Math.max(0, Number(lic && lic.grace_days) || GRACE_DAYS)) * DAY, until = next.first_problem + grace;
    return { enforced: true, ok: false, gate: t < until ? 'grace' : 'locked', reason, fingerprint: FP, problem_since: new Date(next.first_problem).toISOString(), grace_until: new Date(until).toISOString(), grace_days_left: Math.max(0, Math.ceil((until - t) / DAY)) };
  }
  let cache = null;
  const mtime = () => { try { return fs.statSync(FILE).mtimeMs; } catch (e) { return 0; /* no licence file */ } };
  function status() { const t = now(), m = mtime(); if (!cache || cache.m !== m || t - cache.at > 30000) cache = { at: t, m, v: status0() }; return cache.v; }
  function status0() {
    const lic = readLic(), u = usage(), E = enforcement(lic);
    const out = status1(lic, u);
    out.fingerprint = FP;
    out.enforcement = E || { enforced: false, gate: 'ok', note: 'Licensing is not enforced in this build (no issuer key built in).' };
    if (E && !E.ok) { out.warnings.unshift(E.gate === 'locked' ? 'The platform is locked: ' + E.reason + '. Install a valid licence from Citynet.' : 'Licence problem: ' + E.reason + '. The platform keeps working until ' + E.grace_until.slice(0, 10) + ' (' + E.grace_days_left + ' days), then locks.');
      if (out.state === 'unlimited') { out.state = 'unlicensed'; out.note = 'No licence is installed.'; } }
    return out;
  }
  // the gate: null = go ahead, else the reason to refuse
  function allowed(ctx) {
    if (!enforced) return null;
    const s = status(), E = s.enforcement; if (!E || E.gate !== 'locked') return null;
    const who = ctx.who || {}; if (!who.user || isServiceId(who.user)) return null;
    if (/^(\/api\/itam)?\/licence(\/|$)/.test(String(ctx.path || ''))) return null;
    return 'the platform licence is not valid (' + E.reason + ') - an administrator installs a licence from Citynet in Platform Administration -> Modules & Solutions';
  }
  function status1(lic, u) {
    if (!lic) return { state: enforced ? 'unlicensed' : 'unlimited', customer: null, edition: 'Unlimited', modules: null, expires: null, limits: Object.fromEntries(LIMITS.map((k) => [k, null])), usage: u, labels: LABEL, warnings: [],
      note: 'No licence is installed: every module and every limit is unlimited.' };
    const v = verify(lic, readKey());
    const exp = lic.expires ? Date.parse(lic.expires) : null, expired = exp != null && exp < now();
    const limits = Object.fromEntries(LIMITS.map((k) => [k, unlimited((lic.limits || {})[k]) ? null : Number(lic.limits[k])]));
    const warnings = [];
    if (!v.ok) warnings.push('The installed licence does not verify: ' + v.why + '. Nothing is switched off; ask Citynet for a valid licence.');
    if (expired) warnings.push('The licence expired on ' + String(lic.expires).slice(0, 10) + '. Nothing is switched off; ask Citynet to renew it.');
    else if (exp != null && exp - now() < 30 * DAY) warnings.push('The licence expires on ' + String(lic.expires).slice(0, 10) + ' (in ' + Math.ceil((exp - now()) / DAY) + ' days).');
    for (const k of LIMITS) if (limits[k] != null && u[k] != null && u[k] > limits[k]) warnings.push(LABEL[k] + ': ' + u[k] + ' in use, the licence allows ' + limits[k] + '. Nothing is switched off; extend the licence with Citynet.');
    return { state: !v.ok ? 'invalid' : expired ? 'expired' : 'valid', licence_id: lic.licence_id || null, customer: lic.customer || null, edition: lic.edition || null, modules: Array.isArray(lic.modules) ? lic.modules : null,
      issued: lic.issued || null, expires: lic.expires || null, limits, usage: u, labels: LABEL, warnings, why: v.ok ? null : v.why };
  }
  function install(input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot install a licence: a person does');
    body(input || {});   // the request body must be a JSON object (400 otherwise); its one field is checked field by field below
    const lic = input && input.licence;
    if (!lic || typeof lic !== 'object' || Array.isArray(lic)) throw httpErr(400, 'licence: the licence document (JSON object) issued by Citynet is required');
    for (const k of ['customer', 'signature']) if (typeof lic[k] !== 'string' || !lic[k].trim() || lic[k].length > (k === 'signature' ? 200 : 120)) throw httpErr(400, 'licence.' + k + ' is required');
    if (lic.limits !== undefined && (typeof lic.limits !== 'object' || Array.isArray(lic.limits))) throw httpErr(400, 'licence.limits must be an object');
    for (const k of Object.keys(lic.limits || {})) { if (!LIMITS.includes(k)) throw httpErr(400, 'licence.limits.' + k + ' is not a known limit'); const v = lic.limits[k]; if (!unlimited(v) && !(Number.isInteger(v) && v >= 0)) throw httpErr(400, 'licence.limits.' + k + ' must be a whole number or "unlimited"'); }
    if (lic.expires !== undefined && lic.expires !== null && isNaN(Date.parse(lic.expires))) throw httpErr(400, 'licence.expires must be a date');
    if (lic.modules !== undefined && lic.modules !== null && !(Array.isArray(lic.modules) && lic.modules.every((m) => typeof m === 'string' && /^[a-z0-9-]{2,40}$/.test(m)))) throw httpErr(400, 'licence.modules must be a list of module ids or null');
    const v = verify(lic, readKey()); if (!v.ok) throw httpErr(400, 'licence.signature: ' + v.why);
    if (lic.servers !== undefined && !(Array.isArray(lic.servers) && lic.servers.every((x) => typeof x === 'string' && /^[0-9A-F-]{4,40}$/i.test(x)))) throw httpErr(400, 'licence.servers must be a list of server fingerprints');
    if (enforced && Array.isArray(lic.servers) && lic.servers.length && !lic.servers.map((x) => String(x).toUpperCase()).includes(FP)) throw httpErr(400, 'licence.servers: this licence is for other servers - this server is ' + FP);
    if (enforced && lic.expires && Date.parse(lic.expires) < now()) throw httpErr(400, 'licence.expires: this licence expired on ' + String(lic.expires).slice(0, 10));
    const prev = readLic();
    fs.writeFileSync(FILE + '.tmp', JSON.stringify(lic, null, 2), { mode: 0o640 }); fs.renameSync(FILE + '.tmp', FILE);
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'licence.install', target: String(lic.licence_id || lic.customer).slice(0, 80), detail: { customer: lic.customer, edition: lic.edition || null, expires: lic.expires || null, limits: lic.limits || {}, replaced: prev ? prev.licence_id || prev.customer || 'a licence' : null } });
    return status();
  }
  const _install = install;
  function installAndRefresh(input, who) { const r = _install(input, who); cache = null; const s = status(); if (opts.onInstall) opts.onInstall(readLic()); return s; }
  return { status, install: installAndRefresh, usage, verify: (lic) => verify(lic, readKey()), allowed, fingerprint: () => FP, enforced: () => enforced, licenceDoc: readLic };
}
function registerLicence(srv, app, L, opts = {}) {
  // the gate: refuses people on every route of this engine once the grace period is over (licence routes excepted)
  if (typeof srv.gate === 'function') srv.gate((ctx) => { const why = L.allowed(ctx); if (why) throw Object.assign(new Error(why), { status: 403, code2: 'licence' }); });
  // the SIEM verifies the same signed licence with the same built-in key: send it after an install and every 10 minutes
  const SYS = { user: 'system:itam-licence', role: 'admin', ip: '' };
  async function push() {
    const siem = app.discovery && app.discovery.siem; const doc = L.licenceDoc();
    if (!L.enforced() || !doc || !siem || typeof siem.call !== 'function') return { pushed: false };
    try { const r = await siem.call('POST', '/licence', SYS, { licence: doc }); return { pushed: !!(r && r.status >= 200 && r.status < 300), status: r && r.status }; }
    catch (e) { if (app.log && app.log.every) app.log.every('licence:push', 3600000, 'warn', 'licence: could not send the licence to the SIEM', { err: String(e.message).slice(0, 120) }); return { pushed: false }; }
  }
  L.push = push;
  if (!opts.noTimer) { const { guardOf } = require('./errors'); const tick = guardOf(app, 'licence.push', push); const t = setTimeout(tick, 30000); if (t.unref) t.unref(); const iv = setInterval(tick, 600000); if (iv.unref) iv.unref(); }
  srv.route('GET', '/licence', (ctx) => { ctx.need('viewer'); return L.status(); });
  srv.route('POST', '/licence', (ctx) => { ctx.need('admin'); const r = L.install(ctx.body, ctx.who); push().catch(() => { /* push() logs its own failure; the SIEM is sent the licence again every 10 minutes */ }); return r; }, { maxBody: 16384 });
}
module.exports = { createLicence, registerLicence, verify, payloadOf, LIMITS, fingerprintOf };
