// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Platform licence on the SIEM ({P} = /api/soc). The licence is issued and signed by Citynet (Ed25519; tools/licence/licence-tool.js
 * in the shield repository) and installed in IT Asset Management (Platform Admin -> Modules & Solutions), which sends the SIGNED
 * document here; this engine verifies it itself with the issuer's public key built into the code (util/licence-pubkey.js), so a
 * forged or edited licence is refused here too. While that key is empty, licensing is not enforced.
 *   GET  {P}/licence        any signed-in user   state, this server's fingerprint, grace (no names)
 *   POST {P}/licence        admin                {licence} - verified (signature, this server if `servers` is set, not expired)   audited
 * Enforcement, the same rules as ITAM engine/licence.js: no licence / not verifying / expired / for other servers -> administrators
 * are warned for the grace period (licence.grace_days, default 90, max 90) from the first time it was seen; then PEOPLE are refused
 * by every API route below {P} except /licence. Log ingestion (/ingest, outside {P}), the collectors, detection, alerting and the
 * engines' own service identities keep running - a lapse never blinds the SOC.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

const DAY = 86400000, GRACE_DAYS = 90, MAX_GRACE = 90;   // a 90-day trial / grace period, the same as IT Asset Management
const BUILTIN_KEY = (() => { try { return require('../util/licence-pubkey').PUBLIC_KEY || ''; } catch (e) { return ''; /* no key in this build: not enforced */ } })();
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
// the same canonical form and fingerprint as sentra-itam engine/licence.js (the signature covers the licence minus `signature`)
const canon = (o) => JSON.stringify((function sort(v) { if (Array.isArray(v)) return v.map(sort); if (v && typeof v === 'object') return Object.keys(v).sort().reduce((r, k) => { r[k] = sort(v[k]); return r; }, {}); return v; })(o));
const payloadOf = (lic) => { const o = Object.assign({}, lic); delete o.signature; return canon(o); };
function fingerprintOf(hostname, machineId) {
  return crypto.createHash('sha256').update(String(hostname || '').toLowerCase() + '|' + String(machineId || '')).digest('hex').slice(0, 16).toUpperCase().replace(/(.{4})(?=.)/g, '$1-');
}
function readMachineId() {
  for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) { try { const v = fs.readFileSync(f, 'utf8').trim(); if (v) return v; } catch (e) { /* not on this system: try the next file */ } }
  return '';
}
function verify(lic, pub) {
  if (!lic || typeof lic !== 'object' || Array.isArray(lic) || typeof lic.signature !== 'string') return 'the licence carries no signature';
  try { return crypto.verify(null, Buffer.from(payloadOf(lic)), crypto.createPublicKey(pub), Buffer.from(lic.signature, 'base64')) ? null : 'the signature does not match - the licence was not issued by Citynet or was changed'; }
  catch (e) { return 'the signature could not be checked'; }
}

function createSiemLicence(deps, opts = {}) {
  const now = opts.now || deps.now || Date.now;
  const key = opts.publicKey !== undefined ? opts.publicKey : BUILTIN_KEY;
  const FP = fingerprintOf(opts.hostname !== undefined ? opts.hostname : os.hostname(), opts.machineId !== undefined ? opts.machineId : readMachineId());
  const col = deps.state.collection('licence');
  function problemOf(lic) {
    if (!lic) return 'no licence has been received from IT Asset Management';
    const v = verify(lic, key); if (v) return v;
    if (Array.isArray(lic.servers) && lic.servers.length && !lic.servers.map((x) => String(x).toUpperCase()).includes(FP)) return 'the licence is for other servers (this SIEM server is ' + FP + ')';
    if (lic.expires && Date.parse(lic.expires) < now()) return 'the licence expired on ' + String(lic.expires).slice(0, 10);
    return '';
  }
  let cache = null;
  function status() {
    const t = now(); if (cache && t - cache.at < 30000) return cache.v;
    if (!key) { cache = { at: t, v: { enforced: false, gate: 'ok', fingerprint: FP, note: 'Licensing is not enforced in this build.' } }; return cache.v; }
    const doc = col.get('doc'), lic = doc ? doc.licence : null, st = col.get('state') || { id: 'state' };
    let reason = problemOf(lic);
    if (st.max_seen && t < st.max_seen - 2 * DAY) reason = reason || 'the server clock moved back - check the time (NTP)';
    const next = Object.assign({}, st, { id: 'state', max_seen: Math.max(st.max_seen || 0, t) });
    let v;
    if (!reason) { delete next.first_problem; v = { enforced: true, gate: 'ok', fingerprint: FP, licence: { licence_id: lic.licence_id || null, customer: lic.customer, expires: lic.expires || null } }; }
    else {
      if (!next.first_problem) next.first_problem = t;
      const until = next.first_problem + Math.min(MAX_GRACE, Math.max(0, Number(lic && lic.grace_days) || GRACE_DAYS)) * DAY;
      v = { enforced: true, gate: t < until ? 'grace' : 'locked', reason, fingerprint: FP, problem_since: new Date(next.first_problem).toISOString(), grace_until: new Date(until).toISOString(), grace_days_left: Math.max(0, Math.ceil((until - t) / DAY)) };
    }
    if (next.first_problem !== st.first_problem || !st.max_seen || t - st.max_seen > 3600000) col.put(next);
    cache = { at: t, v }; return v;
  }
  function install(lic, who) {
    if (!key) throw new HttpError(409, 'licensing is not enforced in this build');
    if (!lic || typeof lic !== 'object' || Array.isArray(lic)) throw new HttpError(400, 'licence: the signed licence document is required');
    const why = problemOf(lic); if (why) throw new HttpError(400, 'licence: ' + why);
    col.put({ id: 'doc', licence: lic, at: new Date(now()).toISOString(), by: who });
    cache = null; return status();
  }
  function allowed(ctx) {
    const s = status(); if (s.gate !== 'locked') return null;
    if (!ctx.user || isService(ctx.user)) return null;
    if (/\/licence(\/|$)/.test(String(ctx.path || ''))) return null;
    return 'the platform licence is not valid (' + s.reason + ') - an administrator installs a licence from Citynet in Platform Administration -> Modules & Solutions';
  }
  return { status, install, allowed, fingerprint: () => FP };
}

function register(api, deps) {
  const P = prefixOf(deps);
  const L = deps.siemLicence || (deps.siemLicence = createSiemLicence(deps, deps.licenceOpts || {}));
  api.route('GET', `${P}/licence`, wrap(deps, null, (ctx) => ctx.ok(L.status())));
  api.route('POST', `${P}/licence`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx); const r = L.install(b && b.licence, ctx.user);
    audit(ctx, 'licence.install', String((b.licence && (b.licence.licence_id || b.licence.customer)) || '-').slice(0, 80), { gate: r.gate, fingerprint: r.fingerprint });
    return ctx.ok(r);
  }));
  if (typeof api.gate === 'function') api.gate((ctx) => L.allowed(ctx));
  return L;
}

module.exports = { register, createSiemLicence, payloadOf, fingerprintOf };
