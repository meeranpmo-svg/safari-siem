// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Shadow AI DLP API (dashboards Shadow AI DLP page) - engine/soc/shadow-ai.js. {P} = config.api_prefix || '/api/soc'.
 *   GET  {P}/shadow-ai/discovery          any role   ?hours=24|168|720  AI apps in use (names only for operator / admin), audited
 *   GET  {P}/shadow-ai/signals            any role   ?hours=            DLP incidents to AI apps, uploads, policy gaps, audited
 *   GET  {P}/shadow-ai/register           any role   the catalog with each app's status, owner, allowed data classes
 *   GET  {P}/shadow-ai/requests           analyst    ?status=pending|approved|rejected  register change requests
 *   POST {P}/shadow-ai/requests           operator   {app, reason, status?, owner?, allowed_classes?, review_by?, note?, name?, vendor?, category?, domains?}
 *   POST {P}/shadow-ai/requests/:id/decide  approve:security (administrator or a security approver; a person; never the requester)
 *                                         {decision: approve|reject, comment?}
 *   GET  {P}/shadow-ai/blocklist          operator   ?format=txt|csv|json  the blocked apps' domains for the firewall (a person loads it), audited
 *   POST {P}/shadow-ai/cases              operator   {kind: dlp|upload|gap, app, who?, incident_id?, detail?, note?} → SOC case (one per kind / app / person / day)
 *   GET  {P}/shadow-ai/settings           analyst    POST {P}/shadow-ai/settings  admin {upload_mb, auto_enabled, auto_dlp_left, auto_gaps, mode, keywords, heartbeat_min}
 *   GET  {P}/shadow-ai/extension          operator   extension coverage (versions, users, actions), the policy it receives, token set or not
 *   POST {P}/shadow-ai/extension/token    admin      create / replace the ingest token: shown ONCE, stored as SHA-256 in secrets.json (sealed)
 * Browser extension (outside /api/soc, behind nginx /ingest/, authenticated by the ingest token in X-Sentra-Token):
 *   GET  /ingest/ai-dlp/policy            the apps, their status and allowed classes, the mode and keywords
 *   POST /ingest/ai-dlp/events            {events: [{ts, app, host, action, channel, kinds{kind:n}, classes[], user, device, ext_version, file_type}]}
 *                                         metadata only (no text field exists); max 200 per request, 256 KB; 120 requests a minute per address
 * Background: every 15 minutes guard('shadow-ai.auto-cases') opens the automatic cases (settings), rescheduled in finally.
 */
const crypto = require('node:crypto');
const { body: check, param } = require('../util/check');
const { guard } = require('../util/errors');
const { tokenOk } = require('../collect/http-ingest');
const SF = require('../secretfile');
const { finalise } = require('../schema');
const S = require('./shadow-ai');
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');

const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
const ACTIONS = ['blocked', 'warned', 'sent_after_warning', 'page_blocked', 'heartbeat'];
const CHANNELS = ['paste', 'submit', 'file', 'navigate'];
const USER_RE = /^[A-Za-z0-9._@\\ -]{1,120}$/, DEVICE_RE = /^[A-Za-z0-9._-]{1,64}$/;
const MAX_BODY = 256 * 1024, MAX_ITEMS = 200, PER_MIN = 120, FAIL_PER_MIN = 30;
let TIMER = null;

function register(api, deps) {
  if (!deps.state) throw new Error('shadow AI needs deps.state');
  const P = prefixOf(deps), now = deps.now || Date.now, config = deps.config || {};
  const log = deps.log && deps.log.child ? deps.log.child({ mod: 'shadow-ai' }) : (deps.log || { info() {}, warn() {}, error() {}, every() {} });
  const secPath = deps.secretsPath || (config._paths && config._paths.secrets);
  const secrets = () => (config.secrets && config.secrets.shadow_ai) || {};
  const emit = deps.emitEvent || ((ev) => deps.pipeline.emit(finalise(ev, { rts: now() })));
  const X = deps.shadowAi || S.createShadowAi({ ch: deps.ch, state: deps.state, config, log, now, cases: deps.cases, emit, secrets });
  deps.shadowAi = X;
  const named = (ctx) => (RANK[String(ctx.role || '').toLowerCase()] || 0) >= RANK.operator;
  const hoursQ = (ctx) => check(ctx.query || {}).oneOf('hours', ['24', '168', '720']).done();

  api.route('GET', `${P}/shadow-ai/discovery`, wrap(deps, null, async (ctx) => {
    const q = hoursQ(ctx), r = await X.discovery(q.hours || 168, named(ctx));
    audit(ctx, 'shadow_ai.discovery.view', 'all', { hours: r.hours, named: named(ctx), apps: r.configured ? r.apps.length : 0 });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/shadow-ai/signals`, wrap(deps, null, async (ctx) => {
    const q = hoursQ(ctx), r = await X.signals(q.hours || 168, named(ctx));
    audit(ctx, 'shadow_ai.signals.view', 'all', { hours: r.hours, named: named(ctx), incidents: r.totals.incidents });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/shadow-ai/register`, wrap(deps, null, (ctx) => ctx.ok({ items: X.register(), statuses: S.STATUSES, classes: S.CLASSES.map((c) => ({ id: c, label: S.CLASS_LABEL[c] })), categories: S.CATEGORIES })));
  api.route('GET', `${P}/shadow-ai/requests`, wrap(deps, 'analyst', (ctx) => {
    const q = check(ctx.query || {}).oneOf('status', ['pending', 'approved', 'rejected']).done();
    return ctx.ok({ items: X.requests(q) });
  }));
  api.route('POST', `${P}/shadow-ai/requests`, wrap(deps, 'operator', (ctx) => {
    const b = check(ctx.body).str('app', { required: true, max: 48, re: S.APP_ID_RE, msg: 'app must be an app id from the catalog or custom:<name>' })
      .str('reason', { required: true, min: 5, max: 500 }).oneOf('status', S.STATUSES).str('owner', { max: 120 })
      .list('allowed_classes', { item: S.CLASSES, max: S.CLASSES.length, unique: true }).date('review_by').str('note', { max: 500 })
      .str('name', { max: 80 }).str('vendor', { max: 80 }).oneOf('category', S.CATEGORIES)
      .list('domains', { item: 'str', itemMax: 253, max: 20, unique: true })
      .rule((o) => (o.domains || []).map((d) => d.toLowerCase()).find((d) => !S.DOMAIN_RE.test(d)) ? 'domains must be host names such as chat.example.com' : '')
      .rule((o) => o.status === 'unreviewed' ? 'status unreviewed cannot be requested - choose sanctioned, tolerated or blocked' : '').done();
    if (b.domains) b.domains = b.domains.map((d) => d.toLowerCase());
    const r = X.request(b, ctx.user);
    audit(ctx, 'shadow_ai.request', b.app, { request: r.id, change: r.change, before: r.before, reason: b.reason });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/shadow-ai/requests/:id/decide`, wrap(deps, 'approve:security', (ctx) => {
    const id = param(ctx.params.id, 'id'), b = check(ctx.body).oneOf('decision', ['approve', 'reject'], { required: true }).str('comment', { max: 500 }).done();
    const r = X.decide(id, b.decision, ctx.user, b.comment);
    audit(ctx, 'shadow_ai.request.' + (b.decision === 'approve' ? 'approve' : 'reject'), r.app, { request: id, requested_by: r.requested_by, change: r.change, comment: b.comment || '' });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/shadow-ai/blocklist`, wrap(deps, 'operator', (ctx) => {
    const q = check(ctx.query || {}).oneOf('format', ['txt', 'csv', 'json'], { def: 'txt' }).done(), bl = X.blocklist();
    audit(ctx, 'shadow_ai.blocklist.export', q.format, { apps: bl.apps.map((a) => a.id), domains: bl.domains.length });
    if (q.format === 'json' || !ctx.res || typeof ctx.res.writeHead !== 'function') return ctx.ok(bl);
    const text = q.format === 'csv' ? 'domain,app\r\n' + bl.apps.flatMap((a) => a.domains.map((d) => d + ',"' + a.name.replace(/"/g, '""') + '"')).join('\r\n') + '\r\n'
      : '# Blocked AI apps (Zyberon Shadow AI DLP register) - one domain per line, for the firewall\'s external domain list\n' + bl.domains.join('\n') + '\n';
    const buf = Buffer.from(text, 'utf8'); ctx.sent = true;
    ctx.res.writeHead(200, { 'Content-Type': q.format === 'csv' ? 'text/csv; charset=utf-8' : 'text/plain; charset=utf-8', 'Content-Length': buf.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
      'Content-Disposition': `attachment; filename="blocked-ai-apps.${q.format}"` });
    ctx.res.end(buf); return undefined;
  }));
  api.route('POST', `${P}/shadow-ai/cases`, wrap(deps, 'operator', (ctx) => {
    const b = check(ctx.body).oneOf('kind', ['dlp', 'upload', 'gap'], { required: true }).str('app', { required: true, max: 48, re: S.APP_ID_RE, msg: 'app must be an app id' })
      .str('who', { max: 120, re: /^[A-Za-z0-9._@\\:-]{1,120}$/, msg: 'who must be a user name or IP' }).str('incident_id', { max: 80, re: /^[A-Za-z0-9._:-]{1,80}$/, msg: 'incident_id is not a valid id' })
      .str('detail', { max: 300 }).str('note', { max: 500 }).done();
    const r = X.openCase(b, ctx.user, false);
    audit(ctx, 'shadow_ai.case', r.case_id, { kind: b.kind, app: b.app, who: b.who || '', existed: r.existed });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/shadow-ai/settings`, wrap(deps, 'analyst', (ctx) => ctx.ok(X.settings())));
  api.route('POST', `${P}/shadow-ai/settings`, wrap(deps, 'admin', (ctx) => {
    const b = check(ctx.body).int('upload_mb', { min: 1, max: 10240 }).bool('auto_enabled').bool('auto_dlp_left').bool('auto_gaps').oneOf('mode', ['warn', 'block'])
      .list('keywords', { item: 'str', itemMax: 60, max: 100, unique: true }).int('heartbeat_min', { min: 15, max: 1440 })
      .rule((o) => (o.keywords || []).some((k) => k.length < 3) ? 'keywords must be at least 3 characters each' : '').done();
    const r = X.putSettings(b, ctx.user);
    audit(ctx, 'shadow_ai.settings', 'settings', { changed: r.changed, keywords: (r.settings.extension.keywords || []).length });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/shadow-ai/extension`, wrap(deps, 'operator', async (ctx) => ctx.ok(await X.extensionStatus())));
  api.route('POST', `${P}/shadow-ai/extension/token`, wrap(deps, 'admin', (ctx) => {
    if (!secPath) throw new HttpError(503, 'the secrets file path is unknown - the engine was not started with a secrets.json');
    const token = crypto.randomBytes(24).toString('base64url'), digest = 'sha256:' + crypto.createHash('sha256').update(token).digest('hex');
    let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const replaced = !!(sec.shadow_ai && sec.shadow_ai.ext_token);
    sec.shadow_ai = Object.assign({}, sec.shadow_ai || {}, { ext_token: digest, ext_token_created: now() });
    require('../onboard/store').writeJsonAtomic(secPath, sec);   // sealed at rest (secretfile.js)
    if (!config.secrets) Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
    config.secrets.shadow_ai = sec.shadow_ai;
    audit(ctx, 'shadow_ai.extension.token', 'ai-dlp', { replaced });
    return ctx.ok({ token, replaced, note: 'Copy the token now: it is not shown again. Put it in the extension policy (managed storage "token"); the old token stops working.' });
  }));

  /* ---------------- the extension's ingest (its own token; rate limited before the body is read) */
  const win = new Map();
  const rate = (ip, kind, limit) => { const m = Math.floor(now() / 60000), w = win.get(ip) || { m, n: 0, fails: 0 }; if (w.m !== m) { w.m = m; w.n = 0; w.fails = 0; } w[kind]++; win.set(ip, w); if (win.size > 10000) win.clear(); return w[kind] <= limit; };
  const preAuth = (ctx) => {
    const given = ctx.headers['x-sentra-token'] || String(ctx.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!tokenOk(given, secrets().ext_token)) {
      log.every('ai-dlp-auth', 60000, 'warn', 'AI DLP ingest: rejected token', { ip: ctx.ip });
      if (!rate(ctx.ip, 'fails', FAIL_PER_MIN)) { ctx.fail(429, 'too many failed attempts - try again in a minute'); return false; }
      ctx.fail(401, 'invalid or missing token'); return false;
    }
    if (Number(ctx.headers['content-length'] || 0) > MAX_BODY) { ctx.fail(413, 'payload larger than 256 KB'); return false; }
    if (!rate(ctx.ip, 'n', PER_MIN)) { log.every('ai-dlp-rate', 60000, 'warn', 'AI DLP ingest: rate limit reached', { ip: ctx.ip }); ctx.fail(429, 'rate limit reached'); return false; }
    return true;
  };
  api.route('GET', '/ingest/ai-dlp/policy', (ctx) => ctx.ok(X.policy()), { preAuth });
  api.route('POST', '/ingest/ai-dlp/events', (ctx) => {
    let doc; try { doc = JSON.parse((ctx.rawBody || Buffer.alloc(0)).toString('utf8') || 'null', (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype' ? undefined : v)); } catch (e) { return ctx.fail(400, 'the body must be JSON'); }
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.events)) return ctx.fail(400, 'events must be a list');
    if (doc.events.length > MAX_ITEMS) return ctx.fail(413, `more than ${MAX_ITEMS} events in one request`);
    const items = [];
    try { doc.events.forEach((it, i) => items.push(validItem(it, i, now()))); } catch (e) { return ctx.fail(400, e.message); }
    return ctx.ok(Object.assign({ ok: true, policy_version: X.policy().version }, X.ingest(items, { ip: ctx.ip })));
  }, { raw: true, maxBody: MAX_BODY, preAuth, noDedup: true });

  const every = 15 * 60000;
  const tick = guard('shadow-ai.auto-cases', async () => {
    try { const r = await X.autoCases(); if (r.opened) log.info('shadow AI: automatic cases opened', { opened: r.opened }); } finally { if (!deps.noTimers) { TIMER = setTimeout(tick, every); if (TIMER.unref) TIMER.unref(); } }
  });
  if (!deps.noTimers) { if (TIMER) clearTimeout(TIMER); TIMER = setTimeout(tick, 180000); if (TIMER.unref) TIMER.unref(); }
  return X;
}

// one extension event: every field declared, anything else dropped; no field can carry text from the prompt
function validItem(it, i, t) {
  if (!it || typeof it !== 'object' || Array.isArray(it)) throw new HttpError(400, `events[${i}] must be an object`);
  let o;
  try {
    o = check(it).oneOf('action', ACTIONS, { required: true }).str('app', { max: 48, re: S.APP_ID_RE, msg: 'app must be an app id' })
      .str('host', { max: 253, re: S.DOMAIN_RE, msg: 'host must be a host name' }).oneOf('channel', CHANNELS).num('ts', { min: 0 })
      .str('user', { max: 120, re: USER_RE, msg: 'user must be an account name or e-mail' }).str('device', { max: 64, re: DEVICE_RE, msg: 'device must be a computer name' })
      .str('ext_version', { max: 20, re: /^\d{1,4}(\.\d{1,4}){0,3}$/, msg: 'ext_version must be a version number' }).str('file_type', { max: 10, re: /^[a-z0-9]{1,10}$/, msg: 'file_type must be a file extension' })
      .list('classes', { item: S.CLASSES, max: S.CLASSES.length, unique: true }).done();
  } catch (e) { throw new HttpError(400, `events[${i}].${e.message}`); }
  if (o.action !== 'heartbeat' && !o.host) throw new HttpError(400, `events[${i}].host is required`);
  if (it.kinds !== undefined) {
    if (!it.kinds || typeof it.kinds !== 'object' || Array.isArray(it.kinds)) throw new HttpError(400, `events[${i}].kinds must be an object of counts`);
    o.kinds = {};
    for (const [k, v] of Object.entries(it.kinds)) {
      if (!S.KIND_CLASS[k]) throw new HttpError(400, `events[${i}].kinds.${String(k).slice(0, 40)} is not a known kind`);
      if (!Number.isInteger(v) || v < 1 || v > 100000) throw new HttpError(400, `events[${i}].kinds.${k} must be a count`);
      o.kinds[k] = v;
    }
  }
  if (!(o.ts > t - 86400000 && o.ts < t + 300000)) o.ts = t;   // a wrong PC clock: the time it arrived
  return o;
}

module.exports = { register, validItem };
