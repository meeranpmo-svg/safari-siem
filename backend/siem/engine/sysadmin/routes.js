// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI Windows Server Administrator + AI Exchange Server Administrator API ({P} = /api/soc). ?role=windows|exchange.
 *   GET  {P}/sysadmin/overview?role=           viewer    servers, findings, health-check + helper + AI status
 *   GET  {P}/sysadmin/checks?role=             viewer    the read-only checks (no scripts)
 *   GET  {P}/sysadmin/targets?role=            viewer    servers + which logins are set (never values) + last check
 *   GET  {P}/sysadmin/targets/:id              viewer    one server: latest health results, findings
 *   POST {P}/sysadmin/targets                  admin     add / update (IT Asset Management adds servers here too)
 *   DELETE {P}/sysadmin/targets/:id            admin
 *   GET  {P}/sysadmin/profiles                 admin     login profiles: user + auth only
 *   PUT  {P}/sysadmin/profiles/:id             admin     {username, password, auth} | {remove:true} → secrets.json
 *   POST {P}/sysadmin/targets/:id/certificate  admin     read the WinRM HTTPS certificate (no login)
 *   POST {P}/sysadmin/targets/:id/certificate/trust {fingerprint}   DELETE {P}/sysadmin/targets/:id/certificate   admin
 *   POST {P}/sysadmin/targets/:id/check        operator  {check, params} run one read-only check (audited)
 *   POST {P}/sysadmin/targets/:id/poll         operator  run the health checks on this server now
 *   POST {P}/sysadmin/addresses/refresh        operator  read every server's own IPv4 addresses now (network check only; audited)
 *   GET  {P}/sysadmin/runs                     operator  who ran which check where
 *   POST {P}/sysadmin/ask                      analyst   {role, question, conversation?}
 *   GET  {P}/sysadmin/conversations?role=      analyst
 *   GET {P}/sysadmin/uat (viewer) · POST …/uat/items/:id (operator) · …/uat/signoff, …/uat/reset (admin) - engine/sysadmin/uat.js
 *   GET/POST {P}/sysadmin/changes (operator) · POST {P}/sysadmin/changes/:id/decide (admin) · /applied (operator, re-checks the server)
 */
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { createTargets } = require('./targets');
const { createRunner } = require('./runner');
const { createHealth } = require('./health');
const { createSysAI } = require('./ai');
const { createChanges } = require('../netops/changes');

const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const roleOf = (q) => (q && (q.role === 'exchange' || q.role === 'windows') ? q.role : undefined);

function createSysadmin(deps) {
  const { state, config, log, ch } = deps;
  const targets = createTargets({ state, config, log });
  const runner = createRunner({ targets, state, config, log, exec: deps.sysadminExec });
  const health = createHealth({ targets, runner, state, config, log });
  const changes = createChanges({ state, log, collection: 'sysadmin_changes', prefix: 'SCHG', execution: 'manual — the SIEM never changes servers' });
  const N = deps.netopsInstance || deps.netops, availability = N && N.availability;
  const db = (config && config.clickhouse && config.clickhouse.database) || 'siem';
  const ai = createSysAI({ config, log, state, sdk: deps.anthropicSdk, tools: { targets, runner, health, changes, ch, db, availability } });
  return { targets, runner, health, changes, ai };
}

function register(api, deps) {
  if (!deps.state) throw new Error('sysadmin needs deps.state');
  const P = prefixOf(deps), S = deps.sysadmin || createSysadmin(deps);
  deps.sysadminFindings = (role) => health.findings({ role });   // read by the infrastructure manager's questions to the teams
  deps.sysadminInstance = S;   // shared with the AI engineers' duty desk (duty/routes.js), registered after this
  const { targets, runner, health, changes, ai } = S;
  if (deps.config.sysadmin && deps.config.sysadmin.enabled === false) { /* routes stay, health checks off */ } else if (!deps.sysadmin) health.start();
  const atLeast = (ctx, r) => { if ((RANK[ctx.role] || 0) < RANK[r]) throw new HttpError(403, `requires ${r} role`); };
  const view = (t) => { const s = health.snapshot(t.id); return Object.assign({}, t, { logins: targets.loginSummary(t), login_profiles: t.logins || {}, certificate: targets.pin(t.id), last_check: s && s.at ? s.at : null, addresses: health.addresses(t.id) }); };

  api.route('GET', `${P}/sysadmin/overview`, wrap(deps, null, async (ctx) => {
    const role = roleOf(ctx.query) || 'windows', list = targets.list(role), F = health.findings({ role });
    return { role, servers: list.length, with_login: list.filter((t) => (t.roles || []).some((r) => targets.login(t, r))).length, checked: list.filter((t) => health.snapshot(t.id)).length,
      findings: F.slice(0, 60), by_severity: F.reduce((m, f) => (m[f.severity] = (m[f.severity] || 0) + 1, m), {}), health: health.stats(), helper: await runner.status(), ai: ai.status(),
      changes_pending: changes.list({ status: 'proposed' }).length, from_itam: list.filter((t) => t.source === 'itam').length };
  }));
  api.route('GET', `${P}/sysadmin/checks`, wrap(deps, null, (ctx) => ({ items: runner.catalogue(roleOf(ctx.query)) })));
  api.route('GET', `${P}/sysadmin/targets`, wrap(deps, null, (ctx) => { const role = roleOf(ctx.query), F = health.findings({ role }); return { items: targets.list(role).map((t) => Object.assign(view(t), { findings: F.filter((f) => f.server === t.id).length, worst: (F.find((f) => f.server === t.id) || {}).severity || null })) }; }));
  api.route('GET', `${P}/sysadmin/targets/:id`, wrap(deps, null, (ctx) => {
    const t = targets.get(ctx.params.id); if (!t) throw new HttpError(404, 'server not found');
    return { server: view(t), health: health.snapshot(t.id), findings: health.findings().filter((f) => f.server === t.id) };
  }));
  api.route('POST', `${P}/sysadmin/targets`, wrap(deps, 'admin', (ctx) => { const t = targets.put(body(ctx), ctx.user); audit(ctx, 'sysadmin.server.put', t.id, { ip: t.ip, roles: t.roles, source: t.source }); return view(t); }));
  api.route('DELETE', `${P}/sysadmin/targets/:id`, wrap(deps, 'admin', (ctx) => { const r = targets.remove(ctx.params.id, ctx.user); audit(ctx, 'sysadmin.server.remove', ctx.params.id); return r; }));
  api.route('GET', `${P}/sysadmin/profiles`, wrap(deps, 'admin', () => ({ items: targets.profiles() })));
  api.route('PUT', `${P}/sysadmin/profiles/:id`, wrap(deps, 'admin', (ctx) => { const b = body(ctx); const r = targets.setProfile(ctx.params.id, b.remove ? null : b, ctx.user); audit(ctx, 'sysadmin.profile.' + (b.remove ? 'remove' : 'set'), ctx.params.id, { auth: r ? r.auth : null }); return { profile: ctx.params.id, set: r }; }));
  api.route('POST', `${P}/sysadmin/targets/:id/certificate`, wrap(deps, 'admin', async (ctx) => { const r = await runner.readCertificate(ctx.params.id); audit(ctx, 'sysadmin.certificate.read', ctx.params.id, { fingerprint: r.fingerprint }); return r; }));
  api.route('POST', `${P}/sysadmin/targets/:id/certificate/trust`, wrap(deps, 'admin', (ctx) => { const r = runner.trustCertificate(ctx.params.id, body(ctx).fingerprint, ctx.user); audit(ctx, 'sysadmin.certificate.trust', ctx.params.id, { fingerprint: r.fingerprint }); return r; }));
  api.route('DELETE', `${P}/sysadmin/targets/:id/certificate`, wrap(deps, 'admin', (ctx) => { if (!targets.get(ctx.params.id)) throw new HttpError(404, 'server not found'); targets.clearPin(ctx.params.id); audit(ctx, 'sysadmin.certificate.remove', ctx.params.id); return { removed: true }; }));
  api.route('POST', `${P}/sysadmin/targets/:id/check`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx), c = runner.check(b.check);
    try { const r = await runner.run(ctx.params.id, b.check, b.params || {}, { by: ctx.user, via: 'portal' }); audit(ctx, 'sysadmin.check', ctx.params.id, { check: b.check, personal: !!(c && c.personal), ok: true }); return r; }
    catch (e) { audit(ctx, 'sysadmin.check', ctx.params.id, { check: String(b.check || '').slice(0, 40), ok: false, error: String(e.message).slice(0, 200) }); throw e; }
  }));
  api.route('POST', `${P}/sysadmin/targets/:id/poll`, wrap(deps, 'operator', async (ctx) => { const t = targets.get(ctx.params.id); if (!t) throw new HttpError(404, 'server not found'); const s = await health.pollServer(t.id, { org: (t.roles || []).includes('exchange'), by: ctx.user }); return { at: s.at, findings: health.findings().filter((f) => f.server === t.id) }; }));
  api.route('POST', `${P}/sysadmin/addresses/refresh`, wrap(deps, 'operator', async (ctx) => {
    const items = await health.refreshAddresses(ctx.user);
    audit(ctx, 'sysadmin.addresses.refresh', 'servers', { servers: items.length, ok: items.filter((x) => x.status === 'ok').length, no_login: items.filter((x) => x.status === 'no-login').length });
    return { items };
  }));
  api.route('GET', `${P}/sysadmin/runs`, wrap(deps, 'operator', (ctx) => ({ items: runner.log(Number((ctx.query || {}).limit) || 100) })));
  api.route('POST', `${P}/sysadmin/ask`, wrap(deps, null, async (ctx) => {
    atLeast(ctx, 'analyst'); const b = body(ctx);
    // external AI switched off for this administrator (duty policy ai_off, AI Engineering Team)
    if (deps.dutyInstance && typeof deps.dutyInstance.aiAllowed === 'function' && !deps.dutyInstance.aiAllowed(b.role === 'exchange' ? 'exchange' : 'windows')) throw new HttpError(503, 'external AI is switched off for this engineer (AI Engineering Team → Duty policy → External AI per engineer)');
    const r = await ai.ask({ role: b.role, question: b.question, conversation: b.conversation, user: ctx.user || '', userRole: ctx.role });
    audit(ctx, 'sysadmin.ai.ask', r.conversation, { role: b.role, steps: r.steps.length, chars: String(b.question || '').length }); return r;
  }), { anyRole: 'a question to the AI administrators - they propose, never change a server' });
  api.route('GET', `${P}/sysadmin/conversations`, wrap(deps, null, (ctx) => { atLeast(ctx, 'analyst'); return { items: ai.conversations(ctx.user || '', roleOf(ctx.query) || 'windows') }; }));
  api.route('GET', `${P}/sysadmin/changes`, wrap(deps, null, (ctx) => { const role = roleOf(ctx.query), ids = role ? new Set(targets.list(role).map((t) => t.id)) : null; return { items: changes.list({ status: (ctx.query || {}).status }).filter((c) => !ids || ids.has(c.device)) }; }));
  api.route('POST', `${P}/sysadmin/changes`, wrap(deps, 'operator', (ctx) => { const b = body(ctx), t = targets.find(b.server || b.device); if (!t) throw new HttpError(400, 'server required'); const p = changes.propose(Object.assign({}, b, { device: t.id, source: 'user' }), ctx.user); audit(ctx, 'sysadmin.change.propose', p.id, { server: t.id }); return p; }));
  // who approves: the human approvers of the AI Windows Server / Exchange Server Administrator (by the server's roles)
  const sysScope = (ctx) => { const c = changes.get(ctx.params.id), t = c && targets.get(c.device), r = (t && t.roles) || ['windows', 'exchange']; return 'approve:' + r.map((x) => 'eng:' + x).join('|'); };
  api.route('POST', `${P}/sysadmin/changes/:id/decide`, wrap(deps, sysScope, (ctx) => { const b = body(ctx); const c = changes.decide(ctx.params.id, b.decision, ctx.user, b.comment); audit(ctx, 'sysadmin.change.' + b.decision, c.id); return c; }));
  api.route('POST', `${P}/sysadmin/changes/:id/applied`, wrap(deps, 'operator', async (ctx) => {
    const c = changes.markApplied(ctx.params.id, ctx.user, body(ctx).note); audit(ctx, 'sysadmin.change.applied', c.id);
    const t = targets.get(c.device); if (!t) return c;
    try { await health.pollServer(t.id, { org: (t.roles || []).includes('exchange'), by: 'change-validation' }); const open = health.findings().filter((f) => f.server === t.id && /critical|high/.test(f.severity)); return changes.recordValidation(c.id, { ok: open.length === 0, summary: open.length ? `${open.length} high/critical finding(s) still open after the change` : 'server re-checked after the change: no high or critical findings', findings: open }); }
    catch (e) { return changes.recordValidation(c.id, { ok: false, summary: 'validation check failed: ' + e.message }); }
  }));  // Exchange hybrid migration workspace (engine/sysadmin/hybrid.js)
  S.hybrid = require('./hybrid').register(api, deps, S);
  S.uat = require('./uat').register(api, deps, S);   // UAT sign-off checklist (engine/sysadmin/uat.js)
}

module.exports = { register, createSysadmin };
