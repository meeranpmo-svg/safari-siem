// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * Questions to the teams (engine/ops/questions.js), under the SOC prefix. Registered late: reads the DBA alert center, the AI Server
 * Administrators and the AI Network Engineer through deps at request time.
 *   GET  {P}/ops/issues                         any signed-in user   flagged problems (critical / high) by team, with the open question
 *   GET  {P}/ops/questions ?team=&status=open|answered|closed|all&mine=1     any signed-in user
 *   POST {P}/ops/questions                      operator, a person   {team, question, ref?, severity?, reply_to?}        audited
 *   POST {P}/ops/questions/:id/ack              the team (admin or the team's approver scope), not the asker              audited
 *   POST {P}/ops/questions/:id/answer {text}    the team, not the asker                                                    audited
 *   POST {P}/ops/questions/:id/follow-up {text} operator: the asker or an administrator                                     audited
 *   POST {P}/ops/questions/:id/close {note?}    operator: the asker or an administrator                                     audited
 *   PUT  {P}/ops/questions/config               admin  {baseVersion, sla_h:{critical, other}, teams:{dba|server|exchange|network:{emails[]}}}  audited
 */
const { body } = require('../util/check');
const { createQuestions, TEAMS } = require('./questions');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

const ADDR = /^[^\s@<>]+@[^\s@<>]+\.[a-z]{2,}$/i;

function register(api, deps) {
  if (!deps.state) return;
  const P = prefixOf(deps), cfg = deps.config || {};
  // the problem sources (dbaAlerts, sysadminFindings, netopsFindings) register after this module is made: read them from deps each time
  const live = new Proxy({}, { get: (t, k) => (k in t ? t[k] : deps[k]) });
  const Q = createQuestions(Object.assign(live, { mail: (m) => { const r = deps.reports; if (!r || !r.schedules) throw new Error('the SMTP relay (Reports) is not running'); return r.schedules.mail(m); }, portalUrl: cfg.portal_url || ('https://' + ZYB_ORG.portal_host + '/dashboards'), state: deps.state, now: deps.now, log: deps.log }));
  deps.opsQuestions = Q;
  const ID = /^Q-[A-F0-9]{6}$/;
  const idOf = (ctx) => { const id = String(ctx.params.id || ''); if (!ID.test(id)) throw new HttpError(400, 'id is not valid'); return id; };
  const who = (ctx) => ({ user: ctx.user, role: String(ctx.role || '').toLowerCase() });
  const teamScope = (ctx) => { const q = deps.state.collection('ops_questions').get(String(ctx.params.id || '')); return 'approve:' + (q && TEAMS[q.team] ? TEAMS[q.team].scope : 'infra'); };

  api.route('GET', `${P}/ops/issues`, wrap(deps, null, (ctx) => ctx.ok(Q.issues())));
  api.route('GET', `${P}/ops/questions`, wrap(deps, null, (ctx) => { const q = ctx.query || {};
    if (q.team && !TEAMS[q.team]) throw new HttpError(400, 'team must be one of ' + Object.keys(TEAMS).join(', '));
    return ctx.ok(Q.view({ team: q.team || '', status: q.status || 'open', mine: q.mine === '1' ? ctx.user : '' })); }));
  api.route('POST', `${P}/ops/questions`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx.body || {}).oneOf('team', Object.keys(TEAMS), { required: true }).str('question', { required: true, min: 10, max: 3000 }).str('ref', { max: 400 }).oneOf('severity', ['critical', 'high', 'medium', 'low']).str('reply_to', { max: 200 }).done();
    if (b.reply_to && !ADDR.test(b.reply_to)) throw new HttpError(400, 'reply_to: not a mail address');
    const q = Q.ask(b, who(ctx)); audit(ctx, 'ops.question.ask', q.id, { team: q.team, ref: q.issue ? q.issue.ref : null, severity: q.severity });
    return ctx.ok(q); }));
  api.route('POST', `${P}/ops/questions/:id/ack`, wrap(deps, teamScope, (ctx) => { const id = idOf(ctx); body(ctx.body || {}).done(); const q = Q.ack(id, who(ctx)); audit(ctx, 'ops.question.ack', id, { team: q.team }); return ctx.ok(q); }));
  api.route('POST', `${P}/ops/questions/:id/answer`, wrap(deps, teamScope, (ctx) => { const id = idOf(ctx), b = body(ctx.body || {}).str('text', { required: true, min: 3, max: 4000 }).done(); const q = Q.answer(id, b.text, who(ctx)); audit(ctx, 'ops.question.answer', id, { team: q.team, chars: b.text.length }); return ctx.ok(q); }));
  api.route('POST', `${P}/ops/questions/:id/follow-up`, wrap(deps, 'operator', (ctx) => { const id = idOf(ctx), b = body(ctx.body || {}).str('text', { required: true, min: 3, max: 3000 }).done(); const q = Q.followUp(id, b.text, who(ctx)); audit(ctx, 'ops.question.follow_up', id, { team: q.team }); return ctx.ok(q); }));
  api.route('POST', `${P}/ops/questions/:id/close`, wrap(deps, 'operator', (ctx) => { const id = idOf(ctx), b = body(ctx.body || {}).str('note', { max: 1000 }).done(); const q = Q.close(id, b.note, who(ctx)); audit(ctx, 'ops.question.close', id, { team: q.team }); return ctx.ok(q); }));
  api.route('PUT', `${P}/ops/questions/config`, wrap(deps, 'admin', (ctx) => {
    const raw = ctx.body || {}, b = body(raw).int('baseVersion', { min: 0 }).done(), out = { baseVersion: b.baseVersion };
    if (raw.sla_h != null) out.sla_h = body(raw.sla_h).int('critical', { min: 1, max: 72 }).int('other', { min: 1, max: 168 }).done();
    if (raw.teams != null) { if (typeof raw.teams !== 'object' || Array.isArray(raw.teams)) throw new HttpError(400, 'teams must be an object'); out.teams = {};
      for (const k of Object.keys(raw.teams)) { if (!TEAMS[k]) throw new HttpError(400, 'teams.' + k + ': unknown team'); const e = [].concat((raw.teams[k] || {}).emails || []).map((x) => String(x).trim().toLowerCase()).filter(Boolean);
        if (e.length > 20) throw new HttpError(400, 'teams.' + k + '.emails: up to 20'); const badA = e.find((x) => !ADDR.test(x)); if (badA) throw new HttpError(400, 'teams.' + k + '.emails: "' + badA.slice(0, 60) + '" is not a mail address'); out.teams[k] = { emails: [...new Set(e)] }; } }
    const r = Q.putConfig(out, who(ctx)); audit(ctx, 'ops.question.config', 'questions', { version: r.version, teams: out.teams ? Object.keys(out.teams) : [], sla: !!out.sla_h }); return ctx.ok(r); }));
}

module.exports = { register };
