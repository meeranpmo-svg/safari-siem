// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * DFIR API (engine/dfir/dfir.js + engine/dfir/forensics.js) — under the SOC prefix, same auth as the SOC routes.
 * Raw events, evidence and indicators name people and devices (PDPL): every read of them is analyst and above, and the
 * reads that query the event store are written to the audit trail.
 *   GET  {P}/dfir/overview                         any signed-in user   open IR cases, pending response approvals, collection queue
 *   GET  {P}/dfir/board                            any signed-in user   forensic cases, regulatory clocks, what needs attention, readiness
 *   GET  {P}/dfir/timeline ?entity=&type=&hours=&limit=   analyst      forensic super-timeline for a host / user / IP   audited (read)
 *   GET  {P}/dfir/triage   ?entity=&type=&hours=          analyst      triage rollup                                    audited (read)
 *   GET  {P}/dfir/analyse  ?entity=&type=&hours=          analyst      timeline + ML analysis (bursts, sessions, stages, first-seen, pivots, score)  audited
 *   GET  {P}/dfir/collect/catalog                  any signed-in user   the triage-collection catalogue
 *   GET  {P}/dfir/collections ?status=&case=       analyst              collection requests
 *   POST {P}/dfir/collect    {entity,type?,items[],case_id?,rationale}   operator                    audited
 *   POST {P}/dfir/collections/:id/decide {decision, note}                approver eng:dfir (four-eyes) audited
 *   GET  {P}/dfir/cases/:id                        analyst              overlay, clocks, evidence (chain verified), IOCs, collections, AI draft
 *   POST {P}/dfir/cases/:id                        operator             {type?, aware_at?, personal_data?, people_estimate?, regulators?, phase?, phase_note?}  audited
 *   POST {P}/dfir/cases/:id/notify                 operator             {regulator, ref, at?, note?} - a notification made outside the platform  audited
 *   POST {P}/dfir/cases/:id/hold                   operator             {reason} legal hold on                       audited
 *   POST {P}/dfir/cases/:id/hold/release           admin, not the placer {reason}                                     audited
 *   POST {P}/dfir/cases/:id/evidence               operator             {kind, description, sha256, sha1?, md5?, size_bytes?, source?, location, collected_at?, collected_by?, note?}  audited
 *   POST {P}/dfir/evidence/:ref/custody            operator             {action, to?, note?, sha256_observed?}        audited
 *   GET  {P}/dfir/evidence/:ref/verify             analyst              recompute the custody chain
 *   POST {P}/dfir/cases/:id/iocs                   operator             {type, value, note?, source?}                audited
 *   POST {P}/dfir/iocs/:id/retire                  operator             {reason}                                     audited
 *   GET  {P}/dfir/cases/:id/sightings ?days=       analyst              IOC sightings in the event store              audited (read)
 *   GET  {P}/dfir/cases/:id/stix                   analyst              STIX 2.1 bundle of the active IOCs            audited (export)
 *   GET  {P}/dfir/settings                         any signed-in user   reporting hours per regulator, evidence storage
 *   POST {P}/dfir/settings                         admin                                                              audited
 *   POST {P}/dfir/cases/:id/ask                    analyst              {question} the AI forensic analyst (a draft; budgeted)  audited
 *   POST {P}/dfir/cases/:id/ask/decide             operator, a person   {decision: add|discard}                       audited
 * Nothing here runs on an endpoint or contacts a regulator: the platform records what people did.
 */
const { createDfir } = require('./dfir');
const F = require('./forensics');
const { body } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

const ID = /^[A-Za-z0-9_.:-]{1,40}$/;
const SHA256 = /^[a-fA-F0-9]{64}$/, SHA1 = /^[a-fA-F0-9]{40}$/, MD5 = /^[a-fA-F0-9]{32}$/;

function register(api, deps) {
  if (!deps.search) return; // timeline/triage need the event store
  const P = prefixOf(deps);
  const d = createDfir(deps);
  deps.dfir = d;
  const fx = deps.cases && deps.state ? F.createForensics(Object.assign({}, deps, { dfir: d })) : null;
  deps.forensics = fx;
  const q = (ctx) => ctx.query || {};
  const idOf = (ctx, k = 'id') => { const v = String(ctx.params[k] || ''); if (!ID.test(v)) throw new HttpError(400, k + ' is not valid'); return v; };
  const need = () => { if (!fx) throw new HttpError(503, 'the SOC case store is not available on this SIEM'); return fx; };
  const who = (ctx) => ({ user: ctx.user, role: ctx.role });
  const entQ = (ctx) => {
    const b = body(q(ctx)).str('entity', { required: true, max: 200 }).oneOf('type', ['host', 'user', 'ip']).int('hours', { min: 1, max: 2160 }).int('limit', { min: 1, max: 5000 }).done();
    if (/["\\]/.test(b.entity)) throw new HttpError(400, 'entity must not contain quotes or backslashes');
    return b;
  };

  api.route('GET', `${P}/dfir/overview`, wrap(deps, null, (ctx) => ctx.ok(d.overview())));
  api.route('GET', `${P}/dfir/board`, wrap(deps, null, (ctx) => ctx.ok(need().board())));
  api.route('GET', `${P}/dfir/timeline`, wrap(deps, 'analyst', async (ctx) => {
    const b = entQ(ctx), r = await d.timeline(b);
    audit(ctx, 'dfir.timeline', b.entity, { type: r.type, hours: b.hours || 24, events: r.shown });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/dfir/triage`, wrap(deps, 'analyst', async (ctx) => {
    const b = entQ(ctx), r = await d.triage(b);
    audit(ctx, 'dfir.triage', b.entity, { type: r.type, hours: b.hours || 24, events: r.sampled });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/dfir/analyse`, wrap(deps, 'analyst', async (ctx) => {
    const b = entQ(ctx), r = await need().analyseEntity(b);
    audit(ctx, 'dfir.analyse', b.entity, { type: r.timeline.type, hours: b.hours || 24, events: r.analysis.events, score: r.analysis.score });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/dfir/collect/catalog`, wrap(deps, null, (ctx) => ctx.ok(d.collectCatalog())));
  api.route('GET', `${P}/dfir/collections`, wrap(deps, 'analyst', (ctx) => {
    const b = body(q(ctx)).oneOf('status', ['requested', 'approved', 'rejected', 'collected', 'cancelled']).str('case', { max: 40, id: true }).int('limit', { min: 1, max: 500 }).done();
    return ctx.ok(d.collections({ status: b.status, case_id: b.case, limit: b.limit }));
  }));
  api.route('POST', `${P}/dfir/collect`, wrap(deps, 'operator', (ctx) => {
    const b = body(ctx.body).str('entity', { required: true, max: 200 }).oneOf('type', ['host', 'user', 'ip']).list('items', { required: true, max: 30, item: 'id' })
      .str('case_id', { max: 40, id: true }).str('rationale', { required: true, max: 1000 }).done();
    const r = d.requestCollection(b, ctx.user);
    audit(ctx, 'dfir.collect.request', r.id, { entity: r.entity, items: r.items.length, case_id: r.case_id });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/dfir/collections/:id/decide`, wrap(deps, 'approve:eng:dfir', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('decision', ['approved', 'rejected', 'collected', 'cancelled'], { required: true }).str('note', { max: 1000 }).done();
    const r = d.decideCollection(id, b.decision, ctx.user, b.note);
    audit(ctx, 'dfir.collect.decide', id, { decision: r.decision });
    return ctx.ok(r);
  }));

  // ---------------- forensic case record
  api.route('GET', `${P}/dfir/cases/:id`, wrap(deps, 'analyst', (ctx) => ctx.ok(need().caseView(idOf(ctx)))));
  api.route('POST', `${P}/dfir/cases/:id`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx);
    const b = body(ctx.body).oneOf('type', F.TYPES).str('aware_at', { max: 40 }).bool('personal_data').int('people_estimate', { min: 0, max: 100000000 })
      .list('regulators', { max: 3, item: Object.keys(F.REGULATORS) }).oneOf('phase', F.PHASES).str('phase_note', { max: 1000 }).done();
    const r = need().update(id, b, ctx.user);
    audit(ctx, 'dfir.case.update', id, r.changed);
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/dfir/cases/:id/notify`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('regulator', ['sdaia'].concat(Object.keys(F.REGULATORS)), { required: true }).str('ref', { required: true, max: 120 }).str('at', { max: 40 }).str('note', { max: 1000 }).done();
    const r = need().notify(id, b, ctx.user);
    audit(ctx, 'dfir.case.notify', id, { regulator: b.regulator, ref: b.ref });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/dfir/cases/:id/hold`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).str('reason', { required: true, max: 500 }).done();
    const r = need().setHold(id, true, b.reason, ctx.user, ctx.role);
    audit(ctx, 'dfir.hold.place', id, { reason: b.reason });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/dfir/cases/:id/hold/release`, wrap(deps, 'admin', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).str('reason', { required: true, max: 500 }).done();
    const r = need().setHold(id, false, b.reason, ctx.user, String(ctx.role || '').toLowerCase());
    audit(ctx, 'dfir.hold.release', id, { reason: b.reason, placed_by: r.overlay.hold.by });
    return ctx.ok(r);
  }));

  // ---------------- evidence register
  api.route('POST', `${P}/dfir/cases/:id/evidence`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx);
    const b = body(ctx.body).oneOf('kind', F.EV_KINDS, { required: true }).str('description', { required: true, max: 1000 })
      .str('sha256', { required: true, re: SHA256, msg: 'sha256 must be 64 hexadecimal characters (the hash the collector computed)' })
      .str('sha1', { re: SHA1, msg: 'sha1 must be 40 hexadecimal characters' }).str('md5', { re: MD5, msg: 'md5 must be 32 hexadecimal characters' })
      .int('size_bytes', { min: 0, max: Number.MAX_SAFE_INTEGER }).str('source', { max: 200 }).str('location', { required: true, max: 300 })
      .str('collected_at', { max: 40 }).str('collected_by', { max: 120 }).str('note', { max: 1000 }).done();
    const r = need().addEvidence(id, b, ctx.user);
    audit(ctx, 'dfir.evidence.add', r.ref, { case_id: id, kind: r.kind, sha256: r.sha256 });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/dfir/evidence/:ref/custody`, wrap(deps, 'operator', (ctx) => {
    const ref = idOf(ctx, 'ref');
    const b = body(ctx.body).oneOf('action', F.CUSTODY.filter((a) => a !== 'collected'), { required: true }).str('to', { max: 200 }).str('note', { max: 1000 })
      .str('sha256_observed', { re: SHA256, msg: 'sha256_observed must be 64 hexadecimal characters' }).done();
    const r = need().custody(ref, b, ctx.user);
    audit(ctx, 'dfir.evidence.custody', ref, { action: b.action, to: b.to || '', integrity: r.integrity });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/dfir/evidence/:ref/verify`, wrap(deps, 'analyst', (ctx) => ctx.ok(need().verify(idOf(ctx, 'ref')))));

  // ---------------- indicators
  api.route('POST', `${P}/dfir/cases/:id/iocs`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('type', F.IOC_TYPES, { required: true }).str('value', { required: true, max: 2000 }).str('note', { max: 500 }).str('source', { max: 200 }).done();
    const r = need().addIoc(id, b, ctx.user);
    audit(ctx, 'dfir.ioc.add', r.id, { case_id: id, type: r.type, value: r.value });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/dfir/iocs/:id/retire`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).str('reason', { required: true, max: 500 }).done();
    const r = need().retireIoc(id, b.reason, ctx.user);
    audit(ctx, 'dfir.ioc.retire', id, { reason: b.reason });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/dfir/cases/:id/sightings`, wrap(deps, 'analyst', async (ctx) => {
    const id = idOf(ctx), b = body(q(ctx)).int('days', { min: 1, max: 90 }).done();
    const r = await need().sightings(id, b.days);
    audit(ctx, 'dfir.ioc.sightings', id, { days: r.days, iocs: r.items.length, seen: r.seen });
    return ctx.ok(r);
  }));
  // cases like this one (ml.js similar): shared entities, rules, indicators, techniques, type - and how each ended
  api.route('GET', `${P}/dfir/cases/:id/similar`, wrap(deps, 'analyst', (ctx) => {
    const id = idOf(ctx), r = need().similarCases(id);
    audit(ctx, 'dfir.similar', id, { compared: r.compared, matches: r.items.length });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/dfir/cases/:id/stix`, wrap(deps, 'analyst', (ctx) => {
    const id = idOf(ctx), r = need().stix(id);
    audit(ctx, 'dfir.ioc.stix', id, { indicators: r.objects.length - 1 });
    return ctx.ok(r);
  }));

  // ---------------- settings
  api.route('GET', `${P}/dfir/settings`, wrap(deps, null, (ctx) => ctx.ok(need().settings())));
  api.route('POST', `${P}/dfir/settings`, wrap(deps, 'admin', (ctx) => {
    let v = body(ctx.body);
    for (const k of Object.keys(F.REGULATORS)) v = v.int(k + '_hours', { min: 0, max: 720 }).str(k + '_basis', { max: 300 });
    const b = v.list('storage', { max: 20, item: 'str', itemMax: 200 }).done();
    const r = need().saveSettings(b, ctx.user);
    audit(ctx, 'dfir.settings', 'settings', b);
    return ctx.ok(r);
  }));

  // ---------------- AI forensic analyst
  api.route('POST', `${P}/dfir/cases/:id/ask`, wrap(deps, 'analyst', async (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).str('question', { required: true, max: 2000 }).done();
    const r = await need().ask(id, b.question, who(ctx));
    audit(ctx, 'dfir.ai.ask', id, { steps: r.steps.length, unverified: r.unverified, tokens: (r.usage.input_tokens || 0) + (r.usage.output_tokens || 0) });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/dfir/cases/:id/ask/decide`, wrap(deps, 'operator', (ctx) => {
    const id = idOf(ctx), b = body(ctx.body).oneOf('decision', ['add', 'discard'], { required: true }).done();
    const r = need().decideAsk(id, b.decision, who(ctx));
    audit(ctx, 'dfir.ai.decide', id, { decision: b.decision });
    return ctx.ok(r);
  }));
}

module.exports = { register };
