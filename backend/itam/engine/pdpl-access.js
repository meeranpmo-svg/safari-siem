// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Sensitive-access log (PDPL Art. 19; Implementing Regulation Art. 26 - health data: tiered access, every stage documented).
 *
 * The claims, medical-review and fraud systems SEND who opened which record and why (one key per sending system, admin,
 * shown once, stored as sha256). The platform never reads those systems. Each event is appended to a hash-chained journal
 * (<store>/access-YYYYMM.jsonl) - the evidence; per user per day counters and the exceptions live in the store.
 * The rules are Python (pyengine/pdpl_access.py): which events are exceptions (sensitive record with no purpose, "other"
 * with no reason, fraud investigation with no case reference, export / print of sensitive data, deletion) and which
 * user-days are indicators (volume far above the person's own pattern, many sensitive exports).
 * Exceptions and indicators are leads, not proof: a reviewer (a person, never the user concerned) records justified or
 * escalated with a note. Viewers are refused: the log names staff and claim references.
 *
 *   POST /agent/access/events            Bearer access key  {events: [{at, user, record_ref, action, purpose?, reason?, case_ref?, sensitive?, categories?}]} (<= 500)
 *   GET  /pdpl/access                    operator  summaries, exceptions, indicators, keys (audited: it names staff)
 *   POST /pdpl/access/exceptions/:id/review   operator  {decision: justified|escalated, note}   audited
 *   POST /pdpl/access/indicators/review       operator  {id, decision, note}                    audited
 *   POST /pdpl/access/settings           admin     {min_volume, multiplier, export_limit}     audited
 *   POST /pdpl/access/keys               admin     {name} → the key, once                     audited
 *   POST /pdpl/access/keys/:id/revoke    admin                                                audited
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DAY = 86400000, GENESIS = '0'.repeat(64), EXC_CAP = 5000, DAYS_KEPT = 400;
const ACTIONS = ['view', 'search', 'export', 'print', 'modify', 'delete'];
const PURPOSES = ['claim_handling', 'medical_review', 'fraud_investigation', 'underwriting', 'customer_service', 'complaint', 'legal', 'audit', 'other'];
const CATS = ['identity', 'contact', 'financial', 'health', 'credit', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage', 'location', 'employment', 'other'];
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));

function createAccess(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, dir = opts.dir || store.dir, py = opts.py;
  const meta = () => store.collection('pdpl_access_meta'), keysC = () => store.collection('pdpl_access_keys'), daysC = () => store.collection('pdpl_access_days');
  const excC = () => store.collection('pdpl_access_exc'), revC = () => store.collection('pdpl_access_rev');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || 'system', ip: who.ip || '', action, target, detail }); };
  async function rules(op, body) {
    const r = await py.call(op, body);
    if (!r || r.ok === false) {
      if (app.log && app.log.every) app.log.every('pdpl:access-py', 300000, 'error', 'sensitive-access rules (Python) did not answer', { op, cls: r && r.error_class });
      throw httpErr(409, 'The access-log rules run in Python and Python did not answer (' + ((r && r.error_class) || 'no answer') + ') - run the update so pyengine is installed');
    }
    return r;
  }

  // ---- append-only, hash-chained journal (the evidence)
  const file = (t) => path.join(dir, 'access-' + new Date(t).toISOString().slice(0, 7).replace('-', '') + '.jsonl');
  function append(rec) {
    const head = meta().get('head') || { seq: 0, hash: GENESIS };
    const e = Object.assign({ seq: head.seq + 1, prev: head.hash }, rec);
    e.hash = sha256(e.prev + '\n' + JSON.stringify(Object.assign({}, e, { hash: undefined })));
    fs.appendFileSync(file(rec.recorded), JSON.stringify(e) + '\n', { mode: 0o600 });
    meta().put({ id: 'head', seq: e.seq, hash: e.hash });
    return e;
  }
  function verify() {
    let prev = GENESIS, n = 0;
    const files = fs.readdirSync(dir).filter((f) => /^access-\d{6}\.jsonl$/.test(f)).sort();
    for (const f of files) for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
      if (!line) continue; n++;
      let e; try { e = JSON.parse(line); } catch (err) { return { ok: false, length: n, broken_at: n, why: 'entry ' + n + ' is not readable' }; }
      if (e.prev !== prev || e.seq !== n || sha256(e.prev + '\n' + JSON.stringify(Object.assign({}, e, { hash: undefined }))) !== e.hash) return { ok: false, length: n, broken_at: n, why: 'entry ' + n + ' does not match the chain' };
      prev = e.hash;
    }
    const head = meta().get('head');
    if (head && (head.seq !== n || head.hash !== prev)) return { ok: false, length: n, broken_at: n + 1, why: 'entries missing at the end' };
    return { ok: true, length: n };
  }

  // ---- keys (one per sending system)
  function issueKey(b, who) {
    const key = 'ak_' + crypto.randomBytes(24).toString('hex');
    let n = keysC().size() + 1, id = 'AK-' + String(n).padStart(3, '0'); while (keysC().get(id)) id = 'AK-' + String(++n).padStart(3, '0');
    keysC().put({ id, name: b.name, sha256: sha256(key), created_by: who.user, created_at: new Date(now()).toISOString(), revoked_at: null });
    audit(who, 'pdpl.access.key.issue', id, { name: b.name });
    return { id, name: b.name, key, note: 'Shown once. Give it to the system that sends its access log; it is stored as a hash only.' };
  }
  function revokeKey(id, who) {
    const k = keysC().get(id); if (!k) throw httpErr(404, 'no access-log key ' + id);
    if (k.revoked_at) throw httpErr(409, id + ' is already revoked');
    keysC().put(Object.assign({}, k, { revoked_at: new Date(now()).toISOString(), revoked_by: who.user }));
    audit(who, 'pdpl.access.key.revoke', id, { name: k.name });
    return { id, revoked: true };
  }
  function authenticate(bearer) {
    if (!bearer || !/^ak_[0-9a-f]{48}$/.test(bearer)) return null;
    const h = Buffer.from(sha256(bearer), 'hex');
    return keysC().all().find((x) => !x.revoked_at && crypto.timingSafeEqual(Buffer.from(x.sha256, 'hex'), h)) || null;
  }
  const keys = () => keysC().all().map((k) => ({ id: k.id, name: k.name, created_by: k.created_by, created_at: k.created_at, created_ms: Date.parse(k.created_at), revoked_at: k.revoked_at, last_used: k.last_used || null, events: k.events || 0 }));

  // ---- the machine API: events already validated one by one at the boundary
  async function ingest(k, events) {
    const t = now(), types = (await rules('pdpl.access_classify', { events })).types;
    let excN = 0;
    events.forEach((ev, i) => {
      const e = append(Object.assign({ recorded: t, source: k.id, system: k.name }, ev));
      const day = ev.at.slice(0, 10), uid = day + '|' + ev.user.toLowerCase(), d = daysC().get(uid) || { id: uid, day, user: ev.user, n: 0, sensitive: 0, exports: 0, no_purpose: 0, systems: {} };
      d.n++; if (ev.sensitive) d.sensitive++; if (ev.sensitive && (ev.action === 'export' || ev.action === 'print')) d.exports++; if (!ev.purpose) d.no_purpose++;
      d.systems = Object.assign({}, d.systems, { [k.name]: (d.systems[k.name] || 0) + 1 });
      daysC().put(d);
      if (types[i] && types[i].length) {
        excN++;
        excC().put({ id: 'AX-' + e.seq, seq: e.seq, at: ev.at, recorded: t, user: ev.user, record_ref: ev.record_ref, action: ev.action, purpose: ev.purpose || null, reason: ev.reason || '', case_ref: ev.case_ref || '',
          sensitive: !!ev.sensitive, categories: ev.categories || [], system: k.name, types: types[i], status: 'open' });
      }
    });
    keysC().put(Object.assign({}, k, { last_used: new Date(t).toISOString(), events: (k.events || 0) + events.length }));
    prune();
    return { accepted: events.length, exceptions: excN, first_seq: (meta().get('head').seq - events.length + 1) };
  }
  // bounded store: exceptions beyond the cap drop the oldest REVIEWED first; day counters older than DAYS_KEPT go (the journal keeps everything)
  function prune() {
    const all = excC().all();
    if (all.length > EXC_CAP) {
      const done = all.filter((x) => x.status !== 'open').sort((a, b) => a.seq - b.seq);
      for (const x of done.slice(0, all.length - EXC_CAP)) excC().remove(x.id);
    }
    const cut = new Date(now() - DAYS_KEPT * DAY).toISOString().slice(0, 10);
    for (const d of daysC().all((x) => x.day < cut)) daysC().remove(d.id);
  }

  const settings = () => meta().get('settings') || {};
  async function view(who) {
    const exc = excC().all().sort((a, b) => (a.status === 'open') === (b.status === 'open') ? b.seq - a.seq : a.status === 'open' ? -1 : 1);
    const rev = {}; for (const r of revC().all()) rev[r.id] = r;
    const r = await rules('pdpl.access_view', { days: daysC().all(), exceptions: exc, reviews: rev, keys: keys(), settings: settings(), now: now() });
    audit(who, 'pdpl.access.view', 'access-log', { exceptions_open: r.totals.exceptions_open, indicators_open: r.totals.indicators_open });
    return Object.assign(r, { exceptions: exc.slice(0, 200), keys: keys(), chain: verify(), api: { events: 'POST /agent/access/events', auth: 'Authorization: Bearer <access key>', max: 500, actions: ACTIONS, purposes: PURPOSES } });
  }
  async function findings() {
    if (!keysC().size() && !excC().size()) return [];
    const rev = {}; for (const r of revC().all()) rev[r.id] = r;
    const r = await rules('pdpl.access_view', { days: daysC().all(), exceptions: excC().all(), reviews: rev, keys: keys(), settings: settings(), now: now() });
    const ch = verify();
    return r.findings.concat(ch.ok ? [] : [{ key: 'access:chain', severity: 'critical', title: 'The sensitive-access journal fails its integrity check at entry ' + ch.broken_at, evidence: [ch.why], requirement: 'P-14',
      recommendation: 'Treat as an incident: the access evidence was altered. Restore from backup and investigate who changed the store.' }]);
  }

  function reviewer(who, user) {
    if (isService(who.user)) throw httpErr(403, 'a person reviews access, not a service or AI identity');
    if (String(who.user).toLowerCase() === String(user).toLowerCase()) throw httpErr(403, 'four-eyes: you cannot review your own access');
  }
  function reviewException(id, b, who) {
    const x = excC().get(id); if (!x) throw httpErr(404, 'no access exception ' + id);
    if (x.status !== 'open') throw httpErr(409, id + ' was already reviewed (' + x.status + ' by ' + x.review.by + ')');
    reviewer(who, x.user);
    const rec = Object.assign({}, x, { status: b.decision, review: { by: who.user, role: who.role, at: new Date(now()).toISOString(), note: b.note } });
    excC().put(rec);
    audit(who, 'pdpl.access.exception.review', id, { decision: b.decision, user: x.user, types: x.types });
    return rec;
  }
  async function reviewIndicator(b, who) {
    const [day, user] = b.id.split('|');
    const rev = {}; for (const r of revC().all()) rev[r.id] = r;
    const r = await rules('pdpl.access_view', { days: daysC().all(), exceptions: [], reviews: rev, keys: [], settings: settings(), now: now() });
    const i = r.indicators.find((x) => x.id === b.id); if (!i) throw httpErr(404, 'no access indicator ' + b.id + ' (indicators cover the last 30 days)');
    if (i.status !== 'open') throw httpErr(409, b.id + ' was already reviewed (' + i.status + ')');
    reviewer(who, i.user);
    const rec = { id: b.id, day, user, decision: b.decision, by: who.user, role: who.role, at: new Date(now()).toISOString(), note: b.note, why: i.why };
    revC().put(rec);
    audit(who, 'pdpl.access.indicator.review', b.id, { decision: b.decision, user: i.user, type: i.type });
    return rec;
  }
  function putSettings(b, who) {
    const prev = settings(), next = Object.assign({}, prev, b, { id: 'settings', by: who.user, at: new Date(now()).toISOString() });
    meta().put(next);
    audit(who, 'pdpl.access.settings', 'settings', { min_volume: next.min_volume, multiplier: next.multiplier, export_limit: next.export_limit, previous: { min_volume: prev.min_volume, multiplier: prev.multiplier, export_limit: prev.export_limit } });
    return next;
  }
  return { now, ingest, view, findings, verify, issueKey, revokeKey, authenticate, keys, reviewException, reviewIndicator, putSettings, ACTIONS, PURPOSES };
}

function registerAccessRoutes(srv, app, A) {
  const { body, param } = require('./check');
  const DTZ = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;
  srv.route('POST', '/access/events', async (ctx) => {
    const k = A.authenticate(ctx.bearer()); if (!k) throw httpErr(401, 'invalid or revoked access-log key');
    const evs = ctx.body && ctx.body.events;
    if (!Array.isArray(evs) || !evs.length) throw httpErr(400, 'events must be a non-empty list');
    if (evs.length > 500) throw httpErr(400, 'events: at most 500 per call');
    const t = A.now(), ok = [];
    evs.forEach((e, i) => {
      try {
        const v = body(e).str('at', { required: true, max: 30, re: DTZ, msg: 'at must be an ISO date-time with a zone' })
          .str('user', { required: true, max: 80, re: /^[A-Za-z0-9._@\\-]+$/, msg: 'user must be the user name in the sending system' })
          .str('record_ref', { required: true, max: 80, re: /^[A-Za-z0-9][A-Za-z0-9 ._/#-]*$/, msg: 'record_ref must be the claim / policy / case number' })
          .oneOf('action', A.ACTIONS, { required: true }).oneOf('purpose', A.PURPOSES).str('reason', { max: 300 }).str('case_ref', { max: 80 }).bool('sensitive').list('categories', { item: CATS, unique: true, max: 13 }).done();
        const at = Date.parse(v.at);
        if (at > t + 300000 || at < t - 30 * DAY) throw httpErr(400, 'at must be within the last 30 days (and not in the future)');
        v.at = new Date(at).toISOString();
        ok.push(v);
      } catch (err) { throw httpErr(400, 'events[' + i + ']: ' + err.message); }
    });
    return A.ingest(k, ok);
  }, { agent: true });
  srv.route('GET', '/pdpl/access', (ctx) => { ctx.need('operator'); return A.view(ctx.who); });
  srv.route('POST', '/pdpl/access/exceptions/:id/review', (ctx) => {
    ctx.need('operator');
    const id = param(ctx.params.id, 'id'); if (!/^AX-\d{1,12}$/.test(id)) throw httpErr(400, 'id must be an access exception id (AX-n)');
    return A.reviewException(id, body(ctx.body).oneOf('decision', ['justified', 'escalated'], { required: true }).str('note', { required: true, min: 10, max: 500 }).done(), ctx.who);
  });
  srv.route('POST', '/pdpl/access/indicators/review', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', { required: true, max: 120, re: /^\d{4}-\d{2}-\d{2}\|[a-z0-9._@\\-]+\|(volume|exports)$/, msg: 'id must be an indicator id (day|user|type)' })
      .oneOf('decision', ['justified', 'escalated'], { required: true }).str('note', { required: true, min: 10, max: 500 }).done();
    return A.reviewIndicator(b, ctx.who);
  });
  srv.route('POST', '/pdpl/access/settings', (ctx) => {
    ctx.need('admin');
    return A.putSettings(body(ctx.body).int('min_volume', { min: 5, max: 100000 }).num('multiplier', { min: 1.5, max: 20 }).int('export_limit', { min: 1, max: 10000 }).done(), ctx.who);
  });
  srv.route('POST', '/pdpl/access/keys', (ctx) => { ctx.need('admin'); return A.issueKey(body(ctx.body).str('name', { required: true, max: 80, re: /^[A-Za-z0-9 ._()&-]+$/, msg: 'name must be the system name' }).done(), ctx.who); });
  srv.route('POST', '/pdpl/access/keys/:id/revoke', (ctx) => {
    ctx.need('admin');
    const id = param(ctx.params.id, 'id'); if (!/^AK-\d{3,}$/.test(id)) throw httpErr(400, 'id must be an access-log key id (AK-nnn)');
    return A.revokeKey(id, ctx.who);
  });
}

module.exports = { createAccess, registerAccessRoutes, ACTIONS, PURPOSES };
