// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data subject request intake (PDPL Art. 4; Implementing Regulation Arts. 3-10) - requests arrive by themselves.
 *
 * The customer portal, the app and the call-centre system SEND each request here with their own reference, the request type
 * and how they checked the person (Nafath, Absher one-time code, ID seen in a branch ...). The platform then does the
 * legwork a privacy analyst would: records the request and starts the 30-day clock, routes it to the handler for that type,
 * accepts the channel's identity check as verification only when an administrator listed that method as strong, treats a
 * second identical request from the same person while one is open as the same request (one clock, one answer), flags a
 * repeat of a request answered in the last 180 days (only the DPO may refuse it), returns the acknowledgement the channel
 * shows the person (Arabic / English), and - only when an administrator switched it on - searches the confirmed identifier
 * columns for a verified requester at once (engine/pdpl-catalog.js correlate: read-only counts, systems found become tasks).
 * The rules are Python (pyengine/pdpl_intake.py). The identifier is used for that search and turned into a one-way code
 * (HMAC with a sealed pepper, vault purpose sentra-itam-dsar) to recognise the same person again; it is never stored, logged or
 * audited. Answering, refusing and extending stay with people on the Data Subject Requests page.
 *
 *   POST /agent/dsar/intake          Bearer intake key  {ref, type, channel, received?, identity_method?, id_type?, id_value?, systems?[], language?}
 *   GET  /pdpl/intake                operator  settings, keys (never the key), the intake log, findings
 *   POST /pdpl/intake/settings       admin     {default_assignee?, assignees{type: user}, strong_methods[], auto_search}   audited
 *   POST /pdpl/intake/keys           admin     {name} → the key, once                                                       audited
 *   POST /pdpl/intake/keys/:id/revoke admin                                                                                audited
 */
const crypto = require('node:crypto');

const DAY = 86400000;
const TYPES = ['access', 'copy', 'correction', 'destruction', 'withdraw_consent', 'objection', 'other'];
const CHANNELS = ['branch', 'call_centre', 'email', 'web', 'letter', 'app', 'other'];
const METHODS = ['nafath', 'absher_otp', 'policy_number_and_otp', 'registered_email', 'national_id_in_branch', 'none'];
const PER_KEY_PER_DAY = 500;   // a leaked key cannot flood the register
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const SYS = { user: 'system:dsar-intake', role: 'system', ip: '' };

function createIntake(app, PD, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || require('./discovery/vault').createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-dsar' });
  const meta = () => store.collection('pdpl_intake_meta'), keysC = () => store.collection('pdpl_intake_keys');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || 'system', ip: who.ip || '', action, target, detail }); };
  async function rules(op, body) { const r = await PD.rules(op, body); if (r && r.refuse) throw httpErr(r.refuse.status, r.refuse.error); return r; }

  let pepperCache = null;
  function pepper() {
    if (pepperCache) return pepperCache;
    const m = meta().get('pepper');
    if (m && m.enc) { pepperCache = Buffer.from(sealer.unseal('dsar-pepper', m.enc), 'hex'); return pepperCache; }
    const p = crypto.randomBytes(32);
    meta().put({ id: 'pepper', enc: sealer.seal('dsar-pepper', p.toString('hex')), created_at: new Date(now()).toISOString() });
    pepperCache = p; return p;
  }
  const subjectRef = (type, value) => crypto.createHmac('sha256', pepper()).update(type + ':' + String(value).replace(/\s+/g, '').toUpperCase()).digest('hex').slice(0, 40);
  const settings = () => { const s = meta().get('settings') || {}; return { default_assignee: s.default_assignee || null, assignees: s.assignees || {}, strong_methods: s.strong_methods || null, auto_search: !!s.auto_search, updated_by: s.updated_by, updated_at: s.updated_at }; };

  // ---- keys (one per sending system)
  function issueKey(b, who) {
    const key = 'dk_' + crypto.randomBytes(24).toString('hex');
    let n = keysC().size() + 1, id = 'DK-' + String(n).padStart(3, '0'); while (keysC().get(id)) id = 'DK-' + String(++n).padStart(3, '0');
    keysC().put({ id, name: b.name, sha256: sha256(key), created_by: who.user, created_at: new Date(now()).toISOString(), revoked_at: null, day: null, count: 0 });
    audit(who, 'pdpl.intake.key.issue', id, { name: b.name });
    return { id, name: b.name, key, note: 'Shown once. Give it to the system that takes the requests (customer portal, app, call centre); it is stored as a hash only.' };
  }
  function revokeKey(id, who) {
    const k = keysC().get(id); if (!k) throw httpErr(404, 'no intake key ' + id);
    if (k.revoked_at) throw httpErr(409, id + ' is already revoked');
    keysC().put(Object.assign({}, k, { revoked_at: new Date(now()).toISOString(), revoked_by: who.user }));
    audit(who, 'pdpl.intake.key.revoke', id, { name: k.name });
    return { id, revoked: true };
  }
  const keys = () => keysC().all().map((k) => ({ id: k.id, name: k.name, created_by: k.created_by, created_at: k.created_at, revoked_at: k.revoked_at, last_used: k.last_used || null }));
  function authenticate(bearer) {
    if (!bearer || !/^dk_[0-9a-f]{48}$/.test(bearer)) return null;
    const h = Buffer.from(sha256(bearer), 'hex');
    return keysC().all().find((x) => !x.revoked_at && crypto.timingSafeEqual(Buffer.from(x.sha256, 'hex'), h)) || null;
  }

  function setSettings(b, who) {
    const cur = settings(), next = { id: 'settings', default_assignee: b.default_assignee === undefined ? cur.default_assignee : b.default_assignee || null,
      assignees: b.assignees === undefined ? cur.assignees : b.assignees, strong_methods: b.strong_methods === undefined ? cur.strong_methods : b.strong_methods,
      auto_search: b.auto_search === undefined ? cur.auto_search : b.auto_search, updated_by: who.user, updated_at: new Date(now()).toISOString() };
    meta().put(next);
    audit(who, 'pdpl.intake.settings', 'intake', { default_assignee: next.default_assignee, assignees: Object.keys(next.assignees || {}).sort(), strong_methods: next.strong_methods, auto_search: next.auto_search, auto_search_was: cur.auto_search });
    return view();
  }
  async function view() {
    const out = await rules('pdpl.intake_view', { settings: settings(), keys: keys() });
    return Object.assign(out, { keys: keys(), catalog: !!PD.catalog });
  }
  async function findings() {
    if (!keysC().size()) return [];
    return (await rules('pdpl.intake_view', { settings: settings(), keys: keys() })).findings || [];
  }

  // ---- the machine API
  async function intake(k, b) {
    const t = now(), today = new Date(t).toISOString().slice(0, 10);
    const used = k.day === today ? k.count || 0 : 0;
    if (used >= PER_KEY_PER_DAY) throw httpErr(429, 'this key sent ' + PER_KEY_PER_DAY + ' requests today - contact the DPO if that is real');
    keysC().put(Object.assign({}, k, { day: today, count: used + 1, last_used: new Date(t).toISOString() }));
    if (b.received && Date.parse(b.received) > t + 300000) throw httpErr(400, 'received cannot be in the future');
    if (b.received && Date.parse(b.received) < t - 30 * DAY) throw httpErr(400, 'received is more than 30 days ago - record an old request on the Data Subject Requests page');
    const value = b.id_value || null; b.id_value = null;
    const sref = b.id_type && value ? subjectRef(b.id_type, value) : null;
    // the same reference sent again (a retry): the same request, nothing new
    const same = PD.records('dsr').find((r) => String(r.ref).toLowerCase() === String(b.ref).toLowerCase());
    if (same) {
      if (!same.intake || same.intake.source !== k.id) throw httpErr(409, 'reference ' + b.ref + ' is already used by another request');
      return answer(same, (same.intake && same.intake.ack) || null, { repeat_of_call: true }, b.language);
    }
    const history = sref ? PD.records('dsr').filter((r) => r.subject_ref === sref).map((r) => ({ id: r.id, ref: r.ref, type: r.type, stage: r.stage || (r.responded ? 'responded' : 'received'), received: r.received, responded: r.responded,
      due: r.received ? new Date(Date.parse(String(r.received).length === 10 ? r.received + 'T00:00:00Z' : r.received) + (r.extended ? 60 : 30) * DAY).toISOString().slice(0, 10) : null })) : [];
    const d = await rules('pdpl.intake_decide', { request: { ref: b.ref, type: b.type, channel: b.channel, received: b.received || new Date(t).toISOString().slice(0, 10), identity_method: b.identity_method || 'none', has_identifier: !!sref },
      settings: settings(), history, profile: (PD.records('profile')[0] || {}) });
    if (d.action === 'existing') {
      const r0 = PD.records('dsr').find((r) => r.id === d.request);
      audit(Object.assign({}, SYS, { user: 'system:dsar-intake:' + k.id }), 'pdpl.dsar.intake.duplicate', d.request, { source: k.id, sent_ref: b.ref, type: b.type });
      return answer(r0, d.ack, { duplicate_of: d.request, why: d.why }, b.language);
    }
    const who = Object.assign({}, SYS, { user: 'system:dsar-intake:' + k.id });
    const rec = PD.putRecord({ kind: 'dsr', ref: b.ref, type: d.type, channel: b.channel, received: d.received, stage: d.stage, assigned_to: d.assign_to || null,
      identity_verified: d.identity_verified, identity_method: d.identity_method, identity_note: d.identity_verified ? 'checked by ' + k.name + ': ' + d.identity_label : '', identity_by: d.identity_verified ? 'channel:' + k.name : null, identity_at: d.identity_verified ? new Date(t).toISOString() : null,
      tasks: (b.systems || []).map((s) => ({ system: s, status: 'open', note: 'named by ' + k.name })), subject_ref: sref,
      intake: { source: k.id, source_name: k.name, auto_verified: d.identity_verified, flags: d.flags, repetitive_of: d.repetitive_of, ack: d.ack, searched: false } }, who);
    let search = null;
    if (d.auto_search && PD.catalog) {
      try {
        const res = await PD.catalog.correlate(rec.id, { id_type: b.id_type, value, create_tasks: true }, who, { automated: true });
        search = { searched: res.searched, found_in: res.found_in.length, failed: res.failed, tasks_added: res.tasks_added };
      } catch (e) { search = { error: String(e.message).slice(0, 200) }; if (app.log && app.log.every) app.log.every('pdpl:intake-search', 600000, 'warn', 'automatic identity search did not run', { request: rec.id, err: String(e.message).slice(0, 200) }); }
      const cur = PD.records('dsr').find((r) => r.id === rec.id);
      PD.putRecord({ kind: 'dsr', id: rec.id, intake: Object.assign({}, cur.intake, { searched: !!(search && !search.error), found_in: search && !search.error ? search.found_in : null, search_error: search && search.error ? search.error : null }) }, who);
    }
    audit(who, 'pdpl.dsar.intake', rec.id, { source: k.id, type: d.type, channel: b.channel, auto_verified: d.identity_verified, method: d.identity_method, assigned_to: d.assign_to || null, flags: d.flags.map((f) => f.flag), searched: !!(search && !search.error), found_in: search && !search.error ? search.found_in : null });
    return answer(PD.records('dsr').find((r) => r.id === rec.id), d.ack, { search }, b.language);
  }
  function answer(r, ack, extra, lang) {
    const due = r.received ? new Date(Date.parse(String(r.received).length === 10 ? r.received + 'T00:00:00Z' : r.received) + (r.extended ? 60 : 30) * DAY).toISOString().slice(0, 10) : null;
    const a = ack ? (lang === 'ar' ? { ar: ack.ar } : lang === 'en' ? { en: ack.en } : ack) : null;
    return Object.assign({ request: r.id, reference: r.ref, received: r.received, due, stage: r.stage, identity_verified: !!r.identity_verified, assigned: !!r.assigned_to,
      flags: ((r.intake || {}).flags || []).map((f) => f.flag), acknowledgement: a }, extra || {});
  }
  return { intake, view, setSettings, issueKey, revokeKey, keys, authenticate, findings, subjectRef, TYPES, CHANNELS, METHODS };
}

function registerIntakeRoutes(srv, app, I) {
  const { body, param } = require('./check');
  const USER = { max: 80, re: /^[A-Za-z0-9._@-]+$/, msg: 'must be a platform user name' };
  const key = (ctx) => { const k = I.authenticate(ctx.bearer()); if (!k) throw httpErr(401, 'invalid or revoked intake key'); return k; };
  srv.route('POST', '/dsar/intake', (ctx) => {
    const k = key(ctx);
    const b = body(ctx.body).str('ref', { required: true, max: 60, re: /^[A-Za-z0-9_./-]+$/, msg: 'ref must be the request reference in the sending system (letters, digits, - _ . /)' })
      .oneOf('type', I.TYPES, { required: true }).oneOf('channel', I.CHANNELS, { required: true })
      .str('received', { max: 30, re: /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2}))?$/, msg: 'received must be a date (YYYY-MM-DD) or an ISO date-time with a zone' })
      .oneOf('identity_method', I.METHODS).oneOf('id_type', require('./pdpl-catalog').ID_TYPES)
      .str('id_value', { min: 3, max: 120, re: /^[A-Za-z0-9 +@._-]+$/, msg: 'id_value must be the identifier (letters, digits, + @ . _ -)' })
      .list('systems', { item: 'str', itemMax: 120, max: 50, unique: true }).oneOf('language', ['en', 'ar', 'both'])
      .rule((o) => (!!o.id_type !== !!o.id_value ? 'id_type and id_value go together' : null)).done();
    return I.intake(k, b);
  }, { agent: true });
  srv.route('GET', '/pdpl/intake', (ctx) => { ctx.need('operator'); return I.view(); });
  srv.route('POST', '/pdpl/intake/settings', (ctx) => {
    ctx.need('admin');   // what counts as a verified requester, and whether a verified one is searched at once
    const b = body(ctx.body).str('default_assignee', USER).bool('auto_search').list('strong_methods', { item: I.METHODS.filter((m) => m !== 'none'), unique: true, max: 10 }).done();
    const a = ctx.body && ctx.body.assignees;
    if (a !== undefined) {
      if (!a || typeof a !== 'object' || Array.isArray(a)) throw httpErr(400, 'assignees must be an object {request type: user name}');
      b.assignees = {};
      for (const [t, u] of Object.entries(a)) {
        if (!I.TYPES.includes(t)) throw httpErr(400, 'assignees: ' + String(t).slice(0, 30) + ' is not a request type');
        if (u === '' || u === null) continue;
        if (typeof u !== 'string' || !USER.re.test(u) || u.length > 80) throw httpErr(400, 'assignees.' + t + ' must be a platform user name');
        b.assignees[t] = u;
      }
    }
    if (b.strong_methods && !b.strong_methods.length) throw httpErr(400, 'strong_methods: list at least one method, or leave it out to keep the current list');
    return I.setSettings(b, ctx.who);
  });
  srv.route('POST', '/pdpl/intake/keys', (ctx) => { ctx.need('admin'); return I.issueKey(body(ctx.body).str('name', { required: true, max: 80 }).done(), ctx.who); });
  srv.route('POST', '/pdpl/intake/keys/:id/revoke', (ctx) => {
    ctx.need('admin');
    const id = param(ctx.params.id, 'id'); if (!/^DK-\d{3,}$/.test(id)) throw httpErr(400, 'id must be an intake key id (DK-nnn)');
    return I.revokeKey(id, ctx.who);
  });
}

module.exports = { createIntake, registerIntakeRoutes };
