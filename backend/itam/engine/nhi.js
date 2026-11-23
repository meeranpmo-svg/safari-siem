// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body } = require('./check');
/*
 * Non-Human Identities ({P} = /api/itam, Cyber Security -> Non-Human Identities): every identity that is not a person, with
 * an owner, a purpose, its secret age and expiry, its privilege, when it was last used, and what is wrong with it.
 * Python decides (pyengine/nhi_rules.py); this file validates at the boundary, gathers the facts, commits and audits.
 *
 * Sources, each read on its own (one missing source leaves the others, and it is named with what to connect):
 *   SIEM  GET /identity/nhi   directory service accounts (name pattern / SPN), gMSA / sMSA, Entra app registrations with
 *                             the end dates of their secrets and certificates (the SIEM never sends a value)
 *   here                      connector credentials and discovery credentials (the vault: dates and kinds, never a value),
 *                             agent keys and enrolment tokens, the PDPL API keys (stored as hashes), the AI engineers and
 *                             the people who approve them (Roles & Functions)
 * The platform never disables an account and never rotates a secret. A person records the owner; the owner (or an
 * administrator) reviews it every year; decommissioning is requested, approved by an administrator who did not request it,
 * carried out at the source by a person and recorded - and the register shows a "done" that the source contradicts.
 *
 *   GET  /nhi                       operator  identities, risks, counts, sources
 *   GET  /nhi/summary               viewer    counts only (no names)
 *   GET  /nhi/export                operator  CSV                                                         audited
 *   POST /nhi/owner                 operator  {id, owner, purpose?, criticality?}                         audited
 *   POST /nhi/review                operator  {id, decision: keep|decommission, note}  the owner or an admin  audited
 *   POST /nhi/decommission          operator  {id, reason}                                                audited
 *   POST /nhi/decommission/decide   admin     {id, decision: approve|reject, note?}  not the requester    audited
 *   POST /nhi/decommission/done     operator  {id, evidence}  after approval                              audited
 *   PUT  /nhi/policy                admin     {rotation_days, privileged_rotation_days, dormant_days, secret_max_days,
 *                                              expiry_warn_days, review_days, key_unused_days, agent_stale_days}  audited
 * The duty engineer (id nhi, "AI Identity Security Engineer") turns each medium-or-worse identity into a work item and
 * closes it when the risk is gone. It proposes; it never changes an identity.
 */
const SIEM_AS = { user: 'system:itam-nhi', role: 'analyst' };
const ID = { required: true, max: 260, re: /^(ad|entra|itam|ai):[A-Za-z0-9:._@$#\- ]{1,250}$/, msg: 'id must be a non-human identity id from the register (ad:…, entra:…, itam:…, ai:…)' };
const USER = { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'owner must be a platform user name (a person, not a team)' };
const POLICY_KEYS = ['rotation_days', 'privileged_rotation_days', 'dormant_days', 'secret_max_days', 'expiry_warn_days', 'review_days', 'key_unused_days', 'agent_stale_days'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createNhi(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const reg = () => store.collection('nhi_register'), cfg = () => store.collection('nhi_settings');
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, err) => { if (app.log && app.log.every) app.log.every('nhi:' + key, 3600000, 'warn', msg, { err: String((err && err.message) || err || '').slice(0, 200) }); };
  const person = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };

  async function siem(path) {
    if (opts.siem) return opts.siem(path);
    const L = app.discovery && app.discovery.siem; if (!L || typeof L.call !== 'function') return { _down: 'the SIEM link is not configured' };
    const r = await L.call('GET', path, SIEM_AS);
    if (!r) return { _down: 'the SIEM did not answer' };
    if (r.status === 404) return { _down: 'the SIEM has no ' + path + ' route yet - update the SIEM' };
    if (r.status !== 200) return { _down: 'SIEM ' + path + ': HTTP ' + r.status };
    return r.json || {};
  }
  const all = (name, fn) => { try { return store.collection(name).all(fn || (() => true)); } catch (e) { warn('read:' + name, 'NHI: ' + name + ' not read', e); return []; } };

  async function facts() {
    const F = {};
    const s = await siem('/identity/nhi');
    if (s._down) { F.ad = { available: false, reason: s._down }; F.entra = { available: false, reason: s._down }; }
    else { F.ad = s.ad || { available: false, reason: 'the SIEM sent no directory data' }; F.entra = s.entra || { available: false, reason: 'the SIEM sent no Entra data' }; }
    // this platform's own machine identities: dates, kinds and names only - never a secret, a hash or a key
    const P = { available: true };
    P.connectors = all('credentials').map((c) => ({ id: c.id, set_at: c.set_at || null, by: c.by || null }));
    let creds = [];
    try { creds = app.discovery && typeof app.discovery.credentials === 'function' ? app.discovery.credentials() : []; } catch (e) { warn('vault', 'NHI: discovery credentials not read', e); }
    const scopes = all('disc_scopes', (x) => x.status !== 'archived');
    P.credentials = creds.map((c) => {
      const used = scopes.filter((sc) => Object.values(sc.methods || {}).some((m) => m && (m.credential_id === c.id || (m.credential_ids || []).includes(c.id)))).map((sc) => sc.name);
      return { id: c.id, kind: c.kind, label: c.label, target: c.target && typeof c.target === 'object' ? (c.target.host || c.target.server || '') : String(c.target || ''), created_at: c.created_at, updated_at: c.updated_at, last_tested: c.last_tested, in_use: used.length > 0, scopes: used };
    });
    P.agents = all('agents').map((a) => ({ id: a.id, name: a.name, platform: a.platform, site: a.site, status: a.status, enrolled_at: a.enrolled_at, last_seen: a.last_seen }));
    P.enrol_tokens = all('enrol_tokens').map((t) => ({ id: String(t.id).slice(0, 8), note: t.note, site: t.site, created_at: t.created_at, expires_at: t.expires_at, used_at: t.used_at, revoked: !!t.revoked }));
    P.api_keys = [];
    for (const [area, col] of [['intake', 'pdpl_intake_keys'], ['access', 'pdpl_access_keys'], ['consent', 'pdpl_consent_keys']])
      for (const k of all(col)) P.api_keys.push({ area, id: k.id, name: k.name, created_at: k.created_at, last_used: k.last_used || null, revoked_at: k.revoked_at || null });
    try { P.ai_engineers = app.roles && typeof app.roles.engineerApprovers === 'function' ? app.roles.engineerApprovers() : []; } catch (e) { warn('roles', 'NHI: AI engineer approvers not read', e); P.ai_engineers = []; }
    F.platform = P;
    return F;
  }
  const policy = () => { const p = cfg().get('policy') || {}; const o = {}; for (const k of POLICY_KEYS) if (p[k]) o[k] = p[k]; return o; };
  const register = () => { const o = {}; for (const r of reg().all(() => true)) o[r.id] = r; return o; };

  async function view() {
    const r = await py().call('nhi.view', { facts: opts.facts ? await opts.facts() : await facts(), register: register(), policy: policy(), now: now() });
    if (!r || r.ok === false) { warn('py', 'NHI: the rules (Python) did not answer', r && r.error); throw httpErr(409, 'The NHI rules run in Python and Python did not answer - run the update so pyengine is installed'); }
    return Object.assign(r, { generated_at: iso() });
  }
  async function summary() { const v = await view(); return { counts: v.counts, sources: v.sources, generated_at: v.generated_at }; }
  async function item(id) { const v = await view(); const it = v.items.find((x) => x.id === id); if (!it) throw httpErr(404, 'no non-human identity ' + id + ' in the current inventory'); return it; }
  const recOf = (id) => reg().get(id) || { id };

  async function setOwner(input, who) {
    person(who, 'record an owner');
    const b = body(input || {}).str('id', ID).str('owner', Object.assign({ required: true }, USER)).str('purpose', { max: 300 }).oneOf('criticality', ['low', 'medium', 'high', 'critical']).done();
    if (isService(b.owner)) throw httpErr(400, 'owner must be a person, not a service or AI identity');
    const it = await item(b.id);
    if (it.kind === 'ai_engineer') throw httpErr(400, 'an AI engineer is owned through its approvers in Roles & Functions');
    const cur = recOf(b.id), prev = cur.owner || null;
    reg().put(Object.assign({}, cur, { id: b.id, owner: b.owner, purpose: b.purpose !== undefined ? b.purpose : cur.purpose || null, criticality: b.criticality || cur.criticality || null, owner_by: who.user, owner_at: iso() }));
    audit(who, 'nhi.owner', b.id, { owner: b.owner, previous: prev, kind: it.kind });
    return item(b.id);
  }

  async function review(input, who) {
    person(who, 'review an identity');
    const b = body(input || {}).str('id', ID).oneOf('decision', ['keep', 'decommission'], { required: true }).str('note', { required: true, max: 500, min: 5 }).done();
    const it = await item(b.id), cur = recOf(b.id);
    if (!cur.owner) throw httpErr(409, 'record the owner first - the owner reviews it');
    if (!(same(cur.owner, who.user) || who.role === 'admin')) throw httpErr(403, 'the review is done by the owner (' + cur.owner + ') or an administrator');
    const rec = Object.assign({}, cur, { review: { by: who.user, at: iso(), decision: b.decision, note: b.note } });
    if (b.decision === 'decommission' && !(cur.decommission && ['requested', 'approved'].includes(cur.decommission.status))) rec.decommission = { status: 'requested', by: who.user, at: iso(), reason: 'owner review: ' + b.note };
    reg().put(rec);
    audit(who, 'nhi.review', b.id, { decision: b.decision, kind: it.kind });
    return item(b.id);
  }

  async function requestDecom(input, who) {
    person(who, 'request decommissioning');
    const b = body(input || {}).str('id', ID).str('reason', { required: true, max: 500, min: 5 }).done();
    const it = await item(b.id), cur = recOf(b.id);
    if (it.kind === 'ai_engineer') throw httpErr(400, 'AI engineers are switched off in AI Team settings, not here');
    if (cur.decommission && ['requested', 'approved'].includes(cur.decommission.status)) throw httpErr(409, 'decommissioning is already ' + cur.decommission.status);
    reg().put(Object.assign({}, cur, { id: b.id, decommission: { status: 'requested', by: who.user, at: iso(), reason: b.reason } }));
    audit(who, 'nhi.decommission.request', b.id, { kind: it.kind, reason: b.reason });
    return item(b.id);
  }
  async function decideDecom(input, who) {
    person(who, 'approve decommissioning');
    const b = body(input || {}).str('id', ID).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it stays' : null)).done();
    const cur = recOf(b.id), d = cur.decommission;
    if (!d || d.status !== 'requested') throw httpErr(409, 'no decommissioning request waiting for ' + b.id);
    if (same(d.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' requested it and cannot also approve it');
    reg().put(Object.assign({}, cur, { decommission: Object.assign({}, d, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decide_note: b.note || '' }) }));
    audit(who, 'nhi.decommission.' + b.decision, b.id, { requested_by: d.by });
    return item(b.id);
  }
  async function doneDecom(input, who) {
    person(who, 'record decommissioning');
    const b = body(input || {}).str('id', ID).str('evidence', { required: true, max: 300, min: 3 }).done();
    const cur = recOf(b.id), d = cur.decommission;
    if (!d || d.status !== 'approved') throw httpErr(409, 'decommissioning must be approved first');
    reg().put(Object.assign({}, cur, { decommission: Object.assign({}, d, { status: 'done', done_by: who.user, done_at: iso(), evidence: b.evidence }) }));
    audit(who, 'nhi.decommission.done', b.id, { evidence: b.evidence, approved_by: d.decided_by });
    return item(b.id);
  }

  function putPolicy(input, who) {
    person(who, 'change the NHI policy');
    let b = body(input || {});
    for (const k of POLICY_KEYS) b = b.int(k, { min: 1, max: 3650 });
    const o = b.done();
    if (o.privileged_rotation_days && o.rotation_days && o.privileged_rotation_days > o.rotation_days) throw httpErr(400, 'privileged_rotation_days cannot be longer than rotation_days');
    const prev = policy();
    cfg().put(Object.assign({ id: 'policy' }, prev, o, { by: who.user, at: iso() }));
    audit(who, 'nhi.policy', 'policy', { changed: Object.keys(o), previous: prev });
    return policy();
  }

  async function exportCsv(who) {
    const v = await view();
    const q = (s) => { const t = String(s == null ? '' : s); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };   // no formula injection in Excel
    const cell = (s) => '"' + q(s).replace(/"/g, '""') + '"';
    const lines = [['Identity', 'Kind', 'Source', 'Name', 'Owner', 'Purpose', 'Privileged', 'Secret age (days)', 'Expires', 'Last used', 'Risk', 'Risks'].map(cell).join(',')];
    for (const it of v.items) lines.push([it.id, it.kind_name, it.source, it.name, it.owner, it.purpose, it.privileged ? 'yes' : 'no', it.secret_age_days, it.expires, it.last_used, it.risk, it.risks.map((r) => r.severity + ': ' + r.text).join(' | ')].map(cell).join(','));
    audit(who, 'nhi.export', 'register', { identities: v.items.length });
    return { filename: 'non-human-identities-' + iso().slice(0, 10) + '.csv', csv: lines.join('\r\n') };
  }

  let last = null;
  const adapter = {
    id: 'nhi', name: 'AI Identity Security Engineer',
    async findings() { const v = await view(); last = v; return v.findings; },
    investigate(it) {
      const x = last && last.items.find((i) => 'nhi:' + i.id === it.key);
      if (!x) return { summary: 'Non-human identity - see the Non-Human Identities page.', checks: [], causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
      return { summary: x.kind_name + ' ' + x.name + (x.owner ? ' (owner ' + x.owner + ')' : ' (no owner)'),
        checks: x.risks.map((r) => ({ name: r.key, status: r.severity === 'low' ? 'warn' : 'fail', detail: r.text })),
        causes: x.risks.slice(0, 3).map((r) => ({ cause: r.text, confidence: 'high', fix: r.fix })) };
    },
    async verify(it) {
      let v; try { v = await view(); } catch (e) { return { present: null, note: 'could not re-check: ' + String(e.message).slice(0, 120) }; }
      const present = v.findings.some((f) => f.key === it.key);
      return { present, note: present ? 'the identity still carries the risk' : 'the risk is gone' };
    },
  };
  return { view, summary, facts, setOwner, review, requestDecom, decideDecom, doneDecom, putPolicy, exportCsv, adapter };
}

function registerNhiRoutes(srv, app, N) {
  srv.route('GET', '/nhi', (ctx) => { ctx.need('operator'); return N.view(); });
  srv.route('GET', '/nhi/summary', (ctx) => { ctx.need('viewer'); return N.summary(); });
  srv.route('GET', '/nhi/export', (ctx) => { ctx.need('operator'); return N.exportCsv(ctx.who); });
  srv.route('POST', '/nhi/owner', (ctx) => { ctx.need('operator'); return N.setOwner(ctx.body, ctx.who); });
  srv.route('POST', '/nhi/review', (ctx) => { ctx.need('operator'); return N.review(ctx.body, ctx.who); });
  srv.route('POST', '/nhi/decommission', (ctx) => { ctx.need('operator'); return N.requestDecom(ctx.body, ctx.who); });
  srv.route('POST', '/nhi/decommission/decide', (ctx) => { ctx.need('admin'); return N.decideDecom(ctx.body, ctx.who); });
  srv.route('POST', '/nhi/decommission/done', (ctx) => { ctx.need('operator'); return N.doneDecom(ctx.body, ctx.who); });
  srv.route('PUT', '/nhi/policy', (ctx) => { ctx.need('admin'); return N.putPolicy(ctx.body, ctx.who); });
}

module.exports = { createNhi, registerNhiRoutes };
