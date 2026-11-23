// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const { body, param } = require('./check');
/*
 * The Compliance Assistant ({P} = /api/itam): ask in plain words - "are we compliant with SAMA?", "what should we fix first?",
 * "what is a DPIA?", "who approves this?" - and get an answer built from the registers themselves (SAMA CSF + IA, NCA ECC,
 * ISO 27001, NDMO, PDPL). Python decides (pyengine/assist_rules.py): naive Bayes for what the question asks, TF-IDF for
 * which requirement it is about, a ranking for what to do first. All of it runs on this server - no external AI, nothing
 * leaves the platform. This file reads the registers, validates, keeps the feedback and audits it.
 *
 * Learning: "this helped / did not help" on an answer is kept as the question's compliance words only (the words the
 * registers and the intent model know - a name or anything else typed is never stored, PDPL) and feeds the next answers:
 * helpful questions become intent training examples, and the requirement shown gets a lift for the same words.
 * The question text itself is never stored or logged.
 *
 *   GET  /assist/overview                viewer    every framework in one sentence + what to do first
 *   POST /assist/ask                     viewer    {question, fw?}                 a read: nothing is stored but the answer id
 *   GET  /assist/explain/:fw/:id         viewer    one requirement in plain words
 *   GET  /assist/glossary                viewer    the words, the five states, the frameworks, example questions
 *   POST /assist/feedback                viewer    {ask_id, helpful, intent?}      audited (anyone who asked may say if it helped)
 *   GET  /assist/learning                admin     what the assistant has learned (counts, no question text)
 */
const FWS = ['sama', 'ecc', 'iso', 'ndmo', 'pdpl'];
const INTENTS = ['explain', 'status', 'why', 'todo', 'evidence', 'who'];
const KEEP = ['id', 'title', 'subdomain_name', 'domain_name', 'group_name', 'area', 'domain', 'result', 'level', 'why', 'evidence_hint',
  'evidence_expected', 'severity', 'automated', 'recommend', 'ref', 'ecc'];
const ASK_TTL = 30 * 60000, CACHE_MS = 60000, MAX_LEARN = 500;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (x, n) => String(x == null ? '' : x).slice(0, n);

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createComplianceAssist(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const fb = () => store.collection('assist_feedback');
  const L = app.log || { every() {} };
  const warn = (key, msg, err) => { if (L.every) L.every('assist:' + key, 3600000, 'warn', msg, { err: s((err && err.message) || err, 200) }); };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'assist.' + action, target, detail }); };
  const addon = (k) => app.addons && app.addons[k];
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 30000, resident: false }));
  const asks = new Map();   // ask_id -> what feedback may keep, for 30 minutes; never the question text
  let cache = null;

  // each register read on its own; one not installed or not answering is left out and named, never counted as passing.
  // Only the fields the assistant explains are sent on - confirmations (who recorded / approved) never reach an answer.
  const READ = {
    sama: async () => (await addon('samaIa').view({ user: 'system:assist', role: 'viewer' })).requirements,
    ecc: async () => (await addon('ncaEcc').view({ user: 'system:assist', role: 'viewer' })).controls,
    iso: async () => { const v = await addon('iso27001').view({ user: 'system:assist', role: 'viewer' }); return [].concat(v.clauses || [], v.annex || []); },
    ndmo: async () => (await addon('ndmo').view({ user: 'system:assist', role: 'viewer' })).controls,
    pdpl: async () => (await addon('pdpl').view(false)).requirements,
  };
  const ADDON = { sama: 'samaIa', ecc: 'ncaEcc', iso: 'iso27001', ndmo: 'ndmo', pdpl: 'pdpl' };
  async function registers() {
    if (opts.registers) return opts.registers();
    if (cache && now() - cache.at < CACHE_MS) return cache.v;
    const regs = {}, missing = [];
    for (const fw of FWS) {
      if (!addon(ADDON[fw])) { missing.push(fw); continue; }
      try { regs[fw] = ((await READ[fw]()) || []).map((r) => { const o = {}; for (const k of KEEP) if (r[k] !== undefined) o[k] = r[k]; if (r.history) o.history = { p_gap: r.history.p_gap, regression: r.history.regression }; return o; }); }
      catch (e) { missing.push(fw); warn('read:' + fw, 'Compliance Assistant: the ' + fw + ' register was not read', e); }
    }
    cache = { at: now(), v: { regs, missing } };
    return cache.v;
  }
  async function rules(op, input) {
    const r = await py().call(op, input || {});
    if (r && r.ok === false && r.error_class === 'not_found') throw httpErr(404, r.error);
    if (!r || r.ok === false) { warn('py', 'Compliance Assistant: the rules (Python) did not answer', r && r.error); throw httpErr(409, 'The Compliance Assistant runs in Python and Python did not answer - run the update so pyengine is installed'); }
    return r;
  }
  function learning() {
    const examples = [], boosts = {};
    const rows = fb().all((x) => x.helpful).sort((a, b) => String(a.at).localeCompare(String(b.at))).slice(-MAX_LEARN);
    for (const x of rows) {
      if (x.intent) examples.push({ intent: x.intent, tokens: x.tokens });
      for (const t of x.tokens || []) { const b = boosts[t] || (boosts[t] = {}); for (const k of x.shown || []) b[k] = (b[k] || 0) + 1; }
    }
    return { examples, boosts };
  }
  const notInstalled = (missing) => missing.map((fw) => ({ sama: 'SAMA CSF + IA', ecc: 'NCA ECC', iso: 'ISO 27001', ndmo: 'NDMO', pdpl: 'PDPL' }[fw]));

  async function overview() {
    const { regs, missing } = await registers();
    const r = await rules('assist.overview', { registers: regs, top: 10 });
    delete r.ok;
    return Object.assign(r, { not_installed: notInstalled(missing), generated_at: new Date(now()).toISOString() });
  }
  async function ask(input, who) {
    const b = body(input).str('question', { required: true, min: 2, max: 500 }).oneOf('fw', FWS).done();
    const { regs, missing } = await registers();
    const r = await rules('assist.ask', { question: b.question, fw: b.fw, registers: regs, learn: learning() });
    const id = 'ask-' + crypto.randomBytes(8).toString('hex');
    for (const [k, v] of asks) if (now() - v.at > ASK_TTL) asks.delete(k);
    if (asks.size > 2000) asks.delete(asks.keys().next().value);
    asks.set(id, { at: now(), by: who.user, intent: r.intent, tokens: (r.tokens || []).slice(0, 40), shown: (r.matches || []).slice(0, 3).map((m) => m.fw + ':' + m.id) });
    delete r.ok; delete r.tokens;
    return Object.assign(r, { ask_id: id, not_installed: notInstalled(missing) });
  }
  async function explain(fw0, id0) {
    const fw = param(fw0, 'fw'); if (!FWS.includes(fw)) throw httpErr(400, 'fw must be one of: ' + FWS.join(', '));
    const id = param(id0);
    const { regs } = await registers();
    return (await rules('assist.explain', { fw, id, registers: regs })).explanation;
  }
  async function glossary() { const r = await rules('assist.glossary', {}); delete r.ok; return r; }
  function feedback(input, who) {
    const b = body(input).str('ask_id', { required: true, re: /^ask-[0-9a-f]{16}$/, msg: 'ask_id is not an answer id' }).bool('helpful', { required: true })
      .oneOf('intent', INTENTS).done();
    const a = asks.get(b.ask_id);
    if (!a || now() - a.at > ASK_TTL) throw httpErr(404, 'that answer is older than 30 minutes or unknown - ask again, then rate the new answer');
    if (a.by !== who.user) throw httpErr(403, 'only the person who asked can rate the answer');
    if (a.rated) throw httpErr(409, 'this answer was already rated');
    a.rated = true;
    // a correction ("I meant: who approves") teaches the intent the person meant, and counts as helpful for that intent
    const intent = b.intent || a.intent, helpful = b.helpful || !!b.intent;
    const rec = { id: b.ask_id, at: new Date(now()).toISOString(), by: who.user, intent: helpful ? intent : null, predicted: a.intent, helpful,
      corrected: !!(b.intent && b.intent !== a.intent), tokens: a.tokens, shown: helpful && !b.intent ? a.shown : [] };
    fb().put(rec);
    const all = fb().all(() => true);
    if (all.length > 5000) for (const x of all.sort((p, q) => String(p.at).localeCompare(String(q.at))).slice(0, all.length - 5000)) fb().remove(x.id);
    audit(who, 'feedback', b.ask_id, { helpful, intent: rec.intent, predicted: a.intent, corrected: rec.corrected, words: a.tokens.length });
    return { ok: true, learned: helpful, intent: rec.intent };
  }
  function learned() {
    const all = fb().all(() => true), by = {};
    for (const x of all) { const k = x.predicted || 'unknown'; const r = by[k] || (by[k] = { asked: 0, helpful: 0, corrected: 0 }); r.asked++; if (x.helpful && !x.corrected) r.helpful++; if (x.corrected) r.corrected++; }
    return { ratings: all.length, helpful: all.filter((x) => x.helpful && !x.corrected).length, corrected: all.filter((x) => x.corrected).length,
      by_intent: by, examples_in_use: Math.min(MAX_LEARN, all.filter((x) => x.helpful).length),
      note: 'Only the compliance words of each rated question are kept (never the question text, never a name). Helpful answers become training examples; corrections teach the intent that was meant.' };
  }
  return { overview, ask, explain, glossary, feedback, learned, registers };
}

function registerComplianceAssist(srv, app, A) {
  const S = A && A.ask ? A : createComplianceAssist(app, A || {});
  app.addons = app.addons || {}; app.addons.complianceAssist = S;
  srv.route('GET', '/assist/overview', (ctx) => { ctx.need('viewer'); return S.overview(); });
  srv.route('POST', '/assist/ask', (ctx) => { ctx.need('viewer'); return S.ask(ctx.body, ctx.who); }, { maxBody: 4096, anyRole: 'every person may ask the compliance assistant; the answer reads only what their role may read' });
  srv.route('GET', '/assist/explain/:fw/:id', (ctx) => { ctx.need('viewer'); return S.explain(ctx.params.fw, ctx.params.id); });
  srv.route('GET', '/assist/glossary', (ctx) => { ctx.need('viewer'); return S.glossary(); });
  srv.route('POST', '/assist/feedback', (ctx) => { ctx.need('viewer'); return S.feedback(ctx.body, ctx.who); }, { maxBody: 2048, anyRole: 'the person who asked rates their own answer; only a helpful flag is stored' });
  srv.route('GET', '/assist/learning', (ctx) => { ctx.need('admin'); return S.learned(); });
  return S;
}

module.exports = { createComplianceAssist, registerComplianceAssist };
