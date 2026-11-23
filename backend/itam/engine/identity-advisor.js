// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body } = require('./check');
const G = require('./ai-guard');
/*
 * AI identity advisor ({P} = /api/itam; Identity & Sign-in studio, page identity-signin.html -> AI advisor).
 *
 * The sign-in service (as-auth) answers only an administrator's own browser session, so the page reads it and works out the
 * identity facts there (MFA coverage, admins without MFA, dormant, locked, unusual sign-ins, attacks, explainable account
 * risk). The page sends that summary here with the question; this module:
 *   - is administrators only and a person (never a service / AI identity) - it is every account's sign-in picture
 *   - validates the summary's shape and size, masks IP addresses to /24 again (PDPL: user names, not more) and redacts secrets
 *   - frames the summary as UNTRUSTED data (it came from a browser, account names can carry text) with UNTRUSTED_RULE
 *   - runs through the shared budget (admit before, record after) - one model call, no tools: it can change nothing
 *   - answers in plain text, labelled an AI draft; the page renders it escaped, no links
 *   GET  /identity-advisor/status           admin   whether AI is available and why not
 *   POST /identity-advisor/ask              admin   {question?, facts}                                               audited
 * Never a password, token, recovery code or MFA secret: the summary has no field for them and the server drops any other field.
 */
const MODEL = 'claude-opus-5-5';
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const maskIp = (s) => String(s || '').replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b/g, '$1.x').replace(/\b([0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}):[0-9a-f:]+\b/gi, '$1::');
const txt = (v, n) => maskIp(String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n || 200));
const num = (v) => (Number.isFinite(Number(v)) ? Math.round(Number(v) * 10) / 10 : null);
const DEFAULT_Q = 'Brief the platform administrator on the identity posture: 1. the headline in one sentence 2. the three biggest risks, each with the account or the figure behind it 3. what to do first this week, in order 4. what the figures cannot show.';
const SYSTEM = ('You are the identity security advisor for the ' + ZYB_ORG.short + ' platform administrator (Identity & Sign-in). You read a summary of the sign-in service: ')
  + 'accounts with role and MFA state, sign-in statistics, unusual sign-ins and attack patterns found by the page, and an explainable risk score per account. '
  + 'Advise in plain English for Saudi Arabian regulators\' expectations (SAMA CSF 3.3.5 identity and access management, NCA ECC 2-2): MFA for every account and always for administrators, '
  + 'least privilege, break-glass accounts sealed and reviewed, dormant accounts disabled, sign-in attacks blocked at the firewall. '
  + 'Every claim must come from the summary - name the account or the figure; if the summary does not show something, say it is not measured. '
  + 'You cannot change anything: you never create, enable, disable or delete accounts, never turn MFA off, never set or reset passwords, and you never suggest bypassing two-step verification. '
  + 'An administrator makes every change in Identity & Sign-in. Keep it under 350 words, no markdown tables.';

function cleanFacts(f) {
  if (!f || typeof f !== 'object' || Array.isArray(f)) throw httpErr(400, 'facts: the identity summary from the page is required');
  const o = {};
  const k = f.kpis && typeof f.kpis === 'object' ? f.kpis : {};
  o.kpis = {};
  for (const n of ['active', 'admins', 'mfa_pct', 'admins_no_mfa', 'dormant', 'locked', 'breakglass', 'signins_24h', 'failures_24h', 'lockouts_24h', 'attacks', 'attacks_followed_by_success', 'unusual', 'posture', 'days_of_events', 'sso_enabled', 'sso_require_mfa', 'local_login_breakglass_only']) if (n in k) o.kpis[n] = typeof k[n] === 'boolean' ? k[n] : num(k[n]);
  o.policy = txt(f.policy, 200);
  const list = (a, max, fn) => (Array.isArray(a) ? a.slice(0, max).map(fn) : []);
  o.accounts = list(f.accounts, 60, (u) => ({ user: txt(u && u.user, 100), role: txt(u && u.role, 20), mfa: u && typeof u.mfa === 'boolean' ? u.mfa : null, risk: num(u && u.risk), why: list(u && u.why, 8, (w) => txt(w, 120)) }));
  o.unusual = list(f.unusual, 30, (x) => ({ user: txt(x && x.user, 100), at: txt(x && x.at, 30), score: num(x && x.score), why: list(x && x.why, 5, (w) => txt(w, 120)) }));
  o.attacks = list(f.attacks, 20, (x) => ({ kind: txt(x && x.kind, 40), who: txt(x && x.who, 100), at: txt(x && x.at, 30), detail: txt(x && x.detail, 200), followed_by_success: !!(x && x.ok) }));
  o.posture_points = list(f.posture_points, 12, (x) => txt(x, 140));
  if (JSON.stringify(o).length > 60000) throw httpErr(413, 'facts: the summary is too large');
  return o;
}

function createIdentityAdvisor(app, opts = {}) {
  const cfg = (app.config && app.config.identity_ai) || {}, L = app.log || { info() {}, warn() {}, every() {} };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'identity_advisor.' + action, target, detail }); };
  let Ctor = null, loadError = '';
  const getKey = opts.getKey || (() => { try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', app.config && app.config.discovery && app.config.discovery.vault_key_file)() || process.env.ANTHROPIC_API_KEY || ''; } catch (e) { return process.env.ANTHROPIC_API_KEY || ''; } });
  function loadSdk() {
    if (opts.sdk) return opts.sdk; if (Ctor) return Ctor;
    for (const p of [cfg.sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', require('path').join(__dirname, 'ai-sdk-shim.js')].filter(Boolean)) {
      try { const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (the update installs it)' : e.message; }
    }
    return null;
  }
  function status() {
    const model = cfg.model || MODEL;
    if (cfg.enabled === false) return { enabled: false, reason: 'the AI identity advisor is switched off in config (identity_ai.enabled)', model };
    let ok = false; try { ok = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (e) { ok = false; }
    if (!ok) return { enabled: false, reason: 'external AI is not allowed in IT Asset Management settings (external_ai_allowed), or the AI engine is switched off (Platform Administration -> AI Engine) - an administrator decides whether account names may go to Anthropic', model };
    if (!getKey()) return { enabled: false, reason: 'no Anthropic API key (sudo zyb-virt-ai --set-key - the same key)', model };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model };
    return { enabled: true, model };
  }
  async function ask(who, b0) {
    if (!who || !who.user || isService(who.user)) throw httpErr(403, 'the AI identity advisor is asked by a person, not a service or AI identity');
    const b = body(b0 || {}).str('question', { max: 600 }).done();
    if (b.question && b.question.length < 5) throw httpErr(400, 'question: ask a full question (5 characters or more), or leave it empty for the brief');
    const facts = cleanFacts(b0 && b0.facts);
    const st = status(); if (!st.enabled) throw httpErr(424, st.reason);   // 4xx: the server passes the reason through (a 5xx becomes 'internal error')
    const q = b.question || DEFAULT_Q;
    const flags = G.injectionSignals(q + ' ' + JSON.stringify(facts));
    const budget = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    const data = G.redactSecrets(JSON.stringify(facts));
    budget.admit(who.user, 'itam.identity-advisor', q.length + data.length);
    const Anthropic = loadSdk(), client = new Anthropic({ apiKey: getKey(), timeout: (cfg.timeout_s || 120) * 1000, maxRetries: 2 });
    const usage = { input_tokens: 0, output_tokens: 0 }; let answer = '', model = st.model;
    try {
      const resp = await client.messages.create({ model, max_tokens: 3000, thinking: { type: 'adaptive' }, system: SYSTEM + '\n\n' + G.UNTRUSTED_RULE,
        messages: [{ role: 'user', content: G.redactSecrets(q) + '\n\n' + G.untrusted('identity-summary', data) }] });
      for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
      model = resp.model || model;
      answer = resp.stop_reason === 'refusal' ? 'The AI declined this request. Rephrase it as an identity and sign-in question.' : (resp.content || []).filter((x) => x.type === 'text').map((x) => x.text).join('\n').trim();
    } catch (e) {
      if (e.status) throw e;
      if (L.every) L.every('identity-advisor:call', 600000, 'warn', 'AI identity advisor call failed', { err: String(e.message).slice(0, 200) });
      throw httpErr(424, 'the AI service did not answer: ' + String(e.message).slice(0, 160));
    } finally { budget.record(who.user, 'itam.identity-advisor', usage, flags); }
    audit(who, 'ask', 'identity', { custom_question: !!b.question, accounts: facts.accounts.length, tokens: usage.input_tokens + usage.output_tokens, injection_signals: flags.length });
    return { label: 'AI draft - verify; change nothing without checking Identity & Sign-in', answer: G.redactSecrets(answer), model, usage, injection_signals: flags };
  }
  return { status, ask, _cleanFacts: cleanFacts, _maskIp: maskIp };
}
function registerIdentityAdvisor(srv, app, X) {
  const who = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || '' });
  srv.route('GET', '/identity-advisor/status', (ctx) => { ctx.need('admin'); return X.status(); });
  srv.route('POST', '/identity-advisor/ask', (ctx) => { ctx.need('admin'); return X.ask(who(ctx), ctx.body); }, { maxBody: 96 * 1024 });
}
module.exports = { createIdentityAdvisor, registerIdentityAdvisor, cleanFacts, maskIp };
