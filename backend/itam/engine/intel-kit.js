// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const G = require('./ai-guard');
const S = require('./ai-schema');
const { body } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * The shared kit of the GRC intelligence pages (Security Controls, Documents & Evidence, Chain of Custody, Control Validation,
 * Continuous Compliance, Compliance Overview, BCP / DR, AI Governance, Framework Library, Maturity). One implementation of what every
 * one of them needs, so the rules are the same everywhere:
 *   history     one snapshot a day per module (<key>_snaps, 400 kept); snapshot() is idempotent for the day
 *   trend       least squares over the daily values - 3 points before a slope, a projection to a target stated as one, not a promise
 *   beta        Beta(1,1) smoothed rate: 50 % with no history, never 0 / 100 from one observation
 *   robustZ     median / MAD over 7+ values; a value that never moved before and moves now is flagged as such
 *   settings    versioned (409 on a stale version), a person only, audited by the caller's route
 *   ask         the read-only AI advisor: a person, operator+, budget.admit before and record after, redactSecrets, every tool call's
 *               arguments checked against its input_schema before it runs (engine/ai-schema.js), untrusted() tool
 *               output, UNTRUSTED_RULE, tools re-checked per call (an unknown name is refused); it cannot change anything
 *   timer       start(): a daily snapshot through guardOf, rescheduled in finally
 */
const DAY = 86400000, KEEP = 400, MODEL = 'claude-opus-5-5', MAX_STEPS = 5, MAX_RESULT = 30000;
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const clip = (x, n = 300) => String(x == null ? '' : x).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ').slice(0, n);
const median = (a) => { const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const beta = (k, n) => (k + 1) / (n + 2);
function robustZ(values, x) {
  if (values.length < 7) return null;
  const md = median(values), mad = median(values.map((y) => Math.abs(y - md)));
  if (!mad) return x === md ? { z: 0, usual: md } : { z: Infinity, usual: md, never_moved: true };
  return { z: Math.round(0.6745 * (x - md) / mad * 10) / 10, usual: md };
}
function trend(points, o = {}) {
  const pts = points.filter((p) => p.y != null && Number.isFinite(p.y));
  if (pts.length < 3) return { why: 'needs 3 daily snapshots (' + pts.length + ' so far)', n: pts.length };
  const n = pts.length, mx = pts.reduce((a, p) => a + p.t, 0) / n, my = pts.reduce((a, p) => a + p.y, 0) / n, sxx = pts.reduce((a, p) => a + (p.t - mx) ** 2, 0);
  const sl = sxx ? pts.reduce((a, p) => a + (p.t - mx) * (p.y - my), 0) / sxx : 0, wk = Math.round(sl * 7 * 10) / 10;
  const out = { n, slope_per_week: wk, direction: wk > 0.5 ? 'rising' : wk < -0.5 ? 'falling' : 'flat' };
  if (o.target != null && o.current != null) {
    const up = o.higherIsBetter !== false;
    if (up ? o.current >= o.target : o.current <= o.target) return Object.assign(out, { reached: true, why: 'at the ' + o.target + ' target' });
    if (up ? sl <= 0.001 : sl >= -0.001) return Object.assign(out, { why: 'not moving toward the ' + o.target + ' target at the current pace (' + n + ' snapshots)' });
    const days = Math.ceil(Math.abs((o.target - o.current) / sl)); out.date = new Date(o.now + days * DAY).toISOString().slice(0, 10);
    out.why = (wk > 0 ? '+' : '') + wk + ' a week over ' + n + ' snapshots - projected ' + out.date + '; a projection from past pace, not a promise';
    if (o.targetDate) out.target = { date: o.targetDate, status: out.date <= o.targetDate ? 'on_track' : 'at_risk', why: 'projected ' + out.date + ' against ' + o.targetDate };
    return out;
  }
  out.why = (wk > 0 ? '+' : '') + wk + ' a week over ' + n + ' snapshots';
  return out;
}

function createIntelKit(app, o) {
  const now = o.now || Date.now, L = app.log || { info() {}, warn() {}, every() {} }, cfgA = (app.config && app.config[o.configKey || o.key]) || {};
  const iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10);
  const st = app.store, snapCol = () => st.collection(o.key.replace(/-/g, '_') + '_snaps'), cfgCol = () => st.collection(o.key.replace(/-/g, '_') + '_cfg');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: o.key + '.' + action, target, detail }); };
  const warn = (k, e) => L.every(o.key + ':' + k, 600000, 'warn', o.key + ': a source could not be read', { source: k, err: clip(e && e.message, 160) });
  const A = () => app.addons || {};
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  // read a source; a failure is said, never silently zero
  async function read(name, fn, notes) { try { const v = await fn(); if (v == null && notes) notes.push(name + ' is not installed'); return v; } catch (e) { warn(name, e); if (notes) notes.push(name + ' could not be read'); return null; } }
  const history = (n) => snapCol().all(() => true).sort((a, b) => a.id.localeCompare(b.id)).slice(-(n || KEEP));
  async function snapshot(build) {
    if (snapCol().get(today())) return null;
    const rec = await build(); if (!rec) return null;
    const r = Object.assign({ id: today(), at: iso() }, rec); snapCol().put(r);
    const all = snapCol().all(() => true).sort((a, b) => a.id.localeCompare(b.id)); for (const x of all.slice(0, Math.max(0, all.length - KEEP))) snapCol().remove(x.id);
    return r;
  }
  const pts = (key) => history().map((h) => ({ t: Date.parse(h.id + 'T00:00:00Z') / DAY, y: typeof key === 'function' ? key(h) : h[key], date: h.id }));
  const ago = (days) => { const d = new Date(Date.parse(today() + 'T00:00:00Z') - days * DAY).toISOString().slice(0, 10); return history().filter((h) => h.id <= d).pop() || null; };
  function settings(defaults) { const c = cfgCol().get('cfg') || {}; return Object.assign({}, defaults, c.v || {}, { version: c.version || 0, by: c.by || null, at: c.at || null }); }
  function saveSettings(defaults, patch, version, who) {
    person(who, 'change these settings'); const cur = settings(defaults);
    if (version !== cur.version) throw httpErr(409, 'the settings were changed meanwhile (version ' + cur.version + ') - reload and try again');
    const v = Object.assign({}, (cfgCol().get('cfg') || {}).v || {}, patch); cfgCol().put({ id: 'cfg', v, version: cur.version + 1, by: who.user, at: iso() });
    audit(who, 'settings', 'settings', Object.assign({ version: cur.version + 1 }, patch)); return settings(defaults);
  }
  const RUN = { timer: null, stopped: false };
  function start(job) {
    if (RUN.timer || o.noTimer) return;
    const g = guardOf(app, o.key + '.snapshot', job);
    const loop = async () => { try { await g(); } finally { if (!RUN.stopped) { RUN.timer = setTimeout(loop, 3600000); if (RUN.timer.unref) RUN.timer.unref(); } } };
    RUN.timer = setTimeout(loop, 100000 + Math.floor(Math.random() * 60000)); if (RUN.timer.unref) RUN.timer.unref();
  }
  function stop() { RUN.stopped = true; if (RUN.timer) clearTimeout(RUN.timer); RUN.timer = null; }

  // ---- AI advisor (read-only)
  const dc = (app.config && app.config.discovery) || {};
  const getKey = o.getKey || (() => { try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', dc.vault_key_file)() || process.env.ANTHROPIC_API_KEY || ''; } catch (e) { return process.env.ANTHROPIC_API_KEY || ''; } });
  let Ctor = null, loadError = '';
  function loadSdk() { if (o.sdk) return o.sdk; if (Ctor) return Ctor; for (const p of [cfgA.sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', require('path').join(__dirname, 'ai-sdk-shim.js')].filter(Boolean)) { try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (the update installs it)' : clip(e.message, 200); } } return null; }
  // the feature name rides on the status so AI Governance can link a system to its usage and pause it
  function aiStatus() { const r = aiStatus0(); if (r && typeof r === 'object') r.feature = o.feature; return r; }
  function aiStatus0() {
    const model0 = cfgA.model || MODEL;
    let ok = false; try { ok = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (e) { ok = false; /* settings unreadable = not allowed */ }
    if (!ok) return { enabled: false, reason: 'external AI is not allowed in IT Asset Management settings (external_ai_allowed), or the AI engine is switched off (Platform Administration -> AI Engine)', model: model0 };
    if (!getKey()) return { enabled: false, reason: 'no Anthropic API key (sudo zyb-virt-ai --set-key - the same key)', model: model0 };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model: model0 };
    return { enabled: true, model: model0 };
  }
  const TOOLS = (o.tools || []).map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema || { type: 'object', properties: {}, additionalProperties: false } }));
  // every rule a tool declares must be one the platform enforces: an advisor with a schema the checker cannot read does not start
  S.assertSchemas(TOOLS, 'intel kit ' + (o.key || '?'));
  async function ask(input, who) {
    const b = body(input || {}).str('question', { required: true, min: 5, max: 2000 }).done();
    person(who, 'ask the advisor');
    if ((RANK[who.role] || 0) < RANK.operator) throw httpErr(403, 'the advisor works for operators and administrators');
    const s0 = aiStatus(); if (!s0.enabled) throw httpErr(424, s0.reason);
    const bud = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} }), flags = G.injectionSignals(b.question), q = G.redactSecrets(b.question);
    bud.admit(who.user, o.feature, q.length);
    const Anthropic = loadSdk(), client = new Anthropic({ apiKey: getKey(), timeout: (cfgA.timeout_s || 180) * 1000, maxRetries: 2 });
    const messages = [{ role: 'user', content: q }], steps = [], usage = { input_tokens: 0, output_tokens: 0 }; let final = null, mdl = s0.model;
    try {
      for (let i = 0; i < MAX_STEPS; i++) {
        const resp = await client.messages.create({ model: mdl, max_tokens: 4000, thinking: { type: 'adaptive' }, system: o.system + '\n\n' + G.UNTRUSTED_RULE, tools: TOOLS, messages });
        for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
        mdl = resp.model || mdl; messages.push({ role: 'assistant', content: resp.content });
        if (resp.stop_reason === 'refusal') { final = 'The AI declined this request. Rephrase it as a question about this page.'; break; }
        const uses = (resp.content || []).filter((x) => x.type === 'tool_use');
        if (resp.stop_reason !== 'tool_use' || !uses.length) { final = (resp.content || []).filter((x) => x.type === 'text').map((x) => x.text).join('\n').trim(); break; }
        const results = [];
        for (const u of uses) {
          const t = (o.tools || []).find((x) => x.name === u.name);
          if (!t || (RANK[who.role] || 0) < RANK.operator) { steps.push({ tool: u.name, ok: false }); results.push({ type: 'tool_result', tool_use_id: u.id, content: 'unknown or not allowed tool', is_error: true }); continue; }
          // the model's arguments are untrusted: checked against the declared schema, the tool is not run on a mismatch
          const input = u.input === undefined ? {} : u.input, bad = S.checkInput(TOOLS.find((x) => x.name === u.name).input_schema, input);
          if (bad) { steps.push({ tool: u.name, ok: false, error: G.redactSecrets(bad) }); results.push({ type: 'tool_result', tool_use_id: u.id, content: 'invalid input: ' + G.redactSecrets(bad), is_error: true }); continue; }
          let text; try { text = G.redactSecrets(JSON.stringify(await t.run(input, who))); } catch (e) { text = JSON.stringify({ error: clip(e.message, 200) }); }
          if (text.length > MAX_RESULT) text = text.slice(0, MAX_RESULT) + ' …[truncated]';
          const fl = G.injectionSignals(text); if (fl.length) flags.push(...fl);
          steps.push({ tool: u.name, ok: true }); results.push({ type: 'tool_result', tool_use_id: u.id, content: G.untrusted('tool:' + u.name, text) });
        }
        messages.push({ role: 'user', content: results });
      }
    } finally { bud.record(who.user, o.feature, usage, [...new Set(flags)]); }
    if (final === null) final = 'Stopped after ' + MAX_STEPS + ' steps; ask a narrower question.';
    audit(who, 'ai.ask', o.key, { chars: b.question.length, steps: steps.length, injection_signals: [...new Set(flags)].length });
    return { answer: G.redactSecrets(final), steps, model: mdl, injection_signals: [...new Set(flags)] };
  }
  return { now, iso, today, audit, warn, A, person, read, history, snapshot, pts, ago, settings, saveSettings, start, stop, aiStatus, ask, TOOLS, httpErr, clip };
}

// the three routes every intelligence page has; module-specific routes are added by the module
function registerIntel(srv, X, base) {
  srv.route('GET', base, (ctx) => { ctx.need('viewer'); return X.view(ctx.who); });
  if (X.saveSettings) srv.route('POST', base + '/settings', (ctx) => { ctx.need(X.settingsRole || 'admin'); return X.saveSettings(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', base + '/ask', (ctx) => { ctx.need('operator'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
}

module.exports = { registerIntel, createIntelKit, trend, beta, robustZ, median, RANK, DAY, httpErr, clip };
