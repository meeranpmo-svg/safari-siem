// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const G = require('../util/ai-guard');
/*
 * AI Windows Server Administrator and AI Exchange Server Administrator - Claude with read-only tools over the server
 * list, the background health findings, the read-only checks (checks.json, WinRM), the SIEM's Windows / Exchange logs
 * and Server Availability. They answer, correlate and PROPOSE a fix (a change plan a person approves and carries out);
 * no tool changes a server.
 *   createSysAI({ config, log, state, sdk?, tools: { targets, runner, health, changes, ch, db, availability } })
 *     .status() .ask({ role: 'windows'|'exchange', question, conversation?, user, userRole }) .conversations(user, role)
 * Same SDK, API key and model settings as the AI Network Engineer (secrets.json netops.anthropic_api_key, config
 * netops.ai) - one approval for sending data to Anthropic covers all assistants.
 */
const path = require('node:path');
const crypto = require('node:crypto');
const { check } = require('../netops/ai');
const { CHECKS } = require('./runner');

const MODEL = 'claude-opus-5-5', MAX_STEPS = 14, MAX_RESULT = 24000;
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

const COMMON = `
How you work:
- Base every statement on tool results. Start with list_servers or findings, then run the checks that answer the question. Run independent checks in parallel.
- Never invent server names, figures, event IDs or log lines. If a server is not in the list, has no login, or a check fails, say so and say what an administrator must set up.
- You are read-only: you can only run the named checks. When a fix needs a change, write the exact PowerShell (or GUI steps), the precheck and the rollback, and call propose_change so an administrator can review, approve and apply it. Never claim a change was made.
- Restarting servers or services, failing over databases and changing accounts are recommendations for a person to authorise.
- Checks marked "names people" (message tracking, mailbox, local administrators) are personal data under PDPL: run them only when the question needs them.
- Times from checks are UTC; Riyadh is UTC+3.

Answer format (the reader is an administrator):
1. Summary - one or two sentences.
2. Probable cause - with a confidence (high / medium / low).
3. Evidence - the specific values, events and log lines (server, time).
4. Recommended fix - numbered, safe steps with PowerShell where useful, and what to check afterwards.
5. If uncertain, what to check next.
Reply in the language of the question (Arabic or English).`;

const PERSONA = {
  windows: `You are the AI Windows Server Administrator for ${ZYB_ORG.short}'s Windows Server estate (domain controllers, file, application, SQL, RDS and IIS servers). You work inside the company's SIEM and answer the infrastructure team: disk space, services, event log errors, patching and pending reboots, performance, certificates, time sync, scheduled tasks, AD replication, unexpected restarts, and why a server is slow or down.` + COMMON,
  exchange: `You are the AI Exchange Server Administrator for ${ZYB_ORG.short}'s on-premises Exchange Server organisation. You work inside the company's SIEM and answer the messaging team: mail flow and queues, DAG and database copy health, mounted databases and backups, Exchange services and managed-availability health sets, certificates, receive / send connectors (including open-relay risk), transport back pressure, message tracking for a specific sender or recipient, and mailbox size and quota. Exchange servers are also Windows servers - use the Windows checks for disk, services and events on them.` + COMMON,
};

function toolsFor(role) {
  const ids = CHECKS.filter((c) => c.scope === role || (role === 'exchange' && c.scope === 'windows')).map((c) => c.id);
  const desc = CHECKS.filter((c) => ids.includes(c.id)).map((c) => `${c.id}${c.params ? '(' + Object.keys(c.params).join(', ') + ')' : ''}: ${c.title}${c.personal ? ' [names people]' : ''}`).join('; ');
  return [
    { name: 'list_servers', description: `The ${role === 'exchange' ? 'Exchange' : 'Windows'} servers in the list: name, IP, site, roles, whether a login is set, last health check and open findings count.`, input_schema: { type: 'object', properties: { filter: { type: 'string' } }, additionalProperties: false } },
    { name: 'findings', description: 'Current problems from the background health checks (disk, services, events, patching, certificates' + (role === 'exchange' ? ', queues, databases, DAG copies, Exchange services' : '') + '), optionally for one server or a minimum severity.', input_schema: { type: 'object', properties: { server: { type: 'string' }, min_severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] } }, additionalProperties: false } },
    { name: 'server_health', description: 'The latest background health results of one server (all baseline checks with their data and age).', input_schema: { type: 'object', properties: { server: { type: 'string' } }, required: ['server'], additionalProperties: false } },
    { name: 'run_check', description: 'Run one read-only check on a server now over WinRM. Checks: ' + desc + '. Parameters only as listed.', input_schema: { type: 'object', properties: { server: { type: 'string' }, check: { type: 'string', enum: ids }, params: { type: 'object', properties: { name: { type: 'string' }, log: { type: 'string', enum: ['System', 'Application'] }, hours: { type: 'integer', minimum: 1, maximum: 168 }, level: { type: 'string', enum: ['critical', 'error', 'warning'] }, address: { type: 'string' }, direction: { type: 'string', enum: ['sender', 'recipient'] } }, additionalProperties: false } }, required: ['server', 'check'], additionalProperties: false } },
    { name: 'siem_events', description: 'Events the SIEM already collected (no connection to the server): Windows Security / System events (logons, failures, lockouts 4740, service crashes 7031/7034, unexpected shutdowns 41/6008, account and group changes) or Exchange message-tracking / protocol logs. Grouped by event code with examples.', input_schema: { type: 'object', properties: { server: { type: 'string' }, source: { type: 'string', enum: ['windows', 'exchange'] }, event_code: { type: 'string' }, hours: { type: 'integer', minimum: 1, maximum: 720 } }, additionalProperties: false } },
    { name: 'server_availability', description: 'Uptime history from Server Availability: online / offline and for how long, availability % (24 h / 7 d / 30 d), last restart, unexpected shutdowns, HA groups, single points of failure. Optional name / IP filter.', input_schema: { type: 'object', properties: { filter: { type: 'string' } }, additionalProperties: false } },
    { name: 'propose_change', description: 'Record a change plan for human review and approval. It is NOT executed. Include exact PowerShell / steps, prechecks and rollback.', input_schema: { type: 'object', properties: { server: { type: 'string' }, title: { type: 'string' }, reason: { type: 'string' }, commands: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 60 }, rollback: { type: 'array', items: { type: 'string' } }, prechecks: { type: 'array', items: { type: 'string' } }, risk: { type: 'string', enum: ['low', 'medium', 'high'] } }, required: ['server', 'title', 'reason', 'commands', 'rollback'], additionalProperties: false } },
  ];
}

function createSysAI({ config, log, tools, sdk, state } = {}) {
  const L = log || { info() {}, warn() {}, error() {} }, cfg = (config && config.netops && config.netops.ai) || {}, T = tools;
  const chats = state ? state.collection('sysadmin_chats') : null;
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (sdk) return sdk; if (Ctor) return Ctor;
    for (const p of ['@anthropic-ai/sdk', cfg.sdk_path || '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, '..', '..', 'vendor', 'node_modules', '@anthropic-ai', 'sdk'), require('path').join(__dirname, '..', 'util', 'ai-sdk-shim.js')]) {
      try { const m = require(p); Ctor = require('../util/ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (run install/netops-setup.sh)' : e.message; }
    }
    return null;
  }
  const apiKey = () => (config && config.secrets && config.secrets.netops && config.secrets.netops.anthropic_api_key) || process.env.ANTHROPIC_API_KEY || '';
  function status() {
    if (cfg.enabled === false) return { enabled: false, reason: 'AI assistants disabled in config (netops.ai.enabled)' };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed' };
    if (!apiKey()) return { enabled: false, reason: ('no Anthropic API key (secrets.json netops.anthropic_api_key) - set it once ' + ZYB_ORG.short + ' approves sending server data to Anthropic') };
    return { enabled: true, model: cfg.model || MODEL };
  }
  function need(ref, role) { const t = T.targets.find(ref); if (!t) throw new Error(`unknown server "${ref}" - use list_servers`); if (role && !(t.roles || []).includes(role)) throw new Error(`${t.name} is not an Exchange server in the list`); return t; }
  const SEVR = { low: 1, medium: 2, high: 3, critical: 4 };

  function runners(role, ctx) {
    return {
      list_servers: (i) => { const f = String(i.filter || '').toLowerCase(); const F = T.health.findings({ role }); return T.targets.list(role).filter((t) => !f || (t.name + ' ' + t.ip + ' ' + t.site).toLowerCase().includes(f)).map((t) => { const s = T.health.snapshot(t.id); return { name: t.name, ip: t.ip, site: t.site, roles: t.roles, login: T.targets.loginSummary(t), last_health_check: s && s.at ? new Date(s.at).toISOString() : null, open_findings: F.filter((x) => x.server === t.id).length }; }); },
      findings: (i) => { const ms = SEVR[i.min_severity] || 0, t = i.server ? need(i.server) : null; return T.health.findings({ role }).filter((f) => (!t || f.server === t.id) && SEVR[f.severity] >= ms).slice(0, 50); },
      server_health: (i) => { const t = need(i.server), s = T.health.snapshot(t.id); if (!s) return { server: t.name, checked: false, note: 'not checked yet (no login, or the first health check has not run)' }; return { server: t.name, checked_at: new Date(s.at).toISOString(), results: Object.fromEntries(Object.entries(s.results).map(([k, v]) => [k, v.error ? { error: v.error, at: new Date(v.at).toISOString() } : { at: new Date(v.at).toISOString(), data: v.data }])) }; },
      run_check: async (i) => {
        const c = T.runner.check(i.check), t = need(i.server, c && c.scope === 'exchange' ? 'exchange' : null);
        // same rule as POST /targets/:id/check: running a WinRM check (a session with the service login) needs an operator
        if ((RANK[ctx.userRole] || 0) < RANK.operator) throw new Error(c && c.personal ? 'this check names people - it needs the operator role; ask an operator' : 'running a check on a server needs the operator role - I can read the last health results instead (server_health)');
        return T.runner.run(t.id, i.check, i.params || {}, { by: 'ai-' + role + '-admin (asked by ' + (ctx.user || '?') + ')', via: 'ai' });
      },
      siem_events: async (i) => {
        if (!T.ch || typeof T.ch.query !== 'function') return { note: 'the SIEM log store is not available' };
        const t = i.server ? need(i.server) : null, hours = Math.min(720, i.hours || 24), src = i.source || (role === 'exchange' ? 'exchange' : 'windows');
        const where = [`ts >= now() - INTERVAL ${hours} HOUR`, 'src_type = {src:String}']; const params = { src };
        if (t) { where.push("(lower(host) = {h:String} OR startsWith(lower(host), {hd:String}) OR src_ip = {ip:String})"); params.h = t.name.toLowerCase(); params.hd = t.name.toLowerCase().split('.')[0] + '.'; params.ip = t.ip; }
        if (i.event_code) { if (!/^[0-9A-Za-z_-]{1,32}$/.test(i.event_code)) throw new Error('event_code: letters, digits'); where.push('event_code = {ec:String}'); params.ec = i.event_code; }
        const rows = await T.ch.query(`SELECT event_code, any(action) AS action, count() AS n, max(ts) AS last, groupUniqArray(3)(substring(message, 1, 200)) AS examples, groupUniqArray(5)(user) AS users, groupUniqArray(5)(host) AS hosts
          FROM ${T.db || 'siem'}.events WHERE ${where.join(' AND ')} GROUP BY event_code ORDER BY n DESC LIMIT 40`, params, { readonly: true, timeout_ms: 30000, settings: { max_execution_time: 30 } });
        return { server: t ? t.name : 'all', source: src, hours, groups: rows };
      },
      server_availability: async (i) => { if (!T.availability) return { note: 'Server Availability is not enabled' }; const v = await T.availability.view(), f = String(i.filter || '').toLowerCase();
        return { summary: v.summary, hosts: v.items.filter((h) => !f || h.name.toLowerCase().includes(f) || h.ip.includes(f)).slice(0, 60).map((h) => ({ name: h.name, ip: h.ip, status: h.status, availability: h.availability, days_since_restart: h.days_since_boot, unexpected_shutdowns_30d: h.unexpected_shutdowns_30d, flags: h.flags })) }; },
      propose_change: (i) => { if ((RANK[ctx.userRole] || 0) < RANK.operator) throw new Error('recording a change plan needs the operator role (the same rule as POST /sysadmin/changes) - recommend the step to the administrator instead'); const t = need(i.server); const p = T.changes.propose(Object.assign({}, i, { device: t.id, source: 'ai', requested_by: ctx.requested_by || ctx.user || '' }), 'ai-' + role + '-admin (' + (ctx.by || 'asked by ' + (ctx.user || '?')) + ')'); if (ctx.onChange) ctx.onChange(p); return { recorded: p.id, status: p.status, note: 'Recorded for review. An administrator must approve it and a person must apply it; the SIEM does not change servers.' }; },
    };
  }

  async function exec(block, defs, run) {
    const def = defs.find((t) => t.name === block.name), t0 = Date.now();
    if (!def) return { res: { type: 'tool_result', tool_use_id: block.id, content: 'unknown tool', is_error: true }, step: { tool: block.name, ok: false, ms: 0 } };
    const err = check(def.input_schema, block.input);
    if (err) return { res: { type: 'tool_result', tool_use_id: block.id, content: 'invalid input: ' + err, is_error: true }, step: { tool: block.name, input: block.input, ok: false, ms: 0, error: err } };
    try {
      let text = JSON.stringify(await run[block.name](block.input || {}));
      if (text.length > MAX_RESULT) text = text.slice(0, MAX_RESULT) + ' …[truncated — narrow the query]';
      // server output and events are DATA outsiders can influence: secrets masked, framed as untrusted, flagged (util/ai-guard.js)
      const flags = G.injectionSignals(text); if (flags.length && run.flags) run.flags.push(...flags);
      return { res: { type: 'tool_result', tool_use_id: block.id, content: G.untrusted('tool:' + block.name, text) }, step: { tool: block.name, input: block.input, ok: true, ms: Date.now() - t0, injection_signals: flags.length ? flags : undefined } };
    } catch (e) {
      return { res: { type: 'tool_result', tool_use_id: block.id, content: G.untrusted('tool-error:' + block.name, 'error: ' + String(e.message || e).slice(0, 500)), is_error: true }, step: { tool: block.name, input: block.input, ok: false, ms: Date.now() - t0, error: G.redactSecrets(String(e.message || e)).slice(0, 200) } };
    }
  }

  // requested_by: who the plan is for (that person may not approve it); by: who is asking (e.g. the duty engine); onChange(plan)
  async function ask({ role, question, conversation, user, userRole, requested_by, by, onChange }) {
    if (!PERSONA[role]) throw Object.assign(new Error('role must be windows or exchange'), { code: 400 });
    const st = status(); if (!st.enabled) throw Object.assign(new Error(st.reason), { code: 503 });
    const q = String(question || '').trim(); if (!q) throw Object.assign(new Error('question required'), { code: 400 }); if (q.length > 4000) throw Object.assign(new Error('question too long'), { code: 400 });
    const Anthropic = loadSdk(), client = new Anthropic({ apiKey: apiKey(), timeout: (cfg.timeout_s || 180) * 1000, maxRetries: 2, baseURL: cfg.base_url || undefined });
    let conv = conversation && chats ? chats.get(conversation) : null;
    if (conv && (conv.user !== user || conv.role !== role)) conv = null;
    if (!conv) conv = { id: 'sc-' + crypto.randomBytes(8).toString('hex'), user: user || '', role, created: Date.now(), messages: [], title: q.slice(0, 80) };
    if (conv.messages.length > 160) throw Object.assign(new Error('conversation too long — start a new one'), { code: 409 });
    const budget = G.sharedBudget({ log: L, limits: () => (config && config.ai_limits) || {} }), flags = G.injectionSignals(q);
    budget.admit(user || by || 'system', 'sysadmin.' + role, q.length);
    if (JSON.stringify(conv.messages).length > 600000) throw Object.assign(new Error('this conversation is too long for the AI - start a new conversation'), { code: 409, status: 409 });   // cost / abuse limits first
    const defs = require('../util/ai-schema').assertSchemas(toolsFor(role), 'sysadmin ai'), run = runners(role, { user, userRole, requested_by, by, onChange }); run.flags = flags;
    const messages = conv.messages.concat([{ role: 'user', content: `[${new Date().toISOString().replace('T', ' ').slice(0, 16)} UTC] ${q}` }]);
    const steps = [], usage = { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 }; let final = null, model = cfg.model || MODEL;
    try {
    for (let i = 0; i < MAX_STEPS; i++) {
      const params = { model, max_tokens: 16000, thinking: { type: 'adaptive' }, output_config: { effort: cfg.effort || 'high' }, system: PERSONA[role] + '\n\n' + G.UNTRUSTED_RULE, tools: defs, messages, cache_control: { type: 'ephemeral' } };
      if (cfg.fallbacks !== false) { params.betas = ['server-side-fallback-2026-07-01']; params.fallbacks = 'default'; }
      const resp = await (params.betas ? client.beta.messages.create(params) : client.messages.create(params));
      for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
      model = resp.model || model;
      messages.push({ role: 'assistant', content: resp.content });
      if (resp.stop_reason === 'refusal') { final = 'The AI declined this request. Rephrase it as a server administration question.'; break; }
      if (resp.stop_reason === 'pause_turn') continue;
      const uses = resp.content.filter((b) => b.type === 'tool_use');
      if (resp.stop_reason === 'max_tokens' && uses.length) { final = 'The answer was cut off (too long). Ask a narrower question.'; break; }
      if (resp.stop_reason !== 'tool_use' || !uses.length) { final = resp.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim(); break; }
      const results = await Promise.all(uses.map((b) => exec(b, defs, run)));
      for (const r of results) steps.push(r.step);
      messages.push({ role: 'user', content: results.map((r) => r.res) });
    }
    } finally { budget.record(user || by || 'system', 'sysadmin.' + role, usage, [...new Set(flags)]); }   // tokens spent before a failure count too
    if (final === null) final = `Stopped after ${MAX_STEPS} investigation steps. The evidence gathered so far is listed below; ask a narrower follow-up.`;
    conv.messages = messages; conv.updated = Date.now(); if (chats) chats.put(conv);
    L.info('sysadmin ai answer', { role, user, userRole, steps: steps.length, tools: steps.map((x) => x.tool + (x.ok ? '' : '!')).join(','), in: usage.input_tokens, out: usage.output_tokens, injection_signals: flags.length ? [...new Set(flags)] : undefined });
    return { answer: final, conversation: conv.id, steps, model, usage };
  }
  const conversations = (user, role) => (chats ? chats.all((c) => c.user === user && c.role === role).sort((a, b) => b.updated - a.updated).slice(0, 30).map((c) => ({ id: c.id, title: c.title, updated: c.updated })) : []);
  return { status, ask, conversations, toolsFor, PERSONA };
}

module.exports = { createSysAI, toolsFor, PERSONA, MODEL };
