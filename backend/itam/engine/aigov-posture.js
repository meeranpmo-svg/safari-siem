// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI agent posture - the pure part of AI Governance's "agent commander" view (aigov-intel.js uses it). Discover, assess, enforce, monitor:
 *   reach      what each agent's tools can read, from the tool's name and description (word-bounded): personal data, credentials,
 *              health / claims, finance, security telemetry, systems. It is what the tool says it reads - the page says so.
 *   risk       0-100 per agent, every point itemised: a write-capable tool, reach into credentials / personal / health data, an
 *              external model with that reach, review overdue, injection-flag rate, an unusual day, a high refusal share.
 *   shadow     AI software on the endpoints (the software inventory the agents report): chat assistants, coding assistants and local
 *              model runners, word-bounded names. Not sanctioned until an administrator records why it is - a local model runner is
 *              the larger finding (models and data outside any control).
 *   checks     NIST AI RMF functions and the SDAIA AI Ethics principles, each from evidence the platform holds; what it cannot
 *              measure is said, never assumed met.
 */
const DOMAINS = [
  ['credentials', /\b(secrets?|credentials?|passwords?|tokens?|api[_ -]?keys?|certificates?|vault)\b/i, 15],
  ['health', /\b(health|medical|claims?|patients?|diagnos\w*)\b/i, 10],
  ['personal', /\b(users?|employees?|people|persons?|identit\w*|sign[_ -]?ins?|hr|customers?|subjects?|insider|staff|pdpl|personal)\b/i, 12],
  ['finance', /\b(budgets?|costs?|prices?|invoices?|financ\w*|solvency|payments?|iban)\b/i, 4],
  ['security', /\b(alerts?|events?|logs?|siem|incidents?|threats?|vulnerabilit\w*|offen[cs]es?)\b/i, 2],
  ['systems', /\b(assets?|hosts?|devices?|servers?|databases?|db|network|patch\w*|backups?)\b/i, 2],
];
const words = (t) => String((t && (t.name + ' ' + (t.description || ''))) || t || '').replace(/[_-]+/g, ' ');
function reachOf(tools) {
  const out = {};
  for (const t of tools || []) { const w = words(t); for (const [d, re] of DOMAINS) if (re.test(w)) (out[d] = out[d] || []).push(typeof t === 'string' ? t : t.name); }
  return out;
}
const LOCAL = /\b(local|ollama|llama|on[- ]?prem)\b/i;
/* s {name, enabled, model, tools[], writes[]}, u usage stats (aigov-intel stats() row) or null, overdue bool, paused control or null, ext bool */
function agentRisk(s, u, overdue, paused, ext, reach) {
  const items = [], add = (p, l) => items.push({ points: p, label: l });
  if (s.writes && s.writes.length) add(30, 'write-capable tool(s): ' + s.writes.join(', ') + ' - AI proposes, a person decides');
  for (const [d, , p] of DOMAINS) if (reach[d]) add(p, 'reads ' + d + ' (' + reach[d].slice(0, 3).join(', ') + ')');
  const sensitive = reach.credentials || reach.personal || reach.health;
  if (s.enabled && ext && sensitive && !LOCAL.test(String(s.model || ''))) add(8, 'sends what it reads to an external model (' + (s.model || 'cloud') + ') - redacted, but still outside the platform');
  if (overdue) add(10, 'no review by a person in the last 12 months');
  if (u && u.calls >= 10 && u.flag_rate >= 0.1) add(10, Math.round(u.flag_rate * 100) + ' % of calls carried injection signals (a flag, not a control)');
  if (u && u.unusual) add(6, 'unusual use today: ' + u.today + ' calls against a usual ' + u.usual);
  if (u && u.calls + u.refused >= 10 && u.refused / (u.calls + u.refused) >= 0.2) add(5, Math.round(100 * u.refused / (u.calls + u.refused)) + ' % of requests refused by the budget');
  const score = Math.min(100, items.reduce((n, i) => n + i.points, 0));
  return { score, level: paused ? 'paused' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low', items };
}

const AI_APPS = [
  ['chat', /\b(chatgpt|openai)\b/i, 'ChatGPT / OpenAI'], ['chat', /\bclaude\b|\banthropic\b/i, 'Claude'], ['chat', /\bgemini\b/i, 'Gemini'],
  ['chat', /\bperplexity\b/i, 'Perplexity'], ['chat', /\bcopilot\b(?!.*\bgithub\b)/i, 'Microsoft Copilot'], ['coding', /\bgithub copilot\b|\bcopilot\b.*\bgithub\b/i, 'GitHub Copilot'],
  ['coding', /\bcursor\b/i, 'Cursor'], ['coding', /\btabnine\b/i, 'Tabnine'], ['coding', /\bcodeium\b|\bwindsurf\b/i, 'Codeium / Windsurf'],
  ['local', /\bollama\b/i, 'Ollama'], ['local', /\blm ?studio\b/i, 'LM Studio'], ['local', /\bgpt4all\b/i, 'GPT4All'], ['local', /\bjan\.ai\b|^jan$/i, 'Jan'], ['local', /\blocalai\b/i, 'LocalAI'],
];
const KIND = { chat: 'chat assistant - what people paste leaves the company', coding: 'coding assistant - source code leaves the company', local: 'local model runner - models and data outside any control' };
/* rollup rows [{key, name, publisher, installs, asset_ids}], sanctioned map key -> {by, at, reason} */
function shadowAI(rollup, sanctioned) {
  const out = [];
  for (const p of rollup || []) {
    const nm = String(p.name || '') + ' ' + String(p.publisher || ''); const hit = AI_APPS.find(([, re]) => re.test(nm)); if (!hit) continue;
    const san = sanctioned && sanctioned[p.key];
    out.push({ key: p.key, name: p.name, publisher: p.publisher || '', app: hit[2], kind: hit[0], why: KIND[hit[0]], installs: p.installs, assets: (p.asset_ids || []).length, asset_ids: (p.asset_ids || []).slice(0, 50), sanctioned: san || null,
      risk: san ? 'sanctioned' : hit[0] === 'local' ? 'high' : 'medium' });
  }
  return out.sort((a, b) => (a.sanctioned ? 1 : 0) - (b.sanctioned ? 1 : 0) || (b.risk === 'high') - (a.risk === 'high') || b.installs - a.installs);
}

/* evidence -> checks [{id, framework, principle, status: met|gap|not measured, evidence}] */
function checks(ev) {
  const C = [], add = (id, nist, sdaia, status, evidence) => C.push({ id, nist, sdaia, status, evidence });
  add('inventory', 'MAP', 'Transparency & Explainability', ev.systems ? 'met' : 'gap', ev.systems ? ev.systems + ' AI system(s) discovered from the installed modules, with their tools' : 'no AI system discovered');
  add('oversight', 'GOVERN', 'Accountability & Responsibility', ev.writes ? 'gap' : 'met', ev.writes ? ev.writes + ' system(s) with a write-capable tool' : 'every tool reads only; changes are proposals a different person approves');
  add('review', 'GOVERN', 'Accountability & Responsibility', !ev.systems ? 'not measured' : ev.overdue ? 'gap' : 'met', ev.overdue ? ev.overdue + ' system(s) not reviewed by a person in 12 months' : 'every system reviewed within 12 months');
  add('monitoring', 'MEASURE', 'Reliability & Safety', 'met', 'every call and refusal is recorded (user name, feature, tokens, injection flags - never the question or answer); ' + ev.calls + ' call(s) in 90 days');
  add('misuse', 'MANAGE', 'Reliability & Safety', 'met', 'per-person and daily budgets, secrets redacted, tool output framed as untrusted data');
  add('stop', 'MANAGE', 'Reliability & Safety', 'met', 'an administrator can pause any AI system at once; resuming needs a second administrator' + (ev.paused ? ' - ' + ev.paused + ' paused now' : ''));
  add('data', 'MAP', 'Privacy & Security', ev.sensitiveExternal ? 'gap' : 'met', ev.sensitiveExternal ? ev.sensitiveExternal + ' system(s) read personal, health or credential data and send it to an external model' : 'no system sends personal, health or credential data to an external model');
  add('shadow', 'GOVERN', 'Privacy & Security', ev.inventory ? (ev.shadow ? 'gap' : 'met') : 'not measured', ev.inventory ? (ev.shadow ? ev.shadow + ' unsanctioned AI product(s) installed on endpoints' : 'no unsanctioned AI software found on ' + ev.inventory + ' endpoint(s)') : 'no software inventory - enrol the endpoint agent');
  add('fairness', 'MEASURE', 'Fairness', 'not measured', 'the platform\'s AI ranks and summarises operational records; it makes no decision about a person. Bias testing of any model that does is outside what the platform can see');
  return C;
}
module.exports = { reachOf, agentRisk, shadowAI, checks, DOMAINS, AI_APPS };
