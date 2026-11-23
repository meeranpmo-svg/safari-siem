// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA entity identification. Maps a normalised event to the entities it concerns.
 *
 *   createIdentifier(settings) → {
 *     classifyActor(user, ev) → { type, name } | null      // user | service_account | ai_agent
 *     entitiesOf(ev) → [{ id, type, name, role }]          // role: 'actor' | 'host'
 *     isAiAgent(name) → identity|null,  isServiceAccount(name) → bool
 *     entityId(type, name) → "type:name"
 *     aiIdentity(name) → the matching ai_agents.identities entry (home_ips, windows) or null
 *   }
 *
 * Entity types: user (interactive account/UPN), host (device), service_account (non-interactive; svc-* by name or
 * service/batch logon behaviour), ai_agent (our platform agents: SOAR, AI Team, UC agent, autopilot, n8n — matched by
 * their service identities / the collector+user they act as). An event is attributed to its actor (the `user`) and to
 * its `host`, so both get baselined and scored. Pure functions; standard library only.
 */

const { checkRegex } = require('../detect/saferegex');

function esc(s) { return String(s).toLowerCase(); }

// logon types that indicate non-interactive / service behaviour (Windows LogonType numbers + names)
const NONINTERACTIVE_LOGON = new Set(['4', '5', 'batch', 'service']);

function compilePatterns(list) {
  const out = [];
  // service-account patterns are admin-set but run against every event: same safety check as detection regexes
  for (const p of list || []) { try { checkRegex(p); out.push(new RegExp(p, 'i')); } catch { /* ignore bad or unsafe pattern */ } }
  return out;
}

function createIdentifier(settings = {}) {
  const sa = settings.service_accounts || {};
  const saPatterns = compilePatterns(sa.patterns);
  const saNames = new Set((sa.names || []).map(esc));
  const agents = (settings.ai_agents && settings.ai_agents.identities) || [];
  // build quick lookup: lowercased match value -> identity, by field
  const agentIndex = [];
  for (const a of agents) {
    if (!a || !a.name) continue;
    const m = a.match || {};
    agentIndex.push({
      ident: a,
      user: new Set((m.user || []).map(esc)),
      collector: new Set((m.collector || []).map(esc)),
      src_type: new Set((m.src_type || []).map(esc)),
    });
  }

  function aiIdentity(name) {
    const n = esc(name);
    for (const a of agentIndex) if (a.user.has(n)) return a.ident;
    return null;
  }

  function matchAgent(user, ev) {
    const u = esc(user);
    const col = esc(ev && ev.collector);
    const st = esc(ev && ev.src_type);
    for (const a of agentIndex) {
      if (a.user.size && a.user.has(u)) return a.ident;
      if (a.collector.size && a.collector.has(col) && (!a.user.size || a.user.has(u))) return a.ident;
      if (a.src_type.size && a.src_type.has(st) && a.user.size && a.user.has(u)) return a.ident;
    }
    return null;
  }

  function isServiceAccount(name) {
    const n = esc(name);
    if (!n) return false;
    if (saNames.has(n)) return true;
    return saPatterns.some((re) => re.test(n));
  }

  function classifyActor(user, ev) {
    const name = esc(user);
    if (!name) return null;
    const ai = matchAgent(name, ev || {});
    if (ai) return { type: 'ai_agent', name, identity: ai.name };
    if (isServiceAccount(name)) return { type: 'service_account', name };
    // behavioural: a non-interactive logon by an unknown account => service_account
    const lt = ev && ev.fields && (ev.fields.logon_type || ev.fields.logon_type_name);
    if (lt && NONINTERACTIVE_LOGON.has(esc(lt))) return { type: 'service_account', name };
    return { type: 'user', name };
  }

  function entityId(type, name) { return `${type}:${esc(name)}`; }

  function entitiesOf(ev) {
    const out = [];
    const seen = new Set();
    const add = (type, name, role) => {
      const nm = esc(name);
      if (!nm) return;
      const id = entityId(type, nm);
      if (seen.has(id)) return;
      seen.add(id);
      out.push({ id, type, name: nm, role });
    };
    const actor = classifyActor(ev.user, ev);
    if (actor) add(actor.type, actor.name, 'actor');
    if (ev.host) add('host', ev.host, 'host');
    return out;
  }

  return { classifyActor, entitiesOf, isServiceAccount, aiIdentity, entityId, isAiAgent: (n) => aiIdentity(n) };
}

module.exports = { createIdentifier, NONINTERACTIVE_LOGON };
