// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const G = require('../util/ai-guard');
const { createModel, runLoop } = require('../soc/ai-loop');
/*
 * Applications, Web Servers & APIs - the web tier, the application-server tier and the APIs, live from ManageEngine Applications Manager
 * (integrations/me-apm.js: its monitors and alarms; nothing here talks to APM or to a server). Read-only.
 *
 *   tiers        every APM monitor is placed in a tier by its type and name (web: URL / website / IIS / Apache / nginx; app: Tomcat /
 *                WebLogic / JBoss / WildFly / WebSphere / .NET / Java / Node; api: REST / SOAP / web service / API); databases stay on the
 *                Database Dashboard; anything else is "other". The rule is a fixed list, shown with each monitor.
 *   history      a sample of every monitor's availability and health every 5 minutes (webtier_samples, 7 days per monitor).
 *   learning     per monitor: availability over the samples (Beta(1,1), shown from 12 samples); FLAPPING (3+ changes in the last 24 samples);
 *                a problem that is NEW (it was up for most of the history) or CHRONIC (down or critical in over half of it); time since
 *                the state last changed. Per host: when two or more monitors of the same host are down at once, the host is the
 *                PROBABLE CAUSE and its monitors are grouped under it - counted once, not as separate failures.
 *   health       per tier and overall: share of managed monitors up and clear, minus itemised points for critical alarms and flapping.
 *   AI advisor   read-only tools (tiers, problems, learning); proposes what to look at first - it cannot poll, unmanage or change anything.
 *
 *   createWebTier({ state, apm, config, log, now?, sdk? }) → { view(), sample(), advise(question, who) }
 */
const HOUR = 3600000, SLOT = 5 * 60000, KEEP = 7 * 24 * 12;
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });
const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const STR = (max) => ({ type: 'string', maxLength: max || 2000 });
const TIERS = [
  ['api', /\b(rest\s*api|restapi|soap|web\s*service|api)\b/i],
  ['app', /\b(tomcat|weblogic|jboss|wildfly|websphere|glassfish|\.net|dotnet|asp\.?net|java|jvm|jmx|node\.?js|php|ruby|python|application\s*server|app\s*server)\b/i],
  ['web', /\b(url|http|https|website|web\s*site|web\s*server|webserver|iis|apache|nginx|httpd|real\s*browser|rbm)\b/i],
];
const DB = /\b(oracle|mysql|mssql|sql\s*server|postgres|db2|mongodb|redis|sybase|database|maria)\b/i;
function tierOf(m) { const t = (m.type || '') + ' ' + (m.name || ''); if (DB.test(m.type || '')) return 'db'; for (const [k, re] of TIERS) if (re.test(t)) return k; return 'other'; }
const isUp = (x) => x.availability === 'up' && x.health !== 'critical';

const SYSTEM = `You are the application operations advisor for ${ZYB_ORG.short}. You read the live state of the web servers, application servers and
APIs from ManageEngine Applications Manager (via the tools) and advise what to look at first.
Read tiers (tier_health), problems (problems) and the learning (monitor_learning), then call submit_advice once:
- summary: where the tiers stand, two or three sentences;
- priorities: up to 6, each {ref (a monitor id or a host from the tools), action, why} - a probable-cause host first, then new problems, then chronic and flapping ones;
- note: what the tools cannot show (only what APM monitors is seen; a server without a monitor is invisible here).
You propose; a person decides. You cannot poll, unmanage or change anything.`;
const TOOLS = [
  { name: 'tier_health', role: 'operator', description: 'Health per tier (web / app / api / other) with itemised deductions and counts.', input_schema: S({ properties: {} }) },
  { name: 'problems', role: 'operator', description: 'Monitors down or critical, grouped under a probable-cause host when several on one host are down; open alarms.', input_schema: S({ properties: {} }) },
  { name: 'monitor_learning', role: 'operator', description: 'Per monitor: availability over the history, flapping, new or chronic, last change.', input_schema: S({ properties: {} }) },
  { name: 'submit_advice', role: 'operator', description: 'Final answer.', input_schema: S({ required: ['summary', 'priorities'], properties: { summary: STR(1500), note: STR(800),
    priorities: { type: 'array', maxItems: 6, items: S({ required: ['ref', 'action', 'why'], properties: { ref: STR(160), action: STR(300), why: STR(500) } }) } } }) },
];

function createWebTier(deps = {}) {
  const state = deps.state; if (!state) throw new Error('createWebTier needs deps.state');
  const now = deps.now || Date.now, L = deps.log || { info() {}, warn() {}, error() {} };
  const samples = state.collection('webtier_samples');
  const AI = createModel({ config: deps.config || {}, deps, log: L });
  const apm = () => deps.apm || null;

  function current() {
    const A = apm(); if (!A) return { installed: false, status: null, monitors: [], alarms: [] };
    const st = A.status();
    const monitors = A.monitors({}).map((m) => Object.assign({}, m, { tier: tierOf(m) })).filter((m) => m.tier !== 'db');
    const ids = new Set(monitors.map((m) => m.id));
    return { installed: true, status: st, monitors, alarms: A.alarms({}).filter((a) => ids.has(a.resource_id)) };
  }
  // one sample per monitor per 5-minute slot
  function sample() {
    const c = current(); if (!c.installed || !c.status || !c.status.last_sync) return 0;
    const slot = Math.floor(now() / SLOT) * SLOT; let n = 0;
    for (const m of c.monitors) {
      const d = samples.get(m.id) || { id: m.id, s: [] };
      if (d.s.length && d.s[d.s.length - 1].t === slot) continue;
      d.s.push({ t: slot, up: isUp(m) ? 1 : 0, h: m.health === 'critical' ? 2 : m.health === 'warning' ? 1 : 0 });
      if (d.s.length > KEEP) d.s = d.s.slice(-KEEP);
      samples.put(d); n++;
    }
    return n;
  }
  function learn(m) {
    const d = samples.get(m.id), s = d ? d.s : [];
    if (s.length < 12) return { samples: s.length, availability: null, why: 'needs 12 samples (an hour) to learn this monitor (' + s.length + ' so far)', flapping: false, pattern: null, since: null };
    const up = s.filter((x) => x.up).length, recent = s.slice(-24); let flips = 0; for (let i = 1; i < recent.length; i++) if (recent[i].up !== recent[i - 1].up) flips++;
    const bad = s.filter((x) => !x.up || x.h === 2).length / s.length, nowBad = !isUp(m);
    let lastChange = null; for (let i = s.length - 1; i > 0; i--) if (s[i].up !== s[i - 1].up) { lastChange = s[i].t; break; }
    return { samples: s.length, availability: Math.round(((up + 1) / (s.length + 2)) * 1000) / 10, flapping: flips >= 3, flips,
      pattern: !nowBad ? null : bad > 0.5 ? 'chronic' : 'new', since: lastChange ? new Date(lastChange).toISOString() : null,
      why: up + ' of ' + s.length + ' samples up (Beta(1,1) estimate)' + (flips >= 3 ? ', ' + flips + ' changes in the last 2 hours' : '') };
  }

  function analysis() {
    const c = current();
    if (!c.installed) return { installed: false, reason: 'the Applications Manager integration is not installed - run the SIEM update' };
    if (!c.status.configured) return { installed: true, configured: false, reason: 'Applications Manager is not connected - an administrator adds its URL and API key on the Applications Manager page' };
    const mons = c.monitors.map((m) => Object.assign(m, { learning: learn(m), alarms: c.alarms.filter((a) => a.resource_id === m.id && a.severity !== 'clear').length }));
    // probable-cause hosts: 2+ monitors of one host down at once
    const byHost = new Map(); for (const m of mons) if (m.managed && !isUp(m) && m.host) { const k = String(m.host).toLowerCase(); if (!byHost.has(k)) byHost.set(k, []); byHost.get(k).push(m); }
    const hosts = [...byHost.entries()].filter(([, l]) => l.length >= 2).map(([h, l]) => ({ host: h, monitors: l.map((m) => ({ id: m.id, name: m.name, tier: m.tier })), why: l.length + ' monitors on this host are down at the same time - the host (or its network) is the probable cause' }));
    const covered = new Set(hosts.flatMap((h) => h.monitors.map((m) => m.id)));
    const problems = mons.filter((m) => m.managed && !isUp(m)).map((m) => ({ id: m.id, name: m.name, tier: m.tier, host: m.host, availability: m.availability, health: m.health, message: m.message, pattern: m.learning.pattern, since: m.learning.since, covered_by: covered.has(m.id) ? String(m.host).toLowerCase() : null }))
      .sort((a, b) => (a.covered_by ? 1 : 0) - (b.covered_by ? 1 : 0) || (a.pattern === 'new' ? 0 : 1) - (b.pattern === 'new' ? 0 : 1));
    const tiers = {};
    for (const k of ['web', 'app', 'api', 'other']) {
      const T = mons.filter((m) => m.tier === k), man = T.filter((m) => m.managed);
      if (!man.length) { tiers[k] = { tier: k, monitors: T.length, available: false, reason: T.length ? 'every monitor in this tier is unmanaged (in maintenance)' : 'no monitor of this kind in Applications Manager' }; continue; }
      const up = man.filter(isUp).length, crit = c.alarms.filter((a) => a.severity === 'critical' && man.some((m) => m.id === a.resource_id)).length, fl = man.filter((m) => m.learning.flapping).length;
      const ded = [{ what: crit + ' critical alarm(s) open', points: Math.min(30, crit * 5) }, { what: fl + ' flapping monitor(s)', points: Math.min(20, fl * 5) }].filter((d) => d.points > 0);
      const base = Math.round((up / man.length) * 100);
      tiers[k] = { tier: k, monitors: T.length, managed: man.length, up, down: man.length - up, unmanaged: T.length - man.length, base, deductions: ded, score: Math.max(0, base - ded.reduce((t, d) => t + d.points, 0)), available: true };
    }
    const meas = Object.values(tiers).filter((t) => t.available), overall = meas.length ? Math.round(meas.reduce((t, x) => t + x.score, 0) / meas.length) : null;
    return { installed: true, configured: true, last_sync: c.status.last_sync ? new Date(c.status.last_sync).toISOString() : null, sync_ok: c.status.ok, sync_error: c.status.error || null,
      overall, overall_why: meas.length ? 'mean of ' + meas.length + ' tier(s) with managed monitors' : 'no web, application or API monitor yet - add them in Applications Manager',
      tiers, hosts, problems, alarms: c.alarms.filter((a) => a.severity !== 'clear').slice(0, 100),
      monitors: mons.map((m) => ({ id: m.id, name: m.name, type: m.type, tier: m.tier, host: m.host, health: m.health, availability: m.availability, managed: m.managed, last_polled: m.last_polled, message: m.message, alarms: m.alarms, learning: m.learning })),
      tier_rule: 'from the monitor type and name: web = URL / website / IIS / Apache / nginx; app = Tomcat / WebLogic / JBoss / WebSphere / .NET / Java / Node; api = REST / SOAP / web service; databases are on the Database Dashboard' };
  }
  function view() { return Object.assign(analysis(), { ai: AI.status(), note: 'Read-only, from Applications Manager. A server that APM does not monitor is invisible here - the page compares with Business Services to show what is not monitored.' }); }

  async function advise(question, who) {
    const st = AI.status(); if (!st.enabled) throw httpErr(503, st.reason);
    const a = analysis(); if (!a.configured) throw httpErr(409, a.reason);
    const run = async (name) => {
      const v = analysis();
      if (name === 'tier_health') return { overall: v.overall, tiers: v.tiers };
      if (name === 'problems') return { hosts: v.hosts, problems: v.problems, alarms: v.alarms.slice(0, 40) };
      if (name === 'monitor_learning') return { monitors: v.monitors.map((m) => ({ id: m.id, name: m.name, tier: m.tier, host: m.host, learning: m.learning })) };
      throw new Error('unknown tool ' + name);
    };
    const q = G.redactSecrets(String(question || '')).slice(0, 1500);
    const r = await runLoop({ client: AI.client(), model: AI.model(), effort: AI.effort(), system: SYSTEM, tools: TOOLS, role: who.role || 'operator', user: who.user || 'unknown', feature: 'soc.webtier-advisor', config: deps.config, log: L,
      prompt: (q ? 'The engineer asks:\n' + G.untrusted('engineer-question', q) + '\n' : '') + 'Use the tools, then call submit_advice.', run, final: 'submit_advice', maxSteps: 6 });
    if (!r.result) throw httpErr(502, 'the AI did not return advice (' + r.note + ') - try again');
    const v = analysis(), known = new Set(v.monitors.map((m) => m.id).concat(v.monitors.map((m) => String(m.host || '').toLowerCase())).filter(Boolean));
    const pr = (r.result.priorities || []).map((p) => Object.assign({}, p, { verified: known.has(String(p.ref)) || known.has(String(p.ref).toLowerCase()) }));
    return { summary: r.result.summary, priorities: pr, note: r.result.note || '', unverified: pr.filter((p) => !p.verified).length, steps: r.steps, usage: r.usage, injection_signals: r.flags,
      framing: 'Advice for a person to review - nothing was changed.' };
  }
  return { view, analysis, sample, advise, tierOf, TOOLS };
}

module.exports = { createWebTier, tierOf, TOOLS };
