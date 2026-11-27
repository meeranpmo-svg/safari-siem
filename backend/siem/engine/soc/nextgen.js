// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Sentra Next-Gen SIEM - the platform at a glance (ui/sentra-nextgen.html): the three things a next-generation SIEM does, each
 * measured on THIS installation, never a brochure figure.
 *   UNIFY           first and third-party data (sources by type, cloud feeds), the real-time pipeline (events per second, stage
 *                   errors), agents and collectors
 *   HUNT & DETECT   search, threat intelligence (indicators loaded, hits), detections (rules loaded, matches, noise suppressed)
 *   RESPOND         case management (open, resolved, median time), agentic investigations (AI engineers' work items, AI calls),
 *                   governed automation (SOAR runs - every one approved by a person or by a playbook an administrator allowed)
 *   headline        noise removed before an analyst, median time to resolve an alert, share of closed alerts that were false
 *                   positives, events per second now - each with how many it rests on; fewer than MIN cases = not shown
 * Each segment carries a state (ready / partial / not set) and the one thing to do next. Read only; nothing is changed here.
 *   GET {P}/soc/nextgen     any signed-in user (counts and rates only: no event, user or host names)
 */
const { wrap, prefixOf } = require('./routeutil');

const DAY = 864e5, MIN = 3, CLOUD = /^(m365|o365|azure|entra|mimecast|cloudflare|aws|gcp|oci|zscaler|graph)/i;
const median = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const pct = (a, b) => (b ? Math.round(1000 * a / b) / 10 : null);

// everything the page shows, from plain numbers (no engine objects) so it can be tested on its own
function analyse(x, now = Date.now()) {
  const from = now - 30 * DAY;
  // ---- UNIFY
  const src = x.sources || [], live = src.filter((s) => s.last_seen && now - s.last_seen <= 15 * 60000);
  const types = [...new Set(src.map((s) => s.src_type).filter(Boolean))], cloud = types.filter((t) => CLOUD.test(t));
  const collectors = [...new Set(src.map((s) => s.collector).filter(Boolean))];
  const pipe = x.pipeline || {}, stages = pipe.stages || [], stageErr = stages.reduce((a, s) => a + (s.errors || 0), 0), stageCalls = stages.reduce((a, s) => a + (s.calls || 0), 0);
  const parseErr = src.reduce((a, s) => a + (s.parse_errors_since_start || 0), 0), srcEvents = src.reduce((a, s) => a + (s.events_since_start || 0), 0);
  // ---- HUNT & DETECT
  const det = x.detector || {}, rules = det.rules || [];
  const matches = rules.reduce((a, r) => a + (r.matches || 0), 0), suppressed = rules.reduce((a, r) => a + (r.suppressed || 0), 0), ruleAlerts = rules.reduce((a, r) => a + (r.alerts || 0), 0);
  const firing = rules.filter((r) => r.alerts).length, intel = x.intel || {}, iocs = (intel.ip || 0) + (intel.domain || 0) + (intel.hash || 0);
  const intelHits = Object.values(intel.hits || {}).reduce((a, n) => a + (Number(n) || 0), 0);
  // ---- RESPOND
  const A = (x.alerts || []).filter((a) => (a.created || 0) >= from), closed = A.filter((a) => /^closed/.test(String(a.status || '')));
  const fp = closed.filter((a) => a.status === 'closed-false-positive').length;
  const res = closed.filter((a) => a.closed_at > a.created).map((a) => (a.closed_at - a.created) / 60000);
  const ack = A.filter((a) => a.ack_at > a.created).map((a) => (a.ack_at - a.created) / 60000);
  const openAlerts = (x.alerts || []).filter((a) => !/^closed/.test(String(a.status || ''))).length, merged = (x.alertStats || {}).merged || 0;
  const C = x.cases || [], openCases = C.filter((c) => !/closed|resolved/.test(String(c.status || ''))).length;
  const caseRes = C.filter((c) => c.closed_at && c.created && c.closed_at >= from).map((c) => (c.closed_at - c.created) / 3600000);
  const runs = (x.soarRuns || []).filter((r) => (r.at || 0) >= from), autoRuns = runs.filter((r) => r.auto).length;
  const duty = x.dutyItems || [], dutyOpen = duty.filter((d) => !/resolved|closed/.test(String(d.status || ''))).length, dutyFixed = duty.filter((d) => d.status === 'resolved' && (d.resolved_at || d.updated || 0) >= from).length;
  const aiCalls = (x.aiLedger || []).filter((l) => Date.parse(l.day) >= from - DAY).reduce((a, l) => a + (l.calls || 0), 0);

  const seg = (id, pillar, title, page, state, figure, sub, next) => ({ id, pillar, title, page, state, figure, sub, next });
  const segments = [
    seg('data', 'unify', 'First & third-party data', 'soc-sources.html', live.length ? (cloud.length ? 'ready' : 'partial') : src.length ? 'partial' : 'none',
      live.length + ' / ' + src.length, 'sources sending now · ' + types.length + ' type(s)' + (cloud.length ? ' · ' + cloud.length + ' cloud' : ''),
      !src.length ? 'Connect the first log source (Connections & Setup)' : !live.length ? 'No source sent in the last 15 minutes - check the collectors' : !cloud.length ? 'Add a cloud feed (Microsoft 365, Mimecast) for third-party data' : (src.length - live.length) + ' source(s) quiet for 15 min'),
    seg('pipeline', 'unify', 'Real-time data pipeline', 'pipeline-health.html', pipe.eps_1m > 0 ? (stageErr ? 'partial' : 'ready') : 'none',
      pipe.eps_1m != null ? String(pipe.eps_1m) : '—', 'events per second · ' + stages.length + ' stage(s)' + (stageErr ? ' · ' + stageErr + ' stage error(s)' : ''),
      pipe.eps_1m > 0 ? (stageErr ? 'Stage errors since start: open Pipeline Health' : 'Parsing ' + (srcEvents ? (100 - (pct(parseErr, srcEvents) || 0)) + '% clean' : 'clean')) : 'No events flowing yet'),
    seg('collect', 'unify', 'Agents & collectors', 'agents.html', collectors.length ? 'ready' : src.length ? 'partial' : 'none',
      String(collectors.length), 'collector(s) delivering · ' + (x.agents != null ? x.agents + ' Windows agent(s)' : 'agents on the Agents page'),
      collectors.length ? 'Add the Sentra agent to every server that matters' : 'Install the Windows agent or point syslog at the platform'),
    seg('search', 'detect', 'Lightning search', 'soc-hunt.html', x.search ? 'ready' : 'none', x.search ? 'on' : 'off', 'search and hunting over every event',
      x.search ? 'Save the hunts the team repeats' : 'The event store is not answering - check ClickHouse'),
    seg('intel', 'detect', 'Threat intelligence', 'soc-ti.html', iocs ? 'ready' : 'none', iocs.toLocaleString('en-US'), 'indicators loaded · ' + (intel.lists || 0) + ' list(s) · ' + intelHits + ' hit(s)',
      iocs ? 'Indicators are matched against every event as it arrives' : 'Load a threat-intelligence feed'),
    seg('detections', 'detect', 'AI-powered detections', 'soc-alerts.html', rules.length ? (firing ? 'ready' : 'partial') : 'none', String(det.rules_loaded || rules.length),
      'rules loaded · ' + firing + ' firing · ' + suppressed.toLocaleString('en-US') + ' duplicate(s) suppressed', rules.length ? (det.load_errors ? det.load_errors + ' rule(s) failed to load' : 'Rules plus ML baselines on behaviour and flows') : 'Load the detection rules'),
    seg('cases', 'respond', 'Case management', 'soc-cases.html', C.length ? 'ready' : 'partial', String(openCases), 'open case(s) · ' + caseRes.length + ' resolved in 30 days',
      C.length ? (caseRes.length >= MIN ? 'Median ' + Math.round(median(caseRes) * 10) / 10 + ' h to resolve' : 'Cases resolve with evidence and tasks') : 'Open a case from an alert to start'),
    seg('investigate', 'respond', 'Agentic investigations', 'ai-team.html', duty.length || aiCalls ? 'ready' : 'partial', String(dutyOpen), 'open investigation(s) by the AI engineers · ' + aiCalls + ' AI call(s) in 30 days',
      'Every AI finding is a proposal: a named person decides'),
    seg('soar', 'respond', 'Governed SOAR', 'soar.html', runs.length ? 'ready' : 'partial', String(runs.length), 'playbook run(s) in 30 days · ' + autoRuns + ' automatic',
      runs.length ? 'Automatic only where an administrator allowed the playbook' : 'Switch on the first playbook (four-eyes approval stays)')];
  const pillar = (p) => { const L = segments.filter((s) => s.pillar === p); return Math.round(100 * L.reduce((a, s) => a + (s.state === 'ready' ? 1 : s.state === 'partial' ? 0.5 : 0), 0) / L.length); };

  const noiseBase = matches + merged;
  const headline = [
    { id: 'noise', value: noiseBase >= 20 ? pct(suppressed + merged, noiseBase + 0) : null, unit: '%', label: 'Noise removed before an analyst sees it', basis: noiseBase ? (suppressed + merged).toLocaleString('en-US') + ' duplicate matches suppressed or merged into existing alerts, of ' + noiseBase.toLocaleString('en-US') : 'no rule matches yet', why: noiseBase >= 20 ? null : 'shown after 20 rule matches' },
    { id: 'mttr', value: res.length >= MIN ? Math.round(median(res)) : null, unit: 'min', label: 'Median time to resolve an alert (30 days)', basis: res.length + ' closed alert(s)' + (ack.length >= MIN ? ' · median ' + Math.round(median(ack)) + ' min to acknowledge' : ''), why: res.length >= MIN ? null : 'shown after ' + MIN + ' closed alerts' },
    { id: 'fp', value: closed.length >= MIN ? pct(fp, closed.length) : null, unit: '%', label: 'Closed alerts that were false positives (30 days) - lower is better', basis: fp + ' of ' + closed.length + ' closed', why: closed.length >= MIN ? null : 'shown after ' + MIN + ' closed alerts' },
    { id: 'eps', value: pipe.eps_1m != null ? pipe.eps_1m : null, unit: 'eps', label: 'Events per second, right now', basis: (pipe.events || 0).toLocaleString('en-US') + ' events since the engine started', why: pipe.eps_1m != null ? null : 'the pipeline is not running' }];
  return { at: new Date(now).toISOString(), pillars: { unify: pillar('unify'), detect: pillar('detect'), respond: pillar('respond') }, segments, headline,
    totals: { sources: src.length, live_sources: live.length, rules: rules.length, iocs, alerts_30d: A.length, open_alerts: openAlerts, open_cases: openCases, soar_runs_30d: runs.length, ai_calls_30d: aiCalls, duty_fixed_30d: dutyFixed, rule_alerts: ruleAlerts },
    note: 'Measured on this installation; a figure resting on too few cases is not shown.' };
}

// read every part tolerantly: a module that is not loaded is simply absent
function gather(deps) {
  const t = (f) => { try { return f(); } catch (e) { if (deps.log && deps.log.every) deps.log.every('nextgen:' + String(e.message).slice(0, 40), 600000, 'warn', 'next-gen overview: a part could not be read', { err: String(e.message).slice(0, 200) }); return undefined; } };
  const S = deps.state, col = (n) => (S ? S.collection(n).all() : []);
  return {
    sources: t(() => deps.tracker && deps.tracker.summary()) || [],
    pipeline: t(() => deps.pipeline && deps.pipeline.stats()) || {},
    detector: t(() => deps.detector && deps.detector.stats()) || {},
    intel: t(() => deps.intel && deps.intel.stats()) || {},
    search: !!deps.search,
    alerts: t(() => deps.alerts && deps.alerts.all()) || [], alertStats: t(() => deps.alerts && deps.alerts.stats()) || {},
    cases: t(() => deps.cases && deps.cases.all()) || [],
    soarRuns: t(() => col('soar_runs')) || [], dutyItems: t(() => col('duty_items')) || [], aiLedger: t(() => col('ai_ledger')) || [],
  };
}

function register(api, deps) {
  const P = prefixOf(deps);
  api.route('GET', `${P}/soc/nextgen`, wrap(deps, null, (ctx) => ctx.ok(analyse(gather(deps), deps.now ? deps.now() : Date.now()))));
}

module.exports = { register, analyse, gather };
