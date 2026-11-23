// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const crypto = require('node:crypto');
const G = require('../util/ai-guard');
const SC = require('../approvers/scopes');
const { createModel, runLoop } = require('../soc/ai-loop');
const { laneOf } = require('./dfir');
const ML = require('./ml');
/*
 * DFIR forensics - the forensic side of an incident, on top of the SOC cases (engine/soc/cases.js) and the event store.
 *
 *   createForensics({ state, cases, search, dfir, config, log, sdk?, now? })
 *   Case overlay (one per SOC case, collection dfir_case)
 *     incident type, when the company became AWARE, whether personal data is involved (and roughly how many people), the
 *     regulators the incident is reportable to, the forensic phase (identification → preservation → acquisition → analysis →
 *     reporting → closed: one step forward at a time, back at any time), a legal hold.
 *   Regulatory clocks
 *     PDPL: 72 h from awareness when personal data is involved (Implementing Regulation Art. 24) - by law, not a setting.
 *     SAMA / NCA / Insurance Authority: the hours an administrator enters from the circular that applies; until then the
 *     clock reads "hours not set" - the platform never assumes a regulator's deadline. A clock stops when a person records
 *     the notification (made outside the platform) with its reference. A case cannot close with a clock still running.
 *   Evidence register (dfir_evidence)
 *     the collector's own SHA-256 of the item (the platform does not receive the file), where it is kept, and a custody
 *     chain in which every entry carries the hash of the previous one; verify() recomputes the chain. A custody entry that
 *     re-hashes the item and gets a different SHA-256 marks the item's integrity as MISMATCH. While a legal hold is on, an
 *     item cannot be released or returned. Nothing is ever deleted.
 *   IOCs (dfir_iocs)
 *     typed and validated (IP, domain, URL, SHA-256 / SHA-1 / MD5, e-mail); sightings are counts over the event store with
 *     first / last seen and the hosts involved (bound query values); export as a STIX 2.1 bundle.
 *   Timeline analysis (machine learning, explainable - analyse())
 *     bursts: per-bucket event counts scored with a robust z (median / MAD) - a burst is a run of buckets well above the
 *       entity's own normal; activity sessions split on gaps; attack-stage progression: the stages (credential use →
 *       execution → persistence → privilege → defence impairment → outbound) found IN ORDER inside one session; rare values
 *       in the window; first-seen values against the entity's own 30-day baseline (the event store's newValues); pivots:
 *       the other users / hosts / IPs in the timeline, weighted by how often they appear inside a burst; an attention score
 *       0-100 where every point is itemised. Indicators for the investigator, not proof.
 *   AI forensic analyst (ask)
 *     read-only tools filtered by role in code (soc/ai-loop.js: schema-checked inputs, untrusted framing, shared budget,
 *     UNTRUSTED_RULE); every cited ref no tool returned is marked unverified; the answer is a draft a person may add to
 *     the case as their own note.
 */
const H = 3600e3, DAY = 24 * H;
const TYPES = ['ransomware', 'malware', 'account-compromise', 'bec', 'data-breach', 'insider', 'web-attack', 'denial-of-service', 'lost-device', 'other'];
const PHASES = ['identification', 'preservation', 'acquisition', 'analysis', 'reporting', 'closed'];
const EV_KINDS = ['disk-image', 'memory-image', 'triage-package', 'log-export', 'mailbox-export', 'network-capture', 'file', 'screenshot', 'document', 'other'];
const CUSTODY = ['collected', 'transferred', 'accessed', 'analysed', 'copied', 'sealed', 'returned', 'released'];
const REGULATORS = { sama: 'SAMA', nca: 'NCA', ia: 'Insurance Authority' };
const PDPL_HOURS = 72;
const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email'];
const IOC_RE = {
  ipv4: /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/,
  ipv6: /^(?=.*:)[0-9a-f:]{2,39}$/i,
  domain: /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i,
  url: /^https?:\/\/[^\s"'<>\\`]{3,2000}$/i,
  sha256: /^[a-f0-9]{64}$/i, sha1: /^[a-f0-9]{40}$/i, md5: /^[a-f0-9]{32}$/i,
  email: /^[^\s@<>"'`\\]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,}$/i,
};
// attack stages by forensic lane, in kill-chain order (detections are scored separately)
const STAGE = { auth: [1, 'credential use'], execution: [2, 'execution'], persistence: [3, 'persistence'], account: [4, 'privilege / account change'], evasion: [5, 'defence impairment'], network: [6, 'outbound / lateral'], dns: [6, 'outbound / lateral'], web: [6, 'outbound / lateral'] };
const httpErr = (code, msg) => Object.assign(new Error(msg), { code, status: code });
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o);
const STR = (max) => ({ type: 'string', maxLength: max || 4000 });

function toMs(v) {
  if (typeof v === 'number') return v;
  const s = String(v || ''); if (!s) return NaN;
  const iso = /^\d{4}-\d{2}-\d{2} \d/.test(s) ? s.replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? '' : 'Z') : s;
  return Date.parse(iso);
}
function median(a) { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
function isInternal(ip) { return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:|fc|fd)/i.test(String(ip || '')); }

/* analyse(rows, { subject }) - pure, on the rows timeline() returns ({ts, lane, sev, host, user, src_ip, dst_ip, process, …}) */
function analyse(rows, opts = {}) {
  const subj = String(opts.subject || '').toLowerCase();
  const ev = rows.map((r) => Object.assign({}, r, { t: toMs(r.ts) })).filter((r) => Number.isFinite(r.t)).sort((a, b) => a.t - b.t);
  const out = { events: ev.length, bucket_ms: 0, series: [], bursts: [], sessions: [], progression: null, rare: [], pivots: [], score: 0, reasons: [], note: '' };
  if (!ev.length) { out.note = 'no events in the window - nothing to analyse'; Object.assign(out, { beacons: [], commands: [], rare_pairs: [], lateral: [], techniques: [] }); return out; }
  const t0 = ev[0].t, t1 = ev[ev.length - 1].t, span = Math.max(1, t1 - t0);
  const bms = [60e3, 300e3, 900e3, H, 3 * H, 6 * H, DAY].find((b) => span / b <= 160) || DAY;
  out.bucket_ms = bms;
  const n = Math.floor(span / bms) + 1, counts = new Array(n).fill(0), lanesIn = Array.from({ length: n }, () => ({}));
  for (const e of ev) { const i = Math.floor((e.t - t0) / bms); counts[i]++; lanesIn[i][e.lane] = (lanesIn[i][e.lane] || 0) + 1; e._b = i; }
  // robust z of each bucket against the entity's own median bucket (MAD; Poisson-like floor when MAD is 0)
  const med = median(counts), mad = median(counts.map((c) => Math.abs(c - med)));
  const scale = mad > 0 ? 1.4826 * mad : Math.max(1, Math.sqrt(med || 1));
  const z = counts.map((c) => (c - med) / scale);
  out.series = counts.map((c, i) => ({ t: t0 + i * bms, n: c, z: Math.round(z[i] * 10) / 10 }));
  const inBurst = new Array(n).fill(false);
  if (n >= 8) {
    for (let i = 0; i < n; i++) {
      if (!(z[i] >= 3.5 && counts[i] >= 5)) continue;
      let j = i; while (j + 1 < n && z[j + 1] >= 3.5 && counts[j + 1] >= 5) j++;
      const lanes = {}; let c = 0, peak = 0;
      for (let k = i; k <= j; k++) { inBurst[k] = true; c += counts[k]; peak = Math.max(peak, z[k]); for (const [l, v] of Object.entries(lanesIn[k])) lanes[l] = (lanes[l] || 0) + v; }
      out.bursts.push({ from: t0 + i * bms, to: t0 + (j + 1) * bms, events: c, peak_z: Math.round(peak * 10) / 10, baseline: med, lanes: Object.entries(lanes).sort((a, b) => b[1] - a[1]).map(([lane, v]) => ({ lane, n: v })) });
      i = j;
    }
  } else out.note = 'the window holds fewer than 8 time buckets - too short to tell a burst from normal activity';
  // sessions: split where the quiet gap is long compared with this entity's own rhythm
  const gaps = []; for (let i = 1; i < ev.length; i++) gaps.push(ev[i].t - ev[i - 1].t);
  const gapCut = Math.max(30 * 60e3, 5 * median(gaps));
  let cur = null;
  for (const e of ev) {
    if (!cur || e.t - cur.to > gapCut) { cur = { from: e.t, to: e.t, events: 0, stages: {}, lanes: {} }; out.sessions.push(cur); }
    cur.to = e.t; cur.events++; cur.lanes[e.lane] = (cur.lanes[e.lane] || 0) + 1;
    const st = STAGE[e.lane]; if (st && cur.stages[st[0]] === undefined) cur.stages[st[0]] = e.t;
  }
  // attack-stage progression: the longest run of stages whose first occurrence is in kill-chain order, in one session
  let best = null;
  for (const s of out.sessions) {
    const firsts = Object.entries(s.stages).map(([k, t]) => ({ k: Number(k), t })).sort((a, b) => a.t - b.t);
    const L = firsts.map(() => 1), P = firsts.map(() => -1);
    for (let i = 0; i < firsts.length; i++) for (let j = 0; j < i; j++) if (firsts[j].k < firsts[i].k && L[j] + 1 > L[i]) { L[i] = L[j] + 1; P[i] = j; }
    let bi = -1; L.forEach((v, i) => { if (bi < 0 || v > L[bi]) bi = i; });
    if (bi < 0) continue;
    const chain = []; for (let i = bi; i >= 0; i = P[i]) chain.unshift(firsts[i]);
    if (!best || chain.length > best.chain.length) best = { chain, session: s };
  }
  if (best && best.chain.length >= 3) {
    const lbl = (k) => Object.values(STAGE).find((v) => v[0] === k)[1];
    out.progression = { stages: best.chain.map((c) => ({ stage: lbl(c.k), at: c.t })), minutes: Math.round((best.chain[best.chain.length - 1].t - best.chain[0].t) / 60e3), session_from: best.session.from };
  }
  for (const s of out.sessions) delete s.stages;
  // rare values in the window (seen exactly once while the field has several values)
  for (const f of ['process', 'dst_ip', 'user', 'host']) {
    const m = new Map(); for (const e of ev) { const v = e[f]; if (v) m.set(v, (m.get(v) || 0) + 1); }
    if (m.size >= 5) for (const [v, c] of m) if (c === 1 && String(v).toLowerCase() !== subj) out.rare.push({ field: f, value: v });
  }
  out.rare = out.rare.slice(0, 20);
  // pivots: other entities in the timeline; one seen inside a burst weighs three times
  const pv = new Map();
  for (const e of ev) for (const [f, kind] of [['user', 'user'], ['host', 'host'], ['src_ip', 'ip'], ['dst_ip', 'ip']]) {
    const v = e[f]; if (!v || String(v).toLowerCase() === subj) continue;
    const k = kind + ':' + String(v).toLowerCase(), p = pv.get(k) || { entity: k, type: kind, value: v, events: 0, in_bursts: 0, external: kind === 'ip' && !isInternal(v) };
    p.events++; if (inBurst[e._b]) p.in_bursts++; pv.set(k, p);
  }
  out.pivots = [...pv.values()].map((p) => Object.assign(p, { weight: p.events + 2 * p.in_bursts })).sort((a, b) => b.weight - a.weight).slice(0, 15);
  // attention score - every point itemised
  const add = (pts, why) => { if (pts > 0) { out.reasons.push({ points: pts, why }); out.score += pts; } };
  const d4 = ev.filter((e) => e.lane === 'detection' && e.sev >= 4).length, d3 = ev.filter((e) => e.lane === 'detection' && e.sev === 3).length;
  add(Math.min(40, d4 * 25 + d3 * 15), `${d4} critical and ${d3} high detection(s)`);
  if (ev.some((e) => e.lane === 'evasion')) add(20, 'defence impairment (log cleared, auditing off or agent tampered)');
  if (ev.some((e) => e.lane === 'persistence')) add(15, 'persistence created (service, scheduled task, inbox / forwarding rule, run key)');
  if (out.progression) add(Math.min(25, 15 + 5 * (out.progression.stages.length - 3)), `${out.progression.stages.length} attack stages in order within ${out.progression.minutes} min`);
  if (out.bursts.length) add(10, `${out.bursts.length} burst(s) of activity well above this entity's normal`);
  const ext = out.pivots.filter((p) => p.external && p.in_bursts).length; if (ext) add(Math.min(10, 5 * ext), `${ext} external address(es) contacted during a burst`);
  ML.enrich(ev, out);   // beaconing, command lines, rare parent -> child, lateral fan-out, ATT&CK roll-up (dfir/ml.js)
  out.score = Math.min(100, out.score);
  return out;
}

function uuidFrom(s) { const h = sha(s); return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`; }
const stixQ = (v) => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
function stixPattern(i) {
  const v = stixQ(i.value);
  if (i.type === 'ipv4') return `[ipv4-addr:value = '${v}']`;
  if (i.type === 'ipv6') return `[ipv6-addr:value = '${v}']`;
  if (i.type === 'domain') return `[domain-name:value = '${v}']`;
  if (i.type === 'url') return `[url:value = '${v}']`;
  if (i.type === 'email') return `[email-addr:value = '${v}']`;
  return `[file:hashes.'${{ sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' }[i.type]}' = '${v}']`;
}

const ASK_SYSTEM = `You are the AI forensic analyst for ${ZYB_ORG.name}, helping the investigator of ONE incident case.
Use get_case_forensics first. Use entity_timeline_analysis for the hosts / users / IPs in scope (it returns the platform's own burst, session, attack-stage, rare, first-seen and pivot analysis plus a sample of events) and ioc_sightings for the case's indicators. Then call submit_answer once.
- Base every statement on tool results; never invent hosts, users, IPs, hashes, times or counts. Say what is unknown and what evidence is missing.
- Every finding cites a ref a tool returned (an evidence ref EV-…, an indicator value, an entity key user:… / host:… / ip:…, the case id).
- The timeline analysis also carries the platform's machine-learning findings: regular beacons (period, jitter), suspicious command lines (each feature named), rare parent -> child process pairs, lateral-movement fan-out, and the ATT&CK techniques they suggest. Use similar_cases to see how earlier cases like this one ended. For each finding weigh a benign explanation too (an updater beacons, an admin script is encoded, a jump host fans out) and say which evidence would tell them apart.
- The analysis is indicators, not proof: say "consistent with", not "proves". Personal data only as needed (PDPL).
- You cannot change anything: next_steps are steps for the investigator (preserve, collect, analyse, notify); containment is an approval request a named person decides.`;

function createForensics(deps = {}) {
  const { state, cases } = deps;
  if (!state || !cases) throw new Error('createForensics needs state and cases');
  const L = deps.log || { info() {}, warn() {}, error() {} };
  const now = deps.now || Date.now;
  const caseC = state.collection('dfir_case'), evC = state.collection('dfir_evidence'), iocC = state.collection('dfir_iocs'),
    setC = state.collection('dfir_settings'), aiC = state.collection('dfir_ai'), counters = state.collection('counters');
  const AI = createModel({ config: deps.config, deps, log: L });
  const nextId = (prefix, name) => { const n = ((counters.get(name) || {}).n || 0) + 1; counters.put({ id: name, n }); return `${prefix}-${String(n).padStart(6, '0')}`; };
  const who = (by) => String((by && by.user) || by || '').trim();
  const mustCase = (id) => { const c = cases.get(id); if (!c) throw httpErr(404, 'case not found: ' + id); return c; };
  const isClosedCase = (c) => typeof c.status === 'string' && c.status.startsWith('closed');

  function settings() {
    const s = setC.get('settings') || {};
    const regs = {}; for (const k of Object.keys(REGULATORS)) { const h = s.regulators && s.regulators[k] && s.regulators[k].hours; regs[k] = { name: REGULATORS[k], hours: Number.isFinite(h) && h > 0 ? h : null, basis: (s.regulators && s.regulators[k] && s.regulators[k].basis) || '' }; }
    return { regulators: regs, pdpl_hours: PDPL_HOURS, storage: Array.isArray(s.storage) ? s.storage : [], updated: s.updated || 0, updated_by: s.updated_by || '' };
  }
  function saveSettings(b, by) {
    const cur = setC.get('settings') || {}, regs = Object.assign({}, cur.regulators || {});
    for (const k of Object.keys(REGULATORS)) {
      if (b[k + '_hours'] !== undefined) regs[k] = Object.assign({}, regs[k], { hours: b[k + '_hours'] || null });
      if (b[k + '_basis'] !== undefined) regs[k] = Object.assign({}, regs[k], { basis: b[k + '_basis'] });
    }
    const rec = { id: 'settings', regulators: regs, storage: b.storage !== undefined ? b.storage : (cur.storage || []), updated: now(), updated_by: who(by) };
    setC.put(rec); return settings();
  }

  function overlay(id) {
    return caseC.get(id) || { id, type: '', aware_at: 0, personal_data: false, people_estimate: null, regulators: [], phase: 'identification', phase_history: [], hold: null, notifications: [], created: 0 };
  }
  function clocks(o, t) {
    const s = settings(), out = [];
    const one = (key, name, hours, basis) => {
      const sent = (o.notifications || []).find((x) => x.regulator === key);
      if (!o.aware_at) return out.push({ key, name, state: 'no-awareness-time', note: 'record when the company became aware to start the clock' });
      if (!hours) return out.push({ key, name, state: 'hours-not-set', note: 'an administrator enters the reporting hours from the ' + name + ' circular (DFIR settings)' });
      const due = o.aware_at + hours * H;
      if (sent) return out.push({ key, name, hours, basis, due, state: sent.at <= due ? 'notified' : 'notified-late', notified_at: sent.at, ref: sent.ref });
      return out.push({ key, name, hours, basis, due, state: t > due ? 'breached' : due - t <= 12 * H ? 'due-soon' : 'running', left_ms: due - t });
    };
    if (o.personal_data) one('sdaia', 'SDAIA (PDPL)', PDPL_HOURS, 'PDPL Implementing Regulation Art. 24 - 72 hours from awareness');
    for (const k of o.regulators || []) if (s.regulators[k]) one(k, s.regulators[k].name, s.regulators[k].hours, s.regulators[k].basis);
    return out;
  }
  const running = (cl) => cl.filter((c) => ['running', 'due-soon', 'breached', 'hours-not-set', 'no-awareness-time'].includes(c.state));

  function evView(e) { const v = verifyChain(e); return Object.assign({}, e, { chain_ok: v.ok, chain_broken_at: v.broken_at }); }
  function caseScope(c) {
    const out = new Set();
    for (const aid of c.alerts || []) {
      const a = deps.alerts && deps.alerts.get ? deps.alerts.get(aid) : null; if (!a) continue;
      const g = a.group || {}, f = a.fields || {};
      if (g.user) out.add('user:' + g.user); if (g.host) out.add('host:' + g.host);
      for (const k of ['src_ip', 'dst_ip']) { const v = g[k] || f[k]; if (v) out.add('ip:' + v); }
    }
    return [...out].slice(0, 30);
  }

  function board() {
    const t = now(), s = settings();
    let items = [];
    try { const r = cases.list({ limit: 500 }); items = (r.items || r) || []; } catch (e) { L.warn('dfir board: cases', { err: e && e.message }); }
    const rows = items.filter((c) => !isClosedCase(c) || caseC.get(c.id)).map((c) => {
      const o = overlay(c.id), cl = clocks(o, t), ev = evC.all((x) => x.case_id === c.id), io = iocC.all((x) => x.case_id === c.id && x.status === 'active');
      return { id: c.id, title: c.title, severity: c.severity, status: c.status, owner: c.owner || '', type: o.type, phase: o.phase, aware_at: o.aware_at, personal_data: o.personal_data,
        hold: !!(o.hold && o.hold.on), clocks: cl, evidence: ev.length, integrity_issues: ev.filter((x) => x.integrity === 'mismatch' || !verifyChain(x).ok).length, iocs: io.length, tracked: !!caseC.get(c.id) };
    });
    const allCl = rows.flatMap((r) => r.clocks);
    const kpis = { open: rows.filter((r) => !isClosedCase(r)).length, tracked: rows.filter((r) => r.tracked).length,
      breached: allCl.filter((c) => c.state === 'breached').length, due_soon: allCl.filter((c) => c.state === 'due-soon').length,
      unset: allCl.filter((c) => c.state === 'hours-not-set' || c.state === 'no-awareness-time').length,
      evidence: evC.all().length, integrity_issues: rows.reduce((a, r) => a + r.integrity_issues, 0), holds: rows.filter((r) => r.hold).length, iocs: iocC.all((x) => x.status === 'active').length };
    const attention = [];
    for (const r of rows) for (const c of r.clocks) {
      if (c.state === 'breached') attention.push({ level: 'bad', case_id: r.id, text: `${c.name} notification for ${r.id} is overdue (due ${new Date(c.due).toISOString().slice(0, 16).replace('T', ' ')} UTC)` });
      else if (c.state === 'due-soon') attention.push({ level: 'warn', case_id: r.id, text: `${c.name} notification for ${r.id} is due in ${Math.max(0, Math.round(c.left_ms / H))} h` });
      else if (c.state === 'hours-not-set') attention.push({ level: 'info', case_id: r.id, text: `${r.id} is reportable to ${c.name}, but its reporting hours are not set - an administrator enters them in Settings` });
    }
    for (const r of rows) if (r.integrity_issues) attention.push({ level: 'bad', case_id: r.id, text: `${r.integrity_issues} evidence item(s) on ${r.id} failed an integrity or custody-chain check` });
    for (const r of rows) if (r.personal_data && !r.aware_at) attention.push({ level: 'warn', case_id: r.id, text: `${r.id} involves personal data but has no awareness time - the PDPL 72-hour clock cannot start` });
    const rank = { bad: 0, warn: 1, info: 2 }; attention.sort((a, b) => rank[a.level] - rank[b.level]);
    const readiness = [
      { item: 'Event store for timelines', ok: !!deps.search, how: 'the SIEM event store (ClickHouse) is connected' },
      { item: 'Reporting hours for SAMA / NCA / IA', ok: Object.values(s.regulators).every((r) => r.hours), how: 'an administrator enters them from each circular in Settings' },
      { item: 'Evidence storage locations', ok: s.storage.length > 0, how: 'an administrator lists the evidence vaults / shares in Settings' },
      { item: 'Approver for triage collections', ok: hasApprover(), how: 'IT Asset Management → Roles & Functions: a DFIR or security approver' },
      { item: 'AI forensic analyst', ok: AI.status().enabled, how: AI.status().enabled ? 'available' : AI.status().reason },
    ];
    return { at: t, kpis, attention: attention.slice(0, 30), cases: rows.sort((a, b) => (b.severity || 0) - (a.severity || 0)), readiness, settings: s, ai: AI.status(),
      phases: PHASES, types: TYPES, regulators: Object.keys(REGULATORS).map((k) => ({ id: k, name: REGULATORS[k] })), ev_kinds: EV_KINDS, custody_actions: CUSTODY, ioc_types: IOC_TYPES };
  }
  function hasApprover() { try { const m = state.collection('approvers').get('map'); const sc = (m && m.scopes) || {}; return ['eng:dfir', 'security'].some((k) => Array.isArray(sc[k]) && sc[k].length); } catch (e) { return false; } }

  function caseView(id) {
    const c = mustCase(id), o = overlay(id), t = now();
    const ev = evC.all((x) => x.case_id === id).sort((a, b) => a.created - b.created).map(evView);
    const io = iocC.all((x) => x.case_id === id).sort((a, b) => a.created - b.created);
    const col = deps.dfir && deps.dfir.collections ? deps.dfir.collections({ case_id: id }).items || [] : [];
    const a = aiC.get(id);
    return { case: { id: c.id, title: c.title, severity: c.severity, status: c.status, owner: c.owner || '', created: c.created, alerts: (c.alerts || []).length },
      overlay: o, clocks: clocks(o, t), evidence: ev, iocs: io, collections: col, scope: caseScope(c), ai: a || null, ai_status: AI.status(), next_phase: PHASES[PHASES.indexOf(o.phase) + 1] || null };
  }

  function update(id, b, by) {
    const c = mustCase(id), o = overlay(id), t = now(), u = who(by), changed = {};
    if (b.type !== undefined) { o.type = b.type; changed.type = b.type; }
    if (b.aware_at !== undefined) {
      const ms = toMs(b.aware_at); if (!Number.isFinite(ms)) throw httpErr(400, 'aware_at must be a date and time');
      if (ms > t + 5 * 60e3) throw httpErr(400, 'aware_at cannot be in the future');
      if (o.aware_at && ms !== o.aware_at && (o.notifications || []).length) throw httpErr(409, 'a notification is already recorded against this awareness time - it cannot be moved');
      o.aware_at = ms; changed.aware_at = new Date(ms).toISOString();
    }
    if (b.personal_data !== undefined) { if (o.personal_data && !b.personal_data && (o.notifications || []).some((x) => x.regulator === 'sdaia')) throw httpErr(409, 'SDAIA was already notified - personal data cannot be un-marked'); o.personal_data = b.personal_data; changed.personal_data = b.personal_data; }
    if (b.people_estimate !== undefined) { o.people_estimate = b.people_estimate; changed.people_estimate = b.people_estimate; }
    if (b.regulators !== undefined) { o.regulators = [...new Set(b.regulators)]; changed.regulators = o.regulators; }
    if (b.phase !== undefined && b.phase !== o.phase) {
      const from = PHASES.indexOf(o.phase), to = PHASES.indexOf(b.phase);
      if (to > from + 1) throw httpErr(409, `phases go one step at a time: from ${o.phase} the next is ${PHASES[from + 1]}`);
      if (b.phase === 'closed') {
        const open = running(clocks(o, t)); if (open.length) throw httpErr(409, 'cannot close: ' + open.map((x) => x.name + ' (' + x.state + ')').join(', ') + ' - record each notification first');
        const bad = evC.all((x) => x.case_id === id && !verifyChain(x).ok); if (bad.length) throw httpErr(409, 'cannot close: the custody chain of ' + bad.map((x) => x.ref).join(', ') + ' does not verify');
      }
      if (to > from && !b.phase_note && ['acquisition', 'closed'].includes(b.phase)) throw httpErr(400, 'phase_note is required to move to ' + b.phase + ' (what was preserved / why the case is complete)');
      o.phase_history = (o.phase_history || []).concat([{ from: o.phase, to: b.phase, at: t, by: u, note: b.phase_note || '' }]).slice(-50);
      changed.phase = o.phase + ' → ' + b.phase; o.phase = b.phase;
    }
    if (!Object.keys(changed).length) throw httpErr(400, 'nothing to change');
    if (!o.created) { o.created = t; o.created_by = u; }
    o.updated = t; o.updated_by = u; caseC.put(o);
    try { cases.note(c.id, 'DFIR: ' + Object.entries(changed).map(([k, v]) => k + ' = ' + (Array.isArray(v) ? v.join(', ') || 'none' : v)).join('; '), u); } catch (e) { L.warn('dfir: case note failed', { case: id, err: e && e.message }); }
    return { overlay: o, clocks: clocks(o, t), changed };
  }

  function notify(id, b, by) {
    mustCase(id); const o = overlay(id), t = now();
    const ok = b.regulator === 'sdaia' ? o.personal_data : (o.regulators || []).includes(b.regulator);
    if (!ok) throw httpErr(409, b.regulator === 'sdaia' ? 'this case is not marked as involving personal data' : 'this case is not marked reportable to ' + (REGULATORS[b.regulator] || b.regulator));
    if ((o.notifications || []).some((x) => x.regulator === b.regulator)) throw httpErr(409, 'a notification to this regulator is already recorded');
    const at = b.at !== undefined ? toMs(b.at) : t; if (!Number.isFinite(at) || at > t + 5 * 60e3) throw httpErr(400, 'at must be a date and time, not in the future');
    o.notifications = (o.notifications || []).concat([{ regulator: b.regulator, at, ref: b.ref, note: b.note || '', recorded_by: who(by), recorded_at: t }]);
    if (!o.created) { o.created = t; o.created_by = who(by); }
    o.updated = t; caseC.put(o);
    try { cases.note(id, `DFIR: notification to ${b.regulator === 'sdaia' ? 'SDAIA (PDPL)' : REGULATORS[b.regulator]} recorded, reference ${b.ref}`, who(by)); } catch (e) { L.warn('dfir: case note failed', { case: id, err: e && e.message }); }
    return { overlay: o, clocks: clocks(o, t) };
  }

  function setHold(id, on, reason, by, role) {
    mustCase(id); const o = overlay(id), t = now(), u = who(by);
    if (!SC.isHuman(u)) throw httpErr(403, 'only a person places or releases a legal hold');
    if (on) {
      if (o.hold && o.hold.on) throw httpErr(409, 'a legal hold is already on, placed by ' + o.hold.by);
      o.hold = { on: true, by: u, at: t, reason };
    } else {
      if (!o.hold || !o.hold.on) throw httpErr(409, 'there is no legal hold on this case');
      if (role !== 'admin') throw httpErr(403, 'releasing a legal hold needs an administrator');
      if (String(o.hold.by).toLowerCase() === u.toLowerCase()) throw httpErr(403, 'four-eyes: the person who placed the hold cannot release it');
      o.hold = Object.assign({}, o.hold, { on: false, released_by: u, released_at: t, release_reason: reason });
    }
    if (!o.created) { o.created = t; o.created_by = u; }
    o.updated = t; caseC.put(o);
    try { cases.note(id, `DFIR: legal hold ${on ? 'placed' : 'released'} - ${reason}`, u); } catch (e) { L.warn('dfir: case note failed', { case: id, err: e && e.message }); }
    return { overlay: o };
  }

  // ---------------------------------------------------------------- evidence + custody chain
  const entryHash = (prev, e) => sha(prev + '|' + JSON.stringify([e.seq, e.at, e.by, e.action, e.to || '', e.note || '', e.sha256_observed || '', e.ref]));
  function verifyChain(e) {
    let prev = 'GENESIS:' + e.ref;
    for (const x of e.custody || []) { if (x.prev !== prev || x.hash !== entryHash(prev, x)) return { ok: false, broken_at: x.seq }; prev = x.hash; }
    return { ok: true, broken_at: null, entries: (e.custody || []).length, head: prev };
  }
  function pushCustody(e, x) {
    const prev = (e.custody && e.custody.length) ? e.custody[e.custody.length - 1].hash : 'GENESIS:' + e.ref;
    const entry = Object.assign({ seq: (e.custody || []).length + 1, ref: e.ref }, x, { prev });
    entry.hash = entryHash(prev, entry); e.custody = (e.custody || []).concat([entry]); return entry;
  }
  function addEvidence(caseId, b, by) {
    const c = mustCase(caseId), t = now(), u = who(by);
    if (isClosedCase(c) && overlay(caseId).phase === 'closed') throw httpErr(409, 'the forensic case is closed');
    const at = b.collected_at !== undefined ? toMs(b.collected_at) : t; if (!Number.isFinite(at) || at > t + 5 * 60e3) throw httpErr(400, 'collected_at must be a date and time, not in the future');
    const dup = evC.all((x) => x.case_id === caseId && x.sha256 === b.sha256.toLowerCase())[0];
    if (dup) throw httpErr(409, 'this SHA-256 is already registered on the case as ' + dup.ref);
    const e = { id: '', ref: nextId('EV', 'dfir_evidence'), case_id: caseId, kind: b.kind, description: b.description, sha256: b.sha256.toLowerCase(), sha1: b.sha1 ? b.sha1.toLowerCase() : '', md5: b.md5 ? b.md5.toLowerCase() : '',
      size_bytes: b.size_bytes == null ? null : b.size_bytes, source: b.source || '', location: b.location, collected_at: at, collected_by: b.collected_by || u, registered_by: u, created: t, integrity: 'as-registered', custody: [],
      note: 'the platform holds the hash and the custody record, not the file' };
    e.id = e.ref;
    pushCustody(e, { at, by: e.collected_by, action: 'collected', to: b.location, note: b.note || '' });
    evC.put(e); L.info('dfir evidence registered', { ref: e.ref, case: caseId, kind: e.kind, by: u });
    return evView(e);
  }
  function custody(ref, b, by) {
    const e = evC.get(ref); if (!e) throw httpErr(404, 'evidence not found: ' + ref);
    const o = overlay(e.case_id), t = now(), u = who(by);
    if (!verifyChain(e).ok) throw httpErr(409, 'the custody chain of ' + ref + ' does not verify - it cannot be extended; report the break');
    if (['released', 'returned'].includes(b.action) && o.hold && o.hold.on) throw httpErr(409, 'a legal hold is on (' + o.hold.reason + ') - evidence cannot be ' + b.action);
    if ((e.custody || []).some((x) => x.action === 'released' || x.action === 'returned')) throw httpErr(409, ref + ' was already released / returned');
    if (['transferred', 'copied', 'returned', 'released'].includes(b.action) && !b.to) throw httpErr(400, 'to is required for ' + b.action + ' (who or where it went)');
    const x = pushCustody(e, { at: t, by: u, action: b.action, to: b.to || '', note: b.note || '', sha256_observed: b.sha256_observed ? b.sha256_observed.toLowerCase() : '' });
    if (x.sha256_observed) { e.integrity = x.sha256_observed === e.sha256 ? 'verified' : 'mismatch'; e.integrity_at = t; e.integrity_by = u; }
    evC.put(e);
    if (e.integrity === 'mismatch') L.warn('dfir evidence integrity mismatch', { ref, by: u });
    return evView(e);
  }
  function verify(ref) { const e = evC.get(ref); if (!e) throw httpErr(404, 'evidence not found: ' + ref); return Object.assign({ ref, integrity: e.integrity }, verifyChain(e)); }

  // ---------------------------------------------------------------- IOCs, sightings, STIX
  function addIoc(caseId, b, by) {
    mustCase(caseId); const t = now();
    const value = b.type === 'domain' || b.type === 'email' || /^(sha|md5)/.test(b.type) ? b.value.toLowerCase() : b.value;
    if (!IOC_RE[b.type].test(value)) throw httpErr(400, 'value is not a valid ' + b.type);
    if (iocC.all((x) => x.case_id === caseId && x.type === b.type && x.value === value && x.status === 'active').length) throw httpErr(409, 'this indicator is already on the case');
    const r = { id: nextId('IOC', 'dfir_iocs'), case_id: caseId, type: b.type, value, note: b.note || '', source: b.source || '', status: 'active', created: t, created_by: who(by) };
    iocC.put(r); return r;
  }
  function retireIoc(id, reason, by) {
    const r = iocC.get(id); if (!r) throw httpErr(404, 'indicator not found: ' + id);
    if (r.status !== 'active') throw httpErr(409, 'indicator already ' + r.status);
    iocC.put(Object.assign(r, { status: 'retired', retired_by: who(by), retired_at: now(), retire_reason: reason })); return r;
  }
  function iocQuery(i) {
    const v = i.value;   // validated above: no quotes, spaces or backslashes reach the query
    if (i.type === 'ipv4' || i.type === 'ipv6') return `(src_ip:${v} OR dst_ip:${v} OR host_ip:${v})`;
    if (i.type === 'domain') return `(dns_query:"${v}" OR domain:"${v}" OR dns_query:"*.${v}")`;
    if (i.type === 'url') return `url:"${v}"`;
    if (i.type === 'email') return `(user:"${v}" OR target_user:"${v}")`;
    return `hash:"${v}"`;
  }
  async function sightings(caseId, days) {
    mustCase(caseId);
    if (!deps.search) throw httpErr(503, 'the event store is not available on this SIEM');
    const to = now(), from = to - (days || 30) * DAY, list = iocC.all((x) => x.case_id === caseId && x.status === 'active').slice(0, 50), out = [];
    for (const i of list) {
      try {
        const q = iocQuery(i);
        const last = await deps.search({ q, from, to, limit: 50, fields: ['ts', 'host', 'user', 'src_type'], order: 'desc' });
        const first = (last.rows || []).length ? await deps.search({ q, from, to, limit: 1, fields: ['ts'], order: 'asc' }) : { rows: [] };
        const hosts = [...new Set((last.rows || []).map((r) => r.host).filter(Boolean))].slice(0, 10);
        out.push({ id: i.id, type: i.type, value: i.value, events: last.total_estimate != null ? last.total_estimate : (last.rows || []).length, first: (first.rows[0] || {}).ts || null, last: ((last.rows || [])[0] || {}).ts || null, hosts, sources: [...new Set((last.rows || []).map((r) => r.src_type).filter(Boolean))] });
      } catch (e) { L.warn('dfir ioc sighting failed', { ioc: i.id, err: e && e.message }); out.push({ id: i.id, type: i.type, value: i.value, error: String(e.message || e).slice(0, 200) }); }
    }
    return { case_id: caseId, days: days || 30, items: out, seen: out.filter((x) => x.events > 0).length };
  }
  function stix(caseId) {
    const c = mustCase(caseId), t = new Date(now()).toISOString(), idn = 'identity--' + uuidFrom('sentra-dfir');
    const objs = [{ type: 'identity', spec_version: '2.1', id: idn, created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z', name: (ZYB_ORG.name + ' - DFIR'), identity_class: 'organization' }];
    for (const i of iocC.all((x) => x.case_id === caseId && x.status === 'active')) {
      const cr = new Date(i.created).toISOString();
      objs.push({ type: 'indicator', spec_version: '2.1', id: 'indicator--' + uuidFrom(caseId + '|' + i.type + '|' + i.value), created: cr, modified: cr, created_by_ref: idn,
        name: i.type + ' ' + i.value, description: (i.note || '').slice(0, 500), indicator_types: ['malicious-activity'], pattern: stixPattern(i), pattern_type: 'stix', valid_from: cr,
        labels: ['case:' + c.id], confidence: 50 });
    }
    return { type: 'bundle', id: 'bundle--' + uuidFrom(caseId + '|' + t), objects: objs };
  }

  // ---------------------------------------------------------------- timeline analysis (wraps dfir.timeline)
  async function analyseEntity({ entity, type, hours }) {
    if (!deps.dfir) throw httpErr(503, 'the event store is not available on this SIEM');
    const tl = await deps.dfir.timeline({ entity, type, hours, limit: 3000 });
    const a = analyse(tl.rows, { subject: entity });
    a.first_seen = []; a.first_seen_note = '';
    const nv = deps.search && deps.search.newValues;
    if (typeof nv === 'function' && deps.dfir.queryFor) {
      for (const field of ['process', 'dns_query', 'dst_ip']) {
        try { const r = await nv({ q: deps.dfir.queryFor(entity, tl.type), from: tl.from, to: tl.to, field, baselineDays: 30, limit: 15 }); for (const v of r.values || []) a.first_seen.push({ field, value: v.v, n: v.n }); }
        catch (e) { a.first_seen_note = 'first-seen check failed for ' + field + ': ' + String(e.message || e).slice(0, 160); L.warn('dfir first-seen failed', { field, err: e && e.message }); }
      }
      const fs = a.first_seen.length; if (fs) { const p = Math.min(15, 5 * fs); a.reasons.push({ points: p, why: `${fs} value(s) never seen for this entity in the previous 30 days` }); a.score = Math.min(100, a.score + p); }
    } else a.first_seen_note = 'first-seen against a 30-day baseline needs the event store';
    return { timeline: tl, analysis: a };
  }

  // ---------------------------------------------------------------- cases like this one (ml.js similar)
  function features(c) {
    const rules = new Set(), tech = new Set();
    for (const aid of c.alerts || []) { const a = deps.alerts && deps.alerts.get ? deps.alerts.get(aid) : null; if (!a) continue; if (a.rule_id) rules.add(String(a.rule_id)); for (const m of a.mitre || []) tech.add(String(m).toUpperCase()); }
    const o = caseC.get(c.id) || {};
    return { id: c.id, title: c.title, status: c.status, severity: c.severity, resolution: c.resolution, created: c.created, closed: c.closed, type: o.type || '',
      entities: caseScope(c).map((x) => x.toLowerCase()), rules: [...rules], techniques: [...tech], iocs: iocC.all((x) => x.case_id === c.id && x.status === 'active').map((x) => String(x.value).toLowerCase()) };
  }
  function similarCases(id) {
    const c = mustCase(id); let all = [];
    try { const r = cases.list({ status: 'all', limit: 2000 }); all = (r.items || r) || []; } catch (e) { L.warn('dfir similar: cases', { err: e && e.message }); }
    const T = features(c), items = ML.similar(T, all.filter((x) => x.id !== c.id).map((x) => features(cases.get ? cases.get(x.id) || x : x)));
    const closed = items.filter((x) => x.status === 'closed');
    return { case: c.id, compared: all.length - 1, items, basis: { entities: T.entities.length, rules: T.rules.length, iocs: T.iocs.length, techniques: T.techniques.length, type: T.type || null },
      outcome: closed.length ? { closed: closed.length, by_resolution: closed.reduce((m, x) => { m[x.resolution || 'unrecorded'] = (m[x.resolution || 'unrecorded'] || 0) + 1; return m; }, {}), median_hours: closed.filter((x) => x.hours_to_close != null).map((x) => x.hours_to_close).sort((a, b) => a - b)[Math.floor((closed.filter((x) => x.hours_to_close != null).length - 1) / 2)] ?? null } : null,
      note: 'Similarity is shared entities, detection rules, indicators, ATT&CK techniques and incident type - how similar cases ended is a lead, never a reason to close this one.' };
  }

  // ---------------------------------------------------------------- AI forensic analyst
  const TOOLS = [
    { name: 'get_case_forensics', description: 'The case and its forensic record: type, phase, awareness time, personal data, regulatory clocks, legal hold, evidence register (refs, kinds, integrity, custody entries) and indicators.', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'entity_timeline_analysis', description: "The platform's analysis of one host / user / IP timeline: bursts, sessions, attack stages in order, rare and first-seen values, pivots, attention score with reasons, and up to 40 sample events.", role: 'analyst',
      input_schema: S({ properties: { entity: STR(200), hours: { type: 'integer', minimum: 1, maximum: 720 } }, required: ['entity'] }) },
    { name: 'similar_cases', description: 'Earlier cases like this one (shared entities, detection rules, indicators, ATT&CK techniques, type) with how each closed and how long it took. A lead, never a reason to close.', role: 'analyst', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'ioc_sightings', description: 'For each active indicator on the case: events in the event store over the last 30 days, first / last seen and hosts.', role: 'analyst', input_schema: S({ properties: { id: STR(40) }, required: ['id'] }) },
    { name: 'submit_answer', description: 'Submit the answer to the investigator.', input_schema: S({ properties: {
      answer: STR(6000), findings: { type: 'array', maxItems: 20, items: S({ properties: { text: STR(600), ref: STR(300) }, required: ['text', 'ref'] }) },
      next_steps: { type: 'array', maxItems: 12, items: STR(400) }, gaps: { type: 'array', maxItems: 12, items: STR(400) } }, required: ['answer'] }) },
  ];
  async function runTool(caseId, name, i, seen) {
    if (name === 'get_case_forensics') {
      if (String(i.id) !== caseId) return { note: 'only the case being asked about can be read: ' + caseId };
      const v = caseView(caseId); seen.add(caseId);
      for (const e of v.evidence) seen.add(e.ref); for (const x of v.iocs) seen.add(x.value); for (const s of v.scope) seen.add(s.toLowerCase());
      return { case: v.case, overlay: { type: v.overlay.type, phase: v.overlay.phase, aware_at: v.overlay.aware_at ? new Date(v.overlay.aware_at).toISOString() : null, personal_data: v.overlay.personal_data, regulators: v.overlay.regulators, hold: v.overlay.hold && v.overlay.hold.on ? 'on' : 'off' },
        clocks: v.clocks.map((c) => ({ name: c.name, state: c.state, due: c.due ? new Date(c.due).toISOString() : null })), scope: v.scope,
        evidence: v.evidence.map((e) => ({ ref: e.ref, kind: e.kind, description: String(e.description).slice(0, 300), source: e.source, integrity: e.integrity, chain_ok: e.chain_ok, custody: e.custody.map((x) => x.action + ' ' + new Date(x.at).toISOString()) })),
        iocs: v.iocs.filter((x) => x.status === 'active').map((x) => ({ type: x.type, value: x.value, note: x.note })), collections: v.collections.map((c) => ({ id: c.id, entity: c.entity, status: c.status, items: c.items })) };
    }
    if (name === 'entity_timeline_analysis') {
      const ent = String(i.entity).replace(/^(user|host|ip):/i, '');
      const r = await analyseEntity({ entity: ent, hours: i.hours || 72 }); const a = r.analysis, kind = r.timeline.type;
      seen.add(kind + ':' + ent.toLowerCase()); seen.add(ent.toLowerCase()); for (const p of a.pivots) seen.add(p.entity);
      for (const f of a.first_seen) seen.add(String(f.value).toLowerCase());
      for (const b of a.beacons) seen.add(String(b.destination).toLowerCase()); for (const l of a.lateral) { seen.add(String(l.source).toLowerCase()); for (const h of l.hosts) seen.add('host:' + String(h.host).toLowerCase()); }
      return { entity: kind + ':' + ent, events: a.events, score: a.score, reasons: a.reasons, bursts: a.bursts.map((b) => ({ from: new Date(b.from).toISOString(), to: new Date(b.to).toISOString(), events: b.events, lanes: b.lanes })),
        sessions: a.sessions.slice(-10).map((s) => ({ from: new Date(s.from).toISOString(), to: new Date(s.to).toISOString(), events: s.events })), progression: a.progression, rare: a.rare, first_seen: a.first_seen, pivots: a.pivots,
        beacons: a.beacons, commands: a.commands.slice(0, 10).map((c) => Object.assign({}, c, { cmdline: String(c.cmdline).slice(0, 300) })), rare_pairs: a.rare_pairs, lateral: a.lateral, techniques: a.techniques,
        sample: r.timeline.rows.filter((x) => x.lane !== 'other').slice(-40).map((x) => ({ ts: x.ts, lane: x.lane, sev: x.sev, title: String(x.title).slice(0, 220) })) };
    }
    if (name === 'similar_cases') { if (String(i.id) !== caseId) return { note: 'only the case being asked about: ' + caseId }; const r = similarCases(caseId); for (const x of r.items) seen.add(x.id); return r; }
    if (name === 'ioc_sightings') { if (String(i.id) !== caseId) return { note: 'only the case being asked about: ' + caseId }; const r = await sightings(caseId, 30); for (const x of r.items) { seen.add(x.value); for (const h of x.hosts || []) seen.add('host:' + String(h).toLowerCase()); } return r; }
    throw new Error('unknown tool ' + name);
  }
  async function ask(caseId, question, w) {
    mustCase(caseId);
    const st = AI.status(); if (!st.enabled) throw httpErr(503, st.reason);
    const q = G.redactSecrets(String(question || '')).slice(0, 2000);
    const r = await runLoop({ client: AI.client(), model: AI.model(), effort: AI.effort(), system: ASK_SYSTEM, tools: TOOLS, role: w.role || 'analyst', user: w.user || 'unknown', feature: 'dfir.ask', config: deps.config, log: L,
      prompt: `Case ${caseId}. The investigator asks:\n${G.untrusted('investigator-question', q)}\nUse the tools, then call submit_answer.`, run: (n, inp, seen) => runTool(caseId, n, inp, seen), final: 'submit_answer', maxSteps: 10 });
    if (!r.result) throw httpErr(502, 'the AI did not return an answer (' + r.note + ') - try again');
    const chk = (v) => { const s = String(v || '').trim(); return r.seen.has(s) || r.seen.has(s.toLowerCase()); };
    const d = r.result, findings = (d.findings || []).map((f) => ({ text: f.text, ref: f.ref, verified: chk(f.ref) }));
    const rec = { id: caseId, state: 'draft', at: now(), by: AI.model(), asked_by: w.user, role: w.role, question: q, answer: d.answer, findings, next_steps: d.next_steps || [], gaps: d.gaps || [],
      unverified: findings.filter((f) => !f.verified).length, steps: r.steps, usage: r.usage, injection_signals: r.flags };
    aiC.put(rec); L.info('dfir ai answer', { case: caseId, user: w.user, steps: r.steps.length, unverified: rec.unverified });
    return rec;
  }
  function decideAsk(caseId, decision, w) {
    if (!SC.isHuman(w.user)) throw httpErr(403, 'only a person adds an AI answer to a case');
    const r = aiC.get(caseId); if (!r) throw httpErr(404, 'no AI answer for ' + caseId);
    if (r.state !== 'draft') throw httpErr(409, 'this answer was already ' + r.state);
    if (decision === 'add') {
      const ok = r.findings.filter((f) => f.verified);
      const text = `DFIR analysis (AI draft, reviewed and added by ${w.user})\nQ: ${r.question}\n\n${r.answer}` + (ok.length ? '\n\nFindings:\n- ' + ok.map((f) => f.text + ' [' + f.ref + ']').join('\n- ') : '')
        + (r.next_steps.length ? '\n\nNext steps:\n- ' + r.next_steps.join('\n- ') : '') + (r.gaps.length ? '\n\nGaps:\n- ' + r.gaps.join('\n- ') : '') + (r.unverified ? `\n\n(${r.unverified} finding(s) cited something no tool returned and were left out.)` : '');
      cases.note(caseId, text.slice(0, 20000), w.user);
    }
    aiC.put(Object.assign({}, r, { state: decision === 'add' ? 'added' : 'discarded', decided_by: w.user, decided_at: now() }));
    return aiC.get(caseId);
  }

  return { board, caseView, update, notify, setHold, addEvidence, custody, verify, addIoc, retireIoc, sightings, stix, analyseEntity, similarCases, ask, decideAsk, settings, saveSettings, TOOLS };
}

module.exports = { createForensics, analyse, stixPattern, TYPES, PHASES, EV_KINDS, CUSTODY, IOC_TYPES, IOC_RE, REGULATORS, PDPL_HOURS };
