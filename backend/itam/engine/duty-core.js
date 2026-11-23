// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI engineers' duty desk — the part that makes an AI engineer work like an engineer instead of waiting to be asked.
 * The SAME file runs in the SIEM (engine/duty/duty-core.js: network, security, Windows, Exchange) and in IT Asset
 * Management (engine/duty-core.js: penetration testing, desktop support); a test fails if the two copies differ.
 *
 * Each engineer is an adapter:
 *   { id, name,
 *     findings()            → [{ key, severity:'critical'|'high'|'medium'|'low', kind, title, evidence[], recommendation,
 *                                target:{type,id,name}, site }]   (null = source not connected: nothing is created or closed)
 *     investigate?(item)    → { summary, checks:[{name,status,detail}], causes:[{cause,confidence,fix}] }   read-only
 *     aiStatus?()           → { enabled, reason }
 *     aiInvestigate?(item, { onChange })  → { answer, steps, model }   may propose a change plan (never executes one)
 *     propose?(item, { onChange })        → { note }   rule-based proposal, no AI (e.g. request a patch install for approval)
 *     changeStatus?(id)     → { status, comment } of a change plan (proposed / approved / rejected / applied / validated …)
 *     verify?(item)         → { present:boolean, note }   re-checks the target now (a fresh poll), read-only }
 *
 * The duty cycle, every patrol (default 10 min):
 *   1. read the engineer's findings → each problem is one WORK ITEM (identity = engineer + finding key)
 *   2. a new problem is opened; one that comes back after being fixed is RE-OPENED, loudly, with its history
 *   3. open items are INVESTIGATED (read-only checks, the deterministic troubleshooter) → diagnosed
 *   4. serious items (policy.ai_min_severity, default high; at most policy.ai_daily_cap a day) get an AI root-cause
 *      analysis; when the fix is a change, the AI records a change plan in the existing workflow — an administrator
 *      approves it and a person applies it. NOTHING is executed by the duty desk.
 *   5. linked change plans are followed: approved → waiting to be applied; applied → VERIFIED by a fresh re-check;
 *      still present after the fix → back to a person (needs-human)
 *   6. a problem no longer detected is resolved as "cleared" (or "verified-fixed" after a change); never deleted
 *   7. optional ServiceDesk ticket at or above policy.ticket_min_severity
 *   8. a shift handover report per engineer every day at policy.report_hour (Riyadh time)
 * policy.ai_off lists engineers whose EXTERNAL AI is switched off: no AI on patrol, no Investigate with AI, and the engine's
 * Ask / chat routes check aiAllowed(id) too - the engineer keeps working on its rules.
 * People can acknowledge / assign, add notes, snooze with a reason, close with one of four codes, or ask for an
 * investigation now. A finding source that is not connected never resolves anything: silence is not health.
 *
 * createDuty({ store, log, now, engineers, ticketer?, audit?, policyDefaults?, python? })
 *
 * python (migration step 7, docs/PYTHON-MIGRATION.md in sentra-itam): the interpreter that runs duty_rules.py (next to this
 * file, also identical in both engines). The patrol's open / update / re-open / clear / snooze decisions and the views
 * (list, engineers, KPIs, shift handover) are then computed in Python from the same inputs; calling the engineers
 * (findings, checks, AI, change plans) stays here. No python, a missing interpreter or a failing call = the Node.js
 * functions below (planPatrol, listCore, engineersCore, kpisCore, reportCore) answer, exactly as before.
 */
const { spawn } = require('node:child_process');
const nodePath = require('node:path');
const nodeFs = require('node:fs');
const SEV = { low: 1, medium: 2, high: 3, critical: 4 };
const TERMINAL = new Set(['resolved', 'closed']);
const CLOSE_CODES = {
  fixed: 'Fixed by a person outside the change workflow - re-opens if it comes back',
  'accepted-risk': 'Known and accepted (with a reason) - not raised again for 30 days',
  'false-positive': 'The check is wrong for this target - not raised again for 30 days',
  duplicate: 'Already tracked in another work item or ticket',
};
const DEFAULT_POLICY = {
  enabled: true, patrol_min: 10, max_investigations: 5, ai_min_severity: 'high', ai_daily_cap: 10,
  ticket_min_severity: 'off', report_hour: 7, reopen_window_days: 7, verify_every_min: 15,
  ai_off: [],   // engineers whose external AI is switched off (patrol, Investigate with AI, Ask / chat): rules only
};
// KPI targets every engineer is measured against (admin can override per engineer: policy.kpi_targets[engineer][id])
const KPI_DEFAULTS = { open_serious: 0, sla_pct: 90, human_h: 4, approval_h: 24, fix_h: 72, fix_success_pct: 90, reopen_pct: 10, patrol_pct: 95, diag_min: 30 };
const SLA_H = { critical: 24, high: 72, medium: 168, low: 720 };   // time to resolve, by severity
const AI_OFF_REASON = 'external AI is switched off for this engineer (AI Engineering Team → Duty policy → External AI per engineer)';
const DAY = 86400000;
const clip = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u0008\u000b-\u001f]/g, '').slice(0, n);
const riyadh = (t) => new Date(t + 3 * 3600000);                 // Saudi Arabia: UTC+3, no daylight saving
const riyadhDay = (t) => riyadh(t).toISOString().slice(0, 10);

const sevOf = (s) => SEV[s] || 0;
const histOf = (x) => x.history || [];
const RULES_PY = nodePath.join(__dirname, 'duty_rules.py');

// one call to duty_rules.py: ONE JSON request on stdin, ONE JSON answer on stdout, a time limit; null = use Node.js
function pyRules(python, timeoutMs) {
  let missingUntil = 0;
  return (op, body) => new Promise((resolve) => {
    if (!python || Date.now() < missingUntil || !nodeFs.existsSync(RULES_PY)) return resolve(null);
    let p; try { p = spawn(python, ['-I', RULES_PY], { stdio: ['pipe', 'pipe', 'pipe'], env: Object.assign({ PATH: process.env.PATH || '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1', LANG: 'C.UTF-8' }, process.env.TZ ? { TZ: process.env.TZ } : {}) }); } catch (e) { missingUntil = Date.now() + 600000; return resolve(null); }
    let out = '', done = false;
    const fin = (v) => { if (done) return; done = true; clearTimeout(t); resolve(v); };
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (e) { /* gone */ } fin(null); }, timeoutMs || 60000);
    p.on('error', () => { missingUntil = Date.now() + 600000; fin(null); });   // no interpreter: do not try again for 10 min
    p.stdout.on('data', (d) => { out += d; if (out.length > 64 * 1048576) { try { p.kill('SIGKILL'); } catch (e) { /* gone */ } fin(null); } });
    p.stderr.on('data', () => {});
    p.on('close', () => { let v = null; try { v = JSON.parse(out); } catch (e) { v = null; } fin(v && v.ok !== false ? v : null); });
    p.stdin.on('error', () => { /* answered by close */ });
    p.stdin.end(JSON.stringify(Object.assign({ op }, body || {})));
  });
}

function fromFinding(f) {
  const o = {
    severity: SEV[f.severity] ? f.severity : 'medium', kind: clip(f.kind, 60), title: clip(f.title, 240),
    evidence: [].concat(f.evidence || []).map((x) => clip(typeof x === 'string' ? x : JSON.stringify(x), 400)).slice(0, 8),
    recommendation: clip(f.recommendation, 2000), site: clip(f.site, 80),
    target: { type: clip(f.target && f.target.type, 30), id: clip(f.target && f.target.id, 120), name: clip(f.target && f.target.name, 160) },
  };
  // Arabic, when the engineer's rules write it (the PDPL consultant: pyengine/pdpl_ar.py); other engineers' items are unchanged
  if (f.title_ar) Object.assign(o, { title_ar: clip(f.title_ar, 240), recommendation_ar: clip(f.recommendation_ar, 2000) });
  return o;
}

/* the patrol's bookkeeping (steps 1, 2, 6 and the snoozes that ran out) over the engineer's items - pure: returns the
   records to write, the new work-item counter and the counts. findings = the engineer's list, or null when the source did
   not answer with one (then nothing is opened or resolved). */
function planPatrol(inp) {
  const t0 = inp.now, P = inp.policy || {}, live = Array.isArray(inp.findings), eng = { id: inp.engineer, name: inp.engineer_name };
  let n = inp.counter || 0;
  const touched = new Map(), out = { opened: 0, reopened: 0, updated: 0, cleared: 0 };
  const save = (it) => { it.updated = t0; touched.set(it.id, it); };
  const hist = (it, by, action, note) => { it.history = (it.history || []).concat([{ at: t0, by: by || 'duty', action, note: clip(note, 1000) }]).slice(-100); };
  const mine = (inp.items || []).slice(), added = [];
  const byKey = new Map(); if (live) for (const f of inp.findings) if (f && f.key) byKey.set(String(f.key), f);
  const active = new Map(), recent = new Map();
  for (const it of mine) {
    if (!TERMINAL.has(it.status)) active.set(it.key, it);
    else { const prev = recent.get(it.key); if (!prev || (it.resolved_at || 0) > (prev.resolved_at || 0)) recent.set(it.key, it); }
  }
  if (live) {
    // 1-2: open, update, re-open
    for (const [key, f] of byKey) {
      const v = fromFinding(f);
      let it = active.get(key);
      if (it) {
        const worse = sevOf(v.severity) > sevOf(it.severity);
        Object.assign(it, { last_seen: t0, seen_count: (it.seen_count || 0) + 1, evidence: v.evidence, title: v.title, recommendation: v.recommendation || it.recommendation }, v.title_ar ? { title_ar: v.title_ar, recommendation_ar: v.recommendation_ar } : {});
        if (worse) { hist(it, 'duty', 'escalated', `${it.severity} → ${v.severity}`); it.severity = v.severity; }
        save(it); out.updated++; continue;
      }
      const old = recent.get(key);
      if (old && old.status === 'closed' && old.suppress_until && old.suppress_until > t0) { old.last_seen = t0; old.suppressed_seen = (old.suppressed_seen || 0) + 1; save(old); continue; }
      if (old && (t0 - (old.resolved_at || 0)) <= P.reopen_window_days * DAY && !(old.status === 'closed' && old.close_code === 'duplicate')) {
        Object.assign(old, v, { status: 'open', last_seen: t0, seen_count: (old.seen_count || 0) + 1, reopened: (old.reopened || 0) + 1, resolved_at: null, resolution: null, investigation: null, verify_at: 0 });
        hist(old, 'duty', 'reopened', 'the problem came back after it was ' + (old.close_code ? 'closed (' + old.close_code + ')' : 'resolved'));
        save(old); out.reopened++; continue;
      }
      n += 1;
      it = Object.assign({ id: 'DW-' + String(n).padStart(6, '0'), engineer: eng.id, engineer_name: eng.name, key, status: 'open', first_seen: t0, last_seen: t0, seen_count: 1, detected_at: t0,
        investigation: null, ai: null, changes: [], ticket: null, owner: '', reopened: 0, history: [] }, v);
      hist(it, 'duty', 'opened', v.title);
      save(it); added.push(it); out.opened++;
    }
    // 6: no longer detected → resolved (never deleted)
    for (const [key, it] of active) {
      if (byKey.has(key)) continue;
      const fixed = it.status === 'fix-applied';   // only a change a person applied counts as a fix
      it.status = 'resolved'; it.resolved_at = t0; it.resolution = fixed ? 'verified-fixed' : 'cleared';
      hist(it, 'duty', it.resolution, fixed ? 'no longer detected after the change was applied' : 'no longer detected at the patrol');
      save(it); out.cleared++;
    }
  }
  // snoozes that ran out
  for (const it of mine.concat(added)) {
    if (!(it.status === 'snoozed' && it.snooze_until && it.snooze_until <= t0)) continue;
    it.status = it.investigation ? 'diagnosed' : 'open'; hist(it, 'duty', 'snooze-ended', ''); save(it);
  }
  return { puts: [...touched.values()], counter: n, out };
}

function listCore(inp) {
  const f = inp.filter || {};
  let all = (inp.items || []).filter((x) => (!f.engineer || x.engineer === f.engineer));
  if (f.status === 'open') all = all.filter((x) => !TERMINAL.has(x.status));
  else if (f.status) all = all.filter((x) => x.status === f.status);
  if (f.since) all = all.filter((x) => (x.updated || 0) >= Number(f.since));
  all.sort((a, b) => (TERMINAL.has(a.status) - TERMINAL.has(b.status)) || sevOf(b.severity) - sevOf(a.severity) || (b.last_seen || 0) - (a.last_seen || 0));
  const lim = Math.min(Number(f.limit) || 300, 1000);
  const slim = (x) => { const o = Object.assign({}, x); delete o.history; if (o.ai) o.ai = { at: o.ai.at, error: o.ai.error, proposed: o.ai.proposed, steps: o.ai.steps }; return o; };
  return { items: all.slice(0, lim).map(slim), total: all.length };
}

// engineers: [{ id, name, st, ai (aiStatusOf), used_today }] - the AI status is the engineer's own, read by Node.js
function engineersCore(inp) {
  const P = inp.policy || {}, t = inp.now, all = inp.items || [];
  return (inp.engineers || []).map((e) => {
    const st = e.st || {}, mine = all.filter((x) => x.engineer === e.id), open = mine.filter((x) => !TERMINAL.has(x.status));
    const by = {}; for (const x of open) by[x.status] = (by[x.status] || 0) + 1;
    const s = e.ai;
    const late = P.enabled && st.last_patrol && t - st.last_patrol > 3 * P.patrol_min * 60000;
    return { id: e.id, name: e.name, on_duty: P.enabled, last_patrol: st.last_patrol || null, last_ms: st.last_ms || null, patrols: st.patrols || 0,
      late: !!late, last_error: st.last_error || null, last_error_at: st.last_error_at || null, not_connected: !!(st.last_result && st.last_result.not_connected),
      open: open.length, by_status: by, critical: open.filter((x) => x.severity === 'critical').length, high: open.filter((x) => x.severity === 'high').length,
      resolved_24h: mine.filter((x) => TERMINAL.has(x.status) && t - (x.resolved_at || 0) < DAY).length,
      ai: s ? { enabled: !!s.enabled, off: !!s.off, reason: s.reason || '', used_today: e.used_today, cap: P.ai_daily_cap } : null };
  });
}

/* ---- KPIs: how well each engineer (with the people who approve and apply its fixes) is doing, from the work items only.
   A KPI with nothing to measure in the window says "not measured" - never a good score by default.
   inp: { engineer, name, now, days, policy, targets, st, items (the engineer's), domain (the adapter's own measures, or null) } */
const human = (by) => !!by && by !== 'duty' && !/^(system|core)[:-]/.test(by);
const median = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const r1 = (v) => (v == null ? null : Math.round(v * 10) / 10);
function kpisCore(inp) {
  const engId = inp.engineer, t = inp.now, days = Math.min(90, Math.max(1, Math.round(Number(inp.days) || 30))), since = t - days * DAY, P = inp.policy || {}, TG = inp.targets, st = inp.st || {};
  const mine = inp.items || [], open = mine.filter((x) => !TERMINAL.has(x.status));
  const resolved = mine.filter((x) => TERMINAL.has(x.status) && (x.resolved_at || 0) >= since);
  const H = histOf;
  // 1 open serious
  const serious = open.filter((x) => sevOf(x.severity) >= 3 && x.status !== 'snoozed');
  // 2 SLA: serious resolved in the window within SLA_H + serious open now that are already past it
  const slaRes = resolved.filter((x) => sevOf(x.severity) >= 3 && x.resolution !== 'closed:duplicate'), slaOpenLate = serious.filter((x) => t - (x.detected_at || x.first_seen) > SLA_H[x.severity] * 3600000);
  const slaOk = slaRes.filter((x) => (x.resolved_at - (x.detected_at || x.first_seen)) <= SLA_H[x.severity] * 3600000).length, slaN = slaRes.length + slaOpenLate.length;
  // 3 time to diagnosis (automatic) and 4 first human response (serious items opened in the window)
  const opened = mine.filter((x) => (x.detected_at || 0) >= since);
  const diag = opened.map((x) => { const h = H(x).find((e) => e.action === 'diagnosed'); return h ? (h.at - x.detected_at) / 60000 : null; }).filter((v) => v != null);
  const hum = opened.filter((x) => sevOf(x.severity) >= 3).map((x) => { const h = H(x).find((e) => human(e.by) && e.at >= x.detected_at); if (h) return (h.at - x.detected_at) / 3600000; const age = (t - x.detected_at) / 3600000; return !TERMINAL.has(x.status) && age > TG.human_h ? age : null; }).filter((v) => v != null);   // untouched + already past the target counts; untouched and young is not measured yet
  // 5 human approval: a fix proposed → approved / applied / rejected (the decision a person made in the change workflow)
  const appr = [], waiting = [];
  for (const x of mine) {
    const h = H(x);
    h.forEach((e, i) => {
      if (e.action !== 'fix-proposed') return;
      const d = h.slice(i + 1).find((n) => n.action === 'approved' || n.action === 'fix-applied' || n.action === 'needs-human' || n.action === 'verified-fixed');
      if (d) { if (d.at >= since) appr.push((d.at - e.at) / 3600000); } else if (x.status === 'awaiting-approval') waiting.push((t - e.at) / 3600000);
    });
  }
  // 6 time to fix + 7 fixes that held when re-checked
  const fixed = resolved.filter((x) => x.resolution === 'verified-fixed' || x.resolution === 'closed:fixed');
  const stillThere = mine.reduce((n, x) => n + H(x).filter((e) => e.action === 'still-present' && e.at >= since).length, 0);
  const vfix = resolved.filter((x) => x.resolution === 'verified-fixed').length;
  // 8 came back
  const reopened = mine.filter((x) => H(x).some((e) => e.action === 'reopened' && e.at >= since)).length;
  // 9 patrols
  const late = P.enabled && !!st.last_patrol && t - st.last_patrol > 3 * P.patrol_min * 60000;   // never patrolled yet = not measured
  const patrolPct = st.patrols ? Math.max(0, 100 - (st.errors || 0) / st.patrols * 100) : null;
  const notConn = !!(st.last_result && st.last_result.not_connected);
  const K = (id, label, value, unit, dir, detail, measured = value != null) => {
    const target = TG[id]; let status = 'na';
    if (measured && value != null) {
      if (dir === 'max') status = value <= target ? 'ok' : target && value <= target * 1.5 ? 'warn' : 'bad';   // a target of 0 has no grey zone
      else status = value >= target ? 'ok' : value >= target * 0.85 ? 'warn' : 'bad';
    }
    return { id, label, value: measured ? r1(value) : null, unit, target, dir, status, detail };
  };
  const list = [
    K('open_serious', 'Open critical / high problems', serious.length, '', 'max', `${open.length} open in all; ${serious.filter((x) => !x.owner).length} serious and unassigned`, (!!st.patrols && !notConn) || serious.length > 0),
    K('sla_pct', 'Resolved within SLA (critical 24 h, high 72 h)', slaN ? slaOk / slaN * 100 : null, '%', 'min', `${slaOk} of ${slaN} on time` + (slaOpenLate.length ? `; ${slaOpenLate.length} open and already late` : '')),
    K('diag_min', 'Time to diagnosis (automatic, median)', median(diag), 'min', 'max', `${diag.length} problems diagnosed`),
    K('human_h', 'First response by a person (serious, median)', median(hum), 'h', 'max', `${hum.length} serious problems; counts assignment, notes, snooze, close by a named person`),
    K('approval_h', 'Human approval time for proposed fixes (median)', median(appr), 'h', 'max', `${appr.length} decided in the window; ${waiting.length} waiting now` + (waiting.length ? `, oldest ${r1(Math.max(...waiting))} h` : '')),
    K('fix_h', 'Time to fix (median, detected → fixed)', median(fixed.map((x) => (x.resolved_at - (x.detected_at || x.first_seen)) / 3600000)), 'h', 'max', `${fixed.length} fixed (${vfix} verified by a re-check)`),
    K('fix_success_pct', 'Applied fixes that held on re-check', (vfix + stillThere) ? vfix / (vfix + stillThere) * 100 : null, '%', 'min', `${vfix} verified, ${stillThere} still present after the change`),
    K('reopen_pct', 'Problems that came back', resolved.length ? reopened / resolved.length * 100 : null, '%', 'max', `${reopened} came back of ${resolved.length} resolved`),
    K('patrol_pct', 'Patrols without errors', late ? 0 : patrolPct, '%', 'min', late ? 'patrol is LATE (no patrol in ' + (3 * P.patrol_min) + ' min)' : `${st.patrols || 0} patrols, ${st.errors || 0} with errors` + (notConn ? ' - source not connected' : ''), late || patrolPct != null),
  ];
  // the engineer's own measures: from the adapter when it defines them, else open problems by type
  let domain = inp.domain || null;
  if (!domain) { const by = {}; for (const x of open) by[x.kind || 'other'] = (by[x.kind || 'other'] || 0) + 1; domain = Object.entries(by).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, n]) => ({ label: 'Open: ' + k, value: n, unit: '', target: 0, dir: 'max', status: n ? 'bad' : 'ok' })); }
  // a source that is not connected is not scored
  const scored = notConn ? [] : list.filter((k) => k.status !== 'na'), score = scored.length ? Math.round(scored.reduce((a, k) => a + (k.status === 'ok' ? 100 : k.status === 'warn' ? 60 : 0), 0) / scored.length) : null;
  return { engineer: engId, name: inp.name, days, at: t, not_connected: notConn, score, measured: scored.length, kpis: list, domain,
    counts: { opened: opened.length, resolved: resolved.length, verified_fixed: vfix, open: open.length, awaiting_approval: waiting.length } };
}

/* ---- shift handover. inp: { engineer, name, now, since, items (the engineer's), st } */
function reportCore(inp) {
  const t = inp.now, since = inp.since || t - DAY, engId = inp.engineer, eng = { name: inp.name };
  const mine = inp.items || [], open = mine.filter((x) => !TERMINAL.has(x.status));
  const inWin = (x, k) => (x[k] || 0) >= since;
  const ev = (x, a) => (x.history || []).some((h) => h.action === a && h.at >= since);
  const st = inp.st || {};
  const top = (arr) => arr.sort((a, b) => sevOf(b.severity) - sevOf(a.severity)).slice(0, 15).map((x) => ({ id: x.id, severity: x.severity, title: x.title, status: x.status, target: x.target && x.target.name, owner: x.owner, changes: x.changes }));
  const r = {
    id: 'R-' + engId + '-' + riyadhDay(t) + '-' + t, engineer: engId, engineer_name: eng.name, at: t, since,
    day: riyadhDay(t),
    counts: {
      opened: mine.filter((x) => inWin(x, 'detected_at')).length, reopened: mine.filter((x) => ev(x, 'reopened')).length,
      cleared: mine.filter((x) => x.resolution === 'cleared' && inWin(x, 'resolved_at')).length,
      verified_fixed: mine.filter((x) => x.resolution === 'verified-fixed' && inWin(x, 'resolved_at')).length,
      closed: mine.filter((x) => x.status === 'closed' && inWin(x, 'resolved_at')).length,
      ai_investigations: mine.filter((x) => x.ai && (x.ai.at || 0) >= since).length,
      open: open.length, critical_open: open.filter((x) => x.severity === 'critical').length,
    },
    awaiting_approval: top(open.filter((x) => x.status === 'awaiting-approval')),
    approved_not_applied: top(open.filter((x) => x.status === 'approved')),
    needs_human: top(open.filter((x) => x.status === 'needs-human' || x.status === 'diagnosed')),
    still_unassigned: open.filter((x) => !x.owner && sevOf(x.severity) >= 3).length,
    patrols: { last: st.last_patrol || null, total: st.patrols || 0, last_error: st.last_error || null },
  };
  const c = r.counts, lines = [
    `${eng.name} - shift handover ${r.day}`,
    `New ${c.opened}, came back ${c.reopened}; resolved ${c.cleared + c.verified_fixed + c.closed} (${c.verified_fixed} verified after a change, ${c.cleared} cleared, ${c.closed} closed by a person).`,
    `Open now: ${c.open} (${c.critical_open} critical). Waiting for approval: ${r.awaiting_approval.length}. Approved, not yet applied: ${r.approved_not_applied.length}. Needs a person: ${r.needs_human.length}. Serious and unassigned: ${r.still_unassigned}.`,
    st.last_error ? `Last patrol problem: ${st.last_error}` : 'Patrols ran without errors.',
  ];
  r.summary = lines.join('\n');
  return r;
}

function createDuty({ store, log, now, engineers, ticketer, audit, policyDefaults, python } = {}) {
  const items = store.collection('duty_items'), meta = store.collection('duty_meta'), reports = store.collection('duty_reports');
  const T = typeof now === 'function' ? now : () => Date.now();
  const L = log || { info() {}, warn() {}, error() {} };
  const AUD = typeof audit === 'function' ? audit : () => {};
  const ENG = {}; (engineers || []).forEach((e) => { if (e && e.id) ENG[e.id] = e; });
  const running = {};
  const rules = python ? pyRules(python, 60000) : null;
  let lastEngine = rules ? 'python' : 'node';   // which engine answered the last call (shown by engine())
  async function viaRules(op, body, ok) {
    if (!rules) return null;
    const r = await rules(op, body);
    if (r && ok(r)) { lastEngine = 'python'; return r; }
    lastEngine = 'node (python unavailable or failed)'; return null;
  }

  function policy() { return Object.assign({}, DEFAULT_POLICY, policyDefaults || {}, (meta.get('policy') || {}).value || {}); }
  function setPolicy(input, by) {
    const cur = policy(), out = Object.assign({}, cur);
    const num = (k, lo, hi) => { if (input[k] !== undefined) { const v = Number(input[k]); if (!Number.isFinite(v) || v < lo || v > hi) throw err(400, `${k} must be ${lo}-${hi}`); out[k] = Math.round(v); } };
    if (input.enabled !== undefined) out.enabled = !!input.enabled;
    num('patrol_min', 2, 1440); num('max_investigations', 0, 50); num('ai_daily_cap', 0, 200); num('report_hour', 0, 23); num('reopen_window_days', 0, 90); num('verify_every_min', 5, 1440);
    if (input.ai_off !== undefined) {
      if (!Array.isArray(input.ai_off)) throw err(400, 'ai_off must be a list of engineer ids');
      const unknown = input.ai_off.filter((x) => !ENG[x]); if (unknown.length) throw err(400, 'unknown engineer: ' + unknown.join(', '));
      out.ai_off = [...new Set(input.ai_off.map(String))];
    }
    if (input.kpi_targets !== undefined) {
      const kt = input.kpi_targets; if (!kt || typeof kt !== 'object' || Array.isArray(kt)) throw err(400, 'kpi_targets must be { engineer: { kpi: number } }');
      const o = {};
      for (const [e, m] of Object.entries(kt)) {
        if (!ENG[e]) throw err(400, 'unknown engineer: ' + e);
        if (!m || typeof m !== 'object') throw err(400, 'kpi_targets.' + e + ' must be an object');
        o[e] = {};
        for (const [k, v] of Object.entries(m)) {
          if (!(k in KPI_DEFAULTS)) throw err(400, 'unknown KPI: ' + k);
          if (v === null || v === '') continue;   // back to the default
          const n = Number(v); if (!Number.isFinite(n) || n < 0 || n > 100000) throw err(400, `kpi_targets.${e}.${k} must be 0-100000`);
          o[e][k] = n;
        }
      }
      out.kpi_targets = o;
    }
    for (const k of ['ai_min_severity', 'ticket_min_severity']) if (input[k] !== undefined) { if (input[k] !== 'off' && !SEV[input[k]]) throw err(400, `${k} must be off, low, medium, high or critical`); out[k] = input[k]; }
    meta.put({ id: 'policy', value: out, by: by || '', at: T() });
    AUD('duty.policy', 'policy', { by, changed: Object.keys(input).filter((k) => JSON.stringify(cur[k]) !== JSON.stringify(out[k])) });
    return out;
  }
  // external AI for one engineer: switched off in the policy wins over whatever the engineer's own AI status says
  function aiAllowed(id) { return !(policy().ai_off || []).includes(id); }
  function aiStatusOf(e) { if (!e || !e.aiStatus) return null; if (!aiAllowed(e.id)) return { enabled: false, off: true, reason: AI_OFF_REASON }; return e.aiStatus(); }
  function err(code, msg) { return Object.assign(new Error(msg), { code, status: code, statusCode: code }); }
  function nextId() { const m = meta.get('counter') || { id: 'counter', n: 0 }; m.n = (m.n || 0) + 1; meta.put(m); return 'DW-' + String(m.n).padStart(6, '0'); }
  function hist(it, by, action, note) { it.history = (it.history || []).concat([{ at: T(), by: by || 'duty', action, note: clip(note, 1000) }]).slice(-100); }
  function save(it) { it.updated = T(); items.put(it); return it; }
  function must(id) { const it = items.get(id); if (!it) throw err(404, 'work item not found'); return it; }
  function sev(s) { return SEV[s] || 0; }
  function engState(id) { return (meta.get('eng:' + id) || { id: 'eng:' + id, patrols: 0, errors: 0 }); }
  function putEngState(s) { meta.put(s); }

  /* ---- one patrol of one engineer */
  async function patrol(engId, opts = {}) {
    const eng = ENG[engId]; if (!eng) throw err(404, 'unknown engineer');
    if (running[engId]) return { skipped: true, reason: 'a patrol is already running' };
    running[engId] = true;
    const P = policy(), st = engState(engId), t0 = T(), out = { engineer: engId, opened: 0, reopened: 0, updated: 0, cleared: 0, investigated: 0, ai: 0, verified: 0, tickets: 0, errors: [] };
    try {
      let fs;
      try { fs = await eng.findings(); } catch (e) { fs = undefined; out.errors.push('findings: ' + e.message); }
      if (fs === null) out.not_connected = true;
      // 1, 2, 6 and the snoozes that ran out: decided from the items as they are now, then written in one go
      const planIn = () => ({ engineer: engId, engineer_name: eng.name, findings: Array.isArray(fs) ? fs : null, items: items.all((x) => x.engineer === engId),
        policy: { reopen_window_days: P.reopen_window_days }, now: t0, counter: (meta.get('counter') || {}).n || 0 });
      const inp = planIn(), was = new Map(inp.items.map((x) => [x.id, x.updated]));   // before the call: the store hands out live records
      let plan = await viaRules('duty.plan', inp, (r) => Array.isArray(r.puts) && r.out);
      if (plan) {
        // the Python answer took time: if anything it was decided on changed meanwhile (a person assigned, closed, a
        // route opened an item), decide again here on the current items - never write over a newer record
        const cur = planIn();
        if (cur.counter !== inp.counter || cur.items.length !== inp.items.length || cur.items.some((x) => was.get(x.id) !== x.updated)) { plan = null; lastEngine = 'node (items changed during the Python call)'; }
      }
      if (!plan) plan = planPatrol(planIn());
      for (const it of plan.puts) items.put(it);
      if (plan.counter !== ((meta.get('counter') || {}).n || 0)) meta.put(Object.assign({ id: 'counter' }, meta.get('counter') || {}, { n: plan.counter }));
      Object.assign(out, plan.out);
      if (rules) out.engine = lastEngine;
      // 3: investigate (most severe first)
      const toInvestigate = items.all((x) => x.engineer === engId && x.status === 'open').sort((a, b) => sev(b.severity) - sev(a.severity) || a.first_seen - b.first_seen).slice(0, P.max_investigations);
      for (const it of toInvestigate) { try { await investigate(it.id, 'duty', { ai: false }); out.investigated++; } catch (e) { out.errors.push(it.id + ': ' + e.message); } }
      // 4a: rule-based proposals (no AI) - e.g. request a patch install that a different person must approve
      if (eng.propose) {
        for (const it of items.all((x) => x.engineer === engId && x.status === 'diagnosed' && !x.proposed_at)) { try { await propose(it.id, 'duty'); } catch (e) { out.errors.push(it.id + ' propose: ' + e.message); } }
      }
      // 4: AI root cause for serious diagnosed items, within the daily cap
      if (P.ai_min_severity !== 'off' && eng.aiInvestigate) {
        const cand = items.all((x) => x.engineer === engId && x.status === 'diagnosed' && !x.ai && sev(x.severity) >= sev(P.ai_min_severity)).sort((a, b) => sev(b.severity) - sev(a.severity));
        for (const it of cand) {
          if (aiUsedToday(engId) >= P.ai_daily_cap) break;
          const s = eng.aiStatus ? aiStatusOf(eng) : (aiAllowed(engId) ? { enabled: true } : { enabled: false }); if (!s || !s.enabled) break;
          try { await aiInvestigate(it.id, 'duty'); out.ai++; } catch (e) { out.errors.push(it.id + ' AI: ' + e.message); }
        }
      }
      // 5: follow change plans, verify applied fixes
      for (const it of items.all((x) => x.engineer === engId && !TERMINAL.has(x.status) && (x.changes || []).length)) {
        try { if (await followChanges(it)) out.verified++; } catch (e) { out.errors.push(it.id + ' change: ' + e.message); }
      }
      // 7: tickets
      if (ticketer && P.ticket_min_severity !== 'off') {
        for (const it of items.all((x) => x.engineer === engId && !TERMINAL.has(x.status) && x.status !== 'snoozed' && !x.ticket && !x.ticket_queued && sev(x.severity) >= sev(P.ticket_min_severity))) {
          try { const r = await ticket(it.id, 'duty'); if (r && (r.ticket || r.queued)) out.tickets++; } catch (e) { out.errors.push(it.id + ' ticket: ' + e.message); }
        }
      }
    } finally {
      running[engId] = false;
      st.patrols = (st.patrols || 0) + 1; st.last_patrol = t0; st.last_ms = T() - t0; st.last_result = out;
      if (out.errors.length) { st.errors = (st.errors || 0) + 1; st.last_error = out.errors[0]; st.last_error_at = t0; }
      putEngState(st);
    }
    if (out.opened || out.reopened || out.cleared) L.info('duty patrol', out);
    return out;
  }

  function aiUsedToday(engId) { const d = riyadhDay(T()); const c = meta.get('ai:' + engId + ':' + d); return (c && c.n) || 0; }
  function aiCount(engId) { const d = riyadhDay(T()), id = 'ai:' + engId + ':' + d, c = meta.get(id) || { id, n: 0 }; c.n++; meta.put(c); }

  async function investigate(id, by, opts = {}) {
    let it = must(id); const eng = ENG[it.engineer];
    if (TERMINAL.has(it.status)) throw err(409, 'this work item is ' + it.status);
    it.status = 'investigating'; hist(it, by, 'investigating', ''); save(it);
    let inv = null;
    try { inv = eng.investigate ? await eng.investigate(it) : null; } catch (e) { inv = { summary: 'The investigation could not run: ' + e.message, checks: [], causes: [] }; }
    it = must(id);
    it.investigation = inv ? {
      at: T(), summary: clip(inv.summary, 3000),
      checks: (inv.checks || []).slice(0, 20).map((c) => ({ name: clip(c.name, 120), status: clip(c.status, 12), detail: clip(c.detail, 600) })),
      causes: (inv.causes || []).slice(0, 6).map((c) => ({ cause: clip(c.cause, 400), confidence: clip(c.confidence, 10), fix: clip(c.fix, 1200) })),
    } : { at: T(), summary: 'No automated checks for this kind of problem. Recommendation: ' + (it.recommendation || '-'), checks: [], causes: [] };
    it.status = 'diagnosed'; hist(it, by, 'diagnosed', it.investigation.summary.slice(0, 300)); save(it);
    if (opts.ai && eng.aiInvestigate) { try { await aiInvestigate(id, by); } catch (e) { const x = must(id); hist(x, by, 'ai-failed', e.message); save(x); } }
    return must(id);
  }

  async function propose(id, by) {
    const it0 = must(id), eng = ENG[it0.engineer]; if (!eng.propose) throw err(400, 'this engineer cannot propose fixes');
    const got = [];
    const r = await eng.propose(it0, { onChange: (plan) => { if (plan && plan.id) got.push(plan.id); } });
    const it = must(id); it.proposed_at = T();
    for (const c of got) if (!(it.changes || []).includes(c)) it.changes = (it.changes || []).concat([c]);
    if (got.length) { it.status = 'awaiting-approval'; hist(it, by, 'fix-proposed', clip((r && r.note) || ('requested ' + got.join(', ') + ' for approval'), 400) + ' - nothing was executed'); }
    save(it); return it;
  }
  async function aiInvestigate(id, by) {
    const it0 = must(id), eng = ENG[it0.engineer];
    if (!eng.aiInvestigate) throw err(400, 'this engineer has no AI investigation');
    if (!aiAllowed(it0.engineer)) throw err(503, AI_OFF_REASON);
    const s = eng.aiStatus ? aiStatusOf(eng) : { enabled: true }; if (!s || !s.enabled) throw err(503, (s && s.reason) || 'AI is not configured');
    const proposed = [];
    aiCount(it0.engineer);
    let r;
    try { r = await eng.aiInvestigate(it0, { onChange: (plan) => { if (plan && plan.id) proposed.push(plan.id); } }); }
    catch (e) { const x = must(id); x.ai = { at: T(), error: clip(e.message, 500) }; hist(x, by, 'ai-failed', e.message); save(x); throw e; }
    const it = must(id);
    it.ai = { at: T(), answer: clip(r && r.answer, 8000), steps: ((r && r.steps) || []).length, model: clip(r && r.model, 60), proposed };
    for (const c of proposed) if (!(it.changes || []).includes(c)) it.changes = (it.changes || []).concat([c]);
    if (proposed.length) { it.status = 'awaiting-approval'; hist(it, by, 'fix-proposed', 'change plan ' + proposed.join(', ') + ' recorded for approval - nothing was executed'); }
    else if (it.status === 'diagnosed' || it.status === 'investigating') { it.status = 'needs-human'; hist(it, by, 'needs-human', 'AI analysis done; the fix needs a person (no change plan)'); }
    save(it);
    return it;
  }

  async function followChanges(it) {
    const eng = ENG[it.engineer]; if (!eng.changeStatus) return false;
    const st = (it.changes || []).map((c) => ({ id: c, s: eng.changeStatus(c) })).filter((x) => x.s);
    if (!st.length) return false;
    const has = (k) => st.some((x) => x.s.status === k);
    let next = it.status, verified = false;
    if (has('applied') || has('validated') || has('failed-validation')) next = 'fix-applied';
    else if (has('approved')) next = 'approved';
    else if (has('proposed')) next = 'awaiting-approval';
    else if (st.every((x) => x.s.status === 'rejected')) next = 'needs-human';
    if (next !== it.status && it.status !== 'snoozed') {
      const why = next === 'needs-human' ? 'the change plan was rejected' + (st[0].s.comment ? ': ' + st[0].s.comment : '') : next === 'approved' ? 'change approved - waiting for a person to apply it' : next === 'fix-applied' ? 'change applied - verifying' : '';
      it.status = next; hist(it, 'duty', next, why); save(it);
    }
    if (it.status === 'fix-applied' && eng.verify && T() - (it.verify_at || 0) >= policy().verify_every_min * 60000) {
      const r = await eng.verify(it); const x = must(it.id); x.verify_at = T(); verified = true;
      if (r && r.present === false) { x.status = 'resolved'; x.resolved_at = T(); x.resolution = 'verified-fixed'; hist(x, 'duty', 'verified-fixed', clip(r.note, 500) || 'a fresh re-check no longer shows the problem'); }
      else if (r && r.present === true) { x.verify_fail = (x.verify_fail || 0) + 1; if (x.verify_fail >= 2) { x.status = 'needs-human'; hist(x, 'duty', 'still-present', 'the problem is still there after the change: ' + clip(r.note, 400)); } }
      save(x);
    }
    return verified;
  }

  async function ticket(id, by) {
    if (!ticketer) throw err(503, 'ServiceDesk Plus is not connected');
    const it = must(id); if (it.ticket) return { ticket: it.ticket, created: false, existing: true };
    const r = await ticketer.create(it.id, by);
    const x = must(id);
    if (r && r.ticket) { x.ticket = { request_id: r.ticket.request_id, url: r.ticket.url }; hist(x, by, 'ticket', 'ServiceDesk Plus #' + r.ticket.request_id); }
    else if (r && r.queued) { x.ticket_queued = true; hist(x, by, 'ticket-queued', 'ServiceDesk Plus did not answer - queued for retry'); }
    save(x); AUD('duty.ticket', id, { by, request: r && r.ticket && r.ticket.request_id });
    return r;
  }

  /* ---- people */
  function assign(id, owner, by) { const it = must(id); it.owner = clip(owner, 120) || by || ''; hist(it, by, 'assigned', it.owner); AUD('duty.assign', id, { by, owner: it.owner }); return save(it); }
  function note(id, text, by) { const t = clip(text, 2000).trim(); if (!t) throw err(400, 'a note is required'); const it = must(id); hist(it, by, 'note', t); return save(it); }
  function snooze(id, hours, reason, by) {
    const h = Number(hours), r = clip(reason, 500).trim();
    if (!Number.isFinite(h) || h < 1 || h > 720) throw err(400, 'snooze for 1-720 hours'); if (!r) throw err(400, 'a reason is required');
    const it = must(id); if (TERMINAL.has(it.status)) throw err(409, 'this work item is ' + it.status);
    it.status = 'snoozed'; it.snooze_until = T() + h * 3600000; it.snooze_reason = r; hist(it, by, 'snoozed', `${h} h: ${r}`); AUD('duty.snooze', id, { by, hours: h }); return save(it);
  }
  function close(id, code, reason, by) {
    if (!CLOSE_CODES[code]) throw err(400, 'close code must be one of: ' + Object.keys(CLOSE_CODES).join(', '));
    const r = clip(reason, 1000).trim(); if (!r) throw err(400, 'a reason is required');
    const it = must(id); if (TERMINAL.has(it.status)) throw err(409, 'this work item is already ' + it.status);
    it.status = 'closed'; it.close_code = code; it.resolved_at = T(); it.resolution = 'closed:' + code; it.closed_by = by || '';
    if (code === 'accepted-risk' || code === 'false-positive') it.suppress_until = T() + 30 * DAY;
    hist(it, by, 'closed', code + ': ' + r); AUD('duty.close', id, { by, code }); return save(it);
  }

  /* ---- the human writes decided in Python too (duty_rules.py, step 9i): Node.js passes the record it holds; the answer is
     committed only if that record did not change while Python decided - otherwise, or without Python, Node.js decides */
  const wstats = { python: 0, node: 0, changed_meanwhile: 0 };
  async function viaWrite(op, body, held, node, commit) {
    const nodeDo = () => { wstats.node++; return node(); };
    if (!rules) return nodeDo();
    const before = JSON.stringify(held());
    const r = await rules(op, Object.assign({ now: T() }, body, { held: held() }));
    const same = JSON.stringify(held()) === before;
    if (r && !same) wstats.changed_meanwhile++;
    if (!r || r.node || (!r.refuse && !r.result) || !same) return nodeDo();
    wstats.python++;
    if (r.refuse) throw err(r.refuse.status, r.refuse.error);
    return commit(r);
  }
  const itemWrite = (op, id, args, by, node) => viaWrite(op, Object.assign({ id: String(id), by }, args), () => items.get(id) || null, node, (r) => {
    if (!r.result || r.result.id !== items.get(id).id) throw err(500, 'duty: a decision for another work item');
    items.put(r.result); if (r.audit) AUD(r.audit[0], r.audit[1], r.audit[2]); return r.result;
  });
  const assignAuto = (id, owner, by) => itemWrite('duty.assign', id, { owner }, by, () => assign(id, owner, by));
  const noteAuto = (id, text, by) => itemWrite('duty.note', id, { text }, by, () => note(id, text, by));
  const snoozeAuto = (id, hours, reason, by) => itemWrite('duty.snooze', id, { hours, reason }, by, () => snooze(id, hours, reason, by));
  const closeAuto = (id, code, reason, by) => itemWrite('duty.close', id, { code, reason }, by, () => close(id, code, reason, by));
  const setPolicyAuto = (input, by) => viaWrite('duty.policy', { input: input || {}, by, cur: policy(), engineers: Object.keys(ENG), kpi_keys: Object.keys(KPI_DEFAULTS) },
    () => meta.get('policy') || null, () => setPolicy(input, by), (r) => { meta.put(r.put); AUD(r.audit[0], r.audit[1], r.audit[2]); return r.result; });

  /* ---- views: the same inputs to listCore / engineersCore / kpisCore / reportCore above, or to their Python twins (…Auto) */
  const listIn = (f) => ({ filter: f || {}, items: items.all((x) => (!(f || {}).engineer || x.engineer === f.engineer)) });
  function list(f = {}) { return listCore(listIn(f)); }
  async function listAuto(f = {}) { const inp = listIn(f); return (await viaRules('duty.list', inp, (r) => Array.isArray(r.items))) || listCore(inp); }
  function get(id) { return must(id); }
  function engIn() {
    return { policy: policy(), now: T(), items: items.all(),
      engineers: Object.values(ENG).map((e) => ({ id: e.id, name: e.name, st: engState(e.id), ai: aiStatusOf(e), used_today: aiUsedToday(e.id) })) };
  }
  function engineersView() { return engineersCore(engIn()); }
  async function engineersAuto() { const inp = engIn(), r = await viaRules('duty.engineers', inp, (x) => Array.isArray(x.engineers)); return r ? r.engineers : engineersCore(inp); }
  function kpiTargets(engId) { return Object.assign({}, KPI_DEFAULTS, ((policy().kpi_targets || {})[engId]) || {}); }
  function kpiIn(engId, opts) {
    const eng = ENG[engId]; if (!eng) throw err(404, 'unknown engineer');
    const mine = items.all((x) => x.engineer === engId);
    let domain = null;
    if (eng.kpis) { try { domain = (eng.kpis(mine.filter((x) => !TERMINAL.has(x.status))) || []).map((d) => ({ label: clip(d.label, 120), value: d.value == null ? null : Number(d.value), unit: clip(d.unit, 8), target: d.target == null ? null : Number(d.target), dir: d.dir === 'min' ? 'min' : 'max',
      status: d.value == null ? 'na' : d.target == null ? 'info' : (d.dir === 'min' ? Number(d.value) >= d.target : Number(d.value) <= d.target) ? 'ok' : 'bad' })); } catch (e) { domain = null; } }
    return { engineer: engId, name: eng.name, now: T(), days: (opts || {}).days, policy: policy(), targets: kpiTargets(engId), st: engState(engId), items: mine, domain };
  }
  function kpis(engId, opts = {}) { return kpisCore(kpiIn(engId, opts)); }
  async function kpisAuto(engId, opts = {}) { const inp = kpiIn(engId, opts); return (await viaRules('duty.kpis', inp, (r) => Array.isArray(r.kpis))) || kpisCore(inp); }

  /* ---- shift handover */
  function reportIn(engId, sinceMs) {
    const eng = ENG[engId]; if (!eng) throw err(404, 'unknown engineer');
    return { engineer: engId, name: eng.name, now: T(), since: sinceMs || 0, items: items.all((x) => x.engineer === engId), st: engState(engId) };
  }
  function makeReport(engId, sinceMs) { return reportCore(reportIn(engId, sinceMs)); }
  async function makeReportAuto(engId, sinceMs) { const inp = reportIn(engId, sinceMs); return (await viaRules('duty.report', inp, (r) => r.counts && r.summary)) || reportCore(inp); }
  function keepReports(out) { for (const r of out) reports.put(r); const all = reports.all().sort((a, b) => b.at - a.at); for (const r of all.slice(400)) reports.remove(r.id); return out; }
  async function saveReportsAuto() { const out = []; for (const id of Object.keys(ENG)) out.push(await makeReportAuto(id)); return keepReports(out); }
  function saveReports() { return keepReports(Object.keys(ENG).map((id) => makeReport(id))); }
  function listReports(engId, limit) { return reports.all((r) => !engId || r.engineer === engId).sort((a, b) => b.at - a.at).slice(0, Math.min(Number(limit) || 30, 200)); }

  /* ---- the clock */
  let timer = null;
  async function tick() {
    const P = policy(); if (!P.enabled) return;
    const t = T();
    for (const id of Object.keys(ENG)) {
      const st = engState(id);
      if (!st.last_patrol || t - st.last_patrol >= P.patrol_min * 60000) { try { await patrol(id); } catch (e) { L.warn('duty patrol failed', { engineer: id, err: e.message }); } }
    }
    const day = riyadhDay(t), m = meta.get('report-day');
    if (riyadh(t).getUTCHours() >= P.report_hour && (!m || m.day !== day)) { meta.put({ id: 'report-day', day }); try { await saveReportsAuto(); } catch (e) { L.warn('duty report failed', { err: e.message }); } }
  }
  function start(everyMs) { if (timer) return; const run = () => { tick().catch((e) => L.warn('duty tick', { err: e.message })); }; const a = setTimeout(run, 90000); timer = setInterval(run, everyMs || 60000); if (a.unref) a.unref(); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }

  return { aiAllowed, AI_OFF_REASON, patrol, tick, start, stop, investigate, aiInvestigate, propose, ticket, assign, note, snooze, close, assignAuto, noteAuto, snoozeAuto, closeAuto, setPolicyAuto, writeStats: () => Object.assign({}, wstats), list, get, engineers: engineersView,
    makeReport, saveReports, listReports, policy, setPolicy, CLOSE_CODES, ENG, kpis, kpiTargets, KPI_DEFAULTS,
    listAuto, engineersAuto, kpisAuto, makeReportAuto, saveReportsAuto, engine: () => lastEngine,
    allItems: () => items.all() };   // read-only, for the team intelligence (duty-intel.js)
}

// for an adapter's kpis(open): open work items of these kinds ('sec-*' = prefix); distinct = count targets, not items
function kindCount(open, kinds, distinct) {
  const L = (open || []).filter((x) => kinds.some((k) => (k.endsWith('*') ? String(x.kind || '').startsWith(k.slice(0, -1)) : x.kind === k)));
  return distinct ? new Set(L.map((x) => (x.target && x.target.id) || x.key)).size : L.length;
}

module.exports = { createDuty, CLOSE_CODES, DEFAULT_POLICY, SEV, KPI_DEFAULTS, SLA_H, kindCount, planPatrol, listCore, engineersCore, kpisCore, reportCore, RULES_PY };
