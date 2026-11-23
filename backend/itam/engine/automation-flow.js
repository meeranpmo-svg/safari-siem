// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
/*
 * Automation flows ({P} = /api/itam, Audit -> Audit Automation Flow, PDPL -> PDPL Automation Flow): how the audit and the PDPL work
 * runs on the platform, stage by stage, READ-ONLY. Every number is computed at request time from the records the modules keep (their
 * store collections, or the module through app.addons) - nothing is entered or stored here, and nothing is changed.
 *
 *   audit  sources -> use-case tests (audit-auto) -> continuous control monitoring (audit-ccm) and analytics (audit-analytics) ->
 *          proposed findings -> accepted into engagements (audit-engage: IT / Cyber / Internal Audit Teams) -> owners and action
 *          plans -> re-test (manual, and the automatic re-tests audit-auto keeps in audit_auto_retests when installed) -> closed;
 *          beside the flow: evidence requests (audit-checklist), department attestations (dept-checklist), escalations.
 *   pdpl   data discovery (pdpl.js / pdpl-catalog) -> records of processing (pdpl_records ropa, pdpl-ropa campaigns) -> DPIA /
 *          transfers / processors (pdpl.js, pdpl-workflows, pdpl-vendor) -> consent (pdpl-consent) -> data subject requests (30-day
 *          clock) and breaches (72-hour clock) -> control monitor (pdpl-monitor) -> Privacy Office tasks (pdpl-office) -> verified
 *          closed (a task closes only when the registers no longer show it); beside the flow: escalated Privacy Office tasks.
 *
 * Per stage: how many records it holds, what is waiting there, the items STUCK (waiting at least stuck_days, or past a legal
 * clock) oldest first with their age, owner and the page where each is worked, the median cycle time from the records' own
 * timestamps, and the bottleneck (the stage whose stuck items add up to the most days). A module that is not installed reads
 * "not installed"; a module with no records reads what to connect - never zeros that look like data. The page names people:
 * operators and administrators only (PDPL); a viewer is refused. Each view is recorded in the audit trail (who read it).
 *
 *   GET  /audit-flow?stuck_days=1..365   operator  the audit flow                                          audited (view)
 *   GET  /pdpl-flow?stuck_days=1..365    operator  the PDPL flow                                           audited (view)
 */
const DAY = 86400000, HOUR = 3600000, MAX_ITEMS = 25, DEF_STUCK = 7;
const s = (x, n = 200) => String(x == null ? '' : x).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
const low = (x) => String(x == null ? '' : x).trim().toLowerCase();
const TEAMS = { it: ['auditEngage', 'IT Audit Team', 'audit-team.html', 'IT'], cyber: ['cyberAuditEngage', 'Cyber Security Audit Team', 'cyber-audit-team.html', 'Cyber'], internal: ['internalAuditEngage', 'Internal Audit Team', 'internal-audit-team.html', 'Internal'] };
// a date ('YYYY-MM-DD') or a date-time -> ms, or null
function ms(v) { if (v == null || v === '') return null; if (typeof v === 'number') return Number.isFinite(v) ? v : null; const t = String(v); const x = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(t) ? t + 'T00:00:00Z' : t); return Number.isFinite(x) ? x : null; }
const median = (a) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const r1 = (x) => Math.round(x * 10) / 10;

function createAutomationFlow(app, opts = {}) {
  const now = opts.now || Date.now, L = app.log || {};
  const A = () => app.addons || {};
  const warn = (key, msg, err) => { if (L.every) L.every('autoflow:' + key, 3600000, 'warn', msg, { err: s(err && err.message, 160) }); };
  // a collection read that fails is said on the stage ("could not be read"), never shown as an empty stage
  function all(name, f) { try { return app.store.collection(name).all(f || (() => true)); } catch (e) { warn('col:' + name, 'automation flow: a collection could not be read', e); return null; } }
  const age = (t) => (t == null ? null : r1(Math.max(0, now() - t) / DAY));
  const day = (t) => (t == null ? null : new Date(t).toISOString().slice(0, 10));
  // the median of (end - start) over the pairs that have both, in days
  function cycle(pairs, of) {
    const d = pairs.filter(([a, b]) => a != null && b != null && b >= a).map(([a, b]) => (b - a) / DAY);
    return d.length ? { median_days: r1(median(d)), n: d.length, of } : { median_days: null, n: 0, of, why: 'no item has gone through this stage yet' };
  }
  const item = (o) => ({ id: s(o.id, 80), title: s(o.title, 200), age_days: o.age_days == null ? null : o.age_days, owner: o.owner ? s(o.owner, 120) : null, waiting_for: s(o.waiting_for, 200), href: o.href, overdue: !!o.overdue, force: !!o.force });

  /* one stage from what a builder found. waiting = items in the stage now; stuck = waiting >= stuck_days, or past a clock (force) */
  function stage(T, d) {
    const base = { id: d.id, title: d.title, href: d.href, flow: d.flow !== false, lane: !!d.lane };
    if (!d.installed) return Object.assign(base, { status: 'missing', installed: false, count: null, unit: d.unit, lines: ['not installed'], waiting: 0, stuck: 0, items: [], cycle: null, gap: d.missing || 'not installed - run the update' });
    if (d.unreadable) return Object.assign(base, { status: 'off', installed: true, count: null, unit: d.unit, lines: ['could not be read'], waiting: 0, stuck: 0, items: [], cycle: null, gap: 'its records could not be read - see the server log' });
    const items = (d.items || []).map(item), stuck = items.filter((x) => x.force || x.overdue || (x.age_days != null && x.age_days >= T))
      .sort((a, b) => (b.age_days == null ? -1 : b.age_days) - (a.age_days == null ? -1 : a.age_days));
    const status = !d.has_data ? 'off' : stuck.length ? 'part' : 'ok';
    return Object.assign(base, { status, installed: true, count: d.has_data ? d.count : 0, unit: d.unit, lines: (d.has_data ? d.lines : [d.gap || 'nothing yet']).filter(Boolean).map((x) => s(x, 240)),
      waiting: items.length, stuck: stuck.length, stuck_days_total: r1(stuck.reduce((n, x) => n + (x.age_days || 0), 0)), items: stuck.slice(0, MAX_ITEMS).map((x) => { const y = Object.assign({}, x); delete y.force; return y; }),
      more: Math.max(0, stuck.length - MAX_ITEMS), cycle: d.cycle || null, gap: d.has_data ? (d.gap_note || null) : (d.gap || null), gaps: d.gaps || undefined });
  }
  function bottleneck(stages) {
    const c = stages.filter((x) => x.flow && x.stuck).sort((a, b) => b.stuck_days_total - a.stuck_days_total || b.stuck - a.stuck)[0];
    if (!c) return { stage: null, why: 'nothing is stuck in the flow' };
    const oldest = c.items[0] && c.items[0].age_days;
    return { stage: c.id, title: c.title, stuck: c.stuck, days_total: c.stuck_days_total, oldest_days: oldest == null ? null : oldest,
      why: c.stuck + ' item(s) stuck, ' + c.stuck_days_total + ' day(s) in total' + (oldest != null ? ', the oldest ' + oldest + ' day(s)' : '') + ' - more waiting time than any other stage' };
  }
  function finish(kind, T, stages, lanes, who) {
    const flow = stages.filter((x) => x.flow), all2 = stages.concat(lanes);
    const out = { kind, generated_at: new Date(now()).toISOString(), stuck_days: T, stages, lanes, bottleneck: bottleneck(stages),
      kpis: { stages: flow.length, working: flow.filter((x) => x.status === 'ok').length, partly: flow.filter((x) => x.status === 'part').length, not_installed: all2.filter((x) => x.status === 'missing').length,
        stuck: all2.reduce((n, x) => n + x.stuck, 0), oldest_days: all2.reduce((m, x) => Math.max(m, (x.items[0] && x.items[0].age_days) || 0), 0) },
      note: 'Read-only: every number is computed now from the records each module keeps; nothing is entered here. A stage whose module is not installed says so, and a stage with no records says what to connect - never zeros that look like data. Stuck = waiting ' + T + ' day(s) or more, or past a legal clock.' };
    if (app.audit && who) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'automation-flow.view', target: kind, detail: { stuck_days: T, stuck: out.kpis.stuck, bottleneck: out.bottleneck.stage } });
    return out;
  }
  const query = (q) => body(q || {}).int('stuck_days', { min: 1, max: 365, def: DEF_STUCK }).done();

  /* ================================ AUDIT ================================ */
  function useCases() { try { return require('./audit-auto').USE_CASES || []; } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') warn('uc', 'automation flow: the audit use cases could not be loaded', e); return []; } }
  function teamFindings() {
    const teams = [], findings = [], engagements = [];
    for (const [k, t] of Object.entries(TEAMS)) {
      const T = A()[t[0]]; if (!T) continue;
      teams.push({ key: k, name: t[1], page: t[2], short: t[3] });
      try { for (const f of T.listFindings({})) findings.push(Object.assign({}, f, { team: k, team_name: t[1], page: t[2] })); } catch (e) { warn('find:' + k, 'automation flow: audit findings could not be read', e); }
      try { for (const e of T.listEngagements({})) engagements.push(Object.assign({}, e, { team: k })); } catch (e) { warn('eng:' + k, 'automation flow: engagements could not be read', e); }
    }
    return { teams, findings, engagements };
  }
  async function auditFlow(q, who) {
    const { stuck_days: T } = query(q), UC = useCases(), UCI = Object.fromEntries(UC.map((u) => [u.id, u]));
    const AX = A().auditAuto, runs = AX ? all('audit_auto_runs') : null, R = (runs || []).slice().sort((a, b) => String(a.id).localeCompare(String(b.id))), last = R[R.length - 1] || null;
    const res = (last && last.results) || {}, teamOf = (u) => (TEAMS[u.team] || [])[1] || 'an audit team';
    const stages = [];
    // 1. sources: the populations the use cases read
    {
      const pops = {}; for (const u of UC) { const p = pops[u.pop] = pops[u.pop] || { connect: u.connect, ucs: [], n: 0 }; p.ucs.push(u.id); p.n += (res[u.id] && res[u.id].n) || 0; }
      const P = Object.values(pops), withRec = P.filter((p) => p.n > 0), nt = UC.filter((u) => !(res[u.id] && res[u.id].n));
      const gaps = {}; for (const p of P.filter((x) => !x.n)) (gaps[p.connect] = gaps[p.connect] || []).push(...p.ucs);
      stages.push(stage(T, { id: 'sources', title: 'Sources', href: 'audit-command.html', flow: false, installed: !!AX, unreadable: AX && runs === null, has_data: !!last, unit: 'sources with records',
        count: withRec.length, lines: [withRec.length + '/' + P.length + ' sources with records', nt.length + ' use case(s) not testable', withRec.reduce((n, p) => n + p.n, 0) + ' record(s) in the period'],
        gap: 'no use-case run yet - run the use cases on the Audit Command Center (or wait for the daily run)', gaps: last ? Object.entries(gaps).map(([c, ids]) => 'connect ' + c + ' (' + ids.join(', ') + ')') : undefined,
        gap_note: Object.keys(gaps).length ? Object.keys(gaps).length + ' source(s) not connected: their use cases are not testable' : null }));
    }
    // 2. use-case tests: runs and exceptions; a use case with exceptions waits since the first run of its current failing streak
    {
      const tested = UC.filter((u) => res[u.id] && res[u.id].n), withEx = tested.filter((u) => res[u.id].ex > 0), items = [], pairs = [];
      for (const u of withEx) { let st = null; for (let i = R.length - 1; i >= 0; i--) { const x = R[i].results && R[i].results[u.id]; if (x && x.ex > 0) st = ms(R[i].at || R[i].id); else break; }
        items.push({ id: u.id, title: u.id + ' ' + u.title, age_days: age(st), owner: teamOf(u), waiting_for: res[u.id].ex + ' of ' + res[u.id].n + ' record(s) failed - a finding, or the cause corrected', href: 'audit-command.html' }); }
      for (const u of UC) { let st = null; for (const r of R) { const x = r.results && r.results[u.id]; if (!x) continue; if (x.ex > 0 && st == null) st = ms(r.at || r.id); else if (x.status === 'effective' && st != null) { pairs.push([st, ms(r.at || r.id)]); st = null; } } }
      stages.push(stage(T, { id: 'tests', title: 'Use-case tests', href: 'audit-command.html', installed: !!AX, unreadable: AX && runs === null, has_data: R.length > 0, unit: 'use cases tested', count: tested.length,
        lines: [R.length + ' run(s) · last ' + day(ms(last && last.at)), tested.length + '/' + UC.length + ' use cases tested', withEx.length + ' with exceptions · ' + withEx.reduce((n, u) => n + res[u.id].ex, 0) + ' exception(s)'],
        gap: 'no use-case run yet - run the use cases on the Audit Command Center', items, cycle: cycle(pairs, 'from the first failing run to the first clean run') }));
    }
    // 3a. continuous control monitoring over the audit trail
    {
      const CC = A().auditCcm, cr = CC ? all('ccm_runs') : null, disp = CC ? all('ccm_dispositions') : null, dr = CC ? all('ccm_drafts') : null;
      const CR = (cr || []).slice().sort((a, b) => String(a.at).localeCompare(String(b.at))), lc = CR[CR.length - 1] || null, D = new Map((disp || []).map((d) => [d.id, d]));
      const first = new Map(); for (const r of CR) for (const t of r.tests || []) for (const e of t.exceptions || []) if (!first.has(e.id)) first.set(e.id, ms(r.at));
      const items = []; if (lc) for (const t of lc.tests || []) for (const e of t.exceptions || []) if (!D.has(e.id)) items.push({ id: e.id, title: t.id + ' ' + t.name + (e.at ? ' · ' + String(e.at).slice(0, 10) : ''), age_days: age(first.get(e.id)), owner: 'an auditor', waiting_for: 'a disposition: explained, or marked for a finding', href: 'audit-ccm.html' });
      const sm = (lc && lc.summary) || {};
      stages.push(stage(T, { id: 'ccm', title: 'Control monitoring', href: 'audit-ccm.html', installed: !!CC, unreadable: CC && (cr === null || disp === null), has_data: !!lc, unit: 'audit-trail records tested', count: lc ? lc.records || 0 : 0,
        lines: [(sm.effective || 0) + ' effective · ' + (sm.exceptions || 0) + ' with exceptions', items.length + ' open exception(s)', (dr || []).filter((d) => d.state === 'draft').length + ' draft finding(s)'],
        gap: 'no control-monitoring run yet - run it on Continuous Control Monitoring (daily on its own)', items, cycle: cycle([...D.values()].map((d) => [first.get(d.id), ms(d.at)]), 'from the first run that held an exception to its disposition') }));
    }
    // 3b. audit analytics: runs with exceptions wait for a review by a different person
    {
      const AN = A().auditAnalytics, ar = AN ? all('aa_runs') : null, AR = ar || [];
      const items = AR.filter((r) => r.result && r.result.exceptions_total && !r.review).map((r) => ({ id: r.id, title: (r.dataset_name || r.dataset || '') + ' · ' + r.test + ' · ' + r.result.exceptions_total + ' exception(s)', age_days: age(ms(r.at)), owner: r.by, waiting_for: 'review by a different person', href: 'audit-analytics.html' }));
      const open = AR.reduce((n, r) => n + Math.max(0, ((r.result && r.result.exceptions_total) || 0) - Object.keys(r.dispositions || {}).length), 0);
      stages.push(stage(T, { id: 'analytics', title: 'Audit analytics', href: 'audit-analytics.html', installed: !!AN, unreadable: AN && ar === null, has_data: AR.length > 0, unit: 'analytics runs', count: AR.length,
        lines: [AR.length + ' run(s)', open + ' open exception(s)', items.length + ' awaiting review · ' + AR.filter((r) => r.finding).length + ' raised as finding(s)'],
        gap: 'no analytics run yet - import a dataset or use a platform dataset on Audit Analytics', items, cycle: cycle(AR.filter((r) => r.review).map((r) => [ms(r.at), ms(r.review.at)]), 'from the run to its review') }));
    }
    // 4. proposed findings: use-case proposals and control-monitoring drafts waiting for an auditor
    {
      const CC = A().auditCcm, pr = AX ? all('audit_auto_proposals') : [], dr = CC ? all('ccm_drafts') : [], P = pr || [], Dd = dr || [];
      const items = P.filter((p) => p.state === 'proposed').map((p) => ({ id: p.id, title: p.title, age_days: age(ms(p.at)), owner: p.team_name, waiting_for: 'an auditor accepts it into an engagement or dismisses it', href: 'audit-command.html' }))
        .concat(Dd.filter((d) => d.state === 'draft').map((d) => ({ id: d.id, title: d.title || d.test, age_days: age(ms(d.at)), owner: d.drafted_for, waiting_for: 'an auditor accepts it into an engagement or discards it', href: 'audit-ccm.html' })));
      stages.push(stage(T, { id: 'proposed', title: 'Proposed findings', href: 'audit-command.html', installed: !!(AX || CC), unreadable: pr === null || dr === null, has_data: P.length + Dd.length > 0, unit: 'waiting for an auditor', count: items.length,
        lines: [P.filter((p) => p.state === 'proposed').length + ' use-case proposal(s)', Dd.filter((d) => d.state === 'draft').length + ' monitoring draft(s)', (P.filter((p) => p.state === 'accepted').length + Dd.filter((d) => d.state === 'accepted').length) + ' accepted · ' + (P.filter((p) => p.state === 'dismissed').length + Dd.filter((d) => d.state === 'discarded').length) + ' dismissed'],
        gap: 'nothing proposed yet - a use case or control with exceptions is proposed as a finding on the next run', items,
        cycle: cycle(P.map((p) => [ms(p.at), ms(p.decided_at)]).concat(Dd.map((d) => [ms(d.at), ms(d.accepted_at || d.discarded_at)])), 'from proposed to accepted or dismissed') }));
    }
    // 5-9. the findings in the audit teams
    const TF = teamFindings(), F = TF.findings.filter((f) => f.state !== 'withdrawn'), byState = (st) => F.filter((f) => f.state === st), teamsOn = TF.teams.length > 0;
    const missingTeams = Object.values(TEAMS).filter((t) => !A()[t[0]]).map((t) => t[1]);
    {
      const items = byState('draft').map((f) => ({ id: f.id, title: f.title, age_days: age(ms(f.raised_at)), owner: f.raised_by, waiting_for: 'issue to the owner (' + f.team_name + ')', href: f.page }));
      const fw = TF.engagements.filter((e) => e.state === 'fieldwork').length;
      stages.push(stage(T, { id: 'engaged', title: 'Accepted into engagements', href: TF.teams[0] ? TF.teams[0].page : 'audit-team.html', installed: teamsOn, missing: 'the audit teams are not installed - run the update', has_data: F.length + TF.engagements.length > 0, unit: 'findings raised', count: F.length,
        lines: [fw + ' engagement(s) in fieldwork', TF.teams.map((t) => t.short + ' ' + F.filter((f) => f.team === t.key).length).join(' · '), items.length + ' draft(s) not yet issued', missingTeams.length ? missingTeams.join(', ') + ': not installed' : ''],
        gap: 'no engagement or finding yet - an audit team opens an engagement and raises findings in fieldwork', items, cycle: cycle(F.map((f) => [ms(f.raised_at), ms(f.issued_at)]), 'from raised to issued') }));
    }
    {
      const items = byState('issued').map((f) => ({ id: f.id, title: f.title, age_days: age(ms(f.issued_at)), owner: f.owner, waiting_for: 'management response and action plan', href: f.page, overdue: f.overdue }))
        .concat(byState('responded').map((f) => ({ id: f.id, title: f.title, age_days: age(ms(f.responded_at || f.retested_at)), owner: f.owner, waiting_for: 'implementation' + (f.due ? ' (due ' + f.due + ')' : ''), href: f.page, overdue: f.overdue })));
      stages.push(stage(T, { id: 'owners', title: 'Owners & action plans', href: TF.teams[0] ? TF.teams[0].page : 'audit-team.html', installed: teamsOn, missing: 'the audit teams are not installed - run the update', has_data: F.length > 0, unit: 'with their owners', count: items.length,
        lines: [byState('issued').length + ' awaiting a response', byState('responded').length + ' with an action plan', F.filter((f) => f.overdue).length + ' overdue'],
        gap: 'no finding issued yet', items, cycle: cycle(F.map((f) => [ms(f.issued_at), ms(f.implemented_at)]), 'from issued to implemented') }));
    }
    {
      const rt = AX ? all('audit_auto_retests') : null, RT = (rt || []).map((r) => ({ finding: r.finding || r.finding_id, result: low(r.result || r.outcome || r.state), at: ms(r.at || r.tested_at) })).filter((r) => r.finding);
      const latestRt = new Map(); for (const r of RT.sort((a, b) => (a.at || 0) - (b.at || 0))) latestRt.set(r.finding, r);
      const clean = RT.filter((r) => /^(clean|pass|passed|effective)$/.test(r.result)).length, failed = RT.filter((r) => /^(exceptions|fail|failed|reopen|reopened)$/.test(r.result)).length;
      const items = byState('implemented').map((f) => { const r = latestRt.get(f.id);
        return { id: f.id, title: f.title, age_days: age(ms(f.implemented_at)), owner: f.team_name, href: f.page,
          waiting_for: r ? (/^(clean|pass|passed|effective)$/.test(r.result) ? 'automatic re-test clean - an auditor confirms the closure' : /^(waiting|pending|no_records)$/.test(r.result) ? 'automatic re-test waiting for records after the implementation date' : 're-test by an auditor (last automatic re-test: ' + r.result + ')') : 're-test by an auditor - re-test not yet recorded' }; });
      const manual = F.filter((f) => f.retested_at);
      stages.push(stage(T, { id: 'retest', title: 'Re-test', href: 'audit-command.html', installed: teamsOn, missing: 'the audit teams are not installed - run the update', has_data: F.length > 0, unit: 'implemented, waiting', count: items.length,
        lines: [items.length + ' implemented, waiting', RT.length ? 'automatic: ' + clean + ' clean · ' + failed + ' failed' : 're-test not yet recorded', manual.length + ' re-tested by an auditor'],
        gap: 'no finding implemented yet', items, cycle: cycle(F.map((f) => [ms(f.implemented_at), ms(f.retested_at)]), 'from implemented to re-tested') }));
    }
    {
      const done = F.filter((f) => f.state === 'closed' || f.state === 'risk_accepted'), recent = done.filter((f) => (ms(f.retested_at || f.accepted_at) || 0) >= now() - 90 * DAY).length;
      stages.push(stage(T, { id: 'closed', title: 'Closed', href: TF.teams[0] ? TF.teams[0].page : 'audit-team.html', flow: false, installed: teamsOn, missing: 'the audit teams are not installed - run the update', has_data: done.length > 0, unit: 'findings closed', count: done.length,
        lines: [byState('closed').length + ' closed after a re-test', byState('risk_accepted').length + ' risk accepted', recent + ' in the last 90 days'],
        gap: 'nothing closed yet', cycle: cycle(done.map((f) => [ms(f.raised_at), ms(f.state === 'closed' ? f.retested_at : f.accepted_at)]), 'raised to closed, end to end') }));
    }
    // beside the flow
    const lanes = [];
    {
      const CL = A().auditChecklist, seen = new Map(); let bad = false;
      if (CL) for (const fw of ['sama', 'nca', 'ia']) { try { for (const r of CL.requests(fw, true).items) if (!seen.has(r.id)) seen.set(r.id, r); } catch (e) { bad = true; warn('pbc:' + fw, 'automation flow: evidence requests could not be read', e); } }
      const X = [...seen.values()], pbc = CL ? all('audit_pbc') : [];
      const items = X.filter((r) => r.state === 'issued').map((r) => ({ id: r.ref, title: r.title, age_days: age(ms(r.issued_at)), owner: r.owner_name, waiting_for: 'the evidence (due ' + r.due + ')', href: 'ai-auditors.html', overdue: r.overdue }))
        .concat(X.filter((r) => r.state === 'provided').map((r) => ({ id: r.ref, title: r.title, age_days: age(ms(r.response && r.response.at)), owner: r.owner_name, waiting_for: 'acceptance by a different person', href: 'ai-auditors.html' })));
      lanes.push(stage(T, { id: 'evidence', title: 'Evidence requests', href: 'ai-auditors.html', lane: true, installed: !!CL, unreadable: bad && !X.length, has_data: (pbc || []).length > 0, unit: 'open requests', count: X.filter((r) => r.state !== 'accepted').length,
        lines: [X.filter((r) => r.state === 'not_issued').length + ' not issued · ' + X.filter((r) => r.state === 'issued').length + ' issued', X.filter((r) => r.overdue).length + ' overdue', X.filter((r) => r.state === 'provided').length + ' provided, to accept'],
        gap: 'no evidence request issued yet' + (X.length ? ' - ' + X.length + ' check(s) need evidence: an auditor issues the requests on AI Auditors' : ''), items, cycle: cycle((pbc || []).filter((q) => q.state === 'accepted' && q.decision).map((q) => [ms(q.issued_at), ms(q.decision.at)]), 'from issued to accepted') }));
    }
    {
      const DC = A().deptChecklist; let at = null; try { at = DC ? DC.attention() : null; } catch (e) { warn('dept', 'automation flow: the department checklist could not be read', e); }
      const att = DC ? all('dept_attest') : [], X = (at && at.items) || [];
      const items = X.map((d) => ({ id: d.id + (d.period ? ' ' + d.period : ''), title: d.title, age_days: d.days_overdue == null ? null : d.days_overdue, owner: d.dept, waiting_for: d.result === 'overdue' ? 'the department attests the period' : 'the auditor\'s exception resolved', href: 'dept-checklist.html', overdue: d.result === 'overdue' }));
      lanes.push(stage(T, { id: 'attest', title: 'Department attestations', href: 'dept-checklist.html', lane: true, installed: !!DC, unreadable: DC && !at, has_data: (att || []).length > 0 || X.length > 0, unit: 'attestations recorded', count: (att || []).length,
        lines: [(att || []).length + ' attestation(s) recorded', X.filter((d) => d.result === 'overdue').length + ' overdue', X.filter((d) => d.result === 'exception').length + ' exception(s)'],
        gap: 'no attestation yet - an administrator names each department\'s head on the Department Checklist', items, cycle: cycle((att || []).filter((r) => r.review).map((r) => [ms(r.at), ms(r.review.at)]), 'from attested to reviewed') }));
    }
    {
      const fu = AX ? all('audit_auto_followups') : null, U = fu || [], open = U.filter((x) => x.open);
      const items = open.filter((x) => x.escalated).map((x) => ({ id: x.ref || x.id, title: x.title, age_days: x.days == null ? age(ms(x.first_at)) : x.days, owner: x.owner, waiting_for: x.kind + ' overdue - escalated to Notification & Escalation', href: x.page || 'notify-center.html', force: true }));
      lanes.push(stage(T, { id: 'escalations', title: 'Escalations', href: 'notify-center.html', lane: true, installed: !!AX, unreadable: AX && fu === null, has_data: U.length > 0, unit: 'overdue items followed up', count: open.length,
        lines: [open.length + ' overdue, followed up', items.length + ' escalated', U.filter((x) => !x.open).length + ' cleared'],
        gap: 'nothing overdue has been followed up', items, cycle: cycle(U.filter((x) => !x.open).map((x) => [ms(x.first_at), ms(x.cleared_at)]), 'from followed up to cleared') }));
    }
    return finish('audit', T, stages, lanes, who);
  }

  /* ================================ PDPL ================================ */
  async function consentStats(PD) {
    let t = null;
    try { return await Promise.race([PD.consent().stats(), new Promise((_, no) => { t = setTimeout(() => no(new Error('the consent ledger did not answer in time')), opts.consentTimeoutMs || 8000); })]); }
    catch (e) { warn('consent', 'automation flow: consent ledger counts not readable', e); return null; }
    finally { clearTimeout(t); }
  }
  async function pdplFlow(q, who) {
    const { stuck_days: T } = query(q), PD = A().pdpl, recs = PD ? all('pdpl_records') : null, RC = recs || [], live = (k) => RC.filter((r) => r.kind === k && r.status !== 'archived');
    const dpo = (RC.find((r) => r.id === 'profile') || {}).dpo_user || null, DPO = dpo || 'the DPO (not named)', noPd = 'PDPL is not installed - run the update', bad = PD && recs === null;
    const stages = [];
    {
      const sc = PD ? all('pdpl_discovery', (x) => x.id !== '_last') : null, S = sc || [], ids = PD && PD.catalog ? all('pdpl_identifiers') : null;
      const items = S.filter((x) => !x.ok).map((x) => ({ id: x.db, title: (x.engine || '') + ' ' + (x.label || x.db), age_days: age(ms(x.at)), owner: null, waiting_for: 'a read-only login that works (' + s(String(x.error || '').split(':')[0], 60) + ')', href: 'pdpl-catalog.html' }));
      stages.push(stage(T, { id: 'discovery', title: 'Data discovery', href: 'pdpl-catalog.html', installed: !!PD, missing: noPd, unreadable: PD && sc === null, has_data: S.length > 0, unit: 'databases scanned', count: S.length,
        lines: [S.filter((x) => x.ok).length + '/' + S.length + ' scans read', S.reduce((n, x) => n + ((x.columns && x.columns.length) || 0), 0) + ' personal-data column(s)', ids ? ids.length + ' identifier column(s) confirmed' : 'data catalog not installed'],
        gap: 'no database scanned yet - register Oracle databases on the Databases page, or let Asset Discovery prove a read-only login', items, cycle: { median_days: null, n: 0, of: 'discovery is a scan, not a hand-off', why: 'no hand-off to time' } }));
    }
    {
      const ro = live('ropa'), camps = PD && PD.ropaCampaigns ? all('pdpl_ropa_campaigns') : [], C = camps || [], items = [], pairs = [], today = day(now());
      let deps = 0, appr = 0, sub = 0;
      for (const c of C) for (const [dn, d] of Object.entries(c.departments || {})) {
        deps++; if (d.status === 'approved') { appr++; pairs.push([ms(d.submitted_at), ms(d.reviewed_at)]); continue; }
        if (c.status !== 'open') continue;
        if (d.status === 'submitted') { sub++; items.push({ id: c.id + ' ' + dn, title: dn + ' · ' + c.name, age_days: age(ms(d.submitted_at)), owner: DPO, waiting_for: 'review by the DPO', href: 'pdpl-ropa-collect.html' }); }
        else items.push({ id: c.id + ' ' + dn, title: dn + ' · ' + c.name, age_days: age(ms(c.created_at)), owner: d.steward || 'no data steward named', waiting_for: (d.status === 'returned' ? 'changes after the DPO returned it' : 'the department\'s records') + ' (due ' + c.due + ')', href: 'pdpl-ropa-collect.html', overdue: !!(c.due && c.due < today) });
      }
      stages.push(stage(T, { id: 'ropa', title: 'Records of processing', href: 'pdpl-ropa.html', installed: !!PD, missing: noPd, unreadable: bad || camps === null, has_data: ro.length + C.length > 0, unit: 'processing activities', count: ro.length,
        lines: [ro.length + ' processing activit(ies)', PD && PD.ropaCampaigns ? appr + '/' + deps + ' departments approved' : 'RoPA campaigns not installed', sub + ' waiting for the DPO'],
        gap: 'no processing activity recorded - open a RoPA campaign by department, or adopt a discovered database', items, cycle: cycle(pairs, 'from submitted to approved by the DPO') }));
    }
    {
      const dp = live('dpia'), tr = live('transfer'), pr = live('processor'), va = PD && PD.vendor ? all('pdpl_vendor_assessments') : [], V = va || [];
      const items = dp.filter((d) => !d.completed).map((d) => ({ id: d.id, title: 'DPIA ' + d.id + (d.ropa_id ? ' · ' + d.ropa_id : ''), age_days: age(ms(d.created_at)), owner: DPO, waiting_for: d.wizard ? 'the DPO\'s signature (not the preparer)' : 'completion', href: 'pdpl-dpia.html' }))
        .concat(tr.filter((t) => !t.risk_assessed).map((t) => ({ id: t.id, title: (t.name || t.id) + (t.country ? ' · ' + t.country : ''), age_days: age(ms(t.created_at)), owner: t.tia ? DPO : t.created_by, waiting_for: t.tia ? 'the DPO\'s signature on the transfer assessment' : 'a transfer impact assessment', href: 'pdpl-transfers.html' })))
        .concat(pr.filter((p) => !p.agreement).map((p) => ({ id: p.id, title: p.name || p.id, age_days: age(ms(p.created_at)), owner: p.created_by, waiting_for: 'a data processing agreement', href: 'pdpl-processors.html' })))
        .concat(V.filter((a) => !['approved', 'cancelled'].includes(a.status)).map((a) => ({ id: a.id, title: 'Vendor review · ' + (a.vendor || a.processor_id), age_days: age(ms(a.created_at)), owner: a.created_by, waiting_for: 'vendor review (' + a.status + ')' + (a.return_by ? ', answers due ' + a.return_by : ''), href: 'pdpl-processors.html', overdue: !!(a.return_by && ['draft', 'sent'].includes(a.status) && a.return_by < day(now())) })));
      stages.push(stage(T, { id: 'assess', title: 'DPIA, transfers & processors', href: 'pdpl-dpia.html', installed: !!PD, missing: noPd, unreadable: bad || va === null, has_data: dp.length + tr.length + pr.length + V.length > 0, unit: 'assessments, transfers, processors', count: dp.length + tr.length + pr.length,
        lines: [dp.filter((d) => d.completed).length + '/' + dp.length + ' DPIA signed', tr.filter((t) => t.risk_assessed).length + '/' + tr.length + ' transfers assessed', pr.filter((p) => p.agreement).length + '/' + pr.length + ' processors with an agreement', PD && PD.vendor ? V.filter((a) => !['approved', 'cancelled'].includes(a.status)).length + ' vendor review(s) open' : ''],
        gap: 'no impact assessment, transfer or processor recorded - add them on the DPIA, Transfers and Processors pages', items,
        cycle: cycle(dp.map((d) => [ms(d.created_at), ms(d.completed)]).concat(tr.map((t) => [ms(t.created_at), ms(t.tia && t.tia.signed_at)]), V.map((a) => [ms(a.created_at), ms(a.approved_at)])), 'from recorded to signed / approved') }));
    }
    {
      const pu = live('consent_purpose'), ks = PD ? all('pdpl_consent_keys', (k) => !k.revoked_at) : null, st = PD && pu.length ? await consentStats(PD) : null;
      const sum = (k) => pu.reduce((n, p) => n + ((st && st[p.id] && st[p.id][k]) || 0), 0);
      const items = st ? pu.filter((p) => !(st[p.id] && st[p.id].events)).map((p) => ({ id: p.id, title: p.title || p.id, age_days: age(ms(p.created_at)), owner: null, waiting_for: 'no system has sent a consent for this purpose yet', href: 'ai-pdpl.html#consent' })) : [];
      stages.push(stage(T, { id: 'consent', title: 'Consent', href: 'ai-pdpl.html#consent', installed: !!PD, missing: noPd, unreadable: bad || ks === null, has_data: pu.length > 0, unit: 'consent purposes', count: pu.length,
        lines: [(ks || []).length + ' sending system(s)', st ? sum('active') + ' active · ' + sum('withdrawn') + ' withdrawn' : 'ledger counts not readable', st ? sum('events_30d') + ' event(s) in 30 days' : ''],
        gap: 'no consent purpose yet - an administrator adds the purposes (Registers -> Consent purposes) and issues a key to each system that collects consent',
        gap_note: pu.length && !(ks || []).length ? 'no sending system has a consent key yet' : null, items, cycle: { median_days: null, n: 0, of: 'consent is recorded, not handed on', why: 'no hand-off to time' } }));
    }
    {
      const ds = live('dsr'), br = live('breach'), done = (r) => !!r.responded || ['responded', 'refused', 'withdrawn'].includes(r.stage);
      const od = ds.filter((r) => !done(r)), ob = br.filter((b) => !b.sdaia_notified_at), items = [];
      for (const r of od) { const rec = ms(r.received), due = rec == null ? null : rec + (r.extended ? 60 : 30) * DAY, late = due != null && now() > due;
        items.push({ id: r.id, title: r.id + ' · ' + (r.type || 'request') + ' request', age_days: age(rec), owner: r.assigned_to || r.created_by, href: 'pdpl-dsar.html', overdue: late, force: due != null && due - now() <= 5 * DAY,
          waiting_for: (r.identity_verified ? 'the answer' : 'identity verification, then the answer') + (due != null ? (late ? ' - the ' + (r.extended ? 60 : 30) + '-day clock ended ' + day(due) : ' (' + Math.ceil((due - now()) / DAY) + ' day(s) left of ' + (r.extended ? 60 : 30) + ')') : '') }); }
      for (const b of ob) { const aw = ms(b.aware_at), h = aw == null ? null : (now() - aw) / HOUR;
        items.push({ id: b.id, title: b.id + ' · personal data breach', age_days: age(aw), owner: DPO, href: 'pdpl-breach.html', overdue: h != null && h > 72, force: true,
          waiting_for: h == null ? 'SDAIA notification (awareness time not recorded)' : h > 72 ? 'SDAIA notification - the 72 hours passed ' + Math.floor(h - 72) + ' h ago' : 'SDAIA notification (' + Math.floor(72 - h) + ' h left of 72)' }); }
      const bn = br.filter((b) => b.sdaia_notified_at && b.aware_at).map((b) => (ms(b.sdaia_notified_at) - ms(b.aware_at)) / HOUR).filter((x) => x >= 0);
      stages.push(stage(T, { id: 'requests', title: 'Requests & breaches', href: 'pdpl-dsar.html', installed: !!PD, missing: noPd, unreadable: bad, has_data: ds.length + br.length > 0, unit: 'open requests and breaches', count: od.length + ob.length,
        lines: [od.length + ' open request(s) · ' + items.filter((x) => x.href === 'pdpl-dsar.html' && x.overdue).length + ' past 30 days', ob.length + ' breach(es) open · ' + items.filter((x) => x.href === 'pdpl-breach.html' && x.overdue).length + ' past 72 h', bn.length ? 'breaches notified in a median ' + Math.round(median(bn)) + ' h' : ''],
        gap: 'no data subject request or breach recorded - staff record requests on Data Subject Requests; a SIEM incident becomes a breach record', items, cycle: cycle(ds.map((r) => [ms(r.received), ms(r.responded)]), 'from received to answered') }));
    }
    {
      const PM = A().pdplMonitor, mr = PM ? all('pdpl_mon_runs') : null, M = (mr || []).slice().sort((a, b) => String(a.at).localeCompare(String(b.at))), lm = M[M.length - 1] || null, items = [], pairs = [];
      if (lm) for (const [k, v] of Object.entries(lm.states || {})) { if (v !== 'fail') continue; let st = null; for (let i = M.length - 1; i >= 0; i--) { if ((M[i].states || {})[k] === 'fail') st = ms(M[i].at); else break; }
        items.push({ id: k, title: k, age_days: age(st), owner: null, waiting_for: 'the control fixed - the test fails', href: 'pdpl-monitor.html' }); }
      const keys = new Set(); for (const r of M) for (const k of Object.keys(r.states || {})) keys.add(k);
      for (const k of keys) { let st = null; for (const r of M) { const v = (r.states || {})[k]; if (v === 'fail' && st == null) st = ms(r.at); else if (v === 'pass' && st != null) { pairs.push([st, ms(r.at)]); st = null; } } }
      stages.push(stage(T, { id: 'monitor', title: 'Control monitor', href: 'pdpl-monitor.html', installed: !!PM, unreadable: PM && mr === null, has_data: !!lm, unit: 'control tests', count: lm ? Object.keys(lm.states || {}).length : 0,
        lines: lm ? ['score ' + (lm.score == null ? '-' : lm.score + ' %'), (lm.pass || 0) + ' pass · ' + (lm.fail || 0) + ' fail · ' + (lm.not_measured || 0) + ' not measured', ((lm.drift || []).length) + ' drifted since the run before'] : [],
        gap: 'no monitor run yet - run the PDPL Control Monitor (daily on its own)', items, cycle: cycle(pairs, 'from the first failing run to the first passing run') }));
    }
    const PO = A().privacyOffice, tk = PO ? all('pdpl_office_tasks') : null, TK = tk || [], open = TK.filter((t) => t.status !== 'closed'), closed = TK.filter((t) => t.status === 'closed');
    {
      const items = open.map((t) => ({ id: t.id || t.key, title: t.title, age_days: age(ms(t.first_seen)), owner: t.assignee || 'unassigned', href: 'pdpl-office.html', overdue: !!t.overdue,
        waiting_for: t.status === 'claimed' ? 'the registers to confirm it is done' : t.status === 'risk_accepted' ? 'risk accepted until ' + t.risk_until : 'work by the assignee' + (t.due ? ' (due ' + String(t.due).slice(0, 10) + ')' : '') }));
      stages.push(stage(T, { id: 'office', title: 'Privacy Office tasks', href: 'pdpl-office.html', installed: !!PO, unreadable: PO && tk === null, has_data: TK.length > 0, unit: 'open tasks', count: open.length,
        lines: [open.length + ' open · ' + open.filter((t) => t.overdue).length + ' overdue', open.filter((t) => t.escalation).length + ' escalated', open.filter((t) => t.status === 'claimed').length + ' claimed, waiting for the registers'],
        gap: 'no Privacy Office task yet - the office routes every PDPL finding on its next run (every 30 minutes)', items, cycle: cycle(closed.map((t) => [ms(t.first_seen), ms(t.closed_at)]), 'from raised to closed by the registers') }));
    }
    {
      const ds = live('dsr'), br = live('breach'), answered = ds.filter((r) => r.responded).length, notified = br.filter((b) => b.sdaia_notified_at).length, recent = closed.filter((t) => (ms(t.closed_at) || 0) >= now() - 90 * DAY).length;
      stages.push(stage(T, { id: 'closed', title: 'Verified closed', href: 'pdpl-office.html', flow: false, installed: !!(PO || PD), missing: noPd, has_data: closed.length + answered + notified > 0, unit: 'tasks verified closed', count: closed.length,
        lines: [closed.length + ' task(s) closed by the registers', recent + ' in the last 90 days', answered + ' request(s) answered · ' + notified + ' breach(es) notified'],
        gap: 'nothing verified closed yet - a task closes only when the registers no longer show it', cycle: cycle(closed.map((t) => [ms(t.first_seen), ms(t.closed_at)]), 'raised to verified closed, end to end') }));
    }
    const lanes = [];
    {
      const items = open.filter((t) => t.escalation).map((t) => ({ id: t.id || t.key, title: t.title, age_days: age(ms(t.due)), owner: t.escalated_to || DPO, waiting_for: t.escalation >= 2 ? 'escalated to the privacy committee chair' : 'overdue - escalated to the DPO', href: 'pdpl-office.html', force: true }));
      lanes.push(stage(T, { id: 'escalations', title: 'Escalations', href: 'pdpl-office.html', lane: true, installed: !!PO, unreadable: PO && tk === null, has_data: TK.length > 0, unit: 'escalated tasks', count: items.length,
        lines: [items.length + ' escalated', items.filter((x) => /chair/.test(x.waiting_for)).length + ' to the committee chair'], gap: 'no Privacy Office task yet', items, cycle: null }));
    }
    return finish('pdpl', T, stages, lanes, who);
  }

  return { auditFlow, pdplFlow, audit: auditFlow, pdpl: pdplFlow, TEAMS };
}

function registerAutomationFlow(srv, app, X) {
  const F = X && typeof X.auditFlow === 'function' ? X : createAutomationFlow(app, X || {});
  (app.addons = app.addons || {}).automationFlow = app.addons.automationFlow || F;
  // the flows name findings' owners, assignees and requesters (PDPL): operators and administrators, never viewers
  srv.route('GET', '/audit-flow', (ctx) => { ctx.need('operator'); return F.auditFlow(ctx.query, ctx.who); });
  srv.route('GET', '/pdpl-flow', (ctx) => { ctx.need('operator'); return F.pdplFlow(ctx.query, ctx.who); });
  return F;
}

module.exports = { createAutomationFlow, registerAutomationFlow };
