// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * Issues Management ({P} = /api/itam, Risk & Governance -> Issues Management) - one register of every issue the platform's audit
 * and assurance work has raised, for an insurer that answers to SAMA, the Insurance Authority, the NCA and SDAIA. Nothing is
 * entered or copied here: each issue stays where it was raised, with its own owner, workflow, four eyes and audit trail, and the
 * row links back to it. This module reads and adds only what no single source can: the cross-source view.
 *   sources     IT / Cyber Security / Internal Audit Team findings (ia_ / csa_ / iad_findings; drafts are not issues yet),
 *               IT Audit Inspection corrective actions (insp_actions), GRC remediation actions (grc_actions), and regulator /
 *               external / earlier-year findings in the Audit Repository (ar_findings).
 *   normalised  significance critical / high / medium / low (each source's own scale mapped, the mapping shown on the page),
 *               status open / in_progress / awaiting_verification / resolved / risk_accepted, owner, due, raised, age, days
 *               overdue, the body that raised it (internal audit, an AI auditor team, inspection, GRC, SAMA, IA, NCA, external).
 *   cross-source what Archer-style issue management is for: possible DUPLICATES (open issues from different sources whose titles
 *               share >= 50 % of their words - a person confirms, nothing merges by itself), REPEATS (a regulator finding the
 *               Audit Repository marked as a repeat, or an inspection item that failed twice running at a site), an ESCALATION
 *               list (critical / high overdue more than 30 days, regulator issues overdue, repeats still open), owner load.
 *   links       an operator links an issue to a GRC risk (RSK-) or marks it a duplicate of another issue; both validated,
 *               reversible and audited. The source record is never changed.
 *   learning    one snapshot a day of open issues by significance and of overdue ones; least-squares slope per week (3+ days);
 *               median days to resolve per source (from issues that carry a resolution date); the backlog in 30 days at the
 *               last 30 days' inflow and outflow.
 * People and weaknesses are internal: viewers see counts; operators see issues.
 *   GET  /issues                       viewer    kpis, by source / significance / body, aging, learning (+ issues, duplicates, escalation: operator)
 *   POST /issues/:key/link             operator  {risk?, duplicate_of?, note?}  ({} or nulls remove the link)          audited
 *   GET  /issues/export                operator  CSV                                                                     audited
 */
const DAY = 86400000, RIYADH = 3 * 3600000;
const SIG = ['critical', 'high', 'medium', 'low'], SR = { critical: 4, high: 3, medium: 2, low: 1 };
const SOURCES = { ia: 'IT Audit Team', csa: 'Cyber Security Audit Team', iad: 'Internal Audit Team', inspect: 'IT Audit Inspection', grc: 'GRC remediation', repo: 'Audit Repository (regulator / external / earlier years)' };
const PAGE = { ia: 'audit-team.html', csa: 'cyber-audit-team.html', iad: 'internal-audit-team.html', inspect: 'audit-inspections.html', grc: 'grc-register.html', repo: 'audit-repo.html' };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const low = (v) => String(v == null ? '' : v).toLowerCase();
const STOP = new Set(['the', 'a', 'an', 'of', 'to', 'and', 'or', 'in', 'on', 'for', 'is', 'are', 'not', 'no', 'with', 'by', 'be', 'at', 'from', 'all', 'synthetic', 'correct']);
const words = (t) => new Set(low(t).split(/[^a-z0-9؀-ۿ]+/).filter((w) => w.length > 2 && !STOP.has(w)));
const jaccard = (a, b) => { if (!a.size || !b.size) return 0; let n = 0; for (const x of a) if (b.has(x)) n++; return n / (a.size + b.size - n); };
function lsq(pts) { const n = pts.length; if (n < 3) return null; const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n, sxx = pts.reduce((a, p) => a + (p[0] - mx) ** 2, 0); return sxx ? pts.reduce((a, p) => a + (p[0] - mx) * (p[1] - my), 0) / sxx : 0; }
const median = (a) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };

function createIssuesHub(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const C = (n) => store.collection(n), links = () => C('iss_links'), hist = () => C('iss_hist');
  const iso = () => new Date(now()).toISOString(), day = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'issues.' + action, target, detail }); };
  const ms = (v) => { const t = Date.parse(v); return isNaN(t) ? null : t; };

  /* ---- read every source; a source that is missing or fails is reported, never treated as "no issues" */
  function gather() {
    const out = [], status = {};
    const read = (key, fn) => { try { const n0 = out.length; fn(); status[key] = { ok: true, issues: out.length - n0 }; } catch (e) { status[key] = { ok: false, error: s(e.message, 160) }; L.every('iss:' + key, 3600000, 'warn', 'Issues Management: a source could not be read', { source: key, err: s(e.message, 160) }); } };
    for (const k of ['ia', 'csa', 'iad']) read(k, () => {
      for (const f of C(k + '_findings').all((x) => x.state !== 'draft' && x.state !== 'withdrawn')) {
        const st = f.state === 'closed' ? 'resolved' : f.state === 'risk_accepted' ? 'risk_accepted' : f.state === 'implemented' || f.state === 'retest' ? 'awaiting_verification' : f.state === 'responded' ? 'in_progress' : 'open';
        const closedAt = (f.history || []).filter((h) => /closed|accepted/i.test(String(h.what || ''))).map((h) => h.at).pop() || null;
        out.push({ key: k + ':' + f.id, source: k, ref: f.id, title: s(f.title, 200), significance: SR[f.rating] ? f.rating : 'medium', native: 'rating ' + f.rating, status: st, owner: f.owner || '', due: f.due || null, raised: f.raised_at || null, resolved_at: st === 'resolved' || st === 'risk_accepted' ? closedAt : null, body: SOURCES[k], area: f.area || '', engagement: f.engagement || '' });
      }
    });
    read('inspect', () => {
      const t = day(now());
      for (const a of C('insp_actions').all()) {
        const r = (a.likelihood || 3) * (a.impact || 3), sig = a.severity === 'critical' ? 'critical' : r >= 15 ? 'high' : r >= 8 ? 'medium' : 'low';
        const st = a.state === 'verified' ? 'resolved' : a.state === 'accepted' && a.exception && a.exception.until >= t ? 'risk_accepted' : a.state === 'fixed' ? 'awaiting_verification' : a.state === 'exception_requested' ? 'in_progress' : 'open';
        out.push({ key: 'inspect:' + a.id, source: 'inspect', ref: a.inspection, title: s(a.item_text || a.text, 200), significance: sig, native: a.severity + ', risk ' + r, status: st, owner: a.assignee || '', due: a.due || null, raised: a.created_at || null, resolved_at: a.verify ? a.verify.at : a.exception && a.exception.decided_at || null, body: SOURCES.inspect, area: a.site || '' });
      }
    });
    read('grc', () => {
      for (const a of C('grc_actions').all()) {
        const st = a.status === 'closed' ? 'resolved' : a.status === 'done' ? 'awaiting_verification' : a.status === 'in_progress' ? 'in_progress' : a.status === 'cancelled' ? null : 'open';
        if (!st) continue;
        out.push({ key: 'grc:' + a.id, source: 'grc', ref: a.id, title: s(a.title, 200), significance: SR[a.priority] ? a.priority : 'medium', native: 'priority ' + (a.priority || 'medium'), status: st, owner: a.owner || '', due: a.due || null, raised: a.created_at || null, resolved_at: a.closed_at || null, body: SOURCES.grc + (a.source && a.source !== 'manual' ? ' (' + a.source + ')' : ''), area: a.framework || '', framework: a.framework || '' });
      }
    });
    read('repo', () => {
      for (const f of C('ar_findings').all()) {
        const st = /closed|resolved/.test(low(f.status)) ? 'resolved' : /accept/.test(low(f.status)) ? 'risk_accepted' : /progress/.test(low(f.status)) ? 'in_progress' : 'open';
        const sig = SR[low(f.rating)] ? low(f.rating) : SR[low(f.severity)] ? low(f.severity) : 'high';
        out.push({ key: 'repo:' + f.id, source: 'repo', ref: f.id, title: s(f.title || f.condition, 200), significance: sig, native: (f.rating || f.severity || 'regulator finding (high unless rated)'), status: st, owner: f.owner || '', due: f.due || null, raised: f.created_at || null, resolved_at: f.closed_at || null, body: s(f.body || 'Audit Repository', 60) + (f.year ? ' ' + f.year : ''), area: f.area || '', regulator: /sama|insurance authority|\bia\b|nca|sdaia|external/i.test(String(f.body || '')), repeat: (f.repeat || []).length > 0 });
      }
    });
    return { issues: out, status };
  }

  function enrich(G) {
    const t = day(now()), lk = new Map(links().all().map((x) => [x.id, x]));
    // repeats from inspections: the same item failed in the last two submitted inspections of the same template at the same site
    const insRepeat = new Set();
    try { const IN = C('insp_inspections').all((x) => x.state !== 'in_progress' && x.submitted_at).sort((a, b) => String(a.submitted_at).localeCompare(String(b.submitted_at))), last = new Map();
      for (const x of IN) { const k = x.site + '|' + x.template_id; const prev = last.get(k); if (prev) for (const iid of x.failed || []) if ((prev.failed || []).includes(iid)) insRepeat.add(x.id + '|' + iid); last.set(k, x); }
      for (const a of C('insp_actions').all()) if (insRepeat.has(a.inspection + '|' + a.item)) { const i = G.issues.find((y) => y.key === 'inspect:' + a.id); if (i) i.repeat = true; }
    } catch (e) { L.every('iss:insrep', 3600000, 'warn', 'Issues Management: inspection repeats could not be read', { err: s(e.message, 160) }); }
    for (const i of G.issues) {
      const r = ms(i.raised), open = ['open', 'in_progress', 'awaiting_verification'].includes(i.status);
      i.open = open; i.age_days = r ? Math.max(0, Math.floor((now() - r) / DAY)) : null;
      i.overdue_days = open && i.due && i.due < t ? Math.floor((Date.parse(t) - Date.parse(i.due)) / DAY) : 0;
      i.link = lk.get(i.key) || null; i.page = PAGE[i.source];
    }
    return G;
  }

  function analyse() {
    const G = enrich(gather()), I = G.issues, open = I.filter((i) => i.open && !(i.link && i.link.duplicate_of));
    // possible duplicates across sources: open, different sources, title overlap >= 0.5 (a person confirms)
    const W = new Map(open.map((i) => [i.key, words(i.title)])), dups = [];
    for (let a = 0; a < open.length; a++) for (let b = a + 1; b < open.length; b++) {
      const x = open[a], y = open[b]; if (x.source === y.source) continue;
      const j = jaccard(W.get(x.key), W.get(y.key)); if (j >= 0.5) dups.push({ a: x.key, b: y.key, a_title: x.title, b_title: y.title, a_source: SOURCES[x.source], b_source: SOURCES[y.source], similarity: Math.round(j * 100) });
      if (dups.length >= 100) break;
    }
    const escalate = open.filter((i) => (SR[i.significance] >= 3 && i.overdue_days > 30) || (i.regulator && i.overdue_days > 0) || i.repeat).map((i) => Object.assign({}, i, { why: [SR[i.significance] >= 3 && i.overdue_days > 30 ? i.significance + ' and ' + i.overdue_days + ' days overdue' : null, i.regulator && i.overdue_days > 0 ? 'a regulator / external finding past its date' : null, i.repeat ? 'a repeat finding still open' : null].filter(Boolean) }))
      .sort((a, b) => SR[b.significance] - SR[a.significance] || b.overdue_days - a.overdue_days);
    return { G, I, open, dups, escalate };
  }
  function snapshot(open) {
    const d = day(now()), c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const i of open) c[i.significance]++;
    hist().put({ id: d, day: d, at: now(), open: open.length, overdue: open.filter((i) => i.overdue_days > 0).length, critical: c.critical, high: c.high, medium: c.medium, low: c.low });
    for (const o of hist().all((x) => x.day < day(now() - 400 * DAY))) hist().remove(o.id);
  }
  function view(who) {
    const A = analyse(), { I, open } = A; snapshot(open);
    const H = hist().all().sort((a, b) => a.day.localeCompare(b.day)).slice(-30);
    const per = {}; for (const k of ['open', 'overdue', 'critical', 'high']) { const sl = lsq(H.map((h, i) => [i, h[k]])); per[k] = sl == null ? null : Math.round(sl * 7 * 10) / 10; }
    const since = now() - 30 * DAY, inflow = I.filter((i) => (ms(i.raised) || 0) >= since).length, outflow = I.filter((i) => !i.open && (ms(i.resolved_at) || 0) >= since).length;
    const mttr = {}; for (const k of Object.keys(SOURCES)) { const d = I.filter((i) => i.source === k && !i.open && ms(i.resolved_at) && ms(i.raised)).map((i) => (ms(i.resolved_at) - ms(i.raised)) / DAY); mttr[k] = d.length ? { days: Math.round(median(d) * 10) / 10, n: d.length } : null; }
    const count = (f) => { const m = {}; for (const i of open) { const k = f(i); m[k] = (m[k] || 0) + 1; } return Object.entries(m).map(([key, n]) => ({ key, n })).sort((a, b) => b.n - a.n); };
    const aging = [['0-30', 0, 30], ['31-90', 31, 90], ['91-180', 91, 180], ['180+', 181, 1e9]].map(([k, a, b]) => ({ key: k, n: open.filter((i) => i.age_days != null && i.age_days >= a && i.age_days <= b).length }));
    const owners = count((i) => i.owner || '(no owner)').slice(0, 15).map((o) => Object.assign(o, { overdue: open.filter((i) => (i.owner || '(no owner)') === o.key && i.overdue_days > 0).length }));
    const res = { generated_at: iso(), sources: A.G.status, source_names: SOURCES,
      kpis: { open: open.length, overdue: open.filter((i) => i.overdue_days > 0).length, critical_high: open.filter((i) => SR[i.significance] >= 3).length, regulator_open: open.filter((i) => i.regulator).length, repeats_open: open.filter((i) => i.repeat).length,
        awaiting_verification: open.filter((i) => i.status === 'awaiting_verification').length, no_owner: open.filter((i) => !i.owner).length, possible_duplicates: A.dups.length, escalations: A.escalate.length, resolved_30d: outflow, raised_30d: inflow },
      by_source: count((i) => SOURCES[i.source]), by_significance: SIG.map((k) => ({ key: k, n: open.filter((i) => i.significance === k).length })), by_body: count((i) => i.body).slice(0, 12), aging,
      learning: { days: H.length, per_week: per, note: H.length < 3 ? 'trend withheld - ' + H.length + ' day(s) recorded, 3 needed' : null, mttr_days: mttr, backlog_30d: Math.max(0, open.length + inflow - outflow), inflow_30d: inflow, outflow_30d: outflow },
      mapping: { ia: 'audit rating high / medium / low as given', csa: 'audit rating as given', iad: 'audit rating as given', inspect: 'critical item = critical; otherwise risk likelihood x impact: >=15 high, >=8 medium, else low', grc: 'action priority as given', repo: 'the finding\'s own rating; a regulator finding without one counts as high' },
      can_work: ['operator', 'admin'].includes(who.role) };
    if (res.can_work) {
      res.issues = I.slice().sort((a, b) => (b.open - a.open) || SR[b.significance] - SR[a.significance] || b.overdue_days - a.overdue_days).slice(0, 1000);
      res.duplicates = A.dups; res.escalate = A.escalate.slice(0, 100); res.owners = owners;
    }
    return res;
  }

  function link(key, input, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot link issues: a person does');
    const b = body(input).str('risk', { max: 40 }).str('duplicate_of', { max: 80 }).str('note', { max: 400 }).done();
    const A = analyse(), me = A.I.find((i) => i.key === key); if (!me) throw httpErr(404, 'no issue ' + key);
    if (b.risk && !/^RSK-?\d{1,6}$/.test(b.risk)) throw httpErr(400, 'risk must be a GRC risk id (RSK-…)');
    if (b.risk && !C('grc_risks').get(b.risk)) throw httpErr(400, 'risk: no GRC risk ' + b.risk);
    if (b.duplicate_of) { if (b.duplicate_of === key) throw httpErr(400, 'duplicate_of: an issue is not a duplicate of itself'); const d = A.I.find((i) => i.key === b.duplicate_of); if (!d) throw httpErr(400, 'duplicate_of: no issue ' + b.duplicate_of); const dl = links().get(b.duplicate_of); if (dl && dl.duplicate_of === key) throw httpErr(400, 'duplicate_of: ' + b.duplicate_of + ' is already a duplicate of this issue'); }
    const prev = links().get(key) || null;
    if (!b.risk && !b.duplicate_of) { if (prev) links().remove(key); audit(who, 'link.remove', key, { prev: prev ? { risk: prev.risk, duplicate_of: prev.duplicate_of } : null }); return { link: null }; }
    const rec = { id: key, risk: b.risk || null, duplicate_of: b.duplicate_of || null, note: b.note || '', by: who.user, at: iso() };
    links().put(rec); audit(who, 'link', key, { risk: rec.risk, duplicate_of: rec.duplicate_of, note: rec.note });
    return { link: rec };
  }
  function exportCsv(who) {
    const I = analyse().I, cell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
    const head = ['key', 'source', 'body', 'reference', 'title', 'significance', 'native_rating', 'status', 'owner', 'due', 'days_overdue', 'raised', 'age_days', 'repeat', 'regulator', 'linked_risk', 'duplicate_of'];
    const csv = [head.join(',')].concat(I.map((i) => [i.key, SOURCES[i.source], i.body, i.ref, i.title, i.significance, i.native, i.status, i.owner, i.due, i.overdue_days, i.raised, i.age_days, i.repeat ? 'yes' : '', i.regulator ? 'yes' : '', i.link && i.link.risk, i.link && i.link.duplicate_of].map(cell).join(','))).join('\n');
    audit(who, 'export', 'issues', { rows: I.length });
    return { filename: 'issues-' + day(now()) + '.csv', csv };
  }
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'issues.snapshot', () => { if (!hist().get(day(now()))) { const A = analyse(); snapshot(A.open); } }), 6 * 3600000); if (tm.unref) tm.unref(); }
  return { view, link, exportCsv, analyse };
}

function registerIssuesHub(srv, app, X0) {
  const X = X0 && X0.view ? X0 : createIssuesHub(app, X0 || {});
  app.addons = app.addons || {}; app.addons.issuesHub = X;
  srv.route('GET', '/issues', (ctx) => { ctx.need('viewer'); return X.view(ctx.who); });
  srv.route('GET', '/issues/export', (ctx) => { ctx.need('operator'); return X.exportCsv(ctx.who); });
  srv.route('POST', '/issues/:key/link', (ctx) => { ctx.need('operator'); const k = param(ctx.params.key, 'key'); if (!/^(ia|csa|iad|inspect|grc|repo):[A-Za-z0-9_-]{1,40}$/.test(k)) throw httpErr(400, 'key is not an issue key (source:id)'); return X.link(k, ctx.body, ctx.who); });
  return X;
}
module.exports = { createIssuesHub, registerIssuesHub, SOURCES };
