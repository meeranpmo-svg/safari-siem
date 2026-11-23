// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * AI GRC Consultant: the compliance engineer of the AI team. On the duty desk (duty-core.js) it patrols the organisation's
 * compliance position and opens one work item per gap, each with the consultant's recommendation and the framework
 * clauses it touches; it re-checks and resolves an item only when the gap is gone. It also answers questions ("ask the
 * consultant") from the platform's own GRC records, citing them.
 *   patrols:  failing / partial automated GRC controls · policies past their review date · Insurance Authority requirements
 *             not covered or partly covered · DR / BCM drills overdue, failed or not signed off · assets without a business
 *             or IT owner · SAMA CSF gaps (when the AI CISO has read them from the SIEM)
 *   never:    approves, signs off, attests or publishes anything; never changes a policy - it drafts and recommends, the
 *             CISO / policy owner decides (GRC approvals unchanged: drafts need an admin, sign-off needs a second person)
 * Routes:  POST /grc/consult {question} (operator) · GET /grc/consults (viewer) · GET /grc/roadmap (viewer)
 */
const crypto = require('crypto');
const { sanitisePair } = require('./ai/sanitise');
// the masking by Python too when it answers identically (engine/ai/guard-py.js, migration step 9j-a); otherwise sanitise.js
const guardSanitise = async (app, system, prompt, terms) => { try { return await require('./ai/guard-py').guardFor(app.config).sanitisePair(system, prompt, terms); } catch (e) { return sanitisePair(system, prompt, terms); } };
const { extractJson } = require('./ai/validate');

const clip = (s, n) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim().slice(0, n);
const hash = (s) => crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, 10);
const CLOSED = { retired: 1, disposed: 1, lost: 1 };

// what the consultant recommends per kind of gap, and the clauses it maps to (verify with the compliance team)
const ADVICE = {
  'control-fail': ['Restore the control: fix the failing source or process, then let the automated check confirm it.', 'SAMA CSF 3.3 · NCA ECC 2 · ISO 27001 Annex A'],
  'control-partial': ['Close the partial coverage named in the detail so the control passes fully.', 'SAMA CSF 3.3 · NCA ECC 2 · ISO 27001 Annex A'],
  'policy-review': ['Review the policy with its owner, record the review (GRC Policies → Review) or raise a revised draft for approval.', 'SAMA CSF 3.1.3 policy review · ISO 27001 5.2 / A.5.1'],
  'ia-gap': ['Write the missing policy / procedure (GRC Policies → Drafts) and map it to the requirement; the CISO approves it.', 'Insurance Authority requirements'],
  'ia-partial': ['Complete the requirement: the existing policy covers it only in part - extend it or add the missing procedure.', 'Insurance Authority requirements'],
  'drill-overdue': ['Plan and run the recovery test for this system (DR & BCM Drills), with RTO / RPO targets, and have it signed off independently.', 'SAMA BCM · SAMA CSF 3.3.13 · ISO 27001 A.5.30'],
  'drill-failed': ['Fix the findings of the failed test and repeat it; until then the system\'s recovery is not proven.', 'SAMA BCM · ISO 27001 A.5.30'],
  'drill-signoff': ['Have an administrator who did not run the drill review the evidence and sign it off.', 'SAMA BCM - independent review'],
  'owner-business': ['Name a business owner for these assets - per business service is fastest (Asset Ownership).', 'ISO 27001 A.5.9 · SAMA CSF asset management · NCA ECC 2-1'],
  'owner-it': ['Name an IT owner for these assets (Asset Ownership).', 'ISO 27001 A.5.9 · SAMA CSF asset management · NCA ECC 2-1'],
  'pentest-exposure': ['Close or restrict the exposed services listed (patch, disable, or limit to management networks), then let the next assessment confirm it; the IT owner fixes, the business owner accepts any residual risk in writing.', 'SAMA CSF 3.3 (vulnerability management) · NCA ECC 2-10 (vulnerability management) · ISO 27001 A.8.8 (technical vulnerabilities)'],
  'sama-gap': ['Close the SAMA CSF control gap: the SAMA Compliance page lists the checks that fail and the evidence missing.', 'SAMA CSF'],
};

function grcConsultantAdapter(app, G) {
  const sev = { 'control-fail': 'high', 'control-partial': 'medium', 'policy-review': 'medium', 'ia-gap': 'high', 'ia-partial': 'medium', 'drill-overdue': 'high', 'drill-failed': 'critical', 'drill-signoff': 'medium', 'owner-business': 'medium', 'owner-it': 'low', 'sama-gap': 'high', 'pentest-exposure': 'high' };
  const mk = (kind, key, title, evidence, target, extra) => ({ key: kind + ':' + key, severity: (extra && extra.severity) || sev[kind], kind, title, evidence: [].concat(evidence || []).filter(Boolean).concat(['framework: ' + ADVICE[kind][1]]),
    recommendation: ADVICE[kind][0], target: target || { type: 'grc', id: key, name: title } });
  async function current() {
    const out = [];
    const sum = G.summary();
    for (const [k, v] of Object.entries(sum.control_status || {})) {
      const st = v && (v.state || v.status);
      if (st === 'fail') out.push(mk('control-fail', k, 'Control "' + k + '" failing', [v.metric, v.detail], { type: 'control', id: k, name: k }));
      else if (st === 'partial') out.push(mk('control-partial', k, 'Control "' + k + '" only partly met', [v.metric, v.detail], { type: 'control', id: k, name: k }));
    }
    for (const p of G.register({}).items || []) if (p.review && p.review.overdue && !p.review.acknowledged)
      out.push(mk('policy-review', p.doc_id, p.doc_id + ' ' + clip(p.title, 90) + ': review overdue since ' + (p.review.next_review || '?'), ['owner: ' + (p.owner || '-'), 'version ' + (p.version || '-')], { type: 'policy', id: p.doc_id, name: p.doc_id }));
    try {
      const ia = G.frameworkIA();
      for (const d of ia.domains || []) if (d.required && (d.status === 'gap' || d.status === 'partial'))
        out.push(mk(d.status === 'gap' ? 'ia-gap' : 'ia-partial', d.key, 'Insurance Authority: ' + clip(d.name, 100) + (d.status === 'gap' ? ' - not covered' : ' - partly covered'), [d.note, d.policies.length ? 'policies: ' + d.policies.map((x) => x.doc_id).join(', ') : 'no policy mapped'], { type: 'requirement', id: d.key, name: d.name }));
    } catch (e) { /* framework view not available in this engine */ }
    const systems = G.drillSystems(), drills = G.drillList({}).items || [];
    for (const s of systems) {
      if (s.last_result === 'fail') out.push(mk('drill-failed', s.system, s.system + ': last recovery test failed', ['last test ' + ((s.last && s.last.executed) || '?')], { type: 'system', id: s.system, name: s.system }));
      else if (s.overdue) out.push(mk('drill-overdue', s.system, s.system + ': recovery test ' + (s.last ? 'overdue (last ' + clip(s.last.executed, 10) + ')' : 'never performed'), ['cycle ' + s.frequency_months + ' months'], { type: 'system', id: s.system, name: s.system }));
    }
    for (const d of drills) if (d.status === 'completed' && !(d.signoff && d.signoff.by))
      out.push(mk('drill-signoff', d.id, d.id + ' ' + clip(d.title, 80) + ': completed, not signed off', ['ran by ' + (d.executed_by || '-')], { type: 'drill', id: d.id, name: d.id }));
    const ow = app.addons && app.addons.ownership;
    if (ow) {
      const s = ow.summary();
      if (s.assets && s.missing_business) out.push(mk('owner-business', 'all', s.missing_business + ' of ' + s.assets + ' assets without a business owner', [s.business_pct + '% named'], { type: 'assets', id: 'ownership', name: 'Asset ownership' }, { severity: s.business_pct < 50 ? 'high' : 'medium' }));
      if (s.assets && s.missing_it) out.push(mk('owner-it', 'all', s.missing_it + ' of ' + s.assets + ' assets without an IT owner', [s.it_pct + '% named'], { type: 'assets', id: 'ownership', name: 'Asset ownership' }));
    }
    // penetration testing findings → one compliance gap per asset with critical / high findings, owners named
    const pt = app.addons && app.addons.pentest;
    if (pt) {
      let a = null; try { a = pt.assessment(); } catch (e) { a = null; }
      const byAsset = new Map();
      for (const f of (a && a.findings) || []) if (f.severity === 'critical' || f.severity === 'high') { const l = byAsset.get(f.asset_id) || []; l.push(f); byAsset.set(f.asset_id, l); }
      for (const [aid, fs] of byAsset) {
        const crit = fs.some((f) => f.severity === 'critical'), net = fs.some((f) => f.internet), o = ow && ow.ownerOf ? ow.ownerOf(aid) : null;
        out.push(mk('pentest-exposure', aid, `${fs[0].asset}: ${fs.length} serious exposure${fs.length > 1 ? 's' : ''} found by the penetration testing engineer${net ? ' (internet-facing)' : ''}`,
          [fs.slice(0, 6).map((f) => f.title + ' [' + f.severity + ']').join('; '), o ? 'IT owner: ' + (o.it_owner || 'not named') + ' · business owner: ' + (o.business_owner || 'not named') : 'owners: ownership module not installed'],
          { type: 'asset', id: aid, name: fs[0].asset }, { severity: crit && net ? 'critical' : crit || net ? 'high' : 'medium' }));
      }
    }
    const ciso = app.addons && app.addons.ciso;
    if (ciso) { let tm = null; try { const v = await Promise.race([ciso.overview(false), new Promise((_, no) => { tm = setTimeout(() => no(new Error('the CISO overview did not answer in 5 s')), 5000); })]); for (const r of v.risks.filter((x) => x.ref.indexOf('sama:') === 0)) out.push(mk('sama-gap', r.ref.slice(5), r.title, [r.source], { type: 'control', id: r.ref, name: r.ref.slice(5) })); } catch (e) { /* SIEM side not readable now, or slower than 5 s: these SAMA gaps are listed on the next pass */ } finally { clearTimeout(tm); } }
    return out;
  }
  return {
    id: 'grc', name: 'AI GRC Consultant',
    findings: current,
    investigate(it) {
      return { summary: `${it.title}. ${it.recommendation || ''}`.trim(),
        checks: (it.evidence || []).map((e) => ({ name: /^framework:/.test(e) ? 'framework' : 'evidence', status: /^framework:/.test(e) ? 'ok' : 'warn', detail: e })),
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }] };
    },
    // Claude (or the private model) on a work item: the same consultation path as "ask the consultant" - sanitised, answers
    // only from the GRC records, refs checked, audited, inside the daily cap. Advice only: it never approves or changes anything.
    aiStatus() { return app.provider && app.provider.statusSync ? app.provider.statusSync() : { enabled: false, reason: 'no AI provider in this engine' }; },
    async aiInvestigate(it) {
      const C = app.addons && app.addons.grcConsultant; if (!C) throw new Error('the consultant is not loaded');
      const r = await C.consult(`Work item ${it.id} (${it.severity}, ${it.kind}): ${it.title}\nEvidence: ${(it.evidence || []).join(' | ')}\nRule-based recommendation: ${it.recommendation || '-'}\n`
        + ('Explain the compliance risk of this gap for ' + ZYB_ORG.short + ', which framework obligations it touches (from the context only), and the concrete steps to close it, each with the role that owns it.'), { user: 'duty:grc', role: 'operator' });
      if (r.kind !== 'ai') throw new Error(r.why_rules || 'the AI consultant is not available');
      const acts = (r.actions || []).map((a, i) => (i + 1) + '. ' + a.action + (a.owner_role ? ' (' + a.owner_role + ')' : '') + (a.refs && a.refs.length ? ' [' + a.refs.join(', ') + ']' : '')).join('\n');
      return { answer: r.answer + (acts ? '\n\nNext steps:\n' + acts : '') + (r.refs && r.refs.length ? '\n\nRecords cited: ' + r.refs.join(', ') : ''), steps: [], model: r.model || '' };
    },
    async verify(it) { const f = await current(); const present = f.some((x) => x.key === it.key); return { present, note: present ? 'the GRC records still show the gap' : 'the GRC records no longer show the gap' }; },
    current, ADVICE,
  };
}

/* ---- ask the consultant: answers from the GRC records only, citing them */
function createConsult(app, G, adapter, opts = {}) {
  const col = app.store.collection('grc_consults'), now = opts.now || Date.now;
  const cfg = (app.config && app.config.grc_consultant) || {};
  const SYSTEM = [
    ('You are the AI GRC Consultant of ' + ZYB_ORG.name + ' (Saudi Arabia; SAMA CSF, NCA ECC, PDPL, Insurance Authority, ISO 27001).'),
    'Answer the question from the CONTEXT only: the company\'s policy register, control results, framework coverage, DR drills, asset ownership and open gaps.',
    'Cite the record ids you rely on exactly as given (field "ref"). Never invent a policy, control, clause number, date or finding. If the context does not answer the question, say what is missing.',
    'You advise; the CISO and policy owners decide. Never state that anything was approved, attested, signed or changed.',
    'Answer with ONE JSON object: {"answer": string (plain language, max 8 sentences), "actions": [{"action": string, "owner_role": string, "refs": [string]}] (0-6), "refs": [string]}',
  ].join('\n');
  async function context() {
    const s = G.summary(), gaps = await adapter.current();
    const reg = (G.register({}).items || []).map((p) => ({ ref: 'policy:' + p.doc_id, title: p.title, domain: p.domain, owner: p.owner, frameworks: p.frameworks_list, review: p.review && p.review.next_review, overdue: !!(p.review && p.review.overdue), control: p.control && p.control.cls }));
    let ia = null; try { ia = G.frameworkIA(); } catch (e) { ia = null; }
    return { policies: reg.slice(0, 120), controls: Object.entries(s.control_status || {}).map(([k, v]) => ({ ref: 'control:' + k, state: v && (v.state || v.status), metric: v && v.metric, detail: v && v.detail })),
      insurance_authority: ia ? (ia.domains || []).map((d) => ({ ref: 'ia:' + d.key, name: d.name, required: d.required, status: d.status })) : [],
      drills: G.drillSummary(), gaps: gaps.map((g) => ({ ref: 'gap:' + g.key, severity: g.severity, title: g.title, recommendation: g.recommendation })),
      ownership: app.addons && app.addons.ownership ? app.addons.ownership.summary() : null };
  }
  const refsOf = (c) => new Set([].concat(c.policies.map((x) => x.ref), c.controls.map((x) => x.ref), c.insurance_authority.map((x) => x.ref), c.gaps.map((x) => x.ref)));
  async function consult(question, who) {
    const q = clip(question, 1500); if (!q) throw Object.assign(new Error('ask a question'), { status: 400 });
    const c = await context(), known = refsOf(c), t = now();
    const rec = { id: 'GC-' + t.toString(36) + '-' + crypto.randomBytes(3).toString('hex'), at: t, by: (who && who.user) || '', question: q };
    const fallback = (why) => Object.assign(rec, { kind: 'rules', why_rules: why, answer: 'The AI consultant is not available (' + why + '). The open gaps, most serious first, are listed with the recommendation for each.',
      actions: c.gaps.slice(0, 6).map((g) => ({ action: g.title + ' - ' + g.recommendation, owner_role: 'CISO / policy owner', refs: [g.ref] })), refs: c.gaps.slice(0, 6).map((g) => g.ref) });
    const cap = Number(cfg.ai_daily_cap) || 30, day = new Date(t + 3 * 3600000).toISOString().slice(0, 10);
    const today = col.all((x) => x.kind === 'ai' && new Date(x.at + 3 * 3600000).toISOString().slice(0, 10) === day).length;
    if (!app.provider) fallback('no AI provider in this engine');
    else if (app.duty && typeof app.duty.aiAllowed === 'function' && !app.duty.aiAllowed('grc')) fallback('external AI is switched off for the AI GRC Consultant');
    else if (today >= cap) fallback('daily cap of ' + cap + ' consultations reached');
    else {
      const st = await app.provider.status().catch(() => ({ state: 'error' }));
      if (st.state !== 'ready') fallback(st.message || st.state);
      else {
        const settings = (app.settings && app.settings.get && app.settings.get()) || {};
        const pair = await guardSanitise(app, SYSTEM, 'QUESTION: ' + q + '\n\nCONTEXT:\n' + JSON.stringify(c), settings.redact_terms);
        let res; try { res = await app.provider.call({ system: pair.system, prompt: pair.prompt, who: { user: rec.by }, feature: 'itam.grc_consult' }); } catch (e) { res = { ok: false, message: e.message }; }
        if (app.audit) app.audit({ by: rec.by, role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'ai.call', target: rec.id, detail: { feature: 'grc_consult', status: res.ok ? 'ok' : 'error', model: res.model || null, system_sha256: pair.system_sha256, prompt_sha256: pair.prompt_sha256 } });
        const j = res.ok ? extractJson(res.text || '').obj : null;
        if (j && j.answer) {
          let dropped = 0; const keep = (a) => [].concat(a || []).map((x) => clip(x, 120)).filter((x) => { const k = known.has(x); if (!k) dropped++; return k; }).slice(0, 10);
          Object.assign(rec, { kind: 'ai', model: res.model || null, answer: clip(j.answer, 2500), actions: [].concat(j.actions || []).slice(0, 6).map((a) => ({ action: clip(a.action, 400), owner_role: clip(a.owner_role, 60), refs: keep(a.refs) })).filter((a) => a.action),
            refs: keep(j.refs), refs_dropped: dropped });
        } else fallback(res.ok ? 'the AI answer was not valid' : clip(res.message || 'AI call failed', 160));
      }
    }
    col.put(rec);
    if (app.audit) app.audit({ by: rec.by, role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'grc.consult', target: rec.id, detail: { kind: rec.kind, question_sha: hash(q) } });
    return rec;
  }
  function list(limit) { return col.all().sort((a, b) => b.at - a.at).slice(0, Math.min(Number(limit) || 20, 100)); }
  // compliance roadmap: the open gaps grouped into now / next / later by severity, each with its framework
  async function roadmap() {
    const g = await adapter.current(), H = { critical: 'now', high: 'now', medium: 'next', low: 'later' };
    const by = { now: [], next: [], later: [] };
    for (const x of g) by[H[x.severity] || 'later'].push({ ref: 'gap:' + x.key, severity: x.severity, kind: x.kind, title: x.title, recommendation: x.recommendation, framework: ADVICE[x.kind] ? ADVICE[x.kind][1] : '' });
    return { generated: now(), total: g.length, horizons: by };
  }
  return { consult, list, roadmap, context };
}

function registerGrcConsultantRoutes(srv, app, G, adapter, opts = {}) {
  const C = createConsult(app, G, adapter, opts);
  srv.route('POST', '/grc/consult', (ctx) => { ctx.need('operator'); return C.consult((ctx.body || {}).question, ctx.who); });
  srv.route('GET', '/grc/consults', (ctx) => void ctx.need('viewer') || ({ consults: C.list((ctx.query || {}).limit) }));
  srv.route('GET', '/grc/roadmap', (ctx) => void ctx.need('viewer') || C.roadmap());
  (app.addons = app.addons || {}).grcConsultant = C;
  return C;
}

module.exports = { grcConsultantAdapter, registerGrcConsultantRoutes, ADVICE };
