// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { createIntelKit, registerIntel, trend, beta } = require('./intel-kit');
/*
 * PDPL Studio ({P} = /api/itam; Data Privacy -> Overview). The intelligence view over the PDPL register (engine/pdpl.js - 24
 * requirements decided in Python from the records of processing, requests, breaches, impact assessments, processors, transfers,
 * consent and retention, and confirmed by the DPO). Nothing is decided here: the register's results are shown, learned from and ranked.
 *   areas        compliance per PDPL area (Governance, Records, Lawful basis, Risk, Data subject rights, Breach, ...) - only what
 *                the DPO confirmed counts as compliant; an automated pass still waits for the DPO - and movement against 30 days ago
 *   gains        the requirements that would raise compliance most for one action: the points a requirement adds when confirmed
 *                compliant ((1 - its current credit) / scored requirements x 100), weighted by the open findings behind it; an
 *                automated pass the DPO only has to confirm comes first, it is one step
 *   expiring     confirmations are valid for 12 months: the ones that lapse in the next 60 days (they turn into "not assessed")
 *   learning     one snapshot a day of every requirement's result: requirements that regressed (compliant 30 days ago, not now);
 *                how often each one has been failing (Beta(1,1) over its daily history: 50 % with no history, never 0 / 100 from
 *                one day) - "likely to fail next" is one that is compliant now but has failed often; the projection to the target
 *   readiness    what stands between the organisation and the DPO's signed statement (open items), and the statement's state
 * The statement is an internal self-assessment, not an SDAIA certificate - the page says so.
 *   GET  /pdpl-studio                 viewer   (the viewer's view of the register: no finding details, no register records)
 *   POST /pdpl-studio/ask             operator the read-only AI privacy advisor (kit)
 * Confirmations, records and signatures stay on the PDPL register's own audited routes.
 */
const SCORE = { compliant: 1, partial: 0.5 };
const PASS = new Set(['compliant']);
const RES = { compliant: { text: 'compliant (DPO confirmed)', tone: 'ok' }, partial: { text: 'partially compliant', tone: 'warn' }, non_compliant: { text: 'not compliant', tone: 'bad' },
  auto_pass: { text: 'automated pass - DPO to confirm', tone: 'warn' }, not_assessed: { text: 'not assessed', tone: 'na' }, not_applicable: { text: 'n/a', tone: 'na' } };
const TARGET = 90, DAY = 86400000, EXPIRY_DAYS = 60;

function createPdplStudio(app, opts = {}) {
  let K;
  async function collect() {
    const notes = [], P = K.A().pdpl;
    if (!P) { notes.push('the PDPL register is not installed - nothing to read'); return { v: null, notes }; }
    const v = await K.read('the PDPL register', () => P.view(false), notes);
    return { v, notes };
  }
  const credit = (r) => SCORE[r.result] || 0;
  function areasOf(R) {
    const m = new Map();
    for (const r of R) { const a = m.get(r.area) || { area: r.area, reqs: [] }; a.reqs.push(r); m.set(r.area, a); }
    return [...m.values()].map((a) => { const s = a.reqs.filter((r) => r.result !== 'not_applicable');
      return Object.assign(a, { scored: s.length, score: s.length ? Math.round(s.reduce((t, r) => t + credit(r), 0) / s.length * 1000) / 10 : null,
        open: s.filter((r) => !PASS.has(r.result)).length, gaps: s.filter((r) => r.result === 'non_compliant').length, confirm: s.filter((r) => r.result === 'auto_pass').length }); });
  }
  function analyse(v) {
    const H = K.history(), ref = K.ago(30), R = v.requirements, scored = R.filter((r) => r.result !== 'not_applicable'), n = Math.max(1, scored.length);
    const fails = {}; for (const h of H) for (const [id, r] of Object.entries(h.r || {})) { const x = fails[id] = fails[id] || { n: 0, f: 0 }; x.n++; if (!PASS.has(r) && r !== 'not_applicable') x.f++; }
    const failRate = (id) => { const x = fails[id] || { n: 0, f: 0 }; return { p: beta(x.f, x.n), n: x.n, f: x.f }; };
    const regressed = ref && ref.r ? R.filter((r) => PASS.has(ref.r[r.id]) && !PASS.has(r.result) && r.result !== 'not_applicable') : [];
    const improved = ref && ref.r ? R.filter((r) => ref.r[r.id] && !PASS.has(ref.r[r.id]) && PASS.has(r.result)) : [];
    const likely = R.filter((r) => PASS.has(r.result)).map((r) => ({ r, fr: failRate(r.id) })).filter((x) => x.fr.n >= 7 && x.fr.f >= 2).sort((a, b) => b.fr.p - a.fr.p);
    const gain = (r) => Math.round((1 - credit(r)) / n * 1000) / 10;
    const findings = (r) => (r.auto && r.auto.findings) || 0;
    const action = (r) => r.conflict ? 'resolve the conflict: the DPO confirmed it, but the registers now show a gap - fix the gap (' + K.clip(r.auto && r.auto.detail, 160) + ')'
      : r.result === 'auto_pass' ? 'the automated check passes - the DPO confirms it on the PDPL page with the evidence: ' + K.clip(r.evidence_expected, 160)
        : r.result === 'non_compliant' ? 'fix what the registers show: ' + K.clip(String(r.why || '').replace(/^the registers show a gap: /, ''), 200)
          : r.result === 'partial' ? 'complete it and have the DPO confirm it as compliant with evidence'
            : 'assess it (PDPL Self-Assessment) and have the DPO confirm it with: ' + K.clip(r.evidence_expected, 160);
    const gains = scored.filter((r) => !PASS.has(r.result)).map((r) => ({ r, g: gain(r), w: gain(r) * (r.result === 'auto_pass' ? 2 : 1) * (1 + Math.min(5, findings(r)) * 0.2) * (r.conflict ? 1.5 : 1) })).sort((a, b) => b.w - a.w);
    const t0 = K.now(), expiring = R.filter((r) => r.confirmation && !r.confirmation.expired && r.confirmation.due && Date.parse(r.confirmation.due) - t0 <= EXPIRY_DAYS * DAY)
      .map((r) => ({ r, days: Math.max(0, Math.ceil((Date.parse(r.confirmation.due) - t0) / DAY)) })).sort((a, b) => a.days - b.days);
    const tr = trend(K.pts('score'), { target: TARGET, current: v.compliance_pct, now: t0 });
    return { regressed, improved, likely, gains, failRate, gain, action, expiring, findings, areaPrev: ref && ref.a ? ref.a : {}, tr };
  }
  async function view() {
    const Cc = await collect(), v = Cc.v;
    if (!v) return { generated_at: K.iso(), notes: Cc.notes, ai: K.aiStatus(), ring: { value: null, label: 'PDPL compliance', why: 'the PDPL register is not installed' }, kpis: [], sections: [], note: 'Install the AI PDPL Consultant (engine/pdpl.js).' };
    const A = analyse(v), R = v.requirements, cnt = (k) => R.filter((r) => r.result === k).length, areas = areasOf(R), rd = v.readiness || {}, st = v.statement || {};
    const tone = (s) => s == null ? 'na' : s >= TARGET ? 'ok' : s >= 50 ? 'warn' : 'bad';
    const areaCards = areas.map((a) => { const prev = A.areaPrev[a.area], mv = a.score != null && prev != null ? Math.round((a.score - prev) * 10) / 10 : null;
      return { id: 'a-' + a.area, title: a.area, sub: a.score == null ? 'not applicable' : a.score + ' % · ' + a.reqs.length + ' requirement(s)', tone: tone(a.score),
        tags: [a.score == null ? 'na' : a.score >= TARGET ? 'on_target' : 'below'].concat(a.gaps ? ['gaps'] : []).concat(a.confirm ? ['confirm'] : []).concat(mv != null && mv < 0 ? ['down'] : mv > 0 ? ['up'] : []),
        badges: [].concat(a.gaps ? [{ text: a.gaps + ' not compliant', tone: 'bad' }] : []).concat(a.confirm ? [{ text: a.confirm + ' for the DPO to confirm', tone: 'warn' }] : []).concat(mv ? [{ text: (mv > 0 ? '+' : '') + mv + ' pts (30 d)', tone: mv > 0 ? 'ok' : 'bad' }] : []),
        metrics: [{ label: 'compliance', value: a.score == null ? '—' : a.score + ' %' }, { label: 'open', value: a.open }, { label: 'requirements', value: a.reqs.length }],
        detail: { rows: [['Area', a.area], ['Compliance', a.score == null ? 'not applicable' : a.score + ' % (confirmed compliant counts 1, partial 0.5)'], ['30 days ago', prev == null ? 'no history yet' : prev + ' %'], ['Requirements', a.reqs.length + ' · ' + a.open + ' open']],
          lists: [{ title: 'Requirements', items: a.reqs.map((r) => r.id + ' ' + r.title + ' - ' + (RES[r.result] || { text: r.result }).text) }] }, link: 'ai-pdpl.html' }; });
    const rows = R.map((r) => { const fr = A.failRate(r.id), x = RES[r.result] || { text: r.result, tone: '' };
      return { id: r.id, title: r.id + ' ' + r.title, cells: [r.id, r.area, K.clip(r.title, 140), { text: x.text, tone: x.tone }, r.ref || '—', r.automated ? 'yes' : 'DPO'],
        tags: [r.result].concat(r.conflict ? ['conflict'] : []).concat(r.automated ? ['auto'] : []).concat(A.regressed.includes(r) ? ['regressed'] : []).concat(A.expiring.some((e) => e.r === r) ? ['expiring'] : []),
        detail: { rows: [['Requirement', r.id + ' ' + r.title], ['Area', r.area], ['Reference', r.ref || '—'], ['Result', x.text], ['Why', r.why || '—'], ['Evidence expected', r.evidence_expected || '—'],
          ['Checked automatically', r.automated ? (r.auto && r.auto.state === 'pass' ? 'passes' : r.auto && r.auto.state === 'fail' ? 'fails - ' + A.findings(r) + ' finding(s): ' + K.clip(r.auto.detail, 200) : 'no result yet') : 'no - the DPO assesses it'],
          ['DPO confirmation', r.confirmation ? r.confirmation.status + ' by ' + r.confirmation.by + ' · valid until ' + String(r.confirmation.due || '').slice(0, 10) + (r.confirmation.expired ? ' (expired)' : '') : 'none'],
          ['Points if confirmed compliant', A.gain(r) + ' pts'], ['Failing in its history', fr.n ? fr.f + ' of ' + fr.n + ' day(s) (' + Math.round(fr.p * 100) + ' %)' : 'no history yet']],
          text: PASS.has(r.result) ? 'Compliant. Keep the evidence current; the confirmation lapses after 12 months.' : r.result === 'not_applicable' ? 'Not applicable, as confirmed by the DPO.' : 'Next action: ' + A.action(r) + '.' } }; });
    const gainItems = A.gains.slice(0, 24).map((x) => ({ id: 'g' + x.r.id, title: x.r.id + ' ' + x.r.title, sub: '+' + x.g + ' pts · ' + A.action(x.r), tone: x.r.result === 'auto_pass' ? 'ok' : x.r.result === 'non_compliant' ? 'bad' : 'warn',
      badges: [{ text: '+' + x.g + ' pts', tone: 'ok' }, { text: (RES[x.r.result] || { text: x.r.result }).text, tone: (RES[x.r.result] || {}).tone || '' }].concat(A.findings(x.r) ? [{ text: A.findings(x.r) + ' finding(s)', tone: 'bad' }] : []) }));
    const expItems = A.expiring.map((x) => ({ id: 'e' + x.r.id, title: x.r.id + ' ' + x.r.title, sub: 'confirmed by ' + x.r.confirmation.by + ' - lapses ' + (x.days ? 'in ' + x.days + ' day(s)' : 'today') + ' (' + String(x.r.confirmation.due).slice(0, 10) + '); the DPO re-confirms it with current evidence', tone: x.days <= 14 ? 'bad' : 'warn', badges: [{ text: x.days + ' d', tone: x.days <= 14 ? 'bad' : 'warn' }] }));
    const likelyItems = A.likely.slice(0, 15).map((x) => ({ id: 'l' + x.r.id, title: x.r.id + ' ' + x.r.title, sub: 'compliant now; failing on ' + x.fr.f + ' of ' + x.fr.n + ' day(s) - ' + Math.round(x.fr.p * 100) + ' % (Beta(1,1))', tone: 'warn', badges: [{ text: Math.round(x.fr.p * 100) + ' % fail rate', tone: x.fr.p >= 0.4 ? 'bad' : 'warn' }] }));
    const regItems = A.regressed.map((r) => ({ id: 'r' + r.id, title: r.id + ' ' + r.title, sub: 'compliant 30 days ago, now ' + (RES[r.result] || { text: r.result }).text + ' - ' + K.clip(r.why, 160), tone: 'bad', badges: [{ text: 'regressed', tone: 'bad' }] }));
    const hist = K.history(90), scoredN = R.filter((r) => r.result !== 'not_applicable').length;
    const stText = st.status === 'signed' || st.status === 'attested' ? 'signed' : st.status === 'none' || !st.status ? 'not signed' : String(st.status).replace(/_/g, ' ');
    return { generated_at: K.iso(), notes: Cc.notes, ai: K.aiStatus(),
      ring: { value: v.compliance_pct, unit: ' %', label: 'PDPL compliance', why: (v.compliance_pct == null ? 'no scored requirement' : 'DPO-confirmed compliant counts 1, partial 0.5, over ' + scoredN + ' scored requirements') + ' · target ' + TARGET + ' %' },
      kpis: [{ label: 'Not compliant', value: cnt('non_compliant'), tone: cnt('non_compliant') ? 'bad' : 'ok' }, { label: 'For the DPO to confirm', value: cnt('auto_pass'), tone: cnt('auto_pass') ? 'warn' : 'ok', title: 'the automated check passes; it counts once the DPO confirms it' },
        { label: 'Not assessed', value: cnt('not_assessed'), tone: cnt('not_assessed') ? 'warn' : 'ok' }, { label: 'Regressed · 30 days', value: A.regressed.length, tone: A.regressed.length ? 'bad' : 'ok' },
        { label: 'Lapsing · 60 days', value: A.expiring.length, tone: A.expiring.length ? 'warn' : 'ok', title: 'DPO confirmations valid for 12 months that lapse within 60 days' },
        { label: 'Conflicts', value: R.filter((r) => r.conflict).length, tone: R.some((r) => r.conflict) ? 'bad' : 'ok', title: 'the DPO confirmed it, the registers now show a gap' },
        { label: 'Statement', value: rd.ready ? (stText === 'signed' ? 'signed' : 'ready to sign') : (rd.open || 0) + ' open', tone: rd.ready ? 'ok' : 'warn', title: 'items between the organisation and the DPO\'s signed statement' },
        { label: 'Projected ' + TARGET + ' %', value: A.tr.reached ? 'reached' : A.tr.date || '—', tone: A.tr.reached || A.tr.date ? 'ok' : 'warn', title: A.tr.why }],
      sections: [
        { id: 'areas', type: 'bars', title: 'Compliance by area', caption: 'DPO-confirmed compliant counts 1, partial 0.5; an automated pass counts once confirmed', items: areas.map((a) => ({ id: 'a-' + a.area, title: a.area, value: a.score == null ? 0 : a.score, max: 100, label: a.score == null ? 'not applicable' : a.score + ' % · ' + a.open + ' open', tone: a.score == null ? '' : tone(a.score) })) },
        { id: 'gains', type: 'list', title: 'Biggest gains for one action', caption: 'points each requirement adds when confirmed compliant, weighted by the findings behind it - DPO confirmations first, they are one step', items: gainItems, empty: 'Every scored requirement is confirmed compliant.' },
        { id: 'expiring', type: 'list', title: 'Confirmations lapsing', caption: 'a DPO confirmation is valid for 12 months - these lapse within ' + EXPIRY_DAYS + ' days and turn into "not assessed"', items: expItems, empty: 'No confirmation lapses in the next ' + EXPIRY_DAYS + ' days.' },
        { id: 'areacards', type: 'cards', title: 'Areas', caption: 'compliance, open requirements, movement against 30 days ago', wide: true, search: true,
          chips: [{ key: 'all', label: 'All' }, { key: 'below', label: 'Below target' }, { key: 'gaps', label: 'Not compliant' }, { key: 'confirm', label: 'DPO to confirm' }, { key: 'down', label: 'Moved down' }, { key: 'up', label: 'Moved up' }], items: areaCards },
        { id: 'requirements', type: 'table', title: 'Every requirement', caption: 'the register\'s result, why, the evidence expected, the DPO\'s confirmation and its history', wide: true, search: true, columns: ['Req.', 'Area', 'Requirement', 'Result', 'Reference', 'Checked'], limit: 100,
          chips: [{ key: 'all', label: 'All' }, { key: 'non_compliant', label: 'Not compliant' }, { key: 'auto_pass', label: 'DPO to confirm' }, { key: 'not_assessed', label: 'Not assessed' }, { key: 'expiring', label: 'Lapsing' }, { key: 'conflict', label: 'Conflicts' }, { key: 'regressed', label: 'Regressed' }, { key: 'auto', label: 'Automated' }], rows },
        { id: 'learning', type: 'list', title: 'Likely to fail next', caption: 'compliant now, but failing often in its daily history (7+ days, 2+ failing)', items: likelyItems, empty: 'Not enough history yet, or no compliant requirement has failed repeatedly.' },
        { id: 'regressed', type: 'list', title: 'Regressed in 30 days', caption: 'compliant 30 days ago, not now', items: regItems, empty: Object.keys(A.areaPrev).length ? 'No requirement regressed.' : 'No snapshot from 30 days ago yet.' },
        { id: 'readiness', type: 'text', title: 'Compliance statement', text: (rd.ready ? 'Nothing open: the DPO can sign the statement, and a different person in management countersigns it.' : (rd.open || 0) + ' item(s) stand between the organisation and the DPO\'s signed statement (every requirement not confirmed compliant or not applicable, and every open high or critical finding).') + ' Statement: ' + stText + '. The statement is signed on the AI PDPL Consultant page.' },
        { id: 'trend', type: 'trend', title: 'Trend', caption: 'PDPL compliance per day, projected to ' + TARGET + ' %', points: hist.map((h) => ({ date: h.id, value: h.score })), max: 100, text: A.tr.why },
        { id: 'basis', type: 'text', title: 'How to read this page', text: 'Every result comes from the PDPL register: the rules (Python) read the records of processing, data subject requests, breaches, impact assessments, processors, transfers, consent and retention, and only what the appointed DPO confirmed counts as compliant. A gap the registers show is never hidden by a confirmation. The statement is an internal self-assessment, not an SDAIA certificate - SDAIA (or a body it accredits) remains the only authority for certification. No personal data is shown here.' }
      ],
      note: 'The PDPL register, ranked and learned from. Records, confirmations and the statement stay on the AI PDPL Consultant page.' };
  }
  async function snapshot() { return K.snapshot(async () => { const C = await collect(); if (!C.v) return null;
    return { score: C.v.compliance_pct, r: Object.fromEntries(C.v.requirements.map((r) => [r.id, r.result])), a: Object.fromEntries(areasOf(C.v.requirements).filter((a) => a.score != null).map((a) => [a.area, a.score])) }; }); }
  K = createIntelKit(app, { key: 'pdpl-studio', feature: 'itam.pdpl-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: opts.noTimer,
    system: ('You are the privacy advisor to the Data Protection Officer of ' + ZYB_ORG.name + '. You read the PDPL register: the 24 requirements of the Saudi Personal Data Protection Law, its Implementing Regulation and the Cross-Border Transfer Regulation, with their result, why, the evidence expected and the DPO\'s confirmation; compliance per area; the requirements that add the most for one action; confirmations about to lapse; regressions and requirements that fail often. Base every statement on the tool results and name the requirement ids. Only the DPO confirms a requirement and signs the statement; you propose, you never decide. The statement is an internal self-assessment, not an SDAIA certificate. Never ask for or repeat personal data.'),
    tools: [{ name: 'privacy_cockpit', description: 'The Privacy Cockpit: every PDPL clock (data subject requests, breaches to SDAIA and other regulators, impact assessments, transfers, vendor reviews, retention), the requests most likely to miss their deadline (survival model or stated rule), the request volume forecast, and the riskiest processing activities with every point of their score named. Read-only.',
      run: async (i, who) => { const C = K.A().pdplCockpit; return C ? C.aiSummary(who || { user: 'ai-privacy', role: 'operator' }) : { note: 'the Privacy Cockpit is not installed' }; } },
    { name: 'pdpl', description: 'PDPL compliance, areas with movement, the biggest gains, lapsing confirmations, regressions, likely-to-fail requirements, statement readiness.', run: async () => { const v = await view(); if (!v.sections.length) return { error: 'PDPL register not installed' };
      const S = (id) => v.sections.find((s) => s.id === id) || {};
      return { kpis: v.kpis, ring: v.ring, areas: (S('areas').items || []).map((i) => i.title + ': ' + i.label), gains: (S('gains').items || []).slice(0, 12).map((i) => i.title + ' - ' + i.sub), lapsing: (S('expiring').items || []).map((i) => i.title + ' - ' + i.sub),
        regressed: (S('regressed').items || []).map((i) => i.title), likely: (S('learning').items || []).map((i) => i.title + ' - ' + i.sub), readiness: S('readiness').text }; } },
    { name: 'requirements', description: 'PDPL requirements in one area with result, why and the evidence expected.', input_schema: { type: 'object', properties: { area: { type: 'string', maxLength: 60 } }, required: ['area'], additionalProperties: false },
      run: async (inp) => { const C = await collect(); if (!C.v) return { error: 'PDPL register not installed' }; const a = String(inp.area || '').toLowerCase();
        const out = C.v.requirements.filter((r) => String(r.area).toLowerCase() === a).map((r) => ({ id: r.id, title: r.title, ref: r.ref, result: r.result, why: K.clip(r.why, 300), evidence_expected: K.clip(r.evidence_expected, 200) }));
        return out.length ? out : { error: 'no PDPL area named ' + K.clip(inp.area, 60) + '; areas: ' + [...new Set(C.v.requirements.map((r) => r.area))].join(', ') }; } }] });
  return { view, snapshot, ask: K.ask, start: () => K.start(snapshot), stop: K.stop, TOOLS: K.TOOLS };
}
function registerPdplStudio(srv, app, X) { registerIntel(srv, X, '/pdpl-studio'); }
module.exports = { createPdplStudio, registerPdplStudio };
