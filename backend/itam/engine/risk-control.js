// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Risk & Control Hub ({P} = /api/itam, GRC -> Risk & Control Hub). One connected model over the GRC risk register, in the shape
 * integrated-risk platforms use: business hierarchy -> risks -> the controls that treat them -> the authoritative requirements
 * each control meets -> tests of the controls -> findings; key risk indicators and loss events on the risks. What it adds to the
 * register (engine/grc-registers.js, whose risks stay where they are):
 *
 *   HIERARCHY  company / division / business unit / process, each with an owner (admin). A risk is placed in one unit.
 *   CONTROLS   one library every framework maps to: owner, unit, type (preventive / detective / corrective), nature (manual /
 *              automated), frequency, the policy it implements (GRC register), CITATIONS ("SAMA:3.3.6", "NCA:2-3-1", "PDPL:Art. 19",
 *              "ISO:A.8.13", "NDMO:..", "IA:..") and optionally an automated SIGNAL the platform already measures (below).
 *   EFFECTIVENESS = the weaker of DESIGN (rated by a person) and OPERATING (the bound signal, else the latest test in 12 months).
 *              A control never tested and with no signal is UNTESTED and counts as reducing nothing.
 *   TESTS      a person who does not own the control records design / operating tests (pass / partial / fail, sample, evidence).
 *              A partial or failed test raises a remediation action in the GRC register (source "control") - so it appears in
 *              Issues Management with every other finding.
 *   LINKS      risk <-> control, primary (could remove up to 60 % of the risk) or supporting (30 %).
 *   CALCULATED RESIDUAL = inherent x (1 - mitigation), mitigation = 1 - PRODUCT(1 - strength x effectiveness) over the linked
 *              controls, capped at 80 % (controls never make a risk disappear). effectiveness: effective 1, partial 0.5, else 0.
 *              Every point is itemised. The owner's own residual rating stays; when it is LOWER than the controls support, the
 *              risk is flagged "residual claimed below what the controls show".
 *   KRIs       on a risk, amber / red thresholds, higher- or lower-is-worse; values typed with a note, or read from a signal.
 *   LOSSES     loss events: date, unit, risk, controls involved, category (Basel II event types), gross and recovered SAR. A loss
 *              on a risk whose controls all read effective flags those controls as CHALLENGED.
 *   ACCEPTANCES one read-only register of every accepted risk and approved exception across the platform (policy exceptions, risk
 *              acceptances, inspection exceptions, PDPL accepted risks, audit findings accepted), with expiry: past its date = EXPIRED.
 *   ROLL-UPS   per unit (with its sub-units) and per framework (controls citing it, how many effective); and GAPS: risks with no
 *              control, controls treating no risk, controls untested, controls with an unknown signal.
 * Signals (never invented: a source not connected reads unknown): GRC live controls (assets, patching, backup, virtualisation,
 * roles, policy register), Asset Coverage (EDR, patching, backup, vulnerability scans, SIEM logs - share of assets covered) and the
 * PDPL Control Monitor (share of personal-data systems passing a test). >= 95 % effective, >= 70 % partial, else ineffective.
 *
 *   GET  /rc                                     viewer: roll-ups and counts · operator: the whole model
 *   POST /rc/units                    admin      {id?, name, kind, parent?, owner?}                                         audited
 *   POST /rc/units/:id/delete         admin      refused while it has sub-units, risks, controls or losses                   audited
 *   POST /rc/controls                 operator   {id?, title, description?, owner?, unit?, type, nature, frequency, policy?, citations[], signal?, design?}  audited
 *   POST /rc/controls/import-policies admin      one control per approved GRC register policy not yet in the library          audited
 *   POST /rc/tests                    operator   {control, kind, result, sample?, evidence, period?}   tester != control owner  audited
 *   POST /rc/links                    operator   {risk, control, strength?, remove?}                                         audited
 *   POST /rc/risks/:id/unit           operator   {unit | ""}                                                                 audited
 *   POST /rc/kris                     operator   {id?, risk, name, measure, direction, amber, red, signal?}                  audited
 *   POST /rc/kris/:id/value           operator   {value, note?}                                                              audited
 *   POST /rc/losses                   operator   {date, unit?, risk?, controls[], category, gross, recovered?, description}  audited
 */
const DAY = 86400000, YEAR = 365 * DAY;
const KINDS = ['company', 'division', 'unit', 'process'];
const TYPES = ['preventive', 'detective', 'corrective'];
const NATURES = ['manual', 'automated', 'it-dependent manual'];
const FREQS = ['continuous', 'daily', 'weekly', 'monthly', 'quarterly', 'semi-annual', 'annual', 'event-driven'];
const DESIGN = ['effective', 'partial', 'ineffective', 'not_rated'];
const RESULTS = ['pass', 'partial', 'fail'];
const STRENGTH = { primary: 0.6, supporting: 0.3 };
const CAP = 0.8;
const EFF = { effective: 1, partial: 0.5, ineffective: 0, untested: 0, unknown: 0 };
const FRAMEWORKS = ['SAMA', 'NCA', 'PDPL', 'ISO', 'NDMO', 'IA', 'CHI', 'INTERNAL'];
const CITE = /^(SAMA|NCA|PDPL|ISO|NDMO|IA|CHI|INTERNAL):[A-Za-z0-9 .()\-\/]{1,40}$/;
const LOSS_CATS = ['internal fraud', 'external fraud', 'employment practices and workplace safety', 'clients, products and business practices',
  'damage to physical assets', 'business disruption and system failures', 'execution, delivery and process management'];
const RISK_ID = /^RSK-\d{3,}$/;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
const low = (v) => s(v, 200).toLowerCase();
const band = (x) => x == null ? null : x >= 15 ? 'high' : x >= 8 ? 'medium' : 'low';

function createRiskControl(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || {};
  const C = (n) => store.collection(n);
  const units = () => C('rc_units'), controls = () => C('rc_controls'), tests = () => C('rc_tests'), links = () => C('rc_links'), meta = () => C('rc_risk_meta'), kris = () => C('rc_kris'), losses = () => C('rc_losses');
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'only a person ' + what + ' - ' + who.user + ' is a service / AI identity'); };
  function nextId(col, prefix) { let n = 0; for (const x of col.all()) { const m = String(x.id).match(/-(\d+)$/); if (m) n = Math.max(n, +m[1]); } return prefix + '-' + String(n + 1).padStart(3, '0'); }
  let G0 = null, R0 = null;
  const grc = () => opts.grc || (app.addons && app.addons.grc) || G0 || (G0 = (() => { try { return require('./grc').createGrc(app); } catch (e) { if (L.every) L.every('rc:grc', 3600000, 'warn', 'risk hub: the GRC policy register could not be opened', { err: s(e.message, 160) }); return null; } })());
  const registers = () => opts.registers || (app.addons && app.addons.grcRegisters) || R0 || (R0 = (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { return null; } })());

  // ---- signals: what the platform already measures; a source that cannot be read is unknown, never a pass
  const SIGNALS = {
    'grc:assets': 'Every discovered device is in the asset register', 'grc:patch': 'Endpoints have no missing critical patch (Endpoint Central)',
    'grc:backup': 'Guests have a recent successful backup', 'grc:virt': 'Virtualisation platforms report', 'grc:roles': 'Roles defined and held (Roles & Functions)',
    'grc:register': 'IT policies within their review cycle',
    'cov:edr': 'Assets with endpoint protection (Asset Coverage)', 'cov:patch': 'Assets patched (Asset Coverage)', 'cov:backup': 'Servers and VMs backed up (Asset Coverage)',
    'cov:vuln_scan': 'Assets scanned for vulnerabilities in 90 days (Asset Coverage)', 'cov:siem_logs': 'Assets sending logs to the SIEM (Asset Coverage)',
  };
  for (const [id, t] of [['M02', 'classified'], ['M03', 'confidentiality rated'], ['M04', 'on supported software'], ['M05', 'with a named owner'], ['M11', 'under a retention schedule']]) SIGNALS['pdpl:' + id] = 'Personal-data systems ' + t + ' (PDPL Control Monitor)';
  const fromPct = (pct, detail) => pct == null ? { state: 'unknown', value: null, detail } : { state: pct >= 95 ? 'effective' : pct >= 70 ? 'partial' : 'ineffective', value: pct, detail };
  async function readSignals() {
    const out = {};
    try {
      const G = grc(); const st = G && typeof G.controlStatus === 'function' ? G.controlStatus() : {};
      for (const k of ['assets', 'patch', 'backup', 'virt', 'roles', 'register']) {
        const x = st[k]; const m = { pass: 'effective', partial: 'partial', fail: 'ineffective' };
        out['grc:' + k] = x ? { state: m[x.state] || 'unknown', value: null, detail: [x.metric, x.detail].filter(Boolean).join(' - ') } : { state: 'unknown', value: null, detail: 'not measured' };
      }
    } catch (e) { if (L.every) L.every('rc:grc-status', 3600000, 'warn', 'risk hub: GRC live controls could not be read', { err: s(e.message, 160) }); }
    try {
      const CV = app.addons && app.addons.assetCoverage; const v = CV && typeof CV.view === 'function' ? await CV.view() : null;
      for (const k of ['edr', 'patch', 'backup', 'vuln_scan', 'siem_logs']) {
        if (!v) { out['cov:' + k] = { state: 'unknown', value: null, detail: 'Asset Coverage not installed' }; continue; }
        const src = v.sources && v.sources[k];
        if (src && src.ok === false) { out['cov:' + k] = { state: 'unknown', value: null, detail: src.error || 'source not connected' }; continue; }
        let ok = 0, n = 0; for (const r of v.rows || []) { const c = r.controls && r.controls[k]; if (!c || c.state === 'na' || c.state === 'not_checked') continue; n++; if (c.state === 'present' || c.state === 'exempt') ok++; }
        out['cov:' + k] = fromPct(n ? Math.round((100 * ok) / n) : null, n ? ok + ' of ' + n + ' assets' : 'no asset measured');
      }
    } catch (e) { if (L.every) L.every('rc:coverage', 3600000, 'warn', 'risk hub: Asset Coverage could not be read', { err: s(e.message, 160) }); }
    try {
      const last = C('pdpl_mon_runs').all().sort((a, b) => String(b.at).localeCompare(String(a.at)))[0];
      for (const id of ['M02', 'M03', 'M04', 'M05', 'M11']) {
        if (!last) { out['pdpl:' + id] = { state: 'unknown', value: null, detail: 'the PDPL Control Monitor has not run' }; continue; }
        let p = 0, f = 0; for (const [k, st] of Object.entries(last.states || {})) { if (!k.endsWith(':' + id)) continue; if (st === 'pass') p++; else if (st === 'fail') f++; }
        out['pdpl:' + id] = fromPct(p + f ? Math.round((100 * p) / (p + f)) : null, p + f ? p + ' of ' + (p + f) + ' systems, run ' + String(last.at).slice(0, 16).replace('T', ' ') : 'no system measured');
      }
    } catch (e) { if (L.every) L.every('rc:pdpl', 3600000, 'warn', 'risk hub: PDPL monitor runs could not be read', { err: s(e.message, 160) }); }
    for (const k of Object.keys(SIGNALS)) if (!out[k]) out[k] = { state: 'unknown', value: null, detail: 'not measured' };
    return out;
  }

  // ---- effectiveness and residual
  function effectiveness(c, sig, T) {
    const mine = T.filter((t) => t.control === c.id && now() - Date.parse(t.at) <= YEAR).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    const lastOp = mine.find((t) => t.kind === 'operating'), lastDes = mine.find((t) => t.kind === 'design');
    const fromTest = (t) => t ? ({ pass: 'effective', partial: 'partial', fail: 'ineffective' })[t.result] : null;
    let operating, opWhy;
    if (c.signal) { const x = sig[c.signal] || { state: 'unknown' }; operating = x.state; opWhy = 'signal: ' + (SIGNALS[c.signal] || c.signal) + (x.value != null ? ' (' + x.value + '%)' : '') + (x.detail ? ' - ' + x.detail : ''); }
    else if (lastOp) { operating = fromTest(lastOp); opWhy = 'operating test ' + lastOp.id + ' on ' + lastOp.at.slice(0, 10) + ': ' + lastOp.result; }
    else { operating = 'untested'; opWhy = 'no signal and no operating test in 12 months'; }
    const design = lastDes ? fromTest(lastDes) : c.design && c.design !== 'not_rated' ? c.design : 'not_rated';
    const rank = { effective: 3, partial: 2, ineffective: 1, untested: 0, unknown: 0, not_rated: 3 };
    const overall = design === 'not_rated' ? operating : rank[design] < rank[operating] ? design : operating;
    return { design, operating, overall, why: opWhy + (design === 'not_rated' ? ' · design not rated' : ' · design ' + design + (lastDes ? ' (test ' + lastDes.id + ')' : '')), last_test: mine[0] ? { id: mine[0].id, at: mine[0].at, result: mine[0].result, kind: mine[0].kind } : null };
  }
  function residualOf(r, linked) {
    const inh = (r.likelihood || 0) * (r.impact || 0);
    const parts = linked.map((l) => { const e = EFF[l.eff.overall] || 0, st = STRENGTH[l.strength] || STRENGTH.supporting; return { control: l.control, title: l.title, strength: l.strength, effectiveness: l.eff.overall, reduces_pct: Math.round(st * e * 100) }; });
    let keep = 1; for (const p of parts) keep *= 1 - p.reduces_pct / 100;
    const raw = 1 - keep, mit = Math.min(CAP, raw);
    const calc = linked.length ? Math.max(1, Math.round(inh * (1 - mit))) : inh;
    return { inherent: inh, mitigation_pct: Math.round(mit * 100), capped: raw > CAP, calculated: calc, calculated_band: band(calc), parts };
  }

  // ---- the model
  async function model() {
    const sig = await readSignals();
    const T = tests().all(), U = units().all(), Lk = links().all(), M = Object.fromEntries(meta().all().map((m) => [m.id, m]));
    const ctl = controls().all().map((c) => Object.assign({}, c, { eff: effectiveness(c, sig, T) }));
    const byC = Object.fromEntries(ctl.map((c) => [c.id, c]));
    const t = now(), yearAgo = t - YEAR;
    const LS = losses().all();
    const K = kris().all().map((k) => {
      let value = null, at = null, src = 'manual';
      if (k.signal) { const x = sig[k.signal] || {}; value = x.value; src = 'signal'; at = iso(); }
      else { const h = (k.history || [])[(k.history || []).length - 1]; if (h) { value = h.value; at = h.at; } }
      const worse = (a, b) => k.direction === 'lower_worse' ? a <= b : a >= b;
      const status = value == null ? 'no value' : worse(value, k.red) ? 'red' : worse(value, k.amber) ? 'amber' : 'green';
      return Object.assign({}, k, { value, at, source: src, status, history: (k.history || []).slice(-12) });
    });
    const risks = C('grc_risks').all((r) => r.status !== 'closed').map((r) => {
      const linked = Lk.filter((l) => l.risk === r.id && byC[l.control]).map((l) => ({ control: l.control, title: byC[l.control].title, strength: l.strength, eff: byC[l.control].eff }));
      const res = residualOf(r, linked);
      const owner = r.residual_likelihood && r.residual_impact ? r.residual_likelihood * r.residual_impact : null;
      const rk = K.filter((k) => k.risk === r.id);
      const rl = LS.filter((x) => x.risk === r.id && Date.parse(x.date) >= yearAgo);
      const net = rl.reduce((a, x) => a + (x.gross || 0) - (x.recovered || 0), 0);
      const flags = [];
      if (!linked.length) flags.push('no control treats this risk');
      if (owner != null && linked.length && owner < res.calculated - 2) flags.push('residual claimed (' + owner + ') below what the controls show (' + res.calculated + ')');
      if (rk.some((k) => k.status === 'red')) flags.push('a key risk indicator is red');
      if (rl.length && linked.length && linked.every((l) => l.eff.overall === 'effective')) flags.push('losses this year although every control reads effective - controls challenged');
      return { id: r.id, title: r.title, category: r.category || '', owner: r.owner || '', treatment: r.treatment, unit: (M[r.id] || {}).unit || '', likelihood: r.likelihood, impact: r.impact,
        inherent: res.inherent, inherent_band: band(res.inherent), owner_residual: owner, residual: res, controls: linked.map((l) => ({ id: l.control, title: l.title, strength: l.strength, effectiveness: l.eff.overall })),
        kris: rk.map((k) => ({ id: k.id, name: k.name, status: k.status, value: k.value })), losses_12m: { count: rl.length, net_sar: net }, flags };
    });
    const riskIds = new Set(Lk.map((l) => l.risk));
    const challenged = new Set();
    for (const x of LS) if (Date.parse(x.date) >= yearAgo) for (const cid of x.controls || []) if (byC[cid] && byC[cid].eff.overall === 'effective') challenged.add(cid);
    const ctlRows = ctl.map((c) => Object.assign({}, c, { risks: Lk.filter((l) => l.control === c.id).map((l) => l.risk), challenged: challenged.has(c.id) }));
    // roll-ups
    const kids = (id) => U.filter((u) => u.parent === id).map((u) => u.id);
    const under = (id) => { const out = [id], q = [id]; while (q.length) for (const k of kids(q.shift())) { out.push(k); q.push(k); } return new Set(out); };
    const byUnit = U.map((u) => {
      const set = under(u.id), R = risks.filter((r) => set.has(r.unit)), Cs = ctlRows.filter((c) => set.has(c.unit));
      const Ls = LS.filter((x) => set.has(x.unit) && Date.parse(x.date) >= yearAgo);
      return { id: u.id, name: u.name, kind: u.kind, parent: u.parent || '', owner: u.owner || '', risks: R.length, high_residual: R.filter((r) => r.residual.calculated_band === 'high').length,
        max_residual: R.reduce((m, r) => Math.max(m, r.residual.calculated), 0), controls: Cs.length, effective_pct: Cs.length ? Math.round((100 * Cs.filter((c) => c.eff.overall === 'effective').length) / Cs.length) : null,
        kris_red: K.filter((k) => R.some((r) => r.id === k.risk) && k.status === 'red').length, losses_net_sar: Ls.reduce((a, x) => a + (x.gross || 0) - (x.recovered || 0), 0) };
    });
    const byFramework = FRAMEWORKS.map((f) => {
      const Cs = ctlRows.filter((c) => (c.citations || []).some((x) => x.startsWith(f + ':')));
      const refs = [...new Set(Cs.flatMap((c) => (c.citations || []).filter((x) => x.startsWith(f + ':')).map((x) => x.slice(f.length + 1))))].sort();
      return { framework: f, controls: Cs.length, effective: Cs.filter((c) => c.eff.overall === 'effective').length, partial: Cs.filter((c) => c.eff.overall === 'partial').length,
        ineffective: Cs.filter((c) => c.eff.overall === 'ineffective').length, untested: Cs.filter((c) => ['untested', 'unknown'].includes(c.eff.overall)).length, requirements: refs };
    }).filter((x) => x.controls);
    const gaps = {
      risks_without_controls: risks.filter((r) => !r.controls.length).map((r) => ({ id: r.id, title: r.title })),
      controls_without_risks: ctlRows.filter((c) => !riskIds.has(c.id) && !c.risks.length).map((c) => ({ id: c.id, title: c.title })),
      controls_untested: ctlRows.filter((c) => c.eff.overall === 'untested').map((c) => ({ id: c.id, title: c.title })),
      controls_signal_unknown: ctlRows.filter((c) => c.signal && c.eff.operating === 'unknown').map((c) => ({ id: c.id, title: c.title, signal: c.signal })),
      controls_without_citation: ctlRows.filter((c) => !(c.citations || []).length).map((c) => ({ id: c.id, title: c.title })),
    };
    // one register of every accepted risk and approved exception, wherever it was decided (read-only: each is still decided where
    // it lives), with expiry - an acceptance past its date is listed as EXPIRED, never silently still in force
    const acc = [], push = (o) => { const until = o.until ? String(o.until).slice(0, 10) : ''; const d = until ? Math.floor((Date.parse(until + 'T23:59:59Z') - t) / DAY) : null;
      acc.push(Object.assign(o, { until, days_left: d, state: d == null ? 'no end date' : d < 0 ? 'expired' : d <= 30 ? 'expiring' : 'in force' })); };
    try { for (const x of C('grc_exceptions').all((e) => e.status === 'approved')) push({ source: 'Policy exception', ref: x.id, page: 'grc-register.html', title: x.title, decided_by: x.decided_by || '', until: x.expires }); } catch (e) { if (L.every) L.every('rc:acc1', 3600000, 'warn', 'risk hub: policy exceptions not read', { err: s(e.message, 120) }); }
    try { for (const r of C('grc_risks').all((x) => x.status !== 'closed' && x.acceptance)) push({ source: 'Risk acceptance', ref: r.id, page: 'grc-register.html', title: r.title, decided_by: r.acceptance.by || '', until: r.acceptance.until || '' }); } catch (e) { if (L.every) L.every('rc:acc2', 3600000, 'warn', 'risk hub: risk acceptances not read', { err: s(e.message, 120) }); }
    try { for (const a of C('insp_actions').all((x) => x.exception && x.exception.decision === 'approve')) push({ source: 'Inspection exception', ref: a.id, page: 'audit-inspections.html', title: a.item_text || a.id, decided_by: a.exception.decided_by || '', until: a.exception.until || '' }); } catch (e) { if (L.every) L.every('rc:acc3', 3600000, 'warn', 'risk hub: inspection exceptions not read', { err: s(e.message, 120) }); }
    try { for (const k of C('pdpl_office_tasks').all((x) => x.status === 'risk_accepted')) push({ source: 'PDPL accepted risk', ref: k.id, page: 'pdpl-office.html', title: k.title || k.id, decided_by: k.risk_by || '', until: k.risk_until || '' }); } catch (e) { if (L.every) L.every('rc:acc4', 3600000, 'warn', 'risk hub: PDPL acceptances not read', { err: s(e.message, 120) }); }
    for (const [col, src, page] of [['ia_findings', 'IT audit finding accepted', 'audit-team.html'], ['csa_findings', 'Cyber audit finding accepted', 'cyber-audit-team.html'], ['iad_findings', 'Internal audit finding accepted', 'internal-audit-team.html']]) {
      try { for (const f of C(col).all((x) => x.state === 'risk_accepted')) push({ source: src, ref: f.id, page, title: f.title || f.id, decided_by: f.accepted_by || '', until: f.accepted_until || '' }); } catch (e) { if (L.every) L.every('rc:acc-' + col, 3600000, 'warn', 'risk hub: ' + col + ' not read', { err: s(e.message, 120) }); }
    }
    acc.sort((a, b) => (a.days_left == null) - (b.days_left == null) || (a.days_left || 0) - (b.days_left || 0));
    return { acceptances: acc, risks, controls: ctlRows, kris: K, losses: LS.sort((a, b) => String(b.date).localeCompare(String(a.date))), units: U, by_unit: byUnit, by_framework: byFramework, gaps, signals: sig, tests: T.sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 200) };
  }
  async function view(who) {
    const m = await model();
    const kpis = { risks: m.risks.length, high_inherent: m.risks.filter((r) => r.inherent_band === 'high').length, high_residual: m.risks.filter((r) => r.residual.calculated_band === 'high').length,
      flagged: m.risks.filter((r) => r.flags.length).length, controls: m.controls.length, effective: m.controls.filter((c) => c.eff.overall === 'effective').length,
      untested: m.gaps.controls_untested.length, kris_red: m.kris.filter((k) => k.status === 'red').length,
      acceptances_expired: m.acceptances.filter((a) => a.state === 'expired').length, acceptances_expiring: m.acceptances.filter((a) => a.state === 'expiring').length,
      losses_net_sar_12m: m.losses.filter((x) => now() - Date.parse(x.date) <= YEAR).reduce((a, x) => a + (x.gross || 0) - (x.recovered || 0), 0) };
    const base = { kpis, by_unit: m.by_unit, by_framework: m.by_framework.map((f) => ({ framework: f.framework, controls: f.controls, effective: f.effective, partial: f.partial, ineffective: f.ineffective, untested: f.untested })),
      method: 'Calculated residual = inherent x (1 - mitigation). Each linked control can remove up to ' + STRENGTH.primary * 100 + ' % (primary) or ' + STRENGTH.supporting * 100 + ' % (supporting) of the risk, times its effectiveness (effective 1, partial 0.5, ineffective / untested / unknown 0); combined as 1 - product(1 - each), capped at ' + CAP * 100 + ' %. A control nobody tested and no signal measures reduces nothing.' };
    if (who.role === 'viewer') return base;
    return Object.assign(base, m, { can_admin: who.role === 'admin', signal_names: SIGNALS, enums: { kinds: KINDS, types: TYPES, natures: NATURES, frequencies: FREQS, design: DESIGN, results: RESULTS, frameworks: FRAMEWORKS, loss_categories: LOSS_CATS, strengths: Object.keys(STRENGTH) } });
  }

  // ---- hierarchy
  function unitPut(input, who) {
    const b = body(input || {}).str('id', { max: 20 }).str('name', { required: true, max: 120 }).oneOf('kind', KINDS, { required: true }).str('parent', { max: 20 }).str('owner', { max: 120 }).done();
    person(who, 'changes the business hierarchy');
    const col = units(); const cur = b.id ? col.get(b.id) : null; if (b.id && !cur) throw httpErr(404, 'no unit ' + b.id);
    if (b.parent) { if (!col.get(b.parent)) throw httpErr(400, 'parent: no unit ' + b.parent); if (cur) { let p = b.parent; const seen = new Set(); while (p) { if (p === cur.id) throw httpErr(400, 'parent: a unit cannot sit under itself or its own sub-unit'); if (seen.has(p)) break; seen.add(p); p = (col.get(p) || {}).parent; } } }
    if (b.kind !== 'company' && !b.parent && col.all((u) => u.kind === 'company').length) throw httpErr(400, 'parent: a ' + b.kind + ' sits under another unit');
    const rec = Object.assign({}, cur || { id: nextId(col, 'BU'), created_by: who.user, created_at: iso() }, { name: b.name, kind: b.kind, parent: b.parent || '', owner: b.owner || '', updated_at: iso() });
    col.put(rec); audit(who, cur ? 'rc.unit.update' : 'rc.unit.create', rec.id, { name: rec.name, kind: rec.kind, parent: rec.parent });
    return rec;
  }
  function unitDelete(id, who) {
    person(who, 'changes the business hierarchy');
    const u = units().get(id); if (!u) throw httpErr(404, 'no unit ' + id);
    const used = [units().all((x) => x.parent === id).length && 'sub-units', meta().all((m) => m.unit === id).length && 'risks', controls().all((c) => c.unit === id).length && 'controls', losses().all((x) => x.unit === id).length && 'loss events'].filter(Boolean);
    if (used.length) throw httpErr(409, u.name + ' still has ' + used.join(', ') + ' - move them first');
    units().remove(id); audit(who, 'rc.unit.delete', id, { name: u.name });
    return { ok: true };
  }
  const unitOk = (id, f) => { if (id && !units().get(id)) throw httpErr(400, f + ': no business unit ' + id); };

  // ---- controls
  function controlPut(input, who) {
    const b = body(input || {}).str('id', { max: 20 }).str('title', { required: true, max: 200 }).str('description', { max: 2000 }).str('owner', { max: 120 }).str('unit', { max: 20 })
      .oneOf('type', TYPES, { required: true }).oneOf('nature', NATURES, { required: true }).oneOf('frequency', FREQS, { required: true }).str('policy', { max: 40 })
      .list('citations', { item: 'str', itemMax: 60, max: 40, unique: true }).str('signal', { max: 40 }).oneOf('design', DESIGN).done();
    person(who, 'changes the control library');
    unitOk(b.unit, 'unit');
    const badCite = (b.citations || []).find((x) => !CITE.test(x)); if (badCite) throw httpErr(400, 'citations: "' + badCite + '" - write it as FRAMEWORK:reference, e.g. SAMA:3.3.6, NCA:2-3-1, PDPL:Art. 19 (frameworks: ' + FRAMEWORKS.join(', ') + ')');
    if (b.signal && !SIGNALS[b.signal]) throw httpErr(400, 'signal: unknown - one of ' + Object.keys(SIGNALS).join(', '));
    if (b.policy) { const G = grc(); if (!(G && G.policy(b.policy))) throw httpErr(400, 'policy: no policy ' + b.policy + ' in the GRC register'); }
    const col = controls(); const cur = b.id ? col.get(b.id) : null; if (b.id && !cur) throw httpErr(404, 'no control ' + b.id);
    const rec = Object.assign({}, cur || { id: nextId(col, 'CTL'), created_by: who.user, created_at: iso() }, { title: b.title, description: b.description || '', owner: b.owner || '', unit: b.unit || '', type: b.type, nature: b.nature,
      frequency: b.frequency, policy: b.policy || '', citations: b.citations || [], signal: b.signal || '', design: b.design || (cur && cur.design) || 'not_rated', updated_at: iso(), updated_by: who.user });
    col.put(rec); audit(who, cur ? 'rc.control.update' : 'rc.control.create', rec.id, { title: rec.title, citations: rec.citations.length, signal: rec.signal || null, design: rec.design });
    return rec;
  }
  function importPolicies(who) {
    person(who, 'imports controls');
    const G = grc(); if (!G) throw httpErr(424, 'the GRC policy register is not available');
    const have = new Set(controls().all().map((c) => c.policy).filter(Boolean)), made = [];
    for (const p of G.register({}).items) {
      if (!/approved/i.test(p.status || '') || have.has(p.doc_id)) continue;
      const rec = { id: nextId(controls(), 'CTL'), title: 'Policy in force: ' + p.title, description: 'The requirements of ' + p.doc_id + ' are followed. Imported from the GRC policy register; refine the title, owner, type and frequency.',
        owner: p.owner || '', unit: '', type: 'preventive', nature: 'manual', frequency: 'annual', policy: p.doc_id, citations: p.sub_code ? ['SAMA:' + p.sub_code] : [], signal: '', design: 'not_rated', created_by: who.user, created_at: iso(), updated_at: iso(), updated_by: who.user };
      controls().put(rec); have.add(p.doc_id); made.push(rec.id);
    }
    audit(who, 'rc.control.import', 'grc-register', { created: made.length });
    return { created: made };
  }

  // ---- tests
  function testAdd(input, who) {
    const b = body(input || {}).str('control', { required: true, max: 20 }).oneOf('kind', ['design', 'operating'], { required: true }).oneOf('result', RESULTS, { required: true })
      .str('sample', { max: 500 }).str('evidence', { required: true, max: 2000 }).str('period', { max: 40 }).done();
    person(who, 'tests a control');
    const c = controls().get(b.control); if (!c) throw httpErr(400, 'control: no control ' + b.control);
    if (c.owner && low(c.owner) === low(who.user)) throw httpErr(403, 'independence: ' + who.user + ' owns ' + c.id + ' and cannot test it');
    const rec = { id: nextId(tests(), 'TST'), control: c.id, kind: b.kind, result: b.result, sample: b.sample || '', evidence: b.evidence, period: b.period || '', tester: who.user, at: iso(), action: null };
    if (b.result !== 'pass') {
      const R = registers();
      if (R) { try { rec.action = R.actionCreate({ title: ('Control ' + c.id + ' ' + b.kind + ' test ' + b.result + ': ' + c.title).slice(0, 200), source: 'control', ref: rec.id, framework: (c.citations[0] || '').split(':')[0] || '', priority: b.result === 'fail' ? 'high' : 'medium', owner: c.owner || '',
        due: new Date(now() + (b.result === 'fail' ? 30 : 60) * DAY).toISOString().slice(0, 10), description: 'Test ' + rec.id + ' by ' + who.user + ': ' + b.evidence.slice(0, 1500) }, who).id; }
      catch (e) { if (L.every) L.every('rc:action', 600000, 'warn', 'risk hub: the remediation action for a failed control test could not be raised', { test: rec.id, err: s(e.message, 160) }); rec.action_error = s(e.message, 160); } }
    }
    tests().put(rec); audit(who, 'rc.control.test', c.id, { test: rec.id, kind: rec.kind, result: rec.result, action: rec.action });
    return rec;
  }

  // ---- links, risk unit
  function link(input, who) {
    const b = body(input || {}).str('risk', { required: true, max: 20, re: RISK_ID, msg: 'risk must be a risk id (RSK-nnn)' }).str('control', { required: true, max: 20 }).oneOf('strength', Object.keys(STRENGTH)).bool('remove').done();
    person(who, 'links risks and controls');
    if (!C('grc_risks').get(b.risk)) throw httpErr(400, 'risk: no risk ' + b.risk + ' in the GRC risk register');
    if (!controls().get(b.control)) throw httpErr(400, 'control: no control ' + b.control);
    const id = b.risk + '~' + b.control;
    if (b.remove) { if (!links().get(id)) throw httpErr(404, 'not linked'); links().remove(id); audit(who, 'rc.link.remove', id, {}); return { ok: true, removed: id }; }
    const rec = { id, risk: b.risk, control: b.control, strength: b.strength || 'supporting', by: who.user, at: iso() };
    links().put(rec); audit(who, 'rc.link', id, { strength: rec.strength });
    return rec;
  }
  function riskUnit(id, input, who) {
    const b = body(input || {}).str('unit', { max: 20 }).done();
    person(who, 'places a risk');
    if (!C('grc_risks').get(id)) throw httpErr(404, 'no risk ' + id);
    unitOk(b.unit, 'unit');
    meta().put({ id, unit: b.unit || '', by: who.user, at: iso() }); audit(who, 'rc.risk.unit', id, { unit: b.unit || null });
    return { ok: true, risk: id, unit: b.unit || '' };
  }

  // ---- KRIs
  function kriPut(input, who) {
    const b = body(input || {}).str('id', { max: 20 }).str('risk', { required: true, max: 20, re: RISK_ID, msg: 'risk must be a risk id (RSK-nnn)' }).str('name', { required: true, max: 160 })
      .str('measure', { required: true, max: 40 }).oneOf('direction', ['higher_worse', 'lower_worse'], { required: true }).num('amber', { required: true }).num('red', { required: true }).str('signal', { max: 40 })
      .rule((o) => (o.direction === 'higher_worse' ? o.red < o.amber : o.red > o.amber) ? 'red: when ' + (o.direction === 'higher_worse' ? 'higher is worse, red must be at or above amber' : 'lower is worse, red must be at or below amber') : null).done();
    person(who, 'defines key risk indicators');
    if (!C('grc_risks').get(b.risk)) throw httpErr(400, 'risk: no risk ' + b.risk);
    if (b.signal && !SIGNALS[b.signal]) throw httpErr(400, 'signal: unknown');
    const col = kris(); const cur = b.id ? col.get(b.id) : null; if (b.id && !cur) throw httpErr(404, 'no KRI ' + b.id);
    const rec = Object.assign({}, cur || { id: nextId(col, 'KRI'), history: [], created_by: who.user, created_at: iso() }, { risk: b.risk, name: b.name, measure: b.measure, direction: b.direction, amber: b.amber, red: b.red, signal: b.signal || '' });
    col.put(rec); audit(who, cur ? 'rc.kri.update' : 'rc.kri.create', rec.id, { risk: rec.risk, amber: rec.amber, red: rec.red });
    return rec;
  }
  function kriValue(id, input, who) {
    const b = body(input || {}).num('value', { required: true }).str('note', { max: 300 }).done();
    person(who, 'records a KRI value');
    const k = kris().get(id); if (!k) throw httpErr(404, 'no KRI ' + id);
    if (k.signal) throw httpErr(409, k.id + ' is read from a signal - its value is not typed');
    const worse = (a, x) => k.direction === 'lower_worse' ? a <= x : a >= x;
    const status = worse(b.value, k.red) ? 'red' : worse(b.value, k.amber) ? 'amber' : 'green';
    k.history = (k.history || []).concat([{ at: iso(), value: b.value, note: b.note || '', by: who.user }]).slice(-60); kris().put(k);
    audit(who, 'rc.kri.value', id, { value: b.value, status });
    if (status === 'red') audit(who, 'rc.kri.breach', id, { risk: k.risk, value: b.value, red: k.red });
    return { ok: true, id, status };
  }

  // ---- loss events
  function lossAdd(input, who) {
    const b = body(input || {}).date('date', { required: true }).str('unit', { max: 20 }).str('risk', { max: 20, re: RISK_ID, msg: 'risk must be a risk id (RSK-nnn)' }).list('controls', { item: 'str', itemMax: 20, max: 20, unique: true })
      .oneOf('category', LOSS_CATS, { required: true }).num('gross', { required: true, min: 0, max: 1e12 }).num('recovered', { min: 0, max: 1e12 }).str('description', { required: true, max: 2000 })
      .rule((o) => (o.recovered || 0) > o.gross ? 'recovered: cannot exceed the gross loss' : null).done();
    person(who, 'records a loss event');
    if (Date.parse(b.date) > now() + DAY) throw httpErr(400, 'date: a loss event cannot be in the future');
    unitOk(b.unit, 'unit');
    if (b.risk && !C('grc_risks').get(b.risk)) throw httpErr(400, 'risk: no risk ' + b.risk);
    const miss = (b.controls || []).find((c) => !controls().get(c)); if (miss) throw httpErr(400, 'controls: no control ' + miss);
    const rec = { id: nextId(losses(), 'LOSS'), date: b.date, unit: b.unit || '', risk: b.risk || '', controls: b.controls || [], category: b.category, gross: b.gross, recovered: b.recovered || 0, description: b.description, by: who.user, at: iso() };
    losses().put(rec); audit(who, 'rc.loss', rec.id, { gross: rec.gross, recovered: rec.recovered, risk: rec.risk || null, category: rec.category });
    return rec;
  }

  return { view, unitPut, unitDelete, controlPut, importPolicies, testAdd, link, riskUnit, kriPut, kriValue, lossAdd, SIGNALS, _model: model };
}

function registerRiskControl(srv, app, R) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  const ID = (ctx) => param(ctx.params.id, 'id');
  srv.route('GET', '/rc', (ctx) => { ctx.need('viewer'); return R.view(W(ctx)); });
  srv.route('POST', '/rc/units', (ctx) => { ctx.need('admin'); return R.unitPut(ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/rc/units/:id/delete', (ctx) => { ctx.need('admin'); return R.unitDelete(ID(ctx), W(ctx)); });
  srv.route('POST', '/rc/controls', (ctx) => { ctx.need('operator'); return R.controlPut(ctx.body, W(ctx)); }, { maxBody: 16384 });
  srv.route('POST', '/rc/controls/import-policies', (ctx) => { ctx.need('admin'); return R.importPolicies(W(ctx)); });
  srv.route('POST', '/rc/tests', (ctx) => { ctx.need('operator'); return R.testAdd(ctx.body, W(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/rc/links', (ctx) => { ctx.need('operator'); return R.link(ctx.body, W(ctx)); }, { maxBody: 2048 });
  srv.route('POST', '/rc/risks/:id/unit', (ctx) => { ctx.need('operator'); return R.riskUnit(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 1024 });
  srv.route('POST', '/rc/kris', (ctx) => { ctx.need('operator'); return R.kriPut(ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/rc/kris/:id/value', (ctx) => { ctx.need('operator'); return R.kriValue(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 2048 });
  srv.route('POST', '/rc/losses', (ctx) => { ctx.need('operator'); return R.lossAdd(ctx.body, W(ctx)); }, { maxBody: 8192 });
}

module.exports = { createRiskControl, registerRiskControl };
