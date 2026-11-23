// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IT budget for the next fiscal year, built from what the platform already knows plus last year's pending items.
//   GET  /budget                     {settings, fy, envelopes[], lines[], summary, previous{fy, rows, carried}}  operator
//   POST /budget/previous            {fy, rows[]}  last year's budget lines (the page reads the CSV / Excel export)  admin
//   POST /budget/lines               {id?, title, envelope, area, kind, amount, priority, due?, justification}       admin
//   POST /budget/lines/:id/decide    {status: proposed|approved|deferred|rejected, amount?, priority?, note}         admin
//   POST /budget/lines/:id/delete    a manual requirement only                                                       admin
//   PUT  /budget/settings            {fy, currency, envelopes{it_ops, cyber}, unit_costs{}, support_pct, inflation_pct} admin
//   POST /budget/previous            also {fy, xlsx_b64, filename}: last year's budget as an Excel workbook               admin
//   POST /budget/import              {xlsx_b64, filename, apply}: the Excel round trip - the page exports the budget (sheet
//                                    "Budget", one row per line with its Line ID), people edit amount / priority / status /
//                                    note and add rows in Excel, and the workbook comes back. apply=false answers what would
//                                    change and every row's error; apply=true applies all of it or nothing           admin, a person
//   POST /budget/rollover/reviewed   an administrator has checked the carry-over the year-end rollover made              admin, a person
// Year-end rollover (background job budget.rollover, also run at start-up): once the saved fiscal year has ended, that year is
// archived (budget_years), its approved and deferred lines with their actual spend from Budget execution become "last year"
// (the carry-over source), and planning moves to the next year with the same envelopes and standard costs. An import an
// administrator already made for that year is kept, not overwritten. Until an administrator marks the carry-over reviewed,
// Notification & Escalation shows it (source "budget"). Audited as system:budget-rollover.
// Envelopes (defaults; edited on the page): IT Operations (Infrastructure + Applications) 66,000,000 and Cyber
// Security 30,000,000, each line CAPEX or OPEX.
// Lines are GENERATED every time the page is read - so they follow the inventory - from:
//   carry-over  last year's lines still pending / in progress: approved minus spent (cancelled and completed lines drop)
//   licence     active licences expiring before the end of the next fiscal year: renewal at the licence's cost (OPEX)
//   support     servers, storage and network devices whose warranty ends by then: support renewal = purchase cost x
//               support_pct, or the standard support cost for the type (OPEX)
//   eol         assets whose OS / firmware reaches end of support by then: replacement at the asset's own purchase cost,
//               or the standard cost for the type (CAPEX); an EOL OS on a VM is an OS upgrade (standard cost os_upgrade).
//               An asset being replaced gets no support renewal line (it would be counted twice).
//   storage     arrays at or above the warning level: capacity to bring them back to 70 % used x cost per TB (CAPEX)
//   manual      requirements and projects an administrator adds
// NOTHING IS PRICED BY GUESS: an amount comes from the licence, the asset's purchase record or a standard cost set on the
// page; otherwise the line says "price needed" and is counted separately (never as 0, never as an invented figure).
// Security products and firewalls go to the Cyber Security envelope (word-bounded vendor / product list below).
// Fit: per envelope, lines are ranked must > should > could, then by due date, and the running total is compared with
// the envelope; lines past it are marked "does not fit" - a proposal, the decision stays with an administrator.
// Every decision, import and settings change is audited. Self-contained (stored collections), added with one
// registration line (install/add-budget.sh).
const crypto = require('node:crypto');
const { body, fileCheck } = require('./check');
const { readXlsx } = require('./xlsx-read');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');

const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const KINDS = ['capex', 'opex'], PRIOS = ['must', 'should', 'could'], STATUSES = ['proposed', 'approved', 'deferred', 'rejected'];
const AREAS = { it_ops: ['infrastructure', 'applications'], cyber: ['security'] };
const PR = { must: 0, should: 1, could: 2 };
const SECURITY = /\b(kaspersky|fortinet|forti(gate|analyzer|manager|mail|web|siem|edr|nac|token|authenticator|client)|palo ?alto|panorama|prisma|cortex|crowdstrike|sentinel ?one|splunk|qradar|arcsight|wazuh|defender|sentinel|tenable|nessus|qualys|rapid7|ise|duo|okta|cyberark|beyondtrust|thycotic|imperva|darktrace|trend ?micro|sophos|symantec|mcafee|trellix|proofpoint|mimecast|zscaler|cloudflare|varonis|thales|safenet|entrust|digicert|sectigo|knowbe4|checkpoint|check point|barracuda|f5 asm|waf|siem|soc|edr|xdr|dlp|pam|mfa|vpn|firewall|antivirus|anti-virus|email security|vulnerability)\b/i;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n || 300);
const d10 = (v) => (v ? String(v).slice(0, 10) : null);   // records keep full ISO timestamps; the budget works in days
const money = (v) => { if (v == null || v === '') return null; const n = Number(String(v).replace(/[,\s]/g, '').replace(/^(sar|sr|ر\.س)/i, '')); return Number.isFinite(n) && n >= 0 ? Math.round(n * 100) / 100 : null; };
const DEFAULTS = {
  fy: null, currency: 'SAR', envelopes: { it_ops: 66000000, cyber: 30000000 },
  // standard costs are EMPTY until someone sets them: an unpriced line is shown as "price needed", never estimated
  unit_costs: { server: null, workstation: null, network: null, firewall: null, storage: null, printer: null, phone: null, os_upgrade: null, storage_tb: null, support_server: null, support_storage: null, support_network: null },
  support_pct: null, inflation_pct: 0, storage_target_pct: 70, storage_warn_pct: 85,
};

function isSecurity(...txt) { return SECURITY.test(txt.filter(Boolean).join(' ')); }
function isFirewall(a) { return a && (a.type === 'network' || a.type === 'firewall') && (/firewall|fortigate|palo|\bpa-\d|checkpoint|sophos xg|asa\b/i.test([a.model, a.vendor, a.name, (a.tags || []).join(' '), a.discovery && a.discovery.class].join(' '))); }

function createBudget(app, opts = {}) {
  const { store } = app;
  const conf = store.collection('budget_settings'), prev = store.collection('budget_previous'), lines = store.collection('budget_lines'), assets = store.collection('assets');
  const years = store.collection('budget_years');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;

  function settings() {
    const v = (conf.get('settings') || {}).values || {};
    const o = Object.assign({}, DEFAULTS, v, { envelopes: Object.assign({}, DEFAULTS.envelopes, v.envelopes || {}), unit_costs: Object.assign({}, DEFAULTS.unit_costs, v.unit_costs || {}) });
    if (!o.fy) o.fy = new Date(now()).getUTCFullYear() + 1;   // Saudi government / most company fiscal years = calendar year
    return o;
  }
  const fyEnd = (fy) => `${fy}-12-31`, fyStart = (fy) => `${fy}-01-01`;
  const inflate = (n, st) => (n == null ? null : Math.round(n * (1 + (Number(st.inflation_pct) || 0) / 100) * 100) / 100);

  // ---- generators ------------------------------------------------------------------------------------------------
  function carryOver(st) {
    const p = prev.get('current');
    if (!p) return [];
    return (p.rows || []).filter((r) => !/^(completed|closed|done|cancel)/i.test(r.status || '')).map((r, i) => {
      const remaining = r.approved == null ? null : Math.max(0, (r.approved || 0) - (r.spent || 0));
      if (remaining === 0) return null;
      const env = r.envelope || (isSecurity(r.title, r.vendor, r.area) ? 'cyber' : 'it_ops');
      return { id: `carry:${p.fy}:${r.key || i}`, source: 'carryover', envelope: env, area: AREAS[env].includes(r.area) ? r.area : AREAS[env][0], kind: r.kind || 'opex', title: r.title,
        amount: remaining, priced: remaining != null, basis: remaining == null ? 'last year\'s approved amount missing' : `FY${p.fy} approved ${fmt(r.approved)} - spent ${fmt(r.spent || 0)}`,
        reason: `pending from FY${p.fy}${r.status ? ' (' + r.status + ')' : ''}${r.vendor ? ' · ' + r.vendor : ''}`, priority: /commit|progress|po|contract/i.test(r.status || '') ? 'must' : 'should', due: fyStart(st.fy), ref: null };
    }).filter(Boolean);
  }
  function licences(st) {
    const out = [];
    for (const l of store.collection('licences').all((x) => x.status !== 'inactive')) {
      const exp = d10(l.expiry);
      if (!exp || exp > fyEnd(st.fy)) continue;
      const env = isSecurity(l.product, l.publisher, l.notes) ? 'cyber' : 'it_ops';
      const amt = inflate(money(l.cost), st);
      out.push({ id: `lic:${l.id}:${st.fy}`, source: 'licence', envelope: env, area: env === 'cyber' ? 'security' : 'applications', kind: 'opex', title: `Renewal: ${l.product}${l.seats ? ' (' + l.seats + ' seats)' : ''}`,
        amount: amt, priced: amt != null, basis: amt == null ? 'licence has no cost recorded' : `licence cost ${fmt(l.cost)}${st.inflation_pct ? ' + ' + st.inflation_pct + '%' : ''}`,
        reason: `expires ${exp}${exp < fyStart(st.fy) ? ' (before the year starts - renew now)' : ''}`, priority: 'must', due: exp < fyStart(st.fy) ? fyStart(st.fy) : exp, ref: { licence: l.id } });
    }
    return out;
  }
  function eolItems(st) {
    let L; try { L = require('./lifecycle'); } catch { return { lines: [], replaced: new Set() }; }
    const rules = L.compile((((app.config || {}).discovery || {}).lifecycle || {}).rules), replaced = new Set(), out = [];
    for (const a of assets.all((x) => !CLOSED[x.status])) {
      const txt = [a.os, a.os_version, a.firmware, a.sys_descr, a.model].filter(Boolean).join(' · ');
      const e = L.evaluate(txt, rules, now());
      const eolD = d10(e.eol);
      if (e.status !== 'eol' && !(e.status === 'soon' && eolD && eolD <= fyEnd(st.fy))) continue;
      const vm = a.type === 'vm', fw = isFirewall(a), env = fw || isSecurity(a.model, a.vendor) && a.type === 'network' ? 'cyber' : 'it_ops';
      let amt = null, basis;
      if (vm) { amt = inflate(money(st.unit_costs.os_upgrade), st); basis = amt == null ? 'set the standard cost "OS upgrade"' : 'standard cost: OS upgrade'; }
      else if (a.purchase && money(a.purchase.cost) != null) { amt = inflate(money(a.purchase.cost), st); basis = `original purchase cost ${fmt(a.purchase.cost)}${a.purchase.date ? ' (' + a.purchase.date.slice(0, 4) + ')' : ''}`; }
      else { const k = fw ? 'firewall' : a.type; amt = inflate(money(st.unit_costs[k]), st); basis = amt == null ? `set the standard cost for "${k}"` : `standard cost: ${k}`; }
      if (!vm) replaced.add(a.id);
      out.push({ id: `eol:${a.id}:${st.fy}`, source: 'eol', envelope: env, area: env === 'cyber' ? 'security' : 'infrastructure', kind: 'capex',
        title: `${vm ? 'OS upgrade' : 'Replace'}: ${a.name || a.asset_tag || a.mgmt_ip || a.id}${e.product ? ' (' + e.product + ')' : ''}`, amount: amt, priced: amt != null, basis,
        reason: eolD ? `end of support ${eolD}` : 'end of support has passed', priority: e.status === 'eol' ? 'must' : 'should', due: eolD && eolD > fyStart(st.fy) ? eolD : fyStart(st.fy), ref: { asset: a.id } });
    }
    return { lines: out, replaced };
  }
  function support(st, replaced) {
    const out = [];
    for (const a of assets.all((x) => !CLOSED[x.status] && ['server', 'storage', 'network', 'firewall'].includes(x.type))) {
      const end = d10(a.warranty && a.warranty.end);
      if (!end || end > fyEnd(st.fy)) continue;
      if (replaced.has(a.id)) continue;   // being replaced: no support renewal
      const fw = isFirewall(a), env = fw ? 'cyber' : 'it_ops', key = a.type === 'storage' ? 'support_storage' : a.type === 'server' ? 'support_server' : 'support_network';
      let amt = null, basis;
      if (st.support_pct != null && a.purchase && money(a.purchase.cost) != null) { amt = inflate(Math.round(money(a.purchase.cost) * st.support_pct) / 100, st); basis = `${st.support_pct}% of purchase cost ${fmt(a.purchase.cost)}`; }
      else { amt = inflate(money(st.unit_costs[key]), st); basis = amt == null ? `set "support %" or the standard cost "${key.replace('_', ' ')}"` : `standard cost: ${key.replace('_', ' ')}`; }
      out.push({ id: `sup:${a.id}:${st.fy}`, source: 'support', envelope: env, area: env === 'cyber' ? 'security' : 'infrastructure', kind: 'opex',
        title: `Support renewal: ${a.name || a.asset_tag || a.id}${a.warranty.provider ? ' (' + a.warranty.provider + ')' : ''}`, amount: amt, priced: amt != null, basis,
        reason: `warranty ends ${end}`, priority: 'must', due: end < fyStart(st.fy) ? fyStart(st.fy) : end, ref: { asset: a.id } });
    }
    return out;
  }
  function storageGrowth(st) {
    const out = [];
    const snap = store.collection('storage_snapshots');
    for (const p of store.collection('storage_platforms').all()) {
      const d = snap.get(p.id); if (!d || !Array.isArray(d.pools)) continue;
      const size = d.pools.reduce((n, x) => n + (x.size_bytes || 0), 0), used = d.pools.reduce((n, x) => n + (x.used_bytes || 0), 0);
      if (!size || used / size * 100 < st.storage_warn_pct) continue;
      const needTb = Math.ceil((used / (st.storage_target_pct / 100) - size) / 1e12);
      if (needTb <= 0) continue;
      const per = money(st.unit_costs.storage_tb), amt = per == null ? null : inflate(per * needTb, st);
      out.push({ id: `stor:${p.id}:${st.fy}`, source: 'storage', envelope: 'it_ops', area: 'infrastructure', kind: 'capex', title: `Storage expansion: ${p.label} (+${needTb} TB)`,
        amount: amt, priced: amt != null, basis: amt == null ? 'set the standard cost "storage per TB"' : `${needTb} TB x ${fmt(per)} per TB`,
        reason: `${Math.round(used / size * 1000) / 10}% used (warning at ${st.storage_warn_pct}%, target ${st.storage_target_pct}%)`, priority: used / size >= 0.95 ? 'must' : 'should', due: fyStart(st.fy), ref: { storage: p.id } });
    }
    return out;
  }
  function manual(st) { return lines.all((l) => l.source === 'manual' && l.fy === st.fy).map((l) => Object.assign({}, l, { priced: l.amount != null })); }

  // ---- assemble + fit ---------------------------------------------------------------------------------------------
  function build() {
    const st = settings();
    const eol = eolItems(st);
    let list = [].concat(carryOver(st), licences(st), eol.lines, support(st, eol.replaced), storageGrowth(st), manual(st));
    const dec = new Map(lines.all((l) => l.source !== 'manual').map((l) => [l.id, l]));
    list = list.map((l) => {
      const d = dec.get(l.id) || (l.source === 'manual' ? l : null);
      const o = Object.assign({ status: 'proposed' }, l);
      if (d && l.source !== 'manual') { o.status = d.status || 'proposed'; if (d.amount != null) { o.amount_generated = l.amount; o.amount = d.amount; o.priced = true; o.basis = `set by ${d.decided_by} (was ${l.amount == null ? 'unpriced' : fmt(l.amount)})`; } if (d.priority) o.priority = d.priority; o.note = d.note || null; o.decided_by = d.decided_by; o.decided_at = d.decided_at; }
      return o;
    });
    const envelopes = Object.keys(AREAS).map((env) => {
      const own = list.filter((l) => l.envelope === env && l.status !== 'rejected' && l.status !== 'deferred')
        .sort((a, b) => (a.status === 'approved' ? -1 : 0) - (b.status === 'approved' ? -1 : 0) || PR[a.priority] - PR[b.priority] || String(a.due || '').localeCompare(String(b.due || '')));
      let run = 0;
      const cap = Number(st.envelopes[env]) || 0;
      for (const l of own) { if (!l.priced) { l.fit = 'unpriced'; continue; } run += l.amount; l.fit = run <= cap ? 'fits' : 'over'; l.running = Math.round(run * 100) / 100; }
      const sum = (f) => Math.round(own.filter(f).reduce((n, l) => n + (l.priced ? l.amount : 0), 0) * 100) / 100;
      return {
        id: env, name: env === 'cyber' ? 'Cyber Security' : 'IT Operations (Infrastructure & Applications)', envelope: cap,
        proposed: sum(() => true), capex: sum((l) => l.kind === 'capex'), opex: sum((l) => l.kind === 'opex'), approved: sum((l) => l.status === 'approved'),
        by_area: AREAS[env].map((a) => ({ area: a, capex: sum((l) => l.area === a && l.kind === 'capex'), opex: sum((l) => l.area === a && l.kind === 'opex') })),
        by_source: [...new Set(own.map((l) => l.source))].map((src) => ({ source: src, amount: sum((l) => l.source === src), lines: own.filter((l) => l.source === src).length })),
        headroom: Math.round((cap - sum(() => true)) * 100) / 100, unpriced: own.filter((l) => !l.priced).length, over: own.filter((l) => l.fit === 'over').length,
      };
    });
    list.sort((a, b) => a.envelope.localeCompare(b.envelope) || (a.status === 'rejected') - (b.status === 'rejected') || PR[a.priority] - PR[b.priority] || String(a.due || '').localeCompare(String(b.due || '')));
    const p = prev.get('current');
    return {
      settings: st, fy: st.fy, currency: st.currency, envelopes, lines: list,
      summary: { lines: list.length, unpriced: list.filter((l) => !l.priced && l.status !== 'rejected').length, total: envelopes.reduce((n, e) => n + e.proposed, 0), envelope_total: envelopes.reduce((n, e) => n + e.envelope, 0), capex: envelopes.reduce((n, e) => n + e.capex, 0), opex: envelopes.reduce((n, e) => n + e.opex, 0) },
      previous: p ? { fy: p.fy, rows: (p.rows || []).length, imported_by: p.by, imported_at: p.at, approved: p.rows.reduce((n, r) => n + (r.approved || 0), 0), spent: p.rows.reduce((n, r) => n + (r.spent || 0), 0),
        auto: !!p.auto, review: p.review || null, file: p.file || null } : null,
      closed_years: years.all().map((y) => ({ fy: y.fy, closed_at: y.closed_at, lines: (y.lines || []).length, approved: y.approved })).sort((a, b) => b.fy - a.fy),
    };
  }
  const fmt = (n) => (n == null ? '-' : Number(n).toLocaleString('en-US', { maximumFractionDigits: 2 }));

  // ---- writes ------------------------------------------------------------------------------------------------------
  function normRow(r, i) {
    const env = /cyber|secur/i.test(r.envelope || r.budget || r.department || '') ? 'cyber' : /it|oper|infra|app/i.test(r.envelope || r.budget || r.department || '') ? 'it_ops' : null;
    const area = /app/i.test(r.area || r.category || '') ? 'applications' : /infra|network|server|storage|data ?cent/i.test(r.area || r.category || '') ? 'infrastructure' : /secur|cyber/i.test(r.area || r.category || '') ? 'security' : '';
    const kind = /cap/i.test(r.kind || r.type || r.capex_opex || '') ? 'capex' : /op/i.test(r.kind || r.type || r.capex_opex || '') ? 'opex' : null;
    const title = s(r.title || r.item || r.description || r.name, 200);
    if (!title) return null;
    return { key: s(r.id || r.ref || '', 60) || String(i + 1), title, envelope: env, area, kind, approved: money(r.approved != null ? r.approved : r.budget_amount != null ? r.budget_amount : r.amount), spent: money(r.spent != null ? r.spent : r.actual), status: s(r.status, 40), vendor: s(r.vendor || r.supplier, 120) || null };
  }
  function importPrevious(b, who) {
    const fy = Number(b.fy);
    if (!Number.isInteger(fy) || fy < 2000 || fy > 2100) throw bad('fy must be the year of the budget being imported, e.g. 2026');
    if (!Array.isArray(b.rows) || !b.rows.length || b.rows.length > 5000) throw bad('rows must be a list of 1-5000 budget lines');
    const rows = b.rows.map(normRow).filter(Boolean);
    if (!rows.length) throw bad('no usable rows: each needs a title / item / description');
    const noKind = rows.filter((r) => !r.kind).length;
    rows.forEach((r) => { if (!r.kind) r.kind = 'opex'; });
    prev.put({ id: 'current', fy, rows, by: who.user, at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.import_previous', target: `FY${fy}`, detail: { rows: rows.length, skipped: b.rows.length - rows.length, no_kind: noKind } });
    return { imported: rows.length, skipped: b.rows.length - rows.length, assumed_opex: noKind, budget: build() };
  }
  function saveLine(b, who) {
    const st = settings();
    const env = AREAS[b.envelope] ? b.envelope : null; if (!env) throw bad('envelope must be it_ops or cyber');
    const area = AREAS[env].includes(b.area) ? b.area : AREAS[env][0];
    if (!KINDS.includes(b.kind)) throw bad('kind must be capex or opex');
    const title = s(b.title, 200); if (title.length < 3) throw bad('a title is required');
    const amount = money(b.amount); if (b.amount != null && b.amount !== '' && amount == null) throw bad('amount must be a number');
    const id = b.id && String(b.id).startsWith('man:') ? String(b.id) : `man:${crypto.randomBytes(5).toString('hex')}`;
    const cur = lines.get(id);
    const rec = Object.assign({}, cur || {}, { id, fy: st.fy, source: 'manual', envelope: env, area, kind: b.kind, title, amount, basis: amount == null ? 'price needed' : 'entered by ' + who.user,
      reason: s(b.justification, 500) || 'new requirement', priority: PRIOS.includes(b.priority) ? b.priority : 'should', due: /^\d{4}-\d{2}-\d{2}$/.test(b.due || '') ? b.due : fyStart(st.fy), status: (cur && cur.status) || 'proposed', ref: null,
      created_by: (cur && cur.created_by) || who.user, created_at: (cur && cur.created_at) || new Date(now()).toISOString(), updated_by: who.user });
    lines.put(rec);
    audit({ by: who.user, role: who.role, ip: who.ip, action: cur ? 'budget.line_update' : 'budget.line_add', target: id, detail: { title, envelope: env, kind: b.kind, amount } });
    return build();
  }
  function decide(id, b, who) {
    id = String(id || '');
    const cur = build().lines.find((l) => l.id === id);
    if (!cur) throw bad('line not found', 404);
    if (b.status && !STATUSES.includes(b.status)) throw bad('status must be proposed, approved, deferred or rejected');
    if ((b.status === 'rejected' || b.status === 'deferred') && s(b.note, 300).length < 3) throw bad('give a reason for rejecting or deferring (min 3 characters)');
    const amount = b.amount === undefined || b.amount === '' ? undefined : money(b.amount);
    if (b.amount !== undefined && b.amount !== '' && amount == null) throw bad('amount must be a number');
    if (b.status === 'approved' && !cur.priced && amount == null) throw bad('this line has no price - enter the amount to approve it');
    recordDecision(cur, b, amount, who, 'budget.decide');
    return build();
  }
  // one decision on a line (the page's dialog, or a row of an imported workbook): stored with its history, audited
  function recordDecision(cur, b, amount, who, action, extra) {
    const id = cur.id, prevRec = lines.get(id) || {};
    const rec = Object.assign({}, prevRec, cur.source === 'manual' ? {} : { id, source: cur.source }, {
      status: b.status || prevRec.status || 'proposed', priority: PRIOS.includes(b.priority) ? b.priority : prevRec.priority, note: s(b.note, 300) || prevRec.note || null,
      decided_by: who.user, decided_at: new Date(now()).toISOString(), history: (prevRec.history || []).concat({ at: new Date(now()).toISOString(), by: who.user, status: b.status || null, amount: amount === undefined ? null : amount, note: s(b.note, 300) || null }).slice(-20) });
    if (amount !== undefined) rec.amount = amount;
    lines.put(rec);
    audit({ by: who.user, role: who.role, ip: who.ip, action, target: id, detail: Object.assign({ title: cur.title, status: rec.status, amount: amount === undefined ? cur.amount : amount, note: rec.note }, extra || {}) });
  }
  function remove(id, who) {
    const cur = lines.get(String(id || ''));
    if (!cur || cur.source !== 'manual') throw bad('only a requirement added by hand can be deleted - reject a generated line instead', 400);
    lines.remove(cur.id);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.line_delete', target: cur.id, detail: { title: cur.title, amount: cur.amount } });
    return build();
  }
  function putSettings(b, who) {
    const v = settings();
    if ('fy' in b) { const fy = Number(b.fy); if (!Number.isInteger(fy) || fy < 2000 || fy > 2100) throw bad('fy must be a year'); v.fy = fy; }
    if ('currency' in b) { const c = s(b.currency, 8).toUpperCase(); if (!/^[A-Z]{3}$/.test(c)) throw bad('currency must be a 3-letter code'); v.currency = c; }
    if (b.envelopes) for (const k of Object.keys(AREAS)) if (k in b.envelopes) { const n = money(b.envelopes[k]); if (n == null) throw bad(`envelope ${k} must be a number`); v.envelopes[k] = n; }
    if (b.unit_costs) for (const k of Object.keys(DEFAULTS.unit_costs)) if (k in b.unit_costs) { const raw = b.unit_costs[k]; const n = raw === '' || raw === null ? null : money(raw); if (raw !== '' && raw !== null && n == null) throw bad(`standard cost ${k} must be a number`); v.unit_costs[k] = n; }
    for (const [k, lo, hi] of [['support_pct', 0, 100], ['inflation_pct', -50, 100], ['storage_target_pct', 30, 95], ['storage_warn_pct', 50, 100]]) if (k in b) {
      if (b[k] === '' || b[k] === null) { if (k === 'support_pct') { v[k] = null; continue; } throw bad(`${k} is required`); }
      const n = Number(b[k]); if (!Number.isFinite(n) || n < lo || n > hi) throw bad(`${k} must be ${lo}-${hi}`); v[k] = n;
    }
    conf.put({ id: 'settings', values: v, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.settings', target: 'settings', detail: v });
    return build();
  }
  // ---- Excel ------------------------------------------------------------------------------------------------------
  const ENV_IN = (v) => { const t = String(v || '').trim().toLowerCase(); return t === 'cyber' || /cyber|secur/.test(t) ? 'cyber' : t === 'it_ops' || /it op|operation|infra|applic/.test(t) ? 'it_ops' : null; };
  const AREA_IN = (v) => { const t = String(v || '').trim().toLowerCase(); return /app/.test(t) ? 'applications' : /infra/.test(t) ? 'infrastructure' : /secur|cyber/.test(t) ? 'security' : null; };
  const key = (h) => String(h || '').replace(/^\ufeff/, '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
  // a workbook as uploaded by the page (base64): checked as a real .xlsx, size-capped, first worksheet read, formulas never run
  function workbook(input) {
    const b = body(input).str('xlsx_b64', { required: true, max: 11200000 }).str('filename', { max: 200, def: 'budget.xlsx' }).done();
    if (!/^[A-Za-z0-9+/=]+$/.test(b.xlsx_b64)) throw bad('xlsx_b64: the file content is not base64');
    const buf = Buffer.from(b.xlsx_b64, 'base64');
    const fc = fileCheck(b.filename, buf, { allow: ['xlsx'], max: 8 * 1024 * 1024 });
    const X = readXlsx(buf, { maxRows: 5000, maxCols: 40 });
    if (X.truncated) throw bad('the workbook has more than 5000 rows - split it');
    const rows = X.rows.map((r) => { const o = {}; for (const [k, v] of Object.entries(r)) { const kk = key(k); if (kk && !(kk in o)) o[kk] = String(v == null ? '' : v).trim(); } return o; });
    return { rows, fields: X.fields.map(key), file: fc.name, sha256: crypto.createHash('sha256').update(buf).digest('hex'), bytes: buf.length };
  }
  function importPreviousXlsx(input, who) {
    const b = body(input).int('fy', { required: true, min: 2000, max: 2100 }).done();
    const W = workbook(input);
    if (!W.rows.length) throw bad('the workbook has headings but no rows');
    return { fy: b.fy, rows: W.rows, file: W.file, sha256: W.sha256 };
  }
  // the round trip: compare every row of the workbook with the budget as it is now. Nothing is written unless apply is true and
  // every row is valid - a half-applied budget would be worse than none
  function importWorkbook(input, who) {
    const opt = body({ apply: input && input.apply }).bool('apply', { def: false }).done();
    if (opt.apply && !isHuman(who && who.user)) throw bad('a service or AI identity cannot change the budget: a person applies the workbook', 403);
    const W = workbook(input);
    if (!W.fields.includes('title')) throw bad('the workbook has no "Title" column - export the budget from this page and edit that file');
    const B = build(), byId = new Map(B.lines.map((l) => [l.id, l])), fy = B.fy, changes = [], errors = [], seen = new Set();
    let unchanged = 0;
    W.rows.forEach((r, i) => {
      const row = i + 2, err = (m) => errors.push({ row, msg: m });
      if (r.fy && Number(r.fy) !== fy) return err(`FY ${s(r.fy, 10)} is not the budget being planned (FY${fy}) - export FY${fy} again`);
      const id = s(r.line_id, 80);
      const amount = r.amount === undefined || r.amount === '' ? undefined : money(r.amount);
      if (r.amount && amount == null) return err(`Amount "${s(r.amount, 30)}" is not a number`);
      const status = r.status ? r.status.toLowerCase() : undefined, priority = r.priority ? r.priority.toLowerCase() : undefined;
      if (status && !STATUSES.includes(status)) return err(`Status must be proposed, approved, deferred or rejected (not "${s(r.status, 30)}")`);
      if (priority && !PRIOS.includes(priority)) return err(`Priority must be must, should or could (not "${s(r.priority, 30)}")`);
      const note = s(r.note, 300);
      if (r.due && !/^\d{4}-\d{2}-\d{2}$/.test(r.due.slice(0, 10))) return err(`Due must be a date (YYYY-MM-DD), not "${s(r.due, 30)}"`);
      if (!id) {   // a new requirement written in Excel
        const title = s(r.title, 200); if (title.length < 3) return r.title ? err('Title needs at least 3 characters') : undefined;   // an empty row: nothing to do
        // the same workbook imported twice must not add its new rows twice
        const tl = title.toLowerCase(), dup = B.lines.find((l) => l.source === 'manual' && String(l.title).toLowerCase() === tl);
        if (dup) return err(`"${title}" is already in the budget (Line ID ${dup.id}) - put that Line ID in the row to change it`);
        if (seen.has('title:' + tl)) return err(`"${title}" is a new row twice in this workbook`); seen.add('title:' + tl);
        const env = ENV_IN(r.envelope); if (!env) return err('Envelope must be IT Operations or Cyber Security');
        const kind = /cap/i.test(r.type || '') ? 'capex' : /op/i.test(r.type || '') ? 'opex' : null; if (!kind) return err('Type must be CAPEX or OPEX');
        if (status && status !== 'proposed') return err('a new row starts as proposed - add it, then approve it on the page or in the next export');
        const area = AREA_IN(r.area);
        changes.push({ row, action: 'add', title, fields: { envelope: env, area: area && AREAS[env].includes(area) ? area : AREAS[env][0], kind, amount: amount === undefined ? null : amount, priority: priority || 'should', due: r.due ? r.due.slice(0, 10) : null, justification: s(r.reason || note, 500) || 'added from the budget workbook' } });
        return;
      }
      if (seen.has(id)) return err(`Line ID ${id} appears twice`); seen.add(id);
      const cur = byId.get(id); if (!cur) return err(`Line ID ${id} is not in the FY${fy} budget (removed, or from another year)`);
      const f = {};
      if (amount !== undefined && amount !== cur.amount) f.amount = [cur.amount == null ? null : cur.amount, amount];
      if (priority && priority !== cur.priority) f.priority = [cur.priority, priority];
      if (status && status !== cur.status) f.status = [cur.status, status];
      if (note && note !== (cur.note || '')) f.note = [cur.note || '', note];
      if (cur.source === 'manual') {   // a hand-added requirement: its description can be edited in Excel too
        const title = s(r.title, 200); if (title && title !== cur.title) { if (title.length < 3) return err('Title needs at least 3 characters'); f.title = [cur.title, title]; }
        if (r.envelope) { const env = ENV_IN(r.envelope); if (!env) return err('Envelope must be IT Operations or Cyber Security'); if (env !== cur.envelope) f.envelope = [cur.envelope, env]; }
        if (r.type) { const kind = /cap/i.test(r.type) ? 'capex' : /op/i.test(r.type) ? 'opex' : null; if (!kind) return err('Type must be CAPEX or OPEX'); if (kind !== cur.kind) f.kind = [cur.kind, kind]; }
        if (r.due && r.due.slice(0, 10) !== cur.due) f.due = [cur.due, r.due.slice(0, 10)];
      }
      const st = (f.status || [])[1], nt = f.note ? f.note[1] : cur.note || '';
      if ((st === 'rejected' || st === 'deferred') && s(nt, 300).length < 3) return err(`${st === 'rejected' ? 'Rejecting' : 'Deferring'} needs a Note with the reason (3 characters or more)`);
      if (st === 'approved' && !cur.priced && (f.amount ? f.amount[1] : amount) == null) return err('this line has no price - put the Amount in the row to approve it');
      if (!Object.keys(f).length) { unchanged++; return; }
      changes.push({ row, action: 'update', id, title: cur.title, source: cur.source, fields: f });
    });
    const out = { fy, file: W.file, sha256: W.sha256, rows: W.rows.length, changes, errors, unchanged, applied: false };
    if (!opt.apply) return out;
    if (errors.length) throw bad(`nothing was changed - ${errors.length} row(s) need fixing first: ` + errors.slice(0, 5).map((e) => `row ${e.row}: ${e.msg}`).join('; '));
    if (!changes.length) throw bad('nothing to apply - the workbook matches the budget');
    const ref = { file: W.file, sha256: W.sha256.slice(0, 16) };
    for (const c of changes) {
      if (c.action === 'add') {
        const id = `man:${crypto.randomBytes(5).toString('hex')}`, F = c.fields, at = new Date(now()).toISOString();
        lines.put({ id, fy, source: 'manual', envelope: F.envelope, area: F.area, kind: F.kind, title: c.title, amount: F.amount, basis: F.amount == null ? 'price needed' : 'entered by ' + who.user + ' (budget workbook)',
          reason: F.justification, priority: F.priority, due: F.due || fyStart(fy), status: 'proposed', ref: null, created_by: who.user, created_at: at, updated_by: who.user });
        audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.line_add', target: id, detail: Object.assign({ title: c.title, envelope: F.envelope, kind: F.kind, amount: F.amount, via: 'workbook' }, ref) });
        c.id = id; continue;
      }
      const cur = byId.get(c.id), F = c.fields;
      if (cur.source === 'manual' && (F.title || F.envelope || F.kind || F.due || F.amount)) {
        const rec = Object.assign({}, lines.get(c.id), F.title ? { title: F.title[1] } : {}, F.envelope ? { envelope: F.envelope[1], area: AREAS[F.envelope[1]][0] } : {}, F.kind ? { kind: F.kind[1] } : {}, F.due ? { due: F.due[1] } : {},
          F.amount ? { basis: F.amount[1] == null ? 'price needed' : 'entered by ' + who.user + ' (budget workbook)' } : {}, { updated_by: who.user });
        lines.put(rec); Object.assign(cur, rec);
      }
      recordDecision(cur, { status: F.status ? F.status[1] : undefined, priority: F.priority ? F.priority[1] : undefined, note: F.note ? F.note[1] : undefined }, F.amount ? F.amount[1] : undefined, who, 'budget.workbook_change', Object.assign({ changed: Object.keys(F) }, ref));
    }
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.import_workbook', target: `FY${fy}`, detail: Object.assign({ rows: W.rows.length, updated: changes.filter((c) => c.action === 'update').length, added: changes.filter((c) => c.action === 'add').length, unchanged }, ref) });
    return Object.assign(out, { applied: true, budget: build() });
  }

  // ---- year-end rollover ------------------------------------------------------------------------------------------
  const SYS = { user: 'system:budget-rollover', role: 'system', ip: '' };
  function rollover() {
    const done = [];
    for (let guard = 0; guard < 5; guard++) {   // a server that was off for more than a year catches up, one year at a time
      const stored = (conf.get('settings') || {}).values || {};
      const fy = Number(stored.fy);
      if (!Number.isInteger(fy)) break;   // no year saved yet: the page shows next year until an administrator saves one
      if (new Date(now()).toISOString().slice(0, 10) <= fyEnd(fy)) break;
      const B0 = build();
      // actual spend from Budget execution for that year; without it the carry-over is approved minus nothing spent, said so
      let ex = null, exErr = null;
      try { const X = app.addons && app.addons.budgetExec; ex = X && X.view(); if (ex && Number(ex.fy) !== fy) ex = null; } catch (e) { exErr = s(e.message, 200); ex = null; }
      const act = new Map(((ex && ex.lines) || []).map((r) => [r.id, r]));
      const rows = B0.lines.filter((l) => l.status === 'approved' || l.status === 'deferred').map((l) => {
        const x = act.get(l.id), spent = x ? Math.round((x.actual || 0) * 100) / 100 : 0, committed = x ? x.committed || 0 : 0, plan = l.priced ? l.amount : null;
        const status = l.status === 'deferred' ? 'deferred' : plan != null && spent >= plan ? 'completed' : committed > 0 ? 'committed (PO)' : spent > 0 ? 'in progress' : 'not started';
        return { key: l.id, title: l.title, envelope: l.envelope, area: l.area, kind: l.kind, approved: plan, spent, status, vendor: null };
      });
      const at = new Date(now()).toISOString(), p = prev.get('current'), keep = !!(p && Number(p.fy) === fy);
      years.put({ id: String(fy), fy, closed_at: at, by: SYS.user, envelopes: B0.envelopes, summary: B0.summary, approved: B0.lines.filter((l) => l.status === 'approved' && l.priced).reduce((n, l) => n + l.amount, 0),
        spent: ex ? ex.totals && ex.totals.actual : null, lines: B0.lines.map((l) => ({ id: l.id, title: l.title, envelope: l.envelope, kind: l.kind, source: l.source, amount: l.amount, status: l.status, decided_by: l.decided_by || null })) });
      if (!keep) prev.put({ id: 'current', fy, rows, by: SYS.user, at, auto: true, spent_source: ex ? 'budget execution' : 'not recorded', review: { pending: true } });
      else prev.put(Object.assign({}, p, { review: { pending: true } }));
      conf.put({ id: 'settings', values: Object.assign({}, stored, { fy: fy + 1 }), updated_by: SYS.user, updated_at: at });
      audit({ by: SYS.user, role: SYS.role, ip: SYS.ip, action: 'budget.rollover', target: `FY${fy}`, detail: { next_fy: fy + 1, carried_rows: keep ? (p.rows || []).length : rows.length, kept_admin_import: keep, spent_from_execution: !!ex, execution_error: exErr } });
      if (exErr && app.log) app.log.every('budget:rollover:exec', 3600000, 'warn', 'budget rollover: Budget execution could not be read - carry-over without actual spend', { fy, err: exErr });
      done.push({ closed: fy, next: fy + 1, carried: keep ? (p.rows || []).length : rows.length, kept_admin_import: keep });
    }
    return { rolled: done.length > 0, years: done };
  }
  function reviewed(who) {
    if (!isHuman(who && who.user)) throw bad('a service or AI identity cannot sign off the carry-over: a person does', 403);
    const p = prev.get('current'); if (!p || !p.review || !p.review.pending) throw bad('there is no rollover waiting for review', 409);
    prev.put(Object.assign({}, p, { review: { pending: false, by: who.user, at: new Date(now()).toISOString() } }));
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'budget.rollover_reviewed', target: `FY${p.fy}`, detail: { rows: (p.rows || []).length, auto: !!p.auto } });
    return build();
  }
  // for Notification & Escalation: a rollover nobody has checked yet
  function signals() {
    const p = prev.get('current'); if (!p || !p.review || !p.review.pending) return [];
    return [{ fp: 'budget:rollover:' + p.fy, source: 'budget', ref: 'FY' + p.fy, title: `IT budget: FY${p.fy} closed - check the carry-over into FY${Number(p.fy) + 1}`,
      text: `${(p.rows || []).length} line(s) from FY${p.fy} feed next year's budget${p.auto ? ' (made automatically at year end)' : ''}. Open IT Budget, check them and mark the carry-over reviewed.`, severity: 2, condition: true }];
  }
  return { build, importPrevious, importPreviousXlsx, importWorkbook, saveLine, decide, remove, putSettings, settings, rollover, reviewed, signals, isSecurity };
}

function registerBudget(srv, app, opts = {}) {
  const B = createBudget(app, opts);
  // the writes decided in Python (pyengine/desk_budget_write.py, migration step 9h), committed by engine/py-writer.js; the
  // answer (the generated budget) and decisions on generated lines stay in JavaScript - the faster language for that hot
  // path. budget.engine = "node", or a missing Python bridge, keeps Node.js for all of it
  const W = (() => { try { return require('./py-writer').createPyWriter(app, { off: ((app.config && app.config.budget) || {}).engine === 'node' }); } catch (e) { return null; } })();
  const w = (op, spec, who, node) => (W ? W.write(op, Object.assign({ own: ['budget_settings', 'budget_previous', 'budget_lines'], after: () => B.build() }, spec), who, node) : node());
  app.budgetWriteStats = () => (W ? W.stats() : null);
  srv.route('GET', '/budget', (ctx) => void ctx.need('viewer') || B.build()); // read-only: viewers may see the budget (incl. the Cyber Security envelope); all writes below stay admin
  srv.route('POST', '/budget/previous', (ctx) => { ctx.need('admin'); let b = ctx.body || {}; if (b.xlsx_b64) b = B.importPreviousXlsx(b, ctx.who); return w('budget.import', { extra: { body: b }, after: (r) => Object.assign(r, { budget: B.build() }) }, ctx.who, () => B.importPrevious(b, ctx.who)); }, { maxBody: 12 * 1024 * 1024 });
  srv.route('POST', '/budget/import', (ctx) => { ctx.need('admin'); return B.importWorkbook(ctx.body || {}, ctx.who); }, { maxBody: 12 * 1024 * 1024 });
  srv.route('POST', '/budget/rollover/reviewed', (ctx) => { ctx.need('admin'); return B.reviewed(ctx.who); });
  srv.route('POST', '/budget/lines', (ctx) => { ctx.need('admin'); const b = ctx.body || {}; return w('budget.line', { extra: { body: b }, newId: () => `man:${crypto.randomBytes(5).toString('hex')}` }, ctx.who, () => B.saveLine(b, ctx.who)); });
  srv.route('POST', '/budget/lines/:id/decide', (ctx) => { ctx.need('admin'); return B.decide(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/budget/lines/:id/delete', (ctx) => { ctx.need('admin'); return w('budget.remove', { extra: { id: ctx.params.id } }, ctx.who, () => B.remove(ctx.params.id, ctx.who)); });
  srv.route('PUT', '/budget/settings', (ctx) => { ctx.need('admin'); const b = ctx.body || {}; return w('budget.settings', { extra: { body: b } }, ctx.who, () => B.putSettings(b, ctx.who)); });
  (app.addons = app.addons || {}).budget = B;
  // year-end rollover: shortly after start-up, then every 6 hours (the job only acts once the saved fiscal year has ended)
  if (!opts.noTimer) { const run = guardOf(app, 'budget.rollover', () => B.rollover()); setTimeout(run, 90000).unref(); setInterval(run, 6 * 3600000).unref(); }
  return B;
}

module.exports = { createBudget, registerBudget, isSecurity, DEFAULTS };
