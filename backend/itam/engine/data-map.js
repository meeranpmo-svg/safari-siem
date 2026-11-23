// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
/*
 * Data map (PDPL Implementing Regulation Art. 33, page pdpl-ropa.html) - the automated data-mapping method: the register of processing
 * activities (RoPA) is checked against what discovery actually found, instead of being a document that drifts. REPORT ONLY: it reads
 * the PDPL records (activities, processors, transfers, DPIAs) and Data Security Posture's discovered systems (SharePoint / Teams sites,
 * file shares, cloud stores, databases with the personal data classes found), and changes nothing - a suggestion becomes a record only
 * when a steward or the DPO writes it through the RoPA campaign (four-eyes there).
 *   map        nodes: processing activities, systems (with the categories found, inside / outside the Kingdom, public), processors and
 *              countries; edges: an activity names a system (its systems[] equal to, or containing, the system's label / host / key -
 *              the same rule as DSPM), uses a processor (processor_ids), transfers to a country (transfer records).
 *   sync       the gaps between the register and reality, each with its evidence and the fix:
 *                UNMAPPED   a system holding personal data that no activity names (a draft activity is proposed: name, the categories
 *                           found, the system - the steward adds the purpose and legal basis, which discovery cannot know)
 *                UNDER-DECLARED  the activity's systems hold categories it does not declare
 *                NOT FOUND  categories it declares that none of its scanned systems hold (check, or the systems list is incomplete)
 *                UNKNOWN SYSTEMS  systems it names that discovery has never seen (not connected, or renamed)
 *                TRANSFER   personal data outside the Kingdom (a cloud store, a processor outside KSA, reinsurance abroad) with no transfer
 *                           record for the activity, or a transfer with no risk assessment
 *                DPIA       sensitive data (health, biometric, genetic, criminal, credit), automated decisions, profiling, large-scale
 *                           monitoring or 10,000+ people - and no DPIA for the activity
 *                EXPOSED    a system of the activity is public, or holds files shared outside the organisation
 *                STALE      not reviewed for 12 months (or never)
 *   risk       each activity 0-100 with every point itemised; coverage = share of discovered personal-data systems that an activity names.
 * GET /pdpl/data-map    operator (system, processor and activity names), audited
 */
const DAY = 86400000;
const CATMAP = { national_id: 'identity', iqama: 'identity', passport: 'identity', name: 'identity', birth_date: 'identity', email: 'contact', mobile: 'contact', address: 'contact', iban: 'financial', card: 'financial', salary: 'financial', credit: 'credit', health: 'health', biometric: 'biometric', cv: 'employment' };
const SENSITIVE = ['health', 'biometric', 'genetic', 'criminal', 'credit', 'religious', 'beliefs', 'ethnic', 'parentage'];
const low = (s) => String(s || '').toLowerCase().trim();
const names = (s) => [s.label, s.host, s.key, s.service, s.url].filter(Boolean).map(low);
const linked = (sys, entry) => { const e = low(entry); if (!e) return false; return names(sys).some((n) => n && (n === e || n.includes(e) || e.includes(n))); };

/* pure: DSPM context + PDPL records -> the data map */
function analyse({ C, records, now = Date.now() }) {
  const sys = [];
  for (const s of (C && C.stores) || []) { const cats = [...new Set(Object.keys(s.kinds || {}).filter((k) => Number(s.kinds[k])).map((k) => CATMAP[k]).filter(Boolean))]; sys.push({ id: s.id, label: s.label, type: s.type, host: s.host || '', url: s.url || '', personal: (s.personal || 0) > 0, files: s.personal || 0, cats, in_kingdom: null, public: false, shared_outside: 0, scanned: !!s.last_scan || (s.files_seen || 0) > 0 }); }
  for (const s of (C && C.cloudStores) || []) sys.push({ id: s.id, label: s.label, type: s.type, host: '', key: s.raw_id, personal: !!s.personal, files: s.with_findings || 0, cats: [...new Set(Object.keys(s.kinds || {}).map((k) => CATMAP[k]).filter(Boolean))], in_kingdom: s.in_kingdom, public: s.public === true, shared_outside: 0, scanned: !!s.last_scan });
  for (const d of (C && C.dbs) || []) sys.push({ id: String(d.id || d.label).startsWith('db:') ? d.id : 'db:' + (d.id || d.label), label: d.label || d.id, type: 'database', host: d.host || '', service: d.service || '', key: d.key || '', personal: !!d.personal, files: d.columns || 0, cats: [...new Set(Object.keys(d.kinds || {}).map((k) => CATMAP[k]).filter(Boolean).concat((d.cats || []).filter((c) => c !== 'credentials')))], in_kingdom: null, public: false, shared_outside: 0, scanned: !!d.ok });
  const byStore = new Map(sys.map((s) => [s.id, s])); for (const r of (C && C.rows) || []) { const s = r.store && byStore.get(r.store.id); if (s && r.personal && (r.shared === 'anonymous' || r.shared === 'external')) s.shared_outside++; }
  const R = (records || []).filter((r) => !r.archived && r.status !== 'archived');
  const acts = R.filter((r) => r.kind === 'ropa'), procs = new Map(R.filter((r) => r.kind === 'processor').map((p) => [p.id, p])), transfers = R.filter((r) => r.kind === 'transfer'), dpias = R.filter((r) => r.kind === 'dpia');
  const named = new Set(), findings = [], F = (type, sev, act, sysL, why, fix) => findings.push({ type, severity: sev, activity: act ? { id: act.id, name: act.name } : null, system: sysL || null, why, fix });
  const activities = acts.map((a) => {
    const mine = sys.filter((s) => (a.systems || []).some((e) => linked(s, e))); mine.forEach((s) => named.add(s.id));
    const unknown = (a.systems || []).filter((e) => !sys.some((s) => linked(s, e)));
    const decl = new Set(a.data_categories || []), found = new Set(mine.flatMap((s) => s.cats)), scanned = mine.filter((s) => s.scanned);
    const items = [], add = (p, l) => { if (p) items.push({ points: Math.round(p), label: l }); };
    const under = [...found].filter((c) => !decl.has(c)); if (under.length) { add(10 + 3 * under.length, 'its systems hold ' + under.join(', ') + ' - not declared'); F('under-declared', 'high', a, mine.map((s) => s.label).join(', '), 'its systems hold ' + under.join(', ') + ' data the activity does not declare', 'add the categories to the activity (RoPA) or move the data out of these systems'); }
    const notFound = scanned.length ? [...decl].filter((c) => !found.has(c) && c !== 'other') : []; if (notFound.length) F('not-found', 'low', a, null, 'declares ' + notFound.join(', ') + ' but none of its scanned systems holds it', 'check the declaration, or add the system that holds it to the activity');
    if (unknown.length) { add(5, unknown.length + ' named system(s) never seen by discovery'); F('unknown-systems', 'medium', a, unknown.join(', '), 'names ' + unknown.join(', ') + ' - discovery has never seen ' + (unknown.length > 1 ? 'them' : 'it'), 'connect the system to discovery (Data Catalog / DSPM sources) or correct the name'); }
    const abroad = mine.filter((s) => s.in_kingdom === false), procAbroad = (a.processor_ids || []).map((id) => procs.get(id)).filter((p) => p && p.outside_ksa), tr = transfers.filter((t) => t.ropa_id === a.id);
    if ((abroad.length || procAbroad.length || a.reinsurance_outside || a.transfer_outside) && !tr.length) { add(20, 'personal data leaves the Kingdom with no transfer record'); F('transfer', 'high', a, abroad.map((s) => s.label).concat(procAbroad.map((p) => p.name)).join(', ') || (a.reinsurance_outside ? 'reinsurers abroad' : 'transfer outside'), 'personal data goes outside the Kingdom (' + [abroad.length ? abroad.length + ' system(s) abroad' : '', procAbroad.length ? procAbroad.length + ' processor(s) outside KSA' : '', a.reinsurance_outside ? 'reinsurance abroad' : ''].filter(Boolean).join(', ') + ') and no transfer record names this activity', 'record the transfer with its legal basis (PDPL Art. 29 / Transfer Regulation) and its risk assessment'); }
    for (const t of tr) if (!t.risk_assessed) { add(8, 'transfer to ' + t.country + ' without a risk assessment'); F('transfer', 'medium', a, t.country, 'transfer to ' + t.country + ' has no risk assessment date', 'complete the transfer risk assessment (Transfer Regulation Art. 8)'); }
    const sens = [...new Set([...decl, ...found])].filter((c) => SENSITIVE.includes(c)), trig = [].concat(sens.length ? ['sensitive data (' + sens.join(', ') + ')'] : [], a.automated_decision ? ['automated decisions'] : [], a.profiling ? ['profiling'] : [], a.large_scale_monitoring ? ['large-scale monitoring'] : [], (a.volume || 0) >= 10000 ? [a.volume.toLocaleString('en-US') + ' people'] : []);
    const hasDpia = dpias.some((d) => d.ropa_id === a.id);
    if (trig.length && !hasDpia) { add(15, 'needs a DPIA: ' + trig.join(', ')); F('dpia', 'high', a, null, 'a DPIA is required (' + trig.join(', ') + ') and none exists for this activity', 'run the DPIA (PDPL Implementing Regulation Art. 25) from the DPIA page'); }
    const exposed = mine.filter((s) => s.public || s.shared_outside);
    if (exposed.length) { add(12, exposed.length + ' of its systems reachable outside'); F('exposed', 'high', a, exposed.map((s) => s.label).join(', '), exposed.map((s) => s.label + (s.public ? ' is public' : ' has ' + s.shared_outside + ' file(s) shared outside')).join('; '), 'remove the public access / outside sharing (Data Security Posture plan)'); }
    const rv = Date.parse(a.reviewed || ''), age = Number.isFinite(rv) ? Math.floor((now - rv) / DAY) : null;
    if (age == null || age > 365) { add(5, age == null ? 'never reviewed' : 'last reviewed ' + Math.floor(age / 30) + ' months ago'); F('stale', 'low', a, null, age == null ? 'never reviewed' : 'last reviewed ' + Math.floor(age / 30) + ' months ago', 'review the activity with its steward (yearly)'); }
    if (!(a.systems || []).length) add(8, 'names no system');
    return { id: a.id, name: a.name, department: a.department || a.owner || '', legal_basis: a.legal_basis || null, declared: [...decl], found: [...found], systems: mine.map((s) => ({ id: s.id, label: s.label, type: s.type, in_kingdom: s.in_kingdom })), unknown_systems: unknown,
      processors: (a.processor_ids || []).map((id) => procs.get(id)).filter(Boolean).map((p) => ({ id: p.id, name: p.name, outside_ksa: !!p.outside_ksa })), transfers: tr.map((t) => ({ id: t.id, country: t.country, basis: t.basis || null, risk_assessed: t.risk_assessed || null })), dpia: hasDpia, risk: Math.min(100, items.reduce((n, i) => n + i.points, 0)), risk_items: items };
  });
  const pd = sys.filter((s) => s.personal), unmapped = pd.filter((s) => !named.has(s.id));
  const suggestions = unmapped.sort((a, b) => b.files - a.files).slice(0, 25).map((s) => { F('unmapped', s.cats.some((c) => SENSITIVE.includes(c)) ? 'high' : 'medium', null, s.label, s.label + ' holds ' + (s.cats.join(', ') || 'personal data') + ' (' + s.files + ' item(s)) and no processing activity names it', 'add it to the activity that uses it, or record a new activity (draft below)');
    return { system: s.label, system_id: s.id, type: s.type, draft: { name: 'Processing in ' + s.label, systems: [s.label], data_categories: s.cats, transfer_outside: s.in_kingdom === false }, why: 'discovery found ' + (s.cats.join(', ') || 'personal data') + ' in ' + s.files + ' item(s); the purpose, legal basis and retention are for the steward to state - discovery cannot know them' }; });
  const SEV = { high: 0, medium: 1, low: 2 }; findings.sort((a, b) => SEV[a.severity] - SEV[b.severity]);
  const countries = [...new Set(transfers.map((t) => t.country))];
  return { generated_at: new Date(now).toISOString(), coverage: { systems_with_personal_data: pd.length, mapped: pd.length - unmapped.length, pct: pd.length ? Math.round(100 * (pd.length - unmapped.length) / pd.length) : null },
    counts: findings.reduce((m, f) => { m[f.type] = (m[f.type] || 0) + 1; return m; }, {}), activities: activities.sort((a, b) => b.risk - a.risk), systems: sys.filter((s) => s.personal || named.has(s.id)).map((s) => ({ id: s.id, label: s.label, type: s.type, cats: s.cats, files: s.files, in_kingdom: s.in_kingdom, public: s.public, shared_outside: s.shared_outside, mapped: named.has(s.id) })),
    processors: [...procs.values()].map((p) => ({ id: p.id, name: p.name, outside_ksa: !!p.outside_ksa })), countries, findings: findings.slice(0, 200), suggestions,
    discovery: { measured: !!(C && C.src && ((C.src.m365_files && C.src.m365_files.measured) || (C.src.cloud && C.src.cloud.measured) || (C.src.databases && C.src.databases.measured))) },
    note: 'Built from the PDPL records and what discovery found. A suggestion is a proposal - the steward writes it through the RoPA campaign and the DPO approves.' };
}

function registerDataMap(srv, app, opts = {}) {
  const now = opts.now || Date.now;
  async function view(who) {
    const P = (app.addons || {}).dataPosture || opts.dataPosture; let C = {};
    if (P && P.build) { try { C = (await P.build(who)).C || {}; } catch (e) { if (app.log && app.log.every) app.log.every('data-map:dspm', 600000, 'warn', 'data map: discovery could not be read', { err: e.message }); } }
    const v = analyse({ C, records: app.store.collection('pdpl_records').all(), now: now() });
    if (!P) v.discovery.why = 'Data Security Posture is not installed - only the register is checked';
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'pdpl.datamap.read', target: 'data-map', detail: { activities: v.activities.length, findings: v.findings.length } });
    return v;
  }
  srv.route('GET', '/pdpl/data-map', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return view(ctx.who); });
  return { view };
}

module.exports = { analyse, registerDataMap, CATMAP };
