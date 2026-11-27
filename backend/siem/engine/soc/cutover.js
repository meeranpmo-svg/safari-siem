// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SIEM CUTOVER - NewEvol (the SIEM being replaced) against this SIEM during the parallel run, and the go / no-go for switching over.
 * NewEvol's side comes from its own exports, imported by an administrator (CSV or JSON, parsed in the page, checked here):
 *   sources   one row per log source per day:  source, ip, type, day (YYYY-MM-DD), events
 *   alerts    one row per alert / offence:      id, time, rule, severity, host, user, ip, technique
 *   rules     one row per correlation rule:     name, technique, severity, enabled
 * Our side is read live: events per source per day (ClickHouse), our alerts (soc/alerts, LogRhythm imports excluded), our rules.
 * What is compared (all computed in code - no model is called, nothing leaves the server):
 *   coverage     every NewEvol source matched to ours by IP or name; a source only NewEvol has is a cutover blocker
 *   parity       per matched source the daily ratio ours / NewEvol; parity when the median is 0.8-1.25; each day scored against the
 *                source's OWN ratios with a robust z (median / MAD) so a silent day or a sudden drop stands out (ML: no fixed
 *                threshold per source); a day NewEvol had events and we had none is a "silent day"
 *   detections   each NewEvol alert matched to one of ours within the window (default 30 min) on a shared host, user or IP
 *                (one-to-one, closest first) - recall = NewEvol alerts we also raised; ours-only alerts listed too
 *   rules        each enabled NewEvol rule mapped to one of ours by ATT&CK technique or name similarity (token Jaccard)
 *   readiness    five gates (14+ days parallel, 98% source coverage by volume, 90% sources at parity, 90% detection recall on
 *                medium and above, 90% rules mapped) - a score and the blockers, ranked
 * The switch itself is four-eyes: an administrator proposes the cutover (with a written risk acceptance when a gate fails), a
 * DIFFERENT named person (administrator, not a service or AI identity) approves or rejects. Nothing here changes NewEvol or any
 * collector - it is the evidence and the decision record.
 *   GET    {P}/cutover                  ?days=1-60 (default 14)     analyst (host / user names - PDPL), audited
 *   POST   {P}/cutover/import           {kind, rows[], file?}        admin, audited
 *   DELETE {P}/cutover/import/:kind                                 admin, audited
 *   GET    {P}/cutover/signoff                                      viewer
 *   POST   {P}/cutover/signoff          {note, accept_risk?}         admin, audited
 *   POST   {P}/cutover/signoff/:id/decide {decision, note}           admin, not the proposer, a person - audited
 */
const DAY = 86400000, H = 3600000;
const KINDS = ['sources', 'alerts', 'rules'];
const MAX_ROWS = 50000;
const SEV = { info: 0, informational: 0, low: 1, medium: 2, med: 2, high: 3, critical: 4, crit: 4 };
const STOP = new Set(['the', 'and', 'for', 'from', 'with', 'via', 'rule', 'alert', 'detected', 'detection', 'possible', 'suspicious', 'activity', 'on', 'of', 'to', 'in', 'by', 'a', 'an']);
const lc = (s) => String(s == null ? '' : s).trim().toLowerCase();
const short = (h) => lc(h).split('.')[0];
const isDay = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s);
const med = (a) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const r1 = (x) => Math.round(x * 10) / 10;
const tokens = (s) => new Set(lc(s).replace(/[^a-z0-9]+/g, ' ').split(' ').filter((w) => w.length >= 3 && !STOP.has(w)));
const jacc = (a, b) => { if (!a.size || !b.size) return 0; let n = 0; for (const x of a) if (b.has(x)) n++; return n / (a.size + b.size - n); };
const tech = (s) => (String(s || '').toUpperCase().match(/T\d{4}(\.\d{3})?/g) || []).map((t) => t.split('.')[0]);
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });

// ---------- the rows NewEvol exported: checked field by field, unknown columns dropped
function cleanRows(kind, rows) {
  if (!KINDS.includes(kind)) throw bad('kind must be one of ' + KINDS.join(', '));
  if (!Array.isArray(rows) || !rows.length) throw bad('rows must be a non-empty list');
  if (rows.length > MAX_ROWS) throw bad('rows: at most ' + MAX_ROWS + ' per import');
  const out = [], errs = [];
  const str = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
  rows.forEach((r, i) => {
    if (!r || typeof r !== 'object' || Array.isArray(r)) { errs.push('row ' + (i + 1) + ': not an object'); return; }
    const g = (k) => { for (const key of Object.keys(r)) if (lc(key).replace(/[^a-z]/g, '') === k) return r[key]; return undefined; };
    if (kind === 'sources') {
      const source = str(g('source') || g('name') || g('logsource') || g('device'), 200), day = str(g('day') || g('date'), 10), events = Number(g('events') || g('count') || g('eventcount'));
      if (!source) return errs.push('row ' + (i + 1) + ': source missing');
      if (!isDay(day)) return errs.push('row ' + (i + 1) + ': day must be YYYY-MM-DD');
      if (!Number.isFinite(events) || events < 0) return errs.push('row ' + (i + 1) + ': events must be a number');
      out.push({ source, ip: str(g('ip') || g('ipaddress') || g('host'), 64), type: str(g('type') || g('logtype') || g('vendor'), 80), day, events: Math.round(events) });
    } else if (kind === 'alerts') {
      const t = Date.parse(str(g('time') || g('timestamp') || g('date') || g('createdat'), 40));
      if (!Number.isFinite(t)) return errs.push('row ' + (i + 1) + ': time is not a date');
      const rule = str(g('rule') || g('rulename') || g('name') || g('title'), 200); if (!rule) return errs.push('row ' + (i + 1) + ': rule missing');
      out.push({ id: str(g('id') || g('alertid') || ('ne-' + (i + 1)), 80), ts: t, rule, severity: SEV[lc(g('severity'))] == null ? 2 : SEV[lc(g('severity'))],
        host: lc(str(g('host') || g('hostname') || g('asset'), 200)), user: lc(str(g('user') || g('username') || g('account'), 200)), ip: str(g('ip') || g('sourceip') || g('srcip'), 64), technique: tech(g('technique') || g('mitre')).join(',') });
    } else {
      const name = str(g('name') || g('rule') || g('rulename') || g('title'), 200); if (!name) return errs.push('row ' + (i + 1) + ': name missing');
      const en = lc(g('enabled')); out.push({ name, technique: tech(g('technique') || g('mitre')).join(','), severity: SEV[lc(g('severity'))] == null ? 2 : SEV[lc(g('severity'))], enabled: !(en === 'false' || en === 'no' || en === '0' || en === 'disabled') });
    }
  });
  if (errs.length > Math.max(10, rows.length * 0.05)) { const e = bad('too many rows are not readable: ' + errs.slice(0, 5).join('; ')); e.errors = errs.slice(0, 50); throw e; }
  return { rows: out, skipped: errs.length, errors: errs.slice(0, 50) };
}

// ---------- the comparison (pure)
function compare({ ne = {}, ours = {}, now, days = 14, windowMin = 30 }) {
  const from = now - days * DAY, dayOf = (t) => new Date(t + 3 * H).toISOString().slice(0, 10);
  const inWin = (d) => d >= dayOf(from) && d <= dayOf(now);
  // ---- sources
  const neSrc = new Map();
  for (const r of (ne.sources || [])) { if (!inWin(r.day)) continue; const k = lc(r.source); const x = neSrc.get(k) || neSrc.set(k, { source: r.source, ip: r.ip, type: r.type, byDay: {} }).get(k); x.byDay[r.day] = (x.byDay[r.day] || 0) + r.events; if (r.ip) x.ip = r.ip; }
  const ourSrc = new Map(), ourByIp = new Map(), ourByShort = new Map();
  for (const r of (ours.volumes || [])) { if (!inWin(r.d)) continue; const k = lc(r.host) || lc(r.ip); if (!k) continue; const x = ourSrc.get(k) || ourSrc.set(k, { host: r.host, ip: r.ip, src_type: r.src_type, byDay: {}, used: false }).get(k); x.byDay[r.d] = (x.byDay[r.d] || 0) + Number(r.n || 0); if (r.ip && !x.ip) x.ip = r.ip; }
  for (const x of ourSrc.values()) { if (x.ip) ourByIp.set(lc(x.ip), x); ourByShort.set(short(x.host), x); }
  const neDays = [...new Set([].concat(...[...neSrc.values()].map((x) => Object.keys(x.byDay))))].sort();
  const sources = [];
  for (const s of neSrc.values()) {
    const o = (s.ip && ourByIp.get(lc(s.ip))) || ourSrc.get(lc(s.source)) || ourByShort.get(short(s.source)) || null;
    const neTotal = Object.values(s.byDay).reduce((a, b) => a + b, 0);
    if (!o) { sources.push({ source: s.source, ip: s.ip, type: s.type, status: 'missing', ne_events: neTotal, our_events: 0, ratio: 0, silent_days: Object.keys(s.byDay).length, why: 'NewEvol receives this source and our SIEM does not - point it at our collectors before the cutover' }); continue; }
    o.used = true;
    const ratios = [], silent = [];
    for (const d of Object.keys(s.byDay).sort()) { const a = s.byDay[d], b = o.byDay[d] || 0; if (a <= 0) continue; ratios.push({ d, r: b / a }); if (!b) silent.push(d); }
    const m = med(ratios.map((x) => x.r)), mad = med(ratios.map((x) => Math.abs(x.r - m))) || 0.05;
    const drift = ratios.map((x) => ({ day: x.d, ratio: r1(x.r * 100) / 100, z: r1((x.r - m) / (1.4826 * mad)) })).filter((x) => Math.abs(x.z) >= 3.5 && Math.abs(x.ratio - m) >= 0.2);
    const ourTotal = Object.keys(s.byDay).reduce((a, d) => a + (o.byDay[d] || 0), 0);
    const status = m == null ? 'no-data' : silent.length ? 'gaps' : m < 0.8 ? 'low' : m > 1.25 ? 'high' : drift.length ? 'drift' : 'parity';
    const why = status === 'parity' ? 'same volume as NewEvol day by day' : status === 'gaps' ? silent.length + ' day(s) NewEvol had events and we had none (' + silent.slice(-3).join(', ') + ')'
      : status === 'low' ? 'we receive ' + Math.round(m * 100) + '% of what NewEvol receives - a filter, a missing channel or a collector limit'
      : status === 'high' ? 'we receive ' + Math.round(m * 100) + '% of what NewEvol receives - duplicates or a wider feed (fine if expected)'
      : status === 'drift' ? drift.length + ' unusual day(s) against this source\'s own ratio (' + drift.map((x) => x.day + ' ' + Math.round(x.ratio * 100) + '%').slice(0, 3).join(', ') + ')' : 'no overlapping day';
    sources.push({ source: s.source, ip: s.ip, type: s.type, ours: o.host || o.ip, src_type: o.src_type, status, ne_events: neTotal, our_events: ourTotal, ratio: m == null ? null : Math.round(m * 100) / 100, silent_days: silent.length, drift, why });
  }
  const extra = [...ourSrc.values()].filter((x) => !x.used).map((x) => ({ source: x.host || x.ip, ip: x.ip, src_type: x.src_type, events: Object.values(x.byDay).reduce((a, b) => a + b, 0) })).sort((a, b) => b.events - a.events);
  const ORDER = { missing: 0, gaps: 1, low: 2, drift: 3, high: 4, 'no-data': 5, parity: 6 };
  sources.sort((a, b) => ORDER[a.status] - ORDER[b.status] || b.ne_events - a.ne_events);
  const neVol = sources.reduce((a, s) => a + s.ne_events, 0), covVol = sources.filter((s) => s.status !== 'missing').reduce((a, s) => a + s.ne_events, 0);
  const matched = sources.filter((s) => s.status !== 'missing' && s.status !== 'no-data'), atParity = matched.filter((s) => s.status === 'parity' || s.status === 'high');
  // ---- detections: one-to-one, closest in time, sharing an entity
  const win = windowMin * 60000, neA = (ne.alerts || []).filter((a) => a.ts >= from && a.ts <= now).sort((a, b) => a.ts - b.ts);
  const ourA = (ours.alerts || []).filter((a) => a.ts >= from - win && a.ts <= now + win).map((a) => Object.assign({}, a, { ents: new Set([a.host, a.user, a.ip, ...(a.entities || [])].map(lc).filter(Boolean).flatMap((x) => [x, short(x)])), taken: false }));
  const det = [];
  for (const a of neA) {
    const ents = [a.host, a.user, a.ip].map(lc).filter(Boolean).flatMap((x) => [x, short(x)]);
    let best = null, bd = Infinity;
    for (const o of ourA) { if (o.taken) continue; const d = Math.abs(o.ts - a.ts); if (d > win || d >= bd) continue; if (!ents.some((e) => o.ents.has(e))) continue; best = o; bd = d; }
    if (best) best.taken = true;
    det.push({ id: a.id, at: new Date(a.ts).toISOString(), rule: a.rule, severity: a.severity, host: a.host, user: a.user, ip: a.ip, matched: !!best, ours: best ? { id: best.id, rule: best.rule, minutes: Math.round(bd / 60000) } : null });
  }
  const sig = det.filter((d) => d.severity >= 2), recall = sig.length ? sig.filter((d) => d.matched).length / sig.length : null;
  const missedByRule = new Map(); for (const d of det) if (!d.matched) { const x = missedByRule.get(d.rule) || missedByRule.set(d.rule, { rule: d.rule, missed: 0, severity: 0 }).get(d.rule); x.missed++; x.severity = Math.max(x.severity, d.severity); }
  const oursOnly = ourA.filter((o) => !o.taken && o.ts >= from && o.ts <= now);
  // ---- rules
  const ourR = (ours.rules || []).map((r) => ({ id: r.id, name: r.name || r.id, tk: tokens(r.name || r.id), tech: new Set((r.mitre || []).map((t) => String(t).split('.')[0].toUpperCase())) }));
  const rules = (ne.rules || []).filter((r) => r.enabled).map((r) => {
    const tk = tokens(r.name), te = r.technique ? r.technique.split(',') : [];
    let best = null, bs = 0, by = '';
    for (const o of ourR) { const j = jacc(tk, o.tk), t = te.some((x) => o.tech.has(x)); const s = j + (t ? 0.5 : 0); if (s > bs) { bs = s; best = o; by = t && j >= 0.35 ? 'technique and name' : t ? 'ATT&CK technique' : 'name'; } }
    const ok = !!best && bs >= 0.35;
    return { name: r.name, technique: r.technique, severity: r.severity, mapped: ok, ours: ok ? { id: best.id, name: best.name, by, score: Math.round(bs * 100) / 100 } : null };
  }).sort((a, b) => Number(a.mapped) - Number(b.mapped) || b.severity - a.severity);
  // ---- readiness
  const ruleCov = rules.length ? rules.filter((r) => r.mapped).length / rules.length : null;
  const G = [
    { id: 'days', label: 'Parallel run of 14+ days', value: neDays.length, target: 14, unit: 'days', pass: neDays.length >= 14 },
    { id: 'coverage', label: 'Sources covered (by NewEvol volume)', value: neVol ? r1(100 * covVol / neVol) : null, target: 98, unit: '%', pass: !!neVol && covVol / neVol >= 0.98 },
    { id: 'parity', label: 'Matched sources at volume parity', value: matched.length ? r1(100 * atParity.length / matched.length) : null, target: 90, unit: '%', pass: !!matched.length && atParity.length / matched.length >= 0.9 },
    { id: 'recall', label: 'NewEvol detections we also raise (medium+)', value: recall == null ? null : r1(100 * recall), target: 90, unit: '%', pass: recall != null && recall >= 0.9 },
    { id: 'rules', label: 'NewEvol rules mapped to ours', value: ruleCov == null ? null : r1(100 * ruleCov), target: 90, unit: '%', pass: ruleCov != null && ruleCov >= 0.9 },
  ];
  const W = { days: 10, coverage: 30, parity: 20, recall: 30, rules: 10 };
  // a passed gate counts in full; an open one at most half its weight, falling with the square of how far it is from the target
  const score = Math.round(G.reduce((a, g) => a + W[g.id] * (g.pass ? 1 : g.value == null ? 0 : Math.min(0.5, Math.pow(g.value / g.target, 2))), 0));
  const blockers = [];
  for (const s of sources.filter((x) => x.status === 'missing').slice(0, 10)) blockers.push({ level: 'crit', what: 'Source not in our SIEM: ' + s.source + (s.ip ? ' (' + s.ip + ')' : ''), why: s.ne_events.toLocaleString('en-US') + ' events in NewEvol in the window' });
  for (const s of sources.filter((x) => x.status === 'gaps' || x.status === 'low').slice(0, 10)) blockers.push({ level: 'warn', what: s.source + ': ' + s.status, why: s.why });
  for (const m of [...missedByRule.values()].filter((x) => x.severity >= 3).sort((a, b) => b.missed - a.missed).slice(0, 10)) blockers.push({ level: 'crit', what: 'NewEvol detection we do not raise: ' + m.rule, why: m.missed + ' alert(s) in the window with no match of ours' });
  for (const r of rules.filter((x) => !x.mapped && x.severity >= 3).slice(0, 10)) blockers.push({ level: 'warn', what: 'Rule not mapped: ' + r.name, why: (r.technique ? 'ATT&CK ' + r.technique + ' - ' : '') + 'build or tune a rule of ours before the cutover' });
  if (!neDays.length) blockers.unshift({ level: 'info', what: 'No NewEvol data yet', why: 'Import NewEvol\'s source volumes, alerts and rules exports to start the comparison' });
  const ready = G.every((g) => g.pass);
  const series = neDays.map((d) => ({ day: d, newevol: [...neSrc.values()].reduce((a, s) => a + (s.byDay[d] || 0), 0), ours: [...ourSrc.values()].filter((x) => x.used).reduce((a, x) => a + (x.byDay[d] || 0), 0),
    ne_alerts: det.filter((x) => x.at.slice(0, 10) === d).length, matched: det.filter((x) => x.matched && x.at.slice(0, 10) === d).length }));
  const ins = [];
  if (ready) ins.push('Every gate passes: our SIEM receives what NewEvol receives and raises what it raises - the cutover can be proposed.');
  else ins.push('Readiness ' + score + '/100 with ' + G.filter((g) => !g.pass).length + ' gate(s) open: ' + G.filter((g) => !g.pass).map((g) => g.label).join('; ') + '.');
  const miss = sources.filter((s) => s.status === 'missing'); if (miss.length) ins.push(miss.length + ' source(s) only NewEvol receives, ' + (neVol ? Math.round(100 * miss.reduce((a, s) => a + s.ne_events, 0) / neVol) : 0) + '% of its volume - the biggest is ' + miss.sort((a, b) => b.ne_events - a.ne_events)[0].source + '.');
  const dr = sources.filter((s) => s.drift && s.drift.length); if (dr.length) ins.push(dr.length + ' source(s) had a day far from their own usual ratio (robust z) - the first sign of a collector that stopped or a filter that changed.');
  const topMiss = [...missedByRule.values()].sort((a, b) => b.missed - a.missed)[0]; if (topMiss) ins.push('The NewEvol detection we miss most: "' + topMiss.rule + '" (' + topMiss.missed + ' time(s)) - map it to a rule of ours or accept it in writing.');
  if (oursOnly.length) ins.push(oursOnly.length + ' alert(s) only our SIEM raised - detections NewEvol did not have (UEBA, ML and the newer rules), worth showing in the cutover report.');
  if (extra.length) ins.push(extra.length + ' source(s) send to our SIEM only - wider coverage than NewEvol.');
  return { days, from: new Date(from).toISOString(), window_min: windowMin, ready, score, gates: G, blockers, insights: ins, series,
    kpis: { ne_sources: sources.length, missing: miss.length, parity: atParity.length, matched_sources: matched.length, ne_alerts: det.length, matched_alerts: det.filter((d) => d.matched).length, ours_only_alerts: oursOnly.length, ne_rules: rules.length, mapped_rules: rules.filter((r) => r.mapped).length, extra_sources: extra.length, parallel_days: neDays.length },
    by_status: sources.reduce((a, s) => { a[s.status] = (a[s.status] || 0) + 1; return a; }, {}),
    sources: sources.slice(0, 500), extra: extra.slice(0, 100), detections: det.filter((d) => !d.matched).slice(0, 200).concat(det.filter((d) => d.matched).slice(-100)),
    missed_rules: [...missedByRule.values()].sort((a, b) => b.severity - a.severity || b.missed - a.missed).slice(0, 50), ours_only: oursOnly.slice(0, 100).map((o) => ({ id: o.id, at: new Date(o.ts).toISOString(), rule: o.rule, host: o.host })),
    rules: rules.slice(0, 500),
    note: 'NewEvol figures are its own exports, imported by an administrator; ours are read live. Volumes per day in Riyadh time. The switch is four-eyes: proposed by one administrator, approved by another person.' };
}

function createCutover({ state, alerts, rules, volumes, now = Date.now }) {
  const col = state.collection('cutover'), so = state.collection('cutover_signoff');
  function imported() { const o = {}; for (const k of KINDS) { const d = col.get(k); o[k] = d ? { rows: d.rows.length, imported_at: d.imported_at, by: d.by, file: d.file, skipped: d.skipped } : null; } return o; }
  async function view(days) {
    const t = now(), ne = {}; for (const k of KINDS) { const d = col.get(k); ne[k] = d ? d.rows : []; }
    const ourAlerts = (alerts ? alerts.all() : []).filter((a) => a.source !== 'logrhythm').map((a) => ({ id: a.id, ts: Number(a.ts_first) || Date.parse(a.created) || 0, rule: a.rule_name, host: a.host || (a.group || {}).host, user: (a.group || {}).user, ip: (a.group || {}).src_ip || (a.group || {}).ip, entities: Object.values(a.group || {}).map(String) }));
    let vol = [], volErr = '';
    try { vol = volumes ? await volumes(t - (days + 1) * DAY, t) : []; } catch (e) { volErr = 'our event counts could not be read: ' + String(e.message).slice(0, 200); }
    const r = compare({ ne, ours: { volumes: vol, alerts: ourAlerts, rules: rules ? rules() : [] }, now: t, days });
    r.imported = imported(); if (volErr) r.warning = volErr;
    r.signoff = so.all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 10);
    return r;
  }
  function importRows(kind, rows, who, file) {
    const c = cleanRows(kind, rows);
    col.put({ id: kind, kind, rows: c.rows, skipped: c.skipped, imported_at: new Date(now()).toISOString(), by: who, file: file || '' });
    return { kind, rows: c.rows.length, skipped: c.skipped, errors: c.errors };
  }
  function clear(kind) { if (!KINDS.includes(kind)) throw bad('kind must be one of ' + KINDS.join(', ')); const had = !!col.get(kind); col.remove(kind); return { kind, removed: had }; }
  return { view, importRows, clear, imported, signoff: so };
}

function ourVolumes(ch, config) {
  const db = ((config || {}).clickhouse || {}).database || 'siem';
  return async (from, to) => {
    if (!ch || typeof ch.query !== 'function') return [];
    const sql = `SELECT toString(toDate(ts, 'Asia/Riyadh')) AS d, host, toString(host_ip) AS ip, any(src_type) AS src_type, count() AS n FROM ${db}.events WHERE ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts <= fromUnixTimestamp64Milli({t_to:Int64}) GROUP BY d, host, ip LIMIT 200000`;
    return ch.query(sql, { t_from: { type: 'Int64', value: from }, t_to: { type: 'Int64', value: to } }, { readonly: true, settings: { max_execution_time: 60 } });
  };
}

function register(api, deps) {
  const { wrap, audit, prefixOf, HttpError } = require('./routeutil');
  const { body, param } = require('../util/check');
  const SC = require('../approvers/scopes');
  if (!deps.state) return;
  const P = prefixOf(deps);
  const C = deps.cutover || createCutover({ state: deps.state, alerts: deps.alerts, rules: () => (deps.detector && typeof deps.detector.rules === 'function' ? deps.detector.rules() : []), volumes: ourVolumes(deps.ch, deps.config), now: deps.now || Date.now });
  const who = (ctx) => String(ctx.user || '');
  api.route('GET', `${P}/cutover`, wrap(deps, 'analyst', async (ctx) => {
    const v = (ctx.query || {}).days, days = v === undefined || v === '' ? 14 : Number(v);
    if (!Number.isInteger(days) || days < 1 || days > 60) throw new HttpError(400, 'days must be a whole number 1-60');
    const r = await C.view(days);
    audit(ctx, 'cutover.read', 'newevol', { days, score: r.score, ready: r.ready });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/cutover/import`, wrap(deps, 'admin', async (ctx) => {
    const b = body(ctx.body || {}).oneOf('kind', KINDS, { required: true }).list('rows', { required: true, max: MAX_ROWS }).str('file', { max: 200 }).done();
    const r = C.importRows(b.kind, b.rows, who(ctx), b.file);
    audit(ctx, 'cutover.import', b.kind, { rows: r.rows, skipped: r.skipped, file: b.file || '' });
    return ctx.ok(r);
  }, { maxBody: 32 * 1048576 }));
  api.route('DELETE', `${P}/cutover/import/:kind`, wrap(deps, 'admin', async (ctx) => {
    const kind = param((ctx.params || {}).kind, 'kind'); if (!KINDS.includes(kind)) throw new HttpError(400, 'kind must be one of ' + KINDS.join(', '));
    const r = C.clear(kind); audit(ctx, 'cutover.import.clear', kind, r); return ctx.ok(r);
  }));
  api.route('GET', `${P}/cutover/signoff`, wrap(deps, 'viewer', async (ctx) => ctx.ok({ items: C.signoff.all().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50) })));
  api.route('POST', `${P}/cutover/signoff`, wrap(deps, 'admin', async (ctx) => {
    const b = body(ctx.body || {}).str('note', { required: true, min: 10, max: 2000 }).str('accept_risk', { max: 4000 }).done();
    if (C.signoff.all().some((x) => x.status === 'proposed')) throw new HttpError(409, 'a cutover proposal is already waiting for a decision');
    const r = await C.view(14);
    if (!r.ready && (!b.accept_risk || b.accept_risk.length < 20)) throw new HttpError(400, 'accept_risk: ' + r.gates.filter((g) => !g.pass).length + ' gate(s) are open - write the risk you accept (20+ characters) or close them first');
    const id = 'CUT-' + Date.now().toString(36).toUpperCase();
    const item = { id, status: 'proposed', at: new Date().toISOString(), by: who(ctx), note: b.note, accept_risk: b.accept_risk || '', score: r.score, ready: r.ready, gates: r.gates.map((g) => ({ id: g.id, value: g.value, pass: g.pass })), blockers: r.blockers.length };
    C.signoff.put(item);
    audit(ctx, 'cutover.propose', id, { score: r.score, ready: r.ready, risk_accepted: !!b.accept_risk });
    return ctx.ok(item);
  }));
  api.route('POST', `${P}/cutover/signoff/:id/decide`, wrap(deps, 'admin', async (ctx) => {
    const id = param((ctx.params || {}).id, 'id');
    const b = body(ctx.body || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { required: true, min: 5, max: 2000 }).done();
    const it = C.signoff.get(id); if (!it) throw new HttpError(404, 'no such proposal');
    if (it.status !== 'proposed') throw new HttpError(409, 'this proposal is already ' + it.status);
    if (!SC.isHuman(who(ctx))) throw new HttpError(403, 'a cutover is approved by a named person, never a service or AI identity');
    if (lc(it.by) === lc(who(ctx))) throw new HttpError(403, 'four-eyes: the person who proposed the cutover cannot decide it');
    const out = Object.assign({}, it, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who(ctx), decided_at: new Date().toISOString(), decision_note: b.note });
    C.signoff.put(out);
    audit(ctx, 'cutover.' + b.decision, id, { proposed_by: it.by, score: it.score });
    return ctx.ok(out);
  }));
}

module.exports = { register, compare, cleanRows, createCutover, ourVolumes, KINDS };
