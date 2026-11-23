// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { createIntelKit, trend, robustZ } = require('./intel-kit');
const { body } = require('./check');
/*
 * Leadership intelligence ({P} = /api/itam): the thinking behind the CIO Dashboard and the IT Infrastructure Manager page.
 * It reads only what the platform already holds - the asset register and its add-ons (infra-overview: backup, patching, end of
 * life, storage, support contracts), licences, the IT budget and its intelligence, the AI CISO's posture history - and says
 * what each figure stands on. A source that is not installed or has reported nothing is "not measured", never 0 % or fine.
 *   infra   health index 0-100 per area (backup protected, patch compliant, end of life, storage headroom, support cover),
 *           every point itemised; the overall is withheld until 3 areas are measured. A daily snapshot gives each area a trend
 *           (a projection from past pace, not a promise), the storage forecast (date the estate reaches 85 % and 95 % used) and
 *           unusual days (robust z of the day-to-day change, 7+ days). A ranked worklist: what to fix first and why.
 *   cio     the renewal cash wave for the next 12 months (licences and support contracts by month, unpriced ones counted, the
 *           peak month named), the budget forecast (budget-intel: chance of going over each ceiling), the security posture and
 *           its 30-day change, the infrastructure health index, and "this week" - the decisions ranked by money and risk.
 *   ask     the read-only AI advisor (operator, a person): intel-kit / ai-guard, untrusted tool output, it proposes only.
 *   GET  /leader-intel/cio      operator (costs, contracts)
 *   GET  /leader-intel/infra    operator (names servers and contracts)
 *   POST /leader-intel/ask      operator, a person {question}
 * A snapshot is taken at most once a day, hourly timer through intel-kit (guardOf 'leader-intel.snapshot').
 */
const DAY = 86400000, r1 = (x) => Math.round(x * 10) / 10;
const AREAS = [
  { id: 'backup', name: 'Backup protection', weight: 25, link: 'backup-status.html' },
  { id: 'patch', name: 'Patch compliance', weight: 25, link: 'manageengine.html' },
  { id: 'lifecycle', name: 'Supported hardware & software', weight: 20, link: 'lifecycle.html' },
  { id: 'storage', name: 'Storage headroom', weight: 15, link: 'storage.html' },
  { id: 'contracts', name: 'Support contract cover', weight: 15, link: 'support-contracts.html' },
];

function areaScores(o, reg) {
  const out = [];
  const add = (id, score, items, why) => { const a = AREAS.find((x) => x.id === id); out.push(Object.assign({}, a, { measured: score != null, score: score == null ? null : Math.max(0, Math.min(100, Math.round(score))), items, why })); };
  const b = o.backup || {};
  if (b.available && b.protected_pct != null) add('backup', b.protected_pct, [{ label: b.protected + ' protected', points: 0 }, { label: (b.failed || 0) + ' failed, ' + (b.stale || 0) + ' stale, ' + (b.none || 0) + ' with no backup', points: -(100 - b.protected_pct) }], 'share of servers in scope with a recent successful backup');
  else add('backup', null, [], b.why || 'not measured');
  const p = o.patch || {};
  if (p.available && p.compliant_pct != null) { const crit = p.reported ? Math.min(20, Math.round(40 * (p.critical_missing || 0) / p.reported)) : 0;
    add('patch', p.compliant_pct - crit, [{ label: p.compliant + ' of ' + p.reported + ' computers fully patched', points: -(100 - p.compliant_pct) }].concat(crit ? [{ label: p.critical_missing + ' missing a critical patch', points: -crit }] : []), 'computers with no missing patch, less up to 20 for critical ones');
  } else add('patch', null, [], p.why || 'not measured');
  const l = o.lifecycle || {}, tot = reg && reg.available ? (reg.servers.total + reg.network.total + reg.storage.total) : 0;
  if (l.available && tot > 0) { const eolP = Math.min(60, Math.round(100 * (l.eol || 0) / tot * 2)), soonP = Math.min(20, Math.round(100 * (l.soon || 0) / tot * 0.5)), isoP = Math.min(20, (l.isolation_required || 0) * 5);
    add('lifecycle', 100 - eolP - soonP - isoP, [{ label: (l.eol || 0) + ' past end of life', points: -eolP }, { label: (l.soon || 0) + ' reaching it soon', points: -soonP }].concat(isoP ? [{ label: l.isolation_required + ' need isolation', points: -isoP }] : []), 'end-of-life items against ' + tot + ' servers, network and storage devices');
  } else add('lifecycle', null, [], l.available ? 'no server, network or storage device in the register' : (l.why || 'not measured'));
  const s = o.storage || {};
  if (s.available && s.used_pct != null) { const over = Math.max(0, s.used_pct - 70), fd = Math.min(20, (s.failed_disks || 0) * 10);
    add('storage', 100 - over * 3.3 - fd, [{ label: s.used_pct + '% used (each point over 70 % costs 3.3)', points: -r1(over * 3.3) }].concat(fd ? [{ label: s.failed_disks + ' failed disk(s)', points: -fd }] : []), 'free capacity across ' + s.read + ' array(s)');
  } else add('storage', null, [], s.why || 'not measured');
  const c = o.contracts || {};
  if (c.available && c.contracts) { const ex = Math.min(50, (c.expired || 0) * 10), ei = Math.min(20, (c.expiring || 0) * 4), un = tot ? Math.min(40, Math.round(100 * (c.uncovered_assets || 0) / tot)) : 0;
    add('contracts', 100 - ex - ei - un, [{ label: (c.expired || 0) + ' expired', points: -ex }, { label: (c.expiring || 0) + ' expiring', points: -ei }, { label: (c.uncovered_assets || 0) + ' assets with no contract', points: -un }], c.contracts + ' contracts');
  } else add('contracts', null, [], c.why || 'not measured');
  const m = out.filter((a) => a.measured), w = m.reduce((n, a) => n + a.weight, 0);
  const overall = m.length >= 3 ? Math.round(m.reduce((n, a) => n + a.score * a.weight, 0) / w) : null;
  return { areas: out, overall, measured: m.length, of: out.length, withheld_why: overall == null ? 'needs 3 measured areas (' + m.length + ' so far) - connect the sources named below' : null };
}

// renewal wave: next 12 months, by month (pure)
function renewalWave(licences, contracts, todayIso) {
  const t0 = Date.parse(todayIso + 'T00:00:00Z'), months = [];
  for (let i = 0; i < 12; i++) { const d = new Date(t0); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() + i); months.push({ month: d.toISOString().slice(0, 7), amount: 0, items: 0, unpriced: 0, list: [] }); }
  const end = new Date(Date.parse(months[11].month + '-01T00:00:00Z')); end.setUTCMonth(end.getUTCMonth() + 1);
  const put = (date, amount, title, kind) => {
    const d = String(date || '').slice(0, 10); if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return;
    const k = d < todayIso ? months[0] : months.find((m) => m.month === d.slice(0, 7)); if (!k || d >= end.toISOString().slice(0, 10)) return;
    k.items++; if (amount > 0) k.amount += amount; else k.unpriced++;
    k.list.push({ title, date: d, amount: amount > 0 ? amount : null, kind, overdue: d < todayIso });
  };
  for (const l of licences) put(l.expiry, Number(l.cost) || 0, l.product || 'licence', 'licence');
  for (const c of contracts) put(c.end, Number(c.cost) || 0, [c.vendor, c.product].filter(Boolean).join(' ') || 'support contract', 'contract');
  for (const m of months) { m.amount = Math.round(m.amount); m.list.sort((a, b) => (b.amount || 0) - (a.amount || 0)); m.list = m.list.slice(0, 8); }
  const total = months.reduce((n, m) => n + m.amount, 0), peak = months.reduce((a, m) => (m.amount > a.amount ? m : a), months[0]);
  const q = [0, 1, 2, 3].map((i) => months.slice(i * 3, i * 3 + 3).reduce((n, m) => n + m.amount, 0));
  return { months, total, unpriced: months.reduce((n, m) => n + m.unpriced, 0), items: months.reduce((n, m) => n + m.items, 0), peak: peak.amount ? { month: peak.month, amount: peak.amount, share_pct: total ? Math.round(100 * peak.amount / total) : null } : null, by_quarter: q };
}

function createLeaderIntel(app, opts = {}) {
  const K = createIntelKit(app, { key: 'leader-intel', feature: 'itam.leader-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: opts.noTimer,
    system: ('You are the advisor to the CIO and the IT Infrastructure Manager of ' + ZYB_ORG.name + ' (Saudi Arabia, SAR). Read the platform through the leadership_figures tool and answer: where the infrastructure is weakest and what to fix first, when storage runs out, what renewals and money are coming and when, whether the budget lands within its ceilings, and how security posture is moving. Use only what the tool returns, say what each figure rests on, and say plainly when something is not measured. Trends are projections from past pace, not promises. You change nothing: you propose and a person decides.'),
    tools: [{ name: 'leadership_figures', description: 'Infrastructure health per area with its itemised points, trends and storage forecast, the renewal wave by month, the budget forecast, the security posture trend, and the ranked worklists for the CIO and the infrastructure manager.', run: async () => { const c = cio(), i = await infra(); return { infra: { overall: i.health.overall, areas: i.health.areas.map((a) => ({ name: a.name, score: a.score, why: a.why, items: a.items, trend: a.trend && a.trend.why })), storage_forecast: i.storage_forecast, unusual: i.unusual, worklist: i.worklist }, cio: { renewals: { total: c.renewals.total, peak: c.renewals.peak, by_quarter: c.renewals.by_quarter, unpriced: c.renewals.unpriced }, budget: c.budget, posture: c.posture, this_week: c.this_week } }; } }] });
  const now = K.now, today = K.today, A = K.A;
  const io = () => { if (A().infraOverview) return A().infraOverview; return require('./infra-overview').createInfraOverview(app); };
  const overview = () => { try { return io().view('admin'); } catch (e) { K.warn('infra-overview', e); return {}; } };
  function snapRec() {
    const o = overview(), h = areaScores(o, o.register), rec = { overall: h.overall };
    for (const a of h.areas) rec[a.id] = a.score;
    rec.storage_used = o.storage && o.storage.available ? o.storage.used_pct : null;
    return rec;
  }
  const snapshot = () => K.snapshot(async () => snapRec());
  async function infra() {
    const o = overview(), h = areaScores(o, o.register);
    try { await snapshot(); } catch (e) { K.warn('snapshot', e); }
    const hist = K.history(120);
    for (const a of h.areas) a.trend = trend(K.pts(a.id), { now: now() });
    const st = trend(K.pts('storage_used'), { now: now() }), cur = o.storage && o.storage.available ? o.storage.used_pct : null;
    const reach = (target) => { if (cur == null) return null; if (cur >= target) return { date: today(), why: 'already at ' + cur + '%' }; const t = trend(K.pts('storage_used'), { now: now(), target, current: cur }); return t.date ? { date: t.date, why: t.why } : { date: null, why: t.why }; };
    const storage_forecast = cur == null ? { measured: false, why: (o.storage && o.storage.why) || 'no storage array is read' } : { measured: true, used_pct: cur, trend: st, at85: reach(85), at95: reach(95) };
    const unusual = [];
    for (const a of h.areas.concat([{ id: 'overall', name: 'Overall health' }])) {
      const ys = hist.map((x) => x[a.id]).filter((v) => v != null); if (ys.length < 8) continue;
      const diffs = ys.slice(1).map((v, i) => v - ys[i]), last = diffs.pop(), z = robustZ(diffs, last);
      if (!z || !last) continue;
      if (z.never_moved) { if (Math.abs(last) >= 3) unusual.push({ id: a.id, name: a.name, change: r1(last), z: null, why: (last < 0 ? 'fell ' : 'rose ') + Math.abs(r1(last)) + ' points in a day after ' + diffs.length + ' days without moving' }); continue; }
      if (Number.isFinite(z.z) && Math.abs(z.z) >= 3) unusual.push({ id: a.id, name: a.name, change: r1(last), z: z.z, why: (last < 0 ? 'fell ' : 'rose ') + Math.abs(r1(last)) + ' points in a day; a usual day moves about ' + Math.abs(r1(z.usual)) });
    }
    const wl = [], push = (score, title, why, link) => wl.push({ score: Math.round(score), title, why, link });
    const b = o.backup || {}, p = o.patch || {}, l = o.lifecycle || {}, s = o.storage || {}, c = o.contracts || {}, r = o.register || {};
    if (b.available && b.failed) push(90 + b.failed, b.failed + ' server backup(s) failing', 'a failed backup is a server you cannot restore', 'backup-status.html');
    if (b.available && b.none) push(70 + b.none, b.none + ' server(s) with no backup at all', 'not in any backup job', 'backup-status.html');
    if (p.available && p.critical_missing) push(80 + p.critical_missing, p.critical_missing + ' computer(s) missing a critical patch', 'worst: ' + (p.worst || []).slice(0, 3).map((x) => x.name).join(', '), 'manageengine.html');
    if (l.available && l.isolation_required) push(85, l.isolation_required + ' end-of-life device(s) need isolation', 'no vendor fixes any more', 'lifecycle.html');
    if (l.available && l.eol) push(60 + Math.min(20, l.eol), l.eol + ' item(s) past end of life', (l.servers_eol || 0) + ' servers, ' + (l.network_eol || 0) + ' network', 'lifecycle.html');
    if (s.available && s.failed_disks) push(88, s.failed_disks + ' failed disk(s) in storage', 'redundancy is reduced until replaced', 'storage.html');
    if (storage_forecast.measured && storage_forecast.at85 && storage_forecast.at85.date) { const d = Math.round((Date.parse(storage_forecast.at85.date) - now()) / DAY); if (d <= 90) push(75 + Math.max(0, 90 - d) / 6, 'Storage reaches 85 % around ' + storage_forecast.at85.date, storage_forecast.at85.why, 'storage.html'); }
    if (c.available && c.expired) push(65 + c.expired, c.expired + ' support contract(s) expired', 'no vendor support on the covered assets', 'support-contracts.html');
    if (c.available && c.expiring) push(50 + c.expiring, c.expiring + ' support contract(s) expiring', 'start the renewals', 'support-contracts.html');
    if (r.available && r.warranty && r.warranty.expired) push(45, r.warranty.expired + ' device warranty(ies) expired', 'servers, network or storage', 'warranty.html');
    for (const u of unusual) if (u.change < 0) push(70, u.name + ' dropped unusually', u.why, AREAS.find((a) => a.id === u.id) ? AREAS.find((a) => a.id === u.id).link : 'infra-manager.html');
    wl.sort((x, y) => y.score - x.score);
    return { generated_at: new Date(now()).toISOString(), health: h, storage_forecast, unusual, worklist: wl.slice(0, 12), history: hist.map((x) => Object.assign({ day: x.id }, x)), overview: o,
      note: 'Every figure comes from the asset register and its add-ons; an area without a source is not measured and is left out of the index.' };
  }
  function cio() {
    const o = overview(), h = areaScores(o, o.register);
    let lic = []; try { lic = app.store.collection('licences').all((x) => x.status !== 'inactive'); } catch (e) { K.warn('licences', e); }
    let con = []; try { con = app.store.collection('support_contracts').all((x) => !x.retired && !x.deleted); } catch (e) { K.warn('contracts', e); }
    const renewals = renewalWave(lic, con, today());
    let budget = null; try { const bi = A().budgetIntel; if (bi) { const v = bi.view(); budget = { fy: v.fy, elapsed_pct: v.elapsed_pct, envelopes: Object.values(v.forecast.envelopes || {}).map((f) => ({ envelope: f.envelope, p50: f.p50, p90: f.p90, ceiling: f.ceiling, p_over_ceiling: f.p_over_ceiling })), why: v.forecast.why, unpriced: v.unpriced }; } } catch (e) { K.warn('budget', e); }
    let posture = null; try { const H = app.store.collection('ciso_history').all().sort((a, b) => a.at - b.at).filter((x) => x.overall != null);
      if (H.length) { const last = H[H.length - 1], old = H.filter((x) => x.at <= last.at - 30 * DAY + 3600000).pop() || H[0];
        posture = { overall: last.overall, grade: last.grade, day: last.day, change_30d: old && old !== last ? last.overall - old.overall : null, since: old && old !== last ? old.day : null, points: H.slice(-90).map((x) => ({ day: x.day, overall: x.overall })) }; } } catch (e) { K.warn('posture', e); }
    const tw = [], add = (score, title, why, link) => tw.push({ score: Math.round(score), title, why, link });
    const soon = []; for (const m of renewals.months.slice(0, 2)) for (const x of m.list) { const d = Math.round((Date.parse(x.date) - Date.parse(today())) / DAY); if (d <= 30) soon.push(Object.assign({ days: d }, x)); }
    for (const x of soon.slice(0, 5)) add(60 + (x.amount ? Math.min(30, Math.log10(x.amount) * 5) : 5) + (x.overdue ? 15 : 0), (x.overdue ? 'Overdue renewal: ' : 'Renewal in ' + x.days + ' days: ') + x.title, x.amount ? 'SAR ' + x.amount.toLocaleString('en-US') : 'no cost recorded', x.kind === 'licence' ? 'licences.html' : 'support-contracts.html');
    if (budget) for (const e of budget.envelopes) if (e.p_over_ceiling != null && e.p_over_ceiling >= 30) add(50 + e.p_over_ceiling / 2, (e.envelope === 'cyber' ? 'Cyber Security' : 'IT Operations') + ' budget: ' + e.p_over_ceiling + '% chance of going over', 'P50 ' + (e.p50 || 0).toLocaleString('en-US') + ' against a ceiling of ' + (e.ceiling || 0).toLocaleString('en-US'), 'budget.html#ai');
    if (posture && posture.change_30d != null && posture.change_30d <= -5) add(80, 'Security posture down ' + Math.abs(posture.change_30d) + ' points in 30 days', 'now ' + posture.overall + ' (' + posture.grade + ')', 'ai-ciso.html');
    if (h.overall != null && h.overall < 70) add(70, 'Infrastructure health ' + h.overall + '/100', 'weakest: ' + h.areas.filter((a) => a.measured).sort((a, b) => a.score - b.score)[0].name, 'infra-manager.html');
    if (renewals.peak && renewals.peak.share_pct >= 35) add(55, 'Renewal peak in ' + renewals.peak.month + ' (' + renewals.peak.share_pct + '% of the 12-month total)', 'plan cash or negotiate co-terming', 'licences.html');
    tw.sort((a, b) => b.score - a.score);
    return { generated_at: new Date(now()).toISOString(), renewals, budget, posture, infra: { overall: h.overall, measured: h.measured, of: h.of, areas: h.areas.map((a) => ({ id: a.id, name: a.name, score: a.score, measured: a.measured, link: a.link })) }, this_week: tw.slice(0, 10),
      note: 'Renewals come from licences and support contracts with an end date in the next 12 months; one without a cost is counted as unpriced, never as 0.' };
  }
  return { cio, infra, ask: K.ask, TOOLS: K.TOOLS, start: () => K.start(snapshot), stop: K.stop, snapshot };
}

function registerLeaderIntel(srv, app, opts) {
  const X = createLeaderIntel(app, opts || {});
  (app.addons = app.addons || {}).leaderIntel = X;
  srv.route('GET', '/leader-intel/cio', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return X.cio(); });
  srv.route('GET', '/leader-intel/infra', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return X.infra(); });
  srv.route('POST', '/leader-intel/ask', (ctx) => { ctx.need('operator'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
  X.start();
  return X;
}

module.exports = { createLeaderIntel, registerLeaderIntel, areaScores, renewalWave };
