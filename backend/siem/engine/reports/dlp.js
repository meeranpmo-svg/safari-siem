// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * DLP analysis and reports over the incidents the SIEM already normalises (action = 'dlp-incident', fields.dlp_*):
 * Somansa Privacy-i / Mail-i / Server-i (parse/somansa.js) and the CEF DLP vendors - Forcepoint, Symantec, Trend Micro
 * (parse/cef-vendors.js dlp()). Agent / protection disabled on a DLP agent = action 'agent-tamper' with vendor_class dlp.
 * Data: ClickHouse siem.events only, read-only and bounded. Nothing is estimated: a failed query → that panel is null.
 *
 * "Left" = the DLP product let the data go (permitted / released) - the incidents that matter most. Encrypted is counted
 * apart (it left, protected). An incident whose action the product did not report is "not reported", never assumed.
 *
 * Person risk (0-100) is a simple weighted sum so it survives an audit question; every point is itemised in why[]:
 *   data left           5 per incident, max 30        sensitive data class   10 per class (national ID, IBAN, card,
 *   high severity       3 per incident, max 15                                health / medical, salary, policy / claim), max 20
 *   many channels       +10 at 3+ channels            after hours            +10 when ≥ 3 and ≥ 30 % of the person's incidents
 *   volume              +5 at 100+ matches, +10 at 500+   DLP agent disabled  +20 (tamper on the person's account)
 * Behavioural indicators, not proof of wrongdoing (PDPL): names are for operators and administrators only.
 *
 *   createDlp({ ch, config, log, now, calendar() }) → { summary(query, {names}), events(query), report(query, opts) → {html, text, subject},
 *     csv(query), riskOf(row), SQL }
 */
const { resolvePeriod, TIME_WHERE, tparams, runQueries, fillBuckets, toMs, esc } = require('./common');

const LEFT = ['permitted', 'released'];
const BLOCKED = ['blocked', 'quarantined'];
const SENSITIVE = [
  ['National ID / Iqama / passport', /national\s*id|\bnid\b|iqama|passport|identity|هوية|إقامة/i],
  ['Bank account / IBAN', /\biban\b|bank\s*account|account\s*number|حساب/i],
  ['Payment card', /credit\s*card|card\s*number|\bpan\b|\bpci\b|بطاقة/i],
  ['Health / medical', /health|medical|diagnos|patient|icd|صحي|طبي/i],
  ['Salary / payroll', /salary|payroll|راتب|رواتب/i],
  ['Policy / claim data', /policy\s*holder|policyholder|claim|underwrit|premium|مطالب|وثيقة/i],
  ['Personal data (PII)', /\bpii\b|personal|phone|mobile|address|e-?mail\s*address|بيانات شخصية/i],
];
const CHANNEL = (c) => {
  const s = String(c || '').toLowerCase();
  if (!s) return 'not reported';
  if (/usb|removable|storage|media/.test(s)) return 'usb';
  if (/print/.test(s)) return 'print';
  if (/mail|smtp|outlook|exchange/.test(s)) return 'email';
  if (/upload|web|http|browser|cloud|drive|share/.test(s)) return 'web / cloud';
  if (/clip/.test(s)) return 'clipboard';
  if (/network|ftp|smb|share/.test(s)) return 'network';
  if (/screen|capture/.test(s)) return 'screen capture';
  if (/messeng|chat|teams|whatsapp|telegram/.test(s)) return 'messenger';
  return s.slice(0, 40);
};
const sevOf = (n) => ['info', 'low', 'medium', 'high', 'critical'][Math.max(0, Math.min(4, Number(n) || 0))];
const num = (v) => Number(v) || 0;
const arr = (v) => (Array.isArray(v) ? v.map(String).filter(Boolean) : []);

function sql(cal, db = 'siem') {
  const ah = cal ? cal.sql({ ts: 'ts', src: 'src_id' }) : { expr: 'toUInt8(0)', params: {} };
  // one inner projection, the aggregates read only its aliases (ClickHouse alias rule - common.aliasViolations)
  const BASE = `SELECT ts, user, host, src_id, severity, lower(fields['dlp_action']) AS act, lower(fields['dlp_channel']) AS chan,
      fields['dlp_policy'] AS pol, fields['dlp_classification'] AS cls, lower(fields['dlp_vendor']) AS vendor, fields['dlp_product'] AS product,
      fields['dlp_destination'] AS dest, fields['dlp_file'] AS file, fields['dlp_incident_id'] AS incident_id, fields['dlp_severity'] AS dsev,
      toUInt64OrZero(fields['dlp_match_count']) AS matches, ${ah.expr} AS ah, message
    FROM ${db}.events WHERE ${TIME_WHERE} AND action = 'dlp-incident'`;
  const L = `act IN ('permitted', 'released')`, B = `act IN ('blocked', 'quarantined')`;
  return {
    params: ah.params,
    totals: `/* sentra:dlp-totals */ SELECT count() AS n, countIf(${L}) AS n_left, countIf(${B}) AS n_blocked, countIf(act = 'encrypted') AS n_enc,
        countIf(act = '') AS n_unreported, uniqExactIf(user, user != '') AS n_users, uniqExactIf(host, host != '') AS n_hosts,
        countIf(severity >= 3) AS n_high, countIf(ah = 1) AS n_ah, sum(matches) AS n_matches FROM (${BASE})`,
    channels: `/* sentra:dlp-channels */ SELECT chan AS c, count() AS n, countIf(${L}) AS n_left, countIf(${B}) AS n_blocked FROM (${BASE}) GROUP BY c ORDER BY n DESC LIMIT 40`,
    policies: `/* sentra:dlp-policies */ SELECT pol AS p, count() AS n, countIf(${L}) AS n_left, countIf(${B}) AS n_blocked, uniqExactIf(user, user != '') AS people FROM (${BASE}) GROUP BY p ORDER BY n DESC LIMIT 40`,
    classes: `/* sentra:dlp-classes */ SELECT cls AS k, count() AS n, countIf(${L}) AS n_left FROM (${BASE}) GROUP BY k ORDER BY n DESC LIMIT 40`,
    actions: `/* sentra:dlp-actions */ SELECT act AS a, count() AS n FROM (${BASE}) GROUP BY a ORDER BY n DESC LIMIT 20`,
    sources: `/* sentra:dlp-sources */ SELECT vendor AS v, product AS pr, src_id AS s, count() AS n, max(toUnixTimestamp64Milli(ts)) AS last_ms FROM (${BASE}) GROUP BY v, pr, s ORDER BY n DESC LIMIT 50`,
    trend: `/* sentra:dlp-trend */ SELECT intDiv(toUnixTimestamp64Milli(ts) + {t_off:Int64}, {t_bucket:Int64}) AS b, count() AS n, countIf(${L}) AS n_left FROM (${BASE}) GROUP BY b ORDER BY b`,
    users: `/* sentra:dlp-users */ SELECT user AS u, count() AS n, countIf(${L}) AS n_left, countIf(${B}) AS n_blocked, countIf(severity >= 3) AS n_high,
        countIf(ah = 1) AS n_ah, sum(matches) AS n_matches, uniqExact(chan) AS n_chan, groupUniqArray(12)(chan) AS chans, groupUniqArray(20)(cls) AS classes,
        groupUniqArray(10)(host) AS hosts, max(toUnixTimestamp64Milli(ts)) AS last_ms FROM (${BASE}) WHERE user != '' GROUP BY u ORDER BY n DESC LIMIT 300`,
    hostsQ: `/* sentra:dlp-hosts */ SELECT host AS h, count() AS n, countIf(${L}) AS n_left, uniqExactIf(user, user != '') AS people, max(toUnixTimestamp64Milli(ts)) AS last_ms FROM (${BASE}) WHERE host != '' GROUP BY h ORDER BY n DESC LIMIT 100`,
    dests: `/* sentra:dlp-dests */ SELECT dest AS d, count() AS n, uniqExactIf(user, user != '') AS people FROM (${BASE}) WHERE ${L} AND dest != '' GROUP BY d ORDER BY n DESC LIMIT 30`,
    tamper: `/* sentra:dlp-tamper */ SELECT toUnixTimestamp64Milli(ts) AS t, user, host, fields['dlp_product'] AS pr, message FROM ${db}.events
        WHERE ${TIME_WHERE} AND action = 'agent-tamper' AND fields['vendor_class'] = 'dlp' ORDER BY ts DESC LIMIT 200`,
    events: (f) => `/* sentra:dlp-events */ SELECT toUnixTimestamp64Milli(ts) AS t, user, host, src_id, severity, act, chan, pol, cls, vendor, product, dest, file, incident_id, dsev, matches, ah, message
        FROM (${BASE}) WHERE 1 = 1${f.user ? ' AND user = {f_user:String}' : ''}${f.host ? ' AND host = {f_host:String}' : ''}${f.policy ? ' AND pol = {f_pol:String}' : ''}${f.channel ? ' AND chan = {f_chan:String}' : ''}${f.cls ? ' AND cls = {f_cls:String}' : ''}${f.left ? ` AND ${L}` : ''}
        ORDER BY ts DESC LIMIT {f_lim:UInt32}`,
  };
}

function riskOf(r, tamperByUser) {
  const why = []; let s = 0;
  const add = (p, reason) => { if (p > 0) { s += p; why.push({ points: p, reason }); } };
  add(Math.min(30, num(r.n_left) * 5), `${num(r.n_left)} incident(s) where the DLP product let the data go`);
  const cls = arr(r.classes);
  const hit = SENSITIVE.filter(([, re]) => cls.some((c) => re.test(c))).map(([k]) => k);
  add(Math.min(20, hit.length * 10), hit.length ? `sensitive data class(es): ${hit.join(', ')}` : '');
  add(Math.min(15, num(r.n_high) * 3), `${num(r.n_high)} high / critical incident(s)`);
  if (num(r.n_chan) >= 3) add(10, `${num(r.n_chan)} different channels (${arr(r.chans).map(CHANNEL).filter((x, i, a) => a.indexOf(x) === i).join(', ')})`);
  if (num(r.n_ah) >= 3 && num(r.n_ah) / Math.max(1, num(r.n)) >= 0.3) add(10, `${num(r.n_ah)} of ${num(r.n)} outside working hours`);
  const m = num(r.n_matches); if (m >= 500) add(10, `${m} sensitive matches in total`); else if (m >= 100) add(5, `${m} sensitive matches in total`);
  const t = tamperByUser ? num(tamperByUser.get(String(r.u || '').toLowerCase())) : 0;
  if (t) add(20, `DLP agent or protection disabled ${t} time(s) on this account`);
  return { score: Math.min(100, s), why, sensitive: hit };
}

function createDlp(o = {}) {
  const ch = o.ch; const now = o.now || Date.now;
  const cal = typeof o.calendar === 'function' ? o.calendar : () => null;
  const off = () => { const c = cal(); return (c && c.config && c.config.utc_offset_min) || 180; };
  const db = (o.config && o.config.clickhouse && o.config.clickhouse.database) || 'siem';

  async function summary(query = {}, opts = {}) {
    const p = resolvePeriod(query, now(), { dflt: '30d' });
    const S = sql(cal(), db); const params = Object.assign(tparams(p, off()), S.params);
    const names = opts.names !== false;
    const spec = { totals: [S.totals, params], channels: [S.channels, params], policies: [S.policies, params], classes: [S.classes, params], actions: [S.actions, params],
      sources: [S.sources, params], trend: [S.trend, params], tamper: [S.tamper, params] };
    if (names) Object.assign(spec, { users: [S.users, params], hosts: [S.hostsQ, params], dests: [S.dests, params] });
    const { results: R, errors } = await runQueries(ch, spec);
    const t = R.totals && R.totals[0] ? R.totals[0] : null;
    const tamperBy = new Map();
    for (const x of R.tamper || []) { const u = String(x.user || '').toLowerCase(); if (u) tamperBy.set(u, (tamperBy.get(u) || 0) + 1); }
    const chanMap = new Map();
    for (const c of R.channels || []) { const k = CHANNEL(c.c); const cur = chanMap.get(k) || { channel: k, incidents: 0, left: 0, blocked: 0 }; cur.incidents += num(c.n); cur.left += num(c.n_left); cur.blocked += num(c.n_blocked); chanMap.set(k, cur); }
    const users = names && R.users ? R.users.map((r) => { const k = riskOf(r, tamperBy); return { user: String(r.u), incidents: num(r.n), left: num(r.n_left), blocked: num(r.n_blocked), high: num(r.n_high),
      after_hours: num(r.n_ah), matches: num(r.n_matches), channels: [...new Set(arr(r.chans).map(CHANNEL))], classes: arr(r.classes).slice(0, 10), hosts: arr(r.hosts), last_ms: toMs(r.last_ms) || 0,
      risk: k.score, why: k.why, sensitive: k.sensitive, tamper: tamperBy.get(String(r.u).toLowerCase()) || 0 }; }).sort((a, b) => b.risk - a.risk || b.incidents - a.incidents) : null;
    return {
      generated_at: now(), period: Object.assign({}, p, { utc_offset_min: off() }), clickhouse: { ok: !errors.length, errors },
      available: !!(t && num(t.n)) || !!(R.tamper && R.tamper.length),
      totals: t ? { incidents: num(t.n), left: num(t.n_left), blocked: num(t.n_blocked), encrypted: num(t.n_enc), not_reported: num(t.n_unreported), people: num(t.n_users),
        hosts: num(t.n_hosts), high: num(t.n_high), after_hours: num(t.n_ah), matches: num(t.n_matches), tamper: (R.tamper || []).length } : null,
      channels: R.channels ? [...chanMap.values()].sort((a, b) => b.incidents - a.incidents) : null,
      policies: R.policies ? R.policies.map((r) => ({ policy: String(r.p || '') || 'not reported', incidents: num(r.n), left: num(r.n_left), blocked: num(r.n_blocked), people: num(r.people) })) : null,
      classes: R.classes ? R.classes.map((r) => { const k = String(r.k || ''); const s = SENSITIVE.find(([, re]) => re.test(k)); return { class: k || 'not reported', incidents: num(r.n), left: num(r.n_left), sensitive: s ? s[0] : '' }; }) : null,
      actions: R.actions ? R.actions.map((r) => ({ action: String(r.a || '') || 'not reported', incidents: num(r.n) })) : null,
      sources: R.sources ? R.sources.map((r) => ({ vendor: String(r.v || ''), product: String(r.pr || ''), src_id: String(r.s || ''), incidents: num(r.n), last_ms: toMs(r.last_ms) || 0 })) : null,
      trend: R.trend ? fillBuckets(R.trend, p, off(), ['n', 'n_left']) : null,
      users, hosts: names && R.hosts ? R.hosts.map((r) => ({ host: String(r.h), incidents: num(r.n), left: num(r.n_left), people: num(r.people), last_ms: toMs(r.last_ms) || 0 })) : null,
      destinations: names && R.dests ? R.dests.map((r) => ({ destination: String(r.d), incidents: num(r.n), people: num(r.people) })) : null,
      tamper_events: names && R.tamper ? R.tamper.map((r) => ({ ts: toMs(r.t) || 0, user: String(r.user || ''), host: String(r.host || ''), product: String(r.pr || ''), message: String(r.message || '').slice(0, 300) })) : null,
      names,
    };
  }

  async function events(query = {}) {
    const p = resolvePeriod(query, now(), { dflt: '30d' });
    const S = sql(cal(), db);
    const f = { user: String(query.user || '').trim().toLowerCase(), host: String(query.host || '').trim().toLowerCase(), policy: String(query.policy || ''), channel: String(query.channel || '').toLowerCase(), cls: String(query.class || ''), left: query.left === '1' || query.left === true };
    const lim = Math.max(1, Math.min(5000, Number(query.limit) || 200));
    const params = Object.assign(tparams(p, off()), S.params, { f_lim: { type: 'UInt32', value: lim } });
    if (f.user) params.f_user = { type: 'String', value: f.user };
    if (f.host) params.f_host = { type: 'String', value: f.host };
    if (f.policy) params.f_pol = { type: 'String', value: f.policy };
    if (f.channel) params.f_chan = { type: 'String', value: f.channel };
    if (f.cls) params.f_cls = { type: 'String', value: f.cls };
    if (!ch || typeof ch.query !== 'function') throw Object.assign(new Error('ClickHouse client not available'), { code: 503 });
    const rows = await ch.query(S.events(f), params, { readonly: true, timeout_ms: 30000 });
    return { period: p, items: (rows || []).map((r) => ({ ts: toMs(r.t) || 0, user: String(r.user || ''), host: String(r.host || ''), src_id: String(r.src_id || ''), severity: num(r.severity),
      action: String(r.act || '') || 'not reported', channel: CHANNEL(r.chan), channel_raw: String(r.chan || ''), policy: String(r.pol || ''), class: String(r.cls || ''), vendor: String(r.vendor || ''),
      product: String(r.product || ''), destination: String(r.dest || ''), file: String(r.file || ''), incident_id: String(r.incident_id || ''), matches: num(r.matches), after_hours: num(r.ah) === 1,
      message: String(r.message || '').slice(0, 400) })), limit: lim };
  }

  const cell = (v) => { const s = String(v === undefined || v === null ? '' : v); const g = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s; return /[",\n]/.test(g) ? `"${g.replace(/"/g, '""')}"` : g; };
  async function csv(query = {}) {
    const r = await events(Object.assign({}, query, { limit: query.limit || 5000 }));
    const head = ['time (UTC)', 'user', 'host', 'product', 'policy', 'channel', 'data class', 'action', 'file', 'destination', 'matches', 'severity', 'after hours', 'incident id'];
    const filt = ['user', 'host', 'policy', 'channel', 'class', 'left'].filter((k) => query[k]).map((k) => `${k}=${query[k]}`).join(' ') || 'none';
    const lines = [`# DLP incidents ${new Date(r.period.from).toISOString()} - ${new Date(r.period.to).toISOString()}; filter: ${filt}; rows: ${r.items.length}${r.items.length >= r.limit ? ' (limit reached - narrow the filter)' : ''}`, head.join(',')];
    for (const e of r.items) lines.push([new Date(e.ts).toISOString(), e.user, e.host, e.product || e.vendor, e.policy, e.channel_raw || e.channel, e.class, e.action, e.file, e.destination, e.matches, sevOf(e.severity), e.after_hours ? 'yes' : '', e.incident_id].map(cell).join(','));
    return { text: lines.join('\r\n') + '\r\n', rows: r.items.length };
  }

  async function report(query = {}, opts = {}) {
    const s = await summary(query, { names: true });
    const org = opts.org || ZYB_ORG.short;
    const fmt = (ms) => new Date(ms + off() * 60000).toISOString().slice(0, 16).replace('T', ' ');
    const T = s.totals || {};
    const th = 'style="text-align:left;padding:4px 8px;border-bottom:1px solid #ccc;background:#f4f6f8"', td = 'style="padding:4px 8px;border-bottom:1px solid #eee;vertical-align:top"';
    const tbl = (cols, rows) => rows.length ? `<table style="border-collapse:collapse;width:100%;font-size:12.5px;margin:6px 0 14px"><tr>${cols.map((c) => `<th ${th}>${esc(c)}</th>`).join('')}</tr>${rows.map((r) => `<tr>${r.map((c) => `<td ${td}>${c}</td>`).join('')}</tr>`).join('')}</table>` : '<p style="color:#666">None.</p>';
    const topUsers = (s.users || []).filter((u) => u.risk > 0).slice(0, 20);
    const subject = `${org} DLP report ${fmt(s.period.from).slice(0, 10)} → ${fmt(s.period.to).slice(0, 10)}: ${T.incidents || 0} incident(s), ${T.left || 0} let through`;
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>${esc(subject)}</title></head><body style="font-family:Segoe UI,Arial,sans-serif;color:#111;margin:24px;font-size:13px">`
      + `<h1 style="margin:0 0 4px;font-size:20px">${esc(org)} · Data Loss Prevention report</h1><p style="color:#555;margin:0 0 14px">${esc(fmt(s.period.from))} → ${esc(fmt(s.period.to))} (Riyadh) · generated ${esc(fmt(s.generated_at))}${opts.by ? ` by ${esc(opts.by)}` : ''}</p>`
      + (!s.clickhouse.ok ? `<p style="color:#b00"><b>Some figures could not be read:</b> ${esc(s.clickhouse.errors.map((e) => e.panel).join(', '))}. Those sections are left out rather than shown as zero.</p>` : '')
      + (!s.available ? '<p><b>No DLP incident reached the SIEM in this period.</b> Check under Sources that the DLP product is sending (Somansa: SIEM / syslog export to this server).</p>' : '')
      + tbl(['Incidents', 'Let through', 'Blocked / quarantined', 'Encrypted', 'Action not reported', 'People', 'Devices', 'High / critical', 'Outside working hours', 'Agent disabled'],
        [[T.incidents, T.left, T.blocked, T.encrypted, T.not_reported, T.people, T.hosts, T.high, T.after_hours, T.tamper].map((x) => esc(x === undefined ? '–' : x))])
      + '<h2 style="font-size:15px">By channel</h2>' + tbl(['Channel', 'Incidents', 'Let through', 'Blocked'], (s.channels || []).map((c) => [esc(c.channel), c.incidents, c.left, c.blocked]))
      + '<h2 style="font-size:15px">By policy</h2>' + tbl(['Policy', 'Incidents', 'Let through', 'Blocked', 'People'], (s.policies || []).slice(0, 20).map((c) => [esc(c.policy), c.incidents, c.left, c.blocked, c.people]))
      + '<h2 style="font-size:15px">By data class</h2>' + tbl(['Data class', 'Incidents', 'Let through', 'Sensitive'], (s.classes || []).slice(0, 20).map((c) => [esc(c.class), c.incidents, c.left, esc(c.sensitive)]))
      + '<h2 style="font-size:15px">People to review</h2><p style="color:#555;margin:0">Score = itemised weighted sum (see each row). Behavioural indicators, not proof of wrongdoing - review proportionately and record the outcome (PDPL).</p>'
      + tbl(['Person', 'Risk', 'Incidents', 'Let through', 'Why'], topUsers.map((u) => [esc(u.user), `<b>${u.risk}</b>`, u.incidents, u.left, esc(u.why.map((w) => `+${w.points} ${w.reason}`).join('; '))]))
      + '<h2 style="font-size:15px">DLP agent or protection disabled</h2>' + tbl(['Time', 'User', 'Device', 'Product'], (s.tamper_events || []).slice(0, 30).map((e) => [esc(fmt(e.ts)), esc(e.user), esc(e.host), esc(e.product)]))
      + '<h2 style="font-size:15px">Where data was let through to</h2>' + tbl(['Destination', 'Incidents', 'People'], (s.destinations || []).slice(0, 20).map((d) => [esc(d.destination), d.incidents, d.people]))
      + '<h2 style="font-size:15px">Sources reporting</h2>' + tbl(['Vendor', 'Product', 'Source', 'Incidents', 'Last seen'], (s.sources || []).map((x) => [esc(x.vendor), esc(x.product), esc(x.src_id), x.incidents, esc(x.last_ms ? fmt(x.last_ms) : '–')]))
      + `<p style="color:#666;font-size:11.5px;margin-top:18px">Source: ${esc(org)} SIEM (siem.events, DLP incidents as received from the DLP products). Mapped to SAMA CSF 3.3.3 (information classification) / 3.3.14 (event management), NCA ECC 2-7 (data and information protection) and PDPL Art. 19, 20 and 22 (continuous monitoring needs an impact assessment). Contains personal data - handle as Confidential.</p></body></html>`;
    const text = [`${org} - Data Loss Prevention report`, `${fmt(s.period.from)} -> ${fmt(s.period.to)} (Riyadh)`, '',
      `Incidents ${T.incidents || 0} · let through ${T.left || 0} · blocked ${T.blocked || 0} · people ${T.people || 0} · agent disabled ${T.tamper || 0}`, '',
      'People to review:', ...topUsers.slice(0, 10).map((u) => `- ${u.user}: ${u.risk} (${u.why.map((w) => w.reason).join('; ')})`), '', 'The full report is attached (HTML). Behavioural indicators, not proof of wrongdoing.'].join('\n');
    return { html, text, subject, summary: s };
  }

  return { summary, events, csv, report, riskOf, SQL: (c) => sql(c || cal(), db) };
}

module.exports = { createDlp, riskOf, CHANNEL, SENSITIVE, LEFT, BLOCKED };
