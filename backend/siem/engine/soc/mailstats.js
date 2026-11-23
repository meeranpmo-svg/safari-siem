// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Mail volume for the Email dashboard: how many messages were sent to the Internet, received from the Internet, sent and
 * received internally, and how much spam the gateway saw. GET /api/soc/mail/stats?range=1|7|30&domains=a.com,b.com
 *
 * From Exchange message tracking (src_type exchange, category email), counting MESSAGES (unique message-id) not log lines:
 *   received from the Internet  DELIVER to a mailbox, sender outside our domains
 *   internal                    DELIVER to a mailbox, sender inside our domains
 *   sent to the Internet        SEND by a sender inside our domains with at least one recipient outside them
 * Our domains are passed by the page (Domains & Hosting). Without them the internal / external split cannot be made and
 * is reported as such. From the email gateway (vendor_class email_gateway): inbound / outbound events and the spam,
 * phishing and malware verdicts by action. When Exchange is not connected, the gateway's inbound / outbound counts are
 * the sent / received figures and "internal" is not available (the gateway never sees internal mail) - never 0.
 * Aggregates only (counts and domain names, no addresses): any signed-in role. Audited. Every value a parameter.
 */
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');
const RANGES = { 1: 24, 7: 7, 30: 30 };   // days -> buckets (hours for 1 day, days otherwise)
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const MID = "if(fields['message_id'] != '', fields['message_id'], fields['internal_message_id'])";
const DOM = (c) => `lower(substring(${c}, position(${c}, '@') + 1))`;

function options(q, now) {
  const days = RANGES[Number(q.range)] ? Number(q.range) : 7;
  const domains = String(q.domains || '').split(',').map((d) => d.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);
  if (domains.length > 20) throw new HttpError(400, 'at most 20 domains');
  for (const d of domains) if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) || d.length > 200) throw new HttpError(400, 'invalid domain: ' + d.slice(0, 60));
  const to = now, from = to - days * 86400000, bucket = days === 1 ? 3600000 : 86400000;
  return { days, domains, from, to, bucket, buckets: RANGES[days] };
}

async function stats(ch, db, o) {
  const T = `${db}.events`;
  const p = { t_from: { type: 'Int64', value: o.from }, t_to: { type: 'Int64', value: o.to }, d: { type: 'Array(String)', value: o.domains }, b: { type: 'Int64', value: o.bucket } };
  const W = 'ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts < fromUnixTimestamp64Milli({t_to:Int64})';
  const EX = `${W} AND src_type = 'exchange' AND category = 'email'`, GW = `${W} AND fields['vendor_class'] = 'email_gateway'`;
  const inner = `has({d:Array(String)}, ${DOM('user')})`;
  const recv = `action = 'deliver' AND user != '' AND NOT ${inner}`, intl = `action = 'deliver' AND ${inner}`;
  const sent = `action = 'send' AND ${inner} AND arrayExists(r -> r != '' AND NOT has({d:Array(String)}, ${DOM('r')}), splitByChar(';', fields['recipients']))`;
  const q = (tag, sql) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true });
  const split = o.domains.length > 0;
  const [exN, tot, series, gw, spam, topR, topS] = await Promise.all([
    q('ms_ex', `SELECT count() AS n FROM ${T} WHERE ${EX}`),
    split ? q('ms_tot', `SELECT uniqExactIf(${MID}, ${recv}) AS r, uniqExactIf(${MID}, ${intl}) AS i, uniqExactIf(${MID}, ${sent}) AS s FROM ${T} WHERE ${EX}`) : [],
    split ? q('ms_series', `SELECT intDiv(toUnixTimestamp64Milli(ts) - {t_from:Int64}, {b:Int64}) AS k, uniqExactIf(${MID}, ${recv}) AS r, uniqExactIf(${MID}, ${intl}) AS i, uniqExactIf(${MID}, ${sent}) AS s FROM ${T} WHERE ${EX} GROUP BY k ORDER BY k`) : [],
    q('ms_gw', `SELECT fields['email_direction'] AS dir, count() AS n FROM ${T} WHERE ${GW} GROUP BY dir`),
    q('ms_spam', `SELECT fields['email_verdict'] AS v, if(fields['email_action'] != '', fields['email_action'], 'other') AS a, count() AS n FROM ${T} WHERE ${GW} AND fields['email_verdict'] IN ('spam', 'phishing', 'malware') GROUP BY v, a`),
    split ? q('ms_top_r', `SELECT ${DOM('user')} AS dom, uniqExact(${MID}) AS n FROM ${T} WHERE ${EX} AND ${recv} GROUP BY dom ORDER BY n DESC LIMIT 10`) : [],
    split ? q('ms_top_s', `SELECT ${DOM('r')} AS dom, uniqExact(${MID}) AS n FROM ${T} ARRAY JOIN splitByChar(';', fields['recipients']) AS r WHERE ${EX} AND ${sent} AND r != '' AND NOT has({d:Array(String)}, ${DOM('r')}) GROUP BY dom ORDER BY n DESC LIMIT 10`) : [],
  ]);
  const exchange = num((exN[0] || {}).n) > 0;
  const g = {}; for (const r of gw) g[String(r.dir || 'unknown')] = num(r.n);
  const gateway = Object.values(g).some((n) => n > 0);
  const sp = { spam: { total: 0, by_action: {} }, phishing: { total: 0, by_action: {} }, malware: { total: 0, by_action: {} } };
  for (const r of spam) { const x = sp[r.v]; if (!x) continue; x.total += num(r.n); x.by_action[r.a] = (x.by_action[r.a] || 0) + num(r.n); }
  let totals, source;
  if (exchange && split) {
    const t = tot[0] || {};
    totals = { received_external: num(t.r), sent_external: num(t.s), internal: num(t.i) }; source = 'exchange';
  } else if (gateway) {
    totals = { received_external: g.inbound || 0, sent_external: g.outbound || 0, internal: null }; source = 'gateway';
  } else { totals = { received_external: null, sent_external: null, internal: null }; source = 'none'; }
  const byK = new Map(series.map((r) => [num(r.k), r])), daily = [];
  if (source === 'exchange') for (let i = 0; i < o.buckets; i++) { const r = byK.get(i) || {}; daily.push({ t: o.from + i * o.bucket, received: num(r.r), sent: num(r.s), internal: num(r.i) }); }
  const inbound = g.inbound || 0;
  return {
    range_days: o.days, from: o.from, to: o.to, bucket_ms: o.bucket, source, exchange, gateway, domains_used: o.domains, totals,
    spam: Object.assign(sp.spam, { share_of_inbound_pct: inbound ? Math.round(sp.spam.total * 1000 / inbound) / 10 : null }), phishing: sp.phishing, malware: sp.malware,
    gateway_counts: { inbound: g.inbound || 0, outbound: g.outbound || 0 }, series: daily,
    top_received_domains: topR.map((r) => ({ domain: r.dom, n: num(r.n) })), top_sent_domains: topS.map((r) => ({ domain: r.dom, n: num(r.n) })),
    note: source === 'exchange' ? 'Messages counted once each (unique message-id) from Exchange message tracking; internal = sender and delivery inside your domains.'
      : source === 'gateway' ? (exchange ? 'Exchange message tracking is connected but no mail domains were given - add them in Domains & Hosting to split internal from Internet mail; gateway counts shown.' : 'Exchange message tracking is not connected: sent / received are the gateway\'s outbound / inbound events, and internal mail (which never passes the gateway) cannot be counted.')
        : 'Neither Exchange message tracking nor the email gateway has sent logs to the SIEM for this period.',
  };
}

function register(api, deps) {
  const P = prefixOf(deps), { ch } = deps;
  const db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  const now = deps.now || Date.now;
  api.route('GET', `${P}/mail/stats`, wrap(deps, null, async (ctx) => {
    const o = options(ctx.query || {}, now());
    const r = await stats(ch, db, o);
    audit(ctx, 'mail.stats.view', 'mail', { range: o.days, domains: o.domains.length, source: r.source });
    return ctx.ok(r);
  }));
  // counts for every signed-in role; addresses (top senders / recipients) for administrators only
  api.route('GET', `${P}/mail/traffic`, wrap(deps, null, async (ctx) => {
    const o = trafficOptions(ctx.query || {}, now()), named = ctx.role === 'admin';
    const r = await traffic(ch, db, o, { named });
    audit(ctx, 'mail.traffic.view', o.domain || 'mail', { range: o.days, domains: o.domains.length, dir: o.dir, named });
    return ctx.ok(r);
  }));
}

/*
 * Mail traffic for Exchange Reports (Traffic tab, Reporting Center): GET /api/soc/mail/traffic
 *   ?range=1|7|30 &domains=ours.sa,… &domain=partner.com &dir=all|in|out &limit=5-100
 * From Exchange message tracking only, counting unique messages: delivered / sent / failed / deferred / DSN / dropped,
 * failure reasons (the SMTP status text with every address replaced by <address>), internal vs Internet (needs our
 * domains), traffic to / from one chosen domain, by hour of day and day of week (Riyadh time), the daily series and the
 * message size distribution (RECEIVE events, largest size seen per message). Top senders and recipients BY ADDRESS are
 * personal data: only an administrator gets them (named: true); everyone else gets the counts. Subjects are never read.
 */
const { body: checkBody } = require('../util/check');
const DOMAIN_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const SIZE_BUCKETS = ['< 10 KB', '10-100 KB', '100 KB-1 MB', '1-5 MB', '5-10 MB', '10-25 MB', '> 25 MB'];
function trafficOptions(q, now) {
  const b = checkBody(q || {}).oneOf('range', ['1', '7', '30'], { def: '7' }).str('domains', { max: 2000, def: '' })
    .str('domain', { max: 200, def: '' }).oneOf('dir', ['all', 'in', 'out'], { def: 'all' }).int('limit', { min: 5, max: 100, def: 20 }).done();
  const domains = b.domains.split(',').map((d) => d.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);
  if (domains.length > 20) throw new HttpError(400, 'domains: at most 20');
  for (const d of domains) if (!DOMAIN_RE.test(d) || d.length > 200) throw new HttpError(400, 'domains: invalid domain ' + d.slice(0, 60));
  const domain = b.domain.toLowerCase().replace(/\.$/, '');
  if (domain && !DOMAIN_RE.test(domain)) throw new HttpError(400, 'domain must be a domain name such as partner.com');
  if (b.dir !== 'all' && !domains.length) throw new HttpError(400, 'dir needs domains (your own mail domains) to tell inbound from outbound');
  const days = Number(b.range), to = now, from = to - days * 86400000, bucket = days === 1 ? 3600000 : 86400000;
  return { days, domains, domain, dir: b.dir, limit: b.limit, from, to, bucket, buckets: RANGES[days] };
}

async function traffic(ch, db, o, { named = false } = {}) {
  const T = `${db}.events`;
  const p = { t_from: { type: 'Int64', value: o.from }, t_to: { type: 'Int64', value: o.to }, d: { type: 'Array(String)', value: o.domains }, b: { type: 'Int64', value: o.bucket },
    pd: { type: 'String', value: o.domain }, lim: { type: 'UInt32', value: o.limit } };
  const W = 'ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts < fromUnixTimestamp64Milli({t_to:Int64})';
  const EX = `${W} AND src_type = 'exchange' AND category = 'email'`;
  const RCPT = "splitByChar(';', fields['recipients'])";
  const inner = (c) => `has({d:Array(String)}, ${DOM(c)})`;
  const split = o.domains.length > 0;
  // the chosen partner domain: mail received FROM it (sender) or sent TO it (any recipient)
  const fromD = `${DOM('user')} = {pd:String}`, toD = `arrayExists(r -> ${DOM('r')} = {pd:String}, ${RCPT})`;
  const dirS = o.dir === 'in' ? ` AND NOT ${inner('user')}` : o.dir === 'out' ? ` AND ${inner('user')}` : '';
  const dirR = o.dir === 'in' ? ` AND ${inner('r')}` : o.dir === 'out' ? ` AND NOT ${inner('r')}` : '';
  const scope = o.domain ? ` AND (${fromD} OR ${toD})` : '';
  const q = (tag, sql) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true });
  const recv = `action = 'deliver' AND user != '' AND NOT ${inner('user')}`, intl = `action = 'deliver' AND ${inner('user')}`;
  const sent = `action = 'send' AND ${inner('user')} AND arrayExists(r -> r != '' AND NOT ${inner('r')}, ${RCPT})`;
  const MAIN = "('receive', 'send', 'deliver', 'fail', 'defer', 'dsn', 'drop')";
  const [exN, st, reasons, series, hours, dow, sizes, split3, pdom, senders, rcpts] = await Promise.all([
    q('tr_ex', `SELECT count() AS n FROM ${T} WHERE ${EX}`),
    q('tr_status', `SELECT action AS a, uniqExact(${MID}) AS n FROM ${T} WHERE ${EX} AND action IN ${MAIN}${scope} GROUP BY a`),
    q('tr_reasons', `SELECT left(replaceRegexpAll(fields['recipient_status'], '[^\\\\s@<>;,]+@[^\\\\s@<>;,]+', '<address>'), 160) AS reason, action AS a, uniqExact(${MID}) AS n FROM ${T} WHERE ${EX} AND action IN ('fail', 'drop', 'defer') AND fields['recipient_status'] != ''${scope} GROUP BY reason, a ORDER BY n DESC LIMIT 20`),
    q('tr_series', `SELECT intDiv(toUnixTimestamp64Milli(ts) - {t_from:Int64}, {b:Int64}) AS k, uniqExactIf(${MID}, action = 'receive') AS rcv, uniqExactIf(${MID}, action = 'deliver') AS dlv, uniqExactIf(${MID}, action = 'send') AS snd, uniqExactIf(${MID}, action IN ('fail', 'drop')) AS fl FROM ${T} WHERE ${EX}${scope} GROUP BY k ORDER BY k`),
    q('tr_hours', `SELECT toHour(toTimeZone(ts, 'Asia/Riyadh')) AS h, uniqExact(${MID}) AS n FROM ${T} WHERE ${EX} AND action = 'receive'${scope} GROUP BY h ORDER BY h`),
    q('tr_dow', `SELECT toDayOfWeek(toTimeZone(ts, 'Asia/Riyadh')) AS d, uniqExact(${MID}) AS n FROM ${T} WHERE ${EX} AND action = 'receive'${scope} GROUP BY d ORDER BY d`),
    q('tr_sizes', `SELECT multiIf(sz < 10240, 0, sz < 102400, 1, sz < 1048576, 2, sz < 5242880, 3, sz < 10485760, 4, sz < 26214400, 5, 6) AS k, count() AS n, sum(sz) AS bytes FROM (SELECT ${MID} AS mid, max(toUInt64OrZero(fields['total_bytes'])) AS sz FROM ${T} WHERE ${EX} AND action = 'receive'${scope} GROUP BY mid) GROUP BY k ORDER BY k`),
    split ? q('tr_split', `SELECT uniqExactIf(${MID}, ${recv}) AS r, uniqExactIf(${MID}, ${intl}) AS i, uniqExactIf(${MID}, ${sent}) AS s FROM ${T} WHERE ${EX}${scope}`) : [],
    o.domain ? q('tr_domain', `SELECT uniqExactIf(${MID}, action = 'receive' AND ${fromD}) AS rf, uniqExactIf(${MID}, action IN ('send', 'deliver') AND ${toD}) AS st, uniqExactIf(${MID}, action IN ('fail', 'drop') AND ${toD}) AS fl FROM ${T} WHERE ${EX}`) : [],
    named ? q('tr_senders', `SELECT user AS a, uniqExact(${MID}) AS n, sum(toUInt64OrZero(fields['total_bytes'])) AS bytes FROM ${T} WHERE ${EX} AND action = 'receive' AND user != ''${o.domain ? ' AND ' + fromD : ''}${dirS} GROUP BY a ORDER BY n DESC LIMIT {lim:UInt32}`) : [],
    named ? q('tr_rcpts', `SELECT r AS a, uniqExact(${MID}) AS n FROM ${T} ARRAY JOIN ${RCPT} AS r WHERE ${EX} AND action IN ('deliver', 'send') AND r != ''${o.domain ? ` AND ${DOM('r')} = {pd:String}` : ''}${dirR} GROUP BY a ORDER BY n DESC LIMIT {lim:UInt32}`) : [],
  ]);
  const exchange = num((exN[0] || {}).n) > 0;
  const by = {}; for (const r of st) by[String(r.a)] = num(r.n);
  const byK = new Map(series.map((r) => [num(r.k), r])), daily = [];
  for (let i = 0; i < o.buckets; i++) { const r = byK.get(i) || {}; daily.push({ t: o.from + i * o.bucket, received: num(r.rcv), delivered: num(r.dlv), sent: num(r.snd), failed: num(r.fl) }); }
  const hr = Array.from({ length: 24 }, (_, h) => ({ hour: h, n: 0 })); for (const r of hours) if (hr[num(r.h)]) hr[num(r.h)].n = num(r.n);
  const DOW = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], dw = DOW.map((d) => ({ day: d, n: 0 })); for (const r of dow) { const i = num(r.d) - 1; if (dw[i]) dw[i].n = num(r.n); }
  const sz = SIZE_BUCKETS.map((label) => ({ label, n: 0 })); let msgs = 0, bytes = 0; for (const r of sizes) { const k = num(r.k); if (sz[k]) sz[k].n = num(r.n); msgs += num(r.n); bytes += num(r.bytes); }
  const code = (s) => (/\b([245]\.\d{1,3}\.\d{1,3})\b/.exec(s) || /^(\d{3})\b/.exec(s) || [])[1] || '';
  const sp = split3[0] || {}, pd = pdom[0] || {};
  return {
    range_days: o.days, from: o.from, to: o.to, bucket_ms: o.bucket, exchange, domains_used: o.domains, domain: o.domain || null, dir: o.dir, named,
    status: { received: by.receive || 0, delivered: by.deliver || 0, sent: by.send || 0, failed: by.fail || 0, deferred: by.defer || 0, dsn: by.dsn || 0, dropped: by.drop || 0 },
    reasons: reasons.map((r) => ({ reason: String(r.reason || ''), code: code(String(r.reason || '')), status: String(r.a), n: num(r.n) })),
    split: split ? { received_external: num(sp.r), sent_external: num(sp.s), internal: num(sp.i) } : null,
    partner: o.domain ? { domain: o.domain, received_from: num(pd.rf), sent_to: num(pd.st), failed_to: num(pd.fl) } : null,
    series: daily, by_hour: hr, by_weekday: dw, sizes: sz, average_kb: msgs ? Math.round(bytes / msgs / 102.4) / 10 : null,
    top_senders: named ? senders.map((r) => ({ address: String(r.a), n: num(r.n), mb: Math.round(num(r.bytes) / 104857.6) / 10 })) : null,
    top_recipients: named ? rcpts.map((r) => ({ address: String(r.a), n: num(r.n) })) : null,
    note: !exchange ? 'No Exchange message tracking has reached the SIEM for this period: forward the MSGTRK logs (agents/exchange) to see mail traffic.'
      : (named ? '' : 'Top senders and recipients by address are shown to administrators only (PDPL). ') + 'Unique messages from Exchange message tracking; subjects are never read.' + (split ? '' : ' Add your mail domains to split internal from Internet mail.'),
  };
}

module.exports = { register, stats, options, traffic, trafficOptions, SIZE_BUCKETS };
