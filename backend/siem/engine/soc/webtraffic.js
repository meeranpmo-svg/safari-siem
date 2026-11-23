// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Portal traffic: what the customer portal's web server (nginx / Apache access logs, parse/webaccess.js, src_type nginx)
 * actually served. GET {P}/web/traffic?site=<vhost or host>&hours=24|168|720
 *   sites       the web sites seen in the access logs (choose one)
 *   totals      requests, unique visitors (client IPs), visitors in the last 5 minutes, bytes, 2xx-5xx, share answered
 *               without a server error
 *   series      requests per status class, bytes and the 95th-percentile request time per bucket (15 min / 1 h / 6 h)
 *   pages       top pages (path without the query string) with their server errors; error paths (4xx / 5xx)
 *   countries   where visitors come from - as the FIREWALL saw each client IP (its traffic log country); IPs the firewall
 *               did not log are counted as "not seen by the firewall", never guessed
 *   error_ips   the client IPs causing errors - operator and above only (customer IPs are personal data, PDPL)
 * Request time is read only when the log format carries it ($request_time / rt= / request_time= at the end of the line);
 * otherwise latency is "not in the log format", never 0. Every value is a parameter; audited.
 */
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');

const HOURS = { 24: 900000, 168: 3600000, 720: 21600000 };
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const RT = "toFloat64OrNull(extract(fields['extra'], '(?:^|\\\\s|rt=|request_time=)([0-9]+\\\\.[0-9]{1,6})(?:\\\\s|$)'))";
const PATH = "path(url)";
const SITE = "if(fields['vhost'] != '', fields['vhost'], host)";

function options(q, now) {
  const hours = HOURS[Number(q.hours)] ? Number(q.hours) : 24;
  const site = String(q.site || '').trim();
  if (site && !/^[A-Za-z0-9._:-]{1,200}$/.test(site)) throw new HttpError(400, 'site must be a host name');
  return { hours, site, to: now, from: now - hours * 3600000, bucket: HOURS[hours] };
}

async function traffic(ch, db, o, canSeeIps) {
  const T = `${db}.events`;
  const p = { f: { type: 'Int64', value: o.from }, t: { type: 'Int64', value: o.to }, s: { type: 'String', value: o.site }, b: { type: 'Int64', value: o.bucket }, rt5: { type: 'Int64', value: o.to - 300000 } };
  const W = `ts >= fromUnixTimestamp64Milli({f:Int64}) AND ts < fromUnixTimestamp64Milli({t:Int64}) AND src_type = 'nginx'`;
  const WS = `${W} AND ${SITE} = {s:String}`;
  const q = (tag, sql) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true, timeout_ms: 30000 });
  const sites = await q('wt_sites', `SELECT ${SITE} AS site, count() AS n FROM ${T} WHERE ${W} GROUP BY site ORDER BY n DESC LIMIT 30`);
  if (!o.site) return { sites: sites.map((r) => ({ site: r.site, requests: num(r.n) })), site: null };
  const [tot, rt, series, pages, errs, codes, ips, vis] = await Promise.all([
    q('wt_tot', `SELECT count() AS n, uniqExact(src_ip) AS u, uniqExactIf(src_ip, ts >= fromUnixTimestamp64Milli({rt5:Int64})) AS now5, sum(toUInt64OrZero(fields['bytes'])) AS by,
      countIf(http_status < 300) AS s2, countIf(http_status >= 300 AND http_status < 400) AS s3, countIf(http_status >= 400 AND http_status < 500) AS s4, countIf(http_status >= 500) AS s5 FROM ${T} WHERE ${WS}`),
    q('wt_rt', `SELECT count() AS n, quantile(0.5)(${RT}) AS p50, quantile(0.95)(${RT}) AS p95, max(${RT}) AS mx FROM ${T} WHERE ${WS} AND ${RT} IS NOT NULL`),
    q('wt_series', `SELECT intDiv(toUnixTimestamp64Milli(ts) - {f:Int64}, {b:Int64}) AS k, countIf(http_status < 300) AS s2, countIf(http_status >= 300 AND http_status < 400) AS s3,
      countIf(http_status >= 400 AND http_status < 500) AS s4, countIf(http_status >= 500) AS s5, sum(toUInt64OrZero(fields['bytes'])) AS by, quantile(0.95)(${RT}) AS p95 FROM ${T} WHERE ${WS} GROUP BY k ORDER BY k`),
    q('wt_pages', `SELECT ${PATH} AS pth, count() AS n, countIf(http_status >= 500) AS e5, uniqExact(src_ip) AS u FROM ${T} WHERE ${WS} GROUP BY pth ORDER BY n DESC LIMIT 10`),
    q('wt_errs', `SELECT ${PATH} AS pth, countIf(http_status >= 400 AND http_status < 500) AS e4, countIf(http_status >= 500) AS e5, groupUniqArray(4)(toString(http_status)) AS cs FROM ${T} WHERE ${WS} AND http_status >= 400 GROUP BY pth ORDER BY (e4 + e5) DESC LIMIT 10`),
    q('wt_codes', `SELECT toString(http_status) AS c, count() AS n FROM ${T} WHERE ${WS} GROUP BY c ORDER BY n DESC LIMIT 20`),
    canSeeIps ? q('wt_ips', `SELECT src_ip AS ip, countIf(http_status >= 400 AND http_status < 500) AS e4, countIf(http_status >= 500) AS e5, count() AS n FROM ${T} WHERE ${WS} AND http_status >= 400 AND src_ip != '' GROUP BY ip ORDER BY (e4 + e5) DESC LIMIT 10`) : Promise.resolve([]),
    q('wt_vis', `SELECT src_ip AS ip, count() AS n FROM ${T} WHERE ${WS} AND src_ip != '' GROUP BY ip ORDER BY n DESC LIMIT 500`),
  ]);
  // countries as the firewall logged each client IP (its traffic log carries the country it resolved)
  const ipList = [...new Set(vis.map((r) => r.ip).concat(ips.map((r) => r.ip)))].slice(0, 600);
  let geo = [];
  if (ipList.length) {
    geo = await ch.query(`/*q:wt_geo*/ SELECT src_ip AS ip, any(if(fields['srccountry'] != '', fields['srccountry'], fields['src_country'])) AS c FROM ${T}
      WHERE ts >= fromUnixTimestamp64Milli({f:Int64}) - INTERVAL 1 DAY AND ts < fromUnixTimestamp64Milli({t:Int64}) AND category = 'network' AND src_ip IN {ips:Array(String)}
        AND (fields['srccountry'] != '' OR fields['src_country'] != '') GROUP BY ip`, Object.assign({}, p, { ips: { type: 'Array(String)', value: ipList } }), { readonly: true, timeout_ms: 30000 });
  }
  const C = new Map(geo.map((r) => [r.ip, r.c && !/^reserved$/i.test(r.c) ? r.c : null]));
  const byC = {}; let unseen = 0, unseenReq = 0;
  for (const v of vis) { const c = C.get(v.ip); if (!c) { unseen++; unseenReq += num(v.n); continue; } const x = byC[c] || (byC[c] = { name: c, visitors: 0, requests: 0 }); x.visitors++; x.requests += num(v.n); }
  const t = tot[0] || {}, r = rt[0] || {}, n = num(t.n), latency = num(r.n) > 0;
  const byK = new Map(series.map((x) => [num(x.k), x])), buckets = Math.ceil((o.to - o.from) / o.bucket), S = [];
  for (let i = 0; i < buckets; i++) { const x = byK.get(i) || {}; S.push({ t: o.from + i * o.bucket, s2: num(x.s2), s3: num(x.s3), s4: num(x.s4), s5: num(x.s5), bytes: num(x.by), p95_s: latency && x.p95 != null ? Math.round(Number(x.p95) * 1000) / 1000 : null }); }
  return {
    site: o.site, hours: o.hours, from: o.from, to: o.to, bucket_ms: o.bucket, sites: sites.map((s) => ({ site: s.site, requests: num(s.n) })),
    totals: { requests: n, visitors: num(t.u), visitors_5min: num(t.now5), bytes: num(t.by), s2: num(t.s2), s3: num(t.s3), s4: num(t.s4), s5: num(t.s5),
      ok_pct: n ? Math.round((1 - num(t.s5) / n) * 10000) / 100 : null },
    latency: latency ? { p50_s: Math.round(Number(r.p50) * 1000) / 1000, p95_s: Math.round(Number(r.p95) * 1000) / 1000, max_s: Math.round(Number(r.mx) * 1000) / 1000, measured: num(r.n) } : null,
    series: S, pages: pages.map((x) => ({ path: x.pth || '/', requests: num(x.n), server_errors: num(x.e5), visitors: num(x.u) })),
    error_paths: errs.map((x) => ({ path: x.pth || '/', e4: num(x.e4), e5: num(x.e5), codes: x.cs || [] })), codes: codes.map((x) => ({ code: x.c, n: num(x.n) })),
    error_ips: canSeeIps ? ips.map((x) => ({ ip: x.ip, e4: num(x.e4), e5: num(x.e5), requests: num(x.n), country: C.get(x.ip) || null })) : null,
    countries: Object.values(byC).sort((a, b) => b.visitors - a.visitors), not_seen_by_firewall: { visitors: unseen, requests: unseenReq },
    note: (latency ? '' : 'Request time is not in this web server\'s log format - add $request_time to the nginx log_format to see latency. ') + 'Countries are as the firewall logged each client IP; visitors the firewall did not log are counted separately, not guessed.',
  };
}

function register(api, deps) {
  const P = prefixOf(deps), { ch } = deps;
  const db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  const now = deps.now || Date.now;
  const RANK = { viewer: 1, analyst: 2, operator: 3, admin: 4 };
  // aggregates for any signed-in role; the client IP list only for operators and above
  api.route('GET', `${P}/web/traffic`, wrap(deps, null, async (ctx) => {
    const o = options(ctx.query || {}, now());
    const ipsOk = (RANK[String(ctx.role || '').toLowerCase()] || 0) >= RANK.operator;
    const r = await traffic(ch, db, o, ipsOk);
    audit(ctx, 'web.traffic.view', o.site || 'sites', { hours: o.hours, ips: ipsOk && !!o.site });
    return ctx.ok(r);
  }));
}

module.exports = { register, traffic, options };
