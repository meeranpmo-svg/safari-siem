// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network flows from the firewalls' own traffic logs (FortiGate, Palo Alto and every parser that normalises a traffic
 * log the same way: category "network", action "allowed" | "blocked"). The Network Flows page reads this instead of the
 * sample data it used to draw. Vendors name the same fact differently; each is read where it is (never estimated):
 *   country   FortiGate srccountry / dstcountry      Palo Alto src_country / dst_country
 *   app       FortiGate app (app control) or service Palo Alto app
 *   bytes     FortiGate sentbyte + rcvdbyte          Palo Alto bytes
 *   zone      FortiGate srcintfrole / srcintf        Palo Alto from_zone / to_zone
 * Direction: inbound = a public source to a private destination, outbound = the reverse (RFC 1918, CGNAT, loopback,
 * link-local, IPv6 ULA / link-local count as private). A value the firewall did not send stays empty and the page says so.
 *   GET {P}/flows/summary?range=60&fw=<device>|all&dir=in|out   any signed-in role; addresses (talkers, conversations)
 *                                                                analyst and above only (they name hosts and people's PCs)
 *   GET {P}/flows/drill?range&fw&dir + one slice: country | zone (+zside=src|dst) | proto+port | app | action | src | dst |
 *        bucket (index into the summary's histogram)            analyst+: the real sources / destinations / services behind it
 *   source=fw (default) | netflow   the same summary / drill-down from the flow collector's rollups (flow_minute: NetFlow /
 *        IPFIX / sFlow, engine/collect/flow-collector.js); the firewall answer says netflow_available when there is any
 * Every view is written to the audit trail. Read-only: nothing is changed anywhere.
 */
const { wrap, audit, prefixOf, HttpError } = require('./routeutil');

const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const RANGES = { 15: 30, 60: 60, 1440: 48, 10080: 84 };   // minutes → histogram buckets
const PRIV4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16'];
const PRIV6 = ['fc00::/7', 'fe80::/10', '::1/128'];
const priv = (c) => `((isIPv4String(${c}) AND (${PRIV4.map((p) => `isIPAddressInRange(${c}, '${p}')`).join(' OR ')})) OR (isIPv6String(${c}) AND (${PRIV6.map((p) => `isIPAddressInRange(${c}, '${p}')`).join(' OR ')})))`;
const pub = (c) => `((isIPv4String(${c}) OR isIPv6String(${c})) AND NOT ${priv(c)})`;
const X = {
  bytes: "(toUInt64OrZero(fields['sentbyte']) + toUInt64OrZero(fields['rcvdbyte']) + toUInt64OrZero(fields['bytes']))",
  srcC: "if(fields['srccountry'] != '', fields['srccountry'], fields['src_country'])",
  dstC: "if(fields['dstcountry'] != '', fields['dstcountry'], fields['dst_country'])",
  app: "multiIf(fields['app'] != '', fields['app'], fields['service'] != '', fields['service'], '')",
  zs: "multiIf(fields['from_zone'] != '', fields['from_zone'], fields['srcintfrole'] != '', fields['srcintfrole'], fields['srcintf'])",
  zd: "multiIf(fields['to_zone'] != '', fields['to_zone'], fields['dstintfrole'] != '', fields['dstintfrole'], fields['dstintf'])",
  deny: "countIf(action = 'blocked')", allow: "countIf(action = 'allowed')",
};
const DIR = { in: `${pub('src_ip')} AND ${priv('dst_ip')}`, out: `${priv('src_ip')} AND ${pub('dst_ip')}` };
const ctryOf = (dir) => (dir === 'in' ? X.srcC : X.dstC);
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

function options(q, now) {
  const range = RANGES[Number(q.range)] ? Number(q.range) : 60;
  const buckets = RANGES[range], to = now, from = to - range * 60000, step = Math.ceil((to - from) / buckets);
  const fw = typeof q.fw === 'string' && q.fw && q.fw !== 'all' ? q.fw.slice(0, 200) : '';
  const dir = q.dir === 'out' ? 'out' : 'in';
  if (q.source !== undefined && q.source !== '' && q.source !== 'fw' && q.source !== 'netflow') throw new HttpError(400, 'source must be fw (firewall traffic logs) or netflow (NetFlow / IPFIX / sFlow)');
  return { range, buckets, from, to, step, fw, dir, source: q.source === 'netflow' ? 'netflow' : 'fw' };
}

/* The same views from the flow collector's one-minute rollups (<db>.flow_minute, engine/collect/flow-collector.js):
 * flows instead of sessions, no allow / deny, no country and no zone (a flow record carries none of them - those panels
 * stay empty for this source and the answer says why). "fw" = the exporter's address. */
const NF_PROTO = "multiIf(proto = 6, 'tcp', proto = 17, 'udp', proto = 1, 'icmp', proto = 58, 'icmpv6', toString(proto))";
const NF_PORT = 'if(dst_port != 0, dst_port, src_port)';
function nfWhere(o, extra) {
  const params = { t_from: { type: 'Int64', value: o.from }, t_to: { type: 'Int64', value: o.to } };
  let w = 'minute >= toDateTime(intDiv({t_from:Int64}, 1000)) AND minute < toDateTime(intDiv({t_to:Int64}, 1000))';
  if (o.fw) { w += ' AND exporter = {fw:String}'; params.fw = { type: 'String', value: o.fw }; }
  if (extra) w += ' AND ' + extra;
  return { w, params };
}
// What the AI noticed, from the summary's own numbers (explainable, labelled): minutes far above the window's usual (robust z on
// median / MAD over the histogram, 3.5+ and 20+ flows) for denied and for all traffic, the deny ratio, one country holding most of
// the denies, a top talker carrying most of the bytes, a port or application whose share moved most against the previous window.
function analyse(v) {
  if (!v || !Array.isArray(v.hist) || !v.hist.length) return Object.assign(v || {}, { anomalies: [], insights: [] });
  const med = (a) => { const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length ? (b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2) : 0; };
  const spikes = (key, label) => { const vals = v.hist.map((h) => (key === 'all' ? h.allow + h.deny : h[key] || 0)), m = med(vals), mad = med(vals.map((x) => Math.abs(x - m))) || Math.max(1, m * 0.1);
    return v.hist.map((h, i) => ({ i, t: h.t, kind: label, n: vals[i], usual: m, z: Math.round(10 * (vals[i] - m) / (1.4826 * mad)) / 10 })).filter((x) => x.z >= 3.5 && x.n >= 20); };
  const anomalies = spikes('deny', 'denied').concat(spikes('all', 'all traffic')).sort((a, b) => b.z - a.z).slice(0, 12);
  const ins = [], total = v.total || 0, denied = v.denied || 0;
  if (total) ins.push(Math.round(100 * denied / total) + '% of ' + total.toLocaleString('en-US') + ' flows were denied' + (denied / total > 0.5 ? ' - mostly scanning and probing from outside, stopped at the firewall' : ''));
  const dn = anomalies.filter((x) => x.kind === 'denied');
  if (dn.length) ins.push(dn.length + ' minute(s) with denied traffic far above usual (up to ' + dn[0].n + ' against usually ' + Math.round(dn[0].usual) + ', robust z ' + dn[0].z + ') - a scan or an attack burst; check the countries and ports at that time');
  const C = (v.countries || []).slice().sort((a, b) => b.deny - a.deny); if (C.length && denied && C[0].deny / denied >= 0.4) ins.push(C[0].name + ' is the source of ' + Math.round(100 * C[0].deny / denied) + '% of the denied traffic - consider a geo-block on the WAN policies if no business needs it');
  const T = (v.talkers || []).slice().sort((a, b) => b.bytes - a.bytes), tb = T.reduce((n, x) => n + x.bytes, 0); if (T.length && tb && T[0].bytes / tb >= 0.5) ins.push('One conversation carries ' + Math.round(100 * T[0].bytes / tb) + '% of the top talkers’ bytes (' + T[0].svc + ') - a backup, a sync or an exfiltration; confirm it is expected');
  for (const d of v.dev || []) { const mv = (d.rows || []).filter((r) => r.before != null).map((r) => ({ v: r.v, d: r.now - r.before })).sort((a, b) => Math.abs(b.d) - Math.abs(a.d))[0];
    if (mv && Math.abs(mv.d) >= 15) ins.push(d.label + ' ' + mv.v + ' went ' + (mv.d > 0 ? 'up' : 'down') + ' by ' + Math.round(Math.abs(mv.d)) + ' points of share against the previous window'); }
  return Object.assign(v, { anomalies, insights: ins, insights_note: 'Rules over this window’s own numbers (robust z on median / MAD) - indications to check, not verdicts.' });
}

async function netflowSummary(ch, db, o, withAddresses) {
  const T = `${db}.flow_minute`, base = nfWhere(o), dirW = nfWhere(o, DIR[o.dir]);
  const prev = nfWhere(Object.assign({}, o, { from: o.from - (o.to - o.from) }));
  const q = (tag, sql, params) => ch.query(`/*q:${tag}*/ ` + sql, params || base.params, { readonly: true });
  const cur = Object.assign({}, prev.params, { cur: { type: 'Int64', value: o.from } }), isCur = 'minute >= toDateTime(intDiv({cur:Int64}, 1000))';
  const [hist, ports, apps, exps, talk, conv, devPort, devApp] = await Promise.all([
    q('nf_hist', `SELECT intDiv(toUnixTimestamp(minute) * 1000 - {t_from:Int64}, {step:Int64}) AS b, sum(flows) AS a, sum(bytes) AS by FROM ${T} WHERE ${base.w} GROUP BY b ORDER BY b`, Object.assign({ step: { type: 'Int64', value: o.step } }, base.params)),
    q('nf_ports', `SELECT ${NF_PROTO} AS p, ${NF_PORT} AS port, sum(flows) AS n FROM ${T} WHERE ${base.w} GROUP BY p, port ORDER BY n DESC LIMIT 60`),
    q('nf_apps', `SELECT app, sum(flows) AS n FROM ${T} WHERE ${base.w} AND app != '' GROUP BY app ORDER BY n DESC LIMIT 40`),
    q('nf_exporters', `SELECT exporter AS host, sum(flows) AS n, toUnixTimestamp(max(minute)) * 1000 AS last FROM ${T} WHERE minute >= now() - INTERVAL 1 DAY GROUP BY host ORDER BY n DESC LIMIT 50`, {}),
    withAddresses ? q('nf_talkers', `SELECT src_ip, dst_ip, ${NF_PROTO} AS p, ${NF_PORT} AS port, any(app) AS app, sum(flows) AS flows, sum(bytes) AS by FROM ${T} WHERE ${dirW.w} GROUP BY src_ip, dst_ip, p, port ORDER BY flows DESC LIMIT 10`, dirW.params) : null,
    withAddresses ? q('nf_conv', `SELECT src_ip, exporter AS fw, app, dst_ip, sum(flows) AS flows, sum(bytes) AS by FROM ${T} WHERE ${base.w} AND src_ip != '' GROUP BY src_ip, fw, app, dst_ip ORDER BY by DESC, flows DESC LIMIT 12`) : null,
    q('nf_dev_port', `SELECT ${isCur} AS cur, toString(${NF_PORT}) AS v, sum(flows) AS n FROM ${T} WHERE ${prev.w} GROUP BY cur, v`, cur),
    q('nf_dev_app', `SELECT ${isCur} AS cur, app AS v, sum(flows) AS n FROM ${T} WHERE ${prev.w} AND app != '' GROUP BY cur, v`, cur),
  ]);
  const byB = new Map(hist.map((r) => [num(r.b), r]));
  const h = []; for (let i = 0; i < o.buckets; i++) { const r = byB.get(i) || {}; h.push({ i, t: o.from + i * o.step, allow: num(r.a), deny: 0, bytes: num(r.by) }); }
  const svc = (proto, port, app) => [proto && port ? `${proto}/${port}` : proto || '', app || ''].filter(Boolean).join(' ');
  function dev(rows, label) {
    const c = new Map(), p = new Map(); let nc = 0, np = 0;
    for (const r of rows) { const n = num(r.n), m = num(r.cur) ? c : p; m.set(String(r.v), (m.get(String(r.v)) || 0) + n); if (num(r.cur)) nc += n; else np += n; }
    return { label, rows: [...c.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([v, n]) => ({ v, now: nc ? n / nc * 100 : 0, before: np ? (p.get(v) || 0) / np * 100 : null })), previous_flows: np };
  }
  return {
    source: 'netflow', connected: exps.length > 0, range: o.range, from: o.from, to: o.to, step_ms: o.step, dir: o.dir, fw: o.fw || 'all',
    firewalls: exps.map((r) => ({ host: r.host, src_type: 'netflow', flows_24h: num(r.n), last: num(r.last) || null })),
    total: h.reduce((n, x) => n + x.allow, 0), denied: 0, bytes_reported: h.some((x) => x.bytes > 0), hist: h, countries: [], zsrc: [], zdst: [],
    ports: ports.map((r) => ({ action: 'allowed', proto: r.p || '', port: num(r.port), n: num(r.n) })), apps: apps.map((r) => ({ action: 'allowed', app: r.app, n: num(r.n) })),
    talkers: talk ? talk.map((r) => ({ src: r.src_ip, country: '', dst: r.dst_ip, svc: svc(r.p, num(r.port), r.app), flows: num(r.flows), deny: 0, bytes: num(r.by) })) : null,
    conv: conv ? conv.map((r) => ({ src: r.src_ip, fw: r.fw || '', app: r.app || '(no app)', dst: r.dst_ip, flows: num(r.flows), bytes: num(r.by) })) : null,
    dev: [dev(devPort, 'Destination port'), { label: 'Country', rows: [], previous_flows: 0 }, dev(devApp, 'Application')],
    addresses_included: !!withAddresses,
    note: 'NetFlow / IPFIX / sFlow records (bytes scaled by the sampling rate): they carry no country, zone or allow / deny, so those panels stay empty for this source.',
  };
}
async function netflowDrill(ch, db, o, q) {
  for (const k of ['country', 'zone', 'action']) if (typeof q[k] === 'string' && q[k]) throw new HttpError(400, `${k} is not available for NetFlow records`);
  const parts = [], params = {};
  for (const [k, col] of [['src', 'src_ip'], ['dst', 'dst_ip'], ['app', 'app']]) if (typeof q[k] === 'string' && q[k]) { parts.push(`${col} = {v_${k}:String}`); params['v_' + k] = { type: 'String', value: q[k].slice(0, 200) }; }
  if (q.port !== undefined && q.port !== '') { const p = Number(q.port); if (!Number.isInteger(p) || p < 0 || p > 65535) throw new HttpError(400, 'invalid port'); parts.push(`${NF_PORT} = {port:UInt16}`); params.port = { type: 'UInt16', value: p }; }
  if (typeof q.proto === 'string' && q.proto) { parts.push(`${NF_PROTO} = {proto:String}`); params.proto = { type: 'String', value: q.proto.toLowerCase().slice(0, 20) }; }
  let oo = o;
  if (q.bucket !== undefined && q.bucket !== '') { const b = Number(q.bucket); if (!Number.isInteger(b) || b < 0 || b >= o.buckets) throw new HttpError(400, 'invalid bucket'); oo = Object.assign({}, o, { from: o.from + b * o.step, to: Math.min(o.to, o.from + (b + 1) * o.step) }); }
  if (!parts.length && oo === o) throw new HttpError(400, 'choose a slice: proto/port, app, src, dst or bucket');
  const w = nfWhere(oo, parts.join(' AND ') || null), p = Object.assign({}, w.params, params), T = `${db}.flow_minute`;
  const qq = (tag, sql) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true });
  const [tot, src, dst, svc] = await Promise.all([
    qq('nfd_total', `SELECT sum(flows) AS a, sum(bytes) AS by, toUnixTimestamp(min(minute)) * 1000 AS first, toUnixTimestamp(max(minute)) * 1000 AS last FROM ${T} WHERE ${w.w}`),
    qq('nfd_src', `SELECT src_ip AS v, sum(flows) AS n FROM ${T} WHERE ${w.w} GROUP BY v ORDER BY n DESC LIMIT 10`),
    qq('nfd_dst', `SELECT dst_ip AS v, sum(flows) AS n FROM ${T} WHERE ${w.w} GROUP BY v ORDER BY n DESC LIMIT 10`),
    qq('nfd_svc', `SELECT concat(${NF_PROTO}, '/', toString(${NF_PORT}), if(app != '', concat(' ', app), '')) AS v, sum(flows) AS n FROM ${T} WHERE ${w.w} GROUP BY v ORDER BY n DESC LIMIT 10`),
  ]);
  const t = tot[0] || {}, rows = (rs) => rs.map((r) => ({ v: String(r.v), n: num(r.n), deny: 0 }));
  return { source: 'netflow', from: oo.from, to: oo.to, allow: num(t.a), deny: 0, bytes: num(t.by), first: num(t.first) || null, last: num(t.last) || null,
    top_src: rows(src), top_dst: rows(dst), top_svc: rows(svc), top_country: [], peer_zones: [] };
}
// whether the flow collector has written anything in the last day (the page offers the source); a store without the
// NetFlow tables yet (before the schema update) simply answers no
async function netflowAvailable(ch, db) {
  try { const r = await ch.query(`/*q:nf_avail*/ SELECT count() AS n FROM ${db}.flow_minute WHERE minute >= now() - INTERVAL 1 DAY`, {}, { readonly: true }); return num((r[0] || {}).n) > 0; }
  catch (e) { return false; /* table not created yet (schema update pending) or store unreachable: the firewall view still answers */ }
}

function whereOf(o, extra) {
  const params = { t_from: { type: 'Int64', value: o.from }, t_to: { type: 'Int64', value: o.to } };
  let w = "ts >= fromUnixTimestamp64Milli({t_from:Int64}) AND ts < fromUnixTimestamp64Milli({t_to:Int64}) AND category = 'network' AND action IN ('allowed', 'blocked')";
  if (o.fw) { w += ' AND host = {fw:String}'; params.fw = { type: 'String', value: o.fw }; }
  if (extra) w += ' AND ' + extra;
  return { w, params };
}

async function summary(ch, db, o, withAddresses) {
  const T = `${db}.events`, base = whereOf(o), dirW = whereOf(o, DIR[o.dir]);
  const prev = whereOf(Object.assign({}, o, { from: o.from - (o.to - o.from), to: o.to }));
  const q = (tag, sql, params) => ch.query(`/*q:${tag}*/ ` + sql, params || base.params, { readonly: true });
  const step = { step: { type: 'Int64', value: o.step } };
  const [hist, ctry, zs, zd, ports, apps, fws, talk, conv, devPort, devC, devApp] = await Promise.all([
    q('hist', `SELECT intDiv(toUnixTimestamp64Milli(ts) - {t_from:Int64}, {step:Int64}) AS b, ${X.allow} AS a, ${X.deny} AS d, sum(${X.bytes}) AS by FROM ${T} WHERE ${base.w} GROUP BY b ORDER BY b`, Object.assign({}, base.params, step)),
    q('countries', `SELECT ${ctryOf(o.dir)} AS c, ${X.allow} AS a, ${X.deny} AS d, sum(${X.bytes}) AS by FROM ${T} WHERE ${dirW.w} GROUP BY c ORDER BY a + d DESC LIMIT 80`, dirW.params),
    q('zsrc', `SELECT ${X.zs} AS z, ${X.allow} AS a, ${X.deny} AS d FROM ${T} WHERE ${base.w} AND ${X.zs} != '' GROUP BY z ORDER BY a + d DESC LIMIT 12`),
    q('zdst', `SELECT ${X.zd} AS z, ${X.allow} AS a, ${X.deny} AS d FROM ${T} WHERE ${base.w} AND ${X.zd} != '' GROUP BY z ORDER BY a + d DESC LIMIT 12`),
    q('ports', `SELECT action, proto, dst_port AS port, count() AS n FROM ${T} WHERE ${base.w} GROUP BY action, proto, port ORDER BY n DESC LIMIT 60`),
    q('apps', `SELECT action, ${X.app} AS app, count() AS n FROM ${T} WHERE ${base.w} AND ${X.app} != '' GROUP BY action, app ORDER BY n DESC LIMIT 40`),
    q('firewalls', `SELECT host, any(src_type) AS src_type, count() AS n, toUnixTimestamp64Milli(max(ts)) AS last FROM ${T} WHERE ts >= now() - INTERVAL 1 DAY AND category = 'network' AND action IN ('allowed', 'blocked') AND host != '' GROUP BY host ORDER BY n DESC LIMIT 50`, {}),
    withAddresses ? q('talkers', `SELECT src_ip, any(${ctryOf(o.dir)}) AS c, dst_ip, proto, dst_port AS port, any(${X.app}) AS app, count() AS flows, ${X.deny} AS deny, sum(${X.bytes}) AS by FROM ${T} WHERE ${dirW.w} GROUP BY src_ip, dst_ip, proto, port ORDER BY flows DESC LIMIT 10`, dirW.params) : null,
    withAddresses ? q('conv', `SELECT src_ip, host AS fw, ${X.app} AS app, dst_ip, count() AS flows, sum(${X.bytes}) AS by FROM ${T} WHERE ${base.w} GROUP BY src_ip, fw, app, dst_ip ORDER BY by DESC, flows DESC LIMIT 12`) : null,
    q('dev_port', `SELECT ts >= fromUnixTimestamp64Milli({cur:Int64}) AS cur, toString(dst_port) AS v, count() AS n FROM ${T} WHERE ${prev.w} GROUP BY cur, v`, Object.assign({}, prev.params, { cur: { type: 'Int64', value: o.from } })),
    q('dev_country', `SELECT ts >= fromUnixTimestamp64Milli({cur:Int64}) AS cur, ${ctryOf(o.dir)} AS v, count() AS n FROM ${T} WHERE ${prev.w} AND ${DIR[o.dir]} AND ${ctryOf(o.dir)} != '' GROUP BY cur, v`, Object.assign({}, prev.params, { cur: { type: 'Int64', value: o.from } })),
    q('dev_app', `SELECT ts >= fromUnixTimestamp64Milli({cur:Int64}) AS cur, ${X.app} AS v, count() AS n FROM ${T} WHERE ${prev.w} AND ${X.app} != '' GROUP BY cur, v`, Object.assign({}, prev.params, { cur: { type: 'Int64', value: o.from } })),
  ]);
  const byB = new Map(hist.map((r) => [num(r.b), r]));
  const h = []; for (let i = 0; i < o.buckets; i++) { const r = byB.get(i) || {}; h.push({ i, t: o.from + i * o.step, allow: num(r.a), deny: num(r.d), bytes: num(r.by) }); }
  const total = h.reduce((n, x) => n + x.allow + x.deny, 0), denied = h.reduce((n, x) => n + x.deny, 0);
  const svc = (proto, port, app) => [proto && port ? `${proto}/${port}` : proto || '', app || ''].filter(Boolean).join(' ');
  function dev(rows, label) {
    const cur = new Map(), pre = new Map(); let nc = 0, np = 0;
    for (const r of rows) { const n = num(r.n), m = num(r.cur) ? cur : pre; m.set(String(r.v), (m.get(String(r.v)) || 0) + n); if (num(r.cur)) nc += n; else np += n; }
    const top = [...cur.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
    return { label, rows: top.map(([v, n]) => ({ v, now: nc ? n / nc * 100 : 0, before: np ? (pre.get(v) || 0) / np * 100 : null })), previous_flows: np };
  }
  return {
    connected: fws.length > 0, range: o.range, from: o.from, to: o.to, step_ms: o.step, dir: o.dir, fw: o.fw || 'all',
    firewalls: fws.map((r) => ({ host: r.host, src_type: r.src_type, flows_24h: num(r.n), last: num(r.last) || null })),
    total, denied, bytes_reported: h.some((x) => x.bytes > 0),
    hist: h,
    countries: ctry.map((r) => ({ name: String(r.c || ''), allow: num(r.a), deny: num(r.d), bytes: num(r.by) })),
    zsrc: zs.map((r) => ({ z: r.z, allow: num(r.a), deny: num(r.d) })), zdst: zd.map((r) => ({ z: r.z, allow: num(r.a), deny: num(r.d) })),
    ports: ports.map((r) => ({ action: r.action, proto: r.proto || '', port: num(r.port), n: num(r.n) })),
    apps: apps.map((r) => ({ action: r.action, app: r.app, n: num(r.n) })),
    talkers: talk ? talk.map((r) => ({ src: r.src_ip, country: r.c || '', dst: r.dst_ip, svc: svc(r.proto, num(r.port), r.app), flows: num(r.flows), deny: num(r.deny), bytes: num(r.by) })) : null,
    conv: conv ? conv.map((r) => ({ src: r.src_ip, fw: r.fw || '', app: r.app || '(no app)', dst: r.dst_ip, flows: num(r.flows), bytes: num(r.by) })) : null,
    dev: [dev(devPort, 'Destination port'), dev(devC, o.dir === 'in' ? 'Source country (inbound)' : 'Destination country (outbound)'), dev(devApp, 'Application')],
    addresses_included: !!withAddresses,
  };
}

// one slice of the summary → the real rows behind it
const SLICE = {
  country: (o, v) => [`${ctryOf(o.dir)} = {v:String} AND ${DIR[o.dir]}`, { v: { type: 'String', value: v } }],
  zone: (o, v, q) => [`${q.zside === 'dst' ? X.zd : X.zs} = {v:String}`, { v: { type: 'String', value: v } }],
  app: (o, v) => [`${X.app} = {v:String}`, { v: { type: 'String', value: v } }],
  action: (o, v) => (v === 'allowed' || v === 'blocked' ? ['action = {v:String}', { v: { type: 'String', value: v } }] : null),
  src: (o, v) => ['src_ip = {v:String}', { v: { type: 'String', value: v } }],
  dst: (o, v) => ['dst_ip = {v:String}', { v: { type: 'String', value: v } }],
};
async function drill(ch, db, o, q) {
  const parts = [], params = {};
  for (const k of Object.keys(SLICE)) {
    if (typeof q[k] !== 'string' || !q[k]) continue;
    const s = SLICE[k](o, q[k].slice(0, 200), q); if (!s) throw new HttpError(400, `invalid ${k}`);
    parts.push(s[0].replace(/\{v:String\}/g, `{v_${k}:String}`)); params[`v_${k}`] = s[1].v;
  }
  if (q.port !== undefined && q.port !== '') { const p = Number(q.port); if (!Number.isInteger(p) || p < 0 || p > 65535) throw new HttpError(400, 'invalid port'); parts.push('dst_port = {port:UInt16}'); params.port = { type: 'UInt16', value: p }; }
  if (typeof q.proto === 'string' && q.proto) { parts.push('proto = {proto:String}'); params.proto = { type: 'String', value: q.proto.toLowerCase().slice(0, 20) }; }
  let oo = o;
  if (q.bucket !== undefined && q.bucket !== '') { const b = Number(q.bucket); if (!Number.isInteger(b) || b < 0 || b >= o.buckets) throw new HttpError(400, 'invalid bucket'); oo = Object.assign({}, o, { from: o.from + b * o.step, to: Math.min(o.to, o.from + (b + 1) * o.step) }); }
  if (!parts.length && oo === o) throw new HttpError(400, 'choose a slice: country, zone, proto/port, app, action, src, dst or bucket');
  const w = whereOf(oo, parts.join(' AND ') || null), p = Object.assign({}, w.params, params), T = `${db}.events`;
  const qq = (tag, sql) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true });
  const [tot, src, dst, svc, ctry, zp] = await Promise.all([
    qq('d_total', `SELECT ${X.allow} AS a, ${X.deny} AS d, sum(${X.bytes}) AS by, toUnixTimestamp64Milli(min(ts)) AS first, toUnixTimestamp64Milli(max(ts)) AS last FROM ${T} WHERE ${w.w}`),
    qq('d_src', `SELECT src_ip AS v, count() AS n, ${X.deny} AS d FROM ${T} WHERE ${w.w} GROUP BY v ORDER BY n DESC LIMIT 10`),
    qq('d_dst', `SELECT dst_ip AS v, count() AS n, ${X.deny} AS d FROM ${T} WHERE ${w.w} GROUP BY v ORDER BY n DESC LIMIT 10`),
    qq('d_svc', `SELECT concat(proto, '/', toString(dst_port), if(${X.app} != '', concat(' ', ${X.app}), '')) AS v, count() AS n, ${X.deny} AS d FROM ${T} WHERE ${w.w} GROUP BY v ORDER BY n DESC LIMIT 10`),
    qq('d_country', `SELECT ${ctryOf(oo.dir)} AS v, count() AS n, ${X.deny} AS d FROM ${T} WHERE ${w.w} AND ${ctryOf(oo.dir)} != '' GROUP BY v ORDER BY n DESC LIMIT 10`),
    qq('d_zones', `SELECT ${q.zside === 'dst' ? X.zs : X.zd} AS v, count() AS n, ${X.deny} AS d FROM ${T} WHERE ${w.w} AND v != '' GROUP BY v ORDER BY n DESC LIMIT 10`),
  ]);
  const t = tot[0] || {}, rows = (rs) => rs.map((r) => ({ v: String(r.v), n: num(r.n), deny: num(r.d) }));
  return { from: oo.from, to: oo.to, allow: num(t.a), deny: num(t.d), bytes: num(t.by), first: num(t.first) || null, last: num(t.last) || null,
    top_src: rows(src), top_dst: rows(dst), top_svc: rows(svc), top_country: rows(ctry), peer_zones: rows(zp) };
}

// Mail on the wire: SMTP sessions (TCP 25 / 465 / 587) through the firewalls, inbound by source country and outbound by
// destination country - where mail to and from the organisation comes from and goes. Countries only for every role; the
// sending addresses only for analysts and above (the Email dashboard's world map).
const MAILP = 'dst_port IN (25, 465, 587)';
async function mailGeo(ch, db, o, withAddresses) {
  const T = `${db}.events`, inW = whereOf(o, `${DIR.in} AND ${MAILP}`), outW = whereOf(o, `${DIR.out} AND ${MAILP}`), allW = whereOf(o, MAILP);
  const q = (tag, sql, params) => ch.query(`/*q:${tag}*/ ` + sql, params, { readonly: true });
  const step = { step: { type: 'Int64', value: o.step } };
  const [hist, cin, cout, fws, srcs] = await Promise.all([
    q('mail_hist', `SELECT intDiv(toUnixTimestamp64Milli(ts) - {t_from:Int64}, {step:Int64}) AS b, countIf(${DIR.in}) AS i, countIf(${DIR.out}) AS o, ${X.deny} AS d FROM ${T} WHERE ${allW.w} GROUP BY b ORDER BY b`, Object.assign({}, allW.params, step)),
    q('mail_in', `SELECT ${X.srcC} AS c, ${X.allow} AS a, ${X.deny} AS d FROM ${T} WHERE ${inW.w} GROUP BY c ORDER BY a + d DESC LIMIT 80`, inW.params),
    q('mail_out', `SELECT ${X.dstC} AS c, ${X.allow} AS a, ${X.deny} AS d FROM ${T} WHERE ${outW.w} GROUP BY c ORDER BY a + d DESC LIMIT 80`, outW.params),
    q('mail_fw', `SELECT count() AS n FROM ${T} WHERE ts >= now() - INTERVAL 1 DAY AND category = 'network' AND action IN ('allowed', 'blocked')`, {}),
    withAddresses ? q('mail_src', `SELECT src_ip, any(${X.srcC}) AS c, count() AS n, ${X.deny} AS d FROM ${T} WHERE ${inW.w} GROUP BY src_ip ORDER BY n DESC LIMIT 15`, inW.params) : null,
  ]);
  const byB = new Map(hist.map((r) => [num(r.b), r])), h = [];
  for (let i = 0; i < o.buckets; i++) { const r = byB.get(i) || {}; h.push({ i, t: o.from + i * o.step, inbound: num(r.i), outbound: num(r.o), deny: num(r.d) }); }
  const ctry = (rows) => rows.map((r) => ({ name: String(r.c || ''), allow: num(r.a), deny: num(r.d) }));
  const sum = (rows) => rows.reduce((a, r) => ({ total: a.total + num(r.a) + num(r.d), denied: a.denied + num(r.d) }), { total: 0, denied: 0 });
  return { connected: num((fws[0] || {}).n) > 0, range: o.range, from: o.from, to: o.to, step_ms: o.step, hist: h,
    inbound: Object.assign(sum(cin), { countries: ctry(cin) }), outbound: Object.assign(sum(cout), { countries: ctry(cout) }),
    top_sources: srcs ? srcs.map((r) => ({ src: r.src_ip, country: r.c || '', n: num(r.n), deny: num(r.d) })) : null, addresses_included: !!withAddresses,
    note: 'SMTP sessions (TCP 25, 465, 587) through the firewalls, by country as the firewall reports it. A firewall that does not log allowed sessions shows only what it blocked.' };
}

function register(api, deps) {
  const P = prefixOf(deps), { ch } = deps;
  if (!ch || typeof ch.query !== 'function') throw new Error('network flows need deps.ch');
  const db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  const now = deps.now || Date.now;
  api.route('GET', `${P}/flows/summary`, wrap(deps, null, async (ctx) => {
    const o = options(ctx.query || {}, now()), full = (RANK[ctx.role] || 0) >= RANK.analyst;
    const r = analyse(o.source === 'netflow' ? await netflowSummary(ch, db, o, full) : await summary(ch, db, o, full));
    r.source = o.source; r.netflow_available = o.source === 'netflow' ? r.connected : await netflowAvailable(ch, db);
    audit(ctx, 'flows.view', o.fw || 'all', o.source === 'netflow' ? { range: o.range, dir: o.dir, addresses: full, source: 'netflow' } : { range: o.range, dir: o.dir, addresses: full });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/flows/mail`, wrap(deps, null, async (ctx) => {
    const o = options(ctx.query || {}, now()), full = (RANK[ctx.role] || 0) >= RANK.analyst;
    const r = await mailGeo(ch, db, o, full);
    audit(ctx, 'flows.mail.view', 'smtp', { range: o.range, addresses: full });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/flows/drill`, wrap(deps, null, async (ctx) => {
    if ((RANK[ctx.role] || 0) < RANK.analyst) throw new HttpError(403, 'requires analyst role (the detail names addresses)');
    const q = ctx.query || {}, o = options(q, now());
    const r = o.source === 'netflow' ? await netflowDrill(ch, db, o, q) : await drill(ch, db, o, q);
    audit(ctx, 'flows.drill', o.fw || 'all', { range: o.range, dir: o.dir, slice: Object.keys(q).filter((k) => !['range', 'fw', 'dir', 'source'].includes(k)) });
    return ctx.ok(r);
  }));
}

module.exports = { register, analyse, summary, drill, mailGeo, options, netflowSummary, netflowDrill, netflowAvailable, X, DIR };
