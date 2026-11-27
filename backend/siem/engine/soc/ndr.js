// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network Detection & Response (NDR) over the firewalls' own traffic logs (FortiGate and every parser that normalises a traffic
 * log to category "network"; soc/flows.js reads the same rows). Read-only: nothing here blocks or changes a device - a response
 * is a SOC case or a FortiGate change plan (FortiGate Fleet), proposed and approved by people.
 * Each detection learns from the organisation's OWN history (no fixed threshold where a baseline can be measured) and itemises why:
 *   beaconing     an internal host connecting to the same outside address and port at a regular interval (>= 12 connections in
 *                 24 h; interval spread = MAD / median of the gaps <= 0.15) - command-and-control check-ins look like this
 *   exfiltration  an internal host's outbound bytes today against its own last 14 days (robust z on median / MAD, >= 50 MB, z >= 4)
 *   lateral       an internal host reaching many internal hosts on admin ports (SMB, RPC, RDP, WinRM, SSH) - today's distinct
 *                 targets against its own last 14 days (>= 10 targets and z >= 4, or >= 5 targets when it never did it before)
 *   new country   allowed outbound traffic to a country the organisation has not reached in the last 30 days
 * Host risk 0-100 = the itemised detections on that host (beacon 35, exfiltration 30, lateral 30, new country 10 - capped).
 * Suppression (a known updater, a backup job) is four-eyes: an analyst proposes, a different person with the security approver
 * scope approves; a suppression names host + destination (or host + kind) and expires.
 *   createNdr({ ch, db, alerts, state, log, now })  .run()  .view()  .propose(p, by)  .decide(id, d, by, comment)
 * Routes:  GET {P}/ndr analyst (names hosts) · POST {P}/ndr/run operator · GET {P}/ndr/suppressions analyst ·
 *          POST {P}/ndr/suppressions analyst · POST {P}/ndr/suppressions/:id/decide approve:security
 */
const { body, param } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('./routeutil');
const { guard } = require('../util/errors');

const PRIV4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];
const priv = (c) => `(isIPv4String(${c}) AND (${PRIV4.map((p) => `isIPAddressInRange(${c}, '${p}')`).join(' OR ')}))`;
const pub = (c) => `(isIPv4String(${c}) AND NOT ${priv(c)} AND NOT isIPAddressInRange(${c}, '127.0.0.0/8') AND NOT isIPAddressInRange(${c}, '169.254.0.0/16'))`;
const BYTES = "(toUInt64OrZero(fields['sentbyte']) + toUInt64OrZero(fields['rcvdbyte']) + toUInt64OrZero(fields['bytes']))";
const OUTB = "(toUInt64OrZero(fields['sentbyte']) + toUInt64OrZero(fields['bytes_sent']))";
const CTRY = "if(fields['dstcountry'] != '', fields['dstcountry'], fields['dst_country'])";
const NET = "category = 'network' AND action = 'allowed'";
const ADMIN_PORTS = [445, 135, 139, 3389, 5985, 5986, 22];
const W = { beacon: 35, exfil: 30, lateral: 30, country: 10 };
const num = (v) => (v == null || v === '' || !Number.isFinite(Number(v)) ? 0 : Number(v));
function median(a) { const s = a.slice().sort((x, y) => x - y), n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; }
function robustZ(hist, v) { const h = hist.filter(Number.isFinite); if (h.length < 7) return null; const m = median(h), mad = median(h.map((x) => Math.abs(x - m))); const s = 1.4826 * mad || Math.max(1, m * 0.1); return (v - m) / s; }

// beacon score from sorted connection times (seconds): regular gaps → small spread
function beacon(times) {
  const t = times.map(Number).filter(Number.isFinite).sort((a, b) => a - b), gaps = [];
  for (let i = 1; i < t.length; i++) { const g = t[i] - t[i - 1]; if (g > 0) gaps.push(g); }
  if (gaps.length < 11) return null;
  const m = median(gaps), spread = m ? median(gaps.map((g) => Math.abs(g - m))) / m : 1;
  return { period_s: Math.round(m), spread: Math.round(spread * 1000) / 1000, connections: t.length, regular: m >= 10 && m <= 6 * 3600 && spread <= 0.15 };
}

function createNdr({ ch, db, alerts, state, log, now } = {}) {
  const NOW = now || Date.now, L = log || { info() {}, warn() {} }, T = `${db || 'siem'}.events`;
  const sup = state.collection('ndr_suppressions'), last = state.collection('ndr_last');
  const q = (tag, sql) => ch.query(`/*q:ndr_${tag}*/ ` + sql, {}, { readonly: true });
  const suppressed = (host, dst, kind) => sup.all((s) => s.status === 'approved' && (!s.expires || s.expires >= new Date(NOW()).toISOString().slice(0, 10)) && s.host === host && (s.dst ? s.dst === dst : s.kind === kind)).length > 0;

  async function run() {
    const errors = [], det = [];
    const safe = async (tag, fn) => { try { await fn(); } catch (e) { errors.push(tag + ': ' + e.message); L.warn('ndr: detection failed', { detection: tag, err: e.message }); } };
    await safe('beacon', async () => {
      const rows = await q('beacon', `SELECT src_ip, dst_ip, dst_port, count() AS n, arraySort(groupArray(400)(toUnixTimestamp(ts))) AS t FROM ${T} WHERE ts >= now() - INTERVAL 1 DAY AND ${NET} AND ${priv('src_ip')} AND ${pub('dst_ip')} GROUP BY src_ip, dst_ip, dst_port HAVING n >= 12 ORDER BY n DESC LIMIT 3000`);
      for (const r of rows) { const b = beacon(r.t || []); if (b && b.regular) det.push({ kind: 'beacon', host: r.src_ip, dst: r.dst_ip + ':' + r.dst_port, severity: b.spread <= 0.05 ? 'high' : 'medium', why: `${b.connections} connections every ~${b.period_s} s (spread ${b.spread}) to ${r.dst_ip}:${r.dst_port}`, evidence: b }); }
    });
    await safe('exfil', async () => {
      const rows = await q('exfil', `SELECT src_ip, toDate(ts) AS d, sum(${OUTB}) AS b FROM ${T} WHERE ts >= now() - INTERVAL 15 DAY AND ${NET} AND ${priv('src_ip')} AND ${pub('dst_ip')} GROUP BY src_ip, d`);
      const today = new Date(NOW()).toISOString().slice(0, 10), by = new Map();
      for (const r of rows) { const k = r.src_ip; if (!by.has(k)) by.set(k, { hist: [], today: 0 }); const o = by.get(k); if (String(r.d) === today) o.today = num(r.b); else o.hist.push(num(r.b)); }
      for (const [h, o] of by) { const z = robustZ(o.hist, o.today); if (z != null && z >= 4 && o.today >= 50e6) det.push({ kind: 'exfil', host: h, dst: '', severity: z >= 8 ? 'high' : 'medium', why: `${Math.round(o.today / 1e6)} MB out today, usual ${Math.round((median(o.hist) || 0) / 1e6)} MB (z ${Math.round(z * 10) / 10})`, evidence: { today: o.today, usual: median(o.hist), z } }); }
    });
    await safe('lateral', async () => {
      const rows = await q('lateral', `SELECT src_ip, toDate(ts) AS d, uniqExact(dst_ip) AS n FROM ${T} WHERE ts >= now() - INTERVAL 15 DAY AND category = 'network' AND ${priv('src_ip')} AND ${priv('dst_ip')} AND dst_port IN (${ADMIN_PORTS.join(',')}) GROUP BY src_ip, d`);
      const today = new Date(NOW()).toISOString().slice(0, 10), by = new Map();
      for (const r of rows) { const k = r.src_ip; if (!by.has(k)) by.set(k, { hist: [], today: 0 }); const o = by.get(k); if (String(r.d) === today) o.today = num(r.n); else o.hist.push(num(r.n)); }
      for (const [h, o] of by) {
        const z = robustZ(o.hist, o.today), never = !o.hist.some((x) => x > 0);
        if ((o.today >= 10 && z != null && z >= 4) || (never && o.hist.length >= 7 && o.today >= 5)) det.push({ kind: 'lateral', host: h, dst: '', severity: o.today >= 25 ? 'high' : 'medium', why: `${o.today} internal hosts reached on admin ports today` + (never ? ' - it never did this before' : ` (usual ${median(o.hist)})`), evidence: { today: o.today, usual: median(o.hist), z } });
      }
    });
    await safe('country', async () => {
      const rows = await q('country', `SELECT ${CTRY} AS c, min(ts) >= now() - INTERVAL 1 DAY AS fresh, count() AS n, any(src_ip) AS host, sum(${BYTES}) AS b FROM ${T} WHERE ts >= now() - INTERVAL 30 DAY AND ${NET} AND ${priv('src_ip')} AND ${pub('dst_ip')} AND ${CTRY} NOT IN ('', 'Reserved') GROUP BY c HAVING fresh`);
      for (const r of rows) det.push({ kind: 'country', host: r.host, dst: r.c, severity: 'low', why: `First traffic to ${r.c} in 30 days (${num(r.n)} connections, ${Math.round(num(r.b) / 1e3)} KB)`, evidence: { connections: num(r.n), bytes: num(r.b) } });
    });
    const at = new Date(NOW()).toISOString(), out = det.filter((d) => !suppressed(d.host, d.dst, d.kind));
    const hosts = new Map();
    for (const d of out) { const h = hosts.get(d.host) || { host: d.host, risk: 0, reasons: [] }; h.reasons.push({ kind: d.kind, points: W[d.kind], why: d.why }); h.risk = Math.min(100, h.risk + W[d.kind]); hosts.set(d.host, h); }
    // a new high / medium detection raises one alert per host + kind + destination a day
    const day = at.slice(0, 10);
    for (const d of out) {
      if (d.severity === 'low') continue;
      const key = ['ndr', d.kind, d.host, d.dst, day].join('|');
      if (last.get(key)) continue; last.put({ id: key, at });
      if (alerts && typeof alerts.raise === 'function') alerts.raise({ rule_id: 'ndr-' + d.kind, rule_name: 'NDR: ' + ({ beacon: 'beaconing', exfil: 'unusual outbound volume', lateral: 'lateral movement' }[d.kind] || d.kind), rule_type: 'ndr',
        severity: d.severity === 'high' ? 3 : 2, ts_first: at, ts_last: at, count: 1, group: { host: d.host, dst: d.dst }, group_key: key, summary: d.host + ': ' + d.why, source: 'ndr', src_type: 'ndr', src_id: d.host, tags: ['ndr', d.kind, d.kind === 'beacon' ? 'T1071' : d.kind === 'exfil' ? 'T1041' : d.kind === 'lateral' ? 'T1021' : 'T1090'] });
    }
    for (const o of last.all((x) => Date.parse(x.at) < NOW() - 3 * 86400000)) last.remove(o.id);
    const res = { id: 'last', at, detections: out, hosts: [...hosts.values()].sort((a, b) => b.risk - a.risk).slice(0, 200), suppressed: det.length - out.length, errors };
    state.collection('ndr_run').put(res);
    // the day's detections by kind (the last run of the day wins: each run looks at the last 24 hours), for the 14-day trend
    const cnt = { id: day, date: day, beacon: 0, exfil: 0, lateral: 0, country: 0 }; for (const d of out) if (cnt[d.kind] !== undefined) cnt[d.kind]++;
    const daily = state.collection('ndr_daily'); daily.put(cnt); for (const o of daily.all((x) => x.date < new Date(NOW() - 40 * 86400000).toISOString().slice(0, 10))) daily.remove(o.id);
    return res;
  }
  function view() { const r = state.collection('ndr_run').get('last'), trend = state.collection('ndr_daily').all().sort((a, b) => (a.date < b.date ? -1 : 1)).slice(-14).map((x) => ({ date: x.date, beacon: x.beacon, exfil: x.exfil, lateral: x.lateral, country: x.country })); return r ? Object.assign({ ran: true, trend }, r) : { ran: false, detections: [], hosts: [], suppressed: 0, errors: [], note: 'NDR has not run yet - it runs every hour over the firewalls\' traffic logs, or press Run now.' }; }
  function nextId() { let m = 0; for (const s of sup.all()) { const n = Number(String(s.id).slice(4)); if (n > m) m = n; } return 'SUP-' + String(m + 1).padStart(5, '0'); }
  function propose(p, by) {
    if (!/^[0-9.]{7,15}$/.test(p.host)) throw new HttpError(400, 'host: the internal IPv4 address');
    if (!p.dst && !p.kind) throw new HttpError(400, 'dst or kind: what to suppress for this host');
    if (p.dst && !/^[0-9.]{7,15}(:\d{1,5})?$|^[A-Za-z .-]{2,40}$/.test(p.dst)) throw new HttpError(400, 'dst: address[:port] or a country name');
    if (p.expires && p.expires < new Date(NOW()).toISOString().slice(0, 10)) throw new HttpError(400, 'expires: today or later');
    return sup.put({ id: nextId(), host: p.host, dst: p.dst || '', kind: p.dst ? '' : p.kind, reason: p.reason, expires: p.expires || null, status: 'proposed', proposed_by: by, proposed_at: new Date(NOW()).toISOString() });
  }
  function decide(id, decision, by, comment) {
    const s = sup.get(id); if (!s) throw new HttpError(404, 'suppression not found');
    if (s.status !== 'proposed') throw new HttpError(409, 'only a proposed suppression is decided');
    if (String(s.proposed_by).toLowerCase() === String(by).toLowerCase()) throw new HttpError(403, 'four-eyes: the person who proposed a suppression does not approve it');
    if (decision === 'rejected' && !(comment && comment.length >= 5)) throw new HttpError(400, 'comment: say why it is rejected');
    return sup.patch(id, (x) => { x.status = decision; x.decided_by = by; x.decided_at = new Date(NOW()).toISOString(); x.comment = comment || ''; return x; });
  }
  return { run, view, propose, decide, suppressions: () => sup.all().sort((a, b) => String(b.id).localeCompare(String(a.id))) };
}

function register(api, deps) {
  if (!deps.state || !deps.ch) throw new Error('ndr needs deps.state and deps.ch');
  const P = prefixOf(deps), N = createNdr({ ch: deps.ch, db: (deps.config.clickhouse || {}).database || 'siem', alerts: deps.alerts, state: deps.state, log: deps.log, now: deps.now });
  let timer = null; const job = guard('soc.ndr.run', () => N.run());
  const schedule = (ms) => { if (deps.noTimer) return; timer = setTimeout(async () => { try { await job(); } finally { schedule(3600000); } }, ms); if (timer.unref) timer.unref(); };
  schedule(15 * 60000);
  api.route('GET', `${P}/ndr`, wrap(deps, 'analyst', () => N.view()));
  api.route('POST', `${P}/ndr/run`, wrap(deps, 'operator', async (ctx) => { body(ctx.body).done(); const r = await N.run(); audit(ctx, 'ndr.run', '', { detections: r.detections.length, errors: r.errors.length }); return r; }));
  api.route('GET', `${P}/ndr/suppressions`, wrap(deps, 'analyst', () => ({ suppressions: N.suppressions() })));
  api.route('POST', `${P}/ndr/suppressions`, wrap(deps, 'analyst', async (ctx) => {
    const b = body(ctx.body).str('host', { required: true, max: 15 }).str('dst', { max: 60 }).oneOf('kind', ['beacon', 'exfil', 'lateral', 'country']).date('expires').str('reason', { required: true, min: 10, max: 400 }).done();
    const s = N.propose(b, ctx.user); audit(ctx, 'ndr.suppression.propose', s.id, { host: s.host, dst: s.dst, kind: s.kind, expires: s.expires }); return s;
  }));
  api.route('POST', `${P}/ndr/suppressions/:id/decide`, wrap(deps, 'approve:security', async (ctx) => {
    const b = body(ctx.body).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 400 }).done();
    const s = N.decide(param(String(ctx.params.id || ''), 'id'), b.decision, ctx.user, b.comment); audit(ctx, 'ndr.suppression.' + (b.decision === 'approved' ? 'approve' : 'reject'), s.id, { host: s.host, proposed_by: s.proposed_by }); return s;
  }));
  return N;
}

module.exports = { register, createNdr, beacon, robustZ };
