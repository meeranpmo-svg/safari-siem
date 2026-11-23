// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Database Health Statement - the DBA's evidence when an application team says "the database is slow". For one database and
 * the complaint's time window it reads what the SIEM already holds and answers, check by check and with the reading behind
 * each one: was the database up and measured, was it busier or slower than its own normal (the same hours of the previous 7
 * days), were sessions blocked, did a plan change, did the alert log record errors, was the server short of CPU or memory,
 * and - for the application's server, when its IP is given - did the database record network timeouts from that client or
 * the firewall block traffic between them. The conclusion is one of: healthy, database, server, network, not measurable.
 * Nothing is inferred from missing data: a check without readings says "not measured", and too little data overall makes the
 * whole statement "not measurable" rather than "healthy".
 *
 *   POST {P}/db/statements                {instance, from, to, client_ip?, db_ip?, app?, complaint?, ticket?}   operator, audited
 *   GET  {P}/db/statements                list (operator)       GET {P}/db/statements/:id   one (operator)
 *   POST {P}/db/statements/:id/route      {team: dba|network|server|application, note}  operator - opens a SOC case, audited
 * Statements are kept (state "db_statements") with who prepared them and a SHA-256 digest of the findings.
 */
const crypto = require('node:crypto');
const { wrap, audit, prefixOf, HttpError } = require('../soc/routeutil');
const { body } = require('../util/check');

const DAY = 86400000, MAX_WINDOW = DAY, BUCKET = 300000;
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };
const r1 = (v) => (v === null || v === undefined ? null : Math.round(v * 10) / 10);
const CRIT_ORA = { 'ORA-00600': 'internal error', 'ORA-07445': 'process crash', 'ORA-04031': 'shared pool memory exhausted', 'ORA-01555': 'snapshot too old', 'ORA-00060': 'deadlock',
  'ORA-01578': 'block corruption', 'ORA-27072': 'file I/O error', 'ORA-00257': 'archiver stuck', 'ORA-19809': 'recovery area full', 'ORA-00020': 'processes limit reached', 'ORA-00018': 'sessions limit reached' };
const NET_TNS = /TNS-(12170|12535|12537|12547|12560|12571|00505|12606)\b/;
// wait classes that make a database slow, and whose problem it usually is
const CLASS_AREA = { 'User I/O': 'server', 'System I/O': 'server', Concurrency: 'database', Application: 'database', Configuration: 'database', Commit: 'database', Cluster: 'database', Network: 'network', Other: 'database', Scheduler: 'database', Queueing: 'database', Administrative: 'database' };

function createStatements({ ch, state, cases, now = Date.now, table = 'siem.events', log } = {}) {
  const col = state.collection('db_statements');
  const L = log || { warn() {} };
  const q = (tag, sql, p) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true, timeout_ms: 30000 });

  async function read(o) {
    const P = { inst: { type: 'String', value: o.instance }, f: { type: 'Int64', value: o.from }, t: { type: 'Int64', value: o.to },
      bf: { type: 'Int64', value: o.from - 7 * DAY }, hours: { type: 'Array(UInt8)', value: o.hours }, b: { type: 'Int64', value: BUCKET } };
    const W = `ts >= fromUnixTimestamp64Milli({f:Int64}) AND ts < fromUnixTimestamp64Milli({t:Int64}) AND has(tags, 'db-health') AND upper(fields['instance']) = {inst:String}`;
    const B = `ts >= fromUnixTimestamp64Milli({bf:Int64}) AND ts < fromUnixTimestamp64Milli({f:Int64}) AND toHour(ts) IN {hours:Array(UInt8)} AND has(tags, 'db-health') AND upper(fields['instance']) = {inst:String}`;
    const safe = (p) => p.catch((e) => { L.warn('db statement: a reading failed', { err: String(e.message).slice(0, 160) }); return null; });
    const [cov, updown, load, loadB, wc, wcB, waits, sess, block, longq, sql, plans, alerts, host, srv] = await Promise.all([
      safe(q('st_cov', `SELECT countDistinct(intDiv(toUnixTimestamp64Milli(ts) - {f:Int64}, {b:Int64})) AS buckets, count() AS n, any(lower(host)) AS h FROM ${table} WHERE ${W}`, P)),
      safe(q('st_updown', `SELECT action, count() AS n, max(toUnixTimestamp64Milli(ts)) AS last FROM ${table} WHERE ${W} AND action IN ('health-sample', 'instance-down') GROUP BY action`, P)),
      safe(q('st_load', `SELECT avg(toFloat64OrNull(fields['aas'])) AS aas, max(toFloat64OrNull(fields['aas'])) AS aas_max, avg(toFloat64OrNull(fields['db_cpu_s'])) AS cpu, count() AS n FROM ${table} WHERE ${W} AND action = 'load-profile'`, P)),
      safe(q('st_load_b', `SELECT avg(toFloat64OrNull(fields['aas'])) AS aas, count() AS n FROM ${table} WHERE ${B} AND action = 'load-profile'`, P)),
      safe(q('st_wc', `SELECT fields['class'] AS c, avg(toFloat64OrNull(fields['avg_ms'])) AS ms, avg(toFloat64OrNull(fields['time_s'])) AS ts_s, count() AS n FROM ${table} WHERE ${W} AND action = 'wait-class-rate' GROUP BY c`, P)),
      safe(q('st_wc_b', `SELECT fields['class'] AS c, avg(toFloat64OrNull(fields['avg_ms'])) AS ms, avg(toFloat64OrNull(fields['time_s'])) AS ts_s, count() AS n FROM ${table} WHERE ${B} AND action = 'wait-class-rate' GROUP BY c`, P)),
      safe(q('st_waits', `SELECT fields['event'] AS e, any(fields['class']) AS c, avg(toFloat64OrNull(fields['avg_ms'])) AS ms, sum(toFloat64OrNull(fields['time_s'])) AS tm FROM ${table} WHERE ${W} AND action = 'wait-event' GROUP BY e ORDER BY tm DESC LIMIT 5`, P)),
      safe(q('st_sess', `SELECT max(toFloat64OrNull(fields['total'])) AS total, max(toFloat64OrNull(fields['max_sessions'])) AS lim, max(toFloat64OrNull(fields['active'])) AS active FROM ${table} WHERE ${W} AND action = 'session-count'`, P)),
      safe(q('st_block', `SELECT count() AS n, max(toFloat64OrNull(fields['wait_s'])) AS w, any(fields['module']) AS md, any(fields['sql_id']) AS sq FROM ${table} WHERE ${W} AND action IN ('blocking-chain', 'blocked-session')`, P)),
      safe(q('st_long', `SELECT count() AS n, max(toFloat64OrNull(fields['elapsed_s'])) AS el, any(fields['sql_id']) AS sq, any(fields['module']) AS md FROM ${table} WHERE ${W} AND action = 'long-query'`, P)),
      safe(q('st_sql', `SELECT fields['sql_id'] AS s, any(fields['module']) AS md, sum(toFloat64OrNull(fields['elapsed_s'])) AS el, sum(toFloat64OrNull(fields['executions'])) AS ex FROM ${table} WHERE ${W} AND action = 'top-sql-delta' GROUP BY s ORDER BY el DESC LIMIT 5`, P)),
      safe(q('st_plans', `SELECT fields['sql_id'] AS s, any(fields['old_ms_exec']) AS o, any(fields['new_ms_exec']) AS nw, any(fields['module']) AS md FROM ${table} WHERE ${W} AND action = 'plan-change' GROUP BY s LIMIT 20`, P)),
      safe(q('st_alert', `SELECT fields['tail'] AS tail FROM ${table} WHERE ${W} AND action = 'alertlog-tail' LIMIT 500`, P)),
      safe(q('st_host', `SELECT max(toFloat64OrNull(fields['host_cpu_pct'])) AS cpu, min(toFloat64OrNull(fields['mem_free_mb'])) AS memfree, any(toFloat64OrNull(fields['mem_total_mb'])) AS memtot, count() AS n FROM ${table} WHERE ${W} AND action = 'host-stats'`, P)),
      safe(q('st_srv', `SELECT max(toFloat64OrNull(fields['load5']) / nullIf(toFloat64OrNull(fields['ncpu']), 0)) AS loadpc, min(toFloat64OrNull(fields['mem_avail_mb']) / nullIf(toFloat64OrNull(fields['mem_total_mb']), 0)) AS memav, any(fields['ip']) AS ip, count() AS n FROM ${table} WHERE ts >= fromUnixTimestamp64Milli({f:Int64}) - INTERVAL 30 MINUTE AND ts < fromUnixTimestamp64Milli({t:Int64}) AND action = 'db-server' AND (upper(fields['instance']) = {inst:String} OR has(splitByChar(',', upper(fields['pmon'])), {inst:String}))`, P)),
    ]);
    let fw = null;
    const dbIp = o.db_ip || (srv && srv[0] && srv[0].ip) || null;
    if (o.client_ip && dbIp) {
      const F = { f: P.f, t: P.t, c: { type: 'String', value: o.client_ip }, d: { type: 'String', value: dbIp } };
      fw = await safe(q('st_fw', `SELECT action, count() AS n, groupUniqArray(5)(toString(dst_port)) AS ports FROM ${table} WHERE ts >= fromUnixTimestamp64Milli({f:Int64}) AND ts < fromUnixTimestamp64Milli({t:Int64}) AND category = 'network'
        AND ((src_ip = {c:String} AND dst_ip = {d:String}) OR (src_ip = {d:String} AND dst_ip = {c:String})) GROUP BY action`, F));
    }
    return { cov, updown, load, loadB, wc, wcB, waits, sess, block, longq, sql, plans, alerts, host, srv, fw, dbIp };
  }

  function judge(o, R) {
    const checks = [], add = (area, status, title, evidence, reading) => checks.push({ area, status, title, evidence: [].concat(evidence || []).filter(Boolean), reading });
    const span = Math.max(1, Math.round((o.to - o.from) / BUCKET)), c0 = (R.cov && R.cov[0]) || {}, got = num(c0.buckets) || 0, coverage = Math.min(100, Math.round(got / span * 100));
    add('availability', coverage >= 60 ? 'ok' : coverage >= 20 ? 'warn' : 'not_measured', coverage ? `Readings cover ${coverage}% of the window` : 'No reading from this database in the window',
      [`${num(c0.n) || 0} readings in ${got} of ${span} five-minute intervals`], 'SIEM oracle-health readings');
    const ud = Object.fromEntries((R.updown || []).map((x) => [x.action, x]));
    if (ud['instance-down']) add('database', 'issue', 'The instance was reported down or not open in the window', [`${ud['instance-down'].n} down reading(s), last at ${new Date(num(ud['instance-down'].last)).toISOString()}`], 'instance state');
    else if (ud['health-sample']) add('database', 'ok', 'The instance was open throughout the readings', [`${ud['health-sample'].n} instance reading(s), none down`], 'instance state');
    // load against its own normal
    const ld = (R.load && R.load[0]) || {}, lb = (R.loadB && R.loadB[0]) || {}, aas = num(ld.aas), aasB = num(lb.aas);
    if (aas === null) add('database', 'not_measured', 'Database load not measured in the window', [], 'load profile');
    else {
      const ratio = aasB ? aas / aasB : null;
      add('database', ratio !== null && ratio >= 2 && aas >= 1 ? 'issue' : ratio !== null && ratio >= 1.5 && aas >= 1 ? 'warn' : 'ok',
        ratio === null ? `Average active sessions ${r1(aas)} (no baseline for these hours)` : `Average active sessions ${r1(aas)} - ${ratio >= 1.5 ? r1(ratio) + '× its normal' : 'within its normal'} (${r1(aasB)} at these hours over the previous 7 days)`,
        [`peak ${r1(num(ld.aas_max))}`, `DB CPU ${r1(num(ld.cpu))} s/s`], 'load profile (V$SYSMETRIC)');
    }
    // wait classes against their normal
    const base = Object.fromEntries((R.wcB || []).map((x) => [x.c, x]));
    let waitIssue = false;
    for (const w of (R.wc || [])) {
      const ms = num(w.ms), b = base[w.c], bms = b ? num(b.ms) : null, area = CLASS_AREA[w.c] || 'database';
      if (ms === null || num(w.ts_s) === null || num(w.ts_s) < 0.05) continue;   // a class that takes no real time cannot make anyone slow
      const ratio = bms ? ms / bms : null, high = (ratio !== null && ratio >= 2) || (w.c === 'User I/O' && ms >= 20) || (w.c === 'Commit' && ms >= 10);
      if (high) { waitIssue = true; add(area, 'issue', `${w.c} waits ${r1(ms)} ms on average${ratio !== null ? ` - ${r1(ratio)}× normal (${r1(bms)} ms)` : ''}`, [`${r1(num(w.ts_s))} s of waiting per second`], 'wait classes (V$WAITCLASSMETRIC)'); }
    }
    if ((R.wc || []).length && !waitIssue) add('database', 'ok', 'Wait times were within their normal range', (R.waits || []).slice(0, 3).map((x) => `${x.e}: ${r1(num(x.ms))} ms avg`), 'wait classes / top wait events');
    if (!(R.wc || []).length) add('database', 'not_measured', 'Wait times not measured in the window', [], 'wait classes');
    // sessions, blocking, long calls
    const ss = (R.sess && R.sess[0]) || {};
    if (num(ss.total) !== null && num(ss.lim)) { const pct = Math.round(num(ss.total) / num(ss.lim) * 100); add('database', pct >= 95 ? 'issue' : pct >= 85 ? 'warn' : 'ok', `Sessions peaked at ${num(ss.total)} of ${num(ss.lim)} (${pct}%)`, [num(ss.active) !== null ? `${num(ss.active)} active at most` : ''], 'session count'); }
    const bl = (R.block && R.block[0]) || {};
    if (num(bl.n)) add('database', num(bl.w) >= 60 ? 'issue' : 'warn', `Sessions were blocked by locks (${num(bl.n)} reading(s), longest ${Math.round(num(bl.w) || 0)} s)`,
      [bl.md ? `waiting module ${bl.md}` : '', bl.sq ? `SQL ${bl.sq}` : '', 'a lock is held by another session - usually an application transaction not committing'], 'blocking chains (V$SESSION)');
    else if (R.block) add('database', 'ok', 'No session was blocked by a lock', [], 'blocking chains');
    const lq = (R.longq && R.longq[0]) || {};
    if (num(lq.n)) add('database', 'warn', `Long-running calls seen (${num(lq.n)}, longest ${Math.round((num(lq.el) || 0) / 60)} min)`, [lq.sq ? `SQL ${lq.sq}` : '', lq.md ? `module ${lq.md}` : ''], 'long-running calls');
    const regress = (R.plans || []).filter((p) => num(p.nw) !== null && num(p.o) && num(p.nw) >= 2 * num(p.o));
    if (regress.length) add('database', 'issue', `${regress.length} statement(s) changed execution plan and became slower`, regress.slice(0, 3).map((p) => `SQL ${p.s}: ${r1(num(p.o))} → ${r1(num(p.nw))} ms per execution${p.md ? ' (' + p.md + ')' : ''}`), 'plan changes (V$SQL)');
    // alert log: database errors and network timeouts that name the client
    const ora = {}, clients = {}; let tns = 0;
    for (const a of (R.alerts || [])) {
      const lines = String(a.tail || '').split('\n');
      for (const l of lines) {
        for (const m of l.match(/ORA-\d{5}/g) || []) if (CRIT_ORA[m]) ora[m] = (ora[m] || 0) + 1;
        if (NET_TNS.test(l)) tns++;
        const h = /Client address:.*?\(HOST=([0-9.]+)\)/i.exec(l); if (h) clients[h[1]] = (clients[h[1]] || 0) + 1;
      }
    }
    const oraK = Object.keys(ora);
    if (oraK.length) add('database', 'issue', 'Serious database errors in the alert log', oraK.map((k) => `${k} ${CRIT_ORA[k]} ×${ora[k]}`), 'alert log');
    else if (R.alerts) add('database', 'ok', 'No serious database error in the alert log', [], 'alert log');
    if (o.client_ip && clients[o.client_ip]) add('network', 'issue', `The database recorded ${clients[o.client_ip]} dropped / timed-out connection(s) from ${o.client_ip}`, ['TNS-12170 / 12535 style errors name this client: the connection was cut between the application server and the database (firewall idle timeout, network loss)'], 'alert log network errors');
    else if (tns) add('network', 'warn', `${tns} network timeout(s) recorded by the database for other clients`, Object.entries(clients).slice(0, 5).map(([ip, n]) => `${ip} ×${n}`), 'alert log network errors');
    else if (o.client_ip && R.alerts) add('network', 'ok', `No dropped connection from ${o.client_ip} recorded by the database`, [], 'alert log network errors');
    // server
    const hs = (R.host && R.host[0]) || {}, sv = (R.srv && R.srv[0]) || {};
    const cpu = num(hs.cpu), loadpc = num(sv.loadpc) !== null ? num(sv.loadpc) * 100 : null, memav = num(sv.memav) !== null ? num(sv.memav) * 100 : (num(hs.memfree) !== null && num(hs.memtot) ? num(hs.memfree) / num(hs.memtot) * 100 : null);
    if (cpu === null && loadpc === null && memav === null) add('server', 'not_measured', 'Server CPU and memory not measured in the window', [], 'host readings');
    else {
      const busy = (cpu !== null && cpu >= 90) || (loadpc !== null && loadpc >= 150), lowmem = memav !== null && memav < 5;
      add('server', busy || lowmem ? 'issue' : (cpu !== null && cpu >= 75) ? 'warn' : 'ok', busy || lowmem ? 'The database server was short of capacity' : 'The database server had capacity to spare',
        [cpu !== null ? `host CPU up to ${r1(cpu)}%` : '', loadpc !== null ? `load up to ${r1(loadpc)}% of its CPUs` : '', memav !== null ? `memory available down to ${r1(memav)}%` : ''], 'host readings (V$OSSTAT / server SSH read)');
    }
    // firewall between the application server and the database
    if (o.client_ip) {
      if (!R.dbIp) add('network', 'not_measured', 'Firewall path not checked: the database server IP is not known (give db_ip)', [], 'firewall traffic logs');
      else if (!R.fw || !R.fw.length) add('network', 'not_measured', `No firewall log between ${o.client_ip} and ${R.dbIp} (the traffic does not cross a logging firewall, or it is not logged)`, [], 'firewall traffic logs');
      else { const by = Object.fromEntries(R.fw.map((x) => [x.action, num(x.n)])); add('network', by.blocked ? 'issue' : 'ok', by.blocked ? `The firewall blocked ${by.blocked} connection(s) between ${o.client_ip} and ${R.dbIp}` : `The firewall allowed every connection between ${o.client_ip} and ${R.dbIp}`, [`allowed ${by.allowed || 0}`, `blocked ${by.blocked || 0}`], 'firewall traffic logs'); }
    }
    const issues = checks.filter((x) => x.status === 'issue'), areas = [...new Set(issues.map((x) => x.area))];
    let conclusion, text;
    if (coverage < 20) { conclusion = 'not_measurable'; text = `Not measurable: the database sent readings for only ${coverage}% of the window. No statement about its health can be made from this platform for that time.`; }
    else if (!areas.length) { conclusion = 'healthy'; text = `The database ${o.instance} was healthy in this window: it was up, its load and wait times were within its own normal${checks.some((x) => x.status === 'warn') ? ' (notes below)' : ''}, and no lock, plan or error problem was recorded.${o.client_ip ? '' : ' Give the application server IP to check the network path as well.'}`; }
    else { conclusion = areas.length > 1 ? 'mixed' : areas[0]; text = `Problems found in this window: ${areas.join(', ')}. ${issues.map((x) => x.title).join('; ')}.`; }
    return { coverage, checks, conclusion, conclusion_text: text, areas };
  }

  async function create(b, by) {
    const v = body(b).str('instance', { required: true, max: 64, re: /^[A-Za-z][A-Za-z0-9_$#.]{0,63}$/, msg: 'instance must be an Oracle instance / DB_UNIQUE_NAME' })
      .str('from', { required: true, max: 40 }).str('to', { required: true, max: 40 })
      .str('client_ip', { ip: true, max: 15 }).str('db_ip', { ip: true, max: 15 }).str('app', { max: 120 }).str('complaint', { max: 1000 }).str('ticket', { max: 60 }).done();
    const f = Date.parse(v.from), t = Date.parse(v.to);
    if (!Number.isFinite(f)) throw new HttpError(400, 'from must be a date-time'); if (!Number.isFinite(t)) throw new HttpError(400, 'to must be a date-time');
    if (t <= f) throw new HttpError(400, 'to must be after from');
    if (t - f > MAX_WINDOW) throw new HttpError(400, 'the window can be at most 24 hours - narrow it to when the complaint happened');
    if (t > now() + 60000) throw new HttpError(400, 'to cannot be in the future');
    if (f < now() - 30 * DAY) throw new HttpError(400, 'readings are kept 30 days for this statement - choose a window inside them');
    const hours = []; for (let x = Math.floor(f / 3600000); x <= Math.floor((t - 1) / 3600000) && hours.length < 24; x++) { const h = new Date(x * 3600000).getUTCHours(); if (!hours.includes(h)) hours.push(h); }
    const o = { instance: v.instance.toUpperCase(), from: f, to: t, client_ip: v.client_ip || null, db_ip: v.db_ip || null, hours };
    const R = await read(o), J = judge(o, R);
    const n = col.all().length + 1, id = 'DHS-' + new Date(now()).toISOString().slice(0, 10).replace(/-/g, '') + '-' + String(n).padStart(3, '0');
    const doc = { instance: o.instance, from: new Date(f).toISOString(), to: new Date(t).toISOString(), client_ip: o.client_ip, db_ip: R.dbIp, app: v.app || '', complaint: v.complaint || '', ticket: v.ticket || '',
      coverage: J.coverage, checks: J.checks, conclusion: J.conclusion, conclusion_text: J.conclusion_text, areas: J.areas, top_waits: (R.waits || []).map((x) => ({ event: x.e, class: x.c, avg_ms: r1(num(x.ms)) })),
      top_sql: (R.sql || []).map((x) => ({ sql_id: x.s, module: x.md || '', elapsed_s: r1(num(x.el)), executions: num(x.ex) })) };
    const rec = Object.assign({ id, prepared_by: by, prepared_at: now(), routing: [] }, doc, { digest: 'sha256:' + crypto.createHash('sha256').update(JSON.stringify(doc)).digest('hex') });
    col.put(rec);
    return rec;
  }
  function route(id, b, by) {
    const s = col.get(id); if (!s) throw new HttpError(404, 'no statement ' + id);
    const v = body(b).oneOf('team', ['dba', 'network', 'server', 'application'], { required: true }).str('note', { required: true, min: 3, max: 1000 }).done();
    const TEAM = { dba: 'DBA', network: 'Network', server: 'Server / hardware', application: 'Application' };
    let caseId = null;
    if (cases && typeof cases.create === 'function') {
      const c = cases.create({ title: `[${TEAM[v.team]}] ${s.instance} ${s.from.slice(0, 16)}-${s.to.slice(11, 16)}: ${s.app || 'database complaint'}`,
        description: `${s.conclusion_text}\n\nRouted by ${by}: ${v.note}\nStatement ${s.id} (${s.digest})${s.ticket ? '\nTicket ' + s.ticket : ''}`, severity: s.conclusion === 'healthy' ? 1 : 2, auto_playbook: false }, by);
      caseId = c && c.id;
    }
    s.routing = (s.routing || []).concat([{ team: v.team, note: v.note, by, at: now(), case_id: caseId }]);
    col.put(s);
    return s;
  }
  const list = () => col.all().sort((a, b) => b.prepared_at - a.prepared_at).slice(0, 200).map((s) => ({ id: s.id, instance: s.instance, from: s.from, to: s.to, app: s.app, conclusion: s.conclusion, prepared_by: s.prepared_by, prepared_at: s.prepared_at, routed: (s.routing || []).map((r) => r.team) }));
  const get = (id) => { const s = col.get(id); if (!s) throw new HttpError(404, 'no statement ' + id); return s; };
  return { create, route, list, get, judge };
}

function register(api, deps) {
  if (!deps.state || !deps.ch) return null;
  const P = prefixOf(deps), db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  const S = createStatements({ ch: deps.ch, state: deps.state, cases: deps.cases, now: deps.now, table: `${db}.events`, log: deps.log });
  const ID = /^DHS-\d{8}-\d{3,}$/;
  // operator: the statement names applications, client IPs and SQL - not for every viewer
  api.route('POST', `${P}/db/statements`, wrap(deps, 'operator', async (ctx) => {
    const s = await S.create(ctx.body, ctx.user);
    audit(ctx, 'db.statement.create', s.id, { instance: s.instance, from: s.from, to: s.to, client_ip: s.client_ip, conclusion: s.conclusion, digest: s.digest });
    return ctx.ok(s);
  }));
  api.route('GET', `${P}/db/statements`, wrap(deps, 'operator', (ctx) => ctx.ok({ items: S.list() })));
  api.route('GET', `${P}/db/statements/:id`, wrap(deps, 'operator', (ctx) => { if (!ID.test(String(ctx.params.id || ''))) throw new HttpError(400, 'id must be a statement id (DHS-yyyymmdd-nnn)'); return ctx.ok(S.get(ctx.params.id)); }));
  api.route('POST', `${P}/db/statements/:id/route`, wrap(deps, 'operator', (ctx) => {
    if (!ID.test(String(ctx.params.id || ''))) throw new HttpError(400, 'id must be a statement id (DHS-yyyymmdd-nnn)');
    const s = S.route(ctx.params.id, ctx.body, ctx.user), r = s.routing[s.routing.length - 1];
    audit(ctx, 'db.statement.route', s.id, { team: r.team, case_id: r.case_id });
    return ctx.ok(s);
  }));
  deps.dbStatements = S;
  return S;
}

module.exports = { register, createStatements };
