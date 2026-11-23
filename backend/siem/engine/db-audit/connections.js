// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Application Connections - which APIs and services are connected to a database, which dropped off, which the listener
 * refused and why, which clients the database saw time out, and the database links: where each points, as which remote user,
 * and whether that user can change data on the remote database (when the remote database is monitored too).
 * Everything comes from readings the SIEM already holds (the platform's read-only connection): app-session (GV$SESSION per
 * service / machine / program / user), lsnr-conn (listener log), alertlog-tail (TNS timeouts naming the client), db-link and
 * user-write. A reading the database did not send is "not reported", never zero.
 *
 *   GET {P}/db/oracle/connections?instance=X     operator (machine names, programs and database users)
 *   GET {P}/db/oracle/connections/intel?instance=X  operator - learning over 14 days, see connections-intel.js
 */
const { wrap, prefixOf, HttpError } = require('../soc/routeutil');

// listener refusals: what the code means and what fixes it (read-only advice)
const TNS = {
  '12514': ['service not known to the listener', 'The service name the application asks for is not registered: check the name in its connect string, that the service is started on this instance / RAC node (srvctl status service), and ALTER SYSTEM REGISTER.'],
  '12505': ['SID not known to the listener', 'The application uses a SID that is not registered: switch the connect string to the SERVICE_NAME, or fix the SID.'],
  '12516': ['no handler with a matching protocol stack', 'Usually the processes limit: compare sessions / processes with their limits; look for an application pool leaking connections.'],
  '12518': ['listener could not hand off the connection', 'The database process could not be started in time: check the processes limit, server memory and the listener log around that minute.'],
  '12519': ['no appropriate service handler found', 'The database has reached its processes limit (or the service is blocked): raise PROCESSES only after finding the application that holds idle sessions.'],
  '12520': ['no handler for the requested server type', 'Dispatchers / shared server not available for this service, or the processes limit: check the service type in the connect string.'],
  '12526': ['database in restricted mode', 'The database is in restricted session: only users with RESTRICTED SESSION may connect.'],
  '12528': ['instance blocking new connections', 'The instance is starting, shutting down or mounted only: check the instance state.'],
  '12547': ['lost contact', 'The connection was cut while it was being made: network / firewall between the client and the database.'],
  '12537': ['connection closed', 'The client or a firewall closed the connection: check firewall idle timeouts and the client side.'],
};
const tns = (code) => { const t = TNS[String(code)]; return t ? { meaning: t[0], fix: t[1] } : { meaning: 'refused (TNS-' + code + ')', fix: 'Look up the code in the listener log around that time.' }; };

function createConnections({ ch, now = Date.now, table = 'siem.events' } = {}) {
  const q = (tag, sql, p) => ch.query(`/*q:${tag}*/ ` + sql, p, { readonly: true, timeout_ms: 30000 });
  const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };
  const latest = (inst, action, hours) => q('cn_' + action.replace(/-/g, '_'), `SELECT upper(fields['instance']) AS inst, fields['key'] AS k, argMax(fields, ts) AS f, max(toUnixTimestamp64Milli(ts)) AS last_ms
    FROM ${table} WHERE ts >= now64(3) - INTERVAL ${Number(hours)} HOUR AND has(tags, 'db-health') AND action = {a:String}${inst ? " AND upper(fields['instance']) = {inst:String}" : ''}
    GROUP BY inst, k LIMIT 5000`, Object.assign({ a: { type: 'String', value: action } }, inst ? { inst: { type: 'String', value: inst } } : {}));

  // a link's connect string names the remote database (SERVICE_NAME / SID / an alias); match it to a monitored database
  function remoteOf(host, known) {
    const h = String(host || '').toUpperCase();
    const svc = (/SERVICE_NAME\s*=\s*([^)\s]+)/.exec(h) || /SID\s*=\s*([^)\s]+)/.exec(h) || [])[1] || (/^[A-Z0-9_.$#-]+$/.test(h) ? h.split('.')[0] : (/\/([A-Z0-9_.$#-]+)\s*$/.exec(h) || [])[1]);
    if (!svc) return null;
    const base = svc.split('.')[0];
    return known.find((k) => k === svc || k === base) || null;
  }

  async function view(instance) {
    const inst = String(instance || '').toUpperCase();
    if (!/^[A-Z][A-Z0-9_$#.]{0,63}$/.test(inst)) throw new HttpError(400, 'instance must be an Oracle instance / DB_UNIQUE_NAME');
    const t = now();
    const [apps, lsnr, alerts, links, writes] = await Promise.all([
      latest(inst, 'app-session', 26), latest(inst, 'lsnr-conn', 3),
      q('cn_alert', `SELECT fields['tail'] AS tail, toUnixTimestamp64Milli(ts) AS t FROM ${table} WHERE ts >= now64(3) - INTERVAL 24 HOUR AND has(tags, 'db-health') AND action = 'alertlog-tail' AND upper(fields['instance']) = {inst:String} LIMIT 2000`, { inst: { type: 'String', value: inst } }),
      latest(inst, 'db-link', 26), latest('', 'user-write', 26),
    ]);
    // applications: the latest pass vs what was connected earlier in the day
    const pass = (apps || []).reduce((m, r) => Math.max(m, num(r.last_ms) || 0), 0);
    const appRows = (apps || []).map((r) => {
      const f = r.f || {}, lm = num(r.last_ms) || 0, cur = pass && lm >= pass - 10 * 60000;
      return { service: f.service || '?', machine: f.machine || '?', program: f.program || '?', db_user: f.db_user || '?', module: f.module || '', sessions: cur ? num(f.sessions) || 0 : 0,
        active: cur ? num(f.active) || 0 : 0, max_idle_s: cur ? num(f.max_idle_s) : null, oldest_logon: cur ? f.oldest_logon || null : null, instances: cur ? num(f.instances) : null,
        state: cur ? 'connected' : 'dropped', last_seen: lm, last_sessions: num(f.sessions) || 0 };
    }).sort((a, b) => (a.state === b.state ? b.sessions - a.sessions || b.last_sessions - a.last_sessions : a.state === 'dropped' ? -1 : 1));
    // listener: connects and refusals per client and service
    const byClient = new Map();
    for (const r of (lsnr || [])) {
      const f = r.f || {}, k = `${f.client_host || '?'}|${f.service || '?'}`, n = num(f.n) || 0;
      const c = byClient.get(k) || { client_host: f.client_host || '?', service: f.service || '?', programs: [], ok: 0, refused: 0, codes: {}, last: null };
      if (f.program && f.program !== '?' && !c.programs.includes(f.program)) c.programs.push(f.program);
      if (String(f.code) === '0') c.ok += n; else { c.refused += n; c.codes[f.code] = (c.codes[f.code] || 0) + n; }
      if (!c.last || String(f.last) > c.last) c.last = f.last || c.last;
      byClient.set(k, c);
    }
    const listener = [...byClient.values()].map((c) => Object.assign(c, { reasons: Object.entries(c.codes).map(([code, n]) => Object.assign({ code, n }, tns(code))) }))
      .sort((a, b) => b.refused - a.refused || b.ok - a.ok);
    // the database's own record of clients that timed out / were cut (alert log, 24 h)
    const drops = {};
    for (const a of (alerts || [])) {
      const lines = String(a.tail || '').split('\n'); let pend = false;
      for (const l of lines) {
        if (/TNS-(12170|12535|12537|12547|12560|00505)\b|Fatal NI connect error/.test(l)) pend = true;
        const h = /Client address:.*?\(HOST=([0-9a-fA-F.:]+)\)/i.exec(l);
        if (h && pend) { drops[h[1]] = drops[h[1]] || { client_host: h[1], n: 0, last: 0 }; drops[h[1]].n++; drops[h[1]].last = Math.max(drops[h[1]].last, num(a.t) || 0); pend = false; }
      }
    }
    // database links: where they point, as whom, and what that user can change over there
    const W = new Map(); for (const r of (writes || [])) W.set(`${r.inst}|${r.k}`, r.f || {});
    const known = [...new Set((writes || []).map((r) => r.inst))];
    const linkRows = (links || []).map((r) => {
      const f = r.f || {}, remote = remoteOf(f.host, known), ru = String(f.remote_user || '').toUpperCase();
      let verdict, why = [];
      if (!ru) { verdict = 'current_user'; why.push('connects as whoever uses it (CURRENT_USER) - their own rights on the remote side apply'); }
      else if (!remote) { verdict = 'not_monitored'; why.push('the remote database is not monitored here - its rights for ' + ru + ' cannot be checked'); }
      else {
        const w = W.get(`${remote}|${ru}`);
        if (!w) { verdict = 'unknown_user'; why.push(`${ru} was not reported by ${remote} (no such application user, or an Oracle-maintained one)`); }
        else {
          if (w.dba) why.push('role ' + w.dba); if (w.any_dml) why.push(w.any_dml);
          if (num(w.own_tables)) why.push(`owns ${num(w.own_tables)} table(s)`); if (num(w.obj_write)) why.push(`can insert / update / delete ${num(w.obj_write)} table(s) of other schemas`);
          verdict = w.dba || w.any_dml ? 'write_all' : num(w.own_tables) || num(w.obj_write) ? 'write_some' : 'read_only';
          if (verdict === 'read_only') why.push('no write right found (direct grants and roles held directly)');
        }
      }
      return { owner: f.owner || '', link: f.link || r.k, remote_user: ru || null, host: f.host || '', created: f.created || null, remote_db: remote, verdict, why,
        fix: verdict === 'write_all' ? `Give the link its own least-privileged user on ${remote} with SELECT on just what it reads, then recreate the link with that user.` : verdict === 'write_some' ? 'Check that this application really needs to change data over the link; if not, use a read-only user for it.' : '' };
    }).sort((a, b) => ['write_all', 'write_some', 'not_monitored', 'unknown_user', 'current_user', 'read_only'].indexOf(a.verdict) - ['write_all', 'write_some', 'not_monitored', 'unknown_user', 'current_user', 'read_only'].indexOf(b.verdict));
    const connected = appRows.filter((a) => a.state === 'connected');
    return { generated_at: t, instance: inst, read_at: pass || null,
      summary: { applications: connected.length, sessions: connected.reduce((s, a) => s + a.sessions, 0), dropped: appRows.filter((a) => a.state === 'dropped').length,
        refused: listener.reduce((s, c) => s + c.refused, 0), timeouts: Object.values(drops).reduce((s, d) => s + d.n, 0), links: linkRows.length, links_write: linkRows.filter((l) => l.verdict === 'write_all' || l.verdict === 'write_some').length },
      applications: appRows.slice(0, 300), listener: listener.slice(0, 200), timeouts: Object.values(drops).sort((a, b) => b.n - a.n), links: linkRows,
      reported: { sessions: !!(apps && apps.length), listener: !!(lsnr && lsnr.length), links: !!(links && links.length) },
      note: 'Applications from GV$SESSION each pass; "dropped" = connected earlier in the last 24 h, no session now. Listener lines only when the listener logs under this database\'s diagnostic_dest (a SCAN / grid listener usually does not). A link\'s rights are judged from the remote database\'s own reading - only when that database is monitored too.' };
  }
  return { view, remoteOf, TNS, tns };
}

function register(api, deps) {
  if (!deps.ch) return null;
  const P = prefixOf(deps), db = (deps.config && deps.config.clickhouse && deps.config.clickhouse.database) || 'siem';
  const C = createConnections({ ch: deps.ch, now: deps.now, table: `${db}.events` });
  // operator: machine names, programs, database users and link targets
  api.route('GET', `${P}/db/oracle/connections`, wrap(deps, 'operator', async (ctx) => ctx.ok(await C.view((ctx.query || {}).instance))));
  deps.dbConnections = C;
  // what 14 days of these readings teach (connections-intel.js): normal sessions per hour, missing / leaking / spiking / new clients, shared accounts, map
  require('./connections-intel').register(api, deps, P);
  return C;
}

module.exports = { register, createConnections, TNS, tns: (c) => createConnections({}).tns(c) };
