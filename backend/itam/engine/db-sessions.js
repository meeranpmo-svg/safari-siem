// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Databases -> Long-Running Queries ({P} = /api/itam). Finds the sessions hurting an Oracle database and stops them - only
 * after a DBA approver has said yes.
 *
 * Read (live, on demand): inv-helper op "oracle_long" with the database's READ-ONLY monitoring login (same safe-privilege check
 *   as every other read): active user sessions whose current call has run >= min_s seconds (not idle waits), and every session
 *   that blocks others (an idle session holding locks included). Each gets an impact list in plain words (blocks N sessions,
 *   running for X min, temp space, CPU, waiting on …). SQL literals are masked in the helper.
 * Stop: CANCEL (the running statement only - the session and its transaction stay; Oracle 18c+) or KILL (the session; its open
 *   transaction is rolled back). Never with the monitoring login: through a SEPARATE session-control login (ZYB_CONTROL) that
 *   holds CREATE SESSION and EXECUTE on ZYB_OPS.SESSION_CTL only (install/oracle-session-control.sql). That procedure re-checks
 *   inside the database that the session is still the same user running the same SQL_ID and is not a protected account.
 * Four-eyes: an operator asks (with a reason) for a session seen in the last read (<= READ_FRESH_MS old); a DIFFERENT person
 *   decides - an administrator or a named DBA approver (Roles & Functions, scope eng:dba or its group infra); service / AI
 *   identities never decide. A request not decided in REQ_TTL_MS expires (the session will have changed). Every step audited.
 * Routes: GET /db-sessions (operator) - databases + whether session control is set up
 *         GET /db-sessions/long?db=&min_s= (operator) - live read
 *         POST /db-sessions/control {db, username, password} · /db-sessions/control/remove {db} (admin, a person)
 *         GET /db-sessions/requests (operator) · POST /db-sessions/requests {db, inst_id, sid, serial, mode, reason} (operator)
 *         Use cases, learning and the advisor: see db-sessions-intel.js (/db-sessions/cases, /insights, /ask)
 *         POST /db-sessions/requests/:id/decide {decision: approve|reject, comment} (DBA approver / admin, never the requester)
 */
const SC = require('./approve-scopes');

const READ_FRESH_MS = 10 * 60000, REQ_TTL_MS = 30 * 60000, SCOPE = 'eng:dba';

function createDbSessions(app, opts = {}) {
  const store = app.store, ctl = store.collection('db_session_ctl'), reqs = store.collection('db_session_requests'), counters = store.collection('counters');
  const H = opts.dbHealth, now = opts.now || Date.now;
  const dc = (app.config && app.config.discovery) || {};
  const runHelper = opts.invRun || require('./discovery/methods/login').realRunner(dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3');
  const D = () => opts.discovery || app.discovery || null;
  const reads = new Map();   // db key -> {at, sessions}
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  // a database, helper or vault failure is not an engine fault: 424 keeps the reason in words (the HTTP layer masks every 5xx
  // as "internal error", which told the DBA nothing)
  const dep = (m) => bad(m, 424);
  const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action, target, detail }); };
  const iso = (t) => new Date(t).toISOString();

  function dbs() { if (!H || typeof H.targets !== 'function') throw dep('Database Health is not installed on this server (add-db-health.sh)'); const r = H.targets(); return (r && r.list) || []; }
  function dbOf(key) { const t = dbs().find((x) => x.key === String(key || '')); if (!t) throw bad('database not found - choose one of the monitored databases', 404); return t; }
  function label(t) { return t.host || t.ip; }
  function list() {
    return { databases: dbs().map((t) => { const c = ctl.get(t.key); return { key: t.key, label: label(t), ip: t.ip, service: t.service || '', instance: t.instance || '',
      control: c ? { configured: true, ok: !!(c.test && c.test.ok), error: c.test && !c.test.ok ? c.test.error : null, by: c.by, at: c.at } : { configured: false } }; }),
      read_fresh_min: READ_FRESH_MS / 60000, request_ttl_min: REQ_TTL_MS / 60000, pending: reqs.all((r) => r.status === 'pending').length };
  }
  function monitorCred(t) { const V = D() && D().vault; if (!V || (V.available && !V.available())) throw dep('the credential vault is not available (Asset Discovery)'); return V; }
  function openCred(V, id, what) {
    if (!id) throw dep('no saved ' + what + ' for this database - add it in Databases (Connect)');
    try { return V.open(id); } catch (e) { throw dep('the saved ' + what + ' could not be opened (' + (e.status === 404 ? 'it was removed - save it again' : 'vault error') + ')'); }
  }
  async function helper(args) {
    try { return await runHelper(args); } catch (e) { return { ok: false, error: 'the database helper did not run (' + clip(e && e.message, 160) + ')' }; }
  }

  // what makes a session hurt the database, in plain words (highest first); the score only orders the list
  function impact(x) {
    const why = []; let score = 0;
    if (x.blocks > 0) { why.push(`blocks ${x.blocks} other session${x.blocks > 1 ? 's' : ''}`); score += 1000 + x.blocks * 100; }
    if (x.status !== 'ACTIVE' && x.blocks > 0) why.push('idle but holding locks (an open transaction nobody is finishing)');
    if (x.status === 'ACTIVE' && x.elapsed_s != null) { why.push(`running for ${x.elapsed_s >= 3600 ? Math.round(x.elapsed_s / 360) / 10 + ' h' : Math.round(x.elapsed_s / 60) + ' min'}`); score += Math.min(500, x.elapsed_s / 60); }
    if (x.temp_mb >= 1024) { why.push(`${Math.round(x.temp_mb / 102.4) / 10} GB of TEMP`); score += x.temp_mb / 100; }
    if (x.pga_mb >= 1024) { why.push(`${Math.round(x.pga_mb / 102.4) / 10} GB of PGA memory`); score += x.pga_mb / 200; }
    if (x.status === 'ACTIVE' && x.state !== 'WAITING') why.push('on CPU');
    else if (x.status === 'ACTIVE' && x.event) why.push(`waiting on ${x.event}`);
    if (x.blocked_by) why.push(`itself blocked by SID ${x.blocked_by}${x.blocked_by_inst ? ' @' + x.blocked_by_inst : ''}`);
    return { score: Math.round(score), why };
  }

  async function readLong(q, who) {
    const t = dbOf(q && q.db), min = Math.max(5, Math.min(86400, Math.round(Number((q && q.min_s) || 60))));
    const V = monitorCred(t), c = openCred(V, t.cred_id, 'monitoring login');
    let r;
    try { r = await helper({ op: 'oracle_long', min_s: min, host: t.ip, port: t.port, service: t.service, username: c.secret.username, password: c.secret.password, tls: t.tls || (c.target && c.target.tls) || 'off', ca_file: t.ca_file || (c.target && c.target.ca_file) }); }
    finally { c.release(); }
    if (r && !r.ok && r.error_class === 'grant') throw dep(clip(r.error, 1200));   // names the views and the GRANT lines
    if (!r || !r.ok) throw bad('the database did not answer the session read: ' + ((r && (r.error || r.error_class)) || 'no answer'), r && r.error_class === 'unsafe' ? 409 : 424);
    const at = now(), sessions = (r.sessions || []).map((x) => Object.assign(x, { key: `${x.inst_id}:${x.sid}:${x.serial}` }, impact(x))).sort((a, b) => b.score - a.score);
    reads.set(t.key, { at, sessions });
    // use cases and learning (db-sessions-intel.js): records this read and gives every session its verdict and why
    let intel = null; try { const I = (app.addons || {}).dbSessionsIntel; if (I) intel = I.annotate(t.key, sessions, at); } catch (e) { if (app.log && app.log.every) app.log.every('db-sessions:intel', 600000, 'warn', 'long-running queries: use cases could not be applied', { err: e.message }); }
    audit(who, 'db.sessions.read', t.key, { database: label(t), min_s: min, sessions: sessions.length });
    const c2 = ctl.get(t.key);
    return { at: iso(at), database: { key: t.key, label: label(t), service: t.service || '' }, min_s: min, sessions, notes: (r.notes || []).map((n) => clip(n, 400)),
      control: c2 ? { configured: true, ok: !!(c2.test && c2.test.ok), error: c2.test && !c2.test.ok ? c2.test.error : null } : { configured: false },
      intel,
      totals: { sessions: sessions.length, blockers: sessions.filter((x) => x.blocks > 0).length, blocked: sessions.reduce((a, x) => a + (x.blocks || 0), 0), over_1h: sessions.filter((x) => x.status === 'ACTIVE' && x.elapsed_s >= 3600).length } };
  }

  // the session-control login: kept sealed in the Asset Discovery vault like every database login; tested before it is kept
  async function setControl(b, who) {
    if (!SC.isHuman(who && who.user)) throw bad('only a person sets this up', 403);
    const t = dbOf(b && b.db), V = monitorCred(t);
    const user = clip(b && b.username, 128), pw = String((b && b.password) || '');
    if (!user || !pw) throw bad('enter the session-control user (ZYB_CONTROL) and its password');
    const mon = V.get ? V.get(t.cred_id) : null, mt = (mon && mon.target) || {};
    const target = { engine: 'oracle', port: t.port, service: t.service }; if (t.tls || mt.tls) target.tls = t.tls || mt.tls; if (t.ca_file || mt.ca_file) target.ca_file = t.ca_file || mt.ca_file;
    const test = await helper({ op: 'oracle_ctl_test', host: t.ip, port: t.port, service: t.service, username: user, password: pw, tls: target.tls || 'off', ca_file: target.ca_file });
    if (!test || !test.ok) throw bad('not saved: ' + ((test && (test.error || test.error_class)) || 'no answer from the database'), test && test.error_class === 'unsafe' ? 409 : 400);
    const body = { kind: 'db_login', label: ('oracle-ctl-' + label(t)).replace(/[^A-Za-z0-9_.-]+/g, '-').slice(0, 70), target, secret: { username: user, password: pw } };
    const old = ctl.get(t.key);
    const cred = D().createCredential ? D().createCredential(body, who) : V.create(body, who);
    if (old && old.cred_id && V.remove) { try { V.remove(old.cred_id, who); } catch (e) { /* keep going: the new one is in use */ } }
    ctl.put({ id: t.key, cred_id: cred.id, cred_label: cred.label, by: who.user, at: iso(now()), test: { ok: true, at: iso(now()) } });
    audit(who, 'db.sessions.control.set', t.key, { database: label(t), credential: cred.label });
    return list();
  }
  function removeControl(b, who) {
    if (!SC.isHuman(who && who.user)) throw bad('only a person changes this', 403);
    const key = String((b && b.db) || ''), c = ctl.get(key); if (!c) throw bad('session control is not set up for this database', 404);
    ctl.remove(key);
    const V = D() && D().vault; if (V && V.remove) { try { V.remove(c.cred_id, who); } catch (e) { /* the credential page still lists it */ } }
    audit(who, 'db.sessions.control.remove', key, { credential: c.cred_label });
    return list();
  }

  function nextId() { const c = counters.get('db_session_requests') || { id: 'db_session_requests', n: 0 }; c.n++; counters.put(c); return `DBK-${String(c.n).padStart(5, '0')}`; }
  function expire() { const t = now(); for (const r of reqs.all((x) => x.status === 'pending' && t - Date.parse(x.requested_at) > REQ_TTL_MS)) reqs.patch(r.id, (x) => { x.status = 'expired'; x.result = 'not decided within ' + REQ_TTL_MS / 60000 + ' min - read again and ask again'; return x; }); }
  function requests(q = {}) { expire(); return { items: reqs.all((r) => !q.status || r.status === q.status).sort((a, b) => (a.requested_at < b.requested_at ? 1 : -1)).slice(0, 300) }; }

  function request(b, who) {
    b = b || {};
    if (!SC.isHuman(who && who.user)) throw bad('only a person asks for this', 403);
    const t = dbOf(b.db), mode = String(b.mode || '').toLowerCase(), reason = clip(b.reason, 300);
    if (mode !== 'cancel' && mode !== 'kill') throw bad('mode must be cancel (stop the statement) or kill (end the session)');
    if (!reason) throw bad('say why (what it is doing to the database) - the approver reads it');
    const rd = reads.get(t.key);
    if (!rd || now() - rd.at > READ_FRESH_MS) throw bad('read the database again first - a request is made from a read at most ' + READ_FRESH_MS / 60000 + ' min old', 409);
    const k = `${Number(b.inst_id)}:${Number(b.sid)}:${Number(b.serial)}`, s = rd.sessions.find((x) => x.key === k);
    if (!s) throw bad('that session is not in the last read - it may have ended', 404);
    if (reqs.all((r) => r.status === 'pending' && r.db === t.key && r.session.key === k).length) throw bad('a request for this session is already waiting for approval', 409);
    if (mode === 'cancel' && s.status !== 'ACTIVE') throw bad('the session is not running a statement - cancel does nothing; kill ends the session and rolls back its transaction');
    const r = { id: nextId(), db: t.key, database: label(t), mode, reason, status: 'pending', requested_by: who.user, requested_at: iso(now()),
      session: { key: k, inst_id: s.inst_id, sid: s.sid, serial: s.serial, username: s.username, sql_id: s.status === 'ACTIVE' ? s.sql_id : '', status: s.status, elapsed_s: s.elapsed_s, blocks: s.blocks,
        machine: s.machine, program: s.program, osuser: s.osuser, event: s.event, sql_text: s.sql_text, why: s.why } };
    reqs.put(r);
    audit(who, 'db.sessions.request', r.id, { database: r.database, mode, sid: s.sid, serial: s.serial, inst_id: s.inst_id, username: s.username, sql_id: r.session.sql_id, reason });
    return r;
  }

  function mayDecide(who) {
    if (!SC.isHuman(who && who.user)) return false;
    if (app.roles && typeof app.roles.approves === 'function') return app.roles.approves(who.user, SCOPE, who.role);
    return String(who.role || '').toLowerCase() === 'admin';
  }
  async function decide(id, b, who) {
    expire();
    const r = reqs.get(String(id || '')); if (!r) throw bad('request not found', 404);
    if (r.status !== 'pending') throw bad('already ' + r.status, 409);
    if (!mayDecide(who)) throw bad('only an administrator or a DBA approver (Roles & Functions → approves AI Oracle DBA) decides - never a service or AI identity', 403);
    if (String(who.user).toLowerCase() === String(r.requested_by).toLowerCase()) throw bad('the person who asked does not approve their own request', 403);
    const decision = String((b && b.decision) || ''), comment = clip(b && b.comment, 300);
    if (decision !== 'approve' && decision !== 'reject') throw bad('decision must be approve or reject');
    if (decision === 'reject') {
      if (!comment) throw bad('say why it is rejected');
      reqs.patch(r.id, (x) => Object.assign(x, { status: 'rejected', decided_by: who.user, decided_at: iso(now()), comment }));
      audit(who, 'db.sessions.reject', r.id, { database: r.database, comment });
      return reqs.get(r.id);
    }
    const c = ctl.get(r.db);
    if (!c || !(c.test && c.test.ok)) throw bad('session control is not set up for this database (Long-Running Queries → Setup) - nothing was done', 409);
    let t; try { t = dbOf(r.db); } catch (e) { throw bad('the database is no longer monitored - nothing was done', 409); }
    const V = monitorCred(t), cr = openCred(V, c.cred_id, 'session-control login');
    let res;
    try { res = await helper({ op: 'oracle_ctl', mode: r.mode, inst_id: r.session.inst_id, sid: r.session.sid, serial: r.session.serial, target_user: r.session.username, sql_id: r.session.sql_id || '', ref: r.id,
      host: t.ip, port: t.port, service: t.service, username: cr.secret.username, password: cr.secret.password, tls: (cr.target && cr.target.tls) || 'off', ca_file: cr.target && cr.target.ca_file }); }
    catch (e) { res = { ok: false, error: e.message }; }
    finally { cr.release(); }
    const out = res && res.ok ? String(res.result || '') : '';
    const status = !res || !res.ok ? 'failed' : /^DONE/.test(out) ? 'done' : /^GONE/.test(out) ? 'gone' : /^CHANGED/.test(out) ? 'changed' : /^REFUSED/.test(out) ? 'refused' : 'failed';
    const result = res && res.ok ? out : 'not done: ' + ((res && (res.error || res.error_class)) || 'no answer');
    if (res && res.error_class === 'unsafe') ctl.patch(r.db, (x) => { x.test = { ok: false, at: iso(now()), error: res.error }; return x; });
    reqs.patch(r.id, (x) => Object.assign(x, { status, decided_by: who.user, decided_at: iso(now()), comment, result: result.slice(0, 400) }));
    audit(who, 'db.sessions.' + r.mode, r.id, { database: r.database, sid: r.session.sid, serial: r.session.serial, inst_id: r.session.inst_id, username: r.session.username, sql_id: r.session.sql_id, requested_by: r.requested_by, status, result: result.slice(0, 200) });
    return reqs.get(r.id);
  }
  return { list, readLong, setControl, removeControl, request, requests, decide, impact };
}

function registerDbSessions(srv, app, opts = {}) {
  const S = createDbSessions(app, opts);
  (app.addons = app.addons || {}).dbSessions = S;
  try { require('./db-sessions-intel').registerDbSessionsIntel(srv, app, { now: opts.now }); } catch (e) { if (app.log && app.log.warn) app.log.warn('long-running queries: use cases not loaded', { err: e.message }); }
  srv.route('GET', '/db-sessions', (ctx) => { ctx.need('operator'); return S.list(); });
  srv.route('GET', '/db-sessions/long', async (ctx) => { ctx.need('operator'); return S.readLong(ctx.query || {}, ctx.who); });
  srv.route('POST', '/db-sessions/control', async (ctx) => { ctx.need('admin'); return S.setControl(ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-sessions/control/remove', (ctx) => { ctx.need('admin'); return S.removeControl(ctx.body || {}, ctx.who); });
  srv.route('GET', '/db-sessions/requests', (ctx) => { ctx.need('operator'); return S.requests(ctx.query || {}); });
  srv.route('POST', '/db-sessions/requests', (ctx) => { ctx.need('operator'); return S.request(ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-sessions/requests/:id/decide', async (ctx) => { ctx.need('operator'); return S.decide(ctx.params.id, ctx.body || {}, ctx.who); });
  return S;
}

module.exports = { createDbSessions, registerDbSessions, READ_FRESH_MS, REQ_TTL_MS };
