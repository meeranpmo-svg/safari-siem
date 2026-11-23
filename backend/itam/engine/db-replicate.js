// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
/*
 * Our own database engines next to GoldenGate (Databases -> Replication & Data Guard, {P} = /api/itam): the jobs, their
 * dedicated accounts (sealed in the Asset Discovery vault, kind db_login - never the read-only monitoring login), runs,
 * approvals and the readings sent to the SIEM. The database work is in engine/discovery/db_repl.py (via inv-helper.py).
 *
 *   verify     VER-nnnn  compare tables source vs target by primary key, in chunks (rows hashed on the platform server,
 *                        values never stored - only the keys of rows that differ); differing rows re-checked after
 *                        recheck_s so in-flight changes settle; manual or daily. A repair is a PROPOSAL (REPAIR-nnnn) with
 *                        the SQL for a DBA - approved by a named DBA who did not ask for it, run by a person, recorded.
 *   stream     CS-nnnn   LogMiner on chosen schemas every interval: per-transaction metadata (who, from where, which
 *                        program, tables, row counts, DDL with literals masked) to the SIEM as kind change_txn.
 *   replicate  REP-nnnn  LogMiner -> apply to an Oracle / PostgreSQL target with the checkpoint row on the target in the same
 *                        transaction. It WRITES, so: created by an administrator, approved by ANOTHER person (an
 *                        administrator or a named approver for the AI Oracle DBA, eng:dba), never by a service / AI
 *                        identity; the writer account is refused if it holds anything beyond object grants; conflicts,
 *                        DDL and missing logs STOP it with the reason; a person resumes it with a note. Not a DR path:
 *                        for production DR keep Data Guard / GoldenGate.
 * Every create / change / approval / run / stop / resume is audited.
 */
const crypto = require('node:crypto');
const SC = require('./approve-scopes');

const KINDS = { verify: 'VER', stream: 'CS', replicate: 'REP' };
const IDENT = /^[A-Za-z_][A-Za-z0-9_$#]{0,127}$/;
const bad = (m, status = 400) => Object.assign(new Error(m), { status });
const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const who = (w) => ({ user: (w && w.user) || '', role: (w && w.role) || '', ip: (w && w.ip) || '' });

function createReplicate(app, opts = {}) {
  const store = app.store, jobs = store.collection('repl_jobs'), runs = store.collection('repl_runs'), props = store.collection('repl_proposals'), feed = store.collection('repl_changes');
  const dc = (app.config && app.config.discovery) || {};
  const D = () => opts.discovery || app.discovery || null;
  const H = () => opts.dbHealth || (app.addons && app.addons.dbHealth) || null;
  const runHelper = opts.invRun || require('./discovery/methods/login').realRunner(dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3', 300000);
  const now = opts.now || Date.now;
  const later = opts.later || ((fn, ms) => { const t = setTimeout(fn, ms); if (t.unref) t.unref(); return t; });
  const lg = app.log || { info() {}, warn() {} };
  const audit = (w, action, target, detail) => { if (app.audit) app.audit(Object.assign(who(w), { by: (w && w.user) || 'system:itam-replicate', action, target, detail })); };
  const iso = () => new Date(now()).toISOString();
  const timers = new Map(), busy = new Set();

  // numbered per prefix: VER-0001, CS-0001, REP-0001 each start at 1
  function nextId(col, pfx) { const n = col.all((x) => String(x.id).startsWith(pfx + '-')).reduce((m, x) => Math.max(m, Number(String(x.id).split('-')[1]) || 0), 0) + 1; return pfx + '-' + String(n).padStart(4, '0'); }
  // a side of a job: where it is and which sealed login; a new login is sealed in the vault here and never stored elsewhere
  function side(b, label, w) {
    b = b || {};
    const engine = b.engine === 'postgres' ? 'postgres' : 'oracle';
    const host = clip(b.host, 253), port = b.port == null || b.port === '' ? (engine === 'oracle' ? 1521 : 5432) : Number(b.port);
    if (!/^[A-Za-z0-9.-]{1,253}$/.test(host)) throw bad(label + ': host must be an IP address or a host name');
    if (!(Number.isInteger(port) && port > 0 && port < 65536)) throw bad(label + ': port must be 1-65535');
    const svc = clip(engine === 'oracle' ? b.service : b.database, 128);
    if (!/^[A-Za-z0-9_.$#-]{1,128}$/.test(svc)) throw bad(label + ': ' + (engine === 'oracle' ? 'service name' : 'database') + ' is required');
    const V = D() && D().vault; if (!V) throw bad('the credential vault is not available (Asset Discovery)', 503);
    let cred;
    if (b.cred_id) { cred = V.get(String(b.cred_id)); if (!cred || cred.kind !== 'db_login' || !cred.target || cred.target.engine !== engine) throw bad(label + ': choose a saved ' + engine + ' login'); }
    else {
      if (!clip(b.username, 128) || !String(b.password || '')) throw bad(label + ': enter the dedicated account and its password (or choose a saved login)');
      const target = { engine, port }; if (engine === 'oracle') target.service = svc; else target.database = svc; if (b.tls) target.tls = String(b.tls); if (b.ca_file) target.ca_file = String(b.ca_file);
      const body = { kind: 'db_login', label: (label.replace(/\W+/g, '-') + '-' + host).slice(0, 80), target, secret: { username: String(b.username), password: String(b.password) } };
      cred = D().createCredential ? D().createCredential(body, w) : V.create(body, w);
    }
    return { engine, host, port, service: engine === 'oracle' ? svc : undefined, database: engine === 'postgres' ? svc : undefined, cred_id: cred.id, credential: cred.label, label: clip(b.label, 80) || host + '/' + svc };
  }
  function conn(s) {
    const c = D().vault.open(s.cred_id);
    return { req: { engine: s.engine, host: s.host, port: s.port, service: s.service, database: s.database, username: c.secret.username, password: c.secret.password, tls: (c.target && c.target.tls) || 'off', ca_file: c.target && c.target.ca_file }, release: () => c.release() };
  }
  async function helper(op, sides, extra) {
    const opened = Object.entries(sides).map(([k, s]) => [k, conn(s)]);
    try { return await runHelper(Object.assign({ op }, extra || {}, Object.fromEntries(opened.map(([k, c]) => [k, c.req])))); }
    finally { for (const [, c] of opened) c.release(); }
  }
  const ok = (r, what) => { if (!r || !r.ok) throw Object.assign(bad(what + ': ' + ((r && (r.error || r.error_class)) || 'no answer'), 502), { cls: r && r.error_class }); return r; };
  const tableSpec = (t) => { const o = clip(t.owner || t.src_owner, 128), n = clip(t.table || t.src_table, 128); if (!IDENT.test(o) || !IDENT.test(n)) throw bad('table names: schema and table, letters / digits / _ $ #'); return { o, n }; };
  const view = (j) => { const x = Object.assign({}, j); delete x.cursor_secret; return x; };

  /* ---------------- jobs ---------------- */
  function create(b, w) {
    b = b || {};
    const type = String(b.type || ''); if (!KINDS[type]) throw bad('type must be verify, stream or replicate');
    const name = clip(b.name, 80) || type;
    const j = { id: nextId(jobs, KINDS[type]), type, name, created_by: w.user, created_at: iso(), history: [] };
    if (type === 'verify') {
      j.src = side(b.src, 'verify source', w); j.tgt = side(b.tgt, 'verify target', w);
      j.tables = (Array.isArray(b.tables) ? b.tables : []).slice(0, 200).map((t) => { const s = tableSpec(t); const to = clip(t.tgt_owner, 128) || s.o, tn = clip(t.tgt_table, 128) || s.n; if (!IDENT.test(to) || !IDENT.test(tn)) throw bad('target table name not valid');
        return { owner: s.o, table: s.n, tgt_owner: to, tgt_table: tn, exclude: (Array.isArray(t.exclude) ? t.exclude : String(t.exclude || '').split(',')).map((x) => clip(x, 128)).filter((x) => IDENT.test(x)) }; });
      if (!j.tables.length) throw bad('add at least one table to compare');
      j.schedule = b.schedule === 'daily' ? 'daily' : 'manual'; j.hour = Math.max(0, Math.min(23, Number(b.hour) || 2)); j.chunk = Math.max(1000, Math.min(50000, Number(b.chunk) || 20000)); j.recheck_s = Math.max(10, Math.min(3600, Number(b.recheck_s) || 120));
      j.state = 'ready';
    } else if (type === 'stream') {
      j.src = side(b.src, 'change stream', w); if (j.src.engine !== 'oracle') throw bad('the Change Stream reads Oracle redo (LogMiner)');
      j.owners = (Array.isArray(b.owners) ? b.owners : String(b.owners || '').split(',')).map((x) => clip(x, 128).toUpperCase()).filter((x) => IDENT.test(x)).slice(0, 50);
      if (!j.owners.length) throw bad('choose the schemas to follow (e.g. APP, HR)');
      j.mass_rows = Math.max(10, Number(b.mass_rows) || 1000); j.interval_s = Math.max(30, Math.min(3600, Number(b.interval_s) || 60)); j.state = 'stopped'; j.cursor = null;
    } else {
      j.src = side(b.src, 'replication source', w); j.tgt = side(b.tgt, 'replication target', w);
      if (j.src.engine !== 'oracle') throw bad('the replication source is Oracle (LogMiner)');
      j.tables = (Array.isArray(b.tables) ? b.tables : []).slice(0, 200).map((t) => { const s = tableSpec(t); const to = clip(t.tgt_owner, 128) || (j.tgt.engine === 'postgres' ? s.o.toLowerCase() : s.o), tn = clip(t.tgt_table, 128) || (j.tgt.engine === 'postgres' ? s.n.toLowerCase() : s.n);
        const pk = (Array.isArray(t.pk) ? t.pk : String(t.pk || '').split(',')).map((x) => clip(x, 128).toUpperCase()).filter((x) => IDENT.test(x));
        if (!IDENT.test(to) || !IDENT.test(tn)) throw bad('target table name not valid'); return { src_owner: s.o.toUpperCase(), src_table: s.n.toUpperCase(), tgt_owner: to, tgt_table: tn, pk }; });
      if (!j.tables.length) throw bad('add at least one table to replicate');
      const ck = clip(b.checkpoint_owner, 128) || (j.tgt.engine === 'postgres' ? j.tables[0].tgt_owner : j.tables[0].tgt_owner);
      if (!IDENT.test(ck)) throw bad('checkpoint schema not valid');
      j.checkpoint = [ck, j.tgt.engine === 'postgres' ? 'zyb_repl_checkpoint' : 'ZYB_REPL_CHECKPOINT'];
      j.conflict = b.conflict === 'log' ? 'log' : 'stop'; j.interval_s = Math.max(15, Math.min(3600, Number(b.interval_s) || 30));
      j.state = 'draft'; j.approval = null;
      if (j.src.host.toLowerCase() === j.tgt.host.toLowerCase() && (j.src.service || '') === (j.tgt.service || '') && j.src.engine === j.tgt.engine && j.tables.some((t) => t.src_owner.toUpperCase() === String(t.tgt_owner).toUpperCase() && t.src_table.toUpperCase() === String(t.tgt_table).toUpperCase())) throw bad('the target is the source table itself - refused');
    }
    j.history.push({ at: j.created_at, by: w.user, what: 'created' });
    jobs.put(j);
    audit(w, 'db.repl.create', j.id, { type, name, src: j.src && j.src.label, tgt: j.tgt && j.tgt.label });
    return view(j);
  }
  function get(id) { const j = jobs.get(String(id || '')); if (!j) throw bad('job not found', 404); return j; }
  function remove(id, w) { const j = get(id); stopTimer(j.id); jobs.remove(j.id); audit(w, 'db.repl.delete', j.id, { type: j.type, note: 'the sealed logins stay in Asset Discovery -> Credentials' }); return { removed: j.id }; }
  function patch(j, fn, w, what, detail) { const x = jobs.patch(j.id, (y) => { fn(y); y.history = (y.history || []).concat([{ at: iso(), by: (w && w.user) || 'system', what }]).slice(-200); return y; }); if (w) audit(w, 'db.repl.' + what.split(':')[0].replace(/\s+/g, '-'), j.id, detail || {}); return x; }

  /* ---------------- Data Verify ---------------- */
  async function runVerify(id, w) {
    const j = get(id); if (j.type !== 'verify') throw bad('not a verify job');
    if (busy.has(j.id)) throw bad('this comparison is already running', 409);
    busy.add(j.id);
    const run = { id: nextId(runs, 'RUN'), job: j.id, type: 'verify', started_at: iso(), by: (w && w.user) || 'schedule', state: 'running', tables: [] };
    runs.put(run); patch(j, (x) => { x.state = 'running'; x.last_run = run.id; }, w, 'run');
    (async () => {
      try {
        const d = ok(await helper('verify_describe', { src: j.src, tgt: j.tgt }, { tables: j.tables }), 'describe');
        for (const t of d.tables) {
          if (!t.ok) { run.tables.push({ table: t.owner + '.' + t.table, error: t.error }); continue; }
          const spec = { src: t.src, tgt: t.tgt, cmp: t.cmp }, res = { table: t.src.owner + '.' + t.src.table, target: t.tgt.owner + '.' + t.tgt.table, pk: t.cmp.pk.map((p) => p[0]), columns: t.cmp.data.length + t.cmp.pk.length,
            only_source: t.only_source, only_target: t.only_target, lob_columns: t.lob_columns, rows: 0, missing: [], different: [], extra: [], missing_n: 0, different_n: 0, extra_n: 0, started_at: iso(), spec };
          for (const phase of ['forward', 'reverse']) {
            let after = null, guard = 0;
            for (;;) {
              const r = ok(await helper('verify_chunk', { src: j.src, tgt: j.tgt }, { spec, after, limit: j.chunk, phase }), 'compare');
              if (phase === 'forward') res.rows += r.rows;
              for (const k of ['missing', 'different', 'extra']) { res[k + '_n'] += r[k + '_n'] || 0; res[k] = res[k].concat(r[k] || []).slice(0, 5000); }
              after = r.next; run.progress = { table: res.table, phase, rows: res.rows }; runs.put(run);
              if (r.done || ++guard > 100000) break;
            }
          }
          res.first_pass = { missing: res.missing_n, different: res.different_n, extra: res.extra_n };
          run.tables.push(res);
        }
        run.state = 'rechecking'; run.recheck_at = new Date(now() + j.recheck_s * 1000).toISOString(); runs.put(run);
        later(() => { recheck(j, run).catch((e) => { run.state = 'failed'; run.error = String(e.message || e).slice(0, 300); runs.put(run); busy.delete(j.id); }); }, j.recheck_s * 1000);
      } catch (e) {
        run.state = 'failed'; run.error = String(e.message || e).slice(0, 300); run.finished_at = iso(); runs.put(run); busy.delete(j.id);
        patch(j, (x) => { x.state = 'ready'; }, null, 'run failed: ' + run.error);
      }
    })();
    return run;
  }
  // rows that differed are read again after recheck_s: a change still travelling through replication settles
  async function recheck(j, run) {
    for (const t of run.tables) {
      if (!t.spec) continue;
      const keys = [].concat(t.missing, t.different, t.extra);
      if (keys.length) {
        const r = ok(await helper('verify_keys', { src: j.src, tgt: j.tgt }, { spec: t.spec, keys }), 'recheck');
        t.settled = r.equal; t.missing = r.missing; t.different = r.different; t.extra = r.extra;
        // counts beyond the keys kept (5000) cannot be re-checked: they stay as first counted, and the page says so
        const capped = (n, kept) => Math.max(0, n - kept);
        t.missing_n = r.missing.length + capped(t.first_pass.missing, Math.min(t.first_pass.missing, 5000)); t.different_n = r.different.length + capped(t.first_pass.different, Math.min(t.first_pass.different, 5000)); t.extra_n = r.extra.length + capped(t.first_pass.extra, Math.min(t.first_pass.extra, 5000));
      }
      t.in_sync = !t.missing_n && !t.different_n && !t.extra_n;
      delete t.spec;
    }
    run.state = 'done'; run.finished_at = iso(); run.in_sync = run.tables.every((t) => t.in_sync); runs.put(run); busy.delete(j.id);
    patch(j, (x) => { x.state = 'ready'; x.last_result = { run: run.id, at: run.finished_at, in_sync: run.in_sync, tables: run.tables.length, diverged: run.tables.filter((t) => !t.in_sync).length }; }, null, 'run done: ' + (run.in_sync ? 'in sync' : 'differences found'));
    pushSiem([{ kind: 'verify_result', job: j.id, name: j.name, source: j.src.label, target: j.tgt.label, in_sync: run.in_sync, tables: run.tables.length,
      diverged: run.tables.filter((t) => !t.in_sync).map((t) => t.table).join(','), missing: run.tables.reduce((n, t) => n + (t.missing_n || 0), 0), different: run.tables.reduce((n, t) => n + (t.different_n || 0), 0), extra: run.tables.reduce((n, t) => n + (t.extra_n || 0), 0) }], j.src);
    return run;
  }
  // a repair is SQL for the DBA: by primary key, through a database link the DBA names (Oracle to Oracle), else the key list
  const lit = (v, eng) => { if (v === null || v === undefined) return 'NULL'; if (typeof v === 'number') return String(v); if (typeof v === 'object') { if (v.t === 'n') return String(Number(v.v)) === 'NaN' ? 'NULL' : String(v.v).replace(/[^0-9eE.+-]/g, ''); if (v.t === 'ts' || v.t === 'd') return eng === 'oracle' ? `TIMESTAMP '${String(v.v).replace('T', ' ').replace(/[^0-9 :.-]/g, '')}'` : `'${String(v.v).replace(/'/g, "''")}'::timestamp`; if (v.t === 'x') return eng === 'oracle' ? `HEXTORAW('${String(v.v).replace(/[^0-9a-f]/gi, '')}')` : `'\\x${String(v.v).replace(/[^0-9a-f]/gi, '')}'::bytea`; } return `'${String(v).replace(/'/g, "''")}'`; };
  function repairSql(j, t, dblink) {
    const eng = j.tgt.engine, q = (x) => '"' + x + '"', pk = t.pk, tgt = t.target.split('.').map(q).join('.'), src = t.table.split('.').map(q).join('.');
    const cond = (k) => '(' + pk.map((p, i) => `${q(p)} = ${lit(k[i], eng)}`).join(' AND ') + ')';
    const fix = [], undo = [];
    const up = [].concat(t.missing, t.different);
    if (dblink && eng === 'oracle' && j.src.engine === 'oracle') {
      const L = clip(dblink, 128).replace(/[^A-Za-z0-9_$#.]/g, '');
      for (let i = 0; i < up.length; i += 200) {
        const part = up.slice(i, i + 200);
        fix.push(`MERGE INTO ${tgt} t USING (SELECT * FROM ${src}@${L} WHERE ${part.map(cond).join(' OR ')}) s ON (${pk.map((p) => `t.${q(p)} = s.${q(p)}`).join(' AND ')})\n  WHEN MATCHED THEN UPDATE SET /* every non-key column: t.col = s.col */\n  WHEN NOT MATCHED THEN INSERT VALUES /* s.* in column order */;`);
      }
      if (t.extra.length) fix.push(`-- rows only on the target (not on the source): review before deleting\nDELETE FROM ${tgt} WHERE ${t.extra.map(cond).join(' OR ')};`);
      undo.push(`-- take a copy BEFORE running the repair, so it can be undone:\nCREATE TABLE ${t.target.split('.')[0]}.ZYB_BAK_${String(Date.now()).slice(-8)} AS SELECT * FROM ${tgt} WHERE ${[].concat(up, t.extra).slice(0, 1000).map(cond).join(' OR ') || '1=0'};`);
    } else {
      fix.push(`-- rows missing or different on the target (copy them from the source by primary key ${pk.join(', ')}):\n` + up.slice(0, 1000).map((k) => '--   ' + pk.map((p, i) => `${p}=${lit(k[i], eng)}`).join(', ')).join('\n'));
      if (t.extra.length) fix.push(`-- rows only on the target:\nDELETE FROM ${tgt} WHERE ${t.extra.slice(0, 1000).map(cond).join(' OR ')};`);
      undo.push(`-- copy the affected target rows before changing them (CREATE TABLE ... AS SELECT / pg_dump --table).`);
    }
    return { sql: fix.join('\n\n'), rollback: undo.join('\n'), verify: `SELECT COUNT(*) FROM ${tgt};  -- then run the comparison again from the page` };
  }
  function proposeRepair(b, w) {
    const run = runs.get(String((b && b.run) || '')); if (!run || run.type !== 'verify' || run.state !== 'done') throw bad('choose a finished comparison', 404);
    const j = get(run.job), t = run.tables.find((x) => x.table === String(b.table || '')); if (!t || t.in_sync) throw bad('that table has no difference to repair');
    const r = repairSql(j, t, b.dblink);
    const p = { id: nextId(props, 'REPAIR'), job: j.id, run: run.id, table: t.table, target: t.target, counts: { missing: t.missing_n, different: t.different_n, extra: t.extra_n }, fix_sql: r.sql, rollback_sql: r.rollback, verify_sql: r.verify,
      status: 'proposed', requested_by: w.user, created_at: iso(), history: [{ at: iso(), by: w.user, what: 'proposed' }] };
    props.put(p); audit(w, 'db.repl.repair.propose', p.id, { job: j.id, table: t.table, counts: p.counts });
    return p;
  }
  function decideRepair(id, b, w, gate) {
    const p = props.get(String(id || '')); if (!p) throw bad('proposal not found', 404);
    const d = String((b && b.decision) || ''), note = clip(b && b.note, 2000);
    if (!SC.isHuman(w.user)) throw bad('only a person decides: ' + (w.user || 'this identity') + ' is a service / AI identity', 403);
    const T = { approve: ['proposed', 'approved'], reject: ['proposed', 'rejected'], done: ['approved', 'done'], failed: ['approved', 'failed'] }[d];
    if (!T) throw bad('decision must be approve, reject, done or failed');
    if (p.status !== T[0]) throw bad(`this proposal is ${p.status}, not ${T[0]}`, 409);
    if (d === 'approve' || d === 'reject') { gate(); if (p.requested_by && p.requested_by.toLowerCase() === w.user.toLowerCase()) throw bad('four eyes: you asked for this repair - another person decides it', 403); if (d === 'reject' && !note) throw bad('a rejection needs a reason'); }
    if ((d === 'done' || d === 'failed') && !note) throw bad('say what was run on the database and the result');
    p.status = T[1]; p[d + '_by'] = w.user; p[d + '_at'] = iso(); if (note) p[d + '_note'] = note; p.history.push({ at: p[d + '_at'], by: w.user, what: d + (note ? ': ' + note : '') });
    props.put(p); audit(w, 'db.repl.repair.' + d, p.id, { note: note.slice(0, 300) });
    return p;
  }

  /* ---------------- Change Stream ---------------- */
  async function streamCycle(j0) {
    const j = get(j0.id); if (j.state !== 'running' || busy.has(j.id)) return null;
    busy.add(j.id);
    try {
      const r = await helper('logminer_read', { src: j.src }, { owners: j.owners, tables: [], cursor: j.cursor, max_files: 4 });
      if (!r || !r.ok) { patch(j, (x) => { x.last_error = { at: iso(), error: (r && (r.error || r.error_class)) || 'no answer', cls: r && r.error_class }; if (r && /auth|unsafe/.test(r.error_class || '')) x.state = 'stopped'; }, null, 'cycle failed: ' + ((r && r.error_class) || 'error')); return r; }
      if (r.info && r.info.gap) { patch(j, (x) => { x.state = 'stopped'; x.stopped = { at: iso(), reason: 'gap', detail: r.info.gap }; }, null, 'stopped: ' + r.info.gap); pushSiem([{ kind: 'change_stream', job: j.id, name: j.name, state: 'stopped', reason: 'gap', detail: r.info.gap }], j.src); return r; }
      const txs = r.txns || [];
      for (const t of txs.slice(-200)) feed.put(Object.assign({ id: j.id + ':' + t.xid + ':' + t.commit_scn, job: j.id, at: iso() }, t));
      const old = feed.all((x) => x.job === j.id).sort((a, b) => b.commit_scn - a.commit_scn).slice(500); for (const x of old) feed.remove(x.id);
      patch(j, (x) => { x.cursor = r.cursor; x.last_error = null; x.last_cycle = { at: iso(), txns: txs.length, rows: txs.reduce((n, t) => n + t.rows, 0), lag_s: r.info && r.info.lag_s, files: r.info && r.info.files, open: r.info && r.info.open_transactions }; }, null, 'cycle');
      const recs = txs.slice(0, 1000).map((t) => ({ kind: 'change_txn', job: j.id, xid: t.xid, commit_scn: t.commit_scn, commit_ts: t.commit_ts, user: t.user, os_user: t.os_user, machine: t.machine, program: t.program, rows: t.rows,
        tables: Object.keys(t.tables).join(','), inserts: Object.values(t.tables).reduce((n, x) => n + x.INSERT, 0), updates: Object.values(t.tables).reduce((n, x) => n + x.UPDATE, 0), deletes: Object.values(t.tables).reduce((n, x) => n + x.DELETE, 0),
        ddl: t.ddl.map((d) => d.sql).join(' | ').slice(0, 1000), ddl_tables: t.ddl.map((d) => d.table).join(','), mass: t.rows >= j.mass_rows }));
      recs.push({ kind: 'change_stream', job: j.id, name: j.name, state: 'running', txns: txs.length, lag_s: r.info && r.info.lag_s, commit_scn: r.cursor && r.cursor.commit_scn });
      pushSiem(recs, j.src);
      return r;
    } finally { busy.delete(j.id); }
  }

  /* ---------------- Replication ---------------- */
  async function status(id) {
    const j = get(id); if (j.type !== 'replicate') throw bad('not a replication job');
    const r = await helper('repl_status', { src: j.src, tgt: j.tgt }, { job: { id: j.id, tables: j.tables, checkpoint: j.checkpoint } });
    if (!r || !r.ok) return { ok: false, error: (r && (r.error || r.error_class)) || 'no answer', error_class: r && r.error_class };
    // a draft takes the primary keys the dictionary reports (rows are matched on them); after approval nothing changes here
    const pk = {}; for (const t of (r.source && r.source.tables) || []) if (t.pk && t.pk.length) pk[t.table] = t.pk.map((x) => String(x).toUpperCase());
    if (j.state === 'draft' && j.tables.some((t) => !t.pk.length && pk[t.src_owner + '.' + t.src_table])) patch(j, (x) => { x.tables = x.tables.map((t) => (t.pk.length ? t : Object.assign({}, t, { pk: pk[t.src_owner + '.' + t.src_table] || [] }))); }, null, 'primary keys read from the source');
    return Object.assign(r, { job: view(get(id)) });
  }
  function approve(id, b, w, gate) {
    const j = get(id); if (j.type !== 'replicate') throw bad('only a replication job is approved');
    if (!SC.isHuman(w.user)) throw bad('only a person approves: ' + (w.user || 'this identity') + ' is a service / AI identity', 403);
    gate();
    if (j.created_by && j.created_by.toLowerCase() === w.user.toLowerCase()) throw bad('four eyes: you created this replication job - another person approves it', 403);
    if (j.state !== 'draft') throw bad('this job is ' + j.state + ', not waiting for approval', 409);
    if (!j.tables.every((t) => t.pk.length)) throw bad('every table needs its primary key columns (read them with "Check readiness")');
    return view(patch(j, (x) => { x.state = 'approved'; x.approval = { by: w.user, at: iso(), note: clip(b && b.note, 500) }; }, w, 'approved', { note: clip(b && b.note, 300) }));
  }
  async function replCycle(j0) {
    const j = get(j0.id); if (j.state !== 'running' || busy.has(j.id)) return null;
    busy.add(j.id);
    try {
      const r = await helper('repl_cycle', { src: j.src, tgt: j.tgt }, { job: { id: j.id, tables: j.tables, checkpoint: j.checkpoint, conflict: j.conflict, target_engine: j.tgt.engine, batch_rows: 5000 }, max_files: 4 });
      if (!r || !r.ok) {
        const stopIt = r && /auth|unsafe|refused/.test(r.error_class || '');
        patch(j, (x) => { x.last_error = { at: iso(), error: (r && (r.error || r.error_class)) || 'no answer' }; if (stopIt) { x.state = 'stopped'; x.stopped = { at: iso(), reason: r.error_class, detail: r.error }; } }, null, stopIt ? 'stopped: ' + r.error_class : 'cycle failed');
        if (stopIt) pushSiem([{ kind: 'repl_status', job: j.id, name: j.name, state: 'stopped', reason: r.error_class, detail: String(r.error || '').slice(0, 300) }], j.src);
        return r;
      }
      const s = r.stats || {};
      patch(j, (x) => {
        x.last_error = null; x.last_cycle = { at: iso(), txns: s.txns || 0, rows: s.rows || 0, conflicts_logged: (s.conflicts || []).length, lag_s: r.info && r.info.lag_s, last_commit_ts: s.last_commit_ts || (x.last_cycle && x.last_cycle.last_commit_ts) || null };
        x.totals = { txns: ((x.totals && x.totals.txns) || 0) + (s.txns || 0), rows: ((x.totals && x.totals.rows) || 0) + (s.rows || 0), conflicts_logged: ((x.totals && x.totals.conflicts_logged) || 0) + (s.conflicts || []).length };
        if (s.conflicts && s.conflicts.length) x.conflicts = (x.conflicts || []).concat(s.conflicts.map((c) => Object.assign({ at: iso() }, c))).slice(-500);
        if (r.stopped) { x.state = 'stopped'; x.stopped = Object.assign({ at: iso() }, r.stopped); }
      }, null, r.stopped ? 'stopped: ' + r.stopped.reason : 'cycle');
      pushSiem([{ kind: 'repl_status', job: j.id, name: j.name, state: r.stopped ? 'stopped' : 'running', reason: r.stopped ? r.stopped.reason : '', detail: r.stopped ? String(r.stopped.detail || '').slice(0, 300) : '', txns: s.txns || 0, rows: s.rows || 0, lag_s: r.info && r.info.lag_s, conflicts: (s.conflicts || []).length }], j.src);
      return r;
    } finally { busy.delete(j.id); }
  }

  /* ---------------- start / stop / timers ---------------- */
  function startTimer(j) { stopTimer(j.id); const fn = j.type === 'stream' ? streamCycle : replCycle; const t = setInterval(guardOf(app, 'db-replicate.' + j.id, () => fn(j)), (j.interval_s || 60) * 1000); if (t.unref) t.unref(); timers.set(j.id, t); }
  function stopTimer(id) { const t = timers.get(id); if (t) clearInterval(t); timers.delete(id); }
  async function start(id, b, w) {
    const j = get(id);
    if (j.type === 'verify') return runVerify(id, w);
    if (j.type === 'replicate' && !['approved', 'paused', 'stopped'].includes(j.state)) throw bad(j.state === 'draft' ? 'a replication job starts only after another person approved it' : 'this job is ' + j.state, 409);
    if (j.type === 'replicate' && j.state === 'stopped' && !clip(b && b.note, 500)) throw bad('it stopped (' + ((j.stopped && j.stopped.reason) || '?') + '): say what was done about it before resuming');
    if (j.state === 'running') return view(j);
    const x = patch(j, (y) => { y.state = 'running'; y.resumed = { at: iso(), by: w.user, note: clip(b && b.note, 500) }; y.stopped = null; }, w, 'started', { note: clip(b && b.note, 300) });
    startTimer(x);
    guardOf(app, 'db-replicate.' + x.id, () => (x.type === 'stream' ? streamCycle(x) : replCycle(x)))();
    return view(get(id));
  }
  function stop(id, b, w) { const j = get(id); stopTimer(j.id); return view(patch(j, (y) => { y.state = j.type === 'replicate' ? 'paused' : 'stopped'; }, w, j.type === 'replicate' ? 'paused' : 'stopped', { note: clip(b && b.note, 300) })); }
  function pushSiem(recs, src) {
    if (!recs.length || !H() || typeof H().push !== 'function') return;
    const t = iso(), inst = String((src && (src.service || src.database)) || 'REPLICATION').toUpperCase().slice(0, 64);
    H().push(recs.map((x) => Object.assign({ collector: 'sentra-oracle-itam', t, host: (src && src.host) || '', instance: inst, db_name: inst }, x))).catch((e) => lg.warn('db-replicate: SIEM push failed', { err: e.message }));
  }
  // daily comparisons, and the running jobs again after a restart
  function boot() {
    for (const j of jobs.all((x) => x.state === 'running' && (x.type === 'stream' || x.type === 'replicate'))) startTimer(j);
    for (const j of jobs.all((x) => x.type === 'verify' && x.state === 'running')) jobs.patch(j.id, (y) => { y.state = 'ready'; return y; });   // a comparison cut by a restart is not resumed half-way
    const t = setInterval(guardOf(app, 'db-replicate.daily', () => {
      const h = new Date(now() + 3 * 3600000).getUTCHours(), day = new Date(now()).toISOString().slice(0, 10);   // Riyadh hour
      for (const j of jobs.all((x) => x.type === 'verify' && x.schedule === 'daily' && x.hour === h && x.last_daily !== day && x.state === 'ready')) { jobs.patch(j.id, (y) => { y.last_daily = day; return y; }); runVerify(j.id, null).catch((e) => lg.warn('db-replicate: daily comparison failed', { job: j.id, err: e.message })); }
    }), 300000); if (t.unref) t.unref();
  }

  /* ---------------- setup scripts for the DBA ---------------- */
  function setup(id) {
    const j = get(id), out = {};
    const U = (s) => (s && s.credential) || 'the account';
    if (j.type === 'verify') {
      const g = (s, tabs) => s.engine === 'oracle' ? `-- ${s.label}: a dedicated, SELECT-only account for Data Verify\nCREATE USER zyb_verify IDENTIFIED BY "<long random>";\nGRANT CREATE SESSION TO zyb_verify;\n` + tabs.map((t) => `GRANT SELECT ON ${t} TO zyb_verify;`).join('\n')
        : `-- ${s.label}: a dedicated, SELECT-only role for Data Verify\nCREATE ROLE zyb_verify LOGIN PASSWORD '<long random>';\n` + [...new Set(tabs.map((t) => t.split('.')[0]))].map((sc) => `GRANT USAGE ON SCHEMA ${sc} TO zyb_verify;`).join('\n') + '\n' + tabs.map((t) => `GRANT SELECT ON ${t} TO zyb_verify;`).join('\n');
      out.source = g(j.src, j.tables.map((t) => `${t.owner}.${t.table}`)); out.target = g(j.tgt, j.tables.map((t) => `${t.tgt_owner}.${t.tgt_table}`));
      out.note = 'Object grants only. An account holding SELECT ANY TABLE (Oracle) or pg_read_all_data / superuser (PostgreSQL) is refused.';
    } else {
      const owners = j.type === 'stream' ? j.owners : [...new Set(j.tables.map((t) => t.src_owner))];
      out.source = [`-- ${j.src.label}: what LogMiner needs (run as SYSDBA; archive log mode is required)`, `SELECT log_mode, supplemental_log_data_min, supplemental_log_data_pk FROM v$database;`, `ALTER DATABASE ADD SUPPLEMENTAL LOG DATA;   -- minimal: who / program in the redo`,
        ...(j.type === 'replicate' ? j.tables.map((t) => `ALTER TABLE ${t.src_owner}.${t.src_table} ADD SUPPLEMENTAL LOG DATA (PRIMARY KEY) COLUMNS;`) : owners.map((o) => `-- optional per table in ${o}: ALTER TABLE ${o}.<table> ADD SUPPLEMENTAL LOG DATA (PRIMARY KEY) COLUMNS;`)),
        `CREATE USER zyb_miner IDENTIFIED BY "<long random>";`, `GRANT CREATE SESSION, LOGMINING TO zyb_miner;`, `GRANT EXECUTE_CATALOG_ROLE, SELECT_CATALOG_ROLE TO zyb_miner;`, `GRANT SELECT ON sys.v_$logmnr_contents TO zyb_miner;`, `-- it changes no data: it reads the redo. Keep archived logs on disk long enough (RMAN: delete archivelogs only after they are mined).`].join('\n');
      if (j.type === 'replicate') {
        const ck = j.checkpoint.join('.'), pg = j.tgt.engine === 'postgres';
        out.target = [`-- ${j.tgt.label}: the writer account (object grants only) and the checkpoint table`, pg ? `CREATE ROLE zyb_writer LOGIN PASSWORD '<long random>';` : `CREATE USER zyb_writer IDENTIFIED BY "<long random>"; GRANT CREATE SESSION TO zyb_writer;`,
          ...j.tables.map((t) => `GRANT SELECT, INSERT, UPDATE, DELETE ON ${t.tgt_owner}.${t.tgt_table} TO zyb_writer;`),
          pg ? `CREATE TABLE ${ck} (job_id varchar(64) PRIMARY KEY, commit_scn numeric NOT NULL, restart_scn numeric NOT NULL, applied_at timestamp, txns numeric DEFAULT 0, rows_applied numeric DEFAULT 0);`
            : `CREATE TABLE ${ck} (job_id VARCHAR2(64) PRIMARY KEY, commit_scn NUMBER NOT NULL, restart_scn NUMBER NOT NULL, applied_at TIMESTAMP, txns NUMBER DEFAULT 0, rows_applied NUMBER DEFAULT 0);`,
          `GRANT SELECT, UPDATE ON ${ck} TO zyb_writer;`].join('\n');
        out.instantiate = [`-- initial copy at ONE SCN, then tell the job where to start (the same SCN):`, `-- 1. on the source: SELECT current_scn FROM v$database;   -> <SCN>`,
          j.tgt.engine === 'oracle' ? `-- 2. expdp ... TABLES=${j.tables.map((t) => t.src_owner + '.' + t.src_table).join(',')} FLASHBACK_SCN=<SCN>  then impdp into the target (REMAP_SCHEMA if needed)` : `-- 2. copy the tables AS OF that SCN (SELECT ... AS OF SCN <SCN>) into PostgreSQL (ora2pg / your ETL)`,
          `-- 3. on the target:`, `INSERT INTO ${ck} (job_id, commit_scn, restart_scn) VALUES ('${j.id}', <SCN>, <SCN>);`, `COMMIT;`, `-- 4. back here: Check readiness, ask another person to approve, Start. Run a Data Verify between the two to prove the copy.`].join('\n');
      }
    }
    out.accounts = { source: U(j.src), target: j.tgt ? U(j.tgt) : null };
    return out;
  }

  function list() {
    return { jobs: jobs.all().map(view).sort((a, b) => a.id.localeCompare(b.id)), runs: runs.all().sort((a, b) => String(b.started_at).localeCompare(String(a.started_at))).slice(0, 50).map((r) => Object.assign({}, r, { tables: (r.tables || []).map((t) => { const x = Object.assign({}, t); delete x.spec; return x; }) })),
      proposals: props.all().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 100),
      logins: (() => { try { return (D() && D().vault ? D().vault.list() : []).filter((c) => c.kind === 'db_login' && c.target && (c.target.engine === 'oracle' || c.target.engine === 'postgres')).map((c) => ({ id: c.id, label: c.label, engine: c.target.engine })); } catch (e) { return []; } })() };
  }
  function changes(id, limit) { return { items: feed.all((x) => x.job === String(id)).sort((a, b) => b.commit_scn - a.commit_scn).slice(0, Math.min(500, Number(limit) || 100)) }; }
  return { create, get, remove, list, runVerify, recheck, proposeRepair, decideRepair, repairSql, streamCycle, replCycle, status, approve, start, stop, setup, changes, boot, stopTimer };
}

function registerReplicate(srv, app, opts = {}) {
  const R = createReplicate(app, opts);
  (app.addons = app.addons || {}).replicate = R;
  const gate = (ctx) => () => { if (typeof app.approveGate === 'function') return app.approveGate(ctx, 'eng:dba'); if (String((ctx.who && ctx.who.role) || '').toLowerCase() !== 'admin') throw bad('approving needs an administrator', 403); return true; };
  srv.route('GET', '/db-repl', (ctx) => { ctx.need('operator'); return R.list(); });
  srv.route('POST', '/db-repl/jobs', (ctx) => { ctx.need('admin'); return R.create(ctx.body || {}, ctx.who); });
  srv.route('GET', '/db-repl/jobs/:id/setup', (ctx) => { ctx.need('operator'); return R.setup(ctx.params.id); });
  srv.route('GET', '/db-repl/jobs/:id/changes', (ctx) => { ctx.need('operator'); return R.changes(ctx.params.id, (ctx.query || {}).limit); });
  srv.route('GET', '/db-repl/jobs/:id/status', async (ctx) => { ctx.need('operator'); return R.status(ctx.params.id); });
  srv.route('POST', '/db-repl/jobs/:id/start', async (ctx) => { const j = R.get(ctx.params.id); ctx.need(j.type === 'verify' ? 'operator' : 'admin'); return R.start(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-repl/jobs/:id/stop', (ctx) => { ctx.need('operator'); return R.stop(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-repl/jobs/:id/approve', (ctx) => { ctx.need('operator'); return R.approve(ctx.params.id, ctx.body || {}, ctx.who, gate(ctx)); });
  srv.route('POST', '/db-repl/jobs/:id/delete', (ctx) => { ctx.need('admin'); return R.remove(ctx.params.id, ctx.who); });
  srv.route('POST', '/db-repl/repairs', (ctx) => { ctx.need('operator'); return R.proposeRepair(ctx.body || {}, ctx.who); });
  srv.route('POST', '/db-repl/repairs/:id/decide', (ctx) => { ctx.need('operator'); return R.decideRepair(ctx.params.id, ctx.body || {}, ctx.who, gate(ctx)); });
  if (!opts.noTimer) R.boot();
  return R;
}

module.exports = { createReplicate, registerReplicate };
