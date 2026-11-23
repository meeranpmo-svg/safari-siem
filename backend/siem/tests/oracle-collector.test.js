// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// agents/oracle/sentra-oracle-collector.sh end to end: a fake sqlplus / lsnrctl answering with 19c-shaped rows, the real
// collector script, a local ingest endpoint, and every shipped line run through the SIEM's own Oracle parsers.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const zlib = require('zlib');
const { spawn } = require('child_process');
const health = require('../engine/db-audit/oracle-health');

const KIT = path.join(__dirname, '..', 'agents', 'oracle');
const TOKEN = 'tok-0123456789abcdef0123456789';
const PW = 'S3cret-Pw!';

// what sqlplus prints for collect.sql + collect-perf.sql on a healthy 19c CDB/PDB
function rows(diag) {
  return [
    ('#META|PROD|PROD|DBHOST01.' + 'corp-hq.com'), '#ALERT|' + diag,
    '{"kind":"instance","status":"OPEN","database_status":"ACTIVE","open_mode":"READ WRITE","role":"PRIMARY","log_mode":"ARCHIVELOG","version":"19.21.0.0.0","uptime_s":864000,"edition":"EE"}',
    '{"kind":"tablespace","name":"USERS","used_mb":9700,"max_mb":10000,"free_mb":300,"used_pct":97,"contents":"PERMANENT","status":"ONLINE"}',
    '{"kind":"tablespace","name":"SYSTEM","used_mb":900,"max_mb":32767,"free_mb":31867,"used_pct":2.7,"contents":"PERMANENT","status":"ONLINE"}',
    '{"kind":"sessions","total":180,"active":12,"inactive":160,"blocked":1,"max_sessions":472,"processes":190,"max_processes":300}',
    '{"kind":"blocking","sid":201,"serial":7,"user":"APPUSER","wait_s":420,"event":"enq: TX - row lock contention","blocker_sid":88,"blocker_user":"BATCH","object":"FIN.INVOICES"}',
    '{"kind":"backup","status":"COMPLETED","input_type":"DB INCR","age_h":20.5,"output_mb":51200}',
    '{"kind":"redo","log_mode":"ARCHIVELOG","archive_lag_s":120,"redo_switches_1h":6,"unarchived":0}',
    '{"kind":"invalid_objects","count":3,"by_owner":"APP:3"}',
    '{"kind":"fra","name":"/u02/fra","space_limit_mb":200000,"space_used_mb":90000,"reclaimable_mb":10000,"used_pct":40,"files":120}',
    '{"kind":"unified_audit","EVENT_TIMESTAMP_UTC":"2026-10-14T08:00:01.000000Z","DBUSERNAME":"SCOTT","OS_USERNAME":"jdoe","USERHOST":"10.1.2.3","ACTION_NAME":"LOGON","RETURN_CODE":1017,"AUTHENTICATION_TYPE":"(TYPE=(DATABASE));"}',
    '{"kind":"unified_audit","EVENT_TIMESTAMP_UTC":"2026-10-14T08:00:05.123456Z","DBUSERNAME":"SYS","ACTION_NAME":"GRANT","RETURN_CODE":0,"SQL_TEXT":"grant dba to scott","SYSTEM_PRIVILEGE_USED":"SYSDBA"}',
    '{"kind":"load_profile","scope":"instance","aas":9.5,"db_time_s":9.5,"db_cpu_s":6.1,"executions_s":3200,"redo_mb_s":2.5,"cpu_count":8,"host_cpu_pct":81}',
    '{"kind":"efficiency","buffer_cache_hit_pct":99.2,"library_cache_hit_pct":98.7,"soft_parse_pct":97.1,"execute_to_parse_pct":80}',
    '{"kind":"wait_classes","class":"User I/O","time_s":2.1,"waits_s":900,"avg_ms":2.3,"dbtime_pct":22}',
    '{"kind":"wait_events","event":"log file sync","class":"Commit","waits_s":40,"avg_ms":25,"time_s":1,"rank":4,"watch":1,"top_by":"time"}',
    '{"kind":"active_sessions","captures":1,"active_total":10,"aas":10,"cpu_count":8,"top_event":"ON CPU","aas_cpu":6,"aas_user_i_o":3,"aas_commit":1}',
    '{"kind":"ash_sql","sql_id":"7h35uxf5uhmm1","count":4,"aas":4,"pct":40,"top_event":"ON CPU","module":"FIN","user":"APPUSER","captures":1,"rank":1}',
    '{"kind":"long_query","sid":300,"serial":11,"user":"REPORTS","sql_id":"9babjv8yq8ru3","elapsed_s":2400,"state":"WAITING","event":"direct path read"}',
    '{"kind":"plan_change","sql_id":"5k5207588w9ry","new_plan":111,"old_plan":222,"new_ms_exec":80,"old_ms_exec":20,"new_execs":50,"old_execs":5000}',
    '{"kind":"temp_undo","temp_used_mb":9000,"temp_max_mb":10000,"temp_used_pct":90,"undo_used_pct":40,"ora1555_1h":0,"nospace_1h":0}',
    '{"kind":"memory","sga_max_mb":16384,"sga_free_mb":512,"pga_alloc_mb":3000,"pga_target_mb":4096,"pga_limit_mb":8192,"pga_over_alloc":0}',
    '{"kind":"limits","resource":"processes","current":285,"max_util":290,"limit":300}',
    '{"kind":"redo_rate","thread":1,"switches_1h":6,"switches_24h":120,"switches_max_hour_24h":14,"log_groups":4,"log_size_mb":1024}',
    '{"kind":"host","num_cpus":8,"num_cpu_cores":4,"load":6.2,"mem_total_mb":64000,"mem_free_mb":4000,"host_cpu_pct":81}',
    'ORA-00942: table or view does not exist',
  ].join('\n');
}

function kit(dir, opts = {}) {
  const oh = path.join(dir, 'oh'), bin = path.join(oh, 'bin'), st = path.join(dir, 'state'), diag = path.join(dir, 'diag');
  fs.mkdirSync(bin, { recursive: true }); fs.mkdirSync(diag, { recursive: true });
  fs.writeFileSync(path.join(diag, 'alert_PROD.log'), 'Starting ORACLE instance\nORA-00600: internal error code, arguments: [kcbz]\nCompleted checkpoint\n');
  fs.writeFileSync(path.join(dir, 'rows.txt'), opts.rows || rows(diag));
  // fake sqlplus: records its stdin and argv, prints the canned rows
  fs.writeFileSync(path.join(bin, 'sqlplus'), `#!/usr/bin/env bash\necho "$@" > "${dir}/argv.txt"\ncat > "${dir}/stdin.txt"\ncat "${dir}/rows.txt"\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(bin, 'lsnrctl'), `#!/usr/bin/env bash\n${opts.lsnrDown ? 'echo "TNS-12541: TNS:no listener"' : 'echo \'Service "PROD" has 1 instance(s).\'; echo \'Service "PRODPDB1" has 1 instance(s).\'; echo "The command completed successfully"'}\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(dir, 'token'), TOKEN + '\n', { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'pw'), PW + '\n', { mode: 0o600 });
  const conf = path.join(dir, 'collector.conf');
  fs.writeFileSync(conf, [`SIEM_URL=${opts.url}`, 'SOURCE_ID=ora-prod19c', `TOKEN_FILE=${dir}/token`, `ORACLE_HOME=${oh}`, 'ORACLE_SID=PROD',
    'DB_CONNECT=SENTRA_MON@//localhost:1521/PRODPDB1', `PASSWORD_FILE=${dir}/pw`, `STATE_DIR=${st}`, 'ALLOW_HTTP=1', 'PERF=1', 'PACK_ASH=0'].join('\n') + '\n', { mode: 0o600 });
  return { conf, st, diag, dir };
}
function run(k, mode) {
  return new Promise((resolve) => {
    const p = spawn('bash', [path.join(KIT, 'sentra-oracle-collector.sh'), mode], { env: Object.assign({}, process.env, { SENTRA_ORA_CONF: k.conf, ORACLE_HOME: '', ORACLE_SID: '' }) });
    let out = '', err = ''; p.stdout.on('data', (d) => { out += d; }); p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => resolve({ code, out, err }));
  });
}
function server(answer) {
  const got = [];
  const srv = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = zlib.gunzipSync(Buffer.concat(chunks)).toString('utf8');
      got.push({ url: req.url, headers: req.headers, lines: body.split('\n').filter(Boolean) });
      const a = answer(got.length);
      res.writeHead(a.status, { 'Content-Type': a.type || 'application/json' }); res.end(a.body);
    });
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, got, url: `http://127.0.0.1:${srv.address().port}` })));
}

test('collector: health, performance and audit rows reach the SIEM and parse into the events the rules use', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ora-'));
  const s = await server(() => ({ status: 200, body: '{"ok":true,"accepted":30}' }));
  try {
    const k = kit(dir, { url: s.url });
    const r = await run(k, '--test');
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, new RegExp('connected to PROD \\(PROD\\) on dbhost01\\.' + 'corp-hq\\.com'));
    assert.match(r.out, /1 query error\(s\), first: ORA-00942/);
    assert.match(r.out, /SIEM: 1 batch\(es\) accepted/);
    // secrets: the password went to sqlplus on stdin only, the token only as a header
    assert.ok(!fs.readFileSync(path.join(dir, 'argv.txt'), 'utf8').includes(PW), 'password not on the sqlplus command line');
    const stdin = fs.readFileSync(path.join(dir, 'stdin.txt'), 'utf8');
    assert.match(stdin, /^connect SENTRA_MON\/"S3cret-Pw!"@\/\/localhost:1521\/PRODPDB1$/m);
    assert.match(stdin, /define SINCE=INIT/); assert.match(stdin, /collect-perf\.sql/); assert.doesNotMatch(stdin, /collect-pack\.sql/, 'no Diagnostics Pack query without PACK_ASH=1');
    const req = s.got[0];
    assert.equal(req.url, '/ingest/ora-prod19c'); assert.equal(req.headers['x-sentra-token'], TOKEN); assert.ok(req.headers['x-sentra-batch-id']);
    assert.ok(!r.out.includes(TOKEN) && !r.err.includes(TOKEN));
    // every line parses with the SIEM's parser, as the collector's source type
    const evs = req.lines.map((l) => { const o = JSON.parse(l); assert.ok(health.sniff(l, { obj: o }), 'recognised: ' + o.kind); return health.parse(l, { obj: o }); });
    const by = (a) => evs.filter((e) => e && e.action === a);
    assert.equal(by('health-sample').length, 1); assert.equal(by('health-sample')[0].host, ('dbhost01.' + 'corp-hq.com'));
    assert.equal(by('tablespace-usage').find((e) => e.fields.key === 'USERS').severity, 4, 'USERS 97 % → SENTRA-ORA-009');
    assert.equal(by('logon-failed').length, 1, 'unified audit ORA-01017 → SENTRA-ORA-001'); assert.equal(by('logon-failed')[0].user, 'scott');
    assert.equal(by('privilege-granted').length, 1);
    assert.equal(by('blocking-chain')[0].severity, 3, 'blocked 420 s → SENTRA-ORAP-004');
    assert.equal(by('load-profile')[0].fields.over_cpu, '1', 'AAS 9.5 on 8 CPUs → SENTRA-ORAP-001');
    assert.equal(by('wait-event')[0].severity, 2, 'log file sync 25 ms → SENTRA-ORAP-002');
    assert.equal(by('long-query')[0].severity, 2, '40 min → SENTRA-ORAP-005');
    assert.equal(by('plan-change')[0].fields.ratio, '4');
    assert.equal(by('temp-undo')[0].severity, 3, 'TEMP 90 % → SENTRA-ORAP-007');
    assert.equal(by('resource-limit')[0].fields.pct, '95', 'processes 95 % → SENTRA-ORAP-009');
    for (const a of ['efficiency', 'wait-class-rate', 'active-sessions', 'active-sql', 'memory', 'redo-rate', 'host-stats', 'backup-status', 'redo-status', 'fra-usage', 'invalid-objects', 'session-count']) assert.equal(by(a).length, 1, a);
    assert.equal(by('listener-status')[0].fields.services, '2');
    const al = by('alertlog-tail')[0]; assert.equal(al.fields.ora_errors, '1'); assert.match(al.fields.tail, /ORA-00600/);
    const hb = by('agent-heartbeat')[0]; assert.equal(hb.fields.queries_failed, '1'); assert.match(hb.fields.last_error, /ORA-00942/);
    // checkpoints: audit resumes after the newest row, alert log after its end; tablespace history kept for the forecast
    assert.equal(fs.readFileSync(path.join(k.st, 'audit.since'), 'utf8').trim(), '2026-10-14T08:00:05.123456');
    assert.ok(Number(fs.readFileSync(path.join(k.st, 'alert.offset'), 'utf8')) > 0);
    assert.match(fs.readFileSync(path.join(k.st, 'tsgrowth'), 'utf8'), /USERS 9700 10000/);
    assert.equal(fs.readdirSync(path.join(k.st, 'spool')).length, 0, 'delivered batch removed');

    // second run: audit continues from the checkpoint, the alert log sends nothing new
    const r2 = await run(k, '--once');
    assert.equal(r2.code, 0, r2.err);
    assert.match(fs.readFileSync(path.join(dir, 'stdin.txt'), 'utf8'), /define SINCE=2026-10-14T08:00:05\.123456/);
    assert.ok(!s.got[1].lines.some((l) => /"kind":"alertlog"/.test(l)));
  } finally { s.srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('collector: undelivered batches are spooled and re-sent; a 200 that is not the ingest API is not a delivery', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ora-'));
  let mode = 'portal';
  const s = await server(() => (mode === 'portal' ? { status: 200, type: 'text/html', body: '<html>portal</html>' } : { status: 200, body: '{"ok":true}' }));
  try {
    const k = kit(dir, { url: s.url });
    let r = await run(k, '--test');
    assert.equal(r.code, 1); assert.match(r.out, /NOT delivered.*not the SIEM ingest API answer/);
    assert.equal(fs.readdirSync(path.join(k.st, 'spool')).length, 1);
    mode = 'ok';
    r = await run(k, '--test');
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /2 batch\(es\) accepted/);
    assert.equal(fs.readdirSync(path.join(k.st, 'spool')).length, 0);
    const ids = s.got.map((g) => g.headers['x-sentra-batch-id']);
    assert.equal(ids[0], ids[1], 'the spooled batch is re-sent with the same batch id (the SIEM drops repeats)');
  } finally { s.srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('collector: database down → instance-down; bad login is not "down"; listener down; open token file refused; dry run sends nothing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-ora-'));
  const s = await server(() => ({ status: 200, body: '{"ok":true}' }));
  try {
    let k = kit(dir, { url: s.url, rows: 'ERROR:\nORA-01034: ORACLE not available\nORA-27101: shared memory realm does not exist', lsnrDown: true });
    let r = await run(k, '--dry-run');
    assert.equal(r.code, 0, r.err);
    assert.equal(s.got.length, 0, 'dry run sends nothing');
    const evs = r.out.split('\n').filter(Boolean).map((l) => health.parse(l, { obj: JSON.parse(l) }));
    assert.ok(evs.some((e) => e.action === 'instance-down' && e.severity === 4), 'SENTRA-ORA-008');
    assert.ok(evs.some((e) => e.action === 'listener-down'));
    assert.equal(evs.find((e) => e.action === 'agent-heartbeat').fields.sqlplus, 'failed');

    fs.writeFileSync(path.join(dir, 'rows.txt'), 'ERROR:\nORA-01017: invalid username/password; logon denied');
    r = await run(k, '--dry-run');
    const evs2 = r.out.split('\n').filter(Boolean).map((l) => health.parse(l, { obj: JSON.parse(l) }));
    assert.ok(!evs2.some((e) => e.action === 'instance-down'), 'a wrong password is not an outage');
    assert.match(evs2.find((e) => e.action === 'agent-heartbeat').fields.last_error, /ORA-01017/);

    fs.chmodSync(path.join(dir, 'token'), 0o644);
    r = await run(k, '--once');
    assert.equal(r.code, 1); assert.match(r.err, /readable by others - chmod 600/);
  } finally { s.srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('kit SQL: every collected kind is one the parser knows, the pack query is separate, grants cover the views', () => {
  const sql = ['collect.sql', 'collect-perf.sql', 'collect-pack.sql'].map((f) => fs.readFileSync(path.join(KIT, f), 'utf8'));
  const kinds = new Set(); for (const t of sql) for (const m of t.matchAll(/'kind' value '([a-z_]+)'/g)) kinds.add(m[1]);
  const perf = require('../engine/db-audit/oracle-perf');
  const healthKinds = ['instance', 'tablespace', 'sessions', 'blocked_session', 'wait_class', 'redo', 'backup', 'dataguard', 'invalid_objects', 'fra', 'top_sql', 'listener', 'failed_logon', 'alertlog', 'heartbeat', 'unified_audit'];
  for (const k of kinds) assert.ok(healthKinds.includes(k) || perf.KINDS.has(k), 'unknown kind ' + k);
  const code = (t) => t.split('\n').filter((l) => !/^\s*--/.test(l)).join('\n');
  assert.ok(!/active_session_history|dba_hist/i.test(code(sql[0]) + code(sql[1])), 'no Diagnostics Pack views outside collect-pack.sql');
  const grants = fs.readFileSync(path.join(KIT, 'create-monitor-user.sql'), 'utf8');
  const used = new Set(); for (const m of (code(sql[0]) + code(sql[1])).matchAll(/\b(v\$[a-z_]+|dba_[a-z_]+)\b/gi)) used.add(m[1].toLowerCase().replace('v$', 'v_$'));
  for (const v of used) assert.match(grants, new RegExp('grant select on sys\\.' + v.replace('$', '\\$') + ' to', 'i'), 'grant missing for ' + v);
  assert.match(grants, /grant audit_viewer/); assert.match(grants, /^-- grant select on sys\.v_\$active_session_history/m);
});
