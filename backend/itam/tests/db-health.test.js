// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Oracle health from the asset inventory (engine/db-health.js): only the Oracle login Asset Discovery PROVED on a host is
// used there (label match - never tried elsewhere, so nothing is locked out); one "oracle-health" SIEM source is
// registered once and its token kept sealed; records reach /ingest/<src> in the Oracle agent's shape; a query the
// account may not run is reported, not guessed; a reset SIEM token is recovered by rotating.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createDbHealth, SRC_ID } = require('../engine/db-health');
const { createSealer } = require('../engine/discovery/vault');

function setup(e, { ingestStatus = [200] } = {}) {
  const devs = e.app.store.collection('disc_devices');
  devs.put({ id: 'dd1', ip: '10.0.0.5', hostname: 'dbprod01', status: 'approved', asset_id: 'a1', extra: { db_login: { oracle: { credential: 'ORA-RO', instance: 'PROD', host_name: 'dbprod01' } } } });
  devs.put({ id: 'dd2', ip: '10.0.0.6', status: 'approved', extra: { db_login: { oracle: { credential: 'SOMETHING-ELSE', instance: 'TEST' } } } });   // no saved login with that label
  devs.put({ id: 'dd3', ip: '10.0.0.7', status: 'ignored', extra: { db_login: { oracle: { credential: 'ORA-RO' } } } });                            // ignored device
  let released = 0; const helperCalls = [], siemCalls = [], ingest = [];
  const vault = {
    list: () => [{ id: 'c1', kind: 'db_login', label: 'ORA-RO', target: { engine: 'oracle', port: 1521, service: 'PROD' } }, { id: 'c2', kind: 'db_login', label: 'MSSQL', target: { engine: 'mssql' } }],
    open: (id) => { assert.equal(id, 'c1'); return { secret: { username: 'monitor', password: 'Mon-pw-1' }, release() { released++; } }; },
  };
  let tok = 0, created = false;
  const siem = { call: async (m, p, who, body) => {
    if (p === '/onboard/sites') return { status: 200, json: { sites: [{ id: 'dr-site', kind: 'dr' }, { id: 'hq', kind: 'main' }] } };
    siemCalls.push({ m, p, who, body });
    // like the real SIEM: a new source must name its site (the bug seen live: HTTP 400 "site required")
    if (p === '/onboard/sources' && !(body && body.site)) return { status: 400, json: { error: 'site required — pick the site this device or server belongs to' } };
    if (p === '/onboard/sources') { if (created) return { status: 409, json: { error: 'source already exists' } }; created = true; }
    tok++; return { status: 200, json: { source: { id: SRC_ID }, token: 'tok' + tok } };
  } };
  const statuses = ingestStatus.slice();
  const discovery = { vault, siem };
  const H = createDbHealth(e.app, {
    discovery,
    sealer: createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-db-health' }),
    invRun: async (r) => { if (r.op === 'oracle_audit') return { ok: true, rows: [] }; helperCalls.push(r); return { ok: true, records: [{ kind: 'instance', instance: 'PROD', host: 'dbprod01', db_name: 'PRODDB', status: 'OPEN', role: 'PRIMARY' }, { kind: 'tablespace', name: 'USERS', used_pct: 96, used_mb: 960, max_mb: 1000 }], errors: [{ query: 'backup', error: 'privilege' }, { query: 'instance', error: 'privilege', ora: 'ORA-00942' }] }; },
    request: async (url, o) => { ingest.push({ url, o }); return { status: statuses.length ? statuses.shift() : 200 }; },
  });
  return { H, helperCalls, siemCalls, ingest, released: () => released };
}

test('db-health: proven login only, one SIEM source, agent-shaped records, missing privilege named', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { H, helperCalls, siemCalls, ingest, released } = setup(e);
  const r = await H.pass();
  assert.equal(r.hosts, 1, 'only the host where the ORA-RO login was proven (not the other label, not the ignored device)');
  assert.equal(helperCalls.length, 1); assert.equal(helperCalls[0].op, 'oracle_health'); assert.equal(helperCalls[0].host, '10.0.0.5'); assert.equal(helperCalls[0].username, 'monitor'); assert.equal(helperCalls[0].service, 'PROD');
  assert.equal(released(), 2, 'the secret is released after each use (health read, then the audit trail read)');
  assert.equal(r.read, 1); assert.equal(r.sent, 3, 'instance + tablespace + heartbeat'); assert.deepEqual(r.results[0].missing, ['backup', 'instance']);
  const mi = r.results[0].missing_detail.find((m) => m.query === 'instance');
  assert.equal(mi.ora, 'ORA-00942'); assert.deepEqual(mi.grants, ['GRANT SELECT ON sys.v_$instance TO <monitoring user>;', 'GRANT SELECT ON sys.v_$database TO <monitoring user>;'], 'the exact grants for the status reading');
  assert.equal(siemCalls.length, 1); assert.equal(siemCalls[0].p, '/onboard/sources'); assert.equal(siemCalls[0].body.kind, 'oracle-health'); assert.equal(siemCalls[0].body.site, 'hq', 'the SIEM\'s main site'); assert.equal(siemCalls[0].who.user, 'system:itam-db-health');
  assert.match(ingest[0].url, /\/ingest\/ora-itam-assets$/); assert.equal(ingest[0].o.headers['X-Sentra-Token'], 'tok1');
  const lines = ingest[0].o.body.trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((x) => x.kind), ['instance', 'tablespace', 'heartbeat']);
  for (const x of lines) { assert.equal(x.collector, 'sentra-oracle-itam'); assert.equal(x.instance, 'PROD'); assert.equal(x.host, 'dbprod01'); assert.equal(x.db_name, 'PRODDB'); assert.ok(x.t); }
  assert.ok(!JSON.stringify(lines).includes('Mon-pw-1'), 'the password never leaves the helper call');
  await H.pass();
  assert.equal(siemCalls.length, 1, 'the source is registered once; the sealed token is reused');
  const st = H.status();
  assert.equal(st.oracle_logins, 1); assert.equal(st.hosts.length, 1); assert.equal(st.source_registered, true); assert.ok(!JSON.stringify(st).includes('tok1'), 'the token is never returned');
});

test('db-health: a SIEM that no longer accepts the token gets it rotated; nothing saved = says so', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { H, siemCalls, ingest } = setup(e, { ingestStatus: [200, 401, 200] });
  await H.pass();                                          // registers tok1, ingest 200
  const r = await H.pass();                                // ingest 401 → rotate → tok2 → 200
  assert.equal(r.sent, 3); assert.equal(siemCalls.length, 2); assert.equal(siemCalls[1].p, '/onboard/sources/' + SRC_ID + '/rotate-token');
  assert.equal(ingest[2].o.headers['X-Sentra-Token'], 'tok2');

  const e2 = await startApp({ noAi: true }); t.after(() => e2.close());
  const H2 = createDbHealth(e2.app, { discovery: { vault: { list: () => [] }, siem: {} }, invRun: async () => { throw new Error('must not run'); }, request: async () => { throw new Error('must not send'); } });
  const r2 = await H2.pass();
  assert.equal(r2.hosts, 0); assert.match(r2.note, /no Oracle database connected/);
});

test('db-health: a database registered from Connections & Setup is tested once, read every pass, paused on a refused login', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const creds = [], helperCalls = [];
  let authOk = true;
  const vault = {
    available: () => true,
    list: () => creds.slice(),
    get: (id) => creds.find((c) => c.id === id) || null,
    create: (b) => { const c = { id: 'cr' + (creds.length + 1), kind: b.kind, label: b.label, target: b.target }; c._secret = b.secret; creds.push(c); return c; },
    open: (id) => { const c = creds.find((x) => x.id === id); return { secret: Object.assign({}, c._secret), release() {} }; },
  };
  const siem = { call: async () => ({ status: 200, json: { source: { id: SRC_ID }, token: 't1' } }) };
  const H = createDbHealth(e.app, {
    discovery: { vault, siem },
    sealer: createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-db-health' }),
    invRun: async (r) => { if (r.op === 'oracle_audit') return { ok: true, rows: [] }; helperCalls.push(r); return authOk ? { ok: true, records: [{ kind: 'instance', instance: 'FINPRD', host: 'findb01' }] } : { ok: false, error_class: 'auth', error: 'ORA-01017' }; },
    request: async () => ({ status: 200 }),
  });
  const ADM = { user: 'syed', role: 'admin', ip: '' };
  await assert.rejects(() => H.addDb({ host: 'bad host;rm', service: 'X', username: 'u', password: 'p' }, ADM), /host must be/);
  await assert.rejects(() => H.addDb({ host: '10.0.0.9', service: '', username: 'u', password: 'p' }, ADM), /service name/);
  const d = await H.addDb({ label: 'Finance DB', host: '10.0.0.9', port: 1522, service: 'FINPRD', username: 'monitor', password: 'Mon-pw-1' }, ADM);
  assert.equal(d.last_test.ok, true); assert.equal(d.last_test.instance, 'FINPRD'); assert.equal(d.credential, 'oracle-Finance-DB');
  assert.equal(creds[0].target.engine, 'oracle'); assert.equal(creds[0].target.port, 1522);
  assert.deepEqual([helperCalls[0].host, helperCalls[0].port, helperCalls[0].service, helperCalls[0].username], ['10.0.0.9', 1522, 'FINPRD', 'monitor']);
  assert.ok(!JSON.stringify(H.databases()).includes('Mon-pw-1'), 'the password is never returned');
  await assert.rejects(() => H.addDb({ host: '10.0.0.9', port: 1522, service: 'finprd', cred_id: 'cr1' }, ADM), /already registered/);
  await new Promise((r) => setTimeout(r, 20));
  let p = await H.pass(); assert.equal(p.read, 1, 'read every pass');
  // the password was changed on the database: the next read is refused once, then the database is paused - no retries
  authOk = false; const before = helperCalls.length;
  p = await H.pass(); assert.equal(p.failed, 1);
  assert.ok(H.databases().databases[0].paused, 'paused after a refused login');
  p = await H.pass(); assert.equal(helperCalls.length, before + 1, 'not tried again on its own'); assert.match(p.note, /paused/);
  // an administrator tests it again after fixing the password: it resumes
  authOk = true; const back = await H.testDb(d.id, ADM); assert.equal(back.paused, null); assert.equal(back.last_test.ok, true);
  assert.deepEqual(H.removeDb(d.id, ADM), { removed: d.id }); assert.equal(H.databases().databases.length, 0);
});

test('db-health: an account with more than read-only rights is refused and paused; dictionary scans once an hour', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const creds = [], helperCalls = [];
  let mode = 'ok', clock = Date.parse('2026-10-19T08:00:00Z');
  const vault = {
    available: () => true, list: () => creds.slice(), get: (id) => creds.find((c) => c.id === id) || null,
    create: (b) => { const c = { id: 'cr' + (creds.length + 1), kind: b.kind, label: b.label, target: b.target }; c._secret = b.secret; creds.push(c); return c; },
    open: (id) => { const c = creds.find((x) => x.id === id); return { secret: Object.assign({}, c._secret), release() {} }; },
  };
  const H = createDbHealth(e.app, {
    discovery: { vault, siem: { call: async () => ({ status: 200, json: { source: { id: SRC_ID }, token: 't1' } }) } },
    sealer: createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-db-health' }),
    now: () => clock,
    invRun: async (r) => { if (r.op === 'oracle_audit') return { ok: true, rows: [] }; helperCalls.push(r);
      if (mode === 'unsafe') return { ok: false, error_class: 'unsafe', error: 'account holds more than read-only monitoring rights (ALTER SYSTEM, DROP ANY TABLE) - not used' };
      if (mode === 'locked') return { ok: false, error_class: 'auth', error: 'ORA-28000: the account is locked' };
      return { ok: true, records: [{ kind: 'instance', instance: 'FINPRD', host: 'findb01' }] }; },
    request: async () => ({ status: 200 }),
  });
  const ADM = { user: 'syed', role: 'admin', ip: '' };
  // a DBA-grade account entered by mistake: refused at the first test, the reason is shown, it is paused
  mode = 'unsafe';
  const d = await H.addDb({ label: 'Finance DB', host: '10.0.0.9', service: 'FINPRD', username: 'system', password: 'x' }, ADM);
  assert.equal(d.last_test.ok, false); assert.equal(d.last_test.cls, 'unsafe'); assert.match(d.last_test.error, /ALTER SYSTEM/);
  assert.match(d.paused.reason, /more than read-only/);
  const n = helperCalls.length; let p = await H.pass();
  assert.equal(helperCalls.length, n, 'a paused database is not touched by the scheduled pass'); assert.match(p.note, /not a read-only account/);
  // fixed (rights reduced), tested again: resumes; the test always runs the full set
  mode = 'ok'; const i0 = helperCalls.length; await H.testDb(d.id, ADM);
  assert.equal(helperCalls[i0].heavy, true, 'an administrator test reads everything');
  await new Promise((r) => setTimeout(r, 20));   // the test starts a pass of its own (first sample to the DBA at once)
  p = await H.pass(); assert.equal(helperCalls[helperCalls.length - 1].heavy, false, 'within the hour: no dictionary scans');
  clock += 61 * 60000; p = await H.pass(); assert.equal(helperCalls[helperCalls.length - 1].heavy, true, 'once an hour they run');
  clock += 5 * 60000; p = await H.pass(); assert.equal(helperCalls[helperCalls.length - 1].heavy, false);
  // the account gets locked by someone else: paused like a refused login, never retried on its own
  mode = 'locked'; p = await H.pass(); assert.equal(p.failed, 1); assert.match(H.databases().databases[0].paused.reason, /login refused/);
  assert.match(H.databases().databases[0].last_test.error, /^auth: ORA-28000: the account is locked/, 'the exact Oracle error is kept, so the page can say "locked", not "wrong password"');
  const m = helperCalls.length; await H.pass(); assert.equal(helperCalls.length, m, 'a locked account is not retried');
});

test('db-health: a found database can be removed from the inventory (reason required, never read again) and restored', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const { H, helperCalls } = setup(e);
  const who = { user: 'syed', role: 'admin', ip: '10.1.1.1' };
  assert.throws(() => H.dismiss({ device_id: 'dd1' }, who), /say why/);
  assert.throws(() => H.dismiss({ device_id: 'nope', reason: 'x' }, who), /not found/);
  const r = H.dismiss({ device_id: 'dd1', reason: 'old test copy, not used' }, who);
  assert.deepEqual([r.ip, r.engines, r.by], ['10.0.0.5', ['oracle'], 'syed']);
  assert.equal(H.databases().dismissed[0].reason, 'old test copy, not used');
  const p = await H.pass();
  assert.equal(p.hosts, 0, 'a removed database is not read'); assert.equal(helperCalls.length, 0);
  assert.equal(e.app.store.collection('disc_devices').get('dd1').status, 'approved', 'the server stays in Asset Discovery');
  H.undismiss({ device_id: 'dd1' }, who);
  assert.equal(H.databases().dismissed.length, 0);
  assert.equal((await H.pass()).hosts, 1, 'restored: read again');
  assert.throws(() => H.undismiss({ device_id: 'dd1' }, who), /not in the removed list/);
});

test('db-health: edit a registered database - new password lifts the pause, another saved login, validation, audit', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const creds = []; let pw = 'right-1';
  const vault = {
    available: () => true, list: () => creds.slice(), get: (id) => creds.find((c) => c.id === id) || null,
    create: (b) => { const c = { id: 'cr' + (creds.length + 1), kind: b.kind, label: b.label, target: b.target, _secret: b.secret }; creds.push(c); return c; },
    open: (id) => { const c = creds.find((x) => x.id === id); return { secret: Object.assign({}, c._secret), release() {} }; },
  };
  const updates = [];
  const H = createDbHealth(e.app, {
    discovery: { vault, updateCredential: (id, body, who) => { const c = creds.find((x) => x.id === id); updates.push([id, Object.keys(body.secret), who.user]); c._secret = Object.assign({}, c._secret, body.secret); return c; },
      siem: { call: async () => ({ status: 200, json: { source: { id: SRC_ID }, token: 't1' } }) } },
    sealer: createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-db-health' }),
    invRun: async (r) => { if (r.op === 'oracle_audit') return { ok: true, rows: [] };
      return r.password === pw ? { ok: true, records: [{ kind: 'instance', instance: 'ESXDR', host: 'esx-agg' }] } : { ok: false, error_class: 'auth', error: 'ORA-01017: invalid username/password; logon denied' }; },
    request: async () => ({ status: 200 }),
  });
  const ADM = { user: 'syed', role: 'admin', ip: '' };
  const d = await H.addDb({ label: 'ESX-Aggregator', host: '192.168.9.29', service: 'ESXDR', username: 'zyb_monitor', password: 'wrong' }, ADM);
  assert.equal(d.last_test.ok, false); assert.match(d.last_test.error, /ORA-01017/); assert.ok(d.paused, 'refused login pauses it');
  await assert.rejects(H.editDb(d.id, { username: 'zyb_monitor' }, ADM), /password together/);
  await assert.rejects(H.editDb(d.id, { port: 99999, password: 'x' }, ADM), /port/);
  const ok = await H.editDb(d.id, { password: 'right-1', label: 'ESX Aggregator (DR)' }, ADM);
  assert.equal(ok.last_test.ok, true, 'the new password works'); assert.equal(ok.paused, null, 'the pause is lifted'); assert.equal(ok.label, 'ESX Aggregator (DR)');
  assert.deepEqual(updates[0], [d.cred_id, ['password'], 'syed'], 'same saved login, only the password changed, by the admin');
  // another saved login
  const other = vault.create({ kind: 'db_login', label: 'oracle-dr-monitor', target: { engine: 'oracle', port: 1521, service: 'ESXDR' }, secret: { username: 'dr_mon', password: 'right-1' } });
  const sw = await H.editDb(d.id, { cred_id: other.id }, ADM);
  assert.equal(sw.cred_id, other.id); assert.equal(sw.credential, 'oracle-dr-monitor');
  await assert.rejects(H.editDb(d.id, { cred_id: 'nope' }, ADM), /saved Oracle login/);
  assert.ok(e.app.store.auditTail(50, (x) => x.action === 'db.health.database.edit').length >= 2, 'edits are audited');
  assert.ok(!JSON.stringify(H.databases()).includes('right-1'), 'no password in the API');
});

test('db-health: each missing reading says who fixes it - grant (exact views, real account), platform query error, timeout; one script', () => {
  const { missingDetail, fixScript } = require('../engine/db-health');
  const md = missingDetail([
    { query: 'sessions', error: 'ORA-00937: not a single-group group function', ora: 'ORA-00937' },
    { query: 'gg_capture', error: 'ORA-00942: table or view does not exist', ora: 'ORA-00942' },
    { query: 'dg_broker', error: 'ORA-00942: table or view does not exist', ora: 'ORA-00942' },
    { query: 'audit_trail', error: 'ORA-01031: insufficient privileges', ora: 'ORA-01031' },
    { query: 'wait_events', error: 'DPY-4024: call timeout of 10000 ms exceeded' },
    { query: 'asm', error: 'ORA-00942', ora: 'ORA-00942' },
  ], 'ZYB_MONITOR');
  const by = Object.fromEntries(md.map((m) => [m.query, m]));
  assert.equal(by.sessions.kind, 'platform', 'ORA-00937 is a query error of ours, never a grant'); assert.deepEqual(by.sessions.grants, []); assert.match(by.sessions.fix, /Nothing for the DBA/);
  assert.equal(by.gg_capture.kind, 'grant');
  assert.deepEqual(by.gg_capture.grants.sort(), ['GRANT SELECT ON sys.dba_capture TO zyb_monitor;', 'GRANT SELECT ON sys.v_$goldengate_capture TO zyb_monitor;'], 'views taken from the SQL the platform runs, the real account named');
  assert.deepEqual(by.dg_broker.grants, ['GRANT SELECT ON sys.v_$dg_broker_config TO zyb_monitor;']);
  assert.deepEqual(by.audit_trail.grants, ['GRANT AUDIT_VIEWER TO zyb_monitor;'], 'the audit trail needs the read-only role');
  assert.equal(by.wait_events.kind, 'timeout'); assert.equal(by.asm.label, 'ASM disk groups');
  const sc = fixScript(md);
  assert.equal(sc.length, new Set(sc).size, 'each grant once'); assert.ok(sc.includes('GRANT SELECT ON sys.v_$asm_diskgroup_stat TO zyb_monitor;'));
  assert.ok(sc.every((g) => /^GRANT (SELECT ON sys\.[a-z_$]+|AUDIT_VIEWER) TO zyb_monitor;$/.test(g)), 'read-only grants only');
  assert.match(missingDetail([{ query: 'asm', ora: 'ORA-00942' }], "bad'name")[0].grants[0], /<monitoring user>/, 'a strange account name is never put in the script');
});
