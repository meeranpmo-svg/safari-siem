// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Personal-data discovery beyond Oracle, the data catalog and identity correlation:
//  - inv-helper db_pii_scan (SQL Server / PostgreSQL): dictionary + 50-value test inside, counts only out; a login that can
//    write / own / administer is refused before anything is read; identifiers with quotes refused
//  - inv-helper db_find: count(*) with the identifier as a bound parameter (never in the SQL text), mobile variants,
//    numeric columns compared as numbers, counts only out
//  - engine: discovery reads every proven read-only login (db-targets.js); catalog by attribute / source / column;
//    identifier columns set by an administrator; the search only for an open request with a verified requester; tasks
//    created for systems where the person was found; the identifier is in no record, no audit entry, no store file
// Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { spawnSync } = require('node:child_process');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HELPER = path.join(__dirname, '..', 'engine', 'discovery', 'inv-helper.py');
const PY = process.env.PYTHON || 'python3';
const RUN = `
import json, sys, importlib.machinery, importlib.util
spec = importlib.util.spec_from_loader("invh", importlib.machinery.SourceFileLoader("invh", sys.argv[1]))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
LOG = []
UNSAFE = {"v": False}
COLS = {"postgres": [("crm", "customers", "national_id", "character varying", 5200, None), ("crm", "customers", "mobile_no", "character varying", 5200, None),
                     ("crm", "customers", "notes", "text", 5200, None), ("crm", "claims", "diag", "text", 900, "ICD diagnosis code"), ("crm", 'bad"t', "email", "text", 1, None)],
        "mssql": [("dbo", "Members", "IqamaNo", "varchar", 300, None), ("dbo", "Members", "Email", "nvarchar", 300, None), ("dbo", "Members", "MemberRef", "bigint", 300, None)]}
SAMPLE = {"national_id": ["1012345678", "1098765432", "x"], "mobile_no": ["0551234567"], "diag": ["J45.9", "E11"], "IqamaNo": ["2123456789"], "Email": ["not-an-email"]}
class Cur:
    def __init__(s, eng): s.eng = eng; s.res = []
    def execute(s, q, params=None):
        LOG.append({"q": q, "p": params}); ql = q.lower()
        if "rolsuper" in ql or "is_srvrolemember" in ql: s.res = [(1 if UNSAFE["v"] else 0, 0)]
        elif "information_schema.columns" in ql or "sys.tables" in ql: s.res = COLS[s.eng]
        elif ql.startswith("select count(*)"): s.res = [(3 if "national_id" in ql or "iqamano" in ql else 0,)]
        elif ql.startswith("select "):
            col = q.split(" ")[3 if s.eng == "mssql" else 1].strip('"[]')
            s.res = [(v,) for v in SAMPLE.get(col, [])]
        else: s.res = []
    def fetchall(s): return s.res
    def fetchone(s): return s.res[0]
class Conn:
    def __init__(s, eng): s.eng = eng
    def cursor(s): return Cur(s.eng)
    def rollback(s): LOG.append({"rollback": 1})
    def close(s): LOG.append({"close": 1})
m.connect_db = lambda r: Conn(r["engine"])
out = {}
for eng in ("postgres", "mssql"):
    del LOG[:]; out[eng + "_scan"] = {"r": m.op_db_pii_scan({"engine": eng}), "log": list(LOG)}
UNSAFE["v"] = True
del LOG[:]; out["unsafe"] = {"r": m.op_db_pii_scan({"engine": "postgres"}), "log": list(LOG)}
del LOG[:]; out["unsafe_find"] = {"r": m.op_db_find({"engine": "mssql", "kind": "iqama", "value": "2123456789", "columns": [{"owner": "dbo", "table": "Members", "column": "IqamaNo"}]}), "log": list(LOG)}
UNSAFE["v"] = False
del LOG[:]; out["find_pg"] = {"r": m.op_db_find({"engine": "postgres", "kind": "mobile", "value": "+966 55 123 4567", "columns": [{"owner": "crm", "table": "customers", "column": "mobile_no", "type": "character varying"}, {"owner": "crm", "table": 'x"; drop table y; --', "column": "c"}]}), "log": list(LOG)}
del LOG[:]; out["find_ms"] = {"r": m.op_db_find({"engine": "mssql", "kind": "national_id", "value": "1012345678", "columns": [{"owner": "dbo", "table": "Members", "column": "national_id", "type": "varchar"}, {"owner": "dbo", "table": "Members", "column": "MemberRef", "type": "bigint"}]}), "log": list(LOG)}
print(json.dumps(out))
`;
function helper() { const p = spawnSync(PY, ['-I', '-c', RUN, HELPER], { encoding: 'utf8' }); assert.equal(p.status, 0, p.stderr); return { r: JSON.parse(p.stdout), raw: p.stdout }; }

test('helper: SQL Server / PostgreSQL scan - read-only check first, counts only, unsafe login refused; identity search with bound parameters', () => {
  const { r, raw } = helper();
  for (const eng of ['postgres', 'mssql']) {
    const x = r[eng + '_scan'];
    assert.equal(x.r.ok, true, eng);
    assert.match(x.log[0].q, /rolsuper|is_srvrolemember/i, eng + ': privileges checked first');
    for (const l of x.log.filter((y) => y.q)) assert.match(l.q.trim(), /^(select|set )/i, eng + ' only reads: ' + l.q.slice(0, 60));
    assert.equal(x.log[x.log.length - 1].close, 1, eng + ' connection closed');
  }
  const pg = r.postgres_scan.r, by = (c) => pg.columns.find((x) => x.column === c);
  assert.deepEqual(pg.columns.map((c) => c.column).sort(), ['diag', 'email', 'mobile_no', 'national_id'], 'notes is not personal-data named');
  assert.deepEqual([by('national_id').matched, by('national_id').sampled, by('national_id').confirmed], [2, 3, true]);
  assert.equal(by('diag').by, 'comment'); assert.equal(by('diag').category, 'health');
  assert.equal(by('email').sampled, undefined, 'a table name with a quote is never put into SQL');
  assert.ok(r.postgres_scan.log.some((l) => /set session characteristics as transaction read only/.test(l.q || '')));
  const ms = r.mssql_scan.r; assert.equal(ms.columns.find((c) => c.column === 'Email').confirmed, false); assert.equal(ms.columns.find((c) => c.column === 'IqamaNo').confirmed, true);
  assert.ok(r.mssql_scan.log.some((l) => /select top 50 \[IqamaNo\] from \[dbo\]\.\[Members\]/.test(l.q || '')));
  for (const v of ['1012345678', '0551234567', '2123456789']) assert.ok(!JSON.stringify([pg, ms]).includes(v), 'value left the helper: ' + v);
  assert.equal(r.unsafe.r.ok, false); assert.equal(r.unsafe.r.error_class, 'unsafe'); assert.equal(r.unsafe.log.filter((l) => l.q).length, 1, 'nothing read after the refusal');
  assert.equal(r.unsafe_find.r.error_class, 'unsafe');
  // search: the value only as parameters; variants for a mobile; quotes refused; numbers for a numeric column
  const fp = r.find_pg;
  const q = fp.log.find((l) => /^select count\(\*\)/.test(l.q || ''));
  assert.match(q.q, /^select count\(\*\) from "crm"\."customers" where "mobile_no" in \(%s(, %s)+\)$/);
  assert.ok(q.p.includes('0551234567') && q.p.includes('+966551234567'), 'mobile variants as parameters');
  assert.ok(!fp.log.some((l) => /551234567/.test(l.q || '')), 'the identifier never appears in SQL text');
  assert.equal(fp.r.results[1].error, 'identifier not allowed');
  const fm = r.find_ms.r.results; assert.equal(fm[0].count, 3); assert.equal(fm[1].count, 0);
  assert.deepEqual(r.find_ms.log.find((l) => /MemberRef/.test(l.q || '')).p, [1012345678], 'numeric column compared as a number');
  assert.ok(!JSON.stringify(r.find_ms.r).includes('1012345678') && !JSON.stringify(fp.r).includes('551234567'), 'counts only come back');
  assert.ok(raw.length > 0);
});

let clock = Date.parse('2026-10-20T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' };
const NID = '1012345678';
async function setup(t) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  e.app.store.collection('disc_devices').put({ id: 'd-sql', ip: '10.8.0.52', hostname: 'CLAIMS-SQL', status: 'matched', extra: { db_login: { mssql: { credential: 'sql-ro', host_name: 'CLAIMS-SQL' } } } });
  e.app.store.collection('disc_devices').put({ id: 'd-pg', ip: '10.8.0.53', hostname: 'CRM-PG', status: 'matched', extra: { db_login: { postgres: { credential: 'pg-ro', host_name: 'CRM-PG' } } } });
  const vault = { list: () => [{ id: 'c2', kind: 'db_login', label: 'sql-ro', target: { engine: 'mssql' } }, { id: 'c3', kind: 'db_login', label: 'pg-ro', target: { engine: 'postgres', database: 'crm' } }],
    open: (id) => ({ target: id === 'c3' ? { database: 'crm' } : {}, secret: { username: 'ro_syn', password: 'Synthetic-Pass-1' }, release() {} }) };
  e.app.discovery = Object.assign({}, e.app.discovery, { vault });
  const calls = [];
  const invRun = async (input) => {
    calls.push(input);
    if (input.op === 'db_pii_scan' && input.engine === 'mssql') return { ok: true, engine: 'mssql', scanned_columns: 40, columns: [{ owner: 'dbo', table: 'Members', column: 'NationalId', type: 'varchar', rows: 300, kind: 'national_id', category: 'identity', by: 'name', confirmed: true, sampled: 50, matched: 50 },
      { owner: 'dbo', table: 'Claims', column: 'DiagCode', type: 'varchar', rows: 900, kind: 'health', category: 'health', by: 'name', confirmed: true }] };
    if (input.op === 'db_pii_scan') return { ok: true, engine: 'postgres', scanned_columns: 20, columns: [{ owner: 'crm', table: 'customers', column: 'national_id', type: 'character varying', rows: 5200, kind: 'national_id', category: 'identity', by: 'name', confirmed: true },
      { owner: 'crm', table: 'customers', column: 'email', type: 'text', rows: 5200, kind: 'email', category: 'contact', by: 'name', confirmed: false }] };
    if (input.op === 'db_find') return input.engine === 'mssql' ? { ok: false, error_class: 'timeout', error: 'canceling statement' } : { ok: true, results: input.columns.map((c) => Object.assign({}, c, { count: 2 })) };
    return { ok: false, error: 'unexpected op' };
  };
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, pdplInvRun: invRun });
  const post = (p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));
  const get = (p, who = OP) => e.req('GET', p, who);
  return { e, post, get, calls };
}

test('catalog: discovery across SQL Server and PostgreSQL, attributes / sources / columns, identifiers set by an administrator', async (t) => {
  const { e, post, get, calls } = await setup(t);
  const r = await post('/pdpl/discovery/run', {}, ADM); assert.equal(r.status, 200, r.raw);
  assert.deepEqual(r.json.databases.map((d) => d.engine).sort(), ['mssql', 'postgres']);
  assert.ok(calls.every((c) => c.op === 'db_pii_scan' && c.username === 'ro_syn'), 'scans with the vault login');
  assert.equal(calls.find((c) => c.engine === 'postgres').database, 'crm');
  assert.ok(!JSON.stringify(e.app.store.collection('pdpl_discovery').all()).includes('Synthetic-Pass-1'), 'the password is not stored with the scan');
  assert.equal((await get('/pdpl/catalog', VW)).status, 403);
  const c = (await get('/pdpl/catalog')).json;
  assert.equal(c.totals.sources, 2); assert.equal(c.totals.columns, 3, 'a column whose values contradicted its name is not counted');
  const nid = c.attributes.find((a) => a.kind === 'national_id'); assert.equal(nid.sources, 2); assert.equal(nid.attribute, 'National ID');
  assert.equal(c.attributes[0].sensitive, true, 'sensitive attributes first');
  assert.equal(c.suggestions.length, 2, 'national ID columns suggested as identifiers'); assert.equal(c.coverage.targets, 2); assert.match(c.note, /No personal data value is stored/);
  // identifiers: admin only, validated, must exist, not a contradicted column
  const col = 'mssql|10.8.0.52|1433|dbo|Members|NationalId';
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: col, id_type: 'national_id' })).status, 403);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: 'x', id_type: 'national_id' }, ADM)).status, 400);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: col, id_type: 'shoe_size' }, ADM)).status, 400);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: 'mssql|10.8.0.52|1433|dbo|Members|Nope', id_type: 'national_id' }, ADM)).status, 404);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: 'postgres|10.8.0.53|5432|crm|customers|email', id_type: 'email' }, ADM)).status, 409);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: col, id_type: 'national_id' }, ADM)).status, 200);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: 'postgres|10.8.0.53|5432|crm|customers|national_id', id_type: 'national_id' }, ADM)).status, 200);
  const c2 = (await get('/pdpl/catalog')).json; assert.equal(c2.suggestions.length, 0); assert.equal(c2.columns.find((x) => x.id === col).identifier, 'national_id');
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: col, remove: true }, ADM)).status, 200);
  assert.equal((await post('/pdpl/catalog/identifiers', { column_id: col, remove: true }, ADM)).status, 404);
  const acts = e.app.store.auditTail(40).map((x) => x.action);
  for (const a of ['pdpl.discovery.run', 'pdpl.catalog.identifier.set', 'pdpl.catalog.identifier.remove']) assert.ok(acts.includes(a), a);
});

test('identity correlation: open + verified request only, counts only, tasks created, the identifier is stored nowhere', async (t) => {
  const { e, post, calls } = await setup(t);
  await post('/pdpl/discovery/run', {}, ADM);
  for (const id of ['mssql|10.8.0.52|1433|dbo|Members|NationalId', 'postgres|10.8.0.53|5432|crm|customers|national_id']) assert.equal((await post('/pdpl/catalog/identifiers', { column_id: id, id_type: 'national_id' }, ADM)).status, 200);
  const d = (await post('/pdpl/dsar', { ref: 'DSR-SYN-77', type: 'access', channel: 'branch', received: '2026-10-19' })).json; assert.ok(d.id, JSON.stringify(d));
  const cor = (body, who = OP) => post('/pdpl/dsar/' + d.id + '/correlate', body, who);
  assert.equal((await cor({ id_type: 'national_id', value: NID }, VW)).status, 403);
  let r = await cor({ id_type: 'national_id', value: NID }); assert.equal(r.status, 409); assert.match(r.json.error, /verify the requester/);
  assert.equal((await post('/pdpl/dsar/' + d.id + '/verify', { method: 'national_id_in_branch' })).status, 200);
  assert.equal((await cor({ id_type: 'national_id', value: '12' })).status, 400);
  r = await cor({ id_type: 'national_id', value: '9999999999' }); assert.equal(r.status, 400); assert.doesNotMatch(r.json.error, /9999999999/, 'the error never echoes the value');
  assert.equal((await cor({ id_type: 'national_id', value: "1' or '1'='1" })).status, 400);
  r = await cor({ id_type: 'mobile', value: '0551234567' }); assert.equal(r.status, 409); assert.match(r.json.error, /no identifier column of type mobile/);
  assert.equal((await cor({ id_type: 'national_id', value: NID }, { user: 'ai:pdpl', role: 'operator' })).status, 403);
  r = await cor({ id_type: 'national_id', value: NID }); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.searched, 2); assert.deepEqual(r.json.found_in, ['CRM-PG']); assert.equal(r.json.failed, 1, 'the SQL Server search timed out and says so');
  assert.deepEqual(r.json.tasks_added, ['CRM-PG']); assert.match(r.json.note, /not stored or logged/);
  const finds = calls.filter((c) => c.op === 'db_find'); assert.equal(finds.length, 2); assert.ok(finds.every((c) => c.value === NID && c.kind === 'national_id'));
  assert.deepEqual(finds.find((c) => c.engine === 'postgres').columns, [{ owner: 'crm', table: 'customers', column: 'national_id', type: 'character varying' }]);
  const rec = (await e.req('GET', '/pdpl/dsar', OP)).json.requests.find((x) => x.id === d.id);
  assert.equal(rec.correlation.length, 1); assert.equal(rec.correlation[0].by, 'nora.syn'); assert.equal(rec.correlation[0].id_type, 'national_id');
  assert.ok(rec.tasks.some((x) => x.system === 'CRM-PG' && /identity search: 2 row/.test(x.note)));
  // the identifier: in no record, no audit entry, no store file
  assert.ok(!JSON.stringify(e.app.store.collection('pdpl_records').all()).includes(NID));
  assert.ok(!JSON.stringify(e.app.store.auditTail(200)).includes(NID));
  const dir = e.app.store.dir; for (const f of fs.readdirSync(dir)) { const p = path.join(dir, f); if (fs.statSync(p).isFile()) assert.ok(!fs.readFileSync(p, 'utf8').includes(NID), 'identifier found in ' + f); }
  const au = e.app.store.auditTail(40).find((x) => x.action === 'pdpl.dsar.correlate'); assert.equal(au.by, 'nora.syn'); assert.equal(au.detail.found_in, 1);
  // closed requests refuse the search
  await post('/pdpl/dsar/' + d.id + '/withdraw', { note: 'requester withdrew (synthetic)' });
  r = await cor({ id_type: 'national_id', value: NID }); assert.equal(r.status, 409); assert.match(r.json.error, /closed/);
});

test('files: SharePoint and file-share results from the SIEM in the catalog, exposure findings, Scan now starts SharePoint', async (t) => {
  const { e, post, get } = await setup(t);
  const siemCalls = [];
  const FILES = { sharepoint: { at: '2026-10-20T07:00:00Z', status: { running: false, last_error: '', enabled: true }, errors: [],
      sources: [{ key: 'sp:s1', kind: 'sharepoint', label: 'Claims Team (synthetic)', url: 'https://syn.sharepoint.com/sites/claims', files_seen: 120, files_read: 80, errors: [],
        hits: [{ id: 'f1', name: 'claims-register.docx', path: '/Claims', kinds: { national_id: 40 }, name_kinds: [], by: 'content', shared: 'anonymous' },
          { id: 'f2', name: 'Passport_scan.pdf', path: '/', kinds: {}, name_kinds: ['passport'], by: 'name', shared: 'organization' }] }] },
    fileshares: { hosts: [{ host: 'fs-syn-01', at: '2026-10-25T03:00:00Z', settings: { at: '2026-10-25T03:00:00Z', roots: [{ path: 'D:\\Shares\\HR', share: 'HR', files_seen: 300, files_read: 200, dirs_denied: 2,
      hits: [{ p: 'Payroll\\oct.xlsx', size: 9000, kinds: { iban: 12 }, name_kinds: ['salary'], by: 'content', open: true }, { p: 'Team\\list.csv', kinds: { mobile: 5 }, name_kinds: [], by: 'content', open: false }] }] } }] } };
  e.app.discovery.siem = { call: async (m, p, who, body) => { siemCalls.push([m, p, who.user, who.role]); return p === '/pii/files' ? { status: 200, json: FILES } : p === '/pii/sharepoint/run' ? { status: 200, json: { started: true } } : { status: 404, json: {} }; } };
  const c = (await get('/pdpl/catalog')).json;
  assert.deepEqual(siemCalls[0], ['GET', '/pii/files', 'nora.syn', 'analyst'], 'read from the SIEM as the person, analyst');
  assert.equal(c.totals.files, 4); assert.equal(c.totals.exposed_files, 2, 'anonymous link + readable by everyone');
  const sp = c.sources.find((x) => x.engine === 'sharepoint'); assert.equal(sp.files, 2); assert.equal(sp.exposure.anonymous, 1);
  const fs1 = c.sources.find((x) => x.engine === 'fileshare'); assert.equal(fs1.label, '\\\\fs-syn-01\\HR'); assert.match(fs1.error, /2 folder\(s\) could not be read/);
  const f1 = c.files.find((x) => x.name === 'claims-register.docx'); assert.equal(f1.exposure, 'anonymous'); assert.deepEqual(f1.attributes, ['National ID']);
  assert.equal(c.files.find((x) => x.name === 'oct.xlsx').path, 'Payroll');
  assert.ok(c.attributes.find((a) => a.kind === 'national_id').files >= 1);
  assert.equal(c.file_status.sharepoint.enabled, true);
  // duty: exposed sensitive files are findings; an organisation-wide link on a name-only passport scan is not "exposed"
  const f = await e.app.addons.pdpl.adapter.findings();
  assert.ok(f.some((x) => x.key === 'files:sp:s1|f1:exposed' && x.severity === 'high'));
  assert.ok(f.some((x) => /oct\.xlsx/.test(x.title) && /readable by everyone/.test(x.title)));
  assert.ok(!f.some((x) => /list\.csv/.test(x.title)), 'not open: not a finding');
  assert.ok(siemCalls.some((x) => x[2] === 'system:itam-pdpl'), 'the patrol reads as the platform');
  // Scan now (admin) starts the SharePoint run in the SIEM; an operator's catalog view never does
  const r = await post('/pdpl/discovery/run', {}, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.sharepoint.started, true);
  assert.ok(siemCalls.some((x) => x[0] === 'POST' && x[1] === '/pii/sharepoint/run' && x[2] === 'syed' && x[3] === 'admin'));
  // the SIEM down: the catalog still answers, and says why the files are missing
  e.app.discovery.siem = { call: async () => { throw new Error('SIEM not reachable (ECONNREFUSED)'); } };
  const c2 = (await get('/pdpl/catalog')).json; assert.equal(c2.totals.files, 0); assert.match(c2.file_status.sharepoint.last_error, /not reachable/);
});

test('SIEM 403 on the file discovery: the installer fixes the old link line (analyst role), the page names the cause', async (t) => {
  const os = require('node:os'), { spawnSync } = require('node:child_process');
  const SCRIPT = path.join(__dirname, '..', 'install', 'fix-siem-role.sh');
  const app = fs.mkdtempSync(path.join(os.tmpdir(), 'siemrole-')); fs.mkdirSync(path.join(app, 'engine', 'discovery'), { recursive: true });
  const F = path.join(app, 'engine', 'discovery', 'siem.js');
  const OLD = "    const headers = { 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': String(who.user || 'system').slice(0, 200), 'X-Auth-Role': who.role === 'admin' ? 'admin' : 'viewer', Accept: 'application/json' };\n";
  fs.writeFileSync(F, "'use strict';\nfunction x(who, secret) {\n" + OLD + "  return headers;\n}\nmodule.exports = x;\n");
  const run = () => spawnSync('bash', [SCRIPT], { env: Object.assign({}, process.env, { APP: app, NODE: process.execPath }), encoding: 'utf8' });
  let r = run(); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /analyst role now passed through/);
  delete require.cache[F]; const fn = require(F);
  assert.equal(fn({ user: 'u', role: 'analyst' }, () => 's')['X-Auth-Role'], 'analyst');
  assert.equal(fn({ user: 'u', role: 'admin' }, () => 's')['X-Auth-Role'], 'admin');
  assert.equal(fn({ user: 'u', role: 'operator' }, () => 's')['X-Auth-Role'], 'viewer', 'operator still goes as viewer');
  assert.ok(fs.existsSync(F + '.pre-role-fix'), 'previous file kept');
  r = run(); assert.match(r.stdout, /already passed through/, 'safe to run again');
  fs.writeFileSync(F, "'use strict';\n// changed on this server\n"); r = run(); assert.match(r.stdout, /differs from every shipped version/); assert.equal(fs.readFileSync(F, 'utf8'), "'use strict';\n// changed on this server\n", 'an unknown file is left alone');
  fs.rmSync(F); r = run(); assert.match(r.stdout, /not installed - skipped/);
  // the current repository link already passes the role (the script recognises it)
  fs.writeFileSync(F, fs.readFileSync(path.join(__dirname, '..', 'engine', 'discovery', 'siem.js'), 'utf8')); r = run(); assert.match(r.stdout, /already passed through/);
  // the page: a 403 names the link and the fix, a 404 says the SIEM is not updated
  const { e, get } = await setup(t);
  e.app.discovery.siem = { call: async () => ({ status: 403, json: { error: 'requires role analyst' } }) };
  let c = (await get('/pdpl/catalog')).json;
  assert.match(c.file_status.sharepoint.last_error, /refused the request as a viewer/); assert.match(c.file_status.sharepoint.last_error, /fix-siem-role\.sh/);
  e.app.discovery.siem = { call: async () => ({ status: 404, json: { error: 'not found' } }) };
  c = (await get('/pdpl/catalog')).json; assert.match(c.file_status.sharepoint.last_error, /SIEM does not have the file discovery yet/);
});
