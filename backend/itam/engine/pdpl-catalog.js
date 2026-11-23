// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data catalog and identity correlation (PDPL Arts. 4, 12; Implementing Regulation Arts. 3-10, 33).
 *
 * Catalog: the read-only discovery scans of every database with a proven read-only login (Oracle, SQL Server,
 * PostgreSQL - engine/pdpl.js runDiscovery), shown by attribute (national ID, mobile, diagnosis ...), by source and by
 * column. An administrator confirms IDENTIFIER columns - the columns a person can be found by.
 * Identity correlation ("find this person"): for an OPEN data subject request whose requester's identity has been
 * VERIFIED, a person types the identifier; every confirmed identifier column of that type is searched read-only
 * (inv-helper op db_find: count(*) with the value as a bound parameter) and only the number of rows per table comes back.
 * The identifier is never stored, logged or audited - the request record keeps the type, who searched, when, and the
 * counts. Systems where the person was found become tasks on the request. The rules are Python (pyengine/pdpl_catalog.py).
 *
 *   GET  /pdpl/catalog                         operator  attributes, sources, columns, files, identifier suggestions, coverage
 *        files come from the SIEM (GET /pii/files: SharePoint / OneDrive via Graph, file shares via the Windows agent 1.5);
 *        a sensitive file shared anonymously / outside / readable by everyone is a duty finding
 *   POST /pdpl/catalog/identifiers             admin     {column_id, id_type} | {column_id, remove: true}       audited
 *   POST /pdpl/dsar/:id/correlate              operator  {id_type, value, create_tasks?}  open + verified only   audited (never the value)
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const ID_TYPES = ['national_id', 'iqama', 'passport', 'mobile', 'email', 'iban', 'customer_no', 'policy_no', 'claim_no'];
const VALUE_RE = { national_id: /^1\d{9}$/, iqama: /^2\d{9}$/, mobile: /^(\+?966|00966|0)?5\d{8}$/, email: /^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$/, iban: /^SA\d{22}$/i, passport: /^[A-Za-z0-9]{5,12}$/ };

function createCatalog(app, PD, opts) {
  const now = opts.now, store = app.store, py = opts.py, disc = opts.disc;
  const idC = () => store.collection('pdpl_identifiers');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  async function rules(op, body) {
    const r = await py.call(op, body);
    if (!r || r.ok === false) throw httpErr(409, 'The catalog rules run in Python and Python did not answer (' + ((r && r.error_class) || 'no answer') + ') - run the update so pyengine is installed');
    return r;
  }
  const scans = () => disc().all((x) => x.id !== '_last');
  // files: SharePoint / OneDrive and the agents' file-share scans live in the SIEM (GET /pii/files, analyst); null = no link
  async function siemFiles(who) {
    const L = app.discovery && app.discovery.siem;
    if (opts.siemFiles) return opts.siemFiles(who);
    if (!L || typeof L.call !== 'function') return null;
    try {
      const r = await L.call('GET', '/pii/files', { user: who.user, role: 'analyst' });
      if (r && r.status === 200 && r.json) return r.json;
      if (app.log && app.log.every) app.log.every('pdpl:siem-files', 600000, 'warn', 'the SIEM did not return the file discovery', { status: r && r.status });
      const why = r && r.status === 403 ? 'the SIEM refused the request as a viewer: IT Asset Management\'s link to the SIEM (engine/discovery/siem.js) is older than this page and does not pass the analyst role - run the update (install/fix-siem-role.sh corrects that line)'
        : r && r.status === 404 ? 'the SIEM does not have the file discovery yet (GET /pii/files) - run the update so the SIEM is updated too'
        : 'the SIEM answered HTTP ' + (r && r.status) + ' for the file discovery';
      return { sharepoint: { sources: [], status: { last_error: why } }, fileshares: { hosts: [] } };
    } catch (e) {
      if (app.log && app.log.every) app.log.every('pdpl:siem-files', 600000, 'warn', 'the SIEM is not reachable for the file discovery', { err: String(e.message).slice(0, 200) });
      return { sharepoint: { sources: [], status: { last_error: 'the SIEM is not reachable: ' + String(e.message).slice(0, 120) } }, fileshares: { hosts: [] } };
    }
  }
  async function startSharepoint(who) {
    const L = app.discovery && app.discovery.siem;
    if (opts.siemRun) return opts.siemRun(who);
    if (!L || typeof L.call !== 'function') return { started: false, reason: 'no SIEM link' };
    const r = await L.call('POST', '/pii/sharepoint/run', { user: who.user, role: who.role === 'admin' ? 'admin' : 'analyst' }, {});
    return r && r.status === 200 ? r.json : { started: false, reason: 'the SIEM answered HTTP ' + (r && r.status) };
  }
  async function findings() {
    const f = await siemFiles({ user: 'system:itam-pdpl', role: 'analyst' });
    if (!f) return [];
    return (await rules('pdpl.catalog', { scans: [], identifiers: [], targets: [], files: f })).findings || [];
  }
  async function view(who) {
    let targets = []; try { targets = opts.discoveryTargets().map((t) => ({ key: t.key, engine: t.engine, host: t.host || t.ip })); } catch (e) { targets = []; if (app.log && app.log.every) app.log.every('pdpl:catalog-targets', 3600000, 'warn', 'catalog could not list database targets', { err: String(e.message).slice(0, 200) }); }
    const files = await siemFiles(who || { user: 'system:itam-pdpl' });
    return Object.assign(await rules('pdpl.catalog', { scans: scans(), identifiers: idC().all(), targets, files }), { last: disc().get('_last') || null });
  }
  function setIdentifier(b, who) {
    const parts = b.column_id.split('|'), column = parts.pop(), table = parts.pop(), owner = parts.pop(), db = parts.join('|');   // the source key itself holds | (engine|ip|port)
    const s = disc().get(db), col = s && (s.columns || []).find((c) => c.owner === owner && c.table === table && c.column === column);
    if (!col) throw httpErr(404, 'no scanned column ' + b.column_id + ' - run discovery first');
    const prev = idC().get(b.column_id);
    if (b.remove) {
      if (!prev) throw httpErr(404, b.column_id + ' is not an identifier column');
      idC().remove(b.column_id);
      audit(who, 'pdpl.catalog.identifier.remove', b.column_id, { id_type: prev.id_type });
      return { id: b.column_id, removed: true };
    }
    if (col.confirmed === false) throw httpErr(409, 'the sampled values of ' + column + ' did not look like personal data - it cannot be an identifier column');
    const rec = { id: b.column_id, db, owner, table, column, col_type: col.type, id_type: b.id_type, by: who.user, at: new Date(now()).toISOString() };
    idC().put(rec);
    audit(who, 'pdpl.catalog.identifier.set', b.column_id, { id_type: b.id_type, previous: prev ? prev.id_type : null });
    return rec;
  }
  // o.automated: the request intake (engine/pdpl-intake.js) searching for a requester the channel verified, and only when an
  // administrator switched automatic search on - the same read-only counts, audited as automated
  async function correlate(id, b, who, o = {}) {
    if (isService(who.user) && !(o.automated && /^system:dsar-intake(:|$)/.test(who.user))) throw httpErr(403, 'a person searches for a data subject, not a service or AI identity');
    const r = PD.records('dsr').find((x) => x.id === id); if (!r) throw httpErr(404, 'no data subject request ' + id);
    if (['responded', 'refused', 'withdrawn'].includes(r.stage) || (r.responded && !r.stage)) throw httpErr(409, id + ' is closed - a search is only for an open request');
    if (!r.identity_verified) throw httpErr(409, 'verify the requester\'s identity first: the search runs only for a verified data subject');
    const rx = VALUE_RE[b.id_type]; if (rx && !rx.test(String(b.value).replace(/\s+/g, ''))) throw httpErr(400, 'value does not look like a ' + b.id_type.replace('_', ' '));
    const plan = (await rules('pdpl.correlate_plan', { scans: scans(), identifiers: idC().all(), id_type: b.id_type })).plan;
    if (!plan.length) throw httpErr(409, 'no identifier column of type ' + b.id_type + ' is confirmed in the catalog - an administrator confirms them on the Data Catalog page');
    const results = [];
    for (const p of plan) {
      const s = disc().get(p.db);
      const t = { key: p.db, engine: s.engine || 'oracle', ip: s.host, port: s.port || 1521, service: s.service, cred_id: s.cred_id };
      let x;
      if (!t.cred_id) x = { ok: false, error: 'no read-only login recorded for this source - run discovery again' };
      else {
        try { x = await opts.helperWith(t, { op: 'db_find', kind: b.id_type, value: b.value, columns: p.columns }); } catch (e) { x = { ok: false, error: String(e.message || e).slice(0, 200) }; }
      }
      results.push({ db: p.db, label: p.label, engine: p.engine, ok: !!(x && x.ok), error: x && !x.ok ? String(x.error_class || '') + (x.error ? ': ' + String(x.error).slice(0, 160) : '') : '', rows: (x && x.results) || [] });
      if (x && !x.ok && app.log && app.log.every) app.log.every('pdpl:correlate:' + p.db, 600000, 'warn', 'identity search could not read a source', { engine: p.engine, cls: x.error_class });
    }
    b.value = null;   // the identifier goes no further than the read-only queries
    const res = await rules('pdpl.correlate_result', { results });
    const at = new Date(now()).toISOString();
    const entry = { at, by: who.user, id_type: b.id_type, searched: res.searched, found_in: res.found_in, failed: res.failed, systems: res.systems.map((x) => ({ system: x.system, ok: x.ok, error: x.error, rows: x.rows, tables: x.tables })) };
    const upd = { kind: 'dsr', id, correlation: (r.correlation || []).concat([entry]).slice(-10) };
    let added = [];
    if (b.create_tasks !== false) {
      const tasks = (r.tasks || []).slice();
      for (const x of res.systems.filter((y) => y.rows > 0)) {
        if (tasks.some((t) => String(t.system).toLowerCase() === String(x.system).toLowerCase())) continue;
        if (tasks.length >= 50) break;
        tasks.push({ system: x.system, status: 'open', note: 'found by identity search: ' + x.rows + ' row(s) in ' + x.tables.length + ' table(s)', by: who.user, at });
        added.push(x.system);
      }
      if (added.length) upd.tasks = tasks;
    }
    PD.putRecord(upd, who);
    audit(who, 'pdpl.dsar.correlate', id, { id_type: b.id_type, sources: res.searched, found_in: res.found_in.length, failed: res.failed, tasks_added: added.length, automated: !!o.automated });
    return Object.assign(res, { at, tasks_added: added, note: 'Counts only. The identifier you typed was used for these read-only searches and is not stored or logged. Each system where the person was found is now a task on the request.' });
  }
  return { view, setIdentifier, correlate, findings, startSharepoint, ID_TYPES };
}

function registerCatalogRoutes(srv, app, C) {
  const { body, param } = require('./check');
  srv.route('GET', '/pdpl/catalog', (ctx) => { ctx.need('operator'); return C.view(ctx.who); });
  srv.route('POST', '/pdpl/catalog/identifiers', (ctx) => {
    ctx.need('admin');   // which columns a person may be searched by decides what the identity search reads
    const b = body(ctx.body).str('column_id', { required: true, max: 500, re: /^[^|]{1,200}(\|[^|]{1,200}){3,6}$/, msg: 'column_id must be source|schema|table|column' })
      .oneOf('id_type', C.ID_TYPES).bool('remove').rule((o) => (!o.remove && !o.id_type ? 'id_type is required (or remove: true)' : null)).done();
    return C.setIdentifier(b, ctx.who);
  });
  srv.route('POST', '/pdpl/dsar/:id/correlate', (ctx) => {
    ctx.need('operator');
    const id = param(ctx.params.id, 'id'); if (!/^PD-DSR-\d{3,}$/.test(id)) throw httpErr(400, 'id must be a data subject request id (PD-DSR-nnn)');
    const b = body(ctx.body).oneOf('id_type', C.ID_TYPES, { required: true }).str('value', { required: true, min: 3, max: 120, re: /^[A-Za-z0-9 +@._-]+$/, msg: 'value must be the identifier (letters, digits, + @ . _ -)' }).bool('create_tasks').done();
    return C.correlate(id, b, ctx.who);
  });
}

module.exports = { createCatalog, registerCatalogRoutes, ID_TYPES };
