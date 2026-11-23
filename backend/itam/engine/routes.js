// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// REST API /api/itam/* (portal auth) + agent gateway /agent/* (per-agent token). Roles: viewer read-only; operator
// adds/edits/transitions assets, scans, imports, confirms relationships, runs AI, adopts discoveries; admin manages
// settings, agent tokens, opens/closes stocktakes, reads the audit + AI-call log. EVERYONE (viewer up) can look up an
// asset by tag (self-service "whose is this / is it ours"). Hard delete is admin-only and lives in engine/asset-delete.js (reason required, audited).
const { VERSION } = require('./config');
const { BUILDERS } = require('./ai/classify');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const limitOf = (v, dflt, max) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? Math.min(n, max) : dflt; };
const AI_FEATURES = ['classify', 'relate', 'refresh'];

function registerRoutes(srv, app) {
  const { assets, licences, findings, ingest, stocktake, reports, settings, agentgw, provider, jobs, store, audit, importer } = app;
  const started = Date.now();
  const A = (who, action, target, detail) => audit({ by: who.user, role: who.role, ip: who.ip, action, target, detail });
  // the asset read routes in Python (engine/assets-py.js, docs/PYTHON-MIGRATION.md step 8c); null = Node.js answers
  const PY = (() => { try { return require('./assets-py').createAssetsPy(app); } catch (e) { return null; } })();
  // the human asset writes decided in Python, committed here (engine/assets-write.js, step 9d); Node.js decides when off
  const AW = (() => { try { return require('./assets-write').createAssetsWrite(app); } catch (e) { return null; } })();
  app.assetsWriteStats = () => (AW ? AW.stats() : null);
  // licences, stocktake, finding accept / dismiss and CMDB links decided in Python too (engine/py-writer.js, step 9e);
  // writes.engine = "node" turns it off. Settings, credentials and agent tokens always stay here (they carry secrets)
  const CW = (() => { try { return require('./py-writer').createPyWriter(app, { off: ((app.config && app.config.writes) || {}).engine === 'node' }); } catch (e) { return null; } })();
  const cw = (op, spec, who, node) => (CW ? CW.write(op, spec, who, node) : node());
  const rid = (p, n) => () => `${p}_${require('node:crypto').randomBytes(n).toString('hex')}`;
  app.coreWriteStats = () => (CW ? CW.stats() : null);

  // ---- health / status --------------------------------------------------------------------------------------------
  srv.route('GET', '/health', () => ({ ok: true, service: 'sentra-itam', version: VERSION, uptime_s: Math.round((Date.now() - started) / 1000) }));
  srv.route('GET', '/status', async (ctx) => { ctx.need('viewer');
    const p = await provider.status();
    return {
      ai: { provider: p.provider, state: p.state, model: p.model, message: p.message, calls_today: jobs.callsToday(), daily_cap: jobs.dailyCap, per_user_hourly_cap: jobs.perUser, my_calls_last_hour: jobs.userCallsLastHour(ctx.user), queue: jobs.queueInfo() },
      sources: settings.get().sources,
      credentials: settings.credentialStatus(),
      me: { user: ctx.user, role: ctx.role, can: { edit: ctx.role !== 'viewer', admin: ctx.role === 'admin' } },
      version: VERSION,
    };
  });
  srv.route('GET', '/summary', (ctx) => void ctx.need('viewer') || reports.summary());
  srv.route('GET', '/reports', (ctx) => void ctx.need('viewer') || reports.reports());

  // ---- self-service lookup by tag (EVERYONE) ----------------------------------------------------------------------
  srv.route('GET', '/lookup', async (ctx) => { ctx.need('viewer');
    const tag = ctx.query.tag || ctx.query.q || '';
    if (!tag) throw bad('tag query parameter required');
    const p = PY && await PY.lookup(tag); if (p) return { tag: p.tag, found: p.found, assets: p.assets };
    const hits = assets.byTag(tag).map((a) => ({ id: a.id, asset_tag: a.asset_tag, name: a.name, type: a.type, status: a.status, owner: a.owner, custodian: a.custodian, department: a.department, site: a.site, location: a.location }));
    return { tag, found: hits.length, assets: hits };
  });

  // ---- assets -----------------------------------------------------------------------------------------------------
  srv.route('GET', '/assets', async (ctx) => { ctx.need('viewer');
    const q = ctx.query;
    const p = PY && await PY.list(q); if (p) return { total: p.total, assets: p.assets };
    const text = (q.q || '').toLowerCase();
    const filter = (a) => {
      if (q.type && a.type !== q.type) return false;
      if (q.status && a.status !== q.status) return false;
      if (q.site && a.site !== q.site) return false;
      if (q.owner && a.owner !== q.owner) return false;
      if (q.source && !(a.sources || []).some((s) => s.source === q.source)) return false;
      if (q.networked === '1' && !a.networked) return false;
      if (q.networked === '0' && a.networked) return false;
      if (text && !`${a.name || ''} ${a.asset_tag || ''} ${a.serial || ''} ${a.model || ''} ${a.vendor || ''}`.toLowerCase().includes(text)) return false;
      return true;
    };
    const list = assets.list(filter);
    const limit = limitOf(q.limit, 500, 5000);
    return { total: list.length, assets: list.slice(0, limit) };
  });
  srv.route('GET', '/assets/:id', async (ctx) => { ctx.need('viewer'); const p = PY && await PY.detail(ctx.params.id); if (p) { if (!p.found) throw bad('asset not found', 404); return p.detail; } const d = assets.detail(ctx.params.id); if (!d) throw bad('asset not found', 404); return d; });
  /* one asset per asset tag and per serial number (a person's entry; discovery and import match on these on purpose and are
     not refused): a duplicate answers 409 naming the asset that holds it. Serials vendors ship as placeholders are ignored. */
  const JUNK_SERIAL = /^(|0+|n\/?a|none|null|unknown|default|to be filled by o\.?e\.?m\.?|system serial number|not specified|123456789|xxxx+|-+)$/i;
  const normKey = (v) => String(v == null ? '' : v).trim().replace(/\s+/g, ' ').toLowerCase();
  function uniqueOrThrow(b, selfId) {
    const tag = normKey(b && b.asset_tag), serial = normKey(b && b.serial);
    if (!tag && (!serial || JUNK_SERIAL.test(serial))) return;
    for (const a of store.collection('assets').all()) {
      if (a.id === selfId || a.status === 'deleted') continue;
      if (tag && normKey(a.asset_tag) === tag) throw Object.assign(new Error(`asset tag ${b.asset_tag} is already used by ${a.name || a.id} (${a.id})`), { status: 409, code2: 'duplicate_asset_tag' });
      if (serial && !JUNK_SERIAL.test(serial) && normKey(a.serial) === serial) throw Object.assign(new Error(`serial number ${b.serial} is already recorded on ${a.name || a.id} (${a.id})`), { status: 409, code2: 'duplicate_serial' });
    }
  }
  /* two people editing the same asset: a page that sends the updated_at it loaded (if_updated_at) is told the asset changed
     meanwhile (409) instead of silently overwriting the other person's edit */
  function freshOrThrow(id, b) {
    if (!b || b.if_updated_at === undefined) return;
    const cur = store.collection('assets').get(String(id));
    if (cur && String(b.if_updated_at) !== String(cur.updated_at)) throw Object.assign(new Error(`this asset was changed by someone else at ${cur.updated_at} - reload it and apply your change again`), { status: 409, code2: 'stale_edit' });
  }
  /* a person's asset writes are queued one at a time: the checks above and the write must be one step, because the Python
     writer (assets-write.js) decides asynchronously - two requests checked together would both pass and both write */
  let assetWrites = Promise.resolve();
  function oneAtATime(fn) { const run = assetWrites.then(fn, fn); assetWrites = run.then(() => undefined, () => undefined); return run; }
  srv.route('POST', '/assets', (ctx) => { ctx.need('operator'); return oneAtATime(() => { uniqueOrThrow(ctx.body); return AW ? AW.create(ctx.body, ctx.who) : assets.create(ctx.body, ctx.who, { source: 'manual' }); }); });
  srv.route('POST', '/assets/:id', (ctx) => { ctx.need('operator'); return oneAtATime(() => { freshOrThrow(ctx.params.id, ctx.body); if ((ctx.body || {}).asset_tag !== undefined || (ctx.body || {}).serial !== undefined) uniqueOrThrow(ctx.body, ctx.params.id); return AW ? AW.edit(ctx.params.id, ctx.body, ctx.who) : assets.edit(ctx.params.id, ctx.body, ctx.who); }); });
  for (const action of ['retire', 'dispose', 'repair', 'restock', 'activate', 'lost', 'found']) {
    srv.route('POST', `/assets/:id/${action}`, async (ctx) => {
      ctx.need('operator');
      const r = AW ? await AW.transition(ctx.params.id, action, ctx.who, ctx.body.reason) : assets.transition(ctx.params.id, action, ctx.who, ctx.body.reason);
      if (app.membership) app.membership.onLifecycle(ctx.params.id, action, ctx.who); // retire/dispose → pause its SIEM source (best effort)
      return r;
    });
  }

  // ---- log collection (SIEM membership; reads: everyone, writes: admin; engine/monitoring-membership.js) ----------
  const M = app.membership;
  if (M) {
    srv.route('GET', '/log-collection', async (ctx) => void ctx.need('viewer') || M.list());
    srv.route('POST', '/log-collection/bulk', async (ctx) => { ctx.need('admin'); return M.bulk(ctx.body.ids, String(ctx.body.action || ''), ctx.who); });
    srv.route('GET', '/assets/:id/log-collection', async (ctx) => void ctx.need('viewer') || M.detail(ctx.params.id));
    srv.route('GET', '/assets/:id/log-collection/setup', async (ctx) => void ctx.need('viewer') || M.setup(ctx.params.id));
    srv.route('POST', '/assets/:id/log-collection', async (ctx) => {
      ctx.need('admin');
      const act = String(ctx.body.action || '');
      if (act === 'enable') return M.enable(ctx.params.id, ctx.who);
      if (act === 'pause') return M.pause(ctx.params.id, ctx.who, ctx.body.reason);
      if (act === 'resume') return M.resume(ctx.params.id, ctx.who);
      if (act === 'stop') return M.stop(ctx.params.id, ctx.who, { confirm: ctx.body.confirm === true, reason: ctx.body.reason });
      throw bad('action must be enable, pause, resume or stop');
    });
  }
  srv.route('POST', '/assets/:id/move', (ctx) => { ctx.need('operator'); return AW ? AW.move(ctx.params.id, ctx.body, ctx.who) : assets.move(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/assets/:id/assign', (ctx) => { ctx.need('operator'); return AW ? AW.assign(ctx.params.id, ctx.body, ctx.who) : assets.assign(ctx.params.id, ctx.body, ctx.who); });

  // ---- software + licences ----------------------------------------------------------------------------------------
  srv.route('GET', '/software', async (ctx) => { ctx.need('viewer'); const p = PY && await PY.software(); if (p) return { software: p.software }; const { rollup } = require('./model/software'); return { software: rollup(assets.all().filter((a) => a.status !== 'disposed')) }; });
  srv.route('GET', '/licences', async (ctx) => { ctx.need('viewer'); const p = PY && await PY.licences(); return p ? { licences: p.licences } : { licences: licences.complianceView() }; });
  srv.route('POST', '/licences', (ctx) => { ctx.need('operator'); return cw('licences.save', { own: ['licences'], newId: ctx.body.id ? undefined : rid('lic', 5), extra: { body: ctx.body } }, ctx.who, () => ({ licence: licences.upsert(ctx.body, ctx.who) })); });
  srv.route('POST', '/licences/:id/retire', (ctx) => { ctx.need('operator'); return cw('licences.retire', { own: ['licences'], extra: { id: ctx.params.id, reason: ctx.body.reason } }, ctx.who, () => licences.retire(ctx.params.id, ctx.who, ctx.body.reason)); });

  // ---- CMDB -------------------------------------------------------------------------------------------------------
  srv.route('GET', '/cmdb', async (ctx) => { ctx.need('viewer');
    const p = PY && await PY.cmdb(ctx.query); if (p) return p.graph ? { graph: p.graph } : { relationships: p.relationships };
    if (ctx.query.asset) return { graph: assets.relationshipsFor(ctx.query.asset, { confirmedOnly: ctx.query.confirmed === '1' }) };
    return { relationships: assets.allRelationships().map((r) => { const { key, ...rest } = r; return rest; }) };
  });
  srv.route('POST', '/cmdb', (ctx) => { ctx.need('operator'); return cw('cmdb.add', { reads: ['relationships'], own: ['relationships'], newId: rid('rel', 5), extra: { body: ctx.body } }, ctx.who, () => ({ relationship: assets.addRelationship(ctx.body, ctx.who, { source: 'manual', autoConfirm: ctx.body.confirm !== false }) })); });

  // ---- discovery --------------------------------------------------------------------------------------------------
  srv.route('GET', '/discovery', (ctx) => void ctx.need('viewer') || ({ runs: ingest.runSummaries(), unmatched: ingest.discoveredList() }));
  srv.route('POST', '/discovery/run', async (ctx) => {
    ctx.need('admin');
    const source = ctx.query.source || ctx.body.source;
    if (source === 'netops') return ingest.runNetops(app.netopsConnector());
    if (source === 'vcenter') return ingest.runVcenter(app.vcenterConnector());
    throw bad('source must be netops or vcenter');
  });
  srv.route('POST', '/discovery/:id/adopt', (ctx) => { ctx.need('operator'); return ingest.adopt(ctx.params.id, ctx.who); });

  // ---- stocktake --------------------------------------------------------------------------------------------------
  srv.route('GET', '/stocktake', (ctx) => void ctx.need('viewer') || ({ stocktakes: stocktake.list() }));
  srv.route('GET', '/stocktake/:id', (ctx) => { ctx.need('viewer'); const r = stocktake.get(ctx.params.id); if (!r) throw bad('stocktake not found', 404); return r; });
  srv.route('POST', '/stocktake', (ctx) => { ctx.need('admin'); return cw('stocktake.open', { reads: ['assets'], own: ['stocktakes'], newId: rid('stk', 5), extra: { body: ctx.body } }, ctx.who, () => stocktake.open(ctx.body, ctx.who)); });
  srv.route('POST', '/stocktake/:id/scan', (ctx) => { ctx.need('operator'); return cw('stocktake.scan', { reads: ['assets'], own: ['stocktakes'], extra: { id: ctx.params.id, body: ctx.body } }, ctx.who, () => stocktake.scan(ctx.params.id, ctx.body, ctx.who)); });
  srv.route('POST', '/stocktake/:id/close', (ctx) => { ctx.need('admin'); return cw('stocktake.close', { own: ['stocktakes'], extra: { id: ctx.params.id } }, ctx.who, () => stocktake.close(ctx.params.id, ctx.who)); });

  // ---- AI findings + runs -----------------------------------------------------------------------------------------
  srv.route('GET', '/ai/findings', (ctx) => { ctx.need('viewer');
    const status = ctx.query.status || 'open';
    const list = findings.list((f) => (status === 'all' ? true : f.status === status) && (!ctx.query.kind || f.kind === ctx.query.kind));
    return { findings: list, summary: findings.summary() };
  });
  srv.route('POST', '/ai/findings/regenerate', (ctx) => { ctx.need('operator'); return findings.regenerate(ctx.who); });
  srv.route('POST', '/ai/findings/:id/accept', (ctx) => { ctx.need('operator'); return cw('findings.status', { own: ['findings'], extra: { id: ctx.params.id, status: 'accepted', reason: ctx.body.reason } }, ctx.who, () => ({ finding: findings.setStatus(ctx.params.id, 'accepted', ctx.who, ctx.body.reason) })); });
  srv.route('POST', '/ai/findings/:id/dismiss', (ctx) => { ctx.need('operator'); return cw('findings.status', { own: ['findings'], extra: { id: ctx.params.id, status: 'dismissed', reason: ctx.body.reason } }, ctx.who, () => ({ finding: findings.setStatus(ctx.params.id, 'dismissed', ctx.who, ctx.body.reason) })); });
  srv.route('POST', '/ai/run/:feature', async (ctx) => {
    ctx.need('operator');
    const feature = ctx.params.feature;
    if (!AI_FEATURES.includes(feature)) throw bad('unknown AI feature', 404);
    const p = await provider.status();
    if (p.state !== 'ready') { ctx.raw(409, { 'Content-Type': 'application/json; charset=utf-8' }, JSON.stringify({ ok: false, code: p.state, error: p.message, message: p.message })); return undefined; }
    const prepared = BUILDERS[feature](assets.list(), assets.allRelationships());
    if (!prepared.ctx.ids.length) throw bad('nothing to analyse for this feature right now');
    const job = jobs.enqueue({ feature, user: ctx.user, role: ctx.role, prepared });
    A(ctx.who, 'ai.run', feature, { job_id: job.id, count: prepared.meta.count });
    return { job_id: job.id, status: job.status };
  });
  srv.route('GET', '/ai/jobs/:id', (ctx) => { ctx.need('viewer'); const j = jobs.get(ctx.params.id); if (!j) throw bad('job not found', 404); return jobs.view(j); });
  srv.route('GET', '/ai/results/:id', (ctx) => { ctx.need('viewer'); const r = store.collection('ai_results').get(ctx.params.id); if (!r) throw bad('result not found', 404); return r; });
  srv.route('GET', '/ai/refresh-plan', (ctx) => { ctx.need('viewer'); return store.collection('refresh_plans').get('latest') || { items: [], summary: '', risks: [] }; });

  // ---- settings + credentials + agent tokens (admin) --------------------------------------------------------------
  srv.route('GET', '/settings', (ctx) => { ctx.need('admin'); return { settings: settings.get(), credentials: settings.credentialStatus(), imports: Object.keys(importer.MAPPINGS) }; });
  srv.route('POST', '/settings', (ctx) => { ctx.need('admin'); return { settings: settings.update(ctx.body, ctx.who) }; });
  srv.route('POST', '/settings/credential', (ctx) => { ctx.need('admin'); settings.setCredential(ctx.body.name, ctx.body.value, ctx.who); return { ok: true, credentials: settings.credentialStatus() }; });
  srv.route('GET', '/settings/agent-tokens', (ctx) => { ctx.need('admin'); return { tokens: agentgw.listTokens() }; });
  srv.route('POST', '/settings/agent-tokens', (ctx) => { ctx.need('admin'); return agentgw.issueToken(ctx.body, ctx.who); });
  srv.route('POST', '/settings/agent-tokens/:prefix/revoke', (ctx) => { ctx.need('admin'); return agentgw.revokeToken(ctx.params.prefix, ctx.who); });
  srv.route('GET', '/agents', (ctx) => { ctx.need('operator'); return { agents: agentgw.listAgents() }; });
  srv.route('POST', '/agents/:id/revoke', (ctx) => { ctx.need('admin'); return agentgw.revokeAgent(ctx.params.id, ctx.who); });
  srv.route('POST', '/agents/:id/bind', (ctx) => { ctx.need('admin'); return agentgw.bindAgent(ctx.params.id, ctx.body.asset_id, assets, ctx.who); });

  // ---- imports ----------------------------------------------------------------------------------------------------
  srv.route('GET', '/import', (ctx) => { ctx.need('operator'); return { mappings: Object.keys(importer.MAPPINGS), formats: ['csv', 'json'] }; });
  srv.route('POST', '/import/run', (ctx) => { ctx.need('operator'); const r = importer.runImport(ctx.body, assets, { dryRun: ctx.body.dry_run === true, who: ctx.who }); A(ctx.who, 'import.run', ctx.body.mapping || 'generic', { rows: r.rows, created: r.created, updated: r.updated, dry_run: r.dry_run }); return r; }, { maxBody: 8 * 1024 * 1024 });

  // ---- audit (admin) ----------------------------------------------------------------------------------------------
  // the hash-chain check reads every audit file: on a worker thread (engine/audit-verify.js) it runs at the same speed
  // but no longer stops this process meanwhile. audit.engine = "python" (pyengine/store.py) or "node" (here, in line)
  srv.route('GET', '/audit', async (ctx) => {
    ctx.need('admin');
    const eng = ((app.config && app.config.audit) || {}).engine;
    let verify = null;
    if (eng !== 'node' && store.dir) {
      try {
        if (eng === 'python') { const r = await require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 120000 }).call('store.verify_audit', { dir: store.dir }); if (r && typeof r.ok === 'boolean' && typeof r.checked === 'number') verify = r; }
        else verify = await require('./audit-verify').verifyInWorker(store.dir, 120000);
      } catch (e) { verify = null; }
    }
    return { audit: store.auditTail(limitOf(ctx.query.limit, 200, 2000)), verify: verify || store.verifyAudit() };
  });

  // ---- AGENT GATEWAY (per-agent token; NO portal identity) -------------------------------------------------------
  srv.route('POST', '/enrol', (ctx) => agentgw.enrol(ctx.body), { agent: true });
  srv.route('POST', '/heartbeat', (ctx) => { const a = agentgw.authenticate(ctx.bearer()); if (!a) throw bad('invalid or revoked agent key', 401); return agentgw.heartbeat(a); }, { agent: true });
  srv.route('POST', '/report', (ctx) => {
    const a = agentgw.authenticate(ctx.bearer());
    if (!a) throw bad('invalid or revoked agent key', 401);
    const report = agentgw.acceptReport(a, ctx.body);
    const r = ingest.fromAgentReport(agentgw, a, report);
    return { ok: true, asset_id: r.assetId, accepted: true, review: !!r.review };
  }, { agent: true, maxBody: 8 * 1024 * 1024 });
}

module.exports = { registerRoutes };
