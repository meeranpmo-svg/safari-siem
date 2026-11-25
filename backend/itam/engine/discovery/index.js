// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Asset Discovery service (extends sentra-itam; no parallel service). Scopes + safety gate, write-only credential vault,
 * scheduled/cancellable runs, correlated results with admin review (approve / ignore / merge), one-click SIEM connect
 * with silent-source health, rogue-device alerts, dashboard. Everything that changes state is audited into the existing
 * hash-chained ITAM audit with the user's name. See docs/DISCOVERY.md.
 *   createDiscovery({config, store, audit, log, assets, ingest, findings, deps}) → service (used by discovery/routes.js)
 *   deps (tests): exec, connect, readFile, createSession, request, ldapCa, resolve, siemRequest, siemReadFile
 */
const crypto = require('node:crypto');
const diag = require('./diag');
const { createScrubber } = require('./scrub');
const { createVault } = require('./vault');
const { createDevices } = require('./devices');
const { createSiem, KIND_TABLE, CONNECTABLE } = require('./siem');
const scopesM = require('./scopes');
const sched = require('./schedule');
const ip4 = require('./ipv4');
const runner = require('./runner');
const PM = (() => { try { return require('./py-methods'); } catch (e) { return { wrap: (n, m) => m, configure() {} }; } })();   // inventory sources answered by Python (docs/PYTHON-MIGRATION.md step 5a); a missing bridge never stops the engine
const snmpM = PM.wrapSnmp ? PM.wrapSnmp(require('./methods/snmp')) : require('./methods/snmp');
const adM = PM.wrap('ad', require('./methods/ad'));
const vcM = PM.wrap('vcenter', require('./methods/vcenter'));
const ntxM = PM.wrap('nutanix', require('./methods/nutanix'));
const cucmM = PM.wrap('cucm', require('./methods/cucm'));
const azM = PM.wrap('azure', require('./methods/azure'));
const awsM = PM.wrap('aws', require('./methods/aws'));
const hypervM = require('./methods/hyperv');
const loginM = require('./methods/login');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const SYSTEMS_OF_RECORD = ['ad', 'vcenter', 'nutanix', 'hyperv', 'cucm', 'azure', 'aws'];
const DEFAULTS = { methods: Object.fromEntries(scopesM.METHODS.map((m) => [m, true])), rogue_min_sightings: 3, max_concurrent_runs: 2, icmp_mode: 'fping' };
const SYSTEM = { user: 'system:discovery', role: 'system', ip: '' };

function createDiscovery({ config, store, audit, log, assets, ingest, findings, deps = {} }) {
  const dc = config.discovery || {};
  PM.configure({ python: dc.python_bin, engine: dc.engine, py: deps.pyEngine });
  const scrubber = deps.scrubber || createScrubber();
  const slog = scrubber.wrapLogger(log || { info() {}, warn() {}, error() {} });
  const A = (who, action, target, detail) => audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail: scrubber.deep(detail === undefined ? null : detail) });
  const vault = createVault({ store, keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, scrubber });
  const devices = createDevices({ store, assets, ingest, audit: (e) => audit(Object.assign({}, e, { detail: scrubber.deep(e.detail) })), config });
  const siem = createSiem({ config, log: slog, assets, store, audit: (e) => audit(Object.assign({}, e, { detail: scrubber.deep(e.detail) })), findings, request: deps.siemRequest, readFile: deps.siemReadFile });
  // read-only inventory logins (DB / SSH / storage API): trusted host keys + certificates, and the Python helper
  const trust = loginM.createTrust(store, (e) => audit(Object.assign({}, e, { detail: scrubber.deep(e.detail) })));
  const invRun = deps.invRun || loginM.realRunner(dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3');
  const scopesCol = store.collection('disc_scopes');
  const runsCol = store.collection('disc_runs');
  const setCol = store.collection('disc_settings');
  const hvHostsCol = store.collection('disc_hyperv_hosts');   // one row per Hyper-V host that reported: when, how, how many VMs
  const active = new Map(); // run id → {run, cancelled, promise}
  const sites = Array.isArray(dc.sites) && dc.sites.length ? dc.sites : ['Riyadh HQ', 'Jeddah DR', 'Riyadh Olaya', 'Alkhobar'];

  // runs left "running" by a previous process are closed as interrupted
  for (const r of runsCol.all((x) => x.status === 'running' || x.status === 'queued')) runsCol.put(Object.assign({}, r, { status: 'interrupted', finished_at: new Date().toISOString() }));

  // ---------------- settings (global method toggles etc.) ----------------
  function settings() {
    const s = setCol.get('settings') || {};
    return {
      methods: Object.assign({}, DEFAULTS.methods, s.methods || {}),
      rogue_min_sightings: Number.isInteger(s.rogue_min_sightings) ? s.rogue_min_sightings : DEFAULTS.rogue_min_sightings,
      max_concurrent_runs: Number.isInteger(s.max_concurrent_runs) ? s.max_concurrent_runs : DEFAULTS.max_concurrent_runs,
      icmp_mode: s.icmp_mode === 'ping' ? 'ping' : (dc.icmp_mode === 'ping' && !s.icmp_mode ? 'ping' : 'fping'),
      updated_by: s.updated_by || null, updated_at: s.updated_at || null,
    };
  }
  function updateSettings(body, who) {
    const b = body && typeof body === 'object' ? body : {};
    const cur = settings(); const next = JSON.parse(JSON.stringify(cur));
    if (b.methods !== undefined) {
      if (!b.methods || typeof b.methods !== 'object') throw bad('methods must be an object');
      for (const [k, v] of Object.entries(b.methods)) { if (!scopesM.METHODS.includes(k)) throw bad(`unknown method ${k}`); if (typeof v !== 'boolean') throw bad(`methods.${k} must be true or false`); next.methods[k] = v; }
    }
    if (b.rogue_min_sightings !== undefined) { const n = Number(b.rogue_min_sightings); if (!Number.isInteger(n) || n < 1 || n > 100) throw bad('rogue_min_sightings must be 1-100'); next.rogue_min_sightings = n; }
    if (b.max_concurrent_runs !== undefined) { const n = Number(b.max_concurrent_runs); if (!Number.isInteger(n) || n < 1 || n > 8) throw bad('max_concurrent_runs must be 1-8'); next.max_concurrent_runs = n; }
    if (b.icmp_mode !== undefined) { if (!['fping', 'ping'].includes(b.icmp_mode)) throw bad('icmp_mode must be fping or ping'); next.icmp_mode = b.icmp_mode; }
    const changed = {};
    for (const k of ['methods', 'rogue_min_sightings', 'max_concurrent_runs', 'icmp_mode']) if (JSON.stringify(cur[k]) !== JSON.stringify(next[k])) changed[k] = { from: cur[k], to: next[k] };
    if (!Object.keys(changed).length) return settings();
    setCol.put({ id: 'settings', methods: next.methods, rogue_min_sightings: next.rogue_min_sightings, max_concurrent_runs: next.max_concurrent_runs, icmp_mode: next.icmp_mode, updated_by: who.user, updated_at: new Date().toISOString() });
    A(who, 'discovery.methods.update', 'settings', changed);
    return settings();
  }

  // ---------------- scopes ----------------
  const credMeta = (id) => vault.meta(id);
  function scopeView(s) {
    if (!s) return null;
    const gate = scopesM.gateOpen(s);
    const am = scopesM.allowedMethods(s, settings().methods);
    const running = [...active.values()].find((x) => x.run.scope_id === s.id);
    return Object.assign({}, s, {
      gate: { open: gate, required: scopesM.ACTIVE.some((k) => s.methods[k] && s.methods[k].enabled), stale: !!(s.checklist && !gate), checklist: s.checklist || null },
      allowed_methods: am.run, blocked_methods: am.blocked, schedule_label: sched.label(s.schedule), running_run_id: running ? running.run.id : null,
    });
  }
  function listScopes(includeArchived) { return scopesCol.all((s) => includeArchived || s.status !== 'archived').map(scopeView).sort((a, b) => (a.name < b.name ? -1 : 1)); }
  function needScope(id) { const s = scopesCol.get(id); if (!s || s.status === 'archived') throw bad('scope not found', 404); return s; }
  function createScope(body, who) {
    const f = scopesM.normScope(body, { sites, maxHosts: dc.max_hosts_per_scope || 4096, credentials: credMeta });
    const now = new Date().toISOString();
    const s = Object.assign({ id: `sc_${crypto.randomBytes(5).toString('hex')}`, status: 'active', checklist: null, created_by: who.user, created_at: now, updated_by: who.user, updated_at: now, last_run_id: null }, f);
    s.next_run = sched.nextRun(s.schedule, Date.now());
    scopesCol.put(s);
    A(who, 'discovery.scope.create', s.id, { name: s.name, site: s.site, targets: s.targets, exclusions: s.exclusions, allow_public: s.allow_public, schedule: sched.label(s.schedule), methods: Object.keys(s.methods).filter((k) => s.methods[k].enabled) });
    return scopeView(s);
  }
  function updateScope(id, body, who) {
    const cur = needScope(id);
    const f = scopesM.normScope(body, { cur, sites, maxHosts: dc.max_hosts_per_scope || 4096, credentials: credMeta });
    const next = Object.assign({}, cur, f, { updated_by: who.user, updated_at: new Date().toISOString() });
    next.next_run = sched.nextRun(next.schedule, Date.now());
    const changed = {};
    for (const k of Object.keys(f)) if (JSON.stringify(cur[k]) !== JSON.stringify(next[k])) changed[k] = { from: cur[k], to: next[k] };
    const invalidated = !!(cur.checklist && scopesM.targetsFingerprint(cur) !== scopesM.targetsFingerprint(next));
    scopesCol.put(next);
    A(who, 'discovery.scope.update', id, { changed: Object.keys(changed), detail: changed, checklist_invalidated: invalidated });
    return scopeView(next);
  }
  function setScopeStatus(id, status, who) {
    const cur = needScope(id);
    if (!['active', 'disabled', 'archived'].includes(status)) throw bad('invalid status');
    scopesCol.put(Object.assign({}, cur, { status, updated_by: who.user, updated_at: new Date().toISOString() }));
    A(who, `discovery.scope.${status === 'active' ? 'enable' : status === 'disabled' ? 'disable' : 'archive'}`, id, { name: cur.name });
    return scopeView(scopesCol.get(id));
  }
  function completeChecklist(id, body, who) {
    const cur = needScope(id);
    const c = scopesM.normChecklist(body);
    const rec = Object.assign(c, { completed_by: who.user, completed_at: new Date().toISOString(), targets_fp: scopesM.targetsFingerprint(cur), targets: cur.targets, exclusions: cur.exclusions });
    scopesCol.put(Object.assign({}, cur, { checklist: rec, updated_by: who.user, updated_at: rec.completed_at }));
    A(who, 'discovery.scope.checklist', id, { name: cur.name, targets: cur.targets, firewall: rec.firewall, soc_notified_name: rec.soc_notified_name, soc_notified_date: rec.soc_notified_date, approved_by: rec.approved_by, note: rec.note });
    return scopeView(scopesCol.get(id));
  }
  function revokeChecklist(id, who) {
    const cur = needScope(id);
    scopesCol.put(Object.assign({}, cur, { checklist: null, updated_by: who.user, updated_at: new Date().toISOString() }));
    A(who, 'discovery.scope.checklist.revoke', id, { name: cur.name });
    return scopeView(scopesCol.get(id));
  }

  // ---------------- runs ----------------
  function runView(r) { if (!r) return null; const { seen, ...rest } = r; return rest; } // eslint-disable-line no-unused-vars
  function listRuns(q = {}) {
    let list = runsCol.all((r) => (!q.scope_id || r.scope_id === q.scope_id) && (!q.status || r.status === q.status));
    list = list.map((r) => (active.has(r.id) ? runView(active.get(r.id).run) : r));
    return list.sort((a, b) => (a.started_at < b.started_at ? 1 : -1)).slice(0, Math.min(Number(q.limit) || 100, 500));
  }
  function getRun(id) { if (active.has(id)) return runView(active.get(id).run); return runsCol.get(id); }
  function persist(run) { runsCol.put(runView(run)); }

  function startRun(scopeId, { trigger = 'manual', who }) {
    const scope = needScope(scopeId);
    if (scope.status !== 'active') throw bad('scope is disabled', 409);
    if ([...active.values()].some((x) => x.run.scope_id === scopeId)) throw bad('a run for this scope is already in progress', 409);
    if (active.size >= settings().max_concurrent_runs) throw bad(`the maximum of ${settings().max_concurrent_runs} concurrent runs is reached — try again when one finishes`, 409);
    const am = scopesM.allowedMethods(scope, settings().methods);
    const blocked = am.blocked.slice();
    let allowed = am.run;
    if (scope.window && !sched.inWindow(scope.window, Date.now())) {
      for (const k of allowed.filter((x) => scopesM.ACTIVE.includes(x))) blocked.push({ method: k, reason: `outside the scan window ${scope.window.start}-${scope.window.end} (Riyadh)` });
      allowed = allowed.filter((x) => !scopesM.ACTIVE.includes(x));
    }
    const run = {
      id: `dr_${crypto.randomBytes(6).toString('hex')}`, scope_id: scope.id, scope_name: scope.name, site: scope.site, trigger, by: who.user,
      status: 'running', started_at: new Date().toISOString(), finished_at: null, methods_run: allowed, methods_blocked: blocked,
      gate_open: scopesM.gateOpen(scope), progress: { hosts_total: 0, hosts_done: 0 }, stats: {}, devices_seen: 0, devices_new: 0, seen: new Set(),
    };
    const entry = { run, cancelled: false, window: false };
    active.set(run.id, entry);
    persist(run);
    scopesCol.patch(scope.id, (s) => { s.last_run_id = run.id; });
    A(who, 'discovery.scan.start', run.id, { scope_id: scope.id, scope: scope.name, trigger, methods: allowed, blocked });
    let lastPersist = 0;
    const ctx = {
      vault, devices, deps, settings, config, log: slog, trust, invRun,
      isCancelled: () => entry.cancelled || entry.window,
      stopWindow: () => { entry.window = true; },
      onProgress: () => { run.devices_seen = run.seen.size; if (Date.now() - lastPersist > 1500) { lastPersist = Date.now(); persist(run); } },
    };
    entry.promise = (async () => {
      try {
        await runner.execute({ run, scope, allowed, ctx });
        run.status = entry.cancelled ? 'cancelled' : entry.window ? 'stopped_window' : 'finished';
      } catch (e) {
        run.status = 'failed'; run.error = scrubber.text(e && e.status && e.status < 500 ? e.message : 'internal error');
        slog.error('discovery: run failed', { run: run.id, err: e && e.message });
      }
      run.finished_at = new Date().toISOString();
      run.devices_seen = run.seen.size;
      run.devices_new = [...run.seen].filter((id) => { const d = devices.get(id); return d && d.first_seen >= run.started_at; }).length;
      persist(run);
      active.delete(run.id);
      if (findings) { try { findings.syncKinds(['rogue_device'], SYSTEM); } catch (e) { slog.error('discovery: findings sync failed', { err: e.message }); } }
      try { await bridgeRogues(); } catch { /* bridge is best effort */ }
      A(trigger === 'schedule' ? { user: 'system:scheduler', role: 'system' } : who, 'discovery.scan.finish', run.id, { scope_id: scope.id, scope: scope.name, status: run.status, devices_seen: run.devices_seen, devices_new: run.devices_new, stats: run.stats, cancelled_by: run.cancelled_by || null });
      return runView(run);
    })();
    return runView(run);
  }
  function cancelRun(id, who) {
    const e = active.get(id);
    if (!e) { const r = runsCol.get(id); if (!r) throw bad('run not found', 404); throw bad(`run already ${r.status}`, 409); }
    e.cancelled = true; e.run.cancelled_by = who.user;
    A(who, 'discovery.scan.cancel', id, { scope_id: e.run.scope_id, scope: e.run.scope_name });
    return runView(e.run);
  }
  async function wait(id) { const e = active.get(id); if (e) await e.promise; return getRun(id); }

  // ---------------- credentials ----------------
  function refsTo(credId) { return scopesCol.all((s) => s.status !== 'archived' && Object.values(s.methods || {}).some((m) => m.credential_id === credId || (m.credential_ids || []).includes(credId))).map((s) => ({ id: s.id, name: s.name })); }
  function createCredential(body, who) { const v = vault.create(body, who); A(who, 'discovery.credential.create', v.id, { kind: v.kind, label: v.label, target: v.target, fingerprint: v.fingerprint }); return v; }
  function updateCredential(id, body, who) {
    const r = vault.update(id, body, who);
    // target before/after are public connection parameters (never the secret) so a redirect is visible in the audit
    A(who, 'discovery.credential.update', id, { kind: r.credential.kind, label: r.credential.label, target: r.credential.target, target_before: r.target_before, target_after: r.credential.target, target_changed: r.target_changed, secret_changed: r.secret_changed, fingerprint: r.credential.fingerprint });
    return r.credential;
  }
  function deleteCredential(id, who) {
    const used = refsTo(id);
    if (used.length) throw bad(`credential is used by scope(s): ${used.map((s) => s.name).join(', ')} — remove it from them first`, 409);
    const r = vault.remove(id);
    A(who, 'discovery.credential.delete', id, { kind: r.kind });
    return { removed: id };
  }
  // Classified, actionable connection test for the vault + Connect Wizard. Returns a structured result the UI shows
  // verbatim: { ok, latency_ms, error_class, stage, http, tls:{trusted, pinned, presented}, message, hint, discovered }.
  // The connectors (vcenter/ad/cucm/azure/aws) build this via diag.js so a TLS problem is never mislabelled as auth.
  // helper / storage answers → the standard test result; the helper's own text is kept where it says what to do
  function lerr(kind, r, t0, where) {
    const ec = (r && r.error_class) || 'error';
    const code = { auth: 'auth', denied: 'authz', authz: 'authz', timeout: 'timeout', refused: 'unreachable', unreachable: 'unreachable', dns: 'unreachable', service: 'config', busy: 'timeout', missing_module: 'config', config: 'config', tls: 'tls' }[ec] || 'protocol';
    const out = diag.fromError(kind, diag.err(code, (r && r.error) || 'login failed'), { latency_ms: Date.now() - t0 });
    if (ec === 'missing_module' || ec === 'config' || ec === 'denied') out.message = scrubber.text(String((r && r.error) || out.message).slice(0, 300));
    // name the address and port that was tried: a site that runs Oracle / SQL Server / SSH on its own ports gets
    // "refused" on the default port, and the fix is the Port on the credential
    if (where && (ec === 'refused' || ec === 'timeout' || ec === 'unreachable')) {
      const what = kind === 'ssh' ? 'SSH' : kind === 'db_login' ? 'database listener' : 'management API';
      out.message = ec === 'refused'
        ? `Connection refused at ${where.ip}:${where.port} - nothing listens there.${where.defaulted ? ` ${where.port} is the default ${what} port; if this server uses another one, set Port on this credential and test again.` : ` Check that the ${what} runs on port ${where.port}.`}`
        : ec === 'timeout'
          ? `No answer from ${where.ip}:${where.port} - a firewall between the platform server and this host is probably dropping that port${where.defaulted ? ` (or the ${what} uses another port: set Port on this credential)` : ''}.`
          : `Cannot reach ${where.ip} (no route) - check the address and the network path from the platform server.`;
    }
    return out;
  }
  async function testCredential(id, body, who) {
    const meta = vault.get(id);
    if (!meta) throw bad('credential not found', 404);
    let res;
    if (meta.future) res = diag.fromError(meta.kind, diag.err('not_supported', 'stored for future use'), { latency_ms: null });
    else if (meta.kind === 'ssh' || meta.kind === 'db_login' || meta.kind === 'storage_api') {
      // these log in to ONE host: it must be inside an active scope whose pre-scan checklist is complete (same rule as SNMP)
      const host = String((body && body.host) || '').trim();
      const n = ip4.parseIp(host);
      if (n === null) throw bad('host (IPv4) is required to test this credential');
      const scope = scopesCol.all((s) => s.status === 'active' && scopesM.gateOpen(s) && ip4.contains(s.targets, n) && !ip4.contains(s.exclusions, n))[0];
      if (!scope) throw bad('safety gate: the test host must be inside an active scope whose pre-scan checklist is complete', 409);
      const ip = ip4.ipStr(n), t0 = Date.now();
      const c = Object.assign(vault.open(id), { label: meta.label });
      try {
        let r;
        if (meta.kind === 'db_login') {
          const dbPort = c.target.port || loginM.DB_DEFAULT_PORT[c.target.engine];
          r = await invRun({ op: 'db', engine: c.target.engine, host: ip, port: dbPort, username: c.secret.username, password: c.secret.password, service: c.target.service, database: c.target.database, tls: c.target.tls || 'off', ca_file: c.target.ca_file });   // the same TLS setting the scan uses - never weaker for the test
          res = r && r.ok ? diag.result(meta.kind, { latency_ms: Date.now() - t0, message: 'Logged in: ' + String(r.version || '').slice(0, 160) })
            : lerr(meta.kind, r, t0, { ip, port: dbPort, defaulted: !c.target.port });
        } else if (meta.kind === 'ssh') {
          const port = c.target.port || 22, hk = await invRun({ op: 'hostkey', host: ip, port });
          if (!hk || !hk.ok) res = lerr(meta.kind, hk, t0, { ip, port, defaulted: !c.target.port });
          else {
            const tr = trust.see('ssh', ip, port, hk.fp, { type: hk.type });
            if (tr.state !== 'trusted') res = { ok: false, error_class: tr.state === 'changed' ? 'hostkey_changed' : 'hostkey_untrusted', latency_ms: Date.now() - t0, message: tr.state === 'changed' ? 'The SSH host key of this server CHANGED - not logged in. Check it, then trust the new key under Trust.' : `Host key recorded (${hk.type} SHA256 ${hk.fp.slice(0, 16)}…) - trust it under Trust, then test again. No password was sent.` };
            else {
              r = await invRun({ op: 'ssh_facts', host: ip, port, username: c.secret.username, password: c.secret.password, private_key: c.secret.private_key, fp: tr.fp });
              const u = r && r.ok ? loginM.parseUnix(r.facts) : null;
              res = u ? diag.result(meta.kind, { latency_ms: Date.now() - t0, message: 'Logged in: ' + [u.hostname, u.os, u.model, u.serial].filter(Boolean).join(' · ') })
                : lerr(meta.kind, r, t0, { ip, port, defaulted: !c.target.port });
            }
          }
        } else {
          const port = c.target.port || 443, tr = trust.get('tls', ip, port);
          const cred = { secret: c.secret, target: { base_url: `https://${ip}${port === 443 ? '' : ':' + port}`, tls_fingerprint: tr && tr.state === 'trusted' ? tr.fp : undefined } };
          r = await require('../storage-sources')[c.target.platform](cred, { request: deps.request, captureUntrusted: true, timeoutMs: 30000 });
          if (r.ok) res = diag.result(meta.kind, { latency_ms: Date.now() - t0, message: 'Logged in: ' + [r.system && r.system.name, r.system && r.system.model, r.system && r.system.version].filter(Boolean).join(' · ') });
          else if (r.presented && r.presented.fingerprint256) { const s2 = trust.see('tls', ip, port, r.presented.fingerprint256, { subject: r.presented.subject || null, issuer: r.presented.issuer || null, valid_to: r.presented.valid_to || null }); res = { ok: false, error_class: s2.state === 'changed' ? 'cert_changed' : 'cert_untrusted', latency_ms: Date.now() - t0, message: 'Certificate recorded - trust it under Trust, then test again. No password was sent.' }; }
          else res = lerr(meta.kind, r, t0);
        }
      } finally { c.release(); }
    } else if (meta.kind === 'snmp_v2c' || meta.kind === 'snmp_v3') {
      const host = String((body && body.host) || '').trim();
      const n = ip4.parseIp(host);
      if (n === null) throw bad('host (IPv4) is required to test an SNMP credential');
      const scope = scopesCol.all((s) => s.status === 'active' && scopesM.gateOpen(s) && ip4.contains(s.targets, n) && !ip4.contains(s.exclusions, n))[0];
      if (!scope) throw bad('safety gate: the test host must be inside an active scope whose pre-scan checklist is complete', 409);
      const c = vault.open(id);
      let probe;
      try { probe = await snmpM.probe(ip4.ipStr(n), c, { createSession: deps.createSession, timeout: dc.snmp_timeout_ms }); } finally { c.release(); }
      res = probe.ok ? diag.result(meta.kind, { latency_ms: probe.latency_ms, message: 'SNMP responded.' })
        : diag.fromError(meta.kind, diag.err(probe.error_class || 'error', 'SNMP test failed'), { latency_ms: probe.latency_ms });
    } else {
      const c = vault.open(id);
      try {
        if (meta.kind === 'ldap') res = await adM.test(c, { ca: deps.ldapCa });
        else if (meta.kind === 'vcenter') res = await vcM.test(c, { request: deps.request });
        else if (meta.kind === 'nutanix') res = await ntxM.test(c, { request: deps.request });
        else if (meta.kind === 'cucm_axl') res = await cucmM.test(c, { request: deps.request });
        else if (meta.kind === 'azure') res = await azM.test(c, Object.assign({}, dc.azure || {}, deps.request ? { request: deps.request } : {}));
        else if (meta.kind === 'aws') res = await awsM.test(c, Object.assign({}, dc.aws || {}, deps.request ? { request: deps.request } : {}));
        else res = diag.fromError(meta.kind, diag.err('not_supported', 'stored for future use'), { latency_ms: null });
      } finally { c.release(); }
    }
    const out = {
      ok: !!res.ok, latency_ms: res.latency_ms == null ? null : res.latency_ms,
      error_class: res.ok ? null : (res.error_class || 'error'),
      stage: res.stage || (res.ok ? 'read' : 'protocol'),
      http: res.http == null ? null : res.http,
      tls: res.tls || { trusted: !!res.ok, pinned: false, presented: null },
      message: res.message || null, hint: res.hint || null, discovered: res.discovered || null,
    };
    vault.recordTest(id, { ok: out.ok, latency_ms: out.latency_ms, error_class: out.error_class });
    A(who, 'discovery.credential.test', id, Object.assign({ kind: meta.kind, ok: out.ok, error_class: out.error_class, stage: out.stage, http: out.http }, body && body.host ? { host: String(body.host).slice(0, 40) } : {}));
    return out;
  }

  // ---------------- results ----------------
  function cmdbIndex() {
    const macs = new Set(); const serials = new Set();
    // agent-reported identity is self-asserted by the endpoint: an agent's MAC (or serial) claim is NOT a system-of-record
    // match, so it can never suppress a rogue-device alert (an enrolled agent could otherwise "whitelist" any MAC).
    for (const a of assets.all()) {
      if (a.status === 'disposed') continue;
      const prov = a.prov || {};
      if (a.mac && prov.mac !== 'agent') macs.add(String(a.mac).toLowerCase().replace(/[^0-9a-f]/g, ''));
      if (a.serial && prov.serial !== 'agent') serials.add(String(a.serial).toLowerCase());
      for (const sg of a.sources || []) { if (sg.source === 'agent') continue; for (const k of sg.keys || []) if (k.startsWith('mac:')) macs.add(k.slice(4)); }
    }
    return { macs, serials };
  }
  function inCmdb(d, idx) { return !!d.asset_id || (d.macs || []).some((m) => idx.macs.has(m.replace(/:/g, ''))) || (d.serial && idx.serials.has(d.serial.toLowerCase())); }
  function rogueDevices() {
    const st = settings(); const idx = cmdbIndex();
    const infra = new Set(scopesCol.all((s) => s.infra).map((s) => s.id));
    return devices.list((d) => d.status === 'new').filter((d) => {
      // known to AD / vCenter / … → not unknown. A Hyper-V report pushed with an agent key is self-asserted (untrusted) and
      // does not count as a system-of-record sighting.
      if (Object.entries(d.methods || {}).some(([m, v]) => SYSTEMS_OF_RECORD.includes(m) && !(v && v.untrusted))) return false;
      if (inCmdb(d, idx)) return false;
      return d.seen_count >= st.rogue_min_sightings || infra.has(d.scope_id);
    }).map((d) => ({ id: d.id, ip: d.ip, mac: d.mac, vendor: d.vendor || null, type: d.type, site: d.site, scope_id: d.scope_id, seen_count: d.seen_count, first_seen: d.first_seen, last_seen: d.last_seen, infra: infra.has(d.scope_id), reason: infra.has(d.scope_id) ? 'unknown device on a server/infrastructure subnet' : `unknown device seen ${d.seen_count} times` }));
  }
  function rogueFindings() {
    return rogueDevices().map((r) => ({
      key: `rogue_device:${r.id}`, kind: 'rogue_device', severity: r.infra ? 'high' : 'medium', asset_id: null, label: 'Discovery',
      title: `Unknown device on the network: ${r.ip || r.mac} (${r.vendor || 'unknown vendor'})`,
      detail: `${r.reason}. Not in the CMDB and not ignored. Review it in Asset Discovery > Results: approve it into the inventory, merge it into an existing asset, or ignore it with a reason.`,
      evidence: { device_id: r.id, ip: r.ip, mac: r.mac, type: r.type, site: r.site, seen_count: r.seen_count, first_seen: r.first_seen },
    }));
  }
  async function bridgeRogues() {
    const fresh = rogueDevices().filter((r) => { const d = devices.get(r.id); return d && !d.bridged_at; });
    if (!fresh.length) return { sent: 0 };
    const at = new Date().toISOString();
    const res = await siem.bridge(fresh.map((r) => ({ source: 'itam', kind: 'rogue-device', at, device_id: r.id, ip: r.ip, mac: r.mac, vendor: r.vendor, type: r.type, site: r.site, scope_id: r.scope_id, seen_count: r.seen_count, first_seen: r.first_seen, reason: r.reason, severity: r.infra ? 'high' : 'medium' })));
    if (res.sent) for (const r of fresh) devices.col.patch(r.id, (d) => { d.bridged_at = at; });
    return res;
  }
  if (findings && findings.addProvider) { findings.addProvider(rogueFindings); findings.addProvider(() => siem.silentFindings()); }

  function results(q = {}) {
    const text = String(q.q || '').toLowerCase();
    const list = devices.list((d) => (!q.status || q.status === 'all' || d.status === q.status) && (!q.type || d.type === q.type) && (!q.site || d.site === q.site) && (!q.scope_id || d.scope_id === q.scope_id)
      && (!q.method || (d.methods && d.methods[q.method])) && (!text || `${d.ip || ''} ${d.mac || ''} ${d.hostname || ''} ${d.vendor || ''} ${d.serial || ''} ${d.os || ''}`.toLowerCase().includes(text)));
    list.sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1));
    const lim = Math.min(Number(q.limit) || 500, 5000);
    const rogue = new Set(rogueDevices().map((r) => r.id));
    return { total: list.length, devices: list.slice(0, lim).map((d) => Object.assign(devices.view(d, false), { rogue: rogue.has(d.id) })) };
  }
  function result(id) { const d = devices.get(id); if (!d) throw bad('device not found', 404); const v = devices.view(d, true); v.rogue = rogueDevices().some((r) => r.id === id); v.asset_fields = devices.assetFields(d); return v; }
  function after() { if (findings) { try { findings.syncKinds(['rogue_device'], SYSTEM); } catch { /* */ } } }
  function approve(id, who) { const r = devices.approve(id, who); after(); return r; }
  function ignore(id, reason, who) { const r = devices.ignore(id, reason, who); after(); return r; }
  function restore(id, who) { const r = devices.restore(id, who); after(); return r; }
  function merge(id, assetId, who) { const r = devices.mergeInto(id, assetId, who); after(); return r; }

  // Bulk review: approve or ignore every matching "new" result in one call (reuses devices.approve/ignore, so the same
  // MAC/serial dedupe and per-item audit apply). Idempotent — anything already decided is skipped, not re-run. Either a
  // list of ids or a {status:'new', type?, site?, scope_id?} filter. 'merge-skip' approves only results with no strong
  // CMDB duplicate, leaving the ambiguous ones for manual merge. Writes ONE audit summary on top of the per-item lines.
  const BULK_MAX = 1000;
  function bulkResults(body, who) {
    const b = body && typeof body === 'object' ? body : {};
    const action = b.action;
    if (!['approve', 'ignore', 'merge-skip'].includes(action)) throw bad("action must be 'approve', 'ignore' or 'merge-skip'");
    let targets;
    if (Array.isArray(b.ids) && b.ids.length) {
      if (b.ids.length > BULK_MAX) throw bad(`at most ${BULK_MAX} devices per bulk action`, 409);
      const seen = {};
      targets = b.ids.map((x) => String(x)).filter((id) => (seen[id] ? false : (seen[id] = true))).map((id) => devices.get(id)).filter(Boolean);
    } else {
      const f = b.filter && typeof b.filter === 'object' ? b.filter : {};
      targets = devices.list((d) => d.status === 'new' && (!f.type || d.type === f.type) && (!f.site || d.site === f.site) && (!f.scope_id || d.scope_id === f.scope_id));
      if (targets.length > BULK_MAX) throw bad(`${targets.length} devices match — narrow the filter (at most ${BULK_MAX} per bulk action)`, 409);
    }
    const reason = action === 'ignore' ? String((b.reason == null ? '' : b.reason)).trim() : null;
    if (action === 'ignore' && reason.length < 3) throw bad('a reason is required to ignore devices (min 3 characters)');
    const out = { action, requested: targets.length, approved: 0, ignored: 0, skipped: 0, errors: [], asset_ids: [] };
    for (const d of targets) {
      if (!d || d.status !== 'new') { out.skipped++; continue; }
      try {
        if (action === 'ignore') { devices.ignore(d.id, reason, who); out.ignored++; }
        else {
          if (action === 'merge-skip' && (devices.duplicates(d) || []).some((x) => x.strength === 'strong')) { out.skipped++; continue; }
          const r = devices.approve(d.id, who); out.approved++; if (r.asset_id) out.asset_ids.push(r.asset_id);
        }
      } catch (e) { out.errors.push({ id: d.id, error: scrubber.text(e && e.status && e.status < 500 ? e.message : 'internal error') }); }
    }
    after();
    try { bridgeRogues(); } catch { /* best effort */ }
    A(who, `discovery.bulk.${action}`, 'results', { requested: out.requested, approved: out.approved, ignored: out.ignored, skipped: out.skipped, errors: out.errors.length, by: Array.isArray(b.ids) && b.ids.length ? 'selection' : 'filter', filter: b.filter || null });
    out.asset_ids = out.asset_ids.slice(0, 50);
    return out;
  }

  // ---------------- Hyper-V report ingestion ----------------
  // opts.untrusted: report arrived on the agent gateway (agent key, not an admin) → observations are flagged untrusted
  function ingestHyperv(body, who, opts = {}) {
    if (settings().methods.hyperv === false) throw bad('Hyper-V ingestion is disabled globally', 409);
    const rep = hypervM.normReport(body);
    let scope = null;
    if (opts.scope_id) { scope = needScope(opts.scope_id); if (!scope.methods.hyperv || !scope.methods.hyperv.enabled) throw bad('Hyper-V is not enabled on this scope', 409); }
    else if (rep.host.ip) scope = scopesCol.all((s) => s.status === 'active' && s.methods.hyperv && s.methods.hyperv.enabled && ip4.contains(s.targets, rep.host.ip))[0] || null;
    if (!scope) throw bad('no active scope with Hyper-V enabled covers this host (send host.ip inside a scope, or import with scope_id)', 409);
    const ctx = { scope_id: scope.id, site: scope.site, vlan: scope.vlan, at: rep.collected_at };
    const untrusted = opts.untrusted === true;
    devices.observe({ method: 'hyperv', untrusted, ip: rep.host.ip, hostname: rep.host.name, fqdn: rep.host.fqdn, os: rep.host.os, uid: `hyperv-host:${rep.host.name.toLowerCase()}`, extra: { hyperv: { kind: 'host' } } }, ctx);
    let n = 0;
    for (const v of rep.vms) { if (devices.observe({ method: 'hyperv', untrusted, ips: v.ips, macs: v.macs, hostname: v.name, os: v.os, uid: v.id ? `hyperv:${v.id.toLowerCase()}` : `hyperv:${rep.host.name.toLowerCase()}/${(v.name || '').toLowerCase()}`, extra: { hyperv: { kind: 'vm', host: rep.host.name, state: v.state, generation: v.generation } } }, ctx)) n++; }
    hvHostsCol.put({ id: rep.host.name.toLowerCase(), host: rep.host.name, fqdn: rep.host.fqdn, ip: rep.host.ip, os: rep.host.os, scope_id: scope.id, site: scope.site || null,
      vms: n, via: untrusted ? 'agent' : 'import', by: who.user, at: new Date().toISOString(), collected_at: rep.collected_at || null });
    A(who, 'discovery.hyperv.report', rep.host.name, { scope_id: scope.id, vms: n, untrusted });
    return { ok: true, scope_id: scope.id, host: rep.host.name, vms: n };
  }

  // the Hyper-V hosts that have reported (Integration Hub): newest first; no credentials are involved
  function hypervHosts() { return { hosts: hvHostsCol.all().sort((a, b) => String(b.at).localeCompare(String(a.at))), scopes: scopesCol.all((s) => s.status === 'active' && s.methods.hyperv && s.methods.hyperv.enabled).map((s) => ({ id: s.id, name: s.name, site: s.site, targets: s.targets })) }; }
  function forgetHypervHost(id, who) {
    const k = String(id || '').toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{0,119}$/.test(k)) throw bad('host must be a Hyper-V host name', 400);
    const row = hvHostsCol.get(k); if (!row) throw bad('no Hyper-V host ' + k + ' has reported', 404);
    hvHostsCol.remove(k); A(who, 'discovery.hyperv.forget', row.host, { scope_id: row.scope_id });
    return { ok: true, host: row.host };
  }

  // ---------------- SIEM connect ----------------
  async function connect(assetId, body, who) { return siem.connect(assetId, body || {}, who); }
  function connections() {
    return assets.all().filter((a) => a.siem && a.siem.source_id).map((a) => ({ asset_id: a.id, name: a.name, mgmt_ip: a.mgmt_ip, site: a.site, type: a.type, source_id: a.siem.source_id, kind: a.siem.kind, state: a.siem.state, via: a.siem.via || null, last_seen: a.siem.last_seen, checked_at: a.siem.checked_at, alert: !!a.siem.alert, connected_at: a.siem.connected_at, connected_by: a.siem.connected_by }));
  }
  function connectCandidates() {
    return assets.all().filter((a) => a.discovery && !(a.siem && a.siem.source_id) && a.status !== 'disposed' && a.status !== 'retired').map((a) => { const k = siem.kindFor(a); return { asset_id: a.id, name: a.name, mgmt_ip: a.mgmt_ip, site: a.site, class: a.discovery.class, suggested_kind: k.kind, reason: k.reason }; });
  }

  // ---------------- SIEM log-coverage confirmation ----------------
  // For every live asset, confirm it is actually sending logs to the SIEM: match it to a SIEM source by IP, then
  // hostname, then MAC (reusing the existing SIEM link in siem.js — no duplicate connection), and derive a per-asset
  // status: 'covered' (source + recent events), 'silent' (source but stale), 'absent' (no source) or 'unknown' (SIEM
  // unreachable). Read-only cross-service and tolerant. Cached for the sync findings provider + the dashboard.
  let lastCoverage = null;
  const macNorm = (m) => { const h = String(m || '').toLowerCase().replace(/[^0-9a-f]/g, ''); return h.length === 12 ? h.match(/.{2}/g).join(':') : null; };
  function assetHosts(a) {
    const out = [];
    for (const v of [a.name, a.hostname, a.fqdn]) { const s = String(v || '').toLowerCase().trim(); if (s) { out.push(s); if (s.indexOf('.') > 0) out.push(s.split('.')[0]); } }
    return out;
  }
  function assetMacs(a) {
    const out = []; const add = (m) => { const n = macNorm(m); if (n) out.push(n); };
    add(a.mac);
    for (const sg of a.sources || []) for (const k of sg.keys || []) if (typeof k === 'string' && k.indexOf('mac:') === 0) add(k.slice(4));
    return out;
  }
  function normSource(s) {
    const ip = s.match_ip || s.ip || (s.match && s.match.ip) || null;
    const hosts = []; for (const v of [s.host, s.hostname, s.match && s.match.host, s.name]) { const t = String(v || '').toLowerCase().trim(); if (t) hosts.push(t); }
    const macs = []; for (const v of [s.mac, s.match && s.match.mac].concat(Array.isArray(s.macs) ? s.macs : [])) { const n = macNorm(v); if (n) macs.push(n); }
    return { id: s.id, kind: s.kind || null, state: s.state || null, last_seen: s.last_seen != null ? s.last_seen : null, ip: ip ? String(ip) : null, hosts, macs };
  }
  function sourceRecent(s, now, silentMs) {
    if (s.state === 'receiving') return true;
    if (s.last_seen == null) return false;
    const t = typeof s.last_seen === 'number' ? s.last_seen : Date.parse(s.last_seen);
    return Number.isFinite(t) && now - t <= silentMs;
  }
  function covItem(a, src, status, by) {
    const disc = a.discovery || {};
    const lc = a.log_collection || {};
    return { asset_id: a.id, name: a.name || null, mgmt_ip: a.mgmt_ip || null, type: a.type || null, site: a.site || null, is_server: a.type === 'server' || !!(a.discovery && a.discovery.class === 'server'), status, source_id: src ? src.id : (a.siem && a.siem.source_id) || null, source_kind: src ? src.kind : (a.siem && a.siem.kind) || null, last_seen: src && src.last_seen != null ? (typeof src.last_seen === 'number' ? new Date(src.last_seen).toISOString() : src.last_seen) : null, matched_by: by,
      // classification hints for the SIEM auto-onboarding (sentra-siem engine/onboard/auto-onboard.js)
      vendor: disc.vendor || a.vendor || null, os: disc.os || a.os || null, class: disc.class || null, is_dc: !!disc.is_dc, hostname: a.hostname || a.fqdn || null,
      asset_status: a.status || null, approved: true, siem_site: siem.siteMap[a.site] || null, suggested_kind: siem.kindFor(a).kind || null,
      // an administrator stopped log collection for this asset in the inventory → never auto-onboard it again
      auto_onboard: lc.state !== 'stopped' };
  }
  function summarizeCov(per) {
    const s = { total: per.length, covered: 0, silent: 0, absent: 0, unknown: 0 };
    for (const p of per) s[p.status] = (s[p.status] || 0) + 1;
    return s;
  }
  async function logCoverage(now = Date.now()) {
    const live = assets.all().filter((a) => a.status !== 'disposed' && a.status !== 'retired');
    const silentMs = (siem.silentMinutes() || 60) * 60000;
    const got = await siem.fetchSources(now);
    let per;
    if (!got.ok) {
      per = live.map((a) => covItem(a, null, 'unknown', null));
      lastCoverage = { ok: false, siem_reachable: false, error: got.error || 'unreachable', summary: summarizeCov(per), assets: per, generated_at: new Date(now).toISOString() };
      return lastCoverage;
    }
    const srcs = got.sources.map(normSource);
    // per-host view: every machine that itself sent logs (SIEM GET /reporting-hosts). Precise for servers that share
    // one agent or syslog source - the source can be busy while one of its servers has gone quiet. Older SIEM: skipped.
    const repByHost = new Map(); const repByIp = new Map();
    try {
      const rh = await siem.call('GET', '/reporting-hosts?hours=168', { user: 'system:itam-discovery', role: 'viewer' });
      if (rh && rh.status === 200 && rh.json && Array.isArray(rh.json.hosts)) for (const h of rh.json.hosts) {
        const r = { id: h.src_id || null, kind: null, last_seen: h.last_seen || null, host: String(h.host || '').toLowerCase() };
        if (r.host) { repByHost.set(r.host, r); if (r.host.indexOf('.') > 0 && !repByHost.has(r.host.split('.')[0])) repByHost.set(r.host.split('.')[0], r); }
        if (h.ip && !repByIp.has(h.ip)) repByIp.set(h.ip, r);
      }
    } catch (e) { /* SIEM without /reporting-hosts - source matching below still applies */ }
    const byIp = new Map(); const byHost = new Map(); const byMac = new Map(); const byId = new Map();
    for (const s of srcs) { if (s.ip) byIp.set(s.ip, s); for (const h of s.hosts) if (!byHost.has(h)) byHost.set(h, s); for (const m of s.macs) if (!byMac.has(m)) byMac.set(m, s); byId.set(s.id, s); }
    per = live.map((a) => {
      let s = null; let by = null;
      if (a.siem && a.siem.source_id && byId.has(a.siem.source_id)) { s = byId.get(a.siem.source_id); by = 'source'; }
      if (!s && a.mgmt_ip && byIp.has(a.mgmt_ip)) { s = byIp.get(a.mgmt_ip); by = 'ip'; }
      if (!s) { for (const h of assetHosts(a)) if (byHost.has(h)) { s = byHost.get(h); by = 'hostname'; break; } }
      if (!s) { for (const m of assetMacs(a)) if (byMac.has(m)) { s = byMac.get(m); by = 'mac'; break; } }
      let hs = null;
      for (const h of assetHosts(a)) if (repByHost.has(h)) { hs = repByHost.get(h); break; }
      if (!hs && a.mgmt_ip && repByIp.has(a.mgmt_ip)) hs = repByIp.get(a.mgmt_ip);
      const hostOk = !!(hs && sourceRecent(hs, now, silentMs));
      const own = !!(s && by === 'source');   // the asset's own source: its health stands on its own
      if (hs && (hostOk || !own || !sourceRecent(s, now, silentMs))) return covItem(a, hs, hostOk ? 'covered' : 'silent', 'host-logs');
      const status = !s ? 'absent' : (sourceRecent(s, now, silentMs) ? 'covered' : 'silent');
      return covItem(a, s, status, by);
    });
    lastCoverage = { ok: true, siem_reachable: true, summary: summarizeCov(per), assets: per, generated_at: new Date(now).toISOString() };
    if (findings) { try { findings.syncKinds(['log_coverage_gap'], SYSTEM); } catch (e) { slog.error('discovery: log-coverage findings sync failed', { err: e.message }); } }
    return lastCoverage;
  }
  // sync findings provider (reads the cached coverage): a discovered SERVER with no SIEM source is a log-coverage gap
  function coverageFindings() {
    if (!lastCoverage || !lastCoverage.ok) return [];
    return lastCoverage.assets.filter((p) => p.status === 'absent' && p.is_server).map((p) => ({
      key: `log_coverage_gap:${p.asset_id}`, kind: 'log_coverage_gap', severity: 'medium', asset_id: p.asset_id, label: 'Discovery',
      title: `No SIEM logs from server: ${p.name || p.mgmt_ip || p.asset_id}`,
      detail: 'This server is in the inventory but no SIEM log source matches it by IP, host name or MAC. Onboard it to the SIEM so its logs are collected (Asset Discovery > Results > Onboard to SIEM).',
      evidence: { mgmt_ip: p.mgmt_ip, site: p.site, type: p.type },
    }));
  }
  if (findings && findings.addProvider) findings.addProvider(coverageFindings);

  // ---------------- dashboard ----------------
  function dashboard() {
    const live = assets.all().filter((a) => a.status !== 'disposed' && a.status !== 'retired');
    const connected = live.filter((a) => a.siem && a.siem.source_id);
    const all = devices.list();
    const byStatus = { new: 0, approved: 0, ignored: 0, merged: 0 }; const byType = {}; const bySite = {};
    for (const d of all) { byStatus[d.status] = (byStatus[d.status] || 0) + 1; byType[d.type] = (byType[d.type] || 0) + 1; const s = d.site || '(none)'; bySite[s] = (bySite[s] || 0) + 1; }
    const finished = runsCol.all((r) => ['finished', 'stopped_window', 'cancelled'].includes(r.status)).sort((a, b) => (a.started_at < b.started_at ? 1 : -1));
    const last = finished[0] || null;
    const rogue = rogueDevices();
    const scopes = scopesCol.all((s) => s.status !== 'archived');
    const pending = scopes.filter((s) => scopesM.ACTIVE.some((k) => s.methods[k] && s.methods[k].enabled) && !scopesM.gateOpen(s));
    return {
      assets: { total: live.length, connected: connected.length, not_connected: live.length - connected.length, silent: connected.filter((a) => a.siem.alert).length },
      devices: { total: all.length, by_status: byStatus, by_type: byType, by_site: bySite },
      new_since_last_scan: last ? all.filter((d) => d.first_seen >= last.started_at).length : all.length,
      last_scan: last ? { id: last.id, scope_id: last.scope_id, scope: last.scope_name, status: last.status, started_at: last.started_at, finished_at: last.finished_at, devices_seen: last.devices_seen, devices_new: last.devices_new } : null,
      rogue: { count: rogue.length, items: rogue.slice(0, 25) },
      scopes: { total: scopes.length, active: scopes.filter((s) => s.status === 'active').length, gate_pending: pending.map((s) => ({ id: s.id, name: s.name, site: s.site })) },
      running: [...active.values()].map((e) => runView(e.run)),
      next_runs: scopes.filter((s) => s.status === 'active' && s.next_run).map((s) => ({ scope_id: s.id, name: s.name, at: new Date(s.next_run).toISOString(), schedule: sched.label(s.schedule) })).sort((a, b) => (a.at < b.at ? -1 : 1)).slice(0, 10),
      siem: { configured: siem.configured(), silent_minutes: siem.silentMinutes(), last_health: siem.lastHealth() },
      log_coverage: lastCoverage ? lastCoverage.summary : null,
      vault: { available: vault.available(), reason: vault.available() ? null : vault.unavailableReason() },
      methods: settings().methods,
      generated_at: new Date().toISOString(),
    };
  }

  // ---------------- scheduler + health ----------------
  let timer = null; let healthTimer = null;
  function tick(now = Date.now()) {
    const started = [];
    for (const s of scopesCol.all((x) => x.status === 'active' && x.next_run && x.next_run <= now)) {
      if ([...active.values()].some((e) => e.run.scope_id === s.id)) continue;
      if (active.size >= settings().max_concurrent_runs) break; // capacity: retried on the next tick
      if (s.window && !sched.inWindow(s.window, now) && !scopesM.allowedMethods(s, settings().methods).run.some((m) => !scopesM.ACTIVE.includes(m))) { scopesCol.patch(s.id, (x) => { x.next_run = sched.nextRun(x.schedule, now); }); continue; }
      try { const r = startRun(s.id, { trigger: 'schedule', who: { user: 'system:scheduler', role: 'system', ip: '' } }); started.push(r.id); } catch (e) { slog.warn('discovery: scheduled run not started', { scope: s.id, err: e.message }); }
      scopesCol.patch(s.id, (x) => { x.next_run = sched.nextRun(x.schedule, now); });
    }
    return started;
  }
  function start() {
    const tickMs = Math.max(5, Number(dc.scheduler_tick_s) || 30) * 1000;
    timer = setInterval(() => { try { tick(); } catch (e) { slog.error('discovery: scheduler tick failed', { err: e.message }); } }, tickMs);
    timer.unref();
    const hMs = Math.max(1, Number((dc.siem || {}).health_interval_min) || 5) * 60000;
    healthTimer = setInterval(() => { if (siem.configured()) siem.health().then(() => logCoverage()).catch((e) => slog.warn('discovery: SIEM health failed', { err: e.message })); }, hMs);
    healthTimer.unref();
  }
  async function stop() {
    if (timer) clearInterval(timer);
    if (healthTimer) clearInterval(healthTimer);
    for (const e of active.values()) e.cancelled = true;
    await Promise.all([...active.values()].map((e) => e.promise.catch(() => { /* a run's own failure is recorded on the run; here we only wait for it to stop */ })));
  }

  function auditTail(limit) { return store.auditTail(Math.min(Number(limit) || 200, 2000), (r) => /^discovery\./.test(r.action || '') || r.action === 'findings.sync'); }

  return {
    settings, updateSettings,
    listScopes, getScope: (id) => scopeView(needScope(id)), createScope, updateScope, setScopeStatus, completeChecklist, revokeChecklist,
    listRuns, getRun, startRun, cancelRun, wait,
    credentials: () => vault.list(), credential: (id) => vault.get(id), createCredential, updateCredential, deleteCredential, testCredential,
    results, result, approve, ignore, restore, merge, bulkResults, rogueDevices,
    ingestHyperv, hypervHosts, forgetHypervHost, connect, connections, connectCandidates, logCoverage, health: (now) => siem.health(now),
    dashboard, tick, start, stop, auditTail,
    kinds: () => ({ table: KIND_TABLE.map((r) => ({ when: r.when, kind: r.kind })), connectable: CONNECTABLE }),
    credentialKinds: () => Object.entries(vault.KINDS).map(([k, v]) => ({ kind: k, secret_fields: Object.keys(v.secret), target_fields: Object.keys(v.target), future: !!v.future })),
    sites: () => sites.slice(), scrubber, vault, devices, siem,
    trustList: (q) => trust.list(q), trustDecide: (ids, action, who) => trust.decide(ids, action, who),
    loginStatus: () => invRun({ op: 'version' }),
  };
}

module.exports = { createDiscovery, SYSTEMS_OF_RECORD };
