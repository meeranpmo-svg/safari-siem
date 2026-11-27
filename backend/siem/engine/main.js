// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// the organisation SIEM engine entry point: config → ClickHouse → pipeline → collectors → detector → alerts → API.
//   node engine/main.js            (systemd: ExecStart=/opt/sentra-ai/node/bin/node /opt/sentra-siem/engine/main.js)
// Optional modules (detect/, soc/) are loaded when present; the engine starts without them and logs what is missing.
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig, VERSION } = require('./config');
const { createLogger } = require('./log');
const { createCH } = require('./store/clickhouse');
const { createSpool } = require('./store/spool');
const { createWriter } = require('./store/writer');
const { createPipeline } = require('./pipeline');
const { createParser } = require('./parse');
const { createEnricher } = require('./enrich');
const { createSourceTracker } = require('./collect/tracker');
const { createSyslog } = require('./collect/syslog');
const { createHttpIngest } = require('./collect/http-ingest');
const { createApi } = require('./api/server');
const { createSearch } = require('./api/search');
const { createTail } = require('./api/tail');
const coreRoutes = require('./api/routes');
const errorsReg = require('./util/errors');

function tryRequire(rel, log, status) {
  const file = path.join(__dirname, rel);
  if (!fs.existsSync(file)) { log.warn(`optional module not present: ${rel} — starting without it`); if (status) status.absent(rel); return null; }
  try { return require(file); } catch (e) { log.error(`optional module failed to load: ${rel} — starting without it`, { err: e }); if (status) status.loadFailed(rel, e); return null; }
}

function readRuleFiles(dir, log) {
  const rules = [];
  if (!dir || !fs.existsSync(dir)) return rules;
  for (const f of fs.readdirSync(dir).sort()) {
    if (!f.endsWith('.json')) continue;
    try {
      const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
      const list = Array.isArray(j) ? j : Array.isArray(j.rules) ? j.rules : [j];
      for (const r of list) if (r && r.id) rules.push(r);
    } catch (e) { log.error('rule file invalid, skipped', { file: f, err: e.message }); }
  }
  return rules;
}

async function main({ configPath, installSignals = true } = {}) {
  const cfg = loadConfig({ configPath });
  const log = createLogger({ level: cfg.log_level, name: 'sentra-siem' });
  // every failure in one register: background jobs of every module, 5xx answers, the process safety net (util/errors.js)
  const errors = errorsReg.shared(); errors.setLog(log);
  log.info('starting', { version: VERSION, node: process.version, config: cfg._paths.config, config_found: cfg._paths.config_found, data_dir: cfg.data_dir });
  if (!cfg._paths.config_found) log.warn('config file not found — running with built-in defaults', { path: cfg._paths.config });
  fs.mkdirSync(cfg.state_dir, { recursive: true });
  fs.mkdirSync(cfg.spool_dir, { recursive: true });
  const detStateFile = path.join(cfg.state_dir, 'detector-state.json');

  // --- store
  const ch = createCH({ url: cfg.clickhouse.url, user: cfg.clickhouse.user, password: cfg.clickhouse.password, database: cfg.clickhouse.database, timeout_ms: cfg.clickhouse.timeout_ms, log: log.child({ mod: 'clickhouse' }) });
  if (await ch.ping()) log.info('clickhouse reachable', { url: cfg.clickhouse.url });
  else log.warn('clickhouse NOT reachable at startup — events will be spooled until it is', { url: cfg.clickhouse.url });
  const spool = createSpool({ dir: cfg.spool_dir, maxMb: cfg.spool_max_mb, log: log.child({ mod: 'spool' }) });
  const w = cfg.writer;
  const writer = createWriter({ ch, spool, log: log.child({ mod: 'writer' }), stateDir: cfg.state_dir, node: cfg.node_name, batchSize: w.batch_size, flushMs: w.flush_ms, maxInflight: w.max_inflight, maxQueue: w.max_queue, statsFlushMs: w.stats_flush_ms });
  await writer.resumeFromStore();

  // --- core services
  const pipeline = createPipeline({ log: log.child({ mod: 'pipeline' }) });
  const parser = createParser({ log: log.child({ mod: 'parse' }), config: cfg });
  const tracker = createSourceTracker();
  const tail = createTail({ maxClients: cfg.tail.max_clients, maxEps: cfg.tail.max_eps_per_client, log: log.child({ mod: 'tail' }) });
  const search = createSearch({ ch, config: cfg, log: log.child({ mod: 'search' }) });

  // --- optional SOC / detection modules
  let state = null;
  let alerts = null;
  let cases = null;
  let detector = null;
  const stateMod = tryRequire('soc/state.js', log);
  if (stateMod && typeof stateMod.createState === 'function') {
    try { state = await stateMod.createState({ dir: cfg.state_dir, log: log.child({ mod: 'state' }) }); } catch (e) { log.error('soc/state.js createState failed', { err: e }); }
  }
  const alertsMod = tryRequire('soc/alerts.js', log);
  if (alertsMod && typeof alertsMod.createAlerts === 'function') {
    try { alerts = await alertsMod.createAlerts({ state, ch, log: log.child({ mod: 'alerts' }), config: cfg }); } catch (e) { log.error('soc/alerts.js createAlerts failed', { err: e }); }
  }
  const casesMod = tryRequire('soc/cases.js', log);
  if (casesMod && typeof casesMod.createCases === 'function') {
    try { cases = await casesMod.createCases({ state, ch, alerts, log: log.child({ mod: 'cases' }), config: cfg, sla: cfg.sla }); } catch (e) { log.error('soc/cases.js createCases failed', { err: e }); }
  }
  let ueba = null;
  const uebaMod = tryRequire('ueba/index.js', log);
  if (uebaMod && typeof uebaMod.createUeba === 'function') {
    try { ueba = uebaMod.createUeba({ state, ch, alerts, config: cfg, settings: cfg.ueba, search, log: log.child({ mod: 'ueba' }) }); } catch (e) { log.error('ueba/index.js createUeba failed', { err: e }); }
  }
  let intel = null;
  const intelMod = tryRequire('detect/intel.js', log);
  if (intelMod && typeof intelMod.createIntel === 'function') {
    const dir = (cfg.detect && cfg.detect.intel_dir) || path.join(cfg.data_dir, 'intel');
    try { fs.mkdirSync(dir, { recursive: true }); intel = await intelMod.createIntel({ dir, log: log.child({ mod: 'intel' }) }); } catch (e) { log.error('detect/intel.js createIntel failed', { err: e }); }
  }
  let scheduled = null;
  const detectMod = tryRequire('detect/engine.js', log);
  if (detectMod && typeof detectMod.createDetector === 'function') {
    const rulesDir = cfg.detect.rules_dir || path.join(__dirname, 'detect', 'rules');
    let rules;
    const rulesetMod = tryRequire('detect/ruleset.js', log);
    try {
      rules = rulesetMod && typeof rulesetMod.effectiveRules === 'function'
        ? rulesetMod.effectiveRules(state, rulesetMod.loadBuiltinRules(rulesDir))  // built-ins + admin overrides/custom rules
        : readRuleFiles(rulesDir, log);
    } catch (e) {
      log.error('rule pack failed to load — falling back to a tolerant loader', { err: e });
      rules = readRuleFiles(rulesDir, log);
    }
    const onAlert = (a) => {
      try {
        if (alerts && typeof alerts.raise === 'function') {
          const r = alerts.raise(a);
          if (r && typeof r.then === 'function') r.catch((e) => log.error('alerts.raise failed', { err: e, rule_id: a && a.rule_id }));
        } else log.warn('alert raised but soc/alerts.js is not loaded', { rule_id: a && a.rule_id, summary: a && a.summary });
      } catch (e) { log.error('alerts.raise failed', { err: e, rule_id: a && a.rule_id }); }
    };
    try {
      detector = await detectMod.createDetector({ rules, now: Date.now, onAlert, log: log.child({ mod: 'detect' }), intel });
      const st = detector.stats();
      log.info('detector loaded', { rules: rules.length, compiled: st.rules_loaded, load_errors: (st.load_errors || []).length, rules_dir: rulesDir });
      if (st.load_errors && st.load_errors.length) log.warn('some rules failed to compile', { errors: st.load_errors.slice(0, 20) });
      // restore learned state (new_value baselines, open windows) saved at the last shutdown
      if (typeof detector.importState === 'function' && fs.existsSync(detStateFile)) {
        try { detector.importState(JSON.parse(fs.readFileSync(detStateFile, 'utf8'))); log.info('detector state restored'); } catch (e) { log.warn('detector state not restored', { err: e.message }); }
      }
    } catch (e) { log.error('detect/engine.js createDetector failed', { err: e }); }
    const schedMod = tryRequire('detect/scheduled.js', log);
    if (schedMod && typeof schedMod.createScheduled === 'function') {
      try {
        scheduled = schedMod.createScheduled({ rules, search, onAlert, log: log.child({ mod: 'scheduled' }) });
        if (typeof scheduled.load === 'function') scheduled.load(rules);
        if (typeof scheduled.start === 'function') scheduled.start();
      } catch (e) { log.error('detect/scheduled.js createScheduled failed', { err: e }); scheduled = null; }
    }
  }

  // --- optional Data Optimizer (telemetry pipeline management: filter/route/archive before the hot store)
  let dataopt = null;
  const dataoptMod = (cfg.dataopt && cfg.dataopt.enabled === false) ? null : tryRequire('dataopt/index.js', log);
  if (dataoptMod && typeof dataoptMod.createDataOpt === 'function') {
    try {
      dataopt = dataoptMod.createDataOpt({ ch, state, config: cfg, log: log.child({ mod: 'dataopt' }), get detector() { return detector; }, ueba, writer, dir: cfg.data_dir });
      log.info('dataopt loaded', dataopt.health ? { active_pipeline: dataopt.health().active_pipeline } : {});
    } catch (e) { log.error('dataopt/index.js createDataOpt failed', { err: e }); dataopt = null; }
  }

  // --- optional AD identity (engine/ad): read-only LDAPS sync → enrichment fields, rules SENTRA-AD-*, /identity API.
  // The store is created even when ad.enabled is false (the API then reports the configuration problems).
  let identity = null;
  let adSync = null;
  const idMod = tryRequire('ad/identity.js', log);
  const adSyncMod = idMod ? tryRequire('ad/sync.js', log) : null;
  if (idMod && adSyncMod) {
    try {
      const a = cfg.ad || {};
      identity = idMod.createIdentity({ file: path.join(cfg.state_dir, 'ad-identity.json'), dormantDays: a.dormant_days, servicePatterns: a.service_account_patterns, netbios: a.netbios, privilegedNames: a.privileged_groups });
      if (a.enabled && identity.load()) log.info('ad identity restored from the last sync', identity.meta());
      adSync = adSyncMod.createAdSync({ config: cfg, identity, ch, pipeline, log: log.child({ mod: 'ad' }) });
    } catch (e) { log.error('ad identity failed to initialise', { err: e }); identity = null; adSync = null; }
  }

  // --- pipeline: enrich → source stats → detect → store → live tail
  // Detection sees EVERY event before the optimizer touches storage (the optimizer only affects what is stored /
  // archived / forwarded, never what the real-time detector evaluates).
  pipeline.use(createEnricher({ config: cfg, identity: cfg.ad && cfg.ad.enabled ? identity : null }), 'enrich');
  pipeline.use(tracker.stage, 'sources');
  // agent heartbeats (tag "heartbeat") are bookkeeping, not security events: detection skips them
  if (detector && typeof detector.onEvent === 'function') pipeline.use((ev) => { if (ev.action !== 'agent-heartbeat' && ev.action !== 'agent-hardening' && ev.action !== 'agent-pii') detector.onEvent(ev); }, 'detect');
  // the Windows agent's daily baseline-hardening snapshot: the latest per host, for IT Asset Management's baseline scan
  const hardening = require('./hardening/store').createHardeningStore({ file: path.join(cfg.state_dir, 'hardening-snapshots.json'), log: log.child({ mod: 'hardening' }) });
  pipeline.use(hardening.stage, 'hardening');
  // the agent's file-share personal-data scan (counts per file): the latest per host, for the PDPL Data Catalog in IT Asset Management
  const piiShares = require('./hardening/store').createHardeningStore({ file: path.join(cfg.state_dir, 'pii-fileshares.json'), log: log.child({ mod: 'pii' }), action: 'agent-pii', label: 'pii', maxHosts: 2000 });
  pipeline.use(piiShares.stage, 'pii');
  pipeline.use(dataopt ? (ev) => dataopt.router.route(ev) : (ev) => writer.push(ev), 'store');
  pipeline.use(tail.stage, 'tail');
  const tickTimer = detector && typeof detector.tick === 'function'
    ? setInterval(errors.guard('detect.tick', () => detector.tick(Date.now())), 1000)
    : null;
  // UEBA scheduler: baselines nightly (SQL aggregation), detectors every few minutes (recent events vs baseline)
  let uebaDetectTimer = null; let uebaBaselineTimer = null;
  if (ueba) {
    const us = (cfg.ueba || {});
    const detectMs = Math.max(60000, (us.detect_interval_min || 5) * 60000);
    const baselineMs = Math.max(3600000, (us.baseline_interval_h || 24) * 3600000);
    uebaDetectTimer = setInterval(errors.guard('ueba.detectors', () => ueba.runDetectors(Date.now())), detectMs);
    uebaBaselineTimer = setInterval(errors.guard('ueba.baselines', () => ueba.runBaselines(Date.now())), baselineMs);
    if (uebaDetectTimer.unref) uebaDetectTimer.unref();
    if (uebaBaselineTimer.unref) uebaBaselineTimer.unref();
    // build baselines once at startup (non-blocking) so detectors have something to compare against
    errors.guard('ueba.baselines', () => ueba.runBaselines(Date.now()))();
  }

  // --- collectors
  const syslog = createSyslog({ config: cfg, parser, pipeline, log: log.child({ mod: 'syslog' }) });
  const ingest = createHttpIngest({ config: cfg, parser, pipeline, log: log.child({ mod: 'ingest' }), getRelayConfig: dataopt ? () => dataopt.relayConfig() : null });
  const m365Mod = require('./collect/m365');
  let m365 = m365Mod.start({ config: cfg, parser, pipeline, log: log.child({ mod: 'm365' }), stateDir: cfg.state_dir });
  const cfMod = require('./collect/cloudflare');
  let cloudflare = cfMod.start({ config: cfg, parser, pipeline, log: log.child({ mod: 'cloudflare' }), stateDir: cfg.state_dir });
  const reloadCloudflare = async () => { await cloudflare.stop(); cloudflare = cfMod.start({ config: cfg, parser, pipeline, log: log.child({ mod: 'cloudflare' }), stateDir: cfg.state_dir }); };   // settings changed in the portal
  const cloudflareStats = () => cloudflare.stats();
  const mcMod = require('./collect/mimecast');
  let mimecast = mcMod.start({ config: cfg, parser, pipeline, log: log.child({ mod: 'mimecast' }), stateDir: cfg.state_dir });
  const reloadMimecast = async () => { await mimecast.stop(); mimecast = mcMod.start({ config: cfg, parser, pipeline, log: log.child({ mod: 'mimecast' }), stateDir: cfg.state_dir }); };   // settings changed in the portal
  const mimecastStats = () => mimecast.stats(), mimecastPoll = () => mimecast.pollNow();
  const reloadM365 = async () => { await m365.stop(); m365 = m365Mod.start({ config: cfg, parser, pipeline, log: log.child({ mod: 'm365' }), stateDir: cfg.state_dir }); };   // Exchange Online settings changed in the portal
  const lr = require('./collect/lr').start({ config: cfg, state, log: log.child({ mod: 'lr' }) });

  // --- API
  const api = createApi({
    port: cfg.api.port, host: cfg.api.host, log: log.child({ mod: 'api' }), dataDir: cfg.data_dir, maxBody: cfg.api.max_body_mb * 1024 * 1024,
    proxySecret: cfg.secrets.proxy_secret || null,
    audit: state && typeof state.audit === 'function' ? (e) => state.audit(e) : undefined,
    onError: errors.recordServer,
  });
  // Platform Health: background jobs, latest 5xx and the safety-net counts of the SIEM engine (admin)
  api.route('GET', '/api/soc/platform/errors', (ctx) => { ctx.need('admin'); return errors.view(); });
  // AI use: calls, tokens, refusals and prompt-injection flags of today, per person (util/ai-guard.js) - admin
  api.route('GET', '/api/soc/platform/ai-usage', (ctx) => { ctx.need('admin'); return require('./util/ai-guard').sharedBudget({ log, limits: () => cfg.ai_limits || {} }).view(); });
  coreRoutes.register(api, { ch, config: cfg, log, search, tail, pipeline, writer, spool, syslog, ingest, tracker, parser, get detector() { return detector; }, extras: { m365: () => m365.stats(), lr: () => lr.stats(), cloudflare: () => cloudflare.stats() } });
  ingest.register(api);
  require('./api/lr-import').register(api, { alerts, state, config: cfg, log: log.child({ mod: 'lr-import' }) }); // before soc/routes.js (superset of its /lr/alarms); state+config enable collector-health flood remediation
  const m365Graph = require('./collect/m365-graph').createGraph({ config: cfg, log: log.child({ mod: 'm365-graph' }), stateDir: cfg.state_dir }).start();   // licences / users / Intune / posture for the portal
  const m365Files = require('./collect/m365-files').createFiles({ graph: m365Graph, config: cfg, log: log.child({ mod: 'm365-files' }), stateDir: cfg.state_dir }).start();   // SharePoint / OneDrive personal-data discovery (PDPL)
  const deps = { hardening, piiShares, m365Files, ch, state, detector, alerts, cases, ueba, dataopt, identity, adSync, reloadM365, reloadCloudflare, cloudflareStats, reloadMimecast, mimecastStats, mimecastPoll, m365Graph, extras: { m365: () => m365.stats() }, config: cfg, log, search, intel, scheduled, pipeline, writer, parser, api, tracker, ingest, syslog };
  const routeModules = ['detect/routes.js', 'soc/routes.js'];
  if (dataopt) routeModules.push('dataopt/api.js');
  if (identity) routeModules.push('ad/routes.js');
  routeModules.push('pii/routes.js');          // SharePoint / OneDrive and file-share personal-data discovery (ITAM Data Catalog)
  routeModules.push('collect/m365-files-insights.js');
  routeModules.push('collect/m365-files-activity.js');
  routeModules.push('ops/canary.js');   // SIEM pipeline canary + Pipeline Health: a labelled test line through parse -> pipeline -> detect -> alert -> store every 15 min   // SharePoint & OneDrive activity from the unified audit log (sharing, mass downloads, after hours)   // SharePoint & OneDrive insights over that discovery (exposure, retention, trend)
  routeModules.push('hardening/routes.js');    // baseline-hardening snapshots from the Windows agent (ITAM baseline scan)
  routeModules.push('soc/platform.js');       // "Run backup now" (queues zyb-backup via a systemd path unit) + backup status
  routeModules.push('soc/departments.js');    // threats by AD department (alerts → account / host last logon → department)
  routeModules.push('soc/credposture.js');   // credential encryption evidence (SAMA 3.3.9): sealed secrets, key custody, self-test, transport, disk scan
  routeModules.push('soc/mailstats.js');      // mail volume: sent / received / internal / spam (Email dashboard)
  routeModules.push('soc/webtraffic.js');     // portal traffic from the web server access logs (Portal Traffic page)
  routeModules.push('soc/browsing.js');       // live browsing traffic from the web-filter logs (Browsing Traffic page)
  routeModules.push('soc/flows.js');          // network flows from the firewalls' traffic logs (Network Flows page): summary + drill-down
  routeModules.push('soc/hostmap.js');        // host name → last IP / MAC from DC logons + firewall (ITAM discovery)
  routeModules.push('soc/console.js');       // SOC Console: agent heartbeat / version / queue health, file-integrity changes on watched paths, ingest rate
  routeModules.push('soc/darkweb.js');       // Dark Web Watch: staff accounts in breaches / stealer logs (Have I Been Pwned, provider imports), matched to AD, never a password stored
  routeModules.push('collect/m365-routes.js'); // Microsoft 365 settings + Graph data for the portal
  routeModules.push('collect/m365-insights.js'); // Microsoft 365, Users & Endpoints insights (licences, identities, devices, sign-ins, AI analyst)
  routeModules.push('collect/m365-security.js'); // Microsoft 365 Security: Secure Score, MFA, identity risk, Conditional Access, Defender alerts
  routeModules.push('collect/m365-autoconfig.js'); // Microsoft Security Auto-Configuration: permissions granted (token roles), consent link, grant script, report-only CA templates, AI plan
  routeModules.push('compliance/routes.js'); // SAMA CSF coverage + evidence pack (+ optional push to AI GRC)
  routeModules.push('compliance/sama-intel-routes.js'); // SAMA coverage intelligence: history, regressions, leverage, forecast, AI advisor
  routeModules.push('db-audit/routes.js');   // Oracle health/audit parsers (registered at runtime) + /db/oracle summary (docs/ORACLE.md)
  routeModules.push('integrations/routes.js'); // ITSM: ManageEngine ServiceDesk Plus tickets (docs/MANAGEENGINE.md)
  routeModules.push('onboard/routes.js');    // Connect & Onboard hub: self-service sources/tokens (config.json + secrets.json, hot-reloaded)
  routeModules.push('onboard/collection.js'); // inventory log collection (ITAM per-asset sources) + log-flow assurance (after onboard/routes.js)
  routeModules.push('reports/routes.js');    // Attack Summary (dashboard, HTML, scheduled e-mail) + After-hours monitoring + shared business hours
  routeModules.push('reports/dlp-routes.js'); // DLP analysis + reports over Somansa / CEF DLP incidents (after reports: calendar + SMTP)
  if (state) routeModules.push('afterhours/routes.js');
  if (state) routeModules.push('db-audit/dba-routes.js'); // DBA alert center: thresholds the DBA sets, notifications to the DBA, daily database digest, ORA- error findings (after reports: calendar + SMTP) // After-hours mode: page the on-call, prepare containment as approval requests, morning brief (after reports: calendar + SMTP)
  if (state) routeModules.push('db-audit/statement.js');   // Database Health Statement: evidence for a complaint window (database / server / network verdict), routed to a team as a case
  routeModules.push('db-audit/connections.js');   // Application Connections: apps per database, dropped / refused / timed-out clients, DB links and what their users can change
  routeModules.push('db-audit/mssql-routes.js'); // SQL Server Audit: report over 33205 / 18456 (failed logins, permissions, schema, audit, config, after hours)
  if (state) routeModules.push('soc/mailnotify.js');   // mail team alerts: recipients + send path for IT Asset Management's mail route early warnings (after reports: SMTP)
  if (state) routeModules.push('integrations/apm-routes.js'); // ManageEngine Applications Manager: monitors / alarms beside the Database Dashboard, Poll now, maintenance (Unmanage / Manage) under four-eyes approval
  if (state) routeModules.push('integrations/webtier-routes.js'); // Applications, Web Servers & APIs: APM monitors by tier, 5-minute history, probable-cause hosts, AI advisor (after apm-routes)
  if (state) routeModules.push('integrations/apm-insights.js'); // Applications Manager insights: reliability (MTTR / MTBF), ranked problems, probable-cause hosts, noisy / long-open alarms, hygiene, trend (after webtier-routes)
  routeModules.push('bas/routes.js');
  routeModules.push('xdr/routes.js');        // XDR: one incident per attack across endpoint / identity / network / email / web / data, hunts, beacons        // ATT&CK detection-coverage map + SAFE synthetic detection-validation (no endpoints, no real attacks)
  if (state) routeModules.push('soc/analyst-routes.js'); // Security Operations Overview + Alert Queue (explainable ML priority) + AI SOC analyst (drafts; a person decides) - after xdr
  if (state) routeModules.push('soc/investigate-routes.js'); // Investigations & Cases (workspace, AI brief) + Threat Hunting & Search (saved hunts, rare / first-seen, AI hunt assistant) - after the analyst
  if (state) routeModules.push('soc/views-routes.js'); // User Behaviour insights + AI behaviour assessment, Threat Intelligence sightings + retro-hunt
  if (state) routeModules.push('soc/copilot-routes.js'); // SOC Copilot: conversational agent over the SOC read tools; proposals a person accepts (after analyst / investigate / views)
  if (state) routeModules.push('soc/ai-security-routes.js'); // AI Security: inventory, usage ledger, quality, unusual use, daily guard-rail red team (no model call)
  routeModules.push('dfir/routes.js');       // DFIR: forensic super-timeline + host/user triage over the event store, triage-collection requests (read-only; execution via the response agent)
  if (state) routeModules.push('soc/ircenter-routes.js');
  if (state) routeModules.push('soc/soar-routes.js'); // SOAR - Automated Response: playbook matches with learned confidence, runs to four-eyes approvals, opt-in auto-propose, AI brief // Incident Response Center: incidents by phase, SLA breach risk, similar past cases, AI incident commander (after xdr + dfir)
  if (state) routeModules.push('soc/shadow-ai-routes.js'); // Shadow AI DLP: AI apps in use (web / traffic / DNS logs), sanctioned-AI register (four-eyes), DLP signals to AI, browser-extension ingest (after dlp-routes)
  if (state) routeModules.push('soc/insider-routes.js'); // Insider Risk: UEBA + DLP + approved context per pseudonymised person, four-eyes cases, AI analyst (after dlp-routes)
  if (state) routeModules.push('ui/menuprefs.js'); // portal menu add-on: admin's menu order (shared) + per-user favorites
  if (state) routeModules.push('licence/routes.js');   // platform licence: the signed licence sent by IT Asset Management, verified here; grace then lock for people (ingestion and detection keep running)
  if (state) routeModules.push('aiengine/routes.js'); // AI Engine: Claude / local model on the AI server / off, for every SIEM AI feature (util/ai-backend.js)
  if (state) routeModules.push('approvers/routes.js'); // approver list pushed by IT Asset Management (Roles & Functions): operators who may approve infra / security
  if (state) routeModules.push('netops/routes.js'); // AI Network Engineer: device polling, findings, troubleshooting, AI assistant, change plans
  if (state) routeModules.push('netops/synthetic-routes.js'); // Synthetic Monitoring & Apdex, WLC feed, health by device type (after netops: uses deps.netopsInstance)
  if (state) routeModules.push('collect/webhook-ingest.js');  // inbound webhooks POST /ingest/webhook/<name> (own token + HMAC); admin config /collect/webhooks
  if (state) routeModules.push('sysadmin/routes.js'); // AI Windows Server + Exchange Server Administrators (read-only WinRM checks, health, AI, change plans)
  if (state) routeModules.push('soc/exchange-reports.js'); // Exchange Reports: read-only mailbox inventory, permissions, lists, OWA / ActiveSync, Exchange Online (after sysadmin: uses deps.sysadminInstance, deps.m365Graph)
  if (state) routeModules.push('soc/adchanges-routes.js'); // AD change auditing: AD changes (old -> new), lockout analyzer, policy changes, GPO report snapshots (after sysadmin: read-only gpo_report check)
  if (state) routeModules.push('zscaler/routes.js'); // AI Security Engineer — Zscaler (ZIA + ZPA read-only posture, change plans) — before duty (sets deps.zscalerInstance)
  if (state) routeModules.push('ksc/routes.js');     // AI Endpoint Protection Engineer — Kaspersky Security Center (read-only posture) — before duty (sets deps.kscInstance)
  if (state) routeModules.push('duty/routes.js');    // AI engineers' duty desk: patrol, work items, investigation, change-plan follow-up, verification, shift reports (after netops + sysadmin + zscaler + ksc)
  if (state) routeModules.push('itaudit/routes.js'); // evidence for the AI IT / Cyber Security Auditors: AD, network devices, databases, applications (read-only; after netops + db-audit)
  routeModules.push('collect/cloud-routes.js');
  routeModules.push('collect/mimecast-routes.js');
  if (state) routeModules.push('collect/mimecast-manage.js');   // Mimecast actions: held queue, block / permit sender, release / reject held, block URL - four-eyes, separate app   // Mimecast email security: API 2.0 SIEM batch pull (client ID / secret), status, test, poll now      // Cloud log sources settings: Cloudflare pull (API token), status
  if (state) routeModules.push('collect/cloud-data-routes.js'); // Data Security Posture: read-only discovery of Azure Blob / AWS S3 / OCI Object Storage (region, public, encryption, personal-data counts)
  if (state) routeModules.push('facilities/routes.js'); // Door access: ZKTeco ZKBioSecurity controllers, doors and 24 h door alarms (read only, no person)
  if (state) routeModules.push('printers/routes.js');
  if (state) routeModules.push('ops/questions-routes.js'); // questions from the IT Infrastructure Manager to the DBA / server / Exchange / network teams on flagged problems (last: reads their modules) // Printers: Xerox fleet health over SNMP + YSoft SAFEQ 6 usage reports
  if (state) routeModules.push('netops/fmg-routes.js');
  if (state) routeModules.push('netops/fmg-nac.js');   // Network Access Control from FortiGate device detection: endpoints per MAC, explainable risk, four-eyes authorise / quarantine
  if (state) routeModules.push('soc/ndr.js');
  if (state) routeModules.push('netops/geomap.js');
  if (state) routeModules.push('netops/estate.js');   // Network Estate & Licensing: firewalls, switches, FortiCare / FortiGuard licences, risk and renewals (read; after fmg-routes and netops)   // Network Map: the organisation's offices on a map of Saudi Arabia with firewall connectivity and ML flapping / outage (after fmg-routes: reads the fleet)   // NDR: beaconing, unusual outbound volume, lateral movement, new countries from the traffic logs - each against its own baseline   // FortiGate fleet through FortiManager: health, firmware, licences, SD-WAN link state, four-eyes changes
  if (state) routeModules.push('soc/flow-analytics-routes.js'); // NetFlow Analytics: NetFlow v5/v9, IPFIX, sFlow collector (UDP) + traffic analytics (after netops: speeds; after reports: SMTP)
  // what happened to each route module, kept in a file for the updater's summary (journald may drop lines in a start burst)
  const routeStatus = require('./util/route-status').createRouteStatus({ file: path.join(cfg.state_dir, 'routes-status.json') });
  for (const rel of routeModules) {
    const mod = tryRequire(rel, log, routeStatus);
    if (mod && typeof mod.register === 'function') {
      try { await mod.register(api, deps); log.info('routes registered', { module: rel }); routeStatus.registered(rel); } catch (e) { log.error('route registration failed', { module: rel, err: e }); routeStatus.registerFailed(rel, e); }
    } else if (mod) routeStatus.registerFailed(rel, new Error('the module has no register() function'));
  }
  routeStatus.write();
  await api.start();
  await syslog.start();
  if (adSync) adSync.start();
  log.info('engine started', { api: api.address(), syslog: syslog.stats().listeners, detector: !!detector, scheduled: !!scheduled, intel: !!intel, alerts: !!alerts, cases: !!cases, state: !!state });

  // --- shutdown
  let stopping = null;
  function shutdown(reason) {
    if (stopping) return stopping;
    stopping = (async () => {
      log.info('shutting down', { reason });
      const force = setTimeout(() => { log.error('shutdown timed out — forcing exit'); process.exit(1); }, 25000);
      force.unref();
      const step = async (name, fn) => { try { await fn(); } catch (e) { log.error('shutdown step failed', { step: name, err: e }); } };
      await step('syslog', () => syslog.stop());
      await step('hardening', () => hardening.flush());
      await step('pii', () => piiShares.flush());
      await step('m365-files', () => m365Files.stop());
      await step('api', () => api.stop());
      await step('m365', () => m365.stop());
      await step('m365-graph', () => m365Graph.stop());
      await step('cloudflare', () => cloudflare.stop());
      await step('mimecast', () => mimecast.stop());
      await step('lr', () => lr.stop());
      if (adSync) await step('ad-sync', () => adSync.stop());
      if (deps.compliance && deps.compliance.grcPush) await step('grc-push', () => deps.compliance.grcPush.stop());
      if (deps.integrations && deps.integrations.manageengine) await step('manageengine', () => deps.integrations.manageengine.stop());
      if (deps.reports && deps.reports.schedules) await step('report-scheduler', () => deps.reports.schedules.stop());
      if (deps.afterHoursMode) await step('after-hours-mode', () => deps.afterHoursMode.stop());
      if (deps.dlp) await step('dlp-report', () => deps.dlp.stop());
      if (deps.dbaAlerts) await step('dba-alerts', () => deps.dbaAlerts.stop());
      if (deps.meApm) await step('me-apm', () => deps.meApm.stop());
      if (deps.netflow) await step('netflow', () => deps.netflow.stop());
      if (tickTimer) clearInterval(tickTimer);
      if (uebaDetectTimer) clearInterval(uebaDetectTimer);
      if (uebaBaselineTimer) clearInterval(uebaBaselineTimer);
      if (ueba && typeof ueba.stop === 'function') await step('ueba', () => ueba.stop());
      if (scheduled && typeof scheduled.stop === 'function') await step('scheduled', () => scheduled.stop());
      if (detector && typeof detector.flush === 'function') await step('detector-flush', () => detector.flush());
      if (detector && typeof detector.exportState === 'function') {
        await step('detector-state', () => { fs.writeFileSync(detStateFile + '.tmp', JSON.stringify(detector.exportState())); fs.renameSync(detStateFile + '.tmp', detStateFile); });
      }
      if (dataopt && typeof dataopt.stop === 'function') await step('dataopt', () => dataopt.stop());
      await step('writer', () => writer.close());
      if (alerts && typeof alerts.flushMirror === 'function') await step('alerts-mirror', () => alerts.flushMirror());
      if (alerts && typeof alerts.stop === 'function') await step('alerts', () => alerts.stop());
      if (intel && typeof intel.close === 'function') await step('intel', () => intel.close());
      if (state && typeof state.snapshot === 'function') await step('state-snapshot', () => state.snapshot());
      if (state && typeof state.close === 'function') await step('state-close', () => state.close());
      clearTimeout(force);
      log.info('stopped', { writer: writer.stats() });
    })();
    return stopping;
  }

  if (installSignals) {
    process.on('SIGTERM', () => shutdown('SIGTERM').then(() => process.exit(0)));
    process.on('SIGINT', () => shutdown('SIGINT').then(() => process.exit(0)));
    // safety net: a rejection is logged and counted, the engine keeps running; an uncaught exception flushes (shutdown) and
    // exits 1 so systemd starts a clean process
    errors.processHandlers(process, () => shutdown('uncaughtException'), { graceMs: 26000 });
  }

  return { config: cfg, log, ch, api, syslog, ingest, pipeline, parser, writer, spool, detector, scheduled, intel, alerts, cases, ueba, dataopt, identity, adSync, state, search, tail, shutdown };
}

module.exports = { main };

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(JSON.stringify({ t: new Date().toISOString(), lvl: 'fatal', mod: 'sentra-siem', msg: 'startup failed', err: { message: e.message, stack: e.stack } }) + '\n');
    process.exit(1);
  });
}
