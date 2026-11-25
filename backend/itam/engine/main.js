// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// sentra-itam — the organisation AI-powered IT Asset Management + CMDB. "AI proposes, people approve; nothing is destroyed."
// Listens on 127.0.0.1:9150 behind nginx (/api/itam/ portal + /agent/ gateway). Node >= 20, standard library only.
//   node engine/main.js            (config: /etc/sentra-itam/config.json, secrets: /etc/sentra-itam/secrets.json)
// createApp(opts) is exported for tests: {config, secrets, log, connector?, netopsFetch?, vcenterFetch?} → {start(), stop(), ...}
const path = require('node:path');
const { loadConfig, merge, DEFAULTS, VERSION } = require('./config');
const { createLogger, silent } = require('./log');
const { createStore } = require('./store');
const { createServer } = require('./http');
const { createSettings } = require('./settings');
const { createAssets } = require('./assets');
const { createLicences } = require('./licences');
const { createFindings } = require('./findings');
const { createIngest } = require('./ingest');
const { createStocktake } = require('./stocktake');
const { createReports } = require('./reports');
const { createAgentGateway } = require('./agentgw');
const { createProvider } = require('./ai/provider');
const { createJobs } = require('./ai/jobs');
const { validateOutput } = require('./ai/validate');
const { applyClassify, applyRelate, applyRefresh } = require('./ai/classify');
const { createNetopsConnector } = require('./connectors/netops');
const { createVcenterConnector } = require('./connectors/vcenter');
const importer = require('./import');
const { registerRoutes } = require('./routes');
const { createDiscovery } = require('./discovery');
const { createErrors, registerErrorRoutes } = require('./errors');
const { registerDiscoveryRoutes } = require('./discovery/routes');
const { createScrubber } = require('./discovery/scrub');

function createApp(opts = {}) {
  const config = merge(DEFAULTS, opts.config || {});
  const secrets = opts.secrets || {};
  // one scrubber for the whole process: discovery credentials opened from the vault are masked in EVERY log line
  const scrubber = createScrubber();
  const log = scrubber.wrapLogger(opts.log || silent);
  // every failure in one register: background jobs, 5xx answers, page errors (engine/errors.js, Platform Health shows it)
  const errors = createErrors({ log });
  const dataDir = config.data_dir;
  const store = createStore({ dir: path.join(dataDir, 'state'), log, fsync: !!opts.fsync });
  const audit = (e) => store.audit(Object.assign({ by: 'system', role: '', ip: '' }, e, { detail: e.detail === undefined ? null : e.detail }));

  const settings = createSettings({ store, audit, config, log });
  const assets = createAssets({ store, audit });
  const licences = createLicences({ store, audit, assets });
  const findings = createFindings({ store, audit, settings, assets, getLicences: () => licences.active() });
  const ingest = createIngest({ assets, settings, store, audit, log });
  const stocktake = createStocktake({ store, audit, assets });
  const agentgw = createAgentGateway({ store, audit, config });
  const reports = createReports({ assets, licences, findings, ingest, settings, agentgw });

  // AI provider: 'private' by default (not configured until ai.private_url set); claude provider uses an optional connector.
  const provider = createProvider({ config, secrets, getSettings: settings.get, connector: opts.connector, log });

  // AI job result dispatch → validate the model JSON, store the result, apply advisory output.
  async function onResult(job, prepared, res, meta) {
    // checked by Python too when it answers identically (engine/ai/guard-py.js, step 9j-a); otherwise validate.js, as before
    let out; try { out = await require('./ai/guard-py').guardFor(config).validateOutput(job.feature, res.text, prepared.ctx, res); } catch (e) { out = validateOutput(job.feature, res.text, prepared.ctx, res); }
    const id = `air_${Math.random().toString(16).slice(2, 10)}`;
    const rec = { id, feature: job.feature, at: new Date().toISOString(), call_id: meta.call_id, ai: out.ai, validation: out.validation, ai_label: 'AI — verify' };
    let applied = 0;
    if (out.validation.ok) {
      if (job.feature === 'classify') applied = applyClassify(out, { findings });
      else if (job.feature === 'relate') applied = applyRelate(out, { assets });
      else if (job.feature === 'refresh') applied = applyRefresh(out, { store });
    }
    rec.applied = applied;
    store.collection('ai_results').put(rec);
    audit({ by: job.user, role: job.role, action: `ai.result.${job.feature}`, target: id, detail: { ok: out.validation.ok, applied, warnings: out.validation.warnings.length } });
    return id;
  }
  const jobs = createJobs({ store, provider, getSettings: settings.get, config, log, audit, onResult });

  // connector factories (built with current settings credentials; tests inject fetchImpl via opts)
  const netopsConnector = () => createNetopsConnector({ config, getToken: () => settings.getCredential('netops_token') || secrets.netops_token, fetchImpl: opts.netopsFetch });
  const vcenterConnector = () => createVcenterConnector({ config, getCreds: () => ({ user: settings.getCredential('vcenter_user') || secrets.vcenter_user, pass: settings.getCredential('vcenter_pass') || secrets.vcenter_pass }), fetchImpl: opts.vcenterFetch });

  const discovery = createDiscovery({ config, store, audit, log, assets, ingest, findings, deps: Object.assign({ scrubber }, opts.discoveryDeps || {}) });
  // inventory "Log collection" (enable / pause / resume / stop) over the discovery SIEM link — engine/monitoring-membership.js
  const membership = require('./monitoring-membership').createMembership({ assets, store, audit, discovery, log });

  const srv = createServer({ host: config.api.host, port: config.api.port, prefix: config.api.prefix, agentPrefix: config.api.agent_prefix, proxySecret: secrets.proxy_secret, log, onError: errors.recordServer });
  const app = {
    config, store, audit, log, settings, assets, licences, findings, ingest, stocktake, reports,
    agentgw, provider, jobs, importer, srv, netopsConnector, vcenterConnector, discovery, scrubber, membership, errors,
  };
  registerRoutes(srv, app);
  registerErrorRoutes(srv, app);
  registerDiscoveryRoutes(srv, app);
  require('./asset-delete').registerAssetDelete(srv, app); // admin delete (engine/asset-delete.js)
  require('./desktops').registerDesktops(srv, app); // User Desktops: desktops by branch, patch management, remote support (engine/desktops.js)
  require('./asset-propagate').registerAssetPropagate(srv, app); // an asset added / changed reaches every related list within a minute (engine/asset-propagate.js)
  require('./siem-ip').registerSiemIp(srv, app); // IP / MAC for PCs and servers from the SIEM's logs (engine/siem-ip.js)
  require('./lifecycle').registerLifecycle(srv, app); // end-of-life OS / firmware + isolation with CISO approval (engine/lifecycle.js)
  require('./locations').registerLocations(srv, app); // shared locations / sites, rename everywhere (engine/locations.js)
  require('./roles').registerRoles(srv, app); // job roles + functions for the portal (engine/roles.js)
  require('./core-licensing').registerCoreLicensing(srv, app); // core-based licences: Oracle, Windows Server, VMware (engine/core-licensing.js)
  require('./netops-sync').registerNetopsSync(srv, app); // approved switches / routers / firewalls -> AI Network Engineer (engine/netops-sync.js)
  require('./virt').registerVirt(srv, app); // vCenter + Nutanix Prism platforms -> Asset Discovery (engine/virt.js)
  require('./backup').registerBackup(srv, app); // backup coverage: NetBackup, Veeam, Cohesity (engine/backup.js)
  require('./pentest').registerPentest(srv, app); // AI Penetration Testing Engineer: authorised attack-surface assessment (engine/pentest.js)
  require('./grc').registerGrc(srv, app); // GRC policy register + control automation: the the organisation approved IT policies (engine/grc.js)
  // add-ons that install/add-*.sh used to add one by one: registered here so a fresh server serves every page. The service
  // (node engine/main.js) always turns them on; tests that build the base engine and register a module themselves leave them off.
  if (opts.addons) {
    require('./ownership').registerOwnership(srv, app); // asset IT owner + business owner + business service (engine/ownership.js)
    require('./inventory-facts').registerInventoryFacts(srv, app); // inventory columns: IP, VM host, VM name, power state (engine/inventory-facts.js)
    require('./asset-links').registerAssetLinks(srv, app); // web addresses of assets (apps, management consoles) (engine/asset-links.js)
    require('./storage').registerStorage(srv, app); // storage arrays: NetApp ONTAP, HPE MSA (engine/storage.js)
    require('./support-contracts').registerSupportContracts(srv, app); // support contracts for every vendor (engine/support-contracts.js)
    require('./licence-sync').registerLicenceSync(srv, app); // licence details from the assets + Microsoft 365 (engine/licence-sync.js)
    require('./reconcile').registerReconcile(srv, app); // server & asset reconciliation (engine/reconcile.js)
    require('./service-map').registerServiceMap(srv, app); // Business Services: what runs on every server, business-critical decisions (engine/service-map.js)
    require('./handover').registerHandover(srv, app); // staff handover: leavers' items, successors, access removal, notes, sign-off (engine/handover.js)
    require('./log-enrol').registerLogEnrol(srv, app); // automatic SIEM enrolment of discovered assets (engine/log-enrol.js)
    require('./infra-sync').registerInfraSync(srv, app); // IT Asset Management <-> Infrastructure Automation targets (engine/infra-sync.js)
    require('./sysadmin-sync').registerSysadminSync(srv, app); // Windows / Exchange servers -> AI Server Administrators (engine/sysadmin-sync.js)
    require('./manageengine').registerManageEngine(srv, app); // ManageEngine Endpoint Central + ServiceDesk Plus (engine/manageengine.js)
    require('./cred-posture').registerCredPosture(srv, app); // credential encryption evidence (engine/cred-posture.js)
    require('./db-health').registerDbHealth(srv, app); // Oracle health from Asset Discovery logins → AI Oracle DBA (engine/db-health.js)
    require('./cisco-support').registerCiscoSupport(srv, app); // Cisco support coverage (engine/cisco-support.js)
    require('./virt-capacity').registerVirtCapacity(srv, app); // VMware / Nutanix capacity planning (engine/virt-capacity.js)
    require('./virt-power').registerVirtPower(srv, app); // power control: host / VM restart, shutdown, start as approved plans (engine/virt-power.js)
    require('./desksupport').registerDeskSupport(srv, app); // AI Desktop Support (engine/desksupport.js)
    require('./duty').registerDuty(srv, app); // AI engineers' duty desk: pentest + desktop support (engine/duty.js)
    require('./budget').registerBudget(srv, app); // next-year IT budget, CAPEX / OPEX (engine/budget.js)
    require('./infra-overview').registerInfraOverview(srv, app); // IT Infrastructure Manager overview (engine/infra-overview.js)
    require('./ciso').registerCiso(srv, app); // AI CISO: posture, risks, decisions, board brief (engine/ciso.js)
  }
  require('./domains').registerDomains(srv, app); // external domains, DNS, e-mail security and certificates (engine/domains.js)

  let timer = null; let findingsTimer = null;
  app.start = async () => {
    const addr = await srv.start();
    timer = setInterval(errors.guard('store.snapshot', () => store.snapshot()), Math.max(1, Number(config.compaction_hours) || 6) * 3600 * 1000);
    timer.unref();
    // recompute deterministic findings periodically (hourly); first pass shortly after start
    findingsTimer = setInterval(errors.guard('findings.regenerate', () => findings.regenerate()), 3600 * 1000);
    findingsTimer.unref();
    if (!opts.noScheduler) discovery.start();
    log.info('sentra-itam listening', { host: addr.address, port: addr.port, provider: provider.kind, version: VERSION });
    return addr;
  };
  app.stop = async () => {
    if (timer) clearInterval(timer);
    if (app.addons && app.addons.assetPropagate) app.addons.assetPropagate.stop();
    if (findingsTimer) clearInterval(findingsTimer);
    await discovery.stop();
    jobs.stop();
    await srv.stop();
    store.close();
  };
  return app;
}

if (require.main === module) {
  let cfg;
  try { cfg = loadConfig(); } catch (e) { process.stderr.write(`sentra-itam: ${e.message}\n`); process.exit(1); }
  const log = createLogger({ level: cfg.config.log_level });
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 20) { log.error('Node.js >= 20 is required', { node: process.version }); process.exit(1); }
  const app = createApp({ config: cfg.config, secrets: cfg.secrets, log, addons: true });
  app.audit({ action: 'service.start', target: 'sentra-itam', detail: { version: VERSION, provider: app.provider.kind } });
  app.start().catch((e) => { log.error('start failed', { err: e.message }); process.exit(1); });
  let stopping = false;
  const shutdown = (sig) => {
    if (stopping) return; stopping = true;
    log.info('shutting down', { sig });
    app.stop().then(() => process.exit(0), () => process.exit(1));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  // safety net: an unhandled rejection is logged and the engine keeps running; an uncaught exception saves the state and
  // exits 1 so systemd starts a clean process (Restart=always in sentra-itam.service)
  app.errors.processHandlers(process, () => { try { app.store.snapshot(); } catch (e) { log.error('state not saved before restart', { err: e.message }); } });
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = { createApp };
