// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * AI engineers' duty desk in IT Asset Management ({P} = /api/itam): the AI Penetration Testing Engineer and the AI
 * Desktop Support Engineer patrol, open work items, investigate and follow fixes through to a verified result. The
 * duty cycle itself is engine/duty-core.js (byte-for-byte the SIEM's engine/duty/duty-core.js; a test compares them).
 *   pentest  - each attack-surface finding (medium and above, or anything internet-facing) is a work item; the next
 *              assessment verifies it. It never starts a test: engagements still need two-administrator authorisation.
 *   desktop  - each unhealthy desktop issue (agent not reporting, critical patches missing, vulnerable) is a work item.
 *              For missing patches the engineer REQUESTS the install, exactly as a technician would; a different person
 *              approves it before Endpoint Central installs anything (desksupport.js four-eyes, unchanged).
 *   virt     - the AI Virtualization Administrator (engine/virt-admin.js): VMware vCenter and Nutanix Prism health from the
 *              read-only capacity collection; writes PowerCLI / acli change plans that an administrator approves (not the
 *              requester) and a person applies, then verifies with a fresh collection.
 *   grc      - the AI GRC Consultant (engine/grc-consultant.js): each compliance gap (failing control, policy past review,
 *              Insurance Authority requirement not covered, drill overdue / failed / unsigned, assets without owners, SAMA
 *              gaps) is a work item with its recommendation and framework clauses. It drafts and recommends; it never
 *              approves, signs off or attests (GRC approvals unchanged).
 * Routes (same shape as the SIEM's /api/soc/duty/*):
 *   GET  /duty/engineers · /duty/items?engineer&status · /duty/items/:id · /duty/reports · /duty/policy        viewer
 *   POST /duty/items/:id/assign|note|snooze|close|investigate · /duty/patrol · /duty/reports                    operator
 *   PUT  /duty/policy                                                                                            admin
 */
const { createDuty } = require('./duty-core');
const { createPentest } = require('./pentest');
const { createDeskSupport } = require('./desksupport');
const { grcConsultantAdapter, registerGrcConsultantRoutes } = require('./grc-consultant');
const { createVirtAdmin, registerVirtAdminRoutes } = require('./virt-admin');

const SEVS = new Set(['critical', 'high', 'medium', 'low']);

function pentestAdapter(pt) {
  const want = (f) => SEVS.has(f.severity) && (f.severity !== 'low' || f.internet);
  const list = () => pt.assessment();
  return {
    id: 'pentest', name: 'AI Penetration Testing Engineer',
    findings() {
      const a = list(); if (!a.summary.assets) return null;           // nothing discovered yet: not connected, not "secure"
      return a.findings.filter(want).map((f) => ({ key: f.id, severity: f.severity, kind: f.kind, title: `${f.asset}: ${f.title}`,
        evidence: [f.evidence, f.internet ? 'internet-facing' : ''].filter(Boolean), recommendation: f.fix || '',
        target: { type: 'asset', id: f.asset_id, name: f.asset }, site: f.site }));
    },
    investigate(it) {
      let f = null; try { f = pt.finding(it.key); } catch (e) { f = null; }
      if (!f) return { summary: 'The finding is no longer in the assessment.', checks: [], causes: [] };
      return { summary: `${f.why || it.title}`,
        checks: [{ name: 'How to verify (authorised engagement only)', status: 'warn', detail: f.verify || '-' }].concat((f.attack || []).length ? [{ name: 'ATT&CK', status: 'warn', detail: [].concat(f.attack).join(', ') }] : []),
        causes: [{ cause: f.title, confidence: 'high', fix: f.fix || '' }] };
    },
    async verify(it) { const present = list().findings.some((f) => f.id === it.key); return { present, note: present ? 'still in the latest assessment' : 'no longer in the latest assessment' }; },
  };
}

function desktopAdapter(desk, store, now) {
  const ec = store.collection('me_ec_computers'), patches = store.collection('desk_patch');
  const KIND = [[/agent not reporting/, 'offline', 'medium'], [/critical patch/, 'patch', 'high'], [/highly vulnerable/, 'vulnerable', 'high'], [/^vulnerable$/, 'vulnerable', 'medium']];
  const issuesOf = (d) => d.issues.map((x) => { const k = KIND.find((r) => r[0].test(x)); return k ? { kind: k[1], severity: k[2], text: x } : null; }).filter(Boolean);
  const T = now || Date.now;
  return {
    id: 'desktop', name: 'AI Desktop Support Engineer',
    findings() {
      if (!ec.size()) return null;                  // Endpoint Central not synced: not connected
      const out = [];
      for (const d of desk.desktops().items) for (const i of issuesOf(d)) {
        out.push({ key: `${d.resource_id}:${i.kind}`, severity: i.severity, kind: i.kind, title: `${d.name}: ${i.text}`,
          evidence: [d.user ? 'user ' + d.user : '', d.os, d.ip, d.last_contact ? 'last contact ' + new Date(d.last_contact).toISOString().slice(0, 16).replace('T', ' ') : '', d.missing != null ? d.missing + ' patches missing' : ''].filter(Boolean),
          recommendation: i.kind === 'patch' ? 'Request the patch install (a different person approves it before Endpoint Central installs).' : i.kind === 'offline' ? 'Check the machine is on the network and the Endpoint Central agent service is running; re-install the agent if it stays silent.' : 'Review the missing patches and vulnerable software in Endpoint Central and plan remediation.',
          target: { type: 'desktop', id: d.resource_id, name: d.name }, site: d.branch });
      }
      return out;
    },
    investigate(it) {
      const d = desk.desktops().items.find((x) => x.resource_id === it.target.id);
      if (!d) return { summary: 'The computer is no longer in Endpoint Central.', checks: [], causes: [] };
      const open = patches.all((p) => p.resource_id === d.resource_id && (p.state === 'requested' || p.state === 'deploying'));
      return { summary: `${d.name}: ${d.issues.join('; ')}.`,
        checks: [{ name: 'Agent', status: d.live === 'down' ? 'fail' : 'ok', detail: `live ${d.live}, last contact ${d.last_contact ? new Date(d.last_contact).toISOString() : 'never'}` },
          { name: 'Patches', status: d.critical ? 'fail' : 'ok', detail: `${d.critical == null ? '?' : d.critical} critical, ${d.missing == null ? '?' : d.missing} missing` },
          { name: 'Patch requests open', status: open.length ? 'warn' : 'ok', detail: open.map((p) => p.id + ' ' + p.state).join(', ') || 'none' }],
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
    },
    propose(it, { onChange }) {
      if (it.kind !== 'patch') return { note: '' };
      const open = patches.all((p) => p.resource_id === it.target.id && (p.state === 'requested' || p.state === 'deploying'))[0];
      const rec = open || desk.requestPatch(it.target.id, { user: 'duty:desktop', role: 'operator', ip: '' });
      onChange({ id: rec.id });
      return { note: open ? 'linked the open patch request ' + rec.id : 'requested the patch install ' + rec.id + ' - a different person must approve it' };
    },
    changeStatus(id) {
      const p = patches.get(id); if (!p) return null;
      return { status: p.state === 'requested' ? 'proposed' : p.state === 'deploying' ? 'applied' : p.state === 'failed' ? 'rejected' : p.state, comment: p.error ? 'install failed: ' + p.error : '' };
    },
    async verify(it) {
      const d = desk.desktops().items.find((x) => x.resource_id === it.target.id);
      const present = !!d && issuesOf(d).some((i) => `${d.resource_id}:${i.kind}` === it.key);
      if (!present) return { present: false, note: 'Endpoint Central no longer reports it' };
      // a patch deployment takes hours: within a day of approval "still there" is not yet a failed fix
      const dep = patches.all((p) => p.resource_id === it.target.id && p.state === 'deploying').sort((a, b) => (a.approved_at < b.approved_at ? 1 : -1))[0];
      if (dep && T() - Date.parse(dep.approved_at || 0) < 86400000) return { present: null, note: 'deployment in progress since ' + dep.approved_at };
      return { present: true, note: 'Endpoint Central still reports it' };
    },
  };
}

const INTEL_MODULES = [
  ['./controls-intel', 'createControlsIntel', 'registerControlsIntel', 'controlsIntel'],
  ['./docs-intel', 'createDocsIntel', 'registerDocsIntel', 'docsIntel'],
  ['./custody-intel', 'createCustodyIntel', 'registerCustodyIntel', 'custodyIntel'],
  ['./validation-intel', 'createValidationIntel', 'registerValidationIntel', 'validationIntel'],
  ['./contcomp-intel', 'createContcompIntel', 'registerContcompIntel', 'contcompIntel'],
  ['./overview-intel', 'createOverviewIntel', 'registerOverviewIntel', 'overviewIntel'],
  ['./bcm-intel', 'createBcmIntel', 'registerBcmIntel', 'bcmIntel'],
  ['./aigov-intel', 'createAigovIntel', 'registerAigovIntel', 'aigovIntel'],
  ['./fwlib-intel', 'createFwlibIntel', 'registerFwlibIntel', 'fwlibIntel'],
  ['./maturity-intel', 'createMaturityIntel', 'registerMaturityIntel', 'maturityIntel'],
  ['./netcfg-intel', 'createNetcfgIntel', 'registerNetcfgIntel', 'netcfgIntel'],
  ['./raci-intel', 'createRaciIntel', 'registerRaciIntel', 'raciIntel'],
  ['./nca-itaudit-intel', 'createNcaItauditIntel', 'registerNcaItauditIntel', 'ncaItauditIntel'],
  ['./ndmo-intel', 'createNdmoIntel', 'registerNdmoIntel', 'ndmoIntel'],
  ['./pdpl-studio-intel', 'createPdplStudio', 'registerPdplStudio', 'pdplStudio'],
  ['./risk-command', 'createRiskCommand', 'registerRiskCommand', 'riskCommand'],
  ['./cert-autopilot', 'createCertAutopilot', 'registerCertAutopilot', 'certAutopilot'],
  ['./business-risk', 'createBusinessRisk', 'registerBusinessRisk', 'businessRisk'],
];
function registerDuty(srv, app, opts = {}) {
  const store = app.store, cfg = (app.config && app.config.duty) || {};
  const engineers = [pentestAdapter(opts.pentest || createPentest(app)), desktopAdapter(opts.desk || createDeskSupport(app), store, opts.now)];
  // the GRC consultant joins when the GRC module is installed (it reads the register, controls, drills; no timers of its own)
  let G = opts.grc || (app.addons && app.addons.grc) || null;
  if (!G) { try { G = require('./grc').createGrc(app); } catch (e) { G = null; } }
  const grcEng = G ? grcConsultantAdapter(app, G) : null;
  if (grcEng) engineers.push(grcEng);
  // the AI IT Auditor and the AI Cyber Security Auditor (engine/auditors.js): read-only control tests over every module
  // the newer engineers are optional: a file the update did not copy leaves that engineer out (said in readiness and the
  // log) instead of stopping sentra-itam - a missing require() used to take every page down (HTTP 502)
  const optional = (name) => {
    try { return require(name); } catch (e) {
      if (e.code === 'MODULE_NOT_FOUND' && String(e.message).indexOf(name.slice(2)) >= 0) { if (app.log) app.log.warn('duty: module not installed - re-run the update', { module: name }); (app.dutyMissing = app.dutyMissing || []).push(name.slice(2)); return null; }
      throw e;
    }
  };
  const AUM = optional('./auditors'), CLM = AUM && optional('./audit-checklist'), PDM = optional('./pdpl'), CEM = optional('./certs'), MRM = optional('./mail-reputation'), ESM = optional('./libraesva'), SVM = optional('./servers'), ARM = optional('./app-route'), HDM = optional('./hardening');
  const AU = AUM ? AUM.createAuditors(app, { now: opts.now, siemEvidence: opts.siemEvidence }) : null;
  if (AU) engineers.push(AU.adapters.itaudit, AU.adapters.cyberaudit);
  (app.addons = app.addons || {}).auditors = AU;
  // the AI PDPL Consultant (engine/pdpl.js; rules in pyengine/pdpl_rules.py): PDPL registers, gaps as work items, the DPO's statement
  const PD = PDM ? PDM.createPdpl(app, { now: opts.now, python: opts.python, invRun: opts.pdplInvRun }) : null;
  if (PD) engineers.push(PD.adapter);
  // the AI PKI Engineer (engine/certs.js; rules in pyengine/cert_rules.py): certificate inventory, lifecycle, renewals
  const CE = CEM ? CEM.createCerts(app, { now: opts.now, python: opts.python, readCert: opts.readCert }) : null;
  if (CE) { engineers.push(CE.adapter); app.addons.certs = CE; }
  // phase 2: issuance (ACME, AD CS, ordered) - engine/cert-issue.js with csr.js, acme.js, adcs.js
  const CIM = CE && optional('./cert-issue');
  if (CIM) CE.issue = CIM.createIssuer(app, CE, { now: opts.now, sealer: opts.certSealer, acmeRequest: opts.acmeRequest, adcsRequest: opts.adcsRequest, adcsCa: opts.adcsCa });
  // phase 3: installation on Palo Alto / FortiGate - engine/cert-install.js (four-eyes, pinned TLS, verified by a scan)
  const CIN = CE && optional('./cert-install');
  if (CIN) CE.install = CIN.createInstaller(app, CE, { now: opts.now, request: opts.deviceRequest, keySealer: opts.certSealer });
  // the four pillars across the estate: keystores and CA-issued certificates (agent 1.6 via the SIEM), expiry alerts, report
  const CESM = CE && optional('./cert-estate');
  if (CESM) CE.estate = CESM.createCertEstate(app, CE, { now: opts.now, siem: opts.certSiem, noTimer: opts.noTimer });
  app.addons.pdpl = PD;
  // the AI Data Governance Officer (engine/ndmo.js; rules in pyengine/ndmo_rules.py): the NDMO data management register - its
  // Personal Data Protection domain is read from the PDPL register above, so the two never disagree
  const NDM = optional('./ndmo');
  const ND = NDM ? NDM.createNdmo(app, { now: opts.now, python: opts.python, catalogFiles: opts.ndmoCatalogFiles }) : null;
  if (ND) { engineers.push(ND.adapter); app.addons.ndmo = ND; }
  // NDMO gap assessment (engine/ndmo-gap.js on engine/gap-engagement.js): one engagement from the team to the approved report, over the NDMO register
  const DGA = ND && optional('./ndmo-gap');
  if (DGA) DGA.registerNdmoGap(srv, app, DGA.createNdmoGap(app, { now: opts.now }));
  // the AI Cybersecurity Compliance Officer (engine/nca-ecc.js; rules in pyengine/nca_ecc_rules.py): NCA ECC-1:2018 verified
  // from the platform's registers and, through the AI CISO's SIEM link, the SIEM's evidence
  const ECM = optional('./nca-ecc');
  const EC = ECM ? ECM.createNcaEcc(app, { now: opts.now, python: opts.python, facts: opts.eccFacts }) : null;
  if (EC) { engineers.push(EC.adapter); app.addons.ncaEcc = EC; }
  // NCA ECC gap assessment (engine/nca-gap.js on engine/gap-engagement.js): one engagement from the team to the approved report, over the register
  const NGA = EC && optional('./nca-gap');
  if (NGA) NGA.registerNcaGap(srv, app, NGA.createNcaGap(app, { now: opts.now }));
  // the AI ISO 27001 Lead Implementer (engine/iso27001.js; rules in pyengine/iso27001_rules.py): the ISMS on the same facts as
  // NCA ECC (read once), the internal audit programme prepared automatically, nonconformities, management review and the SoA
  const ISM = optional('./iso27001');
  const ISO = ISM ? ISM.createIso27001(app, { now: opts.now, python: opts.python, facts: opts.isoFacts, noTimer: opts.noTimer }) : null;
  if (ISO) { engineers.push(ISO.adapter); app.addons.iso27001 = ISO; }
  // ISO 27001 gap assessment (engine/iso-gap.js on engine/gap-engagement.js): one engagement from the team to the approved report, over the ISMS register
  const IGA = ISO && optional('./iso-gap');
  if (IGA) IGA.registerIsoGap(srv, app, IGA.createIsoGap(app, { now: opts.now }));
  // the AI IT Auditor as an audit team member (engine/audit-engage.js): the risk-based plan, engagements, sampling from real
  // records, workpapers, findings and the report - people approve, sign and close; overdue audit work is patrolled here
  const IAM = optional('./audit-engage');
  const IA = IAM ? IAM.createAuditEngage(app, { now: opts.now, sdk: opts.iaSdk, getKey: opts.iaKey }) : null;
  if (IA) { engineers.push(IA.adapter); app.addons.auditEngage = IA; }
  const CSA = IAM ? IAM.createAuditEngage(app, { kind: 'cyber', now: opts.now, sdk: opts.iaSdk, getKey: opts.iaKey }) : null;   // the Cyber Security Audit Team, same engine
  if (CSA) { engineers.push(CSA.adapter); app.addons.cyberAuditEngage = CSA; }
  const IAD = IAM ? IAM.createAuditEngage(app, { kind: 'internal', now: opts.now, sdk: opts.iaSdk, getKey: opts.iaKey }) : null;   // the Internal Audit Team, same engine
  if (IAD) { engineers.push(IAD.adapter); app.addons.internalAuditEngage = IAD; }
  // Non-Human Identities (engine/nhi.js; rules in pyengine/nhi_rules.py): service accounts, gMSA, Entra apps (through the SIEM),
  // this platform's credentials, agent and API keys, and the AI engineers - owners, rotation, risk; the AI Identity Security Engineer
  const NHM = optional('./nhi');
  const NH = NHM ? NHM.createNhi(app, { now: opts.now, python: opts.python, siem: opts.nhiSiem, facts: opts.nhiFacts }) : null;
  if (NH) { engineers.push(NH.adapter); app.addons.nhi = NH; }
  // mail server reputation against Spamhaus (engine/mail-reputation.js; rules in pyengine/mail_rep_rules.py) - Email Security page
  const MR = MRM ? MRM.createMailReputation(app, { now: opts.now, python: opts.python, resolver: opts.mailResolver, publicResolver: opts.mailPublicResolver, sealer: opts.mailSealer, testNets: opts.mailTestNets, smtpProbe: opts.mailSmtpProbe, discovery: opts.mailDiscovery }) : null;
  app.addons.mailReputation = MR;
  // 24/7 Email Availability programme (engine/mail-ops.js): on-call, runbooks, maintenance windows, failover tests, post-incident reviews over the mail modules
  const MOP = optional('./mail-ops');
  if (MOP) MOP.registerMailOps(srv, app, MOP.createMailOps(app, { now: opts.now }));
  const ES = ESM ? ESM.createLibraesva(app, { now: opts.now, request: opts.esgRequest, sealer: opts.esgSealer, lookup: opts.esgLookup }) : null;
  app.addons.libraesva = ES;
  // servers by platform - VMware / Windows / Exchange / Solaris / Oracle Linux pages (engine/servers.js; rules in pyengine/server_rules.py)
  const SV = SVM ? SVM.createServers(app, { now: opts.now, python: opts.python, invRun: opts.serversInvRun, discovery: opts.serversDiscovery }) : null;
  const VA = createVirtAdmin(app, { now: opts.now });   // reads app.addons.virtCapacity at patrol time: no collection = not connected
  engineers.push(VA.adapter);
  // Claude analysis for the virtualization administrator (engine/virt-ai.js) when installed; it stays off until an
  // administrator allows external AI and stores an API key (add-virt-ai.sh) - status() says which is missing
  let VAI = null; try { VAI = require('./virt-ai').createVirtAI(app, VA, opts.virtAi || {}); VA.adapter.aiStatus = VAI.status; VA.adapter.aiInvestigate = (it, o) => VAI.investigate(it, o); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; VAI = null; }
  // the database inventory (engine/db-inventory.js) and the AI Database Administrator for SQL Server / PostgreSQL / MySQL
  // (engine/sqldba.js) built on it - created before the duty desk so the engineer is on duty from the first patrol
  const DIM = optional('./db-inventory'), SQM = DIM && optional('./sqldba');
  const DI = DIM ? DIM.createDbInventory(app, { now: opts.now, noTimer: opts.noTimer, invRun: opts.invRun }) : null;
  const SQ = DI && SQM ? SQM.createSqlDba(app, DI, { now: opts.now, sdk: opts.sqldbaSdk || opts.iaSdk, getKey: opts.sqldbaKey || opts.iaKey }) : null;
  if (SQ) engineers.push(SQ.adapter);
  // the AI Risk Officer (engine/risk-officer.js): enterprise-risk work items from the register and the RAS, proposals checked by a
  // supervisor, decided by a person, learning from those decisions, graded on outcomes. Business Risk is read at patrol time.
  const ROM = optional('./risk-officer'), RO = ROM ? ROM.createRiskOfficer(app, { now: opts.now, noTimer: opts.noTimer }) : null;
  if (RO) { engineers.push(RO.adapter); (app.addons = app.addons || {}).riskOfficer = RO; }
  // the organisation's own estate (brand setting): its AI engineers join the desk; those for systems it does not run leave it
  engineers.push(...require('./ai-team-adapters').adapters(app));
  const ALL_ENG = !!(app.config && app.config.duty && app.config.duty.all_engineers);   // the product's every-engineer view (tests, a demo)
  if (!ALL_ENG) { const off = new Set(require('./brand').engineers_off || []); for (let i = engineers.length - 1; i >= 0; i--) if (engineers[i] && off.has(engineers[i].id)) engineers.splice(i, 1); }
  const D = createDuty({ store, engineers, now: opts.now, log: app.log,
    audit: (action, target, detail) => { if (app.audit) app.audit({ by: (detail && detail.by) || 'duty', role: '', ip: '', action, target, detail }); },
    policyDefaults: Object.assign({ ai_min_severity: 'off' }, cfg.policy || {}),   // AI on patrol only when an admin sets it; proposals are rule-based
    // the duty rules in Python (engine/duty_rules.py, step 7 of docs/PYTHON-MIGRATION.md); duty.engine = "node" switches back
    python: cfg.engine === 'node' ? null : (opts.python || ((app.config && app.config.discovery) || {}).python_bin || '/opt/sentra-siem/pyenv/bin/python3') });
  app.duty = D;
  if (grcEng) registerGrcConsultantRoutes(srv, app, G, grcEng, { now: opts.now });
  registerVirtAdminRoutes(srv, app, VA);
  if (AU) AUM.registerAuditorRoutes(srv, app, AU);
  // the audit checklist by framework (SAMA CSF / NCA ECC / IA), filled by the AI auditors and the human auditor
  if (CLM) { const CL = CLM.createChecklist(app, { now: opts.now }); app.addons.auditChecklist = CL; CLM.registerChecklistRoutes(srv, app, CL); }
  if (PD) PDM.registerPdplRoutes(srv, app, PD);
  // PDPL across the group (engine/pdpl-group.js): group companies, the data processing agreement with each (four-eyes acceptance),
  // the RoPA activities run for each, breach notices to each controller within the agreed hours
  const PGM = PD && optional('./pdpl-group');
  if (PGM) { app.addons.pdplGroup = PGM.createPdplGroup(app, PD, { now: opts.now }); PGM.registerPdplGroup(srv, app, app.addons.pdplGroup); }
  // RoPA workflow automation (engine/pdpl-ropa-flow.js; ML in pyengine/ropa_flow_rules.py): forecast, risk + DPIA, duplicates,
  // proposed drafts from the Data Catalog, reminders to stewards, late departments to Notification & Escalation
  const RFM = PD && PD.ropaCampaigns && optional('./pdpl-ropa-flow');
  if (RFM) RFM.registerRopaFlow(srv, app, RFM.createRopaFlow(app, { now: opts.now, python: opts.python, noTimer: opts.noTimer, pdpl: PD, siem: opts.ropaSiem }));
  // PDPL Intelligence (engine/pdpl-intel.js): learned column review, DSAR / breach deadline risk, DPIA drafts the DPO approves
  const PIM = PD && optional('./pdpl-intel');
  if (PIM) { app.addons.pdplIntel = PIM.createPdplIntel(app, PD, { now: opts.now, sdk: opts.pdplSdk || opts.iaSdk, getKey: opts.pdplKey || opts.iaKey }); PIM.registerPdplIntel(srv, app, app.addons.pdplIntel); }
  if (ND) NDM.registerNdmoRoutes(srv, app, ND);
  if (EC) ECM.registerNcaEccRoutes(srv, app, EC);
  // NCA ECC Compliance Studio (engine/nca-ecc-intel.js): daily history, ranked priorities and leverage, regressions, forecast to the
  // target, read-only AI compliance officer - over the register above
  const NEI = EC && optional('./nca-ecc-intel');
  if (NEI) { const NI = NEI.createNcaEccIntel(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.ncaEccIntel = NI; NEI.registerNcaEccIntel(srv, app, NI); NI.start(); }
  if (ISO) ISM.registerIso27001Routes(srv, app, ISO);
  // ISO 27001 full lifecycle (engine/iso-lifecycle.js): implementation phases judged from the register, the certification cycle,
  // the plan, a forecast to Stage 2, a read-only AI implementation coach
  const ILM = ISO && optional('./iso-lifecycle');
  if (ILM) { const IL = ILM.createIsoLifecycle(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.isoLifecycle = IL; ILM.registerIsoLifecycle(srv, app, IL); IL.start(); }
  // Saudi Aramco CCC (engine/aramco-ccc.js): scope, imported SACS-002 controls, self-assessment with four-eyes "not applicable",
  // remediation, evidence references, the audit firm's findings, the certificate and its renewal
  // Cisco Unified CM (engine/cucm-manager.js): phones, trunks, calls with learned findings; restart / reset phones four-eyes
  // Hyper-V servers (engine/hyperv-manager.js): metrics in the hosts' own reports → capacity, right-sizing, health; four-eyes VM
  // actions the host's report script fetches and runs
  const HVM = optional('./hyperv-manager');
  if (HVM) { app.addons.hypervManager = HVM.createHypervManager(app, { now: opts.now }); HVM.registerHypervManager(srv, app, app.addons.hypervManager); }
  // Asset Onboarding (engine/asset-onboard.js): the AI helper for adding assets from any pasted list, and the accuracy per branch
  const AOB = optional('./asset-onboard');
  if (AOB) AOB.registerAssetOnboard(srv, app, AOB.createAssetOnboard(app, { now: opts.now }));
  // Microsoft 365 Licences & Security (engine/m365-licence-intel.js): licence waste, forecast and the security the licences buy, read-only
  const MLI = optional('./m365-licence-intel');
  if (MLI) MLI.registerM365LicenceIntel(srv, app, MLI.createM365LicenceIntel(app, { now: opts.now, source: opts.m365Source }), { noTimer: opts.noTimer });
  // Compliance AI Assistant (engine/compliance-copilot.js): the group's companies, the realistic position per company and framework, remediation
  // and control-activity workflows with four-eyes verification, bilingual policy drafts to GRC, and questions in English or Arabic
  const CCP = optional('./compliance-copilot');
  if (CCP) CCP.registerCopilot(srv, app, CCP.createCopilot(app, { now: opts.now, sdk: opts.copilotSdk, getKey: opts.copilotKey, aiOff: opts.copilotAiOff, registers: opts.copilotRegisters, budget: opts.copilotBudget }));
  // Azure Cloud Servers (engine/azure-cloud.js): Azure VMs read-only through Resource Graph - backup, Defender, patches, exposure,
  // cost - with start / stop / deallocate / restart as four-eyes changes sent with a separate action credential
  const AZC = optional('./azure-cloud');
  if (AZC) AZC.registerAzureCloud(srv, app, AZC.createAzureCloud(app, { now: opts.now, request: opts.azureRequest, login_base: opts.azureLogin, arm_base: opts.azureArm }), { noTimer: opts.noTimer });
  // Work From Home (engine/remote-work.js): requests, four-eyes approval by the department's approvers, today's board, VPN readiness
  const RWM = optional('./remote-work');
  if (RWM) RWM.registerRemoteWork(srv, app, RWM.createRemoteWork(app, { now: opts.now, noTimer: opts.noTimer }));
  const UCM = optional('./cucm-manager');
  if (UCM) { const UC = UCM.createCucm(app, { now: opts.now, noTimer: opts.noTimer, request: opts.cucmRequest }); app.addons.cucm = UC; UCM.registerCucm(srv, app, UC); UC.start(); }
  const ACM = optional('./aramco-ccc');
  if (ACM) { const AC = ACM.createAramcoCcc(app, { now: opts.now, noTimer: opts.noTimer }); app.addons.aramcoCcc = AC; ACM.registerAramcoCcc(srv, app, AC); AC.start(); }
  const ACE = ACM && optional('./aramco-ccc-evidence');
  if (ACE) { const AE = ACE.createAcccEvidence(app, { now: opts.now, noTimer: opts.noTimer }); app.addons.aramcoCccEvidence = AE; ACE.registerAcccEvidence(srv, app, AE); AE.start(); }
  if (IA) IAM.registerAuditEngageRoutes(srv, app, IA);
  if (CSA) IAM.registerAuditEngageRoutes(srv, app, CSA);
  if (IAD) IAM.registerAuditEngageRoutes(srv, app, IAD);
  // internal vulnerability scans with Greenbone / OpenVAS (engine/vulnscan.js): scope by an admin, scans approved four-eyes, findings with a lifecycle
  const VSM = optional('./vulnscan');
  if (VSM) { const VS = VSM.createVulnScan(app, { now: opts.now, noTimer: opts.noTimer, connect: opts.gmpConnect, sealer: opts.vulnSealer, filePassword: opts.gvmFilePassword }); app.addons.vulnscan = VS; VSM.registerVulnScanRoutes(srv, app, VS); VS.start(); }
  // the department framework checklist (engine/dept-checklist.js): each department attests its periodic obligations, an auditor reviews
  const DCM = optional('./dept-checklist');
  if (DCM) { const DC = DCM.createDeptChecklist(app, { now: opts.now }); app.addons.deptChecklist = DC; DCM.registerDeptChecklistRoutes(srv, app, DC); }
  // the auditor's dashboard (engine/audit-dashboard.js): every framework and audit team on one page, read from the modules above
  const ADM_ = optional('./audit-dashboard');
  if (ADM_) { const ADB = ADM_.createAuditDashboard(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.auditDashboard = ADB; ADM_.registerAuditDashboard(srv, app, ADB); ADB.start(); }
  // continuous control monitoring (engine/audit-ccm.js): the whole audit trail tested daily (SoD, AI/service approvals, after-hours
  // and volume anomalies, personal-data reads, chain integrity); exceptions explained or drafted into a finding a person accepts
  const CCMM = optional('./audit-ccm');
  if (CCMM) { const CC = CCMM.createAuditCcm(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.auditCcm = CC; CCMM.registerAuditCcm(srv, app, CC); CC.start(); }
  // Audit Analytics (engine/audit-analytics.js): the ACL-class data analytics workbench - datasets, duplicates / fuzzy / gaps / Benford /
  // strata / ageing / outliers / join / filter, attribute + MUS sampling, the re-performable command log, four-eyes review, scripts
  const AANM = optional('./audit-analytics');
  if (AANM) { const AAN = AANM.createAuditAnalytics(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.auditAnalytics = AAN; AANM.registerAuditAnalytics(srv, app, AAN); AAN.start(); }
  // Audit Repository (engine/audit-repo.js): previous years' audits and inspections (SAMA, IA, NCA, external, internal ...) with their
  // reports and findings, repeat findings proposed for a person to decide, closure rates per year and body, carried-forward findings
  // Renewal Autopilot (engine/renewals.js): domains read from the registry (RDAP), hosting subscriptions, renewal tasks with four
  // eyes, verified by the registry; lead time, late rate, price change and cost forecast learned; signals to Notification & Escalation
  // Asset Data Autopilot (engine/asset-autofill.js): warranty, support, end of life, classification and CIA proposed from vendor
  // answers, support contracts and what the register teaches (ML); a person accepts; verified vendor values can auto-fill empty fields
  const AFM = optional('./asset-autofill');
  if (AFM) { const AF = AFM.createAssetAutofill(app, { now: opts.now, noTimer: opts.noTimer }); (app.addons = app.addons || {}).assetAutofill = AF; AFM.registerAssetAutofill(srv, app, AF); AF.start(); }
  // Asset Purchasing (engine/purchasing.js): purchase orders from request to go-live (four-eyes approval), items received into the
  // asset register with purchase + warranty, utilisation against the IT budget; lead time, go-live lag and price learned
  const PUM = optional('./purchasing');
  if (PUM) { const PU = PUM.createPurchasing(app, { now: opts.now }); (app.addons = app.addons || {}).purchasing = PU; PUM.registerPurchasing(srv, app, PU); }
  // Software & Licences Studio (engine/software-studio.js): seats vs installs, waste / true-up, reclaim, unlicensed, risky and rare
  // software (ML), version sprawl, and the approved / blocked software policy (a person, audited)
  const SSM = optional('./software-studio');
  if (SSM) { const SS = SSM.createSoftwareStudio(app, { now: opts.now }); (app.addons = app.addons || {}).softwareStudio = SS; SSM.registerSoftwareStudio(srv, app, SS); }
  // Renewals & Expiry (engine/expiry-hub.js): one calendar of licences, support contracts, certificates, domains, hosting, app
  // secrets, warranties and Cisco coverage, read from the owning modules; renewals claimed by a person, verified by the source;
  // lead time, risk, price change and expiry storms learned (registered after the modules it reads)
  const EXM = optional('./expiry-hub');
  const RNM = optional('./renewals');
  if (RNM) { const RN = RNM.createRenewals(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.renewals = RN; RNM.registerRenewals(srv, app, RN); RN.start(); }
  if (EXM) { const EX = EXM.createExpiryHub(app, { now: opts.now }); (app.addons = app.addons || {}).expiryHub = EX; EXM.registerExpiryHub(srv, app, EX); }
  // ITAM Settings advisor (engine/settings-advisor.js): thresholds learned from the register, silent sources, agent coverage, stale
  // agents / tokens, adoption, AI privacy - recommendations an administrator applies (after the expiry hub: it reads its lead times)
  // ITAM Inventory intelligence (engine/inventory-intel.js): data quality per asset, duplicates, spec outliers per model, stale and ghosts
  const IVM = optional('./inventory-intel');
  if (IVM) { const IV = IVM.createInventoryIntel(app, { now: opts.now }); (app.addons = app.addons || {}).inventoryIntel = IV; IVM.registerInventoryIntel(srv, app, IV); }
  // Ticket intelligence (engine/ticket-intel.js): SLA breach risk, recurring problems, duplicates, flow forecast, AI triage
  const TIM = optional('./ticket-intel');
  if (TIM) { const TI = TIM.createTicketIntel(app, { now: opts.now }); app.addons.ticketIntel = TI; TIM.registerTicketIntel(srv, app, TI); }
  // Update Guardrails (engine/update-guard.js): sandbox first, ML risk, waves with four-eyes approval, policy decisions
  const UGM = optional('./update-guard');
  if (UGM) { const UG = UGM.createUpdateGuard(app, { now: opts.now }); app.addons.updateGuard = UG; UGM.registerUpdateGuard(srv, app, UG); }
  // Budget execution (engine/budget-exec.js): the approved IT budget through its year - phasing, POs and invoices, variance, forecast
  const BXM = optional('./budget-exec');
  if (BXM) { const BX = BXM.createBudgetExec(app, { now: opts.now }); app.addons.budgetExec = BX; BXM.registerBudgetExec(srv, app, BX); }
  // Budget intelligence (engine/budget-intel.js): year-end forecast as a distribution, prices learned from purchases, the best mix, unusual amounts, advisor
  const BIM = optional('./budget-intel');
  if (BIM) BIM.registerBudgetIntel(srv, app, { now: opts.now });
  // Leadership intelligence (engine/leader-intel.js): infrastructure health index, trends and storage forecast, renewal wave, CIO worklist, advisor
  const LIM = optional('./leader-intel');
  if (LIM) LIM.registerLeaderIntel(srv, app, { now: opts.now, noTimer: opts.noTimer });
  // Cost Optimisation platform scenarios (engine/platform-cost.js): consolidation from measured use, hypervisor options, reclaim; four-eyes business cases
  const PCM = optional('./platform-cost');
  if (PCM) { const PC = PCM.createPlatformCost(app, { now: opts.now }); app.addons.platformCost = PC; PCM.registerPlatformCost(srv, app, PC); }
  // ITAM Overview (engine/itam-overview.js): one read over the ITAM modules' views, measured health score, ranked actions, daily trend
  const IOM = optional('./itam-overview');
  if (IOM) { const IO = IOM.createItamOverview(app, { now: opts.now, noTimer: opts.noTimer }); app.addons.itamOverview = IO; IOM.registerItamOverview(srv, app, IO); IO.start(); }
  // ITAM Stocktake intelligence (engine/stocktake-intel.js): progress, missing with likelihood, unexpected-code matching, next site to count
  const STI = optional('./stocktake-intel');
  if (STI) { const SI = STI.createStocktakeIntel(app, { now: opts.now }); (app.addons = app.addons || {}).stocktakeIntel = SI; STI.registerStocktakeIntel(srv, app, SI); }
  // ITAM AI Findings intelligence (engine/findings-intel.js): priority with reasons, per-kind learning from people's decisions, hotspots, trend
  const FIM = optional('./findings-intel');
  if (FIM) { const FI = FIM.createFindingsIntel(app, { now: opts.now }); (app.addons = app.addons || {}).findingsIntel = FI; FIM.registerFindingsIntel(srv, app, FI); }
  const SAD = optional('./settings-advisor');
  if (SAD && app.settings) { const SA = SAD.createSettingsAdvisor(app, { now: opts.now }); (app.addons = app.addons || {}).settingsAdvisor = SA; SAD.registerSettingsAdvisor(srv, app, SA); }
  const ARPM = optional('./audit-repo');
  if (ARPM) { const ARP = ARPM.createAuditRepo(app, { now: opts.now, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.auditRepo = ARP; ARPM.registerAuditRepo(srv, app, ARP); }
  // Audit Command Center (engine/audit-auto.js): 21 audit use cases over every record (no sampling), proposed findings an auditor
  // accepts, follow-up and escalation of overdue audit work to Notification & Escalation, slip forecast, repeat findings, AI advisor
  const AAM = optional('./audit-auto');
  if (AAM) { const AX = AAM.createAuditAuto(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.auditAuto = AX; AAM.registerAuditAuto(srv, app, AX); AX.start(); }
  // SAMA CSF + IA automated assessment (engine/sama-ia.js; rules in pyengine/sama_ia_rules.py): every requirement verified against
  // GRC, hardening, pentest / VAPT and SIEM evidence on the NCA ECC facts, a daily snapshot, the AI Assessor drafts, the CISO approves
  const SAM = optional('./sama-ia');
  if (SAM) { const SA = SAM.createSamaIa(app, { now: opts.now, noTimer: opts.noTimer, python: opts.python, facts: opts.samaFacts, sdk: opts.samaSdk || opts.iaSdk, getKey: opts.samaKey || opts.iaKey }); app.addons.samaIa = SA; SAM.registerSamaIa(srv, app, SA); SA.start(); }
  // SAMA CSF gap assessment (engine/sama-gap.js on engine/gap-engagement.js): one engagement from the team to the approved report, over the SAMA register
  const SGA = app.addons.samaIa && optional('./sama-gap');
  if (SGA) SGA.registerSamaGap(srv, app, SGA.createSamaGap(app, { now: opts.now }));
  // SAMA CSF Audit (engine/sama-audit.js): the audit workflow on the assessment - implementation by domain, the gap remediation
  // tracker (owner, due, plan, closure with evidence confirmed by the CISO, four eyes), closure forecast and due-date risk, AI memo
  const SAU = optional('./sama-audit');
  if (SAU && app.addons.samaIa) { const SX = SAU.createSamaAudit(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.samaSdk || opts.iaSdk, getKey: opts.samaKey || opts.iaKey }); app.addons.samaAudit = SX; SAU.registerSamaAudit(srv, app, SX); SX.start(); }
  if (NH) NHM.registerNhiRoutes(srv, app, NH);
  // HR onboarding (engine/onboarding.js, User Desktops -> HR Onboarding): joiner request, manager approval, laptop from stock,
  // account proposed and approved by a second person, created in the directory by a person - the platform never holds a password
  // Departments (engine/org-departments.js): the organisation's own register - HR onboarding and Work From Home read it
  const ODM = optional('./org-departments');
  if (ODM) ODM.registerDepartments(srv, app, ODM.createDepartments(app, { now: opts.now }));
  const ONM = optional('./onboarding');
  if (ONM) { app.addons.onboarding = ONM.createOnboarding(app, { now: opts.now, noTimer: opts.noTimer, adWriter: opts.adWriter, graphRequest: opts.graphRequest, graphLogin: opts.graphLogin, graphBase: opts.graphBase }); ONM.registerOnboarding(srv, app, app.addons.onboarding); }
  // HR offboarding (engine/offboarding.js, User Desktops -> HR Offboarding): leaver confirmed by the manager, the AD disable approved
  // by a different administrator, disabled on the last day through the same directory settings, equipment back to stock
  // Directory users (engine/ad-directory.js, User Management -> Directory users): the people in AD, read only, through the same
  // directory settings; an administrator creates platform accounts in Identity & Sign-in
  const ADDM = optional('./ad-directory');
  if (ADDM) { app.addons.adDirectory = ADDM.createAdDirectory(app, { now: opts.now, ad: opts.adDirectoryAd, noTimer: opts.noTimer }); ADDM.registerAdDirectory(srv, app, app.addons.adDirectory); }
  // User Inventory (engine/people-inventory.js): each person, the devices they hold or sign in to and the applications on them -
  // joined read-only from the directory read, the asset register and Endpoint Central (PDPL: operators and administrators)
  const PINV = optional('./people-inventory');
  if (PINV) PINV.registerPeopleInventory(srv, app, PINV.createPeopleInventory(app, { now: opts.now, noTimer: opts.noTimer, m365: opts.peopleM365 }));
  const ADCN = optional('./ad-connect');
  if (ADCN) { app.addons.adConnect = ADCN.createAdConnect(app, { ad: opts.adConnectAd, dns: opts.adConnectDns }); ADCN.registerAdConnect(srv, app, app.addons.adConnect); }
  // Workflow Automation (engine/workflow-auto.js): what CISO, risk, audit, HR, admin, GRC, governance and the DPO need from the IT
  // infrastructure teams, as tracked requests - catalogue and routing, four-eyes approval and acceptance, evidence from the platform's
  // own records, scheduled requests, escalation to Notification & Escalation, ML (routing, breach risk, workload) and an AI draft
  const WFA = optional('./workflow-auto');
  if (WFA) { app.addons.workflow = WFA.createWorkflow(app, { now: opts.now, noTimer: opts.noTimer }); WFA.registerWorkflow(srv, app, app.addons.workflow); }
  // Enterprise Asset Management (engine/eam.js): plan, buy, receive, deploy, maintain, retire - work orders, maintenance plans, stock,
  // purchase requests and retirements over the asset register, workspaces for asset managers, field, warehouse, procurement and
  // facilities, and ML (failure risk, MTBF, stock demand, cost outliers, technician suggestion) with an AI advisor
  // Role workflows (engine/role-workflows.js): the recurring work of the GRC consultant, Exchange / Windows / virtualization
  // administrators, network, security and desktop support engineers - live status from the platform's records, sign-off, handover
  // Scan-target planner (engine/scan-targets.js): the Network Assistant proposes scan targets from IP Address Management
  const STG = optional('./scan-targets');
  if (STG) STG.registerScanTargets(srv, app, STG.createScanTargets(app, { now: opts.now }));
  // Scan Coverage Assurance (engine/scan-assurance.js): every connected asset scanned, or the reason and the fix, and the rescan prepared
  const SCA = optional('./scan-assurance');
  if (SCA) SCA.registerScanAssurance(srv, app, SCA.createScanAssurance(app, { now: opts.now, noTimer: opts.noTimer }));
  // Continuous Attack Surface (engine/attack-surface.js): the external surface and its APIs, diffed on every run; feeds the attack chain
  const ATS = optional('./attack-surface');
  if (ATS) ATS.registerAttackSurface(srv, app, ATS.createAttackSurface(app, { now: opts.now, noTimer: opts.noTimer }));
  // Pricing Adequacy (engine/pricing-adequacy.js): Motor & Medical combined-ratio / rate-adequacy review, approved four-eyes
  const PRA = optional('./pricing-adequacy');
  if (PRA) PRA.registerPricingAdequacy(srv, app, PRA.createPricingAdequacy(app, { now: opts.now, noTimer: opts.noTimer }));
  // Process Risk Assessment (engine/process-assessment.js): standalone deep-dives on procurement / succession / pricing / etc
  const PCA = optional('./process-assessment');
  if (PCA) PCA.registerProcessAssessment(srv, app, PCA.createProcessAssessment(app, { now: opts.now }));
  // RCSA risk-owner links (engine/rcsa-collect.js): login-free scoped links; responses are proposals a Risk officer accepts
  const RCS = optional('./rcsa-collect');
  if (RCS) RCS.registerRcsaCollect(srv, app, RCS.createRcsaCollect(app, { now: opts.now }));
  // RBC Own Funds & Solvency Assessment (engine/rbc-assessment.js): the IA RBC workbook read schedule by schedule, with insights
  const RBA = optional('./rbc-assessment');
  if (RBA) RBA.registerRbcAssessment(srv, app, RBA.createRbcAssessment(app, { now: opts.now }));
  // VAPT & Penetration Testing Workflow (engine/vapt-workflow.js): one engagement from the request to the signed report
  const VWF = optional('./vapt-workflow');
  if (VWF) VWF.registerVaptWorkflow(srv, app, VWF.createVaptWorkflow(app, { now: opts.now }));
  // Implementation Roadmap (engine/impl-roadmap.js): PDPL and NDMO from the first day to compliant, measured from the modules' records
  const IMPL = optional('./impl-roadmap');
  if (IMPL) IMPL.registerImplRoadmap(srv, app, IMPL.createImplRoadmap(app, { now: opts.now, noTimer: opts.noTimer }));
  const RWF = optional('./role-workflows');
  if (RWF) { app.addons.roleWorkflows = RWF.createRoleWorkflows(app, { now: opts.now }); RWF.registerRoleWorkflows(srv, app, app.addons.roleWorkflows); }
  const EAM = optional('./eam');
  if (EAM && app.assets) { app.addons.eam = EAM.createEam(app, { now: opts.now, noTimer: opts.noTimer }); EAM.registerEam(srv, app, app.addons.eam); }
  // Welcome kit (engine/welcome-mail.js, User Management -> Create account): the sign-in link, user name, role and first-sign-in
  // steps e-mailed to a new user through the platform e-mail relay - never the password
  const WLC = optional('./welcome-mail');
  if (WLC) { app.addons.welcomeMail = WLC.createWelcomeMail(app, { now: opts.now, siem: opts.welcomeSiem }); WLC.registerWelcomeMail(srv, app, app.addons.welcomeMail); }
  const ADMG = optional('./ad-manage');
  if (ADMG) { app.addons.adManage = ADMG.createAdManage(app, { now: opts.now, ad: opts.adManageAd, noTimer: opts.noTimer }); ADMG.registerAdManage(srv, app, app.addons.adManage); }
  // Password & MFA Posture (engine/identity-posture.js, Identity & access): report only; operator reads, admin adjusts the baseline (audited)
  const MOD_IDPOSTURE = optional('./identity-posture');
  if (MOD_IDPOSTURE) { app.addons.identityPosture = MOD_IDPOSTURE.createIdentityPosture(app, { now: opts.now }); MOD_IDPOSTURE.registerIdentityPosture(srv, app, app.addons.identityPosture); }
  // SSO access from AD (engine/sso-groups.js, Platform Administration -> SSO Access from AD): AD groups mapped to platform roles for
  // Entra ID single sign-on - read only from AD, proposed by one administrator, approved by another, no account created
  const SSOG = optional('./sso-groups');
  if (SSOG) { app.addons.ssoGroups = SSOG.createSsoGroups(app, { now: opts.now, ad: opts.ssoGroupsAd }); SSOG.registerSsoGroups(srv, app, app.addons.ssoGroups, { noTimer: opts.noTimer }); }
  // AI identity advisor (engine/identity-advisor.js, Identity & Sign-in studio -> AI advisor): admin only, budgeted, untrusted summary, no tools
  const IDA = optional('./identity-advisor');
  if (IDA) { app.addons.identityAdvisor = IDA.createIdentityAdvisor(app, { sdk: opts.identityAiSdk, getKey: opts.identityAiKey }); IDA.registerIdentityAdvisor(srv, app, app.addons.identityAdvisor); }
  // IP Address Management (engine/ipam.js, Network -> IP Address Management): the address plan people keep, checked against what
  // the asset register and Asset Discovery see - utilisation, conflicts, stale / unknown addresses, growth, AI advisor
  const IPM = optional('./ipam');
  if (IPM) { app.addons.ipam = IPM.createIpam(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); IPM.registerIpam(srv, app, app.addons.ipam); app.addons.ipam.start(); }
  const OFM = optional('./offboarding');
  if (OFM) { app.addons.offboarding = OFM.createOffboarding(app, { now: opts.now, noTimer: opts.noTimer, exoRun: opts.exoRun }); OFM.registerOffboarding(srv, app, app.addons.offboarding); }
  // HR movers (engine/movers.js, User Desktops -> HR Movers): group memberships changed on the effective date after the receiving
  // manager and a different administrator approve, through the same directory settings
  const MVM = optional('./movers');
  if (MVM) { app.addons.movers = MVM.createMovers(app, { now: opts.now, noTimer: opts.noTimer }); MVM.registerMovers(srv, app, app.addons.movers); }
  // quarterly access reviews of AD groups (engine/access-reviews.js, Identity & Microsoft 365 -> Access Reviews): members read from the
  // directory, attested by their managers, removals approved by a second person and applied through the same directory settings
  const ACRM = optional('./access-reviews');
  if (ACRM) { app.addons.accessReviews = ACRM.createAccessReviews(app, { now: opts.now, noTimer: opts.noTimer }); ACRM.registerAccessReviews(srv, app, app.addons.accessReviews); }
  // just-in-time privileged access (engine/pam.js, Identity & Microsoft 365 -> Privileged Access): time-limited AD group membership,
  // approved by a second person, added at the start and removed at expiry through the same directory settings
  const PAMM = optional('./pam');
  if (PAMM) { app.addons.pam = PAMM.createPam(app, { now: opts.now, noTimer: opts.noTimer }); PAMM.registerPam(srv, app, app.addons.pam); }
  // the guided PDPL self-assessment (engine/pdpl-assessment.js; questions in pyengine/pdpl_assessment.py) - writes back to the requirements above
  const PAM = PD && optional('./pdpl-assessment');
  if (PAM) { app.addons.pdplAssessment = PAM.createPdplAssessment(app, { now: opts.now, python: opts.python }); PAM.registerPdplAssessmentRoutes(srv, app, app.addons.pdplAssessment); }
  // PDPL implementation gap assessment (engine/pdpl-gap.js): one engagement from the team and scope to the approved report, built on the self-assessment
  const PGA = PAM && optional('./pdpl-gap');
  if (PGA) PGA.registerPdplGap(srv, app, PGA.createPdplGap(app, { now: opts.now }));
  // Framework Crosswalk + Gap Analysis - All Frameworks (engine/crosswalk.js): NCA ECC as the hub over the SAMA / ISO / NDMO / PDPL
  // engines' own statuses, disagreements, de-duplicated work items with itemised priority, mapping suggestions, trend + forecast, AI
  // SOC 2 (Trust Services Criteria) and ISO/IEC 42001 readiness (engine/frameworks-x.js): derived from the NCA ECC hub, confirmed
  // four-eyes; both feed the crosswalk and the gap analysis
  const FXM = optional('./frameworks-x');
  if (FXM) { app.addons.frameworksX = FXM.createFrameworksX(app, { now: opts.now }); FXM.registerFrameworksX(srv, app, app.addons.frameworksX); }
  const XWM = optional('./crosswalk');
  if (XWM) { const XW = XWM.createCrosswalk(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.xwSdk || opts.iaSdk, getKey: opts.xwKey || opts.iaKey }); app.addons.crosswalk = XW; XWM.registerCrosswalk(srv, app, XW); XW.start(); }
  // Remediation Roadmap (engine/roadmap.js): framework gaps + GRC actions by quarter, velocity, burn-down, slip risk per owner, capacity,
  // a proposed schedule a person accepts one item at a time (the date is written where the item lives), read-only AI planner
  const RMM = optional('./roadmap');
  if (RMM) { const RM = RMM.createRoadmap(app, { now: opts.now, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.roadmap = RM; RMM.registerRoadmap(srv, app, RM); }
  // Automated Risk Assessment (engine/risk-assess.js): 10 scenarios rated from the AI CISO's live signals and posture, residual after
  // controls, register coverage and calibration, daily history with unusual jumps, proposals to the GRC register by a person, AI assessor
  const RAM = optional('./risk-assess');
  if (RAM) { const RA = RAM.createRiskAssess(app, { now: opts.now, noTimer: opts.noTimer, ciso: opts.raCiso, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.riskAssess = RA; RAM.registerRiskAssess(srv, app, RA); RA.start(); }
  // GRC intelligence pages on the shared kit (engine/intel-kit.js): each reads live platform data, keeps a daily history, and has a
  // read-only AI advisor; their changes go through the GRC register as remediation actions a person raises
  // the platform licence (engine/licence.js): issued and signed by Citynet; enforced (grace, then locked) once the issuer key is built in
  const LCM = optional('./licence');
  if (LCM) { const LC = LCM.createLicence(app, { now: opts.now, file: opts.licenceFile, publicKey: opts.licenceKey, publicKeyFile: opts.licenceKeyFile, enforce: opts.licenceEnforce, hostname: opts.licenceHost, machineId: opts.licenceMachineId }); app.addons.licence = LC; LCM.registerLicence(srv, app, LC, { noTimer: opts.noTimer }); }
  for (const [file, make, reg, name] of INTEL_MODULES) {
    const M = optional(file); if (!M) continue;
    const X = M[make](app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons[name] = X; M[reg](srv, app, X); X.start();
  }
  if (RO) ROM.registerRiskOfficer(srv, app, RO);   // after Business Risk, which it reads
  // the Enterprise Risk Programme (engine/risk-programme.js): close / merge, assessment cycles, RAS proposals and the Board approval,
  // insurance categories and emerging risks, the committee / Board / regulator reports - on top of Business Risk
  const RPM = optional('./risk-programme');
  if (RPM && app.addons.businessRisk) { const RP = RPM.createRiskProgramme(app, { now: opts.now }); app.addons.riskProgramme = RP; RPM.registerRiskProgramme(srv, app, RP); }
  // the KPMG ERM framework's capital and governance parts, on top of Business Risk's register and RAS: Capital, ORSA & Stress
  // Testing (engine/erm-capital.js) and Risk Governance & Models (engine/erm-governance.js) - figures and records entered by people
  const ERMC = optional('./erm-capital');
  if (ERMC) { const X = ERMC.createErmCapital(app, { now: opts.now }); app.addons.ermCapital = X; ERMC.registerErmCapital(srv, app, X); }
  const ERMG = optional('./erm-governance');
  if (ERMG) { const X = ERMG.createErmGovernance(app, { now: opts.now }); app.addons.ermGovernance = X; ERMG.registerErmGovernance(srv, app, X); }
  // audit and PDPL automation: engagement reports drafted from the audit records (engine/audit-report.js), monthly frozen
  // regulator evidence packs (engine/evidence-packs.js), PDPL retention enforcement - read-only counts, disposal attestations,
  // DPO acceptance (engine/pdpl-retention.js), and the audit / PDPL automation flow views (engine/automation-flow.js)
  const MOD_AREPORT = optional('./audit-report');
  if (MOD_AREPORT) { const X = MOD_AREPORT.createAuditReport(app, { now: opts.now }); app.addons.auditReport = X; MOD_AREPORT.registerAuditReport(srv, app, X); }
  const MOD_EVPACKS = optional('./evidence-packs');
  if (MOD_EVPACKS) { const X = MOD_EVPACKS.createEvidencePacks(app, { now: opts.now, noTimer: opts.noTimer }); app.addons.evidencePacks = X; MOD_EVPACKS.registerEvidencePacks(srv, app, X); X.start(); }
  const MOD_PRETENTION = optional('./pdpl-retention');
  if (MOD_PRETENTION) { const X = MOD_PRETENTION.createPdplRetention(app, { now: opts.now, noTimer: opts.noTimer, python: opts.python }); app.addons.pdplRetention = X; MOD_PRETENTION.registerPdplRetention(srv, app, X); X.start(); }
  const MOD_AUTOFLOW = optional('./automation-flow');
  if (MOD_AUTOFLOW) { const X = MOD_AUTOFLOW.createAutomationFlow(app, { now: opts.now }); app.addons.automationFlow = X; MOD_AUTOFLOW.registerAutomationFlow(srv, app, X); }
  // role briefs for My Workspace (engine/role-brief.js): the CISO's and the IT Manager's ranked priorities from the modules above
  const RBM = optional('./role-brief');
  if (RBM) { app.addons.roleBrief = RBM.createRoleBrief(app, { now: opts.now }); RBM.registerRoleBrief(srv, app, app.addons.roleBrief); }
  // Governance, Risk & Compliance Dashboard (engine/grc-dashboard.js): one view over the policy register, Risk Studio, GRC actions,
  // every framework (through the crosswalk) and control monitoring; GRC posture index itemised, trend / unusual change, AI advisor
  const GDM = optional('./grc-dashboard');
  if (GDM) { const GD = GDM.createGrcDashboard(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.gdSdk || opts.iaSdk, getKey: opts.gdKey || opts.iaKey }); app.addons.grcDashboard = GD; GDM.registerGrcDashboard(srv, app, GD); GD.start(); }
  // GRC Register (engine/grc-register.js): one integrated register over policies, controls, risks, actions, exceptions and evidence
  // with their links, health and quality issues; hygiene, orphans, duplicates, owner load, action lateness; AI register analyst
  const GRM = optional('./grc-register');
  if (GRM) { const GR = GRM.createGrcRegister(app, { now: opts.now, sdk: opts.grSdk || opts.iaSdk, getKey: opts.grKey || opts.iaKey }); app.addons.grcRegister = GR; GRM.registerGrcRegister(srv, app, GR); }
  // Insurance Authority - Cyber & Operational Resilience (engine/ia-resilience.js): the IA cyber baseline (SAMA CSF + IA items), incident
  // readiness, third parties, recoverability (DR drills, replication) and backup; critical-system matrix; drill-pass chance; AI advisor
  const IAR = optional('./ia-resilience');
  if (IAR) { const IR = IAR.createIaResilience(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.irSdk || opts.iaSdk, getKey: opts.irKey || opts.iaKey }); app.addons.iaResilience = IR; IAR.registerIaResilience(srv, app, IR); IR.start(); }
  // SQL Server / PostgreSQL / MySQL details pulled from the servers already in the platform (engine/db-inventory.js): the login
  // Asset Discovery proved is read with fixed SELECTs; a server running a database without a proven login is listed with the
  // read-only login to create
  if (DI) { DIM.registerDbInventory(srv, app, DI); DI.start(); }
  if (SQ) { app.addons.sqldba = SQ; SQM.registerSqlDba(srv, app, SQ); }
  // Scope Studio (engine/discovery-advisor.js; ML in pyengine/scope_rules.py): Asset Discovery coverage, gaps as proposals, scope
  // health and tuning learned from the platform's own scans, and an agentic AI advisor that drafts proposals a System Admin accepts
  const DAM = optional('./discovery-advisor');
  if (DAM) DAM.registerDiscoveryAdvisor(srv, app, DAM.createDiscoveryAdvisor(app, { now: opts.now, python: opts.python, sdk: opts.advisorSdk || opts.iaSdk, getKey: opts.advisorKey || opts.iaKey }));
  // DR Studio (engine/dr-studio.js; ML in pyengine/dr_studio_rules.py): Main <-> DR replication health from Nutanix protection
  // domains and Oracle Data Guard standbys, 15-minute samples, forecast / anomaly / compliance / readiness; replaces a sample page
  const DRM = optional('./dr-studio');
  if (DRM) DRM.registerDrStudio(srv, app, DRM.createDrStudio(app, { now: opts.now, python: opts.python, noTimer: opts.noTimer, sdk: opts.drSdk || opts.iaSdk, getKey: opts.drKey || opts.iaKey, siemOracle: opts.drSiem, grc: G }));
  // vSphere Studio (engine/vsphere-studio.js; ML in pyengine/vsphere_studio_rules.py): vCenter / ESXi health from the capacity
  // collection - explained scores, imbalance, version drift, workload profiles, unusual CPU; replaces the portal's sample VMware page
  const VSS = optional('./vsphere-studio');
  if (VSS) VSS.registerVsphereStudio(srv, app, VSS.createVsphereStudio(app, { now: opts.now, python: opts.python, sdk: opts.vssSdk || opts.iaSdk, getKey: opts.vssKey || opts.iaKey }));
  // VAPT Studio (engine/vapt-studio.js; mapping / merge / risk in pyengine/firecompass_rules.py): FireCompass (import or API) and
  // Tenable (cloud or Nessus) findings, GET only, keys sealed, merged with the Greenbone scans; false positive / accepted risk four-eyes
  const VAM = optional('./vapt-studio');
  if (VAM) VAM.registerVaptStudio(srv, app, VAM.createVaptStudio(app, { now: opts.now, python: opts.python, noTimer: opts.noTimer, sdk: opts.fcSdk || opts.iaSdk, getKey: opts.fcKey || opts.iaKey, request: opts.fcRequest, sealer: opts.fcSealer }));
  // Discovery Studio (engine/discovery-studio.js; ML in pyengine/discovery_studio_rules.py): recommendations per new device learnt
  // from past decisions, bulk groups, run anomalies, credential health; changes go through the discovery engine's bulk / merge
  const DSM = optional('./discovery-studio');
  if (DSM) DSM.registerDiscoveryStudio(srv, app, DSM.createDiscoveryStudio(app, { now: opts.now, python: opts.python, sdk: opts.dsSdk || opts.iaSdk, getKey: opts.dsKey || opts.iaKey }));
  // Reporting Center (engine/report-center.js; ML in pyengine/report_center_rules.py): a fixed catalogue of reports built from the
  // modules' own views, daily KPI history with trends / forecasts / unusual moves, read-only AI analyst, scheduled delivery
  // through the SIEM Reports relay; replaces the portal's sample "Reports Center"
  const RPC = optional('./report-center');
  if (RPC) RPC.registerReportCenter(srv, app, RPC.createReportCenter(app, { now: opts.now, python: opts.python, noTimer: opts.noTimer, sdk: opts.rcSdk || opts.iaSdk, getKey: opts.rcKey || opts.iaKey, siem: opts.rcSiem }));
  // VAPT Center (engine/vapt-center.js; analysis in pyengine/vapt_center_rules.py): every finding (Greenbone, FireCompass, Tenable,
  // pentest) merged, prioritised, SLA, lateral paths, delta, MTTR; scan wizard filing four-eyes Greenbone requests; nine reports
  const VCM = optional('./vapt-center');
  if (VCM) VCM.registerVaptCenter(srv, app, VCM.createVaptCenter(app, { now: opts.now, python: opts.python, noTimer: opts.noTimer }));
  // Vulnerabilities + Risk Prioritization (engine/vuln-intel.js): one deduplicated vulnerability inventory over every adapter (by
  // severity / software / OS, primary and max score) and an explained 0-100 risk per device, grouped into profiles, with daily trend
  const VIN = optional('./vuln-intel');
  if (VIN) VIN.registerVulnIntel(srv, app, VIN.createVulnIntel(app, { now: opts.now, noTimer: opts.noTimer }));
  // Scanned Assets (engine/scanned-assets.js): every host the scanners examined matched to the asset register - open findings by
  // severity after deduplication, explained risk, age, VAPT Center SLA, last scan / scanners; coverage of the approved scan scope
  const MOD_SCANNED = optional('./scanned-assets');
  if (MOD_SCANNED) MOD_SCANNED.registerScannedAssets(srv, app, MOD_SCANNED.createScannedAssets(app, { now: opts.now }));
  // Data Security Posture (engine/data-posture.js): a 0-10 explained score over seven data risks (shadow, exposed, credentials,
  // localisation, excessive access, misplaced, privacy) from the SIEM's Microsoft 365 / file / cloud / Shadow AI data and the PDPL
  // registers; AI Data Lineage (engine/ai-lineage.js): which AI reaches which store and which classes, built on the same reads
  const MOD_DPOSTURE = optional('./data-posture');
  if (MOD_DPOSTURE) {
    const X = MOD_DPOSTURE.registerDataPosture(srv, app, MOD_DPOSTURE.createDataPosture(app, { now: opts.now, noTimer: opts.noTimer })); X.start();
    // DSPM intelligence (engine/dspm-intel.js): store risk ranking, toxic combinations, anomalies, forecast, fixes, AI advisor
    const MOD_DSPMI = optional('./dspm-intel'); if (MOD_DSPMI) MOD_DSPMI.registerDspmIntel(srv, app, X, { now: opts.now, sdk: opts.dspmSdk, getKey: opts.dspmKey });
    // sensitive files, label policies and breach analysis (engine/dspm-files.js): prioritised file risks, tagging and labelling, breach radius
    const MOD_DSPMF = optional('./dspm-files'); if (MOD_DSPMF) MOD_DSPMF.registerDspmFiles(srv, app, X, { now: opts.now });
    // the data map (engine/data-map.js): the RoPA checked against what discovery found - unmapped systems, under-declared categories, transfers, DPIAs
    const MOD_DMAP = optional('./data-map'); if (MOD_DMAP) MOD_DMAP.registerDataMap(srv, app, { now: opts.now, dataPosture: X });
  // Infrastructure Automation intelligence (engine/infra-intel.js): forecasts, recurrence, noisy rules, response times, coverage, risk, advisor
  const MOD_INFI = optional('./infra-intel'); if (MOD_INFI) MOD_INFI.registerInfraIntel(srv, app, { now: opts.now, noTimer: opts.noTimer });
  }
  // SIEM pipeline watcher (engine/pipeline-health.js): reads the SIEM canary every 5 minutes, out of band; problems become platform incidents
  const MOD_PIPEH = optional('./pipeline-health'); if (MOD_PIPEH) MOD_PIPEH.registerPipelineHealth(srv, app, { now: opts.now, noTimer: opts.noTimer, siem: opts.pipelineSiem });
  const MOD_AILINEAGE = optional('./ai-lineage');
  if (MOD_AILINEAGE) MOD_AILINEAGE.registerAiLineage(srv, app, MOD_AILINEAGE.createAiLineage(app, { now: opts.now }));
  // AI Penetration Testing (engine/ai-pentest.js): the attack-path console - entry -> pivot -> crown jewel chains reasoned
  // read-only from the merged findings, the register and CMDB relationships; the AI pentester proposes, an admin files a draft
  // engagement in the pentest engineer, which still needs the safety checklist and a second administrator
  const AIP = optional('./ai-pentest');
  if (AIP) AIP.registerAiPentest(srv, app, AIP.createAiPentest(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.aipSdk, getKey: opts.aipKey }));
  // IT Audit Inspections (engine/audit-inspect.js): scored on-site checklists with photo evidence and signatures, corrective
  // actions verified by a second person, schedules, branded report, cross-site analytics (trend, repeat failures)
  const AIN = optional('./audit-inspect');
  if (AIN) AIN.registerAuditInspect(srv, app, AIN.createAuditInspect(app, { now: opts.now, noTimer: opts.noTimer, evidenceDir: opts.inspectDir, sdk: opts.inspSdk, getKey: opts.inspKey }));
  // Issues Management (engine/issues-hub.js): one register over audit-team findings, inspection actions, GRC actions and regulator
  // findings - possible duplicates, repeats, escalation, links to GRC risks; each issue is worked where it was raised
  const ISH = optional('./issues-hub');
  if (ISH) ISH.registerIssuesHub(srv, app, ISH.createIssuesHub(app, { now: opts.now, noTimer: opts.noTimer }));
  // Risk & Control Hub (engine/risk-control.js): business hierarchy, one control library with framework citations, control tests,
  // risk <-> control links with a calculated residual, KRIs, loss events, roll-ups and one register of every acceptance
  const RCH = optional('./risk-control');
  if (RCH) { app.addons.riskControl = RCH.createRiskControl(app, { now: opts.now }); RCH.registerRiskControl(srv, app, app.addons.riskControl); }
  // SAMA IT Audit (engine/sama-itaudit.js; rules in pyengine/sama_itaudit_rules.py): readiness for a SAMA IT audit across the five
  // areas + the audit process, from the platform's own evidence; gaps become draft findings a person sends into an IT Audit engagement
  const SIA = optional('./sama-itaudit');
  if (SIA) SIA.registerSamaItAudit(srv, app, SIA.createSamaItAudit(app, { now: opts.now, python: opts.python, noTimer: opts.noTimer }));
  // Notification & Escalation (engine/notify-center.js; ML in pyengine/notify_rules.py): one router for SIEM alerts and platform
  // conditions - policies, on-call rota, escalation ladders, maintenance windows, delivery through the SIEM relay, learnt ack times,
  // escalation prediction, noise, fatigue and storms; AI explains and proposes, an administrator decides
  const NCM = optional('./notify-center');
  if (NCM) NCM.registerNotifyCenter(srv, app, NCM.createNotifyCenter(app, { now: opts.now, python: opts.python, noTimer: opts.noTimer, sdk: opts.ncSdk || opts.iaSdk, getKey: opts.ncKey || opts.iaKey, siem: opts.ncSiem }));
  // Team Workspace (engine/team-workspace.js): departments, job roles, people and reporting lines an administrator builds; tasks
  // reviewed along the reporting line / a workflow; each person's own mail, meetings and Teams chats through their own Microsoft sign-in
  const TWM = optional('./team-workspace');
  if (TWM) TWM.registerTeamWorkspace(srv, app, TWM.createTeamWorkspace(app, { now: opts.now, request: opts.wsRequest, sealer: opts.wsSealer }));
  // Virtual Network Map (engine/virt-network.js; readers in virt-capacity.js / virt-net-read.js): vCenter / ESXi and Nutanix AHV
  // networking per VM, learned per-cluster baseline, findings with prepared fix + rollback, four-eyes proposals, AI engineer
  const VNM = optional('./virt-network');
  if (VNM) VNM.registerVirtNetwork(srv, app, VNM.createVirtNetwork(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.vnSdk || opts.iaSdk, getKey: opts.vnKey || opts.iaKey, capacity: opts.vnCapacity }));
  // Service Agreement (engine/service-agreement.js): the SLA and NDA between the organisation and Citynet Work (delivered through
  // Zyberon) - customisable terms, support cases between the parties, audit-remediation targets, monthly statement with service
  // credits, documents approved by both signatories and published
  const SVA = optional('./service-agreement');
  if (SVA) SVA.registerServiceAgreement(srv, app, SVA.createServiceAgreement(app, { now: opts.now }));
  // Risk Studio (engine/risk-studio.js): the AI / ML layer over the GRC risk register - evidence linked from audit findings, platform
  // gaps, overdue actions and expired exceptions; evidence-based scoring and calibration; learned categories; candidate risks; appetite;
  // trend; Excel report on the page; a read-only AI risk analyst. The register stays the record.
  const RSM = optional('./risk-studio');
  if (RSM) { app.addons.riskStudio = RSM.createRiskStudio(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.rsSdk || opts.iaSdk, getKey: opts.rsKey || opts.iaKey }); RSM.registerRiskStudio(srv, app, app.addons.riskStudio); }
  // IT Operations & Updates (engine/update-studio.js): every server's update history from Endpoint Central, the agent and the
  // hypervisor reads, checked against the patch and change policy; drift, cadence, risk; a read-only AI update analyst
  const UPD = optional('./update-studio');
  if (UPD) UPD.registerUpdateStudio(srv, app, UPD.createUpdateStudio(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.usSdk || opts.iaSdk, getKey: opts.usKey || opts.iaKey, hosts: opts.usHosts, ec: opts.usEc }));
  // Unified Patch Management (engine/patch-hub.js): servers, desktops, switches / routers, firewalls and databases in one view from
  // Update Studio, Endpoint Central, Cisco Update Manager, the database inventory, the scanner and end of life; baselines, exceptions
  const PHM = optional('./patch-hub');
  if (PHM) PHM.registerPatchHub(srv, app, PHM.createPatchHub(app, { now: opts.now }));
  // Infrastructure Inventory (engine/infra-inventory.js): what sees each firewall / switch / server / VM / storage asset - discovery,
  // agent, hypervisor, SIEM logs, owner, site, criticality; peer outliers, stale and duplicate assets; read-only AI analyst
  const IIV = optional('./infra-inventory');
  if (IIV) IIV.registerInfraInventory(srv, app, IIV.createInfraInventory(app, { now: opts.now, sdk: opts.iiSdk || opts.iaSdk, getKey: opts.iiKey || opts.iaKey, logCoverage: opts.iiCoverage, ec: opts.iiEc, virt: opts.iiVirt }));
  // Servers, Cloud & Applications Dashboard (engine/servers-dashboard.js): five tiers from the modules above - health, ranked issues,
  // unusual drops against their own history, read-only AI analyst (replaces the portal's sample dash-srv page)
  const SDB = optional('./servers-dashboard');
  if (SDB) SDB.registerServersDashboard(srv, app, SDB.createServersDashboard(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.sdSdk || opts.iaSdk, getKey: opts.sdKey || opts.iaKey, sources: opts.sdSources }));
  // Operations Wall (engine/ops-wall.js): NOC + SOC big screen from the modules above - panels, same-time-of-day anomalies, shift diff,
  // read-only AI shift-handover analyst (replaces the portal's wall view)
  const OWL = optional('./ops-wall');
  if (OWL) OWL.registerOpsWall(srv, app, OWL.createOpsWall(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.owSdk || opts.iaSdk, getKey: opts.owKey || opts.iaKey, sources: opts.owSources, sourceMs: opts.owSourceMs }));
  // Executive Dashboard (engine/exec-dashboard.js): health index over five pillars from the Reporting Center, AI CISO and Risk Studio,
  // its daily history (trend, forecast, unusual today), what needs the executive; AI brief = the Reporting Center analyst
  // Phishing Simulation (engine/phish-sim.js): Defender Attack Simulation Training results read through a read-only Graph app;
  // campaign trend, smoothed department susceptibility, repeat clickers, time to click, risk indicators; AI awareness advisor (aggregates)
  const PHS = optional('./phish-sim');
  if (PHS) PHS.registerPhishSim(srv, app, PHS.createPhishSim(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.psSdk || opts.iaSdk, getKey: opts.psKey || opts.iaKey, request: opts.psRequest, sealer: opts.psSealer }));
  // Brand Protection (engine/brand-protect.js): look-alike domains + certificate transparency (passive), ML risk learned from
  // analysts' triage, weekly spikes, takedown cases; AI brand analyst (read-only). Official domains from Domains & Hosting
  const BPR = optional('./brand-protect');
  if (BPR) BPR.registerBrandProtect(srv, app, BPR.createBrandProtect(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.bpSdk || opts.iaSdk, getKey: opts.bpKey || opts.iaKey, net: opts.bpNet }));
  // Application Security & Code Review (engine/appsec.js): application register, SARIF / CycloneDX / npm audit imports, built-in quick
  // review (secrets masked), finding lifecycle with four-eyes risk acceptance, release gate with override, ML (false-positive chance,
  // risk, SLA), AI AppSec reviewer (read-only)
  const APS = optional('./appsec');
  if (APS) { const AS = APS.createAppSec(app, { now: opts.now, sdk: opts.asSdk || opts.iaSdk, getKey: opts.asKey || opts.iaKey }); app.addons.appsec = AS; APS.registerAppSec(srv, app, AS); }
  // Application Penetration Testing (engine/apppt.js): applications with a test cadence, engagements from scope (four-eyes) to retest,
  // coverage per OWASP WSTG area, findings (manual, OWASP ZAP JSON, Burp XML) verified only by another person's retest, ML, AI analyst
  const APT = optional('./apppt');
  if (APT) { const AP = APT.createAppPt(app, { now: opts.now, sdk: opts.ptSdk || opts.iaSdk, getKey: opts.ptKey || opts.iaKey }); app.addons.apppt = AP; APT.registerAppPt(srv, app, AP); }
  // Mobile Application Testing (engine/mobile-test.js): MobSF reports per build mapped to OWASP MASVS, manual MASTG checks, release gate,
  // four-eyes risk acceptance, build-over-build learning, read-only AI analyst
  const MTM = optional('./mobile-test');
  if (MTM) { const MT = MTM.createMobileTest(app, { now: opts.now, sdk: opts.ptSdk || opts.iaSdk, getKey: opts.ptKey || opts.iaKey }); app.addons.mobileTest = MT; MTM.registerMobileTest(srv, app, MT); }
  // Vulnerability & Testing Dashboard (engine/vuln-dashboard.js): exposure, testing coverage, application tests, code security and
  // remediation read from VAPT Center, the testing cadence, App Pen Testing and AppSec - itemised, learned, AI advisor (read-only)
  const VDM = optional('./vuln-dashboard');
  if (VDM) { const VD = VDM.createVulnDashboard(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.iaSdk, getKey: opts.iaKey }); app.addons.vulnDashboard = VD; VDM.registerVulnDashboard(srv, app, VD); VD.start(); }
  const EXD = optional('./exec-dashboard');
  if (EXD) EXD.registerExecDashboard(srv, app, EXD.createExecDashboard(app, { now: opts.now, noTimer: opts.noTimer }));
  // CMDB & Dependencies (engine/cmdb-deps.js): applications and what they stand on - impact / failure propagation, single points of
  // failure, under-rated / end-of-life dependencies, weekly drift, read-only AI analyst (replaces the portal's itam-cmdb view)
  const CDP = optional('./cmdb-deps');
  if (CDP) CDP.registerCmdbDeps(srv, app, CDP.createCmdbDeps(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.cdSdk || opts.iaSdk, getKey: opts.cdKey || opts.iaKey }));
  // Digital Twin Studio (engine/twin-studio.js): the CMDB graph + live backup / DR / vulnerability state -> failure likelihood, Monte
  // Carlo resilience, fix first, site loss and what-if simulation; DR pairs and outages recorded by people (audited); read-only AI analyst
  const TWS = optional('./twin-studio');
  if (TWS && CDP) TWS.registerTwinStudio(srv, app, TWS.createTwinStudio(app, { now: opts.now, sdk: opts.twSdk || opts.iaSdk, getKey: opts.twKey || opts.iaKey }));
  // Implementation Plan & Budget (engine/impl-plan.js): open GRC remediation actions -> person-entered estimates, capacity schedule,
  // cash flow, effort calibration and velocity forecast, read-only AI analyst (replaces the portal's implplan view)
  const IMP = optional('./impl-plan');
  if (IMP) IMP.registerImplPlan(srv, app, IMP.createImplPlan(app, { now: opts.now, sdk: opts.ipSdk || opts.iaSdk, getKey: opts.ipKey || opts.iaKey }));
  // Update Health (engine/update-health.js): what the last update installed, which pages the running engine serves against the ones it
  // should, the modules it could not load and the causes the update doctor found - so a page that is "not installed" says why
  const UHM = optional('./update-health');
  if (UHM) UHM.registerUpdateHealth(srv, app, UHM.createUpdateHealth(app, { reportFile: opts.updateReportFile, srv }));
  // Accountability Studio (engine/owner-studio.js; ML in pyengine/owner_studio_rules.py): owner / service suggestions with their
  // evidence, owner load, reconciliation differences with a fix / accept recommendation learned from past decisions; people apply
  const OSM = optional('./owner-studio');
  if (OSM) OSM.registerOwnerStudio(srv, app, OSM.createOwnerStudio(app, { now: opts.now, python: opts.python, sdk: opts.ownerSdk || opts.iaSdk, getKey: opts.ownerKey || opts.iaKey }));
  // Cost Studio (engine/cost-studio.js; ML in pyengine/cost_studio_rules.py): savings with evidence priced only from recorded
  // costs, budget execution learned from last year, unusual lines, showback, saving actions; the AI only proposes
  const CSTM = optional('./cost-studio');
  if (CSTM) CSTM.registerCostStudio(srv, app, CSTM.createCostStudio(app, { now: opts.now, python: opts.python, sdk: opts.costSdk || opts.iaSdk, getKey: opts.costKey || opts.iaKey }));
  // Lifecycle Studio (engine/lifecycle-studio.js; ML in pyengine/lifecycle_studio_rules.py): risk, replacement due dates with
  // their driver, learned lifespans, the 8-quarter refresh forecast, renewals and the refresh plan; the AI only proposes
  const LSM = optional('./lifecycle-studio');
  if (LSM) LSM.registerLifecycleStudio(srv, app, LSM.createLifecycleStudio(app, { now: opts.now, python: opts.python, sdk: opts.lifecycleSdk || opts.iaSdk, getKey: opts.lifecycleKey || opts.iaKey }));
  // Remote console (engine/remote-console.js): RDP / SSH through the Guacamole gateway and the vSphere / Prism web consoles,
  // only after another person approves a time-limited request; every gateway session recorded and audited
  const RCM = optional('./remote-console');
  if (RCM) RCM.registerRemoteConsole(srv, app, RCM.createRemoteConsole(app, { now: opts.now, noTimer: opts.noTimer, config: opts.consoleConfig }));
  // Asset Studio (engine/asset-studio.js; ML in pyengine/asset_studio_rules.py): the asset register with a health score per
  // asset, anomalies, field suggestions learned from peers and an agentic AI analyst - a person applies every change
  const ASM = optional('./asset-studio');
  if (ASM) ASM.registerAssetStudio(srv, app, ASM.createAssetStudio(app, { now: opts.now, python: opts.python, sdk: opts.assetSdk || opts.iaSdk, getKey: opts.assetKey || opts.iaKey }));
  // CMDB Studio (engine/cmdb-studio.js; ML in pyengine/cmdb_rules.py): CI data quality, duplicates, learned relationship
  // proposals, blast radius / single points of failure, and an agentic AI analyst that records proposals a person decides
  const CSM = optional('./cmdb-studio');
  if (CSM) CSM.registerCmdbStudio(srv, app, CSM.createCmdbStudio(app, { now: opts.now, python: opts.python, sdk: opts.cmdbSdk || opts.iaSdk, getKey: opts.cmdbKey || opts.iaKey }));
  // CMDB Studio insights (engine/cmdb-intel.js): importance (PageRank), service groups, coverage, proposal calibration from people's
  // decisions, daily health with trend and projection, bulk confirm by a person (audited)
  const CINT = optional('./cmdb-intel');
  if (CINT && CSM) CINT.registerCmdbIntel(srv, app, CINT.createCmdbIntel(app, { now: opts.now, noTimer: opts.noTimer }));
  // Coverage & Query (engine/asset-coverage.js): per asset EDR / patch agent / backup / vulnerability scan / SIEM logs with the source
  // of each fact, gaps ranked by criticality, a query language, saved + scheduled queries, and a four-eyes Action Center
  // AI Engine (engine/ai-engine.js + ai-backend.js): the switch between Claude, the local model on the AI server, and no AI
  const AIE = optional('./ai-engine');
  if (AIE) AIE.registerAiEngine(srv, app, AIE.createAiEngine(app, { now: opts.now, fetch: opts.aiFetch, sdk: opts.aiEngineSdk, localKey: opts.aiLocalKey, anthropicKey: opts.aiAnthropicKey }));
  // Private AI Server (engine/private-ai.js): health of the AI server the AI Engine points at - gateway, exporters, every AI call,
  // ML over them (robust baseline, Wilson interval, forecasts), a four-eyes model change and a read-only advisor
  const PAI = optional('./private-ai');
  if (PAI && AIE) PAI.registerPrivateAi(srv, app, PAI.createPrivateAi(app, { now: opts.now, noTimer: opts.noTimer, fetch: opts.privateAiFetch || opts.aiFetch, sdk: opts.privateAiSdk || opts.iaSdk, getKey: opts.privateAiKey || opts.iaKey }));
  // Platform Map (engine/platform-map.js): sources with their real state -> stages -> outcomes, for the Home -> Platform Map page
  // Custom Dashboards (engine/dash-builder.js): widgets over a fixed catalog, query builder, daily ML per widget, AI proposes a widget
  const DSB = optional('./dash-builder');
  if (DSB) DSB.registerDashBuilder(srv, app, DSB.createDashBuilder(app, { now: opts.now, noTimer: opts.noTimer, sdk: opts.dashSdk, getKey: opts.dashKey }));
  const PMAP = optional('./platform-map');
  if (PMAP) PMAP.registerPlatformMap(srv, app, PMAP.createPlatformMap(app, { now: opts.now, noTimer: opts.noTimer }));
  const ACV = optional('./asset-coverage');
  if (ACV) { app.addons.assetCoverage = ACV.createAssetCoverage(app, { now: opts.now, noTimer: opts.noTimer, logCoverage: opts.acovLogCoverage, availMap: opts.acovAvail, siem: opts.acovSiem }); ACV.registerAssetCoverage(srv, app, app.addons.assetCoverage); }
  // PDPL Control Monitor (engine/pdpl-monitor.js): continuous tests of every system holding personal data against the asset register,
  // Asset Coverage and the PDPL registers; drift, GRC actions, staff policy acknowledgements, a hashed evidence pack
  const PMON = optional('./pdpl-monitor');
  if (PMON) { app.addons.pdplMonitor = PMON.createPdplMonitor(app, { now: opts.now, noTimer: opts.noTimer }); PMON.registerPdplMonitor(srv, app, app.addons.pdplMonitor); app.addons.pdplMonitor.start(); }
  // Compliance Assistant (engine/compliance-assist.js; ML in pyengine/assist_rules.py): plain-language answers over every
  // register above - SAMA + IA, NCA ECC, ISO 27001, NDMO, PDPL - with local machine learning, learning from people's ratings
  const CAM = optional('./compliance-assist');
  if (CAM) CAM.registerComplianceAssist(srv, app, CAM.createComplianceAssist(app, { now: opts.now, python: opts.python, registers: opts.assistRegisters }));
  // the Privacy Office - PDPL as its own organisation: routed tasks, escalation, recurring duties, route map (engine/pdpl-office.js; rules in pyengine/pdpl_office.py)
  const POM = PD && optional('./pdpl-office');
  if (POM) { const PO = POM.createPrivacyOffice(app, PD, Object.assign({ now: opts.now, python: opts.python }, opts.privacyOffice || {})); app.addons.privacyOffice = PO; POM.registerPrivacyOfficeRoutes(srv, app, PO); if (!opts.noTimer) PO.start(); }
  if (CE) CEM.registerCertRoutes(srv, app, CE);
  if (CE && CE.estate) { CESM.registerCertEstateRoutes(srv, app, CE.estate); CE.estate.start(); }
  // certificates found automatically from Asset Discovery's open TLS ports (engine/cert-autodiscover.js)
  const CADM = CE && optional('./cert-autodiscover');
  if (CADM) { CE.autodiscover = CADM.createCertAutodiscover(app, CE, { now: opts.now, noTimer: opts.noTimer }); CADM.registerCertAutodiscoverRoutes(srv, app, CE.autodiscover); }
  if (MR) { MRM.registerMailReputationRoutes(srv, app, MR); if (!opts.noTimer) MR.start(); }
  // DNS fixes for mail (engine/dns-fix.js): SPF changes the route map finds, proposed by an operator, approved by another person,
  // written through the Cloudflare API (sealed token) and read back
  // Cisco Update Manager (engine/cisco-update.js): target releases, PSIRT deadlines, four-eyes update plans verified against the
  // running version; joins cisco-support.js (advisories, Smart Net) - it changes nothing on a device
  const CUM = optional('./cisco-update');
  if (CUM) { const CU = CUM.createCiscoUpdate(app, { now: opts.now, ciscoSupport: opts.ciscoSupport }); app.addons.ciscoUpdate = CU; CUM.registerCiscoUpdate(srv, app, CU); CUM.startCiscoUpdate(app, CU, { noTimer: opts.noTimer }); }
  const DNF = optional('./dns-fix');
  if (DNF) DNF.registerDnsFix(srv, app, DNF.createDnsFix(app, { now: opts.now, sealer: opts.mailSealer, cf: opts.dnsCf }));
  // the mail route troubleshooter (engine/mail-doctor.js): verifies DNS against public resolvers, re-checks, follows the path, proposes fixes
  const MDM = MR && optional('./mail-doctor');
  if (MDM) { const MD = MDM.createMailDoctor(app, { now: opts.now, noTimer: opts.noTimer, resolvers: opts.mailDoctorResolvers, siemHealth: opts.mailDoctorSiemHealth, siemTop: opts.mailDoctorSiemTop }); app.addons.mailDoctor = MD; MDM.registerMailDoctorRoutes(srv, app, MD); MD.start(); }
  if (ES) ESM.registerLibraesvaRoutes(srv, app, ES);
  if (SV) { SVM.registerServerRoutes(srv, app, SV); if (!opts.noTimer) SV.start(); }
  // application route map - each application from users to its database (engine/app-route.js; rules in pyengine/app_route.py)
  if (ARM) ARM.registerAppRouteRoutes(srv, app, ARM.createAppRoute(app, { now: opts.now, python: opts.python }));
  // baseline hardening - every IT asset against its CIS benchmark, SAMA CSF 3.3.8 / NCA ECC 2-3 (engine/hardening.js; rules in pyengine/hardening_rules.py)
  if (HDM) { const HD = HDM.createHardening(app, { now: opts.now, python: opts.python, siem: opts.hardeningSiem }); app.addons.hardening = HD; HDM.registerHardeningRoutes(srv, app, HD); if (!opts.noTimer) HD.start(); }
  if (VAI) require('./virt-ai').registerVirtAIRoutes(srv, app, VAI);
  if (cfg.enabled !== false && !opts.noTimer) D.start();
  const b = (ctx) => ctx.body || {};
  // readiness: is each engineer here FULLY working, and if not, what is missing and how to fix it (reads state only)
  /* /duty/readiness reads every engineer's sources (CISO overview, GRC gaps, PDPL / NDMO / NCA ECC rules in Python, ...); on a
     busy server that took longer than the update check waits (8 s) and the page was reported as not answering. The route now
     answers within a budget: the fresh result when it is ready, otherwise the last one marked stale (or "computing" the first
     time) while the one computation in flight finishes in the background and is kept for the next call. */
  const RD = { val: null, at: 0, inflight: null };
  const readinessNow = async () => {
    const chk = (name, ok, detail, fix) => ({ name, ok, detail: String(detail || ''), fix: ok === false ? String(fix || '') : '' });
    const P = D.policy(), eng = {}; for (const e of D.engineers()) eng[e.id] = e;
    const duty = (id) => { const e = eng[id] || {}; return [chk('On duty', !!e.on_duty, e.on_duty ? 'patrols every ' + (P.patrol_min || 10) + ' min' : 'duty desk switched off', 'AI Engineering Team → Duty policy → switch the duty desk on (admin)'),
      chk('Patrolling', e.last_error ? false : e.last_patrol ? true : null, e.last_error ? 'last patrol problem: ' + e.last_error : e.last_patrol ? 'last patrol ' + new Date(e.last_patrol).toISOString() : 'first patrol pending', 'Fix the problem named above; the next patrol retries by itself')]; };
    const out = [];
    let a = null; try { a = (app.addons && app.addons.pentest ? app.addons.pentest : createPentest(app)).assessment().summary; } catch (e) { a = null; }
    out.push({ id: 'pentest', name: 'AI Penetration Testing Engineer', engine: 'itam', checks: [
      chk('Assets to assess', a ? a.assets > 0 : false, a ? a.assets + ' assets, ' + a.internet_facing + ' internet-facing' : 'assessment not available', 'Asset Discovery → run discovery and approve the devices; the inventory is what the engineer assesses'),
      chk('Engagements', null, 'tests run only inside an approved engagement (two administrators) - by design', ''),
    ].concat(duty('pentest')) });
    let st = null; try { st = (app.addons && app.addons.deskSupport ? app.addons.deskSupport : createDeskSupport(app)).status(); } catch (e) { st = null; }
    const me = st && st.configured || {};
    out.push({ id: 'desktop', name: 'AI Desktop Support Engineer', engine: 'itam', checks: [
      chk('Endpoint Central connected', !!me.ec, me.ec ? 'connected' + (st.desktops ? ' · ' + (st.desktops.total || 0) + ' desktops' : '') : 'not configured', 'ManageEngine page → Endpoint Central: server URL and a read-only API key (plus patch-deploy rights for approved installs)'),
      chk('ServiceDesk Plus connected', me.sdp === undefined ? null : !!me.sdp, me.sdp ? 'connected' : 'not configured', 'ManageEngine page → ServiceDesk Plus: server URL and technician key'),
      chk('Technicians listed', st ? st.technicians > 0 : null, st ? st.technicians + ' technician(s) for assignment' : '', 'AI Desktop Support → settings → add the technicians tickets are assigned to'),
    ].concat(duty('desktop')) });
    // the CISO overview reads the SIEM and every source: bounded, so readiness answers even when one source is slow (shown as "not read yet")
    let c = null, ct = null;
    try { c = app.addons && app.addons.ciso ? await Promise.race([app.addons.ciso.overview(false), new Promise((r) => { ct = setTimeout(() => r(null), opts.readinessCisoMs || 5000); })]) : null; } catch (e) { c = null; /* a source failed: the checks say "not read yet" */ } finally { clearTimeout(ct); }
    if (app.addons && app.addons.ciso) {
      const live = c ? c.sources.filter((x) => x.state === 'live').length : 0, siemDown = c ? c.sources.filter((x) => ['siem_duty', 'soc', 'sama', 'approvals'].includes(x.id) && x.state !== 'live') : [];
      const s2 = app.addons.ciso.status();
      out.push({ id: 'ciso', name: 'AI CISO', engine: 'itam', checks: [
        chk('Data sources live', c ? live === c.sources.length : null, c ? live + ' of ' + c.sources.length : 'not read yet', 'The sources not live are listed on the AI CISO page under Data sources'),
        chk('SIEM link', c ? siemDown.length === 0 : null, siemDown.length ? siemDown.map((x) => x.name + ': ' + (x.error || x.state)).join('; ') : 'answering', 'Check discovery.siem (base_url, secret_file) in /etc/sentra-itam/config.json - the same link Server Availability uses'),
        chk('Runs on its own', !!s2.running, s2.running ? 'morning brief at ' + String(s2.brief_hour).padStart(2, '0') + ':00 Sun-Thu' : 'automatic run off', 'Remove ciso.enabled=false from /etc/sentra-itam/config.json and restart sentra-itam'),
        chk('AI brief', app.provider ? null : false, app.provider ? 'uses the IT Asset Management AI provider when it is ready; otherwise the labelled rule-based brief' : 'no AI provider', 'Store the Claude API key on the server: sudo zyb-virt-ai --set-key (or --from-siem), and allow external AI: sudo zyb-virt-ai --allow-external'),
      ] });
    }
    {
      const C = app.addons && app.addons.virtCapacity; let rep = null; try { rep = C ? C.report() : null; } catch (e) { rep = null; }
      const P2 = rep ? rep.platforms : [], bad = P2.filter((p) => p.error), noLogin = P2.filter((p) => !p.credentials_set);
      const raw = app.store.collection('virt_capacity').all(), noHealth = raw.filter((m) => m.kind !== 'nutanix' && m.health && Object.values(m.health).some((v) => v === false));
      const coresMissing = rep ? rep.hosts.filter((h) => !h.cores) : [];
      out.push({ id: 'virt', name: 'AI Virtualization Administrator', engine: 'itam', checks: [
        chk('Capacity collection', !!C, C ? 'installed' : 'not installed', 'Re-run the update (add-virt-capacity.sh) - the administrator reads vCenter / Prism through it'),
        chk('Platforms connected', P2.length ? noLogin.length === 0 : false, P2.length ? P2.length + ' platform(s): ' + P2.map((p) => p.label + ' (' + p.kind + ')').join(', ') : 'no vCenter / Prism on the Virtualization page or in Asset Discovery', 'Virtualization → add each vCenter and Prism with a read-only account (a vCenter / Nutanix credential already saved in Asset Discovery is used automatically)'),
        chk('Last collection', P2.length ? bad.length === 0 && P2.every((p) => p.collected) : null, bad.length ? bad.map((p) => p.label + ': ' + p.error).join('; ') : P2.length ? P2.filter((p) => p.collected).length + ' of ' + P2.length + ' collected' : '', 'Virtualization → Capacity → Collect now; fix the login / certificate / privilege named'),
        chk('Health read', raw.length ? noHealth.length === 0 : null, noHealth.length ? noHealth.map((m) => m.label).join(', ') + ': some health properties refused (snapshots / HA / Tools not checked)' : raw.length ? 'status, HA, snapshots, Tools read' : '', 'Give the vCenter collection account the Read-only role at the root object, propagated to children'),
        chk('Host cores readable', rep && rep.hosts.length ? coresMissing.length === 0 : null, rep ? (rep.hosts.length - coresMissing.length) + ' of ' + rep.hosts.length + ' hosts with sockets / cores' : '', 'Same read-only role on the hosts; until then the core licence audit is incomplete'),
        (() => { const s = VAI ? VAI.status() : null; return chk('AI analysis (Claude)', s ? s.enabled : null, s ? (s.enabled ? 'on - ' + s.model + '; Investigate with AI on each work item, Ask on the page' : s.reason) : 'optional module not installed', s && !s.enabled ? (/external AI/.test(s.reason) ? ('Once ' + ZYB_ORG.short + ' approves sending virtualization inventory to Anthropic: sudo zyb-virt-ai --allow-external') : 'sudo zyb-virt-ai --set-key (the key is typed on the server, never in chat or e-mail)') : ''); })(),
        chk('Changes', null, 'change plans only: an administrator approves (not the requester), a person applies - by design', ''),
      ].concat(duty('virt')) });
    }
    if (SQ) {
      const v = SQ.view(), errs = v.servers.filter((x) => x.error), ai = SQ.aiStatus();
      out.push({ id: 'sqldba', name: 'AI Database Administrator (SQL Server · PostgreSQL · MySQL)', engine: 'itam', checks: [
        chk('Database inventory', !!DI, DI ? 'installed' : 'not installed', 'Re-run the update (the database inventory ships with IT Asset Management)'),
        v.servers.length ? chk('Servers read', errs.length === 0, (v.servers.length - errs.length) + ' of ' + v.servers.length + ' read' + (errs.length ? ' - ' + errs.map((x) => x.name + ': ' + x.error).join('; ') : ''), 'Fix the login of each server above (Asset Discovery → Credentials), then Databases → Read now')
          : chk('Database logins', false, 'no SQL Server / PostgreSQL / MySQL login proven yet', 'Databases → ＋ Add database (the read-only login script), or Asset Discovery → Credentials; then run a scope that covers the server'),
        chk('AI analysis (Claude)', ai.enabled, ai.enabled ? 'on - ' + ai.model + '; Investigate with AI on each work item, Ask on the page' : ai.reason, ai.enabled ? '' : 'An administrator allows external AI and stores the API key (sudo zyb-virt-ai --set-key); the engineer keeps working on its rules without it'),
        chk('Changes', null, 'recommends only: every fix is a statement for a DBA to review and run - by design', ''),
      ].concat(duty('sqldba')) });
    }
    if (grcEng) {
      let gs = null, gaps = null; try { gs = G.summary(); gaps = await grcEng.current(); } catch (e) { gs = null; }
      const ctl = gs ? Object.values(gs.control_status || {}) : [], measured = ctl.filter((v) => v && (v.state || v.status) && (v.state || v.status) !== 'unknown').length;
      const ow = app.addons && app.addons.ownership ? app.addons.ownership.summary() : null, prov = app.provider ? await app.provider.status().catch(() => ({ state: 'error' })) : null;
      out.push({ id: 'grc', name: 'AI GRC Consultant', engine: 'itam', checks: [
        chk('GRC records readable', !!gs, gs ? (gs.total || (G.register({}).items || []).length) + ' policies in the register' + (gaps ? ', ' + gaps.length + ' open gap(s)' : '') : 'GRC module not answering', 'Re-run the update (add-grc.sh installs the GRC module)'),
        chk('Controls measured', gs ? measured > 0 : null, gs ? measured + ' of ' + ctl.length + ' automated controls report a result' : '', 'Connect the sources the GRC controls read (SIEM link, backup, discovery); unknown controls are never counted as passing'),
        chk('Asset ownership', ow ? true : false, ow ? ow.both_pct == null ? 'no active assets yet' : ow.both_pct + '% of assets have both owners' : 'ownership module not installed', 'Re-run the update (add-ownership.sh)'),
        chk('SAMA gaps from the SIEM', app.addons && app.addons.ciso ? null : false, app.addons && app.addons.ciso ? 'read through the AI CISO when the SIEM link answers' : 'AI CISO not installed', 'Re-run the update (add-ciso.sh)'),
        chk('AI answers', prov ? prov.state === 'ready' : false, prov ? (prov.state === 'ready' ? 'AI provider ready (' + (prov.provider === 'anthropic' ? 'Claude ' : '') + (prov.model || '') + ')' : 'AI provider ' + (prov.message || prov.state) + ' - questions get the rule-based answer') : 'no AI provider - questions get the rule-based answer', prov && prov.state === 'external_not_allowed' ? ('Once ' + ZYB_ORG.short + ' approves sending GRC records to Anthropic: sudo zyb-virt-ai --allow-external') : 'Store the Claude API key on the server: sudo zyb-virt-ai --set-key (or --from-siem); a private model can be set in config.ai.private_url instead'),
      ].concat(duty('grc')) });
    }
    for (const id of (AU ? ['itaudit', 'cyberaudit'] : [])) {
      const p = AU.programme(id, false), A2 = app.addons || {};
      const src = id === 'itaudit' ? [['Audit trail', !!app.store.verifyAudit], ['Roles & Functions', !!app.roles], ['Backup / patch / contracts', !!(A2.backup || A2.manageengine || A2.supportContracts)]]
        : [['End of life', !!A2.lifecycle], ['Security testing schedule', !!(A2.pentest && A2.pentest.cadence)], ['SIEM link (through the AI CISO)', !!A2.ciso], ['Credential evidence', !!A2.credPosture]];
      out.push({ id, name: p.name, engine: 'itam', checks: [
        chk('Tests that can run', p.last_run ? p.tested > 0 : null, p.last_run ? p.tested + ' of ' + p.tests.length + ' tests had evidence at the last run' + (p.counts.not_tested ? ' - ' + p.counts.not_tested + ' not tested (source not connected)' : '') : 'first audit run pending', 'Connect the sources named on AI Auditors under "not tested"; a test without evidence is never passed'),
      ].concat(src.map((x) => chk(x[0], x[1] ? true : null, x[1] ? 'installed' : 'not installed - its tests are not tested', ''))).concat([chk('Independence', null, 'read-only: tests and reports, proposes nothing for execution, approves nothing - by design', '')]).concat(duty(id)) });
    }
    if (PD) {
      let a = null, perr = ''; try { a = await PD.assess(); } catch (e) { perr = e.message; }
      const P = (PD.records('profile')[0]) || null, n = (k) => PD.records(k).length;
      out.push({ id: 'pdpl', name: 'AI PDPL Consultant', engine: 'itam', checks: [
        chk('PDPL rules (Python)', !perr, perr || 'answering (pyengine/pdpl_rules.py)', 'Run the update so pyengine and Python 3 are installed on the server'),
        chk('PDPL pages installed', !!(PD.workflows && PD.access && PD.catalog && PD.ropaCampaigns && app.addons.privacyOffice), 'missing: ' + ([!PD.workflows && 'engine/pdpl-workflows.js', !PD.access && 'engine/pdpl-access.js', !PD.catalog && 'engine/pdpl-catalog.js', !PD.ropaCampaigns && 'engine/pdpl-ropa.js', !app.addons.privacyOffice && 'engine/pdpl-office.js'].filter(Boolean).join(', ') || 'none'), 'Re-run the update (update-platform.ps1): add-duty.sh installs engine/pdpl*.js'),
        chk('PDPL profile', !!(P && P.dpo_user), P && P.dpo_user ? 'DPO ' + P.dpo_user + (P.sdaia_ref ? ', SDAIA registration ' + P.sdaia_ref : ', SDAIA registration not recorded') : 'no DPO recorded', 'AI PDPL Consultant → Registers → Profile: name the DPO, record the SDAIA registration and the privacy policy (admin)'),
        chk('Records of processing', n('ropa') ? true : false, n('ropa') + ' processing activit(ies), ' + n('dsr') + ' request(s), ' + n('breach') + ' breach(es), ' + n('processor') + ' processor(s), ' + n('transfer') + ' transfer(s)', 'AI PDPL Consultant → Registers → add the processing activities'),
        chk('Requirements confirmed', a ? a.counts.compliant + a.counts.not_applicable === a.requirements.length : null, a ? (a.counts.compliant + a.counts.not_applicable) + ' of ' + a.requirements.length + ' confirmed by a person' : '', 'The DPO confirms each requirement with its evidence'),
        chk('Signs nothing', null, 'the DPO signs the statement and a different person countersigns; not an SDAIA certificate - by design', ''),
      ].concat(duty('pdpl')) });
    }
    if (ND) {
      let v = null, nerr = ''; try { v = await ND.view(); } catch (e) { nerr = e.message; }
      out.push({ id: 'ndmo', name: 'AI Data Governance Officer', engine: 'itam', checks: [
        chk('NDMO rules (Python)', !nerr, nerr || 'answering (pyengine/ndmo_rules.py)', 'Run the update so pyengine and Python 3 are installed on the server'),
        chk('Chief Data Officer', v ? !!v.profile.cdo_user : null, v && v.profile.cdo_user ? v.profile.cdo_user : 'not named', 'NDMO page → Profile: name the Chief Data Officer (administrator)'),
        chk('Official NDMO control list', v ? v.official_total > 0 : null, v ? v.official_total + ' official control(s) imported, ' + v.coverage.unmapped + ' not mapped' : '', 'NDMO page → Official list: import the controls from the NDMO standard and map them'),
        chk('PDPL link', v ? v.pdpl.available : null, v && v.pdpl.available ? 'the Personal Data Protection domain reads the PDPL register (' + v.pdpl.compliance_pct + '%)' : 'the AI PDPL Consultant is not answering', 'Run the update so the AI PDPL Consultant is installed'),
        chk('Approves nothing', null, 'a person records each control and a second person approves it - by design', ''),
      ].concat(duty('ndmo')) });
    }
    if (EC) {
      let v = null, eerr = ''; try { v = await EC.view(); } catch (e) { eerr = e.message; }
      const off = v ? v.sources.filter((x) => !x.connected).map((x) => x.id) : [];
      out.push({ id: 'nca-ecc', name: 'AI Cybersecurity Compliance Officer', engine: 'itam', checks: [
        chk('NCA ECC rules (Python)', !eerr, eerr || 'answering (pyengine/nca_ecc_rules.py)', 'Run the update so pyengine and Python 3 are installed on the server'),
        chk('CISO named', v ? !!v.profile.ciso_user : null, v && v.profile.ciso_user ? v.profile.ciso_user : 'not named', 'NCA ECC page → Profile: name the CISO (administrator)'),
        chk('Evidence sources', v ? !off.length : null, v ? (off.length ? 'not connected: ' + off.join(', ') : 'every source answering') : '', 'Connect the sources named; their controls read "not measured" until then'),
        chk('Official ECC control list', v ? v.official_total > 0 : null, v ? v.official_total + ' official control(s) imported, ' + v.coverage.unmapped + ' not mapped' : '', 'NCA ECC page → Official list: import the controls from the ECC document and map them'),
        chk('Approves nothing', null, 'a person records each manual control and a second person approves it - by design', ''),
      ].concat(duty('nca-ecc')) });
    }
    if (ISO) {
      let v = null, ierr = ''; try { v = await ISO.view(); } catch (e) { ierr = e.message; }
      const pg = ISO.programme();
      out.push({ id: 'iso27001', name: 'AI ISO 27001 Lead Implementer', engine: 'itam', checks: [
        chk('ISO 27001 rules (Python)', !ierr, ierr || 'answering (pyengine/iso27001_rules.py)', 'Run the update so pyengine and Python 3 are installed on the server'),
        chk('ISMS manager named', v ? !!v.profile.isms_manager : null, v && v.profile.isms_manager ? v.profile.isms_manager : 'not named', 'ISO 27001 page → Profile: name the ISMS manager (administrator)'),
        chk('Scope approved', v ? !!v.profile.scope_approved : null, v && v.profile.scope_approved ? 'approved ' + v.profile.scope_approved : 'not approved', 'ISO 27001 page → Profile: write and approve the ISMS scope - the audit programme then plans itself'),
        chk('Internal audit programme', pg.audits.length > 0, pg.audits.length + ' audit(s) planned', 'ISO 27001 page → Internal audit programme → Plan'),
        chk('Approves nothing', null, 'people approve confirmations, the SoA, audit reports and corrective actions - by design', ''),
      ].concat(duty('iso27001')) });
    }
    for (const [T, page] of [[IAD, 'Internal Audit Team'], [IA, 'IT Audit Team'], [CSA, 'Cyber Security Audit Team']]) {
      if (!T) continue;
      const pr = T.profile(), ai = T.aiStatus(), id = T.adapter.id;
      out.push({ id, name: T.adapter.name, engine: 'itam', checks: [
        chk('Head of Audit named', !!pr.head_of_audit, pr.head_of_audit || 'not named', page + ' page → Profile: name the Head of Audit and the auditors (administrator)'),
        chk('Audit plan', T.plans().some((p) => p.state === 'approved') ? true : null, T.plans().map((p) => p.id + ' ' + p.state).join(', ') || 'no plan yet', page + ' page → Plan: propose this year\'s plan and submit it to the Head of Audit'),
        chk('Ask the auditor (AI)', ai.enabled ? true : null, ai.enabled ? 'on (' + ai.model + ')' : ai.reason, 'Optional: allow external AI and store an API key'),
        chk('Signs nothing', null, 'the lead auditor signs and the Head of Audit approves reports, plans and risk acceptances - by design', ''),
      ].concat(duty(id)) });
    }
    if (NH) {
      let v = null, herr = ''; try { v = await NH.view(); } catch (e) { herr = e.message; }
      const off = v ? v.sources.filter((x) => !x.connected) : [];
      out.push({ id: 'nhi', name: 'AI Identity Security Engineer', engine: 'itam', checks: [
        chk('NHI rules (Python)', !herr, herr || 'answering (pyengine/nhi_rules.py)', 'Run the update so pyengine and Python 3 are installed on the server'),
        chk('Identity sources', v ? !off.length : null, v ? (off.length ? off.map((x) => x.name + ': ' + x.reason).join('; ') : 'directory, Entra and this platform all answering') : '', 'Update the SIEM and connect AD / Microsoft Graph on it (Application.Read.All for app registrations)'),
        chk('Owners recorded', v ? v.counts.no_owner === 0 : null, v ? v.counts.no_owner + ' of ' + v.counts.total + ' identities have no owner' : '', 'Non-Human Identities page: record an owner (a person) for each'),
        chk('Changes nothing', null, 'never disables an account or rotates a secret: decommissioning is approved by a second person and done by a person - by design', ''),
      ].concat(duty('nhi')) });
    }
    if (CE) {
      let a = null, perr = ''; try { a = await CE.assess(); } catch (e) { perr = e.message; }
      out.push({ id: 'pki', name: 'AI PKI Engineer', engine: 'itam', checks: [
        chk('Certificate rules (Python)', !perr, perr || 'answering (pyengine/cert_rules.py)', 'Run the update so pyengine and Python 3 are installed on the server'),
        chk('Endpoints registered', a ? a.endpoints.length > 0 : null, a ? a.endpoints.length + ' endpoint(s), ' + (a.counts['not-scanned'] || 0) + ' not scanned yet' : '', 'Certificates → Discover, then add the endpoints that matter'),
        (function () { const I = CE.issue ? CE.issue.issuers() : null; return chk('Issuance', I ? !!(I.acme || I.adcs) : false, I ? 'ACME ' + (I.acme ? I.acme.directory_url : 'not configured') + ' · AD CS ' + (I.adcs ? I.adcs.url : 'not configured') + ' · vault ' + I.vault : 'cert-issue.js not installed', 'Certificates → Issuers (admin): the ACME directory and / or the AD CS web enrolment URL'); })(),
        chk('Installation', null, 'phase 3 (installation as change plans a second person approves) is not built: certificates are exported and installed by hand', ''),
      ].concat(duty('pki')) });
    }
    if (!AU || !PD || !CLM) out.push({ id: 'modules', name: 'Newer AI engineers', engine: 'itam', checks: [chk('Installed', false, 'not installed: ' + [!AU && 'AI auditors (auditors.js)', !CLM && 'audit checklist (audit-checklist.js)', !PD && 'AI PDPL Consultant (pdpl.js)'].filter(Boolean).join(', '), 'Re-run the update (update-platform.ps1): add-duty.sh installs them')] });
    // the organisation's own engineers (Voice, Hyper-V, Aramco CCC): their module set up and patrolling
    const AD = app.addons || {};
    const own = [['voice', 'AI Voice Engineer (Cisco CUCM)', () => { const v = AD.cucm && AD.cucm.view(); return [chk('Call Manager connected', !!(v && v.status && v.status.configured), v && v.status && v.status.configured ? 'AXL login chosen' : 'no CUCM login chosen', 'Call Manager → Connection: pick the read-only AXL credential'), chk('Polled', v ? !!v.polled : false, v && v.polled ? 'last read ' + v.at : 'not polled yet', 'Call Manager → Poll now')]; }],
      ['hyperv', 'AI Hyper-V Administrator', () => { const v = AD.hypervManager && AD.hypervManager.view(); return [chk('Hosts reporting', v ? v.hosts.length > 0 : false, v ? v.hosts.length + ' host(s), ' + v.kpis.stale_hosts + ' not reporting' : 'module missing', 'On each Hyper-V host: install/hyperv-report.ps1 (read-only) as a scheduled task')]; }],
      ['aramco', 'AI Aramco CCC Officer', () => { const v = AD.aramcoCcc && AD.aramcoCcc.view({ user: 'system', role: 'viewer' }); return [chk('Scope recorded', v ? v.contracts.length > 0 : false, v ? v.contracts.length + ' Aramco contract(s)' : 'module missing', 'Aramco CCC → Scope: name the CCC owner and add the contracts'), chk('Controls imported', v ? v.controls_total > 0 : false, v ? v.controls_total + ' control(s)' : '', 'Aramco CCC → import the SACS-002 control list')]; }]];
    for (const [id, name, f] of own) { let c; try { c = f(); } catch (e) { c = [chk('Readable', false, e.message, 'run the platform update')]; } out.push({ id, name, engine: 'itam', checks: c.concat(duty(id)) }); }
    const offE = new Set(ALL_ENG ? [] : require('./brand').engineers_off || []);
    for (let i = out.length - 1; i >= 0; i--) if (offE.has(out[i].id)) out.splice(i, 1);
    for (const e of out) { const f = e.checks.filter((x) => x.ok === false); e.status = f.some((x) => /Assets|Endpoint Central|On duty|GRC records|Capacity collection|Platforms connected|PDPL rules|PDPL profile|Database logins/.test(x.name)) ? 'blocked' : f.length ? 'partial' : 'ready'; e.to_fix = f.map((x) => ({ name: x.name, fix: x.fix })); }
    return { generated: Date.now(), engineers: out, ready: out.filter((e) => e.status === 'ready').length, of: out.length };
  };
  // warm it once after start, so the update's first check (and the first visitor) finds a result rather than "computing"
  if (!opts.noTimer) { const warm = require('./errors').guardOf(app, 'duty.readiness.warm', async () => { if (!RD.inflight) RD.inflight = readinessNow().then((v) => { RD.val = v; RD.at = Date.now(); return { v }; }, (e) => ({ e })).finally(() => { RD.inflight = null; }); const r = await RD.inflight; if (r && r.e) throw r.e; });   // a failure is recorded by the guard
    const wt = setTimeout(warm, opts.readinessWarmMs || 3000); if (wt.unref) wt.unref(); }
  srv.route('GET', '/duty/readiness', async (ctx) => { ctx.need('viewer');
    if (!RD.inflight) RD.inflight = readinessNow().then((v) => { RD.val = v; RD.at = Date.now(); return { v }; }, (e) => {
      if (app.log && app.log.every) app.log.every('duty:readiness', 600000, 'warn', 'duty readiness failed', { error: e.message });
      return { e };   // handed to the waiting request below; kept as a value so a late failure is never an unhandled rejection
    }).finally(() => { RD.inflight = null; });
    let t = null; const r = await Promise.race([RD.inflight, new Promise((x) => { t = setTimeout(() => x(null), opts.readinessMs || 6000); })]); clearTimeout(t);
    if (r && r.e) throw r.e;
    if (r) return r.v;
    if (RD.val) return Object.assign({}, RD.val, { stale: true, note: 'Some sources are slow: this is the result from ' + new Date(RD.at).toISOString() + '; a fresh one is being computed.' });
    return { generated: Date.now(), computing: true, engineers: [], ready: 0, of: 0, note: 'Readiness is being computed (some sources are slow) - reload in a few seconds.' };
  });
  // team intelligence (engine/duty-intel.js, identical in the SIEM): precision, verified fixes, MTTR, backlog trend, trust, needs you
  srv.route('GET', '/duty/intel', (ctx) => { ctx.need('viewer'); return require('./duty-intel').analyse({ items: D.allItems(), engineers: Object.values(D.ENG).map((e) => ({ id: e.id, name: e.name })), now: (opts.now || Date.now)(), source: 'itam' }); });
  srv.route('GET', '/duty/engineers', async (ctx) => void ctx.need('viewer') || ({ engineers: await D.engineersAuto(), policy: D.policy(), close_codes: D.CLOSE_CODES }));
  // viewers see what is open and its state, not the evidence, the investigation or the history notes: those can carry
  // personal data (the desktop user, IP, OS) and device detail - PDPL, same rule as the desk support pages (operator)
  const forRole = (ctx, it) => (!it || (ctx.who && (ctx.who.role === 'operator' || ctx.who.role === 'admin')) ? it
    : Object.assign({}, it, { evidence: [], investigation: null, ai: null, history: (it.history || []).map((h) => ({ at: h.at, by: h.by, action: h.action })), note_hidden: 'evidence and investigation are shown to operators' }));
  srv.route('GET', '/duty/items', async (ctx) => { ctx.need('viewer'); const r = await D.listAuto(ctx.query || {}); return Object.assign({}, r, { items: (r.items || []).map((x) => forRole(ctx, x)) }); });
  srv.route('GET', '/duty/items/:id', (ctx) => void ctx.need('viewer') || forRole(ctx, D.get(ctx.params.id)));
  srv.route('POST', '/duty/items/:id/assign', (ctx) => { ctx.need('operator'); return D.assignAuto(ctx.params.id, b(ctx).owner, ctx.who.user); });
  srv.route('POST', '/duty/items/:id/note', (ctx) => { ctx.need('operator'); return D.noteAuto(ctx.params.id, b(ctx).text, ctx.who.user); });
  srv.route('POST', '/duty/items/:id/snooze', (ctx) => { ctx.need('operator'); return D.snoozeAuto(ctx.params.id, b(ctx).hours, b(ctx).reason, ctx.who.user); });
  srv.route('POST', '/duty/items/:id/close', (ctx) => { ctx.need('operator'); return D.closeAuto(ctx.params.id, b(ctx).code, b(ctx).reason, ctx.who.user); });
  srv.route('POST', '/duty/items/:id/investigate', (ctx) => { ctx.need('operator'); return D.investigate(ctx.params.id, ctx.who.user, { ai: b(ctx).ai === true }); });
  srv.route('POST', '/duty/patrol', async (ctx) => { ctx.need('operator'); const e = b(ctx).engineer; if (e) return D.patrol(e); const out = []; for (const x of D.engineers()) out.push(await D.patrol(x.id)); return { results: out }; });
  srv.route('GET', '/duty/reports', (ctx) => void ctx.need('viewer') || ({ reports: D.listReports((ctx.query || {}).engineer, (ctx.query || {}).limit) }));
  srv.route('POST', '/duty/reports', async (ctx) => { ctx.need('operator'); const e = b(ctx).engineer; return e ? { report: await D.makeReportAuto(e) } : { reports: await D.saveReportsAuto() }; });
  srv.route('GET', '/duty/kpis', async (ctx) => { ctx.need('viewer'); const q = ctx.query || {}, out = []; for (const e of (q.engineer ? [q.engineer] : Object.keys(D.ENG))) out.push(await D.kpisAuto(e, { days: q.days })); return { defaults: D.KPI_DEFAULTS, engineers: out }; });
  srv.route('GET', '/duty/policy', (ctx) => void ctx.need('viewer') || D.policy());
  srv.route('PUT', '/duty/policy', (ctx) => { ctx.need('admin'); return D.setPolicyAuto(b(ctx), ctx.who.user); });
  return D;
}

module.exports = { registerDuty, pentestAdapter, desktopAdapter, INTEL_MODULES };
