// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// REST API /api/itam/discovery/* (portal session via nginx; identity in X-Auth-User / X-Auth-Role). Every WRITE and every
// read of credential metadata needs the portal role admin ("System Admin"); operator and viewer get read-only results.
// Agent gateway: POST /agent/hyperv (per-agent bearer key) for Hyper-V inventory reports. Documented in docs/DISCOVERY.md.
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

function registerDiscoveryRoutes(srv, app) {
  const D = app.discovery;
  const admin = (ctx) => ctx.need('admin');
  const P = '/discovery';

  // dashboard + configuration (read: everyone)
  srv.route('GET', `${P}/dashboard`, (ctx) => void ctx.need('viewer') || D.dashboard());
  srv.route('GET', `${P}/methods`, (ctx) => void ctx.need('viewer') || ({ settings: D.settings(), active: ['sweep', 'snmp', 'db', 'unix', 'storage'], passive: ['arp', 'ad', 'vcenter', 'nutanix', 'hyperv', 'cucm', 'azure', 'aws'], credential_kinds: D.credentialKinds(), sites: D.sites() }));
  srv.route('POST', `${P}/methods`, (ctx) => { admin(ctx); return { settings: D.updateSettings(ctx.body, ctx.who) }; });

  // scopes
  srv.route('GET', `${P}/scopes`, (ctx) => void ctx.need('viewer') || ({ scopes: D.listScopes(ctx.query.archived === '1'), sites: D.sites() }));
  srv.route('POST', `${P}/scopes`, (ctx) => { admin(ctx); return { scope: D.createScope(ctx.body, ctx.who) }; });
  srv.route('GET', `${P}/scopes/:id`, (ctx) => void ctx.need('viewer') || ({ scope: D.getScope(ctx.params.id) }));
  srv.route('POST', `${P}/scopes/:id`, (ctx) => { admin(ctx); return { scope: D.updateScope(ctx.params.id, ctx.body, ctx.who) }; });
  for (const [act, st] of [['enable', 'active'], ['disable', 'disabled'], ['archive', 'archived']]) {
    srv.route('POST', `${P}/scopes/:id/${act}`, (ctx) => { admin(ctx); return { scope: D.setScopeStatus(ctx.params.id, st, ctx.who) }; });
  }
  srv.route('POST', `${P}/scopes/:id/checklist`, (ctx) => { admin(ctx); return { scope: D.completeChecklist(ctx.params.id, ctx.body, ctx.who) }; });
  srv.route('POST', `${P}/scopes/:id/checklist/revoke`, (ctx) => { admin(ctx); return { scope: D.revokeChecklist(ctx.params.id, ctx.who) }; });
  srv.route('POST', `${P}/scopes/:id/run`, (ctx) => { admin(ctx); return { run: D.startRun(ctx.params.id, { trigger: 'manual', who: ctx.who }) }; });

  // runs
  srv.route('GET', `${P}/runs`, (ctx) => void ctx.need('viewer') || ({ runs: D.listRuns(ctx.query) }));
  srv.route('GET', `${P}/runs/:id`, (ctx) => { ctx.need('viewer'); const r = D.getRun(ctx.params.id); if (!r) throw bad('run not found', 404); return { run: r }; });
  srv.route('POST', `${P}/runs/:id/cancel`, (ctx) => { admin(ctx); return { run: D.cancelRun(ctx.params.id, ctx.who) }; });

  // credentials (admin only — metadata included)
  srv.route('GET', `${P}/credentials`, (ctx) => { admin(ctx); return { credentials: D.credentials(), kinds: D.credentialKinds() }; });
  srv.route('POST', `${P}/credentials`, (ctx) => { admin(ctx); return { credential: D.createCredential(ctx.body, ctx.who) }; });
  srv.route('GET', `${P}/credentials/:id`, (ctx) => { admin(ctx); const c = D.credential(ctx.params.id); if (!c) throw bad('credential not found', 404); return { credential: c }; });
  srv.route('POST', `${P}/credentials/:id`, (ctx) => { admin(ctx); return { credential: D.updateCredential(ctx.params.id, ctx.body, ctx.who) }; });
  srv.route('POST', `${P}/credentials/:id/delete`, (ctx) => { admin(ctx); return D.deleteCredential(ctx.params.id, ctx.who); });
  srv.route('POST', `${P}/credentials/:id/test`, async (ctx) => { admin(ctx); return { result: await D.testCredential(ctx.params.id, ctx.body, ctx.who) }; });

  // results + review
  // trusted SSH host keys / storage certificates for the read-only logins (methods/login.js)
  srv.route('GET', `${P}/trust`, (ctx) => { admin(ctx); return { items: D.trustList({ state: ctx.query.state || '' }) }; });
  srv.route('POST', `${P}/trust`, (ctx) => { admin(ctx); const b = ctx.body || {}; if (!['trust', 'forget'].includes(b.action)) throw bad('action must be trust or forget'); return D.trustDecide(b.ids, b.action, ctx.who); });
  srv.route('GET', `${P}/login-helper`, async (ctx) => { admin(ctx); return { helper: await D.loginStatus() }; });
  srv.route('GET', `${P}/results`, (ctx) => void ctx.need('viewer') || D.results(ctx.query));
  srv.route('POST', `${P}/results/bulk`, (ctx) => { admin(ctx); return D.bulkResults(ctx.body, ctx.who); });
  srv.route('GET', `${P}/results/:id`, (ctx) => void ctx.need('viewer') || ({ device: D.result(ctx.params.id) }));
  srv.route('POST', `${P}/results/:id/approve`, (ctx) => { admin(ctx); return D.approve(ctx.params.id, ctx.who); });
  srv.route('POST', `${P}/results/:id/ignore`, (ctx) => { admin(ctx); return D.ignore(ctx.params.id, ctx.body.reason, ctx.who); });
  srv.route('POST', `${P}/results/:id/restore`, (ctx) => { admin(ctx); return D.restore(ctx.params.id, ctx.who); });
  srv.route('POST', `${P}/results/:id/merge`, (ctx) => { admin(ctx); return D.merge(ctx.params.id, ctx.body.asset_id, ctx.who); });

  // Hyper-V report upload (admin) — the agent route is below
  srv.route('GET', `${P}/hyperv/hosts`, (ctx) => void ctx.need('viewer') || D.hypervHosts());
  srv.route('POST', `${P}/hyperv/hosts/:host/forget`, (ctx) => { admin(ctx); return D.forgetHypervHost(ctx.params.host, ctx.who); });
  srv.route('POST', `${P}/hyperv/import`, (ctx) => { admin(ctx); return D.ingestHyperv(ctx.body.report || ctx.body, ctx.who, { scope_id: ctx.body.scope_id }); }, { maxBody: 4 * 1024 * 1024 });

  // SIEM log-coverage confirmation (read: everyone) — are discovered/approved assets actually sending logs?
  srv.route('GET', `${P}/log-coverage`, async (ctx) => void ctx.need('viewer') || await D.logCoverage());

  // SIEM connect
  srv.route('GET', `${P}/connect`, (ctx) => void ctx.need('viewer') || ({ connections: D.connections(), candidates: D.connectCandidates(), kinds: D.kinds() }));
  srv.route('POST', `${P}/connect`, async (ctx) => { admin(ctx); return D.connect(ctx.body.asset_id, { kind: ctx.body.kind }, ctx.who); });
  srv.route('POST', `${P}/connect/health`, async (ctx) => { admin(ctx); return { health: await D.health() }; });

  // audit (admin)
  srv.route('GET', `${P}/audit`, (ctx) => { admin(ctx); return { audit: D.auditTail(ctx.query.limit) }; });

  // agent gateway: Hyper-V inventory from the Windows agent / relay (per-agent key, no portal identity)
  srv.route('POST', '/hyperv', (ctx) => {
    const a = app.agentgw.authenticate(ctx.bearer());
    if (!a) throw bad('invalid or revoked agent key', 401);
    return D.ingestHyperv(ctx.body, { user: `agent:${a.id}`, role: 'agent', ip: ctx.ip }, { untrusted: true });
  }, { agent: true, maxBody: 4 * 1024 * 1024 });
}

module.exports = { registerDiscoveryRoutes };
