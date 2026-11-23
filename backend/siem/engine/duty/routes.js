// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI engineers' duty desk in the SIEM ({P} = /api/soc): the AI Network Engineer, AI Security Engineer (firewalls),
 * AI Windows Server Administrator, AI Exchange Server Administrator, AI Oracle DBA and AI Application Manager
 * (duty/app-adapters.js) and the AI SIEM Engineer (onboard/assurance.js: every asset that should log does, and the flow is
 * healthy) patrol, open work items, investigate, propose
 * fixes through the existing change workflow and verify them (engine/duty/duty-core.js explains the cycle).
 *   GET  {P}/duty/engineers                 viewer    each engineer: on duty, last patrol, open work, AI budget
 *   GET  {P}/duty/items?engineer&status     viewer    work items (status=open → everything not resolved/closed)
 *   GET  {P}/duty/items/:id                 viewer    one work item with its history
 *   POST {P}/duty/items/:id/assign          operator  {owner?}  (empty = me)
 *   POST {P}/duty/items/:id/note            operator  {text}
 *   POST {P}/duty/items/:id/snooze          operator  {hours, reason}
 *   POST {P}/duty/items/:id/close           operator  {code, reason}
 *   POST {P}/duty/items/:id/investigate     operator  {ai?}  run the investigation now (AI needs it enabled)
 *   POST {P}/duty/items/:id/ticket          operator  raise a ServiceDesk Plus request
 *   POST {P}/duty/patrol                    operator  {engineer}  patrol now
 *   GET  {P}/duty/reports?engineer          viewer    shift handover reports   POST {P}/duty/reports (operator) make one now
 *   GET  {P}/duty/policy (viewer) · PUT {P}/duty/policy (admin)
 * Nothing here changes a device or a server: the AI only records change plans, which an administrator approves and a
 * person applies (netops/sysadmin change workflow, four-eyes as before).
 */
const crypto = require('node:crypto');
const { wrap, audit, body, prefixOf } = require('../soc/routeutil');
const { createDuty, kindCount } = require('./duty-core');
const { dbaAdapter, appAdapter } = require('./app-adapters');
const { zscalerAdapter, kscAdapter } = require('./sec-adapters');

const FW_VENDORS = new Set(['fortigate', 'paloalto', 'cisco-asa']);
const maskDigits = (s) => String(s || '').toLowerCase().replace(/\d+(\.\d+)?/g, '#').replace(/\s+/g, ' ').trim();
const shortHash = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 10);

function netAdapters(N) {
  if (!N) return [];
  const dev = (id) => (N.inventory && N.inventory.get(id)) || null;
  const isFw = (d) => !!d && (FW_VENDORS.has(String(d.vendor || '').toLowerCase()) || String(d.role || '').toLowerCase() === 'firewall');
  const mk = (id, name, want, focus, kpis) => ({
    id, name, kpis,
    findings() {
      if (!N.inventory.list().length) return null;                       // nothing onboarded: not connected, not healthy
      return N.findings().filter((f) => want(dev(f.device))).map((f) => ({
        key: f.id, severity: f.severity, kind: f.kind, title: f.title, evidence: f.evidence, recommendation: f.recommendation,
        target: { type: 'device', id: f.device, name: f.device_name }, site: f.site,
      }));
    },
    async investigate(it) {
      const r = await N.diagnose({ device: it.target.id, symptom: it.title });
      return { summary: r.summary, checks: (r.checks || []).map((c) => ({ name: c.name, status: c.status, detail: c.detail })), causes: (r.causes || []).map((c) => ({ cause: c.cause, confidence: c.confidence, fix: c.fix })) };
    },
    aiStatus: () => N.ai.status(),
    aiInvestigate(it, { onChange }) {
      const q = `${focus}Duty-desk work item ${it.id} (${it.severity}): ${it.title}\nDevice: ${it.target.name} (${it.target.id}), site ${it.site || '-'}.\n`
        + `Evidence: ${(it.evidence || []).join(' | ') || '-'}\nAutomated diagnosis: ${(it.investigation && it.investigation.summary) || '-'}\n`
        + 'Investigate with your read-only tools like an on-duty network engineer: confirm the cause, state the impact, and if a configuration change is needed record it with propose_change (exact commands, prechecks, rollback). Do not claim anything was changed. End with a short "Next steps for the engineer" list.';
      return N.ai.ask({ question: q, user: 'duty:' + id, role: 'operator', by: 'duty desk, work item ' + it.id, requested_by: 'duty:' + id, onChange });
    },
    // a task the SIEM ran: executing = still approved; failed (rolled back) = back to a person
    changeStatus(cid) { const c = N.changes.get(cid); return c ? { status: c.status === 'executing' ? 'approved' : c.status === 'execution-failed' ? 'rejected' : c.status, comment: c.status === 'execution-failed' ? 'the task failed on the device' + (c.rollback_failed ? ' and the ROLLBACK FAILED' : ' and was rolled back') : c.comment } : null; },
    async verify(it) {
      await N.poller.pollDevice(it.target.id);
      const present = N.findings().some((f) => f.id === it.key);
      return { present, note: present ? 'still reported after a fresh poll of ' + it.target.name : 'a fresh poll of ' + it.target.name + ' no longer reports it' };
    },
  });
  return [
    mk('network', 'AI Network Engineer', (d) => !isFw(d), '', (open) => {
      const n = N.inventory.list().filter((d) => !isFw(d)).length, down = kindCount(open, ['unreachable'], true);
      return [{ label: 'Device availability', value: n ? Math.round((n - down) / n * 1000) / 10 : null, unit: '%', target: 99, dir: 'min' },
        { label: 'Devices not reachable', value: down, target: 0 }, { label: 'Links, tunnels, SD-WAN paths or neighbours down', value: kindCount(open, ['if-down', 'tunnel-down', 'path-down', 'neighbor-down']), target: 0 },
        { label: 'Links over the utilisation limit', value: kindCount(open, ['utilization']), target: 0 }, { label: 'Devices with high CPU / memory', value: kindCount(open, ['cpu', 'memory'], true), target: 0 },
        { label: 'Support / subscriptions expired', value: kindCount(open, ['support-expired', 'license-expired']), target: 0 }];
    }),
    mk('security', 'AI Security Engineer', (d) => isFw(d), 'About the Palo Alto / FortiGate firewalls only. ', (open) => [
      { label: 'Risky rules / security findings open', value: kindCount(open, ['sec-*']), target: 0 }, { label: 'Firewalls not reachable', value: kindCount(open, ['unreachable'], true), target: 0 },
      { label: 'HA clusters out of sync', value: kindCount(open, ['ha-sync'], true), target: 0 }, { label: 'Security subscriptions / support expired', value: kindCount(open, ['support-expired', 'license-expired']), target: 0 }]),
  ];
}

function sysAdapters(S) {
  if (!S) return [];
  const keyOf = (f) => `${f.server}:${f.kind}:${shortHash(maskDigits(f.title))}`;
  const mk = (role, name, kpis) => ({
    id: role, name, kpis,
    findings() {
      if (!S.targets.list(role).length) return null;              // no server of this role onboarded: not connected
      return S.health.findings({ role }).map((f) => ({ key: keyOf(f), severity: f.severity, kind: f.kind, title: f.title, evidence: f.evidence, recommendation: f.recommendation,
        target: { type: 'server', id: f.server, name: f.server_name }, site: f.site }));
    },
    investigate(it) {
      const snap = S.health.snapshot ? S.health.snapshot(it.target.id) : null;
      const failing = snap && snap.results ? Object.entries(snap.results).filter(([, r]) => r && r.error).map(([k, r]) => ({ name: k, status: 'fail', detail: r.error })) : [];
      return {
        summary: `${it.title}. ${it.recommendation || ''}`.trim(),
        checks: (it.evidence || []).map((e) => ({ name: 'evidence', status: 'warn', detail: e })).concat(failing).concat(snap && snap.at ? [{ name: 'last health check', status: 'ok', detail: new Date(snap.at).toISOString() }] : []),
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }],
      };
    },
    aiStatus: () => S.ai.status(),
    aiInvestigate(it, { onChange }) {
      const q = `Duty-desk work item ${it.id} (${it.severity}): ${it.title}\nServer: ${it.target.name} (${it.target.id}).\nEvidence: ${(it.evidence || []).join(' | ') || '-'}\n`
        + 'Investigate with your read-only checks like an on-duty administrator: confirm the cause and the impact, and if a change is needed record it with propose_change (exact PowerShell, precheck, rollback). Do not claim anything was changed. End with "Next steps for the administrator".';
      return S.ai.ask({ role, question: q, user: 'duty:' + role, userRole: 'operator', by: 'duty desk, work item ' + it.id, requested_by: 'duty:' + role, onChange });
    },
    changeStatus(cid) { const c = S.changes.get(cid); return c ? { status: c.status, comment: c.comment } : null; },
    async verify(it) {
      await S.health.pollServer(it.target.id);
      const present = S.health.findings({ role }).some((f) => keyOf(f) === it.key);
      return { present, note: present ? 'still reported after re-checking ' + it.target.name : 're-checking ' + it.target.name + ' no longer reports it' };
    },
  });
  return [
    mk('windows', 'AI Windows Server Administrator', (open) => [
      { label: 'Servers with critical findings', value: new Set(open.filter((x) => x.severity === 'critical').map((x) => x.target && x.target.id)).size, target: 0 },
      { label: 'Servers missing patches', value: kindCount(open, ['patch'], true), target: 0 }, { label: 'Servers waiting for a reboot', value: kindCount(open, ['reboot'], true), target: 0 },
      { label: 'Disks over the limit', value: kindCount(open, ['disk']), target: 0 }, { label: 'Automatic services stopped', value: kindCount(open, ['service']), target: 0 },
      { label: 'Servers that cannot be checked', value: kindCount(open, ['cannot-check'], true), target: 0 }]),
    mk('exchange', 'AI Exchange Server Administrator', (open) => [
      { label: 'Mail queue / DAG copy problems', value: kindCount(open, ['ex-queue', 'ex-copy', 'ex-copy-queue']), target: 0 }, { label: 'Databases not mounted / healthy', value: kindCount(open, ['ex-database']), target: 0 },
      { label: 'Certificates expiring', value: kindCount(open, ['ex-certificate', 'certificate']), target: 0 }, { label: 'Exchange services stopped', value: kindCount(open, ['ex-service']), target: 0 },
      { label: 'Database backups overdue', value: kindCount(open, ['ex-backup']), target: 0 }]),
  ];
}

function ticketerFor(me, duty) {
  if (!me || typeof me.registerKind !== 'function') return null;
  const SEVN = { low: 1, medium: 2, high: 3, critical: 4 };
  me.registerKind('duty', {
    get: (id) => { try { return duty().get(id); } catch (e) { return null; } },
    severity: (o) => SEVN[o.severity] || 2,
    subject: (o) => `[${o.engineer_name}] ${o.title}`,
    description: (o) => [
      `${o.engineer_name} - work item ${o.id} (${o.severity})`, `Target: ${(o.target && o.target.name) || '-'}${o.site ? ' · site ' + o.site : ''}`, '',
      'Evidence:', ...(o.evidence || []).map((e) => '  ' + e), '', `Recommendation: ${o.recommendation || '-'}`,
      o.investigation ? `\nDiagnosis: ${o.investigation.summary}` : '', (o.changes || []).length ? `\nChange plans (for approval in the portal): ${o.changes.join(', ')}` : '',
      '', 'Raised by the platform duty desk. Nothing was changed automatically.',
    ].join('\n'),
    note: (id, text) => { try { duty().note(id, text, 'manageengine'); } catch (e) { /* item gone */ } },
  });
  return { create: (id, by) => me.createTicket({ kind: 'duty', id, by }) };
}

function register(api, deps) {
  if (!deps.state) throw new Error('duty desk needs deps.state');
  const P = prefixOf(deps), cfg = (deps.config && deps.config.duty) || {};
  let D = null;
  const N0 = deps.netopsInstance || deps.netops;
  const engineers = netAdapters(N0).concat(sysAdapters(deps.sysadminInstance || deps.sysadmin))
    .concat(dbaAdapter(deps.oracle, deps.oracle_perf)).concat(appAdapter(N0 && N0.availability))
    .concat(zscalerAdapter(deps.zscalerInstance)).concat(kscAdapter(deps.kscInstance))   // Zscaler + Kaspersky KSC (registered before this module)
    .concat(deps.collectionAssurance ? [deps.collectionAssurance.adapter] : []);   // AI SIEM Engineer: log-flow assurance (onboard/assurance.js)
  const ticketer = ticketerFor(deps.integrations && deps.integrations.manageengine, () => D);
  D = deps.duty || createDuty({ store: deps.state, log: deps.log, engineers, ticketer,
    audit: (action, target, detail) => { try { if (deps.state.audit) deps.state.audit({ action, target, detail, by: (detail && detail.by) || 'duty' }); } catch (e) { /* audit is best-effort */ } },
    policyDefaults: cfg.policy,
    // the duty rules in Python (duty_rules.py, step 7 of the Python migration); duty.engine = "node" switches back
    python: cfg.engine === 'node' ? null : [cfg.python, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => require('node:fs').existsSync(p)) || 'python3' });
  deps.dutyInstance = D;
  if (cfg.enabled !== false && !deps.duty) D.start();
  const run = (fn) => fn;   // wrap() already answers coded errors (400/403/404/409/503) with their message

  api.route('GET', `${P}/duty/readiness`, wrap(deps, null, run(() => require('./readiness').readiness(deps, D))));
  // team intelligence (duty-intel.js, identical in IT Asset Management): precision, verified fixes, MTTR, backlog trend, trust, needs you
  api.route('GET', `${P}/duty/intel`, wrap(deps, null, run(() => require('./duty-intel').analyse({ items: D.allItems(), engineers: Object.values(D.ENG).map((e) => ({ id: e.id, name: e.name })), now: (deps.now || Date.now)(), source: 'siem' }))));
  api.route('GET', `${P}/duty/engineers`, wrap(deps, null, run(async () => ({ engineers: await D.engineersAuto(), policy: D.policy(), close_codes: D.CLOSE_CODES }))));
  api.route('GET', `${P}/duty/items`, wrap(deps, null, run((ctx) => D.listAuto(ctx.query || {}))));
  // the AI's answer and the history notes can quote device configuration or name people (message trace, local admins):
  // operators and admins only - viewers and analysts see the item, its state and the evidence
  const OPS = new Set(['operator', 'admin']);
  api.route('GET', `${P}/duty/items/:id`, wrap(deps, null, run((ctx) => {
    const it = D.get(ctx.params.id); if (!it || OPS.has(String(ctx.role || '').toLowerCase())) return it;
    return Object.assign({}, it, { ai: it.ai ? { at: it.ai.at, model: it.ai.model, answer: null, note: 'the AI answer is shown to operators' } : null, history: (it.history || []).map((h) => ({ at: h.at, by: h.by, action: h.action })) });
  })));
  api.route('POST', `${P}/duty/items/:id/assign`, wrap(deps, 'operator', run((ctx) => D.assignAuto(ctx.params.id, body(ctx).owner, ctx.user))));
  api.route('POST', `${P}/duty/items/:id/note`, wrap(deps, 'operator', run((ctx) => D.noteAuto(ctx.params.id, body(ctx).text, ctx.user))));
  api.route('POST', `${P}/duty/items/:id/snooze`, wrap(deps, 'operator', run((ctx) => { const b = body(ctx); return D.snoozeAuto(ctx.params.id, b.hours, b.reason, ctx.user); })));
  api.route('POST', `${P}/duty/items/:id/close`, wrap(deps, 'operator', run((ctx) => { const b = body(ctx); return D.closeAuto(ctx.params.id, b.code, b.reason, ctx.user); })));
  api.route('POST', `${P}/duty/items/:id/investigate`, wrap(deps, 'operator', run(async (ctx) => { const it = await D.investigate(ctx.params.id, ctx.user, { ai: body(ctx).ai === true }); audit(ctx, 'duty.investigate', ctx.params.id, { ai: body(ctx).ai === true }); return it; })));
  api.route('POST', `${P}/duty/items/:id/ticket`, wrap(deps, 'operator', run((ctx) => D.ticket(ctx.params.id, ctx.user))));
  api.route('POST', `${P}/duty/patrol`, wrap(deps, 'operator', run(async (ctx) => { const e = body(ctx).engineer; audit(ctx, 'duty.patrol', e || 'all', {}); if (e) return D.patrol(e); const out = []; for (const x of D.engineers()) out.push(await D.patrol(x.id)); return { results: out }; })));
  api.route('GET', `${P}/duty/reports`, wrap(deps, null, run((ctx) => ({ reports: D.listReports((ctx.query || {}).engineer, (ctx.query || {}).limit) }))));
  api.route('POST', `${P}/duty/reports`, wrap(deps, 'operator', run(async (ctx) => { const e = body(ctx).engineer; return e ? { report: await D.makeReportAuto(e) } : { reports: await D.saveReportsAuto() }; })));
  api.route('GET', `${P}/duty/kpis`, wrap(deps, null, run(async (ctx) => { const q = ctx.query || {}, out = []; for (const e of (q.engineer ? [q.engineer] : Object.keys(D.ENG))) out.push(await D.kpisAuto(e, { days: q.days })); return { defaults: D.KPI_DEFAULTS, engineers: out }; })));
  api.route('GET', `${P}/duty/policy`, wrap(deps, null, run(() => D.policy())));
  api.route('PUT', `${P}/duty/policy`, wrap(deps, 'admin', run(async (ctx) => { const p = await D.setPolicyAuto(body(ctx), ctx.user); audit(ctx, 'duty.policy', 'policy', p); return p; })));
}

module.exports = { register, netAdapters, sysAdapters, ticketerFor, maskDigits };
