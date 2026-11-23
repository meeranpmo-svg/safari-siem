// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Application Audit (engine/netops/app-audit.js): one application (an availability group) - resilience (single server /
// no DR), availability under 99 %, change plans on its servers with four-eyes evidence (a self-approved user plan is a
// finding), failed-logon burst, cleared security log, account changes, and log coverage (a server with no log in the period
// is a finding). ClickHouse is asked for exactly the application's servers by short host name and IP.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createAppAudit, changeMatches } = require('../engine/netops/app-audit');

const NOW = Date.UTC(2026, 9, 20, 12);
function fakeState(cols) { return { collection: (n) => ({ all: (f) => (cols[n] || []).filter((x) => !f || f(x)) }) }; }

test('application audit: resilience, availability, changes (four eyes), security activity, log coverage', async () => {
  const items = [
    { id: 'erp-app1', name: 'ERP-APP1.corp.local', ip: '10.1.1.11', status: 'online', role: 'primary', availability: { d1: 100, d7: 99.9, d30: 99.95 }, flags: [], days_since_boot: 12 },
    { id: 'erp-app2', name: 'ERP-APP2', ip: '10.1.1.12', status: 'offline', role: 'secondary', availability: { d1: 60, d7: 90, d30: 96.5 }, flags: ['offline', 'reboot-overdue'], days_since_boot: 70, unexpected_shutdowns_30d: 2 },
    { id: 'hr-web01', name: 'HR-WEB01', ip: '10.1.2.5', status: 'online' },
  ];
  const groups = [{ key: 'svc:erp', name: 'ERP', members: ['erp-app1', 'erp-app2'], issues: ['no-redundancy-now', 'no-dr'], status: 'degraded', critical: true, ha: true, production: 2, dr: 0 }, { key: 'auto:hr-web', name: 'HR-WEB', members: ['hr-web01'], issues: ['single-server'] }];
  const av = { view: async () => ({ items, groups }) };
  const state = fakeState({
    sysadmin_changes: [
      { id: 'SCHG-000001', device: 'erp-app1', title: 'Install KB5031356', status: 'validated', source: 'user', proposed_by: 'siva', proposed_at: NOW - 86400000, decided_by: 'syed', decided_at: NOW - 80000000, applied_by: 'siva', applied_at: NOW - 70000000 },
      { id: 'SCHG-000002', device: '10.1.1.12', title: 'Disable SMBv1', status: 'applied', source: 'user', proposed_by: 'rasheed', proposed_at: NOW - 3600000, decided_by: 'Rasheed', decided_at: NOW - 3000000, applied_by: 'rasheed', applied_at: NOW - 2000000 },
      { id: 'SCHG-000003', device: 'hr-web01', title: 'other app', status: 'approved', proposed_at: NOW - 3600000 },
      { id: 'SCHG-000004', device: 'erp-app1', title: 'old', status: 'validated', proposed_at: NOW - 60 * 86400000, decided_at: NOW - 60 * 86400000, applied_at: NOW - 59 * 86400000 },
    ],
    netops_changes: [],
    avail_events: [{ host: 'erp-app2', at: NOW - 7200000, from: 'online', to: 'offline' }, { host: 'hr-web01', at: NOW - 7200000, to: 'offline' }],
  });
  const asked = [];
  const ch = { query: async (sql, P) => {
    asked.push({ sql, P });
    if (/app-audit:coverage/.test(sql)) return [{ h: 'erp-app1', ip: '10.1.1.11', c: '5400', t: '2026-10-20 11:59:00.000' }];
    const ev = [];
    for (let i = 0; i < 25; i++) ev.push({ ts: '2026-10-20 10:00:00.000', host: 'ERP-APP1', host_ip: '10.1.1.11', category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: 2, user: 'svc_erp', src_ip: '10.9.9.9', event_code: '4625', message: 'An account failed to log on' });
    ev.push({ ts: '2026-10-20 03:10:00.000', host: 'ERP-APP1', host_ip: '10.1.1.11', category: 'policy', action: 'audit-log-cleared', outcome: 'success', severity: 4, user: 'administrator', event_code: '1102', message: 'The audit log was cleared' });
    ev.push({ ts: '2026-10-20 03:05:00.000', host: 'ERP-APP1', host_ip: '10.1.1.11', category: 'iam', action: 'group-member-added', outcome: 'success', severity: 3, user: 'administrator', event_code: '4732', message: 'A member was added to Administrators' });
    return ev;
  } };
  const A = createAppAudit({ av, state, ch, now: () => NOW });
  const L = await A.list(); assert.deepEqual(L.applications.map((a) => a.name), ['ERP', 'HR-WEB']); assert.equal(L.applications[0].online, 1);
  const r = await A.report({ app: 'svc:erp', hours: 168 });
  assert.deepEqual(asked[0].P.names.value, ['erp-app1', 'erp-app2']); assert.deepEqual(asked[0].P.ips.value, ['10.1.1.11', '10.1.1.12']); assert.equal(asked[0].P.h.value, 168);
  assert.equal(r.servers.length, 2); assert.equal(r.servers[0].logs.events, 5400); assert.equal(r.servers[1].logs.events, 0);
  assert.deepEqual(r.changes.map((c) => c.id).sort(), ['SCHG-000001', 'SCHG-000002'], 'only this application, only the period');
  assert.equal(r.outages.length, 1); assert.equal(r.failed_logons[0].count, 25);
  const t = r.findings.map((f) => f.severity + ' ' + f.title);
  for (const re of [/^high ERP: running without redundancy now/, /^medium ERP: no DR copy/, /^medium ERP-APP2: 96\.5% available over 30 days/, /^high SCHG-000002 was approved by its own author/, /^low SCHG-000002 applied but not validated/,
    /^critical Security log cleared \/ auditing changed on ERP-APP1 by administrator/, /^medium 25 failed logons for svc_erp on ERP-APP1 from 10\.9\.9\.9/, /^medium ERP-APP2: no log received in the period/, /^medium group-member-added on ERP-APP1/, /^medium ERP-APP2: 2 unexpected shutdown/, /^low ERP-APP2: no restart for 70 days/]) assert.ok(t.some((x) => re.test(x)), 'missing ' + re + '\n' + t.join('\n'));
  assert.ok(!t.some((x) => /SCHG-000001.*own author/.test(x)), 'approved by someone else: no finding');
  assert.equal(r.summary.worst, 'critical');
  await assert.rejects(() => A.report({ app: 'nope' }), /not found/);
  const single = await A.report({ app: 'HR-WEB' }); assert.ok(single.findings.some((f) => /runs on a single server/.test(f.title)));
  assert.equal(changeMatches({ device: 'ERP-APP1' }, [{ id: 'x', name: 'erp-app1.corp.local', ip: '1.1.1.1' }]), true);
});
