// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * What an engineer role may call on the servers. The SAME file is in IT Asset Management (engine/access-scopes.js) and in
 * the SIEM (engine/approvers/access.js); a test fails if the two copies differ.
 *
 * The engineer job roles (Roles & Functions: Penetration Testing Engineer, Network Engineer, Virtualization / Windows
 * Server / Exchange / Backup Admin) open only their own pages in the browser (dashboards vendor/zyb-modules.js). The pages
 * hold no data: everything comes from these two APIs, so this list is the boundary. A person is RESTRICTED when their job
 * role grants nothing but engineer functions and "All platform dashboards" is off; they may then call only the route
 * prefixes of their functions plus COMMON (their own work queue, workspace and the AI engineers' queues). Everyone else -
 * administrators (gateway role admin), every other job role, people with no job role, service identities - is unchanged:
 * their routes still decide by base level (viewer / operator / admin) and approval scope, as before.
 *
 * A prefix matches the path below the API prefix (/api/itam, /api/soc) exactly or followed by "/". The lists were taken
 * from what each engineer's pages call (tools/frontend-audit/engineer-access.test.js opens every page and fails on a call
 * the list would refuse). Deliberately NOT given to engineers: the SIEM's log search, top and histogram (every event of
 * every source), SOC approvals, executive figures and the database health of the whole estate.
 */
const ENGINEER_FNS = ['vuln', 'network', 'virtualization', 'windows', 'exchange', 'backup', 'databases'];

const COMMON = {
  itam: ['/health', '/licence', '/roles/me', '/workflow', '/platform/client-errors', '/me', '/workspace/me', '/workspace/org', '/workspace/tasks', '/duty/engineers', '/duty/items', '/duty/kpis', '/duty/readiness'],
  soc: ['/health', '/duty/engineers', '/duty/items', '/duty/kpis', '/duty/readiness'],
};
const SERVER_AVAIL = '/netops/avail', SERVER_HEALTH = '/netops/health/types';   // availability, and health counts by device type (Server Availability)
const ALLOW = {
  vuln: {
    itam: ['/ai-pentest', '/apppt', '/appsec', '/hardening', '/mobile-test', '/pentest', '/risk-prioritization', '/scanned-assets', '/vapt-center', '/vapt-studio', '/vuln-dashboard', '/vuln-inventory', '/vulnscan'],
    soc: ['/bas'],
  },
  network: {
    itam: ['/assets', '/brand', '/certs', '/cisco-support', '/cisco-update', '/discovery/results', '/domains', '/ipam', '/renewals'],
    soc: ['/flows/summary', '/netflow', '/netops'],
  },
  virtualization: {
    itam: ['/console', '/servers', '/virt', '/virt-network', '/vsphere-studio'],
    soc: [SERVER_AVAIL, SERVER_HEALTH],
  },
  windows: {
    itam: ['/console', '/servers', '/virt/capacity'],
    soc: [SERVER_AVAIL, SERVER_HEALTH, '/identity/config', '/identity/summary', '/sysadmin'],
  },
  exchange: {
    itam: ['/console', '/servers', '/dns-fix', '/domains', '/esg', '/mail-availability', '/mail-report', '/mail-reputation', '/mail-route'],
    soc: [SERVER_AVAIL, SERVER_HEALTH, '/flows/mail', '/identity/config', '/identity/summary', '/mail', '/sysadmin'],
  },
  backup: {
    itam: ['/backup', '/dr-studio', '/grc/drills', '/storage', '/virt/capacity'],
    soc: [SERVER_AVAIL, SERVER_HEALTH],
  },
  // the DBA's own estate: every database (the other engineers do not get the database health of the estate) and the Linux /
  // Solaris servers the databases run on
  databases: {
    itam: ['/console', '/db-health', '/db-inventory', '/db-morning', '/db-repl', '/db-servers', '/db-sessions', '/discovery/credentials', '/discovery/results', '/oracle-licences', '/servers', '/sqldba', '/sysadmin-sync', '/virt/capacity'],
    soc: [SERVER_AVAIL, SERVER_HEALTH, '/db', '/integrations/apm/status', '/sysadmin'],
  },
};

// the engineer functions a job role is limited to, or null when the role is not restricted (see the top of this file)
function restrictedFns(role, gatewayRole) {
  if (String(gatewayRole || '').toLowerCase() === 'admin') return null;
  if (!role || !role.functions || typeof role.functions !== 'object') return null;
  const f = role.functions;
  if ((f.dashboards || 'none') !== 'none') return null;
  const granted = Object.keys(f).filter((k) => k !== 'dashboards' && f[k] && f[k] !== 'none');
  if (!granted.length || !granted.every((k) => ENGINEER_FNS.includes(k))) return null;
  return granted.sort();
}

const under = (p, pre) => p === pre || p.startsWith(pre + '/');
// may a person limited to these functions call this path (below the API prefix) on this service ('itam' | 'soc')?
function allows(service, fns, path) {
  const p = '/' + String(path || '').replace(/^\/+/, '').replace(/\/+$/, '');
  if (/(^|\/)\.\.?(\/|$)/.test(p)) return false;   // no dot segments: the prefix test must see the path the router sees
  if ((COMMON[service] || []).some((pre) => under(p, pre))) return true;
  return (fns || []).some((fn) => ((ALLOW[fn] && ALLOW[fn][service]) || []).some((pre) => under(p, pre)));
}

module.exports = { ENGINEER_FNS, COMMON, ALLOW, restrictedFns, allows };
