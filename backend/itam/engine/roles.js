// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Job roles and functions for the portal: System Admin, Network Admin, Cyber Security Admin, Penetration Engineer, ...
// Each role grants every portal function (menu section) none / view / manage, and carries a base access level
// (viewer / operator / admin) that the sign-in gate and the back ends enforce. The portal add-on
// (/dashboards/vendor/zyb-roles.js) shows each person only the sections of their role; the Roles & Functions page
// (/dashboards/roles.html) edits roles and assignments and sets the account's base level in the sign-in gate.
//   GET  /roles/me                      my role and functions (any signed-in user)
//   GET  /roles                         roles, functions catalogue, assignments                          operator
//   POST /roles                         {id?, name, description, base, functions{key: none|view|manage}, approves[]}  admin
// Approvers: a role may carry approval scopes (APPROVE_SCOPES). An operator with such a role may approve that scope's
// change plans / actions (app.approveGate(ctx, scope) on the approval routes, here and - through the approver list this
// module pushes - in the SIEM); everything else stays at the operator level (no users, no settings). Administrators
// approve everything as before; four-eyes (never your own request) is checked by each approval itself.
//   POST /roles/:id/delete              not for built-in roles, not while assigned                       admin
//   POST /roles/assign                  {user, role_id | null}                                           admin
// Self-contained (stored collections), added to an existing install with one registration line (install/add-roles.sh).
const crypto = require('node:crypto');

const LEVELS = ['none', 'view', 'manage'];
// group scopes (infra / security) and one scope per AI engineer (eng:<id>) - approve-scopes.js, same file as the SIEM's
const SC = require('./approve-scopes');
// which routes an engineer job role may call on the servers (same file as the SIEM's engine/approvers/access.js)
const AC = require('./access-scopes');
const APPROVE_SCOPES = SC.SCOPES;
const BASES = ['viewer', 'operator', 'admin'];
const FUNCTIONS = [
  { key: 'command', name: 'Command Center', views: ['home', 'command', 'ciso', 'ciodash', 'cisodash', 'infradash', 'posture', 'status', 'alerts', 'managed', 'noc', 'npm'] },
  { key: 'ai', name: 'AI & Automation (SOAR, approvals)', views: ['aiteam', 'agentops', 'autopilot', 'soar', 'approvals', 'guardrails', 'twin'] },
  { key: 'soc', name: 'Security Operations (SOC / SIEM)', views: ['dash-soc', 'socoverview', 'alarms', 'wazuh', 'soc', 'security', 'aisoc', 'detstudio', 'alarmrules', 'attack', 'hunt', 'socops', 'logs'] },
  { key: 'incidents', name: 'Incidents & Threats', views: ['ir', 'incidents', 'forensics', 'ti', 'brandprot', 'irm', 'rogue', 'emailanalysis'] },
  { key: 'identity', name: 'Identity & Data Protection', views: ['signin', 'pam', 'm365sec', 'spo', 'datagov', 'phishsim', 'awareness'] },
  { key: 'vuln', name: 'Vulnerability & Penetration Testing', views: ['dash-vuln', 'vapt', 'pentest', 'apppt', 'appsec', 'mobile', 'assurance'] },
  { key: 'compliance', name: 'Compliance', views: ['dash-grc', 'grc', 'fwlib', 'ecc', 'iso', 'aramco', 'crosswalk', 'controls', 'validation', 'chain', 'gapall', 'compmat', 'maturity', 'roadmap', 'implplan'] },
  // Audit and Data Privacy are their own departments: a person can be given one without the other (they were part of Compliance)
  { key: 'audit', name: 'Audit & Assurance (internal, IT and cyber audit, regulator audits)', views: ['audit'] },
  { key: 'privacy', name: 'Data Privacy (PDPL · NDMO)', views: ['pdpl'] },
  // Business Risk (enterprise risk register, appetite, capital, risk reports) is its own section: a risk role can be given it
  { key: 'brisk', name: 'Business Risk (enterprise risk register, risk appetite, capital, risk reports)', views: [] },
  { key: 'risk', name: 'Risk & Governance', views: ['grcreg', 'risk', 'irmhub', 'regchange', 'aigov', 'bcm', 'policies', 'docs', 'custody', 'roles'] },
  { key: 'network', name: 'Network (firewalls, switches, discovery)', views: ['dash-net', 'netctl', 'nocmon', 'netperf', 'traffic', 'isp', 'sdwan', 'topology', 'map', 'firewall', 'nac', 'discovery', 'switches', 'portmap', 'wireless', 'voip', 'ipam', 'udt', 'ncm', 'fwupgrade', 'changelog'] },
  { key: 'servers', name: 'Servers & Cloud', views: ['dash-srv', 'sam', 'servers', 'virtualization', 'cloudsrv', 'apps', 'databases', 'dbperf', 'scm', 'itops', 'vps', 'adex'] },
  // four narrower slices of Servers & Cloud, for one engineer each: they open only their own pages (vendor/zyb-modules.js
  // FN_PAGES), not the whole Servers, Storage and Databases sections that Servers & Cloud opens
  { key: 'virtualization', name: 'Virtualization only (VMware, Nutanix, capacity, power control)', views: ['virtualization'] },
  { key: 'windows', name: 'Windows servers only (Windows Server, Active Directory, remote console)', views: [] },
  { key: 'exchange', name: 'Exchange & mail only (Exchange servers, hybrid, mail routing and security)', views: [] },
  { key: 'backup', name: 'Backup, storage & DR only', views: [] },
  { key: 'databases', name: 'Databases and their Linux / Solaris servers only (Oracle and SQL Server health, morning check, sessions, tuning, licences, replication)', views: [] },
  { key: 'assets', name: 'Assets & Licences (ITAM)', views: ['itam', 'itam-ai', 'assets', 'assetreg', 'netinv', 'renewals', 'costopt', 'budget'] },
  { key: 'facilities', name: 'Facilities & Devices (printers, CCTV, UPS)', views: ['dash-fac', 'printers', 'cctv', 'cctvlive', 'door', 'ups', 'devices', 'locations'] },
  { key: 'm365', name: 'Microsoft 365 & Users', views: ['dash-m365', 'm365', 'users', 'intune'] },
  { key: 'admin', name: 'Reports & Administration', views: ['dash-rep', 'repcenter', 'tickets', 'support', 'notify', 'slapolicy', 'integrations', 'rbac', 'auditlog', 'syshealth', 'rules'] },
  // view / manage = every platform dashboard section; none = only the sections of the functions above (vendor/zyb-modules.js FN_AREAS)
  { key: 'dashboards', name: 'All platform dashboards (without it: only the dashboard sections of the functions above)', views: [] },
];
const ALL = (lvl) => Object.fromEntries(FUNCTIONS.map((f) => [f.key, lvl]));
const R = (o) => Object.assign(ALL('none'), o);
const BUILTIN = [
  { id: 'system-admin', name: 'System Admin', base: 'admin', description: 'Runs the platform: every function, users and settings.', functions: ALL('manage') },
  { id: 'ciso', name: 'CISO', base: 'operator', description: 'Oversight of security, risk and compliance; approves isolation and SOAR actions.', approves: ['security'], functions: R(Object.assign(ALL('view'), { ai: 'manage', incidents: 'manage', compliance: 'manage', risk: 'manage' })) },
  { id: 'cyber-security-admin', name: 'Cyber Security Admin', base: 'operator', description: 'SIEM / SOC, incidents, identity protection, vulnerability management.', functions: R({ command: 'view', ai: 'manage', soc: 'manage', incidents: 'manage', identity: 'manage', vuln: 'manage', compliance: 'view', risk: 'view', network: 'view', servers: 'view', assets: 'view', m365: 'view', admin: 'view', dashboards: 'view' }) },
  { id: 'soc-analyst', name: 'SOC Analyst', base: 'operator', description: 'Triage alerts and cases, hunt, incidents.', functions: R({ command: 'view', ai: 'view', soc: 'manage', incidents: 'manage', identity: 'view', vuln: 'view', network: 'view', dashboards: 'view' }) },
  { id: 'penetration-engineer', name: 'Penetration Engineer', base: 'operator', description: 'Penetration tests, VAPT findings and retests.', functions: R({ command: 'view', vuln: 'manage', incidents: 'view', soc: 'view', network: 'view', servers: 'view', assets: 'view', dashboards: 'view' }) },
  { id: 'network-admin', name: 'Network Admin', base: 'operator', description: 'Firewalls, switches, SD-WAN, Wi-Fi, IP plan, discovery.', functions: R({ command: 'view', network: 'manage', assets: 'manage', facilities: 'view', servers: 'view', soc: 'view', admin: 'view', dashboards: 'view' }) },
  { id: 'server-admin', name: 'Server & Cloud Admin', base: 'operator', description: 'Servers, virtualisation, databases, AD & Exchange, backups.', functions: R({ command: 'view', servers: 'manage', assets: 'manage', facilities: 'view', network: 'view', m365: 'view', admin: 'view', dashboards: 'view' }) },
  { id: 'infra-manager', name: 'Infrastructure Manager', base: 'operator', description: 'Infrastructure reports; approves infrastructure change plans, patch installs and endpoint actions (not users or settings).', approves: ['infra'], functions: R({ command: 'view', ai: 'manage', servers: 'manage', network: 'manage', assets: 'manage', facilities: 'manage', m365: 'view', soc: 'view', compliance: 'view', risk: 'view', admin: 'view', dashboards: 'view' }) },
  { id: 'infra-asst-manager', name: 'Infrastructure Assistant Manager', base: 'operator', description: 'End-user devices, assets and licences, printers, facilities.', functions: R({ command: 'view', assets: 'manage', facilities: 'manage', m365: 'view', servers: 'view', network: 'view', admin: 'view', dashboards: 'view' }) },
  { id: 'grc-officer', name: 'Compliance / GRC Officer', base: 'operator', description: 'Compliance frameworks, evidence, risk register, policies.', functions: R({ command: 'view', compliance: 'manage', risk: 'manage', admin: 'view', vuln: 'view', dashboards: 'view' }) },
  // two focused roles: their dashboards stay at none, so each person sees only the platform sections of their own work
  { id: 'desktop-engineer', name: 'Desktop Support Engineer', base: 'operator', description: 'User desktops and laptops, patching, remote support, joiners / movers / leavers, printers and phones; reads assets and Microsoft 365 users.', functions: R({ command: 'view', facilities: 'manage', assets: 'view', m365: 'view' }) },
  { id: 'grc-analyst', name: 'GRC Analyst', base: 'operator', description: 'Compliance frameworks, evidence, risk register, policies, PDPL / NDMO and audit work - only the governance and compliance sections.', functions: R({ command: 'view', compliance: 'manage', risk: 'manage' }) },
  { id: 'risk-head', name: 'Head of Risk & Compliance', base: 'operator', description: 'Owns enterprise and business risk and compliance: the risk registers, appetite and treatment, the compliance frameworks, PDPL / NDMO, audit findings and the risk and compliance reports - only the risk, business risk, compliance, data privacy and audit sections; approves risk acceptances and risk-appetite limit changes (never their own request).', approves: ['risk'], functions: R({ command: 'view', risk: 'manage', brisk: 'manage', compliance: 'manage' }) },
  { id: 'application-admin', name: 'Application Admin', base: 'operator', description: 'Business applications, web servers and APIs, Applications Manager monitors, databases behind the applications and application security findings; reads servers, assets and the AI engineers.', functions: R({ command: 'view', servers: 'manage', vuln: 'view', assets: 'view', ai: 'view', dashboards: 'view' }) },
  { id: 'internal-auditor', name: 'Internal Auditor', base: 'operator', description: 'Audit & Assurance: plans, engagements, findings, the audit repository and regulator audits; reads compliance and risk as evidence.', functions: R({ command: 'view', audit: 'manage', compliance: 'view', risk: 'view', privacy: 'view' }) },
  { id: 'dpo', name: 'Data Protection Officer', base: 'operator', description: 'Data Privacy: PDPL registers (RoPA, DSAR, DPIA, breaches, transfers, processors), NDMO, the data catalog; reads audit and compliance.', functions: R({ command: 'view', privacy: 'manage', compliance: 'view', audit: 'view', identity: 'view' }) },
  // one engineer, one home: these roles open only their own sections (no Command Center, no other team's pages) and approve
  // what their own AI engineer proposes (four-eyes still applies: never their own request)
  { id: 'pentest-engineer', name: 'Penetration Testing Engineer', base: 'operator', description: 'Only Pentest & VAPT: scans, VAPT findings, application and mobile tests, hardening and retests; approves the AI Penetration Testing Engineer.', approves: ['eng:pentest'], functions: R({ vuln: 'manage' }) },
  { id: 'network-engineer', name: 'Network Engineer', base: 'operator', description: 'Only Network: switches, routers, SD-WAN, wireless, IP plan, configuration, NAC, route maps; approves the AI Network Engineer.', approves: ['eng:network'], functions: R({ network: 'manage' }) },
  { id: 'virtualization-admin', name: 'Virtualization Admin', base: 'operator', description: 'Only virtualization: VMware vSphere, Nutanix, virtual networks, capacity, power control, DR replication; approves the AI Virtualization Administrator.', approves: ['eng:virt'], functions: R({ virtualization: 'manage' }) },
  { id: 'windows-admin', name: 'Windows Server Admin', base: 'operator', description: 'Only Windows servers: Windows Server estate, Active Directory, availability, remote console; approves the AI Windows Server Administrator.', approves: ['eng:windows'], functions: R({ windows: 'manage' }) },
  { id: 'exchange-admin', name: 'Exchange Admin', base: 'operator', description: 'Only Exchange and mail: Exchange servers, hybrid, mail routing, mail security gateway; approves the AI Exchange Server Administrator.', approves: ['eng:exchange'], functions: R({ exchange: 'manage' }) },
  { id: 'oracle-dba', name: 'Oracle DBA', base: 'operator', description: 'Only databases and their servers: Oracle and SQL Server health, the morning check, sessions, tuning and statements, the Linux and Solaris servers they run on, licences and replication; approves the AI Oracle DBA.', approves: ['eng:dba'], functions: R({ databases: 'manage' }) },
  { id: 'backup-admin', name: 'Backup Admin', base: 'operator', description: 'Only backup, storage and DR: backup jobs, storage arrays, DR replication and drills.', approves: [], functions: R({ backup: 'manage' }) },
  { id: 'auditor', name: 'Auditor (read-only)', base: 'viewer', description: 'Reads everything, changes nothing.', functions: ALL('view') },
];

// Audit and Data Privacy were inside Compliance: a role that had Compliance keeps the same access to both, once (an administrator
// can then separate them); a role that already carries either key is left as it is
function splitCompliance(fn, force) {
  if (!fn) return false; let ch = false; const lvl = fn.compliance || 'none';
  for (const k of ['audit', 'privacy']) if (force ? fn[k] === 'none' && lvl !== 'none' : !(k in fn)) { fn[k] = lvl; ch = true; }
  return ch;
}
for (const b of BUILTIN) if (!['internal-auditor', 'dpo'].includes(b.id)) splitCompliance(b.functions, true);

const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 120);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const USER_RE = /^[A-Za-z0-9._@\\-]{1,100}$/;

function createRoles(app, opts = {}) {
  const { store } = app;
  const roles = store.collection('job_roles'), assign = store.collection('role_assignments');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  const newId = opts.newId || (() => 'role-' + crypto.randomBytes(4).toString('hex'));
  if (!roles.all().length) for (const b of BUILTIN) roles.put(Object.assign({ builtin: true }, b));
  else for (const b of BUILTIN) if (!roles.get(b.id)) roles.put(Object.assign({ builtin: true }, b));   // new built-ins after an update
  // roles saved before Audit and Data Privacy were split out of Compliance keep the same access to both
  for (const r of roles.all()) { const fn = Object.assign({}, r.functions || {}); if (splitCompliance(fn)) roles.put(Object.assign({}, r, { functions: fn })); }
  // a built-in stored before approval scopes existed gets its default scopes once (an administrator's later edit stays)
  for (const b of BUILTIN) { const r = roles.get(b.id); if (r && r.builtin && !Array.isArray(r.approves)) roles.put(Object.assign({}, r, { approves: (b.approves || []).slice() })); }
  // once per stored role: Business Risk became its own function (a built-in gets its default level and, for the Head of Risk,
  // the risk approval scope; a custom role gets none - before this no job role opened that section) - an administrator's later
  // edit stays, because the migration runs once
  for (const r of roles.all()) {
    if ((r.migrations || []).includes('brisk-1')) continue;
    const b = r.builtin ? BUILTIN.find((x) => x.id === r.id) : null, fn = Object.assign({}, r.functions || {});
    if (!('brisk' in fn)) fn.brisk = b ? (b.functions.brisk || 'none') : 'none';
    const ap = Array.isArray(r.approves) ? r.approves.slice() : [];
    if (b) for (const sc of b.approves || []) if (sc === 'risk' && !ap.includes(sc)) ap.push(sc);
    roles.put(Object.assign({}, r, { functions: fn, approves: ap, migrations: (r.migrations || []).concat('brisk-1') }));
  }
  const k = (u) => String(u || '').toLowerCase();

  function normFunctions(f, cur) {
    const out = Object.assign(ALL('none'), cur || {});
    for (const fn of FUNCTIONS) if (f && fn.key in f) { const v = String(f[fn.key]); if (!LEVELS.includes(v)) throw bad(`${fn.name}: access must be none, view or manage`); out[fn.key] = v; }
    return out;
  }
  function normApproves(v, base) {
    const out = [...new Set((Array.isArray(v) ? v : []).map(String))];
    for (const x of out) if (!APPROVE_SCOPES[x]) throw bad(`unknown approval scope "${s(x, 30)}" (${Object.keys(APPROVE_SCOPES).join(', ')})`);
    if (out.length && base === 'viewer') throw bad('a read-only (viewer) role cannot approve - raise the base level to operator');
    return out;
  }
  // may this user approve this scope (or any of a list)? never a service / AI identity; administrators: yes; operators: when
  // their role carries the scope or its group; viewers: never
  function approves(user, scope, baseRole) {
    if (!SC.isHuman(user)) return false;
    if (String(baseRole || '').toLowerCase() === 'admin') return true;
    const a = assign.get(k(user)); const r = a && roles.get(a.role_id);
    return !!(r && r.base !== 'viewer' && Array.isArray(r.approves) && SC.allows(r.approves, scope));
  }
  // per AI engineer: the named people who may approve its proposals (besides administrators)
  function engineerApprovers() {
    const m = approverMap();
    return Object.entries(SC.ENGINEERS).map(([sc, e]) => ({ scope: sc, group: e[0], engineer: e[1], approves: e[2],
      people: [...new Set((m[sc] || []).concat(m[e[0]] || []))].sort(), direct: (m[sc] || []).slice(), via_group: (m[e[0]] || []).slice() }));
  }
  // {scope: [user, …]} - what the SIEM needs to enforce the same rule on its approval routes
  function approverMap() {
    const out = {}; for (const sc of Object.keys(APPROVE_SCOPES)) out[sc] = [];
    for (const a of assign.all()) { const r = roles.get(a.role_id); if (!r || r.base === 'viewer') continue; for (const sc of r.approves || []) if (out[sc]) out[sc].push(k(a.user)); }
    for (const sc of Object.keys(out)) out[sc].sort();
    return out;
  }
  function list() {
    const a = assign.all();
    return { functions: FUNCTIONS.map((f) => ({ key: f.key, name: f.name, views: f.views })), levels: LEVELS, bases: BASES, approve_scopes: APPROVE_SCOPES,
      roles: roles.all().sort((x, y) => (x.builtin === y.builtin ? x.name.localeCompare(y.name) : x.builtin ? -1 : 1)).map((r) => Object.assign({}, r, { users: a.filter((x) => x.role_id === r.id).map((x) => x.user) })),
      assignments: a.map((x) => Object.assign({ user: x.user, role_id: x.role_id, by: x.by, at: x.at }, x.source ? { source: x.source, via: x.via || '' } : {})) };
  }
  function me(user) {
    const a = assign.get(k(user)); const r = a && roles.get(a.role_id);
    return r ? { user, role: { id: r.id, name: r.name, base: r.base, functions: r.functions, approves: r.base === 'viewer' ? [] : (r.approves || []) }, functions: FUNCTIONS.map((f) => ({ key: f.key, views: f.views })) } : { user, role: null, functions: FUNCTIONS.map((f) => ({ key: f.key, views: f.views })) };
  }
  function save(b, who) {
    b = b || {};
    const id = b.id ? s(b.id, 60) : '';
    const cur = id ? roles.get(id) : null;
    if (id && !cur) throw bad('role not found', 404);
    const name = s(b.name !== undefined ? b.name : cur && cur.name, 60); if (!name) throw bad('a role name is required');
    if (roles.all((r) => r.name.toLowerCase() === name.toLowerCase() && r.id !== id).length) throw bad(`a role called "${name}" already exists`, 409);
    const base = String(b.base !== undefined ? b.base : (cur && cur.base) || 'viewer'); if (!BASES.includes(base)) throw bad('base must be viewer, operator or admin');
    const functions = normFunctions(b.functions, cur && cur.functions);
    if (base === 'viewer' && Object.values(functions).includes('manage')) throw bad('a role with base level "viewer" cannot manage anything - raise the base level or set those functions to view');
    const approvesList = normApproves(b.approves !== undefined ? b.approves : cur && cur.approves, base);
    const r = Object.assign({}, cur || {}, { id: id || newId(), name, base, description: s(b.description !== undefined ? b.description : cur && cur.description, 300), functions, approves: approvesList,
      builtin: !!(cur && cur.builtin), updated_by: who.user, updated_at: new Date(now()).toISOString() });
    if (!cur) { r.created_by = who.user; r.created_at = r.updated_at; }
    roles.put(r);
    audit({ by: who.user, role: who.role, ip: who.ip, action: cur ? 'roles.update' : 'roles.create', target: r.id, detail: { name, base, functions, approves: approvesList } });
    if (opts.onChange) opts.onChange();
    return Object.assign(list(), { saved: r });
  }
  function remove(id, who) {
    const r = roles.get(String(id || '')); if (!r) throw bad('role not found', 404);
    if (r.builtin) throw bad('built-in roles cannot be deleted (change their functions instead)', 409);
    const n = assign.all((x) => x.role_id === r.id).length; if (n) throw bad(`${n} users have this role - assign them another role first`, 409);
    roles.remove(r.id);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'roles.delete', target: r.id, detail: { name: r.name } });
    if (opts.onChange) opts.onChange();
    return list();
  }
  function setUser(b, who) {
    const user = s(b && b.user, 100); if (!USER_RE.test(user)) throw bad('invalid user name');
    const rid = b && b.role_id ? s(b.role_id, 60) : null;
    const before = assign.get(k(user));
    if (rid) {
      const r = roles.get(rid); if (!r) throw bad('role not found', 404);
      if (k(user) === k(who.user) && r.base !== 'admin') throw bad('you cannot give yourself a role without administration - ask another administrator', 409);
      assign.put({ id: k(user), user, role_id: rid, by: who.user, at: new Date(now()).toISOString() });
    } else {
      if (k(user) === k(who.user)) throw bad('you cannot remove your own role', 409);
      if (before) assign.remove(k(user));
    }
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'roles.assign', target: user, detail: { from: before ? before.role_id : null, to: rid } });
    if (opts.onChange) opts.onChange();
    return list();
  }
  // the read routes in Python (pyengine/roles_rules.py, step 8b): it reads the roles and assignments from the store files
  // itself (read-only - this process stays the only writer); the catalogue is code and travels with the request.
  // A missing or failing Python, or roles.engine = "node" → the functions above.
  const py = opts.noPython || ((app.config && app.config.roles) || {}).engine === 'node' || !store.dir ? null
    : (() => { try { return require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || opts.python || undefined, timeoutMs: 30000 }); } catch (e) { return null; } })();
  const catalogue = () => ({ functions: FUNCTIONS, levels: LEVELS, bases: BASES, approve_scopes: APPROVE_SCOPES, groups: SC.GROUPS, engineers: SC.ENGINEERS });
  async function viaPy(op, extra, ok, node) {
    if (py) { const r = await py.call(op, Object.assign({ dir: store.dir, catalogue: catalogue() }, extra || {})); if (r && r.ok !== false && ok(r)) return r; }
    return node();
  }
  const listAuto = () => viaPy('roles.list', {}, (r) => Array.isArray(r.roles), list);
  const meAuto = (user) => viaPy('roles.me', { user }, (r) => 'role' in r, () => me(user));
  const approversAuto = () => viaPy('roles.approvers', {}, (r) => r.approvers && Array.isArray(r.engineers), () => ({ scopes: APPROVE_SCOPES, groups: SC.GROUPS, approvers: approverMap(), engineers: engineerApprovers() }));
  // the WRITES decided in Python (pyengine/roles_write.py, step 9b), committed here - the store keeps ONE writer. Python
  // reads the current roles and assignments and answers the records to write and the audit entry (or a refusal worded
  // as below); they are written only if neither collection changed while Python decided (a fingerprint), otherwise
  // the function above decides again. Only these two collections can be written this way.
  const fp = () => crypto.createHash('sha256').update(JSON.stringify(roles.all()) + '\n' + JSON.stringify(assign.all())).digest('hex');
  const OWN = { job_roles: roles, role_assignments: assign };
  const stats = { python: 0, node: 0, changed_meanwhile: 0 };   // who decided each write (GET /roles shows nothing of this; tests and support read it)
  async function viaPyWrite(op, extra, who, node0, after) {
    const node = () => { stats.node++; return node0(); };
    if (!py) return node();
    const before = fp(), at = new Date(now()).toISOString();
    const r = await py.call(op, Object.assign({ dir: store.dir, catalogue: catalogue(), who: { user: who.user, role: who.role, ip: who.ip }, at, new_id: newId() }, extra));
    if (r && fp() !== before) stats.changed_meanwhile++;
    if (!r || r.ok === false || (!r.refuse && !Array.isArray(r.puts)) || fp() !== before) return node();
    stats.python++;
    if (r.refuse) throw bad(r.refuse.error, r.refuse.status);
    const puts = r.puts || [], removes = r.removes || [];
    if (![...puts, ...removes].every((x) => OWN[x && x.c])) return node();   // never anything but the two Roles collections
    for (const x of removes) OWN[x.c].remove(x.id);
    for (const x of puts) OWN[x.c].put(x.o);
    if (r.audit) audit(r.audit);
    if (opts.onChange) opts.onChange();
    return after(r);
  }
  const saveAuto = (b, who) => viaPyWrite('roles.save', { body: b || {} }, who, () => save(b, who), (r) => Object.assign(list(), { saved: r.saved }));
  const removeAuto = (id, who) => viaPyWrite('roles.remove', { id }, who, () => remove(id, who), () => list());
  // a job role that comes from an AD group (SSO Access from AD, sso-groups.js) is changed there, not by hand: the hourly sync
  // would put it back, and the four-eyes approval of the group mapping is what made it
  const derivedOf = (user) => { const a = assign.get(k(user)); return a && a.source === 'sso-group' ? a : null; };
  const setUserAuto = (b, who) => {
    const d = derivedOf(b && b.user); if (d) throw bad('this job role comes from the AD group ' + (d.via || '') + ' through SSO Access from AD - change the group membership or the approved mapping there', 409);
    return viaPyWrite('roles.assign', { body: b || {} }, who, () => setUser(b, who), () => list());
  };
  // the engineer functions this person is limited to on the servers (access-scopes.js), or null (not restricted)
  function restrictionOf(user, gatewayRole) {
    const a = assign.get(k(user)); const r = a && roles.get(a.role_id);
    return AC.restrictedFns(r, gatewayRole);
  }
  // {user: [functions]} for every restricted person - pushed to the SIEM beside the approver list
  function accessMap() {
    const out = {};
    for (const a of assign.all()) { const r = roles.get(a.role_id), f = AC.restrictedFns(r, ''); if (f) out[k(a.user)] = f; }
    return out;
  }
  // SSO Access from AD writes its derived assignments through here (source 'sso-group'); hand-made assignments are never touched
  function syncDerived(want, who) {
    const cur = assign.all((x) => x.source === 'sso-group'), keep = new Set(), added = [], removed = [], changed = [];
    for (const w of want) {
      if (!USER_RE.test(w.user) || !roles.get(w.role_id)) continue;
      const id = k(w.user), ex = assign.get(id);
      if (ex && ex.source !== 'sso-group') continue;   // set by hand in Roles & Functions: the hand-made one wins
      keep.add(id);
      if (!ex) added.push(w.user); else if (ex.role_id !== w.role_id || ex.via !== w.via) changed.push(w.user); else continue;
      assign.put({ id, user: w.user, role_id: w.role_id, by: who.user, at: new Date(now()).toISOString(), source: 'sso-group', via: w.via, proposal: w.proposal });
    }
    for (const x of cur) if (!keep.has(x.id)) { assign.remove(x.id); removed.push(x.user); }
    if ((added.length || removed.length || changed.length) && opts.onChange) opts.onChange();
    return { added, removed, changed };
  }
  return { syncDerived, list, me, save, remove, setUser, approves, approverMap, restrictionOf, accessMap, engineerApprovers, listAuto, meAuto, approversAuto, saveAuto, removeAuto, setUserAuto, engine: () => (py ? 'python' : 'node'), writeStats: () => Object.assign({}, stats) };
}

// the SIEM enforces the same approvers on its approval routes: the list is pushed to it on every change and every
// 10 minutes (so a SIEM restored from backup or restarted catches up); a SIEM that is not linked simply keeps admin-only
const SYS = { user: 'system:itam-roles', role: 'admin', ip: '' };
function registerRoles(srv, app, opts = {}) {
  let R = null, last = '';
  async function pushApprovers(force) {
    const siem = app.discovery && app.discovery.siem; if (!R || !siem || typeof siem.call !== 'function') return { pushed: false, reason: 'SIEM link not available' };
    const map = R.approverMap(), access = R.accessMap(), sig = JSON.stringify([map, access]); if (!force && sig === last) return { pushed: false, reason: 'unchanged' };
    try { const r = await siem.call('POST', '/approvers', SYS, { scopes: map, access }); if (r && r.status >= 200 && r.status < 300) { last = sig; return { pushed: true }; } return { pushed: false, reason: 'SIEM HTTP ' + (r && r.status) }; }
    catch (e) { if (app.log && app.log.warn) app.log.warn('roles: approver push failed', { err: e.message }); return { pushed: false, reason: e.message }; }
  }
  R = createRoles(app, Object.assign({}, opts, { onChange: () => { guardOf(app, 'roles.push-approvers', () => pushApprovers(true))(); } }));
  app.roles = R;
  // the approval routes of every module call this (falling back to admin-only when this module is not installed)
  // only a person approves: a service / AI identity is refused even as admin
  app.approveGate = (ctx, scope) => {
    if (!SC.isHuman(ctx.who && ctx.who.user)) throw bad('only a person approves: ' + ((ctx.who && ctx.who.user) || 'this identity') + ' is a service / AI identity', 403);
    if (String((ctx.who && ctx.who.role) || '').toLowerCase() === 'admin') return true;
    ctx.need('operator');
    if (R.approves(ctx.who.user, scope, ctx.who.role)) return true;
    throw bad(`approving this needs an administrator, or a human approver for ${[].concat(scope).map(SC.label).join(' / ')} (Roles & Functions)`, 403);
  };
  // server-side boundary for the engineer job roles: a restricted person's request outside their routes is refused here,
  // before any route runs (the pages already hide them; this is what stops a direct call). Refusals are audited, at most
  // once per person and route group every 10 minutes, so a page polling a refused route does not flood the audit trail.
  const PRE = srv.prefix || '/api/itam', refused = new Map(), k = (u) => String(u || '').toLowerCase();
  if (typeof srv.gate !== 'function' && app.log && app.log.warn) app.log.warn('roles: this engine has no access gate (install/patches/http-access-gate.patch) - engineer roles are limited in the browser only');
  if (typeof srv.gate === 'function') srv.gate((ctx) => {
    const who = ctx.who || {}; if (!who.user) return;
    let fns; try { fns = R.restrictionOf(who.user, who.role); } catch (e) {
      // the role store could not be read: refuse rather than let a restricted person through (fail closed), and say why
      if (app.log && app.log.every) app.log.every('roles.gate-read', 60000, 'error', 'roles: access check could not read the job roles', { err: e.message });
      throw bad('access check unavailable - try again in a moment', 503);
    }
    if (!fns) return;
    const rel = ctx.path.startsWith(PRE) ? ctx.path.slice(PRE.length) : ctx.path;
    if (AC.allows('itam', fns, rel)) return;
    const seg = rel.split('/')[1] || '', key = k(who.user) + '|' + seg, t = Date.now();
    if (!refused.has(key) || t - refused.get(key) > 600000) {
      refused.set(key, t); if (refused.size > 5000) refused.clear();
      if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || ctx.ip, action: 'access.refused', target: ctx.method + ' ' + PRE + '/' + seg, detail: { functions: fns, reason: 'outside the job role' } });
    }
    throw bad('not part of your job role - an administrator can change it in Roles & Functions', 403);
  });
  if (!opts.noPush) { const t = setTimeout(guardOf(app, 'roles.push-approvers', () => pushApprovers(true)), 15000); if (t.unref) t.unref(); const iv = setInterval(guardOf(app, 'roles.push-approvers', () => pushApprovers(true)), 600000); if (iv.unref) iv.unref(); }
  srv.route('GET', '/roles/approvers', (ctx) => { ctx.need('operator'); return R.approversAuto(); });
  srv.route('GET', '/roles/me', (ctx) => void ctx.need('viewer') || R.meAuto(ctx.who.user));
  srv.route('GET', '/roles', (ctx) => { ctx.need('operator'); return R.listAuto(); });
  srv.route('POST', '/roles/assign', (ctx) => { ctx.need('admin'); return R.setUserAuto(ctx.body || {}, ctx.who); });
  srv.route('POST', '/roles/:id/delete', (ctx) => { ctx.need('admin'); return R.removeAuto(ctx.params.id, ctx.who); });
  srv.route('POST', '/roles', (ctx) => { ctx.need('admin'); return R.saveAuto(ctx.body || {}, ctx.who); });
  return R;
}

module.exports = { createRoles, registerRoles, FUNCTIONS, BUILTIN, LEVELS, BASES, APPROVE_SCOPES };
