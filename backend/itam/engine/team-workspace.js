// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body } = require('./check');
const { createSealer } = require('./discovery/vault');
const httpc = require('./discovery/httpc');
/*
 * Team Workspace - the IT and Cyber Security teams' own start page, and the organisation behind it.
 *
 * Organisation (administrators create and change all of it; every change audited):
 *   departments   {id, name, description, head_role}            the head is whoever holds head_role
 *   roles         {id, name, department, reports_to_role, access_role, description}
 *                 a job title, not an access level: access stays with Roles & Functions (access_role links one of its roles)
 *   people        {id, name, user, email, department, role, reports_to, active}
 *                 user = the sign-in name; reports_to (a person) overrides the reporting line the role gives
 *   workflows     {id, name, description, steps[{name, to}]}    to = manager | manager2 | dept_head | role:<id> | person:<id>
 * Reporting authority of a person: reports_to, else the holder of the role's reports_to_role, else the department head.
 * A reporting loop is refused when it is saved.
 *
 * Tasks: an administrator assigns to anyone; a person assigns to anyone who reports to them (directly or further down).
 *   assigned -> in_progress -> in_review (one step per workflow step) -> done          returned -> in_progress again
 * Each review step is decided by the person the step resolves to (never the assignee - then their manager decides); a step that
 * resolves to nobody waits for an administrator. Return needs a reason. Service and AI identities never decide.
 *
 * Microsoft 365 (mail, meetings, Teams chats) - each person's OWN mailbox, calendar and chats, with their own Microsoft sign-in
 * (delegated permissions: authorisation code + PKCE). There is no application access to mailboxes: an administrator cannot read
 * anyone's mail through this page and the platform holds no permission that could. The refresh token is sealed in the vault per
 * person and access tokens live in memory only. The Microsoft account must be the e-mail address on the person's profile.
 * Mail and chat contents are passed through, never stored and never written to a log or the audit (only that a reply was sent,
 * with a fingerprint of the message id). Message bodies are returned as text; links in them are not made clickable by the page.
 * Delegated permissions: openid profile offline_access User.Read Mail.Read Mail.Send Calendars.Read Chat.Read ChatMessage.Send
 *
 *   GET  /workspace/me                       any       my profile, manager chain, reports, tasks, Microsoft 365 status
 *   GET  /workspace/org                      viewer    departments, roles, people (sign-in names and e-mail: admins only), workflows
 *   POST /workspace/departments|roles|people|workflows          admin  upsert one        POST .../:id/delete  admin (not while used)
 *   POST /workspace/template                 admin     add the IT + Cyber Security departments and job roles (no people)
 *   GET  /workspace/tasks?scope=mine|review|team|created|all   any (all: admin)
 *   POST /workspace/tasks                    any       assign (checked: admin, or the assignee reports to you)
 *   POST /workspace/tasks/:id/(start|submit|approve|return|comment|cancel|reassign)   any - each checks who may
 *   GET  /workspace/m365/settings  POST /workspace/m365/settings  admin   tenant, app, sealed client secret, redirect page
 *   POST /workspace/m365/connect|callback|disconnect             any (own account only)   POST /workspace/m365/revoke  admin
 *   GET  /workspace/mail  /workspace/mail/:id   POST /workspace/mail/:id/reply   GET /workspace/calendar   GET /workspace/chats
 *   GET  /workspace/chats/:id/messages   POST /workspace/chats/:id/send                     any (own account only)
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (s) => String(s == null ? '' : s).trim().toLowerCase();
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SLUG = /^[a-z0-9][a-z0-9-]{0,47}$/;
const USERNAME = /^[A-Za-z0-9._@\\-]{1,120}$/;
const MSGID = /^[A-Za-z0-9=_+\/-]{8,400}$/;
const CHATID = /^[A-Za-z0-9:@._=-]{8,200}$/;
const SERVICE = /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i;
const STEP_TO = /^(manager|manager2|dept_head|role:[a-z0-9][a-z0-9-]{0,47}|person:[a-z0-9][a-z0-9-]{0,47})$/;
const PRIORITY = ['low', 'normal', 'high', 'urgent'];
const OPEN = ['assigned', 'in_progress', 'in_review', 'returned'];
const SCOPES = 'openid profile offline_access User.Read Mail.Read Mail.Send Calendars.Read Chat.Read ChatMessage.Send';
const RIYADH = 3 * 3600000;
const DEFAULT_WF = { id: 'manager-review', name: 'Reviewed by the manager', description: 'The person the assignee reports to reviews the work.', steps: [{ name: 'Manager review', to: 'manager' }], builtin: true };
// the structure the organisation described - departments and job roles with their reporting lines; people are added on the page.
// Applying it again adds only what is missing (an update brings new departments); everything it adds stays editable and deletable.
const TEMPLATE = {
  departments: [
    { id: 'infrastructure', name: 'Infrastructure Department', head_role: 'infra-manager', description: 'Servers, network, security devices, end-user support' },
    { id: 'cyber-security', name: 'Cyber Security Department', head_role: 'ciso', description: 'Security operations, governance, risk and compliance' },
    { id: 'risk-compliance', name: 'Risk & Compliance Department', head_role: 'head-risk-compliance', description: 'Enterprise risk management, regulatory compliance (SAMA, IA, NCA, PDPL, NDMO), policies and the risk committee' },
    { id: 'network-security', name: 'Network & Security Department', head_role: 'network-security-lead', description: 'Firewalls, switches, SD-WAN, branch connectivity, NAC and the security devices' },
    { id: 'soc', name: 'Security Operations Centre (SOC)', head_role: 'soc-manager', description: 'Alert triage, cases, threat hunting, incident response and the after-hours watch' },
    { id: 'application', name: 'Applications Department', head_role: 'application-manager', description: 'Business applications, web servers and APIs, Applications Manager and application security' },
    { id: 'audit', name: 'IT & Cyber Security Audit', head_role: 'audit-head', description: 'Internal IT and cyber security audits, evidence requests and findings follow-up (read-only on the platform)' },
  ],
  roles: [
    { id: 'infra-manager', name: 'Infrastructure Manager', department: 'infrastructure', reports_to_role: null },
    { id: 'infra-assoc-manager', name: 'Infrastructure Associate Manager', department: 'infrastructure', reports_to_role: 'infra-manager' },
    { id: 'senior-net-sec-engineer', name: 'Senior Network & Security Engineer', department: 'infrastructure', reports_to_role: 'infra-assoc-manager' },
    { id: 'desktop-support-engineer', name: 'Desktop Support Engineer', department: 'infrastructure', reports_to_role: 'infra-assoc-manager', access_role: 'desktop-engineer' },
    { id: 'ciso', name: 'Chief Information Security Officer (CISO)', department: 'cyber-security', reports_to_role: null },
    { id: 'grc-manager', name: 'GRC Manager', department: 'cyber-security', reports_to_role: 'ciso' },
    { id: 'risk-manager', name: 'Risk Manager', department: 'cyber-security', reports_to_role: 'ciso' },
    { id: 'grc-analyst', name: 'GRC Analyst', department: 'cyber-security', reports_to_role: 'ciso', access_role: 'grc-analyst' },
    { id: 'head-risk-compliance', name: 'Head of Risk & Compliance', department: 'risk-compliance', reports_to_role: null, access_role: 'risk-head' },
    { id: 'network-security-lead', name: 'Network & Security Lead', department: 'network-security', reports_to_role: 'infra-manager', access_role: 'network-admin' },
    { id: 'network-security-engineer', name: 'Network & Security Engineer', department: 'network-security', reports_to_role: 'network-security-lead', access_role: 'network-admin' },
    { id: 'soc-manager', name: 'SOC Manager', department: 'soc', reports_to_role: 'ciso', access_role: 'cyber-security-admin' },
    { id: 'soc-analyst', name: 'SOC Analyst', department: 'soc', reports_to_role: 'soc-manager', access_role: 'soc-analyst' },
    { id: 'application-manager', name: 'Applications Manager', department: 'application', reports_to_role: null, access_role: 'application-admin' },
    { id: 'application-engineer', name: 'Application Engineer', department: 'application', reports_to_role: 'application-manager', access_role: 'application-admin' },
    { id: 'audit-head', name: 'Head of IT Audit', department: 'audit', reports_to_role: null, access_role: 'auditor' },
    { id: 'it-auditor', name: 'IT / Cyber Security Auditor', department: 'audit', reports_to_role: 'audit-head', access_role: 'auditor' },
  ],
};
const fp = (s) => crypto.createHash('sha256').update(String(s)).digest('hex').slice(0, 12);
const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
// Teams message bodies are HTML: reduce to text (the page shows text only)
function toText(html) {
  return String(html || '').replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, '').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li)>/gi, '\n').replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/\n{3,}/g, '\n\n').trim();
}
// a meeting link is offered only when it is a Teams meeting address
function teamsJoin(u) {
  try { const x = new URL(String(u || '')); if (x.protocol === 'https:' && (x.hostname === 'teams.microsoft.com' || x.hostname.endsWith('.teams.microsoft.com') || x.hostname === 'teams.live.com')) return x.toString(); } catch (e) { /* not a URL: no link */ }
  return null;
}

function createTeamWorkspace(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-team-workspace' });
  const request = opts.request || httpc.request;
  const loginBase = (opts.loginBase || 'https://login.microsoftonline.com').replace(/\/+$/, '');
  const graphBase = (opts.graphBase || 'https://graph.microsoft.com/v1.0').replace(/\/+$/, '');
  const C = { dep: () => store.collection('ws_departments'), role: () => store.collection('ws_roles'), ppl: () => store.collection('ws_people'), wf: () => store.collection('ws_workflows'),
    task: () => store.collection('ws_tasks'), cfg: () => store.collection('ws_m365_cfg'), tok: () => store.collection('ws_m365_tokens') };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('workspace:' + key, 600000, 'warn', msg, detail); };
  const isAdmin = (who) => who && who.role === 'admin';
  const person = (id) => (id ? C.ppl().get(id) : null);
  const people = () => C.ppl().all().filter((p) => p.active !== false);
  const meOf = (who) => C.ppl().all().find((p) => p.active !== false && p.user && low(p.user) === low(who.user)) || null;
  const deny = (msg) => httpErr(403, msg);
  const notService = (who, what) => { if (SERVICE.test(String(who.user || ''))) throw deny('a service or AI identity cannot ' + what); };

  // ---------- reporting authority
  function holder(roleId, prefDept) {
    const L = people().filter((p) => p.role === roleId).sort((a, b) => (a.name < b.name ? -1 : 1));
    return L.find((p) => p.department === prefDept) || L[0] || null;
  }
  function deptHead(deptId, except) {
    const d = deptId ? C.dep().get(deptId) : null; if (!d || !d.head_role) return null;
    const h = holder(d.head_role, deptId); return h && h.id !== except ? h : null;
  }
  function managerOf(p) {
    if (!p) return null;
    if (p.reports_to) { const m = person(p.reports_to); if (m && m.active !== false && m.id !== p.id) return m; }
    const r = p.role ? C.role().get(p.role) : null;
    if (r && r.reports_to_role) { const m = holder(r.reports_to_role, p.department); if (m && m.id !== p.id) return m; }
    return deptHead(p.department, p.id);
  }
  function chain(p) { const out = [], seen = new Set([p && p.id]); let m = managerOf(p); while (m && !seen.has(m.id) && out.length < 20) { out.push(m); seen.add(m.id); m = managerOf(m); } return out; }
  const reportsTo = (p, boss) => !!(p && boss && chain(p).some((m) => m.id === boss.id));
  const directReports = (boss) => people().filter((p) => { const m = managerOf(p); return m && m.id === boss.id; });
  const card = (p, full) => (p ? Object.assign({ id: p.id, name: p.name, role: p.role || null, role_name: p.role && C.role().get(p.role) ? C.role().get(p.role).name : null, department: p.department || null }, full ? { user: p.user || null, email: p.email || null } : {}) : null);

  // ---------- organisation (admin)
  const idOf = (b, k, name) => b[k] || (low(name).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'x' + fp(name + iso()).slice(0, 6));
  function saveDept(input, who) {
    notService(who, 'change the organisation');
    const b = body(input).str('id', { max: 48, re: SLUG, msg: 'id must be lower-case letters, digits and dashes (infrastructure)' }).str('name', { required: true, max: 80 }).str('description', { max: 300 })
      .str('head_role', { max: 48, re: SLUG, msg: 'head_role must be a role id' }).done();
    if (b.head_role && !C.role().get(b.head_role)) throw httpErr(400, 'head_role: there is no role "' + b.head_role + '"');
    const id = idOf(b, 'id', b.name), cur = C.dep().get(id);
    if (C.dep().all().some((d) => d.id !== id && low(d.name) === low(b.name))) throw httpErr(400, 'name: a department called "' + b.name + '" already exists');
    const rec = Object.assign({}, cur || { created_by: who.user, created_at: iso() }, { id, name: b.name, description: b.description || '', head_role: b.head_role || null, updated_by: who.user, updated_at: iso() });
    C.dep().put(rec); audit(who, cur ? 'workspace.department.update' : 'workspace.department.create', id, { name: rec.name, head_role: rec.head_role });
    return rec;
  }
  function saveRole(input, who) {
    notService(who, 'change the organisation');
    const b = body(input).str('id', { max: 48, re: SLUG, msg: 'id must be lower-case letters, digits and dashes (grc-manager)' }).str('name', { required: true, max: 80 }).str('description', { max: 300 })
      .str('department', { required: true, max: 48, re: SLUG, msg: 'department must be a department id' }).str('reports_to_role', { max: 48, re: SLUG, msg: 'reports_to_role must be a role id' })
      .str('access_role', { max: 48, re: /^[a-z0-9][a-z0-9-]{0,47}$/, msg: 'access_role must be a role id from Roles & Functions' }).done();
    if (!C.dep().get(b.department)) throw httpErr(400, 'department: there is no department "' + b.department + '"');
    const id = idOf(b, 'id', b.name);
    if (b.reports_to_role) {
      if (b.reports_to_role === id) throw httpErr(400, 'reports_to_role: a role cannot report to itself');
      if (!C.role().get(b.reports_to_role)) throw httpErr(400, 'reports_to_role: there is no role "' + b.reports_to_role + '"');
      let r = C.role().get(b.reports_to_role), n = 0; while (r && r.reports_to_role && n++ < 50) { if (r.reports_to_role === id) throw httpErr(400, 'reports_to_role: ' + b.reports_to_role + ' already reports (through ' + r.id + ') to ' + id + ' - that would be a loop'); r = C.role().get(r.reports_to_role); }
    }
    const cur = C.role().get(id);
    const rec = Object.assign({}, cur || { created_by: who.user, created_at: iso() }, { id, name: b.name, description: b.description || '', department: b.department, reports_to_role: b.reports_to_role || null, access_role: b.access_role || null, updated_by: who.user, updated_at: iso() });
    C.role().put(rec); audit(who, cur ? 'workspace.role.update' : 'workspace.role.create', id, { name: rec.name, department: rec.department, reports_to_role: rec.reports_to_role });
    return rec;
  }
  function savePerson(input, who) {
    notService(who, 'change the organisation');
    const b = body(input).str('id', { max: 48, re: SLUG, msg: 'id must be lower-case letters, digits and dashes' }).str('name', { required: true, max: 100 })
      .str('user', { max: 120, re: USERNAME, msg: 'user must be the sign-in name used on this platform (letters, digits, . _ - @)' }).str('email', { max: 200, email: true })
      .str('department', { required: true, max: 48, re: SLUG, msg: 'department must be a department id' }).str('role', { max: 48, re: SLUG, msg: 'role must be a role id' })
      .str('reports_to', { max: 48, re: SLUG, msg: 'reports_to must be a person id' }).bool('active', { def: true }).done();
    if (!C.dep().get(b.department)) throw httpErr(400, 'department: there is no department "' + b.department + '"');
    if (b.role && !C.role().get(b.role)) throw httpErr(400, 'role: there is no role "' + b.role + '"');
    const id = idOf(b, 'id', b.name), cur = C.ppl().get(id);
    if (b.user && C.ppl().all().some((p) => p.id !== id && low(p.user) === low(b.user))) throw httpErr(400, 'user: the sign-in name "' + b.user + '" is already on another profile');
    if (b.email && C.ppl().all().some((p) => p.id !== id && low(p.email) === low(b.email))) throw httpErr(400, 'email: ' + b.email + ' is already on another profile');
    if (b.reports_to) {
      if (b.reports_to === id) throw httpErr(400, 'reports_to: a person cannot report to themselves');
      const m = person(b.reports_to); if (!m) throw httpErr(400, 'reports_to: there is no person "' + b.reports_to + '"');
      if (chain(m).some((x) => x.id === id)) throw httpErr(400, 'reports_to: ' + m.name + ' already reports to this person - that would be a loop');
    }
    const rec = Object.assign({}, cur || { created_by: who.user, created_at: iso() }, { id, name: b.name, user: b.user || null, email: b.email ? low(b.email) : null, department: b.department, role: b.role || null, reports_to: b.reports_to || null, active: b.active, updated_by: who.user, updated_at: iso() });
    C.ppl().put(rec);
    if (cur && cur.email && low(cur.email) !== rec.email) dropToken(cur.user, 'profile e-mail changed');
    audit(who, cur ? 'workspace.person.update' : 'workspace.person.create', id, { name: rec.name, department: rec.department, role: rec.role, reports_to: rec.reports_to, active: rec.active, user: rec.user ? 'set' : 'none', email: rec.email ? 'set' : 'none' });
    return card(rec, true);
  }
  function saveWorkflow(input, who) {
    notService(who, 'change the organisation');
    const b = body(input).str('id', { max: 48, re: SLUG, msg: 'id must be lower-case letters, digits and dashes' }).str('name', { required: true, max: 80 }).str('description', { max: 300 })
      .list('steps', { required: true, max: 6 }).done();
    const id = idOf(b, 'id', b.name);
    if (id === DEFAULT_WF.id) throw httpErr(400, 'id: "' + id + '" is the built-in workflow - choose another id');
    const steps = b.steps.map((s, i) => {
      if (!s || typeof s !== 'object' || Array.isArray(s)) throw httpErr(400, 'steps[' + i + '] must be {name, to}');
      const e = body(s).str('name', { required: true, max: 60 }).str('to', { required: true, max: 60, re: STEP_TO, msg: 'steps[' + i + '].to must be manager, manager2, dept_head, role:<id> or person:<id>' }).done();
      if (e.to.startsWith('role:') && !C.role().get(e.to.slice(5))) throw httpErr(400, 'steps[' + i + '].to: there is no role "' + e.to.slice(5) + '"');
      if (e.to.startsWith('person:') && !person(e.to.slice(7))) throw httpErr(400, 'steps[' + i + '].to: there is no person "' + e.to.slice(7) + '"');
      return e;
    });
    const cur = C.wf().get(id);
    const rec = Object.assign({}, cur || { created_by: who.user, created_at: iso() }, { id, name: b.name, description: b.description || '', steps, updated_by: who.user, updated_at: iso() });
    C.wf().put(rec); audit(who, cur ? 'workspace.workflow.update' : 'workspace.workflow.create', id, { name: rec.name, steps: steps.map((s) => s.to) });
    return rec;
  }
  function remove(kind, id, who) {
    notService(who, 'change the organisation');
    const col = { departments: C.dep, roles: C.role, people: C.ppl, workflows: C.wf }[kind]();
    const cur = col.get(id); if (!cur) throw httpErr(404, 'there is no ' + kind.replace(/s$/, '') + ' "' + id + '"');
    const used = [];
    if (kind === 'departments') { if (C.role().all().some((r) => r.department === id)) used.push('roles'); if (C.ppl().all().some((p) => p.department === id)) used.push('people'); }
    if (kind === 'roles') { if (C.ppl().all().some((p) => p.role === id)) used.push('people'); if (C.role().all().some((r) => r.reports_to_role === id)) used.push('roles that report to it'); if (C.dep().all().some((d) => d.head_role === id)) used.push('a department head'); if (C.wf().all().some((w) => w.steps.some((s) => s.to === 'role:' + id))) used.push('workflows'); }
    if (kind === 'people') { if (C.ppl().all().some((p) => p.reports_to === id)) used.push('people who report to them'); if (C.task().all().some((t) => OPEN.includes(t.status) && t.assignee === id)) used.push('open tasks'); if (C.wf().all().some((w) => w.steps.some((s) => s.to === 'person:' + id))) used.push('workflows'); }
    if (kind === 'workflows' && C.task().all().some((t) => OPEN.includes(t.status) && t.workflow === id)) used.push('open tasks');
    if (used.length) throw httpErr(409, cur.name + ' is still used by ' + used.join(', ') + ' - change those first' + (kind === 'people' ? ' (or mark the person inactive)' : ''));
    if (kind === 'people' && cur.user) dropToken(cur.user, 'profile removed');
    col.remove(id); audit(who, 'workspace.' + kind.replace(/s$/, '') + '.delete', id, { name: cur.name });
    return { ok: true };
  }
  function applyTemplate(input, who) {
    notService(who, 'change the organisation');
    const b = body(input || {}).oneOf('template', ['standard-it'], { required: true }).done();
    const added = { departments: [], roles: [] };
    for (const d of TEMPLATE.departments) if (!C.dep().get(d.id)) { C.dep().put(Object.assign({}, d, { head_role: null, created_by: who.user, created_at: iso(), updated_by: who.user, updated_at: iso() })); added.departments.push(d.id); }
    for (const r of TEMPLATE.roles) if (!C.role().get(r.id)) { C.role().put(Object.assign({ description: '', access_role: null }, r, { created_by: who.user, created_at: iso(), updated_by: who.user, updated_at: iso() })); added.roles.push(r.id); }
    for (const d of TEMPLATE.departments) { const cur = C.dep().get(d.id); if (cur && !cur.head_role && C.role().get(d.head_role)) C.dep().put(Object.assign({}, cur, { head_role: d.head_role })); }
    audit(who, 'workspace.template.apply', b.template, added);
    return Object.assign({ ok: true }, added);
  }
  function org(who) {
    const full = isAdmin(who);
    return {
      departments: C.dep().all().sort((a, b) => (a.name < b.name ? -1 : 1)).map((d) => Object.assign({}, d, { head: card(deptHead(d.id), false), people: people().filter((p) => p.department === d.id).length })),
      roles: C.role().all().sort((a, b) => (a.name < b.name ? -1 : 1)).map((r) => Object.assign({}, r, { holders: people().filter((p) => p.role === r.id).map((p) => p.name) })),
      people: C.ppl().all().sort((a, b) => (a.name < b.name ? -1 : 1)).map((p) => Object.assign(card(p, full), { active: p.active !== false, reports_to: p.reports_to || null, manager: card(managerOf(p), false), connected: full ? !!C.tok().get(low(p.user || '#')) : undefined })),
      workflows: [DEFAULT_WF].concat(C.wf().all().sort((a, b) => (a.name < b.name ? -1 : 1))),
      template: TEMPLATE, can_edit: full,
    };
  }

  // ---------- tasks
  const wfOf = (id) => (id === DEFAULT_WF.id || !id ? DEFAULT_WF : C.wf().get(id));
  function resolveStep(t, idx) {
    const wf = wfOf(t.workflow), st = wf && wf.steps[idx]; if (!st) return null;
    const a = person(t.assignee); let r = null;
    if (st.to === 'manager') r = managerOf(a);
    else if (st.to === 'manager2') r = managerOf(managerOf(a));
    else if (st.to === 'dept_head') r = deptHead(a && a.department, a && a.id);
    else if (st.to.startsWith('role:')) r = holder(st.to.slice(5), a && a.department);
    else if (st.to.startsWith('person:')) r = person(st.to.slice(7));
    if (r && a && r.id === a.id) r = managerOf(a);   // never the assignee
    return r && r.active !== false ? r : null;
  }
  const hist = (t, who, action, note) => { t.history = (t.history || []).concat([{ at: iso(), by: who.user, action, note: note || null }]).slice(-200); };
  function taskView(t) {
    const wf = wfOf(t.workflow), rv = t.status === 'in_review' ? resolveStep(t, t.step) : null;
    const due = t.due ? Date.parse(t.due + 'T23:59:59Z') - RIYADH : null;
    return Object.assign({}, t, { assignee_card: card(person(t.assignee), false), workflow_name: wf ? wf.name : t.workflow, steps: wf ? wf.steps.map((s, i) => ({ name: s.name, to: s.to, done: t.status === 'done' || (t.status === 'in_review' && i < t.step), current: t.status === 'in_review' && i === t.step })) : [],
      reviewer: t.status === 'in_review' ? (rv ? card(rv, false) : { name: 'an administrator (no one holds this step)' }) : null, overdue: !!(due && OPEN.includes(t.status) && now() > due) });
  }
  function canSee(t, who, me) {
    if (isAdmin(who) || t.created_by === who.user) return true; if (!me) return false;
    const a = person(t.assignee); return t.assignee === me.id || reportsTo(a, me) || (t.status === 'in_review' && (resolveStep(t, t.step) || {}).id === me.id);
  }
  function listTasks(q, who) {
    const me = meOf(who), scope = q.scope || 'mine';
    if (!['mine', 'review', 'team', 'created', 'all'].includes(scope)) throw httpErr(400, 'scope must be mine, review, team, created or all');
    if (scope === 'all' && !isAdmin(who)) throw deny('only an administrator sees every task');
    let L = C.task().all();
    if (scope === 'mine') L = me ? L.filter((t) => t.assignee === me.id) : [];
    if (scope === 'review') L = L.filter((t) => t.status === 'in_review' && (() => { const r = resolveStep(t, t.step); return r ? !!me && r.id === me.id : isAdmin(who) && !(me && t.assignee === me.id); })());
    if (scope === 'team') L = me ? L.filter((t) => reportsTo(person(t.assignee), me)) : [];
    if (scope === 'created') L = L.filter((t) => t.created_by === who.user);
    const rank = { urgent: 0, high: 1, normal: 2, low: 3 };
    return { scope, tasks: L.filter((t) => canSee(t, who, me)).sort((a, b) => (OPEN.includes(a.status) === OPEN.includes(b.status) ? (rank[a.priority] - rank[b.priority]) || String(a.due || '9').localeCompare(String(b.due || '9')) : OPEN.includes(a.status) ? -1 : 1)).slice(0, 500).map(taskView) };
  }
  function mayAssign(who, me, a) { return isAdmin(who) || (!!me && (a.id === me.id || reportsTo(a, me))); }
  function createTask(input, who) {
    notService(who, 'assign work');
    const b = body(input).str('title', { required: true, max: 160 }).str('detail', { max: 4000 }).str('assignee', { required: true, max: 48, re: SLUG, msg: 'assignee must be a person id' })
      .oneOf('priority', PRIORITY, { def: 'normal' }).date('due').str('workflow', { max: 48, re: SLUG, msg: 'workflow must be a workflow id' }).done();
    const a = person(b.assignee); if (!a || a.active === false) throw httpErr(400, 'assignee: there is no active person "' + b.assignee + '"');
    if (b.workflow && !wfOf(b.workflow)) throw httpErr(400, 'workflow: there is no workflow "' + b.workflow + '"');
    const me = meOf(who);
    if (!mayAssign(who, me, a)) throw deny(me ? a.name + ' does not report to you - only their reporting line or an administrator assigns them work' : 'your sign-in has no profile in Team Workspace - ask an administrator to add you');
    const id = 'TSK-' + new Date(now()).toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex');
    const t = { id, title: b.title, detail: b.detail || '', assignee: a.id, department: a.department, priority: b.priority, due: b.due || null, workflow: b.workflow || DEFAULT_WF.id, status: 'assigned', step: 0,
      created_by: who.user, created_by_name: me ? me.name : who.user, created_at: iso(), updated_at: iso(), history: [] };
    hist(t, who, 'assigned', 'to ' + a.name); C.task().put(t);
    audit(who, 'workspace.task.create', id, { assignee: a.id, priority: t.priority, due: t.due, workflow: t.workflow });
    return taskView(t);
  }
  function act(id, action, input, who) {
    notService(who, 'act on a task');
    const t0 = C.task().get(id); if (!t0) throw httpErr(404, 'there is no task "' + id + '"');
    const t = JSON.parse(JSON.stringify(t0)), me = meOf(who), a = person(t.assignee), mine = !!me && me.id === t.assignee;
    const b = body(input || {}).str('note', { max: 2000 }).str('assignee', { max: 48, re: SLUG, msg: 'assignee must be a person id' }).done();
    if (!canSee(t, who, me)) throw httpErr(404, 'there is no task "' + id + '"');
    const need = (ok, msg) => { if (!ok) throw deny(msg); };
    const state = (...s) => { if (!s.includes(t.status)) throw httpErr(409, 'the task is ' + t.status.replace('_', ' ') + ' - it cannot be ' + action + (action.endsWith('e') ? 'd' : 'ed') + ' now'); };
    let detail = {};
    if (action === 'start') { need(mine, 'only ' + (a ? a.name : 'the assignee') + ' starts this task'); state('assigned', 'returned'); t.status = 'in_progress'; hist(t, who, 'started'); }
    else if (action === 'submit') {
      need(mine, 'only ' + (a ? a.name : 'the assignee') + ' submits this task'); state('assigned', 'in_progress', 'returned');
      t.status = 'in_review'; t.step = 0; t.submitted_at = iso(); hist(t, who, 'submitted for review', b.note);
      const r = resolveStep(t, 0); detail = { reviewer: r ? r.id : 'admin' };
    } else if (action === 'approve' || action === 'return') {
      state('in_review');
      need(!mine, 'you cannot review your own task');
      const r = resolveStep(t, t.step);
      need(r ? !!me && me.id === r.id : isAdmin(who), r ? 'this step is for ' + r.name + ' to decide' : 'no one holds this step - an administrator decides it');
      if (action === 'return') { if (!b.note) throw httpErr(400, 'note: say what needs to change when you return a task'); t.status = 'returned'; t.step = 0; hist(t, who, 'returned', b.note); }
      else {
        const wf = wfOf(t.workflow); hist(t, who, 'approved: ' + ((wf && wf.steps[t.step]) || {}).name, b.note);
        if (t.step + 1 >= (wf ? wf.steps.length : 1)) { t.status = 'done'; t.done_at = iso(); } else t.step++;
      }
      detail = { step: t.step, status: t.status };
    } else if (action === 'comment') { if (!b.note) throw httpErr(400, 'note is required'); hist(t, who, 'comment', b.note); }
    else if (action === 'cancel') { need(isAdmin(who) || t.created_by === who.user, 'only the person who assigned it or an administrator cancels a task'); state(...OPEN); if (!b.note) throw httpErr(400, 'note: give the reason for cancelling'); t.status = 'cancelled'; hist(t, who, 'cancelled', b.note); }
    else if (action === 'reassign') {
      state(...OPEN); const n = person(b.assignee); if (!n || n.active === false) throw httpErr(400, 'assignee: there is no active person "' + (b.assignee || '') + '"');
      need(isAdmin(who) || (mayAssign(who, me, n) && (t.created_by === who.user || reportsTo(a, me))), 'only the assigner, the assignee\'s reporting line or an administrator reassigns');
      hist(t, who, 'reassigned', 'from ' + (a ? a.name : t.assignee) + ' to ' + n.name + (b.note ? ' - ' + b.note : '')); t.assignee = n.id; t.department = n.department; t.status = 'assigned'; t.step = 0; detail = { assignee: n.id };
    } else throw httpErr(404, 'unknown action');
    t.updated_at = iso(); C.task().put(t);
    audit(who, 'workspace.task.' + action, id, Object.assign({ status: t.status }, detail));
    return taskView(t);
  }

  // ---------- my page
  function me(who) {
    const p = meOf(who);
    const tok = C.tok().get(low(who.user)), c = cfg();
    const base = { user: who.user, role: who.role, profile: null, m365: { configured: m365Ready(), connected: !!tok, account: tok ? tok.upn : null, connected_at: tok ? tok.at : null, features: c.features } };
    if (!p) return Object.assign(base, { note: 'Your sign-in has no profile in Team Workspace yet - an administrator adds you under Organisation.' });
    const reports = directReports(p);
    const T = C.task().all(), open = (t) => OPEN.includes(t.status);
    const mine = T.filter((t) => t.assignee === p.id && open(t)).map(taskView);
    const review = T.filter((t) => t.status === 'in_review' && (resolveStep(t, t.step) || {}).id === p.id).map(taskView);
    const team = T.filter((t) => open(t) && reportsTo(person(t.assignee), p));
    const d = p.department ? C.dep().get(p.department) : null;
    return Object.assign(base, { profile: Object.assign(card(p, true), { department_name: d ? d.name : null }), managers: chain(p).map((m) => card(m, false)), reports: reports.map((r) => card(r, false)),
      head: card(deptHead(p.department), false), tasks: { mine, review, team: { open: team.length, overdue: team.filter((t) => taskView(t).overdue).length, in_review: team.filter((t) => t.status === 'in_review').length } } });
  }

  // ---------- Microsoft 365, delegated, per person
  const cfg = () => Object.assign({ enabled: false, features: { mail: true, reply: true, calendar: true, teams: true } }, C.cfg().get('cfg') || {});
  const m365Ready = () => { const c = cfg(); return !!(c.enabled && c.tenant_id && c.client_id && c.secret_enc && c.redirect_uri); };
  function m365Settings() {
    const c = cfg();
    return { enabled: !!c.enabled, ready: m365Ready(), tenant_id: c.tenant_id || '', client_id: c.client_id || '', client_secret_set: !!c.secret_enc, redirect_uri: c.redirect_uri || '', features: c.features,
      connected: C.tok().all().length, scopes: SCOPES, vault: sealer.available() ? 'available' : 'unavailable: ' + sealer.unavailableReason(), updated_by: c.updated_by || null, updated_at: c.updated_at || null,
      setup: ['Entra ID -> App registrations -> New registration (single tenant).', 'Authentication -> add the Web platform with the redirect URI below (this page, https).', 'Certificates & secrets -> new client secret; paste it here (it is sealed in the vault).',
        'API permissions -> Microsoft Graph -> DELEGATED: ' + SCOPES.replace('openid profile offline_access ', '') + ' -> Grant admin consent.', 'No application permissions: each person signs in and the platform reaches only their own mailbox, calendar and chats.'] };
  }
  function saveM365(input, who) {
    notService(who, 'change these settings');
    const b = body(input).bool('enabled').str('tenant_id', { max: 36, re: GUID, msg: 'tenant_id must be the directory (tenant) id - a GUID' }).str('client_id', { max: 36, re: GUID, msg: 'client_id must be the application (client) id - a GUID' })
      .str('client_secret', { max: 200 }).str('redirect_uri', { max: 300, re: /^https:\/\/[A-Za-z0-9.-]+(:\d{2,5})?\/[A-Za-z0-9._~\/-]*my-workspace\.html$/, msg: 'redirect_uri must be the https address of my-workspace.html on this portal' })
      .bool('mail').bool('reply').bool('calendar').bool('teams').done();
    const c = Object.assign({}, cfg()); c.features = Object.assign({}, c.features);
    for (const k of ['enabled', 'tenant_id', 'client_id', 'redirect_uri']) if (b[k] !== undefined) c[k] = b[k];
    for (const k of ['mail', 'reply', 'calendar', 'teams']) if (b[k] !== undefined) c.features[k] = b[k];
    if (b.client_secret) { if (!sealer.available()) throw httpErr(503, 'credential vault unavailable: ' + sealer.unavailableReason()); c.secret_enc = sealer.seal('graph-app', b.client_secret); }
    if (c.enabled && !(c.tenant_id && c.client_id && c.secret_enc && c.redirect_uri)) throw httpErr(400, 'enabled needs tenant_id, client_id, client_secret and redirect_uri');
    const appChanged = (b.tenant_id && b.tenant_id !== cfg().tenant_id) || (b.client_id && b.client_id !== cfg().client_id);
    Object.assign(c, { id: 'cfg', updated_by: who.user, updated_at: iso() }); C.cfg().put(c);
    let dropped = 0; if (appChanged) for (const t of C.tok().all()) { C.tok().remove(t.id); dropped++; }
    cache.clear();
    audit(who, 'workspace.m365.settings', 'm365', { enabled: !!c.enabled, tenant_id: c.tenant_id || null, client_id: c.client_id || null, features: c.features, client_secret: b.client_secret ? 'changed' : 'unchanged', connections_dropped: dropped });
    return m365Settings();
  }
  const states = new Map(), cache = new Map(), sends = new Map();
  function connect(who) {
    notService(who, 'connect a mailbox');
    if (!m365Ready()) throw httpErr(424, 'Microsoft 365 is not set up for Team Workspace yet - an administrator completes it under Settings');
    const p = meOf(who); if (!p || !p.email) throw httpErr(424, 'your profile has no work e-mail address - an administrator adds it under Organisation, then connect again');
    const c = cfg(), verifier = b64url(crypto.randomBytes(32)), state = b64url(crypto.randomBytes(24));
    for (const [k, v] of states) if (v.exp < now()) states.delete(k);
    states.set(state, { user: low(who.user), verifier, exp: now() + 10 * 60000 });
    const q = new URLSearchParams({ client_id: c.client_id, response_type: 'code', redirect_uri: c.redirect_uri, response_mode: 'query', scope: SCOPES, state, code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256', login_hint: p.email, prompt: 'select_account' });
    return { url: loginBase + '/' + encodeURIComponent(c.tenant_id) + '/oauth2/v2.0/authorize?' + q.toString() };
  }
  async function tokenCall(form) {
    const c = cfg(); let secret;
    try { secret = sealer.unseal('graph-app', c.secret_enc); } catch (e) { throw httpErr(424, 'the client secret cannot be opened from the vault - an administrator saves it again'); }
    const r = await request(loginBase + '/' + encodeURIComponent(c.tenant_id) + '/oauth2/v2.0/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(Object.assign({ client_id: c.client_id, client_secret: secret, scope: SCOPES }, form)).toString(), timeoutMs: 30000 });
    if (r.status >= 300 || !r.json || !r.json.access_token) { const code = r.json && r.json.error ? String(r.json.error).slice(0, 60) : 'HTTP ' + r.status; throw Object.assign(httpErr(424, 'Microsoft refused the sign-in (' + code + ')'), { oauth: code }); }
    return r.json;
  }
  async function callback(input, who) {
    notService(who, 'connect a mailbox');
    const b = body(input).str('code', { required: true, max: 4000 }).str('state', { required: true, max: 100, re: /^[A-Za-z0-9_-]{16,100}$/, msg: 'state is not valid - start the connection again' }).done();
    const s = states.get(b.state); states.delete(b.state);
    if (!s || s.exp < now()) throw httpErr(400, 'state: this sign-in has expired or was already used - press Connect again');
    if (s.user !== low(who.user)) { audit(who, 'workspace.m365.connect_refused', who.user, { reason: 'state belongs to another sign-in' }); throw deny('this Microsoft sign-in was started by another platform user'); }
    const p = meOf(who); if (!p || !p.email) throw httpErr(424, 'your profile has no work e-mail address');
    const j = await tokenCall({ grant_type: 'authorization_code', code: b.code, redirect_uri: cfg().redirect_uri, code_verifier: s.verifier });
    const u = await graphRaw(j.access_token, 'GET', '/me?$select=userPrincipalName,mail,displayName');
    const upn = low((u && (u.mail || u.userPrincipalName)) || ''), upn2 = low((u && u.userPrincipalName) || '');
    if (upn !== p.email && upn2 !== p.email) { audit(who, 'workspace.m365.connect_refused', who.user, { reason: 'Microsoft account differs from the profile e-mail' }); throw deny('you signed in to Microsoft as ' + (u && (u.mail || u.userPrincipalName)) + ' but your profile is ' + p.email + ' - sign in with your own work account'); }
    if (!j.refresh_token) throw httpErr(424, 'Microsoft did not return a refresh token - the app registration must allow offline_access');
    C.tok().put({ id: low(who.user), enc: sealer.seal('rt:' + low(who.user), j.refresh_token), upn: p.email, at: iso(), scope: String(j.scope || '').slice(0, 400) });
    cache.set(low(who.user), { token: j.access_token, exp: now() + (Number(j.expires_in) || 3600) * 1000 - 60000 });
    audit(who, 'workspace.m365.connect', who.user, { account: 'profile e-mail' });
    return { ok: true, account: p.email };
  }
  function dropToken(user, why) { if (!user) return; const k = low(user); if (C.tok().get(k)) { C.tok().remove(k); cache.delete(k); if (app.log) app.log.info && app.log.info('workspace: Microsoft 365 connection removed', { user, why }); } }
  function disconnect(who) { const had = !!C.tok().get(low(who.user)); dropToken(who.user, 'disconnected by the person'); audit(who, 'workspace.m365.disconnect', who.user, { had }); return { ok: true }; }
  function revoke(input, who) {
    notService(who, 'remove a connection');
    const b = body(input).str('user', { required: true, max: 120, re: USERNAME, msg: 'user must be a sign-in name' }).done();
    const had = !!C.tok().get(low(b.user)); dropToken(b.user, 'removed by an administrator'); audit(who, 'workspace.m365.revoke', b.user, { had }); return { ok: true, had };
  }
  async function access(who) {
    if (!m365Ready()) throw httpErr(424, 'Microsoft 365 is not set up for Team Workspace yet');
    const k = low(who.user), c0 = cache.get(k); if (c0 && c0.exp > now()) return c0.token;
    const t = C.tok().get(k); if (!t) throw httpErr(424, 'connect your Microsoft 365 account first');
    const p = meOf(who); if (!p || low(p.email) !== t.upn) { dropToken(who.user, 'profile no longer matches'); throw httpErr(424, 'your profile changed - connect your Microsoft 365 account again'); }
    let rt; try { rt = sealer.unseal('rt:' + k, t.enc); } catch (e) { dropToken(who.user, 'sealed token unreadable'); throw httpErr(424, 'your connection cannot be opened (vault key changed) - connect again'); }
    let j;
    try { j = await tokenCall({ grant_type: 'refresh_token', refresh_token: rt }); }
    catch (e) { if (e.oauth === 'invalid_grant') { dropToken(who.user, 'refresh token no longer valid'); throw httpErr(424, 'your Microsoft 365 sign-in has expired or was revoked - connect again'); } throw e; }
    if (j.refresh_token) C.tok().put(Object.assign({}, t, { enc: sealer.seal('rt:' + k, j.refresh_token), refreshed_at: iso() }));
    cache.set(k, { token: j.access_token, exp: now() + (Number(j.expires_in) || 3600) * 1000 - 60000 });
    return j.access_token;
  }
  async function graphRaw(bearer, method, path, payload, extra) {
    let r;
    try { r = await request(graphBase + path, { method, headers: Object.assign({ Authorization: 'Bearer ' + bearer, Accept: 'application/json' }, payload ? { 'Content-Type': 'application/json' } : {}, extra || {}), body: payload ? JSON.stringify(payload) : undefined, timeoutMs: 30000 }); }
    catch (e) { warn('net', 'workspace: Microsoft Graph not reachable', { err: String(e.message).slice(0, 160) }); throw httpErr(424, 'Microsoft 365 is not reachable from the platform (' + String(e.message).slice(0, 80) + ')'); }
    if (r.status === 404) throw httpErr(404, 'not found in your Microsoft 365 account');
    if (r.status === 403) throw httpErr(424, 'Microsoft refused this (403) - the app registration lacks a delegated permission or admin consent: ' + SCOPES);
    if (r.status >= 300) { const m = r.json && r.json.error ? String(r.json.error.code || '').slice(0, 60) : 'HTTP ' + r.status; warn('graph', 'workspace: Graph call failed', { path: path.split('?')[0].replace(/\/[A-Za-z0-9=_+:@.-]{20,}/g, '/<id>'), status: r.status }); throw httpErr(424, 'Microsoft 365 answered ' + m); }
    return r.json || {};
  }
  const feature = (k) => { if (!cfg().features[k]) throw httpErr(424, 'an administrator has switched off ' + k + ' in Team Workspace'); };
  const g = async (who, method, path, payload, extra) => graphRaw(await access(who), method, path, payload, extra);
  const addr = (x) => (x && x.emailAddress ? { name: x.emailAddress.name || '', address: low(x.emailAddress.address) } : null);
  function tagMail(who, from) {
    const p = meOf(who); if (!p || !from) return null;
    const mgr = chain(p).find((m) => m.email && m.email === from.address); if (mgr) return mgr.id === (managerOf(p) || {}).id ? 'from your manager' : 'from your reporting line';
    if (directReports(p).some((r) => r.email && r.email === from.address)) return 'from your team';
    return null;
  }
  async function mail(q, who) {
    feature('mail');
    const top = Math.min(50, Math.max(5, parseInt(q.top, 10) || 25)), unread = q.unread === '1';
    const j = await g(who, 'GET', '/me/mailFolders/inbox/messages?$top=' + top + '&$select=id,subject,from,receivedDateTime,isRead,importance,flag,bodyPreview,hasAttachments&$orderby=receivedDateTime%20desc' + (unread ? '&$filter=isRead%20eq%20false' : ''));
    const L = (j.value || []).map((m) => { const from = addr(m.from); return { id: m.id, subject: String(m.subject || '(no subject)').slice(0, 300), from, received: m.receivedDateTime, unread: !m.isRead, important: m.importance === 'high', flagged: !!(m.flag && m.flag.flagStatus === 'flagged'), attachments: !!m.hasAttachments, preview: String(m.bodyPreview || '').slice(0, 280), tag: tagMail(who, from) }; });
    return { messages: L, unread: L.filter((m) => m.unread).length, needs_you: L.filter((m) => m.unread && (m.tag || m.important || m.flagged)).length, can_reply: !!cfg().features.reply };
  }
  async function mailOne(id, who) {
    feature('mail'); if (!MSGID.test(id)) throw httpErr(400, 'id is not a message id');
    const m = await g(who, 'GET', '/me/messages/' + encodeURIComponent(id) + '?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,importance,body,hasAttachments', null, { Prefer: 'outlook.body-content-type="text"' });
    const from = addr(m.from);
    return { id: m.id, subject: String(m.subject || '(no subject)').slice(0, 300), from, to: (m.toRecipients || []).map(addr).slice(0, 30), cc: (m.ccRecipients || []).map(addr).slice(0, 30), received: m.receivedDateTime, important: m.importance === 'high', attachments: !!m.hasAttachments,
      text: String((m.body && m.body.content) || '').slice(0, 60000), tag: tagMail(who, from), can_reply: !!cfg().features.reply };
  }
  function rate(who, kind) {
    const k = kind + ':' + low(who.user), L = (sends.get(k) || []).filter((t) => t > now() - 3600000);
    if (L.length >= 30) throw httpErr(429, 'more than 30 ' + kind + ' messages in an hour from this page - wait a little or use Outlook / Teams');
    L.push(now()); sends.set(k, L);
  }
  async function reply(id, input, who) {
    notService(who, 'send mail'); feature('mail'); feature('reply');
    if (!MSGID.test(id)) throw httpErr(400, 'id is not a message id');
    const b = body(input).str('comment', { required: true, max: 20000 }).bool('all', { def: false }).done();
    rate(who, 'mail');
    await g(who, 'POST', '/me/messages/' + encodeURIComponent(id) + (b.all ? '/replyAll' : '/reply'), { comment: b.comment });
    audit(who, 'workspace.mail.reply', 'msg:' + fp(id), { all: b.all, length: b.comment.length });
    return { ok: true };
  }
  async function calendar(q, who) {
    feature('calendar');
    const days = Math.min(31, Math.max(1, parseInt(q.days, 10) || 7));
    const t0 = new Date(now() + RIYADH); t0.setUTCHours(0, 0, 0, 0); const start = new Date(t0.getTime() - RIYADH), end = new Date(start.getTime() + days * 86400000);
    const j = await g(who, 'GET', '/me/calendarView?startDateTime=' + start.toISOString() + '&endDateTime=' + end.toISOString() + '&$top=100&$orderby=start/dateTime&$select=id,subject,start,end,location,organizer,isOnlineMeeting,onlineMeeting,isAllDay,isCancelled,responseStatus,showAs', null, { Prefer: 'outlook.timezone="UTC"' });
    const at = (x) => (x && x.dateTime ? new Date(x.dateTime.replace(/Z?$/, 'Z')).toISOString() : null);
    const L = (j.value || []).filter((e) => !e.isCancelled).map((e) => ({ id: fp(e.id), subject: String(e.subject || '(no title)').slice(0, 200), start: at(e.start), end: at(e.end), all_day: !!e.isAllDay, location: String((e.location && e.location.displayName) || '').slice(0, 120),
      organizer: addr(e.organizer), online: !!e.isOnlineMeeting, join: e.onlineMeeting ? teamsJoin(e.onlineMeeting.joinUrl) : null, response: (e.responseStatus && e.responseStatus.response) || null, show_as: e.showAs || null }));
    const n = now(), next = L.find((e) => !e.all_day && Date.parse(e.end) > n) || null;
    return { days, events: L, next, today: L.filter((e) => Date.parse(e.start) < start.getTime() + 86400000).length };
  }
  async function chats(who) {
    feature('teams');
    const j = await g(who, 'GET', '/me/chats?$expand=lastMessagePreview&$top=25&$orderby=lastMessagePreview/createdDateTime%20desc');
    return { chats: (j.value || []).map((c) => ({ id: c.id, topic: String(c.topic || '').slice(0, 200) || null, type: c.chatType, last: c.lastMessagePreview ? { at: c.lastMessagePreview.createdDateTime, from: String((c.lastMessagePreview.from && c.lastMessagePreview.from.user && c.lastMessagePreview.from.user.displayName) || '').slice(0, 100), text: toText((c.lastMessagePreview.body || {}).content).slice(0, 200) } : null })) };
  }
  async function chatMessages(id, who) {
    feature('teams'); if (!CHATID.test(id)) throw httpErr(400, 'id is not a Teams chat id');
    const j = await g(who, 'GET', '/me/chats/' + encodeURIComponent(id) + '/messages?$top=30');
    return { messages: (j.value || []).filter((m) => m.messageType === 'message' && !m.deletedDateTime).map((m) => ({ at: m.createdDateTime, from: String((m.from && m.from.user && m.from.user.displayName) || 'system').slice(0, 100), text: toText((m.body || {}).content).slice(0, 8000) })).reverse() };
  }
  async function chatSend(id, input, who) {
    notService(who, 'send a Teams message'); feature('teams'); feature('reply');
    if (!CHATID.test(id)) throw httpErr(400, 'id is not a Teams chat id');
    const b = body(input).str('text', { required: true, max: 8000 }).done();
    rate(who, 'teams');
    await g(who, 'POST', '/chats/' + encodeURIComponent(id) + '/messages', { body: { contentType: 'text', content: b.text } });
    audit(who, 'workspace.teams.send', 'chat:' + fp(id), { length: b.text.length });
    return { ok: true };
  }

  return { org, me, saveDept, saveRole, savePerson, saveWorkflow, remove, applyTemplate, listTasks, createTask, act, m365Settings, saveM365, connect, callback, disconnect, revoke, mail, mailOne, reply, calendar, chats, chatMessages, chatSend, managerOf, TEMPLATE, SCOPES };
}

function registerTeamWorkspace(srv, app, W0) {
  const W = W0 || createTeamWorkspace(app);
  app.addons = app.addons || {}; app.addons.teamWorkspace = W;
  const own = { anyRole: 'every person acts only on their own profile, tasks and Microsoft 365 account - checked in the handler' };
  srv.route('GET', '/workspace/me', (ctx) => { ctx.need('viewer'); return W.me(ctx.who); });
  srv.route('GET', '/workspace/org', (ctx) => { ctx.need('viewer'); return W.org(ctx.who); });
  for (const k of ['departments', 'roles', 'people', 'workflows']) {
    const fn = { departments: W.saveDept, roles: W.saveRole, people: W.savePerson, workflows: W.saveWorkflow }[k];
    srv.route('POST', '/workspace/' + k, (ctx) => { ctx.need('admin'); return fn(ctx.body, ctx.who); }, { maxBody: 32768 });
    srv.route('POST', '/workspace/' + k + '/:id/delete', (ctx) => { ctx.need('admin'); return W.remove(k, ctx.params.id, ctx.who); });
  }
  srv.route('POST', '/workspace/template', (ctx) => { ctx.need('admin'); return W.applyTemplate(ctx.body, ctx.who); });
  srv.route('GET', '/workspace/tasks', (ctx) => { ctx.need('viewer'); return W.listTasks(ctx.query || {}, ctx.who); });
  srv.route('POST', '/workspace/tasks', (ctx) => { ctx.need('viewer'); return W.createTask(ctx.body, ctx.who); }, Object.assign({ maxBody: 16384 }, { anyRole: 'a manager of any access level assigns to their own reporting line - checked in createTask' }));
  srv.route('POST', '/workspace/tasks/:id/:action', (ctx) => { ctx.need('viewer'); return W.act(ctx.params.id, ctx.params.action, ctx.body, ctx.who); }, { maxBody: 8192, anyRole: 'the assignee or the reviewer of any access level acts - checked per action in act' });
  srv.route('GET', '/workspace/m365/settings', (ctx) => { ctx.need('admin'); return W.m365Settings(); });
  srv.route('POST', '/workspace/m365/settings', (ctx) => { ctx.need('admin'); return W.saveM365(ctx.body, ctx.who); });
  srv.route('POST', '/workspace/m365/revoke', (ctx) => { ctx.need('admin'); return W.revoke(ctx.body, ctx.who); });
  srv.route('POST', '/workspace/m365/connect', (ctx) => { ctx.need('viewer'); return W.connect(ctx.who); }, own);
  srv.route('POST', '/workspace/m365/callback', (ctx) => { ctx.need('viewer'); return W.callback(ctx.body, ctx.who); }, Object.assign({ maxBody: 16384 }, own));
  srv.route('POST', '/workspace/m365/disconnect', (ctx) => { ctx.need('viewer'); return W.disconnect(ctx.who); }, own);
  srv.route('GET', '/workspace/mail', (ctx) => { ctx.need('viewer'); return W.mail(ctx.query || {}, ctx.who); });
  srv.route('GET', '/workspace/mail/:id', (ctx) => { ctx.need('viewer'); return W.mailOne(ctx.params.id, ctx.who); });
  srv.route('POST', '/workspace/mail/:id/reply', (ctx) => { ctx.need('viewer'); return W.reply(ctx.params.id, ctx.body, ctx.who); }, Object.assign({ maxBody: 65536 }, own));
  srv.route('GET', '/workspace/calendar', (ctx) => { ctx.need('viewer'); return W.calendar(ctx.query || {}, ctx.who); });
  srv.route('GET', '/workspace/chats', (ctx) => { ctx.need('viewer'); return W.chats(ctx.who); });
  srv.route('GET', '/workspace/chats/:id/messages', (ctx) => { ctx.need('viewer'); return W.chatMessages(ctx.params.id, ctx.who); });
  srv.route('POST', '/workspace/chats/:id/send', (ctx) => { ctx.need('viewer'); return W.chatSend(ctx.params.id, ctx.body, ctx.who); }, Object.assign({ maxBody: 32768 }, own));
  return W;
}

module.exports = { createTeamWorkspace, registerTeamWorkspace, toText, teamsJoin, TEMPLATE };
