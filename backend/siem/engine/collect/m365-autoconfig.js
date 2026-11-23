// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * Microsoft Security - Auto-Configuration. Finds out how far the Microsoft 365 / Entra ID connection and the tenant's baseline
 * protection have got, and GENERATES what an administrator needs for the next step. It never writes to the tenant: the collector's
 * app is read-only, and every change is made by a Microsoft administrator who runs the generated script, opens the consent link or
 * imports the policy - in Microsoft, under their own sign-in.
 *   readiness     the app details entered (tenant, client ID, secret / certificate); sign-in to Microsoft; each required Graph
 *                 APPLICATION permission granted or not - read from the token's own "roles" claim when Microsoft issued one (exact),
 *                 else from what each dataset answered (403 = not granted); each dataset read. The admin-consent link (fixed
 *                 Microsoft address, the tenant and client IDs validated) and a Microsoft Graph PowerShell script that grants ONLY
 *                 the missing permissions, looked up by name on Microsoft's own Graph service principal (no hard-coded IDs).
 *   hardening     from the Microsoft 365 Security analysis (m365-security.js): the baseline Conditional Access protections (found by
 *                 policy name only - Graph's list gives names and states here), administrators without MFA, MFA coverage, Secure
 *                 Score, report-only policies left for 30+ days. Each check: pass / fail / warn / not read, with its fix.
 *   templates     Conditional Access policies as Microsoft Graph JSON for what is missing - always created REPORT-ONLY
 *                 (enabledForReportingButNotEnforced) and always excluding the emergency-access (break-glass) accounts. Refused
 *                 until at least one break-glass account is recorded, so a template can never lock every administrator out.
 *   plan          an AI configuration plan (soc/ai-loop.js: role-filtered read-only tools, schema-checked, untrusted framing, shared
 *                 budget, UNTRUSTED_RULE). Each step cites a check or permission the tools returned; one that cites anything else
 *                 is marked unverified. A plan is advice - it changes nothing.
 *   GET  {P}/m365/autoconfig                        analyst   readiness, hardening, break-glass, template list
 *   GET  {P}/m365/autoconfig/template/:id           admin     one Conditional Access template (JSON), audited
 *   GET  {P}/m365/autoconfig/script                 admin     the PowerShell that grants the missing permissions, audited
 *   POST {P}/m365/autoconfig/breakglass             admin     {accounts[{id, label}]} - object IDs of the emergency-access accounts
 *   POST {P}/m365/autoconfig/plan                   operator  {focus?} - the AI plan
 */
const { wrap, audit, prefixOf, HttpError } = require('../soc/routeutil');
const { body, param } = require('../util/check');
const G = require('../util/ai-guard');
const { createModel, runLoop } = require('../soc/ai-loop');
const { PERMS, credsOf } = require('./m365-graph');
const SEC = require('./m365-security');

const DAY = 86400000;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.[a-z]{2,})$/i;
const ENABLES = { licenses: 'licences and renewal dates', users: 'directory users', signins: 'sign-in logs (Entra ID P1)', intune: 'Intune managed devices', serviceHealth: 'Microsoft 365 service health',
  secureScore: 'Secure Score', mfa: 'MFA registration', riskyUsers: 'risky users (Entra ID P2)', riskDetections: 'risk detections (Entra ID P2)', conditionalAccess: 'Conditional Access policies', defenderAlerts: 'Defender alerts', apps: 'app registrations and secret expiry' };
// Microsoft's built-in directory role TEMPLATE IDs (the same in every tenant) - the administrator roles Microsoft's own
// "Require MFA for administrators" template covers. Named on the page so they can be reviewed before import.
const ADMIN_ROLES = [
  ['62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'], ['194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator'], ['e8611ab8-c189-46e8-94e1-60213ab1f814', 'Privileged Role Administrator'],
  ['b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'Conditional Access Administrator'], ['29232cdf-9323-42fd-ade2-1d097af3e4de', 'Exchange Administrator'], ['f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'SharePoint Administrator'],
  ['fe930be7-5e62-47db-91af-98c3a49a38b1', 'User Administrator'], ['729827e3-9c14-49f7-bb1b-9608f156bbb8', 'Helpdesk Administrator'], ['b0f54661-2d74-4c50-afa3-1ec803f12efe', 'Billing Administrator'],
  ['9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'Application Administrator'], ['158c047a-c907-4556-b7ef-446551a6b5f7', 'Cloud Application Administrator'], ['c4e39bd9-1100-46d3-8c65-fb160da0071f', 'Authentication Administrator'],
];
const TEMPLATES = {
  'admins-mfa': { name: 'Require MFA for administrators', baseline: 'admins-mfa', licence: 'Entra ID P1', build: (ex) => ({ conditions: { users: { includeRoles: ADMIN_ROLES.map((r) => r[0]), excludeUsers: ex }, applications: { includeApplications: ['All'] }, clientAppTypes: ['all'] }, grantControls: { operator: 'OR', builtInControls: ['mfa'] } }) },
  'all-mfa': { name: 'Require MFA for all users', baseline: 'all-mfa', licence: 'Entra ID P1', build: (ex) => ({ conditions: { users: { includeUsers: ['All'], excludeUsers: ex }, applications: { includeApplications: ['All'] }, clientAppTypes: ['all'] }, grantControls: { operator: 'OR', builtInControls: ['mfa'] } }) },
  legacy: { name: 'Block legacy authentication', baseline: 'legacy', licence: 'Entra ID P1', build: (ex) => ({ conditions: { users: { includeUsers: ['All'], excludeUsers: ex }, applications: { includeApplications: ['All'] }, clientAppTypes: ['exchangeActiveSync', 'other'] }, grantControls: { operator: 'OR', builtInControls: ['block'] } }) },
  'signin-risk': { name: 'Require MFA for risky sign-ins', baseline: 'risk', licence: 'Entra ID P2', build: (ex) => ({ conditions: { users: { includeUsers: ['All'], excludeUsers: ex }, applications: { includeApplications: ['All'] }, clientAppTypes: ['all'], signInRiskLevels: ['high', 'medium'] }, grantControls: { operator: 'OR', builtInControls: ['mfa'] }, sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } } }) },
  'user-risk': { name: 'Require a secure password change for high-risk users', baseline: 'risk', licence: 'Entra ID P2', build: (ex) => ({ conditions: { users: { includeUsers: ['All'], excludeUsers: ex }, applications: { includeApplications: ['All'] }, clientAppTypes: ['all'], userRiskLevels: ['high'] }, grantControls: { operator: 'AND', builtInControls: ['mfa', 'passwordChange'] }, sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } } }) },
};
const lc = (s) => String(s == null ? '' : s).toLowerCase();

function required() {
  const m = new Map();
  for (const [k, v] of Object.entries(PERMS)) for (const p of String(v).split(/\s*\+\s*/)) { const r = m.get(p) || m.set(p, { permission: p, enables: [], blocks: [] }).get(p); r.enables.push(ENABLES[k] || k); r.blocks.push(k); }
  return [...m.values()];
}
const psq = (s) => String(s).replace(/'/g, "''");
function grantScript(clientId, missing) {
  if (!GUID.test(clientId) || !missing.length) return null;
  return [('# ' + ZYB_ORG.short + ' SIEM - grant the missing Microsoft Graph APPLICATION permissions (read-only) to the collector app.'),
    '# Run as a Global Administrator or Privileged Role Administrator, in Microsoft Graph PowerShell. Review before running.',
    'Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All"',
    "$graph = Get-MgServicePrincipal -Filter \"appId eq '00000003-0000-0000-c000-000000000000'\"   # Microsoft Graph",
    "$app = Get-MgServicePrincipal -Filter \"appId eq '" + clientId + "'\"",
    "if (-not $app) { throw 'The collector app has no service principal in this tenant - open the admin-consent link first.' }",
    '$want = @(' + missing.map((p) => "'" + psq(p) + "'").join(', ') + ')',
    'foreach ($p in $want) {',
    '  $role = $graph.AppRoles | Where-Object { $_.Value -eq $p -and $_.AllowedMemberTypes -contains "Application" }',
    '  if (-not $role) { Write-Warning "$p is not a Microsoft Graph application permission"; continue }',
    '  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.Id -PrincipalId $app.Id -ResourceId $graph.Id -AppRoleId $role.Id | Out-Null',
    '  Write-Host "granted $p"',
    '}', '# Then press "Check again" on the Auto-Configuration page: the next sign-in carries the new permissions.'].join('\r\n');
}

function createAutoConfig(deps = {}) {
  const { state } = deps, now = deps.now || Date.now, L = deps.log || { info() {}, warn() {} };
  const graph = deps.m365Graph, col = state.collection('m365_autoconfig');
  const security = deps.m365Security || SEC.createM365Security({ graph, state, now });
  const AI = createModel({ config: deps.config, deps, log: L });
  const breakglass = () => ((col.get('breakglass') || {}).accounts) || [];

  function readiness() {
    const c = credsOf(deps.config || {}), st = graph ? graph.status() : { blocks: {} }, B = st.blocks || {}, roles = st.granted && Array.isArray(st.granted.roles) ? new Set(st.granted.roles) : null;
    const perms = required().map((r) => {
      let granted = null, source = null;
      if (roles) { granted = roles.has(r.permission); source = 'token'; }
      else { const bs = r.blocks.map((b) => B[b]).filter(Boolean); if (bs.some((b) => b.ok)) { granted = true; source = 'dataset'; } else if (bs.some((b) => b.error === 'permission not granted')) { granted = false; source = 'dataset'; } }
      return Object.assign(r, { granted, source });
    });
    const missing = perms.filter((p) => p.granted === false).map((p) => p.permission), unknown = perms.filter((p) => p.granted == null).length;
    const signedIn = !!(st.granted && st.granted.at), signErr = /sign-in to Microsoft failed/.test(String(st.last_error || ''));
    const datasets = Object.entries(B).map(([k, b]) => ({ key: k, enables: ENABLES[k] || k, ok: !!b.ok, error: b.ok ? null : b.error || 'not read', stale_since: b.stale_since || null }));
    const steps = [
      { id: 'app', label: 'Collector app details entered', state: c.errs.length ? 'todo' : 'done', detail: c.errs.length ? c.errs.join(', ') + ' - enter them on the Microsoft 365 page (Connections & Setup)' : 'tenant ' + c.tenant + ' · app ' + c.clientId + ' · ' + (c.certPem ? 'certificate' : 'client secret') },
      { id: 'signin', label: 'Signs in to Microsoft', state: c.errs.length ? 'todo' : signErr ? 'fail' : signedIn ? 'done' : 'todo', detail: signErr ? String(st.last_error).slice(0, 240) : signedIn ? 'last sign-in ' + new Date(st.granted.at).toISOString() : 'not yet - press Check again' },
      { id: 'consent', label: 'Graph permissions granted (admin consent)', state: !perms.some((p) => p.granted != null) ? 'todo' : missing.length ? 'partial' : unknown ? 'partial' : 'done',
        detail: missing.length ? missing.length + ' missing: ' + missing.join(', ') : unknown ? unknown + ' not yet known' : 'all ' + perms.length + ' granted' + (roles ? ' (read from the sign-in token)' : '') },
      { id: 'data', label: 'Security data read', state: !datasets.length ? 'todo' : datasets.every((d) => d.ok) ? 'done' : datasets.some((d) => d.ok) ? 'partial' : 'fail', detail: datasets.length ? datasets.filter((d) => d.ok).length + ' of ' + datasets.length + ' datasets read' : 'no sync yet' },
    ];
    const consent = TENANT.test(c.tenant) && GUID.test(c.clientId) ? 'https://login.microsoftonline.com/' + encodeURIComponent(c.tenant) + '/adminconsent?client_id=' + encodeURIComponent(c.clientId) : null;
    return { steps, permissions: perms, missing, datasets, consent_url: consent, script_available: !!grantScript(c.clientId, missing), tenant: c.tenant || null, client_id: c.clientId || null, granted_source: roles ? 'token' : 'datasets',
      note: 'Read-only application permissions. The consent link and the script are run by a Microsoft administrator in Microsoft - this platform cannot grant itself anything.' };
  }

  function hardening() {
    const a = security.compute(), out = [];
    const add = (id, label, st, detail, fix) => out.push({ id, label, state: st, detail, fix: fix || null });
    if (!a.configured) return { configured: false, checks: [], note: a.note };
    const acc = a.access;
    const tmplFor = { 'admins-mfa': ['admins-mfa'], 'all-mfa': ['all-mfa'], legacy: ['legacy'], risk: ['signin-risk', 'user-risk'], location: [] };
    if (!acc) add('ca', 'Conditional Access readable', 'not_read', 'Policy.Read.All is not granted - the baseline cannot be checked', { permission: 'Policy.Read.All' });
    else {
      for (const b of acc.baseline) add('ca-' + b.id, b.label, b.found ? 'pass' : b.report_only ? 'warn' : 'fail', b.found ? 'enforced by "' + b.found + '" (matched by name - confirm what it enforces)' : b.report_only ? '"' + b.report_only + '" is report-only - review its report, then switch it on' : 'no enforced policy found by name',
        { templates: b.found ? [] : tmplFor[b.id], link: SEC.LINK.ca, note: b.id === 'location' ? 'needs a named location of your own (trusted country / office IPs) - created in Entra first, so no template is generated' : null });
      if (acc.stale_report_only.length) add('ca-stale', 'Report-only policies decided', 'warn', acc.stale_report_only.length + ' polic(ies) report-only for 30+ days: ' + acc.stale_report_only.slice(0, 3).map((p) => p.name).join(', '), { link: SEC.LINK.ca });
    }
    if (a.mfa) {
      const n = Array.isArray(a.mfa.admins) ? a.mfa.admins.length : (a.mfa.admins && a.mfa.admins.count) || 0;
      add('mfa-admins', 'Every administrator registered for MFA', n ? 'fail' : 'pass', n ? n + ' administrator(s) without MFA - the highest-impact gap' : 'all administrators registered', { link: SEC.LINK.mfa });
      add('mfa-all', 'MFA coverage of 95% or more', a.mfa.pct >= 95 ? 'pass' : a.mfa.pct >= 80 ? 'warn' : 'fail', a.mfa.pct + '% of ' + a.mfa.users + ' users registered', { link: SEC.LINK.mfa });
    } else add('mfa', 'MFA registration readable', 'not_read', 'UserAuthenticationMethod.Read.All + AuditLog.Read.All are not granted', { permission: 'UserAuthenticationMethod.Read.All' });
    if (a.score) add('score', 'Secure Score of 60% or more', a.score.pct >= 60 ? 'pass' : a.score.pct >= 40 ? 'warn' : 'fail', a.score.pct + '%' + (a.score.weakest && a.score.weakest.length ? ' - weakest: ' + a.score.weakest.slice(0, 3).map((x) => x.control).join(', ') : ''), { link: SEC.LINK.score });
    else add('score', 'Secure Score readable', 'not_read', 'SecurityEvents.Read.All is not granted', { permission: 'SecurityEvents.Read.All' });
    return { configured: true, checks: out, pass: out.filter((x) => x.state === 'pass').length, fail: out.filter((x) => x.state === 'fail').length, warn: out.filter((x) => x.state === 'warn').length, not_read: out.filter((x) => x.state === 'not_read').length,
      note: 'Baseline policies are found by NAME - Graph gives the name and state here. A pass means a policy with a matching name is enforced; open it to confirm what it does.' };
  }

  function templateList() { return Object.entries(TEMPLATES).map(([id, t]) => ({ id, name: t.name, licence: t.licence, baseline: t.baseline })); }
  function template(id) {
    const t = TEMPLATES[id]; if (!t) throw new HttpError(404, 'there is no template "' + String(id).slice(0, 40) + '"');
    const bg = breakglass(); if (!bg.length) throw new HttpError(409, 'record at least one emergency-access (break-glass) account first - every template excludes them so it cannot lock every administrator out');
    const pol = Object.assign({ displayName: 'AS - ' + t.name + (' (report-only, from ' + ZYB_ORG.short + ')'), state: 'enabledForReportingButNotEnforced' }, t.build(bg.map((a) => a.id)));
    return { id, name: t.name, licence: t.licence, policy: pol, excluded: bg, roles: id === 'admins-mfa' ? ADMIN_ROLES.map(([rid, name]) => ({ id: rid, name })) : undefined,
      import: "Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess','Policy.Read.All'\r\nNew-MgIdentityConditionalAccessPolicy -BodyParameter (Get-Content -Raw '.\\" + id + ".json' | ConvertFrom-Json -AsHashtable)",
      note: 'Created REPORT-ONLY. Read its sign-in report for a week, then switch it on in Entra (Conditional Access) under your change.' };
  }
  function script() { const c = credsOf(deps.config || {}), r = readiness(), s = grantScript(c.clientId, r.missing); if (!s) throw new HttpError(409, r.missing.length ? 'the application (client) ID is not set' : 'no permission is missing'); return { script: s, missing: r.missing }; }
  function setBreakglass(b0, who) {
    const b = body(b0 || {}).list('accounts', { required: true, max: 5 }).done();
    if (!b.accounts.length) throw new HttpError(400, 'accounts: record at least one emergency-access account');
    const accounts = b.accounts.map((x, i) => {
      const r = body(x).str('id', { required: true, max: 36 }).str('label', { required: true, max: 80 }).done();
      if (!GUID.test(r.id)) throw new HttpError(400, 'accounts[' + i + '].id must be the account\'s object ID (a GUID from Entra -> Users)');
      return { id: r.id.toLowerCase(), label: r.label };
    });
    if (new Set(accounts.map((a) => a.id)).size !== accounts.length) throw new HttpError(400, 'accounts: the same object ID is listed twice');
    col.put({ id: 'breakglass', accounts, by: who, at: now() });
    return { accounts };
  }
  function view() {
    const bg = col.get('breakglass');
    return { at: new Date(now()).toISOString(), readiness: readiness(), hardening: hardening(), templates: templateList(), breakglass: bg ? { accounts: bg.accounts, by: bg.by, at: bg.at } : { accounts: [] },
      plan: col.get('plan') || null, ai: AI.status() };
  }

  // ---------- AI configuration plan
  const S = (o) => Object.assign({ type: 'object', additionalProperties: false }, o), STR = (n) => ({ type: 'string', maxLength: n || 2000 });
  const TOOLS = [
    { name: 'readiness', role: 'analyst', description: 'Connection readiness: app details, sign-in, each required Graph application permission granted or not, each dataset read.', input_schema: S({ properties: {} }) },
    { name: 'hardening', role: 'analyst', description: 'Baseline checks (Conditional Access by policy name, administrators without MFA, MFA coverage, Secure Score, stale report-only policies) with pass / fail / warn / not read and the fix.', input_schema: S({ properties: {} }) },
    { name: 'templates', role: 'analyst', description: 'The Conditional Access templates the platform can generate (report-only, break-glass excluded) and whether break-glass accounts are recorded.', input_schema: S({ properties: {} }) },
    { name: 'submit_plan', description: 'Submit the plan.', input_schema: S({ properties: { summary: STR(2000), steps: { type: 'array', maxItems: 15, items: S({ properties: { title: STR(200), why: STR(600), how: STR(900), ref: STR(80) }, required: ['title', 'why', 'how', 'ref'] }) }, cautions: { type: 'array', maxItems: 8, items: STR(400) } }, required: ['summary', 'steps'] }) },
  ];
  const SYSTEM = `You are the Microsoft 365 / Entra ID security configuration assistant for ${ZYB_ORG.name}.
Call readiness, hardening and templates, then submit_plan: a short, ordered plan to (1) finish connecting the read-only collector and (2) close the baseline gaps.
- Base every step on tool results. Each step's ref is a check id (e.g. ca-legacy, mfa-admins), a permission name (e.g. Policy.Read.All) or a template id that a tool returned.
- Nothing here changes the tenant. Steps say what a Microsoft administrator does (open the consent link, run the generated script, import a template report-only, review its report, then switch it on under a change).
- Order: anything that could lock people out comes AFTER the emergency-access (break-glass) accounts are recorded and excluded. Report-only before enforcement. Administrators before all users.
- Say what a step needs (Entra ID P1 / P2 licence) and what is unknown. Never invent policies, users, counts or scores. Reply in the language of the focus text (Arabic or English).`;
  async function plan(focus, w) {
    const st = AI.status(); if (!st.enabled) throw new HttpError(503, st.reason);
    const q = G.redactSecrets(String(focus || '').slice(0, 1000));
    const run = async (name, inp, seen) => {
      if (name === 'readiness') { const r = readiness(); for (const p of r.permissions) seen.add(lc(p.permission)); for (const s of r.steps) seen.add(s.id); return Object.assign({}, r, { tenant: undefined, client_id: undefined }); }
      if (name === 'hardening') { const h = hardening(); for (const c of h.checks) { seen.add(c.id); if (c.fix && c.fix.permission) seen.add(lc(c.fix.permission)); } return h; }
      if (name === 'templates') { const t = templateList(); for (const x of t) seen.add(x.id); return { templates: t, breakglass_recorded: breakglass().length }; }
      throw new Error('unknown tool ' + name);
    };
    const r = await runLoop({ client: AI.client(), model: AI.model(), effort: AI.effort(), system: SYSTEM, tools: TOOLS, role: w.role || 'operator', user: w.user || 'unknown', feature: 'm365.autoconfig.plan', config: deps.config, log: L,
      prompt: 'Write the configuration plan.' + (q ? '\nThe administrator asks to focus on:\n' + G.untrusted('focus', q) : ''), run, final: 'submit_plan', maxSteps: 8 });
    if (!r.result) throw new HttpError(502, 'the AI did not return a plan (' + r.note + ') - try again');
    const steps = (r.result.steps || []).map((s) => Object.assign({}, s, { verified: r.seen.has(String(s.ref).trim()) || r.seen.has(lc(String(s.ref).trim())) }));
    const rec = { id: 'plan', at: now(), by: AI.model(), asked_by: w.user, focus: q, summary: r.result.summary, steps, cautions: r.result.cautions || [], unverified: steps.filter((s) => !s.verified).length, injection_signals: r.flags, usage: r.usage };
    col.put(rec);
    return rec;
  }
  return { view, readiness, hardening, template, templateList, script, setBreakglass, plan, TOOLS };
}

function register(api, deps) {
  const P = prefixOf(deps); if (!deps.m365Graph) return;
  const A = createAutoConfig(deps);
  api.route('GET', `${P}/m365/autoconfig`, wrap(deps, 'analyst', () => A.view()));
  api.route('GET', `${P}/m365/autoconfig/template/:id`, wrap(deps, 'admin', (ctx) => {
    const id = param(String((ctx.params || {}).id || ''), 'id'), t = A.template(id);
    audit(ctx, 'm365.autoconfig.template', id, { excluded: t.excluded.length });
    return t;
  }));
  api.route('GET', `${P}/m365/autoconfig/script`, wrap(deps, 'admin', (ctx) => {
    const s = A.script();
    audit(ctx, 'm365.autoconfig.script', 'microsoft-365', { missing: s.missing });
    return s;
  }));
  api.route('POST', `${P}/m365/autoconfig/breakglass`, wrap(deps, 'admin', (ctx) => {
    const r = A.setBreakglass(ctx.body, ctx.user);
    audit(ctx, 'm365.autoconfig.breakglass', 'microsoft-365', { accounts: r.accounts.length, labels: r.accounts.map((a) => a.label) });
    return r;
  }));
  api.route('POST', `${P}/m365/autoconfig/plan`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body || {}).str('focus', { max: 1000 }).done();
    const r = await A.plan(b.focus, { user: ctx.user, role: String(ctx.role || '').toLowerCase() });
    audit(ctx, 'm365.autoconfig.plan', 'microsoft-365', { steps: r.steps.length, unverified: r.unverified, injection_signals: r.injection_signals.length });
    return r;
  }));
}

module.exports = { register, createAutoConfig, required, grantScript, TEMPLATES, ADMIN_ROLES };
