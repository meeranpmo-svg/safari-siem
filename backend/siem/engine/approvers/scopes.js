// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Who may approve what an AI engineer proposes. The SAME file is in the SIEM (engine/approvers/scopes.js) and in IT Asset
 * Management (engine/approve-scopes.js); a test fails if the two copies differ.
 *
 * Every change an AI engineer proposes is decided by a PERSON: an administrator, or a named human engineer whose job role
 * (Roles & Functions) carries the scope. A group scope (infra / security) covers every AI engineer in it; an engineer
 * scope (eng:<id>) covers that one AI engineer only - so the DBA team approves the AI Oracle DBA, the network team the AI
 * Network Engineer, and so on. Service and AI identities (system:…, duty:…, core:…, ai:…, svc:…) never approve, whatever
 * their role. Four-eyes (never your own request) stays in each approval.
 */
const GROUPS = {
  infra: 'Infrastructure: every infrastructure AI engineer (virtualization, network, Windows / Exchange, desktop patching)',
  security: 'Security: every security AI engineer (firewalls, SOC response, Kaspersky, Zscaler, forensics, pen-testing)',
  risk: 'Business risk: risk acceptances and risk-appetite limit changes (Business Risk register, Risk Appetite)',
};
// eng:<id> → [group, the AI engineer whose proposals it covers, what is approved]
const ENGINEERS = {
  'eng:virt': ['infra', 'AI Virtualization Administrator', 'vCenter / Nutanix change plans'],
  'eng:network': ['infra', 'AI Network Engineer', 'switch, router, wireless and SD-WAN change plans and tasks'],
  'eng:windows': ['infra', 'AI Windows Server Administrator', 'Windows Server change plans'],
  'eng:exchange': ['infra', 'AI Exchange Server Administrator', 'Exchange change plans'],
  'eng:desktop': ['infra', 'AI Desktop Support Engineer', 'patch installs and Endpoint Central actions'],
  'eng:security': ['security', 'AI Security Engineer (firewalls)', 'Palo Alto / FortiGate / ASA change plans and tasks'],
  'eng:soc': ['security', 'SOC response', 'SOC response actions (isolate, block, disable)'],
  'eng:ksc': ['security', 'AI Endpoint Protection Engineer (Kaspersky)', 'Kaspersky Security Center change plans'],
  'eng:zscaler': ['security', 'AI Security Engineer — Zscaler', 'Zscaler ZIA / ZPA change plans'],
  'eng:dfir': ['security', 'DFIR', 'forensic collections'],
  'eng:pentest': ['security', 'AI Penetration Testing Engineer', 'pen-test engagements'],
  'eng:dba': ['infra', 'AI Oracle DBA', 'Oracle tuning recommendations (a named DBA runs them; the platform only reads)'],
};
const SCOPES = Object.assign({}, GROUPS);
for (const [k, v] of Object.entries(ENGINEERS)) SCOPES[k] = `${v[1]}: ${v[2]}`;

// a person, not a service or an AI engineer acting on its own
// a service, job or AI identity - never a person who may approve: a known prefix followed by a separator or nothing at all
// (a bare 'system'), and the engines' own command-line identities (sentra-siem-ad@host, sentra-siem-validate, sentra-itam-…)
const MACHINE = /^(?:(?:system|duty|core|ai|svc|service|agent|bot)(?:[:._@-]|$)|sentra-(?:siem|itam)(?:[:._@-]|$))/i;
function isHuman(user) { const u = String(user || '').trim(); return !!u && !MACHINE.test(u); }

// the scopes that cover an approval asked for with `scope` (an engineer scope is also covered by its group)
function covering(scope) { const e = ENGINEERS[scope]; return e ? [scope, e[0]] : [scope]; }
// may a user holding `held` (list of scopes) approve something that needs ANY of `needed`?
function allows(held, needed) {
  const h = new Set((held || []).map(String));
  return [].concat(needed || []).some((n) => covering(n).some((c) => h.has(c)));
}
function label(scope) { const e = ENGINEERS[scope]; return e ? e[1] : (GROUPS[scope] || scope).split(':')[0]; }

module.exports = { GROUPS, ENGINEERS, SCOPES, isHuman, covering, allows, label };
