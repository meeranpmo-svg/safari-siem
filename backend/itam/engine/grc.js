// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * GRC — IT policy & procedure register + control automation. The 42 policies approved by the organisation GRC
 * (engine/grc-policies.json, extracted from the signed .docx set) become live data: each policy is mapped to the
 * platform control that already enforces or monitors it, its review lifecycle is tracked (next review, overdue), and
 * owners record periodic attestations. Nothing here is invented — the register is the approved text, and a control is
 * "automated" only where the platform actually holds the signal; otherwise it is "monitored" (a module covers it) or
 * "manual" (owner attestation). This is the engine behind IT-PPM-001 (IT Policy & Procedures Management Policy) itself.
 *
 *   createGrc(app) → { register(), policy(id), summary(), controlStatus(), attest(id,input,who), reviewAck(id,input,who),
 *                      frameworksOf(s), reviewState(p), CONTROL_MAP }
 */
const REGISTER = require('./grc-policy-file')();

// per sub-code: cls = automated (platform has a pass/fail signal) | monitored (a module covers it) | manual (attestation).
// check = which live signal; source = which service holds it (itam computed here; soc/netops filled by the portal).
const CONTROL_MAP = {
  '3.1.1': { cls: 'manual', module: 'IT Governance', page: 'head-of-it.html' },
  '3.1.2': { cls: 'manual', module: 'IT Strategy', page: 'head-of-it.html' },
  '3.1.3': { cls: 'monitored', module: 'Enterprise Architecture / CMDB', page: 'reconcile.html', check: 'cmdb', source: 'itam' },
  '3.1.4': { cls: 'automated', module: 'GRC Policy Register (this module)', page: 'grc-policies.html', check: 'register', source: 'itam' },
  '3.1.5': { cls: 'automated', module: 'RBAC — roles & responsibilities', page: 'roles.html', check: 'roles', source: 'itam' },
  '3.1.6': { cls: 'monitored', module: 'Regulatory compliance (SAMA/NCA/ISO crosswalk)', page: 'it-audit.html', check: 'compliance', source: 'soc' },
  '3.1.7': { cls: 'monitored', module: 'Internal IT audit log', page: 'audit-log.html', check: 'audit', source: 'soc' },
  '3.1.8': { cls: 'manual', module: 'Staff competence & training', page: 'head-of-it.html' },
  '3.1.9': { cls: 'monitored', module: 'IT performance / KPIs', page: 'head-of-it.html' },
  '3.2.1': { cls: 'monitored', module: 'IT risk register', page: 'it-audit.html', check: 'risk', source: 'soc' },
  '3.2.2': { cls: 'monitored', module: 'IT risk register', page: 'it-audit.html', check: 'risk', source: 'soc' },
  '3.2.3': { cls: 'monitored', module: 'IT risk register', page: 'it-audit.html', check: 'risk', source: 'soc' },
  '3.2.4': { cls: 'monitored', module: 'IT risk register', page: 'it-audit.html', check: 'risk', source: 'soc' },
  '3.3.1': { cls: 'automated', module: 'IT Asset Management', page: 'manageengine.html', check: 'assets', source: 'itam' },
  '3.3.2': { cls: 'monitored', module: 'CMDB interdependencies', page: 'reconcile.html', check: 'cmdb', source: 'itam' },
  '3.3.3': { cls: 'monitored', module: 'SLA / support contracts', page: 'support-contracts.html', check: 'sla', source: 'itam' },
  '3.3.4': { cls: 'automated', module: 'Availability & capacity', page: 'capacity.html', check: 'availability', source: 'soc' },
  '3.3.5': { cls: 'manual', module: 'Data centre management', page: 'head-of-it.html' },
  '3.3.6': { cls: 'automated', module: 'Network architecture & monitoring (NOC)', page: 'noc-overview.html', check: 'network', source: 'soc' },
  '3.3.7': { cls: 'manual', module: 'Batch processing', page: 'head-of-it.html' },
  '3.3.8': { cls: 'automated', module: 'IT incident management (SOC / DFIR)', page: 'dfir.html', check: 'incidents', source: 'soc' },
  '3.3.9': { cls: 'monitored', module: 'Problem management (DFIR)', page: 'dfir.html', check: 'incidents', source: 'soc' },
  '3.3.10': { cls: 'automated', module: 'Backup & recoverability', page: 'backup.html', check: 'backup', source: 'itam' },
  '3.3.11': { cls: 'automated', module: 'Virtualization', page: 'virtualization.html', check: 'virt', source: 'itam' },
  '3.4.1': { cls: 'monitored', module: 'System change governance', page: 'network-engineer.html', check: 'change', source: 'soc' },
  '3.4.2': { cls: 'automated', module: 'Change approval workflow (four-eyes)', page: 'network-engineer.html', check: 'change', source: 'soc' },
  '3.4.3': { cls: 'manual', module: 'System acquisition', page: 'support-contracts.html' },
  '3.4.4': { cls: 'manual', module: 'System development' },
  '3.4.5': { cls: 'monitored', module: 'System testing / QA', page: 'pentest.html' },
  '3.4.6': { cls: 'monitored', module: 'Change security requirements (VAPT)', page: 'pentest.html', check: 'vapt', source: 'soc' },
  '3.4.7': { cls: 'monitored', module: 'Change release management', page: 'network-engineer.html', check: 'change', source: 'soc' },
  '3.4.8': { cls: 'monitored', module: 'System configuration management', page: 'network-engineer.html', check: 'change', source: 'soc' },
  '3.4.9': { cls: 'automated', module: 'Patch management (Endpoint Central)', page: 'desk-support.html', check: 'patch', source: 'itam' },
  '3.4.10': { cls: 'manual', module: 'IT project management' },
  '3.4.11': { cls: 'monitored', module: 'Quality assurance', page: 'pentest.html' },
};
const MONTHS = { january: 0, february: 1, march: 2, april: 3, may: 4, june: 5, july: 6, august: 7, september: 8, october: 9, november: 10, december: 11 };
const FW_PATTERNS = [[/sama/i, 'SAMA'], [/insurance authority|\bIA\b[- ]?framework|insurance (regulat|supervis)|\bIA\b cyber/i, 'Insurance Authority'], [/iso\/?iec ?27001|iso ?27001/i, 'ISO 27001'], [/\bnca\b|ecc|ncnicc/i, 'NCA'], [/\bndmo\b|national data management|data management office/i, 'NDMO'], [/pdpl|personal data/i, 'PDPL'], [/\bbcm\b|business continuity/i, 'BCM'], [/\bnist\b/i, 'NIST'], [/aramco|sacs/i, 'Aramco SACS-002']];

// Insurance Authority (KSA) — indicative regulatory domains the IT GRC programme supports. This is a WORKING crosswalk
// of the IT policy register and platform controls to the IA's supervisory areas (governance, risk, outsourcing, BCM,
// cyber, IT ops, change, data). It is NOT the IA's verbatim article catalogue — Compliance must confirm against the
// current Insurance Authority regulations. Each domain lists the policy sub-codes that evidence it and whether the IT
// register is expected to own it (req). partial = a control exists operationally but a dedicated policy is missing.
const IA_DOMAINS = [
  { key: 'cg', name: 'Corporate & IT governance', req: true, policies: ['3.1.1', '3.1.2', '3.1.3', '3.1.5', '3.1.9'], control: 'GRC register + RBAC' },
  { key: 'rm', name: 'Risk management', req: true, policies: ['3.2.1', '3.2.2', '3.2.3', '3.2.4'], control: 'IT risk register' },
  { key: 'audit', name: 'Internal controls & audit', req: true, policies: ['3.1.7'], control: 'Audit log / IT audit' },
  { key: 'comp', name: 'Regulatory compliance', req: true, policies: ['3.1.6', '3.1.4'], control: 'SAMA/IA crosswalk' },
  { key: 'itops', name: 'IT operations & service management', req: true, policies: ['3.3.1', '3.3.2', '3.3.3', '3.3.4', '3.3.5', '3.3.6', '3.3.7', '3.3.8', '3.3.9', '3.3.11'], control: 'NOC / ITAM / DFIR' },
  { key: 'change', name: 'System change & development', req: true, policies: ['3.4.1', '3.4.2', '3.4.3', '3.4.4', '3.4.5', '3.4.6', '3.4.7', '3.4.8', '3.4.9', '3.4.10', '3.4.11'], control: 'Change approval / VAPT' },
  { key: 'bcm', name: 'Business continuity & recoverability', req: true, policies: ['3.3.10'], control: 'Backup / Proxmox', partial: true, note: 'BCM is cited across the policies but there is no dedicated Business Continuity / DR policy — treat as partial.' },
  { key: 'cyber', name: 'Cyber & information security', req: true, policies: ['3.3.6', '3.4.6', '3.4.9'], control: 'SOC / SIEM / VAPT', partial: true, note: 'Covered operationally by the SOC, but no overarching Information / Cyber Security policy exists — add one (SAMA CSF / IA).' },
  { key: 'outsourcing', name: 'Outsourcing & third-party risk', req: true, policies: [], control: 'Vendor / support contracts', note: 'No outsourcing / third-party risk policy — gap. SAMA Outsourcing & the IA expect one.' },
  { key: 'data', name: 'Data management & protection (PDPL / NDMO)', req: true, policies: [], control: 'DLP / Log Archive / data residency', note: 'No data-protection or data-governance policy — gap (PDPL + NDMO).' },
  { key: 'aml', name: 'AML / anti-fraud', req: false, policies: [], control: '—', note: 'Business / compliance function — outside the IT policy register (N/A for IT GRC).' },
  { key: 'consumer', name: 'Consumer protection & market conduct', req: false, policies: [], control: '—', note: 'Business function — outside IT GRC.' },
];

function frameworksOf(s) { const out = []; for (const [re, name] of FW_PATTERNS) if (re.test(String(s || '')) && !out.includes(name)) out.push(name); return out; }

// "November 2026" / "1 November 2026" → epoch ms at end of that month (conservative — due at month end)
function parseReviewDate(s) {
  const t = String(s || '').toLowerCase().trim(); if (!t) return null;
  const m = /([a-z]+)\s+(\d{4})/.exec(t); if (m && MONTHS[m[1]] != null) return Date.UTC(+m[2], MONTHS[m[1]] + 1, 0);
  const d = Date.parse(s); return isNaN(d) ? null : d;
}

// Starter drafts for the policies the register is missing (the PDPL / NDMO / IA gap analysis), created on demand.
const GAP_DRAFTS = [
  { title: 'Personal Data Protection Policy', domain: 'Data Protection', frameworks: 'PDPL, NDMO, Insurance Authority', control: 'DLP / Log Archive', purpose: ('Establish how ' + ZYB_ORG.short + ' processes personal data lawfully under the Saudi PDPL — principles, lawful basis, data subject rights and accountability.') },
  { title: 'Data Classification & Handling Policy', domain: 'Data Protection', frameworks: 'PDPL, NDMO, ISO 27001', control: 'DLP / M365 labels', purpose: 'Define classification levels (Public / Internal / Confidential / Restricted) and the handling, labelling and storage rules for each.' },
  { title: 'Data Breach Notification Policy', domain: 'Data Protection', frameworks: 'PDPL', control: 'SOC / DFIR', purpose: 'Define breach assessment and the notification duty to SDAIA and affected data subjects within the regulatory timeline — distinct from IT incident management.' },
  { title: 'Data Retention & Disposal Policy', domain: 'Data Protection', frameworks: 'PDPL, NDMO', control: 'Log Archive / Backup', purpose: 'Retention schedules per data category and secure disposal of personal and business data.' },
  { title: 'Cross-Border Data Transfer & Residency Policy', domain: 'Data Protection', frameworks: 'PDPL', control: 'Hub residency check', purpose: 'Govern transfer of personal data outside KSA and evidence of data residency.' },
  { title: 'Data Governance Policy', domain: 'Data Management', frameworks: 'NDMO', control: 'RBAC / GRC', purpose: 'Data governance office, data owners/stewards, and the NDMO data-management domains.' },
  { title: 'Information & Cyber Security Policy', domain: 'Cyber Security', frameworks: 'SAMA, Insurance Authority, ISO 27001', control: 'SOC / SIEM', purpose: 'The overarching ISMS policy required by the SAMA CSF / Insurance Authority — the umbrella for all security controls.' },
  { title: 'Access Control & Identity Management Policy', domain: 'Cyber Security', frameworks: 'ISO 27001, Insurance Authority', control: 'RBAC / IAM', purpose: 'Least privilege, joiners/movers/leavers, privileged access and periodic access reviews.' },
  { title: 'Cryptography & Key Management Policy', domain: 'Cyber Security', frameworks: 'ISO 27001', control: 'Encryption', purpose: 'Approved cryptography, encryption in transit/at rest and key lifecycle management.' },
  { title: 'Business Continuity & Disaster Recovery Policy', domain: 'Resilience', frameworks: 'BCM, Insurance Authority', control: 'Backup / Proxmox', purpose: 'BIA, RTO/RPO, continuity and DR arrangements — the dedicated BCM/DR policy the register is missing.' },
  { title: 'Outsourcing & Third-Party Risk Management Policy', domain: 'Third Party', frameworks: 'SAMA, Insurance Authority', control: 'Vendor / contracts', purpose: 'Due diligence, contracts, monitoring and exit for outsourced and third-party services (SAMA Outsourcing rules).' },
  { title: 'Cloud Computing Policy', domain: 'Third Party', frameworks: 'SAMA', control: 'Asset / CMDB', purpose: 'Cloud adoption, data residency/tiering and shared-responsibility per the SAMA cloud rules.' },
  { title: 'Acceptable Use Policy', domain: 'Cyber Security', frameworks: 'ISO 27001', control: 'Endpoint / M365', purpose: 'Acceptable use of IT systems, email, internet and corporate data by staff.' },
  { title: 'Vulnerability & Threat Management Policy', domain: 'Cyber Security', frameworks: 'SAMA, ISO 27001', control: 'VAPT / Detection', purpose: 'Vulnerability scanning, prioritisation, patch SLAs and threat management.' },
  { title: 'Human Resources Security Policy', domain: 'Cyber Security', frameworks: 'ISO 27001', control: 'RBAC / HR', purpose: 'Screening, onboarding/offboarding, security awareness and disciplinary process.' },
  { title: 'Physical & Environmental Security Policy', domain: 'Cyber Security', frameworks: 'ISO 27001', control: 'Facilities', purpose: 'Secure areas, equipment protection and environmental controls for data centres and offices.' },
];

// four-eyes: names compared trimmed and case-insensitive (one sign-in method may send "Alice", another "alice"); requests the
// platform raised itself (duty:<engineer>, system:<job>) have no human requester
const normUser = (u) => String(u == null ? '' : u).trim().toLowerCase();
const sameUser = (a, b) => !!normUser(a) && normUser(a) === normUser(b);
const isSystem = (u) => /^(duty|system):/i.test(String(u || '').trim());
// an approved draft / signed-off drill that is changed afterwards loses its approval: what was approved is no longer what is there
function reopenDraft(rec, who, why) { if (rec.status === 'approved' || rec.status === 'in-review') { rec.history = (rec.history || []).concat([{ at: Date.now(), by: (who && who.user) || '', what: 'back to draft - ' + why + ' after ' + rec.status + (rec.approved_by ? ' (was approved by ' + rec.approved_by + ')' : '') }]); rec.status = 'draft'; rec.approved_by = null; rec.approved_at = null; } }
function reopenDrill(rec, who, why) { if (rec.signoff && rec.signoff.by) { rec.history = (rec.history || []).concat([{ at: Date.now(), by: (who && who.user) || '', what: 'sign-off by ' + rec.signoff.by + ' withdrawn - ' + why + ' after sign-off' }]); rec.signoff = null; } }
function bumpVersion(v) { const m = /^(\d+)\.(\d+)$/.exec(String(v || '0.1')); if (!m) return '0.2'; return m[1] + '.' + (Number(m[2]) + 1); }

// ---- SAMA Cyber Security Framework view of the register. The policies are numbered by the SAMA IT Governance Framework
// (3.1.1 IT governance, 3.4.9 patch management...), not by the CSF, so each is mapped by its subject to the CSF controls
// it supports (an analyst mapping, to be confirmed by GRC). A policy with no CSF control (batch processing) maps to [].
const POLICY_CSF = {
  'IT-GOV-001': ['3.1.1'], 'IT-STR-001': ['3.1.2'], 'IT-EA-001': ['3.3.4'], 'IT-PPM-001': ['3.1.3'], 'IT-RR-001': ['3.1.4'],
  'IT-RC-001': ['3.2.2', '3.2.3'], 'IT-IA-001': ['3.2.4', '3.2.5'], 'IT-SCT-001': ['3.1.6', '3.1.7', '3.3.1'], 'IT-PM-001': ['3.1.1'],
  'IT-RISK-001': ['3.2.1'], 'IT-RISK-002': ['3.2.1'], 'IT-RISK-003': ['3.2.1'],
  'IT-OPS-001': ['3.3.3'], 'IT-OPS-002': ['3.3.4'], 'IT-OPS-003': ['3.4.1'], 'IT-OPS-004': ['3.3.8', 'BCM'], 'IT-OPS-005': ['3.3.2'],
  'IT-OPS-006': ['3.3.8', '3.3.14'], 'IT-OPS-006-F1': ['3.3.14'], 'IT-OPS-006-F2': ['3.3.8', '3.3.5'], 'IT-OPS-006-F3': ['3.3.4', '3.3.8'],
  'IT-OPS-006-F4': ['3.3.14'], 'IT-OPS-006-F5': ['3.3.15'], 'IT-OPS-006-F6': ['3.3.8', 'BCM'], 'IT-OPS-006-F7': ['3.3.7'],
  'IT-OPS-007': [], 'IT-OPS-008': ['3.3.15'], 'IT-OPS-009': ['3.3.15'], 'IT-OPS-010': ['BCM', '3.3.8'], 'IT-OPS-011': ['3.3.8'],
  'IT-DEV-001': ['3.3.7'], 'IT-DEV-002': ['3.3.7'], 'IT-DEV-003': ['3.3.6', '3.4.1'], 'IT-DEV-004': ['3.3.6'], 'IT-DEV-005': ['3.3.6'],
  'IT-DEV-006': ['3.3.6', '3.3.7'], 'IT-DEV-007': ['3.3.7'], 'IT-DEV-008': ['3.3.8', '3.3.7'], 'IT-DEV-009': ['3.3.17', '3.3.8'],
  'IT-DEV-010': ['3.1.5'], 'IT-DEV-011': ['3.3.6'],
};
// words that show a requirement line is about the control (word-bounded at the start: "log" must not match "technology")
const CSF_KW = {
  '3.1.1': 'governance|steering|committee|board', '3.1.2': 'strateg', '3.1.3': 'polic(?:y|ies)|procedure', '3.1.4': 'roles?\\b|responsib|raci',
  '3.1.5': 'project', '3.1.6': 'awareness', '3.1.7': 'training|competen|skill', '3.2.1': 'risk', '3.2.2': 'regulat|compliance|sama\\b',
  '3.2.3': 'standard|iso\\b|cobit|nist\\b', '3.2.4': 'review', '3.2.5': 'audit', '3.3.1': 'staff|employee|human resource|onboard|terminat',
  '3.3.2': 'physical|data cent|facilit|premises', '3.3.3': 'asset|inventor|cmdb', '3.3.4': 'architect|segment|design',
  '3.3.5': 'access|account|privileg|password|authenticat|mfa\\b|identit', '3.3.6': 'application|develop|cod(?:e|ing)\\b|test|software',
  '3.3.7': 'change|release', '3.3.8': 'infrastructure|server|network|firewall|configur|harden|baseline|virtuali|patch',
  '3.3.9': 'encrypt|crypt|key management|certificate', '3.3.10': 'byod|mobile device|personal device', '3.3.11': 'dispos|destr|saniti|wip(?:e|ing)\\b',
  '3.3.12': 'payment', '3.3.13': 'electronic|portal|online|mobile app', '3.3.14': 'logs?\\b|logging|monitor|event|siem\\b|alert',
  '3.3.15': 'incident', '3.3.16': 'threat|intelligence', '3.3.17': 'vulnerab|patch|scan|penetration', '3.4.1': 'vendor|contract|supplier|third.party|sla\\b',
  '3.4.2': 'outsourc', '3.4.3': 'cloud', BCM: 'continuity|recover|backup|disaster|resilien|availab',
};
// ITAM's own live signals (controlStatus) and the CSF controls they evidence; pillar = devices | apps
const SIGNAL_CSF = { assets: { csf: ['3.3.3'], pillar: 'devices', name: 'Asset register (ITAM)' }, patch: { csf: ['3.3.17', '3.3.8'], pillar: 'devices', name: 'Critical patches (Endpoint Central)' },
  backup: { csf: ['BCM', '3.3.8'], pillar: 'devices', name: 'Backups (backup platforms)' }, virt: { csf: ['3.3.8'], pillar: 'devices', name: 'Virtualization platforms reporting' },
  roles: { csf: ['3.1.4', '3.3.5'], pillar: 'apps', name: 'Roles assigned (Roles & Functions)' }, register: { csf: ['3.1.3'], pillar: 'apps', name: 'Policy register reviews current' } };

function createGrc(app) {
  const store = app.store;
  const attCol = store.collection('grc_attestations'), revCol = store.collection('grc_reviews'), draftCol = store.collection('grc_drafts'), counters = store.collection('counters');
  const now = () => (app.now ? app.now() : Date.now());
  function nextId(prefix, name) { const cur = (counters.get(name) || {}).n || 0; const n = cur + 1; counters.put({ id: name, n }); return prefix + '-' + String(n).padStart(4, '0'); }

  function reviewState(p) {
    const due = parseReviewDate(p.next_review);
    const ack = revCol.all((r) => r.policy_id === p.doc_id && r.version === p.version).sort((a, b) => b.at - a.at)[0] || null;
    if (!due) return { next_review: p.next_review || '', due_ms: null, days: null, overdue: false, soon: false, acknowledged: !!ack, ack };
    const days = Math.round((due - now()) / 86400000);
    return { next_review: p.next_review || '', due_ms: due, days, overdue: days < 0, soon: days >= 0 && days <= 90, acknowledged: !!ack, ack };
  }

  function enrich(p) {
    const cm = CONTROL_MAP[p.sub_code] || { cls: 'manual', module: p.sub || p.domain };
    const atts = attCol.all((a) => a.policy_id === p.doc_id).sort((a, b) => b.at - a.at);
    return Object.assign({}, p, { control: cm, frameworks_list: frameworksOf(p.frameworks), review: reviewState(p),
      attestation: atts[0] || null, attestations: atts.length });
  }

  function register(filter = {}) {
    let items = REGISTER.map(enrich);
    if (filter.domain) items = items.filter((p) => p.domain_code === filter.domain);
    if (filter.cls) items = items.filter((p) => p.control.cls === filter.cls);
    if (filter.framework) items = items.filter((p) => p.frameworks_list.includes(filter.framework));
    if (filter.q) { const q = String(filter.q).toLowerCase(); items = items.filter((p) => (p.title + ' ' + p.doc_id + ' ' + p.purpose).toLowerCase().includes(q)); }
    return { items, total: items.length };
  }
  function policy(id) { const p = REGISTER.find((x) => x.doc_id === id); return p ? enrich(p) : null; }

  // server-side live checks for the controls whose signal ITAM holds locally. Honest: a missing feed → 'unknown'.
  function controlStatus() {
    const out = {};
    const pass = (state, metric, detail) => ({ state, metric, detail });
    try { const a = store.collection('assets').all((x) => x.status !== 'disposed'); const disc = store.collection('disc_devices').all((d) => !d.adopted_asset_id); const reg = a.length;
      out.assets = pass(reg ? (disc.length ? 'partial' : 'pass') : 'unknown', reg + ' registered', disc.length ? (disc.length + ' discovered, not yet registered') : (reg ? 'all discovered devices registered' : 'no assets registered yet')); } catch (e) { out.assets = pass('unknown', '', ''); }
    try { const ec = store.collection('me_ec_computers').all(); const vuln = ec.filter((c) => Number(c.critical) > 0).length; const total = ec.length;
      out.patch = total ? pass(vuln ? (vuln > total * 0.1 ? 'fail' : 'partial') : 'pass', (total - vuln) + '/' + total + ' healthy', vuln ? (vuln + ' host(s) missing critical patches') : 'no host is missing a critical patch') : pass('unknown', '', 'Endpoint Central not connected'); } catch (e) { out.patch = pass('unknown', '', ''); }
    try { const plat = store.collection('backup_platforms').all(); const objs = store.collection('backup_objects').all(); const okd = objs.filter((o) => o.ok === true || /ok|success/i.test(String(o.status || o.last_status || ''))).length;
      out.backup = plat.length ? pass(objs.length ? (okd === objs.length ? 'pass' : okd ? 'partial' : 'fail') : 'unknown', okd + '/' + objs.length + ' protected', objs.length ? (objs.length - okd) + ' guest(s) without a recent successful backup' : 'no backup objects reported') : pass('unknown', '', 'no backup platform connected'); } catch (e) { out.backup = pass('unknown', '', ''); }
    try { const vp = store.collection('virt_platforms').all(); const err = vp.filter((v) => v.error || v.status === 'error').length;
      out.virt = vp.length ? pass(err ? 'partial' : 'pass', vp.length + ' platform(s)', err ? (err + ' platform(s) not reporting') : 'all virtualization platforms reporting') : pass('unknown', '', 'no virtualization platform connected'); } catch (e) { out.virt = pass('unknown', '', ''); }
    // the Roles & Functions module keeps its roles in job_roles (an older build used "roles"): reading the wrong one said
    // "0 role(s) - no roles defined" next to eleven built-in roles. Roles nobody holds are not yet a role matrix.
    try { let roles = store.collection('job_roles').all(); if (!roles.length) roles = store.collection('roles').all(); const held = store.collection('role_assignments').all().filter((x) => roles.some((r) => r.id === x.role_id)).length;
      out.roles = roles.length ? pass(held ? 'pass' : 'partial', roles.length + ' role(s)', held ? held + ' people hold a role' : 'roles defined, nobody assigned yet (Roles & Functions)') : pass('unknown', '', 'no roles defined'); } catch (e) { out.roles = pass('unknown', '', ''); }
    // the register itself (IT-PPM-001): are approved policies on-register and reviews current?
    const reg = REGISTER.map(enrich); const overdue = reg.filter((p) => p.review.overdue).length;
    out.register = pass(overdue ? 'partial' : 'pass', REGISTER.length + ' policies', overdue ? (overdue + ' past their review date') : 'all policies within their review cycle');
    return out;
  }

  /* per SAMA CSF control: the policies that support it, each cross-checked on four points (approved record, review in date,
     owner attestation, requirement text that addresses the control) with a remark per point, plus ITAM's live signals. A point
     the register cannot show scores 0 and says why; nothing is assumed followed. */
  function csfCoverage() {
    const sig = controlStatus(), YEAR = 365 * 86400000, out = {}, unmapped = [];
    const kw = {}; for (const [c, re] of Object.entries(CSF_KW)) kw[c] = new RegExp('\\b(?:' + re + ')', 'i');
    const ctl = (c) => (out[c] = out[c] || { code: c, policies: [], signals: [] });
    for (const p of REGISTER.map(enrich)) {
      const csf = POLICY_CSF[p.doc_id]; if (!csf || !csf.length) { unmapped.push({ doc_id: p.doc_id, title: p.title, reason: csf ? 'IT operations policy with no SAMA CSF control' : 'not mapped yet' }); continue; }
      const reqs = (p.requirements || []).filter((l) => l && l.length > 12 && !/^\d+(\.\d+)*\s/.test(l));   // statements, not headings
      for (const c of csf) {
        const items = [], approved = /approved/i.test(p.status || '');
        items.push({ k: 'approved', label: 'Approved policy record', max: 25, pts: approved ? 25 : 0,
          remark: approved ? `${p.status}${p.approver ? ' by ' + p.approver : ''}${p.effective ? ', effective ' + p.effective : ''}.` : `Register status "${p.status || 'none'}" — a procedure flow or an unapproved record, not an approved policy.` });
        const rv = p.review;
        items.push({ k: 'review', label: 'Review in date', max: 25, pts: rv.due_ms && !rv.overdue ? 25 : 0,
          remark: !rv.due_ms ? 'No next review date in the register.' : rv.overdue ? `Review overdue by ${-rv.days} days (due ${rv.next_review}).` : `Next review ${rv.next_review} (${rv.days} days)${rv.acknowledged ? ', current version acknowledged' : ''}.` });
        const att = p.attestation, fresh = att && now() - att.at <= YEAR;
        items.push({ k: 'attested', label: 'Owner attestation (12 months)', max: 25, pts: fresh ? (att.decision === 'exception' ? 10 : 25) : 0,
          remark: !att ? `No attestation recorded: ${p.owner || 'the owner'} has not confirmed the policy is followed.` : !fresh ? `Last attestation ${new Date(att.at).toISOString().slice(0, 10)} by ${att.by} is older than 12 months.`
            : att.decision === 'exception' ? `Exception recorded by ${att.by} on ${new Date(att.at).toISOString().slice(0, 10)}: ${att.note}` : `Confirmed followed by ${att.by} on ${new Date(att.at).toISOString().slice(0, 10)}: ${att.note}` });
        const lines = reqs.filter((l) => kw[c] && kw[c].test(l)).slice(0, 6);
        items.push({ k: 'text', label: 'Requirements address the control', max: 25, pts: !reqs.length ? 0 : lines.length ? 25 : 10,
          remark: !reqs.length ? 'The requirement text was not extracted from the policy document, so it cannot be cross-checked — re-import the .docx.'
            : lines.length ? `${lines.length} requirement statement(s) in the policy address this control.` : 'The policy text does not address this control explicitly — the mapping rests on the policy’s subject only.' });
        const score = items.reduce((a, x) => a + x.pts, 0);
        ctl(c).policies.push({ doc_id: p.doc_id, sub_code: p.sub_code, title: p.title, owner: p.owner || '', status: p.status || '', score, items, lines,
          enforcement: p.control ? { cls: p.control.cls, module: p.control.module, page: p.control.page || '' } : null });
      }
    }
    for (const [k, m] of Object.entries(SIGNAL_CSF)) { const v = sig[k]; if (!v) continue; for (const c of m.csf) ctl(c).signals.push({ key: k, name: m.name, pillar: m.pillar, state: v.state, metric: v.metric, detail: v.detail }); }
    for (const c of Object.values(out)) {
      c.policy_pct = c.policies.length ? Math.round(c.policies.reduce((a, x) => a + x.score, 0) / c.policies.length) : null;
      c.remark = !c.policies.length ? 'No IT policy in the register supports this control — a policy gap.' : c.policies.length + ' polic' + (c.policies.length === 1 ? 'y' : 'ies') + ', average ' + c.policy_pct + '% followed by the register’s evidence.';
    }
    return { generated_at: new Date(now()).toISOString(), mapping: 'Policy to SAMA CSF mapping by subject (analyst draft, confirm with GRC). Scoring: approved record, review in date, owner attestation within 12 months, requirement text addressing the control - 25 points each.',
      policies_total: REGISTER.length, controls: out, unmapped };
  }

  function summary() {
    const reg = REGISTER.map(enrich);
    const byCls = { automated: 0, monitored: 0, manual: 0 }, byDomain = {}, fw = {};
    let overdue = 0, soon = 0, attested = 0;
    for (const p of reg) {
      byCls[p.control.cls] = (byCls[p.control.cls] || 0) + 1;
      const d = p.domain_code; byDomain[d] = byDomain[d] || { domain: p.domain, code: d, total: 0, automated: 0, overdue: 0 };
      byDomain[d].total++; if (p.control.cls === 'automated') byDomain[d].automated++;
      if (p.review.overdue) { overdue++; byDomain[d].overdue++; } if (p.review.soon) soon++;
      if (p.attestation) attested++;
      for (const f of p.frameworks_list) fw[f] = (fw[f] || 0) + 1;
    }
    return { total: reg.length, by_cls: byCls, by_domain: Object.values(byDomain).sort((a, b) => a.code.localeCompare(b.code)),
      reviews: { overdue, soon }, attested, frameworks: Object.keys(fw).map((k) => ({ framework: k, policies: fw[k] })).sort((a, b) => b.policies - a.policies),
      control_status: controlStatus(), generated: now() };
  }

  function attest(id, input, who) {
    const p = REGISTER.find((x) => x.doc_id === id); if (!p) throw httpErr(404, 'policy not found');
    const note = String((input && input.note) || '').slice(0, 2000); if (!note) throw httpErr(400, 'an attestation note is required (what was reviewed / confirmed)');
    const rec = { id: 'ATT-' + id + '-' + now(), policy_id: id, title: p.title, by: (who && who.user) || '', at: now(),
      period: String((input && input.period) || '').slice(0, 40), decision: (input && input.decision === 'exception') ? 'exception' : 'compliant', note };
    attCol.put(rec); return rec;
  }
  function reviewAck(id, input, who) {
    const p = REGISTER.find((x) => x.doc_id === id); if (!p) throw httpErr(404, 'policy not found');
    const rec = { id: 'REV-' + id + '-' + p.version + '-' + now(), policy_id: id, version: p.version, by: (who && who.user) || '', at: now(),
      note: String((input && input.note) || '').slice(0, 2000), next_review: p.next_review };
    revCol.put(rec); return rec;
  }

  // ---- Policy drafting: create / edit / version / upload new or replacement policy documents, kept separate from the
  // signed register (the approved .docx set is never mutated). A draft is approved through its own status workflow.
  function draftStrip(d) { if (!d) return d; const c = Object.assign({}, d); if (c.document) { c.document = Object.assign({}, c.document); delete c.document.content_b64; } return c; }
  function draftList(filter = {}) { let items = draftCol.all(); if (filter.status) items = items.filter((d) => d.status === filter.status); items.sort((a, b) => (b.updated || 0) - (a.updated || 0)); return { items: items.map(draftStrip) }; }
  function draftGet(id) { return draftStrip(draftCol.get(id)); }
  function draftPut(input = {}, who) {
    const t = now();
    let d = input.id ? draftCol.get(input.id) : null;
    if (input.id && !d) throw httpErr(404, 'draft not found');
    const isNew = !d;
    const rec = d ? Object.assign({}, d) : { id: nextId('DRAFT', 'grc_drafts'), status: 'draft', version: '0.1', created: t, by: (who && who.user) || '', history: [], document: null };
    ['doc_id', 'title', 'sub_code', 'domain', 'owner', 'frameworks', 'purpose', 'body', 'control', 'supersedes'].forEach((k) => { if (input[k] !== undefined) rec[k] = String(input[k]).slice(0, 40000); });
    if (input.requirements !== undefined) rec.requirements = (Array.isArray(input.requirements) ? input.requirements : String(input.requirements || '').split('\n')).map((s) => String(s).trim()).filter(Boolean).slice(0, 200);
    if (!String(rec.title || '').trim()) throw httpErr(400, 'a policy title is required');
    rec.updated = t;
    if (!isNew) reopenDraft(rec, who, 'edited');
    rec.version = isNew ? '0.1' : bumpVersion(d.version);
    rec.history = (d ? d.history || [] : []).concat([{ at: t, by: (who && who.user) || '', what: isNew ? 'created' : 'edited' }]);
    draftCol.put(rec); return draftStrip(rec);
  }
  function draftStatus(id, status, who) {
    const d = draftCol.get(id); if (!d) throw httpErr(404, 'draft not found');
    if (!['draft', 'in-review', 'approved', 'rejected'].includes(status)) throw httpErr(400, 'status must be draft, in-review, approved or rejected');
    // four-eyes: whoever wrote or last changed the draft does not approve it
    if (status === 'approved') { const authors = [d.by].concat((d.history || []).filter((h) => /^(created|edited|document uploaded)/.test(h.what)).map((h) => h.by)); if (authors.some((a) => sameUser(a, who && who.user))) throw httpErr(403, 'four eyes: you wrote or changed this draft - another administrator must approve it'); }
    d.status = status; if (status === 'approved') { d.version = /^0\./.test(d.version || '') ? '1.0' : d.version; d.approved_by = (who && who.user) || ''; d.approved_at = now(); }
    d.updated = now(); d.history = (d.history || []).concat([{ at: now(), by: (who && who.user) || '', what: 'status → ' + status }]);
    draftCol.put(d); return draftStrip(d);
  }
  function draftUpload(id, input = {}, who, o = {}) {
    const d = draftCol.get(id); if (!d) throw httpErr(404, 'draft not found');
    const fn = String(input.filename || '').slice(0, 200); if (!fn) throw httpErr(400, 'a filename is required');
    const b64 = typeof input.content_b64 === 'string' ? input.content_b64 : '';
    // ~1 MB file kept for download; larger is recorded by reference only - unless the caller checked the file itself and
    // allows more (the PDPL policy upload: content-checked, up to 6 MB, so the approver reads exactly what was submitted)
    const inline = b64 && b64.length <= (o.maxInlineB64 || 1300000);
    d.document = { filename: fn, size: Number(input.size) || (b64 ? Math.round(b64.length * 0.75) : 0), sha256: String(input.sha256 || '').slice(0, 64).toLowerCase(),
      uploaded_by: (who && who.user) || '', uploaded_at: now(), stored: inline ? 'inline' : 'by-reference', content_b64: inline ? b64 : undefined };
    reopenDraft(d, who, 'document replaced');
    d.updated = now(); d.version = bumpVersion(d.version);
    d.history = (d.history || []).concat([{ at: now(), by: (who && who.user) || '', what: 'document uploaded: ' + fn + (d.document.sha256 ? ' (' + d.document.sha256.slice(0, 12) + '…)' : '') + (inline ? '' : ' — by reference') }]);
    draftCol.put(d); return draftStrip(d);
  }
  function draftDocument(id) {
    const d = draftCol.get(id); if (!d || !d.document) throw httpErr(404, 'no document attached');
    if (!d.document.content_b64) throw httpErr(404, 'document is recorded by reference only (kept in the document store) — no inline copy to download');
    return { filename: d.document.filename, content_b64: d.document.content_b64, sha256: d.document.sha256 };
  }
  function draftDelete(id) { const d = draftCol.get(id); if (!d) throw httpErr(404, 'draft not found'); draftCol.remove(id); return { ok: true }; }
  function draftSeedGaps(who) {
    const have = new Set(draftCol.all().map((d) => String(d.title || '').toLowerCase()));
    let created = 0;
    for (const g of GAP_DRAFTS) { if (have.has(g.title.toLowerCase())) continue;
      draftPut({ title: g.title, domain: g.domain, frameworks: g.frameworks, control: g.control, purpose: g.purpose, body: '' }, who); created++; }
    return { created, total: GAP_DRAFTS.length };
  }

  // ---- DR / BCM drills: Disaster-Recovery and Business-Continuity exercises, recorded by analysts (the customer's own
  // records — not invented), framed to SAMA CSF's requirement to regularly test recoverability. Each drill carries its
  // scope, RTO/RPO targets vs achieved, result, findings and remediation, with operator execution and admin sign-off
  // (four-eyes). Results feed a per-system coverage view and a printable evidence report. Nothing is assumed: a target
  // or achieved time that was not recorded stays null and is reported as "not recorded", never as met.
  const drillCol = store.collection('grc_drills');
  const DR_TYPES = ['failover', 'restore', 'backup-restore', 'tabletop', 'full-dr', 'component'];
  // SAMA CSF requires BCM & recoverability to be tested; these are the supervisory areas a drill typically evidences.
  // Indicative references — confirm the exact clause against the SAMA Cyber Security Framework in force.
  const SAMA_DR_REFS = [
    { ref: 'SAMA CSF 3.3.15', area: 'Business Continuity Management' },
    { ref: 'SAMA CSF 3.3.16', area: 'Disaster Recovery' },
    { ref: 'SAMA CSF 3.3.17', area: 'Backup & Restoration' },
    { ref: 'SAMA BCM Framework', area: 'Business Continuity Programme' },
  ];
  function drillStrip(d) { if (!d) return d; const c = Object.assign({}, d); if (c.evidence) { c.evidence = Object.assign({}, c.evidence); delete c.evidence.content_b64; } return c; }
  function dParse(s) { const t = Date.parse(String(s || '')); return isNaN(t) ? null : t; }
  function drillMet(d) {
    const rto = (d.rto_target_min != null && d.rto_actual_min != null) ? (Number(d.rto_actual_min) <= Number(d.rto_target_min)) : null;
    const rpo = (d.rpo_target_min != null && d.rpo_actual_min != null) ? (Number(d.rpo_actual_min) <= Number(d.rpo_target_min)) : null;
    return { rto, rpo };
  }
  function drillEnrich(d) {
    const met = drillMet(d);
    return Object.assign(drillStrip(d), { met, has_evidence: !!(d.evidence && d.evidence.filename) });
  }
  function drillList(filter = {}) {
    let items = drillCol.all();
    if (filter.status) items = items.filter((d) => d.status === filter.status);
    if (filter.result) items = items.filter((d) => d.result === filter.result);
    if (filter.system) items = items.filter((d) => String(d.system || '').toLowerCase() === String(filter.system).toLowerCase());
    if (filter.type) items = items.filter((d) => d.type === filter.type);
    items.sort((a, b) => (dParse(b.executed) || dParse(b.scheduled) || b.updated || 0) - (dParse(a.executed) || dParse(a.scheduled) || a.updated || 0));
    return { items: items.map(drillEnrich), types: DR_TYPES, sama_refs: SAMA_DR_REFS };
  }
  function drillGet(id) { const d = drillCol.get(id); return d ? drillEnrich(d) : null; }
  function drillPut(input = {}, who) {
    const t = now();
    let d = input.id ? drillCol.get(input.id) : null;
    if (input.id && !d) throw httpErr(404, 'drill not found');
    const isNew = !d;
    const rec = d ? Object.assign({}, d) : { id: nextId('DR', 'grc_drills'), status: 'planned', result: null, executed: null,
      created: t, by: (who && who.user) || '', history: [], evidence: null, findings: [], actions: [],
      rto_target_min: null, rto_actual_min: null, rpo_target_min: null, rpo_actual_min: null };
    ['title', 'system', 'scope_detail', 'objective', 'owner', 'participants', 'sama_ref', 'sama_area'].forEach((k) => { if (input[k] !== undefined) rec[k] = String(input[k]).slice(0, 4000); });
    if (input.type !== undefined) { if (!DR_TYPES.includes(input.type)) throw httpErr(400, 'type must be one of: ' + DR_TYPES.join(', ')); rec.type = input.type; }
    if (!rec.type) rec.type = 'failover';
    if (input.scheduled !== undefined) rec.scheduled = String(input.scheduled).slice(0, 40);
    if (input.frequency_months !== undefined) rec.frequency_months = Math.max(0, Math.min(60, Number(input.frequency_months) || 0));
    if (rec.frequency_months == null) rec.frequency_months = 12; // SAMA expects at least annual testing
    ['rto_target_min', 'rpo_target_min'].forEach((k) => { if (input[k] !== undefined) rec[k] = input[k] === '' || input[k] == null ? null : Math.max(0, Number(input[k]) || 0); });
    if (!String(rec.title || '').trim()) throw httpErr(400, 'a drill title is required');
    if (!String(rec.system || '').trim()) throw httpErr(400, 'the system / service in scope is required');
    if (!isNew) reopenDrill(rec, who, 'drill details edited');
    rec.updated = t;
    rec.history = (d ? d.history || [] : []).concat([{ at: t, by: (who && who.user) || '', what: isNew ? 'planned' : 'edited' }]);
    drillCol.put(rec); return drillEnrich(rec);
  }
  // record the outcome of an executed drill (operator): execution date, result, achieved RTO/RPO, findings, remediation.
  function drillResult(id, input = {}, who) {
    const d = drillCol.get(id); if (!d) throw httpErr(404, 'drill not found');
    const result = input.result; if (!['pass', 'partial', 'fail'].includes(result)) throw httpErr(400, 'result must be pass, partial or fail');
    d.result = result;
    d.executed = String(input.executed || '').slice(0, 40) || new Date(now()).toISOString().slice(0, 10);
    d.status = 'completed';
    d.executed_by = (who && who.user) || '';
    ['rto_actual_min', 'rpo_actual_min'].forEach((k) => { if (input[k] !== undefined) d[k] = input[k] === '' || input[k] == null ? null : Math.max(0, Number(input[k]) || 0); });
    if (input.findings !== undefined) d.findings = (Array.isArray(input.findings) ? input.findings : String(input.findings || '').split('\n')).map((s) => String(s).trim()).filter(Boolean).slice(0, 100);
    if (input.actions !== undefined) d.actions = (Array.isArray(input.actions) ? input.actions : String(input.actions || '').split('\n')).map((s) => String(s).trim()).filter(Boolean).slice(0, 100);
    if (input.summary !== undefined) d.result_summary = String(input.summary).slice(0, 8000);
    d.signoff = null; // a new result needs a fresh independent sign-off
    d.updated = now();
    d.history = (d.history || []).concat([{ at: now(), by: (who && who.user) || '', what: 'result recorded: ' + result + (d.executed ? ' (' + d.executed + ')' : '') }]);
    drillCol.put(d); return drillEnrich(d);
  }
  // admin sign-off on a completed drill — four-eyes: the approver should not be the person who ran it.
  function drillSignoff(id, input = {}, who) {
    const d = drillCol.get(id); if (!d) throw httpErr(404, 'drill not found');
    if (d.status !== 'completed') throw httpErr(400, 'only a completed drill can be signed off');
    const by = (who && who.user) || '';
    const independent = by && d.executed_by ? !sameUser(by, d.executed_by) : null; // null when no gateway identity (local preview)
    // SAMA: recovery tests are reviewed independently - the person who ran the drill may not sign it off
    if (independent === false) throw httpErr(403, 'the drill was run by ' + by + ' - another administrator must sign it off');
    d.signoff = { by, at: now(), note: String(input.note || '').slice(0, 2000), independent };
    d.updated = now();
    d.history = (d.history || []).concat([{ at: now(), by, what: 'signed off' + (independent === false ? ' (not independent — same person ran and approved)' : '') }]);
    drillCol.put(d); return drillEnrich(d);
  }
  function drillCancel(id, input = {}, who) {
    const d = drillCol.get(id); if (!d) throw httpErr(404, 'drill not found');
    d.status = 'cancelled'; d.updated = now();
    d.history = (d.history || []).concat([{ at: now(), by: (who && who.user) || '', what: 'cancelled' + (input.note ? ': ' + String(input.note).slice(0, 400) : '') }]);
    drillCol.put(d); return drillEnrich(d);
  }
  function drillUpload(id, input = {}, who) {
    const d = drillCol.get(id); if (!d) throw httpErr(404, 'drill not found');
    const fn = String(input.filename || '').slice(0, 200); if (!fn) throw httpErr(400, 'a filename is required');
    const b64 = typeof input.content_b64 === 'string' ? input.content_b64 : '';
    const inline = b64 && b64.length <= 1300000;
    d.evidence = { filename: fn, size: Number(input.size) || (b64 ? Math.round(b64.length * 0.75) : 0), sha256: String(input.sha256 || '').slice(0, 64).toLowerCase(),
      uploaded_by: (who && who.user) || '', uploaded_at: now(), stored: inline ? 'inline' : 'by-reference', content_b64: inline ? b64 : undefined };
    reopenDrill(d, who, 'evidence replaced');
    d.updated = now();
    d.history = (d.history || []).concat([{ at: now(), by: (who && who.user) || '', what: 'evidence attached: ' + fn + (inline ? '' : ' — by reference') }]);
    drillCol.put(d); return drillEnrich(d);
  }
  function drillDocument(id) {
    const d = drillCol.get(id); if (!d || !d.evidence) throw httpErr(404, 'no evidence attached');
    if (!d.evidence.content_b64) throw httpErr(404, 'evidence is recorded by reference only — no inline copy to download');
    return { filename: d.evidence.filename, content_b64: d.evidence.content_b64, sha256: d.evidence.sha256 };
  }
  function drillDelete(id) { const d = drillCol.get(id); if (!d) throw httpErr(404, 'drill not found'); drillCol.remove(id); return { ok: true }; }
  // per-system coverage: last completed drill, whether a test is overdue against the expected cadence, RTO/RPO met.
  function drillSystems() {
    const all = drillCol.all(); const bySys = {};
    for (const d of all) { const k = String(d.system || '—'); (bySys[k] = bySys[k] || []).push(d); }
    return Object.keys(bySys).sort().map((sys) => {
      const list = bySys[sys];
      const done = list.filter((d) => d.status === 'completed').sort((a, b) => (dParse(b.executed) || 0) - (dParse(a.executed) || 0));
      const last = done[0] || null;
      const freq = last ? (last.frequency_months || 12) : (list[0].frequency_months || 12);
      const lastMs = last ? dParse(last.executed) : null;
      const dueMs = lastMs && freq ? lastMs + freq * 2629800000 : null; // ~30.44 days/month
      const overdue = dueMs != null ? (now() > dueMs) : true; // never completed → overdue (untested)
      const met = last ? drillMet(last) : { rto: null, rpo: null };
      return { system: sys, drills: list.length, completed: done.length,
        last: last ? { id: last.id, executed: last.executed, result: last.result, type: last.type } : null,
        last_result: last ? last.result : null, frequency_months: freq, next_due_ms: dueMs, overdue,
        tested: !!last, rto_met: met.rto, rpo_met: met.rpo, signed_off: last ? !!(last.signoff && last.signoff.by) : false };
    });
  }
  function drillSummary() {
    const all = drillCol.all();
    const byStatus = { planned: 0, 'in-progress': 0, completed: 0, cancelled: 0 };
    const byResult = { pass: 0, partial: 0, fail: 0 };
    let rtoMet = 0, rtoMeas = 0, rpoMet = 0, rpoMeas = 0, signed = 0, awaitingSignoff = 0;
    for (const d of all) {
      byStatus[d.status] = (byStatus[d.status] || 0) + 1;
      if (d.status === 'completed' && d.result) byResult[d.result] = (byResult[d.result] || 0) + 1;
      const m = drillMet(d);
      if (m.rto != null) { rtoMeas++; if (m.rto) rtoMet++; }
      if (m.rpo != null) { rpoMeas++; if (m.rpo) rpoMet++; }
      if (d.status === 'completed') { if (d.signoff && d.signoff.by) signed++; else awaitingSignoff++; }
    }
    const systems = drillSystems();
    const overdueSystems = systems.filter((s) => s.overdue).length;
    const now2 = now();
    const upcoming = all.filter((d) => d.status === 'planned' && dParse(d.scheduled) && dParse(d.scheduled) >= now2)
      .sort((a, b) => dParse(a.scheduled) - dParse(b.scheduled)).slice(0, 5)
      .map((d) => ({ id: d.id, title: d.title, system: d.system, type: d.type, scheduled: d.scheduled }));
    return { total: all.length, by_status: byStatus, by_result: byResult,
      rto: { measured: rtoMeas, met: rtoMet, pct: rtoMeas ? Math.round(rtoMet / rtoMeas * 100) : null },
      rpo: { measured: rpoMeas, met: rpoMet, pct: rpoMeas ? Math.round(rpoMet / rpoMeas * 100) : null },
      signed_off: signed, awaiting_signoff: awaitingSignoff,
      systems: { total: systems.length, tested: systems.filter((s) => s.tested).length, overdue: overdueSystems },
      upcoming, sama_note: 'SAMA CSF requires business-continuity and recoverability to be tested periodically; a system with no completed drill, or one past its cadence, is flagged overdue.', generated: now() };
  }
  function drillReport() {
    const summary = drillSummary();
    const drills = drillCol.all().map(drillEnrich)
      .sort((a, b) => (dParse(b.executed) || dParse(b.scheduled) || 0) - (dParse(a.executed) || dParse(a.scheduled) || 0));
    return { framework: 'SAMA CSF — Business Continuity & Disaster Recovery', indicative: true,
      org: (app.org && app.org.name) || ZYB_ORG.short, generated: now(), summary, systems: drillSystems(), drills };
  }

  // Insurance Authority framework coverage from the IT policy register + platform controls (indicative crosswalk).
  function frameworkIA() {
    const byCode = {}; for (const p of REGISTER) byCode[p.sub_code] = p;
    const domains = IA_DOMAINS.map((d) => {
      const present = d.policies.filter((c) => byCode[c]).map((c) => ({ sub_code: c, doc_id: byCode[c].doc_id, title: byCode[c].title, cls: (CONTROL_MAP[c] || {}).cls || 'manual' }));
      let status;
      if (!d.req) status = 'na';
      else if (!d.policies.length || present.length === 0) status = 'gap';
      else if (d.partial) status = 'partial';
      else status = 'covered';
      const automated = present.filter((x) => x.cls === 'automated').length;
      return { key: d.key, name: d.name, required: d.req, status, control: d.control, note: d.note || '', policies: present, automated_controls: automated };
    });
    const req = domains.filter((d) => d.required);
    const covered = req.filter((d) => d.status === 'covered').length, partial = req.filter((d) => d.status === 'partial').length, gap = req.filter((d) => d.status === 'gap').length;
    const na = domains.length - req.length;
    const coverage_pct = req.length ? Math.round((covered + partial * 0.5) / req.length * 1000) / 10 : 0;
    return { framework: 'Insurance Authority', authority: 'Insurance Authority (KSA) — insurance sector supervisor (previously SAMA)',
      indicative: true, note: 'Working crosswalk of the IT policy register and platform controls to the Insurance Authority’s supervisory areas. Confirm against the IA’s current issued regulations; business-only domains (AML, consumer protection) are marked N/A for IT GRC.',
      summary: { domains: domains.length, required: req.length, covered, partial, gap, na, coverage_pct }, domains };
  }

  return { register, policy, summary, controlStatus, csfCoverage, attest, reviewAck, frameworksOf, frameworkIA,
    draftList, draftGet, draftPut, draftStatus, draftUpload, draftDocument, draftDelete, draftSeedGaps,
    drillList, drillGet, drillPut, drillResult, drillSignoff, drillCancel, drillUpload, drillDocument, drillDelete, drillSystems, drillSummary, drillReport,
    reviewState: (id) => { const p = REGISTER.find((x) => x.doc_id === id); return p ? reviewState(p) : null; }, CONTROL_MAP, IA_DOMAINS, parseReviewDate };
}

function httpErr(code, msg) { const e = new Error(msg); e.status = code; e.statusCode = code; return e; }

// the read routes in Python (pyengine/grc_read.py, migration step 8d): drafts and DR drills, read from the store files
// (read-only - this process stays the only writer). A drill date Python cannot read exactly like Date.parse answers
// {node: true}; that, a missing or failing Python, or grc.engine = "node" → the Node.js functions answer.
function grcPy(app) {
  if (((app.config && app.config.grc) || {}).engine === 'node' || !app.store || !app.store.dir) return null;
  let py = null; try { py = require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 30000 }); } catch (e) { return null; }
  const now = () => (app.now ? app.now() : Date.now());
  return async (op, body, ok) => { try { const r = await py.call(op, Object.assign({ dir: app.store.dir, now: now() }, body || {})); return r && r.ok !== false && !r.node && ok(r) ? r : null; } catch (e) { return null; } };
}
// the WRITES of drafts and drills decided in Python (pyengine/grc_write.py, migration step 9c), committed here - the store
// keeps ONE writer. Written only if the collection and its number counter did not change while Python decided (a
// fingerprint) and only into grc_drafts / grc_drills / their two counters; otherwise the Node.js function decides again.
function grcWriter(app, G) {
  const cfg = (app.config && app.config.grc) || {};
  if (cfg.engine === 'node' || !app.store || !app.store.dir) return null;
  let py = null; try { py = require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 30000 }); } catch (e) { return null; }
  const st = app.store, counters = st.collection('counters'), crypto2 = require('node:crypto');
  const fp = (col) => crypto2.createHash('sha256').update(JSON.stringify(st.collection(col).all()) + '\n' + JSON.stringify(counters.get(col) || null)).digest('hex');
  const okWrite = (col, x) => x && ((x.c === col) || (x.c === 'counters' && x.o && x.o.id === col));
  const stats = { python: 0, node: 0, changed_meanwhile: 0 };
  async function write(op, col, extra, who, node0) {
    const node = () => { stats.node++; return node0(); };
    const before = fp(col);
    const r = await py.call(op, Object.assign({ dir: st.dir, at: app.now ? app.now() : Date.now(), wall: Date.now(), who: { user: who && who.user, role: who && who.role } }, extra));
    if (r && fp(col) !== before) stats.changed_meanwhile++;
    if (!r || r.ok === false || (!r.refuse && !('result' in r)) || fp(col) !== before) return node();
    const puts = r.puts || [], removes = r.removes || [];
    if (!puts.every((x) => okWrite(col, x)) || !removes.every((x) => x && x.c === col)) return node();
    stats.python++;
    for (const x of removes) st.collection(x.c).remove(x.id);
    for (const x of puts) st.collection(x.c).put(x.o);
    if (r.refuse) throw httpErr(r.refuse.status, r.refuse.error);
    return r.result;
  }
  return { write, stats: () => Object.assign({}, stats) };
}
const qs = (q) => { const o = {}; for (const k of Object.keys(q || {})) if (typeof q[k] === 'string') o[k] = q[k]; return o; };

function registerGrc(srv, app) {
  const G = createGrc(app);
  const PY = grcPy(app);
  const via = async (op, body, ok, node) => (PY && await PY(op, body, ok)) || node();
  const W = grcWriter(app, G);
  const w = (op, col, extra, who, node) => (W ? W.write(op, col, extra, who, node) : node());
  app.grcWriteStats = () => (W ? W.stats() : null);
  srv.route('GET', '/grc/register', (ctx) => void ctx.need('viewer') || G.register(ctx.query || {}));
  srv.route('GET', '/grc/summary', (ctx) => void ctx.need('viewer') || G.summary());
  srv.route('GET', '/grc/control-status', (ctx) => void ctx.need('viewer') || ({ status: G.controlStatus() }));
  srv.route('GET', '/grc/csf-coverage', (ctx) => void ctx.need('viewer') || G.csfCoverage());
  srv.route('GET', '/grc/frameworks/ia', (ctx) => void ctx.need('viewer') || G.frameworkIA());
  // policy drafting (new / replacement policies, kept separate from the signed register)
  srv.route('GET', '/grc/drafts', (ctx) => void ctx.need('viewer') || via('grc.drafts', { query: qs(ctx.query) }, (r) => Array.isArray(r.items), () => G.draftList(ctx.query || {})));
  srv.route('GET', '/grc/drafts/:id', async (ctx) => { ctx.need('viewer'); const r = await via('grc.draft', { id: ctx.params.id }, (x) => typeof x.found === 'boolean', () => ({ found: !!G.draftGet(ctx.params.id), draft: G.draftGet(ctx.params.id) })); if (!r.found) throw httpErr(404, 'draft not found'); return r.draft; });
  srv.route('POST', '/grc/drafts', (ctx) => { ctx.need('operator'); return w('grc.draft_put', 'grc_drafts', { body: ctx.body || {} }, ctx.who, () => G.draftPut(ctx.body || {}, ctx.who)); });
  srv.route('POST', '/grc/drafts/:id', (ctx) => { ctx.need('operator'); const b = Object.assign({}, ctx.body, { id: ctx.params.id }); return w('grc.draft_put', 'grc_drafts', { body: b }, ctx.who, () => G.draftPut(b, ctx.who)); });
  srv.route('POST', '/grc/drafts/:id/status', (ctx) => { ctx.need('admin'); const st = (ctx.body || {}).status; return w('grc.draft_status', 'grc_drafts', { id: ctx.params.id, status: st }, ctx.who, () => G.draftStatus(ctx.params.id, st, ctx.who)); });
  srv.route('POST', '/grc/drafts/:id/upload', (ctx) => { ctx.need('operator'); return w('grc.draft_upload', 'grc_drafts', { id: ctx.params.id, body: ctx.body || {} }, ctx.who, () => G.draftUpload(ctx.params.id, ctx.body || {}, ctx.who)); });
  srv.route('GET', '/grc/drafts/:id/document', (ctx) => { ctx.need('operator'); return G.draftDocument(ctx.params.id); });
  srv.route('POST', '/grc/drafts/:id/delete', (ctx) => { ctx.need('admin'); return w('grc.draft_delete', 'grc_drafts', { id: ctx.params.id }, ctx.who, () => G.draftDelete(ctx.params.id)); });
  srv.route('POST', '/grc/drafts-seed-gaps', (ctx) => { ctx.need('admin'); return G.draftSeedGaps(ctx.who); });
  // DR / BCM drills (SAMA recoverability testing) — reads open; plan/run/evidence need operator; sign-off / delete need admin
  srv.route('GET', '/grc/drills', (ctx) => void ctx.need('viewer') || via('grc.drills', { query: qs(ctx.query) }, (r) => Array.isArray(r.items), () => G.drillList(ctx.query || {})));
  srv.route('GET', '/grc/drills/summary', (ctx) => void ctx.need('viewer') || via('grc.drill_summary', {}, (r) => r.by_status && r.systems, () => G.drillSummary()));
  srv.route('GET', '/grc/drills/systems', (ctx) => void ctx.need('viewer') || via('grc.drill_systems', {}, (r) => Array.isArray(r.systems), () => ({ systems: G.drillSystems() })));
  srv.route('GET', '/grc/drills/report', (ctx) => void ctx.need('viewer') || G.drillReport());
  srv.route('GET', '/grc/drills/:id', async (ctx) => { ctx.need('viewer'); const r = await via('grc.drill', { id: ctx.params.id }, (x) => typeof x.found === 'boolean', () => ({ found: !!G.drillGet(ctx.params.id), drill: G.drillGet(ctx.params.id) })); if (!r.found) throw httpErr(404, 'drill not found'); return r.drill; });
  srv.route('GET', '/grc/drills/:id/document', (ctx) => { ctx.need('operator'); return G.drillDocument(ctx.params.id); });
  srv.route('POST', '/grc/drills', (ctx) => { ctx.need('operator'); return w('grc.drill_put', 'grc_drills', { body: ctx.body || {} }, ctx.who, () => G.drillPut(ctx.body || {}, ctx.who)); });
  srv.route('POST', '/grc/drills/:id', (ctx) => { ctx.need('operator'); const b = Object.assign({}, ctx.body, { id: ctx.params.id }); return w('grc.drill_put', 'grc_drills', { body: b }, ctx.who, () => G.drillPut(b, ctx.who)); });
  srv.route('POST', '/grc/drills/:id/result', (ctx) => { ctx.need('operator'); return w('grc.drill_result', 'grc_drills', { id: ctx.params.id, body: ctx.body || {} }, ctx.who, () => G.drillResult(ctx.params.id, ctx.body || {}, ctx.who)); });
  srv.route('POST', '/grc/drills/:id/signoff', (ctx) => { ctx.need('admin'); return w('grc.drill_signoff', 'grc_drills', { id: ctx.params.id, body: ctx.body || {} }, ctx.who, () => G.drillSignoff(ctx.params.id, ctx.body || {}, ctx.who)); });
  srv.route('POST', '/grc/drills/:id/cancel', (ctx) => { ctx.need('operator'); return w('grc.drill_cancel', 'grc_drills', { id: ctx.params.id, body: ctx.body || {} }, ctx.who, () => G.drillCancel(ctx.params.id, ctx.body || {}, ctx.who)); });
  srv.route('POST', '/grc/drills/:id/upload', (ctx) => { ctx.need('operator'); return w('grc.drill_upload', 'grc_drills', { id: ctx.params.id, body: ctx.body || {} }, ctx.who, () => G.drillUpload(ctx.params.id, ctx.body || {}, ctx.who)); });
  srv.route('POST', '/grc/drills/:id/delete', (ctx) => { ctx.need('admin'); return w('grc.drill_delete', 'grc_drills', { id: ctx.params.id }, ctx.who, () => G.drillDelete(ctx.params.id)); });
  srv.route('GET', '/grc/policy/:id', (ctx) => { ctx.need('viewer'); const p = G.policy(ctx.params.id); if (!p) throw httpErr(404, 'policy not found'); return p; });
  srv.route('POST', '/grc/policy/:id/attest', (ctx) => { ctx.need('operator'); return G.attest(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/grc/policy/:id/review', (ctx) => { ctx.need('admin'); return G.reviewAck(ctx.params.id, ctx.body || {}, ctx.who); });
  (app.addons = app.addons || {}).grc = G;
  // the working registers: remediation actions, risks, policy exceptions, evidence (engine/grc-registers.js)
  try { require('./grc-registers').registerGrcRegisters(srv, app); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; }
  return G;
}

module.exports = { POLICY_CSF, CSF_KW, SIGNAL_CSF, createGrc, registerGrc, CONTROL_MAP, IA_DOMAINS, frameworksOf, parseReviewDate, REGISTER };
