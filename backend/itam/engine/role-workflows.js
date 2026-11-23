// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Role workflows ({P} = /api/itam, My work -> Role Workflows): the recurring work of the people who run the organisation's IT - GRC
 * consultant, Exchange Server administrator, Windows Server administrator, virtualization administrator, network engineer, security
 * engineer, desktop support engineer, SOC analyst, SIEM engineer and penetration testing engineer - as a guided checklist per period (daily / weekly / monthly):
 *   status     each step reads what the platform already records, never typed: the asset register (servers, VMs, network devices,
 *              desktops - not seen, end of life passed or near, warranty ended, lost / in repair), the AI engineers' open duty items
 *              (critical / high, by engineer), the GRC registers (overdue actions, risks past review, exceptions expired or expiring,
 *              evidence past its due date). A step the platform cannot measure is "confirm" - a person checks it on the linked page
 *              and says so; it is never shown as fine. A source that holds nothing says "nothing recorded", not "ok".
 *   sign-off   a person (never a service or AI identity; an operator, and a member of the role when Settings names members) records
 *              the step done / issue / not applicable for the period, with a note; a step that needs attention, an issue and "not
 *              applicable" each need a note saying what was done or why. A sign-off can be replaced, never deleted; every one is audited.
 *   handover   a summary of the period (steps signed, steps open, what needs attention) with the author's notes; acknowledged by a
 *              different person.
 *   GET  /role-workflows                         viewer   the roles with today's progress
 *   GET  /role-workflows/:role?cadence=&period=  viewer   the steps with their live status, sign-offs and handovers
 *   POST /role-workflows/:role/signoff           operator {step, period, outcome: done|issue|na, note?}       audited
 *   POST /role-workflows/:role/handover          operator {cadence, period, notes}                           audited
 *   POST /role-workflows/handovers/:id/ack       operator {note?}  not the author                             audited
 *   GET|POST /role-workflows/settings            admin    {members: {role: [users]}, version}                 audited
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (s) => String(s || '').toLowerCase();
const CAD = ['daily', 'weekly', 'monthly'];
const OUTCOMES = ['done', 'issue', 'na'];
const OPEN_DUTY = (x) => !['resolved', 'closed'].includes(x.status);
const A_OPEN = ['open', 'in_progress', 'done'];

// period key of a cadence for a time: daily YYYY-MM-DD (UTC+3, Riyadh), weekly YYYY-Www (ISO week), monthly YYYY-MM
function periodOf(cadence, t) {
  const d = new Date(t + 3 * 3600000), ymd = d.toISOString().slice(0, 10);
  if (cadence === 'daily') return ymd;
  if (cadence === 'monthly') return ymd.slice(0, 7);
  const x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())), dn = (x.getUTCDay() + 6) % 7; x.setUTCDate(x.getUTCDate() - dn + 3);
  const y = x.getUTCFullYear(), w1 = new Date(Date.UTC(y, 0, 4)), wk = 1 + Math.round(((x - w1) / DAY - 3 + ((w1.getUTCDay() + 6) % 7)) / 7);
  return y + '-W' + String(wk).padStart(2, '0');
}
const PERIOD_RE = { daily: /^\d{4}-\d{2}-\d{2}$/, weekly: /^\d{4}-W\d{2}$/, monthly: /^\d{4}-\d{2}$/ };

// ---- what a step measures: functions over the platform's records. Each returns {state: ok | attention | confirm | none, n, text, items}
function checks(store, now) {
  const t = now(), today = new Date(t).toISOString().slice(0, 10);
  const assets = () => store.collection('assets').all((a) => !['retired', 'disposed'].includes(a.status));
  const days = (iso) => (iso ? (t - Date.parse(iso)) / DAY : null);
  const nm = (a) => a.name || a.asset_tag || a.serial || a.id;
  const pick = (L, f) => L.slice(0, 10).map((a) => ({ id: a.id, name: nm(a), why: f ? f(a) : '' }));
  const res = (L, okText, badText, f) => (L.length ? { state: 'attention', n: L.length, text: L.length + ' ' + badText, items: pick(L, f) } : { state: 'ok', n: 0, text: okText, items: [] });
  const isWin = (a) => /windows/i.test(a.os || '') && ['server', 'vm'].includes(a.type);
  const isExch = (a) => /exchange/i.test([a.name, a.role, a.os, (a.software || []).map((s) => s && s.name).join(' '), (a.tags || []).join(' ')].join(' '));
  const isNet = (a) => a.type === 'network';
  const isDesk = (a) => ['workstation', 'laptop'].includes(a.type);
  const isVm = (a) => a.type === 'vm' || /esxi|hyper-?v|nutanix|ahv|proxmox|vmware/i.test((a.os || '') + ' ' + (a.role || ''));
  const scope = (f, label) => () => { const L = assets().filter(f); return L.length ? null : { state: 'none', n: 0, text: 'no ' + label + ' in the asset register yet', items: [] }; };
  const notSeen = (f, label, d) => () => { const L = assets().filter(f); if (!L.length) return { state: 'none', n: 0, text: 'no ' + label + ' in the asset register yet', items: [] };
    const bad = L.filter((a) => a.last_seen && days(a.last_seen) > d); const never = L.filter((a) => !a.last_seen).length;
    const r = res(bad, 'every one of ' + L.length + ' ' + label + ' seen in the last ' + d + ' days', label + ' not seen for over ' + d + ' days', (a) => 'last seen ' + String(a.last_seen).slice(0, 10));
    if (never) r.text += ' · ' + never + ' never seen by a source'; return r; };
  const eol = (f, label) => () => { const L = assets().filter(f); if (!L.length) return { state: 'none', n: 0, text: 'no ' + label + ' in the asset register yet', items: [] };
    const past = L.filter((a) => a.eol && a.eol < today), soon = L.filter((a) => a.eol && a.eol >= today && days(a.eol) > -180);
    const r = res(past, 'no ' + label + ' past end of life', label + ' past end of life', (a) => 'end of life ' + String(a.eol).slice(0, 10));
    if (soon.length) { r.text += ' · ' + soon.length + ' reach it within 6 months'; if (r.state === 'ok') r.state = 'attention'; }
    if (!L.some((a) => a.eol)) return { state: 'none', n: 0, text: 'no end-of-life date recorded for any ' + label + ' - add them in the asset register', items: [] };
    return r; };
  const warranty = (f, label) => () => { const L = assets().filter(f); if (!L.length) return { state: 'none', n: 0, text: 'no ' + label + ' in the asset register yet', items: [] };
    const W = L.filter((a) => a.warranty && a.warranty.end); if (!W.length) return { state: 'none', n: 0, text: 'no warranty dates recorded for ' + label, items: [] };
    return res(W.filter((a) => a.warranty.end < today), 'every recorded warranty is current', label + ' out of warranty', (a) => 'warranty ended ' + String(a.warranty.end).slice(0, 10)); };
  const status = (f, label, st) => () => { const L = assets().filter((a) => f(a) && st.includes(a.status)); return res(L, 'none ' + st.join(' or ').replace(/_/g, ' '), label + ' ' + st.join(' / ').replace(/_/g, ' '), (a) => a.status.replace(/_/g, ' ')); };
  const duty = (engs, label) => () => { const L = store.collection('duty_items').all((x) => engs.includes(x.engineer) && OPEN_DUTY(x) && ['critical', 'high'].includes(x.severity) && x.status !== 'snoozed');
    const any = store.collection('duty_items').all((x) => engs.includes(x.engineer)).length;
    if (!any) return { state: 'none', n: 0, text: 'the ' + label + ' has recorded nothing yet', items: [] };
    return { state: L.length ? 'attention' : 'ok', n: L.length, text: L.length ? L.length + ' open critical / high item(s) from the ' + label : 'no open critical / high item from the ' + label, items: L.slice(0, 10).map((x) => ({ id: x.id, name: x.title, why: x.severity + ' · ' + x.status })) }; };
  const grc = (kind) => () => {
    if (kind === 'actions') { const L = store.collection('grc_actions').all((a) => A_OPEN.includes(a.status) && a.due && a.due < today); return Object.assign(res(L, 'no overdue remediation action', 'remediation action(s) overdue'), { items: L.slice(0, 10).map((a) => ({ id: a.id, name: a.title, why: 'due ' + a.due + ' · ' + (a.owner || 'no owner') })) }); }
    if (kind === 'risks') { const L = store.collection('grc_risks').all((r) => r.status === 'open' && r.review_due && r.review_due < today); return Object.assign(res(L, 'every open risk reviewed on time', 'risk(s) past their review date'), { items: L.slice(0, 10).map((r) => ({ id: r.id, name: r.title || r.description, why: 'review due ' + r.review_due })) }); }
    if (kind === 'exceptions') { const L = store.collection('grc_exceptions').all((x) => x.status === 'approved' && x.expires && (x.expires < today || days(x.expires) > -30)); return Object.assign(res(L, 'no policy exception expired or expiring in 30 days', 'policy exception(s) expired or expiring within 30 days'), { items: L.slice(0, 10).map((x) => ({ id: x.id, name: x.title || x.policy, why: 'expires ' + x.expires })) }); }
    if (kind === 'evidence') { const L = store.collection('grc_evidence').all((x) => x.status === 'active' && x.next_due && x.next_due < today); return Object.assign(res(L, 'every evidence item is current', 'evidence item(s) past their due date'), { items: L.slice(0, 10).map((x) => ({ id: x.id, name: (x.framework || '') + ' ' + (x.control || x.title || ''), why: 'due ' + x.next_due })) }); }
    return null; };
  return { notSeen, eol, warranty, status, duty, grc, scope, isWin, isExch, isNet, isDesk, isVm };
}

// ---- the roles and their steps. page = where the work is done; check = the measurement (absent = "confirm on the page")
function roles(C) {
  const S = (id, cadence, title, page, how, check) => ({ id, cadence, title, page, how, check: check || null });
  return {
    grc: { name: 'GRC Consultant', page: 'ai-grc-consultant.html', steps: [
      S('actions', 'daily', 'Chase overdue remediation actions', 'grc-workspace.html', 'Every overdue action has an owner and a new date, or is escalated.', C.grc('actions')),
      S('duty', 'daily', 'Review the AI GRC Consultant\'s findings', 'ai-grc-consultant.html', 'Accept, reject or assign each critical / high item.', C.duty(['grc', 'nca-ecc', 'iso27001'], 'AI GRC / compliance engineers')),
      S('exceptions', 'weekly', 'Policy exceptions expiring', 'grc-register.html', 'Renew with fresh compensating controls, or close the exception.', C.grc('exceptions')),
      S('evidence', 'weekly', 'Refresh evidence past its due date', 'evidence-packs.html', 'Collect new evidence for each control whose evidence is stale.', C.grc('evidence')),
      S('risks', 'monthly', 'Risks past their review date', 'risk-start.html', 'Re-assess them (Start a Risk Assessment) or confirm them unchanged.', C.grc('risks')),
      S('regulator', 'monthly', 'Regulatory compliance position (SAMA, NCA ECC, PDPL)', 'compliance-overview.html', 'Read the compliance overview; raise an action for every new gap.'),
      S('report', 'monthly', 'Compliance report to management', 'report-center.html', 'Send the monthly GRC report; record where it went.')] },
    exchange: { name: 'Exchange Server Administrator', page: 'exchange-admin.html', steps: [
      S('seen', 'daily', 'Exchange servers reporting', 'exchange-admin.html', 'Each Exchange server is seen by its source today.', C.notSeen(C.isExch, 'Exchange servers', 1)),
      S('health', 'daily', 'Mail flow, queues, databases and DAG health', 'exchange-admin.html', 'Check queues, database copies and the mail-flow test on the Exchange page.'),
      S('certs', 'weekly', 'Exchange certificates and connectors', 'certificates.html', 'No Exchange certificate expiring within 30 days; send / receive connectors unchanged.'),
      S('backup', 'daily', 'Exchange backups', 'backup.html', 'Every Exchange database protected by a good backup in the last 26 hours.'),
      S('eol', 'monthly', 'Exchange versions and end of life', 'lifecycle.html', 'Plan the upgrade of anything past or near end of life.', C.eol(C.isExch, 'Exchange servers')),
      S('cu', 'monthly', 'Cumulative / security updates', 'patch-management.html', 'Install the latest CU and security update through a change.')] },
    windows: { name: 'Windows Server Administrator', page: 'windows-servers.html', steps: [
      S('seen', 'daily', 'Windows servers reporting', 'windows-servers.html', 'Each Windows server is seen by its source today.', C.notSeen(C.isWin, 'Windows servers', 1)),
      S('events', 'daily', 'Critical events, services and disk space', 'windows-admin.html', 'Review the Windows page for stopped services, critical events and low disk.'),
      S('backup', 'daily', 'Server backups', 'backup.html', 'Every server protected by a good backup in the last 26 hours.'),
      S('repair', 'daily', 'Servers in repair or lost', 'inventory.html', 'Each one has a work order or an explanation.', C.status(C.isWin, 'Windows servers', ['in_repair', 'lost'])),
      S('patch', 'weekly', 'Patch compliance', 'patch-management.html', 'Approve and schedule missing security updates through a change.'),
      S('ad', 'weekly', 'Active Directory health and privileged groups', 'ad-audit.html', 'Replication healthy; review membership changes of privileged groups.'),
      S('eol', 'monthly', 'End of life and warranty', 'lifecycle.html', 'Plan replacement or isolation of servers past end of life.', C.eol(C.isWin, 'Windows servers')),
      S('warranty', 'monthly', 'Hardware warranty', 'support-contracts.html', 'Renew or replace servers out of warranty.', C.warranty((a) => a.type === 'server', 'physical servers'))] },
    virt: { name: 'Virtualization Administrator', page: 'ai-virt-admin.html', steps: [
      S('duty', 'daily', 'Review the AI Virtualization Administrator\'s findings', 'ai-virt-admin.html', 'Accept, reject or assign each critical / high item (hosts, datastores, snapshots).', C.duty(['virt'], 'AI Virtualization Administrator')),
      S('seen', 'daily', 'VMs and hosts reporting', 'virtualization.html', 'Every VM and host seen by vCenter / Prism today.', C.notSeen(C.isVm, 'VMs and hosts', 1)),
      S('capacity', 'weekly', 'Capacity: CPU, memory, datastores', 'capacity.html', 'Nothing above its threshold; order capacity 6 months ahead.'),
      S('snapshots', 'weekly', 'Old snapshots and orphaned VMs', 'virtualization.html', 'Remove snapshots older than 7 days; decide on powered-off VMs.'),
      S('backup', 'daily', 'VM backups', 'backup.html', 'Every VM protected by a good backup in the last 26 hours.'),
      S('hardening', 'monthly', 'Host hardening and versions', 'vsphere-studio.html', 'Hosts on a supported version and hardened.', C.eol(C.isVm, 'VMs and hosts')),
      S('dr', 'monthly', 'DR readiness', 'dr-studio.html', 'Replication healthy; the last DR test passed.')] },
    network: { name: 'Network Engineer', page: 'network-engineer.html', steps: [
      S('seen', 'daily', 'Network devices reporting', 'network-dashboard.html', 'Every switch, router, firewall and access point seen today.', C.notSeen(C.isNet, 'network devices', 1)),
      S('down', 'daily', 'Devices down and WAN links', 'network-engineer.html', 'Read the AI Network Engineer: devices not answering, WAN circuits degraded or filling up.'),
      S('changes', 'daily', 'Configuration changes', 'ncm.html', 'Every config change matches an approved change; unexplained drift is investigated.'),
      S('firewall', 'weekly', 'Firewall rules and VPN', 'cisco-network.html', 'Review rule changes, unused rules and VPN tunnels.'),
      S('eol', 'monthly', 'Firmware and end of life', 'cisco-update.html', 'Plan firmware updates; replace devices past end of life.', C.eol(C.isNet, 'network devices')),
      S('warranty', 'monthly', 'Support contracts (SmartNet / FortiCare)', 'support-contracts.html', 'Renew support for every production device.', C.warranty(C.isNet, 'network devices'))] },
    security: { name: 'Security Engineer', page: 'security-center.html', steps: [
      S('alerts', 'daily', 'SOC alerts and cases', 'soc-alerts.html', 'Triage new critical / high alerts; no case breaching its SLA.'),
      S('duty', 'daily', 'AI security engineers\' findings', 'ai-findings.html', 'Accept, reject or assign each critical / high item.', C.duty(['ciso', 'pentest', 'nhi', 'pki'], 'AI security engineers')),
      S('endpoint', 'daily', 'Endpoint protection', 'security-center.html', 'Every endpoint protected and updated; no unresolved detection.'),
      S('vuln', 'weekly', 'Vulnerabilities and exploited CVEs', 'vuln-dashboard.html', 'Plan remediation of critical / exploited vulnerabilities through a change.'),
      S('access', 'weekly', 'Privileged access review', 'privileged-access.html', 'Review privileged sessions and new admin accounts.'),
      S('certs', 'monthly', 'Certificates expiring', 'certificates.html', 'Renew everything expiring in the next 30 days.'),
      S('phish', 'monthly', 'Awareness and phishing results', 'phishing-simulation.html', 'Follow up the people who clicked; plan the next simulation.')] },
    desktop: { name: 'Desktop Support Engineer', page: 'desktops.html', steps: [
      S('duty', 'daily', 'Review the AI Desktop Support Engineer\'s findings', 'desktops.html', 'Act on each critical / high item.', C.duty(['desktop'], 'AI Desktop Support Engineer')),
      S('tickets', 'daily', 'Service desk tickets', 'tickets.html', 'No ticket breaching its SLA; update every open ticket.'),
      S('seen', 'weekly', 'Desktops and laptops reporting', 'end-user-devices.html', 'Every device seen in the last 14 days, or explained.', C.notSeen(C.isDesk, 'desktops and laptops', 14)),
      S('repair', 'daily', 'Devices in repair or lost', 'eam.html', 'Each one has a work order; a lost device is reported to security.', C.status(C.isDesk, 'desktops and laptops', ['in_repair', 'lost'])),
      S('patch', 'weekly', 'Desktop patching', 'desktop-patches.html', 'Push missing patches; follow up devices that failed.'),
      S('joiners', 'weekly', 'Joiners and leavers', 'hr-onboarding.html', 'New joiners equipped on day one; leavers\' devices collected.'),
      S('eol', 'monthly', 'Devices past end of life', 'lifecycle-studio.html', 'Plan the refresh of devices past or near end of life.', C.eol(C.isDesk, 'desktops and laptops'))] },
    soc: { name: 'SOC Analyst', page: 'soc-alerts.html', steps: [
      S('queue', 'daily', 'Triage the alert queue', 'soc-alerts.html', 'Every new critical / high alert triaged: false positive closed with a reason, true positive opened as a case.'),
      S('cases', 'daily', 'Cases and their SLA', 'soc-cases.html', 'No case breaching its SLA; each open case has a next step and an owner.'),
      S('live', 'daily', 'Live stream and UEBA', 'soc-ueba.html', 'Review unusual users and hosts flagged by behaviour analytics.'),
      S('ti', 'daily', 'Threat intelligence', 'soc-ti.html', 'New indicators checked against the estate; blocks proposed where needed.'),
      S('hunt', 'weekly', 'Threat hunt', 'soc-hunt.html', 'Run at least one hypothesis-driven hunt and record the result.'),
      S('ir', 'weekly', 'Incidents and lessons learned', 'incident-response.html', 'Close resolved incidents with root cause; record lessons learned.'),
      S('kpi', 'monthly', 'SOC performance', 'soc-performance.html', 'MTTA / MTTR and false-positive rate reviewed; report to the SOC manager.')] },
    siem: { name: 'SIEM Engineer', page: 'soc-sources.html', steps: [
      S('sources', 'daily', 'Log sources reporting', 'soc-sources.html', 'Every expected log source sent events today; a silent source is investigated.'),
      S('pipeline', 'daily', 'Ingestion pipeline health', 'pipeline-health.html', 'No parsing errors, queue backlog or dropped events.'),
      S('storage', 'weekly', 'Storage and retention', 'log-assurance.html', 'Retention met (SAMA / NCA); storage growth within the forecast.'),
      S('rules', 'weekly', 'Detection rules tuning', 'alarm-rules.html', 'Tune the noisiest rules; add rules for new use cases; no rule broken.'),
      S('coverage', 'monthly', 'Use-case coverage (ATT&CK) and new assets onboarded', 'sama-siem.html', 'New servers and devices are sending logs; coverage gaps planned.', C.notSeen((a) => ['server', 'vm', 'network'].includes(a.type), 'servers and network devices', 7)),
      S('assurance', 'monthly', 'Log assurance evidence', 'log-assurance.html', 'Export the evidence that logs are complete and unaltered for the auditors.')] },
    pentest: { name: 'Penetration Testing Engineer', page: 'vapt-center.html', steps: [
      S('duty', 'daily', 'Review the AI Penetration Testing Engineer\'s findings', 'ai-pentest.html', 'Validate each critical / high finding; rule out false positives with evidence.', C.duty(['pentest'], 'AI Penetration Testing Engineer')),
      S('scans', 'weekly', 'Vulnerability scans', 'vuln-scans.html', 'Scheduled scans ran; new critical findings triaged and handed to the owner.'),
      S('priority', 'weekly', 'Risk-based prioritisation', 'risk-prioritization.html', 'Exploited / internet-facing vulnerabilities first; owners and dates agreed.'),
      S('retest', 'weekly', 'Re-test fixed findings', 'vapt-center.html', 'A finding marked fixed is re-tested before it is closed.'),
      S('eol', 'monthly', 'Unsupported systems in scope', 'lifecycle.html', 'Systems past end of life are tested and isolated or replaced.', C.eol((a) => ['server', 'vm', 'network'].includes(a.type), 'servers and network devices')),
      S('apps', 'monthly', 'Application security testing', 'apppt.html', 'Test new or changed applications before release; record the results.'),
      S('engagement', 'monthly', 'Penetration test engagement', 'pentest.html', 'Plan the next internal / external test: scope, rules of engagement, approvals.')] },
  };
}

function createRoleWorkflows(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, C = checks(store, now), R = roles(C);
  const SO = () => store.collection('rw_signoffs'), HO = () => store.collection('rw_handovers'), CF = () => store.collection('rw_cfg');
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'role-workflow.' + action, target, detail }); };
  const cfg = () => Object.assign({ members: {}, version: 0 }, CF().get('cfg') || {});
  const mustRole = (r) => { const x = R[String(r || '')]; if (!x) throw httpErr(404, 'unknown role: ' + String(r).slice(0, 40)); return x; };
  const member = (who, role) => { const L = cfg().members[role] || []; return !L.length || L.some((u) => low(u) === low(who.user)) || who.role === 'admin'; };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  function measure(step) {
    if (!step.check) return { state: 'confirm', n: null, text: 'not measured by the platform - check it on the page and sign it off', items: [] };
    try { return step.check() || { state: 'confirm', n: null, text: 'not measured', items: [] }; } catch (e) { if (app.log && app.log.every) app.log.every('rw:check:' + step.id, 600000, 'warn', 'role workflow: a check failed', { step: step.id, err: String(e.message).slice(0, 160) }); return { state: 'confirm', n: null, text: 'the measurement failed - check it on the page', items: [] }; }
  }
  function view(roleId, q0) {
    const role = mustRole(param(roleId, 'role')), q = q0 || {}, cadence = CAD.includes(q.cadence) ? q.cadence : 'daily';
    const period = q.period && PERIOD_RE[cadence].test(String(q.period)) ? String(q.period) : periodOf(cadence, now());
    const so = SO().all((x) => x.role === roleId && x.period === period);
    const steps = role.steps.filter((s) => s.cadence === cadence).map((s) => { const m = measure(s), sg = so.filter((x) => x.step === s.id).sort((a, b) => b.at.localeCompare(a.at))[0] || null;
      return { id: s.id, title: s.title, page: s.page, how: s.how, cadence: s.cadence, measured: !!s.check, status: m, signoff: sg }; });
    const counts = { steps: steps.length, signed: steps.filter((s) => s.signoff).length, attention: steps.filter((s) => s.status.state === 'attention').length, issues: steps.filter((s) => s.signoff && s.signoff.outcome === 'issue').length };
    const handovers = HO().all((h) => h.role === roleId).sort((a, b) => b.at.localeCompare(a.at)).slice(0, 10);
    return { role: roleId, name: role.name, page: role.page, cadence, period, periods: Object.fromEntries(CAD.map((c) => [c, periodOf(c, now())])), steps, counts, handovers, members: cfg().members[roleId] || [] };
  }
  function list() {
    return { roles: Object.keys(R).map((id) => { const v = view(id, { cadence: 'daily' }); return { id, name: R[id].name, page: R[id].page, today: v.counts, steps: R[id].steps.length, members: v.members }; }) };
  }
  function signoff(roleId, b0, who) {
    const role = mustRole(param(roleId, 'role')); person(who, 'signs a step off');
    if (!member(who, roleId)) throw httpErr(403, 'signing off ' + role.name + ' steps: a member of that role (Settings) or an administrator');
    const b = body(b0 || {}).str('step', { required: true, max: 40, re: /^[a-z0-9-]+$/, msg: 'step must be a step id' }).str('period', { required: true, max: 10 }).oneOf('outcome', OUTCOMES, { required: true }).str('note', { max: 2000 }).done();
    const step = role.steps.find((s) => s.id === b.step); if (!step) throw httpErr(400, 'step: not a step of ' + role.name);
    if (!PERIOD_RE[step.cadence].test(b.period)) throw httpErr(400, 'period: a ' + step.cadence + ' period looks like ' + periodOf(step.cadence, now()));
    if (b.period > periodOf(step.cadence, now())) throw httpErr(400, 'period: a future period cannot be signed off');
    const m = measure(step);
    if (!b.note && (b.outcome !== 'done' || m.state === 'attention')) throw httpErr(400, b.outcome === 'done' ? 'note: the platform shows ' + m.text + ' - say what was done about it' : 'note: say ' + (b.outcome === 'issue' ? 'what the issue is' : 'why it does not apply'));
    const rec = { id: 'RWS-' + crypto.randomBytes(5).toString('hex'), role: roleId, step: step.id, period: b.period, outcome: b.outcome, note: b.note || '', by: who.user, at: iso(), measured: { state: m.state, n: m.n, text: m.text } };
    SO().put(rec); audit(who, 'signoff', roleId + ':' + step.id + ':' + b.period, { outcome: b.outcome, measured: m.state, n: m.n });
    return rec;
  }
  function handover(roleId, b0, who) {
    const role = mustRole(param(roleId, 'role')); person(who, 'writes a handover');
    if (!member(who, roleId)) throw httpErr(403, 'handover for ' + role.name + ': a member of that role (Settings) or an administrator');
    const b = body(b0 || {}).oneOf('cadence', CAD, { required: true }).str('period', { required: true, max: 10 }).str('notes', { required: true, max: 4000 }).done();
    if (!PERIOD_RE[b.cadence].test(b.period)) throw httpErr(400, 'period: does not match the cadence');
    const v = view(roleId, { cadence: b.cadence, period: b.period });
    const h = { id: 'RWH-' + crypto.randomBytes(5).toString('hex'), role: roleId, cadence: b.cadence, period: b.period, notes: b.notes, by: who.user, at: iso(), ack: null,
      summary: { signed: v.counts.signed, steps: v.counts.steps, attention: v.steps.filter((s) => s.status.state === 'attention').map((s) => s.title + ': ' + s.status.text), open: v.steps.filter((s) => !s.signoff).map((s) => s.title), issues: v.steps.filter((s) => s.signoff && s.signoff.outcome === 'issue').map((s) => s.title + ': ' + s.signoff.note) } };
    HO().put(h); audit(who, 'handover', h.id, { role: roleId, period: b.period, open: h.summary.open.length }); return h;
  }
  function ack(id, b0, who) {
    person(who, 'acknowledges a handover'); const h = HO().get(String(param(id, 'id'))); if (!h) throw httpErr(404, 'handover not found');
    if (low(h.by) === low(who.user)) throw httpErr(403, 'the author does not acknowledge their own handover');
    if (h.ack) throw httpErr(409, 'already acknowledged by ' + h.ack.by);
    const b = body(b0 || {}).str('note', { max: 1000 }).done(); h.ack = { by: who.user, at: iso(), note: b.note || '' }; HO().put(h);
    audit(who, 'handover.ack', h.id, { role: h.role }); return h;
  }
  function settingsSave(b0, who) {
    person(who, 'changes role workflow settings');
    const b = body(b0 || {}).int('version', { required: true, min: 0, max: 1e9 }).done(), raw = (b0 && b0.members) || {}, cur = cfg();
    if (b.version !== cur.version) throw httpErr(409, 'the settings were changed meanwhile - reload');
    if (typeof raw !== 'object' || Array.isArray(raw)) throw httpErr(400, 'members must be {role: [user names]}');
    const members = {};
    for (const [k, L] of Object.entries(raw)) { if (!R[k]) throw httpErr(400, 'members: unknown role ' + String(k).slice(0, 40)); if (!Array.isArray(L) || L.length > 100) throw httpErr(400, 'members.' + k + ' must be a list');
      members[k] = L.map((u) => { const v = String(u || '').trim(); if (!/^[A-Za-z0-9._@-]{2,100}$/.test(v)) throw httpErr(400, 'members.' + k + ': ' + v.slice(0, 40) + ' is not a user name'); return v; }); }
    const next = { id: 'cfg', members, version: cur.version + 1, updated_by: who.user, updated_at: iso() }; CF().put(next);
    audit(who, 'settings', 'role-workflows', Object.fromEntries(Object.entries(members).map(([k, v]) => [k, v.length]))); return cfg();
  }
  return { list, view, signoff, handover, ack, settings: cfg, settingsSave, periodOf, ROLES: Object.keys(R) };
}

function registerRoleWorkflows(srv, app, W) {
  srv.route('GET', '/role-workflows', (ctx) => { ctx.need('viewer'); return W.list(); });
  srv.route('GET', '/role-workflows/settings', (ctx) => { ctx.need('admin'); return W.settings(); });
  srv.route('POST', '/role-workflows/settings', (ctx) => { ctx.need('admin'); return W.settingsSave(ctx.body, ctx.who); }, { maxBody: 32768 });
  srv.route('POST', '/role-workflows/handovers/:id/ack', (ctx) => { ctx.need('operator'); return W.ack(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('GET', '/role-workflows/:role', (ctx) => { ctx.need('viewer'); return W.view(ctx.params.role, ctx.query || {}); });
  srv.route('POST', '/role-workflows/:role/signoff', (ctx) => { ctx.need('operator'); return W.signoff(ctx.params.role, ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/role-workflows/:role/handover', (ctx) => { ctx.need('operator'); return W.handover(ctx.params.role, ctx.body, ctx.who); }, { maxBody: 8192 });
}

module.exports = { createRoleWorkflows, registerRoleWorkflows, periodOf };
