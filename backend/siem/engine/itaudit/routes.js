// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Audit evidence for the AI IT / Cyber Security Auditors (IT Asset Management engine/auditors.js). They run the tests:
 * CIS benchmarks and the SAMA CSF / NCA ECC / ISO 27001 controls for Active Directory, network devices, databases and
 * applications. This route only hands them the records the SIEM already holds, read-only, so a test can name the rows its
 * finding comes from. Nothing is changed and nothing is collected here.
 *
 *   GET {P}/audit/evidence/ad                         analyst  AD accounts (audit fields only), privileged groups, domain policy
 *   GET {P}/audit/evidence/network                    analyst  devices, monitoring credentials in use (never values), security
 *                                                              check results, configuration captures (without the text)
 *   GET {P}/audit/evidence/network/config/:id         analyst  one device's last running-config (secrets already removed)
 *   GET {P}/audit/evidence/database?hours=1..720      analyst  Database Audit report (activity, posture, findings)
 *   GET {P}/audit/evidence/applications?hours=1..720  analyst  Application Audit report per application (at most 40)
 *   GET {P}/audit/evidence/platform                   analyst  log retention settings and the oldest event kept
 *   GET {P}/audit/evidence/m365                       analyst  MFA registration, guests, sign-in activity, Conditional
 *                                                              Access, risky users, Intune compliance (Graph, as synced)
 * Named people's accounts and activity are personal data (PDPL): analyst and above, and every read is audited.
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { body, param } = require('../util/check');

const DAY = 86400000, MAX_APPS = 40;
const iso = (t) => (t ? new Date(t).toISOString() : null);

function adEvidence(identity, now = Date.now()) {
  if (!identity || typeof identity.snapshot !== 'function') return { available: false, reason: 'the AD identity sync is not configured on the SIEM (Active Directory settings)' };
  const snap = identity.snapshot();
  if (!snap || !snap.synced) return { available: false, reason: 'the AD identity sync has not completed yet' };
  const users = (snap.users || []).map((r) => {
    const f = identity.flags(r, now), uac = Number(r.uac) || 0;
    return { sam: r.sam, name: r.name || '', disabled: f.disabled, privileged: f.privileged, privileged_groups: r.priv_groups || [], service_account: f.service_account,
      dormant: f.dormant, expired: f.expired, admin_orphan: !!(r.admin_count && !f.privileged), pwd_never_expires: !!(uac & 0x10000), pwd_not_required: !!(uac & 0x20),
      no_preauth: !!(uac & 0x400000), delegation: !!(uac & 0x80000), last_logon: iso(r.last_logon), pwd_last_set: iso(r.pwd_last_set), created: iso(r.created),
      rid: (/-(\d+)$/.exec(String(r.sid || '')) || [])[1] || '', has_mail: !!r.mail };   // RID 500 / 501 = built-in Administrator / Guest; a mailbox on an admin account = used as an everyday account
  });
  const sum = identity.summary();
  return { available: true, synced: iso(snap.synced), server: snap.server || '', domain: snap.dnsDomain || '', dormant_days: sum.dormant_days,
    policy: snap.policy || null, counts: sum.counts, users,
    groups: (snap.groups || []).filter((g) => g.privileged).map((g) => ({ name: g.sam, members: (g.members || []).map((m) => ({ sam: m.sam, nested: !!m.nested })) })) };
}

function networkEvidence(N) {
  if (!N) return { available: false, reason: 'the AI Network Engineer (netops) is not running on the SIEM' };
  const devs = N.inventory.list();
  const caps = N.configAudit ? N.configAudit.list() : [];
  const plans = N.changes && typeof N.changes.list === 'function' ? N.changes.list({}) : [];
  // change plans on a device, as the auditors need them: who proposed, who decided, when it was applied
  const changesOf = (id) => plans.filter((c) => String(c.device || '').toLowerCase() === String(id).toLowerCase()).slice(0, 50).map((c) => ({ id: c.id, title: String(c.title || '').slice(0, 160), status: c.status,
    proposed_by: c.proposed_by || '', proposed_at: iso(c.proposed_at), decided_by: c.decided_by || '', decided_at: iso(c.decided_at), applied_by: c.applied_by || '', applied_at: iso(c.applied_at) }));
  return { available: true, generated_at: iso(Date.now()),
    devices: devs.map((d) => {
      const s = N.poller.snapshot(d.id), c = N.inventory.credentialSummary(d.id), cap = caps.find((x) => x.id === d.id);
      return { id: d.id, name: d.name, vendor: d.vendor, role: d.role || '', site: d.site || '', ip: d.ip, criticality: d.criticality || 1,
        os_version: (d.cli_facts && d.cli_facts.version) || '', model: (d.cli_facts && d.cli_facts.model) || '',
        monitoring: { snmp: c.snmp, api: c.api ? c.api : null, ssh: c.ssh ? 'set' : null },   // which kind is set, never a value
        polled_at: s ? iso(s.at) : null, poll_errors: s ? (s.errors || []).slice(0, 5) : [],
        security_at: s && s.security ? iso(s.security.at) : null, security_errors: s && s.security ? (s.security.errors || []).slice(0, 5) : [],
        facts: s && s.security && s.security.facts ? s.security.facts : null,   // fwfacts.js: settings only, no secrets
        security: s && s.security ? (s.security.items || []).map((i) => ({ kind: i.kind, severity: i.severity, key: i.key, title: i.title, evidence: i.evidence || [], rec: i.rec })) : [],
        licenses: s && s.licenses ? (s.licenses.items || []).map((l) => ({ name: l.name || l.feature || '', expires: l.expires || l.expiry || null, status: l.status || '' })) : [],
        config: cap ? { at: iso(cap.at), checked: iso(cap.checked), sha256: cap.sha256 || null, error: cap.error || '', truncated: !!cap.truncated,
          history: (cap.history || []).map((h) => ({ sha256: h.sha256, first_seen: iso(h.first_seen), previous_read: iso(h.previous_read) })) } : null,
        changes: changesOf(d.id) };
    }) };
}

async function platformEvidence(deps) {
  const c = deps.config || {}, out = { available: true, retention_days: c.retention_days || null, archive_retention_days: c.archive_retention_days || null,
    required_retention_days: (c.compliance && c.compliance.sama && c.compliance.sama.required_retention_days) || 365, oldest_event: null, oldest_error: '' };
  if (deps.ch && typeof deps.ch.query === 'function') {
    try {
      // system.parts when granted, else min(ts) of the table itself (the SIEM user is granted siem.* only) - compliance/evidence-ch.js
      const errs = [], o = await require('../compliance/evidence-ch').oldestData(deps.ch, (c.clickhouse && c.clickhouse.database) || 'siem', { readonly: true, timeout_ms: 10000 }, errs);
      if (!o) throw new Error(errs.join('; '));
      out.oldest_event = o.events ? new Date(o.events).toISOString() : null;
    } catch (e) { out.oldest_error = String(e.message || e).slice(0, 200); }
  } else out.oldest_error = 'the event store (ClickHouse) is not available';
  return out;
}

function m365Evidence(G) {
  if (!G || typeof G.data !== 'function') return { available: false, reason: 'the Microsoft 365 (Graph) sync is not running on the SIEM' };
  const d = G.data();
  if (!d || d.configured === false) return { available: false, reason: (d && d.reason) || 'Microsoft 365 is not configured' };
  const sec = d.security || {}, blk = (b) => (b && b.ok ? b.data : null);
  return { available: true, updated: d.updated || null, sync: d.sync || null, blocks: d.blocks || {},
    mfa: blk(sec.mfa), conditional_access: blk(sec.conditionalAccess), risky_users: blk(sec.riskyUsers),
    users: d.users && Array.isArray(d.users.list) ? d.users.list.map((u) => ({ name: u.name, upn: u.upn, enabled: u.enabled !== false, guest: !!u.guest, created: u.created || null, last: u.last === undefined ? undefined : u.last || null, licensed: (u.lic || 0) > 0 })) : null,
    intune: d.intuneOk ? (d.intune || []).map((x) => ({ name: x.name, upn: x.upn, os: x.os, compliance: x.compliance, last_sync: x.lastSync || null })) : null };
}

function register(api, deps) {
  const P = prefixOf(deps);
  const hoursOf = (ctx) => body(ctx.query || {}).int('hours', { min: 1, max: 720, def: 168 }).done().hours;

  api.route('GET', `${P}/audit/evidence/ad`, wrap(deps, 'analyst', (ctx) => {
    const r = adEvidence(deps.identity);
    audit(ctx, 'audit.evidence.read', 'ad', { users: r.users ? r.users.length : 0 });
    return r;
  }));
  api.route('GET', `${P}/audit/evidence/network`, wrap(deps, 'analyst', (ctx) => {
    const r = networkEvidence(deps.netopsInstance);
    audit(ctx, 'audit.evidence.read', 'network', { devices: r.devices ? r.devices.length : 0 });
    return r;
  }));
  api.route('GET', `${P}/audit/evidence/network/config/:id`, wrap(deps, 'analyst', (ctx) => {
    const id = param(ctx.params.id, 'device');
    const N = deps.netopsInstance; if (!N || !N.configAudit) throw new HttpError(404, 'configuration capture is not running');
    const c = N.configAudit.get(id); if (!c || !c.text) throw new HttpError(404, 'no configuration captured for ' + id);
    audit(ctx, 'audit.evidence.read', 'config:' + id, { sha256: c.sha256 });
    return { id: c.id, name: c.name, vendor: c.vendor, at: iso(c.at), sha256: c.sha256, truncated: !!c.truncated, text: c.text };
  }));
  api.route('GET', `${P}/audit/evidence/platform`, wrap(deps, 'analyst', async (ctx) => {
    const r = await platformEvidence(deps);
    audit(ctx, 'audit.evidence.read', 'platform', {});
    return r;
  }));
  api.route('GET', `${P}/audit/evidence/m365`, wrap(deps, 'analyst', (ctx) => {
    const r = m365Evidence(deps.m365Graph);
    audit(ctx, 'audit.evidence.read', 'm365', { users: r.users ? r.users.length : 0 });
    return r;
  }));
  api.route('GET', `${P}/audit/evidence/database`, wrap(deps, 'analyst', async (ctx) => {
    const hours = hoursOf(ctx), R = deps.oracle_audit_report;
    if (!R) return { available: false, reason: 'Database Audit is not running on the SIEM' };
    const r = await R.report({ hours });
    audit(ctx, 'audit.evidence.read', 'database', { hours, events: r.total || 0 });
    return r;
  }));
  api.route('GET', `${P}/audit/evidence/applications`, wrap(deps, 'analyst', async (ctx) => {
    const hours = hoursOf(ctx), A = deps.appAuditInstance;
    if (!A) return { available: false, reason: 'Application Audit is not running on the SIEM (Server Availability groups)' };
    const l = await A.list();
    const apps = (l.applications || []).slice().sort((a, b) => (b.critical - a.critical) || a.name.localeCompare(b.name));
    const out = [];
    for (const a of apps.slice(0, MAX_APPS)) {
      try { out.push(await A.report({ app: a.key, hours })); }
      catch (e) { out.push({ application: { key: a.key, name: a.name, critical: !!a.critical }, error: String(e.message || e).slice(0, 200) }); }
    }
    audit(ctx, 'audit.evidence.read', 'applications', { hours, applications: out.length });
    return { available: true, hours, total: apps.length, read: out.length, applications: out };
  }));
}

module.exports = { register, adEvidence, networkEvidence, platformEvidence, m365Evidence, DAY };
