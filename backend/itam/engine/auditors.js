// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * The AI IT Auditor and the AI Cyber Security Auditor: two duty engineers (engine/duty-core.js) that audit the platform,
 * the departments AND the other AI engineers, independently of them. Third line of the three lines: the AI engineers and
 * their human approvers operate (first line), the GRC consultant advises (second), the auditors test.
 *
 * Each auditor runs an AUDIT PROGRAMME: a fixed list of control tests. A test reads records that already exist (audit trail,
 * approvals, the register, backup, patch, end of life, security testing, SIEM log flow, credential custody, the duty desks)
 * and answers pass / fail / not tested. A test whose source is not connected is NOT TESTED, never passed - and the
 * findings it raised earlier stay open (silence is not a clean audit). Every failed test raises findings with evidence,
 * the framework clauses (ISO/IEC 27001:2022 Annex A numbers; SAMA CSF and NCA ECC by domain) and the department that owns
 * the remediation. Findings become duty work items: the owning department fixes, the auditor re-tests and closes the item
 * only when the next test passes. A person may close a finding (risk accepted, false positive) with a reason, as for any
 * work item. The auditors are read-only: they propose nothing for execution and approve nothing.
 *
 * Infrastructure tests (IT-15/16, CY-16..20) read the SIEM's audit evidence (GET /api/soc/audit/evidence/{ad, network,
 * network/config/:id, database, applications}) as system:itam-auditor with role analyst - named accounts and activity are
 * personal data - and decide in Python (pyengine/infra_audit_rules.py: CIS benchmarks, SAMA CSF, NCA ECC, ISO 27001).
 *
 *   createAuditors(app, { now }) → { programme(id), run(id), adapters: { itaudit, cyberaudit }, DEPTS }
 *   GET  /audit-programme              viewer     both programmes: tests, state, counts (evidence for operators - PDPL)
 *   POST /audit-programme/run          operator   {auditor?} run now (a duty patrol), audited
 */
const fs = require('fs');
const SC = require('./approve-scopes');

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

const DAY = 86400000;
const s = (v, n = 160) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, n);
const lc = (v) => String(v == null ? '' : v).trim().toLowerCase();
const CLOSED = { disposed: 1, retired: 1, lost: 1, stolen: 1, archived: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

// the departments of the organisation chart; every test names the one that owns the remediation
const DEPTS = {
  infra: 'IT Infrastructure', apps: 'IT Applications', cyber: 'Cyber Security', grc: 'Governance, Risk & Compliance',
  audit: 'IT & Cyber Security Audit', platform: 'Platform administration',
};
const ISO = (n, t) => 'ISO/IEC 27001:2022 A.' + n + ' ' + t;

function createAuditors(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, A = () => app.addons || {};
  const last = {};                                     // auditor id → last run (memory; the findings live in the duty desk)
  let infraO = null;
  const infra = () => A().infraOverview || infraO || (infraO = require('./infra-overview').createInfraOverview(app));
  const col = (name) => store.collection(name);
  const notTested = (why) => ({ state: 'not_tested', detail: why, findings: [] });
  const result = (findings, passDetail, failDetail) => (findings.length ? { state: 'fail', detail: failDetail || findings.length + ' finding(s)', findings } : { state: 'pass', detail: passDetail, findings: [] });
  const list = (arr, n = 10) => arr.slice(0, n).join(', ') + (arr.length > n ? ' … +' + (arr.length - n) + ' more' : '');
  const ageH = (t) => { const v = typeof t === 'number' ? t : Date.parse(t || 0); return v ? (now() - v) / 3600000 : null; };
  let cisoCache = null;
  async function siem() {   // the SIEM side, read through the AI CISO's link (one read per patrol)
    const C = A().ciso; if (!C || typeof C.collect !== 'function') return null;
    if (cisoCache && now() - cisoCache.at < 60000) return cisoCache.S;
    const S = await C.collect(); cisoCache = { at: now(), S }; return S;
  }
  const siemData = (S, id) => (S && S[id] && S[id].state === 'live' ? S[id].data : null);

  // ---- infrastructure evidence (AD, network devices, databases, applications) straight from the SIEM's audit-evidence
  // route, read as the auditor (analyst: named accounts are personal data, viewers may not read them); the RULES are in
  // Python (pyengine/infra_audit_rules.py), the same "Python decides" pattern as the PDPL consultant.
  const AUDITOR = { user: 'system:itam-auditor', role: 'analyst' };
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const evCache = {};
  async function siemEvidence(path) {
    if (evCache[path] && now() - evCache[path].at < 60000) return evCache[path].v;
    let v;
    if (opts.siemEvidence) v = await opts.siemEvidence(path);
    else {
      const L = app.discovery && app.discovery.siem; if (!L || typeof L.call !== 'function') return null;
      const r = await L.call('GET', path, AUDITOR);
      if (!r || r.status === 404) return null;                                    // an older SIEM without the route
      if (r.status !== 200) throw httpErr(502, 'SIEM ' + path + ': HTTP ' + r.status + (r.json && r.json.error ? ' ' + s(r.json.error, 120) : ''));
      v = r.json;
    }
    evCache[path] = { at: now(), v }; return v;
  }
  async function rules(op, input) {
    const r = await py().call(op, Object.assign({ now: now() }, input));
    if (!r || r.ok === false) throw new Error('rules (' + op + '): ' + s(r && r.error, 200));
    return r;
  }
  const taken = () => 'Evidence taken ' + new Date(now()).toISOString() + ' by the AI auditors (read-only, as ' + AUDITOR.user + ')';
  // python result → test result: the basis (source, scope, criteria, what was not checked) goes on every finding
  function infraResult(r, basis, passDetail) {
    const b = basis.concat((r.scope || []).map((x) => 'Not checked: ' + x), [taken()]);
    for (const f of r.findings) f.basis = b;
    return result(r.findings, passDetail);
  }
  async function adEvidence() {
    const ev = await siemEvidence('/audit/evidence/ad');
    if (!ev) return { why: 'the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)' };
    if (!ev.available) return { why: ev.reason || 'AD identity not available' };
    return { ev, basis: ['Source: SIEM AD identity sync of ' + s(ev.domain || ev.server, 80) + ' (read-only LDAPS), last sync ' + s(ev.synced, 25) + '; ' + (ev.users || []).length + ' accounts, ' + (ev.groups || []).length + ' privileged groups'] };
  }
  async function netEvidence(vendors, withConfigs) {
    const ev = await siemEvidence('/audit/evidence/network');
    if (!ev) return { why: 'the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)' };
    if (!ev.available) return { why: ev.reason || 'network inventory not available' };
    const devs = (ev.devices || []).filter((d) => vendors.includes(d.vendor));
    const configs = {};
    if (withConfigs) for (const d of devs) {
      if (!d.config || !d.config.sha256 || !['cisco-ios', 'cisco-asa'].includes(d.vendor)) continue;
      try { const c = await siemEvidence('/audit/evidence/network/config/' + encodeURIComponent(d.id)); if (c && c.text) configs[d.id] = c.text; }
      catch (e) { if (app.log && app.log.every) app.log.every('auditors:config:' + d.id, 3600000, 'warn', 'configuration not readable for the audit', { device: d.id, err: s(e.message, 120) }); }
    }
    return { ev, devs, configs };
  }

  // ---------------------------------------------------------------- AI IT Auditor: IT general controls
  const IT = [
    { id: 'IT-01', area: 'Logging', title: 'The audit trail is complete and has not been altered', owner: 'platform',
      refs: [ISO('8.15', 'Logging'), 'SAMA CSF: event logging and monitoring', 'NCA ECC: cybersecurity event logs and monitoring'],
      async run() {
        if (typeof store.verifyAudit !== 'function') return notTested('the audit store cannot be verified here');
        let v = null; if (store.dir) { try { v = await require('./audit-verify').verifyInWorker(store.dir, 60000); } catch (e) { v = null; } }
        if (!v) v = store.verifyAudit();
        if (!v || !v.checked) return notTested('no audit records yet');
        return v.ok ? result([], v.checked + ' audit records, hash chain intact')
          : result([{ key: 'chain', severity: 'critical', title: 'Audit trail hash chain broken at ' + s(v.bad_at, 60), evidence: [s(v.reason, 120), v.checked + ' records verified before the break'],
            recommendation: 'Treat as a possible tampering incident: preserve the audit files, compare with the latest backup, and find who had write access to the data directory at that time.' }]);
      } },
    { id: 'IT-02', area: 'Change management', title: 'Approvals are made by a different, named person (four-eyes)', owner: 'audit',
      refs: [ISO('5.3', 'Segregation of duties'), ISO('8.32', 'Change management'), 'SAMA CSF: change management', 'NCA ECC: cybersecurity in change management'],
      run() {
        const F = [], machine = (u) => !SC.isHuman(u);
        const patches = col('desk_patch').all((p) => p.approved_by);
        for (const p of patches) {
          if (p.auto_approved) continue;   // the armed auto-approval: an administrator armed it (desksupport.js records who), by design
          if (lc(p.approved_by) === lc(p.requested_by)) F.push({ key: 'patch:' + p.id, severity: 'high', title: 'Patch install ' + s(p.id, 30) + ' approved by the person who requested it', evidence: ['requested and approved by ' + s(p.approved_by, 60), s(p.name, 80)], target: { type: 'desktop', id: p.resource_id, name: s(p.name, 80) } });
          else if (machine(p.approved_by)) F.push({ key: 'patch:' + p.id, severity: 'high', title: 'Patch install ' + s(p.id, 30) + ' approved by a service identity outside the armed auto-approval', evidence: ['approved by ' + s(p.approved_by, 60)], target: { type: 'desktop', id: p.resource_id, name: s(p.name, 80) } });
        }
        const plans = col('virt_changes').all();
        for (const p of plans) {
          const decided = p.state === 'approved' || p.state === 'applied' || p.state === 'validated';
          if (decided && !p.decided_by) F.push({ key: 'virt:' + p.id, severity: 'high', title: 'Virtualization change ' + s(p.id, 30) + ' is ' + p.state + ' without a recorded approver', evidence: ['requested by ' + s(p.requested_by, 60)] });
          else if (decided && lc(p.decided_by) === lc(p.requested_by)) F.push({ key: 'virt:' + p.id, severity: 'high', title: 'Virtualization change ' + s(p.id, 30) + ' approved by its requester', evidence: ['requested and approved by ' + s(p.decided_by, 60)] });
          else if (decided && machine(p.decided_by)) F.push({ key: 'virt:' + p.id, severity: 'high', title: 'Virtualization change ' + s(p.id, 30) + ' approved by a service / AI identity', evidence: ['approved by ' + s(p.decided_by, 60)] });
        }
        const n = patches.length + plans.filter((p) => p.decided_by).length;
        if (!n && !F.length) return notTested('no approval decided yet (patch installs, virtualization changes)');
        for (const f of F) f.recommendation = 'Confirm with the change owner whether the change was authorised; record a retrospective approval by a different named person, and find out how the control was bypassed.';
        return result(F, n + ' approval(s) checked: every one by a different, named person');
      } },
    { id: 'IT-03', area: 'Access & roles', title: 'Every AI engineer that proposes changes has a named human approver', owner: 'audit',
      refs: [ISO('5.2', 'Information security roles and responsibilities'), ISO('5.3', 'Segregation of duties'), 'SAMA CSF: roles and responsibilities'],
      run() {
        const R = app.roles; if (!R || typeof R.engineerApprovers !== 'function') return notTested('Roles & Functions is not installed');
        const E = R.engineerApprovers(), none = E.filter((e) => !e.people.length);
        return result(none.map((e) => ({ key: e.scope, severity: 'medium', title: e.engineer + ': no named human approver (administrators only)', evidence: ['approves: ' + s(e.approves, 120)],
          recommendation: 'Roles & Functions: give the responsible human engineer\'s job role "' + e.engineer + '" (or the ' + e.group + ' group) under May approve, then assign the person.' })),
        E.length + ' AI engineers, each with a named approver');
      } },
    { id: 'IT-04', area: 'Asset management', title: 'The asset register is complete (serial numbers, owners)', owner: 'infra',
      refs: [ISO('5.9', 'Inventory of information and other associated assets'), 'SAMA CSF: asset management', 'NCA ECC: asset management'],
      run() {
        const live = col('assets').all((a) => !CLOSED[a.status]);
        if (!live.length) return notTested('the register is empty');
        const F = [], hw = live.filter((a) => /server|network|storage|firewall/.test(lc(a.type)) && !s(a.serial || a.serial_number));
        if (hw.length) F.push({ key: 'no-serial', severity: hw.length > 20 ? 'medium' : 'low', title: hw.length + ' server / network / storage asset(s) without a serial number', evidence: [list(hw.map((a) => s(a.name || a.asset_tag || a.id, 40)))],
          recommendation: 'Read the serials from the devices (Asset Discovery / CLI facts) or the vendor portal and record them; support, end of life and licensing depend on them.' });
        const ow = A().ownership ? A().ownership.summary() : null;
        if (ow && ow.assets && (ow.missing_it || ow.missing_business)) F.push({ key: 'owners', severity: ow.missing_business / ow.assets > 0.25 ? 'medium' : 'low', title: 'Assets without owners: ' + ow.missing_business + ' without a business owner, ' + ow.missing_it + ' without an IT owner', evidence: [ow.assets + ' active assets, ' + ow.both_pct + '% with both owners'],
          recommendation: 'Asset Ownership: assign the business and IT owner (or the business service, whose owners the assets inherit).' });
        return result(F, live.length + ' active assets: serials and owners recorded' + (ow ? '' : ' (ownership module not installed - owners not tested)'));
      } },
    { id: 'IT-05', area: 'Backup', title: 'Servers are backed up and the last backup succeeded', owner: 'infra',
      refs: [ISO('8.13', 'Information backup'), 'SAMA CSF: backup and recovery', 'NCA ECC: backup and recovery management'],
      run() {
        const b = infra().view('operator').backup; if (!b || !b.available) return notTested(b ? b.why : 'backup status not readable');
        // the evidence an auditor needs: every server named, the sources read (and when), the matching method, and the
        // backups that matched no server (a server registered under another name is not "unprotected")
        const B = A().backup, v = B && typeof B.view === 'function' ? B.view() : null, rows = v ? v.assets || [] : [];
        const plats = v ? v.platforms || [] : [], um = v ? v.unmatched || [] : [], vs = (v && v.summary) || {}, hours = ((v && v.settings) || {}).target_hours || 24;
        const basis = v ? [
          'Source: Backup Status, ' + plats.length + ' platform(s) read - ' + plats.map((p) => p.label + ' (' + p.kind + '; last sync ' + (p.last_sync ? s(p.last_sync.at, 25) + (p.last_sync.ok ? ', ok, ' + (p.last_sync.objects || 0) + ' objects' : ', FAILED: ' + s(p.last_sync.error, 80)) : 'never') + ')').join('; '),
          'Scope: every server and VM in the asset register that is not disposed or retired (' + (rows.length || vs.assets || 0) + '), less approved exemptions (' + (vs.exempt || 0) + ')',
          'Method: a server counts as backed up when a backup object matches it by name, short name, host name, asset tag, management IP or VM UUID, and its last successful backup is within ' + hours + ' hours',
          (vs.objects || 0) + ' backup object(s) read; ' + um.length + ' matched no server in the register' + (um.length ? ' (for example: ' + um.slice(0, 8).map((o) => s(o.vm_name || o.name, 40)).join(', ') + ') - check these before concluding a server has no backup' : ''),
          'Evidence taken ' + new Date(now()).toISOString() + ' by the AI IT Auditor (read-only)',
        ] : [];
        const cols = ['Server', 'Management IP', 'Site', 'OS', 'Type', 'Status', 'Last successful backup', 'Last attempt', 'Result', 'Platforms', 'Jobs'];
        const item = (r) => [r.name, r.mgmt_ip, r.site, r.os, r.type, r.status, r.last_success || '', r.last_attempt || '', r.last_result || '', (r.platforms || []).join(' | '), (r.jobs || []).join(' | ')];
        const ev = (st) => ({ basis, columns: cols, items: rows.filter((r) => r.status === st).map(item) });
        const unmatched = um.length ? { columns: ['Backup object', 'VM name', 'Platform', 'Job', 'VM cluster'], items: um.slice(0, 2000).map((o) => [o.name, o.vm_name || '', o.platform || '', o.job || '', o.vm_cluster || '']) } : null;
        const F = [];
        if (b.failed) F.push(Object.assign({ key: 'failed', severity: 'high', title: b.failed + ' server(s) whose last backup failed', evidence: [b.protected_pct + '% of servers protected', 'full list: ' + b.failed + ' server(s) in the evidence annex'], recommendation: 'Backup Status: fix the failed jobs and confirm a successful backup and a test restore.' }, ev('failed')));
        if (b.none) F.push(Object.assign({ key: 'none', severity: 'high', title: b.none + ' server(s) with no backup at all', evidence: [b.assets + ' servers in scope, ' + b.exempt + ' exempt', 'full list: ' + b.none + ' server(s) in the evidence annex', um.length ? um.length + ' backup object(s) matched no server - reconcile them first' : 'every backup object matched a server'], recommendation: 'Add the servers to a backup job, or record an approved exemption with the reason. First reconcile the backup objects that matched no server: a server registered under another name is backed up.' }, ev('none'), { counter: unmatched }));
        if (b.stale) F.push(Object.assign({ key: 'stale', severity: 'medium', title: b.stale + ' server(s) whose last good backup is too old', evidence: ['full list: ' + b.stale + ' server(s) in the evidence annex'], recommendation: 'Check the schedule and the job history on the backup platform.' }, ev('stale')));
        return result(F, b.protected + ' of ' + (b.assets - b.exempt) + ' servers protected, none failed');
      } },
    { id: 'IT-06', area: 'Patch management', title: 'Critical patches are installed on computers', owner: 'infra',
      refs: [ISO('8.8', 'Management of technical vulnerabilities'), ISO('8.19', 'Installation of software on operational systems'), 'SAMA CSF: patch management', 'NCA ECC: patch management'],
      run() {
        const p = infra().view('operator').patch; if (!p || !p.available) return notTested(p ? p.why : 'patch status not readable');
        return result(p.critical_missing ? [{ key: 'critical', severity: p.critical_missing > 10 ? 'high' : 'medium', title: p.critical_missing + ' computer(s) missing critical patches', evidence: [p.compliant_pct + '% of ' + p.reported + ' reporting computers fully patched', list(p.worst.map((w) => w.name + ' (' + w.critical + ' critical)'), 8)],
          recommendation: 'The AI Desktop Support Engineer requests the installs; a different person approves them in Endpoint Central. Check why these computers fall behind (offline, failed deployments).' }] : [],
        p.compliant + ' of ' + p.reported + ' computers fully patched, none missing a critical patch');
      } },
    { id: 'IT-07', area: 'Suppliers', title: 'Support contracts are current for the assets that need them', owner: 'infra',
      refs: [ISO('5.20', 'Addressing information security within supplier agreements'), ISO('5.22', 'Monitoring of supplier services'), 'SAMA CSF: third-party management'],
      run() {
        const c = infra().view('admin').contracts; if (!c || !c.available) return notTested(c ? c.why : 'support contracts not readable');
        const F = [];
        if (c.expired) F.push({ key: 'expired', severity: 'medium', title: c.expired + ' support contract(s) expired', evidence: [list(c.renewing.filter((x) => x.state === 'expired').map((x) => x.vendor + ' ' + x.product), 6)], recommendation: 'Renew, or record that the assets are retired / supported otherwise.' });
        if (c.uncovered_assets) F.push({ key: 'uncovered', severity: 'low', title: c.uncovered_assets + ' asset(s) not covered by any support contract', evidence: [], recommendation: 'Support Contracts: link the assets to their contract, or record why none is needed.' });
        return result(F, c.contracts + ' contract(s), none expired');
      } },
    { id: 'IT-08', area: 'Governance', title: 'Policies are reviewed within their review cycle', owner: 'grc',
      refs: [ISO('5.1', 'Policies for information security'), 'SAMA CSF: cyber security policy', 'NCA ECC: cybersecurity policies and procedures'],
      run() {
        const G = A().grc; if (!G || typeof G.summary !== 'function') return notTested('GRC policy register not installed');
        const g = G.summary(); if (!g || !g.total) return notTested('no policy in the register');
        const od = (g.reviews && g.reviews.overdue) || 0;
        return result(od ? [{ key: 'overdue', severity: od > 5 ? 'high' : 'medium', title: od + ' of ' + g.total + ' policies past their review date', evidence: [(g.reviews.soon || 0) + ' more due within 90 days'],
          recommendation: 'Policy owners review and re-approve them (GRC Policies); an administrator approves the new version.' }] : [], g.total + ' policies, all within their review cycle');
      } },
    { id: 'IT-09', area: 'Business continuity', title: 'DR / BCM drills are run on time, pass and are signed off', owner: 'infra',
      refs: [ISO('5.30', 'ICT readiness for business continuity'), ISO('5.29', 'Information security during disruption'), 'SAMA CSF: business continuity management', 'NCA ECC: cybersecurity resilience aspects of BCM'],
      run() {
        const G = A().grc; if (!G || typeof G.drillSummary !== 'function') return notTested('DR & BCM Drills not installed');
        const d = G.drillSummary(); if (!d || !d.systems || !d.systems.total) return notTested('no system registered for DR drills');
        const F = [];
        if (d.systems.overdue) F.push({ key: 'overdue', severity: 'high', title: d.systems.overdue + ' of ' + d.systems.total + ' critical system(s) overdue for a DR drill', evidence: [d.systems.tested + ' tested'], recommendation: 'Schedule and run the drills (DR & BCM Drills); record RTO / RPO achieved.' });
        if (d.by_result && d.by_result.fail) F.push({ key: 'failed', severity: 'high', title: d.by_result.fail + ' drill(s) failed', evidence: ['RTO met ' + (d.rto.pct == null ? 'not measured' : d.rto.pct + '%') + ', RPO met ' + (d.rpo.pct == null ? 'not measured' : d.rpo.pct + '%')], recommendation: 'Fix the cause and re-run the drill until it passes.' });
        if (d.awaiting_signoff) F.push({ key: 'signoff', severity: 'medium', title: d.awaiting_signoff + ' completed drill(s) not signed off', evidence: [], recommendation: 'A second administrator who did not run the drill signs it off.' });
        return result(F, d.systems.total + ' system(s): drills on time, passed and signed off');
      } },
    { id: 'IT-10', area: 'Software licensing', title: ('Licensed software is within what ' + ZYB_ORG.short + ' owns (Oracle)'), owner: 'apps',
      refs: [ISO('5.32', 'Intellectual property rights'), 'SAMA CSF: asset management'],
      run() {
        const O = A().oracleLicences; if (!O || typeof O.compliance !== 'function') return notTested('Oracle Licences not installed');
        const c = O.compliance(); if (!c || !(c.matrix || []).some((m) => m.level !== 'not_used')) return notTested('no Oracle installation or entitlement recorded (every product "not used")');
        const F = c.matrix.filter((m) => m.level === 'over' || m.level === 'near' || m.level === 'incomplete').map((m) => ({ key: s(m.product + ':' + (m.edition || ''), 80), severity: m.level === 'over' ? 'high' : m.level === 'near' ? 'medium' : 'low',
          title: s(m.name, 60) + ': ' + (m.level === 'over' ? 'over-utilised - needs ' + m.required + ', owns ' + m.owned : m.level === 'near' ? 'at risk - ' + m.utilisation_pct + '% of licences used' : 'incomplete - entitlement or installation data missing'),
          evidence: ['metric ' + s(m.metric, 40), 'owned ' + m.owned + ', required ' + m.required],
          recommendation: m.level === 'over' ? 'Buy the difference or reduce the processors / users; an Oracle LMS audit would find this.' : m.level === 'near' ? 'Plan the purchase before the next expansion.' : 'Record the entitlement and the installation facts (Oracle Licences).' }));
        return result(F, c.matrix.length + ' Oracle product(s): all within entitlement (' + s(c.verdict_label, 40) + ')');
      } },
    { id: 'IT-11', area: 'Asset management', title: 'The register matches what is really on the network', owner: 'infra',
      refs: [ISO('5.9', 'Inventory of information and other associated assets'), ISO('5.11', 'Return of assets'), 'SAMA CSF: asset management'],
      run() {
        const R = A().reconcile; if (!R || typeof R.view !== 'function') return notTested('Server & Asset Reconciliation not installed');
        const rep = R.view().report; if (!rep || !Array.isArray(rep.issues)) return notTested('no reconciliation run yet (Reconcile → Sync all)');
        const open = rep.issues.filter((i) => !i.accepted), K = { retired_alive: ['high', 'retired / disposed in the register but still seen on the network'], not_in_inventory: ['medium', 'on the network but not in the register'], duplicate: ['low', 'recorded twice in the register'], ad_disabled: ['low', 'in use in the register but disabled in Active Directory'] };
        const F = Object.keys(K).map((k) => { const L = open.filter((i) => i.kind === k); return L.length ? { key: k, severity: K[k][0], title: L.length + ' asset(s) ' + K[k][1], evidence: [list(L.map((i) => s(i.name || i.ip, 40)))],
          recommendation: k === 'retired_alive' ? 'Find out why a retired device is still on the network: switch it off, or correct its status.' : k === 'not_in_inventory' ? 'Register them (Asset Discovery → approve) or record why they are excluded.' : 'Correct the register (Reconcile shows each one).' } : null; }).filter(Boolean);
        return result(F, rep.issues.length + ' reconciliation item(s) checked, none of audit significance');
      } },
    { id: 'IT-12', area: 'People', title: 'Leavers hand over their work and access before they go', owner: 'grc',
      refs: [ISO('5.11', 'Return of assets'), ISO('6.5', 'Responsibilities after termination or change of employment'), ISO('5.18', 'Access rights'), 'SAMA CSF: human resource security'],
      run() {
        const H = A().handover; if (!H || typeof H.list !== 'function') return notTested('Staff Handover not installed');
        const L = H.list(); if (!L.length) return notTested('no leaver handover recorded');
        const today = new Date(now()).toISOString().slice(0, 10);
        const late = L.filter((h) => h.state !== 'signed-off' && h.state !== 'cancelled' && h.last_day && String(h.last_day).slice(0, 10) < today);
        return result(late.map((h) => ({ key: s(h.id, 40), severity: h.blockers ? 'high' : 'medium', title: s(h.leaver_name || h.leaver, 60) + ' left on ' + s(h.last_day, 10) + ' - handover ' + (h.progress == null ? 'open' : h.progress + '% done') + (h.blockers ? ', ' + h.blockers + ' blocker(s)' : ''),
          evidence: ['team ' + s(h.team, 30), 'manager ' + s(h.manager, 60)], recommendation: 'Revoke the remaining access, collect the assets and have the manager sign the handover off.' })), L.length + ' handover(s): none past the last day without sign-off');
      } },
    { id: 'IT-13', area: 'Equipment', title: 'Servers, network and storage are under warranty or support', owner: 'infra',
      refs: [ISO('7.13', 'Equipment maintenance'), 'SAMA CSF: asset management'],
      run() {
        const today = new Date(now()).toISOString().slice(0, 10);
        const hw = col('assets').all((a) => !CLOSED[a.status] && /server|network|storage|firewall/.test(lc(a.type)));
        const known = hw.filter((a) => a.warranty && a.warranty.end); if (!known.length) return notTested(hw.length ? 'no warranty end date recorded on any device' : 'no server / network / storage device in the register');
        const exp = known.filter((a) => a.warranty.end < today);
        return result(exp.length ? [{ key: 'expired', severity: exp.length > 10 ? 'medium' : 'low', title: exp.length + ' device(s) out of warranty', evidence: [list(exp.map((a) => s(a.name || a.asset_tag, 30) + ' (' + a.warranty.end + ')'))], recommendation: 'Renew support or plan replacement; confirm the contract on Support Contracts.' }] : [],
          known.length + ' device(s) with a warranty date, all current' + (known.length < hw.length ? ' (' + (hw.length - known.length) + ' without a date)' : ''));
      } },
    { id: 'IT-14', area: 'Capacity', title: 'Storage is healthy and has room to grow', owner: 'infra',
      refs: [ISO('8.6', 'Capacity management'), ISO('8.14', 'Redundancy of information processing facilities')],
      run() {
        const st = infra().view('operator').storage; if (!st || !st.available) return notTested(st ? st.why : 'storage not readable');
        const F = [];
        if (st.failed_disks) F.push({ key: 'disks', severity: 'high', title: st.failed_disks + ' failed disk(s) in the storage arrays', evidence: [list((st.list || []).filter((x) => x.failed_disks).map((x) => x.name + ' (' + x.failed_disks + ')'))], recommendation: 'Replace the disks now: the array is running without its full redundancy.' });
        const full = (st.list || []).filter((x) => x.used_pct != null && x.used_pct >= 85);
        if (full.length) F.push({ key: 'full', severity: full.some((x) => x.used_pct >= 95) ? 'high' : 'medium', title: full.length + ' array(s) at 85% or more used', evidence: [list(full.map((x) => x.name + ' ' + x.used_pct + '%'))], recommendation: 'Plan the expansion or archive; keep the capacity plan current.' });
        return result(F, st.read + ' array(s): no failed disk, under 85% used');
      } },
    { id: 'IT-15', area: 'Databases', title: 'Databases audit who does what, and privileged use is controlled', owner: 'apps',
      refs: [ISO('8.15', 'Logging'), ISO('8.2', 'Privileged access rights'), ISO('8.9', 'Configuration management'), 'CIS Oracle Database 19c Benchmark (auditing, privileges)', 'SAMA CSF 3.3.14 event logging; 3.3.5 identity and access management', 'NCA ECC 2-12 event logs; 2-2 identity and access'],
      async run() {
        const r0 = await siemEvidence('/audit/evidence/database?hours=720');
        if (!r0) return notTested('the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)');
        if (!r0.available) return notTested(r0.reason || 'Database Audit not available');
        const r = await rules('infra_audit.database', { report: r0 }), sm = r0.summary || {};
        return infraResult(r, ['Source: SIEM Database Audit over the last 30 days - ' + (sm.events || 0) + ' audit record(s) from ' + (sm.databases || 0) + ' database(s); ' + (r0.posture || []).length + ' database(s) reported their audit configuration' + (r0.capped ? ' (row cap reached: the period is partly read)' : ''),
          'Criteria: unified auditing on with the ORA_LOGON_FAILURES / ORA_SECURECONFIG / ORA_ACCOUNT_MGMT policies, no audit tampering, privileged actions matched to changes, every monitored database sending its trail'],
        (sm.databases || 0) + ' database(s): audit trail and configuration as expected');
      } },
    { id: 'IT-16', area: 'Applications', title: 'Business applications are resilient, changed under control and logged', owner: 'apps',
      refs: [ISO('8.14', 'Redundancy of information processing facilities'), ISO('8.32', 'Change management'), ISO('8.15', 'Logging'), 'SAMA CSF: business continuity; change management; 3.3.14 event logging', 'NCA ECC 2-12 event logs'],
      async run() {
        const r0 = await siemEvidence('/audit/evidence/applications?hours=720');
        if (!r0) return notTested('the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)');
        if (!r0.available) return notTested(r0.reason || 'Application Audit not available');
        if (!(r0.applications || []).length) return notTested('no application defined (Server Availability → group servers into applications)');
        const r = await rules('infra_audit.applications', { report: r0 });
        return infraResult(r, ['Source: SIEM Application Audit (Server Availability groups) over the last 30 days - ' + r0.read + ' of ' + r0.total + ' application(s), critical ones first',
          'Criteria: no single point of failure for a critical application, changes approved by a different named person and validated, every server sending logs'],
        r.checked + ' application(s): resilience, changes and logging as expected');
      } },
    { id: 'IT-17', area: 'Logging', title: 'Security logs are kept for the required period', owner: 'cyber',
      refs: [ISO('8.15', 'Logging'), 'SAMA CSF 3.3.14 event management (log retention)', 'NCA ECC 2-12-3 log retention (at least 12 months)'],
      async run() {
        const p = await siemEvidence('/audit/evidence/platform');
        if (!p) return notTested('the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)');
        const r = await rules('infra_audit.retention', { platform: p });
        if (r.not_read) return notTested(r.scope[0]);
        for (const f of r.findings) if (!f.items) { f.columns = ['Setting', 'Value', 'Required']; f.items = r.rows; }
        return infraResult(r, ['Source: SIEM configuration (retention_days, archive_retention_days) and the oldest active partition of the event store', 'Criterion: retention at least the required ' + (p.required_retention_days || 365) + ' days'],
          'SIEM keeps events ' + p.retention_days + ' days (required ' + (p.required_retention_days || 365) + ')');
      } },
    { id: 'IT-18', area: 'Business continuity', title: 'DR replication meets its RPO and every workload has a DR copy', owner: 'infra',
      refs: [ISO('8.14', 'Redundancy of information processing facilities'), ISO('5.30', 'ICT readiness for business continuity'), 'SAMA Business Continuity Management Framework (RPO / RTO)', 'NCA ECC 3-1 cybersecurity resilience'],
      async run() {
        if (!app.duty) return notTested('the duty desk is not running');
        const e = (app.duty.engineers() || []).find((x) => x.id === 'virt');
        const items = app.duty.list({ engineer: 'virt', status: 'open', limit: 1000 }).items || [];
        const r = await rules('infra_audit.dr', { engineer: e || null, items });
        if (r.not_read) return notTested(r.scope[0]);
        return infraResult(r, ['Source: the AI Virtualization Administrator\'s DR patrol (Nutanix protection domains / Leap: RPO, remote copy, schedules, stuck replication, remote sites), last patrol ' + (e.last_patrol ? new Date(e.last_patrol).toISOString() : 'never'),
          'Criteria: every protection domain replicated within its RPO, every production VM protected, remote sites healthy'], 'DR replication within RPO; no unprotected workload reported');
      } },
    { id: 'IT-19', area: 'Audit', title: 'Evidence requested by the auditors is provided on time', owner: 'audit',
      refs: [ISO('5.35', 'Independent review of information security'), 'SAMA CSF 3.2.5 cyber security audits', 'NCA ECC 1-8 periodical review and audit'],
      run() {
        const CL = A().auditChecklist; if (!CL || typeof CL.requests !== 'function') return notTested('the audit checklist is not installed');
        const seen = new Map(); for (const fw of ['sama', 'nca', 'ia']) for (const x of CL.requests(fw, true).items) if (!seen.has(x.id)) seen.set(x.id, x);
        const all = [...seen.values()], issued = all.filter((x) => x.state !== 'not_issued');
        if (!issued.length) return notTested('no evidence request issued yet (AI Auditors → Checklist → Evidence requests → Issue)');
        const late = all.filter((x) => x.overdue);
        const cols = ['Request', 'Check', 'Owner', 'Due', 'Days overdue', 'Evidence expected'];
        const byOwner = {}; for (const x of late) (byOwner[x.owner] = byOwner[x.owner] || []).push(x);
        const F = Object.entries(byOwner).map(([o, xs]) => ({ key: 'overdue:' + o, severity: xs.some((x) => x.days_overdue > 14) ? 'high' : 'medium',
          title: (DEPTS[o] || xs[0].owner_name || o) + ': ' + xs.length + ' evidence request(s) overdue', evidence: xs.slice(0, 5).map((x) => x.ref + ' due ' + x.due + ' (' + x.days_overdue + ' days)'),
          recommendation: 'Provide the evidence reference for each request (Checklist → Evidence requests → Respond), or agree a new due date with the auditor.',
          basis: ['Source: the evidence request list (PBC) of the audit checklist - ' + issued.length + ' request(s) issued, ' + all.filter((x) => x.state === 'accepted').length + ' accepted', 'Criterion: every issued request answered by its due date', taken()],
          columns: cols, items: xs.map((x) => [x.ref, x.title, x.owner_name, x.due, x.days_overdue, x.evidence_expected]) }));
        return result(F, issued.length + ' request(s) issued, none overdue');
      } },
  ];

  // ---------------------------------------------------------------- AI Cyber Security Auditor
  const CY = [
    { id: 'CY-01', area: 'Vulnerability management', title: 'End-of-life systems are isolated or have an approved exception', owner: 'cyber',
      refs: [ISO('8.8', 'Management of technical vulnerabilities'), 'SAMA CSF: vulnerability management', 'NCA ECC: vulnerabilities management'],
      run() {
        const L = A().lifecycle; if (!L) return notTested('End of Life is not installed');
        const v = L.view({}), items = (v.items || []).filter((i) => i.isolation_required);
        if (!(v.items || []).length) return notTested('no end-of-life data yet');
        return result(items.slice(0, 50).map((i) => ({ key: 'eol:' + s(i.id || i.asset_id || i.name, 80), severity: /server|vm|firewall|network/.test(lc(i.type)) ? 'high' : 'medium',
          title: s(i.name || i.hostname || i.serial, 60) + ': ' + s(i.product, 60) + ' is past end of life and not isolated', evidence: ['end of life ' + (i.eol || '?'), s(i.type, 30)],
          recommendation: 'Request isolation (CISO approves) or an exception with a compensating control and an end date; plan the replacement.' })),
        (v.summary.eol || 0) + ' end-of-life system(s), all isolated or excepted');
      } },
    { id: 'CY-02', area: 'Security testing', title: 'Penetration tests and VAPT are done on time (critical quarterly, others twice a year)', owner: 'cyber',
      refs: [ISO('8.8', 'Management of technical vulnerabilities'), ISO('5.35', 'Independent review of information security'), 'SAMA CSF: penetration testing', 'NCA ECC: penetration testing'],
      run() {
        const P = A().pentest, Cd = P && P.cadence; if (!Cd || typeof Cd.schedule !== 'function') return notTested('the security testing schedule is not installed');
        const sch = Cd.schedule(); if (!sch.rows.length) return notTested('no asset in the testing scope');
        const F = [];
        for (const tier of ['critical', 'standard']) for (const st of ['overdue', 'never']) {
          const R = sch.rows.filter((r) => r.tier === tier && r.worst === st); if (!R.length) continue;
          F.push({ key: tier + ':' + st, severity: tier === 'critical' ? 'high' : 'medium', title: R.length + ' ' + tier + ' asset(s) ' + (st === 'never' ? 'never tested' : 'overdue for a test'),
            evidence: [list(R.map((r) => s(r.asset, 40)))], recommendation: 'Plan an engagement (two administrators authorise it) and record the test with the tester and the report reference.' });
        }
        return result(F, sch.rows.length + ' asset(s) in scope, all tested within the policy');
      } },
    { id: 'CY-03', area: 'Remediation', title: 'Serious problems found by the AI engineers are fixed within the SLA', owner: 'cyber',
      refs: [ISO('8.8', 'Management of technical vulnerabilities'), ISO('5.26', 'Response to information security incidents'), 'SAMA CSF: vulnerability management'],
      async run() {
        const SLA = { critical: 24, high: 72 }, late = [];
        const take = (items, side) => { for (const it of items || []) { const h = ageH(it.detected_at || it.first_seen); if (SLA[it.severity] && h != null && h > SLA[it.severity] * 7) late.push({ it, side, h }); } };
        const D = app.duty; if (D) take(D.list({ status: 'open', limit: 1000 }).items.filter((x) => x.engineer !== 'itaudit' && x.engineer !== 'cyberaudit'), 'IT Asset Management');
        let S = null; try { S = await siem(); } catch (e) { S = null; }
        const sd = siemData(S, 'siem_duty'); if (sd) take(sd.items, 'SIEM');
        if (!D && !sd) return notTested('no duty desk readable');
        return result(late.slice(0, 40).map((x) => ({ key: 'late:' + x.it.id, severity: x.it.severity === 'critical' ? 'high' : 'medium',
          title: (x.it.engineer_name || x.it.engineer) + ': ' + s(x.it.title, 90) + ' - open ' + Math.round(x.h / 24) + ' days', evidence: [x.side + ' work item ' + x.it.id, 'status ' + x.it.status, 'SLA ' + SLA[x.it.severity] + ' h, audited at 7× the SLA'],
          recommendation: 'The owning department to fix, or close with a recorded risk acceptance; the auditor re-tests.' })),
        'no critical / high work item open longer than 7× its SLA' + (sd ? '' : ' (IT Asset Management only - SIEM not linked)'));
      } },
    { id: 'CY-04', area: 'Change management', title: 'Proposals waiting for a human decision are decided in time', owner: 'audit',
      refs: [ISO('8.32', 'Change management'), 'SAMA CSF: change management'],
      async run() {
        const F = [];
        for (const p of col('desk_patch').all((x) => x.state === 'requested')) { const h = ageH(p.requested_at); if (h > 72) F.push({ key: 'patch:' + p.id, severity: 'low', title: 'Patch install ' + s(p.id, 30) + ' waiting ' + Math.round(h / 24) + ' days for approval', evidence: ['requested by ' + s(p.requested_by, 60), s(p.name, 60)] }); }
        for (const p of col('virt_changes').all((x) => x.state === 'proposed')) { const h = ageH(p.requested_at); if (h > 72) F.push({ key: 'virt:' + p.id, severity: 'low', title: 'Virtualization change ' + s(p.id, 30) + ' waiting ' + Math.round(h / 24) + ' days for approval', evidence: ['requested by ' + s(p.requested_by, 60)] }); }
        let S = null; try { S = await siem(); } catch (e) { S = null; }
        const ap = siemData(S, 'approvals');
        if (ap) for (const a of ap) { const h = ageH(a.requested_at); if (h > 24) F.push({ key: 'soc:' + a.id, severity: 'medium', title: 'SOC response action ' + s(a.id, 30) + ' (' + s(a.action || a.kind || a.title, 40) + ') waiting ' + Math.round(h) + ' h', evidence: ['case ' + s(a.case_id, 30), 'requested by ' + s(a.requested_by, 60)] }); }
        for (const f of F) f.recommendation = 'The named approver decides (approve or reject with a reason); a stale proposal is either still needed or should be rejected.';
        return result(F, 'no proposal waiting longer than its window (patch / change 72 h, SOC response 24 h)' + (ap ? '' : ' - SOC approvals not readable (SIEM not linked)'));
      } },
    { id: 'CY-05', area: 'Monitoring', title: 'The assets that must send logs to the SIEM are sending them', owner: 'cyber',
      refs: [ISO('8.16', 'Monitoring activities'), ISO('8.15', 'Logging'), 'SAMA CSF: security event monitoring', 'NCA ECC: cybersecurity event logs and monitoring'],
      async run() {
        let S = null; try { S = await siem(); } catch (e) { S = null; }
        const lf = siemData(S, 'logflow'); if (!lf || !lf.summary) return notTested('log-flow assurance not readable (SIEM link)');
        const m = lf.summary, F = [];
        if (lf.collector && lf.collector.quiet) F.push({ key: 'collector', severity: 'critical', title: 'The SIEM collector has received nothing for more than 15 minutes', evidence: ['last event ' + (lf.collector.last_event ? new Date(lf.collector.last_event).toISOString() : 'never')], recommendation: 'Check the collector service and the network path to it first: every source is affected.' });
        if (m.silent) F.push({ key: 'silent', severity: 'high', title: m.silent + ' asset(s) stopped sending logs', evidence: ['coverage ' + (m.coverage_pct == null ? 'not measurable' : m.coverage_pct + '%')], recommendation: 'Log Assurance lists them; the AI SIEM Engineer has a work item per asset.' });
        if (m['not-onboarded']) F.push({ key: 'not-onboarded', severity: 'medium', title: m['not-onboarded'] + ' asset(s) required to send logs were never onboarded', evidence: [m.required + ' required'], recommendation: 'Onboard them (Log Assurance → Onboard), or record why they are out of scope.' });
        return result(F, (m.covered || 0) + ' of ' + (m.required || 0) + ' required assets sending logs (' + m.coverage_pct + '%)');
      } },
    { id: 'CY-06', area: 'Cryptography', title: 'Stored credentials are sealed and the key is in custody', owner: 'platform',
      refs: [ISO('8.24', 'Use of cryptography'), ISO('5.17', 'Authentication information'), 'SAMA CSF: cryptography', 'NCA ECC: cryptography'],
      run() {
        const C = A().credPosture; if (!C || typeof C.build !== 'function') return notTested('the credential evidence is not installed (add-cred-security.sh)');
        const b = C.build(false), F = (b.findings || []).filter((f) => f.sev === 'critical' || f.sev === 'high' || f.sev === 'medium');
        return result(F.slice(0, 20).map((f, i) => ({ key: s(f.area, 40) + ':' + i + ':' + s(f.text, 40), severity: f.sev, title: s(f.area, 40) + ': ' + s(f.text, 140), evidence: [(b.summary.sealed || 0) + ' of ' + (b.summary.stored || 0) + ' stored credentials sealed'],
          recommendation: s(f.fix, 300) })), (b.summary.sealed || 0) + ' of ' + (b.summary.stored || 0) + ' stored credentials sealed, key custody correct');
      } },
    { id: 'CY-07', area: 'Security operations', title: 'Every AI engineer is on duty and patrolling', owner: 'audit',
      refs: [ISO('8.16', 'Monitoring activities'), ISO('5.36', 'Compliance with policies, rules and standards for information security')],
      async run() {
        const E = [];
        if (app.duty) for (const e of app.duty.engineers()) E.push(Object.assign({ side: 'IT Asset Management' }, e));
        let S = null; try { S = await siem(); } catch (e) { S = null; }
        const sd = siemData(S, 'siem_duty'); if (sd) for (const e of sd.engineers || []) E.push(Object.assign({ side: 'SIEM' }, e));
        if (!E.length) return notTested('no duty desk readable');
        const bad = E.filter((e) => e.id !== 'itaudit' && e.id !== 'cyberaudit' && (!e.on_duty || e.last_error || e.late));
        return result(bad.map((e) => ({ key: e.side + ':' + e.id, severity: !e.on_duty ? 'medium' : 'low', title: e.name + ': ' + (!e.on_duty ? 'off duty' : e.last_error ? 'last patrol failed' : 'patrol late'),
          evidence: [e.side, e.last_error ? s(e.last_error, 160) : 'last patrol ' + (e.last_patrol ? new Date(e.last_patrol).toISOString() : 'never')],
          recommendation: !e.on_duty ? 'AI Engineering Team → Duty policy: switch the engineer back on, or record why its area is not watched.' : 'Fix the problem named in the engineer\'s readiness card; the next patrol retries.' })),
        E.length + ' AI engineers on duty and patrolling' + (sd ? '' : ' (IT Asset Management only - SIEM not linked)'));
      } },
    { id: 'CY-08', area: 'Compliance', title: 'SAMA Cyber Security Framework controls are covered', owner: 'grc',
      refs: ['SAMA CSF: all domains', ISO('5.36', 'Compliance with policies, rules and standards for information security')],
      async run() {
        let S = null; try { S = await siem(); } catch (e) { S = null; }
        const sm = siemData(S, 'sama'); if (!sm || !sm.summary || sm.summary.coverage_pct == null) return notTested('SAMA CSF coverage not readable (SIEM link)');
        const gaps = (sm.controls || []).filter((c) => c.status === 'gap');
        return result(gaps.slice(0, 30).map((c) => ({ key: s(c.id, 30), severity: 'high', title: 'SAMA CSF ' + s(c.id, 20) + ' ' + s(c.title, 100) + ': no evidence of the control', evidence: ['coverage ' + sm.summary.coverage_pct + '% overall'],
          recommendation: 'Connect the source that evidences it, or record the manual evidence on SAMA Compliance.' })), 'SAMA CSF coverage ' + sm.summary.coverage_pct + '%, no control without evidence');
      } },
    { id: 'CY-09', area: 'Incident response', title: 'Critical security alerts are handled within the SLA', owner: 'cyber',
      refs: [ISO('5.25', 'Assessment and decision on information security events'), ISO('5.26', 'Response to information security incidents'), 'SAMA CSF: cyber security incident management', 'NCA ECC: cybersecurity incident and threat management'],
      async run() {
        let S = null; try { S = await siem(); } catch (e) { S = null; }
        const m = siemData(S, 'soc'); if (!m) return notTested('SOC metrics not readable (SIEM link)');
        const o = m.open_by_severity || {}, crit = Number(o[4] || 0), br = ((m.sla || {}).breaching_now || []);
        const F = [];
        if (br.length) F.push({ key: 'sla', severity: 'high', title: br.length + ' security case(s) breaching the response SLA now', evidence: [list(br.map((x) => s(x.id || x.case_id || x.title, 40)), 8)], recommendation: 'SOC lead assigns and works them; record the reason for each breach.' });
        if (crit) F.push({ key: 'critical', severity: 'high', title: crit + ' critical alert(s) open', evidence: ['high open: ' + Number(o[3] || 0)], recommendation: 'Triage within the hour; close with the outcome or escalate to an incident.' });
        return result(F, 'no critical alert open and no case breaching its SLA');
      } },
    { id: 'CY-10', area: 'Network security', title: 'Nothing critical is exposed to the internet', owner: 'cyber',
      refs: [ISO('8.20', 'Networks security'), ISO('8.22', 'Segregation of networks'), 'SAMA CSF: network security', 'NCA ECC: network security management'],
      run() {
        const P = A().pentest; if (!P || typeof P.assessment !== 'function') return notTested('attack-surface assessment not installed');
        const a = P.assessment(); if (!a.summary || !a.summary.assets) return notTested('no discovered asset to assess');
        const ex = a.findings.filter((f) => f.internet && (f.severity === 'critical' || f.severity === 'high'));
        return result(ex.slice(0, 30).map((f) => ({ key: s(f.id, 80), severity: f.severity, title: s(f.asset, 50) + ': ' + s(f.title, 120) + ' (internet-facing)', evidence: [s(f.evidence, 200)],
          recommendation: s(f.fix || 'Close the exposure at the firewall or put it behind the VPN / ZTNA.', 300) })), (a.summary.internet_facing || 0) + ' internet-facing asset(s), none with a critical / high exposure');
      } },
    { id: 'CY-11', area: 'Asset visibility', title: 'Every device sending logs is a known asset', owner: 'cyber',
      refs: [ISO('5.9', 'Inventory of information and other associated assets'), ISO('8.16', 'Monitoring activities')],
      async run() {
        let S = null; try { S = await siem(); } catch (e) { S = null; }
        const lf = siemData(S, 'logflow'); if (!lf || lf.unknown_senders == null) return notTested('log-flow assurance not readable (SIEM link)');
        const n = Number(lf.unknown_senders) || 0;
        return result(n ? [{ key: 'unknown', severity: n > 10 ? 'medium' : 'low', title: n + ' device(s) send logs to the SIEM but are not in the asset register', evidence: ['Log Assurance → Unknown senders lists them'], recommendation: 'Identify each one: register it, or find out why an unknown device is on the network (shadow IT).' }] : [],
          'every log sender is a known asset');
      } },
    { id: 'CY-12', area: 'Trusted connections', title: 'Device identities the platform trusts have not changed', owner: 'platform',
      refs: [ISO('8.21', 'Security of network services'), ISO('8.24', 'Use of cryptography')],
      run() {
        const C = A().credPosture; if (!C || typeof C.build !== 'function') return notTested('the credential evidence is not installed');
        const t = (C.build(false).transport || {}).trust; if (!t) return notTested('no trusted device identity recorded');
        const ch = (t.ssh.changed || 0) + (t.tls.changed || 0), pend = (t.ssh.pending || 0) + (t.tls.pending || 0), F = [];
        if (ch) F.push({ key: 'changed', severity: 'high', title: ch + ' device identity(ies) changed since they were trusted (SSH host key / TLS certificate)', evidence: ['SSH changed ' + t.ssh.changed + ', TLS changed ' + t.tls.changed], recommendation: 'Confirm each change with the device owner before trusting it again: an unexpected change can mean someone is intercepting the connection.' });
        if (pend) F.push({ key: 'pending', severity: 'low', title: pend + ' device identity(ies) waiting to be trusted', evidence: [], recommendation: 'An administrator compares the fingerprint with the device and trusts it (logins are not sent until then).' });
        return result(F, (t.ssh.trusted + t.tls.trusted) + ' trusted identities, none changed');
      } },
    { id: 'CY-13', area: 'Secrets', title: 'No stored secret has leaked into a file on the server', owner: 'platform',
      refs: [ISO('5.17', 'Authentication information'), ISO('8.12', 'Data leakage prevention')],
      run() {
        const C = A().credPosture; if (!C || typeof C.build !== 'function') return notTested('the credential evidence is not installed');
        const ls = C.build(false).last_scan; if (!ls) return notTested('no secret-leak scan run yet (Credential Security → Scan, admin)');
        const F = [];
        if ((ls.hits || []).length) F.push({ key: 'hits', severity: 'critical', title: ls.hits.length + ' stored secret(s) found in clear text in server files', evidence: (ls.hits || []).slice(0, 8).map((h) => s(h.file, 120) + ' - ' + s(h.secret, 60)), recommendation: 'Remove the files or the values, rotate those secrets at once, and find which process wrote them.' });
        const age = ageH(ls.at); if (age != null && age > 30 * 24) F.push({ key: 'stale', severity: 'low', title: 'Last secret-leak scan ' + Math.round(age / 24) + ' days ago', evidence: [], recommendation: 'Run the scan at least monthly.' });
        return result(F, 'last scan ' + new Date(Date.parse(ls.at)).toISOString().slice(0, 10) + ': ' + ls.secrets_checked + ' secret(s) checked in ' + ls.files + ' file(s), none found');
      } },
    { id: 'CY-14', area: 'Domains & certificates', title: 'Domains and TLS certificates are valid, and hosting stays in the Kingdom', owner: 'cyber',
      refs: [ISO('8.24', 'Use of cryptography'), 'PDPL: transfer of personal data outside the Kingdom', 'SAMA CSF: cryptography'],
      run() {
        const Dm = A().domains; if (!Dm || typeof Dm.view !== 'function') return notTested('Domains & Hosting not installed');
        const v = Dm.view('admin'), m = v.summary || {}; if (!m.domains && !m.hosts) return notTested('no domain or host recorded');
        const F = [];
        if (m.expired) F.push({ key: 'expired', severity: 'critical', title: m.expired + ' domain(s) expired', evidence: [], recommendation: 'Renew at once: an expired domain can be registered by someone else.' });
        if (m.certs_30) F.push({ key: 'certs', severity: 'high', title: m.certs_30 + ' TLS certificate(s) expired or expiring within 30 days', evidence: [], recommendation: 'Renew and install the certificates.' });
        if (m.expiring_90) F.push({ key: 'expiring', severity: 'medium', title: m.expiring_90 + ' domain(s) expiring within 90 days', evidence: [], recommendation: 'Renew (auto-renew where the registrar offers it).' });
        if (m.outside_ksa) F.push({ key: 'outside', severity: 'medium', title: m.outside_ksa + ' site(s) hosted outside the Kingdom', evidence: [], recommendation: 'Confirm no personal data is processed there, or record the PDPL transfer basis and risk assessment.' });
        return result(F, (m.domains || 0) + ' domain(s), ' + (m.hosts || 0) + ' host(s): valid, certificates current, hosted in the Kingdom');
      } },
    { id: 'CY-15', area: 'Endpoint protection', title: 'Computers report to endpoint management', owner: 'infra',
      refs: [ISO('8.1', 'User endpoint devices'), ISO('8.7', 'Protection against malware'), 'SAMA CSF: endpoint protection'],
      run() {
        const Dk = A().deskSupport; if (!Dk || typeof Dk.desktops !== 'function') return notTested('Desktop Support not installed');
        const it = Dk.desktops().items || []; if (!it.length) return notTested('Endpoint Central has not reported any computer');
        const down = it.filter((d) => d.live === 'down'), pct = Math.round(down.length / it.length * 100);
        return result(pct >= 10 ? [{ key: 'silent', severity: pct >= 25 ? 'high' : 'medium', title: down.length + ' of ' + it.length + ' computers (' + pct + '%) not reporting to Endpoint Central', evidence: [list(down.map((d) => s(d.name, 30)))],
          recommendation: 'A silent agent means no patches and no visibility: check the machines are in use and re-install the agent.' }] : [], it.length + ' computers, ' + (100 - pct) + '% reporting');
      } },
    { id: 'CY-16', area: 'Active Directory', title: 'Privileged AD access is limited, named and in use', owner: 'infra',
      refs: [ISO('8.2', 'Privileged access rights'), ISO('5.15', 'Access control'), 'CIS Microsoft Windows Server Benchmark / Microsoft AD tiering (Enterprise / Schema Admins empty)', 'SAMA CSF 3.3.5 identity and access management (privileged access)', 'NCA ECC 2-2-3 privileged access'],
      async run() {
        const e = await adEvidence(); if (!e.ev) return notTested(e.why);
        const r = await rules('infra_audit.ad_privileged', { evidence: e.ev });
        return infraResult(r, e.basis.concat(['Scope: members of the privileged groups (Domain / Enterprise / Schema Admins, Administrators, Account / Server / Backup Operators and the groups configured on the SIEM), through any nesting',
          'Criteria: Enterprise Admins empty, Schema Admins empty, Domain Admins at most 5; no privileged account that is dormant, a service account, never expires, never signed in, or has a password older than 365 days']),
        r.summary.privileged_enabled + ' enabled privileged account(s), none outside the criteria');
      } },
    { id: 'CY-17', area: 'Active Directory', title: 'AD accounts are reviewed and Kerberos weaknesses are closed', owner: 'infra',
      refs: [ISO('5.16', 'Identity management'), ISO('5.18', 'Access rights'), ISO('8.5', 'Secure authentication'), 'CIS Microsoft Windows Server Benchmark (Kerberos, account hygiene)', 'SAMA CSF 3.3.5 identity and access management', 'NCA ECC 2-2 identity and access management'],
      async run() {
        const e = await adEvidence(); if (!e.ev) return notTested(e.why);
        const r = await rules('infra_audit.ad_accounts', { evidence: e.ev });
        return infraResult(r, e.basis.concat(['Scope: every enabled account in the domain',
          'Criteria: no account without Kerberos pre-authentication, with PASSWD_NOTREQD or with unconstrained delegation; no account unused for ' + (e.ev.dormant_days || 90) + ' days; people\'s passwords expire; krbtgt reset at least every 180 days']),
        r.summary.enabled + ' enabled account(s), none outside the criteria');
      } },
    { id: 'CY-18', area: 'Active Directory', title: 'The domain password and lockout policy meets the benchmark', owner: 'infra',
      refs: [ISO('5.17', 'Authentication information'), ISO('8.5', 'Secure authentication'), 'CIS Microsoft Windows Server Benchmark 1.1 password policy, 1.2 account lockout', 'SAMA CSF 3.3.5 identity and access management', 'NCA ECC 2-2-3'],
      async run() {
        const e = await adEvidence(); if (!e.ev) return notTested(e.why);
        const r = await rules('infra_audit.ad_policy', { evidence: e.ev });
        if (r.not_read) return notTested(r.scope[0]);
        return infraResult(r, e.basis.concat(['Source: the Default Domain Policy values on the domain head (minPwdLength, pwdHistoryLength, maxPwdAge, minPwdAge, pwdProperties, lockoutThreshold, lockoutDuration, lockOutObservationWindow)',
          'Criteria: CIS level 1 - length 14+, history 24+, maximum age 1-365 days, minimum age 1+, complexity on, reversible encryption off, lockout after 1-5 failures for 15+ minutes']),
        'every domain password and lockout setting meets the benchmark');
      } },
    { id: 'CY-19', area: 'Network devices', title: 'Cisco switches are hardened (CIS Cisco IOS benchmark)', owner: 'infra',
      refs: [ISO('8.9', 'Configuration management'), ISO('8.20', 'Networks security'), ISO('8.5', 'Secure authentication'), 'CIS Cisco IOS Benchmark level 1 (management plane, AAA, SSH, SNMP, logging, NTP)', 'SAMA CSF: network security; secure configuration and hardening', 'NCA ECC 2-3 secure configuration; 2-5 network security'],
      async run() {
        const e = await netEvidence(['cisco-ios'], true); if (!e.ev) return notTested(e.why);
        if (!e.devs.length) return notTested('no Cisco IOS switch in the SIEM network inventory (Network Engineer → Devices)');
        const r = await rules('infra_audit.switches', { devices: e.devs, configs: e.configs });
        if (!r.checked) return notTested('no Cisco switch configuration could be read yet (' + e.devs.length + ' switch(es): a read-only SSH login and a trusted host key are needed - Network Engineer → Devices → SSH)');
        return infraResult(r, ['Source: SIEM network inventory - ' + e.devs.length + ' Cisco IOS device(s); running-config of ' + r.checked + ' read over the read-only SSH helper (show running-config, secrets removed on the SIEM) in the last day, plus the SIEM\'s TCP probes (Telnet / HTTP) and monitoring credentials',
          'Criteria: CIS Cisco IOS level 1 - password-encryption, enable secret type 8/9, no enable password, AAA with TACACS+/RADIUS, SSH v2 only on vty with access-class and a 10-minute timeout, no HTTP server, no RW / unrestricted SNMP, syslog to the SIEM with timestamps, NTP, login banner, no source routing'],
        r.checked + ' Cisco switch(es) meet the hardening criteria');
      } },
    { id: 'CY-20', area: 'Network security', title: 'Firewall rule bases and management access meet the standard', owner: 'cyber',
      refs: [ISO('8.20', 'Networks security'), ISO('8.22', 'Segregation of networks'), ISO('8.15', 'Logging'), 'CIS Palo Alto / FortiGate / Cisco ASA benchmarks (rule base, management access, logging)', 'SAMA CSF: network security; 3.3.14 event logging', 'NCA ECC 2-5 network security management'],
      async run() {
        const e = await netEvidence(['fortigate', 'paloalto', 'cisco-asa'], true); if (!e.ev) return notTested(e.why);
        if (!e.devs.length) return notTested('no firewall in the SIEM network inventory (Network Engineer → Devices)');
        const r = await rules('infra_audit.firewalls', { devices: e.devs, configs: e.configs });
        const byV = {}; for (const d of e.devs) byV[d.vendor] = (byV[d.vendor] || 0) + 1;
        return infraResult(r, ['Source: SIEM network inventory and its read-only security checks - ' + Object.entries(byV).map(([v, n]) => n + ' ' + v).join(', ') + ' (Palo Alto: edge / external, branch and data-centre connectivity; FortiGate: second layer for users)',
          'Criteria: no any-any or internet-to-any allow rule, logging on every allow rule, no clear-text or internet-facing administration, trusted hosts for administrators, current security subscriptions, rule base readable by the auditor, checks run in the last 48 hours'],
        e.devs.length + ' firewall(s): rule base and management access meet the criteria');
      } },
    { id: 'CY-21', area: 'People', title: 'Leavers\' accounts are disabled on their last day and not used afterwards', owner: 'infra',
      refs: [ISO('6.5', 'Responsibilities after termination'), ISO('5.18', 'Access rights'), 'SAMA CSF 3.3.1 human resources (leavers); 3.3.5 identity and access management', 'NCA ECC 1-9-5 / 2-2'],
      async run() {
        const H = A().handover; if (!H || typeof H.list !== 'function') return notTested('Staff Handover not installed');
        const L = H.list(); if (!L.length) return notTested('no leaver recorded in Staff Handover');
        const e = await adEvidence(); if (!e.ev) return notTested(e.why);
        const r = await rules('infra_audit.leavers', { handovers: L.map((h) => ({ leaver: h.leaver, leaver_name: h.leaver_name, team: h.team, last_day: h.last_day, state: h.state })), evidence: e.ev });
        return infraResult(r, e.basis.concat(['Scope: the IT and cyber security leavers recorded in Staff Handover (' + L.length + '); the HR leaver list for all staff is requested on the evidence request list (PBC)',
          'Criteria: the AD account is disabled by the day after the last working day, and no sign-in after it']), r.checked + ' leaver(s): accounts disabled, no sign-in after leaving');
      } },
    { id: 'CY-22', area: 'Active Directory', title: 'No shared, generic or built-in account is used, and admins have separate accounts', owner: 'infra',
      refs: [ISO('5.16', 'Identity management'), ISO('8.2', 'Privileged access rights'), 'CIS Microsoft Windows Server 2.3.1 (Guest disabled, Administrator renamed)', 'SAMA CSF 3.3.5 identity and access management', 'NCA ECC 2-2-3'],
      async run() {
        const e = await adEvidence(); if (!e.ev) return notTested(e.why);
        const r = await rules('infra_audit.ad_generic', { evidence: e.ev });
        return infraResult(r, e.basis.concat(['Criteria: built-in Guest (RID 501) disabled; built-in Administrator (RID 500) renamed and not used day to day; no enabled generic / shared / test account; privileged accounts have no mailbox']),
          'no shared, generic or built-in account in use');
      } },
    { id: 'CY-23', area: 'Change management', title: 'Network device configurations change only through an approved change', owner: 'infra',
      refs: [ISO('8.32', 'Change management'), ISO('8.9', 'Configuration management'), 'SAMA CSF 3.3.7 change management', 'NCA ECC 1-6 / 2-3'],
      async run() {
        const e = await netEvidence(['cisco-ios', 'cisco-asa'], false); if (!e.ev) return notTested(e.why);
        const r = await rules('infra_audit.config_changes', { devices: e.devs, days: 90 });
        if (!r.checked) return notTested(r.scope[0]);
        return infraResult(r, ['Source: the SIEM\'s daily running-config capture of ' + r.checked + ' Cisco device(s) (SHA-256 of the configuration without volatile lines) and the Network Engineer change plans',
          'Criterion: every configuration change in the last 90 days falls in the window of a change plan that was approved by a named person and applied on that device'],
          r.checked + ' device(s): every configuration change matched to an approved change plan');
      } },
    { id: 'CY-24', area: 'Identity (cloud)', title: 'Microsoft 365 sign-in is protected by MFA and Conditional Access', owner: 'infra',
      refs: [ISO('8.5', 'Secure authentication'), 'CIS Microsoft 365 Foundations 1.1 / 5.2 (MFA, Conditional Access)', 'SAMA CSF 3.3.5 (multi-factor authentication)', 'NCA ECC 2-2-3'],
      async run() {
        const m = await siemEvidence('/audit/evidence/m365');
        if (!m) return notTested('the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)');
        if (!m.available) return notTested(m.reason || 'Microsoft 365 not available');
        const r = await rules('infra_audit.m365_mfa', { m365: m });
        if (r.not_read) return notTested(r.scope.join('; '));
        return infraResult(r, ['Source: Microsoft Graph as synced by the SIEM (' + s(m.updated, 25) + '): authentication-method registration, Conditional Access policies, Entra ID Protection risky users',
          'Criteria: every administrator and at least 98% of users have MFA registered; at least one Conditional Access policy enabled; no medium / high risk user left open'], 'MFA registered, Conditional Access enabled, no open risky user');
      } },
    { id: 'CY-25', area: 'Identity (cloud)', title: 'Guest and unused Microsoft 365 accounts are reviewed and removed', owner: 'infra',
      refs: [ISO('5.18', 'Access rights'), ISO('5.19', 'Information security in supplier relationships'), 'SAMA CSF 3.3.5; 3.4.1 third parties', 'NCA ECC 2-2 / 4-1'],
      async run() {
        const m = await siemEvidence('/audit/evidence/m365');
        if (!m) return notTested('the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)');
        if (!m.available) return notTested(m.reason || 'Microsoft 365 not available');
        const r = await rules('infra_audit.m365_accounts', { m365: m });
        if (r.not_read) return notTested(r.scope[0]);
        return infraResult(r, ['Source: Microsoft Graph users with sign-in activity, as synced by the SIEM (' + s(m.updated, 25) + ')', 'Criteria: no enabled guest or licensed user unused for 90 days'], r.checked + ' account(s): none unused for 90 days');
      } },
    { id: 'CY-26', area: 'Endpoint protection', title: 'Laptops and mobiles comply with the device policy (Intune)', owner: 'infra',
      refs: [ISO('8.1', 'User endpoint devices'), ISO('8.24', 'Use of cryptography'), 'SAMA CSF 3.3.10 BYOD / mobile devices; 3.3.8 infrastructure security', 'NCA ECC 2-6 mobile devices'],
      async run() {
        const m = await siemEvidence('/audit/evidence/m365');
        if (!m) return notTested('the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)');
        if (!m.available) return notTested(m.reason || 'Microsoft 365 not available');
        const r = await rules('infra_audit.intune', { m365: m });
        if (r.not_read) return notTested(r.scope[0]);
        if (!r.checked) return notTested('no device enrolled in Intune');
        return infraResult(r, ['Source: Intune managed devices (compliance state, last check-in) from Microsoft Graph, as synced by the SIEM', 'Criteria: every device compliant with the policy (encryption, OS, password, Defender); every device checks in within 30 days'],
          r.checked + ' device(s), all compliant');
      } },
  ];

  const AUD = {
    itaudit: { id: 'itaudit', name: 'AI IT Auditor', tests: IT, about: 'IT general controls: audit trail, segregation of duties, approvers, asset register and reconciliation, backup, patching, suppliers, policies, DR drills, licensing, leavers, warranty, storage capacity, database auditing, application resilience and change control, log retention, DR replication' },
    cyberaudit: { id: 'cyberaudit', name: 'AI Cyber Security Auditor', tests: CY, about: 'Cyber security controls: end of life, security testing, remediation SLA, approvals in time, SIEM log coverage, credential custody, AI engineers on duty, SAMA CSF coverage, incident SLA, internet exposure, unknown devices, trusted identities, secret leaks, domains and certificates, endpoint agents, Active Directory (privileged access, accounts, password policy), Cisco switch hardening, firewall rule bases, leavers, shared and built-in accounts, unauthorised changes, Microsoft 365 MFA / guests / device compliance' },
  };

  async function run(id) {
    const a = AUD[id]; if (!a) throw httpErr(400, 'auditor: itaudit or cyberaudit');
    cisoCache = null; for (const k of Object.keys(evCache)) delete evCache[k];
    const out = [];
    for (const t of a.tests) {
      let r;
      try { r = await t.run(); } catch (e) {
        r = { state: 'not_tested', detail: 'could not be read: ' + s(e.message, 200), findings: [] };
        if (app.log && app.log.every) app.log.every('auditors:' + t.id, 600000, 'warn', 'audit test could not run', { test: t.id, err: s(e.message, 200) });
      }
      for (const f of r.findings) {
        if (Array.isArray(f.items)) { f.items = f.items.slice(0, 5000).map((row) => row.map((c) => s(c, 200))); f.columns = (f.columns || []).map((c) => s(c, 60)); f.basis = (f.basis || []).map((x) => s(x, 1200)).slice(0, 12);
          f.evidence_digest = 'sha256:' + require('node:crypto').createHash('sha256').update(JSON.stringify({ basis: f.basis, columns: f.columns, items: f.items, counter: f.counter || null })).digest('hex'); f.taken_at = new Date(now()).toISOString(); }
        f.key = t.id + ':' + s(f.key, 120); f.kind = t.id; f.title = s(f.title, 200); f.evidence = (f.evidence || []).filter(Boolean).map((x) => s(x, 300)); f.recommendation = s(f.recommendation, 400); f.target = f.target || { type: 'control', id: t.id, name: t.title }; f.site = DEPTS[t.owner]; }
      out.push({ id: t.id, area: t.area, title: t.title, refs: t.refs, owner: t.owner, owner_name: DEPTS[t.owner], state: r.state, detail: s(r.detail, 300), findings: r.findings });
    }
    last[id] = { at: now(), tests: out };
    return last[id];
  }

  // duty adapter: findings = every failed test's findings; a test NOT TESTED keeps its earlier findings open (re-emitted)
  function adapter(id) {
    const a = AUD[id];
    return {
      id, name: a.name,
      async findings() {
        const r = await run(id);
        if (!r.tests.some((t) => t.state !== 'not_tested')) return null;                // nothing could be tested: not connected
        const F = [];
        for (const t of r.tests) {
          if (t.state !== 'not_tested') { F.push(...t.findings.map((f) => { const o = Object.assign({}, f); delete o.items; delete o.columns; delete o.basis; delete o.counter; return o; })); continue; }
          const open = app.duty ? app.duty.list({ engineer: id, status: 'open', limit: 1000 }).items.filter((x) => String(x.key).indexOf(t.id + ':') === 0) : [];
          for (const x of open) F.push({ key: x.key, severity: x.severity, kind: x.kind, title: x.title, evidence: (x.evidence || []).concat(['not re-tested this time: ' + t.detail]).slice(0, 8), recommendation: x.recommendation, target: x.target, site: x.site });
        }
        return F;
      },
      investigate(it) {
        const t = a.tests.find((x) => String(it.key).indexOf(x.id + ':') === 0), lr = last[id] && last[id].tests.find((x) => t && x.id === t.id);
        if (!t) return { summary: 'The audit test is no longer in the programme.', checks: [], causes: [] };
        return { summary: t.id + ' ' + t.title + ' - owned by ' + DEPTS[t.owner] + '.',
          checks: [{ name: 'Test result', status: lr && lr.state === 'pass' ? 'ok' : lr && lr.state === 'fail' ? 'fail' : 'warn', detail: lr ? lr.state + ': ' + lr.detail : 'not run yet' },
            { name: 'Criteria', status: 'ok', detail: t.refs.join(' · ') }],
          causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
      },
      async verify(it) {
        const t = a.tests.find((x) => String(it.key).indexOf(x.id + ':') === 0); if (!t) return { present: false, note: 'test removed from the programme' };
        let r; try { r = await t.run(); } catch (e) { return { present: null, note: 'could not re-test: ' + s(e.message, 120) }; }
        if (r.state === 'not_tested') return { present: null, note: 'not re-tested: ' + r.detail };
        const present = r.findings.some((f) => t.id + ':' + s(f.key, 120) === it.key);
        return { present, note: present ? 'the re-test still finds it' : 'the re-test no longer finds it' };
      },
    };
  }

  function programme(id, withEvidence) {
    const a = AUD[id], r = last[id];
    const tests = a.tests.map((t) => { const x = r && r.tests.find((y) => y.id === t.id);
      return { id: t.id, area: t.area, title: t.title, refs: t.refs, owner: t.owner, owner_name: DEPTS[t.owner], state: x ? x.state : 'not_run', detail: x ? x.detail : 'not run yet', findings: x ? x.findings.length : 0,
        items: withEvidence && x ? x.findings.map((f) => ({ key: f.key, severity: f.severity, title: f.title, evidence: f.evidence, recommendation: f.recommendation, basis: f.basis, evidence_rows: f.items ? f.items.length : undefined, evidence_digest: f.evidence_digest })) : undefined }; });
    const c = { pass: 0, fail: 0, not_tested: 0, not_run: 0 }; for (const t of tests) c[t.state]++;
    const tested = c.pass + c.fail;
    return { id, name: a.name, about: a.about, last_run: r ? r.at : null, counts: c, tested, pass_pct: tested ? Math.round(c.pass / tested * 100) : null, tests };
  }

  // ---- the audit report: opinion, scope, criteria, findings (condition / criteria / effect / recommendation / owner /
  // status), limitations (what could not be tested), management response and sign-off. Built from the last run.
  const EFFECT = { critical: ('Exposes ' + ZYB_ORG.short + ' to an immediate risk of compromise, data loss or regulatory breach.'), high: 'A key control is not operating; a material risk until fixed.', medium: 'The control operates with gaps that weaken it.', low: 'A minor weakness or a hygiene matter.' };
  const SEVN = { critical: 4, high: 3, medium: 2, low: 1 };
  function opinionOf(p, F) {
    const n = p.tests.length, tested = p.counts.pass + p.counts.fail;
    if (!tested || tested < n / 2) return { rating: 'Unable to conclude', tone: 'grey', why: tested + ' of ' + n + ' controls could be tested - too little evidence for an opinion. Connect the sources listed under Limitations.' };
    const sev = (k) => F.filter((f) => f.severity === k).length;
    if (sev('critical')) return { rating: 'Ineffective', tone: 'red', why: sev('critical') + ' critical finding(s): key controls are not operating.' };
    if (sev('high')) return { rating: 'Needs improvement', tone: 'orange', why: sev('high') + ' high finding(s) need management action.' };
    if (F.length) return { rating: 'Effective with exceptions', tone: 'yellow', why: 'Controls operate; ' + F.length + ' medium / low exception(s).' };
    return { rating: 'Effective', tone: 'green', why: 'Every tested control operated as designed.' };
  }
  // the full evidence of one finding from the last run (the rows behind its count), for the report annex and the CSV
  function rawFinding(aid, key) { const r = last[aid]; if (!r) return null; for (const t of r.tests) for (const f of t.findings) if (f.key === key) return f; return null; }
  function evidence(key) {
    const aid = ['itaudit', 'cyberaudit'].find((x) => rawFinding(x, key));
    if (!aid) throw httpErr(404, 'no finding ' + s(key, 80) + ' in the last audit run - run the audit again');
    const f = rawFinding(aid, key);
    return { key, auditor: aid, title: f.title, severity: f.severity, basis: f.basis || [], columns: f.columns || [], rows: f.items || [], digest: f.evidence_digest || null, taken_at: f.taken_at || null,
      counter: f.counter ? { title: 'Backup objects that matched no server in the register', columns: f.counter.columns, rows: f.counter.items } : null,
      note: f.items ? 'The rows behind the finding, as the auditor read them; the digest is the SHA-256 of this evidence at the time of the test.' : 'This finding carries its evidence in the condition text only.' };
  }
  function reportOf(id) {
    const ids = id === 'all' ? ['itaudit', 'cyberaudit'] : [id];
    if (!ids.every((x) => AUD[x])) throw httpErr(400, 'auditor: itaudit, cyberaudit or all');
    const sections = ids.map((aid) => {
      const p = programme(aid, true), r = last[aid];
      const items = app.duty ? app.duty.list({ engineer: aid, limit: 2000 }).items : [];
      const F = []; let n = 0;
      for (const t of p.tests) for (const f of (t.items || [])) {
        const it = items.find((x) => x.key === f.key);
        const raw = rawFinding(aid, f.key) || {};
        F.push({ ref: (aid === 'itaudit' ? 'ITA-' : 'CSA-') + String(++n).padStart(2, '0'), test: t.id, area: t.area, severity: f.severity, title: f.title, condition: f.evidence, criteria: t.refs, effect: EFFECT[f.severity] || '',
          recommendation: f.recommendation, owner: t.owner_name, status: it ? it.status : 'new', since: it ? new Date(it.first_seen || it.detected_at).toISOString() : null, assignee: it ? it.owner || null : null, work_item: it ? it.id : null,
          key: f.key, basis: raw.basis || [], evidence: raw.items ? { columns: raw.columns, rows: raw.items, count: raw.items.length, digest: raw.evidence_digest, taken_at: raw.taken_at } : null,
          counter: raw.counter ? { columns: raw.counter.columns, rows: raw.counter.items, count: raw.counter.items.length } : null });
      }
      F.sort((a, b) => (SEVN[b.severity] || 0) - (SEVN[a.severity] || 0));
      const sev = { critical: 0, high: 0, medium: 0, low: 0 }; for (const f of F) sev[f.severity] = (sev[f.severity] || 0) + 1;
      return { auditor: aid, name: p.name, run_at: r ? new Date(r.at).toISOString() : null, opinion: opinionOf(p, F), counts: p.counts, pass_pct: p.pass_pct, by_severity: sev,
        scope: p.about, programme: p.tests.map((t) => ({ id: t.id, area: t.area, title: t.title, owner: t.owner_name, result: t.state, detail: t.detail, findings: t.findings })),
        criteria: [...new Set(p.tests.flatMap((t) => t.refs))], findings: F,
        limitations: p.tests.filter((t) => t.state === 'not_tested' || t.state === 'not_run').map((t) => ({ id: t.id, title: t.title, why: t.detail })) };
    });
    const out = { title: id === 'all' ? 'IT and Cyber Security Audit Report' : sections[0].name + ' — Audit Report', organisation: ZYB_ORG.name, generated_at: new Date(now()).toISOString(),
      basis: 'Automated, continuous testing of the platform\'s own records by read-only AI auditors. Evidence is what the connected systems report; a control without evidence is not tested and is never counted as effective. Findings are indicators for management review, not a certification.',
      sections, signoff: { prepared_by: 'AI auditors (automated, read-only)', reviewed_by: null, review_note: 'To be reviewed and signed by the Head of IT & Cyber Security Audit before it is issued.' } };
    out.digest = 'sha256:' + require('node:crypto').createHash('sha256').update(JSON.stringify(out)).digest('hex');
    return out;
  }

  // the network devices the audit is about (name, vendor, site, role, IP and whether the audit could read each one) - no
  // credentials and no configuration text; read by the Network Configuration Audit page (engine/netcfg-intel.js)
  async function network() {
    const ev = await siemEvidence('/audit/evidence/network');
    if (!ev) return { available: false, reason: 'the SIEM audit-evidence route is not reachable (update the SIEM, check the SIEM link)', devices: [] };
    if (!ev.available) return { available: false, reason: ev.reason || 'network inventory not available', devices: [] };
    const V = ['cisco-ios', 'cisco-asa', 'fortigate', 'paloalto'];
    return { available: true, devices: (ev.devices || []).filter((d) => V.includes(d.vendor)).slice(0, 2000).map((d) => ({ id: s(d.id, 80), name: s(d.name, 80), vendor: d.vendor, site: s(d.site, 60), role: s(d.role, 40), ip: s(d.ip, 45),
      has_config: !!(d.config && d.config.sha256), config_at: d.config && d.config.at ? s(d.config.at, 30) : null, config_error: d.config && d.config.error ? s(d.config.error, 160) : null, api: !!(d.monitoring && d.monitoring.api), security_at: d.security_at ? s(d.security_at, 30) : null })) };
  }

  return { run, programme, report: reportOf, evidence, network, adapters: { itaudit: adapter('itaudit'), cyberaudit: adapter('cyberaudit') }, DEPTS, AUD };
}

function registerAuditorRoutes(srv, app, AU) {
  const { body } = require('./check');
  const isOp = (ctx) => ctx.who && (ctx.who.role === 'operator' || ctx.who.role === 'admin');
  srv.route('GET', '/audit-programme', (ctx) => {
    ctx.need('viewer');
    return { departments: AU.DEPTS, auditors: ['itaudit', 'cyberaudit'].map((id) => AU.programme(id, isOp(ctx))),
      note: 'A test passes only on evidence; a source that is not connected is "not tested", never passed. Findings are work items on the duty desk: the owning department fixes, the auditor re-tests.' };
  });
  srv.route('GET', '/audit-programme/report', (ctx) => {
    ctx.need('operator');   // findings name people, devices and evidence (PDPL): operators and administrators
    const q = body((ctx.query || {})).oneOf('auditor', ['itaudit', 'cyberaudit', 'all'], { def: 'all' }).done();
    const r = AU.report(q.auditor);
    if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || '', action: 'audit.report.generate', target: q.auditor, detail: { digest: r.digest, opinions: r.sections.map((x) => x.auditor + ':' + x.opinion.rating) } });
    return r;
  });
  srv.route('GET', '/audit-programme/evidence', (ctx) => {
    ctx.need('operator');   // names servers, people and devices
    const q = body(ctx.query || {}).str('key', { required: true, max: 160, re: /^(IT|CY)-\d{2}:[A-Za-z0-9:._@-]+$/, msg: 'key must be an audit finding key (for example IT-05:none)' }).done();
    const ev = AU.evidence(q.key);
    if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || '', action: 'audit.evidence.view', target: q.key, detail: { rows: ev.rows.length, digest: ev.digest } });
    return ev;
  });
  srv.route('POST', '/audit-programme/run', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).oneOf('auditor', ['itaudit', 'cyberaudit'], {}).done();
    const ids = b.auditor ? [b.auditor] : ['itaudit', 'cyberaudit'], out = [];
    for (const id of ids) {
      if (app.duty) await app.duty.patrol(id); else await AU.run(id);
      out.push(AU.programme(id, true));
    }
    if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || '', action: 'audit.programme.run', target: ids.join(','), detail: { results: out.map((p) => ({ id: p.id, pass: p.counts.pass, fail: p.counts.fail, not_tested: p.counts.not_tested })) } });
    return { auditors: out };
  });
}

module.exports = { createAuditors, registerAuditorRoutes, DEPTS };
