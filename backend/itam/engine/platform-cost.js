// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Cost Optimisation - the platform scenarios (IT Assets -> Cost Optimisation, {P} = /api/itam). Where the virtual estate and the
 * platforms around it can cost less without weakening control, over the REAL collected estate:
 *   facts      hosts, clusters and VMs from the Virtualization collection (engine/virt-capacity.js: sockets, cores, CPU GHz,
 *              memory, CPU / memory IN USE as measured), SPARC / Solaris servers and backup software from the ITAM register
 *   prices     a licence recorded in the register for the platform (vendor VMware / Nutanix, annual cost) wins over a planning
 *              figure; every planning figure is an admin-editable ASSUMPTION with its note, never presented as a quote
 *   scenarios  R1 consolidate each cluster to what its MEASURED CPU and memory need at the target ceilings with N+1 (no usage
 *              measured = not computed, says so); R2 non-production VMs (word-bounded dev / uat / test / qa / staging names) off
 *              the commercial hypervisor; R3 production to Nutanix AHV where Nutanix already runs; R4 powered-off VMs to
 *              reclaim; R5 several backup platforms to one; R6 SPARC servers on support. Each: saving low-high, one-off, effort,
 *              risk, the evidence (measured vs assumed), the CISO view and the compliance impact
 *   cases      a business case per scenario: an operator proposes (a person), a DIFFERENT administrator approves or rejects with
 *              a reason (four-eyes; never the proposer, never a service / AI identity) - all audited. Approving records the
 *              decision; nothing here changes a host, a VM or a licence.
 *   GET  /platform-cost                         operator   (costs are not shown to viewers, like Cost Studio)
 *   POST /platform-cost/assumptions             admin      {key: number, ...} validated, versioned (baseVersion -> 409), audited
 *   POST /platform-cost/cases                   operator   {rec, note}
 *   POST /platform-cost/cases/:id/decide        admin      {decision approve|reject, reason}
 */
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000;
const r0 = (x) => Math.round(x / 1000) * 1000;
const NONPROD = /(^|[^a-z0-9])(dev|uat|test|tst|qa|stg|staging|preprod|pre-prod|sandbox|lab)([^a-z0-9]|$)/i;
// planning figures (SAR unless named) - an admin replaces them with contract prices; each has its note
const DEFAULTS = {
  usd_to_sar: [3.75, 'exchange rate'], eur_to_sar: [4.1, 'exchange rate'],
  vmware_per_core_usd: [190, 'VMware vSphere Foundation list price per core per year (planning figure)'],
  aos_per_core_usd: [140, 'Nutanix AOS (includes AHV) per core per year (planning figure - replace with the Nutanix quote)'],
  proxmox_per_socket_eur: [530, 'Proxmox VE Standard subscription per socket per year (list price)'],
  win_dc_per_16_cores_usd: [1600, 'Windows Server Datacenter SA per 16 cores per year (planning figure)'],
  host_run_sar: [9000, 'power, cooling, rack and hardware support per host per year (planning figure)'],
  migration_per_vm_sar: [1500, 'one-off effort to migrate and test one VM'],
  storage_per_gb_sar: [1.2, 'cost of a GB of primary storage per year, for reclaimed disk'],
  backup_platform_sar: [60000, 'running cost of one backup platform per year (licence + storage + effort)'],
  sparc_support_sar: [45000, 'Oracle hardware + Solaris support per SPARC server per year (planning figure)'],
  cpu_target_pct: [70, 'CPU ceiling a consolidated cluster should stay under'], mem_target_pct: [80, 'memory ceiling a consolidated cluster should stay under'],
};
const BOUNDS = { cpu_target_pct: [30, 95], mem_target_pct: [30, 95] };

function createPlatformCost(app, opts = {}) {
  const now = opts.now || Date.now;
  const CFG = app.store.collection('platform_cost_cfg'), CASES = app.store.collection('platform_cost_cases');
  function assumptions() { const r = CFG.get('assumptions') || { version: 0, values: {} }; const A = {}; for (const [k, [d]] of Object.entries(DEFAULTS)) A[k] = r.values[k] != null ? r.values[k] : d; return { A, version: r.version, by: r.by || null, at: r.at || null, changed: Object.keys(r.values) }; }
  function recorded(vendorRe) { // annual cost of a licence recorded in the register for this platform
    const L = app.store.collection('licences').all((l) => vendorRe.test(String(l.vendor || '') + ' ' + String(l.product || l.name || '')) && l.status !== 'retired');
    const cost = L.reduce((n, l) => n + (Number(l.annual_cost) || Number(l.cost_per_year) || 0), 0);
    return cost > 0 ? { cost, n: L.length } : null;
  }
  function view() {
    const { A, version, by, at, changed } = assumptions(), fx = A.usd_to_sar, T = now();
    const C = app.addons && app.addons.virtCapacity; let rep = null; try { rep = C ? C.report() : null; } catch (e) { rep = null; if (app.log && app.log.every) app.log.every('platform-cost:virt', 3600000, 'warn', 'Cost Optimisation: virtualization report failed', { error: e.message }); }
    const hosts = (rep && rep.hosts) || [], vms = (rep && rep.vms) || [], plats = (rep && rep.platforms) || [];
    const kindOf = (label) => { const p = plats.find((x) => x.label === label); return p ? (p.kind === 'nutanix' || p.kind === 'prism' ? 'nutanix' : 'vmware') : 'vmware'; };
    const vmw = hosts.filter((h) => kindOf(h.platform) === 'vmware'), ntx = hosts.filter((h) => kindOf(h.platform) === 'nutanix');
    const assets = app.store.collection('assets').all((a) => !['retired', 'disposed'].includes(a.status));
    const sparc = assets.filter((a) => /solaris|sparc/i.test(String(a.os || '') + ' ' + String(a.model || '')) && a.type !== 'vm');
    const BK = [['Veeam', /\bveeam\b/i], ['Commvault', /\bcommvault\b/i], ['Veritas NetBackup', /\bnetbackup\b/i], ['Acronis', /\bacronis\b/i], ['Barracuda Backup', /\bbarracuda\b.*\bbackup\b/i], ['Rubrik', /\brubrik\b/i], ['Nakivo', /\bnakivo\b/i]];
    const backups = BK.filter(([, re]) => assets.some((a) => (a.software || []).some((s) => re.test(s.name || s)))).map(([n]) => n);
    const avgCores = vmw.length ? vmw.reduce((n, h) => n + (h.cores || 0), 0) / vmw.length : 0, avgSockets = vmw.length ? vmw.reduce((n, h) => n + (h.sockets || 0), 0) / vmw.length : 0;
    const recV = recorded(/vmware|vsphere|broadcom/i), recN = recorded(/nutanix/i);
    const listV = avgCores * A.vmware_per_core_usd * fx;
    const perHost = { vmware: recV && vmw.length ? recV.cost / vmw.length : listV, vmware_src: recV && vmw.length ? 'recorded: ' + recV.n + ' VMware licence(s) in the register over ' + vmw.length + ' hosts' : 'assumption: ' + Math.round(avgCores) + ' cores x vmware_per_core_usd',
      aos: avgCores * A.aos_per_core_usd * fx, proxmox: Math.max(1, Math.round(avgSockets)) * A.proxmox_per_socket_eur * A.eur_to_sar, windows: avgCores / 16 * A.win_dc_per_16_cores_usd * fx, run: A.host_run_sar };
    const recs = [], add = (r) => recs.push(Object.assign({ saving: null, one_off: null, measured: [], assumed: [] }, r));
    // R1 consolidation, per cluster, from MEASURED use
    const byCl = {}; for (const h of vmw) (byCl[h.platform + ' / ' + h.cluster] = byCl[h.platform + ' / ' + h.cluster] || []).push(h);
    let freedAll = 0; const clRows = [];
    for (const [name, H] of Object.entries(byCl)) {
      const cpuOk = H.every((h) => h.cpu_used_pct != null && h.cores && h.cpu_ghz), memOk = H.every((h) => h.mem_used_pct != null && h.mem_gb);
      if (!cpuOk || !memOk) { clRows.push({ cluster: name, hosts: H.length, measured: false }); continue; }
      const cpuDemand = H.reduce((n, h) => n + h.cores * h.cpu_ghz * h.cpu_used_pct / 100, 0), memDemand = H.reduce((n, h) => n + h.mem_gb * h.mem_used_pct / 100, 0);
      const cpuCap = H.reduce((n, h) => n + h.cores * h.cpu_ghz, 0) / H.length, memCap = H.reduce((n, h) => n + h.mem_gb, 0) / H.length;
      const need = Math.max(Math.ceil(cpuDemand / (cpuCap * A.cpu_target_pct / 100)), Math.ceil(memDemand / (memCap * A.mem_target_pct / 100)), 1) + 1, freed = Math.max(0, H.length - need);
      freedAll += freed; clRows.push({ cluster: name, hosts: H.length, need: Math.min(need, H.length), freed, cpu_used_pct: Math.round(100 * cpuDemand / (cpuCap * H.length)), mem_used_pct: Math.round(100 * memDemand / (memCap * H.length)), measured: true });
    }
    if (vmw.length) {
      const per = perHost.vmware + perHost.windows + perHost.run, unmeasured = clRows.filter((c) => !c.measured);
      add({ id: 'R1', title: freedAll ? 'Consolidate the VMware clusters: about ' + freedAll + ' host(s) can be retired' : 'Consolidation: no host can be retired at the target ceilings', category: 'Right-sizing', audience: ['Infrastructure Manager', 'CISO'],
        saving: freedAll ? { low: r0(freedAll * per * 0.6), high: r0(freedAll * per) } : null, one_off: freedAll ? r0(freedAll * 4000) : null, effort: 'Medium', risk: 'Low', clusters: clRows,
        evidence: clRows.filter((c) => c.measured).map((c) => c.cluster + ': ' + c.hosts + ' hosts at ' + c.cpu_used_pct + ' % CPU / ' + c.mem_used_pct + ' % memory in use -> ' + c.need + ' needed with N+1').join('; ') + (unmeasured.length ? '. Not computed for ' + unmeasured.map((c) => c.cluster).join(', ') + ': CPU / memory in use not reported - run a Virtualization collection.' : ''),
        why: 'Each retired host removes its hypervisor subscription, its Windows Server Datacenter SA and its running cost.', ciso: 'Fewer hypervisors to patch and harden. Keep N+1 and do not consume the DR reserve.',
        compliance: 'Capacity plan and change approval (SAMA CSF 3.3.7, ISO 27001 A.8.6); re-test RTO after consolidation.', measured: ['CPU and memory in use per host (Virtualization collection)'], assumed: [perHost.vmware_src.startsWith('recorded') ? null : 'vmware_per_core_usd', 'win_dc_per_16_cores_usd', 'host_run_sar', 'cpu_target_pct', 'mem_target_pct'].filter(Boolean),
        confidence: unmeasured.length ? 'Partial - ' + unmeasured.length + ' cluster(s) without usage' : 'Good - from measured use; check the peak month before sizing' });
    }
    // R2 non-production off the commercial hypervisor
    const vmwLabels = new Set(vmw.map((h) => h.platform)), np = vms.filter((v) => vmwLabels.has(v.platform) && NONPROD.test(v.name || ''));
    if (np.length) {
      const npHosts = Math.max(1, Math.ceil(np.length / Math.max(1, vms.filter((v) => vmwLabels.has(v.platform) && v.power === 'on').length / Math.max(1, vmw.length)))), d = npHosts * (perHost.vmware - perHost.proxmox);
      add({ id: 'R2', title: 'Move ' + np.length + ' non-production VM(s) off VMware to Proxmox VE', category: 'Platform change', audience: ['Infrastructure Manager'], saving: d > 0 ? { low: r0(d * 0.7), high: r0(d) } : null, one_off: r0(np.length * A.migration_per_vm_sar), effort: 'Low-Medium', risk: 'Low',
        evidence: np.length + ' VMs named as dev / UAT / test / QA / staging (e.g. ' + np.slice(0, 4).map((v) => v.name).join(', ') + ') at today\'s density need about ' + npHosts + ' host(s).', vms: np.slice(0, 200).map((v) => ({ name: v.name, cluster: v.cluster, power: v.power })),
        why: 'Non-production has relaxed RTO and no orchestrated-failover dependency: the safest place to leave a commercial hypervisor and build skills first.', ciso: 'Keep environments segregated (ISO A.8.31), the same hardening baseline, hosts onboarded to the SIEM, no production personal data in test without masking (PDPL).',
        compliance: 'Change approval (SAMA CSF 3.3.7); third-party assessment of the new vendor (SAMA CSF 3.4).', measured: ['VM names and power state (Virtualization collection)'], assumed: ['proxmox_per_socket_eur', 'migration_per_vm_sar'], confidence: 'Good on the count; names are the evidence - confirm the environment of each VM' });
    }
    // R3 production to AHV where Nutanix already runs
    if (vmw.length && ntx.length) { const remain = Math.max(0, vmw.length - freedAll), d = remain * (perHost.vmware - perHost.aos);
      add({ id: 'R3', title: 'Production: move the remaining ' + remain + ' VMware host(s) to Nutanix AHV', category: 'Platform strategy', audience: ['Infrastructure Manager', 'CISO'], saving: d > 0 ? { low: r0(d * 0.6), high: r0(d) } : null, one_off: r0(vms.filter((v) => vmwLabels.has(v.platform)).length * A.migration_per_vm_sar), effort: 'High', risk: 'Medium',
        evidence: 'Nutanix already runs here: ' + ntx.length + ' node(s) collected. AHV is licensed with AOS, so there is no separate hypervisor bill.', why: 'The team, the tooling and the platform already exist; Proxmox is cheaper on paper but has no orchestrated failover and thin local vendor support.',
        ciso: 'A hypervisor change re-opens DR: replace SRM with Nutanix Protection Domains / Leap and re-test failover. Same hardening, logging and privileged access on the new platform.', compliance: 'DR failover test after migration (SAMA BCM); third-party risk of the platform vendor (SAMA CSF 3.4); change management (SAMA CSF 3.3.7).',
        measured: ['host counts and cores (Virtualization collection)'], assumed: [recN ? null : 'aos_per_core_usd', 'migration_per_vm_sar'].filter(Boolean), confidence: 'Directional - replace the AOS assumption with the Nutanix quote' }); }
    // R4 powered-off VMs
    const off = (rep && rep.vms_off) || vms.filter((v) => v.power !== 'on');
    if (off.length) { const gb = off.reduce((n, v) => n + (v.disk_gb || 0), 0);
      add({ id: 'R4', title: 'Reclaim ' + off.length + ' powered-off VM(s) (' + Math.round(gb) + ' GB of disk)', category: 'Reclaim', audience: ['Infrastructure Manager'], saving: gb ? { low: r0(gb * A.storage_per_gb_sar * 0.5), high: r0(gb * A.storage_per_gb_sar) } : null, one_off: 0, effort: 'Low', risk: 'Low',
        evidence: off.length + ' VMs are powered off: ' + off.slice(0, 5).map((v) => v.name).join(', ') + (off.length > 5 ? '…' : ''), vms: off.slice(0, 200).map((v) => ({ name: v.name, cluster: v.cluster, disk_gb: v.disk_gb })),
        why: 'A VM that stays off still holds storage, backup and licence counts.', ciso: 'Archive before delete; an orphaned VM is unpatched and comes back vulnerable if switched on.', compliance: 'Retention before deletion (PDPL Art. 18 for personal data), change approval.',
        measured: ['power state and disk (Virtualization collection)'], assumed: ['storage_per_gb_sar'], confidence: 'Good - confirm each owner before removal' }); }
    // R5 several backup platforms
    if (backups.length > 1) add({ id: 'R5', title: 'Consolidate ' + backups.length + ' backup platforms to one', category: 'Consolidation', audience: ['Infrastructure Manager', 'CISO'], saving: { low: r0((backups.length - 1) * A.backup_platform_sar * 0.5), high: r0((backups.length - 1) * A.backup_platform_sar) }, one_off: r0(A.backup_platform_sar * 0.3), effort: 'Medium', risk: 'Medium',
      evidence: 'Backup software installed in the register: ' + backups.join(', ') + '.', why: 'Each platform carries its own licence, storage and expertise.', ciso: 'Keep an immutable / offline copy and test restores on the surviving platform before retiring the others.',
      compliance: 'Backup and restore testing (SAMA CSF 3.3.x, NCA ECC 2-9); retention of existing backups until they expire.', measured: ['installed software (ITAM register)'], assumed: ['backup_platform_sar'], confidence: 'Directional' });
    // R6 SPARC
    if (sparc.length) add({ id: 'R6', title: sparc.length + ' SPARC / Solaris server(s) on support: plan the move to x86', category: 'Platform strategy', audience: ['Infrastructure Manager', 'DBA'], saving: { low: r0(sparc.length * A.sparc_support_sar * 0.5), high: r0(sparc.length * A.sparc_support_sar) }, one_off: r0(sparc.length * 25000), effort: 'High', risk: 'Medium',
      evidence: sparc.map((a) => a.name).slice(0, 8).join(', '), why: 'SPARC hardware and Solaris support are a premium; Oracle on x86 (or Linux) runs on the estate you already operate.',
      ciso: 'Oracle licence position changes with the core factor - re-check with the Oracle licence page before moving.', compliance: 'Change and DR re-test (SAMA BCM); licence compliance.', measured: ['servers in the register'], assumed: ['sparc_support_sar'], confidence: 'Directional - check the Oracle core-factor impact' });
    // cases
    const cases = CASES.all().sort((a, b) => String(b.at).localeCompare(String(a.at)));
    for (const r of recs) r.case = cases.find((c) => c.rec === r.id && c.status !== 'rejected') || cases.find((c) => c.rec === r.id) || null;
    const tot = recs.reduce((n, r) => ({ low: n.low + (r.saving ? r.saving.low : 0), high: n.high + (r.saving ? r.saving.high : 0), one: n.one + (r.one_off || 0) }), { low: 0, high: 0, one: 0 });
    return { at: new Date(T).toISOString(), currency: 'SAR', connected: !!(rep && plats.some((p) => p.at)), platforms: plats.map((p) => ({ label: p.label, kind: p.kind, at: p.at })),
      facts: { vmware_hosts: vmw.length, nutanix_nodes: ntx.length, vms: vms.length, vms_on: vms.filter((v) => v.power === 'on').length, nonprod_vms: np.length, off_vms: off.length, sparc: sparc.length, backup_platforms: backups, avg_cores: Math.round(avgCores), avg_sockets: Math.round(avgSockets * 10) / 10 },
      per_host: { vmware: r0(perHost.vmware), vmware_src: perHost.vmware_src, aos: r0(perHost.aos), proxmox: r0(perHost.proxmox), windows: r0(perHost.windows), run: r0(perHost.run), nutanix_recorded: recN ? recN.cost : null },
      totals: { low: tot.low, high: tot.high, one_off: tot.one }, recs, cases,
      assumptions: { version, by, at, values: A, changed, notes: Object.fromEntries(Object.entries(DEFAULTS).map(([k, [d, n]]) => [k, { default: d, note: n }])) },
      note: 'Savings are estimates. Measured facts come from the Virtualization collection and the ITAM register; prices are recorded licence costs where the register has them, otherwise the assumptions below - planning figures, not quotes.' };
  }
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  function setAssumptions(input, who) {
    person(who, 'change the assumptions');
    const src = input || {}, b0 = body(src).int('baseVersion', { min: 0 }), cur = CFG.get('assumptions') || { version: 0, values: {} };
    for (const k of Object.keys(DEFAULTS)) b0.num(k, { min: (BOUNDS[k] || [0])[0], max: (BOUNDS[k] || [0, 10000000])[1] });
    const b = b0.done();
    if (b.baseVersion != null && b.baseVersion !== cur.version) throw httpErr(409, 'baseVersion: the assumptions were changed by ' + (cur.by || 'someone') + ' - reload and apply again');
    const changes = {}, values = Object.assign({}, cur.values);
    for (const k of Object.keys(DEFAULTS)) if (b[k] != null && b[k] !== (values[k] != null ? values[k] : DEFAULTS[k][0])) { changes[k] = { from: values[k] != null ? values[k] : DEFAULTS[k][0], to: b[k] }; values[k] = b[k]; }
    if (src.reset === true) { for (const k of Object.keys(values)) changes[k] = { from: values[k], to: DEFAULTS[k][0] }; for (const k of Object.keys(values)) delete values[k]; }
    if (!Object.keys(changes).length) return { ok: true, version: cur.version, changed: 0 };
    const rec = { id: 'assumptions', version: cur.version + 1, values, by: who.user, at: new Date(now()).toISOString() }; CFG.put(rec);
    app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'platform_cost.assumptions', target: 'assumptions', detail: { version: rec.version, changes } });
    return { ok: true, version: rec.version, changed: Object.keys(changes).length };
  }
  function propose(input, who) {
    person(who, 'propose a business case');
    const b = body(input || {}).oneOf('rec', ['R1', 'R2', 'R3', 'R4', 'R5', 'R6'], { required: true }).str('note', { max: 1000 }).done();
    const v = view(), r = v.recs.find((x) => x.id === b.rec); if (!r) throw httpErr(409, 'rec: ' + b.rec + ' does not apply to the estate right now');
    if (CASES.all((c) => c.rec === b.rec && (c.status === 'proposed' || c.status === 'approved')).length) throw httpErr(409, 'rec: a business case for ' + b.rec + ' is already open or approved');
    const id = 'pcc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const c = { id, rec: r.id, title: r.title, saving: r.saving, one_off: r.one_off, evidence: r.evidence, assumptions_version: v.assumptions.version, note: b.note || null, status: 'proposed', proposed_by: who.user, at: new Date(now()).toISOString() };
    CASES.put(c); app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'platform_cost.case.propose', target: id, detail: { rec: r.id, saving: r.saving, note: b.note || null } });
    return { ok: true, case: c };
  }
  function decide(id, input, who) {
    person(who, 'decide a business case');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('reason', { required: true, max: 1000 }).done();
    const c = CASES.get(id); if (!c) throw httpErr(404, 'business case not found');
    if (c.status !== 'proposed') throw httpErr(409, 'this business case was already ' + c.status);
    if (String(c.proposed_by || '').trim().toLowerCase() === String(who.user || '').trim().toLowerCase()) throw httpErr(403, 'four-eyes: the person who proposed a business case cannot decide it');
    const next = Object.assign({}, c, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: new Date(now()).toISOString(), reason: b.reason });
    CASES.put(next); app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'platform_cost.case.' + next.status, target: id, detail: { rec: c.rec, proposed_by: c.proposed_by, reason: b.reason } });
    return { ok: true, case: next };
  }
  return { view, setAssumptions, propose, decide };
}

function registerPlatformCost(srv, app, P) {
  srv.route('GET', '/platform-cost', (ctx) => { ctx.need('operator'); return P.view(); });
  srv.route('POST', '/platform-cost/assumptions', (ctx) => { ctx.need('admin'); return P.setAssumptions(ctx.body, ctx.who); });
  srv.route('POST', '/platform-cost/cases', (ctx) => { ctx.need('operator'); return P.propose(ctx.body, ctx.who); });
  srv.route('POST', '/platform-cost/cases/:id/decide', (ctx) => { ctx.need('admin'); return P.decide(ctx.params.id, ctx.body, ctx.who); });
}

module.exports = { createPlatformCost, registerPlatformCost, DEFAULTS, NONPROD };
