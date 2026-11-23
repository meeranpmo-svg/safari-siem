// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AI Virtualization Administrator ({P} = /api/itam): runs VMware vCenter and Nutanix Prism the way an on-duty
 * virtualization administrator would - on the duty desk (duty-core.js) it patrols what the capacity collection
 * (virt-capacity.js, read-only SOAP / Prism API) reads every hour, opens a work item per problem, writes the change plan
 * (PowerCLI for vSphere, acli / Prism for Nutanix, with prechecks and rollback) and follows it to a verified result.
 *   patrols   platform login / collection failing or stale · host disconnected / not responding / health red · host CPU or
 *             memory over the limits · datastore inaccessible / nearly full / over-provisioned · snapshots older than the
 *             policy · disks needing consolidation · VMware Tools not running · HA off · cluster cannot survive one host
 *             failure (N+1) · vCPU per core above the ratio · capacity forecast inside 90 days · powered-off VMs to reclaim ·
 *             unresolved Nutanix Prism alerts · Nutanix DR replication (RPO missed, no remote copy, no schedule, stuck replication,
 *             remote site down, VMs in no protection domain, a protection domain active on both sites or on none) · hosts whose cores cannot be read (the core licence audit is incomplete)
 *   never     changes vCenter or Prism itself: the collection is read-only by construction (SOAP_OK / NTX_OK in
 *             virt-capacity.js). A change plan is APPROVED by an administrator (never the person who asked for it), APPLIED
 *             by a person, who records it here, and VERIFIED by a fresh read-only collection.
 * Routes:
 *   GET  /virt/admin                    viewer    platforms, findings by kind, change plans, policy
 *   GET  /virt/changes?state · /:id     viewer
 *   POST /virt/changes {item_id}        operator  write the change plan for a work item (the engineer does this on its own too)
 *   POST /virt/changes/:id/approve      admin     {comment?}   not the requester
 *   POST /virt/changes/:id/reject       admin     {reason}
 *   POST /virt/changes/:id/applied      operator  {note}       only after approval; the person who applied it
 *   PUT  /virt/admin/policy             admin     {snapshot_warn_days, snapshot_high_days, ds_free_crit_pct, offline_vm_min}
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
// four-eyes: names compared trimmed and case-insensitive (one sign-in method may send "Alice", another "alice"); requests the
// platform raised itself (duty:<engineer>, system:<job>) have no human requester
const normUser = (u) => String(u == null ? '' : u).trim().toLowerCase();
const sameUser = (a, b) => !!normUser(a) && normUser(a) === normUser(b);
const isSystem = (u) => /^(duty|system):/i.test(String(u || '').trim());
// PowerShell single-quoted literal: PowerShell also ends a literal on the typographic quotes ‘ ’ ‚ ‛, so all are doubled
const ps = (s) => "'" + String(s == null ? '' : s).replace(/['\u2018\u2019\u201A\u201B]/g, '$&$&') + "'";
// objects are addressed by their vCenter / Prism ID, never by name: names come from the platform (anyone who can rename a VM
// controls them) and Get-VM -Name treats * and ? as wildcards. An ID outside the expected shape gives no plan at all.
const MOREF = /^[A-Za-z]+-[0-9A-Za-z_.-]{1,40}$/, UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const localId = (id) => String(id || '').split(':').slice(1).join(':');   // "<platform>:<object id>" → object id
const badId = (id) => Object.assign(new Error('unsafe object id ' + String(id).slice(0, 60)), { badId: true });
const vcId = (type, id) => { if (!MOREF.test(String(id))) throw badId(id); return ps(type + '-' + id); };   // PowerCLI -Id 'VirtualMachine-vm-101'
const ntxId = (id) => { if (!UUID.test(String(id))) throw badId(id); return id; };
const POLICY = { snapshot_warn_days: 3, snapshot_high_days: 14, ds_free_crit_pct: 10, offline_vm_min: 1 };

function createVirtAdmin(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const latest = store.collection('virt_capacity'), plans = store.collection('virt_changes'), cfg = store.collection('virt_admin_cfg');
  const cap = () => (app.addons && app.addons.virtCapacity) || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || 'duty:virt', role: (who && who.role) || '', ip: (who && who.ip) || '', action, target, detail }); };
  function policy() { return Object.assign({}, POLICY, (cfg.get('policy') || {}).value || {}); }
  function setPolicy(b, who) {
    const p = policy(), errs = [];
    for (const [k, lo, hi] of [['snapshot_warn_days', 1, 365], ['snapshot_high_days', 1, 730], ['ds_free_crit_pct', 1, 50], ['offline_vm_min', 1, 10000]]) if (b[k] !== undefined) { const n = Number(b[k]); if (!(n >= lo && n <= hi)) errs.push(`${k}: ${lo}-${hi}`); else p[k] = Math.round(n); }
    if (p.snapshot_high_days < p.snapshot_warn_days) errs.push('snapshot_high_days must be at least snapshot_warn_days');
    if (errs.length) throw Object.assign(httpErr(400, 'invalid policy: ' + errs.join('; ')), { errors: errs });
    cfg.put({ id: 'policy', value: p }); audit(who, 'virt.admin.policy', 'policy', p); return p;
  }

  /* ---- findings: one per problem, keyed so the same condition is the same work item across collections. The duty core
     keeps only the common fields of a finding, so the full one (platform, cluster, data) is kept here by key for the plan. */
  let byKey = new Map();
  function current() {
    const f = scan(); if (f) byKey = new Map(f.map((x) => [x.key, x])); return f;
  }
  function scan() {
    const C = cap(); if (!C) return null;
    const rep = C.report(); if (!rep.platforms.length) return null;           // nothing connected: not connected, never "healthy"
    const st = rep.settings, pol = policy(), t = now(), out = [];
    const plat = new Map(rep.platforms.map((p) => [p.id, p]));
    const add = (o) => out.push(Object.assign({ evidence: [] }, o, { evidence: (o.evidence || []).filter(Boolean) }));
    for (const p of rep.platforms) {
      const tg = { type: 'platform', id: p.id, name: p.label };
      if (!p.credentials_set) add({ key: 'login:' + p.id, kind: 'platform-login', severity: 'medium', title: `${p.label}: no login saved - it cannot be checked`, recommendation: 'Virtualization → the platform → enter a read-only account (vCenter: Read-only role at the root; Prism: Viewer).', target: tg, site: p.site });
      else if (p.error) add({ key: 'collect:' + p.id, kind: 'collection-failed', severity: 'high', title: `${p.label}: the last collection failed`, evidence: [p.error], recommendation: 'Fix the cause named (login, certificate, network or privilege) on the Virtualization page; until then nothing on this platform is checked.', target: tg, site: p.site });
      else if (p.at && t - Date.parse(p.at) > 3 * (st.interval_min || 60) * 60000) add({ key: 'stale:' + p.id, kind: 'collection-stale', severity: 'medium', title: `${p.label}: not collected for ${Math.round((t - Date.parse(p.at)) / 3600000)} h`, recommendation: 'Check the IT Asset Management service and the capacity collection interval (Virtualization → Capacity).', target: tg, site: p.site });
    }
    for (const m of latest.all()) {
      const p = plat.get(m.id); if (!p || !p.collected) continue;
      const pl = p.label, vc = m.kind !== 'nutanix', hn = new Map((m.hosts || []).map((h) => [h.id, h.name]));
      for (const h of m.hosts || []) {
        const tg = { type: 'host', id: m.id + ':' + h.id, name: h.name, platform: pl, platform_id: m.id, kind: m.kind, cluster: h.cluster };
        const ev = [pl, 'cluster ' + h.cluster, h.version];
        if (!h.maintenance && h.state && h.state !== 'connected') add({ key: `host-down:${m.id}:${h.id}`, kind: 'host-down', severity: 'critical', title: `${h.name}: ${h.state === 'notResponding' ? 'not responding' : h.state} in ${vc ? 'vCenter' : 'Prism'}`, evidence: ev,
          recommendation: 'Check the host on its out-of-band console (iDRAC / iLO / IPMI): power, management network, hostd / vpxa (ESXi) or the CVM (Nutanix). HA restarts its VMs elsewhere only if the cluster has the room.', target: tg, site: p.site });
        if (h.status === 'red') add({ key: `host-red:${m.id}:${h.id}`, kind: 'host-health', severity: 'high', title: `${h.name}: health red in vCenter`, evidence: ev, recommendation: 'Open the host\'s triggered alarms and hardware status in vCenter (sensors, storage paths, NICs) and fix what is red.', target: tg, site: p.site });
        const cpuPct = h.cpu_used_mhz != null && h.cpu_mhz ? Math.round(h.cpu_used_mhz / h.cpu_mhz * 100) : null, memPct = h.mem_used_bytes != null && h.mem_bytes ? Math.round(h.mem_used_bytes / h.mem_bytes * 100) : null;
        if (cpuPct != null && cpuPct > st.cpu_max_pct) add({ key: `host-cpu:${m.id}:${h.id}`, kind: 'host-cpu', severity: 'high', title: `${h.name}: CPU ${cpuPct}% (limit ${st.cpu_max_pct}%)`, evidence: ev, recommendation: 'Balance the load: let DRS move VMs (fully automated) or move the busiest VMs to the least loaded host of the cluster.', target: tg, site: p.site, data: { cpu_pct: cpuPct } });
        if (memPct != null && memPct > st.mem_max_pct) add({ key: `host-mem:${m.id}:${h.id}`, kind: 'host-mem', severity: 'high', title: `${h.name}: memory ${memPct}% (limit ${st.mem_max_pct}%)`, evidence: ev, recommendation: 'Move VMs to a host with free memory, or right-size VMs with more memory than they use.', target: tg, site: p.site, data: { mem_pct: memPct } });
        if (!h.sockets || !h.cores) add({ key: `cores:${m.id}:${h.id}`, kind: 'cores-unknown', severity: 'medium', title: `${h.name}: CPU sockets / cores not readable - the core licence count is incomplete`, evidence: ev,
          recommendation: 'Give the collection account read access to the host (vCenter: Read-only at the root, propagated), then Virtualization → Capacity → Collect now; or type the counts in the Licence Audit.', target: tg, site: p.site });
      }
      for (const d of m.datastores || []) {
        const tg = { type: 'datastore', id: m.id + ':' + d.id, name: d.name, platform: pl, platform_id: m.id, kind: m.kind };
        const free = d.capacity ? Math.round((d.free || 0) / d.capacity * 1000) / 10 : null, used = free == null ? null : Math.round((100 - free) * 10) / 10;
        const prov = d.capacity && d.uncommitted != null ? Math.round((d.capacity - (d.free || 0) + d.uncommitted) / d.capacity * 100) : null;
        const ev = [pl, d.type, d.capacity ? Math.round(d.capacity / 1073741824) + ' GB' : '', free != null ? free + '% free' : '', prov != null ? prov + '% provisioned' : ''];
        if (d.accessible === false) add({ key: `ds-down:${m.id}:${d.id}`, kind: 'datastore-inaccessible', severity: 'critical', title: `${d.name}: datastore not accessible`, evidence: ev, recommendation: 'Check the storage paths and the array / vSAN health; VMs on it stop or are already down.', target: tg, site: p.site });
        else if (free != null && free < pol.ds_free_crit_pct) add({ key: `ds-full:${m.id}:${d.id}`, kind: 'datastore-full', severity: 'critical', title: `${d.name}: only ${free}% free`, evidence: ev, recommendation: 'Free space now (old snapshots first), move VMs to another datastore, or grow it - a full datastore stops every VM writing to it.', target: tg, site: p.site, data: { free_pct: free } });
        else if (used != null && used > st.storage_max_pct) add({ key: `ds-full:${m.id}:${d.id}`, kind: 'datastore-full', severity: 'high', title: `${d.name}: ${used}% used (limit ${st.storage_max_pct}%)`, evidence: ev, recommendation: 'Plan space: remove old snapshots, move VMs, or grow the datastore before it fills.', target: tg, site: p.site, data: { free_pct: free } });
        else if (prov != null && prov > 150) add({ key: `ds-prov:${m.id}:${d.id}`, kind: 'datastore-overprovisioned', severity: 'medium', title: `${d.name}: ${prov}% provisioned (thin disks could fill it)`, evidence: ev, recommendation: 'Thin disks have promised more than the datastore holds: watch growth, move large VMs, or add capacity.', target: tg, site: p.site });
      }
      const toolsOff = [];
      for (const v of m.vms || []) {
        const tg = { type: 'vm', id: m.id + ':' + v.id, name: v.name, platform: pl, platform_id: m.id, kind: m.kind, host: hn.get(v.host_id) || '' };
        const sn = v.snapshots;
        if (sn && sn.count && sn.oldest) {
          const age = Math.floor((t - Date.parse(sn.oldest)) / DAY);
          if (age >= pol.snapshot_warn_days) add({ key: `snap:${m.id}:${v.id}`, kind: 'snapshot-old', severity: age >= pol.snapshot_high_days ? 'high' : 'medium', title: `${v.name}: ${sn.count} snapshot${sn.count > 1 ? 's' : ''}, oldest ${age} days`,
            evidence: [pl, 'host ' + (hn.get(v.host_id) || '?'), 'oldest ' + sn.oldest], recommendation: 'Snapshots are not backups and slow the VM as they grow: confirm with the VM owner and the backup team, then delete the old ones.', target: tg, data: { days: age, count: sn.count, older_than_days: pol.snapshot_warn_days } });
        }
        if (v.consolidate === true) add({ key: `consol:${m.id}:${v.id}`, kind: 'consolidation-needed', severity: 'medium', title: `${v.name}: virtual disks need consolidation`, evidence: [pl], recommendation: 'Consolidate the disks (left over after a snapshot delete or a backup); until then the VM runs on a delta disk.', target: tg });
        if (v.power === 'on' && v.tools === 'not-running') toolsOff.push({ id: v.id, name: v.name });
      }
      if (toolsOff.length) add({ key: 'tools:' + m.id, kind: 'tools-not-running', severity: 'low', title: `${pl}: VMware Tools not running on ${toolsOff.length} powered-on VM${toolsOff.length > 1 ? 's' : ''}`, evidence: [toolsOff.slice(0, 15).map((x) => x.name).join(', ') + (toolsOff.length > 15 ? ' …' : '')],
        recommendation: 'Without Tools: no guest IP, no clean shutdown, no quiesced backup. Start / install / upgrade VMware Tools.', target: { type: 'platform', id: m.id, name: pl, platform: pl, platform_id: m.id, kind: m.kind }, data: { vms: toolsOff.slice(0, 50).map((x) => x.name), vm_ids: toolsOff.slice(0, 50).map((x) => x.id) } });
      for (const a of (m.alerts || []).filter((x) => !x.acknowledged && x.severity !== 'info').slice(0, 50)) add({ key: `alert:${m.id}:${a.id}`, kind: 'nutanix-alert', severity: a.severity === 'critical' ? 'high' : 'medium', title: `${pl}: ${a.title || 'Prism alert'}`, evidence: [a.entity ? 'entity ' + a.entity : '', a.created ? 'raised ' + a.created : ''],
        recommendation: 'Open the alert in Prism, follow its resolution steps (the KB it names), then resolve it.', target: { type: 'alert', id: m.id + ':' + a.id, name: a.entity || pl, platform: pl, platform_id: m.id, kind: m.kind } });
    }
    // DR replication (Nutanix protection domains / Leap): RPO met, a remote copy exists, schedules, stuck replications, remote
    // sites, unprotected VMs, and the cross-site check (same protection domain active on two sites, or on none)
    const D = rep.dr || { sites: [], cross: [] };
    for (const S of D.sites) {
      const tg = (name, type, id) => ({ type, id: S.platform_id + ':' + id, name, platform: S.platform, platform_id: S.platform_id, kind: 'nutanix' });
      if (S.read_errors.length) add({ key: 'dr-read:' + S.platform_id, kind: 'dr-read', severity: 'medium', title: `${S.platform}: DR state partly unreadable`, evidence: S.read_errors.slice(0, 5),
        recommendation: 'Give the Prism account read access to protection domains, remote sites and DR snapshots (Viewer role on the cluster). Until then the DR status of what could not be read is unknown, not healthy.', target: tg(S.platform, 'platform', 'dr') });
      for (const d of S.protection_domains) {
        const ev = [d.why, d.remote_sites.length ? 'remote site(s): ' + d.remote_sites.join(', ') : 'no remote site', d.vms.length + ' VM(s): ' + d.vms.slice(0, 10).join(', ') + (d.vms.length > 10 ? ' …' : '')];
        if (d.status === 'critical' || d.status === 'late') add({ key: `dr-rpo:${S.platform_id}:${d.name}`, kind: 'dr-rpo', severity: d.status === 'critical' ? 'critical' : 'high', title: `${d.name}: DR copy ${d.age_min} min old - RPO ${d.rpo_min} min missed (${S.platform})`, evidence: ev,
          recommendation: 'In Prism > Data Protection check the protection domain’s last replication and the remote site connection (bandwidth, network, remote cluster health). Take an out-of-band snapshot with replication once the link is healthy, and confirm it arrives on the DR site.', target: tg(d.name, 'protection-domain', d.name), data: { rpo_min: d.rpo_min, age_min: d.age_min } });
        else if (d.status === 'no-remote') add({ key: `dr-noremote:${S.platform_id}:${d.name}`, kind: 'dr-no-remote', severity: 'high', title: `${d.name}: no DR copy - snapshots stay on ${S.platform} only`, evidence: ev,
          recommendation: 'Add the DR remote site to the protection domain’s schedule (remote retention) so every snapshot is replicated to the DR cluster.', target: tg(d.name, 'protection-domain', d.name) });
        else if (d.status === 'no-schedule') add({ key: `dr-nosched:${S.platform_id}:${d.name}`, kind: 'dr-no-schedule', severity: 'high', title: `${d.name}: no snapshot schedule (${S.platform})`, evidence: ev,
          recommendation: 'Create a schedule that meets the agreed RPO (e.g. hourly with remote retention on the DR site).', target: tg(d.name, 'protection-domain', d.name) });
        else if (d.status === 'unknown') add({ key: `dr-unknown:${S.platform_id}:${d.name}`, kind: 'dr-unknown', severity: 'medium', title: `${d.name}: no DR snapshot reported (${S.platform})`, evidence: ev,
          recommendation: 'Check in Prism that the protection domain takes snapshots; if it does, the account may not read DR snapshots.', target: tg(d.name, 'protection-domain', d.name) });
        if (d.stuck) add({ key: `dr-stuck:${S.platform_id}:${d.name}`, kind: 'dr-replication-stuck', severity: 'high', title: `${d.name}: replication to ${d.stuck.remote_site || 'the remote site'} running for ${d.stuck.minutes} min${d.stuck.pct != null ? ' (' + d.stuck.pct + '%)' : ''}`, evidence: ev,
          recommendation: 'A replication running longer than three RPO periods means the link cannot keep up: check bandwidth throttling on the remote site, WAN utilisation and the amount of changed data.', target: tg(d.name, 'protection-domain', d.name) });
      }
      for (const r of S.remote_sites.filter((x) => x.healthy === false)) add({ key: `dr-remote:${S.platform_id}:${r.name}`, kind: 'dr-remote-site', severity: 'critical', title: `${S.platform}: remote site ${r.name} is ${r.status}`, evidence: [r.address ? 'address ' + r.address : ''].filter(Boolean),
        recommendation: 'Nothing replicates while the remote site is unreachable: check the network path to the DR cluster (ports 2009/2020), the remote cluster’s health and the remote site settings in Prism.', target: tg(r.name, 'remote-site', r.name) });
      if (S.unprotected_vms && S.unprotected_vms.length) add({ key: 'dr-unprot:' + S.platform_id, kind: 'dr-unprotected', severity: 'medium', title: `${S.platform}: ${S.unprotected_vms.length} powered-on VM${S.unprotected_vms.length > 1 ? 's are' : ' is'} in no protection domain`, evidence: [S.unprotected_vms.slice(0, 20).join(', ') + (S.unprotected_vms.length > 20 ? ' …' : '')],
        recommendation: 'Decide per VM whether it needs DR; add the ones that do to a protection domain with a remote site, and record the others as accepted (no DR) in the risk register.', target: tg(S.platform, 'platform', 'unprotected'), data: { vms: S.unprotected_vms.slice(0, 100) } });
    }
    for (const x of D.cross || []) add({ key: 'dr-cross:' + x.name, kind: x.status === 'both-active' ? 'dr-split-brain' : 'dr-none-active', severity: 'critical', title: `${x.name}: ${x.why}`, evidence: x.sites.map((y) => `${y.platform}: ${y.active === true ? 'active' : y.active === false ? 'inactive' : 'unknown'}`),
      recommendation: x.status === 'both-active' ? 'Decide which site owns the workload now, deactivate the protection domain on the other site (Prism > Data Protection), then re-establish replication from the active site.' : 'Activate the protection domain on the site that should run the workload and confirm replication resumes towards the other site.',
      target: { type: 'protection-domain', id: 'cross:' + x.name, name: x.name, platform: x.sites.map((y) => y.platform).join(' / '), kind: 'nutanix' } });
    for (const c of rep.clusters) {
      const p = rep.platforms.find((x) => x.label === c.platform) || {}, tg = { type: 'cluster', id: c.id, name: c.name, platform: c.platform, platform_id: p.id, kind: c.kind };
      if (c.name === 'Standalone hosts') continue;
      if (c.ha === false) add({ key: 'ha:' + c.id, kind: 'ha-off', severity: 'high', title: `${c.name}: vSphere HA is off - a host failure leaves its VMs down`, evidence: [c.platform, c.hosts + ' hosts'], recommendation: 'Turn on vSphere HA (with admission control matching the N+1 policy).', target: tg });
      if (c.n_plus_1 && c.mem_used_pct != null && c.mem_gb && c.mem_gb_after_n1 != null && c.mem_gb * c.mem_used_pct / 100 > c.mem_gb_after_n1)
        add({ key: 'n1:' + c.id, kind: 'n1-memory', severity: 'high', title: `${c.name}: cannot restart all VMs if one host fails (memory in use ${Math.round(c.mem_gb * c.mem_used_pct / 100)} GB, left after one host ${c.mem_gb_after_n1} GB)`, evidence: [c.platform], recommendation: 'Add a host or memory, or right-size / switch off VMs, until the cluster survives one host failure.', target: tg });
      if (c.vcpu_ratio != null && c.vcpu_ratio > st.vcpu_ratio) add({ key: 'vcpu:' + c.id, kind: 'vcpu-ratio', severity: 'medium', title: `${c.name}: ${c.vcpu_ratio} vCPU per core (limit ${st.vcpu_ratio})`, evidence: [c.platform, c.vcpus + ' vCPU on ' + c.cores + ' cores'], recommendation: 'Right-size VMs with more vCPU than they use (Capacity → top VMs) before adding hosts.', target: tg });
      const fm = c.forecast && c.forecast.memory;
      if (fm && fm.reliable && fm.days_to_limit != null && fm.days_to_limit <= 90) add({ key: 'fc:' + c.id, kind: 'capacity-forecast', severity: fm.days_to_limit <= 30 ? 'high' : 'medium', title: `${c.name}: memory reaches ${st.mem_max_pct}% in about ${fm.days_to_limit} days`, evidence: [c.platform, '+' + fm.per_month + '% per month over ' + fm.days_of_history + ' days'], recommendation: 'Order capacity now (lead time), or reclaim powered-off and oversized VMs.', target: tg });
    }
    const off = {}; for (const v of rep.vms_off) { const o = off[v.platform] = off[v.platform] || { n: 0, mem: 0, disk: 0, names: [] }; o.n++; o.mem += v.mem_gb || 0; o.disk += v.disk_gb || 0; if (o.names.length < 15) o.names.push(v.name); }
    for (const [pl, o] of Object.entries(off)) if (o.n >= pol.offline_vm_min) { const p = rep.platforms.find((x) => x.label === pl) || {}; add({ key: 'reclaim:' + (p.id || pl), kind: 'reclaim', severity: 'low', title: `${pl}: ${o.n} powered-off VM${o.n > 1 ? 's' : ''} holding ${Math.round(o.mem)} GB memory reservation and ${Math.round(o.disk)} GB disk`, evidence: [o.names.join(', ')], recommendation: 'Confirm with each owner (Asset Ownership) whether it is still needed; archive and remove the ones that are not.', target: { type: 'platform', id: p.id || pl, name: pl, platform: pl, platform_id: p.id, kind: p.kind }, data: { vms: o.names } }); }
    return out;
  }

  /* ---- change plans: written from the work item, PowerCLI for vSphere, acli / Prism for Nutanix */
  // no plan when an object ID does not have the expected shape: a person handles it (never a command built from odd data)
  function planFor(item) { try { return planBody(item); } catch (e) { if (e.badId) return null; throw e; } }
  function planBody(item) {
    if (!byKey.has(item.key)) current();
    const it = Object.assign({}, item, byKey.get(item.key) || {}, { id: item.id });
    const tg = it.target || {}, d = it.data || {}, ntx = tg.kind === 'nutanix';
    const base = { platform: tg.platform || '', platform_id: tg.platform_id || '', target: tg.name || '', prechecks: ['Change window agreed with the service owner', 'A current backup of the VMs affected'], rollback: '', irreversible: false, risk: 'medium' };
    switch (it.kind) {
      case 'snapshot-old': return Object.assign(base, { title: `Delete snapshots older than ${d.older_than_days || 3} days on ${tg.name}`, risk: 'high', irreversible: true,
        prechecks: ['VM owner confirms the snapshot is no longer needed', 'No backup job is running on the VM (a backup tool\'s temporary snapshot must not be deleted by hand)', 'Enough free space on the datastore for the consolidation'],
        steps: ['List the snapshots and confirm which to delete', 'Delete them, oldest first', 'Wait for the consolidation to finish; the next collection verifies'],
        commands: ntx ? [{ lang: 'acli', text: `acli vm.snapshot_list ${ntxId(localId(tg.id))}\n# for each snapshot to delete (check the name first):\nacli snapshot.delete <snapshot-name>` }]
          : [{ lang: 'powercli', text: `Get-VM -Id ${vcId('VirtualMachine', localId(tg.id))} | Get-Snapshot | Select-Object Name, Created, SizeGB\nGet-VM -Id ${vcId('VirtualMachine', localId(tg.id))} | Get-Snapshot | Where-Object { $_.Created -lt (Get-Date).AddDays(-${Number(d.older_than_days) || 3}) } | Remove-Snapshot -Confirm:$false` }],
        rollback: 'None - a deleted snapshot cannot be restored (the VM keeps its current state).' });
      case 'consolidation-needed': return Object.assign(base, { title: `Consolidate the disks of ${tg.name}`, risk: 'medium', prechecks: base.prechecks.concat(['No backup job running on the VM']),
        steps: ['Start the consolidation', 'Watch the task to completion; the VM stays on'], commands: [{ lang: 'powercli', text: `(Get-VM -Id ${vcId('VirtualMachine', localId(tg.id))}).ExtensionData.ConsolidateVMDisks_Task()` }], rollback: 'Not needed - consolidation merges delta disks into the base disk.' });
      case 'ha-off': return Object.assign(base, { title: `Turn on vSphere HA on cluster ${tg.name}`, risk: 'low', steps: ['Enable HA', 'Check admission control matches the N+1 policy', 'Confirm every host shows HA protected'],
        commands: [{ lang: 'powercli', text: `Get-Cluster -Id ${vcId('ClusterComputeResource', tg.id)} | Set-Cluster -HAEnabled:$true -HAAdmissionControlEnabled:$true -Confirm:$false` }], rollback: `Get-Cluster -Id ${vcId('ClusterComputeResource', tg.id)} | Set-Cluster -HAEnabled:$false -Confirm:$false` });
      case 'host-cpu': case 'host-mem': {
        const m = latest.get(tg.platform_id), hid = String(tg.id || '').split(':').slice(1).join(':'), h = m && (m.hosts || []).find((x) => x.id === hid);
        const peers = m ? (m.hosts || []).filter((x) => x.id !== hid && x.cluster === (h && h.cluster) && x.state === 'connected' && !x.maintenance) : [];
        const load = (x) => (it.kind === 'host-cpu' ? (x.cpu_used_mhz || 0) / (x.cpu_mhz || 1) : (x.mem_used_bytes || 0) / (x.mem_bytes || 1));
        const dest = peers.sort((a, b) => load(a) - load(b))[0];
        const vms = m ? (m.vms || []).filter((v) => v.host_id === hid && v.power === 'on').sort((a, b) => (it.kind === 'host-cpu' ? (b.cpu_used_mhz || 0) - (a.cpu_used_mhz || 0) : (b.mem_mb || 0) - (a.mem_mb || 0))).slice(0, 3) : [];
        if (!dest || !vms.length) return null;
        return Object.assign(base, { title: `Move ${vms.length} VM${vms.length > 1 ? 's' : ''} from ${tg.name} to ${dest.name}`, risk: 'low', prechecks: ['vMotion network healthy', `${dest.name} has the same networks and datastores`],
          steps: vms.map((v) => `vMotion ${v.name} to ${dest.name}`).concat(['Confirm load on both hosts', 'Consider DRS fully automated so this balances on its own']),
          commands: ntx ? [{ lang: 'acli', text: vms.map((v) => `acli vm.migrate ${ntxId(v.id)} host=${ntxId(dest.id)}`).join('\n') }] : [{ lang: 'powercli', text: vms.map((v) => `Move-VM -VM (Get-VM -Id ${vcId('VirtualMachine', v.id)}) -Destination (Get-VMHost -Id ${vcId('HostSystem', dest.id)})`).join('\n') }],
          rollback: ntx ? vms.map((v) => `acli vm.migrate ${ntxId(v.id)} host=${ntxId(hid)}`).join('\n') : vms.map((v) => `Move-VM -VM (Get-VM -Id ${vcId('VirtualMachine', v.id)}) -Destination (Get-VMHost -Id ${vcId('HostSystem', hid)})`).join('\n') });
      }
      case 'datastore-full': return Object.assign(base, { title: `Free space on datastore ${tg.name}`, risk: 'medium',
        steps: ['Delete old snapshots on VMs of this datastore (see their work items)', 'Storage vMotion the largest VMs to a datastore with room', 'If still short: grow the LUN / add vSAN capacity'],
        commands: [{ lang: 'powercli', text: `Get-Datastore -Id ${vcId('Datastore', localId(tg.id))} | Get-VM | Sort-Object UsedSpaceGB -Descending | Select-Object -First 10 Name, UsedSpaceGB\n# then, per VM chosen:\nMove-VM -VM '<vm>' -Datastore (Get-Datastore -Name '<target-datastore>')` }], rollback: 'Move the VMs back with the same command.' });
      case 'tools-not-running': return Object.assign(base, { title: `Start / upgrade VMware Tools on ${(d.vms || []).length} VMs (${tg.name})`, risk: 'medium', prechecks: base.prechecks.concat(['A Windows VM may need a reboot after the upgrade: schedule it']),
        steps: ['Check whether Tools is installed but stopped (start the service in the guest) or missing / old', 'Upgrade without reboot where possible'], commands: [{ lang: 'powercli', text: `Get-VM -Id ${(d.vm_ids && d.vm_ids.length ? d.vm_ids : [null]).slice(0, 25).map((i) => vcId('VirtualMachine', i)).join(', ')} | Update-Tools -NoReboot` }], rollback: 'None needed.' });
      case 'reclaim': return Object.assign(base, { title: `Reclaim powered-off VMs on ${tg.name}`, risk: 'high', irreversible: true, prechecks: ['Each VM\'s business owner confirms in writing that it is no longer needed', 'Final backup / export kept for the retention period'],
        steps: (d.vms || []).map((n) => `Owner confirmation for ${n}`).concat(['Export or back up each confirmed VM', 'Remove from disk']), commands: [{ lang: 'powercli', text: `# only for the VMs confirmed above:\nRemove-VM -VM '<vm>' -DeletePermanently -Confirm:$false` }], rollback: 'Restore from the final backup / export.' });
      default: return null;
    }
  }
  function nextId() { const c = store.collection('counters'), n = ((c.get('virt_change') || {}).n || 0) + 1; c.put({ id: 'virt_change', n }); return 'VCH-' + String(n).padStart(4, '0'); }
  function propose(it, who) {
    const open = plans.all((x) => x.item_id === it.id && (x.state === 'proposed' || x.state === 'approved'))[0];
    if (open) return { plan: open, existing: true };
    const p = planFor(it); if (!p) return null;
    const rec = Object.assign({ id: nextId(), item_id: it.id, item_key: it.key, kind: it.kind, severity: it.severity, state: 'proposed', requested_by: (who && who.user) || 'duty:virt', requested_at: new Date(now()).toISOString() }, p);
    plans.put(rec); audit(who, 'virt.change.propose', rec.id, { item: it.id, title: rec.title, irreversible: rec.irreversible });
    return { plan: rec, existing: false };
  }
  // a plan the AI wrote itself (virt-ai.js) when no standard plan fits: same four-eyes path, marked so the approver
  // checks every command - its text came from a model that read platform-supplied names
  function recordPlan(it, b, who) {
    const open = plans.all((x) => x.item_id === it.id && (x.state === 'proposed' || x.state === 'approved'))[0];
    if (open) return { plan: open, existing: true };
    const full = byKey.get(it.key) || it, tg = full.target || it.target || {}, list = (a, n, m) => (Array.isArray(a) ? a : []).slice(0, n).map((s) => clip(s, m)).filter(Boolean);
    const rec = { id: nextId(), item_id: it.id, item_key: it.key, kind: it.kind, severity: it.severity, state: 'proposed', source: 'ai', ai_written: true,
      requested_by: (who && who.user) || 'duty:virt', requested_at: new Date(now()).toISOString(),
      platform: tg.platform || '', platform_id: tg.platform_id || '', target: tg.name || '',
      title: clip(b.title, 200) || 'AI change plan', reason: clip(b.reason, 1500), risk: ['low', 'medium', 'high'].includes(b.risk) ? b.risk : 'high', irreversible: b.irreversible === true,
      prechecks: ['Every command checked by the approving administrator (AI-written plan)'].concat(list(b.prechecks, 15, 300)), steps: list(b.steps, 30, 400),
      commands: (Array.isArray(b.commands) ? b.commands : []).slice(0, 10).map((c) => ({ lang: ['powercli', 'acli', 'ncli', 'text'].includes(c && c.lang) ? c.lang : 'text', text: String((c && c.text) || '').replace(/\u0000/g, '').slice(0, 6000) })).filter((c) => c.text.trim()),
      rollback: clip(b.rollback, 2000) || 'Not stated - the approver must define one' };
    plans.put(rec); audit(who, 'virt.change.propose', rec.id, { item: it.id, title: rec.title, irreversible: rec.irreversible, source: 'ai' });
    return { plan: rec, existing: false };
  }
  function mustPlan(id) { const p = plans.get(String(id || '')); if (!p) throw httpErr(404, 'change plan not found'); return p; }
  function decide(id, who, approve, text) {
    const p = mustPlan(id);
    if (p.state !== 'proposed') throw httpErr(409, `change plan is ${p.state}`);
    if (sameUser(p.requested_by, who.user)) throw httpErr(403, 'four-eyes: the person who asked for the change cannot approve or reject it');
    if (!approve && !clip(text, 500)) throw httpErr(400, 'a reason is required to reject');
    const at = new Date(now()).toISOString();
    plans.patch(p.id, (x) => { x.state = approve ? 'approved' : 'rejected'; x.decided_by = who.user; x.decided_at = at; x.comment = clip(text, 500); return x; });
    audit(who, approve ? 'virt.change.approve' : 'virt.change.reject', p.id, { comment: clip(text, 500) });
    return plans.get(p.id);
  }
  function applied(id, who, note) {
    const p = mustPlan(id);
    if (p.state !== 'approved') throw httpErr(409, 'only an approved change plan can be recorded as applied' + (p.state === 'proposed' ? ' - it still needs an administrator\'s approval' : ''));
    // two people always: the administrator who approved cannot also be the one who records it as done (a plan the engineer
    // raised has no human requester, so this is what keeps it four-eyes)
    if (sameUser(p.decided_by, who.user)) throw httpErr(403, 'four-eyes: you approved this plan - the person who applies it records it');
    if (!clip(note, 1000)) throw httpErr(400, 'say what was done (a note is required)');
    plans.patch(p.id, (x) => { x.state = 'applied'; x.applied_by = who.user; x.applied_at = new Date(now()).toISOString(); x.note = clip(note, 1000); return x; });
    audit(who, 'virt.change.applied', p.id, { note: clip(note, 1000) });
    return plans.get(p.id);
  }
  function changeStatus(id) { const p = plans.get(id); return p ? { status: p.state, comment: p.state === 'rejected' ? p.comment : p.note || '' } : null; }
  let verifyRun = null;
  async function verify(it) {
    const C = cap(); if (!C) return { present: null, note: 'capacity collection not installed' };
    const done = plans.all((x) => x.item_id === it.id && x.state === 'applied').sort((a, b) => (a.applied_at < b.applied_at ? 1 : -1))[0];
    const full = byKey.get(it.key), pid = (done && done.platform_id) || (full && full.target && full.target.platform_id), rep = C.report(), p = pid ? rep.platforms.find((x) => x.id === pid) : null;
    // a reading taken before the change was applied proves nothing: start a fresh read-only collection and answer next time
    if (done && (!p || !p.at || p.at < done.applied_at)) { if (!verifyRun) verifyRun = Promise.resolve(C.run()).catch(() => null).finally(() => { verifyRun = null; }); return { present: null, note: 'waiting for a collection after the change (' + done.applied_at + ')' }; }
    if (p && p.error) return { present: null, note: 'the platform could not be read: ' + p.error };
    const f = current(); if (f === null) return { present: null, note: 'nothing connected' };
    const present = f.some((x) => x.key === it.key);
    return { present, note: present ? 'still reported by the latest collection' : 'the latest collection no longer reports it' };
  }

  const { kindCount } = require('./duty-core');
  const adapter = {
    id: 'virt', name: 'AI Virtualization Administrator',
    kpis: (open) => [
      { label: 'Hosts not connected', value: kindCount(open, ['host-down'], true), target: 0 },
      { label: 'Datastores over the limit / not accessible', value: kindCount(open, ['datastore-full', 'datastore-inaccessible']), target: 0 },
      { label: 'Snapshots older than policy', value: kindCount(open, ['snapshot-old']), target: 0 },
      { label: 'Clusters failing N+1 / over the vCPU ratio', value: kindCount(open, ['n1-memory', 'vcpu-ratio', 'capacity-forecast'], true), target: 0 },
      { label: 'Platforms not collected', value: kindCount(open, ['collection-failed', 'collection-stale', 'platform-login'], true), target: 0 },
      { label: 'DR: RPO missed / no DR copy / split brain', value: kindCount(open, ['dr-rpo', 'dr-no-remote', 'dr-no-schedule', 'dr-replication-stuck', 'dr-remote-site', 'dr-split-brain', 'dr-none-active'], true), target: 0 }],
    findings: () => current(),
    investigate(it) {
      const p = planFor(it);
      return { summary: `${it.title}. ${it.recommendation || ''}`.trim(),
        checks: (it.evidence || []).map((e) => ({ name: 'evidence', status: 'warn', detail: e })).concat(p ? [{ name: 'Change plan', status: 'warn', detail: p.title + (p.irreversible ? ' (irreversible)' : '') }] : []),
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation || '' }] };
    },
    propose(it, { onChange }) { const r = propose(it, { user: 'duty:virt', role: 'operator' }); if (!r) return { note: '' }; onChange({ id: r.plan.id }); return { note: (r.existing ? 'linked the open change plan ' : 'wrote change plan ') + r.plan.id + ' - an administrator approves it, a person applies it' }; },
    changeStatus, verify,
  };
  return { adapter, current, planFor, propose, recordPlan, decide, applied, changeStatus, policy, setPolicy, plans: () => plans.all().sort((a, b) => (a.requested_at < b.requested_at ? 1 : -1)) };
}

// the change-plan reads in Python (pyengine/virt_read.py, migration step 8e) - small data, read from the store files
// (read-only). A missing or failing Python, or virt_admin.engine = "node" → V.plans() below.
function virtPy(app) {
  if (((app.config && app.config.virt_admin) || {}).engine === 'node' || !app.store || !app.store.dir) return null;
  let py = null; try { py = require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 30000 }); } catch (e) { return null; }
  return async (op, body, ok) => { try { const r = await py.call(op, Object.assign({ dir: app.store.dir }, body)); return r && r.ok !== false && ok(r) ? r : null; } catch (e) { return null; } };
}

function registerVirtAdminRoutes(srv, app, V) {
  const PY = virtPy(app);
  srv.route('GET', '/virt/admin', (ctx) => { ctx.need('viewer');
    const C = app.addons && app.addons.virtCapacity, rep = C ? C.report() : null, f = V.current() || [];
    const byKind = {}; for (const x of f) byKind[x.kind] = (byKind[x.kind] || 0) + 1;
    return { generated: Date.now(), installed: !!C, settings: rep ? rep.settings : null, platforms: rep ? rep.platforms : [], totals: rep ? rep.totals : null, hosts: rep ? rep.hosts : [], clusters: rep ? rep.clusters.map((c) => ({ platform: c.platform, name: c.name, hosts: c.hosts, hosts_up: c.hosts_up, vms_on: c.vms_on, cores: c.cores, vcpu_ratio: c.vcpu_ratio, cpu_used_pct: c.cpu_used_pct, mem_used_pct: c.mem_used_pct, ha: c.ha, drs: c.drs, n_plus_1: c.n_plus_1, room: c.room })) : [],
      datastores: rep ? rep.datastores : [], findings: f.length, by_kind: byKind, policy: V.policy(), changes: V.plans().slice(0, 100) };
  });
  srv.route('GET', '/virt/changes', async (ctx) => { ctx.need('viewer');
    const st = (ctx.query || {}).state;
    const r = PY && await PY('virtplans.changes', { query: typeof st === 'string' ? { state: st } : {} }, (x) => Array.isArray(x.changes));
    return r ? { changes: r.changes } : { changes: V.plans().filter((p) => !st || p.state === st) };
  });
  srv.route('GET', '/virt/changes/:id', async (ctx) => { ctx.need('viewer');
    const r = PY && await PY('virtplans.change', { id: ctx.params.id }, (x) => typeof x.found === 'boolean');
    const p = r ? r.change : V.plans().find((x) => x.id === ctx.params.id); if (!p) throw httpErr(404, 'change plan not found'); return p;
  });
  srv.route('POST', '/virt/changes', (ctx) => {
    ctx.need('operator');
    const it = app.duty && app.duty.get(String((ctx.body || {}).item_id || ''));
    if (!it || it.engineer !== 'virt') throw httpErr(404, 'work item of the AI Virtualization Administrator not found');
    const r = V.propose(it, ctx.who); if (!r) throw httpErr(409, 'no change plan for this kind of problem - it needs a person (see the recommendation)');
    return r.plan;
  });
  srv.route('POST', '/virt/changes/:id/approve', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:virt') : ctx.need('admin')); return V.decide(ctx.params.id, ctx.who, true, (ctx.body || {}).comment); });
  srv.route('POST', '/virt/changes/:id/reject', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:virt') : ctx.need('admin')); return V.decide(ctx.params.id, ctx.who, false, (ctx.body || {}).reason); });
  srv.route('POST', '/virt/changes/:id/applied', (ctx) => { ctx.need('operator'); return V.applied(ctx.params.id, ctx.who, (ctx.body || {}).note); });
  srv.route('PUT', '/virt/admin/policy', (ctx) => { ctx.need('admin'); return V.setPolicy(ctx.body || {}, ctx.who); });
  (app.addons = app.addons || {}).virtAdmin = V;
  return V;
}

module.exports = { createVirtAdmin, registerVirtAdminRoutes, POLICY };
