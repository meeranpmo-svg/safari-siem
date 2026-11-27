// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Azure Cloud Servers - every Azure virtual machine of the organisation in one place, READ ONLY through Azure Resource Graph with
 * an app registration holding the built-in "Reader" role (the Asset Discovery credential of kind "azure", sealed in the vault):
 *   servers     size, power state, OS, private and public IPs, tags, subscription / resource group / region, the disks
 *   protection  Azure Backup (protected items, last backup, health), Defender for Cloud (secure score, unhealthy findings per VM),
 *               Update Manager patch assessment (critical / security patches waiting), management ports open to the internet (NSG)
 *   cost        Azure Advisor recommendations (right-size, shut down), disks attached to nothing, public IPs attached to nothing,
 *               VMs stopped but not deallocated (still billed for compute)
 *   risk        a score per server from the above, with the reasons, and "What the AI noticed" - rules over the data, labelled as such
 *   register    servers not in the IT asset register, added by an operator (site "Azure <region>") so the inventory stays accurate
 *   actions     start / stop / deallocate / restart: proposed by an operator with a reason, approved by a DIFFERENT named person who is
 *               an administrator (never an AI or service identity), then sent to Azure Resource Manager with a SEPARATE credential
 *               (Virtual Machine Contributor) chosen by an administrator - the read credential stays read-only. Audited throughout.
 *   GET  /azure-cloud                     viewer    the picture (tags and names of people only for operators)
 *   POST /azure-cloud/refresh             operator  read Azure now
 *   PUT  /azure-cloud/settings            admin     {credential_id, action_credential_id, refresh_hours}
 *   POST /azure-cloud/register            operator  {ids[]} add servers missing from the asset register
 *   POST /azure-cloud/actions             operator  {vm_id, action, reason} propose
 *   POST /azure-cloud/actions/:id/decide  admin     {decision: approve | reject, note} - another person; approve runs it
 */
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
const httpc = require('./discovery/httpc');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const ACTIONS = { start: 'start', stop: 'powerOff', deallocate: 'deallocate', restart: 'restart' };
const VM_ID = /^\/subscriptions\/[0-9a-f-]{36}\/resourcegroups\/[a-z0-9._()-]{1,90}\/providers\/microsoft\.compute\/virtualmachines\/[a-z0-9._-]{1,64}$/;
const MGMT_PORTS = { 22: 'SSH', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM', 445: 'SMB', 1433: 'SQL Server', 3306: 'MySQL' };
const low = (v) => String(v == null ? '' : v).toLowerCase();

// Resource Graph queries - each section is read on its own, so a missing permission on one (e.g. Defender) does not hide the rest
const Q = {
  subs: "ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, name",
  vms: ["Resources | where type =~ 'microsoft.compute/virtualmachines'",
    '| project id, name, location, resourceGroup, subscriptionId, tags, osType = tostring(properties.storageProfile.osDisk.osType),',
    '  osName = tostring(properties.extended.instanceView.osName), osVersion = tostring(properties.extended.instanceView.osVersion),',
    '  vmSize = tostring(properties.hardwareProfile.vmSize), powerState = tostring(properties.extended.instanceView.powerState.code),',
    '  licenseType = tostring(properties.licenseType), timeCreated = tostring(properties.timeCreated), zones'].join('\n'),
  nics: ["Resources | where type =~ 'microsoft.network/networkinterfaces'",
    '| mv-expand ipc = properties.ipConfigurations',
    '| project vm = tolower(tostring(properties.virtualMachine.id)), nsg = tolower(tostring(properties.networkSecurityGroup.id)),',
    '  privateIp = tostring(ipc.properties.privateIPAddress), publicIpId = tolower(tostring(ipc.properties.publicIPAddress.id)),',
    '  subnet = tolower(tostring(ipc.properties.subnet.id))'].join('\n'),
  pips: ["Resources | where type =~ 'microsoft.network/publicipaddresses'",
    '| project id = tolower(id), name, ip = tostring(properties.ipAddress), attached = tolower(tostring(properties.ipConfiguration.id)),',
    '  sku = tostring(sku.name), resourceGroup, subscriptionId, location'].join('\n'),
  disks: ["Resources | where type =~ 'microsoft.compute/disks'",
    '| project id = tolower(id), name, managedBy = tolower(tostring(managedBy)), state = tostring(properties.diskState),',
    '  sizeGb = toint(properties.diskSizeGB), sku = tostring(sku.name), encryption = tostring(properties.encryption.type),',
    '  resourceGroup, subscriptionId, location, timeCreated = tostring(properties.timeCreated)'].join('\n'),
  nsg: ["Resources | where type =~ 'microsoft.network/networksecuritygroups'",
    '| mv-expand r = properties.securityRules',
    "| where tostring(r.properties.direction) =~ 'Inbound' and tostring(r.properties.access) =~ 'Allow'",
    "| extend src = tostring(r.properties.sourceAddressPrefix) | where src in ('*', 'Internet', '0.0.0.0/0', 'Any')",
    '| project nsg = tolower(id), rule = tostring(r.name), port = tostring(r.properties.destinationPortRange), ports = r.properties.destinationPortRanges,',
    '  subnets = properties.subnets'].join('\n'),
  backup: ["RecoveryServicesResources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'",
    '| project vm = tolower(tostring(properties.sourceResourceId)), lastBackup = tostring(properties.lastBackupTime),',
    '  health = tostring(properties.healthStatus), state = tostring(properties.protectionState), policy = tostring(properties.policyName)'].join('\n'),
  patches: ["PatchAssessmentResources | where type =~ 'microsoft.compute/virtualmachines/patchassessmentresults'",
    "| project vm = tolower(tostring(split(id, '/patchAssessmentResults/')[0])), at = tostring(properties.lastModifiedDateTime),",
    '  critical = toint(properties.availablePatchCountByClassification.critical), security = toint(properties.availablePatchCountByClassification.security),',
    '  other = toint(properties.availablePatchCountByClassification.other), reboot = tostring(properties.rebootPending)'].join('\n'),
  advisor: ["AdvisorResources | where type =~ 'microsoft.advisor/recommendations'",
    '| project res = tolower(tostring(properties.resourceMetadata.resourceId)), category = tostring(properties.category), impact = tostring(properties.impact),',
    '  problem = tostring(properties.shortDescription.problem), solution = tostring(properties.shortDescription.solution),',
    '  savings = todouble(properties.extendedProperties.savingsAmount), currency = tostring(properties.extendedProperties.savingsCurrency),',
    '  targetSku = tostring(properties.extendedProperties.targetSku)'].join('\n'),
  score: "SecurityResources | where type =~ 'microsoft.security/securescores' | project subscriptionId, current = todouble(properties.score.current), max = todouble(properties.score.max)",
  defender: ["SecurityResources | where type =~ 'microsoft.security/assessments' | where tostring(properties.status.code) =~ 'Unhealthy'",
    '| project res = tolower(tostring(properties.resourceDetails.Id)), name = tostring(properties.displayName), severity = tostring(properties.metadata.severity)'].join('\n'),
};

function rowsOf(j) {
  if (Array.isArray(j && j.data)) return j.data;
  if (j && j.data && Array.isArray(j.data.rows) && Array.isArray(j.data.columns)) { const c = j.data.columns.map((x) => x.name); return j.data.rows.map((r) => Object.fromEntries(c.map((n, i) => [n, r[i]]))); }
  return [];
}
const errClass = (status) => (status === 400 || status === 401 ? 'auth' : status === 403 ? 'authz' : 'protocol');

function createAzureCloud(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString();
  const request = opts.request || httpc.request;
  const cfg = (app.config && app.config.azure_cloud) || {};
  const LOGIN = String(opts.login_base || cfg.login_base || 'https://login.microsoftonline.com').replace(/\/+$/, '');
  const ARM = String(opts.arm_base || cfg.arm_base || 'https://management.azure.com').replace(/\/+$/, '');
  const col = () => app.store.collection('azure_cloud');
  const acts = () => app.store.collection('azure_cloud_actions');
  const vault = () => (app.discovery && app.discovery.vault) || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'azure.' + action, target, detail }); };
  const settings = () => Object.assign({ credential_id: null, action_credential_id: null, refresh_hours: 6 }, col().get('settings') || {});
  const snap = () => col().get('snapshot') || null;

  function credentials() {
    const V = vault(); if (!V || !V.available()) return [];
    return V.list().filter((c) => c.kind === 'azure').map((c) => ({ id: c.id, label: c.label, tenant_id: c.target && c.target.tenant_id, subscriptions: (c.target && c.target.subscriptions || []).length, last_tested: c.last_tested || null }));
  }
  function openCred(id) {
    const V = vault(); if (!V || !V.available()) throw bad('the credential vault is not available on this server', 409);
    if (!id) throw bad('no Azure connection set: Settings → choose the Azure credential (Asset Discovery → Credentials, kind Azure)', 409);
    const c = V.open(id); if (c.kind !== 'azure') { c.release(); throw bad('credential ' + id + ' is not an Azure credential'); }
    return c;
  }
  async function token(c) {
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: c.target.client_id, client_secret: c.secret.client_secret, scope: 'https://management.azure.com/.default' }).toString();
    const r = await request(LOGIN + '/' + encodeURIComponent(c.target.tenant_id) + '/oauth2/v2.0/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form, timeout: 20000 });
    if (r.status >= 300 || !r.json || !r.json.access_token) throw Object.assign(new Error('Azure sign-in refused (HTTP ' + r.status + ') - check the tenant, client id and secret of the credential'), { status: 502, cls: errClass(r.status) });
    return r.json.access_token;
  }
  async function graph(c, bearer, q) {
    const rows = []; let skip = null, pages = 0;
    do {
      const b = { query: q, options: Object.assign({ $top: 1000 }, skip ? { $skipToken: skip } : {}) };
      if (c.target.subscriptions && c.target.subscriptions.length) b.subscriptions = c.target.subscriptions;
      const r = await request(ARM + '/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01', { method: 'POST', headers: { Authorization: 'Bearer ' + bearer, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(b), timeout: 30000 });
      if (r.status >= 300 || !r.json) throw Object.assign(new Error('Resource Graph HTTP ' + r.status), { cls: errClass(r.status) });
      rows.push(...rowsOf(r.json)); skip = r.json.$skipToken || null; pages++;
    } while (skip && pages < 50);
    return rows;
  }

  async function refresh(who) {
    const S = settings(), c = openCred(S.credential_id), t0 = now();
    const raw = {}, sections = {};
    try {
      const bearer = await token(c);
      for (const k of Object.keys(Q)) {
        try { raw[k] = await graph(c, bearer, Q[k]); sections[k] = { ok: true, rows: raw[k].length }; }
        catch (e) { raw[k] = []; sections[k] = { ok: false, error: e.cls || 'protocol' }; if (app.log && app.log.every) app.log.every('azure.section.' + k, 3600000, 'warn', 'azure cloud: section ' + k + ' not read (' + (e.cls || 'protocol') + ')'); }
      }
    } finally { c.release(); }
    if (sections.vms && !sections.vms.ok) throw bad('Azure answered the sign-in but the servers could not be read (' + sections.vms.error + ') - give the app registration the Reader role on the subscriptions', 502);
    const S2 = { at: iso(), took_ms: now() - t0, sections, raw };
    col().put(Object.assign({ id: 'snapshot' }, S2));
    audit(who, 'refresh', 'azure', { vms: raw.vms.length, sections_failed: Object.keys(sections).filter((k) => !sections[k].ok) });
    return S2;
  }

  // ---------- analysis ----------
  function analyse(sn) {
    const R = sn.raw, subName = {}; for (const s of R.subs || []) subName[low(s.subscriptionId)] = s.name;
    const pipById = {}; for (const p of R.pips || []) pipById[p.id] = p;
    const nsgOpen = {};   // nsg id -> [{port, label, rule}]
    for (const n of R.nsg || []) {
      const ports = [].concat(n.port ? [n.port] : [], Array.isArray(n.ports) ? n.ports : []);
      for (const p of ports) {
        const hit = Object.keys(MGMT_PORTS).filter((m) => p === '*' || p === m || (/^\d+-\d+$/.test(p) && +p.split('-')[0] <= +m && +m <= +p.split('-')[1]));
        for (const m of hit) (nsgOpen[n.nsg] = nsgOpen[n.nsg] || []).push({ port: +m, label: MGMT_PORTS[m], rule: n.rule });
      }
      // an NSG on the subnet counts for every NIC in it
      for (const s of Array.isArray(n.subnets) ? n.subnets : []) { const sid = low(s && s.id); if (sid && nsgOpen[n.nsg]) nsgOpen['subnet:' + sid] = nsgOpen[n.nsg]; }
    }
    const nicsOf = {}; for (const n of R.nics || []) if (n.vm) (nicsOf[n.vm] = nicsOf[n.vm] || []).push(n);
    const bk = {}; for (const b of R.backup || []) if (b.vm) bk[b.vm] = b;
    const pt = {}; for (const p of R.patches || []) if (p.vm) pt[p.vm] = p;
    const adv = {}; for (const a of R.advisor || []) if (a.res) (adv[a.res] = adv[a.res] || []).push(a);
    const df = {}; for (const d of R.defender || []) if (d.res) (df[d.res] = df[d.res] || []).push(d);
    const disksOf = {}; for (const d of R.disks || []) if (d.managedBy) (disksOf[d.managedBy] = disksOf[d.managedBy] || []).push(d);
    const assets = app.store.collection('assets').all((x) => x.status !== 'deleted');
    const byName = new Map(), byIp = new Map(); for (const a of assets) { if (a.name) byName.set(low(a.name), a); if (a.mgmt_ip) byIp.set(a.mgmt_ip, a); }
    const t = now();
    const vms = (R.vms || []).map((v) => {
      const id = low(v.id), N = nicsOf[id] || [], ips = [...new Set(N.map((n) => n.privateIp).filter(Boolean))];
      const pub = N.map((n) => pipById[n.publicIpId]).filter(Boolean).map((p) => p.ip).filter(Boolean);
      const open = []; for (const n of N) for (const o of (nsgOpen[n.nsg] || []).concat(nsgOpen['subnet:' + n.subnet] || [])) if (!open.some((x) => x.port === o.port)) open.push(o);
      const power = String(v.powerState || '').replace(/^PowerState\//i, '').toLowerCase() || 'unknown';
      const B = bk[id], P = pt[id], A = adv[id] || [], D = df[id] || [], tags = v.tags && typeof v.tags === 'object' ? v.tags : {};
      const lastBk = B && B.lastBackup ? Date.parse(B.lastBackup) : NaN, bkAge = isNaN(lastBk) ? null : Math.floor((t - lastBk) / 86400000);
      const owner = tags.owner || tags.Owner || tags.OWNER || null, asset = byName.get(low(v.name)) || ips.map((i) => byIp.get(i)).find(Boolean) || null;
      const reasons = []; let score = 0; const add = (n, why) => { score += n; reasons.push(why); };
      if (pub.length && open.length) add(30, open.map((o) => o.label).join(', ') + ' open to the internet on a public IP');
      else if (open.length) add(10, open.map((o) => o.label).join(', ') + ' allowed from any source (no public IP on the server)');
      if (!B) add(20, 'not protected by Azure Backup'); else if (/unhealthy|actionrequired/i.test(B.health || '') || (bkAge !== null && bkAge > 2)) add(10, 'backup ' + (bkAge !== null ? bkAge + ' days old' : 'unhealthy'));
      if (P && (P.critical || 0) > 0) add(Math.min(20, 8 + 3 * P.critical), P.critical + ' critical patch(es) waiting');
      else if (P && (P.security || 0) > 0) add(Math.min(12, 4 + 2 * P.security), P.security + ' security patch(es) waiting');
      else if (!P) add(5, 'no patch assessment from Update Manager');
      const high = D.filter((d) => /high/i.test(d.severity)).length; if (high) add(Math.min(15, 5 * high), high + ' high Defender for Cloud finding(s)');
      if (power === 'stopped') add(5, 'stopped but not deallocated - compute still billed');
      if (!owner) add(3, 'no owner tag');
      const disks = disksOf[id] || [];
      return { id, name: v.name, location: v.location, resource_group: v.resourceGroup, subscription: v.subscriptionId, subscription_name: subName[low(v.subscriptionId)] || null,
        size: v.vmSize || null, power, os_type: v.osType || null, os: [v.osName, v.osVersion].filter(Boolean).join(' ') || null, hybrid_benefit: /windows_server|windows_client|rhel_byos|sles_byos/i.test(v.licenseType || ''),
        ips, public_ips: pub, open_ports: open, created: v.timeCreated || null, zones: Array.isArray(v.zones) ? v.zones : [],
        disks: disks.map((d) => ({ name: d.name, size_gb: d.sizeGb || 0, sku: d.sku, encryption: d.encryption || null })), disk_gb: disks.reduce((s, d) => s + (d.sizeGb || 0), 0),
        backup: B ? { last: B.lastBackup || null, age_days: bkAge, health: B.health || null, state: B.state || null, policy: B.policy || null } : null,
        patches: P ? { critical: P.critical || 0, security: P.security || 0, other: P.other || 0, reboot_pending: /true/i.test(P.reboot || ''), at: P.at || null } : null,
        defender: { high, total: D.length, top: D.slice(0, 5).map((d) => ({ name: d.name, severity: d.severity })) },
        advisor: A.map((a) => ({ category: a.category, impact: a.impact, problem: a.problem, solution: a.solution, savings: a.savings || 0, currency: a.currency || null, target_sku: a.targetSku || null })),
        tags, owner, in_register: !!asset, asset_id: asset ? asset.id : null, risk: Math.min(100, score), reasons };
    }).sort((a, b) => b.risk - a.risk || String(a.name).localeCompare(String(b.name)));
    const orphanDisks = (R.disks || []).filter((d) => !d.managedBy && /unattached/i.test(d.state || 'unattached')).map((d) => ({ name: d.name, size_gb: d.sizeGb || 0, sku: d.sku, resource_group: d.resourceGroup, location: d.location, created: d.timeCreated || null }));
    const orphanIps = (R.pips || []).filter((p) => !p.attached).map((p) => ({ name: p.name, ip: p.ip || null, sku: p.sku, resource_group: p.resourceGroup, location: p.location }));
    const savings = (R.advisor || []).filter((a) => /cost/i.test(a.category)).reduce((s, a) => s + (a.savings || 0), 0);
    const currency = ((R.advisor || []).find((a) => a.currency) || {}).currency || null;
    const scores = (R.score || []).map((s) => ({ subscription: s.subscriptionId, name: subName[low(s.subscriptionId)] || null, pct: s.max ? Math.round(100 * s.current / s.max) : null }));
    const cnt = (f) => vms.filter(f).length;
    const totals = { vms: vms.length, running: cnt((v) => v.power === 'running'), stopped_billed: cnt((v) => v.power === 'stopped'), deallocated: cnt((v) => v.power === 'deallocated'),
      exposed: cnt((v) => v.public_ips.length && v.open_ports.length), no_backup: cnt((v) => !v.backup), critical_patches: cnt((v) => v.patches && v.patches.critical > 0), defender_high: cnt((v) => v.defender.high > 0),
      not_in_register: cnt((v) => !v.in_register), orphan_disks: orphanDisks.length, orphan_disk_gb: orphanDisks.reduce((s, d) => s + d.size_gb, 0), orphan_ips: orphanIps.length,
      advisor_savings: Math.round(savings), currency, secure_score: scores.length ? Math.round(scores.reduce((s, x) => s + (x.pct || 0), 0) / scores.length) : null,
      subscriptions: new Set(vms.map((v) => v.subscription)).size, regions: new Set(vms.map((v) => v.location)).size };
    const group = (k) => { const m = {}; for (const v of vms) { const x = v[k] || 'unknown'; m[x] = (m[x] || 0) + 1; } return Object.entries(m).map(([name, n]) => ({ name, n })).sort((a, b) => b.n - a.n); };
    return { vms, orphan_disks: orphanDisks, orphan_ips: orphanIps, scores, totals, by_region: group('location'), by_power: group('power'), by_size: group('size').slice(0, 12), by_os: group('os_type'), insights: insights(vms, totals) };
  }

  function insights(vms, T) {   // rules over the data - said plainly, the reasons are the numbers
    const out = [], p = (lvl, title, detail, ids) => out.push({ level: lvl, title, detail, servers: (ids || []).slice(0, 8) });
    const ex = vms.filter((v) => v.public_ips.length && v.open_ports.length);
    if (ex.length) p('crit', ex.length + ' server(s) reachable from the internet on a management port', 'RDP / SSH / WinRM open on a public IP is the most common way into a cloud server. Close the NSG rule and use Azure Bastion or the VPN (NCA ECC 2-5).', ex.map((v) => v.name));
    const nb = vms.filter((v) => !v.backup && v.power !== 'deallocated');
    if (nb.length) p('warn', nb.length + ' running server(s) without Azure Backup', 'No restore point if the disk is lost or encrypted by ransomware (NCA ECC 2-9).', nb.map((v) => v.name));
    const cp = vms.filter((v) => v.patches && v.patches.critical > 0);
    if (cp.length) p('crit', cp.length + ' server(s) with critical patches waiting', cp.reduce((s, v) => s + v.patches.critical, 0) + ' critical patch(es) in total - schedule them in Update Manager.', cp.map((v) => v.name));
    const sb = vms.filter((v) => v.power === 'stopped');
    if (sb.length) p('warn', sb.length + ' server(s) stopped but still billed', 'Stopped from inside the OS keeps the compute reserved and billed. Deallocate them (Actions) if they are not needed.', sb.map((v) => v.name));
    if (T.orphan_disks) p('warn', T.orphan_disks + ' disk(s) attached to nothing (' + T.orphan_disk_gb + ' GB)', 'Storage paid for every month. Snapshot if needed, then delete in the portal.');
    if (T.orphan_ips) p('info', T.orphan_ips + ' public IP(s) attached to nothing', 'Static public IPs are billed while unused.');
    if (T.advisor_savings) p('info', 'Azure Advisor sees ' + T.advisor_savings + ' ' + (T.currency || '') + ' a month of savings', 'Right-size or shut down the servers Advisor lists under Cost.');
    const big = vms.filter((v) => v.advisor.some((a) => /cost/i.test(a.category) && a.target_sku));
    if (big.length) p('info', big.length + ' server(s) larger than they need to be', 'Advisor suggests a smaller size from their CPU use.', big.map((v) => v.name + ' → ' + v.advisor.find((a) => a.target_sku).target_sku));
    if (T.not_in_register) p('info', T.not_in_register + ' server(s) not in the IT asset register', 'Add them below so the inventory and the branch view are accurate.');
    const wnhb = vms.filter((v) => /windows/i.test(v.os_type || '') && !v.hybrid_benefit);
    if (wnhb.length) p('info', wnhb.length + ' Windows server(s) without Azure Hybrid Benefit', 'If Safari holds Windows Server licences with Software Assurance, Hybrid Benefit removes the Windows charge.', wnhb.map((v) => v.name));
    const no = vms.filter((v) => !v.owner);
    if (no.length && no.length === vms.length) p('info', 'No server carries an owner tag', 'Tag each server with "owner" and "environment" so the right person is asked about changes.');
    return out;
  }

  function view(role) {
    const op = ['operator', 'admin'].includes(role), S = settings(), sn = snap();
    const out = { configured: !!S.credential_id, actions_enabled: !!S.action_credential_id, settings: op ? { credential_id: S.credential_id, action_credential_id: S.action_credential_id, refresh_hours: S.refresh_hours } : { refresh_hours: S.refresh_hours },
      credentials: role === 'admin' ? credentials() : [], vault: !!(vault() && vault().available()), at: sn ? sn.at : null, sections: sn ? sn.sections : {},
      actions: acts().all().sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 50).map((a) => op ? a : Object.assign({}, a, { reason: undefined, note: undefined })) };
    if (!sn) return Object.assign(out, { vms: [], totals: null, insights: [] });
    const A = analyse(sn);
    if (!op) for (const v of A.vms) { v.tags = {}; v.owner = v.owner ? 'set' : null; }
    return Object.assign(out, A);
  }

  function putSettings(b0, who) {
    if (!isHuman(who.user)) throw bad('a person sets the Azure connection', 403);
    const b = body(b0 || {}).str('credential_id', { max: 40, re: /^cr_[0-9a-f]{12}$/, msg: 'credential_id: an Asset Discovery credential id' }).str('action_credential_id', { max: 40, re: /^(cr_[0-9a-f]{12})?$/, msg: 'action_credential_id: an Asset Discovery credential id or empty' })
      .int('refresh_hours', { min: 1, max: 24, def: 6 }).done();
    const ids = new Set(credentials().map((c) => c.id));
    if (b.credential_id && !ids.has(b.credential_id)) throw bad('credential_id: not an Azure credential in the vault');
    if (b.action_credential_id && !ids.has(b.action_credential_id)) throw bad('action_credential_id: not an Azure credential in the vault');
    if (b.action_credential_id && b.action_credential_id === b.credential_id) throw bad('action_credential_id: use a separate credential for actions - the read credential stays Reader-only');
    const prev = settings(), rec = Object.assign({ id: 'settings' }, prev, { credential_id: b.credential_id || null, action_credential_id: b.action_credential_id || null, refresh_hours: b.refresh_hours, updated_by: who.user, updated_at: iso() });
    col().put(rec);
    audit(who, 'settings', 'azure', { credential_id: rec.credential_id, action_credential_id: rec.action_credential_id, refresh_hours: rec.refresh_hours, changed: ['credential_id', 'action_credential_id', 'refresh_hours'].filter((k) => prev[k] !== rec[k]) });
    return view(who.role);
  }

  function register(b0, who) {
    if (!isHuman(who.user)) throw bad('a person adds servers to the register', 403);
    const b = body(b0 || {}).list('ids', { required: true, max: 500, item: 'str', itemMax: 300, unique: true }).done();
    const sn = snap(); if (!sn) throw bad('read Azure first (Refresh)', 409);
    const A = analyse(sn), want = new Set(b.ids.map(low)), created = [], skipped = [];
    for (const v of A.vms.filter((x) => want.has(x.id))) {
      if (v.in_register) { skipped.push({ name: v.name, why: 'already in the register' }); continue; }
      const a = app.assets.create({ name: v.name, type: 'server', status: v.power === 'deallocated' ? 'in_stock' : 'in_use', site: 'Azure ' + (v.location || ''), mgmt_ip: v.ips[0] || undefined, os: v.os || v.os_type || undefined,
        model: v.size || undefined, vendor: 'Microsoft Azure', disk_gb: v.disk_gb || undefined, tags: ['azure', 'cloud'].concat(/windows/i.test(v.os_type || '') ? ['windows'] : []), notes: 'Azure VM ' + v.id }, who);
      created.push({ name: v.name, asset_id: a && a.id });
    }
    const missing = b.ids.filter((i) => !A.vms.some((v) => v.id === low(i)));
    audit(who, 'register', 'assets', { created: created.length, skipped: skipped.length, missing: missing.length });
    return { created, skipped, missing };
  }

  function propose(b0, who) {
    if (!isHuman(who.user)) throw bad('a person proposes a change; an AI or service identity never does', 403);
    const b = body(b0 || {}).str('vm_id', { required: true, max: 300 }).oneOf('action', Object.keys(ACTIONS), { required: true }).str('reason', { required: true, min: 5, max: 300 }).done();
    const id = low(b.vm_id); if (!VM_ID.test(id)) throw bad('vm_id: an Azure virtual machine resource id');
    const sn = snap(), vm = sn && (sn.raw.vms || []).find((v) => low(v.id) === id); if (!vm) throw bad('vm_id: not a server read from Azure - refresh first', 404);
    if (acts().all().some((a) => a.vm_id === id && a.state === 'pending')) throw bad('a change for ' + vm.name + ' is already waiting for approval', 409);
    const rec = { id: 'az_' + now().toString(36) + Math.random().toString(36).slice(2, 6), vm_id: id, vm_name: vm.name, action: b.action, reason: b.reason, state: 'pending', proposed_by: who.user, at: iso() };
    acts().put(rec); audit(who, 'action.propose', id, { vm: vm.name, action: b.action, reason: b.reason });
    return rec;
  }

  async function decide(id0, b0, who) {
    if (!isHuman(who.user)) throw bad('a person approves; an AI or service identity never does', 403);
    const id = param(id0, 'id'), b = body(b0 || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 }).done();
    const a = acts().get(id); if (!a) throw bad('change ' + id + ' not found', 404);
    if (a.state !== 'pending') throw bad('change ' + id + ' is ' + a.state, 409);
    if (low(a.proposed_by) === low(who.user)) throw bad('four-eyes: ' + who.user + ' proposed this change - another person approves it', 403);
    if (b.decision === 'reject') { acts().patch(id, (o) => Object.assign(o, { state: 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || null })); audit(who, 'action.reject', a.vm_id, { change: id, vm: a.vm_name, action: a.action }); return acts().get(id); }
    const S = settings(); if (!S.action_credential_id) throw bad('no action credential set: an administrator chooses a separate Azure credential with Virtual Machine Contributor in Settings', 409);
    acts().patch(id, (o) => Object.assign(o, { state: 'running', decided_by: who.user, decided_at: iso(), note: b.note || null }));
    audit(who, 'action.approve', a.vm_id, { change: id, vm: a.vm_name, action: a.action, proposed_by: a.proposed_by });
    let result;
    const c = openCred(S.action_credential_id);
    try {
      const bearer = await token(c);
      const r = await request(ARM + a.vm_id + '/' + ACTIONS[a.action] + '?api-version=2024-07-01', { method: 'POST', headers: { Authorization: 'Bearer ' + bearer, 'Content-Length': '0', Accept: 'application/json' }, timeout: 30000 });
      result = r.status === 200 || r.status === 202 ? { state: 'sent', http: r.status } : { state: 'failed', http: r.status, error: r.status === 403 ? 'the action credential is not allowed (Virtual Machine Contributor on the server?)' : 'Azure answered HTTP ' + r.status };
    } catch (e) { result = { state: 'failed', error: e.status === 502 ? e.message : 'Azure could not be reached (' + (e.code || 'error') + ')' }; }
    finally { c.release(); }
    acts().patch(id, (o) => Object.assign(o, result, { done_at: iso() }));
    audit(who, 'action.' + (result.state === 'sent' ? 'sent' : 'failed'), a.vm_id, { change: id, vm: a.vm_name, action: a.action, http: result.http || null, error: result.error || null });
    return acts().get(id);
  }

  async function tick() { const S = settings(), sn = snap(); if (!S.credential_id) return; if (sn && now() - Date.parse(sn.at) < S.refresh_hours * 3600000) return; await refresh({ user: 'system:azure-cloud', role: 'system', ip: '' }); }
  return { refresh, view, analyse, putSettings, register, propose, decide, tick, credentials, ACTIONS, Q };
}

function registerAzureCloud(srv, app, X, opts = {}) {
  srv.route('GET', '/azure-cloud', (ctx) => { ctx.need('viewer'); return X.view(ctx.who.role); });
  srv.route('POST', '/azure-cloud/refresh', async (ctx) => { ctx.need('operator'); if (!isHuman(ctx.who.user)) throw bad('a person refreshes', 403); body(ctx.body).done(); await X.refresh(ctx.who); return X.view(ctx.who.role); }, { maxBody: 256 });
  srv.route('PUT', '/azure-cloud/settings', (ctx) => { ctx.need('admin'); return X.putSettings(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/azure-cloud/register', (ctx) => { ctx.need('operator'); return X.register(ctx.body, ctx.who); }, { maxBody: 65536 });
  srv.route('POST', '/azure-cloud/actions', (ctx) => { ctx.need('operator'); return X.propose(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/azure-cloud/actions/:id/decide', (ctx) => { ctx.need('admin'); return X.decide(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  if (!(app.noTimers || opts.noTimer)) { const job = guardOf(app, 'azure.tick', () => X.tick()), t1 = setTimeout(job, 90000), t2 = setInterval(guardOf(app, 'azure.tick', () => X.tick()), 3600000); if (t1.unref) t1.unref(); if (t2.unref) t2.unref(); }
  (app.addons = app.addons || {}).azureCloud = X;
  return X;
}

module.exports = { createAzureCloud, registerAzureCloud, ACTIONS };
