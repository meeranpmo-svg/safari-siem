// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Azure VM inventory — READ ONLY, via Azure Resource Graph with an app registration (client credentials).
// Least privilege: assign the app the built-in "Reader" role on the subscriptions (or management group) to inventory.
// The client secret is write-only in the vault.
//   token: POST {login}/{tenant}/oauth2/v2.0/token  (grant_type=client_credentials, scope=https://management.azure.com/.default)
//   query: POST {arm}/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01  {subscriptions?, query, options}
//   collect(cred, {login_base, arm_base, request}) → {ok, vms[{id, name, location, resource_group, subscription, os_type,
//                                                     size, power, ips[], macs[]}]} | {ok:false, error_class}
// The KQL below joins VMs to their NICs for private IPs and MAC addresses ("verify" against the tenant: the
// powerState projection needs instance view data that Resource Graph does not always carry).
const httpc = require('../httpc');
const diag = require('../diag');

const QUERY = [
  "Resources | where type =~ 'microsoft.compute/virtualmachines'",
  '| extend nics = properties.networkProfile.networkInterfaces | mv-expand nic = nics | extend nicId = tolower(tostring(nic.id))',
  "| join kind=leftouter (Resources | where type =~ 'microsoft.network/networkinterfaces' | extend nicId = tolower(id), mac = tostring(properties.macAddress)",
  '  | mv-expand ipc = properties.ipConfigurations | extend privateIp = tostring(ipc.properties.privateIPAddress) | project nicId, mac, privateIp) on nicId',
  '| project id, name, location, resourceGroup, subscriptionId, osType = tostring(properties.storageProfile.osDisk.osType),',
  '  vmSize = tostring(properties.hardwareProfile.vmSize), powerState = tostring(properties.extended.instanceView.powerState.code), mac, privateIp',
].join('\n');

function errorClass(e) { return ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol'; }
const normMac = (m) => { const h = String(m || '').toLowerCase().replace(/[^0-9a-f]/g, ''); return h.length === 12 ? h.match(/.{2}/g).join(':') : null; };

async function token(cred, o) {
  const login = (o.login_base || 'https://login.microsoftonline.com').replace(/\/+$/, '');
  const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: cred.target.client_id, client_secret: cred.secret.client_secret, scope: 'https://management.azure.com/.default' }).toString();
  const r = await (o.request || httpc.request)(`${login}/${encodeURIComponent(cred.target.tenant_id)}/oauth2/v2.0/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form, caFile: o.caFile, timeoutMs: o.timeoutMs || 30000 });
  if (r.status === 400 || r.status === 401 || r.status === 403) throw diag.err('auth', 'Azure AD rejected the app credentials', { stage: 'auth', http: r.status, tlsTrusted: true });
  if (r.status >= 300 || !r.json || !r.json.access_token) throw diag.err('protocol', `Azure AD token HTTP ${r.status}`, { stage: 'auth', http: r.status, tlsTrusted: true });
  return r.json.access_token;
}

async function query(cred, o, bearer, q, skipToken, top) {
  const arm = (o.arm_base || 'https://management.azure.com').replace(/\/+$/, '');
  const body = { query: q, options: Object.assign({ $top: top || 1000 }, skipToken ? { $skipToken: skipToken } : {}) };
  if (cred.target.subscriptions && cred.target.subscriptions.length) body.subscriptions = cred.target.subscriptions;
  const r = await (o.request || httpc.request)(`${arm}/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01`, { method: 'POST', headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body), caFile: o.caFile, timeoutMs: o.timeoutMs || 60000 });
  if (r.status === 401 || r.status === 403) throw diag.err('authz', 'Azure Resource Graph not authorised (Reader role?)', { stage: 'authz', http: r.status, tlsTrusted: true });
  if (r.status >= 300 || !r.json) throw diag.err('protocol', `Resource Graph HTTP ${r.status}`, { stage: 'read', http: r.status, tlsTrusted: true });
  return r.json;
}

function rowsOf(j) {
  if (Array.isArray(j.data)) return j.data;
  if (j.data && Array.isArray(j.data.rows) && Array.isArray(j.data.columns)) { const cols = j.data.columns.map((c) => c.name); return j.data.rows.map((r) => Object.fromEntries(cols.map((c, i) => [c, r[i]]))); }
  return [];
}

// one VM per id (the NIC join yields one row per NIC/ip configuration)
function foldVms(rows) {
  const by = new Map();
  for (const r of rows) {
    const id = String(r.id || '').toLowerCase();
    if (!id) continue;
    const v = by.get(id) || { id, name: r.name || null, location: r.location || null, resource_group: r.resourceGroup || null, subscription: r.subscriptionId || null, os_type: r.osType || null, size: r.vmSize || null, power: r.powerState ? String(r.powerState).replace(/^PowerState\//i, '') : null, ips: [], macs: [] };
    if (r.privateIp && /^\d{1,3}(\.\d{1,3}){3}$/.test(r.privateIp) && !v.ips.includes(r.privateIp)) v.ips.push(r.privateIp);
    const m = normMac(r.mac); if (m && !v.macs.includes(m)) v.macs.push(m);
    by.set(id, v);
  }
  return [...by.values()];
}

async function collect(cred, o = {}) {
  const t0 = Date.now();
  try {
    const bearer = await token(cred, o);
    const rows = []; let skip = null; let pages = 0;
    do { const j = await query(cred, o, bearer, QUERY, skip, 1000); rows.push(...rowsOf(j)); skip = j.$skipToken || null; pages++; } while (skip && pages < 100);
    return { ok: true, vms: foldVms(rows), latency_ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: errorClass(e), latency_ms: Date.now() - t0 }; }
}

async function test(cred, o = {}) {
  const t0 = Date.now();
  try { const b = await token(cred, o); await query(cred, o, b, 'Resources | project id | limit 1', null, 1); return diag.result('azure', { latency_ms: Date.now() - t0, http: 200 }); } catch (e) { return diag.fromError('azure', e, { latency_ms: Date.now() - t0 }); }
}

module.exports = { collect, test, foldVms, rowsOf, QUERY };
