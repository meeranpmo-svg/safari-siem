// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V inventory INGESTION. Direct WinRM from Node (WS-Man + NTLM/Kerberos message encryption) is not reliably
// implementable with the standard library, so Hyper-V hosts are inventoried by the Windows side and REPORTED here:
//   - the ITAM endpoint agent / SIEM Windows relay runs the read-only PowerShell in docs/DISCOVERY.md on each Hyper-V host
//     (Get-VM + Get-VMNetworkAdapter) and POSTs the JSON to /agent/hyperv (agent key), or
//   - an admin uploads the same JSON at POST /api/itam/discovery/hyperv/import.
// Direct WinRM collection is marked FUTURE.
//   normReport(body) → {host{name, fqdn, ip, os}, vms[{id, name, state, generation, os, ips[], macs[]}], collected_at}  (throws 400)
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const normMac = (m) => { const h = String(m || '').toLowerCase().replace(/[^0-9a-f]/g, ''); return h.length === 12 && /[1-9a-f]/.test(h) ? h.match(/.{2}/g).join(':') : null; };
const STATES = { running: 'on', off: 'off', saved: 'suspended', paused: 'suspended', 2: 'on', 3: 'off', 6: 'suspended', 9: 'suspended' };

function normReport(body) {
  const b = body && typeof body === 'object' ? body : {};
  const h = b.host && typeof b.host === 'object' ? b.host : {};
  const name = str(h.name || h.computer_name, 120);
  if (!name) throw bad('host.name is required');
  if (!Array.isArray(b.vms)) throw bad('vms must be a list');
  if (b.vms.length > 2000) throw bad('at most 2000 VMs per report');
  const host = { name, fqdn: str(h.fqdn, 255).toLowerCase() || null, ip: IP_RE.test(str(h.ip, 40)) ? str(h.ip, 40) : null, os: str(h.os, 200) || null };
  const vms = b.vms.map((v) => {
    const o = v && typeof v === 'object' ? v : {};
    const ips = (Array.isArray(o.ips) ? o.ips : []).map((x) => str(x, 40)).filter((x) => IP_RE.test(x)).slice(0, 32);
    const macs = (Array.isArray(o.macs) ? o.macs : []).map(normMac).filter(Boolean).slice(0, 16);
    const st = String(o.state == null ? '' : o.state).toLowerCase();
    return { id: str(o.vm_id || o.id, 64) || null, name: str(o.name, 200) || null, state: STATES[st] || (st ? st.slice(0, 20) : null), generation: Number(o.generation) || null, os: str(o.os, 200) || null, ips: [...new Set(ips)], macs: [...new Set(macs)] };
  }).filter((v) => v.name || v.id);
  const at = Date.parse(b.collected_at);
  return { host, vms, collected_at: Number.isFinite(at) ? new Date(at).toISOString() : new Date().toISOString() };
}

module.exports = { normReport, normMac };
