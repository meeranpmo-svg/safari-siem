// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Power control ({P} = /api/itam): restart / shut down / start for VMware ESXi hosts, VMware VMs, Nutanix AHV hosts and
 * Nutanix VMs - as change plans. The platform never powers anything itself: it reads the target from the read-only capacity
 * collection (virt-capacity.js), checks it can be done safely (the rest of the cluster can carry the running VMs, one
 * Nutanix node at a time, Tools for a clean guest shutdown, fresh data), writes the exact steps (PowerCLI / acli / CVM /
 * Redfish), an administrator who did not ask APPROVES (a failed check needs an accepted risk in words), a person RUNS it
 * and records it, and the next collection VERIFIES the result. A powered-off host is started through its out-of-band
 * controller (iDRAC / iLO / IPMI): the address is kept here (admin), the login stays with the engineer - curl / ipmitool
 * ask for the password, it is never stored and never on a command line.
 * Routes:
 *   GET    /virt/power                       viewer    targets (hosts, VMs) with their power state, plans, BMC addresses
 *   GET    /virt/power/requests?state · /:id viewer
 *   POST   /virt/power/requests              operator  {platform_id, target_id, action, reason, window?}
 *   POST   /virt/power/requests/:id/approve  approver  {comment?, accept_risk?}   not the requester, never a service identity
 *   POST   /virt/power/requests/:id/reject   approver  {reason}
 *   POST   /virt/power/requests/:id/cancel   operator  {reason}   the requester, or an administrator
 *   POST   /virt/power/requests/:id/applied  operator  {note}     approved, not expired, not the approver
 *   PUT    /virt/power/bmc/:key              admin     {address, kind}   out-of-band controller of a host
 *   DELETE /virt/power/bmc/:key              admin
 */
const { body, param, bad, isIp } = require('./check');
const { guardOf } = require('./errors');

const HOUR = 3600000;
const APPROVAL_TTL = 24 * HOUR;        // an approval is for the conditions the approver saw: after a day, ask again
const VERIFY_WINDOW = 2 * HOUR;        // applied but still not seen in the expected state after this: not verified
const STALE = 2 * HOUR;                // a collection older than this is shown as such in the checks
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);
const normUser = (u) => String(u == null ? '' : u).trim().toLowerCase();
const sameUser = (a, b) => !!normUser(a) && normUser(a) === normUser(b);
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || '').trim());
// objects are addressed by their vCenter / Prism ID, never by name (anyone who can rename a VM would control the command);
// an ID or address outside the expected shape gives no plan at all
const MOREF = /^[A-Za-z]+-[0-9A-Za-z_.-]{1,40}$/, UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const HOSTNAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const unsafe = (what) => httpErr(409, `the ${what} read from the platform has an unexpected format - no plan is written; do this one by hand`);
const vcId = (type, id) => { if (!MOREF.test(String(id))) throw unsafe('object id'); return `'${type}-${id}'`; };
const ntxId = (id) => { if (!UUID.test(String(id))) throw unsafe('object id'); return id; };
const addr = (a, what) => { const s = String(a || ''); if (!(isIp(s) || HOSTNAME.test(s))) throw unsafe(what); return s; };

const TYPES = { 'esxi-host': 'VMware ESXi host', 'vmware-vm': 'VMware VM', 'ahv-host': 'Nutanix AHV host', 'nutanix-vm': 'Nutanix VM' };
const ACTIONS = {
  host: { start: 'Power on', restart: 'Restart', shutdown: 'Shut down', 'power-cycle': 'Power-cycle (not responding)' },
  vm: { start: 'Power on', shutdown: 'Shut down the guest OS', restart: 'Restart the guest OS', 'power-off': 'Power off (hard)', reset: 'Reset (hard restart)' },
};
const BMC_KINDS = { idrac: 'Dell iDRAC', ilo: 'HPE iLO', redfish: 'Redfish (Supermicro / Nutanix NX / other)', ipmi: 'IPMI only' };
const REDFISH_SYSTEM = { idrac: 'System.Embedded.1', ilo: '1', redfish: '1' };
const STATES = ['proposed', 'approved', 'applied', 'verified', 'not-verified', 'rejected', 'cancelled'];
const OPEN = new Set(['proposed', 'approved', 'applied']);
const MGMT_VM = /\b(vcenter|vcsa|prism[- ]?central|cvm)\b/i;

function createVirtPower(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const latest = store.collection('virt_capacity'), plats = store.collection('virt_platforms');
  const plans = store.collection('virt_power'), bmcCol = store.collection('virt_power_bmc');
  const cap = () => (app.addons && app.addons.virtCapacity) || null;
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || 'system:virt-power', role: (who && who.role) || '', ip: (who && who.ip) || '', action, target, detail }); };

  /* ---- what can be powered: the latest read-only collection of every platform */
  function platformOf(pid) {
    const m = latest.get(pid); if (!m) return null;
    const p = plats.get(pid) || {};
    const at = m.at || null, failing = !!(m.last_error && (!at || String(m.last_error_at || '') >= at));
    // "stale": the state shown is the last one read, not the current one - a platform that is shut down (its hosts off,
    // vCenter / Prism unreachable) keeps showing its hosts as connected until a collection succeeds again
    return { m, id: pid, label: p.label || m.label || pid, kind: (p.kind || m.kind) === 'nutanix' ? 'nutanix' : 'vcenter', at, failing, stale: failing || !at || now() - Date.parse(at) > STALE };
  }
  // the host is known to be running: connected in a collection that is current and did not fail since
  const knownUp = (P, h) => h.state === 'connected' && !P.stale;
  function bmcOf(P, h) {
    const key = P.id + ':' + h.id, set = bmcCol.get(key);
    if (set) return { key, address: set.address, kind: set.kind, source: 'set by ' + set.by };
    if (h.bmc_ip) return { key, address: h.bmc_ip, kind: 'redfish', source: 'read from Prism' };
    return { key, address: null, kind: null, source: null };
  }
  function hostView(P, h) {
    const vms = (P.m.vms || []).filter((v) => v.host_id === h.id);
    return { key: P.id + ':' + h.id, platform_id: P.id, platform: P.label, type: P.kind === 'nutanix' ? 'ahv-host' : 'esxi-host', id: h.id, name: h.name, cluster: h.cluster || '',
      state: h.state || 'unknown', maintenance: !!h.maintenance, known_up: knownUp(P, h), ip: h.ip || null, cvm_ip: h.cvm_ip || null, vms: vms.length, vms_on: vms.filter((v) => v.power === 'on').length, bmc: bmcOf(P, h) };
  }
  function vmView(P, v, look) {
    const ad = look ? look(P.id, v) : { ips: Array.isArray(v.ips) ? v.ips : [], src: null }, h = (P.m.hosts || []).find((x) => x.id === v.host_id);
    return { key: P.id + ':' + v.id, platform_id: P.id, platform: P.label, type: P.kind === 'nutanix' ? 'nutanix-vm' : 'vmware-vm', id: v.id, name: v.name, host: h ? h.name : '', cluster: h ? h.cluster || '' : '',
      ips: ad.ips.slice(0, 4), ip_src: ad.src, host_ip: h ? h.ip || null : null, power: v.power || 'unknown', tools: P.kind === 'nutanix' ? null : v.tools || null, mem_gb: v.mem_mb ? Math.round(v.mem_mb / 1024) : null };
  }
  function targets() {
    const out = { platforms: [], hosts: [], vms: [] };
    let look = null; try { const C = cap(); if (C && C.vmAddrLookup) look = C.vmAddrLookup(); } catch (e) { look = null; if (app.log && app.log.every) app.log.every('virt-power:addr', 600000, 'warn', 'Power Control: VM addresses could not be indexed', { err: e.message }); }
    for (const m of latest.all()) {
      const P = platformOf(m.id); if (!P) continue;
      out.platforms.push({ id: P.id, label: P.label, kind: P.kind, at: P.at, stale: P.stale, error: P.failing ? m.last_error : null });
      for (const h of P.m.hosts || []) out.hosts.push(hostView(P, h));
      for (const v of P.m.vms || []) out.vms.push(vmView(P, v, look));
    }
    return out;
  }
  function resolve(pid, tid) {
    const P = platformOf(pid); if (!P) throw httpErr(404, 'platform not found or never collected - check Virtualization → Capacity');
    const h = (P.m.hosts || []).find((x) => x.id === tid); if (h) return { P, kind: 'host', obj: h, view: hostView(P, h) };
    const v = (P.m.vms || []).find((x) => x.id === tid); if (v) return { P, kind: 'vm', obj: v, view: vmView(P, v) };
    throw httpErr(404, 'no host or VM with this id in the latest collection of ' + P.label);
  }

  /* ---- the safety checks, computed from the collection; run again at approval time */
  function checks(T, action) {
    const { P, kind, obj } = T, out = [], add = (name, status, detail) => out.push({ name, status, detail: clip(detail, 600) });
    const age = P.at ? now() - Date.parse(P.at) : Infinity;
    add('Data is current', age <= STALE ? 'ok' : 'warn', P.at ? `collected ${Math.round(age / 60000)} min ago${age > STALE ? ' - confirm the state in ' + (P.kind === 'nutanix' ? 'Prism' : 'vCenter') + ' before running it' : ''}` : 'never collected');
    const others = plans.all((x) => x.id && OPEN.has(x.state) && x.platform_id === P.id && x.target_id !== obj.id);
    if (kind === 'host') {
      // peers = the same cluster only: a standalone ESXi host has no cluster, and other standalone hosts cannot take its VMs
      const hosts = P.m.hosts || [], peers = obj.cluster_id ? hosts.filter((x) => x.id !== obj.id && x.cluster_id === obj.cluster_id) : [];
      const running = (P.m.vms || []).filter((v) => v.host_id === obj.id && v.power === 'on');
      if (action === 'restart' || action === 'shutdown') {
        const up = peers.filter((x) => x.state === 'connected' && !x.maintenance);
        const need = running.reduce((a, v) => a + (v.mem_mb || 0), 0) * 1048576;
        const free = up.reduce((a, x) => a + Math.max(0, (x.mem_bytes || 0) - (x.mem_used_bytes || 0)), 0);
        add('Running VMs on this host', running.length ? 'info' : 'ok', running.length ? `${running.length} running (${Math.round(need / 1073741824)} GB): ${running.slice(0, 20).map((v) => v.name).join(', ')}${running.length > 20 ? ' …' : ''}` : 'none running');
        if (!peers.length) add('Somewhere to move them', running.length ? 'fail' : 'ok', running.length ? 'standalone host: its running VMs go down with it - shut them down first or move them to another cluster' : 'standalone host, nothing running');
        else if (!up.length) add('Somewhere to move them', running.length ? 'fail' : 'warn', 'no other host of the cluster is connected and out of maintenance mode');
        else if (running.length && up.some((x) => x.mem_bytes == null || x.mem_used_bytes == null)) add('The rest of the cluster can carry them', 'warn', 'memory use is not reported for every host - check the room in ' + (P.kind === 'nutanix' ? 'Prism' : 'vCenter'));
        else add('The rest of the cluster can carry them', need <= free ? 'ok' : 'fail', `${Math.round(free / 1073741824)} GB free on ${up.length} other host(s), ${Math.round(need / 1073741824)} GB needed`);
        const downPeers = peers.filter((x) => x.state !== 'connected' || x.maintenance);
        if (P.kind === 'nutanix') {
          // replication factor 2 survives one node: never take a second one away while another is down or being worked on
          const busy = others.filter((x) => x.target_type === 'ahv-host');
          add('One Nutanix node at a time', downPeers.length || busy.length ? 'fail' : 'ok', downPeers.length ? `${downPeers.map((x) => x.name).join(', ')} already down or in maintenance` : busy.length ? `power plan ${busy.map((x) => x.id).join(', ')} is still open on this cluster` : 'every other node is up');
          add('Data resiliency', 'info', 'the plan starts with "ncli cluster get-domain-fault-tolerance-status type=node" - stop if Current Fault Tolerance is 0');
          if (!obj.cvm_ip) add('CVM address', 'warn', 'not reported by Prism - find the CVM of this host before you start');
        } else {
          const cl = (P.m.clusters || []).find((c) => c.id === obj.cluster_id) || {};
          if (cl.drs === false && running.length) add('DRS moves the VMs', 'warn', 'DRS is off on this cluster: the plan moves each running VM by hand before maintenance mode');
          else if (cl.drs === true) add('DRS moves the VMs', 'ok', 'DRS is on: maintenance mode evacuates the host');
          if (downPeers.length) add('Other hosts of the cluster', 'warn', `${downPeers.map((x) => x.name).join(', ')} already down or in maintenance - HA has less room`);
          const busy = others.filter((x) => x.target_type === 'esxi-host');
          if (busy.length) add('Other open host plans', 'warn', `power plan ${busy.map((x) => x.id).join(', ')} is still open on this platform`);
        }
        const mgmt = running.filter((v) => MGMT_VM.test(v.name || ''));
        add('Management VMs', mgmt.length ? 'warn' : 'info', mgmt.length ? `${mgmt.map((v) => v.name).join(', ')} looks like a management VM (vCenter / Prism Central / CVM): make sure it moves, or do this from the host client` : 'if vCenter or Prism Central runs on this host, move it first');
      }
      if (action === 'start' || action === 'power-cycle') {
        const b = bmcOf(P, obj);
        if (obj.state === 'connected') add('Is it really off?', 'warn', `the last ${P.failing ? 'successful ' : ''}collection showed it connected${P.failing ? ' and the platform cannot be read now' : ''} - check the power state on the controller before you ${action === 'start' ? 'power it on' : 'power-cycle it'}`);
        add('Out-of-band controller', b.address ? 'ok' : 'warn', b.address ? `${b.address} (${BMC_KINDS[b.kind] || b.kind}, ${b.source})` : 'no iDRAC / iLO / IPMI address recorded - an administrator adds it on the Power control page, or use the server\'s console');
      }
    } else {
      const toolsNeeded = P.kind !== 'nutanix' && (action === 'shutdown' || action === 'restart');
      if (toolsNeeded) add('VMware Tools running', obj.tools === 'running' ? 'ok' : 'fail', obj.tools === 'running' ? 'a clean guest shutdown is possible' : `Tools ${obj.tools || 'not reported'}: a guest shutdown / restart is not possible - fix Tools, or ask for a hard power-off / reset (unsaved data is lost)`);
      if (P.kind === 'nutanix' && (action === 'shutdown' || action === 'restart')) add('Guest shutdown', 'info', 'acli sends an ACPI shutdown; a guest that ignores it stays on - check, and only then power off');
      if (action === 'power-off' || action === 'reset') add('Hard power operation', 'warn', 'like pulling the power cord: anything not written to disk is lost - prefer a guest shutdown / restart');
      if (MGMT_VM.test(obj.name || '')) add('Management VM', 'warn', `${obj.name} looks like a management VM (vCenter / Prism Central / CVM) - powering it changes how the platform itself is managed`);
    }
    return out;
  }

  /* ---- the plan text: built only from validated IDs and addresses (names go into titles and steps, never into commands) */
  function redfish(b, reset) {
    if (!b.address) return [{ lang: 'text', text: `# no out-of-band address recorded for this host: open its iDRAC / iLO / IPMI console and choose "${reset === 'On' ? 'Power on' : 'Power cycle'}"` }];
    const a = addr(b.address, 'controller address');
    if (b.kind === 'ipmi') return [{ lang: 'shell', text: `# IPMI: the password is read from the IPMI_PASSWORD variable (-E), never typed on the command line\nread -rs -p 'BMC password: ' IPMI_PASSWORD; export IPMI_PASSWORD\nipmitool -I lanplus -H ${a} -U '<your-bmc-login>' -E chassis power ${reset === 'On' ? 'on' : 'cycle'}\nunset IPMI_PASSWORD` }];
    return [{ lang: 'shell', text: `# Redfish (${BMC_KINDS[b.kind] || 'Redfish'}): curl asks for the password; --cacert is the controller's certificate (do not switch checking off)\ncurl --cacert ./bmc-${a}.pem -u '<your-bmc-login>' -X POST https://${a}/redfish/v1/Systems/${REDFISH_SYSTEM[b.kind] || '1'}/Actions/ComputerSystem.Reset -H 'Content-Type: application/json' -d '{"ResetType":"${reset}"}'\n# web console: https://${a}` }];
  }
  function planFor(T, action) {
    const { P, kind, obj } = T, ntx = P.kind === 'nutanix', label = (kind === 'host' ? ACTIONS.host : ACTIONS.vm)[action];
    const base = { title: `${label}: ${clip(obj.name, 120)} (${P.label})`, risk: 'medium', steps: [], commands: [], rollback: '' };
    if (kind === 'vm') {
      const vmc = { start: ['vm.on', 'Start-VM -VM $vm -Confirm:$false'], shutdown: ['vm.shutdown', 'Shutdown-VMGuest -VM $vm -Confirm:$false'], restart: ['vm.reboot', 'Restart-VMGuest -VM $vm -Confirm:$false'],
        'power-off': ['vm.off', 'Stop-VM -VM $vm -Confirm:$false'], reset: ['vm.reset', 'Restart-VM -VM $vm -Confirm:$false'] }[action];
      base.risk = action === 'power-off' || action === 'reset' ? 'high' : 'medium';
      base.steps = ['Tell the VM owner and the users of its service', `${label} ${clip(obj.name, 120)}`, 'Check the service answers again (start / restart) or is down as expected (shut down)'];
      base.commands = ntx ? [{ lang: 'acli', text: `# on any CVM, as nutanix\nacli vm.get ${ntxId(obj.id)}   # check it is the right VM\nacli ${vmc[0]} ${ntxId(obj.id)}` }]
        : [{ lang: 'powercli', text: `$vm = Get-VM -Id ${vcId('VirtualMachine', obj.id)}\n$vm | Select-Object Name, PowerState, VMHost   # check it is the right VM\n${vmc[1]}` }];
      base.rollback = action === 'start' ? 'Shut the guest down again if it was started by mistake.' : action === 'shutdown' || action === 'power-off' ? 'Start the VM again.' : 'None needed - if it does not come back, open its console and check the boot.';
      return base;
    }
    const b = bmcOf(P, obj);
    if (action === 'start' || action === 'power-cycle') {
      const reset = action === 'start' ? 'On' : 'ForceRestart';
      base.risk = action === 'power-cycle' ? 'high' : 'medium';
      base.steps = [action === 'start' ? 'Power the host on from its out-of-band controller' : 'Power-cycle the hung host from its out-of-band controller (anything still running on it stops hard)',
        ntx ? 'Wait until AHV and its CVM are up (Prism shows the host and the CVM)' : 'Wait until vCenter shows the host connected', 'Take it out of maintenance mode if it is in it'];
      base.commands = redfish(b, reset).concat(ntx ? [{ lang: 'acli', text: `# when the host and its CVM are back, on any CVM:\ncluster status | grep -v UP   # every service UP\nacli host.exit_maintenance_mode ${ntxId(obj.id)}` }]
        : [{ lang: 'powercli', text: `# when vCenter shows the host again:\n$h = Get-VMHost -Id ${vcId('HostSystem', obj.id)}\nif ($h.ConnectionState -eq 'Maintenance') { Set-VMHost -VMHost $h -State Connected -Confirm:$false }` }]);
      base.rollback = 'Shut the host down again from vCenter / Prism or the controller if it should have stayed off.';
      return base;
    }
    base.risk = 'high';
    const running = (P.m.vms || []).filter((v) => v.host_id === obj.id && v.power === 'on');
    if (ntx) {
      const hip = obj.ip ? addr(obj.ip, 'host address') : '<host address>', cip = obj.cvm_ip ? addr(obj.cvm_ip, 'CVM address') : '<CVM of this host>';
      base.steps = ['Check the cluster can lose this node (fault tolerance 1, every other node up)', 'Maintenance mode: the VMs live-migrate to the other hosts', 'Shut down this host\'s CVM cleanly', action === 'restart' ? 'Restart the AHV host' : 'Shut down the AHV host',
        action === 'restart' ? 'When the host and its CVM are back: leave maintenance mode, check every service is UP before any other node' : 'Leave it off; to bring it back use a "Power on" plan (out-of-band controller)'];
      base.commands = [{ lang: 'acli', text: `# 1. on any CVM, as nutanix - stop if Current Fault Tolerance is 0 for any component\nncli cluster get-domain-fault-tolerance-status type=node\n# 2. move the VMs off (waits until done)\nacli host.enter_maintenance_mode ${ntxId(obj.id)} wait=true` },
        { lang: 'shell', text: `# 3. on the CVM of this host (${cip}), as nutanix\ncvm_shutdown -P now\n# 4. on the AHV host (${hip}), as root, once the CVM is off\n${action === 'restart' ? 'reboot' : 'shutdown -h now'}` }].concat(action === 'restart' ? [{ lang: 'acli', text: `# 5. when the host and its CVM are back, on any CVM\ncluster status | grep -v UP   # every service UP\nacli host.exit_maintenance_mode ${ntxId(obj.id)}` }] : []);
      base.rollback = action === 'restart' ? 'If the host does not come back in 20 minutes: open its controller console' + (b.address ? ` (https://${addr(b.address, 'controller address')})` : '') + ', check the boot; once it is up run "acli host.exit_maintenance_mode". If the CVM does not start: "virsh start" it on the host.'
        : 'Power the host on from its controller, wait for the CVM, then acli host.exit_maintenance_mode ' + ntxId(obj.id) + '.';
      return base;
    }
    const cl = (P.m.clusters || []).find((c) => c.id === obj.cluster_id) || {};
    const peers = (P.m.hosts || []).filter((x) => x.id !== obj.id && x.cluster_id && x.cluster_id === obj.cluster_id && x.state === 'connected' && !x.maintenance);
    const moves = [];
    if (cl.drs !== true && running.length && peers.length) {
      // DRS off: spread the running VMs by memory over the peers with the most free memory (largest VM first)
      const free = new Map(peers.map((x) => [x.id, Math.max(0, (x.mem_bytes || 0) - (x.mem_used_bytes || 0))]));
      for (const v of running.slice().sort((a, c) => (c.mem_mb || 0) - (a.mem_mb || 0))) { const dest = [...free.entries()].sort((a, c) => c[1] - a[1])[0]; moves.push(`Move-VM -VM (Get-VM -Id ${vcId('VirtualMachine', v.id)}) -Destination (Get-VMHost -Id ${vcId('HostSystem', dest[0])})`); free.set(dest[0], dest[1] - (v.mem_mb || 0) * 1048576); }
    }
    base.steps = (moves.length ? [`DRS is off: move the ${running.length} running VM(s) to the other hosts`] : []).concat(['Maintenance mode (DRS moves the running VMs)', action === 'restart' ? 'Restart the host' : 'Shut the host down',
      action === 'restart' ? 'When it is back: leave maintenance mode; check HA shows it protected' : 'Leave it off; to bring it back use a "Power on" plan (out-of-band controller)']);
    base.commands = (moves.length ? [{ lang: 'powercli', text: '# DRS is off on this cluster: move the running VMs first\n' + moves.join('\n') }] : []).concat([{ lang: 'powercli', text: `$h = Get-VMHost -Id ${vcId('HostSystem', obj.id)}\n# vSAN cluster: add -VsanDataMigrationMode EnsureAccessibility\nSet-VMHost -VMHost $h -State Maintenance -Evacuate:$true -Confirm:$false\n${action === 'restart' ? 'Restart-VMHost -VMHost $h -Confirm:$false' : 'Stop-VMHost -VMHost $h -Confirm:$false'}` }])
      .concat(action === 'restart' ? [{ lang: 'powercli', text: `# when vCenter shows the host again (state Maintenance)\nSet-VMHost -VMHost (Get-VMHost -Id ${vcId('HostSystem', obj.id)}) -State Connected -Confirm:$false` }] : []);
    base.rollback = action === 'restart' ? 'If the host does not come back in 20 minutes: open its controller console' + (b.address ? ` (https://${addr(b.address, 'controller address')})` : '') + ', check the boot; then Set-VMHost -State Connected.'
      : 'Power the host on from its controller, then Set-VMHost -State Connected.';
    return base;
  }

  /* ---- requests and the four-eyes path */
  function nextId() { const c = store.collection('counters'), n = ((c.get('virt_power') || {}).n || 0) + 1; c.put({ id: 'virt_power', n }); return 'VPW-' + String(n).padStart(4, '0'); }
  function allowed(T, action) {
    if (T.kind === 'vm') {
      if (!ACTIONS.vm[action]) throw bad(`action must be one of: ${Object.keys(ACTIONS.vm).join(', ')} for a VM`);
      const on = T.obj.power === 'on';
      if (action === 'start' && on) throw httpErr(409, `${T.obj.name} is already running`);
      if (action !== 'start' && !on) throw httpErr(409, `${T.obj.name} is not running (${T.obj.power || 'state unknown'})`);
      // a guest shutdown / restart goes through VMware Tools: without them it cannot happen at all, whoever accepts the risk
      if (T.P.kind !== 'nutanix' && (action === 'shutdown' || action === 'restart') && T.obj.tools !== 'running') throw httpErr(409, `VMware Tools are ${T.obj.tools || 'not reported'} on ${T.obj.name}: a guest ${action} is not possible - fix Tools, or ask for a hard ${action === 'shutdown' ? 'power-off' : 'reset'} (unsaved data is lost)`);
      return;
    }
    if (!ACTIONS.host[action]) throw bad(`action must be one of: ${Object.keys(ACTIONS.host).join(', ')} for a host`);
    const up = T.obj.state === 'connected';
    // power on is refused only when the host is KNOWN to be running: a stale or failing collection (the platform itself
    // shut down) cannot say it is still on
    if (action === 'start' && knownUp(T.P, T.obj)) throw httpErr(409, `${T.obj.name} is already running (connected in a collection ${Math.round((now() - Date.parse(T.P.at)) / 60000)} min ago)`);
    if ((action === 'restart' || action === 'shutdown') && !up) throw httpErr(409, `${T.obj.name} is ${T.obj.state || 'not connected'}: it cannot be put into maintenance mode - use "Power on" or "Power-cycle" (out-of-band controller)`);
    if (action === 'power-cycle' && knownUp(T.P, T.obj)) throw httpErr(409, `${T.obj.name} is connected: use "restart" (it moves the VMs off first) instead of a hard power-cycle`);
  }
  function request(b, who) {
    const T = resolve(b.platform_id, b.target_id);
    allowed(T, b.action);
    const open = plans.all((x) => x.platform_id === T.P.id && x.target_id === T.obj.id && OPEN.has(x.state))[0];
    if (open) throw httpErr(409, `power plan ${open.id} is already open for ${T.obj.name} (${open.state}) - finish or cancel it first`);
    const p = planFor(T, b.action), pre = checks(T, b.action);
    const rec = Object.assign({ id: nextId(), state: 'proposed', platform_id: T.P.id, platform: T.P.label, platform_kind: T.P.kind, target_id: T.obj.id, target_type: T.view.type, target: clip(T.obj.name, 200),
      action: b.action, reason: b.reason, window: b.window || '', requested_by: who.user, requested_role: who.role, requested_at: iso(), checks: pre, blocked: pre.some((c) => c.status === 'fail') }, p);
    plans.put(rec);
    audit(who, 'virt.power.request', rec.id, { target: rec.target, type: rec.target_type, action: rec.action, platform: rec.platform, blocked: rec.blocked });
    return rec;
  }
  function must(id) { const p = plans.get(id); if (!p) throw httpErr(404, 'power plan not found'); return p; }
  function decide(id, who, approve, b) {
    const p = must(id);
    if (p.state !== 'proposed') throw httpErr(409, `power plan is ${p.state}`);
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot approve or reject a power plan - a named person does');
    if (sameUser(p.requested_by, who.user)) throw httpErr(403, 'four-eyes: the person who asked for the power action cannot approve or reject it');
    const at = iso();
    if (!approve) {
      plans.patch(p.id, (x) => { x.state = 'rejected'; x.decided_by = who.user; x.decided_at = at; x.comment = b.reason; return x; });
      audit(who, 'virt.power.reject', p.id, { reason: b.reason });
      return plans.get(p.id);
    }
    // the checks again, on the data as it is now: the request may be hours old
    let T; try { T = resolve(p.platform_id, p.target_id); allowed(T, p.action); } catch (e) { if (e.status === 404 || e.status === 409) throw httpErr(409, 'cannot approve: ' + e.message); throw e; }
    const pre = checks(T, p.action), fails = pre.filter((c) => c.status === 'fail');
    if (fails.length && !b.accept_risk) throw Object.assign(httpErr(409, `${fails.length} check(s) failed: ${fails.map((c) => c.name + ' - ' + c.detail).join('; ')}. Fix them, or approve with "accept_risk" saying why it is acceptable`), { checks: pre });
    const fresh = planFor(T, p.action);
    plans.patch(p.id, (x) => { Object.assign(x, fresh); x.state = 'approved'; x.decided_by = who.user; x.decided_at = at; x.comment = b.comment || ''; x.checks = pre; x.blocked = !!fails.length; x.accepted_risk = fails.length ? b.accept_risk : ''; x.expires_at = iso(now() + APPROVAL_TTL); return x; });
    audit(who, 'virt.power.approve', p.id, { comment: b.comment || '', failed_checks: fails.map((c) => c.name), accepted_risk: fails.length ? b.accept_risk : '' });
    return plans.get(p.id);
  }
  function cancel(id, who, reason) {
    const p = must(id);
    if (p.state !== 'proposed' && p.state !== 'approved') throw httpErr(409, `power plan is ${p.state} - only a plan that was not run can be cancelled`);
    if (!sameUser(p.requested_by, who.user) && who.role !== 'admin') throw httpErr(403, 'only the person who asked, or an administrator, can cancel it');
    plans.patch(p.id, (x) => { x.state = 'cancelled'; x.cancelled_by = who.user; x.cancelled_at = iso(); x.comment = reason; return x; });
    audit(who, 'virt.power.cancel', p.id, { reason });
    return plans.get(p.id);
  }
  let collecting = null, lastRun = 0;
  function collectSoon() {
    const C = cap(); if (!C || collecting || now() - lastRun < 10 * 60000) return;
    lastRun = now();
    collecting = Promise.resolve().then(() => C.run({ user: 'system:virt-power', role: 'operator', ip: '' }))
      .catch((e) => { if (app.log) app.log.every('virt-power-collect', 600000, 'warn', 'virt-power: verification collection failed', { err: String((e && e.message) || e).slice(0, 200) }); })
      .finally(() => { collecting = null; });
  }
  function applied(id, who, note) {
    const p = must(id);
    if (p.state !== 'approved') throw httpErr(409, 'only an approved power plan can be recorded as run' + (p.state === 'proposed' ? ' - it still needs approval' : ''));
    if (sameUser(p.decided_by, who.user)) throw httpErr(403, 'four-eyes: you approved this plan - the person who runs it records it');
    if (p.expires_at && now() > Date.parse(p.expires_at)) throw httpErr(409, `the approval expired at ${p.expires_at} (approvals last 24 h, the conditions may have changed) - ask again`);
    plans.patch(p.id, (x) => { x.state = 'applied'; x.applied_by = who.user; x.applied_at = iso(); x.note = note; return x; });
    audit(who, 'virt.power.applied', p.id, { note });
    collectSoon();
    return plans.get(p.id);
  }

  /* ---- verification: the first collection after "applied" must show the expected state */
  function expected(p, T) {
    const o = T.obj;
    if (p.target_type.endsWith('-vm')) { const want = p.action === 'shutdown' || p.action === 'power-off' ? 'off' : 'on'; return o.power === want ? { ok: true, note: `${o.name} is ${want}` } : { ok: false, note: `${o.name} is ${o.power}, expected ${want}` }; }
    if (p.action === 'shutdown') return o.state !== 'connected' ? { ok: true, note: `${o.name} is ${o.state} (off)` } : { ok: false, note: `${o.name} is still connected` };
    if (o.state !== 'connected') return { ok: false, note: `${o.name} is ${o.state}` };
    return o.maintenance ? { ok: false, wait: true, note: `${o.name} is back but still in maintenance mode - take it out` } : { ok: true, note: `${o.name} is connected and out of maintenance mode` };
  }
  function verifyTick() {
    const t = now(); let waiting = false;
    for (const p of plans.all((x) => x.state === 'applied')) {
      const P = platformOf(p.platform_id), late = t - Date.parse(p.applied_at) > VERIFY_WINDOW;
      const o = P && ((P.m.hosts || []).find((x) => x.id === p.target_id) || (P.m.vms || []).find((x) => x.id === p.target_id)), T = o ? { obj: o } : null;
      const fresh = P && P.at && P.at > p.applied_at;
      if (fresh && T) {
        const r = expected(p, T);
        if (r.ok) { plans.patch(p.id, (x) => { x.state = 'verified'; x.verified_at = iso(t); x.verify_note = r.note; return x; }); audit(null, 'virt.power.verified', p.id, { note: r.note }); continue; }
        if (!late) { plans.patch(p.id, (x) => { x.verify_note = r.note; return x; }); waiting = true; continue; }
        plans.patch(p.id, (x) => { x.state = 'not-verified'; x.verified_at = iso(t); x.verify_note = r.note; return x; }); audit(null, 'virt.power.not-verified', p.id, { note: r.note }); continue;
      }
      if (late) { const note = !P ? 'the platform is no longer collected' : !T ? 'the target is no longer in the collection' : 'no collection since it was run'; plans.patch(p.id, (x) => { x.state = 'not-verified'; x.verified_at = iso(t); x.verify_note = note; return x; }); audit(null, 'virt.power.not-verified', p.id, { note }); continue; }
      waiting = true;
    }
    if (waiting) collectSoon();
  }

  function setBmc(key, b, who) {
    const [pid, ...rest] = key.split(':'), hid = rest.join(':'), P = platformOf(pid);
    if (!P || !(P.m.hosts || []).some((h) => h.id === hid)) throw httpErr(404, 'host not found in the latest collection');
    const rec = { id: key, address: b.address, kind: b.kind, by: who.user, at: iso() };
    bmcCol.put(rec); audit(who, 'virt.power.bmc.set', key, { address: b.address, kind: b.kind });
    return rec;
  }
  function delBmc(key, who) { if (!bmcCol.get(key)) throw httpErr(404, 'no controller address recorded for this host'); bmcCol.remove(key); audit(who, 'virt.power.bmc.delete', key, {}); return { ok: true }; }
  const list = (st) => plans.all((x) => !st || x.state === st).sort((a, c) => (a.requested_at < c.requested_at ? 1 : -1));
  return { targets, request, decide, cancel, applied, verifyTick, setBmc, delBmc, list, get: must, checks: (pid, tid, a) => checks(resolve(pid, tid), a) };
}

function registerVirtPower(srv, app, opts = {}) {
  const V = createVirtPower(app, opts);
  srv.route('GET', '/virt/power', (ctx) => { ctx.need('viewer'); return Object.assign({ generated: Date.now(), installed: !!(app.addons && app.addons.virtCapacity), types: TYPES, actions: ACTIONS, bmc_kinds: BMC_KINDS, approval_hours: APPROVAL_TTL / HOUR }, V.targets(), { plans: V.list().slice(0, 200) }); });
  srv.route('GET', '/virt/power/requests', (ctx) => { ctx.need('viewer'); const st = (ctx.query || {}).state; if (st && !STATES.includes(st)) throw bad('state must be one of: ' + STATES.join(', ')); return { plans: V.list(st) }; });
  srv.route('GET', '/virt/power/requests/:id', (ctx) => { ctx.need('viewer'); return V.get(param(ctx.params.id)); });
  srv.route('POST', '/virt/power/requests', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('platform_id', { required: true, id: true }).str('target_id', { required: true, id: true }).str('action', { required: true, max: 20, re: /^[a-z-]+$/ })
      .str('reason', { required: true, min: 10, max: 1000 }).str('window', { max: 200 }).done();
    return V.request(b, ctx.who);
  });
  srv.route('POST', '/virt/power/requests/:id/approve', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:virt') : ctx.need('admin')); const b = body(ctx.body).str('comment', { max: 500 }).str('accept_risk', { min: 10, max: 1000 }).done(); return V.decide(param(ctx.params.id), ctx.who, true, b); });
  srv.route('POST', '/virt/power/requests/:id/reject', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:virt') : ctx.need('admin')); const b = body(ctx.body).str('reason', { required: true, max: 500 }).done(); return V.decide(param(ctx.params.id), ctx.who, false, b); });
  srv.route('POST', '/virt/power/requests/:id/cancel', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('reason', { required: true, max: 500 }).done(); return V.cancel(param(ctx.params.id), ctx.who, b.reason); });
  srv.route('POST', '/virt/power/requests/:id/applied', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('note', { required: true, max: 1000 }).done(); return V.applied(param(ctx.params.id), ctx.who, b.note); });
  // the controller of a host is a security-relevant setting: administrators only
  srv.route('PUT', '/virt/power/bmc/:key', (ctx) => { ctx.need('admin'); const b = body(ctx.body).str('address', { required: true, host: true, max: 253 }).oneOf('kind', Object.keys(BMC_KINDS), { required: true }).done(); return V.setBmc(param(ctx.params.key, 'key'), b, ctx.who); });
  srv.route('DELETE', '/virt/power/bmc/:key', (ctx) => { ctx.need('admin'); return V.delBmc(param(ctx.params.key, 'key'), ctx.who); });
  if (!opts.noTimer) { const t = setInterval(guardOf(app, 'virt-power.verify', () => V.verifyTick()), 2 * 60000); if (t.unref) t.unref(); }
  (app.addons = app.addons || {}).virtPower = V;
  return V;
}

module.exports = { createVirtPower, registerVirtPower, TYPES, ACTIONS, BMC_KINDS };
