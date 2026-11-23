// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A fake vCenter answering the vSphere Web Services calls engine/virt-capacity.js makes (tests and page checks).
const GiB = 1024 ** 3;
function prop(name, val) { return `<propSet><name>${name}</name><val>${val}</val></propSet>`; }
function obj(type, id, props) { return `<objects><obj type="${type}">${id}</obj>${Object.entries(props).map(([k, v]) => prop(k, v)).join('')}</objects>`; }
const DATA = {
  HostSystem: [obj('HostSystem', 'host-11', { name: ('esx01.' + 'corp-hq.com'), parent: 'domain-c7', 'runtime.connectionState': 'connected', 'runtime.inMaintenanceMode': 'false', 'summary.hardware.vendor': 'Dell Inc.', 'summary.hardware.model': 'PowerEdge R750',
    'summary.hardware.cpuModel': 'Intel(R) Xeon(R) Gold 6342 CPU @ 2.80GHz', 'summary.hardware.cpuMhz': 2800, 'summary.hardware.numCpuPkgs': 2, 'summary.hardware.numCpuCores': 48, 'summary.hardware.numCpuThreads': 96, 'summary.hardware.memorySize': 768 * GiB,
    'summary.quickStats.overallCpuUsage': 40320, 'summary.quickStats.overallMemoryUsage': 460 * 1024, 'summary.config.product.fullName': 'VMware ESXi 7.0.3 build-21930508' }),
  obj('HostSystem', 'host-12', { name: ('esx02.' + 'corp-hq.com'), parent: 'domain-c7', 'runtime.connectionState': 'connected', 'runtime.inMaintenanceMode': 'false', 'summary.hardware.vendor': 'Dell Inc.', 'summary.hardware.model': 'PowerEdge R750',
    'summary.hardware.cpuModel': 'Intel(R) Xeon(R) Gold 6342 CPU @ 2.80GHz', 'summary.hardware.cpuMhz': 2800, 'summary.hardware.numCpuPkgs': 2, 'summary.hardware.numCpuCores': 48, 'summary.hardware.numCpuThreads': 96, 'summary.hardware.memorySize': 768 * GiB,
    'summary.quickStats.overallCpuUsage': 26880, 'summary.quickStats.overallMemoryUsage': 380 * 1024, 'summary.config.product.fullName': 'VMware ESXi 7.0.3 build-21930508' })],
  ClusterComputeResource: [obj('ClusterComputeResource', 'domain-c7', { name: 'RUH-PROD', 'summary.numHosts': 2, 'summary.totalCpu': 268800, 'summary.totalMemory': 1536 * GiB, 'summary.effectiveCpu': 250000, 'summary.effectiveMemory': 1400 * 1024 })],
  Datastore: [obj('Datastore', 'datastore-1', { 'summary.name': 'VSAN-RUH', 'summary.type': 'vsan', 'summary.capacity': 40 * 1024 * GiB, 'summary.freeSpace': 14 * 1024 * GiB, 'summary.uncommitted': 6 * 1024 * GiB, 'summary.accessible': 'true' })],
  VirtualMachine: Array.from({ length: 30 }, (_, i) => obj('VirtualMachine', 'vm-' + (100 + i), { name: 'APP-' + i, 'config.instanceUuid': '5003aaaa-0000-0000-0000-0000000000' + String(i).padStart(2, '0'), 'config.template': 'false', 'config.guestFullName': 'Microsoft Windows Server 2022',
    'config.hardware.numCPU': 8, 'config.hardware.memoryMB': 32768, 'runtime.powerState': i < 28 ? 'poweredOn' : 'poweredOff', 'runtime.host': i % 2 ? 'host-12' : 'host-11', 'summary.storage.committed': 200 * GiB, 'summary.storage.uncommitted': 50 * GiB,
    'summary.quickStats.overallCpuUsage': 1200, 'summary.quickStats.guestMemoryUsage': 16000 })).concat([obj('VirtualMachine', 'vm-900', { name: 'TPL-WIN', 'config.template': 'true', 'config.hardware.numCPU': 2, 'config.hardware.memoryMB': 4096, 'runtime.powerState': 'poweredOff' })]),
};
const snapTree = (list) => `<VirtualMachineSnapshotTree>${list.map((t) => `<name>s</name><createTime>${t}</createTime>`).join('<childSnapshotList>')}${list.slice(1).map(() => '</childSnapshotList>').join('')}</VirtualMachineSnapshotTree>`;
const HEALTH = {
  HostSystem: [obj('HostSystem', 'host-11', { overallStatus: 'green' }), obj('HostSystem', 'host-12', { overallStatus: 'red' })],
  ClusterComputeResource: [obj('ClusterComputeResource', 'domain-c7', { overallStatus: 'yellow', 'configuration.dasConfig.enabled': 'false', 'configuration.drsConfig.enabled': 'true' })],
  Datastore: [obj('Datastore', 'datastore-1', { overallStatus: 'green' })],
  VirtualMachine: [obj('VirtualMachine', 'vm-101', { 'runtime.consolidationNeeded': 'true', 'guest.toolsRunningStatus': 'guestToolsNotRunning', 'snapshot.rootSnapshotList': snapTree(['2026-06-01T10:00:00Z', '2026-07-20T10:00:00Z']) }),
    obj('VirtualMachine', 'vm-102', { 'runtime.consolidationNeeded': 'false', 'guest.toolsRunningStatus': 'guestToolsRunning' })],
};
const nic = (dev, pg, ip) => `<HostVirtualNic><device>${dev}</device><key>key-${dev}</key><portgroup>${pg}</portgroup><spec><ip><dhcp>false</dhcp><ipAddress>${ip}</ipAddress><subnetMask>255.255.255.0</subnetMask></ip><ipV6Config><ipV6Address><ipAddress>fe80::1</ipAddress></ipV6Address></ipV6Config><mac>00:50:56:00:00:01</mac></spec></HostVirtualNic>`;
const VNIC = [`<objects><obj type="HostSystem">host-11</obj><propSet><name>name</name><val>esx01.corp-hq.com</val></propSet><propSet><name>config.network.vnic</name><val xsi:type="ArrayOfHostVirtualNic">${nic('vmk1', 'vMotion', '10.200.0.11')}${nic('vmk0', 'Management Network', '10.100.5.11')}</val></propSet></objects>`,
  `<objects><obj type="HostSystem">host-12</obj><propSet><name>name</name><val>esx02.corp-hq.com</val></propSet><propSet><name>config.network.vnic</name><val xsi:type="ArrayOfHostVirtualNic">${nic('vmk2', 'NFS', '10.250.0.12')}${nic('vmk0', 'MGMT-VLAN100', '10.100.5.12')}</val></propSet></objects>`];
function fakeVc(calls, o = {}) {
  let views = 0;
  return async (url, req) => {
    const m = /<soapenv:Body><(\w+)/.exec(req.body)[1];
    calls.push({ m, cookie: req.headers.Cookie || '', url });
    const wrap = (inner) => ({ status: 200, headers: m === 'Login' ? { 'set-cookie': ['vmware_soap_session="abc123"; Path=/; HttpOnly'] } : {}, text: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><${m}Response xmlns="urn:vim25">${inner}</${m}Response></soapenv:Body></soapenv:Envelope>` });
    const fault = (cls, msg) => ({ status: 500, headers: {}, text: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>${msg}</faultstring><detail><${cls}Fault xmlns="urn:vim25"/></detail></soapenv:Fault></soapenv:Body></soapenv:Envelope>` });
    if (m === 'RetrieveServiceContent') return wrap('<returnval><rootFolder type="Folder">group-d1</rootFolder><propertyCollector type="PropertyCollector">propertyCollector</propertyCollector><viewManager type="ViewManager">ViewManager</viewManager><sessionManager type="SessionManager">SessionManager</sessionManager></returnval>');
    if (m === 'Login') return /<password>Vc-pass-1<\/password>/.test(req.body) ? wrap('<returnval><userName>svc</userName></returnval>') : fault('InvalidLogin', 'Cannot complete login due to an incorrect user name or password.');
    if (!/vmware_soap_session="abc123"/.test(req.headers.Cookie || '')) return fault('NotAuthenticated', 'The session is not authenticated.');
    if (m === 'CreateContainerView') { const t = /<type>(\w+)<\/type>/.exec(req.body)[1]; return wrap(`<returnval type="ContainerView">session[x]view-${t}-${++views}</returnval>`); }
    if (m === 'RetrievePropertiesEx') {
      const t = /view-(\w+)-/.exec(req.body)[1];
      // host networking: esx01 has vMotion (vmk1) listed before Management (vmk0); esx02's management port group is not
      // called "Management", so vmk0 is taken. o.noVnic = a role that may not read host configuration.
      if (/config\.network\.vnic/.test(req.body)) return o.noVnic ? fault('NoPermission', 'Permission to perform this operation was denied.') : wrap(`<returnval>${VNIC.join('')}</returnval>`);
      if (/hardware\.systemInfo\.serialNumber/.test(req.body)) return o.oldVc ? fault('InvalidProperty', 'InvalidProperty') : wrap(`<returnval>${obj('HostSystem', 'host-11', { 'hardware.systemInfo.serialNumber': 'SVC-TAG-01' })}${obj('HostSystem', 'host-12', { 'hardware.systemInfo.serialNumber': 'SVC-TAG-02' })}</returnval>`);
      // health properties (virt-capacity HEALTH): host-12 red, HA off on the cluster, snapshots / consolidation / Tools on VMs
      if (/overallStatus|runtime\.consolidationNeeded/.test(req.body) && !o.noHealth) return wrap(`<returnval>${(HEALTH[t] || []).join('')}</returnval>`);
      if (/overallStatus|runtime\.consolidationNeeded/.test(req.body)) return fault('InvalidProperty', 'InvalidProperty');
      const all = DATA[t];
      if (t === 'VirtualMachine') return wrap(`<returnval><token>tok-1</token>${all.slice(0, 20).join('')}</returnval>`);   // paged
      return wrap(`<returnval>${all.join('')}</returnval>`);
    }
    if (m === 'ContinueRetrievePropertiesEx') return wrap(`<returnval>${DATA.VirtualMachine.slice(20).join('')}</returnval>`);
    if (m === 'DestroyView' || m === 'Logout') return wrap('');
    return fault('MethodNotFound', m);
  };
}

module.exports = { fakeVc, DATA, GiB, HEALTH, VNIC };
