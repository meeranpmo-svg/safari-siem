// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ESXi and Nutanix baseline hardening reads (engine/virt-capacity.js vcSoap.hostHardening / ntxClient.hardening): only
// allow-listed read calls are sent; each part is read on its own, so a role that cannot read one part leaves it null
// ("not checked") without failing the rest. And the hosts without an address (engine/virt.js fillHostIps): filled from the
// asset, another sighting of the same host, then DNS - never overwriting an address; a Discovery scope whose vCenter step did
// not run says why. Synthetic data.
const test = require('node:test');
const assert = require('node:assert/strict');
const { vcSoap, ntxClient, SOAP_OK, NTX_OK } = require('../engine/virt-capacity');
const { createVirt } = require('../engine/virt');
const { startApp } = require('./helpers');

const cred = { target: { base_url: 'https://10.100.5.1' }, secret: { username: 'svc@vsphere.local', password: 'Vc-pass-1' } };
const o = (type, id, props) => `<objects><obj type="${type}">${id}</obj>${Object.entries(props).map(([k, v]) => `<propSet><name>${k}</name><val>${v}</val></propSet>`).join('')}</objects>`;
const svc = (k, run, pol) => `<HostService><key>${k}</key><label>${k}</label><running>${run}</running><policy>${pol}</policy></HostService>`;
const opt = (k, v) => `<OptionValue><key>${k}</key><value xsi:type="xsd:string">${v}</value></OptionValue>`;
const PROPS = {
  base: [o('HostSystem', 'host-11', { name: 'esx01.corp.test', 'config.product.version': '7.0.3', 'config.product.build': '21930508' }), o('HostSystem', 'host-12', { name: 'esx02.corp.test', 'config.product.version': '6.7.0', 'config.product.build': '1' })],
  'config.service.service': [o('HostSystem', 'host-11', { 'config.service.service': svc('TSM-SSH', 'true', 'on') + svc('slpd', 'false', 'off') + svc('ntpd', 'true', 'on') }), o('HostSystem', 'host-12', { 'config.service.service': svc('TSM-SSH', 'false', 'off') })],
  'config.option': [o('HostSystem', 'host-11', { 'config.option': opt('Security.AccountLockFailures', '10') + opt('Syslog.global.logHost', 'tcp://10.0.0.5:514') + opt('Some.Other', 'x') + opt('Security.PasswordQualityControl', 'retry=3 min=disabled,disabled,disabled,7,7') })],
  'config.dateTimeInfo.ntpConfig.server': [o('HostSystem', 'host-11', { 'config.dateTimeInfo.ntpConfig.server': '<string>10.0.0.1</string><string>10.0.0.2</string>' })],
  'config.firewall': [o('HostSystem', 'host-11', { 'config.firewall': '<defaultPolicy><incomingBlocked>true</incomingBlocked><outgoingBlocked>true</outgoingBlocked></defaultPolicy><ruleset><key>sshServer</key><enabled>true</enabled><allowedHosts><allIp>true</allIp></allowedHosts></ruleset>' })],
  'config.network.vswitch': [o('HostSystem', 'host-11', { 'config.network.vswitch': '<HostVirtualSwitch><name>vSwitch0</name><spec><policy><security><allowPromiscuous>false</allowPromiscuous><macChanges>true</macChanges><forgedTransmits>true</forgedTransmits></security></policy></spec></HostVirtualSwitch>' })],
  'config.network.portgroup': [o('HostSystem', 'host-11', { 'config.network.portgroup': '<HostPortGroup><spec><name>VM Network</name><policy><security/></policy></spec></HostPortGroup>' })],
  'config.lockdownMode': [o('HostSystem', 'host-11', { 'config.lockdownMode': 'lockdownNormal' })],
};
function fakeHv(calls, deny = []) {
  return async (url, req) => {
    const m = /<soapenv:Body><(\w+)/.exec(req.body)[1]; calls.push(m);
    const wrap = (inner) => ({ status: 200, headers: m === 'Login' ? { 'set-cookie': ['vmware_soap_session="s1"; Path=/'] } : {}, text: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><${m}Response xmlns="urn:vim25">${inner}</${m}Response></soapenv:Body></soapenv:Envelope>` });
    const fault = (msg) => ({ status: 500, headers: {}, text: `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><soapenv:Fault><faultstring>${msg}</faultstring><detail><NoPermissionFault/></detail></soapenv:Fault></soapenv:Body></soapenv:Envelope>` });
    if (m === 'RetrieveServiceContent') return wrap('<returnval><rootFolder type="Folder">group-d1</rootFolder><propertyCollector type="PropertyCollector">pc</propertyCollector><viewManager type="ViewManager">vm</viewManager><sessionManager type="SessionManager">sm</sessionManager></returnval>');
    if (m === 'Login') return wrap('<returnval/>');
    if (m === 'CreateContainerView') return wrap('<returnval type="ContainerView">view-1</returnval>');
    if (m === 'RetrievePropertiesEx') {
      const paths = [...req.body.matchAll(/<pathSet>([^<]+)<\/pathSet>/g)].map((x) => x[1]);
      if (paths.includes('name')) return wrap(`<returnval>${PROPS.base.join('')}</returnval>`);
      if (deny.includes(paths[0])) return fault('Permission to perform this operation was denied.');
      return wrap(`<returnval>${(PROPS[paths[0]] || []).join('')}</returnval>`);
    }
    if (m === 'DestroyView' || m === 'Logout') return wrap('');
    return fault('MethodNotFound');
  };
}

test('ESXi hardening read: services, wanted advanced settings only, NTP, firewall, vSwitch security, lockdown - allow-listed SOAP only', async () => {
  const calls = [];
  const H = await vcSoap(cred.target, cred.secret, { request: fakeHv(calls) }).hostHardening();
  assert.ok(calls.every((m) => SOAP_OK.has(m)), calls.join(','));
  assert.equal(calls[calls.length - 1], 'Logout');
  const a = H.find((h) => h.id === 'host-11');
  assert.equal(a.version, '7.0.3');
  assert.deepEqual(a.services['TSM-SSH'], { running: true, policy: 'on' });
  assert.equal(a.options['Security.AccountLockFailures'], '10'); assert.equal(a.options['Some.Other'], undefined, 'only the settings the baseline checks are kept');
  assert.deepEqual(a.ntp, ['10.0.0.1', '10.0.0.2']);
  assert.deepEqual(a.firewall, { incoming_blocked: true, outgoing_blocked: true, rulesets: [{ key: 'sshServer', enabled: true, all_ip: true }] });
  assert.deepEqual(a.vswitches, [{ name: 'vSwitch0', promiscuous: false, mac_changes: true, forged: true }]);
  assert.deepEqual(a.portgroups, [{ name: 'VM Network', promiscuous: null, mac_changes: null, forged: null }], 'a port group that inherits stays null');
  assert.equal(a.lockdown, 'lockdownNormal');
  const d = await vcSoap(cred.target, cred.secret, { request: fakeHv([], ['config.option']) }).hostHardening();
  assert.equal(d[0].options, null, 'a role without advanced-setting read leaves options null'); assert.equal(d[0].read.options, false);
  assert.ok(d[0].services, 'the other parts are still read');
});

test('Nutanix hardening read: cluster security configuration, directory, syslog - GET on allow-listed paths only', async () => {
  const seen = [];
  const req = async (url, r) => {
    const p = url.replace('https://10.9.9.9:9440', ''); seen.push(r.method + ' ' + p);
    assert.ok(NTX_OK.some((re) => re.test(p)), 'allow-listed: ' + p);
    if (/v2\.0\/cluster$/.test(p)) return { status: 200, json: { uuid: 'c1', name: 'NTX-SYN', full_version: 'el8.5-release-fraser-6.5.2', ntp_servers: ['10.0.0.1'], name_servers: ['10.0.0.2'], enable_lock_down: false, enable_password_remote_login_to_cluster: true,
      security_compliance_config: { schedule: 'DAILY', enable_aide: false, enable_core: false, enable_high_strength_password: true, enable_banner: false, enable_snmpv3_only: false } } };
    if (/v1\/authconfig$/.test(p)) return { status: 200, json: { directoryList: [{ name: 'corp' }], authTypeList: ['LOCAL', 'DIRECTORY_SERVICE'] } };
    if (/remote_syslog_servers$/.test(p)) return { status: 404, json: null };
    if (/v2\.0\/hosts$/.test(p)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'NTX-N1', hypervisor_full_name: 'AHV 20230302', hypervisor_address: '10.9.9.11', service_vmexternal_ip: '10.9.9.21' }] } };
    return { status: 404 };
  };
  const r = await ntxClient({ base_url: 'https://10.9.9.9:9440' }, { username: 'ro', password: 'x' }, { request: req }).hardening();
  assert.ok(seen.every((x) => x.startsWith('GET ')));
  assert.equal(r.cluster.scma.schedule, 'DAILY'); assert.equal(r.cluster.scma.aide, false); assert.equal(r.cluster.hv_scma, null, 'not reported stays null');
  assert.equal(r.cluster.lockdown, false); assert.equal(r.auth.directories, 1); assert.equal(r.syslog, null, 'a 404 is not readable, not "no syslog"');
  assert.deepEqual(r.hosts.map((h) => [h.name, h.ip, h.cvm_ip]), [['NTX-N1', '10.9.9.11', '10.9.9.21']]);
  assert.ok(!NTX_OK.some((re) => re.test('/PrismGateway/services/rest/v1/authconfig/directories')), 'only the read paths');
});

test('host addresses: filled from the asset, another sighting, then DNS - never overwritten; inventory shows where it came from', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const ADM = { user: 'syed', role: 'admin' }, mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use' }, x), ADM).asset;
  const a1 = mk({ name: 'hpvm1', type: 'server', os: 'VMware ESXi', mgmt_ip: '192.168.63.21' });
  const devs = e.app.store.collection('disc_devices');
  devs.put({ id: 'd1', hostname: 'hpvm1.corp-hq.test', asset_id: a1.id, ip: null, os: 'VMware ESXi', extra: { vcenter: { kind: 'host' } }, scope_id: 's1', last_seen: '2026-10-11T08:00:00Z' });
  devs.put({ id: 'd2', hostname: 'hpvm2.corp-hq.test', ip: null, os: 'VMware ESXi', extra: { vcenter: { kind: 'host' } }, scope_id: 's1' });
  devs.put({ id: 'd2b', hostname: 'hpvm2.corp-hq.test', ip: '192.168.63.22', os: 'VMware ESXi', extra: { snmp: {} } });
  devs.put({ id: 'd3', hostname: 'hpvm3.corp-hq.test', ip: null, os: 'VMware ESXi', extra: { vcenter: { kind: 'host' } }, scope_id: 's1' });
  devs.put({ id: 'd4', hostname: 'hpvm4', ip: '192.168.63.24', os: 'VMware ESXi', extra: { vcenter: { kind: 'host' } } });
  devs.put({ id: 'd5', hostname: 'nowhere.corp-hq.test', ip: null, os: 'VMware ESXi', extra: { vcenter: { kind: 'host' } } });
  e.app.store.collection('disc_scopes').put({ id: 's1', label: '6388', methods: { vcenter: { enabled: true, credential_id: 'c1' } } });
  e.app.store.collection('disc_runs').put({ id: 'r1', scope_id: 's1', started_at: '2026-10-26T15:01:00Z', status: 'finished', stats: { sweep: { ok: true } }, methods_run: ['sweep'], methods_blocked: [{ method: 'vcenter', reason: 'disabled globally' }] });
  const dns = { 'hpvm3.corp-hq.test': '192.168.63.23' };
  const V = createVirt(e.app, { sealer: { available: () => false }, methods: {}, resolve: async (n) => { if (!dns[n]) throw new Error('ENOTFOUND'); return dns[n]; } });
  let inv = V.inventory();
  const row = (n) => inv.items.find((i) => i.name === n || (i.name || '').startsWith(n));
  assert.equal(row('hpvm1').ip, '192.168.63.21'); assert.equal(row('hpvm1').ip_from, 'asset', 'the asset address is shown at once');
  assert.match(inv.scopes[0].results[0].note, /blocked: disabled globally/, 'the scope says why vCenter did not run');
  const r = await V.fillHostIps(true);
  assert.equal(r.checked, 4); assert.equal(r.filled, 3);
  assert.deepEqual(r.from, { asset: 1, 'another sighting': 1, dns: 1 });
  assert.equal(devs.get('d2').ip, '192.168.63.22'); assert.equal(devs.get('d3').ip, '192.168.63.23'); assert.equal(devs.get('d5').ip, null, 'no source: stays empty, never guessed');
  assert.equal(devs.get('d4').ip, '192.168.63.24', 'an address is never overwritten');
  inv = V.inventory(); assert.equal(row('hpvm3').ip, '192.168.63.23');
  assert.equal((await V.fillHostIps(false)), null, 'the background job runs at most hourly');
});
