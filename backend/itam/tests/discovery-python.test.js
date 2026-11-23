// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 5a (docs/PYTHON-MIGRATION.md): pyengine/discovery_sources.py must answer exactly like the Node.js
// discovery methods vcenter / esxi / nutanix / azure / aws / cucm. Both talk to the same simulated systems over real
// HTTP (loopback) or HTTPS (Nutanix and CUCM refuse plain http: a throwaway certificate, trusted through ca_file);
// collect() and test() answers and the requests they made are compared (latency removed).
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createPyEngine } = require('../engine/pyengine');
const M = { vcenter: require('../engine/discovery/methods/vcenter'), esxi: require('../engine/discovery/methods/esxi'), nutanix: require('../engine/discovery/methods/nutanix'),
  azure: require('../engine/discovery/methods/azure'), aws: require('../engine/discovery/methods/aws'), cucm: require('../engine/discovery/methods/cucm') };
const PM = require('../engine/discovery/py-methods');
const { sign } = require('../engine/discovery/sigv4');
const { fakeVc } = require('./fixtures-vcenter-soap');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const strip = (r) => { const o = JSON.parse(JSON.stringify(r)); delete o.latency_ms; delete o.engine; return o; };
const sorted = (a) => a.map((x) => JSON.stringify(x)).sort();

let TLS = null;
function tls() {
  if (TLS !== null) return TLS;
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'disc-py-'));
  const g = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(d, 'k.pem'), '-out', path.join(d, 'c.pem'), '-days', '2', '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment'], { encoding: 'utf8' });
  TLS = g.status === 0 ? { key: fs.readFileSync(path.join(d, 'k.pem')), cert: fs.readFileSync(path.join(d, 'c.pem')), ca: path.join(d, 'c.pem') } : false;
  return TLS;
}
// a request-function fake served over real HTTP(S); every request is recorded
async function serve(handler, calls, secure) {
  const fn = (q, r) => {
    let b = ''; q.on('data', (x) => (b += x));
    q.on('end', async () => {
      const h = q.headers;
      calls.push([q.method, q.url, h.authorization || '', h['vmware-api-session-id'] || '', h.cookie || '', h['content-type'] || '', h.soapaction || '', h['x-amz-date'] || '', b]);
      const a = await handler(q.method, new URL(q.url, 'http://x'), { method: q.method, headers: { Cookie: h.cookie, Authorization: h.authorization, sid: h['vmware-api-session-id'], host: h.host, amz: h['x-amz-date'] }, body: b, url: q.url });
      r.writeHead(a.status, Object.assign({ 'content-type': a.text != null ? 'text/xml' : 'application/json' }, a.headers || {}));
      r.end(a.text != null ? a.text : JSON.stringify(a.json === undefined ? {} : a.json));
    });
  };
  const srv = secure ? https.createServer({ key: TLS.key, cert: TLS.cert }, fn) : http.createServer(fn);
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  return { base: `${secure ? 'https' : 'http'}://127.0.0.1:${srv.address().port}`, port: srv.address().port, close: () => new Promise((ok) => srv.close(ok)) };
}
// run Node and Python against two identical fakes; compare answers and requests
async function both(label, handlerFn, secure, mk, opts = {}, ops = ['collect', 'test'], cmp = (a) => a) {
  const py = createPyEngine({ python: PY });
  const out = {};
  for (const op of ops) {
    const nc = [], pc = [], s1 = await serve(handlerFn(), nc, secure), s2 = await serve(handlerFn(), pc, secure);
    try {
      const n = await M[mk.method][op](mk.cred(s1), Object.assign({}, opts, mk.opts ? mk.opts(s1) : {}));
      const p = await py.call('discovery.' + op, { method: mk.method, cred: mk.cred(s2), opts: Object.assign({}, opts, mk.opts ? mk.opts(s2) : {}) });
      const fix = (x, s) => JSON.parse(JSON.stringify(strip(x)).split(s.base).join('BASE').split(String(s.port)).join('PORT'));
      assert.deepEqual(fix(p, s2), fix(n, s1), `${label} ${op}: identical answers`);
      const norm = (c, s) => cmp(c.map((x) => JSON.parse(JSON.stringify(x).split(String(s.port)).join('PORT').replace(/session\[x\]view-\w+-\d+/g, 'VIEW'))));
      assert.deepEqual(norm(pc, s2), norm(nc, s1), `${label} ${op}: the same requests`);
      out[op] = n;
    } finally { await s1.close(); await s2.close(); }
  }
  return out;
}

// ---- vCenter: REST inventory + the SOAP host addresses on the same server
function vcFake(mode = '') {
  const soap = fakeVc([]);
  return async (method, u, q) => {
    if (u.pathname === '/sdk') return soap('http://x/sdk', { method, headers: { Cookie: q.headers.Cookie }, body: q.body });
    if (u.pathname === '/api/session') {
      if (method === 'DELETE') return { status: 204, text: '' };
      return q.headers.Authorization === 'Basic ' + Buffer.from('svc@vsphere.local:Vc-pass-1').toString('base64') ? { status: 201, json: 'sid-77' } : { status: 401, json: { error_type: 'UNAUTHENTICATED' } };
    }
    if (q.headers.sid !== 'sid-77') return { status: 401, json: {} };
    if (u.pathname === '/api/vcenter/host') return { status: 200, json: [{ host: 'host-11', name: ('esx01.' + 'corp-hq.com'), connection_state: 'CONNECTED' }, { host: 'host-12', name: 'ESX02.CORP-HQ.COM', connection_state: 'DISCONNECTED' }, { host: 'host-99', name: null }] };
    if (u.pathname === '/api/vcenter/vm') {
      if (mode === 'novms') return { status: 403, json: {} };
      const h = u.searchParams.get('hosts');
      return { status: 200, json: { value: h === 'host-11' ? [{ vm: 'vm-1', name: 'APP1', power_state: 'POWERED_ON' }, { vm: 'vm-2', power_state: 'SUSPENDED', guest_OS: 'OTHER' }, { vm: 'vm-1' }] : h === 'host-12' ? [{ vm: 'vm 3/x', name: 'Ünïcode', power_state: 'powered_off' }] : [] } };
    }
    const m = /^\/api\/vcenter\/vm\/([^/]+)(\/guest\/(networking\/interfaces|identity))?$/.exec(u.pathname);
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (id === 'vm-2') return { status: 500, json: {} };
      if (!m[2]) return { status: 200, json: { value: { name: 'APP1-detail', guest_OS: 'WINDOWS_9_SERVER_64', power_state: 'POWERED_ON', identity: { instance_uuid: '5003-' + id }, nics: { 4000: { mac_address: '00:50:56:AA:BB:01' }, 4001: { mac_address: '00:50:56:AA:BB:02' } } } } };
      if (m[3] === 'networking/interfaces') return { status: 200, json: [{ mac_address: '00:50:56:AA:BB:01', ip: { ip_addresses: [{ ip_address: '10.1.1.5' }, { ip_address: 'fe80::1' }] } }, { mac_address: '00:50:56:AA:BB:03' }] };
      return { status: 200, json: id === 'vm-1' ? { full_name: { default_message: 'Microsoft Windows Server 2022' }, host_name: ('app1.' + 'corp-hq.com'), ip_address: '10.1.1.9' } : { full_name: 'Linux', ip_address: 'bad' } };
    }
    return { status: 404, json: {} };
  };
}

test('Python vCenter and ESXi discovery answer exactly like the Node.js ones', { skip: !hasPy && 'python3 not available' }, async () => {
  const vc = (pw) => ({ method: 'vcenter', cred: (s) => ({ target: { base_url: s.base + '/' }, secret: { username: 'svc@vsphere.local', password: pw } }) });
  const r = await both('vcenter', () => vcFake(), false, vc('Vc-pass-1'));
  assert.equal(r.collect.ok, true); assert.equal(r.collect.vms.length, 3); assert.equal(r.collect.hosts[0].ip, '10.100.5.11');
  assert.deepEqual(r.collect.vms[0].ips, ['10.1.1.5', '10.1.1.9']); assert.equal(r.test.ok, true);
  await both('vcenter, wrong password', () => vcFake(), false, vc('nope'));
  await both('vcenter, no VM privilege', () => vcFake('novms'), false, vc('Vc-pass-1'));
  await both('vcenter, no host addresses', () => vcFake(), false, vc('Vc-pass-1'), { hostIps: false, maxVms: 2 }, ['collect']);
  const esxi = (pw) => ({ method: 'esxi', cred: (s) => ({ target: { base_url: s.base }, secret: { username: 'svc', password: pw } }) });
  const e = await both('esxi', () => vcFake(), false, esxi('Vc-pass-1'));
  assert.equal(e.collect.vms.length, 30); assert.equal(e.test.discovered.vms, 30);
  const bad = await both('esxi, wrong password', () => vcFake(), false, esxi('x'));
  assert.equal(bad.collect.error_class, 'auth'); assert.equal(bad.test.error_class, 'auth');
});

// ---- Nutanix (HTTPS only)
function ntxFake(mode = '') {
  return async (method, u, q) => {
    if (mode === 'bad' || q.headers.Authorization !== 'Basic ' + Buffer.from('svc-ro:Pr1sm é').toString('base64')) return { status: 401, json: {} };
    const p = u.pathname + u.search;
    let m;
    if ((m = /^\/api\/nutanix\/v3\/(\w+)s\/list$/.exec(p))) {
      if (mode === 'pe') return { status: 404, json: {} };
      if (mode === 'noread' && m[1] === 'vm') return { status: 403, json: {} };
      const off = JSON.parse(q.body).offset;
      if (m[1] === 'host') return { status: 200, json: { metadata: { total_matches: '3' }, entities: [
        { metadata: { uuid: 'h1' }, status: { name: 'NTNX-A', cluster_reference: { name: 'RUH-CL' }, resources: { hypervisor: { ip: '10.0.0.11', hypervisor_full_name: 'AHV 9' }, controller_vm: { ip: '10.0.0.21' }, ipmi: { ip: 'n/a' }, num_cpu_sockets: 2, num_cpu_cores: '48', cpu_model: 'Xeon', serial_number: 'S1', block: { block_model: 'NX-3170' } } } },
        { metadata: { uuid: 'pc' }, status: { name: 'PC-VM', resources: {} } }, { metadata: { uuid: 'h2' }, spec: { name: 'NTNX-B' }, status: { resources: { num_cpu_sockets: 1, num_cpu_cores: 3 } } }] } };
      if (m[1] === 'cluster') return { status: 200, json: { entities: [{ metadata: { uuid: 'c1' }, status: { name: 'RUH-CL', resources: { config: { service_list: ['AOS'], software_map: { NOS: { version: '6.5.2' } } } } } }, { metadata: { uuid: 'c2' }, status: { name: 'PC', resources: { config: { service_list: ['PRISM_CENTRAL'] } } } }] } };
      if (off === 0) return { status: 200, json: { entities: Array.from({ length: 500 }, (_, i) => ({ metadata: { uuid: 'v' + i }, status: { name: 'VM' + i, resources: { power_state: i % 2 ? 'ON' : 'paused', num_sockets: i % 3, num_vcpus_per_socket: 2, memory_size_mib: 2048.6, host_reference: i % 4 ? { uuid: 'h1' } : { uuid: 'h2', name: 'ref-B' }, nic_list: [{ mac_address: '50:6B:8D:00:00:0' + (i % 10), ip_endpoint_list: [{ ip: '10.9.0.' + (i % 250) }, { ip: '10.9.0.' + (i % 250) }] }] } } })) } };
      return { status: 200, json: { entities: [{ metadata: { uuid: 'vlast' }, status: { resources: {} } }, { status: {} }] } };
    }
    if (/v2\.0\/hosts$/.test(p)) return { status: 200, json: { entities: [{ uuid: 'h1', name: 'PE-A', hypervisor_address: '10.0.0.11', service_vmexternal_ip: '10.0.0.21', ipmi_address: '10.0.0.31', num_cpu_sockets: 2, num_cpu_cores: 32, serial: 'X1', block_model_name: 'NX-1065', hypervisor_full_name: 'AHV' }, { name: 'no-uuid' }] } };
    if (/v2\.0\/vms\?include_vm_nic_config=true$/.test(p)) return { status: 200, json: { entities: [{ uuid: 'v1', name: 'DB', host_uuid: 'h1', power_state: 'on', num_vcpus: 2, num_cores_per_vcpu: 4, memory_mb: 8192, vm_nics: [{ mac_address: 'AA:BB:CC:DD:EE:01', ip_address: '10.2.0.5', ip_addresses: ['10.2.0.6', 'x'], requested_ip_address: '10.2.0.5' }] }, { uuid: 'v2', host_uuid: 'zz', num_vcpus: 0 }] } };
    if (/v2\.0\/cluster$/.test(p)) return { status: 200, json: { uuid: 'c9', name: 'PE-CL', version: '6.5' } };
    return { status: 404, json: {} };
  };
}

test('Python Nutanix discovery answers exactly like the Node.js one (HTTPS)', { skip: (!hasPy && 'python3 not available') || (!tls() && 'openssl not available') }, async () => {
  const mk = { method: 'nutanix', cred: (s) => ({ target: { base_url: s.base + '/', ca_file: TLS.ca }, secret: { username: 'svc-ro', password: 'Pr1sm é' } }) };
  const pc = await both('nutanix Prism Central', () => ntxFake(), true, mk, {}, ['collect', 'test'], sorted);
  assert.equal(pc.collect.api, 'v3'); assert.equal(pc.collect.vms.length, 501); assert.deepEqual(pc.collect.clusters, [{ id: 'c1', name: 'RUH-CL', version: '6.5.2' }]);
  const pe = await both('nutanix Prism Element', () => ntxFake('pe'), true, mk, {}, ['collect', 'test'], sorted);
  assert.equal(pe.collect.api, 'v2'); assert.deepEqual(pe.collect.vms[0].ips, ['10.2.0.5', '10.2.0.6']);
  await both('nutanix, wrong password', () => ntxFake('bad'), true, mk, {}, ['collect', 'test'], sorted);
  const nr = await both('nutanix, no VM read', () => ntxFake('noread'), true, mk, {}, ['collect'], sorted);
  assert.equal(nr.collect.error_class, 'authz');
  // plain http is refused before anything is sent, by both
  await both('nutanix over http', () => ntxFake(), false, { method: 'nutanix', cred: (s) => ({ target: { base_url: s.base }, secret: {} }) });
});

// ---- Azure Resource Graph
function azFake(mode = '') {
  return async (method, u, q) => {
    if (/\/oauth2\/v2\.0\/token$/.test(u.pathname)) return /client_secret=s3cr%2Bt%26%3D&/.test(q.body) && mode !== 'badsecret' ? { status: 200, json: { access_token: 'at-1' } } : { status: 401, json: { error: 'invalid_client' } };
    if (q.headers.Authorization !== 'Bearer at-1') return { status: 401, json: {} };
    if (mode === 'noreader') return { status: 403, json: {} };
    const b = JSON.parse(q.body);
    if (!b.options.$skipToken) return { status: 200, json: { $skipToken: 'page2', data: [
      { id: '/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM1', name: 'VM1', location: 'uaenorth', resourceGroup: 'RG', subscriptionId: 'S', osType: 'Windows', vmSize: 'Standard_D4s_v5', powerState: 'PowerState/running', mac: '00-0D-3A-11-22-33', privateIp: '10.4.0.4' },
      { id: '/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1', mac: '00-0D-3A-11-22-34', privateIp: '10.4.0.5' }, { name: 'no id' }] } };
    return { status: 200, json: { data: { columns: [{ name: 'id' }, { name: 'name' }, { name: 'privateIp' }, { name: 'mac' }], rows: [['/x/VM2', 'VM2', '10.4.1.4', 'bad'], ['/x/VM2', 'VM2', '10.4.1.4', null]] } } };
  };
}

test('Python Azure discovery answers exactly like the Node.js one', { skip: !hasPy && 'python3 not available' }, async () => {
  const mk = { method: 'azure', cred: () => ({ target: { tenant_id: 'tenant/1', client_id: 'app-1', subscriptions: ['S', 'T'] }, secret: { client_secret: 's3cr+t&=' } }), opts: (s) => ({ login_base: s.base + '/', arm_base: s.base }) };
  const r = await both('azure', () => azFake(), false, mk);
  assert.equal(r.collect.vms.length, 2); assert.deepEqual(r.collect.vms[0].macs, ['00:0d:3a:11:22:33', '00:0d:3a:11:22:34']); assert.equal(r.test.ok, true);
  await both('azure, wrong secret', () => azFake('badsecret'), false, mk);
  await both('azure, no Reader role', () => azFake('noreader'), false, mk);
  await both('azure, no subscriptions listed', () => azFake(), false, Object.assign({}, mk, { cred: () => ({ target: { tenant_id: 't', client_id: 'app-1', subscriptions: [] }, secret: { client_secret: 's3cr+t&=' } }) }), {}, ['collect']);
});

// ---- AWS EC2 (SigV4)
function awsFake(mode = '') {
  const inst = (id, extra = '') => `<item><instanceId>${id}</instanceId><instanceType>t3.medium</instanceType><instanceState><code>16</code><name>running</name></instanceState><privateIpAddress>10.8.0.${id.length}</privateIpAddress>`
    + `<privateDnsName>ip-10-8-0-1.ec2.internal</privateDnsName><placement><availabilityZone>me-south-1a</availabilityZone></placement><networkInterfaceSet><item><macAddress>0E:AA:BB:CC:DD:EE</macAddress></item></networkInterfaceSet>${extra}</item>`;
  return async (method, u, q) => {
    // the signature is checked (with the Node.js signer) for the host and port this server listens on: both engines must sign right
    const region = (/Credential=AKIATEST\/\d{8}\/([a-z0-9-]+)\/ec2\//.exec(q.headers.Authorization || '') || [])[1];
    const want = region && sign({ method: 'GET', url: 'http://' + q.headers.host + q.url, region, service: 'ec2', accessKeyId: 'AKIATEST', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', amzDate: q.headers.amz }).headers.Authorization;
    if (!want || want !== q.headers.Authorization) return { status: 403, text: '<Response><Errors><Error><Code>SignatureDoesNotMatch</Code></Error></Errors></Response>' };
    if (mode === 'deny') return { status: 403, text: '<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>' };
    if (mode === 'badkey') return { status: 401, text: '<Response><Errors><Error><Code>AuthFailure</Code></Error></Errors></Response>' };
    const tok = u.searchParams.get('NextToken');
    if (!tok) return { status: 200, text: `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><ownerId>1234</ownerId><instancesSet>${inst('i-1', '<tagSet><item><key>Env</key><value>p</value></item><item><key>Name</key><value>web &amp; api</value></item></tagSet><platform>windows</platform>')}${inst('', '')}</instancesSet></item></reservationSet><nextToken>tok/+=1</nextToken></DescribeInstancesResponse>` };
    return { status: 200, text: `<DescribeInstancesResponse><reservationSet><item><instancesSet>${inst('i-22', '<platformDetails>Red Hat Enterprise Linux</platformDetails><ipAddress>51.1.1.1</ipAddress>')}</instancesSet></item></reservationSet></DescribeInstancesResponse>` };
  };
}

test('Python AWS discovery answers exactly like the Node.js one (same SigV4 signatures)', { skip: !hasPy && 'python3 not available' }, async () => {
  const mk = { method: 'aws', cred: () => ({ target: { regions: ['me-south-1', 'eu-west-1'] }, secret: { access_key_id: 'AKIATEST', secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' } }), opts: (s) => ({ endpoint: s.base + '/ec2-{region}/' }) };
  const o = { amzDate: '20261019T081500Z' };
  const noSig = (calls) => calls.map((c) => c.slice(0, 2).concat(c.slice(3)));   // the signature covers the port, which differs; the fake verified it
  const r = await both('aws', () => awsFake(), false, mk, o, ['collect', 'test'], noSig);
  assert.equal(r.collect.ok, true); assert.equal(r.collect.instances.length, 4); assert.equal(r.collect.instances[0].name, 'web & api');
  await both('aws, missing permission', () => awsFake('deny'), false, mk, o, ['collect', 'test'], noSig);
  await both('aws, wrong key', () => awsFake('badkey'), false, mk, o, ['collect', 'test'], noSig);
  // the signer itself, on the AWS documentation example (IAM ListUsers, 2015-08-30)
  const py = createPyEngine({ python: PY });
  const vec = { method: 'GET', url: 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08', headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' }, region: 'us-east-1', service: 'iam', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', amzDate: '20150830T123600Z' };
  const p = spawnSync(PY, ['-I', '-c', 'import json,sys;sys.path.insert(0,sys.argv[1]);import sigv4;print(sigv4.sign(json.loads(sys.stdin.read()))["signature"])', path.join(__dirname, '..', 'pyengine')], { input: JSON.stringify(vec), encoding: 'utf8' });
  assert.equal(p.stdout.trim(), sign(vec).signature);
  assert.equal(p.stdout.trim(), '5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7', 'the AWS documentation signature');
  assert.ok(py);
});

// ---- CUCM AXL + RisPort70 (HTTPS only)
function cucmFake(mode = '') {
  const phone = (n) => `<phone uuid="{x}"><name>${n}</name><description>Desk ${n}</description><product>Cisco 8845</product><model>Cisco 8845</model><protocol>SIP</protocol><devicePoolName uuid="{y}">DP-RUH</devicePoolName></phone>`;
  return async (method, u, q) => {
    if (q.headers.Authorization !== 'Basic ' + Buffer.from('axl-ro:Axl!pw').toString('base64')) return { status: 401, text: '' };
    if (u.pathname === '/axl/') {
      if (/getCCMVersion/.test(q.body)) return { status: 200, text: '<soapenv:Envelope><soapenv:Body><ns:getCCMVersionResponse><return><componentVersion><version>14.0.1</version></componentVersion></return></ns:getCCMVersionResponse></soapenv:Body></soapenv:Envelope>' };
      if (mode === 'fault') return { status: 500, text: '<soapenv:Envelope><soapenv:Body><soapenv:Fault><faultstring>Item not valid</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>' };
      const skip = Number(/<skip>(\d+)<\/skip>/.exec(q.body)[1]);
      const all = ['SEP00AABBCCDD01', 'SEP00AABBCCDD02', 'ATA00aabbccdd03', 'CSFSYED'];
      return { status: 200, text: `<soapenv:Envelope><soapenv:Body><ns:listPhoneResponse><return>${all.slice(skip, skip + 3).map(phone).join('')}</return></ns:listPhoneResponse></soapenv:Body></soapenv:Envelope>` };
    }
    if (mode === 'noris') return { status: 500, text: 'oops' };
    return { status: 200, text: '<soapenv:Envelope><soapenv:Body><ns1:selectCmDeviceResponse><ns1:SelectCmDeviceResult><ns1:CmNodes><ns1:item><ns1:CmDevices>'
      + '<ns1:item><ns1:Name>SEP00AABBCCDD01</ns1:Name><ns1:IPAddress><ns1:item><ns1:IP>10.20.1.15</ns1:IP></ns1:item></ns1:IPAddress><ns1:Status>UnRegistered</ns1:Status></ns1:item>'
      + '<ns1:item><ns1:Name>SEP00AABBCCDD01</ns1:Name><ns1:IPAddress><ns1:item><ns1:IP>10.20.1.16</ns1:IP></ns1:item></ns1:IPAddress><ns1:Status>Registered</ns1:Status></ns1:item>'
      + '<ns1:item><ns1:Name>CSFSYED</ns1:Name><ns1:IPAddress>10.20.9.9</ns1:IPAddress><ns1:Status>Registered</ns1:Status></ns1:item></ns1:CmDevices></ns1:item></ns1:CmNodes></ns1:SelectCmDeviceResult></ns1:selectCmDeviceResponse></soapenv:Body></soapenv:Envelope>' };
  };
}

test('Python CUCM discovery answers exactly like the Node.js one (HTTPS)', { skip: (!hasPy && 'python3 not available') || (!tls() && 'openssl not available') }, async () => {
  const mk = (pw) => ({ method: 'cucm', cred: (s) => ({ target: { host: '127.0.0.1', port: s.port, ca_file: TLS.ca, axl_version: '14.0' }, secret: { username: 'axl-ro', password: pw } }) });
  const r = await both('cucm', () => cucmFake(), true, mk('Axl!pw'), { pageSize: 3 });
  assert.equal(r.collect.phones.length, 4); assert.deepEqual([r.collect.phones[0].status, r.collect.phones[0].ip, r.collect.phones[2].mac], ['Registered', '10.20.1.16', '00:aa:bb:cc:dd:03']);
  const nr = await both('cucm without RIS', () => cucmFake('noris'), true, mk('Axl!pw'), { pageSize: 3 }, ['collect']);
  assert.equal(nr.collect.ok, true); assert.equal(nr.collect.phones[0].status, null);
  await both('cucm SOAP fault', () => cucmFake('fault'), true, mk('Axl!pw'), {}, ['collect']);
  await both('cucm wrong password', () => cucmFake(), true, mk('x'));
});

test('the discovery bridge: Python by default, Node.js with an injected request or engine "node", Node.js when Python is missing', { skip: !hasPy && 'python3 not available' }, async () => {
  const calls = [], s = await serve(vcFake(), calls, false);
  try {
    const cred = { target: { base_url: s.base }, secret: { username: 'svc@vsphere.local', password: 'Vc-pass-1' } };
    PM.configure({ python: PY, engine: 'python' });
    const W = PM.wrap('vcenter', M.vcenter);
    assert.equal((await W.collect(cred)).engine, 'python');
    assert.equal((await W.collect(cred, { request: async () => ({ status: 401, json: {} }) })).error_class, 'auth', 'an injected request stays in Node.js');
    PM.configure({ engine: 'node' }); assert.equal((await W.collect(cred)).engine, undefined);
    PM.configure({ python: '/nonexistent/python3', engine: 'python' });
    const f = await W.collect(cred); assert.match(f.engine, /^node \(python unavailable/); assert.equal(f.ok, true);
    assert.equal(W.guard, M.vcenter.guard, 'the other exports are kept');
  } finally { PM.configure({ python: PY, engine: 'python' }); await s.close(); }
});

test('the Python sources keep the read-only guards', { skip: !hasPy && 'python3 not available' }, () => {
  const code = `import sys;sys.path.insert(0,sys.argv[1]);import discovery_sources as d
bad=[]
for f,m,p in [(d.vc_guard,'PATCH','/api/vcenter/vm/vm-1'),(d.vc_guard,'POST','/api/vcenter/vm/vm-1/power'),(d.vc_guard,'DELETE','/api/vcenter/vm/vm-1'),(d.ntx_guard,'POST','/api/nutanix/v3/vms'),(d.ntx_guard,'PUT','/api/nutanix/v3/vms/list'),(d.ntx_guard,'GET','/PrismGateway/services/rest/v2.0/vms/x/set_power_state')]:
    try: f(m,p); bad.append(m+' '+p)
    except d.D as e: assert e.code=='config'
for f,m,p in [(d.vc_guard,'GET','/api/vcenter/host'),(d.vc_guard,'POST','/api/session'),(d.ntx_guard,'POST','/api/nutanix/v3/hosts/list'),(d.ntx_guard,'GET','/PrismGateway/services/rest/v2.0/vms?include_vm_nic_config=true')]: f(m,p)
print('|'.join(bad) or 'ok')`;
  const r = spawnSync(PY, ['-I', '-c', code, path.join(__dirname, '..', 'pyengine')], { encoding: 'utf8' });
  assert.equal(r.stdout.trim(), 'ok', r.stderr);
  for (const [m, p] of [['PATCH', '/api/vcenter/vm/vm-1'], ['DELETE', '/api/vcenter/vm/vm-1']]) assert.throws(() => M.vcenter.guard(m, p), /read-only/);
});
