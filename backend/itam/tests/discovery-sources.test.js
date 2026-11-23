// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Passive discovery sources against in-process fakes (loopback only, synthetic data): Active Directory over LDAPS,
// VMware vCenter REST (read-only guard), Cisco CUCM AXL listPhone + RisPort70, Azure Resource Graph, AWS EC2
// DescribeInstances with SigV4 (signature re-verified by the fake + AWS documentation vectors), Hyper-V report parsing.
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeCA, makeServerCert } = require('./helpers/x509');
const { startFakeLdap, makeDirectory } = require('./helpers/fake-ldap');
const { startHttpsFake, startHttpFake } = require('./helpers/discovery-fakes');
const adM = require('../engine/discovery/methods/ad');
const vcM = require('../engine/discovery/methods/vcenter');
const cucmM = require('../engine/discovery/methods/cucm');
const azM = require('../engine/discovery/methods/azure');
const awsM = require('../engine/discovery/methods/aws');
const hv = require('../engine/discovery/methods/hyperv');
const sigv4 = require('../engine/discovery/sigv4');
const xml = require('../engine/discovery/xml');

const BASE = 'DC=corp-hq,DC=com';
const DC = ('dc-hqa.' + 'corp-hq.com');
const SVC = `CN=svc-itam-discovery-test,OU=Service Accounts,${BASE}`;
const SVC_PW = 'Synthetic-Disc-Bind-7!q';
const ft = (ms) => String((BigInt(ms) + 11644473600000n) * 10000n);

function adDirectory() {
  const dir = makeDirectory();
  dir.add(BASE, { objectClass: ['top', 'domain'] });
  dir.add(SVC, { objectClass: ['top', 'person', 'user'], cn: 'svc-itam-discovery-test' });
  dir.add(`CN=TEST-DC01,OU=Domain Controllers,${BASE}`, { objectClass: ['top', 'computer'], cn: 'TEST-DC01', dNSHostName: ('test-dc01.' + 'corp-hq.com'), operatingSystem: 'Windows Server 2022 Standard', operatingSystemVersion: '10.0 (20348)', userAccountControl: '532480', primaryGroupID: '516', lastLogonTimestamp: ft(Date.UTC(2026, 9, 6, 8)) });
  dir.add(`CN=TEST-PC-0042,OU=Workstations,OU=Riyadh HQ,${BASE}`, { objectClass: ['top', 'computer'], cn: 'TEST-PC-0042', dNSHostName: ('test-pc-0042.' + 'corp-hq.com'), operatingSystem: 'Windows 11 Enterprise', operatingSystemVersion: '10.0 (22631)', userAccountControl: '4096', primaryGroupID: '515', lastLogonTimestamp: ft(Date.UTC(2026, 9, 1, 7)) });
  dir.add(`CN=TEST-OLD-PC,CN=Computers,${BASE}`, { objectClass: ['top', 'computer'], cn: 'TEST-OLD-PC', operatingSystem: 'Windows 10 Pro', userAccountControl: '4098' });
  dir.add(`CN=Not A Computer,OU=Staff,${BASE}`, { objectClass: ['top', 'person', 'user'], cn: 'Not A Computer' });
  return dir;
}

test('Active Directory: computer objects over LDAPS (DC name verified, CA pinned), enabled flag, OU, DC role', async (t) => {
  const ca = makeCA('Synthetic AD Test CA');
  const leaf = makeServerCert(ca, { cn: DC, dns: [DC], ip: ['127.0.0.1'] });
  const srv = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir: adDirectory(), passwords: { [SVC]: SVC_PW } });
  t.after(() => srv.close());
  const cred = { kind: 'ldap', target: { servers: [`ldaps://${DC}:${srv.port}`], ip: '127.0.0.1', base_dn: BASE }, secret: { bind_dn: SVC, password: SVC_PW } };
  const r = await adM.collect(cred, { ca: ca.cert, timeoutMs: 4000 });
  assert.equal(r.ok, true);
  const byName = Object.fromEntries(r.computers.map((c) => [c.name, c]));
  assert.deepEqual(Object.keys(byName).sort(), ['TEST-DC01', 'TEST-OLD-PC', 'TEST-PC-0042']);
  assert.deepEqual(byName['TEST-DC01'], { dn: `CN=TEST-DC01,OU=Domain Controllers,${BASE}`, name: 'TEST-DC01', fqdn: ('test-dc01.' + 'corp-hq.com'), os: 'Windows Server 2022 Standard', os_version: '10.0 (20348)', last_logon: '2026-10-06T08:00:00.000Z', ou: 'Domain Controllers', enabled: true, is_dc: true });
  assert.equal(byName['TEST-PC-0042'].ou, 'Workstations / Riyadh HQ');
  assert.equal(byName['TEST-PC-0042'].is_dc, false);
  assert.equal(byName['TEST-OLD-PC'].enabled, false);
  assert.equal(byName['TEST-OLD-PC'].ou, 'Computers');
  assert.deepEqual(await adM.test(cred, { ca: ca.cert }).then((x) => [x.ok]), [true]);
  // wrong password → auth; untrusted CA → tls (never "fails open")
  assert.equal((await adM.test(Object.assign({}, cred, { secret: { bind_dn: SVC, password: 'wrong' } }), { ca: ca.cert })).error_class, 'auth');
  const other = makeCA('Synthetic Untrusted CA');
  const bad = await adM.test(cred, { ca: other.cert, timeoutMs: 3000 });
  assert.equal(bad.ok, false);
  assert.ok(['tls', 'unreachable'].includes(bad.error_class), bad.error_class);
});

test('vCenter: hosts + VMs with guest IPs/MACs/power; only GET + own session; mutating calls refused', async (t) => {
  const fake = await startHttpsFake((r) => {
    if (r.method === 'POST' && r.url === '/api/session') return r.headers.authorization === 'Basic ' + Buffer.from('svc-ro@vsphere.local:Synthetic-Vc-Pass-1').toString('base64') ? { status: 201, body: JSON.stringify('sess-test-1'), type: 'application/json' } : { status: 401, body: { error: 'x' } };
    if (r.headers['vmware-api-session-id'] !== 'sess-test-1') return { status: 401, body: {} };
    if (r.method === 'DELETE' && r.url === '/api/session') return { status: 204, body: {} };
    if (r.url === '/api/vcenter/host') return { body: [{ host: 'host-1', name: ('test-esx01.' + 'corp-hq.com'), connection_state: 'CONNECTED' }] };
    if (r.url === '/api/vcenter/vm?hosts=host-1') return { body: [{ vm: 'vm-1', name: 'TEST-APP01', power_state: 'POWERED_ON' }, { vm: 'vm-2', name: 'TEST-OFF', power_state: 'POWERED_OFF' }] };
    if (r.url === '/api/vcenter/vm/vm-1') return { body: { name: 'TEST-APP01', guest_OS: 'WINDOWS_9_SERVER_64', power_state: 'POWERED_ON', nics: { 4000: { mac_address: '00:50:56:AA:00:01' } }, identity: { instance_uuid: '4210aaaa-test-uuid' } } };
    if (r.url === '/api/vcenter/vm/vm-1/guest/networking/interfaces') return { body: [{ mac_address: '00:50:56:aa:00:01', ip: { ip_addresses: [{ ip_address: '10.20.0.31', prefix_length: 24 }, { ip_address: 'fe80::1', prefix_length: 64 }] } }] };
    if (r.url === '/api/vcenter/vm/vm-1/guest/identity') return { body: { host_name: 'test-app01', ip_address: '10.20.0.31', full_name: { default_message: 'Microsoft Windows Server 2022 (64-bit)' } } };
    if (r.url === '/api/vcenter/vm/vm-2') return { body: { name: 'TEST-OFF', guest_OS: 'UBUNTU_64', power_state: 'POWERED_OFF', nics: { 4000: { mac_address: '00:50:56:aa:00:02' } } } };
    return { status: 404, body: {} }; // tools-less VM: guest endpoints 404 → read best effort
  });
  t.after(() => fake.close());
  const cred = { kind: 'vcenter', target: { base_url: fake.url, ca_file: fake.caFile }, secret: { username: 'svc-ro@vsphere.local', password: 'Synthetic-Vc-Pass-1' } };
  const r = await vcM.collect(cred);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(r.hosts, [{ id: 'host-1', name: ('test-esx01.' + 'corp-hq.com'), state: 'connected' }]);
  const vm1 = r.vms.find((v) => v.id === 'vm-1');
  assert.deepEqual(vm1, { id: 'vm-1', name: 'TEST-APP01', host_id: 'host-1', host_name: ('test-esx01.' + 'corp-hq.com'), power_state: 'on', guest_os: 'Microsoft Windows Server 2022 (64-bit)', hostname: 'test-app01', ips: ['10.20.0.31'], macs: ['00:50:56:aa:00:01'], uuid: '4210aaaa-test-uuid' });
  const vm2 = r.vms.find((v) => v.id === 'vm-2');
  assert.deepEqual([vm2.power_state, vm2.guest_os, vm2.ips, vm2.macs], ['off', 'UBUNTU_64', [], ['00:50:56:aa:00:02']]);
  const nonGet = fake.requests.filter((x) => x.method !== 'GET').map((x) => `${x.method} ${x.url}`);
  // POST /sdk = the host-address read over SOAP (always POST; virt-capacity's SOAP_OK allow-list holds it to read-only calls)
  assert.deepEqual([...new Set(nonGet)].filter((x) => x !== 'POST /sdk'), ['POST /api/session', 'DELETE /api/session'], 'only our own session is ever created/deleted');
  assert.throws(() => vcM.guard('POST', '/api/vcenter/vm/vm-1/power'), /read-only/);
  assert.throws(() => vcM.guard('GET', '/api/appliance/system/version'), /read-only/);
  assert.equal((await vcM.test(Object.assign({}, cred, { secret: { username: 'x', password: 'y' } }))).error_class, 'auth');
  // TLS is verified: without the CA file the self-signed test chain is refused
  assert.equal((await vcM.test(Object.assign({}, cred, { target: { base_url: fake.url } }))).error_class, 'tls');
});

const AXL_REPLY = `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns:listPhoneResponse xmlns:ns="http://www.cisco.com/AXL/API/12.5"><return>
<phone uuid="{A}"><name>SEP0004F2ABCDEF</name><description>TEST reception &amp; lobby</description><product>Cisco 8845</product><model>Cisco 8845</model><protocol>SIP</protocol><devicePoolName uuid="{D}">DP_TEST_HQ</devicePoolName></phone>
<phone uuid="{B}"><name>SEP001122334455</name><description>TEST spare</description><product>Cisco 7841</product><model>Cisco 7841</model><protocol>SCCP</protocol><devicePoolName uuid="{D}">DP_TEST_JED</devicePoolName></phone>
</return></ns:listPhoneResponse></soapenv:Body></soapenv:Envelope>`;
const RIS_REPLY = `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><ns1:selectCmDeviceResponse xmlns:ns1="http://schemas.cisco.com/ast/soap"><ns1:selectCmDeviceReturn><ns1:SelectCmDeviceResult><ns1:TotalDevicesFound>2</ns1:TotalDevicesFound><ns1:CmNodes>
<ns1:item><ns1:ReturnCode>Ok</ns1:ReturnCode><ns1:Name>cucm-test-pub</ns1:Name><ns1:CmDevices>
<ns1:item><ns1:Name>SEP0004F2ABCDEF</ns1:Name><ns1:DirNumber>1001-Registered</ns1:DirNumber><ns1:Status>Registered</ns1:Status><ns1:IPAddress><ns1:item><ns1:IP>10.30.0.40</ns1:IP><ns1:IPAddrType>ipv4</ns1:IPAddrType></ns1:item></ns1:IPAddress></ns1:item>
<ns1:item><ns1:Name>SEP001122334455</ns1:Name><ns1:Status>UnRegistered</ns1:Status><ns1:IPAddress><ns1:item><ns1:IP>10.30.0.41</ns1:IP></ns1:item></ns1:IPAddress></ns1:item>
</ns1:CmDevices></ns1:item></ns1:CmNodes></ns1:SelectCmDeviceResult></ns1:selectCmDeviceReturn></ns1:selectCmDeviceResponse></soapenv:Body></soapenv:Envelope>`;

test('CUCM: AXL listPhone + RisPort70 selectCmDevice → phones with MAC, model, pool, registration, IP', async (t) => {
  const fake = await startHttpsFake((r) => {
    if (r.headers.authorization !== 'Basic ' + Buffer.from('axl-ro:Synthetic-Axl-1').toString('base64')) return { status: 401, body: 'denied', type: 'text/plain' };
    if (r.url === '/axl/' && /listPhone/.test(r.headers.soapaction)) { assert.match(r.body, /<ns:listPhone><searchCriteria><name>%<\/name>/); return { body: AXL_REPLY }; }
    if (r.url === '/axl/' && /getCCMVersion/.test(r.headers.soapaction)) return { body: '<Envelope><Body><getCCMVersionResponse><return><componentVersion><version>12.5.1</version></componentVersion></return></getCCMVersionResponse></Body></Envelope>' };
    if (r.url === '/realtimeservice2/services/RISService70') { assert.match(r.body, /<soap:Item>SEP0004F2ABCDEF<\/soap:Item>/); return { body: RIS_REPLY }; }
    return { status: 404, body: '' };
  });
  t.after(() => fake.close());
  const port = Number(fake.url.split(':').pop());
  const cred = { kind: 'cucm_axl', target: { host: '127.0.0.1', port, axl_version: '12.5', ca_file: fake.caFile }, secret: { username: 'axl-ro', password: 'Synthetic-Axl-1' } };
  const r = await cucmM.collect(cred);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(r.phones[0], { name: 'SEP0004F2ABCDEF', mac: '00:04:f2:ab:cd:ef', description: 'TEST reception & lobby', model: 'Cisco 8845', device_pool: 'DP_TEST_HQ', protocol: 'SIP', status: 'Registered', ip: '10.30.0.40' });
  assert.deepEqual([r.phones[1].status, r.phones[1].ip], ['UnRegistered', '10.30.0.41']);
  assert.ok(fake.requests.every((x) => x.method === 'POST' && /listPhone|getCCMVersion|selectCmDevice/.test(x.headers.soapaction)), 'read-only SOAP operations only');
  assert.deepEqual([(await cucmM.test(cred)).ok, (await cucmM.test(Object.assign({}, cred, { secret: { username: 'axl-ro', password: 'nope' } }))).error_class], [true, 'auth']);
  // XML reader is entity-safe: an external entity is never expanded
  const d = xml.parse('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><a><b>&e;</b></a>');
  assert.equal(xml.textOf(d, 'b'), '&e;');
});

test('Azure: client-credentials token + Resource Graph (paged) → one record per VM with IPs and MACs', async (t) => {
  const TENANT = '11111111-2222-3333-4444-555555555555'; const APP = '66666666-7777-8888-9999-000000000000';
  const fake = await startHttpFake((r) => {
    if (r.url === `/${TENANT}/oauth2/v2.0/token`) {
      const f = new URLSearchParams(r.body);
      if (f.get('client_secret') !== 'Synthetic-Az-Secret' || f.get('grant_type') !== 'client_credentials' || f.get('scope') !== 'https://management.azure.com/.default') return { status: 401, body: { error: 'invalid_client' } };
      return { body: { access_token: 'synthetic-bearer', expires_in: 3600 } };
    }
    if (r.url === '/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01') {
      if (r.headers.authorization !== 'Bearer synthetic-bearer') return { status: 401, body: {} };
      const b = JSON.parse(r.body);
      assert.match(b.query, /microsoft.compute\/virtualmachines/);
      if (!b.options.$skipToken) return { body: { totalRecords: 3, count: 2, $skipToken: 'page2', data: [
        { id: '/subscriptions/s1/resourceGroups/RG-TEST/providers/Microsoft.Compute/virtualMachines/test-az-web', name: 'test-az-web', location: 'uaenorth', resourceGroup: 'RG-TEST', subscriptionId: 's1', osType: 'Linux', vmSize: 'Standard_B2s', powerState: 'PowerState/running', mac: '00-0D-3A-11-22-33', privateIp: '10.90.1.4' },
        { id: '/subscriptions/s1/resourceGroups/RG-TEST/providers/Microsoft.Compute/virtualMachines/test-az-web', name: 'test-az-web', location: 'uaenorth', resourceGroup: 'RG-TEST', subscriptionId: 's1', osType: 'Linux', vmSize: 'Standard_B2s', powerState: 'PowerState/running', mac: '00-0D-3A-11-22-33', privateIp: '10.90.1.5' }] } };
      return { body: { totalRecords: 3, count: 1, data: [{ id: '/subscriptions/s1/resourceGroups/RG-TEST/providers/Microsoft.Compute/virtualMachines/test-az-dc', name: 'test-az-dc', location: 'uaenorth', resourceGroup: 'RG-TEST', subscriptionId: 's1', osType: 'Windows', vmSize: 'Standard_D2s_v5', powerState: '', mac: '00-0D-3A-44-55-66', privateIp: '10.90.1.10' }] } };
    }
    return null;
  });
  t.after(() => fake.close());
  const cred = { kind: 'azure', target: { tenant_id: TENANT, client_id: APP }, secret: { client_secret: 'Synthetic-Az-Secret' } };
  const r = await azM.collect(cred, { login_base: fake.url, arm_base: fake.url });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.vms.length, 2);
  assert.deepEqual(r.vms[0], { id: '/subscriptions/s1/resourcegroups/rg-test/providers/microsoft.compute/virtualmachines/test-az-web', name: 'test-az-web', location: 'uaenorth', resource_group: 'RG-TEST', subscription: 's1', os_type: 'Linux', size: 'Standard_B2s', power: 'running', ips: ['10.90.1.4', '10.90.1.5'], macs: ['00:0d:3a:11:22:33'] });
  assert.equal((await azM.test(Object.assign({}, cred, { secret: { client_secret: 'wrong' } }), { login_base: fake.url, arm_base: fake.url })).error_class, 'auth');
});

test('AWS: SigV4 matches the AWS documentation vectors; EC2 DescribeInstances signed, paged and parsed', async (t) => {
  const KEY = 'AKIDEXAMPLE'; const SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
  // aws-sig-v4-test-suite "get-vanilla"
  assert.equal(sigv4.sign({ method: 'GET', url: 'https://example.amazonaws.com/', region: 'us-east-1', service: 'service', accessKeyId: KEY, secretAccessKey: SECRET, amzDate: '20150830T123600Z' }).headers.Authorization,
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
  // AWS General Reference SigV4 example (IAM ListUsers): canonical request hash, signing key and signature
  const ex = sigv4.sign({ method: 'GET', url: 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08', headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' }, region: 'us-east-1', service: 'iam', accessKeyId: KEY, secretAccessKey: SECRET, amzDate: '20150830T123600Z' });
  assert.equal(sigv4.sha256hex(ex.canonicalRequest), 'f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59');
  assert.equal(sigv4.signingKey(SECRET, '20150830', 'us-east-1', 'iam').toString('hex'), 'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9');
  assert.equal(ex.signature, '5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7');

  const page1 = `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet><item><ownerId>123456789012</ownerId><instancesSet><item><instanceId>i-0test0000000001</instanceId><instanceType>t3.medium</instanceType><instanceState><code>16</code><name>running</name></instanceState><privateDnsName>ip-10-80-1-10.me-south-1.compute.internal</privateDnsName><privateIpAddress>10.80.1.10</privateIpAddress><ipAddress>198.51.100.7</ipAddress><platformDetails>Windows</platformDetails><placement><availabilityZone>me-south-1a</availabilityZone></placement><networkInterfaceSet><item><macAddress>0a:11:22:33:44:55</macAddress></item></networkInterfaceSet><tagSet><item><key>Name</key><value>test-aws-app</value></item></tagSet></item></instancesSet></item></reservationSet><nextToken>tok2</nextToken></DescribeInstancesResponse>`;
  const page2 = '<DescribeInstancesResponse><reservationSet><item><ownerId>123456789012</ownerId><instancesSet><item><instanceId>i-0test0000000002</instanceId><instanceType>t3.small</instanceType><instanceState><name>stopped</name></instanceState><privateIpAddress>10.80.1.11</privateIpAddress><placement><availabilityZone>me-south-1b</availabilityZone></placement></item></instancesSet></item></reservationSet></DescribeInstancesResponse>';
  let verified = 0;
  const fake = await startHttpFake((r) => {
    const amz = r.headers['x-amz-date'];
    const url = `http://127.0.0.1:${fake.port}${r.url}`;
    const expect = sigv4.sign({ method: 'GET', url, region: 'me-south-1', service: 'ec2', accessKeyId: 'AKIATESTSYNTHETIC', secretAccessKey: 'Synthetic/Aws/Secret/Key', amzDate: amz }).headers.Authorization;
    if (r.headers.authorization !== expect) return { status: 403, body: '<Response><Errors><Error><Code>SignatureDoesNotMatch</Code></Error></Errors></Response>' };
    verified++;
    const q = new URL(url).searchParams;
    assert.equal(q.get('Action'), 'DescribeInstances');
    return { body: q.get('NextToken') === 'tok2' ? page2 : page1 };
  });
  t.after(() => fake.close());
  const cred = { kind: 'aws', target: { regions: ['me-south-1'] }, secret: { access_key_id: 'AKIATESTSYNTHETIC', secret_access_key: 'Synthetic/Aws/Secret/Key' } };
  const r = await awsM.collect(cred, { endpoint: `http://127.0.0.1:${fake.port}` });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(verified, 2, 'both pages carried a valid SigV4 signature');
  assert.deepEqual(r.instances[0], { id: 'i-0test0000000001', name: 'test-aws-app', type: 't3.medium', state: 'running', private_ip: '10.80.1.10', public_ip: '198.51.100.7', private_dns: 'ip-10-80-1-10.me-south-1.compute.internal', macs: ['0a:11:22:33:44:55'], platform: 'Windows', region: 'me-south-1', az: 'me-south-1a', account: '123456789012' });
  assert.deepEqual([r.instances[1].state, r.instances[1].platform], ['stopped', 'Linux/UNIX']);
  const wrong = await awsM.test(Object.assign({}, cred, { secret: { access_key_id: 'AKIATESTSYNTHETIC', secret_access_key: 'not-it' } }), { endpoint: `http://127.0.0.1:${fake.port}` });
  assert.equal(wrong.error_class, 'auth');
});

test('vCenter test: classified result — TLS untrusted captures the cert, Trust & pin then succeeds (TOFU)', async (t) => {
  const fake = await startHttpsFake((r) => {
    if (r.method === 'POST' && r.url === '/api/session') return { status: 201, body: JSON.stringify('sess-pin-1'), type: 'application/json' };
    if (r.method === 'DELETE' && r.url === '/api/session') return { status: 204, body: {} };
    if (r.url === '/api/vcenter/host') return { body: [{ host: 'host-1', name: 'test-esx01', connection_state: 'CONNECTED' }] };
    return { status: 404, body: {} };
  });
  t.after(() => fake.close());
  // self-signed test chain, NO ca_file, NO pin → not trusted; the wizard must see the presented cert, not an auth error
  const cred = { kind: 'vcenter', target: { base_url: fake.url }, secret: { username: 'svc-ro@vsphere.local', password: 'Synthetic-Vc-Pass-1' } };
  const r = await vcM.test(cred);
  assert.equal(r.ok, false); assert.equal(r.error_class, 'tls'); assert.equal(r.stage, 'tls');
  assert.equal(r.tls.trusted, false);
  assert.ok(r.tls.presented, 'the presented certificate is captured');
  assert.match(r.tls.presented.fingerprint256, /^[0-9a-f]{64}$/);
  assert.ok(r.tls.presented.subject && r.tls.presented.issuer, 'subject + issuer present');
  assert.match(String(r.message), /not trusted/i);
  // Trust & pin: pin the captured fingerprint, then the same test succeeds
  const pinned = { kind: 'vcenter', target: { base_url: fake.url, tls_fingerprint: r.tls.presented.fingerprint256 }, secret: cred.secret };
  const ok = await vcM.test(pinned);
  assert.equal(ok.ok, true, JSON.stringify(ok)); assert.equal(ok.stage, 'read'); assert.equal(ok.tls.trusted, true); assert.equal(ok.tls.pinned, true);
  assert.deepEqual(ok.discovered, { hosts: 1 });
});

test('vCenter test: pin mismatch, auth-401 (with the user@domain hint), authz-on-read and timeout are each distinct', async (t) => {
  let mode = 'ok';
  const fake = await startHttpsFake((r) => {
    if (r.method === 'POST' && r.url === '/api/session') {
      if (mode === 'auth') return { status: 401, body: { error: 'bad' } };
      return { status: 201, body: JSON.stringify('sess-2'), type: 'application/json' };
    }
    if (r.method === 'DELETE' && r.url === '/api/session') return { status: 204, body: {} };
    if (r.url === '/api/vcenter/host') return mode === 'authz' ? { status: 403, body: { error: 'no' } } : { body: [{ host: 'h1', name: 'esx', connection_state: 'CONNECTED' }] };
    return { status: 404, body: {} };
  });
  t.after(() => fake.close());
  const base = { kind: 'vcenter', target: { base_url: fake.url, ca_file: fake.caFile }, secret: { username: 'svc-ro@vsphere.local', password: 'pw' } };
  // pin mismatch: a pin is set but it is not the server's certificate
  const mm = await vcM.test({ kind: 'vcenter', target: { base_url: fake.url, tls_fingerprint: '00'.repeat(32) }, secret: base.secret });
  assert.equal(mm.error_class, 'tls'); assert.equal(mm.stage, 'tls'); assert.equal(mm.tls.pin_mismatch, true);
  assert.match(String(mm.message), /does not match the approved pin/i);
  // reached + TLS trusted + 401 on login → auth (NOT tls), with the full-SSO-form hint
  mode = 'auth';
  const au = await vcM.test(base);
  assert.equal(au.error_class, 'auth'); assert.equal(au.stage, 'auth'); assert.equal(au.http, 401); assert.equal(au.tls.trusted, true);
  assert.match(String(au.message), /TLS OK/); assert.match(String(au.hint), /vsphere\.local/);
  // authenticated + 403 on the read → authz (missing read privilege), not auth
  mode = 'authz';
  const az = await vcM.test(base);
  assert.equal(az.error_class, 'authz'); assert.equal(az.stage, 'authz'); assert.equal(az.http, 403); assert.equal(az.tls.trusted, true);
  assert.match(String(az.hint), /read-only|read access|privilege/i);
  // timeout propagates as its own class (injected request)
  const to = await vcM.test(base, { request: () => Promise.reject(Object.assign(new Error('x'), { code: 'timeout' })) });
  assert.equal(to.error_class, 'timeout'); assert.equal(to.stage, 'connect');
});

test('AD test: wrong password is auth (LDAP 49 hint), not TLS; untrusted chain is tls', async (t) => {
  const ca = makeCA('Synthetic AD Diag CA');
  const leaf = makeServerCert(ca, { cn: DC, dns: [DC], ip: ['127.0.0.1'] });
  const srv = await startFakeLdap({ key: leaf.key, cert: leaf.cert, dir: adDirectory(), passwords: { [SVC]: SVC_PW } });
  t.after(() => srv.close());
  const cred = { kind: 'ldap', target: { servers: [`ldaps://${DC}:${srv.port}`], ip: '127.0.0.1', base_dn: BASE }, secret: { bind_dn: SVC, password: 'wrong' } };
  const r = await adM.test(cred, { ca: ca.cert });
  assert.equal(r.ok, false); assert.equal(r.error_class, 'auth'); assert.equal(r.stage, 'auth'); assert.equal(r.tls.trusted, true);
  assert.match(String(r.hint), /49|invalidCredentials/);
  const other = makeCA('Other CA');
  const tls = await adM.test(Object.assign({}, cred, { secret: { bind_dn: SVC, password: SVC_PW } }), { ca: other.cert, timeoutMs: 3000 });
  assert.equal(tls.ok, false);
  assert.ok(['tls', 'unreachable'].includes(tls.error_class), tls.error_class);
  if (tls.error_class === 'tls') assert.equal(tls.stage, 'tls');
});

test('Hyper-V report: normalised and validated (agent / relay ingestion)', () => {
  const r = hv.normReport({ host: { name: 'TEST-HV01', fqdn: ('TEST-HV01.' + 'corp-hq.com'), ip: '10.20.0.60', os: 'Windows Server 2022 Datacenter' }, collected_at: '2026-10-07T08:00:00Z', vms: [
    { name: 'TEST-HV-VM1', vm_id: 'B1C2D3E4-0000-0000-0000-000000000001', state: 'Running', generation: 2, ips: ['10.20.0.61', 'fe80::1'], macs: ['00155D010203'] },
    { name: 'TEST-HV-VM2', state: 3, macs: ['000000000000'] },
  ] });
  assert.deepEqual(r.host, { name: 'TEST-HV01', fqdn: ('test-hv01.' + 'corp-hq.com'), ip: '10.20.0.60', os: 'Windows Server 2022 Datacenter' });
  assert.deepEqual(r.vms[0], { id: 'B1C2D3E4-0000-0000-0000-000000000001', name: 'TEST-HV-VM1', state: 'on', generation: 2, os: null, ips: ['10.20.0.61'], macs: ['00:15:5d:01:02:03'] });
  assert.deepEqual([r.vms[1].state, r.vms[1].macs], ['off', []]);
  assert.throws(() => hv.normReport({ vms: [] }), /host.name/);
  assert.throws(() => hv.normReport({ host: { name: 'x' }, vms: 'no' }), /vms must be a list/);
});
