// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AWS EC2 inventory — READ ONLY. EC2 Query API "DescribeInstances" (Version 2016-11-15), signed with SigV4.
// Least privilege: an IAM user/role with ONLY {"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}.
// Keys are write-only in the vault.
//   collect(cred, {endpoint, request}) → {ok, instances[{id, name, type, state, private_ip, public_ip, private_dns, macs[],
//                                          platform, region, az, account}]} | {ok:false, error_class}
//   test(cred) → one DescribeInstances page (MaxResults 5) in the first region
//   parseDescribe(xmlText) → {instances, nextToken}
const httpc = require('../httpc');
const xml = require('../xml');
const diag = require('../diag');
const { sign } = require('../sigv4');

const VERSION = '2016-11-15';
function errorClass(e) { return ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol'; }

function parseDescribe(text, region) {
  const doc = xml.parse(text);
  const out = [];
  const resSet = xml.find(doc, 'reservationSet');
  for (const res of resSet ? resSet.children : []) {
    const account = xml.childText(res, 'ownerId') || null;
    const inst = xml.child(res, 'instancesSet');
    for (const i of inst ? inst.children : []) {
      const tags = xml.child(i, 'tagSet');
      const nameTag = tags ? tags.children.find((t) => xml.childText(t, 'key') === 'Name') : null;
      const nis = xml.child(i, 'networkInterfaceSet');
      const macs = nis ? nis.children.map((n) => xml.childText(n, 'macAddress').toLowerCase()).filter(Boolean) : [];
      const state = xml.child(i, 'instanceState');
      const placement = xml.child(i, 'placement');
      out.push({
        id: xml.childText(i, 'instanceId'), name: nameTag ? xml.childText(nameTag, 'value') : null, type: xml.childText(i, 'instanceType') || null,
        state: state ? xml.childText(state, 'name') || null : null, private_ip: xml.childText(i, 'privateIpAddress') || null, public_ip: xml.childText(i, 'ipAddress') || null,
        private_dns: xml.childText(i, 'privateDnsName') || null, macs,
        platform: xml.childText(i, 'platformDetails') || (xml.childText(i, 'platform') === 'windows' ? 'Windows' : 'Linux/UNIX'),
        region, az: placement ? xml.childText(placement, 'availabilityZone') || null : null, account,
      });
    }
  }
  const next = xml.find(doc, 'nextToken');
  return { instances: out.filter((x) => x.id), nextToken: next ? next.text.trim() || null : null };
}

async function describe(cred, region, o, nextToken, max) {
  const tpl = o.endpoint || 'https://ec2.{region}.amazonaws.com';
  const base = tpl.replace('{region}', region).replace(/\/+$/, '');
  const qs = new URLSearchParams({ Action: 'DescribeInstances', Version: VERSION, MaxResults: String(max) });
  if (nextToken) qs.set('NextToken', nextToken);
  const url = `${base}/?${qs.toString()}`;
  const s = sign({ method: 'GET', url, region, service: 'ec2', accessKeyId: cred.secret.access_key_id, secretAccessKey: cred.secret.secret_access_key, amzDate: o.amzDate });   // amzDate: tests only
  const r = await (o.request || httpc.request)(url, { method: 'GET', headers: s.headers, caFile: o.caFile, timeoutMs: o.timeoutMs || 30000 });
  const errText = r.status >= 400 ? r.text : '';
  if (/UnauthorizedOperation/.test(errText)) throw diag.err('authz', 'AWS access key lacks ec2:DescribeInstances', { stage: 'authz', http: r.status, tlsTrusted: true });
  if (r.status === 401 || r.status === 403 || /AuthFailure|SignatureDoesNotMatch|InvalidClientTokenId/.test(errText)) throw diag.err('auth', 'AWS rejected the access key', { stage: 'auth', http: r.status, tlsTrusted: true });
  if (r.status >= 400) throw diag.err('protocol', `EC2 DescribeInstances HTTP ${r.status}`, { stage: 'read', http: r.status, tlsTrusted: true });
  return parseDescribe(r.text, region);
}

async function collect(cred, o = {}) {
  const t0 = Date.now();
  try {
    const instances = [];
    for (const region of (cred.target && cred.target.regions) || []) {
      let token = null; let pages = 0;
      do { const r = await describe(cred, region, o, token, 1000); instances.push(...r.instances); token = r.nextToken; pages++; } while (token && pages < 100);
    }
    return { ok: true, instances, latency_ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: errorClass(e), latency_ms: Date.now() - t0 }; }
}

async function test(cred, o = {}) {
  const t0 = Date.now();
  try { await describe(cred, cred.target.regions[0], o, null, 5); return diag.result('aws', { latency_ms: Date.now() - t0, http: 200 }); } catch (e) { return diag.fromError('aws', e, { latency_ms: Date.now() - t0 }); }
}

module.exports = { collect, test, parseDescribe, VERSION };
