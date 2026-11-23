// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 5b (docs/PYTHON-MIGRATION.md): pyengine/ad_source.py + ldap_client.py must answer exactly like
// engine/discovery/methods/ad.js + ldap-client.js. Both talk to the same fake directory (LDAPS and LDAP + StartTLS, a
// throwaway CA, paged search over 1,203 computers) and must return the same computers AND send the same LDAP bytes:
// bind, every search page with its cookie, unbind. Wrong password, an empty password (never sent), no read right, an
// untrusted certificate, a certificate checked against the DNS name while an IP is dialled, failover, size limit.
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const L = require('../engine/discovery/ldap-client');
const AD = require('../engine/discovery/methods/ad');
const { createPyEngine } = require('../engine/pyengine');

const B = L._ber;
const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const BIND = 'CN=svc-discovery,OU=Service Accounts,DC=corp-hq,DC=com', PW = 'Ad$ecret pässword';

let CERTS = null;
function certs() {
  if (CERTS !== null) return CERTS;
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ad-py-'));
  const mk = (n, san) => spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(d, n + '.key'), '-out', path.join(d, n + '.pem'), '-days', '2', '-subj', '/CN=dc1.corp-hq.test',
    '-addext', 'subjectAltName=' + san, '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment']).status === 0;
  CERTS = mk('dc', 'DNS:dc1.corp-hq.test,IP:127.0.0.1') && mk('other', 'DNS:other.test') ? { key: fs.readFileSync(path.join(d, 'dc.key')), cert: fs.readFileSync(path.join(d, 'dc.pem')), ca: path.join(d, 'dc.pem'), otherCa: path.join(d, 'other.pem'), dir: d } : false;
  return CERTS;
}

// 1,203 computers: OUs, the default Computers container, disabled accounts, domain controllers, an escaped comma in a
// name, an upper-case DNS name, a ranged attribute, attributes missing, a never-logged-on account, Arabic text
const COMPUTERS = Array.from({ length: 1203 }, (_, i) => {
  const ou = i % 5 === 0 ? 'CN=Computers' : i % 7 === 0 ? 'OU=Domain Controllers' : 'OU=Workstations,OU=Riyadh';
  const name = i === 3 ? 'PC\\, Finance' : 'CORP-PC' + String(i).padStart(4, '0');
  const a = [['cn', [i === 3 ? 'PC, Finance' : name]], ['distinguishedName', ['CN=' + name + ',' + ou + ',DC=corp-hq,DC=com']]];
  if (i % 3) a.push(['dNSHostName', [(name + '.CORP-HQ.com').replace('\\, ', '-')]]);
  if (i % 4) a.push(['operatingSystem', [i % 8 ? 'Windows 11 Enterprise' : 'Windows Server 2022 Datacenter']], ['operatingSystemVersion', ['10.0 (22631)']]);
  a.push(['lastLogonTimestamp', [i % 11 === 0 ? '0' : i % 13 === 0 ? '9223372036854775807' : String(133700000000000000n + BigInt(i) * 123456789n)]]);
  a.push(['userAccountControl', [i % 6 === 0 ? '4098' : i % 7 === 0 ? '532480' : '4096']]);
  if (i % 7 === 0) a.push(['primaryGroupID', [i % 14 === 0 ? '521' : '516']]);
  if (i === 9) a.push(['name;range=0-1', ['جهاز المالية']]);
  return { dn: i === 10 ? '' : 'CN=' + name + ',' + ou + ',DC=corp-hq,DC=com', attrs: a };
});

function server(mode, secure) {
  const conns = [];
  const res = (id, tag, code, diag, controls) => B.message(id, B.tlv(tag, [B.berInt(code, 0x0a), B.berStr(''), B.berStr(diag || '')]), controls);
  function handle(sock, rec) {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        const t = B.readTLV(buf, 0); if (!t) break;
        const raw = buf.slice(0, t.next); buf = buf.slice(t.next);
        rec.push(raw.toString('hex'));
        const m = B.parseMessage(raw), k = B.children(raw, m.op);
        if (m.tag === 0x42) { sock.end(); return; }
        if (m.tag === 0x77) {   // StartTLS: answer in clear, then the same socket carries TLS
          sock.write(B.message(m.id, B.tlv(0x78, [B.berInt(0, 0x0a), B.berStr(''), B.berStr('')])));
          sock.removeListener('data', onData);
          const ts = new tls.TLSSocket(sock, { isServer: true, key: CERTS.key, cert: CERTS.cert });
          ts.on('error', () => {}); handle(ts, rec); return;
        }
        if (m.tag === 0x60) {
          const dn = B.readStr(raw, k[1]), pw = B.readStr(raw, k[2]);
          sock.write(dn === BIND && pw === PW ? res(m.id, 0x61, 0) : res(m.id, 0x61, 49, '80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563'));
          continue;
        }
        if (m.tag === 0x63) {
          if (mode === 'noread') { sock.write(res(m.id, 0x65, 50, '00002098: SecErr: DSID-03150F94, problem 4003 (INSUFF_ACCESS_RIGHTS)')); continue; }
          const scope = B.readInt(raw, k[1]);
          if (scope === 0) { sock.write(B.message(m.id, B.tlv(0x64, [B.berStr('DC=corp-hq,DC=com'), B.tlv(0x30, [B.tlv(0x30, [B.berStr('distinguishedName'), B.tlv(0x31, [B.berStr('DC=corp-hq,DC=com')])])])]))); sock.write(res(m.id, 0x65, 0)); continue; }
          const pc = m.controls.find((c) => c.oid === L.OID.PAGED), pv = B.children(pc.value, B.readTLV(pc.value, 0));
          const size = B.readInt(pc.value, pv[0]), off = Number(B.readStr(pc.value, pv[1]) || 0);
          for (const c of COMPUTERS.slice(off, off + size)) sock.write(B.message(m.id, B.tlv(0x64, [B.berStr(c.dn), B.tlv(0x30, c.attrs.map(([n, v]) => B.tlv(0x30, [B.berStr(n), B.tlv(0x31, v.map((x) => B.berStr(x)))])))])));
          const next = off + size < COMPUTERS.length ? String(off + size) : '';
          sock.write(res(m.id, 0x65, 0, '', [B.tlv(0x30, [B.berStr(L.OID.PAGED), B.berStr(B.tlv(0x30, [B.berInt(0), B.berStr(next)]))])]));
        }
      }
    };
    sock.on('data', onData); sock.on('error', () => {});
  }
  const srv = (secure ? tls.createServer({ key: certs().key, cert: CERTS.cert }) : net.createServer()).on(secure ? 'secureConnection' : 'connection', (s) => { const rec = []; conns.push(rec); handle(s, rec); });
  return new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok({ port: srv.address().port, conns, close: () => new Promise((d) => { srv.close(() => d()); }) })));
}
const settle = () => new Promise((r) => setTimeout(r, 150));
const strip = (r) => { const o = JSON.parse(JSON.stringify(r)); delete o.latency_ms; delete o.engine; return o; };

async function both(label, mode, secure, cred, opts = {}, ops = ['collect', 'test']) {
  const py = createPyEngine({ python: PY }), out = {};
  for (const op of ops) {
    const s1 = await server(mode, secure), s2 = await server(mode, secure);
    try {
      const n = await AD[op](cred(s1), opts);
      const p = await py.call('discovery.' + op, { method: 'ad', cred: cred(s2), opts });
      await settle();
      assert.deepEqual(strip(p), strip(n), `${label} ${op}: identical answers`);
      assert.deepEqual(s2.conns, s1.conns, `${label} ${op}: the same LDAP messages, byte for byte`);
      out[op] = { r: n, conns: s1.conns };
    } finally { await s1.close(); await s2.close(); }
  }
  return out;
}
const cred = (url, extra = {}, sec = {}) => (s) => ({ target: Object.assign({ servers: [url.replace('PORT', s.port)], base_dn: 'DC=corp-hq,DC=com', ca_file: CERTS.ca }, extra), secret: Object.assign({ bind_dn: BIND, password: PW }, sec) });

test('Python Active Directory discovery answers exactly like the Node.js one', { skip: (!hasPy && 'python3 not available') || (!certs() && 'openssl not available') }, async () => {
  const r = await both('LDAPS', '', true, cred('ldaps://127.0.0.1:PORT'));
  const c = r.collect.r.computers;
  assert.equal(c.length, 1203); assert.equal(r.collect.conns[0].length, 1 + 3 + 1, 'bind, 3 pages of 500, unbind');
  assert.deepEqual([c[3].name, c[0].ou, c[1].ou, c[7].is_dc, c[14].is_dc, c[6].enabled, c[11].last_logon, c[9].name], ['PC, Finance', 'Computers', 'Workstations / Riyadh', true, true, false, null, 'CORP-PC0009']);
  assert.equal(r.test.r.ok, true);
  await both('LDAP + StartTLS', '', false, cred('ldap://127.0.0.1:PORT'));
  await both('IP dialled, certificate checked against the DNS name', '', true, cred('ldaps://dc1.corp-hq.test:PORT', { ip: '127.0.0.1' }));
  const free = await new Promise((ok) => { const x = net.createServer().listen(0, '127.0.0.1', () => { const p = x.address().port; x.close(() => ok(p)); }); });
  const fo = await both('failover', '', true, (s) => ({ target: { servers: ['ldaps://127.0.0.1:' + free, 'ldaps://127.0.0.1:' + s.port], base_dn: 'DC=corp-hq,DC=com', ca_file: CERTS.ca }, secret: { bind_dn: BIND, password: PW } }), {}, ['collect']);
  assert.equal(fo.collect.r.computers.length, 1203);
  const bad = await both('wrong password', '', true, cred('ldaps://127.0.0.1:PORT', {}, { password: 'wrong' }));
  assert.equal(bad.collect.r.error_class, 'auth'); assert.equal(bad.test.r.error_class, 'auth');
  const empty = await both('empty password', '', true, cred('ldaps://127.0.0.1:PORT', {}, { password: '' }));
  assert.equal(empty.collect.r.error_class, 'auth'); assert.equal(empty.collect.conns[0].length, 1, 'only the unbind: the empty bind is never sent');
  assert.equal((await both('no read right', 'noread', true, cred('ldaps://127.0.0.1:PORT'))).collect.r.error_class, 'authz');
  assert.equal((await both('untrusted certificate', '', true, cred('ldaps://127.0.0.1:PORT', { ca_file: CERTS.otherCa }))).test.r.error_class, 'tls');
  assert.equal((await both('wrong name on the certificate', '', true, cred('ldaps://localhost:PORT', { ip: '127.0.0.1' }))).collect.r.error_class, 'tls');
  assert.equal((await both('missing CA file', '', true, cred('ldaps://127.0.0.1:PORT', { ca_file: path.join(CERTS.dir, 'none.pem') }))).collect.r.error_class, 'config');
  // the Node.js classifier reads the word "StartTLS" in the URL hint as a TLS problem; kept identical on purpose
  assert.equal((await both('not an LDAP URL', '', true, cred('https://127.0.0.1:PORT'))).test.r.error_class, 'tls');
  assert.equal((await both('size limit', '', true, cred('ldaps://127.0.0.1:PORT'), { maxEntries: 10 }, ['collect'])).collect.r.error_class, 'protocol');
});

test('Python LDAP filter encoding is byte-identical to the Node.js one', { skip: !hasPy && 'python3 not available' }, () => {
  const filters = ['(objectClass=computer)', 'cn=PC*', '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', '(|(cn=a\\2ab*c*d)(sn>=x)(sn<=y)(sn~=z)(mail=*))',
    '(memberOf:1.2.840.113556.1.4.1941:=CN=Admins,DC=x)', '(cn=*mid*)', '(name=جهاز)', '(:dn:2.5.13.5:=x)'];
  const code = 'import json,sys;sys.path.insert(0,sys.argv[1]);import ldap_client as L;print(json.dumps([L.encode_filter(f).hex() for f in json.loads(sys.stdin.read())]))';
  const p = spawnSync(PY, ['-I', '-c', code, path.join(__dirname, '..', 'pyengine')], { input: JSON.stringify(filters), encoding: 'utf8' });
  assert.deepEqual(JSON.parse(p.stdout), filters.map((f) => L.encodeFilter(f).toString('hex')), p.stderr);
  for (const bad of ['(cn=a(b)', '(=x)', '(cn=\\zz)', '(cn=x))']) {
    assert.throws(() => L.parseFilter(bad));
    const q = spawnSync(PY, ['-I', '-c', 'import sys;sys.path.insert(0,sys.argv[1]);import ldap_client as L\ntry:\n L.parse_filter(sys.argv[2]); print("accepted")\nexcept L.LdapError: print("refused")', path.join(__dirname, '..', 'pyengine'), bad], { encoding: 'utf8' });
    assert.equal(q.stdout.trim(), 'refused', bad);
  }
});
