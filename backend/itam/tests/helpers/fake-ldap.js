// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// In-process fake Active Directory LDAP server for tests (TLS, no network beyond 127.0.0.1). Its BER code is written
// independently of engine/ad/ldap-client.js so codec bugs cannot cancel out.
//   startFakeLdap({ key, cert, dir, passwords, tls: true|false (false = plain TCP that only allows StartTLS), maxPage })
//     → { port, url, requests[], binds[], close() }
//   dir: makeDirectory() — entries keyed by DN with attrs {name: [values]} (names case-insensitive), helpers addMember().
// Behaviour modelled on AD: bind 0 / 49 ("data 52e"); an EMPTY simple-bind password succeeds anonymously (the RFC 4513
// trap the client must refuse); search requires a non-anonymous bind; MaxPageSize 1000 (unpaged > 1000 → 1000 entries +
// sizeLimitExceeded); paged results control 1.2.840.113556.1.4.319; LDAP_MATCHING_RULE_IN_CHAIN on member/memberOf;
// bitwise AND rule 1.2.840.113556.1.4.803; continuation references at the domain root.
const tls = require('tls');
const net = require('net');

const PAGED = '1.2.840.113556.1.4.319';
const IN_CHAIN = '1.2.840.113556.1.4.1941';
const BIT_AND = '1.2.840.113556.1.4.803';

// ---- independent BER
function L(n) { if (n < 128) return Buffer.from([n]); const b = []; while (n) { b.unshift(n & 255); n = Math.floor(n / 256); } return Buffer.from([0x80 | b.length, ...b]); }
function T(tag, ...parts) { const c = Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(String(p), 'utf8')))); return Buffer.concat([Buffer.from([tag]), L(c.length), c]); }
function I(n, tag = 0x02) { const b = []; do { b.unshift(n & 255); n = Math.floor(n / 256); } while (n > 0); if (b[0] & 0x80) b.unshift(0); return T(tag, Buffer.from(b)); }
function read(buf, off, end = buf.length) {
  if (off + 2 > end) return null;
  let len = buf[off + 1]; let p = off + 2;
  if (len & 0x80) { const nb = len & 0x7f; if (p + nb > end) return null; len = 0; for (let i = 0; i < nb; i++) len = len * 256 + buf[p + i]; p += nb; }
  if (p + len > end) return null;
  return { tag: buf[off], s: p, e: p + len, val: buf.slice(p, p + len) };
}
function kids(node) { const out = []; let p = 0; while (p < node.val.length) { const k = read(node.val, p); out.push(k); p = k.e; } return out; }
const num = (n) => { let v = 0; for (const b of n.val) v = v * 256 + b; if (n.val.length && n.val[0] & 0x80) v -= 256 ** n.val.length; return v; };
const str = (n) => n.val.toString('utf8');

function decodeFilter(n) {
  switch (n.tag) {
    case 0xa0: return { t: 'and', f: kids(n).map(decodeFilter) };
    case 0xa1: return { t: 'or', f: kids(n).map(decodeFilter) };
    case 0xa2: return { t: 'not', f: decodeFilter(kids(n)[0]) };
    case 0xa3: case 0xa5: case 0xa6: case 0xa8: { const [a, v] = kids(n); return { t: { 0xa3: 'eq', 0xa5: 'ge', 0xa6: 'le', 0xa8: 'eq' }[n.tag], a: str(a), v: str(v) }; }
    case 0x87: return { t: 'present', a: str(n) };
    case 0xa4: { const [a, s] = kids(n); return { t: 'sub', a: str(a), parts: kids(s).map((k) => ({ k: k.tag, v: str(k).toLowerCase() })) }; }
    case 0xa9: { const o = { t: 'ext' }; for (const k of kids(n)) { if (k.tag === 0x81) o.rule = str(k); if (k.tag === 0x82) o.a = str(k); if (k.tag === 0x83) o.v = str(k); if (k.tag === 0x84) o.dn = !!k.val[0]; } return o; }
    default: throw new Error('fake-ldap: unsupported filter tag 0x' + n.tag.toString(16));
  }
}

function makeDirectory() {
  const byDn = new Map();
  const key = (dn) => String(dn).toLowerCase();
  const dir = {
    add(dn, attrs) {
      const e = { dn, attrs: {} };
      for (const [k, v] of Object.entries(attrs)) e.attrs[k.toLowerCase()] = { name: k, vals: [].concat(v).map((x) => (Buffer.isBuffer(x) ? x : String(x))) };
      e.attrs.distinguishedname = { name: 'distinguishedName', vals: [dn] };
      byDn.set(key(dn), e);
      return e;
    },
    get(dn) { return byDn.get(key(dn)); },
    remove(dn) { byDn.delete(key(dn)); },
    all() { return [...byDn.values()]; },
    vals(e, a) { const x = e.attrs[String(a).toLowerCase()]; return x ? x.vals.map((v) => (Buffer.isBuffer(v) ? v.toString('latin1') : v)) : []; },   // binary values compare as latin1
    set(dn, a, vals) { const e = dir.get(dn); e.attrs[a.toLowerCase()] = { name: a, vals: [].concat(vals).map(String) }; },
    addMember(groupDn, memberDn) {
      const g = dir.get(groupDn); const m = dir.get(memberDn);
      if (!g || !m) throw new Error('fake-ldap: unknown dn ' + (g ? memberDn : groupDn));
      (g.attrs.member = g.attrs.member || { name: 'member', vals: [] }).vals.push(memberDn);
      (m.attrs.memberof = m.attrs.memberof || { name: 'memberOf', vals: [] }).vals.push(groupDn);
    },
  };
  return dir;
}

// transitive closure of a DN-valued attribute (member or memberOf), following the referenced entries
function chain(dir, e, attr) {
  const seen = new Set(); const todo = [...dir.vals(e, attr)];
  while (todo.length) { const dn = todo.pop(); const k = dn.toLowerCase(); if (seen.has(k)) continue; seen.add(k); const x = dir.get(dn); if (x) todo.push(...dir.vals(x, attr)); }
  return seen;
}

function match(dir, e, f) {
  const vals = (a) => dir.vals(e, a);
  switch (f.t) {
    case 'and': return f.f.every((x) => match(dir, e, x));
    case 'or': return f.f.some((x) => match(dir, e, x));
    case 'not': return !match(dir, e, f.f);
    case 'present': return f.a.toLowerCase() === 'objectclass' || vals(f.a).length > 0;
    case 'eq': {
      const v = f.v.toLowerCase();
      if (f.a.toLowerCase() === 'objectcategory') return vals(f.a).some((x) => x.toLowerCase() === v || /^cn=([^,]+)/i.exec(x)[1].toLowerCase() === v);
      return vals(f.a).some((x) => x.toLowerCase() === v);
    }
    case 'ge': return vals(f.a).some((x) => (/^-?\d+$/.test(x) ? Number(x) >= Number(f.v) : x >= f.v));
    case 'le': return vals(f.a).some((x) => (/^-?\d+$/.test(x) ? Number(x) <= Number(f.v) : x <= f.v));
    case 'sub': return vals(f.a).some((x) => {
      let s = x.toLowerCase(); let pos = 0;
      for (const p of f.parts) {
        if (p.k === 0x80) { if (!s.startsWith(p.v)) return false; pos = p.v.length; }
        else if (p.k === 0x81) { const i = s.indexOf(p.v, pos); if (i < 0) return false; pos = i + p.v.length; }
        else if (p.k === 0x82) { if (!s.endsWith(p.v) || s.length - p.v.length < pos) return false; }
      }
      return true;
    });
    case 'ext':
      if (f.rule === IN_CHAIN) return chain(dir, e, f.a).has(String(f.v).toLowerCase());
      if (f.rule === BIT_AND) return vals(f.a).some((x) => (Number(x) & Number(f.v)) === Number(f.v));
      throw new Error('fake-ldap: unsupported matching rule ' + f.rule);
    default: return false;
  }
}

function inScope(dn, base, scope) {
  const d = dn.toLowerCase(); const b = base.toLowerCase();
  if (scope === 0) return d === b;
  if (!(d === b || d.endsWith(',' + b) || b === '')) return false;
  if (scope === 1) return d !== b && d.slice(0, d.length - b.length - 1).indexOf('=') === d.slice(0, d.length - b.length - 1).lastIndexOf('=');
  return true;
}

function startFakeLdap({ key, cert, dir, passwords = {}, tls: useTls = true, maxPage = 1000, host = '127.0.0.1', rootDSE = {}, referrals = true, readOnly = [] } = {}) {
  // Add / Modify: st.passwords[dn lower-case] = the password set through unicodePwd (decoded); readOnly = bind DNs refused writes (50)
  const st = { requests: [], binds: [], connections: 0, passwords: {}, readOnly: new Set(readOnly.map((x) => x.toLowerCase())) };
  function handle(sock, isPlain) {
    st.connections++;
    let buf = Buffer.alloc(0); let bound = null; let upgraded = false;
    const send = (id, op, controls) => { if (!sock.destroyed) sock.write(T(0x30, I(id), op, ...(controls ? [T(0xa0, ...controls)] : []))); };
    const result = (tag, code, diag = '', extra = []) => T(tag, I(code, 0x0a), T(0x04, ''), T(0x04, diag), ...extra);
    function onData(c) {
      buf = Buffer.concat([buf, c]);
      for (;;) {
        const m = read(buf, 0); if (!m) break;
        buf = buf.slice(m.e);
        const [idN, op, ctl] = kids(m);
        const id = num(idN);
        const controls = ctl && ctl.tag === 0xa0 ? kids(ctl).map((cc) => { const k = kids(cc); return { oid: str(k[0]), value: k.find((x) => x.tag === 0x04 && x !== k[0]) }; }) : [];
        if (op.tag === 0x42) { st.requests.push({ op: 'unbind' }); sock.end(); return; }
        if (isPlain && !upgraded) {                                     // plain listener: only StartTLS is accepted
          if (op.tag === 0x77 && str(kids(op)[0]) === '1.3.6.1.4.1.1466.20037') {
            st.requests.push({ op: 'starttls' });
            send(id, result(0x78, 0, '', [T(0x8a, '1.3.6.1.4.1.1466.20037')]));
            upgraded = true; sock.removeListener('data', onData);
            const ts = new tls.TLSSocket(sock, { isServer: true, key, cert });
            ts.on('error', () => {});
            handle(ts, false);
            return;
          }
          st.requests.push({ op: 'cleartext-refused', tag: op.tag });
          send(id, result(op.tag === 0x60 ? 0x61 : 0x65, 13, 'confidentiality required'));
          continue;
        }
        if (op.tag === 0x60) {
          const [, nameN, auth] = kids(op);
          const dn = str(nameN); const pw = auth.val.toString('utf8');
          st.binds.push({ dn, empty: pw.length === 0 });
          st.requests.push({ op: 'bind', dn });
          if (pw.length === 0) { bound = null; send(id, result(0x61, 0)); continue; }  // anonymous "success" — the trap
          // AD also accepts the account's userPrincipalName (user@domain) as the bind name
          const byUpn = /@/.test(dn) ? dir.all().find((x) => (dir.vals(x, 'userPrincipalName')[0] || '').toLowerCase() === dn.toLowerCase()) : null;
          const ok = Object.keys(passwords).find((k) => k.toLowerCase() === (byUpn ? byUpn.dn : dn).toLowerCase());
          if (ok && passwords[ok] === pw) { bound = ok; send(id, result(0x61, 0)); }
          else { bound = null; send(id, result(0x61, 49, '80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563')); }
          continue;
        }
        if (op.tag === 0x6c) {                                          // ModifyDN (move to another OU)
          const k = kids(op); const dn = str(k[0]), rdn = str(k[1]), sup = k[3] && k[3].tag === 0x80 ? str(k[3]) : null;
          st.requests.push({ op: 'moddn', dn, rdn, newSuperior: sup });
          if (!bound) { send(id, result(0x6d, 1, 'bind required')); continue; }
          if (st.readOnly.has(bound.toLowerCase())) { send(id, result(0x6d, 50, '00000005: SecErr: problem 4003 (INSUFF_ACCESS_RIGHTS)')); continue; }
          const e = dir.get(dn);
          if (!e || (sup && !dir.get(sup))) { send(id, result(0x6d, 32, '0000208D: NameErr: problem 2001 (NO_OBJECT)')); continue; }
          const nd = rdn + ',' + (sup || dn.slice(dn.search(/(?<!\\),/) + 1));
          if (dir.get(nd)) { send(id, result(0x6d, 68, 'ENTRY_EXISTS')); continue; }
          const attrs = {}; for (const v of Object.values(e.attrs)) if (v.name !== 'distinguishedName') attrs[v.name] = v.vals;
          dir.remove(dn); dir.add(nd, attrs);
          for (const g of dir.all()) { const m = g.attrs.member; if (m) m.vals = m.vals.map((x) => (x.toLowerCase() === dn.toLowerCase() ? nd : x)); }
          if (st.passwords[dn.toLowerCase()] !== undefined) { st.passwords[nd.toLowerCase()] = st.passwords[dn.toLowerCase()]; delete st.passwords[dn.toLowerCase()]; }
          send(id, result(0x6d, 0)); continue;
        }
        if (op.tag === 0x4a) {                                          // Delete (one leaf object), as AD answers it
          const dn = op.val.toString('utf8');
          st.requests.push({ op: 'delete', dn });
          if (!bound) { send(id, result(0x6b, 1, 'bind required')); continue; }
          if (st.readOnly.has(bound.toLowerCase())) { send(id, result(0x6b, 50, '00000005: SecErr: DSID-03152857, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0')); continue; }
          if (!dir.get(dn)) { send(id, result(0x6b, 32, '0000208D: NameErr: DSID-03100241, problem 2001 (NO_OBJECT)')); continue; }
          if (dir.all().some((x) => x.dn.toLowerCase().endsWith(',' + dn.toLowerCase()))) { send(id, result(0x6b, 66, '00002015: UpdErr: DSID-031A1260, problem 6003 (CANT_ON_NON_LEAF)')); continue; }
          for (const g of dir.all()) { const m = g.attrs.member; if (m) m.vals = m.vals.filter((x) => x.toLowerCase() !== dn.toLowerCase()); }
          dir.remove(dn); delete st.passwords[dn.toLowerCase()];
          send(id, result(0x6b, 0)); continue;
        }
        if (op.tag === 0x68 || op.tag === 0x66) {                       // Add / Modify, as AD answers them
          const rt = op.tag === 0x68 ? 0x69 : 0x67;
          const [dnN, list] = kids(op); const dn = str(dnN);
          const pwdOf = (v) => { const s = v.toString('utf16le'); return v.length % 2 === 0 && /^".*"$/.test(s) ? s.slice(1, -1) : null; };
          if (!bound) { send(id, result(rt, 1, '000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563')); continue; }
          if (st.readOnly.has(bound.toLowerCase())) { send(id, result(rt, 50, '00000005: SecErr: DSID-03152857, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0')); continue; }
          if (op.tag === 0x68) {
            const attrs = {}; let pw = null;
            for (const a of kids(list)) { const [n, vs] = kids(a); const name = str(n); const vals = kids(vs).map((x) => x.val); if (name.toLowerCase() === 'unicodepwd') pw = pwdOf(vals[0]); else attrs[name] = vals.map((x) => x.toString('utf8')); }
            st.requests.push({ op: 'add', dn, attrs, password: pw !== null });
            if (dir.get(dn)) { send(id, result(rt, 68, '00000524: UpdErr: DSID-031A11E2, problem 6005 (ENTRY_EXISTS), data 0')); continue; }
            if (!dir.get(dn.slice(dn.search(/(?<!\\),/) + 1))) { send(id, result(rt, 32, '0000208D: NameErr: DSID-0310028C, problem 2001 (NO_OBJECT)')); continue; }
            if (pw === null) { send(id, result(rt, 53, '0000001F: SvcErr: DSID-031A126C, problem 5003 (WILL_NOT_PERFORM), data 0')); continue; }
            dir.add(dn, attrs); st.passwords[dn.toLowerCase()] = pw;
            send(id, result(rt, 0)); continue;
          }
          const e = dir.get(dn);
          const changes = kids(list).map((c) => { const [o, a] = kids(c); const [n, vs] = kids(a); return { op: ['add', 'delete', 'replace'][num(o)], attr: str(n), vals: kids(vs).map((x) => x.val) }; });
          st.requests.push({ op: 'modify', dn, changes: changes.map((c) => ({ op: c.op, attr: c.attr, vals: c.attr.toLowerCase() === 'unicodepwd' ? ['<password>'] : c.vals.map((x) => x.toString('utf8')) })) });
          if (!e) { send(id, result(rt, 32, '0000208D: NameErr: DSID-03100241, problem 2001 (NO_OBJECT)')); continue; }
          let code = 0, diag = '';
          for (const c of changes) {
            const a = c.attr.toLowerCase(), vals = c.vals.map((x) => x.toString('utf8'));
            if (a === 'unicodepwd') { const p = pwdOf(c.vals[0]); if (p === null) { code = 53; diag = '0000001F: SvcErr: problem 5003 (WILL_NOT_PERFORM)'; break; } st.passwords[dn.toLowerCase()] = p; continue; }
            if (a === 'member') {
              const cur = dir.vals(e, 'member').map((x) => x.toLowerCase());
              if (c.op === 'add') {
                if (vals.some((v) => cur.includes(v.toLowerCase()))) { code = 68; diag = '00000562: UpdErr: DSID-031A11E2, problem 6005 (ENTRY_EXISTS)'; break; }
                for (const v of vals) { if (!dir.get(v)) { code = 32; break; } dir.addMember(dn, v); }
                if (code) break; continue;
              }
              if (c.op === 'delete') {
                if (vals.some((v) => !cur.includes(v.toLowerCase()))) { code = 16; diag = '0000054F: SvcErr: DSID-031A120C, problem 5003 (WILL_NOT_PERFORM)'; break; }
                for (const v of vals) { dir.set(dn, 'member', dir.vals(e, 'member').filter((x) => x.toLowerCase() !== v.toLowerCase())); const m = dir.get(v); if (m) dir.set(v, 'memberOf', dir.vals(m, 'memberOf').filter((x) => x.toLowerCase() !== dn.toLowerCase())); }
                continue;
              }
            }
            if (c.op === 'replace') dir.set(dn, c.attr, vals);
            else if (c.op === 'add') dir.set(dn, c.attr, dir.vals(e, c.attr).concat(vals));
            else dir.set(dn, c.attr, vals.length ? dir.vals(e, c.attr).filter((x) => !vals.includes(x)) : []);
          }
          send(id, result(rt, code, diag)); continue;
        }
        if (op.tag === 0x63) {
          const k = kids(op);
          const base = str(k[0]); const scope = num(k[1]); const sizeLimit = num(k[3]); const filter = decodeFilter(k[6]);
          const attrs = kids(k[7]).map((x) => str(x).toLowerCase());
          const req = { op: 'search', base, scope, filter, attrs, controls: controls.map((c) => c.oid) };
          st.requests.push(req);
          if (base === '' && scope === 0) {
            send(id, T(0x64, T(0x04, ''), T(0x30, ...Object.entries(Object.assign({ defaultNamingContext: 'DC=corp-hq,DC=com', dnsHostName: ('dc-hqa.' + 'corp-hq.com') }, rootDSE)).map(([n, v]) => T(0x30, T(0x04, n), T(0x31, ...[].concat(v).map((x) => T(0x04, x))))))));
            send(id, result(0x65, 0)); continue;
          }
          if (!bound) { send(id, result(0x65, 1, '000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563')); continue; }
          if (!dir.all().some((e) => e.dn.toLowerCase() === base.toLowerCase())) { send(id, result(0x65, 32, '0000208D: NameErr: DSID-03100241, problem 2001 (NO_OBJECT)')); continue; }
          let hits;
          try { hits = dir.all().filter((e) => inScope(e.dn, base, scope) && match(dir, e, filter)); } catch (err) { send(id, result(0x65, 2, err.message)); continue; }
          const paged = controls.find((c) => c.oid === PAGED);
          let page = hits; let cookie = null; let code = 0;
          if (paged) {
            const v = read(paged.value.val, 0); const [sz, ck] = kids(v);
            const size = Math.min(maxPage, num(sz) || maxPage); const off = ck.val.length ? Number(ck.val.toString()) : 0;
            req.page = { size, offset: off };
            page = hits.slice(off, off + size);
            cookie = off + size < hits.length ? String(off + size) : '';
          } else if (hits.length > maxPage || (sizeLimit && hits.length > sizeLimit)) { page = hits.slice(0, sizeLimit || maxPage); code = 4; }
          for (const e of page) {
            const list = Object.values(e.attrs).filter((a) => !attrs.length || attrs.includes('*') || attrs.includes(a.name.toLowerCase()));
            send(id, T(0x64, T(0x04, e.dn), T(0x30, ...list.map((a) => T(0x30, T(0x04, a.name), T(0x31, ...a.vals.map((x) => T(0x04, x))))))));
          }
          if (referrals && scope === 2 && /^dc=/i.test(base)) send(id, T(0x73, T(0x04, 'ldap://DomainDnsZones.' + base.replace(/dc=/gi, '').replace(/,/g, '.') + '/DC=DomainDnsZones,' + base)));
          send(id, result(0x65, code), cookie === null ? null : [T(0x30, T(0x04, PAGED), T(0x04, T(0x30, I(0), T(0x04, cookie))))]);
          continue;
        }
        send(id, result(0x65, 53, 'unsupported operation'));
      }
    }
    sock.on('data', onData);
    sock.on('error', () => {});
  }
  const server = useTls ? tls.createServer({ key, cert }, (s) => handle(s, false)) : net.createServer((s) => handle(s, true));
  const sockets = new Set();
  server.on(useTls ? 'secureConnection' : 'connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.on('tlsClientError', () => {});
  return new Promise((resolve) => server.listen(0, host, () => {
    st.port = server.address().port;
    st.close = () => new Promise((r) => { for (const s of sockets) s.destroy(); server.close(() => r()); });
    resolve(st);
  }));
}

// a port that refuses connections (server bound then closed) and a TCP server that accepts but never answers
async function deadPort() { const s = net.createServer(); await new Promise((r) => s.listen(0, '127.0.0.1', r)); const p = s.address().port; await new Promise((r) => s.close(r)); return p; }
function hangServer() {
  const socks = new Set();
  const s = net.createServer((c) => { socks.add(c); c.on('error', () => {}); });
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r({ port: s.address().port, close: () => new Promise((x) => { for (const c of socks) c.destroy(); s.close(() => x()); }) })));
}

module.exports = { startFakeLdap, makeDirectory, deadPort, hangServer };
