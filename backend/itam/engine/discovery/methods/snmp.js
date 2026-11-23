// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SNMP discovery (read-only; v2c community or v3 USM authNoPriv/authPriv) built on ../snmp-client.js.
//   sessionOptions(cred, {timeout, retries}) → createSession options (cred = vault.open() result)
//   probe(host, cred, opts) → {ok, descr} | {ok:false, error_class}          — the "UDP 161" liveness check of a sweep
//   collect(host, cred, opts) → {ok, sys{descr, object_id, name, location}, macs[], mac, serial, model, neighbours[], arp[{ip, mac}]}
//   arp: the device's own ARP table (routers / L3 switches / firewalls) - gives the MAC of every host it talks to,
//   including user PCs and servers on other subnets that AD or vCenter report without a MAC.
//   parseLldp(remRows, locRows, manRows) / parseCdp(rows, ifNames) → neighbour edges (pure; tested with fixtures)
// Standard MIB objects (SNMPv2-MIB, IF-MIB, ENTITY-MIB, LLDP-MIB 802.1AB) — OIDs verified against the public MIB
// trees; CISCO-CDP-MIB cdpCacheTable column numbers and the lldpRemManAddrTable index decoding are marked "verify"
// in docs/DISCOVERY.md (vendor firmware differs in what it fills in).
const snmp = require('../snmp-client');

const OID = {
  sysDescr: '1.3.6.1.2.1.1.1.0', sysObjectID: '1.3.6.1.2.1.1.2.0', sysName: '1.3.6.1.2.1.1.5.0', sysLocation: '1.3.6.1.2.1.1.6.0',
  ipNetToMediaPhysAddress: '1.3.6.1.2.1.4.22.1.2',          // IP-MIB ARP table: index ifIndex.a.b.c.d → MAC
  ifPhysAddress: '1.3.6.1.2.1.2.2.1.6', ifName: '1.3.6.1.2.1.31.1.1.1.1', ifDescr: '1.3.6.1.2.1.2.2.1.2',
  entPhysicalEntry: '1.3.6.1.2.1.47.1.1.1.1',               // .5 class (3 = chassis), .11 serial, .13 model name
  lldpRemEntry: '1.0.8802.1.1.2.1.4.1.1',                    // .4 chassisIdSubtype .5 chassisId .7 portId .8 portDesc .9 sysName
  lldpLocPortEntry: '1.0.8802.1.1.2.1.3.7.1',                // .3 portId .4 portDesc   (index = lldpLocPortNum)
  lldpRemManAddrEntry: '1.0.8802.1.1.2.1.4.2.1',             // index = timeMark.localPort.remIndex.addrSubtype.len.addr…  (verify)
  cdpCacheEntry: '1.3.6.1.4.1.9.9.23.1.2.1.1',               // .3 addressType .4 address .6 deviceId .7 devicePort .8 platform (verify)
};

function sessionOptions(cred, o = {}) {
  const t = cred.target || {}; const s = cred.secret || {};
  const base = { port: t.port || 161, timeout: o.timeout || 1500, retries: o.retries === undefined ? 1 : o.retries, maxRepetitions: 20 };
  if (cred.kind === 'snmp_v2c') return Object.assign(base, { version: '2c', community: s.community });
  if (cred.kind === 'snmp_v3') {
    const priv = s.priv_password && t.priv_protocol !== 'none';
    return Object.assign(base, { version: '3', user: s.user, authProtocol: t.auth_protocol || 'sha', authPassword: s.auth_password, privProtocol: priv ? 'aes' : undefined, privPassword: priv ? s.priv_password : undefined });
  }
  throw Object.assign(new Error(`credential kind ${cred.kind} is not SNMP`), { code: 'config' });
}

function errorClass(e) {
  const c = e && e.code;
  if (c === 'timeout') return 'timeout';
  if (['wrongDigests', 'unknownUserNames', 'authenticationFailure', 'decryptionError', 'unsupportedSecLevels', 'authorizationError', 'noAccess'].includes(c)) return 'auth';
  if (c === 'config') return 'config';
  if (c === 'send') return 'unreachable';
  return 'protocol';
}

const macOf = (buf) => (Buffer.isBuffer(buf) && buf.length === 6 && buf.some((b) => b) ? buf.toString('hex').match(/.{2}/g).join(':') : null);
const str = (vb) => snmp.vbString(vb);

async function withSession(host, cred, o, fn) {
  const create = o.createSession || snmp.createSession;
  const sess = create(Object.assign({ host }, sessionOptions(cred, o)));
  try { return await fn(sess); } finally { try { sess.close(); } catch { /* */ } }
}

async function probe(host, cred, o = {}) {
  const t0 = Date.now();
  try {
    return await withSession(host, cred, Object.assign({ retries: 0 }, o), async (s) => {
      const vbs = await s.get([OID.sysDescr]);
      return { ok: true, descr: str(vbs[0]) || '', latency_ms: Date.now() - t0 };
    });
  } catch (e) { return { ok: false, error_class: errorClass(e), latency_ms: Date.now() - t0 }; }
}

function decodeManAddrIndex(oidSuffix) {
  // <timeMark>.<localPort>.<remIndex>.<addrSubtype>.<len>.<a1>…   addrSubtype 1 = IPv4
  const p = oidSuffix.split('.').map(Number);
  if (p.length < 6) return null;
  const [timeMark, localPort, remIndex, subtype, len] = p;
  const addr = p.slice(5, 5 + len);
  return { key: `${timeMark}.${localPort}.${remIndex}`, localPort, ip: subtype === 1 && len === 4 && addr.length === 4 ? addr.join('.') : null };
}

// LLDP: remRows = table(lldpRemEntry); locRows = table(lldpLocPortEntry); manVbs = walk(lldpRemManAddrEntry col 3)
function parseLldp(remRows, locRows, manVbs) {
  const local = new Map((locRows || []).map((r) => [r.index, str(r.cols[4]) || str(r.cols[3]) || r.index]));
  const ipByKey = new Map();
  for (const vb of manVbs || []) {
    const suffix = vb.oid.slice(OID.lldpRemManAddrEntry.length + 3); // skip ".3."
    const d = decodeManAddrIndex(suffix);
    if (d && d.ip && !ipByKey.has(d.key)) ipByKey.set(d.key, d.ip);
  }
  const out = [];
  for (const r of remRows || []) {
    const [, localPort] = r.index.split('.');
    const chassisSub = snmp.vbNumber(r.cols[4]);
    const chassisRaw = r.cols[5] && Buffer.isBuffer(r.cols[5].value) ? r.cols[5].value : null;
    out.push({
      via: 'lldp', local_port: local.get(localPort) || localPort || null,
      remote_name: str(r.cols[9]) || null, remote_port: str(r.cols[8]) || str(r.cols[7]) || null,
      remote_mac: chassisSub === 4 ? macOf(chassisRaw) : null,
      remote_chassis: chassisSub === 4 ? macOf(chassisRaw) : (str(r.cols[5]) || null),
      remote_ip: ipByKey.get(r.index) || null,
    });
  }
  return out;
}

// CDP: rows = table(cdpCacheEntry) (index ifIndex.deviceIndex); ifNames: Map(ifIndex → name)
function parseCdp(rows, ifNames) {
  const out = [];
  for (const r of rows || []) {
    const [ifIndex] = r.index.split('.');
    const addrType = snmp.vbNumber(r.cols[3]);
    const addr = r.cols[4] && Buffer.isBuffer(r.cols[4].value) ? r.cols[4].value : null;
    out.push({
      via: 'cdp', local_port: (ifNames && ifNames.get(ifIndex)) || ifIndex || null,
      remote_name: str(r.cols[6]) || null, remote_port: str(r.cols[7]) || null, remote_platform: str(r.cols[8]) || null,
      remote_ip: addrType === 1 && addr && addr.length === 4 ? [...addr].join('.') : null, remote_mac: null, remote_chassis: null,
    });
  }
  return out;
}

async function entityRows(s, soft) {
  const base = OID.entPhysicalEntry, rows = new Map();
  for (const col of [5, 2, 11, 13]) {
    const vbs = await soft(() => s.walk(`${base}.${col}`, { maxRows: 2000 }));
    for (const vb of vbs || []) { const index = vb.oid.slice(base.length + 2 + String(col).length); if (!rows.has(index)) rows.set(index, { index, cols: {} }); rows.get(index).cols[col] = vb; }
  }
  return [...rows.values()];
}
// "Cisco Catalyst 9300 Series 48-port PoE Switch" / "C9300-48P chassis" → a model when the model-name column is empty
function modelFromDescr(d) {
  if (!d) return null;
  const m = /\b((?:WS-|C)\d{4}[A-Z]{0,2}(?:-[A-Z0-9]+)+)\b/i.exec(d) || /\b(Catalyst\s+\d{4}[A-Z]?(?:\s+Series)?)/i.exec(d) || /\b(Nexus\s*\d{4}[A-Z0-9-]*)/i.exec(d);
  return m && !/K9|-M$|UNIVERSAL|IPBASE|LANBASE/i.test(m[1]) ? m[1].trim() : null;   // not a software image name
}
// last resort for Cisco: the platform from the software image in sysDescr - "C2960X Software (C2960X-UNIVERSALK9-M)",
// "Catalyst L3 Switch Software (CAT9K_IOSXE)" → "Catalyst 9000 series (CAT9K_IOSXE)". Marked as a family, not an exact model.
function modelFromSysDescr(d) {
  if (!d || !/cisco/i.test(d)) return null;
  const direct = modelFromDescr(d); if (direct) return direct;
  const img = /\(([A-Z0-9_]+?)(?:-[A-Z0-9]+)*-M\)|\((CAT\d+K[A-Z0-9_]*)\)|\b(C\d{4}[A-Z]{0,3})\s+Software/i.exec(d);
  if (!img) return null;
  const code = (img[1] || img[2] || img[3]).toUpperCase();
  const fam = /^CAT(\d+)K/.exec(code);
  if (fam) return `Catalyst ${fam[1]}000 series (${code})`;
  const c = /^C(\d{4})([A-Z]{0,3})/.exec(code);
  return c ? `Catalyst ${c[1]}${c[2] ? '-' + c[2] : ''} series (${code})` : `Cisco (${code})`;
}

async function collect(host, cred, o = {}) {
  const t0 = Date.now();
  try {
    return await withSession(host, cred, o, async (s) => {
      const sys = await s.get([OID.sysDescr, OID.sysObjectID, OID.sysName, OID.sysLocation]);
      const res = {
        ok: true, latency_ms: 0,
        sys: { descr: str(sys[0]) || null, object_id: sys[1] && sys[1].type === 'OID' ? sys[1].value : null, name: str(sys[2]) || null, location: str(sys[3]) || null },
        macs: [], mac: null, serial: null, model: null, neighbours: [],
      };
      const soft = async (fn) => { try { return await fn(); } catch { return null; } }; // optional MIBs may be absent
      const phys = await soft(() => s.walk(OID.ifPhysAddress, { maxRows: 512 }));
      for (const vb of phys || []) { const m = macOf(vb.value); if (m && !res.macs.includes(m)) res.macs.push(m); }
      res.mac = res.macs[0] || null;
      // ENTITY-MIB: only the columns needed (class .5, description .2, serial .11, model .13). Walking the whole entry
      // ran out of rows on big switch stacks (hundreds of entities x 17 columns) before reaching serial / model.
      const ent = await entityRows(s, soft);
      if (ent.length) {
        const withSerial = ent.filter((r) => str(r.cols[11]));
        const chassis = withSerial.find((r) => snmp.vbNumber(r.cols[5]) === 3) || withSerial[0] || ent.find((r) => snmp.vbNumber(r.cols[5]) === 3);
        if (chassis) { res.serial = str(chassis.cols[11]) || null; res.model = str(chassis.cols[13]) || modelFromDescr(str(chassis.cols[2])) || null; }
      }
      if (!res.model) res.model = modelFromSysDescr(res.sys.descr);
      const rem = await soft(() => s.table(OID.lldpRemEntry, { maxRows: 2000 }));
      if (rem && rem.length) {
        const loc = await soft(() => s.table(OID.lldpLocPortEntry, { maxRows: 2000 }));
        const man = await soft(() => s.walk(OID.lldpRemManAddrEntry + '.3', { maxRows: 2000 }));
        res.neighbours.push(...parseLldp(rem, loc, man));
      }
      const cdp = await soft(() => s.table(OID.cdpCacheEntry, { maxRows: 2000 }));
      if (cdp && cdp.length) {
        const names = await soft(() => s.walk(OID.ifName, { maxRows: 2000 }));
        const ifNames = new Map((names || []).map((vb) => [vb.oid.split('.').pop(), str(vb)]));
        res.neighbours.push(...parseCdp(cdp, ifNames));
      }
      const arp = await soft(() => s.walk(OID.ipNetToMediaPhysAddress, { maxRows: 20000 }));
      res.arp = parseArp(arp || []);
      res.latency_ms = Date.now() - t0;
      return res;
    });
  } catch (e) { return { ok: false, error_class: errorClass(e), latency_ms: Date.now() - t0 }; }
}

// ipNetToMediaPhysAddress rows: oid …4.22.1.2.<ifIndex>.<a>.<b>.<c>.<d>, value = 6-byte MAC
function parseArp(vbs) {
  const out = [], seen = new Set();
  for (const vb of vbs) {
    const p = String(vb.oid || '').slice(OID.ipNetToMediaPhysAddress.length + 1).split('.');
    if (p.length !== 5) continue;
    const ip = p.slice(1).join('.'), mac = macOf(vb.value);
    if (!mac || mac === 'ff:ff:ff:ff:ff:ff' || /^0\.|^127\.|^2(2[4-9]|3\d)\./.test(ip) || seen.has(ip)) continue;
    seen.add(ip); out.push({ ip, mac });
  }
  return out;
}

module.exports = { modelFromSysDescr, modelFromDescr, probe, collect, sessionOptions, parseLldp, parseCdp, parseArp, decodeManAddrIndex, errorClass, OID };
