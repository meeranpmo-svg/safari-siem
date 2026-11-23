// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Service probes for the active scan (only after the scope's safety gate is open):
//   db    database listeners: TCP connect to the engines' well-known ports; MySQL / MariaDB also read the greeting the
//         server sends on its own (protocol version + server version). Nothing is sent, no login is attempted.
//   unix  Solaris / Unix servers: the SSH banner (the server sends it before any authentication; we send nothing) plus
//         the Solaris service ports (rpcbind 111, Solaris Management Console 898 / 6789, WBEM 5987 / 5988).
//         "Sun_SSH" / "SunSSH" in the banner = Oracle Solaris 11.3 or older (11.4 ships OpenSSH); SMC ports = Solaris.
// All network access goes through o.connect(ip, port, ms) → 'open'|'closed'|'timeout'|'unreachable' and
// o.banner(ip, port, ms) → {state, data: Buffer} so tests never touch the network.
const net = require('node:net');
const { cleanIps } = require('./sweep');

const DB_PORTS = {
  oracle: { label: 'Oracle Database (TNS listener)', ports: [1521, 1522, 1526] },
  mssql: { label: 'Microsoft SQL Server', ports: [1433] },
  mysql: { label: 'MySQL / MariaDB', ports: [3306] },
  postgres: { label: 'PostgreSQL', ports: [5432] },
  db2: { label: 'IBM Db2', ports: [50000] },
  mongodb: { label: 'MongoDB', ports: [27017] },
  hana: { label: 'SAP HANA', ports: [30015] },
};
const UNIX_PORTS = [22, 111, 898, 6789, 5987, 5988];
// storage: iSCSI targets, NFS, NDMP (backup of NAS / filers). NDMP or iSCSI is a strong sign; NFS alone is weak (Linux servers export NFS too)
const STORAGE_PORTS = { iscsi: 3260, nfs: 2049, ndmp: 10000 };

function realBanner(ip, port, ms, max = 512) {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port }); const chunks = []; let size = 0, done = false, state = 'timeout';
    const fin = () => { if (done) return; done = true; s.destroy(); resolve({ state, data: Buffer.concat(chunks) }); };
    s.setTimeout(ms, fin);
    s.once('connect', () => { state = 'open'; if (!max) fin(); });
    s.on('data', (c) => { chunks.push(c); size += c.length; if (size >= max || /\n/.test(c.toString('latin1'))) fin(); });
    s.once('error', (e) => { state = e.code === 'ECONNREFUSED' ? 'closed' : e.code === 'ETIMEDOUT' ? 'timeout' : 'unreachable'; fin(); });
    s.once('end', fin);
  });
}
// MySQL / MariaDB initial handshake: 3-byte length, sequence, protocol 0x0a, NUL-terminated server version
function mysqlVersion(buf) {
  if (!buf || buf.length < 6 || buf[4] !== 0x0a) return null;
  const end = buf.indexOf(0, 5);
  const v = buf.slice(5, end > 5 ? end : Math.min(buf.length, 60)).toString('latin1').replace(/[^\x20-\x7e]/g, '');
  return v ? (/mariadb/i.test(v) ? 'MariaDB ' + v.replace(/^5\.5\.5-/, '').replace(/-MariaDB.*$/i, '') : 'MySQL ' + v) : null;
}
function sshBanner(buf) { const m = /^SSH-[\d.]+-([^\r\n]{1,120})/.exec(String(buf ? buf.toString('latin1') : '')); return m ? 'SSH-' + m[0].slice(4) : null; }
function unixHint(banner, open) {
  const b = String(banner || ''), o = new Set(open || []);
  if (/Sun_SSH|SunSSH/i.test(b)) return { os: 'solaris', label: `Oracle Solaris 11.3 or older (${(/Sun_?SSH[_ ]?[\d.]+/i.exec(b) || ['Sun_SSH'])[0]})`, confidence: 85 };
  if (/solaris|sunos/i.test(b)) return { os: 'solaris', label: 'Oracle Solaris', confidence: 85 };
  if (o.has(898) || o.has(6789)) return { os: 'solaris', label: 'Oracle Solaris', confidence: 70 };
  if (/\bAIX\b/i.test(b)) return { os: 'aix', label: 'IBM AIX', confidence: 80 };
  if (/HP-?UX/i.test(b)) return { os: 'hpux', label: 'HP-UX', confidence: 80 };
  if (o.has(111) && o.has(22) && (o.has(5987) || o.has(5988))) return { os: 'unix', label: 'Unix server (rpcbind + WBEM)', confidence: 50 };
  return null;
}

// db(ip, engines[], o) → {alive, open[], found: [{engine, label, port, version?}]}   o.extra_ports = {engine: [port, …]}
async function db(ip, engines, o = {}) {
  const host = cleanIps([ip])[0], ms = o.timeout_ms || 800;
  const connect = o.connect || ((h, p, t) => realBanner(h, p, t, 0).then((r) => r.state));
  const banner = o.banner || realBanner;
  const list = (engines && engines.length ? engines : Object.keys(DB_PORTS)).filter((e) => DB_PORTS[e]);
  // o.extra_ports {engine: [port]}: listeners on non-standard ports (the scope's own list + the port of each database login)
  const extra = (o.extra_ports && typeof o.extra_ports === 'object') ? o.extra_ports : {};
  const jobs = [], seen = new Set();
  for (const e of list) for (const port of DB_PORTS[e].ports.concat(Array.isArray(extra[e]) ? extra[e] : [])) {
    const n = Number(port); if (!Number.isInteger(n) || n < 1 || n > 65535 || seen.has(e + ':' + n)) continue;
    seen.add(e + ':' + n); jobs.push({ e, port: n });
  }
  const rs = await Promise.all(jobs.map(async (j) => {
    if (j.e === 'mysql') { const b = await banner(host, j.port, ms); return Object.assign({ state: b.state, version: b.state === 'open' ? mysqlVersion(b.data) : null }, j); }
    return Object.assign({ state: await connect(host, j.port, ms) }, j);
  }));
  const found = rs.filter((r) => r.state === 'open').map((r) => Object.assign({ engine: r.e, label: DB_PORTS[r.e].label, port: r.port }, r.version ? { version: r.version } : {}));
  return { alive: rs.some((r) => r.state === 'open' || r.state === 'closed'), open: found.map((f) => f.port), found };
}

// unix(ip, o) → {alive, open[], ssh_banner, hint}
async function unix(ip, o = {}) {
  const host = cleanIps([ip])[0], ms = o.timeout_ms || 800;
  const connect = o.connect || ((h, p, t) => realBanner(h, p, t, 0).then((r) => r.state));
  const banner = o.banner || realBanner;
  const [b, ...rest] = await Promise.all([banner(host, 22, Math.max(ms, 1500))].concat(UNIX_PORTS.slice(1).map((p) => connect(host, p, ms))));
  const states = [b.state].concat(rest);
  const open = UNIX_PORTS.filter((p, i) => states[i] === 'open');
  const ssh = b.state === 'open' ? sshBanner(b.data) : null;
  return { alive: states.some((s) => s === 'open' || s === 'closed'), open, ssh_banner: ssh, hint: unixHint(ssh, open) };
}

// storage(ip, o) → {alive, open[], protocols[]}
async function storage(ip, o = {}) {
  const host = cleanIps([ip])[0], ms = o.timeout_ms || 800;
  const connect = o.connect || ((h, p, t) => realBanner(h, p, t, 0).then((r) => r.state));
  const names = Object.keys(STORAGE_PORTS);
  const st = await Promise.all(names.map((n) => connect(host, STORAGE_PORTS[n], ms)));
  const protocols = names.filter((n, i) => st[i] === 'open');
  return { alive: st.some((x) => x === 'open' || x === 'closed'), open: protocols.map((n) => STORAGE_PORTS[n]), protocols };
}

module.exports = { storage, STORAGE_PORTS, db, unix, DB_PORTS, UNIX_PORTS, mysqlVersion, sshBanner, unixHint, realBanner };
