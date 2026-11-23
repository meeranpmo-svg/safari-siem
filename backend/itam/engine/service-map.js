// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
/*
 * Business Services ({P} = /api/itam): what runs on every server - Oracle / SQL Server / MySQL / PostgreSQL and other
 * databases, IIS / Apache / nginx web servers, Tomcat / WebLogic / WebSphere application servers, SAP, Exchange, Active
 * Directory, message queues - found automatically from what the platform can see, and proposed as BUSINESS-CRITICAL for
 * an administrator to confirm. Read only: nothing is installed on, changed on or logged in to a server that the platform
 * was not already allowed to read.
 *
 * Servers = server / VM assets with an IP, Asset Discovery devices classed server / VM (or with a database listener) and the
 * hosts of the monitored databases - one row per IP. The asset each one is: the discovery device's linked asset, else the
 * asset with that management IP (never by name similarity).
 *
 * Evidence, per server, from (each says when it last looked and why it could not):
 *   discovery  Asset Discovery's own results: open ports, database listeners (with the MySQL greeting), AD domain controller
 *   software   the installed-software list of the asset (ITAM agent, licence sync)
 *   dblogin    the databases Database Health reads on that host (instance / service names)
 *   ssh        Linux / Unix: inv-helper.py op ssh_services over the SSH login Asset Discovery proved there (or one an
 *              administrator chose here), only with a host key an administrator trusted, checked before the password is
 *              sent: processes, listening TCP ports, running services, oratab
 *   probe      network, NO login: for servers inside an Asset Discovery scope whose safety gate is open - TCP connects to
 *              a fixed port list, an HTTP HEAD on 80 / 443 / 8080 / 8443 (the Server / X-Powered-By headers and the TLS
 *              certificate name; nothing secret is sent, so an unverified certificate is acceptable here), and the SQL
 *              Server Browser (UDP 1434, the one-byte instance request) for instance names and versions
 * A port alone makes a service "possible"; a banner, a process, a service unit, an installed product, a database login or
 * the SQL Browser make it "confirmed". A server no source could read is shown as NOT CHECKED with the reason - never as
 * "nothing running".
 *
 * Business-critical: a confirmed database, web / application server, ERP, mail, directory or message queue is PROPOSED.
 * An administrator confirms (the asset gets the tags business-critical and svc:<product>, through the normal asset edit,
 * audited) or records "not business-critical" with a reason. A service that appears after the decision is flagged as
 * changed. Nothing is marked critical without a person.
 *
 * Routes: GET /service-map (viewer) · POST /service-map/run (operator) · POST /service-map/decide {ip, decision:
 *         'critical'|'not_critical', reason} (admin) · POST /service-map/ssh {ip, cred_id|null} (admin)
 * Config: service_map {enabled, interval_min (default 60), ssh (true), probe (true), probe_timeout_ms (800)}
 */
const net = require('node:net');
const tls = require('node:tls');
const dgram = require('node:dgram');

const CLOSED = { retired: 1, disposed: 1 };
const KINDS = {
  database: 'Database', web: 'Web server', app: 'Application server', erp: 'ERP', mail: 'Mail', directory: 'Directory',
  messaging: 'Messaging', platform: 'Platform', access: 'Remote access',
};
// the product catalogue: how each one shows itself to each source. Patterns are word-bounded on purpose.
const CATALOGUE = [
  { id: 'oracle', label: 'Oracle Database', kind: 'database', critical: true, ports: [1521, 1522, 1526], disc: 'oracle', db: 'oracle',
    proc: /\bora_pmon_[A-Za-z0-9_$#+]+|\btnslsnr\b/, unit: /^(oracle|dbora|ohasd)\b/i, sw: /\boracle database\b|^oracle \d+[a-z]? (database|client)\b/i },
  { id: 'mssql', label: 'Microsoft SQL Server', kind: 'database', critical: true, ports: [1433], disc: 'mssql', db: 'mssql', browser: true,
    proc: /\bsqlservr\b/, unit: /^mssql-server\b/i, sw: /^microsoft sql server (19|20)\d\d\b(?!.*\b(management studio|native client|odbc|setup|localdb|compact|t-sql|policies|vss writer|data-tier|common files|clr types)\b)/i },
  { id: 'mysql', label: 'MySQL / MariaDB', kind: 'database', critical: true, ports: [3306], disc: 'mysql', db: 'mysql',
    proc: /\b(mysqld|mariadbd)\b/, unit: /^(mysqld?|mariadb)\.service\b/i, sw: /^(mysql server|mariadb) \d/i },
  { id: 'postgres', label: 'PostgreSQL', kind: 'database', critical: true, ports: [5432], disc: 'postgres', db: 'postgres',
    proc: /(^|\/)(postgres|postmaster)(\s|$)/, unit: /^postgresql\b/i, sw: /^postgresql \d/i },
  { id: 'db2', label: 'IBM Db2', kind: 'database', critical: true, ports: [50000], disc: 'db2', proc: /\bdb2sysc\b/, sw: /^ibm db2\b/i },
  { id: 'mongodb', label: 'MongoDB', kind: 'database', critical: true, ports: [27017], disc: 'mongodb', proc: /\bmongod\b/, unit: /^mongod\b/i, sw: /^mongodb( server)? \d/i },
  { id: 'hana', label: 'SAP HANA', kind: 'database', critical: true, ports: [30015], disc: 'hana', proc: /\bhdbindexserver\b/ },
  { id: 'redis', label: 'Redis', kind: 'database', critical: true, ports: [6379], proc: /\bredis-server\b/, unit: /^redis(-server)?\b/i },
  { id: 'elastic', label: 'Elasticsearch / OpenSearch', kind: 'database', critical: true, ports: [9200], proc: /\borg\.(elasticsearch|opensearch)\b/, unit: /^(elasticsearch|opensearch)\b/i },
  { id: 'iis', label: 'Microsoft IIS', kind: 'web', critical: true, http: /^Microsoft-IIS\b/i, powered: /\bASP\.NET\b/i, sw: /^(microsoft web deploy|iis url rewrite module|iis \d+(\.\d+)? express)\b/i },
  { id: 'apache', label: 'Apache HTTP Server', kind: 'web', critical: true, http: /^Apache(?!-Coyote)\b/i, proc: /\b(httpd|apache2)\b/, unit: /^(httpd|apache2)\.service\b/i, sw: /^apache http server\b/i },
  { id: 'nginx', label: 'nginx', kind: 'web', critical: true, http: /^nginx\b/i, proc: /\bnginx\b/, unit: /^nginx\.service\b/i },
  { id: 'tomcat', label: 'Apache Tomcat', kind: 'app', critical: true, http: /\b(Apache-Coyote|Tomcat)\b/i, proc: /\borg\.apache\.catalina\b/, unit: /^tomcat\d*\b/i, sw: /^apache tomcat\b/i },
  { id: 'weblogic', label: 'Oracle WebLogic', kind: 'app', critical: true, ports: [7001, 7002], http: /\bWebLogic\b/i, proc: /\bweblogic\.Server\b/ },
  { id: 'websphere', label: 'IBM WebSphere', kind: 'app', critical: true, ports: [9060, 9043], http: /\bWebSphere\b/i, proc: /\bcom\.ibm\.ws\b/ },
  { id: 'jboss', label: 'JBoss / WildFly', kind: 'app', critical: true, ports: [9990], http: /\b(JBoss|WildFly)\b/i, proc: /\bjboss-modules\.jar\b/ },
  { id: 'sap', label: 'SAP application server', kind: 'erp', critical: true, ports: [3200, 3300], proc: /\b(disp\+work|sapstart)\b/ },
  { id: 'exchange', label: 'Microsoft Exchange', kind: 'mail', critical: true, owa: true, sw: /^microsoft exchange server\b/i },
  { id: 'smtp', label: 'Mail server (SMTP)', kind: 'mail', critical: true, ports: [25], proc: /\b(postfix\/master|sendmail|exim4?)\b/, unit: /^(postfix|sendmail|exim4?)\.service\b/i },
  { id: 'ad', label: 'Active Directory domain controller', kind: 'directory', critical: true, ad: true },
  { id: 'rabbitmq', label: 'RabbitMQ', kind: 'messaging', critical: true, ports: [5672], proc: /\brabbit\b/, unit: /^rabbitmq-server\b/i, sw: /^rabbitmq server\b/i },
  { id: 'kafka', label: 'Apache Kafka', kind: 'messaging', critical: true, ports: [9092], proc: /\bkafka\.Kafka\b/, unit: /^kafka\b/i },
  { id: 'ibmmq', label: 'IBM MQ', kind: 'messaging', critical: true, ports: [1414], proc: /\bamqzxma0\b/, sw: /^ibm mq\b/i },
  { id: 'containers', label: 'Container platform (Docker / Kubernetes)', kind: 'platform', critical: false, proc: /\b(dockerd|containerd|kubelet)\b/, unit: /^(docker|containerd|kubelet)\.service\b/i },
  { id: 'rdp', label: 'Remote Desktop', kind: 'access', critical: false, ports: [3389] },
  { id: 'winrm', label: 'Windows Remote Management', kind: 'access', critical: false, ports: [5985, 5986] },
  { id: 'ssh', label: 'SSH', kind: 'access', critical: false, ports: [22] },
  { id: 'smb', label: 'Windows file sharing (SMB)', kind: 'access', critical: false, ports: [445] },
];
const BY_ID = Object.fromEntries(CATALOGUE.map((c) => [c.id, c]));
// what the network probe connects to (no data sent on these): the catalogue's ports plus the domain controller pair
const PROBE_PORTS = [...new Set(CATALOGUE.flatMap((c) => c.ports || []).concat([88, 389, 80, 443, 8080, 8443]))].sort((a, b) => a - b);
const HTTP_PORTS = [[80, false], [443, true], [8080, false], [8443, true]];

// ---- parsers for what the sources return (pure: tested on their own) ------------------------------------------------
function parsePs(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const m = /^\s*(\S+)\s+(\S+)\s*(.*)$/.exec(line); if (!m) continue;
    out.push({ user: m[1], comm: m[2], args: m[3].slice(0, 300) });
  }
  return out;
}
function parseListen(text) {
  const ports = new Set();
  for (const line of String(text || '').split('\n')) {
    if (/\bUDP\b/i.test(line) || /^\s*udp/i.test(line)) continue;
    // ss: LISTEN 0 128 0.0.0.0:22 ... / netstat: tcp 0 0 0.0.0.0:22 ... LISTEN / Solaris: *.22 *.* ... LISTEN
    for (const m of line.matchAll(/(?:^|\s)(?:\[[^\]]*\]|[\w.*:%-]*?)[:.](\d{1,5})\s+(?:\S+[:.](?:\d{1,5}|\*)|\*\.\*|\[::\]:\*|0\.0\.0\.0:\*)/g)) {
      const p = Number(m[1]); if (p > 0 && p < 65536) ports.add(p); break;
    }
  }
  return [...ports].sort((a, b) => a - b);
}
function parseUnits(text) {
  return String(text || '').split('\n').map((l) => l.trim().replace(/^●\s*/, '').split(/\s+/)[0]).filter((u) => /\.service$/.test(u)).slice(0, 300);
}
function parseOratab(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const p = line.trim().split(':'); if (p.length < 2 || !p[0] || p[0].startsWith('#')) continue;
    out.push({ sid: p[0], home: p[1], autostart: /^y/i.test(p[2] || '') });
  }
  return out;
}
// SQL Server Browser answer: 0x05, 2-byte length, then "ServerName;X;InstanceName;Y;IsClustered;No;Version;15.0.2000.5;tcp;1433;;" per instance
function parseSqlBrowser(buf) {
  if (!buf || buf.length < 4 || buf[0] !== 0x05) return [];
  const text = buf.slice(3).toString('latin1');
  return text.split(';;').map((blk) => {
    const p = blk.split(';'), o = {};
    for (let i = 0; i + 1 < p.length; i += 2) o[p[i].toLowerCase()] = p[i + 1];
    return o.instancename ? { instance: o.instancename.slice(0, 64), server: (o.servername || '').slice(0, 64), version: (o.version || '').slice(0, 32), tcp: o.tcp ? Number(o.tcp) || null : null, clustered: /^yes/i.test(o.isclustered || '') } : null;
  }).filter(Boolean).slice(0, 50);
}
function parseHttpHead(text) {
  const head = String(text || '').split(/\r?\n\r?\n/)[0], h = {};
  const lines = head.split(/\r?\n/), st = /^HTTP\/[\d.]+\s+(\d{3})/.exec(lines[0] || '');
  for (const l of lines.slice(1)) { const i = l.indexOf(':'); if (i > 0) h[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim().slice(0, 200); }
  return st ? { status: Number(st[1]), server: h.server || '', powered: [h['x-powered-by'], h['x-aspnet-version'] ? 'ASP.NET ' + h['x-aspnet-version'] : ''].filter(Boolean).join(' · '), owa: !!(h['x-owa-version'] || /\/owa\b/i.test(h.location || '')), owa_version: h['x-owa-version'] || '' } : null;
}

// ---- recognise the products in one server's evidence (pure) ----------------------------------------------------------
// ev = {ports[], disc_db[], http[], sql[], procs[], units[], oratab[], software[], dblogins[], is_dc, listen[]}
function recognise(ev) {
  const found = new Map();
  const hit = (id, strength, src, detail, extra) => {
    const c = BY_ID[id]; if (!c) return;
    const f = found.get(id) || { id, label: c.label, kind: c.kind, critical: !!c.critical, strength: 0, sources: new Set(), evidence: [], instances: new Set(), versions: new Set(), ports: new Set() };
    f.strength = Math.max(f.strength, strength); f.sources.add(src);
    if (f.evidence.length < 12) f.evidence.push({ source: src, detail: String(detail).slice(0, 200) });
    if (extra) { for (const i of extra.instances || []) f.instances.add(String(i)); if (extra.version) f.versions.add(String(extra.version)); for (const p of extra.ports || []) f.ports.add(p); }
    found.set(id, f);
  };
  const ports = new Set(ev.ports || []), listen = new Set(ev.listen || []);
  for (const c of CATALOGUE) for (const p of c.ports || []) {
    if (listen.has(p)) hit(c.id, 1, 'ssh', `listening on TCP ${p}`, { ports: [p] });
    else if (ports.has(p)) hit(c.id, 1, 'network', `TCP ${p} open`, { ports: [p] });
  }
  if (ports.has(88) && ports.has(389) && ports.has(445)) hit('ad', 1, 'network', 'Kerberos 88 + LDAP 389 + SMB 445 open (domain controller pattern)');
  for (const d of ev.disc_db || []) { const c = CATALOGUE.find((x) => x.disc === d.engine); if (c) hit(c.id, d.version ? 2 : 1, 'discovery', d.version ? `listener ${d.port}: ${d.version}` : `database listener on ${d.port}`, { ports: [d.port], version: d.version }); }
  if (ev.is_dc) hit('ad', 2, 'discovery', 'domain controller in Active Directory');
  for (const h of ev.http || []) {
    const srv = h.server || '';
    for (const c of CATALOGUE) if (c.http && c.http.test(srv)) hit(c.id, 2, 'network', `HTTP${h.tls ? 'S' : ''} ${h.port}: Server ${srv}`, { ports: [h.port], version: (/\/([\d.]+)/.exec(srv) || [])[1] });
    if (h.powered && /\bASP\.NET\b/i.test(h.powered)) hit('iis', 2, 'network', `HTTP${h.tls ? 'S' : ''} ${h.port}: ${h.powered}`, { ports: [h.port] });
    if (h.owa) hit('exchange', 2, 'network', `HTTPS ${h.port}: Outlook on the web${h.owa_version ? ' ' + h.owa_version : ''}`, { version: h.owa_version || undefined });
  }
  for (const s of ev.sql || []) hit('mssql', 2, 'network', `SQL Server Browser: instance ${s.instance}${s.version ? ' version ' + s.version : ''}${s.tcp ? ' on TCP ' + s.tcp : ''}`, { instances: [s.instance], version: s.version, ports: s.tcp ? [s.tcp] : [] });
  for (const p of ev.procs || []) {
    const line = p.comm + ' ' + p.args;
    for (const c of CATALOGUE) if (c.proc && c.proc.test(line)) {
      const sid = c.id === 'oracle' ? (/\bora_pmon_([A-Za-z0-9_$#+]+)/.exec(line) || [])[1] : null;
      hit(c.id, 2, 'ssh', `process ${p.comm}${sid ? ' (instance ' + sid + ')' : ''} as ${p.user}`, sid && !/^\+ASM|^-MGMTDB/i.test(sid) ? { instances: [sid] } : null);
    }
  }
  for (const u of ev.units || []) for (const c of CATALOGUE) if (c.unit && c.unit.test(u)) hit(c.id, 2, 'ssh', `service ${u} running`);
  for (const o of ev.oratab || []) if (!/^\+ASM|^-MGMTDB|^\*$/i.test(o.sid)) hit('oracle', 2, 'ssh', `/etc/oratab: ${o.sid} (${o.home})`, { instances: [o.sid] });
  for (const s of ev.software || []) for (const c of CATALOGUE) if (c.sw && c.sw.test(s.name || '')) hit(c.id, 2, 'software', `installed: ${s.name}${s.version ? ' ' + s.version : ''}`, { version: s.version });
  for (const d of ev.dblogins || []) { const c = CATALOGUE.find((x) => x.db === (d.engine || 'oracle')); if (c) hit(c.id, 2, 'dblogin', `Database Health reads ${d.instance || d.service || 'a database'} here`, { instances: [d.instance || d.service].filter(Boolean) }); }
  return [...found.values()].map((f) => ({ id: f.id, label: f.label, kind: f.kind, kind_label: KINDS[f.kind] || f.kind, critical: f.critical,
    confidence: f.strength >= 2 ? 'confirmed' : 'possible', sources: [...f.sources].sort(), evidence: f.evidence,
    instances: [...f.instances].slice(0, 30), versions: [...f.versions].slice(0, 5), ports: [...f.ports].sort((a, b) => a - b) }))
    .sort((a, b) => (b.critical - a.critical) || (a.confidence === b.confidence ? 0 : a.confidence === 'confirmed' ? -1 : 1) || a.label.localeCompare(b.label));
}

// ---- network probes (no login; injectable for tests) -----------------------------------------------------------------
function tcpOpen(ip, port, ms) {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port }); let done = false;
    const fin = (v) => { if (done) return; done = true; s.destroy(); resolve(v); };
    s.setTimeout(ms, () => fin(false)); s.once('connect', () => fin(true)); s.once('error', () => fin(false));
  });
}
function httpHead(ip, port, useTls, ms) {
  return new Promise((resolve) => {
    let done = false, buf = '', cn = '';
    const fin = () => { if (done) return; done = true; try { s.destroy(); } catch (e) { /* closed */ } const h = parseHttpHead(buf); resolve(h ? Object.assign(h, { port, tls: useTls, cn }) : null); };
    const req = `HEAD / HTTP/1.0\r\nHost: ${ip}\r\nUser-Agent: Sentra-ServiceMap/1 (read-only)\r\nConnection: close\r\n\r\n`;
    const s = useTls ? tls.connect({ host: ip, port, servername: net.isIP(ip) ? undefined : ip, rejectUnauthorized: false }, () => {
      try { const c = s.getPeerCertificate(); cn = (c && c.subject && c.subject.CN) ? String(c.subject.CN).slice(0, 120) : ''; } catch (e) { cn = ''; }
      s.write(req);
    }) : net.connect({ host: ip, port }, () => s.write(req));
    s.setTimeout(ms, fin);
    s.on('data', (d) => { buf += d.toString('latin1'); if (buf.length > 4096 || /\r?\n\r?\n/.test(buf)) fin(); });
    s.once('error', fin); s.once('end', fin); s.once('close', fin);
  });
}
function sqlBrowser(ip, ms) {
  return new Promise((resolve) => {
    const s = dgram.createSocket(net.isIPv6(ip) ? 'udp6' : 'udp4'); let done = false;
    const fin = (v) => { if (done) return; done = true; try { s.close(); } catch (e) { /* closed */ } resolve(v); };
    const t = setTimeout(() => fin([]), ms);
    s.on('message', (m) => { clearTimeout(t); fin(parseSqlBrowser(m)); });
    s.on('error', () => { clearTimeout(t); fin([]); });
    s.send(Buffer.from([0x03]), 1434, ip, (e) => { if (e) { clearTimeout(t); fin([]); } });
  });
}

function createServiceMap(app, opts = {}) {
  const store = app.store, devs = store.collection('disc_devices'), assetsCol = store.collection('assets');
  const trustCol = store.collection('disc_trust'), scopesCol = store.collection('disc_scopes');
  const snaps = store.collection('svc_map'), decisions = store.collection('svc_decisions'), links = store.collection('svc_links');
  const dc = (app.config && app.config.discovery) || {};
  const cfg = () => Object.assign({ enabled: true, interval_min: 60, ssh: true, probe: true, probe_timeout_ms: 800 }, (app.config && app.config.service_map) || {});
  const D = () => opts.discovery || app.discovery || null;
  const H = () => opts.dbHealth || (app.addons && app.addons.dbHealth) || null;
  const runHelper = opts.invRun || require('./discovery/methods/login').realRunner(dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3');
  const P = Object.assign({ tcp: tcpOpen, http: httpHead, sql: sqlBrowser }, opts.probe || {});
  const scopes = opts.scopes || require('./discovery/scopes');
  const ip4 = require('./discovery/ipv4');
  const now = opts.now || Date.now;
  const lg = app.log || { info() {}, warn() {} };
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || 'system:itam-service-map', role: (who && who.role) || 'system', ip: (who && who.ip) || '', action, target, detail }); };
  let timer = null, running = null;

  function dbTargets() { try { return (H() && H().targets && H().targets().list) || []; } catch (e) { return []; } }
  // every server, one per IP
  function servers() {
    const by = new Map();
    const add = (ip, o) => { ip = String(ip || '').trim(); if (!ip || !ip4.parseIp(ip)) return; const cur = by.get(ip) || { ip, host: '', device: null, asset: null, from: [] }; Object.assign(cur, Object.fromEntries(Object.entries(o).filter(([k, v]) => v && !cur[k]))); if (o.src && !cur.from.includes(o.src)) cur.from.push(o.src); by.set(ip, cur); };
    for (const a of assetsCol.all((x) => !CLOSED[x.status] && (x.type === 'server' || x.type === 'vm') && x.mgmt_ip)) add(a.mgmt_ip, { asset: a, host: a.name, src: 'asset register' });
    for (const d of devs.all((x) => x.status !== 'ignored' && (x.type === 'server' || x.type === 'vm' || (x.extra && (x.extra.db || (x.extra.ad && x.extra.ad.is_dc) || x.extra.unix_login))))) {
      for (const ip of [d.ip].concat(d.ips || []).filter(Boolean).slice(0, 1)) add(ip, { device: d, host: d.hostname || d.fqdn, src: 'Asset Discovery' });
    }
    for (const t of dbTargets()) add(t.ip, { host: t.host, src: 'Database Health' });
    for (const s of by.values()) {
      if (!s.device) s.device = devs.all((d) => d.ip === s.ip || (d.ips || []).includes(s.ip))[0] || null;
      if (!s.asset && s.device && s.device.asset_id) { const a = assetsCol.get(s.device.asset_id); if (a && !CLOSED[a.status]) s.asset = a; }
      if (!s.asset) s.asset = assetsCol.all((a) => !CLOSED[a.status] && a.mgmt_ip && low(a.mgmt_ip) === low(s.ip))[0] || null;
      if (!s.host) s.host = (s.asset && s.asset.name) || (s.device && s.device.hostname) || s.ip;
    }
    return [...by.values()].sort((a, b) => (ip4.parseIp(a.ip) || 0) - (ip4.parseIp(b.ip) || 0));
  }
  function vaultSsh() { try { const V = D() && D().vault; return V ? (V.list() || []).filter((c) => c.kind === 'ssh') : []; } catch (e) { return []; } }
  function sshFor(s) {
    const L = links.get(s.ip) || {}, creds = vaultSsh();
    let cred = L.ssh_cred_id ? creds.find((c) => c.id === L.ssh_cred_id) : null, via = cred ? 'chosen here' : '';
    const proven = s.device && s.device.extra && s.device.extra.unix_login && s.device.extra.unix_login.credential;
    if (!cred && proven) { cred = creds.find((c) => c.label === proven) || null; via = cred ? 'proven by Asset Discovery' : ''; }
    const port = (cred && cred.target && cred.target.port) || 22;
    return { cred, via, port, trust: trustCol.get(`ssh:${s.ip}:${port}`) || null };
  }
  // the gate-open Asset Discovery scope that covers this IP (network probes only there)
  function gateScope(ip) {
    for (const sc of scopesCol.all()) {
      try { if (scopes.gateOpen(sc) && ip4.contains(sc.targets || [], ip) && !ip4.contains(sc.exclusions || [], ip)) return sc; } catch (e) { /* malformed scope */ }
    }
    return null;
  }

  async function readSsh(s) {
    const S = sshFor(s), at = new Date(now()).toISOString();
    if (!cfg().ssh) return { at, skipped: 'switched off (service_map.ssh)' };
    if (!S.cred) return { at, skipped: 'no SSH login for this server' };
    if (!S.trust || S.trust.state !== 'trusted') return { at, skipped: 'SSH host key not trusted yet (Asset Discovery → Trust)' };
    const V = D().vault, c = V.open(S.cred.id);
    let r;
    try { r = await runHelper({ op: 'ssh_services', host: s.ip, port: S.port, username: c.secret.username, password: c.secret.password, private_key: c.secret.private_key, fp: S.trust.fp }); }
    finally { c.release(); }
    if (!r || !r.ok) {
      if (r && r.error_class === 'hostkey_changed' && D().trust) D().trust.see('ssh', s.ip, S.port, r.fp, {});   // for an administrator to decide; never accepted here
      return { at, error: String((r && r.error) || 'no answer').slice(0, 200), error_class: (r && r.error_class) || 'error', credential: S.cred.label };
    }
    const f = r.facts || {};
    return { at, ok: true, credential: S.cred.label, via: S.via, hostname: String(f.hostname || '').slice(0, 120), os: String(f.os || '').split('\n').slice(0, 2).join(' · ').slice(0, 200),
      procs: parsePs(f.ps).slice(0, 600), listen: parseListen(f.listen), units: parseUnits(f.units), oratab: parseOratab(f.oratab) };
  }
  async function readProbe(s) {
    const at = new Date(now()).toISOString(), C = cfg();
    if (!C.probe) return { at, skipped: 'switched off (service_map.probe)' };
    const sc = gateScope(s.ip);
    if (!sc) return { at, skipped: 'not inside an Asset Discovery scope whose safety checklist is complete' };
    const ms = Math.max(200, Math.min(5000, Number(C.probe_timeout_ms) || 800));
    const st = await Promise.all(PROBE_PORTS.map((p) => P.tcp(s.ip, p, ms).catch(() => false)));
    const open = PROBE_PORTS.filter((p, i) => st[i]);
    const http = (await Promise.all(HTTP_PORTS.filter(([p]) => open.includes(p)).map(([p, t]) => P.http(s.ip, p, t, Math.max(ms, 2000)).catch(() => null)))).filter(Boolean);
    const sql = open.includes(1433) || open.includes(445) ? await P.sql(s.ip, Math.max(ms, 1500)).catch(() => []) : [];
    return { at, ok: true, scope: sc.name || sc.id, open, http, sql };
  }
  function evidenceOf(s, snap) {
    const d = s.device || {}, ex = d.extra || {}, ssh = (snap && snap.ssh) || {}, pr = (snap && snap.probe) || {};
    const ports = new Set([].concat(d.open_ports || [], (ex.db || []).map((x) => x.port), ex.unix && ex.unix.ports ? ex.unix.ports : [], pr.open || []).map(Number).filter((n) => n > 0));
    return { ports: [...ports], disc_db: ex.db || [], is_dc: !!(ex.ad && ex.ad.is_dc), http: pr.http || [], sql: pr.sql || [],
      procs: ssh.procs || [], units: ssh.units || [], oratab: ssh.oratab || [], listen: ssh.listen || [],
      software: (s.asset && Array.isArray(s.asset.software) ? s.asset.software : []).map((x) => ({ name: x.name, version: x.version })).slice(0, 3000),
      dblogins: dbTargets().filter((t) => String(t.ip) === s.ip).map((t) => ({ engine: t.engine || 'oracle', instance: t.instance, service: t.service })) };
  }
  // which sources could look at this server, and why the others could not
  function coverage(s, snap, ev) {
    const ssh = (snap && snap.ssh) || null, pr = (snap && snap.probe) || null;
    return [
      { source: 'discovery', label: 'Asset Discovery', ok: !!s.device, why: s.device ? 'device ' + (s.device.hostname || s.device.ip) : 'not found by an Asset Discovery scan' },
      { source: 'software', label: 'Installed software', ok: ev.software.length > 0, why: ev.software.length ? ev.software.length + ' products (agent / licence sync)' : s.asset ? 'no software list (no ITAM agent on this server)' : 'not in the asset register' },
      { source: 'dblogin', label: 'Database logins', ok: ev.dblogins.length > 0, why: ev.dblogins.length ? ev.dblogins.length + ' database(s) read by Database Health' : 'no database login registered for this host' },
      { source: 'ssh', label: 'SSH (Linux / Unix)', ok: !!(ssh && ssh.ok), at: ssh && ssh.at, why: !ssh ? 'not read yet' : ssh.ok ? 'read with ' + ssh.credential : ssh.error ? 'failed: ' + ssh.error : ssh.skipped },
      { source: 'network', label: 'Network probe (no login)', ok: !!(pr && pr.ok), at: pr && pr.at, why: !pr ? 'not probed yet' : pr.ok ? (pr.open.length + ' open port(s) · scope ' + pr.scope) : pr.skipped },
    ];
  }
  function decisionState(ip, svc) {
    const dsn = decisions.get(ip) || null, crit = svc.filter((x) => x.critical && x.confidence === 'confirmed');
    if (!dsn) return { state: crit.length ? 'proposed' : 'none', decision: null, new_since: [] };
    const newer = crit.map((x) => x.id).filter((id) => !(dsn.services || []).includes(id));
    return { state: dsn.decision === 'critical' ? 'confirmed' : 'not_critical', decision: dsn, new_since: newer };
  }

  function view(role) {
    const rows = [], findings = [], kinds = {}, products = {};
    for (const s of servers()) {
      const snap = snaps.get(s.ip) || null, ev = evidenceOf(s, snap), svc = recognise(ev), cov = coverage(s, snap, ev), dsn = decisionState(s.ip, svc);
      const checked = cov.some((c) => c.ok);
      for (const x of svc) { if (x.kind !== 'access') { kinds[x.kind] = (kinds[x.kind] || 0) + 1; products[x.id] = (products[x.id] || 0) + 1; } }
      const biz = svc.filter((x) => x.critical);
      const monitoredDb = new Set(ev.dblogins.map((d) => d.engine));
      for (const x of biz.filter((y) => y.kind === 'database' && y.confidence === 'confirmed' && (y.id === 'oracle' || y.id === 'mssql') && !monitoredDb.has(y.id === 'oracle' ? 'oracle' : 'mssql')))
        findings.push({ ip: s.ip, host: s.host, severity: 'high', kind: 'unmonitored-db', title: `${x.label} on ${s.host} is not monitored`, recommendation: 'Register a read-only database login (Databases → Connections) so Database Health, the Morning Check and the AI Oracle DBA watch it.' });
      if (biz.some((y) => y.confidence === 'confirmed') && !s.asset) findings.push({ ip: s.ip, host: s.host, severity: 'medium', kind: 'not-in-register', title: `${s.host} runs business services but is not in the asset register`, recommendation: 'Approve it from Asset Discovery or add it as a server asset, so owner, warranty, backup and end of life are tracked.' });
      if (dsn.state === 'proposed') findings.push({ ip: s.ip, host: s.host, severity: 'medium', kind: 'decide', title: `${s.host}: ${biz.filter((y) => y.confidence === 'confirmed').map((y) => y.label).join(', ')} - business-critical not confirmed`, recommendation: 'An administrator confirms it (the asset is tagged business-critical) or records why it is not.' });
      if (dsn.new_since.length) findings.push({ ip: s.ip, host: s.host, severity: 'medium', kind: 'changed', title: `${s.host}: new since the decision - ${dsn.new_since.map((i) => BY_ID[i].label).join(', ')}`, recommendation: 'Review the server again: the decision was made before these services were found.' });
      if (!checked) findings.push({ ip: s.ip, host: s.host, severity: 'low', kind: 'not-checked', title: `${s.host}: no source could see what runs on it`, recommendation: 'Add an SSH login (Linux / Unix), install the ITAM agent (Windows) or include it in an Asset Discovery scope with a completed safety checklist.' });
      rows.push({ ip: s.ip, host: s.host, from: s.from, os: (snap && snap.ssh && snap.ssh.os) || (s.asset && s.asset.os) || (s.device && s.device.os) || null,
        asset: s.asset ? { id: s.asset.id, name: s.asset.name || null, asset_tag: s.asset.asset_tag || null, tags: s.asset.tags || [], owner: s.asset.owner || null } : null,
        services: svc, business: biz.filter((y) => y.confidence === 'confirmed').map((y) => y.id), possible: biz.filter((y) => y.confidence === 'possible').map((y) => y.id),
        coverage: cov, checked, decision: dsn.decision ? { decision: dsn.decision.decision, reason: dsn.decision.reason || '', by: dsn.decision.by, at: dsn.decision.at } : null, state: dsn.state, new_since: dsn.new_since,
        read_at: snap ? snap.at : null, ssh: (() => { const S = sshFor(s); return { credential: S.cred ? S.cred.label : null, via: S.via || null, host_key: S.trust ? S.trust.state : 'not seen' }; })() });
    }
    const SEVR = { high: 3, medium: 2, low: 1 };
    findings.sort((a, b) => SEVR[b.severity] - SEVR[a.severity]);
    return { generated_at: new Date(now()).toISOString(), settings: cfg(), catalogue: CATALOGUE.map((c) => ({ id: c.id, label: c.label, kind: c.kind, kind_label: KINDS[c.kind], critical: !!c.critical })),
      kinds: KINDS, servers: rows, findings, ssh_logins: role === 'admin' ? vaultSsh().map((c) => ({ id: c.id, label: c.label })) : [],
      summary: { servers: rows.length, checked: rows.filter((r) => r.checked).length, with_business: rows.filter((r) => r.business.length).length,
        confirmed: rows.filter((r) => r.state === 'confirmed').length, proposed: rows.filter((r) => r.state === 'proposed').length,
        not_critical: rows.filter((r) => r.state === 'not_critical').length, by_kind: kinds, by_product: products, last_run: (snaps.get('_meta') || {}).last || null } };
  }

  async function pass() {
    if (running) return running;
    running = (async () => {
      const res = { at: new Date(now()).toISOString(), servers: 0, ssh_read: 0, probed: 0, failed: 0 };
      if (!cfg().enabled) return Object.assign(res, { note: 'switched off (config service_map.enabled)' });
      const list = servers(); res.servers = list.length;
      let i = 0;
      const worker = async () => {
        while (i < list.length) {
          const s = list[i++];
          try {
            const [ssh, probe] = await Promise.all([readSsh(s).catch((e) => ({ at: res.at, error: String(e.message || e).slice(0, 200) })), readProbe(s).catch((e) => ({ at: res.at, error: String(e.message || e).slice(0, 200) }))]);
            if (ssh.ok) res.ssh_read++; if (probe.ok) res.probed++; if (ssh.error) res.failed++;
            snaps.put({ id: s.ip, at: new Date(now()).toISOString(), ssh, probe });
          } catch (e) { res.failed++; }
        }
      };
      await Promise.all([worker(), worker(), worker(), worker()]);   // four servers at a time: gentle on the network
      snaps.put({ id: '_meta', last: res });
      if (res.failed) lg.warn('service-map pass', res);
      return res;
    })().finally(() => { running = null; });
    return running;
  }

  // an administrator's decision; "critical" tags the asset (normal asset edit, audited)
  function decide(b, who) {
    const ip = String((b && b.ip) || '').trim(), s = servers().find((x) => x.ip === ip);
    if (!s) throw bad('not a known server', 404);
    const decision = b.decision === 'critical' ? 'critical' : b.decision === 'not_critical' ? 'not_critical' : null;
    if (!decision) throw bad('decision must be "critical" or "not_critical"');
    const reason = String(b.reason || '').trim().slice(0, 500);
    if (decision === 'not_critical' && reason.length < 5) throw bad('give the reason it is not business-critical (at least 5 characters)');
    const snap = snaps.get(ip) || null, svc = recognise(evidenceOf(s, snap)), crit = svc.filter((x) => x.critical && x.confidence === 'confirmed');
    if (decision === 'critical' && !crit.length && reason.length < 5) throw bad('no business service was confirmed on this server - give the reason it is business-critical');
    let tagged = null;
    if (s.asset && app.assets && typeof app.assets.edit === 'function') {
      const keep = (s.asset.tags || []).filter((t) => t !== 'business-critical' && !/^svc:/.test(t));
      const tags = decision === 'critical' ? keep.concat(['business-critical'], crit.map((x) => 'svc:' + x.id)) : keep;
      app.assets.edit(s.asset.id, { tags }, who); tagged = s.asset.id;
    }
    const rec = { id: ip, decision, reason, services: crit.map((x) => x.id), asset_id: s.asset ? s.asset.id : null, by: (who && who.user) || '', at: new Date(now()).toISOString() };
    decisions.put(rec);
    audit(who, 'service_map.decide', ip, { decision, reason, services: rec.services, asset_id: tagged });
    return view((who && who.role) || 'viewer').servers.find((x) => x.ip === ip);
  }
  function setSsh(b, who) {
    const ip = String((b && b.ip) || '').trim(); if (!servers().some((x) => x.ip === ip)) throw bad('not a known server', 404);
    const id = b.cred_id == null || b.cred_id === '' ? null : String(b.cred_id);
    if (id && !vaultSsh().some((c) => c.id === id)) throw bad('choose a saved SSH login (Asset Discovery → Credentials, kind ssh)');
    links.put(Object.assign(links.get(ip) || { id: ip }, { ssh_cred_id: id, by: (who && who.user) || '', at: new Date(now()).toISOString() }));
    audit(who, 'service_map.ssh', ip, { cred_id: id });
    return view('admin').servers.find((x) => x.ip === ip);
  }
  function start() { if (timer) return; timer = setInterval(guardOf(app, 'service-map.pass', () => pass()), Math.max(15, Number(cfg().interval_min) || 60) * 60000); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { servers, view, pass, decide, setSsh, start, stop, recognise, evidenceOf };
}

function registerServiceMap(srv, app, opts = {}) {
  const S = createServiceMap(app, opts);
  (app.addons = app.addons || {}).serviceMap = S;
  srv.route('GET', '/service-map', (ctx) => void ctx.need('viewer') || S.view(ctx.who && ctx.who.role));
  srv.route('POST', '/service-map/run', async (ctx) => { ctx.need('operator'); const r = await S.pass(); if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip, action: 'service_map.run', target: 'all', detail: r }); return Object.assign(S.view(ctx.who.role), { run: r }); });
  srv.route('POST', '/service-map/decide', (ctx) => { ctx.need('admin'); return S.decide(ctx.body || {}, ctx.who); });
  srv.route('POST', '/service-map/ssh', (ctx) => { ctx.need('admin'); return S.setSsh(ctx.body || {}, ctx.who); });
  if (!opts.noTimer) { S.start(); const t = setTimeout(guardOf(app, 'service-map.pass', () => S.pass()), 240000); if (t.unref) t.unref(); }
  return S;
}

module.exports = { createServiceMap, registerServiceMap, recognise, parsePs, parseListen, parseUnits, parseOratab, parseSqlBrowser, parseHttpHead, CATALOGUE, PROBE_PORTS, KINDS };
