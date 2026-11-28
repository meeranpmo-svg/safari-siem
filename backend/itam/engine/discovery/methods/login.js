// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Read-only inventory LOGINS for the active scan, after the service probes found something to log in to:
//   db       database credentials (kind db_login, one per engine; a scope may hold several) on every host where that
//            engine's listener answered: fixed read-only queries for version, edition, instance and database names.
//   unix     an SSH credential on every host with SSH open: a fixed list of read-only commands (uname, release, CPU,
//            memory, serial / model).
//   storage  a NetApp ONTAP / HPE MSA read-only credential (kind storage_api) on every host with iSCSI / NDMP open:
//            system name, model, serial and version through the arrays' REST API (engine/storage-sources.js).
// TRUST FIRST: a password is only sent to a host whose SSH host key / HTTPS certificate an administrator trusted
// (disc_trust collection). An unknown key is recorded as PENDING without logging in - reading a host key or a
// certificate sends nothing secret - and appears under Credentials → Trust. A key that CHANGED is never used and
// is flagged on the device. Database logins have no host key; use a dedicated read-only account (the page says so).
// SSH and database logins run in inv-helper.py (paramiko / pymysql / pg8000 / oracledb / pytds) with the Python of
// the SIEM's netops venv; credentials go to it on stdin only.
const path = require('node:path');
const { spawn } = require('node:child_process');

const HELPER = path.join(__dirname, '..', 'inv-helper.py');
const str = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);
const DB_DEFAULT_PORT = { oracle: 1521, mssql: 1433, mysql: 3306, postgres: 5432 };

function realRunner(python, timeoutMs = 90000) {
  return (req) => new Promise((resolve) => {
    let p;
    try { p = spawn(python, ['-I', HELPER], { stdio: ['pipe', 'pipe', 'ignore'], env: { PATH: process.env.PATH || '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1', LANG: 'C.UTF-8' } }); } catch (e) { resolve({ ok: false, error_class: 'missing_module', error: `Python not found (${python})` }); return; }
    let out = '';
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* gone */ } }, timeoutMs);
    p.stdout.on('data', (d) => { if (out.length < 200000) out += d; });
    p.on('error', () => { clearTimeout(t); resolve({ ok: false, error_class: 'missing_module', error: `Python not found (${python}) - run install/netops-cli-setup.sh in the SIEM` }); });
    p.on('close', () => { clearTimeout(t); try { resolve(JSON.parse(out)); } catch { resolve({ ok: false, error_class: 'timeout', error: 'the login helper did not answer' }); } });
    p.stdin.end(JSON.stringify(req));
  });
}

// ---- trust list ------------------------------------------------------------------------------------------------------
function createTrust(store, audit) {
  const col = store.collection('disc_trust');
  const id = (kind, ip, port) => `${kind}:${ip}:${port}`;
  return {
    get: (kind, ip, port) => col.get(id(kind, ip, port)) || null,
    // first sighting → pending; same key → touch; different key from a trusted one → changed (never auto-accepted)
    see(kind, ip, port, fp, info) {
      const k = id(kind, ip, port), cur = col.get(k), at = new Date().toISOString();
      if (!cur) { const r = { id: k, kind, ip, port, fp, info: info || null, state: 'pending', first_seen: at, last_seen: at }; col.put(r); return r; }
      if (cur.fp === fp) { col.patch(k, (x) => { x.last_seen = at; if (x.state === 'changed' && x.new_fp === fp) { delete x.new_fp; x.state = 'trusted'; } }); return col.get(k); }
      if (cur.state === 'trusted' || cur.state === 'changed') { col.patch(k, (x) => { x.state = 'changed'; x.new_fp = fp; x.new_info = info || null; x.last_seen = at; }); return col.get(k); }
      col.patch(k, (x) => { x.fp = fp; x.info = info || null; x.last_seen = at; }); return col.get(k);   // still pending: newest key
    },
    list: (q = {}) => col.all((r) => (!q.state || r.state === q.state)).sort((a, b) => (a.ip < b.ip ? -1 : 1)),
    decide(ids, action, who) {
      const done = [];
      for (const k of (Array.isArray(ids) ? ids : []).slice(0, 2000)) {
        const r = col.get(String(k)); if (!r) continue;
        if (action === 'trust') {
          col.patch(r.id, (x) => { if (x.state === 'changed' && x.new_fp) { x.prev_fp = x.fp; x.fp = x.new_fp; x.info = x.new_info || x.info; delete x.new_fp; delete x.new_info; } x.state = 'trusted'; x.trusted_by = who.user; x.trusted_at = new Date().toISOString(); });
        } else if (action === 'forget') col.remove(r.id);
        else continue;
        done.push(r.id);
      }
      if (done.length && audit) audit({ by: who.user, role: who.role, ip: who.ip, action: `discovery.trust.${action}`, target: done.length === 1 ? done[0] : `${done.length} keys`, detail: { ids: done.slice(0, 200) } });
      return { done: done.length };
    },
  };
}

// ---- parsing -------------------------------------------------------------------------------------------------------
function parseUnix(f) {
  f = f || {};
  const o = {};
  const rel = str(f.release, 200), osr = String(f.os_release || '');
  const pretty = (/^PRETTY_NAME="?([^"\n]+)"?/m.exec(osr) || [])[1];
  const un = str(f.uname, 300);
  if (/solaris/i.test(rel)) o.os = rel.replace(/\s+/g, ' ');
  else if (pretty) o.os = str(pretty, 120);
  else if (/^SunOS\s+\S+\s+5\.(\d+)/.test(un)) o.os = 'Oracle Solaris ' + /^SunOS\s+\S+\s+5\.(\d+)/.exec(un)[1];
  else if (/^AIX/.test(un)) o.os = 'IBM AIX';
  else if (un) o.os = un.split(' ')[0];
  o.hostname = str(f.hostname, 120).toLowerCase() || null;
  const smb = String(f.smbios || '');
  const sv = (k) => { const m = new RegExp('^\\s*' + k + ':\\s*(.+)$', 'mi').exec(smb); return m ? str(m[1], 120) : ''; };
  const dmi = String(f.dmi || '').split('\n').map((x) => str(x, 120));
  const bad = /^(none|n\/a|not specified|to be filled.*|0+|system serial number|default string)$/i;
  o.vendor = [sv('Manufacturer'), dmi[0]].find((x) => x && !bad.test(x)) || null;
  o.model = [sv('Product'), dmi[1], str(f.platform, 80)].find((x) => x && !bad.test(x) && x !== 'unknown') || null;
  o.serial = [sv('Serial Number'), dmi[2]].find((x) => x && !bad.test(x) && x.length >= 3) || null;
  const nums = (s) => String(s || '').split('\n').map((x) => parseInt(x, 10)).filter((n) => n > 0);
  o.sockets = nums(f.sockets)[0] || null;
  o.cpus = Math.max(0, ...nums(f.cpus)) || null;
  // physical cores per socket: Linux "cpu cores : 16", Solaris psrinfo -pv "has 8 cores and 64 virtual processors"
  const cm = /cpu cores\s*:\s*(\d+)/i.exec(f.cores || '') || /(\d+)\s+cores\b/i.exec(f.cores || '');
  o.cores_per_socket = cm && parseInt(cm[1], 10) > 0 ? parseInt(cm[1], 10) : null;
  o.sockets_v = 2;   // sockets counted as distinct physical ids (records without it came from the old count)
  const mem = String(f.memory || '');
  const mb = /Memory size:\s*(\d+)\s*Megabytes/i.exec(mem), kb = /MemTotal:\s*(\d+)\s*kB/i.exec(mem);
  o.mem_gb = mb ? Math.round(Number(mb[1]) / 1024) : kb ? Math.round(Number(kb[1]) / 1048576) : null;
  return o;
}
function parseDb(r) {
  const parts = String(r.instance || '').split('|');
  const v = str(r.version, 300);
  const edition = r.engine === 'mssql' ? str(parts[3], 80) : r.engine === 'oracle' ? ((/(Enterprise|Standard|Express|Personal)\s+Edition/i.exec(v) || [])[0] || '') : '';
  return {
    engine: r.engine, version: v, edition: edition || null,
    host_name: str(r.engine === 'postgres' ? '' : r.engine === 'oracle' ? parts[1] : parts[0], 120).toLowerCase().split('.')[0] || null,   // oracle: instance|host|version
    instance: r.engine === 'mssql' ? str(parts[1], 80) : r.engine === 'oracle' ? str(parts[0], 80) : null,
    databases: Array.isArray(r.databases) ? r.databases.map((x) => str(x, 128)).filter((x) => !/^(information_schema|performance_schema|mysql|sys|template\d)$/i.test(x)).slice(0, 100) : [],
    partial: Object.keys(r).filter((k) => /_error$/.test(k) && r[k]).map((k) => k.replace(/_error$/, '') + ': ' + r[k]),
  };
}

// ---- login phase ---------------------------------------------------------------------------------------------------
// targets: [{ip, db: [{engine, port}], ssh: port|null, storage: true|false}]
async function loginPhase({ targets, m, vault, trust, run: runHelper, request, obs, stat, take, stop, pool, concurrency, log }) {
  const dbIds = (m.db && m.db.credential_ids) || [], sshId = m.unix && m.unix.credential_id, stId = m.storage && m.storage.credential_id;
  const opened = new Map();
  const open = (id) => { if (!opened.has(id)) opened.set(id, Object.assign(vault.open(id), { label: ((vault.get && vault.get(id)) || {}).label || id })); return opened.get(id); };
  const S = { db: { tried: 0, ok: 0, auth: 0, failed: 0, skipped_unverified: 0 }, unix: { tried: 0, ok: 0, auth: 0, failed: 0, pending_trust: 0, key_changed: 0 }, storage: { tried: 0, ok: 0, auth: 0, failed: 0, pending_trust: 0, cert_changed: 0 } };
  const errs = {};
  const note = (k, e) => { errs[k] = errs[k] || {}; errs[k][e] = (errs[k][e] || 0) + 1; };
  try {
    // a database login is sent across a whole scope only over TLS with the server's certificate VERIFIED: with tls off or "require"
    // (certificate not checked) any host in the subnet could answer on the database port and capture the password (cleartext
    // auth, a self-signed certificate). Such logins are kept for the one-host test (Asset Discovery -> Credentials -> Test) only.
    const dbAll = dbIds.map((id) => { try { return open(id); } catch (e) { log.warn('discovery: db credential not usable', { id, err: e.message }); return null; } }).filter(Boolean);
    const dbCreds = dbAll.filter((c) => c.target && c.target.tls === 'verify');
    S.db.skipped_unverified = dbAll.length - dbCreds.length;
    if (S.db.skipped_unverified) log.warn('discovery: database logins without a verified TLS connection are not tried across the scope', { skipped: S.db.skipped_unverified });
    const ssh = sshId ? (() => { try { return open(sshId); } catch { return null; } })() : null;
    const st = stId ? (() => { try { return open(stId); } catch { return null; } })() : null;
    await pool(targets, Math.min(concurrency || 4, 8), async (t) => {
      if (stop()) return;
      await take();
      // databases: every credential whose engine answered on this host (one observation per host, all engines)
      const dbOut = {}; let dbHost = '';
      for (const c of dbCreds) {
        const eng = c.target && c.target.engine, hit = (t.db || []).find((x) => x.engine === eng);
        if (!hit) continue;
        S.db.tried++;
        const r = await runHelper({ op: 'db', engine: eng, host: t.ip, port: (c.target && c.target.port) || hit.port || DB_DEFAULT_PORT[eng], username: c.secret.username, password: c.secret.password, service: c.target && c.target.service, database: c.target && c.target.database, tls: (c.target && c.target.tls) || 'off', ca_file: c.target && c.target.ca_file });
        if (r && r.ok) { S.db.ok++; const d = parseDb(r); dbHost = dbHost || d.host_name || ''; dbOut[eng] = Object.assign(d, { at: new Date().toISOString(), credential: c.label }); }
        else { if (r && r.error_class === 'auth') S.db.auth++; else S.db.failed++; note('db', (r && r.error_class) || 'error'); }
      }
      if (Object.keys(dbOut).length) obs({ method: 'db', ip: t.ip, hostname: dbHost, extra: { db_login: dbOut } });
      // SSH: trusted host key first
      if (ssh && t.ssh) {
        const port = (ssh.target && ssh.target.port) || t.ssh;
        const hk = await runHelper({ op: 'hostkey', host: t.ip, port });
        if (!hk || !hk.ok) { S.unix.failed++; note('unix', (hk && hk.error_class) || 'error'); }
        else {
          const tr = trust.see('ssh', t.ip, port, hk.fp, { type: hk.type });
          if (tr.state === 'pending') S.unix.pending_trust++;
          else if (tr.state === 'changed') { S.unix.key_changed++; obs({ method: 'unix', ip: t.ip, extra: { unix_login: { error: 'SSH host key changed - not logged in', at: new Date().toISOString() } } }); }
          else {
            S.unix.tried++;
            const r = await runHelper({ op: 'ssh_facts', host: t.ip, port, username: ssh.secret.username, password: ssh.secret.password, private_key: ssh.secret.private_key, fp: tr.fp });
            if (r && r.ok) {
              S.unix.ok++;
              const u = parseUnix(r.facts);
              obs({ method: 'unix', ip: t.ip, hostname: u.hostname || '', os: u.os || '', serial: u.serial || '', model: u.model || '', vendor: u.vendor || '', extra: { unix_login: Object.assign(u, { at: new Date().toISOString(), credential: ssh.label }) } });
            } else if (r && r.error_class === 'hostkey_changed') { trust.see('ssh', t.ip, port, r.fp, { type: r.type }); S.unix.key_changed++; }
            else { if (r && r.error_class === 'auth') S.unix.auth++; else S.unix.failed++; note('unix', (r && r.error_class) || 'error'); }
          }
        }
      }
      // storage REST API: certificate trusted (public CA, or pinned through the trust list)
      if (st && t.storage) {
        const kind = (st.target && st.target.platform) || 'ontap', port = (st.target && st.target.port) || 443;
        const tr = trust.get('tls', t.ip, port);
        if (tr && tr.state === 'changed') { S.storage.cert_changed++; return; }
        S.storage.tried++;
        const cred = { secret: st.secret, target: { base_url: `https://${t.ip}${port === 443 ? '' : ':' + port}`, tls_fingerprint: tr && tr.state === 'trusted' ? tr.fp : undefined } };
        const r = await require('../../storage-sources')[kind](cred,   // loaded here: installed by add-storage.sh
           { request, captureUntrusted: true, timeoutMs: 30000 });
        if (r.ok) {
          S.storage.ok++;
          const y = r.system || {}, node = (r.controllers || [])[0] || {};
          obs({ method: 'storage', ip: t.ip, hostname: str(y.name, 120).toLowerCase(), serial: y.serial || node.serial || '', model: y.model || node.model || '', vendor: kind === 'ontap' ? 'NetApp' : 'HPE', os: [kind === 'ontap' ? 'NetApp ONTAP' : 'HPE MSA', y.version].filter(Boolean).join(' '), extra: { storage_login: { platform: kind, name: y.name || null, version: y.version || null, health: y.health || null, at: new Date().toISOString(), credential: st.label } } });
        } else if (r.presented && r.presented.fingerprint256) {
          const s2 = trust.see('tls', t.ip, port, r.presented.fingerprint256, { subject: r.presented.subject || null, issuer: r.presented.issuer || null, valid_to: r.presented.valid_to || null });
          S.storage.tried--; if (s2.state === 'changed') S.storage.cert_changed++; else S.storage.pending_trust++;
        } else { if (r.error_class === 'auth' || r.error_class === 'authz') S.storage.auth++; else S.storage.failed++; note('storage', r.error_class || 'error'); }
      }
    }, stop);
  } finally { for (const c of opened.values()) { try { c.release(); } catch { /* released */ } } }
  if (dbIds.length) stat('db_login', Object.assign({ ok: true }, S.db, errs.db ? { errors: errs.db } : {}));
  if (sshId) stat('unix_login', Object.assign({ ok: true }, S.unix, errs.unix ? { errors: errs.unix } : {}));
  if (stId) stat('storage_login', Object.assign({ ok: true }, S.storage, errs.storage ? { errors: errs.storage } : {}));
  return S;
}

module.exports = { realRunner, createTrust, parseUnix, parseDb, loginPhase, HELPER, DB_DEFAULT_PORT };
