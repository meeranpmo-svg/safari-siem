// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * sentra-siem-ad — AD identity sync helper (installed as /usr/local/sbin/sentra-siem-ad, a bash wrapper around this file).
 *
 *   sentra-siem-ad set-password [--no-verify]   prompt (no echo) for the bind password of ad.bindDN, test it with a bind,
 *                                            store it in secrets.json ad.bind_password (mode 600). Restart sentra-siem after.
 *   sentra-siem-ad check                        CA file, DNS, TCP, TLS + certificate, service bind, base DN, NetBIOS name,
 *                                            privileged groups found, number of users visible
 *   sentra-siem-ad sync-now                     ask the running engine to sync now (POST /api/soc/identity/sync on 127.0.0.1)
 *   sentra-siem-ad status                       last sync result + identity counts (from the engine, else from the state files)
 *
 * Reads /etc/sentra-siem/config.json + secrets.json (SENTRA_SIEM_CONFIG / SENTRA_SIEM_SECRETS override). Passwords are never
 * printed; without a TTY the password is read from the first line of stdin.
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('fs');
const path = require('path');
const http = require('http');
const dns = require('dns');
const net = require('net');
const { loadConfig } = require('../config');
const ldap = require('./ldap-client');
const { DEFAULT_PRIVILEGED } = require('./identity');

const out = (s) => process.stdout.write(s + '\n');
const OK = '  [ok]   ', BAD = '  [FAIL] ', INFO = '  [..]   ';

function promptHidden(label) {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    return new Promise((resolve) => { let b = ''; stdin.setEncoding('utf8'); stdin.on('data', (c) => { b += c; }); stdin.on('end', () => resolve(b.split(/\r?\n/)[0] || '')); });
  }
  return new Promise((resolve) => {
    let pw = '';
    process.stderr.write(label);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const on = (chunk) => {
      for (const c of chunk) {
        if (c === '\r' || c === '\n') { stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', on); process.stderr.write('\n'); resolve(pw); return; }
        if (c === '\u0003') { stdin.setRawMode(false); process.stderr.write('\n'); process.exit(130); }
        if (c === '\u007f' || c === '\b') pw = pw.slice(0, -1); else pw += c;
      }
    };
    stdin.on('data', on);
  });
}

function writeJson600(file, obj) {
  if (SF.isSecretsPath(file)) return SF.write(file, obj);   // sealed at rest
  let st = null; try { st = fs.statSync(file); } catch { /* new file */ }
  const tmp = file + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  try { if (st && process.getuid && process.getuid() === 0) fs.chownSync(tmp, st.uid, st.gid); } catch { /* not root */ }
  fs.renameSync(tmp, file);
}

function client(ad, servers) { return ldap.createClient({ servers: servers || ad.servers, caFile: ad.caFile, timeoutMs: ad.timeout_ms || 15000 }); }

async function setPassword(cfg, args) {
  const ad = cfg.ad;
  if (!ad.bindDN) { out('set ad.bindDN in ' + cfg._paths.config + ' first'); return 1; }
  const pw = await promptHidden('Password for ' + ad.bindDN + ': ');
  if (!pw || !pw.trim()) { out('refused: the password is empty'); return 1; }
  if (process.stdin.isTTY) { const again = await promptHidden('Repeat the password: '); if (again !== pw) { out('the two entries differ — nothing stored'); return 1; } }
  if (!args.includes('--no-verify')) {
    try { await client(ad).run((conn) => conn.bind(ad.bindDN, pw)); out(OK + 'test bind as ' + ad.bindDN + ' succeeded'); } catch (e) {
      out(BAD + 'test bind failed: ' + e.message); out('nothing stored (fix the password, or --no-verify while the DC is not reachable yet)'); return 1;
    }
  }
  const file = cfg._paths.secrets;
  let sec = {}; try { sec = SF.read(file) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
  sec.ad = Object.assign({}, sec.ad || {}, { bind_password: pw });
  writeJson600(file, sec);
  out('stored in ' + file + ' (ad.bind_password, mode 600) — apply with: systemctl restart sentra-siem');
  return 0;
}

function tcp(host, port, ms) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port }); const t = setTimeout(() => { s.destroy(); resolve('timeout'); }, ms);
    s.once('connect', () => { clearTimeout(t); s.destroy(); resolve(null); }); s.once('error', (e) => { clearTimeout(t); resolve(e.code || e.message); });
  });
}

async function check(cfg) {
  const ad = cfg.ad; let bad = 0;
  out('AD identity sync: ' + (ad.enabled ? 'enabled' : 'DISABLED (ad.enabled=false)') + ' · every ' + ad.sync_minutes + ' min · dormant after ' + ad.dormant_days + ' days');
  out('base ' + (ad.baseDN || '(unset)') + ' · bind ' + (ad.bindDN || '(unset)') + ' · password ' + (cfg.secrets.ad && cfg.secrets.ad.bind_password ? 'set' : 'NOT SET (sentra-siem-ad set-password)'));
  try { const pem = fs.readFileSync(ad.caFile, 'utf8'); if (!/BEGIN CERTIFICATE/.test(pem)) throw new Error('no PEM certificate inside'); out(OK + 'CA file ' + ad.caFile); } catch (e) { out(BAD + 'CA file ' + (ad.caFile || '(unset)') + ': ' + e.message); return 1; }
  let usable = null;
  for (const raw of ad.servers || []) {
    let s; try { s = ldap.parseServer(raw); } catch (e) { out(BAD + e.message); bad++; continue; }
    out('server ' + s.url + (s.ip ? ' (dial ' + s.ip + ')' : ''));
    if (!s.ip) { try { const a = await dns.promises.lookup(s.host, { all: true }); out(OK + 'DNS → ' + a.map((x) => x.address).join(', ')); } catch (e) { out(BAD + 'DNS ' + s.host + ': ' + e.code); bad++; continue; } }
    const t = await tcp(s.ip || s.host, s.port, ad.timeout_ms || 15000);
    if (t) { out(BAD + 'TCP ' + (s.ip || s.host) + ':' + s.port + ' ' + t + ' (firewall SIEM → DC TCP ' + s.port + '?)'); bad++; continue; }
    out(OK + 'TCP ' + (s.ip || s.host) + ':' + s.port + ' open');
    try {
      const conn = await client(ad, [raw]).connect();
      const c = conn.sock.getPeerCertificate();
      out(OK + 'TLS ' + conn.sock.getProtocol() + ' · trusted, valid for ' + s.servername + ' · issuer ' + ((c.issuer && c.issuer.CN) || '?') + ' · expires ' + c.valid_to);
      conn.close(); if (!usable) usable = raw;
    } catch (e) { out(BAD + 'TLS: ' + e.message); bad++; }
  }
  if (!usable) { out(BAD + 'no DC passed the TLS checks'); return 1; }
  const pw = cfg.secrets.ad && cfg.secrets.ad.bind_password;
  if (!pw) { out(BAD + 'no bind password'); return 1; }
  try {
    await client(ad, [usable]).run(async (conn) => {
      await conn.bind(ad.bindDN, pw); out(OK + 'service bind as ' + ad.bindDN);
      await conn.search(ad.baseDN, { scope: 'base', attributes: ['distinguishedName'] }); out(OK + 'base DN ' + ad.baseDN + ' exists');
      const names = DEFAULT_PRIVILEGED.concat((ad.privileged_groups || []).filter((x) => x.indexOf('=') < 0));
      const g = await conn.search(ad.baseDN, { filter: `(&(objectClass=group)(|${names.map((n) => `(sAMAccountName=${ldap.escapeFilter(n)})`).join('')}))`, attributes: ['sAMAccountName'], pageSize: 1000 });
      const found = g.entries.map((e) => ldap.ad.first(e, 'sAMAccountName'));
      out(OK + 'privileged groups found: ' + (found.join(', ') || '(none)'));
      const miss = names.filter((n) => !found.some((f) => f.toLowerCase() === n.toLowerCase()));
      if (miss.length) out(INFO + 'not found under the base DN: ' + miss.join(', '));
      for (const dn of (ad.privileged_groups || []).filter((x) => x.indexOf('=') >= 0)) {
        try { await conn.search(dn, { scope: 'base', filter: '(objectClass=group)', attributes: ['cn'] }); out(OK + 'privileged group ' + dn); } catch (e) { out(BAD + 'privileged group ' + dn + ': ' + e.message); bad++; }
      }
      const u = await conn.search(ad.baseDN, { filter: '(&(objectCategory=person)(objectClass=user))', attributes: ['1.1'], pageSize: 1000, maxEntries: 1000000 });
      out(OK + u.entries.length + ' user objects readable (' + u.pages + ' page' + (u.pages > 1 ? 's' : '') + ')');
    });
  } catch (e) { out(BAD + e.message); bad++; }
  out(bad ? bad + ' problem(s) found' : 'all checks passed');
  return bad ? 1 : 0;
}

function api(cfg, method, p) {
  return new Promise((resolve, reject) => {
    const host = cfg.api.host === '0.0.0.0' ? '127.0.0.1' : cfg.api.host;
    const prefix = (cfg.api_prefix || '/api/soc').replace(/\/+$/, '');
    const r = http.request({ host, port: cfg.api.port, method, path: prefix + p, timeout: 600000,
      headers: { 'X-Sentra-Proxy-Secret': cfg.secrets.proxy_secret || '', 'X-Auth-User': 'sentra-siem-ad@' + require('os').hostname(), 'X-Auth-Role': 'admin', 'Content-Type': 'application/json', 'Content-Length': 2 } }, (res) => {
      let d = ''; res.on('data', (c) => { d += c; });
      res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch { /* not json */ } resolve({ status: res.statusCode, body: j, text: d }); });
    });
    r.on('timeout', () => r.destroy(new Error('engine API timeout'))); r.on('error', reject); r.end('{}');
  });
}

function printSync(s) {
  if (!s) { out('no sync has run yet'); return; }
  out('last sync   ' + s.at + ' · ' + (s.ok ? 'OK' : 'FAILED: ' + s.error) + (s.duration_ms !== undefined ? ' · ' + s.duration_ms + ' ms' : '') + (s.server ? ' · ' + s.server : ''));
  if (s.ok) out('            ' + s.users + ' users · ' + s.privileged + ' privileged · ' + s.disabled + ' disabled · ' + s.groups + ' privileged groups · new privileged members ' + (s.new_privileged || 0) + (s.clickhouse_error ? ' · ClickHouse mirror failed: ' + s.clickhouse_error : ''));
}

async function syncNow(cfg) {
  let r;
  try { r = await api(cfg, 'POST', '/identity/sync'); } catch (e) { out('engine API not reachable (' + e.message + ') — is sentra-siem running? systemctl status sentra-siem'); return 1; }
  if (r.status !== 200) { out('sync failed (HTTP ' + r.status + '): ' + ((r.body && r.body.error) || r.text).slice(0, 500)); return 1; }
  printSync(r.body); return 0;
}

async function status(cfg) {
  try {
    const r = await api(cfg, 'GET', '/identity/summary');
    if (r.status === 200 && r.body) {
      const b = r.body, sy = b.sync || {};
      out('AD identity sync: ' + (sy.enabled ? 'enabled' : 'disabled') + (sy.problems && sy.problems.length ? ' · problems: ' + sy.problems.join('; ') : '') + (sy.next_at ? ' · next ' + sy.next_at : ''));
      printSync(sy.last);
      const c = b.counts || {};
      out('directory   ' + (b.domain || '?') + ' (' + (b.netbios || []).join(', ') + ') · ' + c.users + ' users · ' + c.privileged + ' privileged · ' + c.disabled + ' disabled · ' + c.dormant + ' dormant (>' + b.dormant_days + ' d) · ' + c.service_accounts + ' service accounts');
      for (const g of b.privileged_groups || []) out('            ' + g.name + ': ' + g.members + ' member(s), ' + g.nested_members + ' through nesting');
      return 0;
    }
    out('engine answered HTTP ' + r.status + ' — falling back to the state files');
  } catch (e) { out('engine API not reachable (' + e.message + ') — reading the state files'); }
  try { printSync(JSON.parse(fs.readFileSync(path.join(cfg.state_dir, 'ad-sync-status.json'), 'utf8'))); } catch { out('no sync status recorded in ' + cfg.state_dir); }
  return 0;
}

async function main(argv) {
  const cmd = argv[0];
  const cfg = loadConfig();
  switch (cmd) {
    case 'set-password': return setPassword(cfg, argv.slice(1));
    case 'check': return check(cfg);
    case 'sync-now': return syncNow(cfg);
    case 'status': return status(cfg);
    default:
      out(fs.readFileSync(__filename, 'utf8').split('\n').slice(2, 12).map((l) => l.replace(/^ \* ?/, '')).join('\n'));
      return 2;
  }
}

if (require.main === module) main(process.argv.slice(2)).then((c) => { process.exitCode = c; }, (e) => { process.stderr.write('sentra-siem-ad: ' + e.message + '\n'); process.exitCode = 1; });
module.exports = { main };
