// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Install-time JSON helper for install.sh (Node standard library only). Never prints secrets.
//
//   node setup-json.js secrets <secrets.json> "<src ids to ensure tokens for>"
//        creates/merges {clickhouse:{user,password}, ingest_tokens:{}} (the shape ch-install.sh also uses);
//        prints the ids for which a token was created now.
//   node setup-json.js config <config.json>   (options via env, see below)
//        writes a default config when the file is missing; applies listener options to an existing file only when
//        they were given explicitly. Prints: "<syslog_host> <syslog_tcp_port> <tls on|off> <lowest_port> <api_port>".
//        env: NODE_NAME, RETENTION, LISTEN_LAN=1 + LAN_IP, SYSLOG_PORT, TLS_ON=1, TOKENS (default windows sources)
//
// Files are written atomically with mode 600; ownership is fixed by install.sh afterwards.
const fs = require('node:fs');
const crypto = require('node:crypto');

// secrets.json may be sealed: engine/secretfile.js reads / writes it (sealed when the key exists)
let SF = null; try { SF = require('../engine/secretfile'); } catch (e) { SF = null; }
const isSec = (p) => !!SF && SF.isSecretsPath(p);
function readJson(p) {
  if (isSec(p)) { try { return SF.read(p); } catch (e) { throw new Error(`cannot use ${p}: ${e.message}`); } }
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw new Error(`cannot use ${p}: ${e.message}`);
  }
}
function writeJson(p, obj) {
  if (isSec(p)) { SF.write(p, obj); return; }
  const tmp = `${p}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, p);
}
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const ids = (s) => String(s || '').split(/[\s,]+/).filter(Boolean);
const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

function secrets(p, tokenIds) {
  const s = readJson(p) || {};
  s.clickhouse = isObj(s.clickhouse) ? s.clickhouse : {};
  if (!s.clickhouse.user) s.clickhouse.user = 'sentra_siem';
  if (!s.clickhouse.password) s.clickhouse.password = crypto.randomBytes(24).toString('hex');
  if (!s.proxy_secret || String(s.proxy_secret).length < 32) s.proxy_secret = crypto.randomBytes(32).toString('hex');   // nginx → engine
  s.ingest_tokens = isObj(s.ingest_tokens) ? s.ingest_tokens : {};
  const created = [];
  for (const id of ids(tokenIds)) {
    if (!ID_RE.test(id)) throw new Error(`invalid source id "${id}"`);
    if (!s.ingest_tokens[id]) { s.ingest_tokens[id] = crypto.randomBytes(32).toString('hex'); created.push(id); }
  }
  writeJson(p, s);
  return created.join(' ');
}

function config(p, e) {
  let c = readJson(p);
  const fresh = !c;
  if (fresh) {
    c = {
      node_name: e.NODE_NAME || require('node:os').hostname(),
      data_dir: '/var/lib/sentra-siem',
      log_level: 'info',
      timezone: 'Asia/Riyadh',
      api: { host: '127.0.0.1', port: 9120, max_body_mb: 5 },
      syslog: {
        host: '127.0.0.1',
        udp: { enabled: true, port: 5514 },
        tcp: { enabled: true, port: 5514 },
        tls: { enabled: false, port: 6514, cert: '/etc/sentra-siem/tls/syslog.crt', key: '/etc/sentra-siem/tls/syslog.key' },
        tz_offset_min: 180,
      },
      ingest: { max_mb: 5, max_decompressed_mb: 20 },
      clickhouse: { url: 'http://127.0.0.1:8123', database: 'siem' },
      retention_days: Number(e.RETENTION) || 365,
      spool_max_mb: 2048,
      sources: ids(e.TOKENS === undefined ? 'win-servers win-dc' : e.TOKENS).map((id) => ({ id, type: 'windows' })),
      m365: { enabled: false },
      lr: { enabled: false },
    };
  }
  c.syslog = isObj(c.syslog) ? c.syslog : {};
  let changed = fresh;
  if (e.LISTEN_LAN === '1') {
    if (!e.LAN_IP) throw new Error('LISTEN_LAN=1 needs LAN_IP');
    c.syslog.host = e.LAN_IP; changed = true;
  }
  if (e.SYSLOG_PORT) {
    const n = Number(e.SYSLOG_PORT);
    if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error('invalid SYSLOG_PORT');
    c.syslog.udp = { ...(c.syslog.udp || {}), port: n };
    c.syslog.tcp = { ...(c.syslog.tcp || {}), port: n };
    changed = true;
  }
  if (e.TLS_ON === '1') {
    c.syslog.tls = { ...(c.syslog.tls || {}), enabled: true, cert: '/etc/sentra-siem/tls/syslog.crt', key: '/etc/sentra-siem/tls/syslog.key' };
    changed = true;
  }
  if (changed) writeJson(p, c);
  const s = c.syslog;
  const api = isObj(c.api) ? c.api : {};
  const apiPort = api.port || 9120;
  const udp = s.udp || {}, tcp = s.tcp || {}, tls = s.tls || {};
  const ports = [apiPort];
  if (udp.enabled !== false) ports.push(udp.port || 5514);
  if (tcp.enabled !== false) ports.push(tcp.port || 5514);
  if (tls.enabled) ports.push(tls.port || 6514);
  return [s.host || '127.0.0.1', tcp.port || 5514, tls.enabled ? 'on' : 'off', Math.min(...ports), apiPort].join(' ');
}

try {
  const [cmd, file, arg] = process.argv.slice(2);
  if (cmd === 'secrets' && file) process.stdout.write(secrets(file, arg));
  else if (cmd === 'nginx-secret' && file && arg) {   // writes the nginx include that carries the proxy secret (mode 600, never printed)
    const s = readJson(file) || {}; if (!s.proxy_secret) { process.stderr.write('no proxy_secret in ' + file + '\n'); process.exit(1); }
    fs.writeFileSync(arg, 'proxy_set_header X-Sentra-Proxy-Secret "' + s.proxy_secret + '";\n', { mode: 0o600 }); fs.chmodSync(arg, 0o600);
  }
  else if (cmd === 'config' && file) process.stdout.write(config(file, process.env));
  else { process.stderr.write('usage: setup-json.js secrets <file> "<ids>" | config <file>\n'); process.exit(2); }
} catch (e) {
  process.stderr.write(`setup-json: ${e.message}\n`);
  process.exit(1);
}
