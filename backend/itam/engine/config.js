// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Configuration: /etc/sentra-itam/config.json merged over defaults, secrets from /etc/sentra-itam/secrets.json (root:sentra-itam 640, values sealed - engine/secret-values.js).
// SENTRA_ITAM_CONFIG / SENTRA_ITAM_SECRETS / SENTRA_ITAM_DATA override the paths (tests, staging).
// Secrets are returned as a separate object and are never serialised into status, logs or audit records.
const fs = require('node:fs');
const path = require('node:path');
// the organisation's sites come from the brand setting (brand/brand.json "sites"); config.json discovery.sites overrides them
const BRAND_SITES = (() => { try { return (require('./brand').sites || []).filter((x) => x && x.name); } catch (e) { return []; /* no brand file in a tool run: no default sites */ } })();

const VERSION = '1.0.0';

const DEFAULTS = {
  data_dir: '/var/lib/sentra-itam',
  log_level: 'info',
  api: { host: '127.0.0.1', port: 9150, prefix: '/api/itam', agent_prefix: '/agent' },
  ai: {
    provider: 'private',                       // private (production, S1) | claude (staging, sentra-ai loopback) | none
    model: 'claude-opus-5',
    effort: 'high',
    claude_url: 'http://127.0.0.1:9093/draft',
    private_url: '',                           // e.g. http://10.x.x.x:9093  (/draft is appended) — 'not configured' until set
    timeout_ms: 6 * 60 * 1000,
    max_queue: 20,
    per_user_hourly_cap: 20,
    daily_cap: 60,
  },
  netops: {
    // ITAM SUBSCRIBES to sentra-netops devices; it does NOT re-poll devices itself.
    base_url: '',                              // sentra-netops engine base, e.g. http://127.0.0.1:9145/api/netops  ('' = not configured)
    devices_path: '/devices',                  // GET: array of netops device records
    topology_path: '/topology',                // GET: LLDP neighbour edges
    timeout_ms: 20000,
  },
  vcenter: {
    base_url: '',                              // https://vcenter.example/ (read-only vSphere REST) — '' = not configured
    insecure_tls: false,                       // allow self-signed — honoured ONLY when lab_mode is true
    lab_mode: false,                           // lab only: permits http:// base_url and insecure_tls (refused otherwise)
    timeout_ms: 30000,
  },
  agent: {
    enrol_token_ttl_hours: 24,                 // one-time enrolment token lifetime
    heartbeat_stale_hours: 48,                 // agent considered stale (not-seen) after this
    clock_skew_s: 300,                         // accepted skew for the report nonce/timestamp (replay window)
  },
  // Asset Discovery (engine/discovery, docs/DISCOVERY.md). Credentials are NOT here: they live in the write-only vault.
  discovery: {
    sites: BRAND_SITES.map((x) => x.name),
    vault_key_file: '/etc/sentra-itam/discovery-vault.key',   // 64 hex chars, mode 600, owner sentra-itam (install creates it)
    vault_create_key: false,                   // production: the installer creates the key; tests/dev may let the engine create it
    max_hosts_per_scope: 4096,
    icmp_mode: 'fping',                         // fping (batch) | ping (per host) — system binaries, argv only, no shell
    fping_bin: '/usr/bin/fping',
    ping_bin: '/usr/bin/ping',
    icmp_timeout_ms: 800,
    tcp_timeout_ms: 800,
    snmp_timeout_ms: 1500,
    arp_path: '/proc/net/arp',
    ad_resolve_dns: true,                       // resolve AD dNSHostName to join AD computers with swept hosts in the scope
    scheduler_tick_s: 30,
    azure: { login_base: 'https://login.microsoftonline.com', arm_base: 'https://management.azure.com' },
    aws: { endpoint: 'https://ec2.{region}.amazonaws.com' },
    siem: {
      base_url: 'http://127.0.0.1:9120',        // sentra-siem engine (loopback only)
      prefix: '/api/soc',
      secret_file: '',                          // e.g. /etc/sentra-itam/siem-proxy-secret (the SIEM proxy_secret; '' = connect disabled)
      silent_minutes: 60,                       // connected source with no events for longer → ITAM finding "siem_silent"
      health_interval_min: 5,
      site_map: Object.fromEntries(BRAND_SITES.map((x) => [x.name, x.id])),
      bridge: { enabled: false, url: 'http://127.0.0.1:9120/ingest/itam-bridge', token_file: '/etc/sentra-itam/siem-bridge-token' },
    },
  },
  // asset considered "not seen" (possible lost/retired) after this many days with no source sighting
  not_seen_days: 30,
  // warranty / EOL "expiring soon" window (days)
  expiry_window_days: 90,
  compaction_hours: 6,
};

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
function merge(base, over) {
  if (!isObj(over)) return base;
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(base[k]) ? merge(base[k], v) : v;
  return out;
}
function readJson(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw new Error(`cannot read ${file}: ${e.code || e.message}`); }
  try { return JSON.parse(text); } catch { throw new Error(`invalid JSON in ${file}`); }
}

function loadConfig(env = process.env) {
  const cfgPath = env.SENTRA_ITAM_CONFIG || '/etc/sentra-itam/config.json';
  const config = merge(DEFAULTS, readJson(cfgPath) || {});
  const secPath = env.SENTRA_ITAM_SECRETS || path.join(path.dirname(cfgPath), 'secrets.json');
  const s = readJson(secPath) || {};
  // values are sealed at rest (engine/secret-values.js; install/itam-secrets.js seal); proxy_secret is readable by design
  const SV = require('./secret-values');
  const sealer = Object.values(s).some(SV.isSealed) ? SV.sealerFor(config.discovery && config.discovery.vault_key_file) : null;
  const val = (k) => SV.openValue(k, s[k], sealer);
  const secrets = {
    proxy_secret: val('proxy_secret'),
    private_token: val('private_token'),     // optional Bearer for the private model
    netops_token: val('netops_token'),       // optional Bearer when subscribing to the netops API
    vcenter_user: val('vcenter_user'),        // read-only vSphere account (write-only via /settings)
    vcenter_pass: val('vcenter_pass'),
  };
  if (env.SENTRA_ITAM_DATA) config.data_dir = env.SENTRA_ITAM_DATA;
  return { config, secrets, cfgPath };
}

module.exports = { loadConfig, DEFAULTS, merge, VERSION };
