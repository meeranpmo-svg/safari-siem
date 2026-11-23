// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./util/brand');
// Configuration: /etc/sentra-siem/config.json (+ secrets.json, mode 600) merged over built-in defaults.
// SENTRA_SIEM_CONFIG=<path> overrides the config path (tests); SENTRA_SIEM_SECRETS=<path> the secrets path
// (default: `secrets_path` from config, else secrets.json next to the config file). SENTRA_SIEM_DATA overrides data_dir.
// Secrets are attached as NON-enumerable properties so JSON.stringify(config) never leaks them.
const SF = require('./secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');

const VERSION = '1.0.0';
const DEFAULT_CONFIG_PATH = '/etc/sentra-siem/config.json';

const DEFAULTS = {
  node_name: os.hostname(),
  data_dir: '/var/lib/sentra-siem',
  log_level: 'info',
  timezone: 'Asia/Riyadh',                // used for "today" boundaries in reports
  api: { host: '127.0.0.1', port: 9120, max_body_mb: 5 },
  syslog: {
    host: '127.0.0.1',
    udp: { enabled: true, port: 5514 },
    tcp: { enabled: true, port: 5514, max_connections: 2000, max_connections_per_peer: 20, idle_timeout_s: 600 },
    tls: { enabled: false, port: 6514, cert: '/etc/sentra-siem/tls/syslog.crt', key: '/etc/sentra-siem/tls/syslog.key', ca: '', request_cert: false },
    max_line: 65536,
    tz_offset_min: 180,                   // RFC 3164 timestamps carry no zone: assume AST (UTC+3) unless the source says otherwise
    // senders not listed in "sources": 'tag' = accept, tag the event "unregistered-source" and warn (default);
    // 'drop' = discard (recommended once every device is onboarded: anyone who can reach the port could otherwise
    // inject forged events); 'accept' = accept silently (old behaviour)
    unknown_sources: 'tag',
    default_sources: {
      'syslog-udp': { id: 'syslog-udp', type: 'syslog' },
      'syslog-tcp': { id: 'syslog-tcp', type: 'syslog' },
      'syslog-tls': { id: 'syslog-tls', type: 'syslog' },
    },
  },
  ingest: { max_mb: 5, max_decompressed_mb: 20, max_items: 50000 },
  clickhouse: { url: 'http://127.0.0.1:8123', database: 'siem', user: 'sentra_siem', timeout_ms: 30000 },
  retention_days: 365,
  netops: {                               // AI Network Engineer (docs/NETOPS.md): device polling, findings, AI troubleshooting
    enabled: true,                        // poller runs only for devices added under Network Engineer → Devices
    interval_s: 120, concurrency: 8, history: true,
    thresholds: {},                       // override analyze.js DEF, e.g. { "util_warn": 70 }
    ai: { enabled: true, model: 'claude-opus-5-5', effort: 'high', fallbacks: true, timeout_s: 180 }, // key: secrets.json netops.anthropic_api_key
  },
  archive_retention_days: 730,            // Data Optimizer cold tier TTL (DATAOPT.md); also settable in /dataopt/settings
  dataopt: {                              // Data Optimizer (engine/dataopt): archive backend + enforcement
    enabled: true,
    archive: { clickhouse: true, file: { enabled: false, dir: '' } },
  },
  writer: { batch_size: 5000, flush_ms: 1000, max_inflight: 2, max_queue: 10, stats_flush_ms: 10000 },
  spool_max_mb: 2048,
  sources: [],                            // [{id, type, match: {ip|cidr}, token?, tz_offset_min?, silent_after_s?}]
                                          // relays: {id, type:"relay", allowed_peers:[CIDR…], file_sources?:{"exchange-msgtrk"|"iis"|"text": src_id}}
  enrich: { assets: [], admin_users: [] },
  tail: { max_clients: 20, max_eps_per_client: 200 },
  detect: { rules_dir: '' },              // '' = engine/detect/rules
  m365: {
    enabled: false,                       // Office 365 Management Activity API pull (collect/m365.js); credentials in secrets.json "m365"
    content_types: ['Audit.AzureActiveDirectory', 'Audit.Exchange', 'Audit.SharePoint', 'Audit.General', 'DLP.All'],
    poll_s: 300, first_lookback_h: 24, overlap_min: 15, src_id: 'm365',
    authority: 'https://login.microsoftonline.com', api_root: 'https://manage.office.com', publisher_id: '',
  },
  exchange: { store_subjects: false },    // false: mail subjects only as SHA-256 (message tracking, Exchange Online items)
  lr: { enabled: false },
  ueba: {},                               // UEBA engine overrides (engine/ueba/settings.js holds the full defaults)
  ad: {                                   // on-prem Active Directory identity sync (engine/ad): read-only LDAPS pull; the bind password
    enabled: false,                       // lives in secrets.json ad.bind_password (set with: sudo sentra-siem-ad set-password)
    servers: [],                          // ["ldaps://dc-hqa.the organisation:636"] or [{url, ip}] (ip = dial address; cert still checked for the name)
    caFile: '',                           // PEM of the AD CS root CA, e.g. /etc/ssl/corp-hq/corp-ca.pem
    baseDN: '',                           // DC=corp-hq,DC=com
    bindDN: '',                           // read-only service account, e.g. CN=svc-zyberon-ldap,OU=Service Accounts,DC=corp-hq,DC=com
    privileged_groups: [],                // extra privileged groups (names or DNs) on top of the built-in admin groups
    sync_minutes: 60,
    dormant_days: 90,
    netbios: [],                          // NetBIOS domain name(s) as they appear in events (also read from AD when possible)
    service_account_patterns: ['svc-*', 'svc_*'],
    user_filter: '',                      // optional extra LDAP filter ANDed to the user query, e.g. (!(sAMAccountName=test*))
    timeout_ms: 15000,
    page_size: 1000,
  },
  compliance: {                           // SAMA CSF coverage (engine/compliance): defaults; admins override thresholds through
    sama: {                               // POST /api/soc/compliance/sama/settings (stored in the state collection compliance_settings)
      required_retention_days: 365,
      required_source_classes: ['domain_controllers', 'windows_servers', 'firewall_network', 'microsoft_365'],
      period_days: 30,                    // default evidence period (alerts, cases, MTTA/MTTR)
      active_window_h: 24,                // a source class / host counts as reporting when seen within this window
      cache_s: 60,                        // evidence collection is cached this long (ClickHouse queries are bounded + read-only)
      grc_push: {                         // periodic push of SIEM evidence per SAMA control to AI GRC (POST {url}/evidence). OFF by default.
        enabled: false,                   // the GRC proxy secret goes in secrets.json "grcai_proxy_secret"
        url: 'http://127.0.0.1:9140/api/grcai',
        interval_h: 24,
        user: 'sentra-siem',                 // identity recorded by GRC for the upload (X-Auth-User); GRC needs role operator to upload
        role: 'operator',
        send_to_ai: false,                // evidence contains host / account names: keep it away from external AI unless approved
        timeout_ms: 15000,
      },
    },
  },
  onboard: {                              // self-service Connect hub (engine/onboard): what the instructions tell admins to point at
    siem_host: ZYB_ORG.portal_host,            // portal / HTTPS ingest host name (agents, relays)
    siem_ip: ZYB_ORG.platform_addr,             // LAN IP devices send syslog to (shown in the instructions and the firewall check)
    kit_base: '/agent',                   // where nginx serves the static agent kits (install/make-agent-kit.sh)
    receiving_window_min: 15,             // a source is "receiving" when it had an event in this window
    sites: [                              // customer sites (editable by admins in the Connect hub; devices are registered per site)
      { id: 'riyadh-hq', name: 'Riyadh HQ', kind: 'main' },
      { id: 'jeddah', name: 'Jeddah branch (DR)', kind: 'dr' },
      { id: 'riyadh-olaya', name: 'Riyadh Olaya branch', kind: 'branch' },
      { id: 'alkhobar', name: 'Alkhobar branch', kind: 'branch' },
    ],
  },
  reports: {                              // Attack Summary + After-hours (engine/reports). Schedules, SMTP relay and business hours are
    scheduler: true,                      // set by admins in the portal (state store); the SMTP password goes to secrets.json
    org_name: '',                         // reports.smtp_password (write-only). '' = "the organisation" in report headers
    catchup_h: 12,                        // a run missed while the engine was down is sent once if missed by less than this
  },
  secrets_path: '',
};

// proxy_secret: shared secret nginx sends as X-Sentra-Proxy-Secret on /api/soc/* (written by install.sh)
// m365: {tenant, client_id, client_secret} or {tenant, client_id, cert_file, key_file, key_passphrase?}
// ad: {bind_password} of the read-only AD identity-sync service account
// reports: {smtp_password} of the SMTP relay account for scheduled Attack Summary e-mails (set write-only from the portal)
// grcai_proxy_secret: sentra-grcai's proxy_secret (X-Sentra-Proxy-Secret) — only needed when compliance.sama.grc_push.enabled
const SECRET_DEFAULTS = { clickhouse: { user: '', password: '' }, ingest_tokens: {}, proxy_secret: '', m365: {}, ad: { bind_password: '' }, grcai_proxy_secret: '' };

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }

function merge(base, over) {
  if (!isObj(over)) return base;
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(base[k]) ? merge(base[k], v) : v;
  return out;
}

function readJson(file, label) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw new Error(`cannot read ${label} ${file}: ${e.message}`);
  }
  try { return JSON.parse(text); } catch (e) { throw new Error(`invalid JSON in ${label} ${file}: ${e.message}`); }
}

const ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

function validate(cfg) {
  const errs = [];
  const ids = new Set();
  if (!Array.isArray(cfg.sources)) errs.push('sources must be an array');
  else for (const [i, s] of cfg.sources.entries()) {
    if (!isObj(s)) { errs.push(`sources[${i}] must be an object`); continue; }
    if (!ID_RE.test(String(s.id || ''))) errs.push(`sources[${i}].id invalid (letters, digits, _ . - ; max 64)`);
    if (ids.has(s.id)) errs.push(`sources[${i}].id duplicate "${s.id}"`);
    ids.add(s.id);
    if (!s.type) errs.push(`sources[${i}].type missing`);
    const m = s.match || {};
    for (const ip of [].concat(m.ip || [])) if (!net.isIP(String(ip))) errs.push(`sources[${i}].match.ip invalid: ${ip}`);
    for (const c of [].concat(m.cidr || [])) {
      const [a, b] = String(c).split('/');
      const fam = net.isIP(a);
      const bits = Number(b);
      if (!fam || !Number.isInteger(bits) || bits < 0 || bits > (fam === 4 ? 32 : 128)) errs.push(`sources[${i}].match.cidr invalid: ${c}`);
    }
    if (s.type === 'relay') { // relay/sentra-relay.js: envelopes only from senders inside allowed_peers (CIDRs or IPs)
      for (const c of [].concat(s.allowed_peers || [])) {
        const [a, b] = String(c).split('/');
        const fam = net.isIP(a);
        const bits = b === undefined ? (fam === 4 ? 32 : 128) : Number(b);
        if (!fam || !Number.isInteger(bits) || bits < 0 || bits > (fam === 4 ? 32 : 128)) errs.push(`sources[${i}].allowed_peers invalid: ${c}`);
      }
      if (s.file_sources !== undefined && !isObj(s.file_sources)) errs.push(`sources[${i}].file_sources must be an object {file_type: src_id}`);
    }
  }
  const pos = (v) => Number.isFinite(v) && v > 0;
  if (!pos(cfg.retention_days)) errs.push('retention_days must be a positive number');
  if (!pos(cfg.spool_max_mb)) errs.push('spool_max_mb must be a positive number');
  if (!pos(cfg.api.port) && cfg.api.port !== 0) errs.push('api.port invalid');
  if (errs.length) throw new Error('config invalid: ' + errs.join('; '));
}

function loadConfig({ configPath, secretsPath, overrides } = {}) {
  const cfgPath = configPath || process.env.SENTRA_SIEM_CONFIG || DEFAULT_CONFIG_PATH;
  const fileCfg = readJson(cfgPath, 'config');
  let cfg = merge(DEFAULTS, fileCfg || {});
  if (overrides) cfg = merge(cfg, overrides);
  if (process.env.SENTRA_SIEM_DATA) cfg.data_dir = process.env.SENTRA_SIEM_DATA;
  const secPath = secretsPath || process.env.SENTRA_SIEM_SECRETS || cfg.secrets_path || path.join(path.dirname(cfgPath), 'secrets.json');
  let secRaw; try { secRaw = SF.read(secPath); } catch (e) { throw new Error(`cannot read secrets ${secPath}: ${e.message}`); }
  const secrets = merge(SECRET_DEFAULTS, secRaw || {});
  validate(cfg);

  if (secrets.clickhouse.user) cfg.clickhouse.user = secrets.clickhouse.user;
  Object.defineProperty(cfg.clickhouse, 'password', { value: secrets.clickhouse.password || '', enumerable: false, writable: true });
  Object.defineProperty(cfg, 'secrets', { value: secrets, enumerable: false, writable: true });
  Object.defineProperty(cfg, '_paths', { value: { config: cfgPath, secrets: secPath, config_found: !!fileCfg }, enumerable: false });
  cfg.state_dir = path.join(cfg.data_dir, 'state');
  cfg.spool_dir = path.join(cfg.data_dir, 'spool');
  return cfg;
}

module.exports = { loadConfig, DEFAULTS, VERSION, merge };
