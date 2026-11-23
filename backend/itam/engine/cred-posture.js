// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Credential security evidence (SAMA CSF 3.3.9 Cryptography, 3.3.5 Identity & Access Management; NCA ECC 2-8;
 * ISO 27001 A.8.24 / A.5.17) - what a CISO or an auditor asks for, read from the LIVE state, never asserted:
 *   - every place a credential is kept, how many records, how many are encrypted (AES-256-GCM) and how many are not
 *   - key custody: where the master key is, its file mode and owner, a key id (HMAC of the key, never the key), and that
 *     it is kept apart from the data it protects
 *   - a self-test run on request: seal / open round trip, a changed byte refused, a value moved to another record refused
 *   - how each stored login reaches its device: TLS verified or pinned, SSH host key trusted, SNMPv3 privacy, database TLS
 *   - findings with the control each one fails and the fix
 *   - on demand (admin): a disk scan proving that no stored secret appears in clear anywhere in the data directory, the
 *     audit journals or the configuration files - each secret is opened in memory, searched for, and dropped
 * Values are never returned, logged or audited.
 *   GET  {prefix}/security/credentials        operator+ (it names systems and weaknesses)
 *   POST {prefix}/security/credentials/scan   admin; audited (files, counts and hits by label - never a value)
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { createSealer } = require('./discovery/vault');
const SV = require('./secret-values');

const ALG = 'AES-256-GCM (256-bit key, 96-bit random IV per value, 128-bit tag, record id bound as AAD)';
const C = { crypto: 'SAMA CSF 3.3.9', iam: 'SAMA CSF 3.3.5', ecc: 'NCA ECC 2-8', iso: 'ISO 27001 A.8.24', isoAuth: 'ISO 27001 A.5.17' };
// collections holding sealed secrets: [name, what, field]
const STORES = [
  ['disc_credentials', 'Asset Discovery logins (SNMP, SSH, databases, LDAP, vCenter, Nutanix, CUCM, Azure, AWS, storage)', 'enc'],
  ['credentials', 'Connector credentials (Settings: vCenter, netops, private model)', 'enc'],
  ['storage_platforms', 'Storage array logins (NetApp ONTAP, HPE MSA)', 'enc'],
  ['backup_platforms', 'Backup platform API keys (NetBackup, Veeam, Cohesity)', 'enc'],
  ['virt_platforms', 'Virtualisation platform logins (vCenter, Nutanix)', 'enc'],
  ['me_config', 'ManageEngine API keys (ServiceDesk Plus, Endpoint Central)', 'enc'],
  ['cisco_support', 'Cisco Support API client secret', 'enc'],
  ['db_health_meta', 'SIEM ingest token for database health', 'enc'],
];
const SECRETISH = /^(password|pass|passwd|secret|client_secret|token|api_key|apikey|key|community|private_key|auth_password|priv_password|secret_access_key|value)$/i;
const LOOP = /^https?:\/\/(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:|\/|$)/i;

function registerCredPosture(srv, app) {
  const store = app.store, cfg = app.config || {}, dc = cfg.discovery || {};
  const keyFile = dc.vault_key_file || SV.DEFAULT_KEY;
  const secFile = process.env.SENTRA_ITAM_SECRETS || path.join(path.dirname(app.cfgPath || '/etc/sentra-itam/config.json'), 'secrets.json');
  const now = () => (app.now ? app.now() : Date.now());
  const meta = store.collection('sec_cred_scans');
  const isEnc = (e) => !!(e && typeof e === 'object' && e.iv && e.tag && e.ct);

  function keyCustody() {
    const k = { file: keyFile, exists: false, findings: [] };
    let st; try { st = fs.statSync(keyFile); } catch (e) { k.error = e.code; k.findings.push(['critical', 'The master key file is not readable (' + e.code + '): no credential can be sealed or opened']); return k; }
    k.exists = true; k.mode = (st.mode & 0o777).toString(8).padStart(3, '0'); k.owner_uid = st.uid; k.modified = new Date(st.mtimeMs).toISOString();
    k.service_uid = typeof process.getuid === 'function' ? process.getuid() : null;
    k.restricted = (st.mode & 0o077) === 0;
    try { const hex = fs.readFileSync(keyFile, 'utf8').trim(); k.bits = /^[0-9a-f]{64}$/i.test(hex) ? 256 : null; if (k.bits) k.key_id = crypto.createHmac('sha256', Buffer.from(hex, 'hex')).update('sentra-itam-key-id').digest('hex').slice(0, 16); }
    catch (e) { k.error = e.code; }
    k.apart_from_data = !path.resolve(keyFile).startsWith(path.resolve(store.dir) + path.sep);
    if (!k.restricted) k.findings.push(['critical', 'The master key file is readable by other accounts (mode ' + k.mode + ') - it must be 600']);
    if (k.bits !== 256) k.findings.push(['critical', 'The master key file does not hold a 256-bit key']);
    if (!k.apart_from_data) k.findings.push(['high', 'The master key is inside the data directory: a copy of the data carries its key']);
    return k;
  }

  function selfTest() {
    const t = { at: new Date(now()).toISOString(), alg: 'aes-256-gcm' };
    const s = createSealer({ keyFile, createKey: false, purpose: 'sentra-itam-selftest' });
    if (!s.available()) return Object.assign(t, { ok: false, reason: s.unavailableReason() });
    const v = crypto.randomBytes(24).toString('base64'), e = s.seal('probe', v);
    t.round_trip = s.unseal('probe', e) === v;
    t.ciphertext_differs = !e.ct.includes(v) && Buffer.from(e.ct, 'base64').toString('latin1').indexOf(v) < 0;
    const e2 = s.seal('probe', v); t.fresh_iv = e2.iv !== e.iv && e2.ct !== e.ct;
    const flip = Buffer.from(e.ct, 'base64'); flip[0] ^= 1;
    try { s.unseal('probe', Object.assign({}, e, { ct: flip.toString('base64') })); t.tamper_refused = false; } catch { t.tamper_refused = true; }
    try { s.unseal('other-record', e); t.move_refused = false; } catch { t.move_refused = true; }
    t.ok = t.round_trip && t.ciphertext_differs && t.fresh_iv && t.tamper_refused && t.move_refused;
    return t;
  }

  function stores() {
    const out = [];
    for (const [name, what, field] of STORES) {
      const col = store.collection(name), rows = col.all();
      let sealed = 0, plain = 0; const plainIds = [];
      for (const r of rows) {
        const hasEnc = isEnc(r[field]);
        const clear = Object.entries(r).filter(([k, v]) => SECRETISH.test(k) && typeof v === 'string' && v).map(([k]) => k);
        if (hasEnc) sealed++;
        if (clear.length) { plain++; plainIds.push(String(r.id)); }
      }
      if (!rows.length) continue;
      out.push({ store: name, what, records: rows.length, sealed, plaintext: plain, plaintext_ids: plainIds.slice(0, 20), alg: sealed ? 'AES-256-GCM' : null });
    }
    const f = SV.fileStatus(secFile, keyFile);
    out.push({ store: 'secrets.json', what: 'Service secrets file (' + secFile + ', mode ' + (f.mode || '?') + ')', records: f.entries.length,
      sealed: f.entries.filter((e) => e.state === 'sealed').length, plaintext: f.entries.filter((e) => e.state === 'plaintext').length,
      plaintext_ids: f.entries.filter((e) => e.state === 'plaintext').map((e) => e.name), by_design: f.entries.filter((e) => e.state === 'plain-by-design').map((e) => ({ name: e.name, why: e.why })),
      unopenable: f.entries.filter((e) => e.state === 'sealed-unopenable').map((e) => e.name), alg: 'AES-256-GCM', mode: f.mode || null, other_readable: !!f.other_readable, error: f.error || null });
    const ag = store.collection('agents').all(), tok = store.collection('enrol_tokens').all();
    if (ag.length || tok.length) out.push({ store: 'agents', what: 'Agent keys and enrolment tokens', records: ag.length + tok.length, sealed: 0, hashed: ag.filter((a) => a.key_hash).length + tok.filter((x) => x.hash || x.token_hash).length,
      plaintext: tok.filter((x) => typeof x.token === 'string' && x.token).length, alg: 'SHA-256 one-way hash, compared in constant time (the key itself is never stored)' });
    return out;
  }

  function transport() {
    const rows = [], V = app.discovery && app.discovery.vault;
    let list = []; try { list = V ? V.list() : []; } catch { list = []; }
    const trust = store.collection('disc_trust').all();
    for (const c of list) {
      const t = c.target || {}; let level = 'ok', how = '';
      switch (c.kind) {
        case 'snmp_v2c': level = 'bad'; how = 'SNMPv2c: the community string travels in clear on UDP 161'; break;
        case 'snmp_v3': if (t.priv_protocol === 'none') { level = 'warn'; how = 'SNMPv3 authNoPriv (' + (t.auth_protocol || 'sha').toUpperCase() + '): authenticated, but the replies are not encrypted'; } else how = 'SNMPv3 authPriv: ' + (t.auth_protocol || 'sha').toUpperCase() + ' authentication + AES-128 privacy'; break;
        case 'ssh': how = 'SSH: the password / key is sent only to hosts whose host key an administrator trusted (SHA-256 pin)'; break;
        case 'db_login': {
          const m = t.tls || 'off', eng = t.engine || 'database';
          if (m === 'off') { level = 'bad'; how = eng + ': no TLS - the login and the query results cross the network unencrypted'; }
          else if (m === 'require') { level = 'warn'; how = eng + ': TLS 1.2+ (' + (eng === 'oracle' ? 'TCPS' : 'encrypted') + '), server certificate not checked'; }
          else how = eng + ': TLS 1.2+, server certificate and name verified' + (t.ca_file ? ' against ' + t.ca_file : ' (system CAs)');
          break;
        }
        case 'storage_api': how = 'HTTPS (TLS 1.2+): certificate verified or pinned by an administrator before the login is sent'; break;
        case 'ldap': how = 'LDAPS / StartTLS, certificate verification cannot be turned off, TLS 1.2+'; break;
        case 'vcenter': case 'nutanix': how = 'HTTPS (TLS 1.2+) ' + (t.tls_fingerprint ? 'with the certificate pinned (SHA-256)' : t.ca_file ? 'verified against ' + t.ca_file : 'verified against the system CAs'); break;
        case 'cucm_axl': how = 'HTTPS AXL (TLS 1.2+), certificate verified'; break;
        case 'azure': case 'aws': how = 'HTTPS to the cloud API (TLS 1.2+), certificate verified'; break;
        case 'winrm': level = t.transport === 'http' ? 'warn' : 'ok'; how = 'WinRM over ' + (t.transport || 'https').toUpperCase() + ' - stored for future use, not used by any collector yet'; break;
        default: how = c.kind;
      }
      rows.push({ id: c.id, label: c.label, kind: c.kind, level, how, last_tested: c.last_tested ? { at: c.last_tested.at, ok: c.last_tested.ok } : null });
    }
    const tr = { ssh: { trusted: 0, pending: 0, changed: 0 }, tls: { trusted: 0, pending: 0, changed: 0 } };
    for (const x of trust) { const k = /ssh/i.test(String(x.kind || x.type || x.id)) ? 'ssh' : 'tls'; if (tr[k][x.state] != null) tr[k][x.state]++; }
    const conn = [];
    const ai = cfg.ai || {}, np = cfg.netops || {}, vc = cfg.vcenter || {};
    if (ai.private_url) conn.push({ name: 'Private AI model', url: ai.private_url, level: /^https:/i.test(ai.private_url) || LOOP.test(ai.private_url) ? 'ok' : 'bad', how: /^https:/i.test(ai.private_url) ? 'HTTPS' : LOOP.test(ai.private_url) ? 'this server only (loopback)' : 'plain HTTP across the network - the Bearer token and the prompts are readable on the wire' });
    if (np.base_url) conn.push({ name: 'Network operations feed', url: np.base_url, level: /^https:/i.test(np.base_url) || LOOP.test(np.base_url) ? 'ok' : 'bad', how: /^https:/i.test(np.base_url) ? 'HTTPS' : LOOP.test(np.base_url) ? 'this server only (loopback)' : 'plain HTTP across the network with a Bearer token' });
    if (vc.base_url) conn.push({ name: 'vCenter (legacy connector)', url: vc.base_url, level: vc.lab_mode ? 'bad' : 'ok', how: vc.lab_mode ? 'lab mode: http and unverified certificates allowed' : 'HTTPS, certificate verified' });
    const siem = dc.siem || {};
    if (siem.base_url) conn.push({ name: 'SIEM link', url: siem.base_url, level: /^https:/i.test(siem.base_url) || LOOP.test(siem.base_url) ? 'ok' : 'bad', how: LOOP.test(siem.base_url) ? 'this server only (loopback)' : /^https:/i.test(siem.base_url) ? 'HTTPS' : 'plain HTTP across the network' });
    return { credentials: rows, trust: tr, connections: conn };
  }

  function findings(k, st, tp, test) {
    const F = [], add = (sev, area, text, fix, ctl) => F.push({ sev, area, text, fix, controls: ctl });
    for (const [sev, text] of k.findings) add(sev, 'Key custody', text, 'sudo chown sentra-itam:sentra-itam ' + keyFile + ' && sudo chmod 600 ' + keyFile, [C.crypto, C.ecc, C.iso]);
    if (test && test.ok === false) add('critical', 'Encryption self-test', 'The encryption self-test did not pass' + (test.reason ? ': ' + test.reason : ''), 'Check the master key file; restore it from the key backup', [C.crypto, C.iso]);
    for (const s of st) {
      if (s.plaintext) add('high', 'Encryption at rest', s.what + ': ' + s.plaintext + ' value(s) stored in clear (' + s.plaintext_ids.join(', ') + ')', s.store === 'secrets.json' ? 'sudo node /opt/sentra-itam/install/itam-secrets.js seal' : 'Re-enter the credential on its page (it is stored sealed) - or restart sentra-itam, which re-seals legacy values', [C.crypto, C.ecc, C.iso]);
      if (s.unopenable && s.unopenable.length) add('high', 'Encryption at rest', 'secrets.json: ' + s.unopenable.join(', ') + ' sealed under a different key - cannot be opened', 'Store the value again: sudo node /opt/sentra-itam/install/itam-secrets.js set NAME', [C.crypto]);
      if (s.other_readable) add('high', 'Encryption at rest', 'secrets.json is readable by every account (mode ' + s.mode + ')', 'sudo chown root:sentra-itam ' + secFile + ' && sudo chmod 640 ' + secFile, [C.iam, C.isoAuth]);
    }
    const n = (lv, kind) => tp.credentials.filter((x) => x.level === lv && (!kind || x.kind === kind));
    if (n('bad', 'snmp_v2c').length) add('high', 'In transit', n('bad', 'snmp_v2c').length + ' SNMPv2c community login(s): the community string is sent in clear', 'Move these devices to SNMPv3 authPriv (SHA-256 + AES); keep v2c only where the device cannot do v3, read-only, ACL-restricted to the platform server', [C.crypto, C.ecc]);
    if (n('warn', 'snmp_v3').length) add('medium', 'In transit', n('warn', 'snmp_v3').length + ' SNMPv3 login(s) without privacy (authNoPriv)', 'Set the privacy protocol to AES with a privacy passphrase', [C.crypto]);
    if (n('bad', 'db_login').length) add('high', 'In transit', n('bad', 'db_login').length + ' database login(s) without TLS: ' + n('bad', 'db_login').map((x) => x.label).join(', '), 'Turn on TLS on the database listener (Oracle TCPS 2484 / SQL Server Force Encryption / MySQL require_secure_transport / PostgreSQL ssl=on), then set Encryption in transit = verify on the login', [C.crypto, C.ecc, C.iso]);
    if (n('warn', 'db_login').length) add('medium', 'In transit', n('warn', 'db_login').length + ' database login(s) encrypted but without server identity check', 'Give the CA file of the database certificate and set Encryption in transit = verify', [C.crypto]);
    if (n('warn', 'winrm').length) add('low', 'In transit', 'A WinRM credential is set to HTTP (not used yet)', 'Set transport = https before it is used', [C.crypto]);
    if (tp.trust.ssh.changed || tp.trust.tls.changed) add('high', 'Device identity', (tp.trust.ssh.changed + tp.trust.tls.changed) + ' device key(s)/certificate(s) CHANGED since they were trusted - logins to them are stopped', 'Confirm the change with the device owner, then trust the new key under Asset Discovery → Trust', [C.crypto, C.iam]);
    for (const c of tp.connections.filter((x) => x.level === 'bad')) add('high', 'In transit', c.name + ': ' + c.how, 'Serve it over HTTPS (or keep it on this server) before a token is sent to it', [C.crypto, C.ecc]);
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return F.sort((a, b) => order[a.sev] - order[b.sev]);
  }

  function build(withTest) {
    const key = keyCustody(), st = stores(), tp = transport(), test = withTest ? selfTest() : null;
    const F = findings(key, st, tp, test);
    const total = st.reduce((s, x) => s + (x.store === 'agents' ? 0 : x.records), 0), sealed = st.reduce((s, x) => s + (x.sealed || 0), 0), plain = st.reduce((s, x) => s + (x.plaintext || 0), 0);
    const out = {
      engine: 'IT Asset Management', generated_at: new Date(now()).toISOString(), algorithm: ALG,
      summary: { stored: total, sealed, plaintext: plain, by_design: st.reduce((s, x) => s + ((x.by_design || []).length), 0), logins: tp.credentials.length,
        logins_secure: tp.credentials.filter((x) => x.level === 'ok').length, logins_weak: tp.credentials.filter((x) => x.level === 'warn').length, logins_clear: tp.credentials.filter((x) => x.level === 'bad').length,
        findings: F.length, critical: F.filter((f) => f.sev === 'critical').length, high: F.filter((f) => f.sev === 'high').length },
      key, self_test: test, stores: st, transport: tp, findings: F,
      handling: [
        'Credentials are write-only: no page or API returns a stored password, key, token or community - only "set" and a 16-hex HMAC fingerprint',
        'The audit trail records who set or changed a credential and when, never the value',
        'Opened secrets are masked in every log line while in use (engine/discovery/scrub.js)',
        'Changing where a credential is sent (host, URL, port, TLS mode) requires the secret to be typed again',
        'Passwords reach the helper processes on stdin only - never on the command line or in the environment',
        'A login is sent only after the device identity checks out: SSH host key or HTTPS certificate trusted by an administrator',
      ],
      last_scan: (meta.get('last') || {}).result || null,
    };
    out.integrity = crypto.createHash('sha256').update(JSON.stringify(out)).digest('hex');
    return out;
  }

  // the secrets themselves, opened in memory for the scan only; [label, value] pairs
  function openAll() {
    const out = [], V = app.discovery && app.discovery.vault;
    let list = []; try { list = V ? V.list() : []; } catch { list = []; }
    for (const c of list) {
      let h; try { h = V.open(c.id); } catch { continue; }
      try { for (const [k, v] of Object.entries(h.secret)) if (typeof v === 'string' && v.length >= 6) out.push([c.label + ' · ' + k, v]); } finally { h.release(); }
    }
    if (app.settings && app.settings.getCredential) for (const n of ['vcenter_user', 'vcenter_pass', 'netops_token', 'private_token']) { try { const v = app.settings.getCredential(n); if (v && v.length >= 6) out.push(['Settings · ' + n, v]); } catch { /* unavailable */ } }
    try {
      const raw = JSON.parse(fs.readFileSync(secFile, 'utf8')), s = SV.sealerFor(keyFile);
      for (const [k, v] of Object.entries(raw)) if (!SV.PLAIN_BY_DESIGN[k] && SV.isSealed(v)) { const p = SV.openValue(k, v, s); if (p && p.length >= 6) out.push(['secrets.json · ' + k, p]); }
    } catch { /* not readable */ }
    return out;
  }
  function scan(who) {
    const t0 = Date.now(), secrets = openAll(), dirs = [store.dir, path.dirname(secFile)], files = [], hits = [], skipped = [];
    let bytes = 0;
    try {
      for (const d of dirs) {
        let names = []; try { names = fs.readdirSync(d); } catch { continue; }
        for (const f of names) {
          const p = path.join(d, f); let st; try { st = fs.lstatSync(p); } catch { continue; }
          if (!st.isFile() || p === keyFile) continue;
          if (st.size > 256 * 1024 * 1024) { skipped.push({ file: p, why: 'larger than 256 MB' }); continue; }
          let buf; try { buf = fs.readFileSync(p); } catch (e) { skipped.push({ file: p, why: e.code }); continue; }
          files.push(p); bytes += buf.length;
          for (const [label, v] of secrets) {
            const forms = [v, JSON.stringify(v).slice(1, -1), Buffer.from(v).toString('base64')];
            if (forms.some((x) => x.length >= 6 && buf.indexOf(x) >= 0)) hits.push({ file: p, secret: label });
          }
          buf.fill(0);
        }
      }
    } finally { for (const s of secrets) s[1] = null; }
    const result = { at: new Date(now()).toISOString(), by: who.user, secrets_checked: secrets.length, files: files.length, bytes, hits, skipped, ms: Date.now() - t0, ok: hits.length === 0 && secrets.length > 0,
      note: secrets.length ? null : 'no stored secret could be opened - nothing to search for' };
    meta.put({ id: 'last', result });
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'security.credentials.scan', target: 'credential-stores', detail: { secrets_checked: result.secrets_checked, files: result.files, hits: hits.map((h) => ({ file: h.file, secret: h.secret })) } });
    return result;
  }

  srv.route('GET', '/security/credentials', (ctx) => { ctx.need('operator'); return build(String((ctx.query || {}).selftest || '1') !== '0'); });
  srv.route('POST', '/security/credentials/scan', (ctx) => { ctx.need('admin'); return scan(ctx.who); });
  const CP = { build, scan, selfTest };
  (app.addons = app.addons || {}).credPosture = CP;   // read by the AI Cyber Security Auditor (engine/auditors.js)
  return CP;
}

module.exports = { registerCredPosture };
