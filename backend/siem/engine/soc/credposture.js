// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Credential security evidence for the SIEM (SAMA CSF 3.3.9 Cryptography, 3.3.5 IAM; NCA ECC 2-8; ISO 27001 A.8.24),
 * read from the live state, never asserted - the same report shape as IT Asset Management's /security/credentials:
 *   - secrets.json (every password, key and token the SIEM keeps): sealed or not, file mode; how many values, per area
 *   - key custody: /etc/sentra-siem-keys/secrets.key mode / owner, 256-bit, a key id (HMAC - never the key), and whether the
 *     service could replace it (it must not be able to write the key folder)
 *   - self-test: AES-256-GCM round trip, fresh IV, a changed byte refused, a different context (AAD) refused
 *   - per network device: SNMP version and privacy, API certificate pinned / verified / NOT verified, SSH host key enforced
 *   - every switch in config or secrets that weakens transport (insecure, reject_unauthorized:false, verify_tls:false,
 *     allow_insecure_auth, allow_http) is a finding with its path; syslog without TLS; ClickHouse off this host; secrets in
 *     the service environment
 *   - POST .../scan (admin): every stored value opened in memory and searched for across the state, spool index and
 *     configuration files - no value in clear on disk. Audited by file and area, never a value.
 *   GET  {P}/security/credentials        operator+
 *   POST {P}/security/credentials/scan   admin
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const SF = require('../secretfile');
const { wrap, audit, prefixOf } = require('./routeutil');

const C = { crypto: 'SAMA CSF 3.3.9', iam: 'SAMA CSF 3.3.5', ecc: 'NCA ECC 2-8', iso: 'ISO 27001 A.8.24' };
const ALG = 'AES-256-GCM (256-bit key, 96-bit random IV per write, 128-bit tag, AAD-bound) - the whole secrets.json is one sealed envelope';
const LOOP = /^https?:\/\/(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:|\/|$)/i;
const WEAK = [['insecure', true, 'certificate verification turned off'], ['reject_unauthorized', false, 'certificate verification turned off'], ['verify_tls', false, 'certificate verification turned off'],
  ['allow_insecure_auth', true, 'password allowed without TLS'], ['allow_http', true, 'plain HTTP allowed']];

function leaves(o, pre, out) {
  if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) leaves(v, pre ? pre + '.' + k : k, out);
  else if (typeof o === 'string' && o) out.push([pre, o]);
  return out;
}
function weakSwitches(o, pre, out) {
  if (!o || typeof o !== 'object') return out;
  for (const [k, v] of Object.entries(o)) {
    const p = pre ? pre + '.' + k : k, w = WEAK.find((x) => x[0] === k && v === x[1]);
    if (w) out.push({ path: p, what: w[2] });
    else if (v && typeof v === 'object') weakSwitches(v, p, out);
  }
  return out;
}
const area = (p) => String(p).split('.').slice(0, String(p).startsWith('netops.devices.') ? 3 : 1).join('.');

function register(api, deps) {
  const P = prefixOf(deps), cfg = deps.config || {}, now = deps.now || Date.now;
  const secPath = () => (cfg._paths && cfg._paths.secrets) || process.env.SENTRA_SIEM_SECRETS || '/etc/sentra-siem/secrets.json';
  const scanFile = () => path.join(cfg.state_dir || path.join(cfg.data_dir || '/var/lib/sentra-siem', 'state'), 'credential-scan.json');
  const secrets = () => { try { return SF.read(secPath()) || {}; } catch (e) { return null; } };

  function keyCustody() {
    const p = SF.keyPath(), k = { file: p, exists: false, findings: [] };
    let st; try { st = fs.statSync(p); } catch (e) { k.error = e.code; k.findings.push(['critical', 'No secrets key at ' + p + ': secrets.json is stored in clear']); return k; }
    k.exists = true; k.mode = (st.mode & 0o777).toString(8).padStart(3, '0'); k.owner_uid = st.uid; k.group_gid = st.gid; k.modified = new Date(st.mtimeMs).toISOString();
    k.restricted = (st.mode & 0o007) === 0;
    try { const key = SF.loadKey(); k.bits = key ? key.length * 8 : null; if (key) k.key_id = crypto.createHmac('sha256', key).update('sentra-siem-key-id').digest('hex').slice(0, 16); } catch (e) { k.error = e.message; }
    try { fs.accessSync(path.dirname(p), fs.constants.W_OK); k.service_can_replace = true; } catch { k.service_can_replace = false; }
    try { fs.accessSync(p, fs.constants.W_OK); k.service_can_replace = true; } catch { /* read-only for the service: as designed */ }
    k.apart_from_data = !path.resolve(p).startsWith(path.resolve(path.dirname(secPath())) + path.sep);
    if (!k.restricted) k.findings.push(['critical', 'The secrets key is readable by every account (mode ' + k.mode + ')']);
    if (k.bits !== 256) k.findings.push(['critical', 'The secrets key is not a 256-bit key']);
    if (k.service_can_replace) k.findings.push(['medium', 'The SIEM service account can write the key or its folder - it should only read it (root:sentra-siem 0440, folder 0750)']);
    if (!k.apart_from_data) k.findings.push(['high', 'The key is in the same folder as secrets.json: a copy of the folder carries its key']);
    return k;
  }

  function selfTest() {
    const t = { at: new Date(now()).toISOString(), alg: 'aes-256-gcm' };
    let key; try { key = SF.loadKey(); } catch (e) { return Object.assign(t, { ok: false, reason: e.message }); }
    if (!key) return Object.assign(t, { ok: false, reason: 'no key' });
    const aad = Buffer.from('sentra-siem-selftest|v1'), v = crypto.randomBytes(24).toString('base64');
    const seal = () => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(aad); const ct = Buffer.concat([c.update(v, 'utf8'), c.final()]); return { iv, tag: c.getAuthTag(), ct }; };
    const open = (e, a) => { const d = crypto.createDecipheriv('aes-256-gcm', key, e.iv, { authTagLength: 16 }); d.setAAD(a || aad); d.setAuthTag(e.tag); return Buffer.concat([d.update(e.ct), d.final()]).toString('utf8'); };
    const e = seal(), e2 = seal();
    t.round_trip = open(e) === v; t.ciphertext_differs = e.ct.toString('latin1').indexOf(v) < 0; t.fresh_iv = !e.iv.equals(e2.iv);
    const f = Buffer.from(e.ct); f[0] ^= 1;
    try { open({ iv: e.iv, tag: e.tag, ct: f }); t.tamper_refused = false; } catch { t.tamper_refused = true; }
    try { open(e, Buffer.from('another-context')); t.move_refused = false; } catch { t.move_refused = true; }
    t.ok = t.round_trip && t.ciphertext_differs && t.fresh_iv && t.tamper_refused && t.move_refused;
    return t;
  }

  function build(withTest) {
    const st = SF.status(secPath()), key = keyCustody(), sec = secrets(), F = [];
    const add = (sev, ar, text, fix, ctl) => F.push({ sev, area: ar, text, fix, controls: ctl });
    let fileMode = null, otherReadable = false; try { const s = fs.statSync(secPath()); fileMode = (s.mode & 0o777).toString(8).padStart(3, '0'); otherReadable = !!(s.mode & 0o007); } catch { /* missing */ }
    const lv = sec ? leaves(sec, '', []) : [], byArea = {};
    for (const [p] of lv) { const a = area(p).split('.')[0]; byArea[a] = (byArea[a] || 0) + 1; }
    const stores = [{ store: 'secrets.json', what: 'Every password, API key and token the SIEM keeps (' + secPath() + ', mode ' + (fileMode || '?') + ')', records: lv.length, sealed: st.sealed ? lv.length : 0, plaintext: st.sealed ? 0 : lv.length,
      areas: Object.entries(byArea).map(([k, n]) => ({ area: k, values: n })).sort((a, b) => b.values - a.values), alg: st.sealed ? 'AES-256-GCM' : null, mode: fileMode, other_readable: otherReadable, error: sec ? null : 'not readable' }];
    for (const [sev, text] of key.findings) add(sev, 'Key custody', text, 'sudo bash /opt/sentra-siem/install/secure-secrets.sh', [C.crypto, C.ecc, C.iso]);
    if (!st.sealed && st.exists) add('critical', 'Encryption at rest', 'secrets.json is NOT sealed: ' + lv.length + ' value(s) are stored in clear', 'sudo bash /opt/sentra-siem/install/secure-secrets.sh  (or: sudo sentra-siem-secrets seal)', [C.crypto, C.ecc, C.iso]);
    if (otherReadable) add('high', 'Encryption at rest', 'secrets.json is readable by every account (mode ' + fileMode + ')', 'sudo chmod 600 ' + secPath(), [C.iam]);
    const test = withTest ? selfTest() : null;
    if (test && test.ok === false) add('critical', 'Encryption self-test', 'The encryption self-test did not pass: ' + (test.reason || 'see the details'), 'Restore the key from the keys backup (zyb-restore keys)', [C.crypto]);

    // network devices
    const devs = [], D = (sec && sec.netops && sec.netops.devices) || {};
    for (const [id, c] of Object.entries(D)) {
      const row = { id, items: [] };
      if (c.snmp) { const v = String(c.snmp.version || ''); row.items.push(v === '3' ? (c.snmp.privKey ? { what: 'SNMPv3 authPriv (' + String(c.snmp.authProtocol || 'sha').toUpperCase() + ' + ' + String(c.snmp.privProtocol || 'aes').toUpperCase() + ')', level: 'ok' } : { what: 'SNMPv3 ' + (c.snmp.authKey ? 'authNoPriv - replies not encrypted' : 'noAuth'), level: 'warn' }) : { what: 'SNMPv' + (v || '2c') + ' - community string in clear', level: 'bad' }); }
      if (c.api) { const tl = c.api.tls || {}; row.items.push(tl.insecure ? { what: 'API over HTTPS with the certificate NOT verified', level: 'bad' } : tl.fingerprint256 ? { what: 'API over HTTPS, certificate pinned (SHA-256)', level: 'ok' } : { what: 'API over HTTPS, certificate verified' + (tl.ca ? ' against the given CA' : ' (system CAs)'), level: 'ok' }); }
      if (c.ssh) row.items.push({ what: 'SSH, host key enforced (trusted by an administrator before any login)', level: 'ok' });
      if (c.ssh_write) row.items.push({ what: c.ssh_write.pam ? 'Change login checked out from PAM per approved task (not stored)' : 'Change login stored sealed, used for approved tasks only', level: 'ok' });
      row.level = row.items.some((x) => x.level === 'bad') ? 'bad' : row.items.some((x) => x.level === 'warn') ? 'warn' : 'ok';
      devs.push(row);
    }
    const v2 = devs.filter((d) => d.items.some((x) => /community string in clear/.test(x.what)));
    if (v2.length) add('high', 'In transit', v2.length + ' network device(s) polled with SNMPv1/v2c: ' + v2.map((d) => d.id).slice(0, 12).join(', '), 'Move them to SNMPv3 authPriv; keep v2c only read-only and ACL-restricted to the platform server where v3 is impossible', [C.crypto, C.ecc]);
    const np = devs.filter((d) => d.items.some((x) => /authNoPriv|noAuth/.test(x.what)));
    if (np.length) add('medium', 'In transit', np.length + ' device(s) on SNMPv3 without privacy', 'Add an AES privacy key', [C.crypto]);

    // weakening switches anywhere in config or secrets (secrets are walked for the switch names only, never values)
    const weak = weakSwitches(cfg, 'config', []).concat(sec ? weakSwitches(sec, 'secrets', []) : []);
    for (const w of weak) add('high', 'In transit', w.path + ': ' + w.what, 'Turn the switch off and pin the certificate (Trust & pin) instead', [C.crypto, C.ecc]);

    const conn = [];
    const sy = cfg.syslog || {};
    conn.push({ name: 'Syslog in (TLS 6514)', level: sy.tls && sy.tls.enabled ? 'ok' : 'warn', how: sy.tls && sy.tls.enabled ? 'TLS 1.2+' + (sy.tls.request_cert ? ' with client certificates' : '') : 'off - devices send syslog over UDP/TCP 514 in clear (log content, no passwords)' });
    if (!(sy.tls && sy.tls.enabled)) add('medium', 'In transit', 'Syslog is received over UDP/TCP without TLS', 'Turn on syslog TLS (port 6514) and point the devices that support it there (FortiGate, Palo Alto, Linux rsyslog, Windows agent already use TLS)', [C.crypto]);
    const chu = (cfg.clickhouse && cfg.clickhouse.url) || '';
    conn.push({ name: 'ClickHouse (event store)', level: LOOP.test(chu) || /^https:/i.test(chu) ? 'ok' : 'bad', how: LOOP.test(chu) ? 'this server only (loopback)' : /^https:/i.test(chu) ? 'HTTPS' : 'plain HTTP across the network with the database password' });
    if (!LOOP.test(chu) && !/^https:/i.test(chu)) add('high', 'In transit', 'ClickHouse is reached over plain HTTP off this host', 'Use https:// or keep ClickHouse on 127.0.0.1', [C.crypto]);
    const envKeys = ['ANTHROPIC_API_KEY'].filter((k) => process.env[k]);
    const proxyCred = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'].some((k) => /\/\/[^/@]+:[^/@]+@/.test(process.env[k] || ''));
    if (envKeys.length) add('low', 'Encryption at rest', 'Secret in the service environment: ' + envKeys.join(', '), 'Store it with: sudo sentra-siem-secrets set netops.anthropic_api_key  and remove it from /etc/default/sentra-siem', [C.crypto]);
    if (proxyCred) add('medium', 'Encryption at rest', 'The outbound proxy password is in the service environment (/etc/default/sentra-siem, 0640)', 'Use a proxy that authenticates the server by IP, or a proxy account with no other rights', [C.iam]);
    const ok = (lv2) => devs.filter((d) => d.level === lv2).length;
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    F.sort((a, b) => order[a.sev] - order[b.sev]);
    let last = null; try { last = JSON.parse(fs.readFileSync(scanFile(), 'utf8')); } catch { /* never scanned */ }
    const out = {
      engine: 'SIEM', generated_at: new Date(now()).toISOString(), algorithm: ALG,
      summary: { stored: lv.length, sealed: st.sealed ? lv.length : 0, plaintext: st.sealed ? 0 : lv.length, by_design: 0, logins: devs.length, logins_secure: ok('ok'), logins_weak: ok('warn'), logins_clear: ok('bad'),
        findings: F.length, critical: F.filter((f) => f.sev === 'critical').length, high: F.filter((f) => f.sev === 'high').length },
      key, self_test: test, stores, transport: { devices: devs, connections: conn }, findings: F,
      handling: [
        'Credentials are write-only: the API answers "set" / "certificate pinned" / the SNMP version, never a value',
        'The audit trail records which fields were set and by whom, never the values',
        'Device CLI output, SMTP errors and ManageEngine logs are scrubbed of secrets before they are stored',
        'Passwords reach the SSH / WinRM / PAM helpers on stdin with a minimal environment - never on the command line',
        'SSH logins only to hosts whose host key an administrator trusted; WinRM over HTTPS only to a pinned certificate, with message encryption on top',
        'LDAP binds only over LDAPS / StartTLS with certificate verification that cannot be turned off',
      ],
      limitations: [
        'The key protects copies, backups and stolen disks. The running service can read both the key and the file - an attacker in control of the service account can read the secrets.',
        'Genian NAC accepts its API key only as a URL parameter (vendor API) - it travels inside HTTPS but can appear in the Genian server\'s own access log.',
      ],
      last_scan: last,
    };
    out.integrity = crypto.createHash('sha256').update(JSON.stringify(out)).digest('hex');
    return out;
  }

  function scan(user) {
    const t0 = Date.now(), sec = secrets(), vals = (sec ? leaves(sec, '', []) : []).filter(([, v]) => v.length >= 8);
    const dirs = [cfg.state_dir, path.dirname(secPath()), cfg.data_dir].filter(Boolean), seen = new Set(), files = [], hits = [], skipped = [];
    let bytes = 0;
    try {
      for (const d of dirs) {
        let names = []; try { names = fs.readdirSync(d); } catch { continue; }
        for (const n of names) {
          const p = path.join(d, n); if (seen.has(p)) continue; seen.add(p);
          let st; try { st = fs.lstatSync(p); } catch { continue; }
          if (!st.isFile() || p === SF.keyPath()) continue;
          if (st.size > 256 * 1024 * 1024) { skipped.push({ file: p, why: 'larger than 256 MB' }); continue; }
          let buf; try { buf = fs.readFileSync(p); } catch (e) { skipped.push({ file: p, why: e.code }); continue; }
          files.push(p); bytes += buf.length;
          for (const [k, v] of vals) { if ([v, JSON.stringify(v).slice(1, -1), Buffer.from(v).toString('base64')].some((x) => buf.indexOf(x) >= 0)) hits.push({ file: p, secret: area(k) + ' · ' + k.split('.').pop() }); }
          buf.fill(0);
        }
      }
    } finally { for (const x of vals) x[1] = null; }
    const r = { at: new Date(now()).toISOString(), by: user, secrets_checked: vals.length, files: files.length, bytes, hits, skipped, ms: Date.now() - t0, ok: hits.length === 0 && vals.length > 0, note: vals.length ? null : 'no stored value could be opened - nothing to search for' };
    try { fs.writeFileSync(scanFile(), JSON.stringify(r), { mode: 0o600 }); } catch { /* reported in the answer only */ }
    return r;
  }

  api.route('GET', `${P}/security/credentials`, wrap(deps, 'operator', async (ctx) => {
    const r = build(String((ctx.query || {}).selftest || '1') !== '0');
    audit(ctx, 'security.credentials.view', 'credential-stores', { findings: r.findings.length });
    return ctx.ok(r);
  }));
  api.route('POST', `${P}/security/credentials/scan`, wrap(deps, 'admin', async (ctx) => {
    const r = scan(ctx.user);
    audit(ctx, 'security.credentials.scan', 'credential-stores', { secrets_checked: r.secrets_checked, files: r.files, hits: r.hits });
    return ctx.ok(r);
  }));
}

module.exports = { register, _leaves: leaves, _weakSwitches: weakSwitches };
