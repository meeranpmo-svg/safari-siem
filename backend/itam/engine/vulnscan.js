// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Vulnerability scans of the organisation's INTERNAL network with Greenbone / OpenVAS (Greenbone Community Edition, installed
 * by the administrators beside the platform). The platform drives gvmd over GMP (engine/gmp.js: a fixed list of commands) and reads the
 * results back as findings with CVEs, severity and the fix.
 *
 * A scan sends probes into the network, so it is a change to systems and goes through four-eyes approval:
 *   1. an administrator sets the INTERNAL SCAN SCOPE: the private (RFC 1918) ranges that may ever be scanned, and exclusions
 *      (fragile devices, OT, third-party kit). A public address can never be in the scope.
 *   2. an operator REQUESTS a scan: targets inside the scope (at most MAX_HOSTS addresses), the profile, a time window (at most
 *      MAX_WINDOW_H hours, starting within 30 days) and the reason;
 *   3. a different named person APPROVES it (app.approveGate 'eng:pentest'; never the requester, never a service / AI identity);
 *   4. the platform starts it in Greenbone when the window opens and STOPS it when the window ends, whatever its progress -
 *      the partial results are still imported and the scan says it was cut short.
 * Findings (host × port × NVT) carry a lifecycle across scans: new / open, FIXED only when a later scan that covered the host
 * no longer reports it (never because someone said so), RISK ACCEPTED until a date when requested with a reason and approved
 * by a different person. Results below the minimum quality of detection, log-level results and overridden false positives
 * are dropped AND counted. Vulnerability details name internal hosts: operators only.
 *
 *   GET    /vulnscan                         operator  scope, connection, scans, open findings by severity, top hosts
 *   GET    /vulnscan/findings?status=&sev=&host=&q=   operator
 *   GET    /vulnscan/findings/:id            operator  one finding with its history
 *   GET    /vulnscan/scans/:id               operator  one scan with its results summary
 *   GET    /vulnscan/export                  operator  open findings as CSV                                  audited
 *   PUT    /vulnscan/config                  admin     {socket | host+port+pin, username, password?, scan_config?, port_list?, scanner?, min_qod?}  audited
 *   DELETE /vulnscan/config                  admin                                                                  audited
 *   PUT    /vulnscan/scope                   admin     {allowed[], exclude[]}                                         audited
 *   POST   /vulnscan/test                    admin     step-by-step connection check with the fix for the first failure
 *   POST   /vulnscan/scans                   operator  {name, targets[], exclude[], profile, window_start, window_end, reason}  audited
 *   POST   /vulnscan/scans/:id/approve       approver  four-eyes                                                     audited
 *   POST   /vulnscan/scans/:id/reject        approver  {note}                                                        audited
 *   POST   /vulnscan/scans/:id/cancel        operator  the requester or an admin; a running scan is stopped          audited
 *   POST   /vulnscan/findings/:id/owner      operator  {owner}                                                       audited
 *   POST   /vulnscan/findings/:id/accept-risk     operator {reason, until}                                         audited
 *   POST   /vulnscan/findings/:id/risk-decision   approver {decision: approve|reject, note?}  not the requester    audited
 */
const crypto = require('node:crypto');
const IP = require('./discovery/ipv4');
const G = require('./gmp');
const { guardOf } = require('./errors');

const DAY = 86400000, HOUR = 3600000, MAX_HOSTS = 4096, MAX_WINDOW_H = 12, MAX_RESULTS = 20000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || '').trim());
const s = (v, max = 400) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, max);
const SYS = { user: 'system:vulnscan', role: 'system', ip: '' };
// Greenbone's built-in ids (the same on every installation)
const PROFILES = {
  full: { name: 'Full and fast', config: 'daba56c8-73ec-11df-a475-002264764cea' },
  discovery: { name: 'Discovery (hosts and services only)', config: '8715c877-47a0-438d-98a3-27c7a6ab2196' },
};
const DEF = { port_list: '33d0cd82-57c6-11e1-8ed1-406186ea4fc5', scanner: '08b69003-5fc2-4037-a479-93b440211c73', min_qod: 70 };
const SEVS = ['critical', 'high', 'medium', 'low'];
const band = (score) => (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low');

// "key=value|key=value" NVT tags
function tags(t) { const o = {}; for (const part of String(t || '').split('|')) { const i = part.indexOf('='); if (i > 0) o[part.slice(0, i).trim()] = part.slice(i + 1).trim(); } return o; }

// a Greenbone report → hosts scanned and findings; what is dropped is counted, never silently lost
function parseReport(resp, minQod) {
  const outer = G.kid(resp, 'report'), rep = G.kid(outer, 'report') || outer;
  if (!rep) throw new Error('the Greenbone answer holds no report');
  const hosts = G.kids(rep, 'host').map((h) => G.txt(h, 'ip')).filter((x) => IP.parseIp(x) !== null);
  const dropped = { log: 0, false_positive: 0, low_qod: 0 }, findings = [];
  for (const r of G.kids(G.kid(rep, 'results'), 'result')) {
    const hn = G.kid(r, 'host'), host = G.txt(hn), nvt = G.kid(r, 'nvt') || { attrs: {}, children: [], text: '' };
    const score = Number(G.txt(r, 'severity')), qod = Number(G.txt(G.kid(r, 'qod'), 'value') || 0);
    if (score < 0) { dropped.false_positive++; continue; }
    if (!(score > 0)) { dropped.log++; continue; }
    if (qod && qod < minQod) { dropped.low_qod++; continue; }
    if (IP.parseIp(host) === null) continue;
    const tg = tags(G.txt(nvt, 'tags')), sol = G.kid(nvt, 'solution');
    const cves = G.kids(G.kid(nvt, 'refs'), 'ref').filter((x) => norm(x.attrs.type) === 'cve').map((x) => s(x.attrs.id, 30))
      .concat(String(G.txt(nvt, 'cve') || '').split(/[,\s]+/).filter((x) => /^CVE-\d{4}-\d+$/.test(x)));
    const port = s(G.txt(r, 'port'), 40) || 'general', oid = s(nvt.attrs.oid, 80);
    findings.push({ host, hostname: s(G.txt(hn, 'hostname'), 120), port, oid, name: s(G.txt(nvt, 'name') || G.txt(r, 'name'), 240), family: s(G.txt(nvt, 'family'), 80),
      score: Math.round(score * 10) / 10, severity: band(score), qod, cves: [...new Set(cves)].slice(0, 40),
      summary: s(tg.summary, 1500), insight: s(tg.insight, 1500), impact: s(tg.impact, 1000), affected: s(tg.affected, 800), detection: s(tg.vuldetect, 800),
      solution: s((sol && sol.text) || tg.solution, 2000), solution_type: s((sol && sol.attrs.type) || tg.solution_type, 40), evidence: s(G.txt(r, 'description'), 2000) });
    if (findings.length >= MAX_RESULTS) break;
  }
  return { hosts: [...new Set(hosts.concat(findings.map((f) => f.host)))], findings, dropped, truncated: findings.length >= MAX_RESULTS };
}

function createVulnScan(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now, iso = (t) => new Date(t == null ? now() : t).toISOString();
  const c = (n) => store.collection(n);
  const cfgCol = () => c('vulnscan'), scans = () => c('vulnscan_scans'), results = () => c('vulnscan_results'), finds = () => c('vulnscan_findings');
  const L = app.log || { info() {}, warn() {}, error() {}, every() {} };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const human = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const dc = (app.config && app.config.discovery) || {};
  let S0 = null;
  const sealer = () => S0 || (S0 = opts.sealer || require('./discovery/vault').createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-vulnscan' }));
  // a password stored with itam-secrets.js set greenbone_password (stdin, sealed in secrets.json) - used when none was entered on the page
  const filePw = opts.filePassword || (() => { try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'greenbone_password', dc.vault_key_file)(); } catch (e) { return ''; /* no secrets file: the page password is the only source */ } });
  const connectFn = opts.connect || G.openGmp;

  const cfg = () => cfgCol().get('cfg') || null;
  const scope = () => cfgCol().get('scope') || { allowed: [], exclude: [] };
  const state = () => cfgCol().get('state') || { id: 'state' };
  const setState = (patch) => cfgCol().put(Object.assign({}, state(), patch, { id: 'state' }));
  function connSummary() {
    const x = cfg();
    return { configured: !!x, via: x ? (x.socket ? 'socket ' + x.socket : x.host + ':' + x.port) : null, username: x ? x.username : null, password: x ? (x.enc ? 'entered on the page (sealed)' : filePw() ? 'from secrets.json (sealed)' : 'not set') : null,
      pinned: !!(x && x.pin), scan_config: x ? x.scan_config || null : null, port_list: x ? x.port_list : null, min_qod: x ? x.min_qod : DEF.min_qod, last_test: state().last_test || null, by: x ? x.by : null, at: x ? x.at : null };
  }

  /* ---- configuration and scope (admin) */
  function setConfig(b, who) {
    human(who, 'sets the Greenbone connection');
    if (!b.socket && !b.host) throw httpErr(400, 'socket or host is required: the gvmd socket path or the gvmd host');
    if (b.host && !b.pin) throw httpErr(400, 'pin is required with host: gvmd\'s certificate is self-signed - paste its SHA-256 fingerprint (the test shows it)');
    const cur = cfg() || {};
    const rec = { id: 'cfg', socket: b.socket || null, host: b.socket ? null : b.host, port: b.socket ? null : (b.port || 9390), pin: b.socket ? null : String(b.pin || '').replace(/:/g, '').toLowerCase(),
      username: b.username, enc: b.password ? sealer().seal('gvm', b.password) : (same(cur.username, b.username) ? cur.enc || null : null),
      scan_config: b.scan_config || null, port_list: b.port_list || DEF.port_list, scanner: b.scanner || DEF.scanner, min_qod: b.min_qod == null ? DEF.min_qod : b.min_qod, by: who.user, at: iso() };
    cfgCol().put(rec);
    audit(who, 'vulnscan.config', 'greenbone', { via: rec.socket ? 'socket' : rec.host + ':' + rec.port, username: rec.username, password_changed: !!b.password, min_qod: rec.min_qod });
    return connSummary();
  }
  function deleteConfig(who) {
    human(who, 'removes the Greenbone connection');
    const had = !!cfg(); cfgCol().remove('cfg');
    audit(who, 'vulnscan.config.delete', 'greenbone', { had });
    return connSummary();
  }
  function parseList(list, field) {
    return (list || []).map((t) => { try { return IP.parseTarget(t); } catch (e) { throw httpErr(400, field + ': ' + e.message); } });
  }
  function setScope(b, who) {
    human(who, 'sets the internal scan scope');
    const allowed = parseList(b.allowed, 'allowed'), exclude = parseList(b.exclude, 'exclude');
    for (const r of allowed) if (!IP.isPrivate(r.first) || !IP.isPrivate(r.last) || r.count > 1 << 24) throw httpErr(400, 'allowed: ' + r.text + ' is not an internal (RFC 1918) range - only private addresses can be in the internal scan scope');
    const prev = scope();
    cfgCol().put({ id: 'scope', allowed: allowed.map((r) => r.text), exclude: exclude.map((r) => r.text), by: who.user, at: iso() });
    audit(who, 'vulnscan.scope', 'scope', { allowed: allowed.map((r) => r.text), exclude: exclude.map((r) => r.text), previous: { allowed: prev.allowed, exclude: prev.exclude } });
    return scope();
  }

  /* ---- the GMP session */
  function password(x) {
    if (x.enc) { try { return sealer().unseal('gvm', x.enc); } catch (e) { throw httpErr(409, 'the stored Greenbone password could not be unsealed - enter it again'); } }
    const p = filePw(); if (p) return p;
    throw httpErr(409, 'no Greenbone password: enter it in the connection settings');
  }
  async function session(fn) {
    const x = cfg(); if (!x) throw httpErr(409, 'Greenbone is not connected: an admin sets the connection first');
    const pw = password(x);
    const g = await connectFn({ socket: x.socket, host: x.host, port: x.port, pin: x.pin, timeoutMs: opts.timeoutMs || 60000 });
    try {
      await g.send('authenticate', '<authenticate><credentials><username>' + G.xesc(x.username) + '</username><password>' + G.xesc(pw) + '</password></credentials></authenticate>');
      return await fn(g, x);
    } finally { g.close(); }
  }

  /* ---- step-by-step connection check (the integration doctor) */
  async function test(who) {
    human(who, 'tests the Greenbone connection');
    const steps = [], add = (step, status, detail, fix) => steps.push({ step, status, detail: s(detail, 300), fix: fix || '' });
    const x = cfg();
    const finish = () => { const r = { ok: !steps.some((t) => t.status === 'fail'), steps, at: iso() }; setState({ last_test: { ok: r.ok, at: r.at, failed: (steps.find((t) => t.status === 'fail') || {}).step || null } }); audit(who, 'vulnscan.test', 'greenbone', { ok: r.ok, failed: (steps.find((t) => t.status === 'fail') || {}).step || null }); return r; };
    if (!x) { add('Connection settings', 'fail', 'not set', 'Enter the gvmd socket path (or host, port and fingerprint) and the platform\'s Greenbone user.'); return finish(); }
    add('Connection settings', 'ok', x.socket ? 'gvmd socket ' + x.socket : 'gvmd at ' + x.host + ':' + x.port + ' (pinned)');
    let pw; try { pw = password(x); add('Password', 'ok', x.enc ? 'entered on the page (sealed)' : 'from secrets.json (sealed)'); } catch (e) { add('Password', 'fail', e.message, 'Enter the password of the Greenbone user in the connection settings.'); return finish(); }
    let g;
    try { g = await connectFn({ socket: x.socket, host: x.host, port: x.port, pin: x.pin, timeoutMs: 20000 }); add('Reach gvmd', 'ok', 'connected'); }
    catch (e) {
      const fix = e.code === 'EPIN' ? 'If this is your Greenbone server, paste the fingerprint ' + e.fingerprint + ' as the pin.' : e.code === 'ENOENT' ? 'The socket does not exist: is Greenbone running, and is its socket shared with this server at that path?'
        : e.code === 'EACCES' ? 'The platform may not open the socket: give the sentra-itam group read and write access to the gvmd socket.' : e.code === 'ECONNREFUSED' ? 'Nothing listens there: start Greenbone or check the host and port.' : 'Check that Greenbone is running and the address is right.';
      add('Reach gvmd', 'fail', e.message, fix); return finish();
    }
    try {
      try { await g.send('authenticate', '<authenticate><credentials><username>' + G.xesc(x.username) + '</username><password>' + G.xesc(pw) + '</password></credentials></authenticate>'); add('Log in', 'ok', 'as ' + x.username); }
      catch (e) { add('Log in', 'fail', e.message, 'Wrong user name or password for Greenbone: reset it (sudo docker compose -p greenbone exec -u gvmd gvmd gvmd --user=' + x.username + ' --new-password=…) and enter it again.'); return finish(); }
      const v = await g.send('get_version', '<get_version/>'); add('Version', 'ok', 'GMP ' + G.txt(v, 'version'));
      const sc = await g.send('get_scan_configs', '<get_scan_configs/>'), ids = G.kids(sc, 'config').map((n) => n.attrs.id);
      const want = [x.scan_config, PROFILES.full.config].filter(Boolean);
      if (want.every((id) => ids.includes(id))) add('Scan configuration', 'ok', ids.length + ' configuration(s), Full and fast present');
      else add('Scan configuration', 'fail', ids.length ? 'the configuration to use is not there' : 'no scan configuration yet', 'Greenbone is still loading its feed (the first start takes 30 minutes or more): wait, then test again.');
      const pl = await g.send('get_port_lists', '<get_port_lists/>');
      if (G.kids(pl, 'port_list').some((n) => n.attrs.id === x.port_list)) add('Port list', 'ok', 'present'); else add('Port list', 'fail', 'port list ' + x.port_list + ' not found', 'Leave the port list empty (the default "All IANA assigned TCP") or pick one Greenbone has.');
      const sn = await g.send('get_scanners', '<get_scanners/>');
      if (G.kids(sn, 'scanner').some((n) => n.attrs.id === x.scanner)) add('Scanner', 'ok', 'OpenVAS scanner present'); else add('Scanner', 'fail', 'scanner ' + x.scanner + ' not found', 'Check the Greenbone installation: the OpenVAS scanner container must be running.');
      const sp = scope();
      add('Internal scan scope', sp.allowed.length ? 'ok' : 'warn', sp.allowed.length ? sp.allowed.join(', ') : 'no range may be scanned yet', sp.allowed.length ? '' : 'Set the internal scan scope (the private ranges that may be scanned) before requesting a scan.');
    } catch (e) { add('Read Greenbone', 'fail', e.message, 'Greenbone answered unexpectedly: check its logs (the gvmd log).'); }
    finally { g.close(); }
    return finish();
  }

  /* ---- scans */
  const scanOut = (x) => Object.assign({}, x, { gvm: undefined });
  function nextId() { const n = scans().all().length + 1; let id; do { id = 'VS-' + String(n).padStart(4, '0') + '-' + crypto.randomBytes(2).toString('hex'); } while (scans().get(id)); return id; }
  function request(b, who) {
    human(who, 'requests a scan');
    const sp = scope(); if (!sp.allowed.length) throw httpErr(409, 'no internal scan scope yet: an admin sets the ranges that may be scanned first');
    const t = parseList(b.targets, 'targets'), ex = parseList(b.exclude, 'exclude'), allowed = parseList(sp.allowed, 'scope');
    for (const r of t) if (!allowed.some((a) => r.first >= a.first && r.last <= a.last)) throw httpErr(400, 'targets: ' + r.text + ' is outside the internal scan scope (' + sp.allowed.join(', ') + ')');
    let hosts; try { hosts = IP.expand(t, ex.concat(parseList(sp.exclude, 'scope exclusions')), { max: MAX_HOSTS }); } catch (e) { throw httpErr(400, 'targets: more than ' + MAX_HOSTS + ' addresses - split the scan'); }
    if (!hosts.length) throw httpErr(400, 'targets: nothing left to scan after the exclusions');
    const ws = Date.parse(b.window_start), we = Date.parse(b.window_end);
    if (!(we > ws)) throw httpErr(400, 'window_end must be after window_start');
    if (we - ws > MAX_WINDOW_H * HOUR) throw httpErr(400, 'window_end: a window is at most ' + MAX_WINDOW_H + ' hours');
    if (we <= now()) throw httpErr(400, 'window_end is in the past');
    if (ws > now() + 30 * DAY) throw httpErr(400, 'window_start must be within 30 days');
    const rec = { id: nextId(), name: b.name, targets: t.map((r) => r.text), exclude: ex.map((r) => r.text), scope_exclude: sp.exclude.slice(), hosts: hosts.length, profile: b.profile || 'full',
      window_start: iso(ws), window_end: iso(we), reason: b.reason, state: 'requested', requested_by: who.user, requested_at: iso(), history: [{ at: iso(), by: who.user, what: 'requested' }] };
    scans().put(rec);
    audit(who, 'vulnscan.scan.request', rec.id, { targets: rec.targets, exclude: rec.exclude, hosts: rec.hosts, profile: rec.profile, window: [rec.window_start, rec.window_end] });
    return scanOut(rec);
  }
  function getScan(id) { const x = scans().get(id); if (!x) throw httpErr(404, 'no scan ' + id); return x; }
  function step(x, by, what, patch) { const r = Object.assign({}, x, patch, { history: (x.history || []).concat([{ at: iso(), by, what }]).slice(-40) }); scans().put(r); return r; }
  function approve(id, who) {
    human(who, 'approves a scan');
    const x = getScan(id);
    if (x.state !== 'requested') throw httpErr(409, id + ' is ' + x.state + ' - only a requested scan can be approved');
    if (same(x.requested_by, who.user)) throw httpErr(403, 'four-eyes: the person who requested the scan cannot approve it');
    if (Date.parse(x.window_end) <= now()) throw httpErr(409, id + '\'s window has already ended - request it again with a new window');
    const r = step(x, who.user, 'approved', { state: 'approved', approved_by: who.user, approved_at: iso() });
    audit(who, 'vulnscan.scan.approve', id, { requested_by: x.requested_by, targets: x.targets, window: [x.window_start, x.window_end] });
    return scanOut(r);
  }
  function reject(id, b, who) {
    human(who, 'rejects a scan');
    const x = getScan(id);
    if (x.state !== 'requested') throw httpErr(409, id + ' is ' + x.state + ' - only a requested scan can be rejected');
    const r = step(x, who.user, 'rejected: ' + b.note, { state: 'rejected', decided_by: who.user, decision_note: b.note });
    audit(who, 'vulnscan.scan.reject', id, { note: b.note.slice(0, 200) });
    return scanOut(r);
  }
  async function cancel(id, b, who) {
    human(who, 'cancels a scan');
    const x = getScan(id);
    if (!same(x.requested_by, who.user) && who.role !== 'admin') throw httpErr(403, 'only the requester or an admin can cancel ' + id);
    if (['requested', 'approved'].includes(x.state)) {
      const r = step(x, who.user, 'cancelled' + (b.note ? ': ' + b.note : ''), { state: 'cancelled' });
      audit(who, 'vulnscan.scan.cancel', id, { was: x.state }); return scanOut(r);
    }
    if (x.state === 'running') {
      await session((g) => g.send('stop_task', '<stop_task task_id="' + G.xesc(x.gvm.task) + '"/>'));
      const r = step(x, who.user, 'stop requested' + (b.note ? ': ' + b.note : ''), { state: 'stopping', stop_reason: 'cancelled by ' + who.user });
      audit(who, 'vulnscan.scan.cancel', id, { was: 'running' }); return scanOut(r);
    }
    throw httpErr(409, id + ' is ' + x.state + ' - nothing to cancel');
  }

  /* ---- the background job: start approved scans in their window, follow running ones, stop at the window's end */
  async function launch(x) {
    const p = PROFILES[x.profile] || PROFILES.full;
    const gvm = await session(async (g, cf) => {
      const tg = await g.send('create_target', '<create_target><name>' + G.xesc('Zyberon ' + x.id + ' ' + x.name) + '</name><hosts>' + G.xesc(x.targets.join(',')) + '</hosts>'
        + '<exclude_hosts>' + G.xesc(x.exclude.concat(x.scope_exclude || []).join(',')) + '</exclude_hosts><port_list id="' + G.xesc(cf.port_list) + '"/><alive_tests>ICMP, TCP-ACK Service &amp; ARP Ping</alive_tests></create_target>');
      const tk = await g.send('create_task', '<create_task><name>' + G.xesc('Zyberon ' + x.id + ' ' + x.name) + '</name><comment>' + G.xesc('Requested by ' + x.requested_by + ', approved by ' + x.approved_by + ', window ' + x.window_start + ' to ' + x.window_end) + '</comment>'
        + '<config id="' + G.xesc(x.profile === 'full' && cf.scan_config ? cf.scan_config : p.config) + '"/><target id="' + G.xesc(tg.attrs.id) + '"/><scanner id="' + G.xesc(cf.scanner) + '"/></create_task>');
      const st = await g.send('start_task', '<start_task task_id="' + G.xesc(tk.attrs.id) + '"/>');
      return { target: tg.attrs.id, task: tk.attrs.id, report: G.txt(st, 'report_id') };
    });
    step(x, SYS.user, 'started in Greenbone', { state: 'running', started_at: iso(), gvm, progress: 0 });
    audit(SYS, 'vulnscan.scan.start', x.id, { approved_by: x.approved_by, hosts: x.hosts });
  }
  async function follow(x) {
    const t = await session((g) => g.send('get_tasks', '<get_tasks task_id="' + G.xesc(x.gvm.task) + '"/>'));
    const task = G.kid(t, 'task'), status = G.txt(task, 'status'), progress = Number(G.txt(task, 'progress')) || 0;
    const rep = (G.kid(G.kid(task, 'last_report'), 'report') || G.kid(G.kid(task, 'current_report'), 'report') || { attrs: {} }).attrs.id || x.gvm.report;
    if (status === 'Done' || status === 'Stopped' || status === 'Interrupted') return importReport(x, rep, status);
    if (Date.parse(x.window_end) <= now() && x.state === 'running') {
      await session((g) => g.send('stop_task', '<stop_task task_id="' + G.xesc(x.gvm.task) + '"/>'));
      step(x, SYS.user, 'stopped: the approved window ended at ' + Math.max(0, progress) + '%', { state: 'stopping', stop_reason: 'the approved window ended', progress });
      audit(SYS, 'vulnscan.scan.window-stop', x.id, { progress });
      return;
    }
    scans().put(Object.assign({}, x, { progress: Math.max(0, progress), gvm_status: s(status, 40) }));
  }
  async function importReport(x, reportId, status) {
    const cf = cfg(), minQod = cf ? cf.min_qod : DEF.min_qod;
    const resp = await session((g) => g.send('get_reports', '<get_reports report_id="' + G.xesc(reportId) + '" details="1" ignore_pagination="1" filter="' + G.xesc('apply_overrides=1 min_qod=0 levels=chmlgf rows=-1 first=1') + '"/>'));
    const r = parseReport(resp, minQod);
    const counts = { critical: 0, high: 0, medium: 0, low: 0 }; for (const f of r.findings) counts[f.severity]++;
    results().put({ id: x.id, findings: r.findings, hosts: r.hosts, at: iso() });
    const life = lifecycle(x, r);
    const done = status === 'Done' && x.state !== 'stopping' ? 'done' : 'stopped';
    step(x, SYS.user, (done === 'done' ? 'finished' : 'stopped (' + (x.stop_reason || status) + ')') + ': ' + r.findings.length + ' finding(s) on ' + r.hosts.length + ' host(s)',
      { state: done, finished_at: iso(), progress: done === 'done' ? 100 : x.progress, partial: done !== 'done', counts, hosts_scanned: r.hosts.length, dropped: r.dropped, truncated: r.truncated, new_findings: life.added, fixed_findings: life.fixed });
    audit(SYS, 'vulnscan.scan.import', x.id, { status, findings: r.findings.length, hosts: r.hosts.length, counts, new: life.added, fixed: life.fixed, dropped: r.dropped });
    L.info('vulnscan: report imported', { scan: x.id, findings: r.findings.length, hosts: r.hosts.length });
  }
  const fidOf = (f) => crypto.createHash('sha256').update(f.host + '|' + f.port + '|' + f.oid).digest('hex').slice(0, 16);
  function lifecycle(x, r) {
    const seen = new Set(), at = iso(); let added = 0, fixed = 0;
    for (const f of r.findings) {
      const id = fidOf(f); seen.add(id);
      const cur = finds().get(id);
      if (!cur) added++;
      const reopened = cur && cur.status === 'fixed';
      finds().put(Object.assign({}, cur || { id, first_seen: at, first_scan: x.id, history: [] }, f, { status: 'open', last_seen: at, last_scan: x.id, fixed_at: null, fixed_by_scan: null,
        history: ((cur && cur.history) || []).concat(!cur ? [{ at, what: 'found by ' + x.id }] : reopened ? [{ at, what: 'reported again by ' + x.id + ' after being fixed - reopened' }] : []).slice(-30) }));
    }
    // fixed only where this scan covered the host and did not report the finding again
    const covered = new Set(r.hosts);
    for (const f of finds().all((y) => y.status === 'open' && covered.has(y.host) && !seen.has(y.id))) {
      fixed++;
      finds().put(Object.assign({}, f, { status: 'fixed', fixed_at: at, fixed_by_scan: x.id, history: (f.history || []).concat([{ at, what: 'not reported by ' + x.id + ', which scanned ' + f.host + ' - fixed' }]).slice(-30) }));
    }
    return { added, fixed };
  }
  let busy = false;
  async function tick() {
    if (busy) return; busy = true;
    try {
      for (const x of scans().all((y) => y.state === 'approved' || y.state === 'running' || y.state === 'stopping')) {
        try {
          if (x.state === 'approved') {
            if (Date.parse(x.window_end) <= now()) { step(x, SYS.user, 'expired: the approved window ended before it could start', { state: 'expired' }); audit(SYS, 'vulnscan.scan.expire', x.id, {}); }
            else if (Date.parse(x.window_start) <= now()) await launch(x);
          } else await follow(x);
        } catch (e) {
          const m = s(e.message, 300);
          L.every('vulnscan:' + x.id, 15 * 60000, 'warn', 'vulnscan: scan step failed', { scan: x.id, state: x.state, err: m });
          if (x.state === 'approved') { step(x, SYS.user, 'could not start: ' + m, { state: 'failed', error: m }); audit(SYS, 'vulnscan.scan.fail', x.id, { error: m }); }
          else scans().put(Object.assign({}, getScan(x.id), { last_error: m, last_error_at: iso() }));
        }
      }
    } finally { busy = false; }
  }
  let timer = null;
  function start() { if (opts.noTimer || timer) return; timer = setInterval(guardOf(app, 'vulnscan.tick', tick), opts.everyMs || 60000); if (timer.unref) timer.unref(); }

  /* ---- findings */
  function statusOf(f) { return f.status === 'open' && f.risk && f.risk.state === 'approved' && Date.parse(f.risk.until) > now() ? 'risk_accepted' : f.status; }
  const slim = (f) => ({ id: f.id, host: f.host, hostname: f.hostname, port: f.port, name: f.name, severity: f.severity, score: f.score, cves: f.cves, status: statusOf(f), first_seen: f.first_seen, last_seen: f.last_seen, fixed_at: f.fixed_at, owner: f.owner || null, risk: f.risk ? { state: f.risk.state, until: f.risk.until } : null, solution_type: f.solution_type });
  function findings(q = {}) {
    const want = q.status || 'open', term = norm(q.q);
    let list = finds().all().filter((f) => (want === 'all' || statusOf(f) === want) && (!q.sev || f.severity === q.sev) && (!q.host || f.host === q.host)
      && (!term || (f.name + ' ' + f.host + ' ' + f.hostname + ' ' + f.cves.join(' ') + ' ' + f.port).toLowerCase().includes(term)));
    list.sort((a, b) => b.score - a.score || a.host.localeCompare(b.host));
    const total = list.length; list = list.slice(0, 1000);
    return { total, shown: list.length, items: list.map(slim) };
  }
  function finding(id) { const f = finds().get(id); if (!f) throw httpErr(404, 'no finding ' + id); return Object.assign({}, f, { status: statusOf(f) }); }
  function setOwner(id, b, who) {
    human(who, 'assigns a finding');
    const f = finding(id), prev = f.owner || null;
    finds().put(Object.assign({}, finds().get(id), { owner: b.owner, history: (f.history || []).concat([{ at: iso(), what: 'owner ' + b.owner + ' (by ' + who.user + ')' }]).slice(-30) }));
    audit(who, 'vulnscan.finding.owner', id, { owner: b.owner, previous: prev, host: f.host, name: f.name.slice(0, 120) });
    return finding(id);
  }
  function acceptRisk(id, b, who) {
    human(who, 'requests a risk acceptance');
    const f = finds().get(id); if (!f) throw httpErr(404, 'no finding ' + id);
    if (f.status !== 'open') throw httpErr(409, 'finding ' + id + ' is ' + f.status + ' - only an open finding can be risk-accepted');
    if (f.risk && f.risk.state === 'pending') throw httpErr(409, 'a risk acceptance for ' + id + ' is already waiting for approval');
    const until = Date.parse(b.until + 'T23:59:59Z');
    if (!(until > now()) || until > now() + 365 * DAY) throw httpErr(400, 'until must be a date within the next 12 months');
    const risk = { state: 'pending', reason: b.reason, until: iso(until), by: who.user, at: iso() };
    finds().put(Object.assign({}, f, { risk, history: (f.history || []).concat([{ at: iso(), what: 'risk acceptance requested by ' + who.user + ' until ' + b.until }]).slice(-30) }));
    audit(who, 'vulnscan.finding.risk-request', id, { until: b.until, reason: b.reason.slice(0, 200), host: f.host, severity: f.severity });
    return finding(id);
  }
  function riskDecision(id, b, who) {
    human(who, 'decides a risk acceptance');
    const f = finds().get(id); if (!f) throw httpErr(404, 'no finding ' + id);
    if (!f.risk || f.risk.state !== 'pending') throw httpErr(409, 'no risk acceptance waiting for ' + id);
    if (same(f.risk.by, who.user)) throw httpErr(403, 'four-eyes: the person who asked for the risk acceptance cannot approve it');
    if (b.decision === 'reject' && !b.note) throw httpErr(400, 'note is required: say why the risk is not accepted');
    const risk = Object.assign({}, f.risk, { state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '' });
    finds().put(Object.assign({}, f, { risk, history: (f.history || []).concat([{ at: iso(), what: 'risk acceptance ' + risk.state + ' by ' + who.user }]).slice(-30) }));
    audit(who, 'vulnscan.finding.risk-' + b.decision, id, { requested_by: f.risk.by, until: f.risk.until, note: (b.note || '').slice(0, 200) });
    return finding(id);
  }

  /* ---- views */
  function view() {
    const all = finds().all(), open = all.filter((f) => statusOf(f) === 'open');
    const by = { critical: 0, high: 0, medium: 0, low: 0 }; for (const f of open) by[f.severity]++;
    const hosts = {}; for (const f of open) { const h = hosts[f.host] = hosts[f.host] || { host: f.host, hostname: f.hostname, critical: 0, high: 0, medium: 0, low: 0, total: 0, top: 0 }; h[f.severity]++; h.total++; h.top = Math.max(h.top, f.score); }
    const list = scans().all().sort((a, b) => String(b.requested_at).localeCompare(String(a.requested_at)));
    const last = list.find((x) => x.state === 'done' || x.state === 'stopped');
    return { generated_at: iso(), connection: connSummary(), scope: scope(), limits: { max_hosts: MAX_HOSTS, max_window_hours: MAX_WINDOW_H }, profiles: Object.entries(PROFILES).map(([k, p]) => ({ key: k, name: p.name })),
      open: by, open_total: open.length, risk_accepted: all.filter((f) => statusOf(f) === 'risk_accepted').length, fixed_30d: all.filter((f) => f.status === 'fixed' && Date.parse(f.fixed_at) > now() - 30 * DAY).length,
      pending_risk: all.filter((f) => f.risk && f.risk.state === 'pending').length,
      hosts: Object.values(hosts).sort((a, b) => b.critical - a.critical || b.high - a.high || b.total - a.total).slice(0, 20), hosts_affected: Object.keys(hosts).length,
      scans: list.slice(0, 30).map(scanOut), last_scan: last ? { id: last.id, finished_at: last.finished_at, partial: !!last.partial } : null,
      waiting_approval: list.filter((x) => x.state === 'requested').length,
      note: 'A finding is fixed only when a later scan that covered the host no longer reports it. Results below the minimum quality of detection (' + (cfg() ? cfg().min_qod : DEF.min_qod) + '%), log-level results and overridden false positives are left out and counted on each scan.' };
  }
  function scanDetail(id) {
    const x = getScan(id), r = results().get(id);
    const top = r ? r.findings.slice().sort((a, b) => b.score - a.score).slice(0, 50).map((f) => ({ id: fidOf(f), host: f.host, hostname: f.hostname, port: f.port, name: f.name, severity: f.severity, score: f.score, cves: f.cves })) : [];
    return Object.assign(scanOut(x), { top, hosts_list: r ? r.hosts.slice(0, 500) : [] });
  }
  function exportCsv(who) {
    const cell = (v) => { let t = s(v, 2000); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return '"' + t.replace(/"/g, '""') + '"'; };   // no formula injection in Excel
    const rows = finds().all().filter((f) => statusOf(f) !== 'fixed').sort((a, b) => b.score - a.score);
    const L2 = [['Host', 'Host name', 'Port', 'Finding', 'Severity', 'CVSS', 'CVEs', 'Status', 'Owner', 'First seen', 'Last seen', 'Solution type', 'Solution'].map(cell).join(',')];
    for (const f of rows) L2.push([f.host, f.hostname, f.port, f.name, f.severity, f.score, f.cves.join(' '), statusOf(f), f.owner || '', f.first_seen, f.last_seen, f.solution_type, f.solution].map(cell).join(','));
    audit(who, 'vulnscan.export', 'findings', { rows: rows.length });
    return { filename: 'vulnerability-findings-' + iso().slice(0, 10) + '.csv', csv: L2.join('\r\n') };
  }

  return { view, findings, finding, scanDetail, exportCsv, setConfig, deleteConfig, setScope, test, request, approve, reject, cancel, setOwner, acceptRisk, riskDecision, tick, start, parseReport };
}

function registerVulnScanRoutes(srv, app, V) {
  const { body, param } = require('./check');
  const USER = { max: 80, re: /^[A-Za-z0-9][A-Za-z0-9 ._@\\-]{1,79}$/, msg: 'owner: a user name (letters, digits, space . _ - @ \\)' };
  const DT = (k) => ({ required: true, re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z$/, msg: k + ' must be a date and time in UTC (YYYY-MM-DDTHH:MMZ)' });
  const ID = (ctx) => param(ctx.params.id, 'id');
  srv.route('GET', '/vulnscan', (ctx) => { ctx.need('operator'); return V.view(); });
  srv.route('GET', '/vulnscan/findings', (ctx) => {
    ctx.need('operator');
    const q = body(ctx.query || {}).oneOf('status', ['open', 'fixed', 'risk_accepted', 'all']).oneOf('sev', SEVS).str('host', { ip: true }).str('q', { max: 100 }).done();
    return V.findings(q);
  });
  srv.route('GET', '/vulnscan/findings/:id', (ctx) => { ctx.need('operator'); return V.finding(ID(ctx)); });
  srv.route('GET', '/vulnscan/scans/:id', (ctx) => { ctx.need('operator'); return V.scanDetail(ID(ctx)); });
  srv.route('GET', '/vulnscan/export', (ctx) => { ctx.need('operator'); return V.exportCsv(ctx.who); });
  srv.route('PUT', '/vulnscan/config', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).str('socket', { max: 200, re: /^\/[A-Za-z0-9._/-]+$/, msg: 'socket must be an absolute path (e.g. /run/zyb-gvmd/gvmd.sock)' }).str('host', { host: true }).int('port', { min: 1, max: 65535 })
      .str('pin', { max: 100, re: /^[A-Fa-f0-9:]{64,95}$/, msg: 'pin must be a SHA-256 fingerprint' }).str('username', { required: true, max: 80, re: /^[A-Za-z0-9._@-]{1,80}$/, msg: 'username: letters, digits . _ @ -' })
      .str('password', { max: 200 }).str('scan_config', { id: true }).str('port_list', { id: true }).str('scanner', { id: true }).int('min_qod', { min: 1, max: 100 }).done();
    return V.setConfig(b, ctx.who);
  });
  srv.route('DELETE', '/vulnscan/config', (ctx) => { ctx.need('admin'); return V.deleteConfig(ctx.who); });
  srv.route('PUT', '/vulnscan/scope', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).list('allowed', { required: true, max: 100, item: 'str', itemMax: 40 }).list('exclude', { max: 500, item: 'str', itemMax: 40, def: [] }).done();
    return V.setScope(b, ctx.who);
  });
  srv.route('POST', '/vulnscan/test', (ctx) => { ctx.need('admin'); return V.test(ctx.who); });
  srv.route('POST', '/vulnscan/scans', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('name', { required: true, max: 120 }).list('targets', { required: true, max: 64, item: 'str', itemMax: 40 }).list('exclude', { max: 200, item: 'str', itemMax: 40, def: [] })
      .oneOf('profile', Object.keys(PROFILES), { def: 'full' }).str('window_start', DT('window_start')).str('window_end', DT('window_end')).str('reason', { required: true, max: 500 }).done();
    return V.request(b, ctx.who);
  });
  srv.route('POST', '/vulnscan/scans/:id/approve', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:pentest') : ctx.need('admin')); return V.approve(ID(ctx), ctx.who); });
  srv.route('POST', '/vulnscan/scans/:id/reject', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:pentest') : ctx.need('admin')); const b = body(ctx.body).str('note', { required: true, max: 500 }).done(); return V.reject(ID(ctx), b, ctx.who); });
  srv.route('POST', '/vulnscan/scans/:id/cancel', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('note', { max: 500 }).done(); return V.cancel(ID(ctx), b, ctx.who); });
  srv.route('POST', '/vulnscan/findings/:id/owner', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('owner', Object.assign({ required: true }, USER)).done(); return V.setOwner(ID(ctx), b, ctx.who); });
  srv.route('POST', '/vulnscan/findings/:id/accept-risk', (ctx) => { ctx.need('operator'); const b = body(ctx.body).str('reason', { required: true, max: 1000 }).date('until', { required: true }).done(); return V.acceptRisk(ID(ctx), b, ctx.who); });
  srv.route('POST', '/vulnscan/findings/:id/risk-decision', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'eng:pentest') : ctx.need('admin')); const b = body(ctx.body).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).done(); return V.riskDecision(ID(ctx), b, ctx.who); });
}

module.exports = { createVulnScan, registerVulnScanRoutes, parseReport, PROFILES, MAX_HOSTS, MAX_WINDOW_H };
