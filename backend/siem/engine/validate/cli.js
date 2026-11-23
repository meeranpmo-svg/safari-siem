#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * sentra-siem-validate — proves the SIEM catches attacks, rule by rule, and writes an evidence report.
 *
 *   offline   run every scenario through this engine's parser + detector in memory. Writes nothing anywhere except
 *             the report. Shows the rule logic works.
 *   live      send the scenarios to the RUNNING engine through its real ingest path (POST /ingest/<source>, the same
 *             path the Windows agent uses), wait for the alerts, report PASS / FAIL per rule, then close the test
 *             alerts as "benign" (unless --keep-alerts). Needs the one-time `setup` (an ingest token for the source).
 *   check     list the alerts raised for one host since a time — used after the endpoint test scripts
 *             (agents/validation/) performed real, harmless actions on a test machine.
 *
 * Options: --etc DIR (/etc/sentra-siem)  --source ID (sentra-validate)  --wait S (120)  --out DIR (.)  --only LIST
 *          (windows,linux,fortigate,web,m365,exchange,intel)  --keep-alerts  --no-intel  --json
 *          check: --host NAME --since TIME [--expect SENTRA-…,SENTRA-…]
 * Exit code: 0 everything expected was detected, 1 something was missed, 2 usage / connection error.
 *
 * Test events are synthetic and labelled (host/user names "ashval-<run>", documentation IP ranges, .invalid domains).
 * They are stored like any other event (the store is append-only); the alerts are closed with a note naming the run.
 * Live mode with intel writes <data_dir>/intel/sentra-validation-<run>.txt (test indicators only) and removes it after.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { buildScenarios } = require('./scenarios');

const ENGINE = path.join(__dirname, '..');
const PLATFORMS = { windows: 'Windows', linux: 'Linux', fortigate: 'FortiGate', web: 'Web', m365: 'Microsoft 365', exchange: 'Exchange', intel: 'Threat intel' };

function parseArgs(argv) {
  const o = { cmd: argv[0] || 'help', etc: '/etc/sentra-siem', source: 'sentra-validate', wait: 120, out: '.', keepAlerts: false, intel: true, json: false, only: null };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '--etc') o.etc = val();
    else if (a === '--source') o.source = val();
    else if (a === '--wait') o.wait = Number(val());
    else if (a === '--out') o.out = val();
    else if (a === '--only') o.only = val().split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    else if (a === '--keep-alerts') o.keepAlerts = true;
    else if (a === '--no-intel') o.intel = false;
    else if (a === '--json') o.json = true;
    else if (a === '--host') o.host = val();
    else if (a === '--since') o.since = val();
    else if (a === '--expect') o.expect = val().split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
    else if (a === '--tag') o.tag = val();
    else throw new Error(`unknown option ${a}`);
  }
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(o.source)) throw new Error('invalid --source');
  if (!(o.wait > 0 && o.wait <= 3600)) throw new Error('--wait must be 1-3600 seconds');
  if (o.only) for (const p of o.only) if (!PLATFORMS[p]) throw new Error(`--only: unknown platform ${p} (${Object.keys(PLATFORMS).join(', ')})`);
  return o;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (o, s) => { if (!o.json) o.print(s + '\n'); };
const color = (c, s) => (process.stdout.isTTY ? `\x1b[${c}m${s}\x1b[0m` : s);

function selectScenarios(set, o) {
  let sc = set.scenarios;
  if (o.only) { const want = new Set(o.only.map((p) => PLATFORMS[p])); sc = sc.filter((s) => want.has(s.platform)); }
  if (!o.intel) sc = sc.filter((s) => !s.intel);
  return sc;
}

function engineVersion() {
  for (const f of [path.join(ENGINE, '..', 'VERSION'), path.join(ENGINE, 'VERSION')]) { try { return fs.readFileSync(f, 'utf8').trim().slice(0, 40); } catch { /* next */ } }
  try { return require('../config').VERSION || 'unknown'; } catch { return 'unknown'; }
}

// ---------------------------------------------------------------------------------------------------------------- offline
async function runOffline(o) {
  const { createParser } = require('../parse');
  const { createDetector } = require('../detect/engine');
  const { loadBuiltinRules } = require('../detect/ruleset');
  const { createIntel } = require('../detect/intel');
  const { createEnricher } = require('../enrich');
  const { DEFAULTS } = require('../config');
  const set = buildScenarios({ tag: o.tag });
  const scenarios = selectScenarios(set, o);
  const rules = loadBuiltinRules();
  const intel = await createIntel({ watch: false });
  intel.add('sentra-validation', [set.intel.domain, set.intel.ip, set.intel.hash]);
  const alerts = [];
  const det = createDetector({ rules, onAlert: (a) => { if (!a.update) alerts.push(Object.assign({ id: `offline-${alerts.length + 1}`, created: Date.now() }, a)); }, intel });
  const parser = createParser({});
  const enrich = createEnricher({ config: DEFAULTS });
  const sentAt = {};
  let n = 0;
  for (const sc of scenarios) {
    sentAt[sc.id] = Date.now();
    for (const it of sc.items) {
      const ev = parser.parse(it.line, { collector: 'http', src_id: o.source, src_type: 'syslog', peer_ip: '127.0.0.1', rts: Date.now() });
      if (!ev.id) ev.id = `validate-${++n}`;
      try { enrich(ev); } catch { /* enrichment is best effort here, as in the pipeline */ }
      det.onEvent(ev);
    }
  }
  if (det.flush) det.flush();
  return buildResult({ o, mode: 'offline', set, scenarios, rules: rules.map(ruleMeta), alerts, sentAt });
}

// ---------------------------------------------------------------------------------------------------------------- live
function loadEtc(o) {
  const { loadConfig } = require('../config');
  const cfgPath = path.join(o.etc, 'config.json');
  let cfg;
  try { cfg = loadConfig({ configPath: cfgPath }); } catch (e) { throw new Error(`cannot read ${cfgPath} / secrets.json (${e.message}) - run with sudo`); }
  if (!cfg._paths.config_found) throw new Error(`${cfgPath} not found - is sentra-siem installed here? (use --etc)`);
  return cfg;
}

function api(cfg, method, p, { body, headers, raw } = {}) {
  const host = cfg.api.host === '0.0.0.0' || !cfg.api.host ? '127.0.0.1' : cfg.api.host;
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(raw ? body : JSON.stringify(body));
    const h = Object.assign({ Accept: 'application/json' }, headers || {});
    if (data) { h['Content-Length'] = data.length; if (!h['Content-Type']) h['Content-Type'] = raw ? 'application/x-ndjson' : 'application/json'; }
    const req = http.request({ host, port: cfg.api.port, method, path: p, headers: h, timeout: 30000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const txt = Buffer.concat(chunks).toString('utf8');
        let json = null; try { json = JSON.parse(txt); } catch { /* not JSON */ }
        if (res.statusCode >= 400) return reject(Object.assign(new Error(`${method} ${p} → HTTP ${res.statusCode}: ${(json && (json.error || json.message)) || txt.slice(0, 200)}`), { status: res.statusCode }));
        resolve(json);
      });
    });
    req.on('timeout', () => req.destroy(new Error(`${method} ${p}: timeout`)));
    req.on('error', (e) => reject(new Error(`cannot reach the engine API at ${host}:${cfg.api.port} (${e.message}) - is sentra-siem running?`)));
    if (data) req.write(data);
    req.end();
  });
}

async function runLive(o) {
  const cfg = loadEtc(o);
  const prefix = (cfg.api_prefix || '/api/soc').replace(/\/+$/, '');
  const secret = cfg.secrets.proxy_secret;
  const token = (cfg.secrets.ingest_tokens || {})[o.source];
  if (!secret) throw new Error('no proxy_secret in secrets.json - the engine API cannot be queried');
  if (!token) throw new Error(`no ingest token for source "${o.source}" - run once: sudo sentra-siem-validate setup`);
  const who = { 'X-Sentra-Proxy-Secret': secret, 'X-Auth-User': 'sentra-siem-validate', 'X-Auth-Role': 'operator' };

  await api(cfg, 'GET', `${prefix}/health`, { headers: who });
  let liveRules = [];
  try { liveRules = ((await api(cfg, 'GET', `${prefix}/rules`, { headers: who })) || {}).items || []; } catch (e) { say(o, color(33, `warning: rule list not available (${e.message}) - built-in metadata used`)); }
  if (!liveRules.length) liveRules = require('../detect/ruleset').loadBuiltinRules();

  const set = buildScenarios({ tag: o.tag });
  const scenarios = selectScenarios(set, o);
  say(o, `run ${set.tag}: ${scenarios.length} scenarios → ${cfg.api.host}:${cfg.api.port} (source ${o.source})`);

  // test indicators for the intel rules: a list file the engine hot-reloads (polls every 15 s)
  let intelFile = null;
  if (scenarios.some((s) => s.intel)) {
    const dir = (cfg.detect && cfg.detect.intel_dir) || path.join(cfg.data_dir, 'intel');
    intelFile = path.join(dir, `sentra-validation-${set.tag}.txt`);
    try {
      fs.writeFileSync(intelFile, `# sentra-siem-validate run ${set.tag} - TEST indicators only, removed after the run\n${set.intel.domain} validation test domain\n${set.intel.ip} validation test address (TEST-NET-1)\n${set.intel.hash} validation test hash\n`, { mode: 0o644 });
      const envWait = process.env.SENTRA_VALIDATE_INTEL_WAIT_MS; // tests shorten it
      const waitMs = envWait !== undefined && Number(envWait) >= 0 ? Number(envWait) : 20000;
      say(o, `test indicators written to ${intelFile}; waiting ${Math.round(waitMs / 1000)} s for the engine to load them (it re-reads the list every 15 s)`);
      await sleep(waitMs);
    } catch (e) {
      say(o, color(33, `warning: cannot write ${intelFile} (${e.message}) - intel scenarios skipped`));
      intelFile = null;
      for (const s of scenarios) if (s.intel) s.skip = 'IOC test list could not be written';
    }
  }

  const t0 = Date.now();
  const sentAt = {};
  try {
    for (const sc of scenarios) {
      if (sc.skip) continue;
      sentAt[sc.id] = Date.now();
      const r = await api(cfg, 'POST', `/ingest/${encodeURIComponent(o.source)}`, { raw: true, body: sc.items.map((i) => i.line).join('\n') + '\n', headers: { 'X-Sentra-Token': token } });
      if (!r || r.accepted !== sc.items.length) sc.skip = `engine accepted ${r ? r.accepted : 0} of ${sc.items.length} events`;
      say(o, `  sent ${sc.id.padEnd(22)} ${String(sc.items.length).padStart(4)} events`);
    }

    // wait for the alerts
    const expected = new Set(scenarios.filter((s) => !s.skip).flatMap((s) => s.rules));
    const deadline = Date.now() + o.wait * 1000;
    let alerts = [];
    say(o, `waiting up to ${o.wait} s for ${expected.size} rules to alert`);
    for (;;) {
      const res = await api(cfg, 'GET', `${prefix}/alerts?status=all&limit=500&sort=-created`, { headers: who });
      alerts = ((res && res.items) || []).filter((a) => a.src_id === o.source && (a.created || 0) >= t0 - 5000);
      const got = new Set(alerts.map((a) => a.rule_id));
      if ([...expected].every((r) => got.has(r)) || Date.now() > deadline) break;
      await sleep(5000);
    }
    const result = buildResult({ o, mode: 'live', set, scenarios, rules: liveRules.map(ruleMeta), alerts, sentAt, server: os.hostname() });

    if (!o.keepAlerts && alerts.length) {
      const open = alerts.filter((a) => !String(a.status || '').startsWith('closed-')).map((a) => a.id);
      for (let i = 0; i < open.length; i += 500) {
        await api(cfg, 'POST', `${prefix}/alerts/bulk`, { headers: who, body: { ids: open.slice(i, i + 500), action: 'close', reason: 'benign', note: `SIEM detection validation test (sentra-siem-validate run ${set.tag}) - synthetic events, no real attack` } });
      }
      result.closed_alerts = open.length;
      say(o, `${open.length} test alerts closed as benign (use --keep-alerts to leave them open for the SOC team to see)`);
    }
    return result;
  } finally {
    if (intelFile) { try { fs.unlinkSync(intelFile); } catch { /* already gone */ } }
  }
}

// ---------------------------------------------------------------------------------------------------------------- check
async function runCheck(o) {
  if (!o.host || !o.since) throw new Error('check needs --host NAME and --since TIME (the endpoint script prints both)');
  const since = Date.parse(o.since);
  if (!Number.isFinite(since)) throw new Error(`invalid --since "${o.since}" (use e.g. 2026-10-10T09:30:00Z)`);
  const cfg = loadEtc(o);
  const prefix = (cfg.api_prefix || '/api/soc').replace(/\/+$/, '');
  const who = { 'X-Sentra-Proxy-Secret': cfg.secrets.proxy_secret, 'X-Auth-User': 'sentra-siem-validate', 'X-Auth-Role': 'viewer' };
  const h = o.host.toLowerCase();
  const res = await api(cfg, 'GET', `${prefix}/alerts?status=all&limit=500&sort=-created`, { headers: who });
  const alerts = ((res && res.items) || []).filter((a) => (a.created || 0) >= since && (String(a.host || '').toLowerCase().startsWith(h) || JSON.stringify(a.group || {}).toLowerCase().includes(h)));
  const got = new Set(alerts.map((a) => a.rule_id));
  const expect = o.expect || [];
  const out = { mode: 'check', host: o.host, since: new Date(since).toISOString(), alerts: alerts.map((a) => ({ id: a.id, rule_id: a.rule_id, rule_name: a.rule_name, severity: a.severity, host: a.host, created: new Date(a.created).toISOString(), status: a.status })),
    expected: expect.map((r) => ({ rule: r, detected: got.has(r) })) };
  if (!o.json) {
    say(o, `alerts for ${o.host} since ${out.since}: ${alerts.length}`);
    for (const a of out.alerts) say(o, `  ${a.created}  ${a.rule_id.padEnd(14)} sev ${a.severity}  ${a.rule_name}  (${a.id})`);
    if (expect.length) {
      say(o, '');
      for (const e of out.expected) say(o, `  ${e.detected ? color(32, 'PASS') : color(31, 'FAIL')}  ${e.rule}`);
      const miss = out.expected.filter((e) => !e.detected).length;
      say(o, miss ? color(31, `${miss} of ${expect.length} expected detections missing`) : color(32, `all ${expect.length} expected detections raised`));
    }
  }
  out.ok = out.expected.every((e) => e.detected);
  return out;
}

// ---------------------------------------------------------------------------------------------------------------- report
function ruleMeta(r) {
  return { id: r.id, name: r.name, severity: r.severity, mitre: r.mitre || [], tactic: r.tactic || '', enabled: r.enabled !== false, type: r.type || 'single',
    // one counter for the whole organisation (no group_by / sequence key): a detection inside its suppression window
    // is added to the previous alert instead of raising a new one
    org_wide: !(r.group_by && r.group_by.length) && !r.by && !(r.sequence && r.sequence.by), suppress_s: r.suppress_s || 300 };
}

function buildResult({ o, mode, set, scenarios, rules, alerts, sentAt, server }) {
  const byRule = new Map(rules.map((r) => [r.id, r]));
  const firstAlert = new Map();
  for (const a of alerts.slice().sort((x, y) => (x.created || 0) - (y.created || 0))) if (!firstAlert.has(a.rule_id)) firstAlert.set(a.rule_id, a);
  const rows = [];
  const seen = new Set();
  for (const sc of scenarios) {
    for (const id of sc.rules) {
      if (seen.has(id)) continue; // a rule is reported once (first scenario that targets it)
      seen.add(id);
      const r = byRule.get(id) || { id, name: id, severity: 0, mitre: [], tactic: '', enabled: true };
      const a = firstAlert.get(id);
      let result;
      if (!byRule.has(id)) result = 'NOT LOADED';
      else if (!r.enabled) result = 'DISABLED';
      else if (sc.skip) result = 'SKIPPED';
      else result = a ? 'PASS' : 'FAIL';
      rows.push({ rule: id, name: r.name, severity: r.severity, mitre: r.mitre, tactic: r.tactic, platform: sc.platform, scenario: sc.id, scenario_title: sc.title,
        result, note: sc.skip || (result !== 'FAIL' ? '' : sc.learning ? 'baseline rule: alerts only after its 7-day learning period has passed on this engine'
          : r.org_wide ? `organisation-wide rule: within ${Math.round(r.suppress_s / 60)} min of its previous alert (an earlier test run or a real alert) new detections are added to that alert - run again later` : ''),
        alert_id: a ? a.id : '', detect_s: a && sentAt[sc.id] ? Math.max(0, Math.round(((a.created || Date.now()) - sentAt[sc.id]) / 100) / 10) : null });
    }
  }
  const order = Object.values(PLATFORMS);
  rows.sort((x, y) => order.indexOf(x.platform) - order.indexOf(y.platform)); // stable: scenario order within a platform
  if (mode === 'offline') for (const r of rows) r.detect_s = null;
  if (!o.only) for (const s of set.skipped) if (!seen.has(s.rule) && byRule.has(s.rule)) { const r = byRule.get(s.rule); rows.push({ rule: s.rule, name: r.name, severity: r.severity, mitre: r.mitre, tactic: r.tactic, platform: 'Scheduled', scenario: '', scenario_title: '', result: 'SKIPPED', note: s.reason, alert_id: '', detect_s: null }); seen.add(s.rule); }
  const custom = rules.filter((r) => !seen.has(r.id) && r.enabled);
  const count = (k) => rows.filter((x) => x.result === k).length;
  return {
    tool: 'sentra-siem-validate', mode, run: set.tag, started: new Date(Math.min(...Object.values(sentAt), Date.now())).toISOString(), finished: new Date().toISOString(),
    server: server || os.hostname(), engine_version: engineVersion(), source: o.source,
    summary: { rules_tested: rows.filter((x) => x.result === 'PASS' || x.result === 'FAIL').length, pass: count('PASS'), fail: count('FAIL'), skipped: count('SKIPPED'), disabled: count('DISABLED'), not_loaded: count('NOT LOADED'), other_rules_not_covered: custom.map((r) => r.id) },
    rows,
  };
}

const esc = (s) => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function html(res) {
  const s = res.summary;
  const tested = s.pass + s.fail;
  const pct = tested ? Math.round((s.pass / tested) * 100) : 0;
  const tactics = {};
  for (const r of res.rows) { if (r.result !== 'PASS' && r.result !== 'FAIL') continue; const t = r.tactic || 'other'; tactics[t] = tactics[t] || { pass: 0, total: 0 }; tactics[t].total++; if (r.result === 'PASS') tactics[t].pass++; }
  const badge = (x) => `<span class="b b-${x.replace(/\s/g, '').toLowerCase()}">${esc(x)}</span>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM Detection Validation ${esc(res.run)}</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#5b6474;--line:#e2e5ea;--ok:#127a3a;--okb:#e3f5e9;--bad:#b3261e;--badb:#fde7e5;--warn:#8a5a00;--warnb:#fff2d6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2b3240;--ok:#5fd28a;--okb:#16301f;--bad:#ff8a80;--badb:#3a1a18;--warn:#f0c060;--warnb:#33290f}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}.mut{color:var(--mut)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.card .v{font-size:26px;font-weight:650}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--mut);font-weight:600}
.wrap{overflow-x:auto}.b{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.b-pass{background:var(--okb);color:var(--ok)}.b-fail{background:var(--badb);color:var(--bad)}.b-skipped,.b-disabled,.b-notloaded{background:var(--warnb);color:var(--warn)}
h2{font-size:16px;margin:28px 0 10px}code{font-size:12px}
</style></head><body><main>
<h1>${ZYB_ORG.short} SIEM - detection validation</h1>
<div class="mut">Run <b>${esc(res.run)}</b> · ${esc(res.mode === 'live' ? 'live engine' : 'offline (rule logic)')} · server ${esc(res.server)} · engine ${esc(res.engine_version)} · ${esc(res.finished.replace('T', ' ').slice(0, 19))} UTC</div>
<div class="cards">
<div class="card"><div class="mut">Detection rate</div><div class="v">${pct}%</div><div class="mut">${s.pass} of ${tested} rules</div></div>
<div class="card"><div class="mut">Passed</div><div class="v" style="color:var(--ok)">${s.pass}</div></div>
<div class="card"><div class="mut">Missed</div><div class="v" style="color:var(--bad)">${s.fail}</div></div>
<div class="card"><div class="mut">Skipped / disabled</div><div class="v">${s.skipped + s.disabled + s.not_loaded}</div></div>
</div>
<h2>By tactic</h2><div class="wrap"><table><tr><th>Tactic</th><th>Detected</th></tr>
${Object.entries(tactics).sort().map(([t, v]) => `<tr><td>${esc(t)}</td><td>${v.pass} / ${v.total}</td></tr>`).join('')}
</table></div>
<h2>Rules</h2><div class="wrap"><table><tr><th>Result</th><th>Rule</th><th>Platform</th><th>MITRE</th><th>Sev</th><th>Test scenario</th><th>Alert</th><th>Time to alert</th></tr>
${res.rows.map((r) => `<tr><td>${badge(r.result)}</td><td><code>${esc(r.rule)}</code><br>${esc(r.name)}</td><td>${esc(r.platform)}</td><td>${esc((r.mitre || []).join(', '))}</td><td>${esc(r.severity)}</td><td>${esc(r.scenario_title)}${r.note ? `<br><span class="mut">${esc(r.note)}</span>` : ''}</td><td><code>${esc(r.alert_id)}</code></td><td>${r.detect_s === null ? '' : esc(r.detect_s + ' s')}</td></tr>`).join('\n')}
</table></div>
${s.other_rules_not_covered.length ? `<h2>Enabled rules without a built-in test</h2><p class="mut">Custom or imported rules: ${esc(s.other_rules_not_covered.join(', '))}</p>` : ''}
<h2>Method</h2><p class="mut">Synthetic, clearly labelled attack events (host and user names <code>ashval-${esc(res.run)}</code>, documentation IP ranges, <code>.invalid</code> domains) were sent in each source's native log format ${res.mode === 'live' ? `to the running engine through its authenticated ingest path (source <code>${esc(res.source)}</code>), and the alerts it raised were collected from the SOC API. Test alerts were closed as benign with a note naming this run.` : 'through the engine\'s parser and detection engine in memory (no data written).'} No real system was attacked.</p>
</main></body></html>`;
}

function writeReports(res, o) {
  fs.mkdirSync(o.out, { recursive: true });
  const stamp = res.finished.replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
  const base = path.join(o.out, `sentra-siem-validation-${res.mode}-${stamp}-${res.run}`);
  fs.writeFileSync(base + '.json', JSON.stringify(res, null, 2) + '\n');
  fs.writeFileSync(base + '.html', html(res));
  // run with sudo: hand the reports to the invoking user
  const uid = Number(process.env.SUDO_UID); const gid = Number(process.env.SUDO_GID);
  if (process.getuid && process.getuid() === 0 && uid > 0) { for (const f of [base + '.json', base + '.html']) { try { fs.chownSync(f, uid, gid); } catch { /* keep root */ } } }
  return base;
}

function printResult(res, o) {
  if (o.json) return;
  say(o, '');
  let platform = '';
  for (const r of res.rows) {
    if (r.platform !== platform) { platform = r.platform; say(o, color(1, platform)); }
    const tag = r.result === 'PASS' ? color(32, 'PASS') : r.result === 'FAIL' ? color(31, 'FAIL') : color(33, r.result.padEnd(4));
    say(o, `  ${tag}  ${r.rule.padEnd(14)} ${r.name}${r.detect_s !== null ? color(2, `  (${r.detect_s} s)`) : ''}${r.note ? color(2, `  - ${r.note}`) : ''}`);
  }
  const s = res.summary;
  say(o, '');
  say(o, `${s.fail ? color(31, 'MISSED ' + s.fail) : color(32, 'ALL DETECTED')}  - ${s.pass} passed, ${s.fail} missed, ${s.skipped} skipped, ${s.disabled} disabled  (run ${res.run}, ${res.mode})`);
}

// io (tests): { print(text), printErr(text) } instead of process.stdout / process.stderr
async function main(argv, io = {}) {
  const print = io.print || ((t) => process.stdout.write(t));
  const printErr = io.printErr || ((t) => process.stderr.write(t));
  let o;
  try { o = parseArgs(argv); } catch (e) { printErr(`sentra-siem-validate: ${e.message}\n`); return 2; }
  o.print = print;
  if (o.cmd === 'help' || o.cmd === '--help' || o.cmd === '-h') {
    const doc = fs.readFileSync(__filename, 'utf8').split('\n');
    print(doc.slice(doc.indexOf('/*') + 1, doc.indexOf(' */')).map((l) => l.replace(/^ \* ?/, '')).join('\n') + '\n');
    return 0;
  }
  try {
    if (o.cmd === 'check') { const r = await runCheck(o); if (o.json) print(JSON.stringify(r, null, 2) + '\n'); return r.ok ? 0 : 1; }
    if (o.cmd !== 'offline' && o.cmd !== 'live') throw new Error(`unknown command ${o.cmd} (offline, live, check, help)`);
    const res = o.cmd === 'live' ? await runLive(o) : await runOffline(o);
    const base = writeReports(res, o);
    if (o.json) print(JSON.stringify(res, null, 2) + '\n');
    printResult(res, o);
    say(o, `report: ${base}.html  (+ .json)`);
    return res.summary.fail ? 1 : 0;
  } catch (e) {
    printErr(`sentra-siem-validate: ${e.message}\n`);
    return 2;
  }
}

if (require.main === module) main(process.argv.slice(2)).then((c) => { process.exitCode = c; });
module.exports = { main, parseArgs, buildResult, html };
