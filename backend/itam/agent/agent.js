// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// itam-agent — cross-platform endpoint agent. OUTBOUND ONLY: it POSTs to the ITAM agent gateway and never listens.
// Commands:
//   itam-agent enrol --server https://portal/agent (--token-stdin | --token-file <path>) [--dir <state-dir>]
//                    (--token <tok> still works but exposes the token in the process list — installers use stdin)
//   itam-agent run   [--interval 3600]     (heartbeat + periodic report loop; store-and-forward when offline)
//   itam-agent once                          (collect + report a single time; exits non-zero only on fatal config error)
//   itam-agent status
// Least privilege: needs only outbound HTTPS and read access to local inventory commands. No admin rights required
// for the registry/CIM/dpkg/rpm/system_profiler queries it runs; install it as LocalService / a dedicated daemon user.
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { createAgentState } = require('./config');
const collector = require('./collect');

// Transport policy: the agent key / enrolment token only ever travel over HTTPS. Plain http:// is accepted solely for a
// loopback server (127.0.0.1 / localhost / ::1 — tests and a local relay). Returns an error string or null.
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
function serverUrlError(url) {
  let u; try { u = new URL(String(url)); } catch { return 'bad server url'; }
  if (u.protocol === 'https:') return null;
  if (u.protocol === 'http:' && LOOPBACK.has(u.hostname.toLowerCase())) return null;
  return `server url must be https:// (http is allowed only for 127.0.0.1/localhost): ${u.protocol}//${u.host}`;
}

function post(url, body, headers, timeoutMs = 30000) {
  return new Promise((resolve) => {
    const ue = serverUrlError(url);
    if (ue) return resolve({ ok: false, error: ue });
    let u; try { u = new URL(url); } catch { return resolve({ ok: false, error: 'bad server url' }); }
    const data = Buffer.from(JSON.stringify(body));
    const mod = u.protocol === 'https:' ? https : http;
    const r = mod.request({ protocol: u.protocol, hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'POST', timeout: timeoutMs, headers: Object.assign({ 'Content-Type': 'application/json', 'Content-Length': data.length }, headers || {}) }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { let j = null; try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* */ } resolve({ ok: res.statusCode < 400, status: res.statusCode, json: j }); });
      res.on('error', () => resolve({ ok: false, error: 'response failed' }));
    });
    r.on('timeout', () => r.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    r.on('error', (e) => resolve({ ok: false, error: e.code || 'error' }));
    r.end(data);
  });
}

async function enrol({ server, token, state }, postImpl = post) {
  if (!server || !token) throw new Error('enrol needs --server and a token (--token-stdin or --token-file)');
  const base = String(server).replace(/\/+$/, '');
  const ue = serverUrlError(base);
  if (ue) throw new Error(ue);
  const collected = await collector.collect();
  const r = await postImpl(`${base}/enrol`, { token, hostname: collected.host.hostname, platform: collected.host.platform, fingerprint: fingerprint(collected.host) });
  if (!r.ok || !r.json || !r.json.agent_key) throw new Error(`enrolment failed: ${(r.json && (r.json.error || r.json.message)) || r.error || 'HTTP ' + r.status}`);
  state.set({ server: base, agent_id: r.json.agent_id, agent_key: r.json.agent_key, enrolled_at: new Date().toISOString() });
  return { agent_id: r.json.agent_id };
}

function fingerprint(host) { return crypto.createHash('sha256').update(`${host.hostname}|${host.serial || ''}|${(host.macs || []).join(',')}`).digest('hex').slice(0, 32); }

function buildReport(seq, collected) {
  return { seq, ts: new Date().toISOString(), nonce: crypto.randomBytes(8).toString('hex'), host: collected.host, software: collected.software, patch_level: collected.host.patch_level || null };
}

// send one report, with store-and-forward: on network failure the report is spooled; spooled reports are flushed
// first (oldest first) so the server's seq stays monotonic.
async function reportOnce(state, postImpl = post) {
  const s = state.get();
  if (!s.agent_id || !s.agent_key) throw new Error('agent is not enrolled — run: itam-agent enrol');
  const headers = { Authorization: `Bearer ${s.agent_key}` };
  // flush spool first
  const spooled = state.spoolTake();
  const requeue = [];
  for (const rep of spooled) {
    const r = await postImpl(`${s.server}/report`, rep, headers);
    if (!r.ok && !(r.json && /replay|order/.test((r.json.code || '')))) requeue.push(rep); // keep on transport failure; drop confirmed replays
  }
  const collected = await collector.collect();
  const report = buildReport(state.nextSeq(), collected);
  const r = await postImpl(`${s.server}/report`, report, headers);
  if (!r.ok) {
    // network/5xx → spool for later; a 401 means revoked (do not spool)
    if (r.status === 401) return { ok: false, revoked: true };
    requeue.unshift(report);
  }
  for (const rep of requeue) state.spoolPush(rep);
  return { ok: !!r.ok, spooled: requeue.length };
}

async function heartbeat(state, postImpl = post) {
  const s = state.get();
  if (!s.agent_id) return { ok: false };
  return postImpl(`${s.server}/heartbeat`, {}, { Authorization: `Bearer ${s.agent_key}` });
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) { const a = argv[i]; if (a.startsWith('--')) { const k = a.slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true; out[k] = v; } else out._.push(a); }
  return out;
}

// enrolment token source: --token-file <path> (first line), --token-stdin / --token - (first line of stdin), or the
// legacy --token <value>. File/stdin keep the one-time token out of the process list and shell history.
function readStdin(stream = process.stdin) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    stream.on('data', (c) => { size += c.length; if (size > 4096) { stream.destroy(); reject(new Error('token on stdin too long')); } else chunks.push(c); });
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    stream.on('error', reject);
  });
}
async function resolveToken(args, { readFile = (f) => require('node:fs').readFileSync(f, 'utf8'), stdin } = {}) {
  const first = (t) => String(t || '').split(/\r?\n/)[0].trim();
  if (typeof args['token-file'] === 'string') return first(readFile(args['token-file']));
  if (args['token-stdin'] === true || args.token === '-') return first(await readStdin(stdin));
  if (typeof args.token === 'string') { process.stderr.write('itam-agent: warning: --token exposes the token in the process list; prefer --token-stdin or --token-file\n'); return args.token; }
  return '';
}

async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const cmd = args._[0] || 'once';
  const state = createAgentState({ dir: args.dir }); state.load();
  if (cmd === 'enrol') { const token = await resolveToken(args); const r = await enrol({ server: args.server, token, state }); process.stdout.write(`enrolled as ${r.agent_id}\n`); return 0; }
  if (cmd === 'status') { const s = state.get(); process.stdout.write(JSON.stringify({ enrolled: state.enrolled(), server: s.server, agent_id: s.agent_id, seq: s.seq, spooled: (s.spool || []).length }, null, 2) + '\n'); return 0; }
  if (cmd === 'once') { const r = await reportOnce(state); process.stdout.write(`report ${r.ok ? 'sent' : r.revoked ? 'REVOKED' : 'spooled'}\n`); return 0; }
  if (cmd === 'run') {
    const interval = Math.max(60, Number(args.interval) || 3600) * 1000;
    const tick = async () => { try { await heartbeat(state); await reportOnce(state); } catch (e) { process.stderr.write(`itam-agent: ${e.message}\n`); } };
    await tick();
    const t = setInterval(tick, interval);
    process.on('SIGTERM', () => { clearInterval(t); process.exit(0); });
    process.on('SIGINT', () => { clearInterval(t); process.exit(0); });
    return new Promise(() => {}); // run forever
  }
  process.stderr.write('usage: itam-agent enrol|run|once|status [--server URL] [--token-stdin | --token-file PATH] [--interval S] [--dir PATH]\n');
  return 2;
}

if (require.main === module) { main().then((c) => { if (typeof c === 'number' && c) process.exit(c); }).catch((e) => { process.stderr.write(`itam-agent: ${e.message}\n`); process.exit(1); }); }

module.exports = { main, enrol, reportOnce, heartbeat, buildReport, fingerprint, parseArgs, post, serverUrlError, resolveToken };
