// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Test helpers: a fake sentra-ai /draft server returning clearly SYNTHETIC JSON, an app bootstrap on a temp dir, an HTTP
// client that sends the proxy-secret + identity headers the way nginx does, and synthetic netops/vCenter fixtures.
// NO real network: the fake server is loopback and the connectors are driven by injected fetch impls.
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
// the policy register is the organisation's own content and is not shipped: tests read a clearly synthetic one
process.env.SENTRA_GRC_POLICIES = process.env.SENTRA_GRC_POLICIES || path.join(__dirname, 'fixtures', 'grc-policies.synthetic.json');
const { createApp } = require('../engine/main');

const SECRET = 'synthetic-proxy-secret-0123456789abcdef';
const S = 'SYNTHETIC TEST OUTPUT';
const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-itam-test-'));
const fence = (o) => '```json\n' + JSON.stringify(o, null, 1) + '\n```';
const ids = (prompt) => [...new Set((String(prompt).match(/id=(as_[0-9a-f]+)/g) || []).map((m) => m.slice(3)))];

function canned(body) {
  const sys = String(body.system || ''); const prompt = String(body.prompt || '');
  const id = ids(prompt);
  if (sys.includes('TASK: classify and normalise')) {
    return { assets: id.slice(0, 3).map((r) => ({ ref: r, type: 'server', vendor: 'Dell', model: 'PowerEdge', category: 'compute', confidence: 0.9, rationale: `${S}` })).concat([{ ref: 'as_invalidref', type: 'server', confidence: 1, rationale: 'invented' }]), merges: id.length >= 2 ? [{ keep: id[0], duplicate: id[1], confidence: 0.8, rationale: S }] : [] };
  }
  if (sys.includes('TASK: infer configuration-item')) {
    return { relationships: id.length >= 2 ? [{ from: id[0], to: id[1], type: 'depends_on', confidence: 0.7, rationale: S }, { from: id[0], to: 'as_bogus', type: 'runs_on', confidence: 1, rationale: 'invented' }] : [] };
  }
  if (sys.includes('TASK: build a refresh plan')) {
    return { summary: `${S}: refresh`, items: id.slice(0, 2).map((a) => ({ asset_id: a, action: 'replace', when: '2027-Q1', reason: S, estimated_cost: 5000 })), risks: [`${S}: risk`] };
  }
  return { nothing: true };
}

function startFakeDraft() {
  const state = { requests: [], override: null };
  const srv = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = {}; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* */ }
      state.requests.push({ url: req.url, headers: req.headers, body });
      let out = state.override ? state.override(body) : null;
      if (!out) out = { ok: true, text: fence(canned(body)), model: 'synthetic-model-1', usage: { input: 100, output: 50 }, truncated: false, stop_reason: 'end_turn' };
      const data = typeof out === 'string' ? out : JSON.stringify(out);
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(data);
    });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(Object.assign(state, {
    port: srv.address().port, url: `http://127.0.0.1:${srv.address().port}`,
    close: () => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections(); }),
  }))));
}

// synthetic netops device fixture + connector fetchImpl
const NETOPS_DEVICES = [
  { id: 'nd1', hostname: 'core-sw-01', type: 'switch', vendor: 'Aruba', model: '6300', serial: 'ARU-SW-001', mgmt_ip: '10.1.0.2', mac: 'aa:bb:cc:00:00:01', site: 'HQ', interfaces: [{ mac: 'aa:bb:cc:00:00:01' }] },
  { id: 'nd2', hostname: 'ap-floor2', type: 'ap', vendor: 'Aruba', model: 'AP-515', serial: 'ARU-AP-002', mgmt_ip: '10.1.0.9', site: 'HQ' },
];
const NETOPS_EDGES = [{ local_device: 'nd1', remote_device: 'nd2', local_port: 'Gi1/0/9' }];
function netopsFetch() {
  return ({ path: p }) => (p.includes('topolog') ? { ok: true, edges: NETOPS_EDGES } : { ok: true, devices: NETOPS_DEVICES });
}

// synthetic vCenter REST fixture (vSphere 7/8 shape) + connector fetchImpl
const VC_HOSTS = { value: [{ host: 'host-1', name: 'esxi01.lab', model: 'Dell R740', vendor: 'Dell', cpu_count: 2, memory_size_MiB: 262144, esxi_version: '8.0', hardware_uuid: 'HOSTUUID-1' }] };
const VC_VMS = { value: [{ vm: 'vm-101', name: 'app01', host: 'host-1', cpu_count: 4, memory_size_MiB: 8192, guest_OS: 'UBUNTU_64', instance_uuid: 'VMUUID-101', power_state: 'POWERED_ON' }] };
function vcenterFetch() { return ({ kind }) => ({ ok: true, json: kind === 'hosts' ? VC_HOSTS : VC_VMS }); }

async function startApp(o = {}) {
  const fake = o.fake || await startFakeDraft();
  const dir = o.dir || tmpDir();
  const logs = [];
  const log = { debug() {}, info: (m, f) => logs.push(['info', m, f]), warn: (m, f) => logs.push(['warn', m, f]), error: (m, f) => logs.push(['error', m, f]), isDebug: () => false, every: (k, ms, l, m, f) => logs.push([l, m, f]) };
  const config = Object.assign({ data_dir: dir, api: { host: '127.0.0.1', port: 0, prefix: '/api/itam', agent_prefix: '/agent' } }, o.config || {});
  config.ai = Object.assign({ provider: 'private', private_url: o.noAi ? '' : fake.url, per_user_hourly_cap: 100, daily_cap: 100, timeout_ms: 10000 }, (o.config && o.config.ai) || {});
  // discovery vault key lives in the per-test temp dir (created by the engine); the scheduler is driven by tick() in tests
  // the product's every-engineer duty desk in tests (the organisation's brand switches some off; tests/ai-team.test.js checks that)
  config.duty = Object.assign({ all_engineers: true }, (o.config && o.config.duty) || {});
  // SYNTHETIC test sites (the product takes the organisation's sites from the brand setting)
  const TEST_SITES = ['Riyadh HQ', 'Jeddah DR', 'Riyadh Olaya', 'Alkhobar'];
  config.discovery = Object.assign({ vault_key_file: path.join(dir, 'discovery-vault.key'), vault_create_key: true, ad_resolve_dns: false, sites: TEST_SITES }, (o.config && o.config.discovery) || {});
  config.discovery.siem = Object.assign({ site_map: { 'Riyadh HQ': 'riyadh-hq', 'Jeddah DR': 'jeddah', 'Riyadh Olaya': 'riyadh-olaya', Alkhobar: 'alkhobar' } }, config.discovery.siem || {});
  const app = createApp({ config, secrets: Object.assign({ proxy_secret: SECRET }, o.secrets || {}), log, netopsFetch: o.netopsFetch, vcenterFetch: o.vcenterFetch, connector: o.connector, discoveryDeps: o.discoveryDeps, noScheduler: o.scheduler !== true });
  app.__testNoLicence = true;   // tests other than the licence tests run without the built-in Citynet key enforcing (engine/licence.js)
  const { port } = await app.start();
  function req(method, p, { body, user = 'op.one', role = 'operator', secret = SECRET, bearer, headers = {} } = {}) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
      const h = Object.assign({}, data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}, secret ? { 'X-Sentra-Proxy-Secret': secret } : {}, user ? { 'X-Auth-User': user } : {}, role ? { 'X-Auth-Role': role } : {}, bearer ? { Authorization: `Bearer ${bearer}` } : {}, headers);
      const full = p.startsWith('/api/') || p.startsWith('/agent/') ? p : `/api/itam${p}`;
      const r = http.request({ host: '127.0.0.1', port, method, path: full, headers: h }, (res) => {
        const chunks = []; res.on('data', (c) => chunks.push(c));
        res.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch { /* */ } resolve({ status: res.statusCode, headers: res.headers, text, json }); });
      });
      r.on('error', reject); if (data) r.write(data); r.end();
    });
  }
  const as = (user, role) => (method, p, opt = {}) => req(method, p, Object.assign({ user, role }, opt));
  async function waitJob(jobId, ms = 8000) {
    const t0 = Date.now();
    for (;;) { const r = await req('GET', `/ai/jobs/${jobId}`); if (r.json && (r.json.status === 'done' || r.json.status === 'failed')) return r.json; if (Date.now() - t0 > ms) throw new Error(`job ${jobId} did not finish: ${r.text}`); await new Promise((res) => setTimeout(res, 10)); }
  }
  async function runAI(feature) { const r = await req('POST', `/ai/run/${feature}`); if (r.status !== 200) throw new Error(`run ${feature} → ${r.status} ${r.text}`); return waitJob(r.json.job_id); }
  return { app, port, dir, fake, logs, req, as, waitJob, runAI, async close() { await app.stop(); if (!o.fake) await fake.close(); } };
}

module.exports = { SECRET, S, startApp, startFakeDraft, canned, fence, tmpDir, netopsFetch, vcenterFetch, NETOPS_DEVICES, VC_HOSTS, VC_VMS };
