// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Throughput benchmark: every built-in real-time rule (64 incl. Exchange) + 52 synthetic ones of every type (116 rules,
// incl. regex rules), realistic event mix, IOC lists with 10k entries, one core.
// Requirement: >= 20,000 events/s. Hard assertion only when SENTRA_BENCH_STRICT=1 (shared CI machines vary); otherwise the
// test asserts a conservative floor and prints the measured rate.  Run alone:  node --test tests/detect-bench.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { createDetector } = require('../engine/detect/engine');
const { createIntel } = require('../engine/detect/intel');
const { loadBuiltinRules } = require('../engine/detect/ruleset');

const T0 = Date.UTC(2026, 8, 29, 6, 0, 0);

function syntheticRules() {
  const out = [];
  for (let i = 0; i < 20; i++) {
    out.push({ id: `BENCH-S${i}`, name: `bench single ${i}`, type: 'single', severity: 1, suppress_s: 600, group_by: ['host'],
      match: { all: [{ field: 'event_code', op: 'eq', value: String(4800 + i) }, { field: 'user', op: 'neq', value: 'system' }] } });
  }
  for (let i = 0; i < 10; i++) {
    out.push({ id: `BENCH-T${i}`, name: `bench threshold ${i}`, type: 'threshold', window_s: 300, count: 500, suppress_s: 600, group_by: ['src_ip'],
      match: { all: [{ field: 'action', op: 'eq', value: 'blocked' }, { field: 'dst_port', op: 'eq', value: 1000 + i }] } });
  }
  for (let i = 0; i < 10; i++) {
    out.push({ id: `BENCH-R${i}`, name: `bench regex ${i}`, type: 'single', suppress_s: 600, group_by: ['host'],
      match: { any: [{ field: 'cmdline', op: 're', value: `bench-tool-${i}\\s+--(exfil|dump)` }, { field: 'url', op: 'contains', value: `/bench-probe-${i}/` }] } });
  }
  for (let i = 0; i < 6; i++) {
    out.push({ id: `BENCH-D${i}`, name: `bench distinct ${i}`, type: 'distinct', window_s: 60, distinct_count: 200, distinct_field: 'url', suppress_s: 600, group_by: ['src_ip'],
      match: { all: [{ field: 'category', op: 'eq', value: 'web' }, { field: 'http_status', op: 'eq', value: 400 + i }] } });
  }
  for (let i = 0; i < 6; i++) {
    out.push({ id: `BENCH-Q${i}`, name: `bench sequence ${i}`, type: 'sequence', window_s: 600, by: ['user'], suppress_s: 600,
      steps: [{ match: { all: [{ field: 'action', op: 'eq', value: 'logon-failed' }, { field: 'src_type', op: 'eq', value: i % 2 ? 'linux' : 'windows' }] }, count: 50 + i },
        { match: { all: [{ field: 'action', op: 'eq', value: 'logon' }, { field: 'fields.bench', op: 'eq', value: `x${i}` }] } }] });
  }
  return out;
}

function makeEvents(nEv) {
  const evs = new Array(nEv);
  const pick = (a, i) => a[i % a.length];
  const users = Array.from({ length: 500 }, (_, i) => `user${i}`);
  const cmd = ['C:\\Windows\\System32\\svchost.exe -k netsvcs', 'powershell.exe -NoProfile -File C:\\ops\\inventory.ps1', '"C:\\Program Files\\App\\app.exe" --update', 'cmd.exe /c dir'];
  const urls = ['/index.html', '/api/v1/items?id=42', '/login', '/static/app.js', '/search?q=insurance+quote', '/wp-login.php'];
  for (let i = 0; i < nEv; i++) {
    const r = i % 100;
    const ts = T0 + i * 3;
    const base = { id: `bench-${i}`, ts, rts: ts, host: `h${i % 300}`, severity: 0, tags: [], fields: {}, user: '', target_user: '', src_ip: '', dst_ip: '', cmdline: '', url: '', dns_query: '', hash: '', event_code: '', process: '', outcome: 'success' };
    let e;
    if (r < 40) { // FortiGate traffic
      e = { src_type: 'fortigate', category: 'network', action: r < 8 ? 'blocked' : 'allowed', src_ip: `10.${(i >> 8) & 255}.${i & 255}.${(i * 7) & 255}`,
        dst_ip: `${(i * 13) % 223 + 1}.${(i * 7) & 255}.${(i * 3) & 255}.${i & 255}`, dst_port: pick([443, 80, 53, 445, 1003, 3389], i), event_code: '0000000013',
        fields: { sentbyte: String((i * 997) % 50000), rcvdbyte: '1200', policyid: '12', subtype: 'forward' } };
    } else if (r < 55) { // Windows security
      const code = pick(['4624', '4625', '4688', '4769', '4634', '4672', '4803'], i);
      e = { src_type: 'windows', category: code === '4688' ? 'process' : 'authentication', event_code: code,
        action: code === '4625' ? 'logon-failed' : code === '4624' ? 'logon' : code === '4688' ? 'process-start' : code === '4769' ? 'kerberos-service-ticket' : 'event',
        outcome: code === '4625' ? 'failure' : 'success', user: pick(users, i * 7), src_ip: `10.1.${i & 255}.${(i >> 3) & 255}`, cmdline: code === '4688' ? pick(cmd, i) : '',
        process: code === '4688' ? 'C:\\Windows\\System32\\svchost.exe' : '', fields: { logon_type: '3', ticket_encryption: '0x12', service_name: 'cifs' } };
    } else if (r < 70) { // Linux sshd / sudo
      e = { src_type: 'linux', category: 'authentication', process: 'sshd', action: r < 60 ? 'logon-failed' : 'logon', outcome: r < 60 ? 'failure' : 'success',
        user: pick(users, i), src_ip: `198.51.100.${i & 255}`, fields: { service: 'ssh' } };
    } else if (r < 85) { // web access
      e = { src_type: 'nginx', category: 'web', action: 'http-request', src_ip: `203.0.113.${i & 255}`, url: pick(urls, i), http_status: pick([200, 200, 200, 304, 404, 401], i),
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', http_method: 'GET' };
    } else if (r < 95) { // DNS
      e = { src_type: 'windows', category: 'dns', action: 'dns-query', event_code: '22', src_ip: `10.2.${i & 255}.9`, dns_query: `host${i % 5000}.example.com` };
    } else { // M365
      e = { src_type: 'm365', category: 'authentication', action: r < 98 ? 'logon' : 'logon-failed', event_code: r < 98 ? '0' : '50126', user: `${pick(users, i)}@example.sa`, src_ip: `203.0.113.${(i * 5) & 255}`, fields: { risk_level: 'none' } };
    }
    evs[i] = Object.assign(base, e);
  }
  return evs;
}

test('throughput: >= 20,000 events/s with >= 100 rules on one core', (t) => {
  const builtins = loadBuiltinRules().filter((r) => r.type !== 'scheduled');
  const rules = builtins.concat(syntheticRules());
  assert.ok(rules.length >= 100);
  const intel = createIntel({ watch: false });
  intel.add('bench-ip', Array.from({ length: 5000 }, (_, i) => `192.0.2.${i % 256}`).concat(Array.from({ length: 200 }, (_, i) => `100.${i}.0.0/16`)));
  intel.add('bench-dom', Array.from({ length: 5000 }, (_, i) => `bad${i}.example.net`));
  intel.add('bench-hash', Array.from({ length: 1000 }, (_, i) => i.toString(16).padStart(64, 'a')));
  let alerts = 0;
  const det = createDetector({ rules, intel, onAlert: () => { alerts++; }, now: () => T0 });
  assert.equal(det.stats().rules_loaded, rules.length);
  const N = 200000;
  const events = makeEvents(N);
  for (let i = 0; i < 20000; i++) det.onEvent(events[i]); // warm-up (JIT)
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < N; i++) det.onEvent(events[i]);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const eps = Math.round(N / (ms / 1000));
  const st = det.stats();
  const slowest = st.rules.slice().sort((a, b) => b.avg_us - a.avg_us).slice(0, 5).map((r) => `${r.id}=${r.avg_us}µs`).join(', ');
  const evals = st.rules.reduce((s, r) => s + r.evaluations, 0);
  const msg = `detector throughput: ${eps.toLocaleString('en-US')} events/s (${N} events, ${rules.length} rules, ${st.rules_unindexed} unindexed, ` +
    `${(evals / st.events).toFixed(1)} rule evaluations/event, ${alerts} alert partials, ${ms.toFixed(0)} ms); slowest rules: ${slowest}`;
  t.diagnostic(msg);
  console.log(msg);
  assert.equal(st.errors, 0);
  const floor = process.env.SENTRA_BENCH_STRICT === '1' ? 20000 : 5000;
  assert.ok(eps >= floor, `throughput ${eps} < ${floor} events/s`);
});
