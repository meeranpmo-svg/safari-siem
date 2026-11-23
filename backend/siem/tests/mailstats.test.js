// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Mail volume (engine/soc/mailstats.js): sent to / received from the Internet, internal, spam - from Exchange message
// tracking (unique messages, our domains passed as a parameter) or, without Exchange, the gateway with internal "not
// available"; domain validation, parameters only, audit, nothing connected. Stub ClickHouse answering by query tag.
const test = require('node:test');
const assert = require('node:assert/strict');
const ms = require('../engine/soc/mailstats');

const NOW = Date.UTC(2026, 9, 26, 9, 0);
function harness(answers) {
  const calls = [], routes = {}, audits = [];
  const ch = { query: async (sql, params) => { const tag = /^\/\*q:([a-z_]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, params }); return (answers[tag] || []).map((r) => Object.assign({}, r)); } };
  ms.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { ch, now: () => NOW, config: {} });
  const call = async (query, role = 'viewer') => {
    let out = null;
    const ctx = { query, role, user: 'syed', ok: (b) => { out = { status: 200, body: b }; return out; }, fail: (s, m) => { out = { status: s, error: m }; return out; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    await routes['GET /api/soc/mail/stats'](ctx);
    return out;
  };
  return { calls, call, audits };
}

test('mail stats from Exchange: unique messages split by our domains, spam by action, series, top domains', async () => {
  const h = harness({ ms_ex: [{ n: 500 }], ms_tot: [{ r: 120, i: 300, s: 80 }], ms_series: [{ k: 2, r: 10, i: 20, s: 5 }],
    ms_gw: [{ dir: 'inbound', n: 400 }, { dir: 'outbound', n: 90 }], ms_spam: [{ v: 'spam', a: 'quarantined', n: 60 }, { v: 'spam', a: 'delivered', n: 4 }, { v: 'phishing', a: 'blocked', n: 7 }],
    ms_top_r: [{ dom: 'partner.test', n: 30 }], ms_top_s: [{ dom: 'reinsurer.test', n: 12 }] });
  const r = await h.call({ range: '7', domains: 'corpgroup.test,Corpgroup-KSA.test.' });
  assert.equal(r.status, 200); const s = r.body;
  assert.equal(s.source, 'exchange'); assert.deepEqual(s.totals, { received_external: 120, sent_external: 80, internal: 300 });
  assert.deepEqual(s.domains_used, ['corpgroup.test', 'corpgroup-ksa.test']);
  assert.equal(s.series.length, 7); assert.deepEqual(s.series[2], { t: s.from + 2 * 86400000, received: 10, sent: 5, internal: 20 }); assert.equal(s.series[0].received, 0);
  assert.equal(s.spam.total, 64); assert.deepEqual(s.spam.by_action, { quarantined: 60, delivered: 4 }); assert.equal(s.spam.share_of_inbound_pct, 16); assert.equal(s.phishing.total, 7);
  assert.equal(s.top_received_domains[0].domain, 'partner.test'); assert.equal(s.top_sent_domains[0].n, 12);
  const tot = h.calls.find((c) => c.tag === 'ms_tot');
  assert.match(tot.sql, /uniqExactIf/); assert.ok(!tot.sql.includes('corpgroup.test'), 'domains are a parameter'); assert.deepEqual(tot.params.d.value, ['corpgroup.test', 'corpgroup-ksa.test']);
  assert.match(tot.sql, /action = 'send'.*arrayExists/s, 'sent = an internal sender with an outside recipient');
  assert.deepEqual(h.audits.at(-1), { a: 'mail.stats.view', t: 'mail', d: { range: 7, domains: 2, source: 'exchange' } });
  assert.equal((await h.call({ range: '1', domains: 'corpgroup.test' })).body.series.length, 24, 'hourly for one day');
});

test('mail stats without Exchange: gateway counts, internal not available; nothing connected; validation', async () => {
  let r = await harness({ ms_gw: [{ dir: 'inbound', n: 400 }, { dir: 'outbound', n: 90 }] }).call({ range: '30', domains: 'corpgroup.test' });
  assert.equal(r.body.source, 'gateway'); assert.deepEqual(r.body.totals, { received_external: 400, sent_external: 90, internal: null }); assert.match(r.body.note, /cannot be counted/);
  r = await harness({ ms_ex: [{ n: 10 }], ms_gw: [{ dir: 'inbound', n: 5 }] }).call({});
  assert.equal(r.body.source, 'gateway'); assert.match(r.body.note, /no mail domains were given/);
  r = await harness({}).call({ domains: 'corpgroup.test' });
  assert.equal(r.body.source, 'none'); assert.equal(r.body.totals.received_external, null, 'nothing connected: null, never 0'); assert.equal(r.body.spam.share_of_inbound_pct, null);
  const bad = await harness({}).call({ domains: "x.test');DROP" }); assert.equal(bad.status, 400);
  const many = await harness({}).call({ domains: Array.from({ length: 21 }, (_, i) => 'd' + i + '.test').join(',') }); assert.equal(many.status, 400);
});
