// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Exchange Reports - mail traffic (engine/soc/mailstats.js GET /mail/traffic) and the ActiveSync device fields of the IIS
// parser (engine/parse/iis.js): unique messages by status, failure reasons with addresses masked, internal / Internet,
// one partner domain, by hour / weekday, size distribution, top senders and recipients BY ADDRESS for administrators only,
// every value a parameter, validation (400 naming the field), audit, nothing connected. Stub ClickHouse; SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const ms = require('../engine/soc/mailstats');
const iis = require('../engine/parse/iis');

const NOW = Date.UTC(2026, 10, 13, 9, 0);
function harness(answers) {
  const calls = [], routes = {}, audits = [];
  const ch = { query: async (sql, params) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; calls.push({ tag, sql, params }); return (answers[tag] || []).map((r) => Object.assign({}, r)); } };
  ms.register({ route: (m, p, fn) => { routes[m + ' ' + p] = fn; } }, { ch, now: () => NOW, config: {} });
  const call = async (query, role = 'viewer') => {
    let out = null;
    const ctx = { query, role, user: role + '.syn', ok: (b) => { out = { status: 200, body: b }; return out; }, fail: (s, m) => { out = { status: s, error: m }; return out; }, audit: (a, t, d) => audits.push({ a, t, d }) };
    await routes['GET /api/soc/mail/traffic'](ctx);
    return out;
  };
  return { calls, call, audits };
}
const A = {
  tr_ex: [{ n: 9000 }], tr_status: [{ a: 'receive', n: 3000 }, { a: 'deliver', n: 2600 }, { a: 'send', n: 500 }, { a: 'fail', n: 40 }, { a: 'defer', n: 12 }, { a: 'dsn', n: 30 }],
  tr_reasons: [{ reason: '550 5.1.1 RESOLVER.ADR.RecipNotFound; not found <address>', a: 'fail', n: 25 }, { reason: '452 4.3.1 Insufficient system resources', a: 'defer', n: 12 }],
  tr_series: [{ k: 0, rcv: 400, dlv: 380, snd: 70, fl: 5 }, { k: 6, rcv: 450, dlv: 420, snd: 80, fl: 9 }], tr_hours: [{ h: 9, n: 800 }, { h: 23, n: 10 }], tr_dow: [{ d: 7, n: 900 }, { d: 5, n: 50 }],
  tr_sizes: [{ k: 0, n: 1000, bytes: 5 * 1048576 }, { k: 3, n: 100, bytes: 300 * 1048576 }, { k: 6, n: 2, bytes: 60 * 1048576 }], tr_split: [{ r: 1200, i: 1400, s: 450 }], tr_domain: [{ rf: 30, st: 44, fl: 2 }],
  tr_senders: [{ a: 'alice.syn@corp-synth.sa', n: 120, bytes: 50 * 1048576 }], tr_rcpts: [{ a: 'partner@audit-synth.example', n: 40 }],
};

test('traffic: counts for every role, addresses for administrators only, partner domain, reasons, hours, sizes', async () => {
  const h = harness(A);
  const v = await h.call({ range: '7', domains: 'corp-synth.sa', domain: 'audit-synth.example' }, 'operator');
  assert.equal(v.status, 200); const t = v.body;
  assert.deepEqual(t.status, { received: 3000, delivered: 2600, sent: 500, failed: 40, deferred: 12, dsn: 30, dropped: 0 });
  assert.deepEqual(t.split, { received_external: 1200, sent_external: 450, internal: 1400 });
  assert.deepEqual(t.partner, { domain: 'audit-synth.example', received_from: 30, sent_to: 44, failed_to: 2 });
  assert.equal(t.reasons[0].code, '5.1.1'); assert.equal(t.reasons[1].code, '4.3.1'); assert.match(t.reasons[0].reason, /<address>/);
  assert.equal(t.series.length, 7); assert.deepEqual(t.series[6], { t: t.from + 6 * 86400000, received: 450, delivered: 420, sent: 80, failed: 9 });
  assert.equal(t.by_hour.length, 24); assert.equal(t.by_hour[9].n, 800); assert.equal(t.by_weekday[6].day, 'Sun'); assert.equal(t.by_weekday[6].n, 900);
  assert.equal(t.sizes.length, 7); assert.equal(t.sizes[6].n, 2); assert.equal(t.average_kb, Math.round((365 * 1048576) / 1102 / 102.4) / 10);
  assert.equal(t.named, false); assert.equal(t.top_senders, null); assert.equal(t.top_recipients, null); assert.match(t.note, /administrators only/);
  assert.ok(!h.calls.some((c) => c.tag === 'tr_senders' || c.tag === 'tr_rcpts'), 'addresses are not even read for an operator');
  const rs = h.calls.find((c) => c.tag === 'tr_reasons');
  assert.match(rs.sql, /replaceRegexpAll\(fields\['recipient_status'\]/, 'addresses in the SMTP reason are masked in the store query');
  assert.ok(!h.calls.some((c) => /subject/i.test(c.sql)), 'subjects are never read');
  const st = h.calls.find((c) => c.tag === 'tr_status'); assert.ok(!st.sql.includes('audit-synth.example') && !st.sql.includes('corp-synth.sa'), 'domains are parameters');
  assert.equal(st.params.pd.value, 'audit-synth.example'); assert.deepEqual(st.params.d.value, ['corp-synth.sa']);
  assert.deepEqual(h.audits.at(-1), { a: 'mail.traffic.view', t: 'audit-synth.example', d: { range: 7, domains: 1, dir: 'all', named: false } });
  const a = (await h.call({ range: '30', domains: 'corp-synth.sa', dir: 'in', limit: '10' }, 'admin')).body;
  assert.equal(a.named, true); assert.equal(a.top_senders[0].address, 'alice.syn@corp-synth.sa'); assert.equal(a.top_senders[0].mb, 50); assert.equal(a.top_recipients[0].n, 40);
  const snd = h.calls.filter((c) => c.tag === 'tr_senders').at(-1); assert.match(snd.sql, /AND NOT has\(\{d:Array\(String\)\}/, 'inbound = senders outside our domains'); assert.equal(snd.params.lim.value, 10);
  assert.equal(a.series.length, 30);
});

test('traffic: validation names the field; nothing connected says what to forward', async () => {
  const h = harness({});
  for (const [q, re] of [[{ range: '365' }, /^range must be one of/], [{ domains: "x.test');DROP" }, /^domains: invalid domain/], [{ domain: 'not a domain' }, /^domain must be a domain/],
    [{ dir: 'in' }, /^dir needs domains/], [{ dir: 'sideways', domains: 'corp-synth.sa' }, /^dir must be one of/], [{ limit: '1000' }, /^limit must be at most 100/]]) {
    const r = await h.call(q); assert.equal(r.status, 400, JSON.stringify(q)); assert.match(r.error, re);
  }
  const r = await h.call({ domains: 'corp-synth.sa' });
  assert.equal(r.body.exchange, false); assert.match(r.body.note, /forward the MSGTRK logs/); assert.equal(r.body.average_kb, null, 'no messages: unknown, not 0');
});

test('IIS: ActiveSync command, device id and type kept from the query; OWA untouched; malformed values dropped', () => {
  const line = (stem, q, user, status) => `2026-11-13 08:00:00 10.0.1.20 POST ${stem} ${q} 443 ${user} 203.0.113.9 Apple-iPhone15C2/2104 - ${status} 0 0 31`;
  const e = iis.parse(line('/Microsoft-Server-ActiveSync/default.eas', 'Cmd=Sync&User=CORP%5Calice.syn&DeviceId=ABCDEF0123&DeviceType=iPhone&Log=V161_Sst5', 'CORP\\alice.syn', 200), { src_type: 'iis' });
  assert.ok(e.tags.includes('exchange-microsoft-server-activesync'));
  assert.equal(e.fields.eas_cmd, 'Sync'); assert.equal(e.fields.eas_device_id, 'ABCDEF0123'); assert.equal(e.fields.eas_device_type, 'iPhone'); assert.equal(e.user, 'alice.syn');
  const bad = iis.parse(line('/Microsoft-Server-ActiveSync/default.eas', 'Cmd=Sync&DeviceId=<script>&DeviceType=%E0%A4%A', '-', 401), { src_type: 'iis' });
  assert.equal(bad.fields.eas_device_id, undefined, 'not an identifier: dropped'); assert.equal(bad.fields.eas_device_type, undefined, 'malformed escape: dropped'); assert.equal(bad.fields.eas_cmd, 'Sync');
  const b64 = iis.parse(line('/Microsoft-Server-ActiveSync/default.eas', 'jAAJBAp2MTQwRGV2aWNl', '-', 200), { src_type: 'iis' });
  assert.equal(b64.fields.eas_cmd, undefined, 'the base64 form is left alone');
  const owa = iis.parse(line('/owa/auth.owa', '-', 'CORP\\bob.syn', 302), { src_type: 'iis' });
  assert.ok(owa.tags.includes('exchange-owa')); assert.equal(owa.fields.eas_cmd, undefined); assert.equal(owa.http_method, 'POST');
});
