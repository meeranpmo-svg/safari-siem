// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Mail server reputation (engine/mail-reputation.js, pyengine/mail_rep_rules.py): targets from Domains & Hosting (MX
// addresses, SPF ip4) and registered IPs, Spamhaus ZEN / DBL answers classified, refusals shown as "not checked" (never
// clean), provider-managed addresses, the DQS key admin-only and sealed (never returned or logged), roles, validation,
// audit. DNS is an injected resolver; addresses are the RFC 5737 documentation ranges. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const PY = process.env.PYTHON || 'python3';
let clock = Date.parse('2026-10-26T08:00:00Z');
const now = () => clock;
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' };
// DNS publishes the SPF the stored Domains & Hosting check saw, unless a test sets state.txt itself (the route map reads SPF live)
function published(state, name) {
  if (!state.store) return null;
  const d = state.store.collection('dom_domains').all().find((x) => x.name === name); if (!d) return null;
  const rec = (state.store.collection('dom_checks').get('d:' + d.id) || {}).records || {};
  return rec.SPF && rec.SPF.length ? rec.SPF : null;
}
function resolver(state) {
  const A = { 'mx1.corpgroup.test': ['203.0.113.10'], 'corpgroup-test.mail.protection.outlook.com': ['198.51.100.20'] };
  return { queries: state.q,
    async resolveTxt(name) { const t = (state.txt || {})[name] || published(state, name); if (t) return t.map((x) => [x]); throw Object.assign(new Error('nf'), { code: 'ENOTFOUND' }); },
    async resolveMx(name) { throw Object.assign(new Error('nf'), { code: 'ENOTFOUND' }); },
    async resolveCname(name) { const c = (state.cname || {})[name]; if (c) return [c]; throw Object.assign(new Error('nf'), { code: 'ENODATA' }); },
    async reverse(ip) { const p = (state.ptr || {})[ip]; if (p) return p; throw Object.assign(new Error('nf'), { code: 'ENOTFOUND' }); },
    async resolve4(name) {
    state.q.push(name);
    if (state.a && state.a[name]) return state.a[name];   // read on each lookup so a test can change DNS between checks
    if (A[name]) return A[name];
    const ans = state.answers[name.replace(/^(.*?)\.(?:[a-z0-9]{20,40}\.)?(zen|dbl)\..*$/, '$1|$2')];
    if (ans) return ans;
    throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
  } };
}
const sealer = { seal: (id, t) => 'SEALED:' + Buffer.from(t).toString('base64'), unseal: (id, e) => Buffer.from(String(e).slice(7), 'base64').toString() };
const probe = (state) => async (host) => (state.smtp || {})[host] || { connected: true, banner: '220 ' + host + ' ESMTP', ehlo: true, starttls: true };
async function setup(t, answers) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const st = { q: [], answers: answers || {} };
  e.app.store.collection('dom_domains').put({ id: 'D1', name: 'corpgroup.test', status: 'active' });
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { MX: ['10 mx1.corpgroup.test', '20 corpgroup-test.mail.protection.outlook.com'], SPF: ['v=spf1 ip4:192.0.2.8 ip4:192.0.2.0/24 include:spf.protection.outlook.com -all'], DMARC: ['v=DMARC1; p=none; rua=mailto:d@corpgroup.test'], DKIM: { selector1: false } } });
  st.store = e.app.store; registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, mailResolver: resolver(st), mailSealer: sealer, mailTestNets: true, mailSmtpProbe: probe(st) });
  return { e, st };
}
const post = (e, p, body, who = OP) => e.req('POST', p, Object.assign({ body }, who));

test('targets from MX and SPF, listings classified with advice, provider-managed addresses, DBL for the domain', async (t) => {
  const { e, st } = await setup(t, { '10.113.0.203|zen': ['127.0.0.4'], '8.2.0.192|zen': ['127.0.0.11'], 'corpgroup.test|dbl': ['127.0.1.104'], '20.100.51.198|zen': ['127.0.0.2'] });
  assert.equal((await e.req('GET', '/mail-reputation', VW)).json.last, null, 'nothing checked yet - nothing invented');
  assert.equal((await post(e, '/mail-reputation/check', {}, VW)).status, 403);
  const r = await post(e, '/mail-reputation/check', {}); assert.equal(r.status, 200, r.raw);
  const L = r.json.last, by = (x) => L.rows.find((y) => y.target === x);
  assert.equal(by('203.0.113.10').state, 'listed'); assert.equal(by('203.0.113.10').severity, 'critical'); assert.ok(by('203.0.113.10').advice.some((a) => /compromise/.test(a)));
  assert.equal(by('192.0.2.8').lists[0].list, 'PBL'); assert.deepEqual(by('192.0.2.8').roles, ['outbound']);
  assert.equal(by('198.51.100.20').provider, 'Microsoft 365 / Exchange Online Protection'); assert.match(by('198.51.100.20').advice[0], /provider|Microsoft/);
  assert.equal(by('corpgroup.test').kind, 'domain'); assert.equal(by('corpgroup.test').severity, 'critical');
  assert.equal(L.counts.listed, 4); assert.equal(L.rows[0].state, 'listed');
  assert.ok(L.notes.some((n) => /256 addresses/.test(n)) && L.notes.some((n) => /Microsoft 365/.test(n)), 'large SPF range and Microsoft-managed sending explained');
  assert.ok(st.q.some((q) => q === '10.113.0.203.zen.spamhaus.org'), 'public zone without a DQS key');
  assert.equal(L.findings.find((f) => f.key === 'mailrep:198.51.100.20').severity, 'medium', 'provider-managed listing is not ours to fix');
  assert.ok(e.app.store.auditTail(10).some((x) => x.action === 'mailrep.check'));
});

test('refused queries are "not checked", never clean; DQS key is admin-only, sealed, never returned or logged', async (t) => {
  const { e, st } = await setup(t, { '10.113.0.203|zen': ['127.255.255.254'], '8.2.0.192|zen': ['127.255.255.254'], '20.100.51.198|zen': ['127.255.255.254'], 'corpgroup.test|dbl': ['127.0.1.255'] });
  let L = (await post(e, '/mail-reputation/check', {})).json.last;
  assert.equal(L.counts.clean, 0); assert.equal(L.counts.not_checked, 4); assert.match(L.warning, /DQS/);
  const key = 'abcdefghij0123456789abcdef';
  assert.equal((await post(e, '/mail-reputation/key', { key }, OP)).status, 403);
  assert.equal((await post(e, '/mail-reputation/key', { key: 'BAD KEY!' }, ADM)).status, 400);
  assert.equal((await post(e, '/mail-reputation/key', {}, ADM)).status, 400);
  assert.equal((await post(e, '/mail-reputation/key', { key }, ADM)).json.dqs_configured, true);
  const v = await e.req('GET', '/mail-reputation', ADM); assert.equal(v.json.dqs_configured, true); assert.ok(!JSON.stringify(v.json).includes(key), 'key never returned');
  assert.ok(!JSON.stringify(e.app.store.collection('mailrep').get('dqs')).includes(key), 'stored sealed');
  assert.ok(!JSON.stringify(e.app.store.auditTail(20)).includes(key), 'not in the audit trail');
  st.answers = {}; L = (await post(e, '/mail-reputation/check', {})).json.last;
  assert.ok(st.q.some((q) => q === '10.113.0.203.' + key + '.zen.dq.spamhaus.net'), 'DQS zone with the key'); assert.equal(L.counts.clean, 4); assert.equal(L.dqs, true);
  assert.equal((await post(e, '/mail-reputation/key', { clear: true }, ADM)).json.dqs_configured, false);
});

test('registered IPs: validation, duplicates, retire; changes since the last run recorded', async (t) => {
  const { e, st } = await setup(t, {});
  assert.equal((await post(e, '/mail-reputation/ips', { ip: '2001:db8::1', label: 'v6' })).status, 400);
  assert.equal((await post(e, '/mail-reputation/ips', { ip: '192.0.2.50' })).status, 400, 'label required');
  assert.equal((await post(e, '/mail-reputation/ips', { ip: '192.0.2.50', label: 'gateway egress' }, VW)).status, 403);
  assert.equal((await post(e, '/mail-reputation/ips', { ip: '192.0.2.50', label: 'gateway egress' }, { user: 'system:x', role: 'operator' })).status, 403);
  const r = await post(e, '/mail-reputation/ips', { ip: '192.0.2.50', label: 'gateway egress', role: 'outbound' }); assert.equal(r.status, 200);
  assert.equal((await post(e, '/mail-reputation/ips', { ip: '192.0.2.50', label: 'again' })).status, 409);
  let L = (await post(e, '/mail-reputation/check', {})).json.last; assert.equal(L.rows.find((x) => x.target === '192.0.2.50').state, 'clean');
  st.answers = { '50.2.0.192|zen': ['127.0.0.3'] };
  L = (await post(e, '/mail-reputation/check', {})).json.last;
  assert.deepEqual(L.changes, [{ target: '192.0.2.50', from: 'clean', to: 'listed' }]); assert.equal(L.rows[0].lists[0].list, 'CSS');
  assert.equal((await post(e, '/mail-reputation/ips/MIP-001/retire', {})).status, 400, 'reason required');
  assert.equal((await post(e, '/mail-reputation/ips/MIP-001/retire', { reason: 'replaced' })).json.status, 'retired');
  assert.equal((await e.req('GET', '/mail-reputation', VW)).json.registered.length, 0);
  const a = e.app.store.auditTail(20).map((x) => x.action); assert.ok(a.includes('mailrep.ip.add') && a.includes('mailrep.ip.retire'));
});

test('mail route: inbound and outbound hops from DNS facts and SIEM counts, issues with fixes, profile, validation', async (t) => {
  const { e, st } = await setup(t, {});
  assert.equal((await e.req('GET', '/mail-route', VW)).json.lanes, null, 'not checked yet');
  st.smtp = { 'mx1.corpgroup.test': { connected: true, banner: '220 mx1 ESMTP', ehlo: true, starttls: false } };
  st.ptr = { '198.51.100.77': ['198-51-100-77.dsl.isp.test'] };
  st.txt = { 'spf.protection.outlook.com': ['v=spf1 ip4:40.92.0.0/15 -all'] };
  await post(e, '/mail-reputation/ips', { ip: '198.51.100.77', label: 'gateway egress', role: 'outbound' });
  assert.equal((await post(e, '/mail-route/profile', { expected_mx: ['bad host!'] })).status, 400);
  assert.equal((await post(e, '/mail-route/profile', { expected_mx: ['gw.corpgroup.test'] }, VW)).status, 403);
  assert.equal((await post(e, '/mail-route/profile', { expected_mx: ['GW.corpgroup.test.'] })).json.expected_mx[0], 'gw.corpgroup.test');
  await post(e, '/mail-reputation/check', {});
  let r = (await e.req('GET', '/mail-route', VW)).json;
  const hop = (lane, id) => r.lanes[lane].find((h) => h.id === id), has = (rx) => r.issues.some((i) => rx.test(i.title));
  assert.equal(hop('inbound', 'mx').state, 'bad'); assert.ok(has(/not the email gateway/), 'MX bypassing the gateway');
  assert.ok(has(/does not offer STARTTLS/)); assert.ok(has(/no MTA-STS/)); assert.ok(has(/no TLS-RPT/));
  assert.equal(hop('inbound', 'gateway_in').state, 'not_connected', 'no SIEM counts - not connected, never healthy');
  assert.ok(has(/198\.51\.100\.77 is not authorised by the SPF/)); assert.ok(has(/does not resolve back/)); assert.ok(has(/generic \/ dynamic/));
  assert.ok(has(/DMARC is p=none/)); assert.ok(has(/no DKIM key/));
  assert.equal(hop('outbound', 'egress').state, 'bad');
  const siem = { gateway_in: { delivered: 900, blocked: 100 }, gateway_out: { delivered: 50, blocked: 10 }, exchange: { receive: 0, deliver: 0, send: 40, submit: 40, fail: 9, defer: 3, dsn: 9 },
    exchange_reasons: [{ value: '550 5.7.606 Access denied, banned sending IP [198.51.100.77]', n: 6 }, { value: '451 4.4.1 Connection timed out', n: 3 }] };
  assert.equal((await post(e, '/mail-route', { siem: { exchange: { send: -1 } } }, VW)).status, 400);
  assert.equal((await post(e, '/mail-route', { siem: { exchange_reasons: [{ value: 5, n: 1 }] } }, VW)).status, 400);
  r = (await post(e, '/mail-route', { siem }, VW)).json;
  assert.ok(has(/gateway delivered mail but Exchange logged nothing received/));
  assert.ok(has(/sending IP is blocked by the receiver \(6\)/) && has(/Could not connect \/ timed out/));
  assert.ok(has(/gateway stopped 10 of 60 outbound/)); assert.ok(has(/non-delivery reports/));
  assert.equal(hop('inbound', 'gateway_in').state, 'ok'); assert.equal(hop('outbound', 'exchange_out').state, 'bad');
  assert.ok(r.issues[0].fix.length >= 1 && ['critical', 'high'].includes(r.issues[0].severity), 'worst first, each with a fix');
  assert.ok(e.app.store.auditTail(20).some((x) => x.action === 'mailrep.route.profile'));
});

test('mail route outage: a hop that normally carries mail but nothing in the last hour is down and is where the lane is blocked', async (t) => {
  const { e } = await setup(t, {});
  await post(e, '/mail-reputation/check', {});
  const siem = { gateway_in: { delivered: 800, blocked: 50 }, gateway_out: { delivered: 120 }, exchange: { receive: 700, deliver: 690, send: 110, submit: 115 },
    recent: { gateway_in: 30, gateway_out: 5, exchange_receive: 0, exchange_send: 4, exchange_deliver: 0 } };
  assert.equal((await post(e, '/mail-route', { siem: { recent: { exchange_receive: 'x' } } }, VW)).status, 400);
  const r = (await post(e, '/mail-route', { siem }, VW)).json;
  const hop = (id) => r.lanes.inbound.find((h) => h.id === id);
  assert.equal(hop('exchange_in').state, 'down'); assert.equal(hop('gateway_in').state, 'ok');
  assert.equal(r.blocked.inbound.hop, 'exchange_in'); assert.match(r.blocked.inbound.reason, /No mail through Exchange receive in the last hour/);
  assert.ok(r.blocked.inbound.fix.some((f) => /receive connector/.test(f)));
  assert.equal(r.issues[0].severity, 'critical');
  assert.notEqual((r.blocked.outbound || {}).state, 'down', 'outbound still flowing');
});


test('availability: minute probes, an outage recorded, budget against 99.99%, not measurable when no MX ever answered, target admin-only', async (t) => {
  const { e, st } = await setup(t, {});
  const M = e.app.addons.mailReputation;
  assert.equal(await M.probeOnce(), null, 'no route facts yet - nothing probed');
  await post(e, '/mail-reputation/check', {});
  st.smtp = { 'mx1.corpgroup.test': { connected: false, error: 'ECONNREFUSED' }, 'corpgroup-test.mail.protection.outlook.com': { connected: false, error: 'ETIMEDOUT' } };
  for (let i = 0; i < 5; i++) { clock += 60000; await M.probeOnce(); }
  let a = (await e.req('GET', '/mail-availability', VW)).json;
  assert.equal(a.windows[0].state, 'not_measurable', 'never answered from here: not measurable, never 0%'); assert.equal(a.windows[0].availability, null);
  st.smtp = {};
  for (let i = 0; i < 100; i++) { clock += 60000; await M.probeOnce(); }
  st.smtp = { 'mx1.corpgroup.test': { connected: false, error: 'ECONNREFUSED' }, 'corpgroup-test.mail.protection.outlook.com': { connected: true, banner: '421 busy' } };
  for (let i = 0; i < 3; i++) { clock += 60000; await M.probeOnce(); }
  a = (await e.req('GET', '/mail-availability', VW)).json; assert.equal(a.current.up, false); assert.ok(a.current.down_since);
  st.smtp = { 'mx1.corpgroup.test': { connected: false, error: 'ECONNREFUSED' } };   // one MX up is enough
  clock += 60000; await M.probeOnce();
  a = (await e.req('GET', '/mail-availability', VW)).json;
  assert.equal(a.target, 99.99); assert.equal(a.current.up, true);
  assert.equal(a.windows[0].down_minutes, 8, '5 early + 3 outage minutes are down'); assert.equal(a.windows[0].allowed_minutes, 4.3);
  assert.equal(a.windows[0].state, 'breached'); assert.equal(a.windows[0].partial, true);
  assert.equal(a.outages[0].minutes, 3); assert.ok(a.outages[0].hosts.some((h) => /ECONNREFUSED/.test(h)));
  assert.ok(a.gaps.some((g) => /99.99% allows 4.3 minutes/.test(g.title)) && a.gaps.some((g) => /inside the network/.test(g.title)));
  assert.equal((await post(e, '/mail-availability/target', { target: 99.9 }, OP)).status, 403);
  assert.equal((await post(e, '/mail-availability/target', { target: 99 }, ADM)).status, 400);
  assert.equal((await post(e, '/mail-availability/target', { target: 99.9 }, ADM)).json.target, 99.9);
  a = (await e.req('GET', '/mail-availability', VW)).json; assert.equal(a.windows[0].allowed_minutes, 43.2); assert.equal(a.windows[0].state, 'met');
  assert.ok(e.app.store.auditTail(10).some((x) => x.action === 'mailrep.availability.target'));
});

test('regulator report: SAMA / IA draft from recorded outages, attack counts and findings; missing items listed; CISO approves four-eyes on the digest', async (t) => {
  const { e, st } = await setup(t, {});
  const M = e.app.addons.mailReputation;
  await post(e, '/mail-reputation/check', {});
  for (let i = 0; i < 20; i++) { clock += 60000; await M.probeOnce(); }
  const t0 = new Date(clock).toISOString();
  st.smtp = { 'mx1.corpgroup.test': { connected: false, error: 'ECONNREFUSED' }, 'corpgroup-test.mail.protection.outlook.com': { connected: false, error: 'ETIMEDOUT' } };
  for (let i = 0; i < 7; i++) { clock += 60000; await M.probeOnce(); }
  st.smtp = {}; clock += 60000; await M.probeOnce();
  const t1 = new Date(clock + 60000).toISOString();
  const OPR = { user: 'nora.syn', role: 'operator' }, CISO = { user: 'ciso.syn', role: 'admin' };
  assert.equal((await post(e, '/mail-report', { regulator: 'sama', kind: 'both', from: t0, to: t1 }, VW)).status, 403);
  assert.equal((await post(e, '/mail-report', { regulator: 'cma', kind: 'both', from: t0, to: t1 }, OPR)).status, 400);
  assert.equal((await post(e, '/mail-report', { regulator: 'sama', kind: 'both', from: t1, to: t0 }, OPR)).status, 400);
  assert.equal((await post(e, '/mail-report', { regulator: 'sama', kind: 'both', from: '2026-10-26', to: t1 }, OPR)).status, 400, 'zone required');
  assert.equal((await post(e, '/mail-report', { regulator: 'sama', kind: 'both', from: t0, to: t1, siem: { threats: { delivered: -1 } } }, OPR)).status, 400);
  const r = await post(e, '/mail-report', { regulator: 'sama', kind: 'both', from: t0, to: t1, notes: { actions: 'Gateway service restarted by the on-call engineer.' },
    siem: { threats: { blocked: 40, quarantined: 5, delivered: 2 }, gateway: { delivered: 900 }, top_threats: [{ v: 'Phish.Invoice', n: 12 }], countries: [{ name: 'CN', allow: 3, deny: 40 }] } }, OPR);
  assert.equal(r.status, 200, JSON.stringify(r.json)); const d = r.json.doc;
  assert.match(d.title, /SAMA/); assert.equal(r.json.state, 'draft');
  const all = JSON.stringify(d);
  assert.match(all, /unavailable for 7 minutes in 1 outage/); assert.match(all, /47 phishing \/ malware messages; 2 were delivered/);
  assert.match(all, /Phish\.Invoice \(12\)/); assert.match(all, /T1566/); assert.match(all, /Gateway service restarted/);
  assert.ok(d.missing.includes('Business and customer impact') && d.missing.includes('Root cause after investigation') && !d.missing.includes('Containment and recovery actions taken'));
  assert.match(d.statement, /not sent from the platform/);
  const ia = (await post(e, '/mail-report', { regulator: 'ia', kind: 'attack', from: t0, to: t1 }, OPR)).json;
  assert.match(ia.doc.title, /Insurance Authority/); assert.ok(ia.doc.missing.some((m) => /SIEM did not return/.test(m)), 'no SIEM counts: said, not invented');
  assert.equal((await e.req('GET', '/mail-report', VW)).status, 403);
  assert.equal((await e.req('GET', '/mail-report', OPR)).json.reports.length, 2);
  assert.equal((await post(e, '/mail-report/' + r.json.id + '/approve', { digest: r.json.digest }, OPR)).status, 403, 'operator cannot approve');
  assert.equal((await post(e, '/mail-report/' + r.json.id + '/approve', { digest: r.json.digest }, { user: 'nora.syn', role: 'admin' })).status, 403, 'preparer cannot approve');
  assert.equal((await post(e, '/mail-report/' + r.json.id + '/approve', { digest: 'sha256:' + '0'.repeat(64) }, CISO)).status, 409, 'digest must match');
  const ap = await post(e, '/mail-report/' + r.json.id + '/approve', { digest: r.json.digest }, CISO);
  assert.equal(ap.json.state, 'approved'); assert.equal(ap.json.approved_by, 'ciso.syn');
  assert.equal((await post(e, '/mail-report/' + r.json.id + '/approve', { digest: r.json.digest }, CISO)).status, 409);
  const a = e.app.store.auditTail(20).map((x) => x.action); assert.ok(a.includes('mailrep.report.prepare') && a.includes('mailrep.report.approve'));
});

test('Cloudflare DNS, hybrid and two ISP links: proxied MX / autodiscover, Email Routing, Microsoft SPF and DKIM, second-link MX', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const st = { q: [], answers: {}, a: { 'mx1.corpgroup.test': ['104.16.10.10'], 'autodiscover.corpgroup.test': ['172.67.1.1'] }, cname: {} };
  e.app.store.collection('dom_domains').put({ id: 'D1', name: 'corpgroup.test', status: 'active' });
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { NS: ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'], MX: ['10 mx1.corpgroup.test'], SPF: ['v=spf1 ip4:192.0.2.8 -all'], DMARC: ['v=DMARC1; p=reject'] } });
  st.store = e.app.store; registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, mailResolver: resolver(st), mailSealer: sealer, mailTestNets: true, mailSmtpProbe: probe(st) });
  assert.equal((await post(e, '/mail-route/profile', { platform: 'cloud' })).status, 400);
  assert.equal((await post(e, '/mail-route/profile', { isp_links: 9 })).status, 400);
  const pr = (await post(e, '/mail-route/profile', { platform: 'hybrid', isp_links: 2 })).json;
  assert.equal(pr.platform, 'hybrid'); assert.equal(pr.isp_links, 2);
  await post(e, '/mail-reputation/check', {});
  const r = (await e.req('GET', '/mail-route', VW)).json, has = (rx) => r.issues.some((i) => rx.test(i.title));
  assert.equal(r.platform, 'hybrid'); assert.equal(r.profile.isp_links, 2);
  assert.ok(has(/resolves to a Cloudflare proxy address/), 'proxied MX host'); assert.equal(r.issues[0].severity, 'critical');
  assert.ok(has(/autodiscover is proxied by Cloudflare/)); assert.ok(has(/DNS is hosted at Cloudflare/));
  assert.ok(has(/SPF does not include Microsoft 365/)); assert.ok(has(/DKIM selectors not published \(selector1, selector2\)/));
  assert.ok(has(/hybrid mail flow - decide where MX points/));
  assert.ok(has(/Two Internet links but every MX address is on one of them/));
  assert.equal(r.lanes.inbound.find((h) => h.id === 'mx').state, 'bad');
  // the route map's topology: DNS host, MX hosts per public network, a declared second link with nothing on it is "unused"
  const T = r.topology;
  assert.equal(T.dns.provider, 'Cloudflare'); assert.equal(T.exo, true); assert.equal(T.declared_links, 2);
  assert.equal(T.mx[0].host, 'mx1.corpgroup.test'); assert.equal(T.mx[0].proxied, true); assert.deepEqual(T.mx[0].links, [0]);
  assert.equal(T.links[0].network, '104.16.10.0/24'); assert.equal(T.links[1].state, 'unused'); assert.equal(T.states.mx, 'bad');
  // Email Routing, and the fixes cleared
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { NS: ['ada.ns.cloudflare.com'], MX: ['10 route1.mx.cloudflare.net', '20 mx2.corpgroup.test'], SPF: ['v=spf1 ip4:192.0.2.8 include:spf.protection.outlook.com -all'], DMARC: ['v=DMARC1; p=reject'] } });
  st.a = { 'route1.mx.cloudflare.net': ['198.51.100.200'], 'mx2.corpgroup.test': ['203.0.113.30'], 'autodiscover.corpgroup.test': ['192.0.2.9'] };
  st.cname = { 'selector1._domainkey.corpgroup.test': 'selector1-corpgroup-test._domainkey.corpgrouptest.onmicrosoft.com', 'selector2._domainkey.corpgroup.test': 'selector2-corpgroup-test._domainkey.corpgrouptest.onmicrosoft.com' };
  const e2 = (await post(e, '/mail-reputation/check', {})).status; assert.equal(e2, 200);
  const r2 = (await e.req('GET', '/mail-route', VW)).json, has2 = (rx) => r2.issues.some((i) => rx.test(i.title));
  assert.ok(has2(/Cloudflare Email Routing/)); assert.ok(!has2(/SPF does not include Microsoft 365/)); assert.ok(!has2(/DKIM selectors not published/));
  assert.ok(!has2(/autodiscover is proxied/)); assert.ok(!has2(/Two Internet links/), 'MX now on two networks');
  assert.equal(r2.topology.mx.find((m) => m.host === 'route1.mx.cloudflare.net').cf_routing, true);
  assert.ok(r2.topology.links.filter((l) => l.mx.length).length === 2, 'each MX on its own link');
});

test('mail servers and early warnings: register validated, NAT mapping, SMTP certificate expiry, DNS change, Exchange health from the SIEM, alert mail to the mail team', async (t) => {
  const { e, st } = await setup(t);
  const calls = [];
  let siemDown = false;
  const siem = { call: async (m, p, who, b) => {
    calls.push({ m, p, who: who.user, role: who.role, b });
    if (siemDown) throw new Error('SIEM not reachable (ECONNREFUSED)');
    if (p.startsWith('/sysadmin/overview')) return { status: 200, json: { servers: 2, checked: 2, findings: [{ server: 'S1', server_name: 'EX01', scope: 'exchange', severity: 'high', kind: 'ex-queue', title: 'Mail queue EX01\\Submission: 150 messages, Retry', evidence: ['last error 451'], recommendation: 'Check the next hop' }] } };
    if (p === '/mail/notify/send') return { status: 200, json: { ok: true, recipients: 2 } };
    return { status: 404, json: { error: 'nf' } };
  } };
  e.app.discovery = Object.assign({}, e.app.discovery || {}, { siem });   // the loopback link to the SIEM (read lazily)
  // validation
  const bad = async (servers, rx) => { const r = await post(e, '/mail-route/profile', { servers }); assert.equal(r.status, 400, JSON.stringify(servers)); assert.match(r.json.error, rx); };
  await bad([{ name: 'GW01', role: 'gateway', private_ip: '203.0.113.10' }], /not an internal address/);
  await bad([{ name: 'GW01', role: 'gateway', public_ips: ['10.0.0.1'] }], /is an internal address/);
  await bad([{ name: 'GW01', role: 'router' }], /role must be one of/);
  await bad([{ name: 'GW01', role: 'gateway' }, { name: 'gw01', role: 'exchange' }], /appears twice/);
  await bad([{ name: 'GW01', role: 'gateway', dns_name: 'bad name' }], /dns_name must be a host name/);
  assert.equal((await post(e, '/mail-route/profile', { servers: [] }, VW)).status, 403, 'viewer cannot edit the register');
  const pr = await post(e, '/mail-route/profile', { servers: [{ name: 'GW01', role: 'gateway', dns_name: 'GW1.corpgroup.test', private_ip: '10.1.2.5', public_ips: ['203.0.113.10'], extra: 'x' }, { name: 'EX01', role: 'exchange', private_ip: '10.1.3.10' }] });
  assert.equal(pr.status, 200); assert.equal(pr.json.servers[0].dns_name, 'gw1.corpgroup.test'); assert.equal(pr.json.servers[0].extra, undefined);
  const pa = e.app.store.auditTail(20).find((x) => x.action === 'mailrep.route.profile'); assert.deepEqual(pa.detail.servers_added, ['GW01', 'EX01']); assert.equal(pa.by, 'nora.syn');
  // first check: certificate near expiry, gw1 public name points elsewhere
  st.a = { 'gw1.corpgroup.test': ['203.0.113.99'] };
  st.smtp = { 'mx1.corpgroup.test': { connected: true, banner: '220 mx1', ehlo: true, starttls: true, tls: { days_left: 9, names: ['mx1.corpgroup.test'], subject: 'mx1.corpgroup.test', issuer: 'Synthetic CA', not_after: '2026-11-04T00:00:00.000Z', trusted: true } } };
  assert.equal((await post(e, '/mail-reputation/check', {})).status, 200);
  let r = (await e.req('GET', '/mail-route', VW)).json;
  const S = r.topology.servers;
  assert.equal(S[0].name, 'GW01'); assert.deepEqual(S[0].mx, ['mx1.corpgroup.test']); assert.equal(S[0].private_ip, '10.1.2.5'); assert.deepEqual(S[0].dns_ips, ['203.0.113.99']);
  assert.ok(r.issues.some((i) => /gw1\.corpgroup\.test \(GW01\) resolves to 203\.0\.113\.99, but its public address is 203\.0\.113\.10/.test(i.title)));
  assert.ok(r.warnings.some((w) => w.key === 'tls-exp:mx1.corpgroup.test' && w.severity === 'high' && w.days_left === 9));
  // second check: MX changed
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { MX: ['10 mx1.corpgroup.test', '30 mx9.corpgroup.test'], SPF: ['v=spf1 ip4:192.0.2.8 include:spf.protection.outlook.com -all'], DMARC: ['v=DMARC1; p=reject'] } });
  st.a['mx9.corpgroup.test'] = ['203.0.113.77'];
  await post(e, '/mail-reputation/check', {});
  r = (await e.req('GET', '/mail-route', VW)).json;
  assert.ok(r.warnings.some((w) => w.key === 'dns-change:corpgroup.test:mx' && /mx9\.corpgroup\.test/.test(w.detail)), 'MX change warned');
  assert.ok(r.issues.some((i) => /MX address 203\.0\.113\.77 \(mx9\.corpgroup\.test\) belongs to no server/.test(i.title)), 'unknown MX address');
  // alerts: viewer refused to run, operator runs; mail sent once through the SIEM as the service identity
  assert.equal((await post(e, '/mail-route/alerts/check', {}, VW)).status, 403);
  let a = (await post(e, '/mail-route/alerts/check', {})).json;
  assert.ok(a.open.some((x) => x.source === 'exchange' && /Mail queue/.test(x.title)), 'Exchange queue from the SIEM');
  assert.ok(a.open.some((x) => /SMTP certificate of mx1\.corpgroup\.test expires in 9 days/.test(x.title)));
  assert.ok(a.open.some((x) => /MX records of corpgroup\.test changed/.test(x.title)));
  const sends = calls.filter((c) => c.p === '/mail/notify/send');
  assert.equal(sends.length, 1); assert.equal(sends[0].who, 'system:itam-mail-route'); assert.equal(sends[0].role, 'admin');
  assert.match(sends[0].b.subject, /^(CRITICAL|HIGH): /); assert.match(sends[0].b.text, /Mail queue/); assert.ok(!/<script/i.test(sends[0].b.html));
  assert.equal(a.state.mail.ok, true);
  const ae = e.app.store.auditTail(30).find((x) => x.action === 'mailrep.alerts.evaluate'); assert.ok(ae && ae.detail.opened.length >= 3 && ae.detail.mailed.ok);
  // re-evaluating does not mail again; the queue fixed in the SIEM clears its alert, a SIEM outage clears nothing
  a = (await post(e, '/mail-route/alerts/check', {})).json;
  assert.equal(calls.filter((c) => c.p === '/mail/notify/send').length, 1, 'no repeat mail');
  siemDown = true;
  a = (await post(e, '/mail-route/alerts/check', {})).json;
  assert.ok(a.open.some((x) => x.source === 'exchange'), 'SIEM unreachable: the Exchange alert stays open');
  assert.ok(a.state.gaps.some((g) => /Exchange health \(SIEM\)/.test(g)));
  // 25 h later, still open: reminded
  siemDown = false; clock += 25 * 3600000;
  await post(e, '/mail-route/alerts/check', {});
  assert.equal(calls.filter((c) => c.p === '/mail/notify/send').length, 2, 'open high alert reminded after 24 h');
  assert.equal((await e.req('GET', '/mail-route/alerts', VW)).status, 200);
});

test('reverse DNS per ISP link, PTR request text, PTR lost, Spamhaus listing and outbound listing risk as early warnings', async (t) => {
  // mx1 (203.0.113.10) listed on XBL; the MX address has a generic ISP PTR; an outbound IP on a second link
  const { e, st } = await setup(t, { '10.113.0.203|zen': ['127.0.0.4'] });
  st.ptr = { '203.0.113.10': ['10-113-0-203.dsl.isp.example'], '198.51.100.40': ['mail.corpgroup.test'] };
  st.a = { '10-113-0-203.dsl.isp.example': ['203.0.113.10'], 'mail.corpgroup.test': ['198.51.100.40'], 'gw1.corpgroup.test': ['203.0.113.10'] };
  await post(e, '/mail-reputation/ips', { ip: '198.51.100.40', label: 'egress link 2', role: 'outbound' });
  await post(e, '/mail-route/profile', { isp_links: 2, servers: [{ name: 'GW01', role: 'gateway', dns_name: 'gw1.corpgroup.test', private_ip: '10.1.2.5', public_ips: ['203.0.113.10'] }] });
  const sends = [], tops = [];
  e.app.discovery = Object.assign({}, e.app.discovery || {}, { siem: { call: async (m, p, who, b) => {
    if (p === '/top') { tops.push(b); if (/email_verdict:\(spam/.test(b.q)) return { status: 200, json: { values: [{ v: 'spam', n: 31 }, { v: 'phishing', n: 2 }] } };
      return { status: 200, json: { values: [{ v: 'clean', n: b.from === 'now-1h' ? 900 : 24 * 100 }] } }; }
    if (p.startsWith('/sysadmin/overview')) return { status: 200, json: { findings: [] } };
    if (p === '/mail/notify/send') { sends.push(b); return { status: 200, json: { ok: true, recipients: 1 } }; }
    return { status: 404, json: {} }; } } });
  assert.equal((await post(e, '/mail-reputation/check', {})).status, 200);
  let r = (await e.req('GET', '/mail-route', VW)).json;
  const rd = r.topology.rdns, mxr = rd.find((x) => x.ip === '203.0.113.10'), egr = rd.find((x) => x.ip === '198.51.100.40');
  assert.equal(mxr.ptr, '10-113-0-203.dsl.isp.example'); assert.equal(mxr.expected, 'gw1.corpgroup.test', 'the server name from the register'); assert.equal(mxr.ok, false); assert.equal(mxr.server, 'GW01');
  assert.equal(egr.ok, true, 'egress PTR right and forward-confirmed');
  assert.ok(r.issues.some((i) => /Reverse DNS of MX address 203\.0\.113\.10 is a generic ISP name/.test(i.title)));
  const l1 = r.topology.links.find((l) => l.rdns.some((x) => x.ip === '203.0.113.10'));
  assert.deepEqual(l1.ptr_request, ['Please set the reverse DNS (PTR) of 203.0.113.10 to gw1.corpgroup.test']);
  assert.deepEqual(r.topology.links.find((l) => l.rdns.some((x) => x.ip === '198.51.100.40')).ptr_request, [], 'nothing to ask that ISP');
  const sp = r.warnings.find((w) => w.key === 'spamhaus:203.0.113.10'); assert.ok(sp, 'listing is an early warning'); assert.match(sp.title, /is listed on Spamhaus XBL/); assert.ok(sp.fix.some((f) => /compromise/.test(f)));
  // the PTR of the egress disappears at the next check
  st.ptr = { '203.0.113.10': ['10-113-0-203.dsl.isp.example'] };
  await post(e, '/mail-reputation/check', {});
  r = (await e.req('GET', '/mail-route', VW)).json;
  assert.ok(r.warnings.some((w) => w.key === 'ptr-gone:198.51.100.40' && w.severity === 'high' && /was mail\.corpgroup\.test/.test(w.title)));
  // alerts: listing, PTR gone, outbound spam and the spike - mailed together
  const a = (await post(e, '/mail-route/alerts/check', {})).json;
  const T = a.open.map((x) => x.title).join(' | ');
  assert.match(T, /203\.0\.113\.10 .* listed on Spamhaus/); assert.match(T, /Reverse DNS of 198\.51\.100\.40 disappeared/);
  assert.match(T, /33 outbound message\(s\) flagged spam \/ phishing by the gateway in 24 h - Spamhaus listing risk/);
  assert.match(T, /Outbound mail spike: 900 messages in the last hour against 100 an hour/);
  assert.equal(a.open.find((x) => x.key === 'r:outbound-bad').severity, 'high');
  assert.ok(tops.some((b) => /email_direction:outbound/.test(b.q)), 'outbound only');
  assert.equal(sends.length, 1); assert.match(sends[0].subject, /^CRITICAL: /); assert.match(sends[0].text, /Spamhaus listing risk/);
});

test('DKIM: no selector recorded - a key published under a common selector is found, never reported missing; none found = not checked (info)', async (t) => {
  const { e, st } = await setup(t, {});
  const KEY = 'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsyntheticSYNTHETICsynthetic';
  // the domain as on the server: Domains & Hosting has no selector recorded (DKIM {})
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { MX: ['10 mx1.corpgroup.test'], SPF: ['v=spf1 ip4:192.0.2.8 -all'], DMARC: ['v=DMARC1; p=reject'], DKIM: {} } });
  st.txt = { 'libraesva._domainkey.corpgroup.test': [KEY] };
  await post(e, '/mail-reputation/check', {});
  let r = (await e.req('GET', '/mail-route', VW)).json;
  assert.ok(!r.issues.some((i) => /DKIM/.test(i.title)), 'the key under "libraesva" is found: no DKIM issue');
  // nothing published anywhere: not checked (info), the SPF/DKIM/DMARC box is not turned to warning for it
  st.txt = {};
  await post(e, '/mail-reputation/check', {});
  r = (await e.req('GET', '/mail-route', VW)).json;
  const dk = r.issues.find((i) => /DKIM/.test(i.title));
  assert.ok(dk && dk.severity === 'info' && /DKIM not checked/.test(dk.title) && /DKIM-Signature/.test(dk.fix.join(' ')), 'not checked, with how to find the selector');
  assert.ok(!r.issues.some((i) => /no DKIM key found/.test(i.title)), 'never "no key found" when nothing was recorded');
  // a recorded selector without a key, and no common one either: still a warning, naming the selector
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { MX: ['10 mx1.corpgroup.test'], SPF: ['v=spf1 ip4:192.0.2.8 -all'], DMARC: ['v=DMARC1; p=reject'], DKIM: { s2026: false } } });
  await post(e, '/mail-reputation/check', {});
  r = (await e.req('GET', '/mail-route', VW)).json;
  assert.ok(r.issues.some((i) => /no DKIM key found for the recorded selectors/.test(i.title) && /s2026/.test(i.evidence.join(' '))), 'recorded selector without a key is a warning');
});

test('reverse DNS: public DNS first; a failed lookup (timeout / SERVFAIL) is "not checked", never "no reverse DNS"; only NXDOMAIN is none', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const st = { q: [], answers: {}, ptr: {} }, base = resolver(st), err = (code) => Object.assign(new Error(code), { code });
  const W = { internal: 'ETIMEOUT', pub: { '198.51.100.50': ['mail2.corpgroup.test'] }, pubFail: null };
  // the server's own DNS (internal AD DNS) cannot reach the ISP reverse zone; public DNS has the PTR the ISP published
  const internal = Object.assign({}, base, { async reverse() { throw err(W.internal); } });
  const pub = Object.assign({}, base, { async reverse(ip) { if (W.pubFail) throw err(W.pubFail); const p = W.pub[ip]; if (p) return p; throw err('ENOTFOUND'); },
    async resolve4(name) { if (name === 'mail2.corpgroup.test') return ['198.51.100.50']; return base.resolve4(name); } });
  e.app.store.collection('dom_domains').put({ id: 'D1', name: 'corpgroup.test', status: 'active' });
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { MX: ['10 mx1.corpgroup.test'], SPF: ['v=spf1 ip4:198.51.100.0/24 -all'], DMARC: ['v=DMARC1; p=reject'], DKIM: { selector1: true } } });
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, mailResolver: internal, mailPublicResolver: pub, mailSealer: sealer, mailTestNets: true, mailSmtpProbe: probe(st) });
  await post(e, '/mail-reputation/ips', { ip: '198.51.100.50', label: 'mail2 egress', role: 'outbound' });
  await post(e, '/mail-reputation/check', {});
  let r = (await e.req('GET', '/mail-route', VW)).json, eg = r.topology.egress.find((x) => x.ip === '198.51.100.50');
  assert.equal(eg.ptr, 'mail2.corpgroup.test', 'found in public DNS although the server DNS timed out');
  assert.ok(!r.issues.some((i) => /198\.51\.100\.50 has no reverse DNS/.test(i.title)));
  assert.equal(r.topology.rdns.find((x) => x.ip === '198.51.100.50').ok, true);
  // both resolvers fail: not checked, not "no reverse DNS", and nothing to ask the ISP
  W.pubFail = 'ESERVFAIL'; await post(e, '/mail-reputation/check', {});
  r = (await e.req('GET', '/mail-route', VW)).json; eg = r.topology.egress.find((x) => x.ip === '198.51.100.50');
  assert.equal(eg.ptr, null); assert.match(eg.ptr_error, /reverse DNS lookup failed \(public DNS: ESERVFAIL; server DNS: ETIMEOUT\)/);
  assert.ok(r.issues.some((i) => /Reverse DNS of 198\.51\.100\.50 could not be checked/.test(i.title) && i.severity === 'low'));
  assert.ok(!r.issues.some((i) => /198\.51\.100\.50 has no reverse DNS/.test(i.title)), 'a failed lookup is not reported as a missing PTR');
  const row = r.topology.rdns.find((x) => x.ip === '198.51.100.50'); assert.equal(row.ok, null);
  assert.ok(!r.topology.links.some((l) => (l.ptr_request || []).some((q) => /198\.51\.100\.50/.test(q))), 'no PTR request sent to the ISP for an unchecked address');
  // public DNS answers NXDOMAIN: now it really has no PTR
  W.pubFail = null; W.pub = {}; await post(e, '/mail-reputation/check', {});
  r = (await e.req('GET', '/mail-route', VW)).json;
  assert.ok(r.issues.some((i) => /198\.51\.100\.50 has no reverse DNS/.test(i.title) && i.severity === 'high'));
});

test('change a registered egress IP in one step: old retired with the reason and what replaced it, new keeps label and role, checked; roles, validation, audit', async (t) => {
  const { e, st } = await setup(t);
  await post(e, '/mail-reputation/ips', { ip: '192.0.2.10', label: 'Libraesva outbound - ISP 1', role: 'outbound' });
  st.ptr = { '192.0.2.50': ['mail2.corpgroup.test'] }; st.a = { 'mail2.corpgroup.test': ['192.0.2.50'] };
  assert.equal((await post(e, '/mail-reputation/ips/MIP-001/replace', { ip: '192.0.2.50', reason: 'wrong NAT address registered' }, VW)).status, 403, 'viewer refused');
  assert.equal((await post(e, '/mail-reputation/ips/MIP-001/replace', { ip: '192.0.2.50', reason: 'wrong NAT address' }, { user: 'system:x', role: 'operator' })).status, 403, 'a service identity does not change it');
  let r = await post(e, '/mail-reputation/ips/MIP-001/replace', { ip: '192.0.2.50' }); assert.equal(r.status, 400); assert.match(r.text, /reason/);
  r = await post(e, '/mail-reputation/ips/MIP-001/replace', { ip: 'not-an-ip', reason: 'wrong NAT address' }); assert.equal(r.status, 400); assert.match(r.text, /ip/);
  r = await post(e, '/mail-reputation/ips/MIP-001/replace', { ip: '192.0.2.10', reason: 'same' }); assert.equal(r.status, 400, 'same address');
  assert.equal((await post(e, '/mail-reputation/ips/BAD/replace', { ip: '192.0.2.50', reason: 'wrong NAT address' })).status, 400);
  assert.equal((await post(e, '/mail-reputation/ips/MIP-009/replace', { ip: '192.0.2.50', reason: 'wrong NAT address' })).status, 404);
  r = await post(e, '/mail-reputation/ips/MIP-001/replace', { ip: '192.0.2.50', reason: 'wrong NAT address registered' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ip, '192.0.2.50'); assert.equal(r.json.label, 'Libraesva outbound - ISP 1'); assert.equal(r.json.role, 'outbound'); assert.deepEqual(r.json.replaces, { id: 'MIP-001', ip: '192.0.2.10' });
  const reg = (await e.req('GET', '/mail-reputation', VW)).json.registered; assert.deepEqual(reg.map((x) => x.ip), ['192.0.2.50'], 'only the new address is registered');
  assert.equal((await post(e, '/mail-reputation/ips/MIP-001/replace', { ip: '192.0.2.60', reason: 'again' })).status, 404, 'a retired entry cannot be changed again');
  await post(e, '/mail-reputation/check', {});
  const route = (await e.req('GET', '/mail-route', VW)).json; const eg = route.topology.egress;
  assert.deepEqual(eg.map((x) => x.ip), ['192.0.2.50'], 'the route map shows the new address'); assert.equal(eg[0].ptr, 'mail2.corpgroup.test');
  const a = e.app.store.auditTail(20).find((x) => x.action === 'mailrep.ip.replace'); assert.ok(a); assert.equal(a.by, 'nora.syn'); assert.equal(a.detail.from, '192.0.2.10'); assert.equal(a.detail.to, '192.0.2.50'); assert.match(a.detail.reason, /wrong NAT/);
});

test('route map reads SPF live: an ip4 added in DNS clears the egress issue before Domains & Hosting re-checks; DNS unreachable falls back to the stored copy and says so', async (t) => {
  const { e, st } = await setup(t, {});
  st.ptr = { '198.51.100.50': ['mail2.corpgroup.test'] }; st.a = { 'mail2.corpgroup.test': ['198.51.100.50'] };
  await post(e, '/mail-reputation/ips', { ip: '198.51.100.50', label: 'link 2 egress', role: 'outbound' });
  const spfIssue = async () => { await post(e, '/mail-reputation/check', {}); return (await e.req('GET', '/mail-route', VW)).json.issues.find((i) => /198\.51\.100\.50 is not authorised by the SPF/.test(i.title)); };
  // the stored Domains & Hosting copy (6-hourly) has no ip4 for .50; DNS has it now
  st.txt = { 'corpgroup.test': ['v=spf1 ip4:192.0.2.8 ip4:198.51.100.50 include:spf.protection.outlook.com -all'], 'spf.protection.outlook.com': ['v=spf1 ip4:40.92.0.0/15 -all'] };
  assert.equal(await spfIssue(), undefined, 'live DNS authorises the IP: no issue, though the stored copy is old');
  // DNS still answers the old record: the issue names the record DNS gave, read live
  st.txt['corpgroup.test'] = ['v=spf1 ip4:192.0.2.8 include:spf.protection.outlook.com -all'];
  let i = await spfIssue(); assert.ok(i);
  assert.ok(i.evidence.some((x) => /corpgroup\.test SPF \(read live from .* DNS\): v=spf1 ip4:192\.0\.2\.8 include/.test(x)), JSON.stringify(i.evidence));
  assert.ok(i.fix.some((x) => /Already added\? .* not published yet/.test(x)));
  // DNS not reachable: the stored copy is used and the evidence says so
  const base = st.txt;
  st.txt = new Proxy({}, { get: () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }); } });   // every TXT lookup times out
  i = await spfIssue(); st.txt = base;
  assert.ok(i && i.evidence.some((x) => /DNS not readable now - the copy Domains & Hosting stored/.test(x)), JSON.stringify(i && i.evidence));
});

test('SPF "mx" / "a:" is judged with PUBLIC DNS (the internal split zone gives private addresses); a mechanism after -all authorises nothing', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const st = { q: [], answers: {}, ptr: { '198.51.100.50': ['mail2.corpgroup.test'], '198.51.100.210': ['mail1.corpgroup.test'] } };
  st.store = e.app.store;
  e.app.store.collection('dom_domains').put({ id: 'D1', name: 'corpgroup.test', status: 'active' });
  e.app.store.collection('dom_checks').put({ id: 'd:D1', at: clock, records: { MX: ['10 mail2.corpgroup.test', '20 mail1.corpgroup.test'], SPF: ['v=spf1 mx -all ip4:198.51.100.99'], DMARC: ['v=DMARC1; p=reject'] } });
  // the site resolver is the internal AD DNS: mail1 / mail2 resolve to private addresses
  const inside = resolver(st); inside.resolve4 = async (n) => ({ 'mail1.corpgroup.test': ['10.0.0.11'], 'mail2.corpgroup.test': ['10.0.0.12'] })[n] || [];
  inside.resolveMx = async () => [{ exchange: 'mail2.corpgroup.test', priority: 10 }, { exchange: 'mail1.corpgroup.test', priority: 20 }];
  const pub = { resolveTxt: async (n) => (n === 'corpgroup.test' ? [['v=spf1 mx -all ip4:198.51.100.99']] : []), resolveMx: inside.resolveMx,
    resolve4: async (n) => ({ 'mail1.corpgroup.test': ['198.51.100.210'], 'mail2.corpgroup.test': ['198.51.100.50'] })[n] || [], resolveCname: async () => [],
    reverse: async (ip) => st.ptr[ip] || [] };
  registerDuty(e.app.srv, e.app, { noTimer: true, now, python: PY, mailResolver: inside, mailPublicResolver: pub, mailSealer: sealer, mailTestNets: true, mailSmtpProbe: probe(st) });
  for (const ip of ['198.51.100.50', '198.51.100.210', '198.51.100.99']) await post(e, '/mail-reputation/ips', { ip, label: 'egress ' + ip, role: 'outbound' });
  await post(e, '/mail-reputation/check', {});
  const titles = (await e.req('GET', '/mail-route', VW)).json.issues.map((i) => i.title).filter((x) => /not authorised by the SPF/.test(x));
  assert.ok(!titles.some((x) => /198\.51\.100\.(50|210) /.test(x)), 'both MX gateways are authorised by "mx" as public DNS resolves it: ' + JSON.stringify(titles));
  assert.ok(titles.some((x) => /198\.51\.100\.99 is not authorised/.test(x)), 'ip4 placed after -all authorises nothing');
});

test('GET /mail-route answers from the last assessment: no Python wait after a restart, a stale one refreshed in the background', async () => {
  const { createMailReputation } = require('../engine/mail-reputation');
  const cols = {}, col = (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return { get: (k) => m.get(k), put: (x) => m.set(x.id, x), all: (f) => [...m.values()].filter(f || (() => true)), remove: (k) => m.delete(k) }; })());
  let t = Date.parse('2026-11-11T08:00:00Z'), calls = 0, fail = false, slow = null;
  const py = { call: async (op) => { calls++; if (slow) await slow; if (fail) return { ok: false, error_class: 'timeout' }; return { lanes: [{ id: 'in' }], issues: [{ title: 'synthetic issue ' + calls }], warnings: [] }; } };
  const app = { store: { collection: col }, config: {}, addons: {}, audit() {}, log: { every() {}, warn() {}, info() {} } };
  col('mailrep').put({ id: 'last', at: t, route: { at: t, domains: [] }, rows: [] });
  let M = createMailReputation(app, { py, now: () => t, noTimer: true });
  let r = await M.routeView(null); assert.equal(calls, 1, 'first time ever: assessed in the request'); assert.equal(r.issues[0].title, 'synthetic issue 1');
  // a restart: a new engine, Python slow to start - the stored assessment answers at once
  let release; slow = new Promise((ok) => { release = ok; });
  M = createMailReputation(app, { py, now: () => t, noTimer: true });
  r = await Promise.race([M.routeView(null), new Promise((ok) => setTimeout(() => ok('waited'), 200))]);
  assert.notEqual(r, 'waited', 'answered without waiting for Python'); assert.equal(r.issues[0].title, 'synthetic issue 1'); assert.equal(calls, 1);
  // older than 15 minutes: shown, marked stale, refreshed once in the background
  t += 16 * 60000; r = await M.routeView(null); assert.match(r.stale.why, /being refreshed/); assert.equal(r.issues[0].title, 'synthetic issue 1');
  await M.routeView(null); release(); slow = null; await new Promise((ok) => setTimeout(ok, 20));
  assert.equal(calls, 2, 'one background refresh, not one per request'); r = await M.routeView(null); assert.equal(r.issues[0].title, 'synthetic issue 2'); assert.equal(r.stale, undefined);
  // a failed refresh keeps the last assessment
  fail = true; t += 16 * 60000; r = await M.routeView(null); assert.equal(r.issues[0].title, 'synthetic issue 2'); await new Promise((ok) => setTimeout(ok, 20));
  assert.equal((await M.routeView(null)).issues[0].title, 'synthetic issue 2', 'Python failing: the last assessment is still shown');
  // the profile changed: recomputed in the request (the person sees the effect of the edit)
  fail = false; col('mailrep').put({ id: 'route_profile', expected_mx: ['gw.synthetic.test'], at: t });
  r = await M.routeView(null); assert.equal(r.stale, undefined); assert.match(r.issues[0].title, /synthetic issue \d/); assert.ok(calls >= 4);
});

// Bug fixed: the update's final check kept reporting "/mail-route (HTTP 0, no answer in 30 s)". Every reputation check rewrites the
// stored facts, and a GET after the facts changed re-ran the Python assessment IN the request - right after an update's restarts the
// Python start took longer than the check waits. Now the last assessment answers at once while the new one runs in the background,
// and with no assessment at all the request waits only a few seconds before saying it is being computed.
test('GET /mail-route never waits on Python when the facts changed, and not long when nothing was assessed yet', async () => {
  const { createMailReputation } = require('../engine/mail-reputation');
  const cols = {}, col = (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return { get: (k) => m.get(k), put: (x) => m.set(x.id, x), all: (f) => [...m.values()].filter(f || (() => true)), remove: (k) => m.delete(k) }; })());
  let t = Date.parse('2026-11-11T08:00:00Z'), calls = 0, slow = null;
  const py = { call: async () => { calls++; if (slow) await slow; return { lanes: [{ id: 'in' }], issues: [{ title: 'synthetic issue ' + calls }], warnings: [] }; } };
  const app = { store: { collection: col }, config: {}, addons: {}, audit() {}, log: { every() {}, warn() {}, info() {} } };
  const quick = (p, ms) => Promise.race([p, new Promise((ok) => setTimeout(() => ok('waited'), ms))]);
  // nothing assessed yet and Python slow to start: a short wait, then "being computed" - never the page check's 30 s
  let release; slow = new Promise((ok) => { release = ok; });
  col('mailrep').put({ id: 'last', at: t, route: { at: t, domains: [] }, rows: [] });
  let M = createMailReputation(app, { py, now: () => t, noTimer: true, routeWait: 50 });
  let r = await quick(M.routeView(null), 1000); assert.notEqual(r, 'waited'); assert.equal(r.computing, true); assert.match(r.note, /being computed/);
  release(); slow = null; await new Promise((ok) => setTimeout(ok, 20));
  r = await M.routeView(null); assert.equal(r.issues[0].title, 'synthetic issue 1', 'the background assessment answers the next request');
  // a reputation check rewrote the facts, then a restart with Python slow again: the last assessment answers at once, marked
  slow = new Promise((ok) => { release = ok; });
  t += 60000; col('mailrep').put({ id: 'last', at: t, route: { at: t, domains: [{ domain: 'corpgroup.test' }] }, rows: [] });
  M = createMailReputation(app, { py, now: () => t, noTimer: true, routeWait: 50 });
  r = await quick(M.routeView(null), 200); assert.notEqual(r, 'waited', 'answered without waiting for Python');
  assert.equal(r.issues[0].title, 'synthetic issue 1'); assert.match(r.stale.why, /facts changed since - being re-assessed/);
  await quick(M.routeView(null), 200); release(); slow = null; await new Promise((ok) => setTimeout(ok, 20));
  assert.equal(calls, 2, 'one background re-assessment, not one per request');
  r = await M.routeView(null); assert.equal(r.issues[0].title, 'synthetic issue 2'); assert.equal(r.stale, undefined);
});
