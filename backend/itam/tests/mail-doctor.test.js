// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// Mail route troubleshooter (engine/mail-doctor.js). Bug it answers: the Email Route Map said "the organisation has no MX record"
// and "no SPF record" while MX Toolbox showed both - the platform had read the internal (split) DNS. The troubleshooter asks the
// public resolvers itself, re-checks the domain, and reports the step as FIXED with the evidence; a record public DNS really
// lacks stays a failure with the record to publish; public DNS unreachable says so; egress IPs are proposed, registered only by a
// person and only when proposed; roles, validation naming the field, audit records. Resolvers are injected; data is SYNTHETIC
// (RFC 5737 addresses, .test-like names).
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createDomains } = require('../engine/domains');

const PY = process.env.PYTHON || 'python3';
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VW = { user: 'v.syn', role: 'viewer' };
const nod = () => Object.assign(new Error('nodata'), { code: 'ENODATA' });
function zoneDns(zone) {
  const get = (t, n) => { const v = (zone[n] || {})[t]; if (v === 'TIMEOUT') return Promise.reject(Object.assign(new Error('t'), { code: 'ETIMEOUT' })); if (v === 'REFUSED') return Promise.reject(Object.assign(new Error('r'), { code: 'ECONNREFUSED' })); return v ? Promise.resolve(v) : Promise.reject(nod()); };
  return { resolveNs: (n) => get('NS', n), resolveMx: (n) => get('MX', n), resolveTxt: (n) => get('TXT', n), resolveCaa: (n) => get('CAA', n), resolve4: (n) => get('A', n), resolveCname: (n) => get('CNAME', n), reverse: (n) => get('PTR', n) };
}
const PUBLIC = { 'corp.test': { NS: ['ns1.dns-syn.net'], MX: [{ priority: 10, exchange: 'esg.corp.test' }], TXT: [['v=spf1 ip4:203.0.113.25 -all']] },
  '_dmarc.corp.test': { TXT: [['v=DMARC1; p=none']] }, 'esg.corp.test': { A: ['203.0.113.25'] } };
const INTERNAL = { 'corp.test': { NS: [('dc01.' + ZYB_ORG.domain)] } };   // the AD zone: no MX, no SPF
const DOWN = new Proxy({}, { get: () => () => Promise.reject(Object.assign(new Error('r'), { code: 'ECONNREFUSED' })) });

async function setup(t, pub) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const pubR = zoneDns(pub), intR = zoneDns(INTERNAL);
  registerDuty(e.app.srv, e.app, { noTimer: true, python: PY, mailResolver: zoneDns(Object.assign({}, pub)), mailSmtpProbe: async (h) => ({ connected: true, banner: '220 ' + h + ' ESMTP', ehlo: true, starttls: true }), mailTestNets: true,
    mailSealer: { seal: (i, x) => x, unseal: (i, x) => x }, mailDoctorResolvers: { pub: [{ name: 'Cloudflare 1.1.1.1', r: pubR }, { name: 'Google 8.8.8.8', r: pubR }], server: intR } });
  // Domains & Hosting as it ran before the fix: only the server's (internal) DNS - so it stored "no MX, no SPF"
  const old = createDomains(e.app, { resolver: intR, publicResolver: null, tlsPeek: async () => { throw new Error('n/a'); } });
  const d = old.putDomain({ name: 'corp.test', registrar: 'SaudiNIC', dns_provider: 'other' }, ADM); await old.check('d:' + d.id);
  // the fixed Domains & Hosting (public DNS first) is what the troubleshooter's re-check uses
  e.app.addons.domains = createDomains(e.app, { resolver: intR, publicResolver: pub === null ? DOWN : pubR, tlsPeek: async () => { throw new Error('n/a'); } });
  return { e, d, post: (p, b, who = OP) => e.req('POST', p, Object.assign({ body: b }, who)), get: (p, who = OP) => e.req('GET', p, who) };
}
const step = (r, id) => r.steps.find((x) => x.id === id);

test('the bug: platform said no MX / no SPF, public DNS has both → re-checked, reported FIXED with the evidence, egress proposed', async (t) => {
  const s = await setup(t, PUBLIC);
  const before = s.e.app.store.collection('dom_checks').get('d:' + s.d.id).records; assert.deepEqual(before.MX, [], 'reproduced: the internal DNS view had no MX');
  assert.equal((await s.post('/mail-route/troubleshoot', {}, VW)).status, 403, 'viewers read, they do not run');
  const r = await s.post('/mail-route/troubleshoot', {}); assert.equal(r.status, 200, r.raw);
  const mx = step(r.json, 'mx:corp.test'); assert.equal(mx.status, 'fixed'); assert.match(mx.detail, /10 esg\.corp\.test/);
  assert.ok(mx.evidence.some((x) => /This server's DNS answers with NO record .*split DNS/.test(x)), 'explains why the earlier answer was wrong');
  assert.equal(step(r.json, 'spf:corp.test').status, 'fixed');
  assert.equal(step(r.json, 'dmarc:corp.test').status, 'warn');
  assert.deepEqual(s.e.app.store.collection('dom_checks').get('d:' + s.d.id).records.MX, ['10 esg.corp.test'], 'the platform now holds the public MX');
  const eg = step(r.json, 'egress'); assert.equal(eg.status, 'warn'); assert.deepEqual(eg.actions.map((a) => a.ip), ['203.0.113.25']);
  assert.ok(s.e.app.store.auditTail(50).some((x) => x.action === 'mail.doctor.run' && x.by === OP.user && x.detail.fixed >= 2));
  assert.equal((await s.get('/mail-route/troubleshoot', VW)).json.last.steps.length, r.json.steps.length, 'the last run is readable');
  // actions: only a proposed IP, by a person; validation names the field
  let a = await s.post('/mail-route/troubleshoot/action', { action: 'register-egress', ip: '198.51.100.9' }); assert.equal(a.status, 409); assert.match(a.json.error, /not proposed/);
  a = await s.post('/mail-route/troubleshoot/action', { action: 'register-egress' }); assert.equal(a.status, 400); assert.match(a.json.error, /ip is required/);
  a = await s.post('/mail-route/troubleshoot/action', { action: 'register-egress', ip: '203.0.113.25' }); assert.equal(a.status, 200, a.raw);
  assert.equal(step(a.json, 'egress').status, 'ok');
  assert.ok(s.e.app.store.auditTail(50).some((x) => x.action === 'mail.doctor.register-egress' && x.by === OP.user));
  a = await s.post('/mail-route/troubleshoot/action', { action: 'add-domain', domain: 'other.test' }); assert.equal(a.status, 403, 'adding a domain needs an admin');
  a = await s.post('/mail-route/troubleshoot/action', { action: 'add-domain', domain: 'not a domain' }, ADM); assert.equal(a.status, 400); assert.match(a.json.error, /domain must be/);
  a = await s.post('/mail-route/troubleshoot/action', { action: 'drop-dns' }); assert.equal(a.status, 400); assert.match(a.json.error, /action must be/);
});

test('a record public DNS really lacks stays a failure with the record to publish', async (t) => {
  const pub = { 'corp.test': { NS: ['ns1.dns-syn.net'] } };
  const s = await setup(t, pub);
  const r = (await s.post('/mail-route/troubleshoot', {})).json;
  const mx = step(r, 'mx:corp.test'); assert.equal(mx.status, 'fail'); assert.match(mx.detail, /Public DNS .* has no MX/); assert.match(mx.fix, /publish an MX record/);
  assert.equal(step(r, 'spf:corp.test').status, 'fail'); assert.equal(r.ok, false);
});

test('public DNS unreachable from the server: says so and how to open it, never calls the record missing', async (t) => {
  const s = await setup(t, null);
  const r = (await s.post('/mail-route/troubleshoot', {})).json;
  const mx = step(r, 'mx:corp.test'); assert.equal(mx.status, 'fail'); assert.match(mx.detail, /Public DNS could not be reached/); assert.match(mx.fix, /UDP and TCP 53/);
  assert.equal(step(r, 'spf:corp.test').status, 'warn');
});

test('no mail domain registered: the first step says so and offers an admin action', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: PY, mailResolver: zoneDns({}), mailTestNets: true, mailSealer: { seal: (i, x) => x, unseal: (i, x) => x }, mailDoctorResolvers: { pub: [{ name: 'p', r: zoneDns({}) }], server: zoneDns({}) } });
  const r = (await e.req('POST', '/mail-route/troubleshoot', Object.assign({ body: {} }, OP))).json;
  const d = step(r, 'domains'); assert.equal(d.status, 'fail'); assert.equal(d.actions[0].action, 'add-domain'); assert.equal(d.actions[0].role, 'admin');
});

// "Exchange receive and send also showing not connected": the troubleshooter says why - no Exchange source in the SIEM, a source
// that stopped sending, or a source with only Windows events (no message tracking) - and what to install where.
test('Exchange: no source, silent source, Windows events only, and message tracking arriving', async (t) => {
  let health = { sources: [{ src_id: 'win-dc01', type: 'windows', state: 'receiving' }] };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: PY, mailResolver: zoneDns({}), mailTestNets: true, mailSealer: { seal: (i, x) => x, unseal: (i, x) => x },
    mailDoctorResolvers: { pub: [{ name: 'p', r: zoneDns({}) }], server: zoneDns({}) }, mailDoctorSiemHealth: async () => health });
  const run = async (b) => (await e.req('POST', '/mail-route/troubleshoot', Object.assign({ body: b }, OP))).json;
  let x = step(await run({ siem: { exchange: null } }), 'exchange');
  assert.equal(x.status, 'fail'); assert.match(x.detail, /no Exchange log source/); assert.match(x.fix, /install-exchange-shipper\.ps1 .*-TokenFile/); assert.doesNotMatch(x.fix, /-Token [^F]/, 'never a token on the command line');
  health = { sources: [{ src_id: 'win-exchange', type: 'exchange', state: 'silent', last_seen: Date.parse('2026-10-28T09:00:00Z'), events_24h: 0 }] };
  x = step(await run({ siem: { exchange: null } }), 'exchange'); assert.equal(x.status, 'fail'); assert.match(x.detail, /not sending/); assert.match(x.fix, /schtasks \/Query \/TN SentraExchangeShipper/);
  assert.match(x.evidence[0], /win-exchange: silent, last event 2026-10-28 09:00 UTC/);
  health = { sources: [{ src_id: 'win-exchange', type: 'exchange', state: 'receiving', events_24h: 900 }] };
  x = step(await run({ siem: { exchange: null } }), 'exchange'); assert.equal(x.status, 'warn'); assert.match(x.detail, /none of them are message tracking/);
  x = step(await run({ siem: { exchange: { receive: 120, send: 80, deliver: 118, fail: 0 } } }), 'exchange'); assert.equal(x.status, 'ok'); assert.match(x.detail, /receive 120/);
  health = { _down: 'the SIEM link is not configured on this server' };
  x = step(await run({}), 'exchange'); assert.equal(x.status, 'warn'); assert.match(x.detail, /could not be asked/);
  const bad = await e.req('POST', '/mail-route/troubleshoot', Object.assign({ body: { siem: { exchange: { receive: -3 } } } }, OP)); assert.equal(bad.status, 400); assert.match(bad.json.error, /siem\.exchange\.receive/);
});

// "Internet link 1 also showing unused": links are told apart by the public /24 of MX and egress addresses. The MX host's address
// is now read from public DNS (the internal DNS answers the gateway's PRIVATE address, which matches no link); the troubleshooter
// says why a link is empty.
test('Internet link: MX address from public DNS fills the link; an empty link is explained', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const pubR = zoneDns(PUBLIC), intR = zoneDns({ 'corp.test': { NS: [('dc01.' + ZYB_ORG.domain)] }, 'esg.corp.test': { A: ['10.20.0.25'] } });
  registerDuty(e.app.srv, e.app, { noTimer: true, python: PY, mailResolver: intR, mailPublicResolver: pubR, mailSmtpProbe: async (h) => ({ connected: true, banner: '220 ' + h, ehlo: true, starttls: true }), mailTestNets: true,
    mailSealer: { seal: (i, x) => x, unseal: (i, x) => x }, mailDoctorResolvers: { pub: [{ name: 'p', r: pubR }], server: intR }, mailDoctorSiemHealth: async () => ({ _down: 'n/a' }) });
  e.app.addons.domains = createDomains(e.app, { resolver: intR, publicResolver: pubR, tlsPeek: async () => { throw new Error('n/a'); } });
  e.app.addons.domains.putDomain({ name: 'corp.test', registrar: 'SaudiNIC', dns_provider: 'other' }, ADM);
  const run = async () => (await e.req('POST', '/mail-route/troubleshoot', Object.assign({ body: {} }, OP))).json;
  let r = await run();
  const mxh = step(r, 'mxhosts'); assert.match(mxh.detail, /esg\.corp\.test → 203\.0\.113\.25/, 'the public address, not the internal 10.20.0.25');
  const route = e.app.store.collection('mailrep').get('last').route; assert.deepEqual(route.domains[0].mx[0].inside_ips, ['10.20.0.25'], 'the inside (NAT) address is kept apart');
  const ln = step(r, 'links'); assert.ok(ln, 'links step present');
  assert.ok(ln.status === 'ok' || /Egress/.test(ln.fix + ln.evidence.join(' ')), 'inbound on the link, or explained by the missing egress: ' + JSON.stringify(ln));
  // public DNS unreachable: the MX resolves internally only - the link step names that cause
  const e2 = await startApp({ noAi: true }); t.after(() => e2.close());
  const down = { resolve4: () => Promise.reject(Object.assign(new Error('r'), { code: 'ECONNREFUSED' })) };
  registerDuty(e2.app.srv, e2.app, { noTimer: true, python: PY, mailResolver: intR, mailPublicResolver: down, mailSmtpProbe: async (h) => ({ connected: true, banner: '220 ' + h, ehlo: true, starttls: true }), mailTestNets: true,
    mailSealer: { seal: (i, x) => x, unseal: (i, x) => x }, mailDoctorResolvers: { pub: [{ name: 'p', r: pubR }], server: intR }, mailDoctorSiemHealth: async () => ({ _down: 'n/a' }) });
  e2.app.addons.domains = createDomains(e2.app, { resolver: intR, publicResolver: pubR, tlsPeek: async () => { throw new Error('n/a'); } });
  e2.app.addons.domains.putDomain({ name: 'corp.test', registrar: 'SaudiNIC', dns_provider: 'other' }, ADM);
  r = (await e2.req('POST', '/mail-route/troubleshoot', Object.assign({ body: {} }, OP))).json;
  const l2 = step(r, 'links'); assert.ok(l2 && l2.status === 'warn', JSON.stringify(l2)); assert.ok(l2.evidence.some((x) => /INTERNAL address/.test(x)), 'names the internal MX address as the cause');
});

// "Egress IP also showing none registered": the troubleshooter finds the egress address from the firewall logs (outbound SMTP
// sessions and their NAT address), the whole SPF tree and the MX addresses - and proposes it; a person registers it.
test('Egress: proposed from firewall NAT logs first, then the SPF tree; private NAT values ignored; none found says how to find it', async (t) => {
  const pub = { 'corp.test': { NS: ['ns1.dns-syn.net'], MX: [{ priority: 10, exchange: 'mx.cloud-syn.test' }], TXT: [['v=spf1 include:_spf.corp.test include:spf.protection.outlook.com -all']] },
    '_spf.corp.test': { TXT: [['v=spf1 ip4:198.51.100.40 -all']] }, 'spf.protection.outlook.com': { TXT: [['v=spf1 ip4:40.92.0.0/15 -all']] }, 'mx.cloud-syn.test': { A: ['192.0.2.77'] } };
  let fw = { 'fields.natsrc': [{ v: '203.0.113.60', n: 1520 }, { v: '10.20.0.25', n: 9 }] };
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const pubR = zoneDns(pub);
  registerDuty(e.app.srv, e.app, { noTimer: true, python: PY, mailResolver: pubR, mailSmtpProbe: async (h) => ({ connected: true, banner: '220 ' + h, ehlo: true, starttls: true }), mailTestNets: true,
    mailSealer: { seal: (i, x) => x, unseal: (i, x) => x }, mailDoctorResolvers: { pub: [{ name: 'p', r: pubR }], server: pubR }, mailDoctorSiemHealth: async () => ({ _down: 'n/a' }),
    mailDoctorSiemTop: async (q, f) => (q === 'dst_port:25' ? (fw[f] || []) : []) });
  e.app.addons.domains = createDomains(e.app, { resolver: pubR, publicResolver: pubR, tlsPeek: async () => { throw new Error('n/a'); } });
  e.app.addons.domains.putDomain({ name: 'corp.test', registrar: 'SaudiNIC', dns_provider: 'other' }, ADM);
  const run = async () => step((await e.req('POST', '/mail-route/troubleshoot', Object.assign({ body: {} }, OP))).json, 'egress');
  let eg = await run();
  assert.match(eg.detail, /firewall logs show outbound mail leaving through 203\.0\.113\.60/);
  assert.equal(eg.actions[0].ip, '203.0.113.60', 'the firewall evidence ranks first');
  assert.ok(!eg.actions.some((a) => a.ip === '10.20.0.25'), 'a private NAT value is never proposed');
  assert.ok(eg.actions.some((a) => a.ip === '198.51.100.40'), 'ip4 found inside an include of the SPF tree');
  assert.ok(!eg.evidence.some((x) => /40\.92/.test(x)), 'the cloud provider include is not proposed');
  // no firewall logs, no SPF ip4 of our own, MX in the cloud only: still proposes what it can, and says how to find it otherwise
  fw = {};
  pub['corp.test'].TXT = [['v=spf1 include:spf.protection.outlook.com -all']];
  pub['mx.cloud-syn.test'].A = undefined;
  eg = await run();
  assert.equal(eg.actions.length, 0); assert.match(eg.detail, /none could be found/); assert.match(eg.fix, /Received:/);
});
