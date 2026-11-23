// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/brand');
// External domains & DNS (engine/domains.js): register with expiry warnings, public DNS / e-mail security / certificate checks
// over a fake resolver and fake TLS peek, change detection, hosting map linked to assets, roles, audit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { createDomains } = require('../engine/domains');

const ADM = { user: 'syed', role: 'admin', ip: '' }, OP = { user: 'ali', role: 'operator', ip: '' };
const DAY = 86400000;
const nod = () => Object.assign(new Error('nodata'), { code: 'ENODATA' });
function fakeDns(zone) {
  const get = (t, n) => { const v = (zone[n] || {})[t]; if (v === 'TIMEOUT') return Promise.reject(Object.assign(new Error('t'), { code: 'ETIMEOUT' })); return v ? Promise.resolve(v) : Promise.reject(nod()); };
  return { resolveNs: (n) => get('NS', n), resolveMx: (n) => get('MX', n), resolveTxt: (n) => get('TXT', n), resolveCaa: (n) => get('CAA', n), resolve4: (n) => get('A', n), resolve6: (n) => get('AAAA', n), resolveCname: (n) => get('CNAME', n) };
}

test('domains: register, DNS / e-mail checks, expiry, certificate, change detection, hosting map', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const now = Date.now();
  const zone = {
    [ZYB_ORG.domain]: { NS: ['ns1.cloudflare.com', 'ns2.cloudflare.com'], MX: [{ priority: 0, exchange: 'corp-example.mail.protection.outlook.com' }], TXT: [['v=spf1 include:spf.protection.outlook.com ~all'], ['MS=ms123']], CAA: [] },
    ['_dmarc.' + ZYB_ORG.domain]: { TXT: [['v=DMARC1; p=none']] },
    ['selector1._domainkey.' + ZYB_ORG.domain]: { TXT: [['v=DKIM1; k=rsa; p=MIIB']] },
    'old-brand.sa': { NS: [], MX: [] },
    ['portal.' + ZYB_ORG.domain]: { A: ['10.20.0.15'] },
    ['claims.' + ZYB_ORG.domain]: { A: ['203.0.113.7'] },
  };
  const certs = { ['portal.' + ZYB_ORG.domain]: { subject: ('portal.' + ZYB_ORG.domain), issuer: 'DigiCert', valid_to: now + 10 * DAY, names: [('portal.' + ZYB_ORG.domain)], name_ok: true, trusted: true, trust_error: '' },
    ['claims.' + ZYB_ORG.domain]: { subject: 'other.example', issuer: 'Self', valid_to: now + 200 * DAY, names: ['other.example'], name_ok: false, trusted: false, trust_error: 'SELF_SIGNED_CERT_IN_CHAIN' } };
  const D = createDomains(e.app, { resolver: fakeDns(zone), tlsPeek: async (h) => { if (!certs[h]) throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }); return certs[h]; } });
  e.app.store.collection('assets').put({ id: 'a_portal', name: 'PORTAL-WEB01', type: 'server', mgmt_ip: '10.20.0.15', status: 'active' });

  assert.throws(() => D.putDomain({ name: 'not a domain' }, ADM), /domain name/);
  assert.throws(() => D.putDomain({ name: 'x.sa', expires: '2026/01/01' }, ADM), /YYYY-MM-DD/);
  const d1 = D.putDomain({ name: (ZYB_ORG.domain + '.'), registrar: 'SaudiNIC', owner: 'IT', expires: new Date(now + 20 * DAY).toISOString().slice(0, 10), auto_renew: false, dns_provider: 'cloudflare', expected_ns: 'ns1.cloudflare.com, ns2.cloudflare.com', dkim_selectors: ['selector1', 'selector2'], cost: 300 }, ADM);
  assert.equal(d1.name, ZYB_ORG.domain);
  assert.throws(() => D.putDomain({ name: ZYB_ORG.domain , id: 'nope' }, ADM), /not found/);
  D.putDomain({ name: 'old-brand.sa', registrar: 'GoDaddy', dns_provider: 'godaddy' }, ADM);
  const h1 = D.putHost({ fqdn: ('portal.' + ZYB_ORG.domain), purpose: 'Staff portal', hosting: 'Riyadh DC', location: 'ksa' }, ADM);
  assert.equal(h1.domain_id, d1.id, 'hostname linked to its domain');
  D.putHost({ fqdn: ('claims.' + ZYB_ORG.domain), purpose: 'Claims portal', hosting: 'AWS Bahrain', location: 'outside' }, ADM);
  D.putHost({ fqdn: ('vpn.' + ZYB_ORG.domain), purpose: 'VPN', location: 'ksa' }, ADM);

  await D.check();
  let v = D.view('admin');
  const dv = v.domains.find((d) => d.name === ZYB_ORG.domain), F = dv.check.findings.map((f) => f.level + ' ' + f.text).join('\n');
  assert.match(F, /bad The registration expires in (19|20) days/, 'expiry inside 30 days without auto-renew = bad');
  assert.match(F, /info SPF ends with ~all/); assert.match(F, /warn DMARC policy is p=none/); assert.match(F, /info DMARC has no rua=/);
  assert.match(F, /warn DKIM selector "selector2" has no public key/); assert.doesNotMatch(F, /selector1/);
  assert.match(F, /info No CAA record/);
  assert.doesNotMatch(F, /Nameservers differ/);
  const old = v.domains.find((d) => d.name === 'old-brand.sa').check.findings.map((f) => f.level + ' ' + f.text).join('\n');
  assert.match(old, /bad The domain has no nameservers/); assert.match(old, /warn No renewal date recorded/);
  const portal = v.hosts.find((h) => h.fqdn === ('portal.' + ZYB_ORG.domain));
  assert.equal(portal.cert_days, 9); assert.match(portal.check.findings[0].text, /expires in 9 day/);
  assert.deepEqual(portal.asset, { id: 'a_portal', name: 'PORTAL-WEB01', how: 'matched by IP 10.20.0.15' });
  const claims = v.hosts.find((h) => h.fqdn === ('claims.' + ZYB_ORG.domain)).check.findings.map((f) => f.text).join('\n');
  assert.match(claims, /does not cover claims/); assert.match(claims, /not trusted \(SELF_SIGNED/); assert.match(claims, /outside the Kingdom/);
  assert.match(v.hosts.find((h) => h.fqdn === ('vpn.' + ZYB_ORG.domain)).check.findings[0].text, /does not resolve/);
  assert.equal(v.summary.domains, 2); assert.equal(v.summary.hosts, 3); assert.equal(v.summary.certs_30, 1); assert.equal(v.summary.outside_ksa, 1); assert.equal(v.summary.expiring_90, 1); assert.equal(v.summary.no_expiry, 1);
  assert.equal(v.domains[0].cost, 300); assert.equal(D.view('viewer').domains[0].cost, undefined, 'cost hidden from viewers');

  // nameservers hijacked + SPF changed -> flagged, and listed as a change; a lookup timeout is not a change
  zone[ZYB_ORG.domain].NS = ['ns1.evil.example', 'ns2.evil.example'];
  zone[ZYB_ORG.domain].TXT = [['v=spf1 include:spf.protection.outlook.com -all']];
  zone[ZYB_ORG.domain].MX = 'TIMEOUT';
  await D.check('d:' + d1.id);
  v = D.view('admin');
  const F2 = v.domains.find((d) => d.name === ZYB_ORG.domain).check.findings.map((f) => f.level + ' ' + f.text).join('\n');
  assert.match(F2, /bad Nameservers differ from the ones recorded: now ns1.evil.example/);
  assert.match(F2, /info DNS changed since .*NS: \+ ns1.evil.example, ns2.evil.example  - ns1.cloudflare.com, ns2.cloudflare.com; SPF: \+ v=spf1 include:spf.protection.outlook.com -all/);
  assert.doesNotMatch(F2, /MX:/, 'a timed-out lookup is not reported as a change');
  const hist = D.history({ id: 'd:' + d1.id }); assert.equal(hist.items.length, 1); assert.match(hist.items[0].changes[0], /^NS:/);

  // asset linked explicitly, retire needs a reason
  const h2 = D.putHost({ id: h1.id, fqdn: ('portal.' + ZYB_ORG.domain), location: 'ksa', asset_id: 'a_portal' }, ADM);
  assert.equal(D.view('admin').hosts.find((h) => h.id === h2.id).asset.how, 'linked');
  assert.throws(() => D.putHost({ fqdn: ('x.' + ZYB_ORG.domain), asset_id: 'nope' }, ADM), /asset not found/);
  assert.throws(() => D.retire('host', h1.id, {}, ADM), /reason/);
  D.retire('host', h1.id, { reason: 'moved to new portal' }, ADM);
  assert.equal(D.view('admin').hosts.length, 2);
});

test('domains: routes - viewer reads, admin writes, operator checks; writes audited', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  assert.equal((await e.req('GET', '/domains', { role: 'viewer' })).status, 200);
  assert.equal((await e.req('POST', '/domains', { role: 'operator', body: { name: 'a.sa' } })).status, 403);
  const r = await e.req('POST', '/domains', { role: 'admin', user: 'syed', body: { name: 'example.sa', dns_provider: 'azure', expires: '2030-01-01' } });
  assert.equal(r.status, 200, r.text); assert.equal(r.json.dns_provider, 'azure');
  assert.equal((await e.req('POST', '/domains/check', { role: 'viewer', body: {} })).status, 403);
  const aud = e.app.store.auditTail(200, (x) => /^domains\./.test(x.action || ''));
  assert.ok(aud.some((x) => x.action === 'domains.create' && x.by === 'syed'), 'create audited: ' + JSON.stringify(aud));
});

test(('domains: Brand Protection follows the register; own-server hostnames are hosted at ' + ZYB_ORG.short), async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  // a stub of the portal twin service's /api/brand (SYNTHETIC names)
  const B = { settings: { official: ['corp3.com'], keywords: ['corp3'], tlds: ['com', 'sa'], slaHours: 72, scanEveryMin: 360 },
    domains: [{ id: 1, domain: ZYB_ORG.domain, status: 'new' }, { id: 2, domain: 'corp-shie1d.com', status: 'new' }, { id: 3, domain: 'corp3online.com', status: 'owned' }] };
  const calls = [];
  const brandCall = async (m, p, b) => { calls.push([m, p, b]);
    if (m === 'GET' && p === '/api/brand') return { status: 200, json: JSON.parse(JSON.stringify(B)) };
    if (m === 'POST' && p === '/api/brand/settings') { B.settings = b; return { status: 200, json: { ok: true } }; }
    const mm = /^\/api\/brand\/domain\/(\d+)$/.exec(p); if (m === 'POST' && mm) { B.domains.find((d) => d.id === +mm[1]).status = b.status; return { status: 200, json: { ok: true } }; }
    return { status: 404 }; };
  const zone = { ['portal.' + ZYB_ORG.domain]: { A: ['10.20.0.15'] } };
  const D = createDomains(e.app, { resolver: fakeDns(zone), tlsPeek: async () => ({ subject: 'x', issuer: 'y', valid_to: Date.now() + 300 * DAY, names: [], name_ok: true, trusted: true }), brandCall, noBrand: true });
  e.app.store.collection('assets').put({ id: 'a_portal', name: 'PORTAL-WEB01', type: 'server', mgmt_ip: '10.20.0.15', status: 'in_use' });
  D.putDomain({ name: ZYB_ORG.domain, dns_provider: 'cloudflare' }, ADM);
  D.putDomain({ name: 'corp3.com', dns_provider: 'godaddy' }, ADM);

  const r = await D.brandSync(ADM);
  assert.equal(r.ok, true);
  assert.deepEqual(B.settings.official, [ZYB_ORG.domain, 'corp3.com'], 'official = the register');
  assert.deepEqual(B.settings.keywords, ['corp3'], 'keywords, TLDs and the rest are kept');
  assert.equal(B.domains[0].status, 'owned', 'a look-alike that is ours is marked owned');
  assert.equal(B.domains[1].status, 'new', 'a real look-alike is left for the analyst');
  assert.deepEqual(r.not_registered, ['corp3online.com'], 'owned in Brand Protection but not in the register: listed, not added');
  assert.ok(!D.view('admin').domains.some((d) => d.name === 'corp3online.com'));
  const n = calls.length; await D.brandSync(ADM);
  assert.ok(!calls.slice(n).some(([m]) => m === 'POST'), 'nothing to change = nothing sent');
  assert.equal(D.view('admin').brand.state, 'synced');

  // Brand Protection not installed: says so, changes nothing
  const D2 = createDomains(e.app, { brandCall: async () => ({ status: 404 }), noBrand: true });
  const r2 = await D2.brandSync(ADM); assert.equal(r2.ok, false); assert.match(r2.error, /not installed/);

  // a hostname on a server in the asset register: hosted at the organisation, no "location not recorded" finding
  const h = D.putHost({ fqdn: ('portal.' + ZYB_ORG.domain), purpose: 'Staff portal' }, ADM);
  assert.equal(h.location, 'unknown');
  await D.check('h:' + h.id);
  const hv = D.view('admin').hosts.find((x) => x.id === h.id);
  assert.equal(hv.location, 'onprem'); assert.match(hv.location_name, new RegExp(ZYB_ORG.short + ' data centre')); assert.equal(hv.hosting, (ZYB_ORG.short + ' data centre'));
  assert.ok(!hv.check.findings.some((f) => /not recorded/.test(f.text)), 'no hosting entry needed');
  const h2 = D.putHost({ fqdn: ('erp.' + ZYB_ORG.domain), asset_id: 'a_portal' }, ADM);
  assert.equal(h2.location, 'onprem'); assert.equal(h2.hosting, (ZYB_ORG.short + ' data centre'));
});

// Bug fix: the organisation has an MX record (MX Toolbox shows it) but the platform reported "MX could not be read" - the
// check used the server's own resolver (internal AD DNS: a split zone, or no forwarding). Public DNS is now asked first; the
// server's DNS only when public DNS is unreachable, and then the finding says so and keeps the real error code.
test('domains: MX read from public DNS even when the server\'s DNS fails; a failed lookup keeps its error code', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const pub = { [ZYB_ORG.domain]: { NS: ['ns1.example-dns.net'], MX: [{ priority: 10, exchange: ('mx1.' + ZYB_ORG.domain) }], TXT: [['v=spf1 mx -all']] }, ['_dmarc.' + ZYB_ORG.domain]: { TXT: [['v=DMARC1; p=reject']] } };
  const internal = { [ZYB_ORG.domain]: { NS: 'TIMEOUT', MX: 'TIMEOUT', TXT: 'TIMEOUT', CAA: 'TIMEOUT' }, ['_dmarc.' + ZYB_ORG.domain]: { TXT: 'TIMEOUT' } };
  const D = createDomains(e.app, { resolver: fakeDns(internal), publicResolver: fakeDns(pub), tlsPeek: async () => { throw new Error('n/a'); } });
  const d = D.putDomain({ name: ZYB_ORG.domain, registrar: 'SaudiNIC', dns_provider: 'other' }, ADM);
  await D.check('d:' + d.id);
  let row = e.app.store.collection('dom_checks').get('d:' + d.id);
  assert.deepEqual(row.records.MX, [('10 mx1.' + ZYB_ORG.domain)], 'MX from public DNS');
  assert.equal(row.records.DNS_via, 'public'); assert.equal(row.records.MX_error, '');
  assert.ok(!row.findings.some((f) => /MX could not be read/.test(f.text)), 'no MX error');
  // public DNS unreachable from the server and the server's DNS failing: the real code, and where to look
  const down = { resolveNs: () => Promise.reject(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })), resolveMx: () => Promise.reject(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })), resolveTxt: () => Promise.reject(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })), resolveCaa: () => Promise.reject(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })) };
  const e2 = await startApp({ noAi: true }); t.after(() => e2.close());
  const D2 = createDomains(e2.app, { resolver: fakeDns(internal), publicResolver: down, tlsPeek: async () => { throw new Error('n/a'); } });
  const d2 = D2.putDomain({ name: ZYB_ORG.domain, registrar: 'SaudiNIC', dns_provider: 'other' }, ADM);
  await D2.check('d:' + d2.id);
  row = e2.app.store.collection('dom_checks').get('d:' + d2.id);
  assert.match(row.records.MX_error, /^ETIMEOUT from this server's DNS; public DNS .* not reachable either \(ECONNREFUSED\)/);
  assert.equal(row.records.DNS_via, 'server');
  assert.ok(row.findings.some((f) => /MX could not be read .*not proof the record is missing/.test(f.text) && /MX Toolbox/.test(f.fix)), 'the finding explains it is the lookup, not the domain');
  assert.ok(row.findings.some((f) => /Public DNS .* could not be reached from this server/.test(f.text)), 'says the server DNS was used');
});
