// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NAC by site (engine/netops/nac-sites.js) over SYNTHETIC endpoints: device class from what was seen; site kind from its name or the
// profile; a camera on the corporate VLAN (high, with the port move to the CCTV VLAN of that site, H3C lines), an unauthorised device on
// management after learning, a contractor still connected after the end date (high at a project site), an undescribed VLAN, low switch
// coverage, the day's count against the site's own history (robust z); per kind summary; the authorisation end date in fmg-nac
// (future, <= 90 days, authorise only; expired = not authorised); routes: analyst reads (viewer refused), admin saves the profile
// (operator refused), fields validated and named, audited.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const NS = require('../engine/netops/nac-sites');
const NAC = require('../engine/netops/fmg-nac');
const { createState } = require('../engine/soc/state');
const { fakeApi } = require('./soc-fakes');

const NOW = Date.parse('2026-11-25T09:00:00Z'), D = 864e5, iso = (t) => new Date(t).toISOString();
const sw = (sw0, port, vlan, vendor = 'h3c-comware') => ({ switch: sw0, device: sw0, port, vlan: String(vlan), desc: '', vendor, shared: 1, moves24: 0 });
const ep = (mac, o) => Object.assign({ mac, ip: '10.1.0.5', host: 'PC-SYN', os: 'Windows 11', site: 'Riyadh Head Office', first_seen: iso(NOW - 30 * D), last_seen: iso(NOW - 3600e3), risk: 0, authorised: true, sw: sw('HO-ACC-01', 'GE1/0/5', 10) }, o);

test('class and kind', () => {
  assert.equal(NS.classOf({ os: 'Hikvision', host: 'CAM-GATE' }), 'camera'); assert.equal(NS.classOf({ host: 'HP LaserJet 4' }), 'printer'); assert.equal(NS.classOf({ os: 'Yealink SIP-T46' }), 'phone');
  assert.equal(NS.classOf({ os: 'Windows Server 2022' }), 'server'); assert.equal(NS.classOf({ os: 'Android 14' }), 'mobile'); assert.equal(NS.classOf({ os: 'Windows 11' }), 'pc'); assert.equal(NS.classOf({}), 'unknown');
  assert.equal(NS.kindOf('Riyadh Head Office'), 'head_office'); assert.equal(NS.kindOf('Jubail Project Site'), 'project_site'); assert.equal(NS.kindOf('Jeddah Branch'), 'branch');
});

test('findings per site, fix steps, history, by kind', () => {
  const E = [ep('aa:00:00:00:00:01'), ep('aa:00:00:00:00:02', { host: 'CAM-LOBBY', os: 'Hikvision IPC', authorised: false, sw: sw('HO-ACC-01', 'GE1/0/9', 10) }),
    ep('aa:00:00:00:00:03', { host: '', os: '', authorised: false, sw: sw('HO-CORE', 'GE1/0/2', 99) }),
    ep('aa:00:00:00:00:04', { site: 'Jubail Project Site', host: 'CONTRACTOR-LT', authorised: false, auth_expires: '2026-11-20', auth_expired: true, sw: sw('JUB-ACC-01', 'GE1/0/7', 60) }),
    ep('aa:00:00:00:00:05', { site: 'Jubail Project Site', sw: sw('JUB-ACC-01', 'GE1/0/8', 77) })];
  for (let i = 0; i < 12; i++) E.push(ep('aa:00:00:00:01:' + String(i).padStart(2, '0'), { site: 'Jeddah Branch', sw: null }));
  const hist = { 'Jeddah Branch': Array.from({ length: 10 }, (_, i) => ({ day: new Date(NOW - (10 - i) * D).toISOString().slice(0, 10), n: 3 + (i % 2) })) };
  const prof = NS.profileOf(null, ['Riyadh Head Office', 'Jubail Project Site', 'Jeddah Branch']);
  const r = NS.analyse({ endpoints: E, learning: false, connected: true }, prof, hist, NOW), has = (code, site) => r.findings.find((f) => f.code === code && (!site || f.site === site));
  const cam = has('wrong-vlan', 'Riyadh Head Office'); assert.equal(cam.severity, 'high'); assert.equal(cam.fix.vlan, '40'); assert.deepEqual(cam.fix.lines, ['system-view', 'interface GE1/0/9', 'port access vlan 40', 'quit', 'save']);
  assert.equal(has('unauthorised', 'Riyadh Head Office').severity, 'high', 'unknown device on management');
  assert.equal(has('expired', 'Jubail Project Site').severity, 'high'); assert.ok(has('vlan-undescribed', 'Jubail Project Site'));
  assert.ok(has('coverage', 'Jeddah Branch') && has('count', 'Jeddah Branch'), 'no switch ports; 12 devices against usually 3-4');
  const ho = r.sites.find((s) => s.site === 'Riyadh Head Office'); assert.equal(ho.kind, 'head_office'); assert.equal(ho.violations, 2); assert.equal(ho.compliance_pct, 33);
  assert.equal(r.by_kind.project_site.sites, 1); assert.ok(r.insights.some((i) => /camera \/ IoT/.test(i)));
  const p2 = NS.profileOf({ sites: { 'Jeddah Branch': 'office' }, overrides: { 'Riyadh Head Office': { 10: 'cctv' } } }, ['Jeddah Branch', 'Riyadh Head Office']);
  assert.equal(p2.sites['Jeddah Branch'], 'office'); assert.equal(p2.kind_source['Jeddah Branch'], 'set');
  assert.ok(!NS.analyse({ endpoints: [E[1]], learning: false }, p2, {}, NOW).findings.some((f) => f.code === 'wrong-vlan'), 'override: VLAN 10 is CCTV at the head office');
});

test('authorisation end date in NAC decisions; expired is not authorised', async () => {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'nacs-')) });
  state.collection('fmg_endpoints').put({ id: 'aa:00:00:00:00:04', mac: 'aa:00:00:00:00:04', site: 'Jubail Project Site', first_seen: iso(NOW - 20 * D), last_seen: iso(NOW - 3600e3), idents: [], sightings: [] });
  const api = fakeApi({ realRanks: true }); NAC.register(api, { state, config: {}, now: () => NOW });
  const base = { mac: 'aa:00:00:00:00:04', action: 'authorise', owner: 'Contractor Syn Co', reason: 'scaffolding contractor laptop' };
  let r = await api.call('POST', '/api/soc/nac/decisions', { role: 'operator', body: Object.assign({}, base, { expires: '2027-06-01' }) }); assert.equal(r.status, 400); assert.match(r.body.error, /90 days/);
  r = await api.call('POST', '/api/soc/nac/decisions', { role: 'operator', body: Object.assign({}, base, { expires: '2026-11-01' }) }); assert.equal(r.status, 400); assert.match(r.body.error, /future/);
  r = await api.call('POST', '/api/soc/nac/decisions', { role: 'operator', body: Object.assign({}, base, { action: 'quarantine', expires: '2026-12-01' }) }); assert.equal(r.status, 400); assert.match(r.body.error, /only an authorisation/);
  r = await api.call('POST', '/api/soc/nac/decisions', { role: 'operator', user: 'syn.ops', body: Object.assign({}, base, { expires: '2026-12-10' }) }); assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.expires, '2026-12-10');
  const L = [{ mac: 'm1', action: 'authorise', status: 'approved', expires: '2026-11-20' }, { mac: 'm2', action: 'authorise', status: 'approved', expires: '2026-12-20' }];
  const a = Object.fromEntries(NAC.assess([{ mac: 'm1', first_seen: iso(NOW - 20 * D) }, { mac: 'm2', first_seen: iso(NOW - 20 * D) }], L, NOW).map((e) => [e.mac, e]));
  assert.equal(a.m1.authorised, false); assert.equal(a.m1.auth_expired, true); assert.equal(a.m2.authorised, true); assert.equal(a.m2.auth_expires, '2026-12-20');
});

test('routes: analyst reads, admin saves the profile, validated and audited', async () => {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'nacs2-')) });
  const deps = { state, config: {}, now: () => NOW, nacApi: { view: () => ({ connected: true, learning: false, endpoints: [ep('aa:00:00:00:00:01'), ep('aa:00:00:00:00:02', { os: 'Hikvision', sw: sw('HO-ACC-01', 'GE1/0/9', 10) })] }) } };
  const api = fakeApi({ realRanks: true }); NS.register(api, deps);
  let r = await api.call('GET', '/api/soc/nac/sites', { role: 'viewer' }); assert.equal(r.status, 403);
  r = await api.call('GET', '/api/soc/nac/sites', { role: 'analyst', user: 'syn.soc' }); assert.equal(r.status, 200); assert.equal(r.body.kpis.sites, 1); assert.equal(r.body.sites[0].kind_source, 'guessed from the name');
  assert.ok(api.audits.some((a) => a.action === 'nac.sites.read'));
  r = await api.call('PUT', '/api/soc/nac/sites/profile', { role: 'operator', body: {} }); assert.equal(r.status, 403);
  r = await api.call('PUT', '/api/soc/nac/sites/profile', { role: 'admin', body: { sites: { 'Riyadh Head Office': 'castle' } } }); assert.equal(r.status, 400); assert.match(r.body.error, /sites\.Riyadh Head Office: one of/);
  r = await api.call('PUT', '/api/soc/nac/sites/profile', { role: 'admin', body: { templates: { branch: { 5000: 'corporate' } } } }); assert.equal(r.status, 400); assert.match(r.body.error, /1-4094/);
  r = await api.call('PUT', '/api/soc/nac/sites/profile', { role: 'admin', body: { extra: 1 } }); assert.equal(r.status, 400); assert.match(r.body.error, /not a profile field/);
  r = await api.call('PUT', '/api/soc/nac/sites/profile', { role: 'admin', user: 'syn.admin', body: { sites: { 'Riyadh Head Office': 'head_office' }, overrides: { 'Riyadh Head Office': { 10: 'cctv' } } } }); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(api.audits.some((a) => a.action === 'nac.sites.profile' && a.user === 'syn.admin'));
  r = await api.call('GET', '/api/soc/nac/sites', { role: 'analyst' }); assert.equal(r.body.sites[0].kind_source, 'set'); assert.equal(r.body.kpis.violations, 1, 'VLAN 10 is CCTV now: the PC is the one on the wrong VLAN');
});
