// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the four certificate lifecycle pillars on certificates.html against the REAL ITAM engine (certs.js +
// cert-estate.js + pyengine/cert_estate.py) with a stubbed TLS reader, a stubbed SIEM (agent 1.6 store and CA snapshots) and
// a fake mail sender, all SYNTHETIC: the four pillar cards with live figures and labelled charts; "All certificates" shows
// one row per certificate with every place (network, server store, CA) and its fix; the expiry timeline; alert settings saved
// by an administrator and due alerts sent once; the compliance report with its controls and CSV; tabs grouped by pillar;
// a hostile subject stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cert-lifecycle.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const DAY = 86400000, NOW = Date.now(), iso = (d) => new Date(NOW + d * DAY).toISOString();
const PRESENT = { 'portal.corp.syn:443': { ok: true, subject: 'portal.corp.syn', issuer: 'Corp Issuing CA', names: ['portal.corp.syn'], name_ok: true, trusted: true, self_signed: false, not_after: NOW + 10 * DAY, key_type: 'rsa', key_bits: 2048, serial: '0A1B', fingerprint256: 'FP:1' } };
const stubRead = async (h, p) => { const c = PRESENT[h + ':' + p]; return c ? Object.assign({}, c, { not_after_iso: new Date(c.not_after).toISOString().slice(0, 10) }) : { ok: false, error: 'ECONNREFUSED' }; };
const SIEM = () => ({ available: true, hosts: [
  { host: 'web01.corp.syn', at: iso(0), settings: { certs: [
    { store: 'My', subject: 'portal.corp.syn', issuer: 'Corp Issuing CA', serial: '0A1B', not_before: iso(-355), not_after: iso(10), has_key: true, key_alg: 'RSA', key_bits: 2048, sig_alg: 'sha256RSA', sans: ['portal.corp.syn'], eku: ['Server Authentication'] },
    { store: 'My', subject: 'legacy ' + XSS, issuer: 'Corp Issuing CA', serial: '0E0F', not_before: iso(-800), not_after: iso(-40), has_key: true, key_alg: 'RSA', key_bits: 2048, sig_alg: 'sha1RSA', sans: [], eku: [] }] } },
  { host: 'ca01.corp.syn', at: iso(0), settings: { certs: [], ca_issued: [{ request_id: '17', cn: 'portal.corp.syn', not_after: iso(10), template: 'WebServer', serial: '0a1b' }] } }] });

(async () => {
  const mails = [];
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', readCert: stubRead, certSiem: async () => SIEM(),
    privacyOffice: { send: async (s, m) => { mails.push(m); return { accepted: m.to }; } } });
  const adm = async (p, b) => { const r = await e.req('POST', p, { body: b, user: 'syed', role: 'admin' }); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  await adm('/certs/endpoints', { host: 'portal.corp.syn', port: 443, owner: 'pki@corp.syn', critical: true, issuer_kind: 'adcs' });
  await adm('/certs/scan', {});
  await adm('/pdpl/office/notify', { email_enabled: true, smtp: { host: 'smtp.corp.syn', port: 25, from: 'grc@corp.syn' } });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'certificates.html?standalone=1'); await p.waitForSelector('#pillars .cpill', { timeout: 15000 });
    const pt = await p.textContent('#pillars');
    ok(['Discovery & Inventory', 'Expiration Risk Prevention', 'Automated Renewal & Publishing', 'Compliance & Audit Readiness'].every((x) => pt.includes(x)), 'the four pillars');
    ok(/3 of 3 sources connected/.test(pt) && (await p.textContent('#pillars .cpill .au-num')).trim() === '2', 'inventory figure and sources: ' + pt.replace(/\s+/g, ' ').slice(0, 120));
    ok(await p.$$eval('#pillars circle title, #pillars .bars span', (x) => x.length > 0 && x.every((el) => (el.tagName === 'title' ? el.textContent : el.getAttribute('title')))), 'every chart segment labelled');
    ok((await p.$$eval('#tabs .pgrp', (x) => x.map((el) => el.textContent.trim()))).join('|') === 'Automation|Discovery & Inventory|Expiration Risk|Renewal & Publishing|Compliance & Audit', 'tabs grouped: the Renewal autopilot (default tab, a2b2ed77) first, then by pillar');
    // pillar button -> All certificates
    await p.click('#pillars [data-go="estate"]'); await p.waitForSelector('#estate table', { timeout: 8000 });
    const et = await p.textContent('#estate');
    ok(/On the network/.test(et) && /In a server store/.test(et) && /Issued by the CA/.test(et), 'one row lists every place');
    ok((await p.$$eval('#estate tbody tr', (x) => x.length)) === 2, 'the same serial in three places is one row (2 certificates)');
    ok(et.includes(XSS) && !(await p.$('#estate img')), 'a hostile subject stays text');
    ok(/Fix: /.test(et) && /SHA-1/.test(et), 'risk with its fix');
    await p.selectOption('#esrc', 'ca'); ok((await p.$$eval('#estate tbody tr', (x) => x.length)) === 1, 'source filter');
    // expiry & alerts
    await p.click('[data-tab="expiry"]'); await p.waitForSelector('#alf', { timeout: 8000 });
    ok(/8-30 days/.test(await p.textContent('#tline')) && /portal\.corp\.syn/.test(await p.textContent('#soon')), 'timeline and the expiring list');
    await p.check('#alf [name=enabled]'); await p.fill('#alf [name=recipients]', 'pki-team@corp.syn'); await p.fill('#alf [name=thresholds]', '30, 7');
    await Promise.all([p.waitForResponse((r) => /\/certs\/alerts$/.test(r.url()) && r.request().method() === 'POST'), p.click('#alf [type=submit]')]);
    await p.waitForFunction(() => /on/.test((document.querySelector('#alerts .badge') || {}).textContent || ''), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'alerts switched on'));
    await Promise.all([p.waitForResponse((r) => /\/certs\/alerts\/run$/.test(r.url())), p.click('#alrun')]);
    ok(mails.some((m) => /portal\.corp\.syn/.test(m.subject) && m.to.includes('pki-team@corp.syn') && m.to.includes('pki@corp.syn')), 'alert e-mailed to the list and the owner');
    const nm = mails.length;
    await Promise.all([p.waitForResponse((r) => /\/certs\/alerts\/run$/.test(r.url())), p.click('#alrun')]);
    ok(mails.length === nm, 'not sent twice');
    // report
    await p.click('[data-tab="report"]'); await p.waitForSelector('#report table', { timeout: 8000 });
    const rt = await p.textContent('#report');
    ok(/Controls evidenced/.test(rt) && /not met/.test(rt) && /SAMA CSF 3\.3\.9/.test(rt), 'controls with references');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#rcsv')]);
    ok(/^certificate-inventory-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'inventory CSV');
    ok(e.app.store.auditTail(300).some((a) => a.action === 'certs.report.export') && e.app.store.auditTail(300).some((a) => a.action === 'certs.alerts.settings'), 'audited');
    // an operator cannot change alerts
    WHO = { user: 'nora.syn', role: 'operator' }; await p.goto(base + 'certificates.html?standalone=1&as=op#expiry'); await p.waitForSelector('#alf', { timeout: 10000 });
    await p.click('#alf [type=submit]'); await p.waitForFunction(() => /administrator/.test(document.getElementById('almsg').textContent), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'an operator is refused'));
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
