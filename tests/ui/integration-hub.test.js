// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Integration Hub (connections.html): what needs attention first (a failing connection, a stale one, one never read), each
// connection's last sync (hosts, VMs) and what it feeds, and the guided vCenter / ESXi / Nutanix set-up - choose the platform,
// the read-only account steps (Next only once the account exists), connect and test, an untrusted certificate shown with its
// fingerprint and trusted with one click (no browser pop-up), the first sync with hosts / VMs / clusters, a refused password
// explained with the fix. Stub IT Asset Management; platforms, addresses and passwords are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node integration-hub.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const iso = (ms) => new Date(Date.now() - ms).toISOString(), H = 3600000;
const P = [
  { id: 'vp_ok', kind: 'vcenter', label: 'VC-HQ (synthetic)', base_url: 'https://vc-hq.synthetic.test', credentials_set: true, interval_min: 60, tls_fingerprint: 'aa', last_test: { at: iso(2 * H), ok: true }, last_sync: { at: iso(20 * 60000), ok: true, hosts: 6, vms: 140 } },
  { id: 'vp_stale', kind: 'nutanix', label: 'Prism-DR (synthetic)', base_url: 'https://prism-dr.synthetic.test:9440', credentials_set: true, interval_min: 60, last_test: { at: iso(30 * H), ok: true }, last_sync: { at: iso(10 * H), ok: true, hosts: 4, vms: 60 } },
  { id: 'vp_bad', kind: 'esxi', label: 'ESXi-LAB (synthetic)', base_url: 'https://10.0.0.9', credentials_set: true, interval_min: 60, last_test: { at: iso(H), ok: false, error_class: 'auth', message: 'login refused' } },
];
let NEW = null, pinned = false, wrongPass = true, KSC = [], ZS = [], kscTries = 0, ssoTries = 0, SG = { connection: { ok: true, base_dn: 'DC=synthetic,DC=test' }, settings: { claim: 'sam' }, groups: null, open: null, applied: null }, ADM = { enabled: false, delete_enabled: false, create_ou: '', protected: [] }, adTries = 0;
const ROOTPEM = '-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDLVJPT1Q=\n-----END CERTIFICATE-----\n';
let SSO = { provider: 'Microsoft Entra ID', issuer: 'https://login.microsoftonline.com/synthetic/v2.0', clientId: 'cid', hasSecret: true, enabled: false, requireMfa: true, roleMap: { 'SENTRA-SOC-Operators': 'operator' } };
const calls = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : {}; calls.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/virt' && req.method === 'GET') return json(200, { platforms: P.concat(NEW ? [NEW] : []), kinds: {}, sites: [] });
    if (u === '/api/itam/virt' && req.method === 'POST') return body((b) => { NEW = Object.assign(NEW || { id: 'vp_new', credentials_set: true }, { kind: b.kind, label: b.label, base_url: b.base_url, interval_min: b.interval_min, site: b.site }); json(200, { platform: NEW }); });
    if (u === '/api/itam/virt/vp_new/test') return body(() => {
      if (wrongPass) { wrongPass = false; return json(200, { result: { ok: false, error_class: 'auth', message: 'Cannot complete login' }, platform: NEW }); }
      if (!pinned) { NEW.presented = { fingerprint256: 'AB:CD:EF:12:34:56:78:90' }; return json(200, { result: { ok: false, error_class: 'tls', message: 'self-signed certificate' }, platform: NEW }); }
      NEW.presented = null; NEW.last_test = { at: new Date().toISOString(), ok: true }; json(200, { result: { ok: true, version: 'vCenter 8.0.2' }, platform: NEW }); });
    if (u === '/api/itam/virt/vp_new/pin') return body((b) => { pinned = b.fingerprint === 'AB:CD:EF:12:34:56:78:90'; json(pinned ? 200 : 409, pinned ? { platform: NEW } : { error: 'pin only the certificate shown by the last test' }); });
    if (u === '/api/itam/virt/vp_new/sync') return body(() => { NEW.last_sync = { at: new Date().toISOString(), ok: true, hosts: 3, vms: 42, clusters: 1, approved: 45, ms: 2400 }; json(200, { sync: NEW.last_sync }); });
    if (u === '/api/soc/m365/config') return json(200, { m365: { tenant: 'synthetic-tenant-id', client_id: 'cid', client_secret_set: true, enabled: true }, graph: { enabled: true, ready: true, missing: [], updated: iso(30 * 60000), blocks: { users: { ok: true }, signins: { ok: true }, risky: { ok: false, error: 'Forbidden: IdentityRiskyUser.Read.All not granted' } } } });
    if (u === '/auth/admin/config') return json(200, { sso: SSO });
    if (u === '/auth/admin/sso' && req.method === 'POST') return body((b) => { const k = Object.assign({}, b); delete k.clientSecret; SSO = Object.assign({}, SSO, k, b.clientSecret ? { hasSecret: true } : {}); json(200, { ok: true }); });
    if (u === '/auth/admin/sso/test') return body(() => { ssoTries++; json(200, ssoTries === 1 ? { error: 'unable to verify the first certificate (UNABLE_TO_VERIFY_LEAF_SIGNATURE)' } : { ok: true, issuer: SSO.issuer, keys: 2, amrSupported: false }); });
    if (u === '/api/itam/ad-directory') return json(200, { connection: { ok: true, servers: ['dc1.synthetic.test'], base_dn: 'DC=synthetic,DC=test' }, last: { at: iso(30 * 24 * H), by: 'syed', count: 412 } });
    if (u === '/api/itam/ad-manage' && req.method === 'GET') return json(200, { connection: { ok: true, servers: ['ldaps://dc1.synthetic.test'], base_dn: 'DC=synthetic,DC=test' }, settings: ADM, delete_days: 30, pending: 0, reviews: 0, requests: [] });
    if (u === '/api/itam/onboarding/ad/test') return body(() => json(200, { ok: true, server: 'ldaps://dc1.synthetic.test:636', ou_found: true }));
    if (u === '/api/itam/ad-manage/settings') return body((b) => { ADM = b; json(200, { connection: { ok: true, base_dn: 'DC=synthetic,DC=test' }, settings: b, delete_days: 30, pending: 0, reviews: 0, requests: [] }); });
    if (u === '/api/itam/ad-connect/discover') return body((b) => json(200, { domain: b.domain, base_dn: 'DC=synthetic,DC=test', servers: [{ host: 'dc01.synthetic.test', url: 'ldaps://dc01.synthetic.test:636' }, { host: 'dc02.synthetic.test', url: 'ldaps://dc02.synthetic.test:636' }, { host: 'dc03.synthetic.test', url: 'ldaps://dc03.synthetic.test:636' }], why: '' }));
    if (u === '/api/itam/ad-connect/certificate') return body((b) => /^dc09\./.test(b.server) && !b.ip ? json(424, { error: 'the platform server cannot resolve dc09.synthetic.test - its DNS server must be one of your domain controllers (or add the name to /etc/hosts) - or give its IP address: the platform connects to the IP and still verifies the certificate as dc09.synthetic.test' })
      : /^dc66\./.test(b.server) ? json(424, { error: 'dc66.synthetic.test refused the connection on that port - LDAPS (636) is off' }) : json(200, { server: 'ldaps://' + b.server + ':636', host: b.server, name_matches: true,
      ip: /^\d+\./.test(b.server) ? b.server : '', verify_as: /^\d+\./.test(b.server) ? 'dc01.synthetic.test' : b.server, by_ip: /^\d+\./.test(b.server) ? 'You typed an IP address. The certificate is for dc01.synthetic.test: the platform connects to ' + b.server + ' and verifies the certificate under that name.' : '', presented: { subject: 'CN=dc01.synthetic.test', issuer: 'CN=Synthetic Root CA', valid_to: '2027-11-12T00:00:00.000Z', names: ['dc01.synthetic.test'], fingerprint256: 'AA:BB' }, chain: [], root: { subject: 'CN=Synthetic Root CA', fingerprint256: '11:22:33:44:SYN', valid_to: '2036-01-01T00:00:00.000Z', pem: ROOTPEM }, why: '', how_to_check: 'On the domain controller: certlm.msc -> Trusted Root (synthetic)' }));
    if (u === '/api/itam/ad-connect/test') return body(() => { adTries++; adTries === 1 ? json(401, { error: 'the domain controller refused the sign-in: the user name or password is wrong (AD code 52e)' }) : json(200, { ok: true, server: 'ldaps://dc01.synthetic.test:636', dc: 'dc01.synthetic.test', base_dn: 'DC=synthetic,DC=test', bind_dn: 'CN=svc-read,OU=Service,DC=synthetic,DC=test', people: 420, enabled: 401, domain: 'synthetic.test' }); });
    if (u === '/api/itam/ad-connect/save') return body(() => json(200, { ok: true, saved: true, base_dn: 'DC=synthetic,DC=test', people: 420 }));
    if (u === '/api/itam/ad-directory/settings') return body((b) => json(200, { settings: b }));
    if (u === '/api/itam/ad-directory/refresh') return body(() => json(200, { users: [{ sam: 'a.syn', enabled: true }, { sam: 'b.syn', enabled: true, admin_count: true }, { sam: 'c.syn', enabled: false }] }));
    if (u === '/api/itam/sso-groups' && req.method === 'GET') return json(200, SG);
    if (u === '/api/itam/sso-groups/refresh') return body((b) => { SG.groups = { at: new Date().toISOString(), by: 'syed', q: b.q, items: [{ dn: 'CN=SENTRA-Platform-Admins,OU=Groups,DC=synthetic,DC=test', sam: 'SENTRA-Platform-Admins', description: 'platform admins <b>x</b>' }, { dn: 'CN=SENTRA-SOC-Operators,OU=Groups,DC=synthetic,DC=test', sam: 'SENTRA-SOC-Operators' }, { dn: 'CN=Domain Users,CN=Users,DC=synthetic,DC=test', sam: 'Domain Users', broad: true }] }; json(200, SG); });
    if (u === '/api/itam/sso-groups/settings') return body((b) => { SG.settings = b; json(200, SG); });
    if (u === '/api/itam/sso-groups/propose') return body((b) => { SG.open = { id: 'SSO-SYN1-AAAA', status: 'proposed', by: 'syed', mappings: b.mappings.map((m) => ({ group: m.group.replace(/^CN=([^,]+).*$/, '$1'), role: m.role })) }; json(200, SG.open); });
    if (u === '/api/itam/me/status') return json(200, { ec: { base_url: 'https://ec.synthetic.test:8383', key_set: true, last_sync: { at: iso(H), ok: true } }, sdp: {}, computers: 380 });
    if (u === '/api/itam/backup') return json(200, { platforms: [{ id: 'bk1', label: 'Veeam-HQ (synthetic)', kind: 'veeam', base_url: 'https://veeam.synthetic.test:9419', credentials_set: true, interval_min: 60, last_sync: { at: iso(H), ok: false, error: 'HTTP 401: token expired' } }] });
    if (u === '/api/itam/storage') return json(200, { platforms: [] });
    if (u === '/api/soc/ksc/overview') return json(200, { servers: KSC });
    if (u === '/api/soc/ksc/servers' && req.method === 'POST') return body((b) => { KSC = KSC.filter((x) => x.id !== b.id).concat([Object.assign({ credentials: {} }, b)]); json(200, b); });
    if (/^\/api\/soc\/ksc\/servers\/[^/]+\/credentials$/.test(u)) return body((b) => json(200, { ok: true }));
    if (/^\/api\/soc\/ksc\/servers\/[^/]+\/test$/.test(u)) return body(() => { kscTries++; json(200, kscTries === 1 ? { ok: false, error: 'getaddrinfo EAI_AGAIN ksc.synthetic.test' } : { ok: true, hostsInKsc: 120, fieldsReturned: ['a', 'b', 'c'], fieldsMissing: [] }); });
    if (/^\/api\/soc\/ksc\/servers\/[^/]+\/sync$/.test(u)) return body(() => { KSC[0].last = { at: Date.now(), errors: [] }; json(200, { ok: true }); });
    if (u === '/api/soc/zscaler/overview') return json(200, { tenants: ZS });
    if (u === '/api/soc/zscaler/tenants' && req.method === 'POST') return body((b) => { ZS = [Object.assign({ credentials: {} }, b)]; json(200, b); });
    if (/^\/api\/soc\/zscaler\/tenants\/[^/]+\/credentials$/.test(u)) return body(() => json(200, { ok: true }));
    if (/^\/api\/soc\/zscaler\/tenants\/[^/]+\/test$/.test(u)) return body(() => json(200, { zia: { ok: true, counts: { users: 900, url_categories: 41 } }, zpa: { ok: false, error: 'HTTP 401 invalid client secret' } }));
    if (/^\/api\/soc\/zscaler\/tenants\/[^/]+\/sync$/.test(u)) return body(() => { ZS[0].last = { at: Date.now(), errors: [] }; json(200, { synced: true, errors: [] }); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = []; let dialogs = 0;
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); page.on('pageerror', (x) => errs.push(x.message)); page.on('dialog', (d) => { dialogs++; d.dismiss(); });
  const wait = (fn, a) => page.waitForFunction(fn, a, { timeout: 15000 }).then(() => true, () => false);
  const txt = (sel) => page.$eval(sel, (x) => x.innerText.replace(/\s+/g, ' '));
  try {
    await page.goto('http://127.0.0.1:' + srv.address().port + '/connections.html?standalone=1');
    ok(await wait(() => document.getElementById('cn-virt') && /VC-HQ/.test(document.getElementById('cn-virt').innerText)), 'virtualization card with its connections');
    ok(/Integration Hub/.test(await page.title()) && /Integration Hub/.test(await txt('.page-title')), 'the page is the Integration Hub');
    const att = await txt('#needs');
    ok(/Needs attention \(\d+\)/.test(att) && att.indexOf('ESXi-LAB') < att.indexOf('Prism-DR'), 'needs attention: a failing connection before a stale one');
    ok(/login refused/.test(att) && /stale - last read 10 h ago/.test(att), 'each with the reason');
    const card = await txt('#cn-virt');
    ok(/6 hosts, 140 VMs/.test(card) && /certificate pinned/.test(card), 'last sync and the pinned certificate shown');
    ok(/stale/.test(card) && /1\/3 connected/.test(card), 'a stale connection is not counted as connected');
    ok(await page.$('#cn-virt a[href="capacity.html"]') && /Feeds:.*Virtualization.*Asset Discovery/.test(card), 'what the connection feeds');
    // the integrations set up on their own pages
    ok(/2 of 3 data sets read/.test(await txt('#cn-m365')) && /IdentityRiskyUser\.Read\.All/.test(await txt('#cn-m365')) && await page.$('#cn-m365 a[href="m365.html"].btn'), 'Microsoft 365: data sets read, the missing permission named, set up on its own page');
    ok(/configured, not enabled/.test(await txt('#cn-sso')) && /1 group\(s\) mapped/.test(await txt('#cn-sso')) && /MFA required/.test(await txt('#cn-sso')), 'single sign-on: configured but not enabled, groups mapped, MFA');
    ok(/412 users/.test(await txt('#cn-ad')) && /stale/.test(await txt('#cn-ad')) && /Read directory on User Management/.test(await txt('#cn-ad')), 'Active Directory: users read a month ago is stale, with what to press');
    ok(/380 computers/.test(await txt('#cn-ec')) && /1\/1 connected/.test(await txt('#cn-ec')), 'Endpoint Central connected');
    ok(/token expired/.test(await txt('#cn-backup')) && /No connection yet/.test(await txt('#cn-storage')) && await page.$('#cn-storage a[href="storage.html"].btn'), 'backup failing, storage not set up with its set-up link');
    const att2 = await txt('#needs'); ok(/Veeam-HQ/.test(att2) && /configured, not enabled/.test(att2) && /Microsoft 365|Tenant/.test(att2), 'needs attention includes the new integrations');
    ok(!(await page.$('#cn-m365 [data-act=test]')) && !(await page.$('#cn-m365 [data-act=del]')), 'no Test or Remove where the set-up lives on another page');
    ok(/Feeds:.*User Management.*Access Reviews/.test(await txt('#cn-ad')), 'what AD feeds');
    // the wizard
    await page.click('#cn-virt [data-act=add]'); await page.waitForSelector('[data-wz=next]');
    ok(/Platform/.test(await txt('.steps')) && (await page.$$('input[name=wz-kind]')).length === 3, 'step 1: three platforms');
    await page.click('label:has(input[name=wz-kind][value=vcenter])'); await page.click('[data-wz=next]');
    ok(/Global Permissions/.test(await txt('#modal')) && /Read-only/.test(await txt('#modal')) && /svc-zyberon-ro@vsphere.local/.test(await txt('#wz-sug')), 'step 2: the read-only account, step by step');
    ok(await page.$eval('#wz-n2', (b) => b.disabled), 'Next waits until the account exists');
    await page.check('#wz-done'); ok(!(await page.$eval('#wz-n2', (b) => b.disabled)), 'Next enabled'); await page.click('#wz-n2');
    await page.fill('#wz-url', 'http://vc-new.synthetic.test'); await page.fill('#wz-user', 'svc-zyberon-ro@vsphere.local'); await page.fill('#wz-pass', 'Synthetic-Pass-1'); await page.click('[data-wz=connect]');
    ok(await wait(() => /https:\/\/name-or-IP/.test([...document.querySelectorAll('.toast-zyb')].map((t) => t.textContent).join(' '))), 'plain http refused before anything is sent');
    ok(!calls.some((c) => c[1] === '/api/itam/virt' && c[0] === 'POST'), 'nothing posted');
    await page.fill('#wz-url', 'https://vc-new.synthetic.test'); await page.click('[data-wz=connect]');
    ok(await wait(() => /password was refused/.test(document.getElementById('modal').innerText)), 'a refused login explained with the fix');
    ok(calls.find((c) => c[1] === '/api/itam/virt' && c[0] === 'POST')[2].label === 'vc-new.synthetic.test', 'name taken from the address');
    await page.fill('#wz-pass', 'Synthetic-Pass-2'); await page.click('[data-wz=connect]');
    ok(await wait(() => document.getElementById('wz-cert') && /AB:CD:EF:12:34:56:78:90/.test(document.getElementById('wz-cert').innerText)), 'untrusted certificate shown with its fingerprint');
    ok(calls.filter((c) => c[1] === '/api/itam/virt' && c[0] === 'POST').every((c) => c[2].id === undefined || c[2].id === 'vp_new'), 'the second try updates the same connection');
    await page.click('[data-wz=pin]');
    ok(await wait(() => /Read 3 host\(s\) and 42 VM\(s\)/.test(document.getElementById('modal').innerText)), 'pinned, tested and first sync read');
    const m = await txt('#modal'); ok(/Certificate pinned/.test(m) && /Signed in with the read-only account · vCenter 8.0.2/.test(m) && /42 VMs/.test(m) && /45 Added to IT Asset Management/.test(m), 'step 4: the result');
    ok(calls.find((c) => /\/pin$/.test(c[1]))[2].fingerprint === 'AB:CD:EF:12:34:56:78:90', 'the fingerprint shown is the one pinned');
    ok(!calls.some((c) => JSON.stringify(c[2]).includes('Synthetic-Pass') && !(c[1] === '/api/itam/virt')), 'the password goes only to the save call');
    ok(!dialogs, 'no browser pop-ups');
    await page.click('[data-wz=close]'); ok(await wait(() => /vc-new\.synthetic\.test/.test(document.getElementById('cn-virt').innerText) && /3 hosts, 42 VMs/.test(document.getElementById('cn-virt').innerText)), 'the new connection on the card');
    // Kaspersky Security Center
    const toastIs = (re) => wait((r) => new RegExp(r).test([...document.querySelectorAll('.toast-zyb')].map((t) => t.textContent).join(' ')), re.source);
    await page.click('#cn-ksc [data-act=add]'); await page.waitForSelector('#gz-n');
    ok(/Auditor/.test(await txt('#modal')) && /13299/.test(await txt('#modal')) && /openssl s_client/.test(await txt('#modal')), 'KSC: read-only Auditor role, the port and the fingerprint command');
    ok(await page.$eval('#gz-n', (b) => b.disabled), 'KSC: Next waits for the account'); await page.check('#gz-done'); await page.click('#gz-n');
    await page.fill('#gz-host', 'https://ksc.synthetic.test'); await page.fill('#gz-user', 'svc-zyberon-ro'); await page.fill('#gz-password', 'Synthetic-KSC-1'); await page.click('#gz-go');
    ok(await toastIs(/without https/), 'KSC: a URL instead of a host refused');
    await page.fill('#gz-host', 'ksc.synthetic.test'); await page.fill('#gz-fingerprint256', 'AB:CD'); await page.click('#gz-go');
    ok(await toastIs(/64 hex characters/), 'KSC: a short fingerprint refused');
    const FP = Array.from({ length: 32 }, (_, i) => (i + 16).toString(16).toUpperCase().padStart(2, '0')).join(':');
    await page.fill('#gz-fingerprint256', FP); await page.click('#gz-go');
    ok(await wait(() => /does not resolve on the platform server \(DNS\)/.test(document.getElementById('modal').innerText)), 'KSC: a DNS failure explained with the fix');
    await page.fill('#gz-password', 'Synthetic-KSC-1'); await page.click('#gz-go');
    ok(await wait(() => /Signed in - 120 hosts in KSC/.test(document.getElementById('modal').innerText) && /First read done/.test(document.getElementById('modal').innerText)), 'KSC: signed in, first read');
    const kc = calls.filter((c) => /\/ksc\/servers\/ksc-ksc-synthetic-test\/credentials$/.test(c[1])).pop();
    ok(kc && kc[2].fingerprint256 === FP && kc[2].password === 'Synthetic-KSC-1', 'KSC: the fingerprint pinned with the sealed password');
    ok(!calls.some((c) => /\/ksc\/servers$/.test(c[1]) && JSON.stringify(c[2]).includes('Synthetic-KSC')), 'KSC: the password is not in the connection record');
    ok(/120/.test(await txt('#modal')) && await page.$('#modal a[href="ai-ksc-engineer.html"]'), 'KSC: result and where to look');
    await page.click('[data-gz=close]'); ok(await wait(() => /ksc\.synthetic\.test/.test(document.getElementById('cn-ksc').innerText)), 'KSC: the connection on its card');
    // Zscaler
    await page.click('#cn-zscaler [data-act=add]'); await page.waitForSelector('#gz-n');
    ok(/View Only/.test(await txt('#modal')) && /API Key Management/.test(await txt('#modal')) && /cannot use SAML/.test(await txt('#modal')), 'Zscaler: the read-only role, the API key and no SAML');
    await page.check('#gz-done'); await page.click('#gz-n');
    await page.fill('#gz-label', 'Synthetic Tenant'); await page.fill('#gz-username', 'svc-ro@synthetic.test'); await page.fill('#gz-apiKey', 'synthetic-key'); await page.fill('#gz-password', 'Synthetic-ZS-1'); await page.fill('#gz-customerId', '1234');
    await page.click('#gz-go'); ok(await toastIs(/client ID and secret/), 'Zscaler: ZPA needs all three fields');
    await page.fill('#gz-clientId', 'cid'); await page.fill('#gz-clientSecret', 'bad'); await page.click('#gz-go');
    ok(await wait(() => /ZIA: signed in/.test(document.getElementById('modal').innerText) && /First read done/.test(document.getElementById('modal').innerText)), 'Zscaler: ZIA signed in and first read');
    const zm = await txt('#modal'); ok(/ZPA: HTTP 401 invalid client secret/.test(zm) && /The account was refused/.test(zm), 'Zscaler: the ZPA failure explained');
    ok(/900/.test(zm) && /url categories/.test(zm), 'Zscaler: what was read');
    ok(calls.find((c) => c[1] === '/api/soc/zscaler/tenants')[2].id === 'synthetic-tenant', 'Zscaler: tenant id from the name');
    await page.click('[data-gz=close]');
    ok(!dialogs, 'still no browser pop-ups');
    // the summary strip: every connection readable on one line, never squeezed into a narrow column
    await wait(() => [...document.querySelectorAll('#summary .cn-sum')].filter((e) => e.getBoundingClientRect().width > 0).length >= 15);
    const sw = await page.$$eval('#summary .cn-sum', (els) => els.map((e) => [e.getBoundingClientRect().width, e.querySelector('.small').getBoundingClientRect().height]));
    ok(sw.length >= 15 && sw.every((x) => x[0] >= 200 && x[1] < 30), 'summary: ' + sw.length + ' tiles, each at least 200 px wide with its status on one line: ' + JSON.stringify(sw.slice(0, 3)));
    // Connect Active Directory: domain -> domain controllers -> certificate by fingerprint -> account tested -> import
    await page.click('#cn-ad [data-act=add]'); await page.waitForSelector('#ad-domain');
    await page.fill('#ad-domain', 'not a domain'); await page.click('[data-ad=find]'); ok(await toastIs(/Type the domain name/), 'AD: a bad domain name refused');
    await page.fill('#ad-domain', 'synthetic.test'); await page.click('[data-ad=find]'); await page.waitForSelector('[data-adsrv]');
    ok((await page.$$('[data-adsrv]')).length === 3 && (await page.$$('[data-adsrv]:checked')).length === 2, 'AD: domain controllers found in DNS, the first two chosen');
    await page.click('[data-ad=next1]'); ok(await wait(() => /11:22:33:44:SYN/.test(document.getElementById('modal').innerText)), 'AD: the root CA with its SHA-256 fingerprint');
    ok(/certlm\.msc/.test(await txt('#modal')) && /name matches/.test(await txt('#modal')) && await page.$eval('[data-ad=next2]', (b) => b.disabled), 'AD: how to compare it; Next waits for the confirmation');
    await page.check('#ad-trust'); await page.click('[data-ad=next2]'); await page.waitForSelector('#ad-user');
    ok(/New-ADUser svc-zyberon-read/.test(await txt('#modal')) && /refuses privileged accounts/.test(await txt('#modal')), 'AD: how to create a normal read-only account');
    await page.fill('#ad-user', 'svc-read@synthetic.test'); await page.fill('#ad-pw', 'Synthetic-AD-Pass'); await page.click('[data-ad=test]');
    ok(await wait(() => /user name or password is wrong \(AD code 52e\)/.test(document.getElementById('modal').innerText)), 'AD: a wrong password explained');
    ok(await page.$eval('[data-ad=next3]', (b) => b.disabled), 'AD: Next waits for a successful test');
    await page.click('[data-ad=test]'); ok(await wait(() => /Signed in/.test(document.getElementById('modal').innerText) && /420 people, 401 enabled/.test(document.getElementById('modal').innerText)), 'AD: the retry keeps the password; signed in, people counted');
    const tc = calls.filter((c) => c[1] === '/api/itam/ad-connect/test').pop()[2];
    ok(tc.ca_pem === ROOTPEM && tc.servers.join('|') === 'dc01.synthetic.test|dc02.synthetic.test' && tc.user === 'svc-read@synthetic.test', 'AD: tested with the confirmed CA and the chosen domain controllers');
    await page.click('[data-ad=next3]'); await page.fill('#ad-group', 'SENTRA-Platform-Users'); await page.selectOption('#ad-auto', '12'); await page.click('[data-ad=save]');
    ok(await wait(() => /Active Directory connected/.test(document.getElementById('modal').innerText)), 'AD: connected and imported');
    const dm = await txt('#modal'); ok(/3 People imported/.test(dm) && /1 Privileged/.test(dm) && /every 12 h/.test(dm) && await page.$('#modal a[href="sso-access.html"]'), 'AD: what was imported and what to do next');
    ok(calls.find((c) => c[1] === '/api/itam/ad-directory/settings')[2].group === 'SENTRA-Platform-Users' && calls.find((c) => c[1] === '/api/itam/ad-directory/settings')[2].auto_hours === 12, 'AD: the import group and the re-read saved');
    ok(!calls.some((c) => !/ad-connect\/(test|save)$/.test(c[1]) && JSON.stringify(c[2]).includes('Synthetic-AD-Pass')), 'AD: the password goes only to test and save');
    await page.click('[data-ad=close]');
    // a domain controller typed as an IP address (the certificate is for its name)
    await page.click('#cn-ad [data-act=add]'); await page.waitForSelector('#ad-manual');
    await page.fill('#ad-domain', 'synthetic.test'); await page.fill('#ad-manual', '192.168.12.51'); await page.click('[data-ad=next1]');
    ok(await wait(() => /You typed an IP address\. The certificate is for dc01\.synthetic\.test/.test(document.getElementById('modal').innerText)), 'AD by IP: the name from the certificate is shown');
    await page.check('#ad-trust'); await page.click('[data-ad=next2]'); await page.waitForSelector('#ad-user');
    await page.fill('#ad-user', 'SYNTHETIC\\svc-read'); await page.fill('#ad-pw', 'Synthetic-AD-Pass'); await page.click('[data-ad=test]');
    ok(await wait(() => /Signed in/.test(document.getElementById('modal').innerText)), 'AD by IP: signed in');
    const ipt = calls.filter((c) => c[1] === '/api/itam/ad-connect/test').pop()[2];
    ok(ipt.servers.length === 1 && ipt.servers[0].name === 'dc01.synthetic.test' && ipt.servers[0].ip === '192.168.12.51' && ipt.user === 'SYNTHETIC\\svc-read', 'AD by IP: the IP dialled, the certificate verified as its name: ' + JSON.stringify(ipt.servers));
    await page.click('[data-ad=close]');
    // names, IP addresses or both; a name the platform cannot resolve gets its IP; a dead one is removed
    await page.click('#cn-ad [data-act=add]'); await page.waitForSelector('#ad-manual');
    await page.fill('#ad-domain', 'synthetic.test'); await page.fill('#ad-manual', '192.168.12.51, dc09.synthetic.test dc66.synthetic.test'); await page.click('[data-ad=next1]');
    ok(await wait(() => /dc09\.synthetic\.test - the platform server's DNS cannot resolve this name/.test(document.getElementById('modal').innerText)), 'mixed list: a name that does not resolve asks for its IP');
    ok(/dc66\.synthetic\.test - dc66\.synthetic\.test refused the connection/.test(await txt('#modal')) && await page.$eval('[data-ad=next2]', (b) => b.disabled), 'mixed list: a dead server named, and Next waits');
    await page.click('[data-adrm="dc66.synthetic.test"]'); await page.waitForSelector('[data-ipfor]');
    await page.fill('[data-ipfor="dc09.synthetic.test"]', 'not-an-ip'); await page.click('[data-ad=useip]'); ok(await toastIs(/Enter an IP address/), 'mixed list: a bad IP refused');
    await page.fill('[data-ipfor="dc09.synthetic.test"]', '10.0.0.9'); await page.click('[data-ad=useip]');
    ok(await wait(() => /You typed an IP address/.test(document.getElementById('modal').innerText) && !document.querySelector('[data-ipfor]')), 'mixed list: every server answered');
    await page.check('#ad-trust'); await page.click('[data-ad=next2]'); await page.waitForSelector('#ad-user');
    await page.fill('#ad-user', 'svc-read@synthetic.test'); await page.fill('#ad-pw', 'Synthetic-AD-Pass'); await page.click('[data-ad=test]');
    await wait(() => /Signed in/.test(document.getElementById('modal').innerText));
    const mx = calls.filter((c) => c[1] === '/api/itam/ad-connect/test').pop()[2].servers;
    ok(JSON.stringify(mx) === JSON.stringify([{ name: 'dc01.synthetic.test', ip: '192.168.12.51' }, { name: 'dc09.synthetic.test', ip: '10.0.0.9' }]), 'mixed list: an IP verified as its certificate name, a name dialled at its IP, the dead one gone: ' + JSON.stringify(mx));
    await page.click('[data-ad=close]');
    // AD Management: switched off, then switched on through the wizard
    ok(/switched off - press Switch on/.test(await txt('#cn-admanage')), 'AD Management card: switched off, says what to press');
    await page.click('#cn-admanage [data-act=add]'); await page.waitForSelector('#gz-n');
    ok(/Delegate Control/.test(await txt('#modal')) && /Never make it a Domain Admin/.test(await txt('#modal')) && /DC=synthetic,DC=test/.test(await txt('#modal')), 'AD Management wizard: the delegated rights, not Domain Admin, the connection it uses');
    await page.check('#gz-done'); await page.click('#gz-n');
    await page.fill('#gz-protected', 'breakglass1, bad name!'); await page.click('#gz-go'); ok(await toastIs(/is not an AD user name/), 'AD Management: a bad protected name refused');
    await page.fill('#gz-protected', 'breakglass1, svc-backup'); await page.selectOption('#gz-delete', 'true'); await page.click('#gz-go');
    ok(await wait(() => /On - every change is approved by a second administrator/.test(document.getElementById('modal').innerText)), 'AD Management: directory tested, switched on');
    ok(ADM.enabled === true && ADM.delete_enabled === true && ADM.protected.join('|') === 'breakglass1|svc-backup', 'AD Management: settings saved as entered');
    ok(calls.some((c) => c[1] === '/api/itam/onboarding/ad/test'), 'AD Management: the directory connection tested first');
    await page.click('[data-gz=close]'); ok(await wait(() => /every change approved by a second administrator/.test(document.getElementById('cn-admanage').innerText)), 'AD Management card: on');
    // Set up single sign-on: provider -> connect and test -> AD groups to roles (proposed) -> switch on -> how to test
    await page.click('#cn-sso [data-act=add]'); await page.waitForSelector('input[name=sw-prov]');
    const s1 = await txt('#modal'); ok(/Set up single sign-on/.test(s1) && /Nobody gets a separate platform user name/.test(s1) && /Microsoft Entra ID · https:\/\/login\.microsoftonline\.com/.test(s1) && /1 group\(s\) mapped/.test(s1), 'SSO step 1: what it does, and what is set now');
    ok(await page.$eval('input[name=sw-prov][value=entra]', (r) => r.checked), 'SSO: the current provider is preselected');
    await page.check('input[name=sw-prov][value=adfs]'); await page.click('[data-sw=next]'); await page.waitForSelector('#sw-host');
    const s2 = await txt('#modal'); ok(/Server application accessing a web API/.test(s2) && /Token-Groups - Unqualified Names/.test(s2) && /\/auth\/sso\/callback/.test(s2), 'SSO step 2 (AD FS): what to prepare, with the redirect URI');
    ok(await page.$eval('[data-sw=next]', (b) => b.disabled), 'SSO: Next waits for a successful test');
    await page.fill('#sw-host', 'sts'); await page.fill('#sw-cid', '11111111-2222-3333-4444-555555555555'); await page.click('[data-sw=test]'); ok(await toastIs(/full name such as sts/), 'SSO: a short AD FS name refused');
    await page.fill('#sw-host', 'https://sts.synthetic.test/adfs'); await page.fill('#sw-cid', 'abc'); await page.click('[data-sw=test]'); ok(await toastIs(/Client ID: the GUID/), 'SSO: a client ID that is not a GUID refused');
    await page.fill('#sw-cid', '11111111-2222-3333-4444-555555555555'); await page.click('[data-sw=test]'); ok(await toastIs(/The secret is required/), 'SSO: the secret asked for (the stored one belongs to Entra ID)');
    await page.fill('#sw-sec', 'Synthetic-ADFS-Secret'); await page.click('[data-sw=test]'); ok(await toastIs(/the https address registered/), 'SSO: a plain-http redirect URI refused');
    ok(!calls.some((c) => c[1] === '/auth/admin/sso'), 'SSO: nothing saved before the fields are right');
    await page.fill('#sw-red', 'https://soc.synthetic.test/auth/sso/callback'); await page.click('[data-sw=test]');
    ok(await wait(() => /does not trust the provider's certificate/.test(document.getElementById('modal').innerText)), 'SSO: an untrusted internal certificate explained with the fix');
    await page.fill('#sw-sec', 'Synthetic-ADFS-Secret'); await page.click('[data-sw=test]');
    ok(await wait(() => /Connected/.test(document.getElementById('modal').innerText) && /2 signing key/.test(document.getElementById('modal').innerText)), 'SSO: discovery and signing keys read');
    const sv = calls.filter((c) => c[1] === '/auth/admin/sso').pop()[2];
    ok(sv.provider === 'ADFS' && sv.issuer === 'https://sts.synthetic.test/adfs' && sv.roleClaim === 'groups' && /allatclaims/.test(sv.scopes) && sv.defaultRole === 'none' && sv.enabled === undefined, 'SSO: issuer, groups claim, unmapped denied, not switched on by saving');
    ok(sv.roleMap['SENTRA-SOC-Operators'] === 'operator' && SSO.hasSecret && !JSON.stringify(SSO).includes('Synthetic-ADFS'), 'SSO: existing mappings kept; the secret sealed, not echoed back');
    await page.click('[data-sw=next]'); await page.waitForSelector('#sw-q');
    await page.click('[data-sw=read]'); await page.waitForSelector('[data-swrole]');
    ok((await page.$$('[data-swrole]')).length === 2 && /means everyone - not allowed/.test(await txt('#modal')), 'SSO step 3: AD groups read; the broad group cannot get a role');
    await page.click('[data-sw=propose]'); ok(await toastIs(/Choose a role for at least one group/), 'SSO: proposing nothing refused');
    await page.selectOption('[data-swrole="CN=SENTRA-Platform-Admins,OU=Groups,DC=synthetic,DC=test"]', 'admin'); await page.fill('#sw-note', 'platform admins (synthetic)'); await page.click('[data-sw=propose]');
    ok(await wait(() => /proposed - proposed by syed/.test(document.getElementById('modal').innerText) && /A different administrator approves and applies it/.test(document.getElementById('modal').innerText)), 'SSO: proposed; a different administrator approves');
    const pp = calls.find((c) => c[1] === '/api/itam/sso-groups/propose')[2];
    ok(pp.mappings.length === 1 && pp.mappings[0].role === 'admin' && /SENTRA-Platform-Admins/.test(pp.mappings[0].group) && pp.note === 'platform admins (synthetic)', 'SSO: the proposal sent');
    ok(!calls.some((c) => c[1] === '/api/itam/sso-groups/settings'), 'SSO: the AD FS claim format (sAMAccountName) already set - not changed');
    await page.click('[data-sw=next]'); await page.waitForSelector('#sw-mfa');
    const s4 = await txt('#modal'); ok(/Identity provider connected: https:\/\/sts\.synthetic\.test\/adfs/.test(s4) && /1 AD group\(s\) mapped/.test(s4), 'SSO step 4: the checklist');
    await page.click('[data-sw=enable]'); ok(await wait(() => /Test with one person from each group/.test(document.getElementById('modal').innerText)), 'SSO: switched on, how to test');
    const on = calls.filter((c) => c[1] === '/auth/admin/sso').pop()[2]; ok(on.enabled === true && on.defaultRole === 'none' && !('clientSecret' in on) && on.roleMap['SENTRA-SOC-Operators'] === 'operator', 'SSO: switched on with the mapping and deny-unmapped, no secret resent');
    ok(await page.$('#modal a[href="identity-signin.html"]'), 'SSO: break-glass advice links Identity & Sign-in');
    await page.click('[data-sw=close]'); ok(await wait(() => /ADFS/.test(document.getElementById('cn-sso').innerText) && !/not enabled/.test(document.getElementById('cn-sso').innerText)), 'SSO: the card shows AD FS, switched on');
    // in Arabic: the set-up steps and the labels
    await page.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' }))); await page.reload(); await page.waitForSelector('#cn-ksc [data-act=add]');
    await page.click('#cn-ksc [data-act=add]'); await page.waitForSelector('#gz-n');
    const arTxt = await txt('#modal'); ok(/ربط Kaspersky Security Center/.test(arTxt) && /المستخدمون والأدوار/.test(arTxt) && /حساب القراءة فقط/.test(arTxt) && /التالي/.test(arTxt), 'the Kaspersky wizard in Arabic');
    await page.click('[data-gz=close]'); await page.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })));
    // a viewer
    const v = await browser.newPage(); await v.route('**/dashboards/whoami.json', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{"user":"vera","role":"viewer"}' }));
    await v.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/connections.html?standalone=1'); await v.waitForSelector('#cn-virt');
    ok(!(await v.$('#cn-virt [data-act=add]')), 'a viewer cannot add');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
