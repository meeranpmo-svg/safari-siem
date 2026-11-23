// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD Management (ad-manage.html), stubbed ITAM API, SYNTHETIC people: the list from the last directory read (hostile names stay
// text); an account opens with its groups and the actions; a request needs a reason; the requester gets no approve button and a
// second administrator approves; a protected account offers no action; delete is offered only when the server says it may be
// (with the reason otherwise) and warns it is permanent; emergency disable is sent as such; a new account is requested with its
// groups; a locked-out account shows when and from which computer (SIEM) and offers Unlock (four eyes, the password untouched),
// an account that is not locked offers no Unlock; the temporary password is shown once and hidden; settings save; an operator and a viewer are told the role; a missing
// directory connection says where to set it. No browser dialog anywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ad-manage.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'syed.syn', role: 'admin' }, CONNECTED = true, POSTS = [], SEQ = 0;
const BASE = 'DC=corp-hq,DC=com', iso = (ago) => new Date(Date.now() - ago).toISOString(), DAY = 86400000;
const USERS = {
  'alia.syn': { sam: 'alia.syn', upn: ('alia.syn@' + 'corp-hq.com'), display_name: '<img src=x onerror=window.PWN=1>Alia Synthetic', department: 'Claims', title: 'Analyst', enabled: true, dn: 'CN=Alia Synthetic,OU=Staff,' + BASE, groups: ['Claims-Team', 'VPN-Users'], last_logon: iso(DAY), when_changed: iso(3 * DAY), privileged: false, protected: false, protected_why: '', can_delete: false, delete_why: 'the account is enabled - disable it first; it can be deleted 30 days after that' },
  'eisa.syn': { sam: 'eisa.syn', upn: ('eisa.syn@' + 'corp-hq.com'), display_name: 'Eisa Synthetic', enabled: true, dn: 'CN=Eisa Synthetic,OU=Staff,' + BASE, groups: ['Domain Admins'], last_logon: null, when_changed: iso(DAY), privileged: false, protected: true, protected_why: 'a member of the privileged group Domain Admins - change it in Active Directory Users and Computers', can_delete: false, delete_why: 'x' },
  'coral.syn': { sam: 'coral.syn', upn: ('coral.syn@' + 'corp-hq.com'), display_name: 'Coral Synthetic', enabled: false, dn: 'CN=Coral Synthetic,OU=Staff,' + BASE, groups: [], last_logon: null, when_changed: iso(45 * DAY), privileged: false, protected: false, protected_why: '', can_delete: true, delete_why: '' },
};
// opened by user name only (not in the directory list): locked out, with and without a lockout source from the SIEM
const LOCKED = {
  'gina.syn': { sam: 'gina.syn', upn: ('gina.syn@' + 'corp-hq.com'), display_name: 'Gina Synthetic', enabled: true, dn: 'CN=Gina Synthetic,OU=Staff,' + BASE, groups: [], last_logon: iso(DAY), when_changed: iso(DAY), privileged: false, protected: false, protected_why: '', can_delete: false, delete_why: 'the account is enabled',
    locked: true, lockout_time: iso(3600000), lockout_source: { available: true, days: 7, sources: [{ computer: '<b>WS-SYN-07</b>', lockouts: 4 }] } },
  'kamal.syn': { sam: 'kamal.syn', upn: ('kamal.syn@' + 'corp-hq.com'), display_name: 'Kamal Synthetic', enabled: true, dn: 'CN=Kamal Synthetic,OU=Staff,' + BASE, groups: [], last_logon: iso(DAY), when_changed: iso(DAY), privileged: false, protected: false, protected_why: '', can_delete: false, delete_why: 'the account is enabled',
    locked: true, lockout_time: iso(600000), lockout_source: { available: false, reason: 'the SIEM is not linked to IT Asset Management' } },
};
let REQS = [];
const view = () => ({ connection: CONNECTED ? { ok: true, servers: ['ldaps://dc01.synthetic.test'], base_dn: BASE, upn_suffix: 'corp-hq.com', default_ou: 'OU=Staff,' + BASE } : { ok: false, why: 'the directory connection is not set - an administrator sets it in HR Onboarding -> Directory settings (servers, base DN, bind account)' },
  settings: { enabled: true, delete_enabled: true, create_ou: '', protected: ['breakglass1'] }, delete_days: 30,
  requests: REQS.map((r) => Object.assign({}, r, { password_ready: !!r.pw && r.by === WHO.user })), pending: REQS.filter((r) => r.status === 'pending').length, reviews: REQS.filter((r) => r.review === 'pending').length });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', () => {
      const body = raw ? JSON.parse(raw) : {};
      if (req.method === 'POST' && u.startsWith('/api/')) POSTS.push([u, body, WHO.user]);
      if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
      if (u === '/api/itam/ad-manage') return WHO.role === 'viewer' ? json(403, { error: 'requires operator role' }) : json(200, view());
      if (u === '/api/itam/ad-directory') return json(200, { connection: { ok: CONNECTED }, last: { at: iso(3600000), by: 'nora.syn', count: 3 }, users: Object.values(USERS).map((x) => ({ sam: x.sam, display_name: x.display_name, department: x.department, title: x.title, enabled: x.enabled, admin_count: false, last_logon: x.last_logon, upn: x.upn })) });
      let m;
      if ((m = /^\/api\/itam\/ad-manage\/user\/(.+)$/.exec(u))) return USERS[m[1]] || LOCKED[m[1]] ? json(200, USERS[m[1]] || LOCKED[m[1]]) : json(404, { error: 'no account ' + m[1] + ' in the directory' });
      if (u === '/api/itam/ad-manage/requests') {
        if (WHO.role !== 'admin') return json(403, { error: 'requires admin role' });
        const r = { id: 'adr_' + String(++SEQ).padStart(16, '0'), action: body.action, sam: body.sam, reason: body.reason, by: WHO.user, at: new Date().toISOString(), status: 'pending', summary: body.action + ' ' + body.sam };
        if (body.emergency) Object.assign(r, { status: 'done', review: 'pending', emergency: true, result: 'disabled', decided_by: WHO.user });
        REQS.unshift(r); return json(200, r);
      }
      if ((m = /^\/api\/itam\/ad-manage\/requests\/([^/]+)\/(approve|reject|cancel|review|reveal)$/.exec(u))) {
        const r = REQS.find((x) => x.id === m[1]);
        if (m[2] === 'approve') { if (r.by === WHO.user) return json(403, { error: 'four eyes: a different administrator approves - you requested this' }); Object.assign(r, { status: 'done', decided_by: WHO.user, result: 'disabled' }); return json(200, r); }
        if (m[2] === 'reject') { Object.assign(r, { status: 'rejected', decided_by: WHO.user, note: body.reason }); return json(200, r); }
        if (m[2] === 'review') { Object.assign(r, { review: 'done', reviewed_by: WHO.user }); return json(200, r); }
        if (m[2] === 'reveal') { const pw = r.pw; r.pw = null; return pw ? json(200, { sam: r.sam, password: pw, note: 'Shown once.' }) : json(410, { error: 'already shown' }); }
        Object.assign(r, { status: 'cancelled' }); return json(200, r);
      }
      if (u === '/api/itam/ad-manage/settings') return json(200, Object.assign(view(), { settings: body }));
      if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
      const f = path.join(DASH, u.replace(/^\/dashboards\//, '/'));
      if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
      fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/ad-manage.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1440, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); }); await p.goto(base); await p.waitForSelector('#status .t, #users .err', { timeout: 15000 }); return p; };
  const toast = (p) => p.evaluate(() => [...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' | '));
  const toastIs = (p, re) => p.waitForFunction((r) => new RegExp(r).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' | ')), re.source, { timeout: 8000 }).then(() => true, () => false);
  const waitText = (p, sel, re) => p.waitForFunction(([s, r]) => document.querySelector(s) && new RegExp(r).test(document.querySelector(s).innerText), [sel, re.source], { timeout: 8000 }).then(() => true, () => false);
  const last = (path) => POSTS.filter((x) => x[0] === path).pop();
  const posted = async (path, ms = 15000) => { for (const t = Date.now(); Date.now() - t < ms; await new Promise((r) => setTimeout(r, 50))) { const x = last(path); if (x) return x; } return [path, {}]; };   // under load the request can land after the click returns
  try {
    let p = await open();
    const st = await p.textContent('#status');
    ok(/Connected/.test(st) && /AD management\s*On/.test(st) && /Allowed/.test(st), 'status: directory connected, management on, delete allowed: ' + st.replace(/\s+/g, ' '));
    ok(/second administrator approves/.test(await p.textContent('main')), 'the page says every change is approved by a second administrator');
    ok((await p.$$('#users tr.pick')).length === 3 && /<img src=x/.test(await p.textContent('#users')), 'the directory list, a hostile name shown as text');
    await p.fill('#q', 'claims'); ok((await p.$$('#users tr.pick')).length === 1, 'the list filters by department');
    await p.click('#users tr.pick'); ok(await waitText(p, '#detail', /Claims-Team/), 'the account opens with its groups');
    ok(await p.$('[data-form=disable]') && !(await p.$('[data-form=enable]')), 'an enabled account offers Disable, not Enable');
    ok(!(await p.$('[data-form=unlock]')) && !/Locked out/.test(await p.textContent('#detail')), 'an account that is not locked out offers no Unlock');
    ok(await p.$eval('[data-form=delete]', (b) => b.disabled) && /Delete: the account is enabled - disable it first/.test(await p.textContent('#detail')), 'delete not offered for an enabled account, with the reason');
    await p.click('[data-form=disable]'); await p.click('[data-send=disable]');
    ok(/at least 5 characters/.test(await toast(p)) && !last('/api/itam/ad-manage/requests'), 'a reason is required before anything is sent');
    await p.fill('#f-reason', 'left the company - HR ticket SYN-1'); await p.click('[data-send=disable]');
    ok(await waitText(p, '#open', /disable alia\.syn/), 'the request waits for approval');
    const sent = last('/api/itam/ad-manage/requests'); ok(sent && sent[1].action === 'disable' && sent[1].sam === 'alia.syn' && !sent[1].emergency, 'sent as a normal disable request');
    ok(/You requested this - another administrator approves it/.test(await p.textContent('#open')) && !(await p.$('#open [data-approve]')), 'the requester has no approve button');
    // a second administrator approves
    WHO = { user: 'huda.syn', role: 'admin' }; await p.close(); p = await open();
    await p.click('#open [data-approve]'); ok(await toastIs(p, /Written to AD and read back/), 'a second administrator approves - written and read back');
    ok(last('/api/itam/ad-manage/requests/adr_0000000000000001/approve')[2] === 'huda.syn', 'approved by the second administrator');
    ok(await waitText(p, '#hist', /done/), 'the history shows it done');
    // protected
    await p.fill('#q', 'eisa.syn'); await p.click('#lookup'); ok(await waitText(p, '#detail', /Not changed from here: a member of the privileged group Domain Admins/), 'a protected account says why');
    ok(!(await p.$('#detail [data-form]')), 'and offers no action');
    // unlock: when and from where, four eyes, the password untouched
    await p.fill('#q', 'gina.syn'); await p.click('#lookup'); ok(await waitText(p, '#detail', /Locked out since/), 'a locked-out account says since when');
    ok(/Bad passwords came from \(SIEM, last 7 days\)/.test(await p.textContent('#detail')) && /<b>WS-SYN-07<\/b> · 4/.test(await p.textContent('#detail')) && !(await p.$('#detail b b')), 'the lockout source from the SIEM, a hostile computer name as text');
    ok(/locked out/.test(await p.textContent('#detail .pill.p-warn')), 'marked locked out');
    await p.click('[data-form=unlock]'); ok(/the password is not changed/.test(await p.textContent('#af')), 'the unlock form says the password is not changed');
    POSTS.length = 0; await p.click('[data-send=unlock]'); ok(/at least 5 characters/.test(await toast(p)) && !last('/api/itam/ad-manage/requests'), 'an unlock needs a reason');
    await p.fill('#f-reason', 'old password on her phone - removed (synthetic)'); await p.click('[data-send=unlock]');
    ok(await waitText(p, '#open', /unlock gina\.syn/), 'the unlock waits for a second administrator');
    const ul = last('/api/itam/ad-manage/requests'); ok(ul && ul[1].action === 'unlock' && ul[1].sam === 'gina.syn' && !ul[1].emergency && !('password' in ul[1]), 'sent as an unlock request, no emergency, no password');
    await p.fill('#q', 'kamal.syn'); await p.click('#lookup'); ok(await waitText(p, '#detail', /Lockout source: the SIEM is not linked/), 'no SIEM: the reason, and Unlock still offered');
    ok(!!(await p.$('[data-form=unlock]')), 'Unlock offered without a SIEM');
    // delete allowed, permanent warning
    await p.fill('#q', 'coral.syn'); await p.press('#q', 'Enter'); ok(await waitText(p, '#detail', /Coral Synthetic/), 'opened by Enter');
    ok(await p.$('[data-form=enable]') && !(await p.$eval('[data-form=delete]', (b) => b.disabled)), 'a disabled account long enough offers Enable and Delete');
    await p.click('[data-form=delete]'); ok(/Deleting is permanent/.test(await p.textContent('#af')), 'delete warns that it is permanent');
    await p.fill('#f-reason', 'left in September (synthetic)'); await p.click('[data-send=delete]');
    ok(await waitText(p, '#open', /delete coral\.syn/) && /Permanent delete/.test(await p.textContent('#open')), 'a delete request is marked permanent for the approver');
    // emergency disable
    await p.fill('#q', 'alia.syn'); await p.click('#lookup'); await waitText(p, '#detail', /Claims-Team/);
    await p.click('[data-form=disable]'); await p.fill('#f-reason', 'phished - password sold (synthetic)'); await p.check('#f-emerg'); await p.click('[data-send=disable]');
    ok(await toastIs(p, /A second administrator reviews it/) && last('/api/itam/ad-manage/requests')[1].emergency === true, 'emergency disable sent as such and runs at once');
    ok(await waitText(p, '#open', /Disabled at once as an emergency/) && /another administrator reviews/.test(await p.textContent('#open')), 'the emergency is listed for review, not by its requester');
    // new account
    await p.fill('#n-given', 'Farah'); await p.fill('#n-sur', 'Synthetic'); await p.fill('#n-sam', 'farah.syn'); await p.fill('#n-groups', 'Claims-Team, VPN-Users'); await p.click('#n-send');
    ok(/at least 5 characters/.test(await toast(p)), 'a new account needs a reason too');
    await p.fill('#n-reason', 'new joiner - HR ticket SYN-2'); await p.click('#n-send');
    await waitText(p, '#open', /create farah\.syn/);
    const cr = last('/api/itam/ad-manage/requests')[1]; ok(cr.action === 'create' && cr.ou === 'OU=Staff,' + BASE && cr.groups.join('|') === 'Claims-Team|VPN-Users' && cr.enable === true && !('upn' in cr), 'create sent with OU, groups and enable; empty UPN left to the server');
    // the temporary password, once
    REQS.unshift({ id: 'adr_00000000000000aa', action: 'reset_password', sam: 'alia.syn', by: 'huda.syn', at: iso(60000), status: 'done', summary: 'reset the password of alia.syn', reason: 'synthetic', decided_by: 'syed.syn', decided_at: iso(30000), result: 'temporary password set', pw: 'Synth-Temp-Pw-9xQ' });
    await p.click('#refreshv'); await p.waitForSelector('[data-reveal]'); await p.click('[data-reveal]');
    ok(await waitText(p, '#pws', /Synth-Temp-Pw-9xQ/) && /not shown again/.test(await p.textContent('#pws')), 'the temporary password is shown once');
    await p.click('#pwhide'); ok(!/Synth-Temp-Pw-9xQ/.test(await p.textContent('#pws')) && !(await p.$('[data-reveal]')), 'hidden, and not offered again');
    // settings
    await p.uncheck('#s-del'); await p.fill('#s-prot', 'breakglass1, svc-backup'); await p.click('#s-save');
    const sv = (await posted('/api/itam/ad-manage/settings'))[1]; ok(sv.enabled === true && sv.delete_enabled === false && sv.protected.join('|') === 'breakglass1|svc-backup', 'settings saved with the protected list');
    ok(/Delegate Control/.test(await p.textContent('#settings')) && /never Domain Admin/.test(await p.textContent('#settings')), 'the bind account rights are listed');
    await p.close();
    // operator: reads, no actions
    WHO = { user: 'nora.syn', role: 'operator' }; p = await open();
    await p.click('#users tr.pick'); await waitText(p, '#detail', /Synthetic/);
    ok(!(await p.$('#detail [data-form]')) && /Requesting changes needs the administrator role/.test(await p.textContent('#detail')), 'an operator sees the account but cannot request changes');
    ok(/Creating accounts needs the administrator role/.test(await p.textContent('#newform')), 'an operator cannot create accounts');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open();
    ok(/needs the operator role/.test(await p.textContent('#users')), 'a viewer is told the role (personal data)'); await p.close();
    WHO = { user: 'syed.syn', role: 'admin' }; CONNECTED = false; p = await open();
    ok(/HR Onboarding → Directory settings/.test(await p.textContent('#banner')), 'not connected: says where to connect'); await p.close();
    CONNECTED = true; p = await open(); await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' }))); await p.reload(); await p.waitForSelector('#status .t');
    ok(await waitText(p, '#status', /متصل/) && await waitText(p, 'main', /بانتظار مسؤول ثانٍ/) && await waitText(p, '#settings', /حفظ الإعدادات/), 'in Arabic: the status, the cards and the settings');
    await p.close();
    ok(!(await (await browser.newPage()).evaluate(() => window.PWN)), 'no script ran from a name');
    ok(!errs.length, 'no page errors or dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
