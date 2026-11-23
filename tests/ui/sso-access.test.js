// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SSO Access from AD (sso-access.html), stubbed ITAM + sign-in admin API, SYNTHETIC groups and people: groups are read and a
// broad group cannot be given a role; members show (hostile names stay text); an administrator proposes; the proposer gets no
// approve / apply button; a second administrator approves and applies; the apply sends the Identity & Sign-in settings back
// UNCHANGED except the role claim (groups) and the role map (old app-role entries kept, after a confirmation), never a secret,
// never "enabled" and never MFA changes; it reads the settings back and records "applied" with that map; a mapping changed
// outside the approval shows as drift; a viewer is told the role. No browser dialog anywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sso-access.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'syed.syn', role: 'admin' }, SSOPOSTS = [], APPLIED = [], PROPOSED = [];
const CFG = { sso: { enabled: true, provider: 'Microsoft Entra ID', issuer: 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0', clientId: '11111111-2222-3333-4444-555555555555', redirectUri: 'https://soc.example.test/auth/sso/callback',
  scopes: 'openid profile email', roleClaim: 'roles', allowedDomains: 'corp-hq.com', defaultRole: 'none', requireMfa: true, roleMap: { 'AS.Admin': 'admin' }, hasSecret: true }, users: [], events: [] };
const GROUPS = [{ dn: 'CN=SENTRA-SOC-Operators,OU=Groups,DC=corp-hq,DC=com', sam: 'SENTRA-SOC-Operators', name: 'SENTRA-SOC-Operators', description: 'SOC team <b>x</b>', sid: 'S-1-5-21-1-2-3-3101', security: true, scope: 'global', broad: false, claim: 'SENTRA-SOC-Operators' },
  { dn: 'CN=SENTRA-Platform-Admins,OU=Groups,DC=corp-hq,DC=com', sam: 'SENTRA-Platform-Admins', name: 'SENTRA-Platform-Admins', description: '', sid: 'S-1-5-21-1-2-3-3102', security: true, scope: 'global', broad: false, claim: 'SENTRA-Platform-Admins' },
  { dn: 'CN=Domain Users,CN=Users,DC=corp-hq,DC=com', sam: 'Domain Users', name: 'Domain Users', description: '', sid: 'S-1-5-21-1-2-3-513', security: true, scope: 'global', broad: true, claim: 'Domain Users' }];
let ROLES = { functions: [{ key: 'vuln', name: 'Vulnerability & Penetration Testing', views: ['vapt'] }], levels: ['none', 'view', 'manage'], bases: ['viewer', 'operator', 'admin'], approve_scopes: { 'eng:pentest': 'AI Penetration Testing Engineer' }, roles: [{ id: 'pentest-engineer', name: 'Penetration Testing Engineer', base: 'operator', functions: { vuln: 'manage' }, approves: ['eng:pentest'], users: ['dana.syn', 'erin.syn'] }], assignments: [{ user: 'dana.syn', role_id: 'pentest-engineer', by: 'huda.syn', at: new Date().toISOString(), source: 'sso-group', via: 'SENTRA-SOC-Operators' }, { user: 'erin.syn', role_id: 'pentest-engineer', by: 'syed.syn', at: new Date().toISOString() }] };
let STATE = { job_roles: [{ id: 'pentest-engineer', name: 'Penetration Testing Engineer', base: 'operator' }], derived: [], last_sync: null, connection: { ok: true, servers: ['ldaps://dc01'], base_dn: 'DC=corp-hq,DC=com', dns_domain: 'corp-hq.com' }, settings: { claim: 'sam', netbios: '' }, groups: null, open: null, applied: null, history: [], roles: ['viewer', 'operator', 'admin'] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), q = new URLSearchParams(req.url.split('?')[1] || ''), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', () => {
      const body = raw ? JSON.parse(raw) : {};
      if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
      if (u === '/auth/admin/config') return WHO.role === 'admin' ? json(200, JSON.parse(JSON.stringify(CFG))) : json(403, { error: 'admin only' });
      if (u === '/auth/admin/sso' && req.method === 'POST') { SSOPOSTS.push(body); Object.assign(CFG.sso, body); return json(200, { ok: true }); }
      if (u === '/api/itam/sso-groups') return WHO.role === 'viewer' ? json(403, { error: 'requires operator role' }) : json(200, STATE);
      if (u === '/api/itam/sso-groups/refresh') { STATE.groups = { at: new Date().toISOString(), by: WHO.user, q: body.q, truncated: false, items: GROUPS }; return json(200, STATE); }
      if (u === '/api/itam/sso-groups/members') return json(200, { group: q.get('group'), members: [{ sam: 'alia.syn', upn: ('alia.syn@' + 'corp-hq.com'), display_name: '<img src=x onerror=window.PWN=1>Alia', enabled: true, admin_count: false }, { sam: 'dana.syn', upn: '', display_name: 'Dana', enabled: true, admin_count: true }] });
      if (u === '/api/itam/sso-groups/propose') { if (WHO.role !== 'admin') return json(403, { error: 'requires admin role' });
        const maps = body.mappings.map((m) => { const g = GROUPS.find((x) => x.dn === m.group || x.sam === m.group); return Object.assign({ group: g.sam, dn: g.dn, key: g.claim, role: m.role, members: 2, security: true }, m.job_role ? { job_role: m.job_role, job_role_name: 'Penetration Testing Engineer' } : {}); });
        PROPOSED.push(body);
        STATE.open = { id: 'SSO-SYN1-AAAA', status: 'proposed', by: WHO.user, at: new Date().toISOString(), note: body.note, mappings: maps,
          preview: { counts: { admin: 1, operator: 1, viewer: 0, disabled: 0 }, people: [{ sam: 'alia.syn', upn: ('alia.syn@' + 'corp-hq.com'), display_name: 'Alia', enabled: true, admin_count: false, role: 'admin', via: ['SENTRA-Platform-Admins → admin', 'SENTRA-SOC-Operators → operator'] }], warnings: [{ kind: 'no-upn', text: '1 enabled member(s) have no UPN - they cannot sign in through Entra ID' }] } };
        STATE.history = [{ id: 'SSO-SYN1-AAAA', status: 'proposed', by: WHO.user, at: STATE.open.at, mappings: maps.length, people: 1 }]; return json(200, STATE.open); }
      if (u === '/api/itam/sso-groups/SSO-SYN1-AAAA/approve') { if (STATE.open.by === WHO.user) return json(403, { error: 'four-eyes: the person who proposed the access cannot approve it - another administrator does' });
        Object.assign(STATE.open, { status: 'approved', approver: WHO.user }); return json(200, STATE.open); }
      if (u === '/api/itam/roles') return json(200, ROLES);
      if (u === '/api/itam/sso-groups/SSO-SYN1-AAAA/applied') { APPLIED.push(body); STATE.derived = [{ user: 'dana.syn', role_id: 'pentest-engineer', via: 'SENTRA-SOC-Operators', at: new Date().toISOString(), source: 'sso-group' }]; STATE.last_sync = { at: new Date().toISOString(), reason: 'applied', added: 1, removed: 0 }; STATE.applied = Object.assign({}, STATE.open, { status: 'applied', applied_by: WHO.user, applied_at: new Date().toISOString(), verified: body.verified, keys: STATE.open.mappings.map((m) => m.key) }); STATE.open = null; return json(200, Object.assign({ job_role_sync: { synced: true, added: ['dana.syn'], removed: [], changed: [] } }, STATE.applied)); }
      if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
      const f = path.join(DASH, u.replace(/^\/dashboards\//, '/'));
      if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
      fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/sso-access.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1440, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); }); await p.goto(base); await p.waitForSelector('#status .t', { timeout: 15000 }); return p; };
  const toast = (p) => p.evaluate(() => [...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' | '));
  try {
    let p = await open();
    const st = await p.textContent('#status');
    ok(/Connected/.test(st) && /Single sign-on\s*On/.test(st) && /Denied/.test(st) && /Required/.test(st), 'status: directory, SSO, default role denied, MFA required: ' + st.replace(/\s+/g, ' '));
    ok(/No groups read yet/.test(await p.textContent('#groups')), 'no groups yet says what to do');
    await p.fill('#q', 'SENTRA'); await p.click('#readg'); await p.waitForSelector('#groups select[data-role]');
    ok((await p.$$('#groups select[data-role]')).length === 2, 'two groups can be given a role; the broad one cannot');
    ok(/means everyone - not allowed/.test(await p.textContent('#groups')), 'Domain Users is marked as not allowed');
    ok(await p.evaluate(() => !document.querySelector('#groups b b')), 'a group description with markup is text');
    await p.click('[data-mem="CN=SENTRA-SOC-Operators,OU=Groups,DC=corp-hq,DC=com"]'); await p.waitForSelector('tr.mem .pill');
    const mem = await p.textContent('tr.mem');
    ok(/no UPN/.test(mem) && /privileged/.test(mem), 'members show no-UPN and privileged flags: ' + mem);
    ok(await p.evaluate(() => !window.PWN), 'a hostile member name does not run');
    ok(/No job role comes from AD yet/.test(await p.textContent('#jobs')), 'no job roles from AD yet');
    await p.selectOption('select[data-job="CN=SENTRA-SOC-Operators,OU=Groups,DC=corp-hq,DC=com"]', 'pentest-engineer');
    ok((await p.inputValue('select[data-role="CN=SENTRA-SOC-Operators,OU=Groups,DC=corp-hq,DC=com"]')) === 'operator' && await p.isDisabled('select[data-role="CN=SENTRA-SOC-Operators,OU=Groups,DC=corp-hq,DC=com"]'), 'a job role sets the platform role to its base level (operator) and locks it');
    await p.selectOption('select[data-role="CN=SENTRA-Platform-Admins,OU=Groups,DC=corp-hq,DC=com"]', 'admin');
    ok(/2 group\(s\) chosen/.test(await p.textContent('#psel')), 'selection counted');
    await p.fill('#pnote', 'go-live SOC'); await p.click('#propose'); await p.waitForSelector('#open .tw');
    ok(PROPOSED[0] && PROPOSED[0].mappings.some((m) => m.job_role === 'pentest-engineer' && m.role === 'operator'), 'the proposal carries the job role: ' + JSON.stringify(PROPOSED[0] && PROPOSED[0].mappings));
    ok(/Penetration Testing Engineer/.test(await p.textContent('#open')), 'the proposal shows the job role');
    const o = await p.textContent('#open');
    ok(/SSO-SYN1-AAAA/.test(o) && /no UPN/.test(o) && /Administrators\s*1/.test(o), 'proposal with the preview and warnings: ' + o.slice(0, 200));
    ok(/You proposed this - another administrator approves it/.test(o) && !(await p.$('[data-approve]')), 'the proposer gets no approve button');
    await p.close();
    // second administrator: approve, then apply (with the confirmation about the old app-role mapping)
    WHO = { user: 'huda.syn', role: 'admin' }; p = await open();
    await p.click('[data-approve]'); await p.waitForSelector('[data-apply]');
    ok(/approved by huda\.syn/.test(await p.textContent('#open')), 'approved by the second administrator');
    ok(/AS\.Admin/.test(await p.textContent('#open')), 'the old app-role mapping is named before the claim changes');
    await p.click('[data-apply]'); await p.waitForTimeout(300);
    ok(SSOPOSTS.length === 0 && /Tick the box/.test(await toast(p)), 'apply waits for the confirmation');
    await p.check('#legack'); await p.click('[data-apply]');
    await p.waitForFunction(() => /Applied and read back/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), null, { timeout: 8000 }).catch(() => {});
    const b = SSOPOSTS[0] || {};
    ok(SSOPOSTS.length === 1 && b.roleClaim === 'groups', 'one save of the sign-in settings, role claim = groups');
    ok(b.roleMap && b.roleMap['SENTRA-SOC-Operators'] === 'operator' && b.roleMap['SENTRA-Platform-Admins'] === 'admin' && b.roleMap['AS.Admin'] === 'admin', 'role map = old entries + the approved groups: ' + JSON.stringify(b.roleMap));
    ok(b.requireMfa === true && b.defaultRole === 'none' && b.issuer === CFG.sso.issuer && b.clientId === CFG.sso.clientId, 'MFA, default role, issuer and client sent back unchanged');
    ok(!('clientSecret' in b) && !('enabled' in b) && !('mfaPolicy' in b), 'no secret, no enable switch, no MFA policy in the save: ' + Object.keys(b).join(','));
    ok(APPLIED.length === 1 && APPLIED[0].verified === true && APPLIED[0].role_claim === 'groups' && APPLIED[0].role_map['SENTRA-Platform-Admins'] === 'admin', 'applied recorded with the map read back');
    ok(/hold the approved AD access/.test(await p.textContent('#drift')), 'after applying, the page says the settings hold the approved access');
    ok(/dana\.syn/.test(await p.textContent('#jobs')) && /SENTRA-SOC-Operators/.test(await p.textContent('#jobs')), 'the job role from the AD group is listed after applying');
    // drift: someone changes the mapping in Identity & Sign-in
    CFG.sso.roleMap['SENTRA-SOC-Operators'] = 'admin'; await p.click('#refreshv'); await p.waitForFunction(() => /no longer match/.test(document.getElementById('drift').textContent));
    ok(/SENTRA-SOC-Operators should be operator but is admin/.test(await p.textContent('#drift')), 'a mapping changed outside the approval shows as drift');
    await p.close();
    // Roles & Functions lists the SSO person with the job role from the group, read-only; a hand-made one keeps its picker
    WHO = { user: 'syed.syn', role: 'admin' }; p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base.replace('sso-access.html', 'roles.html')); await p.waitForSelector('#users table', { state: 'attached', timeout: 10000 }).catch(async () => console.log('roles.html users:', await p.innerHTML('#users').catch(() => '?'), errs.join('|')));
    const rowTxt = await p.$$eval('#users tbody tr', (a) => a.map((r) => r.textContent));
    const dana = rowTxt.find((t) => /dana\.syn/.test(t)) || '';
    ok(/from the AD group SENTRA-SOC-Operators/.test(dana) && /single sign-on/.test(dana), 'the SSO person is listed with the job role from the AD group: ' + dana.replace(/\s+/g, ' ').slice(0, 160));
    ok(!(await p.$('select[data-assign="dana.syn"]')) && !!(await p.$('select[data-assign="erin.syn"]')), 'the group job role has no picker; a hand-made one keeps it');
    await p.close();
    // viewer
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base); await p.waitForSelector('#groups .err');
    ok(/administrator role|operator role|requires/.test(await p.textContent('#groups')), 'a viewer is told the role');
    await p.close();
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
