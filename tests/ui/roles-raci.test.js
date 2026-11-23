// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Roles & RACI (roles-raci.html) against the REAL ITAM engines (engine/raci-intel.js) with SYNTHETIC people and audit records: ring and KPIs;
// role cards with chips; an administrator assigns a holder and a deputy from the people list; the RACI matrix with process chips; a second
// Accountable refused with the reason; the audit-trail proposal accepted; what to fix; load per person; a viewer reads but has no assign
// form and sees no per-person activity; a hostile name stays text; the advisor off until allowed; menu entry, installer, portal "roles" view.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node roles-raci.test.js
const PEOPLE = [{ id: 'p1', name: 'Amal Synthetic', user: 'amal.syn', active: true }, { id: 'p2', name: 'Bader Synthetic', user: 'bader.syn', active: true },
  { id: 'p3', name: 'Caro <img src=x onerror=alert(1)> Synthetic', user: 'caro.syn', active: true }];
require('./intel-harness')({ file: 'roles-raci.html', view: 'roles', after: (e) => {
  e.app.addons.teamWorkspace = { org: () => ({ people: PEOPLE }) };
  for (let i = 0; i < 8; i++) e.app.store.audit({ by: 'caro.syn', role: 'operator', ip: '', action: 'roles.assign', target: 'T' + i });
  for (let i = 0; i < 2; i++) e.app.store.audit({ by: 'bader.syn', role: 'operator', ip: '', action: 'roles.assign', target: 'U' + i });
} },
async (h) => {
  h.who('syed.syn', 'admin'); let p = await h.page();
  // every tile opens what it counts, named by the engine: the roles (all / not held), the RACI matrix, what to fix
  { const zs = await p.$$eval('#zi-hero .zi-kpi', (t) => t.map((x) => (x.getAttribute('data-zsec') || '') + (x.getAttribute('data-zchip') ? '|' + x.getAttribute('data-zchip') : '')));
    h.ok(zs.join() === 'roles|all,roles|gap,raci|all,raci|all,issues,issues', 'each tile opens its list: ' + zs.join(' '));
    await p.click('#zi-hero .zi-kpi[data-zchip="gap"]');
    h.ok(await h.wait(p, () => { const c = document.querySelector('[data-chip="roles|gap"]'); return c && c.getAttribute('aria-pressed') === 'true' && document.getElementById('sec-roles').classList.contains('zi-flash'); }), 'Critical not held: the roles not held, highlighted');
    await p.click('[data-chip="roles|all"]'); }
  h.ok(/RACI health/.test(await h.text(p, '#zi-hero')) && /Roles held/.test(await h.text(p, '#zi-hero')) && /0 \/ 18/.test(await h.text(p, '#zi-hero')), 'ring and KPIs');
  h.ok(await p.$$eval('#sec-roles .zi-it', (x) => x.length === 18), 'role cards');
  await p.click('[data-chip="roles|cyber-security"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-roles .zi-it').length === 5), 'department chip');
  await p.click('[data-chip="roles|all"]');
  // assign the Systems Administrator from the people list (holder + deputy)
  h.ok(await h.openCard(p, 'roles', 'sys'), 'role detail'); h.ok(/Responsibilities/.test(await h.text(p, '#zi-dlgb')), 'responsibilities listed');
  await p.selectOption('#zi-dlgb form select[name="person"]', 'p2');
  await p.click('#zi-dlgb form button[type=submit]'); h.ok(await h.toast(p, 'Systems / Cloud Administrator → Bader Synthetic|Role assigned'), 'assigned');
  h.ok(await h.wait(p, () => /Bader Synthetic · no deputy/.test(document.getElementById('sec-roles').textContent)), 'holder shown, no deputy yet');
  // a deputy equal to the holder is refused, the field named
  if (!(await p.$('#zi-dlg:not([hidden])'))) await h.openCard(p, 'roles', 'dpo');
  else { await h.closeDlg(p); await h.openCard(p, 'roles', 'dpo'); }
  await p.selectOption('#zi-dlgb form select[name="person"]', 'p1'); await p.selectOption('#zi-dlgb form select[name="deputy"]', 'p1');
  await p.click('#zi-dlgb form button[type=submit]'); h.ok(await h.toast(p, 'deputy: the deputy must be a different person'), 'validation names the field'); await h.closeDlg(p);
  // the matrix
  h.ok(await p.$$eval('#sec-raci tbody tr', (x) => x.length >= 20), 'RACI rows');
  await p.click('[data-chip="raci|change"]'); h.ok(await h.wait(p, () => [...document.querySelectorAll('#sec-raci tbody tr')].every((r) => /Change management/.test(r.textContent))), 'process chip');
  await p.click('[data-chip="raci|all"]');
  h.ok(await h.openCard(p, 'raci', 'c4'), 'activity detail');
  await p.selectOption('#zi-dlgb form select[name="role"]', 'ciso'); await p.selectOption('#zi-dlgb form select[name="value"]', 'A');
  await p.click('#zi-dlgb form button[type=submit]'); h.ok(await h.toast(p, 'already has an accountable role'), 'a second Accountable refused with the reason'); await h.closeDlg(p);
  // the proposal from the audit trail
  h.ok(await h.openCard(p, 'raci', 'a1'), 'activity with a proposal'); let d = await h.text(p, '#zi-dlgb');
  h.ok(/Who did it/.test(d) && /80 %/.test(d), 'who did it, from the audit trail'); h.ok(!(await p.$('#zi-dlgb img')), 'a hostile name stays text');
  const acc = await p.$('#zi-dlgb form:has(button:text("Accept the proposal"))'); h.ok(!!acc, 'proposal offered to an administrator'); if (acc) await acc.$eval('button[type=submit]', (b) => b.click());
  h.ok(await h.toast(p, 'Role assigned|→'), 'proposal accepted');
  h.ok(await h.wait(p, () => /Bader Synthetic · deputy Caro/.test(document.getElementById('sec-roles').textContent)), 'proposal: named deputy, the holder kept');
  h.ok(/Critical role not held/.test(await h.text(p, '#sec-issues')), 'what to fix');
  h.ok(await p.$$eval('#sec-load .zi-bar', (x) => x.length >= 1), 'load per person');
  h.ok(/not proof/.test(await h.text(p, '#sec-basis')) || /question to ask/.test(await h.text(p, '#sec-basis')), 'honest framing');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'advisor off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page();
  h.ok(await p.$$eval('#sec-roles .zi-it', (x) => x.length === 18), 'a viewer reads the roles');
  await h.openCard(p, 'roles', 'sys'); h.ok(!(await p.$('#zi-dlgb form')), 'a viewer has no assign form'); await h.closeDlg(p);
  await h.openCard(p, 'raci', 'a1'); d = await h.text(p, '#zi-dlgb'); h.ok(/operators and administrators see who did it/.test(d), 'no per-person activity for a viewer'); await h.closeDlg(p);
  h.ok(await p.$$eval('#sec-load .zi-bar', (x) => x.length === 0), 'no load per person for a viewer');
});
