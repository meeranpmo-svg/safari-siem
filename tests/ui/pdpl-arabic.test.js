// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Every PDPL page in Arabic, against the REAL IT Asset Management engine (Python rules) with a SYNTHETIC register that fills
// each page: with Customize -> Language = Arabic, no English text may be left on the page except data (names, ids, codes,
// dates, e-mail addresses, the synthetic records themselves). Leftovers are listed so the dictionary
// (vendor/zyb-pdpl-ar.js) can be completed. `--harvest` prints every leftover and does not fail.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-arabic.test.js [--harvest]
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
const HARVEST = process.argv.includes('--harvest'), BLOCKS = process.argv.includes('--blocks');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const PAGES = ['pdpl-dashboard', 'pdpl-office', 'pdpl-programme', 'pdpl-governance', 'pdpl-assessment', 'ai-pdpl', 'pdpl-policies', 'pdpl-ropa', 'pdpl-ropa-collect', 'pdpl-catalog', 'pdpl-sensitive',
  'pdpl-dsar', 'pdpl-dpia', 'pdpl-transfers', 'pdpl-breach', 'pdpl-access', 'pdpl-processors'];
// data the synthetic register writes, and data in general: never translated
const DATA = /[\u0600-\u06ff]|[{}|]|^\?|^(Claims|Finance|Legal|Switzerland|Customers)$|\(synthetic\)|\.syn\b|@example\.test|^(PD|PO|RC|RD|PP|DSR|BR|AK)-|^P-\d\d|^[A-Z0-9_.:\/-]{2,}$|^https?:|^[\d\s.,:%\/+-]+$/;
// A product or regulator name excuses a short label ("PDPL Governance"), never a sentence that mentions it.
const ACR = /SAR|SDAIA|PDPL|NCA|SAMA|CHI|ISO|DPIA|RoPA|CSV|PDF|SMTP|Teams|Exchange|SharePoint|OneDrive|Oracle|SQL Server|PostgreSQL|Absher|Najm/;
const isData = (x) => DATA.test(x) || (ACR.test(x) && x.split(/\s+/).length <= 4);

(async () => {
  const e = await H.startApp({ noAi: true });
  const D = require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const as = (who) => async (p, body) => { const r = await e.req('POST', p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  const adm = as({ user: 'syed', role: 'admin' }), op = as({ user: 'nora.syn', role: 'operator' });
  await adm('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01', notify_hours_ia: 24 });
  const a = await adm('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', owner: 'Claims', legal_basis: 'legitimate_interest', data_categories: ['identity', 'health'], systems: ['CLAIMS-SQL'] });
  const b = await adm('/pdpl/records', { kind: 'ropa', name: 'Premium finance (synthetic)', owner: 'Finance', purpose: 'Instalments (synthetic)', legal_basis: 'consent', data_categories: ['identity', 'credit'], subjects: 'Customers (synthetic)', systems: ['FIN'], retention_months: 60, recipients: ['Bank (synthetic)'], security_measures: 'Access control (synthetic)', reinsurance_outside: true, reviewed: '2024-01-01' });
  await adm('/pdpl/records', { kind: 'dsr', ref: 'DSR-SYN-1', type: 'access', received: '2026-08-01', extended: true });
  await adm('/pdpl/records', { kind: 'breach', ref: 'BR-SYN-1', aware_at: '2026-10-10T08:00', harm_likely: true, subjects_count: 40 });
  await adm('/pdpl/records', { kind: 'processor', name: 'Overseas TPA (synthetic)', outside_ksa: true });
  await adm('/pdpl/records', { kind: 'transfer', name: 'Treaty bordereaux (synthetic)', country: 'Switzerland', basis: 'scc', sensitive: true, flow_type: 'reinsurance', data_form: 'identified', ropa_id: b.id });
  await adm('/pdpl/records', { kind: 'consent_purpose', title: 'Marketing (synthetic)', ropa_id: b.id });
  await adm('/pdpl/records', { kind: 'retention', name: 'Claims files (synthetic)', ropa_id: a.id, period_months: 120, trigger: 'claim_closed', action: 'destroy' }).catch(() => null);
  await op('/pdpl/stewards', { department: 'Claims', user: 'faisal.syn', role: 'data_steward' });
  await op('/pdpl/ropa/campaigns', { name: 'RoPA 2026 (synthetic)', due: '2026-12-31', departments: ['Claims', 'Legal'] });
  await op('/pdpl/office/run', {});
  await D.patrol('pdpl');   // the duty desk's work items
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
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : u.pathname.endsWith('.json') ? 'application/json' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const left = {};
  try {
    for (const pg of PAGES) {
      const ctx = await browser.newContext({ viewport: { width: 1400, height: 950 } });
      await ctx.addInitScript(() => { window.ZYB_ARABIC = true; });   // Arabic on (vendor/zyb-dash.js ARABIC_ON), set explicitly so the test does not depend on the default
      if (!BLOCKS) await ctx.addInitScript(() => { try { localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' })); } catch (x) { /* test storage */ } });
      const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(pg + ': ' + x.message));
      await p.goto(base + pg + '.html?standalone=1'); await p.waitForTimeout(2500);
      if (BLOCKS) {   // paragraphs that mix text and inline elements, in English: the keys of the dictionary's whole-paragraph entries
        const bl = await p.evaluate(() => [...document.querySelectorAll('main *')].filter((x) => !/^(SCRIPT|STYLE|TABLE|TBODY|TR|SELECT|SVG)$/.test(x.nodeName) && [...x.childNodes].some((c) => c.nodeType === 3 && /[A-Za-z]{3,}/.test(c.nodeValue)) && [...x.children].some((c) => /^(B|STRONG|A|I|EM|SPAN|CODE)$/.test(c.nodeName) && /[A-Za-z]/.test(c.textContent))).map((x) => x.textContent.replace(/\s+/g, ' ').trim()));
        console.log('=== ' + pg); for (const x of [...new Set(bl)]) console.log(JSON.stringify(x)); await ctx.close(); continue;
      }
      ok(await p.$eval('html', (x) => x.getAttribute('dir')) === 'rtl', pg + ': right-to-left');
      // finding titles: the duty desk's work items and the findings lists are in Arabic (an activity's own name may stay as recorded)
      const FSEL = { 'ai-pdpl': '.zdt-r td:nth-child(2)', 'pdpl-sensitive': '#finds li' }[pg];
      if (FSEL) {
        const rows = await p.$$eval(FSEL, (els) => els.map((x) => x.textContent.replace(/\s+/g, ' ').trim()));
        const eng = rows.filter((x) => !/[\u0600-\u06ff]{3}/.test(x.replace(/«[^»]*»/g, '')) || /^[A-Z][a-z]+ [a-z]+/.test(x));
        ok(rows.length > 0 && !eng.length, pg + ': ' + rows.length + ' finding title(s), in English: ' + eng.slice(0, 5).join(' | '));
      }
      if (process.env.SHOT_DIR) await p.screenshot({ path: path.join(process.env.SHOT_DIR, pg + '.png'), fullPage: false });
      const texts = await p.evaluate(() => {
        const out = new Set(), skip = (el) => { for (let x = el; x && x.nodeType === 1 && x !== document.body; x = x.parentNode) { if (/^(SCRIPT|STYLE|CODE|PRE|TEXTAREA|SVG|KBD)$/.test(x.nodeName) || (x.id && /^zyb-/.test(x.id)) || (x.classList && [...x.classList].some((c) => /^zyb-/.test(c))) || x.id === 'langlbl' || x.hasAttribute('data-no-tr') || x.hasAttribute('hidden') || (x.classList && (x.classList.contains('mono') || x.classList.contains('ltr'))) || x.nodeName === 'BDI') return true; } return false; };
        const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let t;
        while ((t = w.nextNode())) { const v = t.nodeValue.replace(/\s+/g, ' ').trim(); if (v && /[A-Za-z]{3,}/.test(v) && !skip(t.parentNode)) out.add(v); }
        document.querySelectorAll('input[placeholder],textarea[placeholder]').forEach((x) => { if (/[A-Za-z]{3,}/.test(x.placeholder) && !skip(x.parentNode)) out.add(x.placeholder); });
        document.querySelectorAll('option').forEach((x) => { if (/[A-Za-z]{3,}/.test(x.textContent) && !skip(x.parentNode)) out.add(x.textContent.trim()); });
        return [...out];
      });
      // every tab: what is behind it is part of the page
      const tabs = await p.$$eval('main [data-tab]', (els) => els.map((x) => x.getAttribute('data-tab')));
      for (const t of tabs) {
        try {
          await p.click('main [data-tab="' + t + '"]', { timeout: 2000 }); await p.waitForTimeout(900);
          for (const x of await p.evaluate(() => { const out = new Set(), skip = (el) => { for (let y = el; y && y.nodeType === 1 && y !== document.body; y = y.parentNode) { if (/^(SCRIPT|STYLE|CODE|PRE|TEXTAREA|SVG|BDI)$/.test(y.nodeName) || y.hasAttribute('data-no-tr') || y.hasAttribute('hidden') || (y.classList && (y.classList.contains('mono') || y.classList.contains('ltr')))) return true; } return false; };
            const w = document.createTreeWalker(document.querySelector('main'), NodeFilter.SHOW_TEXT); let n2; while ((n2 = w.nextNode())) { const v = n2.nodeValue.replace(/\s+/g, ' ').trim(); if (v && /[A-Za-z]{3,}/.test(v) && !skip(n2.parentNode)) out.add(v); }
            document.querySelectorAll('main input[placeholder], main textarea[placeholder]').forEach((y) => { if (/[A-Za-z]{3,}/.test(y.placeholder) && !skip(y.parentNode)) out.add(y.placeholder); });
            document.querySelectorAll('main option').forEach((y) => { if (/[A-Za-z]{3,}/.test(y.textContent) && !skip(y.parentNode)) out.add(y.textContent.trim()); }); return [...out]; })) texts.push(x);
        } catch (x) { /* a tab that is not clickable for this role: skipped */ }
      }
      // the drawers: the first row of each table and every Add / New / Record button open a form or a detail drawer
      const collect = () => p.evaluate(() => {
        const out = new Set(), d = document.getElementById('zd'); if (!d || d.hidden) return [];
        const w = document.createTreeWalker(d, NodeFilter.SHOW_TEXT); let t;
        const skip = (el) => { for (let x = el; x && x !== d; x = x.parentNode) { if (/^(SCRIPT|STYLE|CODE|PRE|TEXTAREA|BDI)$/.test(x.nodeName) || (x.classList && (x.classList.contains('mono') || x.classList.contains('ltr'))) || (x.hasAttribute && x.hasAttribute('data-no-tr'))) return true; } return false; };
        while ((t = w.nextNode())) { const v = t.nodeValue.replace(/\s+/g, ' ').trim(); if (v && /[A-Za-z]{3,}/.test(v) && !skip(t.parentNode)) out.add(v); }
        d.querySelectorAll('input[placeholder],textarea[placeholder]').forEach((x) => { if (/[A-Za-z]{3,}/.test(x.placeholder)) out.add(x.placeholder); });
        d.querySelectorAll('option').forEach((x) => { if (/[A-Za-z]{3,}/.test(x.textContent)) out.add(x.textContent.trim()); });
        return [...out];
      });
      const openers = await p.$$eval('main tr[data-id], main tr.rowc, main [data-open], main button[id]', (els) => {
        const seen = new Set(), out = [];
        for (const x of els) { if (x.offsetParent === null) continue; const id = x.id || ''; if (x.nodeName === 'BUTTON' && !/^(add|new|rec|start|edit|place|propose)/i.test(id)) continue;
          const key = x.nodeName === 'BUTTON' ? '#' + id : (x.tagName + (x.className || '')); if (seen.has(key)) continue; seen.add(key);
          x.setAttribute('data-ar-probe', String(out.length)); out.push(out.length); }
        return out;
      });
      for (const k of openers) {
        try { await p.click('[data-ar-probe="' + k + '"]', { timeout: 2000 }); await p.waitForTimeout(700); for (const x of await collect()) texts.push(x); await p.keyboard.press('Escape'); await p.waitForTimeout(200); } catch (x) { /* not clickable now (covered or hidden): skipped */ }
      }
      left[pg] = [...new Set(texts)].filter((x) => !isData(x));
      await ctx.close();
    }
    // switching back: in English every page is left-to-right with no Arabic on it (data, the language button and blocks the
    // page marks lang="ar" on purpose are skipped); the Privacy Office button switches both ways and the choice survives a reload
    if (!HARVEST && !BLOCKS) {
      const arOn = (p) => p.evaluate(() => { const skip = (el) => { for (let x = el; x && x.nodeType === 1; x = x.parentNode) { if (x.id === 'langlbl' || x.getAttribute('lang') === 'ar' || x.id === 'langbtn' || x.hasAttribute('hidden')) return true; } return false; };
        const out = [], w = document.createTreeWalker(document.querySelector('main') || document.body, NodeFilter.SHOW_TEXT); let t;
        while ((t = w.nextNode())) { const v = t.nodeValue.trim(); if (/[\u0600-\u06ff]/.test(v) && !skip(t.parentNode)) out.push(v); } return out; });
      for (const pg of PAGES) {
        const ctx = await browser.newContext({ viewport: { width: 1400, height: 950 } });
        await ctx.addInitScript(() => { window.ZYB_ARABIC = true; });
        await ctx.addInitScript(() => { try { if (!localStorage.getItem('zyb-dash-prefs')) localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })); } catch (x) { /* test storage */ } });
        const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(pg + ' (en): ' + x.message));
        await p.goto(base + pg + '.html?standalone=1'); await p.waitForTimeout(1800);
        const dir = await p.$eval('html', (x) => x.getAttribute('dir') || 'ltr'), ar = await arOn(p);
        ok(dir !== 'rtl' && !ar.length, pg + ' in English: dir=' + dir + ', Arabic on the page: ' + ar.slice(0, 5).join(' | '));
        ok(!(await p.evaluate(() => !!window.zybPdplAr)), pg + ' in English: the Arabic dictionary is not loaded');
        if (pg === 'pdpl-office') {
          await p.click('#langbtn'); await p.waitForLoadState('load'); await p.waitForTimeout(1800);
          ok(await p.$eval('html', (x) => x.getAttribute('dir')) === 'rtl' && (await p.textContent('#langlbl')).trim() === 'English', 'Privacy Office: English → Arabic');
          await p.reload(); await p.waitForTimeout(1500);
          ok(await p.$eval('html', (x) => x.getAttribute('dir')) === 'rtl', 'Privacy Office: Arabic kept after a reload');
          await p.click('#langbtn'); await p.waitForLoadState('load'); await p.waitForTimeout(1800);
          const ar2 = await arOn(p);
          ok((await p.$eval('html', (x) => x.getAttribute('dir') || 'ltr')) !== 'rtl' && !ar2.length && (await p.textContent('#langlbl')).trim() === 'العربية', 'Privacy Office: Arabic → English, nothing Arabic left: ' + ar2.slice(0, 5).join(' | '));
          await p.goto(base + 'ai-pdpl.html?standalone=1'); await p.waitForTimeout(1800);
          ok((await p.$eval('html', (x) => x.getAttribute('dir') || 'ltr')) !== 'rtl' && !(await arOn(p)).length, 'the next PDPL page opens in English too');
        }
        await ctx.close();
      }
    }
    // Arabic switched off (window.ZYB_ARABIC = false - the platform ships with it on, the switch still works): Arabic saved in the
    // browser still shows English, left to right, no language button on the Privacy Office and no language choice under Customize
    if (!HARVEST && !BLOCKS) {
      for (const pg of PAGES) {
        const ctx = await browser.newContext({ viewport: { width: 1400, height: 950 } });
        await ctx.addInitScript(() => { window.ZYB_ARABIC = false; try { localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' })); } catch (x) { /* test storage */ } });
        const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(pg + ' (off): ' + x.message));
        await p.goto(base + pg + '.html?standalone=1'); await p.waitForTimeout(1500);
        const st = await p.evaluate(() => { const out = [], w = document.createTreeWalker(document.querySelector('main') || document.body, NodeFilter.SHOW_TEXT); let t;
          while ((t = w.nextNode())) { let hid = false; for (let x = t.parentNode; x && x.nodeType === 1; x = x.parentNode) if (x.hasAttribute('hidden') || x.getAttribute('lang') === 'ar') { hid = true; break; }
            if (!hid && /[\u0600-\u06ff]/.test(t.nodeValue)) out.push(t.nodeValue.trim()); }
          return { dir: document.documentElement.getAttribute('dir') || 'ltr', ar: out, dict: !!window.zybPdplAr, btn: !!document.getElementById('langbtn') && !document.getElementById('langbtn').hidden, cust: !!document.getElementById('zyb-de') }; });
        ok(st.dir !== 'rtl' && !st.ar.length && !st.dict && !st.btn && !st.cust, pg + ' with Arabic switched off: ' + JSON.stringify({ dir: st.dir, ar: st.ar.slice(0, 3), dict: st.dict, btn: st.btn, cust: st.cust }));
        await ctx.close();
      }
    }
  } finally { await browser.close(); srv.close(); e.close(); }
  if (BLOCKS) process.exit(0);
  let total = 0;
  for (const pg of PAGES) {
    total += left[pg].length;
    if (HARVEST) { console.log('=== ' + pg + ' (' + left[pg].length + ')'); for (const x of left[pg]) console.log(JSON.stringify(x)); }
    else ok(!left[pg].length, pg + ': English left in Arabic mode: ' + left[pg].slice(0, process.env.ALL ? 999 : 15).map((x) => JSON.stringify(x)).join(' | '));
  }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((HARVEST ? 'HARVEST ' + total + ' text(s) left; ' : '') + (bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad && !HARVEST ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
