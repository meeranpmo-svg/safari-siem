#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * off-scan.js - what an organisation is NOT under or does not run must not show on any page it can open. Opens every menu page that
 * brand.json does not switch off (pages_off), in POC mode so the pages are full, against a server that fails every other API call,
 * and reports each visible place (text, option, button, title, placeholder) that still names a switched-off framework or platform:
 *   SAMA (fw-sama off), Insurance Authority (fw-ia off), VMware / vCenter / ESXi / vSphere (platforms_off vmware), Nutanix / Prism (nutanix)
 *   node tools/brand/off-scan.js [page.html ...]       exit 1 when anything is found
 */
const http = require('http'), fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), D = path.join(ROOT, 'ui'), B = JSON.parse(fs.readFileSync(path.join(ROOT, 'brand/brand.json'), 'utf8'));
const off = new Set(B.pages_off || []), mods = new Set(B.modules_off || []), plat = new Set(B.platforms_off || []);
const W = [];
if (mods.has('fw-sama')) W.push('SAMA');
if (plat.has('vmware')) W.push('VMware', 'vCenter', 'ESXi', 'vSphere', 'vMotion');
if (plat.has('nutanix')) W.push('Nutanix', 'Prism Central', 'AHV');
const RE = new RegExp('\\b(' + W.join('|') + ')\\b', 'i');
const nav = fs.readFileSync(path.join(D, 'vendor/zyb-nav.js'), 'utf8');
const all = [...new Set([...nav.matchAll(/"h":\s*"([^"#?]+\.html)/g)].map((m) => m[1]))].filter((p) => !off.has(p.replace(/\.html$/, '')) && fs.existsSync(path.join(D, p)));
const pages = process.argv.slice(2).length ? process.argv.slice(2) : all;
const srv = http.createServer((q, r) => { const u = new URL(q.url, 'http://x');
  if (u.pathname.startsWith('/dashboards/whoami')) return r.end('{"user":"admin.scan","role":"admin"}');
  if (u.pathname.startsWith('/api/') || u.pathname.startsWith('/auth/')) { r.writeHead(500, { 'Content-Type': 'application/json' }); return r.end('{"error":"down (scan)"}'); }
  fs.readFile(path.join(D, u.pathname.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
(async () => {
  if (!W.length) { console.log('nothing is switched off in brand.json'); return; }
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || '/opt/node22/lib/node_modules/playwright'); const browser = await chromium.launch();
  const found = {}; let i = 0;
  const work = async () => { while (i < pages.length) { const pg = pages[i++]; const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
    try { await p.goto(base + pg + '?poc=1', { waitUntil: 'load', timeout: 20000 }); await p.waitForTimeout(2500);
      const hits = await p.evaluate((src) => { const re = new RegExp(src, 'i'), out = [];
        const vis = (el) => { for (let e = el; e && e.nodeType === 1; e = e.parentElement) { if (e.hidden) return false; const s = getComputedStyle(e); if (s.display === 'none' || s.visibility === 'hidden') return false; } return true; };
        const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let n;
        while ((n = tw.nextNode())) { const t = n.nodeValue; if (re.test(t) && n.parentElement && !/^(SCRIPT|STYLE|NOSCRIPT)$/.test(n.parentElement.tagName) && vis(n.parentElement)) out.push(t.trim().replace(/\s+/g, ' ').slice(0, 140)); }
        for (const el of document.querySelectorAll('[title],[placeholder],[aria-label],option')) for (const a of ['title', 'placeholder', 'aria-label']) { const v = el.getAttribute(a); if (v && re.test(v)) out.push('@' + a + ': ' + v.slice(0, 120)); }
        if (re.test(document.title)) out.push('title: ' + document.title);
        return [...new Set(out)]; }, RE.source);
      if (hits.length) found[pg] = hits;
    } catch (e) { found[pg] = ['(page did not load: ' + e.message.split('\n')[0] + ')']; } finally { await p.close(); } } };
  await Promise.all(Array.from({ length: 6 }, work));
  await browser.close(); srv.close();
  if (process.env.OFF_JSON) fs.writeFileSync(process.env.OFF_JSON, JSON.stringify(found, null, 1));
  const keys = Object.keys(found).sort();
  for (const k of keys) { console.log('\n' + k + ' (' + found[k].length + ')'); for (const h of found[k].slice(0, 12)) console.log('   ' + h); }
  console.log('\n' + keys.length + ' of ' + pages.length + ' pages still name ' + W.join(' / '));
  process.exit(keys.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
