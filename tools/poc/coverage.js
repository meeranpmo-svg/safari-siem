#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * coverage.js - which dashboards draw fully from the POC data: opens every dashboard of the menu (or the pages named) with ?poc=1
 * against a server that fails every API call, and reports per page how many requests the illustrative data answered and which API
 * paths still went to the server (those need a recording or a hand-written entry in vendor/zyb-poc-data.js).
 *   node tools/poc/coverage.js [page.html ...]       PLAYWRIGHT=<playwright module> optional
 */
const http = require('http'), fs = require('fs'), path = require('path');
const D = path.resolve(__dirname, '../../ui');
const DASH = /dashboard|overview|summary|command|cockpit|360|executive|estate|wall|posture|surface|dark web|ndr|flows|licen|vulnerab|map|audit|compliance|assistant/i;
const nav = fs.readFileSync(path.join(D, 'vendor/zyb-nav.js'), 'utf8');
const all = [...new Set([...nav.matchAll(/"h":\s*"([^"]+\.html)",\s*"s":\s*"([^"]+)"/g)].filter((m) => DASH.test(m[2])).map((m) => m[1]))].filter((p) => fs.existsSync(path.join(D, p)));
const pages = process.argv.slice(2).length ? process.argv.slice(2) : all;
const live = {};
const srv = http.createServer((q, r) => {
  const u = new URL(q.url, 'http://x');
  if (u.pathname.startsWith('/dashboards/whoami')) return r.end('{"user":"admin.poc","role":"admin"}');
  if (u.pathname.startsWith('/api/')) { const ref = (q.headers.referer || '').split('/').pop().split('?')[0]; (live[ref] = live[ref] || new Set()).add(q.method + ' ' + u.pathname); r.writeHead(500, { 'Content-Type': 'application/json' }); return r.end('{"error":"server down (POC coverage)"}'); }
  fs.readFile(path.join(D, u.pathname.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
});
srv.listen(0, async () => {
  const { chromium } = require(process.env.PLAYWRIGHT || '/opt/node22/lib/node_modules/playwright');
  const b = await chromium.launch(), rows = [];
  for (const pg of pages) {
    const p = await b.newPage({ viewport: { width: 1400, height: 900 } });
    let hits = 0, ref = [];
    try { await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/' + pg + '?poc=1&standalone=1', { timeout: 20000 }); await p.waitForTimeout(2500); hits = await p.evaluate(() => (window.zybPoc ? window.zybPoc.hits() : -1)); ref = await p.evaluate(() => (window.zybPoc && window.zybPoc.refused ? window.zybPoc.refused() : [])); } catch (e) { hits = -1; }
    const miss = [...(live[pg] || [])].filter((x) => !/\/(licence|roles\/me|report-brand|auth\/whoami)$/.test(x)).concat([...new Set(ref)].map((x) => 'REFUSED ' + x));
    rows.push({ pg, hits, miss });
    await p.close();
  }
  const full = rows.filter((r) => r.hits > 0 && !r.miss.length), part = rows.filter((r) => r.hits > 0 && r.miss.length), none = rows.filter((r) => r.hits <= 0);
  console.log('POC coverage: ' + full.length + ' full, ' + part.length + ' partial, ' + none.length + ' none, of ' + rows.length + ' dashboards');
  for (const r of part) console.log('PARTIAL ' + r.pg + ' (' + r.hits + ' answered) still live: ' + r.miss.join(', '));
  for (const r of none) console.log('NONE    ' + r.pg + ' live: ' + r.miss.slice(0, 6).join(', '));
  await b.close(); srv.close();
});
