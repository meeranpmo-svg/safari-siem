// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * playwright-recorder.js - a drop-in for the Playwright module the browser tests load (PLAYWRIGHT=<this file>): it hands the tests the
 * real Playwright, and records every successful JSON answer to a GET /api/... that a page receives during the test, to
 * POC_RECORD_DIR/<test>.jsonl (one line per answer: page, method, path, size, body). The tests themselves are unchanged; their data is
 * SYNTHETIC. tools/poc/build-poc-data.js turns the recordings into the POC data file.
 */
const fs = require('fs'), path = require('path');
const REAL = process.env.POC_REAL_PLAYWRIGHT || '/opt/node22/lib/node_modules/playwright';
const pw = require(REAL);
const DIR = process.env.POC_RECORD_DIR;
const name = path.basename(process.argv[1] || 'test').replace(/\.test\.js$/, '');
const out = DIR ? path.join(DIR, name + '.jsonl') : null;

const watched = new WeakSet();
function watch(page) {
  if (!out || watched.has(page)) return page; watched.add(page);
  page.on('response', async (r) => {
    try {
      const req = r.request(); if (req.method() !== 'GET' || r.status() !== 200) return;
      const u = new URL(r.url()); if (!u.pathname.startsWith('/api/')) return;
      if (!/json/i.test(r.headers()['content-type'] || '')) return;
      const text = await r.text(); if (text.length > 400000) return;
      const body = JSON.parse(text); if (body === null || typeof body !== 'object') return;
      let pg = ''; try { pg = new URL(page.url()).pathname.split('/').pop(); } catch (e) { pg = ''; /* the page navigated away: keep the answer without its page */ }
      fs.appendFileSync(out, JSON.stringify({ page: pg, path: u.pathname, size: text.length, body }) + '\n');
    } catch (e) { /* a response that is not JSON or the page closed: nothing to record */ }
  });
  return page;
}
function wrapContext(ctx) {
  const np = ctx.newPage.bind(ctx); ctx.newPage = async (...a) => watch(await np(...a));
  ctx.on('page', (p) => watch(p));
  return ctx;
}
function wrapBrowser(b) {
  const np = b.newPage.bind(b), nc = b.newContext.bind(b);
  b.newPage = async (...a) => watch(await np(...a));
  b.newContext = async (...a) => wrapContext(await nc(...a));
  return b;
}
const chromium = Object.create(pw.chromium);
chromium.launch = async (...a) => wrapBrowser(await pw.chromium.launch(...a));
module.exports = Object.assign({}, pw, { chromium });
