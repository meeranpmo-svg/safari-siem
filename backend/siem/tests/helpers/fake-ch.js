// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Minimal fake ClickHouse HTTP endpoint for tests: records every request, decompresses gzip inserts,
// answers SELECTs with a configurable JSON result, and can be told to fail.
const http = require('node:http');
const zlib = require('node:zlib');

function startFakeCH({ respond } = {}) {
  const st = { requests: [], inserts: {}, fail: 0, failStatus: 503, hang: false, respond };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      let body = Buffer.concat(chunks);
      if (req.headers['content-encoding'] === 'gzip') body = zlib.gunzipSync(body);
      const text = body.toString('utf8');
      const params = Object.fromEntries(url.searchParams);
      const rec = { path: url.pathname, params, body: text, headers: req.headers };
      st.requests.push(rec);
      if (url.pathname === '/ping') { res.end('Ok.\n'); return; }
      if (st.hang) return; // never answer → client timeout
      if (st.fail > 0) { st.fail--; res.writeHead(st.failStatus); res.end('Code: 999. DB::Exception: synthetic failure'); return; }
      const q = params.query || text;
      const m = /^INSERT INTO (\S+) FORMAT JSONEachRow/.exec(q);
      if (m) {
        const rows = text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
        (st.inserts[m[1]] = st.inserts[m[1]] || []).push({ rows, params });
        res.end('');
        return;
      }
      const out = st.respond ? st.respond(q, params, rec) : null;
      if (out && out.status) { res.writeHead(out.status); res.end(out.body || ''); return; }
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(out || { meta: [], data: [], rows: 0, statistics: {} }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    st.url = `http://127.0.0.1:${server.address().port}`;
    st.close = () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); });
    st.rows = (table) => (st.inserts[table] || []).flatMap((b) => b.rows);
    resolve(st);
  }));
}

module.exports = { startFakeCH };
