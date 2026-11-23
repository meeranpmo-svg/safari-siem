// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Live tail: GET /api/soc/tail?q=<query>  → Server-Sent Events ("event" per matching event, "stats" once a second when
// events were dropped). Fed by a pipeline stage; each client's filter is the same query language compiled to JS.
const { compileJS, parse } = require('./query');

function slim(ev) {
  const o = {};
  for (const k in ev) {
    if (k === 'raw') o.raw = ev.raw.length > 4096 ? ev.raw.slice(0, 4096) + '…' : ev.raw;
    else o[k] = ev[k];
  }
  return o;
}

function createTail({ maxClients = 20, maxEps = 200, log } = {}) {
  const clients = new Set();
  const st = { opened: 0, sent: 0, dropped: 0 };

  function stage(ev) {
    if (!clients.size) return;
    const sec = Math.floor(Date.now() / 1000);
    for (const c of clients) {
      if (c.sse.closed) { clients.delete(c); continue; }
      if (!c.pred(ev)) continue;
      if (c.sec !== sec) {
        if (c.dropped) { c.sse.send('stats', { dropped: c.dropped, max_eps: maxEps }); c.dropped = 0; }
        c.sec = sec;
        c.n = 0;
      }
      if (c.n >= maxEps) { c.dropped++; st.dropped++; continue; }
      c.n++;
      if (c.sse.send('event', slim(ev))) st.sent++; else { c.dropped++; st.dropped++; }
    }
  }

  function handler(ctx) {
    const q = typeof ctx.query.q === 'string' ? ctx.query.q : '';
    let pred;
    try { pred = compileJS(parse(q)); } catch (e) { return ctx.fail(400, e.message); }
    if (clients.size >= maxClients) return ctx.fail(503, `too many live tail sessions (max ${maxClients})`);
    const sse = ctx.sse();
    const c = { sse, pred, sec: 0, n: 0, dropped: 0, user: ctx.user, q };
    clients.add(c);
    st.opened++;
    sse.send('hello', { q, max_eps: maxEps });
    sse.onClose(() => clients.delete(c));
    if (log) log.info('tail: client connected', { user: ctx.user, q: q.slice(0, 200), clients: clients.size });
  }

  return { stage, handler, stats: () => ({ clients: clients.size, ...st }) };
}

module.exports = { createTail };
