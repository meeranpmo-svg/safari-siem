// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Office 365 EMAIL LOGS in the SIEM: Exchange Online message trace (mail flow) pulled READ-ONLY from Microsoft Graph with the same
 * Entra ID app registration as the rest of Microsoft 365 (secrets.m365 - tenant, client_id, client_secret or certificate) and the
 * application permission ExchangeMessageTrace.Read.All. Every traced message becomes a SIEM event (parse/m365.js messageTrace:
 * src_type m365, host exchange-mailflow, category email) so it is searchable, correlated and kept like every other log. Mail flow
 * metadata only: sender, recipient, status, size, IP addresses, message id - never a body; the subject is hashed unless the
 * Exchange settings keep subjects in clear.
 *   pull       every mailtrace_poll_s (default 900 s, at least 300) the window since the last pull, with 30 minutes of overlap for
 *              Microsoft's own delay; duplicates are dropped by trace id. The cursor is kept in <state_dir>/m365-mailtrace.json.
 *   endpoint   config m365.mailtrace_url (default the Graph beta messageTraces) - only a graph.microsoft.com address is accepted, so
 *              the token never leaves Graph
 * Analysis (GET {P}/m365/mail, analyst, audited - personal data, PDPL): direction (inbound / outbound / internal by the tenant's own
 * domains), delivery status, blocked inbound (quarantined / spam) by sender domain, failures, the external domains mail goes to,
 * mail to personal webmail, large outbound mail, and each sender's outbound volume against their OWN 14 days before (5x and 30+,
 * or 30+ with no history). Indicators for a person to review, not proof of wrongdoing.
 *   GET  {P}/m365/mail          ?days=1-30 (default 7)   analyst
 *   GET  {P}/m365/mail/status   collector state, no personal data   viewer
 *   POST {P}/m365/mail/poll     pull now   admin
 */
const fs = require('node:fs');
const path = require('node:path');
const { guard: guardJob } = require('../util/errors');
const { credsOf } = require('./m365-graph');

const H = 3600000, DAY = 24 * H, MIN = 60000;
const DEFAULT_URL = 'https://graph.microsoft.com/beta/admin/exchange/tracing/messageTraces';
const PERM = 'ExchangeMessageTrace.Read.All';
const MAX_IDS = 200000, OVERLAP = 30 * MIN, FIRST = DAY;
const PERSONAL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'aol.com',
  'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'yandex.ru', 'zoho.com', 'tutanota.com']);
const lc = (s) => String(s == null ? '' : s).toLowerCase();
const domainOf = (u) => { const m = /@([^@\s]+)$/.exec(lc(u)); return m ? m[1] : ''; };

function urlOf(config) {
  const u = String(((config || {}).m365 || {}).mailtrace_url || DEFAULT_URL).replace(/\/+$/, '');
  if (!/^https:\/\/graph\.microsoft\.com\/(v1\.0|beta)\/[A-Za-z0-9/._-]+$/.test(u)) throw new Error('m365.mailtrace_url must be a graph.microsoft.com address');
  return u;
}

function createMailTrace({ graph, parser, pipeline, config = {}, log, stateDir, now = Date.now } = {}) {
  const lg = log || { info() {}, warn() {}, error() {} };
  const file = stateDir ? path.join(stateDir, 'm365-mailtrace.json') : '';
  let cur = { until: 0 }; try { if (file) cur = Object.assign(cur, JSON.parse(fs.readFileSync(file, 'utf8'))); } catch (e) { if (e.code !== 'ENOENT') lg.warn('m365 mail trace: cursor not readable - starting from the last day', { err: e.message }); }
  const seen = new Map(), st = { polls: 0, records: 0, duplicates: 0, last_poll_at: null, last_error: '', running: false, permission: PERM };
  let timer = null, stopped = false, running = null;
  const mc = () => (config.m365 || {});
  const enabled = () => mc().mailtrace !== false && !credsOf(config).errs.length && !!graph;
  const save = () => { if (!file) return; try { fs.writeFileSync(file, JSON.stringify(cur)); } catch (e) { lg.warn('m365 mail trace: cursor not saved - the next pull repeats the window (duplicates are dropped)', { err: e.message }); } };

  async function pullNow() {
    if (running) return running;
    running = (async () => {
      st.running = true; st.polls++; st.last_poll_at = new Date(now()).toISOString();
      try {
        const to = now(), from = Math.max(cur.until ? cur.until - OVERLAP : to - FIRST, to - 10 * DAY);   // message trace keeps 10 days
        const q = `${urlOf(config)}?$filter=${encodeURIComponent(`receivedDateTime ge ${new Date(from).toISOString()} and receivedDateTime le ${new Date(to).toISOString()}`)}`;
        let rows;
        try { rows = await graph.graphGet(q, 200); } catch (e) { throw e.status === 403 ? Object.assign(new Error('permission not granted: ' + PERM), { status: 403 }) : e; }
        let n = 0;
        for (const r of Array.isArray(rows) ? rows : []) {
          const id = r && r.id ? String(r.id) : '';
          if (id) { if (seen.has(id)) { st.duplicates++; continue; } seen.set(id, 1); while (seen.size > MAX_IDS) seen.delete(seen.keys().next().value); }
          const ev = parser.parse(JSON.stringify(r), { collector: 'm365-mailtrace', src_id: 'm365-mailtrace', src_type: 'm365', peer_ip: '', rts: now(), obj: r });
          if (!ev) continue;
          pipeline.emit(ev); n++;
        }
        st.records += n; cur.until = to; save(); st.last_error = ''; st.last_count = n;
        return { ok: true, records: n, from: new Date(from).toISOString(), to: new Date(to).toISOString() };
      } catch (e) {
        st.last_error = String(e.message || e).slice(0, 300);
        throw e;
      } finally { st.running = false; running = null; }
    })();
    return running;
  }
  const job = guardJob('collect.m365-mailtrace.pull', async () => { if (enabled()) await pullNow(); });
  function schedule(first) {
    if (stopped) return;
    const s = Math.max(300, Number(mc().mailtrace_poll_s) || 900) * 1000;
    timer = setTimeout(async () => { try { await job(); } finally { schedule(false); } }, first ? 20000 : s);
    if (timer.unref) timer.unref();
  }
  return {
    start() { schedule(true); return this; },
    stop() { stopped = true; if (timer) clearTimeout(timer); },
    pullNow, enabled,
    status() { const c = credsOf(config); return Object.assign({ enabled: mc().mailtrace !== false, ready: !c.errs.length && !!graph, missing: c.errs, until: cur.until ? new Date(cur.until).toISOString() : null, endpoint: (() => { try { return urlOf(config); } catch (e) { return 'invalid: ' + e.message; } })() }, st); },
  };
}

function analyse(events, now, o = {}) {
  const days = o.days || 7, from = now - days * DAY, base0 = from - 14 * DAY;
  const ev = events.filter((e) => lc(e.host) === 'exchange-mailflow' && e.ts >= base0 && e.ts <= now);
  const rcpt = (e) => lc(e.target_user || (e.fields || {}).recipient), sndr = (e) => lc(e.user || (e.fields || {}).sender);
  const status = (e) => lc((e.fields || {}).status || e.event_code);
  const size = (e) => Number((e.fields || {}).size) || 0;
  // the tenant's own domains: configured, or the domains that SEND most of the mail that is delivered between known senders
  const internal = new Set((o.internal || []).map(lc));
  if (!internal.size) { const c = new Map(); for (const e of ev) { const d = domainOf(sndr(e)); if (d && !PERSONAL.has(d)) c.set(d, (c.get(d) || 0) + 1); } const top = [...c.entries()].sort((a, b) => b[1] - a[1]); if (top.length) { internal.add(top[0][0]); for (const [d, n] of top.slice(1, 4)) if (n >= top[0][1] * 0.2) internal.add(d); } }
  const dir = (e) => { const s = internal.has(domainOf(sndr(e))), r = internal.has(domainOf(rcpt(e))); return s && r ? 'internal' : s ? 'outbound' : r ? 'inbound' : 'relay'; };
  const blocked = (e) => /^(quarantined|filteredasspam)$/.test(status(e));
  const win = ev.filter((e) => e.ts >= from), base = ev.filter((e) => e.ts < from);
  const byStatus = {}, byDir = { inbound: 0, outbound: 0, internal: 0, relay: 0 };
  const extDom = new Map(), blockDom = new Map(), failDom = new Map(), personal = new Map(), large = [];
  let bytes = 0;
  const series = Array.from({ length: Math.min(days, 30) }, (_, i) => ({ day: new Date(from + i * DAY + 3 * H).toISOString().slice(0, 10), inbound: 0, outbound: 0, internal: 0, blocked: 0, failed: 0 }));
  const hours = Array.from({ length: 24 }, (_, h) => ({ hour: h, messages: 0 }));
  for (const e of win) {
    const s = status(e) || 'unknown', d = dir(e); byStatus[s] = (byStatus[s] || 0) + 1; byDir[d]++; bytes += size(e);
    const k = Math.floor((e.ts - from) / DAY); if (k >= 0 && k < series.length) { if (series[k][d] !== undefined) series[k][d]++; if (blocked(e)) series[k].blocked++; if (s === 'failed') series[k].failed++; }
    hours[new Date(e.ts + 3 * H).getUTCHours()].messages++;
    if (d === 'outbound') {
      const rd = domainOf(rcpt(e)); const x = extDom.get(rd) || extDom.set(rd, { domain: rd, messages: 0, senders: new Set(), bytes: 0 }).get(rd); x.messages++; x.senders.add(sndr(e)); x.bytes += size(e);
      if (PERSONAL.has(rd)) { const u = sndr(e), p = personal.get(u) || personal.set(u, { user: u, messages: 0, bytes: 0, domains: new Set() }).get(u); p.messages++; p.bytes += size(e); p.domains.add(rd); }
      if (size(e) >= 20 * 1048576) large.push({ at: new Date(e.ts).toISOString(), user: sndr(e), recipient: rcpt(e), mb: Math.round(size(e) / 104857.6) / 10 });
    }
    if (d === 'inbound' && blocked(e)) { const sd = domainOf(sndr(e)) || '(none)'; const x = blockDom.get(sd) || blockDom.set(sd, { domain: sd, messages: 0, quarantined: 0, spam: 0 }).get(sd); x.messages++; if (s === 'quarantined') x.quarantined++; else x.spam++; }
    if (s === 'failed') { const fd = domainOf(rcpt(e)) || '(none)'; failDom.set(fd, (failDom.get(fd) || 0) + 1); }
  }
  // each sender's outbound (external) mail per day against the most they sent in any day of their own 14 days before
  const perDay = (L) => { const m = new Map(); for (const e of L) { if (dir(e) !== 'outbound') continue; const u = sndr(e), k = u + '|' + Math.floor((e.ts + 3 * H) / DAY); const x = m.get(k) || m.set(k, { user: u, day: new Date(Math.floor((e.ts + 3 * H) / DAY) * DAY).toISOString().slice(0, 10), n: 0, rc: new Set(), bytes: 0 }).get(k); x.n++; x.rc.add(domainOf(rcpt(e))); x.bytes += size(e); } return m; };
  const bmax = new Map(); for (const x of perDay(base).values()) bmax.set(x.user, Math.max(bmax.get(x.user) || 0, x.n));
  const spikes = [];
  for (const x of perDay(win).values()) {
    const usual = bmax.get(x.user) || 0;
    if (x.n >= 30 && x.n >= 5 * Math.max(1, usual)) spikes.push({ user: x.user, day: x.day, messages: x.n, domains: x.rc.size, mb: Math.round(x.bytes / 104857.6) / 10, usual_max: usual,
      why: x.n + ' external messages in one day to ' + x.rc.size + ' domain(s)' + (usual ? ' against at most ' + usual + ' a day in the 14 days before' : ' with no external mail in the 14 days before') });
  }
  spikes.sort((a, b) => b.messages - a.messages);
  const msgs = win.length, blockedN = (byStatus.quarantined || 0) + (byStatus.filteredasspam || 0);
  const ins = [];
  if (spikes.length) ins.push(spikes[0].user + ': ' + spikes[0].why + ' - check what was sent.');
  if (personal.size) { const top = [...personal.values()].sort((a, b) => b.messages - a.messages)[0]; ins.push(personal.size + ' sender(s) mailed personal webmail; the most is ' + top.user + ' with ' + top.messages + ' message(s) - company data leaving to private mailboxes is a PDPL and NDMO concern.'); }
  if (blockedN) { const tb = [...blockDom.values()].sort((a, b) => b.messages - a.messages)[0]; ins.push(blockedN + ' inbound message(s) were quarantined or filtered as spam' + (tb ? ', most from ' + tb.domain : '') + ' - phishing pressure on the mailboxes (NCA ECC 2-4).'); }
  if (byStatus.failed) ins.push(byStatus.failed + ' message(s) failed to deliver - a burst to one domain usually means a wrong address, a full mailbox or a block on the other side.');
  if (large.length) ins.push(large.length + ' outbound message(s) of 20 MB or more - large attachments leaving the tenant.');
  return { days, from: new Date(from).toISOString(), messages: msgs, baseline_messages: base.length, internal_domains: [...internal].slice(0, 10),
    kpis: { messages: msgs, inbound: byDir.inbound, outbound: byDir.outbound, internal: byDir.internal, blocked: blockedN, failed: byStatus.failed || 0, delivered: byStatus.delivered || 0,
      external_domains: extDom.size, personal_senders: personal.size, spikes: spikes.length, large: large.length, mb: Math.round(bytes / 104857.6) / 10, senders: new Set(win.map(sndr).filter(Boolean)).size },
    by_status: byStatus, by_direction: byDir, series, hours,
    external_domains: [...extDom.values()].map((x) => ({ domain: x.domain, messages: x.messages, senders: x.senders.size, mb: Math.round(x.bytes / 104857.6) / 10, personal: PERSONAL.has(x.domain) })).sort((a, b) => b.messages - a.messages).slice(0, 15),
    blocked_domains: [...blockDom.values()].sort((a, b) => b.messages - a.messages).slice(0, 15),
    failed_domains: [...failDom.entries()].map(([domain, messages]) => ({ domain, messages })).sort((a, b) => b.messages - a.messages).slice(0, 10),
    personal: [...personal.values()].map((p) => ({ user: p.user, messages: p.messages, mb: Math.round(p.bytes / 104857.6) / 10, domains: [...p.domains] })).sort((a, b) => b.messages - a.messages).slice(0, 30),
    spikes: spikes.slice(0, 30), large: large.sort((a, b) => b.mb - a.mb).slice(0, 30), insights: ins,
    recent: win.slice().sort((a, b) => b.ts - a.ts).slice(0, 200).map((e) => ({ at: new Date(e.ts).toISOString(), sender: sndr(e), recipient: rcpt(e), status: (e.fields || {}).status || e.event_code, direction: dir(e), kb: Math.round(size(e) / 1024), from_ip: e.src_ip || '' })),
    note: 'Exchange Online message trace collected by the SIEM (mail flow metadata - no message body). Each sender is compared with their own 14 days before the window. Indicators for a person to review, not proof of wrongdoing (PDPL).' };
}

function register(api, deps) {
  const { wrap, audit, prefixOf, HttpError } = require('../soc/routeutil');
  const { body } = require('../util/check');
  const P = prefixOf(deps);
  api.route('GET', `${P}/m365/mail`, wrap(deps, 'analyst', async (ctx) => {
    const v = (ctx.query || {}).days, days = v === undefined || v === '' ? 7 : Number(v);
    if (!Number.isInteger(days) || days < 1 || days > 30) throw new HttpError(400, 'days must be a whole number 1-30');
    if (!deps.search || typeof deps.search.fetchEvents !== 'function') throw new HttpError(503, 'the event store is not available');
    const now = (deps.now || Date.now)();
    const evs = await deps.search.fetchEvents({ q: 'src_type:m365 AND host:exchange-mailflow', from: now - (days + 14) * DAY, to: now, limit: 300000 });
    const r = analyse(evs, now, { days, internal: ((deps.config || {}).m365 || {}).internal_domains });
    r.truncated = evs.length >= 300000;
    r.collector = deps.m365Mail ? deps.m365Mail.status() : { enabled: false, ready: false, missing: ['the mail trace collector is not running'] };
    audit(ctx, 'm365.mail.read', 'all', { days, messages: r.messages, spikes: r.kpis.spikes, personal_senders: r.kpis.personal_senders });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/m365/mail/status`, wrap(deps, 'viewer', async (ctx) => ctx.ok(deps.m365Mail ? deps.m365Mail.status() : { enabled: false, ready: false, missing: ['the mail trace collector is not running'] })));
  api.route('POST', `${P}/m365/mail/poll`, wrap(deps, 'admin', async (ctx) => {
    body(ctx.body || {}).done();
    if (!deps.m365Mail) throw new HttpError(503, 'the mail trace collector is not running');
    if (!deps.m365Mail.enabled()) throw new HttpError(409, 'Microsoft 365 is not connected or mail trace is switched off - save the Microsoft 365 app registration first');
    let r; try { r = await deps.m365Mail.pullNow(); } catch (e) { audit(ctx, 'm365.mail.poll', 'all', { ok: false, error: String(e.message).slice(0, 200) }); throw new HttpError(502, 'mail trace pull failed: ' + String(e.message).slice(0, 200)); }
    audit(ctx, 'm365.mail.poll', 'all', { ok: true, records: r.records });
    return ctx.ok(r);
  }));
}

module.exports = { createMailTrace, analyse, register, urlOf, PERSONAL, PERM, DEFAULT_URL };
