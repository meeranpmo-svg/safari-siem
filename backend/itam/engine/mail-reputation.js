// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Mail server reputation (Email Security page): the organisation's public mail IPs and mail domains checked against Spamhaus.
 * The DNS queries are made here; what an answer means, the findings and the advice are decided in Python
 * (pyengine/mail_rep_rules.py: mailrep.targets / mailrep.assess). Read-only: nothing is changed anywhere.
 *
 * What is checked: the addresses of each domain's MX hosts (inbound), the ip4 entries of its SPF record (outbound senders),
 * the public IPs an operator registers (e.g. the Exchange / gateway egress IP), and each mail domain against the Spamhaus
 * Domain Block List. Domains come from Domains & Hosting (its last DNS check).
 *
 * Spamhaus does not answer queries that arrive through public resolvers and asks commercial users to use its free Data
 * Query Service (DQS). With a DQS key the queries go to <key>.zen.dq.spamhaus.net / <key>.dbl.dq.spamhaus.net; without one,
 * to the public zones through the server's own resolver - a refusal (127.255.255.x) is shown as "not checked", never clean.
 * The DQS key is a credential: set by an administrator, stored sealed, never returned, never logged.
 *
 *   GET  /mail-reputation                 viewer    last results, targets, notes, whether a DQS key is set
 *   POST /mail-reputation/check           operator  check now                                     audited
 *   POST /mail-reputation/ips             operator  {ip, label, role}  register a public mail IP  audited
 *   POST /mail-reputation/ips/:id/retire  operator  {reason}                                      audited
 *   POST /mail-reputation/ips/:id/replace operator  {ip, reason, label?}  change the address: old retired, new keeps label / role  audited
 *   POST /mail-reputation/key             admin     {key} | {clear:true}  Spamhaus DQS key        audited (never the key)
 *
 * Mail route flow (pyengine/mail_route_rules.py: mailroute.assess): the receiving and sending path hop by hop. Gathered with
 * each check: MX hosts and a read-only SMTP probe of each (banner, EHLO, STARTTLS offered, QUIT - no mail is sent), MTA-STS
 * and TLS-RPT records, the full SPF tree (includes / redirect, a / mx resolved), DKIM and DMARC from Domains & Hosting, and
 * the reverse DNS of each registered outbound IP (forward-confirmed). The SIEM's mail-flow counts (gateway syslog, Exchange
 * message tracking) come from the page, which reads them as the signed-in analyst.
 *   GET  /mail-route                      viewer    route and issues from the DNS facts (the last assessment kept; refreshed in the background)
 *   POST /mail-route                      viewer    {siem}  the same with the SIEM counts (read-only)
 *   POST /mail-route/profile              operator  {expected_mx[], platform, isp_links, servers[{name, role, dns_name, private_ip, public_ips[]}]}  audited
 *   GET  /mail-route/alerts               viewer    early warnings: open, cleared, last evaluation and mail
 *   POST /mail-route/alerts/check         operator  evaluate now (also every 15 min); new ones mailed to the mail team via the SIEM  audited
 *
 * Availability (pyengine/mail_avail_rules.py: mailavail.assess): every minute the MX hosts are probed read-only (TCP 25,
 * banner, EHLO, QUIT); mail is up in a minute when at least one MX answers 220. One bucket per day (measured / up / down
 * minutes and the outages), kept 400 days. Measured against a target, 99.99% by default (about 4.3 minutes a month).
 *   GET  /mail-availability               viewer    30 / 90 / 365-day availability, budget left, outages, design gaps
 *   POST /mail-availability/target        admin     {target}  99.9 | 99.95 | 99.99 | 99.999          audited
 *
 * Regulator report (pyengine/mail_report_rules.py: mailreport.build): an e-mail outage and / or attack written up for SAMA or
 * the Insurance Authority from what the platform recorded (outages, availability, route findings, Spamhaus) and the SIEM
 * counts the page read for the window. What the platform cannot know (impact, actions, root cause) comes from the
 * preparer's notes or is listed as missing. Draft until the CISO approves it - an administrator who did not prepare it,
 * against the digest of the exact text. The platform never sends it.
 *   POST /mail-report                     operator  {regulator, kind, from, to, notes, siem}            audited
 *   GET  /mail-report | /mail-report/:id  operator  reports (regulator submissions are not for viewers)
 *   POST /mail-report/:id/approve         admin     {digest}  the CISO, not the preparer                 audited
 */
const dns = require('node:dns');
const { guardOf } = require('./errors');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const EVERY = 6 * 3600000;
const KEY_RE = /^[a-z0-9]{20,40}$/;

function pythonBin(app, opts) {
  const fs = require('node:fs');
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createMailReputation(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const cfg = (app.config && app.config.mail_reputation) || {};
  const py = opts.py || require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 30000, resident: false });
  const col = () => store.collection('mailrep'), ips = () => store.collection('mailrep_ips');
  const dc = (app.config && app.config.discovery) || {};
  let S0 = null;
  const sealer = () => S0 || (S0 = opts.sealer || require('./discovery/vault').createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-spamhaus-dqs' }));
  // a resolver of our own: the configured servers if any (a site resolver, never a public one), else the system's
  const resolver = opts.resolver || (() => { const r = new dns.promises.Resolver({ timeout: 5000, tries: 2 }); if (Array.isArray(cfg.resolvers) && cfg.resolvers.length) r.setServers(cfg.resolvers); return r; })();
  // MX host addresses as the internet sees them: the site resolver is often the internal AD DNS, which answers a split zone
  // with the gateway's PRIVATE address - that address matches no Internet link and the SMTP probe would test the inside path.
  // Public resolvers first (domains.public_resolvers), the site resolver when they cannot be reached; tests that inject a
  // resolver keep using it alone unless they inject a public one too.
  const pubList = (app.config && app.config.domains && app.config.domains.public_resolvers) || ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
  const pubResolver = opts.publicResolver !== undefined ? opts.publicResolver : opts.resolver ? null : (() => { const r = new dns.promises.Resolver({ timeout: 4000, tries: 1 }); r.setServers(pubList); return r; })();
  async function mxAddrs(host) {
    let inside = []; try { inside = await resolver.resolve4(host); } catch (e) { inside = []; /* no internal answer - the public one decides */ }
    if (pubResolver) { try { const pub = await pubResolver.resolve4(host); if (pub && pub.length) return { ips: pub, inside: inside.filter((x) => !pub.includes(x)) }; } catch (e) { /* public DNS unreachable or no record: fall back to the site resolver */ } }
    return { ips: inside, inside: [] };
  }
  // reverse DNS as the Internet sees it: public resolvers first (what receiving mail servers query), then the server's own resolver.
  // "no PTR" only when a resolver ANSWERED that there is none (NXDOMAIN / no data); a timeout, SERVFAIL or refusal is a failed lookup,
  // reported as not checked - an internal DNS that cannot reach the ISP's reverse zone must never read as "no reverse DNS".
  const NONE = new Set(['ENOTFOUND', 'ENODATA', 'NXDOMAIN']);
  async function ptrOf(ip) {
    const errs = []; let none = null;
    for (const [via, r] of [['public DNS', pubResolver], ['server DNS', resolver]]) {
      if (!r) continue;
      try {
        const names = await r.reverse(ip);
        if (names && names.length) { let fc = false; try { fc = (await r.resolve4(names[0])).includes(ip); } catch (e) { fc = false; /* the PTR name does not resolve */ } return { names: names.slice(0, 3), fcrdns: fc, via, error: null }; }
        none = none || via;
      } catch (e) { if (NONE.has(e.code)) none = none || via; else errs.push(via + ': ' + (e.code || e.message)); }
    }
    return none ? { names: [], fcrdns: false, via: none, error: null } : { names: [], fcrdns: false, via: null, error: 'reverse DNS lookup failed (' + errs.join('; ') + ')' };
  }
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const human = (who, what) => { if (/^(duty|system|ai|svc|service)[:_-]/i.test(String(who.user || ''))) throw httpErr(403, 'a person ' + what + ', not a service identity'); };

  async function rules(op, body) {
    const r = await py.call(op, body);
    if (r && r.ok === false) {
      if (app.log && app.log.every) app.log.every('mailrep:py', 300000, 'error', 'mail reputation rules (Python) did not answer', { op, cls: r.error_class, err: String(r.error || '').slice(0, 200) });
      throw httpErr(409, 'The mail reputation rules run in Python and Python did not answer (' + (r.error_class || 'error') + ') - run the update so pyengine is installed');
    }
    return r;
  }
  function dqsKey() {
    const k = col().get('dqs'); if (!k || !k.enc) return null;
    try { return sealer().unseal('dqs', k.enc); } catch (e) {
      if (app.log && app.log.every) app.log.every('mailrep:key', 3600000, 'warn', 'the Spamhaus DQS key could not be unsealed - set it again', { err: String(e.message).slice(0, 120) });
      return null;
    }
  }
  // the domains Domains & Hosting knows, with their MX hosts resolved to IPv4 and their SPF records
  async function domainInput() {
    const doms = store.collection('dom_domains').all((d) => d.status !== 'retired'), checks = store.collection('dom_checks'), out = [];
    for (const d of doms) {
      const rec = (checks.get('d:' + d.id) || {}).records || {};
      const mx = [];
      for (const line of rec.MX || []) {
        const host = String(line).split(' ').pop();
        let a = []; try { a = await resolver.resolve4(host); } catch (e) { a = []; /* an MX host that does not resolve has no address to check; Domains & Hosting reports it */ }
        mx.push({ host, ips: a });
      }
      out.push({ name: d.name, mx, spf: rec.SPF || [] });
    }
    return out;
  }
  async function lookup(t, key) {
    let q, zone;
    if (t.kind === 'ip') { const rev = t.target.split('.').reverse().join('.'); zone = key ? 'zen.dq.spamhaus.net' : 'zen.spamhaus.org'; q = rev + '.' + (key ? key + '.' : '') + zone; }
    else { zone = key ? 'dbl.dq.spamhaus.net' : 'dbl.spamhaus.org'; q = t.target + '.' + (key ? key + '.' : '') + zone; }
    try { return { target: t.target, kind: t.kind, zone, answers: (await resolver.resolve4(q)).sort() }; } catch (e) { return { target: t.target, kind: t.kind, zone, answers: [], error: e.code || 'error' }; }
  }
  // ---- route facts
  // withTls: after EHLO, STARTTLS and read the certificate (subject, names, issuer, days left) - read-only, then QUIT
  const netSmtp = (host, ip, o2 = {}) => new Promise((resolve) => {
    const net = require('node:net'), sock = net.connect({ host: ip, port: 25 }), out = { connected: false };
    let buf = '', stage = 0, done = false;
    const end = (extra) => { if (done) return; done = true; Object.assign(out, extra || {}); try { sock.destroy(); } catch (e) { /* already closed - nothing to release */ } resolve(out); };
    sock.setTimeout(8000, () => end({ error: out.connected ? 'timeout' : 'no answer on TCP 25' }));
    sock.on('error', (e) => end({ error: e.code || 'error' }));
    sock.on('connect', () => { out.connected = true; });
    sock.on('data', (d) => {
      buf += d.toString('latin1'); if (buf.length > 8192) return end({ error: 'reply too long' });
      if (!/\r?\n$/.test(buf)) return;
      const lines = buf.split(/\r?\n/).filter(Boolean), last = lines[lines.length - 1] || '';
      if (/^\d{3}-/.test(last)) return;   // a multi-line reply continues
      if (stage === 0) { out.banner = lines[0].slice(0, 200); buf = ''; if (!/^220/.test(last)) return end({ error: 'banner ' + last.slice(0, 60) }); stage = 1; sock.write('EHLO ' + (cfg.helo || 'reputation-check.invalid') + '\r\n'); return; }
      if (stage === 1) { out.ehlo = /^250/.test(last); out.starttls = lines.some((l) => /^250[- ]STARTTLS/i.test(l)); const sz = lines.map((l) => /^250[- ]SIZE\s+(\d+)/i.exec(l)).find(Boolean); if (sz) out.size = Number(sz[1]); buf = '';
        if (o2.tls && out.starttls) { stage = 3; sock.write('STARTTLS\r\n'); return; }
        stage = 2; sock.write('QUIT\r\n'); return end(); }
      if (stage === 3) {
        if (!/^220/.test(last)) return end({ tls: { error: 'STARTTLS refused: ' + last.slice(0, 60) } });
        stage = 4; sock.removeAllListeners('data'); sock.setTimeout(0);
        const tls = require('node:tls'), ts = tls.connect({ socket: sock, servername: /^[\d.]+$/.test(host) ? undefined : host, rejectUnauthorized: false });
        const tt = setTimeout(() => { try { ts.destroy(); } catch (e) { /* already closed */ } end({ tls: { error: 'TLS handshake timeout' } }); }, 8000);
        ts.on('error', (e) => { clearTimeout(tt); end({ tls: { error: String(e.code || e.message).slice(0, 80) } }); });
        ts.on('secureConnect', () => {
          clearTimeout(tt);
          const c = ts.getPeerCertificate() || {}, na = c.valid_to ? Date.parse(c.valid_to) : NaN;
          const names = String(c.subjectaltname || '').split(',').map((x) => x.trim().replace(/^DNS:/, '')).filter((x) => x && !/^IP Address:/.test(x)).slice(0, 20);
          const info = { subject: (c.subject && c.subject.CN) || null, issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || null, not_after: Number.isFinite(na) ? new Date(na).toISOString() : null,
            days_left: Number.isFinite(na) ? Math.floor((na - now()) / 86400000) : null, names: names.length ? names : (c.subject && c.subject.CN ? [c.subject.CN] : []), trusted: ts.authorized, trust_error: ts.authorized ? null : String(ts.authorizationError || '').slice(0, 80), protocol: ts.getProtocol() };
          try { ts.write('QUIT\r\n'); ts.end(); } catch (e) { /* closing anyway */ }
          end({ tls: info });
        });
        return;
      }
    });
  });
  const probe = opts.smtpProbe || netSmtp;
  const DKIM_COMMON = ['selector1', 'selector2', 'default', 'dkim', 'mail', 'libraesva', 'esg', 'google', 's1', 's2', 'k1', 'key1', 'smtp', 'email'];
  // public DNS first (what receivers query), the site resolver when public DNS gives no answer: the site resolver is often the
  // internal AD DNS, whose split zone answers mail1 / mail2 with PRIVATE addresses - an SPF "mx" or "a:" judged with those
  // authorises no public egress IP, and every egress box read "not in SPF".
  async function pubFirst(fn, name) {
    if (pubResolver) { try { const v = await pubResolver[fn](name); if (v && v.length) return v; } catch (e) { /* public DNS unreachable or no record: ask the site resolver */ } }
    return resolver[fn](name);
  }
  async function txt(name) { try { return (await pubFirst('resolveTxt', name)).map((r) => (Array.isArray(r) ? r.join('') : String(r))); } catch (e) { return []; /* no record - reported by the rules as missing */ } }
  async function spfTree(domain, record, depth, budget) {
    const node = { domain, record, children: {} };
    if (!record || depth > 10 || budget.n > 25) return node;
    for (const tok of record.split(/\s+/)) {
      if (/^[+~?-]?all$/i.test(tok)) break;   // RFC 7208: nothing after "all" is evaluated
      const inc = /^[+~?-]?include:(\S+)$/i.exec(tok) || /^redirect=(\S+)$/i.exec(tok);
      if (inc && !node.children[inc[1]]) { budget.n++; const r = (await txt(inc[1])).find((x) => /^v=spf1(\s|$)/i.test(x)) || ''; node.children[inc[1]] = await spfTree(inc[1], r, depth + 1, budget); }
      if (/^[+]?a(:|$)/i.test(tok)) { const h = tok.includes(':') ? tok.split(':')[1].split('/')[0] : domain; try { node.a_ips = (node.a_ips || []).concat(await pubFirst('resolve4', h)); } catch (e) { /* an a: mechanism with no address authorises nothing */ } }
      if (/^[+]?mx(:|$)/i.test(tok)) { const h = tok.includes(':') ? tok.split(':')[1].split('/')[0] : domain; try { for (const m of await pubFirst('resolveMx', h)) { try { node.mx_ips = (node.mx_ips || []).concat(await pubFirst('resolve4', m.exchange)); } catch (e) { /* MX host without address */ } } } catch (e) { /* no MX - the mx mechanism authorises nothing */ } }
    }
    return node;
  }
  // SPF read live for the route map, as receivers read it: public DNS first, then the site resolver. The copy Domains & Hosting
  // stored is used only when neither answers - it can be up to 6 h old, so an SPF fix would otherwise stay red until its next check.
  async function liveSpf(name) {
    const NODATA = /ENODATA|ENOTFOUND|NXDOMAIN/;
    for (const [r, via] of [[pubResolver, 'public'], [resolver, 'server']]) {
      if (!r) continue;
      try { return { ok: true, via, v: (await r.resolveTxt(name)).map((x) => (Array.isArray(x) ? x.join('') : String(x))).filter((x) => /^v=spf1(\s|$)/i.test(x)) }; }
      catch (e) { if (NODATA.test(String(e.code || e.message))) return { ok: true, via, v: [] }; /* not reachable: try the next resolver */ }
    }
    return { ok: false };
  }
  async function routeFacts() {
    const doms = store.collection('dom_domains').all((d) => d.status !== 'retired'), checks = store.collection('dom_checks'), out = [];
    for (const d of doms) {
      const rec = (checks.get('d:' + d.id) || {}).records || {}, mx = [];
      for (const line of rec.MX || []) {
        const parts = String(line).split(' '), host = parts.pop(), priority = Number(parts[0]) || 0;
        const ad = await mxAddrs(host), ips = ad.ips;   // empty = reported by the rules: MX host without address
        const smtp = cfg.smtp_probe === false || !ips.length ? null : await probe(host, ips[0], { tls: cfg.smtp_tls !== false });
        // reverse DNS of each MX address too (receivers check the PTR of a host that sends; the ISP that owns the address sets it)
        const ptr = {};
        for (const ip of ips.slice(0, 4)) ptr[ip] = await ptrOf(ip);
        mx.push({ host, priority, ips, inside_ips: ad.inside, smtp, ptr });
      }
      const ls = await liveSpf(d.name), ck = checks.get('d:' + d.id) || {};
      const spfs = ls.ok ? ls.v : rec.SPF || [];
      const spf_read = ls.ok ? { from: 'live', via: ls.via, at: now() } : { from: 'stored', at: ck.at || null };
      const a4 = async (h) => { try { return await resolver.resolve4(h); } catch (e) { return []; /* does not resolve - reported by the rules */ } };
      const cn = async (h) => { try { return ((await resolver.resolveCname(h)) || [])[0] || null; } catch (e) { return null; /* no CNAME */ } };
      const ad = { cname: await cn('autodiscover.' + d.name), ips: await a4('autodiscover.' + d.name) };
      const dkimMs = { selector1: await cn('selector1._domainkey.' + d.name), selector2: await cn('selector2._domainkey.' + d.name) };
      // DKIM: the selectors recorded in Domains & Hosting. When none is recorded - or none of them has a key - look up the selectors
      // the common senders use (Microsoft 365, Libraesva, Google, generic) in public DNS, so a key that is published is found
      // instead of reported missing. Only a TXT record holding p=<key> counts; what was found is labelled 'discovered'.
      let dkim = rec.DKIM || null, dkim_discovered = [];
      if (!dkim || !Object.values(dkim).some(Boolean)) {
        const found = {};
        for (const sel of DKIM_COMMON) {
          const t = await txt(sel + '._domainkey.' + d.name), c = t.length ? null : await cn(sel + '._domainkey.' + d.name);
          if (t.some((x) => /(^|;)\s*p=[A-Za-z0-9+/]{20,}/.test(x)) || (c && (await txt(c)).some((x) => /(^|;)\s*p=[A-Za-z0-9+/]{20,}/.test(x)))) found[sel] = true;
        }
        dkim_discovered = Object.keys(found);
        if (dkim_discovered.length) dkim = Object.assign({}, dkim || {}, found);
      }
      out.push({ name: d.name, ns: rec.NS || [], autodiscover: ad, dkim_ms: dkimMs, mx, mx_error: rec.MX && rec.MX.length ? null : rec.MX_error ? rec.MX_error : rec.MX === undefined ? 'not checked yet - Domains & Hosting has not checked this domain (Check now there)' : rec.MX === null ? 'not readable' : null, dns_via: rec.DNS_via || null, spf_count: spfs.length, spf_read, spf: spfs.length === 1 ? await spfTree(d.name, spfs[0], 0, { n: 0 }) : null,
        dkim, dkim_discovered, dkim_checked: DKIM_COMMON.length, dmarc: (rec.DMARC || [])[0] || '', mta_sts: (await txt('_mta-sts.' + d.name)).some((x) => /^v=STSv1/i.test(x)), tls_rpt: (await txt('_smtp._tls.' + d.name)).some((x) => /^v=TLSRPTv1/i.test(x)) });
    }
    const egress = [];
    for (const x of ips().all((r) => r.status !== 'retired' && r.role !== 'inbound')) {
      const p = await ptrOf(x.ip);
      egress.push({ id: x.id, ip: x.ip, label: x.label, ptr: p.names, fcrdns: p.fcrdns, ptr_via: p.via, ptr_error: p.error });
    }
    // the public DNS names recorded for the mail servers: what the Internet resolves them to (an internal name resolves to nothing)
    const server_dns = {};
    for (const sv of ((col().get('route_profile') || {}).servers || [])) {
      const dn = String(sv.dns_name || '').toLowerCase(); if (!dn || server_dns[dn]) continue;
      try { server_dns[dn] = await resolver.resolve4(dn); } catch (e) { server_dns[dn] = []; /* not in public DNS - shown as an internal name */ }
    }
    return { domains: out, egress, server_dns, at: now() };
  }
  // The route assessment (Python) depends only on the stored facts and the profile, so GET /mail-route keeps the last one (in the
  // store, so a restart does not lose it) and answers from it at once: the page and the update's final check never wait on a
  // Python start (the cause of "no answer in 30 s" right after an update restart). When only time has passed (older than
  // ROUTE_FRESH) it is shown, marked stale, and refreshed in the background; when the PROFILE changed it is recomputed in the
  // request, so a person who has just edited the profile sees the result of the edit. Bug fixed: when the FACTS changed (every
  // reputation check rewrites them) it was recomputed in the request too, so the first GET after a check or a restart waited
  // on a Python start and the update's final check reported /mail-route as not answering in 30 s - now the last assessment
  // answers at once, marked as being re-assessed, and the refresh runs in the background. With no assessment at all yet,
  // the request waits at most ROUTE_WAIT and otherwise says the assessment is being computed.
  const ROUTE_FRESH = 15 * 60000, ROUTE_WAIT = opts.routeWait != null ? opts.routeWait : 8000;
  let routeJob = null;
  async function routeAssess(l, prof, key) {
    const r = await rules('mailroute.assess', { facts: l.route, siem: null, profile: prof, reputation: l.rows || [], prev_dns: l.prev_dns || null, now: now() });
    col().put({ id: 'route_assessed', key, pkey: pkeyOf(prof), at: now(), v: r });
    return r;
  }
  const routeKey = (l, prof) => require('crypto').createHash('sha256').update(JSON.stringify([l.route, l.rows || [], l.prev_dns || null, prof])).digest('hex').slice(0, 32);
  const pkeyOf = (prof) => require('crypto').createHash('sha256').update(JSON.stringify(prof || {})).digest('hex').slice(0, 16);
  // one background assessment at a time; a failure keeps the last one and is logged (once in 5 minutes)
  function refresh(l, prof, key) {
    if (!routeJob) routeJob = routeAssess(l, prof, key).catch((e) => { if (app.log && app.log.every) app.log.every('mailrep:route-refresh', 300000, 'warn', 'mail route: background re-assessment failed - the last one is shown', { err: String(e.message).slice(0, 200) }); return null; }).finally(() => { routeJob = null; });
    return routeJob;
  }
  async function routeView(siem) {
    const l = col().get('last') || {}, prof = col().get('route_profile') || {};
    const pv = { expected_mx: prof.expected_mx || [], platform: prof.platform || 'onprem', isp_links: prof.isp_links || 1, servers: prof.servers || [] };
    if (!l.route) return { lanes: null, issues: [], warnings: [], note: 'Not checked yet - use Check now on the reputation card.', profile: pv };
    const out = (r, extra) => Object.assign({}, r, { checked_at: l.route.at, profile: pv }, extra || {});
    if (siem) return out(await rules('mailroute.assess', { facts: l.route, siem, profile: prof, reputation: l.rows || [], prev_dns: l.prev_dns || null, now: now() }));
    const key = routeKey(l, prof), c = col().get('route_assessed');
    if (c && c.key === key && now() - c.at < ROUTE_FRESH) return out(c.v);
    // the person just edited the profile: they see the result of the edit (a POST-then-GET they are waiting for)
    if (c && c.v && c.pkey && c.pkey !== pkeyOf(prof)) return out(await routeAssess(l, prof, key));
    if (c && c.v) { refresh(l, prof, key);
      return out(c.v, { stale: { at: new Date(c.at).toISOString(), why: c.key === key ? 'older than 15 minutes - being refreshed' : 'the mail facts changed since - being re-assessed' } }); }
    // nothing assessed yet: wait a little, never long enough to fail a page check
    const r = await Promise.race([refresh(l, prof, key), new Promise((ok) => { const tm = setTimeout(() => ok(undefined), ROUTE_WAIT); if (tm.unref) tm.unref(); })]);
    if (r) return out(r);
    return { lanes: null, issues: [], warnings: [], computing: true, note: 'The route assessment is being computed (the rules engine is starting) - reload in a few seconds.', checked_at: l.route.at, profile: pv };
  }
  function setProfile(b, who) {
    human(who, 'sets the mail route profile');
    const cur = col().get('route_profile') || {};
    const rec = { id: 'route_profile', expected_mx: b.expected_mx !== undefined ? b.expected_mx : (cur.expected_mx || []), platform: b.platform || cur.platform || 'onprem', isp_links: b.isp_links || cur.isp_links || 1,
      servers: b.servers !== undefined ? b.servers : (cur.servers || []), by: who.user, at: now() };
    col().put(rec);
    const was = new Set((cur.servers || []).map((x) => x.name)), is = new Set(rec.servers.map((x) => x.name));
    audit(who, 'mailrep.route.profile', 'route_profile', { expected_mx: rec.expected_mx, platform: rec.platform, isp_links: rec.isp_links, servers: rec.servers.length,
      servers_added: [...is].filter((n) => !was.has(n)), servers_removed: [...was].filter((n) => !is.has(n)) });
    return { expected_mx: rec.expected_mx, platform: rec.platform, isp_links: rec.isp_links, servers: rec.servers };
  }
  // ---- availability: one probe round a minute, day buckets
  const av = () => store.collection('mailavail');
  const dayOf = (t) => new Date(t).toISOString().slice(0, 10);
  let probing = false;
  async function probeOnce() {
    if (probing) return null;
    probing = true;
    try {
      const l = col().get('last') || {}, hosts = [];
      for (const d of (l.route && l.route.domains) || []) for (const m of d.mx || []) if (m.ips && m.ips.length && !hosts.some((h) => h.host === m.host)) hosts.push({ host: m.host, ip: m.ips[0] });
      if (!hosts.length) return null;
      const res = await Promise.all(hosts.map((h) => probe(h.host, h.ip).then((r) => ({ host: h.host, up: !!(r && r.connected && /^220/.test(String(r.banner || ''))), err: r && r.error }), () => ({ host: h.host, up: false, err: 'probe failed' }))));
      const t = now(), up = res.some((r) => r.up), id = dayOf(t);
      const b = av().get(id) || { id, measured: 0, up: 0, down: 0, outages: [], hosts: {} };
      b.measured++; if (up) b.up++; else b.down++;
      for (const r of res) { const h = b.hosts[r.host] || { up: 0, down: 0 }; if (r.up) h.up++; else h.down++; b.hosts[r.host] = h; }
      av().put(b);
      const st = av().get('_state') || { id: '_state' };
      if (!up && !st.down_since) { st.down_since = t; st.down_hosts = res.map((r) => r.host + ': ' + (r.err || 'no 220')); if (app.log) app.log.warn('mail availability: no MX host answers - inbound mail is down', { hosts: res.length }); }
      if (up && st.down_since) {
        const sd = dayOf(st.down_since), sb = av().get(sd) || { id: sd, measured: 0, up: 0, down: 0, outages: [], hosts: {} };
        sb.outages = (sb.outages || []).concat([{ start: st.down_since, end: t, minutes: Math.max(1, Math.round((t - st.down_since) / 60000)), hosts: st.down_hosts || [] }]).slice(-200);
        av().put(sb); if (app.log) app.log.warn('mail availability: MX answering again', { minutes: Math.round((t - st.down_since) / 60000) });
        delete st.down_since; delete st.down_hosts;
      }
      st.last_at = t; st.up = up; st.hosts = res; av().put(st);
      for (const x of av().all((x) => x.id !== '_state' && x.id < dayOf(t - 400 * 86400000))) av().remove(x.id);
      return { up, hosts: res };
    } finally { probing = false; }
  }
  async function availability() {
    const st = av().get('_state') || {}, l = col().get('last') || {}, tg = (col().get('avail_target') || {}).target || 99.99;
    const r = await rules('mailavail.assess', { days: av().all((x) => x.id !== '_state'), target: tg, now: now(), facts: l.route || null });
    return Object.assign(r, { current: { up: st.up === undefined ? null : st.up, down_since: st.down_since || null, last_at: st.last_at || null, hosts: st.hosts || [] } });
  }
  function setTarget(b, who) {
    human(who, 'sets the availability target');
    const prev = (col().get('avail_target') || {}).target || 99.99;
    col().put({ id: 'avail_target', target: b.target, by: who.user, at: now() });
    audit(who, 'mailrep.availability.target', 'avail_target', { target: b.target, previous: prev });
    return { target: b.target };
  }
  // ---- regulator reports
  const reps = () => store.collection('mailreports');
  async function buildReport(b, who) {
    human(who, 'prepares a regulator report');
    const f = Date.parse(b.from), t = Date.parse(b.to);
    if (!(f < t)) throw httpErr(400, 'from must be before to');
    if (t > now() + 300000) throw httpErr(400, 'to cannot be in the future');
    const outages = []; for (const d of av().all((x) => x.id !== '_state')) for (const o of d.outages || []) outages.push(o);
    const st = av().get('_state') || {}; if (st.down_since) outages.push({ start: st.down_since, end: null, minutes: Math.round((now() - st.down_since) / 60000), hosts: st.down_hosts || [] });
    let avail = null; try { avail = await availability(); } catch (e) { avail = null; if (app.log && app.log.every) app.log.every('mailrep:report-av', 600000, 'warn', 'availability not readable for the report', { err: String(e.message).slice(0, 120) }); }
    let route = null; try { route = await routeView(null); } catch (e) { route = null; if (app.log && app.log.every) app.log.every('mailrep:report-route', 600000, 'warn', 'route not readable for the report', { err: String(e.message).slice(0, 120) }); }
    const l = col().get('last') || {};
    const doc = await rules('mailreport.build', { regulator: b.regulator, kind: b.kind, from: f, to: t, outages, availability: avail, target: avail && avail.target, route, reputation: l.rows || [], siem: b.siem || null, notes: b.notes || {}, prepared_by: who.user, now: now() });
    const digest = 'sha256:' + require('node:crypto').createHash('sha256').update(JSON.stringify(doc)).digest('hex');
    const n = reps().all().length + 1, id = 'MR-' + String(n).padStart(4, '0');
    const rec = { id, regulator: b.regulator, kind: b.kind, from: f, to: t, doc, digest, state: 'draft', prepared_by: who.user, prepared_at: now() };
    reps().put(rec);
    audit(who, 'mailrep.report.prepare', id, { regulator: b.regulator, kind: b.kind, from: b.from, to: b.to, missing: doc.missing.length, digest });
    return rec;
  }
  const reports = () => reps().all().sort((a, b) => b.prepared_at - a.prepared_at).map((r) => ({ id: r.id, regulator: r.regulator, kind: r.kind, from: r.from, to: r.to, state: r.state, prepared_by: r.prepared_by, prepared_at: r.prepared_at, approved_by: r.approved_by || null, missing: (r.doc.missing || []).length }));
  function report(id, who) { const r = reps().get(id); if (!r) throw httpErr(404, 'no report ' + id); audit(who, 'mailrep.report.view', id, {}); return r; }
  function approveReport(id, b, who) {
    human(who, 'approves a regulator report');
    const r = reps().get(id); if (!r) throw httpErr(404, 'no report ' + id);
    if (r.state === 'approved') throw httpErr(409, id + ' is already approved by ' + r.approved_by);
    if (String(r.prepared_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who prepared the report cannot approve it');
    if (b.digest !== r.digest) throw httpErr(409, 'the report changed since you read it - open it again before approving');
    Object.assign(r, { state: 'approved', approved_by: who.user, approved_at: now() }); reps().put(r);
    audit(who, 'mailrep.report.approve', id, { regulator: r.regulator, digest: r.digest });
    return r;
  }
  let running = null;
  async function check(who) {
    if (running) return running;
    running = (async () => {
      const key = dqsKey();
      const tg = await rules('mailrep.targets', { domains: await domainInput(), manual: ips().all((x) => x.status !== 'retired'), test_nets: !!opts.testNets });
      const lookups = [];
      for (const t of tg.targets.slice(0, 200)) lookups.push(await lookup(t, key));
      const last = col().get('last') || {}, prev = {}; for (const r of last.rows || []) prev[r.target] = r;
      const r = await rules('mailrep.assess', { lookups, targets: tg.targets, prev, now: now(), dqs: !!key });
      let route = null; try { route = await routeFacts(); } catch (e) { route = null; if (app.log && app.log.every) app.log.every('mailrep:route', 3600000, 'warn', 'mail route facts could not be gathered', { err: String(e.message).slice(0, 200) }); }
      // what the next check compares DNS against (MX / NS / SPF changes are early warnings)
      let prevDns = last.prev_dns || null;
      if (last.route && route) { try { prevDns = (await rules('mailroute.snapshot', { facts: last.route })).snapshot; } catch (e) { if (app.log && app.log.every) app.log.every('mailrep:snap', 3600000, 'warn', 'DNS snapshot for change detection failed', { err: String(e.message).slice(0, 120) }); } }
      col().put({ id: 'last', at: now(), by: who.user, rows: r.rows, findings: r.findings, changes: r.changes, counts: r.counts, warning: r.warning, notes: tg.notes, dqs: !!key, route, prev_dns: prevDns });
      // the new facts are assessed here, in the check (already a background job), so GET /mail-route answers from them at once
      if (route) { const l2 = col().get('last'), pr = col().get('route_profile') || {}; try { await routeAssess(l2, pr, routeKey(l2, pr)); } catch (e) { if (app.log && app.log.every) app.log.every('mailrep:route-assess', 3600000, 'warn', 'mail route: assessment after the check failed - the page shows the last one', { err: String(e.message).slice(0, 200) }); } }
      for (const c of r.changes) if (app.log) app.log.warn('mail reputation changed', { target: c.target, from: c.from, to: c.to });
      audit(who, 'mailrep.check', 'spamhaus', { checked: lookups.length, listed: r.counts.listed, not_checked: r.counts.not_checked, dqs: !!key, changes: r.changes.length });
      return view();
    })();
    try { return await running; } finally { running = null; }
  }
  function view() {
    const l = col().get('last') || null;
    return { last: l ? { at: l.at, by: l.by, rows: l.rows, counts: l.counts, findings: l.findings, changes: l.changes, warning: l.warning, notes: l.notes, dqs: l.dqs } : null,
      dqs_configured: !!(col().get('dqs') || {}).enc, registered: ips().all((x) => x.status !== 'retired').map((x) => ({ id: x.id, ip: x.ip, label: x.label, role: x.role, by: x.by })),
      every_hours: EVERY / 3600000,
      note: 'Checked against Spamhaus ZEN (SBL, CSS, XBL, PBL, DROP) for IPs and the Domain Block List for mail domains. A refused query is "not checked", never clean. Listing is a reputation signal - fix the cause before requesting removal.' };
  }
  function addIp(b, who) {
    human(who, 'registers a mail IP');
    if (ips().all((x) => x.ip === b.ip && x.status !== 'retired').length) throw httpErr(409, b.ip + ' is already registered');
    const n = ips().all().length + 1, id = 'MIP-' + String(n).padStart(3, '0');
    const rec = { id, ip: b.ip, label: b.label, role: b.role || 'outbound', status: 'active', by: who.user, at: now() };
    ips().put(rec); audit(who, 'mailrep.ip.add', id, { ip: b.ip, label: b.label, role: rec.role });
    return rec;
  }
  function retireIp(id, b, who) {
    human(who, 'retires a mail IP');
    const r = ips().get(id); if (!r || r.status === 'retired') throw httpErr(404, 'no registered mail IP ' + id);
    r.status = 'retired'; r.retired = { at: now(), by: who.user, reason: b.reason }; ips().put(r);
    audit(who, 'mailrep.ip.retire', id, { ip: r.ip, reason: b.reason });
    return r;
  }
  // change a registered IP in one step: the old one is retired (kept, with the reason and what replaced it), the new one keeps its
  // label and role - a wrong or moved egress address is corrected without two half-done edits
  function replaceIp(id, b, who) {
    human(who, 'changes a mail IP');
    const r = ips().get(id); if (!r || r.status === 'retired') throw httpErr(404, 'no registered mail IP ' + id);
    if (r.ip === b.ip) throw httpErr(400, 'ip is the same as the registered address ' + r.ip);
    if (ips().all((x) => x.ip === b.ip && x.status !== 'retired').length) throw httpErr(409, b.ip + ' is already registered');
    const n = ips().all().length + 1, nid = 'MIP-' + String(n).padStart(3, '0');
    const rec = { id: nid, ip: b.ip, label: b.label || r.label, role: r.role, status: 'active', by: who.user, at: now(), replaces: { id: r.id, ip: r.ip } };
    r.status = 'retired'; r.retired = { at: now(), by: who.user, reason: b.reason, replaced_by: nid }; ips().put(r); ips().put(rec);
    audit(who, 'mailrep.ip.replace', nid, { from: r.ip, to: b.ip, old_id: r.id, label: rec.label, role: rec.role, reason: b.reason });
    return rec;
  }
  function setKey(b, who) {
    human(who, 'sets the Spamhaus key');
    if (b.clear) { col().remove('dqs'); audit(who, 'mailrep.key.clear', 'dqs', {}); return { dqs_configured: false }; }
    col().put({ id: 'dqs', enc: sealer().seal('dqs', b.key), set_by: who.user, set_at: now() });
    audit(who, 'mailrep.key.set', 'dqs', { length: b.key.length });   // never the key itself
    return { dqs_configured: true };
  }
  const findings = () => ((col().get('last') || {}).findings || []);
  // ---- early warnings: route warnings (certificates, DNS changes, SPF near its limit), serious route issues, the Exchange
  // servers' own health findings from the SIEM (queues, certificates, disks, database copies) and the availability budget.
  // Kept with first / last seen; a new one (medium and above) is e-mailed to the mail team through the SIEM relay, and an open
  // high / critical one is reminded every 24 h. Cleared ones stay in the history.
  const alerts = () => store.collection('mail_alerts');
  const MSYS = { user: 'system:itam-mail-route', role: 'admin', ip: '' };
  const D = () => opts.discovery || app.discovery || null;
  const REMIND_MS = 24 * 3600000, MAILED = ['critical', 'high', 'medium'];
  const keyOf = (s) => require('node:crypto').createHash('sha1').update(String(s)).digest('hex').slice(0, 16);
  const escH = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  async function siemExchange() {
    const d = D(); if (!d || !d.siem || typeof d.siem.call !== 'function') return { error: 'no link to the SIEM' };
    try {
      const x = await d.siem.call('GET', '/sysadmin/overview?role=exchange', MSYS);
      if (!x || x.status !== 200 || !x.json) return { error: 'SIEM answered HTTP ' + (x && x.status) };
      return { findings: (x.json.findings || []).slice(0, 60), servers: x.json.servers || 0, checked: x.json.checked || 0 };
    } catch (e) { return { error: String(e.message || e).slice(0, 160) }; }
  }
  // listing risk before a listing: what the gateway saw leave (spam / phishing / malware verdicts) and an outbound spike
  async function siemOutbound() {
    const d = D(); if (!d || !d.siem || typeof d.siem.call !== 'function') return { error: 'no link to the SIEM' };
    const G = 'fields.vendor_class:email_gateway AND fields.email_direction:outbound';
    const top = async (q, from, to) => { const x = await d.siem.call('POST', '/top', MSYS, { q, from, to, field: 'fields.email_verdict', limit: 10 }); if (!x || x.status !== 200 || !x.json) throw new Error('SIEM answered HTTP ' + (x && x.status)); return (x.json.values || []).reduce((m, v) => m + (Number(v.n) || 0), 0); };
    const verdicts = async (q, from) => { const x = await d.siem.call('POST', '/top', MSYS, { q, from, to: 'now', field: 'fields.email_verdict', limit: 10 }); if (!x || x.status !== 200 || !x.json) throw new Error('SIEM answered HTTP ' + (x && x.status)); return x.json.values || []; };
    try {
      const bad = await verdicts(G + ' AND fields.email_verdict:(spam OR phishing OR malware)', 'now-24h');
      const lastHour = await top(G, 'now-1h', 'now'), dayBefore = await top(G, 'now-25h', 'now-1h');
      return { bad: bad.map((v) => ({ verdict: String(v.v), n: Number(v.n) || 0 })), last_hour: lastHour, hourly_avg: Math.round(dayBefore / 24) };
    } catch (e) { return { error: String(e.message || e).slice(0, 160) }; }
  }
  let evaluating = null;
  async function evaluateAlerts(who) {
    if (evaluating) return evaluating;
    evaluating = (async () => {
      const t = now(), items = [], gaps = [];
      let route = null;
      try { route = await routeView(null); } catch (e) { gaps.push('route rules: ' + String(e.message).slice(0, 120)); }
      if (route && route.lanes) {
        for (const w of route.warnings || []) items.push({ key: 'w:' + w.key, source: 'route', severity: w.severity, title: w.title, detail: w.detail, fix: w.fix || [] });
        for (const i of route.issues || []) if (i.severity === 'critical' || i.severity === 'high') items.push({ key: 'i:' + i.hop + ':' + keyOf(i.title), source: 'route', severity: i.severity, title: i.title, detail: (i.evidence || []).join(' · '), fix: i.fix || [] });
      }
      const ex = await siemExchange();
      if (ex.error) gaps.push('Exchange health (SIEM): ' + ex.error);
      for (const f of ex.findings || []) {
        if (f.kind === 'cannot-check') continue;
        const stem = String(f.title || '').replace(/\d[\d,.]*\s*(%|messages|GB|days?)?/g, '#').slice(0, 80);   // numbers move; the condition does not
        items.push({ key: 'x:' + keyOf((f.server || '') + '|' + f.kind + '|' + stem), source: 'exchange', severity: f.severity, title: f.title, detail: [f.server_name, ...(f.evidence || []).slice(0, 3)].filter(Boolean).join(' · '), fix: f.recommendation ? [f.recommendation] : [] });
      }
      const ob = await siemOutbound();
      if (ob.error) gaps.push('outbound mail (SIEM): ' + ob.error);
      else {
        const nBad = ob.bad.reduce((m, v) => m + v.n, 0);
        if (nBad) items.push({ key: 'r:outbound-bad', source: 'risk', severity: nBad >= 20 ? 'high' : 'medium', title: `${nBad} outbound message(s) flagged ${ob.bad.map((v) => v.verdict).join(' / ')} by the gateway in 24 h - Spamhaus listing risk`,
          detail: ob.bad.map((v) => `${v.verdict} ${v.n}`).join(' · '), fix: ['Find the sending mailbox in the gateway log / Exchange message trace, reset its password and revoke its sessions (a compromised account is the usual cause)', 'Clear its queued messages before more leave', 'Keep checking the Spamhaus card until the IPs stay clean'] });
        if (ob.last_hour >= 200 && ob.last_hour >= 3 * Math.max(1, ob.hourly_avg)) items.push({ key: 'r:outbound-spike', source: 'risk', severity: 'high', title: `Outbound mail spike: ${ob.last_hour} messages in the last hour against ${ob.hourly_avg} an hour normally - Spamhaus listing risk`,
          detail: 'gateway outbound events, last hour vs the 24 hours before', fix: ['Check which sender is responsible in the gateway log; if it is not a planned mailing, stop it and check the account for compromise'] });
      }
      try {
        const a = await availability(), w30 = (a.windows || []).find((w) => w.days === 30);
        if (a.current && a.current.up === false) items.push({ key: 'a:down', source: 'availability', severity: 'critical', title: 'Inbound mail is down: no MX host answers SMTP', detail: (a.current.hosts || []).map((h) => h.host + ': ' + (h.err || 'no 220')).join(' · '), fix: ['Open the Email Route Map: the red hop is where mail stops'] });
        if (w30 && w30.budget_used_pct != null && w30.budget_used_pct >= 50) items.push({ key: 'a:budget', source: 'availability', severity: w30.budget_used_pct >= 100 ? 'critical' : w30.budget_used_pct >= 80 ? 'high' : 'medium',
          title: w30.budget_used_pct >= 100 ? 'The 30-day availability target is missed' : `${Math.round(w30.budget_used_pct)}% of the 30-day downtime budget is used`, detail: `availability ${w30.availability}% against ${a.target}% · ${w30.down_minutes} of ${w30.allowed_minutes} minutes`,
          fix: ['Avoid planned downtime until the window rolls over', 'Close the design gaps listed under Email availability (second MX, second link)'] });
      } catch (e) { gaps.push('availability: ' + String(e.message).slice(0, 120)); }
      const seen = new Set(), opened = [], cleared = [], toMail = [];
      for (const it of items) {
        const id = 'MA-' + keyOf(it.key); if (seen.has(id)) continue; seen.add(id);
        const cur = alerts().get(id);
        if (!cur || cur.cleared_at) {
          const rec = Object.assign({ id, first_seen: t, last_seen: t, cleared_at: null, mailed_at: null, reopened: cur ? (cur.reopened || 0) + 1 : 0 }, it);
          alerts().put(rec); opened.push(rec); if (MAILED.includes(it.severity)) toMail.push(rec);
        } else {
          Object.assign(cur, it, { last_seen: t }); alerts().put(cur);
          if ((cur.severity === 'critical' || cur.severity === 'high') && cur.mailed_at && t - cur.mailed_at >= REMIND_MS) toMail.push(cur);
        }
      }
      // a source that could not be read clears nothing it owns: "not readable" is not "fixed"
      const unread = new Set(); if (ex.error) unread.add('exchange'); if (ob.error) unread.add('risk'); if (!route || !route.lanes) unread.add('route');
      for (const a of alerts().all((x) => !x.cleared_at && !seen.has(x.id) && !unread.has(x.source))) { a.cleared_at = t; alerts().put(a); cleared.push(a); }
      for (const old of alerts().all((x) => x.cleared_at && t - x.cleared_at > 90 * 86400000)) alerts().remove(old.id);
      let mail = null;
      if (toMail.length && cfg.alert_mail !== false) {
        mail = await sendAlertMail(toMail, t);
        if (mail.ok) for (const a of toMail) { const r = alerts().get(a.id); if (r) { r.mailed_at = t; alerts().put(r); } }
      }
      const st = { id: 'alerts_state', at: t, by: (who && who.user) || 'system', items: items.length, gaps, mail: mail || ((col().get('alerts_state') || {}).mail) || null };
      col().put(st);
      if (opened.length || cleared.length || mail) audit(who || MSYS, 'mailrep.alerts.evaluate', 'mail_alerts', { opened: opened.map((x) => x.id), cleared: cleared.map((x) => x.id), mailed: mail ? { ok: mail.ok, count: toMail.length, error: mail.error || null } : null });
      for (const g of gaps) if (app.log && app.log.every) app.log.every('mailrep:alerts:' + g.slice(0, 30), 3600000, 'warn', 'mail early warnings: a source could not be read', { gap: g });
      return alertView();
    })();
    try { return await evaluating; } finally { evaluating = null; }
  }
  async function sendAlertMail(list, t) {
    const d = D(); if (!d || !d.siem || typeof d.siem.call !== 'function') return { ok: false, error: 'no link to the SIEM (mail relay)', at: t };
    const S = { critical: 'CRITICAL', high: 'HIGH', medium: 'WARNING' }, top = list.reduce((m, a) => (MAILED.indexOf(a.severity) < MAILED.indexOf(m) ? a.severity : m), 'medium');
    const subject = `${S[top]}: ${list.length === 1 ? list[0].title : list.length + ' mail service warnings - ' + list[0].title}`.slice(0, 200);
    const url = cfg.portal_url ? String(cfg.portal_url).replace(/\/+$/, '') + '/email-route-map.html' : '';
    const text = [('Mail service early warnings from ' + ZYB_ORG.short + ' IT Asset Management:'), ''].concat(list.map((a) => `[${S[a.severity]}] ${a.title}\n  ${a.detail || ''}\n  Fix: ${(a.fix || [])[0] || 'see the Email Route Map'}`), ['', url ? 'Open the Email Route Map: ' + url : 'Open the Email Route Map on the platform.']).join('\n');
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111"><p><b>Mail service early warnings</b></p><ul>${list.map((a) => `<li style="margin-bottom:8px"><b style="color:${a.severity === 'medium' ? '#9a6700' : '#b42318'}">${S[a.severity]}</b> ${escH(a.title)}<br><span style="color:#555">${escH(a.detail || '')}</span><br>Fix: ${escH((a.fix || [])[0] || 'see the Email Route Map')}</li>`).join('')}</ul>${url ? `<p><a href="${escH(url)}">Open the Email Route Map</a></p>` : ''}</div>`;
    try {
      const x = await d.siem.call('POST', '/mail/notify/send', MSYS, { id: 'ma-' + t, subject, text, html });
      return x && x.status >= 200 && x.status < 300 ? { ok: true, at: t, recipients: (x.json && x.json.recipients) || null, count: list.length } : { ok: false, at: t, error: (x && x.json && x.json.error) || ('SIEM HTTP ' + (x && x.status)), count: list.length };
    } catch (e) { return { ok: false, at: t, error: String(e.message || e).slice(0, 200), count: list.length }; }
  }
  function alertView() {
    const all = alerts().all(), st = col().get('alerts_state') || null, SV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return { open: all.filter((a) => !a.cleared_at).sort((a, b) => (SV[b.severity] || 0) - (SV[a.severity] || 0) || a.first_seen - b.first_seen),
      cleared: all.filter((a) => a.cleared_at).sort((a, b) => b.cleared_at - a.cleared_at).slice(0, 30), state: st,
      note: 'Early warnings: SMTP certificates near expiry, DNS (MX / name server / SPF) changes, SPF near its lookup limit, serious route issues, the Exchange servers\' health from the SIEM and the availability budget. New ones are e-mailed to the mail team (recipients set by an administrator), open serious ones every 24 h.' };
  }
  function start() {
    const run = guardOf(app, 'mailrep.check', async () => { const l = col().get('last'); if (!l || now() - l.at >= EVERY) await check({ user: 'system:mail-reputation', role: 'system' }); });
    const t = setInterval(run, 15 * 60000); if (t.unref) t.unref();
    const t0 = setTimeout(run, 60000); if (t0.unref) t0.unref();
    const pa = guardOf(app, 'mailrep.availability', () => probeOnce());
    const t1 = setInterval(pa, Math.max(30, Number(cfg.availability_probe_sec) || 60) * 1000); if (t1.unref) t1.unref();
    if (cfg.alerts !== false) { const ea = guardOf(app, 'mailrep.alerts', () => evaluateAlerts(MSYS)); const t2 = setInterval(ea, 15 * 60000); if (t2.unref) t2.unref(); }
  }
  return { check, view, addIp, replaceIp, retireIp, setKey, findings, start, routeView, setProfile, probeOnce, availability, setTarget, buildReport, reports, report, approveReport, evaluateAlerts, alertView, KEY_RE };
}

function registerMailReputationRoutes(srv, app, M) {
  const { body, param } = require('./check');
  srv.route('GET', '/mail-reputation', (ctx) => { ctx.need('viewer'); return M.view(); });   // public IPs and domains, no personal data
  srv.route('POST', '/mail-reputation/check', async (ctx) => { ctx.need('operator'); return M.check(ctx.who); });
  srv.route('POST', '/mail-reputation/ips', (ctx) => {
    ctx.need('operator');
    return M.addIp(body(ctx.body).str('ip', { required: true, ip: true, max: 15, re: /^\d{1,3}(\.\d{1,3}){3}$/, msg: 'ip must be an IPv4 address (Spamhaus lists are IPv4)' })
      .str('label', { required: true, max: 120 }).oneOf('role', ['outbound', 'inbound', 'both']).done(), ctx.who);
  });
  srv.route('POST', '/mail-reputation/ips/:id/replace', (ctx) => {
    ctx.need('operator');
    const id = param(ctx.params.id, 'id'); if (!/^MIP-\d{3,}$/.test(id)) throw httpErr(400, 'id must be a mail IP id (MIP-nnn)');
    return M.replaceIp(id, body(ctx.body).str('ip', { required: true, ip: true, max: 15, re: /^\d{1,3}(\.\d{1,3}){3}$/, msg: 'ip must be an IPv4 address (Spamhaus lists are IPv4)' })
      .str('label', { max: 120 }).str('reason', { required: true, min: 3, max: 300 }).done(), ctx.who);
  });
  srv.route('POST', '/mail-reputation/ips/:id/retire', (ctx) => {
    ctx.need('operator');
    const id = param(ctx.params.id, 'id'); if (!/^MIP-\d{3,}$/.test(id)) throw httpErr(400, 'id must be a mail IP id (MIP-nnn)');
    return M.retireIp(id, body(ctx.body).str('reason', { required: true, max: 300 }).done(), ctx.who);
  });
  srv.route('GET', '/mail-route', async (ctx) => { ctx.need('viewer'); return M.routeView(null); });
  const GW = ['delivered', 'quarantined', 'blocked', 'rejected', 'email-event'], EX = ['receive', 'send', 'deliver', 'fail', 'defer', 'dsn', 'submit', 'drop', 'expand', 'redirect', 'resolve', 'transfer', 'transport'];
  const counts = (o, keys, name) => {
    if (o === undefined || o === null) return undefined;
    if (typeof o !== 'object' || Array.isArray(o)) throw httpErr(400, name + ' must be an object of counts');
    const out = {}; for (const [k, v] of Object.entries(o)) { if (!keys.includes(k)) continue; if (!Number.isInteger(v) || v < 0 || v > 1e9) throw httpErr(400, name + '.' + k + ' must be a whole number'); out[k] = v; }
    return out;
  };
  srv.route('POST', '/mail-route', async (ctx) => {
    ctx.need('viewer');   // read-only: the counts the page read from the SIEM, judged with the DNS facts
    const sb = (ctx.body || {}).siem;
    if (sb !== undefined && sb !== null && (typeof sb !== 'object' || Array.isArray(sb))) throw httpErr(400, 'siem must be an object');
    let siem = null;
    if (sb) {
      siem = { gateway_in: counts(sb.gateway_in, GW, 'siem.gateway_in'), gateway_out: counts(sb.gateway_out, GW, 'siem.gateway_out'), exchange: counts(sb.exchange, EX, 'siem.exchange'), exchange_reasons: [],
        recent: counts(sb.recent, ['gateway_in', 'gateway_out', 'exchange_receive', 'exchange_send', 'exchange_deliver'], 'siem.recent') };   // the last hour, for an outage
      const rs = sb.exchange_reasons;
      if (rs !== undefined && (!Array.isArray(rs) || rs.length > 15)) throw httpErr(400, 'siem.exchange_reasons must be a list of up to 15 {value, n}');
      for (const r of rs || []) { if (!r || typeof r.value !== 'string' || r.value.length > 300 || !Number.isInteger(r.n) || r.n < 0) throw httpErr(400, 'siem.exchange_reasons: each entry needs value (text) and n (count)'); siem.exchange_reasons.push({ value: r.value, n: r.n }); }
    }
    return M.routeView(siem);
  }, { anyRole: 'a read-only judgement of counts the person already read; nothing is stored' });
  srv.route('GET', '/mail-availability', async (ctx) => { ctx.need('viewer'); return M.availability(); });
  srv.route('POST', '/mail-availability/target', (ctx) => {
    ctx.need('admin');   // the service level is a management decision
    const b = body(ctx.body).num('target', { required: true }).rule((o) => ([99.9, 99.95, 99.99, 99.999].includes(o.target) ? null : 'target must be one of 99.9, 99.95, 99.99, 99.999')).done();
    return M.setTarget(b, ctx.who);
  });
  srv.route('GET', '/mail-report', (ctx) => { ctx.need('operator'); return { reports: M.reports() }; });
  srv.route('GET', '/mail-report/:id', (ctx) => { ctx.need('operator'); const id = param(ctx.params.id, 'id'); if (!/^MR-\d{4,}$/.test(id)) throw httpErr(400, 'id must be a report id (MR-nnnn)'); return M.report(id, ctx.who); });
  srv.route('POST', '/mail-report/:id/approve', (ctx) => {
    ctx.need('admin');   // the CISO approves what goes to the regulator
    const id = param(ctx.params.id, 'id'); if (!/^MR-\d{4,}$/.test(id)) throw httpErr(400, 'id must be a report id (MR-nnnn)');
    return M.approveReport(id, body(ctx.body).str('digest', { required: true, re: /^sha256:[0-9a-f]{64}$/, msg: 'digest must be the report digest (sha256:…)' }).done(), ctx.who);
  });
  const DTR = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;
  const txt = (o, k, max) => { const v = o[k]; if (v === undefined || v === null || v === '') return undefined; if (typeof v !== 'string' || v.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v)) throw httpErr(400, 'notes.' + k + ' must be text up to ' + max + ' characters'); return v.trim(); };
  srv.route('POST', '/mail-report', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).oneOf('regulator', ['sama', 'ia'], { required: true }).oneOf('kind', ['downtime', 'attack', 'both'], { required: true })
      .str('from', { required: true, max: 40, re: DTR, msg: 'from must be a date-time with a zone (YYYY-MM-DDTHH:MMZ)' }).str('to', { required: true, max: 40, re: DTR, msg: 'to must be a date-time with a zone (YYYY-MM-DDTHH:MMZ)' }).done();
    const nb = (ctx.body || {}).notes || {};
    if (typeof nb !== 'object' || Array.isArray(nb)) throw httpErr(400, 'notes must be an object');
    const notes = {}; for (const [k, m] of [['summary', 2000], ['detected', 300], ['impact', 2000], ['personal_data', 500], ['cause', 2000], ['actions', 3000], ['preventive', 2000]]) { const v = txt(nb, k, m); if (v) notes[k] = v; }
    if (nb.timeline !== undefined) {
      if (!Array.isArray(nb.timeline) || nb.timeline.length > 30) throw httpErr(400, 'notes.timeline must be a list of up to 30 {at, event}');
      notes.timeline = nb.timeline.map((x, i) => { if (!x || typeof x.at !== 'string' || typeof x.event !== 'string' || x.at.length > 40 || x.event.length > 500) throw httpErr(400, 'notes.timeline[' + i + '] needs at and event (text)'); return { at: x.at, event: x.event }; });
    }
    const sb = (ctx.body || {}).siem; let siem = null;
    if (sb !== undefined && sb !== null) {
      if (typeof sb !== 'object' || Array.isArray(sb)) throw httpErr(400, 'siem must be an object');
      const cnt = (o, name) => { if (o === undefined || o === null) return undefined; if (typeof o !== 'object' || Array.isArray(o)) throw httpErr(400, name + ' must be an object of counts'); const r = {}; for (const [k, v] of Object.entries(o).slice(0, 20)) { if (!/^[a-z_-]{1,30}$/.test(k) || !Number.isInteger(v) || v < 0) throw httpErr(400, name + '.' + k.slice(0, 30) + ' must be a whole number'); r[k] = v; } return r; };
      const list = (a, name, keys) => { if (a === undefined) return undefined; if (!Array.isArray(a) || a.length > 20) throw httpErr(400, name + ' must be a list of up to 20'); return a.map((x) => { const r = {}; for (const k of keys) { const v = x && x[k]; if (typeof v === 'string' && v.length <= 200) r[k] = v; else if (Number.isInteger(v) && v >= 0) r[k] = v; } return r; }); };
      siem = { threats: cnt(sb.threats, 'siem.threats'), gateway: cnt(sb.gateway, 'siem.gateway'), top_threats: list(sb.top_threats, 'siem.top_threats', ['v', 'n']), countries: list(sb.countries, 'siem.countries', ['name', 'allow', 'deny']) };
    }
    b.notes = notes; b.siem = siem;
    return M.buildReport(b, ctx.who);
  });
  // the mail server register: each gateway / Exchange / edge / relay server with its DNS name, internal address and public (NAT) addresses
  const IP4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const internal = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
  function servers(list) {
    if (list === undefined) return undefined;
    if (!Array.isArray(list) || list.length > 20) throw httpErr(400, 'servers must be a list of up to 20');
    const names = new Set();
    return list.map((x, i) => {
      const s = body(x).str('name', { required: true, max: 80, re: /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/, msg: `servers[${i}].name: letters, digits, space . _ -` })
        .oneOf('role', ['gateway', 'exchange', 'edge', 'relay', 'hybrid', 'other'], { required: true })
        .str('dns_name', { max: 253, re: /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/, msg: `servers[${i}].dns_name must be a host name` })
        .str('private_ip', { max: 15, re: IP4, msg: `servers[${i}].private_ip must be an IPv4 address` })
        .list('public_ips', { max: 4, item: 'str', itemMax: 15, unique: true }).done();
      if (s.private_ip && !internal(s.private_ip)) throw httpErr(400, `servers[${i}].private_ip ${s.private_ip} is not an internal address (10/8, 172.16/12, 192.168/16, 100.64/10)`);
      for (const p of s.public_ips || []) { if (!IP4.test(p)) throw httpErr(400, `servers[${i}].public_ips: ${p.slice(0, 20)} is not an IPv4 address`); if (internal(p)) throw httpErr(400, `servers[${i}].public_ips: ${p} is an internal address`); }
      const k = s.name.toLowerCase(); if (names.has(k)) throw httpErr(400, `servers: ${s.name} appears twice`); names.add(k);
      return { name: s.name, role: s.role, dns_name: s.dns_name ? s.dns_name.toLowerCase() : null, private_ip: s.private_ip || null, public_ips: s.public_ips || [] };
    });
  }
  srv.route('POST', '/mail-route/profile', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).list('expected_mx', { item: 'str', itemMax: 200, max: 10, unique: true }).oneOf('platform', ['onprem', 'hybrid', 'online']).int('isp_links', { min: 1, max: 4 })
      .rule((o) => ((o.expected_mx || []).some((h) => !/^[a-z0-9.-]+$/i.test(h)) ? 'expected_mx must be host names or domain suffixes' : null)).done();
    return M.setProfile({ expected_mx: b.expected_mx ? b.expected_mx.map((h) => h.toLowerCase().replace(/\.$/, '')) : undefined, platform: b.platform, isp_links: b.isp_links, servers: servers((ctx.body || {}).servers) }, ctx.who);
  });
  srv.route('GET', '/mail-route/alerts', (ctx) => { ctx.need('viewer'); return M.alertView(); });   // server names and public facts, no personal data
  srv.route('POST', '/mail-route/alerts/check', async (ctx) => { ctx.need('operator'); return M.evaluateAlerts(ctx.who); });
  srv.route('POST', '/mail-reputation/key', (ctx) => {
    ctx.need('admin');   // a security-integration credential
    const b = body(ctx.body).bool('clear').str('key', { max: 40, re: M.KEY_RE, msg: 'key must be the Spamhaus DQS key (lowercase letters and digits)' })
      .rule((o) => (!o.clear && !o.key ? 'key is required (or clear: true)' : null)).done();
    return M.setKey(b, ctx.who);
  });
}

module.exports = { createMailReputation, registerMailReputationRoutes };
