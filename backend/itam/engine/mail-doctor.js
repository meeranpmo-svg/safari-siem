// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Mail route troubleshooter (Email Route Map → Troubleshoot): an agent that works through the mail path the way an engineer
 * would, step by step, instead of showing a red box. For every mail domain it
 *   1. asks three public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9 - what senders and MX Toolbox see) AND the platform server's own
 *      DNS for MX, SPF and DMARC, separately, and compares them with what the platform last stored;
 *   2. when public DNS has a record the platform reported missing, it re-checks the domain itself (read-only), refreshes the
 *      route and says why the earlier answer was wrong (split internal DNS, a resolver that does not forward, a timeout);
 *   3. only when public DNS itself has no record does it call the record missing - with the record to publish;
 *   4. follows the path: MX hosts resolve, egress IPs (it PROPOSES them from SPF ip4 entries and the MX addresses - a person
 *      registers them), the Libraesva gateway (its own step-by-step diagnosis), Exchange (message tracking in the SIEM: is there
 *      an Exchange source, is it sending, do message-tracking events arrive - the counts come from the page's own SIEM query).
 * What it does by itself is read-only: DNS lookups, the Domains & Hosting check and the route refresh. Anything that changes the
 * platform's configuration (add a domain, register an egress IP) is offered as an action a person clicks, with the role it
 * needs; nothing outside the platform (DNS, gateway, Exchange) is ever changed. It runs on demand and once an hour by itself
 * while the route shows a failure. Every run and every action is audited.
 *   GET  /mail-route/troubleshoot            viewer    the last run (public DNS facts, no personal data)
 *   POST /mail-route/troubleshoot            operator  run now                                               audited
 *   POST /mail-route/troubleshoot/action     {action: recheck | add-domain | register-egress, domain?, ip?}  role per action, audited
 */
const dns = require('node:dns');
const IP = require('./discovery/ipv4');
const { guardOf } = require('./errors');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const NODATA = /ENODATA|ENOTFOUND|NXDOMAIN|ENONAME/;
const PUBLIC = [['Cloudflare', '1.1.1.1'], ['Google', '8.8.8.8'], ['Quad9', '9.9.9.9']];
const SYS = { user: 'system:mail-doctor', role: 'system', ip: '' };
const s = (v, max = 300) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);

function withTimeout(p, ms) { let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), ms); })]).finally(() => clearTimeout(t)); }
async function ask(res, fn, name) {
  try { return { ok: true, v: await withTimeout(res[fn](name), 6000) }; }
  catch (e) { const code = String(e.code || e.message); return NODATA.test(code) ? { ok: true, v: [] } : { ok: false, err: code.slice(0, 40) }; }
}
const mxList = (r) => (r.ok ? r.v.map((x) => x.priority + ' ' + String(x.exchange).toLowerCase().replace(/\.$/, '')).sort() : null);
const txtList = (r) => (r.ok ? r.v.map((x) => (Array.isArray(x) ? x.join('') : String(x))) : null);

function createMailDoctor(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now, iso = () => new Date(now()).toISOString();
  const col = () => store.collection('mail_doctor');
  const A = () => app.addons || {};
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const L = app.log || { every() {} };
  const pubCfg = (app.config && app.config.domains && app.config.domains.public_resolvers) || null;
  const resolvers = opts.resolvers || (() => {
    const list = (pubCfg ? pubCfg.map((ip) => [ip, ip]) : PUBLIC).map(([name, ip]) => { const r = new dns.promises.Resolver({ timeout: 3000, tries: 1 }); r.setServers([ip]); return { name: name + ' ' + ip, r }; });
    return { pub: list, server: dns.promises };
  })();

  async function lookAll(fn, name) {
    const pub = await Promise.all(resolvers.pub.map(async (x) => Object.assign({ who: x.name }, await ask(x.r, fn, name))));
    const server = Object.assign({ who: 'this server\'s DNS' }, await ask(resolvers.server, fn, name));
    return { pub, server };
  }
  // the public answer: the first resolver that answered; unreachable when none did
  const pubAnswer = (x) => x.pub.find((p) => p.ok) || null;

  async function verifyDomain(d, stored) {
    const out = { domain: d.name };
    const mx = await lookAll('resolveMx', d.name), txt = await lookAll('resolveTxt', d.name), dm = await lookAll('resolveTxt', '_dmarc.' + d.name);
    const pm = pubAnswer(mx), pt = pubAnswer(txt), pd = pubAnswer(dm);
    out.public_reachable = !!(pm || pt);
    out.mx = { public: pm ? mxList(pm) : null, server: mxList(mx.server), server_err: mx.server.ok ? null : mx.server.err, stored: stored.MX || null, answered_by: pm ? pm.who : null,
      resolvers: mx.pub.map((p) => ({ who: p.who, ok: p.ok, records: p.ok ? mxList(p).length : null, err: p.err || null })) };
    const spfOf = (r) => (r ? txtList(r).filter((x) => /^v=spf1(\s|$)/i.test(x)) : null);
    out.spf = { public: spfOf(pt), server: txt.server.ok ? spfOf(txt.server) : null, server_err: txt.server.ok ? null : txt.server.err, stored: stored.SPF || null };
    out.dmarc = { public: pd ? txtList(pd).filter((x) => /^v=DMARC1/i.test(x)) : null, stored: stored.DMARC || null };
    return out;
  }

  let running = null;
  // the SIEM's collection health, through the platform's SIEM link (read-only, as an analyst)
  async function siemHealth() {
    if (opts.siemHealth) return opts.siemHealth();
    const Lk = app.discovery && app.discovery.siem; if (!Lk || typeof Lk.call !== 'function') return { _down: 'the SIEM link is not configured on this server' };
    try { const r = await Lk.call('GET', '/collection/health', { user: 'system:mail-doctor', role: 'analyst' }); return r && r.status === 200 && r.json ? r.json : { _down: 'SIEM /collection/health: HTTP ' + (r && r.status) }; }
    catch (e) { return { _down: 'the SIEM did not answer (' + s(e.message, 120) + ')' }; }
  }
  const EXCH_FIX = 'On EACH Exchange server (elevated PowerShell), with the SIEM package copied to C:\\temp\\ash: (1) on the SIEM get the token: sudo sentra-siem-token show win-exchange; (2) cd C:\\temp\\sentra\\agents\\exchange; .\\install-exchange-shipper.ps1 -CollectorUrl https://<SIEM collector> -SourceId win-exchange -TokenFile C:\\temp\\sentra\\win-exchange.token (never put the token on the command line); (3) outbound TCP 443 from the Exchange server to the collector. Details: agents/exchange/INSTALL-EXCHANGE.txt.';
  async function exchangeStep(add, siemFacts) {
    const ex = siemFacts && siemFacts.exchange;
    const tot = ex ? Object.values(ex).reduce((a, b) => a + (Number(b) || 0), 0) : 0;
    if (tot) return add({ id: 'exchange', title: 'Exchange (message tracking)', status: (ex.receive || 0) && (ex.send || 0) ? 'ok' : 'warn',
      detail: 'Message tracking reaches the SIEM: receive ' + (ex.receive || 0) + ', deliver ' + (ex.deliver || 0) + ', send ' + (ex.send || 0) + ', fail ' + (ex.fail || 0) + '.',
      fix: (ex.receive || 0) && (ex.send || 0) ? '' : 'One direction has no events in the period: check the shipper runs on every Exchange server (mailbox and edge), not only one.' });
    const h = await siemHealth();
    const counted = siemFacts ? ' The SIEM holds no Exchange message-tracking events in the period shown on the map' : '';
    if (h._down) return add({ id: 'exchange', title: 'Exchange (message tracking)', status: 'warn', detail: 'The SIEM could not be asked which sources send (' + h._down + ').' + counted + '.', fix: 'If the Exchange boxes stay "not connected": ' + EXCH_FIX });
    const srcs = (h.sources || []).filter((x) => x.type === 'exchange' || /exchange/i.test([x.src_id, x.kind, x.label].join(' ')));
    if (!srcs.length) return add({ id: 'exchange', title: 'Exchange (message tracking)', status: 'fail',
      detail: 'There is no Exchange log source in the SIEM, so the Exchange receive / send / mailbox boxes stay "not connected". Mail may be flowing fine - the platform simply cannot see it.',
      evidence: ['SIEM sources: ' + ((h.sources || []).length ? (h.sources || []).slice(0, 12).map((x) => x.src_id).join(', ') : 'none')], fix: EXCH_FIX });
    const recv = srcs.filter((x) => x.state === 'receiving');
    const ev = srcs.map((x) => x.src_id + ': ' + x.state + (x.last_seen ? ', last event ' + new Date(x.last_seen).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : ', never') + (x.events_24h != null ? ', ' + x.events_24h + ' events in 24 h' : ''));
    if (!recv.length) return add({ id: 'exchange', title: 'Exchange (message tracking)', status: 'fail', detail: 'The Exchange source is registered in the SIEM but is not sending.', evidence: ev,
      fix: 'On each Exchange server: schtasks /Query /TN SentraExchangeShipper (Ready / Running?), then Get-Content C:\\ProgramData\\SentraExchangeShipper\\logs\\*.log -Tail 20 - it names the failure (TLS trust of the collector certificate, token refused, no route to port 443). Message tracking must be on: Get-TransportService | fl Name,MessageTrackingLogEnabled.' });
    return add({ id: 'exchange', title: 'Exchange (message tracking)', status: 'warn', detail: 'The Exchange source sends events, but none of them are message tracking.' + counted + ' - only the Windows agent (admin audit) is probably installed.', evidence: ev,
      fix: 'Install Part 2, the Exchange file shipper, on each Exchange server (same source id and token): ' + EXCH_FIX });
  }

  // top values of a field in the SIEM (24 h), through the platform's SIEM link as an analyst; null = not readable
  async function siemTop(q, field) {
    if (opts.siemTop) return opts.siemTop(q, field);
    const Lk = app.discovery && app.discovery.siem; if (!Lk || typeof Lk.call !== 'function') return null;
    try { const r = await Lk.call('POST', '/top', { user: 'system:mail-doctor', role: 'analyst' }, { q, from: 'now-24h', to: 'now', field, limit: 10 }); return r && r.status === 200 && r.json ? (r.json.values || []) : null; }
    catch (e) { return null; /* SIEM not reachable: the step says firewall logs could not be read */ }
  }

  async function run(who, auto, siemFacts) {
    if (running) return running;
    running = (async () => {
      const steps = [], add = (st) => { steps.push(Object.assign({ evidence: [], actions: [], fix: '' }, st)); return st; };
      const D = A().domains, MR = A().mailReputation, ES = A().libraesva;
      const doms = store.collection('dom_domains').all((d) => d.status !== 'retired');
      const checks = store.collection('dom_checks');
      // ---- 1. which domains carry mail
      if (!doms.length) {
        add({ id: 'domains', title: 'Mail domains', status: 'fail', detail: 'No domain is registered in Domains & Hosting, so nothing about MX, SPF or DMARC can be checked.',
          fix: ('Add the company mail domain (e.g. ' + ZYB_ORG.domain + ') - an admin can do it from here.'), actions: [{ action: 'add-domain', label: 'Add a mail domain', role: 'admin', needs: 'domain' }] });
      } else add({ id: 'domains', title: 'Mail domains', status: 'ok', detail: doms.map((d) => d.name).join(', ') });
      // ---- 2. DNS: public resolvers vs this server vs what the platform stored; re-check by itself when the platform was wrong
      let rechecked = 0, publicDown = false;
      for (const d of doms) {
        const before = (checks.get('d:' + d.id) || {}).records || {};
        let v = await verifyDomain(d, before);
        const storedSaysNoMx = !(before.MX && before.MX.length), storedSaysNoSpf = !(before.SPF && before.SPF.length);
        const wrongMx = v.mx.public && v.mx.public.length && storedSaysNoMx, wrongSpf = v.spf.public && v.spf.public.length && storedSaysNoSpf;
        if ((wrongMx || wrongSpf || !before.MX || !auto) && D) {
          try { await D.checkOne('domain', d); rechecked++; v = await verifyDomain(d, (checks.get('d:' + d.id) || {}).records || {}); }
          catch (e) { L.every('maildoctor:recheck', 3600000, 'warn', 'mail doctor: domain re-check failed', { domain: d.name, err: s(e.message, 160) }); }
        }
        if (!v.public_reachable) publicDown = true;
        const why = (field) => {
          const x = v[field], srvTxt = x.server_err ? 'failed (' + x.server_err + ')' : x.server && x.server.length ? 'answers ' + x.server.join(' | ') : 'answers with NO record';
          return 'This server\'s DNS ' + srvTxt + (x.server && x.server.length ? '' : ' - typically the internal AD DNS holding its own copy of ' + d.name + ' (split DNS) or not forwarding to the internet');
        };
        // MX
        if (v.mx.public && v.mx.public.length) {
          const fixedNow = wrongMx && rechecked;
          add({ id: 'mx:' + d.name, title: 'MX record - ' + d.name, status: fixedNow ? 'fixed' : 'ok', detail: (fixedNow ? 'The platform had reported no MX. Public DNS has it, so the domain was re-checked and the map now uses it: ' : 'Public DNS: ') + v.mx.public.join(', '),
            evidence: v.mx.resolvers.map((r) => r.who + ': ' + (r.ok ? r.records + ' MX' : 'no answer (' + r.err + ')')).concat([why('mx')]),
            fix: fixedNow ? 'Nothing to change at the DNS provider. The earlier error came from the platform server\'s DNS view; checks now use public DNS first.' : '' });
        } else if (v.mx.public) {
          add({ id: 'mx:' + d.name, title: 'MX record - ' + d.name, status: 'fail', detail: 'Public DNS (' + v.mx.answered_by + ') has no MX record for ' + d.name + ': mail from the internet cannot be delivered.',
            evidence: v.mx.resolvers.map((r) => r.who + ': ' + (r.ok ? r.records + ' MX' : 'no answer (' + r.err + ')')),
            fix: 'At the DNS provider publish an MX record pointing to the email gateway, e.g. "' + d.name + '. MX 10 <gateway public host name>." - then Troubleshoot again.' });
        } else {
          add({ id: 'mx:' + d.name, title: 'MX record - ' + d.name, status: v.mx.server && v.mx.server.length ? 'warn' : 'fail',
            detail: 'Public DNS could not be reached from the platform server, so the MX record cannot be verified as the internet sees it.' + (v.mx.server && v.mx.server.length ? ' This server\'s DNS answers ' + v.mx.server.join(', ') + '.' : ''),
            evidence: v.mx.resolvers.map((r) => r.who + ': no answer (' + r.err + ')').concat([why('mx')]),
            fix: 'Allow outbound DNS (UDP and TCP 53) from the platform server to 1.1.1.1 / 8.8.8.8 / 9.9.9.9 (or set domains.public_resolvers in /etc/sentra-itam/config.json to resolvers it may reach). Meanwhile, compare with MX Toolbox.' });
        }
        // SPF
        if (v.spf.public && v.spf.public.length === 1) add({ id: 'spf:' + d.name, title: 'SPF - ' + d.name, status: wrongSpf && rechecked ? 'fixed' : 'ok', detail: v.spf.public[0], evidence: [why('spf')] });
        else if (v.spf.public && v.spf.public.length > 1) add({ id: 'spf:' + d.name, title: 'SPF - ' + d.name, status: 'fail', detail: v.spf.public.length + ' SPF records in public DNS - receivers treat that as an SPF error.', evidence: v.spf.public, fix: 'Merge them into one v=spf1 record.' });
        else if (v.spf.public) add({ id: 'spf:' + d.name, title: 'SPF - ' + d.name, status: 'fail', detail: 'Public DNS has no SPF record for ' + d.name + '.', fix: 'Publish one TXT record "v=spf1 ip4:<egress IP> include:<other senders> -all".' });
        else add({ id: 'spf:' + d.name, title: 'SPF - ' + d.name, status: 'warn', detail: 'Not verifiable: public DNS unreachable from the platform server.', evidence: [why('spf')] });
        // DMARC
        if (v.dmarc.public && v.dmarc.public.length) add({ id: 'dmarc:' + d.name, title: 'DMARC - ' + d.name, status: /p=(quarantine|reject)/i.test(v.dmarc.public[0]) ? 'ok' : 'warn', detail: v.dmarc.public[0], fix: /p=none/i.test(v.dmarc.public[0]) ? 'Move to p=quarantine, then p=reject, once the reports show every sender passing.' : '' });
        else if (v.dmarc.public) add({ id: 'dmarc:' + d.name, title: 'DMARC - ' + d.name, status: 'warn', detail: 'No DMARC record in public DNS.', fix: 'Publish "_dmarc.' + d.name + '. TXT v=DMARC1; p=none; rua=mailto:dmarc@' + d.name + '" and tighten it later.' });
        d._v = v;
      }
      // ---- 3. refresh the route with what was learnt (read-only)
      if (MR && (rechecked || !auto)) { try { await MR.check(who); } catch (e) { L.every('maildoctor:route', 3600000, 'warn', 'mail doctor: route refresh failed', { err: s(e.message, 160) }); } }
      // ---- 4. MX hosts and egress, from the refreshed route
      const route = MR ? await MR.routeView(null).catch(() => null) : null;
      const last = (store.collection('mailrep').get('last') || {}).route || { domains: [] };
      const mxHosts = []; for (const d of last.domains || []) for (const m of d.mx || []) mxHosts.push(m);
      if (mxHosts.length) {
        const noAddr = mxHosts.filter((m) => !(m.ips && m.ips.length)), noSmtp = mxHosts.filter((m) => m.ips && m.ips.length && m.smtp && !m.smtp.connected);
        add({ id: 'mxhosts', title: 'MX hosts answer', status: noAddr.length || noSmtp.length === mxHosts.length ? 'fail' : noSmtp.length ? 'warn' : 'ok',
          detail: mxHosts.map((m) => m.host + ' → ' + ((m.ips || []).join(', ') || 'no address') + (m.smtp ? (m.smtp.connected ? ' (SMTP answers)' : ' (no SMTP answer)') : '')).join('; '),
          fix: noAddr.length ? 'Publish an A record for ' + noAddr.map((m) => m.host).join(', ') + '.' : noSmtp.length ? 'Port 25 did not answer from the platform server for ' + noSmtp.map((m) => m.host).join(', ') + ': check the firewall NAT to the gateway (the platform probes from inside, so a hairpin-NAT block can also cause this).' : '' });
      } else if (doms.length && !publicDown) add({ id: 'mxhosts', title: 'MX hosts answer', status: 'info', detail: 'No MX host in the route yet - it fills in after the MX step above passes and the route is refreshed.' });
      const registered = MR ? MR.view().registered.filter((x) => x.role !== 'inbound') : [];
      if (registered.length) add({ id: 'egress', title: 'Egress IP (where mail leaves from)', status: 'ok', detail: registered.map((x) => x.ip + (x.label ? ' (' + x.label + ')' : '')).join(', ') });
      else {
        // evidence, strongest first: (1) the firewalls' own logs - outbound SMTP (port 25) sessions and the public NAT address
        // they left through; (2) the whole SPF tree (ip4, a, mx at every level, not the cloud providers' includes); (3) MX addresses
        const cand = new Map(), note = (ip, why, w) => { if (IP.parseIp(ip) === null || IP.isPrivate(ip)) return; const c = cand.get(ip) || { why: [], w: 0 }; c.why.push(why); c.w += w; cand.set(ip, c); };
        let fwNote = null;
        for (const f of ['fields.natsrc', 'fields.transip', 'fields.src_nat']) {
          const vals = await siemTop('dst_port:25', f);
          if (vals === null) { fwNote = fwNote || 'firewall logs could not be read from the SIEM'; continue; }
          for (const v of vals) note(String(v.v), Math.round(v.n) + ' outbound SMTP session(s) (port 25) left through this NAT address in 24 h - firewall logs', 1000 + v.n);
        }
        const PROVIDER = /protection\.outlook\.com|_spf\.google\.com|google\.com$|amazonses|sendgrid|mailgun|mimecast|pphosted|messagelabs|zoho|mailchimp|mcsv\.net|sparkpost|mandrillapp/i;
        const walk = (node, dom, depth) => {
          if (!node || depth > 10) return;
          for (const tok of String(node.record || '').split(/\s+/)) { const m = /^\+?ip4:([\d.]+)$/i.exec(tok); if (m) note(m[1], 'ip4 in the SPF record of ' + (node.domain || dom), depth ? 50 : 100); }
          for (const ip of node.a_ips || []) note(ip, '"a" mechanism in the SPF record of ' + (node.domain || dom), 60);
          for (const ip of node.mx_ips || []) note(ip, '"mx" mechanism in the SPF record of ' + (node.domain || dom), 60);
          for (const [k, ch] of Object.entries(node.children || {})) if (!PROVIDER.test(k)) walk(ch, dom, depth + 1);
        };
        for (const d of last.domains || []) walk(d.spf, d.name, 0);
        for (const d of doms) for (const rec of (d._v && d._v.spf.public) || []) walk({ domain: d.name, record: rec }, d.name, 0);
        for (const m of mxHosts) for (const ip of m.ips || []) note(ip, 'address of MX ' + m.host + ' (an on-premises gateway usually sends from it too)', 20);
        const list = [...cand].sort((a, b) => b[1].w - a[1].w);
        const fw = list.filter(([, c]) => c.w >= 1000);
        add({ id: 'egress', title: 'Egress IP (where mail leaves from)', status: 'warn',
          detail: !list.length ? 'None registered, and none could be found in the firewall logs, the SPF record or the MX addresses.'
            : fw.length ? 'None registered. The firewall logs show outbound mail leaving through ' + fw.map(([ip]) => ip).join(', ') + ' - register it (that is the address receivers see).'
            : 'None registered. Found ' + list.length + ' likely address(es) - confirm the one(s) mail actually leaves from:',
          evidence: list.map(([ip, c]) => ip + ' - ' + [...new Set(c.why)].join('; ')).concat(fwNote ? ['(' + fwNote + ')'] : []),
          fix: !list.length ? 'Register the public IP the gateway sends from (Email Route Map → Egress IP box → setup, or the reputation card). To find it: on the gateway, send a test mail to an outside mailbox and read the first "Received:" header, or check the firewall NAT rule for port 25.'
            : 'Register the public IP the gateway sends from: reverse DNS, SPF and Spamhaus are then checked for it.',
          actions: list.slice(0, 6).map(([ip]) => ({ action: 'register-egress', label: 'Register ' + ip, role: 'operator', ip })) });
      }
      // ---- Internet links: drawn from the public /24 of the MX and egress addresses, so an empty link has a reason upstream
      const topo = route && route.topology;
      if (topo && (topo.links || []).length) {
        const unused = topo.links.filter((l) => l.state === 'unused');
        const privMx = mxHosts.filter((m) => (m.ips || []).length && m.ips.every((ip) => IP.isPrivate(ip)));
        const insideOnly = mxHosts.filter((m) => (m.inside_ips || []).length);
        if (!unused.length) add({ id: 'links', title: 'Internet links', status: 'ok', detail: topo.links.map((l) => 'link ' + l.n + ' (' + l.network + '): ' + l.state).join('; ') });
        else {
          const why = [];
          if (!mxHosts.length) why.push('no MX host is known yet (see the MX step above)');
          if (privMx.length) why.push('MX ' + privMx.map((m) => m.host + ' → ' + m.ips.join(', ')).join('; ') + ' resolves to an INTERNAL address - public DNS could not be asked, so this server\'s split DNS answered');
          if (!registered.length) why.push('no egress IP is registered (see the Egress step above)');
          if (!why.length && topo.declared_links > (topo.links || []).filter((l) => l.state !== 'unused').length) why.push('the route profile declares ' + topo.declared_links + ' links but every MX and egress address is on ' + (topo.links.length - unused.length) + ' public network(s)');
          add({ id: 'links', title: 'Internet links', status: 'warn', detail: unused.map((l) => 'link ' + l.n).join(', ') + ' shows unused: no public MX or egress address sits on it. Links are told apart by the public /24 of those addresses - the platform does not see the ISP itself.',
            evidence: why.concat(insideOnly.map((m) => m.host + ' answers internally as ' + m.inside_ips.join(', ') + ' (NAT inside address)')),
            fix: !mxHosts.length || !registered.length ? 'Nothing to do on the link itself: it fills in once the MX and Egress steps above pass.' : privMx.length ? 'Allow outbound DNS from the platform server to public resolvers so MX addresses are read as the internet sees them.' : 'If there really are two ISP links, put an MX (and ideally an egress) address on the second one; otherwise set the number of Internet links to 1 in Route settings.' });
        }
      }
      // ---- 5. the gateway
      if (ES) {
        let dg = null; try { dg = await ES.diagnose(who); } catch (e) { dg = { steps: [{ step: 'Libraesva', status: 'fail', detail: s(e.message), fix: '' }] }; }
        const f = (dg.steps || []).find((x) => x.status === 'fail');
        if (!f) add({ id: 'gateway', title: 'Libraesva ESG', status: 'ok', detail: 'All ' + (dg.steps || []).length + ' checks passed.' });
        else if (f.step === 'Connection settings') add({ id: 'gateway', title: 'Libraesva ESG', status: 'info', detail: 'Not connected: the gateway boxes stay grey (inbound / outbound). Mail itself is not affected.', fix: 'Connections & Setup → Libraesva ESG: the gateway address, an ESG API user (System → Users → API Users) and the read-only ESG user it acts as.' });
        else add({ id: 'gateway', title: 'Libraesva ESG', status: 'fail', detail: 'Stopped at "' + f.step + '": ' + f.detail, fix: f.fix, evidence: (dg.steps || []).map((x) => x.status + ' ' + x.step) });
      }
      // ---- 6. Exchange
      await exchangeStep(add, siemFacts || null);
      // ---- 7. what the route rules still report, so nothing on the map is left unexplained
      const left = route && route.issues ? route.issues.filter((i) => i.severity === 'high' && !/MX|SPF|Exchange/.test(i.title)).slice(0, 5) : [];
      for (const i of left) add({ id: 'route:' + i.title.slice(0, 40), title: 'Route: ' + i.title, status: 'fail', detail: (i.evidence || []).join('; '), fix: (i.fix || []).join(' ') });
      const bad = steps.filter((x) => x.status === 'fail').length;
      const res = { id: 'last', at: iso(), by: who.user, auto: !!auto, ok: !bad, counts: { fail: bad, warn: steps.filter((x) => x.status === 'warn').length, fixed: steps.filter((x) => x.status === 'fixed').length },
        rechecked, steps, note: 'Read-only by itself: DNS lookups, the Domains & Hosting check and the route refresh. Buttons change only the platform\'s own configuration; DNS, the gateway and Exchange are changed by your team.' };
      col().put(res);
      audit(who, 'mail.doctor.run', 'mail-route', { auto: !!auto, fail: res.counts.fail, fixed: res.counts.fixed, rechecked });
      return res;
    })();
    try { return await running; } finally { running = null; }
  }
  function last() { return col().get('last') || null; }
  async function action(b, who) {
    if (/^(duty|system|ai|svc|service)[:_-]/i.test(String(who.user || ''))) throw httpErr(403, 'a person runs troubleshooter actions, not a service identity');
    const D = A().domains, MR = A().mailReputation;
    if (b.action === 'recheck') return run(who, false);
    if (b.action === 'add-domain') {
      if (who.role !== 'admin') throw httpErr(403, 'adding a domain needs an administrator');
      if (!D) throw httpErr(409, 'Domains & Hosting is not installed');
      const rec = D.putDomain({ name: b.domain }, who);
      audit(who, 'mail.doctor.add-domain', rec.id, { domain: rec.name });
      return run(who, false);
    }
    if (b.action === 'register-egress') {
      if (!MR) throw httpErr(409, 'mail reputation is not installed');
      const lr = last(), offered = lr && lr.steps.some((x) => x.id === 'egress' && x.actions.some((a) => a.ip === b.ip));
      if (!offered) throw httpErr(409, b.ip + ' was not proposed by the last troubleshooting run - register other addresses on the reputation card');
      const rec = MR.addIp({ ip: b.ip, label: 'egress (confirmed from the troubleshooter)', role: 'outbound' }, who);
      audit(who, 'mail.doctor.register-egress', rec.id, { ip: b.ip });
      return run(who, false);
    }
    throw httpErr(400, 'action must be one of: recheck, add-domain, register-egress');
  }
  // by itself once an hour while the route shows a failure (read-only steps only; actions always wait for a person)
  let timer = null;
  async function tick() {
    const MR = A().mailReputation; if (!MR) return;
    const r = await MR.routeView(null).catch(() => null);
    if (r && (r.issues || []).some((i) => i.severity === 'high')) await run(SYS, true);
  }
  function start() { if (opts.noTimer || timer) return; timer = setInterval(guardOf(app, 'maildoctor.tick', tick), opts.everyMs || 3600000); if (timer.unref) timer.unref(); }
  return { run, last, action, tick, start };
}

function registerMailDoctorRoutes(srv, app, M) {
  const { body } = require('./check');
  srv.route('GET', '/mail-route/troubleshoot', (ctx) => { ctx.need('viewer'); return { last: M.last() }; });   // public DNS facts and host names, no personal data
  srv.route('POST', '/mail-route/troubleshoot', async (ctx) => {
    ctx.need('operator');
    // the page passes the SIEM counts it already read (as the signed-in analyst): numbers only, each one checked
    const raw = (ctx.body && ctx.body.siem && typeof ctx.body.siem === 'object' && ctx.body.siem.exchange && typeof ctx.body.siem.exchange === 'object') ? ctx.body.siem.exchange : null;
    let ex = null;
    if (raw) { ex = {}; for (const k of ['receive', 'send', 'deliver', 'fail', 'defer', 'dsn', 'submit']) if (raw[k] != null) { const n = Number(raw[k]); if (!Number.isInteger(n) || n < 0 || n > 1e12) throw httpErr(400, 'siem.exchange.' + k + ' must be a whole number'); ex[k] = n; } }
    const given = !!(ctx.body && ctx.body.siem);
    return M.run(ctx.who, false, given ? { exchange: ex } : null);
  });
  srv.route('POST', '/mail-route/troubleshoot/action', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).oneOf('action', ['recheck', 'add-domain', 'register-egress'], { required: true })
      .str('domain', { max: 253, re: /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i, msg: ('domain must be a domain name (e.g. ' + ZYB_ORG.domain + ')') }).str('ip', { ip: true })
      .rule((o) => (o.action === 'add-domain' && !o.domain ? 'domain is required to add a domain' : o.action === 'register-egress' && !o.ip ? 'ip is required to register an egress IP' : null)).done();
    return M.action(b, ctx.who);
  });
}

module.exports = { createMailDoctor, registerMailDoctorRoutes };
