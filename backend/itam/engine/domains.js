// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { guardOf } = require('./errors');
// External domains & DNS — every the organisation internet domain and public hostname in one register, checked from public DNS:
//   Domains    registrar, owner, renewal date (warned 90 / 30 / 7 days ahead; auto-renew softens, never hides it), DNS provider,
//              expected nameservers. Checked: NS, MX, SPF, DMARC, DKIM (the selectors recorded), CAA - each finding says why it
//              matters and what to publish. A record set that changed since the last check is listed (who changed DNS?).
//   Hostnames  portal, claims, mail, VPN …: where each is hosted (provider, in the Kingdom or not - PDPL Art. 29), linked to the
//              asset register (an explicit asset, or one whose management IP the name resolves to - shown as "matched by IP").
//              Checked: resolves, and the TLS certificate on the port (expiry, name match, trusted chain).
// Read-only: DNS lookups and a TLS handshake; nothing at a registrar or DNS provider is changed from here.
//
//   GET  /domains                         {settings, domains[], hosts[], summary}           any role (cost: operator+)
//   GET  /domains/history?id=d:<id>|h:<id> the last changes seen for one domain / hostname   any role
//   POST /domains                         {id?, name, registrar, owner, expires, auto_renew, dns_provider, expected_ns[],
//                                          dkim_selectors[], cost, currency, notes}           admin
//   POST /domains/:id/retire              {reason}                                           admin
//   POST /domains/hosts                   {id?, fqdn, purpose, hosting, location: ksa|outside|unknown, asset_id, port, tls}  admin
//   POST /domains/hosts/:id/retire        {reason}                                           admin
//   POST /domains/check                   {id?}  check now (all, or one d:<id> / h:<id>)     operator
//   POST /domains/brand-sync              push the register to Brand Protection now           admin
// Brand Protection (portal twin service, /api/brand) is kept in step with this register: its official domains are the
// register's domains (it watches look-alikes of exactly these), and a look-alike it found that is one of ours is marked
// owned. A domain Brand Protection calls owned but the register does not hold is listed here to be added - never added
// by itself. A hostname on a server in the asset register is hosted at the organisation (in the Kingdom): no hosting entry needed.
// Every write is audited (domains.*). Checked every 6 hours. Added with one registration line (install/add-domains.sh).
const crypto = require('node:crypto');
const dnsP = require('node:dns').promises;
const tls = require('node:tls');

const DAY = 86400000;
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const FQDN = /^(?=.{3,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const fqdn = (v, what) => { const t = s(v, 253).toLowerCase().replace(/\.$/, ''); if (!FQDN.test(t)) throw bad(`${what || 'name'} must be a domain name like example.com.sa: ${t || '(empty)'}`); return t; };
const isoDate = (v) => { const t = s(v, 30); if (!t) return null; if (!/^\d{4}-\d{2}-\d{2}$/.test(t) || isNaN(Date.parse(t))) throw bad('dates must be YYYY-MM-DD: ' + t); return t; };
const list = (v, fn, max) => (Array.isArray(v) ? v : String(v || '').split(/[\s,;]+/)).map((x) => s(x, 253)).filter(Boolean).slice(0, max || 20).map(fn);
const PROVIDERS = { cloudflare: 'Cloudflare', godaddy: 'GoDaddy', azure: 'Azure DNS', registrar: 'Registrar DNS', other: 'Other' };
const LOCATIONS = { onprem: (ZYB_ORG.short + ' data centre (in the Kingdom)'), ksa: 'In the Kingdom (provider)', outside: 'Outside the Kingdom', unknown: 'Not recorded' };
const ONPREM = (ZYB_ORG.short + ' data centre');
const BRAND_MAX = 10;   // Brand Protection watches at most 10 official domains
const RANK = { bad: 0, warn: 1, info: 2, ok: 3 };
const NODATA = /ENODATA|ENOTFOUND|NXDOMAIN|ENONAME/;

function createDomains(app, o = {}) {
  const store = app.store;
  const dcol = store.collection('dom_domains'), hcol = store.collection('dom_hosts'), ccol = store.collection('dom_checks'), hist = store.collection('dom_history');
  const assets = store.collection('assets');
  const now = () => (app.now ? app.now() : Date.now());
  const audit = (e) => { if (app.audit) app.audit(e); };
  const R = o.resolver || dnsP;                 // tests inject a resolver; production uses the system's DNS
  // public DNS first: these checks are about what the internet sees (MX Toolbox does the same). The server's own resolver is
  // often the internal AD DNS - a split zone for the company's own domain (no MX, internal NS) or no forwarding at all - so it is
  // used only when public DNS cannot be reached from the server (outbound DNS blocked), and the finding says which one answered.
  const pubServers = (app.config && app.config.domains && app.config.domains.public_resolvers) || ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
  const RP = o.publicResolver !== undefined ? o.publicResolver : o.resolver ? null : (() => { const r = new dnsP.Resolver({ timeout: 4000, tries: 1 }); r.setServers(pubServers); return r; })();
  const tlsPeek = o.tlsPeek || peek;
  const by = (who) => ({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '' });

  // ---- register
  function putDomain(b, who) {
    const name = fqdn(b.name, 'domain');
    const prev = b.id ? dcol.get(s(b.id, 40)) : dcol.all((d) => d.name === name && d.status !== 'retired')[0];
    if (b.id && !prev) throw bad('domain not found', 404);
    if (dcol.all((d) => d.name === name && d.status !== 'retired' && (!prev || d.id !== prev.id)).length) throw bad(name + ' is already in the register');
    const prov = s(b.dns_provider, 20) || 'other'; if (!PROVIDERS[prov]) throw bad('dns_provider must be one of ' + Object.keys(PROVIDERS).join(', '));
    const cost = b.cost === '' || b.cost == null ? null : Number(b.cost); if (cost != null && !(cost >= 0)) throw bad('cost must be a number');
    const rec = Object.assign({}, prev || { id: 'dom_' + crypto.randomBytes(5).toString('hex'), created_at: now(), created_by: (who && who.user) || '' }, {
      name, registrar: s(b.registrar, 120), owner: s(b.owner, 120), expires: isoDate(b.expires), auto_renew: !!b.auto_renew, dns_provider: prov,
      expected_ns: list(b.expected_ns, (x) => fqdn(x, 'nameserver'), 13), dkim_selectors: list(b.dkim_selectors, (x) => { if (!/^[a-z0-9][a-z0-9._-]{0,62}$/i.test(x)) throw bad('DKIM selector not valid: ' + x); return x.toLowerCase(); }, 10),
      cost, currency: s(b.currency, 8) || 'SAR', notes: s(b.notes, 1000), status: 'active', updated_at: now(), updated_by: (who && who.user) || '' });
    dcol.put(rec); audit(Object.assign(by(who), { action: prev ? 'domains.update' : 'domains.create', target: rec.id, detail: { name, expires: rec.expires, provider: prov } }));
    return rec;
  }
  function putHost(b, who) {
    const name = fqdn(b.fqdn, 'hostname');
    const prev = b.id ? hcol.get(s(b.id, 40)) : null; if (b.id && !prev) throw bad('hostname not found', 404);
    if (hcol.all((h) => h.fqdn === name && h.status !== 'retired' && (!prev || h.id !== prev.id)).length) throw bad(name + ' is already in the register');
    const aid0 = s(b.asset_id, 60);
    const loc = s(b.location, 10) || (aid0 ? 'onprem' : 'unknown'); if (!LOCATIONS[loc]) throw bad('location must be onprem, ksa, outside or unknown');
    const port = b.port == null || b.port === '' ? 443 : Number(b.port); if (!(Number.isInteger(port) && port > 0 && port < 65536)) throw bad('port must be 1-65535');
    const aid = s(b.asset_id, 60); if (aid && !assets.get(aid)) throw bad('asset not found: ' + aid);
    const dom = dcol.all((d) => d.status !== 'retired' && (name === d.name || name.endsWith('.' + d.name))).sort((x, y) => y.name.length - x.name.length)[0];
    const rec = Object.assign({}, prev || { id: 'host_' + crypto.randomBytes(5).toString('hex'), created_at: now(), created_by: (who && who.user) || '' }, {
      fqdn: name, domain_id: dom ? dom.id : null, purpose: s(b.purpose, 120), hosting: s(b.hosting, 120) || (loc === 'onprem' ? ONPREM : ''), location: loc, asset_id: aid || null, port, tls: b.tls !== false,
      notes: s(b.notes, 1000), status: 'active', updated_at: now(), updated_by: (who && who.user) || '' });
    hcol.put(rec); audit(Object.assign(by(who), { action: prev ? 'domains.host.update' : 'domains.host.create', target: rec.id, detail: { fqdn: name, hosting: rec.hosting, location: loc, asset: rec.asset_id } }));
    return rec;
  }
  function retire(colName, id, b, who) {
    const col = colName === 'host' ? hcol : dcol, rec = col.get(s(id, 40)); if (!rec) throw bad('not found', 404);
    const reason = s(b && b.reason, 300); if (!reason) throw bad('a reason is required');
    rec.status = 'retired'; rec.retired = { at: now(), by: (who && who.user) || '', reason }; col.put(rec);
    audit(Object.assign(by(who), { action: colName === 'host' ? 'domains.host.retire' : 'domains.retire', target: rec.id, detail: { name: rec.name || rec.fqdn, reason } }));
    return rec;
  }

  // ---- checks (read-only)
  async function look1(res, fn, name) {
    try { return { ok: true, v: await withTimeout(res[fn](name), 8000) }; } catch (e) { return NODATA.test(String(e.code || e.message)) ? { ok: true, v: [] } : { ok: false, err: String(e.code || e.message).slice(0, 80) }; }
  }
  let via = null;   // which resolver answered during this check: 'public' | 'server'
  async function look(fn, name) {
    if (RP) { const p = await look1(RP, fn, name); if (p.ok) { via = via || 'public'; return Object.assign(p, { via: 'public' }); }
      const sv = await look1(R, fn, name); via = 'server'; return Object.assign(sv, { via: 'server', public_err: p.err }); }
    return look1(R, fn, name);
  }
  const txtJoin = (rows) => (rows || []).map((r) => (Array.isArray(r) ? r.join('') : String(r)));
  async function checkDomain(d) {
    const F = [], rec = {};
    const add = (level, text, fix) => F.push({ level, text, fix: fix || '' });
    via = null;
    const ns = await look('resolveNs', d.name), mx = await look('resolveMx', d.name), txt = await look('resolveTxt', d.name), dm = await look('resolveTxt', '_dmarc.' + d.name), caa = await look('resolveCaa', d.name);
    rec.NS = ns.ok ? ns.v.map((x) => String(x).toLowerCase()).sort() : null;
    rec.MX = mx.ok ? mx.v.map((x) => x.priority + ' ' + String(x.exchange).toLowerCase()).sort() : null;
    rec.MX_error = mx.ok ? '' : mx.err + (mx.public_err ? ' from this server\'s DNS; public DNS ' + pubServers.join(' / ') + ' not reachable either (' + mx.public_err + ')' : '');
    rec.DNS_via = via || '';
    if (via === 'server') add('warn', 'Public DNS (' + pubServers.join(', ') + ') could not be reached from this server, so ' + d.name + ' was checked with the server\'s own DNS. That is often the internal AD DNS, which can answer differently from the internet (a split zone with no MX or internal nameservers).', 'Allow outbound DNS (UDP and TCP 53) from the platform server to ' + pubServers.join(' / ') + ', or set domains.public_resolvers in /etc/sentra-itam/config.json to resolvers it may reach. Compare with MX Toolbox for what the internet sees.');
    const t = txt.ok ? txtJoin(txt.v) : null, spf = t ? t.filter((x) => /^v=spf1(\s|$)/i.test(x)) : null;
    rec.SPF = spf; rec.DMARC = dm.ok ? txtJoin(dm.v).filter((x) => /^v=DMARC1/i.test(x)) : null;
    rec.CAA = caa.ok ? caa.v.map((x) => Object.keys(x).filter((k) => k !== 'critical').map((k) => k + ' ' + x[k]).join(' ')).sort() : null;
    if (!mx.ok) add('warn', 'MX could not be read (' + rec.MX_error + ') - this is the lookup from the platform server failing, not proof the record is missing.', 'If MX Toolbox shows the MX record, the domain is fine: fix DNS from the platform server (outbound DNS to public resolvers, or its resolver\'s forwarders).');
    if (!ns.ok) add('warn', 'Nameservers could not be read (' + ns.err + ') - DNS not checked this time.');
    else if (!rec.NS.length) add('bad', 'The domain has no nameservers in public DNS - it does not resolve (expired, suspended or not delegated?).', 'Check the registration at ' + (d.registrar || 'the registrar') + ' and the delegation.');
    else if (d.expected_ns.length) { const miss = d.expected_ns.filter((x) => !rec.NS.includes(x)), extra = rec.NS.filter((x) => !d.expected_ns.includes(x)); if (miss.length || extra.length) add('bad', 'Nameservers differ from the ones recorded: now ' + rec.NS.join(', ') + '.', 'If nobody approved this change, treat it as a possible domain hijack: lock the domain at the registrar and restore the nameservers.'); }
    const hasMx = rec.MX && rec.MX.length;
    if (rec.MX && !hasMx) add('info', 'No MX record: the domain receives no e-mail.', 'If it never sends mail either, publish "v=spf1 -all" and DMARC p=reject so nobody can send in its name.');
    if (spf) {
      if (!spf.length) add(hasMx ? 'bad' : 'warn', 'No SPF record: anyone can send e-mail claiming to be @' + d.name + '.', 'Publish one TXT record "v=spf1 include:<your mail service> -all" (Microsoft 365: include:spf.protection.outlook.com).');
      else if (spf.length > 1) add('bad', spf.length + ' SPF records: receivers treat that as an SPF error (permerror) - SPF is not working.', 'Merge them into a single v=spf1 record.');
      else if (/[+]all\b/i.test(spf[0])) add('bad', 'SPF ends with +all: every server in the world is allowed to send for this domain.', 'Change +all to -all.');
      else if (/\?all\b/i.test(spf[0])) add('warn', 'SPF ends with ?all (neutral): it protects nothing.', 'Change ?all to -all (or ~all while testing).');
      else if (/~all\b/i.test(spf[0])) add('info', 'SPF ends with ~all (soft fail).', 'Move to -all once DMARC reports show all legitimate senders pass.');
      else if (!/-all\b/i.test(spf[0]) && !/redirect=/i.test(spf[0])) add('warn', 'SPF has no "all" mechanism at the end.', 'End the record with -all.');
    }
    if (rec.DMARC) {
      if (!rec.DMARC.length) add(hasMx ? 'bad' : 'warn', 'No DMARC record: spoofed mail from @' + d.name + ' is not rejected, and nobody gets reports.', 'Publish TXT at _dmarc.' + d.name + ': "v=DMARC1; p=quarantine; rua=mailto:dmarc@' + d.name + '" and move to p=reject.');
      else { const p = (/;\s*p=([a-z]+)/i.exec(';' + rec.DMARC[0].replace(/^v=DMARC1/i, '')) || [])[1] || ''; if (/^none$/i.test(p)) add('warn', 'DMARC policy is p=none: spoofed mail is reported, not stopped.', 'Move to p=quarantine, then p=reject.'); else if (/^quarantine$/i.test(p)) add('info', 'DMARC policy is p=quarantine.', 'Move to p=reject when reports are clean.'); if (!/rua=/i.test(rec.DMARC[0])) add('info', 'DMARC has no rua= address: nobody receives the aggregate reports.', 'Add rua=mailto:<mailbox>.'); }
    }
    rec.DKIM = {};
    for (const sel of d.dkim_selectors) { const k = await look('resolveTxt', sel + '._domainkey.' + d.name); rec.DKIM[sel] = k.ok ? txtJoin(k.v).filter((x) => /p=/.test(x)).length > 0 : null; if (k.ok && !rec.DKIM[sel]) add('warn', 'DKIM selector "' + sel + '" has no public key in DNS: mail signed with it fails DKIM.', 'Publish the selector record your mail service gives (Microsoft 365: enable DKIM in Defender and publish the selector1/selector2 CNAMEs).'); }
    if (hasMx && !d.dkim_selectors.length) add('info', 'No DKIM selector recorded for this domain, so DKIM is not checked.', 'Record the selectors in the domain (Microsoft 365: selector1, selector2).');
    if (rec.CAA && !rec.CAA.length) add('info', 'No CAA record: any certificate authority may issue certificates for this domain.', 'Publish CAA records naming only the CAs you use.');
    if (d.expires) { const days = Math.floor((Date.parse(d.expires) - now()) / DAY), ar = d.auto_renew ? ' (auto-renew is on - confirm the payment card / account is valid)' : '';
      if (days < 0) add('bad', 'The registration expired on ' + d.expires + '.', 'Renew at ' + (d.registrar || 'the registrar') + ' now - an expired domain stops web and mail and can be bought by someone else.');
      else if (days <= 7) add('bad', 'The registration expires in ' + days + ' day(s) (' + d.expires + ')' + ar + '.', 'Renew now.');
      else if (days <= 30) add(d.auto_renew ? 'warn' : 'bad', 'The registration expires in ' + days + ' days (' + d.expires + ')' + ar + '.', 'Renew, or confirm auto-renew will succeed.');
      else if (days <= 90) add(d.auto_renew ? 'info' : 'warn', 'The registration expires in ' + days + ' days (' + d.expires + ')' + ar + '.', 'Plan the renewal.');
    } else add('warn', 'No renewal date recorded - expiry cannot be warned.', 'Enter the expiry date from the registrar.');
    return { rec, F };
  }
  async function checkHost(h) {
    const F = [], rec = {}; const add = (level, text, fix) => F.push({ level, text, fix: fix || '' });
    const a = await look('resolve4', h.fqdn), a6 = await look('resolve6', h.fqdn), cn = await look('resolveCname', h.fqdn);
    rec.A = a.ok ? a.v.slice().sort() : null; rec.AAAA = a6.ok ? a6.v.slice().sort() : null; rec.CNAME = cn.ok ? cn.v.map((x) => String(x).toLowerCase()) : null;
    let cert = null;
    if (!a.ok && !a6.ok) add('warn', 'The name could not be looked up (' + a.err + ').');
    else if (!(rec.A || []).length && !(rec.AAAA || []).length) add('bad', 'The hostname does not resolve in public DNS.', 'Check the record at the DNS provider, or retire the hostname here if it is no longer used.');
    else if (h.tls) {
      try {
        cert = await tlsPeek(h.fqdn, h.port);
        const days = Math.floor((cert.valid_to - now()) / DAY);
        if (days < 0) add('bad', 'The TLS certificate expired on ' + new Date(cert.valid_to).toISOString().slice(0, 10) + ' - browsers show a security error.', 'Renew and install the certificate.');
        else if (days <= 14) add('bad', 'The TLS certificate expires in ' + days + ' day(s).', 'Renew and install it now.');
        else if (days <= 30) add('warn', 'The TLS certificate expires in ' + days + ' days.', 'Plan the renewal.');
        if (!cert.name_ok) add('bad', 'The certificate does not cover ' + h.fqdn + ' (it is for ' + (cert.names.slice(0, 4).join(', ') || cert.subject) + ').', 'Install a certificate whose names include this hostname.');
        if (!cert.trusted) add('warn', 'The certificate chain is not trusted (' + cert.trust_error + ').', 'Install the full chain from a public CA.');
      } catch (e) { add('bad', 'HTTPS on port ' + h.port + ' did not answer: ' + String(e.code || e.message).slice(0, 120) + '.', 'Check the service, the firewall, or switch off the TLS check for a name that has no web service.'); }
    }
    if (h.location === 'outside') add('info', 'Hosted outside the Kingdom.', 'If it processes personal data, record the transfer assessment (PDPL Art. 29) and the cloud register entry (SAMA CSF 3.4.3).');
    if (h.location === 'unknown' && !onOwnServer(h, rec.A)) add('info', 'Hosting location not recorded.', ('Record where it is hosted - ' + ZYB_ORG.short + ' data centre, a provider in the Kingdom, or outside (PDPL Art. 29).'));
    return { rec, F, cert };
  }
  function diff(prev, rec) {
    if (!prev) return [];
    const out = [];
    for (const k of Object.keys(rec)) {
      if (k === 'DKIM') { for (const sel of Object.keys(rec.DKIM || {})) if (prev.DKIM && prev.DKIM[sel] != null && rec.DKIM[sel] != null && prev.DKIM[sel] !== rec.DKIM[sel]) out.push('DKIM ' + sel + ': ' + (rec.DKIM[sel] ? 'key published' : 'key removed')); continue; }
      if (k === 'MX_error' || k === 'DNS_via') continue;
      const a = prev[k], b = rec[k]; if (!Array.isArray(a) || !Array.isArray(b)) continue;
      const add = b.filter((x) => !a.includes(x)), del = a.filter((x) => !b.includes(x));
      if (add.length || del.length) out.push(k + ': ' + [add.length ? '+ ' + add.join(', ') : '', del.length ? '- ' + del.join(', ') : ''].filter(Boolean).join('  '));
    }
    return out;
  }
  async function checkOne(kind, x) {
    const key = (kind === 'host' ? 'h:' : 'd:') + x.id, prev = ccol.get(key);
    const r = kind === 'host' ? await checkHost(x) : await checkDomain(x);
    const changes = diff(prev && prev.records, r.rec);
    if (changes.length) { r.F.push({ level: 'info', text: 'DNS changed since ' + new Date(prev.at).toISOString().slice(0, 16).replace('T', ' ') + ': ' + changes.join('; '), fix: 'Confirm the change was approved.' }); hist.put({ id: key + ':' + now(), key, at: now(), changes }); }
    // keep the record sets of a failed lookup from the last good read, so a timeout is not reported as a change next time
    const records = Object.assign({}, prev && prev.records, Object.fromEntries(Object.entries(r.rec).filter(([, v]) => v != null)));
    const row = { id: key, at: now(), records, findings: r.F.sort((p, q) => RANK[p.level] - RANK[q.level]), cert: r.cert || null, changes };
    ccol.put(row); return row;
  }
  async function check(id) {
    const ds = dcol.all((d) => d.status !== 'retired'), hs = hcol.all((h) => h.status !== 'retired');
    const jobs = [].concat(ds.map((d) => ['d', d]), hs.map((h) => ['host', h])).filter(([k, x]) => !id || id === (k === 'host' ? 'h:' : 'd:') + x.id);
    if (id && !jobs.length) throw bad('not found: ' + id, 404);
    let i = 0; const run = async () => { while (i < jobs.length) { const [k, x] = jobs[i++]; try { await checkOne(k, x); } catch (e) { ccol.put({ id: (k === 'host' ? 'h:' : 'd:') + x.id, at: now(), records: {}, findings: [{ level: 'warn', text: 'Check failed: ' + String(e.message).slice(0, 160), fix: '' }], changes: [] }); } } };
    await Promise.all([run(), run(), run(), run()]);
    if (!id) store.collection('dom_cfg').put({ id: 'last_run', at: now() });
    return { checked: jobs.length };
  }
  async function tick() {
    const cfg = store.collection('dom_cfg'), last = (cfg.get('last_run') || {}).at || 0;
    if (now() - last >= 6 * 3600000 && (dcol.all().length || hcol.all().length)) await check();
    if (dcol.all().length && now() - ((cfg.get('brand_sync') || {}).at || 0) >= 3600000) await guardOf(app, 'domains.brand-sync', brandSync)();
  }

  // a hostname that points at a server in the asset register is hosted here, at the organisation
  function ownServer(h, ips) {
    if (h.asset_id) { const a = assets.get(h.asset_id); if (a) return { id: a.id, name: a.name, how: 'linked' }; }
    const A = ips || ((ccol.get('h:' + h.id) || {}).records || {}).A || [];
    const m = A.length ? assets.all((a) => a.status !== 'disposed' && a.mgmt_ip && A.includes(a.mgmt_ip))[0] : null;
    return m ? { id: m.id, name: m.name, how: 'matched by IP ' + m.mgmt_ip } : null;
  }
  function onOwnServer(h, ips) { return !!ownServer(h, ips); }

  // ---- Brand Protection (portal twin service) kept in step with the register
  const brandUrl = () => String((app.config && app.config.domains && app.config.domains.brand_url) || o.brandUrl || 'http://127.0.0.1:9094').replace(/\/$/, '');
  const BRAND_WHO = { 'x-auth-user': 'system:itam-domains', 'x-auth-role': 'admin' };
  function brandCall(method, path, body) {
    if (o.brandCall) return o.brandCall(method, path, body);
    return new Promise((resolve) => {
      let u; try { u = new URL(brandUrl() + path); } catch { return resolve({ status: 0, error: 'brand_url is not a URL' }); }
      const data = body ? JSON.stringify(body) : null;
      const req = require(u.protocol === 'https:' ? 'node:https' : 'node:http').request(u, { method, timeout: 15000,
        headers: Object.assign({ Accept: 'application/json' }, BRAND_WHO, data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) }, (res) => {
        let t = ''; res.setEncoding('utf8'); res.on('data', (c) => { if (t.length < 4e6) t += c; });
        res.on('end', () => { let j = null; try { j = JSON.parse(t); } catch { /* not JSON */ } resolve({ status: res.statusCode, json: j }); });
      });
      req.on('timeout', () => req.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })));
      req.on('error', (e) => resolve({ status: 0, error: String(e.code || e.message) }));
      if (data) req.write(data); req.end();
    });
  }
  let brandBusy = null;
  async function brandSync(who) {
    if (brandBusy) return brandBusy;
    brandBusy = (async () => {
      const cfg = store.collection('dom_cfg'), at = now();
      const done = (r) => { const row = Object.assign({ id: 'brand_sync', at }, r); cfg.put(row); return row; };
      const ours = dcol.all((d) => d.status !== 'retired').sort((a, b) => (a.created_at || 0) - (b.created_at || 0)).map((d) => d.name);
      const g = await brandCall('GET', '/api/brand');
      if (g.status === 404 || (g.status === 200 && !(g.json && g.json.settings))) return done({ ok: false, state: 'missing', error: 'Brand Protection is not installed on this server (no /api/brand).' });
      if (g.status !== 200) return done({ ok: false, state: 'error', error: g.error ? 'Brand Protection did not answer (' + g.error + ')' : 'Brand Protection answered HTTP ' + g.status });
      const S = g.json.settings, bdom = Array.isArray(g.json.domains) ? g.json.domains : [];
      const before = (S.official || []).slice();
      const official = ours.slice(0, BRAND_MAX);
      for (const d of before) if (official.length < BRAND_MAX && !official.includes(d)) official.push(d);   // keep what an analyst added, while there is room
      let pushed = false;
      if (ours.length && JSON.stringify(official) !== JSON.stringify(before)) {
        const p = await brandCall('POST', '/api/brand/settings', Object.assign({}, S, { official }));
        if (p.status !== 200) return done({ ok: false, state: 'error', error: 'Brand Protection refused the official domains: ' + ((p.json && p.json.error) || p.error || ('HTTP ' + p.status)) });
        pushed = true;
      }
      const mine = (n) => ours.some((d) => n === d || n.endsWith('.' + d));
      const marked = [];
      for (const d of bdom) {
        if (!d || !d.domain || !mine(String(d.domain).toLowerCase()) || d.status === 'owned') continue;
        const m = await brandCall('POST', '/api/brand/domain/' + Number(d.id), { status: 'owned', notes: 'In the Domains & Hosting register (IT Asset Management)' });
        if (m.status === 200) marked.push(d.domain);
      }
      const notRegistered = bdom.filter((d) => d && d.status === 'owned' && !mine(String(d.domain).toLowerCase())).map((d) => d.domain).slice(0, 50);
      if (pushed || marked.length) audit(Object.assign(by(who || { user: 'system:itam-domains', role: 'admin' }), { action: 'domains.brand_sync', target: 'brand', detail: { official, marked } }));
      return done({ ok: true, state: 'synced', official, official_before: before, pushed, marked, beyond_limit: ours.slice(BRAND_MAX), not_registered: notRegistered, watched: bdom.length });
    })();
    try { return await brandBusy; } finally { brandBusy = null; }
  }
  const brandSoon = () => { if (o.noBrand || (app.noTimers && !o.brandCall)) return; const t = setTimeout(guardOf(app, 'domains.brand-sync', () => brandSync()), 50); if (t.unref) t.unref(); };

  // ---- view
  function worst(f) { return f && f.length ? f.reduce((w, x) => (RANK[x.level] < RANK[w] ? x.level : w), 'ok') : 'ok'; }
  function view(role) {
    const priv = !role || role === 'viewer', all = assets.all((a) => a.status !== 'disposed');
    const domains = dcol.all((d) => d.status !== 'retired').map((d) => { const c = ccol.get('d:' + d.id); const r = Object.assign({}, d, { check: c || null, worst: c ? worst(c.findings) : null,
      days_left: d.expires ? Math.floor((Date.parse(d.expires) - now()) / DAY) : null, provider_name: PROVIDERS[d.dns_provider] }); if (priv) { delete r.cost; delete r.currency; } return r; });
    const hosts = hcol.all((h) => h.status !== 'retired').map((h) => {
      const c = ccol.get('h:' + h.id), ips = c && c.records && c.records.A || [];
      const own = ownServer(h, ips), loc = h.location === 'unknown' && own ? 'onprem' : h.location;   // on one of our servers = hosted here
      return Object.assign({}, h, { check: c || null, worst: c ? worst(c.findings) : null, domain: (dcol.get(h.domain_id) || {}).name || null, location: loc, location_name: LOCATIONS[loc],
        location_derived: loc !== h.location, hosting: h.hosting || (loc === 'onprem' ? ONPREM : ''), asset: own,
        cert_days: c && c.cert ? Math.floor((c.cert.valid_to - now()) / DAY) : null });
    });
    const F = [].concat(domains, hosts).flatMap((x) => (x.check ? x.check.findings : []));
    const summary = { domains: domains.length, hosts: hosts.length, expired: domains.filter((d) => d.days_left != null && d.days_left < 0).length, expiring_90: domains.filter((d) => d.days_left != null && d.days_left >= 0 && d.days_left <= 90).length,
      no_expiry: domains.filter((d) => !d.expires).length, certs_30: hosts.filter((h) => h.cert_days != null && h.cert_days <= 30).length, outside_ksa: hosts.filter((h) => h.location === 'outside').length,
      bad: F.filter((f) => f.level === 'bad').length, warn: F.filter((f) => f.level === 'warn').length, unchecked: [].concat(domains, hosts).filter((x) => !x.check).length,
      last_run: (store.collection('dom_cfg').get('last_run') || {}).at || null, onprem: hosts.filter((h) => h.location === 'onprem').length };
    domains.sort((a, b) => (RANK[a.worst] ?? 4) - (RANK[b.worst] ?? 4) || (a.days_left ?? 1e9) - (b.days_left ?? 1e9) || a.name.localeCompare(b.name));
    hosts.sort((a, b) => (RANK[a.worst] ?? 4) - (RANK[b.worst] ?? 4) || a.fqdn.localeCompare(b.fqdn));
    const bs = store.collection('dom_cfg').get('brand_sync') || null;
    return { at: new Date(now()).toISOString(), providers: PROVIDERS, locations: LOCATIONS, domains, hosts, summary, brand: bs, brand_max: BRAND_MAX };
  }
  const history = (q) => { const key = s(q && q.id, 60); if (!/^[dh]:/.test(key)) throw bad('id must be d:<domain id> or h:<host id>'); return { id: key, items: hist.all((x) => x.key === key).sort((a, b) => b.at - a.at).slice(0, 50) }; };
  return { putDomain: (b, w) => { const r = putDomain(b, w); brandSoon(); return r; }, putHost, retire: (c, id, b, w) => { const r = retire(c, id, b, w); if (c === 'domain') brandSoon(); return r; },
    check, checkOne, tick, view, history, brandSync, PROVIDERS, LOCATIONS };
}

function withTimeout(p, ms) { let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), ms); })]).finally(() => clearTimeout(t)); }
// TLS handshake only (no HTTP request): the certificate the server presents, whether its chain is trusted and whether it names the host
function peek(host, port) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: 8000 }, () => {
      const c = sock.getPeerCertificate() || {}; const names = String(c.subjectaltname || '').split(/,\s*/).filter((x) => /^DNS:/.test(x)).map((x) => x.slice(4).toLowerCase());
      const idErr = c.raw ? tls.checkServerIdentity(host, c) : new Error('no certificate');
      resolve({ subject: (c.subject && c.subject.CN) || '', issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || '', valid_from: Date.parse(c.valid_from), valid_to: Date.parse(c.valid_to), names,
        name_ok: !idErr, trusted: sock.authorized, trust_error: sock.authorized ? '' : String(sock.authorizationError || ''), fingerprint256: c.fingerprint256 || '' });
      sock.end();
    });
    sock.on('timeout', () => { sock.destroy(); reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })); });
    sock.on('error', reject);
  });
}

function registerDomains(srv, app) {
  const D = createDomains(app);
  (app.addons = app.addons || {}).domains = D;
  srv.route('GET', '/domains', (ctx) => void ctx.need('viewer') || D.view(ctx.who && ctx.who.role));
  srv.route('GET', '/domains/history', (ctx) => void ctx.need('viewer') || D.history(ctx.query || {}));
  srv.route('POST', '/domains', (ctx) => { ctx.need('admin'); return D.putDomain(ctx.body || {}, ctx.who); });
  srv.route('POST', '/domains/hosts', (ctx) => { ctx.need('admin'); return D.putHost(ctx.body || {}, ctx.who); });
  srv.route('POST', '/domains/hosts/:id/retire', (ctx) => { ctx.need('admin'); return D.retire('host', ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/domains/:id/retire', (ctx) => { ctx.need('admin'); return D.retire('domain', ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/domains/brand-sync', async (ctx) => { ctx.need('admin'); const r = await D.brandSync(ctx.who); return Object.assign(D.view(ctx.who.role), { brand: r }); });
  srv.route('POST', '/domains/check', async (ctx) => { ctx.need('operator'); const b = ctx.body || {}; const r = await D.check(b.id ? String(b.id) : ''); if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip, action: 'domains.check', target: b.id || 'all', detail: r }); return D.view(ctx.who.role); });
  if (!app.noTimers) { const t1 = setTimeout(guardOf(app, 'domains.tick', () => D.tick()), 90000), t2 = setInterval(guardOf(app, 'domains.tick', () => D.tick()), 600000); if (t1.unref) { t1.unref(); t2.unref(); } }
  return D;
}

module.exports = { createDomains, registerDomains, PROVIDERS, LOCATIONS };
