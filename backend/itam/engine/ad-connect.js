// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const tls = require('node:tls');
const dnsP = require('node:dns').promises;
const { X509Certificate } = require('node:crypto');
const { body, isIp } = require('./check');
const { isHuman } = require('./approve-scopes');
const ldap = require('./discovery/ldap-client');
/*
 * Connect Active Directory ({P} = /api/itam; Integration Hub -> Active Directory -> Connect): the guided way to set the directory
 * connection that Directory users (import), SSO Access from AD, AD Management, access reviews and HR onboarding all use - without
 * typing ldaps:// URLs, a CA file path, a bind DN or a base DN.
 *   discover     the domain name -> its domain controllers from DNS (_ldap._tcp.dc._msdcs.<domain>, the records AD registers)
 *   certificate  a domain controller -> the certificate it presents on LDAPS (636) and the root CA in its chain, with SHA-256
 *                fingerprints for the administrator to compare (certlm.msc on the DC). READ ONLY: the handshake is not trusted and
 *                nothing is sent over it; trust comes only from the administrator's confirmation, and from then on every connection
 *                verifies the certificate and the DC's name against that CA
 *                A domain controller typed as an IP ADDRESS: its certificate is for its name, not the address - the name is taken from
 *                the certificate (verify_as) and every connection dials the IP and verifies the certificate under that name
 *   test         sign in with user@domain (or DOMAIN\user, or a DN) over verified LDAPS, read the domain from the root DSE, find the
 *                account and count the people - nothing saved. A PRIVILEGED account (adminCount = 1, or Domain / Enterprise Admins,
 *                Administrators, operators ...) is REFUSED: reading people needs only a normal domain user
 *   save         the same test again on the server, then the settings through HR onboarding's directory settings (the password is
 *                sealed in the vault there, never returned, logged or audited)
 *   POST /ad-connect/discover     admin  {domain}                                                              audited
 *   POST /ad-connect/certificate  admin  {server, ip?} - ip: dial it for a DC name the platform's DNS cannot resolve audited
 *   POST /ad-connect/test         admin  {servers[] (name | {name, ip}), ca_pem, user, password}               audited
 *   POST /ad-connect/save         admin  {servers[], ca_pem, user, password, domain}                           audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DOMAIN = /^(?=.{3,253}$)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/;
const SERVER = /^(ldaps?:\/\/)?[A-Za-z0-9.-]{1,253}(:\d{1,5})?\/?$/i;
const PEM = /^(-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+$/;
const ACCOUNT = /^([^\u0000-\u001f@\\]{1,104}@[A-Za-z0-9.-]{1,253}|[A-Za-z0-9-]{1,15}\\[A-Za-z0-9._ -]{1,20}|CN=[^\u0000-\u001f]{1,400})$/i;
const PRIV = /^(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|print operators|dnsadmins|group policy creator owners|key admins|enterprise key admins|organization management)$/i;
const BIND_HELP = { '52e': 'the user name or password is wrong', '775': 'the account is locked out', '533': 'the account is disabled', '532': 'the password has expired', '773': 'the password must be changed before first use', '701': 'the account has expired', '530': 'the account may not sign in at this time', '531': 'the account may not sign in from this computer' };

function createAdConnect(app, opts = {}) {
  const OB = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const resolver = opts.dns || dnsP;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('ad-connect:' + key, 600000, 'warn', msg, detail); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const baseOf = (domain) => domain.toLowerCase().split('.').map((p) => 'DC=' + p).join(',');
  const url = (s) => { const m = /^(ldaps?:\/\/)?([A-Za-z0-9.-]+)(?::(\d+))?/i.exec(String(s).trim()); const sch = m[1] ? m[1].toLowerCase().replace('://', '') : 'ldaps'; return sch + '://' + m[2].toLowerCase() + ':' + (m[3] || (sch === 'ldaps' ? 636 : 389)); };
  const netWhy = (e, host) => {
    const c = e.code || '', m = String(e.message || '');
    if (/EAI_AGAIN|ENOTFOUND|ENODATA|ESERVFAIL/.test(c + m)) return 'the platform server cannot resolve ' + host + ' - its DNS server must be one of your domain controllers (or add the name to /etc/hosts)';
    if (/ECONNREFUSED/.test(c + m)) return host + ' refused the connection on that port - LDAPS (636) is off: the domain controller needs a certificate (Active Directory Certificate Services enrols one automatically; or import one into the DC\'s Personal store and restart it)';
    if (/ETIMEDOUT|timeout/i.test(c + m)) return 'no answer from ' + host + ' - a firewall between the platform server and the domain controller drops port 636';
    if (/EHOSTUNREACH|ENETUNREACH/.test(c + m)) return 'no route to ' + host + ' from the platform server';
    if (/ERR_TLS_CERT_ALTNAME_INVALID|Hostname\/IP does not match/i.test(c + m)) return 'the certificate is not for the name ' + host + ' - use the domain controller\'s full name as it appears in its certificate';
    if (/CERT|certificate|self.signed|UNABLE_TO_VERIFY/i.test(c + m)) return 'the domain controller\'s certificate was not issued by the CA you confirmed - read the certificate again';
    return m.slice(0, 200);
  };

  async function discover(b0, who) {
    person(who, 'discovers the domain');
    const b = body(b0 || {}).str('domain', { required: true, max: 253, re: DOMAIN, msg: 'domain must be the AD domain name, e.g. corp.local' }).done();
    const domain = b.domain.toLowerCase(); let servers = [], why = '';
    try {
      const r = await resolver.resolveSrv('_ldap._tcp.dc._msdcs.' + domain);
      servers = r.sort((a, c) => a.priority - c.priority || c.weight - a.weight).map((x) => ({ host: String(x.name).replace(/\.$/, '').toLowerCase(), url: 'ldaps://' + String(x.name).replace(/\.$/, '').toLowerCase() + ':636', priority: x.priority }))
        .filter((x, i, a) => a.findIndex((y) => y.host === x.host) === i).slice(0, 8);
    } catch (e) { why = netWhy(e, '_ldap._tcp.dc._msdcs.' + domain); warn('dns', 'AD discovery: no domain controller records', { domain, err: String(e.code || e.message).slice(0, 80) }); }
    audit(who, 'ad_connect.discover', domain, { found: servers.length });
    return { domain, base_dn: baseOf(domain), servers, why: servers.length ? '' : (why || 'no domain controller records in DNS') + ' - or type a domain controller\'s name' };
  }

  function info(c) {
    const x = c.raw ? new X509Certificate(c.raw) : null;
    return { subject: x ? x.subject.replace(/\n/g, ', ') : '', issuer: x ? x.issuer.replace(/\n/g, ', ') : '', valid_from: x ? new Date(x.validFrom).toISOString() : null, valid_to: x ? new Date(x.validTo).toISOString() : null,
      fingerprint256: x ? x.fingerprint256 : '', names: x && x.subjectAltName ? x.subjectAltName.split(/,\s*/).map((n) => n.replace(/^DNS:/, '')).slice(0, 12) : [], ca: x ? !!x.ca : false };
  }
  async function certificate(b0, who) {
    person(who, 'reads the domain controller certificate');
    const b = body(b0 || {}).str('server', { required: true, max: 270, re: SERVER, msg: 'server must be a domain controller name or IP address, e.g. dc01.corp.local or 192.168.1.10' })
      .str('ip', { max: 45, ip: true }).done();
    const u = url(b.server), m = /^ldaps?:\/\/([^:]+):(\d+)$/.exec(u), named = m[1], port = m[2] === '389' ? 636 : Number(m[2]);
    if (b.ip && isIp(named)) throw httpErr(400, 'ip is for a domain controller NAME the platform cannot resolve - the server is already an address');
    const host = b.ip || named;   // dialled
    const got = await new Promise((resolve, reject) => {
      // read the presented chain only: not trusted, nothing sent - the administrator compares the fingerprint
      const s = tls.connect({ host, port, servername: isIp(named) ? undefined : named, rejectUnauthorized: false, minVersion: 'TLSv1.2' });
      const t = setTimeout(() => { s.destroy(); reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })); }, opts.timeoutMs || 8000);
      s.once('secureConnect', () => { clearTimeout(t); const p = s.getPeerCertificate(true); s.destroy(); resolve(p); });
      s.once('error', (e) => { clearTimeout(t); reject(e); });
    }).catch((e) => { warn('cert', 'AD connect: certificate not read', { host, err: String(e.code || e.message).slice(0, 80) });
      const dnsFail = /EAI_AGAIN|ENOTFOUND|ENODATA|ESERVFAIL/.test(String(e.code || '') + String(e.message || '')) && !isIp(host);
      throw Object.assign(httpErr(424, netWhy(e, host) + (dnsFail ? ' - or give its IP address: the platform connects to the IP and still verifies the certificate as ' + named : '')), dnsFail ? { need_ip: named } : {}); });
    if (!got || !got.raw) throw httpErr(424, host + ' presented no certificate');
    const chain = []; let c = got;
    for (let i = 0; c && c.raw && i < 6; i++) { chain.push(c); if (!c.issuerCertificate || c.issuerCertificate === c || c.issuerCertificate.raw.equals(c.raw)) break; c = c.issuerCertificate; }
    const leaf = info(chain[0]), top = chain[chain.length - 1], topX = new X509Certificate(top.raw);
    const selfSigned = topX.ca && topX.checkIssued(topX);
    // typed as an IP address: the certificate names the DC - verify under that name and dial the IP
    const byIp = isIp(named), dnsNames = leaf.names.filter((n) => /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(n) && !/^\*/.test(n));
    const cnName = (/(?:^|,\s*)CN=([A-Za-z0-9.-]+)/.exec(leaf.subject) || [])[1] || '';
    const verifyAs = byIp ? (dnsNames[0] || (/\./.test(cnName) ? cnName : '')).toLowerCase() : named;
    let nameOk = true; try { nameOk = !!verifyAs && !tls.checkServerIdentity(verifyAs, chain[0]); } catch (e) { nameOk = false; /* no usable name: reported below */ }
    const root = chain.length > 1 && selfSigned ? Object.assign(info(top), { pem: topX.toString() }) : null;
    audit(who, 'ad_connect.certificate', host, { leaf: leaf.fingerprint256, root: root ? root.fingerprint256 : null });
    return { server: 'ldaps://' + named + ':' + port, host: named, presented: leaf, name_matches: nameOk, verify_as: verifyAs, ip: byIp ? named : (b.ip || ''),
      by_ip: byIp ? (verifyAs ? 'You typed an IP address. The certificate is for ' + verifyAs + ': the platform connects to ' + host + ' and verifies the certificate under that name.' : 'You typed an IP address and the certificate names no domain controller - type the domain controller\'s full name instead.') : '', chain: chain.map((x) => info(x).subject), root,
      why: root ? '' : 'the domain controller did not send its root CA - export it (on the DC: certlm.msc -> Trusted Root Certification Authorities -> your CA -> Export, Base-64) and paste it',
      how_to_check: 'On the domain controller: certlm.msc -> Trusted Root Certification Authorities -> the CA -> Details -> Thumbprint (SHA-1 there; PowerShell: (Get-ChildItem Cert:\\LocalMachine\\Root | ? Subject -like "*<CA name>*").GetCertHashString("SHA256")).' };
  }

  // sign in over verified LDAPS, read the domain, find the account, count people - nothing saved
  async function probe(b0) {
    const b = body(b0 || {}).list('servers', { required: true, max: 4 })
      .str('ca_pem', { required: true, max: 20000, re: PEM, msg: 'ca_pem must be the root CA certificate (PEM) - read it in step 2 or paste it' })
      .str('user', { required: true, max: 420, re: ACCOUNT, msg: 'user must be user@domain, DOMAIN\\user or a DN' }).str('password', { required: true, max: 256 }).str('domain', { max: 253, re: DOMAIN, msg: 'domain must be the AD domain name' }).done();
    // each server: a DC name (or ldaps:// URL), or {name, ip} - dial the IP, verify the certificate as the name
    const targets = b.servers.map((x) => {
      if (typeof x === 'string') { if (!SERVER.test(x)) throw httpErr(400, 'servers: ' + x.slice(0, 80) + ' is not a domain controller name'); if (isIp(x.replace(/^ldaps?:\/\/|:\d+\/?$/gi, ''))) throw httpErr(400, 'servers: ' + x + ' is an IP address - give {name, ip} with the name from its certificate (step 2 does this)'); return { url: url(x) }; }
      if (!x || typeof x !== 'object' || Array.isArray(x)) throw httpErr(400, 'servers: each must be a domain controller name or {name, ip}');
      const n = String(x.name || ''), ip = String(x.ip || '');
      if (!/^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$/.test(n) || isIp(n)) throw httpErr(400, 'servers: name must be the domain controller\'s full name from its certificate');
      if (ip && !isIp(ip)) throw httpErr(400, 'servers: ip ' + ip.slice(0, 40) + ' is not an IP address');
      const port = x.port === undefined ? 636 : Number(x.port); if (!Number.isInteger(port) || port < 1 || port > 65535) throw httpErr(400, 'servers: port must be 1-65535 (636 for LDAPS)');
      const u = 'ldaps://' + n.toLowerCase() + ':' + port;
      return ip ? { url: u, ip } : { url: u };
    });
    try { const x = new X509Certificate(b.ca_pem); if (!x.ca) throw httpErr(400, 'ca_pem is not a CA certificate - give the root CA, not the domain controller\'s own certificate'); } catch (e) { if (e.status) throw e; throw httpErr(400, 'ca_pem is not a readable certificate'); }
    const servers = targets.map((t) => t.url), L = opts.ldap || ldap;
    const client = L.createClient({ servers: targets, ca: b.ca_pem, timeoutMs: opts.timeoutMs || 10000 });
    let r;
    try {
      r = await client.run(async (conn) => {
        await conn.bind(b.user, b.password);
        const root = (await conn.search('', { scope: 'base', filter: '(objectClass=*)', attributes: ['defaultNamingContext', 'dnsHostName', 'domainFunctionality'] })).entries[0];
        const ra = (k) => ((root && root.attrs[k.toLowerCase()]) || [])[0] || '';
        const base = ra('defaultNamingContext'); if (!base) throw httpErr(424, 'the directory did not say its domain (no defaultNamingContext in the root DSE) - is this an Active Directory domain controller?');
        const esc = L.escapeFilter, u = b.user;
        const f = /^CN=/i.test(u) ? null : /@/.test(u) ? '(userPrincipalName=' + esc(u) + ')' : '(sAMAccountName=' + esc(u.split('\\')[1]) + ')';
        const acc = f ? (await conn.search(base, { filter: '(&(objectClass=user)' + f + ')', attributes: ['distinguishedName', 'adminCount', 'memberOf', 'userPrincipalName'], sizeLimit: 2 })).entries[0]
          : (await conn.search(u, { scope: 'base', filter: '(objectClass=*)', attributes: ['distinguishedName', 'adminCount', 'memberOf', 'userPrincipalName'] }).catch(() => ({ entries: [] /* a DN that does not exist: reported as not found below */ }))).entries[0];
        const people = await conn.search(base, { filter: '(&(objectCategory=person)(objectClass=user))', attributes: ['userAccountControl'], pageSize: 1000, maxEntries: 50000 });
        const enabled = people.entries.filter((e) => !((parseInt((e.attrs.useraccountcontrol || [])[0], 10) || 0) & 2)).length;
        return { base, dc: ra('dnsHostName'), server: conn.server && conn.server.url, acc, people: people.entries.length, enabled, capped: people.entries.length >= 50000 };
      });
    } catch (e) {
      if (e.status) throw e;
      const ad = /\bdata ([0-9a-f]{3})\b/i.exec(String(e.diagnostic || e.message || ''));
      if (ad && BIND_HELP[ad[1]]) throw httpErr(401, 'the domain controller refused the sign-in: ' + BIND_HELP[ad[1]] + ' (AD code ' + ad[1] + ')');
      if (e.code === 'EMPTY_PASSWORD') throw httpErr(400, 'password is required');
      const host = (targets[0].ip || servers[0] || '').replace(/^ldaps?:\/\/|:\d+$/g, '');
      const why = String(e.message || '').split(' — ').pop();
      warn('test', 'AD connect: sign-in test failed', { err: String(e.code || '').slice(0, 40) });
      throw httpErr(424, 'no domain controller answered: ' + netWhy({ code: e.code, message: why }, host));
    }
    if (!r.acc) throw httpErr(424, 'signed in, but the account ' + b.user + ' was not found under ' + r.base + ' - use the account\'s user@domain name');
    const groups = (r.acc.attrs.memberof || []).map((g) => (/^CN=((?:[^,\\]|\\.)+)/i.exec(g) || [])[1] || g);
    const priv = groups.filter((g) => PRIV.test(g));
    if ((r.acc.attrs.admincount || [])[0] === '1' || priv.length) throw httpErr(403, 'refused: ' + b.user + ' is a privileged account (' + (priv.length ? priv.join(', ') : 'adminCount = 1') + '). Reading people needs only a normal domain user - create a dedicated service account (step 3) and use that');
    const ips = {}; for (const t of targets) if (t.ip) ips[t.url.replace(/^ldaps?:\/\/|:\d+$/g, '')] = t.ip;
    return { b, servers, ips, base_dn: r.base, bind_dn: r.acc.dn, dc: r.dc, server: r.server, people: r.people, enabled: r.enabled, capped: r.capped, domain: b.domain || r.base.replace(/DC=/gi, '').split(',').join('.').toLowerCase() };
  }
  const pub = (r) => ({ ok: true, server: r.server, dc: r.dc, base_dn: r.base_dn, bind_dn: r.bind_dn, people: r.people, enabled: r.enabled, capped: r.capped, domain: r.domain });
  async function test(b0, who) {
    person(who, 'tests the directory sign-in');
    let r; try { r = await probe(b0); } catch (e) { audit(who, 'ad_connect.test', 'directory', { ok: false, error: String(e.message).slice(0, 200) }); throw e; }
    audit(who, 'ad_connect.test', r.base_dn, { ok: true, server: r.server, people: r.people });
    return pub(r);
  }
  async function save(b0, who) {
    person(who, 'connects the directory');
    const ob = OB(); if (!ob) throw httpErr(409, 'HR onboarding (which holds the directory connection) is not installed - run the update');
    const r = await probe(b0);
    ob.configure({ servers: r.servers, server_ips: r.ips, ca_pem: r.b.ca_pem, bind_dn: r.bind_dn, bind_password: r.b.password, base_dn: r.base_dn, upn_suffix: r.domain }, who);
    audit(who, 'ad_connect.save', r.base_dn, { servers: r.servers.length, bind_dn: r.bind_dn, people: r.people });
    return Object.assign(pub(r), { saved: true });
  }
  return { discover, certificate, test, save };
}

function registerAdConnect(srv, app, X) {
  srv.route('POST', '/ad-connect/discover', (ctx) => { ctx.need('admin'); return X.discover(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/ad-connect/certificate', (ctx) => { ctx.need('admin'); return X.certificate(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/ad-connect/test', (ctx) => { ctx.need('admin'); return X.test(ctx.body, ctx.who); }, { maxBody: 32768 });
  srv.route('POST', '/ad-connect/save', (ctx) => { ctx.need('admin'); return X.save(ctx.body, ctx.who); }, { maxBody: 32768 });
}
module.exports = { createAdConnect, registerAdConnect };
