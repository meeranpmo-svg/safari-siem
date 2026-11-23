// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Libraesva Email Security Gateway (ESG) - read-only API connection. The gateway's mail log already reaches the SIEM by
 * syslog (sentra-siem parse/libraesva.js); this adds what syslog does not carry: the appliance's own view (system status,
 * queues, quarantine, message log) through its REST API.
 *
 * What Libraesva documents: POST /api/v2/login {username, password[, otp]} returns a token; every call sends it as
 * X-ESG-Auth-Token; a login made with an ESG "API user" must name the ESG user it acts as in X-Switch-User (without it
 * the API user may only log in). The token carries that user's permissions - give it a read-only ESG user. The list of
 * endpoints is published by each appliance at /api/v2/ and changes between releases, so nothing is hard-coded here: the
 * platform reads that catalogue and an administrator maps which GET endpoint answers "status", "queue", "quarantine"
 * and "messages". Only GET calls on /api/v2/ paths are ever made (plus the login); there is no write path in this module.
 * The password is stored sealed, never returned or logged; the token lives in memory only.
 *
 *   GET  /esg                    viewer    connection summary (no secret), catalogue, mapping, last test
 *   POST /esg/config             admin     {base_url, username, password?, switch_user?, host_name?, pin?}   audited (never the password)
 *   DELETE /esg/config           admin     remove the connection (sealed password, mapping, catalogue)   audited
 *   POST /esg/test               operator  log in and read the catalogue                         audited
 *   POST /esg/diagnose           operator  step by step: DNS, HTTPS + certificate, API, login, catalogue, mapping, sample read audited
 *   POST /esg/endpoints          admin     {status?, queue?, quarantine?, messages?}  paths from the catalogue   audited
 *   GET  /esg/read/:kind         status / queue: viewer · quarantine / messages: operator (addresses - PDPL), audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const KINDS = { status: 'viewer', queue: 'viewer', quarantine: 'operator', messages: 'operator' };
const PATH_RE = /^\/api\/v2\/[A-Za-z0-9/_\-.{}]*$/;
const TOKEN_MS = 20 * 60000, MAX_ROWS = 500;
// the gateway's own reason for a refused login (JSON error / message / detail, or a short text body), one line, capped -
// shown to the administrator as data; it never contains the password (the gateway does not echo it)
function gwMessage(r) {
  const j = r && r.json, pick = (o) => o && (typeof o === 'string' ? o : o.message || o.error_description || o.error || o.detail || o.title || (Array.isArray(o.errors) && o.errors.map((e) => (e && (e.message || e.detail)) || e).join('; ')));
  let m = pick(j) || (j && pick(j.error)) || '';
  if (!m && r && typeof r.text === 'string' && r.text.length < 400 && !/<html/i.test(r.text) && !/^[\s{}\[\]"]*$/.test(r.text)) m = r.text; // an empty JSON body ({}, [], "") says nothing
  if (!m && r && typeof r.text === 'string' && /<html|<title|<h1/i.test(r.text)) m = htmlReason(r.text);   // an error page: its own title / heading
  return String(m || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, 200);
}

// the title / first heading of an HTML error page (e.g. "400 Bad Request", "Untrusted Host"), tags and entities stripped
function htmlReason(t) {
  const pick = (re) => { const x = re.exec(t); return x ? x[1].replace(/<[^>]*>/g, ' ').replace(/&[a-z#0-9]+;/gi, ' ').replace(/\s+/g, ' ').trim() : ''; };
  const title = pick(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i), h = pick(/<h1[^>]*>([\s\S]{0,300}?)<\/h1>/i) || pick(/<h2[^>]*>([\s\S]{0,300}?)<\/h2>/i);
  return (title && h && title !== h ? title + ' - ' + h : title || h).slice(0, 160);
}
const isIpHost = (u) => { try { const h = new URL(u).hostname; return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':'); } catch (e) { return false; } };
// a connection that never got an HTTP answer: name the OS cause and what to change (the code alone - "unreachable" - fixes nothing)
function netReason(e, c) {
  const sys = String(e.sys || (/^E[A-Z]+$/.test(String(e.code || '')) ? e.code : '') || ''), host = (() => { try { return new URL(c.base_url).hostname; } catch (x) { return ''; } })();
  if (e.code === 'timeout' || sys === 'ETIMEDOUT') return `no answer from ${host}:443 within 15 s - a firewall between the platform server and the gateway is dropping it; allow TCP 443 from the platform server`;
  if (sys === 'ENOTFOUND' || sys === 'EAI_AGAIN') return `${host} does not resolve on the platform server (${sys}) - put the gateway's IP address in Gateway URL and its name in "Host name"`;
  if (sys === 'ECONNREFUSED') return `${host}:443 refused the connection (ECONNREFUSED) - check the address and that the ESG web interface listens on 443 there`;
  if (sys === 'EHOSTUNREACH' || sys === 'ENETUNREACH') return `no route from the platform server to ${host} (${sys}) - check the address and the routing / firewall between them`;
  if (sys === 'ECONNRESET' || sys === 'EPIPE') return c.host_name
    ? `the gateway closed the connection during the TLS handshake (${sys}) - it may not accept the server name "${c.host_name}": check "Host name" matches the appliance's certificate, or clear it and test again`
    : `the gateway closed the connection (${sys}) - a firewall or proxy between the platform server and the gateway may be cutting HTTPS`;
  return `the gateway did not answer (${sys || e.code || e.message})`;
}

function createLibraesva(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now, col = () => store.collection('esg');
  const http = opts.request || require('./discovery/httpc').request;
  const dc = (app.config && app.config.discovery) || {};
  let S0 = null;
  const sealer = () => S0 || (S0 = opts.sealer || require('./discovery/vault').createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-libraesva' }));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const human = (who, what) => { if (/^(duty|system|ai|svc|service)[:_-]/i.test(String(who.user || ''))) throw httpErr(403, 'a person ' + what + ', not a service identity'); };
  let token = null;   // { value, at } - memory only

  const cfg = () => col().get('cfg') || null;
  function summary() {
    const c = cfg(), st = col().get('state') || {};
    return { configured: !!(c && c.base_url), base_url: c ? c.base_url : null, username: c ? c.username : null, switch_user: c ? c.switch_user || null : null, host_name: c ? c.host_name || null : null, pinned: !!(c && c.pin),
      password_set: !!(c && c.enc), endpoints: (c && c.endpoints) || {}, catalogue: st.catalogue || [], catalogue_source: st.catalogue_source || null,
      last_test: st.last_test || null, by: c ? c.by : null, at: c ? c.at : null,
      note: 'Read-only: the platform logs in and makes GET calls only, on the paths an administrator maps from the appliance\'s own catalogue (/api/v2/). Use an ESG API user that acts as a read-only ESG user.' };
  }
  function setConfig(b, who) {
    human(who, 'sets the Libraesva connection');
    const cur = cfg() || {};
    const u = new URL(b.base_url);
    if (u.protocol !== 'https:') throw httpErr(400, 'base_url must be https://');
    if (b.host_name && !isIpHost(u.origin)) throw httpErr(400, 'host_name is only for a gateway URL that holds an IP address - put the name in the URL instead');
    const rec = { id: 'cfg', base_url: u.origin, username: b.username, switch_user: b.switch_user || null, host_name: b.host_name ? b.host_name.toLowerCase() : null, pin: b.pin ? b.pin.replace(/:/g, '').toLowerCase() : (b.pin === '' ? null : cur.pin || null),
      enc: b.password ? sealer().seal('esg', b.password) : cur.enc || null, endpoints: cur.base_url === u.origin ? cur.endpoints || {} : {}, by: who.user, at: now() };
    if (!rec.enc) throw httpErr(400, 'password is required the first time');
    col().put(rec); token = null;
    audit(who, 'esg.config', 'libraesva', { base_url: rec.base_url, username: rec.username, switch_user: rec.switch_user, host_name: rec.host_name, pinned: !!rec.pin, password_changed: !!b.password });
    return summary();
  }
  // an appliance reached by IP but configured for a name: send that name (Host header + TLS server name) on every call
  const reqOpts = (c, extra) => {
    const o = Object.assign({ timeoutMs: 15000, pin: c.pin || undefined, maxBytes: 2 * 1024 * 1024 }, extra || {});
    if (c.host_name) { const port = new URL(c.base_url).port; o.headers = Object.assign({ Host: c.host_name + (port ? ':' + port : '') }, o.headers || {}); o.servername = c.host_name; }
    return o;
  };
  async function login(c) {
    if (token && now() - token.at < TOKEN_MS) return token.value;
    let pw; try { pw = sealer().unseal('esg', c.enc); } catch (e) { throw httpErr(409, 'the stored password could not be unsealed - set it again'); }
    let r;
    // an API user names the ESG user it acts as already at login (X-Switch-User) - some releases refuse the login without it
    const lh = { 'Content-Type': 'application/json', Accept: 'application/json' }; if (c.switch_user) lh['X-Switch-User'] = c.switch_user;
    try { r = await http(c.base_url + '/api/v2/login', reqOpts(c, { method: 'POST', headers: lh, body: JSON.stringify({ username: c.username, password: pw }), captureUntrusted: true })); }
    catch (e) { throw httpErr(502, e.cert ? `the appliance certificate is not trusted (SHA-256 ${e.cert.fingerprint256}) - pin it in the connection settings if it is the gateway's` : netReason(e, c)); }
    const said = gwMessage(r);
    if (r.status === 401 || r.status === 403) throw httpErr(502, `login refused by the gateway (HTTP ${r.status})${said ? ': "' + said + '"' : ''} - check the API user and password`);
    const tk = r.json && (r.json.token || (r.json.data && r.json.data.token));
    if (r.status >= 300 || !tk) {
      let hint = '';
      const ct0 = String((r.headers && r.headers['content-type']) || '').split(';')[0], html0 = /html/i.test(ct0) || /<html/i.test(String(r.text || ''));
      // reached by IP and refused with a web page: the appliance answers only to its configured host name
      if (r.status === 400 && html0 && isIpHost(c.base_url) && !c.host_name) hint = ' - the appliance was reached by its IP address and its web server refused the request with an error page. Libraesva answers only to the host name it is configured with: enter that name (the one in the ESG web console address, or on its certificate) in "Host name" - or use it in the Gateway URL if the platform server resolves it - and test again';
      else if (/otp|two.?factor|2fa|totp/i.test(said)) hint = ' - this user has two-factor sign-in: use an ESG API user without 2FA';
      else if (r.status === 400 && !c.switch_user && /switch|act as|impersonat/i.test(said)) hint = ' - an ESG API user must act as an ESG user: fill in "Act as ESG user" (a read-only ESG user) and test again';
      else if (r.status === 400 && !c.switch_user) {
        // the appliance gave no reason: say what came back instead of guessing, and the two cases Libraesva documents
        const ct = String((r.headers && r.headers['content-type']) || '').split(';')[0], html = /html/i.test(ct) || /<html/i.test(String(r.text || ''));
        hint = ' - the gateway gave no reason' + (html ? ' and answered with a web page (' + (ct || 'text/html') + '): check the address is the ESG appliance itself, not a proxy or load balancer in front of it' : ct ? ' (answer type ' + ct + ')' : '')
          + '. A normal ESG user (User Management → Users) signs in with its own name and password and needs no "Act as ESG user"; check it can sign in to the ESG web console with the same name and password and has no two-factor sign-in. Only a user under User Management → API Users needs "Act as ESG user"';
      }
      else if (r.status === 400 && said && !html0) hint = ' - check that "Act as ESG user" is an existing ESG user and that the API user is allowed to switch to it';
      else if (r.status === 400) hint = ' - the gateway gave no reason. If "' + c.username + '" is a normal ESG user (User Management → Users, e.g. a read-only admin) clear "Act as ESG user": only an API User (User Management → API Users) switches to another user, and a normal user that asks to switch is refused. If it is an API User, "Act as ESG user" must be the exact user name of an existing ESG user as the ESG shows it (often the e-mail address)';
      // 404: the address answered but not as the ESG REST API. By IP its web server serves its default site (Libraesva answers only to
      // its configured host name) - the same advice the step-by-step Diagnose gives, so the error alone says what to change
      else if (r.status === 404 && isIpHost(c.base_url) && !c.host_name) hint = ' - the gateway was reached by its IP address and its web server answered with its default site, not the ESG API. Enter the ESG host name (the name in its certificate, the address you open its web console with) in "Host name", keep the IP in Gateway URL, save and test again';
      else if (r.status === 404) hint = ' - ' + (c.host_name ? 'the address with host name ' + c.host_name + ' does not serve /api/v2/login. ' : '') + 'ESG 5.x has REST API v2: check the Gateway URL is the ESG management interface (the address of its web console), not a load balancer, the user quarantine portal or another site, then the API user under System -> API. "Diagnose" checks each step';
      throw httpErr(502, `login did not return a token (HTTP ${r.status})${said ? ': "' + said + '"' : ''}${hint}`);
    }
    token = { value: String(tk), at: now() };
    return token.value;
  }
  async function get(c, path, query, more) {
    if (!PATH_RE.test(path) || path.includes('..')) throw httpErr(400, 'not an /api/v2/ path');
    const tk = await login(c);
    const qs = query && Object.keys(query).length ? '?' + new URLSearchParams(query).toString() : '';
    const headers = { Accept: (more && more.accept) || 'application/json', 'X-ESG-Auth-Token': tk }; if (c.switch_user) headers['X-Switch-User'] = c.switch_user;
    let r;
    try { r = await http(c.base_url + path + qs, reqOpts(c, Object.assign({ method: 'GET', headers }, more && more.maxBytes ? { maxBytes: more.maxBytes } : {}))); } catch (e) { throw httpErr(502, netReason(e, c)); }
    if (r.status === 401) { token = null; throw httpErr(502, 'the gateway rejected the token (HTTP 401) - test the connection again'); }
    if (r.status === 403) throw httpErr(502, 'the ESG user this connection acts as may not read ' + path + (c.switch_user ? '' : ' (an API user needs a user to act as: set "act as user")'));
    // a redirect: followed once (catalogue reads only) when it stays on the same gateway inside /api/v2/; anywhere else it is reported
    // with where it points - ESG 5.x answers /api/v2/ with 302 to its documentation page, or to the console login when the
    // documentation needs a console session
    if (r.status >= 300 && r.status < 400) {
      const loc = String((r.headers && (r.headers.location || r.headers.Location)) || '');
      let to = null; try { const u = new URL(loc, c.base_url + path); if (u.origin === new URL(c.base_url).origin) to = u.pathname + u.search; } catch (e) { to = null; /* not a usable address: reported below */ }
      const toPath = to ? to.split('?')[0] : '';
      if (more && more.follow && toPath && PATH_RE.test(toPath) && !toPath.includes('..') && toPath !== path) return get(c, toPath, null, Object.assign({}, more, { follow: false, redirectedFrom: path }));
      throw Object.assign(httpErr(502, `the gateway answered HTTP ${r.status} for ${path}` + (loc ? ' (redirect to ' + (to || loc).slice(0, 120) + ')' : '')), { redirect: to || loc || null });
    }
    if (r.status >= 300) throw httpErr(502, `the gateway answered HTTP ${r.status} for ${path}`);
    if (more && more.redirectedFrom) r.redirectedFrom = more.redirectedFrom;
    r.path = path;
    return r;
  }
  // where an OpenAPI document is usually published; every read is a logged-in GET, a miss is not an error (the mapping can be typed).
  // ESG 5.x is built on API Platform: its documentation page (/api/v2/, /api/v2/docs) embeds the whole OpenAPI document in
  // <script id="swagger-data" type="application/json">, and /api/v2/docs.jsonopenapi serves it as JSON. The document describes
  // hundreds of resources and is several MB, so the catalogue read allows up to 40 MB (the normal reads keep 2 MB).
  const SPEC_PATHS = ['/api/v2/docs.jsonopenapi', '/api/v2/docs.json', '/api/v2/', '/api/v2/docs', '/api/v2/doc.json', '/api/v2/openapi.json', '/api/v2/swagger.json', '/api/v2/doc'];
  const SPEC_MAX = 40 * 1024 * 1024;
  function specOf(r) {
    if (r.json && r.json.paths) return r.json;
    const t = r.text || '';
    const m = /<script[^>]*id=["']swagger-data["'][^>]*>([\s\S]*?)<\/script>/i.exec(t);
    if (m) { try { const d = JSON.parse(m[1].replace(/&quot;/g, '"').replace(/&amp;/g, '&')); const sp = d && (d.spec || d); if (sp && sp.paths) return sp; } catch (e) { /* not JSON after all: try the next place */ } }
    if (/^\s*\{/.test(t)) { try { const d = JSON.parse(t); if (d && d.paths) return d; } catch (e) { /* not a whole document: try the next place */ } }
    return null;
  }
  async function readCatalogue(c) {
    const tried = [], seen = [];
    for (const p of SPEC_PATHS) {
      for (const accept of ['application/json', 'text/html']) {
        if (accept === 'text/html' && !/\/(docs?)?$/.test(p)) continue;   // only the documentation pages are asked for HTML
        tried.push(p + (accept === 'text/html' ? ' (page)' : ''));
        let r; try { r = await get(c, p, null, { accept, maxBytes: SPEC_MAX, follow: true }); } catch (e) { if (e.status === 409 || (!c.switch_user && /act as user/.test(e.message))) throw e; seen.push(p + ': ' + String(e.message).replace(/^the gateway answered /, '').slice(0, 140)); continue; }
        if (r.redirectedFrom) tried.push(r.redirectedFrom + ' → ' + r.path);   // an API user with no act-as user is refused everything: say so; a 404 here: try the next place
        const sp = specOf(r); if (sp) return { cat: fromSpec(sp), source: (r.redirectedFrom ? r.redirectedFrom + ' → ' + r.path : p) + (accept === 'text/html' ? ' (embedded in the documentation page)' : ''), tried, seen };
        seen.push(p + ': answered (HTTP ' + r.status + ', ' + (r.json ? 'JSON' : (r.text || '').slice(0, 15).trim() ? 'a page' : 'empty') + ') but no OpenAPI document in it');
        // a documentation page that names its JSON document instead: follow it once
        const m = /["'](\/api\/v2\/[A-Za-z0-9/_\-.]*\.(?:json|jsonopenapi|ya?ml))["']/i.exec(r.text || '') || /url:\s*["']([^"']*\.(?:json|ya?ml))["']/i.exec(r.text || '');
        const lp = m ? (m[1].startsWith('/') ? m[1] : '/api/v2/' + m[1].replace(/^\.?\//, '')) : null;
        if (lp && PATH_RE.test(lp) && !lp.includes('..')) { tried.push(lp); try { const d = await get(c, lp, null, { maxBytes: SPEC_MAX }); const s2 = specOf(d); if (s2) return { cat: fromSpec(s2), source: lp, tried }; } catch (e) { /* not there either: keep looking */ } }
      }
    }
    return { cat: [], source: null, tried, seen };
  }
  // the appliance's catalogue: an OpenAPI document (JSON) at /api/v2/ or linked from its documentation page
  function fromSpec(j) {
    const out = [];
    for (const [p, ops] of Object.entries((j && j.paths) || {})) {
      const full = p.startsWith('/api/v2') ? p : '/api/v2' + (p.startsWith('/') ? p : '/' + p);
      const methods = Object.keys(ops || {}).filter((m) => /^(get|post|put|patch|delete)$/i.test(m)).map((m) => m.toUpperCase());
      out.push({ path: full, methods, summary: String(((ops || {}).get || {}).summary || ((ops || {}).get || {}).description || '').slice(0, 160) });
    }
    return out.filter((x) => PATH_RE.test(x.path)).sort((a, b) => a.path.localeCompare(b.path)).slice(0, 5000);   // ESG 5.x publishes several hundred paths: keep them all so status, queue, quarantine and messages are there to map
  }
  // the integration doctor: every step from the address to a sample read, in order, each with what was seen and the exact
  // fix - so an engineer sees where it breaks (DNS, firewall, certificate, API, login, act-as user, mapping) instead of one error.
  // Read-only like the rest of this module: the login and GET calls the connection already makes, nothing else.
  async function diagnose(who) {
    const steps = [], add = (step, status, detail, fix) => steps.push({ step, status, detail: String(detail || '').slice(0, 900), fix: fix || '' });
    const c = cfg();
    if (!c) { add('Connection settings', 'fail', 'no Libraesva connection is saved', 'Connections & Setup → Libraesva ESG: enter the gateway address (https://…), the API user and its password.'); return finish(); }
    const host = new URL(c.base_url).hostname;
    add('Connection settings', 'ok', c.base_url + ' as ' + c.username + (c.switch_user ? ', acting as ' + c.switch_user : '') + (c.pin ? ', certificate pinned' : ''), '');
    // 1. the name resolves on the platform server
    if (!/^[\d.]+$/.test(host) && !host.includes(':')) {
      try { const r = await (opts.lookup || require('node:dns').promises.lookup)(host); add('Address (DNS)', 'ok', host + ' → ' + (r.address || r), ''); }
      catch (e) { add('Address (DNS)', 'fail', host + ' does not resolve on the platform server (' + (e.code || e.message) + ')', 'Use the gateway\'s IP address in the connection, or add ' + host + ' to the DNS the platform server uses.'); return finish(); }
    } else add('Address (DNS)', 'ok', 'an IP address - no DNS needed', '');
    // 2. HTTPS answers and the certificate is trusted (or pinned); the API exists
    let idx = null;
    try { idx = await http(c.base_url + '/api/v2/', reqOpts(c, { method: 'GET', headers: { Accept: 'application/json' }, captureUntrusted: true })); }
    catch (e) {
      if (e.cert) add('HTTPS and certificate', 'fail', 'the gateway answers but its certificate is not trusted (self-signed or private CA). SHA-256 ' + e.cert.fingerprint256, 'If this is your gateway (compare on the ESG: System → Certificates), paste this fingerprint in "Certificate pin" in the connection settings and test again.');
      else add('HTTPS and certificate', 'fail', netReason(e, c), /ECONNRESET|EPIPE/.test(String(e.sys)) && c.host_name ? 'Compare "Host name" with the name on the ESG certificate (System → Certificates); if unsure, clear it, save and test again.' : /ENOTFOUND|EAI_AGAIN/.test(String(e.sys)) ? 'Use the gateway\'s IP address in Gateway URL and put its name in "Host name".' : 'Check the address, and allow TCP 443 from the platform server to the gateway.');
      return finish();
    }
    add('HTTPS and certificate', 'ok', 'HTTPS answers (HTTP ' + idx.status + ')' + (c.pin ? ' - pinned certificate matches' : ''), '');
    // the bare /api/v2/ index is not an API call: ESG 5.x can answer it 404 while the API is there - ask the login endpoint itself
    // (a GET there is refused as 405 / 400 / 401 when it exists; nothing is sent but the request line)
    if (idx.status === 404) {
      let lp = null; try { lp = await http(c.base_url + '/api/v2/login', reqOpts(c, { method: 'GET', headers: { Accept: 'application/json' }, captureUntrusted: true })); } catch (e) { /* reported below as not found: the index already answered over the same connection */ }
      if (lp && lp.status !== 404) add('REST API v2', 'ok', '/api/v2/login answers (HTTP ' + lp.status + '); the /api/v2/ index page is not published on this appliance, which is normal', '');
      else {
        const said = lp ? htmlReason(lp.text) : '';
        add('REST API v2', 'fail', 'neither /api/v2/ nor /api/v2/login is found (HTTP 404)' + (said ? ': "' + said + '"' : ''),
          isIpHost(c.base_url) && !c.host_name
            ? 'The gateway was reached by its IP address and its web server answered with its default site. Enter the ESG\'s host name (the name in its certificate / the address you open its console with) in "Host name", keep the IP in Gateway URL, save and test again. If it still fails: ESG 5.x has REST API v2 - check the address is the ESG management interface, not a load balancer, the quarantine portal or another site.'
            : 'ESG 5.x has REST API v2 - check the Gateway URL is the ESG management interface (the address you open its web console with), not a load balancer, the user quarantine portal or another site; then check the API user under System → API in the ESG console.');
        return finish();
      }
    } else add('REST API v2', 'ok', '/api/v2/ answers (HTTP ' + idx.status + ')', '');
    // 3. login - the existing login explains refusals (wrong password, act-as user, two-factor, no API)
    try { token = null; await login(c); add('Login', 'ok', 'logged in as ' + c.username + (c.switch_user ? ' acting as ' + c.switch_user : ''), ''); }
    catch (e) {
      const m = String(e.message || e);
      let certName = '';
      if (/reached by its IP address/.test(m)) {
        // the name the appliance's own certificate is issued to - read without trusting it, nothing is sent (httpc fails closed)
        try { await http(c.base_url + '/', { method: 'GET', timeoutMs: 10000, captureUntrusted: true }); }
        catch (e2) { const sj = String((e2.cert && e2.cert.subject) || ''), cn = /CN=([^,\/]+)/.exec(sj); if (cn && /^[A-Za-z0-9*.-]+$/.test(cn[1].trim())) certName = cn[1].trim().replace(/^\*\./, ''); }
      }
      const fix = /reached by its IP address/.test(m) ? (certName ? 'The appliance\'s certificate is issued to ' + certName + '. Enter ' + certName + ' in "Host name" (keep the IP in the Gateway URL), save and test again. ' : 'Open the ESG web console in a browser and note the host name in its address (or on its certificate); enter it in "Host name" (keep the IP in the Gateway URL), save and test again. ') + 'Libraesva\'s web server refuses requests addressed to a name it is not configured for.'
        : /clear "Act as ESG user"/.test(m) ? 'If this is your read-only admin (a normal ESG user), empty "Act as ESG user", save and test again. If it is an API User, enter the act-as user exactly as the ESG shows it under User Management → Users (often the e-mail address).'
        : /gave no reason/.test(m) ? 'Sign in to the ESG web console with the same user name and password to confirm they work and no two-factor sign-in is asked. A normal (read-only admin) user needs no "Act as ESG user". If the user is under User Management → API Users, fill in "Act as ESG user" with a read-only ESG user. If the answer was a web page, enter the ESG appliance\'s own address.'
        : /two-factor|2FA/i.test(m) ? 'On the ESG create an API user without two-factor sign-in (System → Users → API users) and use it here.'
        : /must act as|Act as ESG user" is an existing/i.test(m) ? 'Fill in "Act as ESG user" with an existing read-only ESG user the API user may switch to, then test again.'
        : /HTTP 40[13]/.test(m) ? 'Check the user name and password (they are case-sensitive); the user must be an ESG API user. Re-enter the password and save.'
        : /unsealed/.test(m) ? 'Enter the password again in the connection settings and save.' : 'Read the gateway\'s message above; it names what it refused.';
      add('Login', 'fail', m, fix); return finish();
    }
    // 4. the catalogue and the mapping of the four reads
    let cat = (col().get('state') || {}).catalogue || [];
    let catSrc = null, catSeen = []; try { const rc = await readCatalogue(c); catSeen = rc.seen || []; if (rc.cat.length) { cat = rc.cat; catSrc = rc.source; } } catch (e) { catSeen = [String(e.message).slice(0, 160)]; /* the catalogue is optional: the mapping can still be entered by hand */ }
    add('API catalogue', cat.length ? 'ok' : 'warn', cat.length ? cat.length + ' endpoints read from the appliance' + (catSrc ? ' (' + catSrc + ')' : '') : 'the appliance did not publish its catalogue' + (catSeen.length ? ' - what each place answered: ' + catSeen.slice(0, 6).join('; ') : ''), cat.length ? '' : 'The appliance answers the login but no OpenAPI document was found where the platform looks (' + SPEC_PATHS.join(', ') + ', and the document embedded in the /api/v2/ documentation page). In the ESG web console, open the API documentation (https://<gateway>/api/v2/), or ask Libraesva support for the 5.x GET paths of system status, mail queue, quarantine and message log; then enter them on the Libraesva page → Endpoints (read-only GET paths under /api/v2/).');
    const ep = c.endpoints || {}, miss = Object.keys(KINDS).filter((k) => !ep[k]);
    add('Endpoint mapping', miss.length ? 'warn' : 'ok', miss.length ? 'not mapped yet: ' + miss.join(', ') : 'status, queue, quarantine and messages mapped', miss.length ? 'Libraesva page → Endpoints: pick the catalogue path for each one (read-only GET endpoints).' : '');
    // 5. one sample read through the mapping
    const k1 = ['status', 'queue'].find((k) => ep[k]);
    if (k1) {
      try { const r = await get(c, ep[k1]); add('Sample read', 'ok', k1 + ': ' + ep[k1] + ' answered (HTTP ' + r.status + ', ' + rowsOf(r.json).length + ' row(s))', ''); }
      catch (e) { add('Sample read', 'fail', String(e.message || e), 'The ESG user this connection acts as needs read permission on ' + ep[k1] + ' - give it a read-only role on the ESG.'); }
    }
    add('Mail log to the SIEM (syslog)', 'info', 'the message log reaches the SIEM by syslog, not by this API', 'On the ESG: System → Logging → Remote syslog → the SIEM collector address, TCP or UDP 514. SIEM → Sources then shows "libraesva" events within minutes.');
    return finish();
    function finish() {
      const ok = steps.length > 0 && steps.every((x) => x.status === 'ok' || x.status === 'info' || x.status === 'warn');
      const st = col().get('state') || { id: 'state' }; st.last_diagnose = { at: now(), by: who.user, ok, steps }; col().put(st);
      audit(who, 'esg.diagnose', 'libraesva', { ok, failed: (steps.find((x) => x.status === 'fail') || {}).step || null });
      return { ok, steps, at: new Date(now()).toISOString() };
    }
  }
  // remove the connection: the sealed password, the mapping and the catalogue go; the gateway itself is not touched
  function removeConfig(who) {
    human(who, 'removes the Libraesva connection');
    const c = cfg(); if (!c) throw httpErr(404, 'there is no Libraesva connection to remove');
    col().remove('cfg'); col().remove('state'); token = null;
    audit(who, 'esg.config.remove', 'libraesva', { base_url: c.base_url });
    return summary();
  }
  async function test(who) {
    const c = cfg(); if (!c) throw httpErr(409, 'the Libraesva connection is not set yet');
    const st = col().get('state') || { id: 'state' }, t = now();
    try {
      token = null; await login(c);
      const { cat, source, tried } = await readCatalogue(c);
      Object.assign(st, { last_test: { at: t, by: who.user, ok: true, endpoints: cat.length, message: cat.length ? `logged in; ${cat.length} endpoints in the appliance catalogue (${source})` : 'logged in; the appliance publishes no machine-readable catalogue at ' + tried.join(', ') + ' - enter the endpoint paths by hand (Libraesva page → Endpoints)' },
        catalogue: cat.length ? cat : st.catalogue || [], catalogue_source: source || st.catalogue_source || null });
    } catch (e) { st.last_test = { at: t, by: who.user, ok: false, message: e.message }; }
    col().put(st);
    audit(who, 'esg.test', 'libraesva', { ok: st.last_test.ok, endpoints: st.last_test.endpoints || 0 });
    if (!st.last_test.ok && app.log && app.log.every) app.log.every('esg:test', 600000, 'warn', 'Libraesva connection test failed', { err: String(st.last_test.message).slice(0, 160) });
    return summary();
  }
  function setEndpoints(b, who) {
    human(who, 'maps the Libraesva endpoints');
    const c = cfg(); if (!c) throw httpErr(409, 'the Libraesva connection is not set yet');
    const cat = (col().get('state') || {}).catalogue || [], next = Object.assign({}, c.endpoints || {});
    for (const k of Object.keys(KINDS)) {
      if (b[k] === undefined) continue;
      if (b[k] === '') { delete next[k]; continue; }
      const p = String(b[k]);
      if (!PATH_RE.test(p) || p.includes('..') || p.includes('{')) throw httpErr(400, `${k}: a concrete /api/v2/ path (no {placeholders})`);
      if (cat.length && !cat.some((x) => x.path === p && x.methods.includes('GET'))) throw httpErr(400, `${k}: ${p} is not a GET endpoint in the appliance catalogue`);
      next[k] = p;
    }
    c.endpoints = next; c.by = who.user; c.at = now(); col().put(c);
    audit(who, 'esg.endpoints', 'libraesva', { endpoints: next });
    return summary();
  }
  function rowsOf(j) {
    if (Array.isArray(j)) return j;
    if (j && typeof j === 'object') { for (const k of ['data', 'items', 'results', 'rows', 'records', 'messages', 'list']) if (Array.isArray(j[k])) return j[k]; return [j]; }
    return j === undefined || j === null ? [] : [{ value: j }];
  }
  const flat = (o) => { const r = {}; for (const [k, v] of Object.entries(o || {})) r[String(k).slice(0, 60)] = v !== null && typeof v === 'object' ? JSON.stringify(v).slice(0, 300) : v; return r; };
  async function read(kind, query, who) {
    const c = cfg(); if (!c) throw httpErr(409, 'the Libraesva connection is not set yet');
    const p = (c.endpoints || {})[kind]; if (!p) throw httpErr(409, `no endpoint mapped for ${kind} - map it in the connection settings`);
    const r = await get(c, p, query);
    if (r.json === undefined || r.json === null) throw httpErr(502, `${p} did not answer JSON`);
    const all = rowsOf(r.json), rows = all.slice(0, MAX_ROWS).map((x) => (x && typeof x === 'object' ? flat(x) : { value: x }));
    if (kind === 'quarantine' || kind === 'messages') audit(who, 'esg.read.' + kind, 'libraesva', { path: p, query: Object.keys(query || {}), rows: rows.length });
    return { kind, path: p, at: now(), rows, total: all.length, capped: all.length > MAX_ROWS };
  }
  return { diagnose, summary, setConfig, removeConfig, test, setEndpoints, read, KINDS };
}

function registerLibraesvaRoutes(srv, app, E) {
  const { body, param } = require('./check');
  srv.route('GET', '/esg', (ctx) => { ctx.need('viewer'); return E.summary(); });
  srv.route('POST', '/esg/config', (ctx) => {
    ctx.need('admin');   // a security-integration credential
    const b = body(ctx.body).str('base_url', { required: true, max: 200, re: /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/?$/, msg: 'base_url must be https://<gateway host>[:port]' })
      .str('username', { required: true, max: 120 }).str('password', { max: 200 }).str('switch_user', { max: 120 }).str('host_name', { max: 253, host: true })
      .str('pin', { max: 100, re: /^([0-9A-Fa-f]{2}:?){32}$|^$/, msg: 'pin must be a SHA-256 certificate fingerprint' }).done();
    return E.setConfig(b, ctx.who);
  });
  srv.route('DELETE', '/esg/config', (ctx) => { ctx.need('admin'); return E.removeConfig(ctx.who); });
  srv.route('POST', '/esg/test', async (ctx) => { ctx.need('operator'); return E.test(ctx.who); });
  srv.route('POST', '/esg/diagnose', async (ctx) => { ctx.need('operator'); return E.diagnose(ctx.who); });
  srv.route('POST', '/esg/endpoints', (ctx) => {
    ctx.need('admin');
    const v = body(ctx.body).str('status', { max: 200 }).str('queue', { max: 200 }).str('quarantine', { max: 200 }).str('messages', { max: 200 }).done();
    for (const k of Object.keys(E.KINDS)) if ((ctx.body || {})[k] === '') v[k] = '';
    return E.setEndpoints(v, ctx.who);
  });
  srv.route('GET', '/esg/read/:kind', async (ctx) => {
    const kind = param(ctx.params.kind, 'kind'); if (!E.KINDS[kind]) throw Object.assign(new Error('kind must be status, queue, quarantine or messages'), { status: 400 });
    ctx.need(E.KINDS[kind]);   // quarantine and the message log name senders and recipients (PDPL)
    const q = {}; for (const [k, v] of Object.entries(ctx.query || {})) {
      if (!/^[a-z_]{1,30}$/i.test(k)) throw Object.assign(new Error('query keys: letters and _ only'), { status: 400 });
      if (typeof v !== 'string' || v.length > 200 || /[\u0000-\u001f]/.test(v)) throw Object.assign(new Error(`query ${k}: up to 200 characters of text`), { status: 400 });
      q[k] = v; if (Object.keys(q).length > 8) throw Object.assign(new Error('at most 8 query parameters'), { status: 400 });
    }
    return E.read(kind, q, ctx.who);
  });
}

module.exports = { createLibraesva, registerLibraesvaRoutes };
