// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
const WS = require('./ws');
/*
 * Remote console - log in to a server from the portal ({P} = /api/itam, Servers & Virtualization -> Remote Console).
 * Windows over RDP, Linux / Solaris / ESXi / Nutanix CVM / network devices over SSH, through an Apache Guacamole gateway (guacd,
 * 127.0.0.1:4822) on the platform server; the vSphere Client and Nutanix Prism web consoles open directly (launcher - not
 * proxied, not recorded, and the page says so).
 *   1. request   an operator asks for one server, one protocol, 15 minutes to 8 hours (the admin's maximum), with a reason
 *   2. approve   another person (operator / admin, or one of the named approvers) - never the requester, never a service / AI
 *   3. connect   only the requester, only inside the approved window: a one-time ticket (60 s) opens the tunnel. The person
 *                types their OWN account and password into the remote login - the platform never stores, sees in a log, or
 *                fills in a credential (guacd asks the browser; the tunnel relays the answer without reading it)
 *   4. record    every gateway session is recorded by guacd (screen, not keystrokes) to the recordings folder; who, when,
 *                which server, how long and the file are kept, and admins can download a recording (audited)
 *   5. end       at the end of the window the session is closed; the requester or an admin can end it earlier
 * File transfer, drive mapping and printing are off; copy from the server is off unless an admin allows it.
 *   GET  /console                           operator  servers, my requests, waiting for me, active windows, live sessions, settings
 *   POST /console/requests                  operator  {asset_id, protocol, minutes, reason, ticket?}                    audited
 *   POST /console/requests/:id/decide       operator  {decision: approve|reject, note?}   not the requester              audited
 *   POST /console/requests/:id/cancel       operator  the requester, while pending                                       audited
 *   POST /console/requests/:id/end          operator  {reason}   the requester or an admin                               audited
 *   POST /console/requests/:id/ticket       operator  the requester, inside the window → {token} (rdp/ssh) or {url} (web)  audited
 *   GET  /console/tunnel?token=&width=&height=&dpi=   WebSocket (sub-protocol "guacamole") → guacd                       audited
 *   GET  /console/recordings                admin     sessions with their recording
 *   GET  /console/recordings/:id            admin     download one recording                                           audited
 *   PUT  /console/bmc/:asset_id             admin     {kind: idrac|ilo|xclarity|ipmi, address, port?}  a physical server's out-of-band
 *                                                     controller (iDRAC / iLO / XClarity / IPMI web)                             audited
 *   DELETE /console/bmc/:asset_id           admin     forget the controller                                            audited
 *   POST /console/bmc/:asset_id/check       operator  can the platform server reach the controller (TCP, no login)? → {reachable, ms}
 * Out-of-band ("oob"): the controller's own HTML5 virtual console, which keeps running while the operating system reboots - so
 * POST, BIOS / UEFI, the RAID controller and the boot loader can be followed to the login screen. Same request / approve / window
 * rules; the console opens directly from the browser with the engineer's OWN controller account - not proxied, not recorded, and
 * the platform never stores a controller credential. Power state is read in the controller (it needs a login), never guessed.
 *   POST /console/config                    admin     {enabled, guacd_host, guacd_port, recording_dir, max_minutes, clipboard, rdp_security, rdp_ignore_cert, approvers[]}
 */
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const PROTOS = ['rdp', 'ssh', 'web', 'oob'];
const OOB_KINDS = { idrac: { label: 'Dell iDRAC', console: 'Virtual Console' }, ilo: { label: 'HPE iLO', console: 'Integrated Remote Console' },
  xclarity: { label: 'Lenovo XClarity Controller', console: 'Remote Console' }, ipmi: { label: 'BMC (IPMI web)', console: 'KVM / Remote Control' } };
const HOST_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$/i;
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
// which controller a server most likely has, from its vendor - a suggestion for the administrator, never applied on its own
function oobSuggest(a) {
  const v = [a.vendor, a.model].join(' ').toLowerCase();
  if (/\bdell\b|poweredge/.test(v)) return 'idrac';
  if (/\bhpe?\b|hewlett|proliant|synergy/.test(v)) return 'ilo';
  if (/lenovo|thinksystem|thinkagile/.test(v)) return 'xclarity';
  if (/supermicro|gigabyte|asus|inspur|huawei|fujitsu|cisco ucs/.test(v)) return 'ipmi';
  return null;
}
const DEFAULTS = { enabled: false, guacd_host: '127.0.0.1', guacd_port: 4822, recording_dir: '/var/lib/sentra-itam/console-recordings', max_minutes: 240,
  clipboard: 'paste', rdp_security: 'nla', rdp_ignore_cert: true, approvers: [] };
const OPEN_STATES = ['pending', 'approved'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();

// ---- the Guacamole protocol: LENGTH.VALUE,LENGTH.VALUE; with LENGTH in Unicode code points
function enc(...a) { return a.map((x) => { const v = String(x); return [...v].length + '.' + v; }).join(',') + ';'; }
function createParser() {
  let buf = '';
  return function feed(chunk) {   // → complete instructions [{ op, args, raw }]; a partial one waits for the next chunk
    buf += chunk; const out = []; let start = 0;
    for (;;) {
      let i = start; const els = [];
      let complete = false;
      for (;;) {
        const dot = buf.indexOf('.', i);
        if (dot < 0) break;
        const len = Number(buf.slice(i, dot));
        if (!Number.isInteger(len) || len < 0 || dot - i > 9) throw new Error('malformed Guacamole instruction');
        let j = dot + 1, n = 0;
        while (n < len && j < buf.length) { const c = buf.charCodeAt(j); j += c >= 0xd800 && c <= 0xdbff ? 2 : 1; n++; }
        if (n < len || j >= buf.length) break;
        els.push(buf.slice(dot + 1, j));
        const term = buf[j];
        if (term === ';') { complete = true; i = j + 1; break; }
        if (term !== ',') throw new Error('malformed Guacamole instruction');
        i = j + 1;
      }
      if (!complete) break;
      out.push({ op: els[0], args: els.slice(1), raw: buf.slice(start, i) }); start = i;
    }
    buf = buf.slice(start);
    if (buf.length > 4 * 1024 * 1024) throw new Error('Guacamole instruction too large');
    return out;
  };
}
// select → args → size/audio/video/image/timezone → connect → ready. Resolves { sock, id, rest } (instructions after ready)
function guacdHandshake({ host, port, protocol, params, width, height, dpi, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port }), feed = createParser();
    let stage = 'args', done = false;
    const fail = (e) => { if (done) return; done = true; sock.destroy(); reject(e); };
    const t = setTimeout(() => fail(httpErr(504, 'the console gateway (guacd) did not answer in time')), timeoutMs);
    sock.setEncoding('utf8');
    sock.on('connect', () => sock.write(enc('select', protocol)));
    sock.on('error', (e) => fail(httpErr(502, 'the console gateway (guacd) is not reachable at ' + host + ':' + port + ' (' + e.code + ')')));
    sock.on('close', () => fail(httpErr(502, 'the console gateway closed the connection during the handshake')));
    sock.on('data', function onData(d) {
      let ins;
      try { ins = feed(d); } catch (e) { return fail(httpErr(502, e.message)); }
      for (let k = 0; k < ins.length; k++) {
        const x = ins[k];
        if (x.op === 'error') return fail(httpErr(502, 'console gateway: ' + s(x.args[0], 200)));
        if (stage === 'args' && x.op === 'args') {
          const values = x.args.map((name) => (/^VERSION_/.test(name) ? name : params[name] == null ? '' : String(params[name])));
          sock.write(enc('size', width, height, dpi) + enc('audio') + enc('video') + enc('image', 'image/png', 'image/jpeg', 'image/webp') + enc('timezone', 'Asia/Riyadh') + enc('connect', ...values));
          stage = 'ready';
        } else if (stage === 'ready' && x.op === 'ready') {
          clearTimeout(t); done = true; sock.removeAllListeners('data'); sock.removeAllListeners('close'); sock.removeAllListeners('error');
          return resolve({ sock, id: x.args[0], rest: ins.slice(k + 1).map((y) => y.raw).join('') });
        }
      }
    });
  });
}

function createRemoteConsole(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {}, error() {}, every() {} };
  const reqs = () => store.collection('console_requests'), sess = () => store.collection('console_sessions'), cfgCol = () => store.collection('console_config');
  const tickets = new Map(), live = new Map();   // one-time tickets (memory only, 60 s) · live tunnels by session id
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'console.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const bmcCol = () => store.collection('console_bmc');
  const cfg = () => Object.assign({}, DEFAULTS, opts.config || {}, (app.config && app.config.console) || {}, cfgCol().get('config') || {});   // an admin's saved settings win

  // what a server offers: from its OS / type / vendor in the register
  function oobOf(a) {
    const b = bmcCol().get(a.id); if (!b) return null;
    const k = OOB_KINDS[b.kind] || OOB_KINDS.ipmi;
    return { protocol: 'oob', port: b.port, label: k.label + ' console', kind: b.kind, address: b.address, url: 'https://' + b.address + (b.port === 443 ? '' : ':' + b.port) + '/' };
  }
  function protocolsOf(a) {
    const t = [a.os, a.model, a.vendor, a.name].join(' ').toLowerCase(), out = [], oob = oobOf(a);
    if (!IP_RE.test(String(a.mgmt_ip || ''))) return oob ? [oob] : [];   // only the controller is known
    if (/windows/.test(t)) out.push({ protocol: 'rdp', port: 3389, label: 'Remote Desktop' });
    if (/linux|unix|solaris|sunos|aix|centos|rhel|red hat|ubuntu|debian|suse|esxi|ahv|nutanix|cvm|aos/.test(t) || a.type === 'network' || a.type === 'storage') out.push({ protocol: 'ssh', port: 22, label: 'SSH terminal' });
    if (/esxi|vcenter|vmware/.test(t)) out.push({ protocol: 'web', port: 443, label: 'vSphere Client', url: 'https://' + a.mgmt_ip + '/' });
    if (/nutanix|prism|ahv|cvm/.test(t)) out.push({ protocol: 'web', port: 9440, label: 'Nutanix Prism', url: 'https://' + a.mgmt_ip + ':9440/' });
    if (!out.length) out.push({ protocol: 'rdp', port: 3389, label: 'Remote Desktop (OS not known)' }, { protocol: 'ssh', port: 22, label: 'SSH terminal (OS not known)' });
    if (oob) out.push(oob);
    return out;
  }
  function targets() {
    return store.collection('assets').all((a) => ['server', 'vm', 'network', 'storage'].includes(a.type) && a.status === 'in_use' && (IP_RE.test(String(a.mgmt_ip || '')) || !!bmcCol().get(a.id)))
      .slice(0, 5000).map((a) => { const o = oobOf(a); return { id: a.id, name: a.name, type: a.type, os: a.os || '', site: a.site || '', ip: a.mgmt_ip || (o ? o.address : ''), bmc: o ? { kind: o.kind, address: o.address, port: o.port } : null, protocols: protocolsOf(a) }; });
  }
  // physical servers and whether their out-of-band controller is recorded (administrators set it up here)
  function controllers() {
    return store.collection('assets').all((a) => a.type === 'server' && !['retired', 'disposed'].includes(a.status)).slice(0, 3000).map((a) => {
      const b = bmcCol().get(a.id);
      return { id: a.id, name: a.name, vendor: a.vendor || '', model: a.model || '', site: a.site || '', status: a.status || '', serial: a.serial || '', bmc: b ? { kind: b.kind, address: b.address, port: b.port, by: b.by, at: b.at } : null, suggest: oobSuggest(a) };
    }).sort((x, y) => (x.bmc ? 1 : 0) - (y.bmc ? 1 : 0) || String(x.name).localeCompare(String(y.name)));
  }
  function setBmc(id0, input, who) {
    const id = param(id0);
    const b = body(input).oneOf('kind', Object.keys(OOB_KINDS), { required: true }).str('address', { required: true, max: 253, re: HOST_RE, msg: 'address must be the controller IP address or host name (no https://, no path)' })
      .int('port', { min: 1, max: 65535 }).done();
    person(who, 'record a server controller');
    const a = store.collection('assets').get(id);
    if (!a || a.type !== 'server') throw httpErr(404, 'physical server ' + id + ' not found (an out-of-band controller is recorded for type "server")');
    if (IP_RE.test(b.address) && b.address.split('.').some((x) => Number(x) > 255)) throw httpErr(400, 'address is not a valid IPv4 address');
    const clash = bmcCol().all((x) => x.id !== id && same(x.address, b.address) && (x.port || 443) === (b.port || 443))[0];
    if (clash) throw httpErr(409, 'address ' + b.address + ' is already recorded as the controller of another server (' + ((store.collection('assets').get(clash.id) || {}).name || clash.id) + ')');
    const prev = bmcCol().get(id) || null;
    const rec = { id, kind: b.kind, address: b.address.toLowerCase(), port: b.port || 443, by: who.user, at: iso() };
    bmcCol().put(rec);
    audit(who, 'bmc.set', id, { asset: a.name, kind: rec.kind, address: rec.address, port: rec.port, before: prev ? { kind: prev.kind, address: prev.address, port: prev.port } : null });
    return { bmc: rec };
  }
  function delBmc(id0, who) {
    const id = param(id0), prev = bmcCol().get(id);
    if (!prev) throw httpErr(404, 'no controller is recorded for ' + id);
    person(who, 'remove a server controller');
    bmcCol().remove(id);
    audit(who, 'bmc.remove', id, { asset: (store.collection('assets').get(id) || {}).name || id, kind: prev.kind, address: prev.address });
    return { ok: true };
  }
  // a TCP connect from the platform server: answers "can it be reached", nothing about power or health (that needs a login)
  function checkBmc(id0) {
    const id = param(id0), b = bmcCol().get(id);
    if (!b) throw httpErr(404, 'no controller is recorded for ' + id);
    const t0 = Date.now(), connect = opts.connect || ((port, host) => net.connect(port, host));
    return new Promise((resolve) => {
      let done = false; const sock = connect(b.port, b.address);
      const fin = (ok, why) => { if (done) return; done = true; try { sock.destroy(); } catch (e) { /* already closed */ } resolve({ reachable: ok, ms: ok ? Date.now() - t0 : null, error: ok ? null : why, address: b.address, port: b.port, checked_at: iso() }); };
      sock.setTimeout(3000, () => fin(false, 'no answer in 3 s'));
      sock.on('connect', () => fin(true));
      sock.on('error', (e) => fin(false, e.code === 'ECONNREFUSED' ? 'refused - nothing listens on ' + b.port : e.code === 'ENOTFOUND' ? 'the name does not resolve' : 'not reachable (' + (e.code || 'error') + ')'));
    });
  }
  const inWindow = (r) => r.status === 'approved' && Date.parse(r.window_end) > now();
  const canDecide = (r, who) => {
    const c = cfg();
    if (same(r.by, who.user) || !isHuman(who.user) || (RANK[who.role] || 0) < RANK.operator) return false;
    return !c.approvers.length || who.role === 'admin' || c.approvers.some((x) => same(x, who.user));
  };
  const pub = (r, who) => Object.assign({}, r, { can_decide: r.status === 'pending' && canDecide(r, who), mine: same(r.by, who.user), left_s: inWindow(r) ? Math.round((Date.parse(r.window_end) - now()) / 1000) : 0,
    live: [...live.values()].filter((x) => x.request_id === r.id).length });

  function view(who) {
    const c = cfg(), all = reqs().all(() => true).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    const admin = who.role === 'admin';
    return {
      settings: { enabled: c.enabled, max_minutes: c.max_minutes, clipboard: c.clipboard, approvers: c.approvers, guacd: admin ? c.guacd_host + ':' + c.guacd_port : undefined, recording_dir: admin ? c.recording_dir : undefined, rdp_security: admin ? c.rdp_security : undefined, rdp_ignore_cert: admin ? c.rdp_ignore_cert : undefined },
      targets: targets(),
      controllers: admin ? controllers() : undefined,
      oob_kinds: Object.keys(OOB_KINDS).map((k) => ({ kind: k, label: OOB_KINDS[k].label, console: OOB_KINDS[k].console })),
      mine: all.filter((r) => same(r.by, who.user)).slice(0, 100).map((r) => pub(r, who)),
      waiting: all.filter((r) => r.status === 'pending' && canDecide(r, who)).map((r) => pub(r, who)),
      active: all.filter((r) => inWindow(r) && (admin || same(r.by, who.user))).map((r) => pub(r, who)),
      live: [...live.values()].filter((x) => admin || same(x.user, who.user)).map((x) => ({ id: x.id, request_id: x.request_id, user: x.user, asset_name: x.asset_name, protocol: x.protocol, started_at: x.started_at })),
      generated_at: iso(),
    };
  }
  function request(input, who) {
    const c = cfg();
    const b = body(input).str('asset_id', { required: true, id: true }).oneOf('protocol', PROTOS, { required: true })
      .int('minutes', { required: true, min: 15, max: c.max_minutes }).str('reason', { required: true, min: 10, max: 500 }).str('ticket', { max: 60 }).done();
    person(who, 'request console access');
    const t = targets().find((x) => x.id === b.asset_id);
    if (!t) throw httpErr(404, 'server ' + b.asset_id + ' is not a console target (an in-use server, VM, network or storage device with a management IP or a recorded controller)');
    const pr = t.protocols.find((x) => x.protocol === b.protocol);
    if (!pr) throw httpErr(400, 'protocol must be one of ' + t.protocols.map((x) => x.protocol).join(', ') + ' for ' + t.name);
    if (reqs().all((r) => same(r.by, who.user) && r.asset_id === t.id && r.protocol === b.protocol && OPEN_STATES.includes(r.status) && (r.status === 'pending' || inWindow(r))).length)
      throw httpErr(409, 'you already have an open request for ' + t.name + ' (' + b.protocol + ')');
    const r = { id: 'cr_' + crypto.randomBytes(6).toString('hex'), asset_id: t.id, asset_name: t.name, ip: t.ip, protocol: b.protocol, port: pr.port, label: pr.label, url: pr.url || null, kind: pr.kind || null,
      minutes: b.minutes, reason: b.reason, ticket: b.ticket || '', by: who.user, role: who.role, at: iso(), status: 'pending' };
    reqs().put(r);
    audit(who, 'request', r.id, { asset: t.name, ip: t.ip, protocol: b.protocol, minutes: b.minutes, reason: b.reason, ticket: b.ticket || '' });
    return { request: pub(r, who) };
  }
  function decide(id0, input, who) {
    const id = param(id0);
    const b = body(input).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    person(who, 'approve console access');
    const r = reqs().get(id); if (!r) throw httpErr(404, 'request ' + id + ' not found');
    if (r.status !== 'pending') throw httpErr(409, 'request ' + id + ' is already ' + r.status);
    if (same(r.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for this access and cannot also approve it');
    if (!canDecide(r, who)) throw httpErr(403, 'only the named console approvers (or an administrator) decide console access');
    const t = now();
    const next = reqs().patch(id, (x) => {
      x.status = b.decision === 'approve' ? 'approved' : 'rejected'; x.decided_by = who.user; x.decided_at = iso(t); x.note = b.note || '';
      if (b.decision === 'approve') { x.window_start = iso(t); x.window_end = iso(t + x.minutes * 60000); }
    });
    audit(who, b.decision, id, { asset: r.asset_name, protocol: r.protocol, requested_by: r.by, minutes: r.minutes, note: b.note || '', window_end: next.window_end || null });
    return { request: pub(next, who) };
  }
  function cancel(id0, who) {
    const id = param(id0), r = reqs().get(id); if (!r) throw httpErr(404, 'request ' + id + ' not found');
    if (!same(r.by, who.user)) throw httpErr(403, 'only the person who asked can cancel the request');
    if (r.status !== 'pending') throw httpErr(409, 'request ' + id + ' is already ' + r.status);
    reqs().patch(id, (x) => { x.status = 'cancelled'; x.ended_at = iso(); });
    audit(who, 'cancel', id, { asset: r.asset_name });
    return { ok: true };
  }
  function killFor(requestId, why) {
    for (const x of live.values()) if (x.request_id === requestId) x.kill(why);
  }
  function end(id0, input, who) {
    const id = param(id0), b = body(input).str('reason', { required: true, min: 3, max: 300 }).done();
    const r = reqs().get(id); if (!r) throw httpErr(404, 'request ' + id + ' not found');
    if (!same(r.by, who.user) && who.role !== 'admin') throw httpErr(403, 'only the person who asked, or an administrator, can end the access');
    if (!inWindow(r)) throw httpErr(409, 'request ' + id + ' is not active');
    reqs().patch(id, (x) => { x.status = 'ended'; x.ended_at = iso(); x.ended_by = who.user; x.end_reason = b.reason; });
    killFor(id, 'access ended by ' + who.user);
    audit(who, 'end', id, { asset: r.asset_name, reason: b.reason });
    return { ok: true };
  }
  function ticket(id0, who) {
    const id = param(id0), r = reqs().get(id); if (!r) throw httpErr(404, 'request ' + id + ' not found');
    if (!same(r.by, who.user)) throw httpErr(403, 'only the person whose access was approved can connect');
    if (!inWindow(r)) throw httpErr(409, r.status === 'pending' ? 'the request is waiting for approval' : 'the access window is not open (' + r.status + ')');
    if (r.protocol === 'oob') {
      const k = OOB_KINDS[r.kind] || OOB_KINDS.ipmi;
      audit(who, 'oob.open', id, { asset: r.asset_name, kind: r.kind, url: r.url });
      return { url: r.url, note: 'The ' + k.label + ' opens in a new tab - log in with your own controller account and open ' + k.console + ' to follow the reboot (POST, BIOS, boot loader, login screen). It is not proxied or recorded by the platform.' };
    }
    if (r.protocol === 'web') {
      audit(who, 'web.open', id, { asset: r.asset_name, url: r.url });
      return { url: r.url, note: 'The web console opens directly from your browser - it is not proxied or recorded by the platform.' };
    }
    if (!cfg().enabled) throw httpErr(409, 'the console gateway is not switched on yet - an administrator enables it in the settings after installing guacd');
    for (const [k, v] of tickets) if (v.exp < now()) tickets.delete(k);
    const token = crypto.randomBytes(24).toString('hex');
    tickets.set(token, { request_id: id, user: who.user, exp: now() + 60000 });
    audit(who, 'ticket', id, { asset: r.asset_name, protocol: r.protocol });
    return { token, expires_in: 60, tunnel: '/api/itam/console/tunnel' };
  }
  function recordingPath(c, name) {
    const dir = path.resolve(c.recording_dir), p = path.resolve(dir, name);
    if (!p.startsWith(dir + path.sep)) throw httpErr(400, 'bad recording name');
    return p;
  }
  async function tunnel(ctx, req, socket, head) {
    ctx.need('operator');
    const q = ctx.query || {}, tok = String(q.token || '');
    if (!/^[a-f0-9]{48}$/.test(tok)) throw httpErr(400, 'token is required');
    const t = tickets.get(tok); tickets.delete(tok);   // one use, whatever happens next
    if (!t || t.exp < now()) throw httpErr(403, 'the console ticket has expired - press Connect again');
    if (!same(t.user, ctx.user)) throw httpErr(403, 'the console ticket belongs to someone else');
    const r = reqs().get(t.request_id);
    if (!r || !inWindow(r)) throw httpErr(403, 'the access window is not open');
    const c = cfg(); if (!c.enabled) throw httpErr(409, 'the console gateway is not switched on');
    const int = (v, lo, hi, d) => { const n = Number(v); return Number.isInteger(n) && n >= lo && n <= hi ? n : d; };
    const width = int(q.width, 320, 7680, 1280), height = int(q.height, 240, 4320, 800), dpi = int(q.dpi, 72, 400, 96);
    const sid = 'cs_' + crypto.randomBytes(6).toString('hex'), recName = r.id + '-' + sid + '.guac';
    const common = { hostname: r.ip, port: String(r.port), 'recording-path': c.recording_dir, 'recording-name': recName, 'create-recording-path': 'true',
      'recording-include-keys': '', 'disable-copy': c.clipboard === 'both' ? '' : 'true', 'disable-paste': c.clipboard === 'off' ? 'true' : '' };
    const params = r.protocol === 'rdp'
      ? Object.assign(common, { security: c.rdp_security, 'ignore-cert': c.rdp_ignore_cert ? 'true' : '', 'resize-method': 'display-update', 'enable-drive': '', 'enable-printing': '', 'disable-audio': 'true', 'enable-sftp': '', 'enable-audio-input': '' })
      : Object.assign(common, { 'enable-sftp': '', 'server-alive-interval': '30' });
    const ws = WS.accept(req, socket, head, { protocol: 'guacamole' });   // upgraded: from here errors close the socket with a Guacamole status
    let g;
    try { g = await guacdHandshake({ host: c.guacd_host, port: c.guacd_port, protocol: r.protocol, params, width, height, dpi }); } catch (e) {
      L.every('console:guacd', 60000, 'warn', 'remote console: gateway handshake failed', { request: r.id, err: e.message });
      audit(ctx.who, 'session.fail', r.id, { asset: r.asset_name, protocol: r.protocol, error: s(e.message, 200) });
      ws.send(enc('error', e.message, '514')); ws.close(1000, '514'); return;
    }
    const x = { id: sid, request_id: r.id, user: ctx.user, asset_id: r.asset_id, asset_name: r.asset_name, ip: r.ip, protocol: r.protocol, started_at: iso(), recording: recName, up: 0, down: 0, ended: false };
    sess().put({ id: sid, request_id: r.id, user: ctx.user, asset_id: r.asset_id, asset_name: r.asset_name, ip: r.ip, protocol: r.protocol, started_at: x.started_at, recording: recName, guacd_id: g.id });
    audit(ctx.who, 'session.start', sid, { request: r.id, asset: r.asset_name, ip: r.ip, protocol: r.protocol, approved_by: r.decided_by, recording: recName });
    const finish = (why) => {
      if (x.ended) return; x.ended = true; live.delete(sid); clearTimeout(x.timer);
      try { g.sock.end(enc('disconnect')); } catch (e) { /* gateway already gone */ }
      g.sock.destroy();
      if (!ws.closed) { ws.send(enc('error', why, '521')); ws.close(1000, '521'); }
      sess().patch(sid, (y) => { y.ended_at = iso(); y.end_reason = why; y.bytes_up = x.up; y.bytes_down = x.down; });
      audit(ctx.who, 'session.end', sid, { request: r.id, asset: r.asset_name, reason: why, seconds: Math.round((now() - Date.parse(x.started_at)) / 1000) });
    };
    x.kill = finish; live.set(sid, x);
    x.timer = setTimeout(() => finish('the approved access window ended'), Math.max(0, Date.parse(r.window_end) - now())); if (x.timer.unref) x.timer.unref();
    ws.send(enc('', sid));                 // the tunnel UUID the browser expects first
    if (g.rest) ws.send(g.rest);
    const down = createParser(), up = createParser();
    g.sock.on('data', (d) => {
      try { const ins = down(d); if (ins.length) { const m = ins.map((y) => y.raw).join(''); x.down += m.length; ws.send(m); } } catch (e) { finish('gateway protocol error'); }
    });
    g.sock.on('close', () => finish('the server or the gateway closed the session'));
    g.sock.on('error', (e) => L.every('console:sock', 60000, 'warn', 'remote console: gateway socket error', { session: sid, err: e.code || e.message }));
    ws.on('message', (m) => {
      let ins; try { ins = up(m); } catch (e) { return finish('browser protocol error'); }
      const fwd = [];
      for (const y of ins) {
        if (y.op === '') { if (y.args[0] === 'ping') ws.send(enc('', 'ping', y.args[1] || '')); continue; }   // tunnel keep-alive, answered here
        if (y.op === 'file' || y.op === 'pipe') continue;                                                      // no file transfer
        fwd.push(y.raw);
      }
      if (fwd.length) { const out = fwd.join(''); x.up += out.length; try { g.sock.write(out); } catch (e) { finish('write to the gateway failed'); } }
    });
    ws.on('close', () => finish('the browser closed the console'));
  }
  function recordings() {
    const c = cfg();
    return { recordings: sess().all(() => true).sort((a, b) => String(b.started_at).localeCompare(String(a.started_at))).slice(0, 500).map((x) => {
      let size = null; try { size = fs.statSync(recordingPath(c, x.recording)).size; } catch (e) { size = null; /* not written (yet), or another server's folder */ }
      return Object.assign({}, x, { size });
    }) };
  }
  function download(ctx) {
    const id = param(ctx.params.id), x = sess().get(id); if (!x) throw httpErr(404, 'session ' + id + ' not found');
    const p = recordingPath(cfg(), x.recording);
    if (!fs.existsSync(p)) throw httpErr(404, 'the recording of ' + id + ' is not in the recordings folder');
    audit(ctx.who, 'recording.download', id, { asset: x.asset_name, user: x.user, recording: x.recording });
    ctx.file(p, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="' + x.recording + '"' });
  }
  function configure(input, who) {
    const b = body(input).bool('enabled').str('guacd_host', { host: true }).int('guacd_port', { min: 1, max: 65535 })
      .str('recording_dir', { re: /^\/[A-Za-z0-9._/-]{1,200}$/, msg: 'recording_dir must be an absolute folder path' }).int('max_minutes', { min: 15, max: 480 })
      .oneOf('clipboard', ['off', 'paste', 'both']).oneOf('rdp_security', ['nla', 'tls', 'rdp', 'any']).bool('rdp_ignore_cert').list('approvers', { max: 50, item: 'str', itemMax: 120 }).done();
    person(who, 'change console settings');
    const prev = cfgCol().get('config') || {}, next = Object.assign({}, prev, b, { id: 'config', updated_by: who.user, updated_at: iso() });
    cfgCol().put(next);
    audit(who, 'config', 'console', { changed: Object.keys(b), enabled: next.enabled, approvers: next.approvers || [] });
    return { settings: view(who).settings };
  }
  // the window closes even when nobody is connected: approved and past the end → expired, any live tunnel is closed
  function sweep() {
    for (const r of reqs().all((x) => x.status === 'approved' && Date.parse(x.window_end) <= now())) {
      reqs().patch(r.id, (x) => { x.status = 'expired'; x.ended_at = iso(); });
      killFor(r.id, 'the approved access window ended');
    }
  }
  if (!(app.noTimers || opts.noTimer)) { const t = setInterval(guardOf(app, 'console.expire', sweep), 30000); if (t.unref) t.unref(); }
  return { view, setBmc, delBmc, checkBmc, controllers, request, decide, cancel, end, ticket, tunnel, recordings, download, configure, sweep, targets, live, _enc: enc, _parser: createParser };
}

function registerRemoteConsole(srv, app, C) {
  const S = C && C.view ? C : createRemoteConsole(app, C || {});
  app.addons = app.addons || {}; app.addons.remoteConsole = S;
  srv.route('GET', '/console', (ctx) => { ctx.need('operator'); return S.view(ctx.who); });
  srv.route('POST', '/console/requests', (ctx) => { ctx.need('operator'); return S.request(ctx.body, ctx.who); });
  srv.route('POST', '/console/requests/:id/decide', (ctx) => { ctx.need('operator'); return S.decide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/console/requests/:id/cancel', (ctx) => { ctx.need('operator'); return S.cancel(ctx.params.id, ctx.who); });
  srv.route('POST', '/console/requests/:id/end', (ctx) => { ctx.need('operator'); return S.end(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/console/requests/:id/ticket', (ctx) => { ctx.need('operator'); return S.ticket(ctx.params.id, ctx.who); }, { noDedup: true });
  srv.route('GET', '/console/recordings', (ctx) => { ctx.need('admin'); return S.recordings(); });
  srv.route('GET', '/console/recordings/:id', (ctx) => { ctx.need('admin'); return S.download(ctx); });
  srv.route('PUT', '/console/bmc/:id', (ctx) => { ctx.need('admin'); return S.setBmc(ctx.params.id, ctx.body, Object.assign({ ip: ctx.ip }, ctx.who)); });
  srv.route('DELETE', '/console/bmc/:id', (ctx) => { ctx.need('admin'); return S.delBmc(ctx.params.id, Object.assign({ ip: ctx.ip }, ctx.who)); });
  srv.route('POST', '/console/bmc/:id/check', (ctx) => { ctx.need('operator'); return S.checkBmc(ctx.params.id); }, { noDedup: true });
  srv.route('POST', '/console/config', (ctx) => { ctx.need('admin'); return S.configure(ctx.body, ctx.who); });
  if (srv.upgrade) srv.upgrade('/console/tunnel', (ctx, req, socket, head) => { ctx.need('operator'); return S.tunnel(ctx, req, socket, head); });
  return S;
}

module.exports = { createRemoteConsole, registerRemoteConsole, enc, createParser, guacdHandshake };
