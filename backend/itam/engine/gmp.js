// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * A small Greenbone Management Protocol (GMP) client for the vulnerability scans (engine/vulnscan.js). GMP is XML over the
 * gvmd unix socket (or TLS to gvmd's port). Only a FIXED list of commands can be sent - anything else, or a request whose
 * root tag is not its command, is refused before a byte is written. Every value is XML-escaped. The parser is a small,
 * non-validating one: no DTD, no external entities (a report is attacker-influenced text - banners, host names).
 *   const g = await openGmp({ socket | host, port, pin, timeoutMs }); await g.send('authenticate', xml); g.close();
 */
const net = require('node:net');
const tls = require('node:tls');

const ALLOWED = new Set(['authenticate', 'get_version', 'get_scan_configs', 'get_port_lists', 'get_scanners', 'create_target', 'create_task', 'start_task', 'stop_task', 'get_tasks', 'get_reports']);
const MAX_BYTES = 96 * 1024 * 1024;

const xesc = (v) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
function unesc(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#\d+|lt|gt|amp|quot|apos);/g, (m, e) => {
    if (e[0] === '#') { const n = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : ''; }
    return { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[e];
  });
}

// XML text → { name, attrs, children[], text }. Comments, PIs and DOCTYPE are skipped; CDATA is text.
function parseXml(src) {
  const root = { name: '#root', attrs: {}, children: [], text: '' }, stack = [root];
  const ATTR = /([A-Za-z_][\w.:-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let i = 0;
  while (i < src.length) {
    const lt = src.indexOf('<', i);
    if (lt < 0) { stack[stack.length - 1].text += unesc(src.slice(i)); break; }
    if (lt > i) stack[stack.length - 1].text += unesc(src.slice(i, lt));
    if (src.startsWith('<!--', lt)) { const e = src.indexOf('-->', lt); if (e < 0) throw new Error('unterminated comment'); i = e + 3; continue; }
    if (src.startsWith('<![CDATA[', lt)) { const e = src.indexOf(']]>', lt); if (e < 0) throw new Error('unterminated CDATA'); stack[stack.length - 1].text += src.slice(lt + 9, e); i = e + 3; continue; }
    if (src[lt + 1] === '?' || src[lt + 1] === '!') { const e = src.indexOf('>', lt); if (e < 0) throw new Error('unterminated declaration'); i = e + 1; continue; }
    const gt = src.indexOf('>', lt); if (gt < 0) throw new Error('unterminated tag');
    let body = src.slice(lt + 1, gt);
    if (body[0] === '/') {
      const name = body.slice(1).trim(), top = stack.pop();
      if (!top || top.name !== name || !stack.length) throw new Error('mismatched closing tag </' + name + '>');
      i = gt + 1; continue;
    }
    const self = body.endsWith('/'); if (self) body = body.slice(0, -1);
    const m = /^([A-Za-z_][\w.:-]*)/.exec(body); if (!m) throw new Error('bad tag');
    const node = { name: m[1], attrs: {}, children: [], text: '' };
    let a; ATTR.lastIndex = 0; const rest = body.slice(m[1].length);
    while ((a = ATTR.exec(rest))) node.attrs[a[1]] = unesc(a[3] !== undefined ? a[3] : a[4]);
    stack[stack.length - 1].children.push(node);
    if (!self) stack.push(node);
    i = gt + 1;
  }
  if (stack.length !== 1) throw new Error('unclosed tag <' + stack[stack.length - 1].name + '>');
  return root.children[0] || null;
}
// helpers over parsed nodes
const kid = (n, name) => (n && n.children.find((c) => c.name === name)) || null;
const kids = (n, name) => (n ? n.children.filter((c) => c.name === name) : []);
const txt = (n, name) => { const k = name ? kid(n, name) : n; return k ? k.text.trim() : ''; };
const path = (n, ...names) => names.reduce((x, nm) => kid(x, nm), n);

// does the buffer hold one complete root element?
function complete(buf) {
  const s = buf.replace(/^\s*(<\?[^>]*\?>\s*)?/, '');
  const m = /^<([A-Za-z_][\w.:-]*)/.exec(s); if (!m) return false;
  const first = s.indexOf('>'); if (first < 0) return false;
  if (s[first - 1] === '/' && s.slice(first + 1).trim() === '') return true;
  return s.trimEnd().endsWith('</' + m[1] + '>');
}

function openGmp(o = {}) {
  const timeoutMs = o.timeoutMs || 60000;
  return new Promise((resolve, reject) => {
    let sock, done = false;
    const fail = (e) => { if (done) return; done = true; try { sock && sock.destroy(); } catch (x) { /* already closed */ } reject(e); };
    const ready = () => { if (done) return; done = true; sock.setTimeout(0); resolve(client(sock, timeoutMs)); };
    if (o.socket) sock = net.connect({ path: o.socket }, ready);
    else {
      sock = tls.connect({ host: o.host, port: o.port || 9390, rejectUnauthorized: false, servername: /^[\d.]+$/.test(o.host) ? undefined : o.host }, () => {
        const fp = (sock.getPeerCertificate() || {}).fingerprint256 || '';
        const norm = (x) => String(x || '').replace(/:/g, '').toLowerCase();
        // gvmd's certificate is self-signed: it must be pinned, or the connection is refused
        if (!o.pin || norm(fp) !== norm(o.pin)) return fail(Object.assign(new Error('gvmd certificate not pinned (SHA-256 ' + fp + ')'), { code: 'EPIN', fingerprint: fp }));
        ready();
      });
    }
    sock.setTimeout(timeoutMs, () => fail(Object.assign(new Error('gvmd did not answer in ' + timeoutMs / 1000 + ' s'), { code: 'ETIMEDOUT' })));
    sock.on('error', fail);
  });
}

function client(sock, timeoutMs) {
  let queue = Promise.resolve(), closed = false;
  sock.on('close', () => { closed = true; });
  sock.on('error', () => { closed = true; /* reported to the pending request by its own listener */ });
  function once(cmd, xml) {
    return new Promise((resolve, reject) => {
      if (closed) return reject(new Error('the gvmd connection is closed'));
      let buf = '', size = 0;
      const t = setTimeout(() => finish(Object.assign(new Error('gvmd did not answer ' + cmd + ' in ' + timeoutMs / 1000 + ' s'), { code: 'ETIMEDOUT' })), timeoutMs);
      const onData = (d) => {
        size += d.length; if (size > MAX_BYTES) return finish(new Error('gvmd answer to ' + cmd + ' is larger than ' + (MAX_BYTES >> 20) + ' MB'));
        buf += d.toString('utf8');
        if (!complete(buf)) return;
        let n; try { n = parseXml(buf); } catch (e) { return finish(new Error('gvmd answer to ' + cmd + ' is not valid XML: ' + e.message)); }
        if (!n || n.name !== cmd + '_response') return finish(new Error('gvmd answered ' + cmd + ' with <' + (n && n.name) + '>'));
        const st = Number(n.attrs.status || 0);
        if (st < 200 || st >= 300) return finish(Object.assign(new Error('gvmd refused ' + cmd + ': ' + (n.attrs.status_text || 'status ' + st)), { gmpStatus: st }));
        finish(null, n);
      };
      const onClose = () => finish(new Error('gvmd closed the connection during ' + cmd));
      function finish(err, n) { clearTimeout(t); sock.removeListener('data', onData); sock.removeListener('close', onClose); if (err) reject(err); else resolve(n); }
      sock.on('data', onData); sock.on('close', onClose);
      sock.write(xml);
    });
  }
  return {
    send(cmd, xml) {
      if (!ALLOWED.has(cmd)) return Promise.reject(new Error('GMP command not allowed: ' + cmd));
      const m = /^\s*<([A-Za-z_][\w]*)/.exec(String(xml || ''));
      if (!m || m[1] !== cmd) return Promise.reject(new Error('GMP request root <' + (m && m[1]) + '> is not ' + cmd));
      const p = queue.then(() => once(cmd, xml)); queue = p.catch(() => { /* the next request still runs */ }); return p;
    },
    close() { closed = true; try { sock.end(); } catch (e) { /* already closed */ } },
  };
}

module.exports = { openGmp, parseXml, xesc, kid, kids, txt, path, ALLOWED, complete };
