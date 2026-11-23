// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Minimal SMTP submission client (Node standard library only: net + tls). Enough for an internal relay such as
 * Exchange (receive connector on 25 / 587): EHLO, STARTTLS (upgrade of the same socket with tls.connect({socket})),
 * AUTH LOGIN (AUTH PLAIN when LOGIN is not offered), MAIL FROM / RCPT TO / DATA (dot-stuffed), QUIT.
 *
 *   sendMail(opts, message) → Promise<{ accepted[], rejected[], response, stages[] }>
 *   verify(opts)            → Promise<{ ok, tls, auth, capabilities[], stages[] }>   (connect, EHLO, STARTTLS, AUTH, QUIT)
 *   buildMessage(message)   → RFC 5322 / MIME text (multipart/mixed: alternative text+html, attachments base64)
 *   opts    { host, port = 25, tls = false (implicit TLS, e.g. 465), starttls = true (REQUIRE STARTTLS unless tls; false =
 *             plain session), user = '', password = '', ca_file = '' (PEM of the internal CA), ca (PEM string, tests),
 *             reject_unauthorized = true, timeout_ms = 30000, helo = os.hostname(), allow_insecure_auth = false }
 *   message { from, from_name?, to[], subject, text, html?, attachments?[{filename, content (string|Buffer), contentType}], date?, messageId? }
 *
 * Safety: credentials are only sent inside TLS unless allow_insecure_auth is set or the server is loopback (tests);
 * errors never contain the password or the AUTH payloads; header values are CR/LF-free (subject RFC 2047-encoded);
 * addresses are validated. SmtpError { stage, code (reply code or 0), transient } — 4xx / network / timeout are transient.
 */
const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

class SmtpError extends Error {
  constructor(message, { stage = '', code = 0, transient } = {}) {
    super(message); this.name = 'SmtpError'; this.stage = stage; this.code = code;
    this.transient = transient !== undefined ? !!transient : !(code >= 500 && code < 600);
  }
}

const ADDR_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const isAddr = (a) => typeof a === 'string' && a.length <= 254 && ADDR_RE.test(a);
const noCrlf = (s) => String(s === undefined || s === null ? '' : s).replace(/[\r\n\0]+/g, ' ');
const isLoopback = (h) => /^(127\.\d+\.\d+\.\d+|localhost|::1|\[::1\])$/i.test(String(h || ''));

function encWord(s) {
  const v = noCrlf(s);
  // eslint-disable-next-line no-control-regex
  if (/^[\x20-\x7e]*$/.test(v)) return v;
  const out = []; let chunk = '';
  for (const ch of v) { // ≤ 45 bytes per encoded word (RFC 2047 line length), never split a character
    if (Buffer.byteLength(chunk + ch) > 45) { out.push(chunk); chunk = ''; }
    chunk += ch;
  }
  if (chunk) out.push(chunk);
  return out.map((c) => `=?UTF-8?B?${Buffer.from(c, 'utf8').toString('base64')}?=`).join('\r\n ');
}
const b64lines = (buf) => (Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), 'utf8')).toString('base64').replace(/.{1,76}/g, '$&\r\n');
const safeName = (s) => noCrlf(s).replace(/["\\]/g, '_').slice(0, 120) || 'attachment';

function buildMessage(m) {
  if (!isAddr(m.from)) throw new SmtpError('invalid from address', { stage: 'message', transient: false });
  const to = (m.to || []).filter(Boolean);
  if (!to.length || !to.every(isAddr)) throw new SmtpError('invalid recipient address', { stage: 'message', transient: false });
  const id = m.messageId || `<${crypto.randomBytes(12).toString('hex')}@${String(m.from).split('@')[1]}>`;
  const mix = `mix-${crypto.randomBytes(9).toString('hex')}`; const alt = `alt-${crypto.randomBytes(9).toString('hex')}`;
  const h = [
    `From: ${m.from_name ? `${encWord(m.from_name)} <${m.from}>` : m.from}`,
    `To: ${to.join(', ')}`,
    `Subject: ${encWord(m.subject || '')}`,
    `Date: ${(m.date || new Date()).toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: ${noCrlf(id)}`,
    'MIME-Version: 1.0',
    'Auto-Submitted: auto-generated',
    `Content-Type: multipart/mixed; boundary="${mix}"`,
  ];
  const part = (type, body) => `Content-Type: ${type}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64lines(body)}`;
  let body = `--${mix}\r\nContent-Type: multipart/alternative; boundary="${alt}"\r\n\r\n--${alt}\r\n${part('text/plain', m.text || '')}`;
  if (m.html) body += `--${alt}\r\n${part('text/html', m.html)}`;
  body += `--${alt}--\r\n`;
  for (const a of m.attachments || []) {
    const fn = safeName(a.filename);
    body += `--${mix}\r\nContent-Type: ${noCrlf(a.contentType || 'application/octet-stream')}; name="${fn}"\r\nContent-Disposition: attachment; filename="${fn}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64lines(a.content)}`;
  }
  body += `--${mix}--\r\n`;
  return `${h.join('\r\n')}\r\n\r\n${body}`;
}

// ---------------------------------------------------------------- wire protocol
function wire(sock, timeoutMs) {
  let buf = ''; let lines = []; let waiter = null; let failure = null;
  const io = { sock: null, secure: false };
  function onData(d) {
    buf += d.toString('utf8');
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1);
      lines.push(line);
      if (/^\d{3}(?: |$)/.test(line)) { const reply = lines; lines = []; deliver(null, reply); }
    }
  }
  function onErr(e) { deliver(e instanceof SmtpError ? e : new SmtpError(`connection error: ${e.code || e.message}`, { stage: 'connect' }), null); }
  function onClose() { deliver(new SmtpError('connection closed by the server', { stage: 'connect' }), null); }
  function onTimeout() { deliver(new SmtpError(`timeout after ${timeoutMs} ms`, { stage: 'timeout' }), null); try { io.sock.destroy(); } catch { /* ignore */ } }
  const pending = [];
  function deliver(err, reply) {
    if (err && !failure) failure = err;
    if (waiter) { const w = waiter; waiter = null; if (err) w.reject(err); else w.resolve(reply); } else if (reply) pending.push(reply);
  }
  io.bind = (s) => {
    if (io.sock) { io.sock.removeListener('data', onData); io.sock.removeListener('error', onErr); io.sock.removeListener('close', onClose); io.sock.removeListener('timeout', onTimeout); }
    io.sock = s; failure = null;
    s.on('data', onData); s.on('error', onErr); s.on('close', onClose); s.on('timeout', onTimeout);
    s.setTimeout(timeoutMs);
  };
  io.unbind = () => { io.sock.removeListener('data', onData); io.sock.removeListener('error', onErr); io.sock.removeListener('close', onClose); io.sock.removeListener('timeout', onTimeout); };
  io.read = () => new Promise((resolve, reject) => {
    if (pending.length) return resolve(pending.shift());
    if (failure) return reject(failure);
    waiter = { resolve, reject };
  });
  io.expect = async (stage, codes) => {
    let reply;
    try { reply = await io.read(); } catch (e) { e.stage = e.stage === 'connect' || e.stage === 'timeout' ? `${stage}:${e.stage}` : stage; throw e; }
    const code = Number(reply[reply.length - 1].slice(0, 3));
    if (!codes.includes(code)) {
      const text = reply.map((l) => l.slice(4)).join(' ').slice(0, 300);
      throw new SmtpError(`${stage} refused: ${code} ${text}`, { stage, code });
    }
    return { code, lines: reply.map((l) => l.slice(4)) };
  };
  io.send = (stage, line, codes, secretLine) => {
    io.sock.write(line + '\r\n');
    return io.expect(stage, codes).catch((e) => { if (secretLine) e.message = e.message.replace(line, '[redacted]'); throw e; });
  };
  io.bind(sock);
  return io;
}

function caOf(opts) {
  if (opts.ca) return opts.ca;
  if (opts.ca_file) {
    try { return fs.readFileSync(opts.ca_file); } catch (e) { throw new SmtpError(`cannot read ca_file ${opts.ca_file}: ${e.code || e.message}`, { stage: 'config', transient: false }); }
  }
  return undefined;
}

function open(opts) {
  return new Promise((resolve, reject) => {
    const port = Number(opts.port) || (opts.tls ? 465 : 25);
    let s;
    const fail = (e) => reject(new SmtpError(`cannot connect to ${opts.host}:${port}: ${e.code || e.message}`, { stage: 'connect' }));
    if (opts.tls) {
      s = tls.connect({ host: opts.host, port, servername: net.isIP(opts.host) ? undefined : opts.host, ca: caOf(opts), rejectUnauthorized: opts.reject_unauthorized !== false }, () => { s.removeListener('error', fail); resolve(s); });
    } else {
      s = net.connect({ host: opts.host, port }, () => { s.removeListener('error', fail); resolve(s); });
    }
    s.once('error', fail);
    s.setTimeout(Number(opts.timeout_ms) || 30000, () => { s.destroy(); reject(new SmtpError(`connect timeout to ${opts.host}:${port}`, { stage: 'connect' })); });
  });
}

function upgrade(io, opts) {
  return new Promise((resolve, reject) => {
    io.unbind();
    const s = tls.connect({ socket: io.sock, servername: net.isIP(opts.host) ? undefined : opts.host, ca: caOf(opts), rejectUnauthorized: opts.reject_unauthorized !== false }, () => {
      s.removeListener('error', fail); io.bind(s); io.secure = true; resolve();
    });
    const fail = (e) => reject(new SmtpError(`STARTTLS handshake failed: ${e.code || e.message}`, { stage: 'starttls', transient: false }));
    s.once('error', fail);
  });
}

function caps(lines) { return lines.slice(1).map((l) => l.trim().toUpperCase()); }

async function session(opts, fn) {
  if (!opts || !opts.host || /[\s/]/.test(String(opts.host))) throw new SmtpError('SMTP host not configured', { stage: 'config', transient: false });
  const timeout = Number(opts.timeout_ms) || 30000;
  const helo = noCrlf(opts.helo || os.hostname() || 'sentra-siem').replace(/\s+/g, '') || 'sentra-siem';
  const stages = [];
  const sock = await open(opts);
  const io = wire(sock, timeout);
  io.secure = !!opts.tls;
  try {
    await io.expect('greeting', [220]); stages.push('greeting');
    let ehlo = await io.send('ehlo', `EHLO ${helo}`, [250]); stages.push('ehlo');
    let cap = caps(ehlo.lines);
    if (!opts.tls && opts.starttls !== false) {
      if (!cap.includes('STARTTLS')) throw new SmtpError('the server does not offer STARTTLS (required by the settings)', { stage: 'starttls', transient: false });
      await io.send('starttls', 'STARTTLS', [220]);
      await upgrade(io, opts); stages.push('starttls');
      ehlo = await io.send('ehlo', `EHLO ${helo}`, [250]);
      cap = caps(ehlo.lines);
    }
    let auth = false;
    if (opts.user) {
      if (!io.secure && !opts.allow_insecure_auth && !(isLoopback(opts.host) && opts.loopback_plain_auth !== false)) throw new SmtpError('refusing to send credentials without TLS (enable STARTTLS)', { stage: 'auth', transient: false });
      const am = (cap.find((c) => c.startsWith('AUTH ') || c.startsWith('AUTH=')) || '').replace(/^AUTH[ =]/, '').split(/\s+/);
      const pw = String(opts.password || '');
      if (am.includes('LOGIN')) {
        await io.send('auth', 'AUTH LOGIN', [334]);
        await io.send('auth', Buffer.from(String(opts.user)).toString('base64'), [334], true);
        await io.send('auth', Buffer.from(pw).toString('base64'), [235], true);
      } else if (am.includes('PLAIN')) {
        await io.send('auth', `AUTH PLAIN ${Buffer.from(`\0${opts.user}\0${pw}`).toString('base64')}`, [235], true);
      } else throw new SmtpError('the server offers no supported AUTH mechanism (LOGIN or PLAIN)', { stage: 'auth', transient: false });
      auth = true; stages.push('auth');
    }
    const out = await fn(io, { cap, stages, auth });
    try { await io.send('quit', 'QUIT', [221]); } catch { /* server may close first */ }
    return Object.assign({ tls: io.secure, auth, capabilities: cap, stages }, out || {});
  } finally {
    try { io.sock.end(); io.sock.destroy(); } catch { /* ignore */ }
  }
}

async function sendMail(opts, message) {
  const text = buildMessage(message); // validates addresses before connecting
  const to = message.to.filter(Boolean);
  return session(opts, async (io, s) => {
    await io.send('mail', `MAIL FROM:<${message.from}>`, [250]); s.stages.push('mail');
    const accepted = []; const rejected = [];
    for (const r of to) {
      try { await io.send('rcpt', `RCPT TO:<${r}>`, [250, 251]); accepted.push(r); } catch (e) { if (e.code >= 400 && e.code < 600) rejected.push({ rcpt: r, code: e.code }); else throw e; }
    }
    if (!accepted.length) {
      const transient = rejected.every((x) => x.code < 500);
      throw new SmtpError(`every recipient was refused (${rejected.map((x) => x.code).join(', ')})`, { stage: 'rcpt', code: rejected[0] ? rejected[0].code : 0, transient });
    }
    s.stages.push('rcpt');
    await io.send('data', 'DATA', [354]);
    const stuffed = text.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
    io.sock.write(stuffed.endsWith('\r\n') ? stuffed : stuffed + '\r\n');
    const r = await io.send('data', '.', [250]); s.stages.push('data');
    return { accepted, rejected, response: r.lines.join(' ').slice(0, 200), bytes: Buffer.byteLength(stuffed) };
  });
}

function verify(opts) { return session(opts, async () => ({ ok: true })); }

module.exports = { sendMail, verify, buildMessage, encWord, SmtpError, isAddr };
