#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Replay tool for integration tests: sends the lines of a file to a local syslog listener at a chosen rate.
//   node tests/replay.js --file tests/fixtures/synthetic-mixed.log [--host 127.0.0.1] [--port 5514]
//                        [--rate 500 (lines/s, 0 = as fast as possible)] [--loop 1] [--octet] [--udp]
// Lines that are empty or start with '#' are skipped. --octet uses RFC 6587 octet-counting framing (TCP),
// otherwise one line per LF. Use ONLY clearly labelled synthetic test data (see tests/fixtures/README).
const fs = require('node:fs');
const net = require('node:net');
const dgram = require('node:dgram');

function args(argv) {
  const o = { host: '127.0.0.1', port: 5514, rate: 500, loop: 1, octet: false, udp: false, file: '' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--octet') o.octet = true;
    else if (a === '--udp') o.udp = true;
    else if (a === '--help' || a === '-h') o.help = true;
    else if (a.startsWith('--') && i + 1 < argv.length) { o[a.slice(2)] = argv[++i]; }
  }
  o.port = Number(o.port);
  o.rate = Number(o.rate);
  o.loop = Math.max(1, Number(o.loop) || 1);
  return o;
}

async function main() {
  const o = args(process.argv.slice(2));
  if (!o.file || o.help) {
    process.stdout.write('usage: node tests/replay.js --file <path> [--host 127.0.0.1] [--port 5514] [--rate 500] [--loop 1] [--octet] [--udp]\n');
    return 0;
  }
  const lines = fs.readFileSync(o.file, 'utf8').split(/\r?\n/).filter((l) => l && !l.startsWith('#'));
  if (!lines.length) throw new Error('no lines to send in ' + o.file);
  const total = lines.length * o.loop;
  const t0 = Date.now();
  let sent = 0;
  let send;
  let finish;
  if (o.udp) {
    const sock = dgram.createSocket(net.isIPv6(o.host) ? 'udp6' : 'udp4');
    send = (l) => new Promise((r, j) => sock.send(Buffer.from(l), o.port, o.host, (e) => (e ? j(e) : r())));
    finish = () => new Promise((r) => sock.close(r));
  } else {
    const sock = net.connect(o.port, o.host);
    await new Promise((r, j) => { sock.once('connect', r); sock.once('error', j); });
    send = (l) => {
      const b = Buffer.from(l, 'utf8');
      const frame = o.octet ? Buffer.concat([Buffer.from(b.length + ' '), b]) : Buffer.concat([b, Buffer.from('\n')]);
      return sock.write(frame) ? null : new Promise((r) => sock.once('drain', r));
    };
    finish = () => new Promise((r) => { sock.end(() => r()); });
  }
  for (let k = 0; k < o.loop; k++) {
    for (const l of lines) {
      const w = send(l);
      if (w) await w;
      sent++;
      if (o.rate > 0) {
        const due = t0 + (sent / o.rate) * 1000;
        const wait = due - Date.now();
        if (wait > 5) await new Promise((r) => setTimeout(r, wait));
      }
    }
  }
  await finish();
  const s = (Date.now() - t0) / 1000;
  process.stderr.write(`replay: sent ${sent}/${total} lines in ${s.toFixed(2)} s (${Math.round(sent / Math.max(s, 0.001))} lines/s) to ${o.udp ? 'udp' : 'tcp'}://${o.host}:${o.port}${o.octet ? ' (octet-counted)' : ''}\n`);
  return 0;
}

if (require.main === module) {
  main().then((c) => process.exit(c), (e) => { process.stderr.write(`replay failed: ${e.message}\n`); process.exit(1); });
}

module.exports = { args };
