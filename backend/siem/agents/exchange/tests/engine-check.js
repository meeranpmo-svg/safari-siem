// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Optional end-to-end check used by run-tests.ps1 when node is available: feed the lines the loopback listener
// received into the engine parser (engine/parse) exactly as http-ingest would (src_type "exchange") and verify
// host / action / header memory. Usage: node engine-check.js <received.ndjson> <src_id>
const fs = require('node:fs');
const path = require('node:path');
const { createParser } = require(path.join(__dirname, '..', '..', '..', 'engine', 'parse'));

const [file, srcId] = process.argv.slice(2);
const parser = createParser({ config: { exchange: {} } });
const lines = fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim());
const rts = Date.now();
const out = { total: 0, msgtrk: 0, iis: 0, headers: 0, heartbeat: 0, unparsed: 0, hosts: {}, actions: {}, subject_in_clear: 0, errors: [] };
for (const line of lines) {
  let obj;
  if (line[0] === '{') { try { obj = JSON.parse(line); } catch { obj = undefined; } }
  const ev = parser.parse(line, { collector: 'http', src_id: srcId, src_type: 'exchange', peer_ip: '127.0.0.1', rts, tz_offset_min: 0, obj });
  out.total++;
  out.hosts[ev.host || ''] = (out.hosts[ev.host || ''] || 0) + 1;
  if (ev.fields && ev.fields.log_header === '1') { out.headers++; continue; }
  if (obj && obj.Channel === 'SentraExchangeShipper') { out.heartbeat++; continue; }
  if (ev.action === 'unparsed') { out.unparsed++; if (out.errors.length < 5) out.errors.push(line.slice(0, 160)); continue; }
  if (ev.src_type === 'exchange' && ev.category === 'email') { out.msgtrk++; out.actions[ev.action] = (out.actions[ev.action] || 0) + 1; if (/Quarterly results/.test(ev.raw)) out.subject_in_clear++; }
  else if (ev.src_type === 'iis') { out.iis++; if (ev.fields && ev.fields.x_forwarded_for) out.xff = (out.xff || 0) + 1; }
  else { out.unparsed++; if (out.errors.length < 5) out.errors.push(`${ev.src_type}/${ev.action}: ${line.slice(0, 120)}`); }
}
process.stdout.write(JSON.stringify(out) + '\n');
