#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * zyb-siemstats - SIEM log storage and daily log flow for the portal home page. Called by zyb-sysinfo (root, every
 * 30 s; this result is cached for 2 minutes). Prints one JSON object on stdout, or {"error": "..."}.
 * Reads the SIEM's own settings: /etc/sentra-siem/config.json (ClickHouse URL, database, retention) and secrets.json
 * (ClickHouse user/password; never printed). Read-only queries on system.parts and <db>.stats_minute.
 */
const fs = require('fs'), http = require('http'), path = require('path');
const ETC = process.env.SENTRA_SIEM_ETC || '/etc/sentra-siem';
function readJSON(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return {}; } }
const cfg = readJSON(path.join(ETC, 'config.json')), sec = readJSON(cfg.secrets_path || path.join(ETC, 'secrets.json'));
const ch = Object.assign({ url: 'http://127.0.0.1:8123', database: 'siem', user: 'sentra_siem' }, cfg.clickhouse || {});
const user = (sec.clickhouse && sec.clickhouse.user) || ch.user, pass = (sec.clickhouse && sec.clickhouse.password) || '';
const db = /^[A-Za-z0-9_]+$/.test(ch.database) ? ch.database : 'siem';

function q(sql) {
  return new Promise((ok, bad) => {
    const u = new URL(ch.url);
    if (!/^(127\.0\.0\.1|localhost|::1|\[::1\])$/.test(u.hostname)) return bad(new Error('ClickHouse is not local'));
    const req = http.request({ hostname: u.hostname, port: u.port || 8123, path: '/?output_format_json_quote_64bit_integers=0', method: 'POST', timeout: 10000,
      headers: { 'X-ClickHouse-User': user, 'X-ClickHouse-Key': pass, 'X-ClickHouse-Database': db, 'Content-Type': 'text/plain' } }, (res) => {
      let b = ''; res.setEncoding('utf8'); res.on('data', (c) => { b += c; if (b.length > 2e6) req.destroy(); });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          const m = String(b).replace(/\s+/g, ' ');
          return bad(new Error(/Authentication failed|password is incorrect|REQUIRED_PASSWORD|516/.test(m) || res.statusCode === 516 || res.statusCode === 401 ? 'ClickHouse refused the SIEM user (check clickhouse user/password in ' + path.join(ETC, 'secrets.json') + ')' : /UNKNOWN_TABLE|doesn't exist/.test(m) ? 'SIEM tables not found in database ' + db : 'ClickHouse HTTP ' + res.statusCode + ': ' + m.replace(/^Code: \d+\. DB::Exception: /, '').slice(0, 80)));
        }
        ok(b.split('\n').filter(Boolean).map((l) => JSON.parse(l))); });
    });
    req.on('timeout', () => req.destroy(new Error('ClickHouse did not answer (timeout)'))); req.on('error', (e) => bad(e.code === 'ECONNREFUSED' ? new Error('ClickHouse is not running on ' + ch.url) : e)); req.end(sql + ' FORMAT JSONEachRow');
  });
}

(async () => {
  try {
    const tables = await q(`SELECT table, sum(rows) AS rows, sum(bytes_on_disk) AS disk, sum(data_uncompressed_bytes) AS raw, min(partition) AS first_part
      FROM system.parts WHERE active AND database = '${db}' GROUP BY table ORDER BY disk DESC`);
    const days = await q(`SELECT toString(toDate(minute)) AS day, sum(events) AS events, sum(bytes) AS bytes, sum(parse_errors) AS errors, uniqExact(src_id) AS sources
      FROM ${db}.stats_minute WHERE minute >= toStartOfDay(now()) - INTERVAL 13 DAY GROUP BY day ORDER BY day`);
    const ev = tables.find((t) => t.table === 'events') || {};
    const fp = String(ev.first_part || ''), oldest = /^\d{8}$/.test(fp) ? fp.slice(0, 4) + '-' + fp.slice(4, 6) + '-' + fp.slice(6) : null;
    const tot = tables.reduce((a, t) => ({ rows: a.rows + t.rows, disk: a.disk + t.disk, raw: a.raw + t.raw }), { rows: 0, disk: 0, raw: 0 });
    process.stdout.write(JSON.stringify({
      db, retention_days: Number(cfg.retention_days) || 365, oldest, total: tot,
      events: { rows: ev.rows || 0, disk: ev.disk || 0, raw: ev.raw || 0 },
      tables: tables.slice(0, 8).map((t) => ({ table: t.table, rows: t.rows, disk: t.disk })),
      days: days.map((d) => ({ day: d.day, events: d.events, bytes: d.bytes, errors: d.errors, sources: d.sources })),
    }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: String(e.message || e).slice(0, 120) }));
  }
})();
