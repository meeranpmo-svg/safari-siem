// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SQL that renames a column to its own name (toString(ts) AS ts) and then filters on the bare name. ClickHouse resolves a
// bare name to the ALIAS: since the 24.3 analyzer a text ts against a date is refused (NO_COMMON_TYPE - IT Audit's change
// log said "HTTP 200, not JSON"), a millisecond ts against a date matches nothing (UEBA read no events), and an aggregate
// alias in WHERE is ILLEGAL_AGGREGATION on every version (host map). Two checks:
//   1. static, always: no engine query uses such an alias unqualified in WHERE / PREWHERE / HAVING (fails on the old code)
//   2. real ClickHouse, when a binary is available (CLICKHOUSE_BIN or `clickhouse` on PATH): the queries run on the
//      production siem.events schema, with the old and the new analyzer, and return the rows they should. Data is SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { formatParam } = require('../engine/store/clickhouse');

const ENGINE = path.join(__dirname, '..', 'engine');

function selfAliases(file) {
  const s = fs.readFileSync(file, 'utf8'), out = [];
  for (const m of s.matchAll(/`([^`]*\bSELECT\b[^`]*)`/g)) {
    const q = m[1], filt = q.split(/\b(?:WHERE|PREWHERE|HAVING)\b/).slice(1).map((w) => w.split(/\b(?:GROUP BY|ORDER BY|LIMIT|UNION ALL)\b/)[0]).join(' ');
    if (!filt) continue;
    for (const a of q.matchAll(/([A-Za-z0-9_]+\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))\s+AS\s+([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
      const [, expr, name] = a, inner = expr.replace(/^[A-Za-z0-9_]+\(/, '(');
      if (new RegExp('(^|[^.\\w])' + name + '\\b').test(inner) && new RegExp('(^|[^.\\w])' + name + '\\b').test(filt)) {
        out.push(path.relative(ENGINE, file) + ':' + s.slice(0, m.index).split('\n').length + '  ' + expr.slice(0, 50) + ' AS ' + name);
      }
    }
  }
  return out;
}
function jsFiles(d) { return fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? jsFiles(path.join(d, e.name)) : e.name.endsWith('.js') ? [path.join(d, e.name)] : []); }

test('no engine query filters on a column it renamed to its own name (the filter would read the alias)', () => {
  const bad = jsFiles(ENGINE).flatMap(selfAliases);
  assert.deepEqual(bad, [], 'qualify the stored column (FROM t AS e ... WHERE e.ts) in:\n' + bad.join('\n'));
});

function clickhouseBin() {
  for (const c of [process.env.CLICKHOUSE_BIN, 'clickhouse'].filter(Boolean)) {
    try { execFileSync(c, ['local', '--version'], { stdio: 'pipe', timeout: 30000 }); return c; } catch (e) { /* not available - the real-ClickHouse half is skipped */ }
  }
  return null;
}
const BIN = clickhouseBin();
const SCHEMA = (() => { const s = fs.readFileSync(path.join(ENGINE, 'store', 'schema.sql'), 'utf8'); const i = s.indexOf('CREATE TABLE IF NOT EXISTS siem.events\n'); return s.slice(i, s.indexOf(';', i)).replace(/\{[A-Za-z_]+\}/g, '365'); })();   // the retention placeholder migrate.js fills in
const ago = (ms) => new Date(Date.now() - ms).toISOString().replace('T', ' ').replace('Z', '');
const ROWS = [
  { ts: ago(3600e3), src_type: 'fortigate', host: 'FW-SYN-1', host_ip: '10.9.0.1', category: 'config', user: 'admin.syn', message: 'object edited', action: 'x' },
  { ts: ago(7200e3), src_type: 'cisco', host: 'SW-SYN-1', host_ip: '10.9.0.2', category: 'system', user: 'net.syn', message: '%SYS-5-CONFIG_I: Configured from console', action: 'x' },
  { ts: ago(40 * 86400e3), src_type: 'fortigate', host: 'FW-SYN-1', host_ip: '10.9.0.1', category: 'config', user: 'old.syn', message: 'too old', action: 'x' },
  { ts: ago(1800e3), src_type: 'genian', host: 'NAC-SYN', host_ip: '10.9.0.9', category: 'authentication', user: 'u.syn', src_ip: '10.9.5.5', message: 'dot1x ok for 10.9.5.5', action: 'x' },
  { ts: ago(5400e3), src_type: 'windows', host: 'DC-SYN', host_ip: '10.9.0.10', category: 'authentication', user: 'PC-SYN-01$', src_ip: '10.9.7.7', event_code: '4768', message: 'tgt', action: 'x' },
  { ts: ago(60e3), src_type: 'windows', host: 'DC-SYN', host_ip: '10.9.0.10', category: 'authentication', user: 'PC-SYN-01$', src_ip: '127.0.0.1', event_code: '4768', message: 'tgt', action: 'x' },
];
function fakeCh(analyzer) {
  return {
    database: 'siem',
    async query(sql, params) {
      const args = ['local', '--multiquery', '--enable_analyzer=' + analyzer, '--output_format_json_quote_64bit_integers=0'];
      for (const [k, p] of Object.entries(params || {})) args.push('--param_' + k + '=' + formatParam(p));
      const cols = ['ts', 'src_type', 'host', 'host_ip', 'category', 'user', 'src_ip', 'event_code', 'message', 'action'];
      const data = ROWS.map((r) => JSON.stringify(Object.fromEntries(cols.map((c) => [c, r[c] || ''])))).join('\n').replace(/'/g, "\\'");
      const script = `CREATE DATABASE siem; ${SCHEMA};\nINSERT INTO siem.events (${cols}) SELECT ${cols} FROM format(JSONEachRow, '${cols.map((c) => c + ' String').join(', ')}', '${data}');\n${sql} FORMAT JSONEachRow`;
      const r = spawnSync(BIN, args, { input: script, encoding: 'utf8', timeout: 60000 });
      if (r.status !== 0) throw new Error('ClickHouse: ' + String(r.stderr).trim().split('\n')[0]);
      return r.stdout.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
    },
  };
}

for (const analyzer of [1, 0]) {
  test(`real ClickHouse (analyzer ${analyzer}): change log, device events, NAC, UEBA recent events and host map answer with data`, { skip: BIN ? false : 'no clickhouse binary (set CLICKHOUSE_BIN)' }, async () => {
    const ch = fakeCh(analyzer);
    const ev = require('../engine/netops/evidence').createEvidence({ ch, config: { clickhouse: { database: 'siem' } } });
    const changes = await ev.configChanges({ hours: 24 * 7, limit: 1000 });
    assert.deepEqual(changes.map((c) => c.user), ['admin.syn', 'net.syn'], 'the two changes of the week, newest first, nothing older');
    assert.ok(changes.every((c) => typeof c.ts === 'string' && Number.isFinite(c.at) && c.at > Date.now() - 8 * 864e5), 'ts as text, at as epoch ms');
    assert.equal((await ev.configChanges({ ip: '10.9.0.2', hours: 24 })).length, 1);
    assert.equal((await ev.deviceEvents({ ip: '10.9.0.2', minutes: 600, kind: 'config' })).length, 1);
    assert.equal((await ev.nacLookup({ ip: '10.9.5.5', hours: 24 })).length, 1);
    const sql = require('../engine/ueba/sql');
    const ue = await ch.query(sql.recentEventsSQL({ database: 'siem' }), { from: { type: "DateTime64(3,'UTC')", value: ago(86400e3) }, to: { type: "DateTime64(3,'UTC')", value: ago(0) }, limit: { type: 'UInt32', value: 100 }, offset: { type: 'UInt32', value: 0 } });
    assert.equal(ue.length, 5, 'every event of the last 24 h (none was read before)');
    assert.ok(ue.every((r) => typeof r.ts === 'number'));
    const hosts = await require('../engine/soc/hostmap').lookup(ch, 'siem', ['pc-syn-01'], 14);
    assert.equal(hosts['pc-syn-01'] && hosts['pc-syn-01'].ip, '10.9.7.7', 'the latest real IP; the loopback row is skipped');
    const rep = await require('../engine/soc/hostmap').reportingHosts(ch, 'siem', 24);
    assert.ok(rep.hosts.some((h) => h.host === 'fw-syn-1'));
  });
}
