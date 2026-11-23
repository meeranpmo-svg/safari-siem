// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Applies store/schema.sql idempotently:
//   * CREATE … IF NOT EXISTS for every object,
//   * adds columns that exist in schema.sql but not yet in the live table (forward-compatible upgrades),
//   * updates the TTL of events / stats_minute when retention_days changed (only then — MODIFY TTL is expensive).
// CLI:  node engine/store/migrate.js [--print] [--dry-run]     (reads /etc/sentra-siem/config.json or SENTRA_SIEM_CONFIG)
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA_PATH = path.join(__dirname, 'schema.sql');
const TTL_TABLES = { events: 'toDateTime(ts)', stats_minute: 'minute' };

function renderSchema({ retentionDays = 365, archiveRetentionDays, database = 'siem', schemaPath = SCHEMA_PATH } = {}) {
  const days = Math.trunc(Number(retentionDays));
  if (!(days > 0 && days < 100000)) throw new Error(`invalid retention_days: ${retentionDays}`);
  // archive tier keeps data far longer; defaults to 2× the hot retention (DATAOPT.md "Archive tier").
  const archDays = Math.trunc(Number(archiveRetentionDays != null ? archiveRetentionDays : Math.max(days, days * 2)));
  if (!(archDays > 0 && archDays < 100000)) throw new Error(`invalid archive_retention_days: ${archiveRetentionDays}`);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(database)) throw new Error(`invalid database name: ${database}`);
  let sql = fs.readFileSync(schemaPath, 'utf8').replace(/\{retention_days\}/g, String(days)).replace(/\{archive_retention_days\}/g, String(archDays));
  if (database !== 'siem') sql = sql.replace(/\bsiem\./g, database + '.').replace(/DATABASE IF NOT EXISTS siem\b/g, 'DATABASE IF NOT EXISTS ' + database);
  const statements = sql
    .split('\n').filter((l) => !/^\s*--/.test(l)).join('\n')
    .split(/;\s*(?:\n|$)/).map((s) => s.trim()).filter(Boolean);
  return { days, statements };
}

// Column definitions per CREATE TABLE statement: {table: [{name, type}]}
function schemaColumns(statements) {
  const out = {};
  for (const st of statements) {
    const m = /^CREATE TABLE IF NOT EXISTS\s+(\w+)\.(\w+)\s*\(([\s\S]*)\)\s*ENGINE/i.exec(st);
    if (!m) continue;
    const cols = [];
    for (const line of m[3].split('\n')) {
      const l = line.trim().replace(/,$/, '');
      if (!l || /^INDEX\s/i.test(l)) continue;
      const cm = /^(\w+)\s+(.+)$/.exec(l);
      if (cm) cols.push({ name: cm[1], type: cm[2] });
    }
    out[m[2]] = { db: m[1], cols };
  }
  return out;
}

async function migrate({ ch, retentionDays = 365, archiveRetentionDays, database = 'siem', log, dryRun = false } = {}) {
  const { days, statements } = renderSchema({ retentionDays, archiveRetentionDays, database });
  const done = [];
  const run = async (sql) => { done.push(sql); if (!dryRun) await ch.exec(sql); };
  for (const st of statements) await run(st);
  if (dryRun) return { applied: done, days };

  // add missing columns
  const tables = schemaColumns(statements);
  for (const [table, { db, cols }] of Object.entries(tables)) {
    const live = await ch.query('SELECT name FROM system.columns WHERE database = {db:String} AND table = {t:String}', { db: { type: 'String', value: db }, t: { type: 'String', value: table } });
    const have = new Set(live.map((r) => r.name));
    for (const c of cols) {
      if (!have.has(c.name)) {
        const sql = `ALTER TABLE ${db}.${table} ADD COLUMN IF NOT EXISTS ${c.name} ${c.type}`;
        if (log) log.info('migrate: adding column', { table, column: c.name });
        await run(sql);
      }
    }
  }
  // retention change
  for (const [table, expr] of Object.entries(TTL_TABLES)) {
    const r = await ch.query('SELECT engine_full FROM system.tables WHERE database = {db:String} AND name = {t:String}', { db: { type: 'String', value: database }, t: { type: 'String', value: table } });
    if (!r.length) continue;
    const m = /toIntervalDay\((\d+)\)|INTERVAL (\d+) DAY/i.exec(r[0].engine_full || '');
    const cur = m ? Number(m[1] || m[2]) : null;
    if (cur !== days) {
      if (log) log.info('migrate: changing TTL', { table, from: cur, to: days });
      await run(`ALTER TABLE ${database}.${table} MODIFY TTL ${expr} + INTERVAL ${days} DAY`);
    }
  }
  return { applied: done, days };
}

module.exports = { migrate, renderSchema, schemaColumns, SCHEMA_PATH };

if (require.main === module) {
  (async () => {
    const { loadConfig } = require('../config');
    const { createLogger } = require('../log');
    const { createCH } = require('./clickhouse');
    const args = new Set(process.argv.slice(2));
    const cfg = loadConfig();
    const log = createLogger({ level: cfg.log_level, name: 'migrate' });
    if (args.has('--print')) {
      const { statements } = renderSchema({ retentionDays: cfg.retention_days, database: cfg.clickhouse.database });
      process.stdout.write(statements.join(';\n\n') + ';\n');
      return;
    }
    // no default database on the connection: the first statement creates it. DDL runs as the migration user
    // (secrets.clickhouse_admin); the engine's own user only has SELECT + INSERT. Older installs fall back to it.
    const admin = cfg.secrets && cfg.secrets.clickhouse_admin && cfg.secrets.clickhouse_admin.user ? cfg.secrets.clickhouse_admin : null;
    const ch = createCH({ ...cfg.clickhouse, user: admin ? admin.user : cfg.clickhouse.user, password: admin ? admin.password : cfg.clickhouse.password, database: '' });
    if (!(await ch.ping())) throw new Error(`ClickHouse not reachable at ${cfg.clickhouse.url}`);
    const r = await migrate({ ch, retentionDays: cfg.retention_days, archiveRetentionDays: cfg.archive_retention_days, database: cfg.clickhouse.database, log, dryRun: args.has('--dry-run') });
    log.info('migrate: done', { statements: r.applied.length, retention_days: r.days, dry_run: args.has('--dry-run') });
  })().catch((e) => { process.stderr.write(`migrate failed: ${e.message}\n`); process.exit(1); });
}
