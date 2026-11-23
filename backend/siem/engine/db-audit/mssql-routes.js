// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SQL Server Audit API (page sql-audit.html) - engine/db-audit/mssql-report.js. register(api, deps); {P} = config.api_prefix || '/api/soc'.
 * Analyst and above (named people's activity, as the Oracle Database Audit); every read and export is itself audited.
 *   GET {P}/db/mssql/audit         ?hours=1-2160 &instance= &database=
 *       → {available, hours, capped, total, summary{…}, by_action[], failed_logins[], permissions[], accounts[], schema_changes[], audit_changes[],
 *          config_changes[], off_hours[], users[], coverage[], findings[], scope}
 *   GET {P}/db/mssql/audit/events  ?hours= &instance= &database= &category=failed|admin|off-hours|failed-login|login|permission|account|schema|audit|config|data|other
 *                                   &user= &q= &limit=1-10000 &export=1   → {available, hours, capped, total, items[], filter}
 */
const { body: check } = require('../util/check');
const { createMssqlReport, CATEGORIES } = require('./mssql-report');
const { wrap, audit, prefixOf } = require('../soc/routeutil');

const NAME_RE = /^[A-Za-z0-9_$#.\\ -]+$/;

function register(api, deps) {
  const P = prefixOf(deps);
  const rep = deps.mssql_audit_report || createMssqlReport({ ch: deps.ch });
  deps.mssql_audit_report = rep;
  const q = (src) => check(src || {}).int('hours', { min: 1, max: 2160 })
    .str('instance', { max: 128, re: NAME_RE, msg: 'instance must be a SQL Server instance name (HOST or HOST\\INSTANCE)' })
    .str('database', { max: 128, re: NAME_RE, msg: 'database must be a database name' })
    .oneOf('category', ['failed', 'admin', 'off-hours'].concat(CATEGORIES)).str('user', { max: 128 }).str('q', { max: 200 })
    .int('limit', { min: 1, max: 10000 }).oneOf('export', ['1', 'true']).done();
  api.route('GET', `${P}/db/mssql/audit`, wrap(deps, 'analyst', async (ctx) => {
    const x = q(ctx.query), r = await rep.report(x);
    audit(ctx, 'mssql.audit.view', String(x.instance || 'all'), { hours: r.hours || null, database: x.database || null, events: r.total || 0 });
    return ctx.ok(r);
  }));
  api.route('GET', `${P}/db/mssql/audit/events`, wrap(deps, 'analyst', async (ctx) => {
    const x = q(ctx.query), r = await rep.events(x);
    audit(ctx, x.export ? 'mssql.audit.export' : 'mssql.audit.search', String(x.instance || 'all'), { filter: r.filter || null, rows: r.items ? r.items.length : 0 });
    return ctx.ok(r);
  }));
  return rep;
}

module.exports = { register };
