// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * SAMA CSF coverage API — register(api, deps). {P} = config.api_prefix || '/api/soc'; same proxy-secret + portal
 * session auth as every SOC route. Reads: any authenticated user (viewer). Writes: admin. Every write is audited.
 *
 *   GET  {P}/compliance/sama                 ?days=1-400&refresh=1
 *        → { framework, catalogue, map_version, verify_with_compliance_team, generated_at, period{from,to,days}, clickhouse{ok,error},
 *            settings, summary{coverage_pct, evidenced, total, counts{covered,partial,gap,n/a}, by_domain{3.x:{title,…counts}}, scoring},
 *            controls[{id, title, domain, owner, siem_evidenced, status, capped, reasons[], actions[{check, action, topic?}],
 *                      rules{tagged, enabled}, checks[{id, title, result: pass|fail|unknown, value, reason}]}] }
 *   GET  {P}/compliance/sama/report          ?format=json|html&days=&download=1
 *        json → the summary fields + controls[] with evidence detail + evidence_overview + digest (sha256 of the evidence)
 *        html → printable auditor evidence pack (self-contained; Content-Security-Policy default-src 'none')
 *   GET  {P}/compliance/sama/settings        → { settings, defaults, source_classes{name:title}, grc_push{enabled,url,…,last} }
 *   POST {P}/compliance/sama/settings        admin {required_retention_days?, required_source_classes?, period_days?, active_window_h?,
 *                                            dc_hosts?, known_assets?, expected_asset_count?, vendor_account_patterns?} → {settings}
 *   POST {P}/compliance/sama/grc-push        admin — push evidence to AI GRC now (needs compliance.sama.grc_push.enabled) → last push result
 *   GET  {P}/compliance/sama/:control        e.g. 3.3.14 → { …meta, control: {…, checks[] with details, contributing_rules[],
 *                                            source_classes[], sources[] (3.3.14), recent_alerts[], alerts_in_period} }   404 unknown id
 */
const { createSamaCompliance } = require('./sama');
const { createGrcPush } = require('./grc-push');
const { renderHtml, digest } = require('./report');
const { HttpError, wrap, audit, body, prefixOf } = require('../soc/routeutil');

function sendHtml(ctx, html, download, day) {
  const res = ctx.res;
  if (!res || typeof res.writeHead !== 'function') return ctx.ok({ content_type: 'text/html', html });
  ctx.sent = true;
  const buf = Buffer.from(html, 'utf8');
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8', 'Content-Length': buf.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'",
    'Content-Disposition': `${download ? 'attachment' : 'inline'}; filename="sama-csf-evidence-pack-${day}.html"`,
  });
  res.end(buf);
  return undefined;
}

function register(api, deps) {
  const P = prefixOf(deps);
  const cfg = deps.config || {};
  const sama = (deps.compliance && deps.compliance.sama) || createSamaCompliance(deps);
  const grcPush = (deps.compliance && deps.compliance.grcPush) || createGrcPush({ sama, config: cfg, log: deps.log });
  const B = `${P}/compliance/sama`;
  deps.samaCoverage = sama;   // read by compliance/sama-intel-routes.js (history, leverage, forecast, advisor)

  api.route('GET', B, wrap(deps, null, async (ctx) => ctx.ok(await sama.summary(ctx.query || {}))));

  api.route('GET', `${B}/report`, wrap(deps, null, async (ctx) => {
    const q = ctx.query || {};
    const fmt = String(q.format || 'json').toLowerCase();
    if (fmt !== 'json' && fmt !== 'html') throw new HttpError(400, 'format must be json or html');
    const rep = await sama.report(q);
    const sha = digest(rep);
    audit(ctx, 'compliance.sama.report', fmt, { days: rep.period.days, coverage_pct: rep.summary.coverage_pct, digest: sha });
    if (fmt === 'json') return ctx.ok(Object.assign({}, rep, { digest: `sha256:${sha}` }));
    return sendHtml(ctx, renderHtml(rep, { org: cfg.compliance && cfg.compliance.sama && cfg.compliance.sama.org_name, generatedBy: ctx.user }), q.download === '1', rep.generated_at.slice(0, 10));
  }));

  api.route('GET', `${B}/settings`, wrap(deps, null, (ctx) => {
    const classes = {};
    for (const [k, v] of Object.entries(sama.map.source_classes || {})) classes[k] = v.title || k;
    return ctx.ok({ settings: sama.settings.get(), defaults: sama.settings.defaults(), source_classes: classes, grc_push: grcPush.status() });
  }));

  api.route('POST', `${B}/settings`, wrap(deps, 'admin', (ctx) => {
    const b = body(ctx);
    const patch = b.settings && typeof b.settings === 'object' ? b.settings : b;
    const before = sama.settings.get();
    const s = sama.settings.set(patch, ctx.user);
    const changed = {};
    for (const k of Object.keys(patch)) changed[k] = { from: before[k], to: s[k] };
    audit(ctx, 'compliance.sama.settings', 'sama', changed);
    return ctx.ok({ settings: s });
  }));

  api.route('POST', `${B}/grc-push`, wrap(deps, 'admin', async (ctx) => {
    const st = grcPush.status();
    if (!st.enabled) throw new HttpError(409, 'GRC evidence push is disabled (config compliance.sama.grc_push.enabled)');
    if (st.problems.length) throw new HttpError(503, 'GRC evidence push not configured', st.problems);
    const r = await grcPush.pushNow('api:' + (ctx.user || 'unknown'));
    audit(ctx, 'compliance.sama.grc-push', 'sama', { ok: r.ok, pushed: r.pushed, failed: r.failed });
    return ctx.ok(r);
  }));

  api.route('GET', `${B}/:control`, wrap(deps, null, async (ctx) => ctx.ok(await sama.control(String(ctx.params.control || ''), ctx.query || {}))));

  grcPush.start();
  deps.compliance = { sama, grcPush };
  return { sama, grcPush };
}

module.exports = { register };
