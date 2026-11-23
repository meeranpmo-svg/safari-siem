// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
// Printable SAMA CSF evidence pack (HTML, self-contained, no scripts, no external resources).
//   renderHtml(report, { org?, generatedBy? }) → string      digest(report) → sha256 hex of the JSON evidence
// Every value from the engine is escaped with esc(). The pack shows: generation time and period, the coverage score,
// per-domain table, per-control status with checks, evidence, gaps and actions, contributing rules, recent alert
// samples, the evidence overview, the controls not evidenced by the SIEM, and a signatures block.
const crypto = require('node:crypto');

const esc = (s) => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const ST = { covered: ['Covered', '#2e7d4f', '#fff'], partial: ['Partial', '#f2c46d', '#3b2a00'], gap: ['Gap', '#c0392b', '#fff'], 'n/a': ['Not SIEM-evidenced (GRC)', '#e3e6e4', '#333'] };
const RES = { pass: '✓ pass', fail: '✕ fail', unknown: '? unavailable' };
const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const iso = (ms) => (ms ? new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '—');
const badge = (s) => { const x = ST[s] || ST['n/a']; return `<span class="b" style="background:${x[1]};color:${x[2]}">${esc(x[0])}</span>`; };
const fmtVal = (v) => (v === null || v === undefined ? '—' : typeof v === 'object' ? esc(JSON.stringify(v)) : esc(v));

function digest(report) { return crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex'); }

function controlSection(c) {
  if (!c.siem_evidenced) return '';
  const checks = (c.checks || []).map((k) => `<tr><td>${esc(k.title)}</td><td class="r-${esc(k.result)}">${esc(RES[k.result] || k.result)}</td><td>${fmtVal(k.value)}</td><td>${esc(k.reason)}</td></tr>`).join('');
  const actions = (c.actions || []).length
    ? `<h4>Gaps and actions to close them</h4><ul>${c.actions.map((a) => `<li>${esc(a.action)}${a.topic ? ` <span class="m">(${esc(a.topic)})</span>` : ''}</li>`).join('')}</ul>` : '';
  const rules = (c.contributing_rules || []).length
    ? `<h4>Contributing detection rules (${c.rules ? `${esc(c.rules.enabled)} of ${esc(c.rules.tagged)} enabled` : ''})</h4><table><tr><th>Rule</th><th>Name</th><th>Enabled</th><th>Severity</th><th>MITRE</th><th>Alerts in period</th></tr>${
      c.contributing_rules.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>${r.enabled ? 'yes' : '<b>no</b>'}</td><td>${esc(SEV[r.severity] || r.severity)}</td><td>${esc((r.mitre || []).join(', '))}</td><td>${esc(r.alerts_in_period)}</td></tr>`).join('')}</table>` : '';
  const cls = (c.source_classes || []).length
    ? `<h4>Log source classes</h4><table><tr><th>Class</th><th>Reporting</th><th>Hosts</th><th>Sources</th></tr>${c.source_classes.map((s) => `<tr><td>${esc(s.title || s.class)}</td><td>${s.present ? 'yes' : '<b>no</b>'}${(s.expected_missing || []).length ? ` — silent: ${esc(s.expected_missing.join(', '))}` : ''}</td><td>${esc(s.host_count || 0)}${(s.hosts || []).length ? ` <span class="m">(${esc(s.hosts.slice(0, 15).join(', '))}${s.hosts.length > 15 ? ' …' : ''})</span>` : ''}</td><td>${esc((s.sources || []).join(', '))}</td></tr>`).join('')}</table>` : '';
  const alerts = (c.recent_alerts || []).length
    ? `<h4>Recent alert samples (${esc(c.alerts_in_period)} in period)</h4><table><tr><th>Alert</th><th>Rule</th><th>Severity</th><th>Status</th><th>Last event</th><th>Summary</th></tr>${
      c.recent_alerts.map((a) => `<tr><td>${esc(a.id)}${a.case_id ? `<br><span class="m">${esc(a.case_id)}</span>` : ''}</td><td>${esc(a.rule_id)}</td><td>${esc(SEV[a.severity] || a.severity)}</td><td>${esc(a.status)}</td><td>${esc(iso(a.ts_last))}</td><td>${esc(a.summary)}</td></tr>`).join('')}</table>` : '';
  return `<section class="ctl"><h3>${esc(c.id)} ${esc(c.title)} ${badge(c.status)}</h3>
<p class="m">Domain ${esc(c.domain)} — ${esc(c.domain_title)} · Owner: ${esc(c.owner)}${c.capped ? ' · capped at partial: SIEM evidence alone cannot cover this control' : ''}</p>
${c.scope ? `<p><b>SIEM scope:</b> ${esc(c.scope)}</p>` : ''}
<table><tr><th>Check</th><th>Result</th><th>Value</th><th>Evidence</th></tr>${checks}</table>${actions}${cls}${rules}${alerts}</section>`;
}

function overview(o) {
  if (!o) return '';
  const rt = o.retention || {}; const al = o.alerts || {}; const cs = o.cases || {}; const it = o.intel || {}; const id = o.identity || {}; const ue = o.ueba || {}; const as = o.assets || {};
  const row = (k, v) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`;
  return `<h2>Evidence overview</h2><table class="kv">${[
    row('Log sources', `${esc(o.sources.active)} active of ${esc(o.sources.configured)} configured, ${esc(o.sources.silent)} silent`),
    row('Hosts reporting', esc(o.hosts_reporting)),
    row('Retention (hot)', `${esc(rt.effective_days)} days (${esc(rt.source)})${rt.archive_days ? `, archive ${esc(rt.archive_days)} days` : ''}${rt.data_age_days !== null && rt.data_age_days !== undefined ? `, oldest data ${esc(rt.data_age_days)} days old` : ''}`),
    row('Detection', `${esc((o.detector || {}).rules_loaded)} real-time rules compiled, ${esc((o.detector || {}).scheduled)} scheduled, ${esc((o.detector || {}).load_errors)} load errors`),
    row('Alerts in period', `${esc(al.total)} (${esc(al.ack_pct === null ? '—' : al.ack_pct + '%')} triaged, MTTA ${esc(al.mtta_avg_s === null ? '—' : al.mtta_avg_s + ' s')})`),
    row('Cases in period', `${esc(cs.created)} opened, ${esc(cs.closed)} closed, MTTR ${esc(cs.mttr_avg_s === null ? '—' : cs.mttr_avg_s + ' s')}, resolve SLA ${esc(cs.sla_resolve_pct === null ? '—' : cs.sla_resolve_pct + '%')}`),
    row('Threat intel', it.enabled ? `${esc(it.indicators)} indicators, ${esc(it.ioc_alerts)} IOC alerts in period` : 'not loaded'),
    row('AD identity sync', id.enabled ? `${id.last_ok ? 'ok' : 'failing'}${id.last_at ? `, last run ${esc(iso(id.last_at))}` : ''}` : 'disabled'),
    row('UEBA', ue.enabled ? `detectors last ran ${esc(iso(ue.last_detect_run))}` : 'not active'),
    row('Asset inventory', as.inventory === 'none' ? 'not configured' : `${esc(as.reporting_known)}/${esc(as.known)} known assets reporting (${esc(as.pct)}%)`),
  ].join('')}</table>`;
}

function renderHtml(report, opts = {}) {
  const s = report.summary || { counts: {}, by_domain: {} };
  const sha = digest(report);
  const doms = Object.entries(s.by_domain || {}).map(([k, d]) => `<tr><td>${esc(k)} ${esc(d.title)}</td><td>${esc(d.covered)}</td><td>${esc(d.partial)}</td><td>${esc(d.gap)}</td><td>${esc(d['n/a'])}</td></tr>`).join('');
  const na = (report.controls || []).filter((c) => !c.siem_evidenced);
  const ev = (report.controls || []).filter((c) => c.siem_evidenced);
  const list = ev.map((c) => `<tr><td>${esc(c.id)}</td><td>${esc(c.title)}</td><td>${badge(c.status)}</td><td>${esc((c.reasons || [])[0] || 'all checks pass')}</td></tr>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SAMA CSF evidence pack</title><style>
body{font:13px/1.45 system-ui,Segoe UI,Arial,sans-serif;color:#1b1b1b;background:#fff;margin:24px auto;max-width:1100px;padding:0 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;border-bottom:2px solid #1f6e43;padding-bottom:3px;margin-top:28px}h3{font-size:15px;margin:0 0 4px}h4{font-size:13px;margin:12px 0 4px}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #c9d2cc;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eef4f0}
.b{display:inline-block;border-radius:10px;padding:1px 9px;font-size:12px;font-weight:600;vertical-align:2px}.m{color:#5a635e;font-size:12px}
.ctl{border:1px solid #c9d2cc;border-radius:8px;padding:12px;margin:14px 0;page-break-inside:avoid}.warn{border:2px solid #c98a00;background:#fff7e0;padding:8px 10px;border-radius:6px}
.score{font-size:30px;font-weight:700;color:#1f6e43}.r-pass{color:#1f6e43;font-weight:600}.r-fail{color:#a12a1d;font-weight:600}.r-unknown{color:#8a6300;font-weight:600}
.kv th{width:200px}.sig td{height:60px}code{font-size:11px;word-break:break-all}
@media print{body{margin:0}a{color:inherit}}</style></head><body>
<h1>SAMA Cyber Security Framework — SIEM evidence pack</h1>
<div class="m">${esc(opts.org || ZYB_ORG.short)} · ${ZYB_ORG.short} SIEM</div>
<p class="warn"><b>Draft mapping — verify with the ${ZYB_ORG.short} compliance team.</b> This pack shows what the SIEM can evidence from live data. Controls marked "Not SIEM-evidenced" are owned and evidenced in AI GRC. Control ids and titles: ${esc(report.catalogue)}; map version ${esc(report.map_version)}.</p>
<table class="kv"><tr><th>Generated</th><td>${esc(report.generated_at)}${opts.generatedBy ? ` by ${esc(opts.generatedBy)}` : ''}</td></tr>
<tr><th>Evidence period</th><td>${esc(report.period && report.period.from)} → ${esc(report.period && report.period.to)} (${esc(report.period && report.period.days)} days)</td></tr>
<tr><th>Required retention</th><td>${esc(report.settings && report.settings.required_retention_days)} days</td></tr>
<tr><th>Required source classes</th><td>${esc(((report.settings && report.settings.required_source_classes) || []).join(', '))}</td></tr>
<tr><th>Data store</th><td>${report.clickhouse && report.clickhouse.ok ? 'ClickHouse reachable' : `ClickHouse evidence incomplete: ${esc(report.clickhouse && report.clickhouse.error)}`}</td></tr>
<tr><th>Evidence digest</th><td><code>sha256:${esc(sha)}</code></td></tr></table>
<h2>Summary</h2><p><span class="score">${esc(s.coverage_pct)}%</span> coverage across ${esc(s.evidenced)} SIEM-evidenced controls (covered = 1, partial = 0.5, gap = 0).
Covered ${esc(s.counts.covered)} · Partial ${esc(s.counts.partial)} · Gap ${esc(s.counts.gap)} · Not SIEM-evidenced ${esc(s.counts['n/a'])}</p>
<table><tr><th>Domain</th><th>Covered</th><th>Partial</th><th>Gap</th><th>Not SIEM-evidenced</th></tr>${doms}</table>
<table><tr><th>Control</th><th>Title</th><th>Status</th><th>Main finding</th></tr>${list}</table>
${overview(report.evidence_overview)}
<h2>Controls evidenced by the SIEM</h2>${ev.map(controlSection).join('')}
<h2>Controls not evidenced by the SIEM (owned by GRC)</h2><table><tr><th>Control</th><th>Title</th><th>Owner</th><th>Reason</th></tr>${na.map((c) => `<tr><td>${esc(c.id)}</td><td>${esc(c.title)}</td><td>${esc(c.owner)}</td><td>${esc((c.reasons || [])[0])}</td></tr>`).join('')}</table>
<h2>Review and sign-off</h2><table class="sig"><tr><th>Role</th><th>Name</th><th>Signature</th><th>Date</th></tr>
<tr><td>Prepared by — SOC Manager</td><td></td><td></td><td></td></tr><tr><td>Reviewed by — CISO</td><td></td><td></td><td></td></tr>
<tr><td>Verified by — Compliance</td><td></td><td></td><td></td></tr><tr><td>Auditor</td><td></td><td></td><td></td></tr></table>
<p class="m">Generated automatically by the ${ZYB_ORG.short} SIEM from live engine data. The evidence digest is the SHA-256 of the JSON evidence this page was rendered from (the JSON pack returns the same digest while the evidence is cached).</p>
</body></html>`;
}

module.exports = { renderHtml, digest, esc };
