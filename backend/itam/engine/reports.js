// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Summary + reports aggregations (read-only). Pure over the services passed in.
const DAY = 86400000;

function createReports({ assets, licences, findings, ingest, settings, agentgw }) {
  function daysUntil(iso) { const t = Date.parse(iso); return Number.isFinite(t) ? Math.round((t - Date.now()) / DAY) : null; }

  function summary() {
    const st = settings.get();
    const all = assets.all();
    const live = all.filter((a) => a.status !== 'disposed');
    const byType = {}; const byStatus = {}; const bySite = {};
    let networked = 0; let offNetwork = 0;
    let warrantyExpiring = 0; let eolExpiring = 0;
    for (const a of live) {
      byType[a.type] = (byType[a.type] || 0) + 1;
      byStatus[a.status] = (byStatus[a.status] || 0) + 1;
      const site = a.site || '(unknown)'; bySite[site] = (bySite[site] || 0) + 1;
      if (a.networked) networked++; else offNetwork++;
      if (a.warranty && a.warranty.end) { const d = daysUntil(a.warranty.end); if (d !== null && d <= st.expiry_window_days) warrantyExpiring++; }
      if (a.eol) { const d = daysUntil(a.eol); if (d !== null && d <= st.expiry_window_days) eolExpiring++; }
    }
    const compliance = licences.complianceView();
    const licSummary = { total: compliance.length, over: compliance.filter((l) => l.compliance === 'over').length, under: compliance.filter((l) => l.compliance === 'under').length, ok: compliance.filter((l) => l.compliance === 'ok').length };
    const coverage = {};
    for (const a of live) for (const s of a.sources || []) coverage[s.source] = (coverage[s.source] || 0) + 1;
    const agents = agentgw ? agentgw.listAgents() : [];
    return {
      total: live.length,
      by_type: byType, by_status: byStatus, by_site: bySite,
      networked, off_network: offNetwork,
      warranty_expiring: warrantyExpiring, eol_expiring: eolExpiring,
      licences: licSummary,
      ai_findings: findings.summary(),
      discovery: { coverage, runs: ingest.runSummaries(), unmatched: ingest.discoveredList().length },
      agents: { total: agents.length, active: agents.filter((a) => a.status === 'active').length, stale: agents.filter((a) => a.stale).length },
      thresholds: { not_seen_days: st.not_seen_days, expiry_window_days: st.expiry_window_days },
    };
  }

  function reports() {
    const compliance = licences.complianceView();
    return {
      licence_compliance: compliance.map((l) => ({ id: l.id, product: l.product, seats: l.seats, used: l.used, compliance: l.compliance, delta: l.delta, expiry: l.expiry })),
      warranty_eol: assets.all().filter((a) => a.status !== 'disposed' && ((a.warranty && a.warranty.end) || a.eol)).map((a) => ({ id: a.id, name: a.name, asset_tag: a.asset_tag, warranty_end: a.warranty && a.warranty.end, eol: a.eol, warranty_days: a.warranty && a.warranty.end ? daysUntil(a.warranty.end) : null, eol_days: a.eol ? daysUntil(a.eol) : null })).sort((x, y) => (x.eol_days == null ? 1e9 : x.eol_days) - (y.eol_days == null ? 1e9 : y.eol_days)),
      findings_open: findings.list((f) => f.status === 'open').length,
    };
  }

  return { summary, reports };
}

module.exports = { createReports };
