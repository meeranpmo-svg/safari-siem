// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Ingest pipeline: normalise each source, de-dup/merge into asset records, propose CMDB relationships, and stage
// unmatched discoveries for human adoption (unless settings.auto_adopt). Pure orchestration over the assets service
// and the connectors — the connectors do the reading, this decides what becomes/updates an asset.
const asset = require('./model/asset');

function createIngest({ assets, settings, store, audit, log }) {
  const discovered = store.collection('discovered');  // staged unmatched devices awaiting adoption
  const runs = store.collection('discovery_runs');    // last run summary per source

  function stageKey(source, sourceId) { return `${source}:${sourceId}`; }

  function stage(source, sourceId, fields, lastSeen) {
    const id = stageKey(source, sourceId);
    const now = new Date().toISOString();
    const cur = discovered.get(id);
    const rec = {
      id, source, source_id: String(sourceId), fields,
      first_seen: cur ? cur.first_seen : now, last_seen: lastSeen || now,
      seen_count: (cur ? cur.seen_count : 0) + 1, adopted_asset_id: cur ? cur.adopted_asset_id || null : null,
    };
    discovered.put(rec);
    return rec;
  }

  // upsert one device/record from a discovery source, honouring auto_adopt staging.
  function ingestOne(source, item, { adopt }) {
    const fields = item.fields || item;
    const sourceId = item.source_id != null ? String(item.source_id) : '';
    const sighting = { source_id: sourceId || null, at: item.last_seen || new Date().toISOString(), detail: item.detail || null };
    // if already staged + adopted, keep updating that asset
    const staged = sourceId ? discovered.get(stageKey(source, sourceId)) : null;
    if (staged && staged.adopted_asset_id && assets.raw(staged.adopted_asset_id)) {
      const r = assets.upsert(fields, source, sighting, { forceAssetId: staged.adopted_asset_id });
      return { assetId: r.assetId, created: false, staged: false, sourceId };
    }
    // try a deterministic match
    const existing = assets.all().filter((x) => x.status !== 'disposed');
    const keys = require('./model/merge').identityKeys(fields);
    const decision = require('./model/merge').decideMatch(keys, existing);
    if (decision.match) {
      const r = assets.upsert(fields, source, sighting, { forceAssetId: decision.match.id });
      return { assetId: r.assetId, created: false, staged: false, ambiguous: decision.ambiguous, sourceId };
    }
    if (!adopt) { const s = stage(source, sourceId, fields, item.last_seen); return { assetId: null, created: false, staged: true, stageId: s.id, sourceId, ambiguous: decision.ambiguous }; }
    const r = assets.upsert(fields, source, sighting);
    return { assetId: r.assetId, created: true, staged: false, sourceId };
  }

  function recordRun(source, summary) {
    runs.put(Object.assign({ id: source, source, at: new Date().toISOString() }, summary));
  }

  // ---- netops (sensor) --------------------------------------------------------------------------------------------
  async function runNetops(connector) {
    const st = settings.get();
    if (!st.sources.sensor && !st.sources.netops) return { ok: false, error: 'netops/sensor source disabled' };
    const dr = await connector.devices();
    if (!dr.ok) { recordRun('sensor', { ok: false, error: dr.error }); return dr; }
    const idMap = new Map(); // netops source_id → assetId
    let created = 0; let matched = 0; let stagedN = 0;
    for (const dev of dr.devices) {
      const r = ingestOne('sensor', dev, { adopt: st.auto_adopt });
      if (r.created) created++; else if (r.staged) stagedN++; else matched++;
      if (r.assetId && r.sourceId) idMap.set(r.sourceId, r.assetId);
    }
    // topology → connected_to proposals between adopted assets
    let relProposed = 0;
    const tr = await connector.topology().catch(() => ({ ok: false }));
    if (tr && tr.ok) {
      for (const e of tr.edges) {
        const a = idMap.get(String(e.a_source_id)); const b = idMap.get(String(e.b_source_id));
        if (!a || !b || a === b) continue;
        try { assets.addRelationship({ from: a, to: b, type: 'connected_to', source: 'sensor', rationale: `LLDP neighbour via ${e.via || 'port'}` }, { user: 'source:sensor', role: 'system' }, { source: 'sensor', autoConfirm: true }); relProposed++; } catch { /* endpoint missing */ }
      }
    }
    const summary = { ok: true, seen: dr.devices.length, matched, created, staged: stagedN, relationships: relProposed };
    recordRun('sensor', summary);
    if (audit) audit({ by: 'source:sensor', role: 'system', action: 'ingest.netops', target: 'netops', detail: summary });
    return summary;
  }

  // ---- vcenter ----------------------------------------------------------------------------------------------------
  async function runVcenter(connector) {
    const st = settings.get();
    if (!st.sources.vcenter) return { ok: false, error: 'vcenter source disabled' };
    const pr = await connector.pull();
    if (!pr.ok) { recordRun('vcenter', { ok: false, error: pr.error }); return pr; }
    const idMap = new Map();
    let created = 0; let matched = 0; let stagedN = 0;
    for (const h of pr.hosts) { const r = ingestOne('vcenter', h, { adopt: st.auto_adopt }); if (r.created) created++; else if (r.staged) stagedN++; else matched++; if (r.assetId) idMap.set(h.source_id, r.assetId); }
    for (const v of pr.vms) { const r = ingestOne('vcenter', v, { adopt: st.auto_adopt }); if (r.created) created++; else if (r.staged) stagedN++; else matched++; if (r.assetId) idMap.set(v.source_id, r.assetId); }
    let relProposed = 0;
    for (const rel of pr.relationships) {
      const vm = idMap.get(rel.vm_source_id); const host = idMap.get(rel.host_source_id);
      if (!vm || !host) continue;
      try { assets.addRelationship({ from: vm, to: host, type: 'runs_on', source: 'vcenter', rationale: 'vCenter VM placed on host' }, { user: 'source:vcenter', role: 'system' }, { source: 'vcenter', autoConfirm: false }); relProposed++; } catch { /* missing */ }
    }
    const summary = { ok: true, seen: pr.hosts.length + pr.vms.length, hosts: pr.hosts.length, vms: pr.vms.length, matched, created, staged: stagedN, relationships: relProposed };
    recordRun('vcenter', summary);
    if (audit) audit({ by: 'source:vcenter', role: 'system', action: 'ingest.vcenter', target: 'vcenter', detail: summary });
    return summary;
  }

  // ---- endpoint agent (always adopts: an enrolled endpoint is explicit) -------------------------------------------
  function fromAgentReport(agentgw, agent, report) {
    const st = settings.get();
    if (!st.sources.agent) return { ok: false, error: 'agent source disabled' };
    const sighting = { source_id: agent.id, at: new Date().toISOString() };
    const facts = asset.normaliseSourceFields(report.facts).fields;
    let assetId = agent.asset_id && assets.raw(agent.asset_id) ? agent.asset_id : null;
    let r;
    if (assetId) r = assets.upsert(facts, 'agent', sighting, { forceAssetId: assetId });
    else {
      // An agent may only merge into an asset it created or was explicitly bound to. Any serial/tag/MAC/hostname match
      // against another record is treated as AMBIGUOUS and staged for human review — never merged on the agent's word.
      const M = require('./model/merge');
      const cands = M.matchCandidates(M.identityKeys(facts), assets.all().filter((x) => x.status !== 'disposed'));
      if (cands.length) {
        const s = stage('agent', agent.id, facts, sighting.at);
        if (audit) audit({ by: `agent:${agent.id}`, role: 'system', action: 'agent.report.review', target: agent.id, detail: { stage_id: s.id, candidates: cands.slice(0, 5).map((c) => c.asset.id) } });
        return { ok: true, assetId: null, created: false, review: true, stageId: s.id, candidates: cands.slice(0, 5).map((c) => c.asset.id), software: 0 };
      }
      r = assets.upsert(facts, 'agent', sighting);
    }
    assetId = r.assetId;
    assets.setSoftware(assetId, report.software, 'agent');
    if (report.patch_level) { const a = assets.raw(assetId); if (a) { a.patch_level = report.patch_level; a.updated_at = new Date().toISOString(); store.collection('assets').put(a); } }
    agentgw.bindAsset(agent.id, assetId);
    return { ok: true, assetId, created: r.created, software: report.software.length };
  }

  // ---- adoption ---------------------------------------------------------------------------------------------------
  function adopt(stageId, who) {
    const d = discovered.get(stageId);
    if (!d) throw Object.assign(new Error('discovered item not found'), { status: 404 });
    if (d.adopted_asset_id && assets.raw(d.adopted_asset_id)) return { assetId: d.adopted_asset_id, already: true };
    const r = assets.upsert(d.fields, d.source, { source_id: d.source_id, at: d.last_seen });
    discovered.patch(stageId, (o) => { o.adopted_asset_id = r.assetId; });
    // a human adopting an agent's staged report is the explicit binding of that agent to the resulting asset
    if (d.source === 'agent') { const ag = store.collection('agents'); if (ag.get(d.source_id)) ag.patch(d.source_id, (o) => { o.asset_id = r.assetId; }); }
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'discovery.adopt', target: r.assetId, detail: { source: d.source, source_id: d.source_id } });
    return { assetId: r.assetId, already: false };
  }

  function discoveredList({ includeAdopted = false } = {}) {
    return discovered.all((d) => includeAdopted || !d.adopted_asset_id).map((d) => ({ id: d.id, source: d.source, source_id: d.source_id, fields: d.fields, first_seen: d.first_seen, last_seen: d.last_seen, seen_count: d.seen_count, adopted_asset_id: d.adopted_asset_id || null }));
  }
  function runSummaries() { return runs.all().map((r) => { const { id, ...rest } = r; return Object.assign({ source: id }, rest); }); }

  return { ingestOne, runNetops, runVcenter, fromAgentReport, adopt, discoveredList, runSummaries, stage };
}

module.exports = { createIngest };
