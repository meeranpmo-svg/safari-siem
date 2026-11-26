// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Endpoint-agent gateway (like sentra-netops sensors): one-time enrolment token → per-agent key; outbound-only
// heartbeat + report with bearer-key auth and replay protection. The gateway stores only a sha256 of each key.
const crypto = require('node:crypto');
const asset = require('./model/asset');
const { normSoftwareEntry } = require('./model/software');

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const bad = (msg, status = 400, code) => Object.assign(new Error(msg), { status, code2: code });
const newToken = () => crypto.randomBytes(24).toString('hex');
const newAgentId = () => `agt_${crypto.randomBytes(6).toString('hex')}`;

function createAgentGateway({ store, audit, config }) {
  const tokens = store.collection('enrol_tokens');
  const agents = store.collection('agents');
  const ttlH = (config && config.agent && config.agent.enrol_token_ttl_hours) || 24;
  const skewS = (config && config.agent && config.agent.clock_skew_s) || 300;
  const staleH = (config && config.agent && config.agent.heartbeat_stale_hours) || 48;
  // enrolment tokens are kept as a sha256 under a derived id - never the token itself (state files, snapshots, backups);
  // tokens issued before this were stored under the raw token: they are re-keyed at start-up
  const tokId = (token) => 'tok_' + sha256(token).slice(0, 40);
  for (const t of tokens.all()) {
    if (/^tok_/.test(String(t.id))) continue;
    const raw = String(t.id), rec = Object.assign({}, t, { id: tokId(raw), prefix: raw.slice(0, 8) });
    tokens.put(rec); tokens.remove(raw);
  }

  // ---- admin: issue / list / revoke enrolment tokens ------------------------------------------------------------
  function issueToken(body, who) {
    const token = newToken();
    const now = Date.now();
    const rec = {
      id: tokId(token), prefix: token.slice(0, 8), created_by: who && who.user, created_at: new Date(now).toISOString(),
      expires_at: new Date(now + ttlH * 3600 * 1000).toISOString(),
      note: asset.s(body && body.note, 300) || null, site: asset.s(body && body.site, 200) || null,
      used_at: null, used_by_agent: null,
    };
    tokens.put(rec);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'agent.token.issue', target: token.slice(0, 8), detail: { note: rec.note, site: rec.site, expires_at: rec.expires_at } });
    // the raw token is returned exactly once; it is never stored in plaintext elsewhere or logged
    return { token, expires_at: rec.expires_at, note: rec.note, site: rec.site, install_hint: `printf '%s\\n' '${token}' | itam-agent enrol --server https://<portal-url>${(config && config.api && config.api.agent_prefix) || '/agent'} --token-stdin` };
  }
  function listTokens() {
    return tokens.all().map((t) => ({ token_prefix: t.prefix || String(t.id).slice(0, 8), created_by: t.created_by, created_at: t.created_at, expires_at: t.expires_at, note: t.note, site: t.site, used_at: t.used_at, used_by_agent: t.used_by_agent, revoked: !!t.revoked }));
  }
  function revokeToken(prefix, who) {
    // the first 8 characters shown in the list, matching exactly one token - a short prefix could revoke the wrong one
    const p = String(prefix || '');
    if (!/^[0-9a-f]{8,}$/i.test(p)) throw bad('prefix: the first 8 characters of the token, as listed', 400);
    const hits = tokens.all().filter((x) => p.toLowerCase().startsWith(String(x.prefix || '').toLowerCase()) && String(x.prefix || '').length === 8 && p.length >= 8);
    if (hits.length > 1) throw bad('more than one token starts with ' + p.slice(0, 8) + ' - revoke the agent instead, or issue new tokens', 409);
    const t = hits[0];
    if (!t) throw bad('token not found', 404);
    tokens.patch(t.id, (o) => { o.revoked = true; o.revoked_at = new Date().toISOString(); });
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'agent.token.revoke', target: t.prefix || String(t.id).slice(0, 8) });
    return { ok: true };
  }

  // the note on a token (what it was issued for, e.g. "Hyper-V: HV-HOST-01"): corrected by an administrator; exact 8-character prefix
  function setTokenNote(prefix, note, who) {
    const p = String(prefix || '');
    if (!/^[0-9a-f]{8}$/i.test(p)) throw bad('prefix: the first 8 characters of the token, as listed', 400);
    const hits = tokens.all().filter((x) => String(x.prefix || '').toLowerCase() === p.toLowerCase());
    if (hits.length !== 1) throw bad(hits.length ? 'more than one token starts with ' + p : 'token not found', hits.length ? 409 : 404);
    const before = hits[0].note, v = asset.s(note, 300) || null;
    tokens.patch(hits[0].id, (o) => { o.note = v; });
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'agent.token.note', target: p, detail: { from: before, to: v } });
    return { ok: true };
  }
  // ---- admin: list / revoke agents ------------------------------------------------------------------------------
  function listAgents() {
    const now = Date.now();
    return agents.all().map((a) => ({
      id: a.id, name: a.name, platform: a.platform, status: a.status, site: a.site,
      enrolled_at: a.enrolled_at, last_seen: a.last_seen, last_report_at: a.last_report_at, asset_id: a.asset_id || null,
      stale: a.last_seen ? (now - Date.parse(a.last_seen)) > staleH * 3600 * 1000 : true,
    }));
  }
  function revokeAgent(id, who) {
    const a = agents.get(id);
    if (!a) throw bad('agent not found', 404);
    agents.patch(id, (o) => { o.status = 'revoked'; o.revoked_at = new Date().toISOString(); });
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'agent.revoke', target: id });
    return { ok: true };
  }

  // ---- agent: enrol -------------------------------------------------------------------------------------------
  function enrol(body) {
    const token = asset.s(body && body.token, 120);
    if (!token) throw bad('enrolment token required', 401, 'enrol_no_token');
    const t = tokens.get(tokId(token));
    if (!t || t.revoked) throw bad('invalid enrolment token', 401, 'enrol_bad_token');
    if (t.used_at) throw bad('enrolment token already used', 401, 'enrol_used');
    if (Date.parse(t.expires_at) < Date.now()) throw bad('enrolment token expired', 401, 'enrol_expired');
    const key = crypto.randomBytes(32).toString('hex');
    const id = newAgentId();
    const now = new Date().toISOString();
    const agentRec = {
      id, key_hash: sha256(key), name: asset.s(body.hostname || body.name, 300) || id,
      platform: asset.enumOf(body.platform, ['windows', 'linux', 'macos', 'other']) || 'other',
      fingerprint: asset.s(body.fingerprint, 200) || null, site: t.site || asset.s(body.site, 200) || null,
      status: 'active', enrolled_at: now, last_seen: now, last_report_at: null, last_seq: 0, nonces: [], asset_id: null,
    };
    agents.put(agentRec);
    tokens.patch(t.id, (o) => { o.used_at = now; o.used_by_agent = id; });
    if (audit) audit({ by: `agent:${id}`, role: 'system', action: 'agent.enrol', target: id, detail: { platform: agentRec.platform, name: agentRec.name, site: agentRec.site, token_prefix: token.slice(0, 8) } });
    // key returned exactly once
    return { agent_id: id, agent_key: key, heartbeat_interval_s: 3600 };
  }

  // ---- agent: authenticate a bearer key -------------------------------------------------------------------------
  function authenticate(bearer) {
    const key = String(bearer || '');
    if (!key) return null;
    const h = sha256(key);
    const hb = Buffer.from(h, 'hex');
    for (const a of agents.all()) {
      if (a.status !== 'active' || !a.key_hash) continue;
      try { if (crypto.timingSafeEqual(Buffer.from(a.key_hash, 'hex'), hb)) return a; } catch { /* length mismatch */ }
    }
    return null;
  }

  // ---- agent: heartbeat ---------------------------------------------------------------------------------------
  function heartbeat(agent) {
    const now = new Date().toISOString();
    agents.patch(agent.id, (o) => { o.last_seen = now; });
    return { ok: true, now, config: { heartbeat_interval_s: 3600 } };
  }

  // ---- agent: report (replay-protected) → normalised facts for the ingest pipeline ------------------------------
  // body: {seq(int), ts(ISO), nonce, host:{...}, software:[...]}. Returns {agent, facts, software}.
  function acceptReport(agent, body) {
    const seq = Number(body && body.seq);
    if (!Number.isInteger(seq) || seq < 1) throw bad('report seq must be a positive integer', 400, 'report_bad_seq');
    if (seq <= (agent.last_seq || 0)) throw bad(`replayed or out-of-order report (seq ${seq} <= ${agent.last_seq})`, 409, 'report_replay');
    const ts = Date.parse(asset.s(body.ts, 40));
    if (!Number.isFinite(ts)) throw bad('report ts must be an ISO timestamp', 400, 'report_bad_ts');
    const drift = Math.abs(Date.now() - ts) / 1000;
    if (drift > skewS) throw bad(`report timestamp outside the ${skewS}s window (drift ${Math.round(drift)}s)`, 409, 'report_stale');
    const nonce = asset.s(body.nonce, 120);
    if (nonce) { const ring = agent.nonces || []; if (ring.includes(nonce)) throw bad('replayed report nonce', 409, 'report_replay'); }
    // build normalised asset fields from the agent host facts
    const host = body.host && typeof body.host === 'object' ? body.host : {};
    // agent facts are UNTRUSTED input: normalise + cap them exactly like any other source (lengths, macs[] size)
    const os = asset.s(host.os, 300);
    const { fields: facts } = asset.normaliseSourceFields({
      name: host.hostname, serial: host.serial, asset_tag: host.asset_tag, uuid: host.uuid,
      type: host.type || (/(server)/i.test(os) ? 'server' : host.chassis === 'laptop' ? 'laptop' : 'workstation'),
      vendor: host.manufacturer, model: host.model, os: host.os, cpu: host.cpu,
      mem_gb: host.mem_gb, disk_gb: host.disk_gb, mac: host.mac, macs: host.macs, mgmt_ip: host.ip,
      networked: true, tags: ['agent-reported'],
    });
    const software = Array.isArray(body.software) ? body.software.map(normSoftwareEntry).filter(Boolean).slice(0, 5000) : [];
    // commit replay bookkeeping
    agents.patch(agent.id, (o) => {
      o.last_seq = seq; o.last_report_at = new Date().toISOString(); o.last_seen = o.last_report_at;
      o.nonces = (o.nonces || []).concat(nonce ? [nonce] : []).slice(-50);
    });
    return { agent, facts, software, patch_level: asset.s(host.patch_level, 200) || null };
  }
  function bindAsset(agentId, assetId) { agents.patch(agentId, (o) => { o.asset_id = assetId; }); }
  // admin: explicitly bind an agent to an existing asset (the only way an agent may report into a record it did not create)
  function bindAgent(agentId, assetId, assetsSvc, who) {
    const a = agents.get(agentId);
    if (!a) throw bad('agent not found', 404);
    const id = asset.s(assetId, 80);
    if (!id || !assetsSvc.raw(id)) throw bad('asset_id must be an existing asset', 404);
    const from = a.asset_id || null;
    bindAsset(agentId, id);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'agent.bind', target: agentId, detail: { from, to: id } });
    return { ok: true, agent_id: agentId, asset_id: id };
  }
  function getAgent(id) { return agents.get(id); }

  return {
    issueToken, listTokens, revokeToken, setTokenNote, listAgents, revokeAgent,
    enrol, authenticate, heartbeat, acceptReport, bindAsset, bindAgent, getAgent,
    staleH,
  };
}

module.exports = { createAgentGateway, sha256 };
