// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network Configuration Management over the daily read-only configuration capture (config-audit.js: "show running-config"
 * through the allow-listed CLI, secrets removed before anything is kept). Nothing here connects to a device or changes one.
 *   versions     every capture whose hash differs from the last kept one is stored as a VERSION (the redacted text, its hash, when
 *                it was first seen and the read before it); the last 20 per device are kept
 *   diff         line diff between any two versions (longest common subsequence; above 4,000 lines a set difference, said so)
 *   attribution  a new version is AUTHORISED when an approved change plan for that device (netops_changes: applied / validated /
 *                executing) was applied between the read before it and the read that saw it (plus one hour); otherwise it is
 *                UNAUTHORISED - a change nobody recorded. The first version of a device is the BASELINE, not a change.
 *   golden       an operator marks one version as the approved baseline; drift = lines added / removed against it
 *   backups      last good read: ok within 26 h, stale after, never read, or failing with the error the capture recorded
 *   learning     per device, the weekly change count against its own history (robust z on median / MAD, 6+ weeks) and changes
 *                first seen outside Riyadh working hours (Sun-Thu 07:00-18:00); a risk score whose every point is named
 *   createNcm({ state, configAudit, changes, now }) -> { capture(), view(), versions(id), diff(id, a, b), setGolden(id, sha, by) }
 */
const KEEP = 20, DAY = 86400000, STALE_MS = 26 * 3600000, LCS_MAX = 4000, TZ = 3;
const median = (a) => { const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length ? (b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2) : 0; };
function robustZ(hist, x) { if (hist.length < 6) return null; const m = median(hist), mad = median(hist.map((v) => Math.abs(v - m))); return (x - m) / (1.4826 * (mad || 0.5)); }
const offHours = (ms) => { const d = new Date(ms + TZ * 3600000), dow = d.getUTCDay(), h = d.getUTCHours(); return dow === 5 || dow === 6 || h < 7 || h >= 18; };

function lineDiff(a, b) {
  const A = String(a || '').split('\n'), B = String(b || '').split('\n');
  if (A.length > LCS_MAX || B.length > LCS_MAX) {
    const sa = new Set(A), sb = new Set(B);
    return { exact: false, note: 'large configuration: lines compared as sets, order ignored', lines: A.filter((l) => !sb.has(l)).map((t) => ({ op: '-', t })).concat(B.filter((l) => !sa.has(l)).map((t) => ({ op: '+', t }))) };
  }
  const n = A.length, m = B.length, L = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = A[i] === B[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) { if (A[i] === B[j]) { out.push({ op: ' ', t: A[i] }); i++; j++; } else if (L[i + 1][j] >= L[i][j + 1]) out.push({ op: '-', t: A[i++] }); else out.push({ op: '+', t: B[j++] }); }
  while (i < n) out.push({ op: '-', t: A[i++] }); while (j < m) out.push({ op: '+', t: B[j++] });
  return { exact: true, lines: out };
}

function createNcm({ state, configAudit, changes, now = Date.now }) {
  const V = () => state.collection('netops_config_versions'), G = () => state.collection('netops_config_golden');
  const versionsOf = (id) => V().all((x) => x.device === id).sort((a, b) => a.first_seen - b.first_seen);
  // keep a version whenever the captured configuration's hash moved
  function capture() {
    let added = 0;
    for (const c of configAudit.list()) {
      if (!c.sha256 || !c.text) continue;
      const vs = versionsOf(c.id), last = vs[vs.length - 1];
      if (last && last.sha256 === c.sha256) continue;
      const h = (c.history || []).find((x) => x.sha256 === c.sha256) || {};
      V().put({ id: c.id + '|' + c.sha256.slice(0, 16) + '|' + (h.first_seen || c.at), device: c.id, name: c.name, vendor: c.vendor, sha256: c.sha256, first_seen: h.first_seen || c.at,
        previous_read: h.previous_read || null, text: c.text, size: String(c.text).split('\n').length });
      added++;
      const all = versionsOf(c.id); for (const x of all.slice(0, Math.max(0, all.length - KEEP))) V().remove(x.id);
    }
    return { added };
  }
  function planFor(dev, v) {
    if (!changes || typeof changes.list !== 'function') return null;
    const from = v.previous_read || (v.first_seen - DAY), to = v.first_seen + 3600000;
    return (changes.list({}) || []).find((p) => p.device === dev && ['applied', 'validated', 'executing'].includes(p.status)
      && [p.applied_at, p.executed_at, p.validated_at, p.decided_at].some((t) => { const x = typeof t === 'number' ? t : Date.parse(t); return isFinite(x) && x >= from && x <= to; })) || null;
  }
  function classify(dev, vs) {
    return vs.map((v, i) => { if (!i) return Object.assign({}, v, { kind: 'baseline', plan: null }); const p = planFor(dev, v); return Object.assign({}, v, { kind: p ? 'authorised' : 'unauthorised', plan: p ? { id: p.id, title: p.title, status: p.status } : null, off_hours: offHours(v.first_seen) }); });
  }
  function view() {
    capture();
    const t = now(), rows = [];
    for (const c of configAudit.list()) {
      const vs = classify(c.id, versionsOf(c.id)), ch = vs.filter((v) => v.kind !== 'baseline'), gold = G().get(c.id);
      const last = vs[vs.length - 1] || null, g = gold && vs.find((v) => v.sha256 === gold.sha256);
      let drift = null;
      if (g && last && g.sha256 !== last.sha256) { const d = lineDiff(g.text, last.text); drift = { added: d.lines.filter((l) => l.op === '+').length, removed: d.lines.filter((l) => l.op === '-').length }; }
      else if (g) drift = { added: 0, removed: 0 };
      const backup = !c.at ? (c.error ? 'failing' : 'never') : t - c.at > STALE_MS ? (c.error ? 'failing' : 'stale') : 'ok';
      // weekly change counts over the kept history, against the device's own usual
      const weeks = []; for (let w = 0; w < 12; w++) { const a = t - (w + 1) * 7 * DAY, b = t - w * 7 * DAY; weeks.push(ch.filter((v) => v.first_seen > a && v.first_seen <= b).length); }
      const z = robustZ(weeks.slice(1), weeks[0]);
      const pts = [], P = (label, n) => { if (n) pts.push({ label, points: n }); };
      const unauth = ch.filter((v) => v.kind === 'unauthorised' && t - v.first_seen <= 30 * DAY);
      P(unauth.length + ' change(s) in 30 days with no approved change plan', Math.min(45, unauth.length * 15));
      P('a change outside working hours (30 days)', ch.some((v) => v.off_hours && t - v.first_seen <= 30 * DAY) ? 10 : 0);
      P('more changes this week than usual (robust z ' + (z == null ? '' : Math.round(z * 10) / 10) + ')', z != null && z >= 3 ? 15 : 0);
      P('backup ' + backup, backup === 'failing' ? 20 : backup === 'stale' ? 10 : backup === 'never' ? 15 : 0);
      P('drifted from the golden baseline (' + (drift ? drift.added + drift.removed : 0) + ' lines)', drift && drift.added + drift.removed ? 10 : 0);
      P('no golden baseline set', !gold && vs.length ? 5 : 0);
      rows.push({ id: c.id, name: c.name, vendor: c.vendor, site: c.site || '', role: c.role || '', backup, last_read: c.at || null, checked: c.checked || null, error: c.error || '',
        versions: vs.length, changes_30d: ch.filter((v) => t - v.first_seen <= 30 * DAY).length, unauthorised_30d: unauth.length, last_change: ch.length ? ch[ch.length - 1].first_seen : null,
        golden: gold ? { sha256: gold.sha256, by: gold.by, at: gold.at } : null, drift, weekly: weeks.slice().reverse(), unusual_week: z != null && z >= 3,
        risk: Math.min(100, pts.reduce((s, x) => s + x.points, 0)), risk_why: pts });
    }
    rows.sort((a, b) => b.risk - a.risk || String(a.name).localeCompare(String(b.name)));
    const recent = [];
    for (const r of rows) for (const v of classify(r.id, versionsOf(r.id))) if (v.kind !== 'baseline' && t - v.first_seen <= 30 * DAY) recent.push({ device: r.id, name: r.name, sha256: v.sha256, first_seen: v.first_seen, kind: v.kind, plan: v.plan, off_hours: v.off_hours });
    recent.sort((a, b) => b.first_seen - a.first_seen);
    const cnt = (f) => rows.filter(f).length;
    return { generated_at: new Date(t).toISOString(), devices: rows, recent: recent.slice(0, 100),
      kpis: { devices: rows.length, backed_up: cnt((r) => r.backup === 'ok'), failing: cnt((r) => r.backup === 'failing' || r.backup === 'never'), stale: cnt((r) => r.backup === 'stale'),
        changes_30d: recent.length, unauthorised_30d: recent.filter((x) => x.kind === 'unauthorised').length, drifted: cnt((r) => r.drift && r.drift.added + r.drift.removed), no_golden: cnt((r) => !r.golden) },
      note: 'Configurations are read once a day, read only, with secrets removed. A change is authorised only when an approved change plan for that device was applied in the window; the first copy of a device is its baseline.' };
  }
  function versions(id) { return classify(id, versionsOf(id)).map((v) => ({ sha256: v.sha256, first_seen: v.first_seen, size: v.size, kind: v.kind, plan: v.plan, off_hours: v.off_hours || false, golden: !!(G().get(id) && G().get(id).sha256 === v.sha256) })).reverse(); }
  function diff(id, a, b) {
    const vs = versionsOf(id), find = (s) => vs.find((v) => v.sha256 === s || v.sha256.startsWith(s));
    const A = a ? find(a) : (G().get(id) && find(G().get(id).sha256)) || vs[vs.length - 2], B = b ? find(b) : vs[vs.length - 1];
    if (!A || !B) return null;
    const d = lineDiff(A.text, B.text);
    return { device: id, from: { sha256: A.sha256, first_seen: A.first_seen }, to: { sha256: B.sha256, first_seen: B.first_seen }, exact: d.exact, note: d.note || '',
      added: d.lines.filter((l) => l.op === '+').length, removed: d.lines.filter((l) => l.op === '-').length, lines: d.lines.length > 6000 ? d.lines.filter((l) => l.op !== ' ').slice(0, 6000) : d.lines };
  }
  function setGolden(id, sha, by) {
    const v = versionsOf(id).find((x) => x.sha256 === sha); if (!v) return null;
    const rec = { id, sha256: sha, by, at: new Date(now()).toISOString() }; G().put(rec); return rec;
  }
  function text(id, sha) { const v = versionsOf(id).find((x) => x.sha256 === sha); return v ? { device: id, sha256: v.sha256, first_seen: v.first_seen, text: v.text } : null; }
  return { capture, view, versions, diff, setGolden, text };
}

module.exports = { createNcm, lineDiff, offHours };
