// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guard: guardJob } = require('../util/errors');
/*
 * Periodic push of SIEM evidence per SAMA control into AI GRC (sentra-grcai). OFF by default
 * (config compliance.sama.grc_push.enabled). Uses the existing GRC evidence-upload endpoint:
 *
 *   POST {url}/evidence      url default http://127.0.0.1:9140/api/grcai (GRC listens on loopback behind nginx)
 *     headers  X-Sentra-Proxy-Secret: secrets.json grcai_proxy_secret   (GRC refuses every request without it)
 *              X-Auth-User: grc_push.user (default sentra-siem)   X-Auth-Role: grc_push.role (GRC needs operator to upload)
 *     body     { fw: "sama", refs: ["3.3.14"], name: "siem-sama-3.3.14-2026-10-06.json", type: "json",
 *                dataB64: <base64 JSON evidence for that control>, note, send_to_ai: grc_push.send_to_ai (default false) }
 *     → { evidence: {id, sha256, refs…}, duplicate }      (GRC stores the file once per content, links refs on duplicates)
 *
 * One file per SIEM-evidenced control per run; n/a controls are not pushed. A failed control does not stop the others.
 * The engine never deletes or edits GRC evidence. A dedicated endpoint for automated checks (status + metrics per
 * control without a file, e.g. POST /api/grcai/automated-checks {fw, source, generated_at, controls:[{ref, status,
 * score, checks[], evidence_digest}]}) would let GRC show "automated evidence" next to the maturity level; until it
 * exists the JSON file is the hand-off (see the report's evidence digest).
 *
 *   createGrcPush({ sama, config, log, fetch?, now? }) → { pushNow(reason), start(), stop(), status() }
 */
const H = 3600000;

function createGrcPush({ sama, config = {}, log, fetch: fetchFn, now = Date.now } = {}) {
  const L = log || { info() {}, warn() {}, error() {} };
  const opts = Object.assign({ enabled: false, url: 'http://127.0.0.1:9140/api/grcai', interval_h: 24, user: 'sentra-siem', role: 'operator', send_to_ai: false, timeout_ms: 15000 },
    ((config.compliance || {}).sama || {}).grc_push || {});
  const secret = (config.secrets && config.secrets.grcai_proxy_secret) || '';
  const doFetch = fetchFn || globalThis.fetch;
  let timer = null; let first = null; let running = null; let last = null;

  function problems() {
    const p = [];
    if (!/^https?:\/\/[^\s]+$/i.test(String(opts.url || ''))) p.push('grc_push.url invalid');
    if (!secret || secret.length < 16) p.push('secrets.json grcai_proxy_secret missing (≥ 16 characters)');
    if (typeof doFetch !== 'function') p.push('fetch not available (Node >= 18 required)');
    return p;
  }

  async function post(body) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), Number(opts.timeout_ms) || 15000);
    try {
      const res = await doFetch(String(opts.url).replace(/\/+$/, '') + '/evidence', {
        method: 'POST', signal: ac.signal,
        headers: { 'Content-Type': 'application/json', 'X-Sentra-Proxy-Secret': secret, 'X-Auth-User': String(opts.user), 'X-Auth-Role': String(opts.role) },
        body: JSON.stringify(body),
      });
      const text = await res.text();
      let j = null; try { j = JSON.parse(text); } catch { /* keep text */ }
      if (!res.ok) throw new Error(`GRC answered ${res.status}: ${(j && j.error) || text.slice(0, 200)}`);
      return j || {};
    } finally { clearTimeout(t); }
  }

  async function run(reason) {
    const t0 = now();
    const p = problems();
    if (p.length) { last = { at: new Date(t0).toISOString(), ok: false, reason, error: 'not configured: ' + p.join('; '), pushed: 0, failed: 0 }; return last; }
    const rep = await sama.report({ refresh: '1' });
    const day = rep.generated_at.slice(0, 10);
    const results = [];
    for (const c of rep.controls.filter((x) => x.siem_evidenced)) {
      const doc = { kind: 'sentra-siem SAMA CSF automated evidence', control: { id: c.id, title: c.title, domain: c.domain }, status: c.status,
        generated_at: rep.generated_at, period: rep.period, map_version: rep.map_version, verify_with_compliance_team: true,
        checks: c.checks, gaps_and_actions: c.actions, contributing_rules: c.contributing_rules, source_classes: c.source_classes, recent_alerts: c.recent_alerts };
      const body = { fw: 'sama', refs: [c.id], name: `siem-sama-${c.id}-${day}.json`, type: 'json', dataB64: Buffer.from(JSON.stringify(doc, null, 2)).toString('base64'),
        note: `Automated SIEM evidence for SAMA CSF ${c.id} ${c.title}: status ${c.status} (${rep.period.days}-day period). Draft mapping — verify with the compliance team.`,
        send_to_ai: !!opts.send_to_ai };
      try { const r = await post(body); results.push({ control: c.id, ok: true, evidence_id: r.evidence && r.evidence.id, duplicate: !!r.duplicate }); } catch (e) { results.push({ control: c.id, ok: false, error: e.name === 'AbortError' ? 'timeout' : e.message }); }
    }
    const failed = results.filter((r) => !r.ok);
    last = { at: new Date(t0).toISOString(), ok: !failed.length, reason, pushed: results.length - failed.length, failed: failed.length, duration_ms: now() - t0, results };
    (failed.length ? L.warn : L.info)('sama: evidence pushed to AI GRC', { pushed: last.pushed, failed: last.failed, reason });
    return last;
  }

  function pushNow(reason = 'manual') {
    if (!running) running = run(reason).catch((e) => { last = { at: new Date(now()).toISOString(), ok: false, reason, error: e.message, pushed: 0, failed: 0 }; return last; }).finally(() => { running = null; });
    return running;
  }
  function start() {
    if (!opts.enabled) return false;
    const p = problems();
    if (p.length) L.warn('sama: GRC evidence push enabled but not configured', { problems: p });
    const every = Math.max(1, Number(opts.interval_h) || 24) * H;
    first = setTimeout(() => pushNow('startup'), 5 * 60000);
    timer = setInterval(guardJob('compliance.grc-push', () => pushNow('schedule')), every);
    if (first.unref) first.unref();
    if (timer.unref) timer.unref();
    return true;
  }
  function stop() { if (first) clearTimeout(first); if (timer) clearInterval(timer); first = timer = null; return running || Promise.resolve(); }
  function status() { return { enabled: !!opts.enabled, url: opts.url, interval_h: Number(opts.interval_h) || 24, send_to_ai: !!opts.send_to_ai, problems: problems(), running: !!running, last }; }
  return { pushNow, start, stop, status };
}

module.exports = { createGrcPush };
