// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');
const httpc = require('./discovery/httpc');
const xml = require('./discovery/xml');
const cucmM = require('./discovery/methods/cucm');
/*
 * Cisco Unified CM - monitor and manage ({P} = /api/itam). READ with the AXL credential stored in Asset Discovery (kind cucm_axl,
 * role "Standard AXL Read Only API Access" + RIS / PerfMon read):
 *   phones        AXL listPhone + RisPort70 selectCmDevice (engine/discovery/methods/cucm.js): name, MAC, model, device pool,
 *                 description, registration status, IP
 *   trunks        RisPort70 selectCmDevice, DeviceClass SIPTrunk and Gateway: registration per trunk / gateway
 *   calls         PerfMon perfmonCollectCounterData, object "Cisco CallManager": CallsActive, CallsAttempted, CallsCompleted,
 *                 RegisteredHardwarePhones (cumulative counters → the share of failed calls between two polls)
 *   The SOAP element names follow the published RisPort70 / PerfMon WSDLs; confirm against the customer's CUCM version.
 * LEARN (explainable, each finding says why; a baseline needs 6 polls - "learning" before):
 *   pool drop      a device pool's registered share below its own median - max(5 points, 3 x MAD)
 *   flapping       a phone that changed registration 3+ times in 24 h (network, PoE or a duplicate)
 *   stale          a phone not registered for 7+ days (reclaim the licence, or remove it)
 *   trunk down     a SIP trunk / gateway not registered
 *   failed calls   the failed share of attempted calls in the last interval above its own baseline (robust z >= 4, 20+ calls)
 *   busy           active calls at or above 90 % of the highest seen
 * CHANGE (four-eyes): restart or reset phones (AXL doDeviceReset) - proposed by an operator, approved by a different person who is an
 * administrator, run with a SEPARATE AXL write credential and only when write_enabled is on. Nothing else is changed from here.
 *   GET  /cucm                     viewer    summary, pools, trunks, calls, findings (no phone list - it names people)
 *   GET  /cucm/phones              operator  every phone with its status and history
 *   PUT  /cucm/settings            admin     {credential_id, write_credential_id?, write_enabled, poll_min}
 *   POST /cucm/poll                operator
 *   POST /cucm/changes             operator  {type: restart | reset, phones[], reason}
 *   POST /cucm/changes/:id/decide  admin     {decision, comment}   never the proposer
 *   POST /cucm/changes/:id/run     operator
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const median = (a) => { const s = a.slice().sort((x, y) => x - y), n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; };
const PHONE = /^(?:SEP|ATA|BAT|CSF|TCT|BOT|TAB)[0-9A-Za-z]{1,40}$/;

function risClass(cls) {
  return '<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">'
    + '<soapenv:Header/><soapenv:Body><soap:selectCmDevice><soap:StateInfo></soap:StateInfo><soap:CmSelectionCriteria><soap:MaxReturnedDevices>1000</soap:MaxReturnedDevices>'
    + `<soap:DeviceClass>${cls}</soap:DeviceClass><soap:Model>255</soap:Model><soap:Status>Any</soap:Status><soap:NodeName></soap:NodeName><soap:SelectBy>Name</soap:SelectBy>`
    + '<soap:SelectItems><soap:item><soap:Item>*</soap:Item></soap:item></soap:SelectItems><soap:Protocol>Any</soap:Protocol><soap:DownloadStatus>Any</soap:DownloadStatus>'
    + '</soap:CmSelectionCriteria></soap:selectCmDevice></soapenv:Body></soapenv:Envelope>';
}
function perfBody(host) {
  return '<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">'
    + `<soapenv:Header/><soapenv:Body><soap:perfmonCollectCounterData><soap:Host>${xml.esc(host)}</soap:Host><soap:Object>Cisco CallManager</soap:Object></soap:perfmonCollectCounterData></soapenv:Body></soapenv:Envelope>`;
}
function parsePerf(text) {
  const out = {}, re = /<(?:\w+:)?Name>([^<]+)<\/(?:\w+:)?Name>\s*<(?:\w+:)?Value>(-?\d+(?:\.\d+)?)<\/(?:\w+:)?Value>/g; let m;
  while ((m = re.exec(String(text || '')))) { const k = m[1].split('\\').pop(); out[k] = Number(m[2]); }
  return out;
}
function resetBody(ver, name, hard) {
  return '<?xml version="1.0" encoding="UTF-8"?>' + `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/${xml.esc(ver)}">`
    + `<soapenv:Header/><soapenv:Body><ns:doDeviceReset><deviceName>${xml.esc(name)}</deviceName><isHardReset>${hard ? 'true' : 'false'}</isHardReset><isMGCP>false</isMGCP><deviceResetType>${hard ? 'Reset' : 'Restart'}</deviceResetType></ns:doDeviceReset></soapenv:Body></soapenv:Envelope>`;
}

// the explainable model over the latest read and the history (pure, tested)
function assess(snap, hist, phoneHist, now) {
  const F = [], add = (sev, code, title, fix, target) => F.push({ severity: sev, code, title, fix, target: target || '' });
  const learning = hist.length < 6;
  const pools = {};
  for (const p of snap.phones || []) { const k = p.device_pool || 'no pool'; const o = pools[k] = pools[k] || { pool: k, phones: 0, registered: 0 }; o.phones++; if (p.status === 'Registered') o.registered++; }
  for (const o of Object.values(pools)) {
    o.pct = o.phones ? Math.round(1000 * o.registered / o.phones) / 10 : null;
    const past = hist.map((h) => h.pools && h.pools[o.pool]).filter(Boolean).map((x) => x.pct).filter((x) => x != null);
    if (!learning && past.length >= 6 && o.pct != null) {
      const m = median(past), mad = median(past.map((x) => Math.abs(x - m))) || 0; o.usual = m;
      if (o.pct < m - Math.max(5, 3 * mad)) add(o.pct < m - 20 ? 'high' : 'medium', 'pool-drop', `Device pool ${o.pool}: ${o.registered} of ${o.phones} phones registered (${o.pct} %), usually ${m} %`, 'Check the site\'s WAN / VPN to the call manager, the voice VLAN and PoE on its switches', o.pool);
    }
  }
  for (const p of snap.phones || []) {
    const h = phoneHist[p.name] || { changes: [], since: null };
    const recent = (h.changes || []).filter((t) => now - t < DAY).length;
    if (recent >= 3) add('medium', 'flapping', `${p.name} changed registration ${recent} times in 24 h`, 'Check the switch port (errors, PoE), the cable and for a duplicate IP / name', p.name);
    if (p.status !== 'Registered' && h.since && now - h.since > 7 * DAY) add('low', 'stale', `${p.name} (${p.description || p.model || ''}) not registered for ${Math.floor((now - h.since) / DAY)} days`, 'Reclaim its licence or remove the phone', p.name);
  }
  for (const t of snap.trunks || []) if (t.status && t.status !== 'Registered') add('high', 'trunk-down', `${t.class === 'Gateway' ? 'Gateway' : 'SIP trunk'} ${t.name}: ${t.status}`, 'Check the far end (carrier / gateway), the SIP OPTIONS ping and the route between them', t.name);
  const c = snap.calls || {};
  if (c.failed_pct != null && c.attempted_delta >= 20) {
    const past = hist.map((h) => h.calls && h.calls.failed_pct).filter((x) => x != null);
    if (!learning && past.length >= 6) { const m = median(past), mad = median(past.map((x) => Math.abs(x - m))) || 0, s = 1.4826 * mad || Math.max(1, m * 0.2); const z = (c.failed_pct - m) / s;
      if (z >= 4) add('high', 'failed-calls', `${c.failed_pct} % of the last ${c.attempted_delta} calls failed - usually ${Math.round(m * 10) / 10} %`, 'Look at the trunks and gateways first, then the call manager\'s CDR / RTMT alerts'); }
  }
  const peak = Math.max(0, ...hist.map((h) => (h.calls && h.calls.active) || 0));
  if (c.active != null && peak >= 10 && c.active >= 0.9 * peak) add('low', 'busy', `${c.active} active calls - ${Math.round(100 * c.active / peak)} % of the highest seen (${peak})`, 'Watch trunk channels and licences at peak hours');
  const SEV = { high: 3, medium: 2, low: 1 }; F.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
  return { findings: F, pools: Object.values(pools).sort((a, b) => (a.pct || 0) - (b.pct || 0)), learning };
}

function createCucm(app, opts = {}) {
  const now = opts.now || Date.now, C = (n) => app.store.collection(n), iso = () => new Date(now()).toISOString();
  const cfg = () => C('cucm_cfg').get('settings') || { id: 'settings' };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'cucm.' + action, target, detail }); };
  const D = () => app.discovery || null;
  const st = { polls: 0, last_poll_at: null, last_error: '' };
  async function withCred(id, fn) { const V = D() && D().vault; if (!V) throw httpErr(409, 'Asset Discovery is not installed - the CUCM login is stored there'); const c = V.open(id); try { return await fn(c); } finally { c.release(); } }
  function soapOf(c) {
    const t = c.target || {}, req = opts.request || httpc.request, auth = 'Basic ' + Buffer.from(`${c.secret.username}:${c.secret.password}`).toString('base64');
    return async (p, action, b) => { const r = await req(`https://${t.host}:${t.port || 8443}${p}`, { method: 'POST', headers: { 'Content-Type': 'text/xml; charset=utf-8', SOAPAction: action, Authorization: auth, Accept: 'text/xml' }, body: b, caFile: t.ca_file, timeoutMs: 30000 });
      if (r.status === 401 || r.status === 403) throw httpErr(502, 'CUCM refused the login (HTTP ' + r.status + ')'); if (r.status >= 400) throw httpErr(502, 'CUCM ' + action + ': HTTP ' + r.status); return r.text; };
  }
  async function poll() {
    const s = cfg(); if (!s.credential_id) throw httpErr(409, 'no CUCM login chosen - an administrator picks the AXL credential (Asset Discovery → Credentials, kind CUCM AXL)');
    const errors = [], at = now();
    try {
      const snap = await withCred(s.credential_id, async (c) => {
        const r = await cucmM.collect(c, { request: opts.request }); if (!r.ok) throw httpErr(502, 'CUCM phones not read (' + r.error_class + ')');
        const soap = soapOf(c), trunks = [];
        for (const cls of ['SIPTrunk', 'Gateway']) { try { for (const [name, v] of cucmM.parseRis(await soap('/realtimeservice2/services/RISService70', 'selectCmDevice', risClass(cls)))) trunks.push({ name, class: cls, status: v.status, ip: v.ip }); } catch (e) { errors.push(cls + ': ' + e.message); } }
        let perf = {}; try { perf = parsePerf(await soap('/perfmonservice2/services/PerfmonService', 'perfmonCollectCounterData', perfBody(c.target.host))); } catch (e) { errors.push('PerfMon: ' + e.message); }
        return { phones: r.phones, trunks, perf };
      });
      const prev = C('cucm_snap').get('latest'), pc = prev && prev.calls;
      const calls = { active: snap.perf.CallsActive != null ? snap.perf.CallsActive : null, attempted: snap.perf.CallsAttempted, completed: snap.perf.CallsCompleted, attempted_delta: null, failed_pct: null };
      if (pc && calls.attempted != null && pc.attempted != null && calls.attempted >= pc.attempted) { const da = calls.attempted - pc.attempted, dc = calls.completed - pc.completed; calls.attempted_delta = da; calls.failed_pct = da > 0 ? Math.round(1000 * Math.max(0, da - dc) / da) / 10 : null; }
      // per-phone registration history: change times and since when it is not registered
      const ph = C('cucm_phone_hist'), prevBy = new Map(((prev && prev.phones) || []).map((p) => [p.name, p.status]));
      for (const p of snap.phones) { const h = ph.get(p.name) || { id: p.name, changes: [], since: null }; const was = prevBy.get(p.name);
        if (was !== undefined && was !== p.status) h.changes = h.changes.concat(at).filter((t) => at - t < 3 * DAY).slice(-50);
        h.since = p.status === 'Registered' ? null : h.since || at; ph.put(h); }
      const out = { id: 'latest', at: iso(), phones: snap.phones, trunks: snap.trunks, calls, errors };
      C('cucm_snap').put(out);
      const a = assess(out, [], {}, at);   // pools for the history line
      C('cucm_hist').put({ id: out.at, pools: Object.fromEntries(a.pools.map((p) => [p.pool, { pct: p.pct, phones: p.phones }])), calls: { active: calls.active, failed_pct: calls.failed_pct } });
      for (const o of C('cucm_hist').all((x) => now() - Date.parse(x.id) > 30 * DAY)) C('cucm_hist').remove(o.id);
      st.polls++; st.last_poll_at = out.at; st.last_error = errors.join(' · ');
      return status();
    } catch (e) { st.last_error = e.message; throw e; }
  }
  function status() { const s = cfg(); return Object.assign({ configured: !!s.credential_id, write_enabled: !!(s.write_enabled && s.write_credential_id), poll_min: s.poll_min || 15 }, st); }
  function model() {
    const snap = C('cucm_snap').get('latest'); if (!snap) return null;
    const hist = C('cucm_hist').all().sort((a, b) => String(a.id).localeCompare(String(b.id))).slice(0, -1).slice(-200);
    const ph = {}; for (const h of C('cucm_phone_hist').all()) ph[h.id] = h;
    return { snap, a: assess(snap, hist, ph, now()) };
  }
  function view() {
    const m = model(); if (!m) return { status: status(), polled: false, note: status().configured ? 'not polled yet - press Poll now' : 'no CUCM login chosen - an administrator picks it in the settings below' };
    const P = m.snap.phones, reg = P.filter((p) => p.status === 'Registered').length;
    return { status: status(), polled: true, at: m.snap.at, learning: m.a.learning, kpis: { phones: P.length, registered: reg, unregistered: P.length - reg, trunks: m.snap.trunks.length, trunks_down: m.snap.trunks.filter((t) => t.status !== 'Registered').length, active_calls: m.snap.calls.active, failed_pct: m.snap.calls.failed_pct },
      pools: m.a.pools, trunks: m.snap.trunks, calls: m.snap.calls, findings: m.a.findings.map((f) => (f.code === 'stale' || f.code === 'flapping' ? Object.assign({}, f, { title: f.title.replace(/\(.*\)/, '') }) : f)), errors: m.snap.errors,
      changes: C('cucm_changes').all().sort((a, b) => String(b.id).localeCompare(String(a.id))).slice(0, 50) };
  }
  function phones() { const m = model(); if (!m) return { phones: [] }; const ph = {}; for (const h of C('cucm_phone_hist').all()) ph[h.id] = h; return { phones: m.snap.phones.map((p) => Object.assign({}, p, { changes_24h: ((ph[p.name] || {}).changes || []).filter((t) => now() - t < DAY).length, unregistered_since: (ph[p.name] || {}).since ? new Date(ph[p.name].since).toISOString() : null })) }; }
  function settings(b0, who) {
    const b = body(b0).str('credential_id', { id: true }).str('write_credential_id', { id: true }).bool('write_enabled').int('poll_min', { min: 5, max: 240 }).done();
    const V = D() && D().vault; const kindOf = (id) => { const c = V && V.get(id); return c && c.kind; };
    for (const k of ['credential_id', 'write_credential_id']) if (b[k] && kindOf(b[k]) !== 'cucm_axl') throw httpErr(400, k + ': not a CUCM AXL credential in Asset Discovery');
    const cur = Object.assign({}, cfg(), b, { id: 'settings' });
    if (cur.write_credential_id && cur.write_credential_id === cur.credential_id) throw httpErr(400, 'write_credential_id: use a separate AXL account for changes, not the read-only one');
    if (cur.write_enabled && !cur.write_credential_id) throw httpErr(400, 'write_credential_id: needed to run approved changes');
    C('cucm_cfg').put(cur); audit(who, 'settings', 'cucm', { credential: !!cur.credential_id, write_credential: !!cur.write_credential_id, write_enabled: !!cur.write_enabled, poll_min: cur.poll_min || 15 }); return status();
  }
  const chg = () => C('cucm_changes');
  function nextId() { let m = 0; for (const x of chg().all()) { const n = Number(String(x.id).slice(5)); if (n > m) m = n; } return 'UCCH-' + String(m + 1).padStart(5, '0'); }
  function propose(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person proposes a change');
    const b = body(b0).oneOf('type', ['restart', 'reset'], { required: true }).list('phones', { required: true, max: 200, item: 'str', itemMax: 50, unique: true }).str('reason', { required: true, min: 10, max: 500 }).done();
    const snap = C('cucm_snap').get('latest'), known = new Set(((snap && snap.phones) || []).map((p) => p.name));
    const bad = b.phones.filter((p) => !PHONE.test(p) || !known.has(p)); if (bad.length) throw httpErr(400, 'phones: not in the last CUCM read: ' + bad.slice(0, 5).join(', '));
    const c = chg().put({ id: nextId(), type: b.type, phones: b.phones, reason: b.reason, status: 'proposed', proposed_by: who.user, proposed_at: iso() });
    audit(who, 'change.propose', c.id, { type: c.type, phones: c.phones.length }); return c;
  }
  function decide(id, b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'only a person approves'); if (who.role !== 'admin') throw httpErr(403, 'an administrator approves CUCM changes');
    param(id); const c = chg().get(id); if (!c) throw httpErr(404, 'change not found'); if (c.status !== 'proposed') throw httpErr(409, 'only a proposed change is decided');
    if (String(c.proposed_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who proposed it does not approve it');
    const b = body(b0).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 400 }).done();
    if (b.decision === 'rejected' && !(b.comment && b.comment.length >= 5)) throw httpErr(400, 'comment: say why it is rejected');
    const n = chg().patch(id, (x) => { x.status = b.decision; x.decided_by = who.user; x.decided_at = iso(); x.comment = b.comment || ''; return x; });
    audit(who, 'change.' + (b.decision === 'approved' ? 'approve' : 'reject'), id, { proposed_by: c.proposed_by }); return n;
  }
  async function run(id, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person runs an approved change');
    param(id); const c = chg().get(id); if (!c) throw httpErr(404, 'change not found'); if (c.status !== 'approved') throw httpErr(409, 'a change runs only once approved');
    const s = cfg(); if (!(s.write_enabled && s.write_credential_id)) throw httpErr(409, 'running changes is switched off - an administrator chooses a separate AXL write login and switches it on');
    const res = [];
    await withCred(s.write_credential_id, async (cr) => { const soap = soapOf(cr), ver = (cr.target && cr.target.axl_version) || '12.5';
      for (const p of c.phones) { try { await soap('/axl/', `"CUCM:DB ver=${ver} doDeviceReset"`, resetBody(ver, p, c.type === 'reset')); res.push({ phone: p, ok: true }); } catch (e) { res.push({ phone: p, ok: false, error: e.message }); } } });
    const failed = res.filter((r) => !r.ok).length;
    const n = chg().patch(id, (x) => { x.status = failed ? (failed === res.length ? 'failed' : 'partly-done') : 'done'; x.run_by = who.user; x.run_at = iso(); x.results = res; return x; });
    audit(who, 'change.run', id, { type: c.type, phones: res.length, failed }); return n;
  }
  let timer = null; const tick = guardOf(app, 'cucm.poll', async () => { if (cfg().credential_id) await poll(); });
  return { view, phones, poll, settings, propose, decide, run, status, assess,
    start() { if (timer || opts.noTimer) return; const loop = async () => { try { await tick(); } finally { timer = setTimeout(loop, Math.max(5, cfg().poll_min || 15) * 60000); timer.unref(); } }; timer = setTimeout(loop, 120000); timer.unref(); },
    stop() { if (timer) clearTimeout(timer); timer = null; } };
}

function registerCucm(srv, app, X) {
  srv.route('GET', '/cucm', (ctx) => { ctx.need('viewer'); return X.view(); });
  srv.route('GET', '/cucm/phones', (ctx) => { ctx.need('operator'); return X.phones(); });
  srv.route('PUT', '/cucm/settings', (ctx) => { ctx.need('admin'); return X.settings(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/cucm/poll', (ctx) => { ctx.need('operator'); return X.poll(); });
  srv.route('POST', '/cucm/changes', (ctx) => { ctx.need('operator'); return X.propose(ctx.body, ctx.who); }, { maxBody: 16384 });
  srv.route('POST', '/cucm/changes/:id/decide', (ctx) => { ctx.need('admin'); return X.decide(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/cucm/changes/:id/run', (ctx) => { ctx.need('operator'); return X.run(ctx.params.id, ctx.who); });
}

module.exports = { createCucm, registerCucm, assess, parsePerf, risClass, resetBody };
