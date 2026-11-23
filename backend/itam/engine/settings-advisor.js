// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ITAM Settings advisor (Platform -> ITAM Settings, {P} = /api/itam). Reads the ITAM settings, the connector credential STATE (never a
 * value), agents, enrolment tokens, the register and the settings change history, and says what to change and why - every
 * recommendation carries its evidence and, where it is a setting, the exact change; the page applies it only when an administrator
 * clicks (through the existing POST /settings, audited there). Nothing here writes.
 *   learned        not-seen threshold: the 90th percentile of "days since last seen" among in-use networked assets seen in the last
 *                  120 days - the threshold below which normal assets are flagged as missing; how many each value flags
 *                  expiry window: the longest renewal lead time learned on Renewals & Expiry (else its default) + 30 days
 *   sources        a source switched on that reported no asset for 7 days; vCenter on without its credentials; a source switched off
 *                  while assets still carry it as their only source
 *   agents         servers / workstations / laptops in use with no endpoint agent, by site; agents not reporting; enrolment tokens
 *                  never used and expired or older than 7 days
 *   adoption       discovered devices waiting to be adopted vs auto-adopt
 *   AI privacy     the external model allowed with no extra redaction terms
 *   score          0-100 = share of these checks that pass
 *   GET /settings/advisor     admin
 */
const DAY = 86400000;
const AGENT_TYPES = { server: 1, workstation: 1, laptop: 1 };
const pct = (a, p) => { const x = a.slice().sort((m, n) => m - n); return x.length ? x[Math.min(x.length - 1, Math.floor(p * (x.length - 1) + 0.5))] : null; };

function createSettingsAdvisor(app, opts = {}) {
  const now = opts.now || Date.now;
  async function advise() {
    const T = now(), st = app.settings.get(), creds = app.settings.credentialStatus(), recs = [], checks = [];
    const R = (id, sev, title, why, extra) => recs.push(Object.assign({ id, severity: sev, title, why }, extra || {}));
    const C = (name, pass) => checks.push({ name, pass: !!pass });
    const assets = app.store.collection('assets').all((a) => !['retired', 'disposed', 'lost'].includes(a.status));
    const age = (a) => (a.last_seen ? (T - Date.parse(a.last_seen)) / DAY : null);
    // not-seen threshold, learned
    const seen = assets.filter((a) => a.status === 'in_use' && a.networked && age(a) != null && age(a) <= 120).map(age);
    const learnedNs = seen.length >= 10 ? Math.max(7, Math.ceil(pct(seen, 0.9))) : null;
    const flags = (d) => assets.filter((a) => a.status === 'in_use' && a.networked && age(a) != null && age(a) > d).length;
    const ns = { current: st.not_seen_days, flagged_now: flags(st.not_seen_days), learned: learnedNs, flagged_learned: learnedNs == null ? null : flags(learnedNs), sample: seen.length };
    if (learnedNs != null && learnedNs > st.not_seen_days * 1.25) R('not_seen_low', 'medium', 'Not-seen threshold is shorter than how often assets normally report', '90 % of in-use networked assets were seen within ' + learnedNs + ' days (' + seen.length + ' assets); at ' + st.not_seen_days + ' days ' + ns.flagged_now + ' assets are flagged as not seen, at ' + learnedNs + ' days ' + ns.flagged_learned + '.', { apply: { not_seen_days: learnedNs } });
    else if (learnedNs != null && learnedNs * 2 < st.not_seen_days) R('not_seen_high', 'low', 'Not-seen threshold is much longer than needed', 'assets normally report within ' + learnedNs + ' days, so a missing asset is noticed only after ' + st.not_seen_days + ' days.', { apply: { not_seen_days: Math.max(7, learnedNs * 2) } });
    C('Not-seen threshold fits how assets report', learnedNs == null || (learnedNs <= st.not_seen_days * 1.25 && learnedNs * 2 >= st.not_seen_days));
    // expiry window vs learned renewal lead times
    let maxLead = null, leadSrc = 'default';
    try { const H = app.addons && app.addons.expiryHub; if (H) { const v = await H.view('admin'); const LT = Object.values(v.lead_times || {}), L = LT.map((k) => k.days); if (L.length) { maxLead = Math.max(...L); leadSrc = LT.some((k) => k.learned) ? 'learned' : 'default'; } } } catch (e) { /* renewals view unavailable: the expiry window check is skipped */ }
    if (maxLead != null && st.expiry_window_days < maxLead + 30) R('expiry_short', 'medium', 'Warranty / end-of-life window is shorter than the renewal lead time', 'renewals need up to ' + maxLead + ' days (' + leadSrc + ' on Renewals & Expiry); a ' + st.expiry_window_days + '-day window warns too late.', { apply: { expiry_window_days: maxLead + 30 } });
    C('Expiry window covers the renewal lead time', maxLead == null || st.expiry_window_days >= maxLead + 30);
    // sources
    const srcSeen = {}; for (const a of assets) for (const s of a.sources || []) { const k = typeof s === 'string' ? s : s && s.source; const at = (s && s.last_seen) || a.last_seen; if (!k) continue; const t = at ? Date.parse(at) : 0; srcSeen[k] = Math.max(srcSeen[k] || 0, t); }
    for (const [k, on] of Object.entries(st.sources || {})) {
      if (!on) { const only = assets.filter((a) => (a.sources || []).length === 1 && ((a.sources[0] && a.sources[0].source) || a.sources[0]) === k).length; if (only) R('src_off_' + k, 'low', 'Source "' + k + '" is off but ' + only + ' asset(s) are known only from it', 'they will go stale; switch it back on or add another source for them.', { apply: { sources: Object.assign({}, st.sources, { [k]: true }) } }); continue; }
      const last = srcSeen[k] || 0, silent = !last || T - last > 7 * DAY;
      if (silent && k !== 'netops') R('src_silent_' + k, 'medium', 'Source "' + k + '" is on but reported nothing for 7 days', last ? 'last asset from it ' + new Date(last).toISOString().slice(0, 10) : 'no asset has ever come from it', { fix: k === 'agent' ? 'Issue enrolment tokens and install the agent (Agents tab).' : k === 'vcenter' ? 'Set the vCenter credentials and check the connector.' : 'Check the site sensor subscription.' });
      C('Source ' + k + ' reports', !silent || k === 'netops');
    }
    if (st.sources && st.sources.vcenter && !((creds.vcenter_user || {}).configured && (creds.vcenter_pass || {}).configured)) { R('vcenter_creds', 'high', 'vCenter is on without its credentials', 'the connector cannot log in; set the read-only vCenter user and password (Credentials tab).', { fix: 'Credentials tab' }); C('vCenter credentials set', false); }
    // agents
    const need = assets.filter((a) => AGENT_TYPES[a.type] && a.status === 'in_use'), noAgent = need.filter((a) => !(a.sources || []).some((s) => (s && s.source ? s.source : s) === 'agent'));
    const bySite = {}; for (const a of noAgent) bySite[a.site || '(no site)'] = (bySite[a.site || '(no site)'] || 0) + 1;
    const coverage = need.length ? Math.round(100 * (need.length - noAgent.length) / need.length) : null;
    if (coverage != null && coverage < 90) R('agent_coverage', coverage < 60 ? 'high' : 'medium', 'Endpoint agent on ' + coverage + ' % of servers and PCs', noAgent.length + ' without it - most at ' + Object.entries(bySite).sort((x, y) => y[1] - x[1]).slice(0, 3).map(([s, n]) => s + ' (' + n + ')').join(', ') + '. Without the agent there is no installed software, serial or hardware detail for them.', { fix: 'Issue a token per site (Agents tab).', sites: bySite });
    C('Agent on 90 % of servers and PCs', coverage == null || coverage >= 90);
    let agents = [], tokens = [];
    try { agents = app.agentgw.listAgents(); tokens = app.agentgw.listTokens(); } catch (e) { /* agent gateway unavailable: agent checks skipped */ }
    const stale = agents.filter((a) => a.stale && a.status !== 'revoked');
    if (stale.length) R('agents_stale', 'medium', stale.length + ' agent(s) stopped reporting', stale.slice(0, 6).map((a) => (a.name || a.id) + (a.last_seen ? ' (last ' + String(a.last_seen).slice(0, 10) + ')' : '')).join(', '), { fix: 'Check the agent service on those machines, or revoke the agents of machines that were replaced.' });
    C('All agents report', !stale.length);
    const oldTok = tokens.filter((t) => !t.used_at && !t.revoked && ((t.expires_at && Date.parse(t.expires_at) < T) || (t.created_at && T - Date.parse(t.created_at) > 7 * DAY)));
    if (oldTok.length) R('tokens_unused', 'low', oldTok.length + ' enrolment token(s) never used', 'issued ' + oldTok.map((t) => String(t.created_at).slice(0, 10)).slice(0, 5).join(', ') + ' and still open - revoke them so a leaked token cannot enrol a machine.', { fix: 'Revoke on the Agents tab.', tokens: oldTok.map((t) => t.token_prefix) });
    C('No stale enrolment tokens', !oldTok.length);
    // adoption
    let waiting = 0; try { waiting = app.store.collection('disc_devices').all((d) => d.status !== 'ignored' && !d.asset_id).length; } catch (e) { /* discovery not installed */ }
    if (waiting >= 25 && !st.auto_adopt) R('adopt', 'low', waiting + ' discovered devices are waiting to be adopted', 'they are not in the register until a person adopts them (Asset Discovery), or auto-adopt is switched on.', { apply: { auto_adopt: true }, apply_note: 'Auto-adopt creates records for every new device; review the discovery scopes first.' });
    C('Discovered devices are adopted', waiting < 25 || st.auto_adopt);
    // AI privacy
    if (st.external_ai_allowed && !(st.redact_terms || []).length) R('ai_redact', 'medium', 'The external model is allowed with no extra redaction terms', 'sanitised content leaves the platform; add company-specific terms (project names, customer names) to redact.', { fix: 'AI privacy on the General tab.' });
    C('AI redaction set for the external model', !st.external_ai_allowed || (st.redact_terms || []).length);
    const history = app.store.auditTail ? app.store.auditTail(500).filter((a) => /^settings\./.test(a.action || '')).slice(-20).reverse().map((a) => ({ at: a.at || a.ts, by: a.by, action: a.action, target: a.target })) : [];
    const SEV = { high: 0, medium: 1, low: 2 }; recs.sort((a, b) => SEV[a.severity] - SEV[b.severity]);
    return { at: new Date(T).toISOString(), score: checks.length ? Math.round(100 * checks.filter((c) => c.pass).length / checks.length) : null, checks, recommendations: recs,
      learned: { not_seen: ns, expiry: { current: st.expiry_window_days, max_lead_days: maxLead, basis: leadSrc } },
      agents: { need: need.length, without: noAgent.length, coverage_pct: coverage, by_site: bySite, enrolled: agents.length, stale: stale.length }, discovery_waiting: waiting, history,
      note: 'Recommendations only - a setting changes when an administrator applies it. Thresholds are learned from this register.' };
  }
  return { advise };
}

function registerSettingsAdvisor(srv, app, A) {
  srv.route('GET', '/settings/advisor', (ctx) => { ctx.need('admin'); return A.advise(); });
}

module.exports = { createSettingsAdvisor, registerSettingsAdvisor };
