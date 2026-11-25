// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * AI engineer readiness ({P}/duty/readiness, viewer): for each AI engineer in the SIEM, is it FULLY working, and if not,
 * exactly what is missing and how to fix it. Every check reads the engine's own state - nothing is probed or changed.
 *   status per engineer: ready (everything in place) · partial (working, something limited) · blocked (cannot do its job)
 *   checks[{name, ok: true|false|null, detail, fix}]   null = not applicable / informational
 */
async function readiness(deps, D) {
  const N = deps.netopsInstance || deps.netops, S = deps.sysadminInstance || deps.sysadmin, O = deps.oracle;
  const eng = {}; for (const e of (D ? D.engineers() : [])) eng[e.id] = e;
  const P = D ? D.policy() : {};
  const chk = (name, ok, detail, fix) => ({ name, ok, detail: String(detail || ''), fix: ok === false ? String(fix || '') : '' });
  const dutyChecks = (id) => {
    const e = eng[id]; if (!e) return [chk('On the duty desk', false, 'not registered', 'Update the SIEM engine (update-platform.ps1)')];
    const late = e.late || (e.last_patrol == null && P.enabled);
    return [
      chk('On duty', !!e.on_duty, e.on_duty ? 'patrols every ' + (P.patrol_min || 10) + ' min' : 'duty desk switched off', 'AI Engineering Team → Duty policy → switch the duty desk on (admin)'),
      chk('Patrolling', e.last_error ? false : late ? null : true, e.last_error ? 'last patrol problem: ' + e.last_error : e.last_patrol ? 'last patrol ' + new Date(e.last_patrol).toISOString() : 'first patrol pending', 'Fix the problem named above; the next patrol retries by itself'),
    ];
  };
  const ai = (st) => chk('AI analysis', !!(st && st.enabled), st && st.enabled ? 'model ' + (st.model || '?') : (st && st.reason) || 'not available',
    ('On the server: sudo bash sentra-siem/install/netops-setup.sh --set-key --restart (an Anthropic API key, once ' + ZYB_ORG.short + ' approves sending device/server data to Anthropic). Without it the engineer still patrols and diagnoses rule-based.'));
  const out = [];

  // network + security: the onboarded devices
  const devs = N && N.inventory ? N.inventory.list() : [];
  const isFw = (d) => /^(fortigate|paloalto|cisco-asa)$/i.test(String(d.vendor || '')) || String(d.role || '').toLowerCase() === 'firewall';
  for (const [id, name, want, what] of [['network', 'AI Network Engineer', (d) => !isFw(d), 'switches / routers / wireless'], ['security', 'AI Security Engineer', isFw, 'firewalls (Palo Alto, FortiGate, Cisco ASA)']]) {
    const mine = devs.filter(want);
    const cred = mine.filter((d) => { try { const c = N.inventory.credentialSummary(d.id); return !!(c.snmp || c.api); } catch (e) { return false; } });
    const polled = mine.filter((d) => { try { const s = N.poller.snapshot(d.id); return s && s.ok !== false; } catch (e) { return false; } });
    const checks = [
      chk('Devices onboarded', mine.length > 0, mine.length + ' ' + what, 'Network Discovery / Add a Server or Network Device → approve the devices (or ITAM → Sync to the AI Network Engineer)'),
      chk('Read-only credentials', mine.length ? cred.length === mine.length : null, cred.length + ' of ' + mine.length + ' with SNMP or API credentials', 'AI Network Engineer → device → set the read-only SNMP v3 / API credentials for the ' + (mine.length - cred.length) + ' device(s) without them'),
      chk('Polling answers', mine.length ? polled.length > 0 && polled.length >= Math.ceil(mine.length * 0.9) : null, polled.length + ' of ' + mine.length + ' answered the last poll', 'Check reachability / ACLs from the SIEM server to the devices that do not answer (AI Network Engineer → device → Poll now shows the error)'),
      ai(N && N.ai && N.ai.status()),
    ].concat(dutyChecks(id));
    out.push({ id, name, engine: 'siem', checks });
  }

  // windows + exchange: onboarded servers, logins, the PowerShell remoting helper
  let helper = null; try { helper = S && S.runner && S.runner.status ? await S.runner.status() : null; } catch (e) { helper = null; }
  for (const [id, name, what] of [['windows', 'AI Windows Server Administrator', 'Windows servers'], ['exchange', 'AI Exchange Server Administrator', 'Exchange servers']]) {
    const list = S && S.targets ? S.targets.list(id) : [];
    const withLogin = list.filter((t) => { try { const l = S.targets.loginSummary(t); return !!l[id]; } catch (e) { return false; } });
    const checked = list.filter((t) => { try { const s = S.health.snapshot(t.id); return s && s.at; } catch (e) { return false; } });
    const failing = list.filter((t) => { try { const s = S.health.snapshot(t.id); return s && s.results && Object.values(s.results).some((r) => r && r.error); } catch (e) { return false; } });
    out.push({ id, name, engine: 'siem', checks: [
      chk('Servers onboarded', list.length > 0, list.length + ' ' + what, 'AI Server Administrators → Servers → add the ' + what + ' (or ITAM → Sync to the AI Server Administrators)'),
      chk('Read-only logins', list.length ? withLogin.length === list.length : null, withLogin.length + ' of ' + list.length + ' with a login profile', 'AI Server Administrators → Logins → create the read-only profile and assign it to the ' + (list.length - withLogin.length) + ' server(s) without one'),
      chk('PowerShell remoting helper', helper ? !!helper.available : (checked.length ? true : null), helper ? (helper.available ? 'pypsrp ready' : helper.reason) : (checked.length ? 'health checks are running' : 'not run yet'), 'On the server: sudo bash sentra-siem/install/netops-cli-setup.sh (installs pypsrp for WinRM; the update prints the reason if it cannot)'),
      chk('Health checks answer', list.length ? checked.length > 0 && failing.length < Math.max(1, list.length / 2) : null, checked.length + ' checked, ' + failing.length + ' with failing checks', 'Open a server with failing checks: WinRM (5985/5986) must be reachable from the SIEM and the login must be in the read-only group'),
      ai(S && S.ai && S.ai.status()),
    ].concat(dutyChecks(id)) });
  }

  // Oracle DBA
  let ora = null; try { if (O) { const s = await O.summary({}); ora = { instances: s.totals.instances, stale: s.totals.stale }; } } catch (e) { ora = null; }
  out.push({ id: 'dba', name: 'AI Oracle DBA', engine: 'siem', checks: [
    chk('Oracle module', !!O, O ? 'installed' : 'not installed', 'Update the SIEM engine'),
    chk('Databases reporting', ora ? ora.instances > 0 : null, ora ? ora.instances + ' instance(s), ' + ora.stale + ' not reporting' : 'could not be read', 'Easiest: Connections & Setup → Oracle databases → Add (host, service name, a read-only login) - the platform reads it every 4 min, no agent needed. Or save the login in Asset Discovery (credential kind db_login, engine oracle) and run the scope with the db method. Or install the read-only Oracle collector on each database host: agents/oracle (docs/ORACLE.md). Either way one account with SELECT_CATALOG_ROLE'),
    chk('All instances fresh', ora && ora.instances ? ora.stale === 0 : null, ora ? ora.stale + ' stale' : '', 'Check the collector schedule on the hosts whose instance is stale (AI Oracle DBA page lists them)'),
    chk('AI analysis', null, 'rule-based by design: it recommends the DBA step for each problem', ''),
  ].concat(dutyChecks('dba')) });

  // Application Manager
  let av = null; try { if (N && N.availability) { const v = await N.availability.view(); av = { items: v.items.length, groups: v.groups.length, inferred: v.groups.filter((g) => g.inferred).length }; } } catch (e) { av = null; }
  out.push({ id: 'apps', name: 'AI Application Manager', engine: 'siem', checks: [
    chk('Servers monitored', av ? av.items > 0 : null, av ? av.items + ' servers in ' + av.groups + ' services' : 'could not be read', 'Server Availability fills from IT Asset Management (servers with a management IP): run the ITAM sync'),
    chk('Services named', av && av.groups ? av.inferred < av.groups : null, av ? (av.groups - av.inferred) + ' of ' + av.groups + ' services set by an administrator (the rest grouped by server name)' : '', 'Server Availability → set the business service on each server so findings name the right application'),
    chk('AI analysis', null, 'rule-based by design: it recommends the owner\'s next step', ''),
  ].concat(dutyChecks('apps')) });

  // SIEM engineer: log-flow assurance (inventory link, sources, collectors)
  if (deps.collectionAssurance) {
    let m = null; try { m = await deps.collectionAssurance.model(); } catch (e) { m = null; }
    const S2 = m && m.summary;
    out.push({ id: 'siem', name: 'AI SIEM Engineer', engine: 'siem', checks: [
      chk('Log sources registered', m ? m.sources.length > 0 : null, m ? m.sources.length + ' source(s)' : 'could not be read', 'Connect & Onboard → add the first sources, or enable log collection on assets in IT Asset Management'),
      chk('Inventory link', m ? m.inventory.connected : null, m ? (m.inventory.connected ? m.inventory.assets_total + ' assets read from IT Asset Management' : m.inventory.error) : '', 'SIEM config onboard.discovery: base_url of IT Asset Management and secret_file (its proxy secret); without it the engineer sees sources only, not which assets are missing'),
      chk('Collectors receiving', m ? !m.collector.quiet && !!m.collector.last_event : null, m ? (m.collector.last_event ? (m.collector.quiet ? 'no event for 15 min' : m.collector.eps_1h + ' eps') : 'nothing received yet') : '', 'Check the sentra-siem syslog listeners and the host firewall (port 5514)'),
      chk('Required assets logging', S2 && S2.coverage_pct != null ? S2.coverage_pct >= 95 : null, S2 && S2.coverage_pct != null ? S2.coverage_pct + '% of ' + S2.required + ' (' + S2.silent + ' silent, ' + S2.waiting + ' waiting for device config, ' + S2['not-onboarded'] + ' not onboarded)' : 'not measured yet', 'Log Flow Assurance lists each asset with the device configuration to apply'),
    ].concat(dutyChecks('siem')) });
  }

  // Zscaler (ZIA + ZPA)
  { const Z = deps.zscalerInstance; let ov = null; try { ov = Z ? Z.overview() : null; } catch (e) { ov = null; }
    const tenants = ov ? ov.tenants : [];
    const withCreds = tenants.filter((t) => t.credentials && (t.credentials.zia || t.credentials.zpa));
    const answered = tenants.filter((t) => t.last && !(t.last.errors || []).length);
    out.push({ id: 'zscaler', name: 'AI Security Engineer — Zscaler', engine: 'siem', checks: [
      chk('Module', !!Z, Z ? 'installed' : 'not installed', 'Update the SIEM engine (update-platform.ps1)'),
      chk('Tenant onboarded', Z ? tenants.length > 0 : null, tenants.length + ' tenant(s)', 'AI Security Engineer — Zscaler → Add tenant (ZIA cloud + admin login, and/or ZPA client)'),
      chk('Credentials set', tenants.length ? withCreds.length === tenants.length : null, withCreds.length + ' of ' + tenants.length + ' with API credentials', 'Zscaler → tenant → set the read-only ZIA API key + admin login and/or the ZPA client id/secret'),
      chk('API answers', tenants.length ? answered.length > 0 : null, answered.length + ' of ' + tenants.length + ' answered the last read', 'Zscaler → tenant → Test shows the error (credentials, API access enabled, reachability to the Zscaler cloud)'),
      chk('AI analysis', null, 'rule-based by design: it recommends the console change for each problem', ''),
    ].concat(dutyChecks('zscaler')) });
  }
  // Kaspersky Security Center
  { const K = deps.kscInstance; let ov = null; try { ov = K ? K.overview() : null; } catch (e) { ov = null; }
    const servers = ov ? ov.servers : [];
    const withCreds = servers.filter((s) => s.credentials && s.credentials.password);
    const answered = servers.filter((s) => s.last && s.last.summary);
    out.push({ id: 'ksc', name: 'AI Endpoint Protection Engineer (Kaspersky)', engine: 'siem', checks: [
      chk('Module', !!K, K ? 'installed' : 'not installed', 'Update the SIEM engine (update-platform.ps1)'),
      chk('Server onboarded', K ? servers.length > 0 : null, servers.length + ' KSC server(s)', 'AI Endpoint Protection Engineer → Add server (KSC host:13299, read-only account)'),
      chk('Credentials set', servers.length ? withCreds.length === servers.length : null, withCreds.length + ' of ' + servers.length + ' with a password', 'Kaspersky → server → set the read-only KSC account password (and pin the KSC certificate)'),
      chk('OpenAPI answers', servers.length ? answered.length > 0 : null, answered.length + ' of ' + servers.length + ' answered the last read', 'Kaspersky → server → Test shows the error (account rights, OpenAPI enabled on 13299, reachability)'),
      chk('AI analysis', null, 'rule-based by design: it recommends the console action for each problem', ''),
    ].concat(dutyChecks('ksc')) });
  }

  // the organisation's own estate: FortiGate fleet, Network Access Control, NDR, Mimecast (set up and patrolling)
  { const F = deps.fmgApi, fs = F ? F.status() : null, N = deps.nacApi, nv = N ? (() => { try { return N.view(); } catch (e) { return null; } })() : null, nr = deps.state ? deps.state.collection('ndr_run').get('last') : null, mc = deps.mimecastStats ? deps.mimecastStats() : null, mcc = (deps.config && deps.config.mimecast) || {};
    out.push({ id: 'fortigate', name: 'AI Firewall Engineer (FortiGate)', engine: 'siem', checks: [chk('FortiGates connected', fs ? fs.configured : false, fs ? (fs.fortimanager ? 'FortiManager' : 'no FortiManager') + ' · ' + (fs.standalone || 0) + ' standalone' : 'module missing', 'Integration Hub → FortiManager and / or Standalone FortiGates'), chk('Polled', fs ? !!fs.last_poll_at : false, fs && fs.last_poll_at ? fs.devices + ' FortiGate(s), ' + fs.last_poll_at : 'not polled yet', 'FortiGate Fleet → Poll now')].concat(dutyChecks('fortigate')) });
    out.push({ id: 'nac', name: 'AI Network Access Engineer', engine: 'siem', checks: [chk('Endpoints seen', nv ? nv.total > 0 : false, nv ? nv.total + ' endpoint(s) from ' + nv.sources.switches + ' switch(es) and ' + nv.sources.fortigate + ' FortiGate-detected' : 'module missing', 'Switch Port Map: read the switches; FortiGates: switch on Device detection'), chk('Learning done', nv ? !nv.learning : null, nv && nv.learning ? 'learning until ' + nv.learning_until : 'baseline ready', '')].concat(dutyChecks('nac')) });
    out.push({ id: 'ndr', name: 'AI NDR Analyst', engine: 'siem', checks: [chk('Traffic logs analysed', nr ? !(nr.errors || []).length : false, nr ? 'last run ' + nr.at + ((nr.errors || []).length ? ' · ' + nr.errors[0] : '') : 'not run yet', 'The FortiGates send traffic logs to the SIEM (log all sessions on the policies); Network Detection → Run now')].concat(dutyChecks('ndr')) });
    out.push({ id: 'mimecast', name: 'AI Email Security Engineer (Mimecast)', engine: 'siem', checks: [chk('Mimecast connected', !!mcc.enabled, mcc.enabled ? 'collector on' : 'collector off', 'Integration Hub → Mimecast: client ID / secret'), chk('Collecting', mc ? !mc.last_error && !!mc.last_poll_at : false, mc ? (mc.last_error || (mc.last_poll_at ? (mc.records || 0) + ' record(s), last ' + mc.last_poll_at : 'not polled yet')) : '', 'Integration Hub → Mimecast → Test')].concat(dutyChecks('mimecast')) }); }
  for (const e of out) {
    const fails = e.checks.filter((c) => c.ok === false);
    const blocking = fails.filter((c) => /onboarded|reporting|monitored|module|On the duty desk|On duty|sources registered/.test(c.name));
    e.status = blocking.length ? 'blocked' : fails.length ? 'partial' : 'ready';
    e.to_fix = fails.map((c) => ({ name: c.name, fix: c.fix }));
  }
  return { generated: Date.now(), engineers: out, ready: out.filter((e) => e.status === 'ready').length, of: out.length };
}

module.exports = { readiness };
