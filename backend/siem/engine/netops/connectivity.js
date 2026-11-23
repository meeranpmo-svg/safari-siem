// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Connectivity troubleshooter - "Outlook keeps disconnecting", "RDP / SSH sessions time out" for users behind one firewall
 * (FortiGate) reaching servers behind another (Palo Alto in the data centre). Deterministic and read-only:
 *   diagnose(deps, { service:'outlook'|'rdp'|'ssh'|'custom', port?, users?, server?, minutes? })
 *     deps: { inventory, poller, evidence, probe?(ip, port) → bool, factsFor?(dev) → facts (live re-read) }
 *   → { service, ports, scope:{firewalls[]}, checks[], causes[], path[], summary }
 * Evidence, in the order an engineer would look:
 *   1. how the sessions ENDED on each firewall (traffic logs in the SIEM: FortiGate action, PAN-OS session_end_reason,
 *      one-way sessions with no reply, durations) - evidence.sessions / sessionApps
 *   2. the firewalls' own settings (fwfacts.js, kept by the 6-hourly security run): asymmetric routing handling, TCP
 *      non-SYN rejection, session time-outs per port / application, TCP MSS on tunnels, SSL inspection
 *   3. whether the server answers on the port from the data centre (one TCP connect from the SIEM)
 *   4. firewall CPU / memory / HA and link events in the window
 * Every cause carries its evidence and the fix as steps per device - FortiOS / PAN-OS lines with their rollback, or a client /
 * server setting - for a person to run, or to propose as a change plan that a different named engineer approves.
 * Nothing here changes a device.
 */
const SERVICES = {
  outlook: { label: 'Outlook / Exchange', ports: [443, 135, 80], apps: ['ms-exchange', 'mapi-over-http', 'rpc-over-http', 'outlook-web', 'activesync', 'msrpc', 'ssl', 'web-browsing'], idle: false, appRe: /exchange|outlook|mapi|rpc|activesync|ssl|web-browsing|office365|autodiscover/i },
  rdp: { label: 'Remote Desktop (RDP)', ports: [3389], apps: ['ms-rdp'], idle: true, appRe: /rdp/i, paApp: 'ms-rdp' },
  ssh: { label: 'SSH', ports: [22], apps: ['ssh'], idle: true, appRe: /ssh/i, paApp: 'ssh' },
  custom: { label: 'Custom port', ports: [], apps: [], idle: true, appRe: null },
};
const FW = new Set(['fortigate', 'paloalto']);
const DENY = /^(deny|denied|drop|block|blocked|policy-deny|reset-both|reset-client|reset-server)$/;
const NORMAL = /^(close|tcp-fin|accept|start|n\/a)$/;
const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
const minutes = (s) => (s >= 120 ? Math.round(s / 60) + ' min' : Math.round(s) + ' s');

function ttlFor(f, port) {
  // FortiGate: a port override in system session-ttl wins over the default; a policy session-ttl wins over both (listed apart)
  if (!f || !f.session_ttl) return null;
  const o = (f.session_ttl.ports || []).find((p) => (p.protocol === 6 || p.protocol == null) && p.start <= port && (p.end || p.start) >= port);
  return o ? o.timeout : f.session_ttl.default || 3600;
}
function paTimeout(f, app) {
  if (!f || !f.session) return null;
  const o = app && (f.overrides || []).find((x) => x.name === app);
  return (o && (o.tcp_timeout || o.timeout)) || f.session.timeout_tcp || 3600;
}

async function diagnose(deps, input = {}) {
  const { inventory, poller, evidence } = deps;
  const svc = SERVICES[input.service] || SERVICES.custom;
  const ports = input.service === 'custom' || !SERVICES[input.service] ? [Number(input.port)].filter((p) => p > 0 && p < 65536) : svc.ports;
  const users = input.users || '', server = input.server || '', win = Math.max(15, Math.min(1440, Number(input.minutes) || 120));
  const checks = [], causes = [];
  const add = (name, status, detail, ev) => checks.push({ name, status, detail, evidence: (ev || []).filter(Boolean).slice(0, 10) });
  const cause = (c) => causes.push(Object.assign({ evidence: [], steps: [] }, c, { evidence: (c.evidence || []).filter(Boolean).slice(0, 8) }));

  const fws = inventory.list().filter((d) => FW.has(String(d.vendor || '').toLowerCase()));
  const factsOf = {};
  for (const d of fws) {
    let f = null;
    if (input.refresh && deps.factsFor) { try { f = await deps.factsFor(d); } catch (e) { f = null; } }
    if (!f) { const s = poller.snapshot(d.id); f = (s && s.security && s.security.facts) || null; }
    factsOf[d.id] = f;
  }
  const fg = fws.filter((d) => d.vendor === 'fortigate'), pa = fws.filter((d) => d.vendor === 'paloalto');
  const nameOf = (ip) => { const d = fws.find((x) => x.ip === ip); return d ? d.name : ip; };
  const devOf = (ip) => fws.find((x) => x.ip === ip) || null;
  if (!fws.length) add('Firewalls known to the platform', 'fail', 'no FortiGate or Palo Alto in Network Engineer → Devices', []);
  else add('Firewalls known to the platform', 'ok', `${fg.length} FortiGate, ${pa.length} Palo Alto`, fws.map((d) => `${d.name} (${d.vendor}) ${d.ip}${factsOf[d.id] ? '' : ' - settings not read yet (API key with configuration read, then Poll now with security)'}`));

  // 1 - how the sessions ended
  let rows = [], apps = [];
  if (!ports.length) add('Traffic logs', 'skip', 'no port given', []);
  else {
    try { rows = await evidence.sessions({ src: users, dst: server, ports, minutes: win }); } catch (e) { add('Traffic logs (SIEM)', 'skip', 'log search unavailable: ' + e.message, []); rows = null; }
    try { apps = await evidence.sessionApps({ src: users, dst: server, ports, minutes: win }); } catch (e) { apps = []; }
  }
  const by = { fortigate: { total: 0, oneway: 0, reasons: {}, rows: [] }, paloalto: { total: 0, oneway: 0, reasons: {}, rows: [] } };
  for (const r of rows || []) {
    const b = by[r.vendor]; if (!b) continue;
    const n = Number(r.sessions) || 0; b.total += n; b.oneway += Number(r.oneway) || 0; b.reasons[r.reason] = (b.reasons[r.reason] || 0) + n; b.rows.push(r);
  }
  if (rows) {
    for (const v of ['fortigate', 'paloalto']) {
      const b = by[v], label = v === 'fortigate' ? 'FortiGate (users side)' : 'Palo Alto (data centre)';
      if (!(v === 'fortigate' ? fg : pa).length) continue;
      if (!b.total) add(`${label}: sessions to port ${ports.join(', ')}`, 'warn', `no traffic logs in the last ${win} min`, ['either the path does not cross this firewall, or the policy does not log (FortiGate: logtraffic all; PAN-OS: Log at Session End + a log forwarding profile to the SIEM)']);
      else add(`${label}: sessions to port ${ports.join(', ')}`, Object.keys(b.reasons).some((k) => !NORMAL.test(k)) ? 'warn' : 'ok', `${b.total} sessions in ${win} min, ${pct(b.oneway, b.total)} % with no reply`,
        Object.entries(b.reasons).sort((a, c) => c[1] - a[1]).map(([k, n]) => `${k || '(none)'}: ${n} (${pct(n, b.total)} %)`));
    }
    if (fws.length && !by.fortigate.total && !by.paloalto.total) cause({ id: 'no-logs', title: 'The firewalls send no traffic logs for this service to the SIEM', confidence: 'medium', w: 30,
      explanation: 'Without session logs the platform cannot see where the sessions end. Turn on traffic logging for the user → server policies, then run the diagnosis again while a user reproduces the problem.',
      evidence: [`0 sessions logged to port ${ports.join(', ')} in ${win} min`],
      steps: [{ vendor: 'fortigate', title: 'Log all sessions on the user → server policies', commands: ['config firewall policy', '    edit <policy-id>', '        set logtraffic all', '    next', 'end'], rollback: ['config firewall policy', '    edit <policy-id>', '        set logtraffic utm', '    next', 'end'] },
        { vendor: 'paloalto', title: 'Log at session end and forward to the SIEM', commands: ['set rulebase security rules <rule> log-end yes', 'set rulebase security rules <rule> log-setting <syslog-forwarding-profile>', 'commit'], rollback: ['set rulebase security rules <rule> log-end no', 'commit'] }] });
  }

  // 2 - policy denies (a firewall refuses the flow)
  const denyRows = (rows || []).filter((r) => DENY.test(r.reason));
  const paDeny = apps.filter((a) => DENY.test(a.reason || '') || /deny|drop|block|reset/.test(a.action || ''));
  if (denyRows.length || paDeny.length) {
    const fwIp = (denyRows[0] || paDeny[0]).firewall_ip, d = devOf(fwIp), vendor = d ? d.vendor : (denyRows[0] || {}).vendor;
    const appsSeen = [...new Set(paDeny.map((a) => a.app).filter(Boolean))].slice(0, 8);
    const rule = (paDeny.find((a) => a.rule) || {}).rule || '';
    const ruleName = 'SENTRA-' + (input.service || 'svc').toUpperCase() + '-USERS';
    cause({ id: 'policy-deny', title: `${d ? d.name : 'A firewall'} denies ${svc.label} traffic`, confidence: 'high', w: 95, devices: d ? [d.id] : [],
      explanation: `Sessions to port ${ports.join(', ')} are refused by policy${rule ? ' (rule "' + rule + '")' : ''}${appsSeen.length ? '. Applications seen: ' + appsSeen.join(', ') : ''}. On PAN-OS a rule that allows only part of the applications ${svc.label} uses breaks it after the first packets (App-ID identifies the next application and the rule no longer matches).`,
      evidence: denyRows.slice(0, 4).map((r) => `${r.firewall}: ${r.sessions}× ${r.reason} e.g. ${r.sample}`).concat(paDeny.slice(0, 4).map((a) => `${a.firewall}: app ${a.app || '?'} rule ${a.rule || '?'} ${a.action}/${a.reason} ${a.sessions}×`)),
      steps: vendor === 'fortigate' ? [{ vendor: 'fortigate', device: d && d.id, title: `Allow ${svc.label} from the users to the server`, risk: 'medium',
        commands: ['config firewall policy', '    edit 0', `        set name "${ruleName}"`, '        set srcintf "<users-interface>"', '        set dstintf "<dc-interface>"', `        set srcaddr "${users ? 'USERS-' + users.replace(/[./]/g, '-') : '<users-address>'}"`, `        set dstaddr "${server ? 'SRV-' + server.replace(/\./g, '-') : '<server-address>'}"`,
          `        set service ${ports.map((p) => (p === 3389 ? '"RDP"' : p === 22 ? '"SSH"' : p === 443 ? '"HTTPS"' : p === 80 ? '"HTTP"' : '"TCP-' + p + '"')).join(' ')}`, '        set action accept', '        set schedule "always"', '        set logtraffic all', '    next', 'end', '# then move it above the denying policy: config firewall policy / move <new-id> before <deny-id>'],
        rollback: ['config firewall policy', '    delete <new-id>', 'end'] }]
        : [{ vendor: 'paloalto', device: d && d.id, title: `Allow every application ${svc.label} needs from the users to the server`, risk: 'medium',
          commands: [`set rulebase security rules ${ruleName} from <users-zone> to <servers-zone> source ${users || '<users-subnet>'} destination ${server || '<server>'} application [ ${(svc.apps.length ? svc.apps : appsSeen).join(' ') || 'any'} ] service application-default action allow log-end yes`,
            `move rulebase security rules ${ruleName} before ${rule && !/interzone-default|intrazone-default/.test(rule) ? rule : '<deny-rule>'}`, 'commit'],
          rollback: [`delete rulebase security rules ${ruleName}`, 'commit'] }] });
  }

  // 3 - asymmetric routing (each firewall sees one direction only)
  const fgOne = by.fortigate.total ? pct(by.fortigate.oneway, by.fortigate.total) : 0, paOne = by.paloalto.total ? pct(by.paloalto.oneway, by.paloalto.total) : 0;
  const nonSyn = pa.map((d) => ({ d, n: ((factsOf[d.id] || {}).counters || {}).flow_tcp_non_syn_drop || ((factsOf[d.id] || {}).counters || {}).flow_tcp_non_syn || 0 })).filter((x) => x.n > 0);
  const asym = (by.fortigate.total >= 10 && fgOne >= 15) || (by.paloalto.total >= 10 && paOne >= 15) || nonSyn.length;
  const fgFacts = fg.map((d) => [d, factsOf[d.id]]).filter((x) => x[1]), paFacts = pa.map((d) => [d, factsOf[d.id]]).filter((x) => x[1]);
  const factLines = fgFacts.map(([d, f]) => `${d.name}: asymroute ${f.settings ? f.settings.asymroute : 'not read'}`).concat(paFacts.map(([d, f]) => `${d.name}: TCP reject non-SYN ${f.session ? f.session.reject_non_syn : 'not read'}, asymmetric path ${f.session ? f.session.asymmetric_path : 'not read'}`));
  add('Return path (asymmetric routing)', asym ? 'fail' : (by.fortigate.total || by.paloalto.total) ? 'ok' : 'skip', asym ? 'sessions without replies / non-SYN drops: the reply takes another path' : 'replies come back through the same firewall', [`FortiGate: ${fgOne} % of sessions with no reply`, `Palo Alto: ${paOne} % of sessions with no reply`].concat(nonSyn.map((x) => `${x.d.name}: ${x.n} TCP packets dropped as non-SYN (flow_tcp_non_syn_drop)`), factLines));
  if (asym) {
    const paD = pa[0], fgD = fg[0];
    cause({ id: 'asymmetric', title: 'Asymmetric routing between the FortiGate and the Palo Alto', confidence: (fgOne >= 30 || paOne >= 30 || nonSyn.length) ? 'high' : 'medium', w: 90, devices: fws.map((d) => d.id),
      explanation: 'The request goes through one firewall and the reply comes back another way (typically: users reach the servers through the FortiGate and the core switch, but the servers\' default gateway is the Palo Alto). A stateful firewall that sees only half of a TCP conversation drops the rest ("non-SYN TCP") or lets the session expire - users see Outlook disconnecting and RDP / SSH freezing. The fix is routing: the reply must return through the firewall that saw the request.',
      evidence: [`FortiGate: ${by.fortigate.oneway} of ${by.fortigate.total} sessions got no reply (${fgOne} %)`, `Palo Alto: ${by.paloalto.oneway} of ${by.paloalto.total} sessions got no reply (${paOne} %)`].concat(nonSyn.map((x) => `${x.d.name}: ${x.n} non-SYN TCP drops`), factLines),
      steps: [
        { vendor: 'routing', title: 'Make the reply return through the same firewall (the real fix)', risk: 'medium', device: paD && paD.id,
          commands: [`# On the Palo Alto (the servers' gateway): route the user subnet back to the FortiGate's inside interface`, `set network virtual-router default routing-table ip static-route SENTRA-USERS-RETURN destination ${users && users.includes('/') ? users : '<users-subnet>'} nexthop ip-address <fortigate-inside-ip> interface <ethernet-to-fortigate>`, 'commit',
            '# or, if users must go through both firewalls: point the core switch route for the server subnet at the FortiGate, and the FortiGate route at the Palo Alto, so both directions follow FortiGate ↔ Palo Alto'],
          rollback: ['delete network virtual-router default routing-table ip static-route SENTRA-USERS-RETURN', 'commit'] },
        { vendor: 'fortigate', device: fgD && fgD.id, title: 'Interim only (weakens inspection): let the FortiGate pass replies it did not see', risk: 'high',
          commands: ['config system settings', '    set asymroute enable', 'end', '# asymroute turns off stateful checking for those flows - keep it only until the routing is corrected'], rollback: ['config system settings', '    set asymroute disable', 'end'] },
        { vendor: 'paloalto', device: paD && paD.id, title: 'Interim only (weakens inspection): stop the Palo Alto dropping half-seen TCP sessions on the users zone', risk: 'high',
          commands: ['set network profiles zone-protection-profile <users-zone-profile> asymmetric-path bypass', 'set network profiles zone-protection-profile <users-zone-profile> tcp-reject-non-syn no', 'commit'],
          rollback: ['set network profiles zone-protection-profile <users-zone-profile> asymmetric-path global', 'set network profiles zone-protection-profile <users-zone-profile> tcp-reject-non-syn global', 'commit'] }] });
  }

  // 4 - idle time-outs (RDP / SSH left idle are cut by the firewall)
  if (ports.length) {
    const port = ports[0], fgT = fgFacts.map(([d, f]) => ({ d, t: ttlFor(f, port), pol: (f.policies || []).filter((p) => p.status !== 'disable' && p.action === 'accept' && p.session_ttl && p.session_ttl !== 'never' && p.session_ttl < 3600) }));
    const paT = paFacts.map(([d, f]) => ({ d, t: paTimeout(f, svc.paApp) }));
    const tmo = (rows || []).filter((r) => (r.vendor === 'fortigate' && r.reason === 'timeout') || (r.vendor === 'paloalto' && r.reason === 'aged-out'));
    const tmoN = tmo.reduce((a, r) => a + Number(r.sessions), 0), allN = by.fortigate.total + by.paloalto.total - denyRows.reduce((a, r) => a + Number(r.sessions), 0);
    const settings = fgT.map((x) => `${x.d.name}: TCP ${port} idle time-out ${x.t === 'never' ? 'never' : minutes(x.t)}${x.pol.length ? `; ${x.pol.length} policy(ies) with a shorter session-ttl: ${x.pol.slice(0, 3).map((p) => p.id + ' (' + minutes(p.session_ttl) + ')').join(', ')}` : ''}`)
      .concat(paT.map((x) => `${x.d.name}: ${svc.paApp || 'TCP'} time-out ${minutes(x.t)}`));
    add('Idle session time-outs', tmoN >= 5 && pct(tmoN, allN) >= 20 ? 'fail' : tmoN ? 'warn' : 'ok', tmoN ? `${tmoN} sessions ended by the firewall's idle timer` : 'no session ended by an idle timer', tmo.slice(0, 4).map((r) => `${r.firewall}: ${r.sessions}× ${r.reason}, typical length ${minutes(Number(r.p50_s))}`).concat(settings));
    const shortPolicy = fgT.some((x) => x.pol.length) || fgT.some((x) => x.t !== 'never' && x.t < 3600);
    if ((svc.idle && tmoN >= 5 && pct(tmoN, allN) >= 20) || (svc.idle && shortPolicy)) {
      const minT = Math.min(...fgT.map((x) => (x.t === 'never' ? 1e9 : x.t)).concat(paT.map((x) => x.t)).concat(fgT.flatMap((x) => x.pol.map((p) => p.session_ttl))).filter(Number.isFinite));
      const fgD = fg[0], paD = pa[0], app = svc.paApp || 'ms-rdp';
      cause({ id: 'idle-timeout', title: `Idle ${svc.label} sessions are cut by the firewall${Number.isFinite(minT) && minT < 1e9 ? ' after about ' + minutes(minT) : ''}`, confidence: tmoN >= 5 ? 'high' : 'medium', w: tmoN >= 5 ? 85 : 45, devices: fws.map((d) => d.id),
        explanation: `A session with no traffic for longer than the firewall's idle time-out is removed from its table; the next keystroke is dropped and the client shows a time-out. Administrators leave RDP / SSH windows idle for long periods, so these are the sessions that break. Keep-alives on the client / server are the reliable fix; a longer time-out for these ports only is the firewall-side fix.${shortPolicy ? ' A FortiGate policy or port override sets a shorter time-out than the default.' : ''}`,
        evidence: tmo.slice(0, 4).map((r) => `${r.firewall}: ${r.sessions} sessions ended by ${r.reason} after ~${minutes(Number(r.p50_s))}`).concat(settings),
        steps: [
          { vendor: 'client', title: input.service === 'ssh' ? 'SSH keep-alives (servers and admin PCs)' : 'RDP keep-alives (Group Policy on the servers)', risk: 'low',
            commands: input.service === 'ssh' ? ['# /etc/ssh/sshd_config on the servers (then: systemctl reload sshd)', 'ClientAliveInterval 60', 'ClientAliveCountMax 3', '# ~/.ssh/config or PuTTY on the admin PCs: ServerAliveInterval 60 / PuTTY Connection → Seconds between keepalives = 60']
              : ['# GPO: Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Connections', '#   "Configure keep-alive connection interval" = Enabled, 1 minute', '# the same as a registry value on one server:', 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v KeepAliveEnable /t REG_DWORD /d 1 /f', 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v KeepAliveInterval /t REG_DWORD /d 1 /f'],
            rollback: input.service === 'ssh' ? ['# remove the ClientAliveInterval / ClientAliveCountMax lines and reload sshd'] : ['reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v KeepAliveEnable /f', 'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v KeepAliveInterval /f'] },
          { vendor: 'fortigate', device: fgD && fgD.id, title: `8-hour idle time-out for TCP ${port} only`, risk: 'low',
            commands: ['config system session-ttl', '    config port', '        edit 0', '            set protocol 6', `            set start-port ${port}`, `            set end-port ${port}`, '            set timeout 28800', '        next', '    end', 'end'].concat(fgT.some((x) => x.pol.length) ? ['# and remove the short session-ttl from policy ' + fgT.flatMap((x) => x.pol.map((p) => p.id)).slice(0, 3).join(', ') + ': config firewall policy / edit <id> / unset session-ttl / next / end'] : []),
            rollback: ['config system session-ttl', '    config port', '        delete <entry-id created above>', '    end', 'end'] },
          { vendor: 'paloalto', device: paD && paD.id, title: `8-hour time-out for the ${app} application`, risk: 'low',
            commands: [`set shared override application ${app} tcp-timeout 28800`, 'commit'], rollback: [`delete shared override application ${app}`, 'commit'] }] });
    }
  }

  // 5 - resets from the server side (not the network)
  const rst = (rows || []).filter((r) => r.reason === 'server-rst' || r.reason === 'tcp-rst-from-server'), rstN = rst.reduce((a, r) => a + Number(r.sessions), 0);
  if (rstN >= 5 && pct(rstN, by.fortigate.total + by.paloalto.total) >= 30) cause({ id: 'server-reset', title: 'The server closes the sessions (TCP reset from the server)', confidence: 'medium', w: 50,
    explanation: 'The firewalls pass the traffic, and the server ends the session with a reset. Look at the server: RDP session limits and idle / disconnected-session time limits (GPO), Remote Desktop licensing, sshd MaxStartups / MaxSessions, or the host firewall / antivirus.',
    evidence: rst.slice(0, 4).map((r) => `${r.firewall}: ${r.sessions}× ${r.reason} e.g. ${r.sample}`),
    steps: [{ vendor: 'server', title: 'Check the server side', commands: ['# RDP: gpresult /h rsop.html → Remote Desktop Session Host → Session Time Limits; Event Viewer → TerminalServices-LocalSessionManager', '# SSH: journalctl -u sshd --since "-2h"; grep -E "MaxStartups|MaxSessions|ClientAlive" /etc/ssh/sshd_config'], rollback: [] }] });

  // 6 - SSL / TLS inspection breaking Outlook (or a second decryption on the other firewall)
  const dec = (rows || []).filter((r) => /^decrypt|threat/.test(r.reason || ''));
  const deep = fgFacts.flatMap(([d, f]) => {
    const prof = new Set((f.ssl_profiles || []).filter((p) => p.https === 'deep-inspection' || p.ssl === 'deep-inspection').map((p) => p.name));
    return (f.policies || []).filter((p) => p.status !== 'disable' && p.action === 'accept' && prof.has(p.ssl_ssh_profile) && (p.service.includes('ALL') || p.service.some((s) => /HTTPS|443|WEB/i.test(s)))).map((p) => ({ d, p }));
  });
  const paDec = paFacts.filter(([, f]) => f.decryption && (f.decryption.decrypting || []).length);
  if (input.service === 'outlook' || dec.length) {
    add('SSL / TLS inspection', dec.length ? 'fail' : deep.length || paDec.length ? 'warn' : 'ok', dec.length ? 'sessions ended by decryption errors' : deep.length || paDec.length ? 'deep inspection is on for user web traffic' : 'no deep inspection found on the path',
      dec.slice(0, 3).map((r) => `${r.firewall}: ${r.sessions}× ${r.reason}`).concat(deep.slice(0, 4).map((x) => `${x.d.name}: policy ${x.p.id}${x.p.name ? ' (' + x.p.name + ')' : ''} deep-inspects with "${x.p.ssl_ssh_profile}"`), paDec.map(([d, f]) => `${d.name}: ${f.decryption.decrypting.length} decryption rule(s) decrypt`)));
    if (dec.length || (input.service === 'outlook' && (deep.length || paDec.length))) {
      const step = [];
      if (deep.length) step.push({ vendor: 'fortigate', device: deep[0].d.id, title: 'Do not deep-inspect the Exchange server', risk: 'low',
        commands: ['config firewall address', `    edit "SRV-EXCHANGE"`, `        set subnet ${server || '<exchange-ip>'} 255.255.255.255`, '    next', 'end', 'config firewall ssl-ssh-profile', `    edit "${deep[0].p.ssl_ssh_profile}"`, '        config ssl-exempt', '            edit 0', '                set type address', '                set address "SRV-EXCHANGE"', '            next', '        end', '    next', 'end'],
        rollback: ['config firewall ssl-ssh-profile', `    edit "${deep[0].p.ssl_ssh_profile}"`, '        config ssl-exempt', '            delete <entry-id created above>', '        end', '    next', 'end'] });
      if (paDec.length) step.push({ vendor: 'paloalto', device: paDec[0][0].id, title: 'No decryption for traffic to the Exchange server', risk: 'low',
        commands: [`set rulebase decryption rules SENTRA-NO-DECRYPT-EXCHANGE from any to any source any destination ${server || '<exchange-ip>'} service any category any action no-decrypt`, `move rulebase decryption rules SENTRA-NO-DECRYPT-EXCHANGE top`, 'commit'],
        rollback: ['delete rulebase decryption rules SENTRA-NO-DECRYPT-EXCHANGE', 'commit'] });
      cause({ id: 'ssl-inspection', title: deep.length && paDec.length ? 'Outlook traffic is decrypted twice (FortiGate and Palo Alto)' : 'SSL / TLS inspection interferes with Outlook', confidence: dec.length ? 'high' : 'medium', w: dec.length ? 80 : 40, devices: deep.map((x) => x.d.id).concat(paDec.map(([d]) => d.id)),
        explanation: 'Outlook (MAPI over HTTP, EWS, Autodiscover) keeps long-lived TLS connections and checks the certificate chain. Deep inspection re-signs the certificate and buffers the stream, which shows as repeated "Disconnected / Trying to connect" and password prompts. Exempt the Exchange server (and Microsoft 365 if used) from inspection on both firewalls.',
        evidence: dec.slice(0, 3).map((r) => `${r.firewall}: ${r.sessions}× ${r.reason}`).concat(deep.slice(0, 3).map((x) => `${x.d.name}: policy ${x.p.id} uses deep inspection profile "${x.p.ssl_ssh_profile}"`), paDec.map(([d, f]) => `${d.name}: decrypting rules ${f.decryption.decrypting.slice(0, 3).map((r) => r.name).join(', ')}`)),
        steps: step.length ? step : [{ vendor: 'paloalto', title: 'Find the decryption rule that matches the Exchange traffic', commands: ['show running decryption-policy', `test decryption-policy-match from <users-zone> to <servers-zone> source <user-ip> destination ${server || '<exchange-ip>'} category any`], rollback: [] }] });
    }
  }

  // 7 - MTU / MSS (large packets lost over tunnels: Outlook hangs on attachments, RDP freezes on screen updates)
  const mtuDrops = paFacts.map(([d, f]) => ({ d, n: (f.counters || {}).flow_fwd_mtu_exceeded || 0 })).filter((x) => x.n > 0);
  const tunNoMss = fgFacts.flatMap(([d, f]) => (f.interfaces || []).filter((i) => i.type === 'tunnel' && !i.tcp_mss).map((i) => ({ d, i: i.name }))).concat(paFacts.flatMap(([d, f]) => (f.interfaces || []).filter((i) => i.type === 'tunnel' && !i.mss).map((i) => ({ d, i: i.name }))));
  add('MTU / TCP MSS', mtuDrops.length ? 'fail' : tunNoMss.length ? 'warn' : 'ok', mtuDrops.length ? 'packets dropped for exceeding the MTU' : tunNoMss.length ? `${tunNoMss.length} tunnel interface(s) without TCP MSS adjustment` : 'no MTU drops, tunnels adjust MSS',
    mtuDrops.map((x) => `${x.d.name}: ${x.n} packets over the MTU (flow_fwd_mtu_exceeded)`).concat(tunNoMss.slice(0, 6).map((x) => `${x.d.name}: ${x.i} has no TCP MSS`)));
  if (mtuDrops.length || (tunNoMss.length && (by.fortigate.total || by.paloalto.total) && input.service !== 'ssh')) {
    const fgT = tunNoMss.find((x) => x.d.vendor === 'fortigate'), paT = tunNoMss.find((x) => x.d.vendor === 'paloalto');
    cause({ id: 'mss', title: 'Large packets are lost on a tunnel (MTU / TCP MSS)', confidence: mtuDrops.length ? 'high' : 'low', w: mtuDrops.length ? 70 : 20, devices: mtuDrops.map((x) => x.d.id).concat(tunNoMss.map((x) => x.d.id)),
      explanation: 'IPsec / GRE adds headers, so full-size packets no longer fit. Small packets (log-in, keystrokes) pass, large ones (Outlook attachments and folder sync, RDP screen updates) are dropped - the application hangs and then times out. Clamping the TCP MSS on the tunnel avoids it.',
      evidence: mtuDrops.map((x) => `${x.d.name}: ${x.n} MTU drops`).concat(tunNoMss.slice(0, 4).map((x) => `${x.d.name}: ${x.i} without TCP MSS`)),
      steps: [fgT && { vendor: 'fortigate', device: fgT.d.id, title: `Clamp TCP MSS on ${fgT.i}`, risk: 'low', commands: ['config system interface', `    edit "${fgT.i}"`, '        set tcp-mss 1350', '    next', 'end'], rollback: ['config system interface', `    edit "${fgT.i}"`, '        unset tcp-mss', '    next', 'end'] },
        paT && { vendor: 'paloalto', device: paT.d.id, title: `Adjust TCP MSS on ${paT.i}`, risk: 'low', commands: [`set network interface tunnel units ${paT.i} adjust-tcp-mss enable yes ipv4-mss-adjustment 100`, 'commit'], rollback: [`set network interface tunnel units ${paT.i} adjust-tcp-mss enable no`, 'commit'] }].filter(Boolean) });
  }

  // 8 - firewall health, HA and link events
  const hot = fws.map((d) => ({ d, s: (poller.snapshot(d.id) || {}).system || {} })).filter((x) => (x.s.mem_pct >= 88) || (x.s.cpu_pct >= 90));
  add('Firewall CPU / memory', hot.length ? 'fail' : 'ok', hot.length ? `${hot.length} firewall(s) under pressure` : 'within limits', fws.map((d) => { const s = (poller.snapshot(d.id) || {}).system || {}; return `${d.name}: CPU ${s.cpu_pct == null ? '?' : s.cpu_pct + ' %'}, memory ${s.mem_pct == null ? '?' : s.mem_pct + ' %'}, sessions ${s.sessions == null ? '?' : s.sessions}`; }));
  for (const x of hot) cause({ id: 'resources', title: `${x.d.name} is under resource pressure`, confidence: 'high', w: 75, devices: [x.d.id],
    explanation: x.d.vendor === 'fortigate' && x.s.mem_pct >= 88 ? 'At about 88 % memory a FortiGate enters conserve mode and stops accepting new sessions or bypasses inspection - users see random time-outs.' : 'A firewall near its CPU / memory limit drops or delays packets for every application.',
    evidence: [`CPU ${x.s.cpu_pct} %, memory ${x.s.mem_pct} %, sessions ${x.s.sessions}`],
    steps: [{ vendor: x.d.vendor, device: x.d.id, title: 'Find what uses the resources', commands: x.d.vendor === 'fortigate' ? ['diagnose sys top 2 20', 'get system performance status', 'diagnose sys session full-stat'] : ['show system resources', 'show session info', 'show running resource-monitor minute last 5'], rollback: [] }] });
  if (evidence && fws.length) {
    try {
      const ev = []; for (const d of fws.slice(0, 6)) for (const r of await evidence.deviceEvents({ ip: d.ip, host: d.name, minutes: win, limit: 10, kind: 'link' })) ev.push(`${r.ts} ${d.name}: ${r.message}`);
      add('HA / link / tunnel events', ev.length ? 'warn' : 'ok', ev.length ? `${ev.length} event(s) in ${win} min` : `none in ${win} min`, ev.slice(0, 8));
      if (ev.some((e) => /failover|HA/i.test(e))) cause({ id: 'ha-failover', title: 'A firewall HA failover happened in the window', confidence: 'medium', w: 55, devices: fws.map((d) => d.id),
        explanation: 'Without session synchronisation, every open session (RDP, SSH, Outlook) is dropped when the cluster fails over.', evidence: ev.filter((e) => /failover|HA/i.test(e)).slice(0, 4),
        steps: [{ vendor: 'fortigate', title: 'Synchronise sessions in the FortiGate cluster', commands: ['config system ha', '    set session-pickup enable', '    set session-pickup-connectionless enable', 'end'], rollback: ['config system ha', '    set session-pickup disable', 'end'] }] });
    } catch (e) { add('HA / link / tunnel events', 'skip', 'log search unavailable: ' + e.message, []); }
  }

  // 9 - the server itself, from the data centre
  if (server && deps.probe && ports.length) {
    const res = []; for (const p of ports.slice(0, 3)) res.push([p, await deps.probe(server, p)]);
    const closed = res.filter((r) => !r[1]);
    add(`Server ${server} from the data centre`, closed.length === res.length ? 'fail' : 'ok', closed.length === res.length ? 'does not answer from the SIEM either' : 'answers - the problem is on the users\' path', res.map(([p, ok]) => `TCP ${p}: ${ok ? 'open' : 'no answer'}`));
    if (closed.length === res.length) cause({ id: 'server-down', title: `The server ${server} does not answer on ${ports.join(', ')}`, confidence: 'medium', w: 60,
      explanation: 'The SIEM in the data centre cannot open the port either: the service is stopped, the host firewall blocks it, or the SIEM is not allowed to that segment (check that first).', evidence: res.map(([p]) => `TCP ${p}: no answer from the SIEM`),
      steps: [{ vendor: 'server', title: 'Check the service on the server', commands: input.service === 'ssh' ? ['systemctl status sshd', 'ss -ltnp | grep :22', 'firewall-cmd --list-all'] : ['Get-Service TermService, UmRdpService', 'Test-NetConnection localhost -Port 3389', 'Get-NetFirewallRule -DisplayGroup "Remote Desktop" | ft DisplayName, Enabled'], rollback: [] }] });
  }

  causes.sort((a, b) => b.w - a.w);
  const ranked = causes.map((c, i) => ({ rank: i + 1, id: c.id, title: c.title, confidence: c.confidence, explanation: c.explanation, evidence: c.evidence, devices: c.devices || [], steps: c.steps.map((s) => ({ vendor: s.vendor, device: s.device || null, title: s.title, risk: s.risk || 'low', commands: s.commands || [], rollback: s.rollback || [] })) }));
  const path = [{ hop: 'Users', detail: users || 'all users' }].concat(fg.map((d) => ({ hop: d.name, vendor: 'fortigate', detail: by.fortigate.total ? `${by.fortigate.total} sessions logged` : 'no sessions logged' })),
    pa.map((d) => ({ hop: d.name, vendor: 'paloalto', detail: by.paloalto.total ? `${by.paloalto.total} sessions logged` : 'no sessions logged' })), [{ hop: 'Server', detail: server || 'all servers' }]);
  const summary = !fws.length ? 'Add the FortiGate and the Palo Alto in Network Engineer → Devices (read-only API keys) so their logs and settings can be used.'
    : ranked.length ? `Most likely: ${ranked[0].title}.` : rows && !(by.fortigate.total + by.paloalto.total) ? 'No traffic logs for this service in the window - reproduce the problem and run the diagnosis again.' : 'No firewall-side cause found in the logs and settings; check the client, DNS and the server.';
  return { service: input.service || 'custom', label: svc.label, ports, users, server, minutes: win, scope: { firewalls: fws.map((d) => ({ id: d.id, name: d.name, vendor: d.vendor, ip: d.ip, facts_at: factsOf[d.id] ? factsOf[d.id].at : null })) }, path, checks, causes: ranked, summary };
}

module.exports = { diagnose, SERVICES, ttlFor, paTimeout };
