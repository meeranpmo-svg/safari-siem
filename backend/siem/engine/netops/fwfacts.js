// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Firewall configuration FACTS (read-only), for the Palo Alto baseline hardening (IT Asset Management, CIS PAN-OS) and the
 * connectivity troubleshooter (connectivity.js: users behind the FortiGate, servers behind the Palo Alto).
 *   paloalto(dev, cred, o)  PAN-OS XML API: type=config&action=show (running configuration) on a FIXED list of xpaths, and
 *                           two "show" operational commands (system info, global drop counters). Needs an admin role with
 *                           Configuration read (XML API → Configuration, Operational Requests) - nothing else.
 *   fortigate(dev, cred, o) FortiOS REST: GET /api/v2/cmdb/... on a FIXED list of paths.
 * Each section is read on its own; one the key may not read is null and named in `unread` ("not checked", never a pass).
 * Nothing secret is kept: no SNMP community, no admin password hash, no pre-shared key - only the settings the checks need.
 * o.get(url, opts) replaces the HTTP client in tests.
 */
const { getRaw } = require('./http');
const X = require('./xml');

const PA_XPATH = {
  system: '/config/devices/entry/deviceconfig/system',
  management: '/config/devices/entry/deviceconfig/setting/management',
  session: '/config/devices/entry/deviceconfig/setting/session',
  tcp: '/config/devices/entry/deviceconfig/setting/tcp',
  password: '/config/mgt-config/password-complexity',
  users: '/config/mgt-config/users',
  syslog: '/config/shared/log-settings/syslog',
  zones: '/config/devices/entry/vsys/entry/zone',
  zpp: '/config/devices/entry/network/profiles/zone-protection-profile',
  ethernet: '/config/devices/entry/network/interface/ethernet',
  tunnel: '/config/devices/entry/network/interface/tunnel',
  rules: '/config/devices/entry/vsys/entry/rulebase/security/rules',
  decryption: '/config/devices/entry/vsys/entry/rulebase/decryption/rules',
  overrides: '/config/shared/override/application',
  alg: '/config/shared/alg-override/application',
};
const PA_OPS = { info: '<show><system><info></info></system></show>', counters: '<show><counter><global><filter><severity>drop</severity></filter></global></counter></show>' };
const PA_COUNTERS = /^(flow_tcp_non_syn|flow_policy_deny|tcp_drop|tcp_out_of_sync|flow_fwd_mtu|flow_dos|flow_rcv_dot1q|session_|flow_host|flow_tcp_|tcp_|flow_fwd_l3_noarp|flow_ipfrag|flow_predict|ctd_)/;
const MAX_RULES = 400;

const FG_PATHS = {
  settings: '/api/v2/cmdb/system/settings',
  global: '/api/v2/cmdb/system/global',
  session_ttl: '/api/v2/cmdb/system/session-ttl',
  policies: '/api/v2/cmdb/firewall/policy',
  interfaces: '/api/v2/cmdb/system/interface',
  ssl_profiles: '/api/v2/cmdb/firewall/ssl-ssh-profile',
  services: '/api/v2/cmdb/firewall.service/custom',
  session_helper: '/api/v2/cmdb/system/session-helper',
};

const yes = (v) => (v === '' ? null : v === 'yes');
const num = (v) => (v === '' || v == null || !Number.isFinite(Number(v)) ? null : Number(v));
const mem = (n, p) => (n ? X.all(n, p + '/member').map((m) => m.text.trim()) : []);

async function paloalto(dev, cred = {}, o = {}) {
  const get = o.get || getRaw;
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}/api/`, ho = { headers: { 'X-PAN-KEY': cred.token }, tls: cred.tls, timeoutMs: 15000 };
  const out = { vendor: 'paloalto', at: (o.now || Date.now)(), unread: [] };
  async function call(qs) {
    const r = await get(base + '?' + qs, ho);
    if (r.status === 401 || r.status === 403) throw Object.assign(new Error('not allowed for this API key'), { denied: true });
    if (r.status !== 200) throw new Error('HTTP ' + r.status);
    const d = X.parse(r.text);
    if (d.attrs.status !== 'success') throw Object.assign(new Error(X.txt(d, 'msg/line') || X.txt(d, 'msg') || 'API error'), { denied: /not authorized|access denied|unauthori/i.test(r.text) });
    return d;
  }
  const show = (xpath) => call('type=config&action=show&xpath=' + encodeURIComponent(xpath));
  const op = (cmd) => { if (!/^<show>/.test(cmd)) throw new Error('only show commands are allowed'); return call('type=op&cmd=' + encodeURIComponent(cmd)); };
  async function section(name, fn) {
    try { out[name] = await fn(); } catch (e) { out[name] = null; out.unread.push({ section: name, reason: e.denied ? 'not allowed for this API key (add Configuration read to its admin role)' : String(e.message).slice(0, 160) }); }
  }
  // a show of an xpath that is not configured answers success with an empty result: that is "default", not unread
  const leaf = (d, name) => X.find(d, 'result/' + name);

  await section('info', async () => { const s = X.find(await op(PA_OPS.info), 'result/system'); return { version: X.txt(s, 'sw-version'), model: X.txt(s, 'model'), hostname: X.txt(s, 'hostname'), threat_version: X.txt(s, 'threat-version'), av_version: X.txt(s, 'av-version') }; });
  await section('system', async () => {
    const s = leaf(await show(PA_XPATH.system), 'system');
    const svc = s && X.find(s, 'service'), snmp = s && X.find(s, 'snmp-setting/access-setting/version');
    const upd = {};
    for (const k of ['threats', 'anti-virus', 'wildfire', 'app-profile']) {
      const n = s && X.find(s, 'update-schedule/' + k + '/recurring');
      if (!n) { upd[k] = null; continue; }
      const kind = (n.children.find((c) => c.name !== 'sync-to-peer' && c.name !== 'threshold') || {}).name || '';
      upd[k] = { every: kind, action: X.txt(n, kind + '/action') };
    }
    return { banner: !!(s && X.txt(s, 'login-banner')), ntp: [X.txt(s, 'ntp-servers/primary-ntp-server/ntp-server-address'), X.txt(s, 'ntp-servers/secondary-ntp-server/ntp-server-address')].filter(Boolean),
      permitted_ip: s ? X.all(s, 'permitted-ip/entry').length : 0, telnet_off: svc ? yes(X.txt(svc, 'disable-telnet')) : null, http_off: svc ? yes(X.txt(svc, 'disable-http')) : null,
      snmp: snmp ? (X.find(snmp, 'v3') ? 'v3' : X.find(snmp, 'v2c') ? 'v2c' : '') : '', dns: s ? [X.txt(s, 'dns-setting/servers/primary'), X.txt(s, 'dns-setting/servers/secondary')].filter(Boolean).length : 0,
      panorama: !!(s && X.txt(s, 'panorama/local-panorama/panorama-server')), timezone: s ? X.txt(s, 'timezone') : '', updates: upd };
  });
  await section('management', async () => {
    const m = leaf(await show(PA_XPATH.management), 'management');
    return { idle_timeout: num(m && X.txt(m, 'idle-timeout')), lockout_attempts: num(m && X.txt(m, 'admin-lockout/failed-attempts')), lockout_time: num(m && X.txt(m, 'admin-lockout/lockout-time')) };
  });
  await section('session', async () => {
    const s = leaf(await show(PA_XPATH.session), 'session'), t = leaf(await show(PA_XPATH.tcp), 'tcp');
    return { reject_non_syn: s && X.txt(s, 'tcp-reject-non-syn') ? X.txt(s, 'tcp-reject-non-syn') : 'yes', timeout_tcp: num(s && X.txt(s, 'timeout-tcp')) || 3600, timeout_default: num(s && X.txt(s, 'timeout-default')) || 30,
      timeout_tcp_half_closed: num(s && X.txt(s, 'timeout-tcp-half-closed')) || 120, asymmetric_path: t && X.txt(t, 'asymmetric-path') ? X.txt(t, 'asymmetric-path') : 'drop' };
  });
  await section('password', async () => {
    const p = leaf(await show(PA_XPATH.password), 'password-complexity');
    return { enabled: p ? X.txt(p, 'enabled') === 'yes' : false, min_length: num(p && X.txt(p, 'minimum-length')), change_period_days: num(p && X.txt(p, 'password-change/expiration-period')), history: num(p && X.txt(p, 'password-history-count')) };
  });
  await section('admins', async () => {
    const u = X.all(await show(PA_XPATH.users), 'result/users/entry').map((e) => e.attrs.name);
    return { count: u.length, default_admin: u.includes('admin') };
  });
  await section('syslog', async () => ({ profiles: X.all(await show(PA_XPATH.syslog), 'result/syslog/entry').length }));
  await section('zpp', async () => X.all(await show(PA_XPATH.zpp), 'result/zone-protection-profile/entry').map((e) => ({ name: e.attrs.name,
    reject_non_syn: X.txt(e, 'tcp-reject-non-syn') || 'global', asymmetric_path: X.txt(e, 'asymmetric-path') || 'global', flood: !!X.find(e, 'flood') })));
  await section('zones', async () => X.all(await show(PA_XPATH.zones), 'result/zone/entry').map((e) => ({ name: e.attrs.name, zpp: X.txt(e, 'network/zone-protection-profile'),
    interfaces: X.all(e, 'network/layer3/member').map((m) => m.text.trim()).filter(Boolean), log_setting: X.txt(e, 'network/log-setting') })));
  await section('interfaces', async () => {
    const eth = X.all(await show(PA_XPATH.ethernet), 'result/ethernet/entry'), out2 = [];
    for (const e of eth) {
      const l3 = X.find(e, 'layer3'); if (!l3) continue;
      out2.push({ name: e.attrs.name, type: 'ethernet', mss: X.txt(l3, 'adjust-tcp-mss/enable') === 'yes', mtu: num(X.txt(l3, 'mtu')) });
      for (const u of X.all(l3, 'units/entry')) out2.push({ name: u.attrs.name, type: 'subinterface', mss: X.txt(u, 'adjust-tcp-mss/enable') === 'yes', mtu: num(X.txt(u, 'mtu')) });
    }
    try { for (const u of X.all(await show(PA_XPATH.tunnel), 'result/tunnel/units/entry')) out2.push({ name: u.attrs.name, type: 'tunnel', mss: X.txt(u, 'adjust-tcp-mss/enable') === 'yes', mtu: num(X.txt(u, 'mtu')) }); } catch (e) { /* no tunnel interfaces configured: the ethernet list stands */ }
    return out2.slice(0, 300);
  });
  await section('rules', async () => {
    const items = X.all(await show(PA_XPATH.rules), 'result/rules/entry').slice(0, MAX_RULES).map((e) => ({
      name: e.attrs.name, disabled: X.txt(e, 'disabled') === 'yes', action: X.txt(e, 'action'), from: mem(e, 'from'), to: mem(e, 'to'), source: mem(e, 'source'), destination: mem(e, 'destination'),
      application: mem(e, 'application'), service: mem(e, 'service'), profile: !!(X.find(e, 'profile-setting/group/member') || X.find(e, 'profile-setting/profiles')),
      log_end: X.txt(e, 'log-end') !== 'no', log_setting: !!X.txt(e, 'log-setting') }));
    return { count: items.length, items };
  });
  await section('decryption', async () => { const r = X.all(await show(PA_XPATH.decryption), 'result/rules/entry'); return { count: r.length, names: r.slice(0, 20).map((e) => e.attrs.name), decrypting: r.filter((e) => X.txt(e, 'action') === 'decrypt' && X.txt(e, 'disabled') !== 'yes').map((e) => ({ name: e.attrs.name, destination: mem(e, 'destination'), category: mem(e, 'category') })).slice(0, 50) }; });
  await section('overrides', async () => X.all(await show(PA_XPATH.overrides), 'result/application/entry').map((e) => ({ name: e.attrs.name, tcp_timeout: num(X.txt(e, 'tcp-timeout')), timeout: num(X.txt(e, 'timeout')) })));
  // ALGs switched off (one-way audio troubleshooter, voice.js: SIP ALG on or off)
  await section('alg', async () => X.all(await show(PA_XPATH.alg), 'result/application/entry').map((e) => ({ name: e.attrs.name, disabled: X.txt(e, 'alg-disabled') === 'yes' })));
  await section('counters', async () => {
    const c = {};
    for (const e of X.all(await op(PA_OPS.counters), 'result/global/counters/entry')) { const n = X.txt(e, 'name'); if (PA_COUNTERS.test(n)) c[n] = num(X.txt(e, 'value')) || 0; }
    return c;
  });
  return out;
}

async function fortigate(dev, cred = {}, o = {}) {
  const get = o.get || getRaw;
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}`, ho = { headers: { Authorization: 'Bearer ' + cred.token }, tls: cred.tls, timeoutMs: 15000 };
  const vd = cred.vdom ? '?vdom=' + encodeURIComponent(cred.vdom) : '';
  const out = { vendor: 'fortigate', at: (o.now || Date.now)(), unread: [] };
  async function cmdb(path) {
    const r = await get(base + path + vd, ho);
    if (r.status === 401 || r.status === 403) throw Object.assign(new Error('not allowed for this API key'), { denied: true });
    if (r.status !== 200 || !r.json) throw new Error('HTTP ' + r.status);
    return r.json.results;
  }
  async function section(name, fn) {
    try { out[name] = await fn(); } catch (e) { out[name] = null; out.unread.push({ section: name, reason: e.denied ? 'not allowed for this API key (give its profile read access to System and Firewall)' : String(e.message).slice(0, 160) }); }
  }
  const names = (a) => (Array.isArray(a) ? a.map((x) => String((x && (x.name || x.q_origin_key)) || x)) : []);
  await section('settings', async () => { const s = (await cmdb(FG_PATHS.settings)) || {}; return { asymroute: s.asymroute || 'disable', asymroute_icmp: s['asymroute-icmp'] || 'disable', opmode: s.opmode || 'nat', inspection_mode: s['inspection-mode'] || '',
    default_voip_alg_mode: s['default-voip-alg-mode'] || 'proxy-based', sip_expectation: s['sip-expectation'] || 'disable', sip_nat_trace: s['sip-nat-trace'] || 'enable' }; });
  await section('global', async () => { const g = (await cmdb(FG_PATHS.global)) || {}; return { admin_lockout_threshold: num(g['admin-lockout-threshold']), admintimeout: num(g.admintimeout), strong_crypto: g['strong-crypto'] || '', admin_https_redirect: g['admin-https-redirect'] || '', tcp_halfopen_timer: num(g['tcp-halfopen-timer']), tcp_halfclose_timer: num(g['tcp-halfclose-timer']) }; });
  await section('session_ttl', async () => { const s = (await cmdb(FG_PATHS.session_ttl)) || {}; return { default: num(s.default) || 3600, ports: (s.port || []).map((p) => ({ protocol: num(p.protocol), start: num(p['start-port']), end: num(p['end-port']), timeout: p.timeout === 'never' ? 'never' : num(p.timeout) })) }; });
  await section('policies', async () => ((await cmdb(FG_PATHS.policies)) || []).slice(0, 1000).map((p) => ({
    id: p.policyid, name: p.name || '', status: p.status || 'enable', action: p.action, srcintf: names(p.srcintf), dstintf: names(p.dstintf), srcaddr: names(p.srcaddr), dstaddr: names(p.dstaddr), service: names(p.service),
    session_ttl: p['session-ttl'] === 'never' ? 'never' : num(p['session-ttl']) || 0, tcp_session_without_syn: p['tcp-session-without-syn'] || 'disable', ssl_ssh_profile: (p['ssl-ssh-profile'] && (p['ssl-ssh-profile'].name || p['ssl-ssh-profile'])) || '',
    utm: p['utm-status'] || 'disable', tcp_mss_sender: num(p['tcp-mss-sender']) || 0, tcp_mss_receiver: num(p['tcp-mss-receiver']) || 0, logtraffic: p.logtraffic || '', nat: p.nat || 'disable',
    voip_profile: (p['voip-profile'] && (p['voip-profile'].name || p['voip-profile'])) || '' })));
  await section('interfaces', async () => ((await cmdb(FG_PATHS.interfaces)) || []).slice(0, 400).map((i) => ({ name: i.name, type: i.type, role: i.role || '', tcp_mss: num(i['tcp-mss']) || 0, mtu_override: i['mtu-override'] === 'enable', mtu: num(i.mtu) })));
  await section('ssl_profiles', async () => ((await cmdb(FG_PATHS.ssl_profiles)) || []).map((p) => ({ name: p.name, https: (p.https && p.https.status) || '', ssl: (p.ssl && p.ssl.inspect_all) || (p.ssl && p.ssl['inspect-all']) || '', exempt: (p['ssl-exempt'] || []).length })));
  // UDP port ranges of custom services, and the kernel session helpers (one-way audio troubleshooter, voice.js)
  await section('services', async () => ((await cmdb(FG_PATHS.services)) || []).slice(0, 2000).map((x) => ({ name: x.name, udp: String(x['udp-portrange'] || '').trim(), tcp: String(x['tcp-portrange'] || '').trim(), protocol: x.protocol || '' })));
  await section('session_helper', async () => ((await cmdb(FG_PATHS.session_helper)) || []).map((h) => ({ id: h.id, name: h.name, protocol: num(h.protocol), port: num(h.port) })));
  return out;
}

module.exports = { paloalto, fortigate, PA_XPATH, FG_PATHS, PA_OPS };
