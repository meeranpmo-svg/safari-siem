// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * FortiGate fleet through FortiManager (JSON-RPC, https://<fmg>/jsonrpc, API admin key as "Authorization: Bearer").
 * READ: the managed devices of each ADOM (/dvmdb/adom/<adom>/device: model, serial, FortiOS build, connection, config
 * sync, HA) and, through FortiManager's proxy to each FortiGate (/sys/proxy/json, many devices per call), CPU / memory /
 * sessions, IPsec tunnels, SD-WAN health checks (link state: latency, jitter, loss, SLA) and licences / contracts.
 * Nothing is written by the poll. The read key needs a FortiManager admin profile with read-only Device Manager and
 * Policy & Objects, and JSON API access "Read".
 * ASSESS (pure, tested): offline, configuration changed outside FortiManager, conserve-mode memory, CPU, HA out of sync,
 * tunnels down, SD-WAN members out of SLA, licences / support expiring, firmware behind the target for the model (the
 * administrator's target, else the newest build the fleet already runs for that model), and an unusual reading against
 * the device's OWN history (robust z-score on the median / MAD of its last polls - a baseline per device, no fixed number).
 * CHANGE (four-eyes): a fixed list of operations, proposed by an operator, approved by a different PERSON with the firewall
 * scope (approve:eng:security), then run by an operator:
 *   install-package   FortiManager installs an approved policy package on named devices (exec /securityconsole/install/package
 *                     with the separate WRITE key, only when write_enabled is on); the task is followed to the end
 *   retrieve-config   a person runs "Retrieve Config" in FortiManager and marks it done (recorded plan, not run from here)
 *   firmware-upgrade  a person schedules the upgrade in FortiManager and marks it done (recorded plan, not run from here)
 * Nothing the model or a page sends becomes an API call: the call is built here from validated names that exist in the poll.
 *   createFmg({ config, secrets, state, log, transport?, now? })
 *     .poll() .status() .fleet() .device(sn) .testConnection()
 *     .propose(p, by) .decide(id, decision, by, comment) .run(id, by) .markDone(id, by, note) .refreshTask(id) .changes()
 */
const H = require('./http');

const NAME = /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,62}$/;          // FortiManager device / ADOM / package names
const SERIAL = /^[A-Z0-9]{6,20}$/;
const VER = /^\d{1,2}\.\d{1,2}\.\d{1,3}$/;
const TYPES = { 'install-package': 'Install a policy package', 'retrieve-config': 'Retrieve the configuration into FortiManager', 'firmware-upgrade': 'Upgrade FortiOS' };
const EXECUTED = new Set(['install-package']);
const SYSTEM_ADOMS = /^(?:Fortinet|FortiAnalyzer|FortiAuthenticator|FortiCache|FortiCarrier|FortiClient|FortiDDoS|FortiDeceptor|FortiFirewall|FortiFirewallCarrier|FortiMail|FortiManager|FortiProxy|FortiSandbox|FortiWeb|Syslog|Unmanaged_Devices|others|rootp)$/i;
const MON = {
  res: '/api/v2/monitor/system/resource/usage?interval=1-min',
  ipsec: '/api/v2/monitor/vpn/ipsec',
  sdwan: '/api/v2/monitor/virtual-wan/health-check',
  lic: '/api/v2/monitor/license/status',
  dev: '/api/v2/monitor/user/device/query',
};
class FmgError extends Error { constructor(code, msg) { super(msg); this.code = code; this.errors = [msg]; } }
const bad = (m) => new FmgError(400, m);

/* ---------- numbers ---------- */
function median(a) { const s = a.slice().sort((x, y) => x - y), n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; }
// robust z of `v` against the device's own history: (v - median) / (1.4826 * MAD); null until there is enough history
function robustZ(hist, v, min = 24) {
  const h = (hist || []).filter((x) => Number.isFinite(x)); if (h.length < min || !Number.isFinite(v)) return null;
  const m = median(h), mad = median(h.map((x) => Math.abs(x - m))) || 0, s = 1.4826 * mad;
  if (!s) return v === m ? 0 : (Math.abs(v - m) > Math.max(1, Math.abs(m) * 0.25) ? (v > m ? 10 : -10) : 0);
  return (v - m) / s;
}
function verCmp(a, b) { const x = String(a || '').split('.').map(Number), y = String(b || '').split('.').map(Number); for (let i = 0; i < 3; i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; }
const num = (v) => (v === null || v === undefined || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
const first = (r) => (Array.isArray(r) ? r[0] : r);

/* ---------- normalising FortiManager / FortiOS answers (tolerant: fields differ between versions) ---------- */
function normDevice(d, adom) {
  const ver = d.os_ver != null && d.mr != null ? `${String(d.os_ver).replace(/\D.*$/, '')}.${d.mr}.${d.patch != null ? d.patch : 0}` : (String(d.version || '').match(/\d+\.\d+\.\d+/) || [''])[0];
  const conn = d.conn_status === 1 || /^(?:up|1|connected)$/i.test(String(d.conn_status)) ? 'up' : d.conn_status === 2 || /^(?:down|2)$/i.test(String(d.conn_status)) ? 'down' : 'unknown';
  const confStr = String(d.conf_status == null ? '' : d.conf_status).toLowerCase();
  const conf = confStr === '1' || confStr === 'insync' ? 'in-sync' : confStr === '2' || /modified|outofsync|out-of-sync/.test(confStr) ? 'modified' : confStr === '0' || confStr === 'unknown' || !confStr ? 'unknown' : confStr;
  const members = Array.isArray(d.ha_slave) ? d.ha_slave.map((m) => ({ name: String(m.name || ''), serial: String(m.sn || ''), role: Number(m.role) === 1 || /primary|master/i.test(String(m.role)) ? 'primary' : 'secondary', status: Number(m.status) === 1 || /up|ok/i.test(String(m.status)) ? 'up' : 'down' })) : [];
  return { id: String(d.sn || d.name), serial: String(d.sn || ''), name: String(d.name || d.hostname || d.sn), adom, hostname: String(d.hostname || ''),
    model: String(d.platform_str || d.platform || ''), ip: String(d.ip || ''), firmware: ver, build: num(d.build),
    conn, conf, ha_mode: Number(d.ha_mode) ? (String(d.ha_mode) === '1' ? 'a-p' : String(d.ha_mode) === '2' ? 'a-a' : String(d.ha_mode)) : (typeof d.ha_mode === 'string' && d.ha_mode !== '0' ? d.ha_mode : 'standalone'), ha_members: members,
    site: String(d.desc || d.location || '').slice(0, 80) };
}
function normRes(r) {
  const res = (r && r.results) || r || {}, at = (k) => { const x = res[k]; const v = Array.isArray(x) ? (x[0] && (x[0].current != null ? x[0].current : x[0].historical && x[0].historical['1-min'] && x[0].historical['1-min'].avg)) : x; return num(v); };
  return { cpu: at('cpu'), mem: at('mem'), sessions: at('session'), setup_rate: at('setuprate') };
}
function normIpsec(r) {
  const list = (r && r.results) || (Array.isArray(r) ? r : []);
  const out = [];
  for (const t of list) {
    const props = Array.isArray(t.proxyid) && t.proxyid.length ? t.proxyid : [t];
    const up = props.some((p) => /^up$/i.test(String(p.status || '')));
    out.push({ name: String(t.name || ''), peer: String(t.rgwy || t.tun_id || ''), up, in_bytes: num(t.incoming_bytes), out_bytes: num(t.outgoing_bytes) });
  }
  return out;
}
function normSdwan(r) {
  const res = (r && r.results) || r || {}, out = [];
  for (const [hc, members] of Object.entries(res)) {
    if (!members || typeof members !== 'object') continue;
    for (const [m, v] of Object.entries(members)) {
      if (!v || typeof v !== 'object') continue;
      const sla = v.sla_targets_met; const slaOk = Array.isArray(sla) ? sla.length > 0 : sla == null ? null : !!sla;
      out.push({ check: hc, member: m, state: String(v.status || '').toLowerCase() === 'up' ? 'up' : String(v.status || '').toLowerCase() === 'down' ? 'down' : 'unknown',
        latency: num(v.latency), jitter: num(v.jitter), loss: num(v.packet_loss), sla_ok: slaOk });
    }
  }
  return out;
}
// FortiGate device detection: every endpoint the FortiGate sees on its LAN (MAC, IP, host name, OS, hardware, interface)
function normEndpoints(r) {
  const list = (r && r.results) || (Array.isArray(r) ? r : []), out = [];
  for (const e of list) {
    const mac = String(e.mac || e.master_mac || '').toLowerCase(); if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) continue;
    out.push({ mac, ip: String(e.ipv4_address || e.ip || ''), host: String(e.hostname || e.host_name || '').slice(0, 80), os: String(e.os_name || e.os || '').slice(0, 60),
      os_version: String(e.os_version || '').slice(0, 30), hw: String(e.hardware_vendor || e.hardware_family || '').slice(0, 60), type: String(e.hardware_type || e.type || '').slice(0, 40),
      iface: String(e.detected_interface || e.interface || '').slice(0, 40), user: String(e.user_name || e.user || '').slice(0, 80), online: e.is_online !== false });
  }
  return out;
}
function normLic(r) {
  const res = (r && r.results) || r || {}, out = [];
  for (const [k, v] of Object.entries(res)) {
    if (!v || typeof v !== 'object') continue;
    const exp = num(v.expires) || (v.expiry_date ? Date.parse(v.expiry_date) / 1000 : null);
    if (exp || v.status) out.push({ name: k, status: String(v.status || ''), expires: exp ? new Date(exp * 1000).toISOString().slice(0, 10) : null });
  }
  return out;
}

/* ---------- assessment ---------- */
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };
function assess(dev, { targets = {}, newest = {}, now = Date.now(), staleMin = 45 } = {}) {
  const f = [], add = (sev, code, title, fix) => f.push({ severity: sev, code, title, fix });
  if (dev.conn === 'down') add('critical', 'offline', 'FortiManager cannot reach the FortiGate', 'Check the FGFM tunnel (TCP 541) and the WAN link at the site');
  if (dev.last_seen && now - Date.parse(dev.last_seen) > staleMin * 60000 && dev.conn !== 'down') add('medium', 'stale', 'No reading for ' + Math.round((now - Date.parse(dev.last_seen)) / 60000) + ' min', 'The FortiManager proxy call to this device fails - see the poll error');
  if (dev.conf === 'modified') add('high', 'drift', 'Configuration changed on the device, outside FortiManager', 'Review the change, then Retrieve Config (keep it) or install the package (undo it) - a four-eyes plan here');
  const m = dev.metrics || {};
  if (m.mem != null && m.mem >= 88) add('critical', 'conserve', `Memory ${m.mem} % - conserve mode starts at about 88 %`, 'Find the process or session growth; in conserve mode new sessions and inspection fail');
  else if (m.mem != null && m.mem >= 80) add('medium', 'mem', `Memory ${m.mem} %`, 'Watch the trend; plan an upgrade or reduce inspection load');
  if (m.cpu != null && m.cpu >= 90) add('high', 'cpu', `CPU ${m.cpu} %`, 'Check top sessions and the inspection profiles on the busiest policies');
  if (dev.ha_mode !== 'standalone' && dev.ha_members && dev.ha_members.some((x) => x.status === 'down')) add('high', 'ha', 'An HA member is down', 'Check the heartbeat links and the member\'s power');
  const tun = dev.tunnels || [], down = tun.filter((t) => !t.up);
  if (down.length) add(down.length === tun.length ? 'high' : 'medium', 'vpn', `${down.length} of ${tun.length} IPsec tunnel(s) down: ${down.slice(0, 4).map((t) => t.name).join(', ')}`, 'Check the peer and phase-1 / phase-2 settings, and the WAN link');
  const links = dev.links || [], lDown = links.filter((l) => l.state === 'down'), lSla = links.filter((l) => l.state === 'up' && l.sla_ok === false);
  if (lDown.length) add('high', 'link-down', `SD-WAN member down: ${lDown.slice(0, 4).map((l) => l.member).join(', ')}`, 'Call the carrier for that circuit; traffic runs on the other members');
  if (lSla.length) add('medium', 'link-sla', `SD-WAN member out of SLA: ${lSla.slice(0, 4).map((l) => `${l.member} (${l.loss != null ? l.loss + ' % loss, ' : ''}${l.latency != null ? Math.round(l.latency) + ' ms' : ''})`).join(', ')}`, 'Quality is below the health-check SLA - raise it with the carrier');
  for (const l of dev.licences || []) {
    if (!l.expires) continue; const days = Math.floor((Date.parse(l.expires) - now) / 86400000);
    if (days < 0) add('high', 'licence', `${l.name} expired ${-days} day(s) ago`, 'Renew the FortiCare / FortiGuard contract for this serial');
    else if (days <= 30) add('medium', 'licence', `${l.name} expires in ${days} day(s)`, 'Renew before it lapses');
  }
  const target = targets[dev.model] || newest[dev.model];
  if (dev.firmware && target && verCmp(dev.firmware, target) < 0) add(targets[dev.model] ? 'medium' : 'low', 'firmware', `FortiOS ${dev.firmware}, ${targets[dev.model] ? 'the target' : 'the newest in the fleet'} for ${dev.model} is ${target}`, 'Plan the upgrade (a four-eyes plan here, scheduled in FortiManager)');
  const z = dev.z || {};
  for (const [k, lbl] of [['cpu', 'CPU'], ['sessions', 'sessions'], ['mem', 'memory']]) if (z[k] != null && z[k] >= 4 && m[k] != null) add('low', 'unusual-' + k, `Unusual ${lbl} for this device: ${m[k]} (its own baseline: ${dev.baseline && dev.baseline[k] != null ? dev.baseline[k] : '?'})`, 'Compare with what changed: traffic, a new policy, an attack');
  f.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
  const worst = f[0] ? f[0].severity : null;
  return { findings: f, health: dev.conn === 'down' ? 'down' : worst === 'critical' || worst === 'high' ? 'attention' : worst ? 'watch' : 'ok' };
}

function createFmg({ config, secrets, state, log, transport, now } = {}) {
  const NOW = now || Date.now, L = log || { info() {}, warn() {}, error() {} };
  const C = () => (config && config.fortimanager) || {};
  const S = () => (secrets && secrets.fortimanager) || (config && config.secrets && config.secrets.fortimanager) || {};
  const devs = state.collection('fmg_devices'), chg = state.collection('fmg_changes');
  const st = { polls: 0, last_poll_at: null, last_error: '', devices: 0, calls: 0 };
  let seq = 1;

  function baseUrl() { const b = String(C().base_url || '').replace(/\/+$/, ''); if (!/^https:\/\/[A-Za-z0-9.-]+(?::\d{2,5})?$/.test(b)) throw new FmgError(409, 'FortiManager address not set (https://<fortimanager>)'); return b; }
  async function rpc(method, url, extra, { write } = {}) {
    const key = write ? S().write_key : S().api_key;
    if (!key) throw new FmgError(409, write ? 'no FortiManager write key is stored - an administrator adds it in the Integration Hub' : 'no FortiManager API key is stored');
    const body = { id: seq++, method, params: [Object.assign({ url }, extra || {})] };
    st.calls++;
    let j;
    if (transport) j = await transport(body, { write: !!write, base: baseUrl() });
    else {
      const c = C(), r = await H.getRaw(baseUrl() + '/jsonrpc', { method: 'POST', body: JSON.stringify(body), timeoutMs: 30000,
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key }, tls: { fingerprint256: c.tls_fingerprint || undefined, ca: c.ca_pem || undefined } });
      if (r.status === 401 || r.status === 403) throw new FmgError(502, 'FortiManager refused the API key (HTTP ' + r.status + ')');
      if (r.status !== 200 || !r.json) throw new FmgError(502, 'FortiManager answered HTTP ' + r.status);
      j = r.json;
    }
    const res = first(j && j.result) || {}, code = res.status ? Number(res.status.code) : 0;
    if (code === -11) throw new FmgError(502, 'FortiManager: no permission for ' + url + ' (the API admin profile)');
    if (code !== 0) throw new FmgError(502, 'FortiManager ' + url + ': ' + ((res.status && res.status.message) || 'error ' + code));
    return res.data;
  }
  async function adoms() {
    const want = Array.isArray(C().adoms) && C().adoms.length ? C().adoms : null;
    if (want) return want;
    const list = (await rpc('get', '/dvmdb/adom', { fields: ['name', 'state'] })) || [];
    return list.map((a) => String(a.name)).filter((n) => n && !SYSTEM_ADOMS.test(n));
  }
  async function proxy(resource, targets) {
    const out = new Map();
    for (let i = 0; i < targets.length; i += 25) {
      const part = targets.slice(i, i + 25);
      let data;
      try { data = await rpc('exec', '/sys/proxy/json', { data: { action: 'get', resource, target: part } }); }
      catch (e) { for (const t of part) out.set(t, { error: e.message }); continue; }
      for (const r of Array.isArray(data) ? data : []) {
        const t = String(r.target || ''), ok = r.status && Number(r.status.code) === 0;
        out.set(t, ok ? { response: r.response } : { error: (r.status && r.status.message) || 'no answer' });
      }
    }
    return out;
  }

  async function poll() {
    const at = new Date(NOW()).toISOString(), errors = [];
    try {
      const list = [];
      for (const adom of await adoms()) {
        if (!NAME.test(adom)) continue;
        const d = await rpc('get', `/dvmdb/adom/${adom}/device`, { fields: ['name', 'sn', 'ip', 'platform_str', 'os_ver', 'mr', 'patch', 'build', 'conn_status', 'conf_status', 'ha_mode', 'ha_slave', 'hostname', 'desc'] });
        for (const x of Array.isArray(d) ? d : []) list.push(normDevice(x, adom));
      }
      const up = list.filter((d) => d.conn === 'up'), tgt = (d) => `adom/${d.adom}/device/${d.name}`;
      const [res, ips, sdw, lic, edv] = await Promise.all([proxy(MON.res, up.map(tgt)), proxy(MON.ipsec, up.map(tgt)), proxy(MON.sdwan, up.map(tgt)), proxy(MON.lic, up.map(tgt)), C().endpoints === false ? new Map() : proxy(MON.dev, up.map(tgt))]);
      for (const d of list) {
        const prev = devs.get(d.id) || {}, t = tgt(d), hist = prev.history || { cpu: [], mem: [], sessions: [] };
        const rr = res.get(t), ir = ips.get(t), sr = sdw.get(t), lr = lic.get(t);
        const metrics = rr && rr.response ? normRes(rr.response) : null;
        const next = Object.assign({}, d, {
          metrics: metrics || (d.conn === 'up' ? prev.metrics || null : null),
          tunnels: ir && ir.response ? normIpsec(ir.response) : prev.tunnels || [],
          links: sr && sr.response ? normSdwan(sr.response) : prev.links || [],
          licences: lr && lr.response ? normLic(lr.response) : prev.licences || [],
          last_seen: metrics ? at : prev.last_seen || null, first_seen: prev.first_seen || at,
          read_errors: [rr, ir, sr, lr].filter((x) => x && x.error).map((x) => x.error).slice(0, 4) });
        const z = {}, baseline = {};
        for (const k of ['cpu', 'mem', 'sessions']) {
          const v = metrics ? metrics[k] : null;
          z[k] = robustZ(hist[k], v); baseline[k] = hist[k] && hist[k].length >= 24 ? median(hist[k]) : null;
          if (v != null) hist[k] = (hist[k] || []).concat(v).slice(-288);
        }
        next.history = hist; next.z = z; next.baseline = baseline;
        devs.put(next);
        const er = edv.get(t); if (er && er.response) endpointsSeen(d, normEndpoints(er.response), at);
      }
      // a device FortiManager no longer manages is kept 7 days, marked removed, then dropped
      const seen = new Set(list.map((d) => d.id));
      for (const o of devs.all((x) => !seen.has(x.id))) { if (!o.removed_at) devs.patch(o.id, (c) => { c.removed_at = at; return c; }); else if (NOW() - Date.parse(o.removed_at) > 7 * 86400000) devs.remove(o.id); }
      st.devices = list.length;
    } catch (e) { errors.push(e.message); L.warn('fortimanager: poll failed', { err: e.message }); }
    st.polls++; st.last_poll_at = at; st.last_error = errors.join(' · ');
    return status();
  }
  // endpoints: one record per MAC across the fleet, with where and as what it was seen (the NAC view reads these)
  const eps = state.collection('fmg_endpoints');
  function endpointsSeen(d, list, at) {
    for (const e of list.slice(0, 5000)) {
      const cur = eps.get(e.mac) || { id: e.mac, mac: e.mac, first_seen: at, sightings: [], idents: [] };
      const ident = [e.os, e.host].join('|');
      if (!cur.idents.includes(ident)) cur.idents = cur.idents.concat(ident).slice(-6);
      cur.sightings = cur.sightings.filter((x) => x.fortigate !== d.name).concat({ fortigate: d.name, site: d.site || d.adom, at, iface: e.iface }).slice(-8);
      Object.assign(cur, { ip: e.ip, host: e.host, os: e.os, os_version: e.os_version, hw: e.hw, type: e.type, user: e.user, last_seen: at, fortigate: d.name, site: d.site || d.adom });
      eps.put(cur);
    }
  }
  function status() { const c = C(); return Object.assign({ enabled: !!c.enabled, configured: !!(c.base_url && S().api_key), write_enabled: !!(c.write_enabled && S().write_key) }, st); }

  function targets() {
    const t = {}; for (const s of C().firmware_targets || []) { const m = String(s).match(/^(.+?)=(\d+\.\d+\.\d+)$/); if (m) t[m[1].trim()] = m[2]; } return t;
  }
  function assessed() {
    const all = devs.all((d) => !d.removed_at), newest = {};
    for (const d of all) if (d.model && d.firmware && (!newest[d.model] || verCmp(d.firmware, newest[d.model]) > 0)) newest[d.model] = d.firmware;
    const T = targets(), n = NOW();
    return { all: all.map((d) => Object.assign({}, d, assess(d, { targets: T, newest, now: n }))), newest, T };
  }
  function slim(d) { const o = Object.assign({}, d); delete o.history; return o; }
  function fleet() {
    const { all, newest, T } = assessed(), by = (k) => all.filter((d) => d.health === k).length;
    const models = {};
    for (const d of all) { const m = models[d.model || 'unknown'] = models[d.model || 'unknown'] || { model: d.model || 'unknown', devices: 0, versions: {}, target: T[d.model] || null, newest: newest[d.model] || null }; m.devices++; m.versions[d.firmware || '?'] = (m.versions[d.firmware || '?'] || 0) + 1; }
    const links = []; for (const d of all) for (const l of d.links || []) links.push(Object.assign({ device: d.name, serial: d.serial, site: d.site }, l));
    const tunnels = { up: 0, down: 0 }; for (const d of all) for (const t of d.tunnels || []) tunnels[t.up ? 'up' : 'down']++;
    const findings = []; for (const d of all) for (const f of d.findings) findings.push(Object.assign({ device: d.name, serial: d.serial, adom: d.adom }, f));
    findings.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
    return { status: status(), kpis: { devices: all.length, ok: by('ok'), watch: by('watch'), attention: by('attention'), down: by('down'), out_of_sync: all.filter((d) => d.conf === 'modified').length,
      firmware_behind: all.filter((d) => d.findings.some((f) => f.code === 'firmware')).length, tunnels, links_down: links.filter((l) => l.state === 'down').length, links_out_of_sla: links.filter((l) => l.state === 'up' && l.sla_ok === false).length,
      licences_due: all.filter((d) => d.findings.some((f) => f.code === 'licence')).length },
      devices: all.map(slim).sort((a, b) => ({ down: 0, attention: 1, watch: 2, ok: 3 }[a.health] - { down: 0, attention: 1, watch: 2, ok: 3 }[b.health]) || a.name.localeCompare(b.name)),
      models: Object.values(models).sort((a, b) => b.devices - a.devices), links, findings: findings.slice(0, 500), changes_open: chg.all((c) => ['proposed', 'approved', 'running'].includes(c.status)).length };
  }
  function device(id) { const d = assessed().all.find((x) => x.id === id || x.name === id); if (!d) throw new FmgError(404, 'device not found in the FortiManager poll'); return slim(d); }

  async function testConnection() {
    const steps = [];
    try { baseUrl(); } catch (e) { return { ok: false, steps: [{ ok: false, text: e.message }] }; }
    try { const v = await rpc('get', '/sys/status'); steps.push({ ok: true, text: 'signed in - FortiManager ' + ((v && (v.Version || v.version)) || '') + (v && v.Hostname ? ' (' + v.Hostname + ')' : '') }); }
    catch (e) { steps.push({ ok: false, text: e.message }); return { ok: false, steps }; }
    try { const a = await adoms(); steps.push({ ok: true, text: a.length + ' ADOM(s): ' + a.slice(0, 6).join(', ') }); let n = 0; for (const x of a.slice(0, 10)) { const d = await rpc('get', `/dvmdb/adom/${x}/device`, { fields: ['name'] }); n += Array.isArray(d) ? d.length : 0; } steps.push({ ok: n > 0, text: n + ' managed FortiGate(s) readable' + (n ? '' : ' - the admin profile may not see Device Manager') }); }
    catch (e) { steps.push({ ok: false, text: e.message }); }
    return { ok: steps.every((s) => s.ok), steps };
  }

  /* ---------- four-eyes changes ---------- */
  function nextId() { let max = 0; for (const c of chg.all()) { const n = Number(String(c.id).slice(5)); if (n > max) max = n; } return 'FGCH-' + String(max + 1).padStart(6, '0'); }
  function must(id) { const c = chg.get(id); if (!c) throw new FmgError(404, 'change not found'); return c; }
  function propose(p, by) {
    if (!TYPES[p.type]) throw bad('type: one of ' + Object.keys(TYPES).join(', '));
    const known = new Map(devs.all((d) => !d.removed_at).map((d) => [d.name, d]));
    const names = [...new Set(p.devices || [])];
    if (!names.length || names.length > 100) throw bad('devices: name 1 - 100 FortiGates');
    const miss = names.filter((n) => !NAME.test(n) || !known.has(n)); if (miss.length) throw bad('devices: not managed by FortiManager (from the last poll): ' + miss.slice(0, 5).join(', '));
    const adomSet = [...new Set(names.map((n) => known.get(n).adom))];
    const plan = { id: nextId(), type: p.type, title: TYPES[p.type], devices: names, adom: adomSet.length === 1 ? adomSet[0] : null, reason: String(p.reason || '').slice(0, 600),
      status: 'proposed', proposed_by: by, proposed_at: new Date(NOW()).toISOString(), history: [{ at: new Date(NOW()).toISOString(), by, what: 'proposed' }], executed_here: EXECUTED.has(p.type) };
    if (!plan.reason || plan.reason.length < 10) throw bad('reason: say why, in at least 10 characters');
    if (p.type === 'install-package') {
      if (!p.package || !NAME.test(p.package)) throw bad('package: the policy package name as FortiManager shows it');
      if (!plan.adom) throw bad('devices: an install covers devices of one ADOM');
      plan.package = p.package;
    }
    if (p.type === 'firmware-upgrade') {
      if (!VER.test(String(p.version || ''))) throw bad('version: FortiOS version such as 7.2.10');
      const models = [...new Set(names.map((n) => known.get(n).model))]; if (models.length > 1) throw bad('devices: one model per upgrade plan (' + models.join(', ') + ')');
      plan.version = p.version; plan.model = models[0];
      plan.from = [...new Set(names.map((n) => known.get(n).firmware))];
      if (plan.from.every((v) => v && verCmp(v, p.version) >= 0)) throw bad('version: every device already runs ' + p.version + ' or newer');
    }
    if (p.window && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(p.window)) throw bad('window: YYYY-MM-DDTHH:MM');
    plan.window = p.window || null;
    return chg.put(plan);
  }
  function decide(id, decision, by, comment) {
    const c = must(id);
    if (c.status !== 'proposed') throw new FmgError(409, 'only a proposed change is decided (this one is ' + c.status + ')');
    if (!['approved', 'rejected'].includes(decision)) throw bad('decision: approved or rejected');
    if (String(by).toLowerCase() === String(c.proposed_by).toLowerCase()) throw new FmgError(403, 'four-eyes: the person who proposed a change does not approve it');
    if (decision === 'rejected' && !(comment && String(comment).trim().length >= 5)) throw bad('comment: say why it is rejected');
    return chg.patch(id, (x) => { x.status = decision; x.decided_by = by; x.decided_at = new Date(NOW()).toISOString(); x.comment = String(comment || '').slice(0, 400); x.history.push({ at: x.decided_at, by, what: decision }); return x; });
  }
  async function run(id, by) {
    const c = must(id);
    if (c.status !== 'approved') throw new FmgError(409, 'a change runs only once approved (this one is ' + c.status + ')');
    if (!c.executed_here) throw new FmgError(409, c.title + ' is carried out in FortiManager by a person - mark it done when it is');
    if (!(C().write_enabled && S().write_key)) throw new FmgError(409, 'running changes is switched off - an administrator stores a FortiManager write key and switches it on');
    const known = new Map(devs.all((d) => !d.removed_at).map((d) => [d.name, d]));
    const miss = c.devices.filter((n) => !known.has(n) || known.get(n).adom !== c.adom); if (miss.length) throw new FmgError(409, 'no longer managed in ADOM ' + c.adom + ': ' + miss.join(', '));
    chg.patch(id, (x) => { x.status = 'running'; x.run_by = by; x.run_at = new Date(NOW()).toISOString(); x.history.push({ at: x.run_at, by, what: 'run' }); return x; });
    try {
      const data = await rpc('exec', '/securityconsole/install/package', { data: { adom: c.adom, pkg: c.package, scope: c.devices.map((n) => ({ name: n, vdom: 'root' })), flags: ['none'] } }, { write: true });
      const task = data && (data.task != null ? data.task : data.taskid);
      return chg.patch(id, (x) => { x.task = task != null ? Number(task) : null; x.history.push({ at: new Date(NOW()).toISOString(), by, what: 'FortiManager task ' + (task != null ? task : '?') + ' started' }); return x; });
    } catch (e) {
      return chg.patch(id, (x) => { x.status = 'failed'; x.error = e.message; x.history.push({ at: new Date(NOW()).toISOString(), by, what: 'failed: ' + e.message }); return x; });
    }
  }
  async function refreshTask(id) {
    const c = must(id); if (c.status !== 'running' || c.task == null) return c;
    const t = await rpc('get', '/task/task/' + Number(c.task));
    const pct = num(t && t.percent), errs = num(t && t.num_err) || 0, done = pct === 100 || (t && /done|finish/i.test(String(t.state)));
    return chg.patch(id, (x) => { x.task_percent = pct; if (done) { x.status = errs ? 'failed' : 'done'; x.done_at = new Date(NOW()).toISOString(); x.history.push({ at: x.done_at, by: 'FortiManager', what: errs ? errs + ' device(s) failed in task ' + x.task : 'installed on every device' }); } return x; });
  }
  function markDone(id, by, note) {
    const c = must(id);
    if (c.status !== 'approved') throw new FmgError(409, 'only an approved change is marked done (this one is ' + c.status + ')');
    if (c.executed_here) throw new FmgError(409, 'this change is run from here - press Run');
    return chg.patch(id, (x) => { x.status = 'done'; x.done_by = by; x.done_at = new Date(NOW()).toISOString(); x.note = String(note || '').slice(0, 400); x.history.push({ at: x.done_at, by, what: 'done in FortiManager' }); return x; });
  }
  const changes = () => chg.all().sort((a, b) => String(b.id).localeCompare(String(a.id)));
  return { poll, status, fleet, device, testConnection, propose, decide, run, refreshTask, markDone, changes, get: (id) => chg.get(id), TYPES };
}

module.exports = { createFmg, assess, robustZ, normDevice, normRes, normIpsec, normSdwan, normLic, normEndpoints, verCmp, NAME, TYPES, FmgError };
