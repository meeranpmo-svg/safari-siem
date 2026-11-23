// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
const G = require('../util/ai-guard');
const S = require('../util/ai-schema');
/*
 * AI Network Engineer — Claude with read-only tools over the network inventory, live poll snapshots, health findings,
 * the deterministic troubleshooter and the SIEM's logs. It answers questions ("why is the Jeddah branch slow?"),
 * correlates evidence, and can PROPOSE a change plan (which a person must approve and carry out). It cannot change a
 * device: no tool writes to the network (show_commands runs allowlisted read-only show commands over SSH, cli.js).
 *   createAI({ config, log, tools: { inventory, poller, evidence, diagnose, findings, sites, changes, ping, cli? }, sdk? })
 *     .status() → {enabled, reason, model}
 *     .ask({ question, conversation?, user, role?, system_extra?, by? }) → { answer, conversation, steps:[{tool, input, ok, ms}], model, usage }
 *   Tools carry the same minimum role as the matching API route (TOOL_ROLE): an analyst's question cannot run device
 *   CLI commands or file change plans through the AI. The ticket desk (tickets.js) asks with the role it was set up with.
 * Uses the official Anthropic SDK (@anthropic-ai/sdk, installed with install/netops-ai-sdk.*). API key: secrets.json
 * "netops.anthropic_api_key" (or ANTHROPIC_API_KEY). Outbound proxy: HTTPS_PROXY + NODE_USE_ENV_PROXY=1 in
 * /etc/default/sentra-siem. Conversations are kept append-only in the state collection "netops_chats" (per user).
 */
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');

const MODEL = 'claude-opus-5-5';
const MAX_STEPS = 14, MAX_RESULT = 24000;

const SYSTEM = `You are the AI Network Engineer for ${ZYB_ORG.short}'s enterprise network (Cisco switches and routers, FortiGate and Palo Alto firewalls, Genian NAC, HPE Aruba EdgeConnect / Silver Peak SD-WAN, branch offices across Saudi Arabia). You work inside the company's SIEM and answer the network and security operations team.

How you work:
- Base every statement on tool results. Start broad (network_overview or diagnose), then drill into the devices, interfaces, tunnels, logs and changes that matter. Run independent lookups in parallel.
- Never invent device names, IP addresses, interface names, figures or log lines. If the data is missing or a device is not monitored, say so and say what would need to be connected.
- For server uptime, outages, restarts, HA, single points of failure and DR use server_availability.
- For live state the poll does not hold (which port a MAC or IP is on, CDP / LLDP neighbours, VLANs, err-disabled ports, STP, PoE, the running configuration, the switch's own log buffer, model and serial) use show_commands on Cisco devices. Only read-only show commands from the allowlist run; group the commands you need into one call per device. If a device has no SSH login or trusted host key, say an administrator must add them (Devices → device → Credentials / SSH host key).
- For security questions use security_review and findings (kinds starting with sec-): risky firewall rules, exposed administration, weak monitoring credentials, certificates.
- Correlate across layers: reachability → links and utilisation → VPN / SD-WAN paths → routing → firewall policy (blocked connections) → NAC → recent configuration changes and up/down events in the SIEM.
- You never change a device yourself. For these jobs on Cisco IOS / IOS-XE use propose_task: create a VLAN, put access ports in a VLAN, allow a VLAN on trunks, set a port description, shut down / enable a port, stage an IOS image (copy, MD5 check, boot variable - never a reload), schedule a reload. After an administrator approves it, an operator presses Run and the platform applies it with prechecks, verification and automatic rollback. Check the current state with show_commands first (VLAN exists? port is a trunk?). For IOS staging the image URL and the MD5 must come from the person - never invent them. Anything else: write the exact vendor commands and a rollback and call propose_change, so an engineer can review, approve and apply it. Never claim a change was made.
- Quarantine, blocking or other disruptive actions are recommendations for a human to authorise, never something you do.

Answer format (keep it tight; the reader is an engineer):
1. Summary — one or two sentences.
2. Probable root cause — with a confidence (high / medium / low).
3. Evidence — the specific measurements and log lines that support it (device, interface, time).
4. Recommended fix — numbered, safe steps; vendor CLI where useful; what to check afterwards.
5. If uncertain, what to check next.
Reply in the language of the question (Arabic or English).`;

const TOOLS = [
  { name: 'network_overview', description: 'Sites with status, device counts, average latency/loss, and the most severe current findings. Start here for broad questions.', input_schema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'route_map', description: 'The WAN / LAN route map: incidents with their root cause (a down node or link and what it cuts off; covered incidents point to their cause), bandwidth / loss / latency problems per link with the learned baseline for this hour and the capacity forecast, and the FortiGate users at a congested site. Use it for "where is the outage", "why is branch X slow", "who is using the bandwidth".', input_schema: { type: 'object', properties: { site: { type: 'string', maxLength: 80 }, only_problems: { type: 'boolean' } }, additionalProperties: false } },
  { name: 'list_devices', description: 'Monitored network devices (id, name, vendor, IP, site, role, last poll result). Optional filters.', input_schema: { type: 'object', properties: { site: { type: 'string' }, vendor: { type: 'string', enum: ['cisco-ios', 'cisco-asa', 'fortigate', 'paloalto', 'genian', 'edgeconnect', 'other'] } }, additionalProperties: false } },
  { name: 'device_status', description: 'Latest poll of one device: reachability, CPU/memory/sessions, interfaces (status, utilisation, errors), VPN tunnels, HA, BGP/OSPF neighbours, SD-WAN paths, NAC summary.', input_schema: { type: 'object', properties: { device: { type: 'string', description: 'device id or name' }, interface_filter: { type: 'string', description: 'optional substring to limit interfaces' } }, required: ['device'], additionalProperties: false } },
  { name: 'findings', description: 'Current health findings (problems) with evidence and recommendations, optionally for one site or device or minimum severity.', input_schema: { type: 'object', properties: { site: { type: 'string' }, device: { type: 'string' }, min_severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] } }, additionalProperties: false } },
  { name: 'diagnose', description: 'Run the standard troubleshooting workflow for a site or device (reachability, links, tunnels/SD-WAN, routing, HA, SIEM up/down events, recent config changes, firewall blocks to a target, NAC) and get ranked probable causes.', input_schema: { type: 'object', properties: { site: { type: 'string' }, device: { type: 'string' }, target_ip: { type: 'string', description: 'application/server IP the users cannot reach, if known' }, symptom: { type: 'string' }, minutes: { type: 'integer', minimum: 30, maximum: 1440 } }, additionalProperties: false } },
  { name: 'device_events', description: 'SIEM log events for a device. kind=link for interface/tunnel/routing/HA up-down messages, config for configuration changes, all for everything.', input_schema: { type: 'object', properties: { device: { type: 'string' }, minutes: { type: 'integer', minimum: 5, maximum: 10080 }, kind: { type: 'string', enum: ['all', 'link', 'config'] } }, required: ['device'], additionalProperties: false } },
  { name: 'config_changes', description: 'Configuration changes recorded in the SIEM for network devices (who, when, what), optionally for one device.', input_schema: { type: 'object', properties: { device: { type: 'string' }, hours: { type: 'integer', minimum: 1, maximum: 720 } }, additionalProperties: false } },
  { name: 'blocked_connections', description: 'Connections denied/blocked by the firewalls, grouped by source → destination:port, from the SIEM.', input_schema: { type: 'object', properties: { src_ip: { type: 'string' }, dst_ip: { type: 'string' }, dst_port: { type: 'integer', minimum: 1, maximum: 65535 }, minutes: { type: 'integer', minimum: 5, maximum: 10080 } }, additionalProperties: false } },
  { name: 'top_talkers', description: 'Heaviest traffic from firewall traffic logs in the SIEM: by source/destination pair, source IP or application.', input_schema: { type: 'object', properties: { minutes: { type: 'integer', minimum: 5, maximum: 1440 }, ip: { type: 'string' }, by: { type: 'string', enum: ['pair', 'src', 'app'] } }, additionalProperties: false } },
  { name: 'nac_lookup', description: 'Genian NAC / 802.1X / RADIUS events for an endpoint IP or MAC from the SIEM, plus the current NAC node record if the NAC API is polled.', input_schema: { type: 'object', properties: { ip: { type: 'string' }, mac: { type: 'string' }, hours: { type: 'integer', minimum: 1, maximum: 720 } }, additionalProperties: false } },
  { name: 'metric_history', description: 'History of a polled metric for trends: loss_pct, rtt_ms, jitter_ms, cpu_pct, mem_pct, sessions (key empty) or in_bps, out_bps, util_pct, err_per_min (key = interface name), path_loss_pct/path_latency_ms (key = check/member).', input_schema: { type: 'object', properties: { device: { type: 'string' }, metric: { type: 'string' }, key: { type: 'string' }, hours: { type: 'integer', minimum: 1, maximum: 2160 } }, required: ['device', 'metric'], additionalProperties: false } },
  { name: 'security_review', description: 'Results of the network security checks per device: firewall rules allowing any-any or internet-to-any, policies without logging, Telnet/HTTP or WAN-exposed administration, administrators without trusted hosts, open Telnet, expiring certificates, weak SNMP. Optional device filter.', input_schema: { type: 'object', properties: { device: { type: 'string' } }, additionalProperties: false } },
  { name: 'server_availability', description: 'Servers and IT devices: online/offline and for how long, availability % (24 h / 7 d / 30 d), last restart and days since restart, unexpected shutdowns, HA groups, single points of failure, services without DR. Optional filter: name/IP substring or a flag (offline, reboot-overdue, single-server, no-dr, no-redundancy-now).', input_schema: { type: 'object', properties: { filter: { type: 'string' } }, additionalProperties: false } },
  { name: 'ping', description: 'Ping a monitored device (by id/name) or a private IP address from the SIEM server: loss, latency, jitter.', input_schema: { type: 'object', properties: { target: { type: 'string' } }, required: ['target'], additionalProperties: false } },
  { name: 'show_commands', description: 'Log in to a Cisco IOS switch / router or Cisco ASA over SSH and run read-only show commands (allowlist only: e.g. show version, show inventory, show interfaces status, show interfaces <if>, show interfaces counters errors, show vlan brief, show cdp neighbors detail, show lldp neighbors detail, show mac address-table [address aaaa.bbbb.cccc | interface <if>], show ip arp [ip], show spanning-tree summary, show etherchannel summary, show power inline, show environment all, show logging, show running-config [interface <if>], show ip route [ip], show processes cpu sorted; "| include text" filters allowed). Passwords and keys are removed from the output. Configuration commands are refused.', input_schema: { type: 'object', properties: { device: { type: 'string', description: 'device id or name' }, commands: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 6 } }, required: ['device', 'commands'], additionalProperties: false } },
  { name: 'propose_task', description: 'Propose an approved task on a Cisco IOS / IOS-XE device. The platform builds the exact commands, an administrator approves, an operator presses Run; prechecks, verification and automatic rollback are done by the platform. Types and params: vlan-create {vlan, name?} · port-access-vlan {vlan, interfaces[], description?} · trunk-vlan-add {vlans[], interfaces[]} · port-description {interface, description} · port-shutdown {interface} · port-enable {interface} · ios-stage {image, url, md5} (no reload) · ios-reload {minutes}.', input_schema: { type: 'object', properties: { device: { type: 'string' }, type: { type: 'string', enum: ['vlan-create', 'port-access-vlan', 'trunk-vlan-add', 'port-description', 'port-shutdown', 'port-enable', 'ios-stage', 'ios-reload'] }, reason: { type: 'string' },
    params: { type: 'object', properties: { vlan: { type: 'integer', minimum: 2, maximum: 4094 }, name: { type: 'string' }, interfaces: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 48 }, vlans: { type: 'array', items: { type: 'integer', minimum: 2, maximum: 4094 }, minItems: 1, maxItems: 32 }, description: { type: 'string' }, interface: { type: 'string' }, image: { type: 'string' }, url: { type: 'string' }, md5: { type: 'string' }, minutes: { type: 'integer', minimum: 5, maximum: 1440 } }, additionalProperties: false } }, required: ['device', 'type', 'params', 'reason'], additionalProperties: false } },
  { name: 'propose_change', description: 'Record a configuration change plan for human review and approval. It is NOT executed. Include exact commands, prechecks and rollback.', input_schema: { type: 'object', properties: { device: { type: 'string' }, title: { type: 'string' }, reason: { type: 'string' }, commands: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 60 }, rollback: { type: 'array', items: { type: 'string' } }, prechecks: { type: 'array', items: { type: 'string' } }, risk: { type: 'string', enum: ['low', 'medium', 'high'] } }, required: ['device', 'title', 'reason', 'commands', 'rollback'], additionalProperties: false } },
];
S.assertSchemas(TOOLS, 'netops ai');   // a rule the checker cannot enforce is refused at load, never silently ignored

/* minimal JSON-schema check for the shapes above (types, enums, ranges, required, no extra keys) */
// the model's arguments against the tool's schema - the shared checker (util/ai-schema.js, the same file as IT Asset Management's)
const check = (schema, v, at = 'input') => S.checkInput(schema, v, at);

// minimum portal role per tool = the role of the matching API route (POST /netops/devices/:id/cli, POST /netops/changes)
const TOOL_ROLE = { show_commands: 'operator', propose_change: 'operator', propose_task: 'operator' };
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const toolAllowed = (name, role) => !TOOL_ROLE[name] || (RANK[role] || 0) >= RANK[TOOL_ROLE[name]];

function isPrivate(ip) { return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip); }

function createAI({ config, log, tools, sdk, state } = {}) {
  const L = log || { info() {}, warn() {}, error() {} }, cfg = (config && config.netops && config.netops.ai) || {};
  const T = tools, chats = state ? state.collection('netops_chats') : null;
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (sdk) return sdk; if (Ctor) return Ctor;
    const tries = ['@anthropic-ai/sdk', cfg.sdk_path || '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, '..', '..', 'vendor', 'node_modules', '@anthropic-ai', 'sdk'), require('path').join(__dirname, '..', 'util', 'ai-sdk-shim.js')];
    for (const p of tries) { try { const m = require(p); Ctor = require('../util/ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (run install/netops-ai-sdk)' : e.message; } }
    return null;
  }
  function apiKey() { return (config && config.secrets && config.secrets.netops && config.secrets.netops.anthropic_api_key) || process.env.ANTHROPIC_API_KEY || ''; }
  function status() {
    if (cfg.enabled === false) return { enabled: false, reason: 'AI assistant disabled in config (netops.ai.enabled)', model: cfg.model || MODEL };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model: cfg.model || MODEL };
    if (!apiKey()) return { enabled: false, reason: 'no Anthropic API key (secrets.json netops.anthropic_api_key)', model: cfg.model || MODEL };
    return { enabled: true, model: cfg.model || MODEL };
  }

  function dev(ref) { const all = T.inventory.list(), r = String(ref || '').toLowerCase(); return all.find((d) => d.id === r) || all.find((d) => d.name.toLowerCase() === r) || all.find((d) => d.ip === ref) || null; }
  function need(ref) { const d = dev(ref); if (!d) throw new Error(`unknown device "${ref}" — use list_devices`); return d; }
  function slimSnap(s, filter) {
    if (!s) return { polled: false };
    const ifs = (s.interfaces || []).filter((i) => !filter || (i.name + ' ' + (i.alias || '')).toLowerCase().includes(filter.toLowerCase()));
    const ranked = ifs.slice().sort((a, b) => (b.oper === 'down' && b.admin === 'up') - (a.oper === 'down' && a.admin === 'up') || Math.max(b.util_in || 0, b.util_out || 0) - Math.max(a.util_in || 0, a.util_out || 0));
    return { polled_at: new Date(s.at).toISOString(), ok: s.ok, sources: s.sources, errors: s.errors, reach: s.reach, system: s.system, ha: s.ha,
      interfaces: ranked.slice(0, 40).map((i) => ({ name: i.name, alias: i.alias || undefined, admin: i.admin, oper: i.oper, speed_mbps: i.speed_mbps, in_mbps: i.in_bps != null ? Math.round(i.in_bps / 1e4) / 100 : undefined, out_mbps: i.out_bps != null ? Math.round(i.out_bps / 1e4) / 100 : undefined, util_in: i.util_in, util_out: i.util_out, err_per_min: i.err_per_min || undefined, changed: i.changed })),
      interfaces_total: ifs.length, tunnels: s.tunnels, neighbors: s.neighbors, paths: s.paths,
      nac: s.nac ? { nodes: s.nac.nodes, unauthorized: s.nac.unauthorized, quarantined: s.nac.quarantined } : undefined,
      sdwan: s.sdwan ? { appliances: s.sdwan.appliances, alarms: (s.sdwan.alarms || []).slice(0, 20) } : undefined };
  }
  const SEVR = { low: 1, medium: 2, high: 3, critical: 4 };

  const run = {
    route_map: (i) => (T.routemap ? T.routemap.forAi(i) : { note: 'the route map is not available' }),
    network_overview: () => ({ sites: T.sites(), findings: T.findings().slice(0, 25), devices: T.inventory.list().length }),
    list_devices: (i) => T.inventory.list().filter((d) => (!i.site || d.site.toLowerCase().includes(i.site.toLowerCase())) && (!i.vendor || d.vendor === i.vendor)).map((d) => { const s = T.poller.snapshot(d.id); return { id: d.id, name: d.name, vendor: d.vendor, ip: d.ip, site: d.site, role: d.role, criticality: d.criticality, polled: !!s, ok: s ? s.ok : null, rtt_ms: s && s.reach ? s.reach.rtt_avg_ms : null, model: d.cli_facts ? d.cli_facts.model : undefined, ssh_ready: T.cli ? !!(T.cli.supported(d.vendor) && T.inventory.credentialSummary(d.id).ssh && T.cli.hostKey(d.id)) : false }; }),
    device_status: (i) => { const d = need(i.device); return Object.assign({ device: { id: d.id, name: d.name, vendor: d.vendor, ip: d.ip, site: d.site, role: d.role } }, slimSnap(T.poller.snapshot(d.id), i.interface_filter)); },
    findings: (i) => { const ms = SEVR[i.min_severity] || 0, dd = i.device ? need(i.device).id : null; return T.findings().filter((f) => (!i.site || f.site.toLowerCase().includes(i.site.toLowerCase())) && (!dd || f.device === dd) && SEVR[f.severity] >= ms).slice(0, 40); },
    diagnose: (i) => T.diagnose({ site: i.site, device: i.device ? need(i.device).id : undefined, target_ip: i.target_ip, symptom: i.symptom, minutes: i.minutes }),
    device_events: (i) => { const d = need(i.device); return T.evidence.deviceEvents({ ip: d.ip, host: d.name, minutes: i.minutes || 120, kind: i.kind || 'all', limit: 60 }); },
    config_changes: (i) => T.evidence.configChanges({ ip: i.device ? need(i.device).ip : undefined, hours: i.hours || 24 }),
    blocked_connections: (i) => T.evidence.blocked({ src: i.src_ip, dst: i.dst_ip, port: i.dst_port, minutes: i.minutes || 60 }),
    top_talkers: (i) => T.evidence.topTalkers({ minutes: i.minutes || 60, ip: i.ip, by: i.by || 'pair' }),
    nac_lookup: async (i) => {
      const events = await T.evidence.nacLookup({ ip: i.ip, mac: i.mac, hours: i.hours || 24 });
      const mac = String(i.mac || '').toLowerCase().replace(/[^0-9a-f]/g, ''); const nodes = [];
      for (const d of T.inventory.list().filter((x) => x.vendor === 'genian')) { const s = T.poller.snapshot(d.id); for (const n of (s && s.nac && s.nac.items) || []) if ((i.ip && n.ip === i.ip) || (mac && String(n.mac).toLowerCase().replace(/[^0-9a-f]/g, '') === mac)) nodes.push(n); }
      return { nac_nodes: nodes, events };
    },
    metric_history: (i) => T.evidence.metricHistory({ device: need(i.device).id, metric: i.metric, key: i.key || '', hours: i.hours || 24 }),
    security_review: (i) => { const list = i.device ? [need(i.device)] : T.inventory.list(); return list.map((d) => { const s = T.poller.snapshot(d.id), sec = s && s.security; return { device: d.name, vendor: d.vendor, site: d.site, checked_at: sec ? new Date(sec.at).toISOString() : null, items: sec ? sec.items : [], notes: sec ? sec.errors : ['not checked yet'] }; }).filter((x) => !i.device ? x.items.length || x.checked_at : true); },
    server_availability: async (i) => { if (!T.availability) return { note: 'availability monitoring not enabled' }; const v = await T.availability.view(), f = String(i.filter || '').toLowerCase();
      const items = v.items.filter((h) => !f || h.flags.includes(f) || h.name.toLowerCase().includes(f) || h.ip.includes(f)).slice(0, 80).map((h) => ({ name: h.name, ip: h.ip, site: h.site, service: h.group && h.group.name, role: h.role, status: h.status, for: h.duration_s != null ? Math.round(h.duration_s / 3600 * 10) / 10 + ' h' : null, availability: h.availability, days_since_restart: h.days_since_boot, unexpected_shutdowns_30d: h.unexpected_shutdowns_30d, flags: h.flags }));
      return { summary: v.summary, groups_with_issues: v.groups.filter((g) => g.issues.length).slice(0, 60), hosts: items }; },
    ping: (i) => { const d = dev(i.target); const ip = d ? d.ip : i.target; if (!net.isIP(ip) || (!d && !isPrivate(ip))) throw new Error('target must be a monitored device or a private IP address'); return T.ping(ip).then((r) => Object.assign({ target: d ? d.name : ip, ip }, r)); },
    show_commands: async (i, ctx) => {
      if (!T.cli) throw new Error('device CLI access is not available');
      const d = need(i.device), r = await T.cli.run(d.id, i.commands, { by: 'ai-network-engineer (' + (ctx.by || 'asked by ' + (ctx.user || '?')) + ')', via: 'ai' });
      return { device: r.name, prompt: r.prompt, results: r.results.map((x) => ({ command: x.command, error: x.error, output: x.output && x.output.length > 9000 ? x.output.slice(0, 9000) + '\n…[truncated — use a "| include" filter or a narrower command]' : x.output })) };
    },
    propose_task: (i, ctx) => {
      if (!T.tasks) throw new Error('approved tasks are not available');
      const d = need(i.device), p = T.tasks.propose({ device: d.id, type: i.type, params: i.params, reason: i.reason, source: 'ai', requested_by: ctx.requested_by || ctx.user || '', ticket: ctx.ticket || '' }, 'ai-network-engineer (' + (ctx.by || 'asked by ' + (ctx.user || '?')) + ')');
      if (ctx.onChange) ctx.onChange(p);
      const st = T.tasks.status(d.id);
      return { recorded: p.id, title: p.title, status: p.status, can_run: st.enabled, run_blocker: st.enabled ? undefined : st.reason, note: 'Recorded for approval. An administrator who did not ask for it approves; an operator presses Run; the platform verifies and rolls back on failure. Nothing has changed yet.' };
    },
    propose_change: (i, ctx) => { const d = need(i.device); const p = T.changes.propose(Object.assign({}, i, { device: d.id, source: 'ai', requested_by: ctx.requested_by || ctx.user || '', ticket: ctx.ticket || '' }), 'ai-network-engineer (' + (ctx.by || 'asked by ' + (ctx.user || '?')) + ')'); if (ctx.onChange) ctx.onChange(p); return { recorded: p.id, status: p.status, note: 'Recorded for review. An administrator must approve it and an engineer must apply it; the SIEM does not change devices.' }; },
  };

  async function exec(block, ctx) {
    const def = TOOLS.find((t) => t.name === block.name), t0 = Date.now();
    if (!def) return { res: { type: 'tool_result', tool_use_id: block.id, content: 'unknown tool', is_error: true }, step: { tool: block.name, ok: false, ms: 0 } };
    if (!toolAllowed(block.name, ctx.role)) return { res: { type: 'tool_result', tool_use_id: block.id, content: `not allowed: ${block.name} needs the ${TOOL_ROLE[block.name]} role and this question was asked with ${ctx.role || 'no'} role. Recommend the step to the engineer instead.`, is_error: true }, step: { tool: block.name, input: block.input, ok: false, ms: 0, error: 'role' } };
    const err = check(def.input_schema, block.input);
    if (err) return { res: { type: 'tool_result', tool_use_id: block.id, content: 'invalid input: ' + err, is_error: true }, step: { tool: block.name, input: block.input, ok: false, ms: 0, error: err } };
    try {
      const out = await run[block.name](block.input || {}, ctx);
      let text = JSON.stringify(out); if (text.length > MAX_RESULT) text = text.slice(0, MAX_RESULT) + ' …[truncated — narrow the query]';
      // device output and logs are DATA that outsiders can influence: secrets masked, framed as untrusted, flagged if they
      // look like instructions (util/ai-guard.js)
      const flags = G.injectionSignals(text); if (flags.length && ctx.flags) ctx.flags.push(...flags);
      return { res: { type: 'tool_result', tool_use_id: block.id, content: G.untrusted('tool:' + block.name, text) }, step: { tool: block.name, input: block.input, ok: true, ms: Date.now() - t0, injection_signals: flags.length ? flags : undefined } };
    } catch (e) {
      return { res: { type: 'tool_result', tool_use_id: block.id, content: G.untrusted('tool-error:' + block.name, 'error: ' + String(e.message || e).slice(0, 500)), is_error: true }, step: { tool: block.name, input: block.input, ok: false, ms: Date.now() - t0, error: G.redactSecrets(String(e.message || e)).slice(0, 200) } };
    }
  }

  async function ask({ question, conversation, user, role, system_extra, by, ticket, onChange, requested_by }) {
    role = RANK[role] != null ? role : 'analyst';
    const tools = TOOLS.filter((t) => toolAllowed(t.name, role)), system = (system_extra ? SYSTEM + '\n\n' + system_extra : SYSTEM) + '\n\n' + G.UNTRUSTED_RULE;
    const st = status(); if (!st.enabled) throw Object.assign(new Error(st.reason), { code: 503 });
    const q = String(question || '').trim(); if (!q) throw Object.assign(new Error('question required'), { code: 400 }); if (q.length > 12000) throw Object.assign(new Error('question too long'), { code: 400 });
    const Anthropic = loadSdk();
    const client = new Anthropic({ apiKey: apiKey(), timeout: (cfg.timeout_s || 180) * 1000, maxRetries: 2, baseURL: cfg.base_url || undefined });
    let conv = conversation && chats ? chats.get(conversation) : null;
    if (conv && conv.user !== user) conv = null; // conversations are private to their user
    if (!conv) conv = { id: 'nc-' + crypto.randomBytes(8).toString('hex'), user: user || '', created: Date.now(), messages: [], title: q.slice(0, 80) };
    if (conv.messages.length > 160) throw Object.assign(new Error('conversation too long — start a new one'), { code: 409 });
    // cost and abuse limits before any token is spent: per person per hour / day, the platform's daily budget, the size
    const budget = G.sharedBudget({ log: L, limits: () => (config && config.ai_limits) || {} }), flags = G.injectionSignals(q);
    budget.admit(user || by || 'system', 'netops.ask', q.length);
    if (JSON.stringify(conv.messages).length > 600000) throw Object.assign(new Error('this conversation is too long for the AI - start a new conversation'), { code: 409, status: 409 });
    const now = new Date(), when = now.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    const messages = conv.messages.concat([{ role: 'user', content: `[${when}] ${q}` }]);
    const steps = []; let usage = { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 }, final = null, model = cfg.model || MODEL;
    try {
    for (let i = 0; i < MAX_STEPS; i++) {
      const params = { model, max_tokens: 16000, thinking: { type: 'adaptive' }, output_config: { effort: cfg.effort || 'high' }, system, tools, messages, cache_control: { type: 'ephemeral' } };
      if (cfg.fallbacks !== false) { params.betas = ['server-side-fallback-2026-07-01']; params.fallbacks = 'default'; }
      const resp = await (params.betas ? client.beta.messages.create(params) : client.messages.create(params));
      for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
      model = resp.model || model;
      messages.push({ role: 'assistant', content: resp.content }); // append unchanged (thinking blocks included)
      if (resp.stop_reason === 'refusal') { final = 'The AI declined this request. Rephrase it as a network troubleshooting question.'; break; }
      if (resp.stop_reason === 'pause_turn') continue;
      const uses = resp.content.filter((b) => b.type === 'tool_use');
      if (resp.stop_reason === 'max_tokens' && uses.length) { final = 'The answer was cut off (too long). Ask a narrower question.'; break; }
      if (resp.stop_reason !== 'tool_use' || !uses.length) { final = resp.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim(); break; }
      const results = await Promise.all(uses.map((b) => exec(b, { user, role, by, ticket, onChange, requested_by, flags })));
      for (const r of results) steps.push(r.step);
      messages.push({ role: 'user', content: results.map((r) => r.res) });
    }
    } finally { budget.record(user || by || 'system', 'netops.ask', usage, [...new Set(flags)]); }   // tokens spent before a failure count too
    if (final === null) final = 'Stopped after ' + MAX_STEPS + ' investigation steps. The evidence gathered so far is listed below; ask a narrower follow-up.';
    conv.messages = messages; conv.updated = Date.now();
    if (chats) chats.put(conv);
    L.info('netops ai answer', { user, role, steps: steps.length, tools: steps.map((x) => x.tool + (x.ok ? '' : '!')).join(','), in: usage.input_tokens, out: usage.output_tokens, injection_signals: flags.length ? [...new Set(flags)] : undefined });
    return { answer: final, conversation: conv.id, steps, model, usage };
  }
  function conversations(user) { return chats ? chats.all((c) => c.user === user).sort((a, b) => b.updated - a.updated).slice(0, 30).map((c) => ({ id: c.id, title: c.title, updated: c.updated })) : []; }
  return { status, ask, conversations, TOOLS, SYSTEM, _check: check };
}

module.exports = { createAI, TOOLS, SYSTEM, MODEL, check, TOOL_ROLE, toolAllowed };
