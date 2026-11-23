// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * DFIR machine learning - explainable detectors over one entity's timeline, and case similarity. Pure functions: the same inputs
 * always give the same findings, every finding says which events and which feature made it, and each carries the ATT&CK technique
 * it suggests. Indicators for the investigator, not proof - a finding is a place to look.
 *
 *   beacons(ev)        command-and-control beaconing: contacts to one destination whose inter-arrival times are regular
 *                      (coefficient of variation <= 0.25 over >= 6 contacts, median period 10 s - 6 h). Jitter is reported, so
 *                      a "jittered" beacon reads as such. A destination reached by many hosts of the estate on the same period
 *                      is usually software updating - the page says to check the destination before calling it C2.  T1071 / T1573
 *   commands(ev)       command lines scored on features: encoded PowerShell, a download cradle, a living-off-the-land binary
 *                      used to run or fetch code, an Office / mail / PDF / browser process starting a shell, high character
 *                      entropy on a long line (obfuscation), and extreme length. Each feature is named with its points.
 *   parentChild(ev)    process pairs (parent -> child) seen once in the window while the entity runs many - rare pairs whose child
 *                      is a shell or script host are listed first.
 *   lateral(ev)        network / remote-desktop logons (type 3 / 10, or remote protocols) from one internal source to >= 3
 *                      distinct hosts within an hour - the fan-out of lateral movement.                                T1021
 *   techniques(f)      the ATT&CK techniques the findings suggest, with how many findings point at each.
 *   enrich(ev, out)    adds the four detectors to analyse()'s result and their points to the itemised attention score.
 *   similar(target, cases)  "cases like this one": weighted Jaccard over shared entities, detection rules, IOCs, ATT&CK techniques
 *                      and incident type, with the shared items named - and for each closed match its resolution and how long it
 *                      took, so an analyst sees how a similar case ended. Never a reason to close a case by itself.
 */
const MIN = 60e3, H = 3600e3;
const SHELL = /(^|[\\/])(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bash|sh)(\.exe)?$/i;
const OFFICE = /(^|[\\/])(winword|excel|powerpnt|outlook|onenote|msaccess|acrord32|acrobat|foxitreader|chrome|msedge|firefox|iexplore|teams)(\.exe)?$/i;
const FEATURES = [
  [/\s-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|frombase64string/i, 30, 'encoded PowerShell', 'T1059.001'],
  [/(invoke-webrequest|\biwr\b|downloadstring|downloadfile|net\.webclient|start-bitstransfer|certutil(\.exe)?\s+[^\n]*-urlcache|bitsadmin(\.exe)?\s+[^\n]*\/transfer|curl(\.exe)?\s+[^\n]*https?:|wget\s+[^\n]*https?:)/i, 25, 'download cradle', 'T1105'],
  [/(^|[\\/\s])(mshta|regsvr32|rundll32|installutil|msbuild|cmstp|wmic)(\.exe)?\s+[^\n]*(https?:|javascript:|scrobj|\/i:|process\s+call\s+create|\.sct\b|,\s*#?\d)/i, 25, 'living-off-the-land binary running code', 'T1218'],
  [/(-w(indowstyle)?\s+h(idden)?|-nop(rofile)?\b|-ep\s+bypass|-executionpolicy\s+bypass)/i, 10, 'hidden / policy-bypass PowerShell', 'T1059.001'],
  [/(vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete|bcdedit\s+[^\n]*recoveryenabled\s+no)/i, 35, 'backup / shadow copy deletion', 'T1490'],
  [/(sekurlsa|lsadump|procdump[^\n]*lsass|comsvcs(\.dll)?[^\n]*minidump)/i, 35, 'credential dumping', 'T1003'],
];
const lc = (s) => String(s == null ? '' : s).toLowerCase();
const median = (a) => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const internal = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80:|fc|fd)/i.test(String(ip || ''));
function entropy(s) { const m = new Map(); for (const c of s) m.set(c, (m.get(c) || 0) + 1); let h = 0; for (const n of m.values()) { const p = n / s.length; h -= p * Math.log2(p); } return h; }
const dstOf = (e) => e.dns_query ? 'dns:' + lc(e.dns_query) : e.url ? 'url:' + lc(String(e.url).replace(/^https?:\/\/([^/:]+).*$/i, '$1')) : e.dst_ip ? 'ip:' + e.dst_ip : '';

function beacons(ev) {
  const by = new Map();
  for (const e of ev) if (['network', 'dns', 'web'].includes(e.lane)) { const d = dstOf(e); if (d) (by.get(d) || by.set(d, []).get(d)).push(e.t); }
  const out = [];
  for (const [dst, ts0] of by) {
    const ts = [...new Set(ts0)].sort((a, b) => a - b); if (ts.length < 6) continue;
    const gaps = []; for (let i = 1; i < ts.length; i++) gaps.push(ts[i] - ts[i - 1]);
    const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length, sd = Math.sqrt(gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / gaps.length), cv = mean ? sd / mean : 1, period = median(gaps);
    if (cv > 0.25 || period < 10e3 || period > 6 * H) continue;
    const ip = dst.startsWith('ip:') ? dst.slice(3) : null;
    out.push({ destination: dst.replace(/^(ip|dns|url):/, ''), kind: dst.split(':')[0], contacts: ts.length, period_s: Math.round(period / 1000), jitter_pct: Math.round(cv * 100), from: ts[0], to: ts[ts.length - 1],
      external: ip ? !internal(ip) : true, technique: 'T1071', why: ts.length + ' contacts every ~' + fmtS(period / 1000) + ' (jitter ' + Math.round(cv * 100) + '%)' });
  }
  return out.sort((a, b) => (b.external - a.external) || a.jitter_pct - b.jitter_pct || b.contacts - a.contacts).slice(0, 10);
}
function fmtS(s) { return s < 90 ? Math.round(s) + ' s' : s < 5400 ? Math.round(s / 60) + ' min' : (s / 3600).toFixed(1) + ' h'; }

function commands(ev) {
  const seen = new Map();
  for (const e of ev) {
    if (e.lane !== 'execution') continue;
    const cl = String(e.cmdline || ''), proc = String(e.process || ''), par = String(e.parent_process || ''); if (!cl && !proc) continue;
    const feats = [];
    for (const [re, pts, name, tech] of FEATURES) if (re.test(cl)) feats.push({ points: pts, feature: name, technique: tech });
    if (OFFICE.test(par) && SHELL.test(proc)) feats.push({ points: 25, feature: 'started by ' + par.split(/[\\/]/).pop() + ' (a document, mail or browser process starting a shell)', technique: 'T1204' });
    const body = cl.replace(/^\S+\s*/, '');
    if (body.length >= 80) { const h = entropy(body); if (h >= 5.2) feats.push({ points: 15, feature: 'high character entropy ' + h.toFixed(1) + ' bits (obfuscated)', technique: 'T1027' }); }
    if (cl.length > 1000) feats.push({ points: 10, feature: 'command line of ' + cl.length + ' characters', technique: 'T1027' });
    if (!feats.length) continue;
    const k = lc(proc) + '|' + cl.slice(0, 400), cur = seen.get(k);
    if (cur) { cur.count++; cur.last = e.t; continue; }
    seen.set(k, { process: proc, parent: par, cmdline: cl.slice(0, 600), host: e.host || '', user: e.user || '', first: e.t, last: e.t, count: 1, features: feats, score: Math.min(100, feats.reduce((s, f) => s + f.points, 0)) });
  }
  return [...seen.values()].sort((a, b) => b.score - a.score || a.first - b.first).slice(0, 20);
}

function parentChild(ev) {
  const m = new Map();
  for (const e of ev) if (e.lane === 'execution' && e.process && e.parent_process) { const k = lc(e.parent_process).split(/[\\/]/).pop() + ' -> ' + lc(e.process).split(/[\\/]/).pop(); const r = m.get(k) || m.set(k, { pair: k, count: 0, first: e.t, shell: SHELL.test(e.process) }).get(k); r.count++; }
  if (m.size < 5) return [];
  return [...m.values()].filter((r) => r.count === 1).sort((a, b) => b.shell - a.shell || a.first - b.first).slice(0, 15);
}

function lateral(ev) {
  const auth = ev.filter((e) => e.lane === 'auth' && e.src_ip && internal(e.src_ip) && e.host && (/^(3|10)$/.test(String((e.fields || {}).logon_type || (e.fields || {}).LogonType || '')) || /rdp|smb|winrm|ssh|psexec|wmi/i.test(String(e.proto || '') + ' ' + String(e.action || '')))
    && !/fail/i.test(String(e.outcome || '')));
  const by = new Map(); for (const e of auth) (by.get(e.src_ip) || by.set(e.src_ip, []).get(e.src_ip)).push(e);
  const out = [];
  for (const [src, L] of by) {
    L.sort((a, b) => a.t - b.t);
    let best = null;
    for (let i = 0; i < L.length; i++) {
      const hosts = new Map(); for (let j = i; j < L.length && L[j].t - L[i].t <= H; j++) if (!hosts.has(lc(L[j].host))) hosts.set(lc(L[j].host), { host: L[j].host, at: L[j].t, user: L[j].target_user || L[j].user || '' });
      if (hosts.size >= 3 && (!best || hosts.size > best.length)) best = [...hosts.values()];
    }
    if (best) out.push({ source: src, hosts: best, accounts: [...new Set(best.map((h) => h.user).filter(Boolean))], minutes: Math.round((best[best.length - 1].at - best[0].at) / MIN), technique: 'T1021',
      why: src + ' logged on to ' + best.length + ' hosts within ' + Math.max(1, Math.round((best[best.length - 1].at - best[0].at) / MIN)) + ' min' });
  }
  return out.sort((a, b) => b.hosts.length - a.hosts.length).slice(0, 10);
}

const TNAME = { T1071: 'Application layer protocol (C2)', 'T1059.001': 'PowerShell', T1105: 'Ingress tool transfer', T1218: 'System binary proxy execution', T1490: 'Inhibit system recovery', T1003: 'OS credential dumping', T1204: 'User execution', T1027: 'Obfuscated files or information', T1021: 'Remote services' };
function techniques(f) {
  const m = new Map(), add = (id) => m.set(id, (m.get(id) || 0) + 1);
  for (const b of f.beacons || []) add(b.technique);
  for (const c of f.commands || []) for (const x of new Set(c.features.map((y) => y.technique))) add(x);
  for (const l of f.lateral || []) add(l.technique);
  return [...m].map(([id, n]) => ({ id, name: TNAME[id] || id, findings: n })).sort((a, b) => b.findings - a.findings);
}

function enrich(ev, out) {
  out.beacons = beacons(ev); out.commands = commands(ev); out.rare_pairs = parentChild(ev); out.lateral = lateral(ev);
  out.techniques = techniques(out);
  const add = (pts, why) => { if (pts > 0) { out.reasons.push({ points: pts, why }); out.score += pts; } };
  const xb = out.beacons.filter((b) => b.external);
  if (xb.length) add(Math.min(25, 15 + 5 * (xb.length - 1)), xb.length + ' regular beacon(s) to an external destination (' + xb.slice(0, 2).map((b) => b.destination + ' every ' + fmtS(b.period_s)).join(', ') + ')');
  const top = out.commands[0]; if (top && top.score >= 25) add(Math.min(25, Math.round(top.score / 2)), 'suspicious command line: ' + top.features.map((x) => x.feature).join(', '));
  if (out.lateral.length) add(Math.min(20, 10 + 2 * (out.lateral[0].hosts.length - 3)), 'lateral movement fan-out: ' + out.lateral[0].why);
  const rs = out.rare_pairs.filter((r) => r.shell).length; if (rs) add(Math.min(10, 5 * rs), rs + ' rare parent -> shell process pair(s)');
  out.score = Math.min(100, out.score);
  return out;
}

// ---------- case similarity
const W = { entities: 3, rules: 2, iocs: 4, techniques: 2, type: 1 };
function jac(a, b) { if (!a.size && !b.size) return { j: 0, shared: [] }; const shared = [...a].filter((x) => b.has(x)); return { j: shared.length / (a.size + b.size - shared.length), shared }; }
function similar(target, cases, opts = {}) {
  const T = { entities: new Set(target.entities || []), rules: new Set(target.rules || []), iocs: new Set(target.iocs || []), techniques: new Set(target.techniques || []), type: new Set(target.type ? [target.type] : []) };
  const out = [];
  for (const c of cases) {
    if (c.id === target.id) continue;
    const C = { entities: new Set(c.entities || []), rules: new Set(c.rules || []), iocs: new Set(c.iocs || []), techniques: new Set(c.techniques || []), type: new Set(c.type ? [c.type] : []) };
    let num = 0, den = 0; const why = [];
    for (const k of Object.keys(W)) {
      if (!T[k].size && !C[k].size) continue;
      const r = jac(T[k], C[k]); num += W[k] * r.j; den += W[k];
      if (r.shared.length) why.push({ on: k, shared: r.shared.slice(0, 5) });
    }
    if (!den || !why.length) continue;
    const score = Math.round(num / den * 100);
    if (score < (opts.min || 15)) continue;
    out.push({ id: c.id, title: c.title, status: c.status, severity: c.severity, resolution: c.resolution || '', created: c.created, closed: c.closed || 0,
      hours_to_close: c.closed ? Math.round((c.closed - c.created) / H * 10) / 10 : null, similarity: score, why });
  }
  return out.sort((a, b) => b.similarity - a.similarity || b.created - a.created).slice(0, opts.limit || 8);
}

module.exports = { beacons, commands, parentChild, lateral, techniques, enrich, similar, entropy, TNAME };
