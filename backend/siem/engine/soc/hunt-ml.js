// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Threat Hunting machine-learning hunts (POST {P}/soc/hunt/ml, investigate.js mlHunts()) - unsupervised statistics over the SIEM's
 * own events that turn into hunt leads. Every lead is scored with its features named and carries the query that shows its events,
 * so an analyst can check it in one click. Leads, not detections: nothing is raised, blocked or changed from here.
 *   dga        domains queried in 24 h scored for looking machine-generated: Shannon entropy of the registered label (>= 3.5 bits
 *              per character: +35), length (>= 15: +15), digits mixed into letters (+15), a run of 5+ consonants (+15), rare - asked
 *              by one or two hosts (+20). 50 or more is a lead. Known content / CDN suffixes are skipped (CDN_OK).
 *   lineage    process launches (parent -> child) in 24 h against the same pairs over 7 days across every host: a pair seen on at
 *              most two hosts in the week is rare (+30); an Office / browser / PDF reader / mail client starting a shell or script
 *              host (+40); a living-off-the-land binary as the child (+20); started by a service account or SYSTEM-like name is
 *              not scored lower or higher. 50 or more is a lead.
 *   fanout     successful logons in the last 24 h: an account reaching 5+ distinct hosts within one hour, and at least 3 times the
 *              most it reached in any hour of the 7 days before - the shape of lateral movement (or a new admin task: say which).
 */
const H = 3600000, DAY = 24 * H;
const CDN_OK = /(^|\.)(microsoft|windows|office|office365|live|msftncsi|azure|azureedge|akamai(edge|ized)?|cloudfront|amazonaws|googleapis|gstatic|google|apple|icloud|digicert|letsencrypt|sentry|trafficmanager|edgekey|edgesuite|fastly|cdn77|cloudflare)\.(com|net|org)$/i;
const SHELL = /(^|\\|\/)(cmd|powershell|pwsh|wscript|cscript|mshta|bash|sh)(\.exe)?$/i;
const OFFICE = /(^|\\|\/)(winword|excel|powerpnt|outlook|onenote|msaccess|acrord32|acrobat|foxitreader|chrome|msedge|firefox|iexplore|thunderbird)(\.exe)?$/i;
const LOLBIN = /(^|\\|\/)(rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|msbuild|installutil|regasm|regsvcs|cmstp|odbcconf|forfiles|schtasks|at)(\.exe)?$/i;
const base = (p) => String(p || '').split(/[\\/]/).pop().toLowerCase();
function entropy(s) { const m = new Map(); for (const ch of s) m.set(ch, (m.get(ch) || 0) + 1); let e = 0; for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p); } return e; }
function label(domain) {
  const parts = String(domain || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (parts.length < 2) return parts[0] || '';
  const sld2 = ['com', 'net', 'org', 'gov', 'edu', 'co', 'ac'];   // example.com.sa: the label before the two-part suffix
  return parts.length >= 3 && sld2.includes(parts[parts.length - 2]) ? parts[parts.length - 3] : parts[parts.length - 2];
}

function dga(rows) {   // rows: [{domain, n, hosts}]
  const out = [];
  for (const r of rows) {
    const d = String(r.domain || '').toLowerCase(); if (!d || CDN_OK.test(d) || /\.(arpa|local|lan|internal)$/.test(d)) continue;
    const l = label(d); if (l.length < 6) continue;
    const why = [], add = (p, f, t) => why.push({ points: p, factor: f, reason: t }), e = entropy(l);
    if (e >= 3.5) add(35, 'entropy', 'random-looking name: ' + e.toFixed(2) + ' bits per character');
    if (l.length >= 15) add(15, 'length', l.length + ' characters');
    if (/[a-z]/.test(l) && /\d/.test(l) && /\d[a-z]|[a-z]\d/.test(l)) add(15, 'digits', 'digits mixed into letters');
    if (/[bcdfghjklmnpqrstvwxz]{5,}/.test(l)) add(15, 'consonants', 'a run of 5+ consonants');
    if (r.hosts != null && r.hosts <= 2) add(20, 'rare', 'asked by ' + r.hosts + ' host(s)');
    const score = Math.min(100, why.reduce((a, w) => a + w.points, 0));
    if (score >= 50) out.push({ domain: d, label: l, queries: r.n, hosts: r.hosts, score, why, q: 'dns_query:' + JSON.stringify(d) });
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 30);
}

function lineage(recent, week) {   // events: {host, process, parent_process, user}
  const hostsOf = new Map();
  for (const e of week) { if (!e.process || !e.parent_process) continue; const k = base(e.parent_process) + '>' + base(e.process); (hostsOf.get(k) || hostsOf.set(k, new Set()).get(k)).add(String(e.host || '').toLowerCase()); }
  const seen = new Map();
  for (const e of recent) {
    if (!e.process || !e.parent_process) continue;
    const k = base(e.parent_process) + '>' + base(e.process), x = seen.get(k) || seen.set(k, { parent: base(e.parent_process), child: base(e.process), n: 0, hosts: new Set(), users: new Set(), sample: e }).get(k);
    x.n++; x.hosts.add(String(e.host || '')); if (e.user) x.users.add(e.user);
  }
  const out = [];
  for (const [k, x] of seen) {
    const wk = hostsOf.get(k), why = [], add = (p, f, t) => why.push({ points: p, factor: f, reason: t });
    if (!wk || wk.size <= 2) add(30, 'rare', 'seen on ' + (wk ? wk.size : 0) + ' host(s) in 7 days across the estate');
    if (OFFICE.test(x.parent) && SHELL.test(x.child)) add(40, 'office to shell', x.parent + ' started ' + x.child + ' - how macro and document exploits run code');
    if (LOLBIN.test(x.child)) add(20, 'living off the land', x.child + ' is a Windows tool attackers use to run or fetch code');
    const score = Math.min(100, why.reduce((a, w) => a + w.points, 0));
    if (score >= 50) out.push({ parent: x.parent, child: x.child, launches: x.n, hosts: [...x.hosts].slice(0, 5), users: [...x.users].slice(0, 5), score, why,
      q: 'parent_process:*' + x.parent + ' AND process:*' + x.child });
  }
  return out.sort((a, b) => b.score - a.score).slice(0, 30);
}

function fanout(logons, now) {   // successful logons: {ts, user, host}
  const by = new Map();
  for (const e of logons) { const u = String(e.user || '').toLowerCase(); if (!u || !e.host || /\$$/.test(u)) continue; (by.get(u) || by.set(u, []).get(u)).push({ t: e.ts, h: String(e.host).toLowerCase() }); }
  const out = [];
  for (const [u, L] of by) {
    const hourly = new Map(); for (const x of L) { const k = Math.floor(x.t / H); (hourly.get(k) || hourly.set(k, new Set()).get(k)).add(x.h); }
    let peak = null, base7 = 0;
    for (const [k, s] of hourly) { const at = k * H; if (at >= now - DAY) { if (!peak || s.size > peak.hosts.size) peak = { at, hosts: s }; } else if (at >= now - 8 * DAY) base7 = Math.max(base7, s.size); }
    if (!peak || peak.hosts.size < 5 || peak.hosts.size < 3 * Math.max(1, base7)) continue;
    out.push({ user: u, hosts: peak.hosts.size, hour: new Date(peak.at).toISOString(), usual_max: base7, sample_hosts: [...peak.hosts].slice(0, 8),
      score: Math.min(100, 40 + 5 * peak.hosts.size), why: 'logged on to ' + peak.hosts.size + ' hosts within one hour; at most ' + base7 + ' in any hour of the 7 days before - lateral movement, or a new admin task to confirm',
      q: 'user:' + JSON.stringify(u) + ' AND category:authentication AND outcome:success' });
  }
  return out.sort((a, b) => b.hosts - a.hosts).slice(0, 20);
}

module.exports = { dga, lineage, fanout, entropy, label };
