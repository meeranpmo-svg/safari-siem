// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Oracle reference library for the AI Oracle DBA - a copy of Oracle's own guidance (github.com/oracle/skills, UPL 1.0),
 * fixed at one commit (oracle-ref/SOURCE.json lists every file with its SHA-256; LICENSE.txt is Oracle's licence).
 *
 *   createOracleRef({ dir?, log? }) -> { ok, source, guides(), guide(id, {pack}), select({ topic, text, question, pack, max_chars }),
 *                                       forTopic(topic) -> [{ id, title }], topicOf(findingKey) }
 *
 * - A file whose hash differs from SOURCE.json is not loaded (an edited or swapped copy is never fed to the model).
 * - select() returns the SECTIONS (split at "## ") most relevant to a finding - the guides mapped to its topic first, then
 *   words of the finding / question - within max_chars (default 24 000), at most 3 guides: never a whole library per call.
 * - Without the Diagnostics Pack confirmed, the AWR / ASH guides and any section that uses AWR, ASH, DBA_HIST_* or the
 *   tuning advisors are left out, and the answer says how many were left out - the same licence rule the AI DBA follows.
 * - The text is reference DATA for the model: the caller frames it with ai-guard untrusted(); nothing here is executed.
 *   Oracle's guides contain statements that change a database (ALTER SYSTEM, DROP ...): the tuning engine's FORBIDDEN
 *   check and four-eyes approval apply to whatever the model proposes, wherever it read it.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DIR = path.join(__dirname, 'oracle-ref');
const LICENSED_GUIDES = new Set(['performance/awr-reports', 'performance/ash-analysis']);
const LICENSED_TEXT = /\bDBA_HIST_|V\$ACTIVE_SESSION_HISTORY|GV\$ACTIVE_SESSION_HISTORY|\bAWR\b|\bASH\b|DBMS_WORKLOAD_REPOSITORY|DBMS_SQLTUNE|DBMS_ADVISOR|SQL Tuning Advisor|SQL Access Advisor|\bADDM\b/;
const DG = 'data-guard/references/';
// finding topic -> guides, most relevant first (tuning finding keys and AI DBA duty kinds)
const TOPICS = {
  'plan-change': ['performance/explain-plan', 'performance/optimizer-stats'],
  'stale-statistics': ['performance/optimizer-stats', 'performance/explain-plan'],
  'long-query': ['monitoring/top-sql-queries', 'performance/explain-plan', 'performance/index-strategy'],
  'temp-undo': ['admin/undo-management', 'monitoring/space-management'],
  memory: ['performance/memory-tuning'],
  'resource-limit': ['admin/user-management', 'performance/memory-tuning'],
  'wait-event': ['performance/wait-events'],
  'wait-lfs': ['performance/wait-events', 'admin/redo-log-management'],
  'wait-dfsr': ['performance/wait-events', 'performance/index-strategy', 'performance/explain-plan'],
  'dg-transport': [DG + '04_TRANSPORT_TROUBLESHOOTING', DG + '05_ASYNC_TRANSPORT_ADVANCED', DG + '06_SYNC_TRANSPORT_PERFORMANCE'],
  'dg-apply': [DG + '07_APPLY_TROUBLESHOOTING', DG + '08_APPLY_TUNING_SIRA_MIRA', DG + '03_OVERVIEW_AND_LAG_MODEL'],
  'dg-lag': [DG + '03_OVERVIEW_AND_LAG_MODEL', DG + '07_APPLY_TROUBLESHOOTING', DG + '04_TRANSPORT_TROUBLESHOOTING'],
  'dg-gap': [DG + '04_TRANSPORT_TROUBLESHOOTING', DG + '09_SQL_QUERY_COOKBOOK'],
  'dg-broker': [DG + '02_BROKER_FIXED_VIEW_ROUTING', DG + '10_DECISION_TREES_AND_PLAYBOOKS'],
  'dg-config': [DG + '00_DG_RESOURCE_INDEX', DG + '03_OVERVIEW_AND_LAG_MODEL', DG + '10_DECISION_TREES_AND_PLAYBOOKS'],
  'dg-standby-logs': [DG + '06_SYNC_TRANSPORT_PERFORMANCE', 'admin/redo-log-management'],
  'tablespace-usage': ['monitoring/space-management'],
  'backup-status': ['backup-recovery/rman-basics', 'backup-recovery/rman-overview'],
  'fra-usage': ['backup-recovery/rman-overview', 'monitoring/space-management'],
  'redo-status': ['admin/redo-log-management'],
  'instance-down': ['monitoring/alert-log-analysis', 'monitoring/health-monitor'],
  'alert-log': ['monitoring/alert-log-analysis'],
  'cpu-bound': ['monitoring/top-sql-queries', 'performance/wait-events'],
  'wait-dominated': ['performance/wait-events'],
  blocking: ['performance/wait-events'],
  sessions: ['admin/user-management'],
  audit: ['security/auditing', 'security/privilege-management'],
  privileges: ['security/privilege-management'],
  encryption: ['security/encryption'],
};
// the AI DBA duty desk's finding kinds (duty/app-adapters.js DBA_ADVICE)
const DUTY_ALIAS = { 'host-cpu': 'cpu-bound', 'dataguard-lag': 'dg-lag', 'session-count': 'sessions', 'blocked-session': 'blocking', 'alertlog-tail': 'alert-log', 'status-unknown': 'instance-down', 'logon-failed': 'audit', 'invalid-objects': 'alert-log' };
const STOP = new Set('this that with from have will your when what which their there these those into than then them been were does done only also more most such very over under about after before should could would oracle database the and for are not you can all any use using used each other must'.split(' '));
const words = (t) => [...new Set(String(t || '').toLowerCase().match(/[a-z0-9$_#-]{4,}/g) || [])].filter((w) => !STOP.has(w)).slice(0, 60);
const slug = (t) => String(t).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);

function topicOf(key) {
  const k = String(key || '').toLowerCase();
  if (TOPICS[k]) return k;
  if (DUTY_ALIAS[k]) return DUTY_ALIAS[k];
  const [a, b] = k.split(':');
  if (a === 'plan') return 'plan-change';
  if (a === 'stats') return 'stale-statistics';
  if (a === 'long') return 'long-query';
  if (a === 'temp' || a === 'undo') return 'temp-undo';
  if (a === 'pga' || a === 'sga') return 'memory';
  if (a === 'limit') return 'resource-limit';
  if (a === 'wait') return b === 'lfs' ? 'wait-lfs' : b === 'dfsr' ? 'wait-dfsr' : 'wait-event';
  if (a === 'dg') {
    if (/^(dest|deferred|gap|sbgap)$/.test(b)) return b === 'gap' || b === 'sbgap' ? 'dg-gap' : 'dg-transport';
    if (b === 'mrp' || b === 'idle') return 'dg-apply';
    if (b === 'lag') return 'dg-lag';
    if (b === 'broker' || b === 'err') return 'dg-broker';
    if (b === 'srl') return 'dg-standby-logs';
    return 'dg-config';
  }
  return '';
}

function createOracleRef({ dir = DIR, log } = {}) {
  const warn = (m, d) => { try { if (log && log.every) log.every('oracle-ref:' + m, 3600000, 'warn', m, d); else if (log && log.warn) log.warn(m, d); } catch (e) { /* logging must never stop the library */ } };
  let source = null; const G = new Map();
  try { source = JSON.parse(fs.readFileSync(path.join(dir, 'SOURCE.json'), 'utf8')); } catch (e) { warn('oracle reference library not readable - the AI DBA works without it', { error: e.message }); }
  for (const [rel, sum] of Object.entries((source && source.files) || {})) {
    if (!/^[a-z0-9_/-]+\.md$/i.test(rel) || rel.includes('..')) { warn('oracle reference: unexpected file name skipped', { file: rel }); continue; }
    let buf; try { buf = fs.readFileSync(path.join(dir, rel)); } catch (e) { warn('oracle reference: file missing', { file: rel }); continue; }
    if (crypto.createHash('sha256').update(buf).digest('hex') !== sum) { warn('oracle reference: file does not match SOURCE.json - not loaded', { file: rel }); continue; }
    const text = buf.toString('utf8'), id = rel.replace(/\.md$/, ''), title = ((/^#\s+(.+)$/m.exec(text) || [])[1] || id).trim();
    const sections = []; let cur = { heading: 'Overview', lines: [] };
    for (const line of text.split('\n')) {
      if (/^##\s+/.test(line)) { if (cur.lines.join('').trim()) sections.push(cur); cur = { heading: line.replace(/^##\s+/, '').trim(), lines: [] }; } else if (!/^#\s+/.test(line)) cur.lines.push(line);
    }
    if (cur.lines.join('').trim()) sections.push(cur);
    G.set(id, { id, title, licensed: LICENSED_GUIDES.has(id), sections: sections.map((x) => {
      const body = x.lines.join('\n').trim();
      return { id: id + '#' + slug(x.heading), heading: x.heading, text: body, licensed: LICENSED_GUIDES.has(id) || LICENSED_TEXT.test(x.heading + '\n' + body), lc: (x.heading + '\n' + body).toLowerCase() };
    }) });
  }
  const meta = () => (source ? { repository: source.repository, commit: source.commit, committed: source.committed, licence: source.licence, guides: G.size } : null);

  function select({ topic, key, text, question, pack = false, max_chars = 24000, max_guides = 3, max_sections = 8 } = {}) {
    const t = topic || topicOf(key), mapped = (TOPICS[t] || []).filter((g) => G.has(g)), terms = words([text, question].join(' '));
    const cap = Math.max(2000, Math.min(40000, Number(max_chars) || 24000)), out = [], excluded = { licence: 0 };
    if (!G.size || (!mapped.length && !terms.length)) return { topic: t, sections: [], excluded, chars: 0 };
    const scored = [];
    for (const g of G.values()) {
      const pri = mapped.indexOf(g.id);
      for (const sec of g.sections) {
        let sc = pri >= 0 ? 6 - pri : 0;
        for (const w of terms) { if (sec.heading.toLowerCase().includes(w)) sc += 3; const n = sec.lc.split(w).length - 1; sc += Math.min(n, 3); }
        if (/^(sources|see also|references|related skills?)\b/i.test(sec.heading)) continue;   // link lists, not guidance
        if (pri < 0 && sc < 6) continue;                          // an unmapped guide needs several matching words to qualify
        if (pri >= 0 && sc <= 6 - pri && terms.length && /^(overview|introduction|best practices|common mistakes|oracle version notes|sources|see also|references)/i.test(sec.heading)) sc -= 1;
        if (!pack && sec.licensed) { excluded.licence++; continue; }
        scored.push({ g, sec, sc });
      }
    }
    scored.sort((a, b) => b.sc - a.sc || a.sec.id.localeCompare(b.sec.id));
    const used = new Set(); let chars = 0;
    for (const { g, sec } of scored) {
      if (!used.has(g.id) && used.size >= max_guides) continue;
      let body = sec.text;
      if (body.length > 6000) body = body.slice(0, body.lastIndexOf('\n\n', 6000) > 2000 ? body.lastIndexOf('\n\n', 6000) : 6000) + '\n[... section shortened]';
      const block = `### [ref:${sec.id}] ${g.title} - ${sec.heading}\n${body}\n`;
      if (chars + block.length > cap) continue;
      out.push({ id: sec.id, guide: g.id, title: g.title, heading: sec.heading, text: block }); chars += block.length; used.add(g.id);
      if (chars > cap - 1500 || out.length >= max_sections) break;
    }
    return { topic: t, sections: out, excluded, chars };
  }

  return {
    ok: G.size > 0, source: meta(), topicOf, select,
    guides: () => [...G.values()].map((g) => ({ id: g.id, title: g.title, sections: g.sections.length, licensed: g.licensed })).sort((a, b) => a.id.localeCompare(b.id)),
    guide(id, { pack = false } = {}) {
      const g = G.get(String(id || '')); if (!g) return null;
      return { id: g.id, title: g.title, licensed: g.licensed, sections: g.sections.map((x) => ({ id: x.id, heading: x.heading, licensed: x.licensed, text: x.licensed && !pack ? null : x.text })) };
    },
    forTopic: (topic) => (TOPICS[topicOf(topic)] || []).filter((g) => G.has(g)).map((g) => ({ id: g, title: G.get(g).title, licensed: G.get(g).licensed })),
  };
}

module.exports = { createOracleRef, topicOf, TOPICS, LICENSED_TEXT };
