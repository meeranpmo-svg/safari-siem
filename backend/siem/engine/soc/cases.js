// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Cases — created from alerts; status workflow, tasks (from playbooks), timeline, evidence, SLA.
 *
 *   createCases({ state, alerts, playbooks, log, now, sla })
 *     → { create(input, by), get(id), list(filter), update(id, patch, by), setStatus(id, status, by, {resolution, note, close_alerts}),
 *         assign(id, owner, by), note(id, text, by), addEvidence(id, {name, ref, kind}, by), addTask(id, {title}, by),
 *         setTask(id, taskId, done, by), addAlerts(id, alertIds, by), applyPlaybook(id, playbookId, by),
 *         approvals: { list(filter), get(id), decide(id, decision, by, comment) }, slaState(case, nowMs), SLA }
 *
 * Case object (ARCH): { id: "CASE-000123", title, severity, status, owner, alerts[], timeline[{at,by,kind,text}],
 *   evidence[{at,by,name,ref,kind}], playbook_id, tasks[{id,title,done,by,at,kind,action_id,phase}], sla:{ack_due,resolve_due},
 *   created, closed, resolution } + description, acked_at, updated, resolution_note.
 * Statuses: open → investigating → contained → eradicated → recovered → closed (forward jumps and steps back allowed;
 *   closed → investigating = reopen). Closing requires a resolution: true-positive | false-positive | benign | duplicate | other.
 *   close_alerts (default true) closes linked open alerts with the matching reason (feeds the false-positive-rate metric).
 * SLA by severity (hours; override with opts.sla / config.sla):
 *   critical(4) 1h ack / 24h resolve, high(3) 4h / 72h, medium(2) 24h / 7d, low(0-1) 72h / 30d.
 *   "ack" = first owner assignment or first status change away from open.
 * Approvals: automatable playbook tasks create approval requests (collection "approvals"):
 *   { id: "APR-000001", case_id, task_id, action_id, title, target_type, targets[], params, rationale,
 *     status: pending|approved|rejected, requested_at, requested_by, decided_at, decided_by, comment,
 *     execution: 'not-executed-by-engine' }
 *   Deciding only records the decision — this engine never executes response actions.
 */
const { WorkflowError, isClosed } = require('./alerts');
const defaultPlaybooks = require('./playbooks');

const STATUSES = ['open', 'investigating', 'contained', 'eradicated', 'recovered', 'closed'];
const RESOLUTIONS = ['true-positive', 'false-positive', 'benign', 'duplicate', 'other'];
const DEFAULT_SLA = {
  critical: { ack_h: 1, resolve_h: 24 },
  high: { ack_h: 4, resolve_h: 72 },
  medium: { ack_h: 24, resolve_h: 168 },
  low: { ack_h: 72, resolve_h: 720 },
};
const H = 3600000;

function sevName(s) { return s >= 4 ? 'critical' : s === 3 ? 'high' : s === 2 ? 'medium' : 'low'; }

function createCases(opts = {}) {
  const state = opts.state;
  if (!state) throw new Error('createCases needs state');
  const alerts = opts.alerts || null;
  const playbooks = opts.playbooks || defaultPlaybooks;
  const log = opts.log || { info() {}, warn() {}, error() {} };
  const now = opts.now || Date.now;
  const SLA = {};
  for (const k of Object.keys(DEFAULT_SLA)) SLA[k] = Object.assign({}, DEFAULT_SLA[k], (opts.sla || {})[k] || {});
  const col = state.collection('cases');
  const apr = state.collection('approvals');
  const counters = state.collection('counters');

  function next(name, prefix, width) {
    const cur = (counters.get(name) || {}).n || 0;
    const n = cur + 1;
    counters.put({ id: name, n });
    return `${prefix}-${String(n).padStart(width, '0')}`;
  }
  function slaFor(sev, created) {
    const s = SLA[sevName(sev)];
    return { ack_due: created + s.ack_h * H, resolve_due: created + s.resolve_h * H, policy: sevName(sev) };
  }
  function tl(c, by, kind, text) {
    c.timeline = c.timeline || [];
    c.timeline.push({ at: now(), by: by || 'system', kind, text: String(text || '') });
    if (c.timeline.length > 5000) c.timeline.splice(1, 1);
  }
  function must(id) {
    const c = col.get(id);
    if (!c) throw new WorkflowError(404, `case ${id} not found`);
    return c;
  }
  function markAck(c, t) { if (!c.acked_at) c.acked_at = t; }

  function createApprovals(c, tasks, by) {
    const linked = alerts ? c.alerts.map((id) => alerts.get(id)).filter(Boolean) : [];
    const ents = playbooks.entitiesFrom(linked);
    const recs = playbooks.recommendations(tasks, ents);
    const ids = [];
    for (const r of recs) {
      const a = Object.assign({ id: next('approval', 'APR', 6), case_id: c.id }, r, {
        status: 'pending', requested_at: now(), requested_by: by || 'system', decided_at: 0, decided_by: '', comment: '',
        execution: 'not-executed-by-engine',
      });
      apr.put(a);
      ids.push(a.id);
    }
    return ids;
  }

  function create(input = {}, by) {
    const alertIds = Array.isArray(input.alert_ids) ? [...new Set(input.alert_ids.map(String))] : [];
    const linked = [];
    if (alerts) for (const id of alertIds) { const a = alerts.get(id); if (!a) throw new WorkflowError(404, `alert ${id} not found`); linked.push(a); }
    for (const a of linked) if (a.case_id) throw new WorkflowError(409, `alert ${a.id} already belongs to ${a.case_id}`);
    let severity = input.severity !== undefined && input.severity !== '' ? Number(input.severity) : linked.reduce((m, a) => Math.max(m, a.severity || 0), 0);
    if (!(severity >= 0 && severity <= 4)) throw new WorkflowError(400, 'severity must be 0-4');
    severity = Math.floor(severity);
    const title = String(input.title || (linked[0] ? linked[0].summary : '') || '').trim();
    if (!title) throw new WorkflowError(400, 'title required (or give alert_ids)');
    let playbookId = input.playbook_id || '';
    if (!playbookId && input.auto_playbook !== false && linked.length) playbookId = playbooks.suggest(linked) || '';
    if (playbookId && !playbooks.get(playbookId)) throw new WorkflowError(400, `unknown playbook ${playbookId}`);
    const t = now();
    const c = {
      id: next('case', 'CASE', 6), title: title.slice(0, 300), description: String(input.description || ''), severity,
      status: 'open', owner: String(input.owner || ''), alerts: alertIds, timeline: [], evidence: [],
      playbook_id: playbookId, tasks: playbookId ? playbooks.instantiate(playbookId) : [], approvals: [],
      sla: slaFor(severity, t), created: t, updated: t, acked_at: input.owner ? t : 0, closed: 0, resolution: '', resolution_note: '',
    };
    tl(c, by, 'created', `case created${alertIds.length ? ` from ${alertIds.length} alert(s)` : ''}${playbookId ? `, playbook ${playbookId}` : ''}`);
    if (c.owner) tl(c, by, 'assign', `owner ${c.owner}`);
    col.put(c);
    if (alerts && alertIds.length) alerts.linkCase(alertIds, c.id, by);
    if (c.tasks.length) {
      const ids = createApprovals(c, c.tasks, by);
      if (ids.length) {
        return col.patch(c.id, (x) => { x.approvals = ids; tl(x, 'system', 'approval', `${ids.length} response action(s) awaiting approval (not executed by the engine)`); });
      }
    }
    return col.get(c.id);
  }

  function update(id, p = {}, by) {
    must(id);
    return col.patch(id, (c) => {
      const t = now();
      if (p.title !== undefined) { const v = String(p.title).trim(); if (!v) throw new WorkflowError(400, 'title empty'); c.title = v.slice(0, 300); tl(c, by, 'update', 'title changed'); }
      if (p.description !== undefined) { c.description = String(p.description); tl(c, by, 'update', 'description changed'); }
      if (p.severity !== undefined) {
        const s = Number(p.severity);
        if (!(s >= 0 && s <= 4)) throw new WorkflowError(400, 'severity must be 0-4');
        if (s !== c.severity) {
          tl(c, by, 'severity', `${c.severity}→${s}`);
          c.severity = Math.floor(s);
          const pol = slaFor(c.severity, c.created);
          c.sla = pol;
        }
      }
      if (p.owner !== undefined) { c.owner = String(p.owner); markAck(c, t); tl(c, by, 'assign', `owner ${c.owner || '-'}`); }
      c.updated = t;
    });
  }

  function setStatus(id, status, by, o = {}) {
    if (!STATUSES.includes(status)) throw new WorkflowError(400, `unknown case status ${status}`);
    const cur = must(id);
    if (cur.status === status) return cur;
    if (cur.status === 'closed' && status !== 'investigating') throw new WorkflowError(409, 'a closed case can only be reopened to investigating');
    let resolution = '';
    if (status === 'closed') {
      resolution = String(o.resolution || '');
      if (!RESOLUTIONS.includes(resolution)) throw new WorkflowError(400, `closing needs resolution: ${RESOLUTIONS.join(' | ')}`);
    }
    const t = now();
    const c = col.patch(id, (x) => {
      const from = x.status;
      x.status = status;
      markAck(x, t);
      if (status === 'closed') { x.closed = t; x.resolution = resolution; x.resolution_note = String(o.note || ''); }
      else if (from === 'closed') { x.closed = 0; x.resolution = ''; }
      x.updated = t;
      tl(x, by, 'status', `${from}→${status}${resolution ? ` (${resolution})` : ''}${o.note ? `: ${o.note}` : ''}`);
    });
    if (status === 'closed' && alerts && o.close_alerts !== false) {
      const reason = resolution === 'true-positive' ? 'true-positive' : resolution === 'false-positive' ? 'false-positive' : 'benign';
      for (const aid of c.alerts) {
        const a = alerts.get(aid);
        if (a && !isClosed(a.status)) {
          try { alerts.close(aid, reason, by, `closed with ${c.id}`); } catch (e) { log.warn('closing linked alert failed', { alert: aid, err: e.message }); }
        }
      }
    }
    return c;
  }

  function assign(id, owner, by) { return update(id, { owner }, by); }

  function note(id, text, by) {
    const tx = String(text || '').trim();
    if (!tx) throw new WorkflowError(400, 'note text is empty');
    if (tx.length > 20000) throw new WorkflowError(400, 'note too long');
    must(id);
    return col.patch(id, (c) => { tl(c, by, 'note', tx); c.updated = now(); });
  }

  function addEvidence(id, ev = {}, by) {
    const name = String(ev.name || '').trim();
    const ref = String(ev.ref || '').trim();
    if (!name || !ref) throw new WorkflowError(400, 'evidence needs name and ref (event id, search query, file hash, ticket/URL…)');
    must(id);
    return col.patch(id, (c) => {
      c.evidence = c.evidence || [];
      c.evidence.push({ at: now(), by: by || 'system', name: name.slice(0, 300), ref: ref.slice(0, 4000), kind: String(ev.kind || 'reference') });
      tl(c, by, 'evidence', name);
      c.updated = now();
    });
  }

  function addTask(id, task = {}, by) {
    const title = String(task.title || '').trim();
    if (!title) throw new WorkflowError(400, 'task title required');
    must(id);
    return col.patch(id, (c) => {
      c.tasks = c.tasks || [];
      const n = c.tasks.reduce((m, t) => Math.max(m, Number(String(t.id).replace(/\D/g, '')) || 0), 0) + 1;
      c.tasks.push({ id: `T${n}`, title: title.slice(0, 300), phase: String(task.phase || ''), kind: 'manual', action_id: '', done: false, by: '', at: 0 });
      tl(c, by, 'task', `added T${n}: ${title}`);
      c.updated = now();
    });
  }

  function setTask(id, taskId, done, by) {
    const c0 = must(id);
    if (!(c0.tasks || []).some((t) => t.id === taskId)) throw new WorkflowError(404, `task ${taskId} not found in ${id}`);
    return col.patch(id, (c) => {
      const t = c.tasks.find((x) => x.id === taskId);
      t.done = !!done; t.by = done ? (by || 'system') : ''; t.at = done ? now() : 0;
      markAck(c, now());
      tl(c, by, 'task', `${taskId} ${done ? 'done' : 'reopened'}: ${t.title}`);
      c.updated = now();
    });
  }

  function addAlerts(id, alertIds, by) {
    must(id);
    if (!Array.isArray(alertIds) || !alertIds.length) throw new WorkflowError(400, 'alert_ids[] required');
    const add = [];
    for (const aid of alertIds) {
      const a = alerts ? alerts.get(aid) : null;
      if (alerts && !a) throw new WorkflowError(404, `alert ${aid} not found`);
      if (a && a.case_id && a.case_id !== id) throw new WorkflowError(409, `alert ${aid} already belongs to ${a.case_id}`);
      add.push(String(aid));
    }
    const c = col.patch(id, (x) => {
      const fresh = add.filter((a) => !x.alerts.includes(a));
      x.alerts.push(...fresh);
      if (fresh.length) tl(x, by, 'alerts', `linked ${fresh.join(', ')}`);
      x.updated = now();
    });
    if (alerts) alerts.linkCase(add, id, by);
    return c;
  }

  function applyPlaybook(id, playbookId, by) {
    const pb = playbooks.get(playbookId);
    if (!pb) throw new WorkflowError(400, `unknown playbook ${playbookId}`);
    const c0 = must(id);
    if (c0.playbook_id === playbookId) throw new WorkflowError(409, `playbook ${playbookId} already applied`);
    const base = (c0.tasks || []).reduce((m, t) => Math.max(m, Number(String(t.id).replace(/\D/g, '')) || 0), 0);
    const tasks = playbooks.instantiate(playbookId).map((t, i) => Object.assign(t, { id: `T${base + i + 1}` }));
    let c = col.patch(id, (x) => {
      x.playbook_id = playbookId;
      x.tasks = (x.tasks || []).concat(tasks);
      tl(x, by, 'playbook', `applied ${playbookId} (${tasks.length} tasks)`);
      x.updated = now();
    });
    const ids = createApprovals(c, tasks, by);
    if (ids.length) c = col.patch(id, (x) => { x.approvals = (x.approvals || []).concat(ids); tl(x, 'system', 'approval', `${ids.length} response action(s) awaiting approval (not executed by the engine)`); });
    return c;
  }

  function slaState(c, nowMs) {
    const t = nowMs || now();
    const ackAt = c.acked_at || 0;
    const doneAt = c.closed || 0;
    return {
      policy: (c.sla && c.sla.policy) || sevName(c.severity),
      ack_due: c.sla.ack_due, resolve_due: c.sla.resolve_due,
      ack_breached: ackAt ? ackAt > c.sla.ack_due : t > c.sla.ack_due,
      resolve_breached: doneAt ? doneAt > c.sla.resolve_due : t > c.sla.resolve_due,
      ack_remaining_ms: ackAt ? 0 : c.sla.ack_due - t,
      resolve_remaining_ms: doneAt ? 0 : c.sla.resolve_due - t,
    };
  }

  /** Case as returned by the API: + sla_state, playbook_name, recommended_actions[] (approval requests; never executed). */
  function view(c, t) {
    if (!c) return null;
    const pb = c.playbook_id ? playbooks.get(c.playbook_id) : null;
    const recs = apr.all((a) => a.case_id === c.id).sort((a, b) => (a.id < b.id ? -1 : 1)).map((a) => ({
      id: a.id, title: a.title, action: a.action_id, requires_approval: true, status: a.status, task_id: a.task_id,
      target_type: a.target_type, targets: a.targets, rationale: a.rationale, decided_by: a.decided_by, execution: a.execution,
    }));
    return Object.assign({}, c, { sla_state: slaState(c, t), playbook_name: pb ? pb.name : '', recommended_actions: recs });
  }

  function list(f = {}) {
    let statuses = f.status ? String(f.status).split(',') : null;
    if (statuses && statuses.includes('all')) statuses = null;
    const q = f.q ? String(f.q).toLowerCase() : '';
    const t = now();
    const items = col.all((c) => {
      if (statuses && !statuses.some((s) => (s === 'active' ? c.status !== 'closed' : c.status === s))) return false;
      if (f.owner !== undefined && f.owner !== '' && c.owner !== (f.owner === '-' ? '' : f.owner)) return false;
      if (f.severity_min !== undefined && f.severity_min !== '' && c.severity < Number(f.severity_min)) return false;
      if (f.breached === 'true' || f.breached === true) { const s = slaState(c, t); if (!s.ack_breached && !s.resolve_breached) return false; }
      if (q && !`${c.id} ${c.title} ${c.description}`.toLowerCase().includes(q)) return false;
      return true;
    });
    const sort = String(f.sort || '-created');
    const desc = sort.startsWith('-');
    const key = ['created', 'updated', 'severity', 'id'].includes(sort.replace(/^[-+]/, '')) ? sort.replace(/^[-+]/, '') : 'created';
    items.sort((a, b) => { const c = a[key] < b[key] ? -1 : a[key] > b[key] ? 1 : 0; return desc ? -c : c; });
    const limit = Math.max(1, Math.min(500, Number(f.limit) || 100));
    const offset = Math.max(0, Number(f.offset) || 0);
    return { total: items.length, items: items.slice(offset, offset + limit).map((c) => view(c, t)) };
  }

  const approvals = {
    list(f = {}) {
      return apr.all((a) => (!f.status || a.status === f.status) && (!f.case_id || a.case_id === f.case_id))
        .sort((a, b) => b.requested_at - a.requested_at);
    },
    get: (id) => apr.get(id),
    decide(id, decision, by, comment) {
      const a = apr.get(id);
      if (!a) throw new WorkflowError(404, `approval ${id} not found`);
      if (!['approved', 'rejected'].includes(decision)) throw new WorkflowError(400, 'decision must be approved or rejected');
      if (a.status !== 'pending') throw new WorkflowError(409, `approval ${id} already ${a.status}`);
      // four-eyes: whoever asked for the response action may not decide it (approve or reject)
      if (by && a.requested_by && String(by).toLowerCase() === String(a.requested_by).toLowerCase()) throw new WorkflowError(403, `${id} was requested by ${by} - another administrator must decide it`);
      const r = apr.patch(id, (x) => { x.status = decision; x.decided_at = now(); x.decided_by = by || ''; x.comment = String(comment || ''); });
      if (col.get(a.case_id)) {
        col.patch(a.case_id, (c) => {
          tl(c, by, 'approval', `${id} ${decision}: ${a.title}${comment ? ` — ${comment}` : ''} (the engine does not execute actions)`);
          c.updated = now();
        });
      }
      return r;
    },
  };

  return {
    create, get: (id) => view(col.get(id)), view,
    list, all: (fn) => col.all(fn), update, setStatus, assign, note, addEvidence, addTask, setTask, addAlerts, applyPlaybook,
    approvals, slaState, SLA, STATUSES, RESOLUTIONS,
  };
}

module.exports = { createCases, CASE_STATUSES: STATUSES, RESOLUTIONS, DEFAULT_SLA, sevName };
