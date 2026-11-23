// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network change plans (guided automation, phase 3) — PROPOSE → APPROVE / REJECT → APPLIED (by a person) → VALIDATED.
 * A free-text plan is carried out by an engineer, who then marks it applied; validation re-polls the device and re-runs
 * the diagnosis so the result is recorded next to the plan. A plan built from a TASK template (tasks.js) is carried out by
 * the SIEM after approval (EXECUTING → VALIDATED, or EXECUTION-FAILED with the rollback recorded).
 *   createChanges({ state, log, collection?, prefix?, execution? })   (defaults: netops_changes, NCHG; the AI Server
 *   Administrators use their own collection and prefix through the same rules)
 *     .propose({device, title, reason, commands[], rollback[], prechecks[], risk, source:'ai'|'user'}, by) → plan
 *     .decide(id, 'approved'|'rejected', by, comment)    (admin; the proposer cannot approve their own plan, and for an AI
 *       plan neither can the person who asked the AI or assigned it the ticket — requested_by)
 *     .markApplied(id, by, note)   .recordValidation(id, result)   .list({status})   .get(id)
 * State collection "netops_changes". Ids NCHG-000001.
 */
const STATUSES = ['proposed', 'approved', 'rejected', 'executing', 'execution-failed', 'applied', 'validated', 'failed-validation'];
// a plan built from a task template (netops/tasks.js) is carried out by the SIEM after approval; every other plan by a person
const TASK_EXEC = 'automated after approval - an operator presses Run; the SIEM pushes the exact lines with the write login, verifies, rolls back on failure and saves only when verified';
class ChangeError extends Error { constructor(code, msg) { super(msg); this.code = code; this.errors = [msg]; } }
function clean(s, max) { return String(s == null ? '' : s).replace(/[\u0000-\u0008\u000b-\u001f]/g, '').slice(0, max); }
function lines(a, max = 60) { return (Array.isArray(a) ? a : String(a || '').split('\n')).map((x) => clean(x, 400)).filter((x) => x.trim()).slice(0, max); }

function createChanges({ state, log, collection, prefix, execution } = {}) {
  const col = state.collection(collection || 'netops_changes'), L = log || { info() {} }, PFX = (prefix || 'NCHG') + '-';
  const EXEC = execution || 'manual — the SIEM never changes devices';
  function nextId() { let max = 0; for (const c of col.all()) { const n = Number(String(c.id).slice(PFX.length)); if (n > max) max = n; } return PFX + String(max + 1).padStart(6, '0'); }
  function must(id) { const c = col.get(id); if (!c) throw new ChangeError(404, 'change plan not found'); return c; }
  return {
    STATUSES,
    propose(p, by) {
      const title = clean(p.title, 160).trim(); if (!title) throw new ChangeError(400, 'title required');
      const commands = lines(p.commands); if (!commands.length) throw new ChangeError(400, 'at least one command / step required');
      const plan = { id: nextId(), device: clean(p.device, 40), title, reason: clean(p.reason, 2000), commands, rollback: lines(p.rollback), prechecks: lines(p.prechecks, 30),
        risk: ['low', 'medium', 'high'].includes(p.risk) ? p.risk : 'medium', source: p.source === 'ai' ? 'ai' : 'user', status: 'proposed',
        requested_by: clean(p.requested_by, 120), ticket: clean(p.ticket, 40),
        proposed_by: by || '', proposed_at: Date.now(), history: [{ at: Date.now(), by: by || '', action: 'proposed' }], execution: p.task ? TASK_EXEC : EXEC };
      if (p.task && typeof p.task === 'object' && typeof p.task.type === 'string') { const t = JSON.stringify({ type: p.task.type, params: p.task.params || {} }); if (t.length <= 4000) plan.task = JSON.parse(t); }
      col.put(plan); L.info('netops change proposed', { id: plan.id, by }); return plan;
    },
    decide(id, decision, by, comment) {
      const c = must(id);
      if (c.status !== 'proposed') throw new ChangeError(409, 'only a proposed plan can be approved or rejected');
      if (!['approved', 'rejected'].includes(decision)) throw new ChangeError(400, 'decision must be approved or rejected');
      if (decision === 'approved' && by && String(c.proposed_by || '').trim().toLowerCase() === String(by).trim().toLowerCase() && c.source === 'user') throw new ChangeError(403, 'a plan must be approved by someone other than its author');
      if (decision === 'approved' && by && c.requested_by && c.requested_by.trim().toLowerCase() === String(by).trim().toLowerCase()) throw new ChangeError(403, 'this AI plan was requested by you: another administrator must approve it');
      return col.patch(id, (x) => { x.status = decision; x.decided_by = by || ''; x.decided_at = Date.now(); x.comment = clean(comment, 1000); x.history.push({ at: Date.now(), by, action: decision, comment: x.comment }); return x; });
    },
    markApplied(id, by, note) {
      const c = must(id); if (c.status !== 'approved') throw new ChangeError(409, 'only an approved plan can be marked applied');
      return col.patch(id, (x) => { x.status = 'applied'; x.applied_by = by || ''; x.applied_at = Date.now(); x.applied_note = clean(note, 1000); x.history.push({ at: Date.now(), by, action: 'applied', comment: x.applied_note }); return x; });
    },
    recordValidation(id, result) {
      must(id);
      return col.patch(id, (x) => { x.validation = { at: Date.now(), ok: !!result.ok, summary: clean(result.summary, 1000), open_findings: (result.findings || []).slice(0, 20) }; x.status = result.ok ? 'validated' : 'failed-validation'; x.history.push({ at: Date.now(), by: 'engine', action: x.status }); return x; });
    },
    // a task run by the SIEM (tasks.js): executing → applied + validated, or execution-failed (rolled back, or not)
    recordExecution(id, r) {
      must(id);
      return col.patch(id, (x) => {
        x.run = { status: r.status, by: r.by || '', steps: (r.steps || []).slice(0, 40), started: (x.run && x.run.started) || Date.now(), finished: r.finished || null };
        if (r.status === 'executing') { x.status = 'executing'; x.history.push({ at: Date.now(), by: r.by, action: 'execution started' }); }
        else if (r.status === 'done') {
          const v = (r.steps || []).filter((s) => s.name === 'verify' || s.name === 'schedule reload').pop();
          x.status = 'validated'; x.applied_by = (r.by || '') + ' via the SIEM'; x.applied_at = Date.now(); x.applied_note = 'executed by the SIEM after approval by ' + (x.decided_by || '?');
          x.validation = { at: Date.now(), ok: true, summary: v ? v.detail : 'verified', open_findings: [] };
          x.history.push({ at: Date.now(), by: r.by, action: 'executed', comment: x.validation.summary });
        } else { x.status = 'execution-failed'; x.rollback_failed = r.status === 'rollback-failed'; x.history.push({ at: Date.now(), by: r.by, action: r.status === 'rolled-back' ? 'execution failed - rolled back' : r.status === 'rollback-failed' ? 'execution failed - ROLLBACK FAILED' : 'execution failed (nothing changed)' }); }
        return x;
      });
    },
    list(f = {}) { return col.all((c) => !f.status || c.status === f.status).sort((a, b) => b.proposed_at - a.proposed_at); },
    get: (id) => col.get(id) || null,
  };
}
module.exports = { createChanges, ChangeError, STATUSES };
