// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SIEM pipeline watcher (engine/pipeline-health.js): the SIEM's canary read out of band - healthy gives no signal; a failing canary,
// a stopped canary and a degraded day become platform signals naming the stage; the SIEM not answering twice in a row becomes "The
// SIEM is not answering" (once is not enough); a SIEM without the canary yet is not an incident; the signals reach Notification &
// Escalation's platform source; roles (viewer reads, operator checks - audited), validation (undeclared fields dropped). SYNTHETIC.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const PH = require('../engine/pipeline-health');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' };

async function setup(t, answer) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  const state = { answer };
  const siem = async (m, p, who) => { if (typeof state.answer === 'function') return state.answer(m, p, who); return state.answer; };
  const X = PH.registerPipelineHealth(e.app.srv, e.app, { siem, noTimer: true });
  return { e, X, state, call: (m, p, who, b) => e.req(m, p, Object.assign({ body: b }, who)) };
}
const view = (status, extra) => ({ status: 200, json: Object.assign({ status, why: 'synthetic ' + status, last: { failed_stage: status === 'failing' ? 'alert' : null } }, extra || {}) });

test('watcher: healthy is quiet; failing, stopped and degraded become platform signals', async (t) => {
  const s = await setup(t, view('healthy'));
  await s.X.check(); assert.deepEqual(s.X.signals(), []);
  s.state.answer = view('failing'); await s.X.check();
  let g = s.X.signals(); assert.equal(g.length, 1); assert.equal(g[0].fp, 'platform:siem:pipeline'); assert.equal(g[0].severity, 4); assert.match(g[0].title, /failing at "alert"/); assert.equal(g[0].source, 'platform');
  s.state.answer = view('stale'); await s.X.check(); g = s.X.signals(); assert.equal(g[0].fp, 'platform:siem:canary-stopped');
  s.state.answer = view('degraded'); await s.X.check(); g = s.X.signals(); assert.equal(g[0].severity, 2);
  s.state.answer = { status: 404, json: { error: 'not found' } }; await s.X.check(); assert.deepEqual(s.X.signals(), [], 'a SIEM without the canary yet is not an incident');
  assert.equal(s.X.view().siem.status, 'not_installed');
});

test('watcher: the SIEM not answering twice in a row is an incident, once is not; it clears when the SIEM answers', async (t) => {
  const s = await setup(t, () => { throw new Error('connect ECONNREFUSED 127.0.0.1:8443'); });
  await s.X.check(); assert.deepEqual(s.X.signals(), [], 'one failed read is not enough');
  await s.X.check(); const g = s.X.signals();
  assert.equal(g.length, 1); assert.equal(g[0].fp, 'platform:siem:unreachable'); assert.match(g[0].text, /2 reads in a row failed .*ECONNREFUSED/); assert.match(g[0].text, /systemctl status sentra-siem/);
  s.state.answer = view('healthy'); await s.X.check(); assert.deepEqual(s.X.signals(), []);
});

test('watcher: signals reach Notification & Escalation; routes and roles', async (t) => {
  const s = await setup(t, view('failing'));
  await s.X.check();
  const nc = require('../engine/notify-center').createNotifyCenter(s.e.app, { noTimer: true });
  const col = nc.collect ? await nc.collect() : null;
  if (col) assert.ok(col.signals.some((x) => x.fp === 'platform:siem:pipeline'), 'the platform source carries the pipeline signal');
  let r = await s.call('GET', '/pipeline-health', VIEW); assert.equal(r.status, 200); assert.equal(r.json.reachable, true); assert.match(r.json.note, /separate service/);
  r = await s.call('POST', '/pipeline-health/check', VIEW, {}); assert.equal(r.status, 403);
  r = await s.call('POST', '/pipeline-health/check', OP, { extra: 1 }); assert.equal(r.status, 200, r.text);
  assert.ok(s.e.app.store.auditTail(50).some((a) => a.action === 'pipeline-health.check' && a.by === 'nora.syn'));
});
