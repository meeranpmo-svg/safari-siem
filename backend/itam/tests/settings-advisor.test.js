// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ITAM Settings advisor (engine/settings-advisor.js) over a SYNTHETIC register: the not-seen threshold learned from how often assets
// report (with how many each value flags), the expiry window against the renewal lead time, a silent source, vCenter on without
// credentials, agent coverage by site, a stale enrolment token, adoption, AI privacy; administrators only; nothing written.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'op.syn', role: 'operator' };
const ago = (d) => new Date(Date.now() - d * 86400000).toISOString();
test('learned thresholds, sources, agents, tokens, adoption, AI privacy; admin only; nothing written', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const A = e.app.store.collection('assets');
  for (let i = 0; i < 20; i++) A.put({ id: 'pc' + i, name: 'PC-' + i, type: 'workstation', status: 'in_use', networked: true, site: i < 15 ? 'Jeddah' : 'Riyadh', last_seen: ago(5 + i * 2), sources: [{ source: 'sensor', last_seen: ago(5 + i * 2) }] });
  for (let i = 0; i < 30; i++) e.app.store.collection('disc_devices').put({ id: 'd' + i, status: 'new' });
  e.app.settings.update({ sources: { vcenter: true, agent: true }, not_seen_days: 14, expiry_window_days: 30, external_ai_allowed: true }, ADM);
  e.app.agentgw.issueToken({ note: 'old batch', site: 'Jeddah' }, ADM);
  const tk = e.app.store.collection('enrol_tokens'); for (const x of tk.all()) tk.put(Object.assign(x, { created_at: ago(20) }));
  const before = JSON.stringify(e.app.settings.get());
  assert.equal((await e.req('GET', '/settings/advisor', OP)).status, 403, 'administrators only');
  const v = (await e.req('GET', '/settings/advisor', ADM)).json;
  const R = (id) => v.recommendations.find((r) => r.id === id);
  const L = v.learned.not_seen.learned; assert.ok(L >= 39 && L <= 40, 'p90 of 5..43 days: ' + L); assert.equal(R('not_seen_low').apply.not_seen_days, L); assert.match(R('not_seen_low').why, /at 14 days \d+ assets are flagged/);
  assert.ok(R('expiry_short') && R('expiry_short').apply.expiry_window_days >= 90, 'window vs the 60-day default lead time');
  assert.equal(R('vcenter_creds').severity, 'high');
  assert.ok(R('src_silent_agent'), 'agent source on, nothing from it');
  assert.ok(R('agent_coverage') && /Jeddah \(15\)/.test(R('agent_coverage').why), 'coverage by site');
  assert.ok(R('tokens_unused'), 'a 20-day-old unused token');
  assert.ok(R('adopt') && R('adopt').apply.auto_adopt === true);
  assert.ok(R('ai_redact'));
  assert.equal(v.recommendations[0].severity, 'high'); assert.ok(v.score < 50);
  assert.equal(JSON.stringify(e.app.settings.get()), before, 'the advisor writes nothing');
});
