// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UAT sign-off checklist for the AI Windows Server Administrator ({P} = /api/soc). A test round runs against the servers
 * of one site (default "UAT"); each test has a fixed id, what to do and what to expect. A person records the result -
 * the platform only shows the evidence it holds next to it (servers checked, problems raised, change plans approved by
 * someone else), never a result of its own.
 *   GET  {P}/sysadmin/uat                 viewer    the current round: site, tests + evidence + results, sign-off, past rounds
 *   POST {P}/sysadmin/uat/items/:id       operator  {result: pass|fail|not_run, note, server?}   (a fail needs a note)
 *   POST {P}/sysadmin/uat/signoff         admin     {note}  every required test passed; the signer recorded none of the results
 *   POST {P}/sysadmin/uat/reset           admin     {site?, note}  archive this round and start a new one
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { body, param } = require('../util/check');

const TESTS = [
  { id: 'connection', title: 'Connection and read-only login', how: 'Servers → a UAT server → Check now.', expect: 'Results for disks, services, events, updates, certificates and time sync.', required: true },
  { id: 'finding', title: 'A real problem is raised', how: 'Fill a UAT disk to under 10 % free, or stop a non-critical service, then Check now.', expect: 'A finding appears with evidence and a recommended fix.', required: true },
  { id: 'unreachable', title: 'Unreachable server is never "healthy"', how: 'Block TCP 5985 on one UAT server, then Check now.', expect: 'The server shows "could not run" with the reason, not ok.', required: true },
  { id: 'badlogin', title: 'Wrong password', how: 'Point one UAT server at a login profile with a wrong password, then Check now.', expect: 'A clear login failure; no password in any log or screen.', required: true },
  { id: 'ai', title: 'AI answers from evidence', how: 'Ask the AI: "Why is <UAT server> slow?"', expect: 'The answer cites the checks and SIEM events it read and only proposes changes.', required: true },
  { id: 'foureyes', title: 'Four-eyes change approval', how: 'Have the AI propose a change plan; try to approve it as its author; a different administrator approves; a person applies it and marks it applied.', expect: 'The author is refused; after "applied" the server is re-checked and the result recorded.', required: true },
  { id: 'roles', title: 'Roles', how: 'Sign in as a viewer, then as an operator.', expect: 'A viewer only reads; an operator runs checks but cannot approve a change plan or set logins.', required: true },
  { id: 'eventlog', title: 'Windows event logs in the SIEM (optional)', how: 'Install the Windows agent on one UAT server (install-agent.ps1 -TokenFile …).', expect: 'Its events reach the SIEM and the AI can quote them.', required: false },
];
const RESULTS = ['pass', 'fail', 'not_run'];
const same = (a, b) => String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();

function createUat({ state, targets, health, changes, now }) {
  const col = state.collection('sysadmin_uat'), T = () => (now ? now() : Date.now());
  const fresh = (site, by, n) => ({ id: 'current', round: n || 1, site: site || 'UAT', started: T(), started_by: by || '', results: {}, signoff: null });
  const current = () => col.get('current') || fresh();
  const save = (r) => { col.put(r); return r; };
  const atSite = (site) => targets.list('windows').filter((t) => same(t.site, site));

  // what the platform itself holds for each test - shown beside the result, never used as the result
  function evidence(site) {
    const S = atSite(site), ids = new Set(S.map((t) => t.id)), F = health.findings({ role: 'windows' }).filter((f) => ids.has(f.server));
    const snaps = S.map((t) => [t, health.snapshot(t.id)]), checked = snaps.filter(([, s]) => s && s.at);
    const auth = snaps.filter(([, s]) => s && Object.values(s.results || {}).some((r) => r && r.error && r.kind === 'auth'));
    const C = changes.list({}).filter((c) => ids.has(c.device));
    const indep = C.filter((c) => c.decided_by && c.status !== 'rejected' && c.status !== 'proposed' && !same(c.decided_by, c.proposed_by));
    const applied = C.filter((c) => c.validation);
    return {
      connection: checked.length ? `${checked.length} of ${S.length} UAT server(s) checked; with a login: ${S.filter((t) => targets.login(t, 'windows')).length}` : null,
      finding: F.filter((f) => f.kind !== 'cannot-check').length ? `${F.filter((f) => f.kind !== 'cannot-check').length} problem(s) open on UAT servers` : null,
      unreachable: F.filter((f) => f.kind === 'cannot-check').length ? `${F.filter((f) => f.kind === 'cannot-check').length} "could not run" finding(s) on UAT servers` : null,
      badlogin: auth.length ? `login refused on: ${auth.map(([t]) => t.name).join(', ')}` : null,
      ai: null,
      foureyes: C.length ? `${C.length} change plan(s) on UAT servers; approved by someone other than the author: ${indep.length}; re-checked after applying: ${applied.length}` : null,
      roles: null,
      eventlog: null,
    };
  }

  function view() {
    const r = current(), E = evidence(r.site), S = atSite(r.site);
    const items = TESTS.map((t) => Object.assign({}, t, { evidence: E[t.id], result: (r.results[t.id] || {}).result || 'not_run' }, r.results[t.id] ? { note: r.results[t.id].note, server: r.results[t.id].server, by: r.results[t.id].by, at: r.results[t.id].at } : {}));
    const req = items.filter((i) => i.required);
    return { round: r.round, site: r.site, started: r.started, started_by: r.started_by, servers: S.map((t) => ({ id: t.id, name: t.name, ip: t.ip, last_check: (health.snapshot(t.id) || {}).at || null })),
      items, summary: { required: req.length, passed: req.filter((i) => i.result === 'pass').length, failed: items.filter((i) => i.result === 'fail').length, not_run: items.filter((i) => i.result === 'not_run').length },
      ready_to_sign: req.every((i) => i.result === 'pass') && !r.signoff, signoff: r.signoff,
      past: col.all((x) => x.id !== 'current').sort((a, b) => b.round - a.round).slice(0, 10).map((x) => ({ round: x.round, site: x.site, started: x.started, signoff: x.signoff, closed: x.closed, closed_by: x.closed_by })) };
  }

  function record(id, input, by) {
    const t = TESTS.find((x) => x.id === id); if (!t) throw new HttpError(404, 'unknown UAT test');
    const b = body(input).oneOf('result', RESULTS, { required: true }).str('note', { max: 1000 }).str('server', { max: 40 }).done();
    if (b.result === 'fail' && !b.note) throw new HttpError(400, 'note is required when a test fails (what happened)');
    const r = current(); if (r.signoff) throw new HttpError(409, 'this round is signed off - start a new round to test again');
    if (b.server && !atSite(r.site).some((x) => x.id === b.server)) throw new HttpError(400, `server: not a ${r.site} server`);
    const prev = r.results[id];
    r.results[id] = { result: b.result, note: b.note || '', server: b.server || '', by: by || '', at: T(), history: ((prev && prev.history) || []).concat(prev ? [{ result: prev.result, by: prev.by, at: prev.at }] : []).slice(-20) };
    save(r); return { test: id, from: prev ? prev.result : 'not_run', to: b.result };
  }

  function signoff(input, by) {
    const b = body(input).str('note', { max: 1000 }).done(), r = current(), v = view();
    if (r.signoff) throw new HttpError(409, 'this round is already signed off');
    const open = v.items.filter((i) => i.required && i.result !== 'pass');
    if (open.length) throw new HttpError(409, 'every required test must pass first: ' + open.map((i) => i.title).join(', '));
    if (!by) throw new HttpError(403, 'sign-off needs a named person');
    if (Object.values(r.results).some((x) => same(x.by, by))) throw new HttpError(403, 'four eyes: the person who signs off must not have recorded any of the results');
    r.signoff = { by, at: T(), note: b.note || '', passed: v.summary.passed, required: v.summary.required };
    save(r); return r.signoff;
  }

  function reset(input, by) {
    const b = body(input).str('site', { max: 60, re: /^[A-Za-z0-9 ._-]+$/, msg: 'site: letters, digits, spaces, dots, dashes' }).str('note', { max: 500 }).done(), r = current();
    if (col.get('current')) col.put(Object.assign({}, r, { id: 'round-' + r.round, closed: T(), closed_by: by || '', close_note: b.note || '' }));
    return save(fresh(b.site || r.site, by, r.round + (col.get('current') ? 1 : 0)));
  }

  return { view, record, signoff, reset, evidence };
}

function register(api, deps, S) {
  const P = prefixOf(deps);
  const U = createUat({ state: deps.state, targets: S.targets, health: S.health, changes: S.changes, now: deps.now });
  api.route('GET', `${P}/sysadmin/uat`, wrap(deps, null, () => U.view()));
  api.route('POST', `${P}/sysadmin/uat/items/:id`, wrap(deps, 'operator', (ctx) => { const id = param(ctx.params.id, 'test'); const r = U.record(id, ctx.body, ctx.user); audit(ctx, 'sysadmin.uat.result', id, r); return U.view(); }));
  api.route('POST', `${P}/sysadmin/uat/signoff`, wrap(deps, 'admin', (ctx) => { const s = U.signoff(ctx.body, ctx.user); audit(ctx, 'sysadmin.uat.signoff', 'round', { passed: s.passed, required: s.required }); return U.view(); }));
  api.route('POST', `${P}/sysadmin/uat/reset`, wrap(deps, 'admin', (ctx) => { const r = U.reset(ctx.body, ctx.user); audit(ctx, 'sysadmin.uat.reset', 'round-' + r.round, { site: r.site }); return U.view(); }));
  return U;
}

module.exports = { register, createUat, TESTS };
