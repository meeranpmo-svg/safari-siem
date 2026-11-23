// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Evidence & Chain of Custody (engine/custody-intel.js) over the REAL evidence register with SYNTHETIC files uploaded through it:
// integrity re-hashed from the stored bytes (VERIFIED, MISMATCH after the bytes are altered, LINK with nothing to hash); a download is a
// custody event in the audit log (grc.evidence.file, with who); the daily ledger chains and catches a recorded hash changed after
// recording and a snapshot removed; the audit-log chain is reported; "verify now" by a person, audited; roles; advisor off.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const DAY = 86400000, VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:grc', role: 'operator' };
const PDF = Buffer.from('%PDF-1.4\n% synthetic evidence\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n');
async function setup(t) {
  let clock = Date.parse('2026-11-02T08:00:00Z');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const s = { e, tick: (ms) => { clock += ms; }, post: (p, b, who = OP) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), audit: (a) => e.app.store.auditTail(2000).filter((x) => x.action === a) };
  let r = await s.post('/grc/evidence', { framework: 'SAMA CSF', control: '3.3.14', title: 'Log review record (synthetic)', filename: 'log-review.pdf', content_b64: PDF.toString('base64'), owner: 'nora.syn' }); assert.equal(r.status, 200, r.raw); s.a = r.json;
  r = await s.post('/grc/evidence', { framework: 'SAMA CSF', control: '3.3.5', title: 'Access review (synthetic)', filename: 'access.pdf', content_b64: Buffer.concat([PDF, Buffer.from('x')]).toString('base64') }); assert.equal(r.status, 200, r.raw); s.b = r.json;
  r = await s.post('/grc/evidence', { framework: 'NCA ECC', control: '2-3-1', title: 'Vendor portal (synthetic)', url: 'https://example.test/evidence' }); assert.equal(r.status, 200, r.raw); s.c = r.json;
  return s;
}
const it = (v, id) => v.sections[0].items.find((i) => i.id === id);

test('integrity, a download in the custody trail, the audit chain', async (t) => {
  const s = await setup(t);
  let v = (await s.get('/custody-intel', VIEW)).json;
  assert.ok(it(v, s.a.id).tags.includes('verified') && it(v, s.c.id).tags.includes('link')); assert.equal(v.ring.value, 100);
  assert.equal((await s.get('/grc/files/' + s.a.file.file_id, OP)).status, 200);
  assert.equal(s.audit('grc.evidence.file').length, 1, 'the download is recorded'); assert.equal(s.audit('grc.evidence.file')[0].by, 'nora.syn');
  v = (await s.get('/custody-intel')).json; assert.ok(it(v, s.a.id).tags.includes('downloaded')); assert.ok(it(v, s.a.id).detail.lists[0].items.some((x) => /nora\.syn · downloaded a copy/.test(x)));
  // the stored bytes are altered behind the register's back
  const f = s.e.app.store.collection('grc_files'), rec = f.get(s.b.file.file_id); f.put(Object.assign({}, rec, { content_b64: Buffer.from('%PDF-1.4 tampered').toString('base64') }));
  v = (await s.get('/custody-intel')).json; assert.ok(it(v, s.b.id).tags.includes('mismatch')); assert.match(it(v, s.b.id).detail.rows[0][1], /recorded/); assert.equal(v.ring.value, 50);
  assert.ok(v.kpis.find((k) => k.label === 'Audit log chain').value.startsWith('intact'));
  assert.match(v.sections[1].text, /tamper-evident|not tamper-proof|Root on the server/);
});

test('the ledger catches a changed hash and a removed snapshot; verify now; roles', async (t) => {
  const s = await setup(t), X = s.e.app.addons.custodyIntel;
  for (let d = 0; d < 3; d++) { assert.ok(await X.snapshot()); assert.equal(await X.snapshot(), null, 'one a day'); s.tick(DAY); }
  let v = (await s.get('/custody-intel')).json; assert.match(v.kpis.find((k) => k.label === 'Ledger').value, /intact · 3 d/);
  const ev = s.e.app.store.collection('grc_evidence'), r0 = ev.get(s.a.id); ev.put(Object.assign({}, r0, { file: Object.assign({}, r0.file, { sha256: 'f'.repeat(64) }) }));   // recorded hash edited
  assert.ok(await X.snapshot());
  v = (await s.get('/custody-intel')).json; assert.ok(it(v, s.a.id).tags.includes('changed') && it(v, s.a.id).tags.includes('mismatch'));
  s.e.app.store.collection('custody_intel_snaps').remove('2026-11-03');
  v = (await s.get('/custody-intel')).json; assert.match(v.kpis.find((k) => k.label === 'Ledger').value, /broken/);
  assert.equal((await s.post('/custody-intel/verify', {}, VIEW)).status, 403);
  assert.equal((await s.post('/custody-intel/verify', {}, BOT)).status, 403);
  const r = await s.post('/custody-intel/verify', {}, ADM); assert.equal(r.status, 200, r.raw); assert.match(r.json.message, /MISMATCH: EVD-/);
  assert.equal(s.audit('custody-intel.verify').length, 1);
  assert.equal((await s.post('/custody-intel/ask', { question: 'what can we rely on?' }, VIEW)).status, 403);
  assert.equal((await s.post('/custody-intel/ask', { question: 'what can we rely on?' })).status, 424);
});
