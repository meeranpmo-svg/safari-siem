// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Evidence & Chain of Custody (evidence-custody.html) against the REAL ITAM engines (evidence register + engine/custody-intel.js) with
// SYNTHETIC files uploaded through the register: ring and KPIs; integrity chips; a tampered file shown as MISMATCH; the custody trail of
// an item with its download; the ledger text; "verify every file now" by an operator; a hostile title stays text; a viewer has no
// verify; the custodian off until allowed; menu entry, installer, the portal's custody redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node evidence-custody.test.js
const PDF = Buffer.from('%PDF-1.4\n% synthetic evidence\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n');
let A, B;
require('./intel-harness')({ file: 'evidence-custody.html', view: 'custody',
  after: async (e) => { const R = require('../../backend/itam/engine/grc-registers').createGrcRegisters(e.app), who = { user: 'nora.syn', role: 'operator' };
    A = R.evCreate({ framework: 'SAMA CSF', control: '3.3.14', title: '<img src=x onerror="window.__xss=1"> log review', filename: 'a.pdf', content_b64: PDF.toString('base64') }, who);
    B = R.evCreate({ framework: 'SAMA CSF', control: '3.3.5', title: 'Access review (synthetic)', filename: 'b.pdf', content_b64: Buffer.concat([PDF, Buffer.from('x')]).toString('base64') }, who);
    R.file(A.file.file_id, who);
    const f = e.app.store.collection('grc_files'), r = f.get(B.file.file_id); f.put(Object.assign({}, r, { content_b64: Buffer.from('%PDF-1.4 tampered').toString('base64') })); } },
async (h) => {
  let p = await h.page();
  h.ok(/integrity verified/.test(await h.text(p, '#zi-hero')) && /50%/.test(await h.text(p, '#zi-hero')), 'ring');
  h.ok(/Hash mismatch/.test(await h.text(p, '#zi-hero')) && /Audit log chain/.test(await h.text(p, '#zi-hero')), 'KPIs');
  await p.click('[data-chip="items|mismatch"]'); h.ok(await h.wait(p, () => document.querySelectorAll('#sec-items .zi-it').length === 1 && /HASH MISMATCH/.test(document.getElementById('sec-items').textContent)), 'mismatch chip');
  await p.click('[data-chip="items|all"]');
  h.ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('sec-items').textContent)), 'a hostile title stays text');
  h.ok(await h.openCard(p, 'items', A.id), 'item detail'); const d = await h.text(p, '#zi-dlgb');
  h.ok(/Custody trail/.test(d) && /downloaded a copy/.test(d) && /nora\.syn/.test(d) && /hash to the recorded SHA-256/.test(d), 'integrity and the custody trail'); await h.closeDlg(p);
  h.ok(/first ledger snapshot|daily snapshot/.test(await h.text(p, '#sec-ledger')) && /Root on the server/.test(await h.text(p, '#sec-ledger')), 'the ledger, honestly framed');
  await p.click('#zi-hero form[data-gact="0"] button'); h.ok(await h.toast(p, '1 of 2 verified · MISMATCH'), 'verify every file now');
  h.ok(await h.wait(p, () => /nora\.syn/.test(document.getElementById('zi-hero').textContent)), 'the last verification is shown');
  h.ok(/Not available/.test(await h.text(p, '#zi-ai')), 'custodian off until allowed');
  h.who('vera.syn', 'viewer'); p = await h.page(); h.ok(!(await p.$('#zi-hero form')), 'a viewer cannot run a verification');
});
