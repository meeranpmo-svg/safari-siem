// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Email / Phishing Analysis: the analysis library (vendor/zyb-eml.js) in Node, then email-analysis.html in Chromium after the
// static build. The messages below are SYNTHETIC test fixtures (example / documentation addresses), never real mail.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node email-analysis.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
global.ZYB_ORG = require('../../brand/index');   // the brand setting, as vendor/zyb-org.js gives it to a page
const E = require(path.join(SRC, 'vendor/zyb-eml.js'));
// a domain one character away from the company's own (synthetic): what the look-alike rule must catch
const LBL = ZYB_ORG.domain.split('.')[0], LOOK = LBL.slice(0, -1) + (LBL.slice(-1) === 'x' ? 'y' : 'x') + '.com';
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

const PHISH = [
  ('Received: from mail.' + LOOK + ' (mail.' + LOOK + ' [203.0.113.9]) by mx.' + ZYB_ORG.domain + '; Tue, 20 Oct 2026 22:14:05 +0300'),
  'Received: from relay.internal (relay.internal [10.0.0.5]) by mail.' + LOOK + '; Tue, 20 Oct 2026 22:14:01 +0300',
  ('Authentication-Results: mx.' + ZYB_ORG.domain + '; spf=fail smtp.mailfrom=' + LOOK + '; dkim=none; dmarc=fail header.from=' + LOOK + ''),
  ('From: "' + ZYB_ORG.short + ' IT Support" <it-support@' + LOOK + '>'),
  'Reply-To: helpdesk@collector.example',
  ('To: claims@' + ZYB_ORG.domain),
  'Subject: =?UTF-8?B?2LnYp9is2YQ6INiq2K3ZgtmCINmF2YYg2YPZhNmF2Kkg2KfZhNmF2LHZiNix?=',
  'Message-ID: <synthetic-test-1@' + LOOK + '>',
  'Content-Type: multipart/mixed; boundary="b1"',
  '',
  '--b1',
  'Content-Type: text/html; charset=utf-8',
  '',
  ('<p>Your mailbox will be suspended. Verify your password now:</p><a href="https://evil-login.example/owa">https://mail.' + ZYB_ORG.domain + '/owa</a> <a href="https://bit.ly/x1">more</a>'),
  '--b1',
  'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
  'Content-Disposition: attachment; filename="invoice.pdf.exe"',
  '',
  'AAAA',
  '--b1--', ''].join('\r\n');
const CLEAN = [('Received: from mail.' + ZYB_ORG.domain + ' ([198.51.100.20]) by mx.' + ZYB_ORG.domain + '; Tue, 20 Oct 2026 09:00:00 +0300'),
  ('Authentication-Results: mx.' + ZYB_ORG.domain + '; spf=pass smtp.mailfrom=' + ZYB_ORG.domain + '; dkim=pass header.d=' + ZYB_ORG.domain + '; dmarc=pass header.from=' + ZYB_ORG.domain),
  ('DKIM-Signature: v=1; a=rsa-sha256; d=' + ZYB_ORG.domain + '; s=s1; b=x'),
  ('From: HR <hr@' + ZYB_ORG.domain + '>'), 'Subject: Team lunch on Thursday', '', 'See you at 1pm.', ''].join('\r\n');

// ---------------- library
let R = E.analyze(PHISH, null);
const K = R.F.map((f) => f.k);
ok(R.verdict === 'High' && R.score === 100, 'phish: High, capped at 100 (' + R.score + ')');
ok(K.includes('DMARC fail') && K.includes('SPF fail'), 'auth failures named');
ok(K.includes('Look-alike sender domain') && new RegExp(LOOK.replace(/\./g, '\\.')).test(R.F.find((f) => f.k === 'Look-alike sender domain').d), LOOK + ' is a look-alike');
ok(K.includes('Reply-To goes elsewhere') && K.includes(('Display name claims ' + ZYB_ORG.short)), 'reply-to and display-name tricks');
ok(K.includes('Risky attachment') && R.att[0].double, 'double-extension attachment');
const u0 = R.urls.find((u) => u.host === 'evil-login.example');
ok(u0 && u0.flags.some((f) => new RegExp('link text shows mail\\.' + ZYB_ORG.domain_re.replace(/\\\.[a-z]+$/, '')).test(f)), 'link text vs destination mismatch');
ok(R.urls.some((u) => u.host === 'bit.ly' && u.flags.some((f) => /shortener/.test(f))), 'shortener flagged');
ok(/عاجل/.test(R.subject), 'Arabic subject decoded: ' + R.subject);
ok(R.firstIp === '203.0.113.9' && R.hops.length === 2 && R.hops[0].ip === '10.0.0.5', 'delivery path oldest first, origin = first public hop');
ok(!R.tiChecked, 'without the SIEM answer, reputation is not checked');
const ind = E.indicators(PHISH);
ok(ind.includes('evil-login.example') && ind.includes('203.0.113.9') && ind.includes(LOOK) && !ind.includes(ZYB_ORG.domain), 'indicators: outside hosts only: ' + ind.join(','));
R = E.analyze(PHISH, new Map([['evil-login.example', ['cert-sa']], ['203.0.113.9', ['feed-abuse']]]));
ok(R.tiChecked && R.F.some((f) => f.k === 'Link matches threat intel') && R.F.some((f) => f.k === 'Origin IP matches threat intel' && /feed-abuse/.test(f.d)), 'TI hits add named indicators');
const C = E.analyze(CLEAN, new Map());
ok(C.verdict === 'No indicators' && C.score === 0, 'authenticated internal mail: no indicators (' + C.F.map((f) => f.k).join(',') + ')');
ok(E.lookalike(ZYB_ORG.domain) === false && E.lookalike(('mail.' + ZYB_ORG.domain)) === false && !!E.lookalike(ZYB_ORG.domain.split('.')[0] + '.co') && !!E.lookalike('xn--corpshild-abc.com'), 'look-alike rules');
ok(E.defang('https://evil.example/a') === 'hxxps://evil[.]example/a', 'defang');
ok(E.analyze('hello', null).err, 'not an e-mail → explains where to get the headers');
const SPOOF = CLEAN.replace('spf=pass', 'spf=fail').replace('dmarc=pass', 'dmarc=fail');
ok(E.analyze(SPOOF, null).F.some((f) => f.k === (ZYB_ORG.short + ' domain failing authentication')), 'spoofed internal sender');

// ---------------- page
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'emlpage-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
let ROLE = 'operator', INTEL = 'on'; const POSTS = [];
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'rasheed', role: ROLE });
    if (u === '/api/soc/intel') return j(200, { enabled: true, stats: { domain: 1200, ip: 800 } });
    if (q.method === 'POST' && u.startsWith('/api/')) { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { const body = JSON.parse(b || '{}'); POSTS.push({ u, body, raw: b });
      if (u === '/api/soc/intel/check') { if (INTEL === 'down') return j(503, { error: 'engine restarting' }); return j(200, { enabled: true, results: { 'evil-login.example': ['cert-sa'] }, reference: {} }); }
      if (u === '/api/soc/cases') return j(200, { id: 'CASE-000042' });
      j(404, {}); }); return; }
    if (u.startsWith('/api/')) return j(404, {});
    fs.readFile(path.join(B, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/email-analysis.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(url); await p.waitForTimeout(400); return p; };
  let p = await open();
  await p.fill('#src', PHISH); await p.click('#go'); await p.waitForFunction(() => /Indicators/.test(document.getElementById('out').innerText), null, { timeout: 5000 }).catch(() => {});
  let st = await p.evaluate(() => ({ out: document.getElementById('out').innerText, anchors: document.querySelectorAll('#out a').length, imgs: document.querySelectorAll('#out img').length }));
  const chk = POSTS.find((x) => x.u === '/api/soc/intel/check');
  ok(chk && chk.body.values.includes('evil-login.example') && !/suspended|password|invoice/i.test(chk.raw), 'only indicators go to the SIEM, never the message text');
  ok(/100\s*High/.test(st.out) && /Link matches threat intel/.test(st.out) && /checked against the SIEM's indicator lists/.test(st.out), 'verdict and TI note on the page');
  ok(/hxxps:\/\/evil-login\[\.\]example/.test(st.out) && st.anchors === 0, 'links shown defanged, nothing clickable');
  ok(/invoice\.pdf\.exe/.test(st.out) && /double extension/.test(st.out), 'attachment flagged');
  ok(/10\.0\.0\.5 \(private\)/.test(st.out), 'private hop marked');
  await p.click('#case'); await p.waitForTimeout(300);
  const cs = POSTS.find((x) => x.u === '/api/soc/cases');
  ok(cs && cs.body.playbook_id === 'PB-PHISHING' && cs.body.severity === 3 && /hxxps:\/\/evil-login\[\.\]example/.test(cs.body.description), 'case opened with the phishing playbook, defanged indicators');
  ok(await p.evaluate(() => /CASE-000042/.test(document.getElementById('case').textContent)), 'button shows the case');
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 3000 }).catch(() => null), p.click('#rep')]);
  ok(dl && /^phishing-analysis-\d{4}-\d{2}-\d{2}\.html$/.test(dl.suggestedFilename()), 'report downloads');
  await p.click('#clr'); ok(await p.evaluate(() => !document.getElementById('out').innerText.trim() && !document.getElementById('src').value), 'clear empties the page');
  await p.fill('#src', 'just some text'); await p.click('#go'); await p.waitForTimeout(200);
  ok(/No e-mail headers found/.test(await p.evaluate(() => document.getElementById('out').innerText)), 'not an e-mail: says where to get headers');
  await p.close();

  INTEL = 'down'; ROLE = 'viewer';
  p = await open(); await p.fill('#src', PHISH); await p.click('#go'); await p.waitForTimeout(600);
  st = await p.evaluate(() => ({ out: document.getElementById('out').innerText, caseBtn: !!document.getElementById('case') }));
  ok(/Reputation not checked/.test(st.out) && /not the same as clean/.test(st.out), 'SIEM unreachable: says reputation was not checked, never "clean"');
  ok(!st.caseBtn, 'viewer cannot open a case');
  await p.close();

  const nav = fs.readFileSync(path.join(SRC, 'vendor/zyb-nav.js'), 'utf8');
  ok(/"h": "email-analysis\.html"/.test(nav), 'page is in the menu');
  ok(/email-analysis\.html/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')) && /vendor\/zyb-eml\.js/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'installer ships the page and its library');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
