// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Personal-data discovery in files:
//  - pii/classify.js: counts only, thresholds, Luhn for cards, an IBAN is not a card, Arabic terms, Office files read
//    through the minimal zip reader, file names classified; credentials in files (private_key / api_key / password at 1,
//    secret_file by name, configuration and script files read) - counted, never the value
//  - the Windows agent (1.5) applies the SAME rules and thresholds (parsed from sentra-agent.ps1 and compared)
//  - collect/m365-files.js against a fake Graph: sites → libraries → delta, content counted (never kept), sharing read for
//    hits (anonymous / external / organisation), a permission not granted named, budgets, one run at a time
//  - the agent's 'pii' snapshot: parser action agent-pii (detection skips it), latest per host
//  - GET /pii/files (analyst; viewer refused; audited) with the credentials summary, POST /pii/sharepoint/run (admin only; audited)
// Data is SYNTHETIC. Secret-shaped strings are assembled at run time from obvious placeholders (SYNTHETIC...) - no real key.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), zlib = require('node:zlib');
const C = require('../engine/pii/classify');
const { createFiles } = require('../engine/collect/m365-files');
const { createParser } = require('../engine/parse');
const { createHardeningStore } = require('../engine/hardening/store');
const routes = require('../engine/pii/routes');

// a tiny .docx: one deflated word/document.xml entry
function docx(xml) {
  const name = Buffer.from('word/document.xml'), data = zlib.deflateRawSync(Buffer.from(xml)), crc = 0;
  const loc = Buffer.alloc(30); loc.writeUInt32LE(0x04034b50, 0); loc.writeUInt16LE(8, 8); loc.writeUInt32LE(crc, 14); loc.writeUInt32LE(data.length, 18); loc.writeUInt32LE(xml.length, 22); loc.writeUInt16LE(name.length, 26);
  const cen = Buffer.alloc(46); cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(8, 10); cen.writeUInt32LE(data.length, 20); cen.writeUInt32LE(xml.length, 24); cen.writeUInt16LE(name.length, 28); cen.writeUInt32LE(0, 42);
  const body = Buffer.concat([loc, name, data]), cd = Buffer.concat([cen, name]);
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(body.length, 16);
  return Buffer.concat([body, cd, end]);
}
const IDS = '1012345678, 1098765432, 1011111111';
// synthetic credentials: shaped to match the patterns, assembled at run time, obviously not real
const SYN = { aws: 'AK' + 'IA' + 'SYNTHETICEXAMPLE', anth: 'sk-' + 'ant-' + 'SYNTHETIC_PLACEHOLDER_not_a_key', gh: 'gh' + 'p_' + 'SYNTHETIC'.padEnd(36, '0'),
  pem: '-----BEGIN ' + 'RSA PRIVATE KEY-----', pwd: 'pass' + 'word = ' + 'SYNTHETIC-placeholder', pwdAr: 'كلمة المرور: ' + 'SYNTHETIC-placeholder' };

test('classify: credentials in files counted at 1 - never the value; personal-data rules unchanged', () => {
  assert.deepEqual(C.classifyText('key ' + SYN.aws).kinds, { api_key: 1 });
  assert.equal(C.classifyText(SYN.anth + ' and ' + SYN.gh).kinds.api_key, 2);
  assert.deepEqual(C.classifyText(SYN.pem + '\nMIIsyntheticbody\n-----END RSA PRIVATE KEY-----').kinds, { private_key: 1 });
  assert.equal(C.classifyText('-----BEGIN OPENSSH PRIVATE KEY-----').kinds.private_key, 1);
  assert.equal(C.classifyText('-----BEGIN PUBLIC KEY-----').kinds.private_key, undefined, 'a public key is not a secret');
  assert.deepEqual(C.classifyText('DB_HOST=x\n' + SYN.pwd).kinds, { password: 1 });
  assert.equal(C.classifyText('PWD: ' + 'SYNTHETIC1').kinds.password, 1, 'case does not matter');
  assert.equal(C.classifyText(SYN.pwdAr).kinds.password, 1, 'Arabic');
  assert.equal(C.classifyText('forgot your password? ask IT').kinds.password, undefined, 'the word alone is not a password');
  for (const r of C.RULES.filter((x) => C.CATEGORY[x.kind] === 'credentials')) assert.equal(r.min, 1, r.kind + ' counts at 1');
  assert.deepEqual(['private_key', 'api_key', 'password', 'secret_file'].map((k) => C.CATEGORY[k]), ['credentials', 'credentials', 'credentials', 'credentials']);
  // Luhn / IBAN interplay unchanged next to credentials
  const mix = C.classifyText('IBAN SA03 8000 0000 6080 1016 7519 card 4111 1111 1111 1111 ' + SYN.aws + ' ' + SYN.pwd);
  assert.deepEqual(mix.kinds, { iban: 1, card: 1, api_key: 1, password: 1 });
  assert.equal(C.classifyText('IBAN SA03 8000 0000 6080 1016 7519 ' + SYN.pwd).kinds.card, undefined, 'an IBAN is still not a card');
  const out = JSON.stringify(C.classifyText([SYN.aws, SYN.anth, SYN.gh, SYN.pem, SYN.pwd, SYN.pwdAr].join(' ')));
  assert.ok(!/SYNTHETIC|BEGIN/.test(out), 'only counts come back - no value, no snippet');
  // credential file names
  for (const n of ['id_rsa', 'id_ed25519', 'server.pem', 'tls.key', 'cert.pfx', 'store.p12', '.env', '.env.production', 'aws-credentials.txt', 'secrets.yaml', 'Passwords.xlsx', 'my_secrets.txt', 'كلمات المرور.docx'])
    assert.ok(C.classifyName(n).includes('secret_file'), n);
  for (const n of ['secretary-minutes.docx', 'budget.xlsx', 'environment.docx', 'keynote-notes.txt', 'id_rsa.pub']) assert.ok(!C.classifyName(n).includes('secret_file'), n);
  // configuration and script files are read; the size bound is kept
  for (const n of ['app.env', '.env', 'web.config', 'settings.ini', 'nginx.conf', 'deploy.yml', 'ci.yaml', 'run.ps1', 'boot.sh', 'job.py', 'server.pem', 'tls.key']) assert.ok(C.readable(n), n);
  assert.equal(C.classifyText(C.textOf('web.config', Buffer.from('<add key="Db" value="' + SYN.pwd + '"/>'))).kinds.password, 1);
  assert.equal(C.textOf('big.env', Buffer.alloc(3 * 1024 * 1024, 0x61)).length, 2 * 1024 * 1024, 'MAX_TEXT bound');
  assert.equal(C.readable('photo.jpg'), false);
});

test('classify: thresholds, Luhn, IBAN not a card, Arabic terms, names, Office text; counts only', () => {
  assert.deepEqual(C.classifyText('one id 1012345678').kinds, {}, 'one stray number is not a register');
  assert.equal(C.classifyText(IDS).kinds.national_id, 3);
  assert.equal(C.classifyText('2123456789 2123456788 2123456787').kinds.iqama, 3);
  assert.equal(C.classifyText('0551234567 +966551234568 00966551234569').kinds.mobile, 3);
  assert.equal(C.classifyText('card 4111 1111 1111 1111').kinds.card, 1);
  assert.equal(C.classifyText('card 4111 1111 1111 1112').kinds.card, undefined, 'not Luhn-valid');
  const ib = C.classifyText('IBAN SA03 8000 0000 6080 1016 7519');
  assert.equal(ib.kinds.iban, 1); assert.equal(ib.kinds.card, undefined, 'an IBAN is not counted as a card');
  assert.equal(C.classifyText('Diagnosis: x. ICD-10 J45').kinds.health, 2);
  assert.equal(C.classifyText('تقرير طبي ... تشخيص').kinds.health, 2, 'Arabic terms');
  assert.equal(C.classifyText(Array.from({ length: 9 }, (_, i) => 'a' + i + '@x.sa').join(' ')).kinds.email, undefined, 'a few addresses are business mail, not a list');
  assert.deepEqual(C.classifyName('Scan_Passport_2025.pdf'), ['passport']); assert.deepEqual(C.classifyName('رواتب أكتوبر.xlsx'), ['salary']); assert.deepEqual(C.classifyName('budget.xlsx'), []);
  const t = C.textOf('claims.docx', docx('<w:document><w:t>' + IDS + '</w:t></w:document>'));
  assert.match(t, /1012345678/); assert.equal(C.classifyText(t).kinds.national_id, 3);
  assert.equal(C.textOf('photo.jpg', Buffer.from('x')), null); assert.equal(C.textOf('bad.docx', Buffer.from('not a zip')), null);
  assert.ok(!JSON.stringify(C.classifyText(IDS)).includes('1012345678'), 'only counts come back');
});

test('the Windows agent uses the same rules and thresholds as classify.js', () => {
  const ps = fs.readFileSync(path.join(__dirname, '..', 'agents', 'windows', 'sentra-agent.ps1'), 'utf8');
  assert.match(ps, /\$AgentVersion = '1\.7\.0'/);   // 1.7.0: credentials in file-share scans
  const unesc = (x) => x.replace(/\\u([0-9A-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
  const psRules = [...ps.matchAll(/@\{ k = '(\w+)'; re = '([^']+)'; min = (\d+)/g)].map((m) => ({ k: m[1], re: unesc(m[2]), min: Number(m[3]) }));
  assert.deepEqual(psRules.map((r) => [r.k, r.min]), C.RULES.map((r) => [r.kind, r.min]), 'same kinds, same thresholds, same order');
  for (const r of C.RULES) assert.equal(psRules.find((x) => x.k === r.kind).re, r.re.source, r.kind + ' pattern identical');
  // case: the agent ignores case exactly where classify.js has the i flag
  const psCi = [...ps.matchAll(/@\{ k = '(\w+)'; re = '[^']+'; min = \d+([^}]*)\}/g)].filter((m) => /ci = \$true/.test(m[2])).map((m) => m[1]);
  assert.deepEqual(psCi, C.RULES.filter((r) => r.re.flags.includes('i')).map((r) => r.kind), 'same case-insensitive rules');
  assert.match(ps, /if \(\$r\.ContainsKey\('ci'\)\) \{ \$opt = \[Text\.RegularExpressions\.RegexOptions\]::IgnoreCase \}/);
  // the same readable extensions: text files read as text, Office files through the zip reader
  const textExt = "'" + C.TEXT_EXT.source + "'", zipExt = "'" + C.ZIP_EXT.source + "'";
  assert.ok(ps.includes("$Path -match " + textExt), 'Get-PiiText reads the same text extensions');
  assert.ok(ps.includes("$f -match " + textExt + " -or $f -match " + zipExt), 'Invoke-FileScan reads the same extensions');
  for (const k of ['private_key', 'api_key', 'password']) assert.ok(psRules.some((r) => r.k === k), k + ' in the agent');
  const psNames = [...ps.matchAll(/@\{ k = '(\w+)'; re = '([^']+)' \}/g)].map((m) => [m[1], unesc(m[2])]);
  assert.deepEqual(psNames, C.NAME_RULES.map((r) => [r[0], r[2].source]), 'same file-name rules');
  assert.ok(psNames.some((n) => n[0] === 'secret_file'), 'credential file names in the agent');
  assert.ok(!/AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9]/.test(ps), 'no secret-shaped value in the agent');
  assert.match(ps, /FileScanPaths\s+= @\(\)/, 'off until folders are listed');
  assert.match(ps, /\[IO\.File\]::Open\(\$Path, 'Open', 'Read', 'ReadWrite'\)/, 'files are opened read-only');
  assert.doesNotMatch(ps.slice(ps.indexOf('function Invoke-FileScan'), ps.indexOf('if ($FileScan)')), /Remove-Item|Set-Content|Out-File|Move-Item|Set-Acl/, 'the scan writes nothing to the shares');
});

function fakeGraph(o = {}) {
  const calls = [];
  const files = { 'd1': [{ id: 'f1', name: 'claims-register.docx', size: 3000, file: {}, parentReference: { path: '/drives/d1/root:/Claims/2026' }, lastModifiedDateTime: '2026-10-01T00:00:00Z' },
    { id: 'f2', name: 'Passport_scan.pdf', size: 900000, file: {}, parentReference: { path: '/drives/d1/root:' } },
    { id: 'f3', name: 'notes.txt', size: 40, file: {}, parentReference: { path: '/drives/d1/root:' } },
    { id: 'f4', name: 'huge.csv', size: 50 * 1048576, file: {}, parentReference: { path: '/drives/d1/root:' } },
    { id: 'dir', name: 'Claims', folder: {} }, { id: 'gone', name: 'old.txt', file: {}, deleted: {} }] };
  const perms = { f1: [{ link: { scope: 'anonymous' } }], f2: [{ grantedToV2: { user: { email: 'broker@partner-syn.com' } } }] };
  const content = { f1: docx('<w:t>' + IDS + '</w:t>'), f3: Buffer.from('nothing personal here') };
  return { calls,
    async graphGet(u) {
      calls.push(u);
      if (u.startsWith('/organization')) return [{ verifiedDomains: [{ name: 'corp-syn.com' }] }];
      if (u.startsWith('/sites?')) { if (o.noSites) { const e = new Error('HTTP 403'); e.status = 403; throw e; } return [{ id: 's1', displayName: 'Claims Team (synthetic)', webUrl: 'https://syn.sharepoint.com/sites/claims' }]; }
      if (u.startsWith('/sites/s1/drives')) return [{ id: 'd1', name: 'Documents' }];
      if (u.startsWith('/drives/d1/root/delta')) return files.d1;
      const m = /^\/drives\/d1\/items\/(\w+)\/permissions$/.exec(u); if (m) return perms[m[1]] || [];
      throw new Error('unexpected ' + u);
    },
    async graphContent(u, max) { calls.push('content ' + u); const id = u.split('/')[4]; const b = content[id]; if (!b) { const e = new Error('HTTP 404'); e.status = 404; throw e; } if (b.length > max) { const e = new Error('too large'); e.status = 413; throw e; } return b; } };
}

test('SharePoint discovery: libraries walked, content counted, sharing of hits, nothing kept but counts', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-files-')), G = fakeGraph();
  const F = createFiles({ graph: G, config: { m365: { files: { max_content: 10 } } }, stateDir: dir });
  assert.equal(F.data().never, true);
  const r1 = F.runNow('nora.syn'); assert.equal(r1.started, true);
  assert.equal(F.runNow('nora.syn').running, true, 'one run at a time');
  await F.wait();
  const d = F.data(), s = d.sources[0];
  assert.equal(d.status.last_error, ''); assert.equal(d.by, 'nora.syn');
  assert.equal(s.kind, 'sharepoint'); assert.equal(s.files_seen, 4, 'folders and deleted items are not files');
  assert.equal(s.files_read, 2); assert.equal(s.files_skipped, 1, 'over max_mb: named only');
  const f1 = s.hits.find((h) => h.name === 'claims-register.docx'), f2 = s.hits.find((h) => h.name === 'Passport_scan.pdf');
  assert.deepEqual(f1.kinds, { national_id: 3 }); assert.equal(f1.by, 'content'); assert.equal(f1.path, '/Claims/2026'); assert.equal(f1.shared, 'anonymous');
  assert.deepEqual(f2.name_kinds, ['passport']); assert.equal(f2.by, 'name'); assert.equal(f2.shared, 'external', 'a recipient outside the verified domains');
  assert.ok(!s.hits.some((h) => h.name === 'notes.txt'));
  assert.ok(!G.calls.includes('content /drives/d1/items/f2/content'), 'a PDF is not downloaded');
  const saved = fs.readFileSync(path.join(dir, 'm365-files.json'), 'utf8');
  assert.ok(!saved.includes('1012345678')); assert.equal((fs.statSync(path.join(dir, 'm365-files.json')).mode & 0o777).toString(8), '600');
  // a permission not granted is named, the last good result is kept
  const F2 = createFiles({ graph: fakeGraph({ noSites: true }), config: {}, stateDir: dir });
  F2.runNow('nora.syn'); await F2.wait();
  assert.match(F2.data().status.last_error, /Sites\.Read\.All not granted/); assert.equal(F2.data().sources.length, 1, 'last good result kept');
});

test('agent pii snapshot: parsed as agent-pii, kept per host; routes: analyst read audited, run admin only', async () => {
  const snap = { at: '2026-10-25T03:00:00Z', roots: [{ path: 'D:\\Shares\\HR', share: 'HR', files_seen: 10, hits: [{ p: 'Payroll\\oct.xlsx', kinds: { iban: 12 }, name_kinds: ['salary'], by: 'content', open: true },
    { p: 'IT\\deploy.ps1', kinds: { password: 2 }, name_kinds: [], by: 'content', open: true }, { p: 'IT\\keys\\id_rsa', kinds: {}, name_kinds: ['secret_file'], by: 'name', open: false }] }] };
  const line = JSON.stringify({ Channel: 'SentraAgent', EventID: 1, TimeCreated: '2026-10-25T03:00:00.000Z', Computer: 'FS-SYN-01', RecordId: 0, Level: 4, ProviderName: 'SentraAgent', EventData: { type: 'pii', agent_version: '1.5.0', settings: JSON.stringify(snap) }, Message: 'x' });
  const ev = createParser().parse(line, { collector: 'agent', src_id: 'win', src_type: 'windows', rts: Date.now() });
  assert.equal(ev.action, 'agent-pii'); assert.ok(ev.tags.includes('heartbeat'));
  const S = createHardeningStore({ action: 'agent-pii', label: 'pii' });
  S.stage(ev); assert.equal(S.get('fs-syn-01').settings.roots[0].hits[0].kinds.iban, 12);
  const H = createHardeningStore(); H.stage(ev); assert.equal(H.list().length, 0, 'the hardening store does not take it');
  const R = {}, runs = [];
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { config: {}, piiShares: S, m365Files: { data: () => ({ sources: [{ key: 'sp:1', hits: [
    { name: 'claims.docx', kinds: { national_id: 3 }, name_kinds: [], shared: 'anonymous' },
    { name: 'aws-credentials.txt', kinds: { api_key: 1, password: 1 }, name_kinds: ['secret_file'], shared: 'anonymous' },
    { name: 'tls.pem', kinds: { private_key: 1 }, name_kinds: ['secret_file'], shared: null }] }], status: {} }), runNow: (w) => { runs.push(w); return { started: true }; } } });
  const ctx = (user, role) => { const out = { status: 200, body: null }, audits = []; const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
    return { user, role, query: {}, out, audits, need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out.status = 403; return false; } return true; }, fail: (c, m) => { out.status = c; out.body = { error: m }; return out.body; }, audit: (a, t, d) => audits.push({ a, t, d }) }; };
  const v = ctx('v.syn', 'viewer'); await R['GET /api/soc/pii/files'](v); assert.equal(v.out.status, 403);
  const a = ctx('nora.syn', 'analyst'); const r = await R['GET /api/soc/pii/files'](a);
  assert.equal(r.fileshares.hosts.length, 1); assert.equal(r.sharepoint.sources.length, 1); assert.equal(a.audits[0].a, 'pii.files.read');
  assert.deepEqual(r.credentials, { files: 4, by_kind: { private_key: 1, api_key: 1, password: 2, secret_file: 3 }, shared: 2 },
    'files holding a secret: shared = anonymous link (SharePoint) or open to everyone (file share); sharing not read is not counted as shared');
  assert.equal(a.audits[0].d.credential_files, 4); assert.ok(!JSON.stringify(a.audits).includes('credentials.txt'), 'no file name in the audit detail');
  assert.deepEqual(routes.credentialSummary({ sources: [] }, []), { files: 0, by_kind: { private_key: 0, api_key: 0, password: 0, secret_file: 0 }, shared: 0 }, 'nothing held: zeros, not made up');
  assert.deepEqual(routes.credentialSummary({ never: true }, [{ host: 'x', settings: {} }]).files, 0, 'no result yet / a host without roots');
  const a2 = ctx('nora.syn', 'analyst'); await R['POST /api/soc/pii/sharepoint/run'](a2); assert.equal(a2.out.status, 403);
  const ad = ctx('syed', 'admin'); const rr = await R['POST /api/soc/pii/sharepoint/run'](ad); assert.equal(rr.started, true); assert.deepEqual(runs, ['syed']); assert.equal(ad.audits[0].a, 'pii.sharepoint.run');
});
