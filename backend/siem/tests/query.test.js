// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Query language compiler tests (SQL + JS predicate), including injection attempts. Synthetic data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { parse, compile, compileJS, parseTimeValue, QueryError } = require('../engine/api/query');
const { blankEvent } = require('../engine/schema');

const vals = (c) => Object.values(c.params).map((p) => p.value);
const types = (c) => Object.values(c.params).map((p) => p.type);

// Every user-supplied value must be a parameter: the SQL text may only contain identifiers, operators,
// placeholders and the literal '' (empty string). No quotes, comments or statement separators.
function assertSafeSql(where) {
  const stripped = where.replace(/''/g, '').replace(/\{q\d+:(String|UInt16|Int64|Float64)\}/g, 'P');
  assert.doesNotMatch(stripped, /['";]|--|\/\*/, 'unsafe SQL: ' + where);
  assert.match(stripped, /^[\w\s()=!<>.,`\[\]\->]*$/, 'unexpected characters in SQL: ' + where);
}

function ev(o) { return Object.assign(blankEvent(), { ts: Date.UTC(2024, 4, 1, 10), rts: Date.UTC(2024, 4, 1, 10) }, o); }

test('empty query matches everything', () => {
  assert.deepEqual(parse(''), { type: 'all' });
  assert.equal(compile('').where, '1');
  assert.equal(compile('   ').where, '1');
  assert.equal(compileJS('')(ev({})), true);
});

test('field equality normalises case for keyword fields', () => {
  const c = compile('user:Alice action:LOGON-FAILED host:TEST-DC-01');
  assert.equal(c.where, '(`user` = {q1:String} AND `action` = {q2:String} AND `host` = {q3:String})');
  assert.deepEqual(vals(c), ['alice', 'logon-failed', 'TEST-DC-01']);
  const f = compileJS('user:Alice action:LOGON-FAILED');
  assert.equal(f(ev({ user: 'alice', action: 'logon-failed' })), true);
  assert.equal(f(ev({ user: 'alice', action: 'logon' })), false);
});

test('quoted phrase, prefix wildcard, general wildcard, exists', () => {
  let c = compile('process:"C:\\\\Program Files\\\\x.exe"');
  assert.equal(c.where, '`process` = {q1:String}');
  assert.deepEqual(vals(c), ['C:\\Program Files\\x.exe']);
  c = compile('host:test-dc*');
  assert.equal(c.where, 'startsWith(`host`, {q1:String})');
  assert.deepEqual(vals(c), ['test-dc']);
  c = compile('user:a*m?n');
  assert.equal(c.where, '`user` ILIKE {q1:String}');
  assert.deepEqual(vals(c), ['a%m_n']);
  c = compile('user:50%_off*');
  assert.deepEqual(vals(c), ['50%_off']); // startsWith takes a literal: no LIKE escaping
  assert.equal(c.where, 'startsWith(`user`, {q1:String})');
  c = compile('user:*50%*');
  assert.deepEqual(vals(c), ['%50\\%%']);
  c = compile('hash:*');
  assert.equal(c.where, "`hash` != ''");
  const f = compileJS('user:a*m?n');
  assert.equal(f(ev({ user: 'admin' })), true);
  assert.equal(f(ev({ user: 'adman' })), true);
  assert.equal(f(ev({ user: 'admn' })), false);
});

test('text fields use case-insensitive substring', () => {
  const c = compile('cmdline:"-enc " message:mimikatz');
  assert.equal(c.where, '(positionCaseInsensitiveUTF8(`cmdline`, {q1:String}) > 0 AND positionCaseInsensitiveUTF8(`message`, {q2:String}) > 0)');
  const f = compileJS('cmdline:"-ENC "');
  assert.equal(f(ev({ cmdline: 'powershell -enc AAAA' })), true);
  assert.equal(f(ev({ cmdline: 'powershell -e AAAA' })), false);
});

test('numeric comparisons and ranges', () => {
  let c = compile('severity:>=3');
  assert.equal(c.where, '`severity` >= {q1:UInt16}');
  assert.deepEqual(vals(c), [3]);
  c = compile('dst_port:[1 TO 1024}');
  assert.equal(c.where, '(`dst_port` >= {q1:UInt16} AND `dst_port` < {q2:UInt16})');
  c = compile('http_status:[500 TO *]');
  assert.equal(c.where, '(`http_status` >= {q1:UInt16})');
  c = compile('dst_port:443');
  assert.equal(c.where, '`dst_port` = {q1:UInt16}');
  const f = compileJS('dst_port:[1 TO 1024} severity:>2');
  assert.equal(f(ev({ dst_port: 22, severity: 3 })), true);
  assert.equal(f(ev({ dst_port: 1024, severity: 3 })), false);
  assert.equal(f(ev({ dst_port: 22, severity: 2 })), false);
  assert.throws(() => compile('severity:high'), QueryError);
  assert.throws(() => compile('dst_port:70000'), QueryError);
  assert.throws(() => compile('severity:1*'), QueryError);
});

test('time comparisons and ranges', () => {
  const t0 = Date.UTC(2024, 4, 1);
  let c = compile('ts:>=2024-05-01');
  assert.equal(c.where, '`ts` >= fromUnixTimestamp64Milli({q1:Int64})');
  assert.deepEqual(vals(c), [t0]);
  c = compile('ts:["2024-05-01T00:00:00Z" TO "2024-05-02T00:00:00+03:00"]');
  assert.deepEqual(vals(c), [t0, Date.UTC(2024, 4, 1, 21)]);
  const now = Date.now();
  const v = parseTimeValue('now-15m', now);
  assert.equal(v, now - 900000);
  assert.throws(() => compile('ts:yesterday'), QueryError);
  assert.throws(() => compile('ts:2024-05-01'), /use ts:>=/);
  const f = compileJS('ts:<2024-05-01T10:00:01Z');
  assert.equal(f(ev({})), true);
});

test('ip: cidr on src_ip OR dst_ip, exact, prefix; src_ip cidr', () => {
  let c = compile('ip:10.0.0.0/8');
  assert.equal(c.where, "((`src_ip` != '' AND isIPAddressInRange(`src_ip`, {q1:String})) OR (`dst_ip` != '' AND isIPAddressInRange(`dst_ip`, {q2:String})))");
  assert.deepEqual(vals(c), ['10.0.0.0/8', '10.0.0.0/8']);
  c = compile('src_ip:192.0.2.1');
  assert.equal(c.where, '`src_ip` = {q1:String}');
  c = compile('dst_ip:2001:db8::/32');
  assert.match(c.where, /isIPAddressInRange\(`dst_ip`/);
  c = compile('src_ip:10.1.*');
  assert.equal(c.where, 'startsWith(`src_ip`, {q1:String})');
  const f = compileJS('ip:10.0.0.0/8 NOT src_ip:10.9.0.0/16');
  assert.equal(f(ev({ src_ip: '203.0.113.5', dst_ip: '10.1.2.3' })), true);
  assert.equal(f(ev({ src_ip: '10.9.1.1', dst_ip: '203.0.113.5' })), false);
  assert.equal(f(ev({ src_ip: '203.0.113.5', dst_ip: '198.51.100.1' })), false);
  assert.equal(compileJS('src_ip:2001:db8::/32')(ev({ src_ip: '2001:db8::1' })), true);
  assert.throws(() => compile('ip:10.0.0.0/33'), /invalid CIDR/);
  assert.throws(() => compile('ip:300.1.1.1/8'), /invalid CIDR/);
});

test('full text: token vs substring vs wildcard', () => {
  let c = compile('mimikatz');
  assert.equal(c.where, '(hasTokenCaseInsensitive(raw, {q1:String}) OR hasTokenCaseInsensitive(message, {q1:String}))');
  c = compile('"failed password"');
  assert.equal(c.where, '(positionCaseInsensitiveUTF8(raw, {q1:String}) > 0 OR positionCaseInsensitiveUTF8(message, {q1:String}) > 0)');
  c = compile('10.1.2.3');
  assert.match(c.where, /positionCaseInsensitiveUTF8/); // contains separators → not a hasToken needle
  c = compile('admin_user');
  assert.match(c.where, /positionCaseInsensitiveUTF8/);
  c = compile('mimi*');
  assert.equal(c.where, '(raw ILIKE {q1:String} OR message ILIKE {q1:String})');
  assert.deepEqual(vals(c), ['%mimi%']);
  const f = compileJS('mimikatz');
  assert.equal(f(ev({ raw: 'ran Mimikatz.exe today' })), true);
  assert.equal(f(ev({ raw: 'ran mimikatzz today' })), false); // token semantics
  assert.equal(compileJS('"failed PASSWORD"')(ev({ message: 'Failed password for x' })), true);
  assert.equal(compileJS('mimi*')(ev({ raw: 'xx MIMIKATZ' })), true);
});

test('boolean logic, precedence, grouping, default AND, -negation', () => {
  let c = compile('action:logon-failed OR action:logon AND user:bob');
  assert.equal(c.where, '(`action` = {q1:String} OR (`action` = {q2:String} AND `user` = {q3:String}))');
  c = compile('(action:logon-failed OR action:logon) user:bob');
  assert.equal(c.where, '((`action` = {q1:String} OR `action` = {q2:String}) AND `user` = {q3:String})');
  c = compile('NOT user:bob');
  assert.equal(c.where, 'NOT (`user` = {q1:String})');
  c = compile('-user:bob -"x y"');
  assert.match(c.where, /^\(NOT \(`user`.*AND NOT \(\(position/);
  c = compile('user:(alice OR bob carol)');
  assert.equal(c.where, '(`user` = {q1:String} OR (`user` = {q2:String} AND `user` = {q3:String}))');
  const f = compileJS('src_type:windows AND (event_code:4625 OR event_code:4771) NOT user:*$');
  assert.equal(f(ev({ src_type: 'windows', event_code: '4625', user: 'bob' })), true);
  assert.equal(f(ev({ src_type: 'windows', event_code: '4625', user: 'pc01$' })), false);
  assert.equal(f(ev({ src_type: 'windows', event_code: '4624', user: 'bob' })), false);
});

test('fields map, tags, id', () => {
  let c = compile('fields.logon_type:10');
  assert.equal(c.where, '`fields`[{q1:String}] = {q2:String}'.replace('`fields`', 'fields'));
  assert.deepEqual(vals(c), ['logon_type', '10']);
  c = compile('fields.sentbyte:>1000000');
  assert.equal(c.where, 'toFloat64OrNull(fields[{q1:String}]) > {q2:Float64}');
  c = compile('fields.vhost:*');
  assert.equal(c.where, 'mapContains(fields, {q1:String})');
  c = compile('fields.x_forwarded_for:10.0.0.0/8');
  assert.match(c.where, /isIPv4String\(fields\[\{q1:String\}\]\)/);
  c = compile('tags:T1110 tags:T1059*');
  assert.equal(c.where, '(has(tags, {q1:String}) AND arrayExists(x -> startsWith(x, {q2:String}), tags))');
  c = compile('id:0B7C2A55-1111-4222-8333-944455556666');
  assert.equal(c.where, '`id` = toUUIDOrZero({q1:String})');
  assert.deepEqual(vals(c), ['0b7c2a55-1111-4222-8333-944455556666']);
  assert.throws(() => compile('id:1 OR 1=1'), QueryError);
  const f = compileJS('fields.logon_type:10 tags:T1110');
  assert.equal(f(ev({ fields: { logon_type: '10' }, tags: ['T1110', 'rdp'] })), true);
  assert.equal(f(ev({ fields: { logon_type: '3' }, tags: ['T1110'] })), false);
  assert.equal(compileJS('fields.sentbyte:>100')(ev({ fields: { sentbyte: '101' } })), true);
  assert.equal(compileJS('fields.sentbyte:>100')(ev({ fields: {} })), false);
});

test('rejects unknown fields and malformed queries with clear errors', () => {
  const bad = [
    ['foo:bar', /unknown field "foo"/],
    ['http://x', /unknown field "http"/],
    ['fields:x', /fields\.<key>/],
    ['(user:a', /missing "\)"/],
    ['user:a)', /unbalanced/],
    ['"abc', /unterminated quote/],
    ['user:', /missing value/],
    ['user: a', /missing value/],
    ['AND user:a', /unexpected keyword/],
    ['user:a OR', /OR needs/],
    ['NOT', /NOT needs a term/],
    ['()', /empty parentheses/],
    ['severity:[1 2]', /range must be/],
    ['severity:[1 TO 2', /unterminated range/],
    ['user:[a TO b]', /ranges are only supported/],
    ['user:>a', /comparison is only supported/],
  ];
  for (const [q, re] of bad) {
    assert.throws(() => compile(q), (e) => e instanceof QueryError && e.status === 400 && re.test(e.message), q);
  }
  assert.throws(() => compile('x'.repeat(5000)), /too long/);
  assert.throws(() => compile(Array(200).fill('a').join(' ')), /too many terms/);
  assert.throws(() => compile('('.repeat(30) + 'a' + ')'.repeat(30)), /nested too deeply/);
  assert.throws(() => compile({ toString: () => 'x' }), QueryError);
});

test('injection attempts never reach SQL text', () => {
  const nasty = [
    "user:\"x' OR '1'='1\"",
    "user:x'--",
    "user:\"a\\\" OR 1=1 --\"",
    "'; DROP TABLE siem.events; --",
    "\"'; DROP TABLE siem.events; --\"",
    'message:"\\\'); SELECT * FROM system.users; --"',
    'host:`evil`',
    'host:{p1:String}',
    'user:"{q1:String}"',
    'fields.a\'b:1',
    'fields.x:"\') OR 1=1"',
    'src_ip:"1.1.1.1\' OR 1=1"',
    'process:C:\\\\Windows\\\\x.exe',
    'cmdline:*\\%\\_*',
    'tags:"a\'b"',
    'url:"/a?b=1;DROP"',
    'user:"\\u0000\\n\\t"',
    'raw:"*/ SELECT 1 /*"',
    'user:(a OR "b\' OR 1=1 --")',
    'ip:10.0.0.0/8\' OR 1=1',
  ];
  for (const q of nasty) {
    let c;
    try { c = compile(q); } catch (e) { assert.ok(e instanceof QueryError, `${q}: ${e.message}`); continue; }
    assertSafeSql(c.where);
    for (const t of types(c)) assert.ok(['String', 'UInt16', 'Int64', 'Float64'].includes(t));
  }
  // field names are only ever whitelisted identifiers; anything else is treated as (parameterised) text
  for (const q of ['`user`:x', 'user;drop:x', 'user) OR (1:x']) {
    try { assertSafeSql(compile(q).where); } catch (e) { assert.ok(e instanceof QueryError, q + ': ' + e.message); }
  }
  // injected text lands verbatim in a parameter
  const c = compile("user:\"x' OR '1'='1\"");
  assert.deepEqual(vals(c), ["x' or '1'='1"]);
});

test('param prefix option and AST reuse', () => {
  const ast = parse('user:a b');
  const c = compile(ast, { prefix: 'z' });
  assert.equal(c.where, '(`user` = {z1:String} AND (hasTokenCaseInsensitive(raw, {z2:String}) OR hasTokenCaseInsensitive(message, {z2:String})))');
  assert.equal(typeof compileJS(ast), 'function');
});

test('wildcards: linear matcher agrees with the regex semantics it replaced', () => {
  // reference: the old RegExp construction, run only on short strings where backtracking cannot blow up
  const toRe = (pat, anchored) => {
    const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    let src = '';
    for (const ch of pat) src += ch === '*' ? '[\\s\\S]*' : ch === '?' ? '[\\s\\S]' : esc(ch);
    return new RegExp(anchored ? '^' + src + '$' : src, 'i');
  };
  let seed = 7;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const alpha = 'abAB-';
  for (let k = 0; k < 400; k++) {
    let pat = '';
    for (let i = 1 + rnd(6); i > 0; i--) pat += 'ab*?'[rnd(4)];
    if (!/[*?]/.test(pat)) pat += '*';
    let s = '';
    for (let i = rnd(12); i > 0; i--) s += alpha[rnd(alpha.length)];
    // anchored: user:<pattern> ; unanchored: bare word (leading/trailing * trimmed, substring match)
    // user values are stored lowercase by the parsers (and a lone trailing * takes the startsWith path)
    const u = s.toLowerCase();
    const anchored = compileJS(`user:${pat}`)({ ...blankEvent(), user: u });
    assert.equal(anchored, toRe(pat, true).test(u), `user:${pat} vs "${u}"`);
    if (/[ab]/.test(pat)) {
      const bare = compileJS(pat)({ ...blankEvent(), raw: s });
      assert.equal(bare, toRe(pat.replace(/^\*+|\*+$/g, ''), false).test(s), `${pat} vs raw "${s}"`);
    }
  }
});

test('wildcards: pathological patterns stay fast and the per-term cap holds', () => {
  const long = 'a'.repeat(64 * 1024);
  const nginx = '198.51.100.23 - - [01/May/2024:10:00:25 +0300] "GET /portal/login?next=%2F HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (SyntheticTest)"';
  for (const [q, raw] of [['a*a*a*a*a*a*b', long], ['0*0*0*0*0*0*0*0*0*0*0*0*|', nginx], ['user:a*a*a*a*b', null]]) {
    const pred = compileJS(q);
    const ev = { ...blankEvent(), raw: raw || '', user: raw ? '' : long };
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < 20; i++) pred(ev);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 500, `${q} took ${ms.toFixed(1)} ms for 20 events`);
  }
  assert.throws(() => parse('a' + '*a'.repeat(17)), QueryError);
  assert.doesNotThrow(() => parse('a' + '*a'.repeat(16)));
});
