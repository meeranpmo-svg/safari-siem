// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Sigma → native conversion. Rules below follow the public SigmaHQ rule structure (written for these tests).
const test = require('node:test');
const assert = require('node:assert/strict');
const { convertSigma, convertSigmaAll, mapField } = require('../engine/detect/sigma');
const { createDetector } = require('../engine/detect/engine');

const T0 = Date.UTC(2026, 8, 29, 10, 0, 0);
let n = 0;
const ev = (o) => Object.assign({ id: `s${++n}`, ts: T0, src_type: 'windows', host: 'pc1', action: '', fields: {}, tags: [] }, o);
function fire(rule, events) {
  const out = [];
  const d = createDetector({ rules: [Object.assign({}, rule, { suppress_s: 0, enabled: true })], onAlert: (a) => out.push(a), now: () => T0 });
  for (const e of events) d.onEvent(e);
  assert.equal(d.stats().errors, 0);
  assert.equal(d.stats().load_errors.length, 0, JSON.stringify(d.stats().load_errors));
  return out.filter((a) => !a.update).length;
}

const WHOAMI = `
title: Whoami Privilege Discovery
id: 5c4a1f2e-7b3d-4e8f-9a0b-1c2d3e4f5a6b
status: test
description: |
    Detects whoami.exe used to enumerate privileges.
    Second description line.
references:
    - https://example.org/whoami
author: Sentra test
date: 2026/09/29
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    selection_cli:
        CommandLine|contains|all:
            - '/priv'
            - '/groups'
    filter_main_admin:
        ParentImage|startswith: 'C:\\Program Files\\Admin Tools\\'
    condition: all of selection_* and not 1 of filter_main_*
falsepositives:
    - Administrators
level: medium
`;

test('process_creation rule: logsource, field mapping, modifiers, all/1 of, not', () => {
  const r = convertSigma(WHOAMI);
  assert.ok(r.ok, JSON.stringify(r.errors));
  const rule = r.rule;
  assert.equal(rule.id, 'SIGMA-5C4A1F2E');
  assert.equal(rule.name, 'Whoami Privilege Discovery');
  assert.equal(rule.severity, 2);
  assert.deepEqual(rule.mitre, ['T1033']);
  assert.equal(rule.tactic, 'discovery');
  assert.equal(rule.description, 'Detects whoami.exe used to enumerate privileges.');
  assert.equal(rule.type, 'single');
  assert.equal(rule.source, 'sigma');
  assert.deepEqual(rule.falsepositives, ['Administrators']);
  const s = JSON.stringify(rule.match);
  assert.ok(s.includes('"field":"src_type","op":"eq","value":"windows"'));
  assert.ok(s.includes('"field":"action","op":"eq","value":"process-start"'));
  assert.ok(s.includes('"field":"process","op":"endswith","value":"\\\\whoami.exe"'));
  assert.ok(s.includes('"field":"fields.OriginalFileName"'));
  assert.ok(s.includes('"field":"parent_process","op":"startswith"'));
  const base = { src_type: 'windows', action: 'process-start', process: 'C:\\Windows\\System32\\whoami.exe', cmdline: 'whoami /priv /groups', parent_process: 'C:\\Windows\\explorer.exe' };
  assert.equal(fire(rule, [ev(base)]), 1);
  assert.equal(fire(rule, [ev(Object.assign({}, base, { cmdline: 'whoami /priv' }))]), 0, '|all needs both');
  assert.equal(fire(rule, [ev(Object.assign({}, base, { parent_process: 'C:\\Program Files\\Admin Tools\\x.exe' }))]), 0, 'filter');
  assert.equal(fire(rule, [ev(Object.assign({}, base, { src_type: 'linux' }))]), 0, 'logsource');
  assert.equal(fire(rule, [ev(Object.assign({}, base, { process: 'C:\\x\\renamed.exe', fields: { OriginalFileName: 'WHOAMI.EXE' } }))]), 1, 'list of maps = OR, case-insensitive');
});

test('aggregation count() by → threshold; count(field) by → distinct', () => {
  const t = convertSigma(`
title: Many failed logons from one source
id: 0f7d2a11-0000-4000-8000-000000000001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
            - 4771
    timeframe: 5m
    condition: selection | count() by IpAddress > 10
level: high
`);
  assert.ok(t.ok, JSON.stringify(t.errors));
  assert.equal(t.rule.type, 'threshold');
  assert.deepEqual(t.rule.group_by, ['src_ip']);
  assert.equal(t.rule.count, 11);
  assert.equal(t.rule.window_s, 300);
  assert.equal(t.rule.severity, 3);
  const evs = Array.from({ length: 11 }, (_, i) => ev({ event_code: i % 2 ? '4625' : '4771', src_ip: '203.0.113.5', ts: T0 + i * 1000 }));
  assert.equal(fire(t.rule, evs.slice(0, 10)), 0);
  assert.equal(fire(t.rule, evs), 1);

  const d = convertSigma(`
title: Password spray
logsource: {product: windows, service: security}
detection:
    selection:
        EventID: 4625
    timeframe: 10m
    condition: selection | count(TargetUserName) by IpAddress >= 5
level: high
`);
  assert.ok(d.ok, JSON.stringify(d.errors));
  assert.equal(d.rule.type, 'distinct');
  assert.equal(d.rule.distinct_field, 'target_user');
  assert.equal(d.rule.distinct_count, 5);
  assert.equal(d.rule.window_s, 600);
  assert.match(d.rule.id, /^SIGMA-PASSWORD/);
});

test('webserver rule: keyword-ish contains list, |re with (?i), parentheses', () => {
  const r = convertSigma(`
title: Web traversal or injection
id: 9a8b7c6d-0000-4000-8000-000000000002
logsource:
    category: webserver
detection:
    sel_traversal:
        cs-uri-query|contains:
            - '../../'
            - '/etc/passwd'
    sel_sqli:
        cs-uri-query|re: '(?i)union\\s+select'
    filter_scanner_ok:
        c-ip: '10.0.0.5'
    condition: (sel_traversal or sel_sqli) and not filter_scanner_ok
level: high
`);
  assert.ok(r.ok, JSON.stringify(r.errors));
  const rule = r.rule;
  assert.equal(fire(rule, [ev({ category: 'web', url: '/x?f=../../../etc/shadow', src_ip: '203.0.113.1' })]), 1);
  assert.equal(fire(rule, [ev({ category: 'web', url: '/x?id=1 UNION   SELECT 1', src_ip: '203.0.113.1' })]), 1);
  assert.equal(fire(rule, [ev({ category: 'web', url: '/x?f=../../', src_ip: '10.0.0.5' })]), 0);
  assert.equal(fire(rule, [ev({ category: 'network', url: '/x?f=../../', src_ip: '203.0.113.1' })]), 0);
});

test('firewall rule: |cidr, numeric lists, not filter', () => {
  const r = convertSigma(`
title: SMB or RDP to internal ranges from outside
logsource:
    category: firewall
detection:
    selection:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '192.168.0.0/16'
        DestinationPort:
            - 445
            - 3389
    filter:
        SourceIp|cidr: '10.0.0.0/8'
    condition: selection and not filter
level: medium
`);
  assert.ok(r.ok, JSON.stringify(r.errors));
  const e = (o) => ev(Object.assign({ category: 'network', src_type: 'fortigate' }, o));
  assert.equal(fire(r.rule, [e({ src_ip: '198.51.100.1', dst_ip: '10.1.1.1', dst_port: 445 })]), 1);
  assert.equal(fire(r.rule, [e({ src_ip: '10.2.2.2', dst_ip: '10.1.1.1', dst_port: 445 })]), 0);
  assert.equal(fire(r.rule, [e({ src_ip: '198.51.100.1', dst_ip: '10.1.1.1', dst_port: 22 })]), 0);
});

test('linux keywords, wildcards, null, exists, windash, gt, 1 of them (underscore excluded)', () => {
  const k = convertSigma(`
title: Root password logon keyword
logsource:
    product: linux
    service: sshd
detection:
    keywords:
        - 'Accepted password for root'
    condition: keywords
level: high
`);
  assert.ok(k.ok);
  assert.ok(k.warnings.some((w) => /substring/.test(w)));
  assert.equal(fire(k.rule, [ev({ src_type: 'linux', raw: 'sshd[1]: Accepted password for root from 1.2.3.4 port 22' })]), 1);

  const w = convertSigma(`
title: Wildcards and modifiers
logsource:
    product: windows
detection:
    sel_dns:
        QueryName: '*.duckdns.org'
    sel_mid:
        CommandLine: 'net* user * /add'
    sel_null:
        User: null
        Image|endswith: '\\cmd.exe'
    sel_dash:
        CommandLine|windash|contains: ' -accepteula '
    sel_big:
        DestinationPort|gt: 60000
    _helper:
        Image: 'never'
    condition: 1 of them
level: low
`);
  assert.ok(w.ok, JSON.stringify(w.errors));
  const s = JSON.stringify(w.rule.match);
  assert.ok(!s.includes('never'), '_helper is not part of "them"');
  assert.equal(fire(w.rule, [ev({ dns_query: 'c2.duckdns.org' })]), 1);
  assert.equal(fire(w.rule, [ev({ cmdline: 'net1 user bob P@ss /add' })]), 1);
  assert.equal(fire(w.rule, [ev({ process: 'C:\\Windows\\System32\\cmd.exe', user: '' })]), 1);
  assert.equal(fire(w.rule, [ev({ process: 'C:\\Windows\\System32\\cmd.exe', user: 'bob' })]), 0);
  assert.equal(fire(w.rule, [ev({ cmdline: 'psexec.exe /accepteula \\\\host cmd' })]), 1, 'windash matches the / variant');
  assert.equal(fire(w.rule, [ev({ dst_port: 61000 })]), 1);
  assert.equal(fire(w.rule, [ev({ dst_port: 443, dns_query: 'example.com' })]), 0);
});

test('field-name mapping', () => {
  assert.equal(mapField('Image'), 'process');
  assert.equal(mapField('ParentImage'), 'parent_process');
  assert.equal(mapField('CommandLine'), 'cmdline');
  assert.equal(mapField('TargetUserName'), 'target_user');
  assert.equal(mapField('SubjectUserName'), 'user');
  assert.equal(mapField('User'), 'user');
  assert.equal(mapField('IpAddress'), 'src_ip');
  assert.equal(mapField('SourceIp'), 'src_ip');
  assert.equal(mapField('DestinationIp'), 'dst_ip');
  assert.equal(mapField('DestinationPort'), 'dst_port');
  assert.equal(mapField('EventID'), 'event_code');
  assert.equal(mapField('QueryName'), 'dns_query');
  assert.equal(mapField('Hashes'), 'hash');
  assert.equal(mapField('LogonType'), 'fields.LogonType');
});

test('unsupported constructs are reported, not guessed', () => {
  const base = (det, extra = '') => `title: U\nlogsource:\n    product: windows\n${extra}detection:\n${det}`;
  const cases = [
    [base('    sel:\n        CommandLine|base64offset|contains: abc\n    condition: sel\n'), /base64offset/],
    [base('    sel:\n        CommandLine|fieldref: Image\n    condition: sel\n'), /fieldref/],
    [base('    a:\n        EventID: 1\n    b:\n        EventID: 2\n    condition: a near b\n'), /near/],
    [base('    a:\n        EventID: 1\n    b:\n        EventID: 2\n    condition: 2 of a*\n'), /only 1\/any\/all/],
    [base('    a:\n        EventID: 1\n    timeframe: 5m\n    condition: a | count() by host < 5\n'), /operator "<"/],
    [base('    a:\n        EventID: 1\n    timeframe: 5m\n    condition: a | max(x) by host > 5\n'), /max\(\)/],
    [base('    a:\n        EventID: 1\n    condition: a | count() > 5\n'), /without timeframe/],
    [base('    a:\n        EventID: 1\n    condition: a and missing\n'), /unknown selection "missing"/],
    [base('    a:\n        CommandLine|re: "(?s)x.y"\n    condition: a\n'), /inline regex flags/],
    [base('    a:\n        CommandLine|foo: x\n    condition: a\n'), /unknown modifier \|foo/],
    ['title: C\ncorrelation:\n    type: event_count\n', /correlation/],
    ['action: global\ntitle: G\n', /collection action/],
    ['title: bad yaml\ndetection: [unclosed\n', /YAML line/],
  ];
  for (const [yaml, re] of cases) {
    const r = convertSigma(yaml);
    assert.equal(r.ok, false, `should be unsupported: ${yaml}`);
    assert.ok(r.errors.some((e) => re.test(e)), `${re} not in ${JSON.stringify(r.errors)}`);
  }
});

test('unmapped logsource → warning (not an error); multi-document files; cased warning', () => {
  const res = convertSigmaAll(`
title: One
logsource:
    product: exotic_product
detection:
    s:
        Field|cased: X
    condition: s
---
title: Two
logsource:
    product: windows
detection:
    s:
        EventID: 4720
    condition: s
level: critical
`, { enabled: false });
  assert.equal(res.length, 2);
  assert.ok(res[0].ok);
  assert.ok(res[0].warnings.some((w) => /exotic_product is not mapped/.test(w)));
  assert.ok(res[0].warnings.some((w) => /cased/.test(w)));
  assert.equal(res[1].rule.severity, 4);
  assert.equal(res[1].rule.enabled, false);
  assert.equal(fire(res[1].rule, [ev({ event_code: '4720' })]), 1);
});
