// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parse, parseAll, YamlError } = require('../engine/detect/yaml');

test('block maps, nesting, sequences, scalars, comments', () => {
  const doc = parse(`
# leading comment
title: Test rule   # trailing comment
id: 1234
ratio: 0.5
enabled: true
missing: null
tilde: ~
hex: 0x10
str_num: '4625'
tags:
    - attack.t1110
    - attack.credential_access
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        Image|endswith: '\\whoami.exe'
        CommandLine|contains|all:
            - '/priv'
            - "/all"
    condition: selection
`);
  assert.equal(doc.title, 'Test rule');
  assert.equal(doc.id, 1234);
  assert.equal(doc.ratio, 0.5);
  assert.equal(doc.enabled, true);
  assert.equal(doc.missing, null);
  assert.equal(doc.tilde, null);
  assert.equal(doc.hex, 16);
  assert.equal(doc.str_num, '4625');
  assert.deepEqual(doc.tags, ['attack.t1110', 'attack.credential_access']);
  assert.deepEqual(doc.logsource, { product: 'windows', service: 'security' });
  assert.equal(doc.detection.selection.EventID, 4625);
  assert.equal(doc.detection.selection['Image|endswith'], '\\whoami.exe', 'single-quoted backslashes are literal');
  assert.deepEqual(doc.detection.selection['CommandLine|contains|all'], ['/priv', '/all']);
});

test('sequences of maps, same-indent sequences, nested sequences, empty values', () => {
  const doc = parse(`
sel:
- Image|endswith: a.exe
  User: bob
- Image|endswith: b.exe
list:
  - - x
    - y
  - z
empty:
after: 1
`);
  assert.deepEqual(doc.sel, [{ 'Image|endswith': 'a.exe', User: 'bob' }, { 'Image|endswith': 'b.exe' }]);
  assert.deepEqual(doc.list, [['x', 'y'], 'z']);
  assert.equal(doc.empty, null);
  assert.equal(doc.after, 1);
});

test('quoted scalars: escapes, doubled single quotes, # and : inside quotes', () => {
  const doc = parse(`
a: "tab\\there \\"q\\" \\u0041 \\x42"
b: 'it''s # not a comment: really'
c: "C:\\\\Windows\\\\"
d: plain value with # hash
e: 'x' # comment
`);
  assert.equal(doc.a, 'tab\there "q" A B');
  assert.equal(doc.b, "it's # not a comment: really");
  assert.equal(doc.c, 'C:\\Windows\\');
  assert.equal(doc.d, 'plain value with');
  assert.equal(doc.e, 'x');
});

test('block scalars | and > with chomping; multi-line plain scalars', () => {
  const doc = parse(`
lit: |
    line one
      indented
    line three
folded: >
    folded text
    continues here

    new paragraph
strip: |-
    no newline
keep: |+
    keep

next: value
multi: this is a long
    plain scalar
`);
  assert.equal(doc.lit, 'line one\n  indented\nline three\n');
  assert.equal(doc.folded, 'folded text continues here\nnew paragraph\n');
  assert.equal(doc.strip, 'no newline');
  assert.equal(doc.keep, 'keep\n\n');
  assert.equal(doc.next, 'value');
  assert.equal(doc.multi, 'this is a long plain scalar');
});

test('flow collections', () => {
  const doc = parse(`
tags: [attack.t1059, 'attack.execution', "x y"]
empty: []
map: {product: windows, service: 'security'}
nested: [a, [b, c], {k: v}]
`);
  assert.deepEqual(doc.tags, ['attack.t1059', 'attack.execution', 'x y']);
  assert.deepEqual(doc.empty, []);
  assert.deepEqual(doc.map, { product: 'windows', service: 'security' });
  assert.deepEqual(doc.nested, ['a', ['b', 'c'], { k: 'v' }]);
});

test('multiple documents', () => {
  const docs = parseAll('---\na: 1\n---\nb: 2\n...\n');
  assert.deepEqual(docs, [{ a: 1 }, { b: 2 }]);
  assert.deepEqual(parse('a: 1\n---\nb: 2'), { a: 1 });
});

test('unsupported / invalid YAML is reported with a line number', () => {
  assert.throws(() => parse('a: &anchor 1'), YamlError);
  assert.throws(() => parse('a: *alias'), /aliases/);
  assert.throws(() => parse('a: !!str 1'), /tags/);
  assert.throws(() => parse('a:\n\t- x'), /tabs/);
  assert.throws(() => parse('a: 1\na: 2'), /duplicate key "a"/);
  assert.throws(() => parse('a: [1, 2'), YamlError);
  assert.throws(() => parse('a: 1\n   b: 2'), /line 2/);
});
