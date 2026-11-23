// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The test-only X.509 builder (tests/helpers/x509.js): DER integers are minimal. A random serial starting with 0x00 used to keep a
// superfluous leading zero, OpenSSL refused the certificate ("illegal padding") and the tests using the fake LDAPS server failed
// about once in 512 certificates. Fails without the fix: the fixed serials below are exactly the bad cases.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { build, uint, makeCA, makeServerCert } = require('./helpers/x509');

test('DER INTEGER is minimal: leading zeros stripped, one 0x00 only before a high bit', () => {
  assert.deepEqual([...uint(Buffer.from([0x00, 0x01, 0x02]))], [0x02, 0x02, 0x01, 0x02]);
  assert.deepEqual([...uint(Buffer.from([0x00, 0x00, 0x85]))], [0x02, 0x02, 0x00, 0x85]);
  assert.deepEqual([...uint(Buffer.from([0x85, 0x01]))], [0x02, 0x03, 0x00, 0x85, 0x01]);
  assert.deepEqual([...uint(Buffer.from([0x00]))], [0x02, 0x01, 0x00], 'zero stays one byte');
});

test('certificates with the serials that used to break parse, and a run of random ones all parse', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  for (const serial of [Buffer.from('00017f0000000000000000aa', 'hex'), Buffer.from('0000000000000000000001ff', 'hex'), Buffer.from('80aa00000000000000000001', 'hex')]) {
    const pem = build({ subject: 'syn', issuer: 'syn', pub: publicKey, signKey: privateKey, isCA: true, serial });
    assert.doesNotThrow(() => new crypto.X509Certificate(pem), 'serial ' + serial.toString('hex'));
  }
  const ca = makeCA();
  for (let i = 0; i < 40; i++) { const c = makeServerCert(ca); assert.ok(new crypto.X509Certificate(c.cert).verify(new crypto.X509Certificate(ca.cert).publicKey)); }
});
