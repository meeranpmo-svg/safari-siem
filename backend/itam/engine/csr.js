// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Private key + PKCS#10 certificate signing request, Node.js crypto only (no OpenSSL call, no dependency). The DER is
 * assembled by hand: CertificationRequestInfo { version 0, subject CN, SubjectPublicKeyInfo, [0] extensionRequest {
 * subjectAltName } }, signed with SHA-256 (RSA, EC P-256) or SHA-384 (EC P-384). The private key is returned as PKCS#8
 * PEM for the caller to SEAL at once; it is never logged.
 *   newKey({type: 'rsa'|'ec', bits}) → {privateKey (KeyObject), keyPem}
 *   buildCsr(privateKey, names[], {o?}) → {der (Buffer), pem}
 *   inspectCert(pem, privateKey?) → facts of an issued certificate (names, validity, issuer, key match, chain)
 */
const crypto = require('node:crypto');

function len(n) { if (n < 128) return Buffer.from([n]); const b = []; while (n > 0) { b.unshift(n & 255); n = Math.floor(n / 256); } return Buffer.from([0x80 | b.length].concat(b)); }
function der(tag, ...parts) { const c = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), len(c.length), c]); }
const seq = (...p) => der(0x30, ...p), set = (...p) => der(0x31, ...p);
function oid(s) {
  const a = s.split('.').map(Number), out = [40 * a[0] + a[1]];
  for (const n of a.slice(2)) { const b = [n & 0x7f]; let v = Math.floor(n / 128); while (v > 0) { b.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); } out.push(...b); }
  return der(0x06, Buffer.from(out));
}
const IP_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const NAME_RE = /^(\*\.)?(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$/;

function newKey({ type = 'rsa', bits = 2048 } = {}) {
  let k;
  if (type === 'ec') { if (![256, 384].includes(bits)) throw new Error('EC keys are P-256 or P-384'); k = crypto.generateKeyPairSync('ec', { namedCurve: bits === 256 ? 'prime256v1' : 'secp384r1' }); }
  else { if (![2048, 3072, 4096].includes(bits)) throw new Error('RSA keys are 2048, 3072 or 4096 bits'); k = crypto.generateKeyPairSync('rsa', { modulusLength: bits }); }
  return { privateKey: k.privateKey, keyPem: k.privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

function sigAlg(privateKey) {
  const t = privateKey.asymmetricKeyType;
  if (t === 'rsa') return { hash: 'sha256', alg: seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00])) };
  if (t === 'ec') { const c = privateKey.asymmetricKeyDetails && privateKey.asymmetricKeyDetails.namedCurve; return c === 'secp384r1' ? { hash: 'sha384', alg: seq(oid('1.2.840.10045.4.3.3')) } : { hash: 'sha256', alg: seq(oid('1.2.840.10045.4.3.2')) }; }
  throw new Error('unsupported key type ' + t);
}

function buildCsr(privateKey, names, opts = {}) {
  if (!names || !names.length) throw new Error('at least one name is needed');
  for (const n of names) if (!(NAME_RE.test(n) || IP_RE.test(n))) throw new Error('not a host name or IPv4 address: ' + String(n).slice(0, 80));
  const pub = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const rdn = [set(seq(oid('2.5.4.3'), der(0x0c, Buffer.from(names[0], 'utf8'))))];
  if (opts.o) rdn.unshift(set(seq(oid('2.5.4.10'), der(0x0c, Buffer.from(String(opts.o).slice(0, 64), 'utf8')))));
  const subject = seq(...rdn);
  const gn = names.map((n) => (IP_RE.test(n) ? der(0x87, Buffer.from(n.split('.').map(Number))) : der(0x82, Buffer.from(n.toLowerCase(), 'ascii'))));
  const san = seq(oid('2.5.29.17'), der(0x04, seq(...gn)));
  const attrs = der(0xa0, seq(oid('1.2.840.113549.1.9.14'), set(seq(san))));
  const cri = seq(der(0x02, Buffer.from([0])), subject, pub, attrs);
  const s = sigAlg(privateKey);
  const sig = crypto.sign(s.hash, cri, privateKey);
  const out = seq(cri, s.alg, der(0x03, Buffer.concat([Buffer.from([0]), sig])));
  return { der: out, pem: '-----BEGIN CERTIFICATE REQUEST-----\n' + out.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE REQUEST-----\n' };
}

function splitPem(bundle) { return String(bundle || '').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || []; }
// facts about an issued certificate (and its chain) for the rules to judge; privateKey → does it belong to our key
function inspectCert(bundle, privateKey) {
  const pems = splitPem(bundle); if (!pems.length) return { ok: false, error: 'no PEM certificate found' };
  let x; try { x = new crypto.X509Certificate(pems[0]); } catch (e) { return { ok: false, error: 'not a valid certificate: ' + String(e.message).slice(0, 120) }; }
  const names = String(x.subjectAltName || '').split(/,\s*/).map((s) => s.replace(/^(DNS|IP Address):/, '').toLowerCase()).filter(Boolean);
  let keyMatch = null; if (privateKey) { try { keyMatch = x.checkPrivateKey(privateKey); } catch (e) { keyMatch = false; } }
  const chain = pems.slice(1).map((p) => { try { return new crypto.X509Certificate(p).subject.replace(/\n/g, ', '); } catch (e) { return 'unreadable'; } });
  return { ok: true, names, subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), not_before: Date.parse(x.validFrom), not_after: Date.parse(x.validTo), serial: x.serialNumber,
    fingerprint256: x.fingerprint256, key_match: keyMatch, self_signed: x.issuer === x.subject, chain, leaf_pem: pems[0], chain_pem: pems.slice(1).join('\n') };
}

module.exports = { newKey, buildCsr, inspectCert, splitPem, NAME_RE, IP_RE, _der: { der, seq, set, oid } };
