// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Connection-test diagnostics for the credential vault + Connect Wizard.
 * One place that turns a connector outcome into a CLEAR, CLASSIFIED, ACTIONABLE result the UI shows:
 *   { ok, latency_ms, error_class, stage, http, tls:{trusted, pinned, presented}, message, hint, discovered? }
 * Before this, every connector collapsed failures to error_class 'auth' / generic text, so a TLS problem read as an
 * auth problem (a real support case: an admin spent an hour on a vCenter TLS error thinking the password was wrong).
 *
 *   result(kind, { ok, latency_ms, pin, trusted, http, discovered })      → success result
 *   fromError(kind, err, { latency_ms, pin })                             → classified failure result
 * The connector throws Error objects carrying: code (auth|authz|timeout|unreachable|tls|config|protocol), optional
 * stage, http (status), tlsTrusted (handshake succeeded), and — from httpc on TLS failures — presented / pinMismatch.
 * error_class keeps the existing vocabulary (auth/timeout/unreachable/tls/config/protocol/not_supported); 'authz' is
 * added for "authenticated but not authorised to read". Messages are the English canon (the UI re-localises by
 * stage+error_class+http for Arabic); callers/tests may rely on error_class unchanged.
 */
const CLASSES = ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol', 'not_supported'];
const SYS = { proxmox: 'Proxmox VE', vcenter: 'vCenter', esxi: 'the ESXi host', cucm_axl: 'CUCM', ldap: 'the directory', azure: 'Azure', aws: 'AWS' };

function classOf(code) { return CLASSES.indexOf(code) >= 0 ? code : 'protocol'; }
function stageOf(code, given) {
  if (given) return given;
  if (code === 'tls') return 'tls';
  if (code === 'auth') return 'auth';
  if (code === 'authz') return 'authz';
  if (code === 'timeout' || code === 'unreachable') return 'connect';
  if (code === 'not_supported') return 'none';
  return code === 'config' ? 'config' : 'protocol';
}

// kind-specific extra line for the credential-rejected (auth) case — the #1 misdiagnosis
function authHint(kind) {
  if (kind === 'vcenter') return 'Check: the user name is in full SSO form (for example administrator@vsphere.local, not a bare name), the account is not locked, and the password is current.';
  if (kind === 'ldap') return 'Check: the bind DN and password are correct (LDAP result 49, invalidCredentials), the account is not locked, and the password is current.';
  if (kind === 'cucm_axl') return 'Check: the AXL user name and password are correct, the account is not locked, and the user has the Standard AXL Read Only API Access role.';
  return 'Check the user name and password and that the account is not locked.';
}
function authzHint(kind) {
  if (kind === 'vcenter') return 'Assign the service account a read-only role in vCenter (the built-in Read-only role is enough).';
  if (kind === 'ldap') return 'Grant the bind account permission to read the search base.';
  if (kind === 'cucm_axl') return 'Grant the AXL user the Standard AXL Read Only API Access role.';
  if (kind === 'azure') return 'Assign the app registration the built-in Reader role on the subscriptions.';
  if (kind === 'aws') return 'Grant the IAM principal ec2:DescribeInstances.';
  return 'Assign the account read-only access to the system.';
}

function texts(kind, code, stage, http) {
  const sys = SYS[kind] || 'the system';
  if (code === 'tls') {
    if (stage === 'pin-mismatch') return { message: 'TLS: the presented certificate does not match the approved pin.', hint: 'The appliance certificate changed, or this is not the host you pinned. Confirm the new certificate is genuine before re-pinning.' };
    return { message: 'TLS: certificate not trusted — review and pin the certificate below.', hint: 'This is a TLS / certificate problem, not a login problem. Check the presented certificate (subject, issuer, validity, SHA-256 fingerprint); if it is the correct appliance certificate, pin it.' };
  }
  if (code === 'auth') return { message: `TLS OK (certificate trusted); ${sys} rejected the credentials (HTTP ${http || 401}).`, hint: authHint(kind) };
  if (code === 'authz') return { message: `Authenticated, but the account lacks a required read privilege (HTTP ${http || 403}).`, hint: authzHint(kind) };
  if (code === 'timeout') return { message: `Timed out waiting for ${sys} to respond.`, hint: 'Check the host and port, the firewall path from the platform server, and that the service is running.' };
  if (code === 'unreachable') return { message: `Could not reach ${sys} (connection failed).`, hint: 'Check the host / IP and port and the network path from the platform server.' };
  if (code === 'config') return { message: `Connection settings are invalid for ${sys}.`, hint: 'Check the URL / host, port and CA file path.' };
  if (code === 'not_supported') return { message: 'This credential type is stored for future use and is not tested.', hint: null };
  return { message: `${sys} answered, but not as expected.`, hint: 'The endpoint responded but not in the expected way — verify the URL / path and the system version.' };
}

function result(kind, o = {}) {
  return {
    ok: true,
    latency_ms: o.latency_ms == null ? null : o.latency_ms,
    error_class: null,
    stage: 'read',
    http: o.http == null ? null : o.http,
    tls: { trusted: true, pinned: !!o.pin, presented: o.presented || null },
    message: o.message || `Connected to ${SYS[kind] || 'the system'}.`,
    hint: null,
    discovered: o.discovered || null,
  };
}

function fromError(kind, err, o = {}) {
  const e = err || {};
  const code = classOf(e.code);
  const presented = e.presented || null;
  const stage = code === 'tls' && e.pinMismatch ? 'pin-mismatch' : stageOf(code, e.stage);
  const t = texts(kind, code, stage, e.http);
  const trusted = code === 'auth' || code === 'authz' ? true : code === 'tls' ? false : !!e.tlsTrusted;
  return {
    ok: false,
    latency_ms: o.latency_ms == null ? null : o.latency_ms,
    error_class: code,
    stage: stage === 'pin-mismatch' ? 'tls' : stage,
    http: e.http == null ? null : e.http,
    tls: { trusted, pinned: !!o.pin, presented, pin_mismatch: !!e.pinMismatch },
    message: t.message,
    hint: t.hint,
    discovered: null,
  };
}

// make an Error the connectors can throw with the diagnostic fields attached
function err(code, message, extra) { return Object.assign(new Error(message || code), { code }, extra || {}); }

module.exports = { result, fromError, err, CLASSES, SYS };
