// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Servers the AI Windows Server Administrator and AI Exchange Server Administrator look after, the WinRM logins they
 * use (write-only) and trusted WinRM HTTPS certificates.
 *   createTargets({ state, config, log, paths? })
 *     .list(role?) .get(id) .find(ref) .put(input, by) .remove(id, by)
 *     .profiles() → which logins are set (never values)   .setProfile(id, {username, password, auth} | null, by)
 *     .login(target, role) → {username, password, auth} (engine-internal)
 *     .pin(id) / .setPin(id, fingerprint, by) / .clearPin(id)
 * A server: { id, name, ip, roles: ['windows'] | ['windows','exchange'], site, criticality 1-3, winrm: {ssl, port},
 *   logins: {windows?: profileId, exchange?: profileId}, source: 'manual'|'itam', asset_id, detected_by, notes }.
 * Logins live in secrets.json "sysadmin.profiles.<id>" (mode 600, atomic). Default profiles: "windows" (Windows checks)
 * and "exchange" (Exchange checks); a server can name another profile per role.
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const net = require('node:net');
const { writeJsonAtomic } = require('../onboard/store');

const ROLES = ['windows', 'exchange'];
const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/, PID_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;
class TargetError extends Error { constructor(code, msg) { super(msg); this.code = code; this.errors = [msg]; } }
const clean = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, max);

function validate(input, ex) {
  const t = Object.assign({}, ex || {});
  if (!ex) { t.id = clean(input.id, 40).toLowerCase(); if (!ID_RE.test(t.id)) throw new TargetError(400, 'server id: 2-40 lowercase letters, digits and dashes'); }
  if (input.name !== undefined || !ex) t.name = clean(input.name || t.id, 80);
  if (input.ip !== undefined || !ex) { t.ip = clean(input.ip, 253); if (!net.isIP(t.ip) && !/^[a-z0-9][a-z0-9.-]{0,252}$/i.test(t.ip)) throw new TargetError(400, 'IP address or DNS name required'); }
  if (input.roles !== undefined || !ex) {
    const r = [...new Set((Array.isArray(input.roles) ? input.roles : [input.roles || 'windows']).map(String))];
    if (!r.length || r.some((x) => !ROLES.includes(x))) throw new TargetError(400, 'roles: windows and/or exchange');
    if (r.includes('exchange') && !r.includes('windows')) r.unshift('windows');   // an Exchange server is a Windows server
    t.roles = r;
  }
  if (input.site !== undefined || !ex) t.site = clean(input.site || 'Unassigned', 60);
  if (input.criticality !== undefined || !ex) { const c = Number(input.criticality || 2); t.criticality = c >= 1 && c <= 3 ? Math.round(c) : 2; }
  if (input.winrm !== undefined || !ex) {
    const w = input.winrm || {}, ssl = !!w.ssl, port = w.port === undefined || w.port === '' ? (ssl ? 5986 : 5985) : Number(w.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new TargetError(400, 'WinRM port must be 1-65535');
    t.winrm = { ssl, port };
  }
  if (input.logins !== undefined) { const l = {}; for (const r of ROLES) { const v = input.logins && input.logins[r]; if (v) { if (!PID_RE.test(String(v))) throw new TargetError(400, 'login profile id: 2-32 lowercase letters, digits and dashes'); l[r] = String(v); } } t.logins = l; }
  if (input.notes !== undefined) t.notes = clean(input.notes, 500);
  if (input.source !== undefined) t.source = input.source === 'itam' ? 'itam' : 'manual';
  if (input.asset_id !== undefined) t.asset_id = clean(input.asset_id, 80);
  if (input.detected_by !== undefined) t.detected_by = clean(input.detected_by, 120);
  if (input.poll !== undefined) t.poll = input.poll !== false;
  return t;
}

function createTargets({ state, config, log, paths } = {}) {
  if (!state) throw new Error('targets need state');
  const col = state.collection('sysadmin_targets'), pins = state.collection('sysadmin_certs');
  const secPath = (paths && paths.secrets) || (config && config._paths && config._paths.secrets);
  const L = log || { info() {}, warn() {} };
  const allProfiles = () => (config && config.secrets && config.secrets.sysadmin && config.secrets.sysadmin.profiles) || {};

  function setProfile(id, p, by) {
    if (!PID_RE.test(String(id || ''))) throw new TargetError(400, 'login profile id: 2-32 lowercase letters, digits and dashes');
    if (!secPath) throw new TargetError(500, 'secrets path unknown');
    let v = null;
    if (p) {
      if (!p.username || !p.password) throw new TargetError(400, 'user name and password required');
      if (!/^[A-Za-z0-9._@\\-]{1,104}$/.test(String(p.username))) throw new TargetError(400, 'user name: DOMAIN\\user or user@domain');
      v = { username: String(p.username), password: String(p.password).slice(0, 256), auth: ['negotiate', 'ntlm', 'kerberos'].includes(p.auth) ? p.auth : 'negotiate' };
    }
    let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    sec.sysadmin = sec.sysadmin || {}; sec.sysadmin.profiles = sec.sysadmin.profiles || {};
    if (v) sec.sysadmin.profiles[id] = v; else delete sec.sysadmin.profiles[id];
    writeJsonAtomic(secPath, sec);
    if (config && config.secrets) { config.secrets.sysadmin = config.secrets.sysadmin || {}; config.secrets.sysadmin.profiles = sec.sysadmin.profiles; }
    L.info('sysadmin login profile changed', { id, by, set: !!v });
    return profiles()[id] || null;
  }
  function profiles() { const o = {}; for (const [id, p] of Object.entries(allProfiles())) o[id] = { user: p.username, auth: p.auth || 'negotiate' }; return o; }

  return {
    ROLES,
    list: (role) => col.all((t) => !role || (t.roles || []).includes(role)).sort((a, b) => (a.site + a.name).localeCompare(b.site + b.name)),
    get: (id) => col.get(id) || null,
    find(ref) { const r = String(ref || '').toLowerCase(), all = col.all(); return all.find((t) => t.id === r) || all.find((t) => t.name.toLowerCase() === r) || all.find((t) => t.name.toLowerCase().split('.')[0] === r.split('.')[0]) || all.find((t) => t.ip === ref) || null; },
    put(input, by) {
      const ex = input && input.id ? col.get(String(input.id).toLowerCase()) : null;
      const t = validate(input || {}, ex);
      if (!ex && col.all().some((x) => x.ip === t.ip)) throw new TargetError(409, `${t.ip} is already in the list`);
      t.updated = Date.now(); t.updated_by = by || ''; if (!ex) { t.created = t.updated; t.source = t.source || 'manual'; t.poll = t.poll !== false; }
      col.put(t); return t;
    },
    remove(id, by) { if (!col.get(id)) throw new TargetError(404, 'server not found'); col.remove(id); pins.remove(id); L.info('sysadmin server removed', { id, by }); return { removed: id }; },
    profiles, setProfile,
    login(t, role) { const pid = (t.logins && t.logins[role]) || role, p = allProfiles()[pid]; return p ? Object.assign({ profile: pid }, p) : null; },
    loginSummary(t) { const o = {}; for (const r of t.roles || []) { const pid = (t.logins && t.logins[r]) || r, p = allProfiles()[pid]; o[r] = p ? `${pid}: ${p.username}` : null; } return o; },
    pin: (id) => { const p = pins.get(id); return p ? { fingerprint: p.fingerprint, by: p.by, at: p.at } : null; },
    setPin(id, fingerprint, by) { pins.put({ id, fingerprint, by: by || '', at: Date.now() }); return this.pin(id); },
    clearPin: (id) => pins.remove(id),
  };
}

module.exports = { createTargets, validate, ROLES, TargetError };
