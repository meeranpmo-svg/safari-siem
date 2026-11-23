// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Active Directory WRITES for HR onboarding - the only part of the platform that changes the directory, and only what an
 * approved onboarding request asked for. LDAPS (or StartTLS) with certificate verification always on, through the shared
 * read client (engine/discovery/ldap-client.js, kept identical to the SIEM's and the sign-in gate's copies): this module adds
 * the LDAP Add and Modify operations on its own connection object and changes nothing in the shared file.
 *
 * The bind account should be a dedicated service account DELEGATED on the joiners' OU only ("Create User objects", "Reset
 * password", write the listed attributes) and "write members" on the allowed groups - never a Domain Admin. AD refuses a
 * password over a connection that is not encrypted; this client never offers one.
 *
 *   createAdWriter({ servers, caFile | ca, bindDN, password, baseDN, timeoutMs, ldap })
 *     test()                                    bind, read the root DSE, check the OU exists -> { ok, server, ou }
 *     exists({ sam, upn })                      -> dn | null
 *     findGroup(nameOrDn)                       -> dn | null (a group inside baseDN)
 *     createUser(ou, attrs, password, marker)   -> { dn, existed } - created DISABLED (514) with the temporary password,
 *                                                  pwdLastSet = 0 (change at first sign-in); a retry after a dropped
 *                                                  connection finds its own object by the marker instead of writing twice
 *     addToGroup(groupDn, userDn)               member add (already a member = fine)
 *     setEnabled(dn, enabled)                   userAccountControl 512 / 514
 *     resetPassword(dn, password)               unicodePwd replace + pwdLastSet = 0
 *     unlock(dn)                                lockoutTime replace 0 - clears an account lockout (AD Management, after four-eyes
 *                                                  approval; the password is not touched)
 *     read(dn)                                  -> { dn, uac, enabled, must_change, member_of[], sam, upn, description, lockout_time (ISO or null),
 *                                                  locked } - locked from msDS-User-Account-Control-Computed (UF_LOCKOUT, which knows
 *                                                  when the lockout duration has run out) when AD gives it, else lockoutTime > 0
 *     findUser(sam)                             -> { dn, sam, upn, display_name, employee_id, enabled, member_of[], description, department, title,
 *                                                  last_logon (ISO or null), admin_count, lockout_time (ISO or null) } | null - for leavers
 *     describe(dn, text)                        description replace (the leaver record that disabled it)
 *     move(dn, parentDn)                        ModifyDN to another OU (the leavers OU) -> the new dn
 *     deleteUser(dn)                            LDAP Delete of one user object (AD Directory: only a disabled account, 30 days unchanged,
 *                                                  after four-eyes approval - engine/ad-manage.js decides; this only deletes) -> true
 *     removeFromGroup(groupDn, userDn)          member delete (not a member = fine) - for movers
 *     setAttrs(dn, { department, title, ... })  replace plain text attributes (an empty value clears it)
 *     groupMembers(nameOrDn, { nested? })       -> { dn, name, members: [{ dn, sam, upn, display_name, employee_id, enabled, last_logon,
 *                                                  manager_dn, admin_count }] } | null - direct user members (access reviews); nested: true =
 *                                                  members through nested groups too (LDAP_MATCHING_RULE_IN_CHAIN, as Entra ID counts them)
 *     directoryGroups({ q?, max? })             READ ONLY -> { groups: [{ dn, sam, name, description, sid, security, scope }], truncated }
 *                                                  - groups under baseDN, optionally whose name contains q (SSO access from AD)
 *     samsOf(dns[])                             -> { dn(lower-case): sAMAccountName } (the managers of those members)
 *     passwordSettings()                        READ ONLY -> { readable, items: [{ name, precedence, applies_to (count), min_length, history,
 *                                                  max_age_days, min_age_days, complexity, reversible, lockout_threshold, lockout_minutes,
 *                                                  lockout_window_minutes }] } - fine-grained password policies (PSOs) the bind account
 *                                                  may see; by default only Domain Admins may read them, so none seen proves nothing
 *     directoryUsers({ group?, max? })          READ ONLY -> { users: [{ dn, sam, upn, display_name, mail, department, title, enabled,
 *                                                  last_logon, admin_count, groups (count) }], truncated } - person accounts under baseDN
 *                                                  (or the direct members of one group), for Identity & Sign-in -> Directory users
 * Passwords are never logged and never returned; errors carry the LDAP result name, not the request.
 */
const real = require('./discovery/ldap-client');

const UAC_NORMAL = 0x200, UAC_DISABLED = 0x2, UF_LOCKOUT = 0x10;
const ATTR_OK = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;

function createAdWriter(o) {
  const L = o.ldap || real, B = L._ber;
  const { tlv, berStr, children, readInt, readStr } = B;
  const enumB = (n) => tlv(0x0a, Buffer.from([n]));
  const set = (vals) => tlv(0x31, vals.map((v) => berStr(v)));
  const pwd = (p) => Buffer.from('"' + String(p) + '"', 'utf16le');   // unicodePwd: the quoted password in UTF-16LE
  const client = L.createClient({ servers: o.servers, caFile: o.caFile, ca: o.ca, timeoutMs: o.timeoutMs || 15000, log: o.log });
  const err = (msg, extra) => Object.assign(new Error(msg), extra || {});

  // this connection also accepts ModifyResponse (0x67), AddResponse (0x69), DelResponse (0x6b) and ModifyDNResponse (0x6d); the rest as the shared client
  function extend(conn) {
    if (conn._adw) return conn;
    const orig = conn._dispatch.bind(conn);
    conn._dispatch = function (m) {
      if (m.tag === 0x67 || m.tag === 0x69 || m.tag === 0x6b || m.tag === 0x6d) {
        const k = children(m.buf, m.op);
        return this._finish(m.id, null, { code: readInt(m.buf, k[0]), matchedDN: readStr(m.buf, k[1]), diagnostic: readStr(m.buf, k[2]) });
      }
      return orig(m);
    };
    conn._adw = true;
    return conn;
  }
  const RES = L.RESULT || {};
  function check(op, r, ok) {
    if (r.code === 0 || (ok || []).includes(r.code)) return r;
    const ad = /\bdata ([0-9a-f]{3,8})\b/i.exec(r.diagnostic || '');
    throw err(op + ' refused by the directory: ' + (RES[r.code] || 'result ' + r.code) + ' (' + r.code + ')' + (r.diagnostic ? ' - ' + String(r.diagnostic).slice(0, 160) : ''), { ldapCode: r.code, adCode: ad ? ad[1] : '' });
  }
  async function session(fn) {
    return client.run(async (conn) => { extend(conn); await conn.bind(o.bindDN, o.password); return fn(conn); });
  }
  const add = (conn, dn, attrs) => conn._request(tlv(0x68, [berStr(dn), tlv(0x30, Object.entries(attrs).map(([k, v]) => {
    if (!ATTR_OK.test(k)) throw err('attribute name ' + k + ' is not valid');
    return tlv(0x30, [berStr(k), set([].concat(v))]);
  }))]));
  // changes: [[op 'add'|'delete'|'replace', attr, values[]]]
  const modify = (conn, dn, changes) => conn._request(tlv(0x66, [berStr(dn), tlv(0x30, changes.map(([op, k, v]) => tlv(0x30, [enumB({ add: 0, delete: 1, replace: 2 }[op]), tlv(0x30, [berStr(k), set([].concat(v))])])))]));
  const one = async (conn, base, filter, attributes, scope) => { const r = await conn.search(base, { scope: scope || 'sub', filter, attributes, sizeLimit: 2 }); return r.entries[0] || null; };
  const esc = L.escapeFilter;

  return {
    async test(ou) {
      return session(async (conn) => {
        const ent = ou ? await one(conn, ou, '(objectClass=organizationalUnit)', ['ou'], 'base').catch(() => null) : null;
        return { ok: true, server: conn.server && conn.server.url, ou: ou ? !!ent : null };
      });
    },
    async exists({ sam, upn }) {
      return session(async (conn) => {
        const f = '(|' + (sam ? '(sAMAccountName=' + esc(sam) + ')' : '') + (upn ? '(userPrincipalName=' + esc(upn) + ')' : '') + ')';
        const e = await one(conn, o.baseDN, f, ['distinguishedName']);
        return e ? e.dn : null;
      });
    },
    async findGroup(name) {
      return session(async (conn) => {
        const isDn = /^cn=/i.test(name);
        const e = isDn ? await one(conn, name, '(objectClass=group)', ['cn'], 'base').catch(() => null) : await one(conn, o.baseDN, '(&(objectClass=group)(sAMAccountName=' + esc(name) + '))', ['cn']);
        return e ? e.dn : null;
      });
    },
    async createUser(ou, a, password, marker) {
      const dn = 'CN=' + L.escapeDN(a.displayName || a.sAMAccountName) + ',' + ou;
      const attrs = { objectClass: ['top', 'person', 'organizationalPerson', 'user'], sAMAccountName: a.sAMAccountName, userPrincipalName: a.userPrincipalName,
        displayName: a.displayName, description: marker, userAccountControl: String(UAC_NORMAL | UAC_DISABLED) };
      for (const k of ['givenName', 'sn', 'department', 'title', 'employeeID', 'physicalDeliveryOfficeName', 'company']) if (a[k]) attrs[k] = a[k];
      return session(async (conn) => {
        const r = await add(conn, dn, Object.assign({}, attrs, { unicodePwd: pwd(password) }));
        if (r.code === 68) {   // already there: ours (a retry after a dropped connection) or someone else's
          const e = await one(conn, dn, '(objectClass=user)', ['description', 'sAMAccountName'], 'base');
          if (!e || (e.attrs.description || [])[0] !== marker) throw err('an account named ' + dn + ' already exists in the directory and was not created by this request', { ldapCode: 68 });
          await modify(conn, dn, [['replace', 'unicodePwd', [pwd(password)]]]).then((x) => check('password', x));
          await modify(conn, dn, [['replace', 'pwdLastSet', ['0']]]).then((x) => check('must-change', x));
          return { dn, existed: true };
        }
        check('create', r);
        check('must-change', await modify(conn, dn, [['replace', 'pwdLastSet', ['0']]]));
        return { dn, existed: false };
      });
    },
    async addToGroup(groupDn, userDn) {
      return session(async (conn) => { check('group ' + groupDn, await modify(conn, groupDn, [['add', 'member', [userDn]]]), [68]); return true; });   // 68: already a member
    },
    async removeFromGroup(groupDn, userDn) {
      return session(async (conn) => { check('group ' + groupDn, await modify(conn, groupDn, [['delete', 'member', [userDn]]]), [16, 53]); return true; });   // 16 / 53: not a member
    },
    async setAttrs(dn, attrs) {
      const ch = Object.entries(attrs).filter(([k]) => ATTR_OK.test(k) && !/^(unicodePwd|userAccountControl|member|memberOf|objectClass|sAMAccountName|userPrincipalName)$/i.test(k))
        .map(([k, v]) => (v === '' || v == null ? ['delete', k, []] : ['replace', k, [String(v)]]));
      if (!ch.length) return true;
      return session(async (conn) => { check('attributes', await modify(conn, dn, ch), [16]); return true; });
    },
    async setEnabled(dn, enabled) {
      return session(async (conn) => { check(enabled ? 'enable' : 'disable', await modify(conn, dn, [['replace', 'userAccountControl', [String(UAC_NORMAL | (enabled ? 0 : UAC_DISABLED))]]])); return true; });
    },
    async resetPassword(dn, password) {
      return session(async (conn) => {
        check('password', await modify(conn, dn, [['replace', 'unicodePwd', [pwd(password)]]]));
        check('must-change', await modify(conn, dn, [['replace', 'pwdLastSet', ['0']]]));
        return true;
      });
    },
    async unlock(dn) {
      return session(async (conn) => { check('unlock', await modify(conn, dn, [['replace', 'lockoutTime', ['0']]])); return true; });
    },
    async passwordSettings() {
      const span = (v, unit) => { if (v === undefined || v === null || v === '') return null; let b; try { b = BigInt(v); } catch (e) { return null; /* not a number: not readable */ }
        if (b === 0n || b <= -9223372036854775000n) return 0; return Math.round(Number(-b) / 1e7 / unit); };
      return session(async (conn) => {
        const base = 'CN=Password Settings Container,CN=System,' + o.baseDN;
        let r;
        try { r = await conn.search(base, { scope: 'one', filter: '(objectClass=msDS-PasswordSettings)', pageSize: 200, maxEntries: 200,
          attributes: ['cn', 'msDS-PasswordSettingsPrecedence', 'msDS-PSOAppliesTo', 'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength', 'msDS-MaximumPasswordAge', 'msDS-MinimumPasswordAge',
            'msDS-PasswordComplexityEnabled', 'msDS-PasswordReversibleEncryptionEnabled', 'msDS-LockoutThreshold', 'msDS-LockoutDuration', 'msDS-LockoutObservationWindow'] }); }
        catch (e) { if (e.transport) throw e; return { readable: false, items: [], error: String(e.message).slice(0, 160) }; }
        const f = (e, k) => (e.attrs[k.toLowerCase()] || [])[0];
        const int = (v) => (v === undefined || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
        const bool = (v) => (v === undefined ? null : String(v).toUpperCase() === 'TRUE');
        return { readable: true, items: r.entries.map((e) => ({ name: f(e, 'cn') || cnOfDn(e.dn), precedence: int(f(e, 'msDS-PasswordSettingsPrecedence')), applies_to: (e.attrs['msds-psoappliesto'] || []).length,
          min_length: int(f(e, 'msDS-MinimumPasswordLength')), history: int(f(e, 'msDS-PasswordHistoryLength')), max_age_days: span(f(e, 'msDS-MaximumPasswordAge'), 86400), min_age_days: span(f(e, 'msDS-MinimumPasswordAge'), 86400),
          complexity: bool(f(e, 'msDS-PasswordComplexityEnabled')), reversible: bool(f(e, 'msDS-PasswordReversibleEncryptionEnabled')), lockout_threshold: int(f(e, 'msDS-LockoutThreshold')),
          lockout_minutes: span(f(e, 'msDS-LockoutDuration'), 60), lockout_window_minutes: span(f(e, 'msDS-LockoutObservationWindow'), 60) })) };
      });
    },
    async findUser(sam) {
      return session(async (conn) => {
        const e = await one(conn, o.baseDN, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=' + esc(sam) + '))',
          ['sAMAccountName', 'userPrincipalName', 'displayName', 'employeeID', 'userAccountControl', 'memberOf', 'description', 'lastLogonTimestamp', 'adminCount', 'department', 'title', 'whenChanged', 'mail', 'lockoutTime']);
        if (!e) return null;
        const f = (k) => (e.attrs[k.toLowerCase()] || [])[0] || '';
        const uac = parseInt(f('userAccountControl'), 10) || 0, ll = f('lastLogonTimestamp');
        const llms = /^\d{11,}$/.test(ll) && ll !== '0' ? Math.round(Number(ll) / 10000 - 11644473600000) : null;   // FILETIME -> ms
        return { dn: e.dn, sam: f('sAMAccountName'), upn: f('userPrincipalName'), display_name: f('displayName'), employee_id: f('employeeID'), uac, enabled: !(uac & UAC_DISABLED),
          member_of: e.attrs.memberof || [], description: f('description'), department: f('department'), title: f('title'), last_logon: llms ? new Date(llms).toISOString() : null, admin_count: f('adminCount') === '1',
          mail: f('mail'), when_changed: genTime(f('whenChanged')), lockout_time: fileTime(f('lockoutTime')) };
      });
    },
    async directoryUsers(q) {
      const max = Math.max(1, Math.min(50000, (q && q.max) || 20000));
      return session(async (conn) => {
        let filter = '(&(objectCategory=person)(objectClass=user))';
        if (q && q.group) {
          const isDn = /^cn=/i.test(q.group);
          const g = isDn ? await one(conn, q.group, '(objectClass=group)', ['cn'], 'base').catch(() => null) : await one(conn, o.baseDN, '(&(objectClass=group)(sAMAccountName=' + esc(q.group) + '))', ['cn']);
          if (!g) throw err('group ' + q.group + ' was not found in the directory');
          filter = '(&(objectCategory=person)(objectClass=user)(memberOf=' + esc(g.dn) + '))';
        }
        const r = await conn.search(o.baseDN, { scope: 'sub', filter, pageSize: 500, maxEntries: max,
          attributes: ['sAMAccountName', 'userPrincipalName', 'displayName', 'mail', 'department', 'title', 'userAccountControl', 'lastLogonTimestamp', 'adminCount', 'memberOf'] });
        const f = (e, k) => (e.attrs[k.toLowerCase()] || [])[0] || '';
        return { truncated: r.entries.length >= max, users: r.entries.map((e) => {
          const uac = parseInt(f(e, 'userAccountControl'), 10) || 0, ll = f(e, 'lastLogonTimestamp');
          const llms = /^\d{11,}$/.test(ll) && ll !== '0' ? Math.round(Number(ll) / 10000 - 11644473600000) : null;
          return { dn: e.dn, sam: f(e, 'sAMAccountName'), upn: f(e, 'userPrincipalName'), display_name: f(e, 'displayName'), mail: f(e, 'mail'), department: f(e, 'department'), title: f(e, 'title'),
            enabled: !(uac & UAC_DISABLED), last_logon: llms ? new Date(llms).toISOString() : null, admin_count: f(e, 'adminCount') === '1', groups: (e.attrs.memberof || []).length };
        }) };
      });
    },
    async directoryGroups(q) {
      const max = Math.max(1, Math.min(5000, (q && q.max) || 2000)), text = q && q.q ? String(q.q) : '';
      return session(async (conn) => {
        const filter = text ? '(&(objectClass=group)(|(sAMAccountName=*' + esc(text) + '*)(cn=*' + esc(text) + '*)))' : '(objectClass=group)';
        const r = await conn.search(o.baseDN, { scope: 'sub', filter, pageSize: 500, maxEntries: max, attributes: ['sAMAccountName', 'cn', 'description', 'objectSid', 'groupType'] });
        const f = (e, k) => (e.attrs[k.toLowerCase()] || [])[0] || '';
        const sidOf = (e) => { const b = (e.raw && e.raw.objectsid || [])[0]; return b && L.ad && L.ad.sidToString ? L.ad.sidToString(b) : ''; };
        return { truncated: r.entries.length >= max, groups: r.entries.map((e) => { const gt = parseInt(f(e, 'groupType'), 10) || 0;
          return { dn: e.dn, sam: f(e, 'sAMAccountName'), name: f(e, 'cn') || f(e, 'sAMAccountName'), description: f(e, 'description'), sid: sidOf(e),
            security: (gt & 0x80000000) !== 0, scope: gt & 0x8 ? 'universal' : gt & 0x4 ? 'domain-local' : gt & 0x2 ? 'global' : gt & 0x1 ? 'builtin' : '' }; }) };
      });
    },
    async groupMembers(name, gopt) {
      const chain = !!(gopt && gopt.nested), IN_CHAIN = (L.ad && L.ad.IN_CHAIN) || '1.2.840.113556.1.4.1941';
      return session(async (conn) => {
        const isDn = /^cn=/i.test(name);
        const g = isDn ? await one(conn, name, '(objectClass=group)', ['cn', 'sAMAccountName'], 'base').catch(() => null) : await one(conn, o.baseDN, '(&(objectClass=group)(sAMAccountName=' + esc(name) + '))', ['cn', 'sAMAccountName']);
        if (!g) return null;
        const r = await conn.search(o.baseDN, { scope: 'sub', filter: '(&(objectCategory=person)(objectClass=user)(memberOf' + (chain ? ':' + IN_CHAIN + ':' : '') + '=' + esc(g.dn) + '))', pageSize: 500, maxEntries: 20000,
          attributes: ['sAMAccountName', 'userPrincipalName', 'displayName', 'employeeID', 'userAccountControl', 'lastLogonTimestamp', 'manager', 'adminCount'] });
        const f = (e, k) => (e.attrs[k.toLowerCase()] || [])[0] || '';
        return { dn: g.dn, name: f(g, 'sAMAccountName') || f(g, 'cn'), members: r.entries.map((e) => {
          const uac = parseInt(f(e, 'userAccountControl'), 10) || 0, ll = f(e, 'lastLogonTimestamp');
          const llms = /^\d{11,}$/.test(ll) ? Math.round(Number(ll) / 10000 - 11644473600000) : null;
          return { dn: e.dn, sam: f(e, 'sAMAccountName'), upn: f(e, 'userPrincipalName'), display_name: f(e, 'displayName'), employee_id: f(e, 'employeeID'), enabled: !(uac & UAC_DISABLED),
            last_logon: llms ? new Date(llms).toISOString() : null, manager_dn: f(e, 'manager') || null, admin_count: f(e, 'adminCount') === '1' };
        }) };
      });
    },
    async samsOf(dns) {
      return session(async (conn) => {
        const out = {};
        for (const dn of [...new Set(dns.filter(Boolean))].slice(0, 2000)) {
          const e = await one(conn, dn, '(objectClass=user)', ['sAMAccountName'], 'base').catch(() => null);
          if (e) out[dn.toLowerCase()] = (e.attrs.samaccountname || [])[0] || '';
        }
        return out;
      });
    },
    async describe(dn, text) {
      return session(async (conn) => { check('description', await modify(conn, dn, [['replace', 'description', [String(text).slice(0, 1024)]]])); return true; });
    },
    async move(dn, parent) {
      const rdn = /^((?:[^,\\]|\\.)+),/.exec(dn); if (!rdn) throw err('cannot read the name of ' + dn);
      return session(async (conn) => {
        // ModifyDNRequest: entry, newrdn, deleteoldrdn TRUE, newSuperior [0]
        check('move', await conn._request(tlv(0x6c, [berStr(dn), berStr(rdn[1]), tlv(0x01, Buffer.from([0xff])), tlv(0x80, Buffer.from(parent, 'utf8'))])));
        return rdn[1] + ',' + parent;
      });
    },
    async deleteUser(dn) {
      if (!/^CN=/i.test(String(dn || ''))) throw err('only a user object (CN=...) can be deleted');
      // DelRequest: [APPLICATION 10] primitive, the DN itself
      return session(async (conn) => { check('delete', await conn._request(tlv(0x4a, Buffer.from(String(dn), 'utf8')))); return true; });
    },
    async read(dn) {
      return session(async (conn) => {
        const e = await one(conn, dn, '(objectClass=user)', ['userAccountControl', 'pwdLastSet', 'memberOf', 'sAMAccountName', 'userPrincipalName', 'description', 'lockoutTime', 'msDS-User-Account-Control-Computed'], 'base');
        if (!e) return null;
        const uac = parseInt((e.attrs.useraccountcontrol || [])[0], 10) || 0, lt = fileTime((e.attrs.lockouttime || [])[0]);
        const comp = (e.attrs['msds-user-account-control-computed'] || [])[0];
        return { dn: e.dn, uac, enabled: !(uac & UAC_DISABLED), must_change: String((e.attrs.pwdlastset || [])[0]) === '0', member_of: e.attrs.memberof || [],
          sam: (e.attrs.samaccountname || [])[0] || '', upn: (e.attrs.userprincipalname || [])[0] || '', description: (e.attrs.description || [])[0] || '',
          lockout_time: lt, locked: comp !== undefined && /^\d+$/.test(String(comp)) ? !!(parseInt(comp, 10) & UF_LOCKOUT) : !!lt };
      });
    },
  };
}

// AD GeneralizedTime (20261112093000.0Z) -> ISO, or null
function genTime(v) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(String(v || ''));
  return m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6])).toISOString() : null;
}

// AD FILETIME (100-ns intervals since 1601) -> ISO, or null for 0 / never / unreadable
function fileTime(v) {
  const s = String(v || '');
  if (!/^\d{11,}$/.test(s)) return null;
  const ms = Math.round(Number(s) / 10000 - 11644473600000);
  return ms > 0 ? new Date(ms).toISOString() : null;
}
const cnOfDn = (dn) => { const m = /^CN=((?:[^,\\]|\\.)+)/i.exec(String(dn || '')); return m ? m[1] : String(dn || ''); };

// a temporary password AD accepts under the default complexity rules: 16 characters, all four classes, no look-alikes
function tempPassword(rand) {
  const R = rand || require('node:crypto').randomInt;
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#$%*-_=+?'];
  const all = sets.join(''), out = sets.map((s) => s[R(s.length)]);
  while (out.length < 16) out.push(all[R(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = R(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join('');
}

module.exports = { createAdWriter, tempPassword, fileTime };
