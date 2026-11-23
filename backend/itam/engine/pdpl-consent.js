// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Consent ledger for the AI PDPL Consultant (PDPL Arts. 5-6, Implementing Regulation Arts. 11-12, 28-29).
 *
 * The customer portal, the apps and the call-centre system SEND each consent and each withdrawal here; systems that act
 * on consent (marketing, profiling) CHECK it before processing. The ledger never sees the person's identity in clear:
 *   subject_ref = HMAC-SHA256(pepper, the identifier the system sends) - the pepper is random, sealed in the vault
 *   (purpose sentra-itam-consent) and never leaves the engine, so a reference cannot be reversed or matched elsewhere.
 * Events are append-only, one JSON line each in <store>/consent-YYYYMM.jsonl, hash-chained (prev + sha256) like the audit
 * journal: an edited or deleted line breaks verify(). The journal is the source of truth. Current state per (subject,
 * purpose) and the counters per purpose live in SQLite (<store>/pdpl-consent.sqlite, 0600) through the resident Python
 * service (pyengine/consent_db.py) - not in the engine's memory, so the ledger scales with the customer base. Every
 * database update carries the journal sequence it applies; when the database is behind the journal (first start after
 * the upgrade, or a crash between the two writes) the missing events are replayed from the journal before any answer.
 *
 * Purposes are PDPL records (kind consent_purpose: title, ropa_id, explicit, marketing, version) set by an administrator.
 * A grant must carry the purpose's CURRENT notice version (otherwise 409: collect again under the new notice) and, for an
 * explicit purpose, explicit:true. A withdrawal is ALWAYS accepted - on any channel, any version (Art. 12: as easy as
 * giving it). Consent keys (one per sending system, admin) are shown once and stored as sha256 only.
 *
 *   createConsent(app, { now, sealer, purposes(), py }) → { event, check, lookup, stats, verify, keys, issueKey, revokeKey, sync } (event / check / lookup / stats async)
 * Routes (registered by registerConsentRoutes):
 *   POST /agent/consent/events   Bearer consent key  {subject, purpose, action: grant|withdraw, channel, version?, explicit?, at?, evidence_ref?}
 *   GET  /agent/consent/check    Bearer consent key  ?subject&purpose  → {consented, version, at}
 *   GET  /pdpl/consent           operator   purposes with counts, keys (never the key), ledger integrity
 *   GET  /pdpl/consent/lookup    operator   ?subject  one person's consent history (for a data subject request; audited)
 *   POST /pdpl/consent/keys      admin      {name, purposes?} → the key, once        POST /pdpl/consent/keys/:id/revoke (admin)
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DAY = 86400000;
const GENESIS = '0'.repeat(64);
const CHANNELS = ['web', 'app', 'branch', 'call_centre', 'email', 'sms', 'paper', 'api'];
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function createConsent(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const dir = opts.dir || store.dir;
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || require('./discovery/vault').createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-consent' });
  const meta = () => store.collection('pdpl_consent_meta'), keysC = () => store.collection('pdpl_consent_keys');
  const dbPath = path.join(dir, 'pdpl-consent.sqlite');
  const pyBin = () => { const c = opts.python || dc.python_bin; return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((x) => fs.existsSync(x)) || 'python3'; };
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pyBin(), timeoutMs: 30000 }));
  async function db(op, body) {
    const r = await py().call(op, Object.assign({ db: dbPath }, body || {}));
    if (!r || r.ok === false) {
      if (app.log && app.log.every) app.log.every('pdpl:consent-db', 300000, 'error', 'consent database (Python / SQLite) did not answer', { op, cls: r && r.error_class, err: String((r && r.error) || '').slice(0, 200) });
      throw httpErr(503, 'the consent database is not available (' + ((r && r.error_class) || 'no answer') + ') - consents are still recorded in the journal; run the update so pyengine is installed');
    }
    return r;
  }
  const purposes = () => (opts.purposes ? opts.purposes() : []).filter((p) => p.status !== 'archived');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || 'system', ip: who.ip || '', action, target, detail }); };

  let pepperCache = null;
  function pepper() {
    if (pepperCache) return pepperCache;
    const m = meta().get('pepper');
    if (m && m.enc) { pepperCache = Buffer.from(sealer.unseal('consent-pepper', m.enc), 'hex'); return pepperCache; }
    const p = crypto.randomBytes(32);
    meta().put({ id: 'pepper', enc: sealer.seal('consent-pepper', p.toString('hex')), created_at: new Date(now()).toISOString() });
    pepperCache = p; return p;
  }
  // the identifier as systems send it (National ID, Iqama, customer number): trimmed, upper-case, no spaces
  const ref = (subject) => crypto.createHmac('sha256', pepper()).update(String(subject).replace(/\s+/g, '').toUpperCase()).digest('hex').slice(0, 40);

  // ---- append-only, hash-chained journal
  const file = (t) => path.join(dir, 'consent-' + new Date(t).toISOString().slice(0, 7).replace('-', '') + '.jsonl');
  const files = () => fs.readdirSync(dir).filter((f) => /^consent-\d{6}\.jsonl$/.test(f)).sort();
  function append(rec) {
    const head = meta().get('head') || { seq: 0, hash: GENESIS };
    const e = Object.assign({ seq: head.seq + 1, prev: head.hash }, rec);
    e.hash = sha256(e.prev + '\n' + JSON.stringify(Object.assign({}, e, { hash: undefined })));
    fs.appendFileSync(file(e.t), JSON.stringify(e) + '\n', { mode: 0o600 });
    meta().put({ id: 'head', seq: e.seq, hash: e.hash });
    return e;
  }
  function verify() {
    let prev = GENESIS, n = 0;
    for (const f of files()) {
      for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
        if (!line) continue;
        let e; try { e = JSON.parse(line); } catch (err) { return { ok: false, length: n, broken_at: n + 1, why: 'unreadable line in ' + f }; }
        n++;
        const h = sha256(e.prev + '\n' + JSON.stringify(Object.assign({}, e, { hash: undefined })));
        if (e.prev !== prev || h !== e.hash || e.seq !== n) return { ok: false, length: n, broken_at: n, why: 'entry ' + n + ' does not match the chain' };
        prev = e.hash;
      }
    }
    const head = meta().get('head');
    if (head && (head.seq !== n || head.hash !== prev)) return { ok: false, length: n, broken_at: n + 1, why: 'entries missing at the end (head ' + head.seq + ', found ' + n + ')' };
    return { ok: true, length: n };
  }

  // ---- the database follows the journal: replay what it has not applied yet (first start after the upgrade = migration)
  let synced = false, syncing = null;
  function journalAfter(seq, fn) {
    for (const f of files()) for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
      if (!line) continue;
      let e; try { e = JSON.parse(line); } catch (err) { continue; /* an unreadable line is reported by verify() */ }
      if (e.seq > seq) fn(e);
    }
  }
  async function sync() {
    if (synced) return { replayed: 0 };
    if (syncing) return syncing;
    syncing = (async () => {
      const head = (meta().get('head') || {}).seq || 0, last = (await db('consent.last')).last_seq;
      let replayed = 0;
      if (head > last) {
        let batch = [];
        const flush = async () => { if (batch.length) { replayed += (await db('consent.apply', { events: batch })).applied; batch = []; } };
        const all = []; journalAfter(last, (e) => all.push({ seq: e.seq, t: e.t, subject_ref: e.subject_ref, purpose: e.purpose, action: e.action, version: e.version, channel: e.channel }));
        for (const e of all) { batch.push(e); if (batch.length >= 2000) await flush(); }
        await flush();
        if (app.log && app.log.info) app.log.info('consent database caught up with the journal', { from: last, to: head, replayed });
        if (last === 0) migrated();
      }
      synced = true;
      return { replayed };
    })();
    try { return await syncing; } finally { syncing = null; }
  }
  // the state was kept in the store before the database: once the journal is replayed those copies are no longer read
  function migrated() {
    for (const m of meta().all((x) => /^c:/.test(String(x.id)))) meta().remove(m.id);
    const stamp = new Date(now()).toISOString().slice(0, 10);
    for (const f of ['pdpl_consent_state.jsonl', 'pdpl_consent_state.snap.json']) {
      const p = path.join(dir, f);
      try { if (fs.existsSync(p)) fs.renameSync(p, p + '.migrated-' + stamp); } catch (e) { if (app.log && app.log.warn) app.log.warn('old consent state file not renamed', { file: f, err: e.message }); }
    }
  }
  async function stats() {
    await sync();
    const cur = {}; for (const p of purposes()) cur[p.id] = Number(p.version || 1);
    return (await db('consent.stats', { purposes: cur, since_day: new Date(now() - 30 * DAY).toISOString().slice(0, 10) })).stats;
  }
  async function stateOf(sref, pids) { await sync(); return (await db('consent.get', { subject_ref: sref, purposes: pids })).state; }

  // ---- keys (one per sending system)
  function issueKey(b, who) {
    const key = 'ck_' + crypto.randomBytes(24).toString('hex'), n = keysC().size() + 1;
    let id = 'CK-' + String(n).padStart(3, '0'); while (keysC().get(id)) id = 'CK-' + String(Number(id.slice(3)) + 1).padStart(3, '0');
    keysC().put({ id, name: b.name, sha256: sha256(key), purposes: b.purposes && b.purposes.length ? b.purposes : null, created_by: who.user, created_at: new Date(now()).toISOString(), revoked_at: null });
    audit(who, 'pdpl.consent.key.issue', id, { name: b.name, purposes: b.purposes || 'all' });
    return { id, name: b.name, key, note: 'Shown once. Give it to the system that collects consent; it is stored as a hash only.' };
  }
  function revokeKey(id, who) {
    const k = keysC().get(id); if (!k) throw httpErr(404, 'no consent key ' + id);
    keysC().put(Object.assign({}, k, { revoked_at: new Date(now()).toISOString(), revoked_by: who.user }));
    audit(who, 'pdpl.consent.key.revoke', id, { name: k.name });
    return { id, revoked: true };
  }
  const keys = () => keysC().all().map((k) => ({ id: k.id, name: k.name, purposes: k.purposes, created_by: k.created_by, created_at: k.created_at, revoked_at: k.revoked_at, last_used: k.last_used || null }));
  function authenticate(bearer) {
    if (!bearer || !/^ck_[0-9a-f]{48}$/.test(bearer)) return null;
    const h = sha256(bearer);
    const k = keysC().all().find((x) => !x.revoked_at && crypto.timingSafeEqual(Buffer.from(x.sha256, 'hex'), Buffer.from(h, 'hex')));
    return k || null;
  }
  function purposeFor(k, pid) {
    const p = purposes().find((x) => x.id === pid);
    if (!p) throw httpErr(404, 'unknown consent purpose ' + pid);
    if (k.purposes && !k.purposes.includes(pid)) throw httpErr(403, 'this key may not record consent for ' + pid);
    return p;
  }

  // ---- the machine API
  async function event(k, b) {
    const p = purposeFor(k, b.purpose), t = now();
    const at = b.at ? Date.parse(b.at) : t;
    if (!Number.isFinite(at) || at > t + 300000 || at < t - 30 * DAY) throw httpErr(400, 'at must be within the last 30 days (and not in the future)');
    const version = b.version == null ? null : Number(b.version), current = Number(p.version || 1);
    if (b.action === 'grant') {
      if (version !== current) throw httpErr(409, 'consent for ' + p.id + ' must be collected under notice version ' + current + (version == null ? '' : ' (sent ' + version + ')'));
      if (p.explicit && b.explicit !== true) throw httpErr(400, p.id + ' needs explicit consent: send explicit:true only when the person actively agreed to this purpose');
    }
    const sref = ref(b.subject), cur = (await stateOf(sref, [p.id]))[p.id] || null;
    const e = append({ t: at, recorded: t, subject_ref: sref, purpose: p.id, action: b.action, version: b.action === 'grant' ? current : (cur ? cur.v : version), explicit: !!b.explicit, channel: b.channel, source: k.id, evidence_ref: b.evidence_ref || '' });
    // the journal holds the event; the database follows it (if this update fails the next call replays it)
    try { await db('consent.apply', { events: [{ seq: e.seq, t: e.t, subject_ref: e.subject_ref, purpose: e.purpose, action: e.action, version: e.version, channel: e.channel }] }); }
    catch (err) { synced = false; }
    keysC().put(Object.assign({}, k, { last_used: new Date(t).toISOString() }));
    return { receipt: 'CE-' + e.seq, purpose: p.id, consented: b.action === 'grant', version: e.version, at: new Date(at).toISOString() };
  }
  async function check(k, q) {
    const p = purposeFor(k, q.purpose), s0 = (await stateOf(ref(q.subject), [p.id]))[p.id];
    const ok = !!(s0 && s0.s === 'g' && Number(s0.v) === Number(p.version || 1));
    return { purpose: p.id, consented: ok, version: s0 ? s0.v : null, current_version: Number(p.version || 1), at: s0 ? new Date(s0.t).toISOString() : null,
      why: ok ? 'consent on record' : !s0 ? 'no consent on record' : s0.s === 'w' ? 'withdrawn' : 'given under an older notice - collect again' };
  }
  // one person's history, for a data subject request (the operator types the identifier; it is hashed the same way)
  async function lookup(subject, who) {
    const sref = ref(subject), hist = [];
    for (const f of files()) for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
      if (!line || line.indexOf(sref) < 0) continue;
      try { const e = JSON.parse(line); if (e.subject_ref === sref) hist.push({ receipt: 'CE-' + e.seq, at: new Date(e.t).toISOString(), purpose: e.purpose, action: e.action, version: e.version, explicit: e.explicit, channel: e.channel, source: e.source, evidence_ref: e.evidence_ref }); }
      catch (err) { /* an unreadable line is reported by verify(), not here */ }
    }
    const st = await stateOf(sref, purposes().map((p) => p.id));
    const current = purposes().map((p) => { const s0 = st[p.id]; return { purpose: p.id, title: p.title, status: s0 ? (s0.s === 'g' ? 'given' : 'withdrawn') : 'none', version: s0 ? s0.v : null, current_version: Number(p.version || 1) }; });
    audit(who, 'pdpl.consent.lookup', 'subject:' + sref.slice(0, 12), { events: hist.length });
    return { subject_ref: sref, current, history: hist.slice(-500), note: 'The identifier you typed is not stored; it is turned into the same one-way reference the ledger uses.' };
  }
  return { event, check, lookup, stats, sync, verify, keys, issueKey, revokeKey, authenticate, ref, CHANNELS, dbPath };
}

function registerConsentRoutes(srv, app, C, PD) {
  const { body } = require('./check');
  const SUBJ = { required: true, max: 64, re: /^[A-Za-z0-9 ._+@-]{3,64}$/, msg: 'subject must be the identifier the system uses (3-64 letters, digits, . _ + @ -)' };
  const PURP = { required: true, max: 60, re: /^PD-CONSENT_PURPOSE-\d{3,}$/, msg: 'purpose must be a consent purpose id (PD-CONSENT_PURPOSE-nnn)' };
  const key = (ctx) => { const k = C.authenticate(ctx.bearer()); if (!k) throw Object.assign(new Error('invalid or revoked consent key'), { status: 401 }); return k; };
  srv.route('POST', '/consent/events', (ctx) => {
    const k = key(ctx);
    const b = body(ctx.body).str('subject', SUBJ).str('purpose', PURP).oneOf('action', ['grant', 'withdraw'], { required: true }).oneOf('channel', C.CHANNELS, { required: true })
      .int('version', { min: 1, max: 1000 }).bool('explicit').str('at', { max: 30, re: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/, msg: 'at must be an ISO date-time with a zone' })
      .str('evidence_ref', { max: 120 }).done();
    return C.event(k, b);
  }, { agent: true });
  srv.route('GET', '/consent/check', (ctx) => {
    const k = key(ctx);
    const q = body(ctx.query || {}).str('subject', SUBJ).str('purpose', PURP).done();
    return C.check(k, q);
  }, { agent: true });
  srv.route('GET', '/pdpl/consent', async (ctx) => { ctx.need('operator'); return PD.consentView(); });
  srv.route('GET', '/pdpl/consent/lookup', (ctx) => {
    ctx.need('operator');
    const q = body(ctx.query || {}).str('subject', SUBJ).done();
    return C.lookup(q.subject, ctx.who);
  });
  srv.route('POST', '/pdpl/consent/keys', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).str('name', { required: true, max: 80 }).list('purposes', { max: 50, item: 'id' })
      .rule((o) => ((o.purposes || []).some((p) => !/^PD-CONSENT_PURPOSE-\d{3,}$/.test(p)) ? 'purposes must be consent purpose ids' : null)).done();
    return C.issueKey(b, ctx.who);
  });
  srv.route('POST', '/pdpl/consent/keys/:id/revoke', (ctx) => {
    ctx.need('admin');
    const { param } = require('./check');
    return C.revokeKey(param(ctx.params.id, 'id'), ctx.who);
  });
}

module.exports = { createConsent, registerConsentRoutes, CHANNELS };
