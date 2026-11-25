// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Mimecast email security (API 2.0, read-only pull - collect/mimecast.js):
 *   GET  {P}/cloud/mimecast        settings (client ID / secret only as set / not set) + collector status        admin
 *   PUT  {P}/cloud/mimecast        {enabled, base_url, types[], poll_min, client_id?, client_secret?}            admin
 *   POST {P}/cloud/mimecast/test   sign in and read one SIEM batch answer (nothing downloaded or stored)        admin
 *   POST {P}/cloud/mimecast/sync   poll now                                                                    operator
 * config.json "mimecast" + secrets.json "mimecast.client_id / client_secret" (sealed at rest, write-only: never returned,
 * never logged, never audited). Applied at once: the collector is restarted in-process. Every change is audited.
 */
const fs = require('node:fs');
const SF = require('../secretfile');
const { body } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const MC = require('./mimecast');

function register(api, deps) {
  const P = prefixOf(deps), cfg = deps.config, writeJson = require('../onboard/store').writeJsonAtomic;
  const sec = () => (cfg.secrets && cfg.secrets.mimecast) || {};
  const view = () => {
    const c = cfg.mimecast || {};
    return { enabled: !!c.enabled, base_url: c.base_url || MC.DEFAULT_BASE, types: Array.isArray(c.types) && c.types.length ? c.types : MC.DEFAULT_TYPES, poll_min: c.poll_min || 15,
      client_id_set: !!sec().client_id, client_secret_set: !!sec().client_secret, known_types: MC.DEFAULT_TYPES, status: deps.mimecastStats ? deps.mimecastStats() : null };
  };
  const read = (p) => { try { if (SF.isSecretsPath(p)) return SF.read(p) || {}; return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw new HttpError(500, `cannot read ${p}`); } };

  api.route('GET', `${P}/cloud/mimecast`, wrap(deps, 'admin', () => view()));

  api.route('PUT', `${P}/cloud/mimecast`, wrap(deps, 'admin', async (ctx) => {
    const b = body(ctx.body).bool('enabled').str('base_url', { max: 200 }).list('types', { max: 15, item: 'str', itemMax: 40 }).int('poll_min', { min: 15, max: 240 })
      .str('client_id', { max: 200 }).str('client_secret', { max: 500 }).done();
    const paths = cfg._paths || {};
    if (!paths.config || !paths.secrets) throw new HttpError(409, 'config / secrets files not available');
    const c = Object.assign({}, cfg.mimecast || {});
    if (b.base_url !== undefined) { const u = b.base_url.replace(/\/+$/, ''); if (!MC.baseOk(u)) throw new HttpError(400, 'base_url: the Mimecast API 2.0 address, https on mimecast.com (for example ' + MC.DEFAULT_BASE + ')'); c.base_url = u; }
    if (b.types !== undefined) {
      const t = [...new Set(b.types.map((x) => x.toLowerCase().replace(/\s+/g, ' ').trim()))];
      const badT = t.filter((x) => !MC.TYPE_RE.test(x)); if (badT.length) throw new HttpError(400, 'types: lower-case letters and spaces only (for example "receipt", "url protect"): ' + badT.slice(0, 3).join(', '));
      if (!t.length) throw new HttpError(400, 'types: choose at least one log type');
      c.types = t;
    }
    if (b.poll_min !== undefined) c.poll_min = b.poll_min;
    if (b.enabled !== undefined) c.enabled = b.enabled;
    if (b.client_id !== undefined && /\s/.test(b.client_id)) throw new HttpError(400, 'client_id: no spaces');
    if (b.client_secret !== undefined && /\s/.test(b.client_secret)) throw new HttpError(400, 'client_secret: no spaces');
    const newId = b.client_id || '', newSecret = b.client_secret || '';
    if (c.enabled && !((newId || sec().client_id) && (newSecret || sec().client_secret))) throw new HttpError(400, 'enter the client ID and client secret to switch the Mimecast collector on');
    const file = read(paths.config); file.mimecast = Object.assign({}, file.mimecast || {}, c); writeJson(paths.config, file); cfg.mimecast = Object.assign(cfg.mimecast || {}, c);
    if (newId || newSecret) {
      const s = read(paths.secrets), m = Object.assign({}, s.mimecast || {}); if (newId) m.client_id = newId; if (newSecret) m.client_secret = newSecret;
      s.mimecast = m; writeJson(paths.secrets, s); if (cfg.secrets) cfg.secrets.mimecast = Object.assign(cfg.secrets.mimecast || {}, m);
    }
    let applied = false; if (deps.reloadMimecast) { await deps.reloadMimecast(); applied = true; }
    audit(ctx, 'cloud.mimecast.config', '', { enabled: !!c.enabled, base_host: new URL(c.base_url || MC.DEFAULT_BASE).hostname, types: (c.types || MC.DEFAULT_TYPES).length, poll_min: c.poll_min || 15, client_id_changed: !!newId, client_secret_changed: !!newSecret });
    return Object.assign(view(), { applied });
  }));

  api.route('POST', `${P}/cloud/mimecast/test`, wrap(deps, 'admin', async (ctx) => {
    body(ctx.body).done();   // nothing is accepted here: the test reads the saved settings
    if (!sec().client_id || !sec().client_secret) throw new HttpError(409, 'save the client ID and client secret first');
    const tmpCfg = { mimecast: Object.assign({}, cfg.mimecast || {}, { enabled: true }) }; Object.defineProperty(tmpCfg, 'secrets', { value: { mimecast: sec() } });
    const c = MC.start({ config: tmpCfg, parser: { parse: () => ({}) }, pipeline: { emit() {} }, log: deps.log, stateDir: '', fetchImpl: deps.mimecastFetch, autoStart: false });
    const r = await c.testConnection();
    audit(ctx, 'cloud.mimecast.test', '', { ok: r.ok, failed: (r.steps.find((s) => !s.ok) || {}).text ? 'yes' : 'no' });
    return Object.assign(r, { at: new Date().toISOString() });
  }));

  api.route('POST', `${P}/cloud/mimecast/sync`, wrap(deps, 'operator', async (ctx) => {
    body(ctx.body).done();
    if (!deps.mimecastPoll) throw new HttpError(409, 'the Mimecast collector is not running');
    if (!(cfg.mimecast && cfg.mimecast.enabled)) throw new HttpError(409, 'the Mimecast collector is switched off - an administrator switches it on in the Integration Hub');
    await deps.mimecastPoll();
    const st = deps.mimecastStats ? deps.mimecastStats() : {};
    audit(ctx, 'cloud.mimecast.sync', '', { records: st.records || 0, error: st.last_error ? 'yes' : 'no' });
    return st;
  }));
}

module.exports = { register };
