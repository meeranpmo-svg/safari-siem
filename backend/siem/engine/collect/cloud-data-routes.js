// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Data Security Posture - cloud object stores (Azure Blob, AWS S3, OCI Object Storage), read-only (collect/cloud-data.js).
 *   GET    {P}/cloud-data/stores               any signed-in role: stores, exposure, counts (audited read);
 *                                               analyst and above also get top_objects (object names); a viewer gets {hidden:true}
 *   GET    {P}/cloud-data/settings             admin: non-secret settings + credentials as {configured, set_at} only
 *   POST   {P}/cloud-data/settings             admin: {azure|aws|oci: {...}, in_kingdom_regions[], schedule_hours}   audited (field names)
 *   POST   {P}/cloud-data/credentials          admin: {provider, ...secret fields} → secrets.json sealed          audited (no value)
 *   DELETE {P}/cloud-data/credentials/:provider admin                                                             audited
 *   POST   {P}/cloud-data/scan                 operator: start a scan now (one at a time, 409 while running)      audited
 *   POST   {P}/cloud-data/test                 admin {provider}: one read-only list call proves the credentials   audited
 * Background: a scheduled scan every schedule_hours (0 = manual only) through guard('cloud-data.scan'), rescheduled in
 * finally; no timer when deps.noTimers. deps.cloudHttp replaces the HTTPS transport (tests stub the providers).
 */
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { body, param } = require('../util/check');
const { guard } = require('../util/errors');
const { createCloudData, PROVIDERS } = require('./cloud-data');

const RANK = { viewer: 1, readonly: 1, analyst: 2, operator: 3, admin: 4 };
const REGION = /^[a-z0-9]+(-[a-z0-9]+){0,4}$/;
const PATTERN = /^[A-Za-z0-9._*\/-]{1,255}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OCID = (kind) => new RegExp(`^ocid1\\.${kind}\\.[a-z0-9-]*\\.[a-z0-9-]*\\.[a-z0-9]{10,120}$`);
const FINGERPRINT = /^([0-9a-f]{2}:){15}[0-9a-f]{2}$/;
const MB = 1024 * 1024;

// a nested object validated with check.js; the field name in the error says where it is (aws.regions[0] …)
function nested(prefix, src, fn) {
  if (src === undefined || src === null) return undefined;
  if (typeof src !== 'object' || Array.isArray(src)) throw new HttpError(400, `${prefix} must be an object`);
  try { return fn(body(src)).done(); } catch (e) { if (e.status === 400) throw new HttpError(400, `${prefix}.${e.message}`); throw e; }
}
function lists(v) {
  return v.list('regions', { max: 30, item: 'str', itemMax: 40, unique: true }).list('include', { max: 100, item: 'str', itemMax: 255 }).list('exclude', { max: 100, item: 'str', itemMax: 255 })
    .rule((o) => ((o.regions || []).find((r) => !REGION.test(r)) !== undefined ? 'regions: lowercase region names (me-jeddah-1, eu-west-1, uaenorth)' : null))
    .rule((o) => ([...(o.include || []), ...(o.exclude || [])].find((p) => !PATTERN.test(p)) !== undefined ? 'include / exclude: store names or * patterns (letters, digits . _ - / *)' : null))
    .int('max_objects_per_store', { min: 1, max: 100000 }).int('max_bytes_per_scan', { min: MB, max: 50 * 1024 * MB }).bool('enabled');
}
function settingsBody(b) {
  const top = body(b).list('in_kingdom_regions', { max: 50, item: 'str', itemMax: 40, unique: true }).int('schedule_hours', { min: 0, max: 720 })
    .rule((o) => ((o.in_kingdom_regions || []).find((r) => !REGION.test(r)) !== undefined ? 'in_kingdom_regions: lowercase region names (me-riyadh-1, saudiarabiacentral)' : null)).done();
  const src = b || {};
  const aws = nested('aws', src.aws, (v) => { lists(v); return v.str('account_label', { max: 80 }); });
  const azure = nested('azure', src.azure, (v) => {
    lists(v);
    return v.bool('use_m365_app').bool('discover').list('subscription_ids', { max: 50, item: 'str', itemMax: 36, unique: true })
      .rule((o) => ((o.subscription_ids || []).find((x) => !GUID.test(x)) !== undefined ? 'subscription_ids: subscription GUIDs' : null))
      .list('accounts', { max: 100 });
  });
  if (azure && azure.accounts) azure.accounts = azure.accounts.map((a, i) => nested(`azure.accounts[${i}]`, a, (v) => v.str('name', { required: true, re: /^[a-z0-9]{3,24}$/, msg: 'name: the storage account name (3-24 lowercase letters and digits)' }).str('location', { max: 40, re: REGION, msg: 'location: an Azure region name (e.g. uaenorth)' })));
  const oci = nested('oci', src.oci, (v) => {
    lists(v);
    return v.str('region', { max: 40, re: REGION, msg: 'region: an OCI region (me-jeddah-1, me-riyadh-1 …)' })
      .str('compartment_id', { max: 255, re: /^ocid1\.(compartment|tenancy)\.[a-z0-9-]*\.[a-z0-9-]*\.[a-z0-9]{10,120}$/, msg: 'compartment_id: a compartment (or tenancy) OCID' })
      .str('tenancy_id', { max: 255, re: OCID('tenancy'), msg: 'tenancy_id: the tenancy OCID' }).str('user_id', { max: 255, re: OCID('user'), msg: 'user_id: the user OCID' })
      .str('fingerprint', { max: 47, re: FINGERPRINT, msg: 'fingerprint: the API key fingerprint (aa:bb:… 16 pairs)' })
      .str('namespace', { max: 64, re: /^[a-z0-9]{1,64}$/i, msg: 'namespace: the Object Storage namespace' });
  });
  const out = {};
  if (top.in_kingdom_regions) out.in_kingdom_regions = top.in_kingdom_regions;
  if (top.schedule_hours !== undefined) out.schedule_hours = top.schedule_hours;
  if (aws) out.aws = aws; if (azure) out.azure = azure; if (oci) out.oci = oci;
  if (!Object.keys(out).length) throw new HttpError(400, 'nothing to change: send aws, azure, oci, in_kingdom_regions or schedule_hours');
  return out;
}
function credentialsBody(b) {
  const p = body(b).oneOf('provider', PROVIDERS, { required: true }).done().provider;
  if (p === 'aws') {
    return { provider: p, value: body(b).str('access_key_id', { required: true, re: /^(AKIA|ASIA)[A-Z0-9]{12,124}$/, msg: 'access_key_id: an AWS access key ID (AKIA… / ASIA…)' })
      .str('secret_access_key', { required: true, min: 16, max: 128, re: /^[A-Za-z0-9/+=]+$/, msg: 'secret_access_key: the 40-character secret access key' })
      .str('session_token', { max: 4096, re: /^[A-Za-z0-9/+=]+$/, msg: 'session_token: the session token as issued' }).done() };
  }
  if (p === 'azure') {
    const v = body(b).str('tenant_id', { re: GUID, msg: 'tenant_id: the directory (tenant) GUID' }).str('client_id', { re: GUID, msg: 'client_id: the application (client) GUID' })
      .str('client_secret', { min: 8, max: 256 }).list('account_keys', { max: 20 }).done();
    if (v.account_keys) v.account_keys = v.account_keys.map((a, i) => nested(`account_keys[${i}]`, a, (x) => x.str('account', { required: true, re: /^[a-z0-9]{3,24}$/, msg: 'account: the storage account name' }).str('key', { required: true, max: 120, re: /^[A-Za-z0-9+/]{40,100}={0,2}$/, msg: 'key: the base64 account key' })));
    const entra = v.tenant_id || v.client_id || v.client_secret;
    if (entra && !(v.tenant_id && v.client_id && v.client_secret)) throw new HttpError(400, (!v.tenant_id ? 'tenant_id' : !v.client_id ? 'client_id' : 'client_secret') + ' is required with an Entra app (tenant_id, client_id, client_secret)');
    if (!entra && !(v.account_keys || []).length) throw new HttpError(400, 'client_secret (with tenant_id and client_id) or account_keys is required - or set use_m365_app in the Azure settings');
    return { provider: p, value: v };
  }
  return { provider: p, value: body(b).str('private_key_pem', { required: true, max: 8192, re: /^-----BEGIN (RSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+-----END (RSA |ENCRYPTED )?PRIVATE KEY-----$/, msg: 'private_key_pem: the PEM private key of the API key' })
    .str('passphrase', { max: 256 }).done() };
}

function register(api, deps) {
  if (!deps.state) throw new Error('cloud data discovery needs deps.state');
  const P = prefixOf(deps), B = `${P}/cloud-data`;
  const X = deps.cloudData || createCloudData({ config: deps.config, state: deps.state, log: deps.log, now: deps.now, httpRequest: deps.cloudHttp, classify: deps.cloudClassify });
  deps.cloudDataInstance = X;

  api.route('GET', `${B}/stores`, wrap(deps, null, (ctx) => X.view({ keys: (RANK[String(ctx.role || '').toLowerCase()] || 0) >= RANK.analyst })), { auditRead: true });
  api.route('GET', `${B}/settings`, wrap(deps, 'admin', () => X.settingsView()));
  api.route('POST', `${B}/settings`, wrap(deps, 'admin', (ctx) => {
    const r = X.saveSettings(settingsBody(ctx.body), ctx.user);
    audit(ctx, 'cloud-data.settings', 'settings', { changed: r.changed });
    return Object.assign(X.settingsView(), { changed: r.changed });
  }));
  api.route('POST', `${B}/credentials`, wrap(deps, 'admin', (ctx) => {
    const { provider, value } = credentialsBody(ctx.body), r = X.setCredentials(provider, value);
    audit(ctx, 'cloud-data.credentials.set', provider, { fields: Object.keys(value) });
    return { provider, credentials: r };
  }));
  api.route('DELETE', `${B}/credentials/:provider`, wrap(deps, 'admin', (ctx) => {
    const p = param(ctx.params.provider, 'provider'); if (!PROVIDERS.includes(p)) throw new HttpError(400, 'provider must be one of: ' + PROVIDERS.join(', '));
    const r = X.deleteCredentials(p); audit(ctx, 'cloud-data.credentials.delete', p, {}); return r;
  }));
  api.route('POST', `${B}/scan`, wrap(deps, 'operator', (ctx) => {
    body(ctx.body).done();   // no field is taken
    const r = X.startScan(ctx.user); audit(ctx, 'cloud-data.scan', 'now', { providers: r.providers }); return r;
  }));
  api.route('POST', `${B}/test`, wrap(deps, 'admin', async (ctx) => {
    const b = body(ctx.body).oneOf('provider', PROVIDERS, { required: true }).done(), r = await X.testProvider(b.provider);
    audit(ctx, 'cloud-data.test', b.provider, { ok: r.ok, count: r.count === undefined ? null : r.count }); return r;
  }));
  if (!deps.noTimers) X.schedule(guard);
  return X;
}
module.exports = { register, settingsBody, credentialsBody };
