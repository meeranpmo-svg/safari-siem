// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SYNTHETIC SIEM answers and local records for Data Security Posture / AI Data Lineage tests (engine and page). Every name ends in
// -SYN / .syn / syn or uses example.invalid; no value is a real person, file, bucket or tenant. Shapes follow the SIEM routes:
// GET /pii/files, /m365/files/insights, /cloud-data/stores, /shadow-ai/register, /shadow-ai/signals, /m365/security, /m365/graph.
const DAY = 86400000;
const HOSTILE = '<img src=x onerror="window.__pwned=1">-SYN.docx';

function siemData(T0, o = {}) {
  const D = (n) => new Date(T0 - n * DAY).toISOString();
  const files = { sharepoint: { at: D(1), status: { running: false, last_error: '', enabled: true, onedrive: true }, sources: [
    { key: 'site-hr-syn', kind: 'sharepoint', label: 'HR-Site-SYN', url: 'https://tenant.example.invalid/sites/hr-syn', files_seen: 120, files_read: 80, hits: [
      { id: 'f1', name: 'payroll-syn.xlsx', path: '/Payroll', size: 1000, modified: D(10), kinds: { national_id: 5, iban: 2 }, name_kinds: ['salary'], by: 'content', shared: 'anonymous' },
      { id: 'f2', name: HOSTILE, path: '/Old', size: 10, modified: D(1200), kinds: { mobile: 4 }, name_kinds: [], by: 'content', shared: 'external' },
      { id: 'f3', name: 'keys-syn.txt', path: '/IT', size: 10, modified: D(3), kinds: { private_key: 1 }, name_kinds: ['secret_file'], by: 'content', shared: 'organization' },
      { id: 'f4', name: 'medical-syn.docx', path: '/Claims', size: 10, modified: D(3), kinds: { health: 3 }, name_kinds: [], by: 'content', shared: 'organization' }] },
    { key: 'od-syn-1', kind: 'onedrive', label: 'OneDrive: alia.syn@example.invalid', url: '', files_seen: 20, hits: [
      { id: 'f5', name: 'passport-syn.pdf', path: '/', size: 10, modified: D(2), kinds: {}, name_kinds: ['passport'], by: 'name', shared: 'none' },
      { id: 'f6', name: 'notes-syn.txt', path: '/', size: 10, modified: D(2), kinds: { api_key: 1 }, name_kinds: [], by: 'content', shared: 'none' }] }] },
  fileshares: { hosts: [{ host: 'FS-SYN-01', at: D(2), settings: { at: D(2), roots: [{ share: 'Public', path: 'D:\\Public', files_seen: 50, hits: [{ p: 'D:\\Public\\salaries-syn.csv', kinds: { iban: 3 }, name_kinds: ['salary'], open: true, modified: D(5) }] }] } }] } };
  if (o.credSummary) files.credentials = o.credSummary;
  const insights = { never: false, read_at: D(1), kpis: { sources: 2, anonymous: 1, external: 1, old: 1, credentials: 2, credentials_shared: 1 }, files: [{ source_label: 'HR-Site-SYN', path: '/Payroll', name: 'payroll-syn.xlsx', score: 95 }] };
  const cloud = { configured: true, note: '', scan: { running: false },
    providers: [{ provider: 'azure', configured: true, last_scan: D(1), last_ok: D(1), error: null }, { provider: 'aws', configured: false, last_scan: null, last_ok: null, error: null }],
    stores: [
      { id: 'st-syn-1', provider: 'azure', account: 'sub-syn', name: 'claimsdocssyn', region: 'westeurope', in_kingdom: false, public: true, public_why: 'allowBlobPublicAccess is true', encrypted: true, cmk: false, objects_seen: 100, objects_scanned: 80, objects_with_findings: 3, kinds: { national_id: 2, password: 1 }, categories: { identity: 2, credentials: 1 }, truncated: false, last_scan: D(1) },
      { id: 'st-syn-2', provider: 'azure', account: 'sub-syn', name: 'ksaarchivesyn', region: 'saudiarabia', in_kingdom: true, public: false, encrypted: true, cmk: true, objects_seen: 10, objects_scanned: 10, objects_with_findings: 1, kinds: { health: 1 }, categories: { health: 1 }, last_scan: D(1) },
      { id: 'st-syn-3', provider: 'azure', account: 'sub-syn', name: 'unknownsyn', region: '', in_kingdom: null, public: null, objects_seen: 5, objects_scanned: 5, objects_with_findings: 1, kinds: { email: 1 }, categories: { contact: 1 }, last_scan: D(1) }],
    totals: { stores: 3, public: 1, outside_kingdom: 1 }, top_objects: [] };
  const register = { items: [{ id: 'chatgpt', name: 'ChatGPT', vendor: 'OpenAI', category: 'chat', status: 'tolerated', allowed_classes: ['confidential'], owner: 'owner.syn' },
    { id: 'copilot', name: 'Microsoft Copilot', vendor: 'Microsoft', category: 'chat', status: 'sanctioned', allowed_classes: ['personal'], owner: '' },
    { id: 'deepseek', name: 'DeepSeek', vendor: 'DeepSeek', category: 'chat', status: 'blocked', allowed_classes: [], owner: '' }] };
  const signals = { totals: { incidents: 3 }, incidents: [
    { ts: D(2), app: 'chatgpt', app_name: 'ChatGPT', status: 'tolerated', source: 'dlp', action: 'allowed', left: true, classes: ['personal'] },
    { ts: D(3), app: 'copilot', app_name: 'Microsoft Copilot', status: 'sanctioned', source: 'extension', action: 'sent_after_warning', left: true, classes: ['personal'] },
    { ts: D(4), app: 'deepseek', app_name: 'DeepSeek', status: 'blocked', source: 'zscaler', action: 'blocked', left: false, classes: ['health'] }] };
  const security = { configured: true, updated: D(0), kpis: { admins_no_mfa: 1 }, mfa: { users: 50, registered: 49, admins: [{ name: 'Admin SYN', upn: 'admin.syn@example.invalid' }] },
    alerts: { list: [{ created: D(1), title: 'DLP policy match (synthetic)', category: 'Exfiltration', severity: 'high', status: 'new', open: true, product: 'microsoftDataLossPrevention' },
      { created: D(1), title: 'Malware (synthetic)', category: 'Malware', severity: 'low', status: 'new', open: true, product: 'microsoftDefenderForEndpoint' }] } };
  const graph = { configured: true, updated: D(0), licenses: o.noCopilot ? [{ sku: 'SPE_E5', total: 100, consumed: 90 }] : [{ sku: 'Microsoft_365_Copilot', total: 10, consumed: 4 }, { sku: 'SPE_E5', total: 100, consumed: 90 }],
    users: { list: [{ name: 'Guest One', upn: 'guest1-syn#EXT#@example.invalid', guest: true, enabled: true, last: D(200), skus: [] }, { name: 'Guest Two', upn: 'guest2-syn#EXT#@example.invalid', guest: true, enabled: true, last: D(5), skus: [] },
      { name: 'User SYN', upn: 'user.syn@example.invalid', guest: false, enabled: true, last: D(1), skus: ['Microsoft_365_Copilot'] }] } };
  return { '/pii/files': files, '/m365/files/insights': insights, '/cloud-data/stores': cloud, '/shadow-ai/register': register, '/shadow-ai/signals?hours=720': signals, '/m365/security': security, '/m365/graph': graph };
}

// a SIEM link: call(method, path, who) -> {status, json}; o.missing = paths answering 404, o.only = the only paths answering
function fakeSiem(T0, o = {}) {
  const data = siemData(T0, o), calls = [];
  const fn = async (method, path, who) => {
    calls.push({ method, path, who });
    if (o.fail) throw new Error('synthetic SIEM outage');
    if ((o.missing || []).includes(path) || (o.only && !o.only.includes(path))) return { status: 404, json: { error: 'not found' } };
    if (o.override && o.override[path]) return { status: 200, json: o.override[path] };
    return data[path] ? { status: 200, json: JSON.parse(JSON.stringify(data[path])) } : { status: 404, json: { error: 'not found' } };
  };
  fn.calls = calls;
  return fn;
}

// local registers: two database scans, records of processing, transfers, a breach, an access review campaign
function seedLocal(app, T0) {
  const D = (n) => new Date(T0 - n * DAY).toISOString(), S = app.store;
  S.collection('pdpl_discovery').put({ id: 'oracle|10.0.0.5|1521', db: 'oracle|10.0.0.5|1521', engine: 'oracle', label: 'CLAIMS-DB-SYN', host: '10.0.0.5', ok: true, at: D(3),
    columns: [{ owner: 'CLM', table: 'MEMBERS', column: 'NATIONAL_ID', kind: 'national_id', category: 'identity', confirmed: true, rows: 1000 }, { owner: 'CLM', table: 'CLAIMS', column: 'DIAGNOSIS', kind: 'health', category: 'health', confirmed: true, rows: 500 }] });
  S.collection('pdpl_discovery').put({ id: 'mssql|10.0.0.6|1433', db: 'mssql|10.0.0.6|1433', engine: 'mssql', label: 'HRDB-SYN', host: '10.0.0.6', ok: true, at: D(3),
    columns: [{ owner: 'dbo', table: 'Staff', column: 'Iqama', kind: 'iqama', category: 'identity', confirmed: true, rows: 200 }, { owner: 'dbo', table: 'Staff', column: 'Phone', kind: 'mobile', category: 'contact', confirmed: false, rows: 200 }] });
  S.collection('pdpl_discovery').put({ id: '_last', at: D(3), by: 'syed', databases: 2 });
  const R = S.collection('pdpl_records');
  R.put({ id: 'PD-ROPA-001', kind: 'ropa', status: 'active', name: 'Claims handling (synthetic)', systems: ['CLAIMS-DB-SYN'], data_categories: ['identity'] });
  R.put({ id: 'PD-ROPA-002', kind: 'ropa', status: 'archived', name: 'Old HR (synthetic)', systems: ['HRDB-SYN', 'HR-Site-SYN'], data_categories: ['identity'] });
  R.put({ id: 'PD-TRANSFER-001', kind: 'transfer', status: 'active', name: 'Reinsurer SYN', country: 'Germany' });
  R.put({ id: 'PD-TRANSFER-002', kind: 'transfer', status: 'active', name: 'TPA SYN', country: 'UAE', basis: 'scc' });
  R.put({ id: 'PD-TRANSFER-003', kind: 'transfer', status: 'active', name: 'Signed SYN', country: 'UK', basis: 'adequacy', tia: { signed_by: 'dpo.syn' } });
  R.put({ id: 'PD-BREACH-001', kind: 'breach', status: 'active', ref: 'BR-SYN-1', aware_at: D(1) });
  R.put({ id: 'PD-BREACH-002', kind: 'breach', status: 'active', ref: 'BR-SYN-0', aware_at: D(40), sdaia_notified_at: D(39), subjects_notified_at: D(38), harm_likely: true });
  S.collection('access_reviews').put({ id: 'AR-2026-Q4', quarter: '2026-Q4', status: 'open', started_at: D(30), due_at: D(5) });
  const I = S.collection('access_review_items');
  I.put({ id: 'AR-2026-Q4:00001', campaign: 'AR-2026-Q4', group: 'Domain Admins', privileged_group: true, user: 'old.admin.syn', enabled: true, dormant: true, decision: null, state: 'open' });
  I.put({ id: 'AR-2026-Q4:00002', campaign: 'AR-2026-Q4', group: 'Finance SYN', privileged_group: false, user: 'fin.syn', enabled: true, dormant: false, decision: null, state: 'open' });
  I.put({ id: 'AR-2026-Q4:00003', campaign: 'AR-2026-Q4', group: 'Finance SYN', privileged_group: false, user: 'left.syn', enabled: true, dormant: false, decision: 'remove', state: 'removal_pending' });
  I.put({ id: 'AR-2026-Q4:00004', campaign: 'AR-2026-Q4', group: 'Domain Admins', privileged_group: true, user: 'active.admin.syn', enabled: true, dormant: false, decision: 'keep', state: 'kept' });
}

module.exports = { siemData, fakeSiem, seedLocal, HOSTILE, DAY };
