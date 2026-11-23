// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Cisco Unified CM IP phones — READ ONLY:
 *   AXL  listPhone   POST https://<cucm>:8443/axl/   SOAPAction "CUCM:DB ver=<v> listPhone"
 *        → name (SEP<MAC>), description, model/product, devicePoolName, protocol
 *   RIS  selectCmDevice  POST https://<cucm>:8443/realtimeservice2/services/RISService70  SOAPAction "selectCmDevice"
 *        → registration status + IP per device name
 * The SOAP envelopes below follow the published AXL schema (AXLSoap.xsd, namespace http://www.cisco.com/AXL/API/<v>)
 * and the RisPort70 WSDL (namespace http://schemas.cisco.com/ast/soap). Exact element names/paging limits are marked
 * "verify" in docs/DISCOVERY.md — confirm against the customer's CUCM version (AXL schema download in CUCM admin).
 * The AXL user needs only the "Standard AXL Read Only API Access" role; RIS needs "Standard CCM Admin Users" read +
 * "Standard RealtimeAndTraceCollection" (verify).
 *   collect(cred, {request}) → {ok, phones[{name, mac, description, model, device_pool, protocol, status, ip}]}
 *   test(cred) → getCCMVersion via AXL
 */
const httpc = require('../httpc');
const xml = require('../xml');
const diag = require('../diag');

function errorClass(e) { return ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol'].includes(e && e.code) ? e.code : 'protocol'; }

function axlEnvelope(ver, op, inner) {
  return '<?xml version="1.0" encoding="UTF-8"?>'
    + `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns="http://www.cisco.com/AXL/API/${xml.esc(ver)}">`
    + `<soapenv:Header/><soapenv:Body><ns:${op}>${inner}</ns:${op}></soapenv:Body></soapenv:Envelope>`;
}
function listPhoneBody(ver, skip, first) {
  return axlEnvelope(ver, 'listPhone', '<searchCriteria><name>%</name></searchCriteria>'
    + '<returnedTags><name/><description/><product/><model/><protocol/><devicePoolName/></returnedTags>'
    + `<skip>${Number(skip) | 0}</skip><first>${Number(first) | 0}</first>`);
}
function risBody(names) {
  const items = (names && names.length ? names : ['*']).map((n) => `<soap:item><soap:Item>${xml.esc(n)}</soap:Item></soap:item>`).join('');
  return '<?xml version="1.0" encoding="UTF-8"?>'
    + '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap="http://schemas.cisco.com/ast/soap">'
    + '<soapenv:Header/><soapenv:Body><soap:selectCmDevice><soap:StateInfo></soap:StateInfo><soap:CmSelectionCriteria>'
    + '<soap:MaxReturnedDevices>1000</soap:MaxReturnedDevices><soap:DeviceClass>Phone</soap:DeviceClass><soap:Model>255</soap:Model>'
    + '<soap:Status>Any</soap:Status><soap:NodeName></soap:NodeName><soap:SelectBy>Name</soap:SelectBy>'
    + `<soap:SelectItems>${items}</soap:SelectItems><soap:Protocol>Any</soap:Protocol><soap:DownloadStatus>Any</soap:DownloadStatus>`
    + '</soap:CmSelectionCriteria></soap:selectCmDevice></soapenv:Body></soapenv:Envelope>';
}

function macFromName(name) {
  const m = /^(?:SEP|ATA|BAT)?([0-9A-Fa-f]{12})$/.exec(String(name || ''));
  return m ? m[1].toLowerCase().match(/.{2}/g).join(':') : null;
}
function parseListPhone(text) {
  const doc = xml.parse(text);
  return xml.findAll(doc, 'phone').map((p) => {
    const name = xml.childText(p, 'name');
    return { name, mac: macFromName(name), description: xml.childText(p, 'description') || null, model: xml.childText(p, 'model') || xml.childText(p, 'product') || null, device_pool: xml.childText(p, 'devicePoolName') || null, protocol: xml.childText(p, 'protocol') || null };
  }).filter((p) => p.name);
}
function parseRis(text) {
  const doc = xml.parse(text);
  const out = new Map();
  for (const dev of xml.findAll(doc, 'CmDevices')) {
    for (const it of dev.children) {
      const name = xml.childText(it, 'Name');
      if (!name) continue;
      const ipNode = xml.child(it, 'IPAddress');
      const ip = ipNode ? (xml.textOf(ipNode, 'IP') || ipNode.text.trim()) : '';
      const status = xml.childText(it, 'Status') || null;
      const prev = out.get(name);
      // a phone can appear on several nodes; "Registered" wins
      if (!prev || (status === 'Registered' && prev.status !== 'Registered')) out.set(name, { status, ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? ip : null });
    }
  }
  return out;
}
function faultOf(text) { try { const d = xml.parse(text); const f = xml.find(d, 'Fault'); return f ? xml.textOf(f, 'faultstring') || 'SOAP fault' : null; } catch { return null; } }

function caller(cred, o) {
  const t = cred.target || {};
  const host = t.host; const port = t.port || 8443;
  const req = o.request || httpc.request;
  const auth = 'Basic ' + Buffer.from(`${cred.secret.username}:${cred.secret.password}`).toString('base64');
  return async function soap(path, action, body) {
    const r = await req(`https://${host}:${port}${path}`, { method: 'POST', headers: { 'Content-Type': 'text/xml; charset=utf-8', SOAPAction: action, Authorization: auth, Accept: 'text/xml' }, body, caFile: t.ca_file, captureUntrusted: !!o.captureUntrusted, timeoutMs: o.timeoutMs || 30000 });
    if (r.status === 401 || r.status === 403) throw diag.err('auth', 'CUCM rejected the credentials', { stage: 'auth', http: r.status, tlsTrusted: true });
    if (r.status >= 400) throw diag.err('protocol', `CUCM ${action}: HTTP ${r.status}${faultOf(r.text) ? ' (SOAP fault)' : ''}`, { stage: 'read', http: r.status, tlsTrusted: true });
    return r.text;
  };
}

async function collect(cred, o = {}) {
  const t0 = Date.now();
  const ver = (cred.target && cred.target.axl_version) || '12.5';
  const soap = caller(cred, o);
  try {
    const phones = [];
    for (let skip = 0, page = o.pageSize || 500; skip < 50000; skip += page) {
      const batch = parseListPhone(await soap('/axl/', `"CUCM:DB ver=${ver} listPhone"`, listPhoneBody(ver, skip, page)));
      phones.push(...batch);
      if (batch.length < page) break;
    }
    // RisPort70: registration + IP, 1000 names per call (verify the per-call limit for the customer's version)
    const reg = new Map();
    for (let i = 0; i < phones.length; i += 1000) {
      try { for (const [k, v] of parseRis(await soap('/realtimeservice2/services/RISService70', 'selectCmDevice', risBody(phones.slice(i, i + 1000).map((p) => p.name))))) reg.set(k, v); } catch (e) { if (e.code === 'auth') throw e; /* RIS optional */ }
    }
    for (const p of phones) { const r = reg.get(p.name); p.status = r ? r.status : null; p.ip = r ? r.ip : null; }
    return { ok: true, phones, latency_ms: Date.now() - t0 };
  } catch (e) { return { ok: false, error_class: errorClass(e), latency_ms: Date.now() - t0 }; }
}

async function test(cred, o = {}) {
  const t0 = Date.now();
  const ver = (cred.target && cred.target.axl_version) || '12.5';
  try { await caller(cred, Object.assign({ captureUntrusted: true }, o))('/axl/', `"CUCM:DB ver=${ver} getCCMVersion"`, axlEnvelope(ver, 'getCCMVersion', '')); return diag.result('cucm_axl', { latency_ms: Date.now() - t0, http: 200 }); } catch (e) { return diag.fromError('cucm_axl', e, { latency_ms: Date.now() - t0 }); }
}

module.exports = { collect, test, parseListPhone, parseRis, listPhoneBody, risBody, macFromName };
