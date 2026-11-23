// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// In-process fake ManageEngine MDM Plus API (/api/v1/mdm) for the leaver device tests. SYNTHETIC devices only.
const http = require('http');
const TOKEN = 'Synthetic-ME-Token-42';
function fakeMdm() {
  const st = { calls: [], fail: 0, auth: [], devices: {
    '1001': { device_id: '1001', device_name: 'LAP-CLAIMS-07', platform_type: 'windows', owned_by: 1, serial_number: 'SN-LAP-1', model: 'Latitude 7440', user: { user_email: 'khalid.harbi@corp.syn', user_name: 'khalid.harbi' }, last_contact_time: 1761638400000, actions: [] },
    '1002': { device_id: '1002', device_name: 'Khalid Pixel', platform_type: 'android', owned_by: 2, serial_number: 'PX-77', user: { user_email: 'khalid.harbi@corp.syn' }, actions: [] },
    '1003': { device_id: '1003', device_name: 'MBP-CLAIMS-02', platform_type: 'macos', owned_by: 1, serial_number: 'C02-MAC', user: { user_email: 'khalid.harbi@corp.syn' }, actions: [] },
    '1004': { device_id: '1004', device_name: 'Someone else', platform_type: 'windows', owned_by: 1, serial_number: 'SN-OTHER', user: { user_email: 'other@corp.syn' }, actions: [] } } };
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    st.calls.push(req.method + ' ' + u.pathname); st.auth.push(req.headers.authorization);
    if (req.headers.authorization !== TOKEN) return J(401, { error_description: 'Invalid API token' });
    let m;
    if (u.pathname === '/api/v1/mdm/devices') { const all = Object.values(st.devices).map((d) => Object.assign({}, d, { actions: undefined })); const lim = Number(u.searchParams.get('limit') || 500); return J(200, { devices: all.slice(0, lim), metadata: { total_record_count: all.length }, paging: {} }); }
    if ((m = /^\/api\/v1\/mdm\/devices\/(\d+)$/.exec(u.pathname))) { const d = st.devices[m[1]]; return d ? J(200, Object.assign({}, d, { actions: undefined })) : J(404, {}); }
    if ((m = /^\/api\/v1\/mdm\/devices\/(\d+)\/actions$/.exec(u.pathname))) { const d = st.devices[m[1]]; if (!d) return J(404, {}); d.actions.forEach((a) => { if (++a.polls >= 2 && a.status === 'Initiated') a.status = 'Success'; }); return J(200, { actions: d.actions.map((a) => ({ action_name: a.action_name, status: a.status })) }); }
    if ((m = /^\/api\/v1\/mdm\/devices\/(\d+)\/actions\/(complete_wipe|corporate_wipe)$/.exec(u.pathname)) && req.method === 'POST') {
      if (st.fail > 0) { st.fail--; return J(500, { message: 'Internal error' }); }
      const d = st.devices[m[1]]; if (!d) return J(404, {}); d.actions.push({ action_name: m[2], status: 'Initiated', polls: 0 }); return J(202, { status: 'success' });
    }
    J(404, { message: 'no route ' + u.pathname });
  }); });
  return { st, srv, TOKEN };
}
module.exports = { fakeMdm, TOKEN };
