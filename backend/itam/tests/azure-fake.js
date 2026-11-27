// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A fake Azure (sign-in, Resource Graph, Resource Manager) with SYNTHETIC servers, for tests/azure-cloud.test.js and the page test.
const SUB = '11111111-1111-4111-8111-111111111111', TEN = '22222222-2222-4222-8222-222222222222', APP = '33333333-3333-4333-8333-333333333333', APP2 = '44444444-4444-4444-8444-444444444444';
const VM = (n) => '/subscriptions/' + SUB + '/resourcegroups/rg-syn/providers/microsoft.compute/virtualmachines/' + n;
const NSG = '/subscriptions/' + SUB + '/resourcegroups/rg-syn/providers/microsoft.network/networksecuritygroups/nsg-syn';
const PIP = '/subscriptions/' + SUB + '/resourcegroups/rg-syn/providers/microsoft.network/publicipaddresses/pip-web';

function fakeAzure(calls, o = {}) {
  return async (url, req) => {
    calls.push({ url, method: req.method, body: req.body, auth: req.headers && req.headers.Authorization });
    if (/oauth2\/v2\.0\/token$/.test(url)) { const f = new URLSearchParams(req.body); return /Synthetic-(Read|Act)/.test(f.get('client_secret')) ? { status: 200, json: { access_token: 'bearer-' + f.get('client_id').slice(0, 4) } } : { status: 401, json: {} }; }
    if (/ResourceGraph/.test(url)) {
      const q = JSON.parse(req.body).query, R = (data) => ({ status: 200, json: { data } });
      if (/securescores/.test(q) && o.noDefender) return { status: 403, json: {} };
      if (/resources\/subscriptions/.test(q)) return R([{ subscriptionId: SUB, name: 'Safari Production (synthetic)' }]);
      if (/virtualmachines'/.test(q) && !/patch/.test(q)) return R([
        { id: VM('web-syn'), name: 'web-syn', location: 'uaenorth', resourceGroup: 'rg-syn', subscriptionId: SUB, tags: { owner: 'a.syn' }, osType: 'Windows', osName: 'Windows Server 2022', vmSize: 'Standard_D4s_v5', powerState: 'PowerState/running', licenseType: '' },
        { id: VM('app-syn'), name: 'app-syn', location: 'uaenorth', resourceGroup: 'rg-syn', subscriptionId: SUB, tags: {}, osType: 'Linux', vmSize: 'Standard_B2s', powerState: 'PowerState/stopped' },
        { id: VM('db-syn'), name: 'db-syn', location: 'westeurope', resourceGroup: 'rg-syn', subscriptionId: SUB, tags: { owner: 'b.syn' }, osType: 'Windows', vmSize: 'Standard_E8s_v5', powerState: 'PowerState/deallocated', licenseType: 'Windows_Server' }]);
      if (/networkinterfaces/.test(q)) return R([{ vm: VM('web-syn'), nsg: NSG, privateIp: '10.50.0.4', publicIpId: PIP, subnet: '' }, { vm: VM('app-syn'), nsg: '', privateIp: '10.50.0.5', publicIpId: '', subnet: '' }, { vm: VM('db-syn'), nsg: '', privateIp: '10.50.1.9', publicIpId: '', subnet: '' }]);
      if (/publicipaddresses/.test(q)) return R([{ id: PIP, name: 'pip-web', ip: '203.0.113.10', attached: 'x', sku: 'Standard' }, { id: PIP + '2', name: 'pip-old', ip: '203.0.113.11', attached: '', sku: 'Standard', resourceGroup: 'rg-syn' }]);
      if (/compute\/disks/.test(q)) return R([{ id: 'd1', name: 'web-os', managedBy: VM('web-syn'), state: 'Attached', sizeGb: 128 }, { id: 'd2', name: 'old-data', managedBy: '', state: 'Unattached', sizeGb: 512, sku: 'Premium_LRS', resourceGroup: 'rg-syn' }]);
      if (/networksecuritygroups/.test(q)) return R([{ nsg: NSG, rule: 'allow-rdp', port: '3389', ports: [], subnets: [] }]);
      if (/protecteditems/.test(q)) return R([{ vm: VM('db-syn'), lastBackup: new Date(Date.now() - 3600000).toISOString(), health: 'Passed', state: 'Protected' }]);
      if (/patchassessmentresults/.test(q)) return R([{ vm: VM('web-syn'), critical: 3, security: 2, other: 1 }, { vm: VM('app-syn'), critical: 0, security: 0 }]);
      if (/advisor/.test(q)) return R([{ res: VM('db-syn'), category: 'Cost', impact: 'High', problem: 'Right-size or shutdown underutilized virtual machines', savings: 412.5, currency: 'USD', targetSku: 'Standard_E4s_v5' }]);
      if (/securescores/.test(q)) return R([{ subscriptionId: SUB, current: 31.5, max: 45 }]);
      if (/assessments/.test(q)) return R([{ res: VM('web-syn'), name: 'Management ports should be closed', severity: 'High' }]);
      return R([]);
    }
    if (/\/(start|powerOff|deallocate|restart)\?api-version/.test(url)) return { status: o.actStatus || 202, json: null, text: '' };
    return { status: 404, json: null };
  };
}

module.exports = { fakeAzure, SUB, TEN, APP, APP2, VM };
