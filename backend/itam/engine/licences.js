// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Licence records + compliance view over the software rollup. No hard delete (retire a licence = status inactive).
const crypto = require('node:crypto');
const { normLicence, rollup, licenceCompliance } = require('./model/software');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

function createLicences({ store, audit, assets }) {
  const col = store.collection('licences');

  function upsert(body, who) {
    const incoming = Object.assign({}, body);
    if (!incoming.id) incoming.id = `lic_${crypto.randomBytes(5).toString('hex')}`;
    const lic = normLicence(incoming);
    if (!lic) throw bad('licence needs id and product');
    const prev = col.get(lic.id);
    const rec = Object.assign({ status: 'active', created_at: new Date().toISOString() }, prev || {}, lic, { updated_at: new Date().toISOString() });
    col.put(rec);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: prev ? 'licence.update' : 'licence.create', target: rec.id, detail: { product: rec.product, seats: rec.seats } });
    return rec;
  }
  function retire(id, who, reason) {
    const l = col.get(id); if (!l) throw bad('licence not found', 404);
    col.put(Object.assign({}, l, { status: 'inactive', retired_at: new Date().toISOString(), reason: reason || null }));
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'licence.retire', target: id, detail: { reason: reason || null } });
    return { ok: true };
  }
  function all(includeInactive = false) { return col.all((l) => includeInactive || l.status !== 'inactive'); }
  function active() { return col.all((l) => l.status !== 'inactive'); }

  // compliance list joining each licence to its computed usage
  function complianceView() {
    const rolled = rollup(assets.all().filter((a) => a.status !== 'disposed' && a.status !== 'retired'));
    return active().map((lic) => {
      const c = licenceCompliance(lic, rolled);
      return Object.assign({}, lic, { used: c.used, compliance: c.compliance, delta: c.delta, products: c.products });
    });
  }

  return { upsert, retire, all, active, complianceView };
}

module.exports = { createLicences };
