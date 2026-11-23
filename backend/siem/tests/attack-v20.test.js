// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// MITRE ATT&CK v20: the bundled catalog is v20 (Stealth + Defense Impairment tactics), no built-in rule or parser carries
// an id MITRE revoked, and an old id (an imported Sigma rule, a stored alert) is counted under its v20 replacement - with
// the renamed tactic key defense-evasion read as stealth.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const cat = require('../engine/bas/attack-catalog.json');
const { computeCoverage } = require('../engine/bas/coverage');

test('ATT&CK v20 catalog, no revoked ids in the rule packs, old ids resolve to the new ones', () => {
  assert.equal(cat.attack_version, '20.0');
  const keys = cat.tactics.map((t) => t.key);
  assert.ok(keys.includes('stealth') && keys.includes('defense-impairment') && !keys.includes('defense-evasion'));
  assert.equal(cat.tactics.find((t) => t.key === 'defense-impairment').id, 'TA0112');
  assert.equal(cat.revoked['T1562.001'], 'T1685');
  const dir = path.join(__dirname, '../engine/detect/rules');
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.json'))) {
    const s = fs.readFileSync(path.join(dir, f), 'utf8');
    for (const old of Object.keys(cat.revoked)) assert.ok(!s.includes('"' + old + '"'), f + ' still uses revoked ' + old);
    assert.ok(!s.includes('"defense-evasion"'), f + ' still uses the pre-v20 tactic key');
    for (const r of [].concat(JSON.parse(s))) for (const m of r.mitre || []) assert.ok(cat.techniques[m] || cat.techniques[m.split('.')[0]], f + ' ' + r.id + ': ' + m + ' is not in the catalog');
  }
  const cov = computeCoverage({ rules: [{ id: 'SIGMA-OLD', name: 'old import', enabled: true, mitre: ['T1562.001', 'T1562'], tactic: 'defense-evasion', match: {} }] });
  const ids = cov.techniques.map((t) => t.id);
  assert.deepEqual(ids, ['T1685'], 'both old ids count once, under T1685');
  assert.ok(JSON.stringify(cov.tactics).includes('stealth'), 'defense-evasion is read as stealth');
});
