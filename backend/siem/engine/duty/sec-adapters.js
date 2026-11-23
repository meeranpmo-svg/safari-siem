// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Two more AI engineers on the duty desk (duty-core.js), each over a read-only security-API module:
 *   zscaler  AI Security Engineer — Zscaler   (engine/zscaler: ZIA + ZPA posture)
 *   ksc      AI Endpoint Protection Engineer  (engine/ksc: Kaspersky Security Center posture)
 * The modules already return findings in the duty shape and own their own investigation, verification and four-eyes
 * change plans (a plan is applied by a person in the vendor console; the SIEM only reads). Each factory returns [] when
 * its module is not wired, exactly like dbaAdapter / appAdapter — so the duty desk simply has no such engineer then.
 */
function adapterFor(id, name, M) {
  if (!M || typeof M.findings !== 'function') return [];
  return [{
    id, name,
    findings() { return M.findings(); },                 // null = not connected (no tenant/server configured)
    investigate(it) { return M.investigate(it); },
    propose(it, opts) { return M.propose(it, opts); },   // rule-based change plan → awaiting-approval (four-eyes)
    changeStatus(cid) { return M.changeStatus(cid); },
    verify(it) { return M.verify(it); },
  }];
}

const zscalerAdapter = (Z) => adapterFor('zscaler', 'AI Security Engineer — Zscaler', Z);
const kscAdapter = (K) => adapterFor('ksc', 'AI Endpoint Protection Engineer (Kaspersky)', K);

module.exports = { zscalerAdapter, kscAdapter };
