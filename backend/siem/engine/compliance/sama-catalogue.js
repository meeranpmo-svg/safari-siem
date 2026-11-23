// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SAMA Cyber Security Framework control list — an EXACT copy of the SAMA entry in sentra-grcai/engine/catalogue.js
// (LEGACY.sama: domains + ctrls [ref, domain, title, owner]), which is the single source of truth for the the
// organisation portal. Do not edit titles here: change them in sentra-grcai first and copy them across.
// tests/compliance-sama.test.js compares this file with ../sentra-grcai/engine/catalogue.js whenever that checkout is
// present next to sentra-siem, and checks that every id used by sama-map.json and by the rule `sama` tags exists here.

const DOMAINS = {
  '3.1': 'Cyber Security Leadership & Governance',
  '3.2': 'Cyber Security Risk Management & Compliance',
  '3.3': 'Cyber Security Operations & Technology',
  '3.4': 'Third Party Cyber Security',
};

const CTRLS = [
  ['3.1.1', '3.1', 'Cyber Security Governance', 'CISO'],
  ['3.1.2', '3.1', 'Cyber Security Strategy', 'CISO'],
  ['3.1.3', '3.1', 'Cyber Security Policy', 'CISO'],
  ['3.1.4', '3.1', 'Cyber Security Roles & Responsibilities', 'CISO'],
  ['3.1.5', '3.1', 'Cyber Security in Project Management', 'PMO'],
  ['3.1.6', '3.1', 'Cyber Security Awareness', 'CISO'],
  ['3.1.7', '3.1', 'Cyber Security Training', 'HR'],
  ['3.2.1', '3.2', 'Cyber Security Risk Management', 'Risk'],
  ['3.2.2', '3.2', 'Regulatory Compliance', 'Compliance'],
  ['3.2.3', '3.2', 'Compliance with (inter)national standards', 'Compliance'],
  ['3.2.4', '3.2', 'Cyber Security Review', 'Internal Audit'],
  ['3.2.5', '3.2', 'Cyber Security Audits', 'Internal Audit'],
  ['3.3.1', '3.3', 'Human Resources security', 'HR'],
  ['3.3.2', '3.3', 'Physical Security', 'Admin'],
  ['3.3.3', '3.3', 'Asset Management', 'IT'],
  ['3.3.4', '3.3', 'Cyber Security Architecture', 'IT'],
  ['3.3.5', '3.3', 'Identity & Access Management', 'IT'],
  ['3.3.6', '3.3', 'Application Security', 'IT'],
  ['3.3.7', '3.3', 'Change Management', 'IT'],
  ['3.3.8', '3.3', 'Infrastructure Security', 'IT'],
  ['3.3.9', '3.3', 'Cryptography', 'IT'],
  ['3.3.10', '3.3', 'Bring Your Own Device (BYOD)', 'IT'],
  ['3.3.11', '3.3', 'Secure Disposal of Information Assets', 'IT'],
  ['3.3.12', '3.3', 'Payment Systems (premium & claims settlement)', 'Finance'],
  ['3.3.13', '3.3', 'Electronic Services (portal & mobile app)', 'Digital'],
  ['3.3.14', '3.3', 'Cyber Security Event Management', 'SOC'],
  ['3.3.15', '3.3', 'Cyber Security Incident Management', 'SOC'],
  ['3.3.16', '3.3', 'Threat Management', 'SOC'],
  ['3.3.17', '3.3', 'Vulnerability Management', 'SOC'],
  ['3.4.1', '3.4', 'Contract & Vendor Management', 'Procurement'],
  ['3.4.2', '3.4', 'Outsourcing', 'Compliance'],
  ['3.4.3', '3.4', 'Cloud Computing', 'IT'],
];

const CONTROLS = CTRLS.map(([ref, domain, title, owner]) => ({ ref, domain, title, owner }));
const BY_REF = new Map(CONTROLS.map((c) => [c.ref, c]));

const control = (ref) => BY_REF.get(String(ref)) || null;
const has = (ref) => BY_REF.has(String(ref));
const refNum = (r) => String(r).split('.').reduce((n, p) => n * 1000 + (Number(p) || 0), 0);

module.exports = { DOMAINS, CTRLS, CONTROLS, control, has, refNum, SOURCE: 'sentra-grcai/engine/catalogue.js (LEGACY.sama)' };
