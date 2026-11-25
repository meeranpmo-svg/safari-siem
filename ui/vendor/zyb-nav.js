// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-nav.js - THE list of dashboards: one registry for the portal menu (zyb-menu.js), the dashboard sidebar,
 * breadcrumb and Ctrl+K search (zyb-dash.js) and the home page (index.html). Add a page here and it appears everywhere.
 * Area: sn = short menu name, name = full name, c = colour. Page fields: h = file, s = short menu label, t = full title, d = description. Area icon = inner SVG (24x24, stroke). */
// the brand setting: vendor/zyb-org.js on a page; a test that loads this file outside a page puts it on its window / global
var ZYB_ORG = (typeof window !== 'undefined' && window.ZYB_ORG) || (typeof globalThis !== 'undefined' && globalThis.ZYB_ORG) || undefined;
/* compliance frameworks each page supports (page field fw: {sama, nca, pdpl, ia} - codes of the domains below). The mapping
 * says which framework domain a page gives evidence or control for; it is not a certification. IA has no framework of its own: circular
 * UTC/277/202401 keeps insurers on the earlier rules, so a page's IA codes are its SAMA CSF codes (plus IA-277 below). xw = crosswalk: each NCA sub-domain / PDPL article -> the SAMA CSF controls that address
 * the same thing (domain level; a DRAFT for the compliance team to verify). Live Compliance (live-compliance.html) reads it. */
window.ZYB_FW = {
 "sama": {
  "name": "SAMA Cyber Security Framework",
  "short": "SAMA",
  "c": "#3fb950",
  "domains": {
   "3.1.1": "Cyber Security Governance",
   "3.1.2": "Cyber Security Strategy",
   "3.1.3": "Cyber Security Policy",
   "3.1.4": "Cyber Security Roles and Responsibilities",
   "3.1.5": "Cyber Security in Project Management",
   "3.1.6": "Cyber Security Awareness",
   "3.1.7": "Cyber Security Training",
   "3.2.1": "Cyber Security Risk Management",
   "3.2.2": "Regulatory Compliance",
   "3.2.3": "Compliance with International Industry Standards",
   "3.2.4": "Cyber Security Review",
   "3.2.5": "Cyber Security Audits",
   "3.3.1": "Human Resources",
   "3.3.2": "Physical Security",
   "3.3.3": "Asset Management",
   "3.3.4": "Cyber Security Architecture",
   "3.3.5": "Identity and Access Management",
   "3.3.6": "Application Security",
   "3.3.7": "Change Management",
   "3.3.8": "Infrastructure Security",
   "3.3.9": "Cryptography",
   "3.3.10": "Bring Your Own Device (BYOD)",
   "3.3.11": "Secure Disposal of Information Assets",
   "3.3.12": "Payment Systems",
   "3.3.13": "Electronic Banking Services",
   "3.3.14": "Cyber Security Event Management",
   "3.3.15": "Cyber Security Incident Management",
   "3.3.16": "Threat Management",
   "3.3.17": "Vulnerability Management",
   "3.4.1": "Contract and Vendor Management",
   "3.4.2": "Outsourcing",
   "3.4.3": "Cloud Computing",
   "BCM": "SAMA Business Continuity Management Framework (separate SAMA framework)"
  }
 },
 "nca": {
  "name": "NCA Essential Cybersecurity Controls (ECC-2:2024)",
  "short": "NCA",
  "c": "#79b8ff",
  "domains": {
   "1-1": "Cybersecurity Strategy",
   "1-2": "Cybersecurity Management",
   "1-3": "Cybersecurity Policies and Procedures",
   "1-4": "Cybersecurity Roles and Responsibilities",
   "1-5": "Cybersecurity Risk Management",
   "1-6": "Cybersecurity in Information Technology Projects",
   "1-7": "Compliance with Cybersecurity Standards, Laws and Regulations",
   "1-8": "Periodical Cybersecurity Review and Audit",
   "1-9": "Cybersecurity in Human Resources",
   "1-10": "Cybersecurity Awareness and Training Program",
   "2-1": "Asset Management",
   "2-2": "Identity and Access Management",
   "2-3": "Information System and Processing Facilities Protection",
   "2-4": "Email Protection",
   "2-5": "Networks Security Management",
   "2-6": "Mobile Devices Security",
   "2-7": "Data and Information Protection",
   "2-8": "Cryptography",
   "2-9": "Backup and Recovery Management",
   "2-10": "Vulnerabilities Management",
   "2-11": "Penetration Testing",
   "2-12": "Cybersecurity Event Logs and Monitoring Management",
   "2-13": "Cybersecurity Incident and Threat Management",
   "2-14": "Physical Security",
   "2-15": "Web Application Security",
   "3-1": "Cybersecurity Resilience Aspects of Business Continuity Management",
   "4-1": "Third-Party Cybersecurity",
   "4-2": "Cloud Computing and Hosting Cybersecurity"
  },
  "xw": {
   "1-1": [
    "3.1.2"
   ],
   "1-2": [
    "3.1.1"
   ],
   "1-3": [
    "3.1.3"
   ],
   "1-4": [
    "3.1.4"
   ],
   "1-5": [
    "3.2.1"
   ],
   "1-6": [
    "3.1.5"
   ],
   "1-7": [
    "3.2.2",
    "3.2.3"
   ],
   "1-8": [
    "3.2.4",
    "3.2.5"
   ],
   "1-9": [
    "3.3.1"
   ],
   "1-10": [
    "3.1.6",
    "3.1.7"
   ],
   "2-1": [
    "3.3.3"
   ],
   "2-2": [
    "3.3.5"
   ],
   "2-3": [
    "3.3.8"
   ],
   "2-4": [
    "3.3.8"
   ],
   "2-5": [
    "3.3.4",
    "3.3.8"
   ],
   "2-6": [
    "3.3.10"
   ],
   "2-7": [
    "3.3.3",
    "3.3.11"
   ],
   "2-8": [
    "3.3.9"
   ],
   "2-9": [
    "3.3.8",
    "BCM"
   ],
   "2-10": [
    "3.3.17"
   ],
   "2-11": [
    "3.3.17"
   ],
   "2-12": [
    "3.3.14"
   ],
   "2-13": [
    "3.3.15",
    "3.3.16"
   ],
   "2-14": [
    "3.3.2"
   ],
   "2-15": [
    "3.3.6"
   ],
   "3-1": [
    "BCM"
   ],
   "4-1": [
    "3.4.1",
    "3.4.2"
   ],
   "4-2": [
    "3.4.3"
   ]
  }
 },
 "pdpl": {
  "name": "Personal Data Protection Law (PDPL) and its Implementing Regulation",
  "short": "PDPL",
  "c": "#d2a8ff",
  "domains": {
   "Art. 4": "Data subject rights (informed, access, copy, correction, destruction)",
   "Art. 5": "Consent, and its withdrawal (IR Arts. 11-12)",
   "Art. 8": "Processors - sufficient guarantees, written agreement, sub-processors (IR Art. 17)",
   "Art. 11": "Minimum necessary data, for the stated purpose",
   "Art. 17": "Correction of personal data",
   "Art. 18": "Destruction once no longer needed",
   "Art. 19": "Security of personal data - organisational, administrative and technical measures (IR Art. 23: NCA controls)",
   "Art. 20": "Personal data breach - notify SDAIA within 72 hours (IR Art. 24)",
   "Art. 22": "Impact assessment - continuous monitoring, linking sources, new technology (IR Art. 25)",
   "Art. 23": "Health data",
   "Art. 24": "Credit data (Credit Information Law; IR Art. 27)",
   "Art. 29": "Transfer outside the Kingdom (Cross-Border Transfer Regulation)",
   "Art. 35": "Penalty - disclosing or publishing sensitive data to harm or for gain (prison up to 2 years, fine up to SAR 3 million)",
   "Art. 36": "Penalty - other violations: warning or fine up to SAR 5 million, doubled for a repeat",
   "Art. 41": "Confidentiality of personal data by everyone processing it",
   "Art. 31": "Records of processing activities",
   "IR Art. 32": "Data Protection Officer",
   "IR Art. 33": "Records of processing activities (processing period + 5 years)"
  },
  "xw": {
   "Art. 4": [],
   "Art. 5": [],
   "Art. 8": [
    "3.4.2"
   ],
   "Art. 11": [],
   "Art. 17": [],
   "Art. 18": [
    "3.3.11"
   ],
   "Art. 19": [
    "3.3.5",
    "3.3.8",
    "3.3.9",
    "3.3.14"
   ],
   "Art. 20": [
    "3.3.15"
   ],
   "Art. 22": [
    "3.2.1"
   ],
   "Art. 23": [
    "3.3.5"
   ],
   "Art. 24": [],
   "Art. 29": [
    "3.4.2",
    "3.4.3"
   ],
   "Art. 35": [],
   "Art. 36": [],
   "Art. 41": [
    "3.3.1",
    "3.3.5"
   ],
   "Art. 31": [
    "3.3.14"
   ],
   "IR Art. 32": [
    "3.1.2"
   ],
   "IR Art. 33": [
    "3.3.14"
   ]
  }
 },
 "ia": {
  "name": "Insurance Authority (IA) - SAMA CSF baseline",
  "short": "IA",
  "c": "#ffa657",
  "domains": {
   "3.1.1": "Cyber Security Governance",
   "3.1.2": "Cyber Security Strategy",
   "3.1.3": "Cyber Security Policy",
   "3.1.4": "Cyber Security Roles and Responsibilities",
   "3.1.5": "Cyber Security in Project Management",
   "3.1.6": "Cyber Security Awareness",
   "3.1.7": "Cyber Security Training",
   "3.2.1": "Cyber Security Risk Management",
   "3.2.2": "Regulatory Compliance",
   "3.2.3": "Compliance with International Industry Standards",
   "3.2.4": "Cyber Security Review",
   "3.2.5": "Cyber Security Audits",
   "3.3.1": "Human Resources",
   "3.3.2": "Physical Security",
   "3.3.3": "Asset Management",
   "3.3.4": "Cyber Security Architecture",
   "3.3.5": "Identity and Access Management",
   "3.3.6": "Application Security",
   "3.3.7": "Change Management",
   "3.3.8": "Infrastructure Security",
   "3.3.9": "Cryptography",
   "3.3.10": "Bring Your Own Device (BYOD)",
   "3.3.11": "Secure Disposal of Information Assets",
   "3.3.12": "Payment Systems",
   "3.3.13": "Electronic Banking Services",
   "3.3.14": "Cyber Security Event Management",
   "3.3.15": "Cyber Security Incident Management",
   "3.3.16": "Threat Management",
   "3.3.17": "Vulnerability Management",
   "3.4.1": "Contract and Vendor Management",
   "3.4.2": "Outsourcing",
   "3.4.3": "Cloud Computing",
   "BCM": "SAMA Business Continuity Management Framework (separate SAMA framework)",
   "IA-277": "Cyber-incident contact mailbox, not tied to one employee (circular UTC/277/202401)"
  },
  "baseline": "sama",
  "basis": "The Insurance Authority has not published its own cyber security framework. IA circular UTC/277/202401 (January 2024) tells insurers to keep applying the cyber security rules issued before, so this view shows the SAMA Cyber Security Framework as the IA baseline, plus the circular’s own requirement: a cyber-incident contact mailbox that is not tied to one employee.",
  "extra": [
   {
    "code": "IA-277",
    "name": "Cyber-incident contact mailbox, not tied to one employee (circular UTC/277/202401)"
   }
  ]
 }
};

/* a page's frameworks as [{k, short, c, codes:[[code, domain name]]}] - frameworks it has no code for are left out */
window.zybFwTags = function (fw) {
 var F = window.ZYB_FW || {}, out = [];
 ['sama', 'nca', 'pdpl', 'ia'].forEach(function (k) { var f = F[k], c = (fw && fw[k]) || []; if (f && c.length) out.push({ k: k, short: f.short, c: f.c, codes: c.map(function (x) { return [x, f.domains[x] || '']; }) }); });
 return out;
};
/* the menu's five headings (area field hd), in this order; an area's pages flagged start:true are shown once, under "Start
   here" at the top, and not again inside their area */
/* sub-menu headings (page field g) in both menus: a coloured line icon per heading, chosen by its words, so "Audit teams" looks
 * the same in the portal menu and the dashboard sidebar. Each heading opens / hides its pages; the choice is remembered. */
window.zybSgStyle = function (name) {
  var n = String(name || '').toLowerCase(), M = [
    [/exchange|mail/, '#0ea5e9', '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>'],
    [/vulnerab/, '#f97316', '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>'],
    [/penetration|pentest/, '#e11d48', '<path d="M14.5 17.5 3 6V3h3l11.5 11.5"/><path d="m13 19 6-6M16 16l4 4M19 21l2-2"/>'],
    [/attack|simulation/, '#d946ef', '<path d="M13 2 3 14h9l-1 8 10-12h-9z"/>'],
    [/overview|dashboard/, '#3b82f6', '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>'],
    [/team/, '#a855f7', '<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><circle cx="17" cy="9" r="2.5"/><path d="M15.5 14.2c2.9.4 5.5 2.6 5.5 5.8"/>'],
    [/evidence|log/, '#f59e0b', '<path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="1"/><path d="m9 14 2 2 4-4"/>'],
    [/technical|audit/, '#14b8a6', '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4z"/>'],
    [/regulat|framework|compliance/, '#22c55e', '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9 4.6-.4 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>'],
    [/grc|governance|risk/, '#6366f1', '<path d="M12 3v18M5 7h14"/><path d="m5 7-3 6c0 1.7 1.3 3 3 3s3-1.3 3-3zM19 7l-3 6c0 1.7 1.3 3 3 3s3-1.3 3-3z"/>'],
    [/server/, '#06b6d4', '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>'],
    [/virtual|cloud/, '#8b5cf6', '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>'],
    [/network|wireless/, '#0ea5e9', '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M12 12l-6 5M12 12l6 5"/>'],
    [/security|cyber|threat/, '#ef4444', '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9 4.6-.4 8-4 8-9V6z"/>'],
    [/data|database|storage/, '#10b981', '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/>']
  ];
  for (var i = 0; i < M.length; i++) if (M[i][0].test(n)) return { c: M[i][1], icon: M[i][2] };
  var pal = ['#3b82f6', '#a855f7', '#f59e0b', '#14b8a6', '#ec4899', '#22c55e'], h = 0;
  for (var j = 0; j < n.length; j++) h = (h * 31 + n.charCodeAt(j)) >>> 0;
  return { c: pal[h % pal.length], icon: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 12h8"/>' };
};
window.ZYB_HEADS = [['overview', 'Overview'], ['security', 'Security'], ['infra', 'Infrastructure'], ['business', 'Business services'], ['gov', 'Governance & compliance'], ['privacy', 'Data privacy'], ['audit', 'Audit & assurance'], ['admin', 'Administration'], ['ai', 'Artificial Intelligence']];
window.ZYB_NAV = [
 {
  "id": "cmd",
  "sn": "Command Center",
  "name": "Command & Leadership",
  "c": "#a371f7",
  "hd": "overview",
  "icon": "<path d=\"M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z\"/>",
  "pages": [
   {"h": "ops-command.html", "s": "Operations Command", "t": "Operations Command - the whole estate in one colourful view: FortiGate fleet, NAC, NDR, Hyper-V, Call Manager, Aramco CCC and the AI engineers' open work", "d": "Charts read live from each module, with the learned findings of every module ranked together. A module that is not connected says what to connect; nothing is invented."},
   {
    "h": "executive-dashboard.html",
    "s": "Executive Dashboard",
    "t": "Executive Dashboard",
    "d": "One explainable health index for IT and cyber security over five pillars (cyber posture, compliance, resilience, IT operations, risk) read live from the Reporting Center, AI CISO and Risk Studio; daily history with trend, 30-day forecast and unusual days; what needs the executive, ranked; AI executive brief",
    "fw": {
     "sama": [
      "3.1.1",
      "3.1.3",
      "3.3.8"
     ],
     "nca": [
      "1-1",
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.1.3",
      "3.3.8"
     ]
    },
    "g": "Leadership dashboards"
   },
   {
    "h": "cio-dashboard.html",
    "s": "CIO Dashboard",
    "t": "CIO Dashboard",
    "d": "IT performance, spend and delivery: business service availability (Applications Manager), the IT budget generated from the asset register, renewals and unused licences, security posture and SAMA coverage, critical risks and decisions waiting for a person (AI CISO overview), the AI engineering team, detection and response, the latest board brief. A source not connected says so; no sample data.",
    "fw": {
     "sama": [
      "3.1.1",
      "3.1.3",
      "3.3.8"
     ],
     "nca": [
      "1-1",
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.1.3",
      "3.3.8"
     ]
    },
    "g": "Leadership dashboards"
   },
   {
    "h": "ciso-dashboard.html",
    "s": "CISO Dashboard",
    "t": "CISO Dashboard",
    "d": "Security posture by domain with its trend and ML forecast, the alerts open right now synced live from the SOC (every 10 seconds, new ones highlighted), alerts per day with an unusual-day flag and a 7-day forecast, what moved since last week, where to focus, top risks, decisions waiting for a person and the latest board brief. A source not connected says so; no sample data.",
    "fw": {
     "sama": [
      "3.1.1",
      "3.3.14"
     ],
     "nca": [
      "1-1",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.3.14"
     ]
    },
    "g": "Leadership dashboards"
   },
   {
    "h": "head-of-it.html",
    "s": "IT Command Center",
    "t": "IT Command Center (Head of IT)",
    "d": "Applications and infrastructure: services, SLAs, incidents, capacity and changes",
    "fw": {
     "sama": [
      "3.1.1",
      "3.2.1"
     ],
     "nca": [
      "1-2",
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.2.1"
     ]
    },
    "g": "Leadership dashboards"
   },
   {
    "h": "infra-manager.html",
    "s": "IT Infrastructure Manager",
    "t": "IT Infrastructure Manager",
    "d": "Infrastructure health, capacity and change from the asset register and the collectors: servers and network devices, host and device availability, applications (Applications Manager), databases, backups, Endpoint Central patches, storage, end of life, approved changes waiting, support contracts and warranty. A source not connected says so; no sample data.",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3",
      "BCM"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3",
      "BCM"
     ]
    },
    "g": "Leadership dashboards"
   },
   {
    "h": "live-status.html",
    "s": "Live Status",
    "t": "Live Status",
    "d": "Is every data feed alive right now: each SIEM source with its last event, volume, lag and parse errors; ML learns each feed's rhythm and its usual volume per hour of the day to flag late, dropped and spiking feeds before the SLA; health per feed; AI live-status analyst",
    "fw": {
     "sama": [
      "3.1.1",
      "3.1.3",
      "3.3.8"
     ],
     "nca": [
      "1-1",
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.1.3",
      "3.3.8"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "custom-dashboards.html",
    "s": "Custom Dashboards",
    "k": ["widgets", "query builder", "my dashboard", "kpi", "charts"],
    "t": "Custom Dashboards - build your own widget dashboards over live data with a query builder; AI proposes widgets, machine learning shows trend, forecast and unusual days",
    "d": "Dashboards of KPI, gauge, table, bar, donut and split widgets over assets and their coverage, open vulnerabilities, installed software and the platform's sources; a query builder with field / operator / value suggestions and a live preview; describe a widget and the AI proposes it for a person to add; per-widget trend, 30-day forecast and unusual-day flag from daily history; private or shared, owner or admin edits",
    "fw": {
     "sama": [
      "3.1.1"
     ],
     "nca": [
      "1-3"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "platform-map.html",
    "s": "Platform Map",
    "k": ["architecture", "how it works", "integrations", "sources", "diagram"],
    "t": "Platform Map - how the platform works for {{org.short}}: sources, AI and machine learning stages, outcomes",
    "d": "Every source that feeds the platform (vulnerability scanners, firewalls, endpoint protection, SIEM, service desk, endpoint management, identity, email, backup, virtualization, storage, databases, certificates, discovery) with its real state - connected, needs attention or not connected - flowing into Zyberon: collect, correlate, machine learning, AI engineers, a person approves; and out to asset intelligence, coverage gaps, unified vulnerabilities, risk, compliance, detection and remediation verification, each a click away",
    "fw": {
     "sama": [
      "3.3.4"
     ],
     "nca": [
      "1-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.4"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "ops-wall.html",
    "s": "Operations Wall",
    "t": "{{org.short}} Operations Wall",
    "d": "Big-screen NOC + SOC wall: live high / critical alerts, posture, platform tiers, incidents and who is on call, decisions waiting for a person, what changed this shift, metrics unusual for the time of day, rotating views and kiosk mode (?kiosk=1&rotate=30), AI shift handover",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-1",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "noc-overview.html",
    "s": "NOC Overview",
    "t": "NOC Overview",
    "d": "One-screen network operations centre: node health, availability, infrastructure by device role, nodes with problems, interface errors, devices by CPU/memory, and recent alarms",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-5",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "servers-dashboard.html",
    "s": "Servers, Cloud & Applications",
    "t": "Servers, Cloud & Applications Dashboard",
    "d": "The platforms the business runs on in five tiers - virtualization, servers & OS, databases, DR replication, cloud servers - from the modules that measure them: health per tier, one ranked issue feed with where to fix it, cluster capacity forecasts, daily health trend with unusual-drop detection, AI operations analyst, Excel",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-1",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "infra-inventory.html",
    "s": "Infrastructure Inventory",
    "t": "Infrastructure Inventory",
    "d": "Every firewall, switch, router, server, VM, storage system and cloud server in the asset register with what sees it - discovery, agent / Endpoint Central, vCenter / Prism, SIEM logs, owner, site, criticality; coverage heat map, peer outliers, stale and duplicate assets, sites, the portal's hand-kept rows not in the register, AI analyst, Excel",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-1",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "infra-ai.html",
    "s": "Infrastructure Automation AI",
    "t": "Infrastructure Automation AI",
    "d": "Learned from Infrastructure Automation (sentra-infra): disk and connection-pool forecasts, recurring and flapping problems, noisy self-clearing rules, MTTA / MTTR now against before, unusual incident days, monitoring coverage gaps, itemised risk per target and a health index, ranked next actions, read-only AI advisor",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-1",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "update-studio.html",
    "s": "IT Operations & Updates",
    "t": "IT Operations & Updates",
    "d": "Every server update measured from Endpoint Central, the IT Asset Management agent and vCenter / Prism and checked against the patch and change policy: critical patches within SLA, patch state known, update cycle, version drift, change reference and post-update check on production, staging before production; update history, risk ranking, cadence anomalies, AI update analyst, Excel",
    "fw": {
     "sama": [
      "3.3.13",
      "3.3.7"
     ],
     "nca": [
      "2-3",
      "1-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.13",
      "3.3.7"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "patch-management.html",
    "s": "Patching - All Assets",
    "t": "Unified Patch Management",
    "d": "Every IT asset's patch state in one view - servers, desktops and laptops, switches and routers, firewalls and databases - from Update Studio, Endpoint Central, Cisco Update Manager, the database inventory, the vulnerability scanner and end of life: overdue, end of life, behind, current or not measured, coverage per class with what to connect, the priority with every point named, baseline releases per platform, and patch exceptions approved by a different person",
    "fw": {
     "sama": [
      "3.3.13"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.13"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "update-guardrails.html",
    "s": "Update Guardrails",
    "t": "Update Guardrails - sandbox first, then waves, for servers, network and security devices",
    "d": "Every server patch, network firmware, firewall / VPN firmware and hypervisor update goes to a registered sandbox twin first (matched by vendor, model and OS), passes measured and attested checks and a soak time, then rolls out in waves (canary first) each approved by a different person and verified healthy before the next. ML risk 0-100, itemised and learned from this platform's own update outcomes; maintenance window, change freezes, blocked versions; a decision point (UG-01..11) answering allow / deny / allow with conditions; AI sandbox test plan from the release notes (advisory).",
    "fw": {
     "sama": [
      "3.3.7",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "1-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.7",
      "3.3.14"
     ]
    },
    "g": "Live operations"
   },
   {
    "h": "my-workspace.html",
    "s": "My Workspace",
    "t": "My Workspace - mail, meetings, Teams and tasks",
    "d": "Your own Outlook inbox (read and reply), today's meetings with Join, Teams chats, the tasks assigned to you and waiting for your review, and your team - plus the organisation: departments, job roles, people, reporting lines and task workflows",
    "fw": {
     "sama": [
      "3.1.4",
      "3.3.15"
     ],
     "nca": [
      "1-4",
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.1.4",
      "3.3.15"
     ]
    },
    "start": true,
    "g": "My work"
   },
   {
    "h": "my-workflow.html",
    "s": "Role Workflows",
    "g": "My work",
    "t": "Role Workflows - the daily, weekly and monthly work of each IT role, with sign-off and handover",
    "d": "GRC consultant, Exchange Server, Windows Server and virtualization administrators, network, security and desktop support engineers, SOC analyst, SIEM engineer and penetration testing engineer: each step shows what the platform records now (servers not seen, end of life, warranty, the AI engineers' open findings, overdue GRC actions, risks past review, expiring exceptions, stale evidence) or says it must be confirmed on the linked page - never shown as fine; each person signs steps off (done / issue / not applicable with a note), writes the handover, and another person acknowledges it",
    "fw": {
     "sama": [
      "3.3.1"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.1"
     ]
    }
   },
   {
    "h": "my-work.html",
    "s": "My Work",
    "t": "My Work - start here",
    "d": "What needs you now across every AI engineer and system: decisions waiting (approvals, changes to apply, patch installs, response actions, tickets), critical and high problems, and what is not set up yet - one click to each",
    "fw": {
     "sama": [
      "3.3.7",
      "3.3.15"
     ],
     "nca": [
      "1-2",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.3.7",
      "3.3.15"
     ]
    },
    "start": true,
    "g": "My work"
   },
   {
    "h": "report-center.html",
    "s": "Reporting Center",
    "t": "Reporting Center - reports with AI and machine learning",
    "d": "Executive, compliance, security, SOC, DR and asset reports built from the platform's live modules; daily history with trends, forecasts and unusual moves; AI executive summary; scheduled e-mail with HTML and CSV",
    "fw": {
     "sama": [
      "3.1.2",
      "3.3.14"
     ],
     "nca": [
      "1-1",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.1.2",
      "3.3.14"
     ]
    },
    "g": "Reports & service"
   },
   {
    "h": "notify-center.html",
    "s": "Notification & Escalation",
    "t": "Notification & Escalation - on-call routing with AI and machine learning",
    "d": "SOC alerts and platform problems routed to the person on call, escalation ladders until someone acknowledges, maintenance windows, after-hours hold; learnt acknowledge times, escalation risk, noisy policies, alert fatigue and storms; AI explains and proposes, a person approves",
    "fw": {
     "sama": [
      "3.3.15",
      "3.3.14"
     ],
     "nca": [
      "2-13",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.15",
      "3.3.14"
     ]
    },
    "g": "Reports & service"
   },
   {
    "h": "workflow-automation.html",
    "s": "Workflow Automation",
    "t": "Workflow Automation - business requests to the IT teams, with AI and machine learning",
    "d": "What the CISO office, risk, audit, HR, administration, GRC, IT governance and the DPO need from the network, server, database, security, identity, backup, endpoint and application teams: a request catalogue with SLAs, four-eyes approval and acceptance, evidence collected from the platform's own records, scheduled requests, escalation; machine learning routes, forecasts breach risk and workload and finds recurring demand; AI drafts the team's response",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.15"
     ],
     "nca": [
      "1-2",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5",
      "3.3.15"
     ]
    },
    "g": "Reports & service"
   },
   {
    "h": "service-agreement.html",
    "s": "Service Agreement (SLA & NDA)",
    "t": "Service Agreement - SLA and NDA, {{org.short}} and Citynet Work",
    "d": "The SLA and NDA between {{org.short}} and Citynet Work (delivered through Zyberon Information Technology): customisable support terms, priorities and audit-remediation targets, support cases between the parties, the monthly statement with service-credit deductions and Excel export, and agreements approved by both signatories and published",
    "fw": {
     "sama": [
      "3.4.2",
      "3.4.3"
     ],
     "nca": [
      "4-1"
     ],
     "pdpl": [],
     "ia": [
      "3.4.2",
      "3.4.3"
     ]
    },
    "g": "Reports & service"
   }
  ]
 },
 {
  "id": "soc",
  "sn": "SOC & Response",
  "name": "Security Operations & Incident Response",
  "c": "#ff7b72",
  "hd": "security",
  "icon": "<path d=\"M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z\"/><path d=\"m9 12 2 2 4-4\"/>",
  "pages": [
   {"h": "ndr.html", "s": "Network Detection (NDR)", "t": "Network Detection & Response - beaconing, unusual outbound volume, lateral movement and new countries from the firewalls' traffic logs", "d": "Hosts ranked by an itemised risk from machine-learning detections over the FortiGate traffic logs, each against the organisation's own history: regular check-ins to the same outside address, outbound volume above a host's usual, admin-port reach inside, first traffic to a country; four-eyes suppressions", "fw": {"nca": ["2-12", "2-13"], "iso": ["8.16", "8.20"]}, "k": ["ndr", "network detection", "beacon", "c2", "exfiltration", "lateral movement", "machine learning", "linkshadow"]},
   {
    "h": "soc-overview.html",
    "s": "SOC Overview",
    "t": "Security Operations Overview",
    "d": "The SOC at a glance from the SIEM's own stores: open alerts by explainable priority and severity, 14-day volume raised vs closed (true positive / false positive / benign), time to acknowledge and resolve, act-now alerts, ATT&CK tactics, top rules, entities and sources, XDR incidents, UEBA (machine learning) riskiest behaviour, rules learned as noisy, and how often analysts agreed with the AI SOC analyst",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.15"
     ],
     "nca": [
      "2-12",
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.14",
      "3.3.15"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "soc-alerts.html",
    "s": "Alert Queue",
    "t": "Alert Queue with the AI SOC analyst",
    "d": "Every open alert ranked by an itemised priority learned from this SIEM's history (severity, first-time entity, rare rule, UEBA risk, threat intel, XDR correlation, how the rule was closed before), near-identical alerts grouped, filters and bulk acknowledge / assign; the AI SOC analyst investigates one alert with read-only tools and drafts a verdict with cited evidence - a person accepts or rejects it, and containment stays an approval request",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.15"
     ],
     "nca": [
      "2-12",
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.14",
      "3.3.15"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "soc-console.html",
    "s": "SOC Console",
    "t": "SOC Console (offenses, agents, file integrity, ingest)",
    "d": "The SOC's working console: open offenses by explainable priority with a magnitude 1-10, the ATT&CK tactics in play, events per minute against the hour's normal, every agent's heartbeat, version and queue health (active, delayed, disconnected, outdated, retired with a reason), file and registry changes on the watched paths with their coverage, and the live event stream",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.15"
     ],
     "nca": [
      "2-12",
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.14",
      "3.3.15"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "alarm-rules.html",
    "s": "Alarm Inbox Rules",
    "t": "Alarm Inbox Rules (detection rules with ML tuning and an AI rule assistant)",
    "d": "The SIEM engine's rules that raise every alarm: a form editor with backtest, health from each rule's own alerts (noisy, mostly false positives, bursts, silent, broken), the false-positive rate withheld below three closures, proposed exclusions, overlapping rules and ATT&CK coverage gaps - and an AI rule assistant whose drafts arrive disabled for a person to backtest and an admin to save",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.15"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.3.15"
     ]
    },
    "g": "SIEM platform"
   },
   {
    "h": "soc-performance.html",
    "s": "SOC Performance",
    "t": "SOC Performance & Operations",
    "d": "How fast the SOC detects, acknowledges and resolves alerts (median and 90th percentile, per severity and week, from the alert records), the open alerts to work first with every priority point explained, the watchlist of hosts, IPs, users, domains, hashes and CVEs whose appearance raises an alert, and the crown-jewel systems that raise an alert's priority",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "security-center.html",
    "s": "Security Center",
    "t": "Security Center",
    "d": "The security posture on one screen, read live: a threat level with its reasons, open alerts by severity, what the firewalls, IPS and antivirus blocked or detected in 24 h (by source, kind and host), endpoint protection coverage, Microsoft 365 Secure Score and MFA, rogue devices, silent log sources, the most alerted entities and tactics - each card opens the page that owns it",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "soc-live.html",
    "s": "Live SIEM Stream",
    "t": "Live SIEM Stream (real time, AI / ML)",
    "d": "Every event the moment the SIEM receives it, with the learned normal rate, bursts, new log patterns, password spray and brute force, quiet sources, top entities and the SOC Copilot",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "log-monitor.html",
    "s": "Log Monitor & Analysis",
    "t": "Log Monitor & Analysis",
    "d": "What the logs say, not only that they arrive: events and rate against the usual rate, the share at medium or worse, volume over time by source type, top sources, hosts and categories, and every message reduced to its pattern - new, spiking and stopped patterns against the window before, with the latest line and a hunt link. Analysts and above (personal data).",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "soc-xdr.html",
    "s": "XDR",
    "t": "SOC XDR - Extended Detection & Response",
    "d": "One incident per attack across endpoint, identity, network, email, web and data alerts: explainable score, ATT&CK chain, open a case with playbook approvals, threat hunting and beaconing analysis",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.15",
      "3.3.16"
     ],
     "nca": [
      "2-12",
      "2-13"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.14",
      "3.3.15",
      "3.3.16"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "soc-intel.html",
    "s": "After-hours monitoring",
    "t": "After-hours monitoring and paging",
    "d": "Indicator lists and their matches; activity outside working hours by person, admin action and SharePoint file use; after-hours alerting and working hours; after-hours mode: on-call paging, containment prepared for approval, morning brief",
    "fw": {
     "sama": [
      "3.3.16",
      "3.3.14"
     ],
     "nca": [
      "2-13",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.16",
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "soc-cases.html",
    "s": "Investigations & Cases",
    "t": "Investigations & Cases",
    "d": "Every case with its stage, SLA, owner and workload; the case workspace merges the case log, its alerts (with their explainable priority), their history and the AI triage decisions into one timeline, shows the scope (users, hosts, IPs), tasks, evidence and the containment actions waiting for approval, and suggests open alerts that share an entity; the AI writes an investigation brief that a person reviews and adds as their note",
    "fw": {
     "sama": [
      "3.3.15"
     ],
     "nca": [
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.15"
     ]
    },
    "g": "Investigate"
   },
   {
    "h": "soc-hunt.html",
    "s": "Threat Hunting & Search",
    "t": "Threat Hunting & Search",
    "d": "Search every collected event with the platform query language, events over time and top values, long-tail (rare) and first-seen statistics against a baseline, the ATT&CK hunt library, saved and shared hunts, beaconing, leads the alert queue would miss, and the AI hunt assistant that proposes queries from counts and top values only - every search audited (PDPL)",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.16"
     ],
     "nca": [
      "2-12",
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.14",
      "3.3.16"
     ]
    },
    "g": "Investigate"
   },
   {
    "h": "soc-ueba.html",
    "s": "User Behaviour (UEBA)",
    "t": "User Behaviour (UEBA, machine learning)",
    "d": "Each user's, service account's and host's learned baseline and peer group; risk tiers, the risk-score distribution and timeline, every finding explained, detector precision learned from analysts' reviews, peer groups, threats by department, and the AI behaviour assessment (indicators, not proof)",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.5",
      "3.3.16"
     ],
     "nca": [
      "2-12",
      "2-2",
      "2-13"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 22",
      "Art. 11"
     ],
     "ia": [
      "3.3.14",
      "3.3.5",
      "3.3.16"
     ]
    },
    "g": "Investigate"
   },
   {
    "h": "insider-risk.html",
    "s": "Insider Risk",
    "t": "Insider risk: behaviour, DLP and approved context, pseudonymised",
    "d": "Live insider-risk indicators per pseudonymised person: UEBA behaviour, DLP incidents and time-bound context (departing, privileged, role change) approved by a second person; itemised score, the behaviour-and-data pattern, comparison with the department; cases authorised by a different administrator, the name only inside an authorised case and every look recorded; AI indicator notes that never name anyone. Indicators, not proof (PDPL)",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.5",
      "3.3.16"
     ],
     "nca": [
      "2-12",
      "2-2",
      "2-13"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 22",
      "Art. 11"
     ],
     "ia": [
      "3.3.14",
      "3.3.5",
      "3.3.16"
     ]
    },
    "g": "Investigate"
   },
   {
    "h": "soc-ti.html",
    "s": "Threat Intelligence",
    "t": "Threat Intelligence",
    "d": "Indicators loaded from the feeds, sightings (every alert in 30 days carrying a listed IP, domain, URL host or hash, with the hosts and users involved), a retro-hunt of recent traffic against today's lists, indicator lookup, the lists and feed management (administrator)",
    "fw": {
     "sama": [
      "3.3.16"
     ],
     "nca": [
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.16"
     ]
    },
    "g": "Investigate"
   },
   {
    "h": "dark-web-watch.html",
    "s": "Dark Web Watch",
    "t": "Dark Web Watch (leaked staff credentials)",
    "d": "Staff accounts on the company's e-mail domains found in data breaches, stealer-malware logs, pastes and underground mentions - from Have I Been Pwned and the threat-intelligence provider's exports, never by crawling - matched to Active Directory (enabled, privileged, password changed since the leak), with an explainable risk, alerts for serious exposures and a verified reset lifecycle; passwords are never stored",
    "fw": {
     "sama": [
      "3.3.6"
     ],
     "nca": [
      "2-13"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.6"
     ]
    },
    "g": "Investigate"
   },
   {
    "h": "incident-response.html",
    "s": "Incident Response Center",
    "t": "Incident Response Center: every incident by lifecycle phase",
    "d": "Every incident the SOC is responding to, by phase (open, investigating, contained, eradicated, recovered) with its SLA, the playbook next steps, response actions waiting for an approver and the DFIR regulator clocks; SLA breach risk and similar past incidents learned from closed cases; MTTA / MTTC / MTTR and the backlog forecast; XDR incidents without a case; the AI incident commander drafts a response plan or a stakeholder update a person adds to the case",
    "fw": {
     "sama": [
      "3.3.15"
     ],
     "nca": [
      "2-13"
     ],
     "pdpl": [
      "Art. 20",
      "Art. 19",
      "Art. 41"
     ],
     "ia": [
      "3.3.15"
     ]
    },
    "g": "Respond"
   },
   {
    "h": "soc-response.html",
    "s": "Playbooks & Approvals",
    "t": "SOC Response: Playbooks & Approvals",
    "d": "Response actions waiting for approval (block IP, disable account, revoke sessions), playbooks, and applying a playbook to an open case",
    "fw": {
     "sama": [
      "3.3.15",
      "3.3.7"
     ],
     "nca": [
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.15",
      "3.3.7"
     ]
    },
    "g": "Respond"
   },
   {
    "h": "soar.html",
    "s": "SOAR - Automated Response",
    "t": "SOAR - Automated Response: playbook matches, runs, approvals, automation",
    "d": "Open alerts matched to response playbooks with an itemised confidence learned from closed cases and approval decisions; a person runs a playbook (a case whose response actions wait for a different person to approve them); per-playbook opt-in automatic proposals as system:soar, which never approves; AI response brief per match; the SIEM never executes an action",
    "fw": {
     "sama": [
      "3.3.15",
      "3.3.7"
     ],
     "nca": [
      "2-13"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.3.15",
      "3.3.7"
     ]
    },
    "g": "Respond"
   },
   {
    "h": "dfir.html",
    "s": "Forensics & IR (DFIR)",
    "t": "DFIR - Forensics & Incident Response",
    "d": "Investigate a host, user or IP: a forensic super-timeline (processes, logons, network, DNS, detections) and triage rollup from the event store, the open IR cases and response-approval queue, and triage-collection requests routed to the response agent",
    "fw": {
     "sama": [
      "3.3.15"
     ],
     "nca": [
      "2-13"
     ],
     "pdpl": [
      "Art. 20",
      "Art. 19",
      "Art. 41"
     ],
     "ia": [
      "3.3.15"
     ]
    },
    "g": "Respond"
   },
   {
    "h": "soc-sources.html",
    "s": "Log Sources & Agents",
    "t": "SIEM Log Sources & Windows Agents",
    "d": "Every log source: receiving, silent, never received or not identified (with its last lines); which Windows servers' agents report and which inventory servers do not; collectors and ports",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.3"
     ],
     "nca": [
      "2-12",
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.3.3"
     ]
    },
    "g": "SIEM platform"
   },
   {
    "h": "log-assurance.html",
    "s": "Log Flow Assurance",
    "t": "Log Flow Assurance",
    "d": "Is every asset that should log actually logging: coverage by class and site, silent assets, assets waiting for device configuration, not onboarded, log senders not in the inventory, delay and unparsed share per source; the AI SIEM Engineer works each gap",
    "fw": {
     "sama": [
      "3.3.14",
      "3.2.4"
     ],
     "nca": [
      "2-12",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.2.4"
     ]
    },
    "g": "SIEM platform"
   },
   {
    "h": "pipeline-health.html",
    "s": "Pipeline Health",
    "t": "Pipeline Health - is the SIEM reading, analysing and alerting",
    "d": "A labelled test line goes through the SIEM's real path every 15 minutes - parse, pipeline, detection rule, alert, event store - each stage timed; healthy / degraded / failing / canary stopped, 24 hours of runs, live stage counters, and an independent watcher in IT Asset Management that raises a platform incident when it fails or the SIEM does not answer",
    "fw": {
     "sama": [
      "3.3.14",
      "3.2.4"
     ],
     "nca": [
      "2-12",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.2.4"
     ]
    },
    "g": "SIEM platform"
   },
   {
    "h": "device-config.html",
    "s": "Device Configuration",
    "t": "Device Configuration - every device by type",
    "d": "Every device the asset register says must send logs, by device type, with the real count sending / waiting for the device / stopped / not enrolled / without connector, the exact configuration to apply per type, devices waiting longer than usual for their type (learned), sources that keep dropping out, AI configuration assistant, Excel",
    "fw": {
     "sama": [
      "3.3.14",
      "3.2.4"
     ],
     "nca": [
      "2-12",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.2.4"
     ]
    },
    "g": "SIEM platform"
   },
   {
    "h": "soc-tickets.html",
    "s": "SIEM Health & SLA",
    "t": "SIEM Health, Tickets & SLA (CISO)",
    "d": "Is the SIEM working: engine, collectors, log sources, hardware. Tickets from SIEM alerts, time to resolve, SLA violations",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.15"
     ],
     "nca": [
      "2-12",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.3.15"
     ]
    },
    "g": "SIEM platform"
   },
   {
    "h": "soc-lr.html",
    "s": "SIEM vs LogRhythm",
    "t": "SIEM vs LogRhythm",
    "d": "Parallel run: LogRhythm alarms our SIEM also raised, the ones it missed with a review of why, rule and source comparison, and the exit criteria to retire LogRhythm",
    "fw": {
     "sama": [
      "3.3.14",
      "3.2.4"
     ],
     "nca": [
      "2-12",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.2.4"
     ]
    },
    "g": "SIEM platform"
   }
  ]
 },
 {
  "id": "pt",
  "sn": "Pentest & VAPT",
  "name": "Pentest & Vulnerability Management",
  "c": "#e5534b",
  "hd": "security",
  "icon": "<circle cx=\"12\" cy=\"12\" r=\"8\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M12 2v3M12 19v3M2 12h3M19 12h3\"/>",
  "pages": [
   {
    "h": "vuln-dashboard.html",
    "s": "Vulnerability & Testing Dashboard",
    "g": "Overview",
    "t": "Vulnerability & Testing Dashboard - exposure, testing coverage, application and code findings, remediation",
    "d": "Live from Greenbone, Tenable, FireCompass, the testing schedule, App Pen Testing and AppSec: five pillars with every deduction itemised (a pillar with nothing to measure is left out, never counted as good), open findings by source and severity, the testing pipeline, top vulnerabilities by explained priority, trend and unusual changes, days to clear criticals at the fix rate, and a read-only AI testing advisor",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {"h": "vapt-workflow.html", "s": "VAPT Workflow", "g": "Overview", "t": "VAPT & Penetration Testing Workflow - one engagement from scoping to the signed report", "d": "One engagement from the request to the signed report: scoping with targets proposed by the Network Assistant from IP Address Management, safety checklist and authorisation, four-eyes approval, testing inside the window (Greenbone scan filed, tool runs, manual findings with evidence, scanner findings imported), validation (false positive decided by a second person), remediation with SLA and GRC actions, retest (fixed only by a later scan or an independent retest), the report generated from the records with SHA-256 versions, and sign-off by a person who did not write it", "fw": {"sama": ["3.3.10", "3.3.11"], "nca": ["2-10", "2-11"], "iso": ["A.8.8", "A.8.29"]}, "k": ["vapt", "penetration test", "pentest", "engagement", "rules of engagement", "report", "retest", "start to end"]},
   {"h": "scan-assurance.html", "s": "Scan Coverage Assurance", "g": "Overview", "t": "Scan Coverage Assurance - every connected asset scanned, or why not and the fix", "d": "Every connected asset in the register against the scans: scanned within policy, in a scan now, left out on purpose (fragile / excluded), or not scanned with ONE reason (no address, no scanner, outside the scope, request rejected, scan failed / expired, cut short, blocked by a firewall, offline, stale, never scanned) and its fix; failures for 2+ days first; the rescan prepared in batches and filed by a person (a different person approves); the coverage statement as HTML / CSV; daily trend", "fw": {"sama": ["3.3.10"], "nca": ["2-10"], "iso": ["A.8.8"]}, "k": ["coverage", "scan coverage", "not scanned", "failed scan", "rescan", "assurance", "vapt"]},
   {"h": "attack-surface.html", "s": "Attack Surface", "g": "Overview", "t": "Continuous Attack Surface - internet-facing assets, exposed services and APIs, re-checked on every change", "d": "What an attacker reaches first, kept current: every internet-facing asset with its exposed services (Asset Discovery open ports named) and the APIs among them, each with its evidence; shadow surface (reachable but in no asset record); an itemised 0-100 exposure per asset; and a 'what changed' feed diffed on every run - a new internet-facing asset, a newly exposed service or API, a new external finding, a service that closed. Read-only and passive: it builds from the register, discovery and the scanners' findings and exploits nothing; an entry point links to the AI-Driven Attack Chain and a test is proposed on the VAPT Workflow with four-eyes approval", "fw": {"sama": ["3.3.10", "3.3.11"], "nca": ["2-10", "2-12"], "iso": ["A.8.8", "A.5.7"]}, "k": ["attack surface", "external", "internet-facing", "exposed", "api", "shadow", "cart", "continuous", "exposure"]},
   {
    "h": "vapt-center.html",
    "s": "VAPT Center",
    "t": "VAPT Center - every finding, one scan wizard, every report",
    "d": "Greenbone, FireCompass, Tenable and penetration-testing findings merged and prioritised with reasons; SLA and breach forecast, lateral-movement paths, new / fixed / reopened, time to fix; a scan wizard filing four-eyes Greenbone requests; executive, technical, per asset / owner / department, compliance, SLA, changes and retest reports",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "vuln-scans.html",
    "s": "Vulnerability Scans",
    "g": "Vulnerability scanning",
    "t": "Vulnerability Scans (internal network, Greenbone / OpenVAS)",
    "d": "Scans of the internal network with Greenbone / OpenVAS: an internal scan scope set by an administrator (private ranges, exclusions), scans requested with a time window and approved by a second person, started and stopped by the platform inside the window; findings with CVEs, severity and the fix, fixed only when a later scan stops reporting them, owners, risk acceptance with four-eyes approval, export to CSV",
    "fw": {
     "sama": [
      "3.3.17"
     ],
     "nca": [
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17"
     ]
    }
   },
   {
    "h": "vuln-inventory.html",
    "s": "Vulnerabilities",
    "k": ["cve", "vulns", "findings", "tenable", "greenbone", "nessus", "deduplicate"],
    "t": "Vulnerabilities - one deduplicated inventory over every scanner: by severity, software and OS, primary and max score",
    "d": "Vulnerability data from Greenbone, Tenable, FireCompass and the penetration-testing engineer consolidated into one view: the same weakness from several adapters or devices is one row with its adapters, primary score and max score; charts by severity, by software (matched to installed software) and by operating system; devices per vulnerability; CSV export",
    "fw": {
     "sama": [
      "3.3.17"
     ],
     "nca": [
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17"
     ]
    },
    "g": "Vulnerability scanning"
   },
   {
    "h": "scanned-assets.html",
    "s": "Scanned Assets",
    "g": "Vulnerability scanning",
    "t": "Scanned Assets - every scanned host matched to the asset register, with open findings, risk, SLA and scan coverage",
    "d": "Every host Greenbone, Tenable, FireCompass and the pen-test engineer reported, matched to the asset register (by asset id, IP or name, said per row) with owner, department, criticality, type and site; open findings by severity after deduplication, an explained risk score, oldest open finding, last scan and scanners, fixed in 30 days, past the VAPT Center remediation SLA; coverage: assets in the approved scan scope never or not recently scanned, scanned hosts not in the register; Excel export",
    "fw": {
     "sama": [
      "3.3.17"
     ],
     "nca": [
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17"
     ]
    }
   },
   {
    "h": "risk-prioritization.html",
    "s": "Risk Prioritization",
    "k": ["risk score", "profiles", "prioritise", "prioritize", "exposure", "eol"],
    "t": "Risk Prioritization - an explained 0-100 risk per device, profiles, overall risk, trend and risk factors",
    "d": "Every device scored from its open vulnerabilities and context (internet exposure, end of support, sensitive data, business criticality, endpoint protection), each point itemised; device profiles with active status, severity, device count and average score; overall share of critical / medium / low devices, daily trend with weekly slope, risk factors and a fix-first list",
    "fw": {
     "sama": [
      "3.3.17",
      "3.2.1"
     ],
     "nca": [
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17",
      "3.2.1"
     ]
    },
    "g": "Vulnerability scanning"
   },
   {
    "h": "vapt-studio.html",
    "s": "VAPT Studio",
    "k": ["tenable", "firecompass", "greenbone", "nessus", "pentest"],
    "g": "Vulnerability scanning",
    "t": "VAPT Studio - Greenbone, FireCompass and Tenable merged with ML and AI",
    "d": "Every vulnerability from the internal Greenbone scans, FireCompass (external attack surface: export import with an ML column mapper, or its API) and Tenable (cloud or a Nessus scanner, GET only, keys sealed): internet exposure, the same weakness seen by two tools, an explained 0-100 risk per finding (severity, exposure, exploit, business criticality, age), weakness families, an attack-surface map, four-eyes false positive / accepted risk, CSV export and a read-only AI vulnerability analyst",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {
    "h": "live-scan.html",
    "s": "Live Scan Engine & Attack Simulation",
    "g": "Vulnerability scanning",
    "t": "Live Scan Engine & Attack Simulation - Greenbone scans and detection validation with ML and AI",
    "d": "Real internal vulnerability scans with Greenbone (inside the approved scope, four-eyes approved, live progress, stopped when the window ends, smart targets from the testing schedule and stale findings) beside scheduled attack simulations that prove the SIEM's rules fire - reliability per technique, regressions, flapping, latency drift, ranked gaps and a read-only AI purple-team advisor",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.14"
     ],
     "nca": [
      "2-10",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.14"
     ]
    }
   },
   {
    "h": "appsec.html",
    "s": "AppSec & Code Review",
    "g": "Application testing",
    "t": "Application security: SAST, secrets, dependencies, release gate",
    "d": "{{org.short}} applications with the findings of the scanners the teams already run (SARIF from Semgrep / CodeQL / SonarQube / Checkmarx / Gitleaks, CycloneDX or npm audit for dependencies) and a built-in quick review of source files; secrets masked before anything is stored; triage, risk acceptance approved by the CISO, fixed when the next scan no longer reports it, regressions; a release gate per application with an override by someone else; machine learning learns false positives and fix times; the AI AppSec reviewer explains findings and suggests fixes as text",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {
    "h": "apppt.html",
    "s": "Application Pen Testing",
    "g": "Application testing",
    "t": "Application penetration testing: cadence, engagements from scope to retest, findings",
    "d": "The pen-test programme for web applications, APIs and mobile back ends: a test cadence per application (critical external every 90 days), each engagement with a scope approved by the CISO and testing only inside the approved window, coverage of every OWASP WSTG area, findings entered or imported (OWASP ZAP JSON, Burp Suite XML) and mapped to the OWASP Top 10 / API Top 10, a fix verified only by another person's retest, four-eyes risk acceptance; machine learning learns fix times and SLA misses, retest failures, regressions and systemic weaknesses; the AI pen-test analyst explains and plans retests as text",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {
    "h": "mobile-test.html",
    "s": "Mobile Application Testing",
    "g": "Application testing",
    "t": "Mobile Application Testing - OWASP MASVS / MASTG with ML and AI",
    "d": "Mobile apps against the OWASP MASVS: MobSF reports per build mapped to the eight MASVS groups (secrets masked), manual MASTG checks recorded by a tester, a coverage matrix, a release gate with each failed rule named, new / fixed / regressed findings build over build, the group failure rate across builds, four-eyes risk acceptance and a read-only AI mobile security analyst",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.10"
     ],
     "nca": [
      "1-6",
      "2-15"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.10"
     ]
    }
   },
   {
    "h": "detection-validation.html",
    "s": "Detection Validation",
    "t": "Detection Validation & ATT&CK",
    "d": "What the SIEM would actually detect: ATT&CK coverage by tactic (covered / partial / gap), the technique catalogue, and safe synthetic validation runs (no real attacks, no endpoints) with detected / missed results",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.17",
      "3.2.4"
     ],
     "nca": [
      "2-12",
      "2-11",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.3.17",
      "3.2.4"
     ]
    },
    "g": "Penetration testing & simulation"
   },
   {
    "h": "hardening.html",
    "s": "Baseline Hardening",
    "t": "Baseline Hardening",
    "d": "Every IT asset against its CIS benchmark: Windows Server, Windows 11, Active Directory, Exchange, IIS, Hyper-V, Oracle / SQL Server / PostgreSQL, Oracle Linux, Solaris, VMware ESXi, Nutanix, Proxmox, Cisco, FortiGate, Palo Alto (PAN-OS); score, coverage, not-scanned assets with what to connect, fix and rollback script per asset",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.5",
      "3.3.14",
      "3.3.17"
     ],
     "nca": [
      "2-3",
      "2-2",
      "2-5",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.5",
      "3.3.14",
      "3.3.17"
     ]
    },
    "g": "Secure configuration"
   }
  ]
 },
 {
  "id": "eps",
  "sn": "Endpoint & Email",
  "name": "Endpoint, Web & Email Security",
  "c": "#ffa657",
  "hd": "security",
  "icon": "<rect x=\"2\" y=\"4\" width=\"20\" height=\"13\" rx=\"2\"/><path d=\"M8 21h8M12 17v4\"/><path d=\"m2 6 10 6 10-6\"/>",
  "pages": [
   {"h": "mail-ops.html", "s": "24/7 Email Availability", "g": "Email security", "t": "24/7 Email Availability - the programme that keeps mail available around the clock", "d": "Step by step for the mail team: the service owner, escalation and at least two on-call engineers with the RTO / RPO, the mail path mapped, 24/7 monitoring with no gap, no single point of failure, an approved runbook for every standard mail failure, planned maintenance windows with impact and rollback, a tested failover within the RTO, a review of every outage, and the approved monthly availability report - each people record approved by a second person", "fw": {"sama": ["3.3.14"], "nca": ["3-1"], "pdpl": []}, "k": ["email", "mail", "exchange", "24/7", "availability", "on-call", "runbook", "failover", "dr", "uptime"]},
   {
    "h": "email-dashboard.html",
    "s": "Email Dashboard",
    "t": "Email Dashboard",
    "d": "The mail service at a glance: up / down and availability against the 99.99% target, where mail comes from and goes on a world map (SMTP sessions through the firewalls by country), and every service on the receiving and sending route in detail with its top issue and fix",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.16"
     ],
     "nca": [
      "2-4",
      "2-13"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.16"
     ]
    },
    "g": "Email security"
   },
   {"h": "mimecast-actions.html", "s": "Mimecast Actions", "t": "Mimecast Actions - block / permit senders, release / reject held mail, block URLs, four-eyes", "d": "The Mimecast held queue and four-eyes actions in Mimecast: an operator proposes, a different person with the security approver scope approves, an operator runs it with a separate Mimecast management application", "fw": {"nca": ["2-4"], "iso": ["8.23", "5.14"]}, "k": ["mimecast", "email", "block", "sender", "held", "quarantine", "release", "url"]},
   {
    "h": "email-security.html",
    "s": "Email Security",
    "t": "Email Security",
    "d": "Email security gateway (Libraesva ESG and CEF gateways): delivered / blocked / quarantined, phishing and malware, threats that got through, top attacking senders and targeted people, outbound spam, and Exchange mailbox take-over signals",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.16"
     ],
     "nca": [
      "2-4",
      "2-13"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.16"
     ]
    },
    "g": "Email security"
   },
   {
    "h": "email-analysis.html",
    "s": "Email / Phishing Analysis",
    "t": "Email / Phishing Analysis",
    "d": "Paste or open a reported message: SPF / DKIM / DMARC, look-alike sender domains, Reply-To and display-name tricks, delivery path, defanged links and risky attachments, checked against the SIEM's indicator lists; an itemised score and a case with the phishing playbook - analysed in the browser, nothing stored or fetched",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.16"
     ],
     "nca": [
      "2-4",
      "2-13"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.16"
     ]
    },
    "g": "Email security"
   },
   {
    "h": "libraesva.html",
    "s": "Libraesva ESG",
    "t": "Libraesva ESG",
    "d": "The Libraesva Email Security Gateway: its mail log in the SIEM by syslog (with setup steps), and its own status, mail queue, quarantine and message log through the REST API - read-only, sealed credentials, endpoints mapped from the appliance's own catalogue",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.16"
     ],
     "nca": [
      "2-4"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.16"
     ]
    },
    "g": "Email security"
   },
   {
    "h": "email-route-map.html",
    "s": "Email Route Map",
    "t": "Email Route Map",
    "d": "The whole mail path on one graphical map: DNS (MX) and where it is hosted (Cloudflare), each Internet link, the MX hosts, the email gateway, Exchange on-premises and Exchange Online (hybrid) and the egress IPs - a broken hop and the line into it turn red, with the fix",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.16"
     ],
     "nca": [
      "2-4",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.16"
     ]
    },
    "g": "Email security"
   },
   {
    "h": "phishing-simulation.html",
    "s": "Phishing Simulation",
    "t": "Phishing Simulation",
    "d": "Results of the phishing simulations run in Microsoft Defender Attack Simulation Training, read-only: click and report rate per campaign, trend, Bayesian-smoothed department susceptibility, repeat clickers, time to click, training indicator, people to support (operators; indicators, not proof); AI awareness advisor on aggregates only",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.16"
     ],
     "nca": [
      "2-4",
      "2-13"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.16"
     ]
    },
    "g": "Email security"
   },
   {
    "h": "dlp.html",
    "s": "Data Loss Prevention",
    "t": "Data Loss Prevention (DLP)",
    "d": "Somansa Privacy-i / Mail-i / Server-i and CEF DLP incidents in the SIEM: let through vs blocked, channels, policies, sensitive data classes, people to review with an itemised risk, devices, destinations, DLP agent disabled, sources reporting; HTML report, CSV export and a weekly / monthly e-mailed report",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.14"
     ],
     "nca": [
      "2-7",
      "2-12"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 20",
      "Art. 22"
     ],
     "ia": [
      "3.3.3",
      "3.3.14"
     ]
    },
    "g": "Endpoint & web"
   },
   {
    "h": "data-posture.html",
    "s": "Data Security Posture",
    "t": "Data Security Posture (DSPM, AI / ML)",
    "d": "A 0-10 data security score with every point explained, from what the platform really reads: shadow data, exposed data, risky credentials in files, data outside the Kingdom, excessive access, misplaced data and privacy incidents; every data store ranked 0-100 with its reasons, toxic combinations, unusual jumps, the score trend, the fixes that regain the most points and an AI advisor",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.14"
     ],
     "nca": [
      "2-7",
      "2-2"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 29"
     ],
     "ia": [
      "3.3.3",
      "3.3.14"
     ]
    },
    "g": "Data security"
   },
   {
    "h": "cloud-stores.html",
    "s": "Cloud Data Stores",
    "t": "Cloud Data Stores",
    "d": "Azure Blob, AWS S3 and Oracle Cloud Object Storage read-only: public stores, encryption, stores outside the Kingdom, personal data and credentials found in objects (counts only); connect providers and scan",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.14"
     ],
     "nca": [
      "2-7",
      "4-2"
     ],
     "pdpl": [
      "Art. 29"
     ],
     "ia": [
      "3.3.3",
      "3.3.14"
     ]
    },
    "g": "Data security"
   }
  ]
 },
 {
  "id": "usr",
  "sn": "Identity & M365",
  "name": "Identity & Microsoft 365",
  "c": "#39c5cf",
  "hd": "security",
  "icon": "<circle cx=\"9\" cy=\"8\" r=\"3.5\"/><path d=\"M2.5 20a6.5 6.5 0 0 1 13 0\"/><path d=\"M16 4.5a3.5 3.5 0 0 1 0 7M21.5 20a6.5 6.5 0 0 0-4-6\"/>",
  "pages": [
   {
    "h": "m365-dashboard.html",
    "s": "M365, Users & Endpoints",
    "t": "Microsoft 365, Users & Endpoints Dashboard",
    "d": "From the tenant itself: what to do first (ordered by impact), licence seats to reclaim (disabled and 90-day-idle accounts) with renewal and consumption forecast, explainable identity risk, device fleet (builds behind the fleet, stale, leavers' devices, non-compliant), sign-in failure bursts and new countries, expiring app secrets, daily trend with unusual changes, and an AI Microsoft 365 analyst",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.6"
     ],
     "nca": [
      "2-2",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5",
      "3.3.6"
     ]
    },
    "g": "Microsoft 365"
   },
   {
    "h": "m365.html",
    "s": "Microsoft 365",
    "t": "Microsoft 365",
    "d": "Licences, users, Intune devices, sign-ins, Secure Score, MFA and service health from Microsoft Graph; the Microsoft 365 connection (tenant, app, secret) is set here",
    "fw": {
     "sama": [
      "3.3.5",
      "3.4.3",
      "3.3.8"
     ],
     "nca": [
      "2-2",
      "4-2",
      "2-4"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 29"
     ],
     "ia": [
      "3.3.5",
      "3.4.3",
      "3.3.8"
     ]
    },
    "g": "Microsoft 365"
   },
   {
    "h": "m365-security.html",
    "s": "Microsoft 365 Security",
    "t": "Microsoft 365 Security (Secure Score, MFA, identity risk, Conditional Access, Defender)",
    "d": "Secure Score with its weakest controls and daily trend; MFA coverage with administrators without MFA first; Entra ID risky users and risk detections by type and country; one explainable score per person where risk, missing MFA, open Defender alerts, detections and failed sign-ins agree; a detection and an alert on the same account within 24 hours as one chain; Conditional Access - nothing enforced, report-only for 30+ days, changed this week, the baseline by name; Defender alerts by severity, category and age; datasets Graph did not give named with the permission to grant; read-only, every fix opens the Microsoft page",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "2-2",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.14"
     ]
    }
   },
   {
    "h": "m365-autoconfig.html",
    "s": "MS Security Auto-Config",
    "t": "Microsoft Security — Auto-Configuration",
    "d": "How far the Microsoft 365 / Entra ID connection and the baseline protection have got: each Graph permission granted (read from the sign-in token), the admin-consent link, a script that grants only the missing read-only permissions, the baseline checks (Conditional Access, administrators without MFA, MFA coverage, Secure Score), Conditional Access policies generated report-only with the break-glass accounts excluded, and an AI configuration plan - nothing here changes the tenant",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5"
     ]
    }
   },
   {
    "h": "sharepoint.html",
    "s": "SharePoint & OneDrive",
    "t": "SharePoint & OneDrive - personal data, sharing and file activity",
    "d": "File activity from the Microsoft 365 audit log - sharing, mass downloads against each user's own history, after-hours changes, external and anonymous sharing - and every SharePoint site and OneDrive read for personal data (counts per kind only, never a value): each file scored for exposure with every point named (what it holds x how far it is shared), anonymous links and outside sharing first, sites ranked, folders where personal data concentrates, files unchanged for 3 years for the retention schedule, coverage gaps by permission, the trend across runs with unusual jumps, ranked actions",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.9"
     ],
     "nca": [
      "2-6",
      "2-7"
     ],
     "pdpl": [
      "Art. 18",
      "Art. 19"
     ],
     "ia": [
      "3.3.3",
      "3.3.9"
     ]
    },
    "g": "Microsoft 365"
   },
   {
    "h": "exchange-hybrid.html",
    "s": "Exchange Hybrid Migration",
    "t": "Exchange Hybrid Migration (on-premises to Exchange Online)",
    "d": "Moving on-premises Exchange to Exchange Online in hybrid mode: readiness read from the servers (versions, certificate, EWS / MRS Proxy, routing and remote domains, connector, Hybrid Configuration Wizard, free/busy, OAuth), the steps people confirm, mailboxes still on-premises vs in the cloud, migration waves with the exact Exchange Online commands - run by your admins, never by the platform",
    "fw": {
     "sama": [
      "3.3.8",
      "3.4.3"
     ],
     "nca": [
      "2-4"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.4.3"
     ]
    },
    "g": "Microsoft 365"
   },
   {
    "h": "ad-exchange.html",
    "s": "AD & Exchange",
    "t": "Active Directory & Exchange (live)",
    "d": "Domain controllers and Exchange servers: up/down, HA/DR, logs in the SIEM; failed sign-ins, lockouts, admin-group changes, mailbox forwarding and permissions",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "2-2",
      "2-4",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.14"
     ]
    },
    "g": "Identity & access"
   },
   {
    "h": "access-reviews.html",
    "s": "Access Reviews",
    "t": "Access Reviews (quarterly AD groups)",
    "d": "Quarterly reviews of Active Directory group memberships: members read from the directory, attested by their line manager with a signed statement, removals approved by a second person and removed in the directory, exceptions and CSV evidence",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5"
     ]
    },
    "g": "Identity & access"
   },
   {
    "h": "privileged-access.html",
    "s": "Privileged Access",
    "t": "Privileged Access (just-in-time)",
    "d": "Just-in-time privileged access: time-limited AD group membership requested with a reason and ticket, approved by a second person, added at the start and removed automatically at expiry (read back both times), with the standing members of each admin group listed",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5"
     ]
    },
    "g": "Identity & access"
   },
   {
    "h": "identity-posture.html",
    "s": "Password & MFA Posture",
    "g": "Identity & access",
    "t": "Password & MFA Posture - domain policy, MFA, lockouts (report only)",
    "d": "The domain and fine-grained password policies scored against the baseline (NCA ECC 2-2-3, SAMA CSF 3.3.5), accounts whose password never expires, is not required or is old, MFA coverage and administrators without MFA from Entra, Conditional Access requiring MFA, lockout statistics and a ranked remediation list - changes nothing",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5"
     ]
    }
   },
   {
    "h": "nhi.html",
    "s": "Non-Human Identities",
    "t": "Non-Human Identities (NHI)",
    "d": "Every identity that is not a person - AD service accounts and gMSA, Entra app registrations, the platform's credentials, agent and API keys, the AI engineers: owner, purpose, secret age and expiry, privilege, last use and risk (Kerberoastable, never-expiring, privileged, unused, expiring secrets); owner reviews and decommissioning approved by a second person",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.9"
     ],
     "nca": [
      "2-2",
      "2-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5",
      "3.3.9"
     ]
    },
    "g": "Identity & access"
   }
  ]
 },
 {
  "id": "net",
  "sn": "Network",
  "name": "Network",
  "c": "#79b8ff",
  "hd": "infra",
  "icon": "<circle cx=\"12\" cy=\"5\" r=\"2\"/><circle cx=\"5\" cy=\"19\" r=\"2\"/><circle cx=\"19\" cy=\"19\" r=\"2\"/><path d=\"M12 7v4M12 11l-6 6M12 11l6 6\"/>",
  "pages": [
   {"h": "fortigate-fleet.html", "s": "FortiGate Fleet", "t": "FortiGate Fleet - every FortiGate through FortiManager: health, firmware, licences, SD-WAN link state, four-eyes changes", "d": "Every FortiGate FortiManager manages, ranked by what needs doing: offline, configuration changed outside FortiManager, conserve mode, HA, IPsec tunnels, SD-WAN links out of SLA, licences expiring, firmware behind the target per model and readings unusual against each device's own baseline; change plans (install a policy package, retrieve config, firmware upgrade) proposed by an operator and approved by a different person", "fw": {"nca": ["2-5", "2-7", "2-12"], "iso": ["8.20", "8.9", "8.32"]}, "k": ["fortigate", "fortinet", "fortimanager", "firewall", "fleet", "firmware", "sd-wan", "link", "vpn", "ipsec", "licence", "ha"]},
   {"h": "fortigate-nac.html", "s": "Network Access Control", "t": "Network Access Control - every endpoint on the switches and FortiGates, with an explainable risk and four-eyes authorise / quarantine", "d": "One endpoint per MAC across every site from the FortiGates' device detection through FortiManager: new devices after a learning week, a MAC that changes OS, the same MAC at two sites within 30 minutes, a device rare at its site, never authorised; authorise or quarantine as four-eyes decisions a person carries out", "fw": {"nca": ["2-5", "2-3"], "iso": ["8.20", "5.9"]}, "k": ["nac", "network access", "endpoint", "mac", "device detection", "quarantine", "rogue", "machine learning"]},
   {
    "h": "npm-summary.html",
    "s": "NOC Summary",
    "t": "NOC Summary (NPM)",
    "d": "The NOC at a glance with AI/ML: network health score, probable causes (one incident per cause), anomalies against each node's own normal, flapping, capacity forecast, site health and an AI shift brief - plus every node by vendor and status, interfaces running hot and the map.",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-5",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "sdwan.html",
    "s": "SD-WAN",
    "t": "SD-WAN",
    "d": "SD-WAN fabric: control status, per-site WAN health, transport-speed mix, WAN-edge inventory and health, and the application-aware routing table (tunnel latency / loss / jitter)",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.4"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.4"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "wan-optimization.html",
    "s": "WAN Optimization",
    "t": "WAN Optimization",
    "d": "HPE Aruba EdgeConnect (Silver Peak) from the Orchestrator, read only: bytes saved and data reduction per appliance and per application, tunnel loss, latency and jitter against thresholds, active Orchestrator alarms, a drop against each appliance's own usual reduction, and what to do first. A counter the Orchestrator does not report is shown as not reported, never as zero.",
    "fw": {
     "sama": [
      "3.3.8"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "wireless.html",
    "s": "Wireless",
    "t": "Wireless Networks",
    "d": "Wireless estate: access points and controllers grouped by site and vendor, an access-point map of Saudi Arabia, and the live controller feed (APs, clients, SSIDs, channels) from wireless LAN controllers over SNMP",
    "fw": {
     "sama": [
      "3.3.8"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "network-flows.html",
    "s": "Network Flows",
    "t": "Network Flows",
    "d": "Flow map, conversations, what changed, zones and top talkers",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.8"
     ],
     "nca": [
      "2-5",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.14",
      "3.3.8"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "netflow.html",
    "s": "NetFlow Analytics",
    "g": "Monitor",
    "t": "NetFlow Analytics",
    "d": "NetFlow v5 / v9, IPFIX and sFlow from the routers and switches: live traffic and interface utilisation, applications and DSCP, conversations, IP groups with usage billing, alarms, capacity forecast, hour-of-week patterns and flow-based security detections",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14"
     ]
    }
   },
   {
    "h": "cisco-network.html",
    "s": "Cisco Network Inventory",
    "t": "Cisco Network Inventory (switches, routers, firewalls)",
    "d": "Every Cisco switch, router and ASA in the AI Network Engineer with its model, serial numbers and IOS / IOS-XE / ASA version read from the device, its state and its support contract",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "cisco-update.html",
    "s": "Cisco Updates",
    "t": "Cisco Updates",
    "d": "Which Cisco switches, routers and ASAs need a software update, why and by when: target release per platform, the Cisco PSIRT advisories on each running release with a deadline from first seen, Smart Net coverage, a priority with every point named, and update plans approved by a second person and completed only when the device reports the target version. The upgrade itself runs as the AI Network Engineer's staged tasks.",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "branch-connectivity.html",
    "s": "Branch Connectivity",
    "t": "Branch Connectivity",
    "d": "Every site in one window: both WAN paths, whether it reaches the data centre and the DR site (without passing the DC) right now, path quality, 7-day availability, outages, MTTR, failovers and flapping, the ISP scorecard against the availability target, resilience gaps (single path, one ISP, one edge, no DR route), ranked actions and an ISP ticket draft",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-5",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Monitor"
   },
   {
    "h": "network-dashboard.html",
    "s": "Network Dashboard",
    "t": "Network Dashboard",
    "d": "One read-only view over the whole network: devices up by vendor, site health, open route-map incidents with root cause, branch connectivity to the data centre and DR, SD-WAN appliance and path health, NAC enforcement and the AI Network Engineer's findings - every figure links to the page that owns it. Nothing is changed from here.",
    "fw": {
     "sama": [
      "3.3.8"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "network-route-map.html",
    "s": "WAN & LAN Route Map",
    "t": "WAN & LAN Route Map",
    "d": "Internet, Palo Alto edge, data centre, Silver Peak SD-WAN and branch FortiGates on one live map: link state, bandwidth against the contracted capacity, loss and latency, the root cause of an outage with what it cuts off, FortiGate users on a congested link, learned baselines per hour, capacity forecast, alerts to the on-call engineer, fix steps per vendor",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-5",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "ipam.html",
    "s": "IP Address Management",
    "t": "IP Address Management",
    "d": "The address plan (subnets, sites, VLANs, gateways, DHCP ranges, reservations) checked against every address the asset register and Asset Discovery see: utilisation and the next free address per subnet, conflicts, duplicates, stale and unknown addresses, networks missing from the plan, growth and days until full learned from daily history, read-only AI advisor",
    "fw": {
     "sama": [
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "change-log.html",
    "s": "Change Log & NOC↔SOC Correlation",
    "t": "Change Log & NOC↔SOC Correlation",
    "d": "Every change made to the systems in one register - change plans carried out by the network, server, Kaspersky and Zscaler desks, configuration changes found on devices (authorised or not) and changes people record - with the SIEM alerts on the same system in the hours after, the device's state now, failed, high-risk and off-hours changes",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.14"
     ],
     "nca": [
      "2-5",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.14"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "ncm.html",
    "s": "Network Config Management",
    "t": "Network Configuration Management",
    "d": "Every switch and router configuration backed up daily (read only, secrets removed) with its versions: what changed and when, line-by-line diffs, each change matched to an approved change plan or flagged unauthorised, changes outside working hours, a golden baseline per device and the drift from it, backup health, unusual change rates learned from each device's own history",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.8"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.8"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "network-map.html",
    "s": "Intelligent Network Map",
    "t": "Intelligent Network Map",
    "d": "The physical network as the Cisco switches report it over CDP / LLDP, with live state from the polls: layers from firewall to access, links with their ports and state, single points of failure and what each one cuts off, the blast radius of a down device or link, unmanaged switches found in the neighbour tables, links seen from one side only, the path between two devices, and what changed since the last snapshot. Read only.",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "rogue-detection.html",
    "s": "Advanced Rogue Detection",
    "t": "Advanced Rogue Detection",
    "d": "Every device on the LANs joined by MAC from the switch ports, the FortiGate DHCP and ARP tables and Genian NAC: maker boards, unknown vendors, private MACs, unmanaged switches behind a port, devices on server VLANs, new and moving devices - each risk point explained; Trusted / Guest (with expiry) / Suspect labels, in bulk; blocking proposed as a port shut-down change plan a second person approves",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-5"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "switch-port-map.html",
    "s": "Switch Port Map",
    "t": "Switch Port Map",
    "d": "Every port of every Cisco switch on a live front panel: status, VLAN, device type, utilisation, PoE and findings; what is plugged in (MAC, IP, Genian NAC, vendor) and where a device is plugged in; device types learned from people's confirmations; MAC flapping, swapped devices, unmanaged switches, err-disabled and unused ports; capacity forecast; fixes as approved change plans",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "network-onboarding.html",
    "s": "Network Onboarding & Architecture",
    "t": "Network Onboarding & Architecture",
    "d": "Onboard Palo Alto, FortiGate, Genian NAC, Cisco UCS, Cisco switches and routers in one form with a read-only account (over-privileged accounts refused); verification, placement in the WAN / LAN route map, the architecture diagram, the configuration architecture against NCA ECC and CIS, and fixes as change plans another person approves (Cisco IOS hardening runs automatically after approval)",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-1",
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Maps & architecture"
   },
   {
    "h": "network-access.html",
    "s": "Network Access Control",
    "t": "Network Access Control",
    "d": "Every device Genian NAC sees and whether it was let in: authorised, quarantined, unauthorised, devices on a switch port NAC never saw, the same MAC on two ports, quarantine stuck for days, host name changed under one MAC, 802.1X / MAB failure spikes against the usual hour; itemised risk per device, switch exposure, AI NAC analyst (read-only)",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Access & troubleshooting"
   },
   {
    "h": "network-connectivity.html",
    "s": "Connectivity Troubleshooter",
    "t": "Connectivity Troubleshooter",
    "d": "Outlook disconnects, RDP / SSH time-outs between the FortiGate users side and the Palo Alto data centre: session-end evidence from both firewalls, asymmetric routing, idle time-outs, policy denies / App-ID, SSL inspection, MSS; fix and rollback per device, proposed for approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Access & troubleshooting"
   },
   {
    "h": "domains.html",
    "s": "Domains & DNS",
    "t": "Domains, DNS & Hosting",
    "d": "Every {{org.short}} internet domain and public hostname: renewal dates, nameserver changes, SPF / DMARC / DKIM, TLS certificate expiry, where each name is hosted (in the Kingdom or not) and the asset behind it; Renewal Autopilot - expiry, registrar and transfer lock read from the registry (RDAP), renewal tasks opened by themselves, approved by a second person and verified by the registry, hosting subscriptions, hijack signs, learned lead time, 12-month cost forecast",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.9",
      "3.4.3"
     ],
     "nca": [
      "2-4",
      "2-5",
      "2-8",
      "4-2"
     ],
     "pdpl": [
      "Art. 29"
     ],
     "ia": [
      "3.3.8",
      "3.3.9",
      "3.4.3"
     ]
    },
    "g": "Names & certificates"
   },
   {
    "h": "certificates.html",
    "s": "Certificates",
    "k": ["ssl", "tls", "pki", "expiry"],
    "t": "SSL / TLS Certificates",
    "d": "Every TLS certificate on the network: issuer, names, key and chain read every 6 hours, renewal due by issuer lead time (ACME, AD CS, ordered), expiring and weak certificates as work for the AI PKI Engineer, renewals confirmed only by a scan",
    "fw": {
     "sama": [
      "3.3.9",
      "3.3.3"
     ],
     "nca": [
      "2-8",
      "2-1"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.9",
      "3.3.3"
     ]
    },
    "g": "Names & certificates"
   },
   {
    "h": "brand-protection.html",
    "s": "Brand Protection",
    "t": "Brand Protection",
    "d": "Who is imitating {{org.short}} online: look-alike domains (typo, homoglyph, TLD, keyword) checked passively in public DNS, their certificate and homepage; certificate transparency; ML risk learned from analysts' triage, weekly spikes; takedown case board; AI brand analyst (read-only, drafts takedown wording)",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.9",
      "3.4.3"
     ],
     "nca": [
      "2-4",
      "2-5",
      "2-8",
      "4-2"
     ],
     "pdpl": [
      "Art. 29"
     ],
     "ia": [
      "3.3.8",
      "3.3.9",
      "3.4.3"
     ]
    },
    "g": "Names & certificates"
   }
  ]
 },
 {
  "id": "srv",
  "sn": "Servers & VMs",
  "name": "Servers & Virtualization",
  "c": "#e3b341",
  "hd": "infra",
  "icon": "<rect x=\"3\" y=\"3\" width=\"18\" height=\"7\" rx=\"2\"/><rect x=\"3\" y=\"14\" width=\"18\" height=\"7\" rx=\"2\"/><path d=\"M7 6.5h.01M7 17.5h.01\"/>",
  "pages": [
   {"h": "hyperv.html", "s": "Hyper-V Servers", "t": "Hyper-V Servers - hosts and VMs with capacity forecasts, right-sizing, health and four-eyes VM actions", "d": "Every Hyper-V host that reports (a read-only script on the host) with CPU, memory, volumes and the days until they fill; every VM's memory demand against what it is assigned (14-day p95), heartbeat, checkpoints, replication, zombies; start / shut down / turn off / restart / checkpoint approved by a different administrator and run by the host itself", "fw": {"nca": ["2-3", "2-9"], "iso": ["8.6", "8.14"]}, "k": ["hyper-v", "hyperv", "virtual machines", "vm", "capacity", "rightsizing", "checkpoint", "replication", "servers"]},
   {
    "h": "server-availability.html",
    "s": "Server Availability",
    "g": "Servers",
    "t": "Server Availability",
    "d": "Online / offline and for how long, availability %, days since restart, single points of failure, HA and DR per service",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14",
      "BCM"
     ],
     "nca": [
      "2-3",
      "3-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14",
      "BCM"
     ]
    }
   },
   {
    "h": "servers.html",
    "s": "All Servers",
    "g": "Servers",
    "t": "Servers by Platform",
    "d": "Every server and VM in the asset register by platform - OS, backup, end of support, patches, OS health over SSH, findings with the fix",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    }
   },
   {
    "h": "windows-servers.html",
    "s": "Windows Servers",
    "g": "Servers",
    "t": "Windows Server Estate",
    "d": "Windows servers and VMs: backup, end of support, Endpoint Central patches and the AI Windows Administrator's WinRM health checks",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    }
   },
   {
    "h": "solaris-servers.html",
    "s": "Solaris Servers",
    "g": "Servers",
    "t": "Oracle Solaris Servers",
    "d": "Solaris servers read over SSH (read-only): file systems / ZFS, memory, swap, load, SMF services in maintenance, NTP, last update",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    }
   },
   {
    "h": "oracle-linux-servers.html",
    "s": "Oracle Linux Servers",
    "g": "Servers",
    "t": "Oracle Linux Servers",
    "d": "Oracle Linux servers read over SSH (read-only): file systems, inodes, memory, swap, load, failed services, NTP, last update",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    }
   },
   {
    "h": "add-server.html",
    "s": "Add Server / Device",
    "g": "Servers",
    "t": "Add a Server or Network Device",
    "d": "One form for a Linux / Solaris / AIX server (SSH) or a firewall / switch / router (SNMP v2c or v3), with its web addresses: IP, site, a read-only SSH login (optional SNMP and Oracle), the scan approval - then it scans, asks you to confirm the SSH key, and adds the server to IT Asset Management.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "start": true
   },
   {
    "h": "exchange-servers.html",
    "s": "Exchange Servers",
    "g": "Mail servers",
    "t": "Exchange Server Estate",
    "d": "Exchange servers (recognised from software, tags or host name) with backup, patches and the AI Exchange Administrator's health checks",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    }
   },
   {
    "h": "exchange-reports.html",
    "s": "Exchange Reports",
    "g": "Mail servers",
    "t": "Exchange Reports",
    "d": "Mailbox sizes and growth, quotas, inactive and forwarding mailboxes, Full Access / Send As / Send on Behalf, distribution lists, mail traffic, OWA / ActiveSync devices and Exchange Online - read-only",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-4"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14"
     ]
    }
   },
   {
    "h": "remote-console.html",
    "s": "Remote Console",
    "t": "Remote Console - Remote Desktop and SSH to servers, approved and recorded",
    "d": "Log in to Windows (Remote Desktop), Linux, Solaris, ESXi, Nutanix and network devices (SSH) from the portal through the Guacamole gateway, or open the vSphere Client / Prism: only after another person approves a time-limited request, with your own account (never stored), every gateway session recorded and audited, ended at the end of the window",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.7"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5",
      "3.3.7"
     ]
    },
    "g": "Server administration"
   },
   {
    "h": "virtualization.html",
    "s": "Virtualization",
    "g": "Virtualization",
    "t": "Virtualization Platforms (vCenter & Nutanix)",
    "d": "Any number of VMware vCenter and Nutanix Prism connections; hosts and VMs flow into Asset Discovery, the inventory, Server Availability and the Licensing Audit (Nutanix cores filled in)",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-3",
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    }
   },
   {
    "h": "vmware-servers.html",
    "s": "VMware",
    "g": "Virtualization",
    "t": "VMware ESXi Hosts & VMs",
    "d": "ESXi hosts from vCenter (state, CPU, memory, VMs) and the VMs on them, joined to the asset register: backup, end of support, findings",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    }
   },
   {
    "h": "vsphere-studio.html",
    "s": "vSphere Studio",
    "g": "Virtualization",
    "t": "vSphere Studio - VMware vCenter / ESXi health with ML and AI",
    "d": "Every vCenter cluster, ESXi host, datastore and VM the capacity collection reads (read-only): explained health scores, hosts out of balance with DRS off, ESXi version drift, workload profiles learnt from each VM's own peaks (k-means), unusual CPU, old snapshots, consolidation, VMware Tools, right-sizing, datastore risk, the AI Virtualization Administrator's findings and plans, and a read-only AI vSphere analyst",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.8"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5",
      "3.3.8"
     ]
    }
   },
   {
    "h": "nutanix-vms.html",
    "s": "Nutanix VMs",
    "g": "Virtualization",
    "t": "Nutanix VMs Dashboard",
    "d": "Nutanix VM inventory and cluster health: VM count, powered on/off, vCPU and memory allocated, per-cluster CPU / memory / storage utilization from Prism, and a per-VM summary (IP address, host, vCPU, memory, disk)",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-3",
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    }
   },
   {
    "h": "virtual-network-map.html",
    "s": "Virtual Network Map",
    "g": "Virtualization",
    "t": "Virtual Network Map - vCenter, ESXi and Nutanix networking",
    "d": "How every VM reaches the physical network: port groups and VLANs per host, standard / distributed switches, uplinks with link and speed, VMkernel services and MTU, AHV networks and host NICs; the per-cluster baseline learned from the hosts, VLAN matrix, VM path trace, changes between reads, fixes with esxcli / PowerCLI / acli and rollback approved by a second administrator, and an AI virtualization network engineer",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-5",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    }
   },
   {
    "h": "capacity.html",
    "s": "Capacity Planning",
    "g": "Capacity & power",
    "t": "Capacity Planning: VMware & Nutanix",
    "d": "Clusters, hosts, datastores and VMs from vCenter and Prism: CPU and memory in use, vCPU per core, memory allocation, storage, room for more VMs with one host in reserve (N+1), the date each limit is reached at the current trend, powered-off VMs to reclaim. CSV and print / PDF.",
    "fw": {
     "sama": [
      "3.3.8",
      "BCM"
     ],
     "nca": [
      "2-3",
      "3-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "BCM"
     ]
    }
   },
   {
    "h": "virt-power.html",
    "s": "Power Control",
    "g": "Capacity & power",
    "t": "Power Control (hosts and VMs)",
    "d": "Restart, shut down and start VMware ESXi hosts, VMware VMs, Nutanix AHV hosts and VMs as change plans: safety checks (cluster room, one Nutanix node at a time, Tools), exact steps, four-eyes approval, run by an engineer, verified by the next collection; host start through iDRAC / iLO / IPMI",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-3",
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    }
   }
  ]
 },
 {
  "id": "stor",
  "sn": "Storage & Backup",
  "name": "Storage, Backup & DR",
  "c": "#bc8cff",
  "hd": "infra",
  "icon": "<path d=\"M4 4h16v6H4zM4 14h16v6H4z\"/><path d=\"M8 7h.01M8 17h.01M14 17h3M14 7h3\"/>",
  "pages": [
   {
    "h": "storage.html",
    "s": "Storage",
    "t": "Storage",
    "d": "NetApp ONTAP and HPE MSA read-only: health, controllers, pools and capacity, fullest volumes, failed disks, error events; linked to the inventory",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.3"
     ],
     "nca": [
      "2-3",
      "2-7"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.3"
     ]
    },
    "g": "Storage & backup"
   },
   {
    "h": "backup.html",
    "s": "Backup Coverage",
    "t": "Backup Coverage",
    "d": "Veritas NetBackup, Veeam and Cohesity (read-only): last good backup of every server and VM, failed runs, machines with no backup, backups of machines not in the inventory",
    "fw": {
     "sama": [
      "BCM",
      "3.3.8"
     ],
     "nca": [
      "2-9",
      "3-1"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "BCM",
      "3.3.8"
     ]
    },
    "g": "Storage & backup"
   },
   {
    "h": "dr-studio.html",
    "s": "DR Studio",
    "t": "DR Studio - Main Site ⇄ DR Site Replication Health",
    "d": "Can we fail over now within the agreed RPOs? Every replication stream the platform reads (Nutanix protection domains, Oracle Data Guard standbys) with lag against the RPO, sampled every 15 minutes: forecast of the next RPO breach, unusual lag, flapping, 7-day RPO compliance, an explained readiness score including the last DR & BCM drill, a site-to-site picture, 24-hour heat map and a read-only AI DR analyst",
    "fw": {
     "sama": [
      "BCM",
      "3.3.8"
     ],
     "nca": [
      "3-1",
      "2-9"
     ],
     "pdpl": [],
     "ia": [
      "BCM",
      "3.3.8"
     ]
    },
    "g": "Disaster recovery"
   },
   {
    "h": "dr-replication.html",
    "s": "DR Replication",
    "t": "DR Replication (Nutanix HQ ↔ DR)",
    "d": "Nutanix protection domains and Leap rules at HQ and DR: RPO met or missed, last copy on the DR site, replications in progress, remote sites, VMs with no DR protection, split brain - with alerts to the AI Virtualization Administrator",
    "fw": {
     "sama": [
      "BCM",
      "3.3.8"
     ],
     "nca": [
      "3-1",
      "2-9"
     ],
     "pdpl": [],
     "ia": [
      "BCM",
      "3.3.8"
     ]
    },
    "g": "Disaster recovery"
   },
   {
    "h": "dr-drills.html",
    "s": "DR & BCM Drills",
    "t": "DR & BCM Drills",
    "d": "Disaster-recovery and business-continuity exercises evidencing SAMA recoverability testing: scope, RTO/RPO targets vs achieved, result, findings and remediation per drill; recoverability-by-system coverage with overdue-cadence flags; operator execution, four-eyes admin sign-off, evidence attachments and a printable evidence report",
    "fw": {
     "sama": [
      "BCM"
     ],
     "nca": [
      "3-1",
      "2-9"
     ],
     "pdpl": [],
     "ia": [
      "BCM"
     ]
    },
    "g": "Disaster recovery"
   }
  ]
 },
 {
  "id": "db",
  "sn": "Databases",
  "name": "Databases",
  "c": "#d29922",
  "hd": "infra",
  "icon": "<ellipse cx=\"12\" cy=\"5\" rx=\"8\" ry=\"3\"/><path d=\"M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5\"/><path d=\"M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6\"/>",
  "pages": [
   {
    "h": "db-morning.html",
    "s": "Morning Health Check",
    "t": "Morning Health Check",
    "d": "The DBA's daily round done by the platform every working morning: every instance (open, restarts, tablespaces, FRA, ASM, archiving and archive space, RMAN backup, alert-log ORA- errors, sessions, invalid objects), Data Guard (shipping, lag, MRP, gaps) and every database server (file systems, memory, load, instances vs oratab, listener, clock); PASS / WARN / FAIL / NOT CHECKED with evidence, e-mailed and signed off",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.6",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-9",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.6",
      "3.3.14"
     ]
    },
    "g": "Daily operations"
   },
   {
    "h": "db-dashboard.html",
    "s": "Database Dashboard",
    "t": "Database Dashboard",
    "d": "Every database at a glance: tablespaces with days to full, recovery area, TEMP, backups, Data Guard; thresholds the DBA sets (per database and per tablespace), alerts e-mailed to the DBA with acknowledge / snooze / maintenance windows, a daily digest, and alert-log ORA- error findings with what to check",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-9",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.3",
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Daily operations"
   },
   {
    "h": "databases.html",
    "s": "All Databases",
    "t": "Databases",
    "d": "Every database in one place - monitored (health and performance every 4 minutes, sent to the SIEM) and found by Asset Discovery - with status, login and encryption in transit; add a database in three steps with the read-only account script for the DBA; test, remove, read now",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8",
      "3.3.9"
     ],
     "nca": [
      "2-1",
      "2-3",
      "2-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.3",
      "3.3.8",
      "3.3.9"
     ]
    },
    "g": "Daily operations"
   },
   {
    "h": "db-servers.html",
    "s": "Database Servers",
    "t": "Database Servers",
    "d": "The servers the Oracle databases run on, aligned with their IT asset records: file systems, memory, CPU, Oracle instances vs oratab, listeners, clock sync, HugePages, patches - read over SSH with a trusted host key; link a server to its asset",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8",
      "3.3.17"
     ],
     "nca": [
      "2-1",
      "2-3",
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8",
      "3.3.17"
     ]
    },
    "g": "Daily operations"
   },
   {
    "h": "db-health-statement.html",
    "s": "Database Health Statement",
    "t": "Database Health Statement",
    "d": "Evidence when an application team reports the database is slow: for the complaint's time window, the database, its server and the network path from the application server, each with its reading, concluding healthy / database / server / network / not measurable; printable, recorded, and routed to the team that owns the problem as a case",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.14"
     ],
     "nca": [
      "2-9",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.14"
     ]
    },
    "g": "Daily operations"
   },
   {
    "h": "db-performance.html",
    "s": "Database Performance",
    "t": "Database Performance",
    "d": "Oracle databases at a glance: inventory by version, top activity by wait class over time, CPU insight, high wait time, degrading SQL (plan changes) and every database by health — select a database and window",
    "fw": {
     "sama": [
      "3.3.8"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8"
     ]
    },
    "g": "Performance"
   },
   {
    "h": "db-sessions.html",
    "s": "Long-Running Queries",
    "t": "Long-Running Queries",
    "d": "Sessions holding up a database right now: blockers (including idle sessions holding locks) and statements running too long, with why each hurts (sessions blocked, run time, TEMP, CPU, waits); Cancel SQL or Kill session only after a DBA approver approves, re-checked inside the database",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.6",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.6",
      "3.3.14"
     ]
    },
    "g": "Performance"
   },
   {
    "h": "oracle-tuning.html",
    "s": "Oracle Tuning",
    "t": "Oracle Tuning & GoldenGate",
    "d": "Explainable findings from the collected readings (plan changes, stale statistics, waits, memory, undo, limits), Top SQL with live execution plans, GoldenGate integrated Extract / Replicat status and lag, and AI Oracle DBA recommendations with fix, rollback and check scripts - approved and run by a named DBA, never by the platform; Diagnostics Pack reading only after the licence is confirmed",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Performance"
   },
   {
    "h": "db-connections.html",
    "s": "Application Connections",
    "t": "Application Connections",
    "d": "Which APIs and services are connected to each database (service, machine, program, user, sessions), which dropped off, listener refusals with what they mean and how to fix them, clients the database saw time out, and database links with what their remote user can change",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.8"
     ],
     "nca": [
      "2-2",
      "2-9"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5",
      "3.3.8"
     ]
    },
    "g": "Applications"
   },
   {
    "h": "app-route-map.html",
    "s": "Application Route Map",
    "t": "Application Route Map",
    "d": "Every business application as one route from its users to its database - front end and APIs (Applications Manager), application servers, database service and the database with its RAC instances - the broken hop in red with the fix; an administrator sets up each application from its boxes",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.8"
     ],
     "nca": [
      "2-2",
      "2-9"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5",
      "3.3.8"
     ]
    },
    "g": "Applications"
   },
   {
    "h": "db-replication.html",
    "s": "Replication & Data Guard",
    "t": "Replication & Data Guard",
    "d": "Data Guard (transport, apply, gaps, lag, broker) and GoldenGate monitoring, and the platform's own engines: Data Verify (source vs target row by row, repairs approved by a named DBA), Change Stream (who changed what, from the redo) and Replication to a reporting target with four-eyes approval",
    "fw": {
     "sama": [
      "BCM",
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "3-1",
      "2-9",
      "2-7"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 29"
     ],
     "ia": [
      "BCM",
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Availability & licensing"
   },
   {
    "h": "oracle-licences.html",
    "s": "Oracle Licence Inventory",
    "t": "Oracle Licence Inventory",
    "d": "Every Oracle Database deployment (software inventory, monitored databases' own edition, entries) and the servers it must be licensed on - VMware cluster rules, sockets and cores, the Oracle Processor Core Factor Table row matched to each CPU, processor licences and NUP minimums against what is owned",
    "fw": {
     "sama": [
      "3.3.3",
      "3.4.1"
     ],
     "nca": [
      "2-1",
      "1-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.4.1"
     ]
    },
    "g": "Availability & licensing"
   }
  ]
 },
 {
  "id": "eud",
  "sn": "Workplace",
  "name": "Workplace: Desktops, Printers & Voice",
  "c": "#56d4dd",
  "hd": "infra",
  "icon": "<rect x=\"3\" y=\"4\" width=\"14\" height=\"10\" rx=\"1.5\"/><path d=\"M1 18h18\"/><rect x=\"18\" y=\"8\" width=\"5\" height=\"12\" rx=\"1\"/>",
  "pages": [
   {
    "h": "desktops.html",
    "s": "User Desktops",
    "t": "User Desktops",
    "d": "Every user desktop and laptop by branch: user, Endpoint Central agent, missing patches, open tickets; remote support with a logged reason; branches assigned to each desktop engineer",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.5",
      "3.3.14"
     ]
    },
    "g": "Desktops"
   },
   {
    "h": "mdm.html",
    "s": "Endpoint & Mobile Management",
    "t": "Endpoint & Mobile Management",
    "d": "The managed laptops, tablets and phones exactly as ManageEngine Mobile Device Manager Plus reports them: by platform and ownership (company or personal - container only), and the devices that stopped checking in. Read only, operators and above; no compliance verdict is inferred.",
    "fw": {
     "sama": [
      "3.3.8"
     ],
     "nca": [
      "2-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8"
     ]
    },
    "g": "Desktops"
   },
   {
    "h": "end-user-devices.html",
    "s": "End-User Devices",
    "t": "End-User Devices (Infrastructure Assistant Manager)",
    "d": "PCs, laptops, mobiles, printers and IP phones: who has what, unsupported OS, not seen, warranty, spares and repairs, agent coverage",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.10",
      "3.3.11"
     ],
     "nca": [
      "2-1",
      "2-6"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.3",
      "3.3.10",
      "3.3.11"
     ]
    },
    "g": "Desktops"
   },
   {
    "h": "desktop-patches.html",
    "s": "Patch Management",
    "t": "Desktop Patch Management",
    "d": "Missing patches across the desktops, compliance by branch, deploy or scan a branch through Endpoint Central after a second person approves",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "2-3",
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.8",
      "3.3.5",
      "3.3.14"
     ]
    },
    "g": "Desktops"
   },
   {
    "h": "support-center.html",
    "s": "Support Center",
    "t": "Support Center",
    "d": "The IT service-desk queue over ManageEngine ServiceDesk Plus: tickets the platform opens from the asset and patch rules and by hand, shown as a worked queue - waiting for approval, open at the desk, closed, rejected - with each ticket's age against a per-priority target so a breach is visible. Raising a request waits for a second person; approve and reject are four-eyes. Read only otherwise; the integration, rules and patch actions stay on ManageEngine Automation.",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5"
     ]
    },
    "g": "Desktops"
   },
   {
    "h": "tickets.html",
    "s": "Tickets",
    "t": "Tickets - infrastructure and security tickets in ServiceDesk Plus",
    "d": "Every ticket the platform raised in ServiceDesk Plus: infrastructure tickets from IT Asset Management with SLA breach and breach risk learned from closed tickets, recurring problems, possible duplicates, weekly flow and backlog forecast, AI triage; and the tickets the SIEM opened for security alerts and cases",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.3.5"
     ]
    },
    "g": "Desktops"
   },
   {
    "h": "manageengine.html",
    "s": "ManageEngine",
    "t": "ManageEngine: ServiceDesk Plus & Endpoint Central",
    "d": "Computers and patch health from Endpoint Central into IT Asset Management; ServiceDesk Plus tickets opened by rules (missing patches, silent agents, warranty, end-of-life) automatically or after approval, and by hand; Endpoint Central scans and patch installs approved by a second administrator.",
    "fw": {
     "sama": [
      "3.3.17",
      "3.3.7",
      "3.3.3"
     ],
     "nca": [
      "2-10",
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17",
      "3.3.7",
      "3.3.3"
     ]
    },
    "g": "Desktops"
   },
   {
    "h": "hr-onboarding.html",
    "s": "HR Onboarding",
    "t": "HR Onboarding",
    "d": "New joiners from HR's request to a working laptop and account: manager approval, a laptop reserved from stock in the asset register, the account proposed and approved by a second person, created in Active Directory automatically after the four-eyes approval (disabled, temporary password shown once to the manager) or by a person, and the laptop handover",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.3"
     ],
     "nca": [
      "1-9",
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.3"
     ]
    },
    "g": "People lifecycle"
   },
   {
    "h": "hr-offboarding.html",
    "s": "HR Offboarding",
    "t": "HR Offboarding (leavers)",
    "d": "Leavers: the manager confirms, a different administrator approves disabling the Active Directory account, the platform disables it on the last day (password replaced, moved to the leavers OU, verified, never deleted) and the equipment goes back to stock",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.3"
     ],
     "nca": [
      "2-2",
      "1-9"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.3"
     ]
    },
    "g": "People lifecycle"
   },
   {
    "h": "hr-movers.html",
    "s": "HR Movers",
    "t": "HR Movers (department / job changes)",
    "d": "Movers: the account's current groups read from Active Directory, the groups to leave and to join chosen from them and from the allowed list, approved by the receiving manager and a different administrator, changed on the effective date, read back and verified, revertible with a second approval",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.3"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.3"
     ]
    },
    "g": "People lifecycle"
   },
   {
    "h": "facilities.html",
    "s": "Facilities & Devices",
    "t": "Facilities & Devices",
    "d": "The physical estate per site, only from what the platform monitors: printers (faults, toner, pages), device reachability from the availability scanner, UPS units through the UPS-MIB, door controllers and door alarms from ZKBioSecurity, and the site list. CCTV / NVR says not connected - no figure is shown for it.",
    "fw": {
     "sama": [
      "3.3.6"
     ],
     "nca": [
      "2-14"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6"
     ]
    },
    "g": "Printers"
   },
   {
    "h": "door-access.html",
    "s": "Door Access",
    "t": "Door Access (ZKBioSecurity)",
    "d": "Door controllers online / offline and the last 24 h of door alarms (duress, forced open, tamper, held open, denied) from ZKTeco ZKBioSecurity, read only. No door is opened from here and no person, card or level is read into the platform.",
    "fw": {
     "sama": [
      "3.3.6"
     ],
     "nca": [
      "2-14"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6"
     ]
    },
    "g": "Printers"
   },
   {
    "h": "cctv.html",
    "s": "CCTV / NVR",
    "t": "CCTV / NVR - recorder and camera health",
    "d": "Hikvision recorders read through ISAPI (GET only, no video): cameras online / offline / not reported, disk health, 7-day availability measured by the platform, cameras going on and off, group outages pointing to one shared cause (PoE switch, uplink, power), ranked actions, cameras missing from the asset register; recorders and their read-only login set by an administrator",
    "fw": {
     "sama": [
      "3.3.6"
     ],
     "nca": [
      "2-14"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6"
     ]
    },
    "g": "Printers"
   },
   {
    "h": "printers.html",
    "s": "Printers",
    "t": "Printers (Xerox / YSoft SAFEQ)",
    "d": "Printer status, toner, paper, jams and page counters over SNMP; pages, colour and cost per user, department and printer from SAFEQ reports",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    },
    "g": "Printers"
   },
   {"h": "cucm.html", "s": "Call Manager", "t": "Call Manager - Cisco Unified CM: phones, trunks, calls, learned findings, four-eyes restarts", "d": "Every phone with its registration by device pool, SIP trunks and gateways, active calls and the failed share, findings each against its own baseline (a pool losing phones, flapping, trunk down, failed calls up), and restart / reset of phones approved by a different administrator", "fw": {"nca": ["2-3"], "iso": ["8.20"]}, "k": ["cucm", "call manager", "cisco", "phones", "voice", "sip trunk", "gateway", "telephony", "uc"]},
   {
    "h": "uc.html",
    "s": "UC Overview",
    "t": "Unified Communications",
    "d": "Call control, voicemail, presence, contact centre, SBC and voice gateways (up / down and availability from Server Availability), and every IP phone and video device: by vendor and site, in the asset register or found on the network and not yet approved, not seen for 30 days",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.3"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.3"
     ]
    },
    "g": "Voice & video"
   },
   {
    "h": "voice-troubleshoot.html",
    "s": "One-way Audio",
    "t": "One-way Audio Troubleshooter",
    "d": "Cisco IP phones where one side cannot hear the other: the voice sessions per direction on every firewall, SIP ALG, NAT, voice policies allowed one way only, asymmetric paths and WAN events; fix and rollback per device, proposed for approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.6"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.6"
     ]
    },
    "g": "Voice & video"
   }
  ]
 },
 {
  "id": "app",
  "sn": "Applications",
  "name": "Applications & Business Services",
  "c": "#f778ba",
  "hd": "business",
  "icon": "<rect x=\"3\" y=\"4\" width=\"18\" height=\"16\" rx=\"2\"/><path d=\"M3 9h18M8 14l2 2-2 2M13 18h3\"/>",
  "pages": [
   {
    "h": "applications.html",
    "s": "All Applications",
    "t": "Applications",
    "d": "Every application with the servers it runs on: up or down, redundant or single-server, DR copy, business and IT owner; create an application, add or remove its servers, set primary / secondary / DR roles",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.3",
      "BCM"
     ],
     "nca": [
      "2-15",
      "2-1",
      "3-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.3",
      "BCM"
     ]
    },
    "g": "Applications"
   },
   {
    "h": "business-services.html",
    "s": "Business Services",
    "t": "Business Services",
    "d": "What runs on every server, found automatically: Oracle, SQL Server and other databases, IIS / Apache / nginx, Tomcat / WebLogic, SAP, Exchange, Active Directory - with the evidence, who could look, and business-critical proposed for an administrator to confirm",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.6",
      "BCM"
     ],
     "nca": [
      "2-1",
      "2-15"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.6",
      "BCM"
     ]
    },
    "g": "Applications"
   },
   {
    "h": "webapps.html",
    "s": "Applications, Web Servers & APIs",
    "t": "Applications, Web Servers & APIs - web tier, application servers and APIs with ML and AI",
    "d": "Live from Applications Manager: web, application-server and API monitors by tier with an itemised health score, probable-cause hosts (several monitors down at once counted as one cause), a 5-minute history with availability, flapping and new vs chronic problems, servers running web / app software with no monitor (from Business Services), certificate expiry on those hosts, and a read-only AI application operations advisor",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.3"
     ],
     "nca": [
      "2-3",
      "2-15"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.3"
     ]
    },
    "g": "Applications"
   },
   {
    "h": "apm.html",
    "s": "Applications Manager",
    "t": "ManageEngine Applications Manager",
    "d": "Every Applications Manager monitor (applications, URLs, servers, databases) with health, availability and open alarms; Poll now at once, Maintenance / Resume only after a different person approves; coverage against the Database Dashboard; connection and API key (administrator)",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.3",
      "3.3.14"
     ],
     "nca": [
      "2-15",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.3",
      "3.3.14"
     ]
    },
    "g": "Performance"
   },
   {
    "h": "apm-claims-portal.html",
    "s": "Claims Portal (APM)",
    "t": "Claims Portal Performance",
    "d": "Calls, response time, errors, JVM memory and database",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.13",
      "3.3.14"
     ],
     "nca": [
      "2-15",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.6",
      "3.3.13",
      "3.3.14"
     ]
    },
    "g": "Performance"
   },
   {
    "h": "synthetic.html",
    "s": "Synthetic & Apdex",
    "g": "Performance",
    "t": "Synthetic Monitoring & Apdex",
    "d": "Scheduled GET checks of each application URL (and link-following transactions): availability 24 h / 7 d / 30 d, Apdex per check and application, response-time breakdown (DNS, connect, TLS, first byte), TLS certificate expiry, and portal Apdex from the web server logs; allowed hosts set by an administrator",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.14"
     ],
     "nca": [
      "2-15",
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.14"
     ]
    }
   },
   {
    "h": "portal-traffic.html",
    "s": "Portal Traffic",
    "t": "Portal Traffic Overview",
    "d": "What the customer portal's web server actually served (nginx / Apache access logs in the SIEM): requests, visitors, answered without server error, 95th-percentile request time, status codes over time, top pages, error paths, visitors by country as the firewall saw them, and the client IPs causing errors",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.13",
      "3.3.14"
     ],
     "nca": [
      "2-15",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.6",
      "3.3.13",
      "3.3.14"
     ]
    },
    "g": "Traffic"
   },
   {
    "h": "browsing-monitor.html",
    "s": "Browsing Traffic",
    "t": "Browsing Traffic - Live Monitor",
    "d": "Live from the firewall web-filter logs in the SIEM: requests allowed / blocked, risky categories that were allowed (policy gaps), top sites and categories, sites seen for the first time, unusual volume against each person's own average (operators, PDPL, audited), live feed, AI web-security analyst, Excel",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.13",
      "3.3.14"
     ],
     "nca": [
      "2-15",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.6",
      "3.3.13",
      "3.3.14"
     ]
    },
    "g": "Traffic"
   }
  ]
 },
 {
  "id": "ast",
  "sn": "IT Assets & Cost",
  "name": "IT Assets, Licences & Cost",
  "c": "#7ee787",
  "hd": "business",
  "icon": "<path d=\"M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8z\"/><path d=\"M7.5 7.5h.01\"/>",
  "pages": [
   {
    "h": "asset-studio.html",
    "s": "Asset Studio",
    "t": "Asset Studio - the asset register with machine learning and an AI analyst",
    "d": "Every asset with a 0-100 health score explained point by point (missing details, not seen for 30 days, warranty, end of life, owner), the estate by type, a searchable register with an asset detail panel, retired assets still seen on the network, missing vendor / model / OS / site learned from similar assets for a person to apply, and an AI asset analyst",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Register & CMDB"
   },
   {
    "h": "cmdb-studio.html",
    "s": "CMDB Studio",
    "t": "CMDB Studio - configuration items and relationships with machine learning and an AI analyst",
    "d": "Every configuration item and what it runs on, connects to and depends on: overview with what to do next and CMDB health over time (trend, 30-day projection), relationship explorer coloured by type / quality / importance with blast radius, ML proposals with confidence calibrated from your decisions and bulk confirm, crown jewels (PageRank) and criticality mismatches, service groups (CIs that work together, unmapped services), coverage heat maps by type and site, data quality, duplicates, orphans, AI CMDB analyst, Excel",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Register & CMDB"
   },
   {
    "h": "asset-coverage.html",
    "s": "Coverage & Query",
    "k": ["edr", "coverage gaps", "query", "octox", "missing agent", "unprotected"],
    "t": "Coverage & Query - security coverage gaps per asset, asset queries, scheduled reports and an approval-gated Action Center",
    "d": "Every asset joined with what the security tools report about it: endpoint protection (and out-of-date versions), Endpoint Central patch agent, backup, Greenbone scans and SIEM logs - present, weak or missing, each with its source; gaps ranked by criticality, coverage heat maps by site and type, a query language (type:server edr:missing gaps>0), saved queries shared with each team and scheduled to e-mail only when the result changes, exemptions with an end date, and an Action Center (SIEM enrolment, owner, tag) that a different person approves",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Register & CMDB"
   },
   {
    "h": "cmdb-deps.html",
    "s": "CMDB & Dependencies",
    "t": "CMDB & Dependencies",
    "d": "Every business application and what it stands on: layered dependency map, click a component to see what fails with it (clusters keep standing), single points of failure, under-rated / end-of-life / unconfirmed dependencies, unmapped machines, cycles, itemised risk per application, weekly changes, AI dependency analyst, Excel",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Register & CMDB"
   },
   {
    "h": "digital-twin.html",
    "s": "Digital Twin",
    "t": "Digital Twin",
    "d": "A living model of the estate from the asset register and CMDB with live backup, DR and vulnerability state: site map, what-if simulation (lose a site or a component), Monte Carlo outage probability per application, failure likelihood per component with its reasons (learned from recorded outages), fix-first ranking, DR copies, recovery targets, AI twin analyst, Excel",
    "fw": {
     "sama": [
      "3.3.3",
      "BCM"
     ],
     "nca": [
      "2-1",
      "3-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "BCM"
     ]
    },
    "g": "Register & CMDB"
   },
   {
    "h": "reconcile.html",
    "s": "Asset Reconciliation",
    "t": "Server & Asset Reconciliation",
    "d": "Where IT Asset Management disagrees with AD, vCenter, Nutanix, Server Availability and the AI Server Administrators: IP, OS, name, missing servers, retired-but-alive, duplicates, Exchange role; Apply / Accept, Sync all now",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Register & CMDB"
   },
   {
    "h": "network-discovery.html",
    "s": "Network Discovery",
    "t": "Network Discovery",
    "d": "Add many firewalls, switches, routers and servers at once: give it a name, an IP range, subnets or a CSV list, tick the saved SNMP credentials (up to 8, tried in order), approve the scan - then pick the devices found and add them to IT Asset Management in one click.",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.8"
     ],
     "nca": [
      "2-1",
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.8"
     ]
    },
    "start": true,
    "g": "Discovery"
   },
   {
    "h": "discovery-studio.html",
    "s": "Discovery Studio",
    "g": "Discovery",
    "t": "Discovery Studio - Asset Discovery runs, results, bulk add and credentials with ML and AI",
    "d": "What Asset Discovery found and what to do with it: a recommendation per new device (merge into an existing asset, add, ignore, check first) with its reasons, learnt from your team's past decisions; bulk groups added in one click through the same de-duplication and audit; runs compared with each scope's own history (drops and failed methods flagged); credential health with every point named; coverage gaps; an AI analyst whose bulk proposals a person applies",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.4"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.4"
     ]
    }
   },
   {
    "h": "scope-studio.html",
    "s": "Scope Studio",
    "t": "Scope Studio - Asset Discovery scopes with machine learning and an AI advisor",
    "d": "What the discovery scopes cover and what they miss: a coverage map of every known subnet, gaps turned into scope proposals with methods chosen from what each subnet holds, a 0-100 health score per scope with every point explained, anomalies in the devices a run saw, idle methods, ports calling for a method that is off, expected run time learned from your own scans, and an AI advisor that drafts proposals a System Admin accepts or dismisses",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Discovery"
   },
   {
    "h": "owner-studio.html",
    "s": "Accountability Studio",
    "t": "Accountability Studio - owners and source differences with machine learning and an AI analyst",
    "d": "IT owner, business owner and business service coverage, owner suggestions with their evidence (CMDB dependencies, name and subnet peers, departments) that a person applies, owner load, every difference with AD, vCenter, Nutanix and the other sources with a priority and a fix / accept recommendation learned from how your team decided before, causes at one source, stale sources, and an AI accountability analyst",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Ownership"
   },
   {
    "h": "people-inventory.html",
    "s": "User Inventory",
    "k": ["users", "people", "employees", "microsoft 365 per user", "m365 licences", "office apps", "teams usage", "who has", "assigned devices", "laptop owner", "custodian", "installed software", "applications per user", "leaver devices"],
    "t": "User Inventory - each person, their devices, applications and Microsoft 365 apps",
    "d": "Each person from Active Directory with the devices they hold or sign in to (asset custodian, owner of end-user devices, Endpoint Central signed-in user - exact name matches only) and the applications installed on those devices: leavers still holding devices, no sign-in for 90 days, names not in the directory, remote-access and blocked software, applications unusual for the department, Microsoft 365 licences, the Microsoft 365 apps each person used in 30 days (Outlook, Word, Excel, PowerPoint, OneNote, Teams) and their Exchange / OneDrive / SharePoint / Teams activity, licences on disabled accounts or unused for 30 days, end-user devices with no person, CSV export",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.5"
     ],
     "nca": [
      "2-1",
      "2-2"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.5"
     ]
    },
    "g": "Ownership"
   },
   {
    "h": "asset-ownership.html",
    "s": "Asset Ownership",
    "t": "Asset Ownership (IT owner · business owner)",
    "d": "Every asset with its IT owner, business owner and business service: coverage, owners set once per service and inherited, bulk assignment, CSV import and export, audited",
    "fw": {
     "sama": [
      "3.3.3",
      "3.1.4"
     ],
     "nca": [
      "2-1",
      "1-4"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.1.4"
     ]
    },
    "g": "Ownership"
   },
   {
    "h": "eam.html",
    "s": "Enterprise Asset Management",
    "t": "Enterprise Asset Management - plan, buy, receive, deploy, maintain and retire every asset, with machine learning and an AI advisor",
    "d": "Purchase requests approved by procurement (four-eyes), receiving into stock with serials becoming assets, deployment, corrective and preventive work orders verified by a second person, maintenance plans that raise their own work orders, spares and consumables with days of cover and reorder suggestions, retirement and disposal approved by a different administrator, and machine learning from your own records: failure risk explained point by point, MTBF / MTTR per model, next failure projection, cost outliers, technician suggestion - with workspaces for asset managers, field service, warehouse, procurement and facilities",
    "fw": {
     "sama": [
      "3.3.3",
      "3.4.2"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "lifecycle-studio.html",
    "s": "Lifecycle Studio",
    "t": "Lifecycle Studio - replace, upgrade, renew or isolate, and when, with machine learning and an AI planner",
    "d": "Every asset with a 0-100 lifecycle risk explained point by point, the replacement due date and what drives it (end of life, warranty, lifespan learned from your own retirements), the action, the cost from recorded purchases only, an 8-quarter refresh forecast, support renewals for the next 12 months, the refresh plan people accept, and an AI lifecycle planner that proposes plan items",
    "fw": {
     "sama": [
      "3.3.3",
      "3.4.2"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.4.2"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "asset-autofill.html",
    "s": "Asset Data Autopilot",
    "t": "Asset Data Autopilot - serial, MAC, warranty, support, end of life, classification and CIA filled automatically",
    "d": "How complete each record field is, and the values the platform works out for the gaps: support from contracts and Cisco by serial, warranty from purchase dates and the term learned from peers, end of life from the vendor OS / firmware table and the hardware life learned from your own retirements, classification and CIA from classified peers and the record's facts. Each with its source, verified or estimated, and the reason; a person accepts.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1",
      "2-7"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "asset-purchasing.html",
    "s": "Asset Purchasing",
    "t": "Asset Purchasing - purchase orders from request to go-live, against the IT budget",
    "d": "Every IT purchase: PO number, vendor, product lines, dates (requested, approved, ordered, delivered, installed, go-live, invoiced, paid) and cost, with four-eyes approval and items received straight into the asset register. Budget utilisation per line and envelope (committed vs spent, remaining, year-end forecast), vendor scorecard, and machine learning on these orders: late deliveries from each vendor's own lead time, delivered-but-not-live, prices above the usual.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "software-studio.html",
    "s": "Software & Licences",
    "t": "Software & Licences - licence compliance, waste and true-up, reclaim, unlicensed and risky software",
    "d": "Every installed product from the endpoint agents and imports, against the licence records: seats vs installs, utilisation, the cost of unused seats and the true-up exposure (from the licence's own cost), seats to reclaim from in-stock or long-unseen assets, commercial software with no licence, remote-access tools, software rare for its asset type (machine learning) and version sprawl, with an approved / blocked software policy.",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.5"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.5"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "renewals-expiry.html",
    "s": "Renewals & Expiry",
    "t": "Renewals & Expiry - licences, certificates, domains, support contracts, app secrets and warranties in one calendar",
    "d": "Everything that expires, read from the module that owns it: licences, support contracts, certificates, domains and hosting, app secrets and credential rotation, warranties, asset support and Cisco Smart Net. Ranked by an itemised risk with lead times learned from verified renewals; owner, in progress, renewed and not-renewing tracked by a person, a renewal verified only when the source shows the new date; 12-month cost forecast and expiry storms.",
    "fw": {
     "sama": [
      "3.3.3",
      "3.4.2"
     ],
     "nca": [
      "2-1",
      "2-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.4.2"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "itam-settings.html",
    "s": "ITAM Settings",
    "t": "ITAM Settings - sources, thresholds, agents, credentials and imports, with an advisor",
    "d": "The configuration of IT Asset Management with a health score and recommendations backed by evidence: the not-seen threshold learned from how often assets report, the expiry window against the renewal lead time, silent sources, vCenter without credentials, agent coverage by site, agents and tokens that are stale, devices waiting to be adopted, AI privacy - applied when an administrator clicks. Agent enrolment, write-only connector credentials and CSV / CMDB import with a dry run.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "itam-overview.html",
    "s": "IT Asset Management",
    "t": "IT Asset Management overview - health, what to do next, every ITAM module in one view",
    "d": "One view over Inventory, Asset Data Autopilot, Purchasing, Software & Licences, Renewals & Expiry, Stocktake and AI Findings: a health score from the parts that have data (each part shown with its weight; parts without data are left out and the score is withheld below three), the next things to do ranked with the page that fixes each, tiles that open their module, assets by type, site and status, the weakest data fields and sites, budget use and a daily trend.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "inventory.html",
    "s": "Inventory",
    "t": "ITAM Inventory - the asset register with data quality, duplicates and outliers",
    "d": "Every asset with facets, search, sortable columns you choose, saved views, CSV export and bulk changes; a data-quality score per asset with what is missing, duplicates by serial / MAC / name, spec outliers against the same model, assets not seen and retired assets still seen. A drawer shows the record with the source of each field, edits it (a conflicting change is refused), moves it through its lifecycle with a reason, and shows its history.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "stocktake.html",
    "s": "Stocktake",
    "t": "ITAM Stocktake - physical count with a barcode scanner, missing assets ranked, unexpected codes matched",
    "d": "Open a count for a site (or the whole register) and scan tags or serials with a barcode scanner or by typing them. Progress by type and department with the pace and time to go; missing assets ranked by how likely they are really gone (seen on the network recently, portable, missed before, not seen for months) and resolved by a person; unexpected codes matched to the closest tag or serial; assets found at the wrong site; which site to count next; CSV of the missing.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "lifecycle.html",
    "s": "End of Life & Isolation",
    "t": "End of Life & Isolation",
    "d": "Servers, PCs, switches, routers and firewalls running an operating system or firmware past vendor end of support; isolate one with CISO approval",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.11",
      "3.3.17"
     ],
     "nca": [
      "2-1",
      "2-10"
     ],
     "pdpl": [
      "Art. 18"
     ],
     "ia": [
      "3.3.3",
      "3.3.11",
      "3.3.17"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "support-contracts.html",
    "s": "Support Contracts",
    "t": "Support Contracts",
    "d": "Every vendor support agreement - Microsoft (Windows, Exchange, SQL), VMware, Nutanix, Oracle, Red Hat, Cisco Smart Net, hardware - assigned to what it covers and checked against the inventory: expiry, devices not covered, quantity, Cisco serials validated with Cisco.",
    "fw": {
     "sama": [
      "3.4.1",
      "3.4.2"
     ],
     "nca": [
      "4-1"
     ],
     "pdpl": [],
     "ia": [
      "3.4.1",
      "3.4.2"
     ]
    },
    "g": "Lifecycle & contracts"
   },
   {
    "h": "cost-optimisation.html",
    "s": "Cost Optimisation",
    "t": "Cost Optimisation - where the virtual estate and its platforms can cost less, from the collected estate",
    "d": "Platform scenarios over what vCenter / Prism and the asset register report: consolidation from measured CPU and memory (with N+1), non-production VMs off the commercial hypervisor, production to Nutanix AHV where Nutanix runs, powered-off VMs to reclaim, several backup platforms to one, SPARC servers on support. Each with saving, one-off effort, payback, risk, evidence (measured vs assumed), CISO view and compliance impact; recorded licence costs win over planning figures, which an administrator replaces with contract prices; business cases are approved by a different administrator.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Cost & budget"
   },
   {
    "h": "cost-studio.html",
    "s": "Cost Studio",
    "t": "Cost Studio - savings, budget execution and showback with machine learning and an AI analyst",
    "d": "Savings with their evidence, priced only from recorded costs: licence seats paid for and not used, support contracts for more units than the inventory needs or still listing retired assets, overlapping contracts, powered-off and oversized VMs; how much of each budget area was really spent last year applied to this year's lines; unusual budget lines; cost by site, department and type; saving actions tracked to the amount realised; and an AI cost analyst that proposes actions",
    "fw": {
     "sama": [
      "3.1.5"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [],
     "ia": [
      "3.1.5"
     ]
    },
    "g": "Cost & budget"
   },
   {
    "h": "budget.html",
    "s": "IT Budget",
    "t": "IT Budget",
    "d": "Next year's CAPEX / OPEX budget built from last year's pending items, licence renewals, support renewals, end-of-life replacements and storage growth, against the IT Operations (66M) and Cyber Security (30M) envelopes; approve, defer, export. Execution tab: the approved budget through the year - quarterly phasing, purchase orders and invoices against each line, variance, year-end forecast with overspend and lapse warnings",
    "fw": {
     "sama": [
      "3.1.2"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [],
     "ia": [
      "3.1.2"
     ]
    },
    "g": "Cost & budget"
   }
  ]
 },
 {
  "id": "grc",
  "sn": "Risk & Governance",
  "name": "Risk & Governance",
  "c": "#3fb950",
  "hd": "gov",
  "icon": "<path d=\"M9 11l3 3 8-8\"/><path d=\"M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9\"/>",
  "pages": [
   {
    "h": "risk-command.html",
    "s": "Risk Command Center",
    "t": "Risk Command Center - posture, heat map, Monte Carlo, appetite, treatment, owners",
    "d": "The front door of risk management: the risk register and the ten insurer risk scenarios in one view - an itemised risk posture with its daily history and projection, inherent and residual heat maps, risks above appetite or rated high, a seeded Monte Carlo of how many risks may occur in a year from the owners' ratings, categories against appetite, treatment effectiveness (mitigate with no reduction recorded), owner concentration, movers, risks proposed from platform signals, read-only AI risk advisor",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "grc-dashboard.html",
    "s": "GRC Dashboard",
    "g": "Overview",
    "t": "Governance, risk and compliance posture across every register",
    "d": "One view over the policy register, Risk Studio, the GRC actions, every framework register and continuous control monitoring: a GRC posture index with every deduction itemised, the attention list, framework compliance, the risk heat map, remediation and named roles; daily trend, unusual changes and the biggest movers learned from the platform own snapshots; the AI GRC advisor for the CISO and the board",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {"h": "risk-assessments.html", "s": "Risk Assessments", "g": "Identify & assess", "t": "Process Risk Assessments - standalone deep-dives on procurement, succession, pricing and more", "d": "Standalone risk assessments on a specific process - procurement, the succession plan, pricing, outsourcing, underwriting, claims, IT change - separate from the risk register. When the team notices an issue they open an assessment, record findings (likelihood x impact rating), raise GRC actions for the recommendations, and extract the standalone report auditors ask for (white background, company logo). A different person in the Risk function approves each assessment (four eyes).", "fw": {"sama": ["3.2"], "nca": ["1-5"], "iso": ["6.1", "A.5.35"]}, "k": ["risk assessment", "procurement", "succession", "pricing", "process", "deep dive", "standalone", "finding"]},
   {
    "h": "risk-assess.html",
    "s": "Automated Risk Assessment",
    "g": "Identify & assess",
    "t": "Automated Risk Assessment - ten scenarios rated from live signals, controls and the register",
    "d": "Ten risk scenarios for an insurer (ransomware, account compromise, data leakage, unpatched systems, outage, third party, regulatory, detection, network, insider) rated from the AI CISO's live signals and measured control posture: itemised likelihood, residual after controls, not-assessed said, heat map, register coverage and ratings that look too low, daily history with unusual jumps, proposals to the GRC register by a person and a read-only AI risk assessor",
    "fw": {
     "sama": [
      "3.1.5"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.5"
     ]
    }
   },
   {
    "h": "risk-studio.html",
    "s": "Risk Studio",
    "g": "Identify & assess",
    "t": "Risk Studio (risk register with evidence, ML and Excel report)",
    "d": "The risk register with its evidence: audit findings, platform gaps, overdue actions and expired exceptions linked to each risk by text similarity; an evidence-based rating beside the owner's with under-rated flags; categories learned from the register; proposed new risks from uncovered signals; appetite per category; 30-day trend; housekeeping; an AI risk analyst that reads only; multi-sheet Excel report",
    "fw": {
     "sama": [
      "3.2.1",
      "3.2.2"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1",
      "3.2.2"
     ]
    }
   },
   {
    "h": "grc-workspace.html",
    "s": "Risks & Actions",
    "g": "Treat & track",
    "t": "Risks & Actions (GRC working registers)",
    "d": "Where GRC gaps are worked: remediation actions with owner, due date, evidence and four-eyes closure; the risk register (likelihood x impact, heat map, treatment, acceptance by an administrator who is not the owner); policy exceptions that expire by date; and the evidence library with SAMA IT governance coverage",
    "fw": {
     "sama": [
      "3.2.1",
      "3.2.2"
     ],
     "nca": [
      "1-5",
      "1-7"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1",
      "3.2.2"
     ]
    }
   },
   {
    "h": "roadmap.html",
    "s": "Remediation Roadmap",
    "g": "Treat & track",
    "t": "Remediation Roadmap - gaps and actions by quarter with pace, slip risk and capacity",
    "d": "Every framework gap from the crosswalk and every GRC remediation action on one timeline (overdue, this quarter, next, later, unscheduled, closed), the pace the team closes them, burn-down date, the chance each item slips from its owner's own history, capacity per quarter, a proposed schedule a person accepts and a read-only AI planner",
    "fw": {
     "sama": [
      "3.3.10"
     ],
     "nca": [
      "1-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10"
     ]
    }
   },
   {
    "h": "impl-plan.html",
    "s": "Implementation Plan & Budget",
    "g": "Treat & track",
    "t": "Implementation Plan & Budget",
    "d": "Every open remediation action (SAMA, NCA ECC, ISO 27001, PDPL, NDMO, DR, audit) as a costed plan: person-entered effort and quotations (never priced by guess), schedule against team capacity with late / at-risk flags, roadmap, cash flow against the envelope, effort calibration from closed actions, velocity forecast, AI plan analyst, Excel",
    "fw": {
     "sama": [
      "3.2.1",
      "3.2.2"
     ],
     "nca": [
      "1-5",
      "1-7"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1",
      "3.2.2"
     ]
    }
   },
   {
    "h": "risk-control.html",
    "s": "Risk & Control Hub",
    "k": ["archer", "risk control", "control library", "residual risk", "control effectiveness", "control testing", "kri", "key risk indicators", "loss events", "business hierarchy", "authoritative sources", "risk acceptance", "exceptions register"],
    "t": "Risk & Control Hub - business hierarchy, risks, the controls that treat them, requirements, tests, KRIs and losses, with residual risk calculated from the controls",
    "d": "One connected risk and control model: business units; risks from the GRC register placed in them and linked to the controls that treat them; one control library citing SAMA, NCA, PDPL, ISO, NDMO and IA requirements; control effectiveness from platform signals or independent tests (a failed test becomes a GRC action and an issue); residual risk calculated from control effectiveness with every point itemised; key risk indicators with thresholds; loss events; roll-ups per unit and framework; one register of every accepted risk and approved exception with expiry",
    "fw": {
     "sama": [
      "3.2.1",
      "3.2.3"
     ],
     "nca": [
      "1-5",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1",
      "3.2.3"
     ]
    },
    "g": "Registers & reports"
   },
   {
    "h": "issues.html",
    "s": "Issues Management",
    "k": ["issues", "findings", "archer", "cyberarrow", "remediation", "duplicates", "repeat findings", "escalation", "regulator findings", "audit findings", "corrective actions", "issue register"],
    "t": "Issues Management - one register of audit, inspection, GRC and regulator issues: duplicates, repeats, escalation, links to risks",
    "d": "Every issue raised by the IT, Cyber Security and Internal Audit teams, IT audit inspections, GRC remediation and regulator / external findings (SAMA, Insurance Authority, NCA) in one register: significance mapped across sources, status, owner, due and overdue, age; possible duplicates across sources confirmed with one click, repeat findings, an escalation list, owner load, links to GRC risks; trend, median days to resolve per source and the backlog in 30 days; each issue links back to the module where it is worked",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-8",
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    },
    "g": "Registers & reports"
   },
   {
    "h": "grc-register.html",
    "s": "GRC Register",
    "g": "Registers & reports",
    "t": "One register: policies, controls, risks, actions, exceptions and evidence with their links",
    "d": "Every GRC record the platform keeps in one register with the links between them, health and itemised quality issues; machine learning finds orphans, possible duplicates, overloaded owners and late actions; a relationship map per record; Excel; the AI GRC register analyst. Records are changed in their own registers",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {
    "h": "grc-policies.html",
    "s": "Policies & Controls",
    "g": "Policies & roles",
    "t": "GRC Policies & Controls",
    "d": "The {{org.short}} approved IT policy register (governance, risk, operations, change): each policy mapped to the platform control that automates or monitors it, live control status, review-cycle tracking (due / overdue), framework coverage (SAMA, NCA, ISO 27001, PDPL) and owner attestations",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.2"
     ],
     "nca": [
      "1-3",
      "1-7"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.2"
     ]
    }
   },
   {
    "h": "roles-raci.html",
    "s": "Roles & RACI",
    "g": "Policies & roles",
    "t": "Roles & RACI (governance roles, holders, RACI matrix)",
    "d": "Governance roles (CISO, GRC, DPO, internal audit, change manager, CAB, administrators, SOC, owners) with their holder and deputy; the RACI of change, incident, access, vulnerability, governance & audit and PDPL work; checks for one accountable role per activity, unheld critical roles, missing deputies, segregation of duties and holders who left; the audit trail mapped to each activity (who actually does it, key-person risk, self-approval, proposed assignments a person accepts); load per person, daily trend, read-only AI advisor",
    "fw": {
     "sama": [
      "3.1.4",
      "3.3.7"
     ],
     "nca": [
      "1-4",
      "1-8"
     ],
     "pdpl": [
      "IR Art. 32"
     ],
     "ia": [
      "3.1.4",
      "3.3.7"
     ]
    }
   },
   {
    "h": "credential-security.html",
    "s": "Credential Security",
    "k": ["passwords", "secrets", "vault", "keys"],
    "g": "Policies & roles",
    "t": "Credential Security (SAMA 3.3.9 evidence)",
    "d": "How every stored password, API key, token and SNMP community is protected: encrypted at rest with AES-256-GCM (per store, sealed vs clear), master-key custody, a live encryption self-test, how each login reaches its device (TLS verified / pinned, SSH host key, SNMPv3, database TLS), a disk scan proving no secret is stored in clear, findings with SAMA / NCA / ISO controls, a CISO statement and one-click save to the GRC evidence library",
    "fw": {
     "sama": [
      "3.3.9",
      "3.3.5"
     ],
     "nca": [
      "2-8",
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.9",
      "3.3.5"
     ]
    }
   }
  ]
 },
 {
  "id": "brisk",
  "sn": "Business Risk",
  "name": "Business Risk",
  "c": "#f97316",
  "hd": "gov",
  "icon": "<path d=\"M3 21h18\"/><path d=\"M5 21V10l7-5 7 5v11\"/><path d=\"M9 21v-6h6v6\"/>",
  "pages": [
   {
    "h": "enterprise-risk.html",
    "s": "Enterprise Risk Dashboard",
    "t": "Enterprise Risk Dashboard - IT and cyber risk, business risk and risk appetite in one view",
    "d": "One dashboard for the Head of Risk Management: the IT and cyber risk posture and scenarios (Risk Command Center), the business risk register (Class III / IV, high inherent) and the Risk Appetite Statement (metrics outside appetite, early warnings), with one ranked list of priorities that says why each item is there",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    }
   },
   {
    "h": "risk-start.html",
    "s": "Start a Risk Assessment",
    "t": "Start a Risk Assessment - a guided path from new risks to the committee-approved cycle",
    "d": "Step by step: your methodology and current position, new risks with machine-learning suggestions (area, category, starting rating, possible duplicates), open the assessment cycle, re-assess every risk or confirm it unchanged with a live preview of the class, decide the treatment of Class III / IV risks (acceptance by a second administrator), department sign-off by someone who assessed none of its risks, risk committee approval that freezes the cycle, and the committee, board and regulator reports - each step says what is done and what blocks it",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    }
   },
   {
    "h": "risk-cycle.html",
    "s": "Risk Assessment Cycle",
    "t": "Risk Assessment Cycle - the quarterly risk and control self-assessment, in the system",
    "d": "Each quarter every open risk is re-assessed (or confirmed unchanged) by its owner in the system; department heads sign off (a person who assessed none of the department's risks), the risk committee approves or returns it, and the approved cycle is frozen and compared with the previous one - replaces the spreadsheet round",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    }
   },
   {
    "h": "ras-manage.html",
    "s": "RAS Management",
    "t": "RAS Management - the Risk Appetite Statement kept in the system, approved by the Board",
    "d": "New appetite metrics (from insurance templates or blank), changes to a metric's definition and retiring one are proposals a second administrator approves; the year's RAS is frozen and its Board approval recorded with the Board reference; what changed since the approval is listed",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    }
   },
   {
    "h": "erm-capital.html",
    "s": "Capital, ORSA & Stress Testing",
    "t": "Capital, ORSA & Stress Testing - capital adequacy, stress scenarios and the yearly ORSA approved by the Board",
    "d": "The capital and solvency position each period (entered by finance, confirmed by a second person) judged against the Risk Appetite Statement; stress scenarios with contingency actions, reverse stress and sensitivity; the yearly ORSA frozen with a fingerprint and approved by the Board; return on risk capital by line of business; risk review of M&A, transformation and new products before a decision",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    }
   },
   {
    "h": "erm-governance.html",
    "s": "Risk Governance & Models",
    "t": "Risk Governance & Models - model validation, committees and delegated authority, fit and proper, risk culture and succession",
    "d": "The inventory of reserving, pricing, capital and IFRS 17 models with independent validation and findings; Board and committee charters, delegated authorities, meetings, decisions and actions; fit-and-proper attestations, key risk takers and risk-culture survey results; succession for key functions - each record entered by a person, due dates and gaps flagged",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    }
   },
   {
    "h": "risk-catalogue.html",
    "s": "Insurance Risk Catalogue",
    "t": "Insurance Risk Catalogue - insurer risk categories, metric templates and emerging risks",
    "d": "The risk categories of an insurer (underwriting, reserving, reinsurance and counterparty, catastrophe, capital and solvency, market, credit, liquidity, operational, IT and cyber, conduct, regulatory, strategic) with a category for every register risk (suggested from its words, confirmed by a person), insurance metric templates without limits, and the emerging-risks watch list promoted to the register by a person",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    }
   },
   {
    "h": "risk-reports.html",
    "s": "Risk Reports",
    "t": "Risk Reports - Risk Committee pack, Board report and Insurance Authority pack",
    "d": "Built from the register, the RAS, the assessment cycles and the emerging risks when opened: the profile by category and residual class, Class III / IV risks, appetite breaches and early warnings, the Board approval of the RAS, the last self-assessment, emerging risks, and for the regulator the full register and RAS; print or save as PDF, download to Excel",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    }
   },
   {
    "h": "business-risk.html",
    "s": "Business Risk Dashboard",
    "t": "Business Risk Dashboard - register, risk appetite and machine-learning insights",
    "d": "The enterprise risk register and the Risk Appetite Statement in one view: inherent and residual heat maps by the department methodology, risks by area and department, appetite metrics outside appetite or tolerance, early warnings forecast from reported values, likely duplicate risks, risks rated unlike similar risks, possible mis-categorisation, data quality, metrics not reported, and a read-only AI Business Risk Officer",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    }
   },
   {"h": "rcsa.html", "s": "RCSA Collection", "g": "Solvency & Capital", "t": "RCSA Collection - risk-owner links with no login; responses reviewed before they reach the register", "d": "Risk & Control Self-Assessment without a login per department. The Risk team opens a campaign; owners are taken from the GRC register; each owner gets a private link (signed, scoped to their own risks, expiring with the campaign, revocable) to send by e-mail. The owner re-assesses likelihood, impact, residual rating and controls on a page carrying the company logo. Every submission arrives as a proposal beside the current rating; a Risk officer accepts it into the register or rejects it with a reason. Audited end to end; also carries RAS figures and RBC inputs.", "fw": {"sama": ["3.2"], "iso": ["6.1.2", "6.1.3"], "nca": ["1-5"]}, "k": ["rcsa", "self assessment", "risk owner", "link", "control", "re-assessment", "register"]},
   {"h": "business-risk-years.html", "s": "Register by Year", "t": "Risk Register by Year - each year's register kept and compared risk by risk", "d": "Close the year (the Risk Head freezes the live register as that year), import past years' register workbooks (preview, then apply; the live register untouched), the trend of risks, high inherent and Class III / IV by year, and any two years (or the live register) compared risk by risk: worse, better, same, new, gone, by risk area and on two heat maps, with Excel export.", "fw": {"sama": ["3.2.1"], "iso": ["6.1.2"], "nca": ["1-5"]}, "k": ["risk register", "year", "previous year", "compare", "trend", "history", "annual"]},
   {
    "h": "business-risk-register.html",
    "s": "Risk Register",
    "t": "Business Risk Register - every business risk, rated by the methodology",
    "d": "Import the department risk register workbook (preview, then apply; matched on the risk code, history kept), likelihood x impact and exposure x band calculated on the server (Class I-IV), quality flags, similar risks, re-assessment with history, four-eyes acceptance of Class III / IV risks, suggestions for a new risk (area, category, starting ratings, possible duplicates) learned from the register, CSV export",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    }
   },
   {"h": "pricing-adequacy.html", "s": "Pricing Adequacy", "g": "Solvency & Capital", "t": "Pricing Adequacy (Motor & Medical) - combined ratio and rate adequacy per line", "d": "Is the premium enough for the risk, per line of business - Motor and Medical. Actuarial records the loss ratio, expense and commission per period; the platform computes the combined ratio and the rate change required to reach target, cross-checks it against the solvency return's own loss ratios, trends it with an early warning when the combined ratio heads above 100%, and extracts the report (white background, company logo). A different person in Risk approves each review (four eyes)", "fw": {"sama": ["3.3"]}, "k": ["pricing", "adequacy", "combined ratio", "loss ratio", "motor", "medical", "rate adequacy", "actuarial"]},
   {"h": "rbc-assessment.html", "s": "RBC Assessment", "g": "Solvency & Capital", "t": "RBC Own Funds & Solvency Assessment - the IA workbook read schedule by schedule, with insights", "d": "Upload the Insurance Authority RBC Own Funds and Solvency Assessment workbook for a period (2025 year end, 2026 Q1, Q2 ...). The platform reads every schedule - MCR and RBC, the solvency position and ratio, own funds by tier with components, the tier-limit PASS / FAIL checks, the eligible own-funds adjustments, the financial projection and the board answers - and explains it: headroom, the change split into the own-funds and RBC effects, capital quality, combined ratio above 100%, the claims trend and the ratio across periods. Report with the company logo; a different person in Risk approves each period (four eyes)", "fw": {"sama": ["3.3"]}, "k": ["rbc", "solvency", "own funds", "mcr", "capital", "insurance authority", "tier 1"]},
   {
    "h": "solvency-capital.html",
    "s": "Solvency & Capital",
    "t": "Solvency & Capital - the Insurance Authority's Solvency and Capital template, reviewed and returned in its own format",
    "d": "Upload the filled Solvency and Capital template (SCA.nn): the regulatory solvency ratio and schedules, RBC, own funds and the RBC solvency ratio (actual and projected), the composition of the capital charge, every stress and scenario test ranked, the template's own Pass / Fail checks with explanations, changes against the last approved return and any changed formula; sign-off by every area, four-eyes approval by the Risk Head, the submission record - and the same workbook back for the Authority with the sign-offs written in",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    }
   },
   {
    "h": "ras-cockpit.html",
    "s": "Risk Appetite Cockpit",
    "t": "Risk Appetite Cockpit - where every metric stands, which risks it watches, what is due, limits to fix",
    "d": "The Risk Appetite Statement run by the platform: section tiles by worst zone and reporting progress, each metric on its six-limit ladder with the next forecast, what changed since the period before; machine learning matches every register risk to the metrics that watch it (text, department, family of risk, learning from confirmed links) for a person to approve one by one or in bulk; each department reports its due values in one form (email reminder); values outside tolerance raise a GRC action at once; corrected limits proposed (order, scale, similar metric, own values) for a four-eyes approval",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    }
   },
   {
    "h": "risk-appetite.html",
    "s": "Risk Appetite (RAS)",
    "t": "Risk Appetite Statement monitoring - limits, reported values, zones and forecasts",
    "d": "Import the RAS workbook (sections, metrics, capacity / tolerance / appetite floors and ceilings read as numbers, limit issues listed), each department reports its values monthly or quarterly (one or many), zone within appetite / outside appetite / outside tolerance / capacity breached, Holt forecast and early warning, link metrics to register risks, raise a GRC action for a breach",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    }
   }
  ]
 },
 {
  "id": "cmp",
  "sn": "Compliance",
  "name": "Compliance & Frameworks",
  "c": "#22c55e",
  "hd": "gov",
  "icon": "<path d=\"M12 3 4 6v6c0 5 3.4 8.6 8 9 4.6-.4 8-4 8-9V6z\"/><path d=\"m9 12 2 2 4-4\"/>",
  "pages": [
   {"h": "aramco-ccc.html", "s": "Aramco CCC", "t": "Aramco CCC - the Saudi Aramco Cybersecurity Compliance Certificate from scope to renewal", "d": "The Aramco contracts and their service types, the control list imported from your SACS-002 copy, self-assessment with a four-eyes 'not applicable', remediation actions, evidence references, the approved audit firm's findings, the certificate, its coverage and renewal, and the readiness trend against the planned audit", "fw": {}, "k": ["aramco", "ccc", "sacs-002", "third party", "certificate", "contractor", "vendor"]},
   {
    "h": "compliance-flow.html",
    "s": "Compliance Automation Flow",
    "t": "Compliance Automation Flow",
    "d": "How the compliance automation works, live: data sources -> collectors -> SIEM and IT engines -> machine learning -> controls tested -> frameworks -> evidence & approvals -> reports & AI, each stage lit from its own source; and the Requirement -> Control -> Evidence chain with its breaks, reliability (ML), regressions and leverage",
    "fw": {
     "sama": [
      "3.2.3",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.3",
      "3.2.4"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "compliance-start.html",
    "s": "Compliance Programme",
    "g": "Overview",
    "t": "Compliance Programme - how {{org.short}} starts, achieves and keeps compliance with PDPL, NDMO, NCA ECC and SAMA CSF",
    "d": "A guided path per regulation over the platform's compliance registers: name the owner (DPO, Chief Data Officer, CISO), the baseline from the platform's own records (met / gap / needs evidence, by area), gaps sent to the GRC register as remediation actions, evidence and confirmations recorded by a person, independent approval by a second person (for PDPL the DPO signs the statement and management countersigns), the assessment report or the register export, and continuous assurance (evidence to renew, confirmations over a year old, records that disagree) - an automated gap always wins over a confirmation",
    "fw": {
     "sama": [
      "3.2.3"
     ],
     "nca": [
      "1-7"
     ],
     "pdpl": [
      "Art. 32"
     ],
     "ia": [
      "3.2.3"
     ]
    }
   },
   {
    "h": "compliance-overview.html",
    "s": "Compliance Overview",
    "g": "Overview",
    "t": "Compliance Overview - every framework, top priorities, risk and delivery",
    "d": "SAMA CSF, NCA ECC, ISO 27001, NDMO and PDPL as their registers measure them with the crosswalk projection, the ten work items that close the most, risks above appetite from the Automated Risk Assessment, GRC remediation delivery, contradictions and drift, the overall trend and a read-only AI board reporting advisor",
    "fw": {
     "sama": [
      "3.1.1",
      "3.2.4"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.2.4"
     ]
    }
   },
   {
    "h": "live-compliance.html",
    "s": "Live Compliance",
    "g": "Overview",
    "t": "Live Compliance (SAMA, IA, NCA, PDPL)",
    "d": "Pick a framework and see it graded live: coverage ring, domain bars and a tile per control coloured by the SIEM's evidence checks, with the crosswalk to the other frameworks and the dashboards that give evidence",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.4"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.2.2",
      "3.2.4"
     ]
    }
   },
   {
    "h": "compliance-map.html",
    "s": "Compliance Map",
    "g": "Overview",
    "t": "Compliance Map (SAMA, NCA, PDPL, IA)",
    "d": "Which dashboard supports which SAMA CSF, NCA ECC, PDPL and IA domain: domain-by-domain coverage, domains with no page, every page's tags, Excel export",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.4"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.2",
      "3.2.4"
     ]
    }
   },
   {
    "h": "gap-analysis.html",
    "s": "Gap Analysis - All Frameworks",
    "g": "Overview",
    "t": "Every open gap in SAMA, NCA ECC, ISO 27001, NDMO and PDPL, de-duplicated and prioritised",
    "d": "Every requirement not met in any framework register, merged through the crosswalk into work items that close gaps in several frameworks at once, priority itemised, owner and target date, not-assessed listed apart, daily trend and forecast to the target, send to GRC, Excel, and the AI compliance analyst",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {
    "h": "crosswalk.html",
    "s": "Framework Crosswalk",
    "g": "Overview",
    "t": "One control, several frameworks: SAMA, NCA ECC, ISO 27001, NDMO",
    "d": "NCA ECC as the hub with the SAMA CSF / IA requirements and ISO 27001 Annex A controls that rest on each control, statuses from each framework register, disagreements where one framework says met and another gap, mapping suggestions by machine learning confirmed by an administrator, and the AI compliance analyst",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {
    "h": "compliance-assistant.html",
    "s": "Compliance Assistant",
    "g": "Overview",
    "t": "Compliance Assistant - ask about SAMA, NCA ECC, ISO 27001, NDMO and PDPL in plain words",
    "d": "Ask in your own words (English or Arabic) - are we compliant, what to fix first, what a requirement means, why it is not met, what evidence an auditor accepts, who approves - and get a plain answer built from the registers themselves; machine learning on this server (naive Bayes for what the question asks, TF-IDF for which requirement it is about, a ranking for what to do first) with no external AI; a question it cannot match is not guessed; rated answers teach it, keeping only compliance words; a glossary of the terms and the five states; the same help as a side panel on every compliance page",
    "fw": {
     "sama": [
      "3.1.1"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.1.1"
     ]
    }
   },
   {
    "h": "sama-compliance.html",
    "s": "SAMA Compliance",
    "g": "SAMA & Insurance Authority",
    "t": "SAMA Compliance (CSF)",
    "d": "SAMA Cyber Security Framework coverage the SIEM can evidence from live data: coverage % by domain, per-control status (covered / partial / gap / GRC-owned), evidence checks, and a printable evidence report",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.3"
     ],
     "nca": [
      "1-7"
     ],
     "pdpl": [],
     "ia": [
      "3.2.2",
      "3.2.3"
     ]
    }
   },
   {"h": "sama-roadmap.html", "s": "SAMA CSF Assessment Roadmap", "g": "SAMA & Insurance Authority", "t": "SAMA CSF Assessment Roadmap - from the first day to assessed, remediated and re-assessed monthly", "d": "The whole SAMA Cyber Security Framework assessment in order - mobilise (CISO, committee, strategy, applicability of 3.3.12 / 3.3.13), discover (assets, risks), assess (every requirement recorded with evidence and approved by the CISO, maturity self-assessment), implement (maturity level 3, gaps to GRC actions, closure), train, operate (BCM drill, monthly re-assessment) and assure (independent audit) - each task measured from the SAMA module's own records, with owner, due date, next best actions, the critical path and a forecast finish date", "fw": {"sama": ["3.1", "3.2", "3.3", "3.4"]}, "k": ["sama roadmap", "sama csf assessment", "start to end", "implementation", "plan", "forecast"]},
   {
    "h": "sama-gap-start.html",
    "s": "Start a SAMA CSF Gap Assessment",
    "k": ["sama", "csf", "cyber security framework", "gap assessment", "gap analysis", "insurance authority", "ciso", "start"],
    "g": "SAMA & Insurance Authority",
    "t": "Start a SAMA CSF Gap Assessment - a guided path from the team and scope to the approved report",
    "d": "Step by step for the cybersecurity team: name the lead assessor, assessors and scope, send the kick-off with the standard SAMA CSF evidence requests per department across the four domains and the Insurance Authority cyber circular, take a baseline of the SAMA register (maturity against the target level, sources not connected shown as such), complete the requirement review on the SAMA register (each requirement verified by the platform or recorded by a person and approved by the CISO), rate every gap (likelihood x impact, root cause, recommendation, owner, target), publish the remediation plan to the GRC actions, then the lead signs and the CISO approves the report (four eyes) - each step says what is done and what blocks it",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.3"
     ],
     "nca": [],
     "pdpl": []
    }
   },
   {
    "h": "sama-ia.html",
    "s": "SAMA & IA Assessment",
    "k": ["sama csf", "insurance authority", "ia"],
    "g": "SAMA & Insurance Authority",
    "t": "SAMA CSF & Insurance Authority automated assessment",
    "d": "Every SAMA Cyber Security Framework requirement (4 domains, 32 subdomains) verified every day against its own evidence - GRC (policies, risk, attestations, control monitoring, audit findings), hardening (baseline coverage, critical failures, patching), pentest / VAPT (scans, cadence, exposed services) and SIEM logs (log sources, monitoring, retention) - on the same facts as NCA ECC and ISO 27001; indicative maturity per subdomain against level 3; a daily history that learns which requirements are likely to fail next, regressions and a 30-day forecast; the Insurance Authority view; manual evidence approved by the CISO; the AI Assessor drafts the report with read-only tools and the CISO approves it; gaps to GRC; export to CSV",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.4"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.2.2",
      "3.2.4"
     ]
    }
   },
   {
    "h": "sama-siem.html",
    "s": "SAMA coverage from SIEM evidence",
    "g": "SAMA & Insurance Authority",
    "t": "SAMA coverage from SIEM evidence - history, regressions, leverage, forecast and AI",
    "d": "Which SAMA CSF controls the SIEM evidences today from its own log sources, rules, retention and alerts: controls by domain, the daily history with regressions and flapping controls, the one check that moves most controls (gain in coverage points), quick wins, the forecast to the target, the printable evidence pack and a read-only AI compliance advisor",
    "fw": {
     "sama": [
      "3.3.14",
      "3.2.3"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.2.3"
     ]
    }
   },
   {
    "h": "ia-resilience.html",
    "s": "IA Cyber & Operational Resilience",
    "g": "SAMA & Insurance Authority",
    "t": "Insurance Authority: cyber baseline, incidents, third parties, DR and backup",
    "d": "The Insurance Authority cyber baseline (SAMA CSF plus the IA requirements) next to incident readiness, third parties, recoverability (DR drills, RTO / RPO, replication) and backup coverage; a matrix of critical systems with the weakest link of each; the chance each system passes its next drill; daily trend; the AI resilience advisor",
    "fw": {
     "sama": [
      "3.3.10",
      "3.3.7"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.10",
      "3.3.7"
     ]
    }
   },
   {
    "h": "ecc-studio.html",
    "s": "NCA ECC Compliance Studio",
    "g": "NCA ECC",
    "t": "NCA ECC Compliance Studio - domains, priorities, forecast and AI",
    "d": "The NCA Essential Cybersecurity Controls from the register's evidence: the 5 domains and 29 subdomains by NCA level, every control not met ranked by value with the kind of work (fix, connect, confirm, complete), leverage, regressions, the fully-compliant trend projected to the target date and a read-only AI compliance officer",
    "fw": {
     "sama": [
      "3.1.1",
      "3.2.4"
     ],
     "nca": [
      "1-1",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.2.4"
     ]
    }
   },
   {"h": "nca-roadmap.html", "s": "NCA ECC Assessment Roadmap", "g": "NCA ECC", "t": "NCA ECC Assessment Roadmap - from the first day to assessed and remediated", "d": "The whole NCA ECC-2:2024 assessment in order - mobilise (head of cybersecurity, independent function, strategy, steering committee, 4-2 / 5-1 applicability), discover (official control list, mapping, assets), assess (risks, every control recorded and approved), implement (gaps to GRC actions and their closure), train, operate (BCM drill) and assure (periodic review) - each task measured from the NCA ECC module's own records, with owner, due date, next best actions, the critical path and a forecast finish date", "fw": {"nca": ["1-1", "1-2", "1-3", "1-5", "1-8", "1-10", "2-1", "3-1"]}, "k": ["nca roadmap", "ecc assessment", "start to end", "implementation", "plan", "forecast"]},
   {
    "h": "nca-gap-start.html",
    "s": "Start an NCA ECC Gap Assessment",
    "k": ["ecc", "nca", "gap assessment", "gap analysis", "essential cybersecurity controls", "ciso", "evidence", "start"],
    "g": "NCA ECC",
    "t": "Start an NCA ECC Gap Assessment - a guided path from the team and scope to the approved report",
    "d": "Step by step for the cybersecurity team: name the lead assessor, assessors and scope, send the kick-off with the standard NCA ECC evidence requests per department across the five domains, take a baseline of the control register (sources not connected shown as such), complete the control review on the NCA ECC register (each control verified by the platform or recorded by a person and approved by the CISO), rate every gap (likelihood x impact, root cause, recommendation, owner, target), publish the remediation plan to the GRC actions, then the lead signs and the CISO approves the report (four eyes) - each step says what is done and what blocks it",
    "fw": {
     "sama": [
      "3.2.2"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": []
    }
   },
   {
    "h": "nca-ecc.html",
    "s": "NCA ECC Verification",
    "k": ["ecc", "essential cybersecurity controls", "nca"],
    "g": "NCA ECC",
    "t": "NCA ECC Verification",
    "d": "The NCA Essential Cybersecurity Controls (29 subdomains) verified automatically from the platform's registers and the SIEM: each control verified, a gap, or not measured with what to connect; manual controls recorded with evidence and approved by a second person; the official ECC list imported and mapped; gaps to GRC",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.3"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.2",
      "3.2.3"
     ]
    }
   },
   {
    "h": "iso-lifecycle.html",
    "s": "ISO 27001 Lifecycle",
    "g": "ISO 27001",
    "t": "ISO 27001 Lifecycle - implementation roadmap and certification cycle with ML and AI",
    "d": "The ISO/IEC 27001 journey judged from the register: nine PDCA phases with every criterion and its clause, the current phase, the certification cycle (Stage 1, Stage 2, certificate, surveillance, recertification) with the next audit due, the plan, a forecast to the 90 % Stage 2 threshold and a read-only AI implementation coach",
    "fw": {
     "sama": [
      "3.1.1",
      "3.2.5"
     ],
     "nca": [
      "1-1",
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.2.5"
     ]
    }
   },
   {"h": "iso-roadmap.html", "s": "ISO 27001 ISMS Roadmap", "g": "ISO 27001", "t": "ISO/IEC 27001:2022 ISMS Implementation Roadmap - from the first day to certified", "d": "The whole ISMS implementation in order - leadership and ISMS manager, context, scope, policy (clauses 4-5), risk method, assets, risk assessment and treatment, Statement of Applicability (6, 8), objectives, the 93 Annex A controls recorded and approved, awareness (7), operation and measurement (8, 9.1), internal audit, nonconformities, management review (9.2, 9.3, 10) and the Stage 1 / Stage 2 certification audit - each task measured from the ISO 27001 modules' own records, with owner, due date, next best actions, the critical path and a forecast finish date", "fw": {"iso": ["4.3", "5.2", "6.1.2", "6.1.3", "9.2", "9.3", "10.2"]}, "k": ["isms roadmap", "iso implementation", "start to end", "certification", "plan", "forecast"]},
   {
    "h": "iso-gap-start.html",
    "s": "Start an ISO 27001 Gap Assessment",
    "k": ["iso", "27001", "isms", "gap assessment", "gap analysis", "annex a", "certification readiness", "start"],
    "g": "ISO 27001",
    "t": "Start an ISO 27001 Gap Assessment - a guided path from the team and scope to the approved report",
    "d": "Step by step for the ISMS team: name the lead assessor, assessors and the ISMS scope, send the kick-off with the documented information ISO/IEC 27001:2022 requires and the key Annex A records per department, take a baseline of the ISMS register (Statement of Applicability, sources not connected shown as such), complete the clause and control review on the ISO 27001 register (each item verified by the platform or recorded by a person and approved by the ISMS manager), rate every gap (likelihood x impact, root cause, recommendation, owner, target), publish the remediation plan to the GRC actions, then the lead signs and the ISMS manager approves the report (four eyes) - each step says what is done and what blocks it",
    "fw": {
     "sama": [
      "3.1.3"
     ],
     "nca": [
      "1-7"
     ],
     "pdpl": []
    }
   },
   {
    "h": "iso27001.html",
    "s": "ISO 27001 ISMS",
    "g": "ISO 27001",
    "t": "ISO/IEC 27001:2022 ISMS (automated register, audit programme, SoA)",
    "d": "Clauses 4-10 and the 93 Annex A controls checked from the platform's own evidence (the same checks as NCA ECC, so nothing is collected twice; an approved NCA ECC confirmation counts here too), the Statement of Applicability with four-eyes approval, the internal audit programme planned risk-first with working papers prepared automatically, nonconformities and corrective action verified by another person, the management review pack, certification readiness",
    "fw": {
     "sama": [
      "3.2.4"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.2.4"
     ]
    }
   },
   {
    "h": "security-controls.html",
    "s": "Security Controls → Compliance",
    "g": "Controls & evidence",
    "t": "Security Controls → Compliance - live controls and the requirements they evidence",
    "d": "The technical controls the platform measures (asset register, critical patches, backups, virtualization, roles, policy reviews) with their state, daily history and regressions, every framework requirement each one evidences through the crosswalk, leverage of failing controls, GRC actions raised by a person and a read-only AI advisor",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.17"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.3.17"
     ]
    }
   },
   {
    "h": "control-validation.html",
    "s": "Control Validation",
    "g": "Controls & evidence",
    "t": "Control Validation - cross-framework disagreements and claim vs measurement",
    "d": "Crosswalk lines where one framework says fully met and another not met, SAMA CSF controls attested as followed while the platform measures them failing, consistency score, how far each framework's self-assessment holds (Beta), new findings since yesterday, resolution actions raised by a person and a read-only AI advisor",
    "fw": {
     "sama": [
      "3.2.3",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.3",
      "3.2.4"
     ]
    }
   },
   {
    "h": "continuous-compliance.html",
    "s": "Continuous Compliance & Auto-Remediation",
    "g": "Controls & evidence",
    "t": "Continuous Compliance & Auto-Remediation - daily drift and automatic tracking",
    "d": "Every framework's fully-met share today against yesterday, new drift and resolved gaps from the daily snapshot, time to fix learned per severity, the projection per framework, automatic GRC tracking actions for new drift (an administrator's setting, never a change to a system), actions raised by a person and a read-only AI advisor",
    "fw": {
     "sama": [
      "3.2.4",
      "3.2.3"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.4",
      "3.2.3"
     ]
    }
   },
   {
    "h": "compliance-docs.html",
    "s": "Compliance Documents & Evidence",
    "g": "Controls & evidence",
    "t": "Compliance Documents & Evidence - freshness, renewal wave, coverage and renewals",
    "d": "The evidence register and the policy register: current / due / stale evidence with its file hash, the renewal wave by month, coverage per framework, files reused across controls, renewal lateness learned per owner, renewal actions raised by a person and a read-only AI advisor",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.4"
     ],
     "nca": [
      "1-3"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.4"
     ]
    }
   },
   {
    "h": "evidence-custody.html",
    "s": "Evidence & Chain of Custody",
    "g": "Controls & evidence",
    "t": "Evidence & Chain of Custody - integrity, custody trail and a chained ledger",
    "d": "Every evidence file re-hashed against its recorded SHA-256 (verified, mismatch, missing, link), its custody trail from the record history and the audit log (received, downloaded, retired), a daily hash-chained ledger that catches a recorded hash changed after recording, the audit-log chain, verify-now by a person and a read-only AI custodian",
    "fw": {
     "sama": [
      "3.3.14",
      "3.2.4"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.2.4"
     ]
    }
   },
   {
    "h": "bcm-matrix.html",
    "s": "Business Continuity & DR Matrix",
    "g": "Controls & evidence",
    "t": "Business Continuity & DR Matrix - tests, RTO / RPO, replication and readiness",
    "d": "Every recoverable system from the DR & BCM drills and DR Studio replication: last test and result, RTO / RPO achieved vs target, sign-off, replication lag vs RPO, readiness itemised over what is measured (untested is never ready), the chance the next test passes, RTO worsening across tests, test actions raised by a person and a read-only AI advisor",
    "fw": {
     "sama": [
      "3.3.8",
      "3.4.2"
     ],
     "nca": [
      "2-9"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.4.2"
     ]
    }
   },
   {
    "h": "framework-library.html",
    "s": "Regulatory Framework Library",
    "g": "Framework library",
    "t": "Regulatory Framework Library - every requirement held, mapped and searchable",
    "d": "The frameworks held in the platform's registers (NCA ECC, SAMA CSF, ISO 27001, NDMO, PDPL) with requirement / assessed / mapped counts, every requirement in one searchable table with its level and NCA ECC mapping, title-similarity mapping suggestions an administrator confirms, and a read-only AI librarian",
    "fw": {
     "sama": [
      "3.1.2"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [],
     "ia": [
      "3.1.2"
     ]
    }
   },
   {
    "h": "frameworks-x.html",
    "s": "SOC 2 & ISO 42001",
    "g": "Framework library",
    "t": "SOC 2 & ISO 42001 readiness - voluntary assurance frameworks mapped to NCA ECC",
    "d": "SOC 2 Trust Services Criteria (Security plus the categories you choose) and ISO/IEC 42001 AI management system clauses and Annex A: each item derived from the NCA ECC controls it maps to, not assessed until evidence exists, confirmed with evidence and approved by a second person, exported as a readiness sheet - readiness only, never an attestation or a certificate",
    "fw": {
     "sama": [
      "3.1.2"
     ],
     "nca": [
      "1-7"
     ],
     "pdpl": [],
     "ia": [
      "3.1.2"
     ]
    }
   },
   {
    "h": "maturity-level.html",
    "s": "Cybersecurity Maturity Level",
    "g": "Framework library",
    "t": "Cybersecurity Maturity Level - SAMA CSF maturity by domain and subdomain",
    "d": "The indicative SAMA CSF maturity (L0-L5) of every subdomain from the automated assessment with why, not rated when there is no evidence, domain means over rated subdomains, the gap to the target level and the next step, movement over 30 days, the projection to target and a read-only AI maturity advisor",
    "fw": {
     "sama": [
      "3.1.1",
      "3.2.1"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.2.1"
     ]
    }
   }
  ]
 },
 {
  "id": "pdpl",
  "sn": "Data Privacy",
  "name": "Personal Data Protection & Data Management (PDPL · NDMO)",
  "c": "#2dd4bf",
  "hd": "privacy",
  "icon": "<path d=\"M12 3l8 4v5c0 5-3.5 8-8 9c-4.5-1-8-4-8-9V7z\"/><rect x=\"9\" y=\"11\" width=\"6\" height=\"5\" rx=\"1\"/><path d=\"M10 11V9a2 2 0 0 1 4 0v2\"/>",
  "pages": [
   {"h": "pdpl-group.html", "s": "Group Companies", "t": "PDPL Group Companies - the group companies whose data this organisation processes, their agreements and breach notices", "d": "Each group company this organisation processes personal data for: the data processing agreement (terms, expiry, acceptance by the DPO, four-eyes), the RoPA activities run for it, and breach notices to it within the agreed hours", "fw": {"pdpl": ["8", "20"]}, "k": ["pdpl", "group", "processor", "controller", "dpa", "data processing agreement", "breach", "subsidiary"]},
   {
    "h": "pdpl-roadmap.html",
    "s": "PDPL Implementation Roadmap",
    "g": "Overview",
    "t": "PDPL Implementation Roadmap - from the first day to compliant and kept compliant",
    "d": "The whole PDPL implementation in order - mobilise (DPO, SDAIA registration, committee, privacy notice), discover (personal data, catalogue, records of processing, sensitive data, processors, transfers), assess (self-assessment, DPIA, processor and transfer risk), implement (consent, data subject requests, retention, breach procedure, access reviews), train, operate and assure (signed statement) - each task measured from the PDPL modules' own records, with owner, due date, next best actions, the critical path and a forecast finish date",
    "fw": {
     "pdpl": [
      "Art. 4",
      "Art. 8",
      "Art. 18",
      "Art. 20",
      "Art. 22",
      "Art. 29",
      "Art. 30"
     ],
     "sama": [
      "3.3.11"
     ],
     "nca": [
      "2-7"
     ]
    },
    "k": [
     "roadmap",
     "implementation",
     "start to end",
     "plan",
     "forecast"
    ]
   },
   {
    "h": "pdpl-dashboard.html",
    "s": "PDPL & NDMO Dashboard",
    "t": "PDPL & NDMO Dashboard",
    "d": "One colourful overview of PDPL and NDMO: compliance and maturity scores, requirements by result and area, the 15 NDMO domains, data subject requests against their 30 days, breaches against 72 hours, vendor risk tiers, cross-border transfers and the Privacy Office work queue",
    "fw": {
     "sama": [
      "3.3.11",
      "3.1.4"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 4",
      "Art. 8",
      "Art. 20",
      "Art. 29"
     ],
     "ia": [
      "3.3.11",
      "3.1.4"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "privacy-cockpit.html",
    "s": "Privacy Cockpit",
    "t": "Privacy Cockpit - every PDPL clock, requests at risk, the riskiest processing activities",
    "d": "One view over every PDPL register: every legal clock most urgent first (breaches to SDAIA in 72 hours and to the other regulators, data subject requests in 30 days, missing or outdated impact assessments, transfers without a signed assessment, vendor reviews, retention), the requests most likely to miss their deadline (Kaplan-Meier survival of the handling time, or a stated rule with little history), the request volume forecast, an explainable risk score per processing activity with a heat map, and an AI-drafted DPO weekly briefing to verify",
    "fw": {
     "sama": [
      "3.3.11"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 4",
      "Art. 20",
      "Art. 22"
     ],
     "ia": [
      "3.3.11"
     ]
    }
   },
   {
    "h": "pdpl-flow.html",
    "s": "PDPL Automation Flow",
    "g": "Overview",
    "t": "PDPL Automation Flow - how the PDPL work runs on the platform, live",
    "d": "Data discovery -> records of processing -> DPIA, transfers and processors -> consent -> data subject requests (30-day clock) and breaches (72-hour clock) -> control monitor -> Privacy Office tasks -> verified closed; per stage the count, the items stuck oldest first with owner and age, the median cycle time, the bottleneck and escalations",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.3"
     ]
    }
   },
   {
    "h": "pdpl-gap-start.html",
    "s": "Start a PDPL Gap Assessment",
    "t": "Start a PDPL Gap Assessment - a guided path from the team and scope to the approved report",
    "d": "Step by step for the PDPL team: name the lead assessor, assessors and scope (departments, systems), send the kick-off with the standard PDPL evidence requests per department, take a baseline of the PDPL registers, answer the 40-question self-assessment approved by the DPO, rate every gap (likelihood x impact, root cause, recommendation, owner, target), publish the remediation plan to the GRC actions, then the lead signs and the DPO approves the report (four eyes) - each step says what is done and what blocks it",
    "fw": {
     "sama": [
      "3.1.3"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [
      "Art. 19",
      "IR Art. 32",
      "IR Art. 33"
     ]
    },
    "g": "Overview",
    "k": ["pdpl", "gap assessment", "gap analysis", "implementation", "readiness", "start", "dpo", "evidence"]
   },
   {
    "h": "pdpl-programme.html",
    "s": "PDPL Programme",
    "t": "PDPL Programme",
    "d": "Controller obligations with what the registers show and the penalty each carries, departments with their data stewards and team playbooks, training, and the four-area maturity assessment (mapping, consent, people, audit readiness)",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "IR Art. 32",
      "Art. 35",
      "Art. 36"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "pdpl-governance.html",
    "s": "PDPL Governance",
    "t": "PDPL Governance",
    "d": "The DPO's reporting line and authority, a named person for each PDPL function, the data protection committee (quarterly; legal, IT, HR, operations), privacy-by-design reviews decided by the DPO before go-live, and the yearly programme review with remediation actions closed on evidence",
    "fw": {
     "sama": [
      "3.1.1",
      "3.1.3"
     ],
     "nca": [
      "1-2",
      "1-3"
     ],
     "pdpl": [
      "IR Art. 32",
      "Art. 19",
      "Art. 22"
     ],
     "ia": [
      "3.1.1",
      "3.1.3"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "pdpl-assessment.html",
    "s": "PDPL Self-Assessment",
    "t": "PDPL Self-Assessment",
    "d": "Guided PDPL assessment: 40 questions over the 24 requirements with the Law / Implementing Regulation article, evidence per answer, suggestions from the registers, chapter scores, four-eyes approval by the DPO, gaps sent to the GRC register",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [
      "Art. 4",
      "Art. 19",
      "Art. 20",
      "Art. 22",
      "Art. 29"
     ],
     "ia": [
      "3.1.3",
      "3.2.4"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "pdpl-monitor.html",
    "s": "PDPL Control Monitor",
    "t": "PDPL Control Monitor",
    "d": "Continuous tests of every system holding personal data (classification, CIA, end of life, owner, EDR, patching, backup, vulnerability scans, SIEM logs, retention) from the asset register and Asset Coverage, drift alerts, gaps to GRC, staff policy acknowledgement campaigns and a hashed evidence pack",
    "k": ["cyberarrow", "continuous control monitoring", "automated evidence", "policy acknowledgement", "staff attestation", "drift", "technical controls"],
    "fw": {
     "sama": [
      "3.1.3",
      "3.3.5"
     ],
     "nca": [
      "1-8",
      "2-7"
     ],
     "pdpl": [
      "Art. 18",
      "Art. 19",
      "Art. 20"
     ],
     "ia": [
      "3.1.3",
      "3.3.5"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "pdpl-studio.html",
    "s": "PDPL Studio",
    "t": "PDPL Studio - compliance by area, biggest gains, lapsing confirmations, learning",
    "d": "The PDPL register as an intelligence view: compliance per area with movement against 30 days ago, the requirements that add the most for one action (DPO confirmations of automated passes first), confirmations lapsing within 60 days, every requirement with why, evidence and history, requirements likely to fail next (learned from the daily history), regressions, statement readiness, projection to 90 %, read-only AI privacy advisor",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 22"
     ],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "pdpl-intel.html",
    "s": "PDPL Intelligence",
    "t": "PDPL Intelligence (learned column review, deadline risk, DPIA drafts)",
    "d": "A column model that learns from your reviews which discovered columns really hold personal data and asks about the least certain first; the chance of answering each data subject request within 30 days from your own history and the 72-hour SDAIA clock for breaches; impact assessment drafts (rules or AI) for activities that need one, approved by the DPO - people decide",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 4",
      "Art. 20",
      "Art. 22"
     ],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Overview"
   },
   {
    "h": "pdpl-policies.html",
    "s": "PDPL Policies",
    "t": "PDPL Policies",
    "d": "The policy set PDPL expects - data protection policy, privacy notice, consent, data subject rights, retention, breach notification, DPIA, transfers, processors, sensitive data, records of processing, marketing, DPO charter, training, privacy by design - approved, in review, draft or missing, with what each must cover and a draft started on GRC Policies",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.2"
     ],
     "nca": [
      "1-3",
      "1-7"
     ],
     "pdpl": [
      "Art. 5",
      "Art. 19",
      "IR Art. 32"
     ],
     "ia": [
      "3.1.3",
      "3.2.2"
     ]
    },
    "g": "Registers"
   },
   {
    "h": "pdpl-ropa.html",
    "s": "Records of Processing",
    "t": "Records of Processing (RoPA)",
    "d": "Every processing activity with purpose, legal basis, data categories, systems, retention and owner; completeness, links to DPIA, transfers, retention rules, consent and sensitive controls; export for SDAIA",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "IR Art. 33",
      "Art. 11",
      "Art. 18"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Registers"
   },
   {
    "h": "pdpl-ropa-collect.html",
    "s": "RoPA by Department",
    "t": "RoPA by Department",
    "d": "The records of processing collected department by department: each data steward describes the processing from templates and from what the Data Catalog found, checked as it is written, approved by the DPO into the register (Art. 33)",
    "fw": {
     "sama": [
      "3.1.3"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [
      "Art. 31",
      "IR Art. 33"
     ],
     "ia": [
      "3.1.3"
     ]
    },
    "g": "Registers"
   },
   {
    "h": "pdpl-catalog.html",
    "s": "Data Catalog",
    "t": "Data Catalog",
    "d": "Personal data found in every Oracle, SQL Server and PostgreSQL database with a read-only login - by attribute, source and column; identifier columns that let a verified data subject request find the person everywhere",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 4",
      "Art. 31"
     ],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Registers"
   },
   {
    "h": "pdpl-processors.html",
    "s": "Processor Management",
    "t": "Processor Management",
    "d": "Processors with their agreement and PDPL clauses, the scored due-diligence questionnaire, 12-month review, and sub-processors approved in advance by the DPO",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "Art. 8"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Registers"
   },
   {
    "h": "pdpl-transfers.html",
    "s": "Cross-Border Transfers",
    "t": "Cross-Border Transfers",
    "d": "Transfers outside the Kingdom with purpose and basis, the transfer impact assessment (Cross-Border Transfer Regulation Art. 8) scored and signed by the DPO, and what must happen before the transfer",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "Art. 29"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Registers"
   },
   {
    "h": "pdpl-sensitive.html",
    "s": "Sensitive Data Controls",
    "t": "Sensitive Data Controls",
    "d": "Health, credit, biometric and other sensitive data: explicit consent, access tiers, encryption, masking outside production, logged access, access review, DPIA, CHI health and credit-disclosure rules",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "Art. 23",
      "Art. 24",
      "Art. 19"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Operations"
   },
   {
    "h": "pdpl-access.html",
    "s": "Access Intelligence",
    "t": "Access Intelligence",
    "d": "Who opened which claim, medical or fraud record and why - sent by the business systems; policy hits (no purpose, no case reference, sensitive exports, deletions) and unusual volumes reviewed by a different person",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 23"
     ],
     "ia": [
      "3.3.5"
     ]
    },
    "g": "Operations"
   },
   {
    "h": "pdpl-dsar.html",
    "s": "Data Subject Requests",
    "t": "Data Subject Requests (DSAR)",
    "d": "Requests recorded by staff (reference only): identity verified, every system worked, the 30-day clock with one notified extension, refusal on an allowed ground by the DPO, answer letter in Arabic and English",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "Art. 4",
      "Art. 5",
      "Art. 17"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Operations"
   },
   {
    "h": "pdpl-dpia.html",
    "s": "Impact Assessments (DPIA)",
    "t": "Data Protection Impact Assessment",
    "d": "Which activities need an assessment and why, the scored questionnaire with measures, and the DPO's four-eyes signature; out-of-date assessments flagged",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "Art. 22"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Operations"
   },
   {
    "h": "pdpl-breach.html",
    "s": "Breach Response",
    "t": "Breach Response",
    "d": "The 72-hour SDAIA clock and the playbook - contain, assess, notify SDAIA, notify data subjects, remediate, lessons learned - with every step stamped; opened from a SIEM incident",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.2.2",
      "3.3.3"
     ]
    },
    "g": "Operations"
   },
   {
    "h": "pdpl-office.html",
    "s": "Privacy Office",
    "t": "Privacy Office",
    "d": "PDPL as its own organisation: DPO, privacy committee, function owners, data stewards and champions; every finding and recurring duty routed to a named person with a deadline and escalation; the live route map from implementation to maintenance",
    "fw": {
     "sama": [
      "3.1.1"
     ],
     "nca": [
      "1-1"
     ],
     "pdpl": [
      "IR Art. 32"
     ],
     "ia": [
      "3.1.1"
     ]
    },
    "g": "Operations"
   },
   {
    "h": "pdpl-retention.html",
    "s": "Retention Enforcement",
    "g": "Operations",
    "t": "Retention Enforcement - rows past their retention period counted read-only, disposals attested and verified",
    "d": "Retention rules mapped to tables, a monthly read-only count of the rows past retention (counts only, never the data), a disposal task for the data owner, acceptance by the DPO and verification by the next scan; legal holds approved by a second person",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 18"
     ],
     "ia": [
      "3.3.3"
     ]
    }
   },
   {
    "h": "ndmo-studio.html",
    "s": "NDMO Studio",
    "t": "NDMO Studio - score, maturity, biggest gains, learning",
    "d": "The NDMO Data Management and Personal Data Protection register as an intelligence view: score and indicative maturity per domain with movement against 30 days ago, the controls that add the most score for one action (approvals waiting first), every control with why and its history, controls likely to fail next (learned from the register's daily history), regressions, official NDMO list coverage, projection to 80 %, gaps to GRC in one click, read-only AI data management advisor",
    "fw": {
     "sama": [
      "3.1.1",
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 31"
     ],
     "ia": [
      "3.1.1",
      "3.3.3"
     ]
    },
    "g": "Data management (NDMO)"
   },
   {
    "h": "ndmo-roadmap.html",
    "s": "NDMO Implementation Roadmap",
    "g": "Overview",
    "t": "NDMO Implementation Roadmap - from the first day to compliant and kept compliant",
    "d": "The NDMO standards in order - Chief Data Officer, Data Management Office, strategy, committee and applicability; the official control list and its mapping; catalogue and classification; every control recorded and approved by a second person; the PDPL domain, data lifecycle and quality; gaps to GRC actions and the annual review - measured from the NDMO and PDPL registers, with owner, due date, next best actions, the critical path and a forecast finish date",
    "fw": {
     "pdpl": [
      "Art. 30"
     ],
     "sama": [
      "3.1.4"
     ],
     "nca": [
      "2-7"
     ]
    },
    "k": [
     "roadmap",
     "implementation",
     "start to end",
     "plan",
     "forecast"
    ]
   },
   {
    "h": "ndmo-gap-start.html",
    "s": "Start an NDMO Gap Assessment",
    "k": ["ndmo", "data management", "data governance", "gap assessment", "gap analysis", "cdo", "sdaia", "start"],
    "g": "Data management (NDMO)",
    "t": "Start an NDMO Gap Assessment - a guided path from the team and scope to the approved report",
    "d": "Step by step for the data management team: name the lead assessor, assessors and scope, send the kick-off with the standard NDMO evidence requests per department across the 15 data management domains, take a baseline of the NDMO register (maturity per domain, the Chief Data Officer, official controls mapped), complete the control review on the NDMO register (each control passed by the platform or recorded by a person and approved by the Chief Data Officer), rate every gap (likelihood x impact, root cause, recommendation, owner, target), publish the remediation plan to the GRC actions, then the lead signs and the Chief Data Officer approves the report (four eyes) - each step says what is done and what blocks it",
    "fw": {
     "sama": [],
     "nca": [],
     "pdpl": [
      "Art. 19"
     ]
    }
   },
   {
    "h": "ndmo.html",
    "s": "NDMO Data Management",
    "t": "NDMO Data Management",
    "d": "The 15 NDMO data management domains as {{org.short}}'s register: controls checked against the PDPL registers, the Data Catalog, the GRC policies, database monitoring and backups; maturity by domain; the official NDMO control list imported and mapped; gaps to GRC; the Personal Data Protection domain read from PDPL",
    "fw": {
     "sama": [
      "3.1.1",
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 31"
     ],
     "ia": [
      "3.1.1",
      "3.3.3"
     ]
    },
    "g": "Data management (NDMO)"
   }
  ]
 },
 {
  "id": "aud",
  "sn": "Audit",
  "name": "Audit & Assurance",
  "c": "#f59e0b",
  "hd": "audit",
  "icon": "<path d=\"M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2\"/><rect x=\"9\" y=\"3\" width=\"6\" height=\"4\" rx=\"1\"/><path d=\"m9 14 2 2 4-4\"/>",
  "pages": [
   {
    "h": "audit-dashboard.html",
    "s": "Audit Dashboard",
    "g": "Overview",
    "t": "Audit Dashboard (for auditors)",
    "d": "For internal and external auditors: PDPL, NCA ECC, NDMO, SAMA CSF and Insurance Authority status from the registers, evidence requests, the AI audit programmes and the three audit teams on one page - every figure linked to its evidence, export to CSV",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [
      "Art. 31"
     ],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    }
   },
   {
    "h": "audit-command.html",
    "s": "Audit Command Center",
    "g": "Overview",
    "t": "Audit Command Center - audit use cases, automation and machine learning",
    "d": "21 audit use cases (leavers, joiners, privileged access, changes, access reviews, service accounts, end-of-life exceptions, assets, risks, actions, DSRs, breaches, contracts) tested on every record; findings drafted for an auditor to accept; overdue audit work followed up and escalated; slip forecast, repeat findings and the AI audit advisor",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [
      "Art. 31"
     ],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    }
   },
   {
    "h": "audit-flow.html",
    "s": "Audit Automation Flow",
    "g": "Overview",
    "t": "Audit Automation Flow - how the audit work runs on the platform, live",
    "d": "Sources -> use-case tests -> continuous control monitoring and analytics -> proposed findings -> accepted into engagements (IT / Cyber / Internal Audit Teams) -> owners and action plans -> re-test -> closed, with evidence requests, department attestations and escalations; per stage the count, the items stuck oldest first with owner and age, the median cycle time and the bottleneck",
    "fw": {
     "sama": [
      "3.3.15"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.15"
     ]
    }
   },
   {
    "h": "audit-ccm.html",
    "s": "Control Monitoring",
    "g": "Overview",
    "t": "Continuous Control Monitoring (whole audit trail, tested daily)",
    "d": "Every record of the platform audit trail for the last 30 days tested every day against eight controls - segregation of duties, approvals by a person, after-hours administrator changes and unusual change volumes (statistics against each person's own history), personal-data reads against peers, trail integrity, self-granted roles, credential settings - exceptions explained by an auditor or drafted into a finding (rules or AI) accepted into an audit engagement; indicators, not proof; export to CSV",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "2-2",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.14"
     ]
    }
   },
   {
    "h": "audit-analytics.html",
    "s": "Audit Analytics",
    "g": "Overview",
    "t": "Audit Analytics (data analytics workbench - duplicates, Benford, gaps, sampling)",
    "d": "Analyse whole populations - the platform's own records (assets, licences, contracts, GRC, joiners, leavers, privileged access, the audit trail) or an imported CSV (payments, claims, vendor master): column profile and suggested tests, duplicates, fuzzy duplicates, gaps in sequences, Benford's law, stratify, ageing, summarize, outliers by peer group, join / unmatched, filters, attribute sample sizes (binomial), seeded random and monetary-unit samples; a hashed, re-performable command log, four-eyes review, exception dispositions, findings raised into audit engagements, scripts scheduled after a second person's approval, read-only AI advisor; indicators, not proof",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.14"
     ]
    }
   },
   {
    "h": "audit-repo.html",
    "s": "Audit Repository",
    "g": "Overview",
    "t": "Audit Repository (previous years - SAMA, IA, NCA, external, internal)",
    "d": "Every past audit and inspection year by year - SAMA, Insurance Authority, NCA, SDAIA, CMA, the external auditor, internal audit, certification bodies - with the report files kept on this server and their findings imported from the management letter in Excel; repeat findings proposed against earlier years (words, area, controls) for a person to confirm; findings by year and body, smoothed closure rates, median days to close, carried-forward and overdue findings, systemic areas over 3+ years, late-closure risk, GRC remediation actions, Excel export, read-only AI advisor",
    "fw": {
     "sama": [
      "3.1.5",
      "3.3.14"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.1.5",
      "3.3.14"
     ]
    }
   },
   {
    "h": "dept-checklist.html",
    "s": "Department Checklist",
    "g": "Overview",
    "t": "Department Checklist (framework obligations per department)",
    "d": "What each department (HR, IT, Cyber Security, GRC, Data Protection, Data Management, Legal, Procurement, Facilities, Finance, Underwriting, Claims, Customer Service, Marketing) must keep doing every month, quarter, half or year for SAMA CSF, NCA ECC, PDPL, NDMO and the Insurance Authority - attested by the department head with the evidence reference, verified by an independent auditor, overdue when a period passes unattested; percentages per department and framework, export to CSV",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.4"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.2.2",
      "3.2.4"
     ]
    }
   },
   {
    "h": "nca-it-audit.html",
    "s": "NCA IT Audit",
    "g": "Regulator audits",
    "t": "NCA IT Audit - plan, procedures, requests, action plans, analytics",
    "d": "The IT and Cyber Security audit teams' engagements by phase with a slip forecast learned from past engagements, procedure status, NCA evidence requests, action plans by priority with the chance each is implemented late, NCA ECC audit coverage ranked by what to audit next (weakness x time since audited), full-population data analytics (duplicate serials, audit-trail chain, Benford's law on costs, segregation of duties in the audit work), daily trend, read-only AI audit advisor",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    }
   },
   {
    "h": "sama-it-audit.html",
    "s": "SAMA IT Audit",
    "t": "SAMA IT Audit - readiness from the platform's evidence",
    "d": "Governance, cyber risk, data protection, incident response, BC/DR and the audit process checked against live evidence; weighted readiness per area with its trend; draft findings sent into an IT Audit engagement; regulator-ready pack",
    "fw": {
     "sama": [
      "3.1.6",
      "3.3.8",
      "BCM"
     ],
     "nca": [
      "1-8",
      "2-10"
     ],
     "pdpl": [
      "Art. 20"
     ],
     "ia": [
      "3.1.6",
      "3.3.8",
      "BCM"
     ]
    },
    "g": "Regulator audits"
   },
   {
    "h": "sama-audit.html",
    "s": "SAMA CSF Audit",
    "g": "Regulator audits",
    "t": "SAMA CSF audit: implementation by domain and gap remediation",
    "d": "The audit of {{org.short}} against the SAMA Cyber Security Framework and the Insurance Authority items, on the automated assessment: implemented / not implemented / not applicable and the rate per domain; the gap remediation tracker - owner, due date by severity, plan, history, closure with the evidence relied on confirmed by the CISO or an administrator who did not request it (four eyes); closed-but-not-verified and regressed-after-closure shown, never counted as implemented; machine learning forecasts when the last gap closes and which gaps will miss their due date; the AI internal auditor drafts the audit memo with read-only tools and the CISO approves it; the audit sheet in Excel",
    "fw": {
     "sama": [
      "3.2.2",
      "3.2.4"
     ],
     "nca": [
      "1-7",
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.2.2",
      "3.2.4"
     ]
    }
   },
   {
    "h": "audit-start.html",
    "s": "Start an Audit",
    "g": "Audit teams",
    "t": "Start an Audit - a guided path from the audit team to the approved report",
    "d": "Step by step for the IT, Cyber Security and Internal Audit teams: name the Head of Audit and auditors, propose and approve the risk-based annual plan, open the engagement (independence checked), start fieldwork, draw samples from real records and conclude each item against the platform's suggested tests, write and review workpapers, raise and issue findings, write the executive summary (AI draft optional), sign and approve the final report - each step says what is done and what blocks it",
    "fw": {
     "sama": [
      "3.2.5"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.5"
     ]
    }
   },
   {
    "h": "internal-audit-team.html",
    "s": "Internal Audit Team",
    "g": "Audit teams",
    "t": "Internal Audit Team (AI Internal Auditor)",
    "d": "Risk-based internal audit plan over the insurer's business (underwriting, claims, reinsurance, reserves, finance, procurement, HR, AML, fraud, conduct, compliance, PDPL, governance), engagements, sampling from data subject requests, breaches, vendor contracts, joiners and leavers, workpapers, findings and follow-up, signed reports, morning brief, ask the auditor",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [
      "Art. 31"
     ],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    }
   },
   {
    "h": "audit-inspections.html",
    "s": "IT Audit Inspections",
    "k": ["inspection", "checklist", "site audit", "walkthrough", "goaudits", "audit now", "corrective action", "capa", "signature", "photo evidence", "exception", "risk acceptance", "branch audit", "data centre audit"],
    "t": "IT Audit Inspections - scored on-site checklists with photo evidence, signatures, corrective actions, exceptions, schedules and site trends",
    "d": "Run an on-site IT audit checklist (data centre, branch, backups, endpoints, network closet, claims system access, third parties, customer data) on a laptop or tablet: yes / no, ratings, ranges, photos with time and location, the inspector's and the site representative's signatures; weighted score with critical items; corrective actions with likelihood x impact risk, fixed by the owner and verified by a different person; risk acceptance with an expiry decided by another administrator; recurring schedules; site trends, forecast and repeat failures; a branded report frozen and hashed when it closes; AI drafts a checklist from a described scope, a person saves it",
    "fw": {
     "sama": [
      "3.1.3",
      "3.2.1"
     ],
     "nca": [
      "1-8",
      "2-14"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3",
      "3.2.1"
     ]
    },
    "g": "Audit teams"
   },
   {
    "h": "audit-team.html",
    "s": "IT Audit Team",
    "g": "Audit teams",
    "t": "IT Audit Team (AI IT Auditor)",
    "d": "Risk-based annual audit plan, engagements, sampling from real records, workpapers, findings and follow-up, signed reports, morning brief, ask the auditor",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    }
   },
   {
    "h": "cyber-audit-team.html",
    "s": "Cyber Security Audit Team",
    "g": "Audit teams",
    "t": "Cyber Security Audit Team (AI Cyber Security Auditor)",
    "d": "Risk-based cyber security audit plan over the NCA ECC / SAMA CSF universe, engagements, sampling from privileged access, access reviews, service accounts, end-of-life exceptions and leavers, workpapers, findings and follow-up, signed reports, morning brief, ask the auditor",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    }
   },
   {
    "h": "audit-reports.html",
    "s": "Audit Reports",
    "g": "Audit teams",
    "t": "Audit Reports - engagement reports drafted from the audit records, signed and issued",
    "d": "Engagement reports drafted from the audit records: scope, procedures, samples, findings with management response, overall rating by a stated rule; optional AI summary as a proposal; the lead signs, an administrator outside the team issues it, frozen with a SHA-256 fingerprint; print and Excel",
    "fw": {
     "sama": [
      "3.3.15"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.15"
     ]
    }
   },
   {
    "h": "ad-audit.html",
    "s": "AD Audit",
    "t": "Active Directory Audit",
    "d": "Findings an auditor asks for first: privileged accounts, passwords that never expire or are not required, Kerberos pre-auth off, delegation, dormant and never-used accounts, admin-group changes, lockouts, log clearing; CSV and printable report",
    "fw": {
     "sama": [
      "3.3.5",
      "3.2.5"
     ],
     "nca": [
      "2-2",
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.2.5"
     ]
    },
    "g": "Technical audits"
   },
   {
    "h": "network-config-audit.html",
    "s": "Network Config Audit",
    "t": "Network Configuration Audit (Cisco switches / routers and firewalls)",
    "d": "Cisco IOS switches and routers against CIS Cisco IOS level 1 (central AAA, SSH v2 and no Telnet, enable secret and password encryption, no SNMP read-write community, HTTP server off, syslog, NTP, banner), FortiGate / Palo Alto / Cisco ASA rule bases and management access, expired subscriptions, firewalls that cannot be reviewed or have had no check in 48 hours, and change control - every check with its standard, every device with the lines that failed; a configuration that cannot be read is not tested, never passed; daily trend, run now, read-only AI assistant",
    "fw": {
     "sama": [
      "3.3.7",
      "3.3.14"
     ],
     "nca": [
      "2-5",
      "1-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.7",
      "3.3.14"
     ]
    },
    "g": "Technical audits"
   },
   {
    "h": "db-audit.html",
    "s": "Database Audit",
    "t": "Database Audit",
    "d": "Who did what in the Oracle databases from the unified audit trail: failed logons, privileged and SYSDBA activity, account and grant changes, schema and configuration changes, audit tampering, activity outside working hours, audit-policy checks and coverage; multi-sheet Excel report",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.5",
      "3.2.5"
     ],
     "nca": [
      "2-12",
      "2-2",
      "1-8"
     ],
     "pdpl": [
      "Art. 19",
      "IR Art. 33"
     ],
     "ia": [
      "3.3.14",
      "3.3.5",
      "3.2.5"
     ]
    },
    "g": "Technical audits"
   },
   {
    "h": "app-audit.html",
    "s": "Application Audit",
    "t": "Application Audit",
    "d": "One audit report per application: availability and resilience, every change to its servers with who proposed, approved and applied it, failed logons, account and audit-policy events on its servers, and log coverage; Excel report",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.7",
      "3.3.14",
      "3.2.5"
     ],
     "nca": [
      "2-15",
      "2-12",
      "1-8"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.6",
      "3.3.7",
      "3.3.14",
      "3.2.5"
     ]
    },
    "g": "Technical audits"
   },
   {
    "h": "licence-audit.html",
    "s": "Licensing Audit",
    "t": "Licensing Audit",
    "d": "Oracle Database and Oracle Data Integrator (processor / socket, VMware cluster rules), Windows Server Standard / Datacenter cores, VMware per-core; Microsoft 365 unused, disabled and inactive licences; software installs vs licences",
    "fw": {
     "sama": [
      "3.3.3",
      "3.4.1"
     ],
     "nca": [
      "2-1",
      "4-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3",
      "3.4.1"
     ]
    },
    "g": "Technical audits"
   },
   {
    "h": "sql-audit.html",
    "s": "SQL Server Audit",
    "g": "Technical audits",
    "t": "SQL Server Audit",
    "d": "Who did what in the SQL Server instances from SQL Server Audit (event 33205) and login events: failed logins, permission grants / revokes and role changes, account, schema, audit and configuration changes, administrative work after hours, coverage per server; masked statements, CSV",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14"
     ]
    }
   },
   {
    "h": "it-audit.html",
    "s": "IT Audit",
    "g": "Audit evidence",
    "t": "IT Audit",
    "d": "Change audit (device changes vs approved plans), privileged activity, user access review, evidence pack for auditors",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    }
   },
   {
    "h": "audit-log.html",
    "s": "Audit Log",
    "g": "Audit evidence",
    "t": "Audit Log",
    "d": "Who did what in the SIEM and portal: credentials, onboarding, approvals, AI questions, denied access (administrators)",
    "fw": {
     "sama": [
      "3.3.14",
      "3.2.5"
     ],
     "nca": [
      "2-12",
      "1-8"
     ],
     "pdpl": [
      "Art. 19",
      "IR Art. 33"
     ],
     "ia": [
      "3.3.14",
      "3.2.5"
     ]
    }
   },
   {
    "h": "evidence-packs.html",
    "s": "Regulator Evidence Packs",
    "g": "Audit evidence",
    "t": "Regulator Evidence Packs - frozen monthly packs per framework, compare, Excel, sign-off",
    "d": "Every month a frozen, SHA-256-fingerprinted evidence pack per framework (SAMA CSF, Insurance Authority, NCA ECC, PDPL, NDMO) from the registers as they stand: each control result, the live evidence (record counts, test runs, policies, evidence file names and hashes - never the files), the owner and what is missing; compared with the previous month, Excel and print, signed off by a compliance reviewer who did not build it",
    "fw": {
     "sama": [
      "3.3.15"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.3.15"
     ]
    }
   }
  ]
 },
 {
  "id": "adm",
  "sn": "Platform Admin",
  "name": "Platform Administration",
  "c": "#8b949e",
  "hd": "admin",
  "icon": "<circle cx=\"12\" cy=\"12\" r=\"3\"/><path d=\"M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z\"/>",
  "pages": [
   {
    "h": "connections.html",
    "s": "Integration Hub",
    "k": ["integrations", "connectors", "setup", "credentials", "api", "connections & setup", "vcenter", "nutanix"],
    "t": "Integration Hub - every connection the platform reads, its health and a guided set-up",
    "d": "One place to add and check every data source the platform reads - VMware vCenter / ESXi / Nutanix with a guided set-up (read-only account, connect, trust the certificate, first sync), Zscaler, Kaspersky, Oracle, e-mail security, DLP, Cloudflare, firewalls and network devices - with what needs attention first (failing, stale, never read), what each connection feeds and a consistent Test and Sync (read-only connections; admin to add)",
    "fw": {
     "sama": [
      "3.3.9",
      "3.4.1"
     ],
     "nca": [
      "2-8",
      "4-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.9",
      "3.4.1"
     ]
    },
    "start": true,
    "g": "Setup"
   },
   {
    "h": "solution-admin.html",
    "s": "Modules & Solutions",
    "t": "Modules & Solutions",
    "d": "Which modules this organisation uses - the whole platform or a custom solution (Cyber Security, Network, Servers & Infrastructure, GRC, Audit & Privacy) - and the platform licence: users, IP addresses, servers, network devices and databases in use against what the licence allows (no licence = unlimited; admin to change)",
    "fw": {
     "sama": [
      "3.1.4",
      "3.3.5"
     ],
     "nca": [
      "1-4",
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.1.4",
      "3.3.5"
     ]
    },
    "g": "Setup"
   },
   {
    "h": "identity-signin.html",
    "s": "Identity & Sign-in",
    "k": ["mfa", "2fa", "otp", "sso", "login", "password policy", "authenticator"],
    "t": "Identity & Sign-in (users, single sign-on, MFA, sign-in log, ML insights, AI advisor)",
    "d": "One place for every local account (add, edit, MFA, unlock, disable - risky changes confirmed by typing the name), single sign-on with Entra ID and role mapping, the MFA and local sign-in policy with lock-out guards, the sign-in log with CSV, ML insights (learned hours and addresses, spraying / brute force / stuffing, explainable account risk) and an AI identity advisor that can change nothing",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "2-2",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.14"
     ]
    },
    "g": "People & access"
   },
   {
    "h": "user-management.html",
    "s": "User Management",
    "k": ["users", "accounts", "add user", "roles", "permissions"],
    "t": "User Management",
    "d": "Everyone who can reach the platform in one register - local accounts, single sign-on job roles from AD groups and Active Directory, matched on the user name: an ML review score with every reason (leavers who can still sign in, admins without MFA, no AD owner, dormant, peer-group outliers by department), checks, bulk disable with a typed confirmation, Excel, and an AI-drafted access review",
    "fw": {
     "sama": [
      "3.3.1",
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.1",
      "3.3.5"
     ]
    },
    "g": "People & access"
   },
   {
    "h": "sso-access.html",
    "s": "SSO Access from AD",
    "t": "SSO Access from Active Directory (Entra ID single sign-on)",
    "d": "AD groups given a platform role for Microsoft Entra ID single sign-on: groups read from AD (members through nested groups), broad groups refused, a preview of who gets which role with warnings, proposed by one administrator and approved and applied by another - no account created, nothing written to AD, MFA unchanged",
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5"
     ]
    },
    "g": "People & access"
   },
   {
    "h": "ad-manage.html",
    "s": "AD Management",
    "t": "Active Directory management (create, disable, reset, groups, delete)",
    "d": "Create, disable, enable, reset passwords, move, change groups and details, and delete accounts in the organisation's own Active Directory - every change a request that a second administrator approves before it is written and read back; emergency disable with a review afterwards; privileged and protected accounts refused; delete only after 30 days disabled",
    "k": ["active directory", "ad users", "create user", "disable user", "delete user", "reset password", "ad groups", "local ad", "on-premises"],
    "fw": {
     "sama": [
      "3.3.5"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5"
     ]
    },
    "g": "People & access"
   },
   {
    "h": "roles.html",
    "s": "Roles & Functions",
    "t": "Roles & Functions",
    "d": "Job roles (System Admin, Network Admin, Cyber Security Admin, Penetration Engineer, …) with the functions each one may see or manage, and who has which role",
    "fw": {
     "sama": [
      "3.1.4",
      "3.3.5"
     ],
     "nca": [
      "1-4",
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.1.4",
      "3.3.5"
     ]
    },
    "g": "People & access"
   },
   {
    "h": "handover.html",
    "s": "Staff Handover",
    "t": "Staff Handover (leavers)",
    "d": "When an IT or cyber security employee leaves: what they own in the platform (assets, services, risks, actions, contracts, domains, job role, open plans, saved credentials), successors who accept each item, the access-removal checklist with evidence, knowledge notes (no secrets), manager sign-off; printable as PDF",
    "fw": {
     "sama": [
      "3.3.1",
      "3.3.5",
      "3.1.4"
     ],
     "nca": [
      "1-9",
      "2-2"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.1",
      "3.3.5",
      "3.1.4"
     ]
    },
    "g": "People & access"
   },
   {
    "h": "platform.html",
    "s": "Platform Health",
    "t": "Platform Health & Backup",
    "d": "Health of the server hosting the platform (hardware, disks, temperatures, services, certificate) and the encrypted nightly backup with restore",
    "fw": {
     "sama": [
      "3.3.8",
      "BCM"
     ],
     "nca": [
      "2-3",
      "2-9"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "BCM"
     ]
    },
    "g": "Platform health"
   },
   {
    "h": "update-health.html",
    "s": "Update Health",
    "t": "Update Health - did the last update work?",
    "d": "After an update: every page's API against the running engine, the modules that did not load, each installer's result, and the cause of each failure read from the service log with its fix - nothing rolled back silently",
    "fw": {
     "sama": [
      "3.3.6"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6"
     ]
    },
    "g": "Platform health"
   }
  ]
 },
 {
  "id": "ai",
  "sn": "AI & Automation",
  "name": "AI & Automation",
  "c": "#a3e635",
  "hd": "ai",
  "icon": "<path d=\"M12 3v3M12 18v3M3 12h3M18 12h3\"/><rect x=\"7\" y=\"7\" width=\"10\" height=\"10\" rx=\"2.5\"/><path d=\"M10 11h.01M14 11h.01M10 14h4\"/>",
  "pages": [
   {
    "h": "ai-engine.html",
    "s": "AI Engine",
    "k": ["switch", "local model", "llm", "claude", "anthropic", "openai", "ollama", "vllm", "provider", "ai off", "ai settings", "api key"],
    "t": "AI Engine - choose the local model on the AI server, Claude, or no AI, for every AI feature",
    "d": "One switch for every AI feature in IT Asset Management and the SIEM: the local model on {{org.short}}'s AI server (OpenAI-compatible or Anthropic-compatible gateway, nothing leaves the network), Claude through the Anthropic API, or off. Shows per engine whether data leaves the network, the gateway and model, AI calls today, and a test that checks a plain answer and a tool call",
    "fw": {
     "sama": [
      "3.3.6"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 29"
     ],
     "ia": [
      "3.3.6"
     ]
    },
    "g": "AI Engine"
   },
   {
    "h": "private-ai.html",
    "s": "Private AI Server",
    "k": ["ai server", "ai-01", "gpu", "llm health", "ollama", "vllm", "model gateway", "local model", "nvidia", "dcgm"],
    "t": "Private AI Server - health and management of {{org.short}}'s own AI server",
    "d": "Health of the AI server the AI Engine points at: a score with named deductions and the action for each, gateway availability and outages, the latency and failures of every AI call against the server's own usual (robust baseline, Wilson interval), generation speed, GPU use / memory / temperature and CPU, memory and disk from read-only exporters, disk and GPU memory forecasts, the models served and loaded, a model switch approved by a second administrator, and an AI-drafted health briefing to verify",
    "fw": {
     "sama": [
      "3.3.6"
     ],
     "nca": [
      "2-2"
     ],
     "pdpl": [
      "Art. 29"
     ],
     "ia": [
      "3.3.6"
     ]
    },
    "g": "AI Engine"
   },
   {
    "h": "ai-team.html",
    "s": "Team Overview",
    "t": "AI Engineering Team",
    "d": "The AI engineers on duty: who patrolled when, open work, what is waiting for approval or a person, shift handover reports and the duty policy",
    "fw": {
     "sama": [
      "3.1.4",
      "3.3.7"
     ],
     "nca": [
      "1-4",
      "1-2"
     ],
     "pdpl": [],
     "ia": [
      "3.1.4",
      "3.3.7"
     ]
    },
    "start": true,
    "g": "AI team"
   },
   {
    "h": "ai-ciso.html",
    "s": "AI CISO",
    "t": "AI CISO (CISO / BISO view)",
    "d": "Executive security view: itemised posture score by domain, risk register, decisions waiting for a person, BISO view by domain and site, the AI engineering team, and an AI board brief that cites only the platform's own records",
    "fw": {
     "sama": [
      "3.1.1",
      "3.1.2",
      "3.2.1"
     ],
     "nca": [
      "1-1",
      "1-2",
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.1.1",
      "3.1.2",
      "3.2.1"
     ]
    },
    "g": "AI team"
   },
   {
    "h": "ai-security.html",
    "s": "AI Security",
    "t": "AI Security (guard rails, usage, quality, red team)",
    "d": "Every AI feature: what it may read, what it may only propose and who decides; AI calls, tokens, refusals and prompt-injection flags per day and feature; how often people accepted the AI's drafts; unusual AI use per person (robust statistics); a daily red team of the guard rails in code with no model call; the limits in force",
    "fw": {
     "sama": [
      "3.3.5",
      "3.3.14"
     ],
     "nca": [
      "1-5",
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.5",
      "3.3.14"
     ]
    },
    "g": "AI team"
   },
   {
    "h": "ai-soc-analyst.html",
    "s": "AI SOC Analyst",
    "t": "AI SOC Analyst",
    "d": "A conversational analyst grounded in the live SOC: quick questions (focus now, threat briefing, active attack, containment options, lateral movement, today vs yesterday, brief my manager), answers that cite the records, next steps proposed for a person to accept, and drafts of incident reports, runbooks, change requests, catalogue entries and manager briefs for review - it cannot contain, block or close anything itself",
    "fw": {
     "sama": [
      "3.3.14"
     ],
     "nca": [
      "2-12"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.14"
     ]
    },
    "g": "Security analysts & engineers"
   },
   {
    "h": "ai-security-engineer.html",
    "s": "AI Security Engineer",
    "t": "AI Security Engineer (Firewalls)",
    "d": "Palo Alto and FortiGate security posture: firewall health, policy & configuration hygiene (any/any rules, missing logging, exposed management), expired security subscriptions, and AI assistance; response routed to SOC Response for approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.4",
      "3.3.7"
     ],
     "nca": [
      "2-5",
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.4",
      "3.3.7"
     ]
    },
    "g": "Security analysts & engineers"
   },
   {
    "h": "ai-pentest.html",
    "s": "AI Penetration Testing",
    "k": ["attack path", "attack paths", "strike7", "red team", "crown jewel", "lateral movement", "mitre", "att&ck", "autonomous pentest", "continuous testing", "exploit"],
    "t": "AI Penetration Testing - continuous, attack-path focused: entry -> pivot -> crown jewel chains reasoned from your own evidence, an AI pentester that proposes the next test",
    "d": "An attack graph from the internet through internet-facing vulnerable devices and footholds to business-critical and sensitive-data devices, every path scored with its points itemised and every stage mapped to MITRE ATT&CK; attack-surface coverage from the testing cadence; daily trend; triage (validating, confirmed, mitigated, false positive); the AI pentester proposes the next authorised, non-destructive test and an administrator files it as a draft engagement that still needs four-eyes approval - nothing is run by the AI",
    "fw": {
     "sama": [
      "3.3.17",
      "3.2.1"
     ],
     "nca": [
      "2-10",
      "2-11"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17",
      "3.2.1"
     ]
    },
    "g": "Security analysts & engineers"
   },
   {
    "h": "pentest.html",
    "s": "AI Pentest Engineer",
    "t": "AI Penetration Testing Engineer",
    "d": "Authorised, read-only attack-surface assessment of the estate: exposed services, end-of-life systems and monitoring gaps, prioritised with fixes and ATT&CK; engagement register with the safety checklist and four-eyes approval",
    "fw": {
     "sama": [
      "3.3.17",
      "3.2.4"
     ],
     "nca": [
      "2-11",
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17",
      "3.2.4"
     ]
    },
    "g": "Security analysts & engineers"
   },
   {
    "h": "ai-ksc-engineer.html",
    "s": "AI Endpoint (Kaspersky)",
    "t": "AI Endpoint Protection Engineer (Kaspersky)",
    "d": "Kaspersky Security Center endpoint posture over the read-only OpenAPI: protection running, databases up to date, active threats and device status; work items per problem with actions a person takes in the KSC console under four-eyes approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.17"
     ],
     "nca": [
      "2-3",
      "2-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.17"
     ]
    },
    "g": "Security analysts & engineers"
   },
   {
    "h": "ai-zscaler-engineer.html",
    "s": "AI Zscaler Engineer",
    "t": "AI Security Engineer - Zscaler",
    "d": "Zscaler Internet Access (ZIA) and Private Access (ZPA) posture over the read-only API: Cloud Firewall and URL policy hygiene, locations without enforcement, App Connector health, disabled segments/rules; change plans applied by a person in the Zscaler console with four-eyes approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.4.3"
     ],
     "nca": [
      "2-5",
      "4-2"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 29"
     ],
     "ia": [
      "3.3.8",
      "3.4.3"
     ]
    },
    "g": "Security analysts & engineers"
   },
   {
    "h": "network-engineer.html",
    "s": "AI Network Engineer",
    "t": "AI Network Engineer",
    "d": "Cisco, FortiGate, Palo Alto, Genian NAC and Silver Peak: site health, problems, troubleshooting, ask the AI, change approvals",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-5"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Infrastructure engineers"
   },
   {
    "h": "windows-admin.html",
    "s": "AI Windows Admin",
    "g": "Infrastructure engineers",
    "t": "AI Windows Server Administrator",
    "d": "Disk, services, event errors, patching and pending reboots, certificates, AD replication on every Windows server (read-only WinRM checks, health findings every 15 min); ask the AI, change plans for approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7",
      "3.3.17"
     ],
     "nca": [
      "2-3",
      "2-10"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7",
      "3.3.17"
     ]
    }
   },
   {
    "h": "exchange-admin.html",
    "s": "AI Exchange Admin",
    "t": "AI Exchange Server Administrator",
    "d": "Mail queues, databases and DAG copies, backups, Exchange services and health sets, certificates, connectors, message tracking; ask the AI, change plans for approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-4"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Infrastructure engineers"
   },
   {
    "h": "ai-virt-admin.html",
    "s": "AI Virtualization Admin",
    "g": "Infrastructure engineers",
    "t": "AI Virtualization Administrator",
    "d": "VMware vCenter and Nutanix Prism every hour: hosts down or red, CPU / memory pressure, datastores filling, old snapshots, disks to consolidate, Tools, HA off, N+1, capacity forecast; physical cores per host for licensing; change plans for approval",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    }
   },
   {
    "h": "ai-dba.html",
    "s": "AI Oracle DBA",
    "t": "AI Oracle DBA",
    "d": "Patrols every Oracle instance the collector reports: instance down, tablespaces, blocked sessions, RMAN backups, Data Guard lag, archiving, FRA, listener, failed logons, alert-log errors; a work item per problem with the DBA's next step",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Infrastructure engineers"
   },
   {
    "h": "ai-sql-dba.html",
    "s": "AI Database Administrator",
    "t": "AI Database Administrator (SQL Server · PostgreSQL · MySQL)",
    "d": "Patrols every SQL Server, PostgreSQL and MySQL server the database inventory reads with read-only logins: databases offline, missing or old backups, FULL recovery without log backups, sessions near the limit, deadlocks, replication lag, servers it cannot read; a work item per problem with the DBA's exact statement, verified by a fresh read; read-only Claude analysis",
    "fw": {
     "sama": [
      "3.3.8",
      "3.3.7"
     ],
     "nca": [
      "2-3"
     ],
     "pdpl": [],
     "ia": [
      "3.3.8",
      "3.3.7"
     ]
    },
    "g": "Infrastructure engineers"
   },
   {
    "h": "ai-app-manager.html",
    "s": "AI Application Manager",
    "t": "AI Application Manager",
    "d": "Every business service as an application owner sees it: down, running without redundancy, single point of failure, no or offline DR copy, and disk / CPU / memory pressure on its production servers",
    "fw": {
     "sama": [
      "3.3.6",
      "3.3.7"
     ],
     "nca": [
      "2-15"
     ],
     "pdpl": [],
     "ia": [
      "3.3.6",
      "3.3.7"
     ]
    },
    "g": "Infrastructure engineers"
   },
   {
    "h": "desk-support.html",
    "s": "AI Desktop Support",
    "t": "AI Desktop Support Engineer",
    "d": "Automated IT service management: triages ServiceDesk Plus tickets (priority, technician, group, status, first response), monitors desktop health from Endpoint Central, and deploys patches with four-eyes approval — suggest or full-auto modes",
    "fw": {
     "sama": [
      "3.3.17",
      "3.3.3"
     ],
     "nca": [
      "2-10",
      "2-6"
     ],
     "pdpl": [],
     "ia": [
      "3.3.17",
      "3.3.3"
     ]
    },
    "g": "Infrastructure engineers"
   },
   {
    "h": "ai-grc-consultant.html",
    "s": "AI GRC Consultant",
    "g": "Governance, risk & audit",
    "t": "AI GRC Consultant",
    "d": "Patrols the compliance position: failing controls, policies past review, Insurance Authority requirements not covered, DR drills overdue or unsigned, assets without owners, SAMA gaps; a roadmap and answers that cite the records",
    "fw": {
     "sama": [
      "3.2.2",
      "3.1.3"
     ],
     "nca": [
      "1-7",
      "1-3"
     ],
     "pdpl": [],
     "ia": [
      "3.2.2",
      "3.1.3"
     ]
    }
   },
   {
    "h": "ai-pdpl.html",
    "s": "AI PDPL Consultant",
    "t": "AI PDPL Consultant",
    "d": "Saudi Personal Data Protection Law (SDAIA): records of processing, data subject requests, breaches (72 h), impact assessments, processors and transfers checked against 24 requirements, gaps raised as work, and the compliance statement the DPO signs",
    "fw": {
     "sama": [
      "3.2.2",
      "3.3.3",
      "3.3.11"
     ],
     "nca": [
      "1-7",
      "2-7"
     ],
     "pdpl": [
      "Art. 4",
      "Art. 18",
      "Art. 19",
      "Art. 20",
      "Art. 22",
      "Art. 23",
      "Art. 29",
      "IR Art. 33"
     ],
     "ia": [
      "3.2.2",
      "3.3.3",
      "3.3.11"
     ]
    },
    "g": "Governance, risk & audit"
   },
   {
    "h": "ai-auditors.html",
    "s": "AI Auditors",
    "t": "AI IT & Cyber Security Auditors",
    "d": "Independent audit programmes run by the AI IT Auditor and the AI Cyber Security Auditor: every control test pass / fail / not tested with evidence, findings routed to the owning department and re-tested",
    "fw": {
     "sama": [
      "3.2.5",
      "3.2.4"
     ],
     "nca": [
      "1-8"
     ],
     "pdpl": [],
     "ia": [
      "3.2.5",
      "3.2.4"
     ]
    },
    "g": "Governance, risk & audit"
   },
   {
    "h": "ai-findings.html",
    "s": "AI Findings",
    "t": "ITAM AI Findings - what needs a decision, ranked, and what people decided before",
    "d": "Findings from the asset register and licences (not seen, shadow IT, missing data, warranty and end of life, licence over- and under-use) ranked 0-100 with every point explained: severity, how critical the asset is, how long it has been open, whether it came back, and what people did with that kind before. Accept or dismiss one or many with a reason; per-kind learning flags noisy rules; hotspots by asset, site and owner; a 12-week trend; AI classification, relationships and refresh plan through the server's AI budget.",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-1"
     ],
     "pdpl": [],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "Governance, risk & audit"
   },
   {
    "h": "risk-flow.html",
    "s": "AI Risk Automation Flow",
    "t": "Enterprise Risk Automation Flow - how enterprise risk management runs on the platform, live",
    "d": "Seven stages lit and counted from their own sources: the register and RAS workbooks and platform signals -> the methodology on the server -> machine learning (duplicates, rating consistency, coverage, forecasts) -> the AI Risk Officer's proposals -> its supervisor (passed / flagged / held) -> a person decides (four eyes for limits and acceptances) -> GRC actions and outcomes; the learning loop from decisions back to the officer, its outcome scorecard",
    "fw": {
     "sama": [
      "3.2.1"
     ],
     "nca": [
      "1-5"
     ],
     "pdpl": [],
     "ia": [
      "3.2.1"
     ]
    },
    "g": "Governance, risk & audit"
   },
   {
    "h": "ai-governance.html",
    "s": "AI Governance",
    "g": "AI governance & data",
    "t": "AI Governance - the platform's AI register, usage and reviews",
    "d": "Every AI advisor in the installed modules (enabled or why not, model, tools, write-capable tools flagged), 90 days of usage from the shared AI budget per feature (calls, tokens, users, refusals, injection-signal flags - never the questions), unusual days, the yearly review by an administrator and a read-only AI governance advisor",
    "fw": {
     "sama": [
      "3.1.3"
     ],
     "nca": [
      "1-3"
     ],
     "pdpl": [],
     "ia": [
      "3.1.3"
     ]
    }
   },
   {
    "h": "ai-lineage.html",
    "s": "AI Data Lineage",
    "t": "AI Data Lineage",
    "d": "Which AI can reach which data: Microsoft 365 Copilot, the sanctioned and shadow AI apps and the platform's own AI engineers, the data stores they reach and the data classes held there - each line with why it exists",
    "fw": {
     "sama": [
      "3.3.3"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 19"
     ],
     "ia": [
      "3.3.3"
     ]
    },
    "g": "AI governance & data"
   },
   {
    "h": "shadow-ai.html",
    "s": "Shadow AI DLP",
    "t": "Shadow AI DLP",
    "d": "AI apps people use (ChatGPT, Claude, Gemini, Copilot ...) found in the web-filter, firewall and DNS logs; a sanctioned-AI register changed only with four-eyes approval; the blocked apps' domains for the firewall; DLP incidents, large uploads and policy gaps towards AI apps; a browser extension that checks prompts and files on the PC and reports only what it found",
    "fw": {
     "sama": [
      "3.3.3",
      "3.3.14"
     ],
     "nca": [
      "2-7"
     ],
     "pdpl": [
      "Art. 19",
      "Art. 29"
     ],
     "ia": [
      "3.3.3",
      "3.3.14"
     ]
    },
    "g": "AI governance & data"
   },
   {
    "h": "aiops.html",
    "s": "AIOps Center",
    "t": "AIOps Center",
    "d": "Noise reduction from events to alerts to correlated incidents, MTTD / MTTA / MTTR, predictive capacity and SLA alerts, noisy rules to tune, and the AI engineers' approved, verified fixes",
    "fw": {
     "sama": [
      "3.3.14",
      "3.3.15"
     ],
     "nca": [
      "2-12",
      "2-13"
     ],
     "pdpl": [],
     "ia": [
      "3.3.14",
      "3.3.15"
     ]
    },
    "g": "Automation"
   },
   {
    "h": "automation-org.html",
    "s": "Organisation & Automation",
    "t": "Organisation & Automation",
    "d": "Organisation chart of IT Infrastructure, IT Applications, Cyber Security, Governance and IT & Cyber Audit: each AI engineer beside the named people who approve its work, and how the automation flows from patrol to human approval to independent audit",
    "fw": {
     "sama": [
      "3.1.4",
      "3.1.2"
     ],
     "nca": [
      "1-4",
      "1-2"
     ],
     "pdpl": [],
     "ia": [
      "3.1.4",
      "3.1.2"
     ]
    },
    "g": "Automation"
   }
  ]
 }
];
// a section's sub-menus (page field g) are each drawn once: pages of the same sub-menu are kept together, in the order the
// sub-menus first appear, so a page listed out of place never repeats a heading in the menu
window.ZYB_NAV.forEach(function (a) {
  var order = [], by = {};
  a.pages.forEach(function (p) { var k = p.g || ''; if (!by[k]) { by[k] = []; order.push(k); } by[k].push(p); });
  if (order.length > 1) a.pages = order.reduce(function (out, k) { return out.concat(by[k]); }, []);
});

// the registry above is plain data (tools and tests read it as JSON): it names the company as {{org.*}} tokens, which are
// filled here from the brand setting. Without a brand setting (a tool reading the file) the tokens simply stay.
(function (o) {
  if (!o) return;
  var f = function (s) { return s.replace(/\{\{org\.([a-z_]+)\}\}/g, function (m, k) { return typeof o[k] === 'string' ? o[k] : m; }); };
  window.ZYB_NAV.forEach(function (a) {
    ['name', 'sn', 'd'].forEach(function (k) { if (typeof a[k] === 'string') a[k] = f(a[k]); });
    (a.pages || []).forEach(function (p) {
      ['s', 't', 'd'].forEach(function (k) { if (typeof p[k] === 'string') p[k] = f(p[k]); });
      // framework tags: only the frameworks the organisation follows (brand setting: frameworks); a page keeps the rest of its record
      if (p.fw && Array.isArray(o.frameworks) && o.frameworks.length && !o.frameworks_all) Object.keys(p.fw).forEach(function (k) { if (o.frameworks.indexOf(k === 'iso' ? 'iso27001' : k === 'ecc' ? 'nca' : k) < 0) delete p.fw[k]; });
    });
  });
})(ZYB_ORG);
