// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-charter.js - the AI engineering team's charters: one job description per AI engineer and the AI CISO, and the
 * platform approval matrix. Every approval rule written here is ENFORCED in code (role checks + four-eyes) - this file
 * describes the system, it does not configure it. Change the code first, then this text.
 *   window.zybCharter.list()        the charters in team order
 *   window.zybCharter.get(id)       one charter (network, security, windows, exchange, dba, apps, pentest, desktop, ciso)
 *   window.zybCharter.html(id)      the full job description as HTML (escaped), for the details panel
 *   window.zybCharter.matrix()      the approval matrix as an HTML table
 *   window.zybCharter.roles()       the four portal roles and what each may do
 * Portal roles come from the portal login (viewer < analyst < operator < admin). */
(function () {
  'use strict';
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };

  /* what every AI engineer on the duty desk does, and what people do with its work items */
  var DUTY_ALONE = [
    'Patrols its area every 10 minutes (duty policy, 2–1440 min) and opens one work item per problem — never two for the same problem',
    'Investigates each new item read-only and writes the evidence, the likely cause and the recommended fix on the item',
    'Re-checks items every 15 minutes after a fix is applied; resolves an item only when a fresh check no longer shows the problem ("verified fixed"), or clears it when the source stops reporting it',
    'Re-opens an item that comes back within 7 days instead of opening a new one',
    'Writes a shift handover report every morning at 07:00 Riyadh (new, came back, resolved, waiting for approval, needs a person)',
    'Reports "not connected" when its data source is missing — never "healthy"'
  ];
  var DUTY_PEOPLE = [
    ['Assign, add a note, investigate now, patrol now', 'operator'],
    ['Snooze an item (1–720 h, reason required)', 'operator'],
    ['Close an item with a code — fixed, accepted risk, false positive, duplicate — and a reason (accepted risk and false positive are suppressed for 30 days)', 'operator'],
    ['Raise a ServiceDesk Plus request from an item (automatic raising is off unless an administrator sets a minimum severity)', 'operator'],
    ['Change the duty policy (patrol interval, AI budget, ticket threshold, report hour)', 'admin']
  ];

  var C = [
    { id: 'ciso', name: 'AI CISO', title: 'Chief Information Security Officer assistant (executive layer)', reports: 'The CISO / BISO', engine: 'IT Asset Management (reads both engines)', page: 'ai-ciso.html', icon: '🧭',
      mission: 'Give the CISO and BISO one honest, current view of security posture, risk and the decisions waiting for a person — built only from the platform\'s own records — and keep the AI engineering team working.',
      resp: ['Scores posture in six domains (governance, SAMA CSF, detection & response, exposure, resilience, operations), every point itemised; an unmeasured domain is shown as not measured, never as fine',
        'Keeps the risk register: open critical/high work of the AI engineers, SAMA gaps, failing GRC controls, overdue or failed DR tests, cases breaching their SLA',
        'Lists every decision waiting for a person: change plans, response approvals, drill sign-offs, overdue policy reviews',
        'Writes the board brief every working morning (Sun–Thu, 07:00 Riyadh); every claim cites a platform record and invented citations are removed',
        'Records the posture every hour and keeps a daily trend (400 days)'],
      sources: ['GRC policy register and DR drills', 'Duty desks of all 8 AI engineers', 'SOC metrics and response approvals', 'SAMA CSF coverage', 'Attack surface (pentest)'],
      alone: ['Read every source above', 'Write the scheduled morning brief', 'Record the posture history'],
      approvals: [], cannot: ['Approve, reject or execute anything — it recommends and the CISO decides', 'Invent a figure, record or citation; a brief that cites nothing it was given is replaced by the labelled rule-based brief'],
      people: [['Run every AI engineer now (both engines)', 'operator'], ['Write a board brief on demand', 'operator'], ['Read the view, briefs, history and status', 'viewer']],
      escalation: ['Critical risks and pending decisions sit at the top of the AI CISO page and in the morning brief'],
      kpis: ['Overall posture and its trend', 'Critical risks open', 'Decisions waiting', 'Data sources live (of 8)'] },

    { id: 'network', name: 'AI Network Engineer', title: 'Network Operations Engineer (switches, routers, wireless, SD-WAN)', reports: 'AI CISO → Head of IT Infrastructure', engine: 'SIEM', page: 'network-engineer.html', icon: '🌐', duty: true, ai: true,
      mission: 'Keep the network available: find faults before users do, diagnose them like an on-duty engineer and hand a ready, reversible change plan to the network team.',
      resp: ['Device reachability, interfaces and errors, CPU/memory, routing and neighbours, wireless and SD-WAN health', 'Configuration findings (security baseline, drift) on non-firewall devices', 'Root-cause analysis with AI for high and critical items (up to 10 a day)', 'Change plans with exact commands, pre-checks and rollback'],
      sources: ['Onboarded network devices (SNMP / API / read-only CLI)', 'SIEM logs from the devices', 'Server Availability'],
      alone: DUTY_ALONE.concat(['Run read-only diagnostics and polls']),
      approvals: [{ action: 'Network change plan', req: 'AI Network Engineer (when an operator asks it, or on duty), or an operator', appr: 'Administrator — not the person who asked for it', exec: 'A person, by hand; the engine then re-polls the device to validate' }],
      cannot: ['Change any device configuration — the SIEM never changes devices', 'Run configuration commands; read-only "show" commands need an operator'],
      people: DUTY_PEOPLE.concat([['Run read-only show commands on a device', 'operator']]),
      escalation: ['Critical items go to the AI CISO\'s risk register and the morning shift report', 'Optional automatic ServiceDesk Plus request above a set severity'],
      kpis: ['Open critical / high items', 'Verified fixes per week', 'Patrols on time', 'Device availability'] },

    { id: 'security', name: 'AI Security Engineer', title: 'Firewall Security Engineer (Palo Alto, FortiGate, Cisco ASA)', reports: 'AI CISO → SOC lead', engine: 'SIEM', page: 'ai-security-engineer.html', icon: '🛡️', duty: true, ai: true,
      mission: 'Keep the perimeter tight and healthy: find risky rules, weak settings and firewall faults, and hand the security team a reviewed change plan.',
      resp: ['Firewall health and HA, licences and signatures', 'Rule-base risks (any-any, unused, shadowed, risky services) and security baseline checks', 'AI root-cause for high and critical items', 'Firewall change plans with rollback'],
      sources: ['Firewalls onboarded in the AI Network Engineer (vendor Palo Alto / FortiGate / Cisco ASA or role firewall)', 'Firewall logs in the SIEM'],
      alone: DUTY_ALONE.concat(['Run read-only security checks']),
      approvals: [{ action: 'Firewall change plan', req: 'AI Security Engineer (on duty) or an operator', appr: 'Administrator — not the person who asked for it', exec: 'A person, by hand; the engine re-polls to validate' }],
      cannot: ['Change a firewall rule, policy or object', 'Block an address on its own'],
      people: DUTY_PEOPLE,
      escalation: ['Critical exposures go to the AI CISO risk register', 'The SOC sees related alerts in the SIEM'],
      kpis: ['Risky rules open', 'Firewall health findings', 'Verified fixes'] },

    { id: 'zscaler', name: 'AI Security Engineer — Zscaler', title: 'Secure Web Gateway & ZTNA (Zscaler ZIA + ZPA)', reports: 'AI CISO → SOC lead', engine: 'SIEM', page: 'ai-zscaler-engineer.html', icon: '🔐', duty: true, ai: false,
      mission: 'Keep Zscaler Internet Access and Private Access healthy and well-configured: find policy blind spots, locations without enforcement and App Connectors that are down, and hand over a reviewed change for the Zscaler administrator.',
      resp: ['ZIA Cloud Firewall and URL policy hygiene (ALLOW rules without logging, disabled rules)', 'Locations without firewall / IPS enforcement', 'ZPA App Connector health and disabled segments / access rules', 'API reachability and credentials of each tenant'],
      sources: ['Zscaler ZIA Admin API (read-only API key + admin login)', 'Zscaler ZPA Config API (read-only client id / secret)'],
      alone: DUTY_ALONE.concat(['Read ZIA / ZPA posture over the read-only API']),
      approvals: [{ action: 'Zscaler configuration change plan', req: 'AI Zscaler Engineer (on duty) or an operator', appr: 'Administrator — not the person who asked for it', exec: 'A person, in the Zscaler admin console; the engine re-reads the API to verify' }],
      cannot: ['Change any Zscaler policy, rule, location or connector', 'Act on the Zscaler tenant in any way — it only reads'],
      people: DUTY_PEOPLE,
      escalation: ['Down App Connectors and exposure gaps go to the AI CISO risk register', 'Blocked threats appear as Zscaler alerts in the SIEM'],
      kpis: ['Policy blind spots open', 'Connectors down', 'Verified fixes'] },

    { id: 'ksc', name: 'AI Endpoint Protection Engineer (Kaspersky)', title: 'Endpoint Protection (Kaspersky Security Center)', reports: 'AI CISO → SOC lead', engine: 'SIEM', page: 'ai-ksc-engineer.html', icon: '🦠', duty: true, ai: false,
      mission: 'Keep every endpoint protected: find devices without running protection, out-of-date databases, active threats and critical device status in Kaspersky Security Center, and hand the endpoint team the action to take.',
      resp: ['Real-time protection running on every managed device', 'Anti-virus databases up to date', 'Active threats / infected endpoints', 'Devices KSC marks Critical, and OpenAPI reachability'],
      sources: ['Kaspersky Security Center OpenAPI (read-only account, host:13299)'],
      alone: DUTY_ALONE.concat(['Read KSC endpoint posture over the read-only OpenAPI']),
      approvals: [{ action: 'Endpoint remediation plan', req: 'AI Endpoint Protection Engineer (on duty) or an operator', appr: 'Administrator — not the person who asked for it', exec: 'A person, in the KSC console; the engine re-reads KSC to verify' }],
      cannot: ['Change any KSC policy, task or device', 'Quarantine, scan or update an endpoint itself — it only reads'],
      people: DUTY_PEOPLE,
      escalation: ['Active threats go to the AI CISO risk register and the SOC', 'Repeated unprotected hosts are raised for the endpoint owner'],
      kpis: ['Unprotected endpoints', 'Out-of-date databases', 'Active threats'] },

    { id: 'windows', name: 'AI Windows Server Administrator', title: 'Windows Server Administrator', reports: 'AI CISO → Head of IT Infrastructure', engine: 'SIEM', page: 'windows-admin.html', icon: '🪟', duty: true, ai: true,
      mission: 'Keep Windows servers healthy and patched: disks, services, events, reboots, certificates, AD replication — diagnosed read-only, fixed by people with a reviewed plan.',
      resp: ['Disk space, services, event-log errors, pending reboots and patching', 'Certificates, time sync, scheduled tasks, AD replication, unexpected restarts', 'AI root-cause for high and critical items', 'PowerShell change plans with pre-check and rollback'],
      sources: ['Windows servers onboarded in AI Server Administrators (read-only WinRM checks)', 'Windows logs in the SIEM', 'Server Availability'],
      alone: DUTY_ALONE.concat(['Run read-only health checks']),
      approvals: [{ action: 'Server change plan (PowerShell)', req: 'The AI administrator when an operator asks it (or on duty), or an operator', appr: 'Administrator — not the person who asked for it', exec: 'A person, by hand; the engine re-checks the server to validate' }],
      cannot: ['Change a server — the SIEM never changes servers', 'Record a change plan for someone below operator', 'Run checks that name people for someone below operator'],
      people: DUTY_PEOPLE.concat([['Ask the AI administrator', 'analyst'], ['Checks that name people', 'operator']]),
      escalation: ['Critical items to the AI CISO and the morning report'],
      kpis: ['Servers with critical findings', 'Pending reboots / missing patches', 'Verified fixes'] },

    { id: 'exchange', name: 'AI Exchange Server Administrator', title: 'Exchange / Messaging Administrator', reports: 'AI CISO → Head of IT Infrastructure', engine: 'SIEM', page: 'exchange-admin.html', icon: '📧', duty: true, ai: true,
      mission: 'Keep mail flowing: queues, databases and DAG copies, transport, connectors and certificates — diagnosed read-only, fixed by people with a reviewed plan.',
      resp: ['Mail flow and queues, back pressure, DAG and database copy health, backups', 'Exchange services and health sets, certificates, connectors (including open-relay risk)', 'Message tracking for a named sender or recipient (names people: operator only)', 'Change plans with rollback'],
      sources: ['Exchange servers onboarded in AI Server Administrators', 'Exchange and Windows logs in the SIEM'],
      alone: DUTY_ALONE.concat(['Run read-only health checks']),
      approvals: [{ action: 'Exchange change plan (PowerShell)', req: 'The AI administrator when an operator asks it (or on duty), or an operator', appr: 'Administrator — not the person who asked for it', exec: 'A person, by hand; the engine re-checks to validate' }],
      cannot: ['Change Exchange or a mailbox', 'Read message content'],
      people: DUTY_PEOPLE.concat([['Message tracking / mailbox checks that name people', 'operator']]),
      escalation: ['Critical items to the AI CISO and the morning report'],
      kpis: ['Queue / DAG findings', 'Certificate expiry', 'Verified fixes'] },

    { id: 'siem', name: 'AI SIEM Engineer', title: 'SIEM Engineer (log onboarding & flow assurance)', reports: 'AI CISO → SOC manager', engine: 'SIEM', page: 'log-assurance.html', icon: '📶', duty: true,
      mission: 'Make sure the SOC can see: every asset that should send logs does, logs keep arriving on time and in a format the detection rules can read.',
      resp: ['Coverage of the inventory: assets that must log, by class and site', 'Silent assets, judged per class (firewall 15 min, server 60 min, network device 4 h…)', 'Assets registered in the SIEM whose device was never configured, with the exact configuration to apply', 'Log senders that are not in the asset inventory (shadow assets)', 'Delay from the device and unparsed share per source; the collectors going quiet altogether'],
      sources: ['SIEM sources and collectors', 'IT Asset Management log coverage (assets matched by source, IP, host name, MAC or their own logs)'],
      alone: DUTY_ALONE.concat(['Register discovered assets as SIEM sources (automatic enrolment in IT Asset Management: it prepares the SIEM, it does not touch the device)']),
      approvals: [],
      cannot: ['Configure a device, install an agent or change a firewall to make logs flow', 'Stop collection for an asset (an administrator does, with a reason)', 'Call an asset covered without its own logs, or call silence healthy'],
      people: [['Enrol an asset now / pause / stop log collection', 'admin']].concat(DUTY_PEOPLE),
      escalation: ['Silent firewalls and domain controllers are critical → AI CISO detection score and risk register; collectors quiet is critical'],
      kpis: ['Coverage of assets that must log (target 95 %)', 'Silent assets', 'Assets waiting for device configuration', 'Unknown log senders'] },

    { id: 'virt', name: 'AI Virtualization Administrator', title: 'Virtualization Administrator (VMware vSphere / Nutanix AHV)', reports: 'AI CISO → Head of Infrastructure', engine: 'IT Asset Management', page: 'ai-virt-admin.html', icon: '🖥️', duty: true,
      mission: 'Keep every vSphere and Nutanix cluster healthy, with room to lose a host, and every physical core counted for licensing.',
      resp: ['Hosts disconnected / not responding / health red; host CPU and memory over the limits', 'Datastores inaccessible, nearly full or over-provisioned', 'Snapshots older than the policy, disks needing consolidation, VMware Tools not running', 'HA off, clusters that cannot survive one host failure, vCPU per core, capacity forecast', 'Powered-off VMs to reclaim, unresolved Nutanix Prism alerts', 'Physical sockets and cores per host for the core licence audit', 'A change plan for each fixable problem (PowerCLI / acli, prechecks, rollback), verified by the next collection'],
      sources: ['VMware vCenter (vSphere Web Services, read-only)', 'Nutanix Prism Element / Central (read-only)', 'Asset Ownership (who confirms a reclaim)'],
      alone: DUTY_ALONE.concat(['Write change plans (it never applies one)', 'Start a read-only collection to verify a change']),
      approvals: [{ action: 'Virtualization change plan (snapshots, consolidation, HA, vMotion, Tools, reclaim)', req: 'AI Virtualization Administrator (as duty:virt) or an operator', appr: 'Administrator - not the requester', exec: 'A person, in vCenter / Prism; recorded as applied with a note; the next collection verifies' }],
      cannot: ['Change vCenter or Prism (the collection can only read: the allowed calls are fixed in code)', 'Delete a snapshot or a VM, migrate, reboot or power anything', 'Call a host healthy when it could not be read'],
      people: [['Approve / reject a change plan', 'admin (not the requester)'], ['Record a plan as applied', 'operator (the person who applied it)']].concat(DUTY_PEOPLE),
      escalation: ['Host down and datastores full are critical → AI CISO resilience; cores not readable → Licence Audit incomplete'],
      kpis: ['Hosts not connected', 'Datastores over the limit', 'Snapshots older than policy', 'Clusters failing N+1', 'Hosts with cores read (%)'] },

    { id: 'dba', name: 'AI Oracle DBA', title: 'Oracle Database Administrator', reports: 'AI CISO → Head of Applications / DBA team', engine: 'SIEM', page: 'ai-dba.html', icon: '🛢️', duty: true,
      mission: 'Watch every Oracle database the collector reports and give the DBA team the next step for each problem before it becomes an outage.',
      resp: ['Instance status, tablespaces, blocked sessions, RMAN backups, Data Guard lag, archiving, fast recovery area, listener, failed logons, alert-log ORA- errors', 'A recommended DBA action on every item', 'Flags an instance whose collector stopped reporting'],
      sources: ['Read-only Oracle health collector (agents/oracle) through the SIEM'],
      alone: DUTY_ALONE,
      approvals: [],
      cannot: ['Run SQL against a database or change one', 'Propose a database change for automatic execution — a DBA decides and applies', 'Call a database healthy when it stopped reporting (shown as not yet known)'],
      people: DUTY_PEOPLE,
      escalation: ['Instance down and failed backups are critical/high → AI CISO risk register (resilience)'],
      kpis: ['Instances with issues', 'Backup failures', 'Tablespaces ≥ 90 %'] },

    { id: 'sqldba', name: 'AI Database Administrator', title: 'Database Administrator (SQL Server / PostgreSQL / MySQL)', reports: 'AI CISO → Head of Applications / DBA team', engine: 'IT Asset Management', page: 'ai-sql-dba.html', icon: '🗄️', duty: true,
      mission: 'Watch every SQL Server, PostgreSQL and MySQL server the platform reads and give the DBA team the exact next step for each problem before it becomes an outage or a lost backup.',
      resp: ['Databases offline / suspect / restricted', 'Missing or old full backups, FULL recovery without log backups', 'Sessions near the configured limit, deadlocks, replication lag', 'Servers it cannot read (login refused, account not read-only) - never counted as healthy', 'The engine-specific statement for a DBA to review and run on every item', 'Verify each fix with a fresh read of that server'],
      sources: ['Database inventory (read-only logins proven by Asset Discovery; fixed SELECT-only queries)', 'Business Services (servers running a database without a login yet)'],
      alone: DUTY_ALONE.concat(['Re-read one server to verify a fix']),
      approvals: [],
      cannot: ['Connect to a database to change it (the logins are read-only and the queries are fixed SELECTs)', 'Run the statements it recommends - a DBA decides and applies', 'Retry a refused login on its own (no lockout)', 'Call a server healthy when it could not be read'],
      people: DUTY_PEOPLE,
      escalation: ['Database offline and no backup are high → AI CISO risk register (resilience)'],
      kpis: ['Servers that cannot be read', 'Databases without a recent full backup', 'Open high problems'] },

    { id: 'apps', name: 'AI Application Manager', title: 'Application / Service Owner assistant', reports: 'AI CISO → Head of Applications', engine: 'SIEM', page: 'ai-app-manager.html', icon: '📦', duty: true,
      mission: 'See every business service the way its owner should: is it up, does it still have redundancy, is there a working DR copy, are its servers under pressure.',
      resp: ['Service down, running without redundancy, single point of failure, no or offline DR copy', 'Disk / CPU / memory pressure and unexpected shutdowns on production servers', 'Business-critical services ranked one level higher'],
      sources: ['Server Availability (services set by an administrator, otherwise grouped by server name)'],
      alone: DUTY_ALONE,
      approvals: [],
      cannot: ['Restart, fail over or change anything', 'Propose an application change for automatic execution — the application owner decides'],
      people: DUTY_PEOPLE,
      escalation: ['Service down is critical → AI CISO risk register; DR gaps feed DR & BCM drill planning'],
      kpis: ['Services down / without redundancy', 'Single points of failure', 'Services without DR'] },

    { id: 'pentest', name: 'AI Penetration Testing Engineer', title: 'Penetration Tester (attack surface)', reports: 'AI CISO → CISO', engine: 'IT Asset Management', page: 'pentest.html', icon: '🗡️', duty: true,
      mission: 'Know the attack surface at all times — every exposed service and weak configuration the inventory shows — and run authorised engagements under strict two-person control.',
      resp: ['Attack-surface findings from the asset inventory and discovery (open ports, internet-facing services, weak protocols)', 'An explainable risk score per finding and how to verify it in an authorised test', 'Engagement records, findings and reports for the compliance packs'],
      sources: ['Asset inventory and Asset Discovery (read-only scope)'],
      alone: DUTY_ALONE.concat(['Assess the inventory — passive, from data already collected']),
      approvals: [{ action: 'Penetration test engagement', req: 'Administrator creates it and records the manager\'s written authorisation (reference + safety checklist)', appr: 'A second administrator — not the one who authorised it', exec: 'People run the test; the platform never starts one' }],
      cannot: ['Start a test, open a connection or scan on its own', 'Test outside an approved engagement'],
      people: [['Create / authorise / approve engagements, add findings, close', 'admin']].concat(DUTY_PEOPLE),
      escalation: ['Internet-facing critical exposures → AI CISO risk register (exposure)'],
      kpis: ['Critical / high exposures', 'Internet-facing assets with findings', 'Engagements completed'] },

    { id: 'desktop', name: 'AI Desktop Support Engineer', title: 'Desktop Support / Endpoint Engineer', reports: 'AI CISO → IT Service Desk lead', engine: 'IT Asset Management', page: 'desk-support.html', icon: '🧑‍💻', duty: true,
      mission: 'Keep end-user devices healthy and patched: find the device that stopped reporting or misses critical patches, and request the fix the way a technician would.',
      resp: ['Agents not reporting, missing critical patches, vulnerable devices (Endpoint Central)', 'Requests the patch installation for approval', 'Follows the deployment and verifies (a deployment under 24 h old is "in progress", not failed)'],
      sources: ['ManageEngine Endpoint Central', 'ServiceDesk Plus'],
      alone: DUTY_ALONE.concat(['Request a patch installation (it never approves it)']),
      approvals: [{ action: 'Patch installation on devices', req: 'AI Desktop Support Engineer (as duty:desktop) or an operator', appr: 'Administrator — not the requester', exec: 'Endpoint Central installs automatically once approved (the only installation the platform triggers)' }],
      cannot: ['Approve its own request', 'Install anything without an administrator\'s approval', 'Change a device outside Endpoint Central'],
      people: [['Request a patch installation', 'operator'], ['Approve a patch installation', 'admin (not the requester)']].concat(DUTY_PEOPLE),
      escalation: ['Critical patch gaps → AI CISO risk register; tickets to the service desk'],
      kpis: ['Devices missing critical patches', 'Agents not reporting', 'Patch deployments verified'] },

    { id: 'grc', name: 'AI GRC Consultant', title: 'GRC / Compliance Consultant', reports: 'AI CISO → CISO / Head of GRC', engine: 'IT Asset Management', page: 'ai-grc-consultant.html', icon: '⚖️', duty: true,
      mission: ('Keep ' + ZYB_ORG.short + ' audit-ready for SAMA CSF, NCA ECC, PDPL, the Insurance Authority and ISO 27001: find every compliance gap in the platform\'s own records, say what to do and which clause it touches, and follow it until the gap is closed.'),
      resp: ['Failing or partly met automated GRC controls', 'Policies past their review date', 'Insurance Authority requirements not covered or partly covered by a policy', 'DR / BCM drills overdue, failed or not signed off', 'Assets without a business or IT owner', 'SAMA CSF gaps read from the SIEM through the AI CISO', 'A compliance roadmap (now / next / later) and answers to compliance questions, citing the records'],
      sources: ['GRC policy register, control automation, Insurance Authority crosswalk, DR & BCM drills', 'Asset Ownership', 'SAMA CSF assessment (SIEM, through the AI CISO)'],
      alone: DUTY_ALONE.concat(['Answer compliance questions from the records, citing them (an invented reference is removed)']),
      approvals: [],
      cannot: ['Approve, publish or retire a policy (an administrator decides drafts)', 'Sign off a drill (a second administrator who did not run it)', 'Attest compliance or record a policy review on anyone\'s behalf', 'Call a control compliant when it is not measured (shown as unknown)'],
      people: [['Ask the consultant', 'operator']].concat(DUTY_PEOPLE),
      escalation: ['High gaps (failing controls, uncovered requirements, overdue drills) → AI CISO governance / compliance / resilience scores and the morning brief'],
      kpis: ['Open compliance gaps by severity', 'Policies overdue for review', 'Requirements not covered', 'Assets with both owners (%)'] },
    { id: 'itaudit', name: 'AI IT Auditor', title: 'IT Auditor (IT general controls)', reports: 'Head of IT & Cyber Security Audit (independent of IT operations)', engine: 'IT Asset Management', page: 'ai-auditors.html#itaudit', icon: '🔎', duty: true,
      mission: 'Test, independently and every patrol, that the IT general controls actually work — including the controls around the AI engineers and their human approvers — and report every exception with evidence until the re-test passes.',
      resp: ['Audit trail complete and unaltered (hash chain)', 'Segregation of duties: every approval by a different, named person, never by a service or AI identity', 'Every AI engineer that proposes changes has a named human approver', 'Asset register complete (serial numbers, owners) and matching the network (reconciliation)', 'Backup coverage and last result', 'Critical patch compliance', 'Supplier support contracts current', 'Policies within their review cycle', 'DR / BCM drills on time, passed and signed off', 'Oracle licences within entitlement', 'Leavers handed over and access removed', 'Equipment under warranty', 'Storage healthy with room to grow', 'Issues a formal audit report: opinion, findings (condition, criteria, effect, recommendation, owner), limitations, sign-off'],
      sources: ['Audit trail', 'Patch install and virtualization change approvals', 'Roles & Functions', 'Asset register and ownership', 'Backup Status, Endpoint Central, Support Contracts'],
      alone: DUTY_ALONE.concat(['Run its audit programme: each test is pass, fail or NOT TESTED (no evidence is never a pass); a finding stays open while its test cannot run']),
      approvals: [],
      cannot: ['Change, approve or reject anything — it is read-only and independent of the people it audits', 'Close its own finding: the owning department fixes, the re-test closes it, or a person records a risk acceptance with a reason', 'Call a control effective when its source is not connected'],
      people: DUTY_PEOPLE,
      escalation: ['High findings (four-eyes breaches, broken audit trail, failed backups) → the owning department head and the AI CISO morning brief'],
      kpis: ['Tests passed / tested (%)', 'Tests not tested (no evidence)', 'Open audit findings by severity', 'Time from finding to passed re-test'] },
    { id: 'cyberaudit', name: 'AI Cyber Security Auditor', title: 'Cyber Security Auditor', reports: 'Head of IT & Cyber Security Audit (independent of the CISO\'s operations)', engine: 'IT Asset Management', page: 'ai-auditors.html#cyberaudit', icon: '🛡️', duty: true,
      mission: 'Test, independently, that the cyber security controls are operating: exposure is handled, testing is on time, logs reach the SIEM, credentials are protected, proposals are decided and the AI engineers are on duty.',
      resp: ['End-of-life systems isolated or excepted', 'Penetration tests and VAPT on time (critical quarterly, others twice a year)', 'Serious problems fixed within the SLA (all AI engineers, both engines)', 'Proposals and SOC response actions decided in time', 'Required assets sending logs to the SIEM', 'Stored credentials sealed, key in custody', 'Every AI engineer on duty and patrolling', 'SAMA CSF controls evidenced', 'Critical alerts handled within the SLA', 'Nothing critical exposed to the internet', 'Every log sender a known asset', 'Trusted device identities unchanged (SSH host keys, TLS certificates)', 'No stored secret leaked into server files', 'Domains and certificates valid, hosting in the Kingdom (PDPL)', 'Computers reporting to endpoint management', 'Issues a formal audit report with an opinion and sign-off'],
      sources: ['End of Life', 'Security testing schedule', 'SIEM: log-flow assurance, SOC approvals, AI engineers (through the AI CISO)', 'Credential evidence', 'Duty desks of both engines'],
      alone: DUTY_ALONE.concat(['Run its audit programme: each test is pass, fail or NOT TESTED; a finding stays open while its test cannot run']),
      approvals: [],
      cannot: ['Change, approve, isolate or block anything — read-only', 'Close its own finding (re-test or a person\'s recorded risk acceptance)', 'Call a control effective when its source is not connected'],
      people: DUTY_PEOPLE,
      escalation: ['Critical findings (SIEM collector silent, unisolated end-of-life servers) → Cyber Security and the AI CISO'],
      kpis: ['Tests passed / tested (%)', 'Tests not tested (no evidence)', 'Open audit findings by severity', 'Findings past the SLA'] },
    { id: 'pki', name: 'AI PKI Engineer', title: 'PKI / Certificate Engineer', reports: 'CISO (Cyber Security)', engine: 'IT Asset Management (rules in Python)', page: 'certificates.html', icon: '🔐', duty: true,
      mission: 'Keep every SSL / TLS certificate known, valid and renewed before it expires.',
      resp: ['Certificate inventory read every 6 hours (issuer, names, key, chain, expiry)', 'Renewal due by issuer lead time: ACME, AD CS, ordered by hand', 'Expired and expiring certificates, weak keys, names not covered, untrusted public chains, self-signed on critical services', 'Renewals confirmed only by a scan that sees the new certificate', 'Discovery of certificates on the register\'s networked assets (proposals)', 'Issuance through ACME, AD CS or an ordered certificate: key and CSR on the platform, sealed; every certificate checked against its key and names', 'Automatic renewal of flagged endpoints with the same names'],
      sources: ['TLS handshake with each endpoint (nothing sent to the service)', 'Asset register', 'Domains & Hosting'],
      alone: DUTY_ALONE.concat(['Read every registered certificate and raise each lifecycle problem as a work item']),
      approvals: [],
      cannot: ['Request a name the endpoint does not present, or a wildcard, without a second person\'s approval', 'Install or revoke a certificate (phase 3 installation is not built; it will be a change plan a second person approves)', 'Return or log a private key (an administrator exports one with a reason, audited)', 'Mark a renewal verified by hand'],
      people: DUTY_PEOPLE,
      escalation: ['An expired certificate on a critical service → Cyber Security and the owner at once'],
      kpis: ['Certificates expired', 'Renewals done before the lead time', 'Weak keys', 'Endpoints not read'] },
    { id: 'pdpl', name: 'AI PDPL Consultant', title: 'Personal Data Protection Consultant', reports: 'Data Protection Officer, with Governance, Risk & Compliance', engine: 'IT Asset Management (rules in Python)', page: 'ai-pdpl.html', icon: '🔏', duty: true,
      mission: 'Oversee compliance with the Saudi Personal Data Protection Law (SDAIA): keep the registers honest, raise every gap, and prepare the compliance statement the DPO signs.',
      resp: ['Records of processing complete and reviewed', 'A valid legal basis per activity; explicit consent where required; no legitimate interest on sensitive data', 'Impact assessments before high-risk processing', 'Data subject requests answered within 30 days (one notified 30-day extension)', 'Breaches notified to SDAIA within 72 hours and to data subjects when harm is likely', 'Processor agreements with the required terms, assessed yearly', 'Transfers outside the Kingdom with a basis and risk assessment', 'Retention periods set', 'Security measures (through the AI auditors\' tests)', 'The compliance statement: prepared, never signed by the consultant'],
      sources: ['PDPL registers: profile, processing, requests, breaches, impact assessments, processors, transfers', 'AI auditors\' security tests', 'Domains & Hosting (sites hosted outside the Kingdom)'],
      alone: DUTY_ALONE.concat(['Check the 24 PDPL requirements every patrol and raise each gap as a work item for Governance']),
      approvals: [],
      cannot: ['Sign or countersign the compliance statement', 'Confirm a requirement (a named person records the evidence)', 'Call the organisation certified - the statement is an internal self-assessment, not an SDAIA certificate', 'Read or store a data subject\'s details (requests are kept as references only)'],
      people: DUTY_PEOPLE,
      escalation: ['A breach not notified within 72 hours, or legitimate interest on health data → the DPO and the CISO at once'],
      kpis: ['Requirements confirmed (%)', 'Requests answered within 30 days', 'Breaches notified within 72 hours', 'Open gaps by severity', 'Statement signed and current'] }
  ];

  /* the platform approval matrix: every decision that needs a person, as enforced in code */
  var MATRIX = [
    ['PDPL compliance statement', 'AI PDPL Consultant prepares it', 'The appointed DPO signs, then a different person in management countersigns', 'Yes — the countersigner is not the DPO', 'Nothing is executed; lapses when a requirement stops holding', 'AI PDPL Consultant'],
    ['Network / firewall change plan', 'AI engineer or operator', 'Administrator', 'Yes — not who asked', 'A person, by hand; re-poll validates', 'AI Network / Security Engineer'],
    ['Windows / Exchange change plan', 'AI administrator (asked by an operator) or operator', 'Administrator', 'Yes — not who asked', 'A person, by hand; re-check validates', 'AI Server Administrators'],
    ['SOC response action (isolate, disable account, block)', 'Playbook on a case', 'Administrator', 'Yes — not the requester', 'A person or a separately approved tool; the SIEM executes nothing', 'Playbooks & Approvals'],
    ['Patch installation', 'AI Desktop Support or operator', 'Administrator', 'Yes — not the requester', 'Endpoint Central, automatically after approval', 'AI Desktop Support'],
    ['Penetration test engagement', 'Administrator, with the manager\'s written authorisation', 'Second administrator', 'Yes — not the authoriser', 'People run the test', 'AI Penetration Testing'],
    ['End-of-life device isolation', 'Administrator', 'Listed approver (CISO) or administrator', 'Yes — not the requester', 'FortiGate quarantine on approval when configured, otherwise by hand', 'End of Life & Isolation'],
    ['DR / BCM drill sign-off', 'Operator records the result', 'Administrator', 'Yes — not who ran the drill', '—', 'DR & BCM Drills'],
    ['Policy draft approval / publication', 'Operator drafts (the AI GRC Consultant only recommends)', 'Administrator', '—', 'The policy owner publishes the approved version', 'GRC Policies'],
    ['Virtualization change plan', 'AI Virtualization Administrator or operator', 'Administrator', 'Yes - not the requester', 'A person in vCenter / Prism; the next collection verifies', 'AI Virtualization Administrator'],
    ['Stop SIEM log collection for an asset', 'Administrator (reason, confirmation)', '—', '—', 'Paused while it still sends; removed after 24 h quiet; never enrolled again automatically', 'Asset inventory / Log Flow Assurance'],
    ['Duty policy (patrol, AI budget, tickets)', '—', 'Administrator', '—', 'Applies to the AI engineers at once', 'AI Engineering Team'],
    ['Close / snooze / accept risk on a work item', 'Operator', '— (reason and close code required, recorded)', '—', '—', 'Every duty desk'],
    ['Close an audit finding (risk accepted / false positive)', 'Owning department operator', '— (reason and close code required; the auditor re-tests a fix itself)', 'The auditor never closes its own finding', '—', 'AI Auditors']
  ];
  var ROLES = [['viewer', 'Reads dashboards, work items, reports and briefs'], ['analyst', 'Viewer + asks the AI administrators questions'],
    ['operator', 'Works items (assign, note, snooze, close, ticket), requests changes and patch installs, runs patrols and briefs'],
    ['admin', 'Operator + approves change plans, patch installs, response actions, engagements and sign-offs — never their own request — and sets policy']];

  function list() { return C.slice(); }
  function get(id) { for (var i = 0; i < C.length; i++) if (C[i].id === id) return C[i]; return null; }
  function ul(a) { return a && a.length ? '<ul style="margin:4px 0 10px;padding-left:18px">' + a.map(function (x) { return '<li style="margin:2px 0">' + esc(x) + '</li>'; }).join('') + '</ul>' : '<p style="margin:4px 0 10px;opacity:.75">None.</p>'; }
  function h(t) { return '<h4 style="margin:14px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;opacity:.8">' + esc(t) + '</h4>'; }
  function tbl(head, rows) { return '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:12.5px"><thead><tr>' + head.map(function (x) { return '<th style="text-align:left;padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.15);white-space:nowrap">' + esc(x) + '</th>'; }).join('') + '</tr></thead><tbody>'
    + rows.map(function (r) { return '<tr>' + r.map(function (x) { return '<td style="padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top">' + esc(x) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>'; }
  function html(id) {
    var c = get(id); if (!c) return '<p>No charter for this engineer.</p>';
    return '<p style="margin:0 0 6px"><b>' + esc(c.title) + '</b></p><p style="margin:0 0 4px;opacity:.85">Reports to: ' + esc(c.reports) + ' · Runs in: ' + esc(c.engine) + (c.duty ? ' · on duty 24/7 (patrols every 10 min)' : '') + '</p>'
      + h('Mission') + '<p style="margin:4px 0 10px">' + esc(c.mission) + '</p>'
      + h('Responsibilities') + ul(c.resp) + h('Data it works from') + ul(c.sources)
      + h('Does on its own') + ul(c.alone)
      + h('Needs approval') + (c.approvals.length ? tbl(['Action', 'Requested by', 'Approved by', 'Carried out by'], c.approvals.map(function (a) { return [a.action, a.req, a.appr, a.exec]; })) : '<p style="margin:4px 0 10px">Nothing — it only recommends; it never proposes a change for execution.</p>')
      + h('Never does') + ul(c.cannot)
      + h('What people do with its work (portal role)') + tbl(['Action', 'Role'], c.people)
      + h('Escalation') + ul(c.escalation) + h('Measured by') + ul(c.kpis)
      + '<p style="font-size:12px;opacity:.7;margin-top:12px">Every approval above is enforced by the platform (role checks and four-eyes: nobody approves their own request). Full matrix: AI Engineering Team → Roles &amp; approvals.</p>';
  }
  function matrix() { return tbl(['Decision', 'Requested by', 'Approved by', 'Four-eyes', 'Carried out by', 'Where'], MATRIX); }
  function roles() { return tbl(['Portal role', 'May'], ROLES); }
  window.zybCharter = { list: list, get: get, html: html, matrix: matrix, roles: roles };
})();
