# Sentra - code map

A snapshot taken on 2026-11-23, when this tree was created. It is not regenerated automatically: update it by hand when a page or module is added.

## How a page gets its data

```
All dashboards (ui/index.html) + the menu (ui/vendor/zyb-nav.js)
  -> a page (ui/<page>.html) + shared scripts (ui/vendor/*.js)
     -> /api/itam/...  -> backend/itam/engine/<module>.js  -> /var/lib/sentra-itam (store collections)
     -> /api/soc/...   -> backend/siem/engine/<module>/...  -> /var/lib/sentra-siem (state) + ClickHouse database siem
```

## Summary

| Component | Live files | Unused (left out) | Tests kept | Tests dropped |
|---|---|---|---|---|
| Portal pages (UI) | 469 | 1 | 0 | 0 |
| IT Asset Management engine | 528 | 11 | 359 | 3 |
| SIEM / SOC engine | 472 | 156 | 181 | 1 |
| Update / deploy scripts | 12 | 22 | 0 | 0 |
| Page tests | 0 | 0 | 416 | 3 |

Pages: 351 live of 352 HTML files · backend routes: 2436 (1128 called by a page; the rest are background jobs, agents, collectors and admin APIs - not unused)

## Pages

| Menu group | Page | Title | Backend modules | Data |
|---|---|---|---|---|
| (not in the menu) | `node-details.html` |  | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| (not in the menu) | `oracle-licence-report.html` |  | `itam:engine/oracle-licences.js` | sentra-itam store: core_lic_facts<br>sentra-itam store: assets<br>sentra-itam store: oracle_cf_table<br>sentra-itam store: ora_lic_alerts<br>sentra-itam store: ora_lic_reports |
| (not in the menu) | `threats-by-department.html` |  | `siem:engine/soc/departments.js` | ClickHouse (siem) |
| AI & Automation | `ai-app-manager.html` | AI Application Manager | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| AI & Automation | `ai-auditors.html` | AI Auditors | `itam:engine/auditors.js`<br>`itam:engine/audit-checklist.js` | sentra-itam store: audit_checklist<br>sentra-itam store: audit_pbc |
| AI & Automation | `ai-ciso.html` | AI CISO | `itam:engine/ciso.js` | sentra-itam store: ciso_briefs<br>sentra-itam store: ciso_history |
| AI & Automation | `ai-dba.html` | AI Oracle DBA | `siem:engine/db-audit/connections-intel.js` | ClickHouse (siem) |
| AI & Automation | `ai-engine.html` | AI Engine | `itam:engine/ai-engine.js`<br>`siem:engine/aiengine/routes.js`<br>`siem:engine/collect/cloud-data-routes.js` | sentra-itam store: ai_backend<br>sentra-siem state: ai_backend |
| AI & Automation | `ai-findings.html` | AI Findings | `itam:engine/findings-intel.js`<br>`itam:engine/routes.js` | sentra-itam store: findings<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| AI & Automation | `ai-governance.html` | AI Governance | `itam:engine/aigov-intel.js` | sentra-itam store: aigov_usage<br>sentra-itam store: aigov_reviews<br>sentra-itam store: aigov_control<br>sentra-itam store: aigov_sanctioned<br>sentra-itam store: assets |
| AI & Automation | `ai-grc-consultant.html` | AI GRC Consultant | `itam:engine/grc-consultant.js` | sentra-itam store: grc_consults |
| AI & Automation | `ai-ksc-engineer.html` | AI Endpoint (Kaspersky) | `siem:engine/ksc/routes.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`itam:engine/discovery/routes.js` | — |
| AI & Automation | `ai-lineage.html` | AI Data Lineage | `itam:engine/ai-lineage.js` | — |
| AI & Automation | `ai-pdpl.html` | AI PDPL Consultant | `itam:engine/data-map.js`<br>`itam:engine/pdpl.js`<br>`itam:engine/pdpl-workflows.js`<br>`itam:engine/pdpl-consent.js`<br>`itam:engine/pdpl-retention.js` | sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>sentra-itam store: pdpl_statement<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: pdpl_consent_meta<br>sentra-itam store: pdpl_consent_keys<br>… |
| AI & Automation | `ai-pentest.html` | AI Penetration Testing | `itam:engine/ai-pentest.js` | sentra-itam store: aip_state<br>sentra-itam store: aip_hist<br>sentra-itam store: aip_proposals<br>sentra-itam store: pentest_settings<br>sentra-itam store: test_tier<br>sentra-itam store: assets<br>… |
| AI & Automation | `ai-security-engineer.html` | AI Security Engineer | `siem:engine/netops/routes.js`<br>`siem:engine/compliance/sama-intel-routes.js` | sentra-siem state: nac_hist |
| AI & Automation | `ai-security.html` | AI Security | `siem:engine/soc/ai-security-routes.js` | — |
| AI & Automation | `ai-soc-analyst.html` | AI SOC Analyst | `siem:engine/soc/copilot-routes.js` | — |
| AI & Automation | `ai-sql-dba.html` | AI Database Administrator | `itam:engine/sqldba.js` | sentra-itam store: db_inventory |
| AI & Automation | `ai-team.html` | Team Overview | `siem:engine/duty/routes.js`<br>`itam:engine/duty.js`<br>`itam:engine/roles.js` | sentra-itam store: me_ec_computers<br>sentra-itam store: desk_patch<br>sentra-itam store: virt_capacity<br>sentra-itam store: job_roles<br>sentra-itam store: role_assignments |
| AI & Automation | `ai-virt-admin.html` | AI Virtualization Admin | `itam:engine/virt-admin.js`<br>`itam:engine/duty.js`<br>`itam:engine/virt-ai.js` | sentra-itam store: virt_capacity<br>sentra-itam store: virt_changes<br>sentra-itam store: virt_admin_cfg<br>sentra-itam store: counters<br>sentra-itam store: me_ec_computers<br>sentra-itam store: desk_patch |
| AI & Automation | `ai-zscaler-engineer.html` | AI Zscaler Engineer | `siem:engine/zscaler/routes.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`itam:engine/discovery/routes.js` | — |
| AI & Automation | `aiops.html` | AIOps Center | `siem:engine/soc/routes.js`<br>`siem:engine/xdr/routes.js`<br>`siem:engine/duty/routes.js`<br>`itam:engine/duty.js`<br>`itam:engine/virt-capacity.js` | sentra-itam store: me_ec_computers<br>sentra-itam store: desk_patch<br>sentra-itam store: virt_capacity<br>sentra-itam store: core_lic_facts<br>sentra-itam store: virt_platforms<br>sentra-itam store: virt_capacity_hist<br>… |
| AI & Automation | `automation-org.html` | Organisation & Automation | `siem:engine/duty/routes.js`<br>`itam:engine/duty.js`<br>`itam:engine/roles.js`<br>`itam:engine/auditors.js` | sentra-itam store: me_ec_computers<br>sentra-itam store: desk_patch<br>sentra-itam store: virt_capacity<br>sentra-itam store: job_roles<br>sentra-itam store: role_assignments |
| AI & Automation | `desk-support.html` | AI Desktop Support | `itam:engine/desksupport.js` | sentra-itam store: me_config<br>sentra-itam store: me_ec_computers<br>sentra-itam store: desk_config<br>sentra-itam store: desk_triage<br>sentra-itam store: desk_patch<br>sentra-itam store: assets |
| AI & Automation | `exchange-admin.html` | AI Exchange Admin | — | — |
| AI & Automation | `network-engineer.html` | AI Network Engineer | `siem:engine/netops/routes.js`<br>`siem:engine/compliance/sama-intel-routes.js`<br>`itam:engine/discovery/routes.js`<br>`siem:engine/integrations/routes.js`<br>`itam:engine/routes.js` | sentra-siem state: nac_hist<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| AI & Automation | `pentest.html` | AI Pentest Engineer | `itam:engine/pentest.js`<br>`itam:engine/routes.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-itam store: pentest_engagements<br>sentra-itam store: pentest_findings<br>sentra-itam store: pentest_settings<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: test_records<br>… |
| AI & Automation | `private-ai.html` | Private AI Server | `itam:engine/private-ai.js` | sentra-itam store: private_ai<br>sentra-itam store: private_ai_changes |
| AI & Automation | `risk-flow.html` | AI Risk Automation Flow | `itam:engine/business-risk.js`<br>`itam:engine/risk-command.js`<br>`itam:engine/risk-officer.js` | — |
| AI & Automation | `shadow-ai.html` | Shadow AI DLP | `siem:engine/soc/shadow-ai-routes.js` | — |
| AI & Automation | `windows-admin.html` | AI Windows Admin | — | — |
| Applications & Business Services | `apm-claims-portal.html` | Claims Portal (APM) | `siem:engine/integrations/apm-routes.js` | — |
| Applications & Business Services | `apm.html` | Applications Manager | `siem:engine/integrations/apm-routes.js` | — |
| Applications & Business Services | `applications.html` | All Applications | `siem:engine/netops/routes.js`<br>`itam:engine/ownership.js` | sentra-siem state: nac_hist<br>sentra-itam store: asset_ownership<br>sentra-itam store: ownership_services |
| Applications & Business Services | `browsing-monitor.html` | Browsing Traffic | `siem:engine/soc/browsing.js` | ClickHouse (siem) |
| Applications & Business Services | `business-services.html` | Business Services | `itam:engine/service-map.js` | sentra-itam store: disc_devices<br>sentra-itam store: assets<br>sentra-itam store: disc_trust<br>sentra-itam store: disc_scopes<br>sentra-itam store: svc_map<br>sentra-itam store: svc_decisions<br>… |
| Applications & Business Services | `portal-traffic.html` | Portal Traffic | `siem:engine/soc/webtraffic.js` | ClickHouse (siem) |
| Applications & Business Services | `synthetic.html` | Synthetic & Apdex | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Applications & Business Services | `webapps.html` | Applications, Web Servers & APIs | `siem:engine/integrations/webtier-routes.js`<br>`itam:engine/service-map.js`<br>`itam:engine/cert-autodiscover.js` | sentra-itam store: disc_devices<br>sentra-itam store: assets<br>sentra-itam store: disc_trust<br>sentra-itam store: disc_scopes<br>sentra-itam store: svc_map<br>sentra-itam store: svc_decisions<br>… |
| Audit & Assurance | `ad-audit.html` | AD Audit | `siem:engine/ad/routes.js`<br>`siem:engine/api/routes.js`<br>`siem:engine/soc/adchanges-routes.js` | ClickHouse (siem) |
| Audit & Assurance | `app-audit.html` | Application Audit | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Audit & Assurance | `audit-analytics.html` | Audit Analytics | `itam:engine/audit-analytics.js` | sentra-itam store: aa_datasets<br>sentra-itam store: aa_rows<br>sentra-itam store: aa_runs<br>sentra-itam store: aa_scripts |
| Audit & Assurance | `audit-ccm.html` | Control Monitoring | `itam:engine/audit-ccm.js` | — |
| Audit & Assurance | `audit-command.html` | Audit Command Center | `itam:engine/audit-auto.js`<br>`siem:engine/integrations/routes.js` | — |
| Audit & Assurance | `audit-dashboard.html` | Audit Dashboard | `itam:engine/workflow-auto.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters |
| Audit & Assurance | `audit-flow.html` | Audit Automation Flow | `itam:engine/automation-flow.js` | — |
| Audit & Assurance | `audit-inspections.html` | IT Audit Inspections | `itam:engine/audit-inspect.js`<br>`itam:engine/routes.js`<br>`siem:engine/dataopt/api.js` | sentra-itam store: insp_templates<br>sentra-itam store: insp_schedules<br>sentra-itam store: insp_inspections<br>sentra-itam store: insp_actions<br>sentra-itam store: insp_evidence<br>sentra-itam store: assets<br>… |
| Audit & Assurance | `audit-log.html` | Audit Log | `siem:engine/itaudit/routes.js` | ClickHouse (siem) |
| Audit & Assurance | `audit-repo.html` | Audit Repository | — | — |
| Audit & Assurance | `audit-reports.html` | Audit Reports | `itam:engine/audit-report.js` | sentra-itam store: audit_reports |
| Audit & Assurance | `audit-start.html` | Start an Audit | `siem:engine/collect/webhook-ingest.js`<br>`itam:engine/routes.js`<br>`itam:engine/roles.js` | sentra-siem state: webhooks<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans<br>sentra-itam store: job_roles<br>sentra-itam store: role_assignments |
| Audit & Assurance | `audit-team.html` | IT Audit Team | — | — |
| Audit & Assurance | `cyber-audit-team.html` | Cyber Security Audit Team | — | — |
| Audit & Assurance | `db-audit.html` | Database Audit | `siem:engine/db-audit/routes.js` | ClickHouse (siem) |
| Audit & Assurance | `dept-checklist.html` | Department Checklist | — | — |
| Audit & Assurance | `evidence-packs.html` | Regulator Evidence Packs | `itam:engine/evidence-packs.js` | sentra-itam store: evidence_packs<br>sentra-itam store: evidence_pack_job<br>sentra-itam store: grc_evidence<br>sentra-itam store: grc_files<br>sentra-itam store: sama_runs |
| Audit & Assurance | `internal-audit-team.html` | Internal Audit Team | — | — |
| Audit & Assurance | `it-audit.html` | IT Audit | `siem:engine/netops/routes.js`<br>`siem:engine/sysadmin/routes.js`<br>`siem:engine/ksc/routes.js`<br>`siem:engine/zscaler/routes.js`<br>`siem:engine/itaudit/routes.js` | sentra-siem state: nac_hist<br>ClickHouse (siem) |
| Audit & Assurance | `licence-audit.html` | Licensing Audit | `itam:engine/core-licensing.js`<br>`itam:engine/licence-sync.js`<br>`siem:engine/collect/m365-routes.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`siem:engine/ad/routes.js`<br>`itam:engine/routes.js` | sentra-itam store: core_lic_facts<br>sentra-itam store: core_lic_entitlements<br>sentra-itam store: core_lic_settings<br>sentra-itam store: assets<br>sentra-itam store: relationships<br>sentra-itam store: disc_devices<br>… |
| Audit & Assurance | `nca-it-audit.html` | NCA IT Audit | — | — |
| Audit & Assurance | `network-config-audit.html` | Network Config Audit | `itam:engine/netcfg-intel.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-siem state: webhooks |
| Audit & Assurance | `sama-audit.html` | SAMA CSF Audit | `itam:engine/sama-audit.js` | — |
| Audit & Assurance | `sama-it-audit.html` | SAMA IT Audit | `itam:engine/sama-itaudit.js` | sentra-itam store: sama_itaudit_hist<br>sentra-itam store: pentest_settings<br>sentra-itam store: test_tier<br>sentra-itam store: assets |
| Audit & Assurance | `sql-audit.html` | SQL Server Audit | `siem:engine/db-audit/mssql-routes.js` | — |
| Business Risk | `business-risk-register.html` | Risk Register | `itam:engine/business-risk.js`<br>`itam:engine/risk-programme.js` | — |
| Business Risk | `business-risk-years.html` | Register by Year | `itam:engine/business-risk.js` | — |
| Business Risk | `business-risk.html` | Business Risk Dashboard | `itam:engine/workflow-auto.js`<br>`itam:engine/business-risk.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters<br>sentra-siem state: webhooks |
| Business Risk | `enterprise-risk.html` | Enterprise Risk Dashboard | `itam:engine/business-risk.js`<br>`itam:engine/risk-programme.js`<br>`itam:engine/workflow-auto.js`<br>`itam:engine/risk-command.js`<br>`itam:engine/risk-officer.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters |
| Business Risk | `erm-capital.html` | Capital, ORSA & Stress Testing | `itam:engine/erm-capital.js`<br>`itam:engine/routes.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Business Risk | `erm-governance.html` | Risk Governance & Models | `itam:engine/erm-governance.js` | — |
| Business Risk | `pricing-adequacy.html` | Pricing Adequacy | — | — |
| Business Risk | `ras-cockpit.html` | Risk Appetite Cockpit | `itam:engine/business-risk.js` | — |
| Business Risk | `ras-manage.html` | RAS Management | `itam:engine/risk-programme.js`<br>`itam:engine/business-risk.js` | — |
| Business Risk | `rbc-assessment.html` | RBC Assessment | — | — |
| Business Risk | `rcsa.html` | RCSA Collection | — | — |
| Business Risk | `risk-appetite.html` | Risk Appetite (RAS) | `itam:engine/business-risk.js`<br>`itam:engine/routes.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Business Risk | `risk-catalogue.html` | Insurance Risk Catalogue | `itam:engine/risk-programme.js` | — |
| Business Risk | `risk-cycle.html` | Risk Assessment Cycle | `itam:engine/risk-programme.js` | — |
| Business Risk | `risk-reports.html` | Risk Reports | `itam:engine/risk-programme.js` | — |
| Business Risk | `risk-start.html` | Start a Risk Assessment | `itam:engine/business-risk.js`<br>`itam:engine/routes.js`<br>`itam:engine/roles.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans<br>sentra-itam store: job_roles<br>sentra-itam store: role_assignments |
| Business Risk | `solvency-capital.html` | Solvency & Capital | `itam:engine/solvency.js`<br>`itam:engine/solvency-collect.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`siem:engine/bas/routes.js` | sentra-itam store: sca_returns<br>sentra-itam store: sca_cycles<br>sentra-siem state: webhooks<br>ClickHouse (siem) |
| Command & Leadership | `cio-dashboard.html` | CIO Dashboard | `itam:engine/budget.js`<br>`itam:engine/ciso.js`<br>`itam:engine/support-contracts.js`<br>`itam:engine/routes.js`<br>`siem:engine/integrations/apm-routes.js`<br>`itam:engine/workflow-auto.js` | sentra-itam store: budget_settings<br>sentra-itam store: budget_previous<br>sentra-itam store: budget_lines<br>sentra-itam store: assets<br>sentra-itam store: budget_years<br>sentra-itam store: licences<br>… |
| Command & Leadership | `ciso-dashboard.html` | CISO Dashboard | `itam:engine/workflow-auto.js`<br>`itam:engine/ciso.js`<br>`siem:engine/integrations/routes.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters<br>sentra-itam store: ciso_briefs<br>sentra-itam store: ciso_history |
| Command & Leadership | `custom-dashboards.html` | Custom Dashboards | `itam:engine/dash-builder.js` | sentra-itam store: dash_boards<br>sentra-itam store: dash_hist<br>sentra-itam store: assets<br>sentra-itam store: vulnscan_findings<br>sentra-itam store: fc_findings |
| Command & Leadership | `executive-dashboard.html` | Executive Dashboard | `itam:engine/workflow-auto.js`<br>`itam:engine/exec-dashboard.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters<br>sentra-itam store: exec_hist |
| Command & Leadership | `head-of-it.html` | IT Command Center | `itam:engine/infra-overview.js`<br>`itam:engine/cert-autodiscover.js`<br>`itam:engine/routes.js`<br>`siem:engine/netops/routes.js`<br>`siem:engine/db-audit/connections-intel.js`<br>`siem:engine/integrations/apm-routes.js`<br>`siem:engine/duty/routes.js`<br>`siem:engine/sysadmin/routes.js`<br>`itam:engine/workflow-auto.js` | sentra-itam store: assets<br>sentra-itam store: cert_autodisc<br>sentra-itam store: cert_autodisc_seen<br>sentra-itam store: disc_devices<br>sentra-itam store: cert_endpoints<br>sentra-itam store: ai_results<br>… |
| Command & Leadership | `infra-ai.html` | Infrastructure Automation AI | — | — |
| Command & Leadership | `infra-inventory.html` | Infrastructure Inventory | `itam:engine/infra-inventory.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-itam store: assets<br>sentra-siem state: webhooks |
| Command & Leadership | `infra-manager.html` | IT Infrastructure Manager | `itam:engine/infra-overview.js`<br>`siem:engine/netops/routes.js`<br>`siem:engine/db-audit/connections-intel.js`<br>`siem:engine/integrations/apm-routes.js`<br>`siem:engine/sysadmin/routes.js`<br>`itam:engine/workflow-auto.js`<br>`siem:engine/ops/questions-routes.js` | sentra-itam store: assets<br>sentra-siem state: nac_hist<br>ClickHouse (siem)<br>sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>… |
| Command & Leadership | `live-status.html` | Live Status | — | — |
| Command & Leadership | `my-work.html` | My Work | `itam:engine/duty.js`<br>`siem:engine/soc/routes.js`<br>`itam:engine/manageengine.js`<br>`itam:engine/desksupport.js` | sentra-itam store: me_ec_computers<br>sentra-itam store: desk_patch<br>sentra-itam store: virt_capacity<br>sentra-itam store: me_config<br>sentra-itam store: me_ec_patches<br>sentra-itam store: me_tickets<br>… |
| Command & Leadership | `my-workflow.html` | Role Workflows | `itam:engine/role-workflows.js`<br>`itam:engine/handover.js`<br>`itam:engine/routes.js`<br>`itam:engine/roles.js` | sentra-itam store: assets<br>sentra-itam store: duty_items<br>sentra-itam store: grc_actions<br>sentra-itam store: grc_risks<br>sentra-itam store: grc_exceptions<br>sentra-itam store: grc_evidence<br>… |
| Command & Leadership | `my-workspace.html` | My Workspace | `itam:engine/team-workspace.js`<br>`itam:engine/role-brief.js`<br>`itam:engine/roles.js`<br>`itam:engine/risk-command.js` | sentra-itam store: ws_departments<br>sentra-itam store: ws_roles<br>sentra-itam store: ws_people<br>sentra-itam store: ws_workflows<br>sentra-itam store: ws_tasks<br>sentra-itam store: ws_m365_cfg<br>… |
| Command & Leadership | `noc-overview.html` | NOC Overview | `siem:engine/netops/routes.js`<br>`itam:engine/workflow-auto.js` | sentra-siem state: nac_hist<br>sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters |
| Command & Leadership | `notify-center.html` | Notification & Escalation | `itam:engine/notify-center.js` | sentra-itam store: nc_cfg<br>sentra-itam store: nc_incidents<br>sentra-itam store: nc_proposals |
| Command & Leadership | `ops-wall.html` | Operations Wall | `itam:engine/ops-wall.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/netops/routes.js`<br>`siem:engine/collect/m365-security.js`<br>`siem:engine/ksc/routes.js` | sentra-itam store: ow_samples<br>sentra-siem state: nac_hist<br>sentra-siem state: m365_security_hist |
| Command & Leadership | `patch-management.html` | Patching - All Assets | `itam:engine/patch-hub.js` | sentra-itam store: patch_cfg<br>sentra-itam store: patch_exceptions<br>sentra-itam store: db_inventory<br>sentra-itam store: vulnscan_findings<br>sentra-itam store: assets |
| Command & Leadership | `platform-map.html` | Platform Map | `itam:engine/platform-map.js` | — |
| Command & Leadership | `report-center.html` | Reporting Center | `itam:engine/report-center.js` | sentra-itam store: rc_kpis<br>sentra-itam store: rc_schedules<br>sentra-itam store: rc_runs<br>sentra-itam store: pentest_settings |
| Command & Leadership | `servers-dashboard.html` | Servers, Cloud & Applications | `itam:engine/workflow-auto.js`<br>`itam:engine/servers-dashboard.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters<br>sentra-itam store: sd_hist |
| Command & Leadership | `service-agreement.html` | Service Agreement (SLA & NDA) | `itam:engine/service-agreement.js` | sentra-itam store: sa_cfg<br>sentra-itam store: sa_cases<br>sentra-itam store: sa_statements<br>sentra-itam store: sa_documents<br>sentra-itam store: sa_measures |
| Command & Leadership | `update-guardrails.html` | Update Guardrails | `itam:engine/update-guard.js` | sentra-itam store: ug_requests<br>sentra-itam store: ug_cfg<br>sentra-itam store: ug_decisions<br>sentra-itam store: assets<br>sentra-itam store: relationships |
| Command & Leadership | `update-studio.html` | IT Operations & Updates | `itam:engine/update-studio.js` | sentra-itam store: us_obs<br>sentra-itam store: us_events<br>sentra-itam store: us_cfg<br>sentra-itam store: assets |
| Command & Leadership | `workflow-automation.html` | Workflow Automation | `itam:engine/workflow-auto.js`<br>`itam:engine/routes.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>… |
| Compliance & Frameworks | `bcm-matrix.html` | Business Continuity & DR Matrix | `itam:engine/bcm-intel.js` | sentra-itam store: grc_drills |
| Compliance & Frameworks | `compliance-assistant.html` | Compliance Assistant | `itam:engine/compliance-assist.js` | sentra-itam store: assist_feedback |
| Compliance & Frameworks | `compliance-docs.html` | Compliance Documents & Evidence | `itam:engine/docs-intel.js` | — |
| Compliance & Frameworks | `compliance-flow.html` | Compliance Automation Flow | `itam:engine/controls-intel.js`<br>`itam:engine/exec-dashboard.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-itam store: exec_hist<br>sentra-siem state: webhooks |
| Compliance & Frameworks | `compliance-map.html` | Compliance Map | — | — |
| Compliance & Frameworks | `compliance-overview.html` | Compliance Overview | `itam:engine/workflow-auto.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters |
| Compliance & Frameworks | `compliance-start.html` | Compliance Programme | `itam:engine/data-map.js`<br>`itam:engine/pdpl.js`<br>`itam:engine/ndmo.js`<br>`itam:engine/nca-ecc.js`<br>`itam:engine/sama-ia.js`<br>`itam:engine/roles.js` | sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>sentra-itam store: pdpl_statement<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: ndmo_profile<br>sentra-itam store: ndmo_confirm<br>… |
| Compliance & Frameworks | `continuous-compliance.html` | Continuous Compliance & Auto-Remediation | `itam:engine/contcomp-intel.js` | — |
| Compliance & Frameworks | `control-validation.html` | Control Validation | `itam:engine/validation-intel.js` | — |
| Compliance & Frameworks | `crosswalk.html` | Framework Crosswalk | `itam:engine/crosswalk.js` | sentra-itam store: xw_mappings<br>sentra-itam store: xw_items<br>sentra-itam store: xw_snapshots<br>sentra-itam store: xw_cfg |
| Compliance & Frameworks | `ecc-studio.html` | NCA ECC Compliance Studio | `itam:engine/nca-ecc-intel.js` | sentra-itam store: ecc_intel_snaps<br>sentra-itam store: ecc_intel_cfg |
| Compliance & Frameworks | `evidence-custody.html` | Evidence & Chain of Custody | `itam:engine/custody-intel.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-itam store: grc_files<br>sentra-itam store: custody_verifications<br>sentra-siem state: webhooks |
| Compliance & Frameworks | `framework-library.html` | Regulatory Framework Library | — | — |
| Compliance & Frameworks | `frameworks-x.html` | SOC 2 & ISO 42001 | `itam:engine/frameworks-x.js` | sentra-itam store: fx_confirmations<br>sentra-itam store: fx_cfg |
| Compliance & Frameworks | `gap-analysis.html` | Gap Analysis - All Frameworks | `itam:engine/crosswalk.js` | sentra-itam store: xw_mappings<br>sentra-itam store: xw_items<br>sentra-itam store: xw_snapshots<br>sentra-itam store: xw_cfg |
| Compliance & Frameworks | `ia-resilience.html` | IA Cyber & Operational Resilience | `itam:engine/crosswalk.js`<br>`itam:engine/ia-resilience.js` | sentra-itam store: xw_mappings<br>sentra-itam store: xw_items<br>sentra-itam store: xw_snapshots<br>sentra-itam store: xw_cfg<br>sentra-itam store: iares_snapshots |
| Compliance & Frameworks | `iso-gap-start.html` | Start an ISO 27001 Gap Assessment | — | — |
| Compliance & Frameworks | `iso-lifecycle.html` | ISO 27001 Lifecycle | `itam:engine/iso-lifecycle.js` | — |
| Compliance & Frameworks | `iso-roadmap.html` | ISO 27001 ISMS Roadmap | — | — |
| Compliance & Frameworks | `iso27001.html` | ISO 27001 ISMS | `itam:engine/iso27001.js` | — |
| Compliance & Frameworks | `live-compliance.html` | Live Compliance | `itam:engine/grc.js` | sentra-itam store: grc_attestations<br>sentra-itam store: grc_reviews<br>sentra-itam store: grc_drafts<br>sentra-itam store: counters<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>… |
| Compliance & Frameworks | `maturity-level.html` | Cybersecurity Maturity Level | — | — |
| Compliance & Frameworks | `nca-ecc.html` | NCA ECC Verification | `itam:engine/nca-ecc.js` | sentra-itam store: ecc_profile<br>sentra-itam store: ecc_confirm<br>sentra-itam store: ecc_official<br>sentra-itam store: ecc_mapping<br>sentra-itam store: grc_drafts<br>sentra-itam store: grc_drills<br>… |
| Compliance & Frameworks | `nca-gap-start.html` | Start an NCA ECC Gap Assessment | — | — |
| Compliance & Frameworks | `nca-roadmap.html` | NCA ECC Assessment Roadmap | — | — |
| Compliance & Frameworks | `sama-compliance.html` | SAMA Compliance | — | — |
| Compliance & Frameworks | `sama-gap-start.html` | Start a SAMA CSF Gap Assessment | — | — |
| Compliance & Frameworks | `sama-ia.html` | SAMA & IA Assessment | `itam:engine/sama-ia.js` | — |
| Compliance & Frameworks | `sama-roadmap.html` | SAMA CSF Assessment Roadmap | — | — |
| Compliance & Frameworks | `sama-siem.html` | SAMA coverage from SIEM evidence | — | — |
| Compliance & Frameworks | `security-controls.html` | Security Controls → Compliance | `itam:engine/controls-intel.js` | — |
| Databases | `app-route-map.html` | Application Route Map | `siem:engine/integrations/apm-routes.js`<br>`siem:engine/db-audit/dba-routes.js`<br>`siem:engine/db-audit/connections-intel.js`<br>`itam:engine/app-route.js` | ClickHouse (siem)<br>sentra-itam store: app_route |
| Databases | `databases.html` | All Databases | `itam:engine/db-health.js`<br>`itam:engine/routes.js`<br>`siem:engine/db-audit/connections-intel.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`itam:engine/db-inventory.js` | sentra-itam store: disc_devices<br>sentra-itam store: db_health_meta<br>sentra-itam store: db_health_targets<br>sentra-itam store: db_health_dismissed<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>… |
| Databases | `db-connections.html` | Application Connections | `siem:engine/db-audit/connections-intel.js`<br>`siem:engine/db-audit/dba-routes.js` | ClickHouse (siem) |
| Databases | `db-dashboard.html` | Database Dashboard | `siem:engine/db-audit/dba-routes.js`<br>`itam:engine/db-servers.js`<br>`itam:engine/db-health.js`<br>`siem:engine/db-audit/routes.js`<br>`siem:engine/integrations/apm-routes.js`<br>`siem:engine/db-audit/dba-intel.js` | ClickHouse (siem)<br>sentra-itam store: disc_devices<br>sentra-itam store: assets<br>sentra-itam store: disc_trust<br>sentra-itam store: db_server_links<br>sentra-itam store: db_server_health<br>… |
| Databases | `db-health-statement.html` | Database Health Statement | `siem:engine/db-audit/statement.js`<br>`siem:engine/db-audit/dba-routes.js` | sentra-siem state: db_statements<br>ClickHouse (siem) |
| Databases | `db-morning.html` | Morning Health Check | `itam:engine/db-morning.js` | sentra-itam store: db_morning_meta<br>sentra-itam store: db_morning_reports |
| Databases | `db-performance.html` | Database Performance | `siem:engine/db-audit/connections-intel.js`<br>`siem:engine/db-audit/routes.js`<br>`itam:engine/db-health.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`siem:engine/db-audit/perf-intel.js` | ClickHouse (siem)<br>sentra-itam store: disc_devices<br>sentra-itam store: db_health_meta<br>sentra-itam store: db_health_targets<br>sentra-itam store: db_health_dismissed<br>sentra-itam store: assets |
| Databases | `db-replication.html` | Replication & Data Guard | `itam:engine/db-replicate.js`<br>`itam:engine/routes.js`<br>`siem:engine/db-audit/routes.js` | sentra-itam store: repl_jobs<br>sentra-itam store: repl_runs<br>sentra-itam store: repl_proposals<br>sentra-itam store: repl_changes<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>… |
| Databases | `db-servers.html` | Database Servers | `itam:engine/db-servers.js`<br>`itam:engine/asset-delete.js` | sentra-itam store: disc_devices<br>sentra-itam store: assets<br>sentra-itam store: disc_trust<br>sentra-itam store: db_server_links<br>sentra-itam store: db_server_health<br>sentra-itam store: relationships<br>… |
| Databases | `db-sessions.html` | Long-Running Queries | `itam:engine/db-sessions.js`<br>`itam:engine/db-sessions-intel.js` | sentra-itam store: db_session_ctl<br>sentra-itam store: db_session_requests<br>sentra-itam store: counters<br>sentra-itam store: db_session_cases<br>sentra-itam store: db_session_learn |
| Databases | `oracle-licences.html` | Oracle Licence Inventory | `itam:engine/oracle-licences.js` | sentra-itam store: core_lic_facts<br>sentra-itam store: assets<br>sentra-itam store: oracle_cf_table<br>sentra-itam store: ora_lic_alerts<br>sentra-itam store: ora_lic_reports |
| Databases | `oracle-tuning.html` | Oracle Tuning | `siem:engine/db-audit/routes.js`<br>`itam:engine/db-health.js`<br>`siem:engine/db-audit/tuning-intel.js` | ClickHouse (siem)<br>sentra-itam store: disc_devices<br>sentra-itam store: db_health_meta<br>sentra-itam store: db_health_targets<br>sentra-itam store: db_health_dismissed<br>sentra-itam store: assets |
| Endpoint, Web & Email Security | `cloud-stores.html` | Cloud Data Stores | `siem:engine/collect/webhook-ingest.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`itam:engine/routes.js`<br>`itam:engine/discovery/routes.js` | sentra-siem state: webhooks<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Endpoint, Web & Email Security | `data-posture.html` | Data Security Posture | `itam:engine/dspm-intel.js`<br>`itam:engine/data-posture.js`<br>`itam:engine/dspm-files.js` | sentra-itam store: data_posture_hist<br>sentra-itam store: dspm_store_hist<br>sentra-itam store: dspm_plans<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: db_inventory<br>sentra-itam store: access_reviews<br>… |
| Endpoint, Web & Email Security | `dlp.html` | Data Loss Prevention | `siem:engine/reports/dlp-routes.js` | sentra-siem state: dlp_settings |
| Endpoint, Web & Email Security | `email-analysis.html` | Email / Phishing Analysis | `siem:engine/detect/routes.js`<br>`siem:engine/integrations/routes.js` | sentra-siem state: rules |
| Endpoint, Web & Email Security | `email-dashboard.html` | Email Dashboard | `siem:engine/api/routes.js`<br>`siem:engine/soc/flows.js`<br>`itam:engine/mail-reputation.js`<br>`itam:engine/mail-doctor.js`<br>`itam:engine/domains.js`<br>`siem:engine/soc/mailstats.js` | ClickHouse (siem)<br>sentra-itam store: mailrep<br>sentra-itam store: mailrep_ips<br>sentra-itam store: dom_domains<br>sentra-itam store: dom_checks<br>sentra-itam store: mailavail<br>… |
| Endpoint, Web & Email Security | `email-route-map.html` | Email Route Map | `siem:engine/api/routes.js`<br>`itam:engine/mail-reputation.js`<br>`itam:engine/dns-fix.js`<br>`itam:engine/libraesva.js`<br>`siem:engine/sysadmin/routes.js`<br>`siem:engine/soc/mailnotify.js`<br>`itam:engine/mail-doctor.js` | ClickHouse (siem)<br>sentra-itam store: mailrep<br>sentra-itam store: mailrep_ips<br>sentra-itam store: dom_domains<br>sentra-itam store: dom_checks<br>sentra-itam store: mailavail<br>… |
| Endpoint, Web & Email Security | `email-security.html` | Email Security | `siem:engine/api/routes.js`<br>`itam:engine/mail-reputation.js`<br>`itam:engine/mail-doctor.js` | ClickHouse (siem)<br>sentra-itam store: mailrep<br>sentra-itam store: mailrep_ips<br>sentra-itam store: dom_domains<br>sentra-itam store: dom_checks<br>sentra-itam store: mailavail<br>… |
| Endpoint, Web & Email Security | `libraesva.html` | Libraesva ESG | `siem:engine/api/routes.js`<br>`itam:engine/libraesva.js` | ClickHouse (siem)<br>sentra-itam store: esg |
| Endpoint, Web & Email Security | `mail-ops.html` | 24/7 Email Availability | — | — |
| Endpoint, Web & Email Security | `phishing-simulation.html` | Phishing Simulation | `itam:engine/phish-sim.js` | sentra-itam store: phishsim |
| Home | `index.html` |  | `siem:engine/soc/analyst-routes.js`<br>`itam:engine/risk-command.js`<br>`itam:engine/audit-dashboard.js`<br>`itam:engine/exec-dashboard.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`itam:engine/duty.js`<br>`siem:engine/duty/routes.js`<br>`siem:engine/soc/routes.js`<br>`siem:engine/netops/routes.js`<br>`itam:engine/db-health.js`<br>`itam:engine/roles.js`<br>`itam:engine/aigov-intel.js`<br>`siem:engine/soc/platform.js` | sentra-itam store: exec_hist<br>sentra-siem state: webhooks<br>sentra-itam store: me_ec_computers<br>sentra-itam store: desk_patch<br>sentra-itam store: virt_capacity<br>sentra-siem state: nac_hist<br>… |
| Identity & Microsoft 365 | `access-reviews.html` | Access Reviews | `itam:engine/access-reviews.js` | sentra-itam store: access_reviews<br>sentra-itam store: access_review_items<br>sentra-itam store: access_review_cfg |
| Identity & Microsoft 365 | `ad-exchange.html` | AD & Exchange | `siem:engine/netops/routes.js`<br>`siem:engine/api/routes.js`<br>`siem:engine/ad/routes.js` | sentra-siem state: nac_hist<br>ClickHouse (siem) |
| Identity & Microsoft 365 | `exchange-hybrid.html` | Exchange Hybrid Migration | `siem:engine/sysadmin/hybrid.js`<br>`siem:engine/sysadmin/routes.js`<br>`itam:engine/domains.js`<br>`itam:engine/routes.js` | sentra-siem state: exo_hybrid<br>ClickHouse (siem)<br>sentra-itam store: dom_domains<br>sentra-itam store: dom_hosts<br>sentra-itam store: dom_checks<br>sentra-itam store: dom_history<br>… |
| Identity & Microsoft 365 | `identity-posture.html` | Password & MFA Posture | `itam:engine/identity-posture.js` | sentra-itam store: identity_posture |
| Identity & Microsoft 365 | `m365-autoconfig.html` | MS Security Auto-Config | `siem:engine/collect/m365-autoconfig.js`<br>`siem:engine/collect/m365-routes.js` | sentra-siem state: m365_autoconfig |
| Identity & Microsoft 365 | `m365-dashboard.html` | M365, Users & Endpoints | `siem:engine/collect/m365-insights.js` | sentra-siem state: m365_insights_hist |
| Identity & Microsoft 365 | `m365-security.html` | Microsoft 365 Security | — | — |
| Identity & Microsoft 365 | `m365.html` | Microsoft 365 | `siem:engine/collect/m365-routes.js` | — |
| Identity & Microsoft 365 | `nhi.html` | Non-Human Identities | `itam:engine/nhi.js` | sentra-itam store: nhi_register<br>sentra-itam store: nhi_settings |
| Identity & Microsoft 365 | `privileged-access.html` | Privileged Access | `itam:engine/pam.js` | sentra-itam store: pam_requests<br>sentra-itam store: pam_cfg |
| Identity & Microsoft 365 | `sharepoint.html` | SharePoint & OneDrive | — | — |
| IT Assets, Licences & Cost | `asset-autofill.html` | Asset Data Autopilot | `itam:engine/asset-autofill.js` | sentra-itam store: assets<br>sentra-itam store: autofill_cfg<br>sentra-itam store: autofill_dismissed<br>sentra-itam store: relationships |
| IT Assets, Licences & Cost | `asset-coverage.html` | Coverage & Query | `itam:engine/asset-coverage.js` | sentra-itam store: acov_exempt<br>sentra-itam store: acov_queries<br>sentra-itam store: acov_runs<br>sentra-itam store: acov_actions<br>sentra-itam store: backup_platforms<br>sentra-itam store: me_ec_computers<br>… |
| IT Assets, Licences & Cost | `asset-ownership.html` | Asset Ownership | `itam:engine/ownership.js` | sentra-itam store: asset_ownership<br>sentra-itam store: ownership_services |
| IT Assets, Licences & Cost | `asset-purchasing.html` | Asset Purchasing | `itam:engine/purchasing.js` | sentra-itam store: purchase_orders<br>sentra-itam store: assets |
| IT Assets, Licences & Cost | `asset-studio.html` | Asset Studio | `itam:engine/asset-studio.js` | sentra-itam store: asset_studio_decisions<br>sentra-itam store: asset_studio_ai<br>sentra-itam store: assets |
| IT Assets, Licences & Cost | `budget.html` | IT Budget | `itam:engine/budget.js`<br>`itam:engine/budget-exec.js`<br>`itam:engine/budget-intel.js` | sentra-itam store: budget_settings<br>sentra-itam store: budget_previous<br>sentra-itam store: budget_lines<br>sentra-itam store: assets<br>sentra-itam store: budget_years<br>sentra-itam store: licences<br>… |
| IT Assets, Licences & Cost | `cmdb-deps.html` | CMDB & Dependencies | `itam:engine/cmdb-deps.js` | sentra-itam store: cmdb_dep_snaps<br>sentra-itam store: assets<br>sentra-itam store: relationships<br>sentra-itam store: app_route |
| IT Assets, Licences & Cost | `cmdb-studio.html` | CMDB Studio | `itam:engine/cmdb-studio.js`<br>`itam:engine/cmdb-intel.js` | sentra-itam store: cmdb_decisions<br>sentra-itam store: relationships<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: cmdb_health<br>sentra-itam store: app_route |
| IT Assets, Licences & Cost | `cost-optimisation.html` | Cost Optimisation | `itam:engine/platform-cost.js` | sentra-itam store: platform_cost_cfg<br>sentra-itam store: platform_cost_cases<br>sentra-itam store: licences<br>sentra-itam store: assets |
| IT Assets, Licences & Cost | `cost-studio.html` | Cost Studio | `itam:engine/cost-studio.js`<br>`itam:engine/routes.js` | sentra-itam store: cost_actions<br>sentra-itam store: cost_decisions<br>sentra-itam store: budget_previous<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| IT Assets, Licences & Cost | `digital-twin.html` | Digital Twin | `itam:engine/twin-studio.js` | sentra-itam store: twin_settings<br>sentra-itam store: twin_dr_pairs<br>sentra-itam store: twin_outages<br>sentra-itam store: assets |
| IT Assets, Licences & Cost | `discovery-studio.html` | Discovery Studio | `itam:engine/discovery-studio.js` | — |
| IT Assets, Licences & Cost | `eam.html` | Enterprise Asset Management | `itam:engine/eam.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`itam:engine/routes.js` | sentra-itam store: eam_wo<br>sentra-itam store: eam_pm<br>sentra-itam store: eam_stock<br>sentra-itam store: eam_moves<br>sentra-itam store: eam_po<br>sentra-itam store: eam_retire<br>… |
| IT Assets, Licences & Cost | `inventory.html` | Inventory | `itam:engine/inventory-intel.js`<br>`itam:engine/routes.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| IT Assets, Licences & Cost | `itam-overview.html` | IT Asset Management | `itam:engine/itam-overview.js` | sentra-itam store: itam_overview_snapshots<br>sentra-itam store: assets |
| IT Assets, Licences & Cost | `itam-settings.html` | ITAM Settings | `itam:engine/routes.js`<br>`itam:engine/settings-advisor.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans<br>sentra-itam store: disc_devices |
| IT Assets, Licences & Cost | `lifecycle-studio.html` | Lifecycle Studio | `itam:engine/lifecycle-studio.js`<br>`itam:engine/routes.js` | sentra-itam store: lifecycle_plan<br>sentra-itam store: assets<br>sentra-itam store: relationships<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| IT Assets, Licences & Cost | `lifecycle.html` | End of Life & Isolation | `itam:engine/lifecycle.js` | sentra-itam store: isolation_requests<br>sentra-itam store: lifecycle_exceptions<br>sentra-itam store: lifecycle_settings<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: virt_capacity<br>… |
| IT Assets, Licences & Cost | `network-discovery.html` | Network Discovery | `itam:engine/discovery-advisor.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`itam:engine/discovery/routes.js`<br>`itam:engine/asset-delete.js` | sentra-itam store: scope_proposals<br>sentra-itam store: scope_ai_drafts<br>sentra-itam store: disc_devices<br>sentra-itam store: assets<br>sentra-siem state: webhooks<br>sentra-itam store: relationships<br>… |
| IT Assets, Licences & Cost | `owner-studio.html` | Accountability Studio | `itam:engine/owner-studio.js` | sentra-itam store: owner_studio_decisions<br>sentra-itam store: owner_studio_ai<br>sentra-itam store: assets<br>sentra-itam store: reconcile_accepted<br>sentra-itam store: relationships |
| IT Assets, Licences & Cost | `people-inventory.html` | User Inventory | `itam:engine/people-inventory.js` | sentra-itam store: m365_user_apps<br>sentra-itam store: ad_directory |
| IT Assets, Licences & Cost | `reconcile.html` | Asset Reconciliation | `itam:engine/reconcile.js`<br>`itam:engine/infra-sync.js` | sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: reconcile_accepted<br>sentra-itam store: reconcile_settings<br>sentra-itam store: me_config<br>sentra-itam store: infra_sync<br>… |
| IT Assets, Licences & Cost | `renewals-expiry.html` | Renewals & Expiry | `itam:engine/expiry-hub.js` | sentra-itam store: expiry_tracking |
| IT Assets, Licences & Cost | `scope-studio.html` | Scope Studio | `itam:engine/discovery-advisor.js`<br>`itam:engine/routes.js` | sentra-itam store: scope_proposals<br>sentra-itam store: scope_ai_drafts<br>sentra-itam store: disc_devices<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| IT Assets, Licences & Cost | `software-studio.html` | Software & Licences | `itam:engine/software-studio.js`<br>`itam:engine/routes.js` | sentra-itam store: software_policy<br>sentra-itam store: assets<br>sentra-itam store: licences<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| IT Assets, Licences & Cost | `stocktake.html` | Stocktake | `itam:engine/stocktake-intel.js`<br>`itam:engine/routes.js`<br>`siem:engine/collect/cloud-data-routes.js` | sentra-itam store: stocktake_resolutions<br>sentra-itam store: assets<br>sentra-itam store: stocktakes<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| IT Assets, Licences & Cost | `support-contracts.html` | Support Contracts | `itam:engine/support-contracts.js`<br>`itam:engine/cisco-support.js`<br>`siem:engine/netops/routes.js` | sentra-itam store: support_contracts<br>sentra-itam store: support_contracts_cfg<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: cisco_coverage<br>sentra-itam store: cisco_support<br>… |
| Network | `branch-connectivity.html` | Branch Connectivity | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `brand-protection.html` | Brand Protection | `itam:engine/brand-protect.js` | sentra-itam store: bp_domains<br>sentra-itam store: bp_ct<br>sentra-itam store: bp_cases<br>sentra-itam store: bp_cfg<br>sentra-itam store: dom_domains |
| Network | `certificates.html` | Certificates | `itam:engine/certs.js`<br>`itam:engine/cert-autodiscover.js`<br>`itam:engine/cert-estate.js`<br>`siem:engine/collect/cloud-data-routes.js` | sentra-itam store: cert_endpoints<br>sentra-itam store: cert_scans<br>sentra-itam store: cert_renewals<br>sentra-itam store: cert_policy<br>sentra-itam store: cert_requests<br>sentra-itam store: cert_discover_job<br>… |
| Network | `change-log.html` | Change Log & NOC↔SOC Correlation | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `cisco-network.html` | Cisco Network Inventory | `siem:engine/netops/routes.js`<br>`itam:engine/cisco-support.js` | sentra-siem state: nac_hist<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: cisco_coverage<br>sentra-itam store: cisco_support<br>sentra-itam store: cisco_psirt |
| Network | `cisco-update.html` | Cisco Updates | `itam:engine/cisco-update.js`<br>`itam:engine/cisco-support.js` | sentra-itam store: cisco_update_plans<br>sentra-itam store: cisco_update_cfg<br>sentra-itam store: cisco_update_seen<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: cisco_coverage<br>… |
| Network | `domains.html` | Domains & DNS | `itam:engine/domains.js` | sentra-itam store: dom_domains<br>sentra-itam store: dom_hosts<br>sentra-itam store: dom_checks<br>sentra-itam store: dom_history<br>sentra-itam store: assets<br>sentra-itam store: dom_cfg |
| Network | `ipam.html` | IP Address Management | — | — |
| Network | `ncm.html` | Network Config Management | — | — |
| Network | `netflow.html` | NetFlow Analytics | `siem:engine/soc/flow-analytics-routes.js` | — |
| Network | `network-access.html` | Network Access Control | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `network-connectivity.html` | Connectivity Troubleshooter | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `network-dashboard.html` | Network Dashboard | `itam:engine/workflow-auto.js`<br>`siem:engine/netops/routes.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters<br>sentra-siem state: nac_hist |
| Network | `network-flows.html` | Network Flows | `siem:engine/soc/flows.js` | ClickHouse (siem) |
| Network | `network-map.html` | Intelligent Network Map | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `network-onboarding.html` | Network Onboarding & Architecture | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `network-route-map.html` | WAN & LAN Route Map | `siem:engine/netops/routes.js`<br>`siem:engine/compliance/sama-intel-routes.js` | sentra-siem state: nac_hist |
| Network | `npm-summary.html` | NOC Summary | `siem:engine/netops/routes.js`<br>`itam:engine/workflow-auto.js` | sentra-siem state: nac_hist<br>sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters |
| Network | `rogue-detection.html` | Advanced Rogue Detection | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `sdwan.html` | SD-WAN | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `switch-port-map.html` | Switch Port Map | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `wan-optimization.html` | WAN Optimization | `siem:engine/netops/routes.js` | sentra-siem state: nac_hist |
| Network | `wireless.html` | Wireless | `itam:engine/routes.js`<br>`siem:engine/netops/synthetic-routes.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Pentest & Vulnerability Management | `apppt.html` | Application Pen Testing | `itam:engine/apppt.js`<br>`itam:engine/routes.js`<br>`siem:engine/bas/routes.js` | sentra-itam store: pt_targets<br>sentra-itam store: pt_engagements<br>sentra-itam store: pt_findings<br>sentra-itam store: pt_cfg<br>sentra-itam store: pt_counters<br>sentra-itam store: ecc_profile<br>… |
| Pentest & Vulnerability Management | `appsec.html` | AppSec & Code Review | `itam:engine/appsec.js`<br>`itam:engine/routes.js` | sentra-itam store: as_apps<br>sentra-itam store: as_findings<br>sentra-itam store: as_scans<br>sentra-itam store: as_releases<br>sentra-itam store: as_cfg<br>sentra-itam store: as_counters<br>… |
| Pentest & Vulnerability Management | `attack-surface.html` | Attack Surface | — | — |
| Pentest & Vulnerability Management | `detection-validation.html` | Detection Validation | — | — |
| Pentest & Vulnerability Management | `hardening.html` | Baseline Hardening | `itam:engine/hardening.js` | sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: hardening_history<br>sentra-itam store: server_os_health<br>sentra-itam store: db_server_health<br>sentra-itam store: db_hardening |
| Pentest & Vulnerability Management | `live-scan.html` | Live Scan Engine & Attack Simulation | `itam:engine/vulnscan.js`<br>`itam:engine/vapt-center.js` | sentra-itam store: vc_snapshots<br>sentra-itam store: vc_cfg<br>sentra-itam store: pentest_settings<br>sentra-itam store: test_tier<br>sentra-itam store: assets |
| Pentest & Vulnerability Management | `mobile-test.html` | Mobile Application Testing | `itam:engine/mobile-test.js`<br>`itam:engine/routes.js` | sentra-itam store: ecc_profile<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Pentest & Vulnerability Management | `risk-prioritization.html` | Risk Prioritization | `itam:engine/vuln-intel.js` | sentra-itam store: vi_cfg<br>sentra-itam store: rp_profiles<br>sentra-itam store: rp_hist<br>sentra-itam store: assets<br>sentra-itam store: pentest_settings<br>sentra-itam store: test_tier |
| Pentest & Vulnerability Management | `scan-assurance.html` | Scan Coverage Assurance | — | — |
| Pentest & Vulnerability Management | `scanned-assets.html` | Scanned Assets | `itam:engine/scanned-assets.js` | sentra-itam store: sa_cfg<br>sentra-itam store: pentest_settings<br>sentra-itam store: test_tier<br>sentra-itam store: assets<br>sentra-itam store: vulnscan_results<br>sentra-itam store: vapt_scanned<br>… |
| Pentest & Vulnerability Management | `vapt-center.html` | VAPT Center | `itam:engine/vapt-center.js` | sentra-itam store: vc_snapshots<br>sentra-itam store: vc_cfg<br>sentra-itam store: pentest_settings<br>sentra-itam store: test_tier<br>sentra-itam store: assets |
| Pentest & Vulnerability Management | `vapt-studio.html` | VAPT Studio | — | — |
| Pentest & Vulnerability Management | `vapt-workflow.html` | VAPT Workflow | — | — |
| Pentest & Vulnerability Management | `vuln-dashboard.html` | Vulnerability & Testing Dashboard | `itam:engine/vuln-dashboard.js` | sentra-itam store: vulnd_snapshots |
| Pentest & Vulnerability Management | `vuln-inventory.html` | Vulnerabilities | `itam:engine/vuln-intel.js` | sentra-itam store: vi_cfg<br>sentra-itam store: rp_profiles<br>sentra-itam store: rp_hist<br>sentra-itam store: assets<br>sentra-itam store: pentest_settings<br>sentra-itam store: test_tier |
| Pentest & Vulnerability Management | `vuln-scans.html` | Vulnerability Scans | — | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `ndmo-gap-start.html` | Start an NDMO Gap Assessment | — | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `ndmo-roadmap.html` | NDMO Implementation Roadmap | — | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `ndmo-studio.html` | NDMO Studio | — | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `ndmo.html` | NDMO Data Management | `itam:engine/ndmo.js` | sentra-itam store: ndmo_profile<br>sentra-itam store: ndmo_confirm<br>sentra-itam store: ndmo_official<br>sentra-itam store: ndmo_mapping<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: grc_drafts |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-access.html` | Access Intelligence | `itam:engine/pdpl-access.js` | sentra-itam store: pdpl_access_meta<br>sentra-itam store: pdpl_access_keys<br>sentra-itam store: pdpl_access_days<br>sentra-itam store: pdpl_access_exc<br>sentra-itam store: pdpl_access_rev |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-assessment.html` | PDPL Self-Assessment | `itam:engine/pdpl-assessment.js` | sentra-itam store: pdpl_assessments |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-breach.html` | Breach Response | `itam:engine/pdpl-workflows.js`<br>`itam:engine/pdpl.js` | sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>sentra-itam store: pdpl_statement<br>sentra-itam store: pdpl_discovery |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-catalog.html` | Data Catalog | `itam:engine/pdpl-catalog.js`<br>`itam:engine/pdpl.js` | sentra-itam store: pdpl_identifiers<br>sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>sentra-itam store: pdpl_statement<br>sentra-itam store: pdpl_discovery |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-dashboard.html` | PDPL & NDMO Dashboard | `itam:engine/data-map.js`<br>`itam:engine/ndmo.js`<br>`itam:engine/pdpl-assessment.js`<br>`itam:engine/pdpl-catalog.js`<br>`itam:engine/pdpl-workflows.js`<br>`itam:engine/pdpl-vendor.js`<br>`itam:engine/pdpl-notify.js`<br>`itam:engine/pdpl-office.js` | sentra-itam store: pdpl_records<br>sentra-itam store: ndmo_profile<br>sentra-itam store: ndmo_confirm<br>sentra-itam store: ndmo_official<br>sentra-itam store: ndmo_mapping<br>sentra-itam store: pdpl_discovery<br>… |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-dpia.html` | Impact Assessments (DPIA) | `itam:engine/pdpl-workflows.js`<br>`itam:engine/pdpl.js` | sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>sentra-itam store: pdpl_statement<br>sentra-itam store: pdpl_discovery |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-dsar.html` | Data Subject Requests | `itam:engine/pdpl-catalog.js`<br>`itam:engine/pdpl-ropa.js`<br>`itam:engine/pdpl-intake.js` | sentra-itam store: pdpl_identifiers<br>sentra-itam store: pdpl_ropa_campaigns<br>sentra-itam store: pdpl_ropa_drafts<br>sentra-itam store: assets<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: pdpl_intake_meta<br>… |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-flow.html` | PDPL Automation Flow | `itam:engine/automation-flow.js` | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-gap-start.html` | Start a PDPL Gap Assessment | — | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-governance.html` | PDPL Governance | `itam:engine/pdpl-workflows.js` | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-intel.html` | PDPL Intelligence | `itam:engine/pdpl-intel.js` | sentra-itam store: pdpl_column_review<br>sentra-itam store: pdpl_dpia_drafts<br>sentra-itam store: pdpl_discovery |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-monitor.html` | PDPL Control Monitor | `itam:engine/pdpl-monitor.js` | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-office.html` | Privacy Office | `itam:engine/pdpl-office.js`<br>`itam:engine/pdpl-notify.js` | sentra-itam store: pdpl_office_tasks<br>sentra-itam store: pdpl_office_cfg<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: pdpl_ropa_campaigns<br>sentra-itam store: pdpl_access_keys<br>sentra-itam store: pdpl_statement<br>… |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-policies.html` | PDPL Policies | `itam:engine/pdpl-workflows.js`<br>`itam:engine/grc.js` | sentra-itam store: grc_attestations<br>sentra-itam store: grc_reviews<br>sentra-itam store: grc_drafts<br>sentra-itam store: counters<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>… |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-processors.html` | Processor Management | `itam:engine/pdpl-workflows.js`<br>`itam:engine/pdpl.js`<br>`itam:engine/pdpl-vendor.js` | sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>sentra-itam store: pdpl_statement<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: pdpl_vendor_assessments |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-programme.html` | PDPL Programme | `itam:engine/pdpl-workflows.js` | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-retention.html` | Retention Enforcement | `itam:engine/pdpl-retention.js` | sentra-itam store: pdpl_retention_maps<br>sentra-itam store: pdpl_retention_tasks<br>sentra-itam store: pdpl_retention_holds<br>sentra-itam store: pdpl_retention_runs<br>sentra-itam store: pdpl_retention_cfg<br>sentra-itam store: pdpl_records<br>… |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-roadmap.html` | PDPL Implementation Roadmap | — | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-ropa-collect.html` | RoPA by Department | `itam:engine/pdpl-ropa.js`<br>`itam:engine/pdpl-ropa-flow.js`<br>`itam:engine/routes.js` | sentra-itam store: pdpl_ropa_campaigns<br>sentra-itam store: pdpl_ropa_drafts<br>sentra-itam store: assets<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: pdpl_ropa_flow<br>sentra-itam store: pdpl_ropa_reminders<br>… |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-ropa.html` | Records of Processing | `itam:engine/pdpl-ropa.js`<br>`itam:engine/pdpl.js`<br>`itam:engine/data-map.js`<br>`itam:engine/pdpl-workflows.js` | sentra-itam store: pdpl_ropa_campaigns<br>sentra-itam store: pdpl_ropa_drafts<br>sentra-itam store: assets<br>sentra-itam store: pdpl_discovery<br>sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>… |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-sensitive.html` | Sensitive Data Controls | `itam:engine/pdpl-workflows.js` | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-studio.html` | PDPL Studio | — | — |
| Personal Data Protection & Data Management (PDPL · NDMO) | `pdpl-transfers.html` | Cross-Border Transfers | `itam:engine/pdpl-workflows.js`<br>`itam:engine/pdpl.js` | sentra-itam store: pdpl_records<br>sentra-itam store: pdpl_confirm<br>sentra-itam store: pdpl_statement<br>sentra-itam store: pdpl_discovery |
| Personal Data Protection & Data Management (PDPL · NDMO) | `privacy-cockpit.html` | Privacy Cockpit | `itam:engine/pdpl-cockpit.js` | — |
| Platform Administration | `ad-manage.html` | AD Management | `itam:engine/ad-manage.js`<br>`itam:engine/ad-directory.js` | sentra-itam store: ad_manage<br>sentra-itam store: ad_manage_requests<br>sentra-itam store: ad_manage_secrets<br>sentra-itam store: ad_directory |
| Platform Administration | `connections.html` | Integration Hub | `itam:engine/virt-admin.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`siem:engine/ksc/routes.js`<br>`itam:engine/discovery/routes.js`<br>`siem:engine/zscaler/routes.js`<br>`itam:engine/sso-groups.js`<br>`itam:engine/ad-manage.js`<br>`itam:engine/onboarding-ad.js`<br>`itam:engine/ad-connect.js`<br>`itam:engine/ad-directory.js`<br>`itam:engine/db-health.js`<br>`itam:engine/libraesva.js`<br>`siem:engine/collect/cloud-routes.js`<br>`siem:engine/netops/routes.js`<br>`siem:engine/collect/m365-routes.js`<br>`itam:engine/manageengine.js`<br>`itam:engine/backup.js`<br>`itam:engine/storage.js` | sentra-itam store: virt_capacity<br>sentra-itam store: virt_changes<br>sentra-itam store: virt_admin_cfg<br>sentra-itam store: counters<br>sentra-itam store: sso_groups<br>sentra-itam store: ad_manage<br>… |
| Platform Administration | `handover.html` | Staff Handover | `itam:engine/handover.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`itam:engine/pdpl-access.js` | sentra-itam store: handovers<br>sentra-itam store: pdpl_access_meta<br>sentra-itam store: pdpl_access_keys<br>sentra-itam store: pdpl_access_days<br>sentra-itam store: pdpl_access_exc<br>sentra-itam store: pdpl_access_rev |
| Platform Administration | `identity-signin.html` | Identity & Sign-in | `itam:engine/identity-advisor.js` | — |
| Platform Administration | `platform.html` | Platform Health | `siem:engine/soc/platform.js`<br>`itam:engine/errors.js`<br>`siem:engine/main.js` | ClickHouse (siem) |
| Platform Administration | `roles.html` | Roles & Functions | `itam:engine/roles.js` | sentra-itam store: job_roles<br>sentra-itam store: role_assignments |
| Platform Administration | `solution-admin.html` | Modules & Solutions | `itam:engine/licence.js` | sentra-itam store: assets<br>sentra-itam store: role_assignments<br>sentra-itam store: licence_state |
| Platform Administration | `sso-access.html` | SSO Access from AD | `itam:engine/sso-groups.js` | sentra-itam store: sso_groups |
| Platform Administration | `update-health.html` | Update Health | `itam:engine/update-health.js` | — |
| Platform Administration | `user-management.html` | User Management | `itam:engine/roles.js`<br>`itam:engine/welcome-mail.js`<br>`itam:engine/identity-advisor.js`<br>`itam:engine/ad-directory.js` | sentra-itam store: job_roles<br>sentra-itam store: role_assignments<br>sentra-itam store: welcome_mail_settings<br>sentra-itam store: welcome_mail_log<br>sentra-itam store: ad_directory |
| Risk & Governance | `credential-security.html` | Credential Security | `itam:engine/cred-posture.js`<br>`siem:engine/soc/credposture.js`<br>`itam:engine/grc-registers.js` | sentra-itam store: sec_cred_scans<br>sentra-itam store: agents<br>sentra-itam store: enrol_tokens<br>sentra-itam store: disc_trust<br>ClickHouse (siem)<br>sentra-itam store: grc_actions<br>… |
| Risk & Governance | `grc-dashboard.html` | GRC Dashboard | `itam:engine/crosswalk.js`<br>`itam:engine/workflow-auto.js`<br>`itam:engine/grc-dashboard.js` | sentra-itam store: xw_mappings<br>sentra-itam store: xw_items<br>sentra-itam store: xw_snapshots<br>sentra-itam store: xw_cfg<br>sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>… |
| Risk & Governance | `grc-policies.html` | Policies & Controls | `itam:engine/grc.js`<br>`siem:engine/dfir/routes.js`<br>`siem:engine/netops/routes.js`<br>`itam:engine/routes.js` | sentra-itam store: grc_attestations<br>sentra-itam store: grc_reviews<br>sentra-itam store: grc_drafts<br>sentra-itam store: counters<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>… |
| Risk & Governance | `grc-register.html` | GRC Register | `itam:engine/crosswalk.js`<br>`itam:engine/grc-register.js` | sentra-itam store: xw_mappings<br>sentra-itam store: xw_items<br>sentra-itam store: xw_snapshots<br>sentra-itam store: xw_cfg |
| Risk & Governance | `grc-workspace.html` | Risks & Actions | `itam:engine/grc-registers.js`<br>`itam:engine/workflow-auto.js`<br>`itam:engine/routes.js` | sentra-itam store: grc_actions<br>sentra-itam store: grc_risks<br>sentra-itam store: grc_exceptions<br>sentra-itam store: grc_evidence<br>sentra-itam store: grc_files<br>sentra-itam store: counters<br>… |
| Risk & Governance | `impl-plan.html` | Implementation Plan & Budget | `itam:engine/impl-plan.js` | sentra-itam store: impl_estimates<br>sentra-itam store: impl_config<br>sentra-itam store: grc_actions |
| Risk & Governance | `issues.html` | Issues Management | `itam:engine/issues-hub.js`<br>`siem:engine/integrations/routes.js` | — |
| Risk & Governance | `risk-assess.html` | Automated Risk Assessment | `itam:engine/risk-assess.js` | sentra-itam store: riskassess_snaps<br>sentra-itam store: riskassess_cfg |
| Risk & Governance | `risk-assessments.html` | Risk Assessments | — | — |
| Risk & Governance | `risk-command.html` | Risk Command Center | `itam:engine/risk-command.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-siem state: webhooks |
| Risk & Governance | `risk-control.html` | Risk & Control Hub | `itam:engine/risk-control.js` | — |
| Risk & Governance | `risk-studio.html` | Risk Studio | `itam:engine/risk-studio.js` | sentra-itam store: rs_cfg<br>sentra-itam store: rs_hist<br>sentra-itam store: rs_links<br>sentra-itam store: grc_actions<br>sentra-itam store: grc_exceptions |
| Risk & Governance | `roadmap.html` | Remediation Roadmap | `itam:engine/roadmap.js` | — |
| Risk & Governance | `roles-raci.html` | Roles & RACI | `itam:engine/raci-intel.js`<br>`siem:engine/collect/webhook-ingest.js` | sentra-siem state: webhooks |
| Security Operations & Incident Response | `alarm-rules.html` | Alarm Inbox Rules | `siem:engine/detect/routes.js` | sentra-siem state: rules |
| Security Operations & Incident Response | `dark-web-watch.html` | Dark Web Watch | `siem:engine/soc/darkweb.js` | sentra-siem state: darkweb_exposures<br>sentra-siem state: darkweb_cfg |
| Security Operations & Incident Response | `device-config.html` | Device Configuration | — | — |
| Security Operations & Incident Response | `dfir.html` | Forensics & IR (DFIR) | `siem:engine/dfir/routes.js`<br>`siem:engine/integrations/routes.js`<br>`itam:engine/notify-center.js`<br>`siem:engine/compliance/sama-intel-routes.js`<br>`itam:engine/routes.js` | sentra-itam store: nc_cfg<br>sentra-itam store: nc_incidents<br>sentra-itam store: nc_proposals<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Security Operations & Incident Response | `incident-response.html` | Incident Response Center | `siem:engine/soc/ircenter-routes.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/xdr/routes.js`<br>`itam:engine/routes.js`<br>`siem:engine/soc/routes.js`<br>`siem:engine/compliance/sama-intel-routes.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Security Operations & Incident Response | `insider-risk.html` | Insider Risk | `itam:engine/crosswalk.js`<br>`siem:engine/soc/insider-routes.js`<br>`siem:engine/compliance/sama-intel-routes.js` | sentra-itam store: xw_mappings<br>sentra-itam store: xw_items<br>sentra-itam store: xw_snapshots<br>sentra-itam store: xw_cfg |
| Security Operations & Incident Response | `log-assurance.html` | Log Flow Assurance | `itam:engine/log-enrol.js` | sentra-itam store: log_enrol_attempts |
| Security Operations & Incident Response | `log-monitor.html` | Log Monitor & Analysis | `siem:engine/api/logmon.js` | ClickHouse (siem) |
| Security Operations & Incident Response | `pipeline-health.html` | Pipeline Health | `itam:engine/pipeline-health.js`<br>`siem:engine/ops/canary.js` | sentra-siem state: siem_canary_runs<br>sentra-siem state: siem_canary_cfg<br>ClickHouse (siem) |
| Security Operations & Incident Response | `security-center.html` | Security Center | `siem:engine/soc/analyst-routes.js`<br>`siem:engine/api/routes.js`<br>`siem:engine/ksc/routes.js`<br>`siem:engine/collect/m365-security.js`<br>`siem:engine/netops/routes.js` | ClickHouse (siem)<br>sentra-siem state: m365_security_hist<br>sentra-siem state: nac_hist |
| Security Operations & Incident Response | `soar.html` | SOAR - Automated Response | `siem:engine/soc/soar-routes.js`<br>`siem:engine/compliance/sama-intel-routes.js`<br>`siem:engine/soc/routes.js` | — |
| Security Operations & Incident Response | `soc-alerts.html` | Alert Queue | `siem:engine/soc/analyst-routes.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/soc/routes.js` | — |
| Security Operations & Incident Response | `soc-cases.html` | Investigations & Cases | `siem:engine/soc/investigate-routes.js`<br>`siem:engine/integrations/routes.js`<br>`itam:engine/team-workspace.js`<br>`itam:engine/routes.js` | sentra-itam store: ws_departments<br>sentra-itam store: ws_roles<br>sentra-itam store: ws_people<br>sentra-itam store: ws_workflows<br>sentra-itam store: ws_tasks<br>sentra-itam store: ws_m365_cfg<br>… |
| Security Operations & Incident Response | `soc-console.html` | SOC Console | `siem:engine/soc/console.js`<br>`siem:engine/soc/analyst-routes.js` | sentra-siem state: soc_console<br>sentra-siem state: soc_console_retired<br>sentra-siem state: soc_console_fim_seen |
| Security Operations & Incident Response | `soc-hunt.html` | Threat Hunting & Search | `siem:engine/soc/investigate-routes.js`<br>`siem:engine/api/routes.js`<br>`siem:engine/xdr/routes.js`<br>`siem:engine/integrations/routes.js` | ClickHouse (siem) |
| Security Operations & Incident Response | `soc-intel.html` | After-hours monitoring | `siem:engine/detect/routes.js`<br>`siem:engine/reports/routes.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/afterhours/routes.js` | sentra-siem state: rules<br>ClickHouse (siem) |
| Security Operations & Incident Response | `soc-live.html` | Live SIEM Stream | `siem:engine/soc/copilot-routes.js`<br>`siem:engine/api/routes.js` | ClickHouse (siem) |
| Security Operations & Incident Response | `soc-lr.html` | SIEM vs LogRhythm | `siem:engine/integrations/routes.js`<br>`siem:engine/soc/routes.js`<br>`siem:engine/api/routes.js`<br>`itam:engine/routes.js`<br>`siem:engine/api/lr-import.js` | ClickHouse (siem)<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans |
| Security Operations & Incident Response | `soc-overview.html` | SOC Overview | `itam:engine/workflow-auto.js`<br>`siem:engine/soc/analyst-routes.js` | sentra-itam store: wf_requests<br>sentra-itam store: wf_schedules<br>sentra-itam store: wf_cfg<br>sentra-itam store: counters |
| Security Operations & Incident Response | `soc-performance.html` | SOC Performance | `siem:engine/soc/analyst-routes.js` | — |
| Security Operations & Incident Response | `soc-response.html` | Playbooks & Approvals | `siem:engine/soc/routes.js`<br>`siem:engine/integrations/routes.js` | — |
| Security Operations & Incident Response | `soc-sources.html` | Log Sources & Agents | `siem:engine/collect/cloud-data-routes.js`<br>`siem:engine/api/routes.js`<br>`itam:engine/routes.js`<br>`itam:engine/asset-delete.js`<br>`siem:engine/netops/routes.js` | ClickHouse (siem)<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans<br>sentra-itam store: relationships<br>sentra-itam store: disc_devices<br>… |
| Security Operations & Incident Response | `soc-ti.html` | Threat Intelligence | `siem:engine/soc/views-routes.js`<br>`siem:engine/detect/routes.js` | sentra-siem state: rules |
| Security Operations & Incident Response | `soc-tickets.html` | SIEM Health & SLA | — | — |
| Security Operations & Incident Response | `soc-ueba.html` | User Behaviour (UEBA) | `siem:engine/soc/views-routes.js`<br>`siem:engine/ueba/api.js`<br>`siem:engine/soc/departments.js` | ClickHouse (siem) |
| Security Operations & Incident Response | `soc-xdr.html` | XDR | `siem:engine/xdr/routes.js` | — |
| Servers & Virtualization | `add-server.html` | Add Server / Device | `itam:engine/discovery-advisor.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`itam:engine/discovery/routes.js`<br>`itam:engine/asset-delete.js`<br>`itam:engine/asset-links.js` | sentra-itam store: scope_proposals<br>sentra-itam store: scope_ai_drafts<br>sentra-itam store: disc_devices<br>sentra-itam store: assets<br>sentra-siem state: webhooks<br>sentra-itam store: relationships<br>… |
| Servers & Virtualization | `capacity.html` | Capacity Planning | `itam:engine/virt-capacity.js` | sentra-itam store: core_lic_facts<br>sentra-itam store: virt_platforms<br>sentra-itam store: virt_capacity<br>sentra-itam store: virt_capacity_hist<br>sentra-itam store: virt_vm_hist<br>sentra-itam store: virt_capacity_cfg<br>… |
| Servers & Virtualization | `exchange-reports.html` | Exchange Reports | `siem:engine/soc/exchange-reports.js`<br>`siem:engine/soc/mailstats.js` | sentra-siem state: exrep_parts<br>sentra-siem state: exrep_daily<br>sentra-siem state: exrep_meta<br>ClickHouse (siem) |
| Servers & Virtualization | `exchange-servers.html` | Exchange Servers | — | — |
| Servers & Virtualization | `nutanix-vms.html` | Nutanix VMs | `itam:engine/virt-capacity.js` | sentra-itam store: core_lic_facts<br>sentra-itam store: virt_platforms<br>sentra-itam store: virt_capacity<br>sentra-itam store: virt_capacity_hist<br>sentra-itam store: virt_vm_hist<br>sentra-itam store: virt_capacity_cfg<br>… |
| Servers & Virtualization | `oracle-linux-servers.html` | Oracle Linux Servers | — | — |
| Servers & Virtualization | `remote-console.html` | Remote Console | `itam:engine/remote-console.js` | sentra-itam store: console_requests<br>sentra-itam store: console_sessions<br>sentra-itam store: console_config<br>sentra-itam store: console_bmc<br>sentra-itam store: assets |
| Servers & Virtualization | `server-availability.html` | Server Availability | `siem:engine/netops/routes.js`<br>`itam:engine/routes.js`<br>`itam:engine/asset-delete.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`siem:engine/netops/synthetic-routes.js` | sentra-siem state: nac_hist<br>sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans<br>sentra-itam store: relationships<br>sentra-itam store: disc_devices<br>… |
| Servers & Virtualization | `servers.html` | All Servers | — | — |
| Servers & Virtualization | `solaris-servers.html` | Solaris Servers | — | — |
| Servers & Virtualization | `virt-power.html` | Power Control | `itam:engine/virt-power.js` | sentra-itam store: virt_capacity<br>sentra-itam store: virt_platforms<br>sentra-itam store: virt_power<br>sentra-itam store: virt_power_bmc<br>sentra-itam store: counters |
| Servers & Virtualization | `virtual-network-map.html` | Virtual Network Map | `itam:engine/virt-network.js` | sentra-itam store: vnet_proposals<br>sentra-itam store: vnet_snap<br>sentra-itam store: vnet_changes |
| Servers & Virtualization | `virtualization.html` | Virtualization | `itam:engine/virt-admin.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`siem:engine/integrations/routes.js`<br>`itam:engine/virt.js` | sentra-itam store: virt_capacity<br>sentra-itam store: virt_changes<br>sentra-itam store: virt_admin_cfg<br>sentra-itam store: counters<br>sentra-itam store: virt_platforms<br>sentra-itam store: disc_devices<br>… |
| Servers & Virtualization | `vmware-servers.html` | VMware | — | — |
| Servers & Virtualization | `vsphere-studio.html` | vSphere Studio | `itam:engine/vsphere-studio.js` | — |
| Servers & Virtualization | `windows-servers.html` | Windows Servers | — | — |
| Storage, Backup & DR | `backup.html` | Backup Coverage | `itam:engine/backup.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`siem:engine/integrations/routes.js` | sentra-itam store: backup_platforms<br>sentra-itam store: backup_objects<br>sentra-itam store: backup_settings<br>sentra-itam store: backup_exempt<br>sentra-itam store: assets<br>sentra-itam store: virt_capacity<br>… |
| Storage, Backup & DR | `dr-drills.html` | DR & BCM Drills | `itam:engine/grc.js` | sentra-itam store: grc_attestations<br>sentra-itam store: grc_reviews<br>sentra-itam store: grc_drafts<br>sentra-itam store: counters<br>sentra-itam store: assets<br>sentra-itam store: disc_devices<br>… |
| Storage, Backup & DR | `dr-replication.html` | DR Replication | `itam:engine/virt-capacity.js` | sentra-itam store: core_lic_facts<br>sentra-itam store: virt_platforms<br>sentra-itam store: virt_capacity<br>sentra-itam store: virt_capacity_hist<br>sentra-itam store: virt_vm_hist<br>sentra-itam store: virt_capacity_cfg<br>… |
| Storage, Backup & DR | `dr-studio.html` | DR Studio | `itam:engine/dr-studio.js` | sentra-itam store: dr_history<br>sentra-itam store: dr_rpo |
| Storage, Backup & DR | `storage.html` | Storage | `itam:engine/storage.js`<br>`siem:engine/collect/cloud-data-routes.js`<br>`siem:engine/integrations/routes.js` | sentra-itam store: storage_platforms<br>sentra-itam store: storage_snapshots<br>sentra-itam store: storage_settings<br>sentra-itam store: assets |
| Workplace: Desktops, Printers & Voice | `cctv.html` | CCTV / NVR | `siem:engine/facilities/routes.js`<br>`itam:engine/asset-delete.js`<br>`siem:engine/integrations/routes.js` | sentra-itam store: assets<br>sentra-itam store: relationships<br>sentra-itam store: disc_devices<br>sentra-itam store: disc_ignores<br>sentra-itam store: agents |
| Workplace: Desktops, Printers & Voice | `desktop-patches.html` | Patch Management | `itam:engine/desktops.js` | sentra-itam store: me_ec_computers<br>sentra-itam store: assets<br>sentra-itam store: me_tickets<br>sentra-itam store: desktop_remote_sessions<br>sentra-itam store: desktop_settings |
| Workplace: Desktops, Printers & Voice | `desktops.html` | User Desktops | `siem:engine/printers/routes.js`<br>`itam:engine/desktops.js`<br>`itam:engine/desksupport.js` | sentra-itam store: me_ec_computers<br>sentra-itam store: assets<br>sentra-itam store: me_tickets<br>sentra-itam store: desktop_remote_sessions<br>sentra-itam store: desktop_settings<br>sentra-itam store: me_config<br>… |
| Workplace: Desktops, Printers & Voice | `door-access.html` | Door Access | `siem:engine/facilities/routes.js`<br>`itam:engine/servers.js`<br>`siem:engine/integrations/routes.js` | sentra-itam store: assets<br>sentra-itam store: disc_devices<br>sentra-itam store: disc_trust<br>sentra-itam store: server_os_health<br>sentra-itam store: server_links<br>sentra-itam store: db_server_health |
| Workplace: Desktops, Printers & Voice | `end-user-devices.html` | End-User Devices | `itam:engine/asset-delete.js`<br>`itam:engine/routes.js`<br>`siem:engine/collect/m365-routes.js`<br>`itam:engine/manageengine.js` | sentra-itam store: assets<br>sentra-itam store: relationships<br>sentra-itam store: disc_devices<br>sentra-itam store: disc_ignores<br>sentra-itam store: agents<br>sentra-itam store: ai_results<br>… |
| Workplace: Desktops, Printers & Voice | `facilities.html` | Facilities & Devices | `siem:engine/printers/routes.js`<br>`siem:engine/netops/routes.js`<br>`itam:engine/locations.js`<br>`siem:engine/facilities/routes.js` | sentra-siem state: nac_hist<br>sentra-itam store: locations<br>sentra-itam store: assets |
| Workplace: Desktops, Printers & Voice | `hr-movers.html` | HR Movers | `itam:engine/movers.js` | sentra-itam store: movers |
| Workplace: Desktops, Printers & Voice | `hr-offboarding.html` | HR Offboarding | `itam:engine/exo.js`<br>`itam:engine/offboarding.js`<br>`itam:engine/mdm.js` | sentra-itam store: exo_cfg<br>sentra-itam store: offboarding<br>sentra-itam store: offboarding_apps<br>sentra-itam store: assets<br>sentra-itam store: handovers<br>sentra-itam store: pdpl_records<br>… |
| Workplace: Desktops, Printers & Voice | `hr-onboarding.html` | HR Onboarding | `itam:engine/m365-licensing.js`<br>`itam:engine/onboarding.js`<br>`itam:engine/onboarding-ad.js`<br>`itam:engine/routes.js`<br>`itam:engine/discovery/routes.js` | sentra-itam store: onboarding_m365<br>sentra-itam store: onboarding<br>sentra-itam store: assets<br>sentra-itam store: onboarding_ad<br>sentra-itam store: onboarding_secrets<br>sentra-itam store: ai_results<br>… |
| Workplace: Desktops, Printers & Voice | `manageengine.html` | ManageEngine | `itam:engine/desksupport.js`<br>`siem:engine/collect/webhook-ingest.js`<br>`itam:engine/routes.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/detect/routes.js`<br>`itam:engine/asset-delete.js`<br>`siem:engine/collect/cloud-data-routes.js` | sentra-itam store: me_config<br>sentra-itam store: me_ec_computers<br>sentra-itam store: desk_config<br>sentra-itam store: desk_triage<br>sentra-itam store: desk_patch<br>sentra-itam store: assets<br>… |
| Workplace: Desktops, Printers & Voice | `mdm.html` | Endpoint & Mobile Management | `itam:engine/mdm.js` | sentra-itam store: mdm_cfg<br>sentra-itam store: mdm_inventory |
| Workplace: Desktops, Printers & Voice | `printers.html` | Printers | `siem:engine/printers/routes.js`<br>`itam:engine/routes.js`<br>`siem:engine/integrations/routes.js`<br>`siem:engine/netops/routes.js`<br>`itam:engine/desktops.js` | sentra-itam store: assets<br>sentra-itam store: ai_results<br>sentra-itam store: refresh_plans<br>sentra-siem state: nac_hist<br>sentra-itam store: me_ec_computers<br>sentra-itam store: me_tickets<br>… |
| Workplace: Desktops, Printers & Voice | `support-center.html` | Support Center | `itam:engine/desksupport.js`<br>`itam:engine/routes.js`<br>`siem:engine/integrations/routes.js` | sentra-itam store: me_config<br>sentra-itam store: me_ec_computers<br>sentra-itam store: desk_config<br>sentra-itam store: desk_triage<br>sentra-itam store: desk_patch<br>sentra-itam store: assets<br>… |
| Workplace: Desktops, Printers & Voice | `tickets.html` | Tickets | `itam:engine/ticket-intel.js` | sentra-itam store: me_tickets<br>sentra-itam store: assets |
| Workplace: Desktops, Printers & Voice | `uc.html` | UC Overview | `itam:engine/asset-delete.js`<br>`itam:engine/routes.js`<br>`siem:engine/netops/routes.js` | sentra-itam store: assets<br>sentra-itam store: relationships<br>sentra-itam store: disc_devices<br>sentra-itam store: disc_ignores<br>sentra-itam store: agents<br>sentra-itam store: ai_results<br>… |
| Workplace: Desktops, Printers & Voice | `voice-troubleshoot.html` | One-way Audio | `siem:engine/netops/routes.js`<br>`itam:engine/asset-delete.js` | sentra-siem state: nac_hist<br>sentra-itam store: assets<br>sentra-itam store: relationships<br>sentra-itam store: disc_devices<br>sentra-itam store: disc_ignores<br>sentra-itam store: agents |

## Pages deployed but not reachable by clicking

None.


## API calls with no backend route found

Usually the portal's own routes (/api/db, /auth, whoami) or a path built at run time - each one is worth a look.

| Page | Call |
|---|---|
| `audit-start.html` | `/api/itam` |
| `compliance-overview.html` | `/api/itam/overview-intel` |
| `sama-siem.html` | `/api/soc/compliance/sama/report` |
| `index.html` | `/api/itam/infra-intel` |
| `door-access.html` | `/api/device/list` |
| `door-access.html` | `/api/door/list` |
| `door-access.html` | `/api/transaction/list` |
| `tickets.html` | `/api/soc/integrations/manageengine/tickets` |
| `tickets.html` | `/api/soc/integrations/manageengine/status` |

## Unused - not in the clean tree

Nothing that runs or is deployed refers to these. They stay in GitHub history.

| Folder | Files |
|---|---|
| `itam:.gitignore` | 1 |
| `itam:install/ad-tls-check.sh` | 1 |
| `itam:install/apply_safari_itam.py` | 1 |
| `itam:install/oracle-code-change-audit.sql` | 1 |
| `itam:ui/INSTALL-PLATFORM.md` | 1 |
| `itam:ui/discovery-module.js` | 1 |
| `itam:ui/discovery-nav.json` | 1 |
| `itam:ui/discovery.ar.json` | 1 |
| `itam:ui/itam-module.js` | 1 |
| `itam:ui/itam-nav.json` | 1 |
| `itam:ui/itam.ar.json` | 1 |
| `ops:check-agents.ps1` | 1 |
| `ops:check-dashboard-freshness.ps1` | 1 |
| `ops:check-log-sources.ps1` | 1 |
| `ops:check-m365.ps1` | 1 |
| `ops:check-server.ps1` | 1 |
| `ops:check-siem.ps1` | 1 |
| `ops:collect-portal-auth.sh` | 1 |
| `ops:collect-sources.ps1` | 1 |
| `ops:connect-to-siem.ps1` | 1 |
| `ops:deploy-modules.ps1` | 1 |
| `ops:diff-discovery-engine.ps1` | 1 |
| `ops:enable-syslog-514.ps1` | 1 |
| `ops:find-silverpeak-login.ps1` | 1 |
| `ops:fix-silverpeak-406.ps1` | 1 |
| `ops:get-portal-auth.ps1` | 1 |
| `ops:import-grcai-source.ps1` | 1 |
| `ops:lint-terms.js` | 1 |
| `ops:portal-find-sidebar.sh` | 1 |
| `ops:sama-coverage-doc.py` | 1 |
| `ops:setup-platform-workspace.ps1` | 1 |
| `ops:test-silverpeak.ps1` | 1 |
| `ops:update-discovery-now.ps1` | 1 |
| `siem:.gitattributes` | 1 |
| `siem:.gitignore` | 1 |
| `siem:CLAUDE.md` | 1 |
| `siem:engine/detect` | 2 |
| `siem:engine/onboard` | 1 |
| `siem:scripts/compare-server.ps1` | 1 |
| `siem:server-snapshots/sentra-siem` | 147 |
| `siem:tools/attack-catalog-gen.py` | 1 |
| `siem:ui/mock` | 1 |
| `ui:cost-optimization.html` | 1 |

Every file with its status and reason: `docs/files.csv`. Every page with its API calls: `docs/pages.csv`.
