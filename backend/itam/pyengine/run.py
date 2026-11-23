# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Entry point for the Python modules of IT Asset Management (gradual move from Node.js, docs/PYTHON-MIGRATION.md).

The engine starts:  python3 -I pyengine/run.py   and writes ONE JSON request on stdin, reads ONE JSON answer on stdout:
  {"op": "storage.collect", "kind": "ontap"|"msa", "cred": {...}, "opts": {...}}   -> the array model
  {"op": "storage.test",    "kind": ..., "cred": ..., "opts": ...}                 -> {ok, message} | error
  {"op": "backup.collect" | "backup.test", "kind": "netbackup"|"veeam"|"cohesity", ...}  -> the backup model
  {"op": "cisco.coverage", "token_url", "base_url", "client_id", "client_secret", "serials", "per_call"}  -> {entries, error?}
  {"op": "virt.vcenter" | "virt.vcenter_hosts" | "virt.nutanix", "target", "secret", "opts"}  -> the capacity model
  {"op": "discovery.collect" | "discovery.test", "method": vcenter|esxi|nutanix|azure|aws|cucm, "cred", "opts"}
  {"op": "rules.reconcile", assets, devices, accepted, settings, now, avail, targets, netdevs} -> the reconciliation report
  {"op": "store.read" | "store.verify_audit" | "store.audit_tail", "dir", ...}   -> the store, read-only (store.py)
  {"op": "roles.list" | "roles.me" | "roles.approvers", "dir", "catalogue", "user"?}  -> the Roles routes, from the store
  {"op": "pdpl.assess" | "pdpl.sign" | "pdpl.statement", records, confirms, tests, now, ...}  -> the PDPL consultant (pdpl_rules.py)
  {"op": "certs.assess", endpoints, scans, renewals, policy, now}  -> certificate lifecycle (cert_rules.py)
  {"op": "consent.apply" | "consent.get" | "consent.stats" | "consent.last", db, ...}  -> consent state in SQLite (consent_db.py)
  {"op": "infra_audit.<test>", evidence | devices | report, now}  -> the AI auditors' AD / network / database / application tests (infra_audit_rules.py)
  {"op": "ping"}                                                                 -> {ok, python, modules}
Credentials only ever travel on stdin (never argv or the environment, which other users can see), and nothing is
written to disk. A request that cannot be handled is answered {"ok": false, "error_class": ..., "error": ...}.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # -I leaves the script folder out of the path

import backup_sources  # noqa: E402
import cisco_api  # noqa: E402
import discovery_sources  # noqa: E402
import reconcile_rules  # noqa: E402
import asset_rules  # noqa: E402
import lifecycle_rules  # noqa: E402
import core_licensing_rules  # noqa: E402
import roles_rules  # noqa: E402
import roles_write  # noqa: E402
import grc_write  # noqa: E402
import assets_write  # noqa: E402
import core_write  # noqa: E402
import addons_write  # noqa: E402
import support_write  # noqa: E402
import desk_budget_write  # noqa: E402
import ai_guard  # noqa: E402
import assets_read  # noqa: E402
import grc_read  # noqa: E402
import virt_read  # noqa: E402
import pdpl_rules  # noqa: E402
import cert_rules  # noqa: E402
import infra_audit_rules  # noqa: E402
import consent_db  # noqa: E402
import pdpl_workflows  # noqa: E402
import pdpl_intake  # noqa: E402
import pdpl_vendor  # noqa: E402
import mail_rep_rules  # noqa: E402
import mail_route_rules  # noqa: E402
import mail_avail_rules  # noqa: E402
import mail_report_rules  # noqa: E402
import server_rules  # noqa: E402
import app_route  # noqa: E402
import hardening_rules  # noqa: E402
import pdpl_assessment  # noqa: E402
import pdpl_access  # noqa: E402
import pdpl_catalog  # noqa: E402
import pdpl_ropa  # noqa: E402
import pdpl_ar  # noqa: E402  (Arabic for findings: every pdpl.* answer, and pdpl_office)
import pdpl_office  # noqa: E402
import ndmo_rules  # noqa: E402
import nca_ecc_rules  # noqa: E402
import iso27001_rules  # noqa: E402
import sama_ia_rules  # noqa: E402
import assist_rules  # noqa: E402
import scope_rules  # noqa: E402
import cmdb_rules  # noqa: E402
import asset_studio_rules  # noqa: E402
import lifecycle_studio_rules  # noqa: E402
import cost_studio_rules  # noqa: E402
import owner_studio_rules  # noqa: E402
import dr_studio_rules  # noqa: E402
import vsphere_studio_rules  # noqa: E402
import firecompass_rules  # noqa: E402
import report_center_rules  # noqa: E402
import notify_rules  # noqa: E402
import ropa_flow_rules  # noqa: E402
import vapt_center_rules  # noqa: E402
import sama_itaudit_rules  # noqa: E402
import discovery_studio_rules  # noqa: E402
import ciso_insights_rules  # noqa: E402
import nhi_rules  # noqa: E402
import cert_estate  # noqa: E402
from asset_rules import _clean as js_clean  # noqa: E402
import store  # noqa: E402
import storage_sources  # noqa: E402
import virt_capacity  # noqa: E402

OPS = {
    'storage.collect': lambda r: getattr(storage_sources, r.get('kind') or '', None)(r.get('cred') or {}, r.get('opts') or {})
    if r.get('kind') in ('ontap', 'msa') else {'ok': False, 'error_class': 'config', 'error': 'unknown storage platform'},
    'storage.test': lambda r: storage_sources.test(r.get('kind'), r.get('cred') or {}, r.get('opts') or {}),
    'backup.collect': lambda r: getattr(backup_sources, r.get('kind') or '', None)(r.get('cred') or {}, r.get('opts') or {})
    if r.get('kind') in ('netbackup', 'veeam', 'cohesity') else {'ok': False, 'error_class': 'config', 'error': 'unknown platform'},
    'backup.test': lambda r: backup_sources.test(r.get('kind'), r.get('cred') or {}, r.get('opts') or {}),
    'cisco.coverage': lambda r: cisco_api.coverage(r),
    'virt.vcenter': lambda r: virt_capacity.vcenter(r.get('target') or {}, r.get('secret') or {}, r.get('opts') or {}),
    'virt.vcenter_hosts': lambda r: virt_capacity.vcenter_hosts(r.get('target') or {}, r.get('secret') or {}, r.get('opts') or {}),
    'virt.nutanix': lambda r: virt_capacity.nutanix(r.get('target') or {}, r.get('secret') or {}, r.get('opts') or {}),
    'discovery.collect': lambda r: discovery_sources.run('collect', r.get('method'), r.get('cred') or {}, r.get('opts') or {}),
    'discovery.test': lambda r: discovery_sources.run('test', r.get('method'), r.get('cred') or {}, r.get('opts') or {}),
    'rules.reconcile': lambda r: reconcile_rules.compare(r),
    'rules.findings': lambda r: asset_rules.findings(r),
    'rules.licence_facts': lambda r: asset_rules.licence_facts(r),
    'rules.unlicensed': lambda r: asset_rules.unlicensed(r),
    'rules.lifecycle': lambda r: lifecycle_rules.view(r),
    'rules.core_licensing': lambda r: core_licensing_rules.view(r),
    'store.read': lambda r: store.op_read(r),
    'store.verify_audit': lambda r: store.op_verify(r),
    'store.audit_tail': lambda r: store.op_tail(r),
    'roles.list': lambda r: roles_rules.list_(r),
    'roles.me': lambda r: roles_rules.me(r),
    'roles.approvers': lambda r: roles_rules.approvers(r),
    'assets.list': lambda r: assets_read.list_(r),
    'assets.detail': lambda r: assets_read.detail(r),
    'assets.lookup': lambda r: assets_read.lookup(r),
    'assets.software': lambda r: assets_read.software(r),
    'assets.licences': lambda r: assets_read.licences(r),
    'assets.cmdb': lambda r: assets_read.cmdb(r),
    'certs.assess': lambda r: cert_rules.assess(r),
    'certs.plan_request': lambda r: cert_rules.plan_request(r),
    'certs.accept_issued': lambda r: cert_rules.accept_issued(r),
    'certs.plan_install': lambda r: cert_rules.plan_install(r),
    'pdpl.assess': lambda r: pdpl_rules.assess(r),
    'pdpl.sign': lambda r: pdpl_rules.sign(r),
    'pdpl.statement': lambda r: pdpl_rules.statement_state(r),
    'pdpl.discovery': lambda r: pdpl_rules.discovery(r),
    'pdpl.breach_draft': lambda r: pdpl_rules.breach_draft(r),
    'pdpl.dpia_questions': lambda r: pdpl_rules.dpia_questions(r),
    'pdpl.dpia_score': lambda r: pdpl_rules.dpia_score(r),
    'pdpl.consent_view': lambda r: pdpl_rules.consent_view(r),
    'pdpl.retention_view': lambda r: pdpl_rules.retention_view(r),
    'pdpl.hold_check': lambda r: pdpl_rules.hold_check(r),
    'pdpl.holds_view': lambda r: pdpl_rules.holds_view(r),
    'pdpl.translate': lambda r: {'findings': [f for f in (r.get('findings') or []) if isinstance(f, dict)][:2000]},   # Arabic added by pdpl_ar.annotate below
    'ping': lambda r: {'ok': True, 'python': sys.version.split()[0], 'modules': ['storage', 'backup', 'cisco', 'virt', 'discovery', 'rules', 'store', 'roles', 'assets', 'grc', 'virt-admin', 'pdpl', 'ndmo', 'ecc', 'nhi', 'certs', 'infra_audit', 'hardening']},
}


OPS.update(server_rules.OPS)   # servers by platform (engine/servers.js)
OPS.update(app_route.OPS)   # application route map (engine/app-route.js)
OPS.update(hardening_rules.OPS)   # baseline hardening scan, CIS / SAMA / NCA (engine/hardening.js)
OPS.update(pdpl_assessment.OPS)   # PDPL self-assessment questionnaire (engine/pdpl-assessment.js)
OPS.update(mail_report_rules.OPS)   # regulator report on an e-mail incident (engine/mail-reputation.js)
OPS.update(mail_avail_rules.OPS)   # e-mail availability against its target (engine/mail-reputation.js)
OPS.update(mail_route_rules.OPS)   # mail route flow, hop by hop (engine/mail-reputation.js)
OPS.update(mail_rep_rules.OPS)   # mail server reputation against Spamhaus (engine/mail-reputation.js)
OPS.update(pdpl_workflows.OPS)   # the PDPL operating pages (engine/pdpl-workflows.js)
OPS.update(pdpl_intake.OPS)   # data subject request intake (engine/pdpl-intake.js)
OPS.update(pdpl_vendor.OPS)   # vendor risk: tier, questionnaire, residual, schedule (engine/pdpl-vendor.js)
OPS.update(consent_db.OPS)   # consent state in SQLite (engine/pdpl-consent.js)
OPS.update(pdpl_access.OPS)   # sensitive-access log (engine/pdpl-access.js)
OPS.update(pdpl_catalog.OPS)   # data catalog and identity correlation (engine/pdpl-catalog.js)
OPS.update(pdpl_ropa.OPS)   # RoPA by department (engine/pdpl-ropa.js)
OPS.update(pdpl_office.OPS)   # Privacy Office: organisation, routed tasks, escalation, route map (engine/pdpl-office.js)
OPS.update(ndmo_rules.OPS)   # NDMO data management register (engine/ndmo.js)
OPS.update(assist_rules.OPS)   # Compliance Assistant: plain-language answers over every register (engine/compliance-assist.js)
OPS.update(scope_rules.OPS)   # Scope Studio: coverage, gaps, scope health, learned method yield, duration (engine/discovery-advisor.js)
OPS.update(cmdb_rules.OPS)
OPS.update(asset_studio_rules.OPS)
OPS.update(lifecycle_studio_rules.OPS)
OPS.update(cost_studio_rules.OPS)
OPS.update(owner_studio_rules.OPS)
OPS.update(dr_studio_rules.OPS)   # CMDB Studio: quality, duplicates, relationship inference, blast radius (engine/cmdb-studio.js)
OPS.update(vsphere_studio_rules.OPS)   # vSphere Studio: host / cluster / VM health, imbalance, workload profiles (engine/vsphere-studio.js)
OPS.update(sama_itaudit_rules.OPS)   # SAMA IT audit readiness: 5 areas + audit process, evidence, draft findings (engine/sama-itaudit.js)
OPS.update(vapt_center_rules.OPS)   # VAPT Center: merge, priority, SLA, paths, delta, MTTR, rollups (engine/vapt-center.js)
OPS.update(ropa_flow_rules.OPS)   # RoPA workflow: forecast, risk + DPIA, duplicates, retention, proposed drafts (engine/pdpl-ropa-flow.js)
OPS.update(notify_rules.OPS)   # Notification & Escalation: ack times, escalation prediction, noise, fatigue, storms (engine/notify-center.js)
OPS.update(report_center_rules.OPS)   # Reporting Center: KPI trends, forecasts, unusual moves (engine/report-center.js)
OPS.update(firecompass_rules.OPS)   # FireCompass: field mapping, normalisation, merge with Greenbone, risk (engine/firecompass.js)
OPS.update(discovery_studio_rules.OPS)   # Discovery Studio: recommendations learnt from decisions, run anomalies, credential health (engine/discovery-studio.js)
OPS.update(ciso_insights_rules.OPS)   # CISO dashboard: posture forecast, domain movers, alert anomaly (engine/ciso.js /ciso/insights)
OPS.update(nca_ecc_rules.OPS)   # NCA ECC verification register (engine/nca-ecc.js)
OPS.update(iso27001_rules.OPS)   # ISO/IEC 27001:2022 ISMS register, audit programme, readiness (engine/iso27001.js)
OPS.update(sama_ia_rules.OPS)   # SAMA CSF + Insurance Authority automated assessment (engine/sama-ia.js)
OPS.update(nhi_rules.OPS)   # Non-Human Identities register (engine/nhi.js)
OPS.update(cert_estate.OPS)   # certificate lifecycle across the estate: keystores, CA, network (engine/certs.js)
OPS.update(infra_audit_rules.OPS)   # the AI auditors' infrastructure tests (CY-16..CY-20, IT-15, IT-16)
OPS.update(roles_write.OPS)
OPS.update(grc_write.OPS)   # the GRC draft / drill writes (step 9c): decided here, committed by Node.js   # the Roles writes (step 9b): decided here, committed by Node.js
OPS.update(ai_guard.OPS)   # the AI guard rails (step 9j-a): compared with Node.js on every call
OPS.update(assets_write.OPS)   # the human asset writes (step 9d): add, edit, lifecycle, move, assign - committed by Node.js
for _k, _f in list(grc_read.OPS.items()) + list(virt_read.OPS.items()) + list(core_write.OPS.items()) + list(addons_write.OPS.items()) + list(support_write.OPS.items()) + list(desk_budget_write.OPS.items()):   # + the 9e-9h writes   # GRC reads (step 8d); undefined values dropped as JSON.stringify does
    OPS[_k] = (lambda f: lambda r: js_clean(f(r)))(_f)
for _k in [k for k in OPS if k.startswith('assets.')]:
    OPS[_k] = (lambda f: lambda r: js_clean(f(r)))(OPS[_k])

# every PDPL answer carries the Arabic for its findings (pyengine/pdpl_ar.py); the pages show it when the language is Arabic
for _k in [k for k in OPS if k.startswith('pdpl')]:
    OPS[_k] = (lambda f: lambda r: pdpl_ar.annotate(f(r)))(OPS[_k])


def main():
    try:
        req = json.loads(sys.stdin.read() or '{}')
    except ValueError:
        out = {'ok': False, 'error_class': 'protocol', 'error': 'the request is not JSON'}
    else:
        fn = OPS.get(req.get('op'))
        try:
            out = fn(req) if fn else {'ok': False, 'error_class': 'config', 'error': 'unknown operation %r' % req.get('op')}
        except Exception as e:  # pragma: no cover - modules answer classified errors themselves
            out = {'ok': False, 'error_class': 'protocol', 'error': '%s: %s' % (type(e).__name__, e)}
    sys.stdout.write(json.dumps(out, separators=(',', ':')))
    sys.stdout.flush()


if __name__ == '__main__':
    main()
