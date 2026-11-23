# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The AI PDPL Consultant's rules (Saudi Personal Data Protection Law, Royal Decree M/19 amended by M/148; its Implementing
Regulation; SDAIA's Cross-Border Transfer Regulation v2.0). Python decides, Node.js commits (engine/pdpl.js): this module
reads only what it is given and writes nothing.

  pdpl.assess  {records, confirms, tests, now}            -> requirements, findings, counts, readiness, attestation state
  pdpl.sign    {records, confirms, tests, now, attestation, signer:{user, role}, as: dpo|management, digest}
                                                           -> {put, audit} | {refuse: {status, error}}

A requirement is NON-COMPLIANT when the registers show a breach of it (whatever a person recorded); "automated check
passed" waits for a person to confirm; nothing is compliant without evidence. The statement is an internal self-
assessment signed by the named DPO and countersigned by a different person in management - not an SDAIA certificate.
Article references are as read from the law and regulations, for the DPO to verify: the official SDAIA texts are
https://sdaia.gov.sa/en/SDAIA/about/Documents/PersonalDataProtectionLaw.pdf (PDPL, M/19 amended by M/148) and
https://sdaia.gov.sa/en/SDAIA/about/Documents/ImplementingRegulation.pdf (Implementing Regulation). Standard library only.
"""
import hashlib
import json
from datetime import datetime, timezone
from org_brand import fill as _org_fill

DAY = 86400000
VALID_DAYS = 365
# PDPL Art. 1 sensitive data. Credit data is NOT sensitive: it is its own class (Art. 24, IR Arts. 11 / 27) - explicit consent,
# the person told of every disclosure request - but no impact assessment and no 'sensitive' label because of it.
SENSITIVE = ('health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage')
SEVN = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
# insurer processing that needs an impact assessment whatever the data (PDPL Art. 22; IR Art. 25: linking sources,
# continuous monitoring, new technologies, automated decisions likely to cause serious harm)
INSURER_TRIGGERS = [('fraud_scoring', 'fraud scoring / fraud analytics on customers and claimants'), ('profiling', 'profiling or segmentation of individuals (pricing, retention, marketing)'),
                    ('automated_underwriting', 'automated underwriting or pricing decisions'), ('telematics', 'telematics or wearables (continuous monitoring)')]


def insurer_triggers(r):
    return [lbl for k, lbl in INSURER_TRIGGERS if r.get(k)]


def ms(v):
    """ISO date / date-time (UTC when no zone) -> epoch ms, or None."""
    if not v or not isinstance(v, str):
        return None
    s = v.strip()
    try:
        if len(s) == 10:
            d = datetime.strptime(s, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        else:
            s2 = s[:-1] + '+00:00' if s.endswith('Z') else s
            d = datetime.fromisoformat(s2)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp() * 1000)
    except ValueError:
        return None


def iso(t):
    return datetime.fromtimestamp(t / 1000, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t % 1000)


R = lambda id_, area, title, ref, procedure, evidence, auto=None: {  # noqa: E731
    'id': id_, 'area': area, 'title': title, 'ref': ref, 'procedure': procedure, 'evidence': evidence, 'auto': auto}
REQS = [
    R('P-01', 'Governance', 'A Data Protection Officer is appointed and named', 'Implementing Regulation Art. 32',
      'Confirm the appointment letter and that the DPO is the contact point for SDAIA. An insurer whose core activities process health data is in the mandatory case.',
      'DPO appointment letter; contact published', 'dpo'),
    R('P-02', 'Governance', _org_fill('{{org.short}} is registered as a controller on SDAIA\'s National Data Governance Platform, where required'), 'SDAIA Personal Data Controllers Register',
      'Confirm the registration and that its details are current.', 'Registration reference / certificate of registration', 'register'),
    R('P-03', 'Transparency', 'A privacy policy is published and available before personal data is collected', 'PDPL Arts. 12-13',
      'Inspect the published policy: legal basis, purpose, recipients, transfers outside the Kingdom, rights, contact.', 'Privacy policy URL and approval', 'policy'),
    R('P-04', 'Records', 'Records of processing activities are kept, complete and reviewed', 'Implementing Regulation Art. 33',
      'Inspect the register: purpose, legal basis, categories, recipients, transfers, retention, security measures, owner; reviewed in the last 12 months.', 'Records of processing (this register)', 'ropa'),
    R('P-05', 'Lawful basis', 'Every processing activity has a valid legal basis; consent is documented, explicit where required', 'PDPL Arts. 5-6; Implementing Regulation Arts. 11-12',
      'Sample activities: basis recorded; consent records kept; explicit consent for sensitive and credit data and for solely automated decisions.', 'Consent records; basis per activity', 'basis'),
    R('P-06', 'Lawful basis', 'Legitimate interest is used only by assessment, never for sensitive data', 'Implementing Regulation Art. 16',
      'For each activity on legitimate interest: a written assessment before processing, no sensitive data.', 'Legitimate interest assessments', 'lia'),
    R('P-07', 'Risk', 'An impact assessment is done before high-risk processing', 'PDPL Art. 22; Implementing Regulation Art. 25',
      'Sensitive data, several sources combined, continuous monitoring, solely automated decisions: each needs a completed impact assessment.', 'Impact assessments', 'dpia'),
    R('P-08', 'Data subject rights', 'Requests (access, copy, correction, destruction, withdrawal) are answered within 30 days, extended once by 30 with notice', 'PDPL Art. 4; Implementing Regulation Arts. 3-10',
      'Inspect the request log: received, answered, extension notified, identity verified, outcome.', 'Data subject request log (this register)', 'dsr'),
    R('P-09', 'Breach', 'A personal data breach is notified to SDAIA within 72 hours of awareness, and data subjects without undue delay when harm is likely', 'PDPL Art. 20; Implementing Regulation Art. 24',
      'Inspect the breach register: awareness time, SDAIA notification time, data subject notification, content of the notification.', 'Breach register; SDAIA notifications', 'breach'),
    R('P-10', 'Processors', 'Processors work under a written agreement with the required terms and are assessed periodically', 'PDPL Art. 8; Implementing Regulation Art. 17',
      'Inspect each processor agreement: purpose, duration, breach notice, sub-processors, foreign law; an assessment in the last 12 months.', 'Processor agreements; assessments', 'processor'),
    R('P-11', 'Transfers', 'Transfers outside the Kingdom have a basis (adequacy, appropriate safeguards or an exemption) and a risk assessment where required', 'PDPL Art. 29; Cross-Border Transfer Regulation Arts. 2-8',
      'Inspect each transfer: basis, risk assessment for safeguards / exemptions and for continuous or large-scale sensitive transfers; hosting locations agree.', 'Transfer register; risk assessments', 'transfer'),
    R('P-12', 'Retention', 'Personal data is kept only as long as needed, then destroyed or anonymised', 'PDPL Art. 18; Implementing Regulation Art. 19',
      'Inspect the retention period of each activity and evidence of destruction at its end.', 'Retention schedule; destruction records', 'retention'),
    R('P-13', 'Security', 'Organisational, administrative and technical security measures protect personal data', 'PDPL Art. 19; Implementing Regulation Art. 23',
      'Reads the AI auditors\' tests: audit trail intact, credentials sealed, no secret in clear text, leavers\' access removed, logs collected.', 'AI auditor results; NCA controls', 'security'),
    R('P-14', 'Sensitive data', 'Health data is processed under the health-sector controls (Council of Health Insurance), with tiered access', 'PDPL Art. 23; Implementing Regulation Art. 26',
      'Inspect access tiers to health data, documentation of each processing stage and processor terms.', 'Access matrix; health data procedures'),
    R('P-15', 'Sensitive data', 'Credit data is processed with consent and the data subject is told of any disclosure request', 'PDPL Art. 24; Implementing Regulation Art. 27',
      'Inspect consent and disclosure notices for credit data, or record not applicable.', 'Consent records; notices'),
    R('P-16', 'Collection', 'Only the minimum data needed is collected, from the data subject, for the stated purpose', 'PDPL Arts. 10-11',
      'Sample forms and systems; every field linked to a purpose.', 'Data maps; forms'),
    R('P-17', 'Disclosure', 'Personal data is disclosed only on an allowed basis, and each disclosure to an authority is documented', 'PDPL Art. 15; Implementing Regulation Art. 20',
      'Inspect the disclosure log and its bases.', 'Disclosure log'),
    R('P-18', 'Accuracy', 'Corrections are made, recipients told, and processing suspended where inaccuracy could harm', 'PDPL Art. 17; Implementing Regulation Art. 22',
      'Sample corrections and their notifications.', 'Correction records'),
    R('P-19', 'Marketing', 'Marketing and awareness messages need prior consent and an opt-out at least as easy as opting in', 'PDPL Art. 25; Implementing Regulation Arts. 28-29',
      'Inspect consent capture, sender identification and opt-out handling.', 'Consent records; opt-out log'),
    R('P-20', 'Consent', 'Consent can be withdrawn at any time, as easily as it was given, and processing stops', 'Implementing Regulation Art. 12',
      'Test the withdrawal channel; confirm processing stops and recipients are told. The consent ledger accepts a withdrawal on every channel and systems check it before processing.', 'Withdrawal procedure; consent ledger', 'withdrawal'),
    R('P-21', 'Techniques', 'Anonymisation or pseudonymisation is used where the purpose allows', 'Implementing Regulation Arts. 7-9',
      'Inspect where data is anonymised / pseudonymised and the re-identification assessment.', 'Technique register'),
    R('P-22', 'Research', 'Research and statistics use non-identifying data or meet the conditions, or are not applicable', 'PDPL Art. 27; Implementing Regulation Art. 30',
      'Inspect research and statistics uses of personal data.', 'Research register or not-applicable statement'),
    R('P-23', 'People', 'Staff who handle personal data are trained on PDPL and their obligations', 'PDPL Art. 19; Implementing Regulation Art. 23',
      'Inspect training records for staff handling personal data.', 'Training records'),
    R('P-24', 'Records', 'Records of processing are kept for the processing period plus 5 years and given to SDAIA on request', 'Implementing Regulation Art. 33',
      'Confirm the retention of the processing records themselves.', 'Records retention'),
]
SECURITY_TESTS = ('IT-01', 'CY-06', 'CY-13', 'IT-12', 'CY-05')


def _by(records, kind):
    return [r for r in records if r.get('kind') == kind and r.get('status') != 'archived']


def _f(key, sev, title, evidence, rec, req, target=None):
    return {'key': req + ':' + key, 'severity': sev, 'kind': req, 'title': title, 'evidence': [e for e in evidence if e][:8],
            'recommendation': rec, 'target': target or {'type': 'pdpl', 'id': req, 'name': req}}


def _check(rq, records, tests, now):
    """-> (state, detail, findings): state pass | fail | not_tested."""
    a = rq['auto']
    P = (_by(records, 'profile') or [{}])[0]
    ropa = _by(records, 'ropa')
    F = []
    if a == 'dpo':
        if not P:
            return 'not_tested', 'the PDPL profile is not set (Registers → Profile)', []
        if not P.get('dpo_user') or not P.get('dpo_appointed'):
            F.append(_f('dpo', 'high', 'No Data Protection Officer recorded', ['profile: DPO not named or appointment date missing'], 'Appoint a DPO (internal or external), record the appointment and publish the contact.', 'P-01'))
        return ('fail' if F else 'pass'), ('DPO ' + str(P.get('dpo_user')) + ' since ' + str(P.get('dpo_appointed')) if not F else 'no DPO recorded'), F
    if a == 'register':
        if not P:
            return 'not_tested', 'the PDPL profile is not set', []
        if not P.get('sdaia_registered') or not P.get('sdaia_ref'):
            F.append(_f('register', 'high', 'Registration on SDAIA\'s National Data Governance Platform not recorded', ['profile: registered=' + str(bool(P.get('sdaia_registered')))], 'Register as a controller (an insurer processing health data is in scope) and record the reference.', 'P-02'))
        return ('fail' if F else 'pass'), ('registered, reference ' + str(P.get('sdaia_ref')) if not F else 'not registered'), F
    if a == 'policy':
        if not P:
            return 'not_tested', 'the PDPL profile is not set', []
        if not P.get('privacy_policy_published') or not P.get('privacy_policy_url'):
            F.append(_f('policy', 'high', 'Privacy policy not published', [], 'Publish the approved privacy policy where data is collected (portal, app, forms).', 'P-03'))
        return ('fail' if F else 'pass'), ('published at ' + str(P.get('privacy_policy_url')) if not F else 'not published'), F
    if a == 'ropa':
        if not ropa:
            return 'not_tested', 'no processing activity recorded yet', []
        for r in ropa:
            miss = [k for k in ('purpose', 'legal_basis', 'owner') if not r.get(k)] + ([] if r.get('data_categories') else ['data_categories']) + ([] if r.get('retention_months') else ['retention_months'])
            if miss:
                F.append(_f('ropa:' + r['id'] + ':incomplete', 'medium', 'Processing activity "' + str(r.get('name')) + '" is incomplete', ['missing: ' + ', '.join(miss)], 'Complete the record: purpose, legal basis, categories, retention, owner.', 'P-04', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            rv = ms(r.get('reviewed'))
            if not rv or now - rv > VALID_DAYS * DAY:
                F.append(_f('ropa:' + r['id'] + ':review', 'low', 'Processing activity "' + str(r.get('name')) + '" not reviewed in the last 12 months', ['last review: ' + str(r.get('reviewed') or 'never')], 'Review the record with its owner and update the review date.', 'P-04', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        return ('fail' if F else 'pass'), str(len(ropa)) + ' activities' + (', ' + str(len(F)) + ' gap(s)' if F else ', complete and reviewed'), F
    if a == 'basis':
        if not ropa:
            return 'not_tested', 'no processing activity recorded yet', []
        for r in ropa:
            sens = [c for c in (r.get('data_categories') or []) if c in SENSITIVE]
            b = r.get('legal_basis')
            ledger = any(p.get('ropa_id') == r.get('id') and (p.get('events') or 0) > 0 for p in _by(records, 'consent_purpose'))
            if b in ('consent', 'explicit_consent') and not r.get('consent_records') and not ledger:
                F.append(_f('basis:' + r['id'] + ':records', 'high', '"' + str(r.get('name')) + '" relies on consent with no consent records', [], 'Keep provable records of each consent (time, method, purpose).', 'P-05', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            why = sens + (['credit'] if 'credit' in (r.get('data_categories') or []) else [])
            if b == 'consent' and (why or r.get('automated_decision')):
                F.append(_f('basis:' + r['id'] + ':explicit', 'high', '"' + str(r.get('name')) + '" needs explicit consent (' + (', '.join(why) if why else 'solely automated decision') + ')', [], 'Obtain explicit consent, or record another lawful basis.', 'P-05', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        return ('fail' if F else 'pass'), str(len(ropa)) + ' activities checked', F
    if a == 'lia':
        li = [r for r in ropa if r.get('legal_basis') == 'legitimate_interest']
        if not ropa:
            return 'not_tested', 'no processing activity recorded yet', []
        for r in li:
            sens = [c for c in (r.get('data_categories') or []) if c in SENSITIVE]
            if sens:
                F.append(_f('lia:' + r['id'] + ':sensitive', 'critical', '"' + str(r.get('name')) + '" uses legitimate interest for sensitive data (' + ', '.join(sens) + ')', [], 'Legitimate interest cannot cover sensitive data: move to another basis or stop the processing.', 'P-06', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            if 'credit' in (r.get('data_categories') or []):
                F.append(_f('lia:' + r['id'] + ':credit', 'high', '"' + str(r.get('name')) + '" uses legitimate interest for credit data', [], 'Credit data needs the person\'s explicit consent (Implementing Regulation Arts. 11, 27): obtain it or record another basis the law gives.', 'P-15', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            if not r.get('lia_done'):
                F.append(_f('lia:' + r['id'] + ':assessment', 'high', '"' + str(r.get('name')) + '" on legitimate interest without a written assessment', [], 'Complete and record the legitimate interest assessment before processing.', 'P-06', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        return ('fail' if F else 'pass'), (str(len(li)) + ' on legitimate interest' if li else 'no activity on legitimate interest'), F
    if a == 'dpia':
        if not ropa:
            return 'not_tested', 'no processing activity recorded yet', []
        done = {d.get('ropa_id') for d in _by(records, 'dpia') if d.get('completed')}
        need = 0
        for r in ropa:
            why = []
            sens = [c for c in (r.get('data_categories') or []) if c in SENSITIVE]
            if sens:
                why.append('sensitive data (' + ', '.join(sens) + ')')
            if (r.get('sources') or 1) >= 2:
                why.append('combines ' + str(r.get('sources')) + ' sources')
            if r.get('large_scale_monitoring'):
                why.append('continuous large-scale monitoring')
            if r.get('automated_decision'):
                why.append('solely automated decisions')
            why += insurer_triggers(r)
            if why:
                need += 1
                if r['id'] not in done:
                    F.append(_f('dpia:' + r['id'], 'high', 'No impact assessment for "' + str(r.get('name')) + '"', ['needed because: ' + '; '.join(why)], 'Complete the impact assessment and record its outcome before (or alongside) the processing.', 'P-07', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        return ('fail' if F else 'pass'), str(need) + ' activit(ies) need an assessment' + (', ' + str(len(F)) + ' missing' if F else ', all done'), F
    if a == 'dsr':
        D = _by(records, 'dsr')
        if not D:
            return 'not_tested', 'no data subject request recorded (a request log is still expected)', []
        for r in D:
            rc = ms(r.get('received'))
            if not rc:
                continue
            limit = 60 if r.get('extended') and r.get('extension_notified') else 30
            ans = ms(r.get('responded'))
            if r.get('extended') and not r.get('extension_notified') and (ans is None or ans - rc > 30 * DAY):
                F.append(_f('dsr:' + r['id'] + ':extension', 'medium', 'Request ' + str(r.get('ref')) + ' extended without notice to the data subject', [], 'Tell the data subject of the extension and its reasons before the first 30 days end.', 'P-08', {'type': 'pdpl', 'id': r['id'], 'name': r.get('ref')}))
            end = ans if ans is not None else now
            if end - rc > limit * DAY:
                F.append(_f('dsr:' + r['id'] + ':late', 'high', 'Request ' + str(r.get('ref')) + ' (' + str(r.get('type')) + ') ' + ('answered' if ans is not None else 'open') + ' after ' + str(int((end - rc) // DAY)) + ' days',
                            ['received ' + str(r.get('received')) + (', answered ' + str(r.get('responded')) if ans is not None else ', not answered'), 'limit ' + str(limit) + ' days'],
                            'Answer the request; review the request process so answers go out within 30 days.', 'P-08', {'type': 'pdpl', 'id': r['id'], 'name': r.get('ref')}))
        return ('fail' if F else 'pass'), str(len(D)) + ' request(s)' + (', ' + str(len(F)) + ' late' if F else ', all within time'), F
    if a == 'breach':
        B = _by(records, 'breach')
        if not B:
            return 'pass', 'no personal data breach recorded', []
        for r in B:
            aw = ms(r.get('aware_at'))
            if not aw:
                continue
            nt = ms(r.get('sdaia_notified_at'))
            if r.get('harm_likely', True):
                end = nt if nt is not None else now
                if end - aw > 72 * 3600000:
                    F.append(_f('breach:' + r['id'] + ':sdaia', 'critical', 'Breach ' + str(r.get('ref')) + ': SDAIA ' + ('notified after ' + str(int((end - aw) // 3600000)) + ' h' if nt is not None else 'not notified (' + str(int((now - aw) // 3600000)) + ' h since awareness)'),
                                ['aware ' + str(r.get('aware_at'))], 'Notify SDAIA at once with what is known and the reason for the delay; review the breach procedure.', 'P-09', {'type': 'pdpl', 'id': r['id'], 'name': r.get('ref')}))
                if not r.get('subjects_notified_at') and now - aw > 7 * DAY:
                    F.append(_f('breach:' + r['id'] + ':subjects', 'high', 'Breach ' + str(r.get('ref')) + ': data subjects not notified', ['harm likely; ' + str(r.get('subjects_count') or '?') + ' data subject(s)'], 'Notify the data subjects in clear language with what to do to protect themselves.', 'P-09', {'type': 'pdpl', 'id': r['id'], 'name': r.get('ref')}))
        return ('fail' if F else 'pass'), str(len(B)) + ' breach(es) recorded' + (', ' + str(len(F)) + ' late notification(s)' if F else ', notified in time'), F
    if a == 'processor':
        PR = _by(records, 'processor')
        if not PR:
            return 'not_tested', 'no processor recorded', []
        need = ('purpose', 'duration', 'breach_notice', 'subprocessors')
        for r in PR:
            if not r.get('agreement'):
                F.append(_f('proc:' + r['id'] + ':agreement', 'high', 'Processor ' + str(r.get('name')) + ' has no written agreement', [], 'Sign a data processing agreement with the required terms.', 'P-10', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            else:
                miss = [c for c in need if c not in (r.get('clauses') or [])]
                if miss:
                    F.append(_f('proc:' + r['id'] + ':clauses', 'medium', 'Processor ' + str(r.get('name')) + ': agreement lacks ' + ', '.join(miss), [], 'Add the missing terms to the agreement.', 'P-10', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            at = ms(r.get('assessed'))
            if not at or now - at > VALID_DAYS * DAY:
                F.append(_f('proc:' + r['id'] + ':assessed', 'low', 'Processor ' + str(r.get('name')) + ' not assessed in the last 12 months', [], 'Assess the processor\'s compliance (or have an independent party do it).', 'P-10', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        return ('fail' if F else 'pass'), str(len(PR)) + ' processor(s)', F
    if a == 'transfer':
        T = _by(records, 'transfer')
        out_ksa = (tests.get('CY-14') or {}).get('outside_ksa')
        procs_out = [p for p in _by(records, 'processor') if p.get('outside_ksa')]
        ropa_out = [r for r in ropa if r.get('transfer_outside') or r.get('reinsurance_outside')]
        if not T and not procs_out and not ropa_out and not out_ksa:
            return ('pass', 'no transfer outside the Kingdom recorded or detected', []) if ropa else ('not_tested', 'no processing activity recorded yet', [])
        if not T and (procs_out or ropa_out or out_ksa):
            F.append(_f('transfer:unrecorded', 'high', 'Data leaves the Kingdom but no transfer is recorded', [('processors outside the Kingdom: ' + ', '.join(str(p.get('name')) for p in procs_out)) if procs_out else '', ('activities transferring: ' + ', '.join(str(r.get('name')) for r in ropa_out)) if ropa_out else '', 'Domains & Hosting: sites hosted outside the Kingdom' if out_ksa else ''],
                        'Record each transfer with its basis and risk assessment, or bring the data back.', 'P-11'))
        for r in ropa:
            if r.get('reinsurance_outside') and not any(t.get('ropa_id') == r.get('id') and t.get('flow_type') in ('reinsurance', 'retrocession') for t in T):
                F.append(_f('transfer:' + r['id'] + ':reinsurance', 'high', '"' + str(r.get('name')) + '" is reinsured outside the Kingdom but no reinsurance transfer is recorded for it', ['reinsurers: ' + (', '.join(r.get('reinsurers') or []) or 'not named')],
                            'Record the transfer to each reinsurer (country, basis, what is sent: aggregated, pseudonymised or identified) and its risk assessment.', 'P-11', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        for r in T:
            b = r.get('basis')
            if r.get('flow_type') in ('reinsurance', 'retrocession') and r.get('data_form') == 'identified' and r.get('sensitive') and not r.get('identified_why'):
                F.append(_f('transfer:' + r['id'] + ':minimise', 'medium', 'Transfer ' + str(r.get('name')) + ' sends identified sensitive data to a reinsurer', ['data form: identified'],
                            'Send pseudonymised or aggregated bordereaux where the treaty allows; otherwise record why identified data is needed (e.g. a large-claim file the reinsurer must assess).', 'P-11', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            if not b:
                F.append(_f('transfer:' + r['id'] + ':basis', 'high', 'Transfer ' + str(r.get('name')) + ' to ' + str(r.get('country')) + ' has no basis', [], 'Record the basis: adequacy decision, appropriate safeguards (BCR / SCC / certification / code of conduct) or an exemption.', 'P-11', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
            needs_ra = b != 'adequacy' or (r.get('sensitive') and r.get('large_scale'))
            if b and needs_ra and not r.get('risk_assessed'):
                F.append(_f('transfer:' + r['id'] + ':risk', 'high', 'Transfer ' + str(r.get('name')) + ' needs a risk assessment', ['basis: ' + str(b) + ('; continuous / large-scale sensitive data' if r.get('sensitive') and r.get('large_scale') else '')], 'Complete the transfer risk assessment before transferring.', 'P-11', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        return ('fail' if F else 'pass'), str(len(T)) + ' transfer(s) recorded', F
    if a == 'withdrawal':
        purposes = _by(records, 'consent_purpose')
        cb = [r for r in ropa if r.get('legal_basis') in ('consent', 'explicit_consent')]
        if not purposes and not cb:
            return 'not_tested', 'no consent-based processing and no consent purpose recorded', []
        for r in cb:
            if not any(p.get('ropa_id') == r.get('id') for p in purposes):
                F.append(_f('withdrawal:' + r['id'], 'high', '"' + str(r.get('name')) + '" relies on consent but its withdrawals are not tracked in the consent ledger', [],
                            'Add a consent purpose for this activity and have the collecting system send grants and withdrawals to the ledger (and check it before processing).', 'P-20', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        wd = sum(p.get('withdrawals') or 0 for p in purposes)
        return ('fail' if F else 'pass'), ('%d purpose(s) in the ledger, %d withdrawal(s) recorded; a withdrawal is accepted on every channel' % (len(purposes), wd)) if not F else 'withdrawal not tracked', F
    if a == 'retention':
        if not ropa:
            return 'not_tested', 'no processing activity recorded yet', []
        rules = _by(records, 'retention')
        runs = [x for x in _by(records, 'destruction')]
        for r in ropa:
            if not r.get('retention_months'):
                continue
            sys_ = {_rn(x) for x in (r.get('systems') or [])}
            if not any(q.get('ropa_id') == r.get('id') or (sys_ & {_rn(x) for x in (q.get('systems') or [])}) for q in rules):
                F.append(_f('retention:' + r['id'] + ':schedule', 'medium', '"' + str(r.get('name')) + '" has a retention period but no retention rule in the schedule', [],
                            'Add a retention rule (systems, trigger, period, legal reference, destroy or anonymise) so destruction can be planned and evidenced.', 'P-12', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        for q in rules:
            due = _rule_due(q, runs, now)
            if due['overdue']:
                F.append(_f('retention:' + q['id'] + ':overdue', 'medium', 'Retention rule "' + str(q.get('name')) + '": no destruction evidenced since ' + str(due['since']), ['review every ' + str(q.get('review_months') or 12) + ' months'],
                            'Plan the destruction run for records past their retention, have it approved by the DPO, run it in the system and record the evidence.', 'P-12', {'type': 'pdpl', 'id': q['id'], 'name': q.get('name')}))
        for x in runs:
            if x.get('status') == 'executed' and not x.get('approved_by'):
                F.append(_f('retention:' + x['id'] + ':unapproved', 'high', 'Destruction ' + x['id'] + ' executed without an approval', [], 'Every destruction is approved by the DPO before it runs.', 'P-12'))
            if x.get('status') == 'approved' and ms(x.get('approved_at')) and now - ms(x.get('approved_at')) > 30 * DAY:
                F.append(_f('retention:' + x['id'] + ':stalled', 'low', 'Destruction ' + x['id'] + ' approved more than 30 days ago and not recorded as done', [], 'Run it and record the evidence, or reject it with a reason.', 'P-12'))
        F.extend(hold_findings(records, now))
        nr = [r for r in ropa if not r.get('retention_months')]
        for r in nr:
            F.append(_f('retention:' + r['id'], 'medium', '"' + str(r.get('name')) + '" has no retention period', [], 'Set the retention period and the destruction / anonymisation step at its end.', 'P-12', {'type': 'pdpl', 'id': r['id'], 'name': r.get('name')}))
        return ('fail' if F else 'pass'), str(len(ropa) - len(nr)) + ' of ' + str(len(ropa)) + ' activities have a retention period, ' + str(len(rules)) + ' retention rule(s)' + (', ' + str(len(F)) + ' gap(s) in the schedule or its destruction evidence' if F else ', destruction evidenced on time'), F
    if a == 'security':
        got = {k: tests.get(k) for k in SECURITY_TESTS if tests.get(k)}
        tested = {k: v for k, v in got.items() if v.get('state') in ('pass', 'fail')}
        if not tested:
            return 'not_tested', 'the AI auditors have no result for ' + ', '.join(SECURITY_TESTS), []
        bad = [k for k, v in tested.items() if v.get('state') == 'fail']
        for k in bad:
            F.append(_f('security:' + k, 'high', 'Security measure failing: ' + str(tested[k].get('title') or k), [str(tested[k].get('detail') or '')], 'Fix the finding on the AI auditors\' page; the PDPL requirement follows when the test passes.', 'P-13'))
        return ('fail' if F else 'pass'), str(len(tested)) + ' of ' + str(len(SECURITY_TESTS)) + ' security tests ran' + (', failing: ' + ', '.join(bad) if bad else ', all passed'), F
    return None, None, []


def assess(req):
    records = req.get('records') or []
    confirms = req.get('confirms') or {}
    tests = req.get('tests') or {}
    now = int(req.get('now') or 0)
    out, F = [], []
    for rq in REQS:
        state, detail, fs = _check(rq, records, tests, now) if rq['auto'] else (None, None, [])
        F.extend(fs)
        m = confirms.get(rq['id'])
        due = (ms(m.get('at')) + VALID_DAYS * DAY) if m and ms(m.get('at')) else None
        expired = bool(m and due is not None and due < now)
        if state == 'fail':
            result, why = 'non_compliant', 'the registers show a gap: ' + str(detail)
        elif m and not expired:
            result, why = m.get('status'), 'confirmed by ' + str(m.get('by'))
        elif state == 'pass':
            result, why = 'auto_pass', 'automated check passed - DPO to confirm'
        else:
            result, why = 'not_assessed', ('the last confirmation is over 12 months old' if expired else 'not assessed yet')
        out.append({'id': rq['id'], 'area': rq['area'], 'title': rq['title'], 'ref': rq['ref'], 'procedure': rq['procedure'], 'evidence_expected': rq['evidence'],
                    'automated': bool(rq['auto']), 'auto': None if not rq['auto'] else {'state': state, 'detail': detail, 'findings': len(fs)},
                    'confirmation': (dict(m, due=iso(due), expired=expired) if m else None), 'result': result, 'why': why,
                    'conflict': bool(state == 'fail' and m and not expired and m.get('status') in ('compliant', 'not_applicable'))})
    counts = {k: 0 for k in ('compliant', 'partial', 'non_compliant', 'not_applicable', 'auto_pass', 'not_assessed')}
    for r in out:
        counts[r['result']] = counts.get(r['result'], 0) + 1
    scored = len(out) - counts['not_applicable']
    pct = round((counts['compliant'] + counts['partial'] / 2) / scored * 1000) / 10 if scored else None
    F.sort(key=lambda f: -SEVN.get(f['severity'], 0))
    blockers = []
    for r in out:
        if r['result'] not in ('compliant', 'not_applicable'):
            blockers.append(r['id'] + ' ' + r['title'] + ': ' + r['why'])
    serious = [f for f in F if f['severity'] in ('critical', 'high')]
    for f in serious[:20]:
        blockers.append('open ' + f['severity'] + ' finding: ' + f['title'])
    P = (_by(records, 'profile') or [{}])[0]
    snap = {'requirements': [[r['id'], r['result']] for r in out], 'findings': [f['key'] for f in serious], 'dpo': P.get('dpo_user')}
    digest = 'sha256:' + hashlib.sha256(json.dumps(snap, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    return {'requirements': out, 'findings': F, 'counts': counts, 'compliance_pct': pct,
            'readiness': {'ready': not blockers, 'blockers': blockers[:60], 'digest': digest, 'dpo_user': P.get('dpo_user') or None},
            'connected': bool(records)}


def _is_service(u):
    s = str(u or '').strip().lower()
    return any(s.startswith(p + c) for p in ('duty', 'system', 'ai', 'svc', 'service') for c in ':_-')


def sign(req):
    """The two signatures of the PDPL compliance statement. Refusals are decided here; Node.js commits {put, audit}."""
    a = assess(req)
    rd = a['readiness']
    who = req.get('signer') or {}
    user, as_ = str(who.get('user') or ''), req.get('as')
    now = int(req.get('now') or 0)
    cur = req.get('attestation') or None
    if _is_service(user):
        return {'refuse': {'status': 403, 'error': 'a service or AI identity cannot sign the PDPL statement'}}
    if as_ not in ('dpo', 'management'):
        return {'refuse': {'status': 400, 'error': 'as must be dpo or management'}}
    if req.get('digest') != rd['digest']:
        return {'refuse': {'status': 409, 'error': 'the assessment changed since you opened it - reload and review the statement again'}}
    if not rd['ready']:
        return {'refuse': {'status': 409, 'error': 'not ready to attest: ' + str(len(rd['blockers'])) + ' item(s) open - ' + '; '.join(rd['blockers'][:3])}}
    if as_ == 'dpo':
        if not rd['dpo_user'] or user.lower() != str(rd['dpo_user']).lower():
            return {'refuse': {'status': 403, 'error': 'only the appointed DPO (' + str(rd['dpo_user'] or 'none recorded') + ') signs as DPO'}}
        rec = {'id': 'statement', 'digest': rd['digest'], 'dpo': {'user': user, 'at': iso(now)}, 'management': None, 'status': 'awaiting_management', 'compliance_pct': a['compliance_pct']}
        return {'put': rec, 'audit': {'action': 'pdpl.statement.sign_dpo', 'target': rd['digest'], 'detail': {'compliance_pct': a['compliance_pct']}}}
    if not cur or cur.get('digest') != rd['digest'] or not cur.get('dpo') or cur.get('status') != 'awaiting_management':
        return {'refuse': {'status': 409, 'error': 'the DPO signs first, on this same assessment'}}
    if user.lower() == str(cur['dpo'].get('user') or '').lower():
        return {'refuse': {'status': 403, 'error': 'the countersignature must be a different person from the DPO (four-eyes)'}}
    rec = dict(cur, management={'user': user, 'at': iso(now)}, status='attested', valid_until=iso(now + VALID_DAYS * DAY))
    return {'put': rec, 'audit': {'action': 'pdpl.statement.countersign', 'target': rd['digest'], 'detail': {'dpo': cur['dpo'].get('user')}}}


def statement_state(req):
    """Is the signed statement still valid? It lapses when it expires or the assessment it signed no longer holds."""
    cur = req.get('attestation')
    if not cur:
        return {'status': 'none'}
    a = assess(req)
    now = int(req.get('now') or 0)
    st = cur.get('status')
    if st == 'attested':
        if ms(cur.get('valid_until')) and ms(cur.get('valid_until')) < now:
            st = 'expired'
        elif not a['readiness']['ready']:
            st = 'lapsed'
    return dict(cur, status=st, current_digest=a['readiness']['digest'])


# ---------------------------------------------------------------- automation: discovery, breach drafts, DPIA wizard
SENSITIVE_CATS = SENSITIVE


def _norm(v):
    return str(v or '').strip().lower()


def discovery(req):
    """pdpl.discovery {scans: [{db, label, host, service, at, ok, error, columns[]}], records, now}
    Personal data the databases hold (from the read-only dictionary scan) against the records of processing: a database
    with personal data that no activity names, categories an activity does not declare, sensitive data without a DPIA."""
    recs = [r for r in req.get('records') or [] if r.get('status') != 'archived']
    ropa = [r for r in recs if r.get('kind') == 'ropa']
    dpias = {r.get('ropa_id') for r in recs if r.get('kind') == 'dpia' and r.get('completed')}
    out, F = [], []
    for s in req.get('scans') or []:
        names = {_norm(x) for x in (s.get('label'), s.get('host'), s.get('service'), s.get('db')) if x}
        acts = [r for r in ropa if any(_norm(x) in names or any(n and n in _norm(x) for n in names) for x in (r.get('systems') or []))]
        cols = s.get('columns') or []
        cats = {}
        for c in cols:
            if c.get('confirmed') is False:
                continue          # the values sampled did not look like that kind of data
            e = cats.setdefault(c.get('category'), {'columns': 0, 'confirmed': 0, 'tables': set(), 'rows': 0, 'kinds': set()})
            e['columns'] += 1
            e['confirmed'] += 1 if c.get('confirmed') else 0
            e['tables'].add(str(c.get('owner')) + '.' + str(c.get('table')))
            e['kinds'].add(c.get('kind'))
            e['rows'] = max(e['rows'], c.get('rows') or 0)
        declared = set()
        for a in acts:
            declared.update(a.get('data_categories') or [])
        summary = [{'category': k, 'columns': v['columns'], 'confirmed': v['confirmed'], 'tables': len(v['tables']), 'max_rows': v['rows'], 'kinds': sorted(x for x in v['kinds'] if x),
                    'declared': k in declared, 'sensitive': k in SENSITIVE_CATS, 'credit': k == 'credit'} for k, v in sorted(cats.items())]
        label = s.get('label') or s.get('host') or s.get('db')
        row = {'db': s.get('db'), 'label': label, 'at': s.get('at'), 'ok': bool(s.get('ok')), 'error': s.get('error') or '', 'activities': [a.get('id') for a in acts],
               'categories': summary, 'columns': len(cols), 'scanned_columns': s.get('scanned_columns'), 'probed': s.get('probed') or 0, 'probe_denied': s.get('probe_denied') or 0, 'truncated': bool(s.get('truncated'))}
        out.append(row)
        if not s.get('ok') or not summary:
            continue
        tgt = {'type': 'database', 'id': str(s.get('db')), 'name': label}
        if not acts:
            F.append(_f('disc:' + str(s.get('db')) + ':unmapped', 'high', label + ' holds personal data (' + ', '.join(x['category'] for x in summary) + ') but no processing activity names it',
                        ['%d column(s) in %d table(s); largest table about %d rows' % (len(cols), len({c.get('owner') + '.' + c.get('table') for c in cols}), max(x['max_rows'] for x in summary))],
                        'Record the processing activity for this system (purpose, legal basis, retention, recipients) - "Adopt as processing activity" pre-fills it from the scan.', 'P-04', tgt))
        else:
            miss = [x['category'] for x in summary if not x['declared']]
            if miss:
                F.append(_f('disc:' + str(s.get('db')) + ':undeclared', 'medium', label + ': ' + ', '.join(miss) + ' data found that its processing activities do not declare',
                            ['activities: ' + ', '.join(a.get('id') for a in acts)], 'Add the categories to the activity (and check the purpose needs them - data minimisation, PDPL Art. 11).', 'P-16', tgt))
        sens = [x['category'] for x in summary if x['sensitive']]
        if sens and not any(a.get('id') in dpias for a in acts):
            F.append(_f('disc:' + str(s.get('db')) + ':dpia', 'high', label + ': sensitive data (' + ', '.join(sens) + ') with no completed impact assessment',
                        ['sensitive data needs explicit consent or another basis, and an impact assessment before processing'], 'Run the DPIA wizard for the activity that uses this system.', 'P-07', tgt))
    return {'databases': out, 'findings': F}


def breach_draft(req):
    """pdpl.breach_draft {breach, profile, now} -> the SDAIA notification draft (Implementing Regulation Art. 24 contents),
    the data subject notice (Arabic and English), the 72-hour clock and what is still missing. A draft for the DPO: the
    platform does not send it - SDAIA is notified through its own portal."""
    b, p, now = req.get('breach') or {}, req.get('profile') or {}, req.get('now') or 0
    aw = ms(b.get('aware_at'))
    deadline = aw + 72 * 3600000 if aw else None
    sent = ms(b.get('sdaia_notified_at'))
    left = None if not deadline or sent else round((deadline - now) / 3600000.0, 1)
    cats = b.get('categories') or []
    missing = [lbl for k, lbl in (('description', 'description of the breach'), ('categories', 'categories of personal data'), ('subjects_count', 'approximate number of data subjects'),
                                  ('risks', 'risks and impact'), ('measures', 'measures taken and planned')) if b.get(k) in (None, '', [])]
    if not p.get('dpo_user'):
        missing.append('DPO contact (Personal data profile)')
    sdaia = [
        ['Controller', _org_fill('{{org.name}}')],
        ['SDAIA registration', p.get('sdaia_ref') or 'not recorded'],
        ['DPO / contact', p.get('dpo_user') or 'not recorded'],
        ['When it happened / when we became aware', (b.get('occurred_at') or 'unknown') + ' / ' + (b.get('aware_at') or '?')],
        ['How it happened (circumstances)', b.get('description') or ''],
        ['Categories of personal data', ', '.join(cats)],
        ['Approximate number of data subjects', '' if b.get('subjects_count') is None else str(b.get('subjects_count'))],
        ['Sensitive data involved', 'yes' if any(c in SENSITIVE_CATS for c in cats) else 'no'],
        ['Credit data involved', 'yes' if 'credit' in cats else 'no'],
        ['Risks and actual / potential impact', b.get('risks') or ''],
        ['Measures taken to contain and limit the impact', b.get('measures') or ''],
        ['Measures planned to prevent recurrence', b.get('prevention') or ''],
        ['Data subjects notified', ('yes, ' + str(b.get('subjects_notified_at'))) if b.get('subjects_notified_at') else ('to be notified' if b.get('harm_likely') else 'not required unless harm is likely')],
        ['Reason for any delay beyond 72 hours', b.get('delay_reason') or ('' if not deadline or (sent or now) <= deadline else 'REQUIRED - the 72 hours have passed')],
    ]
    en = (_org_fill('Dear customer,\n\nOn %s {{org.name}} became aware of an incident affecting personal data. %s\n\n'
          'The information involved: %s.\nWhat we have done: %s\nWhat you can do: be careful with unexpected calls, messages or e-mails asking for your details or for payment, and contact us if you notice anything unusual.\n\n'
          'For questions contact our Data Protection Officer: %s.')) % ((b.get('aware_at') or '')[:10], b.get('description') or '', ', '.join(cats) or '-', b.get('measures') or '-', p.get('dpo_contact') or p.get('dpo_user') or '-')
    ar = (_org_fill('عزيزنا العميل،\n\nبتاريخ %s علمت {{org.name_ar}} بحادثة تتعلق ببيانات شخصية. %s\n\n'
          'البيانات المعنية: %s.\nما قمنا به: %s\nما يمكنك فعله: الحذر من المكالمات أو الرسائل غير المتوقعة التي تطلب بياناتك أو مبالغ مالية، والتواصل معنا عند ملاحظة أي أمر غير معتاد.\n\n'
          'للاستفسار يرجى التواصل مع مسؤول حماية البيانات الشخصية: %s.')) % ((b.get('aware_at') or '')[:10], b.get('description') or '', '، '.join(cats) or '-', b.get('measures') or '-', p.get('dpo_contact') or p.get('dpo_user') or '-')
    return {'breach': b.get('id'), 'ref': b.get('ref'), 'deadline': iso(deadline) if deadline else None, 'hours_left': left, 'notified': bool(sent),
            'late': bool(deadline and ((sent or now) > deadline)), 'missing': missing, 'sdaia': sdaia, 'subject_notice': {'en': en, 'ar': ar},
            'subjects_required': bool(b.get('harm_likely')),
            'note': 'A draft for the DPO. Notify SDAIA through its portal within 72 hours of awareness - with what is known, and the rest later; the platform does not send it. Implementing Regulation Art. 24.'}


# the DPIA questionnaire (PDPL Art. 22; Implementing Regulation Art. 25): each answer adds likelihood (L) / severity (S)
# points; each measure in place removes points from the residual risk. Plain additive scoring so every point is explainable.
DPIA_Q = [
    {'id': 'sensitive', 'q': 'Does the processing involve sensitive data (health, biometric, genetic, criminal or security records, religious, intellectual or political beliefs, racial or ethnic origin, unknown parentage) or credit data?', 'opts': [['no', 0, 0], ['credit', 1, 2], ['yes', 1, 3]]},
    {'id': 'scale', 'q': 'How many data subjects?', 'opts': [['under 1,000', 0, 0], ['1,000 - 100,000', 1, 1], ['over 100,000', 2, 2]]},
    {'id': 'sources', 'q': 'Is data from two or more sources combined, compared or linked?', 'opts': [['no', 0, 0], ['yes', 1, 1]]},
    {'id': 'automated', 'q': 'Are decisions made solely by automated means (pricing, claim approval, fraud scoring)?', 'opts': [['no', 0, 0], ['with human review', 1, 1], ['solely automated', 2, 2]]},
    {'id': 'monitoring', 'q': 'Is there continuous monitoring of individuals (location, behaviour, telematics, CCTV)?', 'opts': [['no', 0, 0], ['yes', 2, 1]]},
    {'id': 'vulnerable', 'q': 'Are minors or people lacking legal capacity involved?', 'opts': [['no', 0, 0], ['yes', 1, 2]]},
    {'id': 'new_tech', 'q': 'Does it use new technology (AI models, biometrics, new vendor platform)?', 'opts': [['no', 0, 0], ['yes', 1, 1]]},
    {'id': 'transfer', 'q': 'Is personal data transferred or accessible outside the Kingdom?', 'opts': [['no', 0, 0], ['with safeguards', 1, 1], ['no safeguard yet', 2, 2]]},
    {'id': 'processors', 'q': 'Do processors (vendors, TPAs, cloud) handle the data?', 'opts': [['no', 0, 0], ['yes, with agreements', 0, 1], ['yes, no agreement yet', 2, 1]]},
    {'id': 'necessity', 'q': 'Is every data field needed for the purpose (data minimisation)?', 'opts': [['yes, mapped field by field', 0, 0], ['mostly', 1, 0], ['not assessed', 2, 1]]},
]
DPIA_M = [
    ['encryption', 'Encryption at rest and in transit', 2], ['access', 'Role-based access, least privilege, reviewed', 2], ['logging', 'Access logged and monitored by the SOC', 1],
    ['minimisation', 'Fields reduced to the minimum; pseudonymised where possible', 2], ['retention', 'Retention period defined and enforced', 1], ['rights', 'Data subject rights process in place', 1],
    ['consent', 'Consent / legal basis documented, explicit where needed', 1], ['human_review', 'Human review of automated decisions, with appeal', 2], ['contracts', 'Processor agreements with PDPL terms', 1],
    ['training', 'Staff trained on PDPL for this processing', 1],
]


def dpia_questions(req):
    return {'questions': [{'id': q['id'], 'question': q['q'], 'options': [o[0] for o in q['opts']]} for q in DPIA_Q],
            'measures': [{'id': m[0], 'measure': m[1], 'reduces': m[2]} for m in DPIA_M]}


def dpia_score(req):
    """pdpl.dpia_score {answers: {qid: option}, measures: [mid]} -> likelihood, severity, inherent, residual, level,
    suggested outcome, every point named. Refuses an unanswered or unknown answer (the DPO must answer each question)."""
    a, ms_ = req.get('answers') or {}, set(req.get('measures') or [])
    L = S = 0
    why, problems = [], []
    for q in DPIA_Q:
        opt = next((o for o in q['opts'] if o[0] == a.get(q['id'])), None)
        if opt is None:
            problems.append(q['id'])
            continue
        L += opt[1]
        S += opt[2]
        if opt[1] or opt[2]:
            why.append('%s: %s (+%d likelihood, +%d severity)' % (q['id'], opt[0], opt[1], opt[2]))
    unknown = [m for m in ms_ if m not in {x[0] for x in DPIA_M}]
    if problems or unknown:
        return {'refuse': {'status': 400, 'error': ('answer every question: ' + ', '.join(problems)) if problems else ('unknown measure: ' + ', '.join(unknown))}}
    inherent = L + S
    reduce_ = sum(m[2] for m in DPIA_M if m[0] in ms_)
    residual = max(0, inherent - reduce_)
    level = 'high' if residual >= 9 else 'medium' if residual >= 5 else 'low'
    outcome = {'low': 'acceptable', 'medium': 'mitigations', 'high': 'not_acceptable'}[level]
    need = []
    if a.get('sensitive') != 'no' and 'consent' not in ms_:
        need.append('explicit consent or another documented basis for sensitive / credit data')
    if a.get('automated') == 'solely automated' and 'human_review' not in ms_:
        need.append('human review of solely automated decisions')
    if a.get('transfer') == 'no safeguard yet':
        need.append('a transfer basis (adequacy, SCC, BCR) and a transfer risk assessment before any transfer')
    if a.get('processors') == 'yes, no agreement yet':
        need.append('a processor agreement with the PDPL terms')
    if need and outcome == 'acceptable':
        outcome, level = 'mitigations', 'medium'
    return {'likelihood': L, 'severity': S, 'inherent': inherent, 'reduced_by': reduce_, 'residual': residual, 'level': level, 'outcome': outcome,
            'why': why, 'measures': sorted(ms_), 'required': need,
            'note': 'High residual risk: do not start the processing; reduce the risk, or consult before proceeding. Implementing Regulation Art. 25.' if level == 'high' else ''}



# ---------------------------------------------------------------- consent ledger and retention schedule
def _rn(v):
    return str(v or '').strip().lower()


def _rule_due(q, runs, now):
    """next destruction for a retention rule: every review_months after the last executed run (or after the rule was made)"""
    done = sorted([ms(x.get('executed_at')) for x in runs if x.get('retention_id') == q.get('id') and x.get('status') == 'executed' and ms(x.get('executed_at'))])
    base = done[-1] if done else ms(q.get('created_at')) or now
    nxt = base + int(q.get('review_months') or 12) * 30 * DAY
    return {'last_executed': iso(done[-1]) if done else None, 'next_due': iso(nxt), 'overdue': nxt < now, 'since': iso(done[-1])[:10] if done else 'the rule was created (' + str(q.get('created_at') or '')[:10] + ')'}


def consent_view(req):
    """pdpl.consent_view {records (purposes carry their counts), keys, chain: {ok, length, broken_at}, now}"""
    recs, now = req.get('records') or [], req.get('now') or 0
    purposes = [p for p in recs if p.get('kind') == 'consent_purpose' and p.get('status') != 'archived']
    ropa = {r['id']: r for r in recs if r.get('kind') == 'ropa'}
    chain, keys = req.get('chain') or {}, [k for k in req.get('keys') or [] if not k.get('revoked')]
    F, rows = [], []
    if chain and chain.get('ok') is False:
        F.append(_f('consent:chain', 'critical', 'The consent ledger fails its integrity check at entry ' + str(chain.get('broken_at')), ['entries: ' + str(chain.get('length'))],
                    'Treat as an incident: the append-only consent records were altered. Restore from backup and investigate who changed the store.', 'P-05'))
    for p in purposes:
        r = ropa.get(p.get('ropa_id'))
        stale = p.get('stale_version') or 0
        rows.append({'id': p['id'], 'title': p.get('title'), 'version': p.get('version'), 'explicit': bool(p.get('explicit')), 'marketing': bool(p.get('marketing')), 'ropa_id': p.get('ropa_id'),
                     'activity': r.get('name') if r else None, 'active': p.get('active') or 0, 'withdrawn': p.get('withdrawn') or 0, 'stale_version': stale,
                     'events_30d': p.get('events_30d') or 0, 'last_event': p.get('last_event'), 'channels': p.get('channels') or {}})
        tgt = {'type': 'pdpl', 'id': p['id'], 'name': p.get('title')}
        if not p.get('ropa_id') or not r:
            F.append(_f('consent:' + p['id'] + ':ropa', 'medium', 'Consent purpose "' + str(p.get('title')) + '" is not linked to a processing activity', [], 'Link it to the processing activity it covers (records of processing).', 'P-05', tgt))
        if not p.get('events'):
            F.append(_f('consent:' + p['id'] + ':silent', 'medium', 'No consent has been recorded for "' + str(p.get('title')) + '" - the collecting system is not sending to the ledger yet', [],
                        'Connect the portal / app with a consent key (Consent ledger → Keys) so every grant and withdrawal is recorded.', 'P-05', tgt))
        if stale:
            F.append(_f('consent:' + p['id'] + ':stale', 'medium', str(stale) + ' consent(s) for "' + str(p.get('title')) + '" were given under an older notice than version ' + str(p.get('version')), [],
                        'A material change to the purpose or notice needs fresh consent: ask these data subjects again, and stop the processing the old consent does not cover.', 'P-05', tgt))
    if purposes and not keys:
        F.append(_f('consent:nokey', 'low', 'No active consent key: no system can send consents to the ledger', [], 'Issue a key for each collecting system (portal, app, call centre).', 'P-05'))
    return {'purposes': rows, 'findings': F, 'active_keys': len(keys), 'chain': chain}


# ---------------------------------------------------------------- legal holds
HOLD_REASONS = {'claim': 'open or disputed claim', 'litigation': 'court case or arbitration', 'complaint': 'complaint (customer, SDAIA, Insurance Authority)',
                'regulator': 'regulator inquiry or inspection', 'fraud_investigation': 'fraud investigation', 'audit': 'audit', 'other': 'other'}


def _holds(recs):
    return [h for h in recs if h.get('kind') == 'legal_hold']


def hold_covers(h, system, cats):
    """an ACTIVE hold covers a system when it names it (or all systems) and, when both sides list data categories, they overlap"""
    if h.get('status') != 'active':
        return False
    if not (h.get('all_systems') or _rn(system) in {_rn(x) for x in h.get('systems') or []}):
        return False
    hc, rc = set(h.get('data_categories') or []), set(cats or [])
    return not hc or not rc or bool(hc & rc)


def _hold_review(h, now):
    base = ms(h.get('reviewed_at')) or ms(h.get('placed_at')) or now
    nxt = base + int(h.get('review_months') or 6) * 30 * DAY
    return {'next_review': iso(nxt), 'overdue': h.get('status') == 'active' and nxt < now}


def hold_check(req):
    """pdpl.hold_check {records, system, retention_id, excluded[]} -> the active holds that cover the records a destruction
    would touch, and those of them the run does not exclude (blocking). A blocking hold stops the plan, the approval and the
    recording of the run: records under a legal hold are kept until the hold is released (PDPL Art. 18)."""
    recs = req.get('records') or []
    q = next((x for x in recs if x.get('id') == req.get('retention_id')), None) or {}
    cats, ex = q.get('data_categories') or [], set(req.get('excluded') or [])
    cov = [h for h in _holds(recs) if hold_covers(h, req.get('system'), cats)]
    row = lambda h: {'id': h['id'], 'ref': h.get('ref'), 'reason': h.get('reason'), 'scope': h.get('scope') or ''}  # noqa: E731
    return {'covering': [row(h) for h in cov], 'blocking': [row(h) for h in cov if h['id'] not in ex]}


def holds_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    rules = [q for q in recs if q.get('kind') == 'retention' and q.get('status') != 'archived']
    runs = [x for x in recs if x.get('kind') == 'destruction' and x.get('status') in ('planned', 'approved')]
    out = []
    for h in sorted(_holds(recs), key=lambda x: (x.get('status') != 'active', str(x.get('placed_at') or ''))):
        rev = _hold_review(h, now)
        out.append(dict(h, reason_label=HOLD_REASONS.get(h.get('reason'), h.get('reason')), review=rev,
                        rules=[q['id'] for q in rules if h.get('status') == 'active' and any(hold_covers(h, s, q.get('data_categories')) for s in (q.get('systems') or []))],
                        runs=[{'id': x['id'], 'status': x.get('status'), 'system': x.get('system'), 'excluded': h['id'] in [e.get('id') for e in x.get('holds_excluded') or []]}
                              for x in runs if hold_covers(h, x.get('system'), next((q.get('data_categories') for q in rules if q['id'] == x.get('retention_id')), None))]))
    act = [x for x in out if x.get('status') == 'active']
    return {'holds': out, 'active': len(act), 'review_overdue': sum(1 for x in act if x['review']['overdue']), 'reasons': [[k, v] for k, v in HOLD_REASONS.items()],
            'note': 'A legal hold keeps records past their retention period while a claim, court case, complaint, regulator inquiry or investigation needs them. '
                    'While a hold is active no destruction that touches its systems can be planned, approved or recorded unless the run states how the held records are excluded. '
                    'A hold is released by the DPO or an administrator who did not place it.'}


def hold_findings(recs, now):
    F = []
    for h in _holds(recs):
        rev = _hold_review(h, now)
        if rev['overdue']:
            F.append(_f('retention:hold:' + h['id'] + ':review', 'medium', 'Legal hold ' + str(h.get('ref')) + ' has not been reviewed since ' + str((h.get('reviewed_at') or h.get('placed_at') or '')[:10]),
                        ['review every ' + str(h.get('review_months') or 6) + ' months', HOLD_REASONS.get(h.get('reason'), '')],
                        'Confirm the claim, case or inquiry still needs the records (record a review), or release the hold so the retention schedule applies again.', 'P-12', {'type': 'pdpl', 'id': h['id'], 'name': h.get('ref')}))
    return F


def retention_view(req):
    recs, now = req.get('records') or [], req.get('now') or 0
    rules = [q for q in recs if q.get('kind') == 'retention' and q.get('status') != 'archived']
    runs = [x for x in recs if x.get('kind') == 'destruction']
    holds = [h for h in _holds(recs) if h.get('status') == 'active']
    out = []
    for q in rules:
        due = _rule_due(q, runs, now)
        mine = sorted([x for x in runs if x.get('retention_id') == q['id']], key=lambda x: str(x.get('created_at') or ''), reverse=True)
        out.append(dict(q, due=due, holds=[{'id': h['id'], 'ref': h.get('ref'), 'systems': [s for s in (q.get('systems') or []) if hold_covers(h, s, q.get('data_categories'))]}
                                            for h in holds if any(hold_covers(h, s, q.get('data_categories')) for s in (q.get('systems') or []))],
                        runs=[{'id': x['id'], 'status': x.get('status'), 'system': x.get('system'), 'cutoff': x.get('cutoff'), 'count': x.get('count'), 'planned_by': x.get('created_by'), 'approved_by': x.get('approved_by'),
                               'executed_at': x.get('executed_at'), 'holds_excluded': x.get('holds_excluded') or [], 'exclusion': x.get('exclusion') or ''} for x in mine[:10]]))
    out.sort(key=lambda x: (not x['due']['overdue'], x['due']['next_due']))
    return {'rules': out, 'overdue': sum(1 for x in out if x['due']['overdue']), 'pending_approval': sum(1 for x in runs if x.get('status') == 'planned'), 'active_holds': len(holds),
            'note': 'The platform never deletes data. A destruction run is planned by the system owner, approved by the DPO (a different person), carried out in the system, and recorded here with its evidence. '
                    'Records under an active legal hold are kept until the hold is released.'}
