# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""PDPL self-assessment (engine/pdpl-assessment.js): a guided questionnaire over the 24 PDPL requirements of the AI PDPL
Consultant (pdpl_rules.REQS), each requirement asked as plain questions with the article of the Law (Royal Decree M/19,
amended by M/148), the Implementing Regulation or the Cross-Border Transfer Regulation it comes from.

Answers: yes / partial / no / na. "yes" and "partial" need the evidence relied on, "no" and "na" a note (what is missing /
why it does not apply). An unanswered question is a gap, never a pass. The registers' automated result for the requirement
(pdpl_rules.assess) is shown beside each question as a SUGGESTION: a person answers; where the answer contradicts a gap the
registers show, the conflict is flagged rather than overridden.

  {"op": "pdplassess.questions"}                                   -> {chapters[], questions[]}
  {"op": "pdplassess.view", "assessment", "auto": [requirements]}  -> {questions[] with answer + suggestion, chapters[] with
      score, requirements[] roll-up, score, progress, gaps[], conflicts[], ready_to_submit, missing[]}
The roll-up per requirement (all yes -> compliant, any no / unanswered -> non_compliant, otherwise partial, all na ->
not_applicable) is what an approved assessment writes back as the requirement's confirmation.
"""
from pdpl_rules import REQS
from org_brand import fill as _org_fill

W = {'yes': 1.0, 'partial': 0.5, 'no': 0.0}
ANSWERS = ('yes', 'partial', 'no', 'na')


def Q(qid, req, text, ref, hint, weight=1):
    return {'id': qid, 'req': req, 'text': text, 'ref': ref, 'hint': hint, 'weight': weight}


QUESTIONS = [
    Q('P01-1', 'P-01', _org_fill('Has {{org.short}} appointed a Data Protection Officer by a written decision?'), 'Implementing Regulation Art. 32',
      'The appointment letter. An insurer whose core activity processes health data, or which monitors individuals regularly at large scale, must appoint one.', 2),
    Q('P01-2', 'P-01', 'Is the DPO the named contact point for SDAIA and for data subjects, with contact details published?', 'Implementing Regulation Art. 32',
      'The published DPO contact (privacy policy, website) and the DPO\'s responsibilities in the job description.'),
    Q('P02-1', 'P-02', _org_fill('Is {{org.short}} registered as a controller on SDAIA\'s National Data Governance Platform, where registration is required, and are the details current?'), 'SDAIA Personal Data Controllers Register',
      'The registration reference or certificate, and the date the details were last checked.'),
    Q('P03-1', 'P-03', 'Is a privacy policy published and available to data subjects before their personal data is collected?', 'PDPL Art. 12',
      'The URL / form where the policy is shown, and its approval.', 2),
    Q('P03-2', 'P-03', 'At collection, are data subjects told the legal basis, the purpose, who collects, who receives the data, transfers outside the Kingdom, the effect of not providing it and their rights?', 'PDPL Art. 13',
      'A sample collection form or call script with the notice.'),
    Q('P04-1', 'P-04', 'Is there a record of every processing activity (purpose, categories, recipients, transfers, retention, security measures, owner)?', 'Implementing Regulation Art. 33',
      'The records of processing (PDPL -> RoPA register).', 2),
    Q('P04-2', 'P-04', 'Has every record of processing been reviewed in the last 12 months?', 'Implementing Regulation Art. 33', 'Review dates in the register.'),
    Q('P05-1', 'P-05', 'Does every processing activity have a legal basis recorded (consent, contract, legal obligation, actual interest, legitimate interest)?', 'PDPL Arts. 5-6; Implementing Regulation Arts. 11-15',
      'The basis column of the records of processing.', 2),
    Q('P05-2', 'P-05', 'Where processing relies on consent, is the consent specific, freely given, documented and provable (when and how it was given)?', 'Implementing Regulation Art. 11',
      'Consent records / consent ledger.'),
    Q('P05-3', 'P-05', 'Is explicit consent obtained for sensitive data, credit data and solely automated decisions?', 'Implementing Regulation Art. 11', 'Consent wording and records for those activities.'),
    Q('P05-4', 'P-05', 'Is no service made conditional on consent to processing that the service does not need?', 'PDPL Art. 7', 'Sample product journeys / forms.'),
    Q('P06-1', 'P-06', 'For each activity on legitimate interest, was a written assessment made before processing, and is no sensitive data processed on that basis?', 'Implementing Regulation Art. 16',
      'Legitimate interest assessments; or "na" if no activity relies on it.'),
    Q('P07-1', 'P-07', 'Is an impact assessment completed before processing sensitive data, combining several sources, continuous monitoring, new technology or solely automated decisions?', 'PDPL Art. 22; Implementing Regulation Art. 25',
      'Completed impact assessments (PDPL -> DPIA) for each such activity.', 2),
    Q('P07-2', 'P-07', 'Where an assessment showed harm to privacy, was the cause addressed and the assessment repeated?', 'Implementing Regulation Art. 25', 'The re-assessment record, or "na".'),
    Q('P08-1', 'P-08', 'Can data subjects request access, a copy, correction and destruction through an easy channel, and are oral requests documented too?', 'PDPL Art. 4; Implementing Regulation Arts. 3-6',
      'The request channel(s) and the request log.', 2),
    Q('P08-2', 'P-08', 'Are requests answered within 30 days, extended at most once by 30 days with the reasons notified in advance?', 'Implementing Regulation Art. 4', 'Request log: received, answered, extensions.'),
    Q('P08-3', 'P-08', 'Is the requester\'s identity verified before data is released?', 'Implementing Regulation Art. 4', 'The verification step in the procedure.'),
    Q('P09-1', 'P-09', 'Is there a procedure to notify SDAIA within 72 hours of becoming aware of a breach that may harm data subjects?', 'PDPL Art. 20; Implementing Regulation Art. 24',
      'The breach procedure with the 72-hour clock and the SDAIA notification contents.', 2),
    Q('P09-2', 'P-09', 'Are data subjects notified without undue delay, in clear language, when a breach may harm them?', 'Implementing Regulation Art. 24', 'The data subject notice template.'),
    Q('P09-3', 'P-09', 'Is every breach recorded (time of awareness, data affected, people affected, actions, notifications)?', 'Implementing Regulation Art. 24', 'The breach register.'),
    Q('P10-1', 'P-10', 'Does every processor work under a written agreement covering purpose, data, duration, breach notice, sub-processors and foreign law?', 'PDPL Art. 8; Implementing Regulation Art. 17',
      'Processor agreements (PDPL -> Processors).', 2),
    Q('P10-2', 'P-10', 'Is each processor\'s compliance assessed periodically, and must a processor get prior approval before using a sub-processor?', 'Implementing Regulation Art. 17', 'Assessment records; sub-processor clause.'),
    Q('P11-1', 'P-11', 'Is every transfer or disclosure outside the Kingdom recorded with its purpose and basis (adequacy, appropriate safeguards, or an exemption)?', 'PDPL Art. 29; Cross-Border Transfer Regulation Arts. 2-6',
      'The transfer register; or "na" if no personal data leaves the Kingdom (including cloud and support access).', 2),
    Q('P11-2', 'P-11', 'Was a transfer risk assessment made where the transfer relies on safeguards or an exemption, or is a continuous / large-scale transfer of sensitive data?', 'Cross-Border Transfer Regulation Art. 8',
      'Transfer risk assessments.'),
    Q('P12-1', 'P-12', 'Does every processing activity have a retention period, after which data is destroyed or anonymised?', 'PDPL Art. 18; Implementing Regulation Art. 19',
      'The retention schedule.', 2),
    Q('P12-2', 'P-12', 'Is destruction at the end of the period carried out and recorded with evidence?', 'Implementing Regulation Art. 19', 'Destruction records.'),
    Q('P13-1', 'P-13', 'Are organisational, administrative and technical security measures in place for personal data, following the NCA controls?', 'PDPL Art. 19; Implementing Regulation Art. 23',
      'NCA ECC compliance, access control, encryption, logging (AI auditors\' results).', 2),
    Q('P13-2', 'P-13', 'Is access to personal data limited to staff who need it, and reviewed?', 'Implementing Regulation Art. 23', 'Access reviews.'),
    Q('P14-1', 'P-14', 'Is health data processed under the health-sector controls (Council of Health Insurance), with tiered access and each processing stage documented?', 'PDPL Art. 23; Implementing Regulation Art. 26',
      'Access matrix for health data; procedures.', 2),
    Q('P15-1', 'P-15', 'Is credit data processed with the data subject\'s consent, and is the data subject told of any request to disclose it?', 'PDPL Art. 24; Implementing Regulation Art. 27',
      'Consent and disclosure notices for credit data; or "na".'),
    Q('P16-1', 'P-16', 'Is only the minimum personal data needed for the purpose collected, with each field linked to a purpose?', 'PDPL Art. 11', 'Data maps; sample forms.'),
    Q('P16-2', 'P-16', 'Is personal data collected from the data subject directly, or from another source only where the Law allows it?', 'PDPL Art. 10', 'Sources recorded per activity.'),
    Q('P17-1', 'P-17', 'Is personal data disclosed only on a basis the Law allows, and is each disclosure to an authority documented?', 'PDPL Art. 15; Implementing Regulation Art. 20', 'The disclosure log.'),
    Q('P18-1', 'P-18', 'When data is corrected, are earlier recipients told, and is processing suspended where inaccurate data could cause harm?', 'PDPL Art. 17; Implementing Regulation Art. 22', 'Correction records and notifications.'),
    Q('P19-1', 'P-19', 'Do marketing and awareness messages require prior consent, identify the sender, and offer an opt-out at least as easy as opting in, stopped at once on request?', 'PDPL Art. 25; Implementing Regulation Arts. 28-29',
      'Consent capture and opt-out handling; or "na" if no marketing is sent.'),
    Q('P20-1', 'P-20', 'Can consent be withdrawn at any time, as easily as it was given, with processing stopped and earlier recipients told?', 'Implementing Regulation Art. 12', 'The withdrawal channel; the consent ledger.'),
    Q('P21-1', 'P-21', 'Is personal data anonymised or pseudonymised where the purpose allows, with the re-identification risk assessed?', 'Implementing Regulation Arts. 7-9', 'Where it is used and the assessment.'),
    Q('P22-1', 'P-22', 'Do research and statistics use non-identifying data, or meet the Law\'s conditions?', 'PDPL Art. 27; Implementing Regulation Art. 30', 'Research uses; or "na".'),
    Q('P23-1', 'P-23', 'Have staff who handle personal data been trained on PDPL and their obligations in the last 12 months?', 'PDPL Art. 19; Implementing Regulation Art. 23', 'Training records.'),
    Q('P24-1', 'P-24', 'Are the records of processing kept for the processing period plus 5 years, and can they be given to SDAIA on request?', 'Implementing Regulation Art. 33', 'The retention rule for the records themselves.'),
]
REQ = {r['id']: r for r in REQS}
CHAPTERS = []
for r in REQS:
    if r['area'] not in CHAPTERS:
        CHAPTERS.append(r['area'])


def questions(req):
    return {'ok': True, 'chapters': CHAPTERS, 'questions': [dict(q, area=REQ[q['req']]['area'], requirement=REQ[q['req']]['title']) for q in QUESTIONS]}


def _rollup(qs):
    ans = [q['answer'] for q in qs]
    if all(a == 'na' for a in ans):
        return 'not_applicable'
    if any(a in (None, 'no') for a in ans):
        return 'non_compliant'
    if all(a in ('yes', 'na') for a in ans):
        return 'compliant'
    return 'partial'


def view(req):
    a = req.get('assessment') or {}
    answers = a.get('answers') or {}
    auto = {r.get('id'): r for r in (req.get('auto') or [])}
    out, gaps, conflicts, missing = [], [], [], []
    for q in QUESTIONS:
        x = answers.get(q['id']) or {}
        ans = x.get('answer') if x.get('answer') in ANSWERS else None
        r = auto.get(q['req']) or {}
        au = r.get('auto') or {}
        sug = None
        if au.get('state') == 'fail':
            sug = {'answer': 'no', 'why': 'the registers show a gap: ' + str(au.get('detail') or '')}
        elif au.get('state') == 'pass':
            sug = {'answer': 'yes', 'why': 'the registers support this: ' + str(au.get('detail') or 'automated check passed')}
        elif au.get('state'):
            sug = {'answer': None, 'why': 'the registers cannot tell yet: ' + str(au.get('detail') or 'not tested')}
        row = dict(q, area=REQ[q['req']]['area'], requirement=REQ[q['req']]['title'], answer=ans, evidence=x.get('evidence') or '', note=x.get('note') or '',
                   by=x.get('by'), at=x.get('at'), suggestion=sug)
        if ans is None:
            missing.append(q['id'])
        if ans in (None, 'no', 'partial'):
            gaps.append({'id': q['id'], 'req': q['req'], 'area': row['area'], 'text': q['text'], 'ref': q['ref'], 'answer': ans or 'unanswered', 'note': row['note'], 'weight': q['weight']})
        if sug and sug['answer'] == 'no' and ans in ('yes', 'na'):
            row['conflict'] = True
            conflicts.append({'id': q['id'], 'req': q['req'], 'answer': ans, 'why': sug['why']})
        out.append(row)

    def score(rows):
        num = den = 0.0
        for q in rows:
            if q['answer'] == 'na':
                continue
            den += q['weight']
            num += q['weight'] * W.get(q['answer'] or 'no', 0)
        return int(100.0 * num / den + 0.5) if den else None
    chapters = []
    for c in CHAPTERS:
        rows = [q for q in out if q['area'] == c]
        chapters.append({'area': c, 'questions': len(rows), 'answered': len([q for q in rows if q['answer']]), 'score': score(rows),
                         'gaps': len([q for q in rows if q['answer'] in (None, 'no', 'partial')])})
    reqs = []
    for r in REQS:
        rows = [q for q in out if q['req'] == r['id']]
        if not rows:
            continue
        res = _rollup(rows)
        reqs.append({'id': r['id'], 'title': r['title'], 'area': r['area'], 'ref': r['ref'], 'result': res,
                     'evidence': '; '.join('%s: %s' % (q['id'], q['evidence']) for q in rows if q['evidence'])[:500],
                     'note': '; '.join('%s: %s' % (q['id'], q['note'] or ('unanswered' if not q['answer'] else q['answer'])) for q in rows if q['answer'] in (None, 'no', 'partial', 'na'))[:1000]})
    gaps.sort(key=lambda g: (-g['weight'], 0 if g['answer'] in ('no', 'unanswered') else 1, g['id']))
    return {'ok': True, 'questions': out, 'chapters': chapters, 'requirements': reqs, 'score': score(out),
            'progress': {'answered': len(out) - len(missing), 'total': len(out)}, 'gaps': gaps, 'conflicts': conflicts,
            'missing': missing, 'ready_to_submit': not missing}


OPS = {
    'pdplassess.questions': questions,
    'pdplassess.view': view,
}
