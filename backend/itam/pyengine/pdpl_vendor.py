# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Vendor risk for processors (engine/pdpl-vendor.js; PDPL Art. 8, Implementing Regulation Art. 17: sufficient guarantees,
periodic assessment). Python decides; Node.js commits.

  inherent tier   from what the vendor actually handles: the processing activities that name it (data categories, volume),
                  whether it works outside the Kingdom, its role and its sub-processors - every point itemised. A vendor no
                  activity names is NOT rated (never assumed low): link it to the activities it serves.
  questionnaire   insurer due-diligence questions the vendor answers (a CSV it fills in and returns); each answer is reviewed
                  by a person, a challenged answer scores as "no" until it is resolved.
  residual risk   the questionnaire score against the inherent tier; gaps become GRC remediation actions on approval.
  schedule        re-assessment every 12 months (critical / high), 24 (medium), 36 (low).
"""
import csv
import io
from datetime import datetime, timezone
from org_brand import fill as _org_fill

DAY = 86400000
SENSITIVE = ('health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage')
CADENCE = {'critical': 12, 'high': 12, 'medium': 24, 'low': 36}
YN = [['yes', 'Yes', 100], ['partial', 'Partly', 50], ['no', 'No', 0], ['na', 'Not applicable', None]]
# id, domain, question, weight, evidence asked for, processor due-diligence check it proves (engine/pdpl-workflows.js DD)
Q = [
    ('GOV-1', 'Governance', 'Is a named person responsible for data protection in your organisation (DPO or equivalent)?', 1, 'name and role', None),
    ('GOV-2', 'Governance', 'Do you have a written information security policy approved by management and reviewed yearly?', 1, 'policy title and date', None),
    ('CER-1', 'Certification', 'Do you hold a current ISO/IEC 27001 certificate (or SOC 2 Type II report) covering the service you provide us?', 3, 'certificate number, issuer and expiry', 'iso27001'),
    ('LOC-1', 'Data location', 'Is our data processed and stored only in the Kingdom of Saudi Arabia (including backups)?', 3, 'data centre locations', 'data_in_ksa'),
    ('LOC-2', 'Data location', 'Can anyone outside the Kingdom access our data (support staff, administrators, tools)?  Answer "No" when no one can.', 2, 'who and from where', None),
    ('SUB-1', 'Sub-processors', 'Do you tell us in advance and wait for our approval before using a new sub-processor for our data?', 2, 'clause in the agreement', None),
    ('SUB-2', 'Sub-processors', 'Do your sub-processors carry the same data protection obligations as you?', 1, 'how it is contracted', None),
    ('BRE-1', 'Breach', 'Will you notify us of a personal data breach affecting our data within 24 hours of becoming aware?', 3, 'clause and contact', 'breach_24h'),
    ('BRE-2', 'Breach', 'Do you have a tested incident response plan (tested in the last 12 months)?', 1, 'test date', None),
    ('ACC-1', 'Access control', 'Is access to our data limited to named staff who need it, with multi-factor authentication?', 2, 'how access is granted and reviewed', None),
    ('ACC-2', 'Access control', 'Is access to our data logged and the logs kept for at least 12 months?', 1, 'log retention', None),
    ('ENC-1', 'Encryption', 'Is our data encrypted in transit (TLS 1.2 or later) and at rest?', 2, 'methods', None),
    ('RET-1', 'Retention', 'At the end of the contract will you return or delete our data (including backups) and confirm it in writing?', 2, 'clause', 'deletion_at_end'),
    ('RET-2', 'Retention', 'Do you keep our data only for as long as we instruct?', 1, 'clause', None),
    ('AUD-1', 'Audit', 'May we audit you, or will you give us independent audit results every year?', 1, 'clause or report', 'audit_right'),
    ('STF-1', 'People', 'Are your staff who handle our data bound by confidentiality and trained in data protection every year?', 1, 'training records', 'staff_confidentiality'),
    ('CON-1', 'Contract', 'Does our agreement state the purpose, the duration, the breach notice, the sub-processor approval and any foreign law that applies to you?', 3, 'agreement reference', 'pdpl_terms'),
    ('BCP-1', 'Continuity', 'Do you have a business continuity / disaster recovery plan for the service, tested in the last 12 months?', 1, 'test date', None),
    ('VUL-1', 'Security testing', 'Is the service penetration-tested by an independent party at least yearly, with high findings fixed?', 2, 'last test date', None),
    ('REQ-1', 'Data subject requests', 'Will you help us answer data subject requests (find, export, correct or delete a person\'s data) within 10 days?', 1, 'clause', None),
]
INVERT = {'LOC-2'}   # "No" is the good answer
VERSION = 1


def ms(v):
    if not v:
        return None
    s = str(v)
    try:
        if len(s) == 10:
            return int(datetime.strptime(s, '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp() * 1000)
        return int(datetime.fromisoformat(s.replace('Z', '+00:00')).timestamp() * 1000)
    except ValueError:
        return None


def day(t):
    return datetime.fromtimestamp(t / 1000, timezone.utc).strftime('%Y-%m-%d') if t else None


def add_months(t, n):
    d = datetime.fromtimestamp(t / 1000, timezone.utc)
    m = d.month - 1 + n
    y, m = d.year + m // 12, m % 12 + 1
    return int(d.replace(year=y, month=m, day=min(d.day, 28)).timestamp() * 1000)


def questions():
    return [{'id': i, 'domain': d, 'q': q, 'weight': w, 'evidence': e, 'proves': p, 'good': 'no' if i in INVERT else 'yes', 'options': [[o[0], o[1]] for o in YN]} for i, d, q, w, e, p in Q]


def tier(p, recs):
    acts = [r for r in recs if r.get('kind') == 'ropa' and r.get('status') != 'archived' and p['id'] in (r.get('processor_ids') or [])]
    if not acts:
        return {'tier': None, 'points': 0, 'why': ['no processing activity names this vendor - link it on Records of Processing so its risk can be rated'], 'activities': []}
    cats = set(c for a in acts for c in (a.get('data_categories') or []))
    vol = max([int(a.get('volume') or 0) for a in acts] or [0])
    pts, why = 0, []
    sens = sorted(cats.intersection(SENSITIVE))
    if sens:
        pts += 3; why.append('+3 sensitive data: ' + ', '.join(sens))
    if 'credit' in cats:
        pts += 2; why.append('+2 credit data')
    if cats.intersection(('identity', 'financial')):
        pts += 1; why.append('+1 identity / financial data')
    if vol > 100000:
        pts += 2; why.append('+2 more than 100,000 people')
    elif vol > 10000:
        pts += 1; why.append('+1 more than 10,000 people')
    elif not vol:
        why.append('+0 volume not recorded on the activities')
    if p.get('outside_ksa'):
        pts += 2; why.append('+2 works outside the Kingdom')
    if p.get('role') == 'joint_controller':
        pts += 1; why.append('+1 joint controller')
    subs = [s for s in (p.get('subprocessors') or []) if s.get('status') != 'rejected']
    if subs:
        pts += 1; why.append('+1 uses %d sub-processor(s)' % len(subs))
    t = 'critical' if pts >= 6 else 'high' if pts >= 4 else 'medium' if pts >= 2 else 'low'
    return {'tier': t, 'points': pts, 'why': why, 'activities': [{'id': a['id'], 'name': a.get('name')} for a in acts]}


def _pts(qid, ans):
    if ans in (None, '', 'na'):
        return None
    if qid in INVERT:
        return {'no': 100, 'partial': 50, 'yes': 0}.get(ans)
    return {'yes': 100, 'partial': 50, 'no': 0}.get(ans)


def score(answers, reviews):
    tot, got, gaps, unanswered = 0, 0, [], []
    for i, d, q, w, e, p in Q:
        a = (answers or {}).get(i) or {}
        ans = a.get('answer')
        if not ans:
            unanswered.append(i); continue
        rv = (reviews or {}).get(i) or {}
        pt = _pts(i, ans)
        if pt is None:
            continue
        if rv.get('verdict') == 'challenged':
            pt = 0   # a challenged answer counts as not met until the vendor resolves it
        tot += w * 100; got += w * pt
        if pt < 100:
            gaps.append({'id': i, 'domain': d, 'q': q, 'weight': w, 'answer': ans, 'challenged': rv.get('verdict') == 'challenged', 'note': rv.get('note') or a.get('note') or '',
                         'priority': 'high' if (w >= 3 and pt == 0) else 'medium' if pt == 0 or w >= 2 else 'low'})
    return {'score': round(got * 100.0 / tot) if tot else None, 'gaps': gaps, 'unanswered': unanswered}


def residual(t, sc):
    if sc is None or t is None:
        return None
    base = 'low' if sc >= 85 else 'medium' if sc >= 60 else 'high'
    if t == 'critical':
        return {'low': 'medium', 'medium': 'high', 'high': 'critical'}[base]
    if t == 'low' and base == 'high':
        return 'medium'
    return base


def dd_from(answers):
    """the processor's due-diligence checks (Processors page) proven by an approved questionnaire"""
    out = {}
    for i, d, q, w, e, p in Q:
        if p:
            out[p] = _pts(i, ((answers or {}).get(i) or {}).get('answer')) == 100
    return out


def assessment_view(req):
    a, recs = req.get('assessment') or {}, req.get('records') or []
    p = next((r for r in recs if r.get('id') == a.get('processor_id')), {}) or {}
    t = tier(p, recs) if p else {'tier': a.get('tier')}
    sc = score(a.get('answers'), a.get('reviews'))
    rows = []
    for qq in questions():
        an = (a.get('answers') or {}).get(qq['id']) or {}
        rows.append(dict(qq, answer=an.get('answer'), evidence_given=an.get('evidence') or '', note=an.get('note') or '', review=(a.get('reviews') or {}).get(qq['id'])))
    blockers = []
    if sc['unanswered']:
        blockers.append('%d question(s) not answered: %s' % (len(sc['unanswered']), ', '.join(sc['unanswered'][:6])))
    unrev = [r['id'] for r in rows if r['answer'] and not r['review']]
    if a.get('status') in ('returned', 'draft', 'sent') and unrev:
        blockers.append('%d answer(s) not reviewed yet' % len(unrev))
    t0 = a.get('tier') or t.get('tier')
    return {'assessment': a, 'questions': rows, 'score': sc['score'], 'gaps': sc['gaps'], 'residual': residual(t0, sc['score']), 'tier': t0, 'blockers': blockers,
            'can_submit': a.get('status') in ('sent', 'returned') and not blockers, 'dd': dd_from(a.get('answers'))}


def view(req):
    recs, now, A = req.get('records') or [], req.get('now') or 0, req.get('assessments') or []
    out, F = [], []
    for p in [r for r in recs if r.get('kind') == 'processor' and r.get('status') != 'archived']:
        t = tier(p, recs)
        mine = sorted([a for a in A if a.get('processor_id') == p['id']], key=lambda x: str(x.get('created_at') or ''), reverse=True)
        appr = next((a for a in mine if a.get('status') == 'approved'), None)
        open_ = next((a for a in mine if a.get('status') not in ('approved', 'cancelled')), None)
        cad = CADENCE.get(t['tier']) if t['tier'] else None
        last = ms(appr.get('approved_at')) if appr else None
        next_due = day(add_months(last, cad)) if last and cad else None
        overdue = bool(t['tier'] and (not appr or (next_due and ms(next_due) < now)))
        sc = score(appr.get('answers'), appr.get('reviews')) if appr else None
        row = {'id': p['id'], 'name': p.get('name'), 'service': p.get('service'), 'tier': t['tier'], 'tier_points': t['points'], 'tier_why': t['why'], 'activities': t['activities'], 'cadence_months': cad,
               'last_approved': appr.get('approved_at') if appr else None, 'score': sc['score'] if sc else None, 'residual': residual(appr.get('tier') or t['tier'], sc['score']) if sc else None,
               'next_due': next_due, 'overdue': overdue, 'open': {'id': open_['id'], 'status': open_.get('status'), 'return_by': open_.get('return_by')} if open_ else None,
               'grc_actions': appr.get('grc_actions') if appr else []}
        out.append(row)
        nm = str(p.get('name'))
        if not t['tier']:
            F.append({'key': 'vendor:%s:unrated' % p['id'], 'severity': 'medium', 'title': 'Vendor %s: risk not rated (no processing activity names it)' % nm, 'evidence': t['why'],
                      'recommendation': 'Add the vendor to the processing activities it serves (Records of Processing → processors).', 'requirement': 'P-10'})
        elif overdue and not open_:
            F.append({'key': 'vendor:%s:due' % p['id'], 'severity': 'high' if t['tier'] in ('critical', 'high') else 'medium',
                      'title': 'Vendor %s (%s risk): %s' % (nm, t['tier'], 'never assessed' if not appr else 'assessment due since ' + next_due), 'evidence': t['why'][:4],
                      'recommendation': 'Start a vendor assessment on the Processors page and send the questionnaire.', 'requirement': 'P-10'})
        if open_ and open_.get('status') == 'sent' and open_.get('return_by') and ms(open_.get('return_by')) < now:
            F.append({'key': 'vendor:%s:late' % p['id'], 'severity': 'medium', 'title': 'Vendor %s has not returned the questionnaire (due %s)' % (nm, open_.get('return_by')), 'evidence': [open_['id']],
                      'recommendation': 'Chase the vendor; a vendor that will not answer is itself a risk to record.', 'requirement': 'P-10'})
        if row['residual'] in ('high', 'critical'):
            F.append({'key': 'vendor:%s:residual' % p['id'], 'severity': 'high', 'title': 'Vendor %s: %s residual risk after assessment (score %s%%)' % (nm, row['residual'], row['score']),
                      'evidence': [g['id'] + ' ' + g['q'][:80] for g in (score(appr.get('answers'), appr.get('reviews'))['gaps'][:4])],
                      'recommendation': 'Work the GRC actions raised from the assessment, or replace the vendor.', 'requirement': 'P-10'})
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, None: 4}
    out.sort(key=lambda x: (order.get(x['tier'], 4), not x['overdue']))
    return {'vendors': out, 'findings': F, 'cadence': CADENCE, 'questions': len(Q), 'version': VERSION,
            'summary': {'vendors': len(out), 'critical': sum(1 for x in out if x['tier'] == 'critical'), 'high': sum(1 for x in out if x['tier'] == 'high'), 'unrated': sum(1 for x in out if not x['tier']),
                        'due': sum(1 for x in out if x['overdue']), 'in_progress': sum(1 for x in out if x['open']), 'high_residual': sum(1 for x in out if x['residual'] in ('high', 'critical'))},
            'note': 'Tier = what the vendor handles (from the processing activities that name it); residual = that tier against the vendor\'s reviewed answers. A processor must give sufficient guarantees and be assessed periodically (PDPL Art. 8; Implementing Regulation Art. 17).'}


def questionnaire_csv(req):
    a, p = req.get('assessment') or {}, req.get('processor') or {}
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\r\n')
    w.writerow([_org_fill('# {{org.name}} - vendor data protection questionnaire'), a.get('id'), 'version %d' % VERSION])
    w.writerow(['# Vendor: ' + str(p.get('name') or '').lstrip('=+-@\t'), 'Return by: ' + str(a.get('return_by') or ''), 'Answer each row: yes / partial / no / na, and give the evidence asked for. Do not change the id column.'])
    w.writerow(['id', 'domain', 'question', 'answer', 'evidence', 'note', 'evidence asked for'])
    for i, d, q, wt, e, pr in Q:
        w.writerow([i, d, q, '', '', '', e])
    text = buf.getvalue()   # every cell is fixed text from this file; the vendor name cannot start a formula (stripped above)
    return {'csv': text, 'filename': 'vendor-questionnaire-%s.csv' % a.get('id')}


def import_csv(req):
    text = str(req.get('csv') or '')
    if len(text) > 200000:
        return {'refuse': {'status': 400, 'error': 'csv is larger than 200 KB'}}
    ids = {i for i, *_ in Q}
    answers, errors, seen = {}, [], set()
    rows = list(csv.reader(io.StringIO(text)))
    head = next((n for n, r in enumerate(rows) if r and r[0].strip().lower() == 'id'), None)
    if head is None:
        return {'refuse': {'status': 400, 'error': 'csv: the header row (id, domain, question, answer, evidence, note) is missing - send back the questionnaire file as it was given'}}
    cols = [c.strip().lower() for c in rows[head]]
    ia, ie, inn = (cols.index(c) if c in cols else None for c in ('answer', 'evidence', 'note'))
    if ia is None:
        return {'refuse': {'status': 400, 'error': 'csv: no "answer" column'}}
    for n, r in enumerate(rows[head + 1:], start=head + 2):
        if not r or not r[0].strip() or r[0].strip().startswith('#'):
            continue
        qid = r[0].strip().upper()
        if qid not in ids:
            errors.append('row %d: unknown question id %s' % (n, qid[:20])); continue
        if qid in seen:
            errors.append('row %d: %s answered twice' % (n, qid)); continue
        seen.add(qid)
        ans = (r[ia] if ia < len(r) else '').strip().lower()
        ans = {'y': 'yes', 'n': 'no', 'partly': 'partial', 'n/a': 'na', 'not applicable': 'na'}.get(ans, ans)
        if not ans:
            continue
        if ans not in ('yes', 'partial', 'no', 'na'):
            errors.append('row %d: %s answer must be yes / partial / no / na' % (n, qid)); continue
        clean = lambda v: ''.join(ch for ch in str(v) if ch >= ' ')[:500].lstrip('=+-@\t')
        answers[qid] = {'answer': ans, 'evidence': clean(r[ie]) if ie is not None and ie < len(r) else '', 'note': clean(r[inn]) if inn is not None and inn < len(r) else ''}
    return {'answers': answers, 'errors': errors[:50], 'answered': len(answers), 'of': len(Q)}


OPS = {'pdpl.vendor_view': view, 'pdpl.vendor_assessment': assessment_view, 'pdpl.vendor_questions': lambda r: {'questions': questions(), 'version': VERSION},
       'pdpl.vendor_csv': questionnaire_csv, 'pdpl.vendor_import': import_csv, 'pdpl.vendor_tier': lambda r: tier(r.get('processor') or {}, r.get('records') or [])}
