# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The Compliance Assistant (engine/compliance-assist.js): plain-language answers about SAMA CSF + IA, NCA ECC, ISO 27001,
NDMO and PDPL, decided here with machine learning that runs on this server - no external AI, nothing leaves the platform.

  * understanding the question  - a multinomial naive Bayes classifier over a labelled seed set (+ the questions people
                                  marked helpful) picks the intent: explain / status / why / todo / evidence / who
  * finding the requirement      - TF-IDF + cosine similarity over every requirement of every register, with plain words
                                  (and a few Arabic ones) expanded to the registers' own terms, re-ranked by what people
                                  marked helpful for the same words before
  * what to do first             - a ranking over every open requirement: how important x how far from met x the chance of
                                  a gap next run x how many frameworks one fix closes; every factor is said in words

The registers decide compliance (their own rules); this module only explains them. An answer is built from the register's
own fields - title, result, why, the evidence it needs - and says so when it cannot match a question: it never invents a
status, an owner or a requirement. Standard library only.
"""
import math
import re

FW = {
    'sama': {'name': 'SAMA CSF + IA', 'page': 'sama-ia.html', 'approver': 'the CISO (or an administrator)',
             'plain': 'The Saudi Central Bank\'s Cyber Security Framework, plus the Insurance Authority requirements. As a regulated insurer the company must meet it; SAMA can inspect at any time.'},
    'ecc': {'name': 'NCA ECC', 'page': 'nca-ecc.html', 'approver': 'the CISO (or an administrator)',
            'plain': 'The National Cybersecurity Authority\'s Essential Cybersecurity Controls - the national minimum for cyber security.'},
    'iso': {'name': 'ISO/IEC 27001', 'page': 'iso27001.html', 'approver': 'the CISO / ISMS owner (or an administrator)',
            'plain': 'The international standard for running information security as a managed system (the ISMS): clauses 4-10 and the 93 Annex A controls. It is what a certification body audits.'},
    'ndmo': {'name': 'NDMO', 'page': 'ndmo.html', 'approver': 'the Chief Data Officer (or an administrator)',
             'plain': 'The National Data Management Office\'s data management and personal data protection standards: 15 domains from data governance to data quality.'},
    'pdpl': {'name': 'PDPL', 'page': 'pdpl-dashboard.html', 'approver': 'the Data Protection Officer (or an administrator)',
             'plain': 'The Personal Data Protection Law (SDAIA): how personal data of customers and staff is collected, used, kept, shared and protected.'},
}
ORDER = ['sama', 'ecc', 'iso', 'ndmo', 'pdpl']

# every register's own result word -> one of five plain states
STATE = {'verified': 'met', 'compliant': 'met', 'auto_pass': 'met', 'met': 'met', 'confirmed': 'met',
         'partial': 'partial', 'partially': 'partial',
         'gap': 'gap', 'non_compliant': 'gap', 'auto_fail': 'gap', 'not': 'gap',
         'not_measured': 'unknown', 'no_evidence': 'unknown', 'not_assessed': 'unknown', 'pending': 'unknown',
         'not_applicable': 'na'}
PLAIN_STATE = {
    'met': 'Done - the platform sees the evidence that it is in place.',
    'partial': 'Partly done - some of it is in place, some is missing.',
    'gap': 'Not done yet - the evidence shows it is missing or failing.',
    'unknown': 'Not checked yet - no evidence source is connected for it, or a person still has to record the evidence.',
    'na': 'Does not apply to the company (decided and recorded with a reason).',
}
SHORT_STATE = {'met': 'Done', 'partial': 'Partly done', 'gap': 'Not done', 'unknown': 'Not checked yet', 'na': 'Not applicable'}
SEV_W = {'high': 3.0, 'medium': 2.0, 'low': 1.0}
STATE_W = {'gap': 1.0, 'partial': 0.6, 'unknown': 0.5}

GLOSSARY = {
    'ciso': 'Chief Information Security Officer - the person accountable for cyber security.',
    'dpo': 'Data Protection Officer - the person accountable for PDPL and the contact point for SDAIA.',
    'cdo': 'Chief Data Officer - the person accountable for data management (NDMO).',
    'isms': 'Information Security Management System - the policies, risk process, roles and reviews that run security as a managed cycle.',
    'soa': 'Statement of Applicability - the ISO 27001 list saying which Annex A controls apply and why.',
    'ropa': 'Record of Processing Activities - the list of every way the company uses personal data, with its purpose and legal basis.',
    'dpia': 'Data Protection Impact Assessment - a risk check done before starting processing that could harm people\'s privacy.',
    'dsar': 'Data Subject Access Request - a person asking to see, correct or delete the data the company holds about them.',
    'siem': 'Security Information and Event Management - collects the logs of every system so attacks can be detected and investigated.',
    'mfa': 'Multi-factor authentication - a second proof of identity (app, code, token) besides the password.',
    'pam': 'Privileged Access Management - controls and records administrator access, ideally granted only when needed.',
    'vapt': 'Vulnerability Assessment and Penetration Testing - scanning for weaknesses and testing whether they can be exploited.',
    'hardening': 'Configuring a system to a secure baseline (for example CIS): unneeded services off, secure settings on.',
    'maturity': 'How established a practice is, from 0 (does not exist) to 5 (continuously improved). SAMA expects level 3.',
    'four-eyes': 'A second, different person must approve - the person who asked never approves their own request.',
    'evidence': 'The proof an auditor accepts: a record, a report, a configuration or a log that shows the control works.',
    'gap': 'A requirement that is not met yet.',
    'not measured': 'The platform has no source connected that can check this requirement - it is not a pass and not a fail.',
    'not applicable': 'The requirement does not apply to the company; the decision and its reason are recorded.',
    'control': 'A safeguard the company puts in place - a policy, a process or a technical setting.',
    'legal basis': 'The PDPL reason that makes using personal data lawful - consent, a contract, a legal duty or a legitimate interest.',
    'retention': 'How long data is kept before it is deleted or anonymised.',
    'incident': 'A security event that harmed or could have harmed systems or data.',
    'third party': 'An outside company (vendor, processor, outsourcer) that handles the company\'s systems or data.',
    'bcp': 'Business Continuity Plan - how the business keeps running when systems or sites are lost.',
    'drp': 'Disaster Recovery Plan - how systems are restored after a major failure.',
    'cis': 'Center for Internet Security benchmarks - the secure configuration baselines the hardening checks use.',
    'grc': 'Governance, Risk and Compliance - policies, risk register, exceptions and the actions that close gaps.',
}

# plain words people use -> the registers' own words (English and a few Arabic)
SYN = {
    'password': 'authentication credential mfa identity access', 'passwords': 'authentication credential mfa',
    'login': 'authentication access identity mfa', 'hacker': 'threat attack incident', 'hackers': 'threat attack incident',
    'attack': 'threat incident', 'breach': 'incident breach notification', 'leak': 'breach incident data loss dlp',
    'backup': 'backup recovery resilience continuity', 'backups': 'backup recovery resilience', 'restore': 'recovery backup',
    'disaster': 'recovery continuity resilience', 'privacy': 'pdpl personal data subject', 'customer': 'personal data subject',
    'customers': 'personal data subject', 'laptop': 'endpoint device asset', 'laptops': 'endpoint device asset',
    'pc': 'endpoint device asset', 'computer': 'endpoint device asset', 'phone': 'mobile device',
    'patch': 'patch vulnerability update', 'patching': 'patch vulnerability update', 'update': 'patch vulnerability',
    'updates': 'patch vulnerability', 'logs': 'log siem monitoring event', 'logging': 'log siem monitoring',
    'monitor': 'monitoring siem log', 'vendor': 'third party supplier outsourcing processor', 'vendors': 'third party supplier outsourcing processor',
    'supplier': 'third party outsourcing', 'suppliers': 'third party outsourcing', 'training': 'awareness training',
    'awareness': 'awareness training', 'staff': 'personnel employee awareness', 'leaver': 'offboarding access revocation',
    'leavers': 'offboarding access revocation', 'resign': 'offboarding access', 'joiner': 'onboarding access', 'admin': 'privileged access',
    'admins': 'privileged access', 'encrypt': 'encryption cryptography key', 'encryption': 'cryptography key',
    'firewall': 'network security segmentation', 'internet': 'network exposed internet facing', 'cloud': 'cloud hosting',
    'strategy': 'strategy roadmap governance', 'board': 'governance committee approval', 'manager': 'governance owner',
    'audit': 'audit internal review', 'auditor': 'audit evidence', 'consent': 'consent personal data', 'delete': 'retention destruction deletion',
    'keep': 'retention', 'scan': 'vulnerability scan vapt', 'pentest': 'penetration test vapt', 'virus': 'malware endpoint protection',
    'antivirus': 'malware endpoint protection', 'email': 'email mail phishing', 'phishing': 'email phishing awareness',
    'risk': 'risk assessment register', 'policy': 'policy policies approved', 'policies': 'policy approved',
    # Arabic
    'كلمة': 'authentication', 'المرور': 'authentication credential', 'نسخ': 'backup', 'احتياطي': 'backup recovery',
    'بيانات': 'data', 'شخصية': 'personal pdpl', 'الخصوصية': 'pdpl personal privacy', 'سياسة': 'policy', 'سياسات': 'policy',
    'مخاطر': 'risk', 'المخاطر': 'risk', 'حوادث': 'incident', 'حادث': 'incident', 'تدريب': 'awareness training', 'توعية': 'awareness',
    'تشفير': 'encryption cryptography', 'مورد': 'third party supplier', 'الموردين': 'third party supplier', 'صلاحيات': 'access privileged',
    'سجلات': 'log siem', 'ثغرات': 'vulnerability', 'تحديثات': 'patch', 'استراتيجية': 'strategy', 'حوكمة': 'governance',
    'ساما': 'sama', 'الهيئة': 'nca', 'نديمو': 'ndmo', 'ايزو': 'iso',
}
FW_WORDS = {'sama': 'sama', 'csf': 'sama', 'insurance': 'sama', 'ia': 'sama', 'nca': 'ecc', 'ecc': 'ecc', 'iso': 'iso', '27001': 'iso',
            'isms': 'iso', 'annex': 'iso', 'ndmo': 'ndmo', 'pdpl': 'pdpl', 'sdaia': 'pdpl', 'ساما': 'sama', 'الهيئة': 'ecc',
            'نديمو': 'ndmo', 'ايزو': 'iso'}

STOP = set('a an the of to in on for and or is are be been being was were it this that these those i we our us you your my me '
           'do does did can could should would will shall may might must have has had with without by from at as about into '
           'what which who whom how why when where there here please tell show give me any all some more most very just '
           'في من على الى إلى عن هل ما ماذا كيف لماذا هذا هذه نحن'.split())
SUFFIX = ('ations', 'ation', 'ings', 'ing', 'ness', 'ments', 'ment', 'ies', 'ed', 'es', 's')
TOKEN = re.compile(r'[a-z0-9]+|[؀-ۿ]+')


def stem(w):
    if not w.isascii() or len(w) <= 4:
        return w
    for s in SUFFIX:
        if w.endswith(s) and len(w) - len(s) >= 4:
            return w[:-len(s)] + ('y' if s == 'ies' else '')
    return w


def words(text):
    return [w for w in TOKEN.findall(str(text or '').lower()) if w not in STOP and len(w) > 1]


def tokens(text, expand=False):
    out = []
    for w in words(text):
        out.append(stem(w))
        if expand and w in SYN:
            out.extend(stem(x) for x in SYN[w].split())
    return out


# ---------------------------------------------------------------- intent: multinomial naive Bayes
SEED = {
    'explain': ['what does this mean', 'explain this requirement', 'what is this control', 'in simple words', 'what is a dpia',
                'what is ropa', 'meaning of', 'describe this', 'what does sama ask', 'what is the requirement about', 'help me understand',
                'what is maturity level', 'ماذا يعني', 'اشرح'],
    'status': ['are we compliant', 'how are we doing', 'what is our score', 'where do we stand', 'compliance percentage',
               'overall status', 'how compliant are we with sama', 'summary of our compliance', 'progress', 'how many requirements are met',
               'readiness', 'are we ready for the audit', 'ما هي نسبة الامتثال', 'هل نحن ملتزمون'],
    'why': ['why is this failing', 'why is it a gap', 'why red', 'why not met', 'why is it not compliant', 'what is wrong',
            'reason it failed', 'why does it say not measured', 'why partial', 'why did it change', 'لماذا'],
    'todo': ['what should i do', 'how do i fix this', 'next step', 'how to close the gap', 'what to do first', 'priorities',
             'what should we fix first', 'how to become compliant', 'action plan', 'remediate', 'how to improve the score',
             'quick wins', 'ماذا افعل', 'كيف نصلح'],
    'evidence': ['what evidence is needed', 'what proof does the auditor want', 'which document', 'what do i upload',
                 'evidence for this control', 'what will the auditor ask', 'how do we prove it', 'ما الدليل المطلوب'],
    'who': ['who approves', 'who is responsible', 'who owns this', 'who must sign', 'who decides', 'who can approve the evidence',
            'من يوافق', 'من المسؤول'],
}
INTENTS = list(SEED)


def train(extra=None):
    counts = {i: {} for i in INTENTS}
    docs = {i: 0 for i in INTENTS}
    examples = [(i, s) for i, ls in SEED.items() for s in ls]
    for ex in (extra or [])[-500:]:
        if isinstance(ex, dict) and ex.get('intent') in counts and isinstance(ex.get('tokens'), list):
            examples.append((ex['intent'], ' '.join(str(t) for t in ex['tokens'][:40])))
    vocab = set()
    for i, s in examples:
        docs[i] += 1
        for t in words(s):   # intent words are kept unstemmed and include question words
            counts[i][t] = counts[i].get(t, 0) + 1
            vocab.add(t)
    return counts, docs, vocab


INTENT_WORDS = {'what', 'why', 'how', 'who', 'which'}


def classify(question, extra=None):
    counts, docs, vocab = train(extra)
    raw = [w for w in TOKEN.findall(str(question or '').lower()) if len(w) > 1]
    ws = [w for w in raw if w in vocab or w in INTENT_WORDS]
    total = sum(docs.values())
    scores = {}
    for i in INTENTS:
        n = sum(counts[i].values())
        lp = math.log(docs[i] / total)
        for w in ws:
            lp += math.log((counts[i].get(w, 0) + 1) / (n + len(vocab) + 1))
        scores[i] = lp
    # the question word is strong evidence on its own (why -> why, who -> who)
    if 'why' in raw or 'لماذا' in raw:
        scores['why'] += 3
    if 'who' in raw:
        scores['who'] += 3
    m = max(scores.values())
    ex = {i: math.exp(v - m) for i, v in scores.items()}
    z = sum(ex.values())
    best = max(ex, key=ex.get)
    return best, round(ex[best] / z, 2)


# ---------------------------------------------------------------- the requirements, one shape
def area_of(fw, r):
    return r.get('subdomain_name') or r.get('domain_name') or r.get('group_name') or r.get('area') or r.get('domain') or ''


def norm(fw, r):
    res = str(r.get('result') or r.get('level') or 'not_assessed')
    st = STATE.get(res) or STATE.get(str(r.get('level') or ''), 'unknown')
    hint = r.get('evidence_hint') or r.get('evidence_expected') or ''
    links = []
    for k in ('ecc',):
        v = r.get(k)
        if isinstance(v, str) and v:
            links.append(('ecc', v))
        elif isinstance(v, list):
            links.extend(('ecc', x) for x in v if isinstance(x, str))
    hist = r.get('history') if isinstance(r.get('history'), dict) else {}
    return {'fw': fw, 'id': str(r.get('id') or '')[:40], 'title': str(r.get('title') or '')[:400], 'area': str(area_of(fw, r))[:120],
            'state': st, 'result': res, 'why': str(r.get('why') or '')[:500], 'hint': str(hint)[:300],
            'severity': r.get('severity') if r.get('severity') in SEV_W else 'medium', 'automated': bool(r.get('automated')),
            'recommend': str(r.get('recommend') or '')[:400] if isinstance(r.get('recommend'), str) else '',
            'ref': str(r.get('ref') or '')[:80], 'p_gap': float(hist.get('p_gap')) if isinstance(hist.get('p_gap'), (int, float)) else None,
            'regression': bool(hist.get('regression')), 'links': links}


def collect(req):
    regs = req.get('registers') if isinstance(req.get('registers'), dict) else {}
    items = []
    for fw in ORDER:
        for r in (regs.get(fw) or [])[:400]:
            if isinstance(r, dict) and r.get('id'):
                items.append(norm(fw, r))
    # cross-framework reach: SAMA and ISO name the NCA ECC control they share evidence with
    by_ecc = {}
    for it in items:
        for _, e in it['links']:
            by_ecc.setdefault(e, []).append(it)
    for it in items:
        also = []
        if it['fw'] == 'ecc':
            also = [(x['fw'], x['id']) for x in by_ecc.get(it['id'], [])]
        else:
            for _, e in it['links']:
                also.append(('ecc', e))
                also.extend((x['fw'], x['id']) for x in by_ecc.get(e, []) if x is not it)
        seen, out = set(), []
        for a in also:
            if a not in seen and a != (it['fw'], it['id']):
                seen.add(a)
                out.append({'fw': a[0], 'id': a[1], 'name': FW[a[0]]['name']})
        it['also'] = out[:8]
    return items


# ---------------------------------------------------------------- TF-IDF retrieval
def doc_text(it):
    return ' '.join([FW[it['fw']]['name'], it['id'], it['title'], it['title'], it['area'], it['hint'], it['why'], it['ref']])


def index(items):
    docs = [tokens(doc_text(it)) for it in items]
    df = {}
    for d in docs:
        for t in set(d):
            df[t] = df.get(t, 0) + 1
    n = len(docs) or 1
    idf = {t: math.log((n + 1) / (c + 1)) + 1 for t, c in df.items()}
    vecs = []
    for d in docs:
        tf = {}
        for t in d:
            tf[t] = tf.get(t, 0) + 1
        v = {t: (1 + math.log(c)) * idf[t] for t, c in tf.items()}
        norm_ = math.sqrt(sum(x * x for x in v.values())) or 1.0
        vecs.append({t: x / norm_ for t, x in v.items()})
    return vecs, idf


def search(items, question, fw=None, boosts=None, k=5, built=None):
    vecs, idf = built or index(items)
    q = tokens(question, expand=True)
    tf = {}
    for t in q:
        if t in idf:
            tf[t] = tf.get(t, 0) + 1
    qv = {t: (1 + math.log(c)) * idf[t] for t, c in tf.items()}
    qn = math.sqrt(sum(x * x for x in qv.values())) or 1.0
    # an exact requirement id in the question wins outright
    ids = {m.upper() for m in re.findall(r'[A-Za-z0-9]+(?:[-.][A-Za-z0-9]+)+', str(question))}
    boosts = boosts or {}
    out = []
    for it, v in zip(items, vecs):
        if fw and it['fw'] != fw:
            continue
        s = sum(qv[t] / qn * v.get(t, 0.0) for t in qv)
        if it['id'].upper() in ids:
            s += 1.0
        learned = sum(boosts.get(t, {}).get(it['fw'] + ':' + it['id'], 0) for t in set(q))
        if learned:
            s *= 1 + min(0.5, 0.1 * learned)   # people marked this requirement helpful for these words before
        if s > 0:
            out.append((s, it))
    out.sort(key=lambda x: -x[0])
    return [(round(s, 3), it) for s, it in out[:k]]


# ---------------------------------------------------------------- plain-language explanation
def glossary_for(*texts):
    blob = ' '.join(texts).lower()
    found = []
    for term, plain in GLOSSARY.items():
        if re.search(r'(?<![a-z])' + re.escape(term) + r'(?![a-z])', blob):
            found.append({'term': term, 'plain': plain})
    return found[:6]


def next_step(it):
    fwn = FW[it['fw']]
    if it['state'] == 'met':
        return 'Nothing to do now - keep the evidence current; the register re-checks it automatically.'
    if it['state'] == 'na':
        return 'Nothing to do - review the not-applicable decision when the business changes.'
    if it['recommend']:
        return it['recommend']
    hint = (' (' + it['hint'] + ')') if it['hint'] else ''
    if it['state'] == 'unknown' and not it['automated']:
        return ('A person records the evidence' + hint + ' on the ' + fwn['name'] + ' page; ' + fwn['approver']
                + ' approves it. After that it counts as met until its review date.')
    if it['state'] == 'unknown':
        return ('Connect the source the platform reads for this (see "why" above) so it can be checked automatically - '
                'or record the evidence' + hint + ' by hand for approval.')
    return ('Put the missing part in place' + hint + '. When it is done the register sees it on the next run (daily); '
            'there is nothing else to report.')


def explain(it):
    fwn = FW[it['fw']]
    why = it['why'] or 'the register gives no further detail'
    out = {
        'fw': it['fw'], 'framework': fwn['name'], 'id': it['id'], 'title': it['title'], 'area': it['area'],
        'state': it['state'], 'status': SHORT_STATE[it['state']], 'severity': it['severity'],
        'what': 'It asks that: ' + it['title'].rstrip('.') + '.',
        'where': PLAIN_STATE[it['state']] + (' Detail: ' + why + '.' if it['state'] != 'met' else ' Detail: ' + why + '.'),
        'todo': next_step(it),
        'evidence': ('An auditor accepts: ' + it['hint'] + '.') if it['hint'] else 'The register does not list a specific document for this one.',
        'who': 'Approved by ' + fwn['approver'] + ' - never by the person who recorded it, and never by a service or AI identity.',
        'checked': ('Checked automatically from the platform\'s own data.' if it['automated']
                    else 'Not automatic: a person records the evidence and another person approves it.'),
        'importance': {'high': 'High importance - an auditor will look at this first.', 'medium': 'Medium importance.',
                       'low': 'Lower importance.'}[it['severity']],
        'also': it.get('also') or [],
        'page': fwn['page'], 'ref': it['ref'],
    }
    if out['also']:
        out['also_plain'] = 'The same evidence also counts for: ' + ', '.join(a['name'] + ' ' + a['id'] for a in out['also'][:5]) + '.'
    out['glossary'] = glossary_for(it['title'], it['why'], it['hint'])
    return out


# ---------------------------------------------------------------- overview and what to do first
def counts(items):
    c = {'met': 0, 'partial': 0, 'gap': 0, 'unknown': 0, 'na': 0}
    for it in items:
        c[it['state']] += 1
    applicable = len(items) - c['na']
    c['total'] = len(items)
    c['applicable'] = applicable
    c['pct_met'] = round(100 * c['met'] / applicable) if applicable else 0
    return c


def priority(it):
    if it['state'] not in STATE_W:
        return None
    reach = 1 + 0.5 * len({a['fw'] for a in it.get('also') or []})
    p = it['p_gap'] if it['p_gap'] is not None else 0.5
    s = SEV_W[it['severity']] * STATE_W[it['state']] * (1 + p) * reach * (1.2 if it['automated'] else 1.0) + (1 if it['regression'] else 0)
    why = [it['severity'] + ' importance', SHORT_STATE[it['state']].lower()]
    if it.get('also'):
        why.append('one fix also counts for ' + ', '.join(sorted({a['name'] for a in it['also']})))
    if it['p_gap'] is not None:
        why.append('%d%% chance it is still a gap at the next run' % round(100 * p))
    if it['automated']:
        why.append('checked automatically, so the fix shows the next day')
    if it['regression']:
        why.append('it was met and slipped back')
    return round(s, 2), why


def weakest(items):
    by = {}
    for it in items:
        if it['state'] == 'na' or not it['area']:
            continue
        b = by.setdefault(it['area'], [0, 0])
        b[1] += 1
        b[0] += 1 if it['state'] == 'met' else 0
    rows = sorted(((m / n, n, a) for a, (m, n) in by.items() if n >= 2), key=lambda x: (x[0], -x[1]))
    return [{'area': a, 'pct_met': round(100 * r), 'requirements': n} for r, n, a in rows[:3]]


def fw_sentence(fw, c, weak):
    name = FW[fw]['name']
    if not c['total']:
        return name + ': the register is not installed or did not answer, so nothing can be said about it.'
    s = '%s: %d of %d applicable requirements are done (%d%%).' % (name, c['met'], c['applicable'], c['pct_met'])
    parts = []
    if c['gap']:
        parts.append('%d not done yet' % c['gap'])
    if c['partial']:
        parts.append('%d partly done' % c['partial'])
    if c['unknown']:
        parts.append('%d not checked yet (no source connected or waiting for a person to record evidence)' % c['unknown'])
    if parts:
        s += ' ' + '; '.join(parts).capitalize() + '.'
    if weak:
        s += ' Weakest area: ' + weak[0]['area'] + ' (%d%% done).' % weak[0]['pct_met']
    return s


def overview(items, fws=None, top=8):
    out = []
    for fw in ORDER:
        if fws and fw not in fws:
            continue
        its = [i for i in items if i['fw'] == fw]
        c = counts(its)
        w = weakest(its)
        out.append({'fw': fw, 'framework': FW[fw]['name'], 'plain': FW[fw]['plain'], 'page': FW[fw]['page'], 'counts': c,
                    'weakest': w, 'sentence': fw_sentence(fw, c, w), 'installed': bool(its)})
    pr = []
    for it in items:
        if fws and it['fw'] not in fws:
            continue
        p = priority(it)
        if p:
            pr.append({'fw': it['fw'], 'framework': FW[it['fw']]['name'], 'id': it['id'], 'title': it['title'], 'status': SHORT_STATE[it['state']],
                       'state': it['state'], 'score': p[0], 'why': p[1], 'todo': next_step(it), 'page': FW[it['fw']]['page']})
    pr.sort(key=lambda x: -x['score'])
    return {'frameworks': out, 'first': pr[:top],
            'method': 'Ranked by importance x how far from done x the chance it is still a gap at the next run x how many '
                      'frameworks one fix closes; checked-automatically items get a small lift because the fix shows the next day.'}


# ---------------------------------------------------------------- the operations
SUGGEST = ['Are we compliant with SAMA?', 'What should we fix first?', 'What is a DPIA?', 'Who approves PDPL evidence?',
           'Why is the cybersecurity strategy a gap?', 'What evidence does the auditor want for backups?', 'How do we handle leavers\' access?']


def op_ask(req):
    q = str(req.get('question') or '')[:500]
    items = collect(req)
    learn = req.get('learn') if isinstance(req.get('learn'), dict) else {}
    intent, conf = classify(q, learn.get('examples'))
    qw = words(q)
    fw = req.get('fw') if req.get('fw') in FW else None
    named = [FW_WORDS[w] for w in qw if w in FW_WORDS]
    fw = fw or (named[0] if named else None)
    built = index(items) if items else ([], {})
    hits = search(items, q, fw, learn.get('boosts'), built=built)
    best = hits[0][0] if hits else 0
    # the words feedback may keep: compliance vocabulary only, so a name or anything else typed is never stored (PDPL)
    _, _, ivocab = train()
    known = [t for t in tokens(q, expand=True) if t in built[1]] + [w for w in qw if w in ivocab]
    gl = glossary_for(q)
    ans = {'ok': True, 'intent': intent, 'intent_confidence': conf, 'fw': fw, 'framework': FW[fw]['name'] if fw else None,
           'match_confidence': round(min(1.0, best), 2), 'tokens': sorted(set(known))[:40], 'glossary': gl, 'matches': [],
           'engine': 'local machine learning (naive Bayes intent, TF-IDF search) - nothing is sent outside the platform'}
    if not items:
        ans['summary'] = 'No compliance register answered, so there is nothing to explain yet. Run the update so the registers are installed.'
        ans['suggest'] = SUGGEST[:3]
        return ans
    overall = intent == 'status' or (intent == 'todo' and best < 0.35)
    if overall:
        ov = overview(items, [fw] if fw else None, top=5)
        ans['overview'] = ov
        if intent == 'status':
            ans['summary'] = ' '.join(f['sentence'] for f in ov['frameworks'])
        else:
            ans['summary'] = ('Start with these %d - they close the most risk for the effort, and several count for more than one '
                              'framework at once.' % len(ov['first'])) if ov['first'] else 'Nothing is open - every applicable requirement is done.'
        return ans
    if gl and intent == 'explain' and best < 0.3:
        ans['summary'] = ' '.join('%s: %s' % (g['term'].upper() if len(g['term']) <= 5 else g['term'].capitalize(), g['plain']) for g in gl[:2])
        ans['matches'] = [explain(it) for s, it in hits[:3] if s >= 0.12]
        return ans
    good = [(s, it) for s, it in hits if s >= 0.12]
    if not good:
        ans['summary'] = ('I could not match that to a requirement in the registers, so I will not guess. Try the words a policy '
                          'or an auditor would use (backup, access review, encryption, personal data, incident) or a requirement id.')
        ans['suggest'] = SUGGEST[:4]
        return ans
    ex = [explain(it) for s, it in good[:3]]
    top = ex[0]
    lead = {'explain': top['what'] + ' ' + top['where'], 'why': top['where'], 'todo': top['todo'], 'evidence': top['evidence'],
            'who': top['who']}.get(intent, top['what'] + ' ' + top['where'])
    ans['summary'] = '%s %s - %s. %s' % (top['framework'], top['id'], top['status'], lead)
    ans['matches'] = ex
    if best < 0.25:
        ans['note'] = 'A loose match - check that the requirement below is the one you meant.'
    return ans


def op_explain(req):
    items = collect(req)
    fw, rid = req.get('fw'), str(req.get('id') or '')
    for it in items:
        if it['fw'] == fw and it['id'] == rid:
            return {'ok': True, 'explanation': explain(it)}
    return {'ok': False, 'error_class': 'not_found', 'error': 'requirement %s is not in the %s register' % (rid[:40], FW.get(fw, {}).get('name', fw))}


def op_overview(req):
    items = collect(req)
    fws = [f for f in (req.get('fws') or []) if f in FW] or None
    return dict({'ok': True}, **overview(items, fws, top=int(req.get('top') or 10)))


def op_glossary(req):
    return {'ok': True, 'terms': [{'term': k, 'plain': v} for k, v in sorted(GLOSSARY.items())],
            'frameworks': [{'fw': f, 'name': FW[f]['name'], 'plain': FW[f]['plain'], 'page': FW[f]['page']} for f in ORDER],
            'states': [{'state': k, 'label': SHORT_STATE[k], 'plain': v} for k, v in PLAIN_STATE.items()], 'suggest': SUGGEST}


OPS = {'assist.ask': op_ask, 'assist.explain': op_explain, 'assist.overview': op_overview, 'assist.glossary': op_glossary}
