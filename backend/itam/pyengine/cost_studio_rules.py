# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Cost Studio rules (engine/cost-studio.js): where the IT money goes, where it can be saved, and how the budget will really be
spent - from the platform's own records, every number explained, nothing priced by guess.

op cost.studio  {budget, licences, contracts, virt, assets, blocked, now}
  savings     opportunities with their evidence: licence seats paid for and not used (installs the agents saw), a support
              contract for more units than the inventory needs, a contract that still lists retired / missing assets, two
              active contracts of one family and vendor covering the same period, VMs that are powered off but hold memory and
              disk, VMs configured larger than their 95th-percentile use. A saving in money is given only when a cost is
              recorded (licence cost / seats, contract cost / quantity); otherwise the resource is given (seats, vCPU, GB)
              and the money is "not known".
  execution   learned from last year's budget (approved vs spent per envelope / area / kind, 3+ lines): the share that was
              really spent, applied to this year's priced lines - expected spend and the part that will likely not be spent.
  unusual     a priced line more than 3x the median of last year's approved lines of the same area and kind (5+ lines), or a
              line with last year's title whose amount changed by more than 50 %.
  showback    purchase cost of the active assets by site, department and type, and the yearly licence and contract costs.
"""
import re

TRIM = re.compile(r'[^a-z0-9]+')


def norm(t):
    return TRIM.sub(' ', str(t or '').lower()).strip()


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return None
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def op_studio(req):
    blocked = set(req.get('blocked') or [])
    out = []

    def opp(key, kind, title, evidence, saving=None, resource=None, confidence=0.8, where=None):
        if key in blocked:
            return
        out.append({'key': key, 'kind': kind, 'title': title, 'evidence': evidence, 'saving': saving, 'resource': resource,
                    'confidence': confidence, 'where': where})

    # ---- licences: seats not used
    for l in req.get('licences') or []:
        seats, used, cost = num(l.get('seats')), num(l.get('used')), num(l.get('cost'))
        if seats is None or used is None or used >= seats:
            continue
        free = seats - used
        sv = None
        if cost and seats:
            sv = {'value': round(cost * free / float(seats)), 'basis': '%d of %d seats x recorded cost %s / %d seats' % (free, seats, '{:,.0f}'.format(cost), seats)}
        opp('lic|' + str(l.get('id')), 'unused-licence', '%s: %d of %d seats not used' % (l.get('product'), free, seats),
            'installs seen by the agents: %d (a device without an agent is not counted - check before reducing)' % used, sv,
            '%d seat(s)' % free, 0.85 if used else 0.6, 'licences.html')

    # ---- support contracts
    con = req.get('contracts') or []
    for c in con:
        if c.get('state') in ('retired', 'expired'):
            continue
        q, need, cost = num(c.get('quantity')), num(c.get('need')), num(c.get('cost'))
        if q and need is not None and need < q:
            sv = {'value': round(cost * (q - need) / float(q)), 'basis': '%s of %s units x recorded cost / quantity' % (q - need, q)} if cost else None
            opp('con-qty|' + str(c.get('id')), 'contract-quantity', '%s %s: %s units paid, %s needed' % (c.get('vendor'), c.get('product'), q, need),
                'the inventory counts %s %s in scope at renewal (%s)' % (need, c.get('unit') or 'units', c.get('end') or 'no end date'), sv, '%s unit(s)' % (q - need), 0.8, 'support-contracts.html')
        stale = [i for i in (c.get('issues') or []) if re.search(r'retired|not in the inventory|missing', str(i), re.I)]
        if stale:
            opp('con-stale|' + str(c.get('id')), 'contract-stale-assets', '%s %s still lists assets that are gone' % (c.get('vendor'), c.get('product')),
                '; '.join(str(x) for x in stale)[:300], None, None, 0.7, 'support-contracts.html')
    act = [c for c in con if c.get('state') in ('active', 'expiring') and c.get('family')]
    for i in range(len(act)):
        for j in range(i + 1, len(act)):
            a, b = act[i], act[j]
            if a['family'] == b['family'] and norm(a.get('vendor')) == norm(b.get('vendor')) and a.get('family') not in ('hardware', 'other') \
                    and str(a.get('start') or '') <= str(b.get('end') or '9999') and str(b.get('start') or '') <= str(a.get('end') or '9999'):
                opp('con-dup|' + '|'.join(sorted([str(a['id']), str(b['id'])])), 'contract-overlap', 'Two %s contracts for %s cover the same period' % (a.get('vendor'), a.get('family')),
                    '%s (%s to %s) and %s (%s to %s) - check they do not cover the same assets' % (a.get('contract_number') or a['id'], a.get('start'), a.get('end'), b.get('contract_number') or b['id'], b.get('start'), b.get('end')),
                    None, None, 0.6, 'support-contracts.html')

    # ---- virtualization (from the over-provisioning report: 95th percentile, never averages)
    v = req.get('virt') or {}
    for x in (v.get('off') or [])[:200]:
        res = ', '.join(p for p in [('%s GB RAM' % x['mem_gb']) if x.get('mem_gb') else '', ('%s GB disk' % (x.get('disk_prov_gb') or x.get('disk_gb'))) if (x.get('disk_prov_gb') or x.get('disk_gb')) else ''] if p)
        if res:
            opp('vm-off|' + str(x.get('pid')) + '|' + str(x.get('id')), 'vm-off', 'VM %s is powered off and holds %s' % (x.get('name'), res),
                'cluster %s - delete or archive it if nobody needs it (Power Control / the AI Virtualization Administrator)' % (x.get('cluster') or '?'), None, res, 0.7, 'virt-power.html')
    for x in (v.get('vms') or [])[:300]:
        parts = [p for p in [('%s vCPU' % x['save_vcpu']) if x.get('save_vcpu') else '', ('%s GB RAM' % x['save_mem_gb']) if x.get('save_mem_gb') else ''] if p]
        if parts:
            opp('vm-size|' + str(x.get('pid')) + '|' + str(x.get('id')), 'vm-rightsize', 'VM %s can give back %s' % (x.get('name'), ' and '.join(parts)),
                '95th percentile over %s day(s): %s' % (v.get('days') or 30, x.get('why') or 'CPU and memory well under what is configured'), None, ' + '.join(parts), 0.75, 'capacity.html')

    # ---- execution learned from last year's budget
    b = req.get('budget') or {}
    prev = [r for r in (b.get('previous_rows') or []) if num(r.get('approved'))]
    groups = {}
    for r in prev:
        k = (r.get('envelope') or '?', r.get('area') or '', r.get('kind') or 'opex')
        groups.setdefault(k, []).append(r)
    exe = []
    for k, rows in groups.items():
        ap = sum(r['approved'] for r in rows)
        sp = sum(num(r.get('spent')) or 0 for r in rows)
        if len(rows) >= 3 and ap > 0:
            exe.append({'envelope': k[0], 'area': k[1], 'kind': k[2], 'lines': len(rows), 'approved': round(ap), 'spent': round(sp), 'ratio': round(sp / ap, 3)})
    exe_ix = {(e['envelope'], e['area'], e['kind']): e for e in exe}
    lines = [l for l in (b.get('lines') or []) if l.get('status') not in ('rejected', 'deferred')]
    expected = []
    for env in set([l.get('envelope') for l in lines]):
        own = [l for l in lines if l.get('envelope') == env and l.get('priced')]
        total = sum(l['amount'] for l in own)
        exp, used_hist = 0.0, 0
        for l in own:
            e = exe_ix.get((env, l.get('area') or '', l.get('kind') or 'opex'))
            if e:
                exp += l['amount'] * min(1.2, e['ratio'])
                used_hist += 1
            else:
                exp += l['amount']
        expected.append({'envelope': env, 'proposed': round(total), 'expected_spend': round(exp), 'likely_unspent': round(total - exp),
                         'lines_with_history': used_hist, 'lines': len(own)})

    # ---- unusual lines
    unusual = []
    by_ak = {}
    for r in prev:
        by_ak.setdefault((r.get('area') or '', r.get('kind') or 'opex'), []).append(r['approved'])
    prev_title = {norm(r.get('title')): r for r in prev}
    for l in lines:
        if not l.get('priced'):
            continue
        m = by_ak.get((l.get('area') or '', l.get('kind') or 'opex'))
        if m and len(m) >= 5 and l['amount'] > 3 * median(m):
            unusual.append({'line': l.get('id'), 'title': l.get('title'), 'amount': l['amount'], 'why': '%.1fx the median of last year\'s %d approved %s %s lines (%s)'
                            % (l['amount'] / median(m), len(m), l.get('area') or '', l.get('kind'), '{:,.0f}'.format(median(m)))})
        p = prev_title.get(norm(l.get('title')))
        if p and p.get('approved') and abs(l['amount'] - p['approved']) / float(p['approved']) > 0.5:
            unusual.append({'line': l.get('id'), 'title': l.get('title'), 'amount': l['amount'], 'why': 'last year this line was approved at %s (%+d %%)'
                            % ('{:,.0f}'.format(p['approved']), round(100.0 * (l['amount'] - p['approved']) / p['approved']))})

    # ---- showback
    show = {'site': {}, 'department': {}, 'type': {}}
    known = 0
    for a in req.get('assets') or []:
        c = num(a.get('cost'))
        if not c:
            continue
        known += 1
        for dim in show:
            k = a.get(dim) or '(not set)'
            show[dim][k] = show[dim].get(k, 0) + c
    lic_year = sum(num(l.get('cost')) or 0 for l in req.get('licences') or [])
    con_year = sum(num(c.get('cost')) or 0 for c in con if c.get('state') in ('active', 'expiring'))

    out.sort(key=lambda x: (-(x['saving'] or {}).get('value', 0), -x['confidence']))
    money = sum((x['saving'] or {}).get('value', 0) for x in out)
    return {'ok': True,
            'summary': {'opportunities': len(out), 'saving_known': round(money), 'priced_opportunities': len([x for x in out if x['saving']]),
                        'licence_cost': round(lic_year), 'contract_cost': round(con_year), 'assets_with_cost': known,
                        'unusual': len(unusual), 'history_groups': len(exe)},
            'savings': out[:500], 'execution': sorted(exe, key=lambda e: e['ratio']), 'expected': expected, 'unusual': unusual[:100],
            'showback': {k: sorted([{'name': n, 'cost': round(c)} for n, c in d.items()], key=lambda x: -x['cost'])[:30] for k, d in show.items()},
            'learned': {'note': 'Execution learned from %d of last year\'s budget lines (%d groups with 3+ lines); savings priced only from recorded licence and contract costs.' % (len(prev), len(exe))}}


OPS = {'cost.studio': op_studio}
