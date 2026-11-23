# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""CMDB Studio (engine/cmdb-studio.js): machine learning over the configuration items and their relationships. Standard library
only; every figure comes from the asset register, its relationships, what Asset Discovery saw (LLDP / CDP neighbours) and the
decisions people made - never from an assumption.

  quality       per CI, the fields its type should carry (owner, site, serial, OS, management IP, vendor / model); missing ones
                are named, the register's quality is the mean
  duplicates    pairs that look like one device: the same serial or MAC (certain), the same management IP on two active CIs
                (likely), or near-identical names of the same type at the same site (character-trigram Jaccard >= 0.85)
  proposals     relationships the evidence supports and nobody has recorded:
                  - neighbours  an LLDP / CDP neighbour Asset Discovery saw that matches a CI exactly -> connected_to (0.9)
                  - learned     peers: when most CIs of a type in the same /24 are connected to one device, a CI of that type in
                                that /24 without the link is proposed with the observed share as its confidence (k-NN style,
                                from confirmed relationships only, at least 3 peers)
                  - gateway     a network device on .1 / .254 of a /24 where servers live -> connected_to (0.45, says so)
                a key dismissed or rejected by a person is never proposed again
  impact        blast radius per CI: what fails with it, following depends_on / runs_on / installed_on backwards (BFS, depth 6);
                single points of failure = CIs whose loss reaches the most others
  orphans       active servers, VMs, network and storage CIs with no relationship at all
  anomalies     a runs_on / installed_on whose target cannot host anything (a printer, a phone), dependency cycles

Proposals are proposals: a person confirms one (it becomes a confirmed relationship) or dismisses it with a reason.
"""
import re

EXPECT = {
    'server': ['owner', 'site', 'serial', 'os', 'mgmt_ip', 'vendor', 'model'],
    'vm': ['owner', 'site', 'os', 'mgmt_ip'],
    'network': ['owner', 'site', 'serial', 'mgmt_ip', 'vendor', 'model'],
    'storage': ['owner', 'site', 'serial', 'mgmt_ip', 'vendor', 'model'],
    'workstation': ['owner', 'site', 'serial', 'os'],
    'laptop': ['owner', 'site', 'serial', 'os'],
    'printer': ['site', 'serial', 'mgmt_ip', 'vendor', 'model'],
    'phone': ['owner', 'site', 'serial'],
    'ups': ['site', 'serial', 'vendor', 'model'],
}
DEFAULT_EXPECT = ['owner', 'site']
HOSTS = {'server', 'vm', 'storage', 'network', 'other'}
CORE = {'server', 'vm', 'network', 'storage'}
DEP = {'depends_on', 'runs_on', 'installed_on'}
ACTIVE = {'in_use', 'in_stock', 'in_repair'}
LABEL = {'owner': 'owner', 'site': 'site', 'serial': 'serial number', 'os': 'operating system', 'mgmt_ip': 'management IP',
         'vendor': 'vendor', 'model': 'model'}
IP_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def net24(ip):
    m = IP_RE.match(str(ip or ''))
    return '.'.join(m.groups()[:3]) if m else None


def last_octet(ip):
    m = IP_RE.match(str(ip or ''))
    return int(m.group(4)) if m else None


def norm_name(s):
    return re.sub(r'[^a-z0-9]', '', str(s or '').lower().split('.')[0])


def trigrams(s):
    s = '  ' + s + ' '
    return {s[i:i + 3] for i in range(len(s) - 2)}


def jaccard(a, b):
    return len(a & b) / float(len(a | b)) if a and b else 0.0


def rel_key(frm, to, t):
    if t == 'connected_to':
        a, b = sorted([frm, to])
        return '%s|%s|%s' % (t, a, b)
    return '%s|%s|%s' % (t, frm, to)


def quality(a):
    want = EXPECT.get(a.get('type'), DEFAULT_EXPECT)
    missing = [f for f in want if not a.get(f)]
    score = int(round(100.0 * (len(want) - len(missing)) / len(want))) if want else 100
    return score, missing


def op_analyse(req):
    assets = [a for a in (req.get('assets') or []) if isinstance(a, dict) and a.get('id')]
    rels = [r for r in (req.get('relationships') or []) if isinstance(r, dict) and r.get('from') and r.get('to')]
    devices = [d for d in (req.get('devices') or []) if isinstance(d, dict)]
    blocked = set(req.get('blocked') or [])
    focus = req.get('focus')
    by = {a['id']: a for a in assets}
    active = [a for a in assets if a.get('status', 'in_use') in ACTIVE]
    existing = {rel_key(r['from'], r['to'], r.get('type')) for r in rels}

    # ---- quality
    q = []
    for a in active:
        sc, miss = quality(a)
        q.append({'id': a['id'], 'name': a.get('name'), 'type': a.get('type'), 'score': sc, 'missing': [LABEL.get(m, m) for m in miss]})
    qmean = int(round(sum(x['score'] for x in q) / float(len(q)))) if q else None

    # ---- duplicates
    dups, seen_pairs = [], set()

    def dup(a, b, conf, why):
        k = tuple(sorted([a['id'], b['id']]))
        if k in seen_pairs:
            return
        seen_pairs.add(k)
        dups.append({'a': {'id': a['id'], 'name': a.get('name'), 'type': a.get('type')}, 'b': {'id': b['id'], 'name': b.get('name'), 'type': b.get('type')}, 'confidence': conf, 'why': why})
    for field, conf, why in (('serial', 0.99, 'same serial number'), ('mac', 0.97, 'same MAC address'), ('mgmt_ip', 0.8, 'same management IP')):
        idx = {}
        for a in active:
            v = str(a.get(field) or '').strip().lower()
            if v and v not in ('unknown', 'n/a', 'none', '0', 'to be filled by o.e.m.', 'default string'):
                idx.setdefault(v, []).append(a)
        for v, group in idx.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    dup(group[i], group[j], conf, '%s (%s)' % (why, v))
    grams = [(a, trigrams(norm_name(a.get('name')))) for a in active if len(norm_name(a.get('name'))) >= 4]
    for i in range(len(grams)):
        for j in range(i + 1, len(grams)):
            a, ga = grams[i]
            b, gb = grams[j]
            if a.get('type') != b.get('type') or (a.get('site') or '') != (b.get('site') or ''):
                continue
            sim = jaccard(ga, gb)
            if sim >= 0.85:
                dup(a, b, round(0.5 + 0.3 * sim, 2), 'names %.0f%% alike, same type and site' % (100 * sim))
        if len(dups) > 300:
            break
    dups.sort(key=lambda x: -x['confidence'])

    # ---- proposals
    props = {}

    def propose(frm, to, t, conf, kind, why):
        if frm == to or frm not in by or to not in by:
            return
        k = rel_key(frm, to, t)
        if k in existing or k in blocked:
            return
        cur = props.get(k)
        if cur and cur['confidence'] >= conf:
            return
        props[k] = {'key': k, 'from': frm, 'to': to, 'type': t, 'confidence': round(conf, 2), 'kind': kind, 'why': why,
                    'from_name': by[frm].get('name'), 'to_name': by[to].get('name')}
    # neighbours seen by discovery (exact matches only)
    ip_ix, mac_ix, name_ix = {}, {}, {}
    for a in active:
        if a.get('mgmt_ip'):
            ip_ix[a['mgmt_ip']] = a['id']
        if a.get('mac'):
            mac_ix[str(a['mac']).lower()] = a['id']
        if norm_name(a.get('name')):
            name_ix.setdefault(norm_name(a.get('name')), []).append(a['id'])
    for d in devices:
        src = d.get('asset_id')
        if src not in by:
            continue
        for nb in d.get('neighbours') or []:
            peer = ip_ix.get(nb.get('remote_ip')) or mac_ix.get(str(nb.get('remote_mac') or '').lower())
            if not peer:
                cands = name_ix.get(norm_name(nb.get('remote_name')), [])
                peer = cands[0] if len(cands) == 1 else None
            if peer:
                propose(src, peer, 'connected_to', 0.9, 'neighbours', '%s neighbour of %s%s' % (str(nb.get('via') or 'LLDP').upper(), by[src].get('name'),
                        (' on port ' + str(nb.get('local_port'))) if nb.get('local_port') else ''))
    # learned from confirmed links: CIs of one type in one /24 mostly linked to one device - a peer without that link gets it
    # proposed. connected_to learns the switch (target type network); runs_on learns the host (target type server)
    conf_links = {}
    for r in rels:
        if r.get('status') != 'confirmed':
            continue
        if r.get('type') == 'connected_to':
            for x, y in ((r['from'], r['to']), (r['to'], r['from'])):
                conf_links.setdefault(('connected_to', x), set()).add(y)
        elif r.get('type') == 'runs_on':
            conf_links.setdefault(('runs_on', r['from']), set()).add(r['to'])
    groups = {}
    for a in active:
        n = net24(a.get('mgmt_ip'))
        if n and a.get('type') in ('server', 'vm', 'workstation', 'printer', 'storage', 'phone'):
            groups.setdefault((n, a.get('type')), []).append(a['id'])
    LEARN = (('connected_to', 'network', 'connected to'), ('runs_on', 'server', 'running on'))
    for (n, t), ids in groups.items():
        for rt, target_type, verb in LEARN:
            if rt == 'runs_on' and t != 'vm':
                continue
            has = lambda i: set(y for y in conf_links.get((rt, i), set()) if (by.get(y) or {}).get('type') == target_type)
            linked = [i for i in ids if has(i)]
            if len(linked) < 2:
                continue
            counts = {}
            for i in linked:
                for y in has(i):
                    counts[y] = counts.get(y, 0) + 1
            for dev, c in counts.items():
                share = c / float(len(linked))
                if share < 0.6 or dev in ids:
                    continue
                conf = round(0.45 + 0.45 * share * min(1.0, len(linked) / 3.0), 2)
                for i in ids:
                    if not has(i):
                        propose(i, dev, rt, conf, 'learned', '%d of %d %s CIs in %s.0/24 are %s %s (confirmed)' % (c, len(linked), t, n, verb, by[dev].get('name')))
    # likely gateway (weak, said)
    servers_by_net = {}
    for a in active:
        n = net24(a.get('mgmt_ip'))
        if n and a.get('type') in ('server', 'vm'):
            servers_by_net.setdefault(n, []).append(a['id'])
    for a in active:
        if a.get('type') == 'network' and last_octet(a.get('mgmt_ip')) in (1, 254):
            for sid in servers_by_net.get(net24(a.get('mgmt_ip')), [])[:50]:
                if not conf_links.get(('connected_to', sid)):
                    propose(sid, a['id'], 'connected_to', 0.45, 'gateway', '%s is .%d of the same /24 - likely its gateway (check before confirming)'
                            % (a.get('name'), last_octet(a.get('mgmt_ip'))))
    proposals = sorted(props.values(), key=lambda x: -x['confidence'])

    # ---- impact: who fails with a CI (edges point from the dependent to what it needs)
    needs_me = {}
    for r in rels:
        if r.get('type') in DEP:
            needs_me.setdefault(r['to'], set()).add(r['from'])

    def blast(cid, depth=6):
        seen, frontier, layers = {cid}, [cid], []
        for _ in range(depth):
            nxt = []
            for c in frontier:
                for d in needs_me.get(c, ()):
                    if d not in seen:
                        seen.add(d)
                        nxt.append(d)
            if not nxt:
                break
            layers.append(nxt)
            frontier = nxt
        return layers
    spof = []
    for cid in needs_me:
        if cid not in by:
            continue
        layers = blast(cid)
        n = sum(len(l) for l in layers)
        if n:
            spof.append({'id': cid, 'name': by[cid].get('name'), 'type': by[cid].get('type'), 'impacted': n, 'depth': len(layers)})
    spof.sort(key=lambda x: -x['impacted'])

    # ---- orphans and anomalies
    linked_ids = set()
    for r in rels:
        linked_ids.add(r['from'])
        linked_ids.add(r['to'])
    orphans = [{'id': a['id'], 'name': a.get('name'), 'type': a.get('type')} for a in active if a.get('type') in CORE and a['id'] not in linked_ids]
    anomalies = []
    for r in rels:
        if r.get('type') in ('runs_on', 'installed_on'):
            tgt = by.get(r['to'])
            if tgt and tgt.get('type') not in HOSTS:
                anomalies.append({'rel': r.get('id'), 'text': '%s %s %s, which is a %s and cannot host anything' % ((by.get(r['from']) or {}).get('name'), r['type'].replace('_', ' '), tgt.get('name'), tgt.get('type'))})
    # dependency cycles (DFS)
    out_edges = {}
    for r in rels:
        if r.get('type') in DEP:
            out_edges.setdefault(r['from'], []).append(r['to'])
    color, cycles = {}, []

    def dfs(u, path):
        color[u] = 1
        path.append(u)
        for v in out_edges.get(u, []):
            if color.get(v) == 1 and len(cycles) < 10:
                cyc = path[path.index(v):] + [v]
                cycles.append(' -> '.join((by.get(x) or {}).get('name') or x for x in cyc))
            elif not color.get(v):
                dfs(v, path)
        path.pop()
        color[u] = 2
    for u in list(out_edges):
        if not color.get(u):
            dfs(u, [])
    for c in cycles:
        anomalies.append({'rel': None, 'text': 'dependency cycle: ' + c})

    # per CI type: how complete, how many CIs others fail with (3+), how many have no relationship (team page, the KPIs)
    types = []
    for t in sorted({a.get('type') or 'other' for a in active}):
        sc = [x['score'] for x in q if (x.get('type') or 'other') == t]
        types.append({'type': t, 'cis': len(sc), 'quality_pct': int(round(sum(sc) / float(len(sc)))) if sc else None,
                      'spof': len([x for x in spof if (x.get('type') or 'other') == t and x['impacted'] >= 3]),
                      'orphans': len([x for x in orphans if (x.get('type') or 'other') == t])})
    res = {'ok': True,
           'summary': {'cis': len(active), 'relationships': len(rels), 'confirmed': len([r for r in rels if r.get('status') == 'confirmed']),
                       'proposed': len([r for r in rels if r.get('status') == 'proposed']), 'quality_pct': qmean, 'orphans': len(orphans),
                       'duplicates': len(dups), 'proposals': len(proposals), 'spof': len([s for s in spof if s['impacted'] >= 3]),
                       'types': types,
                       'by_type': {t: len([a for a in active if a.get('type') == t]) for t in sorted({a.get('type') or 'other' for a in active})}},
           'quality': sorted(q, key=lambda x: x['score'])[:200], 'duplicates': dups[:100], 'proposals': proposals[:200],
           'spof': spof[:30], 'orphans': orphans[:200], 'anomalies': anomalies[:50],
           'learned': {'note': 'Learned from this register: %d confirmed relationship(s), %d discovery neighbour record(s), %d person decision(s).'
                       % (len([r for r in rels if r.get('status') == 'confirmed']), sum(len(d.get('neighbours') or []) for d in devices), len(blocked))}}
    if focus and focus in by:
        res['impact'] = {'id': focus, 'layers': [[{'id': x, 'name': by[x].get('name'), 'type': by[x].get('type')} for x in l] for l in blast(focus)]}
    return res


OPS = {'cmdb.analyse': op_analyse}
