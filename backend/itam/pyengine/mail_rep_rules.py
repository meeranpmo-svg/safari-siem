# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Mail server reputation against Spamhaus (engine/mail-reputation.js does the DNS queries; this module decides).

Python decides, Node.js commits. Standard library only.

  mailrep.targets {domains, manual, provider_ok}   which public IPs and domains to check: the MX hosts' addresses (inbound),
                                                    the ip4 entries of each domain's SPF record (outbound senders), the IPs an
                                                    operator registered, and each mail domain itself (Spamhaus DBL)
  mailrep.assess  {lookups, targets, prev, now, dqs}  what each answer means, findings, what changed since the last run

Spamhaus answers with 127.0.0.x (ZEN) / 127.0.1.x (DBL) when a target is listed and NXDOMAIN when it is not. 127.255.255.x
means Spamhaus refused the query (public resolver, over the free-use limit, or a bad DQS key): that is reported as
"not checked", never as clean.
"""
import ipaddress
import re
from datetime import datetime, timezone

ZEN = {
    '127.0.0.2': ('SBL', 'Spamhaus Block List - a known spam source or spam operation', 'high'),
    '127.0.0.3': ('CSS', 'Spamhaus CSS - this IP sent low-reputation / snowshoe spam', 'high'),
    '127.0.0.4': ('XBL', 'Exploits Block List - the IP shows signs of an infected machine, open proxy or exploited host', 'critical'),
    '127.0.0.5': ('XBL', 'Exploits Block List', 'critical'), '127.0.0.6': ('XBL', 'Exploits Block List', 'critical'), '127.0.0.7': ('XBL', 'Exploits Block List', 'critical'),
    '127.0.0.9': ('DROP', 'Spamhaus DROP - the range is hijacked or run by criminals', 'critical'),
    '127.0.0.10': ('PBL', 'Policy Block List (ISP) - the range should not send mail directly to the internet', 'medium'),
    '127.0.0.11': ('PBL', 'Policy Block List (Spamhaus) - the range should not send mail directly to the internet', 'medium'),
}
DBL = {
    '127.0.1.2': ('DBL spam', 'the domain appears in spam', 'high'), '127.0.1.4': ('DBL phish', 'the domain is used for phishing', 'critical'),
    '127.0.1.5': ('DBL malware', 'the domain is used to spread malware', 'critical'), '127.0.1.6': ('DBL botnet', 'the domain is a botnet command-and-control', 'critical'),
    '127.0.1.102': ('DBL abused-legit spam', 'a legitimate domain abused for spam (compromised site or account)', 'high'),
    '127.0.1.103': ('DBL abused-legit redirector', 'a legitimate domain abused as a spam redirector', 'high'),
    '127.0.1.104': ('DBL abused-legit phish', 'a legitimate domain abused for phishing (compromised)', 'critical'),
    '127.0.1.105': ('DBL abused-legit malware', 'a legitimate domain abused to spread malware (compromised)', 'critical'),
    '127.0.1.106': ('DBL abused-legit botnet', 'a legitimate domain abused for botnet C&C (compromised)', 'critical'),
}
REFUSED = {'127.255.255.252': 'the query was malformed (typing error in the zone)', '127.255.255.254': 'Spamhaus refuses queries through public / open resolvers (8.8.8.8, 1.1.1.1 …)',
           '127.255.255.255': 'over the free-use limit or the DQS key is not valid', '127.0.1.255': 'Spamhaus refused the DBL query (bad zone or excessive queries)'}
# hosts that belong to a mail provider: their reputation is the provider's to manage
PROVIDERS = [(r'\.mail\.protection\.outlook\.com$', 'Microsoft 365 / Exchange Online Protection'), (r'(^|\.)google\.com$|googlemail\.com$', 'Google Workspace'),
             (r'\.mimecast\.com$', 'Mimecast'), (r'\.pphosted\.com$', 'Proofpoint'), (r'\.barracudanetworks\.com$', 'Barracuda'), (r'\.messagelabs\.com$', 'Broadcom / Symantec'),
             (r'\.iphmx\.com$', 'Cisco Secure Email'), (r'\.trendmicro\.(com|eu)$', 'Trend Micro'), (r'\.sophos\.com$', 'Sophos'), (r'\.kaspersky', 'Kaspersky')]
MAX_RANGE = 16   # an SPF ip4 range larger than /28 is not expanded (it is a provider block, not our servers)
SEV = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def _provider(host):
    h = str(host or '').lower().rstrip('.')
    for rx, name in PROVIDERS:
        if re.search(rx, h):
            return name
    return None


TEST_NETS = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]


def _public(ip, test=False):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # tests use the documentation ranges (RFC 5737) as synthetic "public" addresses; production never does
    return a.version == 4 and (a.is_global or (test and any(a in n for n in TEST_NETS)))


def targets(req):
    """Which IPs and domains to look up. Only public IPv4 is checked (DNSBLs are IPv4; private addresses are meaningless)."""
    out, notes, seen, test = [], [], {}, bool(req.get('test_nets'))

    def add(ip, role, source, provider=None, label=None):
        if not _public(ip, test):
            notes.append('%s (%s) is not a public IPv4 address - not checked' % (ip, source))
            return
        t = seen.get(ip)
        if t:
            if role not in t['roles']:
                t['roles'].append(role)
            if source not in t['sources']:
                t['sources'].append(source)
            t['provider'] = t['provider'] or provider
            return
        seen[ip] = {'kind': 'ip', 'target': ip, 'roles': [role], 'sources': [source], 'provider': provider, 'label': label}
        out.append(seen[ip])

    for d in req.get('domains') or []:
        name = str(d.get('name') or '').lower()
        if not name:
            continue
        for mx in d.get('mx') or []:
            prov = _provider(mx.get('host'))
            for ip in mx.get('ips') or []:
                add(ip, 'inbound', 'MX ' + str(mx.get('host')) + ' (' + name + ')', prov)
        for spf in d.get('spf') or []:
            for tok in str(spf).split():
                m = re.match(r'^[+]?ip4:([0-9.]+)(?:/(\d{1,2}))?$', tok, re.I)
                if not m:
                    continue
                try:
                    net = ipaddress.ip_network(m.group(1) + '/' + (m.group(2) or '32'), strict=False)
                except ValueError:
                    notes.append('SPF of %s has an invalid entry %s' % (name, tok))
                    continue
                if net.num_addresses > MAX_RANGE:
                    notes.append('SPF of %s allows %s (%d addresses) - a range that large is not expanded; register the actual sending IPs' % (name, tok, net.num_addresses))
                    continue
                for ip in (net.hosts() if net.num_addresses > 2 else [net.network_address] if net.num_addresses == 1 else net):
                    add(str(ip), 'outbound', 'SPF of ' + name)
            if re.search(r'include:spf\.protection\.outlook\.com', str(spf), re.I):
                notes.append('%s sends through Microsoft 365: its outbound IPs are shared and managed by Microsoft (check the tenant in the Defender portal, Restricted entities)' % name)
        if d.get('mx') or d.get('spf'):
            out.append({'kind': 'domain', 'target': name, 'roles': ['mail domain'], 'sources': ['Domains & Hosting'], 'provider': None, 'label': None})
    for m in req.get('manual') or []:
        add(m.get('ip'), m.get('role') or 'outbound', 'registered: ' + str(m.get('label') or m.get('id')), None, m.get('label'))
    return {'targets': out, 'notes': notes}


def _classify(lk):
    ans, err = lk.get('answers') or [], lk.get('error')
    table = DBL if lk.get('kind') == 'domain' else ZEN
    if err and err not in ('ENOTFOUND', 'ENODATA'):
        return {'state': 'not_checked', 'why': 'DNS error ' + str(err)}
    refused = [REFUSED[a] for a in ans if a in REFUSED]
    if refused:
        return {'state': 'not_checked', 'why': refused[0]}
    if not ans:
        return {'state': 'clean', 'why': 'not listed'}
    lists = []
    for a in ans:
        x = table.get(a)
        lists.append({'code': a, 'list': x[0], 'meaning': x[1], 'severity': x[2]} if x else {'code': a, 'list': 'unknown', 'meaning': 'unrecognised return code', 'severity': 'medium'})
    return {'state': 'listed', 'lists': lists, 'severity': max((l['severity'] for l in lists), key=lambda s: SEV[s])}


def _advice(t, c):
    names = {l['list'] for l in c.get('lists') or []}
    if t['kind'] == 'domain':
        return ['Find how the domain is being abused (compromised website, mailbox or DNS record) and fix it first',
                'Then request removal at https://check.spamhaus.org/ (domain lookup)', 'Treat phishing / malware listings as a security incident: open a SIEM case']
    if t.get('provider'):
        return ['This address belongs to %s: ask the provider to resolve it (open a support case quoting the Spamhaus listing)' % t['provider']]
    steps = []
    if names & {'XBL'}:
        steps.append('Treat as a possible compromise: the IP shows infected-host or proxy activity - find the machine behind this public IP (firewall NAT logs) and open a SIEM case')
    if names & {'SBL', 'CSS', 'DROP'}:
        steps.append('Stop the spam at the source: check the mail queue, outbound volume per mailbox and compromised accounts (Exchange / Defender) before asking for removal')
    if 'PBL' in names:
        steps.append('The IP is in a range marked "should not send mail directly": if it is a static IP of a real mail server, ask the ISP (or Spamhaus for 127.0.0.11) to remove it from the PBL, and make sure reverse DNS names the server')
    steps.append('After fixing the cause, request removal at https://check.spamhaus.org/ and re-check here')
    if 'outbound' in t['roles']:
        steps.append('Until it is delisted, mail from this IP is being rejected or junked by receivers that use Spamhaus')
    return steps


def assess(req):
    tg = {t['target']: t for t in (req.get('targets') or [])}
    prev = req.get('prev') or {}
    now = req.get('now') or 0
    rows, findings, changes = [], [], []
    for lk in req.get('lookups') or []:
        t = tg.get(lk.get('target'))
        if not t:
            continue
        c = _classify(lk)
        row = dict(t, state=c['state'], why=c.get('why'), lists=c.get('lists') or [], severity=c.get('severity'), zone=lk.get('zone'))
        row['advice'] = _advice(t, c) if c['state'] == 'listed' else []
        was = (prev.get(t['target']) or {}).get('state')
        if was and was != c['state'] and c['state'] != 'not_checked':
            changes.append({'target': t['target'], 'from': was, 'to': c['state']})
            row['changed'] = was
        rows.append(row)
        if c['state'] == 'listed':
            sev = c['severity'] if not t.get('provider') else 'medium'
            findings.append({'key': 'mailrep:' + t['target'], 'severity': sev,
                             'title': ('Mail domain ' if t['kind'] == 'domain' else 'Mail server IP ') + t['target'] + ' is listed on Spamhaus ' + ', '.join(sorted({l['list'] for l in c['lists']})) + (' (' + t['provider'] + ')' if t.get('provider') else ''),
                             'evidence': [l['code'] + ' ' + l['meaning'] for l in c['lists']] + ['roles: ' + ', '.join(t['roles']), 'source: ' + '; '.join(t['sources'])],
                             'recommendation': row['advice'][0]})
    rows.sort(key=lambda r: (r['state'] != 'listed', -SEV.get(r.get('severity') or 'info', 0), r['state'] != 'not_checked', r['kind'], r['target']))
    counts = {k: sum(1 for r in rows if r['state'] == k) for k in ('listed', 'clean', 'not_checked')}
    nc = [r for r in rows if r['state'] == 'not_checked']
    warn = None
    if nc and len(nc) == len(rows):
        warn = 'Nothing could be checked: ' + nc[0]['why'] + '. ' + ('Check the DQS key.' if req.get('dqs') else 'Spamhaus does not answer public resolvers and asks commercial users to use the free Data Query Service (DQS): an administrator adds the DQS key.')
    return {'rows': rows, 'findings': findings, 'changes': changes, 'counts': counts, 'warning': warn,
            'checked_at': datetime.fromtimestamp(now / 1000, tz=timezone.utc).isoformat().replace('+00:00', 'Z') if now else None}


OPS = {'mailrep.targets': targets, 'mailrep.assess': assess}
