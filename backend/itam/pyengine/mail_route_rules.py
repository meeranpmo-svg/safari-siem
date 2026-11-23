# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Mail route flow (Email Security page): the receiving and sending path hop by hop, what is wrong at each hop and how
to fix it. engine/mail-reputation.js gathers the DNS facts (MX, SMTP banner / STARTTLS, SPF tree, DKIM, DMARC, MTA-STS,
TLS-RPT, egress reverse DNS) and the page passes the SIEM's mail-flow counts (gateway and Exchange message tracking);
this module decides. Standard library only.

  mailroute.assess {facts, siem, profile, reputation}  -> lanes (inbound / outbound hops) and issues with fixes

Inbound:  Internet -> MX (DNS) -> MX hosts (SMTP, TLS) -> email gateway -> Exchange (receive) -> mailbox (deliver)
Outbound: mailbox (submit) -> Exchange (send) -> email gateway -> egress IP (rDNS, SPF, Spamhaus) -> Internet (DKIM, DMARC)
A hop with no data is "not connected" / "not checked", never healthy.
"""
import ipaddress
import re

SEV = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
# Cloudflare's published proxy ranges (https://www.cloudflare.com/ips-v4): an MX host resolving here is proxied (orange
# cloud) - Cloudflare does not carry SMTP, so inbound mail to it fails
CLOUDFLARE = [ipaddress.ip_network(n) for n in ('173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
              '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22')]


def _cf(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CLOUDFLARE)
# enhanced status codes seen in Exchange recipient-status (fail / defer) and what to do about each
SMTP_CODES = [
    (r'5\.1\.1|5\.1\.10|recipient not found|user unknown|does not exist', 'Recipient address does not exist', 'medium',
     ['Check the address with the sender; for internal recipients confirm the mailbox / contact exists and the accepted domain is right']),
    (r'5\.7\.(23|25|26|27)|spf|dmarc', 'Rejected for SPF / DKIM / DMARC (authentication)', 'high',
     ['Make sure every server that sends for the domain is in SPF and signs with DKIM (see the outbound hops)', 'Read the DMARC aggregate reports to find the failing source']),
    (r'5\.7\.(606|607|608|708|750)|banned sending ip|ip .* blocked|block list|blocklist|spamhaus|listed', 'Our sending IP is blocked by the receiver', 'high',
     ['Check the egress IP on Spamhaus (Mail server reputation card) and with the receiver\'s own portal', 'Fix the cause (compromised account, open relay) and request delisting']),
    (r'5\.7\.1\b|relay (access )?denied|unable to relay|not permitted to relay', 'Relay denied', 'high',
     ['Inbound: the receive connector does not accept the domain - add it as an accepted domain or allow the gateway IP on the connector', 'Outbound: send through the smart host / connector that is allowed to relay']),
    (r'5\.4\.1\b', 'Recipient address rejected: access denied (directory-based edge blocking)', 'medium',
     ['Exchange Online rejects recipients it does not know: check the recipient exists in Entra ID / the accepted domain type (authoritative vs internal relay)']),
    (r'5\.7\.57|client was not authenticated|smtp auth', 'Client not authenticated to send', 'medium',
     ['The application / device must authenticate (SMTP AUTH or an authenticated relay connector); check the connector and credentials']),
    (r'5\.2\.2|mailbox full|quota', 'Recipient mailbox full', 'low', ['The recipient must clear space or raise the quota']),
    (r'5\.3\.4|5\.2\.3|message size|too large', 'Message too large', 'low', ['Check the size limits on the connectors, the gateway and the receiving organisation']),
    (r'4\.4\.(1|2|7)|5\.4\.7|timed out|timeout|connection (refused|dropped|lost)|unreachable', 'Could not connect / timed out to the next hop', 'high',
     ['Check the route to the next hop: DNS of the target, firewall rules for TCP 25 from the gateway / Exchange, and whether the target is up', 'Messages expire after the retry period (4.4.7)']),
    (r'4\.4\.(3|4)|5\.4\.4|dns|no mx|host not found', 'DNS failure resolving the destination', 'high',
     ['Check the DNS servers the transport uses, and the destination domain\'s MX record']),
    (r'4\.7\.0|tls|starttls|certificate', 'TLS negotiation problem', 'medium',
     ['Check the connector TLS settings and certificate (expiry, name, chain) on both sides; a forced-TLS partner refuses plain text']),
    (r'4\.2\.|4\.3\.|greylist|try again later|temporar', 'Temporary refusal by the receiver (greylisting / load)', 'low', ['Usually resolves on retry; investigate if the same destination keeps deferring']),
]


def _code(status):
    s = str(status or '').lower()
    for rx, title, sev, fix in SMTP_CODES:
        if re.search(rx, s):
            return title, sev, fix
    return 'Other delivery failure', 'medium', ['Open the message trace for the full NDR text']


def _n(x):
    try:
        return int(x or 0)
    except (TypeError, ValueError):
        return 0


def _spf_eval(node, ip, depth=0):
    """Does the SPF tree authorise ip? Only ip4 and resolved a / mx addresses are evaluated (no macros)."""
    if not node or depth > 10:
        return False
    for tok in str(node.get('record') or '').split():
        if re.match(r'^[+~?-]?all$', tok, re.I):
            break   # RFC 7208: nothing after "all" is read - an ip4 added after -all authorises nothing
        m = re.match(r'^[+]?ip4:([0-9.]+(?:/\d{1,2})?)$', tok, re.I)
        if m:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(m.group(1), strict=False):
                    return True
            except ValueError:
                pass
    if ip in (node.get('a_ips') or []) or ip in (node.get('mx_ips') or []):
        return True
    return any(_spf_eval(ch, ip, depth + 1) for ch in (node.get('children') or {}).values())


def _spf_lookups(node, depth=0):
    if not node or depth > 12:
        return 0
    n = sum(1 for tok in str(node.get('record') or '').split() if re.match(r'^[+~?-]?(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)', tok, re.I))
    return n + sum(_spf_lookups(ch, depth + 1) for ch in (node.get('children') or {}).values())


def _ptr_generic(name):
    return bool(re.search(r'(\d{1,3}[-.]){3}\d{1,3}|dynamic|dyn\b|dsl|dhcp|pool|client|ppp|cable|static-ip|broadband', str(name or ''), re.I))


def assess(req):
    facts, siem, prof = req.get('facts') or {}, req.get('siem'), req.get('profile') or {}
    rep = {r.get('target'): r for r in (req.get('reputation') or [])}
    issues = []

    def issue(sev, hop, title, evidence, fix):
        issues.append({'severity': sev, 'hop': hop, 'title': title, 'evidence': evidence if isinstance(evidence, list) else [evidence], 'fix': fix})

    doms = facts.get('domains') or []
    expected = [str(x).lower().rstrip('.') for x in prof.get('expected_mx') or []]
    # ---- inbound: MX
    mx_state, mx_hosts = 'ok', []
    if not doms:
        mx_state = 'not_checked'
    for d in doms:
        name, mx = d.get('name'), d.get('mx') or []
        if d.get('mx_error'):
            if str(d['mx_error']).startswith('not checked yet'):
                issue('medium', 'mx', '%s: MX %s' % (name, d['mx_error']), 'no DNS check yet', ['Domains & Hosting -> Check now; the map fills in after the check'])
                mx_state = mx_state if mx_state == 'bad' else 'not_checked'
                continue
            issue('high', 'mx', '%s: MX could not be read from the platform server (%s)' % (name, d['mx_error']), 'DNS lookup from this server failed',
                  ['This is the platform server\'s lookup failing - if MX Toolbox shows the MX record, mail to the domain is fine',
                   'Allow outbound DNS (UDP/TCP 53) from the platform server to public resolvers (1.1.1.1, 8.8.8.8), or fix its resolver\'s forwarders',
                   'Then Domains & Hosting -> Check now'])
            mx_state = 'bad'
            continue
        if not mx:
            if d.get('receives', True):
                issue('high', 'mx', '%s has no MX record - it cannot receive e-mail' % name, 'no MX in DNS', ['Publish MX records pointing to the email gateway (or Exchange Online Protection)'])
                mx_state = 'bad'
            continue
        for m in mx:
            mx_hosts.append(dict(m, domain=name))
            if not m.get('ips'):
                issue('high', 'mx', 'MX host %s (%s) does not resolve to an address' % (m.get('host'), name), 'no A record', ['Fix the A record of the MX host, or remove the MX entry'])
                mx_state = 'bad'
        if len(mx) == 1 and not re.search(r'protection\.outlook\.com|mimecast|pphosted|google', str(mx[0].get('host')), re.I):
            issue('low', 'mx', '%s has a single MX host' % name, mx[0].get('host'), ['Add a second MX (secondary gateway node) so mail queues at the sender, not lost, during maintenance'])
            mx_state = mx_state if mx_state == 'bad' else 'warn'
        if expected:
            off = [m.get('host') for m in mx if not any(str(m.get('host')).lower().rstrip('.').endswith(e) for e in expected)]
            if off:
                issue('high', 'mx', '%s: MX points to a host that is not the email gateway - mail can bypass filtering' % name, off,
                      ['Point every MX at the gateway (%s)' % ', '.join(expected), 'Lock the Exchange receive connector to accept Internet mail only from the gateway IPs'])
                mx_state = 'bad'
        prio = {}
        for m in mx:
            prio.setdefault(m.get('priority'), []).append(m.get('host'))
    # ---- DNS hosting (Cloudflare), hybrid readiness, ISP links
    platform = prof.get('platform') or 'onprem'
    for d in doms:
        name, mx = d.get('name'), d.get('mx') or []
        on_cf = any('cloudflare' in str(n).lower() for n in d.get('ns') or [])
        for m in mx:
            host = str(m.get('host') or '').lower()
            if re.search(r'mx\.cloudflare\.net$', host):
                issue('critical', 'mx', '%s: MX points to Cloudflare Email Routing (%s) - mail does not reach Exchange' % (name, host), 'Cloudflare Email Routing replaces the MX records',
                      ['Disable Email Routing in the Cloudflare dashboard (Email > Email Routing) and restore the MX records to the gateway / Exchange'])
                mx_state = 'bad'
            elif any(_cf(ip) for ip in m.get('ips') or []):
                issue('critical', 'mx', '%s: MX host %s resolves to a Cloudflare proxy address - SMTP is not carried by the proxy' % (name, host), ', '.join(m.get('ips') or []),
                      ['In Cloudflare DNS set the A record of %s to "DNS only" (grey cloud) so it points to the real public IP of the gateway' % host])
                mx_state = 'bad'
        ad = d.get('autodiscover') or {}
        if platform in ('onprem', 'hybrid'):
            if not ad.get('ips') and not ad.get('cname'):
                issue('medium', 'smtp', '%s: no autodiscover record - Outlook clients and the hybrid configuration cannot find Exchange' % name, 'autodiscover.%s does not resolve' % name,
                      ['Publish autodiscover.%s (A to the Exchange / reverse-proxy public IP, or CNAME to the mail host name)' % name])
            elif any(_cf(ip) for ip in ad.get('ips') or []):
                issue('high', 'smtp', '%s: autodiscover is proxied by Cloudflare' % name, ', '.join(ad.get('ips') or []),
                      ['Set autodiscover (and the EWS / OWA host name) to "DNS only" in Cloudflare: Exchange hybrid needs Office 365 to reach Autodiscover and EWS directly, without proxy pre-authentication or a different certificate'])
        if on_cf:
            issue('info', 'mx', '%s: DNS is hosted at Cloudflare' % name, ', '.join(d.get('ns') or [])[:200],
                  ['Keep MX, the mail host names, autodiscover, SPF, DKIM and DMARC records "DNS only" (grey cloud)', 'Leave Cloudflare Email Routing off while Exchange receives the mail',
                   'Protect the Cloudflare account with MFA and restricted API tokens - whoever controls DNS controls where mail goes'])
        if platform in ('hybrid', 'online'):
            spf_txt = ' '.join(str(n.get('record') or '') for n in [d.get('spf') or {}])
            if d.get('spf') and 'spf.protection.outlook.com' not in spf_txt.lower():
                issue('high', 'auth', '%s: SPF does not include Microsoft 365 (include:spf.protection.outlook.com)' % name, spf_txt[:200],
                      ['Add include:spf.protection.outlook.com to the SPF record - mail sent from Exchange Online mailboxes will otherwise fail SPF'])
            ms = d.get('dkim_ms') or {}
            bad = [s for s in ('selector1', 'selector2') if not re.search(r'onmicrosoft\.com\.?$', str(ms.get(s) or ''), re.I)]
            if bad:
                issue('medium', 'auth', '%s: Microsoft 365 DKIM selectors not published (%s)' % (name, ', '.join(bad)), 'CNAME selector1._domainkey / selector2._domainkey',
                      ['Publish the two CNAMEs shown in Defender (Email authentication > DKIM) pointing to <selector>-<domain>._domainkey.<tenant>.onmicrosoft.com, then enable DKIM signing'])
            eop = any('protection.outlook.com' in str(m.get('host')).lower() for m in mx)
            if platform == 'online' and mx and not eop:
                issue('medium', 'mx', '%s: mailboxes are in Exchange Online but MX does not point to Exchange Online Protection' % name, ', '.join(str(m.get('host')) for m in mx),
                      ['Point the MX to <domain>.mail.protection.outlook.com (the value in the Microsoft 365 admin centre) once the gateway is no longer needed in front'])
            if platform == 'hybrid':
                issue('info', 'mx', '%s: hybrid mail flow - decide where MX points' % name, 'MX now: ' + ', '.join(str(m.get('host')) for m in mx),
                      ['Keep MX on-premises (centralized mail transport) while most mailboxes are local: the gateway / Exchange must accept mail from Exchange Online Protection on the hybrid receive connector (TLS, certificate name matching the connector)',
                       'Move MX to Exchange Online Protection when most mailboxes have moved: the firewall must then allow TCP 25 from Microsoft\'s EOP ranges to the on-premises Exchange',
                       'Either way: run the Hybrid Configuration Wizard, keep the certificate on the hybrid send / receive connectors valid, and test both directions before switching'])
    links = int(prof.get('isp_links') or 1)
    if links >= 2 and platform in ('onprem', 'hybrid'):
        nets = {}
        for m in mx_hosts:
            for ip in m.get('ips') or []:
                try:
                    nets.setdefault(str(ipaddress.ip_network(ip + '/24', strict=False)), []).append(m.get('host'))
                except ValueError:
                    pass
        if len(nets) < 2:
            issue('high', 'mx', 'Two Internet links but every MX address is on one of them - a failure of that link stops inbound mail', ', '.join(nets.keys()) or 'no MX address',
                  ['Publish a second MX record (higher preference number) pointing to the gateway\'s public IP on the second ISP, with its own A record and reverse DNS',
                   'NAT TCP 25 on the second link to the gateway and allow it on the firewall; test by sending from outside with the first link down',
                   'Add the second link\'s egress IP to SPF so outbound mail can fail over too'])
            mx_state = 'bad' if mx_state == 'bad' else 'warn'
    # ---- inbound: SMTP / TLS on the MX hosts
    smtp_state = 'not_checked'
    probed = [m for m in mx_hosts if m.get('smtp')]
    if probed:
        smtp_state = 'ok'
        for m in probed:
            s = m['smtp']
            if not s.get('connected'):
                issue('info', 'smtp', 'Could not connect to %s on TCP 25 from the platform (%s)' % (m.get('host'), s.get('error') or 'no answer'),
                      'probe from the platform server', ['If outbound TCP 25 is blocked from the platform this is expected - test from outside (e.g. a mail tester)', 'If not blocked: the MX host is down or the firewall drops port 25'])
                smtp_state = 'warn' if smtp_state == 'ok' else smtp_state
            elif not s.get('starttls'):
                issue('medium', 'smtp', '%s does not offer STARTTLS - inbound mail travels unencrypted' % m.get('host'), s.get('banner') or '', ['Enable TLS on the gateway listener with a valid certificate for %s' % m.get('host')])
                smtp_state = 'warn'
    for d in doms:
        if d.get('mx') and not d.get('mta_sts'):
            issue('info', 'smtp', '%s publishes no MTA-STS policy' % d.get('name'), '_mta-sts TXT missing', ['Publish MTA-STS (TXT _mta-sts + https://mta-sts.%s/.well-known/mta-sts.txt) so senders must use TLS' % d.get('name')])
        if d.get('mx') and not d.get('tls_rpt'):
            issue('info', 'smtp', '%s publishes no TLS-RPT record' % d.get('name'), '_smtp._tls TXT missing', ['Publish "v=TLSRPTv1; rua=mailto:tls-reports@%s" to receive TLS failure reports' % d.get('name')])
    # ---- SIEM hops
    gi, go, ex = (siem or {}).get('gateway_in'), (siem or {}).get('gateway_out'), (siem or {}).get('exchange')
    gw_in_state = 'not_connected' if not gi else 'ok'
    ex_in_state = ex_out_state = gw_out_state = 'not_connected'
    if gi:
        tot = sum(_n(v) for v in gi.values())
        if not tot:
            gw_in_state = 'warn'
            issue('medium', 'gateway_in', 'The email gateway reported no inbound mail in the period', 'gateway events: 0', ['Check the gateway is sending syslog to the SIEM, and that MX really points at it'])
    if ex:
        recv, deliv, send, sub = _n(ex.get('receive')), _n(ex.get('deliver')), _n(ex.get('send')), _n(ex.get('submit'))
        fail, defer, dsn = _n(ex.get('fail')), _n(ex.get('defer')), _n(ex.get('dsn'))
        ex_in_state = 'ok' if recv else 'warn'
        ex_out_state = 'ok' if send else 'warn'
        if gi and _n(gi.get('delivered')) and not recv:
            issue('high', 'exchange_in', 'The gateway delivered mail but Exchange logged nothing received', ['gateway delivered: %d' % _n(gi.get('delivered')), 'Exchange RECEIVE: 0'],
                  ['Check the Exchange message tracking shipper is running (SIEM)', 'Check the gateway delivers to Exchange and the receive connector accepts it'])
        tot = recv + send + deliv
        if tot and (fail + defer) * 100 > tot * 5:
            issue('high' if fail else 'medium', 'exchange', 'Exchange: %d failed and %d deferred messages (%d%% of traffic)' % (fail, defer, round((fail + defer) * 100.0 / tot)),
                  'message tracking', ['Read the reasons below - each code says where the route breaks'])
            ex_in_state = ex_out_state = 'warn'
        for r in (siem or {}).get('exchange_reasons') or []:
            if _n(r.get('n')) <= 0:
                continue
            title, sev, fix = _code(r.get('value'))
            issue(sev, 'exchange', '%s (%d)' % (title, _n(r.get('n'))), str(r.get('value'))[:300], fix)
            if SEV[sev] >= 3:
                ex_out_state = 'bad'
        if dsn and send and dsn * 100 > send * 10:
            issue('medium', 'exchange_out', '%d non-delivery reports for %d sent messages' % (dsn, send), 'Exchange DSN events', ['Look at the failure reasons; a sudden rise can mean a compromised mailbox sending to invalid addresses'])
    if go:
        gw_out_state = 'ok'
        blk = _n(go.get('blocked')) + _n(go.get('rejected')) + _n(go.get('quarantined'))
        tot = sum(_n(v) for v in go.values())
        if tot and blk * 100 > tot * 2:
            issue('high', 'gateway_out', 'The gateway stopped %d of %d outbound messages' % (blk, tot), 'gateway outbound actions', ['Outbound spam / malware / DLP from inside: find the sending accounts (Outbound with a threat verdict) - a compromised mailbox will get the egress IP blocklisted'])
            gw_out_state = 'warn'
    # ---- outage: a hop that normally carries mail but carried nothing in the last hour (siem.recent, read by the page)
    rec = (siem or {}).get('recent') or {}
    down = {}
    def stopped(hop, period, recent, label, fix):
        if recent is None or period is None:
            return
        if _n(period) >= 50 and _n(recent) == 0:
            down[hop] = True
            issue('critical', hop, 'No mail through %s in the last hour (%d in the period) - the flow may be stopped here' % (label, _n(period)), ['period: %d' % _n(period), 'last hour: 0'], fix)
    if gi is not None:
        stopped('gateway_in', sum(_n(v) for v in gi.values()), rec.get('gateway_in'), 'the email gateway (inbound)',
                ['Check the gateway is up and its service running (console / health page)', 'Check MX still resolves to the gateway and TCP 25 from the Internet reaches it (firewall / NAT)', 'Check the gateway is still sending syslog to the SIEM (Log assurance)'])
    if go is not None:
        stopped('gateway_out', sum(_n(v) for v in go.values()), rec.get('gateway_out'), 'the email gateway (outbound)',
                ['Check Exchange can reach the gateway on its send connector / smart host (TCP 25)', 'Check the gateway\'s outbound queue and its delivery to the Internet'])
    if ex:
        stopped('exchange_in', _n(ex.get('receive')), rec.get('exchange_receive'), 'Exchange receive',
                ['Check the Exchange transport services (MSExchangeFrontEndTransport, MSExchangeTransport) are running', 'Check the receive connector bound to the gateway and that the gateway can reach Exchange on TCP 25', 'Check back pressure (disk space / memory on the transport server, event 15004-15007)'])
        stopped('exchange_out', _n(ex.get('send')), rec.get('exchange_send'), 'Exchange send',
                ['Check the send connector to the gateway / smart host and its queue (Get-Queue)', 'Check DNS and TCP 25 from Exchange to the next hop', 'Check back pressure on the transport server'])
        stopped('mailbox', _n(ex.get('deliver')), rec.get('exchange_deliver'), 'mailbox delivery',
                ['Check the Mailbox Transport Delivery service and the mailbox databases are mounted'])
    if probed and all(not (m.get('smtp') or {}).get('connected') for m in probed) and any((m.get('smtp') or {}).get('error') not in (None, 'no answer on TCP 25') for m in probed):
        down['smtp'] = True
    # ---- egress IPs
    eg = facts.get('egress') or []
    eg_state = 'ok' if eg else 'not_checked'
    if not eg:
        issue('medium', 'egress', 'No outbound mail IP is registered', 'nothing to check', ['Register the public IP mail leaves from (the gateway\'s NAT address - visible in the "Received:" headers of a mail sent to an outside mailbox)'])
    for e in eg:
        ip = e.get('ip')
        if not e.get('ptr') and e.get('ptr_error'):
            # the lookup failed (timeout / SERVFAIL / refused): not known, never reported as "no PTR"
            issue('low', 'egress', 'Reverse DNS of %s could not be checked' % ip, e.get('ptr_error'), ['Check that the IT Asset Management server can reach public DNS (1.1.1.1 / 8.8.8.8, UDP and TCP 53) or set domains.public_resolvers', 'Confirm the PTR yourself: nslookup %s 8.8.8.8' % ip])
            eg_state = 'warn' if eg_state == 'ok' else eg_state
        elif not e.get('ptr'):
            issue('high', 'egress', '%s has no reverse DNS (PTR) - many receivers reject mail from it' % ip, 'PTR lookup: none', ['Ask the ISP that owns the IP to set the PTR to the gateway\'s host name (e.g. mail.<domain>)'])
            eg_state = 'bad'
        else:
            if not e.get('fcrdns'):
                issue('medium', 'egress', 'Reverse DNS of %s (%s) does not resolve back to the same IP' % (ip, e['ptr'][0]), 'forward-confirmed rDNS failed', ['Create an A record for %s pointing to %s' % (e['ptr'][0], ip)])
                eg_state = 'warn' if eg_state == 'ok' else eg_state
            if _ptr_generic(e['ptr'][0]):
                issue('medium', 'egress', 'Reverse DNS of %s looks like a generic / dynamic name (%s)' % (ip, e['ptr'][0]), 'receivers score generic PTRs as spam', ['Set a PTR that names the mail server (mail.<domain>) with the ISP'])
                eg_state = 'warn' if eg_state == 'ok' else eg_state
        r = rep.get(ip)
        if r and r.get('state') == 'listed':
            issue('critical' if r.get('severity') == 'critical' else 'high', 'egress', '%s is listed on Spamhaus (%s)' % (ip, ', '.join(l.get('list') for l in r.get('lists') or [])), 'Mail server reputation card', (r.get('advice') or [])[:3])
            eg_state = 'bad'
        bad_d = [d for d in doms if d.get('spf') and not _spf_eval(d['spf'], ip)]
        if bad_d:
            ev = ['SPF evaluation (ip4 / a / mx / includes)']
            for d in bad_d:
                rd = d.get('spf_read') or {}
                src = 'read live from %s DNS' % ('public' if rd.get('via') == 'public' else "this server's") if rd.get('from') == 'live' else 'DNS not readable now - the copy Domains & Hosting stored at its last check'
                ev.append('%s SPF (%s): %s' % (d.get('name'), src, str((d['spf'] or {}).get('record') or '')[:300]))
            fix = ['Add "ip4:%s" to the SPF record (before the -all) - otherwise mail from it fails SPF and, without DKIM, DMARC' % ip,
                   'Already added? The record above is what DNS answers now: if ip4:%s is not in it, the change is not published yet - check it was saved in the zone of the DNS host the domain\'s name servers point to, that it is the one v=spf1 TXT record on the domain itself (not a sub-name), and wait for the old record\'s TTL to expire' % ip]
            issue('high', 'egress', '%s is not authorised by the SPF record of %s' % (ip, ', '.join(d.get('name') for d in bad_d)), ev, fix)
            eg_state = 'bad'
    # ---- authentication published for receivers
    auth_state = 'ok' if doms else 'not_checked'
    for d in doms:
        name, spf = d.get('name'), d.get('spf')
        if d.get('spf_count', 1) == 0:
            issue('high', 'auth', '%s has no SPF record' % name, 'TXT v=spf1 missing', ['Publish one SPF record listing every sending service, ending in -all'])
            auth_state = 'bad'
        elif d.get('spf_count', 1) > 1:
            issue('high', 'auth', '%s has %d SPF records (permerror)' % (name, d['spf_count']), 'more than one v=spf1', ['Merge them into one record'])
            auth_state = 'bad'
        if spf:
            n = _spf_lookups(spf)
            if n > 10:
                issue('high', 'auth', 'SPF of %s needs %d DNS lookups - over the limit of 10 (permerror: SPF fails everywhere)' % (name, n), 'include / a / mx / redirect count', ['Remove unused includes or replace them with ip4 ranges (SPF flattening)'])
                auth_state = 'bad'
        dk = d.get('dkim') or {}
        if dk and any(dk.values()):
            pass   # a key is published for at least one selector (recorded or found among the common ones)
        elif dk:
            issue('medium', 'auth', '%s: no DKIM key found for the recorded selectors' % name, ', '.join(dk.keys()) + (' - and none of the %d common selectors has one either' % d['dkim_checked'] if d.get('dkim_checked') else ''), ['Check the selector name your gateway / Exchange Online signs with (the s= tag in a sent mail\'s DKIM-Signature header) and record it in Domains & Hosting; publish its key if it is missing'])
            auth_state = auth_state if auth_state == 'bad' else 'warn'
        elif d.get('dkim_checked') is not None:
            # nothing recorded and none of the common selectors answers: DKIM is NOT CHECKED here - that is not "missing"
            issue('info', 'auth', '%s: DKIM not checked - no selector recorded and none of the %d common selectors has a key' % (name, d['dkim_checked']), 'no selector recorded', ['Open a mail you sent, read s= in its DKIM-Signature header, and record that selector in Domains & Hosting'])
        dm = str(d.get('dmarc') or '')
        if not dm:
            issue('high', 'auth', '%s has no DMARC record' % name, '_dmarc TXT missing', ['Publish v=DMARC1; p=quarantine; rua=mailto:dmarc@%s and move to p=reject' % name])
            auth_state = 'bad'
        elif re.search(r'p=none', dm, re.I):
            issue('medium', 'auth', '%s: DMARC is p=none - spoofed mail is still delivered' % name, dm[:200], ['Review the aggregate reports, then move to p=quarantine and p=reject'])
            auth_state = auth_state if auth_state == 'bad' else 'warn'

    def worst(*states):
        order = ['bad', 'warn', 'ok', 'not_checked', 'not_connected']
        st = [s for s in states if s]
        return min(st, key=order.index) if st else 'not_checked'
    exn = ex or {}
    lanes = {
        'inbound': [
            {'id': 'internet_in', 'label': 'Internet senders', 'state': 'info'},
            {'id': 'mx', 'label': 'MX record (DNS)', 'state': mx_state, 'detail': ', '.join(sorted({str(m.get('priority')) + ' ' + str(m.get('host')) for m in mx_hosts}))[:300]},
            {'id': 'smtp', 'label': 'MX host - SMTP / TLS', 'state': smtp_state, 'detail': '%d of %d probed hosts offer STARTTLS' % (sum(1 for m in probed if (m.get('smtp') or {}).get('starttls')), len(probed)) if probed else 'not probed'},
            {'id': 'gateway_in', 'label': 'Email gateway (inbound)', 'state': gw_in_state, 'counts': gi or {}},
            {'id': 'exchange_in', 'label': 'Exchange - receive', 'state': ex_in_state, 'counts': {'receive': _n(exn.get('receive'))} if ex else {}},
            {'id': 'mailbox', 'label': 'Mailbox - deliver', 'state': ('ok' if _n(exn.get('deliver')) else 'warn') if ex else 'not_connected', 'counts': {'deliver': _n(exn.get('deliver')), 'fail': _n(exn.get('fail'))} if ex else {}},
        ],
        'outbound': [
            {'id': 'mailbox_out', 'label': 'Mailbox - submit', 'state': ('ok' if _n(exn.get('submit')) else 'warn') if ex else 'not_connected', 'counts': {'submit': _n(exn.get('submit'))} if ex else {}},
            {'id': 'exchange_out', 'label': 'Exchange - send', 'state': ex_out_state, 'counts': {'send': _n(exn.get('send')), 'defer': _n(exn.get('defer')), 'dsn': _n(exn.get('dsn'))} if ex else {}},
            {'id': 'gateway_out', 'label': 'Email gateway (outbound)', 'state': gw_out_state, 'counts': go or {}},
            {'id': 'egress', 'label': 'Egress IP - rDNS / SPF / Spamhaus', 'state': eg_state, 'detail': ', '.join(e.get('ip') + (' → ' + e['ptr'][0] if e.get('ptr') else '') for e in eg)[:300]},
            {'id': 'auth', 'label': 'SPF / DKIM / DMARC', 'state': auth_state},
            {'id': 'internet_out', 'label': 'Internet receivers', 'state': 'info'},
        ],
    }
    for lane in lanes.values():
        for h in lane:
            if down.get(h['id']):
                h['state'] = 'down'
    issues.sort(key=lambda i: -SEV[i['severity']])
    blocked = {}
    for name, lane in lanes.items():
        b = next((h for h in lane if h['state'] in ('down', 'bad')), None)
        if b:
            top = next((i for i in issues if i['hop'] == b['id'] or (i['hop'] == 'exchange' and b['id'] in ('exchange_in', 'exchange_out'))), None)
            blocked[name] = {'hop': b['id'], 'label': b['label'], 'state': b['state'], 'reason': top['title'] if top else '', 'fix': top['fix'] if top else []}
    for lane in lanes.values():
        for h in lane:
            h['issues'] = sum(1 for i in issues if i['hop'] == h['id'] or (i['hop'] == 'exchange' and h['id'] in ('exchange_in', 'exchange_out')))
    topo = _topology(doms, mx_hosts, eg, platform, int(prof.get('isp_links') or 1), {h['id']: h['state'] for l in lanes.values() for h in l})
    servers, srv_issues = _servers(prof.get('servers') or [], mx_hosts, eg, facts.get('server_dns') or {})
    for i in srv_issues:
        issues.append(i)
    rdns, rd_issues = _rdns(mx_hosts, eg, prof.get('servers') or [], doms, topo)
    for i in rd_issues:
        issues.append(i)
    topo['rdns'] = rdns
    issues.sort(key=lambda i: -SEV[i['severity']])
    topo['servers'] = servers
    topo['domains'] = [d.get('name') for d in doms if d.get('name')]
    warnings = _warnings(doms, mx_hosts, req.get('prev_dns') or None, req.get('now'), eg, req.get('reputation') or [])
    return {'lanes': lanes, 'issues': issues, 'blocked': blocked, 'topology': topo, 'warnings': warnings, 'counts': {k: sum(1 for i in issues if i['severity'] == k) for k in SEV},
            'siem': bool(siem), 'platform': platform, 'note': 'Inbound and outbound route hop by hop. DNS facts are read by the platform; counts come from the SIEM (gateway syslog and Exchange message tracking). A hop with no data is not connected - never healthy.'}


_INTERNAL = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16')]


def _private(ip):
    """An internal address (RFC 1918, carrier NAT, loopback, link-local) - never reachable from the Internet. Not Python's
    is_private, which also counts the documentation ranges."""
    try:
        a = ipaddress.ip_address(str(ip))
        return a.version == 4 and any(a in n for n in _INTERNAL)
    except ValueError:
        return False


def _servers(reg, mx_hosts, eg, server_dns):
    """The mail server register (profile): each server's DNS name, private address and public (NAT) addresses, joined to
    what DNS says - which MX record reaches it, whether mail leaves from it, what its public name resolves to. Issues only
    from facts: an MX address no registered server owns, a public name that resolves elsewhere, a private address in MX."""
    issues, out = [], []

    def issue(sev, hop, title, evidence, fix):
        issues.append({'severity': sev, 'hop': hop, 'title': title, 'evidence': evidence if isinstance(evidence, list) else [evidence], 'fix': fix})
    seen = set()
    for m in mx_hosts:
        for ip in m.get('ips') or []:
            if _private(ip) and (m.get('host'), ip) not in seen:
                seen.add((m.get('host'), ip))
                issue('critical', 'mx', 'MX host %s resolves to a private address %s - nobody on the Internet can deliver to it' % (m.get('host'), ip), 'A record of the MX host',
                      ['Point the public A record of %s to the public (NAT) address of the gateway, not its internal address - internal names belong in the internal DNS zone only' % m.get('host')])
    owned = {}
    for s in reg:
        for ip in s.get('public_ips') or []:
            owned[ip] = s.get('name')
    for s in reg[:20]:
        pubs = list(s.get('public_ips') or [])
        mx_on = sorted({m.get('host') for m in mx_hosts if set(m.get('ips') or []) & set(pubs)})
        eg_on = [e.get('ip') for e in eg if e.get('ip') in pubs]
        dn = str(s.get('dns_name') or '').lower().rstrip('.')
        res = server_dns.get(dn) if dn else None
        row = {'name': s.get('name'), 'role': s.get('role'), 'dns_name': dn or None, 'private_ip': s.get('private_ip'), 'public_ips': pubs,
               'mx': mx_on, 'egress': eg_on, 'dns_ips': res, 'notes': []}
        if dn and res is not None:
            if not res:
                row['notes'].append('%s does not resolve in public DNS (internal name)' % dn)
            elif pubs and not set(res) & set(pubs):
                issue('medium', 'mx', '%s (%s) resolves to %s, but its public address is %s' % (dn, s.get('name'), ', '.join(res), ', '.join(pubs)), 'public DNS vs the mail server register',
                      ['Correct the A record of %s, or the public address recorded for %s (the firewall NAT rule decides which is right)' % (dn, s.get('name'))])
                row['notes'].append('public DNS points elsewhere')
            elif any(_private(x) for x in res):
                row['notes'].append('public DNS returns a private address')
        if s.get('role') in ('gateway', 'edge') and pubs and not mx_on:
            row['notes'].append('not reached by any MX record')
        out.append(row)
    if reg:
        for m in mx_hosts:
            for ip in m.get('ips') or []:
                if not _private(ip) and ip not in owned and not _cf(ip) and 'protection.outlook.com' not in str(m.get('host')).lower():
                    issue('medium', 'mx', 'MX address %s (%s) belongs to no server in the mail server register' % (ip, m.get('host')), 'register: ' + ', '.join(sorted(owned)) if owned else 'no public addresses recorded',
                          ['Record which server this address is NATed to (Route settings → Mail servers), or correct the MX if it is not yours'])
        for e in eg:
            if e.get('ip') not in owned:
                issue('low', 'egress', 'Egress IP %s belongs to no server in the mail server register' % e.get('ip'), 'outbound NAT', ['Record which server sends from this address so a listing or PTR problem leads straight to the right server'])
    return out, issues


def _rdns(mx_hosts, eg, reg, doms, topo):
    """Reverse DNS of every public mail address, per Internet link: the PTR the ISP publishes, whether it resolves back, and
    the name to ask the ISP for (the server's name in the register, else the MX name, else mail.<domain>). Outbound IPs are
    judged by the egress checks already; here the MX addresses are added and the ISP request is written out."""
    issues, rows = [], []
    owner = {}
    for s in reg:
        for ip in s.get('public_ips') or []:
            owner[ip] = s
    first_dom = (doms[0].get('name') if doms else None) or 'your-domain'
    eg_ips = {e.get('ip') for e in eg}
    seen = set()

    def link_of(ip):
        n = _net24(ip)
        for l in topo.get('links') or []:
            if l.get('network') == n:
                return l.get('n')
        return None
    for m in mx_hosts:
        for ip in m.get('ips') or []:
            if ip in seen or _private(ip) or _cf(ip) or 'protection.outlook.com' in str(m.get('host')).lower():
                continue
            seen.add(ip)
            p = (m.get('ptr') or {}).get(ip)
            if p is None:
                continue
            names = p.get('names') or []
            srv = owner.get(ip)
            want = (srv or {}).get('dns_name') or str(m.get('host') or '').rstrip('.').lower()
            row = {'ip': ip, 'role': 'inbound + outbound' if ip in eg_ips else 'inbound (MX)', 'link': link_of(ip), 'ptr': names[0] if names else None, 'fcrdns': bool(p.get('fcrdns')),
                   'expected': want, 'server': (srv or {}).get('name'), 'ok': bool(names) and bool(p.get('fcrdns')) and names[0].lower().rstrip('.') == want}
            rows.append(row)
            if ip in eg_ips:
                continue   # the egress checks already judge this address
            if not names and p.get('error'):
                row['ok'] = None
                issues.append({'severity': 'low', 'hop': 'mx', 'title': 'Reverse DNS of MX address %s (%s) could not be checked' % (ip, m.get('host')), 'evidence': [p.get('error')],
                               'fix': ['Check that the server can reach public DNS (UDP and TCP 53) or set domains.public_resolvers', 'Confirm the PTR yourself: nslookup %s 8.8.8.8' % ip]})
            elif not names:
                issues.append({'severity': 'medium', 'hop': 'mx', 'title': 'MX address %s (%s) has no reverse DNS' % (ip, m.get('host')), 'evidence': ['PTR lookup: none'],
                               'fix': ['Ask the ISP that owns %s to set its PTR to %s' % (ip, want), 'Many senders and gateways score a mail host without PTR as suspicious, and the same address sends bounces and replies']})
            elif not p.get('fcrdns'):
                issues.append({'severity': 'low', 'hop': 'mx', 'title': 'Reverse DNS of MX address %s (%s) does not resolve back' % (ip, names[0]), 'evidence': ['forward-confirmed rDNS failed'],
                               'fix': ['Create an A record %s -> %s, or ask the ISP to set the PTR to %s' % (names[0], ip, want)]})
            elif _ptr_generic(names[0]):
                issues.append({'severity': 'low', 'hop': 'mx', 'title': 'Reverse DNS of MX address %s is a generic ISP name (%s)' % (ip, names[0]), 'evidence': ['generic / dynamic-looking PTR'],
                               'fix': ['Ask the ISP to set the PTR of %s to %s' % (ip, want)]})
    for e in eg:
        ip = e.get('ip')
        if ip in seen:
            continue
        seen.add(ip)
        names = e.get('ptr') or []
        srv = owner.get(ip)
        want = (srv or {}).get('dns_name') or (names[0].lower().rstrip('.') if names and e.get('fcrdns') and not _ptr_generic(names[0]) else 'mail.' + first_dom)
        rows.append({'ip': ip, 'role': 'outbound', 'link': link_of(ip), 'ptr': names[0] if names else None, 'fcrdns': bool(e.get('fcrdns')), 'expected': want,
                     'server': (srv or {}).get('name'), 'ok': None if (not names and e.get('ptr_error')) else bool(names) and bool(e.get('fcrdns')) and names[0].lower().rstrip('.') == want,
                     'error': e.get('ptr_error')})
    for r in rows:
        if r['server'] and r['ptr'] and r['ptr'].lower().rstrip('.') != r['expected'] and r['fcrdns']:
            issues.append({'severity': 'low', 'hop': 'egress' if r['role'] == 'outbound' else 'mx', 'title': 'PTR of %s is %s but the server %s is named %s' % (r['ip'], r['ptr'], r['server'], r['expected']),
                           'evidence': ['reverse DNS vs the mail server register'], 'fix': ['Ask the ISP to set the PTR of %s to %s (and keep the A record of %s pointing to %s)' % (r['ip'], r['expected'], r['expected'], r['ip'])]})
    # the request to send each ISP: one line per address that is not right yet
    for l in topo.get('links') or []:
        mine = [r for r in rows if r['link'] == l.get('n')]
        l['rdns'] = mine
        l['ptr_request'] = ['Please set the reverse DNS (PTR) of %s to %s' % (r['ip'], r['expected']) for r in mine if r['ok'] is False]
    return rows, issues


def _warnings(doms, mx_hosts, prev, now_ms, eg=None, reputation=None):
    """Early warnings: what will break if nobody acts - certificates near expiry, SPF close to its lookup limit, DNS that
    changed since the last check (an unplanned MX / name-server change is how mail is hijacked)."""
    out = []

    def warn(sev, key, title, detail, fix, days=None):
        out.append({'severity': sev, 'key': key, 'title': title, 'detail': detail, 'fix': fix, 'days_left': days})
    for m in mx_hosts:
        t = (m.get('smtp') or {}).get('tls')
        if not t:
            continue
        host = m.get('host')
        if t.get('error'):
            warn('high', 'tls-fail:' + host, 'STARTTLS on %s fails (%s) - senders that require TLS cannot deliver' % (host, t['error']), 'the server offers STARTTLS but the TLS handshake did not complete',
                 ['Check the certificate bound to the receive connector / gateway listener and the TLS settings (protocol versions, ciphers)'])
            continue
        d = t.get('days_left')
        if d is not None and d < 30:
            sev = 'critical' if d < 7 else 'high' if d < 14 else 'medium'
            warn(sev, 'tls-exp:' + host, ('SMTP certificate of %s expired %d days ago' % (host, -d)) if d < 0 else ('SMTP certificate of %s expires in %d days' % (host, d)),
                 'subject %s · issuer %s · valid to %s' % (t.get('subject') or '?', t.get('issuer') or '?', t.get('not_after') or '?'),
                 ['Renew the certificate (same names: %s), import it on every gateway / Exchange node behind this MX and bind it to SMTP (Enable-ExchangeCertificate -Services SMTP)' % ', '.join((t.get('names') or [])[:4] or [host]),
                  'Update the hybrid send / receive connectors if they name the certificate (TlsCertificateName)'], d)
        if t.get('trusted') is False and d is not None and d >= 0:
            warn('low', 'tls-trust:' + host, 'SMTP certificate of %s is not issued by a publicly trusted CA (%s)' % (host, t.get('trust_error') or 'untrusted'), 'issuer %s' % (t.get('issuer') or '?'),
                 ['Most senders still deliver over an untrusted certificate, but MTA-STS / DANE senders and Exchange Online hybrid connectors refuse it - use a public CA certificate for the MX name'])
        if t.get('names') and not any(_name_ok(host, n) for n in t['names']):
            warn('medium', 'tls-name:' + host, 'SMTP certificate of %s does not carry its name' % host, 'names on the certificate: ' + ', '.join(t['names'][:6]),
                 ['Use a certificate whose subject or SAN includes %s - MTA-STS and DANE senders refuse a mismatch' % host])
    for d in doms:
        spf = d.get('spf')
        if spf:
            n = _spf_lookups(spf)
            if 8 <= n <= 10:
                warn('medium', 'spf-near:' + d.get('name'), 'SPF of %s uses %d of the 10 allowed DNS lookups - one more include breaks SPF everywhere' % (d.get('name'), n), 'include / a / mx / redirect count',
                     ['Before adding a sending service, remove unused includes or replace them with ip4 ranges'])
    if prev:
        for d in doms:
            name = d.get('name')
            p = prev.get(name)
            if not p:
                continue
            cur = {'mx': sorted(str(m.get('host')).lower() for m in d.get('mx') or []), 'ns': sorted(str(x).lower().rstrip('.') for x in d.get('ns') or []), 'spf': (d.get('spf') or {}).get('record') or ''}
            for k, label in (('mx', 'MX records'), ('ns', 'name servers'), ('spf', 'SPF record')):
                if p.get(k) is not None and p.get(k) != cur[k]:
                    was = ', '.join(p[k]) if isinstance(p[k], list) else p[k]
                    now_v = ', '.join(cur[k]) if isinstance(cur[k], list) else cur[k]
                    warn('high' if k in ('mx', 'ns') else 'medium', 'dns-change:%s:%s' % (name, k), '%s of %s changed since the last check' % (label, name), 'was: %s · now: %s' % (str(was)[:200] or 'none', str(now_v)[:200] or 'none'),
                         ['If this was a planned change, nothing to do - record it in the change log', 'If not: check who changed it in the DNS provider (Cloudflare audit log), lock the account with MFA and restricted API tokens, and restore the record'])
    # reverse DNS that changed or disappeared since the last check (an ISP renumbering or a lost PTR breaks delivery quietly)
    cur_ptr = _ptr_map(mx_hosts, eg or [])
    if prev and isinstance(prev.get('_ptr'), dict):
        for ip, was in prev['_ptr'].items():
            now_p = cur_ptr.get(ip)
            if now_p is None or was == now_p:
                continue
            if was and not now_p:
                warn('high', 'ptr-gone:' + ip, 'Reverse DNS of %s disappeared (was %s)' % (ip, was), 'PTR lookup now returns nothing',
                     ['Ask the ISP that owns %s to restore the PTR %s - receivers reject or junk mail from an address without one' % (ip, was)])
            else:
                warn('medium', 'ptr-change:' + ip, 'Reverse DNS of %s changed' % ip, 'was: %s · now: %s' % (was or 'none', now_p),
                     ['If the ISP or the network team did not plan this, ask the ISP to set it back to the server\'s name'])
    # Spamhaus: any of our mail addresses or domains listed - at once, with what to do; XBL / CSS are compromise signals
    for r in reputation or []:
        if r.get('state') != 'listed':
            continue
        names = {l.get('list') for l in r.get('lists') or []}
        roles = ', '.join(r.get('roles') or []) or r.get('kind') or ''
        sev = 'critical' if (names & {'SBL', 'CSS', 'XBL', 'DBL', 'DROP'} and 'outbound' in (r.get('roles') or []) + ['outbound' if r.get('kind') == 'domain' else '']) else (r.get('severity') or 'high')
        if r.get('provider'):
            sev = 'medium'
        warn(sev if sev in SEV else 'high', 'spamhaus:' + str(r.get('target')), '%s (%s) is listed on Spamhaus %s' % (r.get('target'), roles, ', '.join(sorted(n for n in names if n))),
             '; '.join('%s: %s' % (l.get('list'), l.get('meaning')) for l in r.get('lists') or [])[:300], (r.get('advice') or [])[:4])
    out.sort(key=lambda w: -SEV[w['severity']])
    return out


def _ptr_map(mx_hosts, eg):
    out = {}
    for m in mx_hosts:
        for ip, p in (m.get('ptr') or {}).items():
            out[ip] = ((p.get('names') or [''])[0] or '').lower().rstrip('.')
    for e in eg:
        out[e.get('ip')] = ((e.get('ptr') or [''])[0] or '').lower().rstrip('.')
    return out


def _name_ok(host, name):
    host, name = str(host).lower().rstrip('.'), str(name).lower().rstrip('.')
    if name.startswith('*.'):
        return host.split('.', 1)[-1] == name[2:]
    return host == name


def dns_snapshot(req):
    """What the next check compares against: per domain, the MX hosts, name servers and SPF record."""
    out = {}
    for d in (req.get('facts') or {}).get('domains') or []:
        out[d.get('name')] = {'mx': sorted(str(m.get('host')).lower() for m in d.get('mx') or []), 'ns': sorted(str(x).lower().rstrip('.') for x in d.get('ns') or []), 'spf': (d.get('spf') or {}).get('record') or ''}
    mxh = [m for d in (req.get('facts') or {}).get('domains') or [] for m in d.get('mx') or []]
    out['_ptr'] = _ptr_map(mxh, (req.get('facts') or {}).get('egress') or [])
    return {'snapshot': out}


def _net24(ip):
    try:
        return str(ipaddress.ip_network(str(ip) + '/24', strict=False))
    except ValueError:
        return None


def _topology(doms, mx_hosts, eg, platform, links, states):
    """What the route map draws: DNS hosting, each MX host and egress IP grouped by public network (/24) - a stand-in for
    "which Internet link" that is labelled as such - and whether Exchange Online is on the path. Facts only: a link the
    profile declares with no MX or egress address on it is shown as unused, never as healthy."""
    ns = sorted({str(n).lower().rstrip('.') for d in doms for n in (d.get('ns') or [])})
    cf = any('cloudflare' in n for n in ns)
    nets = []
    def net_of(ip):
        # an internal address (the gateway's NAT inside address from a split DNS) is not an Internet link
        if _private(ip):
            return None
        n = _net24(ip)
        if n and n not in nets:
            nets.append(n)
        return nets.index(n) if n else None
    mx = []
    seen = set()
    for m in mx_hosts:
        host = str(m.get('host') or '').lower().rstrip('.')
        if host in seen:
            continue
        seen.add(host)
        ips = [str(i) for i in (m.get('ips') or [])][:4]
        smtp = m.get('smtp') or {}
        mx.append({'host': host[:120], 'priority': m.get('priority'), 'ips': ips, 'links': sorted({x for x in (net_of(i) for i in ips) if x is not None}),
                   'proxied': any(_cf(i) for i in ips), 'cf_routing': bool(re.search(r'mx\.cloudflare\.net$', host)),
                   'eop': 'protection.outlook.com' in host, 'probed': bool(smtp), 'connected': smtp.get('connected'), 'starttls': smtp.get('starttls')})
    egress = [{'ip': str(e.get('ip')), 'ptr': (e.get('ptr') or [None])[0], 'ptr_error': e.get('ptr_error') if not e.get('ptr') else None, 'link': net_of(e.get('ip'))} for e in eg][:8]
    used = len(nets)
    link_rows = []
    for i in range(max(links, used)):
        on_mx = [m['host'] for m in mx if i in m['links']]
        on_eg = [e['ip'] for e in egress if e['link'] == i]
        link_rows.append({'n': i + 1, 'network': nets[i] if i < used else None, 'mx': on_mx, 'egress': on_eg,
                          'state': 'unused' if not on_mx and not on_eg else 'inbound+outbound' if on_mx and on_eg else 'inbound' if on_mx else 'outbound'})
    return {'dns': {'provider': 'Cloudflare' if cf else ('other' if ns else None), 'ns': ns[:6]}, 'mx': mx[:12], 'egress': egress, 'links': link_rows,
            'declared_links': links, 'platform': platform, 'exo': platform in ('hybrid', 'online'), 'states': states,
            'note': 'Internet links are told apart by public network (/24) of the MX and egress addresses - the platform does not see the ISP itself.'}


OPS = {'mailroute.assess': assess, 'mailroute.snapshot': dns_snapshot}
