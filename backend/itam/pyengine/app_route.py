# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Application Route Map rules (engine/app-route.js): each business application drawn as a route, the same design as the
Email Route Map -

    Users -> Application (its front door: an APM URL / web monitor) -> APIs and services (APM monitors)
          -> application servers (the client machines the database sees) -> database service (listener) -> database (instances)

and the state of every hop judged from facts the platform already reads - nothing assumed:
  * ManageEngine Applications Manager monitors (SIEM /integrations/apm/monitors): availability and health
  * the DBA Alert Center (SIEM /db/dba/status): every instance of the database, its level and open problems
  * Application Connections (SIEM /db/oracle/connections, operator): sessions per client machine / program / service,
    machines that dropped off, listener refusals with the TNS code
The page reads those as the signed-in person and posts them; the register of applications (which monitors, machines,
database and services make up an application) is kept by an administrator in IT Asset Management.

A hop with no fact is "not connected" or "not checked" with what to connect - never "working". A RAC database with one
instance down is degraded, not down. Client machines the database sees that belong to no application are offered as
"discovered" so an administrator can add them; nothing is added by itself. Standard library only.
"""
import re

SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
STATE_ORDER = ['down', 'bad', 'warn', 'ok', 'info', 'not_checked', 'not_connected', 'unused']


def _low(v):
    return str(v if v is not None else '').strip().lower()


def _short(v):
    return _low(v).split('.')[0]


def worst(states):
    states = [s for s in states if s]
    return min(states, key=STATE_ORDER.index) if states else 'not_connected'


def _issue(sev, hop, title, evidence, fix):
    return {'severity': sev, 'hop': hop, 'title': title, 'evidence': [e for e in (evidence or []) if e], 'fix': fix}


def monitor_state(m):
    """an APM monitor -> (state, why)"""
    if not m:
        return 'not_connected', 'monitor not found in Applications Manager'
    if m.get('managed') is False:
        return 'not_checked', 'unmanaged in Applications Manager (not polled)'
    av, he = _low(m.get('availability')), _low(m.get('health'))
    if av == 'down':
        return 'down', 'down in Applications Manager'
    if he == 'critical':
        return 'bad', 'health critical'
    if he == 'warning':
        return 'warn', 'health warning'
    if av == 'up' or he == 'clear':
        return 'ok', 'up'
    return 'not_checked', 'availability not reported'


def _mon_node(hop, mid, M, apm_ok, label):
    if not mid:
        return {'state': 'not_connected', 'title': label, 'sub': 'no monitor linked', 'monitor': None,
                'issues': [_issue('low', hop, label + ': no Applications Manager monitor linked', [], ['An administrator links the monitor that checks it (click the box, then Set up).'])]}
    if not apm_ok:
        return {'state': 'not_connected', 'title': label, 'sub': 'Applications Manager not connected', 'monitor': {'id': mid},
                'issues': [_issue('low', hop, 'Applications Manager is not connected - the monitor cannot be read', [], ['Connect ManageEngine Applications Manager in Connections & Setup (read-only API key).'])]}
    m = M.get(str(mid))
    st, why = monitor_state(m)
    out = {'state': st, 'title': (m or {}).get('name') or label, 'sub': ((m or {}).get('type') or '') + ((' · ' + m['host']) if (m or {}).get('host') else ''),
           'monitor': {'id': mid, 'name': (m or {}).get('name'), 'type': (m or {}).get('type'), 'host': (m or {}).get('host'),
                       'availability': (m or {}).get('availability'), 'health': (m or {}).get('health'), 'message': (m or {}).get('message')}, 'issues': []}
    if not m:
        out['issues'].append(_issue('medium', hop, 'Monitor ' + str(mid) + ' is no longer in Applications Manager', [], ['Link the monitor that replaced it, or remove the link.']))
    elif st == 'down':
        out['issues'].append(_issue('critical', hop, (m.get('name') or label) + ' is DOWN', [m.get('message')], ['Open the monitor in Applications Manager for the failed check and the time it went down.', 'Check the application server and the service behind the URL; the hops to the right show whether the database side is affected.']))
    elif st in ('bad', 'warn'):
        out['issues'].append(_issue('high' if st == 'bad' else 'medium', hop, (m.get('name') or label) + ': ' + why, [m.get('message')], ['Open the monitor in Applications Manager for the attribute that breached its threshold.']))
    elif st == 'not_checked' and m.get('managed') is False:
        out['issues'].append(_issue('low', hop, (m.get('name') or label) + ' is unmanaged - nothing checks it', [], ['Manage the monitor again in Applications Manager (or through the APM page, with approval).']))
    return out


def _db_node(app, D):
    name = (app.get('database') or '').upper()
    if not name:
        return {'state': 'not_connected', 'title': 'Database', 'sub': 'none linked', 'instances': [],
                'issues': [_issue('low', 'database', 'No database linked to this application', [], ['An administrator links the database the application uses (click the box, then Set up).'])]}
    d = D.get(name)
    if not d:
        return {'state': 'not_connected', 'title': name, 'sub': 'not monitored', 'instances': [],
                'issues': [_issue('medium', 'database', name + ' is not monitored by the DBA Alert Center', [], ['Add the database in Databases -> Add database (read-only account), or correct the name linked here.'])]}
    inst = d.get('instances') or []
    states = []
    for i in inst:
        lv = _low(i.get('level'))
        i['state'] = 'bad' if lv == 'crit' else 'warn' if lv == 'warn' else 'ok' if lv == 'ok' else 'not_checked'
        if re.search(r'mount|nomount|down|closed', _low(i.get('status'))) and _low(i.get('role')) not in ('physical standby', 'standby'):
            i['state'] = 'down'
        states.append(i['state'])
    issues = []
    down = [i for i in inst if i['state'] == 'down']
    if inst and len(down) == len(inst):
        st = 'down'
        issues.append(_issue('critical', 'database', name + ': every instance is down / not open', [i['instance'] + ' ' + (i.get('status') or '') for i in down], ['Start the instance(s) (srvctl start database -d ' + name.lower() + '), then check the alert log for why it stopped.']))
    elif down:
        st = 'warn'
        issues.append(_issue('high', 'database', name + ': ' + ', '.join(i['instance'] for i in down) + ' not open - the database runs on the remaining instance(s)', [], ['Start the instance (srvctl start instance), and check the services moved back to it (srvctl status service).']))
    else:
        st = worst(states) if states else 'not_checked'
    crit = sum(int(i.get('crit') or 0) for i in inst)
    warn = sum(int(i.get('warn') or 0) for i in inst)
    if crit or warn:
        issues.append(_issue('high' if crit else 'medium', 'database', name + ': ' + str(crit) + ' critical and ' + str(warn) + ' warning DBA alert(s) open', [], ['Open the Database Dashboard / DBA Alert Center for each problem and its fix.']))
    if not inst:
        st = 'not_checked'
    return {'state': st, 'title': name, 'sub': (str(len(inst)) + ' instances (RAC)') if len(inst) > 1 else ((inst[0].get('host') or '') if inst else ''), 'instances': inst, 'issues': issues}


def assess(r):
    prof = r.get('profile') or {}
    apps = prof.get('apps') or []
    F = r.get('facts') or {}
    apm_ok = bool((F.get('apm') or {}).get('connected'))
    M = {str(m.get('id')): m for m in F.get('monitors') or [] if m.get('id') is not None}
    D = {(_low(d.get('database'))).upper(): d for d in F.get('databases') or [] if d.get('database')}
    S = F.get('sessions')               # {DB: {reported, apps:[{machine, program, service, sessions, state}]}} or None (role)
    L = F.get('listener') or {}         # {DB: [{client_host, service, refused, reasons:[{code, meaning, fix, n}]}]}
    out_apps, all_issues, linked_m, used = [], [], set(), {}
    for a in apps:
        db = (a.get('database') or '').upper()
        front = _mon_node('front', a.get('front_monitor'), M, apm_ok, 'Application front end')
        if a.get('front_monitor'):
            linked_m.add(str(a.get('front_monitor')))
        apis = []
        for mid in a.get('api_monitors') or []:
            linked_m.add(str(mid))
            apis.append(_mon_node('api', mid, M, apm_ok, 'API / service'))
        sess = (S or {}).get(db) if S is not None else None
        rows = (sess or {}).get('apps') or []
        lst = L.get(db) or []
        servers = []
        for mach in a.get('machines') or []:
            k = _short(mach)
            used.setdefault(db, set()).add(k)
            mine = [x for x in rows if _short(x.get('machine')) == k]
            ref = [x for x in lst if _short(x.get('client_host')) == k and int(x.get('refused') or 0) > 0]
            node = {'title': mach, 'machine': mach, 'issues': [], 'sessions': sum(int(x.get('sessions') or 0) for x in mine if x.get('state') != 'dropped'),
                    'programs': sorted({str(x.get('program') or '') for x in mine if x.get('program')})[:8]}
            if S is None:
                node['state'], node['sub'] = 'not_checked', 'sessions visible to operators'
            elif not db:
                node['state'], node['sub'] = 'not_connected', 'no database linked'
            elif not sess or not sess.get('reported'):
                node['state'], node['sub'] = 'not_checked', 'no session reading from ' + db
                node['issues'].append(_issue('low', 'server', 'No session reading from ' + db, [], ['The session reading comes with the read-only account (Databases -> Add database script).']))
            elif any(x.get('state') == 'dropped' for x in mine) and not node['sessions']:
                node['state'], node['sub'] = 'bad', 'dropped off ' + db
                node['issues'].append(_issue('critical', 'server', mach + ' dropped its connections to ' + db, [', '.join(node['programs'])], ['Check the application service on ' + mach + ' (stopped pool, crashed service) and the network path to the database; the Application Connections page shows when it last had sessions.']))
            elif node['sessions']:
                node['state'], node['sub'] = 'ok', str(node['sessions']) + ' sessions'
            else:
                node['state'], node['sub'] = 'warn', 'no session to ' + db
                node['issues'].append(_issue('medium', 'server', mach + ' has no session to ' + db + ' now', [], ['If the application should be connected, check its service and connect string; if it connects on demand this can be normal.']))
            if ref:
                node['state'] = worst([node['state'], 'bad'])
                for x in ref:
                    node['issues'].append(_issue('high', 'server', 'The listener refused ' + str(x.get('refused')) + ' connection(s) from ' + mach + ' to ' + str(x.get('service') or db),
                                                 ['TNS-' + str(c.get('code')) + ' ' + str(c.get('meaning') or '') for c in x.get('reasons') or []], [c.get('fix') for c in x.get('reasons') or [] if c.get('fix')] or ['Look up the TNS code in the listener log.']))
            servers.append(node)
        svcs = [s.upper() for s in a.get('services') or []]
        svc_issues, svc_state = [], 'info'
        if svcs and lst:
            for x in lst:
                if str(x.get('service') or '').upper() in svcs and int(x.get('refused') or 0) > 0:
                    svc_state = 'bad'
                    svc_issues.append(_issue('high', 'service', 'Service ' + str(x.get('service')) + ': ' + str(x.get('refused')) + ' refused from ' + str(x.get('client_host')),
                                             ['TNS-' + str(c.get('code')) + ' ' + str(c.get('meaning') or '') for c in x.get('reasons') or []], [c.get('fix') for c in x.get('reasons') or [] if c.get('fix')]))
        if svcs and svc_state != 'bad' and sess and sess.get('reported'):
            seen = {str(x.get('service') or '').upper() for x in rows if x.get('state') != 'dropped'}
            miss = [s for s in svcs if s not in seen]
            svc_state = 'warn' if miss else 'ok'
            if miss:
                svc_issues.append(_issue('medium', 'service', 'No session on service ' + ', '.join(miss), [], ['Check the service runs on its preferred instances (srvctl status service -d ' + (db.lower() or '<db>') + ') and the connect string of the application.']))
        service = {'state': svc_state if svcs else 'not_connected', 'title': ', '.join(svcs) or 'Database service', 'sub': 'listener' if svcs else 'no service linked', 'issues': svc_issues}
        dbn = _db_node(a, D)
        nodes = [front] + apis + servers + [service, dbn]
        iss = [i for n in nodes for i in n['issues']]
        iss.sort(key=lambda i: SEV_ORDER.get(i['severity'], 9))
        st = worst([n['state'] for n in nodes if n['state'] not in ('not_connected', 'not_checked')]) if any(n['state'] not in ('not_connected', 'not_checked') for n in nodes) else 'not_connected'
        out_apps.append({'id': a.get('id'), 'name': a.get('name'), 'url': a.get('url') or '', 'database': db, 'state': st,
                         'front': front, 'apis': apis, 'servers': servers, 'service': service, 'db': dbn, 'issues': iss})
        all_issues += [dict(i, app=a.get('name')) for i in iss]
    # discovered: client machines connected to a database that no application claims, and monitors nobody linked
    disc = []
    for db, s in (S or {}).items():
        groups = {}
        for x in (s or {}).get('apps') or []:
            k = _short(x.get('machine'))
            if not k or k in used.get(db.upper(), set()):
                continue
            g = groups.setdefault(k, {'database': db.upper(), 'machine': x.get('machine'), 'programs': set(), 'services': set(), 'sessions': 0, 'dropped': False})
            if x.get('program'):
                g['programs'].add(str(x.get('program')))
            if x.get('service'):
                g['services'].add(str(x.get('service')))
            if x.get('state') == 'dropped':
                g['dropped'] = True
            else:
                g['sessions'] += int(x.get('sessions') or 0)
        for g in groups.values():
            g['programs'], g['services'] = sorted(g['programs'])[:8], sorted(g['services'])[:8]
            disc.append(g)
    disc.sort(key=lambda g: (g['database'], -g['sessions']))
    unlinked = [{'id': m.get('id'), 'name': m.get('name'), 'type': m.get('type'), 'host': m.get('host'), 'state': monitor_state(m)[0]} for k, m in M.items() if k not in linked_m]
    all_issues.sort(key=lambda i: SEV_ORDER.get(i['severity'], 9))
    return {'apps': out_apps, 'issues': all_issues, 'discovered': disc[:300], 'unlinked_monitors': unlinked[:500],
            'summary': {'apps': len(out_apps), 'down': sum(1 for a in out_apps if a['state'] == 'down'), 'failing': sum(1 for a in out_apps if a['state'] == 'bad'),
                        'warning': sum(1 for a in out_apps if a['state'] == 'warn'), 'ok': sum(1 for a in out_apps if a['state'] == 'ok'),
                        'discovered': len(disc), 'sessions_visible': S is not None, 'apm_connected': apm_ok}}


OPS = {'approute.assess': assess}
