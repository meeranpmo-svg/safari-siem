// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* ===================== ZS-DISCOVERY — Asset Discovery (the organisation portal) =====================
   Views: discovery (dashboard) · discovery-scopes · discovery-results · discovery-runs · discovery-credentials.
   Live-only: every figure is read at runtime from the sentra-itam engine (/api/itam/discovery/*) over the portal session;
   when the engine cannot be reached the page says so and shows nothing else.
   System Admin (portal role "admin", from /auth/whoami) adds scopes, completes the mandatory pre-scan SAFETY GATE,
   manages write-only credentials, runs / cancels scans, approves / ignores / merges results and connects assets to the
   SIEM. Operators and viewers see results read-only; the engine enforces the same rules.
   Strict ES5, no libraries, inline-SVG charts. Arabic via T() + window.X_AR (discovery.ar.json, merged by as_addmod.py);
   engine evidence (IPs, MACs, reasons, server messages) is shown left-to-right.                                     */
(function () {
  if (typeof viewHTML !== 'function') return;
  /* version guard: this module is also loaded as a portal add-on (/dashboards/vendor/discovery-module.js via zyb-menu.js)
     so a newer copy can take over the pages from the one built into the portal; an equal or newer copy never loads twice */
  var MODULE_VERSION = 13;
  if ((window.__asDscVersion || 0) >= MODULE_VERSION) return;
  var OVERLAY = !!window._asDscWired;   // an older copy is already wired (the one built into the portal)
  window.__asDscVersion = MODULE_VERSION;
  var VIEWS = { 'discovery': dash, 'discovery-scopes': scopes, 'discovery-results': results, 'discovery-runs': runs, 'discovery-credentials': creds };
  var API = '/api/itam/discovery';
  var PLATFORM_IP = ZYB_ORG.platform_addr;
  var TTL = 20000;

  /* ── i18n / escaping ── */
  function N(s) { return s; }   /* marks an English string that is translated later with T() */
  function isAr() { try { return typeof LANG !== 'undefined' && LANG === 'ar'; } catch (e) { return false; } }
  function T(en) { var r = en; try { if (typeof t === 'function') r = t(en); } catch (e) { /* portal function not available on this page: carry on without it */ } if (r === en && isAr() && window.X_AR && Object.prototype.hasOwnProperty.call(window.X_AR, en)) r = window.X_AR[en]; return r; }
  function TF(tpl, o) { return T(tpl).replace(/\{(\w+)\}/g, function (m, k) { return o && o[k] != null ? String(o[k]) : m; }); }
  function E(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function ltr(s) { return '<span dir="ltr" class="dsc-mono">' + E(s) + '</span>'; }
  function enc(s) { return encodeURIComponent(String(s == null ? '' : s)); }
  function toast(m) { try { if (typeof infoToast === 'function') infoToast(m); } catch (e) { /* portal function not available on this page: carry on without it */ } }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function when(iso) { if (!iso) return '—'; var d = new Date(typeof iso === 'number' ? iso : String(iso)); if (isNaN(d.getTime())) return String(iso); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }

  /* ── label maps (English keys; translated at render with T) ── */
  var TYPE_L = { server: N('Server'), workstation: N('Workstation'), 'switch': N('Switch'), router: N('Router'), firewall: N('Firewall'), ap: N('Access point'), printer: N('Printer'), phone: N('IP phone'), vm: N('Virtual machine'), cloud: N('Cloud instance'), unknown: N('Unknown') };
  var TYPES = ['server', 'workstation', 'switch', 'router', 'firewall', 'ap', 'printer', 'phone', 'vm', 'cloud', 'unknown'];
  var STATUS_L = { 'new': N('New'), approved: N('Approved'), ignored: N('Ignored'), merged: N('Merged') };
  var STATUS_C = { 'new': '#ffd54f', approved: '#69f0ae', ignored: '#90a4ae', merged: '#4fc3f7' };
  var RUN_L = { running: N('Running'), finished: N('Finished'), cancelled: N('Cancelled'), failed: N('Failed'), stopped_window: N('Stopped (window closed)'), interrupted: N('Interrupted'), queued: N('Queued') };
  var RUN_C = { running: '#4fc3f7', finished: '#69f0ae', cancelled: '#90a4ae', failed: '#ff6e7f', stopped_window: '#ffd54f', interrupted: '#ff8a65', queued: '#a9c7e3' };
  var TRIG_L = { manual: N('Manual'), schedule: N('Scheduled') };
  var METHOD_L = { sweep: N('Network sweep (ICMP / TCP)'), snmp: N('SNMP'), arp: N('ARP table'), ad: N('Active Directory'), vcenter: N('VMware vCenter'), nutanix: N('Nutanix Prism'), db: N('Database listeners (Oracle, SQL Server, MySQL, PostgreSQL)'), unix: N('Solaris / Unix servers (SSH banner)'), storage: N('Storage arrays and NAS (iSCSI, NFS, NDMP)'), hyperv: N('Hyper-V (agent report)'), cucm: N('Cisco CUCM phones'), azure: N('Microsoft Azure'), aws: N('Amazon Web Services'), icmp: N('ICMP') };
  var METHODS = ['sweep', 'snmp', 'db', 'unix', 'storage', 'arp', 'ad', 'vcenter', 'nutanix', 'hyperv', 'cucm', 'azure', 'aws'];
  var ACTIVE = { sweep: 1, snmp: 1, db: 1, unix: 1, storage: 1 };
  var METHOD_CRED = { snmp: ['snmp_v2c', 'snmp_v3'], db: ['db_login'], unix: ['ssh'], storage: ['storage_api'], ad: ['ldap'], vcenter: ['vcenter'], nutanix: ['nutanix'], cucm: ['cucm_axl'], azure: ['azure'], aws: ['aws'] };
  var KIND_L = { snmp_v2c: N('SNMP v2c community'), snmp_v3: N('SNMP v3 user'), ssh: N('SSH login (read-only commands)'), db_login: N('Database login (read-only)'), storage_api: N('Storage API login (NetApp / HPE MSA, read-only)'), winrm: N('WinRM (stored for future use)'), ldap: N('LDAP / Active Directory bind'), vcenter: N('VMware vCenter (read-only)'), nutanix: N('Nutanix Prism (read-only)'), cucm_axl: N('Cisco CUCM AXL (read-only)'), azure: N('Azure app registration (Reader)'), aws: N('AWS access key (EC2 read-only)') };
  var KINDS = ['snmp_v2c', 'snmp_v3', 'ldap', 'vcenter', 'nutanix', 'cucm_axl', 'azure', 'aws', 'ssh', 'db_login', 'storage_api', 'winrm'];
  var ERR_L = { auth: N('Authentication failed'), timeout: N('Timed out'), unreachable: N('Unreachable'), tls: N('TLS certificate not trusted'), config: N('Configuration error'), protocol: N('Unexpected response'), not_supported: N('Not executed (stored for future use)'), unavailable: N('Unavailable'), vault: N('Vault unavailable'), error: N('Failed') };
  var SIEM_L = { receiving: N('Receiving'), silent: N('Silent'), waiting: N('Waiting for first event'), missing: N('Missing in SIEM') };
  var SIEM_C = { receiving: '#69f0ae', silent: '#ff6e7f', waiting: '#ffd54f', missing: '#ff6e7f' };
  var DUP_L = { mac: N('MAC address'), serial: N('Serial number'), hostname: N('Host name') };
  var STRENGTH_L = { strong: N('Strong match'), weak: N('Weak hint') };
  var DAY_L = [N('Sunday'), N('Monday'), N('Tuesday'), N('Wednesday'), N('Thursday'), N('Friday'), N('Saturday')];
  var AUDIT_L = {
    'discovery.scope.create': N('Scope created'), 'discovery.scope.update': N('Scope changed'), 'discovery.scope.enable': N('Scope enabled'), 'discovery.scope.disable': N('Scope disabled'),
    'discovery.scope.archive': N('Scope archived'), 'discovery.scope.checklist': N('Pre-scan checklist completed'), 'discovery.scope.checklist.revoke': N('Pre-scan checklist revoked'),
    'discovery.scan.start': N('Scan started'), 'discovery.scan.finish': N('Scan finished'), 'discovery.scan.cancel': N('Scan cancelled'),
    'discovery.approve': N('Device approved'), 'discovery.ignore': N('Device ignored'), 'discovery.restore': N('Device restored'), 'discovery.merge': N('Device merged'),
    'discovery.credential.create': N('Credential added'), 'discovery.credential.update': N('Credential changed'), 'discovery.credential.delete': N('Credential deleted'), 'discovery.credential.test': N('Credential tested'),
    'discovery.connect': N('Connected to SIEM'), 'discovery.methods.update': N('Method switches changed'), 'discovery.hyperv.report': N('Hyper-V report received'), 'findings.sync': N('Alerts refreshed')
  };
  /* credential form fields per kind: [field, label, input type, secret?] */
  /* credentials that are tested against one host (inside a gate-open scope) */
  var HOST_TEST = { snmp_v2c: 1, snmp_v3: 1, ssh: 1, db_login: 1, storage_api: 1 };
  var KIND_FIELDS = {
    snmp_v2c: [['community', N('Community string'), 'password', 1], ['port', N('UDP port (default 161)'), 'number', 0]],
    snmp_v3: [['user', N('User name'), 'password', 1], ['auth_protocol', N('Authentication protocol'), 'sel:sha,sha256', 0], ['auth_password', N('Authentication passphrase (min 8)'), 'password', 1], ['priv_protocol', N('Privacy protocol'), 'sel:aes,none', 0], ['priv_password', N('Privacy passphrase (min 8)'), 'password', 1], ['port', N('UDP port (default 161)'), 'number', 0]],
    ssh: [['username', N('User name'), 'password', 1], ['password', N('Password'), 'password', 1], ['private_key', N('Private key (PEM)'), 'textarea-secret', 1], ['port', N('Port'), 'number', 0]],
    db_login: [['engine', N('Database engine'), 'sel:oracle,mssql,mysql,postgres', 0], ['port', N('Port (blank = the engine default)'), 'number', 0], ['service', N('Oracle service name (Oracle only)'), 'text', 0], ['database', N('Database to connect to (optional)'), 'text', 0], ['tls', N('Encryption in transit'), 'sel:require,verify,off', 0], ['ca_file', N('CA certificate file on the platform server (for verify; SQL Server always)'), 'text', 0], ['username', N('User name'), 'password', 1], ['password', N('Password'), 'password', 1]],
    storage_api: [['platform', N('Array type'), 'sel:ontap,msa', 0], ['port', N('HTTPS port (default 443)'), 'number', 0], ['username', N('User name'), 'password', 1], ['password', N('Password'), 'password', 1]],
    winrm: [['username', N('User name'), 'password', 1], ['password', N('Password'), 'password', 1], ['transport', N('Transport'), 'sel:https,http', 0], ['port', N('Port'), 'number', 0]],
    ldap: [['servers', N('Directory servers (one per line, ldaps://host:636)'), 'lines', 0], ['ip', N('Dial IP for the first server (optional)'), 'text', 0], ['base_dn', N('Search base DN'), 'text', 0], ['ca_file', N('CA certificate file on the platform server'), 'text', 0], ['bind_dn', N('Bind DN (service account)'), 'password', 1], ['password', N('Password'), 'password', 1]],
    vcenter: [['base_url', N('vCenter URL (https://…)'), 'text', 0], ['ca_file', N('CA certificate file on the platform server'), 'text', 0], ['tls_fingerprint', N('Approved certificate SHA-256 fingerprint (self-signed only)'), 'text', 0], ['username', N('User name'), 'password', 1], ['password', N('Password'), 'password', 1]],
    nutanix: [['base_url', N('Prism Central or cluster URL (https://…, port 9440)'), 'text', 0], ['ca_file', N('CA certificate file on the platform server'), 'text', 0], ['tls_fingerprint', N('Approved certificate SHA-256 fingerprint (self-signed only)'), 'text', 0], ['username', N('User name'), 'password', 1], ['password', N('Password'), 'password', 1]],
    cucm_axl: [['host', N('CUCM publisher host'), 'text', 0], ['port', N('Port (default 8443)'), 'number', 0], ['axl_version', N('AXL schema version (e.g. 12.5)'), 'text', 0], ['ca_file', N('CA certificate file on the platform server'), 'text', 0], ['username', N('User name'), 'password', 1], ['password', N('Password'), 'password', 1]],
    azure: [['tenant_id', N('Tenant ID'), 'text', 0], ['client_id', N('Application (client) ID'), 'text', 0], ['subscriptions', N('Subscription IDs (one per line, optional)'), 'lines', 0], ['client_secret', N('Client secret'), 'password', 1]],
    aws: [['regions', N('Regions (one per line, e.g. me-south-1)'), 'lines', 0], ['access_key_id', N('Access key ID'), 'password', 1], ['secret_access_key', N('Secret access key'), 'password', 1]]
  };

  /* ── Connect Wizard: per-field inline help + correct defaults/ports. The FIELD LIST itself comes from the engine
     (vault.KINDS, via /credentials.kinds) so it can never silently diverge; this map only adds help text + defaults. ── */
  var WIZ_HELP = {
    'vcenter.base_url': { help: N('The vCenter address, e.g. https://<ip> or https://vcenter.example.com'), def: 'https://' },
    'vcenter.username': { help: N('Full SSO form — e.g. administrator@vsphere.local (a bare name fails).') },
    'vcenter.password': { help: N('To avoid problems, use a service account with an ASCII password.') },
    'vcenter.ca_file': { help: N('Leave the certificate blank — a self-signed certificate is trusted and pinned automatically on the first test.') },
    'vcenter.tls_fingerprint': { help: N('Leave blank — Trust & pin fills this in from the first test (TOFU).') },
    'nutanix.base_url': { help: N('Prism Central (all clusters) or one cluster, e.g. https://10.0.12.30:9440 — port 9440 is used when none is given.'), def: 'https://' },
    'nutanix.username': { help: N('A local Prism user or a directory user (user@domain) with the Viewer role.') },
    'nutanix.ca_file': { help: N('Leave the certificate blank — a self-signed certificate is trusted and pinned automatically on the first test.') },
    'nutanix.tls_fingerprint': { help: N('Leave blank — Trust & pin fills this in from the first test (TOFU).') },
    'ldap.servers': { help: N('One per line: ldaps://<dc>:636 (LDAPS) or ldap://<dc>:389 (StartTLS).'), def: 'ldaps://' },
    'ldap.ip': { help: N('Optional dial IP for the first server; the certificate is still checked against the DNS name.') },
    'ldap.base_dn': { help: N('Search base, e.g. DC=corp-hq,DC=com') },
    'ldap.ca_file': { help: N('PEM file of the directory root CA on the platform server.') },
    'ldap.bind_dn': { help: N('Service account DN, e.g. CN=svc-discovery,OU=Service Accounts,DC=corp-hq,DC=com') },
    'ldap.password': { help: N('The bind account password.') },
    'snmp_v2c.community': { help: N('The read-only community string.') },
    'snmp_v2c.port': { help: N('UDP port — default 161.'), def: 161 },
    'snmp_v3.user': { help: N('The SNMPv3 USM user name.') },
    'snmp_v3.port': { help: N('UDP port — default 161.'), def: 161 },
    'snmp_v3.auth_password': { help: N('Authentication passphrase (at least 8 characters).') },
    'snmp_v3.priv_password': { help: N('Privacy passphrase (at least 8 characters); leave blank if privacy is None.') },
    'cucm_axl.host': { help: N('CUCM publisher host or IP.') },
    'cucm_axl.port': { help: N('Port — default 8443.'), def: 8443 },
    'cucm_axl.axl_version': { help: N('AXL schema version — e.g. 12.5.'), def: '12.5' },
    'cucm_axl.ca_file': { help: N('CA certificate file on the platform server (optional).') },
    'cucm_axl.username': { help: N('AXL user with the Standard AXL Read Only API Access role.') },
    'azure.tenant_id': { help: N('Directory (tenant) ID — a GUID.') },
    'azure.client_id': { help: N('Application (client) ID of the app registration — a GUID.') },
    'azure.subscriptions': { help: N('Optional: one subscription GUID per line; blank means all the app can read.') },
    'azure.client_secret': { help: N('The app registration client secret (assign it the Reader role).') },
    'ssh.username': { help: N('A read-only account on the Solaris / Unix servers (no root needed; serial and model may need it).') },
    'ssh.port': { help: N('SSH port — default 22.'), def: 22 },
    'db_login.engine': { help: N('One credential per engine. Oracle: an account with CREATE SESSION and SELECT_CATALOG_ROLE; SQL Server: a login with VIEW SERVER STATE; MySQL / PostgreSQL: any login.') },
    'db_login.service': { help: N('Oracle only: the service name, e.g. ORCL or PRODDB.') },
    'db_login.tls': { help: N('require = the login and every query are encrypted (TLS 1.2+; Oracle over TCPS, usually port 2484). verify = also checks the server certificate and name - SAMA 3.3.9. off = plaintext: shown as a finding on Credential Security.') },
    'storage_api.platform': { help: N('NetApp ONTAP: a user with the readonly role for the http application. HPE MSA: a user with the monitor role.') },
    'aws.regions': { help: N('One per line, e.g. me-south-1.'), def: 'me-south-1' },
    'aws.access_key_id': { help: N('Access key ID of an IAM user limited to ec2:DescribeInstances.') },
    'aws.secret_access_key': { help: N('The matching secret access key.') }
  };
  var GEN_HELP = { port: N('Network port.'), username: N('The service account user name.'), password: N('The service account password.') };
  /* result card text, keyed by the engine result (error_class / stage / http) so Arabic works too */
  var STAGE_T = { tls: N('TLS / certificate problem'), auth: N('Credentials rejected'), authz: N('Missing read privilege'), connect: N('Could not connect'), config: N('Configuration problem'), protocol: N('Unexpected response'), read: N('Connected'), none: N('Not tested') };
  var STAGE_C = { tls: '#ffd54f', auth: '#ff6e7f', authz: '#ff8a65', connect: '#ff6e7f', config: '#ff8a65', protocol: '#ff8a65', read: '#69f0ae', none: '#90a4ae' };

  /* ── live state + API cache ── */
  var ST = { who: null, whoDone: false, cache: {}, ui: {}, sel: {}, rf: { status: 'new', type: '', site: '', method: '', q: '', rogue: false } };
  function getJ(url, opt) {
    opt = opt || {};
    var o = { cache: 'no-store', credentials: 'same-origin', method: opt.method || 'GET', headers: {} };
    if (opt.body != null) { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(opt.body); }
    return fetch(url, o).then(function (r) {
      var ct = (r.headers && r.headers.get && r.headers.get('content-type')) || '';
      var pj = ct.indexOf('json') >= 0 ? r.json().catch(function () { return null; }) : Promise.resolve(null);
      return pj.then(function (j) { return { status: r.status, ok: r.ok, j: j }; });
    });
  }
  function api(path) {
    var c = ST.cache[path];
    if (c && c.state === 'loading') return c;
    if (c && (c.state === 'ok' || c.state === 'err') && Date.now() - c.at < TTL) return c;
    ST.cache[path] = { state: 'loading', at: Date.now() };
    getJ(API + path).then(function (x) { ST.cache[path] = { state: x.ok ? 'ok' : 'err', code: x.status, data: x.j, at: Date.now() }; })
      .catch(function () { ST.cache[path] = { state: 'err', code: 0, data: null, at: Date.now() }; })
      .then(function () { repaint(); });
    return ST.cache[path];
  }
  function invalidate(prefix) { var k; for (k in ST.cache) if (Object.prototype.hasOwnProperty.call(ST.cache, k) && (!prefix || k.indexOf(prefix) === 0)) delete ST.cache[k]; }
  function down(c) { return c && c.state === 'err' && (c.code === 0 || c.code >= 500); }
  function post(path, body, okMsg, cb) {
    getJ(API + path, { method: 'POST', body: body || {} }).then(function (x) {
      if (x.ok) { if (okMsg) toast(T(okMsg)); if (cb) cb(x.j); return; }
      ST.ui.err = (x.j && x.j.error) || ('HTTP ' + x.status);
      toast(x.status === 403 ? T('Your role is not allowed to do this.') : T('The engine refused the request') + ': ' + ST.ui.err);
      repaint();
    }).catch(function () { toast(T('The asset discovery service could not be reached.')); });
  }
  function whoami() {
    if (ST.whoDone) return;
    ST.whoDone = true;
    fetch('/auth/whoami', { cache: 'no-store', credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { ST.who = j; }).catch(function () { /* identity unknown: treated as signed out of the menu extras */ }).then(function () { ST.whoLoaded = true; repaint(); });
  }
  function role() { try { if (ST.who && ST.who.role) return String(ST.who.role).toLowerCase(); } catch (e) { /* identity not read yet: treated as no role below */ } return 'viewer'; }
  function isAdmin() { return role() === 'admin'; }
  function cur() { try { return typeof currentView !== 'undefined' ? currentView : ''; } catch (e) { return ''; } }
  function mine() { return Object.prototype.hasOwnProperty.call(VIEWS, cur()); }
  function typing() { var a = document.activeElement; if (!a) return false; var tg = a.tagName; if (tg !== 'INPUT' && tg !== 'TEXTAREA' && tg !== 'SELECT') return false; return !!(a.closest && a.closest('#dsc-root')); }
  function repaint() { if (typeof document === 'undefined' || !document || !document.getElementById) return; if (!document.getElementById('dsc-root')) return; if (!mine()) return; if (typing()) return; try { renderFocus(); } catch (e) { /* portal function not available on this page: carry on without it */ } try { qcredRestore(); } catch (e) { /* portal function not available on this page: carry on without it */ } }
  function val(id) { var el = document.getElementById(id); return el ? String(el.value == null ? '' : el.value).trim() : ''; }
  function checked(id) { var el = document.getElementById(id); return !!(el && el.checked); }
  function lines(s) { return String(s || '').split(/[\r\n,]+/).map(function (x) { return x.trim(); }).filter(function (x) { return !!x; }); }

  /* ── building blocks (all text arguments are already translated) ── */
  function head(title, count) { try { if (typeof _vhead === 'function') return _vhead(title, count || ''); } catch (e) { /* portal function not available on this page: carry on without it */ } return '<div class="vhead"><h2>' + E(title) + '</h2><span class="vcount">' + E(count || '') + '</span></div>'; }
  function card(icon, title, right, body, cls) { return '<div class="card ' + (cls || '') + '"><h3>' + (icon ? E(icon) + ' ' : '') + E(title) + (right ? '<span class="dsc-right">' + right + '</span>' : '') + '</h3>' + body + '</div>'; }
  function tile(v, label, color) { return '<div class="noc-stat"><div class="v"' + (color ? ' style="color:' + color + '"' : '') + '>' + v + '</div><div class="k">' + E(label) + '</div></div>'; }
  function pill(text, color) { return '<span class="dsc-pill" style="background:' + color + '22;color:' + color + ';border-color:' + color + '66">' + E(text) + '</span>'; }
  function empty(text) { return '<div class="dsc-empty">' + E(text) + '</div>'; }
  function note(text) { return '<div class="dsc-note">ℹ️ ' + E(text) + '</div>'; }
  function tbl(cols, rows) { return '<div class="dsc-scroll"><table><thead><tr>' + cols.map(function (c) { return '<th>' + E(c) + '</th>'; }).join('') + '</tr></thead><tbody>' + rows + '</tbody></table></div>'; }
  function btn(label, data, cls) { return '<button type="button" class="btn ' + (cls || '') + '" ' + data + '>' + E(label) + '</button>'; }
  // the guided single-server page (dashboards/server/add-server.html): one form instead of credential + scope + checklist + trust
  function easyBtn() { return '<a class="btn" style="text-decoration:none" href="/dashboards/add-server.html" target="_blank" rel="noopener">➕ ' + E(T('Add a server (easy)')) + '</a>'; }
  // "oracle 1600, 1601; mssql 51433" <-> {oracle: [1600, 1601], mssql: [51433]} (the engine validates engines and ranges)
  function portsText(p) { var o = [], k; p = p || {}; for (k in p) if (Object.prototype.hasOwnProperty.call(p, k) && p[k] && p[k].length) o.push(k + ' ' + p[k].join(', ')); return o.join('; '); }
  function parsePorts(s) {
    var out = {}; String(s || '').split(/[;\n]+/).forEach(function (part) {
      var m = /^\s*([a-z0-9]+)\s*[: ]\s*([\d,\s]+)$/i.exec(part); if (!m) return;
      var e = m[1].toLowerCase(), ps = m[2].split(/[,\s]+/).filter(function (x) { return !!x; }).map(Number);
      out[e] = (out[e] || []).concat(ps);
    });
    return out;
  }
  function easyBar() { return isAdmin() ? '<div style="display:flex;justify-content:flex-end">' + easyBtn() + '</div>' : ''; }
  function goBtn(view, label) { return '<button type="button" class="dsc-link" data-dsc-go="' + E(view) + '">' + E(label) + ' →</button>'; }
  function input(id, label, type, value, extra) { return '<label class="dsc-f">' + E(label) + '<input id="' + id + '" type="' + (type || 'text') + '" value="' + E(value == null ? '' : value) + '"' + (extra || '') + '></label>'; }
  function area(id, label, value, extra) { return '<label class="dsc-f">' + E(label) + '<textarea id="' + id + '" rows="3"' + (extra || '') + '>' + E(value == null ? '' : value) + '</textarea></label>'; }
  function select(id, label, opts, value) { return '<label class="dsc-f">' + E(label) + '<select id="' + id + '">' + opts.map(function (o) { return '<option value="' + E(o[0]) + '"' + (String(o[0]) === String(value == null ? '' : value) ? ' selected' : '') + '>' + E(o[1]) + '</option>'; }).join('') + '</select></label>'; }
  function check(id, label, on) { return '<label class="dsc-c"><input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + '> ' + E(label) + '</label>'; }
  function bars(rows) {
    if (!rows.length) return empty(T('No data yet'));
    var max = 1; rows.forEach(function (r) { if (r.v > max) max = r.v; });
    var y = 4, h = rows.length * 24 + 8, out = '';
    rows.forEach(function (r) {
      var w = Math.round(r.v / max * 160), row = '<rect x="0" y="' + y + '" width="330" height="22" fill="transparent"/><text x="0" y="' + (y + 13) + '" font-size="11" fill="var(--muted)">' + E(r.l) + '</text><rect x="110" y="' + (y + 3) + '" width="' + w + '" height="12" rx="3" fill="' + r.c + '"/><text x="' + (114 + w) + '" y="' + (y + 13) + '" font-size="11" font-weight="700" fill="var(--txt,#eef6ff)">' + r.v + '</text>';
      // r.go = {type|status}: the row opens Results with that filter (click or Enter)
      out += r.go ? '<g class="dsc-bar-go" data-dsc-rf="1"' + (r.go.type ? ' data-type="' + E(r.go.type) + '"' : '') + (r.go.status ? ' data-st="' + E(r.go.status) + '"' : '') + ' role="link" tabindex="0" aria-label="' + E(TF('Show {what} in Results', { what: r.l })) + '"><title>' + E(TF('Show {what} in Results', { what: r.l })) + '</title>' + row + '</g>' : row;
      y += 24;
    });
    return '<svg viewBox="0 0 330 ' + h + '" width="100%" height="' + h + '" role="img">' + out + '</svg>';
  }
  var PAL = ['#4fc3f7', '#69f0ae', '#ffd54f', '#ff8a65', '#ba68c8', '#4dd0e1', '#f06292', '#aed581', '#7986cb', '#90a4ae', '#ffb74d'];
  function stateCard(c, title) {
    if (down(c)) return head(title, '') + card('🔌', T('Asset discovery service'), '', '<div class="dsc-empty"><b>' + E(T('Not connected')) + '</b><div>' + E(T('The asset discovery service is not reachable right now. Nothing is shown until it answers.')) + '</div></div>');
    if (c && c.state === 'err' && c.code === 403) return head(title, '') + card('🔒', T('Administrators only'), '', empty(T('Your role is not allowed to view this page.')));
    if (c && c.state === 'err') return head(title, '') + card('⚠️', T('Could not load'), '', empty(T('The engine refused the request') + ' (' + c.code + ')'));
    return head(title, '') + card('⏳', T('Loading'), '', '<div class="dsc-empty">' + E(T('Loading…')) + '</div>');
  }
  function methodName(m) { return T(METHOD_L[m] || m); }
  function blockedText(b) {
    var r = String(b.reason || '');
    if (r.indexOf('safety gate') === 0) return T('Safety gate: pre-scan checklist not completed');
    if (r.indexOf('disabled globally') === 0) return T('Disabled globally');
    if (r.indexOf('outside the scan window') === 0) { var m = /(\d\d:\d\d-\d\d:\d\d)/.exec(r); return T('Outside the scan window') + (m ? ' ' + m[1] : ''); }
    return r;
  }
  function schedText(s) {
    if (!s || s.type === 'manual') return T('Manual only');
    if (s.type === 'once') return TF('Once on {at} (Riyadh time)', { at: String(s.at || '').replace('T', ' ') });
    if (s.type === 'daily') return TF('Daily at {time} (Riyadh time)', { time: s.time });
    return TF('Weekly on {day} at {time} (Riyadh time)', { day: T(DAY_L[s.day] || ''), time: s.time });
  }
  function errText(cls) { return T(ERR_L[cls] || ERR_L.error); }

  /* ── css (once) ── */
  function css() {
    if (document.getElementById('dsc-css')) return '';
    var s = document.createElement('style'); s.id = 'dsc-css';
    s.textContent = '' +
      '#dsc-root{display:flex;flex-direction:column;gap:14px}' +
      '#dsc-root .dsc-right{margin-inline-start:auto;font-size:11px;display:inline-flex;gap:6px;align-items:center}' +
      '#dsc-root .card h3{display:flex;align-items:center;gap:6px;flex-wrap:wrap}' +
      '#dsc-root .dsc-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}' +
      '#dsc-root .dsc-grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}' +
      '#dsc-root .dsc-pill{display:inline-block;border:1px solid;border-radius:999px;padding:1px 9px;font-size:11px;font-weight:700;white-space:nowrap}' +
      '#dsc-root .dsc-empty{color:var(--muted);text-align:center;padding:20px 12px;border:1px dashed var(--line);border-radius:12px;font-size:13px}' +
      '#dsc-root .dsc-note{color:var(--muted);font-size:11.5px;border:1px solid var(--line);border-radius:8px;padding:8px 12px;line-height:1.55;margin:8px 0}' +
      '#dsc-root .dsc-mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px}' +
      '#dsc-root .dsc-scroll{overflow:auto}' +
      '#dsc-root .dsc-grpw{display:flex;flex-wrap:wrap;gap:4px 2px}#dsc-root .dsc-grp{border-color:rgba(255,255,255,.12);padding:3px 9px;margin-inline-end:4px}#dsc-root .dsc-grp b{color:#4fc3f7;margin-inline-start:4px}#dsc-root .dsc-grp.on{border-color:#4fc3f7;background:rgba(79,195,247,.18)}' +
      '#dsc-root .dsc-chip{background:none;border:1px solid transparent;border-radius:9px;padding:2px 4px;margin-inline-end:8px;color:inherit;font:inherit;cursor:pointer}#dsc-root .dsc-chip:hover,#dsc-root .dsc-chip:focus-visible{border-color:rgba(79,195,247,.5);background:rgba(79,195,247,.08)}' +
      '#dsc-root .dsc-bar-go{cursor:pointer}#dsc-root .dsc-bar-go:hover rect:first-child,#dsc-root .dsc-bar-go:focus rect:first-child{fill:rgba(79,195,247,.10)}#dsc-root .dsc-bar-go:focus{outline:none}' +
      '#dsc-root .dsc-link{border:1px solid rgba(79,195,247,.4);background:rgba(79,195,247,.10);color:inherit;border-radius:9px;padding:4px 10px;font-weight:700;font-size:12px;cursor:pointer}' +
      '#dsc-root .dsc-gate{border:2px solid #ff6e7f;background:rgba(255,110,127,.08)}' +
      '#dsc-root .dsc-gate-ok{border:1px solid rgba(105,240,174,.5)}' +
      '#dsc-root .dsc-gate b.big{font-size:15px;color:#ff6e7f}' +
      '#dsc-root .dsc-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px;margin:8px 0}' +
      '#dsc-root .dsc-f{display:flex;flex-direction:column;gap:4px;font-size:11.5px;color:var(--muted)}' +
      '#dsc-root .dsc-c{display:flex;gap:7px;align-items:flex-start;font-size:12.5px;margin:5px 0}' +
      '#dsc-root .dsc-filters{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px}' +
      '#dsc-root .dsc-row{cursor:pointer}#dsc-root .dsc-row:hover{background:rgba(79,195,247,.08)}' +
      '#dsc-root .dsc-scope{border:1px solid var(--line);border-radius:12px;padding:12px;margin:10px 0}' +
      '#dsc-root .dsc-kv{display:grid;grid-template-columns:170px 1fr;gap:4px 10px;font-size:12px}#dsc-root .dsc-kv .k{color:var(--muted)}' +
      '#dsc-root .dsc-once{border:2px solid #ffd54f;background:rgba(255,213,79,.08)}' +
      '#dsc-root .dsc-secret{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;background:rgba(3,29,51,.5);border:1px solid rgba(79,195,247,.4);border-radius:8px;padding:8px 10px}' +
      '#dsc-root .dsc-pre{white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;background:rgba(3,29,51,.35);border:1px solid var(--line);border-radius:8px;padding:8px 10px}' +
      '#dsc-root .dsc-acts{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}' +
      '#dsc-root .dsc-wizard{border:1px solid rgba(79,195,247,.5)}' +
      '#dsc-root .dsc-wsteps{display:flex;gap:8px;flex-wrap:wrap;margin:4px 0 10px}' +
      '#dsc-root .dsc-wstep{font-size:11.5px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:2px 10px}' +
      '#dsc-root .dsc-wstep.on{color:#4fc3f7;border-color:#4fc3f7;font-weight:700}#dsc-root .dsc-wstep.done{color:#69f0ae;border-color:rgba(105,240,174,.5)}' +
      '#dsc-root .dsc-wpicks{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}' +
      '#dsc-root .dsc-wf{display:flex;flex-direction:column;gap:2px}' +
      '#dsc-root .dsc-help{font-size:10.5px;color:var(--muted);line-height:1.5}' +
      '#dsc-root .dsc-result-msg{font-size:13.5px;font-weight:600;margin:6px 0;line-height:1.5}' +
      '#dsc-root .dsc-bulkbar{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px;padding:8px;border:1px solid var(--line);border-radius:10px}' +
      '#dsc-root .dsc-selcell{width:28px;text-align:center}#dsc-root .dsc-selbox{cursor:pointer}' +
      '@media(max-width:1000px){#dsc-root .dsc-grid2{grid-template-columns:1fr}}';
    document.head.appendChild(s); return '';
  }

  /* ════════════ discovery · DASHBOARD ════════════ */
  function dash() {
    var c = api('/dashboard');
    if (c.state !== 'ok' || !c.data) return stateCard(c, T('Asset Discovery'));
    var d = c.data;
    var h = head(T('Asset Discovery'), TF('{n} devices discovered', { n: d.devices.total }));
    var pend = (d.scopes && d.scopes.gate_pending) || [];
    var gate = pend.length
      ? card('🛑', T('Safety gate: active scanning is blocked'), '', '<b class="big">' + E(TF('{n} scope(s) cannot run network sweeps or SNMP yet', { n: pend.length })) + '</b>'
        + '<p>' + E(TF('A System Admin must complete the pre-scan checklist first: firewall rules from {ip} (SNMP UDP 161, SSH 22, WinRM 5985/5986, ICMP), the SOC notified of the scan window, and the approver named. Passive sources (Active Directory, vCenter, Hyper-V, CUCM, cloud, ARP table) still run.', { ip: PLATFORM_IP })) + '</p>'
        + '<ul>' + pend.map(function (s) { return '<li>' + E(s.name) + ' — ' + E(s.site) + '</li>'; }).join('') + '</ul>' + goBtn('discovery-scopes', T('Open scopes')), 'dsc-gate')
      : card('✅', T('Safety gate'), '', note(T('Every scope with active methods has a completed pre-scan checklist. Changing a scope\'s addresses closes its gate again.')), 'dsc-gate-ok');
    var a = d.assets || {};
    var cov = covMaps();
    var covTile = cov.loaded && cov.reachable && cov.summary ? tile(E(cov.summary.covered + '/' + cov.summary.total), T('Logging to SIEM'), (cov.summary.absent || cov.summary.silent) ? '#ffd54f' : '#69f0ae') : '';
    var stats = '<div class="dsc-stats">' + tile(E(a.total), T('Total assets')) + tile(E(a.connected), T('Connected to SIEM'), '#69f0ae') + tile(E(a.not_connected), T('Not connected to SIEM'), '#ffd54f')
      + tile(E(d.new_since_last_scan), T('New since last scan'), '#4fc3f7') + tile(E(d.rogue.count), T('Unknown / rogue devices'), d.rogue.count ? '#ff6e7f' : '') + tile(E(a.silent), T('Silent SIEM sources'), a.silent ? '#ff6e7f' : '') + covTile + '</div>';
    var rows = (d.rogue.items || []).map(function (r) {
      return '<tr class="dsc-row" data-dsc-row="' + E(r.id) + '"><td>' + ltr(r.ip || '—') + '</td><td>' + ltr(r.mac || '—') + '</td><td>' + E(r.vendor || T('Unknown vendor')) + '</td><td>' + E(T(TYPE_L[r.type] || 'Unknown')) + '</td><td>' + E(r.site || '—') + '</td><td>' + E(r.seen_count) + '</td><td>' + E(r.infra ? T('Unknown device on a server/infrastructure subnet') : TF('Unknown device seen {n} times', { n: r.seen_count })) + '</td></tr>';
    }).join('');
    var rogue = card('🚨', T('Rogue / unknown device alerts'), goBtn('discovery-results', T('Review results')), rows ? tbl([T('IP'), T('MAC'), T('Vendor'), T('Type'), T('Site'), T('Seen'), T('Why')], rows) + note(T('Not in the CMDB, not ignored, seen repeatedly or on a server/infrastructure subnet. Approve, merge or ignore each one in Results.')) : empty(T('No unknown devices right now')));
    var bt = TYPES.filter(function (k) { return d.devices.by_type[k]; }).map(function (k, i) { return { l: T(TYPE_L[k]), v: d.devices.by_type[k], c: PAL[i % PAL.length], go: { type: k } }; });
    var bs = d.devices.by_status || {};
    var statusRow = ['new', 'approved', 'merged', 'ignored'].map(function (k) { return '<button type="button" class="dsc-chip" data-dsc-rf="1" data-st="' + k + '" title="' + E(TF('Show {what} in Results', { what: T(STATUS_L[k]) })) + '">' + pill(T(STATUS_L[k]), STATUS_C[k]) + ' <b>' + E(bs[k] || 0) + '</b></button>'; }).join('');
    var allDev = api('/results?status=all&limit=5000'), devs = allDev.state === 'ok' && allDev.data ? allDev.data.devices || [] : null;
    var groups = devs && devs.length ? card('🗂️', T('Discovered devices by operating system and brand'), goBtn('discovery-results', T('Review results')),
      '<div class="dsc-f">' + E(T('Operating system')) + '</div><div class="dsc-grpw">' + grpChips('os', groupCounts(devs, function (x) { return osFamily(x.os); }), '', 12) + '</div>'
      + '<div class="dsc-f" style="margin-top:8px">' + E(T('Hardware brand')) + '</div><div class="dsc-grpw">' + grpChips('brand', groupCounts(devs, brandOf), '', 12) + '</div>'
      + note(T('Click one to open those devices in Results.'))) : '';
    var types = card('🏷️', T('Discovered devices by type'), goBtn('discovery-results', T('Review results')), '<div style="margin-bottom:8px">' + statusRow + '</div>' + bars(bt) + note(T('Click a status or a type to open those devices in Results.')));
    var ls = d.last_scan;
    var runBody = (ls ? '<div class="dsc-kv"><span class="k">' + E(T('Last scan')) + '</span><span>' + E(ls.scope) + ' · ' + pill(T(RUN_L[ls.status] || ls.status), RUN_C[ls.status] || '#a9c7e3') + ' · ' + E(when(ls.finished_at)) + '</span><span class="k">' + E(T('Devices seen / new')) + '</span><span>' + E(ls.devices_seen) + ' / ' + E(ls.devices_new) + '</span></div>' : empty(T('No scan has finished yet')))
      + (d.running.length ? '<h4>' + E(T('Running now')) + '</h4>' + d.running.map(function (r) { return '<div>' + E(r.scope_name) + ' — ' + E((r.progress && r.progress.hosts_done) || 0) + '/' + E((r.progress && r.progress.hosts_total) || 0) + '</div>'; }).join('') : '')
      + (d.next_runs.length ? '<h4>' + E(T('Next scheduled scans')) + '</h4>' + d.next_runs.map(function (n) { return '<div>' + E(n.name) + ' — ' + E(when(n.at)) + '</div>'; }).join('') : '');
    var runCard = card('⏱️', T('Scans'), goBtn('discovery-runs', T('All runs')), runBody);
    var vaultWarn = d.vault && !d.vault.available && isAdmin() ? card('🔐', T('Credential vault unavailable'), '', note(T('The vault key file is missing on the platform server, so credentials cannot be stored or used. See the installation guide.'))) : '';
    var easy = !isAdmin() ? (ST.whoLoaded ? note(TF('Adding a server needs the System Admin role - you are signed in as {role}.', { role: role() })) : '') : card('➕', T('Add one server'), easyBtn(), note(T('One form: IP, site and a read-only login. It scans, asks you to confirm the server\'s SSH key, and adds it to IT Asset Management.')));
    return h + easy + gate + stats + rogue + '<div class="dsc-grid2">' + types + runCard + '</div>' + groups + siemCard() + vaultWarn
      + note(T('Live data from the asset discovery engine. Nothing is added to the inventory until a System Admin approves it.'));
  }

  function siemCard() {
    var c = api('/connect');
    if (c.state !== 'ok' || !c.data) return card('🔗', T('SIEM log sources'), '', empty(T('Loading…')));
    var conns = c.data.connections || [], cands = c.data.candidates || [];
    var rows = conns.map(function (x) {
      return '<tr><td>' + E(x.name || x.asset_id) + '</td><td>' + ltr(x.source_id) + (x.via ? '<div class="muted" style="font-size:10.5px">↪ ' + ltr(x.via) + '</div>' : '') + '</td><td>' + ltr(x.kind) + '</td><td>' + pill(T(SIEM_L[x.state] || 'Waiting for first event'), SIEM_C[x.state] || '#ffd54f') + (x.alert ? ' ' + pill(T('Alert'), '#ff6e7f') : '') + '</td><td>' + E(when(x.last_seen)) + '</td></tr>';
    }).join('');
    var candRows = cands.map(function (x) {
      return '<tr><td>' + E(x.name || x.asset_id) + '</td><td>' + ltr(x.mgmt_ip || '—') + '</td><td>' + E(T(TYPE_L[x['class']] || 'Unknown')) + '</td><td>' + (x.suggested_kind ? ltr(x.suggested_kind) : E(T('Choose manually'))) + '</td><td>' + (isAdmin() && x.suggested_kind ? btn(T('Connect'), 'data-dsc-connect="' + E(x.asset_id) + '" data-kind="' + E(x.suggested_kind) + '"', 'sm') : '') + '</td></tr>';
    }).join('');
    var right = isAdmin() ? '<button type="button" class="dsc-link" data-dsc="health">' + E(T('Check now')) + '</button>' : '';
    return card('🔗', T('SIEM log sources'), right, onceBox()
      + (rows ? tbl([T('Asset'), T('Source'), T('Connector'), T('State'), T('Last event')], rows) : empty(T('No asset is connected to the SIEM yet')))
      + (candRows ? '<h4>' + E(T('Approved assets not yet connected')) + '</h4>' + tbl([T('Asset'), T('IP'), T('Type'), T('Suggested connector'), ''], candRows) : '')
      + note(T('Connecting creates the log source in the SIEM and shows its one-time token and setup steps once. A connected source that goes silent raises an alert.')));
  }
  function onceBox() {
    var o = ST.ui.once; if (!o) return '';
    var steps = (o.instructions || []).map(function (i) { return '<div><b>' + E(i.title || '') + '</b><div class="dsc-pre" dir="ltr">' + E(i.body || '') + '</div></div>'; }).join('')
      + (o.steps || []).map(function (s) { return '<div class="dsc-pre" dir="ltr">' + E(typeof s === 'string' ? s : JSON.stringify(s)) + '</div>'; }).join('');
    return '<div class="card dsc-once"><h3>🔑 ' + E(T('Shown once — copy it now')) + '<span class="dsc-right"><button type="button" class="dsc-link" data-dsc="once-close">' + E(T('Close')) + '</button></span></h3>'
      + '<div class="dsc-kv"><span class="k">' + E(T('Source')) + '</span><span>' + ltr(o.source_id) + '</span><span class="k">' + E(T('Connector')) + '</span><span>' + ltr(o.kind) + '</span></div>'
      + (o.token ? '<div style="margin:8px 0">' + E(T('One-time token')) + '<div class="dsc-secret" dir="ltr">' + E(o.token) + '</div></div>' : '')
      + steps + note(T('The token is not stored by the asset service and cannot be shown again.')) + '</div>';
  }

  /* ════════════ discovery-scopes · SCOPES + SAFETY GATE ════════════ */
  function scopes() {
    var c = api('/scopes'); var m = api('/methods');
    if (c.state !== 'ok' || !c.data) return stateCard(c, T('Discovery Scopes'));
    var list = c.data.scopes || [];
    var h = head(T('Discovery Scopes'), TF('{n} scopes', { n: list.length }));
    var add = '<a class="btn" style="text-decoration:none" href="/dashboards/scope-studio.html" target="_blank" rel="noopener">✨ ' + E(T('Scope Studio (AI)')) + '</a> ' + (isAdmin() ? easyBtn() + ' <button type="button" class="btn" data-dsc="scope-new">➕ ' + E(T('Add scope')) + '</button>' : '');
    var form = ST.ui.scopeForm && isAdmin() ? scopeForm(ST.ui.scopeForm === 'new' ? null : list.filter(function (s) { return s.id === ST.ui.scopeForm; })[0], c.data.sites || []) : '';
    var body = list.length ? list.map(scopeBox).join('') : empty(T('No scope yet. A System Admin adds the address ranges to discover.'));
    return h + methodsCard(m) + card('🎯', T('Scopes'), add, form + body + (isAdmin() ? '' : note(T('Scopes, the safety gate and scans are managed by a System Admin.'))));
  }
  function methodsCard(m) {
    if (m.state !== 'ok' || !m.data) return '';
    var s = m.data.settings;
    var lst = METHODS.map(function (k) { return isAdmin() ? check('dsc_gm_' + k, methodName(k), s.methods[k] !== false) : '<div>' + (s.methods[k] !== false ? '✅ ' : '⛔ ') + E(methodName(k)) + '</div>'; }).join('');
    var extra = isAdmin() ? '<div class="dsc-form">' + input('dsc_gm_rogue', T('Rogue alert after this many sightings'), 'number', s.rogue_min_sightings) + input('dsc_gm_conc', T('Maximum concurrent scans'), 'number', s.max_concurrent_runs)
      + select('dsc_gm_icmp', T('ICMP tool'), [['fping', 'fping'], ['ping', 'ping']], s.icmp_mode) + '</div>' + btn(T('Save method switches'), 'data-dsc="methods-save"') : '';
    return card('🧰', T('Discovery methods (global switches)'), '', '<div class="dsc-form">' + lst + '</div>' + extra + note(T('Active methods (network sweep, SNMP) send packets to the scope and need the safety gate. Passive methods only read systems of record.')));
  }
  function scopeBox(s) {
    var gate = s.gate || {};
    var gb = !gate.required ? pill(T('Passive only — no gate needed'), '#4fc3f7') : gate.open ? pill(T('Safety gate open'), '#69f0ae') : pill(gate.stale ? T('Safety gate closed — addresses changed since approval') : T('Safety gate closed — active methods blocked'), '#ff6e7f');
    var meth = METHODS.filter(function (k) { return s.methods[k] && s.methods[k].enabled; }).map(function (k) { return pill(methodName(k) + (ACTIVE[k] ? ' · ' + T('active') : ''), ACTIVE[k] ? '#ff8a65' : '#4fc3f7'); }).join(' ');
    var blocked = (s.blocked_methods || []).map(function (b) { return '<div>⛔ ' + E(methodName(b.method)) + ': ' + E(blockedText(b)) + '</div>'; }).join('');
    var acts = isAdmin() ? '<div class="dsc-acts">' + btn(T('Run now'), 'data-dsc-run="' + E(s.id) + '"', 'sm') + btn(T('Edit'), 'data-dsc-edit="' + E(s.id) + '"', 'ghost sm')
      + btn(T('Pre-scan checklist'), 'data-dsc-check="' + E(s.id) + '"', 'ghost sm') + (s.status === 'active' ? btn(T('Disable'), 'data-dsc-scope-act="disable" data-id="' + E(s.id) + '"', 'ghost sm') : btn(T('Enable'), 'data-dsc-scope-act="enable" data-id="' + E(s.id) + '"', 'ghost sm'))
      + btn(T('Archive'), 'data-dsc-scope-act="archive" data-id="' + E(s.id) + '"', 'ghost sm') + '</div>' : '';
    var cl = s.checklist;
    var clInfo = cl ? '<div class="dsc-note">' + E(TF('Checklist completed by {by} on {at}; SOC notified: {soc} ({date}); approved by {appr}.', { by: cl.completed_by, at: when(cl.completed_at), soc: cl.soc_notified_name, date: cl.soc_notified_date, appr: cl.approved_by })) + '</div>' : '';
    return '<div class="dsc-scope"><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b>' + E(s.name) + '</b> ' + pill(s.status === 'active' ? T('Active') : T('Disabled'), s.status === 'active' ? '#69f0ae' : '#90a4ae') + ' ' + gb + (s.running_run_id ? ' ' + pill(T('Running'), '#4fc3f7') : '') + '</div>'
      + '<div class="dsc-kv" style="margin-top:6px"><span class="k">' + E(T('Site')) + '</span><span>' + E(s.site) + (s.vlan ? ' · VLAN ' + E(s.vlan) : '') + (s.infra ? ' · ' + E(T('Server / infrastructure subnet')) : '') + '</span>'
      + '<span class="k">' + E(T('Addresses')) + '</span><span>' + ltr((s.targets || []).join(', ') || '—') + ' (' + E(TF('{n} addresses', { n: s.host_count })) + ')' + (s.allow_public ? ' ' + pill(T('Public range allowed'), '#ff8a65') : '') + '</span>'
      + '<span class="k">' + E(T('Exclusions')) + '</span><span>' + ltr((s.exclusions || []).join(', ') || '—') + '</span>'
      + '<span class="k">' + E(T('Schedule')) + '</span><span>' + E(schedText(s.schedule)) + (s.next_run ? ' · ' + E(T('next')) + ' ' + E(when(s.next_run)) : '') + '</span>'
      + '<span class="k">' + E(T('Scan window')) + '</span><span>' + (s.window ? ltr(s.window.start + '–' + s.window.end) + ' ' + E(T('Riyadh time')) : E(T('Any time'))) + '</span>'
      + '<span class="k">' + E(T('Rate limit')) + '</span><span>' + E(TF('{r} hosts per second, {c} at a time', { r: s.rate.max_hosts_per_sec, c: s.rate.concurrency })) + '</span>'
      + '<span class="k">' + E(T('Methods')) + '</span><span>' + (meth || E(T('None enabled'))) + '</span></div>'
      + (blocked ? '<div class="dsc-note">' + blocked + '</div>' : '') + clInfo + (ST.ui.check === s.id && isAdmin() ? checklistForm(s) : '') + acts + '</div>';
  }
  function checklistForm(s) {
    var p = PLATFORM_IP;
    return '<div class="card dsc-gate"><h3>🛡️ ' + E(T('Pre-scan checklist (mandatory before any active scan)')) + '</h3>'
      + '<div>' + E(TF('Addresses covered: {t}', { t: (s.targets || []).join(', ') })) + '</div>'
      + check('dsc_cl_snmp', TF('The network firewall allows SNMP (UDP 161) from {ip} to this scope', { ip: p }))
      + check('dsc_cl_ssh', TF('The network firewall allows SSH (TCP 22) from {ip} to this scope', { ip: p }))
      + check('dsc_cl_winrm', TF('The network firewall allows WinRM (TCP 5985/5986) from {ip} to this scope', { ip: p }))
      + check('dsc_cl_icmp', TF('The network firewall allows ICMP echo from {ip} to this scope', { ip: p }))
      + '<div class="dsc-form">' + input('dsc_cl_soc', T('Security team / SOC contact notified of the scan window (name)'), 'text', '') + input('dsc_cl_date', T('Date notified'), 'date', '')
      + input('dsc_cl_appr', T('Approved by (name)'), 'text', '') + area('dsc_cl_note', T('Note (optional)'), '') + '</div>'
      + '<div class="dsc-acts">' + btn(T('Complete checklist'), 'data-dsc-check-save="' + E(s.id) + '"') + (s.checklist ? btn(T('Revoke checklist'), 'data-dsc-check-revoke="' + E(s.id) + '"', 'ghost') : '') + btn(T('Cancel'), 'data-dsc="check-cancel"', 'ghost') + '</div>'
      + note(T('Completing the checklist is recorded in the audit trail with your name. Changing the scope\'s addresses or exclusions closes the gate again.')) + '</div>';
  }
  var DB_ENGINES = [['oracle', 'Oracle (1521)'], ['mssql', 'SQL Server (1433)'], ['mysql', 'MySQL / MariaDB (3306)'], ['postgres', 'PostgreSQL (5432)'], ['db2', 'IBM Db2 (50000)'], ['mongodb', 'MongoDB (27017)'], ['hana', 'SAP HANA (3xx15)']];
  /* why a credential list is empty: only admins see credentials; none of this kind stored; vCenter / Nutanix can also be
     connected on the Virtualization page, which feeds Discovery itself (its login lives there, not in this vault) */
  function credHint(k) {
    if (!isAdmin()) return note(T('Only an administrator can choose the credential.'));
    var c = api('/credentials');
    if (!c || c.state !== 'ok' || !c.data) return '';
    var have = (c.data.credentials || []).some(function (x) { return METHOD_CRED[k].indexOf(x.kind) >= 0; });
    var qb = '<button type="button" class="btn sm" data-dsc-qcred="' + E(k) + '">➕ ' + E(T('Add a credential here')) + '</button>';
    if (have) return '<div style="margin:2px 0 6px">' + qb + '</div>';
    if (k === 'db' || k === 'unix' || k === 'storage') return '<div class="dsc-note">ℹ️ ' + E(TF('No {kind} is stored yet - add one here to log in; without it the scan only probes.', { kind: METHOD_CRED[k].map(function (x) { return T(KIND_L[x] || x); }).join(' / ') })) + ' ' + qb + '</div>';
    return '<div class="dsc-note">⚠️ ' + E(TF('No {kind} credential is stored yet, so there is nothing to choose. Add one here:', { kind: METHOD_CRED[k].map(function (x) { return T(KIND_L[x] || x); }).join(' / ') })) + ' ' + qb
      + (k === 'vcenter' || k === 'nutanix' ? ' ' + E(T('Or connect it on the Virtualization page instead - it feeds Discovery on its own, with no scope needed.')) + ' <a href="/dashboards/virtualization.html">' + E(T('Virtualization page')) + '</a>' : '') + '</div>';
  }
  /* "Add a credential here", from inside the scope form: a pop-up outside #dsc-root (so repaints leave it alone) saves
     the credential through the same /credentials route, then the scope form is repainted with what was typed in it and
     the new credential chosen - nobody has to leave a half-filled scope to visit the Credentials tab. */
  function qcredOpen(k) {
    var kinds = METHOD_CRED[k]; if (!kinds) return;
    var old = document.getElementById('dsc-qcred'); if (old) old.remove();
    var d = document.createElement('div'); d.id = 'dsc-qcred'; d.setAttribute('role', 'dialog'); d.setAttribute('aria-modal', 'true');
    d.style.cssText = 'position:fixed;inset:0;z-index:10060;background:rgba(0,0,0,.55);display:flex;align-items:flex-start;justify-content:center;padding:6vh 16px;overflow:auto';
    var fs = 'font:13px system-ui,sans-serif;background:#0b1520;color:#e6e9ef;border:1px solid rgba(255,255,255,.18);border-radius:7px;padding:7px 9px;width:100%;box-sizing:border-box';
    function field(f) {
      var id = 'dsc_qc_' + f[0], lab = '<span style="display:block;font-size:12px;color:#9aa4b2;margin:8px 0 3px">' + E(T(f[1])) + '</span>';
      if (f[2].indexOf('sel:') === 0) return '<label>' + lab + '<select id="' + id + '" style="' + fs + '">' + f[2].slice(4).split(',').map(function (o) { return '<option>' + E(o) + '</option>'; }).join('') + '</select></label>';
      if (f[2] === 'lines' || f[2] === 'textarea-secret') return '<label>' + lab + '<textarea id="' + id + '" dir="ltr" rows="3" spellcheck="false" style="' + fs + ';font-family:Consolas,monospace"></textarea></label>';
      return '<label>' + lab + '<input id="' + id + '" type="' + (f[2] === 'number' ? 'number' : f[3] ? 'password' : 'text') + '" dir="ltr" spellcheck="false"' + (f[3] ? ' autocomplete="new-password"' : '') + ' style="' + fs + '"></label>';
    }
    function paint(kind) {
      d.innerHTML = '<div style="background:#13151b;border:1px solid #2e3440;border-radius:12px;padding:16px 18px;width:min(520px,100%);color:#eceef2">'
        + '<h3 style="margin:0 0 4px;font-size:16px">➕ ' + E(T('Add credential')) + ' - ' + E(methodName(k)) + '</h3>'
        + '<div style="font-size:12px;color:#9aa4b2">' + E(T('Stored encrypted; the secret is never shown again.')) + '</div>'
        + (kinds.length > 1 ? '<label><span style="display:block;font-size:12px;color:#9aa4b2;margin:8px 0 3px">' + E(T('Kind')) + '</span><select id="dsc_qc_kind" style="' + fs + '">' + kinds.map(function (x) { return '<option value="' + E(x) + '"' + (x === kind ? ' selected' : '') + '>' + E(T(KIND_L[x] || x)) + '</option>'; }).join('') + '</select></label>' : '')
        + '<label><span style="display:block;font-size:12px;color:#9aa4b2;margin:8px 0 3px">' + E(T('Label')) + '</span><input id="dsc_qc_label" style="' + fs + '" placeholder="' + E(T(KIND_L[kind] || kind)) + '"></label>'
        + (KIND_FIELDS[kind] || []).map(field).join('')
        + '<div id="dsc_qc_err" style="color:#ff7b72;font-size:12.5px;margin-top:8px"></div>'
        + '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px"><button type="button" class="btn ghost sm" data-qc="cancel">' + E(T('Cancel')) + '</button><button type="button" class="btn sm" data-qc="save">' + E(T('Save credential')) + '</button></div></div>';
      var ks = document.getElementById('dsc_qc_kind'); if (ks) ks.onchange = function () { paint(ks.value); };
      d.setAttribute('data-kind', kind);
      var first = d.querySelector('#dsc_qc_label'); if (first) first.focus();
    }
    function close() { d.remove(); document.removeEventListener('keydown', esc, true); }
    function esc(ev) { if (ev.key === 'Escape') close(); }
    d.addEventListener('click', function (ev) {
      if (ev.target === d) { close(); return; }
      var b = ev.target.closest && ev.target.closest('[data-qc]'); if (!b) return;
      if (b.getAttribute('data-qc') === 'cancel') { close(); return; }
      var kind = d.getAttribute('data-kind'), secret = {}, target = {};
      (KIND_FIELDS[kind] || []).forEach(function (f) {
        var v = val('dsc_qc_' + f[0]); if (!v) return;
        if (f[3]) secret[f[0]] = v; else if (f[2] === 'lines') target[f[0]] = lines(v); else if (f[2] === 'number') target[f[0]] = Number(v); else target[f[0]] = v;
      });
      var snap = {};   // what is typed in the scope form, put back after the repaint
      [].forEach.call(document.querySelectorAll('#dsc-root [id^="dsc_sf_"]'), function (el) { snap[el.id] = el.type === 'checkbox' ? { c: el.checked } : { v: el.value }; });
      b.disabled = true;
      getJ(API + '/credentials', { method: 'POST', body: { kind: kind, label: val('dsc_qc_label') || T(KIND_L[kind] || kind), secret: secret, target: target } }).then(function (x) {
        if (!x.ok || !x.j || !x.j.credential) { b.disabled = false; document.getElementById('dsc_qc_err').textContent = x.status === 403 ? T('Your role is not allowed to do this.') : T('The engine refused the request') + ': ' + ((x.j && x.j.error) || ('HTTP ' + x.status)); return; }
        snap['dsc_sf_m_' + k] = { c: true };
        ST.ui.restore = { snap: snap, k: k, cid: x.j.credential.id };
        close(); toast(T('Credential saved and selected')); invalidate('/credentials'); repaint();
      }).catch(function () { b.disabled = false; document.getElementById('dsc_qc_err').textContent = T('The asset discovery service could not be reached.'); });
    });
    document.addEventListener('keydown', esc, true);
    document.body.appendChild(d); paint(kinds[0]);
  }
  // after the credentials reload: the scope form gets back what was typed, and the new credential is chosen
  function qcredRestore() {
    var R = ST.ui.restore; if (!R) return;
    var sel = document.getElementById('dsc_sf_cred_' + R.k), box = document.getElementById('dsc_sf_dbc_' + R.cid);
    var ready = (sel && [].some.call(sel.options, function (o) { return o.value === R.cid; })) || box;
    Object.keys(R.snap).forEach(function (id) { var el = document.getElementById(id), v = R.snap[id]; if (!el) return; if ('c' in v) el.checked = v.c; else el.value = v.v; });
    if (!ready) return;   // the list is still loading - the next repaint finishes the job
    if (sel) sel.value = R.cid; if (box) box.checked = true;
    ST.ui.restore = null;
  }
  function credList(kinds) { var c = isAdmin() ? api('/credentials') : null; var list = c && c.state === 'ok' && c.data ? c.data.credentials : []; return list.filter(function (x) { return kinds.indexOf(x.kind) >= 0; }); }
  function credChecks(prefix, kinds, on) { return credList(kinds).map(function (x) { return check(prefix + x.id, x.label + (x.target && x.target.engine ? ' (' + x.target.engine + ')' : ''), on.indexOf(x.id) >= 0); }).join(''); }
  function credIds(prefix, kinds) { return credList(kinds).filter(function (x) { return checked(prefix + x.id); }).map(function (x) { return x.id; }); }
  function credOptions(kinds) {
    var c = isAdmin() ? api('/credentials') : null;
    var list = c && c.state === 'ok' && c.data ? c.data.credentials : [];
    return [['', T('— choose —')]].concat(list.filter(function (x) { return kinds.indexOf(x.kind) >= 0; }).map(function (x) { return [x.id, x.label + ' (' + T(KIND_L[x.kind] || x.kind) + ')']; }));
  }
  function scopeForm(s, sites) {
    s = s || { methods: {}, rate: { max_hosts_per_sec: 20, concurrency: 8 }, schedule: { type: 'manual' } };
    var mth = s.methods || {};
    var sc = s.schedule || { type: 'manual' };
    var methRows = METHODS.map(function (k) {
      var m = mth[k] || {};
      var extra = '';
      if (k === 'sweep') extra = check('dsc_sf_icmp', T('ICMP echo (ping)'), m.icmp !== false) + input('dsc_sf_ports', T('TCP ports to probe'), 'text', (m.tcp_ports || [22, 80, 135, 443, 445, 3389, 5985]).join(', '));
      else if (k === 'snmp') extra = select('dsc_sf_cred_snmp', T('SNMP credential'), credOptions(METHOD_CRED.snmp), (m.credential_ids || [])[0] || '') + credHint(k);
      else if (k === 'db') extra = '<div class="dsc-f">' + E(T('Engines to look for')) + '</div>' + DB_ENGINES.map(function (e) { return check('dsc_sf_dbe_' + e[0], e[1], !m.engines || m.engines.indexOf(e[0]) >= 0); }).join('')
        + input('dsc_sf_dbports', T('Non-standard listener ports (e.g. oracle 1600, 1601; mssql 51433) - a database login\'s own port is tried automatically'), 'text', portsText(m.ports), ' dir="ltr" placeholder="oracle 1600; mssql 51433"')
        + '<div class="dsc-f">' + E(T('Database logins (optional - one per engine)')) + '</div>' + credChecks('dsc_sf_dbc_', METHOD_CRED.db, m.credential_ids || []) + credHint(k)
        + note(T('Without a login it only records which database listener answers. With a login for that engine it also reads the version, edition, instance and database names - fixed read-only queries, nothing is changed.'));
      else if (k === 'unix' || k === 'storage') extra = select('dsc_sf_cred_' + k, k === 'unix' ? T('SSH login (optional)') : T('Storage API login (optional)'), [['', T('— none: probe only, no login —')]].concat(credOptions(METHOD_CRED[k]).slice(1)), m.credential_id || '') + credHint(k)
        + note(k === 'unix' ? T('Without a login the OS is recognised from the SSH banner and the Solaris ports. With a login it runs fixed read-only commands (uname, release, CPUs, memory, serial, model) - only on servers whose SSH host key you trusted under Credentials → Trust.') : T('Without a login arrays are found by their iSCSI / NDMP ports. With a NetApp ONTAP / HPE MSA read-only login it reads the name, model, serial and version - only from arrays whose certificate is trusted. Health and capacity monitoring: Storage page; backup servers: Backup Coverage page.'))
        + (k === 'storage' ? '<div class="dsc-note">🔗 <a href="/dashboards/storage.html#plat">' + E(T('Storage page')) + '</a> · <a href="/dashboards/backup.html">' + E(T('Backup Coverage page')) + '</a></div>' : '');
      else if (METHOD_CRED[k]) extra = select('dsc_sf_cred_' + k, T('Credential'), credOptions(METHOD_CRED[k]), m.credential_id || '') + credHint(k);
      return '<div class="dsc-scope">' + check('dsc_sf_m_' + k, methodName(k) + (ACTIVE[k] ? ' — ' + T('active, needs the safety gate') : ''), !!m.enabled) + extra + '</div>';
    }).join('');
    return '<div class="card"><h3>' + E(s.id ? T('Edit scope') : T('Add scope')) + '</h3><div class="dsc-form">'
      + input('dsc_sf_name', T('Name'), 'text', s.name) + select('dsc_sf_site', T('Site'), sites.map(function (x) { return [x, x]; }), s.site)
      + input('dsc_sf_vlan', T('VLAN ID (optional)'), 'number', s.vlan) + input('dsc_sf_label', T('Label (optional)'), 'text', s.label)
      + area('dsc_sf_targets', T('Addresses: CIDR, range or IP (one per line)'), (s.targets || []).join('\n'), ' dir="ltr"') + area('dsc_sf_excl', T('Exclusions (one per line)'), (s.exclusions || []).join('\n'), ' dir="ltr"')
      + select('dsc_sf_stype', T('Schedule'), [['manual', T('Manual only')], ['once', T('Once')], ['daily', T('Daily')], ['weekly', T('Weekly')]], sc.type)
      + input('dsc_sf_at', T('Date and time (once, Riyadh time)'), 'datetime-local', sc.at || '') + input('dsc_sf_time', T('Time (daily / weekly, Riyadh time)'), 'time', sc.time || '02:00')
      + select('dsc_sf_day', T('Day (weekly)'), DAY_L.map(function (d, i) { return [i, T(d)]; }), sc.day == null ? 5 : sc.day)
      + input('dsc_sf_wstart', T('Scan window start (optional)'), 'time', s.window ? s.window.start : '') + input('dsc_sf_wend', T('Scan window end'), 'time', s.window ? s.window.end : '')
      + input('dsc_sf_rate', T('Maximum hosts per second'), 'number', s.rate.max_hosts_per_sec) + input('dsc_sf_conc', T('Hosts probed at the same time'), 'number', s.rate.concurrency) + '</div>'
      + check('dsc_sf_public', T(('Allow a public (non-RFC 1918) range — only ranges ' + ZYB_ORG.short + ' owns')), !!s.allow_public) + check('dsc_sf_infra', T('Server / infrastructure subnet (unknown devices alert immediately)'), !!s.infra)
      + '<h4>' + E(T('Methods for this scope')) + '</h4>' + methRows
      + '<div class="dsc-acts">' + btn(T('Save scope'), 'data-dsc-scope-save="' + E(s.id || '') + '"') + btn(T('Cancel'), 'data-dsc="scope-cancel"', 'ghost') + '</div>'
      + note(T('Changing addresses or exclusions closes the safety gate until the checklist is completed again.')) + '</div>';
  }
  function scopeBody() {
    var methods = {};
    METHODS.forEach(function (k) {
      var m = { enabled: checked('dsc_sf_m_' + k) };
      if (k === 'sweep') { m.icmp = checked('dsc_sf_icmp'); m.tcp_ports = lines(val('dsc_sf_ports')).map(function (x) { return Number(x); }); }
      else if (k === 'snmp') { var cs = val('dsc_sf_cred_snmp'); m.credential_ids = cs ? [cs] : []; }
      else if (METHOD_CRED[k] && k !== 'db') m.credential_id = val('dsc_sf_cred_' + k) || null;
      else if (k === 'db') { m.engines = DB_ENGINES.map(function (e) { return e[0]; }).filter(function (e) { return checked('dsc_sf_dbe_' + e); }); if (!m.engines.length) delete m.engines; m.credential_ids = credIds('dsc_sf_dbc_', METHOD_CRED.db); m.ports = parsePorts(val('dsc_sf_dbports')); }
      methods[k] = m;
    });
    var st = val('dsc_sf_stype') || 'manual';
    var sched = st === 'once' ? { type: 'once', at: val('dsc_sf_at') } : st === 'daily' ? { type: 'daily', time: val('dsc_sf_time') } : st === 'weekly' ? { type: 'weekly', day: Number(val('dsc_sf_day')), time: val('dsc_sf_time') } : { type: 'manual' };
    return {
      name: val('dsc_sf_name'), site: val('dsc_sf_site'), vlan: val('dsc_sf_vlan') ? Number(val('dsc_sf_vlan')) : null, label: val('dsc_sf_label'),
      targets: lines(val('dsc_sf_targets')), exclusions: lines(val('dsc_sf_excl')), allow_public: checked('dsc_sf_public'), infra: checked('dsc_sf_infra'),
      schedule: sched, window: val('dsc_sf_wstart') && val('dsc_sf_wend') ? { start: val('dsc_sf_wstart'), end: val('dsc_sf_wend') } : null,
      rate: { max_hosts_per_sec: Number(val('dsc_sf_rate')) || 20, concurrency: Number(val('dsc_sf_conc')) || 8 }, methods: methods
    };
  }

  /* ════════════ SIEM log-coverage (are discovered assets actually sending logs?) ════════════ */
  var LOG_L = { covered: N('Logging'), silent: N('Silent'), absent: N('No logs'), unknown: N('SIEM unknown') };
  var LOG_C = { covered: '#69f0ae', silent: '#ffd54f', absent: '#ff6e7f', unknown: '#90a4ae' };
  function covMaps() {
    var c = api('/log-coverage');
    var ok = c.state === 'ok' && c.data;
    var list = ok ? (c.data.assets || []) : [];
    var byAsset = {}, byIp = {};
    list.forEach(function (p) { if (p.asset_id) byAsset[p.asset_id] = p; if (p.mgmt_ip) byIp[p.mgmt_ip] = p; });
    return { loaded: !!ok, reachable: !!(ok && c.data.siem_reachable), summary: ok ? c.data.summary : null, list: list, byAsset: byAsset, byIp: byIp };
  }
  function devLog(d, maps) { var p = (d.asset_id && maps.byAsset[d.asset_id]) || (d.ip && maps.byIp[d.ip]) || null; return p ? p.status : null; }
  function logBadge(status) { return status ? pill(T(LOG_L[status] || status), LOG_C[status] || '#90a4ae') : '—'; }
  function covSummaryLine(maps) {
    if (!maps.loaded) return '';
    if (!maps.reachable) return note('🔌 ' + T('SIEM coverage is unavailable right now (the SIEM could not be reached).'));
    var s = maps.summary || {};
    return note('📡 ' + TF('Logging to SIEM: {c}/{t} assets.', { c: s.covered || 0, t: s.total || 0 }) + ' ' + TF('{a} not sending, {i} silent.', { a: s.absent || 0, i: s.silent || 0 }));
  }
  function logGapCard(maps) {
    if (!maps.loaded || !maps.reachable) return '';
    var gaps = maps.list.filter(function (p) { return p.status === 'absent'; });
    var body;
    if (!gaps.length) body = empty(T('Every asset has a matching SIEM log source.'));
    else body = tbl([T('Asset'), T('IP'), T('Type'), ''], gaps.map(function (p) {
      return '<tr><td>' + E(p.name || p.asset_id) + (p.is_server ? ' ' + pill(T('Server'), '#ff8a65') : '') + '</td><td>' + ltr(p.mgmt_ip || '—') + '</td><td>' + E(T(TYPE_L[p.type] || 'Unknown')) + '</td><td>' + (isAdmin() && p.asset_id ? btn(T('Onboard to SIEM'), 'data-dsc-connect="' + E(p.asset_id) + '"', 'sm') : '') + '</td></tr>';
    }).join(''));
    return card('📡', T('Not sending logs to the SIEM'), '', body + note(T('An asset is matched to a SIEM source by IP, then host name, then MAC. Onboard a missing one with one click (it reuses the SIEM connect flow).')));
  }

  /* ════════════ discovery-results · REVIEW ════════════ */

  /* ── grouping: operating system family and hardware brand, from what discovery reported (never guessed) ── */
  var OS_RULES = [[/windows server\s*(\d{4}(\s*r2)?)/i, function (m) { return 'Windows Server ' + m[1].toUpperCase().replace(/\s+/, ' '); }], [/windows\s*(11|10|8\.1|8|7)\b/i, function (m) { return 'Windows ' + m[1]; }], [/windows/i, 'Windows (other)'],
    [/esxi/i, 'VMware ESXi'], [/\bahv\b|nutanix/i, 'Nutanix AHV'], [/red ?hat|rhel/i, 'Red Hat Enterprise Linux'], [/oracle linux/i, 'Oracle Linux'], [/ubuntu/i, 'Ubuntu'], [/centos/i, 'CentOS'], [/suse|sles/i, 'SUSE Linux'], [/debian/i, 'Debian'], [/linux/i, 'Linux (other)'],
    [/solaris|sunos/i, 'Solaris'], [/\baix\b/i, 'AIX'], [/fortios/i, 'FortiOS'], [/pan-?os/i, 'PAN-OS'], [/ios[ -]?xe/i, 'Cisco IOS XE'], [/nx-?os/i, 'Cisco NX-OS'], [/cisco ios|\bios\b.*cisco|cisco.*\bios\b/i, 'Cisco IOS'],
    [/junos/i, 'Junos'], [/aos-?cx|arubaos|instant on/i, 'ArubaOS'], [/mac ?os|os x|darwin/i, 'macOS'], [/android/i, 'Android'], [/iphone|ipad|\bios\b/i, 'Apple iOS'], [/ontap/i, 'NetApp ONTAP']];
  function osFamily(os) {
    var t = String(os || '').trim(); if (!t) return T('Not identified');
    for (var i = 0; i < OS_RULES.length; i++) { var m = OS_RULES[i][0].exec(t); if (m) return typeof OS_RULES[i][1] === 'function' ? OS_RULES[i][1](m) : OS_RULES[i][1]; }
    return t.split(/[\s,;(]+/).slice(0, 2).join(' ');
  }
  var BRANDS = [[/hewlett packard enterprise|\bhpe\b/i, 'HPE'], [/aruba/i, 'Aruba (HPE)'], [/hewlett|^hp\b|\bhp inc/i, 'HP'], [/dell/i, 'Dell'], [/lenovo/i, 'Lenovo'], [/\bibm\b/i, 'IBM'], [/oracle|sun micro/i, 'Oracle / Sun'],
    [/cisco|meraki/i, 'Cisco'], [/fortinet|fortigate/i, 'Fortinet'], [/palo ?alto/i, 'Palo Alto Networks'], [/juniper/i, 'Juniper'], [/huawei/i, 'Huawei'], [/vmware/i, 'VMware (virtual)'], [/microsoft|hyper-v/i, 'Microsoft'],
    [/nutanix/i, 'Nutanix'], [/supermicro|super micro/i, 'Supermicro'], [/netapp/i, 'NetApp'], [/xerox/i, 'Xerox'], [/canon/i, 'Canon'], [/ricoh/i, 'Ricoh'], [/kyocera/i, 'Kyocera'], [/brother/i, 'Brother'], [/epson/i, 'Epson'],
    [/apple/i, 'Apple'], [/samsung/i, 'Samsung'], [/intel/i, 'Intel'], [/realtek/i, 'Realtek'], [/hikvision/i, 'Hikvision'], [/dahua/i, 'Dahua'], [/axis/i, 'Axis'], [/apc|schneider/i, 'APC / Schneider'], [/grandstream/i, 'Grandstream'], [/yealink/i, 'Yealink'], [/polycom|poly\b/i, 'Poly']];
  function brandOf(d) {
    var t = String((d && (d.vendor || d.vendor_hint)) || '').trim(); if (!t) return T('Unknown brand');
    for (var i = 0; i < BRANDS.length; i++) if (BRANDS[i][0].test(t)) return BRANDS[i][1];
    return t.replace(/[,.]?\s+(inc|corp|corporation|co|ltd|limited|llc|gmbh|technologies|technology|networks|systems|international|electronics)\.?$/ig, '').replace(/[,.]+$/, '').trim() || t;
  }
  function groupCounts(list, fn) { var m = {}, out = []; list.forEach(function (d) { var k = fn(d); m[k] = (m[k] || 0) + 1; }); for (var k in m) if (Object.prototype.hasOwnProperty.call(m, k)) out.push([k, m[k]]); return out.sort(function (a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); }); }
  function grpChips(kind, counts, active, max) {
    var shown = counts.slice(0, max || 40);
    return shown.map(function (c) { var on = active === c[0]; return '<button type="button" class="dsc-chip dsc-grp' + (on ? ' on' : '') + '" data-dsc-grp="' + kind + '" data-v="' + E(c[0]) + '" aria-pressed="' + (on ? 'true' : 'false') + '" title="' + E(TF('Show {what} in Results', { what: c[0] })) + '">' + E(c[0]) + ' <b>' + E(c[1]) + '</b></button>'; }).join('')
      + (counts.length > shown.length ? ' <span class="muted">' + E(TF('+{n} more', { n: counts.length - shown.length })) + '</span>' : '');
  }
  function groupCard(base) {
    var f = ST.rf;
    return card('🗂️', T('Group by operating system and brand'), (f.os || f.brand) ? '<button type="button" class="dsc-link" data-dsc="grp-clear">' + E(T('Clear')) + '</button>' : '',
      '<div class="dsc-f">' + E(T('Operating system')) + '</div><div class="dsc-grpw">' + grpChips('os', groupCounts(base, function (d) { return osFamily(d.os); }), f.os) + '</div>'
      + '<div class="dsc-f" style="margin-top:8px">' + E(T('Hardware brand')) + '</div><div class="dsc-grpw">' + grpChips('brand', groupCounts(base, brandOf), f.brand) + '</div>'
      + note(T('Click to show only those devices; click again to show all. Brand is the vendor discovery reported (network card maker, SNMP, vCenter, login); "VMware (virtual)" means a virtual machine.')));
  }
  function rq() { var f = ST.rf, q = []; if (f.status) q.push('status=' + enc(f.status)); if (f.type) q.push('type=' + enc(f.type)); if (f.site) q.push('site=' + enc(f.site)); if (f.method) q.push('method=' + enc(f.method)); if (f.q) q.push('q=' + enc(f.q)); q.push('limit=5000'); return '?' + q.join('&'); }
  function results() {
    var path = '/results' + rq();
    var c = api(path);
    if (c.state !== 'ok' || !c.data) return stateCard(c, T('Discovery Results'));
    var base = (c.data.devices || []).filter(function (d) { return !ST.rf.rogue || d.rogue; });
    var list = base.filter(function (d) { return (!ST.rf.os || osFamily(d.os) === ST.rf.os) && (!ST.rf.brand || brandOf(d) === ST.rf.brand); });
    var h = head(T('Discovery Results'), TF('{n} devices', { n: c.data.total }) + (ST.rf.os || ST.rf.brand ? ' · ' + TF('{n} shown', { n: list.length }) : ''));
    var f = ST.rf;
    var filters = '<div class="dsc-filters">'
      + select('dsc_rf_status', T('Decision'), [['new', T('New')], ['approved', T('Approved')], ['merged', T('Merged')], ['ignored', T('Ignored')], ['all', T('All')]], f.status)
      + select('dsc_rf_type', T('Type'), [['', T('All')]].concat(TYPES.map(function (k) { return [k, T(TYPE_L[k])]; })), f.type)
      + select('dsc_rf_method', T('Seen by'), [['', T('All')]].concat(METHODS.map(function (k) { return [k, methodName(k)]; })), f.method)
      + input('dsc_rf_q', T('Search'), 'search', f.q, ' placeholder="' + E(T('IP, MAC, host name, vendor…')) + '"')
      + check('dsc_rf_rogue', T('Rogue / unknown only'), f.rogue) + btn(T('Apply'), 'data-dsc="rf-apply"', 'ghost') + '</div>';
    var admin = isAdmin();
    var maps = covMaps();
    var rows = list.map(function (d) {
      var selCell = admin ? '<td class="dsc-selcell">' + (d.status === 'new' ? '<input type="checkbox" class="dsc-selbox" id="dsc_sel_' + E(d.id) + '"' + (ST.sel[d.id] ? ' checked' : '') + '>' : '') + '</td>' : '';
      return '<tr class="dsc-row" data-dsc-row="' + E(d.id) + '">' + selCell + '<td>' + pill(T(STATUS_L[d.status] || d.status), STATUS_C[d.status] || '#a9c7e3') + (d.rogue ? ' ' + pill(T('Rogue'), '#ff6e7f') : '') + '</td>'
        + '<td>' + E(T(TYPE_L[d.type] || 'Unknown')) + '</td><td>' + E(d.vendor || '—') + '</td><td>' + E(d.os || '—') + '</td><td>' + ltr(d.ip || '—') + '</td><td>' + ltr(d.mac || '—') + '</td>'
        + '<td>' + E(d.hostname || '—') + '</td><td>' + E(d.site || '—') + '</td><td>' + E(when(d.first_seen)) + '</td><td>' + E(when(d.last_seen)) + '</td>'
        + '<td>' + E((d.methods_seen || []).map(methodName).join(', ')) + '</td><td>' + E(d.confidence || 0) + '%</td><td>' + logBadge(devLog(d, maps)) + '</td></tr>';
    }).join('');
    var cols = (admin ? [''] : []).concat([T('Decision'), T('Type'), T('Vendor'), T('OS'), T('IP'), T('MAC'), T('Host name'), T('Site'), T('First seen'), T('Last seen'), T('Seen by'), T('Confidence'), T('Logs → SIEM')]);
    var table = rows ? tbl(cols, rows) : empty(T('No device matches these filters'));
    return h + easyBar() + filters + groupCard(base) + (ST.ui.sel ? drawer(ST.ui.sel) : '') + covSummaryLine(maps)
      + card('🧾', T('Discovered devices'), '', bulkBar(list) + table + note(T('Click a device to review it. Approve adopts it into the IT asset inventory (duplicates are matched by MAC address and serial number), Merge attaches it to an existing asset, Ignore remembers it with your reason.')))
      + logGapCard(maps);
  }
  function drawer(id) {
    var c = api('/results/' + enc(id));
    if (c.state !== 'ok' || !c.data) return card('🔎', T('Device'), '<button type="button" class="dsc-link" data-dsc="sel-close">' + E(T('Close')) + '</button>', empty(c.state === 'err' ? T('Could not load') : T('Loading…')));
    var d = c.data.device; var x = d.extra || {};
    var kv = [[T('Type'), T(TYPE_L[d.type] || 'Unknown') + ' (' + d.confidence + '%)'], [T('Vendor'), d.vendor || '—'], [T('OS'), d.os || '—'], [T('Model'), d.model || '—'], [T('Serial'), d.serial || '—'], [T('Host name'), d.hostname || d.fqdn || '—'], [T('Location'), d.location || '—'], [T('Site'), (d.site || '—') + (d.vlan ? ' · VLAN ' + d.vlan : '')], [T('Seen'), TF('{n} scans', { n: d.seen_count })]];
    var html = '<div class="dsc-kv">' + kv.map(function (p) { return '<span class="k">' + E(p[0]) + '</span><span>' + E(p[1]) + '</span>'; }).join('')
      + '<span class="k">' + E(T('IP addresses')) + '</span><span>' + ltr((d.ips || []).join(', ') || '—') + '</span><span class="k">' + E(T('MAC addresses')) + '</span><span>' + ltr((d.macs || []).join(', ') || '—') + '</span>'
      + '<span class="k">' + E(T('Open ports')) + '</span><span>' + ltr((d.open_ports || []).join(', ') || '—') + '</span><span class="k">' + E(T('Seen by')) + '</span><span>' + E((d.methods_seen || []).map(methodName).join(', ')) + '</span></div>';
    if (x.ad) html += '<h4>' + E(T('Active Directory')) + '</h4><div class="dsc-kv"><span class="k">' + E(T('OU')) + '</span><span>' + E(x.ad.ou || '—') + '</span><span class="k">' + E(T('Account enabled')) + '</span><span>' + E(x.ad.enabled ? T('Yes') : T('No')) + '</span><span class="k">' + E(T('Last logon')) + '</span><span>' + E(when(x.ad.last_logon)) + '</span><span class="k">' + E(T('Domain controller')) + '</span><span>' + E(x.ad.is_dc ? T('Yes') : T('No')) + '</span></div>';
    if (x.vcenter) html += '<h4>' + E(T('VMware vCenter')) + '</h4><div class="dsc-kv"><span class="k">' + E(T('ESXi host')) + '</span><span>' + E(x.vcenter.host || '—') + '</span><span class="k">' + E(T('Power state')) + '</span><span>' + E(x.vcenter.power_state || x.vcenter.state || '—') + '</span></div>';
    if (x.db && x.db.length) html += '<h4>' + E(T('Database listeners')) + '</h4><div class="dsc-kv">' + x.db.map(function (d) { return '<span class="k">' + E(d.label) + '</span><span>' + ltr('TCP ' + d.port + (d.version ? ' · ' + d.version : '')) + '</span>'; }).join('') + '</div>';
    if (x.unix) html += '<h4>' + E(T('Solaris / Unix servers (SSH banner)')) + '</h4><div class="dsc-kv"><span class="k">' + E(T('Operating system')) + '</span><span>' + E(x.unix.label || T('not identified')) + '</span><span class="k">' + E(T('SSH banner')) + '</span><span>' + ltr(x.unix.ssh_banner || '—') + '</span><span class="k">' + E(T('Open ports')) + '</span><span>' + ltr((x.unix.ports || []).join(', ') || '—') + '</span></div>';
    if (x.storage) html += '<h4>' + E(T('Storage arrays and NAS (iSCSI, NFS, NDMP)')) + '</h4><div class="dsc-kv"><span class="k">' + E(T('Protocols')) + '</span><span>' + ltr((x.storage.protocols || []).join(', ').toUpperCase() || '—') + '</span></div>';
    if (x.nutanix) html += '<h4>' + E(T('Nutanix Prism')) + '</h4><div class="dsc-kv"><span class="k">' + E(x.nutanix.kind === 'host' ? T('Cluster') : T('AHV host')) + '</span><span>' + E((x.nutanix.kind === 'host' ? x.nutanix.cluster : x.nutanix.host) || '—') + '</span>' + (x.nutanix.kind === 'host' ? '<span class="k">' + E(T('CPU sockets × cores')) + '</span><span>' + ltr((x.nutanix.sockets || '?') + ' × ' + (x.nutanix.cores_per_socket || '?') + ' = ' + (x.nutanix.cores || '?')) + '</span>' : '<span class="k">' + E(T('Power state')) + '</span><span>' + E(x.nutanix.power_state || '—') + '</span><span class="k">' + E(T('vCPU / memory')) + '</span><span>' + ltr((x.nutanix.vcpus || '?') + ' vCPU · ' + (x.nutanix.memory_mb ? Math.round(x.nutanix.memory_mb / 1024) + ' GB' : '?')) + '</span>') + '</div>';
    if (x.hyperv) html += '<h4>' + E(T('Hyper-V')) + '</h4><div class="dsc-kv"><span class="k">' + E(T('Host')) + '</span><span>' + E(x.hyperv.host || '—') + '</span><span class="k">' + E(T('Power state')) + '</span><span>' + E(x.hyperv.state || '—') + '</span></div>';
    if (x.cucm) html += '<h4>' + E(T('Cisco CUCM phones')) + '</h4><div class="dsc-kv"><span class="k">' + E(T('Model')) + '</span><span>' + E(x.cucm.model || '—') + '</span><span class="k">' + E(T('Device pool')) + '</span><span>' + E(x.cucm.device_pool || '—') + '</span><span class="k">' + E(T('Registration')) + '</span><span>' + E(x.cucm.status || '—') + '</span></div>';
    if (x.cloud) html += '<h4>' + E(T('Cloud instance')) + '</h4><div class="dsc-kv"><span class="k">' + E(T('Provider')) + '</span><span>' + E(x.cloud.provider) + '</span><span class="k">' + E(T('Region')) + '</span><span>' + ltr(x.cloud.region || x.cloud.location || '—') + '</span><span class="k">' + E(T('Power state')) + '</span><span>' + E(x.cloud.power || x.cloud.state || '—') + '</span></div>';
    if ((d.neighbours || []).length) html += '<h4>' + E(T('Neighbours (LLDP / CDP)')) + '</h4>' + tbl([T('Via'), T('Local port'), T('Neighbour'), T('Neighbour port'), T('IP')], d.neighbours.map(function (n) { return '<tr><td>' + ltr(String(n.via || '').toUpperCase()) + '</td><td>' + ltr(n.local_port || '—') + '</td><td>' + E(n.remote_name || '—') + '</td><td>' + ltr(n.remote_port || '—') + '</td><td>' + ltr(n.remote_ip || '—') + '</td></tr>'; }).join(''));
    if ((d.reasons || []).length) html += '<h4>' + E(T('Classification evidence')) + '</h4><div class="dsc-pre" dir="ltr">' + E(d.reasons.join('\n')) + '</div>';
    var dups = d.duplicates || [];
    html += '<h4>' + E(T('Possible duplicates in the CMDB')) + '</h4>' + (dups.length ? tbl([T('Asset'), T('Matched on'), T('Strength'), ''], dups.map(function (u) {
      return '<tr><td>' + E(u.name || u.asset_tag || u.asset_id) + '</td><td>' + E(u.by.map(function (b) { return T(DUP_L[b] || b); }).join(', ')) + '</td><td>' + pill(T(STRENGTH_L[u.strength]), u.strength === 'strong' ? '#69f0ae' : '#ffd54f') + '</td><td>' + (isAdmin() && d.status === 'new' ? btn(T('Merge into this asset'), 'data-dsc-merge="' + E(d.id) + '" data-asset="' + E(u.asset_id) + '"', 'sm') : '') + '</td></tr>';
    }).join('')) : empty(T('No matching asset in the CMDB')));
    if (d.status === 'ignored') html += note(TF('Ignored by {by}: {reason}', { by: d.decided_by || '—', reason: d.ignore_reason || '' }));
    if (d.asset_id) html += '<div class="dsc-acts">' + btn(T('Open asset'), 'data-dsc-asset="' + E(d.asset_id) + '"', 'ghost') + '</div>';
    var acts = '';
    if (isAdmin()) {
      if (d.status === 'new') acts = '<div class="dsc-acts">' + btn(T('Approve into inventory'), 'data-dsc-approve="' + E(d.id) + '"') + '</div>'
        + '<div class="dsc-form">' + input('dsc_ig_reason', T('Reason for ignoring (required)'), 'text', '') + '</div><div class="dsc-acts">' + btn(T('Ignore'), 'data-dsc-ignore="' + E(d.id) + '"', 'ghost') + '</div>'
        + '<div class="dsc-form">' + input('dsc_mg_asset', T('Merge into asset id'), 'text', '') + '</div><div class="dsc-acts">' + btn(T('Merge'), 'data-dsc-merge="' + E(d.id) + '"', 'ghost') + '</div>';
      else if (d.status === 'ignored') acts = '<div class="dsc-acts">' + btn(T('Restore'), 'data-dsc-restore="' + E(d.id) + '"', 'ghost') + '</div>';
      else if (d.asset_id) acts = '<div class="dsc-form">' + select('dsc_cn_kind', T('SIEM connector'), [['', T('Automatic (mapping table)')], ['windows', 'windows'], ['dc', 'dc'], ['linux', 'linux'], ['fortigate', 'fortigate'], ['palo-alto', 'palo-alto'], ['cisco', 'cisco'], ['cisco-asa-ftd', 'cisco-asa-ftd'], ['check-point', 'check-point'], ['sophos-firewall', 'sophos-firewall'], ['sonicwall', 'sonicwall'], ['f5-bigip', 'f5-bigip'], ['vmware-esxi-hosts', 'vmware-esxi-hosts'], ['syslog', 'syslog']], '') + '</div><div class="dsc-acts">' + btn(T('Connect to SIEM'), 'data-dsc-connect="' + E(d.asset_id) + '"') + '</div>';
    }
    return card('🔎', (d.hostname || d.ip || d.mac || d.id), '<button type="button" class="dsc-link" data-dsc="sel-close">' + E(T('Close')) + '</button>', onceBox() + html + acts);
  }

  /* ════════════ discovery-runs ════════════ */
  function runs() {
    var c = api('/runs?limit=100');
    if (c.state !== 'ok' || !c.data) return stateCard(c, T('Discovery Runs'));
    var list = c.data.runs || [];
    var h = head(T('Discovery Runs'), TF('{n} runs', { n: list.length }));
    var rows = list.map(function (r) {
      var p = r.progress || {};
      return '<tr><td>' + E(when(r.started_at)) + '</td><td>' + E(r.scope_name) + '</td><td>' + E(T(TRIG_L[r.trigger] || r.trigger)) + '</td><td>' + E(r.by) + '</td><td>' + pill(T(RUN_L[r.status] || r.status), RUN_C[r.status] || '#a9c7e3') + '</td>'
        + '<td>' + E((r.methods_run || []).map(methodName).join(', ') || '—') + '</td><td>' + E((r.methods_blocked || []).map(function (b) { return methodName(b.method) + ': ' + blockedText(b); }).join('; ') || '—') + '</td>'
        + '<td>' + (p.hosts_total ? E(p.hosts_done + '/' + p.hosts_total) : '—') + '</td><td>' + E((r.devices_seen || 0) + ' / ' + (r.devices_new || 0)) + '</td><td>' + E(when(r.finished_at)) + '</td>'
        + '<td>' + (isAdmin() && r.status === 'running' ? btn(T('Cancel'), 'data-dsc-cancel="' + E(r.id) + '"', 'ghost sm') : '') + '</td></tr>';
    }).join('');
    var table = rows ? tbl([T('Started'), T('Scope'), T('Trigger'), T('By'), T('Status'), T('Methods run'), T('Blocked'), T('Hosts'), T('Devices seen / new'), T('Finished'), ''], rows) : empty(T('No scan has run yet'));
    return h + easyBar() + card('⏱️', T('Scans'), '', table) + (isAdmin() ? auditCard() : '');
  }
  function auditCard() {
    var c = api('/audit?limit=40');
    if (c.state !== 'ok' || !c.data) return '';
    var rows = (c.data.audit || []).map(function (a) { return '<tr><td>' + E(when(a.at)) + '</td><td>' + E(a.by) + '</td><td>' + E(T(AUDIT_L[a.action] || a.action)) + '</td><td>' + ltr(a.target || '') + '</td></tr>'; }).join('');
    return card('📜', T('Discovery audit trail'), '', rows ? tbl([T('When'), T('User'), T('Action'), T('Target')], rows) + note(T('Every scan, decision, scope, checklist, credential and SIEM action is written to the tamper-evident audit log.')) : empty(T('Nothing recorded yet')));
  }

  /* ════════════ bulk review (discovery-results toolbar) ════════════ */
  function selectedIds() { var out = [], k; for (k in ST.sel) if (Object.prototype.hasOwnProperty.call(ST.sel, k) && ST.sel[k]) out.push(k); return out; }
  function clearSel() { ST.sel = {}; }
  function bulkBar(list) {
    if (!isAdmin()) return '';
    var newCount = 0, i; for (i = 0; i < list.length; i++) if (list[i].status === 'new') newCount++;
    var sel = selectedIds().length;
    return '<div class="dsc-bulkbar"><b>' + E(TF('{n} selected', { n: sel })) + '</b>'
      + btn(T('Approve selected'), 'data-dsc="bulk-approve"', 'sm') + btn(T('Ignore selected'), 'data-dsc="bulk-ignore"', 'ghost sm')
      + '<label class="dsc-f" style="min-width:180px">' + E(T('Ignore reason')) + '<input id="dsc_bulk_reason" type="text" placeholder="' + E(T('reason — required to ignore')) + '"></label>'
      + btn(TF('Approve ALL new ({n})', { n: newCount }), 'data-dsc="bulk-approve-all"', 'sm')
      + (sel ? btn(T('Clear selection'), 'data-dsc="bulk-clear"', 'ghost sm') : '') + '</div>'
      + note(T('Bulk actions apply to New results only and reuse the same MAC / serial de-duplication. Already-decided devices are skipped and a single audit summary is recorded.'));
  }
  function bulkToast(j) {
    if (!j) { toast(T('The engine refused the request')); return; }
    toast(TF('Done: {a} approved, {i} ignored, {s} skipped.', { a: j.approved || 0, i: j.ignored || 0, s: j.skipped || 0 }) + (j.errors && j.errors.length ? ' ' + TF('{e} error(s).', { e: j.errors.length }) : ''));
  }

  /* ════════════ Connect Wizard (guided, layered over the raw Add form) ════════════ */
  function wizKinds() { var c = isAdmin() ? api('/credentials') : null; return (c && c.state === 'ok' && c.data && c.data.kinds) ? c.data.kinds : []; }
  function kfEntry(kind, name) { var a = KIND_FIELDS[kind] || [], i; for (i = 0; i < a.length; i++) if (a[i][0] === name) return a[i]; return null; }
  function wizDefs(kind, kinds) {
    var spec = null, i; for (i = 0; i < kinds.length; i++) if (kinds[i].kind === kind) spec = kinds[i];
    if (!spec) return [];
    var secret = {}; (spec.secret_fields || []).forEach(function (f) { secret[f] = 1; });
    return (spec.target_fields || []).concat(spec.secret_fields || []).map(function (name) {
      var e = kfEntry(kind, name), h = WIZ_HELP[kind + '.' + name] || {};
      return { name: name, secret: !!secret[name], label: e ? e[1] : name, type: e ? e[2] : 'text', help: h.help || GEN_HELP[name] || '', def: h.def == null ? '' : h.def };
    });
  }
  function wizField(d, cur) {
    var id = 'dsc_wf_' + d.name, label = T(d.label), type = d.type;
    var v = cur && cur[d.name] != null ? (Array.isArray(cur[d.name]) ? cur[d.name].join('\n') : cur[d.name]) : (d.secret ? '' : d.def);
    var field;
    if (type.indexOf('sel:') === 0) field = select(id, label, type.slice(4).split(',').map(function (o) { return [o, o]; }), v);
    else if (type === 'lines') field = area(id, label, v, ' dir="ltr"');
    else if (type === 'textarea-secret') field = area(id, label, '', ' dir="ltr" autocomplete="off" spellcheck="false"');
    else field = input(id, label, type, v, (d.secret ? ' autocomplete="new-password" spellcheck="false"' : '') + ' dir="ltr"');
    return '<div class="dsc-wf">' + field + (d.help ? '<span class="dsc-help">' + E(T(d.help)) + '</span>' : '') + '</div>';
  }
  function wizBody(kind) {
    var defs = wizDefs(kind, wizKinds()), secret = {}, target = {};
    defs.forEach(function (d) {
      var v = val('dsc_wf_' + d.name);
      if (d.secret) { if (v) secret[d.name] = v; return; }
      if (!v) return;
      if (d.type === 'lines') target[d.name] = lines(v);
      else if (d.type === 'number') target[d.name] = Number(v);
      else target[d.name] = v;
    });
    return { label: val('dsc_wf_label'), kind: kind, target: target, secret: secret };
  }
  function wizCanPin(kind, kinds) { var i; for (i = 0; i < kinds.length; i++) if (kinds[i].kind === kind) return (kinds[i].target_fields || []).indexOf('tls_fingerprint') >= 0; return false; }
  function wizDupWarn(kind) {
    var c = api('/credentials'); var list = (c && c.state === 'ok' && c.data) ? (c.data.credentials || []) : [];
    var same = list.filter(function (x) { return x.kind === kind; });
    if (!same.length) return '';
    return '<div class="dsc-note">⚠️ ' + E(TF('You already have {n} credential(s) of this kind: {labels}. Make sure you are not creating a duplicate.', { n: same.length, labels: same.map(function (x) { return x.label; }).join(', ') })) + '</div>';
  }
  function certBox(p) {
    return '<div class="dsc-kv">'
      + '<span class="k">' + E(T('Subject')) + '</span><span>' + ltr(p.subject || '—') + '</span>'
      + '<span class="k">' + E(T('Issuer')) + '</span><span>' + ltr(p.issuer || '—') + '</span>'
      + '<span class="k">' + E(T('Valid from')) + '</span><span>' + ltr(p.valid_from || '—') + '</span>'
      + '<span class="k">' + E(T('Valid to')) + '</span><span>' + ltr(p.valid_to || '—') + '</span>'
      + '<span class="k">' + E(T('SHA-256 fingerprint')) + '</span><span>' + ltr(p.fingerprint256 || '—') + '</span></div>';
  }
  function wizMessage(r) {
    var ec = r.error_class, http = r.http;
    if (r.ok) return T('Connected — the credential works.');
    if (ec === 'tls') return (r.tls && r.tls.pin_mismatch) ? T('TLS: the presented certificate does not match the approved pin.') : T('TLS: certificate not trusted — review and pin the certificate below.');
    if (ec === 'auth') return TF('TLS OK (certificate trusted); the system rejected the credentials (HTTP {http}).', { http: http || 401 });
    if (ec === 'authz') return TF('Authenticated, but the account lacks a required read privilege (HTTP {http}).', { http: http || 403 });
    if (ec === 'timeout') return T('Timed out waiting for the system to respond.');
    if (ec === 'unreachable') return T('Could not reach the system (connection failed).');
    if (ec === 'config') return T('The connection settings are invalid.');
    if (ec === 'not_supported') return T('This credential type is stored for future use and is not tested.');
    return r.message || T('The system answered, but not as expected.');
  }
  function wizHint(r, kind) {
    var ec = r.error_class;
    if (ec === 'auth') return kind === 'vcenter' ? T('Check the user name is in full SSO form (for example administrator@vsphere.local, not a bare name), the account is not locked, and the password is current.')
      : kind === 'ldap' ? T('Check the bind DN and password (LDAP result 49, invalidCredentials), that the account is not locked, and the password is current.')
      : T('Check the user name and password and that the account is not locked.');
    if (ec === 'authz') return kind === 'vcenter' ? T('Assign the service account the built-in Read-only role in vCenter.') : kind === 'nutanix' ? T('Give the Prism user the Viewer role (Prism Central: Viewer on all clusters).') : T('Assign the account read-only access to the system.');
    if (ec === 'tls') return (r.tls && r.tls.pin_mismatch) ? T('The appliance certificate changed, or this is not the host you pinned. Confirm the new certificate before re-pinning.') : T('If this is the correct appliance certificate, pin it with Trust & pin. Otherwise fix the certificate or CA file.');
    if (ec === 'timeout') return T('Check the host and port, the firewall path from the platform server, and that the service is running.');
    if (ec === 'unreachable') return T('Check the host / IP and port and the network path from the platform server.');
    if (ec === 'config') return T('Check the URL / host, port and CA file path.');
    return r.hint || '';
  }
  function wizStep1(kinds) {
    var avail = kinds.filter(function (k) { return !k.future; }), future = kinds.filter(function (k) { return k.future; });
    var btns = avail.map(function (k) { return '<button type="button" class="btn ghost dsc-wpick" data-dsc-wkind="' + E(k.kind) + '">' + E(T(KIND_L[k.kind] || k.kind)) + '</button>'; }).join('');
    var fut = future.length ? note(T('Also stored for future use (not tested yet):') + ' ' + future.map(function (k) { return T(KIND_L[k.kind] || k.kind); }).join(', ')) : '';
    return '<p>' + E(T('Pick the system to connect. The next step shows only that system\'s fields, with inline help and the right defaults.')) + '</p><div class="dsc-wpicks">' + btns + '</div>' + fut;
  }
  function wizStep2(w, kinds) {
    var defs = wizDefs(w.kind, kinds);
    var isSnmp = !!HOST_TEST[w.kind];
    var fields = defs.map(function (d) { return wizField(d, w.target || null); }).join('');
    var host = isSnmp ? '<div class="dsc-wf">' + input('dsc_wf_host', T('Test host IP (inside an active, gate-open scope)'), 'text', w.host || '', ' dir="ltr"') + '</div>' : '';
    return '<div style="font-weight:700;margin-bottom:6px">' + E(T(KIND_L[w.kind] || w.kind)) + '</div>' + wizDupWarn(w.kind)
      + '<div class="dsc-form">' + input('dsc_wf_label', T('Label'), 'text', w.label || '') + '</div>'
      + '<div class="dsc-form">' + fields + host + '</div>'
      + '<div class="dsc-acts">' + btn(T('Back'), 'data-dsc="wiz-back1"', 'ghost') + btn(w.credId ? T('Save & test again') : T('Save & test'), 'data-dsc-wsave="' + E(w.kind) + '"') + '</div>'
      + note(T('The secret is write-only: after saving it is never shown again, only that it is set and its fingerprint.'));
  }
  function wizStep3(w, kinds) {
    var r = w.result;
    if (!r) return '<div class="dsc-empty">' + E(T('Testing…')) + '</div>';
    var st = r.ok ? 'read' : (r.stage || 'protocol');
    var out = '<div style="margin:6px 0">' + pill(T(STAGE_T[st] || STAGE_T.protocol), STAGE_C[st] || '#ff8a65') + (r.latency_ms != null ? ' <span class="dsc-mono">' + E(TF('{ms} ms', { ms: r.latency_ms })) + '</span>' : '') + '</div>';
    out += '<div class="dsc-result-msg">' + E(wizMessage(r)) + '</div>';
    var hint = wizHint(r, w.kind); if (hint) out += note(hint);
    if (!r.ok && r.error_class === 'tls' && r.tls && r.tls.presented) {
      out += '<h4>' + E(T('Presented certificate')) + '</h4>' + certBox(r.tls.presented);
      if (wizCanPin(w.kind, kinds) && !r.tls.pin_mismatch && r.tls.presented.fingerprint256) out += '<div class="dsc-acts">' + btn(T('Trust & pin this certificate'), 'data-dsc-wpin="' + E(w.credId) + '"') + '</div>';
    }
    if (r.ok) out += note('✅ ' + (r.discovered && r.discovered.hosts != null ? TF('Reached vCenter — {n} host(s) visible.', { n: r.discovered.hosts }) : T('The credential works.')));
    out += '<div class="dsc-acts">' + (r.ok ? '' : btn(T('Edit details'), 'data-dsc="wiz-back2"', 'ghost') + btn(T('Test again'), 'data-dsc-wretest="' + E(w.credId) + '"', 'ghost'))
      + btn(T('Finish'), 'data-dsc="wiz-finish"') + btn(T('Delete this credential'), 'data-dsc-wdel="' + E(w.credId) + '"', 'ghost') + '</div>';
    return out;
  }
  function wizard() {
    var w = ST.ui.wizard; if (!w) return '';
    var kinds = wizKinds(); var step = w.step || 1;
    var steps = '<div class="dsc-wsteps">' + [1, 2, 3].map(function (n) { return '<span class="dsc-wstep ' + (n === step ? 'on' : (n < step ? 'done' : '')) + '">' + n + '. ' + E(T([N('Choose system'), N('Details'), N('Test')][n - 1])) + '</span>'; }).join('') + '</div>';
    var body = step === 1 ? wizStep1(kinds) : step === 2 ? wizStep2(w, kinds) : wizStep3(w, kinds);
    return '<div class="card dsc-wizard"><h3>🧭 ' + E(T('Connect a system')) + '<span class="dsc-right"><button type="button" class="dsc-link" data-dsc="wiz-close">' + E(T('Close')) + '</button></span></h3>' + steps + body + '</div>';
  }
  function wizTest(w) {
    if (!w || !w.credId) return;
    post('/credentials/' + enc(w.credId) + '/test', HOST_TEST[w.kind] ? { host: w.host || '' } : {}, '', function (j) {
      w.result = (j && j.result) || { ok: false, error_class: 'error', stage: 'protocol' }; w.step = 3; invalidate('/credentials'); repaint();
    });
  }

  /* ════════════ discovery-credentials (System Admin) ════════════ */
  function creds() {
    var h = head(T('Discovery Credentials'), '');
    if (!ST.whoLoaded) { whoami(); return h + card('⏳', T('Loading'), '', '<div class="dsc-empty">' + E(T('Loading…')) + '</div>'); }
    if (!isAdmin()) return h + card('🔒', T('Administrators only'), '', empty(T('Credentials are managed by a System Admin. They are write-only: nobody can read a stored secret back.')));
    var c = api('/credentials');
    if (c.state !== 'ok' || !c.data) return stateCard(c, T('Discovery Credentials'));
    var list = c.data.credentials || [];
    var rows = list.map(function (x) {
      var lt = x.last_tested;
      var test = lt ? (lt.ok ? pill(T('OK'), '#69f0ae') + ' ' + E(TF('{ms} ms', { ms: lt.latency_ms })) : pill(errText(lt.error_class), '#ff6e7f')) + ' · ' + E(when(lt.at)) : E(T('Never tested'));
      var tgt = x.target || {}; var tparts = []; var k; for (k in tgt) if (Object.prototype.hasOwnProperty.call(tgt, k)) tparts.push(k + '=' + (Array.isArray(tgt[k]) ? tgt[k].join(',') : tgt[k]));
      var hostIn = HOST_TEST[x.kind] ? '<input id="dsc_ct_host_' + E(x.id) + '" type="text" dir="ltr" placeholder="' + E(T('test host IP')) + '" style="width:120px"> ' : '';
      return '<tr><td><b>' + E(x.label) + '</b>' + (x.future ? ' ' + pill(T('Stored for future use'), '#90a4ae') : '') + '</td><td>' + E(T(KIND_L[x.kind] || x.kind)) + '</td><td>' + ltr(tparts.join(' · ') || '—') + '</td><td>' + pill(T('Set'), '#69f0ae') + ' ' + ltr(x.fingerprint) + '</td><td>' + test + '</td><td>' + E(x.updated_by) + ' · ' + E(when(x.updated_at)) + '</td>'
        + '<td style="white-space:nowrap">' + hostIn + btn(T('Test connection'), 'data-dsc-ctest="' + E(x.id) + '"', 'ghost sm') + ' ' + btn(T('Replace secret'), 'data-dsc-cedit="' + E(x.id) + '"', 'ghost sm') + ' ' + btn(T('Delete'), 'data-dsc-cdel="' + E(x.id) + '"', 'ghost sm') + '</td></tr>';
    }).join('');
    var form = ST.ui.credForm ? credForm(ST.ui.credForm === 'new' ? null : list.filter(function (x) { return x.id === ST.ui.credForm; })[0]) : '';
    var right = '<button type="button" class="btn sm" data-dsc="wiz-open">🧭 ' + E(T('Connect a system')) + '</button> <button type="button" class="btn ghost sm" data-dsc="cred-new">➕ ' + E(T('Add credential')) + '</button>';
    return h + easyBar() + card('🔐', T('Credential vault'), right, wizard() + form
      + (rows ? tbl([T('Label'), T('Kind'), T('Target'), T('Secret'), T('Last test'), T('Changed'), ''], rows) : empty(T('No credential stored yet')))
      + note(T('Write-only: after saving, a secret is never shown again — only that it is set, its fingerprint and the last test result. Secrets are encrypted (AES-256-GCM) and never logged. A test returns only success, latency and an error class.'))
      + note(T('SSH, database and storage API logins are used by the active scan for read-only details (see the scope form). WinRM credentials are stored for future use only. Hyper-V is inventoried from the Windows agent report.')))
      + trustCard();
  }
  /* SSH host keys / storage certificates seen by the scan or a credential test: a login only ever goes to a trusted one */
  function trustCard() {
    var t = api('/trust');
    if (!t || t.state !== 'ok' || !t.data) return '';
    var items = t.data.items || [], sel = ST.tsel || (ST.tsel = {});
    var KL = { ssh: T('SSH host key'), tls: T('HTTPS certificate') };
    var SC = { pending: ['#ffd54f', T('waiting for trust')], trusted: ['#69f0ae', T('trusted')], changed: ['#ff6e7f', T('CHANGED - not used')] };
    var rows = items.map(function (r) {
      var fp = r.state === 'changed' && r.new_fp ? r.new_fp : r.fp, info = (r.state === 'changed' && r.new_info) || r.info || {};
      var what = r.kind === 'ssh' ? (info.type || '') : [info.subject, info.valid_to ? T('valid to') + ' ' + info.valid_to : ''].filter(Boolean).join(' · ');
      return '<tr><td>' + check('dsc_tsel_' + r.id.replace(/[^A-Za-z0-9]/g, '_'), '', !!sel[r.id]).replace('<input', '<input data-dsc-tsel="' + E(r.id) + '"') + '</td><td>' + ltr(r.ip + ':' + r.port) + '</td><td>' + E(KL[r.kind] || r.kind) + (what ? '<div class="dsc-mono" style="font-size:11px">' + E(String(what).slice(0, 120)) + '</div>' : '') + '</td><td><span dir="ltr" class="dsc-mono" title="SHA-256 ' + E(fp) + '">' + E(String(fp).slice(0, 24)) + '…</span>' + (r.state === 'changed' ? '<div style="font-size:11px">' + E(T('was')) + ' ' + ltr(String(r.fp).slice(0, 24) + '…') + '</div>' : '') + '</td><td>' + pill((SC[r.state] || ['#90a4ae', r.state])[1], (SC[r.state] || ['#90a4ae'])[0]) + '</td><td>' + E(when(r.first_seen)) + (r.trusted_by ? '<div style="font-size:11px">' + E(T('trusted by')) + ' ' + E(r.trusted_by) + '</div>' : '') + '</td></tr>';
    }).join('');
    var pend = items.filter(function (r) { return r.state !== 'trusted'; }).length;
    var right = btn(T('Trust selected'), 'data-dsc="trust-sel"', 'sm') + ' ' + btn(TF('Trust all waiting ({n})', { n: pend }), 'data-dsc="trust-pending"', 'ghost sm') + ' ' + btn(T('Forget selected'), 'data-dsc="trust-forget"', 'ghost sm');
    return card('🔏', T('Trust - SSH host keys and storage certificates'), items.length ? right : '', (rows ? tbl(['', T('Host'), T('Kind'), T('Fingerprint (SHA-256)'), T('State'), T('First seen')], rows) : empty(T('Nothing seen yet - run a scope with an SSH or storage login, or test such a credential against one host.')))
      + note(T('A password is sent only to a server whose key or certificate is trusted here. Reading a key or certificate sends nothing secret. Compare the fingerprint with the server (ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub) before trusting; a CHANGED key is never used until you trust it again.')));
  }
  function credForm(x) {
    var kind = x ? x.kind : (ST.ui.credKind || 'snmp_v2c');
    var fields = KIND_FIELDS[kind] || [];
    var t = (x && x.target) || {};
    var inner = fields.map(function (f) {
      var id = 'dsc_cf_' + f[0], label = T(f[1]), type = f[2], v = f[3] ? '' : (t[f[0]] == null ? '' : (Array.isArray(t[f[0]]) ? t[f[0]].join('\n') : t[f[0]]));
      if (type.indexOf('sel:') === 0) return select(id, label, type.slice(4).split(',').map(function (o) { return [o, o]; }), v);
      if (type === 'lines') return area(id, label, v, ' dir="ltr"');
      if (type === 'textarea-secret') return area(id, label, '', ' dir="ltr" autocomplete="off" spellcheck="false"');
      return input(id, label, type, v, (f[3] ? ' autocomplete="new-password" spellcheck="false"' : '') + ' dir="ltr"');
    }).join('');
    return '<div class="card"><h3>' + E(x ? T('Replace secret') + ': ' + x.label : T('Add credential')) + '</h3><div class="dsc-form">'
      + (x ? '' : select('dsc_cf_kind', T('Kind'), KINDS.map(function (k) { return [k, T(KIND_L[k])]; }), kind)) + input('dsc_cf_label', T('Label'), 'text', x ? x.label : '') + inner + '</div>'
      + '<div class="dsc-acts">' + btn(T('Save credential'), 'data-dsc-csave="' + E(x ? x.id : '') + '" data-kind="' + E(kind) + '"') + btn(T('Cancel'), 'data-dsc="cred-cancel"', 'ghost') + '</div>'
      + (x ? note(T('Leave a secret field empty to keep the stored value.')) : '') + '</div>';
  }
  function credBody(kind, isNew) {
    var secret = {}, target = {};
    (KIND_FIELDS[kind] || []).forEach(function (f) {
      var v = val('dsc_cf_' + f[0]);
      if (f[3]) { if (v) secret[f[0]] = v; return; }
      if (!v) return;
      if (f[2] === 'lines') target[f[0]] = lines(v);
      else if (f[2] === 'number') target[f[0]] = Number(v);
      else target[f[0]] = v;
    });
    var b = { label: val('dsc_cf_label'), target: target, secret: secret };
    if (isNew) b.kind = kind;
    return b;
  }
  function clearSecrets() { var k, i, f; for (k in KIND_FIELDS) if (Object.prototype.hasOwnProperty.call(KIND_FIELDS, k)) for (i = 0; i < KIND_FIELDS[k].length; i++) { f = KIND_FIELDS[k][i]; if (f[3]) { var el = document.getElementById('dsc_cf_' + f[0]); if (el) el.value = ''; } } }

  /* ── actions ── */
  function refreshAll() { invalidate(); repaint(); }
  // dashboard chip / type bar → Results with that filter
  function openResults(status, type, grp) { clearSel(); ST.rf = { status: status || 'new', type: type || '', site: '', method: '', q: '', rogue: false, os: (grp && grp.os) || '', brand: (grp && grp.brand) || '' }; invalidate('/results'); if (cur() !== 'discovery-results') { try { setView('discovery-results'); } catch (e) { /* portal function not available on this page: carry on without it */ } } else repaint(); }
  function onKey(ev) { var tg = ev.target; if ((ev.key === 'Enter' || ev.key === ' ') && tg && tg.closest && tg.closest('#dsc-root') && tg.getAttribute && tg.getAttribute('data-dsc-rf') && tg.tagName !== 'BUTTON') { ev.preventDefault(); openResults(tg.getAttribute('data-st') || (tg.getAttribute('data-type') ? 'all' : 'new'), tg.getAttribute('data-type') || ''); } }
  function onClick(ev) {
    var tg = ev.target; if (!tg || !tg.closest) return;
    var x;
    if ((x = tg.closest('[data-dsc-go]'))) { try { setView(x.getAttribute('data-dsc-go')); } catch (e) { /* portal function not available on this page: carry on without it */ } return; }
    if (!tg.closest('#dsc-root')) return;
    if (tg.tagName === 'INPUT' && tg.type === 'checkbox') return; // selection + form checkboxes are read on their action buttons
    if ((x = tg.closest('[data-dsc-grp]'))) {
      var gk = x.getAttribute('data-dsc-grp'), gv = x.getAttribute('data-v');
      if (cur() !== 'discovery-results') { var g = {}; g[gk] = gv; openResults('all', '', g); return; }
      clearSel(); ST.rf[gk] = ST.rf[gk] === gv ? '' : gv; repaint(); return;
    }
    if ((x = tg.closest('[data-dsc-rf]'))) { openResults(x.getAttribute('data-st') || (x.getAttribute('data-type') ? 'all' : 'new'), x.getAttribute('data-type') || ''); return; }
    if ((x = tg.closest('[data-dsc-row]'))) { ST.ui.sel = x.getAttribute('data-dsc-row'); invalidate('/results/'); if (cur() !== 'discovery-results') { try { setView('discovery-results'); } catch (e) { /* portal function not available on this page: carry on without it */ } } else repaint(); return; }
    if ((x = tg.closest('[data-dsc-asset]'))) { try { if (typeof window.itamOpenAsset === 'function') window.itamOpenAsset(x.getAttribute('data-dsc-asset')); else setView('itam-assets'); } catch (e) { /* portal function not available on this page: carry on without it */ } return; }
    if (!isAdmin() && (tg.closest('[data-dsc-run],[data-dsc-edit],[data-dsc-check],[data-dsc-approve],[data-dsc-ignore],[data-dsc-merge],[data-dsc-restore],[data-dsc-connect],[data-dsc-cancel],[data-dsc-csave],[data-dsc-qcred],[data-dsc-ctest],[data-dsc-cdel],[data-dsc-scope-save],[data-dsc-scope-act],[data-dsc-check-save],[data-dsc-wkind],[data-dsc-wsave],[data-dsc-wpin],[data-dsc-wretest],[data-dsc-wdel]'))) { toast(T('Your role is not allowed to do this.')); return; }
    if ((x = tg.closest('[data-dsc]'))) {
      var a = x.getAttribute('data-dsc');
      if (a === 'scope-new') { ST.ui.scopeForm = 'new'; invalidate('/credentials'); }
      else if (a === 'scope-cancel') ST.ui.scopeForm = null;
      else if (a === 'check-cancel') ST.ui.check = null;
      else if (a === 'sel-close') ST.ui.sel = null;
      else if (a === 'once-close') ST.ui.once = null;
      else if (a === 'cred-new') { ST.ui.credForm = 'new'; ST.ui.wizard = null; }
      else if (a === 'cred-cancel') ST.ui.credForm = null;
      else if (a === 'trust-sel' || a === 'trust-forget' || a === 'trust-pending') {
        var tl = api('/trust'), all = (tl && tl.data && tl.data.items) || [], ids;
        ids = a === 'trust-pending' ? all.filter(function (r) { return r.state !== 'trusted'; }).map(function (r) { return r.id; }) : Object.keys(ST.tsel || {}).filter(function (k) { return ST.tsel[k]; });
        if (!ids.length) { toast(T('Select at least one row.')); return; }
        if (a === 'trust-pending') { try { if (!window.confirm(TF('Trust {n} key(s) / certificate(s)? Only do this on a network you control, after checking the fingerprints.', { n: ids.length }))) return; } catch (e) { return; /* confirm() blocked (sandboxed frame): never act without the person's yes */ } }
        post('/trust', { ids: ids, action: a === 'trust-forget' ? 'forget' : 'trust' }, a === 'trust-forget' ? N('Forgotten') : N('Trusted - the next scan logs in'), function () { ST.tsel = {}; invalidate('/trust'); repaint(); });
        return;
      }
      else if (a === 'wiz-open') { ST.ui.wizard = { step: 1 }; ST.ui.credForm = null; invalidate('/credentials'); }
      else if (a === 'wiz-close' || a === 'wiz-finish') { ST.ui.wizard = null; invalidate('/credentials'); }
      else if (a === 'wiz-back1') { if (ST.ui.wizard) { ST.ui.wizard.step = 1; } }
      else if (a === 'wiz-back2') { if (ST.ui.wizard) { ST.ui.wizard.step = 2; } }
      else if (a === 'bulk-clear') { clearSel(); }
      else if (a === 'bulk-approve' || a === 'bulk-ignore') {
        if (!isAdmin()) { toast(T('Your role is not allowed to do this.')); return; }
        var ids = selectedIds();
        if (!ids.length) { toast(T('Select at least one New device first.')); return; }
        if (a === 'bulk-ignore') {
          var br = val('dsc_bulk_reason'); if (br.length < 3) { toast(T('A reason is required to ignore devices.')); return; }
          try { if (!window.confirm(TF('Ignore {n} selected device(s)?', { n: ids.length }))) return; } catch (e) { return; /* confirm() blocked (sandboxed frame): never act without the person's yes */ }
          post('/results/bulk', { action: 'ignore', ids: ids, reason: br }, '', function (j) { clearSel(); bulkToast(j); refreshAll(); }); return;
        }
        try { if (!window.confirm(TF('Approve {n} selected device(s) into the inventory?', { n: ids.length }))) return; } catch (e) { return; /* confirm() blocked (sandboxed frame): never act without the person's yes */ }
        post('/results/bulk', { action: 'approve', ids: ids }, '', function (j) { clearSel(); bulkToast(j); refreshAll(); }); return;
      }
      else if (a === 'bulk-approve-all') {
        if (!isAdmin()) { toast(T('Your role is not allowed to do this.')); return; }
        var flt = { status: 'new' }; if (ST.rf.type) flt.type = ST.rf.type; if (ST.rf.site) flt.site = ST.rf.site;
        try { if (!window.confirm(T('Approve ALL New devices that match the current filter into the inventory?'))) return; } catch (e) { return; /* confirm() blocked (sandboxed frame): never act without the person's yes */ }
        post('/results/bulk', { action: 'approve', filter: flt }, '', function (j) { clearSel(); bulkToast(j); refreshAll(); }); return;
      }
      else if (a === 'grp-clear') { clearSel(); ST.rf.os = ''; ST.rf.brand = ''; }
      else if (a === 'rf-apply') { clearSel(); ST.rf = { status: val('dsc_rf_status') || 'new', type: val('dsc_rf_type'), site: '', method: val('dsc_rf_method'), q: val('dsc_rf_q'), rogue: checked('dsc_rf_rogue'), os: ST.rf.os || '', brand: ST.rf.brand || '' }; invalidate('/results'); }
      else if (a === 'health') { post('/connect/health', {}, N('Health check finished'), function () { invalidate('/connect'); invalidate('/dashboard'); repaint(); }); return; }
      else if (a === 'methods-save') {
        var ms = {}; METHODS.forEach(function (k) { ms[k] = checked('dsc_gm_' + k); });
        post('/methods', { methods: ms, rogue_min_sightings: Number(val('dsc_gm_rogue')), max_concurrent_runs: Number(val('dsc_gm_conc')), icmp_mode: val('dsc_gm_icmp') }, N('Method switches saved'), refreshAll); return;
      }
      repaint(); return;
    }
    if ((x = tg.closest('[data-dsc-run]'))) { post('/scopes/' + enc(x.getAttribute('data-dsc-run')) + '/run', {}, N('Scan started'), function () { invalidate('/runs'); invalidate('/scopes'); invalidate('/dashboard'); repaint(); }); return; }
    if ((x = tg.closest('[data-dsc-qcred]'))) { qcredOpen(x.getAttribute('data-dsc-qcred')); return; }
    if ((x = tg.closest('[data-dsc-edit]'))) { ST.ui.scopeForm = x.getAttribute('data-dsc-edit'); invalidate('/credentials'); repaint(); return; }
    if ((x = tg.closest('[data-dsc-check-save]'))) {
      post('/scopes/' + enc(x.getAttribute('data-dsc-check-save')) + '/checklist', { firewall: { snmp_161: checked('dsc_cl_snmp'), ssh_22: checked('dsc_cl_ssh'), winrm_5985_5986: checked('dsc_cl_winrm'), icmp: checked('dsc_cl_icmp') }, soc_notified_name: val('dsc_cl_soc'), soc_notified_date: val('dsc_cl_date'), approved_by: val('dsc_cl_appr'), note: val('dsc_cl_note') }, N('Checklist completed — the safety gate is open'), function () { ST.ui.check = null; refreshAll(); });
      return;
    }
    if ((x = tg.closest('[data-dsc-check-revoke]'))) { post('/scopes/' + enc(x.getAttribute('data-dsc-check-revoke')) + '/checklist/revoke', {}, N('Checklist revoked — active methods blocked'), function () { ST.ui.check = null; refreshAll(); }); return; }
    if ((x = tg.closest('[data-dsc-check]'))) { ST.ui.check = x.getAttribute('data-dsc-check'); repaint(); return; }
    if ((x = tg.closest('[data-dsc-scope-act]'))) { var act = x.getAttribute('data-dsc-scope-act'); if (act === 'archive') { try { if (!window.confirm(T('Archive this scope? Its results and audit trail are kept.'))) return; } catch (e) { return; /* confirm() blocked (sandboxed frame): never act without the person's yes */ } } post('/scopes/' + enc(x.getAttribute('data-id')) + '/' + act, {}, N('Scope updated'), refreshAll); return; }
    if ((x = tg.closest('[data-dsc-scope-save]'))) { var sid = x.getAttribute('data-dsc-scope-save'); post(sid ? '/scopes/' + enc(sid) : '/scopes', scopeBody(), N('Scope saved'), function () { ST.ui.scopeForm = null; refreshAll(); }); return; }
    if ((x = tg.closest('[data-dsc-approve]'))) { post('/results/' + enc(x.getAttribute('data-dsc-approve')) + '/approve', {}, N('Approved into the inventory'), function (j) { toast(j && j.merged_into_existing ? T('Matched an existing asset — merged, no duplicate created') : T('New asset created')); refreshAll(); }); return; }
    if ((x = tg.closest('[data-dsc-ignore]'))) { var why = val('dsc_ig_reason'); if (why.length < 3) { toast(T('A reason is required to ignore a device.')); return; } post('/results/' + enc(x.getAttribute('data-dsc-ignore')) + '/ignore', { reason: why }, N('Device ignored — it stays ignored if seen again'), refreshAll); return; }
    if ((x = tg.closest('[data-dsc-merge]'))) { var aid = x.getAttribute('data-asset') || val('dsc_mg_asset'); if (!aid) { toast(T('Choose the asset to merge into.')); return; } post('/results/' + enc(x.getAttribute('data-dsc-merge')) + '/merge', { asset_id: aid }, N('Merged into the existing asset'), refreshAll); return; }
    if ((x = tg.closest('[data-dsc-restore]'))) { post('/results/' + enc(x.getAttribute('data-dsc-restore')) + '/restore', {}, N('Device restored for review'), refreshAll); return; }
    if ((x = tg.closest('[data-dsc-connect]'))) { var kind = x.getAttribute('data-kind') || val('dsc_cn_kind'); post('/connect', kind ? { asset_id: x.getAttribute('data-dsc-connect'), kind: kind } : { asset_id: x.getAttribute('data-dsc-connect') }, N('Log source created in the SIEM'), function (j) { ST.ui.once = j; invalidate('/connect'); invalidate('/dashboard'); repaint(); }); return; }
    if ((x = tg.closest('[data-dsc-cancel]'))) { post('/runs/' + enc(x.getAttribute('data-dsc-cancel')) + '/cancel', {}, N('Cancelling the scan'), function () { invalidate('/runs'); repaint(); }); return; }
    if ((x = tg.closest('[data-dsc-cedit]'))) { ST.ui.credForm = x.getAttribute('data-dsc-cedit'); repaint(); return; }
    if ((x = tg.closest('[data-dsc-csave]'))) {
      var cid = x.getAttribute('data-dsc-csave'), ck = x.getAttribute('data-kind');
      post(cid ? '/credentials/' + enc(cid) : '/credentials', credBody(ck, !cid), N('Credential stored — it cannot be read back'), function () { clearSecrets(); ST.ui.credForm = null; invalidate('/credentials'); repaint(); });
      return;
    }
    if ((x = tg.closest('[data-dsc-ctest]'))) { var id = x.getAttribute('data-dsc-ctest'); post('/credentials/' + enc(id) + '/test', { host: val('dsc_ct_host_' + id) }, '', function (j) { var r = j && j.result; toast(r && r.ok ? (r.message || TF('Connection OK ({ms} ms)', { ms: r.latency_ms })) : (r && r.message) || (T('Connection failed') + ': ' + errText(r && r.error_class))); if (r && /untrusted|changed/.test(r.error_class || '')) invalidate('/trust'); invalidate('/credentials'); repaint(); }); return; }
    if ((x = tg.closest('[data-dsc-tsel]'))) { ST.tsel = ST.tsel || {}; ST.tsel[x.getAttribute('data-dsc-tsel')] = !!x.checked; return; }
    if ((x = tg.closest('[data-dsc-cdel]'))) { try { if (!window.confirm(T('Delete this credential? Scopes must not be using it.'))) return; } catch (e) { return; /* confirm() blocked (sandboxed frame): never act without the person's yes */ } post('/credentials/' + enc(x.getAttribute('data-dsc-cdel')) + '/delete', {}, N('Credential deleted'), function () { invalidate('/credentials'); repaint(); }); return; }
    /* ── Connect Wizard ── */
    if ((x = tg.closest('[data-dsc-wkind]'))) { if (ST.ui.wizard) { ST.ui.wizard.kind = x.getAttribute('data-dsc-wkind'); ST.ui.wizard.step = 2; ST.ui.wizard.target = null; ST.ui.wizard.credId = null; ST.ui.wizard.result = null; } repaint(); return; }
    if ((x = tg.closest('[data-dsc-wsave]'))) {
      var wk = x.getAttribute('data-dsc-wsave'), w = ST.ui.wizard; if (!w) return;
      var body = wizBody(wk); w.host = HOST_TEST[wk] ? val('dsc_wf_host') : '';
      if (!body.label) { toast(T('A label is required.')); return; }
      post(w.credId ? '/credentials/' + enc(w.credId) : '/credentials', body, '', function (j) {
        var cr = j && j.credential; if (!cr) { toast(T('The engine refused the request')); return; }
        w.credId = cr.id; w.target = cr.target; w.label = cr.label; invalidate('/credentials'); wizTest(w);
      });
      return;
    }
    if ((x = tg.closest('[data-dsc-wpin]'))) {
      var wp = ST.ui.wizard; if (!wp || !wp.result || !wp.result.tls || !wp.result.tls.presented) return;
      post('/credentials/' + enc(x.getAttribute('data-dsc-wpin')), { target: { tls_fingerprint: wp.result.tls.presented.fingerprint256 } }, N('Certificate pinned — testing again'), function () { invalidate('/credentials'); wizTest(wp); });
      return;
    }
    if ((x = tg.closest('[data-dsc-wretest]'))) { if (ST.ui.wizard) wizTest(ST.ui.wizard); return; }
    if ((x = tg.closest('[data-dsc-wdel]'))) {
      var wid = x.getAttribute('data-dsc-wdel'); if (!wid) { ST.ui.wizard = null; repaint(); return; }
      try { if (!window.confirm(T('Delete this credential?'))) return; } catch (e) { return; /* confirm() blocked (sandboxed frame): never act without the person's yes */ }
      post('/credentials/' + enc(wid) + '/delete', {}, N('Credential deleted'), function () { ST.ui.wizard = null; invalidate('/credentials'); repaint(); });
      return;
    }
  }
  function onChange(ev) {
    var tg = ev.target; if (!tg || !tg.id) return;
    if (tg.id === 'dsc_cf_kind') { ST.ui.credKind = tg.value; repaint(); }
    else if (tg.id.indexOf('dsc_sel_') === 0) { ST.sel[tg.id.slice(8)] = !!tg.checked; }
  }

  /* ── install over the base views (claims the existing "discovery" page) ── */
  var _prev = viewHTML;
  viewHTML = function (v) {
    if (Object.prototype.hasOwnProperty.call(VIEWS, v)) {
      whoami();
      try { return '<div id="dsc-root">' + css() + VIEWS[v]() + '</div>'; }
      catch (e) { return '<div class="card"><div class="muted">' + E(T('This page hit an error')) + ': ' + E(e && e.message) + '</div></div>'; }
    }
    return _prev.apply(this, arguments);
  };
  if (window._asDscWiredVer !== MODULE_VERSION) {
    window._asDscWired = true; window._asDscWiredVer = MODULE_VERSION;
    if (!OVERLAY) { document.addEventListener('click', onClick); document.addEventListener('change', onChange); document.addEventListener('keydown', onKey); }
    else {
      // over an older built-in copy: handle the page's clicks / changes first and stop them reaching the old copy's
      // document listeners (its state is stale and it would act a second time); default actions are untouched
      var inPage = function (ev) { return ev.target && ev.target.closest && ev.target.closest('#dsc-root'); };
      window.addEventListener('click', function (ev) { if (!inPage(ev)) return; onClick(ev); ev.stopPropagation(); }, true);
      window.addEventListener('change', function (ev) { if (!inPage(ev)) return; onChange(ev); ev.stopPropagation(); }, true);
      window.addEventListener('keydown', function (ev) { if (inPage(ev)) onKey(ev); }, true);
      try { if (mine() && typeof renderFocus === 'function') renderFocus(); } catch (e) { /* portal function not available on this page: carry on without it */ }
    }
    setInterval(function () {
      if (typeof document === 'undefined' || !document || document.hidden || !mine()) return;
      var running = ST.cache['/dashboard'] && ST.cache['/dashboard'].data && ST.cache['/dashboard'].data.running && ST.cache['/dashboard'].data.running.length;
      if (running || Date.now() % 30000 < 6000) { invalidate('/dashboard'); invalidate('/runs'); invalidate('/results'); repaint(); }
    }, 6000);
  }
})();
