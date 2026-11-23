// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// install-login-skin.sh (the sign-in page design, nginx sub_filter) with stubbed nginx / curl / reload, so every outcome of
// its final check can be produced: switched on and checked; a sign-in page that answers late (the update has just reloaded
// nginx and restarted services) is waited for instead of failing the step; a sign-in service that stays down is reported as
// that - the design stays on, nothing is put back; a service that compresses its page, and a page served from elsewhere,
// put the original file back and say why; a second run adds nothing twice; --remove gives the original file back; every
// failure line starts with "!! login-skin:" so the update summary can quote it. Run: node login-skin-install.test.js
const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
const SCRIPT = path.resolve(__dirname, '../../ui/install-login-skin.sh');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

const T = fs.mkdtempSync(path.join(os.tmpdir(), 'zyb-loginskin-'));
for (const d of ['sites-enabled', 'conf.d', 'bak', 'web', 'bin']) fs.mkdirSync(path.join(T, d), { recursive: true });
const SITE = path.join(T, 'sites-enabled/sentra');
const ORIG = `server {
    listen 443 ssl;
    server_name ${ZYB_ORG.portal_host};
    location = /logo.webp { root /var/www/sentra; }
    location /login { proxy_pass http://127.0.0.1:9000; }
    location / { root /var/www/sentra; }
}
`;
// nginx: -T prints the file as nginx -T does, -t passes, -V says the sub module is there
fs.writeFileSync(path.join(T, 'bin/nginx'), `#!/bin/bash
case "$1" in -T) echo "# configuration file ${SITE}:"; cat "${SITE}";; -t) exit 0;; -V) echo "configure arguments: --with-http_sub_module" >&2;; esac
`);
// curl: answers by scenario (file scn): ok | slow:N (the first N /login checks get 502) | down | gzip | noline
fs.writeFileSync(path.join(T, 'bin/curl'), `#!/bin/bash
S="$(cat ${T}/scn)"; W=0; H=0; U=""; for a in "$@"; do case "$a" in -w) W=1;; -D) H=1;; https://*) U="\${a#https://127.0.0.1}";; esac; done
if [ "$U" = /zyb-login/zyb-login.js ]; then [ $W = 1 ] && printf 200; exit 0; fi
LOGIN=200
case "$S" in down) LOGIN=502;; slow:*) N="\${S#slow:}"; C=$(cat ${T}/cnt 2>/dev/null || echo 0); if [ $W = 1 ]; then C=$((C+1)); echo $C > ${T}/cnt; fi; [ "$C" -le "$N" ] && LOGIN=502;; esac
if [ $W = 1 ]; then printf '%s' "$LOGIN"; exit 0; fi
if [ $H = 1 ]; then printf 'HTTP/1.1 200 OK\\r\\n'; [ "$S" = gzip ] && printf 'Content-Encoding: gzip\\r\\n'; printf '\\r\\n'; exit 0; fi
TAG=""; grep -q zyb_loginskin "${SITE}" && [ "$S" != gzip ] && [ "$S" != noline ] && TAG='<script src="/zyb-login/zyb-login.js"></script>'
printf '<html><head><title>Sign in</title>%s</head><body><form></form></body></html>' "$TAG"
`);
for (const f of ['nginx', 'curl']) fs.chmodSync(path.join(T, 'bin', f), 0o755);
const env = Object.assign({}, process.env, { ZYB_NGINX_ETC: T, ZYB_NGINX: path.join(T, 'bin/nginx'), ZYB_NGINX_RELOAD: 'true', ZYB_CURL: path.join(T, 'bin/curl'),
  ZYB_BAKDIR: path.join(T, 'bak'), ZYB_WEB: path.join(T, 'web'), ZYB_WAIT: '8' });
const run = (scn, args, wait) => { fs.writeFileSync(path.join(T, 'scn'), scn); try { fs.unlinkSync(path.join(T, 'cnt')); } catch (e) { /* first run */ }
  const r = cp.spawnSync('bash', [SCRIPT].concat(args || []), { env: Object.assign({}, env, wait ? { ZYB_WAIT: wait } : {}), encoding: 'utf8' }); return { rc: r.status, out: r.stdout + r.stderr }; };
const site = () => fs.readFileSync(SITE, 'utf8');
const fresh = () => fs.writeFileSync(SITE, ORIG);

fresh();
let r = run('ok', ['--desk', 'itdesk@example.test']);
ok(r.rc === 0 && /==> done: the sign-in page shows the new design/.test(r.out), 'switched on and checked: ' + r.out);
ok(/location \^~ \/zyb-login\//.test(site()) && /location \/login \{ sub_filter_types text\/html;.*set \$zyb_loginskin 1;/.test(site()), 'the public script location and the sub_filter line in /login');
ok(/var DESK = 'itdesk@example\.test'/.test(fs.readFileSync(path.join(T, 'web/zyb-login.js'), 'utf8')), 'the script is in place with the service desk contact');
const once = site();
r = run('ok'); ok(r.rc === 0 && site() === once, 'a second run (every update) adds nothing twice');

// the sign-in page answers late: waited for, not a failure (this is what failed the update step before)
fresh(); r = run('slow:2');
ok(r.rc === 0 && /==> done/.test(r.out) && /zyb_loginskin/.test(site()), 'sign-in page answering after two 502s: waited for, done: ' + r.out);

// the sign-in service stays down: said so; the design stays on (removing it would not help)
fresh(); r = run('down', [], '3');
ok(r.rc === 1 && /^!! login-skin: the sign-in page itself did not answer \(HTTP 502 after 3s\)/m.test(r.out) && /systemctl status sentra-auth/.test(r.out), 'service down: named as such: ' + r.out);
ok(/zyb_loginskin/.test(site()) && !/the original nginx file was put back/.test(r.out), 'service down: the design is not taken off');

// compressed pages and a page served from elsewhere: the original file back, and why
fresh(); r = run('gzip', [], '3');
ok(r.rc === 1 && /^!! login-skin: the sign-in service sends its page compressed/m.test(r.out) && /proxy_set_header Accept-Encoding/.test(r.out), 'compressed: the cause and the line to add: ' + r.out);
ok(site() === ORIG, 'compressed: the original nginx file is back');
fresh(); r = run('noline', [], '3');
ok(r.rc === 1 && /^!! login-skin: the sign-in page did not get the design line/m.test(r.out) && site() === ORIG, 'no design line: original back, reason given');

// switched off
fresh(); run('ok'); r = run('ok', ['--remove']);
ok(r.rc === 0 && site() === ORIG && !fs.existsSync(path.join(T, 'web')), 'removed: the original page and no script left: ' + r.out);
// bad options are reported in the same form (the update summary quotes the last "!!" line)
r = run('ok', ['--desk', "x';alert(1)//"]); ok(r.rc === 1 && /^!! login-skin --desk:/m.test(r.out), 'a desk value with quotes is refused');
r = run('ok', ['--bogus']); ok(r.rc === 1 && /^!! login-skin: unknown option/m.test(r.out), 'unknown option reported');

fs.rmSync(T, { recursive: true, force: true });
console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
