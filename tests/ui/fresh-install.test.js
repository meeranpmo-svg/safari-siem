// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The fresh-server installer (deploy/install-fresh-server.sh) and its nginx site template, checked without a server:
// the script parses, the template renders with nothing left over, every location that needs a session has the check,
// the anchor the dashboards installer looks for is there, and the installer never creates accounts or touches
// passwords / two-factor settings (those belong to a person and to the sign-in service's own tool). No browser needed.
// Run: node fresh-install.test.js
const fs = require('fs'), path = require('path'), { spawnSync } = require('child_process');
const ROOT = path.resolve(__dirname, '../..');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = path.join(ROOT, 'deploy/install-fresh-server.sh'), TPL = fs.readFileSync(path.join(ROOT, 'deploy/nginx-site.conf.tmpl'), 'utf8'), src = fs.readFileSync(SH, 'utf8');

ok(spawnSync('bash', ['-n', SH]).status === 0, 'the installer is valid shell');
const help = spawnSync('bash', [SH, '--help'], { encoding: 'utf8' });
ok(help.status !== 0 && /run with sudo/.test(help.stdout + help.stderr) || /--auth-src/.test(help.stdout), 'it refuses to run without root, or prints its options');

// the template: every token the installer fills, and nothing else
const tokens = [...new Set(TPL.match(/@[A-Z_]+@/g))].sort();
ok(tokens.join() === '@AUTH_PORT@,@CERT@,@HOST@,@IP@,@KEY@,@LOGO_TYPE@', 'template tokens: ' + tokens.join());
for (const t of tokens) ok(src.includes('s|' + t + '|'), 'the installer fills ' + t);
const site = TPL.replace(/@HOST@/g, 'soc.synthetic.example').replace(/@IP@/g, '10.0.0.5').replace(/@CERT@/g, '/c').replace(/@KEY@/g, '/k').replace(/@AUTH_PORT@/g, '9098').replace(/@LOGO_TYPE@/g, 'image/png');
ok(!/@[A-Z_]+@/.test(site), 'nothing is left unfilled');
ok(/listen 80;[\s\S]*return 301 https:\/\/\$host\$request_uri;/.test(site) && /listen 443 ssl;/.test(site) && /ssl_protocols\s+TLSv1\.2 TLSv1\.3;/.test(site), 'HTTP redirects to HTTPS; TLS 1.2 and 1.3 only');
ok(/location = \/auth\/verify \{\s*internal;/.test(site), 'the session check cannot be called from outside');
ok(/location = \/login \{[^}]*limit_req zone=sentra_login/.test(site) && /proxy_set_header X-Auth-User "";/.test(site), 'sign-in is rate-limited and cannot be sent identity headers');
ok(/location = \/logo\.webp/.test(site), 'the anchor add-dashboards-nginx.sh inserts /dashboards/ above');
ok(/include \/opt\/sentra-siem\/install\/nginx-soc\.conf;/.test(site) && /include \/opt\/sentra-itam\/install\/nginx-itam\.conf;/.test(site), 'both engines sit behind the site');
ok(/location \/ \{ return 404; \}/.test(site) && /location = \/ \{ return 302 \/dashboards\/; \}/.test(site), 'nothing else is served; the site opens on the home page');
// the engines' own location files demand a session on every browser-facing location
for (const f of ['backend/siem/install/nginx-soc.conf', 'backend/itam/install/nginx-itam.conf']) {
  const t = fs.readFileSync(path.join(ROOT, f), 'utf8'), blocks = t.split(/\n(?=location )/).filter((b) => /^location /.test(b));
  const open = blocks.filter((b) => !/auth_request\s+\/auth\/verify;/.test(b)).map((b) => b.split('{')[0].trim());
  ok(blocks.length > 0 && open.every((l) => /ingest|agent|netexec/.test(l)), f + ': only the agent / ingest locations work without a session (they check their own token): ' + open.join(' | '));
}
// the zones the locations use exist
ok(/zone=sentra_login:/.test(src) && /zone=sentra_api:/.test(fs.readFileSync(path.join(ROOT, 'backend/siem/install/nginx-soc-http.conf'), 'utf8')), 'the rate-limit zones are defined');
// accounts, passwords and two-factor: never the installer's business
const code = src.split('\n').filter((l) => !/^\s*#/.test(l) && !/^\s*echo /.test(l)).join('\n');
ok(!/totp|mfa|2fa|two-?factor|passw|pbkdf|bootstrap-admin\.js"?\s*(<|--)/i.test(code.replace(/install -m 644[^\n]*bootstrap-admin\.js[^\n]*/g, '').replace(/\[ -f [^\n]*bootstrap-admin\.js[^\n]*/g, '')), 'the installer does not create accounts, set passwords or touch two-factor settings');
ok(/install -m 644 -o root -g root "\$AUTH_JS" \/opt\/sentra-auth\/auth\.js/.test(src) && !/sed -i[^\n]*\/opt\/sentra-auth/.test(src), 'the sign-in service is copied as it is, never edited');
ok(/_HOST=127\.0\.0\.1/.test(src), 'the sign-in service listens on the loopback address only');
console.log(bad ? 'FAILED ' + (n - bad) + '/' + n + ' checks' : 'ALL ' + n + ' checks passed');
process.exit(bad ? 1 : 0);
