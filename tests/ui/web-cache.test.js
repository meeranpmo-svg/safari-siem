// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// web-cache.sh against a REAL nginx in a temporary prefix: a the organisation server block like the portal's (pages, an
// unversioned and a versioned script, /api/, /dashboards/ with its own Cache-Control). After the script: portal pages and
// unversioned scripts are sent "Cache-Control: no-cache" (re-checked, 304 when unchanged); ?v= files, /api/ and
// /dashboards/ keep what they had; a second run changes nothing; --remove restores the original file; a broken
// config is never left behind (nginx -t fails -> restored, nginx's message shown); a site that sets its own expires keeps it;
// nginx already broken before the step is reported as such. Run: node web-cache.test.js
const fs = require('fs'), os = require('os'), path = require('path'), http = require('http'), cp = require('child_process');
const SCRIPT = path.resolve(__dirname, '../../ui/web-cache.sh');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const get = (port, p, h) => new Promise((res, rej) => http.get({ host: '127.0.0.1', port, path: p, headers: Object.assign({ Host: ZYB_ORG.portal_host }, h || {}) }, (r) => { r.resume(); r.on('end', () => res(r)); }).on('error', rej));

(async () => {
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'zyb-webcache-')), port = 20000 + Math.floor(Math.random() * 20000);
  fs.chmodSync(T, 0o755);   // the nginx worker (www-data / nobody) must read the web root
  for (const d of ['conf.d', 'sites-enabled', 'www/dashboards', 'logs', 'bak']) fs.mkdirSync(path.join(T, d), { recursive: true });
  fs.writeFileSync(path.join(T, 'www/index.html'), '<!doctype html><title>portal</title>');
  fs.writeFileSync(path.join(T, 'www/app.js'), 'var x=1;');
  fs.writeFileSync(path.join(T, 'www/dashboards/index.html'), '<!doctype html><title>dash</title>');
  fs.writeFileSync(path.join(T, 'nginx.conf'), `pid ${T}/nginx.pid; error_log ${T}/logs/error.log; events {}
http { access_log off; client_body_temp_path ${T}/logs; proxy_temp_path ${T}/logs; fastcgi_temp_path ${T}/logs; uwsgi_temp_path ${T}/logs; scgi_temp_path ${T}/logs;
  include ${T}/conf.d/*.conf; include ${T}/sites-enabled/*; }\n`);
  const site = `server {
    listen 127.0.0.1:${port};
    server_name ${ZYB_ORG.portal_host} soc.${ZYB_ORG.domain};
    root ${T}/www;
    add_header X-Content-Type-Options "nosniff" always;
    location / { try_files $uri $uri/ /index.html; }
    location /api/ { default_type application/json; return 200 '{"ok":true}'; }
    location /dashboards/ { add_header Cache-Control "no-cache" always; }
}\n`;
  fs.writeFileSync(path.join(T, 'sites-enabled/sentra'), site);
  const NGX = `nginx -p ${T} -c ${T}/nginx.conf`;
  const env = Object.assign({}, process.env, { ZYB_NGINX_ETC: T, ZYB_NGINX: NGX, ZYB_NGINX_RELOAD: `${NGX} -s reload`, ZYB_BAKDIR: path.join(T, 'bak') });
  const run = (args) => cp.spawnSync('bash', [SCRIPT].concat(args || []), { env, encoding: 'utf8' });
  const wait = () => new Promise((r) => setTimeout(r, 400));
  cp.execSync(NGX);
  try {
    let r = await get(port, '/'); ok(!r.headers['cache-control'], 'before: the portal page has no Cache-Control (browser caches by guesswork)');
    const a = run(); ok(a.status === 0 && /web-cache: done/.test(a.stdout), 'applied: ' + a.stdout + a.stderr); await wait();
    const conf = fs.readFileSync(path.join(T, 'sites-enabled/sentra'), 'utf8');
    ok((conf.match(/ZYB-PORTALCACHE/g) || []).length === 1, 'one line in the server block');
    r = await get(port, '/'); ok(/no-cache/.test(r.headers['cache-control'] || ''), 'portal page re-checked: ' + r.headers['cache-control']);
    ok(r.headers['x-content-type-options'] === 'nosniff', 'server-level security header still inherited (expires, not add_header)');
    r = await get(port, '/app.js'); ok(/no-cache/.test(r.headers['cache-control'] || ''), 'unversioned script re-checked');
    const et = r.headers.etag; r = await get(port, '/app.js', { 'If-None-Match': et }); ok(r.statusCode === 304, 'unchanged file answers 304 (no download)');
    r = await get(port, '/app.js?v=20261026'); ok(!r.headers['cache-control'], 'versioned file left alone: ' + r.headers['cache-control']);
    r = await get(port, '/api/x'); ok(!r.headers['cache-control'], 'API left alone');
    r = await get(port, '/dashboards/index.html'); ok(r.headers['cache-control'] === 'no-cache', 'dashboards keep their own single header: ' + r.headers['cache-control']);
    const b = run(); ok(b.status === 0 && /already/.test(b.stdout), 'second run: nothing to do'); ok(fs.readFileSync(path.join(T, 'sites-enabled/sentra'), 'utf8') === conf, 'second run did not change the file');
    const c = run(['--remove']); await wait(); ok(c.status === 0 && fs.readFileSync(path.join(T, 'sites-enabled/sentra'), 'utf8') === site && !fs.existsSync(path.join(T, 'conf.d/zyb-portal-cache.conf')), 'removed: original file back');
    // a server block that already sets expires at server level: nginx -t fails -> restored, nothing left behind
    const dup = site.replace('root ', 'expires 1h;\n    root ');
    fs.writeFileSync(path.join(T, 'sites-enabled/sentra'), dup); cp.execSync(`${NGX} -s reload`); await wait();
    const d = run(); ok(d.status === 0 && /already sets its own expires/.test(d.stdout), 'own expires kept, not an update failure: ' + d.stdout);
    ok(fs.readFileSync(path.join(T, 'sites-enabled/sentra'), 'utf8') === dup && !fs.existsSync(path.join(T, 'conf.d/zyb-portal-cache.conf')), 'original restored, map removed');
    // nginx already broken before the step: said so with nginx's own message, nothing touched, step fails
    const broken = site.replace('root ', 'bogus_directive on;\n    root ');
    fs.writeFileSync(path.join(T, 'sites-enabled/sentra'), broken);
    const g = run(); ok(g.status === 1 && /already fails before this step/.test(g.stdout) && /bogus_directive/.test(g.stdout), 'pre-existing nginx error named: ' + g.stdout);
    ok(fs.readFileSync(path.join(T, 'sites-enabled/sentra'), 'utf8') === broken, 'nothing changed');
  } finally {
    try { cp.execSync(`${NGX} -s stop`); } catch (e) { /* already stopped */ }
  }
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
