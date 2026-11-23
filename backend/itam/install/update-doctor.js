#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * update-doctor.js - makes an IT Asset Management update verifiable instead of all-or-nothing (used by install/lib-itam.sh).
 *   preflight <installed engine dir> <package engine dir>
 *       loads every installed engine module in this throw-away process BEFORE the service restarts. A module that require()s a
 *       file nobody installed is fixed here (the file is copied from the package) instead of the engine failing to start and the
 *       whole update rolling back. Prints JSON {checked, ok, supplied[], errors[]}. Never starts the engine (main.js is skipped).
 *   diagnose <log file>
 *       reads the service log and names the cause of each failure it recognises, with the fix - deterministic rules, so the same
 *       log always gives the same answer and nothing is guessed. Prints JSON {findings[]}.
 *   report <report file> <installer> <status> [json detail]
 *       records this installer's result in the update report the Update Health page reads (one entry per installer, newest kept).
 */
const fs = require('node:fs');
const path = require('node:path');

const RULES = [
  { id: 'missing-module', re: /Cannot find module '([^']+)'/, cause: (m) => 'a file the engine needs is missing: ' + m[1],
    fix: (m) => (/^\.{1,2}\//.test(m[1]) || m[1].startsWith('/') ? 'copy the whole sentra-itam folder and run the update again - the file ' + path.basename(m[1]) + (/\.(js|json)$/.test(m[1]) ? '' : '.js') + ' was not installed' : 'the Node.js package ' + m[1] + ' is not installed - run the update, which installs vendor packages') },
  { id: 'duty-module-missing', re: /duty: module not installed[^{]*\{[^}]*"module":"\.\/([a-z0-9-]+)"/, cause: (m) => 'the module ' + m[1] + ' is not on the server, so its page reports "not installed"', fix: (m) => 'run the update again; it copies ' + m[1] + '.js (it is read from duty.js)' },
  { id: 'permission', re: /EACCES[^']*'([^']+)'/, cause: (m) => 'the engine is not allowed to read ' + m[1], fix: (m) => 'sudo chown root:sentra-itam ' + m[1] + ' && sudo chmod 640 ' + m[1] },
  { id: 'syntax', re: /SyntaxError: ([^\n]+)/, cause: (m) => 'a JavaScript file does not parse: ' + m[1].slice(0, 160), fix: () => 'a file was cut short or edited by hand - copy the package again and re-run the update' },
  { id: 'port-in-use', re: /EADDRINUSE.*:(\d{2,5})/, cause: (m) => 'port ' + m[1] + ' is already used by another process', fix: (m) => 'find it with: sudo ss -ltnp | grep :' + m[1] + ' - stop the old process, then restart sentra-itam' },
  { id: 'python-import', re: /(ModuleNotFoundError|ImportError): (No module named '[^']+'|[^\n]+)/, cause: (m) => 'the Python rules cannot load: ' + m[2].slice(0, 160), fix: () => 'run the update again - it copies every pyengine/*.py file together' },
  { id: 'config-json', re: /(config|secrets)\.json[^\n]*(Unexpected token|JSON)/i, cause: (m) => 'the ' + m[1] + '.json file is not valid JSON', fix: (m) => 'check /etc/sentra-itam/' + m[1] + '.json (a missing comma or quote) - the update does not change it' },
  { id: 'vault-key', re: /credential vault unavailable: ([^\n]+)/, cause: (m) => 'the credential vault key cannot be read: ' + m[1].slice(0, 120), fix: () => 'check discovery.vault_key_file in /etc/sentra-itam/config.json and its permissions (640, group sentra-itam)' },
];

function diagnose(text) {
  const out = [], seen = new Set();
  for (const line of String(text || '').split('\n')) {
    for (const r of RULES) {
      const m = line.match(r.re); if (!m) continue;
      const key = r.id + '|' + m[1]; if (seen.has(key)) break; seen.add(key);
      out.push({ rule: r.id, cause: r.cause(m), fix: r.fix(m), line: line.trim().slice(0, 300) });
      break;
    }
  }
  return { findings: out };
}

function preflight(appDir, pkgDir) {
  const res = { checked: 0, ok: true, supplied: [], errors: [] };
  const files = fs.existsSync(appDir) ? fs.readdirSync(appDir).filter((f) => f.endsWith('.js') && f !== 'main.js') : [];
  const tryLoad = (f) => { const p = path.join(appDir, f); try { delete require.cache[require.resolve(p)]; require(p); return null; } catch (e) { return e; } };
  for (const f of files) {
    res.checked++;
    let e = tryLoad(f);
    // a relative file the module needs that is missing: supply it from the package, then load again (at most 5 times)
    for (let i = 0; e && e.code === 'MODULE_NOT_FOUND' && i < 5; i++) {
      const m = String(e.message).match(/Cannot find module '(\.{1,2}\/[^']+)'/); if (!m) break;
      const from = (e.requireStack && e.requireStack[0]) || path.join(appDir, f);
      let rel = path.relative(appDir, path.resolve(path.dirname(from), m[1])); if (!/\.(js|json)$/.test(rel)) rel += '.js';
      if (rel.startsWith('..')) break;
      const src = path.join(pkgDir, rel);
      if (!pkgDir || !fs.existsSync(src)) break;
      fs.mkdirSync(path.dirname(path.join(appDir, rel)), { recursive: true });
      fs.copyFileSync(src, path.join(appDir, rel)); res.supplied.push(rel);
      e = tryLoad(f);
    }
    if (e) { res.ok = false; res.errors.push({ module: f, code: e.code || e.name || 'error', message: String(e.message).split('\n')[0].slice(0, 300) }); }
  }
  return res;
}

function report(file, installer, status, detail) {
  let doc = { updated_at: null, installers: {} };
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); if (!doc.installers) doc.installers = {}; } catch (e) { /* first report on this server */ }
  let d = {}; try { d = detail ? JSON.parse(detail) : {}; } catch (e) { d = { note: String(detail).slice(0, 500) }; }
  const at = new Date().toISOString();
  doc.installers[installer] = Object.assign({ status, at }, d);
  doc.updated_at = at;
  fs.writeFileSync(file + '.tmp', JSON.stringify(doc, null, 1)); fs.renameSync(file + '.tmp', file);
  return doc;
}

// the steps that did not end ok, with what they named - printed at the end of the update so nobody has to scroll for it
function summary(file) {
  let doc; try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return ''; }
  const out = [];
  for (const [k, v] of Object.entries(doc.installers || {})) {
    if (!v || v.status === 'ok') continue;
    out.push('   ' + k + ' (' + v.status + (v.at ? ', ' + v.at.slice(0, 16).replace('T', ' ') : '') + ')' + (v.missing ? ': pages not answering: ' + v.missing : '') + (v.reason ? ': ' + v.reason : '') + (v.note ? ': ' + v.note : ''));
    for (const f of [].concat(v.findings || []).slice(0, 6)) out.push('     - ' + (typeof f === 'string' ? f : [f.title || f.code || f.module, f.message || f.detail, f.fix ? 'fix: ' + f.fix : ''].filter(Boolean).join(' - ')).slice(0, 300));
  }
  return out.length ? out.join('\n') + '\n' : '';
}

if (require.main === module) {
  const [mode, a, b, c, d] = process.argv.slice(2);
  try {
    if (mode === 'preflight') { process.stdout.write(JSON.stringify(preflight(a, b))); process.exit(0); }
    if (mode === 'diagnose') { process.stdout.write(JSON.stringify(diagnose(fs.existsSync(a) ? fs.readFileSync(a, 'utf8') : a))); process.exit(0); }
    if (mode === 'report') { report(a, b, c, d); process.exit(0); }
    if (mode === 'summary') { process.stdout.write(summary(a)); process.exit(0); }
    process.stderr.write('usage: update-doctor.js preflight|diagnose|report ...\n'); process.exit(2);
  } catch (e) { process.stderr.write('update-doctor: ' + e.message + '\n'); process.exit(1); }
}

module.exports = { diagnose, preflight, report, summary, RULES };
