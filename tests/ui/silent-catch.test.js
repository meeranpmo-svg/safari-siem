// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The pages' half of the "never swallow an error silently" rule (CLAUDE.md, error handling): in every dashboard page and our
// own vendor scripts an empty catch - try{…}catch(e){}, .catch(function(){}), .catch(()=>{}) - must say why in a comment, and
// a confirm() inside a try must not let the action go ahead when the browser blocks the dialog (sandboxed frame): the catch
// has to return. Third-party libraries (Chart.js, d3, topojson, Guacamole) are not ours and are left out. No browser needed.
// Run: node silent-catch.test.js
const fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const THIRD_PARTY = new Set(['chart.umd.js', 'd3-sankey.min.js', 'd3.min.js', 'guacamole-common.js', 'topojson-client.min.js']);
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const EMPTY = /catch\s*\(\s*\w*\s*\)\s*\{\s*\}|\.catch\(\s*function\s*\(\s*\w*\s*\)\s*\{\s*\}\s*\)|\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)|catch\s*\{\s*\}/g;
const CONFIRM = /try\s*\{\s*if\s*\(\s*!\s*(?:window\.)?confirm\([^;]*\)\s*\)\s*return;\s*\}\s*catch\s*\(\s*\w*\s*\)\s*\{(?!\s*return)/g;
const files = fs.readdirSync(DASH).filter((f) => f.endsWith('.html')).concat(fs.readdirSync(path.join(DASH, 'vendor')).filter((f) => f.endsWith('.js') && !THIRD_PARTY.has(f)).map((f) => 'vendor/' + f));
const empty = [], confirms = [];
for (const f of files) {
  const s = fs.readFileSync(path.join(DASH, f), 'utf8'), line = (i) => s.slice(0, i).split('\n').length;
  let m; EMPTY.lastIndex = 0; while ((m = EMPTY.exec(s))) empty.push(f + ':' + line(m.index));
  CONFIRM.lastIndex = 0; while ((m = CONFIRM.exec(s))) confirms.push(f + ':' + line(m.index));
}
ok(files.length > 100, 'pages and scripts scanned: ' + files.length);
ok(!empty.length, 'no empty catch without a comment saying why (' + empty.length + '):\n  ' + empty.slice(0, 40).join('\n  '));
ok(!confirms.length, 'a blocked confirm() never lets the action go ahead (' + confirms.length + '):\n  ' + confirms.join('\n  '));
console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
