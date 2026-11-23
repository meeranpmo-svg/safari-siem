// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A stateful mock gvmd on a unix socket, speaking GMP, for the vulnerability scan tests (engine and Playwright). SYNTHETIC data:
// 10.20.x.x hosts, made-up NVT names, documentation CVE numbers. st.findings drives the next report; st.status the task state.
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { parseXml, complete, xesc } = require('../engine/gmp');

const CONFIGS = ['daba56c8-73ec-11df-a475-002264764cea', '8715c877-47a0-438d-98a3-27c7a6ab2196'];
function reportXml(st) {
  const res = st.findings.map((f, i) => '<result id="r' + i + '"><name>' + xesc(f.name) + '</name><host>' + f.host + '<asset asset_id="a"/><hostname>' + xesc(f.hostname || '') + '</hostname></host><port>' + f.port + '</port>'
    + '<nvt oid="' + f.oid + '"><type>nvt</type><name>' + xesc(f.name) + '</name><family>General</family><tags>' + xesc('summary=' + (f.summary || 'synthetic summary') + '|insight=x|solution_type=VendorFix') + '</tags>'
    + '<solution type="VendorFix">' + xesc(f.solution || 'Update to the fixed release (synthetic).') + '</solution><refs>' + (f.cves || []).map((c) => '<ref type="cve" id="' + c + '"/>').join('') + '</refs></nvt>'
    + '<threat>x</threat><severity>' + f.score + '</severity><qod><value>' + (f.qod || 80) + '</value></qod><description>' + xesc(f.evidence || 'banner (synthetic)') + '</description></result>').join('');
  return '<get_reports_response status="200" status_text="OK"><report id="' + st.report + '"><report id="' + st.report + '">' + st.hosts.map((h) => '<host><ip>' + h + '</ip></host>').join('')
    + '<results>' + res + '</results></report></report></get_reports_response>';
}

async function startGmpMock(init = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gmp-')), sock = path.join(dir, 'gvmd.sock');
  const st = Object.assign({ user: 'zyberon', password: 'synthetic-pw', status: 'Running', progress: 40, hosts: [], findings: [], commands: [], report: 'rep-1', task: 'task-1', target: 'tgt-1', failAuth: false }, init);
  const server = net.createServer((c) => {
    let buf = '', authed = false;
    c.on('data', (d) => {
      buf += d.toString('utf8');
      while (buf.trim() && complete(buf)) {
        const n = parseXml(buf); buf = '';
        st.commands.push({ name: n.name, attrs: n.attrs, xml: n });
        const ok = (body) => c.write(body);
        const name = n.name;
        if (name === 'authenticate') {
          const u = n.children[0].children.find((x) => x.name === 'username').text, p = n.children[0].children.find((x) => x.name === 'password').text;
          if (st.failAuth || u !== st.user || p !== st.password) { ok('<authenticate_response status="400" status_text="Authentication failed"/>'); continue; }
          authed = true; ok('<authenticate_response status="200" status_text="OK"><role>User</role></authenticate_response>'); continue;
        }
        if (!authed) { ok('<' + name + '_response status="401" status_text="Authenticate first"/>'); continue; }
        if (name === 'get_version') ok('<get_version_response status="200" status_text="OK"><version>22.5</version></get_version_response>');
        else if (name === 'get_scan_configs') ok('<get_scan_configs_response status="200" status_text="OK">' + CONFIGS.map((id) => '<config id="' + id + '"><name>c</name></config>').join('') + '</get_scan_configs_response>');
        else if (name === 'get_port_lists') ok('<get_port_lists_response status="200" status_text="OK"><port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"><name>All IANA assigned TCP</name></port_list></get_port_lists_response>');
        else if (name === 'get_scanners') ok('<get_scanners_response status="200" status_text="OK"><scanner id="08b69003-5fc2-4037-a479-93b440211c73"><name>OpenVAS Default</name></scanner></get_scanners_response>');
        else if (name === 'create_target') ok('<create_target_response status="201" status_text="OK, resource created" id="' + st.target + '"/>');
        else if (name === 'create_task') ok('<create_task_response status="201" status_text="OK, resource created" id="' + st.task + '"/>');
        else if (name === 'start_task') ok('<start_task_response status="202" status_text="OK, request submitted"><report_id>' + st.report + '</report_id></start_task_response>');
        else if (name === 'stop_task') { st.status = 'Stopped'; ok('<stop_task_response status="202" status_text="OK, request submitted"/>'); }
        else if (name === 'get_tasks') ok('<get_tasks_response status="200" status_text="OK"><task id="' + st.task + '"><status>' + st.status + '</status><progress>' + st.progress + '</progress><last_report><report id="' + st.report + '"/></last_report></task></get_tasks_response>');
        else if (name === 'get_reports') ok(reportXml(st));
        else ok('<' + name + '_response status="400" status_text="Unknown command"/>');
      }
    });
    c.on('error', () => { /* the client went away: nothing to answer */ });
  });
  await new Promise((r) => server.listen(sock, r));
  return { st, socket: sock, close: () => new Promise((r) => { server.close(() => { fs.rmSync(dir, { recursive: true, force: true }); r(); }); }) };
}

module.exports = { startGmpMock };
