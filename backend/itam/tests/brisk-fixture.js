// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SYNTHETIC Business Risk workbooks (risk register + RAS) in the layout of the department's Excel files - invented departments, codes,
// texts and limits; no customer record. Shared by tests/business-risk.test.js and tools/frontend-audit/business-risk.test.js.
const fs = require('fs'), path = require('path'), vm = require('vm');
const XL = (() => { const w = { TextEncoder, Blob }; w.window = w; vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../../ui/vendor/zyb-xlsx.js'), 'utf8'), w); return w.zybXlsx; })();
const b64 = async (sheets) => Buffer.from(await XL.build(sheets, { title: 'synthetic' }).arrayBuffer()).toString('base64');

const REG_H = ['Department', 'S. No.', 'Risk Code', 'Risk Title', 'Risk Description', 'Date of Risk', 'Risk Areas', 'Primary Risk Category - Risk Map', 'Secondary Risk Category - Risk Map', 'Impact',
  'Likelihood', 'Inherent Risk Rating', 'Risk Owner', 'Control', 'Treatment Plan', 'Control Implementation Target Date', 'Control Rating', 'Exposure', 'Exposure Rating Factors', 'Residual Risk Rating', 'Treatment Status', 'Response', 'Status', 'Monitoring Method'];
const IMP = ['1 – Negligible', '2 – Minor', '3 – Moderate ', '4 – Significant', '5 – Major'], LIK = ['1 - Unlikely', '2 - Rare', '3 - Possible', '4 - Likely', '5 - Almost Certain'];
const AREAS = [
  ['Insurance_Risk', 'Synthetic Claims', 'Claims', ['claim settlement delay', 'claim fraud detection', 'claim reserve adequacy', 'claim document verification', 'claim surveyor appointment', 'claim workshop approval'], 'claims handling and settlement of policyholder claims'],
  ['Financial_Risk', 'Synthetic Finance', 'Treasury', ['liquidity forecast', 'budget variance', 'investment concentration', 'receivable collection', 'cash reconciliation', 'currency exposure'], 'treasury cash liquidity and budget control of the company'],
  ['Operational_Risk', 'Synthetic IT', 'Technology', ['server outage', 'backup restore', 'patch backlog', 'access review', 'network failure', 'application change'], 'information technology systems availability and change management'],
];
function registerRows() {
  const rows = []; let n = 0;
  for (const [area, dept, cat, topics, ctx] of AREAS) topics.forEach((tp, i) => {
    for (const v of [0, 1]) {
      n++; const L = 2 + ((i + v) % 2), I = 3 + (i % 2), sc = L * I, band = sc <= 4 ? 'Low' : sc <= 9 ? 'Low-Medium' : sc <= 12 ? 'Medium' : 'High';
      rows.push([dept, String(n), dept.split(' ')[1].slice(0, 3).toUpperCase() + '-' + (i * 2 + v + 1), (v ? 'Weak ' : 'Risk of ') + tp + (v ? ' oversight' : ''), 'Synthetic: ' + tp + ' affecting ' + ctx + (v ? ' through weak monitoring' : ''), '2026-01-21',
        area, cat, tp.split(' ')[0], IMP[I - 1], LIK[L - 1], band + ' (' + sc + ')', 'Head of ' + dept.split(' ')[1], '1- synthetic control for ' + tp, '1- synthetic plan', 'Implemented', 'Controls are fully effective',
        'Minor', 'A - Control Definition', sc >= 10 ? 'Class II' : 'Class I', 'Treatment are in place', 'Mitigate', 'Solved', 'Monitor']);
    }
  });
  // the cases the engine must catch
  rows.push(['Synthetic IT', '90', 'IT-90', 'Risk of server outage', 'Synthetic: server outage affecting information technology systems availability and change management', '2026-01-21', 'Operational_Risk', 'Technology', 'server', IMP[3], LIK[2], 'Low-Medium (12)', 'Head of IT', 'x', 'x', 'Q1-2026', 'Controls are not effective', 'Minor', 'C - Control Effectiveness', 'Class I', 'Treatment are not in place', 'Mitigate', 'Solved', 'Verify']);
  rows.push(['Synthetic IT', '91', 'IT-1', 'Duplicate code row', 'Synthetic: a second row reusing a code', '2026-01-21', 'Operational_Risk', 'Technology', 'x', IMP[1], LIK[1], 'Low (4)', '', 'x', 'x', 'Implemented', 'Controls are fully effective', 'Limited', 'A - Control Definition', 'Class I', 'Treatment are in place', 'Mitigate', 'In Progress', 'Monitor']);
  return rows;
}
const RAS_H = ['S.', 'Components', 'Description', 'Metric / Formula', 'Source', 'Responsibility', 'RBS Category', 'Risk Capacity Floor', 'Risk Tolerance Floor', 'Risk Appetite Floor', 'Risk Appetite Ceiling', 'Risk Tolerance Ceiling', 'Risk Capacity Ceiling'];
function rasRows() {
  return [
    ['1', 'STRATEGIC RISK', '', '', '', '', '', '', '', '', '', '', ''],
    ['1', 'Synthetic solvency ratio', 'Regulatory capital over the required margin (synthetic)', 'capital / margin', 'synthetic', 'Synthetic Finance', 'Strategic Risk', '2', '2.25', '>=250%', '-', '-', '-'],
    ['2', 'Synthetic combined ratio', 'Claims and expenses over earned premium (synthetic)', 'x', 'synthetic', 'Synthetic Finance', 'Strategic Risk', '-', '-', '-', '<97%', '0.98', '>100%'],
    ['3', '', 'Synthetic combined ratio for one line, limits out of order', 'x', 'synthetic', 'Synthetic Finance', 'Strategic Risk', '-', '-', '-', '<95%', '0.9', '>98%'],
    ['2', 'OPERATIONAL RISK- IT', '', '', '', '', '', '', '', '', '', '', ''],
    ['1', 'Synthetic system availability', 'Core system availability (synthetic)', 'uptime', 'synthetic', 'Synthetic IT', 'Operational Risk', '0.8', '0.85', '0.95', '-', '-', '-'],
    ['2', 'Synthetic disaster recovery time', 'Time to recover the core system (synthetic)', 'x', 'synthetic', 'Synthetic IT', 'Operational Risk', '-', '-', '1 hours', '3 hours', '4 hours', '5 hours'],
    ['3', 'Synthetic treaty limits', 'Business written within treaty limits (synthetic)', 'x', 'synthetic', 'Synthetic IT', 'Operational Risk', '(Yes / No)', '', '', '', '', ''],
    ['4', 'Synthetic active return', 'Return against the benchmark (synthetic)', 'x', 'synthetic', 'Synthetic Finance', 'Market Risk', 'Lower than the benchmark by 1%', '', 'Higher than the benchmark', '-', '-', '-'],
    ['5', 'Synthetic IFRS 17 ratio', 'Monitored only (synthetic)', 'x', 'synthetic', 'Synthetic Finance', 'Strategic Risk', '', '', '', '', '', ''],
  ];
}
const registerB64 = () => b64([{ name: 'Dashboard', columns: [{ h: 'synthetic' }], rows: [['x']] }, { name: 'Risk Register', columns: REG_H.map((h) => ({ h })), rows: registerRows() }]);
const rasB64 = () => b64([{ name: 'RAS 2026 - Final', columns: RAS_H.map((h) => ({ h })), rows: rasRows() }]);
module.exports = { registerB64, rasB64, registerRows, rasRows, REG_H, b64 };
