// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A SYNTHETIC workbook in the layout of the Insurance Authority's "RBC Own Funds and Solvency Assessment" template (1-Instructions,
// 2-Own Funds & Solvency, 3-Financial Projection), with the cached values Excel saves. Invented company and figures - no real record.
// o: { period, prior, ownFunds, rbc, mcr, priorOwnFunds, priorRbc, goodwill, q4Claims, fail, noProjection, notTemplate }
const { bookOf } = require('./sca-fixture');

function sheets(o = {}) {
  const P = o.period || 'Q1 2026', PR = o.prior || 'YE 2025';
  const of = o.ownFunds == null ? 1300000 : o.ownFunds, rbc = o.rbc == null ? 500000 : o.rbc, mcr = o.mcr == null ? 170000 : o.mcr;
  const pof = o.priorOwnFunds == null ? 1250000 : o.priorOwnFunds, prbc = o.priorRbc == null ? 480000 : o.priorRbc;
  const gw = o.goodwill == null ? 300000 : o.goodwill, intang = 50000, csm = 120000, ra = 10000;
  const t1 = of + gw + intang - csm - ra, pt1 = pof + gw + intang - csm - ra;
  const adj = -(gw + intang) + csm + ra;
  const of2 = {
    A3: 'Own Funds and Solvency ', A9: 'Select from here >>>> ', B9: 'Insurance Company', C11: 'All amounts in thousands',
    A13: 'Schedule 1 - Required Capital', G14: 'Check', A15: 'Required capital', B15: P, C15: PR,
    A16: 'MCR', B16: mcr, C16: mcr - 5000, G16: o.fail ? 'FAIL' : 'PASS', A17: 'RBC', B17: rbc, C17: prbc,
    A19: 'Schedule 2 - Summary of Solvency Position',
    A21: 'Total Assets', B21: 5000000, C21: 4800000, A22: 'Total Liabilities', B22: 3500000, C22: 3330000,
    A23: 'Regulatory Adjustments ', B23: adj, C23: adj, A24: 'Own Funds ', B24: of, C24: pof,
    A26: 'Eligible Own Funds Available to Meet RBC', B26: of, C26: pof, A27: 'RBC', B27: rbc, C27: prbc,
    A28: 'Solvency Ratio', B28: { f: 'IFERROR(B26/B27,"-")', v: of / rbc }, C28: { f: 'IFERROR(C26/C27,"-")', v: pof / prbc },
    A30: 'Schedule 3 - Basic Own Funds', A32: 'Tier 1', B32: t1, C32: pt1, A33: 'Share capital (synthetic)', B33: 800000, C33: 800000, B34: t1 - 800000, C34: pt1 - 800000,
    A43: 'Tier 2', B43: 0, C43: 0, A54: 'Tier 3', B54: 0, C54: 0,
    A65: 'Schedule 4 - Ancillary Own Funds', A67: 'Tier 2', B67: 0, C67: 0, A78: 'Tier 3', B78: 0, C78: 0,
    A83: 'Schedule 5 - Total Own Funds', A85: 'Total Own Funds ', B85: t1, C85: pt1, A86: 'Tier 1', B86: t1, C86: pt1, A87: 'Tier 2', B87: 0, C87: 0, A88: 'Tier 3', B88: 0, C88: 0,
    A90: 'Schedule 6 - Eligible Own Funds and Limits', A92: 'SCR', A93: 'Tier 1 ', B93: t1, C93: pt1, A94: 'Tier 2', B94: 0, C94: 0,
    A103: 'SCR', A104: 'Tier 1 ', B104: 'PASS', C104: 'PASS', A108: 'MCR', A109: 'Tier 1 ', B109: o.fail ? 'FAIL' : 'PASS', C109: 'PASS',
    A113: 'Schedule 6 - Eligible Own Funds', A116: 'Total Adjustments', B116: adj, C116: adj, A117: 'Net Contractual Service Margin ', B117: csm, C117: csm,
    A118: 'Net Risk Adjustment ', B118: ra, C118: ra, A120: 'Goodwill ', B120: gw, C120: gw, A122: 'Intangible Assets ', B122: intang, C122: intang,
    A124: 'Total Eligible Own Funds Before Adjustments', B124: t1, C124: pt1, A125: 'Total Eligible Own Funds After Adjustments', B125: of, C125: pof,
  };
  const q4c = o.q4Claims == null ? 0.93 : o.q4Claims;
  const claims = [0.80, 0.84, 0.82, 0.86, q4c, 0.85], exp = [0.06, 0.06, 0.06, 0.055, 0.05, 0.057], ri = [0.004, 0.003, 0.0035, 0.003, 0.0025, 0.003], nonatt = [0.07, 0.065, 0.067, 0.06, 0.055, 0.062];
  const cols = ['C', 'D', 'E', 'F', 'G', 'H'], hdr = ['Q1', 'Q2', 'H1', 'Q3', 'Q4', 2026], rev = [1000000, 1050000, 2050000, 1100000, 1150000, 4300000];
  const proj = { A2: 'Financial Forecast ', A9: 'Item' };
  cols.forEach((c, i) => {
    proj[c + '9'] = hdr[i]; proj[c + '10'] = rev[i];
    const comb = claims[i] + exp[i] + ri[i] + nonatt[i];
    proj[c + '36'] = Math.round(rev[i] * (1 - comb) * 0.85); proj[c + '37'] = claims[i]; proj[c + '38'] = exp[i]; proj[c + '39'] = ri[i]; proj[c + '40'] = nonatt[i];
    proj[c + '41'] = { f: c + '37+' + c + '38+' + c + '39+' + c + '40', v: comb }; proj[c + '42'] = rev[i] * 1.3;
  });
  Object.assign(proj, { A10: 'Insurance revenue', A36: 'Net Income, AFTER zakat & tax, attributable to shareholders', A37: 'Claims %', A38: 'Attributable Expenses %', A39: 'Reinsurance %', A40: 'Non-Attributable expenses % (other operating expenses)', A41: 'Net Combined Ratio', A42: 'GWP' });
  const ins = { A3: 'RBC available capital and solvency template (synthetic)', A9: 'Company', B9: 'Synthetic Insurance Co', A21: 'Shared with finance, actuarial and risk?', F21: 'Yes', A22: 'Presented to the Board?', F22: o.boardNo ? 'No' : 'Yes' };
  if (o.notTemplate) return [['Sheet1', { A1: 'hello' }]];
  const out = [['1-Instructions', ins], ['2-Own Funds & Solvency', of2]];
  if (!o.noProjection) out.push(['3-Financial Projection', proj]);
  return out;
}
const build = (o) => bookOf(sheets(o));
const b64 = (o) => build(o).toString('base64');
module.exports = { build, b64 };
