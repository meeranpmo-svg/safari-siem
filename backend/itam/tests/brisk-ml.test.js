// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The Business Risk machine learning (engine/brisk-ml.js) on SYNTHETIC text and numbers: tokens, TF-IDF similarity, naive Bayes with
// leave-one-out, Holt forecasting and the breach probability, the RAS limit parser (ratios, %, ranges, durations, SAR million, ratings,
// yes / no, text, out-of-order and mixed-scale limits), zones and value parsing.
const test = require('node:test');
const assert = require('node:assert/strict');
const M = require('../engine/brisk-ml');

test('tokens, TF-IDF and similarity', () => {
  assert.deepEqual(M.tokens('The Claims settlement delays in Motor'), ['claim', 'settlement', 'delay', 'motor']);
  const V = M.tfidf(['claim settlement delay motor', 'claim settlement delay motor workshop', 'liquidity budget treasury']);
  assert.ok(M.cosine(V.vectors[0], V.vectors[1]) > 0.8); assert.equal(M.cosine(V.vectors[0], V.vectors[2]), 0);
  assert.equal(M.neighbours(V.vectors, 0, 5, 0.2)[0].j, 1);
  assert.ok(M.shared(V.vectors[0], V.vectors[1]).includes('claim'));
});

test('naive Bayes, leave-one-out', () => {
  const docs = ['claim fraud motor', 'claim settlement medical', 'claim surveyor motor', 'liquidity cash budget', 'budget variance treasury', 'investment liquidity concentration'];
  const y = ['ins', 'ins', 'ins', 'fin', 'fin', 'fin'], B = M.bayesTrain(docs, y);
  const p = M.bayesPredict(B, 'motor claim delay'); assert.equal(p[0].label, 'ins'); assert.ok(p[0].p > 0.5); assert.ok(Math.abs(p.reduce((a, x) => a + x.p, 0) - 1) < 0.01);
  const loo = M.bayesPredict(B, docs[0], { label: 'ins', text: docs[0] }); assert.equal(loo[0].label, 'ins', 'still classified without itself');
});

test('Holt forecast and breach probability', () => {
  assert.match(M.holt([1, 2, 3]).why, /needs 4/);
  const H = M.holt([10, 9, 8, 7, 6]); assert.ok(H.trend < 0); assert.ok(H.forecast[0].value < 6); assert.ok(H.forecast[0].lo <= H.forecast[0].value && H.forecast[0].hi >= H.forecast[0].value);
  assert.ok(H.pBelow(5.5, 1) > 0.5); assert.ok(H.pAbove(20, 1) < 0.01); assert.match(H.why, /not a promise/);
  assert.ok(Math.abs(M.normCdf(0) - 0.5) < 1e-6); assert.ok(M.normCdf(1.96) > 0.97);
});

test('RAS limits, zones and values', () => {
  assert.equal(M.parseLimit('<70%').v, 0.7); assert.equal(M.parseLimit('>=250%').v, 2.5); assert.equal(M.parseLimit('0.75').v, 0.75); assert.equal(M.parseLimit('-').kind, 'blank');
  assert.deepEqual([M.parseLimit('70% - 90%').lo, M.parseLimit('70% - 90%').hi], [0.7, 0.9]); assert.deepEqual([M.parseLimit("'-5%-20%").lo, M.parseLimit("'-5%-20%").hi], [-0.05, 0.2]);
  assert.deepEqual([M.parseLimit('1 days').v, M.parseLimit('30 Min').v, M.parseLimit('1H').v], [24, 0.5, 1]);
  assert.deepEqual([M.parseLimit('100 MN - 120 MN').hi, M.parseLimit('100 MN - 120 MN').unit], [120, 'SAR million']);
  assert.equal(M.parseLimit('BBB+').kind, 'rating'); assert.equal(M.parseLimit('(Yes / No)').kind, 'boolean'); assert.equal(M.parseLimit('Higher than the benchmark').kind, 'text');
  const floor = M.parseLimits({ cap_floor: '2', tol_floor: '2.25', app_floor: '>=250%', app_ceil: '-', tol_ceil: '-', cap_ceil: '-' });
  assert.deepEqual([floor.kind, floor.unit, floor.issues.length], ['floor', 'ratio', 0]);
  assert.deepEqual([M.zoneOf(floor, 2.6).zone, M.zoneOf(floor, 2.4).zone, M.zoneOf(floor, 2.1).zone, M.zoneOf(floor, 1.9).zone], ['within_appetite', 'outside_appetite', 'outside_tolerance', 'capacity_breach']);
  const band = M.parseLimits({ cap_floor: '<50%', tol_floor: '0.55', app_floor: '0.6', app_ceil: '0.7', tol_ceil: '0.75', cap_ceil: '>85%' });
  assert.equal(band.kind, 'band'); assert.equal(M.zoneOf(band, 0.65).zone, 'within_appetite'); assert.deepEqual([M.zoneOf(band, 0.8).zone, M.zoneOf(band, 0.8).side], ['outside_tolerance', 'above']); assert.equal(M.zoneOf(band, 0.57).side, 'below');
  assert.match(M.parseLimits({ app_ceil: '<95%', tol_ceil: '0.9', cap_ceil: '>98%' }).issues[0], /ceilings out of order/);
  assert.match(M.parseLimits({ cap_floor: '<85', tol_floor: '0.95', app_floor: '1' }).issues.join(' '), /mix scales/);
  assert.equal(M.parseLimits({ app_ceil: 'BBB-', tol_ceil: 'BB+', cap_ceil: 'BB' }).kind, 'rating');
  assert.equal(M.parseLimits({}).kind, 'none'); assert.equal(M.parseLimits({ cap_floor: '(Yes / No)' }).kind, 'boolean'); assert.equal(M.parseLimits({ app_floor: 'Higher than the benchmark' }).kind, 'manual');
  assert.equal(M.parseValue(floor, '82%').v, 0.82); assert.match(M.parseValue(floor, '82').error, /ratio/); assert.match(M.parseValue(floor, 'abc').error, /number/);
  assert.equal(M.parseValue({ kind: 'boolean' }, 'Yes').v, 1); assert.equal(M.parseValue({ kind: 'rating' }, 'bbb+').text, 'BBB+'); assert.equal(M.parseValue({ kind: 'band', unit: 'hours' }, '90 min').v, 1.5);
});
