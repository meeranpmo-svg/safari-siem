// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * UEBA geo / IP feature extraction. The engine's core enrichment (engine/enrich.js) only tags public IPs; it has no
 * country database. So UEBA derives geo features from what collectors already put on the event:
 *   - country  : fields.country | fields.geo_country | fields.src_country (M365 supplies location.countryOrRegion)
 *   - lat/lon  : fields.geo_lat/geo_lon | fields.latitude/longitude (when a collector enriched them)
 *   - subnets  : /24 and /16 (IPv4) or /48 (IPv6) computed from the source IP (no external lookup)
 * Everything is standard library only; impossible-travel uses coordinates when present, otherwise a conservative
 * "different country within N minutes" rule.
 */
const { parseIP } = require('../detect/ip');

function firstField(ev, keys) {
  const f = (ev && ev.fields) || {};
  for (const k of keys) { const v = f[k]; if (v !== undefined && v !== null && v !== '') return String(v); }
  return '';
}

function subnetsOf(ip) {
  const p = parseIP(ip);
  if (!p) return { s24: '', s16: '' };
  if (p.v === 4) {
    const a = (p.n >>> 24) & 255, b = (p.n >>> 16) & 255, c = (p.n >>> 8) & 255;
    return { s24: `${a}.${b}.${c}.0/24`, s16: `${a}.${b}.0.0/16` };
  }
  // IPv6: /48 prefix (first three hextets)
  const top = p.n >> 80n;
  const h = [];
  for (let i = 2; i >= 0; i--) h.push(((top >> BigInt(i * 16)) & 0xffffn).toString(16));
  return { s24: `${h.join(':')}::/48`, s16: `${h.slice(0, 2).join(':')}::/32` };
}

function num(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }

/** geoOf(ev) → { ip, country, subnet24, subnet16, lat, lon } using the event's src_ip (fallback host_ip). */
function geoOf(ev) {
  const ip = ev.src_ip || ev.host_ip || '';
  const { s24, s16 } = subnetsOf(ip);
  const country = firstField(ev, ['country', 'geo_country', 'src_country', 'countryorregion']).toUpperCase().slice(0, 32);
  const lat = num(firstField(ev, ['geo_lat', 'latitude', 'lat']));
  const lon = num(firstField(ev, ['geo_lon', 'longitude', 'lon', 'lng']));
  return { ip, country, subnet24: s24, subnet16: s16, lat, lon };
}

const R_KM = 6371;
function haversineKm(a, b) {
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const la1 = toRad(a.lat), la2 = toRad(b.lat);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin(dLon / 2) ** 2;
  return 2 * R_KM * Math.asin(Math.min(1, Math.sqrt(h)));
}

/**
 * travelInfeasible(a, b, gapMs, cfg) → { infeasible, km, kph, reason } | null (cannot tell).
 *   a,b are geoOf() results; gapMs is |t(b) - t(a)|.
 *   With coordinates: implied speed > max_kph over at least min_km.
 *   Without coordinates: different non-empty countries within min_gap_min_diff_country minutes.
 */
function travelInfeasible(a, b, gapMs, cfg = {}) {
  const maxKph = cfg.max_kph || 900;
  const minKm = cfg.min_km || 500;
  const hours = Math.max(gapMs, 1) / 3600000;
  if (a.lat !== null && a.lon !== null && b.lat !== null && b.lon !== null) {
    const km = haversineKm(a, b);
    if (km < minKm) return { infeasible: false, km, kph: km / hours, reason: 'distance below floor' };
    const kph = km / hours;
    return { infeasible: kph > maxKph, km: Math.round(km), kph: Math.round(kph), reason: `${Math.round(km)} km in ${(hours * 60).toFixed(0)} min = ${Math.round(kph)} km/h` };
  }
  if (a.country && b.country && a.country !== b.country) {
    const minGapMs = (cfg.min_gap_min_diff_country || 60) * 60000;
    return { infeasible: gapMs < minGapMs, km: null, kph: null, reason: `${a.country}→${b.country} in ${(gapMs / 60000).toFixed(0)} min` };
  }
  return null;
}

module.exports = { geoOf, subnetsOf, haversineKm, travelInfeasible };
