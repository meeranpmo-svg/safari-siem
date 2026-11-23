// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
// Printable / e-mailable Attack Summary (HTML, self-contained: no scripts, no external resources, inline SVG bars with
// every value also printed as text). English or Arabic (lang 'ar' → <html lang="ar" dir="rtl">; data values such as
// host names, IPs, rule ids stay left-to-right in <bdi>). Every value from the engine passes through esc().
//   renderHtml(report, { lang, org, generatedBy }) → string      renderText(report, { lang }) → plain-text summary
//   subjectOf(report, { lang, scheduleName }) → mail subject      label(key, lang)
const { esc } = require('./common');

const AR = {
  'Attack summary': 'ملخص الهجمات',
  'Security operations report': 'تقرير عمليات الأمن',
  'Period': 'الفترة', 'Generated': 'تاريخ الإنشاء', 'by': 'بواسطة', 'Time zone': 'المنطقة الزمنية',
  'Last 24 hours': 'آخر 24 ساعة', 'Last 7 days': 'آخر 7 أيام', 'Last 30 days': 'آخر 30 يومًا', 'Custom period': 'فترة مخصصة',
  'Key figures': 'الأرقام الرئيسية', 'Security events': 'الأحداث الأمنية', 'Threat events': 'أحداث التهديد', 'Alerts': 'التنبيهات',
  'Open alerts': 'التنبيهات المفتوحة', 'Closed alerts': 'التنبيهات المغلقة', 'Hosts reporting': 'الأجهزة المُبلِّغة', 'Log sources': 'مصادر السجلات',
  'Blocked': 'محظور', 'Allowed': 'مسموح', 'Unknown outcome': 'نتيجة غير معروفة',
  'Alerts by severity': 'التنبيهات حسب الخطورة', 'Severity': 'الخطورة', 'Total': 'الإجمالي', 'Open': 'مفتوح', 'Closed': 'مغلق',
  'Info': 'معلومات', 'Low': 'منخفض', 'Medium': 'متوسط', 'High': 'عالٍ', 'Critical': 'حرج',
  'Open vs closed offenses': 'المخالفات المفتوحة مقابل المغلقة',
  'Closed as true positive': 'أُغلقت كإيجابية صحيحة', 'Closed as false positive': 'أُغلقت كإيجابية كاذبة', 'Closed as benign': 'أُغلقت كحميدة',
  'Cases opened': 'الحالات المفتوحة في الفترة', 'Cases closed': 'الحالات المغلقة في الفترة', 'Cases open now': 'الحالات المفتوحة حاليًا',
  'Attack categories': 'فئات الهجمات', 'Category': 'الفئة', 'Events': 'الأحداث',
  'Failed logons / brute force': 'محاولات الدخول الفاشلة / التخمين', 'Malware / EDR': 'البرمجيات الخبيثة / الحماية الطرفية',
  'Web attacks / WAF': 'هجمات الويب / جدار حماية التطبيقات', 'Intrusion prevention (IPS)': 'منع التسلل (IPS)', 'Data loss prevention (DLP)': 'منع تسرب البيانات (DLP)',
  'Policy violations': 'مخالفات السياسات', 'Firewall blocks': 'حظر جدار الحماية', 'Admin changes': 'التغييرات الإدارية',
  'Blocked vs allowed threat events': 'أحداث التهديد المحظورة مقابل المسموح بها',
  'Firewall, IPS, EDR/antivirus, WAF, DLP and policy events by prevention outcome.': 'أحداث جدار الحماية ومنع التسلل والحماية الطرفية ومكافحة الفيروسات وجدار تطبيقات الويب ومنع تسرب البيانات والسياسات حسب نتيجة المنع.',
  'Trend': 'الاتجاه', 'per hour': 'لكل ساعة', 'per day': 'لكل يوم', 'Time': 'الوقت',
  'Top attacked hosts': 'أكثر الأجهزة تعرضًا للهجمات', 'Host / target': 'الجهاز / الهدف', 'High severity': 'خطورة عالية', 'Sources': 'المصادر', 'Last seen': 'آخر ظهور',
  'Top attacker source IPs': 'أبرز عناوين IP المهاجمة', 'Source IP': 'عنوان IP المصدر', 'Country': 'الدولة', 'Targets': 'الأهداف', 'internal': 'داخلي',
  'Top targeted usernames (failed logons)': 'أكثر أسماء المستخدمين استهدافًا (دخول فاشل)', 'User': 'المستخدم', 'Failures': 'مرات الفشل', 'Hosts': 'الأجهزة',
  'MITRE ATT&CK tactics and techniques': 'أساليب وتقنيات MITRE ATT&CK', 'Tactic': 'الأسلوب', 'Techniques': 'التقنيات',
  'Top triggered rules': 'أكثر قواعد الكشف تفعيلًا', 'Rule': 'القاعدة', 'Highest severity': 'أعلى خطورة',
  'SAMA controls touched': 'ضوابط ساما المتأثرة', 'Control': 'الضابط', 'Rules': 'القواعد',
  'Response times': 'أزمنة الاستجابة', 'Mean time to acknowledge': 'متوسط زمن الإقرار', 'Mean time to close': 'متوسط زمن الإغلاق',
  'median': 'الوسيط', 'alerts measured': 'تنبيهات مقيسة',
  'Notable incidents': 'الحوادث البارزة', 'Alert': 'التنبيه', 'Status': 'الحالة', 'Summary': 'الملخص', 'Assignee': 'المكلَّف', 'Case': 'القضية', 'Opened': 'تاريخ الفتح', 'Owner': 'المالك',
  'No data in this period.': 'لا توجد بيانات في هذه الفترة.', 'Not available': 'غير متاح',
  'Some panels could not be loaded from the data store; they are marked "Not available".': 'تعذر تحميل بعض الأقسام من مخزن البيانات؛ وهي مُعلَّمة بـ"غير متاح".',
  'Figures are computed from live SIEM data for the period shown. Nothing is estimated.': 'الأرقام محسوبة من بيانات SIEM الفعلية للفترة المعروضة، دون أي تقدير.',
  ['Generated automatically by the ' + ZYB_ORG.short + ' SIEM.']: ('أُنشئ تلقائيًا بواسطة نظام SIEM لدى ' + ZYB_ORG.short_ar + '.'),
  [ZYB_ORG.short]: ZYB_ORG.short_ar, 'unmapped': 'غير مصنف',
  'new': 'جديد', 'acknowledged': 'تم الإقرار', 'in-progress': 'قيد المعالجة', 'closed-true-positive': 'مغلق — إيجابي صحيح', 'closed-false-positive': 'مغلق — إيجابي كاذب', 'closed-benign': 'مغلق — حميد',
  'open': 'مفتوح', 'investigating': 'قيد التحقيق', 'contained': 'تم الاحتواء', 'eradicated': 'تمت الإزالة', 'recovered': 'تم التعافي', 'closed': 'مغلق',
  'daily': 'يومي', 'weekly': 'أسبوعي', 'monthly': 'شهري',
};
const TACTICS = {
  'reconnaissance': ['Reconnaissance', 'الاستطلاع'], 'resource-development': ['Resource Development', 'تطوير الموارد'], 'initial-access': ['Initial Access', 'الوصول الأولي'],
  'execution': ['Execution', 'التنفيذ'], 'persistence': ['Persistence', 'الاستمرارية'], 'privilege-escalation': ['Privilege Escalation', 'تصعيد الصلاحيات'],
  'stealth': ['Stealth', 'التخفي'], 'defense-impairment': ['Defense Impairment', 'إضعاف الدفاعات'], 'defense-evasion': ['Stealth', 'التخفي'], 'credential-access': ['Credential Access', 'الوصول إلى بيانات الاعتماد'], 'discovery': ['Discovery', 'الاستكشاف'],
  'lateral-movement': ['Lateral Movement', 'الحركة الجانبية'], 'collection': ['Collection', 'الجمع'], 'command-and-control': ['Command and Control', 'القيادة والتحكم'],
  'exfiltration': ['Exfiltration', 'تسريب البيانات'], 'impact': ['Impact', 'التأثير'], 'unmapped': ['Unmapped', 'غير مصنف'],
};
const CAT_LABEL = { brute_force: 'Failed logons / brute force', malware: 'Malware / EDR', web: 'Web attacks / WAF', ips: 'Intrusion prevention (IPS)', dlp: 'Data loss prevention (DLP)', policy: 'Policy violations', firewall: 'Firewall blocks', admin_change: 'Admin changes' };
const SEV = ['Info', 'Low', 'Medium', 'High', 'Critical'];
const SEV_COLOR = ['#7a8580', '#3d7ea6', '#c98a00', '#c0562b', '#a12a1d'];
const PERIOD = { '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days', custom: 'Custom period' };

function label(k, lang) { return lang === 'ar' && Object.prototype.hasOwnProperty.call(AR, k) ? AR[k] : k; }
function tacticName(t, lang) { const x = TACTICS[t]; return x ? x[lang === 'ar' ? 1 : 0] : t; }

function localTs(ms, offMin, withTime = true) {
  if (!ms) return '—';
  const s = new Date(Number(ms) + offMin * 60000).toISOString();
  return withTime ? `${s.slice(0, 10)} ${s.slice(11, 16)}` : s.slice(0, 10);
}
function dur(ms) {
  if (ms === null || ms === undefined) return '—';
  const m = Math.round(ms / 60000);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60); if (h < 48) return `${h} h ${m % 60} min`;
  return `${Math.floor(h / 24)} d ${h % 24} h`;
}
const fmtN = (v) => String(Number(v) || 0).replace(/\B(?=(\d{3})+(?!\d))/g, ',');

function renderHtml(rep, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const L = (k) => esc(label(k, lang));
  const off = (rep.period && rep.period.utc_offset_min) || 180;
  const ts = (ms, t) => `<bdi>${esc(localTs(ms, off, t))}</bdi>`;
  const bdi = (s) => `<bdi>${esc(s)}</bdi>`;
  const NA = (panel) => `<p class="na">${L('Not available')}${panel ? '' : ''}</p>`;
  const EMPTY = `<p class="empty">${L('No data in this period.')}</p>`;
  const table = (head, rows) => `<table><thead><tr>${head.map((h) => `<th>${L(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
  const bar = (v, max, color) => {
    const w = max > 0 ? Math.max(v > 0 ? 2 : 0, Math.round((v / max) * 160)) : 0;
    return `<svg class="bar" width="164" height="12" viewBox="0 0 164 12" aria-hidden="true"><rect x="0" y="1" width="${w}" height="10" rx="2" fill="${color}"/></svg>`;
  };
  const sec = (title, body, note) => `<section><h2>${L(title)}</h2>${note ? `<p class="m">${L(note)}</p>` : ''}${body}</section>`;
  const sevName = (s) => L(SEV[Math.max(0, Math.min(4, Number(s) || 0))]);

  const T = rep.totals; const A = rep.alerts; const V = rep.threat_verdicts;
  const kpi = (k, v) => `<div class="kpi"><div class="kv">${v === null || v === undefined ? '—' : esc(fmtN(v))}</div><div class="kl">${L(k)}</div></div>`;
  const threat = rep.categories ? rep.categories.filter((c) => c.id !== 'admin_change' && c.id !== 'brute_force').reduce((s, c) => s + c.events, 0) : null;
  const kpis = `<div class="kpis">${kpi('Security events', T ? T.events : null)}${kpi('Threat events', threat)}${kpi('Alerts', A ? A.total : null)}${kpi('Open alerts', A ? A.open : null)}${kpi('Blocked', V ? V.blocked : null)}${kpi('Allowed', V ? V.allowed : null)}${kpi('Hosts reporting', T ? T.hosts : null)}${kpi('Log sources', T ? T.sources : null)}</div>`;

  let sevSec;
  if (!A) sevSec = NA();
  else if (!A.total) sevSec = EMPTY;
  else {
    const mx = Math.max(...[0, 1, 2, 3, 4].map((s) => A.by_severity[s]));
    sevSec = table(['Severity', 'Total', 'Open', ''], [4, 3, 2, 1, 0].map((s) => `<tr><td>${sevName(s)}</td><td class="n">${fmtN(A.by_severity[s])}</td><td class="n">${fmtN(A.open_by_severity[s])}</td><td>${bar(A.by_severity[s], mx, SEV_COLOR[s])}</td></tr>`));
  }
  let offSec;
  if (!A) offSec = NA();
  else {
    const rows = [['Open', A.open], ['Closed', A.closed], ['Closed as true positive', A.closed_by_reason['true-positive']], ['Closed as false positive', A.closed_by_reason['false-positive']], ['Closed as benign', A.closed_by_reason.benign]];
    if (rep.cases) rows.push(['Cases opened', rep.cases.opened], ['Cases closed', rep.cases.closed], ['Cases open now', rep.cases.open_now]);
    offSec = A.total || (rep.cases && (rep.cases.opened || rep.cases.open_now)) ? `<table class="kvt"><tbody>${rows.map(([k, v]) => `<tr><th>${L(k)}</th><td class="n">${fmtN(v)}</td></tr>`).join('')}</tbody></table>` : EMPTY;
  }
  let catSec;
  if (!rep.categories) catSec = NA();
  else if (!rep.categories.length) catSec = EMPTY;
  else {
    const mx = Math.max(...rep.categories.map((c) => c.events));
    catSec = table(['Category', 'Events', 'Blocked', 'Allowed', 'Unknown outcome', ''], rep.categories.map((c) => `<tr><td>${L(CAT_LABEL[c.id] || c.id)}</td><td class="n">${fmtN(c.events)}</td><td class="n">${c.blocked === null ? '—' : fmtN(c.blocked)}</td><td class="n">${c.allowed === null ? '—' : fmtN(c.allowed)}</td><td class="n">${c.unknown === null ? '—' : fmtN(c.unknown)}</td><td>${bar(c.events, mx, '#1f6e43')}</td></tr>`));
  }
  let verSec;
  if (!V) verSec = NA();
  else if (!(V.blocked + V.allowed + V.unknown)) verSec = EMPTY;
  else {
    const tot = V.blocked + V.allowed + V.unknown;
    const pct = (v) => `${Math.round((v / tot) * 1000) / 10}%`;
    verSec = table(['Category', 'Total', ''], [['Blocked', V.blocked, '#1f6e43'], ['Allowed', V.allowed, '#a12a1d'], ['Unknown outcome', V.unknown, '#7a8580']].map(([k, v, c]) => `<tr><td>${L(k)}</td><td class="n">${fmtN(v)} (${pct(v)})</td><td>${bar(v, tot, c)}</td></tr>`));
  }
  let trendSec;
  if (!rep.trend) trendSec = NA();
  else if (!rep.trend.points.some((p) => p.events || p.alerts)) trendSec = EMPTY;
  else {
    const pts = rep.trend.points; const mx = Math.max(1, ...pts.map((p) => p.events));
    const W = 700; const Hh = 120; const bw = W / pts.length;
    const svg = `<svg class="trend" viewBox="0 0 ${W} ${Hh}" width="100%" height="${Hh}" role="img" aria-label="${L('Trend')}">${pts.map((p, i) => {
      const h = Math.round((p.events / mx) * (Hh - 10)); const th = Math.round((p.threats / mx) * (Hh - 10));
      return `<rect x="${(i * bw + 1).toFixed(1)}" y="${Hh - h}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${h}" fill="#b9d3c3"/><rect x="${(i * bw + 1).toFixed(1)}" y="${Hh - th}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${th}" fill="#c0562b"/>`;
    }).join('')}</svg>`;
    const hourly = rep.trend.bucket === 'hour';
    trendSec = `${svg}<p class="m">■ ${L('Security events')} · <span style="color:#c0562b">■</span> ${L('Threat events')} — ${L(hourly ? 'per hour' : 'per day')}</p>${
      table(['Time', 'Security events', 'Threat events', 'Alerts'], pts.filter((p) => p.events || p.alerts).map((p) => `<tr><td>${ts(p.t, hourly)}</td><td class="n">${fmtN(p.events)}</td><td class="n">${fmtN(p.threats)}</td><td class="n">${p.alerts === null ? '—' : fmtN(p.alerts)}</td></tr>`))}`;
  }
  const listSec = (arr, head, row) => (!arr ? NA() : !arr.length ? EMPTY : table(head, arr.map(row)));
  const hostsSec = listSec(rep.top_targets, ['Host / target', 'Events', 'High severity', 'Sources', 'Category', 'Last seen'],
    (h) => `<tr><td>${bdi(h.target)}</td><td class="n">${fmtN(h.events)}</td><td class="n">${fmtN(h.high)}</td><td class="n">${fmtN(h.sources)}</td><td>${h.classes.map((c) => L(CAT_LABEL[c] || c)).join(', ')}</td><td>${ts(h.last_ms)}</td></tr>`);
  const attSec = listSec(rep.top_attackers, ['Source IP', 'Country', 'Events', 'Targets', 'Category', 'Last seen'],
    (a) => `<tr><td>${bdi(a.ip)}${a.internal ? ` <span class="m">(${L('internal')})</span>` : ''}</td><td>${esc(a.country || '—')}</td><td class="n">${fmtN(a.events)}</td><td class="n">${fmtN(a.targets)}</td><td>${a.classes.map((c) => L(CAT_LABEL[c] || c)).join(', ')}</td><td>${ts(a.last_ms)}</td></tr>`);
  const usrSec = listSec(rep.top_failed_users, ['User', 'Failures', 'Sources', 'Hosts', 'Last seen'],
    (u) => `<tr><td>${bdi(u.user)}</td><td class="n">${fmtN(u.failures)}</td><td class="n">${fmtN(u.sources)}</td><td class="n">${fmtN(u.hosts)}</td><td>${ts(u.last_ms)}</td></tr>`);
  let mitreSec;
  if (!rep.mitre) mitreSec = NA();
  else if (!rep.mitre.tactics.length) mitreSec = EMPTY;
  else {
    const mx = Math.max(...rep.mitre.tactics.map((t) => t.alerts));
    mitreSec = table(['Tactic', 'Alerts', 'Techniques'], rep.mitre.tactics.map((t) => {
      const a = Math.min(1, t.alerts / mx); const bg = `rgba(192,86,43,${(0.12 + a * 0.6).toFixed(2)})`;
      return `<tr><td style="background:${bg}">${esc(tacticName(t.tactic, lang))}</td><td class="n">${fmtN(t.alerts)}</td><td>${t.techniques.map((x) => `${bdi(x.id)} (${fmtN(x.alerts)})`).join(' · ')}</td></tr>`;
    }));
  }
  const rulesSec = listSec(rep.top_rules, ['Rule', 'Alerts', 'Highest severity', 'Tactic'],
    (r) => `<tr><td>${bdi(r.rule_id)}<br><span class="m">${bdi(r.rule_name)}</span></td><td class="n">${fmtN(r.alerts)}</td><td>${sevName(r.max_severity)}</td><td>${esc(r.tactic ? tacticName(r.tactic, lang) : '—')}</td></tr>`);
  const samaSec = listSec(rep.sama, ['Control', 'Alerts', 'Rules'],
    (c) => `<tr><td>${bdi('SAMA CSF ' + c.control)} ${bdi(c.title)}</td><td class="n">${fmtN(c.alerts)}</td><td>${c.rules.map(bdi).join(', ')}</td></tr>`);
  let respSec;
  const R = rep.response;
  if (!R) respSec = NA();
  else if (!R.mtta.n && !R.mttc.n) respSec = EMPTY;
  else respSec = `<table class="kvt"><tbody><tr><th>${L('Mean time to acknowledge')}</th><td>${esc(dur(R.mtta.avg_ms))} (${L('median')} ${esc(dur(R.mtta.median_ms))}; ${fmtN(R.mtta.n)} ${L('alerts measured')})</td></tr><tr><th>${L('Mean time to close')}</th><td>${esc(dur(R.mttc.avg_ms))} (${L('median')} ${esc(dur(R.mttc.median_ms))}; ${fmtN(R.mttc.n)} ${L('alerts measured')})</td></tr></tbody></table>`;
  let notSec = listSec(rep.notable_alerts, ['Alert', 'Severity', 'Status', 'Last seen', 'Summary', 'Assignee'],
    (a) => `<tr><td>${bdi(a.id)}<br><span class="m">${bdi(a.rule_name || a.rule_id)}</span></td><td><span class="sev s${a.severity}">${sevName(a.severity)}</span></td><td>${L(a.status)}</td><td>${ts(a.last_ms)}</td><td>${bdi(a.summary)}</td><td>${bdi(a.assignee || '—')}</td></tr>`);
  if (rep.notable_cases && rep.notable_cases.length) {
    notSec += table(['Case', 'Severity', 'Status', 'Opened', 'Owner'], rep.notable_cases.map((c) => `<tr><td>${bdi(c.id)}<br><span class="m">${bdi(c.title)}</span></td><td><span class="sev s${c.severity}">${sevName(c.severity)}</span></td><td>${L(c.status)}</td><td>${ts(c.created)}</td><td>${bdi(c.owner || '—')}</td></tr>`));
  }

  const p = rep.period || {};
  const org = opts.org || label(ZYB_ORG.short, lang);
  return `<!doctype html><html lang="${lang}" dir="${lang === 'ar' ? 'rtl' : 'ltr'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${L('Attack summary')} — ${esc(org)}</title><style>
body{font:13px/1.45 system-ui,"Segoe UI",Tahoma,Arial,sans-serif;color:#1b1b1b;background:#fff;margin:24px auto;max-width:1000px;padding:0 16px}
h1{font-size:22px;margin:0 0 2px}h2{font-size:16px;border-bottom:2px solid #1f6e43;padding-bottom:3px;margin:26px 0 8px}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #cfd8d2;padding:4px 6px;text-align:start;vertical-align:top}th{background:#eef4f0}
td.n{text-align:end;font-variant-numeric:tabular-nums;white-space:nowrap}.m{color:#5a635e;font-size:12px}.kvt th{width:45%}
.kpis{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}.kpi{border:1px solid #cfd8d2;border-radius:8px;padding:8px 12px;min-width:110px}
.kv{font-size:22px;font-weight:700;color:#1f6e43}.kl{font-size:12px;color:#5a635e}.empty{color:#5a635e;font-style:italic}.na{color:#8a6300;font-weight:600}
.warn{border:2px solid #c98a00;background:#fff7e0;padding:8px 10px;border-radius:6px}.sev{font-weight:700}.s4{color:#a12a1d}.s3{color:#c0562b}.s2{color:#8a6300}
svg.bar{vertical-align:middle}section{page-break-inside:avoid}@media print{body{margin:0}}</style></head><body>
<h1>${L('Attack summary')}</h1><div class="m">${esc(org)} · ${L('Security operations report')}</div>
<table class="kvt"><tbody><tr><th>${L('Period')}</th><td>${L(PERIOD[p.label] || 'Custom period')}: ${ts(p.from)} → ${ts(p.to)}</td></tr>
<tr><th>${L('Time zone')}</th><td>${bdi(`${p.timezone || 'Asia/Riyadh'} (UTC${(p.utc_offset_min || 180) >= 0 ? '+' : '-'}${Math.abs((p.utc_offset_min || 180) / 60)})`)}</td></tr>
<tr><th>${L('Generated')}</th><td>${ts(Date.parse(rep.generated_at))}${opts.generatedBy ? ` ${L('by')} ${bdi(opts.generatedBy)}` : ''}</td></tr></tbody></table>
${rep.clickhouse && !rep.clickhouse.ok ? `<p class="warn">${L('Some panels could not be loaded from the data store; they are marked "Not available".')}</p>` : ''}
${sec('Key figures', kpis)}
${sec('Alerts by severity', sevSec)}${sec('Open vs closed offenses', offSec)}
${sec('Attack categories', catSec)}${sec('Blocked vs allowed threat events', verSec, 'Firewall, IPS, EDR/antivirus, WAF, DLP and policy events by prevention outcome.')}
${sec('Trend', trendSec)}${sec('Top attacked hosts', hostsSec)}${sec('Top attacker source IPs', attSec)}${sec('Top targeted usernames (failed logons)', usrSec)}
${sec('MITRE ATT&CK tactics and techniques', mitreSec)}${sec('Top triggered rules', rulesSec)}${sec('SAMA controls touched', samaSec)}
${sec('Response times', respSec)}${sec('Notable incidents', notSec)}
<p class="m">${L('Figures are computed from live SIEM data for the period shown. Nothing is estimated.')} ${L(('Generated automatically by the ' + ZYB_ORG.short + ' SIEM.'))}</p>
</body></html>`;
}

function renderText(rep, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const L = (k) => label(k, lang);
  const off = (rep.period && rep.period.utc_offset_min) || 180;
  const v = (x) => (x === null || x === undefined ? L('Not available') : fmtN(x));
  const T = rep.totals; const A = rep.alerts; const V = rep.threat_verdicts;
  const lines = [
    `${L('Attack summary')} — ${opts.org || L(ZYB_ORG.short)}`,
    `${L('Period')}: ${localTs(rep.period.from, off)} → ${localTs(rep.period.to, off)} (${rep.period.timezone || 'Asia/Riyadh'})`,
    '',
    `${L('Security events')}: ${v(T && T.events)}`,
    `${L('Alerts')}: ${v(A && A.total)} (${L('Open')}: ${v(A && A.open)}, ${L('Closed')}: ${v(A && A.closed)})`,
    `${L('Blocked')}: ${v(V && V.blocked)} · ${L('Allowed')}: ${v(V && V.allowed)}`,
  ];
  if (A) lines.push(`${L('Critical')}: ${fmtN(A.by_severity[4])} · ${L('High')}: ${fmtN(A.by_severity[3])}`);
  if (rep.notable_alerts && rep.notable_alerts.length) {
    lines.push('', `${L('Notable incidents')}:`);
    for (const a of rep.notable_alerts.slice(0, 5)) lines.push(`- ${a.id} ${a.rule_name || a.rule_id} (${L(SEV[a.severity] || '')}, ${L(a.status)})`);
  }
  lines.push('', L('Figures are computed from live SIEM data for the period shown. Nothing is estimated.'));
  return lines.join('\n');
}

function subjectOf(rep, opts = {}) {
  const lang = opts.lang === 'ar' ? 'ar' : 'en';
  const off = (rep.period && rep.period.utc_offset_min) || 180;
  const per = opts.period ? ` (${label(opts.period, lang)})` : '';
  return `${opts.org || label(ZYB_ORG.short, lang)} — ${label('Attack summary', lang)}${per} ${localTs(rep.period.to - 1, off, false)}`;
}

module.exports = { renderHtml, renderText, subjectOf, label, AR, CAT_LABEL, TACTICS };
