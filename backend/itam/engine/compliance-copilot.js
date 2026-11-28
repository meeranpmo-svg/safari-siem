// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Compliance AI Assistant - the compliance consultant for a group of companies: NCA ECC, ISO 27001, PDPL, NDMO and Aramco CCC,
 * read from the platform's own registers, weighed by what each company actually does, and kept current with strong workflows.
 *   companies    the group's companies (an administrator creates and renames them; names in English and Arabic), which
 *                frameworks apply to each and what each does (operations & maintenance, project sites, manpower, Aramco
 *                contracts, ...). The audit and compliance reports use this register (app.addons.companies).
 *   gaps         a REALISTIC position per company and framework: "as recorded" (met / partial over what was assessed) next to
 *                "realistic" (not measured and not assessed count as not met); the priorities ranked by state x severity x
 *                relevance to the company's business, each with why it matters for that company, the effort, the policy that
 *                covers it, and a 90-day plan. Indicators from the registers, not an audit opinion.
 *   actions      gap → remediation action (owner, due) → evidence submitted → verified by a DIFFERENT person (an administrator)
 *                → closed, or returned with the reason; overdue said. Every step audited.
 *   duties       the recurring control activities that keep compliance true (access reviews incl. the ERP, restore tests, DR
 *                drill, vulnerability scans, firewall rule review, awareness, ROPA review, policy review, management review ...):
 *                due → done with an evidence reference (where the evidence is kept - never the file, PDPL) → verified by
 *                another person → the next due date. An administrator adjusts frequency and owner.
 *   policies     bilingual (English / Arabic) policy drafts from policy-templates.js filled with the company's values, sent to
 *                GRC drafts, where a person other than the author approves them (four-eyes) - nothing is published from here.
 *   ask          questions in English or Arabic. With the AI engine allowed: Claude through ai-guard (budget before / record
 *                after, redactSecrets, untrusted() tool output, UNTRUSTED_RULE) with READ-ONLY tools filtered by the asker's
 *                role and re-checked per call; it can change nothing. Otherwise a local answer from the same data.
 *   GET  /org/companies                 viewer     PUT  /org/companies/:id           admin
 *   GET  /copilot/overview?company=     viewer     (gaps, priorities, plan, duties due, actions, policy drafts)
 *   POST /copilot/actions               operator   POST /copilot/actions/:id/submit   operator   POST /copilot/actions/:id/verify admin
 *   POST /copilot/duties/:id/done       operator   POST /copilot/duties/:id/verify    admin      PUT  /copilot/duties/:id         admin
 *   GET  /copilot/policies              viewer     POST /copilot/policies/preview     operator   POST /copilot/policies/draft     operator
 *   POST /copilot/ask                   viewer
 */
const fs = require('fs'), path = require('path');
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const G = require('./ai-guard');
const PT = require('./policy-templates');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const DAY = 86400000, MODEL = 'claude-opus-5-5';
const ID = /^[a-z][a-z0-9_-]{1,39}$/;
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const FW = { nca: 'NCA ECC', iso27001: 'ISO 27001', pdpl: 'PDPL', ndmo: 'NDMO', aramco: 'Aramco CCC' };
const FW_AR = { nca: 'الضوابط الأساسية للأمن السيبراني', iso27001: 'آيزو 27001', pdpl: 'نظام حماية البيانات الشخصية', ndmo: 'معايير مكتب إدارة البيانات الوطنية', aramco: 'شهادة أرامكو للأمن السيبراني' };
const LINES = { om: 'Operations & maintenance services', projects: 'Project sites / field workforce', manpower: 'Manpower supply (workforce personal data)', aramco: 'Saudi Aramco contracts',
  government: 'Government clients', ot: 'Work on client industrial / operational systems', cloud: 'Cloud services (Microsoft 365, Azure)', erp: 'ERP (finance, HR, payroll)', fleet: 'Fleet & transport', facility: 'Facility management' };
// state of a register row, whatever the register calls it (the same mapping as the Compliance Assistant's rules)
const STATE = { verified: 'met', compliant: 'met', auto_pass: 'met', met: 'met', confirmed: 'met', implemented: 'met', partial: 'partial', partially: 'partial',
  gap: 'gap', non_compliant: 'gap', auto_fail: 'gap', not: 'gap', 'not-implemented': 'gap', not_implemented: 'gap',
  not_measured: 'unknown', no_evidence: 'unknown', not_assessed: 'unknown', 'not-assessed': 'unknown', pending: 'unknown', not_applicable: 'na', 'not-applicable': 'na' };
// what a requirement is about, from its own words - so the company's business can weigh it
const TOPICS = [
  ['governance', /strategy|committee|roles and responsibilit|top management|leadership/i, 'S'],
  ['third_party', /third[- ]part|supplier|vendor|contractor|outsourc|cloud (service|provider)|processor/i, 'L'], ['incident', /incident|breach|threat/i, 'M'],
  ['iam', /access|identit|authenticat|password|privileg|account|user/i, 'M'], ['network', /network|firewall|segment|remote|vpn|wireless/i, 'M'],
  ['privacy', /personal data|privacy|consent|data subject|ropa|processing activ|pdpl|dpia|impact assess/i, 'M'], ['classification', /classif|label|handling/i, 'S'],
  ['backup', /backup|recover|continuity|disaster|resilien/i, 'M'], ['vuln', /vulnerab|patch|penetration|hardening|configuration/i, 'M'], ['logging', /\blogs?\b|logging|monitor|security event|siem|audit trail|clock sync/i, 'M'],
  ['physical', /physical|site|premises|facilit|equipment/i, 'S'], ['ot', /industrial|ics|ot\b|operational technology|scada/i, 'L'], ['endpoint', /mobile|endpoint|device|malware|email/i, 'S'],
  ['hr', /awareness|training|human resource|employ|screening/i, 'S'], ['governance', /policy|policies|strategy|role|responsib|governance|management review|committee/i, 'S'],
  ['risk', /risk/i, 'M'], ['crypto', /crypt|key management|certificate/i, 'S'], ['data_mgmt', /data quality|metadata|catalog|master data|reference data|data architecture|open data|freedom of information|business intelligence|data sharing|data value|document and content|data operations/i, 'M'],
  ['appsec', /application|software|develop|web/i, 'M'],
];
const RELEVANCE = { aramco: { third_party: 0.8, incident: 0.4, iam: 0.4, network: 0.3, logging: 0.3 }, projects: { physical: 0.6, network: 0.4, endpoint: 0.5, backup: 0.2 },
  manpower: { privacy: 0.8, hr: 0.3, classification: 0.2 }, ot: { ot: 1.2, network: 0.3 }, cloud: { third_party: 0.3, iam: 0.3, crypto: 0.2 }, erp: { iam: 0.4, logging: 0.3, backup: 0.3 },
  government: { classification: 0.5, data_mgmt: 0.4, incident: 0.3 }, om: { backup: 0.2, vuln: 0.2 }, fleet: { endpoint: 0.2, privacy: 0.2 }, facility: { physical: 0.3 } };
const WHY = { third_party: 'its own clients (Aramco and others) assess it as a third party, and its subcontractors reach client sites', privacy: 'it holds identity, iqama, payroll and medical data of a large workforce',
  physical: 'equipment and people are spread over project sites outside head office', network: 'branches and project sites connect back to head office', ot: 'staff work on client operational / industrial systems',
  iam: 'many joiners, movers and leavers across sites, and ERP roles that need segregation of duties', incident: 'a client contract can be suspended after an unreported incident', endpoint: 'shared and field devices leave the office',
  logging: 'auditors and clients ask for proof of who did what', backup: 'operations stop if the ERP or file shares are lost', classification: 'client documents carry the client\'s classification',
  data_mgmt: 'government data rules apply to data shared with government clients', hr: 'a large site workforce needs awareness in their own language', governance: 'every other control rests on approved policies and roles',
  risk: 'treatment decisions must be recorded for each contract and site', vuln: 'unpatched systems are the most common way in', crypto: 'data leaves the company to clients and sites', appsec: 'web applications face the internet' };
const WHY_AR = { third_party: 'عملاؤها (أرامكو وغيرها) يقيّمونها كطرف خارجي، ومقاولوها يصلون إلى مواقع العملاء', privacy: 'تحتفظ ببيانات الهوية والإقامة والرواتب والبيانات الطبية لعدد كبير من العاملين',
  physical: 'معداتها وموظفوها موزعون على مواقع مشاريع خارج المقر الرئيسي', network: 'الفروع ومواقع المشاريع تتصل بالمقر الرئيسي', ot: 'موظفوها يعملون على الأنظمة التشغيلية والصناعية للعملاء',
  iam: 'كثرة الالتحاق والانتقال وإنهاء الخدمة في المواقع، وأدوار نظام ERP تحتاج إلى فصل المهام', incident: 'قد يُعلَّق عقد العميل بعد حادث لم يُبلَّغ عنه', endpoint: 'الأجهزة المشتركة والميدانية تعمل خارج المكتب',
  logging: 'المدققون والعملاء يطلبون إثبات من فعل ماذا', backup: 'تتوقف العمليات إذا فُقد نظام ERP أو الملفات المشتركة', classification: 'مستندات العملاء تحمل تصنيف العميل',
  data_mgmt: 'قواعد البيانات الحكومية تنطبق على البيانات المتبادلة مع العملاء الحكوميين', hr: 'العاملون في المواقع بحاجة إلى توعية بلغتهم', governance: 'جميع الضوابط الأخرى تقوم على سياسات وأدوار معتمدة',
  risk: 'يجب توثيق قرارات معالجة المخاطر لكل عقد وموقع', vuln: 'الأنظمة غير المحدّثة هي أكثر طرق الاختراق شيوعاً', crypto: 'البيانات تخرج من الشركة إلى العملاء والمواقع', appsec: 'تطبيقات الويب مكشوفة على الإنترنت' };
const TOPIC_POLICY = { third_party: 'thirdparty', privacy: 'pdpl', physical: 'sites', network: 'network', ot: 'sites', iam: 'access', incident: 'incident', endpoint: 'remote', logging: 'logging', backup: 'backup',
  classification: 'classification', data_mgmt: 'classification', hr: 'aup', governance: 'infosec', risk: 'infosec', vuln: 'change_patch', crypto: 'access', appsec: 'change_patch' };
// the recurring control activities (days between), the frameworks they keep true, the department that owns them
const DUTIES = [
  ['access_review', 'User access review (incl. ERP roles and segregation of duties)', 'مراجعة صلاحيات المستخدمين (بما فيها أدوار ERP وفصل المهام)', 90, 'it', ['nca:2-2', 'iso27001:5.18', 'aramco:IAM']],
  ['priv_review', 'Privileged account review', 'مراجعة الحسابات ذات الصلاحيات المميزة', 90, 'it', ['nca:2-2', 'iso27001:8.2']],
  ['restore_test', 'Backup restore test', 'اختبار استعادة النسخ الاحتياطية', 90, 'it', ['nca:2-9', 'iso27001:8.13']],
  ['dr_drill', 'Disaster recovery exercise', 'تمرين التعافي من الكوارث', 365, 'it', ['nca:3-1', 'iso27001:5.30']],
  ['vuln_scan', 'Vulnerability scan and remediation review', 'فحص الثغرات ومراجعة معالجتها', 30, 'it', ['nca:2-10', 'iso27001:8.8']],
  ['pentest', 'Penetration test of internet-facing systems', 'اختبار اختراق للأنظمة المتصلة بالإنترنت', 365, 'it', ['nca:2-11', 'iso27001:8.8']],
  ['fw_review', 'Firewall rule review (Firewall & Device Audit)', 'مراجعة قواعد جدران الحماية (تدقيق الأجهزة)', 180, 'it', ['nca:2-5', 'iso27001:8.20', 'aramco:Network']],
  ['log_review', 'Security log and SIEM coverage review', 'مراجعة سجلات الأمن وتغطية SIEM', 30, 'it', ['nca:2-12', 'iso27001:8.15']],
  ['awareness', 'Security awareness training (all staff and site workforce)', 'التدريب على التوعية الأمنية (جميع الموظفين والعاملين في المواقع)', 365, 'hr', ['nca:1-10', 'iso27001:6.3']],
  ['phishing', 'Phishing exercise', 'تمرين التصيد الاحتيالي', 90, 'it', ['nca:1-10', 'iso27001:6.3']],
  ['risk_assess', 'Information security risk assessment', 'تقييم مخاطر أمن المعلومات', 365, 'it', ['nca:1-5', 'iso27001:6.1']],
  ['policy_review', 'Policy review and re-approval', 'مراجعة السياسات وإعادة اعتمادها', 365, 'legal', ['nca:1-3', 'iso27001:5.1']],
  ['ropa_review', 'Record of processing activities review', 'مراجعة سجل أنشطة المعالجة', 365, 'legal', ['pdpl:ROPA']],
  ['dsr_review', 'Data subject requests and breach log review', 'مراجعة طلبات أصحاب البيانات وسجل التسربات', 90, 'legal', ['pdpl:4', 'pdpl:20']],
  ['classification_review', 'Data classification review', 'مراجعة تصنيف البيانات', 365, 'it', ['ndmo:Data Classification', 'nca:2-7']],
  ['third_party_review', 'Third-party / contractor security review', 'مراجعة أمن الأطراف الخارجية والمقاولين', 365, 'procurement', ['nca:4-1', 'iso27001:5.22', 'aramco:Third party']],
  ['internal_audit', 'Internal cybersecurity audit', 'التدقيق الداخلي للأمن السيبراني', 365, 'legal', ['nca:1-8', 'iso27001:9.2']],
  ['mgmt_review', 'Management review of the ISMS', 'مراجعة الإدارة لنظام إدارة أمن المعلومات', 365, 'management', ['iso27001:9.3']],
  ['site_check', 'Project site IT security check', 'فحص أمن تقنية المعلومات في مواقع المشاريع', 90, 'operations', ['nca:2-14', 'iso27001:7.9']],
];

function createCopilot(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10);
  const C = (n) => app.store.collection(n);
  const companies = () => C('org_companies'), actions = () => C('copilot_actions'), duties = () => C('copilot_duties'), pol = () => C('copilot_policies');
  const L = app.log || { every() {} };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'copilot.' + action, target, detail }); };
  const addon = (k) => app.addons && app.addons[k];
  const person = (who, what) => { if (!isHuman(who.user)) throw bad('a person ' + what + '; an AI or service identity never does', 403); };
  const same = (a, b) => low(a) === low(b);

  // ---------- companies ----------
  function seedCompanies() {
    const fws = (ZYB_ORG.frameworks || []).filter((f) => FW[f]);
    const list = Array.isArray(ZYB_ORG.companies) && ZYB_ORG.companies.length ? ZYB_ORG.companies : [{ id: 'main', name: ZYB_ORG.name || 'The company', name_ar: ZYB_ORG.name_ar || '' }];
    return list.map((c, i) => ({ id: String(c.id || (i ? 'company' + i : 'main')).toLowerCase().replace(/[^a-z0-9_-]/g, '_'), name: String(c.name || ''), name_ar: String(c.name_ar || ''), short: String(c.short || ZYB_ORG.short || ''),
      frameworks: Array.isArray(c.frameworks) ? c.frameworks.filter((f) => FW[f]) : fws, lines: Array.isArray(c.lines) ? c.lines.filter((x) => LINES[x]) : ['om', 'projects', 'manpower', 'cloud', 'erp'], parent: '', active: true, from: 'company setting' }));
  }
  function companyList(all) { const S = companies().all(), L0 = S.length ? S : seedCompanies(); return L0.filter((c) => all || c.active !== false).sort((a, b) => (a.parent ? 1 : 0) - (b.parent ? 1 : 0) || a.name.localeCompare(b.name)); }
  function company(id) { const L0 = companyList(true); const c = id ? L0.find((x) => x.id === id) : L0.find((x) => !x.parent) || L0[0]; if (!c) throw bad('company not found: ' + String(id).slice(0, 40), 404); return c; }
  function putCompany(id0, b0, who) {
    person(who, 'changes the company register');
    const id = param(id0, 'id'); if (!ID.test(id)) throw bad('id: 2-40 lower-case letters, digits, _ or - starting with a letter');
    const b = body(b0 || {}).str('name', { required: true, min: 2, max: 160 }).str('name_ar', { max: 160 }).str('short', { max: 40 }).str('cr_number', { max: 20, re: /^[0-9]*$/, msg: 'cr_number: digits only' })
      .list('frameworks', { max: 5, item: Object.keys(FW), unique: true, def: [] }).list('lines', { max: 10, item: Object.keys(LINES), unique: true, def: [] }).str('parent', { max: 40 }).bool('active', { def: true }).done();
    if (b.parent && (b.parent === id || !companyList(true).some((c) => c.id === b.parent))) throw bad('parent: another company in the register');
    if (!companies().all().length) for (const c of seedCompanies()) companies().put(Object.assign({}, c, { created_by: who.user, created_at: iso() }));
    const clash = companyList(true).find((c) => c.id !== id && low(c.name) === low(b.name)); if (clash) throw bad('name: "' + b.name + '" is already company ' + clash.id, 409);
    const prev = companies().get(id), rec = Object.assign({}, prev || {}, b, { id, updated_by: who.user, updated_at: iso() }, prev ? {} : { created_by: who.user, created_at: iso() });
    companies().put(rec);
    audit(who, prev ? 'company.update' : 'company.create', id, { name: b.name, renamed_from: prev && prev.name !== b.name ? prev.name : undefined, frameworks: b.frameworks, lines: b.lines, active: b.active });
    return { companies: companyList(true), saved: id };
  }

  // ---------- registers ----------
  const SYS = { user: 'system:copilot', role: 'viewer' };
  const READ = {
    nca: async () => (await addon('ncaEcc').view(SYS)).controls,
    iso27001: async () => { const v = await addon('iso27001').view(SYS); return [].concat(v.clauses || [], v.annex || []); },
    ndmo: async () => (await addon('ndmo').view(SYS)).controls,
    pdpl: async () => (await addon('pdpl').view(false)).requirements,
    aramco: async () => (await addon('aramcoCcc').view(SYS)).controls,
  };
  const ADDON = { nca: 'ncaEcc', iso27001: 'iso27001', ndmo: 'ndmo', pdpl: 'pdpl', aramco: 'aramcoCcc' };
  async function readRegisters() {
    if (opts.registers) return opts.registers();
    const out = {};
    for (const f of Object.keys(FW)) {
      if (!addon(ADDON[f])) { out[f] = { installed: false, rows: [] }; continue; }
      try { out[f] = { installed: true, rows: ((await READ[f]()) || []).slice(0, 2000) }; }
      catch (e) { out[f] = { installed: true, error: 'not read', rows: [] }; if (L.every) L.every('copilot.read.' + f, 3600000, 'warn', 'Compliance AI Assistant: the ' + f + ' register was not read', { err: String(e.message || e).slice(0, 200) }); }
    }
    return out;
  }
  const rowState = (r) => STATE[low(r.result || r.status || r.state || '').replace(/\s+/g, '_')] || STATE[low(r.result || r.status || '')] || 'unknown';
  const rowText = (r) => [r.title, r.subdomain_name, r.domain_name, r.group_name, r.area, r.domain, r.requirement].filter(Boolean).join(' ');
  const topicOf = (r) => { const t = rowText(r); const m = TOPICS.find(([, re]) => re.test(t)); return m ? m[0] : 'other'; };
  const effortOf = (tp) => (TOPICS.find((x) => x[0] === tp) || [0, 0, 'S'])[2];
  const sevW = (r) => { const s = low(r.severity || r.level || r.priority || ''); return /crit/.test(s) ? 1.6 : /high/.test(s) ? 1.3 : /low/.test(s) ? 0.8 : 1; };
  const relevance = (c, tp) => (tp === 'other' ? 0.8 : 1) + (c.lines || []).reduce((s, l) => s + ((RELEVANCE[l] || {})[tp] || 0), 0);

  async function gaps(c) {
    const R = await readRegisters(), frameworks = [], pri = [];
    for (const f of c.frameworks || []) {
      const reg = R[f] || { installed: false, rows: [] };
      const rows = reg.rows.map((r) => ({ r, s: rowState(r) })).filter((x) => x.s !== 'na');
      const n = (s) => rows.filter((x) => x.s === s).length, met = n('met'), part = n('partial'), gap = n('gap'), unk = n('unknown'), assessed = met + part + gap;
      frameworks.push({ id: f, name: FW[f], name_ar: FW_AR[f], installed: reg.installed, error: reg.error || null, applicable: rows.length, met, partial: part, gap, unknown: unk,
        recorded: assessed ? Math.round(100 * (met + part / 2) / assessed) : null, realistic: rows.length ? Math.round(100 * (met + part / 2) / rows.length) : null,
        note: !reg.installed ? 'not installed' : !rows.length ? (f === 'aramco' ? 'no control list imported - import your copy of SACS-002 on the Aramco CCC page' : 'register empty') : unk ? unk + ' requirement(s) not measured or not assessed count as not met in the realistic score' : '' });
      for (const x of rows.filter((y) => y.s !== 'met')) {
        const tp = topicOf(x.r), w = { gap: 3, unknown: 2, partial: 1.5 }[x.s] * sevW(x.r) * relevance(c, tp);
        pri.push({ fw: f, fw_name: FW[f], id: String(x.r.id || ''), title: String(x.r.title || x.r.requirement || '').slice(0, 220), state: x.s, topic: tp, effort: effortOf(tp), score: Math.round(w * 10) / 10,
          why: 'Matters for ' + (c.short || c.name) + ' because ' + (WHY[tp] || 'it is a requirement of ' + FW[f]) + '.', why_ar: 'أهميته لـ ' + (c.name_ar || c.name) + ': ' + (WHY_AR[tp] || 'من متطلبات ' + FW_AR[f]) + '.', policy: TOPIC_POLICY[tp] || null, hint: String(x.r.recommend || x.r.evidence_hint || x.r.why || '').slice(0, 300) });
      }
    }
    pri.sort((a, b) => b.score - a.score || a.fw.localeCompare(b.fw));
    // the same topic across frameworks is one piece of work: grouped, so one action closes several requirements
    const byTopic = {}; for (const p of pri) { const t = byTopic[p.topic] = byTopic[p.topic] || { topic: p.topic, effort: p.effort, score: 0, items: 0, frameworks: new Set(), policy: p.policy, why: WHY[p.topic] || '' }; t.score += p.score; t.items++; t.frameworks.add(p.fw_name); }
    const themes = Object.values(byTopic).filter((t) => t.topic !== 'other').map((t) => Object.assign(t, { score: Math.round(t.score), frameworks: [...t.frameworks] })).sort((a, b) => b.score - a.score);
    // 90 days: quick wins and the heaviest themes first, about the capacity of a small team (S=1, M=2, L=3 units, 4 units a month)
    const cap = { S: 1, M: 2, L: 3 }, plan = [[], [], []]; let m = 0, used = 0;
    for (const t of themes.slice(0, 12)) { if (used + cap[t.effort] > 4 && m < 2) { m++; used = 0; } plan[m].push({ topic: t.topic, effort: t.effort, items: t.items, frameworks: t.frameworks, policy: t.policy }); used += cap[t.effort]; }
    const by_fw = {}; for (const f of c.frameworks || []) by_fw[f] = pri.filter((p) => p.fw === f).slice(0, 10);
    return { frameworks, priorities: pri.slice(0, 40), by_fw, themes, plan: plan.map((p, i) => ({ month: i + 1, work: p })), total_open: pri.length };
  }

  // ---------- duties ----------
  function dutyRows(c) {
    const S = new Map(duties().all().filter((d) => d.company === c.id).map((d) => [d.key, d])), t = now();
    return DUTIES.filter(([, , , , , refs]) => refs.some((r) => (c.frameworks || []).includes(r.split(':')[0]))).map(([key, en, ar, every, dept, refs]) => {
      const s = S.get(key) || {}, freq = s.every_days || every, last = s.last_verified || null, due = s.next_due || (last ? new Date(Date.parse(last) + freq * DAY).toISOString().slice(0, 10) : today());
      const days = Math.floor((Date.parse(due) - t) / DAY);
      return { id: c.id + '__' + key, key, company: c.id, title: en, title_ar: ar, every_days: freq, owner_dept: s.owner_dept || dept, refs, active: s.active !== false, last_done: s.last_done || null, last_verified: last, next_due: due, days,
        pending: s.pending || null, status: s.pending ? 'awaiting verification' : !last && !s.next_due ? 'never done' : days < 0 ? 'overdue' : days <= 14 ? 'due soon' : 'on track', history: (s.history || []).slice(-6) };
    }).filter((d) => d.active);
  }
  function dutyGet(id0) { const id = param(id0, 'id'), m = id.match(/^([a-z][a-z0-9_-]{1,39})__([a-z_]+)$/); if (!m) throw bad('id: a control activity id'); const c = company(m[1]); const d = DUTIES.find((x) => x[0] === m[2]); if (!d) throw bad('control activity not found', 404); return { c, key: m[2], id }; }
  const dutyRec = (c, key) => duties().get(c.id + '__' + key) || { id: c.id + '__' + key, company: c.id, key, history: [] };
  function dutyDone(id0, b0, who) {
    person(who, 'records a control activity'); const { c, key, id } = dutyGet(id0);
    const b = body(b0 || {}).str('evidence_ref', { required: true, min: 4, max: 300 }).str('note', { max: 600 }).date('done_on', { notFuture: true, now: now() }).done();
    const r = dutyRec(c, key); if (r.pending) throw bad('this activity is already waiting for verification', 409);
    r.pending = { by: who.user, at: iso(), done_on: b.done_on || today(), evidence_ref: b.evidence_ref, note: b.note || '' }; r.last_done = r.pending.done_on;
    r.history = (r.history || []).concat([{ at: iso(), by: who.user, what: 'done', evidence_ref: b.evidence_ref }]).slice(-30); duties().put(r);
    audit(who, 'duty.done', id, { evidence_ref: b.evidence_ref, done_on: r.pending.done_on }); return dutyRows(c).find((d) => d.id === id);
  }
  function dutyVerify(id0, b0, who) {
    person(who, 'verifies a control activity'); const { c, key, id } = dutyGet(id0);
    const b = body(b0 || {}).oneOf('decision', ['accept', 'return'], { required: true }).str('note', { max: 600 }).done();
    const r = dutyRec(c, key); if (!r.pending) throw bad('nothing is waiting for verification', 409);
    if (same(r.pending.by, who.user)) throw bad('four-eyes: ' + who.user + ' recorded this activity - another person verifies it', 403);
    if (b.decision === 'return' && !b.note) throw bad('note: say what is missing when returning');
    const every = r.every_days || DUTIES.find((x) => x[0] === key)[3];
    if (b.decision === 'accept') { r.last_verified = r.pending.done_on; r.next_due = new Date(Date.parse(r.pending.done_on) + every * DAY).toISOString().slice(0, 10); r.evidence_ref = r.pending.evidence_ref; }
    r.history = (r.history || []).concat([{ at: iso(), by: who.user, what: b.decision === 'accept' ? 'verified' : 'returned', note: b.note || '' }]).slice(-30); r.pending = null; duties().put(r);
    audit(who, 'duty.' + (b.decision === 'accept' ? 'verify' : 'return'), id, { note: b.note || null, next_due: r.next_due || null }); return dutyRows(c).find((d) => d.id === id);
  }
  function dutyPut(id0, b0, who) {
    person(who, 'changes a control activity'); const { c, key, id } = dutyGet(id0);
    const b = body(b0 || {}).int('every_days', { min: 7, max: 730 }).str('owner_dept', { max: 40, re: /^[a-z0-9_-]*$/, msg: 'owner_dept: a department id' }).bool('active', {}).done();
    const r = dutyRec(c, key); Object.assign(r, b); duties().put(r); audit(who, 'duty.update', id, b); return dutyRows(c).find((d) => d.id === id) || { id, active: false };
  }

  // ---------- remediation actions ----------
  const actionView = (a) => Object.assign({}, a, { overdue: a.state !== 'closed' && a.due && a.due < today() });
  function actionCreate(b0, who) {
    person(who, 'raises a remediation action');
    const b = body(b0 || {}).str('company', { required: true, max: 40 }).oneOf('fw', Object.keys(FW), { required: true }).str('req_id', { max: 60 }).str('title', { required: true, min: 5, max: 300 })
      .str('owner', { required: true, max: 64, re: /^[A-Za-z0-9._@-]+$/, msg: 'owner: a platform user name' }).date('due', { required: true }).oneOf('topic', TOPICS.map((t) => t[0]), {}).str('note', { max: 600 }).done();
    const c = company(b.company); if (!(c.frameworks || []).includes(b.fw)) throw bad('fw: ' + FW[b.fw] + ' does not apply to ' + c.name);
    if (b.due < today()) throw bad('due: today or later');
    if (b.req_id && actions().all().some((a) => a.company === c.id && a.fw === b.fw && a.req_id === b.req_id && a.state !== 'closed')) throw bad('an open action already covers ' + b.req_id, 409);
    const rec = Object.assign({ id: 'ca_' + now().toString(36) + Math.random().toString(36).slice(2, 6), state: 'open', raised_by: who.user, at: iso(), history: [{ at: iso(), by: who.user, what: 'raised' }] }, b, { company: c.id });
    actions().put(rec); audit(who, 'action.raise', rec.id, { company: c.id, fw: b.fw, req_id: b.req_id || null, owner: b.owner, due: b.due }); return actionView(rec);
  }
  function actionSubmit(id0, b0, who) {
    person(who, 'submits evidence'); const a = actions().get(param(id0, 'id')); if (!a) throw bad('action not found', 404);
    if (!['open', 'returned'].includes(a.state)) throw bad('action is ' + a.state, 409);
    if (!(same(a.owner, who.user) || same(a.raised_by, who.user) || who.role === 'admin')) throw bad('the action owner (' + a.owner + ') submits it', 403);
    const b = body(b0 || {}).str('evidence_ref', { required: true, min: 4, max: 300 }).str('note', { max: 600 }).done();
    actions().patch(a.id, (o) => Object.assign(o, { state: 'submitted', evidence_ref: b.evidence_ref, submitted_by: who.user, submitted_at: iso(), history: o.history.concat([{ at: iso(), by: who.user, what: 'submitted', evidence_ref: b.evidence_ref, note: b.note || '' }]) }));
    audit(who, 'action.submit', a.id, { evidence_ref: b.evidence_ref }); return actionView(actions().get(a.id));
  }
  function actionVerify(id0, b0, who) {
    person(who, 'verifies a remediation'); const a = actions().get(param(id0, 'id')); if (!a) throw bad('action not found', 404);
    if (a.state !== 'submitted') throw bad('action is ' + a.state + ' - evidence must be submitted first', 409);
    if (same(a.submitted_by, who.user) || same(a.owner, who.user)) throw bad('four-eyes: the owner or the person who submitted does not verify', 403);
    const b = body(b0 || {}).oneOf('decision', ['accept', 'return'], { required: true }).str('note', { max: 600 }).done();
    if (b.decision === 'return' && !b.note) throw bad('note: say what is missing when returning');
    actions().patch(a.id, (o) => Object.assign(o, { state: b.decision === 'accept' ? 'closed' : 'returned', verified_by: b.decision === 'accept' ? who.user : null, closed_at: b.decision === 'accept' ? iso() : null, history: o.history.concat([{ at: iso(), by: who.user, what: b.decision === 'accept' ? 'verified and closed' : 'returned', note: b.note || '' }]) }));
    audit(who, 'action.' + (b.decision === 'accept' ? 'close' : 'return'), a.id, { note: b.note || null }); return actionView(actions().get(a.id));
  }

  // ---------- policies ----------
  const grc = () => opts.grc || (app.addons && app.addons.grc) || require('./grc').createGrc(app);
  function policyOptions(b0) {
    const o = (b0 && b0.options) || {}; if (typeof o !== 'object' || Array.isArray(o)) throw bad('options must be an object');
    return body(o).int('review_months', { min: 6, max: 36 }).int('pw_min', { min: 8, max: 64 }).int('lockout', { min: 3, max: 10 }).int('access_review_months', { min: 1, max: 12 }).int('retention_years', { min: 1, max: 30 })
      .int('backup_days', { min: 7, max: 3650 }).int('rto_hours', { min: 1, max: 720 }).int('log_days', { min: 90, max: 3650 }).int('patch_critical_days', { min: 1, max: 60 }).int('breach_hours', { min: 1, max: 168 })
      .oneOf('owner_role', Object.keys(PT.ROLES), {}).done();
  }
  function policyPreview(b0) {
    const b = body(b0 || {}).oneOf('template', PT.TEMPLATES.map((t) => t.id), { required: true }).str('company', { max: 40 }).done(), c = company(b.company), o = policyOptions(b0);
    return PT.render(b.template, Object.assign({ company: c.name, company_ar: c.name_ar || c.name }, o));
  }
  function policyDraft(b0, who) {
    person(who, 'drafts a policy');
    const d = policyPreview(b0), c = company((b0 || {}).company);
    const dr = grc().draftPut({ title: d.title.en + ' - ' + c.name, owner: d.owner.en, domain: 'Policy', frameworks: [d.refs.nca.length ? 'NCA ECC ' + d.refs.nca.join(', ') : '', d.refs.iso.length ? 'ISO 27001 ' + d.refs.iso.join(', ') : '', d.refs.pdpl.length ? 'PDPL Art. ' + d.refs.pdpl.join(', ') : '', d.refs.ndmo.length ? 'NDMO ' + d.refs.ndmo.join(', ') : '', d.refs.aramco ? 'Aramco CCC: ' + d.refs.aramco : ''].filter(Boolean).join(' · '),
      purpose: d.sections[0] ? d.sections[0].en : '', body: d.text_en + '\n\n==========  النسخة العربية  ==========\n\n' + d.text_ar, requirements: d.sections.map((s) => s.h.en) }, who);
    const rec = { id: 'cp_' + now().toString(36) + Math.random().toString(36).slice(2, 5), template: d.id, company: c.id, title: d.title, grc_draft: dr.id, by: who.user, at: iso() };
    pol().put(rec); audit(who, 'policy.draft', rec.id, { template: d.id, company: c.id, grc_draft: dr.id }); return Object.assign({}, rec, { status: dr.status, version: dr.version });
  }
  function policyList(c) {
    let drafts = []; try { const L0 = grc().draftList({}); drafts = Array.isArray(L0) ? L0 : (L0 && L0.items) || []; } catch (e) { drafts = []; /* GRC not available: the drafts show without their status */ }
    const by = new Map(drafts.map((d) => [d.id, d]));
    const mine = pol().all().filter((p) => !c || p.company === c.id).map((p) => { const d = by.get(p.grc_draft); return Object.assign({}, p, { status: d ? d.status : 'unknown', version: d ? d.version : null, approved_by: d ? d.approved_by || null : null }); });
    return { templates: PT.list(), drafts: mine.sort((a, b) => (a.at < b.at ? 1 : -1)) };
  }

  // ---------- overview ----------
  async function overview(cid, role) {
    const c = company(cid), g = await gaps(c), D = dutyRows(c), A = actions().all().filter((a) => a.company === c.id).map(actionView).sort((a, b) => (a.at < b.at ? 1 : -1));
    const op = ['operator', 'admin'].includes(role);
    const fwsc = g.frameworks.filter((f) => f.realistic !== null);
    return { company: c, companies: companyList(false).map((x) => ({ id: x.id, name: x.name, name_ar: x.name_ar })), lines: LINES, frameworks_all: FW, ...g,
      kpis: { realistic: fwsc.length ? Math.round(fwsc.reduce((s, f) => s + f.realistic, 0) / fwsc.length) : null, recorded: fwsc.filter((f) => f.recorded !== null).length ? Math.round(fwsc.filter((f) => f.recorded !== null).reduce((s, f) => s + f.recorded, 0) / fwsc.filter((f) => f.recorded !== null).length) : null,
        open_gaps: g.total_open, duties_overdue: D.filter((d) => d.status === 'overdue' || d.status === 'never done').length, duties_waiting: D.filter((d) => d.pending).length,
        actions_open: A.filter((a) => a.state !== 'closed').length, actions_overdue: A.filter((a) => a.overdue).length, actions_waiting: A.filter((a) => a.state === 'submitted').length },
      duties: D, actions: op ? A : A.map((a) => ({ id: a.id, fw: a.fw, req_id: a.req_id, title: a.title, state: a.state, due: a.due, overdue: a.overdue })), policies: policyList(c), insights: insights(c, g, D, A) };
  }
  function insights(c, g, D, A) {
    const out = [], p = (level, title, detail) => out.push({ level, title, detail });
    for (const f of g.frameworks) if (f.recorded !== null && f.realistic !== null && f.recorded - f.realistic >= 20) p('warn', FW[f.id] + ': ' + f.recorded + '% as recorded, ' + f.realistic + '% realistic', f.unknown + ' requirement(s) are not measured or not assessed. An auditor counts them as not met until there is evidence.');
    if (g.themes[0]) p('crit', 'Start with ' + g.themes[0].topic.replace('_', ' ') + ' (' + g.themes[0].items + ' open requirement(s) across ' + g.themes[0].frameworks.join(', ') + ')', 'For ' + (c.short || c.name) + ': ' + g.themes[0].why + '. One piece of work closes them together.');
    const od = D.filter((d) => d.status === 'overdue' || d.status === 'never done'); if (od.length) p('warn', od.length + ' control activit' + (od.length === 1 ? 'y' : 'ies') + ' overdue or never done', od.slice(0, 4).map((d) => d.title).join('; ') + '. A control that is not operated is a finding even when the policy exists.');
    const ao = A.filter((a) => a.overdue); if (ao.length) p('warn', ao.length + ' remediation action(s) overdue', 'Escalate to the owners or agree new dates - an overdue action is reported as an open gap.');
    const ar = g.frameworks.find((f) => f.id === 'aramco'); if (ar && !ar.applicable && (c.lines || []).includes('aramco')) p('info', 'Aramco CCC: no control list yet', 'Import your copy of SACS-002 on the Aramco CCC page so the Aramco requirements join this view.');
    const pol0 = g.themes.filter((t) => t.policy).map((t) => t.policy); if (pol0.length) p('info', 'Policies to draft first: ' + [...new Set(pol0)].slice(0, 3).map((id) => (PT.TEMPLATES.find((t) => t.id === id) || {}).title.en).join(', '), 'Bilingual drafts are ready in the policy builder; GRC approval needs a second person.');
    return out;
  }

  // ---------- ask (AI with read-only tools, or local) ----------
  const TOOLS = [
    { name: 'gaps', min: 'viewer', description: 'The realistic compliance position of a company: frameworks, priorities with why, themes and the 90-day plan.', input_schema: { type: 'object', properties: { company: { type: 'string', maxLength: 40 } }, additionalProperties: false } },
    { name: 'duties', min: 'viewer', description: 'The recurring control activities of a company with due dates and status.', input_schema: { type: 'object', properties: { company: { type: 'string', maxLength: 40 } }, additionalProperties: false } },
    { name: 'actions', min: 'operator', description: 'Remediation actions of a company: owner, due, state, evidence reference.', input_schema: { type: 'object', properties: { company: { type: 'string', maxLength: 40 } }, additionalProperties: false } },
    { name: 'policy_templates', min: 'viewer', description: 'The bilingual policy templates with their framework references.', input_schema: { type: 'object', properties: {}, additionalProperties: false } },
  ];
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const toolsFor = (role) => TOOLS.filter((t) => (RANK[role] || 0) >= RANK[t.min]);
  function checkInput(schema, input) { if (!input || typeof input !== 'object' || Array.isArray(input)) return 'not an object'; for (const k of Object.keys(input)) { const p = schema.properties[k]; if (!p) return 'unknown field ' + k; if (typeof input[k] !== 'string' || input[k].length > (p.maxLength || 100)) return k + ' must be short text'; } return null; }
  async function runTool(name, input, who) {
    const t = toolsFor(who.role).find((x) => x.name === name); if (!t) throw new Error('tool not allowed for ' + who.role);   // re-checked per call
    const e = checkInput(t.input_schema, input); if (e) throw new Error('invalid input: ' + e);
    const c = company(input.company || undefined);
    if (name === 'gaps') { const g = await gaps(c); return { company: c.name, frameworks: g.frameworks, priorities: g.priorities.slice(0, 20), by_framework: g.by_fw, themes: g.themes.slice(0, 8), plan: g.plan }; }
    if (name === 'duties') return dutyRows(c).map((d) => ({ title: d.title, every_days: d.every_days, next_due: d.next_due, status: d.status, refs: d.refs }));
    if (name === 'actions') return actions().all().filter((a) => a.company === c.id).map(actionView).map((a) => ({ title: a.title, fw: a.fw, req_id: a.req_id, owner: a.owner, due: a.due, state: a.state, overdue: a.overdue }));
    return PT.list();
  }
  const cfg = () => (app.config && app.config.copilot_ai) || (app.config && app.config.ia_ai) || {};
  let Ctor = null;
  function sdk() { if (opts.sdk) return opts.sdk; if (Ctor) return Ctor;
    for (const p of [cfg().sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', path.join(__dirname, '..', 'vendor', 'node_modules', '@anthropic-ai', 'sdk')].filter(Boolean)) {
      try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { Ctor = null; /* try the next location; none found = local answers */ }
    }
    return null; }
  const key = () => { if (opts.getKey) return opts.getKey(); try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', app.config && app.config.discovery && app.config.discovery.vault_key_file)() || process.env.ANTHROPIC_API_KEY || ''; } catch (e) { return process.env.ANTHROPIC_API_KEY || ''; } };
  function aiStatus() {
    if (opts.aiOff) return { enabled: false, reason: 'off' };
    let allowed = false; try { allowed = !!(opts.sdk || (app.settings && require('./ai-backend').allowed(app.settings.get()))); } catch (e) { allowed = false; /* settings unreadable = not allowed */ }
    if (!allowed) return { enabled: false, reason: 'external AI is not allowed in IT Asset Management settings - answering from the registers on this server' };
    if (!key()) return { enabled: false, reason: 'no Anthropic API key - answering from the registers on this server' };
    if (!sdk()) return { enabled: false, reason: 'Anthropic SDK not installed - answering from the registers on this server' };
    return { enabled: true, model: cfg().model || MODEL };
  }
  const SYSTEM = 'You are the compliance consultant of ' + (ZYB_ORG.name || 'the organisation') + ', a group of companies. You help its compliance and audit teams with NCA ECC, ISO/IEC 27001:2022, the Saudi PDPL, the NDMO standards and the Saudi Aramco CCC, using ONLY what the read-only tools return (the organisation\'s own registers, control activities, remediation actions and policy templates). Answer in the language of the question (Arabic or English). Be concrete and short: what to do first, why for this company, which policy or control activity covers it. Say "not measured" when the data does not show it - never claim compliance the registers do not show, never invent clause text, and say the answer is an indicator, not an audit opinion. You cannot change anything; a person raises actions and approves policies.';
  async function ask(b0, who) {
    const b = body(b0 || {}).str('question', { required: true, min: 2, max: 2000 }).str('company', { max: 40 }).done(), c = company(b.company);
    const st = aiStatus();
    if (!st.enabled) return Object.assign(await localAnswer(b.question, c, who), { ai: false, note: st.reason });
    const budget = opts.budget || G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    const q = G.redactSecrets(b.question); budget.admit(who.user, 'copilot.ask', q.length);
    const flags = G.injectionSignals(b.question), usage = { input_tokens: 0, output_tokens: 0 }, tools = toolsFor(who.role).map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema })), steps = [];
    const Anthropic = sdk(), client = new Anthropic({ apiKey: key(), timeout: 120000, maxRetries: 2 });
    const messages = [{ role: 'user', content: '[company: ' + c.id + '] ' + q }]; let answer = null;
    try {
      for (let n = 0; n < 6; n++) {
        const r = await client.messages.create({ model: st.model, max_tokens: 4000, system: SYSTEM + '\n\n' + G.UNTRUSTED_RULE, tools, messages });
        for (const k of Object.keys(usage)) usage[k] += (r.usage && r.usage[k]) || 0;
        messages.push({ role: 'assistant', content: r.content });
        const uses = (r.content || []).filter((x) => x.type === 'tool_use');
        if (r.stop_reason !== 'tool_use' || !uses.length) { answer = (r.content || []).filter((x) => x.type === 'text').map((x) => x.text).join('\n').trim(); break; }
        const res = [];
        for (const u of uses) {
          try { let text = G.redactSecrets(JSON.stringify(await runTool(u.name, u.input || {}, who))); if (text.length > 20000) text = text.slice(0, 20000) + ' …[truncated]'; flags.push(...G.injectionSignals(text)); res.push({ type: 'tool_result', tool_use_id: u.id, content: G.untrusted('tool:' + u.name, text) }); steps.push({ tool: u.name, ok: true }); }
          catch (e) { res.push({ type: 'tool_result', tool_use_id: u.id, content: 'error: ' + String(e.message || e).slice(0, 200), is_error: true }); steps.push({ tool: u.name, ok: false }); }
        }
        messages.push({ role: 'user', content: res });
      }
    } finally { budget.record(who.user, 'copilot.ask', usage, [...new Set(flags)]); }
    audit(who, 'ask', c.id, { ai: true, steps: steps.length, flags: [...new Set(flags)] });
    return { ai: true, answer: answer || 'No answer - ask a narrower question.', steps, model: st.model, injection_signals: [...new Set(flags)] };
  }
  async function localAnswer(q, c, who) {
    const ar = /[؀-ۿ]/.test(q), t = low(q), g = await gaps(c), lines = [];
    const fw = Object.keys(FW).find((f) => new RegExp({ nca: 'nca|ecc|الأمن السيبراني|الضوابط', iso27001: 'iso|27001|آيزو|ايزو', pdpl: 'pdpl|personal data|privacy|البيانات الشخصية|خصوصية', ndmo: 'ndmo|data management|إدارة البيانات', aramco: 'aramco|ccc|أرامكو|ارامكو' }[f], 'i').test(t));
    if (/polic|سياس/.test(t)) {
      const pick = g.themes.filter((x) => x.policy).slice(0, 3).map((x) => PT.TEMPLATES.find((p) => p.id === x.policy)).filter(Boolean);
      lines.push(ar ? 'السياسات المقترح إعدادها أولاً لـ ' + (c.name_ar || c.name) + ':' : 'Policies to draft first for ' + c.name + ':'); for (const p of [...new Set(pick)]) lines.push('• ' + (ar ? p.title.ar : p.title.en));
      lines.push(ar ? 'تجدها جاهزة بالعربية والإنجليزية في منشئ السياسات، ويعتمدها شخص آخر في الحوكمة.' : 'They are ready in English and Arabic in the policy builder; a second person approves them in GRC.');
    } else if (/due|overdue|calendar|activit|مستحق|متأخر|التقويم|نشاط/.test(t)) {
      const D = dutyRows(c).filter((d) => d.status !== 'on track').slice(0, 8); lines.push(ar ? 'الأنشطة الرقابية المستحقة أو المتأخرة:' : 'Control activities due or overdue:'); for (const d of D) lines.push('• ' + (ar ? d.title_ar : d.title) + ' - ' + d.status + ' (' + d.next_due + ')');
      if (!D.length) lines.push(ar ? 'لا شيء مستحق الآن.' : 'Nothing is due now.');
    } else {
      const F = fw ? g.frameworks.filter((f) => f.id === fw) : g.frameworks;
      for (const f of F) lines.push((ar ? f.name_ar : f.name) + ': ' + (f.realistic === null ? (ar ? 'لا توجد بيانات' : 'no data') + (f.note ? ' - ' + f.note : '') : (ar ? 'النسبة الواقعية ' : 'realistic ') + f.realistic + '%' + (f.recorded !== null ? (ar ? '، المسجلة ' : ', as recorded ') + f.recorded + '%' : '') + (ar ? '، فجوات ' : ', gaps ') + f.gap + (ar ? '، غير مقاسة ' : ', not measured ') + f.unknown));
      const P = (fw ? g.by_fw[fw] || [] : g.priorities).slice(0, 5); if (P.length) { lines.push(ar ? 'ابدأ بـ:' : 'Start with:'); for (const p of P) lines.push('• [' + p.fw_name + ' ' + p.id + '] ' + p.title + ' - ' + (ar ? p.why_ar : p.why)); }
    }
    lines.push(ar ? 'هذه مؤشرات من السجلات وليست رأي تدقيق.' : 'Indicators from the registers, not an audit opinion.');
    audit(who, 'ask', c.id, { ai: false });
    return { answer: lines.join('\n') };
  }

  return { companyList, company, putCompany, gaps, overview, dutyRows, dutyDone, dutyVerify, dutyPut, actionCreate, actionSubmit, actionVerify, policyPreview, policyDraft, policyList, ask, toolsFor, runTool, aiStatus, DUTIES, TOPICS };
}

function registerCopilot(srv, app, X) {
  srv.route('GET', '/org/companies', (ctx) => { ctx.need('viewer'); return { companies: X.companyList(true), lines: LINES, frameworks: FW }; });
  srv.route('PUT', '/org/companies/:id', (ctx) => { ctx.need('admin'); return X.putCompany(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('GET', '/copilot/overview', (ctx) => { ctx.need('viewer'); const c = (ctx.query || {}).company; return X.overview(c ? param(String(c), 'company') : undefined, ctx.who.role); });
  srv.route('POST', '/copilot/actions', (ctx) => { ctx.need('operator'); return X.actionCreate(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/copilot/actions/:id/submit', (ctx) => { ctx.need('operator'); return X.actionSubmit(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/copilot/actions/:id/verify', (ctx) => { ctx.need('admin'); return X.actionVerify(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/copilot/duties/:id/done', (ctx) => { ctx.need('operator'); return X.dutyDone(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/copilot/duties/:id/verify', (ctx) => { ctx.need('admin'); return X.dutyVerify(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('PUT', '/copilot/duties/:id', (ctx) => { ctx.need('admin'); return X.dutyPut(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/copilot/policies', (ctx) => { ctx.need('viewer'); const c = (ctx.query || {}).company; return X.policyList(c ? X.company(param(String(c), 'company')) : null); });
  srv.route('POST', '/copilot/policies/preview', (ctx) => { ctx.need('operator'); return X.policyPreview(ctx.body); }, { maxBody: 4096 });
  srv.route('POST', '/copilot/policies/draft', (ctx) => { ctx.need('operator'); return X.policyDraft(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/copilot/ask', (ctx) => { ctx.need('viewer'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192, anyRole: 'a question is a read: it changes nothing and its tools are read-only and filtered by role' });
  (app.addons = app.addons || {}).copilot = X;
  app.addons.companies = { list: () => X.companyList(true), get: (id) => X.company(id) };
  return X;
}

module.exports = { createCopilot, registerCopilot, FW, LINES, DUTIES, TOPICS, STATE };
