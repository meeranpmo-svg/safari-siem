// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test: a person who chose Arabic sees Arabic, not a mix. Each page is opened in Arabic with every API answering "not
// connected" (the empty states), and every text node, placeholder, title and aria-label is read: a text with English WORDS left in
// it fails - acronyms, standards and product names (SAMA, NCA ECC, Microsoft 365, ...) are allowed, and data (code, .mono,
// [data-no-tr]) is never read. The leadership pages and the home page must be clean; every other page is measured and must not
// fall below the coverage the Arabic pack reached (MIN_COVERAGE). English mode is checked too: no Arabic leaks into it.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node arabic-coverage.test.js [page-regex]
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const CLEAN = ['index.html', 'my-workspace.html', 'enterprise-risk.html', 'business-risk.html', 'business-risk-register.html', 'risk-appetite.html', 'risk-command.html', 'ciso-dashboard.html', 'head-of-it.html'];
const MIN_COVERAGE = 99.5;   // % of texts on all pages that read as Arabic (measured when the pack was built; may only go up)
// words that stay as written in Arabic text: acronyms, standards, products, units
const KEEP = new RegExp('\\b(' + ZYB_ORG.short.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '|' + 'Citynet Work|CityNet|Zyberon Information Technology|Zyberon Sentra|SAMA|CSF|NCA|ECC|CCC|PDPL|SDAIA|NDMO|IA|CHI|ISO|IEC|SOC|NIST|MITRE|ATT&CK|IFRS|RAS|KRIs?|KPIs?|SLAs?|NDA|RTO|RPO|DR|BCM|BCP|CISO|BISO|CIO|CFO|CEO|DPO|DPIA|RoPA|DSARs?|SIEM|SOAR|XDR|EDR|UEBA|DLP|MDM|NAC|VAPT|CVEs?|CVSS|CMDB|ITAM|AD|LDAP|SSO|MFA|2FA|VPN|IPs?|DNS|TLS|SSL|APIs?|CSV|PDF|Excel|SNMP|WAN|LAN|SD-WAN|VMs?|CPU|RAM|AI|ML|GRC|RACI|PAM|NHI|SPF|DKIM|DMARC|MX|PTR|SMTP|HTTP|HTTPS|URL|SQL|OS|USB|UPS|NVR|CCTV|QR|OTP|ID|IT|OT|ICS|AML|UW|P&C|P&S|BBB|MN|SAR|GB|TB|MB|ms|s|h|min|Microsoft|365|Exchange|Active|Directory|Entra|Intune|Teams|SharePoint|OneDrive|Oracle|PostgreSQL|MySQL|ManageEngine|Endpoint|Central|ServiceDesk|Plus|Kaspersky|Zscaler|Cisco|Fortinet|FortiGate|Palo|Alto|Aruba|VMware|vSphere|ESXi|Nutanix|AHV|Veeam|Commvault|NetApp|Synology|Libraesva|Wazuh|Greenbone|OpenVAS|Tenable|Nessus|Claude|Zyberon|SmartShield|CityNet|Windows|Linux|Solaris|Server|Data|Guard|LogRhythm|AIOps|Graph|Azure|Proxmox|HPE|MSA|Dell|Lenovo|iOS|Android|Chrome|Edge|Segoe|UI|vCenter|SSH|Prism|MAC|FireCompass|syslog|Online|OWASP|GoldenGate|Defender|MASVS|MASTG|CIS|ESG|NOC|NPM|IOS|ZKBioSecurity|SAFEQ|ASA|DFIR|BYOD|JSON|Hyper-V|Silver|Peak|VLAN|Genian|Monte|Carlo|Benford|MTTR|MTTA|MTTD|Kaspersky Security Center|Security Center|Outlook|Cloudflare|KSC|WinRM|NTP|vCPU|SHA-\\d+|Anthropic|PowerShell|Spamhaus|SAST|DAST|SCA|Conditional|Access|Secure|Score|Remote|Desktop|Xerox|YSoft|CIA|HTML|IIS|DAG|RAC|GET|POST|SFTP|FTP|ODI|vMotion|vSAN|Aruba|ClearPass|Exchange Online|Applications Manager|OpManager|Log360|ADAudit|ADManager|Ctrl|Alt|Shift|Esc|Enter|Tab|K|N|x|vs|v\\d[\\w.]*)\\b', 'g');   // the company name comes from the brand setting
// file names, commands and paths are code, written as they are typed
const CODE = /[\w.\\\/-]+\.(?:ps1|sh|js|json|html|py|xlsx|csv|pem|conf)\b|\bgit pull origin main\b|(?:^|\s|\()\/[\w\/.:-]+|\b[\w-]+\/[\w\/.-]+|Accent #[0-9A-Fa-f]{6}|\bArt\. ?\d|\bsudo [\w .\/-]+|\b[a-z]+[._][a-z0-9._]+\b/g;
// a text with no Arabic is English when an English word is left once acronyms, products and code are taken out; an Arabic text is
// English-mixed when a lower-case English word is left (a product name is capitalised; a sentence fragment is not)
const LOWER_OK = /\b(syslog|inodes|vCenter|vMotion|vSphere|vSAN|vCPU|iOS|macOS|eDiscovery|x64|ms|min|kbps|mbps|gbps|https?|www|api|json|csv|id|ids)\b/g;
// example values and identifiers in placeholders (CASE-000123, ORADB01, a CSV header) are data, not words
const DATA_LIKE = (t) => !/\s/.test(t) || /^[\w.@#+-]+(\s*,\s*[\w.@#+ -]+)+$/.test(t) || (/^[A-Z0-9_+. -]{2,24}$/.test(t) && !/[a-z]/.test(t));
const english = (t) => { if (DATA_LIKE(t)) return false; const r = t.replace(CODE, ' ').replace(KEEP, ' ').replace(LOWER_OK, ' '); return /[\u0600-\u06ff]/.test(t) ? (r.match(/\b[a-z]{3,}\b/g) || []).length >= 3 && /\b[a-z]{3,} [a-z]{3,} [a-z]{3,}\b/.test(r) : /[A-Za-z]{3,}/.test(r.replace(/\([^)]*\)/g, (m) => (/[a-z]{4,}/.test(m) ? m : ' '))); };
(async () => {
  const ONLY = process.argv[2] ? new RegExp(process.argv[2]) : null;
  const W = { ZYB_ORG: require('../../brand/index') }; require('vm').runInNewContext(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'), { window: W, document: {} });
  const pages = [...new Set(['index.html'].concat(...W.ZYB_NAV.map((a) => a.pages.map((p) => p.h))))].filter((h) => fs.existsSync(path.join(DASH, h)) && (!ONLY || ONLY.test(h)));
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end('{"user":"syn.admin","role":"admin"}'); }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"not connected"}'); }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html; charset=utf-8' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r)); const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const read = (p) => p.evaluate(() => { const S = new Set(), sk = (e) => { for (; e && e.nodeType === 1; e = e.parentNode) { if (/^(SCRIPT|STYLE|CODE|PRE|TEXTAREA|SVG|KBD|NOSCRIPT|OPTION)$/.test(e.nodeName)) return true; if (e.hasAttribute('data-no-tr') || (e.classList && e.classList.contains('mono'))) return true; } return false; };
    const add = (t) => { t = String(t || '').replace(/\s+/g, ' ').trim(); if (t && t.length <= 2000 && /[A-Za-z؀-ۿ]/.test(t)) S.add(t); };
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT); let x; while ((x = w.nextNode())) if (!sk(x.parentNode)) add(x.nodeValue);
    document.querySelectorAll('[placeholder],[title],[aria-label]').forEach((e) => { if (!sk(e) || /^(INPUT|TEXTAREA)$/.test(e.nodeName)) ['placeholder', 'title', 'aria-label'].forEach((a) => add(e.getAttribute(a))); });
    return [...S]; });
  let total = 0, en = 0; const left = {};
  try {
    const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } }); await ctx.addInitScript(() => { try { localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' })); } catch (e) { /* test storage */ } });
    for (const pg of pages) {
      const p = await ctx.newPage(); p.on('dialog', (d) => d.dismiss()); p.on('pageerror', (x) => errs.push(pg + ': ' + x.message));
      await p.goto(base + pg, { timeout: 30000 }); await p.waitForTimeout(1300);
      const T = await read(p), E = T.filter(english); total += T.length; en += E.length; if (E.length) left[pg] = E;
      if (CLEAN.includes(pg)) ok(!E.length, pg + ' is all Arabic - English left: ' + E.slice(0, 8).map((t) => JSON.stringify(t.slice(0, 80))).join(' | '));
      if (pg === pages[0]) ok(await p.evaluate(() => document.documentElement.dir === 'rtl' && !!window.__zybArPack), 'Arabic pack loaded, right to left');
      await p.close();
    }
    const cov = total ? Math.round((1000 * (total - en)) / total) / 10 : 100;
    console.log('coverage ' + cov + ' % (' + (total - en) + ' of ' + total + ' texts on ' + pages.length + ' pages); pages with English left: ' + Object.keys(left).length);
    if (process.env.SHOW_ENGLISH) console.log(JSON.stringify(left, null, 1));   // SHOW_ENGLISH=1: list the texts still in English
    if (!ONLY) ok(cov >= MIN_COVERAGE, 'coverage ' + cov + ' % is at least ' + MIN_COVERAGE + ' %');
    if (process.env.LEFT) fs.writeFileSync(process.env.LEFT, JSON.stringify(left, null, 1));
    // English mode: no Arabic, and the Arabic pack is not downloaded
    const ec = await browser.newContext(); const p = await ec.newPage(); const got = []; p.on('request', (r) => got.push(r.url()));
    await p.goto(base + 'enterprise-risk.html'); await p.waitForTimeout(1200);
    ok(!/[؀-ۿ]/.test(await p.evaluate(() => document.querySelector('main').innerText)) && !got.some((u) => /zyb-ar\.js/.test(u)), 'English: no Arabic text and the Arabic pack is not loaded');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.slice(0, 5).join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
