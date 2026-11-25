# Brand setting

`brand.json` is the one place the company identity is set: name, Arabic name, short name, domain, website, logo, report
header, brand colours, sector and the frameworks that apply. Pages, reports and e-mails read it; none of them carries
the company name as text.

| Who reads it | How |
|---|---|
| Pages (browser) | `ui/vendor/zyb-org.js` defines `window.ZYB_ORG`; static page text uses `{{org.short}}` / `{{org.name}}` tokens it fills in |
| Asset engine | `backend/itam/engine/brand.js` |
| SIEM engine | `backend/siem/engine/util/brand.js` |
| Page tests, tools | `brand/index.js` |

After changing `brand.json` (or the logo) run `node tools/brand/apply-brand.js`; it rewrites the generated copies
(`ui/vendor/zyb-org.js` and each engine's `brand.default.json`). `node tools/brand/apply-brand.js --check` fails when a
copy is stale. On a server the engines read `/etc/sentra/brand.json` first (`SENTRA_BRAND_FILE` to point elsewhere) and
fall back to the copy they were installed with.

Values are plain text: `< > & " ' \`` and line breaks are refused, because the name is placed into pages and reports.

`framework_scope` says who each framework covers (for example `nca`: the company only, `pdpl`: the company and the group companies it processes data for); the NCA ECC page, the home page tiles and PDPL Group Companies show it.

`modules_off` / `pages_off` take modules and pages out of every menu, search and the home page; `connections_off` takes cards
out of the Integration Hub for products the organisation does not use (ids as in `ui/connections.html`, e.g. `cloudflare`,
`esg`, `esglog`). A card whose page is in `pages_off` is hidden too.
