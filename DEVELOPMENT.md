# Development

## Requirements

* Node.js 20 or later (both engines use only the standard library: no `npm install`)
* Python 3.9+ for the Python readers and their tests
* Chromium + Playwright for the page tests (`PLAYWRIGHT=<path to the playwright package>`)

## Tests

```bash
bash tools/run-tests.sh            # everything: asset engine, SIEM engine, pages
bash tools/run-tests.sh itam       # one part: itam | siem | ui
```

* `backend/itam/tests` - engine tests with fake devices (`node --test`), Python parity tests (Node and Python readers
  must answer identically)
* `backend/siem/tests` - engine tests; tests that need ClickHouse or a live service are skipped, never faked as passing
* `tests/ui` - each page in a real browser against stub APIs, including "not installed / refused / no data" states

## Adding a page

1. `ui/<page>.html` - use the shared scripts (`vendor/zyb-dash.js`, `vendor/zyb-soc.js` …); no inline handlers
2. one entry in `ui/vendor/zyb-nav.js` (menu group, short label, title, description, frameworks)
3. Arabic labels in `ui/vendor/zyb-lang.js` when a menu group is added
4. the file name in `ui/install-dashboards.sh`
5. a test in `tests/ui/`

## Adding a backend module

1. `backend/itam/engine/<module>.js` exporting `register<Module>(srv, app)`; routes call `ctx.need('<role>')`
2. register it in `engine/main.js`
3. an installer `backend/itam/install/add-<module>.sh` (backup -> install -> health check -> roll back on failure)
4. tests in `backend/itam/tests/<module>.test.js`
5. the files in `deploy/stage-map.txt` (add them by hand)

## Keep the tree clean

A file nothing reaches is dead code: remove it or wire it in. Keep `docs/CODEMAP.md` in step when a page or module is added.

## The company name

Never write the company name, its domain, the portal host or the server address in code, pages or tests. Read them from
the brand setting: `ZYB_ORG` in pages (`vendor/zyb-org.js`), `require('./brand')` in the engines, `org_brand` in Python,
`{{org.short}}` tokens in static page text. See `brand/README.md`.
