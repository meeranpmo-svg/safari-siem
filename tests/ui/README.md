# Front-end wiring audit

Checks that every dashboard page is connected: each API call a page makes on load must reach a real route.

- The **real** IT Asset Management engine runs with every add-on registered the way `install/add-*.sh` registers them on the server.
- The **real** SIEM engine runs with a fake ClickHouse (from its tests) and the syslog listeners off.
- A small nginx-like proxy routes `/api/itam/` and `/api/soc` to them, adding the proxy secret and an admin identity. Every other `/api/` or `/auth/` path answers 599: it is not served by these engines.
- Every `dashboards/server/*.html` page is opened in Chromium. Every request, its status, page / console errors and "not installed / not connected" wording are written to `report.json`.

```bash
# from shield/tools/frontend-audit, with the sentra-siem checkout next to shield (or SENTRA_SIEM_DIR=...)
PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node harness.js
ONLY=budget.html,soc-ueba.html node harness.js     # a few pages only
```

Limits: only what a page loads on opening is exercised; buttons that save something are not clicked. Data sources are not
configured, so "not connected" states are expected and correct.

- `RESULTS.md` - the results of the 20 Oct 2026 run.
- `STORES.md` - inventory of the three data stores (ITAM collections, the portal Asset Register `/api/db`, the SIEM state + ClickHouse): record shapes, overlaps between stores, and the structural problems found, with file:line references.
