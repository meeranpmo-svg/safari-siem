# Front-end wiring audit - results (20 Oct 2026)

Run: `node harness.js` (see README.md). Both engines real, every add-on registered, all 68 pages of dashboards/server opened in Chromium.

**304 of 307 requests answered by a real route; no page or console errors.**

## Requests that did not succeed

| Page | Request | Status |
|---|---|---|
| roles.html | GET /auth/admin/config | 599 |
| roles.html | GET /auth/whoami | 599 |
| soc-live.html | GET /api/soc/tail | failed |

599 = not served by the two engines (the portal sign-in service, outside this audit). `failed` on /api/soc/tail = the live stream cut off when the page was closed.

## Pages that show generated sample data (not connected to any source)

| Page | What it invents | Real source |
|---|---|---|
| network-flows.html | firewall flows, countries, apps, zones, bytes | SIEM events from FortiGate / Palo Alto (country, app, bytes, zones are kept in `fields`) |
| portal-traffic.html | visitors, countries, error paths, latency | the customer portal nginx logs in the SIEM (url, http_status, user_agent) |
| apm-claims-portal.html | response times | none yet - must say "not connected" |
| head-of-it.html | applications and uptimes | server availability, SIEM tickets / alerts, ITAM assets and owners |

## Per page (requests made on load / answered / errors)

| Page | Requests | OK | Errors |
|---|---|---|---|
| ad-audit.html | 15 | 15 | 0 |
| ad-exchange.html | 17 | 17 | 1 |
| add-server.html | 1 | 1 | 1 |
| ai-app-manager.html | 5 | 5 | 1 |
| ai-ciso.html | 4 | 4 | 1 |
| ai-dba.html | 5 | 5 | 1 |
| ai-grc-consultant.html | 6 | 6 | 1 |
| ai-ksc-engineer.html | 6 | 6 | 2 |
| ai-security-engineer.html | 6 | 6 | 2 |
| ai-team.html | 12 | 12 | 1 |
| ai-virt-admin.html | 6 | 6 | 2 |
| ai-zscaler-engineer.html | 6 | 6 | 2 |
| apm-claims-portal.html | 1 | 1 | 0 |
| asset-ownership.html | 2 | 2 | 1 |
| audit-log.html | 2 | 2 | 0 |
| backup.html | 2 | 2 | 1 |
| budget.html | 2 | 2 | 1 |
| capacity.html | 2 | 2 | 1 |
| connections.html | 6 | 6 | 1 |
| cost-optimization.html | 6 | 6 | 1 |
| db-performance.html | 5 | 5 | 0 |
| desk-support.html | 5 | 5 | 2 |
| detection-validation.html | 4 | 4 | 1 |
| dfir.html | 2 | 2 | 1 |
| dr-drills.html | 4 | 4 | 1 |
| email-security.html | 8 | 8 | 1 |
| end-user-devices.html | 13 | 13 | 0 |
| exchange-admin.html | 7 | 7 | 2 |
| grc-policies.html | 9 | 9 | 1 |
| head-of-it.html | 1 | 1 | 0 |
| index.html | 1 | 1 | 1 |
| it-audit.html | 5 | 5 | 0 |
| licence-audit.html | 7 | 7 | 1 |
| lifecycle.html | 2 | 2 | 1 |
| log-assurance.html | 6 | 6 | 2 |
| m365.html | 2 | 2 | 1 |
| manageengine.html | 1 | 1 | 1 |
| my-work.html | 11 | 11 | 1 |
| network-discovery.html | 1 | 1 | 1 |
| network-engineer.html | 5 | 5 | 2 |
| network-flows.html | 1 | 1 | 0 |
| noc-overview.html | 3 | 3 | 0 |
| node-details.html | 1 | 1 | 1 |
| npm-summary.html | 2 | 2 | 0 |
| nutanix-vms.html | 2 | 2 | 0 |
| pentest.html | 6 | 6 | 2 |
| platform.html | 2 | 2 | 2 |
| portal-traffic.html | 1 | 1 | 0 |
| printers.html | 3 | 3 | 0 |
| reconcile.html | 2 | 2 | 1 |
| roles.html | 4 | 2 | 2 |
| sama-compliance.html | 2 | 2 | 0 |
| sdwan.html | 2 | 2 | 0 |
| server-availability.html | 2 | 2 | 1 |
| soc-intel.html | 5 | 5 | 1 |
| soc-live.html | 5 | 4 | 1 |
| soc-lr.html | 5 | 5 | 1 |
| soc-response.html | 4 | 4 | 1 |
| soc-sources.html | 9 | 9 | 1 |
| soc-tickets.html | 6 | 6 | 1 |
| soc-ueba.html | 5 | 5 | 1 |
| soc-xdr.html | 3 | 3 | 1 |
| storage.html | 2 | 2 | 1 |
| support-contracts.html | 4 | 4 | 1 |
| threats-by-department.html | 2 | 2 | 1 |
| virtualization.html | 3 | 3 | 1 |
| windows-admin.html | 7 | 7 | 2 |
| wireless.html | 3 | 3 | 0 |
