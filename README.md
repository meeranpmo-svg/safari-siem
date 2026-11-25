# Safari Company Limited: IT operations, security and GRC platform (Zyberon Sentra)

Everything the platform runs for Safari Company Limited, and nothing it doesn't: every portal page, both engines, their
installers, the collector kits and the tests. Code only, with no history and no data from any other organisation.

```
brand/              THE BRAND SETTING: brand.json (name, Arabic name, short name, domain, portal host, logo, report
                    header, colours, sector, frameworks, modules and pages switched off) + logo + README
ui/                 the portal: every page, the menu, shared scripts, styles
backend/
  itam/             IT Asset Management engine (node engine/main.js): assets, discovery, backup, virtualisation (Hyper-V),
                    storage, licences, GRC, PDPL, NDMO ... + installers + Python readers
  siem/             SIEM / SOC engine (node engine/main.js): logs, alerts, cases, UEBA, XDR, audit trail, change plans ...
                    + installers + collector kits (agents/) for remote sites + docs
tests/ui/           the page tests (a real browser)
deploy/
  stage-map.txt     the update package layout
  build-package.sh  builds the update package from this tree
  server/           the server-side update scripts the package carries
docs/               CODEMAP.md, pages.csv, files.csv: how each page gets its data (snapshot)
tools/
  brand/            apply-brand.js writes the generated copies of the brand setting
  run-tests.sh      every test
```

## The brand setting

The company identity is set once, in `brand/brand.json`. Pages, reports, e-mails and AI prompts read it; none of them
carries the company name, domain or server address as text. After a change:

```bash
node tools/brand/apply-brand.js          # rewrites ui/vendor/zyb-org.js and each engine's brand.default.json
node tools/brand/apply-brand.js --check  # fails when a generated copy is stale
```

See `brand/README.md`. Two values in it are placeholders until Safari confirms them: `portal_host` (the HTTPS name of
the portal) and `platform_ip` (the LAN address of the platform server, empty until set).

## Sector

Safari is a group of companies, not a financial institution. Frameworks: NCA ECC, ISO/IEC 27001, PDPL, NDMO.
`modules_off` and `pages_off` in the brand setting take the parts that do not apply out of every menu, search and the
home page, for every role: SAMA CSF, Insurance Authority, CST, Aramco CCC, Business Risk & capital, Cisco update manager,
Cisco collaboration, the VMware / Nutanix / Cisco-only pages, the Oracle-only pages (tuning, licences, Oracle Linux, Solaris,
Data Guard, AI Oracle DBA), the Kaspersky and Zscaler engineer pages, and three application pages Safari has no source for (Applications Manager, synthetic
monitoring, portal traffic). Virtualisation is Hyper-V (set up as a scope in Asset
Discovery), firewalls are Fortinet, switches are multi-vendor (SNMP / SSH), mail is hybrid Exchange, and remote sites
report through the collector kits in `backend/siem/agents/`. An administrator can add a module back in Platform Admin ->
Modules & Solutions.

## Install on a new server

On the server (Ubuntu 22.04 / 24.04, with this tree copied or cloned onto it):

```bash
sudo bash deploy/install-fresh-server.sh --auth-src /path/to/the/sign-in/service
```

It installs, in order: nginx and the other system packages, the SIEM engine with ClickHouse, the asset engine, the
organisation's sign-in service (copied unchanged; the script never creates an account or touches a password or
two-factor setting), the HTTPS site for the portal host, and the pages. The portal host and the server's address come
from the brand setting (`portal_host`, `platform_ip`); `--host`, `--ip`, `--tls-cert` and `--tls-key` override them.
It ends with a summary of what is running and what a person does next (DNS, the first administrator, the
certificate, the firewall). Re-running it upgrades in place and keeps settings, secrets and data.

## Tests

```bash
bash tools/run-tests.sh            # asset engine, SIEM engine, pages
```

## Data is not here

Code only. Data stays on the server: `/var/lib/sentra-itam` (assets, settings, encrypted logins), `/var/lib/sentra-siem`
and the ClickHouse database `siem`. Secrets are generated on the server by the installers; none is in this tree. The
organisation's own signed policy register is not shipped either (`backend/itam/engine/grc-policies.json` is an empty
list; an administrator provides the file on the server). No customer data, logs or credentials may be added (PDPL).

Sign-in, two-factor authentication and the authorisation rules are unchanged. The sign-in service itself is a separate
component and is not part of this tree; the scripts here expect it at `/opt/sentra-auth`.
