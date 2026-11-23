# AI Windows Server Administrator and AI Exchange Server Administrator

Two assistants on one engine (`engine/sysadmin/`), pages `windows-admin.html` and `exchange-admin.html`.

## What they do

* **Server list** — Windows servers and VMs come from IT Asset Management automatically (`sentra-itam/engine/sysadmin-sync.js`,
  every 5 min): Windows OS + an IP. Exchange servers are recognised from installed software "Microsoft Exchange Server", a tag
  `exchange`, the record naming Exchange, or a host name such as EXCH01 / MBX02; the reason is stored (`detected_by`). An
  Exchange server is in both lists. A server an administrator removes is not added again.
* **Read-only checks** — `checks.json` (30 checks: disks, services, events, updates / pending reboot, certificates, performance,
  network, time sync, scheduled tasks, AD replication; Exchange servers, service health, queues, databases, DAG copies,
  certificates, health sets, back pressure, connectors, message tracking, mailbox). `ps-helper.py` (pypsrp) runs **only** a
  named check from that file with validated parameters; there is no free-form PowerShell. Tests assert no check uses a
  Set-/New-/Remove-/Restart-/Stop-… cmdlet.
* **Health checks** every 15 min (`sysadmin.interval_min`) → findings with plain thresholds (disk < 10 %, services stopped,
  critical events, no patch for 45 days, reboot pending, certificates < 30 days, queues > 100 / retry, database dismounted,
  no backup for 7 days, DAG copy not healthy, …). A server that cannot be checked is a finding, never "healthy".
  Organisation-wide Exchange checks run once per round, on one Exchange server.
* **AI** (`ai.js`) — same API key / SDK / model as the AI Network Engineer. Tools: list servers, findings, latest health, run a
  check, SIEM events (Windows / Exchange logs already collected), Server Availability, propose a change plan.
* **Change plans** (`SCHG-…`) — proposed by people or the AI, approved by an administrator (not the author), applied by a
  person; "applied" re-checks the server and records whether high / critical problems remain. The SIEM never changes a server.

## Connection and accounts

WinRM, port 5985 (HTTP — the session is encrypted by Kerberos / NTLM message encryption, required) or 5986 (HTTPS — the
certificate must be read and trusted by an administrator first; a different certificate later refuses the login).

Logins are profiles in `secrets.json` `sysadmin.profiles` (write-only): `windows` for Windows checks, `exchange` for Exchange
checks; a server can name another profile per role.

* **windows**: a domain account in *Remote Management Users*, *Event Log Readers* and *Performance Monitor Users* on each
  server (GPO restricted groups). `failed_tasks`, `roles`, `shares` need local administrator and report "access denied" otherwise.
* **exchange**: *View-Only Organization Management* + *Remote Management Users* on each Exchange server. Message tracking needs
  the *Message Tracking* role in addition. The checks load the Exchange snap-in on the Exchange server itself (the Exchange
  remote endpoint runs in NoLanguage mode, which cannot run the checks).

On the servers: `Enable-PSRemoting` (already on by default on Windows Server 2012+), firewall 5985 (or 5986) from the SIEM only.

## UAT checklist and site filter

* **Site filter** (top of the page, remembered per browser): the server tables and the problem list show one site, e.g. UAT.
  The KPI tiles stay estate-wide and the page says so.
* **UAT checklist** tab (Windows page, `engine/sysadmin/uat.js`): eight tests on the servers of the round's site (default
  `UAT`) - connection, a real problem raised, unreachable server, wrong password, AI answers from evidence, four-eyes change
  approval, roles, and (optional) Windows event logs. Beside each test the platform shows the evidence it holds (servers
  checked, problems open, refused logins, change plans approved by someone else); **a person records the result** (operator;
  a fail needs a note). Sign-off: every required test passed, by an administrator who recorded none of the results. A new
  round (admin) keeps the old one under *Earlier rounds*. Every result, sign-off and new round is audited.
  Routes: `GET /api/soc/sysadmin/uat` (viewer), `POST …/uat/items/:id` (operator), `POST …/uat/signoff`, `…/uat/reset` (admin).

## Roles (portal)

viewer: overview, findings, servers · analyst: ask the AI · operator: run checks (checks that name people are audited),
check now, propose / mark applied · admin: servers, logins, certificates, approve plans.

## Install

`install/netops-cli-setup.sh` installs pypsrp next to Netmiko in `/opt/sentra-siem/pyenv` (`--proxy`, `--wheels`); the server
update runs it. Tests: `tests/sysadmin.test.js`, `sentra-itam/tests/sysadmin-sync.test.js`.
