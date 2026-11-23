# Detection validation — proving the SIEM catches attacks

`sentra-siem-validate` tests every built-in detection rule and writes an HTML + JSON report (detection rate, result per
rule, MITRE technique, alert id, time to alert). Use it after every upgrade, after rule changes, and monthly or
quarterly as evidence for SAMA CSF 3.3.14 (security event management) and 3.3.15 (incident management).

There are three levels:

| Level | Command | What it proves | Changes |
|---|---|---|---|
| 1. Rule logic | `sentra-siem-validate offline` | the parsers and rules detect each attack pattern | nothing (report file only) |
| 2. Live engine | `sudo sentra-siem-validate live` | the **running** engine ingests, parses, detects and raises the alerts | synthetic events + test alerts (closed automatically) |
| 3. End to end | endpoint scripts + `sudo sentra-siem-validate check` | real actions on a test machine reach the SIEM and alert (audit policy, agent, forwarding) | a test user / service / task on the test machine, removed afterwards |

Get a change/test approval and tell the SOC team before levels 2 and 3: they raise real alerts.

## 1 and 2: on the SIEM server

```bash
sudo sentra-siem-validate setup        # once: ingest token for the test source "sentra-validate", restarts sentra-siem
sudo sentra-siem-validate live         # about 1 minute; report written to the current directory
```

Output (one line per rule, then the totals):

```
Windows
  PASS  SENTRA-AUTH-001   Brute force against one account  (0.4 s)
  ...
ALL DETECTED  - 64 passed, 0 missed, 2 skipped, 0 disabled  (run 4f2a9c, live)
report: sentra-siem-validation-live-20261010-101500-4f2a9c.html  (+ .json)
```

Options: `--only windows,linux,fortigate,web,m365,exchange,intel`, `--keep-alerts` (leave the test alerts open so
the SOC team can see them in the portal), `--no-intel`, `--wait 180`, `--out /var/tmp`, `--json`.
Exit code 0 = everything detected, 1 = something missed, 2 = setup / connection problem.

What it sends: 49 scenarios, one or more per rule, as raw log lines in each source's own format (Windows agent
JSON, sshd/sudo syslog, FortiGate key=value, nginx access log, Microsoft 365 / Graph JSON, Exchange IIS and
message tracking). They go through the authenticated ingest path the Windows agent uses (`POST /ingest/sentra-validate`).
The events are clearly labelled: host and user names `ashval-<run>`, IP addresses from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or 10.250.0.0/16, and `.invalid` / `.example` domains.

- **Alerts**: all of a run's alerts are closed as *benign*, with the note "SIEM detection validation test (run …)".
  In the audit log they appear under the user `sentra-siem-validate`.
- **Events**: they stay in the event store, which is append-only and protected by the integrity chain. Find them
  with a search for `ashval-`.
- **Threat intel**: for the intel rules, the run writes `/var/lib/sentra-siem/intel/sentra-validation-<run>.txt`. It holds
  only test indicators (a `.invalid` domain, a TEST-NET-1 address and a hash of the run id) and is deleted after
  the run.

Results that are not PASS:

| Result | Meaning | What to do |
|---|---|---|
| FAIL | the engine did not raise the alert | `sudo journalctl -u sentra-siem -n 100`; check that the rule is enabled and was not edited (portal: Detection rules) |
| FAIL + "organisation-wide rule" | SENTRA-M365-004 counts across the whole tenant and stays quiet for 60 min after an alert | run again after an hour |
| FAIL + "baseline rule" | SENTRA-FGT-006 / SENTRA-EXO-015 alert on a *new* value only after a 7-day learning period | normal on an engine running for less than 7 days |
| DISABLED | the rule is switched off on this engine | intended? |
| SKIPPED | SENTRA-SCH-001/002 are scheduled searches over stored data | level 3: a real failed-logon storm / stopping a real log source |

## 3. End to end: on a test machine

**Windows** (run as Administrator on a test PC or server with the SentraAgent installed):

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-SentraDetections.ps1 -EnableAuditing
```

The script is in `agents/validation/`. It does the following:
- creates a local test user and makes 12 failed logons for it
- adds the user to Administrators
- installs a service that is never started, from a path in `C:\Users\Public`
- creates a disabled scheduled task
- runs an encoded PowerShell command that only prints text
- runs a download cradle against `127.0.0.1:9`, where nothing listens

Everything is removed at the end. The script then prints the command to run on the SIEM server, for example:

```bash
sudo sentra-siem-validate check --host pc01 --since 2026-10-10T09:30:00Z --expect SENTRA-IAM-003,SENTRA-IAM-004,SENTRA-AUTH-001,SENTRA-IAM-001,SENTRA-SYS-002,SENTRA-SYS-003,SENTRA-SYS-004,SENTRA-EXEC-001,SENTRA-EXEC-002
```

**Linux** (as a normal user with sudo, on a server that forwards syslog to the SIEM):

```bash
./test-sentra-detections.sh
```

The script does the following:
- 25 SSH attempts as a user that does not exist
- wrong sudo passwords
- `sudo -i`, which exits at once
- creates and deletes a test user

It then prints the `check` command to run on the SIEM server.

If an expected detection is missing at level 3 but passed at level 2, the cause is on the endpoint or in the
transport, not in the rules. Check these in order:
1. **Audit policy.** Use `-EnableAuditing`. Process creation needs command-line logging, and scheduled tasks need
   "Other Object Access Events".
2. **The agent:** `Get-Service SentraAgent` and the agent log, or rsyslog forwarding.
3. **The source's ingest token.**

Credential theft (LSASS dumps, Mimikatz) and clearing the security log are only covered at levels 1 and 2. Test
those on real endpoints in an isolated lab VM only, for example with Atomic Red Team (T1003.001, T1070.001). Never
run them on production machines.

## Evidence

Keep the HTML/JSON reports, together with the change ticket, in the SOC evidence folder. The JSON report holds the
run id, which links each report to the audit-log entries and the closed alerts.
