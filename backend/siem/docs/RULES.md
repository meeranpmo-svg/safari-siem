# Detection rules

The engine evaluates **native JSON rules** on every event in real time (in event time), plus **scheduled search
rules** that run a query every N minutes. Sigma rules are converted into native rules on import.

* Built-in pack: `engine/detect/rules/*.json` (~50 rules: authentication, Windows/IAM, Linux, network/FortiGate, web,
  threat intel / cloud, scheduled). Shipped with the code, read-only, updated with each release.
* Your changes (new rules, Sigma imports, tuning of built-ins) are stored in the engine state (collection `rules`)
  and survive upgrades. Every change is written to the audit journal.
* Rule changes need the **admin** role; testing a rule needs **operator**.

---

## 1. Event fields you can match

Top-level normalised fields (ARCH "Normalised event"): `ts`, `src_type`, `src_id`, `collector`, `host`, `host_ip`,
`category`, `action`, `outcome`, `severity`, `user`, `target_user`, `domain`, `src_ip`, `dst_ip`, `src_port`,
`dst_port`, `proto`, `process`, `parent_process`, `cmdline`, `hash`, `url`, `http_method`, `http_status`,
`user_agent`, `dns_query`, `event_code`, `message`, `tags`, `raw` — and every vendor-specific key as
`fields.<key>`.

Useful values:

| field | examples |
|---|---|
| `category` | `authentication`, `network`, `web`, `process`, `iam`, `malware`, `file`, `registry`, `dns`, `system`, `policy`, `email`, `cloud`, `other` |
| `action` | `logon`, `logon-failed`, `logoff`, `user-created`, `group-member-added`, `process-start`, `connection`, `blocked`, `allowed`, `http-request`, `service-installed`, `audit-log-cleared`, `ips-detection`, `av-detection`, `sudo`, `config-change`, `unparsed` |
| `outcome` | `success`, `failure`, `unknown` |
| `event_code` | Windows EventID (`"4625"`), FortiGate `logid`, CEF signature id … (always a string) |
| `fields.*` | Windows `EventData` names as sent by the agent (`fields.LogonType`, `fields.TargetUserName`, `fields.ServiceFileName`, `fields.ScriptBlockText` …), FortiGate keys (`fields.subtype`, `fields.attack`, `fields.crlevel` …) |

Look at a real event first: search in the portal, open the event, and copy field names from the JSON view.

---

## 2. Native rule format

```json
{
  "id": "SENTRA-AUTH-001",
  "name": "Brute force against one account",
  "enabled": true,
  "severity": 3,
  "mitre": ["T1110.001"],
  "tactic": "credential-access",
  "description": "10 or more failed logons for the same account within 5 minutes (any source).",
  "author":"Sentra SOC",
  "version": 1,
  "type": "threshold",
  "match": {
    "all":  [ { "field": "action", "op": "eq", "value": "logon-failed" } ],
    "none": [ { "field": "user", "op": "endswith", "value": "$" } ]
  },
  "group_by": ["user"],
  "window_s": 300,
  "count": 10,
  "suppress_s": 3600,
  "fields_in_alert": ["user", "src_ip", "host", "src_type"]
}
```

| key | meaning |
|---|---|
| `id` | unique, `[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}`. Use `SENTRA-…` for the built-in pack and e.g. `CUS-…` for your own |
| `severity` | 0 info · 1 low · 2 medium · 3 high · 4 critical |
| `mitre` | ATT&CK technique ids (reports, alert badges) |
| `match` | `all` (AND), `any` (OR — at least one), `none` (NOT any). Items may be leaf conditions or nested groups `{all?, any?, none?}`; a leaf may carry `"not": true` |
| `group_by` | fields that identify "the same thing" (per user, per src_ip …). Events whose group values are all empty are skipped (`skip_empty_group`, default true) |
| `suppress_s` | one alert per group per window (default 300). Detections during suppression are counted into the existing alert, not lost |
| `fields_in_alert` | fields copied into the alert summary |

### Condition operators

| op | value | notes |
|---|---|---|
| `eq`, `neq` | string/number or list (any-of) | case-insensitive for strings |
| `in` | list | any-of |
| `contains`, `startswith`, `endswith` | string or list | case-insensitive |
| `re` | regular expression | always case-insensitive; keep it anchored and simple |
| `exists` | `true` | absent = missing / `''` / `0` / `[]` |
| `gt`, `gte`, `lt`, `lte` | number | e.g. `http_status` ≥ 500, `fields.sentbyte` |
| `cidr` | CIDR or list | on IP fields: `["10.0.0.0/8", "192.168.0.0/16"]` |
| `intel` | IOC list name | `ip`, `domain`, `hash`, `any`, or a file name from `/var/lib/sentra-siem/intel/` (see §6) |
| `hour_between` | `[start, end]` | hour of `ts` in Asia/Riyadh (`tz_offset_min`, default 180); wraps midnight when start > end |
| `weekday_in` | `[0..6]` | 0 = Sunday … 5 = Friday, 6 = Saturday |

Array fields (`tags`) match when any element matches.

### Rule types

**single** — every matching event (per group, subject to suppression):

```json
{ "id": "CUS-WIN-001", "name": "Security audit log cleared", "enabled": true, "severity": 4, "mitre": ["T1685.005"],
  "type": "single",
  "match": { "any": [ { "field": "event_code", "op": "eq", "value": "1102" },
                      { "field": "action", "op": "eq", "value": "audit-log-cleared" } ] },
  "group_by": ["host"], "suppress_s": 3600, "fields_in_alert": ["host", "user"] }
```

**threshold** — at least `count` matching events per group within `window_s` (example above). Optional
`sum_field` + `sum_gt`: fire when the sum of a numeric field exceeds a value (e.g. bytes sent):

```json
{ "id": "CUS-NET-001", "name": "Large upload to the internet from one host", "enabled": true, "severity": 3,
  "mitre": ["T1048"], "type": "threshold",
  "match": { "all": [ { "field": "src_type", "op": "eq", "value": "fortigate" },
                      { "field": "action", "op": "eq", "value": "allowed" } ],
             "none": [ { "field": "dst_ip", "op": "cidr", "value": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] } ] },
  "group_by": ["src_ip"], "window_s": 3600, "sum_field": "fields.sentbyte", "sum_gt": 2000000000,
  "suppress_s": 21600, "fields_in_alert": ["src_ip", "host"] }
```

**distinct** — at least `distinct_count` different values of `distinct_field` per group within `window_s`
(password spraying: one source, many accounts):

```json
{ "id": "SENTRA-AUTH-002", "name": "Password spraying from one source", "enabled": true, "severity": 3,
  "mitre": ["T1110.003"], "type": "distinct",
  "match": { "all": [ { "field": "action", "op": "eq", "value": "logon-failed" } ] },
  "group_by": ["src_ip"], "distinct_field": "user", "distinct_count": 10, "window_s": 600, "suppress_s": 3600 }
```

**sequence** — step 1 then step 2 (…) within `window_s` with the same `by` values; a step may require `count`:

```json
{ "id": "SENTRA-AUTH-003", "name": "Successful logon after repeated failures", "enabled": true, "severity": 3,
  "mitre": ["T1110"], "type": "sequence",
  "steps": [ { "match": { "all": [ { "field": "action", "op": "eq", "value": "logon-failed" } ] }, "count": 5 },
             { "match": { "all": [ { "field": "action", "op": "eq", "value": "logon" },
                                   { "field": "outcome", "op": "eq", "value": "success" } ] } } ],
  "by": ["user"], "window_s": 600, "suppress_s": 3600 }
```

**new_value** — a value of `new_field` never seen before for the group, after a learning period (`learn_s`, default
7 days of event time):

```json
{ "id": "CUS-AUTH-010", "name": "Admin logs on from a new source address", "enabled": true, "severity": 2,
  "mitre": ["T1078"], "type": "new_value",
  "match": { "all": [ { "field": "action", "op": "eq", "value": "logon" },
                      { "field": "outcome", "op": "eq", "value": "success" },
                      { "field": "tags", "op": "eq", "value": "admin" } ] },
  "group_by": ["user"], "new_field": "src_ip", "learn_s": 1209600, "suppress_s": 86400 }
```

**scheduled** — a query (portal search language) run every `every_min` over the last `lookback_min`, alerting on a
count condition. `lt` / `lte` make "absence" rules (a source went silent):

```json
{ "id": "CUS-SCH-001", "name": "FortiGate HQ silent for 30 minutes", "enabled": true, "severity": 2,
  "mitre": ["T1685.002"], "type": "scheduled",
  "query": "src_id:fw-hq-01", "every_min": 10, "lookback_min": 30,
  "condition": { "op": "lt", "value": 1 }, "suppress_s": 3600 }
```

Optional `group_by` evaluates the condition per group (e.g. `"query": "action:blocked", "group_by": ["src_ip"],
"condition": {"op": "gte", "value": 1000}`).

Windows for threshold/distinct/sequence are evaluated in **event time**, so late or replayed events (agent queue,
spool) still correlate correctly.

---

## 3. Creating and changing rules

Portal: **SIEM Detection Rules** (rule list with live statistics, enable/disable). Creating and editing rules, Sigma
import and rule tests are API calls (the portal session is used when they are called from the browser):

```bash
# from a shell on the SIEM server (admins only). The engine trusts these headers from 127.0.0.1 - put YOUR
# account name in X-Auth-User: it is what the audit journal records.
curl -s http://127.0.0.1:9120/api/soc/rules/import-sigma -H 'Content-Type: application/json' \
     -H 'X-Auth-User: j.smith' -H 'X-Auth-Role: admin' \
     --data-binary @<(python3 -c 'import json,sys; print(json.dumps({"yaml": open(sys.argv[1]).read(), "dry_run": True}))' rule.yml)
```

| call | role | body |
|---|---|---|
| `GET /api/soc/rules` (`?type=&enabled=&q=&origin=`) | viewer | — |
| `POST /api/soc/rules` | admin | native rule JSON — validated by compiling it; same id = update |
| `POST /api/soc/rules/<id>/enable` / `disable` | admin | — |
| `POST /api/soc/rules/<id>/delete` | admin | custom rule → deleted; built-in → your override removed (back to shipped) |
| `POST /api/soc/rules/import-sigma` | admin | `{yaml, enabled?, dry_run?, id?}` |
| `POST /api/soc/rules/test` | operator | `{rule | rule_id | sigma, from, to, q?, max_events?}` |

Tuning a **built-in** rule (threshold, exclusions, disable) stores a full copy marked as an override; the shipped
version stays untouched and "delete" resets to it. After an upgrade that improves a built-in rule you keep your
override — compare with `engine/detect/rules/` and reset when appropriate.

Conventions: one idea per rule; `description` says what fires and why it matters; always set `mitre`;
`fields_in_alert` = what the analyst needs first; version bump on every logic change.

---

## 4. Sigma import

```json
POST /api/soc/rules/import-sigma
{ "yaml": "<one or more Sigma documents>", "dry_run": true, "enabled": false }
```

The converter never guesses: anything it cannot translate faithfully is returned as an **error** (no rule created);
lossy-but-safe situations are **warnings**.

* Supported: selections (maps = AND, lists = OR), value lists, `|all`, wildcards, modifiers `contains`, `startswith`,
  `endswith`, `all`, `re` (+ `i/m/s`), `cidr`, `gt/gte/lt/lte`, `exists`, `windash`, `cased` (warning: the engine is
  case-insensitive), keyword lists (full-text on `raw`), `null` (field absent); conditions with `and/or/not`,
  parentheses, `1 of sel*`, `all of sel*`, `1 of them`, `all of them`; aggregations `| count() by f > N` (→ threshold)
  and `| count(field) by f > N` (→ distinct) with `timeframe` → `window_s`.
* Not supported (reported as errors): `base64`, `base64offset`, `utf16*`, `wide`, `expand`, `fieldref`, `near`,
  aggregations other than `count`, `<`/`<=`/`=` aggregation operators, `N of` with N > 1, correlation rules,
  `action: global` collections.
* Field mapping: common Sigma names map to the schema (`Image`→`process`, `ParentImage`→`parent_process`,
  `CommandLine`→`cmdline`, `TargetUserName`→`target_user`, `SubjectUserName`/`User`→`user`, `IpAddress`/`SourceIp`→`src_ip`,
  `DestinationIp`→`dst_ip`, `EventID`→`event_code`, `QueryName`→`dns_query`, `Hashes`→`hash`, `c-uri`/`cs-uri-query`→`url`,
  `c-useragent`→`user_agent`, `sc-status`→`http_status` …); every other field becomes `fields.<SigmaName>`, which matches
  Windows `EventData` names forwarded by the agent.
* Logsource mapping: `product: windows|linux|fortigate|cisco|m365|nginx|apache`, categories `process_creation`,
  `network_connection`, `firewall`, `dns`, `webserver`, `proxy`, `file_*`, `registry_*`, `process_access`, `image_load`,
  `driver_load`, `create_remote_thread`, `ps_script` (4104), `ps_module` (4103), `authentication`, `antivirus`;
  services `security`, `system`, `sysmon`, `powershell`, `sshd`, `auth`, `sudo`, `auditd`, `signinlogs`, `auditlogs` ….

Workflow:

1. Take the rule from a trusted repository (SigmaHQ), review it.
2. `dry_run: true` → read errors/warnings and the produced native rule.
3. Test it over the last 7–30 days (§5). Expect some noise — add `none` exclusions in the native rule.
4. Import with `enabled: false`, then enable after the test shows an acceptable rate.

Note: Sigma rules for Sysmon (`process_creation` etc.) only work where Sysmon (or 4688 with command line) is collected;
PowerShell rules need script block logging (4104) — see agents/windows/README.md.

---

## 5. Testing rules

```json
POST /api/soc/rules/test
{ "rule": { …native rule… }, "from": "2026-09-01T00:00:00Z", "to": "2026-09-29T00:00:00Z",
  "q": "src_type:windows", "max_events": 500000 }
```

(or `"rule_id": "SENTRA-AUTH-001"` for an existing rule, or `"sigma": "<yaml>"`). `from`/`to` are ISO-8601 timestamps or
epoch seconds/milliseconds. The engine replays the stored events
of the time range (optionally pre-filtered by `q`, ordered by time) through a fresh detector and returns the alerts
the rule **would** have raised — nothing is written. Use it to:

* check a new rule fires on the known-bad case (find a past incident, or generate a harmless test event, e.g. 11
  wrong passwords for a test account),
* measure noise: alerts per day over 30 days; aim for a rate the SOC can triage,
* compare thresholds (run twice with different `count`/`window_s`).

Testing tips:

* Narrow `q` to the relevant source type to keep replays fast; `max_events` caps the replay.
* `new_value` rules need a range longer than `learn_s` to show anything.
* For a rule matching `fields.X`, first confirm the field exists: search `fields.X:*` over the same range.
* Unit-level checks for the engine itself live in `tests/` (`node --test tests/`) — they use clearly labelled
  synthetic lines only.

---

## 6. Threat-intel lists (`intel` operator)

Drop files into `/var/lib/sentra-siem/intel/` (owner `sentra-siem`): `*.txt` (one indicator per line, `#` comments, text
after the first space = description) or `*.csv` (`indicator,type,description`). Types are detected automatically
(IP, CIDR, domain — also matches subdomains —, MD5/SHA-1/SHA-256, URL → host). Lists reload automatically within
~15 s; `POST /api/soc/intel/reload` forces it. Use them as:

```json
{ "field": "dst_ip", "op": "intel", "value": "ip" }          // any IP/CIDR indicator
{ "field": "dns_query", "op": "intel", "value": "domain" }
{ "field": "hash", "op": "intel", "value": "bad-hashes" }    // only /var/lib/sentra-siem/intel/bad-hashes.*
```

Sources: NCA / Saudi CERT advisories, vendor feeds you are licensed for, IOCs from your own incidents. Keep lists
curated (expire old indicators) — stale IP lists cause false positives.

---

## 7. Tuning and noise control

| problem | fix |
|---|---|
| service/computer accounts trigger auth rules | `none`: `{"field":"user","op":"endswith","value":"$"}` or a list of service accounts |
| scanners / monitoring systems | `none`: `{"field":"src_ip","op":"in","value":[…]}` or `cidr` — document why |
| one noisy host repeats the same alert | `group_by` includes `host`; raise `suppress_s` |
| threshold too sensitive | raise `count` or shorten `window_s` — test before/after (§5) |
| rule useless in this environment | disable (keeps history), don't delete |

The **SIEM SOC Overview** page (`GET /api/soc/metrics`) lists noisy rules (alerts/day, false-positive closures). Review monthly: rules with many
`closed-false-positive` alerts need tuning; rules that never fire need a test proving they still can.
