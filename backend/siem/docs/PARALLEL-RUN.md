# Parallel run with LogRhythm

The new SIEM runs **next to** LogRhythm on the same log sources until it has proven — with data, not opinion — that it
collects at least the same logs and detects at least the same threats. Only then is LogRhythm retired.

```
                 ┌──────────────► LogRhythm (unchanged: System Monitor agents, syslog, AIE alarms)
 each source ────┤                              │ alarms (export / API)
                 └──────────────► Sentra SIEM ◄───┘ POST /api/soc/lr/alarms
                                   GET /api/soc/lr-compare  →  both / only ours / only LogRhythm
```

Plan for **at least 30 days** of full parallel operation after the last source is onboarded, covering a month-end
and at least one patch cycle; 60 days is better for low-frequency detections.

---

## 1. Dual-forwarding each source

Rule: **never take a log feed away from LogRhythm** during the parallel run — add a second destination.

| source | LogRhythm keeps | add for the new SIEM |
|---|---|---|
| FortiGate | `config log syslogd setting` → LR collector | `config log syslogd2 setting` + `syslogd2 filter` → SIEM:5514 (same filter as LR) |
| Cisco IOS / ASA | existing `logging host <LR>` | a second `logging host <SIEM> transport tcp port 5514` (IOS allows several hosts; ASA: another `logging host` line + `logging permit-hostdown`) |
| Linux (rsyslog) | existing LR forwarding rule | `install-rsyslog-forwarder.sh` — adds its own `60-sentra-siem.conf`, does not touch other rules |
| Linux with the LR System Monitor agent | the agent | rsyslog forwarding as above (independent of the LR agent) |
| Windows (LR System Monitor agent) | the agent | SentraAgent side by side — both read the event logs independently; no conflict, no change to audit policy needed beyond what LR already requires (check the recommended policy for gaps) |
| CEF / LEEF appliances | existing syslog destination | second syslog destination (most products support 2–4) |
| appliance with only ONE syslog destination | — | point it to an rsyslog relay that forwards to both LR and the SIEM (`omfwd` twice); register the relay IP as the source on both sides — the device host name is kept in the syslog header |
| Microsoft 365 | LR cloud collector | phase 2 (Graph pull) — compare manually until then |

Checklist per source after enabling the second feed:

1. Onboarding verification (ONBOARDING.md checklist) on the SIEM side.
2. **Volume parity**: events/day on both sides for the same source (LogRhythm: Log Source → volume report / Search
   by log source; SIEM: query below). Differences > 5 % need an explanation (LR filters/drops, dedup, collection
   gaps, different message splitting).
3. LogRhythm's collection for that source must be unchanged (no drop in LR volume).

```sql
-- SIEM events per source per day (last 14 days)
SELECT toDate(minute, 'Asia/Riyadh') AS day, src_id, sum(events) AS events, sum(parse_errors) AS parse_errors
FROM siem.stats_minute WHERE minute >= now() - INTERVAL 14 DAY
GROUP BY day, src_id ORDER BY src_id, day;
```

Keep a **source mapping table** (LR log source name ↔ SIEM `src_id`), e.g. `FW-HQ-01 (Syslog - Fortinet FortiGate)`
↔ `fw-hq-01`. The comparison uses LR's `log_source` as the alert source.

---

## 2. Getting LogRhythm alarms into the comparison

The engine compares its own alerts with LogRhythm **alarms** stored alongside them (`source: logrhythm`). The
automatic LogRhythm pull collector is phase 2; until then import alarms (daily, or at least weekly) through the API
(operator role):

```
POST /api/soc/lr/alarms
{ "alarms": [
  { "alarm_id": 1234567, "alarm_rule_id": 1000123, "alarm_rule_name": "AIE: Brute Force Attack",
    "alarm_date": "2026-09-29T10:15:00Z", "first_event": "2026-09-29T10:10:02Z", "last_event": "2026-09-29T10:14:55Z",
    "priority": 75, "status": "New", "entity": "the organisation HQ",
    "log_source": "FW-HQ-01", "log_source_type": "Syslog - Fortinet FortiGate",
    "user": "alice", "src_ip": "203.0.113.7", "dst_ip": "", "host": "dc01", "event_count": 42, "mitre": ["T1110"] }
] }
```

* Required: `alarm_id` (unique — re-importing the same id merges, so overlapping exports are safe),
  `alarm_rule_name`, `alarm_date` (ISO or epoch ms). Everything else is optional but **entities matter**: the
  comparison matches on `user`, `src_ip`, `dst_ip`, `host`.
* `priority` (0–100) maps to severity: ≥ 90 → 4, ≥ 70 → 3, ≥ 40 → 2, ≥ 20 → 1.
* Up to 10,000 alarms per request.
* Source of the data: the LogRhythm Web Console alarm list export (CSV), or the LogRhythm Alarm API
  (`/lr-alarm-api/alarms` and the alarm's events for entities). Map the columns to the shape above with a small
  script; keep the raw exports as evidence.
* Imported alarms are ordinary alerts with `source: logrhythm` and rule id `LR-<rule id|name>`. Exclude them from
  SOC triage queues (filter `source != logrhythm`) — they exist only for the comparison.

---

## 3. The comparison report

Portal: the parallel-run panel on **SIEM SOC Overview**, or
`GET /api/soc/lr-compare?from=<iso>&to=<iso>&window_s=900&bucket_s=3600`
(default: last 7 days).

A LogRhythm alarm and one of our alerts count as **the same detection** when their time spans overlap within
±`window_s` (default 900 s, config `lr_match_window_s`) **and** either

* the LR rule is mapped to our rule in `lr_rule_map` (config.json), or
* they share an entity value (`user`, `src_ip`, `dst_ip` or `host`).

```json
"lr_rule_map": {
  "AIE: Brute Force Attack":              "SENTRA-AUTH-001",
  "AIE: Password Spray":                  "SENTRA-AUTH-002",
  "1000123":                              ["SENTRA-AUTH-001", "SENTRA-AUTH-003"],
  "AIE: Audit Log Cleared":               "SENTRA-WIN-004"
},
"lr_match_window_s": 900
```

(Rule ids on the right are examples — use the ids from the SIEM's rule list.)

Output: `totals {ours, lr, both_ours, both_lr, only_ours, only_lr, overlap_pct}`, and the same split `by_rule` (ours),
`by_lr_rule`, `by_source`, `by_bucket` (time), plus the matched `pairs` and the ids of unmatched alerts/alarms.

### Weekly review (SOC lead + SIEM engineer, ~1 hour)

For every **only LogRhythm** alarm (a potential miss), classify and act:

| class | meaning | action |
|---|---|---|
| missing source | the events never reached the SIEM | onboard / fix the feed; re-check volume parity |
| missing rule | events are there, no equivalent rule | write/import a rule (RULES.md), test it on the period, add to `lr_rule_map` |
| threshold / window | a rule exists but did not trigger | tune, test with `POST /api/soc/rules/test` on that period |
| entity mismatch | both fired, match failed | improve entity mapping in the import, or add the rule mapping |
| LR false positive | LR alarm was noise (closed as FP in LR) | record as accepted, no action |

For every **only ours** alert: new coverage (keep — note it as a benefit) or false positive (tune).

Record each decision in a log (date, LR alarm id / our alert id, class, action, owner) — it is the evidence for the exit
decision and for auditors.

---

## 4. Exit criteria to retire LogRhythm

Proposed; agree the numbers with the CISO / SOC manager at the start of the parallel run.

| # | criterion | measured by |
|---|---|---|
| 1 | **Source coverage**: every in-scope LogRhythm log source has a mapped SIEM `src_id`, status `ok` for ≥ 14 consecutive days | source mapping table, Sources page |
| 2 | **Volume parity**: per source, daily event counts within ±5 % of LogRhythm (or the difference explained) for ≥ 14 days | §1 query vs. LR volume report |
| 3 | **Detection parity**: over the last 30 days ≥ 95 % of LR alarms with priority ≥ 70 matched (`both_lr / lr`), and **every** unmatched one classified; zero unexplained misses of high/critical alarms | `lr-compare`, review log |
| 4 | **Parsing quality**: parse-error rate < 1 % per source (0 % for agents) | Sources page |
| 5 | **Operations**: SOC has triaged all alerts in the new portal for ≥ 14 days; cases, playbooks, SLA reporting in use; MTTD/MTTR not worse than with LogRhythm | SIEM SOC Overview (`/api/soc/metrics`) |
| 6 | **Reliability**: health `ok` ≥ 99.5 % of the last 30 days; no spool drops; agents' queues drained; no data-loss incident | health history, `spool.dropped_*` |
| 7 | **Resilience**: backup running; a full restore test done on a spare VM; upgrade + rollback rehearsed | OPERATOR-GUIDE §5–6 |
| 8 | **Compliance**: retention set to the required period (confirm with Compliance — SAMA CSF / NCA ECC commonly require 12 months), archive export tested, integrity ledger check passes, audit journal backed up | OPERATOR-GUIDE §4, §7 |
| 9 | **Historical data**: decision on LogRhythm history (keep LR read-only until its retention expires, or export to the archive) | signed decision |
| 10 | **Sign-off**: CISO + SOC manager + IT operations | signed record |

## 5. Cut-over and decommissioning

1. Freeze: no new LR rules; any LR rule change during the run is mirrored in the SIEM first.
2. Switch SOC triage to the SIEM only (already the case per criterion 5); stop importing LR alarms after the final
   comparison report is archived.
3. Per source, remove the LogRhythm destination (FortiGate `syslogd`, Cisco `no logging host <LR>`, rsyslog LR rule,
   uninstall the LR System Monitor agent) — in batches, verifying after each batch that the SIEM volume is unchanged.
4. Keep LogRhythm read-only (search of history) for the agreed period, then decommission and end the licence.
5. Update runbooks, the source inventory and the network documentation (firewall rules to the LR collectors can go).
