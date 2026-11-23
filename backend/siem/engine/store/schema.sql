-- Sentra SIEM — ClickHouse schema (ARCH.md "Normalised event").
-- Applied idempotently by engine/store/migrate.js, which substitutes {retention_days} (and the database name
-- when it is not `siem`). Statements are separated by a line ending in ';'.

CREATE DATABASE IF NOT EXISTS siem;

CREATE TABLE IF NOT EXISTS siem.events
(
    ts              DateTime64(3, 'UTC'),
    rts             DateTime64(3, 'UTC'),
    id              UUID,
    src_type        LowCardinality(String),
    src_id          LowCardinality(String),
    collector       LowCardinality(String),
    host            String,
    host_ip         String,
    category        LowCardinality(String),
    action          LowCardinality(String),
    outcome         LowCardinality(String),
    severity        UInt8,
    user            String,
    target_user     String,
    domain          String,
    src_ip          String,
    dst_ip          String,
    src_port        UInt16,
    dst_port        UInt16,
    proto           LowCardinality(String),
    process         String,
    parent_process  String,
    cmdline         String,
    hash            String,
    url             String,
    http_method     String,
    http_status     UInt16,
    user_agent      String,
    dns_query       String,
    event_code      String,
    message         String,
    tags            Array(LowCardinality(String)),
    fields          Map(String, String),
    raw             String CODEC(ZSTD(3)),
    batch_id        String CODEC(ZSTD(3)),
    INDEX idx_raw        raw        TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_message    message    TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_user       user       TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_src_ip     src_ip     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dst_ip     dst_ip     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_hash       hash       TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_event_code event_code TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (src_type, host, ts)
TTL toDateTime(ts) + INTERVAL {retention_days} DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;

-- Integrity chain: one row per inserted batch; sha256 over the exact NDJSON sent, chained to the previous batch.
CREATE TABLE IF NOT EXISTS siem.batches
(
    batch_id     String,
    seq          UInt64,
    ts           DateTime64(3, 'UTC'),
    rows         UInt32,
    bytes        UInt64,
    sha256       String,
    prev_sha256  String,
    first_ts     DateTime64(3, 'UTC'),
    last_ts      DateTime64(3, 'UTC'),
    node         LowCardinality(String),
    tagged       UInt8
)
ENGINE = MergeTree
ORDER BY (ts, seq)
SETTINGS non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS siem.stats_minute
(
    minute        DateTime('UTC'),
    src_id        LowCardinality(String),
    src_type      LowCardinality(String),
    events        UInt64,
    bytes         UInt64,
    parse_errors  UInt64
)
ENGINE = SummingMergeTree((events, bytes, parse_errors))
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, src_id, src_type)
TTL minute + INTERVAL {retention_days} DAY;

-- ---------------------------------------------------------------------------------------------------------------------
-- Data Optimizer (DATAOPT.md). Cold archive tier + per-rule volume counters + pipeline version audit mirror.

-- Cold/cheap archive tier: full events routed to archive, plus minimal drop STUBS (ts, source, type, hash) so nothing
-- is truly lost. Long TTL, aggressive compression. Mirrors siem.events columns + arch_* bookkeeping.
CREATE TABLE IF NOT EXISTS siem.events_archive
(
    ts              DateTime64(3, 'UTC'),
    rts             DateTime64(3, 'UTC'),
    id              UUID,
    src_type        LowCardinality(String),
    src_id          LowCardinality(String),
    collector       LowCardinality(String),
    host            String,
    host_ip         String,
    category        LowCardinality(String),
    action          LowCardinality(String),
    outcome         LowCardinality(String),
    severity        UInt8,
    user            String,
    target_user     String,
    domain          String,
    src_ip          String,
    dst_ip          String,
    src_port        UInt16,
    dst_port        UInt16,
    proto           LowCardinality(String),
    process         String,
    parent_process  String,
    cmdline         String,
    hash            String,
    url             String,
    http_method     String,
    http_status     UInt16,
    user_agent      String,
    dns_query       String,
    event_code      String,
    message         String,
    tags            Array(LowCardinality(String)),
    fields          Map(String, String),
    raw             String CODEC(ZSTD(9)),
    arch_at         DateTime64(3, 'UTC'),
    arch_rule       LowCardinality(String),
    arch_reason     String,
    arch_stub       UInt8,
    INDEX idx_arch_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_arch_user   user   TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (src_type, src_id, ts)
TTL toDateTime(ts) + INTERVAL {archive_retention_days} DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- Per-rule volume counters (events + bytes, hourly) for EVERY action incl. keep — the blind-spot guard's "what we kept
-- / archived / dropped / sampled / trimmed" ledger.
CREATE TABLE IF NOT EXISTS siem.dataopt_rule_stat
(
    hour         DateTime('UTC'),
    pipeline_id  LowCardinality(String),
    rule_id      LowCardinality(String),
    action       LowCardinality(String),
    events       UInt64,
    bytes        UInt64
)
ENGINE = SummingMergeTree((events, bytes))
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, pipeline_id, rule_id, action);

-- Source breakdown of what is dropped / sampled / trimmed / aggregated (feeds GET /dataopt/drops): nothing is silently
-- discarded.
CREATE TABLE IF NOT EXISTS siem.dataopt_drop_log
(
    hour         DateTime('UTC'),
    pipeline_id  LowCardinality(String),
    rule_id      LowCardinality(String),
    src_id       LowCardinality(String),
    src_type     LowCardinality(String),
    event_type   String,
    action       LowCardinality(String),
    events       UInt64,
    bytes        UInt64
)
ENGINE = SummingMergeTree((events, bytes))
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, pipeline_id, rule_id, src_id, src_type, event_type, action);

-- Pipeline version audit mirror (source of truth is the engine state journal; this is a durable, queryable copy —
-- hash-chained, one row per pipeline change).
CREATE TABLE IF NOT EXISTS siem.dataopt_pipeline
(
    ts           DateTime64(3, 'UTC'),
    seq          UInt64,
    pipeline_id  LowCardinality(String),
    version      UInt32,
    action       LowCardinality(String),
    by           String,
    enabled      UInt8,
    hash         String,
    prev_hash    String,
    rules_json   String CODEC(ZSTD(3))
)
ENGINE = MergeTree
ORDER BY (pipeline_id, seq, ts);

-- Mirror of the engine's alert state for search/reporting (latest version per id wins).
CREATE TABLE IF NOT EXISTS siem.alerts
(
    id          String,
    rule_id     LowCardinality(String),
    rule_name   String,
    severity    UInt8,
    ts_first    DateTime64(3, 'UTC'),
    ts_last     DateTime64(3, 'UTC'),
    status      LowCardinality(String),
    assignee    String,
    summary     String,
    group_json  String,
    mitre       Array(String),
    updated     DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY id;

-- ===================================================================================================================
-- UEBA (User & Entity Behaviour Analytics) — engine/ueba/*. Live queue state is held in the engine (soc/state.js) and
-- mirrored here for search/history/reporting. Retention aligned with events via {retention_days}.
-- ===================================================================================================================

-- Latest profile per entity (user | host | service_account | ai_agent).
CREATE TABLE IF NOT EXISTS siem.ueba_entity
(
    id            String,
    type          LowCardinality(String),
    name          String,
    peer_group    String,
    tags          Array(String),
    first_seen    DateTime64(3, 'UTC'),
    last_seen     DateTime64(3, 'UTC'),
    days_observed UInt32,
    state         LowCardinality(String),
    risk_score    Float64,
    risk_tier     LowCardinality(String),
    open_findings UInt32,
    updated       DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY id;

-- Full baseline snapshot per entity (JSON: robust stats, known-value sets, active-hour histogram).
CREATE TABLE IF NOT EXISTS siem.ueba_baseline
(
    entity_id     String,
    type          LowCardinality(String),
    name          String,
    days_observed UInt32,
    state         LowCardinality(String),
    baseline_json String,
    computed_at   DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY entity_id;

-- Per-entity-per-day numeric features (the robust-stats inputs). Produced by the ClickHouse aggregation.
CREATE TABLE IF NOT EXISTS siem.ueba_feature_daily
(
    entity_id     String,
    type          LowCardinality(String),
    name          String,
    day           Date,
    events        UInt64,
    auth_fail     UInt64,
    auth_success  UInt64,
    egress_bytes  UInt64,
    privileged    UInt64,
    distinct_hosts UInt32,
    updated       DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated)
PARTITION BY toYYYYMM(day)
ORDER BY (entity_id, day)
TTL day + INTERVAL {retention_days} DAY;

-- Findings raised by the detectors (explainable: observed vs baseline).
CREATE TABLE IF NOT EXISTS siem.ueba_finding
(
    id            String,
    entity_id     String,
    entity_type   LowCardinality(String),
    entity_name   String,
    detector      LowCardinality(String),
    severity      UInt8,
    weight        Float64,
    status        LowCardinality(String),
    mitre         Array(String),
    explanation   String,
    observed_json String,
    baseline_json String,
    evidence      Array(String),
    ts_first      DateTime64(3, 'UTC'),
    ts_last       DateTime64(3, 'UTC'),
    count         UInt32,
    alert_id      String,
    created       DateTime64(3, 'UTC'),
    updated       DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY id;

-- Risk-score timeline per entity.
CREATE TABLE IF NOT EXISTS siem.ueba_risk
(
    entity_id     String,
    at            DateTime64(3, 'UTC'),
    score         Float64,
    tier          LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(at)
ORDER BY (entity_id, at)
TTL toDateTime(at) + INTERVAL {retention_days} DAY;

-- Analyst tuning / allow-list (benign per entity+detector).
CREATE TABLE IF NOT EXISTS siem.ueba_tuning
(
    id            String,
    entity_id     String,
    detector      LowCardinality(String),
    action        LowCardinality(String),
    values        Array(String),
    by            String,
    note          String,
    updated       DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated)
ORDER BY id;

-- ---------------------------------------------------------------------------------------------------------------------
-- AD identity (engine/ad/sync.js, read-only LDAPS pull every ad.sync_minutes). Latest state per key wins
-- (ReplacingMergeTree on `synced`): query with FINAL. Accounts that vanished from AD get one row with deleted = 1;
-- members that left a privileged group one row with removed = 1. Times 1970-01-01 = never / unknown.
CREATE TABLE IF NOT EXISTS siem.identity_users
(
    sam               String,
    upn               String,
    display_name      String,
    mail              String,
    department        String,
    title             String,
    manager           String,
    dn                String,
    sid               String,
    member_of         Array(String),
    uac               UInt32,
    disabled          UInt8,
    admin_count       UInt8,
    privileged        UInt8,
    privileged_groups Array(String),
    last_logon        DateTime64(3, 'UTC'),
    pwd_last_set      DateTime64(3, 'UTC'),
    created           DateTime64(3, 'UTC'),
    expires           DateTime64(3, 'UTC'),
    deleted           UInt8,
    synced            DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(synced)
ORDER BY sam;

-- Privileged-group membership with nesting resolved (nested = 1: member through another group; primaryGroupID counts as direct).
CREATE TABLE IF NOT EXISTS siem.identity_groups
(
    group_dn          String,
    group_sam         String,
    group_sid         String,
    member_sam        String,
    member_dn         String,
    nested            UInt8,
    privileged        UInt8,
    removed           UInt8,
    synced            DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(synced)
ORDER BY (group_dn, member_sam);

-- One row per sync run (ok or failed) — sync health and history.
CREATE TABLE IF NOT EXISTS siem.identity_sync
(
    ts                DateTime64(3, 'UTC'),
    ok                UInt8,
    server            String,
    users             UInt32,
    groups            UInt32,
    privileged        UInt32,
    new_privileged    UInt32,
    duration_ms       UInt32,
    error             String
)
ENGINE = MergeTree
ORDER BY ts
TTL toDateTime(ts) + INTERVAL {retention_days} DAY;

-- ---------------------------------------------------------------------------------------------------------------------
-- AI Network Engineer (docs/NETOPS.md): polled device metrics (reachability, CPU/memory, interface rates/utilisation,
-- SD-WAN path quality, tunnel state) for trends and capacity forecasting. key = interface / path / tunnel name.
CREATE TABLE IF NOT EXISTS siem.net_metrics
(
    ts      DateTime('UTC'),
    device  LowCardinality(String),
    site    LowCardinality(String),
    key     String,
    metric  LowCardinality(String),
    value   Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (device, metric, key, ts)
TTL ts + INTERVAL 400 DAY;

-- ---------------------------------------------------------------------------------------------------------------------
-- NetFlow Analytics (engine/collect/flow-collector.js, engine/soc/flow-analytics.js): NetFlow v5 / v9, IPFIX and sFlow
-- records from the exporters on the allow-list, scaled by each exporter's sampling rate. Summing tables: always read them
-- with sum(). One-minute rollups (35 days), per interface per minute (400 days, utilisation and capacity forecasting),
-- per private / group address per hour (400 days, IP groups and billing), a bounded raw sample (7 days).
CREATE TABLE IF NOT EXISTS siem.flow_minute
(
    minute    DateTime('UTC'),
    exporter  LowCardinality(String),
    if_in     UInt32,
    if_out    UInt32,
    src_ip    String,
    dst_ip    String,
    src_port  UInt16,
    dst_port  UInt16,
    proto     UInt8,
    dscp      UInt8,
    app       LowCardinality(String),
    bytes     UInt64,
    packets   UInt64,
    flows     UInt64
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, exporter, if_in, if_out, src_ip, dst_ip, proto, src_port, dst_port, dscp, app)
TTL minute + INTERVAL 35 DAY;

CREATE TABLE IF NOT EXISTS siem.flow_if_minute
(
    minute    DateTime('UTC'),
    exporter  LowCardinality(String),
    if_index  UInt32,
    dir       LowCardinality(String),
    bytes     UInt64,
    packets   UInt64,
    flows     UInt64
)
ENGINE = SummingMergeTree((bytes, packets, flows))
PARTITION BY toYYYYMM(minute)
ORDER BY (exporter, if_index, dir, minute)
TTL minute + INTERVAL 400 DAY;

CREATE TABLE IF NOT EXISTS siem.flow_ip_hour
(
    hour      DateTime('UTC'),
    exporter  LowCardinality(String),
    ip        String,
    dir       LowCardinality(String),
    app       LowCardinality(String),
    bytes     UInt64,
    packets   UInt64
)
ENGINE = SummingMergeTree((bytes, packets))
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, exporter, ip, dir, app)
TTL hour + INTERVAL 400 DAY;

CREATE TABLE IF NOT EXISTS siem.flow_raw
(
    ts         DateTime('UTC'),
    exporter   LowCardinality(String),
    version    LowCardinality(String),
    src_ip     String,
    dst_ip     String,
    src_port   UInt16,
    dst_port   UInt16,
    proto      UInt8,
    tos        UInt8,
    tcp_flags  UInt8,
    if_in      UInt32,
    if_out     UInt32,
    bytes      UInt64,
    packets    UInt64,
    sampling   UInt32,
    app        LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (exporter, ts)
TTL ts + INTERVAL 7 DAY;
