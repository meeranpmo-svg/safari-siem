# Oracle Database in the SIEM

The setup guide, the collector, the monitoring account and the queries live with the kit:
**[agents/oracle/README.md](../agents/oracle/README.md)**.

- Source type `oracle-health` (Log Sources > *Oracle Database — health & performance*): `agents/oracle/sentra-oracle-collector.sh`
  on the database host, read-only account from `create-monitor-user.sql`, queries `collect.sql` (health + unified audit),
  `collect-perf.sql` (performance, licence-free views) and `collect-pack.sql` (Diagnostics Pack only, `PACK_ASH=1`).
- Record shapes per kind: `engine/db-audit/oracle-health.js` (health), `oracle-perf.js` (performance), `oracle-audit.js`
  (unified audit rows, and Unified / traditional audit over syslog for the `oracle-audit` source type).
- Rules: `engine/detect/rules/oracle.json` (SENTRA-ORA-001 … 010) and `oracle-perf.json` (SENTRA-ORAP-001 … 011).
