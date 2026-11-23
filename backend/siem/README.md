# Sentra SIEM engine

Custom SIEM/SOC engine (Node.js standard library, ClickHouse store): collectors (syslog, HTTPS ingest, Windows agent, Microsoft 365), parsers incl. Exchange on-premises, real-time detection rules (MITRE ATT&CK), SOC workflow, API and the portal SOC module. Contract: ARCH.md. Tests: `node --test tests/`. Detection validation (does the SIEM catch attacks?): docs/VALIDATION.md (`sentra-siem-validate`).

Confidential — Smart Shield / Zyberon. Private repository.
