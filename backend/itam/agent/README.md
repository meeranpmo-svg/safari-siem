# itam-agent — Sentra ITAM endpoint agent

Cross-platform (Windows / Linux / macOS), **outbound-only** inventory agent. It reads local hardware, OS, installed
software and patch level, and POSTs them to the ITAM gateway (`/agent`). It never listens on a port, needs no inbound
firewall rule, and requires **no administrator rights at run time**.

## Commands
```
itam-agent enrol  --server https://<portal>/agent (--token-stdin | --token-file <path>) [--dir <state-dir>]   # https only (http just for 127.0.0.1/localhost)
itam-agent run    [--interval 3600]     # heartbeat + periodic report loop (store-and-forward when offline)
itam-agent once                          # one collect + report, then exit
itam-agent status                        # show enrolment + spool state
```

## How it works
- **Enrol once** with an admin-issued one-time token → receives a per-agent key (stored `0600`). The token cannot be
  reused.
- **Collect** via native, read-only tools, each degrading to null on failure (never crashes):
  - Windows: PowerShell CIM (`Win32_ComputerSystem/BIOS/OperatingSystem`, Uninstall registry keys, `Get-HotFix`),
    with a `wmic` fallback.
  - Linux: `/proc`, `/sys/class/dmi/id`, `dpkg-query` or `rpm`.
  - macOS: `system_profiler` (hardware + applications), `sw_vers`.
- **Report** with a monotonic `seq`, a `nonce` and a timestamp. If the gateway is unreachable the report is spooled to
  disk and flushed (oldest first) on the next successful run, keeping `seq` monotonic so the server rejects nothing
  legitimate and all replays.

## Least privilege
- Needs only outbound HTTPS to the portal and read access to the inventory commands above.
- Install scripts register it as a **non-admin** service: LOCAL SERVICE (Windows) / the `itam-agent` system user
  (Linux/macOS).
- The state file holds the agent key — it is created `0600` (Linux/macOS) or ACL-restricted to SYSTEM/Administrators/
  LocalService (Windows). Revoke an agent from the portal (`POST /agents/:id/revoke`) to invalidate its key immediately.

See `agent/install/install.sh` (Linux/macOS) and `agent/install/install.ps1` (Windows).
