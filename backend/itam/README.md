# sentra-itam

**AI-powered IT Asset Management + CMDB** (Zyberon Sentra). Discovers and de-duplicates every asset
(networked and off-network) into one record, classifies and relates them with an advisory AI layer, and tracks
lifecycle / licences / warranty / ownership. **AI proposes, people approve; nothing is hard-deleted.**

- `engine/**` — model, merge/de-dup, ingest (netops/vCenter/agent/manual/import), AI layer, API `/api/itam/*` +
  agent gateway `/agent/*`, hash-chained audit.
- `agent/**` — the cross-platform endpoint agent (`itam-agent`) + install scripts.
- `install/**` — systemd unit, nginx locations, installer, `apply_safari_itam.py`.
- `docs/ITAM.md` — operations, sources, agent + least-privilege, vCenter + ManageEngine import, what the customer supplies.
- `engine/discovery/**` + `docs/DISCOVERY.md` — Asset Discovery: scopes with a mandatory pre-scan safety gate, active
  sweep / SNMP and passive AD / vCenter / Hyper-V / CUCM / Azure / AWS / ARP, write-only AES-256-GCM credential vault,
  results review (approve / ignore / merge), one-click SIEM connect + silent-source alerts, rogue-device alerts.
- `ui/itam-module.js` + `ui/discovery-module.js` (+ `.ar.json`, `-nav.json`) — platform portal pages;
  `ui/INSTALL-PLATFORM.md` — install / nginx / portal steps for the platform server.

Node >= 20, standard library only, CommonJS.

```
npm test        # node --test tests/*.test.js
npm start       # node engine/main.js   (reads /etc/sentra-itam/config.json + secrets.json)
```

The portal pages in `ui/**` are strict ES5 modules applied to the built portal with `as_addmod.py` (see
`ui/INSTALL-PLATFORM.md`).
See `ARCH.md` for the authoritative contract and `docs/ITAM.md` for operations.
