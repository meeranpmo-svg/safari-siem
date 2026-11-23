// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// TODO (phase 2): LogRhythm alarm collector for the parallel-run comparison (/api/soc/lr-compare).
//   Planned: pull alarms from the LogRhythm Alarm API (base URL + API token from secrets.json) every `lr.poll_s`,
//   or receive them via a LogRhythm SmartResponse/webhook POST, normalise to {lr_alarm_id, rule_name, ts, entities…}
//   and store them in the state journal collection "lr_alarms" for the comparison report.
// For now start() only logs and returns a no-op handle.
function start({ config, log } = {}) {
  const enabled = !!(config && config.lr && config.lr.enabled);
  if (log) log.info(enabled ? 'lr collector: enabled in config but not implemented yet (phase 2) — nothing is pulled' : 'lr collector: disabled (phase 2 TODO)');
  return { stop: async () => {}, stats: () => ({ enabled, implemented: false }) };
}

module.exports = { start };
