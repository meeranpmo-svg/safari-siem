// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * One-way audio troubleshooter - "I hear them, they don't hear me" on Cisco IP phones. The call is set up (signalling to the
 * call manager works) but the voice (RTP, UDP 16384-32767, phone to phone or phone to gateway) is lost in one direction.
 * Deterministic and read-only:
 *   diagnose(deps, { a, b, hear: 'a_cannot_hear_b'|'b_cannot_hear_a'|'both'|'unsure', minutes?, refresh? })
 *     a = the phone that reports the problem (IP or voice subnet), b = the far end (phone, voice gateway, subnet)
 *     deps: { inventory, poller, evidence, factsFor?(dev) }
 *   → { a, b, hear, lost, scope, path[], checks[], causes[], manual[], summary }
 * Evidence, in the order a voice engineer would look:
 *   1. the voice sessions between a and b on every firewall that logged them, per DIRECTION (evidence.voiceFlows):
 *      denied, sessions with no reply (one-way), NAT, which firewall saw which direction (asymmetric path)
 *   2. the signalling side a uses (SIP 5060/5061 or SCCP 2000) and which firewall it crosses
 *   3. the firewalls' own settings (fwfacts.js): SIP ALG (FortiGate default-voip-alg-mode, sip session helper, VoIP profiles;
 *      PAN-OS alg-override), policies / rules that allow the RTP range in one direction only
 *   4. WAN / tunnel / SD-WAN (Silver Peak) events and firewall CPU / memory in the window
 * "a cannot hear b" means the audio from b to a is lost. Every cause carries its evidence and the fix per device with its
 * rollback, for a person to run or to propose as a change plan another engineer approves. Nothing here changes a device.
 */
const FW = new Set(['fortigate', 'paloalto']);
const WAN = new Set(['fortigate', 'paloalto', 'edgeconnect', 'silverpeak']);
const DENY = /^(deny|denied|drop|dropped|block|blocked|reject|reset-both|policy-deny)$/;
const RTP_LO = 16384, RTP_HI = 32767;
const pct = (x, y) => (y ? Math.round((100 * x) / y) : 0);

// does a FortiGate service cover the Cisco RTP range? ALL / ALL_UDP or a custom service whose UDP range spans 16384-32767
function coversRtp(names, services) {
  const byName = new Map((services || []).map((s) => [s.name, s]));
  return (names || []).some((n) => {
    if (n === 'ALL' || n === 'ALL_UDP') return true;
    const s = byName.get(n); if (!s || !s.udp) return false;
    return s.udp.split(/\s+/).some((r) => { const m = /^(\d+)(?:-(\d+))?/.exec(r); if (!m) return false; const lo = +m[1], hi = m[2] ? +m[2] : lo; return lo <= RTP_LO && hi >= RTP_HI; });
  });
}
// interface / zone pairs that allow voice in one direction only
function oneDirection(pairs) { const set = new Set(pairs.map((p) => p.from + '>' + p.to)); return pairs.filter((p) => p.from !== p.to && !set.has(p.to + '>' + p.from)); }
function rtpPairs(dev, f) {
  if (!f) return null;
  if (dev.vendor === 'fortigate') {
    if (!f.policies) return null;
    return f.policies.filter((p) => p.status !== 'disable' && p.action === 'accept' && coversRtp(p.service, f.services)).flatMap((p) => p.srcintf.flatMap((s) => p.dstintf.map((d) => ({ from: s, to: d, rule: String(p.id) + (p.name ? ' (' + p.name + ')' : '') }))));
  }
  if (!f.rules || !f.rules.items) return null;
  return f.rules.items.filter((r) => !r.disabled && r.action === 'allow' && (r.application.some((a) => /^(any|rtp|rtcp|rtp-base|skinny|sip)$/.test(a)) || r.service.includes('any')))
    .flatMap((r) => r.from.flatMap((s) => r.to.map((d) => ({ from: s, to: d, rule: r.name }))));
}
function algState(dev, f) {
  if (!f) return null;
  if (dev.vendor === 'fortigate') {
    const s = f.settings || {}, helpers = (f.session_helper || []).filter((h) => h.name === 'sip');
    const profiles = (f.policies || []).filter((p) => p.voip_profile).map((p) => p.id);
    const on = s.default_voip_alg_mode !== 'kernel-helper-based' || helpers.length > 0;
    return { on, read: !!f.settings, detail: `default-voip-alg-mode ${s.default_voip_alg_mode || 'not read'}; sip session helper ${f.session_helper ? (helpers.length ? 'present (id ' + helpers.map((h) => h.id).join(', ') + ', port ' + helpers.map((h) => h.port).join(', ') + ')' : 'none') : 'not read'}${profiles.length ? '; VoIP profile on policy ' + profiles.slice(0, 5).join(', ') : ''}`, helpers, profiles };
  }
  if (!f.alg) return { on: true, read: false, detail: 'ALG overrides not read (SIP ALG is on by default in PAN-OS)' };
  const off = f.alg.some((x) => x.name === 'sip' && x.disabled);
  return { on: !off, read: true, detail: off ? 'SIP ALG disabled (alg-override sip)' : 'SIP ALG on (PAN-OS default)' };
}

async function diagnose(deps, input = {}) {
  const { inventory, poller, evidence } = deps;
  const a = String(input.a || ''), b = String(input.b || ''), hear = input.hear || 'unsure', win = Math.max(15, Math.min(1440, Number(input.minutes) || 120));
  const checks = [], causes = [];
  const add = (name, status, detail, ev) => checks.push({ name, status, detail, evidence: (ev || []).filter(Boolean).slice(0, 12) });
  const cause = (c) => causes.push(Object.assign({ evidence: [], steps: [] }, c, { evidence: (c.evidence || []).filter(Boolean).slice(0, 8) }));
  // which audio is lost, in the direction of travel
  const lost = hear === 'a_cannot_hear_b' ? 'b_to_a' : hear === 'b_cannot_hear_a' ? 'a_to_b' : hear === 'both' ? 'both' : null;
  const arrow = (d) => (d === 'a_to_b' ? `${a} → ${b}` : `${b} → ${a}`);

  const devs = inventory.list(), fws = devs.filter((d) => FW.has(String(d.vendor || '').toLowerCase()));
  const factsOf = {};
  for (const d of fws) {
    let f = null;
    if (input.refresh && deps.factsFor) { try { f = await deps.factsFor(d); } catch (e) { f = null; } }   // a failed live read falls back to the last snapshot below
    if (!f) { const s = poller.snapshot(d.id); f = (s && s.security && s.security.facts) || null; }
    factsOf[d.id] = f;
  }
  const byIp = (ip) => fws.find((x) => x.ip === ip) || null;
  if (!fws.length) add('Firewalls known to the platform', 'fail', 'no FortiGate or Palo Alto in Network Engineer → Devices', []);
  else add('Firewalls known to the platform', 'ok', `${fws.length} firewall(s)`, fws.map((d) => `${d.name} (${d.vendor}) ${d.ip}${factsOf[d.id] ? '' : ' - settings not read yet'}`));

  // 1 - the voice sessions, per direction and firewall
  let rows = null;
  if (evidence && evidence.voiceFlows) { try { rows = await evidence.voiceFlows({ a, b, minutes: win }); } catch (e) { add('Voice sessions in the firewall logs', 'skip', 'log search unavailable: ' + e.message, []); } }
  else add('Voice sessions in the firewall logs', 'skip', 'log search unavailable', []);
  const rtp = (rows || []).filter((r) => r.kind === 'rtp' && (r.direction === 'a_to_b' || r.direction === 'b_to_a'));
  const sig = (rows || []).filter((r) => (r.kind === 'sip' || r.kind === 'sccp') && r.direction !== 'other');
  const dir = { a_to_b: { n: 0, oneway: 0, deny: 0, fw: new Set(), rows: [] }, b_to_a: { n: 0, oneway: 0, deny: 0, fw: new Set(), rows: [] } };
  for (const r of rtp) { const x = dir[r.direction], n = Number(r.sessions) || 0; x.n += n; x.rows.push(r); if (DENY.test(r.action || '')) x.deny += n; else { x.oneway += Number(r.oneway) || 0; x.fw.add(r.firewall_ip); } }
  // audio lost b → a: a's sessions got no reply, or b's packets were denied (and the reverse)
  const loss = { b_to_a: dir.a_to_b.oneway + dir.b_to_a.deny, a_to_b: dir.b_to_a.oneway + dir.a_to_b.deny };
  const total = dir.a_to_b.n + dir.b_to_a.n;
  if (rows) {
    if (!total) add('Voice (RTP) between the two ends', 'warn', `no voice session between ${a} and ${b} logged in the last ${win} min`, ['the call path does not cross a firewall that logs (both ends on the same site / VLAN), or the voice policy does not log - FortiGate: logtraffic all; PAN-OS: Log at Session End']);
    else add('Voice (RTP) between the two ends', loss.a_to_b || loss.b_to_a ? 'fail' : 'ok', `${total} voice session(s) in ${win} min`,
      ['a_to_b', 'b_to_a'].map((d) => `${arrow(d)}: ${dir[d].n} session(s), ${dir[d].deny} denied, ${dir[d].oneway} with no reply${dir[d].fw.size ? ' - seen on ' + [...dir[d].fw].map((ip) => (byIp(ip) || { name: ip }).name).join(', ') : ''}`)
        .concat(rtp.slice(0, 6).map((r) => `${r.firewall}: ${r.sessions}× ${r.action || '?'} e.g. ${r.sample}${r.nat_ip ? ' (NAT ' + r.nat_ip + ')' : ''}`)));
  }

  // 2 - signalling of side a
  const sigKinds = [...new Set(sig.map((r) => r.kind))];
  if (rows) add('Signalling of ' + a, sig.length ? (sig.some((r) => DENY.test(r.action || '')) ? 'warn' : 'ok') : 'skip', sig.length ? `${sigKinds.map((k) => (k === 'sccp' ? 'SCCP (Skinny, TCP 2000)' : 'SIP (5060/5061)')).join(' and ')} to ${[...new Set(sig.map((r) => r.peer))].slice(0, 3).join(', ')}` : 'no SIP / SCCP from this phone crossed a logging firewall (the call manager is on the same side)',
    sig.slice(0, 5).map((r) => `${r.firewall}: ${r.kind} ${r.sessions}× ${r.action || '?'} e.g. ${r.sample}${r.nat_ip ? ' (NAT ' + r.nat_ip + ')' : ''}`));

  const fgDevs = fws.filter((d) => d.vendor === 'fortigate'), paDevs = fws.filter((d) => d.vendor === 'paloalto');
  const sawFw = new Set(rtp.concat(sig).map((r) => r.firewall_ip));
  const onPath = fws.filter((d) => sawFw.has(d.ip));
  const scopeFw = onPath.length ? onPath : fws;

  // a voice policy or rule denies one direction
  if (dir.a_to_b.deny || dir.b_to_a.deny) {
    const d0 = dir.b_to_a.deny >= dir.a_to_b.deny ? 'b_to_a' : 'a_to_b', r0 = dir[d0].rows.find((r) => DENY.test(r.action || '')), dev = byIp(r0.firewall_ip);
    const from = d0 === 'a_to_b' ? a : b, to = d0 === 'a_to_b' ? b : a;
    cause({ id: 'rtp-deny', title: `${dev ? dev.name : 'A firewall'} blocks the voice from ${from} to ${to}`, confidence: 'high', w: 95, devices: dev ? [dev.id] : [],
      explanation: `The call is set up, but the voice packets ${arrow(d0)} are refused by policy, so ${d0 === 'b_to_a' ? a + ' cannot hear ' + b : b + ' cannot hear ' + a}. Cisco phones send and receive RTP on UDP ${RTP_LO}-${RTP_HI}; the policy must allow that range in BOTH directions between the voice networks (or a SIP ALG must open it - which is often what breaks it).`,
      evidence: ['a_to_b', 'b_to_a'].filter((d) => dir[d].deny).map((d) => `${arrow(d)}: ${dir[d].deny} denied`).concat(dir[d0].rows.filter((r) => DENY.test(r.action || '')).slice(0, 3).map((r) => `${r.firewall}: ${r.sessions}× ${r.action} e.g. ${r.sample}`)),
      steps: dev && dev.vendor === 'paloalto' ? [{ vendor: 'paloalto', device: dev.id, title: 'Allow RTP / RTCP between the voice networks in both directions', risk: 'medium',
        commands: [`set rulebase security rules SENTRA-VOICE-RTP from [ <zone-of-${a}> <zone-of-${b}> ] to [ <zone-of-${a}> <zone-of-${b}> ] source [ ${a} ${b} ] destination [ ${a} ${b} ] application [ rtp rtcp ] service any action allow log-end yes`, 'move rulebase security rules SENTRA-VOICE-RTP top', 'commit'],
        rollback: ['delete rulebase security rules SENTRA-VOICE-RTP', 'commit'] }]
        : [{ vendor: 'fortigate', device: dev && dev.id, title: 'Allow Cisco RTP (UDP 16384-32767) between the voice networks in both directions', risk: 'medium',
          commands: ['config firewall service custom', '    edit "CISCO-RTP"', `        set udp-portrange ${RTP_LO}-${RTP_HI}`, '    next', 'end',
            'config firewall policy', '    edit 0', '        set name "SENTRA-VOICE-RTP-A-B"', `        set srcintf "<interface-of-${a}>"`, `        set dstintf "<interface-of-${b}>"`, `        set srcaddr "<address-${a}>"`, `        set dstaddr "<address-${b}>"`, '        set service "CISCO-RTP"', '        set action accept', '        set schedule "always"', '        set logtraffic all', '    next',
            '    edit 0', '        set name "SENTRA-VOICE-RTP-B-A"', `        set srcintf "<interface-of-${b}>"`, `        set dstintf "<interface-of-${a}>"`, `        set srcaddr "<address-${b}>"`, `        set dstaddr "<address-${a}>"`, '        set service "CISCO-RTP"', '        set action accept', '        set schedule "always"', '        set logtraffic all', '    next', 'end', '# move both above the policy that denies: config firewall policy / move <id> before <deny-id>'],
          rollback: ['config firewall policy', '    delete <SENTRA-VOICE-RTP-A-B id>', '    delete <SENTRA-VOICE-RTP-B-A id>', 'end', 'config firewall service custom', '    delete "CISCO-RTP"', 'end'] }] });
  }

  // one direction never comes back
  const oneSide = ['b_to_a', 'a_to_b'].filter((d) => loss[d] - dir[d].deny >= 2 && pct(loss[d], total) >= 25);
  const asym = dir.a_to_b.fw.size && dir.b_to_a.fw.size && ![...dir.a_to_b.fw].some((ip) => dir.b_to_a.fw.has(ip));
  if (asym) {
    const names = (s) => [...s].map((ip) => (byIp(ip) || { name: ip }).name).join(', ');
    cause({ id: 'asymmetric', title: 'The two directions of the call take different paths (asymmetric routing)', confidence: 'high', w: 92, devices: scopeFw.map((d) => d.id),
      explanation: `The voice ${arrow('a_to_b')} crosses ${names(dir.a_to_b.fw)}, the voice ${arrow('b_to_a')} crosses ${names(dir.b_to_a.fw)}. A stateful firewall that sees only one half of the UDP conversation drops the other half after its timer, or never matches the reverse pinhole a SIP ALG opened - so one side hears nothing. Typical cause: the voice VLAN's gateway or the SD-WAN (Silver Peak) sends the return traffic over another link.`,
      evidence: [`${arrow('a_to_b')}: seen on ${names(dir.a_to_b.fw)}`, `${arrow('b_to_a')}: seen on ${names(dir.b_to_a.fw)}`],
      steps: [{ vendor: 'routing', title: 'Make both directions follow the same firewall (the real fix)', risk: 'medium',
        commands: [`# on the router / core switch of the ${b} side: route ${a} back through the firewall that carries ${a} → ${b}`, `ip route ${a.includes('/') ? a.replace(/\/\d+$/, '') + ' <mask>' : a + ' 255.255.255.255'} <inside-ip-of-that-firewall>`, '# SD-WAN (Silver Peak): put the voice traffic on ONE overlay / business-intent policy for both directions (Orchestrator → Business Intent Overlays → Voice), not "best path per packet"'],
        rollback: [`no ip route ${a.includes('/') ? a.replace(/\/\d+$/, '') + ' <mask>' : a + ' 255.255.255.255'} <inside-ip-of-that-firewall>`] }] });
  }

  // SIP ALG
  const alg = scopeFw.map((d) => ({ d, s: algState(d, factsOf[d.id]) })).filter((x) => x.s);
  if (fws.length) add('SIP ALG on the firewalls', alg.some((x) => x.s.on) ? 'warn' : alg.length ? 'ok' : 'skip', alg.length ? (alg.some((x) => x.s.on) ? 'SIP ALG is on on ' + alg.filter((x) => x.s.on).map((x) => x.d.name).join(', ') : 'SIP ALG is off') : 'settings not read yet', alg.map((x) => `${x.d.name}: ${x.s.detail}`));
  const sipCrosses = sig.some((r) => r.kind === 'sip');
  const algOn = alg.filter((x) => x.s.on && (!sig.length || sig.some((r) => r.kind === 'sip' && r.firewall_ip === x.d.ip)));
  const natSeen = rtp.concat(sig).filter((r) => r.nat_ip);
  if (algOn.length && (sipCrosses || (!sig.length && (oneSide.length || natSeen.length)))) {
    const strong = oneSide.length > 0 || natSeen.length > 0;
    const steps = [];
    for (const x of algOn) {
      if (x.d.vendor === 'fortigate') steps.push({ vendor: 'fortigate', device: x.d.id, title: `Turn the SIP ALG off on ${x.d.name}`, risk: 'medium',
        commands: ['config system settings', '    set default-voip-alg-mode kernel-helper-based', 'end'].concat(x.s.helpers && x.s.helpers.length ? ['config system session-helper'].concat(x.s.helpers.map((h) => `    delete ${h.id}`), ['end']) : [], x.s.profiles && x.s.profiles.length ? ['config firewall policy'].concat(x.s.profiles.slice(0, 10).flatMap((id) => [`    edit ${id}`, '        unset voip-profile', '    next']), ['end']) : [], ['# then clear the SIP sessions so calls re-establish without the ALG: diagnose sys session filter dport 5060 / diagnose sys session clear']),
        rollback: ['config system settings', '    set default-voip-alg-mode proxy-based', 'end'].concat(x.s.helpers && x.s.helpers.length ? ['config system session-helper'].concat(x.s.helpers.flatMap((h) => [`    edit ${h.id}`, '        set name sip', '        set protocol 17', `        set port ${h.port || 5060}`, '    next']), ['end']) : []) });
      else steps.push({ vendor: 'paloalto', device: x.d.id, title: `Turn the SIP ALG off on ${x.d.name}`, risk: 'medium', commands: ['set shared alg-override application sip alg-disabled yes', 'commit'], rollback: ['delete shared alg-override application sip', 'commit'] });
    }
    cause({ id: 'sip-alg', title: 'The firewall\'s SIP ALG rewrites the call setup', confidence: strong ? 'high' : 'medium', w: strong ? 88 : 45, devices: algOn.map((x) => x.d.id),
      explanation: 'A SIP ALG reads the call setup and rewrites the addresses and ports the phones announce for the voice, and opens a pinhole for them. With Cisco call managers it often writes the wrong address (or the NAT address one way only), so the voice in one direction is sent to an address that does not exist or arrives at a closed pinhole. Cisco and Fortinet both recommend turning the SIP ALG off when the call manager handles the calls; then the policies must allow UDP 16384-32767 both ways.',
      evidence: algOn.map((x) => `${x.d.name}: ${x.s.detail}`).concat(sipCrosses ? [`${a} signals with SIP through the firewall`] : [], natSeen.slice(0, 3).map((r) => `${r.firewall}: NAT ${r.nat_ip} on ${r.kind} e.g. ${r.sample}`), oneSide.map((d) => `audio ${arrow(d)} lost on ${loss[d]} of ${total} sessions`)),
      steps });
  } else if (algOn.length && sigKinds.length === 1 && sigKinds[0] === 'sccp') {
    add('SIP ALG and this phone', 'ok', `${a} uses SCCP (Skinny), which a SIP ALG does not touch - the ALG is not the cause for this phone`, []);
  }

  // NAT on the voice
  if (natSeen.filter((r) => r.kind === 'rtp').length && !algOn.length) {
    const r0 = natSeen.find((r) => r.kind === 'rtp'), dev = byIp(r0.firewall_ip);
    cause({ id: 'nat', title: `${dev ? dev.name : 'A firewall'} translates the voice addresses (NAT) between the two ends`, confidence: oneSide.length ? 'high' : 'medium', w: oneSide.length ? 80 : 40, devices: dev ? [dev.id] : [],
      explanation: 'The phones tell each other their own (inside) address in the call setup. When a firewall translates the voice between two internal networks, the far end sends its audio to the address it was told, which the firewall does not translate back - one side hears nothing. Voice between internal networks and across the VPN must not be NATed.',
      evidence: natSeen.filter((r) => r.kind === 'rtp').slice(0, 4).map((r) => `${r.firewall}: ${r.sample} translated to ${r.nat_ip}`),
      steps: dev && dev.vendor === 'paloalto' ? [{ vendor: 'paloalto', device: dev.id, title: 'No NAT for voice between the internal networks', risk: 'medium', commands: [`set rulebase nat rules SENTRA-VOICE-NO-NAT from any to any source [ ${a} ${b} ] destination [ ${a} ${b} ] service any`, 'move rulebase nat rules SENTRA-VOICE-NO-NAT top', 'commit'], rollback: ['delete rulebase nat rules SENTRA-VOICE-NO-NAT', 'commit'] }]
        : [{ vendor: 'fortigate', device: dev && dev.id, title: 'No NAT on the voice policy between the internal networks', risk: 'medium', commands: ['config firewall policy', '    edit <voice-policy-id>', '        set nat disable', '    next', 'end'], rollback: ['config firewall policy', '    edit <voice-policy-id>', '        set nat enable', '    next', 'end'] }] });
  }

  // policies that allow the RTP range one way only
  const pairs = scopeFw.map((d) => ({ d, p: rtpPairs(d, factsOf[d.id]) })).filter((x) => x.p);
  const single = pairs.map((x) => ({ d: x.d, miss: oneDirection(x.p) })).filter((x) => x.miss.length);
  if (fws.length) add('Policies that allow the voice range', single.length ? 'warn' : pairs.length ? 'ok' : 'skip', pairs.length ? (single.length ? 'some interface / zone pairs allow voice one way only' : 'every pair that allows voice also allows the way back') : 'policies not read yet',
    pairs.map((x) => `${x.d.name}: ${x.p.length} interface/zone pair(s) allow UDP ${RTP_LO}-${RTP_HI}`).concat(single.flatMap((x) => x.miss.slice(0, 4).map((m) => `${x.d.name}: ${m.from} → ${m.to} allowed by ${m.rule}, nothing allows ${m.to} → ${m.from}`))));
  if (single.length && (oneSide.length || dir.a_to_b.deny || dir.b_to_a.deny || !total)) {
    const x = single[0], m = x.miss[0];
    cause({ id: 'policy-one-way', title: `${x.d.name} allows voice ${m.from} → ${m.to} but not back`, confidence: oneSide.length ? 'medium' : 'low', w: oneSide.length ? 70 : 30, devices: single.map((y) => y.d.id),
      explanation: 'Without a SIP ALG opening pinholes, each direction of the voice is a new UDP flow from the far phone and needs its own allow rule. A rule for one direction only gives exactly "I hear them, they don\'t hear me".',
      evidence: single.flatMap((y) => y.miss.slice(0, 3).map((n) => `${y.d.name}: ${n.from} → ${n.to} (${n.rule}); nothing ${n.to} → ${n.from}`)),
      steps: [x.d.vendor === 'fortigate' ? { vendor: 'fortigate', device: x.d.id, title: `Add the way back: ${m.to} → ${m.from}`, risk: 'medium',
        commands: ['config firewall policy', '    edit 0', `        set name "${('SENTRA-VOICE-' + m.to + '-' + m.from).slice(0, 35)}"`, `        set srcintf "${m.to}"`, `        set dstintf "${m.from}"`, '        set srcaddr "<voice-networks>"', '        set dstaddr "<voice-networks>"', '        set service "CISCO-RTP"', '        set action accept', '        set schedule "always"', '        set logtraffic all', '    next', 'end'],
        rollback: ['config firewall policy', '    delete <new-id>', 'end'] }
        : { vendor: 'paloalto', device: x.d.id, title: `Add the way back: ${m.to} → ${m.from}`, risk: 'medium', commands: [`set rulebase security rules SENTRA-VOICE-RETURN from ${m.to} to ${m.from} source <voice-networks> destination <voice-networks> application [ rtp rtcp ] service any action allow log-end yes`, 'commit'], rollback: ['delete rulebase security rules SENTRA-VOICE-RETURN', 'commit'] }] });
  }

  // generic one-way with no firewall-side explanation: the return route
  if (oneSide.length && !causes.some((c) => ['asymmetric', 'sip-alg', 'nat', 'policy-one-way'].includes(c.id))) {
    const d = oneSide[0];
    cause({ id: 'return-path', title: `The voice ${arrow(d)} does not come back through the firewall`, confidence: 'medium', w: 65, devices: scopeFw.map((x) => x.id),
      explanation: `Sessions ${d === 'b_to_a' ? 'from ' + a : 'from ' + b} get no reply: the other end's audio leaves by another route, is dropped before the firewall, or is sent to a wrong address (call manager media resource / gateway binding). Check the route back from the far side and the gateway's media binding.`,
      evidence: [`${loss[d]} of ${total} voice sessions with no reply`],
      steps: [{ vendor: 'routing', title: 'Check the route back and the gateway media binding', risk: 'low', commands: [`# on the far side's router / L3 switch: show ip route ${a.replace(/\/\d+$/, '')}`, `# on a Cisco voice gateway / CUBE: the voice must leave from the interface the far end can reach`, 'voice service voip', ' sip', '  bind control source-interface <inside-interface>', '  bind media source-interface <inside-interface>'], rollback: ['voice service voip', ' sip', '  no bind media source-interface <inside-interface>'] }] });
  }

  // no voice crossed a logging firewall
  if (rows && !total && fws.length) cause({ id: 'no-logs', title: 'No voice between the two ends was logged by a firewall', confidence: 'low', w: 20,
    explanation: 'Either both ends are on the same site (then the firewalls are not the cause - look at the voice VLAN gateway and the call manager\'s media resources, see the checks below), or the voice policy does not log. Turn logging on for the voice policies and run the diagnosis again during a bad call.',
    evidence: [`0 voice sessions between ${a} and ${b} in ${win} min`],
    steps: [{ vendor: 'fortigate', title: 'Log the voice policies', risk: 'low', commands: ['config firewall policy', '    edit <voice-policy-id>', '        set logtraffic all', '    next', 'end'], rollback: ['config firewall policy', '    edit <voice-policy-id>', '        set logtraffic utm', '    next', 'end'] },
      { vendor: 'paloalto', title: 'Log voice at session end', risk: 'low', commands: ['set rulebase security rules <voice-rule> log-end yes', 'commit'], rollback: ['set rulebase security rules <voice-rule> log-end no', 'commit'] }] });

  // WAN / tunnel / SD-WAN events and firewall load
  const wan = devs.filter((d) => WAN.has(String(d.vendor || '').toLowerCase()));
  if (evidence && evidence.deviceEvents && wan.length) {
    try {
      const ev = []; for (const d of wan.slice(0, 8)) for (const r of await evidence.deviceEvents({ ip: d.ip, host: d.name, minutes: win, limit: 10, kind: 'link' })) ev.push(`${r.ts} ${d.name}: ${r.message}`);
      add('WAN / tunnel / SD-WAN events', ev.length ? 'warn' : 'ok', ev.length ? `${ev.length} event(s) in ${win} min` : `none in ${win} min`, ev.slice(0, 8));
      const flaps = ev.filter((e) => /tunnel|ipsec|overlay|path|down/i.test(e));
      if (flaps.length >= 2) cause({ id: 'wan-flap', title: 'The WAN / VPN path changed during the window', confidence: 'medium', w: 50, devices: wan.map((d) => d.id),
        explanation: 'When a tunnel or SD-WAN path goes down and comes back, the voice in flight may continue on a path where the firewall has no session for it - one direction stops until the call is redialled. Pin voice to one overlay and keep sessions on failover.',
        evidence: flaps.slice(0, 5),
        steps: [{ vendor: 'routing', title: 'Keep voice on one path and keep sessions on failover', risk: 'low', commands: ['# Silver Peak Orchestrator: Business Intent Overlays → Voice → link bonding "High availability", path conditioning on', '# FortiGate SD-WAN: config system sdwan / config service / edit <voice-rule> / set hold-down-time 20 / set dscp-forward enable'], rollback: [] }] });
    } catch (e) { add('WAN / tunnel / SD-WAN events', 'skip', 'log search unavailable: ' + e.message, []); }
  }
  const hot = scopeFw.map((d) => ({ d, s: (poller.snapshot(d.id) || {}).system || {} })).filter((x) => x.s.mem_pct >= 88 || x.s.cpu_pct >= 90);
  if (fws.length) add('Firewall CPU / memory', hot.length ? 'fail' : 'ok', hot.length ? `${hot.length} firewall(s) under pressure` : 'within limits', scopeFw.map((d) => { const s = (poller.snapshot(d.id) || {}).system || {}; return `${d.name}: CPU ${s.cpu_pct == null ? '?' : s.cpu_pct + ' %'}, memory ${s.mem_pct == null ? '?' : s.mem_pct + ' %'}`; }));
  for (const x of hot) cause({ id: 'resources', title: `${x.d.name} is under resource pressure`, confidence: 'medium', w: 55, devices: [x.d.id], explanation: 'A firewall near its CPU / memory limit (FortiGate conserve mode at ~88 % memory) drops or delays UDP first - voice breaks before anything else.', evidence: [`CPU ${x.s.cpu_pct} %, memory ${x.s.mem_pct} %`], steps: [] });

  // the checks only a person can do on the phone and the call manager
  const manual = [
    { where: 'Phone', what: `During a bad call on ${a}: Settings (or the ? button twice) → Status → Call Statistics.`, why: 'Rcvr Packets staying at 0 while Sender Packets grow = the audio from the far end never arrives (network path). Both growing = the problem is the handset / headset or a codec / transcoder.' },
    { where: 'Phone', what: 'Settings → Admin settings → Network setup: check the IP address, subnet mask and default router of the voice VLAN.', why: 'A wrong default router on the phone sends its audio nowhere while calls still set up through the call manager on the same VLAN.' },
    { where: 'Call manager (CUCM)', what: 'Call → the device pool / region of both phones: is a Media Termination Point, transcoder or conference bridge inserted (MTP Required on the SIP trunk, codec mismatch between regions)?', why: 'The audio then flows phone → MTP → phone; if the MTP\'s IP is not reachable from one side, that side hears nothing.' },
    { where: 'Voice gateway / CUBE', what: 'show running-config | section voice service voip → bind control / bind media source-interface; show call active voice brief during the call.', why: 'A gateway that sends media from the wrong interface gives one-way audio on PSTN and remote-site calls only.' },
  ];

  causes.sort((x, y) => y.w - x.w);
  const ranked = causes.map((c, i) => ({ rank: i + 1, id: c.id, title: c.title, confidence: c.confidence, explanation: c.explanation, evidence: c.evidence, devices: c.devices || [], steps: c.steps.map((s) => ({ vendor: s.vendor, device: s.device || null, title: s.title, risk: s.risk || 'low', commands: s.commands || [], rollback: s.rollback || [] })) }));
  const path = [{ hop: 'Phone ' + a, detail: hear === 'a_cannot_hear_b' ? 'hears nothing' : hear === 'b_cannot_hear_a' ? 'is not heard' : '' }]
    .concat(onPath.map((d) => ({ hop: d.name, vendor: d.vendor, detail: ['a_to_b', 'b_to_a'].filter((x) => dir[x].fw.has(d.ip)).map((x) => (x === 'a_to_b' ? '→' : '←')).join(' ') || 'signalling only' })), [{ hop: 'Far end ' + b, detail: '' }]);
  const lostTxt = lost === 'b_to_a' ? `the audio ${b} → ${a} is lost` : lost === 'a_to_b' ? `the audio ${a} → ${b} is lost` : lost === 'both' ? 'audio is lost both ways' : '';
  const summary = !fws.length ? 'Add the firewalls in Network Engineer → Devices (read-only API keys) so their logs and settings can be used; meanwhile use the phone and call manager checks below.'
    : ranked.length ? `${lostTxt ? lostTxt[0].toUpperCase() + lostTxt.slice(1) + '. ' : ''}Most likely: ${ranked[0].title}.`
      : rows && !total ? 'No voice between the two ends crossed a logging firewall - reproduce the problem and run again, and use the phone and call manager checks below.'
        : 'No firewall-side cause found in the logs and settings - use the phone and call manager checks below.';
  if (lost && total && !loss[lost === 'both' ? 'a_to_b' : lost] && !(lost === 'both' && loss.b_to_a)) add('What the logs say about the reported direction', 'warn', `the firewalls passed the audio ${lost === 'both' ? 'both ways' : lost === 'b_to_a' ? b + ' → ' + a : a + ' → ' + b} in this window`, ['the loss happens beyond the firewalls (phone VLAN, call manager media resource, gateway) or outside this time window']);
  return { a, b, hear, lost, minutes: win, scope: { firewalls: fws.map((d) => ({ id: d.id, name: d.name, vendor: d.vendor, ip: d.ip, facts_at: factsOf[d.id] ? factsOf[d.id].at : null, on_path: sawFw.has(d.ip) })) }, path, checks, causes: ranked, manual, summary };
}

module.exports = { diagnose, coversRtp, oneDirection, algState, RTP_LO, RTP_HI };
