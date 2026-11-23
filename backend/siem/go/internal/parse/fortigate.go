// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

package parse

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"sentra-siem/go/internal/jsrt"
)

// Port of parse/fortigate.js: FortiOS 6.x/7.x key=value logs - traffic, utm (ips / virus / webfilter / app-ctrl /
// dns / anomaly), event (vpn, admin login/logout, config changes, user auth).

var fgStart = regexp.MustCompile(`(?:^|[` + jsrt.WS + `])(?:date|logver|devname|logid|eventtime)=`)

var fgConsumed = map[string]bool{"date": true, "time": true, "eventtime": true, "tz": true, "devname": true, "logid": true,
	"level": true, "srcip": true, "dstip": true, "srcport": true, "dstport": true, "proto": true, "user": true, "msg": true}

var blockWords = map[string]bool{"deny": true, "denied": true, "block": true, "blocked": true, "drop": true, "dropped": true,
	"reject": true, "reset": true, "clear_session": true, "drop_session": true, "close_session": true, "server-rst-blocked": true}
var allowWords = map[string]bool{"accept": true, "allow": true, "allowed": true, "pass": true, "passthrough": true, "permit": true,
	"close": true, "timeout": true, "client-rst": true, "server-rst": true, "start": true, "ip-conn": true, "monitored": true, "detected": true}

var (
	reTz       = regexp.MustCompile(`^[+-]\d{2}:?\d{2}$`)
	reAllDig   = regexp.MustCompile(`^\d+$`)
	reVpnFail  = regexp.MustCompile(`login-fail|auth-fail|ssl-login-fail`)
	reCfgAct   = regexp.MustCompile(`^(edit|add|delete|set|unset|move|config)$`)
	reParenIP  = regexp.MustCompile(`\(([^)]+)\)`)
	reSniffLog = regexp.MustCompile(`\blogid="?\d+`)
	reSniffTyp = regexp.MustCompile(`\btype="?\w+`)
)

// Raw is a parser's event before the router merges and finalises it (numbers stay float64: NaN and fractions are
// JavaScript values until finalise truncates them).
type Raw struct {
	SrcType, Host, SrcIP, DstIP, Proto, User, Domain, EventCode         string
	Category, Action, Outcome, Message, Hash, URL, HTTPMethod, DNSQuery string
	Ts, SrcPort, DstPort, Severity                                      float64
	HashSet, URLSet, MethodSet, DNSSet                                  bool
	Tags                                                                []string
	Fields                                                              *jsrt.OMap
}

func fgTs(kv *jsrt.OMap, off int, now float64) (float64, bool) {
	if et := kv.S("eventtime"); allDigits(et) {
		return epochToMs(jsrt.Number(et)), true
	}
	d, t := kv.S("date"), kv.S("time")
	if d != "" && t != "" {
		z := kv.S("tz")
		s := d + "T" + t
		if z != "" && reTz.MatchString(z) {
			s += z
		}
		return parseTime(s, off, now)
	}
	return 0, true
}

var fgKeys = []string{"date=", "logver=", "devname=", "logid=", "eventtime="}

// fgFind is body.search(START_RE): the first place one of the keys starts the line or follows a JavaScript space
// (the index includes that space). Plain scanning; fgStart stays the reference the test compares it with.
func fgFind(body string) int {
	best := -1
	for _, k := range fgKeys {
		off := 0
		for {
			j := strings.Index(body[off:], k)
			if j < 0 {
				break
			}
			j += off
			if j == 0 {
				if best < 0 || 0 < best {
					best = 0
				}
				break
			}
			r, w := utf8.DecodeLastRuneInString(body[:j])
			if jsrt.IsWS(r) {
				if best < 0 || j-w < best {
					best = j - w
				}
				break
			}
			off = j + 1
		}
	}
	return best
}

func verdict(a string) string {
	v := jsrt.Lower(a)
	if blockWords[v] {
		return "blocked"
	}
	if allowWords[v] {
		return "allowed"
	}
	return ""
}

// FortiSniff is fortigate.sniff.
func FortiSniff(body string) bool {
	return fgStart.MatchString(body) && reSniffLog.MatchString(body) && reSniffTyp.MatchString(body)
}

// Fortigate is fortigate.parse(body, meta). nil = not a FortiGate line; ok=false = hand back (a timestamp only
// Date.parse reads).
func Fortigate(body string, off int, now float64) (*Raw, bool) {
	at := fgFind(body)
	if at < 0 {
		return nil, true
	}
	kv := parseKV(body[at:])
	if kv.S("logid") == "" && kv.S("devid") == "" && kv.S("devname") == "" {
		return nil, true
	}
	if kv.S("type") == "" && kv.S("subtype") == "" {
		return nil, true
	}
	typ := jsrt.Lower(kv.S("type"))
	sub := jsrt.Lower(kv.S("subtype"))
	act := jsrt.Lower(kv.S("action"))
	user, domain := splitUser(or(kv.S("user"), kv.S("srcuser"), kv.S("unauthuser")))
	ts, ok := fgTs(kv, off, now)
	if !ok {
		return nil, false
	}
	ev := &Raw{SrcType: "fortigate", Ts: ts, Host: clean(kv.S("devname")),
		SrcIP: ipOrEmpty(kv.S("srcip")), DstIP: ipOrEmpty(kv.S("dstip")), SrcPort: toInt(kv.S("srcport")), DstPort: toInt(kv.S("dstport")),
		Proto: protoName(kv.S("proto")), User: user, Domain: domain, EventCode: kv.S("logid"),
		Severity: sevFromName(kv.S("level"), 0), Category: "network", Action: "event", Outcome: "unknown",
		Message: or(kv.S("msg"), kv.S("logdesc"), jsrt.Trim(typ+"/"+sub+" "+act)), Tags: []string{}, Fields: jsrt.NewOMap()}
	kv.Each(func(k, v string) {
		if !fgConsumed[k] && v != "" && v != "N/A" {
			ev.Fields.Set(k, v)
		}
	})
	if lv := kv.S("level"); lv != "" {
		ev.Fields.Set("fg_level", lv)
	}

	switch typ {
	case "traffic":
		vd := verdict(act)
		if vd == "" {
			if kv.S("policyid") == "0" {
				vd = "blocked"
			} else {
				vd = "allowed"
			}
		}
		ev.Action = vd
		if vd == "blocked" {
			ev.Outcome = "failure"
		} else {
			ev.Outcome = "success"
		}
		if kv.S("msg") == "" && kv.S("logdesc") == "" {
			ev.Message = jsrt.Trim(sub + " " + or(act, vd) + " " + kv.S("srcip") + ":" + kv.S("srcport") + " → " + kv.S("dstip") + ":" + kv.S("dstport") + " " + kv.S("service"))
		}
	case "utm":
		vd := verdict(act)
		if vd != "" {
			if vd == "blocked" {
				ev.Outcome = "failure"
			} else {
				ev.Outcome = "success"
			}
		}
		if cl := kv.S("crlevel"); cl != "" {
			ev.Severity = jsMax(ev.Severity, sevFromName(cl, 0))
		}
		switch {
		case sub == "ips" || sub == "anomaly":
			ev.Action = "ips-detection"
			ev.Severity = jsMax(ev.Severity, sevFromName(kv.S("severity"), 2))
			if a := kv.S("attack"); a != "" {
				ev.Message = "IPS: " + a
			}
		case sub == "virus" || sub == "av":
			ev.Category = "malware"
			ev.Action = "av-detection"
			ev.Severity = jsMax(ev.Severity, 3)
			ev.Hash, ev.HashSet = clean(or(kv.S("filehash"), kv.S("analyticscksum"))), true
			if u := kv.S("url"); u != "" {
				ev.URL, ev.URLSet = kv.S("hostname")+u, true
			}
			if vi := kv.S("virus"); vi != "" {
				ev.Message = jsrt.Trim("AV: " + vi + " in " + or(kv.S("filename"), kv.S("url")))
			}
		case sub == "webfilter":
			ev.Category = "web"
			ev.Action = or(vd, "allowed")
			ev.URL, ev.URLSet = kv.S("hostname")+kv.S("url"), true
			if m := kv.S("method"); m != "" {
				ev.HTTPMethod, ev.MethodSet = jsrt.Upper(m), true
			}
		case sub == "dns":
			ev.Category = "dns"
			if vd == "blocked" {
				ev.Action = "blocked"
			} else {
				ev.Action = "dns-query"
			}
			ev.DNSQuery, ev.DNSSet = jsrt.Lower(clean(kv.S("qname"))), true
		case sub == "app-ctrl" || sub == "application":
			ev.Action = or(vd, "allowed")
		default:
			ev.Action = or(vd, "event")
		}
	case "event":
		ev.Category = "system"
		status := jsrt.Lower(kv.S("status"))
		logdesc := kv.S("logdesc")
		failed := strings.Contains(status, "fail") || strings.Contains(act, "fail") || jsrt.ContainsFold(logdesc, "fail")
		switch {
		case sub == "vpn":
			ev.Tags = append(ev.Tags, "vpn")
			switch {
			case reVpnFail.MatchString(act) || (strings.Contains(act, "login") && failed):
				ev.Category, ev.Action, ev.Outcome, ev.Severity = "authentication", "logon-failed", "failure", jsMax(ev.Severity, 1)
				ev.Tags = append(ev.Tags, "T1110")
			case act == "tunnel-up" || act == "ssl-login" || act == "login":
				ev.Category, ev.Action, ev.Outcome = "authentication", "logon", "success"
			case act == "tunnel-down" || act == "logout":
				ev.Category, ev.Action, ev.Outcome = "authentication", "logoff", "success"
			default:
				ev.Category, ev.Action = "network", "vpn-event"
			}
			if r := kv.S("remip"); r != "" {
				if ip := ipOrEmpty(r); ip != "" {
					ev.SrcIP = ip
				}
			}
			if ti := kv.S("tunnelip"); ti != "" && ev.DstIP == "" {
				ev.Fields.Set("tunnel_ip", ti)
			}
		case act == "login" || act == "logout" || jsrt.ContainsFold(logdesc, "admin login") || jsrt.ContainsFold(logdesc, "admin logout"):
			ev.Tags = append(ev.Tags, "admin")
			ev.Category = "authentication"
			switch {
			case act == "logout":
				ev.Action, ev.Outcome = "logoff", "success"
			case failed:
				ev.Action, ev.Outcome, ev.Severity = "logon-failed", "failure", jsMax(ev.Severity, 2)
				ev.Tags = append(ev.Tags, "T1110")
			default:
				ev.Action, ev.Outcome = "logon", "success"
			}
			if ui := kv.S("ui"); ev.SrcIP == "" && ui != "" {
				if m := reParenIP.FindStringSubmatch(ui); m != nil {
					ev.SrcIP = ipOrEmpty(m[1])
				}
			}
		case kv.S("cfgpath") != "" || reCfgAct.MatchString(act) || jsrt.ContainsFold(logdesc, "config"):
			if strings.HasPrefix(kv.S("cfgpath"), "firewall") {
				ev.Category = "policy"
			} else {
				ev.Category = "system"
			}
			ev.Action, ev.Outcome, ev.Severity = "config-change", "success", jsMax(ev.Severity, 1)
			ev.Tags = append(ev.Tags, "admin")
		case sub == "user" || act == "authentication":
			ev.Category = "authentication"
			if failed {
				ev.Action, ev.Outcome = "logon-failed", "failure"
			} else {
				ev.Action, ev.Outcome = "logon", "success"
			}
		default:
			ev.Action = or(act, "event")
		}
	default:
		ev.Action = or(verdict(act), "event")
	}
	return ev, true
}
