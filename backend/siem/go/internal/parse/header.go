// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

package parse

import (
	"regexp"
	"strings"

	"sentra-siem/go/internal/jsrt"
)

// Header is a parsed syslog header (parse/rfc5424.js, parse/rfc3164.js). HasFacility=false is JavaScript's
// facility: undefined (RFC 3164 without a PRI).
type Header struct {
	Format      string
	Pri         int
	Facility    int
	HasFacility bool
	Sev         int
	Ts          float64
	Host        string
	App         string
	Pid         string
	Msgid       string
	Msg         string
}

const nws = `[^` + jsrt.WS + `]+`

var hdr5424 = regexp.MustCompile(`^<(\d{1,3})>1 (` + nws + `) (` + nws + `) (` + nws + `) (` + nws + `) (` + nws + `) `)

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// parseSD walks RFC 5424 structured data and returns the index after it, or -1 if malformed (the values are not
// kept: the FortiGate path never reads them, only the generic fallback - which hands back - would).
func parseSD(line string, i int) int {
	at := func(k int) byte {
		if k < len(line) {
			return line[k]
		}
		return 0
	}
	for at(i) == '[' {
		i++
		for i < len(line) && line[i] != ' ' && line[i] != ']' {
			i++
		}
		for at(i) == ' ' {
			i++
			for i < len(line) && line[i] != '=' && line[i] != ']' {
				i++
			}
			if at(i) != '=' || at(i+1) != '"' {
				return -1
			}
			i += 2
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) && strings.IndexByte(`"\]`, line[i+1]) >= 0 {
					i += 2
					continue
				}
				i++
			}
			if at(i) != '"' {
				return -1
			}
			i++
		}
		if at(i) != ']' {
			return -1
		}
		i++
	}
	return i
}

// parse5424 returns nil when the line is not RFC 5424; ok=false when its timestamp needs Date.parse.
func parse5424(line string) (*Header, bool) {
	if len(line) == 0 || line[0] != '<' {
		return nil, true
	}
	j := 1
	for j < len(line) && j < 4 && line[j] >= '0' && line[j] <= '9' {
		j++
	}
	if j == 1 || j+2 >= len(line) || line[j] != '>' || line[j+1] != '1' || line[j+2] != ' ' {
		return nil, true
	}
	m := hdr5424.FindStringSubmatch(line)
	if m == nil {
		return nil, true
	}
	pri := atoi(m[1])
	if pri > 191 {
		return nil, true
	}
	i := len(m[0])
	sdNil := false
	if i < len(line) && line[i] == '-' {
		i++
		sdNil = true
	} else if i < len(line) && line[i] == '[' {
		if i = parseSD(line, i); i < 0 {
			return nil, true
		}
	} else {
		return nil, true
	}
	_ = sdNil
	var msg string
	if i < len(line) && line[i] == ' ' {
		msg = line[i+1:]
	} else {
		msg = line[i:]
	}
	msg = strings.TrimPrefix(msg, "\ufeff")
	ts := 0.0
	if m[2] != "-" {
		var ok bool
		if ts, ok = parseTime(m[2], 0, 0); !ok {
			return nil, false
		}
	}
	return &Header{Format: "rfc5424", Pri: pri, Facility: pri >> 3, HasFacility: true, Sev: pri & 7, Ts: ts,
		Host: nilDash(m[3]), App: nilDash(m[4]), Pid: nilDash(m[5]), Msgid: nilDash(m[6]), Msg: msg}, true
}

var (
	priRe = regexp.MustCompile(`^<(\d{1,3})>`)
	// the JavaScript lookahead (?=\s|:) becomes a consumed group: RE2's leftmost-first choice is the match a
	// backtracking engine settles on, and the header ends where that group starts
	bsdTs  = regexp.MustCompile(`^([A-Z][a-z]{2})[` + jsrt.WS + `]{1,2}(\d{1,2})(?:[` + jsrt.WS + `]+(\d{4}))?[` + jsrt.WS + `]+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?([` + jsrt.WS + `]|:)`)
	isoTs  = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)([` + jsrt.WS + `])`)
	tagRe  = regexp.MustCompile(`^([A-Za-z0-9_./()\-]{1,64})(?:\[([^\]` + jsrt.WS + `]{0,32})\])?: ?`)
	hostRe = regexp.MustCompile(`^[A-Za-z0-9_.:%\-]{1,255}$`)
	payRe  = regexp.MustCompile(`^(?:CEF:\d|LEEF:\d|%[A-Z])`)
)

// bsdTsMatch: the BSD timestamp starts with an upper-case letter, so most FortiGate lines (PRI then "date=") skip
// the regexp entirely.
func bsdTsMatch(s string) []int {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return nil
	}
	return bsdTs.FindStringSubmatchIndex(s)
}

func parse3164(line string, offMin int, refMs float64) (*Header, bool) {
	i := 0
	pri := -1
	if pm := priRe.FindStringSubmatch(line); pm != nil {
		pri = atoi(pm[1])
		if pri > 191 {
			return nil, true
		}
		i = len(pm[0])
	}
	ts := 0.0
	hasTs := false
	if m := bsdTsMatch(line[i:]); m != nil {
		mon := line[i+m[2] : i+m[3]]
		if mo, ok := months[strings.ToLower(mon)]; ok {
			g := func(k int) string {
				if m[2*k] < 0 {
					return ""
				}
				return line[i+m[2*k] : i+m[2*k+1]]
			}
			ms := 0.0
			if g(7) != "" {
				ms = fracMs(g(7))
			}
			if g(3) != "" {
				ts = wallToMs(atoi(g(3)), mo, atoi(g(2)), atoi(g(4)), atoi(g(5)), atoi(g(6)), ms, offMin)
			} else {
				ts = inferYear(mo, atoi(g(2)), atoi(g(4)), atoi(g(5)), atoi(g(6)), ms, offMin, refMs)
			}
			i += m[16] // where the lookahead group starts
			hasTs = true
		}
	}
	if !hasTs && i < len(line) && line[i] >= '0' && line[i] <= '9' {
		if m := isoTs.FindStringSubmatchIndex(line[i:]); m != nil {
			var ok bool
			if ts, ok = parseTime(line[i+m[2]:i+m[3]], offMin, refMs); !ok {
				return nil, false
			}
			i += m[4]
			hasTs = true
		}
	}
	if pri < 0 && !hasTs {
		return nil, true
	}
	host, app, pid := "", "", ""
	rest := jsrt.TrimLeft(line[i:])
	if hasTs {
		sp := strings.IndexByte(rest, ' ')
		cand := rest
		if sp >= 0 {
			cand = rest[:sp]
		}
		if cand != "" && sp > 0 && !strings.HasSuffix(cand, ":") && hostRe.MatchString(cand) && !payRe.MatchString(cand) {
			host = cand
			rest = rest[sp+1:]
		}
		var t []string
		if !payRe.MatchString(rest) {
			t = tagRe.FindStringSubmatch(rest)
		}
		if t != nil {
			app, pid = t[1], t[2]
			rest = rest[len(t[0]):]
		} else if strings.HasPrefix(rest, ": ") {
			rest = rest[2:]
		}
	}
	h := &Header{Format: "rfc3164", Pri: pri, Sev: -1, Ts: ts, Host: host, App: app, Pid: pid, Msg: rest}
	if pri >= 0 {
		h.Facility, h.HasFacility, h.Sev = pri>>3, true, pri&7
	}
	return h, true
}

// syslogHeader: RFC 5424 first, then RFC 3164. nil = no header; ok=false = hand the line back.
func syslogHeader(line string, offMin int, refMs float64) (*Header, bool) {
	if line == "" {
		return nil, true
	}
	h, ok := parse5424(line)
	if !ok || h != nil {
		return h, ok
	}
	return parse3164(line, offMin, refMs)
}
