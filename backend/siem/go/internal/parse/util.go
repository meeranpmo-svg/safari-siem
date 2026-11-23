// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

// Package parse is the Go port of engine/parse (router, syslog headers, FortiGate) and engine/schema.js finalise.
// Same input, same event, field for field: tests/go-fortigate-parity.test.js runs both on the same lines.
// What Go cannot decide exactly like JavaScript (a timestamp only Date.parse reads, a line FortiGate does not take
// and the router would offer to the other parsers) is handed back to Node.js, never guessed.
package parse

import (
	"math"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"sentra-siem/go/internal/jsrt"
)

var months = map[string]int{"jan": 0, "feb": 1, "mar": 2, "apr": 3, "may": 4, "jun": 5, "jul": 6, "aug": 7, "sep": 8, "oct": 9, "nov": 10, "dec": 11}

var syslogSev = [8]float64{4, 4, 3, 2, 1, 0, 0, 0}

func sevFromSyslog(n int) float64 {
	if n >= 0 && n <= 7 {
		return syslogSev[n]
	}
	return 0
}

var namedSev = map[string]float64{
	"emergency": 4, "emerg": 4, "alert": 4, "critical": 4, "crit": 4, "very-high": 4, "veryhigh": 4,
	"error": 3, "err": 3, "high": 3,
	"warning": 2, "warn": 2, "medium": 2,
	"notice": 1, "low": 1,
	"information": 0, "informational": 0, "info": 0, "debug": 0, "none": 0, "unknown": 0,
}

// sevFromName: a prototype name finds a function on the object literal in JavaScript, which turns the severity
// into NaN (and 0 once finalised) - kept.
func sevFromName(s string, dflt float64) float64 {
	if s == "" {
		return dflt
	}
	k := jsrt.Trim(jsrt.Lower(s))
	if v, ok := namedSev[k]; ok {
		return v
	}
	if jsrt.ProtoName[k] {
		return math.NaN()
	}
	return dflt
}

func jsMax(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Max(a, b)
}

func toInt(v string) float64 {
	if v == "" {
		return 0
	}
	n := jsrt.ParseInt(v)
	if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
		return 0
	}
	return n
}

func epochToMs(n float64) float64 {
	if math.IsNaN(n) || math.IsInf(n, 0) || n <= 0 {
		return 0
	}
	switch {
	case n > 1e17:
		return math.Floor(n / 1e6)
	case n > 1e14:
		return math.Floor(n / 1e3)
	case n > 1e11:
		return math.Floor(n)
	}
	return math.Floor(n * 1000)
}

var tzRe = regexp.MustCompile(`^([+-])(\d{2}):?(\d{2})?$`)

func tzToMin(tz string) (int, bool) {
	if tz == "" {
		return 0, false
	}
	if tz == "Z" || tz == "z" || strings.EqualFold(tz, "utc") || strings.EqualFold(tz, "gmt") {
		return 0, true
	}
	m := tzRe.FindStringSubmatch(tz)
	if m == nil {
		return 0, false
	}
	v := atoi(m[2])*60 + atoi(m[3])
	if m[1] == "-" {
		v = -v
	}
	return v, true
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// wallToMs is Date.UTC(y, mo, d, h, mi, s, ms) - off minutes (years 0-99 mean 1900-1999, out-of-range parts roll over).
func wallToMs(y, mo, d, h, mi, s int, ms float64, off int) float64 {
	if y >= 0 && y <= 99 {
		y += 1900
	}
	t := time.Date(y, time.January, 1, 0, 0, 0, 0, time.UTC).AddDate(0, mo, d-1)
	base := float64(t.UnixMilli()) + float64(h)*3600000 + float64(mi)*60000 + float64(s)*1000 + ms
	if math.Abs(base) > 8.64e15 {
		return math.NaN()
	}
	return base - float64(off)*60000
}

func fracMs(f string) float64 { return float64(atoi((f + "00")[:3])) }

var (
	reEpoch  = regexp.MustCompile(`^\d{9,19}(\.\d+)?$`)
	reMsDate = regexp.MustCompile(`^/Date\((-?\d+)(?:[+-]\d{4})?\)/$`)
	reISO    = regexp.MustCompile(`(?i)^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?[` + jsrt.WS + `]*(Z|[+-]\d{2}(?::?\d{2})?|UTC|GMT)?$`)
	reApache = regexp.MustCompile(`^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:[` + jsrt.WS + `]+([+-]\d{4}))?$`)
	reBSD    = regexp.MustCompile(`^([A-Za-z]{3})[` + jsrt.WS + `]+(\d{1,2})(?:[` + jsrt.WS + `]+(\d{4}))?[` + jsrt.WS + `]+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:[` + jsrt.WS + `]+(Z|UTC|GMT|[+-]\d{2}:?\d{2}))?$`)
)

// parseTime returns epoch ms; ok=false means only Date.parse would read it (the caller hands the line back).
func parseTime(v string, offMin int, refMs float64) (float64, bool) {
	if v == "" {
		return 0, true
	}
	s := jsrt.Trim(v)
	if reEpoch.MatchString(s) {
		return epochToMs(jsrt.Number(s)), true
	}
	if m := reMsDate.FindStringSubmatch(s); m != nil {
		return jsrt.Number(m[1]), true
	}
	if m := reISO.FindStringSubmatch(s); m != nil {
		ms := 0.0
		if m[7] != "" {
			ms = fracMs(m[7])
		}
		off := offMin
		if m[8] != "" {
			z := m[8]
			if strings.EqualFold(z, "UTC") || strings.EqualFold(z, "GMT") {
				z = "Z"
			}
			off, _ = tzToMin(z)
		}
		return wallToMs(atoi(m[1]), atoi(m[2])-1, atoi(m[3]), atoi(m[4]), atoi(m[5]), atoi(m[6]), ms, off), true
	}
	if m := reApache.FindStringSubmatch(s); m != nil {
		mo, ok := months[strings.ToLower(m[2])]
		if !ok {
			return 0, true
		}
		off := offMin
		if m[8] != "" {
			off, _ = tzToMin(m[8])
		}
		ms := 0.0
		if m[7] != "" {
			ms = fracMs(m[7])
		}
		return wallToMs(atoi(m[3]), mo, atoi(m[1]), atoi(m[4]), atoi(m[5]), atoi(m[6]), ms, off), true
	}
	if m := reBSD.FindStringSubmatch(s); m != nil {
		mo, ok := months[strings.ToLower(m[1])]
		if !ok {
			return 0, true
		}
		off := offMin
		if m[8] != "" {
			z := m[8]
			if z == "UTC" || z == "GMT" {
				z = "Z"
			}
			off, _ = tzToMin(z)
		}
		ms := 0.0
		if m[7] != "" {
			ms = fracMs(m[7])
		}
		if m[3] != "" {
			return wallToMs(atoi(m[3]), mo, atoi(m[2]), atoi(m[4]), atoi(m[5]), atoi(m[6]), ms, off), true
		}
		return inferYear(mo, atoi(m[2]), atoi(m[4]), atoi(m[5]), atoi(m[6]), ms, off, refMs), true
	}
	return 0, false
}

func inferYear(mo, d, h, mi, s int, ms float64, off int, refMs float64) float64 {
	y := time.UnixMilli(int64(refMs + float64(off)*60000)).UTC().Year()
	t := wallToMs(y, mo, d, h, mi, s, ms, off)
	if t > refMs+86400000 {
		t = wallToMs(y-1, mo, d, h, mi, s, ms, off)
	}
	return t
}

// parseKV is util.parseKV: key=value, values "double" / 'single' quoted with \" and \\ escapes.
func parseKV(s string) *jsrt.OMap {
	out := jsrt.NewOMap()
	n := len(s)
	i := 0
	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == ',' || s[i] == ';') {
			i++
		}
		ks := i
		for i < n && s[i] != '=' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		if i >= n || s[i] != '=' {
			continue
		}
		key := s[ks:i]
		i++
		var val string
		if i < n && (s[i] == '"' || s[i] == '\'') {
			q := s[i]
			i++
			vs := i
			for i < n && s[i] != q && s[i] != '\\' {
				i++
			}
			if i < n && s[i] == '\\' { // an escape: build the value
				b := []byte(s[vs:i])
				for i < n && s[i] != q {
					if s[i] == '\\' && i+1 < n && (s[i+1] == q || s[i+1] == '\\') {
						b = append(b, s[i+1])
						i += 2
						continue
					}
					b = append(b, s[i])
					i++
				}
				val = string(b)
			} else {
				val = s[vs:i]
			}
			i++
		} else {
			vs := i
			for i < n && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			val = s[vs:i]
		}
		if key != "" {
			out.Set(key, val)
		}
	}
	return out
}

var nullish = map[string]bool{"": true, "-": true, "n/a": true, "na": true, "(null)": true, "null": true, "none": true, "unknown": true, "?": true}

func clean(v string) string {
	s := jsrt.Trim(v)
	if nullish[jsrt.Lower(s)] {
		return ""
	}
	return s
}

func splitUser(u string) (string, string) {
	user := clean(u)
	domain := ""
	if bs := strings.IndexByte(user, '\\'); bs >= 0 {
		domain = user[:bs]
		user = user[bs+1:]
	} else if at := strings.LastIndexByte(user, '@'); at > 0 {
		domain = user[at+1:]
	}
	return jsrt.Lower(user), jsrt.Lower(domain)
}

var zoneRe = regexp.MustCompile(`^[0-9a-zA-Z\-.:]+$`)

// isIP is net.isIP: strict dotted IPv4 (no leading zeros), IPv6 with an optional zone of Node's characters.
func isIP(s string) int {
	if s == "" || strings.TrimSpace(s) != s {
		return 0
	}
	host := s
	if p := strings.IndexByte(s, '%'); p >= 0 {
		if !strings.Contains(s[:p], ":") || !zoneRe.MatchString(s[p+1:]) {
			return 0
		}
		host = s[:p]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return 0
	}
	if a.Is4() && !strings.Contains(host, ":") {
		return 4
	}
	if strings.Contains(host, ":") {
		return 6
	}
	return 0
}

func ipOrEmpty(v string) string {
	s := clean(v)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "::ffff:")
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	if isIP(s) != 0 {
		return s
	}
	return ""
}

var protoNum = map[string]string{"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "51": "ah", "58": "ipv6-icmp", "132": "sctp"}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func protoName(p string) string {
	if p == "" {
		return ""
	}
	s := jsrt.Lower(jsrt.Trim(p))
	if allDigits(s) {
		if v, ok := protoNum[s]; ok {
			return v
		}
	}
	return s
}

// or is JavaScript's a || b || c over strings.
func or(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
