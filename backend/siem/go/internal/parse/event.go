// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

package parse

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"sentra-siem/go/internal/jsrt"
)

// Event is the normalised event of engine/schema.js after finalise (blankEvent's fields, in its order).
type Event struct {
	Ts, Rts                                                                int64
	ID, SrcType, SrcID, Collector, Host, HostIP, Category, Action, Outcome string
	Severity                                                               int
	User, TargetUser, Domain, SrcIP, DstIP                                 string
	SrcPort, DstPort                                                       int
	Proto, Process, ParentProcess, Cmdline, Hash, URL, HTTPMethod          string
	HTTPStatus                                                             int
	UserAgent, DNSQuery, EventCode, Message                                string
	Tags                                                                   []string
	Fields                                                                 *jsrt.OMap
	Raw                                                                    string
	ParseError                                                             bool // _perr (not serialised)
}

const (
	maxFieldsKeys = 200
	maxFieldValue = 8192
	maxMessage    = 4096
	minTs         = 946684800000 // Date.UTC(2000, 0, 1)
)

var categories = map[string]bool{"authentication": true, "network": true, "web": true, "process": true, "iam": true, "malware": true,
	"file": true, "registry": true, "dns": true, "system": true, "policy": true, "email": true, "cloud": true, "database": true, "other": true}
var outcomes = map[string]bool{"success": true, "failure": true, "unknown": true}

var wsRun = regexp.MustCompile(`[` + jsrt.WS + `]+`)

// uuid4 is crypto.randomUUID(): random bytes from the OS generator, read 4 KB at a time (Node.js caches its entropy too)
var (
	uuidMu   sync.Mutex
	uuidPool [4096]byte
	uuidPos  = len(uuidPool)
)

func uuid4() string {
	var b [16]byte
	uuidMu.Lock()
	if uuidPos+16 > len(uuidPool) {
		_, _ = rand.Read(uuidPool[:])
		uuidPos = 0
	}
	copy(b[:], uuidPool[uuidPos:uuidPos+16])
	uuidPos += 16
	uuidMu.Unlock()
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// cleanIp is schema.cleanIp: ("", true) empty, (ip, true) valid, ("", false) present but invalid.
func cleanIp(v string) (string, bool) {
	s := jsrt.Trim(v)
	if s == "" || s == "-" {
		return "", true
	}
	if s[0] == '[' {
		if e := strings.IndexByte(s, ']'); e > 0 {
			s = s[1:e]
		}
	}
	if p := strings.IndexByte(s, '%'); p > 0 {
		s = s[:p]
	}
	if strings.HasPrefix(s, "::ffff:") && isIP(s[7:]) == 4 {
		s = s[7:]
	}
	if isIP(s) != 0 {
		return jsrt.Lower(s), true
	}
	return "", false
}

// schema int(v, max): a negative, NaN or infinite value is 0, above max is max, else truncated.
func jsInt(n float64, max int) int {
	if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
		return 0
	}
	if n > float64(max) {
		return max
	}
	return int(math.Trunc(n))
}

// finalise is schema.finalise for the fields a syslog parser fills (the others are ” / 0 from blankEvent).
// ts / rts arrive as JavaScript numbers; the order of the checks is the order of FIELDS, so the extra field keys
// (ts_invalid, *_raw, category_raw, outcome_raw) land where JavaScript puts them.
func finalise(r *Raw, ev *Event, rts float64, hostIP string) {
	f := ev.Fields
	// ts (rts is already set by the router and valid)
	n := r.Ts
	if !(n > minTs) || n > rts+86400000 {
		if n != 0 && !math.IsNaN(n) {
			f.Set("ts_invalid", jsrt.NumString(r.Ts))
		}
		n = rts
	}
	ev.Ts = int64(math.Trunc(n))
	ev.Rts = int64(math.Trunc(rts))
	ev.ID = uuid4()
	ev.SrcType = jsrt.Lower(ev.SrcType)
	ev.Collector = jsrt.Lower(ev.Collector)
	ipField := func(name, v string) string {
		c, ok := cleanIp(v)
		if !ok {
			f.Set(name+"_raw", jsrt.U16Slice(v, 256))
			return ""
		}
		return c
	}
	ev.HostIP = ipField("host_ip", hostIP)
	ev.Category = jsrt.Lower(ev.Category)
	ev.Action = jsrt.Lower(ev.Action)
	ev.Outcome = jsrt.Lower(ev.Outcome)
	ev.Severity = jsInt(r.Severity, 4)
	ev.User = jsrt.Lower(ev.User)
	ev.Domain = jsrt.Lower(ev.Domain)
	ev.SrcIP = ipField("src_ip", ev.SrcIP)
	ev.DstIP = ipField("dst_ip", ev.DstIP)
	ev.SrcPort = jsInt(r.SrcPort, 65535)
	ev.DstPort = jsInt(r.DstPort, 65535)
	ev.Proto = jsrt.Lower(ev.Proto)
	ev.Hash = jsrt.Lower(ev.Hash)
	ev.HTTPMethod = jsrt.Upper(ev.HTTPMethod)
	ev.DNSQuery = jsrt.Lower(ev.DNSQuery)
	if jsrt.U16Len(ev.Message) > maxMessage {
		ev.Message = jsrt.U16Slice(ev.Message, maxMessage)
	}
	if len(r.Tags) > 0 {
		seen := map[string]bool{}
		var out []string
		for _, t := range r.Tags {
			if t != "" && !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
		if len(out) > 64 {
			out = out[:64]
		}
		ev.Tags = out
	} else {
		ev.Tags = []string{}
	}
	if !categories[ev.Category] {
		if ev.Category != "" {
			f.Set("category_raw", ev.Category)
		}
		ev.Category = "other"
	}
	if !outcomes[ev.Outcome] {
		if ev.Outcome != "" {
			f.Set("outcome_raw", ev.Outcome)
		}
		ev.Outcome = "unknown"
	}
	if ev.Action != "" && strings.IndexFunc(ev.Action, jsrt.IsWS) >= 0 {
		ev.Action = wsRun.ReplaceAllString(ev.Action, "-")
	}
	cnt := 0
	for _, k := range f.Keys() {
		v := f.S(k)
		if v == "" {
			f.Del(k)
			continue
		}
		cnt++
		if cnt > maxFieldsKeys || jsrt.U16Len(k) > 128 {
			f.Del(k)
			continue
		}
		if jsrt.U16Len(v) > maxFieldValue {
			f.Set(k, jsrt.U16Slice(v, maxFieldValue))
		}
	}
}

// MarshalJSON writes the event the way JSON.stringify writes the Node.js one (same keys, same order).
func (e *Event) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.Grow(2*len(e.Raw) + 768)
	str := func(k, v string, comma bool) {
		b.WriteByte('"')
		b.WriteString(k)
		b.WriteString(`":`)
		writeStr(&b, v)
		if comma {
			b.WriteByte(',')
		}
	}
	num := func(k string, v int64) {
		b.WriteByte('"')
		b.WriteString(k)
		b.WriteString(`":`)
		b.WriteString(strconv.FormatInt(v, 10))
		b.WriteByte(',')
	}
	b.WriteByte('{')
	num("ts", e.Ts)
	num("rts", e.Rts)
	str("id", e.ID, true)
	str("src_type", e.SrcType, true)
	str("src_id", e.SrcID, true)
	str("collector", e.Collector, true)
	str("host", e.Host, true)
	str("host_ip", e.HostIP, true)
	str("category", e.Category, true)
	str("action", e.Action, true)
	str("outcome", e.Outcome, true)
	num("severity", int64(e.Severity))
	str("user", e.User, true)
	str("target_user", e.TargetUser, true)
	str("domain", e.Domain, true)
	str("src_ip", e.SrcIP, true)
	str("dst_ip", e.DstIP, true)
	num("src_port", int64(e.SrcPort))
	num("dst_port", int64(e.DstPort))
	str("proto", e.Proto, true)
	str("process", e.Process, true)
	str("parent_process", e.ParentProcess, true)
	str("cmdline", e.Cmdline, true)
	str("hash", e.Hash, true)
	str("url", e.URL, true)
	str("http_method", e.HTTPMethod, true)
	num("http_status", int64(e.HTTPStatus))
	str("user_agent", e.UserAgent, true)
	str("dns_query", e.DNSQuery, true)
	str("event_code", e.EventCode, true)
	str("message", e.Message, true)
	b.WriteString(`"tags":[`)
	for i, t := range e.Tags {
		if i > 0 {
			b.WriteByte(',')
		}
		writeStr(&b, t)
	}
	b.WriteString(`],"fields":{`)
	first := true
	e.Fields.Each(func(k, v string) {
		if !first {
			b.WriteByte(',')
		}
		first = false
		writeStr(&b, k)
		b.WriteByte(':')
		writeStr(&b, v)
	})
	b.WriteString(`},`)
	str("raw", e.Raw, false)
	b.WriteByte('}')
	return b.Bytes(), nil
}

const hexDigits = "0123456789abcdef"

// writeStr writes s as JSON.stringify does: ", \ and control characters escaped, everything else as is.
func writeStr(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		b.WriteString(s[start:i])
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
		start = i + 1
	}
	b.WriteString(s[start:])
	b.WriteByte('"')
}
