// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

package parse

import (
	"math"
	"strconv"
	"sync/atomic"
	"time"

	"sentra-siem/go/internal/jsrt"
)

// Meta is the router's meta (parse/index.js).
type Meta struct {
	Collector string  `json:"collector"`
	SrcID     string  `json:"src_id"`
	SrcType   string  `json:"src_type"`
	PeerIP    string  `json:"peer_ip"`
	Rts       float64 `json:"rts"`
	TzOffMin  int     `json:"tz_offset_min"`
	Site      string  `json:"site"`
}

// Result: an event, or a hand-back to Node.js with the reason. A hand-back is not a failure: it is a line the
// JavaScript router would have sent somewhere this slice has not ported (another parser, Date.parse), so Node.js
// must parse it - Go never guesses.
type Result struct {
	Event    *Event
	Handback string
}

// Stats counts what the router did (by parser, hand-backs by reason).
type Stats struct {
	Events, Handbacks atomic.Int64
	HandbackSrcType   atomic.Int64
	HandbackNotFG     atomic.Int64
	HandbackDateParse atomic.Int64
}

var stats Stats

func GetStats() map[string]int64 {
	return map[string]int64{"events": stats.Events.Load(), "handbacks": stats.Handbacks.Load(),
		"handback_src_type": stats.HandbackSrcType.Load(), "handback_not_fortigate": stats.HandbackNotFG.Load(),
		"handback_date_parse": stats.HandbackDateParse.Load()}
}

func handback(reason string, c *atomic.Int64) Result {
	stats.Handbacks.Add(1)
	c.Add(1)
	return Result{Handback: reason}
}

// Parse is router.parse(line, meta) for sources registered as FortiGate.
func Parse(line string, meta Meta) Result {
	srcType := meta.SrcType
	if srcType == "" {
		srcType = "syslog"
	}
	if srcType != "fortigate" {
		return handback("src_type "+srcType+" is not ported", &stats.HandbackSrcType)
	}
	rts := meta.Rts
	if rts == 0 {
		rts = float64(time.Now().UnixMilli())
	}
	hdr, ok := syslogHeader(line, meta.TzOffMin, rts)
	if !ok {
		return handback("syslog timestamp needs Date.parse", &stats.HandbackDateParse)
	}
	body := line
	if hdr != nil {
		body = hdr.Msg
	}
	r, ok := Fortigate(body, meta.TzOffMin, rts)
	if !ok {
		return handback("FortiGate timestamp needs Date.parse", &stats.HandbackDateParse)
	}
	if r == nil {
		// the JavaScript router now offers the line to every other parser and the generic syslog event
		return handback("not a FortiGate line", &stats.HandbackNotFG)
	}
	if hdr != nil {
		if r.Ts == 0 || math.IsNaN(r.Ts) {
			r.Ts = hdr.Ts
		}
		if r.Host == "" {
			r.Host = hdr.Host
		}
		if hdr.App != "" && !r.Fields.Has("app") {
			r.Fields.Set("app", hdr.App)
		}
		if hdr.Pid != "" && !r.Fields.Has("pid") {
			r.Fields.Set("pid", hdr.Pid)
		}
		if hdr.HasFacility && !r.Fields.Has("facility") {
			r.Fields.Set("facility", strconv.Itoa(hdr.Facility))
		}
	}
	ev := &Event{SrcType: r.SrcType, SrcID: meta.SrcID, Collector: meta.Collector, Host: r.Host,
		Category: r.Category, Action: r.Action, Outcome: r.Outcome, User: r.User, Domain: r.Domain,
		SrcIP: r.SrcIP, DstIP: r.DstIP, Proto: r.Proto, Hash: r.Hash, URL: r.URL, HTTPMethod: r.HTTPMethod,
		DNSQuery: r.DNSQuery, EventCode: r.EventCode, Message: r.Message, Fields: r.Fields, Raw: line}
	if ev.SrcType == "" {
		ev.SrcType = srcType
	}
	if meta.Site != "" && !ev.Fields.Has("site") {
		ev.Fields.Set("site", jsrt.U16Slice(meta.Site, 64))
	}
	finalise(r, ev, rts, meta.PeerIP)
	stats.Events.Add(1)
	return Result{Event: ev}
}
