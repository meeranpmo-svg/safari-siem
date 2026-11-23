// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

package syslog

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"sentra-siem/go/internal/parse"
)

// SYNTHETIC test lines only.
const fgLine = `<189>date=2026-10-21 time=10:00:00 devname="FG-SYNTH" devid="FGT0" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.1.1.5 dstip=10.2.2.2 action="deny" policyid=0`

func TestListenerUDPTCPLimits(t *testing.T) {
	f := false
	cfg := Config{Host: "127.0.0.1", UnknownSources: "accept", DefaultSources: map[string]Source{
		"syslog-udp": {ID: "fw-udp", Type: "fortigate"}, "syslog-tcp": {ID: "fw-tcp", Type: "fortigate"}}}
	cfg.TCP.MaxConnPerPeer = 2
	cfg.TLS.Enabled = f
	var mu sync.Mutex
	var evs []*parse.Event
	var hbs []*Handback
	s := New(cfg, func(ev *parse.Event, h *Handback) {
		mu.Lock()
		defer mu.Unlock()
		if ev != nil {
			evs = append(evs, ev)
		} else {
			hbs = append(hbs, h)
		}
	})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	u, err := net.Dial("udp", s.Listeners["udp"])
	if err != nil {
		t.Fatal(err)
	}
	_, _ = u.Write([]byte(fgLine + "\r\n"))
	_, _ = u.Write([]byte("<13>Oct 21 10:00:00 host sshd[1]: not a firewall line"))
	u.Close()

	c1, _ := net.Dial("tcp", s.Listeners["tcp"])
	c2, _ := net.Dial("tcp", s.Listeners["tcp"])
	time.Sleep(100 * time.Millisecond)
	c3, _ := net.Dial("tcp", s.Listeners["tcp"]) // third from the same peer: refused
	// octet-counted frame, then the same line again (still octet mode for this connection)
	_, _ = c1.Write([]byte(strconv.Itoa(len(fgLine)) + " " + fgLine + strconv.Itoa(len(fgLine)) + " " + fgLine))
	c1.Close()
	c2.Close()
	buf := make([]byte, 1)
	_ = c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c3.Read(buf); err == nil {
		t.Error("third connection from one peer should be closed")
	}
	c3.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(evs) + len(hbs)
		mu.Unlock()
		if n >= 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hbs) != 1 || hbs[0].Reason != "not a FortiGate line" || hbs[0].Meta.Collector != "syslog-udp" {
		t.Errorf("hand-backs: %+v", hbs)
	}
	if len(evs) != 3 {
		t.Fatalf("events: %d", len(evs))
	}
	for _, e := range evs {
		if e.Action != "blocked" || e.Outcome != "failure" || e.SrcIP != "10.1.1.5" || e.HostIP != "127.0.0.1" {
			t.Errorf("event: %+v", e)
		}
	}
	st := s.Stats()
	if st["rejected_connections"].(int64) != 1 {
		t.Errorf("rejected_connections = %v", st["rejected_connections"])
	}
}
