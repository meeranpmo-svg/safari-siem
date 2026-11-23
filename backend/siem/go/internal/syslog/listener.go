// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

package syslog

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentra-siem/go/internal/jsrt"
	"sentra-siem/go/internal/parse"
)

// Source is one entry of config.sources (collect/sources.js).
type Source struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	TzOffMin *int   `json:"-"`
	Site     string `json:"site"`
	Match    struct {
		IP   any `json:"ip"`
		CIDR any `json:"cidr"`
	} `json:"match"`
}

// LoadEngineConfig reads the engine's own config.json (syslog + sources) leniently: config.json is written by the
// SIEM's onboarding pages, so a field of an unexpected type is skipped, never a reason to stop.
func LoadEngineConfig(raw []byte) (Config, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return Config{}, err
	}
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	num := func(m map[string]any, k string) (int, bool) {
		f, ok := m[k].(float64)
		if !ok || f != float64(int(f)) {
			return 0, false
		}
		return int(f), true
	}
	obj := func(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }
	boolp := func(m map[string]any, k string) *bool {
		if b, ok := m[k].(bool); ok {
			return &b
		}
		return nil
	}
	src := func(m map[string]any) Source {
		s := Source{ID: str(m, "id"), Type: str(m, "type"), Site: str(m, "site")}
		if n, ok := num(m, "tz_offset_min"); ok {
			s.TzOffMin = &n
		}
		if mt := obj(m, "match"); mt != nil {
			s.Match.IP, s.Match.CIDR = mt["ip"], mt["cidr"]
		}
		return s
	}
	var c Config
	sl := obj(root, "syslog")
	if sl == nil {
		sl = map[string]any{}
	}
	c.Host = str(sl, "host")
	c.MaxLine, _ = num(sl, "max_line")
	c.TzOffMin, _ = num(sl, "tz_offset_min")
	c.UnknownSources = str(sl, "unknown_sources")
	c.DefaultSources = map[string]Source{}
	for k, v := range obj(sl, "default_sources") {
		if m, ok := v.(map[string]any); ok {
			c.DefaultSources[k] = src(m)
		}
	}
	if u := obj(sl, "udp"); u != nil {
		c.UDP.Enabled = boolp(u, "enabled")
		c.UDP.Port, _ = num(u, "port")
	}
	if t := obj(sl, "tcp"); t != nil {
		c.TCP.Enabled = boolp(t, "enabled")
		c.TCP.Port, _ = num(t, "port")
		c.TCP.MaxConnections, _ = num(t, "max_connections")
		c.TCP.MaxConnPerPeer, _ = num(t, "max_connections_per_peer")
		c.TCP.IdleTimeoutS, _ = num(t, "idle_timeout_s")
	}
	if t := obj(sl, "tls"); t != nil {
		c.TLS.Enabled, _ = t["enabled"].(bool)
		c.TLS.Port, _ = num(t, "port")
		c.TLS.Cert, c.TLS.Key, c.TLS.CA = str(t, "cert"), str(t, "key"), str(t, "ca")
		c.TLS.RequestCert, _ = t["request_cert"].(bool)
	}
	if arr, ok := root["sources"].([]any); ok {
		for _, e := range arr {
			if m, ok := e.(map[string]any); ok {
				c.Sources = append(c.Sources, src(m))
			}
		}
	}
	return c, nil
}

// Config is config.syslog plus config.sources.
type Config struct {
	Host           string            `json:"host"`
	MaxLine        int               `json:"max_line"`
	TzOffMin       int               `json:"tz_offset_min"`
	UnknownSources string            `json:"unknown_sources"`
	DefaultSources map[string]Source `json:"default_sources"`
	UDP            struct {
		Enabled *bool `json:"enabled"`
		Port    int   `json:"port"`
	} `json:"udp"`
	TCP struct {
		Enabled        *bool `json:"enabled"`
		Port           int   `json:"port"`
		MaxConnections int   `json:"max_connections"`
		MaxConnPerPeer int   `json:"max_connections_per_peer"`
		IdleTimeoutS   int   `json:"idle_timeout_s"`
	} `json:"tcp"`
	TLS struct {
		Enabled     bool   `json:"enabled"`
		Port        int    `json:"port"`
		Cert        string `json:"cert"`
		Key         string `json:"key"`
		CA          string `json:"ca"`
		RequestCert bool   `json:"request_cert"`
	} `json:"tls"`
	Sources []Source `json:"-"`
}

func list(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func normPeer(ip string) string {
	if strings.HasPrefix(ip, "::ffff:") {
		if a, err := netip.ParseAddr(ip[7:]); err == nil && a.Is4() {
			ip = ip[7:]
		}
	}
	return strings.ToLower(ip)
}

type sourceMap struct {
	byIP  map[string]*Source
	cidrs []struct {
		p   netip.Prefix
		src *Source
	}
	defaults map[string]Source
	mu       sync.Mutex
	cache    map[string]*Source
}

func newSourceMap(sources []Source, defaults map[string]Source) *sourceMap {
	m := &sourceMap{byIP: map[string]*Source{}, defaults: defaults, cache: map[string]*Source{}}
	for i := range sources {
		s := &sources[i]
		for _, ip := range list(s.Match.IP) {
			if _, ok := m.byIP[normPeer(ip)]; !ok {
				m.byIP[normPeer(ip)] = s
			}
		}
		for _, c := range list(s.Match.CIDR) {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				continue
			}
			m.cidrs = append(m.cidrs, struct {
				p   netip.Prefix
				src *Source
			}{p.Masked(), s})
		}
	}
	return m
}

func (m *sourceMap) lookup(peer, collector string) Source {
	ip := normPeer(peer)
	m.mu.Lock()
	s, hit := m.cache[ip]
	m.mu.Unlock()
	if !hit {
		s = m.byIP[ip]
		if s == nil {
			if a, err := netip.ParseAddr(ip); err == nil {
				for _, c := range m.cidrs {
					if c.p.Addr().Is4() == a.Is4() && c.p.Contains(a) {
						s = c.src
						break
					}
				}
			}
		}
		m.mu.Lock()
		if len(m.cache) > 50000 {
			m.cache = map[string]*Source{}
		}
		m.cache[ip] = s
		m.mu.Unlock()
	}
	if s != nil {
		return *s
	}
	if d, ok := m.defaults[collector]; ok {
		return d
	}
	id := collector
	if id == "" {
		id = "unknown"
	}
	return Source{ID: id, Type: "syslog"}
}

// Emit receives each parsed event, or the raw line when Go hands it back to the Node.js parser.
type Emit func(ev *parse.Event, handback *Handback)

// Handback is a line for the Node.js router, with the meta it needs.
type Handback struct {
	Line   string     `json:"line"`
	Meta   parse.Meta `json:"meta"`
	Reason string     `json:"reason"`
	Trunc  bool       `json:"truncated,omitempty"`
}

type peerStat struct {
	Peer, Collector, SrcID     string
	Messages, Bytes, Truncated int64
	FirstSeen, LastSeen        int64
	min, cur, prev             int64
}

// Server is createSyslog(...).
type Server struct {
	cfg                                                                                  Config
	emit                                                                                 Emit
	sources                                                                              *sourceMap
	maxLine                                                                              int
	mu                                                                                   sync.Mutex
	peers                                                                                map[string]*peerStat
	perPeer                                                                              map[string]int
	conns                                                                                map[net.Conn]bool
	closers                                                                              []func() error
	Listeners                                                                            map[string]string
	messages, bytes, truncated, errorsN, connections, rejected, idleClosed, droppedUnreg atomic.Int64
	wg                                                                                   sync.WaitGroup
	Logf                                                                                 func(format string, a ...any)
}

func New(cfg Config, emit Emit) *Server {
	ml := cfg.MaxLine
	if ml == 0 {
		ml = 65536
	}
	return &Server{cfg: cfg, emit: emit, sources: newSourceMap(cfg.Sources, cfg.DefaultSources), maxLine: ml,
		peers: map[string]*peerStat{}, perPeer: map[string]int{}, conns: map[net.Conn]bool{}, Listeners: map[string]string{},
		Logf: func(string, ...any) {}}
}

var trailUDP = regexp.MustCompile(`[\r\n\x00]+$`)

func (s *Server) handle(frame []byte, peerIP, collector string, truncated bool) {
	now := time.Now().UnixMilli()
	line := jsrt.DecodeUTF8(frame)
	if collector == "syslog-udp" {
		line = trailUDP.ReplaceAllString(line, "")
		if line == "" {
			return
		}
	}
	src := s.sources.lookup(peerIP, collector)
	def, hasDef := s.cfg.DefaultSources[collector]
	unregistered := src.ID == "unknown" || (hasDef && src.ID == def.ID)
	if unregistered && s.cfg.UnknownSources != "accept" && s.cfg.UnknownSources == "drop" {
		s.droppedUnreg.Add(1)
		return
	}
	tz := s.cfg.TzOffMin
	if src.TzOffMin != nil {
		tz = *src.TzOffMin
	}
	typ := src.Type
	if typ == "" {
		typ = "syslog"
	}
	meta := parse.Meta{Collector: collector, SrcID: src.ID, SrcType: typ, PeerIP: peerIP, Rts: float64(now), TzOffMin: tz, Site: src.Site}
	s.messages.Add(1)
	s.bytes.Add(int64(len(frame)))
	s.mu.Lock()
	p := s.peer(peerIP, collector, src.ID, now)
	p.Messages++
	p.Bytes += int64(len(frame))
	p.LastSeen = now
	m := now / 60000
	if m != p.min {
		if m == p.min+1 {
			p.prev = p.cur
		} else {
			p.prev = 0
		}
		p.cur, p.min = 0, m
	}
	p.cur++
	if truncated {
		p.Truncated++
	}
	s.mu.Unlock()
	if truncated {
		s.truncated.Add(1)
	}
	r := parse.Parse(line, meta)
	if r.Event == nil {
		s.emit(nil, &Handback{Line: line, Meta: meta, Reason: r.Handback, Trunc: truncated})
		return
	}
	if truncated {
		r.Event.Fields.Set("truncated", "1")
	}
	if unregistered && s.cfg.UnknownSources != "accept" {
		r.Event.Tags = append(r.Event.Tags, "unregistered-source")
	}
	s.emit(r.Event, nil)
}

func (s *Server) peer(ip, collector, srcID string, now int64) *peerStat {
	k := collector + "|" + ip
	p := s.peers[k]
	if p == nil {
		if len(s.peers) >= 10000 {
			var oldest string
			var t int64 = 1 << 62
			for kk, v := range s.peers {
				if v.FirstSeen < t {
					oldest, t = kk, v.FirstSeen
				}
			}
			delete(s.peers, oldest)
		}
		p = &peerStat{Peer: ip, Collector: collector, SrcID: srcID, FirstSeen: now}
		s.peers[k] = p
	}
	return p
}

func (s *Server) onConn(c net.Conn, collector string) {
	defer s.wg.Done()
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	peer := normPeer(host)
	maxConn := or(s.cfg.TCP.MaxConnections, 2000)
	maxPer := or(s.cfg.TCP.MaxConnPerPeer, 20)
	idle := time.Duration(or(s.cfg.TCP.IdleTimeoutS, 600)) * time.Second
	s.mu.Lock()
	mine := s.perPeer[peer]
	if len(s.conns) >= maxConn || mine >= maxPer {
		s.mu.Unlock()
		s.rejected.Add(1)
		s.Logf("syslog: connection refused (limit reached) peer=%s collector=%s", peer, collector)
		c.Close()
		return
	}
	s.conns[c] = true
	s.perPeer[peer] = mine + 1
	s.mu.Unlock()
	s.connections.Add(1)
	defer func() {
		c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		if n := s.perPeer[peer] - 1; n > 0 {
			s.perPeer[peer] = n
		} else {
			delete(s.perPeer, peer)
		}
		s.mu.Unlock()
	}()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(60 * time.Second)
	}
	fr := NewFramer(s.maxLine, func(b []byte, trunc bool) { s.handle(b, peer, collector, trunc) })
	buf := make([]byte, 64*1024)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		n, err := c.Read(buf)
		if n > 0 {
			fr.Push(buf[:n])
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				s.idleClosed.Add(1)
				return // destroyed: no End(), as sock.destroy() in Node.js
			}
			fr.End()
			return
		}
	}
}

func or(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func (s *Server) serveTCP(ln net.Listener, collector string) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.onConn(c, collector)
	}
}

// Start opens the listeners configured (UDP, TCP, TLS).
func (s *Server) Start() error {
	host := s.cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	if s.cfg.UDP.Enabled == nil || *s.cfg.UDP.Enabled {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprint(s.cfg.UDP.Port)))
		if err != nil {
			return err
		}
		if uc, ok := pc.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(8 * 1024 * 1024)
		}
		s.Listeners["udp"] = pc.LocalAddr().String()
		s.closers = append(s.closers, pc.Close)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			buf := make([]byte, 65536)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				h, _, _ := net.SplitHostPort(addr.String())
				msg := buf[:n]
				trunc := n > s.maxLine
				if trunc {
					msg = msg[:s.maxLine]
				}
				s.handle(append([]byte(nil), msg...), normPeer(h), "syslog-udp", trunc)
			}
		}()
	}
	if s.cfg.TCP.Enabled == nil || *s.cfg.TCP.Enabled {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(s.cfg.TCP.Port)))
		if err != nil {
			return err
		}
		s.Listeners["tcp"] = ln.Addr().String()
		s.closers = append(s.closers, ln.Close)
		s.wg.Add(1)
		go s.serveTCP(ln, "syslog-tcp")
	}
	if s.cfg.TLS.Enabled {
		tc, err := s.tlsConfig()
		if err != nil {
			s.Logf("syslog: TLS listener disabled - cannot read certificate/key: %v", err)
		} else {
			ln, err := tls.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(s.cfg.TLS.Port)), tc)
			if err != nil {
				return err
			}
			s.Listeners["tls"] = ln.Addr().String()
			s.closers = append(s.closers, ln.Close)
			s.wg.Add(1)
			go s.serveTCP(ln, "syslog-tls")
		}
	}
	return nil
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.Cert, s.cfg.TLS.Key)
	if err != nil {
		return nil, err
	}
	c := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if s.cfg.TLS.CA != "" {
		pem, err := os.ReadFile(s.cfg.TLS.CA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		c.ClientCAs = pool
	}
	if s.cfg.TLS.RequestCert {
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}

// Stop closes the listeners and every open connection.
func (s *Server) Stop() {
	for _, c := range s.closers {
		_ = c()
	}
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Stats is stats(): counters plus the 500 most recent peers.
func (s *Server) Stats() map[string]any {
	now := time.Now().UnixMilli()
	m := now / 60000
	s.mu.Lock()
	var peers []map[string]any
	for _, p := range s.peers {
		last := int64(0)
		if p.min == m {
			last = p.prev
		} else if p.min == m-1 {
			last = p.cur
		}
		peers = append(peers, map[string]any{"peer": p.Peer, "collector": p.Collector, "src_id": p.SrcID, "messages": p.Messages,
			"bytes": p.Bytes, "truncated": p.Truncated, "first_seen": p.FirstSeen, "last_seen": p.LastSeen,
			"eps_1m": float64(int64(float64(last)/60*100+0.5)) / 100})
	}
	open := len(s.conns)
	s.mu.Unlock()
	sort.Slice(peers, func(a, b int) bool { return peers[a]["last_seen"].(int64) > peers[b]["last_seen"].(int64) })
	if len(peers) > 500 {
		peers = peers[:500]
	}
	return map[string]any{"listeners": s.Listeners, "messages": s.messages.Load(), "bytes": s.bytes.Load(), "truncated": s.truncated.Load(),
		"errors": s.errorsN.Load(), "connections": s.connections.Load(), "rejected_connections": s.rejected.Load(),
		"idle_closed": s.idleClosed.Load(), "dropped_unregistered": s.droppedUnreg.Load(), "open_connections": open,
		"peers": peers, "parser": parse.GetStats()}
}
