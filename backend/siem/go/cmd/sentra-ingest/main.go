// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

// sentra-ingest - the Go test slice of the SIEM engine: the syslog collector and the FortiGate parser.
//
//	sentra-ingest parse                 one JSON request per stdin line {"line","meta"} → one JSON answer per line
//	                                 ({"event":{…}} or {"handback":"reason"}); used by the parity test
//	sentra-ingest bench -f lines.txt [-n 200000] [-workers N] [-src-type fortigate]
//	                                 parses the lines over and over, prints lines/second as JSON
//	sentra-ingest listen -config syslog.json [-out events.jsonl|-] [-stats-every 10s]
//	                                 runs the UDP / TCP / TLS listeners; events and hand-backs go out as JSON lines
//
// Standard library only. Nothing here changes a device or the store: the slice reads logs and writes JSON.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sentra-siem/go/internal/jsrt"
	"sentra-siem/go/internal/parse"
	"sentra-siem/go/internal/syslog"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sentra-ingest parse | bench -f FILE | listen -config FILE")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "parse":
		parseMode()
	case "bench":
		benchMode(os.Args[2:])
	case "listen":
		listenMode(os.Args[2:])
	case "frames":
		framesMode()
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}

type answer struct {
	Event    *parse.Event `json:"event,omitempty"`
	Handback string       `json:"handback,omitempty"`
	Error    string       `json:"error,omitempty"`
}

func parseMode() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for {
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			var req struct {
				Line string     `json:"line"`
				Meta parse.Meta `json:"meta"`
			}
			if e := json.Unmarshal([]byte(line), &req); e != nil {
				_ = enc.Encode(answer{Error: e.Error()})
			} else {
				r := parse.Parse(req.Line, req.Meta)
				if r.Event != nil {
					j, _ := r.Event.MarshalJSON()
					_, _ = out.WriteString(`{"event":`)
					_, _ = out.Write(j)
					_, _ = out.WriteString("}\n")
				} else {
					_ = enc.Encode(answer{Handback: r.Handback})
				}
			}
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

// framesMode: one JSON request per line {"max_line":N,"chunks":["base64",…]} → {"frames":[{"text","truncated"}…],"mode"}
// - the framer and the UTF-8 decoder, for the parity test against createFramer + Buffer.toString
func framesMode() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	for {
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			var req struct {
				MaxLine int      `json:"max_line"`
				Chunks  [][]byte `json:"chunks"`
			}
			if e := json.Unmarshal([]byte(line), &req); e != nil {
				_ = enc.Encode(map[string]string{"error": e.Error()})
			} else {
				type fr struct {
					Text      string `json:"text"`
					Truncated bool   `json:"truncated"`
				}
				frames := []fr{}
				f := syslog.NewFramer(req.MaxLine, func(b []byte, t bool) { frames = append(frames, fr{jsrt.DecodeUTF8(b), t}) })
				for _, c := range req.Chunks {
					f.Push(c)
				}
				f.End()
				_ = enc.Encode(map[string]any{"frames": frames, "mode": f.Mode()})
			}
		}
		if err != nil {
			return
		}
	}
}

func benchMode(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	file := fs.String("f", "", "file with one log line per line")
	n := fs.Int("n", 200000, "lines to parse")
	workers := fs.Int("workers", 1, "parallel parsers (0 = every CPU)")
	srcType := fs.String("src-type", "fortigate", "source type")
	_ = fs.Parse(args)
	b, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if *workers <= 0 {
		*workers = runtime.NumCPU()
	}
	var next, events, hb atomic.Int64
	var bytesOut atomic.Int64
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := next.Add(1) - 1
				if i >= int64(*n) {
					return
				}
				r := parse.Parse(lines[i%int64(len(lines))], parse.Meta{Collector: "syslog-udp", SrcID: "fw1", SrcType: *srcType, PeerIP: "10.0.0.1", Rts: 1792605600000})
				if r.Event != nil {
					j, _ := r.Event.MarshalJSON() // serialising is part of the work, as in the engine
					bytesOut.Add(int64(len(j)))
					events.Add(1)
				} else {
					hb.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	sec := time.Since(start).Seconds()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"engine": "go", "lines": *n, "workers": *workers, "seconds": sec,
		"lines_per_sec": float64(*n) / sec, "events": events.Load(), "handbacks": hb.Load(), "heap_mb": float64(ms.HeapAlloc) / 1e6,
		"sys_mb": float64(ms.Sys) / 1e6})
}

// rotating is the event file: when it passes max bytes it becomes <name>.1 (the older .1 is dropped), so the shadow
// run can never fill the disk.
type rotating struct {
	path string
	max  int64
	f    *os.File
	n    int64
}

func openRotating(path string, maxMB int) (*rotating, error) {
	r := &rotating{path: path, max: int64(maxMB) << 20}
	return r, r.open()
}

func (r *rotating) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	r.f, r.n = f, st.Size()
	return nil
}

// rotateIfFull is called between whole events (after the buffer is flushed), so a line is never cut in two.
func (r *rotating) rotateIfFull(pending int) {
	if r.max <= 0 || r.n+int64(pending) <= r.max {
		return
	}
	r.f.Close()
	_ = os.Rename(r.path, r.path+".1")
	_ = r.open()
}

func (r *rotating) Write(p []byte) (int, error) {
	n, err := r.f.Write(p)
	r.n += int64(n)
	return n, err
}

func writeStats(path string, v any) {
	j, _ := json.MarshalIndent(v, "", " ")
	tmp := path + ".tmp"
	if os.WriteFile(tmp, j, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

func listenMode(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	cfgFile := fs.String("config", "", "the engine's config.json (syslog + sources), read only")
	outFile := fs.String("out", "-", "where events go (- = stdout, empty = count only)")
	maxMB := fs.Int("max-out-mb", 0, "rotate the event file at this size (0 = never)")
	every := fs.Duration("stats-every", 0, "print stats to stderr this often")
	statsFile := fs.String("stats-file", "", "also write the stats to this file (atomically) at each -stats-every")
	udpPort := fs.Int("udp-port", -1, "listen on this UDP port instead of the config's (0 = off)")
	tcpPort := fs.Int("tcp-port", -1, "listen on this TCP port instead of the config's (0 = off)")
	noTLS := fs.Bool("no-tls", false, "do not open the TLS listener")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*cfgFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sc, err := syslog.LoadEngineConfig(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	off := false
	if *udpPort == 0 {
		sc.UDP.Enabled = &off
	} else if *udpPort > 0 {
		sc.UDP.Port, sc.UDP.Enabled = *udpPort, nil
	}
	if *tcpPort == 0 {
		sc.TCP.Enabled = &off
	} else if *tcpPort > 0 {
		sc.TCP.Port, sc.TCP.Enabled = *tcpPort, nil
	}
	if *noTLS {
		sc.TLS.Enabled = false
	}
	var w io.Writer = io.Discard
	var rf *rotating
	if *outFile == "-" {
		w = os.Stdout
	} else if *outFile != "" {
		rf, err = openRotating(*outFile, *maxMB)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		w = rf
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	var mu sync.Mutex
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	srv := syslog.New(sc, func(ev *parse.Event, h *syslog.Handback) {
		mu.Lock()
		defer mu.Unlock()
		if ev != nil {
			j, _ := ev.MarshalJSON() // written as is: re-encoding through json.Encoder would validate it twice
			_, _ = bw.WriteString(`{"event":`)
			_, _ = bw.Write(j)
			_, _ = bw.WriteString("}\n")
		} else {
			_ = enc.Encode(map[string]any{"handback": h})
		}
		if rf != nil && rf.max > 0 && rf.n+int64(bw.Buffered()) > rf.max {
			_ = bw.Flush()
			rf.rotateIfFull(0)
		}
	})
	srv.Logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
	if err := srv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	j, _ := json.Marshal(srv.Listeners)
	fmt.Fprintf(os.Stderr, "LISTENING %s\n", j)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	tick := make(<-chan time.Time)
	if *every > 0 {
		tick = time.NewTicker(*every).C
	}
	flush := time.NewTicker(time.Second)
	started := time.Now().UTC().Format(time.RFC3339)
	report := func() {
		st := srv.Stats()
		st["started"] = started
		st["at"] = time.Now().UTC().Format(time.RFC3339)
		s, _ := json.Marshal(st)
		fmt.Fprintf(os.Stderr, "STATS %s\n", s)
		if *statsFile != "" {
			writeStats(*statsFile, st)
		}
	}
	for {
		select {
		case <-tick:
			report()
		case <-flush.C:
			mu.Lock()
			_ = bw.Flush()
			mu.Unlock()
		case <-stop:
			srv.Stop()
			mu.Lock()
			_ = bw.Flush()
			mu.Unlock()
			report()
			return
		}
	}
}
