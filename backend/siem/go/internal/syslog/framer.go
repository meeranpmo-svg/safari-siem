// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

// Package syslog is the Go port of collect/syslog.js: UDP, TCP (LF framing and RFC 6587 octet counting,
// auto-detected per connection) and TLS listeners with the same connection limits, source lookup and counters.
package syslog

import "bytes"

// Framer is createFramer(maxLine, onFrame). The mode is decided on a connection's first frame: "octet" if it starts
// with `<digits> <`, otherwise "lf". In octet mode a frame that does not start with digits is read as LF for that frame.
type Framer struct {
	maxLine  int
	onFrame  func(b []byte, truncated bool)
	buf      []byte
	mode     string
	skip     int
	dropToLF bool
}

func NewFramer(maxLine int, onFrame func([]byte, bool)) *Framer {
	return &Framer{maxLine: maxLine, onFrame: onFrame}
}

func (f *Framer) Mode() string { return f.mode }

func (f *Framer) emit(b []byte, truncated bool) {
	end := len(b)
	for end > 0 && (b[end-1] == 10 || b[end-1] == 13 || b[end-1] == 0) {
		end--
	}
	if end > 0 {
		f.onFrame(b[:end], truncated)
	}
}

// Push feeds one chunk read from the socket.
func (f *Framer) Push(chunk []byte) {
	if len(f.buf) > 0 {
		f.buf = append(f.buf, chunk...)
	} else {
		f.buf = append([]byte(nil), chunk...)
	}
	buf := f.buf
	off, n := 0, len(buf)
	for off < n {
		if f.skip > 0 {
			k := f.skip
			if n-off < k {
				k = n - off
			}
			off += k
			f.skip -= k
			continue
		}
		if f.dropToLF {
			nl := bytes.IndexByte(buf[off:], 10)
			if nl < 0 {
				off = n
				break
			}
			off += nl + 1
			f.dropToLF = false
			continue
		}
		c := buf[off]
		if c == 10 || c == 13 || c == 0 || c == 32 {
			off++
			continue
		}
		if c >= 0x31 && c <= 0x39 && f.mode != "lf" {
			j, ln := off, 0
			for j < n && j-off < 8 && buf[j] >= 0x30 && buf[j] <= 0x39 {
				ln = ln*10 + int(buf[j]-0x30)
				j++
			}
			if j >= n {
				if j-off < 8 {
					break // need more bytes to decide
				}
			} else if buf[j] == 0x20 {
				if f.mode == "" {
					if j+1 >= n {
						break
					}
					if buf[j+1] == 0x3c {
						f.mode = "octet"
					}
				}
				if f.mode == "octet" {
					start := j + 1
					if ln > f.maxLine {
						if n-start < f.maxLine {
							break
						}
						f.emit(buf[start:start+f.maxLine], true)
						off = start + f.maxLine
						f.skip = ln - f.maxLine
						continue
					}
					if n-start < ln {
						break
					}
					f.emit(buf[start:start+ln], false)
					off = start + ln
					continue
				}
			}
		}
		// LF framing
		if f.mode == "" {
			f.mode = "lf"
		}
		nl := bytes.IndexByte(buf[off:], 10)
		if nl < 0 {
			if n-off > f.maxLine {
				f.emit(buf[off:off+f.maxLine], true)
				off = n
				f.dropToLF = true
			}
			break
		}
		nl += off
		if nl-off > f.maxLine {
			f.emit(buf[off:off+f.maxLine], true)
		} else {
			f.emit(buf[off:nl], false)
		}
		off = nl + 1
	}
	if off >= n {
		f.buf = nil
	} else {
		f.buf = append([]byte(nil), buf[off:]...)
	}
	if f.buf != nil && len(f.buf) > f.maxLine*2+16 {
		f.emit(f.buf[:f.maxLine], true)
		f.buf = nil
		f.dropToLF = f.mode != "octet"
	}
}

// End flushes what is left when the connection closes.
func (f *Framer) End() {
	if len(f.buf) > 0 && f.skip == 0 && !f.dropToLF {
		if len(f.buf) > f.maxLine {
			f.emit(f.buf[:f.maxLine], true)
		} else {
			f.emit(f.buf, false)
		}
	}
	f.buf = nil
}
