// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

// Package jsrt holds the JavaScript rules a port keeps so the Go engine answers exactly like the Node.js one:
// JavaScript's whitespace (\s, trim), UTF-16 lengths and slices, parseInt, Number → String, the WHATWG UTF-8
// decoder Buffer.toString('utf8') uses, ASCII-only /i matching, and an object whose key order is JavaScript's
// (integer-like keys first, ascending, then insertion order).
package jsrt

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// WS is JavaScript's \s (WhiteSpace + LineTerminator) as a regexp character-class body.
const WS = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// IsWS: one rune of JavaScript's \s.
func IsWS(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// Trim is String.prototype.trim.
func Trim(s string) string { return strings.TrimFunc(s, IsWS) }

// TrimLeft is s.replace(/^\s+/, ”).
func TrimLeft(s string) string { return strings.TrimLeftFunc(s, IsWS) }

// Lower is String.prototype.toLowerCase: Unicode lower case plus the two context rules Go does not apply
// (İ → i + combining dot, final sigma).
func Lower(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(s)
	}
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		switch {
		case r == 0x130:
			b.WriteString("i̇")
		case r == 0x3a3 && finalSigma(rs, i):
			b.WriteRune(0x3c2)
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func finalSigma(rs []rune, i int) bool {
	before := false
	for j := i - 1; j >= 0; j-- {
		if unicode.Is(unicode.Mn, rs[j]) {
			continue
		}
		before = unicode.IsLetter(rs[j])
		break
	}
	if !before {
		return false
	}
	for j := i + 1; j < len(rs); j++ {
		if unicode.Is(unicode.Mn, rs[j]) {
			continue
		}
		return !unicode.IsLetter(rs[j])
	}
	return true
}

// Upper is String.prototype.toUpperCase for what parsers upper-case (HTTP methods): ß becomes SS as in JavaScript.
func Upper(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "ß", "SS")) }

// LowerASCII folds A-Z only, the way a JavaScript /i regexp without the u flag compares ASCII text.
func LowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// ContainsFold is /needle/i.test(s) for an ASCII needle.
func ContainsFold(s, needle string) bool { return strings.Contains(LowerASCII(s), needle) }

// U16Len is a JavaScript string's .length (UTF-16 code units).
func U16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// U16Slice is s.slice(0, n). A cut through a surrogate pair drops the half pair (JavaScript would keep a lone
// surrogate, which UTF-8 cannot hold; the parity test documents this as the one known difference).
func U16Slice(s string, n int) string {
	if n <= 0 {
		return ""
	}
	c := 0
	for i, r := range s {
		w := 1
		if r >= 0x10000 {
			w = 2
		}
		if c+w > n {
			return s[:i]
		}
		c += w
	}
	return s
}

// ParseInt is parseInt(s, 10): leading JavaScript whitespace, a sign, the longest run of digits; NaN when there is none.
func ParseInt(s string) float64 {
	s = TrimLeft(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return math.NaN()
	}
	f, err := strconv.ParseFloat(s[:i], 64)
	if err != nil && !math.IsInf(f, 0) {
		return math.NaN()
	}
	if neg {
		f = -f
	}
	return f
}

// Number is Number(s) for the digit strings the parsers feed it ("123", "123.45").
func Number(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !math.IsInf(f, 0) {
		return math.NaN()
	}
	return f
}

// NumString is String(n) for a JavaScript number.
func NumString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	a := math.Abs(f)
	if a >= 1e-6 && a < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // 1e+21, 1.5e-07
	if i := strings.IndexAny(s, "+-"); i > 0 && s[i-1] == 'e' {
		exp := strings.TrimLeft(s[i+1:], "0")
		if exp == "" {
			exp = "0"
		}
		s = s[:i+1] + exp
	}
	return s
}

// DecodeUTF8 is Buffer.toString('utf8'): the WHATWG decoder, one U+FFFD per maximal invalid subpart.
func DecodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b) + 8)
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			sb.WriteByte(c)
			i++
			continue
		}
		need, lo, hi := 0, byte(0x80), byte(0xbf)
		switch {
		case c >= 0xc2 && c <= 0xdf:
			need = 1
		case c == 0xe0:
			need, lo = 2, 0xa0
		case c >= 0xe1 && c <= 0xec, c == 0xee, c == 0xef:
			need = 2
		case c == 0xed:
			need, hi = 2, 0x9f
		case c == 0xf0:
			need, lo = 3, 0x90
		case c >= 0xf1 && c <= 0xf3:
			need = 3
		case c == 0xf4:
			need, hi = 3, 0x8f
		default:
			sb.WriteRune(utf8.RuneError)
			i++
			continue
		}
		j := i + 1
		ok := true
		for k := 0; k < need; k++ {
			if j >= len(b) {
				ok = false
				break
			}
			l, h := byte(0x80), byte(0xbf)
			if k == 0 {
				l, h = lo, hi
			}
			if b[j] < l || b[j] > h {
				ok = false
				break
			}
			j++
		}
		if !ok {
			sb.WriteRune(utf8.RuneError)
			i = j
			continue
		}
		sb.Write(b[i:j])
		i = j
	}
	return sb.String()
}

// ProtoName: the names an object literal answers for keys it never had (Object.prototype). A Go port must not
// pretend these are absent; callers hand such input back to Node.js.
var ProtoName = map[string]bool{"constructor": true, "__proto__": true, "hasOwnProperty": true, "isPrototypeOf": true,
	"propertyIsEnumerable": true, "toLocaleString": true, "toString": true, "valueOf": true, "__defineGetter__": true,
	"__defineSetter__": true, "__lookupGetter__": true, "__lookupSetter__": true}

// OMap is a plain JavaScript object of strings: own keys in JavaScript order. Kept as a slice of pairs (log lines
// carry tens of keys, where a scan beats a hash map); an index map is built once it grows past 48 keys.
type OMap struct {
	ks     []string
	vs     []string
	idx    map[string]int
	hasIdx bool // some key is integer-like (Keys must reorder)
}

func NewOMap() *OMap { return &OMap{ks: make([]string, 0, 32), vs: make([]string, 0, 32)} }

func (o *OMap) find(k string) int {
	if o.idx != nil {
		if i, ok := o.idx[k]; ok {
			return i
		}
		return -1
	}
	for i, x := range o.ks {
		if x == k {
			return i
		}
	}
	return -1
}

// Set is o[k] = v ("__proto__" = a string is a no-op in JavaScript).
func (o *OMap) Set(k, v string) {
	if k == "__proto__" {
		return
	}
	if i := o.find(k); i >= 0 {
		o.vs[i] = v
		return
	}
	o.ks = append(o.ks, k)
	o.vs = append(o.vs, v)
	if !o.hasIdx && ArrayIndex(k) {
		o.hasIdx = true
	}
	if o.idx != nil {
		o.idx[k] = len(o.ks) - 1
	} else if len(o.ks) > 48 {
		o.idx = make(map[string]int, 2*len(o.ks))
		for i, x := range o.ks {
			o.idx[x] = i
		}
	}
}

func (o *OMap) Get(k string) (string, bool) {
	if i := o.find(k); i >= 0 {
		return o.vs[i], true
	}
	return "", false
}

// S is o[k] read as a string (” when absent).
func (o *OMap) S(k string) string {
	if i := o.find(k); i >= 0 {
		return o.vs[i]
	}
	return ""
}

func (o *OMap) Has(k string) bool { return o.find(k) >= 0 }

func (o *OMap) Del(k string) {
	i := o.find(k)
	if i < 0 {
		return
	}
	o.ks = append(o.ks[:i], o.ks[i+1:]...)
	o.vs = append(o.vs[:i], o.vs[i+1:]...)
	if o.idx != nil {
		delete(o.idx, k)
		for j := i; j < len(o.ks); j++ {
			o.idx[o.ks[j]] = j
		}
	}
}

func (o *OMap) Len() int { return len(o.ks) }

// Keys is Object.keys(o). The slice is a copy: callers may delete while they walk it.
func (o *OMap) Keys() []string {
	if !o.hasIdx {
		return append([]string(nil), o.ks...)
	}
	var idx, rest []string
	for _, k := range o.ks {
		if ArrayIndex(k) {
			idx = append(idx, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.Slice(idx, func(a, b int) bool {
		if len(idx[a]) != len(idx[b]) {
			return len(idx[a]) < len(idx[b])
		}
		return idx[a] < idx[b]
	})
	return append(idx, rest...)
}

// Each calls fn for every key and value in JavaScript order (no copy when no key is integer-like).
func (o *OMap) Each(fn func(k, v string)) {
	if !o.hasIdx {
		for i, k := range o.ks {
			fn(k, o.vs[i])
		}
		return
	}
	for _, k := range o.Keys() {
		fn(k, o.S(k))
	}
}

// ArrayIndex: a key JavaScript orders first ("0", or no leading zero, below 2^32 - 1).
func ArrayIndex(k string) bool {
	if k == "" || len(k) > 10 || (len(k) > 1 && k[0] == '0') {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < '0' || k[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(k, 10, 64)
	return err == nil && n < 4294967295
}

// U16 returns the UTF-16 code units of s (for code that indexes like JavaScript).
func U16(s string) []uint16 { return utf16.Encode([]rune(s)) }
