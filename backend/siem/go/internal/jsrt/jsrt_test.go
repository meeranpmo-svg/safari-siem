// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.

package jsrt

import (
	"math"
	"reflect"
	"testing"
)

// The expected values are what Node.js 22 prints for the same input (String(n), parseInt, Buffer.toString,
// Object.keys); the parity test in tests/go-fortigate-parity.test.js checks them end to end as well.
func TestNumString(t *testing.T) {
	for in, want := range map[float64]string{1792578930123: "1792578930123", 1e21: "1e+21", 1.5e-7: "1.5e-7", 0.5: "0.5", -12: "-12", 1e19: "10000000000000000000"} {
		if got := NumString(in); got != want {
			t.Errorf("NumString(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestParseInt(t *testing.T) {
	for in, want := range map[string]float64{" 80": 80, "443abc": 443, "-1": -1, "+7": 7, "1e3": 1} {
		if got := ParseInt(in); got != want {
			t.Errorf("ParseInt(%q) = %v, want %v", in, got, want)
		}
	}
	if !math.IsNaN(ParseInt("abc")) || !math.IsNaN(ParseInt("")) {
		t.Error("no digits must be NaN")
	}
}

func TestDecodeUTF8(t *testing.T) {
	// Buffer.from([0x61,0xe2,0x82,0x20,0xff,0xf0,0x9f,0x98,0x80,0xed,0xa0,0x80]).toString('utf8')
	got := DecodeUTF8([]byte{0x61, 0xe2, 0x82, 0x20, 0xff, 0xf0, 0x9f, 0x98, 0x80, 0xed, 0xa0, 0x80})
	if want := "a� �😀���"; got != want {
		t.Errorf("DecodeUTF8 = %q, want %q", got, want)
	}
}

func TestOMapOrder(t *testing.T) {
	o := NewOMap()
	for _, k := range []string{"b", "10", "a", "2", "01", "__proto__", "4294967295"} {
		o.Set(k, "x")
	}
	o.Set("b", "y") // keeps its place
	if got, want := o.Keys(), []string{"2", "10", "b", "a", "01", "4294967295"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Keys = %v, want %v", got, want)
	}
	o.Del("a")
	if o.Has("a") || o.S("b") != "y" {
		t.Error("Del / Set")
	}
}

func TestLowerTrim(t *testing.T) {
	if got := Lower("İSTANBUL ΟΔΥΣΣΕΑΣ"); got != "i̇stanbul οδυσσεας" {
		t.Errorf("Lower = %q", got)
	}
	if got := Trim(" \ufeff x 　"); got != "x" {
		t.Errorf("Trim = %q", got)
	}
}
