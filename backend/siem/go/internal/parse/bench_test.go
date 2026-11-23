package parse

import (
	"os"
	"strings"
	"testing"
)

func BenchmarkParse(b *testing.B) {
	raw, err := os.ReadFile(os.Getenv("SENTRA_BENCH_LINES"))
	if err != nil {
		b.Skip("SENTRA_BENCH_LINES not set")
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	m := Meta{Collector: "syslog-udp", SrcID: "fw1", SrcType: "fortigate", PeerIP: "10.0.0.1", Rts: 1792605600000}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := Parse(lines[i%len(lines)], m)
		if r.Event != nil {
			_, _ = r.Event.MarshalJSON()
		}
	}
}
