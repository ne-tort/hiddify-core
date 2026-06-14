package connectudp

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
)

const (
	datagramSplitBenchPayloadLen = DefaultBenchUDPPayloadLen
	datagramSplitMaxNsPerB     = 800.0
	parseHTTPDatagramMaxNsPerOp  = 200.0
)

var benchParseHTTPDatagramSample = []byte{0x00, 0x01, 0x02, 0x03}

// BenchmarkConnectUDPDatagramSplitWrite profiles CONNECT-UDP H2 split WriteTo hot path.
func BenchmarkConnectUDPDatagramSplitWrite(b *testing.B) {
	stub := &stubPacketConn{failAfterNWrites: -1}
	conn := NewDatagramSplitConn(stub, DatagramSplitOptions{
		MaxPayload: 1200,
		HTTPLayer:  option.MasqueHTTPLayerH2,
	})
	payload := make([]byte, datagramSplitBenchPayloadLen)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.WriteTo(payload, addr); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConnectUDPParseHTTPDatagramUDP profiles RFC 9297 payload parse hot path.
func BenchmarkConnectUDPParseHTTPDatagramUDP(b *testing.B) {
	sample := benchParseHTTPDatagramSample
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, err := ParseHTTPDatagramUDP(sample); !ok || err != nil {
			b.Fatalf("parse: ok=%v err=%v", ok, err)
		}
	}
}

func assertConnectUDPUnitCPUBudget(t *testing.T, name string, bench func(*testing.B), maxNsPerB float64, nbytes int64) {
	t.Helper()
	result := testing.Benchmark(bench)
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations: " + name)
	}
	nsPerByte := float64(result.NsPerOp()) / float64(nbytes)
	if nsPerByte > maxNsPerB {
		t.Fatalf("connectudp %s CPU budget: %.1f ns/B > %.0f ns/B", name, nsPerByte, maxNsPerB)
	}
	t.Logf("connectudp %s CPU: %.1f ns/B", name, nsPerByte)
}

// TestConnectUDPDatagramSplitCPUBudget locks DatagramSplitConn WriteTo ns/byte ceiling.
func TestConnectUDPDatagramSplitCPUBudget(t *testing.T) {
	assertConnectUDPUnitCPUBudget(t, "DatagramSplitWrite", func(b *testing.B) {
		stub := &stubPacketConn{failAfterNWrites: -1}
		conn := NewDatagramSplitConn(stub, DatagramSplitOptions{
			MaxPayload: 1200,
			HTTPLayer:  option.MasqueHTTPLayerH2,
		})
		payload := make([]byte, datagramSplitBenchPayloadLen)
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := conn.WriteTo(payload, addr); err != nil {
				b.Fatal(err)
			}
		}
	}, datagramSplitMaxNsPerB, int64(datagramSplitBenchPayloadLen))
}

// TestConnectUDPParseHTTPDatagramCPUBudget locks ParseHTTPDatagramUDP ns/op ceiling.
func TestConnectUDPParseHTTPDatagramCPUBudget(t *testing.T) {
	sample := benchParseHTTPDatagramSample
	assertConnectUDPUnitCPUBudget(t, "ParseHTTPDatagramUDP", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, ok, err := ParseHTTPDatagramUDP(sample); !ok || err != nil {
				b.Fatal(err)
			}
		}
	}, parseHTTPDatagramMaxNsPerOp, 1)
}
