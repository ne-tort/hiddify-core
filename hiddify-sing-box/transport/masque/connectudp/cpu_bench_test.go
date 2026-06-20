package connectudp

import (
	"bytes"
	"net"
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/option"
)

const (
	datagramSplitBenchPayloadLen = DefaultBenchUDPPayloadLen
	datagramSplitMaxNsPerB       = 800.0
	parseHTTPDatagramMaxNsPerOp    = 200.0
	capsuleEncodeMaxNsPerB         = 800.0
	capsuleScanMaxNsPerB           = 800.0
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

// TestConnectUDPH2CapsuleEncodeCPUBudget locks RFC9297 encode ns/byte for one 512 B datagram.
func TestConnectUDPH2CapsuleEncodeCPUBudget(t *testing.T) {
	payload := make([]byte, datagramSplitBenchPayloadLen)
	assertConnectUDPUnitCPUBudget(t, "H2CapsuleEncode512B", func(b *testing.B) {
		var pending bytes.Buffer
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pending.Reset()
			if err := h2c.AppendUDPPayloadAsDatagramCapsules(&pending, payload); err != nil {
				b.Fatal(err)
			}
		}
	}, capsuleEncodeMaxNsPerB, int64(datagramSplitBenchPayloadLen))
}

// TestConnectUDPH2CapsuleScanCPUBudget locks inline server scan ns/byte on batched wire.
func TestConnectUDPH2CapsuleScanCPUBudget(t *testing.T) {
	payload := make([]byte, datagramSplitBenchPayloadLen)
	var wire bytes.Buffer
	if err := h2c.AppendUDPPayloadAsDatagramCapsules(&wire, payload); err != nil {
		t.Fatal(err)
	}
	batch := wire.Bytes()
	assertConnectUDPUnitCPUBudget(t, "H2CapsuleScan512B", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := batch
			for len(buf) > 0 {
				inner, n, err := h2c.ParseNextDatagramCapsuleWire(buf)
				if err != nil {
					b.Fatal(err)
				}
				if n == 0 {
					b.Fatal("truncated batch")
				}
				buf = buf[n:]
				if inner == nil {
					continue
				}
				if _, ok, perr := ParseHTTPDatagramUDP(inner); !ok || perr != nil {
					b.Fatal(perr)
				}
			}
		}
	}, capsuleScanMaxNsPerB, int64(datagramSplitBenchPayloadLen))
}
