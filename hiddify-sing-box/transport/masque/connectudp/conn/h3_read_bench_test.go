package conn

import (
	"context"
	"testing"

	"github.com/quic-go/quic-go"
)

// mockH3Stream feeds HTTP/3 datagram payloads for ReadFrom CPU isolation.
type mockH3Stream struct {
	ch chan []byte
}

func (m *mockH3Stream) Read([]byte) (int, error)  { return 0, nil }
func (m *mockH3Stream) Write([]byte) (int, error) { return 0, nil }
func (m *mockH3Stream) Close() error              { return nil }
func (m *mockH3Stream) CancelRead(quic.StreamErrorCode) {}
func (m *mockH3Stream) SendDatagram([]byte) error { return nil }
func (m *mockH3Stream) TryReceiveDatagram() ([]byte, bool) {
	select {
	case b := <-m.ch:
		return b, true
	default:
		return nil, false
	}
}
func (m *mockH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b := <-m.ch:
		return b, nil
	}
}

func benchH3ConnReadFrom(b *testing.B, payloadLen int) {
	wire := make([]byte, 1+payloadLen)
	wire[0] = 0
	m := &mockH3Stream{ch: make(chan []byte, 64)}
	c := NewH3Conn(m, masqueAddr{"local"}, masqueAddr{"remote"})
	buf := make([]byte, payloadLen+64)

	b.SetBytes(int64(payloadLen))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dup := append([]byte(nil), wire...)
		m.ch <- dup
		if _, _, err := c.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkH3ConnReadFrom512 profiles client S2C ReadFrom hot path @512 B (masque-go blocking recv).
func BenchmarkH3ConnReadFrom512(b *testing.B) {
	benchH3ConnReadFrom(b, 512)
}
