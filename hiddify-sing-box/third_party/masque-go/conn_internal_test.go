package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

type testHTTP3Stream struct {
	datagrams chan []byte
}

func (s *testHTTP3Stream) Read([]byte) (int, error)        { return 0, io.EOF }
func (s *testHTTP3Stream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *testHTTP3Stream) Close() error                    { return nil }
func (s *testHTTP3Stream) SendDatagram([]byte) error       { return nil }
func (s *testHTTP3Stream) CancelRead(quic.StreamErrorCode) {}
func (s *testHTTP3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case d := <-s.datagrams:
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (s *testHTTP3Stream) TryReceiveDatagram() ([]byte, bool) {
	select {
	case d := <-s.datagrams:
		return d, true
	default:
		return nil, false
	}
}

type dropStormHTTP3Stream struct{}

func (s *dropStormHTTP3Stream) Read([]byte) (int, error)        { return 0, io.EOF }
func (s *dropStormHTTP3Stream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *dropStormHTTP3Stream) Close() error                    { return nil }
func (s *dropStormHTTP3Stream) SendDatagram([]byte) error       { return nil }
func (s *dropStormHTTP3Stream) CancelRead(quic.StreamErrorCode) {}
func (s *dropStormHTTP3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *dropStormHTTP3Stream) TryReceiveDatagram() ([]byte, bool) {
	return []byte{0x01}, true
}

type scriptedHTTP3Stream struct {
	receiveSeq [][]byte
	trySeq     [][]byte
	recvIdx    int
	tryIdx     int
}

func (s *scriptedHTTP3Stream) Read([]byte) (int, error)        { return 0, io.EOF }
func (s *scriptedHTTP3Stream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *scriptedHTTP3Stream) Close() error                    { return nil }
func (s *scriptedHTTP3Stream) SendDatagram([]byte) error       { return nil }
func (s *scriptedHTTP3Stream) CancelRead(quic.StreamErrorCode) {}
func (s *scriptedHTTP3Stream) ReceiveDatagram(context.Context) ([]byte, error) {
	if s.recvIdx >= len(s.receiveSeq) {
		return nil, io.EOF
	}
	d := s.receiveSeq[s.recvIdx]
	s.recvIdx++
	return d, nil
}
func (s *scriptedHTTP3Stream) TryReceiveDatagram() ([]byte, bool) {
	if s.tryIdx >= len(s.trySeq) {
		return nil, false
	}
	d := s.trySeq[s.tryIdx]
	s.tryIdx++
	return d, true
}

type receiveOnlyHTTP3Stream struct {
	receiveSeq [][]byte
	recvIdx    int
}

func (s *receiveOnlyHTTP3Stream) Read([]byte) (int, error)        { return 0, io.EOF }
func (s *receiveOnlyHTTP3Stream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *receiveOnlyHTTP3Stream) Close() error                    { return nil }
func (s *receiveOnlyHTTP3Stream) SendDatagram([]byte) error       { return nil }
func (s *receiveOnlyHTTP3Stream) CancelRead(quic.StreamErrorCode) {}
func (s *receiveOnlyHTTP3Stream) ReceiveDatagram(context.Context) ([]byte, error) {
	if s.recvIdx >= len(s.receiveSeq) {
		return nil, io.EOF
	}
	d := s.receiveSeq[s.recvIdx]
	s.recvIdx++
	return d, nil
}

func TestParseProxiedDatagramPayload(t *testing.T) {
	t.Run("context zero fast path", func(t *testing.T) {
		payload, ok, err := parseProxiedDatagramPayload([]byte{0x00, 0xaa, 0xbb})
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, []byte{0xaa, 0xbb}, payload)
	})

	t.Run("unknown context id", func(t *testing.T) {
		raw := quicvarint.Append(nil, 37)
		raw = append(raw, 0xaa)
		payload, ok, err := parseProxiedDatagramPayload(raw)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, payload)
	})
	t.Run("unknown context id two-byte highbits fast reject", func(t *testing.T) {
		payload, ok, err := parseProxiedDatagramPayload([]byte{0x45, 0x00, 0xaa})
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, payload)
	})
	t.Run("context zero two-byte fast path", func(t *testing.T) {
		payload, ok, err := parseProxiedDatagramPayload([]byte{0x40, 0x00, 0xaa})
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, []byte{0xaa}, payload)
	})
	t.Run("unknown context id two-byte lowbits fast reject", func(t *testing.T) {
		payload, ok, err := parseProxiedDatagramPayload([]byte{0x40, 0x01, 0xaa})
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, payload)
	})

	t.Run("malformed datagram", func(t *testing.T) {
		_, _, err := parseProxiedDatagramPayload(nil)
		require.ErrorIs(t, err, io.EOF)
	})
}

func BenchmarkParseProxiedDatagramPayload(b *testing.B) {
	b.Run("context_zero_fast_path", func(b *testing.B) {
		raw := []byte{0x00, 0xaa, 0xbb, 0xcc}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, ok, err := parseProxiedDatagramPayload(raw)
			if err != nil || !ok {
				b.Fatal("unexpected parse result")
			}
		}
	})

	b.Run("context_non_zero_varint", func(b *testing.B) {
		raw := quicvarint.Append(nil, 37)
		raw = append(raw, 0xaa, 0xbb, 0xcc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, ok, err := parseProxiedDatagramPayload(raw)
			if err != nil || ok {
				b.Fatal("unexpected parse result")
			}
		}
	})

	b.Run("context_non_zero_two_byte_varint", func(b *testing.B) {
		raw := quicvarint.Append(nil, 1337)
		raw = append(raw, 0xaa, 0xbb, 0xcc)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, ok, err := parseProxiedDatagramPayload(raw)
			if err != nil || ok {
				b.Fatal("unexpected parse result")
			}
		}
	})
	b.Run("context_non_zero_two_byte_highbits", func(b *testing.B) {
		raw := []byte{0x45, 0xaa, 0xbb, 0xcc}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, ok, err := parseProxiedDatagramPayload(raw)
			if err != nil || ok {
				b.Fatal("unexpected parse result")
			}
		}
	})
	b.Run("context_zero_two_byte", func(b *testing.B) {
		raw := []byte{0x40, 0x00, 0xaa, 0xbb}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, ok, err := parseProxiedDatagramPayload(raw)
			if err != nil || !ok {
				b.Fatal("unexpected parse result")
			}
		}
	})
}

func BenchmarkExtractContextZeroPayloadForUDP(b *testing.B) {
	b.Run("context_zero_fast_path", func(b *testing.B) {
		raw := []byte{0x00, 0xaa, 0xbb, 0xcc}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, result := extractContextZeroPayloadForUDP(raw)
			if result != udpPayloadAccept || len(payload) != 3 {
				b.Fatal("unexpected extract result")
			}
		}
	})

	b.Run("context_non_zero_single_byte_fast_reject", func(b *testing.B) {
		raw := []byte{0x25, 0xaa, 0xbb, 0xcc}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, result := extractContextZeroPayloadForUDP(raw)
			if result != udpPayloadDropUnknownContext || payload != nil {
				b.Fatal("unexpected extract result")
			}
		}
	})

	b.Run("context_zero_two_byte", func(b *testing.B) {
		raw := []byte{0x40, 0x00, 0xaa, 0xbb}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, result := extractContextZeroPayloadForUDP(raw)
			if result != udpPayloadAccept || len(payload) != 2 {
				b.Fatal("unexpected extract result")
			}
		}
	})

	b.Run("context_non_zero_two_byte_lowbits_fast_reject", func(b *testing.B) {
		raw := []byte{0x40, 0x01, 0xaa, 0xbb}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, result := extractContextZeroPayloadForUDP(raw)
			if result != udpPayloadDropUnknownContext || payload != nil {
				b.Fatal("unexpected extract result")
			}
		}
	})

	b.Run("context_zero_four_byte", func(b *testing.B) {
		raw := []byte{0x80, 0x00, 0x00, 0x00, 0xaa, 0xbb}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, result := extractContextZeroPayloadForUDP(raw)
			if result != udpPayloadAccept || len(payload) != 2 {
				b.Fatal("unexpected extract result")
			}
		}
	})

	b.Run("context_non_zero_four_byte_lowbits_fast_reject", func(b *testing.B) {
		raw := []byte{0x80, 0x00, 0x00, 0x01, 0xaa, 0xbb}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, result := extractContextZeroPayloadForUDP(raw)
			if result != udpPayloadDropUnknownContext || payload != nil {
				b.Fatal("unexpected extract result")
			}
		}
	})
}

func TestReadFromSkipsMalformedDatagrams(t *testing.T) {
	stream := &testHTTP3Stream{datagrams: make(chan []byte, 2)}
	conn := newProxiedConn(stream, masqueAddr{"local"}, masqueAddr{"remote"})
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))

	stream.datagrams <- nil
	stream.datagrams <- []byte{0x00, 0xaa, 0xbb}

	buf := make([]byte, 16)
	n, addr, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte{0xaa, 0xbb}, buf[:n])
	require.Equal(t, net.Addr(masqueAddr{"remote"}), addr)
}

func TestProxyConnSendForcesTryDrainAfterDropWhenGateSkips(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	stream := &scriptedHTTP3Stream{
		receiveSeq: [][]byte{
			{0x00, 0xaa}, // context-id=0 payload; first drain probe is empty, gate enters skip state.
			{0x25, 0xff}, // non-zero context; should force bounded try-drain regardless of skip budget.
		},
		trySeq: [][]byte{
			{0x00, 0xbb}, // queued valid payload must be forwarded despite gate skip budget.
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- (&Proxy{}).proxyConnSend(client, stream)
	}()

	require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 16)
	n, _, err := server.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, []byte{0xaa}, buf[:n])

	n, _, err = server.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, []byte{0xbb}, buf[:n])

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("proxyConnSend did not exit")
	}
}

func TestProxyConnSendWithoutDrainerFastPath(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	stream := &receiveOnlyHTTP3Stream{
		receiveSeq: [][]byte{
			{0x00, 0xaa}, // valid context-id=0 payload
			{0x25, 0xbb}, // unknown context; must be dropped without affecting liveness
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- (&Proxy{}).proxyConnSend(client, stream)
	}()

	require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 16)
	n, _, err := server.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, []byte{0xaa}, buf[:n])

	// Unknown-context datagram is dropped: no second UDP payload must arrive.
	require.NoError(t, server.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err = server.ReadFromUDP(buf)
	require.Error(t, err)
	var netErr net.Error
	require.True(t, errors.As(err, &netErr) && netErr.Timeout())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("proxyConnSend did not exit")
	}
}

func TestReadFromDeadlineExceededDuringPrefetchDropStorm(t *testing.T) {
	stream := &dropStormHTTP3Stream{}
	conn := newProxiedConn(stream, masqueAddr{"local"}, masqueAddr{"remote"})
	t.Cleanup(func() { _ = conn.Close() })
	conn.prefetchSlots[0] = []byte{0x01}
	conn.prefetchCount = 1
	conn.prefetchCountAtomic.Store(1)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Millisecond)))

	done := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(make([]byte, 1500))
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("ReadFrom blocked on prefetch drop storm after deadline")
	}
}

func TestAdaptiveTryDrainGate(t *testing.T) {
	t.Run("backs off after consecutive empty probes", func(t *testing.T) {
		var gate adaptiveTryDrainGate
		require.True(t, gate.shouldProbe())
		gate.observeDrain(0)
		require.Equal(t, 1, gate.skipBudgetValue())

		require.False(t, gate.shouldProbe())
		require.True(t, gate.shouldProbe())
		gate.observeDrain(0)
		require.Equal(t, 2, gate.skipBudgetValue())

		require.False(t, gate.shouldProbe())
		require.False(t, gate.shouldProbe())
		require.True(t, gate.shouldProbe())
		gate.observeDrain(0)
		require.Equal(t, 4, gate.skipBudgetValue())
	})

	t.Run("resets backoff immediately when backlog appears", func(t *testing.T) {
		var gate adaptiveTryDrainGate
		gate.observeDrain(0)
		require.Equal(t, 1, gate.skipBudgetValue())
		require.False(t, gate.shouldProbe())
		require.True(t, gate.shouldProbe())
		gate.observeDrain(8)
		require.Equal(t, 0, gate.skipBudgetValue())
		require.True(t, gate.shouldProbe())
	})

	t.Run("caps maximum skip budget", func(t *testing.T) {
		var gate adaptiveTryDrainGate
		for i := 0; i < 32; i++ {
			gate.observeDrain(0)
		}
		require.Equal(t, proxyConnDrainProbeMaxSkip, gate.skipBudgetValue())
	})
}

func BenchmarkTakePrefetched(b *testing.B) {
	b.Run("empty_queue_fast_path", func(b *testing.B) {
		conn := &proxiedConn{
			prefetchSlots: make([][]byte, proxiedConnPrefetchMax),
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, ok, hasMore := conn.takePrefetched()
			if ok || hasMore {
				b.Fatal("expected empty queue")
			}
		}
	})
}

func TestExtractContextZeroPayloadForUDP(t *testing.T) {
	t.Run("accepts single-byte context zero", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x00, 0xaa, 0xbb})
		require.Equal(t, udpPayloadAccept, result)
		require.Equal(t, []byte{0xaa, 0xbb}, payload)
	})

	t.Run("accepts two-byte context zero", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x40, 0x00, 0xaa, 0xbb})
		require.Equal(t, udpPayloadAccept, result)
		require.Equal(t, []byte{0xaa, 0xbb}, payload)
	})

	t.Run("rejects two-byte lowbits non-zero context", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x40, 0x01, 0xaa, 0xbb})
		require.Equal(t, udpPayloadDropUnknownContext, result)
		require.Nil(t, payload)
	})

	t.Run("accepts four-byte context zero", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x80, 0x00, 0x00, 0x00, 0xaa, 0xbb})
		require.Equal(t, udpPayloadAccept, result)
		require.Equal(t, []byte{0xaa, 0xbb}, payload)
	})

	t.Run("rejects four-byte lowbits non-zero context", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x80, 0x00, 0x00, 0x01, 0xaa, 0xbb})
		require.Equal(t, udpPayloadDropUnknownContext, result)
		require.Nil(t, payload)
	})

	t.Run("accepts eight-byte context zero", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb})
		require.Equal(t, udpPayloadAccept, result)
		require.Equal(t, []byte{0xaa, 0xbb}, payload)
	})

	t.Run("rejects eight-byte lowbits non-zero context", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb})
		require.Equal(t, udpPayloadDropUnknownContext, result)
		require.Nil(t, payload)
	})

	t.Run("rejects non-zero context", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x25, 0xaa, 0xbb})
		require.Equal(t, udpPayloadDropUnknownContext, result)
		require.Nil(t, payload)
	})

	t.Run("rejects malformed datagram", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP(nil)
		require.Equal(t, udpPayloadDropMalformed, result)
		require.Nil(t, payload)
	})

	t.Run("rejects malformed truncated two-byte context", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x40})
		require.Equal(t, udpPayloadDropMalformed, result)
		require.Nil(t, payload)
	})

	t.Run("rejects malformed truncated four-byte context", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0x80, 0x00, 0x00})
		require.Equal(t, udpPayloadDropMalformed, result)
		require.Nil(t, payload)
	})

	t.Run("rejects malformed truncated eight-byte context", func(t *testing.T) {
		payload, result := extractContextZeroPayloadForUDP([]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		require.Equal(t, udpPayloadDropMalformed, result)
		require.Nil(t, payload)
	})

	t.Run("rejects oversize payload", func(t *testing.T) {
		payload := make([]byte, maxUDPPayloadSize+1)
		raw := append([]byte{0x00}, payload...)
		out, result := extractContextZeroPayloadForUDP(raw)
		require.Equal(t, udpPayloadDropOversize, result)
		require.Nil(t, out)
	})

	t.Run("accepts max payload boundary", func(t *testing.T) {
		payload := make([]byte, maxUDPPayloadSize)
		raw := append([]byte{0x00}, payload...)
		out, result := extractContextZeroPayloadForUDP(raw)
		require.Equal(t, udpPayloadAccept, result)
		require.Len(t, out, maxUDPPayloadSize)
		require.Equal(t, payload, out)
	})
}

type timeoutNetError struct{}

func (e timeoutNetError) Error() string   { return "timeout" }
func (e timeoutNetError) Timeout() bool   { return true }
func (e timeoutNetError) Temporary() bool { return true }

func TestIsTransientUDPSendError(t *testing.T) {
	t.Run("accepts socket pressure errors", func(t *testing.T) {
		require.True(t, isTransientUDPSendError(syscall.ENOBUFS))
		require.True(t, isTransientUDPSendError(syscall.EAGAIN))
		require.True(t, isTransientUDPSendError(syscall.EWOULDBLOCK))
		require.True(t, isTransientUDPSendError(syscall.EINTR))
		require.True(t, isTransientUDPSendError(syscall.ECONNREFUSED))
		require.True(t, isTransientUDPSendError(syscall.ECONNRESET))
	})

	t.Run("accepts wrapped and timeout errors", func(t *testing.T) {
		require.True(t, isTransientUDPSendError(fmt.Errorf("wrapped: %w", syscall.ENOBUFS)))
		require.True(t, isTransientUDPSendError(timeoutNetError{}))
	})

	t.Run("rejects permanent errors", func(t *testing.T) {
		require.False(t, isTransientUDPSendError(nil))
		require.False(t, isTransientUDPSendError(syscall.ENOTSOCK))
	})
}

func TestIsTransientUDPReadError(t *testing.T) {
	t.Run("accepts socket pressure errors", func(t *testing.T) {
		require.True(t, isTransientUDPReadError(syscall.ENOBUFS))
		require.True(t, isTransientUDPReadError(syscall.EAGAIN))
		require.True(t, isTransientUDPReadError(syscall.EWOULDBLOCK))
		require.True(t, isTransientUDPReadError(syscall.EINTR))
	})

	t.Run("accepts wrapped and timeout errors", func(t *testing.T) {
		require.True(t, isTransientUDPReadError(fmt.Errorf("wrapped: %w", syscall.ECONNRESET)))
		require.True(t, isTransientUDPReadError(timeoutNetError{}))
	})

	t.Run("accepts ICMP-induced read errors", func(t *testing.T) {
		require.True(t, isTransientUDPReadError(syscall.ECONNREFUSED))
		require.True(t, isTransientUDPReadError(syscall.ECONNRESET))
	})

	t.Run("rejects permanent errors", func(t *testing.T) {
		require.False(t, isTransientUDPReadError(nil))
		require.False(t, isTransientUDPReadError(syscall.ENOTSOCK))
	})
}

func TestIsTransientHTTPDatagramSendError(t *testing.T) {
	t.Run("accepts socket pressure errors", func(t *testing.T) {
		require.True(t, isTransientHTTPDatagramSendError(syscall.ENOBUFS))
		require.True(t, isTransientHTTPDatagramSendError(syscall.EAGAIN))
		require.True(t, isTransientHTTPDatagramSendError(syscall.EWOULDBLOCK))
		require.True(t, isTransientHTTPDatagramSendError(syscall.EINTR))
		require.True(t, isTransientHTTPDatagramSendError(syscall.ECONNREFUSED))
		require.True(t, isTransientHTTPDatagramSendError(syscall.ECONNRESET))
	})

	t.Run("accepts wrapped and timeout errors", func(t *testing.T) {
		require.True(t, isTransientHTTPDatagramSendError(fmt.Errorf("wrapped: %w", syscall.EAGAIN)))
		require.True(t, isTransientHTTPDatagramSendError(timeoutNetError{}))
	})

	t.Run("rejects permanent errors", func(t *testing.T) {
		require.False(t, isTransientHTTPDatagramSendError(nil))
		require.False(t, isTransientHTTPDatagramSendError(syscall.ENOTSOCK))
		require.False(t, isTransientHTTPDatagramSendError(io.EOF))
	})
}

func TestIsTransientHTTPDatagramReceiveError(t *testing.T) {
	t.Run("accepts socket pressure errors", func(t *testing.T) {
		require.True(t, isTransientHTTPDatagramReceiveError(syscall.ENOBUFS))
		require.True(t, isTransientHTTPDatagramReceiveError(syscall.EAGAIN))
		require.True(t, isTransientHTTPDatagramReceiveError(syscall.EWOULDBLOCK))
		require.True(t, isTransientHTTPDatagramReceiveError(syscall.EINTR))
		require.True(t, isTransientHTTPDatagramReceiveError(syscall.ECONNREFUSED))
		require.True(t, isTransientHTTPDatagramReceiveError(syscall.ECONNRESET))
	})

	t.Run("accepts wrapped and timeout errors", func(t *testing.T) {
		require.True(t, isTransientHTTPDatagramReceiveError(fmt.Errorf("wrapped: %w", syscall.EAGAIN)))
		require.True(t, isTransientHTTPDatagramReceiveError(timeoutNetError{}))
	})

	t.Run("rejects permanent errors", func(t *testing.T) {
		require.False(t, isTransientHTTPDatagramReceiveError(nil))
		require.False(t, isTransientHTTPDatagramReceiveError(syscall.ENOTSOCK))
		require.False(t, isTransientHTTPDatagramReceiveError(io.EOF))
	})
}

func TestIsHTTPDatagramTooLargeError(t *testing.T) {
	t.Run("accepts quic datagram too large", func(t *testing.T) {
		require.True(t, isHTTPDatagramTooLargeError(&quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}))
		require.True(t, isHTTPDatagramTooLargeError(fmt.Errorf("wrapped: %w", &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1000})))
	})

	t.Run("rejects non size-limit errors", func(t *testing.T) {
		require.False(t, isHTTPDatagramTooLargeError(nil))
		require.False(t, isHTTPDatagramTooLargeError(syscall.ENOBUFS))
		require.False(t, isHTTPDatagramTooLargeError(io.EOF))
	})
}

func TestTransientBackoffDuration(t *testing.T) {
	require.Equal(t, time.Duration(0), transientBackoffDuration(0))
	require.Equal(t, time.Duration(0), transientBackoffDuration(1))
	require.Equal(t, time.Duration(0), transientBackoffDuration(2))
	require.Equal(t, 50*time.Microsecond, transientBackoffDuration(3))
	require.Equal(t, 100*time.Microsecond, transientBackoffDuration(4))
	require.Equal(t, 200*time.Microsecond, transientBackoffDuration(5))
	require.Equal(t, 800*time.Microsecond, transientBackoffDuration(7))
	require.Equal(t, 800*time.Microsecond, transientBackoffDuration(20))
}

func TestTransientBackoffDurationWithMaxShift(t *testing.T) {
	require.Equal(t, time.Duration(0), transientBackoffDurationWithMaxShift(0, dropOnlyPressureBackoffMaxShift))
	require.Equal(t, 50*time.Microsecond, transientBackoffDurationWithMaxShift(3, dropOnlyPressureBackoffMaxShift))
	require.Equal(t, 100*time.Microsecond, transientBackoffDurationWithMaxShift(4, dropOnlyPressureBackoffMaxShift))
	require.Equal(t, 100*time.Microsecond, transientBackoffDurationWithMaxShift(5, dropOnlyPressureBackoffMaxShift))
	require.Equal(t, 100*time.Microsecond, transientBackoffDurationWithMaxShift(20, dropOnlyPressureBackoffMaxShift))
}

func TestTransientPressureBackoffReset(t *testing.T) {
	var b transientPressureBackoff
	require.Equal(t, time.Duration(0), b.onTransientError())
	require.Equal(t, time.Duration(0), b.onTransientError())
	require.Equal(t, 50*time.Microsecond, b.onTransientError())
	b.onProgress()
	require.Equal(t, time.Duration(0), b.onTransientError())
}

func TestTransientPressureBackoffPersistsAcrossBatches(t *testing.T) {
	w := &udpDatagramWriter{}
	require.Equal(t, 0, w.sendBackoff.consecutive)

	require.Equal(t, time.Duration(0), w.sendBackoff.onTransientError())
	require.Equal(t, 1, w.sendBackoff.consecutive)

	// Simulate the next fallback batch under continued pressure: state must carry over.
	require.Equal(t, time.Duration(0), w.sendBackoff.onTransientError())
	require.Equal(t, 2, w.sendBackoff.consecutive)
	require.Equal(t, 50*time.Microsecond, w.sendBackoff.onTransientError())
	require.Equal(t, 3, w.sendBackoff.consecutive)

	w.sendBackoff.onProgress()
	require.Equal(t, 0, w.sendBackoff.consecutive)
	require.Equal(t, time.Duration(0), w.sendBackoff.onTransientError())
}

func TestObserveBatchProgressResetsBackoff(t *testing.T) {
	w := &udpDatagramWriter{}
	require.Equal(t, time.Duration(0), w.sendBackoff.onTransientError())
	require.Equal(t, time.Duration(0), w.sendBackoff.onTransientError())
	require.Equal(t, 50*time.Microsecond, w.sendBackoff.onTransientError())
	require.Equal(t, 3, w.sendBackoff.consecutive)

	w.observeBatchProgress(1)
	require.Equal(t, 0, w.sendBackoff.consecutive)

	require.Equal(t, time.Duration(0), w.sendBackoff.onTransientError())
	require.Equal(t, 1, w.sendBackoff.consecutive)

	w.observeBatchProgress(0)
	require.Equal(t, 1, w.sendBackoff.consecutive)
}

func TestShouldSleepOnTransientFallback(t *testing.T) {
	require.False(t, shouldSleepOnTransientFallback(0, 0))
	require.True(t, shouldSleepOnTransientFallback(50*time.Microsecond, 0))
	require.False(t, shouldSleepOnTransientFallback(50*time.Microsecond, transientFallbackSleepMaxPerBatch))
}

func TestShouldRetryTransientFallback(t *testing.T) {
	require.True(t, shouldRetryTransientFallback(0, 0))
	require.False(t, shouldRetryTransientFallback(transientFallbackRetryMaxPerBatch, 0))
	require.False(t, shouldRetryTransientFallback(0, 1))
}

func TestShouldPauseTransientFallback(t *testing.T) {
	require.False(t, shouldPauseTransientFallback(0, 0))
	require.True(t, shouldPauseTransientFallback(50*time.Microsecond, 0))
	require.False(t, shouldPauseTransientFallback(50*time.Microsecond, transientFallbackSleepMaxPerBatch))
}

func TestShouldDropTransientFallbackTail(t *testing.T) {
	require.False(t, shouldDropTransientFallbackTail(0, transientFallbackSleepMaxPerBatch, transientFallbackDropTailMinRemaining, 0))
	require.False(t, shouldDropTransientFallbackTail(transientFallbackDropTailBackoffThreshold-time.Microsecond, transientFallbackSleepMaxPerBatch, transientFallbackDropTailMinRemaining, 0))
	require.False(t, shouldDropTransientFallbackTail(transientFallbackDropTailBackoffThreshold, transientFallbackSleepMaxPerBatch-1, transientFallbackDropTailMinRemaining, 0))
	require.False(t, shouldDropTransientFallbackTail(transientFallbackDropTailBackoffThreshold, transientFallbackSleepMaxPerBatch, transientFallbackDropTailMinRemaining-1, 0))
	require.False(t, shouldDropTransientFallbackTail(transientFallbackDropTailBackoffThreshold, transientFallbackSleepMaxPerBatch, transientFallbackDropTailMinRemaining, 1))
	require.True(t, shouldDropTransientFallbackTail(transientFallbackDropTailBackoffThreshold, transientFallbackSleepMaxPerBatch, transientFallbackDropTailMinRemaining, 0))
	require.True(t, shouldDropTransientFallbackTail(800*time.Microsecond, transientFallbackSleepMaxPerBatch, transientFallbackDropTailMinRemaining+4, 0))
}

func TestUDPPayloadDropTallyBatching(t *testing.T) {
	var pending udpPayloadDropTally
	pending.observe(udpPayloadDropMalformed)
	pending.observe(udpPayloadDropUnknownContext)
	require.Equal(t, 2, pending.total())
	require.False(t, shouldFlushUDPPayloadDropTally(pending))

	delta := udpPayloadDropTally{
		malformed: udpPayloadDropFlushThreshold - 2,
		oversize:  1,
	}
	pending.observeTally(delta)
	require.Equal(t, udpPayloadDropFlushThreshold+1, pending.total())
	require.True(t, shouldFlushUDPPayloadDropTally(pending))
}

func TestShouldFlushOversizedDrops(t *testing.T) {
	require.False(t, shouldFlushOversizedDrops(0))
	require.False(t, shouldFlushOversizedDrops(oversizedDropFlushThreshold-1))
	require.True(t, shouldFlushOversizedDrops(oversizedDropFlushThreshold))
	require.True(t, shouldFlushOversizedDrops(oversizedDropFlushThreshold+17))
}

func TestShouldMarkProxyConnSendProgress(t *testing.T) {
	require.False(t, shouldMarkProxyConnSendProgress(udpPayloadAccept, 0, 0))
	require.False(t, shouldMarkProxyConnSendProgress(udpPayloadDropUnknownContext, 1, 0))
	require.True(t, shouldMarkProxyConnSendProgress(udpPayloadDropUnknownContext, 0, 1))
	require.False(t, shouldMarkProxyConnSendProgress(udpPayloadDropMalformed, 0, 0))
}

func TestShouldBackoffProxyConnSendNoWrite(t *testing.T) {
	require.True(t, shouldBackoffProxyConnSendNoWrite(0))
	require.False(t, shouldBackoffProxyConnSendNoWrite(1))
	require.False(t, shouldBackoffProxyConnSendNoWrite(8))
}

func TestShouldUseDropOnlyBackoff(t *testing.T) {
	require.False(t, shouldUseDropOnlyBackoff(udpPayloadAccept, 0, 1, 0))
	require.False(t, shouldUseDropOnlyBackoff(udpPayloadAccept, 0, 0, 0))
	require.False(t, shouldUseDropOnlyBackoff(udpPayloadDropUnknownContext, 1, 0, 1))
	require.False(t, shouldUseDropOnlyBackoff(udpPayloadDropMalformed, 0, 0, 0))
	require.True(t, shouldUseDropOnlyBackoff(udpPayloadDropUnknownContext, 0, 0, 1))
	require.True(t, shouldUseDropOnlyBackoff(udpPayloadDropOversize, 0, 0, 4))
}

func TestClassifyProxyConnSendNoWriteBackoff(t *testing.T) {
	useDropOnly, skipReceiveSleep := classifyProxyConnSendNoWriteBackoff(udpPayloadAccept, 0, 1, 0, false)
	require.False(t, useDropOnly)
	require.False(t, skipReceiveSleep)

	useDropOnly, skipReceiveSleep = classifyProxyConnSendNoWriteBackoff(udpPayloadAccept, 0, 0, 0, true)
	require.False(t, useDropOnly)
	require.True(t, skipReceiveSleep)

	useDropOnly, skipReceiveSleep = classifyProxyConnSendNoWriteBackoff(udpPayloadDropMalformed, 0, 0, 1, false)
	require.True(t, useDropOnly)
	require.False(t, skipReceiveSleep)

	useDropOnly, skipReceiveSleep = classifyProxyConnSendNoWriteBackoff(udpPayloadDropUnknownContext, 1, 0, 1, false)
	require.False(t, useDropOnly)
	require.False(t, skipReceiveSleep)
}

func TestMergeSendPressureNoProgress(t *testing.T) {
	require.False(t, mergeSendPressureNoProgress())
	require.False(t, mergeSendPressureNoProgress(false, false, false))
	require.True(t, mergeSendPressureNoProgress(true))
	require.True(t, mergeSendPressureNoProgress(false, false, true))
	require.True(t, mergeSendPressureNoProgress(true, false, false))
}

func TestShouldReportSendPressureNoProgress(t *testing.T) {
	require.False(t, shouldReportSendPressureNoProgress(false, 0, 0, 1))
	require.False(t, shouldReportSendPressureNoProgress(true, 1, 0, 1))
	require.False(t, shouldReportSendPressureNoProgress(true, 0, 0, 0))
	require.True(t, shouldReportSendPressureNoProgress(true, 0, 0, 1))
	require.True(t, shouldReportSendPressureNoProgress(true, 3, 3, 2))
}

func TestShouldObserveDrainProbe(t *testing.T) {
	require.True(t, shouldObserveDrainProbe(false, 0))
	require.True(t, shouldObserveDrainProbe(false, 3))
	require.False(t, shouldObserveDrainProbe(true, 0))
	require.True(t, shouldObserveDrainProbe(true, 1))
}
