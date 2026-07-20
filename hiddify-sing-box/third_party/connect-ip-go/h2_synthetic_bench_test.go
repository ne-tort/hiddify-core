package connectip

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
)

func benchmarkH2SendDatagramToWriter(b *testing.B, payloadLen int, dst io.Writer) {
	b.Helper()
	payload := make([]byte, payloadLen)
	s := &h2CapsulePipeStream{pipeW: dst}
	b.SetBytes(int64(payloadLen))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.SendDatagram(payload); err != nil {
			b.Fatalf("SendDatagram failed: %v", err)
		}
	}
}

func BenchmarkH2SyntheticMicroSendDatagram(b *testing.B) {
	b.Run("payload_128_discard", func(b *testing.B) {
		benchmarkH2SendDatagramToWriter(b, 128, io.Discard)
	})
	b.Run("payload_1200_discard", func(b *testing.B) {
		benchmarkH2SendDatagramToWriter(b, 1200, io.Discard)
	})
	b.Run("payload_1200_pipe", func(b *testing.B) {
		pr, pw := io.Pipe()
		defer pr.Close()
		var wg sync.WaitGroup
		ctx, cancel := context.WithCancel(context.Background())
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if _, err := pr.Read(buf); err != nil {
					return
				}
			}
		}()
		benchmarkH2SendDatagramToWriter(b, 1200, pw)
		cancel()
		_ = pw.Close()
		wg.Wait()
	})
}

func BenchmarkH2SyntheticMacroEndToEnd(b *testing.B) {
	run := func(b *testing.B, payloadLen int) {
		pr, pw := io.Pipe()
		payload := make([]byte, payloadLen)
		s := &h2CapsulePipeStream{pipeW: pw}
		readerDone := make(chan error, 1)
		go func(expected int) {
			r := quicvarint.NewReader(pr)
			for i := 0; i < expected; i++ {
				tp, cr, err := parseConnectIPStreamCapsule(r)
				if err != nil {
					readerDone <- err
					return
				}
				if tp != capsuleTypeHTTPDatagram {
					readerDone <- io.ErrUnexpectedEOF
					return
				}
				if _, err := readRFC9297HTTPDatagramCapsulePayload(cr); err != nil {
					readerDone <- err
					return
				}
			}
			readerDone <- nil
		}(b.N)

		b.SetBytes(int64(payloadLen))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := s.SendDatagram(payload); err != nil {
				b.Fatalf("SendDatagram failed: %v", err)
			}
		}
		b.StopTimer()
		_ = pw.Close()
		if err := <-readerDone; err != nil {
			b.Fatalf("reader failed: %v", err)
		}
		_ = pr.Close()
	}

	b.Run("payload_128", func(b *testing.B) { run(b, 128) })
	b.Run("payload_1200", func(b *testing.B) { run(b, 1200) })
}

func BenchmarkH2SyntheticMacroConnReadPacket(b *testing.B) {
	run := func(b *testing.B, payloadLen int) {
		bodyR, bodyW := io.Pipe()
		str := &h2CapsulePipeStream{
			body:  bodyR,
			pipeW: io.Discard,
		}
		conn := newProxiedConn(str, true)
		defer conn.Close()
		defer bodyR.Close()
		defer bodyW.Close()

		payload := make([]byte, payloadLen)
		wire := bytes.NewBuffer(make([]byte, 0, payloadLen+32))
		out := make([]byte, payloadLen+32)

		b.SetBytes(int64(payloadLen))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wire.Reset()
			dgramPayload := composeProxiedIPDatagramPayload(contextIDZero, payload)
			if err := appendHTTPDatagramCapsule(wire, dgramPayload); err != nil {
				b.Fatalf("appendHTTPDatagramCapsule failed: %v", err)
			}
			if _, err := bodyW.Write(wire.Bytes()); err != nil {
				b.Fatalf("body write failed: %v", err)
			}
			n, err := conn.ReadPacket(out)
			if err != nil {
				b.Fatalf("ReadPacket failed: %v", err)
			}
			if n != payloadLen {
				b.Fatalf("ReadPacket size=%d want %d", n, payloadLen)
			}
		}
	}

	b.Run("payload_128", func(b *testing.B) { run(b, 128) })
	b.Run("payload_1200", func(b *testing.B) { run(b, 1200) })
}

