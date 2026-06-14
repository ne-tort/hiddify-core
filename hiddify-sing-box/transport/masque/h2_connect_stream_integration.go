package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

var errIntegrationBenchDuration = errors.New("masque: integration bench duration elapsed")

type integrationBenchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *integrationBenchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errIntegrationBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

// IntegrationMeasureTCPDownloadWriteToMbps drains via io.WriterTo (prod route writer_to path).
func IntegrationMeasureTCPDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, fmt.Errorf("masque: conn lacks io.WriterTo (prod download path)")
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &integrationBenchWriteToSink{deadline: deadline}
	_, err := wt.WriteTo(sink)
	if err != nil && err != errIntegrationBenchDuration && err != io.EOF {
		if sink.total == 0 {
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

// Integration helpers for protocol/masque cross-package synth tests.

func IntegrationStartH2FakeIperfDownloadTarget(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake iperf: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if _, err := conn.Write([]byte("iperf3\r\n")); err != nil {
					return
				}
				buf := make([]byte, 4096)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, conn) }()
				payload := make([]byte, 64*1024)
				for i := range payload {
					payload[i] = 'B'
				}
				for i := 0; i < 4; i++ {
					if _, err := conn.Write(payload); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return port
}

func IntegrationSocksTCPDial(t *testing.T, socksPort, targetPort uint16) net.Conn {
	t.Helper()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("socks tcp dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
