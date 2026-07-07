package relay

import (
	"errors"
	"io"
	"net"
	"time"
)

// relayTunnelPrimeDownload peeks the first onward-TCP segment without blocking for WAN RTT.
func relayTunnelPrimeDownload(conn net.Conn) ([]byte, error) {
	return relayTunnelPrimeDownloadPolicy(conn, currentRelayProbePolicy())
}

func relayTunnelPrimeDownloadPolicy(conn net.Conn, policy RelayProbePolicy) ([]byte, error) {
	buf := make([]byte, 4096)
	if prime, err, ok := relayTunnelPeekConn(conn, buf, 0); ok {
		if len(prime) > 0 || err != nil {
			return prime, err
		}
	}
	if policy.DownloadPrimeWait <= 0 {
		return nil, nil
	}
	prime, err, _ := relayTunnelPeekConn(conn, buf, policy.DownloadPrimeWait)
	return prime, err
}

func relayTunnelPeekConn(conn net.Conn, buf []byte, wait time.Duration) ([]byte, error, bool) {
	if conn == nil {
		return nil, nil, true
	}
	deadlineSetter, hasDeadline := conn.(interface {
		SetReadDeadline(time.Time) error
	})
	if !hasDeadline && wait == 0 {
		return nil, nil, true
	}
	if hasDeadline {
		deadline := time.Now()
		if wait > 0 {
			deadline = deadline.Add(wait)
		}
		_ = deadlineSetter.SetReadDeadline(deadline)
		defer func() { _ = deadlineSetter.SetReadDeadline(time.Time{}) }()
	}
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil, true
	}
	if err == nil {
		return nil, nil, true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil, nil, true
	}
	if errors.Is(err, io.EOF) {
		return nil, err, true
	}
	return nil, err, true
}
