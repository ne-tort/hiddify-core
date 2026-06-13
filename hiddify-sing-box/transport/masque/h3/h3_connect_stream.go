package h3

import (
	"time"

	"github.com/quic-go/quic-go"
)

// h3ConnectStream is the HTTP/3 CONNECT byte pipe used by TunnelConn (*http3.Stream in prod).
type h3ConnectStream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	CancelRead(quic.StreamErrorCode)
	QUICStream() *quic.Stream
}
