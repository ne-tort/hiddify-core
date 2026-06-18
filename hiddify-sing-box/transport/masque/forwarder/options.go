package forwarder

import (
	"net"
	"net/netip"
)

const (
	// DefaultDatagramCeilingMax is the CONNECT-IP IPv4 datagram ceiling before H3 slack.
	DefaultDatagramCeilingMax = 1500
	// DatagramSlack is subtracted from the ceiling when sizing forwarder segments (H3 overhead).
	DatagramSlack = 80
)

// PacketPlaneConn is the CONNECT-IP session packet I/O surface used by the S2 forwarder.
type PacketPlaneConn interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
	CurrentPeerPrefixes() []netip.Prefix
}

// ConnectIPTCPForwarderOptions carries generic MASQUE server policy knobs reused by the
// CONNECT-IP IPv4/TCP packet-plane forwarder (S2 path).
type ConnectIPTCPForwarderOptions struct {
	AllowPrivateTargets bool
	AllowedTargetPorts  []uint16
	BlockedTargetPorts  []uint16
	Dialer              net.Dialer
	// WriteQueueMetrics optionally records writeCh depth under backpressure (tests/profiling).
	WriteQueueMetrics *WriteQueueMetrics
	// DownloadQueueMetrics optionally records downloadCh depth under S2C DATA pressure.
	DownloadQueueMetrics *DownloadQueueMetrics
}
