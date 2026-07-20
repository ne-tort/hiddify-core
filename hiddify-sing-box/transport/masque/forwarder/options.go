package forwarder

import (
	"net"
	"net/netip"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
)

const (
	// DefaultDatagramCeilingMax is the CONNECT-IP IPv4 datagram ceiling before H3 slack.
	DefaultDatagramCeilingMax = cip.DefaultDatagramCeilingMax
	// MaxIPv4WireBytes caps forwarder S2C IPv4 datagram size (H3 CONNECT-IP return path ~1372 B).
	MaxIPv4WireBytes = cip.MaxIPv4WireBytes
	// DatagramSlack is WireSlack (= TCPHTTP3DatagramSlack): ceiling − MaxIPv4WireBytes.
	// Not FramingSlack (H3FramingSlack=80); see connectip P2-10 domain split.
	DatagramSlack = DefaultDatagramCeilingMax - MaxIPv4WireBytes
)

// PacketPlaneConn is the CONNECT-IP session packet I/O surface used by the S2 forwarder.
type PacketPlaneConn interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
	CurrentPeerPrefixes() []netip.Prefix
}

// packetPlaneCoalescedWriter is optional on PacketPlaneConn for Fountain S2C batching.
type packetPlaneCoalescedWriter interface {
	WritePacketNoWake([]byte) ([]byte, error)
	FlushOutgoingDatagramSend()
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
	// LeaveConnOpenOnCancel keeps PacketPlaneConn open when ctx is canceled (in-proc forwarder restart synth).
	LeaveConnOpenOnCancel bool
}
