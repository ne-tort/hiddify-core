package connectip

import (
	"context"

	connectip "github.com/quic-go/connect-ip-go"
	cipegress "github.com/sagernet/sing-box/transport/masque/connectip/pump/egress"
)

// ClientPacketSessionConfig wires a CONNECT-IP client packet session wrapper.
type ClientPacketSessionConfig struct {
	Conn              *connectip.Conn
	DatagramCeiling   int
	UDPPayloadHardCap int
	TCPDatagramSlack  int
	PMTUState         *UDPPMTUState
	ProfileLocalIPv4  string
	ProfileLocalIPv6  string
	OverlayH2         bool
	WakeAfterDatagram func()
}

// ClientPacketSession wraps connect-ip-go Conn for masque IPPacketSession consumers.
// The core session owns CONNECT-IP lifecycle; Close on this wrapper is a no-op.
type ClientPacketSession struct {
	conn              *connectip.Conn
	datagramCeiling   int
	udpPayloadHardCap int
	tcpDatagramSlack  int
	pmtuState         *UDPPMTUState
	profileLocalIPv4  string
	profileLocalIPv6  string
	overlayH2         bool
	wakeAfterDatagram func()
}

// NewClientPacketSession constructs a CONNECT-IP packet session wrapper.
func NewClientPacketSession(cfg ClientPacketSessionConfig) *ClientPacketSession {
	return &ClientPacketSession{
		conn:              cfg.Conn,
		datagramCeiling:   cfg.DatagramCeiling,
		udpPayloadHardCap: cfg.UDPPayloadHardCap,
		tcpDatagramSlack:  cfg.TCPDatagramSlack,
		pmtuState:         cfg.PMTUState,
		profileLocalIPv4:  cfg.ProfileLocalIPv4,
		profileLocalIPv6:  cfg.ProfileLocalIPv6,
		overlayH2:         cfg.OverlayH2,
		wakeAfterDatagram: cfg.WakeAfterDatagram,
	}
}

// Conn returns the underlying connect-ip-go connection.
func (s *ClientPacketSession) Conn() *connectip.Conn {
	return s.conn
}

// SessionBootstrap returns netstack factory metadata from this session.
func (s *ClientPacketSession) SessionBootstrap() SessionBootstrap {
	return SessionBootstrap{
		PrefixSource:       s.conn,
		ProfileLocalIPv4:   s.profileLocalIPv4,
		ProfileLocalIPv6:   s.profileLocalIPv6,
		DatagramCeiling:    s.datagramCeiling,
		OverlayH2:          s.overlayH2,
		TCPDatagramSlack:   s.tcpDatagramSlack,
		DatagramCeilingMax: DatagramCeilingMax(),
	}
}

// UDPBridgeConfig carries UDP packet conn parameters derived from this session.
type UDPBridgeConfig struct {
	PrefixSource      PrefixSource
	UDPPayloadHardCap int
	DatagramCeiling   int
	PMTUState         *UDPPMTUState
	ProfileLocalIPv4  string
	OK                bool
}

// UDPBridgeConfigFrom extracts UDP bridge hints when sess is a live client packet session.
func UDPBridgeConfigFrom(sess PacketSession) UDPBridgeConfig {
	s, ok := sess.(*ClientPacketSession)
	if !ok || s.conn == nil {
		return UDPBridgeConfig{}
	}
	cfg := UDPBridgeConfig{
		PrefixSource:      s.conn,
		UDPPayloadHardCap: s.udpPayloadHardCap,
		DatagramCeiling:   s.datagramCeiling,
		PMTUState:         s.pmtuState,
		ProfileLocalIPv4:  s.profileLocalIPv4,
		OK:                true,
	}
	if cfg.DatagramCeiling > 0 {
		if cap := DatagramCeilingMax(); cfg.DatagramCeiling > cap {
			cfg.DatagramCeiling = cap
		}
	}
	return cfg
}

// SessionBootstrapFrom returns netstack bootstrap metadata when sess is a client packet session.
func SessionBootstrapFrom(sess PacketSession) SessionBootstrap {
	boot := SessionBootstrap{DatagramCeilingMax: DatagramCeilingMax()}
	if s, ok := sess.(*ClientPacketSession); ok {
		return s.SessionBootstrap()
	}
	return boot
}

func (s *ClientPacketSession) ReadPacket(buffer []byte) (int, error) {
	n, err := s.conn.ReadPacket(buffer)
	if err != nil {
		TrackReadExit(err)
		return n, err
	}
	TrackPacketRx(n)
	return n, err
}

func (s *ClientPacketSession) ReadPacketWithContext(ctx context.Context, buffer []byte) (int, error) {
	n, err := s.conn.ReadPacketWithContext(ctx, buffer)
	if err != nil {
		TrackReadExit(err)
		return n, err
	}
	TrackPacketRx(n)
	return n, err
}

func (s *ClientPacketSession) WritePacket(buffer []byte) ([]byte, error) {
	return cipegress.WritePacket(s.egressHost(), buffer)
}

// WritePacketNoWake enqueues without QUIC flush; caller must FlushEgressBatch once per pump iteration.
func (s *ClientPacketSession) WritePacketNoWake(buffer []byte) ([]byte, error) {
	return cipegress.WritePacketNoWake(s.egressHost(), buffer)
}

// WritePacketFromNetstack sends a netstack pool buffer in-place (NoWake); caller flushes the batch.
func (s *ClientPacketSession) WritePacketFromNetstack(outbound []byte) (retained bool, icmp []byte, err error) {
	return cipegress.WritePacketFromNetstack(s.egressHost(), outbound)
}

// WritePacketPrefixed sends a datagram buffer that already includes the RFC9297 context ID prefix.
func (s *ClientPacketSession) WritePacketPrefixed(buffer []byte) ([]byte, error) {
	return cipegress.WritePacketPrefixed(s.egressHost(), buffer, connectip.DatagramContextPrefixLen())
}

// FlushEgressBatch wakes QUIC/H2 send after batched WritePacketInPlaceNoWake calls.
func (s *ClientPacketSession) FlushEgressBatch() {
	cipegress.FlushEgressBatch(s.egressHost())
}

// ScheduleEgressFlush is a legacy alias for FlushEgressBatch (netstack OnEgressBatchComplete wiring).
func (s *ClientPacketSession) ScheduleEgressFlush() {
	cipegress.ScheduleEgressFlush(s.egressHost())
}

func (s *ClientPacketSession) Close() error {
	// The core session owns CONNECT-IP lifecycle. Closing this wrapper must not
	// tear down the shared underlying conn used by runtime packet-plane.
	return nil
}
