package connectip

import (
	"errors"
	"log"
	"strings"

	libconnectip "github.com/quic-go/connect-ip-go"
)

// BeginOpenSession records CONNECT-IP open scope and lifecycle observability markers.
func BeginOpenSession(scopeTarget string, scopeIPProto uint8) {
	EmitObservabilityEvent("open_ip_session_begin")
	SetSessionScope(scopeTarget, scopeIPProto)
}

// OpenSessionNotSupportedError records observability for unsupported CONNECT-IP capability.
func OpenSessionNotSupportedError() error {
	IncWriteFailReason("open_not_supported")
	EmitObservabilityEvent("open_ip_session_fail")
	return errors.Join(Errs.Capability, errors.New("masque backend does not support CONNECT-IP"))
}

// RecordOpenSessionFailure records observability for a failed CONNECT-IP open attempt.
func RecordOpenSessionFailure(err error) {
	if err == nil {
		return
	}
	IncWriteFailReason(ClassifyWriteError(err))
	EmitObservabilityEvent("open_ip_session_fail")
}

// RecordOpenSessionSuccessReuse records observability when an existing CONNECT-IP session is reused.
func RecordOpenSessionSuccessReuse() {
	EmitObservabilityEvent("open_ip_session_success_reuse")
}

// RecordOpenSessionSuccessNew records observability for a freshly opened CONNECT-IP session.
func RecordOpenSessionSuccessNew() {
	IncOpenSessionTotal()
	SetSessionID()
	EmitObservabilityEvent("open_ip_session_success")
}

// LogOpenDialFailure logs a CONNECT-IP dial failure with auth context.
func LogOpenDialFailure(server string, serverPort uint16, serverTokenSet, warpMTLS bool, err error) {
	log.Printf("masque connectip dial failed server=%s:%d server_token_set=%t warp_mtls=%t err=%v",
		server, serverPort, serverTokenSet, warpMTLS, err)
}

// SessionPacketParams wires production CONNECT-IP client packet session fields from core session.
type SessionPacketParams struct {
	Conn              *libconnectip.Conn
	DatagramCeiling   int
	UDPPayloadHardCap int
	TCPDatagramSlack  int
	PMTUState         *UDPPMTUState
	ProfileLocalIPv4  string
	ProfileLocalIPv6  string
	OverlayH2         bool
	WakeAfterDatagram func()
}

// NewClientPacketSessionFromParams constructs a client packet session with trimmed profile locals.
func NewClientPacketSessionFromParams(p SessionPacketParams) *ClientPacketSession {
	return NewClientPacketSession(ClientPacketSessionConfig{
		Conn:              p.Conn,
		DatagramCeiling:   p.DatagramCeiling,
		UDPPayloadHardCap: p.UDPPayloadHardCap,
		TCPDatagramSlack:  p.TCPDatagramSlack,
		PMTUState:         p.PMTUState,
		ProfileLocalIPv4:  strings.TrimSpace(p.ProfileLocalIPv4),
		ProfileLocalIPv6:  strings.TrimSpace(p.ProfileLocalIPv6),
		OverlayH2:         p.OverlayH2,
		WakeAfterDatagram: p.WakeAfterDatagram,
	})
}
