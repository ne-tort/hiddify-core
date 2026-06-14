package masque

import (
	"context"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/session"
)

type tcpHTTPTransportHost struct {
	s *coreSession
}

func (s *coreSession) tcpHTTPTransportHost() tcpHTTPTransportHost {
	return tcpHTTPTransportHost{s: s}
}

func (h tcpHTTPTransportHost) ResetH2ConnectStreamTransportLockedAssumeMu() {
	h.s.resetH2ConnectStreamTransportLockedAssumeMu()
}

func (s *coreSession) openHTTP3ClientConn(ctx context.Context) (*http3.ClientConn, error) {
	return session.OpenH3ClientConn(ctx, &s.CoreSession)
}

func (s *coreSession) resetIPH3TransportLockedAssumeMu() {
	session.ResetIPH3TransportLockedAssumeMu(&s.CoreSession)
}

func (s *coreSession) resetTCPHTTPTransport() {
	session.ResetTCPHTTPTransport(&s.CoreSession, s.tcpHTTPTransportHost())
}

func (s *coreSession) newEphemeralTCPHTTPTransport() *http3.Transport {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return session.NewTCPConnectStreamHTTP3Transport(&s.CoreSession)
}
