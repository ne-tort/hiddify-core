package client

import (
	"context"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
)

// Plane wraps a SessionIP host for CONNECT-IP overlay operations.
type Plane struct {
	host SessionIP
}

// NewPlane returns a CONNECT-IP client plane backed by host.
func NewPlane(host SessionIP) *Plane {
	return &Plane{host: host}
}

// OpenIPSessionLocked opens or reuses the CONNECT-IP packet plane. Caller must hold s.Mu.
func (p *Plane) OpenIPSessionLocked(s *session.CoreSession, ctx context.Context) (session.IPPacketSession, error) {
	return session.OpenIPSessionLocked(s, p.host, ctx)
}

// Ingress returns the shared CONNECT-IP ingress demux (lazy on host).
func (p *Plane) Ingress() *mcip.Ingress {
	return p.host.IngressPlane()
}
