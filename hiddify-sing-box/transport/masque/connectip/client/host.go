package client

import (
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
)

// SessionIP combines CONNECT-IP open and ingress plane access for client.Plane (X-03 parity UDP).
type SessionIP interface {
	session.IPPlaneHost
	IngressPlane() *mcip.Ingress
}
