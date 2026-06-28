package connectip

import cipingress "github.com/sagernet/sing-box/transport/masque/connectip/pump/ingress"

// Root re-exports from connectip/pump/ingress during W-IP-1 subdir migration (IP-1-PR2).
// Hook wiring lives in netstack_reexport.go init.

type (
	Ingress                = cipingress.Ingress
	IngressHost            = cipingress.Host
	IngressNetstack        = cipingress.Netstack
	UDPIngressSubscriber   = cipingress.UDPIngressSubscriber
	IngressAckWake         = cipingress.AckWake
	TCPIngressDeliverHooks = cipingress.TCPDeliverHooks
)

const (
	IngressUDPDeliverQueueDepth = cipingress.UDPDeliverQueueDepth
	PreTCPNetstackIngressMax    = cipingress.PreTCPNetstackIngressMax
)

var (
	NewIngress                     = cipingress.New
	DeliverTCPIngress              = cipingress.DeliverTCP
	ClassifyIPv4UDPBridgeCandidate = cipingress.ClassifyIPv4UDPBridgeCandidate
)
