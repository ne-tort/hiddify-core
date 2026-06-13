package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
)

type (
	ClientSession              = session.ClientSession
	ClientOptions              = session.ClientOptions
	ClientFactory              = session.ClientFactory
	CapabilitySet              = session.CapabilitySet
	HopOptions                 = session.HopOptions
	IPPacketSession            = session.IPPacketSession
	IPPacketSessionWithContext = session.IPPacketSessionWithContext
	HTTPLayerCacheDialIdentity = session.HTTPLayerCacheDialIdentity
	QUICExperimentalOptions    = session.QUICExperimentalOptions
	QUICDialFunc               = session.QUICDialFunc
	MasqueTCPDialFunc = session.MasqueTCPDialFunc
)
