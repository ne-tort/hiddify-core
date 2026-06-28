package masque

// datagramTransportLink models QUIC wire RTT + in-flight window for CONNECT-UDP localize benches.

type datagramTransportLink interface {
	quicDialOverride() QUICDialFunc
}

type instantDatagramLink struct{}

func (instantDatagramLink) quicDialOverride() QUICDialFunc { return nil }
