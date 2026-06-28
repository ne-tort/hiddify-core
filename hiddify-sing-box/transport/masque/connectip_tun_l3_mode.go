package masque

// enterConnectIPNativeL3Mode stops the netstack ingress loop so the TUN L3 bridge owns ReadPacket exclusively.
func enterConnectIPNativeL3Mode(sess ClientSession) (leave func()) {
	s, ok := sess.(*coreSession)
	if !ok {
		return nil
	}
	s.stopConnectIPIngressGracefully()
	s.connectIPNativeL3Active.Store(true)
	return func() {
		s.connectIPNativeL3Active.Store(false)
	}
}
