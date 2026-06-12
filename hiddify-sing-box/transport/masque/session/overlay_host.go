package session

// OverlaySwitchHost wires production teardown for H3↔H2 http_layer_fallback pivot (phase F5 bridge).
type OverlaySwitchHost interface {
	ConnectIPTeardownHost
	CancelConnectIPIngress()
	TeardownOverlayHTTPLockedAssumeMu()
	CloseConnectAuthorityClient() error
	CloseUDPClientLockedAssumeMu()
	CloseAllH2ClientTransports()
	OverlaySwitchLog(tag, from, to string)
}
