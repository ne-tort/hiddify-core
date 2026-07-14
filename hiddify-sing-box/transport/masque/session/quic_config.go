package session

import (
	"github.com/quic-go/quic-go"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

// H3QUICDialProfile maps session options to package h3 QUIC dial tuning.
func H3QUICDialProfile(opts ClientOptions) h3t.QUICDialProfile {
	return h3t.QUICDialProfile{
		WarpMasqueClientCert:     opts.WarpMasqueClientCert,
		WarpMasqueLegacyH3Extras: opts.WarpMasqueLegacyH3Extras,
		WarpConnectIPProtocol:    opts.WarpConnectIPProtocol,
		CongestionControl:        opts.CongestionControl,
	}
}

// QUICConfigForDial returns QUIC settings for CONNECT-UDP / CONNECT-IP client overlays.
func QUICConfigForDial(opts ClientOptions) *quic.Config {
	return h3t.QUICConfigForDial(H3QUICDialProfile(opts))
}

// TCPConnectStreamQUICConfig returns bulk TCP CONNECT-stream QUIC tuning.
func TCPConnectStreamQUICConfig(opts ClientOptions) *quic.Config {
	return h3t.TCPConnectStreamQUICConfig(H3QUICDialProfile(opts))
}

// TCPConnectStreamHTTP3EnableDatagrams reports whether CONNECT-stream H3 transport enables QUIC datagrams.
func TCPConnectStreamHTTP3EnableDatagrams(opts ClientOptions) bool {
	return h3t.TCPConnectStreamHTTP3EnableDatagrams(H3QUICDialProfile(opts))
}

// HTTPServerQUICConfig returns QUIC settings for the MASQUE HTTP/3 server listener.
func HTTPServerQUICConfig(congestionControl ...string) *quic.Config {
	return h3t.HTTPServerQUICConfig(congestionControl...)
}

// H3HTTPServerQUICConfig is QUIC tuning for standalone HTTP/3 listeners without datagram plane.
func H3HTTPServerQUICConfig(congestionControl ...string) *quic.Config {
	cfg := HTTPServerQUICConfig(congestionControl...)
	if cfg != nil {
		cfg.EnableDatagrams = false
	}
	return cfg
}
