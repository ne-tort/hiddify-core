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
func HTTPServerQUICConfig() *quic.Config {
	return h3t.HTTPServerQUICConfig()
}

// H3HTTPServerQUICConfig is QUIC tuning for standalone HTTP/3 listeners without datagram plane.
func H3HTTPServerQUICConfig() *quic.Config {
	cfg := HTTPServerQUICConfig()
	if cfg != nil {
		cfg.EnableDatagrams = false
	}
	return cfg
}

// ApplyQUICExperimentalOptions merges lab/WARP QUIC knobs onto a base config clone.
func ApplyQUICExperimentalOptions(base *quic.Config, opts QUICExperimentalOptions) *quic.Config {
	if base == nil {
		base = &quic.Config{}
	}
	config := base.Clone()
	if !opts.Enabled {
		return config
	}
	if opts.KeepAlivePeriod > 0 {
		config.KeepAlivePeriod = opts.KeepAlivePeriod
	}
	if opts.MaxIdleTimeout > 0 {
		config.MaxIdleTimeout = opts.MaxIdleTimeout
	}
	if opts.InitialStreamReceiveWindow > 0 {
		config.InitialStreamReceiveWindow = opts.InitialStreamReceiveWindow
	}
	if opts.MaxStreamReceiveWindow > 0 {
		config.MaxStreamReceiveWindow = opts.MaxStreamReceiveWindow
	}
	if opts.InitialConnectionWindow > 0 {
		config.InitialConnectionReceiveWindow = opts.InitialConnectionWindow
	}
	if opts.MaxConnectionWindow > 0 {
		config.MaxConnectionReceiveWindow = opts.MaxConnectionWindow
	}
	if opts.MaxIncomingStreams > 0 {
		config.MaxIncomingStreams = opts.MaxIncomingStreams
	}
	config.DisablePathMTUDiscovery = opts.DisablePathMTUDiscovery
	return config
}
