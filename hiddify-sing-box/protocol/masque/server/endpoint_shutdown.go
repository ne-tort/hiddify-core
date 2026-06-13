package server

import (
	"context"
	"time"

	qmasque "github.com/quic-go/masque-go"
	btls "github.com/sagernet/sing-box/common/tls"
)

const defaultMasqueShutdownTimeout = 8 * time.Second

// ShutdownMasqueEndpointConfig tears down listeners started by LaunchMasqueStack or connect-stream-only path.
type ShutdownMasqueEndpointConfig struct {
	Stack           *MasqueStack
	UDPProxy        *qmasque.Proxy
	SingServerTLS   btls.ServerConfig
	ShutdownTimeout time.Duration
}

// ShutdownMasqueEndpoint closes UDP proxy, HTTP/2, inbound TLS, HTTP/3, and packet conn.
// Safe to call multiple times; nil fields are skipped.
func ShutdownMasqueEndpoint(cfg ShutdownMasqueEndpointConfig) error {
	if cfg.UDPProxy != nil {
		cfg.UDPProxy.Close()
	}
	timeout := cfg.ShutdownTimeout
	if timeout <= 0 {
		timeout = defaultMasqueShutdownTimeout
	}
	if cfg.Stack != nil {
		if cfg.Stack.HTTP2Server != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
			_ = cfg.Stack.HTTP2Server.Shutdown(shutdownCtx)
			cancel()
		}
		if cfg.Stack.TCPTLSListener != nil {
			_ = cfg.Stack.TCPTLSListener.Close()
		}
	}
	if cfg.SingServerTLS != nil {
		_ = cfg.SingServerTLS.Close()
	}
	var packetErr error
	if cfg.Stack != nil {
		drainBudget := timeout / 4
		if drainBudget < time.Second {
			drainBudget = time.Second
		}
		waitConnectIPRoutesDrained(drainBudget)
		if cfg.Stack.H3Server != nil {
			_ = cfg.Stack.H3Server.Close()
		}
		if cfg.Stack.PacketConn != nil {
			packetErr = cfg.Stack.PacketConn.Close()
			if packetErr != nil && ExpectedShutdownError(packetErr) {
				packetErr = nil
			}
		}
	}
	return packetErr
}
