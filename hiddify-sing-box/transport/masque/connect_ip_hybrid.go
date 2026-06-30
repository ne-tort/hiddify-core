package masque

import (
	"errors"
	"strings"
)

// ErrConnectIPHybridTransport is the config error for transport_mode=connect_ip + tcp_transport=connect_stream.
var ErrConnectIPHybridTransport = errors.New("masque: transport_mode connect_ip with tcp_transport connect_stream is not supported (use tcp_transport connect_ip for native TUN, or transport_mode connect_udp with connect_stream for TCP stream)")

// RejectConnectIPHybridTransport rejects the invalid connect_ip + connect_stream TCP combo.
func RejectConnectIPHybridTransport(transportMode, tcpTransport string) error {
	tm := strings.ToLower(strings.TrimSpace(transportMode))
	tt := strings.ToLower(strings.TrimSpace(tcpTransport))
	if tm == "connect_ip" && tt == "connect_stream" {
		return ErrConnectIPHybridTransport
	}
	return nil
}
