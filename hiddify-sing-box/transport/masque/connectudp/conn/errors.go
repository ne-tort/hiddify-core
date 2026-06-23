package conn

import "errors"

// ErrICMPPortUnreachable is returned by ReadFrom when the proxy signals ICMP port unreachable (empty datagram).
var ErrICMPPortUnreachable = errors.New("masque connect-udp: icmp port unreachable")
