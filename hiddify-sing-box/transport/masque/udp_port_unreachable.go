package masque

import E "github.com/sagernet/sing/common/exceptions"

// ErrUDPPortUnreachable signals CONNECT-UDP relay delivered ICMP destination-unreachable
// (empty RFC 9297 DATAGRAM payload). route.packetConnectionCopy must not treat this as a fatal
// relay error — the download goroutine should keep draining (H3 proxiedConn parity).
var ErrUDPPortUnreachable = E.New("masque connect-udp icmp port unreachable")
