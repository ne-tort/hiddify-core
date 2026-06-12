package masque

import (
	"fmt"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/option"
	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
)

type masqueUDPDatagramSplitConn = cudp.DatagramSplitConn

func newMasqueUDPDatagramSplitConn(pc net.PacketConn, maxPayload int, httpLayer string) *cudp.DatagramSplitConn {
	return cudp.NewDatagramSplitConn(pc, cudp.DatagramSplitOptions{
		MaxPayload: maxPayload,
		HTTPLayer:  httpLayer,
		MapICMP: func(addr net.Addr, err error) error {
			return cudp.NewPortUnreachableError(addr)
		},
		MapDataplaneErr: func(op string, err error) error {
			if err == nil || httpLayer != option.MasqueHTTPLayerH3 {
				return err
			}
			return fmt.Errorf("masque h3 dataplane connect-udp %s: %w", op, err)
		},
	})
}

// ParseMasqueHTTPDatagramUDP interprets CONNECT-UDP HTTP Datagram payload (RFC 9297 / MASQUE).
func ParseMasqueHTTPDatagramUDP(data []byte) (payload []byte, ok bool, err error) {
	return cudp.ParseHTTPDatagramUDP(data)
}

// ServeH2ConnectUDP relays UDP over HTTP/2 CONNECT-UDP (RFC 9297 DATAGRAM capsules).
func ServeH2ConnectUDP(w http.ResponseWriter, r *http.Request, conn *net.UDPConn) error {
	return cudp.ServeH2(w, r, conn)
}
