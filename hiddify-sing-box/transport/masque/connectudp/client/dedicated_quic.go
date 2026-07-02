package client

import (
	"net"
	"sync"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
)

// h3UsesDedicatedQUICClient reports whether each CONNECT-UDP flow owns a separate masque-go Client (UDP-M2-04).
func h3UsesDedicatedQUICClient(host SessionUDP) bool {
	return host.CurrentHTTPLayer() == option.MasqueHTTPLayerH3
}

type ownedQUICPacketConn struct {
	net.PacketConn
	client *qmasque.Client

	closeOnce sync.Once
}

func wrapOwnedQUICPacketConn(pc net.PacketConn, client *qmasque.Client) net.PacketConn {
	if pc == nil || client == nil {
		return pc
	}
	return &ownedQUICPacketConn{PacketConn: pc, client: client}
}

func (c *ownedQUICPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.PacketConn.Close()
		if c.client != nil {
			_ = c.client.Close()
			c.client = nil
		}
	})
	return err
}

func refreshDedicatedQUICClient(host SessionUDP, prev *qmasque.Client) *qmasque.Client {
	if prev != nil {
		_ = prev.Close()
	}
	return host.NewQUICClient()
}
