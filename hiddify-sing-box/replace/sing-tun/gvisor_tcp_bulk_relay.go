//go:build with_gvisor

package tun

import (
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/sing/common"
)

// tuneGvisorEndpointBulkRelay applies TUN bulk-relay socket tuning on a gVisor TCP endpoint.
// Re-applied from route/conn after MASQUE CONNECT-stream handshake (TuneMasqueBulkRelay).
func tuneGvisorEndpointBulkRelay(ep tcpip.Endpoint) {
	if ep == nil {
		return
	}
	opts := ep.SocketOptions()
	opts.SetKeepAlive(true)
	opts.SetDelayOption(false)
	opts.SetSendBufferSize(tunGvisorTCPBulkBuf, true)
	opts.SetReceiveBufferSize(tunGvisorTCPBulkBuf, true)
	cc := tcpip.CongestionControlOption("cubic")
	_ = ep.SetSockOpt(&cc)
	ep.SetSockOpt(common.Ptr(tcpip.KeepaliveIdleOption(15 * time.Second)))
	ep.SetSockOpt(common.Ptr(tcpip.KeepaliveIntervalOption(15 * time.Second)))
}
